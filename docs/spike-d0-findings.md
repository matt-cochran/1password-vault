# D0 spike findings: how op and flyctl actually behave

This doc answers the four D0 questions, plus two follow-ups: how `fly secrets import` parses stdin, and why the rate-limit deltas came out as zero.

- **Tool versions:** op 2.40.0 (Linux, service account `spike-fleet`) and flyctl v0.4.112 (commit `ca63052e`).
- **Targets:** vault `fleet-dev`, item `fleet` (Secure Note), Fly app `secretctl-test` (no machines). The Fly app keeps its original name `secretctl-test` although the CLI is now `opv`.
- **Runs:** the owner ran `spike/d0-probe.sh` twice on 2026-10-07. Run 1 did the stdin edit and then stopped in step 4 because of a script bug that was later fixed. Run 2 completed every step.
- **Evidence:** file names below are in `spike/out/`, which is git-ignored. All values in it are redacted to `"<v>"` and stderr is scrubbed. The leak grep was clean after both runs.
- **Copy:** this file is committed as `docs/spike-d0-findings.md`. The redacted fixtures are `tests/fixtures/op_item.json` and `tests/fixtures/fly_list.json`.

## Q1: item JSON shape (`op item get <item-id> --vault <vault-id> --format json`)

Evidence: `op_item.redacted.json`, `q1_shape.json` and `q2_attempt1.out.redacted`.

- **Top-level keys:** `id`, `title`, `version`, `vault{id,name}`, `category` (`SECURE_NOTE`), `last_edited_by`, `created_at`, `updated_at`, `sections[]`, `fields[]`.
- **`sections[]`:** each entry is `{id, label}`.
- **Fields inside a section:** `{id, section{id,label}, type, label, value, reference}`.
  - The section object carries **both** `id` and `label` (`section_has_id_and_label: true`).
- **Field types:** exactly `"CONCEALED"` and `"STRING"` (`field_types`).
- **Concealed values:** returned in plaintext in the JSON. No `--reveal` flag is needed (`concealed_value_returned_in_json: true`).
- **Fields outside sections:** only the built-in `notesPlain` (`type STRING`, `purpose NOTES`). It has **no `section` key**, and it has **no `value` key** when empty.
  - So the adapter must filter on `section` being present, not on `purpose`. A missing `value` must be treated as empty, not as an error.
- **Field id vs label:** these are separate. op kept the ids we supplied in the template (`probe_a_api_key`) and the labels (`API_KEY`).
  - Template-created section ids equal their labels (`probe_a`). Items created in the UI get random ids.
  - **The adapter must match on `section.label` and the field `label`, never on `id`.**
- **`reference`:** present on every field. Its value has the form `op://…`. It is redacted in the evidence, but it identifies a field and holds no value.

## Q2: can a JSON template be piped to `op item edit` on stdin?

**Yes.** `printf '%s' "$TEMPLATE" | op item edit <item-id> --vault <vault-id> --format json` returned rc=0 in run 1, as attempt 1, with no values in argv.

- **Evidence:** `q2_attempt1.out.redacted` (the resulting item: two sections, each with a CONCEALED and a STRING field), `q2_attempt1.stderr.txt` (empty), and `q2_template.redacted.json`.
- **Docs:** `op item edit --help` documents this form (`cat updatedLogin.json | op item edit oldLogin`), and says piped input can't be combined with `--template` (`op_item_edit_help.txt`).
- **Semantics:** the template **replaces** the item's sections and fields. Anything left out of the template is dropped.
  - So `item skeleton` (FR-19) must use read → merge in memory → pipe the result. This is the merge form the probe implements for reruns.
  - It must never pipe a partial template. Doing so would delete fields, which goes against the "never delete" rule and SR-5.
- **Consequence for S3 and I5:** `op item create` + archive is **not** needed. The pinned item IDs survive a stdin edit (`version` went 1 → 2, and `id` was unchanged).

## Q3: requests per whole-item read

Evidence: `ratelimit-0.json`, `ratelimit-1a.json`, `ratelimit-1b.json` and `ratelimit-1.json` from run 2, plus the `ratelimit-delta-*.json` files.

| Snapshot (run 2) | token read `used` | account read_write `used` | token read `reset` (s) |
|---|---|---|---|
| `ratelimit-0` (before any op item call) | 0 | 3 | 0 (no hourly window open) |
| *step 3 pre-check: first `op item get` (cold)* | | | |
| `ratelimit-1a` | 2 | 5 | 3599 |
| `ratelimit-1b` (right after 1a) | 2 | 5 | 3598 |
| *step 4: second, identical `op item get`* | | | |
| `ratelimit-1` | 2 | 5 | 3597 |

- The script's computed delta (1b→1) was 0 because it measured the **second** read. The first, cold read of the same item had already been counted by `1a`.
- **A cold whole-item read by vault ID + item ID costs 2 read requests** (token read +2, account +2).
  - The 2 most likely break down as vault/keyset access plus the item fetch. "Some 1Password CLI commands make more than one request" ([rate-limits docs](https://www.1password.dev/service-accounts/rate-limits)).
- **A repeat read on the same machine costs 0.** op 2.x caches by default on UNIX ("`--cache` … Caching is enabled by default on UNIX-like systems … `OP_CACHE`", from `op --help`). The second get was served from that cache.
- **The 0 is caching, not late accounting.** `1a` was taken seconds after the cold read and already showed +2, so the counter updates promptly.
- **Free calls:** `op service-account ratelimit` (1a→1b = 0) and `op whoami` (`used` was still 0 at `ratelimit-0`) did not count.
- **Granularity:** the token limit counts per action (read 1000/h, write 100/h). The hour window starts at the first request (`reset` 0 → 3599). The account limit is read_write 1000 per 24 h.
- **FR-13 (≤4 requests per environment per release):** partly verified here. One cold whole-item read = 2 ≤ 4, and the free calls above stay free. It **cannot be fully verified here**:
  - CI runners start with an empty cache, so every read is cold.
  - The real flow (`fly sync` / `run` via `op run`) may issue different calls from a bare `op item get`.
- **Recommendation:** verify FR-13 at I5/O2 after the first real release. Run `op service-account ratelimit ci-fleet-prod` before and after the release job (or read the job's own snapshots), and record the delta. Set `OP_CACHE=false` in that job so the number is the worst case.

## Q4: Fly secrets list, digests, staging

Evidence: `fly_list-{0,1,2,3,dotenv,4}.json`, `q4_digest.json`, `fly_import_*.out.txt`, `fly_unset.out.txt` and `fly_deploy.stderr.txt`.

- **List shape:** `fly secrets list --app <app> --json` returns an array of `{name, digest, status}`. There are no timestamps and no value.
  - Source: flyctl `internal/command/secrets/list.go` L36-40 (`SecretWithStatus`).
  - `status` is one of `Deployed | Staged | Partial | Unknown` (list.go L29-34). "Deployed" means `secret updated_at <= machine release created_at` (L53-57).
  - Every secret on the no-machine app showed `Staged`.
- **Digest:** 16 lowercase hex characters.
  - **Stable for an identical value:** re-importing `probe1` gave the same digest (`abbf42e97d95a292` both times).
  - **Changes for a different value:** `probe2` gave `abd0c8276c1dd3e9`.
- **Not computable locally.** None of the candidates matched: sha256, sha1, md5 and sha512 of `value`, `value\n`, `NAME=value` and `NAMEvalue`, each compared as a full hash, a 16-character prefix and a suffix (`computable_locally: false`, `matches_*: []`). The digest is presumably keyed or salted server-side.
- **`fly secrets import --stage` reading stdin:** rc=0 with "Secrets have been staged, but not set on VMs". `--stage` is accepted.
- **`fly secrets unset A B --app <app> --stage`:** rc=0, and the names were gone from the next list (`fly_list-4.json` = `[]`). `--stage` is accepted.
- **`fly secrets deploy` with no machines:** rc=1, with "Error: no machines available to deploy … Try 'fly deploy' first" (`fly_deploy.stderr.txt`). opv must map this to a distinct, typed error (FR-10). It must not be reported as a sync failure of the secrets themselves.
- **No JSON import form exists.** `fly secrets import --help` documents only NAME=VALUE on stdin.

### Consequences (controller ruling P1)

Because digests can't be computed locally, **P1 stage-and-compare is in force** for S4 (fly sync), S6 (status/plan) and the I5/O2 gate:

1. Read the list (digests A).
2. Stage via `import --stage` on stdin.
3. Read the list again (digests B).
4. Compare A and B by name. If every digest is the same, report no change and don't deploy. If any changed, deploy only with `--deploy` (§6.4).

`plan` without staging can only report names: new, managed-but-missing, and prune candidates. It **cannot** report changed values without staging.

**Open question for S4:** whether re-staging an identical value resets `Deployed` to `Staged`. That can't be observed without machines. S4 should rely on the digest comparison, not on `status`.

## Follow-up 2a: how `fly secrets import` parses stdin (flyctl v0.4.112 source)

The digests can't settle this (the dotenv probe matched no candidate, `q4_dotenv.json`), so it comes from source: `internal/command/secrets/parser.go` at `ca63052e` (`parseSecrets`, called from `import.go` L42). There are no escape sequences at all: `\`, `$` and backslash-n are literal.

Lines and comments:

- **L17:** lines come from `bufio.Scanner`, which splits on `\n` and strips one trailing `\r`.
- **L17 and L77:** a line longer than 64 KiB (`bufio.MaxScanTokenSize`) stops the scanner. `scanner.Err()` is never checked, so **the rest of the input is silently dropped** and the call still returns success with whatever was parsed so far.
- **L27:** a line whose first byte is `#`, or that is blank or whitespace-only, is skipped.

Key and value split:

- **L31:** the line is split at the **first** `=`, so `=` inside a value is safe.
- **L35:** the key is `TrimSpace`d.
- **L36:** **leading spaces** (U+0020 only, not tabs) are stripped from the value.

Comments inside the value:

- **L37-40:** if the value contains `#` **and** the text before the first `#` has an **even** number of `"` characters (zero counts as even), the value is cut at that `#` and trailing spaces are trimmed.
- So `pa#ss` is stored as `pa`. Trailing spaces survive only when no cut happens.
- Our probe ` probe-dq"h#x$y\z=w` had one `"` before the `#`, so no cut happened. It would have been stored with only its leading space removed.

Quotes and multiline:

- **L42-45:** a value that starts **and** ends with `"""` (length ≥ 6) becomes its inner text verbatim. Leading and trailing spaces are kept, and so are inner quotes.
- **L46-51 and L62-72:** a value that starts with `"""` but doesn't end with it starts a multiline value. Following lines are joined with `\n` until a line **ends** with `"""`.
- **L53-59:** otherwise, one surrounding pair of `"…"` or `'…'` is stripped.
  - A value that is exactly a single `"` makes `value[1:0]` panic.

### What round-trips unchanged

**Plain form `KEY=V`:** V is stored byte-for-byte only if all of these hold:

- V has no `\n`;
- V doesn't end in `\r`;
- V doesn't start with a space;
- V doesn't start with `"""`;
- V isn't wrapped in matching `"…"` or `'…'`;
- V has no `#`, or has an odd number of `"` before its first `#`;
- the line is under 64 KiB.

**Triple-quoted form `KEY="""V"""`:** V is stored byte-for-byte only if all of these hold:

- V has no `\n`;
- V has no `#`, or has an **even** number of `"` before its first `#`;
- the line (key + `="""` + V + `"""`) is ≤ 65 535 bytes.

The `"""` prefix stops leading spaces from being stripped (L36). The suffix check means trailing spaces, quotes, `\r`, `'`, `$`, `\`, `=` and inner `"""` are all kept.

### Recommendation for S4

- **Encoding:** always emit `KEY="""V"""\n`. Before staging, refuse any value that breaks one of the four rules below. Each rule failure names the key and the rule, never the value (FR-15). Fail the whole sync before anything is staged.
- **Rules:**
  1. `import-newline`: the value contains `\n`. Multiline values are out of scope for v0.1. The `"""` multiline form can't express a value whose own line ends in `"""`, and it would need its own proof.
  2. `import-hash-after-odd-quotes`: the value contains `#`, and the number of `"` before its first `#` is odd.
  3. `import-line-too-long`: the encoded line is longer than 65 535 bytes. A silent partial import is the worst outcome here, because the digests can't reveal it. To be safe, cap values at 60 000 bytes.
  4. `import-invalid-utf8`: the value is not valid UTF-8. flyctl sends values as JSON, and Go's encoder replaces invalid bytes with U+FFFD.
- **Why it matters:** the values for every rule fit in one byte-level check in the domain layer, which can be unit-tested with no `flyctl`. P1's compare **can't** detect a mangled value: it only sees that the digest changed, not what the value became. So the encoding has to be correct by construction.
- **What rule 2 still allows:** `#` with zero or an even number of `"` before it, such as connection strings with `#fragment`.

## Follow-up 2b: why the rate-limit deltas were 0

These are the Q3 results above:

- The measured read was a cache hit. The cold read cost 2 and had already been counted by `ratelimit-1a`.
- `op service-account ratelimit` and `op whoami` are free.
- The counter updates within seconds, so this is not late accounting.

Verify FR-13 in CI at I5/O2 with `op service-account ratelimit ci-fleet-prod` (before and after, with `OP_CACHE=false`). This spike's local number is a lower bound for a cold read.
