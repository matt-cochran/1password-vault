# Owner value ingestion: matched sets and in-memory producers (#262, #253)

Status: draft design for 0.18.0, 2026-11-04, cut from `dev` at opv 0.17.2 (`7cc0b6dd`). Not yet
vetted by the DESIGN-FMECA review; owner decisions in §8 are open. Code is not changed by this
document.

Evidence convention: `file:line` points at the 0.17.2 tree. Claims marked **(inferred)** are about
behaviour opv does not own (the `op` CLI, the 1Password service, the kernel) and were not
re-verified against a live account for this document; §11 lists them for the FMECA reviewer.

## 1. Summary

One new person-only command, `opv provision <SET> --env <ENV>`, fills a **set**: a group of
declared keys whose values must be made together, agree with each other, and land in 1Password in
one write. A set is declared in the committed contract, value-free. Each member's value comes from
one of three places:

- `generate`: opv's own CSPRNG (the existing `opv generate` recipes, plus a prefixed token form for
  public identifiers);
- `producer`: an external program the contract names, spawned by opv, speaking a new
  `opv.produce/1` protocol over pipes (request on its stdin, result on its stdout, stderr held and
  scrubbed); this is #253's OAuth consent helper;
- `template`: a JSON document built from other members (#262's site-secret bundle).

Every value is made in memory, checked against every destination key's rules and the set's own
rules, and written in **one `op item edit` of one item**, guarded by a version check before and
after. A set may only span one 1Password item (one access boundary), because 1Password offers no
cross-item transaction (§4.6); the contract makes this a load error, not a runtime surprise.

**One mechanism covers both issues.** #253 is a one-member (or few-member) set whose member comes
from a producer; #262 is a nine-member set from generators and a template, optionally with
producer members for provider-issued pairs. Both need the same refusals, the same plan, the same
single checked write and the same value-free receipt.

## 2. The problems

### 2.1 #262: a matched set cannot be provisioned atomically

Zonetico/Journeeze staging needs nine values that must be made once and agree: a versioned
site-secret bundle, three public site keys each paired with an identity secret, a gateway signing
key, and a user-hash key. The bundle must contain exactly the component values. Today a person
either runs nine `opv set` prompts (easy to mismatch, and the bundle must be hand-assembled from
values the person is not supposed to see) or writes a script around raw `op item edit` (bypasses
opv's rules, receipts and argv/file custody). The gap was found only by release-time `opv sync`
(infra run 40770821491), the first command that checked the contract's nine bindings.

### 2.2 #253: a person-owned producer cannot hand a value to opv

An owner-operated Workspace Admin connector obtains a refresh token in memory after a PKCE OAuth
consent. Every current way into 1Password needs the value to pass through something the custody
rules forbid: a terminal (masked `opv set`, which needs the person to see and paste it), a file
(`--from-file`, `import --from <dotenv>`), or a never-stored channel (`sync --supply-stdin`, which
by design does not write 1Password). The connector currently must refuse before consent.

### 2.3 What exists today

| Capability | Where | What it does | Why it does not cover the issues |
|---|---|---|---|
| `opv set <KEY> --env E` | `src/app/set.rs:41-94` | one masked value; refuses an agent marker (`:57`) and a non-TTY (`:58-63`); checks rules (`:75-84`); writes through the importer (`:85-91`) | one value; the person types it; no matching across keys |
| `opv set … --from-file` | `src/app/set.rs:105-166` | one file key's exact bytes from a regular file, 64 KiB cap (`:26`, `:227-270`) | needs a value file on disk (#253 forbids) |
| `opv apply --generate E:p/K` (`opv generate`) | `src/app/generate.rs:60-85` (recipe), `:98-109` (CSPRNG), `:124-178` (run) | CSPRNG `base64_bytes`/`hex_bytes` values; refuses a field that already holds a value (`:137-145`); requires a person's session (`:135`); one write per boundary item | no template, no public prefixed tokens, no producer; per-key, not per-set; no partial-set notion |
| `opv import E --from <dotenv>\|target:` | `src/app/import.rs:39`, `:330-379` | values from a file or a readable target; `--confirm <env>` for production tier (`:238-241`); requires a person (`:320`, `:341`) | a file, or values already elsewhere |
| `opv_import_local` (MCP) | `src/mcp.rs:385-402`, `src/app/import_local.rs:1-7` | an assistant may import into a `local`-tier environment only, tagging items `assistant_imported` | precedent only: assistant writes are confined to local tier |
| `opv sync E --supply-stdin` | `docs/design/deliver-only.md` §3; parser `src/app/deliver_only.rs:205-213`, bounded read `:217-262`, deadline reader `:272-300`; schema text `src/schema.rs:522` | infrastructure values on stdin as `opv.supply/1`, never written to 1Password | by design never stores a value; CI-oriented (stdin must not be a TTY) |
| The item writer | `src/app/import.rs:384-416` (`write_values`), `:447-528` (`write_item`) | groups writes by boundary item; one fresh read (`:456`); builds a whole-item JSON template; keeps a replaced value in `opv · kept` (`:461-475`); one `op item edit` (`:503`); reads back and compares each written field | **no version check**: unlike the tidy, it never compares the item's version before or after the edit (inferred from reading `:447-528`; no `version` reference in the function) |
| `op item edit` | `src/adapters/onepassword_tidy.rs:373-411` | `op item edit <id> --vault <v> --format json` with the whole item JSON on **stdin**; echoed item registered with the scrubber (`:394`); exit status unknown ⇒ `unfinished_write` (`:408-409`, comment "One atomic edit") | per item only |
| Tidy's optimistic check | `src/app/tidy.rs:635-678` | re-reads, compares the `(version, updated_at)` stamp (`:637`), writes, then requires exactly `version + 1` (`:667-679`), else `ConcurrentEdit` | detection after the fact, not prevention (§4.6) |
| Person/identity checks | `src/host.rs:139-160` (agent markers), `:170-175` (`refuse_if_agent`), `:85-95` (MCP mode, "presentation only, never a security control"); `src/app/tidy.rs:117-132` (`identity_on`), `:157-185` (`require_person_on`) | agent marker ⇒ `PersonOnly`; CI, service account, Connect, deploy credentials ⇒ `NeedsTerminal`/`NeedsOwnSession` | `opv set` checks agent + TTY but **not** identity (no `require_person` call in `set.rs`): a person's terminal with `OP_SERVICE_ACCOUNT_TOKEN` exported can `opv set` under the service account (inferred from `set.rs:41-94`; see D9) |
| Structure approval (FR-61) | `docs/design/requirements.md` FR-61 | `opv_structure_apply` refuses `OP_SESSION_*`, `OP_SERVICE_ACCOUNT_TOKEN`, `OP_CONNECT_*` in its environment "so writes go through the 1Password app's authorization" | precedent for the production rule (D6) |
| Child process hygiene | `src/runner.rs:945-975` (`isolated_env`, cleared env for non-`op` children), `:1799` (`strip_session_vars`); `src/hardening.rs:9` (non-dumpable, soft `RLIMIT_CORE=0`) | | reused for the producer |
| Scrubber | `src/scrub.rs:1-20`, `:533` | registered values and patterns masked in child stderr | reused for producer stderr |
| Key sources | `src/domain/model.rs:221-232`, validated `src/config.rs:2099-2115` | `source = person \| generated \| derived \| infrastructure` | a set member gets `source = "provisioned"` (§3.2) |
| Boundaries | `src/domain/model.rs:734-777`; FR-57 | one values item per access boundary; by default one boundary per product; `boundary = "<group>"` shares one | a set must fit one boundary (§4.6) |

Architecture guards any design here must respect: FR-37 `core_modules_name_no_provider`
(`src/app/mod.rs:2313`; `provider_named` word list `:2280-2300`) and FR-12
`use_cases_name_no_target_adapter` (`src/app/mod.rs:2128`), both scanning `src/app` and
`src/domain` production code; the `Observed` seal (`tests/observed_seal.rs`: only the runner calls
`Observed::from_failed_call`/`from_unusable_reply`); and the global registration tests of the error
catalog (`docs/design/error-catalog.md` §11, §13.4: every variant renders, every `Next` parses,
every variant reached by an e2e cell, generated docs table).

## 3. The contract (committed, value-free)

### 3.1 Sets and producers

Sets live in the contract (`secrets.toml`, or the manifest under FR-44), so `plan`, `ready` and
`sync` know them too (D2). Example for #262:

```toml
[products.journeeze-shared]          # a source-only product (FR-47): one boundary, one item
source_only = true

[products.journeeze-shared.keys.GATEWAY_SIGNING_KEY]
kind = "secret"
source = "provisioned"
rules = { base64_bytes = 32 }
immutable = true

[products.journeeze-shared.keys.SITE_A_KEY]      # public: may be shown
kind = "config"
source = "provisioned"
rules = { regex = "jz_site_[A-Za-z0-9]{22}" }

[products.journeeze-shared.keys.SITE_A_SECRET]
kind = "secret"
source = "provisioned"
rules = { hex_bytes = 32 }

# … SITE_B_*, SITE_C_*, USER_HASH_KEY likewise …

[products.journeeze-shared.keys.SITE_SECRET_BUNDLE]
kind = "secret"
source = "provisioned"
rules = { regex = "\\{.+\\}" }

[sets.journeeze-site]
product = "journeeze-shared"
environments = ["staging", "prod"]

[sets.journeeze-site.members]
GATEWAY_SIGNING_KEY = { generate = "rules" }                     # recipe from the key's rules
USER_HASH_KEY       = { generate = "rules" }
SITE_A_KEY          = { generate = { token = "base62", bytes = 16, prefix = "jz_site_" } }
SITE_A_SECRET       = { generate = "rules" }
# … B, C …
SITE_SECRET_BUNDLE  = { template = { version = 1, gateway = "${GATEWAY_SIGNING_KEY}", user_hash = "${USER_HASH_KEY}", sites = [
  { key = "${SITE_A_KEY}", secret = "${SITE_A_SECRET}" },
  { key = "${SITE_B_KEY}", secret = "${SITE_B_SECRET}" },
  { key = "${SITE_C_KEY}", secret = "${SITE_C_SECRET}" },
] } }

# Consumers read the set's fields; they never get their own copies (FR-45):
[products.journeeze-gateway.keys.GATEWAY_SIGNING_KEY]
from = "journeeze-shared/GATEWAY_SIGNING_KEY"
```

Example for #253:

```toml
[products.workspace-admin.keys.ADMIN_REFRESH_TOKEN]
kind = "secret"
source = "provisioned"
rules = { regex = "[!-~]{20,}" }
environments = ["prod"]

[products.workspace-admin.keys.ADMIN_GRANTED_SCOPE]
kind = "config"
source = "provisioned"
rules = { enum = ["https://www.googleapis.com/auth/admin.directory.user.alias"] }
environments = ["prod"]

[producers.workspace-consent]
command = ["python3", "tools/workspace_consent.py"]   # argv, no shell, no values; relative to the project
outputs = ["refresh_token", "granted_scope"]
inputs  = { client_id = "workspace-admin/OAUTH_CLIENT_ID" }   # D5: same-environment keys only
open_url_hosts = ["accounts.google.com"]
timeout = "10m"

[sets.workspace-admin-consent]
product = "workspace-admin"
environments = ["prod"]

[sets.workspace-admin-consent.members]
ADMIN_REFRESH_TOKEN = { producer = "workspace-consent", output = "refresh_token" }
ADMIN_GRANTED_SCOPE = { producer = "workspace-consent", output = "granted_scope" }
```

Provider and vendor words appear only in the contract (user data), never in `src/app` or
`src/domain` code, so FR-37's guard is unaffected.

### 3.2 Load rules (`config_invalid`, before any command runs)

| Rule | Field rule | Why |
|---|---|---|
| a set's `product` is declared and every member is a key of it | `NotDeclared` | one boundary, known at load |
| each member key declares `source = "provisioned"`, and every `source = "provisioned"` key is a member of exactly one set | `Missing` / `ConflictsWith{set}` | nothing fills such a key another way (`set`, `import`, `generate` refuse it, §5.6); no key is in two sets |
| the set's `product` resolves to **one boundary** in each listed environment; `from` consumers live elsewhere | `Type{"a set fills one 1Password item"}` | §4.6, D1 |
| member key is not `personal`, not `from`, not `source = infrastructure`, not in a `source_only=false` product with targets that cannot hold it (existing rules) | `ConflictsWith{…}` | a provisioned value is a team value stored in 1Password |
| `environments` of the set ⊆ each member's environments; no member `except`ed in a set environment | `Type{"member not present in <env>"}` | no half-wanted set |
| `generate = "rules"` only on a key whose rules give a recipe (`generate::recipe`, `generate.rs:60`); `generate = {token, bytes, prefix}`: `token ∈ {base62, hex, base64url}`, `bytes ∈ 16..=64`, prefix printable ASCII ≤ 32 | `Type{…}` | generators are closed, CSPRNG-only |
| `template`: TOML table/array/scalars; a string leaf is either a literal (no `${`) or exactly `"${MEMBER}"` naming another member of the same set; no partial interpolation; references form no cycle; a template member is `kind = "secret"` when any referenced member is secret | `Type{…}` | escaping is done by the JSON writer, never by string splicing (§5.3) |
| `producer` names a declared `[producers.X]`; `output` is in its `outputs`; every output of a producer used by a set is used by exactly one member of that set | `NotDeclared` / `Type{…}` | a producer's whole result is accounted for |
| `[producers.X].command`: non-empty array of strings, first element a program name or a path relative to the project; no element matches the scrubber's secret patterns (`scrub::scrub_patterns`); `inputs` name keys of the **same product's boundary**, `kind = "config"` unless D5 allows secrets; `open_url_hosts` are host names; `timeout` ≤ 30 min | `Type{…}` | SR-7: no shell strings; a token pasted into argv is caught at load |
| no `allow_same_value` on a member | `ConflictsWith{set}` | §5.5 compares across environments |

`source = "provisioned"` is a fifth value of the existing attribute
(`src/domain/model.rs:221-232`). An opv before 0.18 refuses the contract at load (unknown variant),
so an old binary fails loudly; pins must move first (as `deliver-only.md` §2.2 S13).

## 4. Command surface and semantics

### 4.1 CLI

```
opv provision <SET> --env <ENV> [--dry-run] [--json]
              [--fill-missing | --replace] [--expect-plan <ID>]
```

- `--dry-run`: the plan only (§4.3). Reads 1Password (to report the set's state), runs no producer,
  makes no value, writes nothing. Allowed for an assistant and in CI (it is a read).
- `--fill-missing`: recovery for a partial set (D7).
- `--replace`: re-make the whole set (explicit rotation, D8); old values are kept in `opv · kept`
  by the existing writer (`import.rs:461-475`). Refused when any member is `immutable` (FR-16).
- `--expect-plan <ID>`: refuse (`stale_plan`) unless the recomputed plan id matches the one a person
  reviewed in a dry-run (FR-41 pattern).
- No `--yes`, no `--confirm` flag: the confirmation is typed at the prompt (§4.4).
- MCP: one read-only tool, `opv_provision_plan {set, env}`, returning the dry-run document. No MCP
  write tool exists (D3).

### 4.2 Order of operations

Each step runs only if every earlier one passed; nothing is written before step 11.

1. **Load** the contract (§3.2 load rules).
2. **Resolve** `<SET>` and `--env`: set declared, environment in the set's `environments`.
3. **Who is running** (§6): agent marker ⇒ `PersonOnly`; CI ⇒ `NeedsTerminal{Ci}`; not a TTY ⇒
   `NeedsTerminal{NoTty}`. (`--dry-run` skips this step.)
4. **Identity** (`require_person_on`): service account, Connect, deploy credentials ⇒
   `NeedsOwnSession`. For a production-tier or `confirm_env` environment, additionally refuse when
   `OP_SESSION_*`, `OP_SERVICE_ACCOUNT_TOKEN` or `OP_CONNECT_*` is in opv's environment (D6).
5. **Read** the set's item fresh (`read_whole_fresh`): stamp `S0 = (version, updated_at)`.
   Unprovable item layout (`onepassword_tidy::unprovable`) ⇒ refuse (the whole-item edit could drop
   a field).
6. **Classify** the set (§4.5): `absent`, `complete`, `partial`, `inconsistent`. `complete` without
   `--replace` ⇒ print `unchanged` and exit 0 (no producer runs, nothing is made). `partial`
   without `--fill-missing`/`--replace`, or `inconsistent` without `--replace` ⇒ refuse.
7. **Plan and confirm** (§4.3, §4.4). Plan id `pv-<16 hex>` = SHA-256 over: set name, environment,
   account id, item id, `S0.version`, the canonical text of the set and producer declarations, the
   mode, the members to be made. `--expect-plan` mismatch ⇒ `PlanChanged`.
8. **Produce** (§5.2): run each producer the plan needs, once, in declared order.
9. **Generate** (§5.1) and **render templates** (§5.3), in dependency order.
10. **Validate** in memory, all before the write (§5.4, §5.5): every member against its key's rules;
    every template round-trips; cross-environment distinctness. Any failure ⇒ refuse, nothing
    written, every value dropped (zeroized).
11. **Commit** (§4.6): re-read, check the stamp, one `op item edit`, verify version and fields.
12. **Receipt** (§7): names, states, item revision, provision id. Never a value.

### 4.3 The plan (also the `--dry-run` output)

Names, generators, destinations and edges only:

```
opv provision journeeze-site --env staging   (plan pv-3f9c0a1b2c4d5e6f)
  item   journeeze · journeeze-shared · staging values   (vault journeeze-journeeze-shared-staging, version 14)
  state  absent (0 of 9 members set)
  make   GATEWAY_SIGNING_KEY   generate base64, 32 random bytes      secret
         SITE_A_KEY            generate base62 token, 16 bytes, prefix jz_site_   config (shown after write)
         SITE_A_SECRET         generate hex, 32 random bytes          secret
         …
         SITE_SECRET_BUNDLE    template ← GATEWAY_SIGNING_KEY, USER_HASH_KEY, SITE_A_KEY, SITE_A_SECRET, …
  read by journeeze-gateway/GATEWAY_SIGNING_KEY (from), journeeze-web/SITE_SECRET_BUNDLE (from), …
  write  one edit of one item; nothing else in the item changes
```

For a producer member the `make` column reads `producer workspace-consent → refresh_token` and the
plan lists the producer's command words and declared inputs by key name.

### 4.4 Confirmation

After the plan, opv asks on the terminal: `Type the environment name to provision <SET> in it:`.
The answer must equal `--env` exactly (production and non-production alike; a set write is never a
routine step). A wrong answer ⇒ `ConfirmMismatch`, nothing run; Ctrl-C or empty ⇒ `Declined`
(exit 0). The prompt reads the terminal through the existing masked-prompt module
(`src/app/masked.rs`) in visible mode; it never reads opv's stdin if stdin is not a TTY (step 3
already refused).

For a set with a producer, confirmation happens **before** the producer runs: the person agrees to
the write first, then completes consent.

### 4.5 Set states (also used by `ready`)

Computed in memory from the fresh item, never printed except as the state word and member names:

| State | Condition |
|---|---|
| `absent` | no member field holds a value |
| `complete` | every member holds a value that passes its rules, **and** every template member parses as JSON whose `${…}` leaves equal the referenced members' stored values and whose literal leaves equal the template's literals |
| `partial` | some but not all members hold a value |
| `inconsistent` | every member holds a value, but a template does not match its members, or a value fails its rules |

The comparison is an equality fact, the documented SR-1 exception (#92), never a value, length or
digest.

### 4.6 What 1Password can and cannot guarantee, and the commit

**Can (inferred, relied on since FR-43):** one `op item edit` of one item with the whole item JSON
on stdin is applied as one item revision: afterwards the item is either at its previous version or
at the next version with every field of the template. opv already depends on this
(`onepassword_tidy.rs:408-409`; FR-43 acceptance "an interrupted write leaves the item untouched or
fully tidied"). The service keeps every previous version in the item's history, restorable by a
person in the 1Password app.

**Cannot (inferred):**
- **No compare-and-swap.** `op item edit` has no "only if version is N" precondition. opv can
  detect a concurrent edit (re-read before, version + 1 after) but cannot prevent one landing
  between its last read and its write. Because the edit sends the whole item, such an edit is
  overwritten; it survives only in the item's history. This is the tidy's existing limit
  (`tidy.rs:667-679`, NR-8 "detect, don't lock").
- **No cross-item transaction.** Two `op item edit` calls are two independent revisions; a failure
  or interruption between them leaves one written and one not, and "rolling back" the first is a
  third write that can itself fail or race.
- **No restore-version command** in `op` that opv could call (inferred); only the app restores
  history.

**Design consequence: a set fills exactly one item** (load rule §3.2; D1). Members that other
products need are read there with `from` (FR-45), so "matched across product fields" is achieved by
reading one field, not by copying it. Within that one item the commit is:

1. Re-read the item fresh: `S1`. If `S1 ≠ S0`:
   - if every member field is unchanged since `S0` (same presence, and for `--fill-missing` the same
     present values), re-plan on the fresh item and continue (the setup precedent, SR-5), so a
     person who spent minutes in an OAuth consent does not have to consent again because an
     unrelated field changed;
   - otherwise refuse `ChangedBeforeWrite`; nothing written; values dropped.
2. Build the whole-item template from `S1` (existing `onepassword_tidy::apply` with `Op::SetValue` /
   `Op::Add`, `kept` for `--replace`), plus one value-free marker field in the `opv` section
   (`MARKER_SECTION`, `convention.rs:55`): label `set <SET>`, text
   `prv-<26 base32> spec <12 hex of the set declaration text> <YYYY-MM-DD>`.
3. One `op item edit` (`onepassword_tidy::write`).
4. Verify: the echoed (or freshly re-read) version must be `S1.version + 1`, else `ConcurrentEdit`
   (the set was written but another edit landed in the same window; named with the item-history
   pointer). Then `lost()` (nothing opv wrote or kept is missing) and every member field equals the
   in-memory value, else `ReadBackMissing`.
5. **Unknown outcome** (timeout, kill, lost reply after the edit was sent): read back once
   (`NR-2`). Version `S1` and members unchanged ⇒ nothing was written; report `WriteOutcomeUnknown`
   resolved as "not written; safe to re-run". Version `S1 + 1` and every member equals the in-memory
   value ⇒ success. Anything else ⇒ exit 9 `WriteOutcomeUnknown` naming the set's state as found;
   because the edit is atomic, the found state is `absent`, `complete` or the prior state, never a
   new partial.

This is a new checked writer, `provision_commit`, not a reuse of `import::write_item`, because the
latter has no version check (§2.3).

**Producer values after a failed commit.** A refresh token that was minted and not stored is still
valid at its issuer. Every failure after step 8 that leaves it unstored prints a fixed Do: "the
producer's credential was not stored; revoke the grant at the issuer before re-running", with no
value. opv cannot revoke it (it holds no issuer credential and must not).

## 5. Making the values

### 5.1 Generators

- `generate = "rules"`: exactly `generate::recipe` + `generate::make` (`generate.rs:60-109`):
  `base64_bytes`/`hex_bytes`, 16..=1024 bytes, from `getrandom`.
- `generate = {token, bytes, prefix}`: `bytes` from `getrandom` encoded `base62` (fixed-length,
  unbiased by rejection sampling), `hex` or unpadded `base64url`, after `prefix`. Used for public
  identifiers such as site keys.
- Every generated value is a `SecretValue` registered with the scrubber (`Kind::Secret` for secret
  keys, `Kind::Setting` for config keys) as it is made.

### 5.2 Producers: the `opv.produce/1` protocol

A producer is a program a person declared in the contract and opv starts as a **runner effect**
(`CommandRunner::produce`), like the HTTPS effect (`http-target.md` §5), so the run budget, signal
forwarding (NR-12), the verbose line, and the sealed `Observed` (only the runner builds it) apply.

**Spawn.**
- argv: exactly `command` from the contract (structured, SR-7); never a value.
- cwd: the project directory.
- environment: cleared, then opv's basics (`host::is_basic_env`) plus `BROWSER`, `DISPLAY`,
  `WAYLAND_DISPLAY`, `XDG_RUNTIME_DIR` if set (so the helper can open a browser); `OP_SESSION_*`,
  `OP_SERVICE_ACCOUNT_TOKEN`, `OP_CONNECT_*` and every provider credential variable are never
  passed (reuses `runner::isolate` and `strip_session_vars`, `runner.rs:966`, `:1799`).
- stdin, stdout, stderr: three pipes owned by opv. The producer never gets the terminal: it cannot
  prompt the person, and nothing it prints reaches the screen unfiltered.
- Unix `pre_exec`: hard and soft `RLIMIT_CORE = 0`; new process group so Ctrl-C reaches it through
  opv's forwarding only. (The producer's own memory hygiene is its own; see §9.)
- Program resolution: a relative path in `command[0]` must be a regular file inside the project,
  not group/world-writable; a bare name is resolved on `PATH` and named in the plan.

**Request** (opv → producer stdin, one JSON line, then stdin is closed):

```json
{"schema":"opv.produce/1","kind":"request","env":"prod","set":"workspace-admin-consent",
 "outputs":["refresh_token","granted_scope"],"nonce":"n-6f1c…(26 base32)",
 "inputs":{"client_id":"…"}}
```

`nonce` is 128 fresh random bits per run. `inputs` holds only the declared input keys of the same
environment (D5); the request buffer is `Zeroizing` and wiped after the write to the pipe.

**Response** (producer stdout): newline-delimited JSON objects, at most 1 MiB in all.

- zero or more notices: `{"schema":"opv.produce/1","kind":"notice","open_url":"https://…"}` or
  `{"schema":"opv.produce/1","kind":"notice","waiting":true}`. opv prints a fixed sentence for
  each ("open this address to give consent: <url>"; "waiting for the producer"). `open_url` must be
  `https`, its host in `open_url_hosts`, at most 2048 bytes, no userinfo; anything else is refused.
  No free text from the producer is ever displayed while it runs.
- exactly one result, last:
  `{"schema":"opv.produce/1","kind":"result","env":"prod","nonce":"n-6f1c…","outputs":{"refresh_token":"…","granted_scope":"…"}}`

**Admission** (all before the producer's values are used):

| Check | Refusal |
|---|---|
| producer exits 0, after the result, within `timeout` and the run budget | `ProducerFailed{producer, exit}` / `Timeout` |
| every line is one JSON object with `deny_unknown_fields`, `schema = opv.produce/1` | `InputInvalid{kind: Produce, rule}` by line number, never serde's text (as `deliver-only.md` §3) |
| exactly one `result`, the last line | `NoResult` / `ResultNotLast` |
| `env` equals `--env`; `nonce` equals this run's | `WrongEnvironment` / `NonceMismatch` (a replayed or cached document) |
| `outputs` keys = the producer's declared `outputs` used by the set, each once (custom map visitor, as the supply parser) | `Undeclared` (by position) / `Missing{names}` / `Duplicate` |
| values: non-empty JSON strings, no NUL, ≤ 64 KiB each | `Empty` / `NotAString` / `TooLarge` |

Each value is registered with the scrubber **as it is parsed** (as `deliver_only::parse`). The
parser reuses the supply stream code (bounded read, deadline reader, zeroizing buffers, duplicate
detection), extracted into a shared module (lane L4).

**stderr.** Read into a bounded (64 KiB, last bytes kept), zeroizing buffer; never shown while the
producer runs. On success it is wiped unseen. On failure, the last ≤ 5 lines are shown as
`producer said:` **after** any parsed values have been registered, through `scrub::scrub` (values,
then patterns), escape-stripped and cut at 240 characters (NR-31). With `--verbose`, the same
scrubbed lines and stdout's shape (never content).

### 5.3 Templates

A template is rendered by a small JSON writer into a `Zeroizing<Vec<u8>>`: objects in declared
order, literals as given, each `${MEMBER}` leaf written as a JSON string with `serde_json`'s string
escaping applied directly from the member's `SecretValue` into the buffer. No intermediate
`serde_json::Value` holds a secret (SR-8). The result is then parsed back and every reference leaf
compared to its member (round-trip check). The rendered bytes are the member's value; they are
checked against that key's rules like any other member.

### 5.4 Validation (step 10)

All of these, collected, so a refusal names every failing member at once (NR-17):

- each member against its key: `rules::check` (or `check_verbatim` for a `file` key), every rule
  counted (a person runs it), placeholders refused;
- each template round-trips (§5.3);
- each member's value is at least `SECRET_MIN` (8) bytes when `kind = "secret"`, so the output guard
  can mask it.

A failing member is named with the rule only (`malformed{regex}`), never its value or length.

### 5.5 Production and staging stay distinct

- The environment is one flag, echoed by the producer and checked; the prompt makes the person type
  it.
- No spec construct reads another environment's value: references (`${…}`, `inputs`) resolve only
  within this run's set and this environment's item.
- After validation, opv reads the same member fields in **every other environment of the set** that
  the person can read, and refuses `SameAcrossEnvironments{member, env}` if any new value equals one
  stored there (an equality fact, SR-1 #92 exception). An environment the person cannot read is
  named as "not compared" in the plan and receipt; it never blocks.

### 5.6 What the other write commands do with a provisioned key

`opv set`, `opv set --from-file`, `opv import` and `opv apply --generate` refuse a
`source = "provisioned"` key with `Guard::ProvisionedKey{set}`, Next `opv provision <set> --env E`.
A matched value written alone would make the set `inconsistent`.

## 6. Refusal rules

| Situation | Refused at | Cause | Real control or friction |
|---|---|---|---|
| MCP | no tool exists for the write; `opv_provision_plan` is read-only | — | structural |
| CI (`CI`/`GITHUB_ACTIONS` truthy) | step 3 | `NeedsTerminal{Ci}` | friction; CI also has only a service account (below) |
| Agent marker (`OPV_AGENT`, `CLAUDECODE`, …) | step 3 | `PersonOnly`, handing the exact command to the person | friction only: markers are under the caller's control (`host.rs:85-95`, error catalog §9.1) |
| stdin or stdout not a terminal | step 3 | `NeedsTerminal{NoTty}` | friction |
| `OP_SERVICE_ACCOUNT_TOKEN` / Connect set, or `op whoami` says service account | step 4 | `NeedsOwnSession` | **real**: the write would be the service account's, and CI never writes (SR-5) |
| deploy credentials signed in | step 4 | `NeedsOwnSession` | real (same) |
| production tier / `confirm_env`, with `OP_SESSION_*` or a token in the environment | step 4 | `NeedsOwnSession{…without OP_SESSION_*}` | narrows: the write goes through the app or a sign-in opv itself prompts for (D6) |
| wrong typed environment | step 7 | `ConfirmMismatch` | friction against mistakes |
| vault access | 1Password | `MissingRight` | **real**: the only permission system (owner principle) |

What actually stops an assistant running as the same user in the person's own terminal is the same
as for every opv write (error catalog §9.1): 1Password's authorization of the session and vault
grants. The terminal, marker and typed-confirmation rules prevent unattended and accidental writes;
the document and the docs say plainly that they are not a boundary against a same-user process.

## 7. Receipts and evidence (value-free)

`--json` prints one document (also written as the success output in text form):

```json
{"schema":"opv.provision/1","set":"journeeze-site","env":"staging","plan_id":"pv-3f9c…",
 "provision_id":"prv-…","mode":"absent","result":"written",
 "item":{"vault_id":"…","item_id":"…","version_before":14,"version_after":15},
 "members":[{"key":"journeeze-shared/GATEWAY_SIGNING_KEY","made_by":"generate","state":"set"},
            {"key":"journeeze-shared/SITE_A_KEY","made_by":"generate","state":"set","public":true},
            {"key":"journeeze-shared/SITE_SECRET_BUNDLE","made_by":"template","state":"set"}],
 "producers":[{"name":"workspace-consent","exit":0}],
 "compared_environments":["prod"],"not_compared":[],
 "next":"opv plan staging"}
```

- `result`: `written`, `unchanged`, `declined`, or a refusal code.
- No value, length, digest or prefix of a value. Public (`kind = "config"`) members are **not**
  included either; a person reads them with `opv explain` / 1Password (keeps one rule: the receipt
  has no values).
- The marker field (§4.6 step 2) is what `opv ready` reads: `ready` reports per declared set its
  state (§4.5) and `provision_id`; a `partial` or `inconsistent` set is a `keys_blocking` finding
  naming `opv provision <set> --env <env> --fill-missing|--replace`. This is what moves #262's
  detection from release-time `sync` to `ready`.
- `version_after` is the revision normal plan-bound delivery and verification build on (#253's
  "metadata-only results identify the written keys and revisions").

## 8. Owner decisions

Each is independent; recommendations are consistent with each other.

**D1. Can a set span more than one 1Password item?**
Situation: each product has its own item by default (FR-57). 1Password writes one item atomically
but has no transaction across items (§4.6).
- A. One item per set, refused at load otherwise. Matching fields elsewhere are read with `from`.
  In practice: Journeeze's nine values go in one product (a source-only "shared" product) and the
  consuming products declare `from` keys. All-or-nothing is real.
- B. Several items, written one after another; on a failure opv writes back the earlier items'
  previous contents (compensation). In practice: no restructuring, but a crash or a racing edit
  between writes leaves a partial set that opv can only report (`stuck_partial`, exit 9) and a person
  repairs from item history; compensation is a write that can itself fail.
Recommendation: **A.** It gives the guarantee the issue asks for without promising one 1Password
cannot keep; B's failure mode is exactly the mismatch #262 exists to prevent.

**D2. Where is the set declared?**
- A. In the contract (`[sets.*]`, `[producers.*]` in `secrets.toml` / the manifest). `ready`, `plan`
  and `sync` know the set, so a partial set is caught at `ready`.
- B. A separate committed file passed as `opv provision <file>`. In practice: other commands do not
  know sets; partial sets are still found only by `sync`.
Recommendation: **A**, because the reported failure was late detection.

**D3. One command, or propose/apply?**
- A. `opv provision <SET> --env E` with `--dry-run` and `--expect-plan`; assistants get only the
  read-only `opv_provision_plan` MCP tool.
- B. `opv propose provision …` prints a plan id; `opv apply <plan_id>` writes. In practice: fits the
  structural flow's shape, but `apply` today runs structural plans and records approvals for 15
  minutes; values are made only at write time anyway, so the extra step adds a second command
  without adding a check `--expect-plan` lacks.
Recommendation: **A.**

**D4. Producer protocol: reuse `opv.supply/1` or a sibling `opv.produce/1`?**
- A. New `opv.produce/1`: a request on stdin with a nonce, notices, one result, names are the
  producer's declared outputs. Shares the supply parser's code.
- B. Reuse `opv.supply/1` verbatim (names `product/KEY`, `serial`). In practice: one schema, but
  `opv.supply/1` means "never stored" everywhere in docs and receipts, it has no nonce (a saved
  document could be replayed), and no way to show a consent URL.
Recommendation: **A.**

**D5. May a producer receive inputs from 1Password?**
Situation: an OAuth helper needs its client id (and, for some issuers' "desktop" clients, a
non-confidential client secret). Without inputs it must read them from a file or environment,
which the custody rules forbid.
- A. Declared `inputs`, same environment and same item only, on the request over stdin;
  `kind = "config"` keys only.
- B. As A, also `kind = "secret"` keys.
- C. No inputs.
Recommendation: **B**, limited to keys in the same set's item and environment and listed in the
plan by name: the helper is the person's own program, and the alternative is a file or environment
variable. If the owner prefers the narrower start, A.

**D6. How strict is a production write?**
- A. Typed environment name (all environments) **plus**, for production tier or `confirm_env`,
  refusing `OP_SESSION_*` and token variables in opv's environment (FR-61's rule), so the write uses
  the desktop app's authorization or a sign-in opv itself prompts for. In practice: a WSL person who
  ran `eval "$(opv login --shell)"` opens a fresh shell (or unsets the variable) for production
  provisioning.
- B. Typed environment name only.
Recommendation: **A**: it costs one extra step for production only and is the one rule here that
narrows what a same-user agent with an exported session can do.

**D7. Recovering a partial set.**
- A. `--fill-missing`: keep present members, make only missing ones, re-render templates from the
  stored plus new values. Refused when a present template references a missing member (the
  template would have to change). Producers run only if one of their outputs is missing.
- B. Only `--replace` (re-make everything).
In practice: A avoids rotating values already deployed; B is simpler but rotates live values to fix
a gap. Recommendation: **A, plus B's `--replace`** for the inconsistent case.

**D8. Rotation (`--replace`) in 0.18.0?**
- A. Yes: whole-set replace, old values kept in `opv · kept`, refused for `immutable` members.
- B. Defer; 0.18.0 only fills absent and partial sets.
Recommendation: **A**: #253 asks that replacement be explicit, and the writer already keeps old
values; deferring leaves people to rotate by hand with `opv set`, which §5.6 now refuses.

**D9. `opv set` and the identity check.**
Situation: `opv set` refuses agent markers and non-terminals but never checks that 1Password is
used by a person (§2.3). With a service-account token exported in a terminal it writes under the
service account.
- A. Add `require_person` to `set` and `set --from-file` in the same release.
- B. Leave as is.
Recommendation: **A** (one call, one test).

## 9. Self-vet

### 9.1 Poka-yoke

| Mistake | Prevented by |
|---|---|
| a set spans two items | load rule (§3.2) |
| a member filled by `opv set` and mismatching its bundle | `ProvisionedKey` refusal (§5.6); `ready` reports `inconsistent` |
| hand-built JSON bundle with bad escaping | references are whole leaves; the writer escapes; round-trip check |
| a template that does not agree with its members | round-trip check before write; set state on every rerun and in `ready` |
| silent rotation | `complete` ⇒ `unchanged`, no producer, no generation; rotation only with `--replace`; `immutable` refused |
| writing staging values into prod | typed environment; producer echoes env and nonce; distinctness check across environments |
| re-feeding an old producer output | nonce per run; no flag reads a document from a file or opv's stdin |
| token pasted into the producer's argv in the contract | load rule matches argv against secret patterns |
| a value the producer mis-maps into a name | names admitted only if declared; undeclared names reported by position |
| partially written item | one atomic item edit; version + 1 and read-back checks; unknown outcome reconciled |
| concurrent edit | stamp check before (re-plan if unrelated), version check after (detected, history pointer) |
| person waits through consent then the write is refused | confirmation before the producer runs; re-plan when only unrelated fields changed |

### 9.2 Security

| Channel | Status |
|---|---|
| argv | never a value: opv's own argv has none; `op item edit` gets the item on stdin; the producer's argv is committed text checked at load |
| environment | never a value: the producer gets a cleared environment without session or tokens; inputs go over stdin |
| files | none written by opv; no `--from-file` route for sets; `op`'s own cache behaviour is unchanged (existing) |
| terminal | no value printed; public members are not printed either; producer has no terminal; notices are fixed sentences with an allow-listed URL |
| logs / `--verbose` | scrubbed stderr lines and stdout shape only (NR-22, NR-31) |
| producer stderr | held in memory, never shown on success, shown ≤ 5 lines after values are registered and patterns applied on failure. Limit: a value the producer prints to stderr **before** its result line, in a format no pattern knows, and then crashes before emitting a parseable result, is masked only by patterns. Mitigation: document that producers must never print credentials; the canary test covers the parsed case |
| core dumps | opv is non-dumpable (`hardening.rs`); the producer gets `RLIMIT_CORE = 0` (hard). Limit (inferred): a pipe-based core handler may ignore `RLIMIT_CORE`; the producer's own memory is outside opv's control |
| memory | `SecretValue` and `Zeroizing` buffers for request, stdout, stderr and the rendered template; no `serde_json::Value` holding a secret |
| `Debug` | names only, as `SecretValue` |
| replay | nonce; set state makes a rerun `unchanged` |
| partial writes | impossible within one item (inferred atomic edit); across items refused by design |
| issued-but-unstored credential | named in a fixed Do with "revoke the grant at the issuer" |
| same-user agent | not a boundary (§6); D6 narrows the exported-session route |
| prod/staging cross-contamination | §5.5 |

### 9.3 Architecture guards

- `src/app/provision*.rs` and `src/domain/provision*.rs` name no provider word and no target
  adapter (FR-37, FR-12). They use `adapters::onepassword` / `onepassword_tidy` like `import.rs`
  (the source adapter is not a target adapter). Vendor names live only in user contracts and docs.
- The producer is a runner effect; only `runner*.rs` constructs `Observed` for it
  (`tests/observed_seal.rs` unchanged).
- New causes: `Guard::ProvisionRefused{set, env, reason}` (reasons `Partial{missing}`,
  `Inconsistent{members}`, `ImmutableMember`, `SameAcrossEnvironments`, `TemplateReferencesMissing`),
  `Guard::ProvisionedKey{set}`, `ProducerFailed{producer, exit}`, `InputInvalid{kind: Produce, rule}`
  and `FieldRule::Produce{…}`. Existing `ChangedBeforeWrite`, `ConcurrentEdit`, `ReadBackMissing`,
  `WriteOutcomeUnknown`, `NeedsTerminal`, `PersonOnly`, `NeedsOwnSession`, `ConfirmMismatch`,
  `Declined`, `PlanChanged` are reused. Each new variant needs: fixture (`every_variant_renders`),
  catalog row (`error-catalog.md` §4), generated usage table, `Next` that parses, an e2e cell or an
  `UNREACHABLE` entry with reason (`tests/e2e/coverage.rs`).
- Global registrations: CLI surface tests (`tests/surface_contract.rs`, `tests/one_way.rs`,
  `tests/docs_commands.rs`), `schema.rs` (`opv.produce/1`, `opv.provision/1`, the contract's
  `[sets]`/`[producers]`), MCP tool list (`opv_provision_plan`), agent guidance
  (`tests/agent_guidance.rs`).

## 10. Test plan

One behavioural assertion per test. Unit tests use `FakeOp` (`src/adapters/fake_op.rs`, with
`racing_edit` and `edit_elsewhere`) and a `FakeRunner` `produce` script; end-to-end tests use
`opv-sim` with a new fake producer (`tests/sim/producer.rs`) driven by the scenario's
`world.json`, and the fault kinds `Timeout`, `AppliedButReplyLost`, `MalformedOutput`.

### 10.1 Load (config)
1. a set whose members resolve to two boundaries is `config_invalid`.
2. a `source = "provisioned"` key in no set is `config_invalid`.
3. a key in two sets is `config_invalid`.
4. a template leaf `"x${A}"` (partial interpolation) is `config_invalid`.
5. a template cycle is `config_invalid`.
6. a producer argv element matching a token pattern is `config_invalid`.
7. a producer input naming another product's key is `config_invalid`.
8. `generate = "rules"` on a key without a byte-count rule is `config_invalid`.

### 10.2 Domain (pure)
9. no member set ⇒ `absent`.
10. all members set and the bundle matches ⇒ `complete`.
11. one member missing ⇒ `partial` naming it.
12. bundle leaf differs from its member ⇒ `inconsistent` naming the bundle.
13. a rendered template with a value holding `"` and `\` parses back to the same value.
14. base62 token has the declared prefix and length.
15. the plan id changes when the item version changes.

### 10.3 Use case (`provision_tests.rs`, FakeOp)
16. matched values: after a write, each bundle leaf equals its member field (#262 AT1).
17. partial existing set is refused with no `item edit` call (#262 AT2).
18. rerun of a complete set makes no `item edit` call (#262 AT3).
19. rerun of a complete set does not start the producer.
20. `racing_edit` on the write ⇒ `ConcurrentEdit` (#262 AT4).
21. an unrelated field changed between plan and write ⇒ one write, re-planned.
22. a member field filled elsewhere between plan and write ⇒ `ChangedBeforeWrite`, no edit.
23. an `item edit` failure leaves the item at its previous version (#262 AT5).
24. unknown outcome with the edit applied ⇒ success after read-back.
25. unknown outcome with nothing applied ⇒ "not written; safe to re-run".
26. `--fill-missing` writes only the missing member and keeps the present one.
27. `--fill-missing` with a present bundle and a missing member ⇒ `TemplateReferencesMissing`.
28. `--replace` keeps each old value in `opv · kept`.
29. `--replace` with an immutable member is refused before any read of values.
30. a new value equal to another environment's stored value ⇒ `SameAcrossEnvironments` (#262 AT7).
31. a malformed member ⇒ refused, no edit, all failing members named.
32. `opv set` on a provisioned key ⇒ `ProvisionedKey`.
33. `opv set` with a service-account token ⇒ `NeedsOwnSession` (D9).

### 10.4 Refusals
34. agent marker ⇒ `PersonOnly`, no `op` call.
35. `CI=true` ⇒ `NeedsTerminal{Ci}`, no `op` call.
36. non-TTY ⇒ `NeedsTerminal{NoTty}`, prompt never called.
37. service-account identity ⇒ `NeedsOwnSession`.
38. production tier with `OP_SESSION_x` set ⇒ `NeedsOwnSession` (D6).
39. wrong typed environment ⇒ `ConfirmMismatch`, producer not started.
40. `--dry-run` under an agent marker succeeds and makes no write.
41. `opv_provision_plan` over MCP returns the plan and makes no write.

### 10.5 Producer (runner effect + parser)
42. the producer's argv equals the contract's `command`.
43. the producer's environment holds no `OP_SESSION_*` variable.
44. the producer's environment holds no `OP_SERVICE_ACCOUNT_TOKEN`.
45. the request on the producer's stdin carries this run's nonce.
46. a result with another nonce ⇒ `NonceMismatch`.
47. a result for another environment ⇒ `WrongEnvironment`.
48. an undeclared output name is reported by position, not by name.
49. a duplicate output name ⇒ `Duplicate`.
50. producer exit 1 after a valid result ⇒ `ProducerFailed`, nothing written.
51. producer past its timeout is killed ⇒ `Timeout`.
52. `open_url` with a host outside the allow list ⇒ refused.
53. stderr is not shown on success.
54. on failure, a parsed output value in stderr is shown as `********`.
55. Ctrl-C during the producer ⇒ the producer gets SIGTERM and nothing is written.
56. a serde error's text never appears in the refusal.

### 10.6 Custody (canaries, `tests/security.rs` style)
57. the canary value never appears in any process's argv (#262 AT6, #253).
58. the canary never appears on opv's stdout or stderr.
59. the canary never appears in the `--json` receipt.
60. no file under the scratch `HOME` or project contains the canary after the run.
61. no snapshot under `tests/e2e/snapshots/` contains the canary.
62. the producer runs with `RLIMIT_CORE` hard limit 0 (Linux, `/proc/<pid>/limits`).

### 10.7 End-to-end (`tests/e2e/scenarios/provision.rs`, opv-sim)
63. Journeeze-shaped nine-member set in staging is `complete` per `opv ready`.
64. partial set ⇒ `opv ready` blocking finding naming `--fill-missing`.
65. fault `AppliedButReplyLost` on the edit ⇒ success after reconciliation.
66. consent-shaped producer flow writes both members and prints the revision.
67. snapshots of text and `--json` for each refusal in §6 (catalog §13.3 rules).

## 11. For the FMECA reviewer: inferred behaviour

1. `op item edit <id>` with a whole-item JSON on stdin is applied as one item revision (no partial
   field application). Relied on by FR-43 since 0.4; never contradicted by the recorded fixtures.
2. `op item edit` has no version precondition flag (op 2.x reference from memory; the repo holds no
   recorded `op item edit --help`; not re-verified live). If one exists, §4.6 step 1's detection
   becomes prevention and nothing else changes.
3. No 1Password operation spans two items atomically via `op`.
4. Item history keeps prior versions and a person can restore them in the app; `op` has no
   restore-version command.
5. The 1Password app prompts on a write from a new terminal session when the app integration is
   used (error catalog §9.1 states it; behaviour depends on the app's settings).
6. A pipe-based Linux core handler may ignore `RLIMIT_CORE` for the producer.

## 12. Delivery steps

Step 0, before any lane: DESIGN-FMECA review of this document by a separate agent; owner answers
D1–D9. Lanes assume the recommendations.

| Id | Lane | Files owned | Prereqs | Est. h | Owner type |
|---|---|---|---|---|---|
| L1 | Contract model and load rules: `[sets]`, `[producers]`, `source = "provisioned"`, §3.2 | `src/config/sets.rs` (new), `src/config/sets_tests.rs` (new), hook lines in `src/config.rs`, `ValueSource::Provisioned` in `src/domain/model.rs` | 0 | 4 | Claude agent (config conventions span `config.rs`, FR-60 rules) |
| L2 | Pure domain: set states, plan + plan id, generators (`token`), template writer and round-trip | `src/domain/provision.rs`, `src/domain/provision_template.rs`, `*_tests.rs` (new) | L1 (types only; can stub) | 4 | commodity worker (file-scoped, spec §4.5, §5.1, §5.3) |
| L3 | Causes and catalog | `src/cause/mod.rs`, `src/cause/render.rs`, `src/cause/codes.rs`, fixtures in `src/cause/*_tests.rs`, `docs/design/error-catalog.md` rows | 0 | 3 | Claude agent (global registration tests) |
| L4 | Shared JSON stream module + `opv.produce/1` parser | `src/app/json_stream.rs` (new, extracted from `deliver_only.rs`), `src/app/deliver_only.rs` (calls only), `src/app/produce_doc.rs` (new) + tests | L3 | 4 | commodity worker (mechanical extraction then parser to §5.2 table); split if extraction exceeds 300 lines |
| L5 | Runner `produce` effect: spawn, pipes, cleared env, `pre_exec` limits, deadline, signals, stderr capture, `Observed`; `FakeRunner` support | `src/runner_produce.rs` (new), trait method in `src/runner.rs`, `src/adapters/fake_op.rs` (produce script) | L3 | 5 | Claude agent (runner, signals, seal) |
| L6 | Checked commit writer (§4.6) | `src/app/provision_commit.rs` (new) + tests | L3 | 3 | Claude agent (reads `tidy.rs`, `import.rs`, `onepassword_tidy.rs`) |
| L7 | Use case `opv provision` (refusals, read, classify, confirm, produce, generate, validate, distinctness, commit, receipt) | `src/app/provision.rs` (new), `src/app/provision_tests.rs` (new), `src/app/mod.rs` (module line) | L1, L2, L4, L5, L6 | 6 | Claude agent; split into L7a (steps 1–7, plan/dry-run) and L7b (steps 8–12) if over 400 lines |
| L8 | Refuse provisioned keys in other writers; D9 identity check | `src/app/set.rs`, `src/app/set_tests.rs`, `src/app/generate.rs`, `src/app/import.rs` (guard call only) | L1, L3 | 2 | commodity worker |
| L9 | CLI, schema, MCP plan tool, surface/golden tests | `src/main.rs`, `src/schema.rs`, `src/mcp.rs`, `tests/surface_contract.rs`, `tests/one_way.rs`, `tests/docs_commands.rs`, `tests/agent_guidance.rs` | L7 | 3 | Claude agent (global registration) |
| L10 | `ready` set state and blocking finding | `src/app/ready.rs`, `src/app/ready_tests.rs` | L2, L3 | 2 | commodity worker |
| L11 | Simulator producer, e2e scenarios, coverage, custody canaries | `tests/sim/producer.rs` (new), `tests/sim/opv_sim.rs` (dispatch line), `tests/e2e/scenarios/provision.rs` (new), `tests/e2e/coverage.rs`, `tests/security.rs`, `tests/e2e/snapshots/` | L9, L10 | 5 | Claude agent |
| L12 | Docs: `docs/provision.md` (incl. the OAuth consent-output flow and producer contract), `docs/usage.md`, `requirements.md` FR-64 + SR-3/SR-5 notes, CHANGELOG, skill text | `docs/provision.md` (new), `docs/usage.md`, `docs/design/requirements.md`, `CHANGELOG.md`, skill files | L9 | 3 | Claude agent |

Total about 44 h. Critical path: 0 → L3 → L5 → L7 → L9 → L11 (≈ 22 h of lane time). L1, L3 and
L8's D9 half start in parallel; L2, L4, L6 run in parallel once L3's types exist. File ownership is
disjoint except the one-line hooks in `src/config.rs`, `src/app/mod.rs`, `src/runner.rs`
(trait method) and `tests/sim/opv_sim.rs`, each owned by the lane named above.

Release gate (per project practice): `cargo test`, the e2e suite with `CI=true`, and the custody
canary scan.

Rollback: the feature is opt-in per contract; removing `[sets]` and changing `source =
"provisioned"` keys back to `person` restores today's behaviour. Values written stay in 1Password.
