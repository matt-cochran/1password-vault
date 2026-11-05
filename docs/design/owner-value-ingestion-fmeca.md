# DESIGN-FMECA vet: owner value ingestion (#262, #253), `docs/design/owner-value-ingestion.md`

Reviewer: independent; did not write the design. Date: 2026-11-04. Method: the owner's
DESIGN-FMECA procedure (persona, objective, constraints, code-change-proposal requirements, three
phases, output format, verification checklist), applied as written.

Owner question: **is this the right design for the two issues, is it safe, and is it the
smallest thing that serves them?**

**Short answer.** The core is right: a person-only command, a set declared in the contract, every
value made in memory, one write to one item through `op`'s stdin, refusals before anything runs,
and a receipt with no values. Three of the design's claims hold in the code:
- the single whole-item `op item edit` keeps values out of argv;
- the identity checks it reuses exist;
- `opv set` lacks the identity check (D9).

**As written, it is not ready.** There are four reasons:
1. **The #262 model does not match the real set.** In the infra contract and the existing owner
   script, the three site keys (`pk_…`) and the bundle's `siteId`s are *issued by Journeeze*
   (site get-or-create). opv does not generate them. The bundle is
   `{"version":1,"sites":[{"siteId","identitySecret","gatewaySecret"}]}`, with no user-hash key
   and no site key. `siteId` is stored only inside the bundle, so it is not a key. The design's
   template rules ("a leaf is `${MEMBER}`"; "every producer output is used by exactly one member")
   cannot express this. Its prefixed-token generator has no consumer.
2. **The producer cannot be built on the runner the way the design says.** The runner returns
   stdout only after the child exits and the pipe closes, so an `open_url` notice cannot be shown
   while consent waits. A browser or loopback server that the helper starts keeps the pipe open,
   so a consent that succeeded ends in `Timeout` and the minted refresh token is never stored.
   The runner kills only the direct child, and `tests/observed_seal.rs` pins `Observed`
   construction to exactly `src/runner.rs`, not to `runner*.rs`.
3. **Showing producer stderr on failure contradicts #253's acceptance criteria.** The issue says
   "producer diagnostics cannot leak response bodies or credentials". The scrubber's patterns
   cannot know an OAuth token format they have never seen.
4. **Some scope is speculative:** the token generator, `--expect-plan`, the MCP plan tool, the
   item marker field, and cross-environment reads for CSPRNG members. A new parallel writer
   (`provision_commit`) duplicates `import::write_item` instead of extending it.

**Fixes.** Each is small and reuses existing code:
- the producer becomes a streaming, single-attempt runner effect run in its own process group;
- opv opens the consent URL itself with the existing `open::opener`;
- the producer reports failure only through a closed error code;
- templates may reference producer outputs that are never stored;
- the existing writer gains the tidy's version check.

**Recommended scope cut.** Ship #253 plus the shared core first (Slice A). Redo the #262 template
and `--fill-missing` against the real Journeeze script as Slice B. After these changes no High or
Medium risk remains. One residual risk stays Low only because the item is shared by the whole
fleet: a later whole-item write can still erase a set after its receipt. It is detected and
recoverable, but `op` cannot prevent it.

Evidence levels: **Proven** (shown in code here, or documented by the tool), **Adapted**
(reasonable, not proven in this setting), **Speculative** (assumed, not validated).
Sources and revisions:
- opv paths are relative to `/home/mc/.cache/lanes/opv-0180-design` (rev `7cc0b6dd`, 0.17.2).
- Infra paths are in `/home/mc/working/infra-wt-jz` (rev `6b783b8b`, 2026-11-04; Journeeze) and
  `/home/mc/working/infra-wt-wave2` (rev `434101cd`; Workspace Admin).
- `op` is the installed 2.40.0; only `--help` was run.

Nothing was written to 1Password and no value was read.

---

## 0. Claims checked against the code and evidence

| Design claim (§) | Verdict | Evidence |
|---|---|---|
| One `op item edit` with the whole item JSON **on stdin**; argv holds only ids (§2.3, §9.2) | **Holds (Proven)** | `src/adapters/onepassword_tidy.rs:373-411` (`Call::new(OP, ["item","edit",id,"--vault",v,"--format","json"]).with_stdin(template)`). Every production `item edit` call site uses this form (`onepassword_tidy.rs:381`, `onepassword_manifest.rs:756`). No assignment statements are used. `op item edit --help` (2.40.0): "Command arguments can be visible to other processes … For sensitive values, use a template", and "You can also edit an item using piped input" |
| The whole-item edit is one item revision (§4.6, §11.1) | **Adapted**, relied on since FR-43, never contradicted by fixtures. `op` documents the template edit but not its atomicity | `onepassword_tidy.rs:408-409`. `op` help warns that a JSON template **overwrites passkeys**, which `unprovable()` (`ROUND_TRIP_TYPES`, `onepassword_tidy.rs:416`) already refuses |
| `op item edit` has no version precondition (§4.6, §11.2) | **Holds for flags (Proven)**: 2.40.0 lists `--dry-run --favorite --generate-password --reveal --tags --template --title --url --vault`, with no version flag. **Speculative**: whether the `version` field inside the piped template is enforced by the service. Nothing in the repo shows either way | `op item edit --help` |
| `import::write_item` has no version check (§2.3) | **Holds** | `src/app/import.rs:447-528`: one fresh read, apply, write, read back. No stamp or version |
| Tidy's check: stamp before, `version + 1` after (§2.3) | **Holds** | `src/app/tidy.rs:635-690`. The after-check prefers the **echoed** version (`:658-662`) |
| `opv set` checks agent + TTY but not identity (D9) | **Holds** | `src/app/set.rs:41-94`: `refuse_if_agent` (`:58`), `interactive()` (`:59`), no `require_person*`. Compare `generate.rs:135` |
| `require_person_on` refuses service account, Connect, deploy credentials, CI (§6) | **Holds** | `src/app/tidy.rs:117-132`, `:157-185` |
| FR-61's `OP_SESSION_*`/token refusal exists to reuse (D6) | **Holds** | `src/mcp.rs:530` `credential_in_environment`; `docs/design/requirements.md` FR-61 |
| The producer gets a cleared env via `runner::isolate` + `strip_session_vars` (§5.2) | **Holds with a hole**: both return early when `program == "op"`. A producer whose `command[0]` is `op` inherits the whole environment, including `OP_SERVICE_ACCOUNT_TOKEN` | `src/runner.rs:966-975`, `:1799-1806` |
| The producer is "a runner effect like HTTPS" (§5.2) | **Does not hold as is.** The runner returns stdout only after exit **and** EOF (`wait_attempt`, `src/runner.rs:1619-1712`), so no live notices. A pipe kept open by a grandchild blocks until the deadline, then reports `TimedOut` (`:1694-1699`). `signals::kill` kills only the direct child (`:2239-2246`). `read` retries | `src/runner.rs:1580-1712`, `:2239`; `runner_https.rs` is request/reply only |
| "Only `runner*.rs` constructs `Observed` (`tests/observed_seal.rs` unchanged)" (§9.3) | **Wrong**: the guard pins exactly `["src/runner.rs"]`. `src/runner_produce.rs` calling `from_failed_call` fails it | `tests/observed_seal.rs:79-96` |
| Producer `RLIMIT_CORE = 0`; opv non-dumpable (§9.2) | **Partly.** opv's `PR_SET_DUMPABLE 0` (`src/hardening.rs:75`) is **reset by `execve`** for the producer. The runner has no `pre_exec` today. A pipe `core_pattern` handler is not bound by `RLIMIT_CORE` at the kernel level; systemd-coredump honours the crashing process's limit, while apport's behaviour is **Speculative** | `src/hardening.rs:1-80`; `grep pre_exec src/` is empty |
| The supply parser can be extracted and reused for the producer (§5.2, L4) | **Partly.** `deliver_only::read` reads the whole stream to EOF, then parses (`src/app/deliver_only.rs:205-262`). The producer needs a line-streaming reader. Only the admission helpers (duplicate-name visitor, value rules, zeroizing buffers) carry over | `deliver_only.rs:205-300` |
| The confirmation uses `masked.rs` "in visible mode" (§4.4) | **No such mode**; `masked::prompt` is masked only | `src/app/masked.rs:84` |
| E2E scenarios 63-66 run under opv-sim (§10.7) | **Do not hold.** The e2e harness never gives opv a terminal (`tests/e2e/coverage.rs:84-92`, the `PlanUnknown` entry), and provision refuses a non-TTY at step 3. A PTY harness exists only as `tests/console.rs` → `console_walkthrough.py` (Unix, Python) | as cited |
| #262's set: generated site keys `jz_site_…` (config), bundle `{version,gateway,user_hash,sites[{key,secret}]}`, a new source-only product (§3.1) | **Wrong for the real set.** Site keys are `pk_[A-Za-z0-9_]{1,61}`, `kind = "secret"`, **issued by Journeeze**. The bundle is `{"version":1,"sites":[{"siteId","identitySecret","gatewaySecret"}]}`. `JOURNEEZE_USER_HASH_KEY` is not in it and is `immutable`. Products `journeeze` and `zonetico` **already share** `boundary = "fleet"` (one item), so no restructuring is needed. Allumata **appends** its site to the same bundle (infra#1430) | infra-wt-jz `fly/shared-host/fleet/secrets.toml:246-247,280-283,543-544,566-612,70-81`; `fly/shared-host/zonetico_journeeze_staging.py:1-40,150-177,300-346` |
| #253's producer needs only `client_id` as input; D5-A (config only) might do (§3.1, D5) | **D5-B is required.** `WORKSPACE_ADMIN_CLIENT_ID` and `WORKSPACE_ADMIN_CLIENT_SECRET` are both `kind = "secret"` (Google Desktop client). The environment is `prod-workspace`: `tier = "production"`, `confirm_env = true` | infra-wt-wave2 `workspace/admin/secrets.toml` |
| The producer opens the browser itself (needs `BROWSER`, `DISPLAY`, …) (§5.2) | **Fragile on the owner's platform.** `connect.py` calls `webbrowser.open` and runs a loopback `HTTPServer`, so it spawns a launcher that inherits stdout. On WSL, opening a Windows browser needs interop variables the design does not pass (**Adapted**). opv already has a WSL-aware opener | `workspace/admin/connect.py:103-110`; `src/app/open.rs:1-40` |
| The consumer gates on an opv capability | **Holds, and the design omits it.** `connect.py` reads `opv schema`'s `capabilities` and refuses before consent unless exactly one known ingestion capability is listed | `connect.py:118-134`; `src/schema.rs:520` (`"capabilities": ["supplied_values/1"]`) |
| Default run budget vs producer timeout ≤ 30 min (§3.2) | **Conflict**: `DEFAULT_RUN_TIMEOUT` is 1800 s, so a producer timeout of up to 30 min leaves no budget for the commit | `src/runner.rs:328`, `:319-321` |
| FR-37 scans `src/app`, `src/domain` (§2.3) | **Also scans `src/config/`** and the three config files; `_tests.rs` files are exempt. FR-12 scans test files in `src/app` too (only `init.rs` and `characterization_tests.rs` are exempt). L1's `src/config/sets.rs` is covered | `src/app/mod.rs:2128-2140`, `:2280-2330` |

---

## Phase 1: Architecture Assessment

| Component | Purpose | Classification | Justification | Simpler Alternative | Risk if Removed |
|---|---|---|---|---|---|
| C1. `opv provision <SET> --env` (person-only) | One command for a matched or produced write | **Essential** (Adapted from `set`/`generate`) | Both issues ask for an owner-only operation | — | No feature |
| C2. `[sets]` in the contract (D2-A) | `ready`/`plan` know the set | **Essential** | #262's failure was late detection | — | Detection stays at `sync` |
| C3. `source = "provisioned"` | Mark keys only a set fills | **Useful; simplify** | It restates set membership, so the same fact is declared twice (FR-60). It also forces a pin bump on every consumer of the contract | Derive "provisioned" from membership; no new enum value | Small: one load rule less |
| C4. Load rule: a set fits one boundary (D1-A) | Real atomicity | **Essential** (Adapted: atomic edit) | `op` has no cross-item transaction. The real Journeeze keys already share `boundary = "fleet"` | — | Partial sets across items |
| C5. `generate = "rules"` | CSPRNG members | **Essential** (Proven: `generate::recipe`/`make`) | Five hex32 secrets in #262 | — | — |
| C6. `generate = {token, bytes, prefix}` | Prefixed public ids | **Unjustified** | The real site keys are issued by Journeeze, not generated. No consumer | Remove | None |
| C7. Producers over `opv.produce/1` (D4-A) | #253 consent; #262 site issuance | **Essential** (Adapted) | No other channel meets the custody rules. Both issues have a real producer | — | #253 stays blocked |
| C8. `open_url` notice shown live | Consent URL on WSL or headless | **Essential, simplified** | Consent cannot complete otherwise | **opv opens the URL with `open::opener` and prints it.** The producer starts no browser, gets no `BROWSER`/`DISPLAY` | Consent fails on WSL |
| C9. Nonce + env echo | Stop a cached or other-environment result | **Useful** (cheap) | 128 bits and two comparisons | — | Low |
| C10. Producer `inputs` (D5-B, secrets) | Client id/secret to the helper | **Essential** (evidence: both are `kind = "secret"`) | The alternative is a file or an environment variable | — | #253 cannot run |
| C11. JSON templates | #262's bundle | **Essential, re-specify** (Speculative as written) | The bundle needs `siteId`, a producer output never stored as a key | Leaves `${member}` **or** `${producer.output}` | No #262 |
| C12. Set states absent/complete/partial/inconsistent | Idempotency and refusal (AT2, AT3) | **Essential** | — | — | Silent rotation or mismatches |
| C13. `--replace` (D8-A) | Rotation, re-consent | **Essential for producer sets** | #253's README "Reauthorize" after revocation; refused for `immutable` | — | Re-consent impossible once `set` refuses the key |
| C14. `--fill-missing` (D7-A) | Partial-set recovery | **Useful; move to Slice B** | Needed because `JOURNEEZE_USER_HASH_KEY` is `immutable`, so `--replace` is refused. Bound to the template re-render | Slice A refuses `partial` | Slice A has no template sets, so no loss |
| C15. `--dry-run` | Names-only plan | **Essential** (#262 item 8) | — | — | — |
| C16. `--expect-plan` + plan id | Bind a reviewed dry-run | **Speculative** | The typed confirmation already follows the plan in the same process. No consumer is named | Defer | None |
| C17. MCP `opv_provision_plan` | Assistant reads the plan | **Useful; defer** | `opv provision --dry-run --json` is already allowed for an assistant. The tool adds registration and guidance tests | CLI `--dry-run --json` | Low |
| C18. Typed environment confirmation | Explicit confirmation (#253) | **Essential** (friction) | — | — | — |
| C19. D6 session-variable refusal (prod) | The write goes through the app's authorization | **Useful** (Proven precedent FR-61, `mcp.rs:530`) | — | — | Narrower protection only |
| C20. Marker field `set <SET>` in the item | Provision id for `ready` | **Speculative** | `ready` computes the state from values. The receipt carries the version | Defer | None |
| C21. Cross-environment distinctness read (§5.5) | Prod ≠ staging | **Useful; narrow** | Vacuous for CSPRNG members (256-bit). Real for producer outputs (one client misused for two environments). Costs a prod-vault read on every staging run | Compare **producer-made members only** | Low |
| C22. `ready` set state | Detection before `sync` | **Essential** (#262 item 7) | — | — | Late detection |
| C23. Other writers refuse set members (§5.6) | No lone write breaks a set | **Essential** | — | — | `inconsistent` sets |
| C24. D9: `set` identity check | Close the service-account write | **Essential, independent** | A bug today. Ship in 0.17.3 | — | A service-account write path stays open |
| C25. New `provision_commit` writer | Version-checked write | **Unjustified as a parallel writer** | Code-change rule: no divergent implementations. `import::write_item` serves `set`, `import`, `generate` and needs the same check | **Add the stamp and echoed-version check to `import::write_item`**, used by all four | — |
| C26. Shared JSON stream module (L4) | Reuse the supply parser | **Simplify** | Streaming differs (see §0) | Reuse the admission helpers only; no extraction of `deliver_only`'s reader | Lower regression risk for `--supply-stdin` |
| C27. `opv schema` capability `owner_produce/1` | Consumer gating | **Essential** (missing from design) | `connect.py:118-134` refuses before consent without it | — | The connector never runs |

### Revised Architecture

- **Components retained:** C1, C2, C4, C5, C7, C9, C10, C12, C13, C15, C18, C19, C22, C23, C24, C27.
- **Components simplified:**
  - C3: membership marks a key as provisioned.
  - C8: opv opens and prints the URL.
  - C11: templates may reference producer outputs that are never stored; the bundle shape comes from
    the consumer, not invented.
  - C21: compare producer members only.
  - C25: one checked writer, by extending `import::write_item`.
  - C26: admission helpers only.
- **Components removed:** C6 (token generator).
- **Components demoted or deferred:** C14 (to Slice B with templates), C16, C17, C20.

---

## Phase 2: FMECA + poka-yoke + TRIZ

Domains: **UX**, **Runtime**, **Architecture**, **Delivery**. S = severity, P = probability.

### Iteration 1 Risk Table

| Domain | Failure Mode | Cause | Effect | S | P | Mitigation (Poka-Yoke) | Observability | TRIZ Resolution | Res. S | Res. P |
|---|---|---|---|---|---|---|---|---|---|---|
| Arch | F1. The #262 set cannot be expressed | Template leaves only `${MEMBER}`; "each producer output used by exactly one member"; invented bundle shape; site keys generated | The design ships and Journeeze still needs its bespoke script | High | High | Re-derive the #262 spec from `zonetico_journeeze_staging.py`. Templates take `${producer.output}` leaves (intermediates, held as `SecretValue`, never stored). The site get-or-create becomes a producer. Remove C6. Make Allumata's append (infra#1430) an explicit non-goal of 0.18 | A load test that loads the real Journeeze set; a unit test that renders the real bundle shape | Segmentation: Slice A (#253) first; Slice B (#262) after re-spec | Low | Low |
| Runtime | F2. Consent succeeds, opv reports `Timeout`, token unstored | A browser launcher or loopback server that the helper starts inherits stdout/stderr; the runner waits for EOF until the deadline (`runner.rs:1694`) | Minted refresh token lost; the person must revoke and consent again | High | Med | Streaming line reader: done at **result line + child exit**, never waiting for EOF. Unix `process_group(0)`, `killpg` after the result, on timeout and on signal. opv opens the URL itself, so the helper has no reason to spawn a browser | Verbose line `producer: result after N s, group stopped`; a test with a fake producer that forks a sleeper holding stdout | Taking out: move browser opening out of the producer | Low | Low |
| Runtime | F3. Notices never shown; or consent run twice | The runner's `Call`/`Attempt` returns stdout at exit; `read` retries | The person sees nothing until timeout; or a retried producer asks for consent again | High | High | A dedicated streaming attempt in `runner.rs`, write-class (one attempt, never retried), tracked as the current child for signals | Unit test: a notice arrives before the child exits; FakeRunner counts one spawn | Local quality: one effect with its own shape, inside the runner | Low | Low |
| Arch | F4. Seal test fails | `runner_produce.rs` builds `Observed`; the guard pins `src/runner.rs` only | Build red; or someone widens the seal | Low | High | `runner_produce.rs` returns a raw attempt; `runner.rs` builds `Observed` (the HTTPS pattern, `runner_https.rs` + `runner.rs:200-230`). The seal list is unchanged | `tests/observed_seal.rs` | — | Low | Low |
| Runtime | F5. Credential leaks through "producer said:" | A failing helper's exception text carries the token response body in a format no scrub pattern knows | A refresh token in the terminal or scrollback; #253's acceptance criteria are broken | High | Med | **Never display producer free text.** Add `{"kind":"error","code":"<[a-z_]{1,40}>"}` as an allowed last line, rendered as `producer reported <code>`. Wipe stderr unread. `--verbose` shows only its byte count | Canary test: a fake producer prints the canary to stderr in an unknown format, then exits 1; the canary is absent from all output | Prior counteraction: a closed vocabulary instead of filtering | Low | Low |
| Runtime | F6. Producer inherits 1Password credentials | `isolate` and `strip_session_vars` exempt `program == "op"` | A service-account token or session reaches a program that is not opv's `op` call | Med | Low | Load rule: `command[0]` basename ∉ {`op`, `op.exe`, `opv`, `opv.exe`}. The produce spawn clears the env unconditionally (no `op` exemption) | Tests 43-44 plus a case with `command = ["op", …]` refused at load | — | Low | Low |
| Runtime | F7. Consent cannot open a browser on WSL | The cleared env lacks interop variables; `BROWSER`/`DISPLAY` are not enough (Adapted) | #253 fails on the owner's platform | Med | High | Same as F2: opv opens the URL (`open::opener` already handles WSL `rundll32.exe`/`wslview`); the producer env stays basics-only | Plan line `consent opens in: <opener>`; verify once on the owner's WSL | Taking out | Low | Low |
| Runtime | F8. Core dump of the producer holds a value | `PR_SET_DUMPABLE` resets at `execve`; a pipe core handler is not bound by `RLIMIT_CORE` | A token in `/var/crash` or the journal | Med | Low | `pre_exec`: hard `RLIMIT_CORE = 0` (async-signal-safe). Remove the design's "opv is non-dumpable" from the producer claims. Document that the producer held the value before opv did, so opv adds no exposure | Test 62 (`/proc/<pid>/limits`) | — | Low | Low |
| Runtime | F9. Windows producers misbehave | No `pre_exec`, no group kill (`signals::forward` is a no-op off Unix), no core limit | Orphans; consent hangs | Med | Med | 0.18: **refuse a producer member on native Windows** (`Unsupported`, Next: run from WSL). Generators work everywhere. Job Object later | e2e refusal snapshot on Windows CI | Segmentation by platform | Low | Low |
| Runtime | F10. The run budget expires during or after consent | Producer timeout up to 30 min = `DEFAULT_RUN_TIMEOUT` | Commit refused after the token was minted | High | Med | Plan-time check: producer timeout + commit reserve (read 60 s + write 120 s + read 60 s) ≤ remaining budget, else refuse **before** consent. Cap the producer timeout at 15 min | The plan prints the time budget; refusal names `--timeout` | Preliminary action | Low | Low |
| Runtime | F11. Edit between S1 and the write is overwritten | No compare-and-swap; the whole-item edit replaces the item | A colleague's or a tidy's change to another fleet field is lost (kept in history) | Med | Low | Use the **echoed** version only (as tidy, `tidy.rs:658-662`). If echo ≠ S1+1: result `written`, with the note "an edit made just before opv's may have been replaced; restore it from the item's history". Members verified. Not an error exit that invites a re-run | Receipt `version_before/after`; `concurrent_edit` note | Detect, don't lock (NR-8) | Low | Low |
| Runtime | F12. A later whole-item writer erases the set after its receipt | Another writer (a person's read that tidies, or `set`/`import`) built its template from a pre-provision read. The fleet item is shared by every fleet product | Set `absent` again; a producer credential survives only in history | High | Low | A final fresh read after the echo check, so the receipt says `verified at version N`. `ready` reports the set state. Items kept in history | `ready` finding `absent`/`inconsistent` names `opv provision` | Cannot prevent without CAS (§4.6) | Med | Low |
| Arch | F13. Atomicity assumption is wrong | The service might apply template fields one by one (Speculative, never observed) | Partial set | High | Low | Read-back of every member plus `ready` classification. Optional owner experiment (§Final): a stale-template edit on a scratch item, to learn whether the template's `version` is enforced | `ReadBackMissing`; `ready` `partial` | — | Med | Low |
| UX | F14. The confirmation prompt has no reader | `masked.rs` has no visible mode | Built ad hoc, diverging from patterns | Low | High | Reuse the setup console's line reader (`src/app/setup_runtime.rs:659-700`, `confirm_on`/`choose_on`) for a typed-back answer; `opv approve` is no longer a subcommand (`src/main.rs:6148`) | Unit test with a fake prompt | — | Low | Low |
| Delivery | F15. E2E plan unreachable | The harness has no TTY; provision refuses at step 3 | New causes lack e2e cells; the catalog test fails or `UNREACHABLE` grows silently | Med | High | One PTY happy path plus one refusal through the `tests/console.rs` pattern (Unix). Every other new variant: a unit cell plus an `UNREACHABLE` entry with its reason, reviewed | `tests/e2e/coverage.rs` | — | Low | Low |
| Delivery | F16. Speculative scope slows delivery | C6, C16, C17, C20, full C21, and a parallel writer | More causes, rows and tests; a longer critical path | Med | High | Cut as in Phase 1 | Lane count; catalog rows added | Trimming | Low | Low |
| Security | F17. Edited producer file receives prod inputs and the token | `tools/…py` is project code that a PR or an agent can change | Exfiltration of the client secret and refresh token | High | Low | Contract pins `sha256` of `command`'s project file. Load refuses a mismatch. The plan prints the hash, and the plan's identity covers it. A same-user process stays out of scope (§6) | Refusal `producer_changed`; PR diff shows the hash change | Separation in time: review at contract change | Med | Low |
| Security | F18. Prod/staging cross-contamination | Wrong environment flag; one OAuth client used for both; a cached result | A prod credential in staging, or the reverse | High | Low | Typed environment; env echo plus nonce; inputs from the same environment's item only; **distinctness check on producer members** (other environments that are readable); generators are independent by construction | `SameAcrossEnvironments` refusal; the receipt lists the compared environments | — | Low | Low |
| UX | F19. Wrong recovery text after a failed commit | "Revoke the grant at the issuer" is fixed text; #262's producer is an idempotent get-or-create | Needless revocation, or a confused person | Low | Med | Neutral fixed text: "the producer's outputs were not stored; what it created at its issuer still exists". The producer's docs say what to do | Snapshot of the text | — | Low | Low |
| Delivery | F20. Pinned old opv in CI rejects the new contract | `[sets]`/`source` unknown to 0.17 | Releases blocked | Med | Med | C3 removal avoids the new enum value. The pin bump precedes the contract change (deliver-only S13 precedent). Add the `owner_produce/1` capability so `connect.py` gates on it | CI load error names the version | — | Low | Low |
| Runtime | F21. Service-account or agent session writes | Exported `OP_SERVICE_ACCOUNT_TOKEN`; agent marker; MCP | A write not by the person | High | Low | Step 3 refusals plus `require_person_on` (Proven) plus D6 `credential_in_environment` for production. No MCP write tool. D9 closes the `set` route | Tests 34-41; refusal snapshots | — | Low | Low |

### Remaining Risks After Iteration 1

- **High:** none.
- **Medium (residual severity):**
  - F12: a later writer erases the set.
  - F13: the atomicity assumption.
  - F17: an edited producer.
- **Low:** all others.

### Iteration Summary (1)

- Key mitigations:
  - a streaming, single-attempt, process-group producer effect built in `runner.rs`;
  - opv opens the URL;
  - a closed error vocabulary;
  - a hard core limit;
  - a budget check before consent;
  - the echoed version check in the one shared writer;
  - a producer hash pin;
  - templates with intermediates.
- Simplifications:
  - removed the token generator;
  - deferred `--expect-plan`, the MCP tool and the marker;
  - narrowed the distinctness read;
  - one writer;
  - no supply-stream extraction;
  - producers refused on native Windows.
- Trade-offs:
  - Windows users run producers from WSL;
  - showing no producer text makes debugging harder (TRIZ: closed codes plus the producer's own log);
  - D10 below changes `set`/`import`/`generate` to detect concurrent edits too.
- Continue: three residual Mediums.

### Iteration 2 Risk Table

| Domain | Failure Mode | Further Mitigation | Observability | TRIZ Resolution | Res. S | Res. P |
|---|---|---|---|---|---|---|
| Runtime | F12 | `ready` reads the members' state on every release preflight, so an erased set is caught before deploy. The value is recoverable from item history. No lock is possible (`op` has no CAS; NR-8) | `ready` | Accept: further mitigation would need a lock opv cannot build | Low | Low |
| Arch | F13 | The same detection as F12; the read-back makes a partial write loud at once. 1Password stores an item as one encrypted record (Adapted), which makes a partial apply implausible | `ReadBackMissing` | — | Low | Low |
| Security | F17 | Hash pin plus the plan line. The prod environment requires D6, so an agent with an exported session cannot run it unattended | Plan shows `sha256`; `producer_changed` | — | Low | Low |

### Remaining Risks After Iteration 2

- High: none.
- Medium: none.
- Low: all. F12 is Low only because it is detected and recoverable, not because it is prevented.

### Iteration Summary (2)

No new mechanism; the residual risks rest on existing detection (`ready`, read-back, item
history). Stop: further mitigation would need compare-and-swap in `op` or a lock (NR-8 forbids).

---

## Phase 3: Systemic Risk Review

- **Calibration risk.** No scores or confidences in the design.
  - The set-state classification is exact equality over in-memory values. It is calibrated only
    if the template comparison treats intermediates (`siteId`) by shape, not by equality to a
    stored key. Test it against the real bundle.
  - The plan's time-budget arithmetic must use the runner's own constants, not new ones.
- **Observability risk.** Each failure is visible:
  - a bad write: read-back and `ready`;
  - a wrong environment: nonce, echo, distinctness;
  - premature completion: the result must be last, and the group is stopped;
  - a policy regression: the refusal snapshots, the seal, FR-12/FR-37 and the catalog tests.

  One gap: a producer that fails with no code shows only `producer exited 1`. Accept it; the
  closed code is the producer author's tool.
- **Complexity vs utility.** 44 h / 12 lanes is not grossly over in hours. Removing the
  speculative pieces saves about 5 h, and the producer effect, PTY e2e and template intermediates
  add about 4 h. The over-engineering is in **scope that serves neither issue**: the token
  generator, `--expect-plan`, the MCP tool, the marker, and a full distinctness read. The
  under-engineering is in the two pieces the issues hinge on: the producer's process model and the
  real bundle shape. The simplest viable version is Slice A below.
- **Oversimplification risk.**
  - Removing producers or templates would leave both issues open.
  - Removing `--replace` would make #253 unrecoverable after revocation.
  - Removing the version check would contradict #262 AT4.

  None of these is cut.
- **Incremental delivery.** Clean phases:
  - D9 is a standalone fix (0.17.3).
  - The writer's version check (D10) is independently useful and testable with `FakeOp::racing_edit`.
  - Slice A adds producer sets.
  - Slice B adds templates and `--fill-missing`.

  Rollback: remove `[sets]`; the written values stay in 1Password. With C3 removed there is no enum
  value to revert.

### Final Outcome

All High and Medium risks are reduced to Low, provided the required changes below are made. One
check is optional and is a write, so only the owner can run it, on a scratch item: an
`op item edit` piped a template whose `version` is stale. If it is refused, F11/F12 become
prevention. This review did not run it.

---

## Conflicts with owner decisions D1–D9

| D | Design rec. | This review | Note |
|---|---|---|---|
| D1 | A | **Agree** | The example's `journeeze-shared` restructuring is unnecessary: `journeeze` and `zonetico` already share `boundary = "fleet"`. The load rule is "one boundary". The shared fleet item widens F11/F12 |
| D2 | A | Agree | — |
| D3 | A | **Agree, minus `--expect-plan`** (deferred) | — |
| D4 | A | **Agree with changes** | Streaming, single attempt, process group, closed error code, opv opens the URL, schema capability |
| D5 | B | **Agree; the evidence requires B** | The real client id and secret are `kind = "secret"`. Add the producer `sha256` pin |
| D6 | A | Agree | Reuse `mcp.rs:530` `credential_in_environment` |
| D7 | A | **Agree, but in Slice B** | Slice A refuses `partial` |
| D8 | A | Agree | Justified by #253 re-consent; refused for `immutable` (the real user-hash key) |
| D9 | A | **Agree; ship separately** (0.17.3) | — |

New decisions for the owner:
- **D10.** One checked writer: add the stamp and echoed-version check to `import::write_item`, so
  `set`, `import` and `generate` detect concurrent edits too. Recommended: yes.
- **D11.** Split into Slice A (#253 + core, 0.18.0) and Slice B (#262 templates + `--fill-missing`,
  0.18.x). Recommended: yes.
- **D12.** Refuse producers on native Windows in 0.18. Recommended: yes.
- **D13.** Is Allumata's append to the shared bundle (infra#1430) in or out of #262? Recommended:
  out for 0.18. A key in two sets needs its own design.

---

## Required design changes

1. §3.1/§3.2/§5.3: rewrite the #262 example from the real contract and script:
   - members are 3 `*_IDENTITY_SECRET`, `JOURNEEZE_SITES_GATEWAY_KEY`, `JOURNEEZE_USER_HASH_KEY`
     (generated, `hex_bytes = 32`), 3 `*_SITE_KEY` (producer) and `JOURNEEZE_SITE_SECRETS`
     (template);
   - template leaves may be `${producer.output}` intermediates;
   - drop the rule "each output used by exactly one member";
   - remove the token generator.
2. §5.2: the producer is a streaming, write-class runner effect:
   - one attempt;
   - result line plus exit ends it;
   - `process_group(0)`, with `killpg` after the result, on timeout and on signal;
   - `Observed` is built in `runner.rs` only;
   - no `BROWSER`/`DISPLAY`; opv opens `open_url` with `open::opener`;
   - unconditional env clear;
   - `command[0]` may not be `op`/`opv`;
   - hard `RLIMIT_CORE = 0` in `pre_exec`;
   - native Windows refused.
3. §5.2 stderr and §9.2: no producer text is ever shown. Add the closed `error` line, and wipe
   stderr unread.
4. §4.2: refuse before consent when the producer timeout plus the commit reserve exceeds the
   remaining budget. Cap `timeout` at 15 min.
5. §4.6: extend `import::write_item` (D10) instead of a new `provision_commit`:
   - check against the echoed version;
   - add the overwritten-edit wording;
   - do a final fresh read;
   - make the "revoke" text neutral.
6. §3.2: add a `sha256` pin for a project-relative producer file. Show it in the plan.
7. §3.2/§2.3: derive "provisioned" from set membership (no `ValueSource::Provisioned`).
8. §7/§9.3: add the schema capability `owner_produce/1`. Drop the MCP tool, `--expect-plan`, the
   plan id and the marker field from 0.18.
9. §5.5: compare producer-made members only.
10. §4.4: reuse the setup console's line reader (`setup_runtime.rs:659-700`); there is no "visible mode".
11. §10.7: the PTY harness for one success and one refusal. List each new unreachable variant with
    its reason. Correct §9.3's seal statement and FR-37's scanned directories.

## Revised delivery steps

| Id | Step | Prereqs | Est. h |
|---|---|---|---|
| S0 | D9 (`require_person_on` in `set`, `set --from-file`) as 0.17.3 | — | 1.5 |
| A1 | Contract: `[sets]`, `[producers]` (sha256, timeout cap, `command[0]` rule), membership-derived refusal | — | 3 |
| A2 | Causes and catalog rows (fewer: no plan/marker causes) | — | 2.5 |
| A3 | Runner produce effect: streaming, process group, `pre_exec`, opener, budget check, Windows refusal, FakeRunner | A2 | 6 |
| A4 | Version check in `import::write_item` (D10) + `racing_edit` tests | A2 | 2.5 |
| A5 | Use case `provision` (refusals, dry-run, confirm, produce, `generate = "rules"`, validate, producer distinctness, commit, receipt, `--replace`) | A1, A3, A4 | 6 |
| A6 | Other writers refuse members | A1, A2 | 1 |
| A7 | CLI, schema (`opv.produce/1`, `opv.provision/1`, capability), surface tests | A5 | 2 |
| A8 | `ready` set state | A1 | 1.5 |
| A9 | PTY e2e (one success, one refusal), custody canaries, `UNREACHABLE` entries | A7, A8 | 4 |
| A10 | Docs: `docs/provision.md` with the OAuth consent flow and producer contract; usage; requirements; CHANGELOG | A7 | 2.5 |
| | **Slice A total (0.18.0)** | | **≈ 31 h** (critical path A2→A3→A5→A7→A9 ≈ 20.5 h; S0 separate) |
| B1 | Templates with intermediates; real Journeeze bundle; round-trip | Slice A | 4 |
| B2 | `--fill-missing` (re-render from stored + new; recover `siteId` from the stored bundle) | B1 | 3 |
| B3 | Journeeze set e2e (PTY) + docs | B2 | 3 |
| | **Slice B total (0.18.x)** | | **≈ 10 h** |

Total ≈ 41 h, against the design's 44 h. #253 is unblocked in about 31 h, with no speculative
surface. Slice A could start with 8 lanes instead of 12.
