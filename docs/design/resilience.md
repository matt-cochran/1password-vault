# Resilience: the fallacies of distributed computing

Status: as built for 0.5.0 (proposed 2026-10-08, after the P1 Azure recon). Requirements NR-1 to NR-31 in
`docs/design/requirements.md` §4a are normative; this document is their argument. Owner
direction: every realistic issue is a true requirement, designed for resiliency,
transparency, and to make the user effective.

## 1. Why

opv drives three remote systems through their CLIs: 1Password (`op`), Fly (`flyctl`) and
Azure (`az`). Each call crosses a network opv does not control. The P1 recon showed the
failure that matters most: `az containerapp env create` exited 1 after a dropped connection
while Azure finished the change. Today opv treats every non-zero exit as "nothing happened",
retries nothing, and has one 300 s limit per call.

The goal is not a retry library. It is that **every opv run is safe to interrupt at any
point and safe to run again**, that opv never claims a state it has not observed, and that a
CI pipeline can tell "fix something" from "just run it again" by exit code alone.

## 2. Model: three outcomes, two effects

Every external call has an **effect** and an **outcome**.

| Effect | Examples | Retry |
|---|---|---|
| `Read` | `op item get`, `flyctl secrets list`, `az keyvault secret list/show`, `az containerapp show`, `revision show` | Bounded automatic retry |
| `Write` | `flyctl secrets import/unset/deploy`, `az keyvault secret set/delete`, `az containerapp update` | Never retried blindly; reconciled by a `Read` |

| Outcome | Meaning |
|---|---|
| `Done` | exit 0 and the output parsed |
| `Refused` | the remote answered with a definite "no" opv can name (not found, auth, policy) |
| `Unknown` | timeout, killed, spawn lost, or a non-zero exit of a `Write` — the change may or may not have happened |

The effect is a type, not a comment: the runner exposes `read(..)` and `write(..)`, and only
`read` retries (poka-yoke: a write cannot be retried by mistake, because the API that
retries does not accept it).

## 3. The eight fallacies, applied

| # | Fallacy | Where it bites opv | Mechanism (poka-yoke first) | Observability |
|---|---|---|---|---|
| 1 | The network is reliable | Calls drop mid-flight; `az` reports failure for a change that succeeded | **Convergent steps** (NR-1): every step is idempotent or reconciled. **Outcome classes** (NR-2): a `Write` that fails is `Unknown`; opv reads the state back before reporting. **Bounded read retry** (NR-3) | Exit 9 "outcome unknown, safe to re-run" naming the step; reconciled state printed |
| 2 | Latency is zero | Azure environments and revisions take minutes; a 300 s limit can kill a slow but healthy write | **Per-effect deadlines** (NR-4): probe 15 s, read 60 s, write 120 s, a rollout write (Fly deploy, Container Apps update, kubectl apply/replace) 15 min, waits poll with their own deadline in elapsed time; a run budget `--timeout` (default 1800 s) caps everything | A progress line on stderr at least every 15 s while waiting ("waiting for revision r3: Provisioning, 45 s") |
| 3 | Bandwidth is infinite | A CLI printing an unexpected huge document fills memory | **Output cap** (NR-5): captured stdout over 8 MiB is killed and refused | Target error naming the program and the cap |
| 4 | The network is secure | CLIs log argv to disk (`~/.azure/commands`); outputs could be tampered or malformed | Values only on stdin (SR-3); **validated outputs** (NR-6): every id, version and name read from a CLI is checked against a strict pattern before opv reuses it in argv or a document | Config/Target error naming the field, never the value |
| 5 | Topology doesn't change | Default subscription or account switches under you; an app is moved; a revision replaced | **Explicit scope on every call** (NR-7): Azure `subscription` is required in config and passed as `--subscription`; Fly `--app`; 1Password IDs. No CLI default is ever relied on | `doctor` shows the resolved subscription/app per environment |
| 6 | There is one administrator | People edit the target in the portal; two opv runs overlap (CI + laptop) | Ownership tag and managed set (FR-8, FR-32); **detect, don't lock** (NR-8): RMW fingerprint before and after apply (R9), Fly list A/B compare; identical desired state makes overlapping runs converge | Drift and "changed outside opv" errors naming paths |
| 7 | Transport cost is zero | Key Vault and ARM throttle; each `az` call costs ~1 s of Python start-up; Fly deploys restart machines | **Fewest calls** (NR-9): list once, read only ready secrets, write only differing ones, deploy only on change; retries back off with jitter | `--json` summary counts calls per program |
| 8 | The network is homogeneous | Different CLI versions, user config (`core.output = table`, `defaults.group`), OSes (Windows `/dev/stdin`, WSL `op.exe`) | **Pinned CLI environment** (NR-7): every call gets an env that overrides behaviour-changing user config; JSON output forced; `doctor` checks minimum versions; tests use recorded real outputs (R10) | `doctor` version lines; a fixed env asserted in tests |

## 4. Convergence invariant (NR-1)

For every command, for every external call k in its sequence: if the run stops after call k
(crash, Ctrl-C, CI cancel, network loss, `Unknown`), then

1. the target is no worse than before the run — nothing live points at a missing or
   half-written value, and
2. running the same command again reaches the same end state as an uninterrupted run.

How each flow satisfies it:

- **Fly** (stage → deploy): staging is invisible until `deploy`; a staged-but-not-deployed
  change shows as pending and triggers the next deploy; Fly's `Partial` deploy status is
  the same trigger. Prune is staged like any change, with one known gap: Fly hides an
  unset name immediately, so a run interrupted between `flyctl secrets unset --stage` and
  `deploy` leaves the name on the machines and the next run cannot see it as pending. The
  target is still safe (the machines keep a value they already had); the remedy is
  `opv sync <env> --deploy` again, or `flyctl secrets deploy --app <app>` (usage.md, Pruning on Fly).
- **Clouds** (write versions → apply pinned refs → await health → prune): a written version
  is invisible until a revision pins it; apply is one document; prune happens only after a
  healthy revision no longer binds the name, and a crash between unbind and delete leaves a
  tagged, unbound entry that the next `--prune --deploy` removes.
- **1Password** is read-only for every command but `item skeleton`, which only adds empty
  fields and is idempotent.

The invariant is tested, not argued: an **interruption matrix** test runs each sync scenario
with the fake runner failing call k (for every k) as `Unknown`, then re-runs it cleanly, and
asserts the end state equals the uninterrupted run's, that no intermediate state binds a
missing version, and that the interrupted run exits 0 or 9. Fly's staged flow has its own
matrix (`src/app/staged_tests.rs`).

## 5. Exit code 9 (NR-2)

A new category, `Error::Unknown`, exit **9**: "an external change may or may not have been
applied; nothing is known to be broken; re-run the same command". It is returned only after
at least one `Write` started, when the reconciling read itself failed or showed a partial
state. The runner records when the first target write started, so any read that times out
or exhausts the run budget after it is exit 9 and never says "nothing was changed"; so is a
sign-in probe that times out. A target that refused an update and applied nothing (Azure:
no new revision, provisioning `Failed`) is exit 5 `update_refused`, not 9: re-running would
repeat the refusal. CI can retry the whole job on 9 and must not retry on 2–8. Codes 0–8 keep their
meaning (FR-10 is extended, not changed).

## 6. Every realistic issue as a requirement

Beyond the eight fallacies, each issue below has happened to a CLI like opv or will. Each is a
requirement (NR-n), with the mechanism (prevention first), what the user sees, and the test
that holds it.

| NR | Issue | Requirement / mechanism | What the user sees | Test |
|---|---|---|---|---|
| NR-1 | Run stops anywhere (crash, Ctrl-C, CI cancel, lost network) | Convergence invariant (§4) | Next run reports and finishes the remaining work | Interruption matrix per flow |
| NR-2 | A write fails with unknown outcome | Reconcile by read; exit 9 when still unknown (§5) | `outcome unknown after <step>; state now: <names>; safe to re-run` | Fake `Unknown` on each write |
| NR-3 | Transient read failure, throttling (429/5xx) | Reads retried 3 times, backoff 1 s/2 s/4 s with jitter, within the run budget; a `Refused` (not found, auth) is never retried | One stderr line per retry: `retrying az keyvault secret list (2/3) in 2 s` | Read fails twice then succeeds; auth failure not retried |
| NR-4 | Slow operations; hung CLI | Per-effect deadlines (a rollout write up to 15 min) and a run budget `--timeout` (default 1800 s); every wait polls with progress against its own limit in elapsed time | Progress line ≥ every 15 s; timeout names the step and the last observed state | Fake clock: timeout message; progress cadence |
| NR-5 | Oversized or runaway output | stdout cap 8 MiB, child killed | Target error naming program and cap | Fake 9 MiB output |
| NR-6 | Malformed or hostile CLI output | Strict validation of every id/version/name reused; unknown JSON fields ignored, missing required ones refused | Error naming the field and program, never the value | Version with `/`, name with `..`, missing `id` |
| NR-7 | User CLI config or defaults change behaviour; wrong subscription/account | Explicit scope flags on every call; required `azure.subscription`; pinned env per CLI (az: output json, no defaults, no prompts, no dynamic extension install, no color, no telemetry; flyctl: no update check, no color; op: no color) | `doctor` prints the resolved scope per environment | Every recorded call carries the pinned env and scope flags |
| NR-8 | Someone else changes the target, or two runs overlap | Managed set + ownership tags; detect (fingerprint, A/B compare, drift), never lock | `changed outside opv: <paths>; nothing applied; safe to re-run` / drift lines | RMW race fixture; overlapping-run convergence test |
| NR-9 | Calls are slow and rate-limited | Fewest calls: one list, reads only for ready secrets, writes only for differences, deploy only on change | `--json` summary: calls per program, duration | Call-count assertions per scenario |
| NR-10 | Sign-in expires mid-run (op session ~30 min idle, az token, Fly token) | Auth is checked before the first write (a cheap probe), not only on failure; a failure after a write is diagnosed with the same probe and reported as `Auth` plus the re-run hint | `signed out of Azure during sync after writing 2 versions; run az login, then re-run` | Fake auth loss between write 1 and 2 |
| NR-11 | Interactive prompt would hang a run (op biometric/desktop unlock, az device code, extension install) | Non-interactive by construction: no TTY stdin for captured calls, prompt-disabling env, probes with 15 s limits; a hang becomes a timeout with the sign-in hint | `op is waiting for an unlock prompt; unlock the 1Password app or use a service account` | Probe timeout → that message |
| NR-12 | Signals (SIGINT/SIGTERM from CI) | opv forwards the signal to the running child, waits up to 5 s, kills it, then exits 130/143 with the last completed step | `interrupted during <step>; completed: <steps>; safe to re-run` | Signal injection in a process test |
| NR-13 | CLI version drift changes output or flags | `doctor` checks minimum versions for op, flyctl, az; parsers tolerant of extra fields; recorded real fixtures | `doctor` warn/fail line with the install/upgrade command | Fixture per supported version |
| NR-14 | OS differences (Windows has no `/dev/stdin`, WSL `op.exe`, PATH, line endings) | Values reach `az` through a user-only named pipe on Windows and stdin elsewhere (FR-40); native op checked up front; value bytes never re-encoded | Typed Dependency error naming WSL or Linux op; a pipe az never read is an error | cfg(windows) pipe tests, existing WSL tests |
| NR-15 | Value encoding edge cases (Unicode, CRLF, trailing newline, leading spaces, very long) | Byte-exact round trip; rules reject what a target would mangle before any call (FR-15/FR-22); limits per store | `status` shows the failing rule per key, never the value | Round-trip tests per adapter with edge-case markers |
| NR-16 | Large fleets (hundreds of keys, many products) | O(keys) calls at most; output grouped and summarised, details on request; `--product` scoping works for status/plan/sync | A one-line count summary first; rows unchanged (PR #63) | 500-key fixture: call-count bound |
| NR-17 | Partial configuration or 1Password item (new product, missing section) | Refuse before any write, naming every missing field at once (not one per run) | One list of all blockers with the next command for each | Multi-missing fixture |
| NR-18 | User cannot tell what happened | Every mutating run ends with one **run summary**: written, deployed, pruned, pending, unchanged, skipped, next step; same in `--json` | Final block; exit code matches it | Golden summary per scenario |
| NR-19 | User does not know what to do next | Every error and every non-zero exit ends with exactly one `Next:` line holding a runnable command (FR-22 extended to all errors) | `Next: az login` / `Next: opv sync prod --deploy` | Each error constructor requires a next step (type-enforced) |
| NR-20 | Destructive mistake (wrong env, prune too much) | Destructive flags explicit (SR-6); `--prune` lists names before acting; prod-like environments can declare `confirm_env = true`, which makes mutating commands require `--confirm <env>` | The list of what will be removed, then the result | Missing confirm flag refuses with the exact command |
| NR-21 | Clock skew and time-based assumptions | No decision depends on wall-clock comparison between machines; only monotonic local timers for deadlines | — | Lint: no `SystemTime` in decision code |
| NR-22 | Diagnostics leak secrets while debugging | `--verbose` adds program, argv (no values exist there), durations and outcomes only; stderr of children still never captured | Timing and outcome per call | Marker-value tests over verbose output |
| NR-23 | A run fails halfway because something was wrong from the start | **Preflight before the first write**: every mutating command first checks, read-only and in this order, every CLI it will call (present, version), every sign-in, reachability of each provider, and the target's state (NR-24..NR-26). Any failure stops the run with nothing written | `preflight: az ok, signed in (sub …), key vault ok, container app: Provisioning — wait`; then the plan | Each preflight failure makes zero write calls |
| NR-24 | **Fly state** problems: app suspended or deleted, no machines, machines stopped, a deploy already in progress, a previous deploy `Partial` | Preflight reads app status; deleted apps are refused with the next step; a running deploy is waited for with progress, within the run budget (refused only if still running then); suspended/pending apps have no machines, so secrets stage with a warning and `--deploy` is skipped; stopped machines are reported (secrets still stage); `Partial` triggers a redeploy (existing) | `warn  fly app <app>: no machines; secrets are staged and apply when machines start (fly scale count 1 --app <app>)` | Fixtures for each state |
| NR-25 | **Azure state** problems: vault soft-deleted or behind a firewall/private endpoint, RBAC not yet propagated (minutes after a grant), resource lock, Container App provisioning `Failed`/in progress, multiple-revision mode, environment unavailable | Preflight reads the vault (`keyvault show`) and the app (`containerapp show`): in-progress provisioning waits with progress (NR-4); `Failed` refuses naming the state; firewall/403 → Auth/Target error naming network access; a write refused right after a grant is retried as a read-gated write: probe `secret list` until allowed, up to 5 min, with progress | `waiting for Key Vault access to propagate (role granted 1 min ago), 30 s…` | Fixtures per state; propagation wait test |
| NR-26 | **1Password state** problems: item moved, archived or deleted; vault access removed; service-account rate limit; desktop app locked | Item read by IDs fails as `Source` naming vault and item IDs and the check `op item get <id> --vault <id>`; rate-limit and lock are retried reads (NR-3) then reported with the specific cause the exit code allows; never falls back to a title lookup (FR-13) | `1Password item <id> not found in vault <id> (moved or archived?); Next: opv doctor --env prod` | Fixtures per failure |
| NR-27 | **Missing or broken dependency** (op, flyctl, az not installed, not on PATH, wrong architecture, missing az extension, not executable) | Resolved once per run in preflight; only the CLIs the chosen environment needs are required (FR-36); the install command for the detected OS is printed; az extensions never auto-installed (NR-11) | `az not found; Next: curl -sL https://aka.ms/InstallAzureCLIDeb \| sudo bash` | Missing-binary tests per CLI |
| NR-28 | **Provider outage** (1Password, Fly, Azure region or ARM down) | Reads exhausted after NR-3 retries before any write ⇒ exit 9 `provider unavailable`, naming the provider, the step and its status page (status.1password.com, status.flyio.net, azure.status.microsoft); nothing written. Outage after writes began ⇒ NR-2 | `Azure did not respond after 3 attempts (key vault list); nothing was changed. Check https://azure.status.microsoft, then re-run` | Fake persistent failure before and after first write |
| NR-29 | **Temporary network glitches**, DNS failures, captive portals, proxy/TLS interception | Read retries (NR-3); proxy env (`HTTPS_PROXY`, `NO_PROXY`, `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`) passed through untouched to CLIs; a write's dropped connection is NR-2 | Retry lines; on exhaustion the NR-28 message with a hint to check network/proxy | Env pass-through test |
| NR-30 | **Eventual consistency**: a read right after a write returns the old value or version (Key Vault, ARM, Fly list) | After a write, the confirming read polls until it observes the written version or the deadline (bounded, with progress); never reports "unchanged" from a stale read | `confirming Key Vault version 4668… (2 s)` | Stale-then-fresh fixture |
| NR-31 | User cannot tell why a CLI failed, but its stderr may hold a secret | Child stderr held in memory (last 64 KiB, zeroized), scrubbed of every value read or staged in the run (raw, JSON, Go and Python quoting, base64, base64url, percent) and of token, key and password patterns; an excerpt attaches only to the error of its own call (call ids; the failure's diagnosis probes excepted); stdout and stdin never shown | After the error line: `  az said: <line>` (≤5 lines); with `--verbose`, `    stderr:` lines and `    stdout: <n> bytes, JSON object with keys: …` per call | Marker value in fake stderr in each encoding never reaches output; each pattern; ≤5 labelled lines; verbose shape without content; a failed probe followed by a successful call attaches nothing; `az said:` / `kubectl said:` survive diagnosis |

## 7. Rejected

- **Distributed locks** (a lock secret in the store). They add a failure mode (stale lock)
  worse than the race they prevent; detection plus convergence covers the race.
- **Retrying writes with idempotency keys.** None of the three CLIs accepts one.
  Reconcile-by-read gives the same guarantee.
- **Capturing child stderr to classify errors.** SR-1 keeps stderr uncaptured; classification
  uses exit codes, effect type and a read-back instead.
- **Parallel calls.** Fewer calls first (NR-9); concurrency only if the live run shows a need.
