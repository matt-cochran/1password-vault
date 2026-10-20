# DESIGN-FMECA review: session reuse (#203)

A separate agent reviewed `session-reuse.md` (fbd1d58, opv 0.13.0 + lanes) using the owner's
DESIGN-FMECA procedure. The evidence came from the code at c27bd84 and from op 2.40.0's own
`op --help`, `op signin --help`, `op whoami --help`, `op run --help` and binary strings, all
read-only. Nothing was signed in.

**Verdict: approve after H1-H3, which are applied in `session-reuse.md`, and after the owner
decides H4 and H5.** The design breaks none of the owner's fixed decisions: app reuse, `eval`
elsewhere, no daemon, never on disk, argv or logs, and MCP never signs in. H5 is a place where
shipping as drafted *would* break "never in logs".

## Phase 1: Architecture validity

| Component | Purpose | Class | Evidence | Note / simpler alternative |
|---|---|---|---|---|
| `opv login --shell` (posix, fish) | carry a session with no holder process | Essential | Adapted (op's own `eval $(op signin)`) | none |
| `--shell=powershell` | the same for pwsh | Speculative | native op.exe probably prints `$env:` lines, which `session_assignment` (`setup_runtime.rs:171`) rejects; 4104 logging | withhold (H5) |
| stdout-is-a-pipe guard | keeps the token off screens and files | Essential | Adapted, **insufficient**: `\| cat` passes | require the pipe's reader to be the parent shell (M1) |
| raw stdout write past `OutputGuard` | the only way the line can reach the shell unmasked | Essential (missing in draft) | Proven: the guard masks `OP_SESSION_\w*=` (`scrub.rs:348`) | H2 |
| `DesktopIntegration` detection | doctor's wording, the expiry cause | Useful | Speculative inputs (I1, O2, I3) | keep steps 1-4 static; Linux `Available` only with the app running (M2) |
| `SignInKind` from V1 | App vs token at sign-in | Essential | Proven (`op --help`, `--session`) | confirm App with one probe (M9) |
| `op shell session` doctor row | live or expired | Useful | Adapted; the draft's `whoami` check is contradicted by #167 | vault list (H3) |
| "already live" short-circuit | fewer prompts and emissions | Useful | Adapted, once it uses the vault list | removing it is the fallback |
| `OP_SESSION*` strip for non-op children | target CLIs never get the session | Useful → Essential | Adapted; covers only captured calls | all spawn paths (M6), plus `opv run` (H1) |
| `opv run` always via `local-delivery` | the app never gets `OP_*` | Essential (missing in draft) | Proven in the step (`local_delivery.rs:182`) | H1 |
| `ReusePath` / expired rendering | the right Next on expiry | Useful | its interface cannot map an account to a variable | M3 |
| e2e canary scan | proves no leak | Essential | Adapted; channels missing | M8 |

**Revised architecture.**
- Retained: posix and fish emitters, `SignInKind`, detection steps 1-4, the doctor rows, the expiry rendering.
- Added: the unguarded single write (H2) and the delivery step for every local `opv run` (H1).
- Simplified: liveness becomes one function on the #167 rule (H3).
- Demoted: PowerShell, withheld (H5).
- Removed: nothing else. Removing the short-circuit is the fallback if H3's check proves flaky.

## Phase 2: Iteration 1 risk table

S/P = severity/probability. Res = residual S/P. Obs = how the failure shows up.

| # | Domain | Failure mode: cause → effect (evidence) | S/P | Poka-yoke + observability (TRIZ where there is a trade-off) | Res |
|---|---|---|---|---|---|
| H1 | Security | **`opv run`'s app inherits the session.** Only products with `[products.<p>.local]` go through the delivery step (`run.rs:345-391`). Otherwise `op run -- <cmd>` starts the app directly, and `op run` passes shell variables through (`op run --help`, precedence section). §6 "enforced, with or without `declared_only`" is false. The same path already leaks opv's in-command session today (`add_op_session` on program `op`). Every dev server, test runner and `npm` script gets full vault access for the session's life | High/High | Every local `opv run` puts `local-delivery` between `op run` and the app, in inherit mode when there is no `local` section; it removes every `OP_*`. Obs: S8 with and without `local`, and an owner recording of `op run -- env` names so the sim matches op | Low/Low |
| H2 | Tech | **The emitted line is masked.** main wraps stdout in `OutputGuard` (`main.rs:1950-1957`). The guard masks `OP_SESSION_\w*=…` (`scrub.rs:348`), and §5.6 registers the token, so the fish line is masked too. §7.4's `run(.., out: &mut dyn Write)` invites passing the guard. The shell then evals `********`, every later `op` call fails, and the core feature is dead | High/High | `run` returns `ShellEmit`. main's `Login` arm alone writes it to the raw lock after a second `stdout_kind()` check, and EPIPE becomes `terminal_lost`. TRIZ: separation in space; the guard stays on every other byte. Obs: S1b | Low/Low |
| H3 | Runtime/UX | **"Already live" and doctor `live` trust `whoami`.** #167, found live (`setup.rs:273`): a stale `OP_SESSION_*` keeps `whoami` naming the account while the vault list is signed out. Then `eval "$(opv login --shell)"` prints nothing, says "Already signed in", and **can never refresh**. Every command keeps prompting, and doctor says `live` | High/Med | One `shell_session` on the vault-list rule, shared by doctor and `--shell`. Obs: S6b | Low/Low |
| H4 | Security | **Everything started from the shell inherits the session.** That includes assistants (Claude Code's Bash tool can `op read` any secret with no prompt, and its activity keeps the idle timer alive), install scripts that harvest the environment, editors and language servers. MCP's write refusal (#133) doesn't cover `op` itself. The target user (WSL plus an assistant in the same terminal) is the likely case. §6 rates this "documented" | High/Med | **Owner decision.** Recommended: emit a non-exported shell variable plus an `opv` function that passes it only to `opv` (§5.2 note). Children, assistants and MCP never get it. Trade-off: plain `op` and scripts in that shell aren't signed in. TRIZ: separation in space (the variable belongs to the shell, the environment to opv). Fallback: keep the export and add a stderr warning at sign-in. Obs: doctor's `inherited_by_assistant` row | Low/Low (function); Med/Med (export) |
| H5 | Security | **PowerShell logs the token.** With script-block logging on, event 4104 records the `Invoke-Expression` text, which breaks the fixed "never in logs" rule. Native op.exe probably prints `$env:` lines, which `session_assignment` rejects as `Bug` (inferred), so the main audience may already be broken. Linux pwsh is rare | High/Low | **Owner decision.** Recommended: withhold `--shell=powershell` in 0.14 (applied as "withheld"); `choice_required` until decided. If shipped, refuse when the policy key is set | Low/Low (withheld) |
| M1 | Security/UX | A pipe isn't an eval. `opv login --shell \| cat`, `\| tee f`, `\| clip.exe`, a named FIFO or `>(…)` all pass `S_ISFIFO`, so the token reaches the screen or a file. A person debugging "why doesn't eval work" does exactly this | Med/Med | Linux/WSL: the pipe's read end (fd 1's `pipe:[inode]`) must be open in the parent's `/proc/<ppid>/fd` (bash/zsh `$(…)`, fish `\| source` and pwsh all read it themselves; a sibling `cat` doesn't). Otherwise `shell_eval_required`. macOS/Windows: `S_ISFIFO` only, an accepted residual (the app is usual there). Obs: S7 gains `\| cat` | Low/Low (Linux) |
| M2 | UX | Step 6 and §7.3 treat any Linux with a display as `Available`, and `session_cause` returns `AppLocked`. CLI-only users on a Linux desktop (op with `op account add`, no app) get "turn on Developer > Integrate" in doctor. Under `--json` they get "unlock the 1Password app" (`render.rs:3183`) instead of `<refresh>`, so an assistant hands them the wrong step | Med/Med | Linux: `Available` only when a `1password` process is running (`/proc/*/comm`); otherwise `Unavailable { NoApp }`. `session_cause` uses `AppLocked` only for `Active`, or today's macOS/Windows/op.exe. Obs: doctor JSON `reason` | Low/Low |
| M3 | Tech | §7.3 `reuse_path(host, account)` can't name the variable: op suffixes it with the shorthand or user UUID, and opv's account is matched against `op account list` (`account.rs:417-421`). `Host::op_session_in_env` is a bool where §4.3 needs a name. `host::op_session_vars()` duplicates `account::session_var_names()` (`account.rs:122`) | Med/High | Reuse `session_var_names`. Extract `session_var_owner(var, listed)` from `session_var_findings`. `reuse_path(account, vars, listed)`; with no listing and exactly one variable, `Shell`. Obs: S3/S4 with two accounts | Low/Low |
| M4 | UX | With no account, `session_vars` also emits a bare `OP_SESSION`. opv's own #142 check calls a bare one `stale_session_variable` and says "unset OP_SESSION" (`account.rs:415`), so doctor contradicts login | Med/Med | `--shell` emits only `OP_SESSION_<id>`: an account is always resolved first (`choose_account_with`, or `choice_required --account`). Obs: S11 has no stale finding after eval | Low/Low |
| M5 | Security | Wrong-shell syntax echoes the token. `$SHELL` is the login shell (§10.8). pwsh's parse error prints the offending line (`+ export OP_SESSION_x=…`), and so does fish's for function syntax (H4). §10.8's claim that the shell "rejects it without running anything (safe)" doesn't hold there; bash and zsh print only the command word | Med/Med | Linux/WSL: take the shell from the parent's `/proc/<ppid>/comm` (the parent M1 finds), falling back to `$SHELL`. An explicit `--shell=X` that contradicts a recognised parent is refused (`shell_mismatch`, before any prompt). Obs: S2 mis-shell cases scan the shell's stderr | Low/Low |
| M6 | Security | The non-op strip is only in `command_for` (captured calls). `run_inherited`/`run_inherited_clean` start `flyctl` inherited (`fly/mod.rs:933`), and the editor (`config_cmd.rs:538`) inherits the variable as well | Med/Med | One `strip_op_session(cmd, program)` in all three runner spawn paths, plus the editor. `opv login -- <cmd>` uses `spawn_child` and keeps it by design. Obs: the S8 call log | Low/Low |
| M7 | UX | Expired under MCP: Next is `<refresh>`, but a running MCP server or assistant keeps its environment snapshot, so a refresh in the person's shell never reaches it and the loop repeats | Med/Med | Under MCP, Next says to refresh, then restart the assistant from that shell. Moot under H4's function form, where MCP never holds a session. Obs: MCP `next` text test | Low/Low |
| M8 | Verification | The canary scan misses channels: the **stdout** of every other command (S1, S3 `--json`, S11), MCP responses, `TMPDIR` outside the temp root, history (`script -c 'sh …'` writes none, so that check proves nothing), the wrong-shell echo (M5) and `\| cat` (M1). S8 and S6b are only as good as the sim | Med/High | Add every stdout except the one capture, an MCP case started from an eval'd environment, `TMPDIR` inside the root, the M1 and M5 cases, and the sim fidelity recordings (H1, #167). Obs: the scan itself | Low/Low |
| M9 | Runtime | `SignInKind::App` means "op printed nothing". If a later op prints elsewhere or nothing, the person sees "Nothing to set", exit 0, and every later command prompts | Med/Low | Confirm App with §3.2's probe (`whoami` with `OP_SESSION*` removed succeeds); otherwise `Cause::Bug { "op signin gave no session" }`. Obs: the Bug code in reports | Low/Low |
| M10 | Security | `set -x` / `fish_trace` print `+ eval 'export OP_SESSION_x=…'` to stderr: scrollback, or a file when stderr is redirected | Med/Low | Can't be prevented: any evaluated text is traced, and the parent's xtrace is invisible to opv. Documented. Accepted residual (constraint) | Med/Low |
| D1 | Delivery | The lanes are building from the draft. H1, H2 and H3 change §7 interfaces, and `run.rs` belonged to no lane | Med/High | §7 now assigns `run.rs` to `session-desktop-reuse` and the raw write to `session-shell`. See the interface list below | Low/Low |
| L1 | Runtime | `OP_BIOMETRIC_UNLOCK_ENABLED` values: §3.2 matches only `false`/`0`. op is Go; `FALSE`, `f`, `False` are likely accepted too | Low/Med | Parse as Go's `ParseBool`; anything else is ignored | Low/Low |
| L2 | Runtime | O2 (no `user_type` under the app) has one recording and no fixture | Low/Med | It fails safe (`Unknown`, warn only). The owner recording is in §8.1 | Low/Low |
| L3 | Runtime | I1: op keeps a cache daemon (`--cache` defaults to true on UNIX; `op-daemon.sock` was seen in `$XDG_RUNTIME_DIR`). If it ever served a CLI session with no variable, the probe would see `user_type` and report `Unknown` | Low/Low | Fails safe; keep | Low/Low |
| L4 | Runtime | I3: SSH into, or remote desktop onto, a Linux machine running the app is misclassified one way or the other | Low/Low | After M2 both are safe: the eval path still works, and V1 decides at sign-in | Low/Low |
| L5 | UX | I4 and revocation: doctor's "(30 minutes idle)" asserts a cause, but an `op signout` elsewhere reads the same | Low/Med | Show no numbers: "expired or signed out" (applied in §3.3) | Low/Low |
| L6 | Tech | `OP_SESSION_DELEGATION_ENABLED` (in op 2.40's strings) matches `OP_SESSION_*`. It would count as a session in `session_var_names`, MCP's `credential_in_environment` (`mcp.rs:526`), #142 and the strip | Low/Low | One `is_session_var` predicate that excludes it by name (unverified that it is ever set) | Low/Low |
| L7 | Tech | Spec contradiction: §5.1 says `require_equals` makes `--shell dev` mean auto + env `dev`; §5.5 and §8.2 list it as a usage error | Low/High | §5.5 corrected (applied): `--shell dev` is valid; `--shell=dev` is the usage error | Low/Low |
| L8 | Runtime | A shell that substitutes through a temp file (ksh93) is refused | Low/Low | Safe; documented | Low/Low |
| L9 | UX | Forgetting `eval`, as in `"$(opv login --shell)"` alone, makes bash print `export OP_SESSION_x=…: command not found` | Low/Low | Docs always show `eval`. Accepted | Low/Low |

**Checked, sound:**
- `signin_command` already strips inherited sessions and `OP_ACCOUNT` (`setup.rs:362-388`).
- An unrecognised `op signin` line fails closed (`setup_runtime.rs:160`).
- The remote step passes no `OP_*` (`remote_delivery.rs:233`, `:370`).
- In-command sign-in still runs on any `op_not_signed_in` (`main.rs:1962`), so the shell expiry path loses nothing.
- V1, V2 and V3 match op 2.40.0's help.

**Remaining after iteration 1.**
- High: H4 and H5, pending the owner. Both have a recommended fix that brings them to Low.
- Medium: M10 (`set -x`), accepted because opv can't see or prevent it. M1's macOS/Windows residual.
- Low: the rest.

Stopping: further mitigation adds surface, not safety.

## Phase 3: Systemic review

- **Calibration.** Detection rests on two inferences, I1 and O2, both made to fail toward
  `Unknown`. V1 settles each sign-in, and M9 cross-checks it. Validate with §8.1's owner recordings
  before the release.
- **Observability.** A dead feature (H2) or a stuck refresh (H3) would show up only as "it keeps
  asking". S1b and S6b turn both into red tests. Doctor's rows name the variable, never the value.
- **Over-engineering.** PowerShell is the speculative part (H5). The detection enum is justified
  for doctor and for picking the right Next. The short-circuit is kept only on the #167 rule.
- **Oversimplification.** Equating "a pipe" with "an eval" (M1) and "has a display" with "has
  the app" (M2) was too simple. The fixes are Linux-only `/proc` reads, which fits WSL as the main
  target.
- **Incremental delivery.** The cli-surface lane merges first, unchanged. H1 is independent and
  also closes today's in-command leak, so it could ship in a patch on its own. Rollback is
  removing `--shell`; nothing persists.

## Interface changes to §7 (for the rework lane)

| § | Change | Source |
|---|---|---|
| 7.4 | `login_shell::run(req, backend, ui) -> Result<ShellEmit, Error>`: the `out` parameter is removed. New `pub struct ShellEmit { pub lines: Zeroizing<String> }`. main's `Cmd::Login` arm writes it to the raw stdout lock, past `OutputGuard`, after re-checking `stdout_kind()`; EPIPE is `terminal_lost` | H2 (applied) |
| 7.2 | `shell_session` keeps its signature but decides by `op vault list --format json` under the variable; `login_shell::run` calls it for "already live" | H3 (applied) |
| 7.3 + lane table | `run.rs::delivery_args(local: Option<&Local>, selected)`: `None` runs inherit mode with no files; the local `opv run` path always inserts the step. Owner: `session-desktop-reuse` | H1 (applied) |
| 7.1 / 5.2 | `ShellArg::PowerShell` maps to `choice_required` until the owner decides; the emitter for it isn't built | H5 (applied) |
| 7.4 | `export_lines` text (export, or variable plus function) | H4 (owner) |
| 7.1 | `StdoutKind` gains `PipeToOther` (a pipe whose reader isn't the parent); `NoIntegration` gains `NoApp`; `Cause::ShellMismatch { requested, running }` | M1, M2, M5 (proposed) |
| 7.2 | Drop `host::op_session_vars()` and use `account::session_var_names()`. `Host::op_session_in_env` stays a bool for doctor only. New `account::session_var_owner(var, listed)` and `is_session_var(name)` (excludes `OP_SESSION_DELEGATION_ENABLED`) | M3, L6 (proposed) |
| 7.3 | `reuse_path(account: Option<&str>, vars: &[String], listed: &[Account]) -> ReusePath`; `session_cause` takes the static `DesktopIntegration`, not just `&Host` | M2, M3 (proposed) |
| 7.3 | `runner::strip_op_session(&mut Command, program)` in `command_for`, `run_inherited` and `run_inherited_clean`, plus `config_cmd::edit` | M6 (proposed) |
| 7.4 | `ShellLogin` emits only `OP_SESSION_<id>`; an account is always resolved first | M4 (proposed) |
| 7.4 | `sign_in_kind` becomes `fn(vars, probe_ok: bool) -> Result<SignInKind, Error>` | M9 (proposed) |

## Decisions for the owner

1. **H4: an exported variable or an `opv` function.** Recommended: the function. Nothing started
   from the shell inherits the session, at the cost of plain `op` and scripts there not being
   signed in.
2. **H5 / §11 Q1: PowerShell.** Recommended: don't ship it in 0.14. If you want it, refuse when
   ScriptBlockLogging is on, rather than only warning.
3. **M10: `set -x`.** Accept it as a documented residual.

## Recommendations on §11

1. **PowerShell:** withhold (H5). Native Windows usually has the app, and the op.exe output
   format is unverified.
2. **`OP_ACCOUNT` export:** agree, no. opv sets it per call.
3. **Linux desktop app:** agree that `--add` routing stays. Detection needs the app process
   running, not only a display (M2).
4. **`opv logout --shell`:** agree, not now. Under H4's function form, `exit` also drops the
   function.
5. **`script(1)` for the PTY:** agree. Linux CI only; macOS's `script` flags differ.
6. **Function form (new):** see decision 1.
