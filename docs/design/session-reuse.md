# Session reuse across commands (#203)

Status: draft for 0.14.0 (cpm line v0140), 2026-10-20, revised after the DESIGN-FMECA review
(`session-reuse-fmeca.md`: fixes for H1-H3 applied here; H4 and H5 wait for the owner). Built on
opv 0.13.0. The owner chose the direction on 2026-10-20; this document specifies it.

## 1. The decision

A sign-in that one opv command makes ends with that command (`runner.rs`, `OP_SESSION`: "gone
when the process exits"). On WSL with the Linux `op`, every command then asks for the password.

- **With the 1Password desktop app integration,** opv reuses the app's unlock across commands.
  op and the app handle the unlock (Touch ID, Windows Hello, Linux system authentication). opv
  holds nothing.
- **Without it** (WSL with the Linux `op`, headless, no app), `opv login --shell` prints only
  shell assignment lines for `eval "$(opv login --shell)"`. The token lives only in that shell's
  environment. opv never writes it to disk, argv, logs or stderr.
- No daemon, no agent process, no file.
- MCP never signs in. Sign-in stays person-only.

The #203 comment ruled out an export line under FR-40 and SR-1. This design amends both with one
narrow exception (§9): the token may go to stdout of `opv login --shell`, and only when stdout is a
pipe.

| Component | Class | Why |
|---|---|---|
| `opv login --shell` | essential | the only way to carry a session without a holder process |
| stdout-is-a-pipe guard | essential | stops the token reaching a screen, scrollback or file |
| `DesktopIntegration` detection | useful | doctor's report and the right wording; reuse itself works without it |
| `OP_SESSION_*` stripped from non-`op` children, and `opv run`'s app always behind the delivery step | essential | the app and target CLIs never get the person's session (FMECA H1) |
| "already live" short-circuit | useful | fewer prompts and fewer token emissions; decided by a vault list, never `whoami` (FMECA H3) |

## 2. The three paths

| Path | When | Second command | opv holds |
|---|---|---|---|
| App | op talks to the desktop app | op asks the app; no prompt while the app keeps this terminal authorized | nothing |
| Shell | `OP_SESSION_*` exported by `opv login --shell` | op reads the variable | nothing (the shell holds it) |
| Per-command | neither | prompts again (today's behaviour, unchanged) | the session, in memory, for one process |

`opv login [<env>]` (subshell) and `opv login -- <cmd>` keep working as today.

## 3. Detecting the desktop app integration

### 3.1 Signals

| # | Signal | Source | Status |
|---|---|---|---|
| V1 | A successful `op signin` prints a session token **only when** the app integration is off | `op --help`, `--session`: "outputs session tokens for successful 'op signin' commands when 1Password app integration is not enabled" | verified (op 2.40.0 help) |
| V2 | `op signin` "only prompts for authentication if you aren't already authenticated" | `op signin --help` | verified |
| V3 | The integration needs the app's Settings > Security unlock option and Developer > "Integrate with 1Password CLI"; Linux has a "system authentication option" | `op signin --help` | verified |
| V4 | `OP_BIOMETRIC_UNLOCK_ENABLED` turns the integration on or off for one process | 1Password's environment-variable docs; the name is in the op 2.40.0 binary | documented, not in `--help` |
| O1 | `op whoami` never asks the app; with the integration it fails until another call is approved | `onepassword::wake` doc comment (found live) | observed |
| O2 | Under the integration, `op whoami --format json` has no `user_type` and no `shorthand`; under a CLI session it has both (`s06`, `s07`, `s20`) | `app_integration_whoami_is_a_person` (live, 0.5.0); fixtures s06/s07 (op 2.40.0, WSL) | observed; the app shape has no fixture |
| I1 | A `whoami` that succeeds with every `OP_SESSION*` removed from its environment, and no service-account or Connect credential, can only be the app's session | op 2 keeps CLI sessions only in `OP_SESSION_*` (V1) | inferred |
| I2 | The Linux app cannot serve a Linux `op` inside WSL | `docs/local-development.md#wsl` | observed (owner) |
| I3 | The Linux app needs a graphical session (`DISPLAY` or `WAYLAND_DISPLAY`); an SSH login without one cannot use it | none | inferred |
| I4 | The app's authorization of a terminal lapses after about 10 minutes idle, with a 12-hour cap | 1Password app-integration docs | documented, not verified here |

V1 is the only definitive signal, and it needs a sign-in. Doctor never relies on it.

### 3.2 Classification

`DesktopIntegration` (§7.1) is decided in this order, from the host first and then one probe:

1. CI, `OP_SERVICE_ACCOUNT_TOKEN`, Connect: `NotApplicable`. No probe.
2. `OP_BIOMETRIC_UNLOCK_ENABLED` is `false` or `0`: `Unavailable { reason: DisabledByEnv }`.
3. WSL with the Linux `op` (`Platform::Wsl && !op_is_windows_exe()`): `Unavailable { reason: WslLinuxOp }`.
4. Linux with neither `DISPLAY` nor `WAYLAND_DISPLAY`: `Unavailable { reason: Headless }` (I3).
5. Probe `op whoami --format json` with every `OP_SESSION*` removed, exit status plus the
   presence of `user_type` (O2; the identity is never kept). It succeeds without `user_type`:
   `Active`. It succeeds with `user_type`: `Unknown` (I1 is wrong somewhere; report, don't guess).
6. It fails on macOS, Windows, WSL with `op.exe`, or Linux with a display: `Available`. The next
   real call raises the app's prompt, or fails if the integration is off in the app's settings.
7. op missing or the probe timed out: `Unknown`.

At sign-in, V1 settles it: `SignInKind::App` when `op signin` succeeded and printed nothing,
`SignInKind::Token` when it printed an assignment.

### 3.3 What `opv doctor` reports

Two new rows after `op auth`. Neither ever fails; `op auth` stays the failing row. Doctor keeps
its existing single `wake`, and adds no prompt of its own.

| State | Row (text) | JSON `check` / `state` |
|---|---|---|
| `Active` | `ok    op app integration: on; commands here reuse the 1Password app's unlock` | `op_app_integration` / `active` |
| `Available` | `warn  op app integration: not confirmed; approve 1Password's prompt at the next command, or turn on Developer > Integrate with 1Password CLI` | `available` |
| `Unavailable` | `ok    op app integration: unavailable (<why>); sign in once per shell: <refresh>` | `unavailable`, `reason` |
| `NotApplicable` | row skipped | `skip` |
| `Unknown` | `warn  op app integration: could not tell` | `unknown` |

`<refresh>` is §5.2's eval line for the detected shell. `<why>` (JSON `reason`) is `WSL with the Linux op`,
`no graphical session`, or `OP_BIOMETRIC_UNLOCK_ENABLED=false`.

`op shell session` appears only when an `OP_SESSION*` is in the environment:

| Finding | Row | JSON `state` |
|---|---|---|
| `op vault list` succeeds under it | `ok    op shell session: live in this shell (<var>)` | `live` |
| `op vault list` fails as signed out under it | `warn  op shell session: expired or signed out` + `fix: <refresh>` | `expired` |
| an agent marker is also set | `warn  op shell session: an assistant started from this shell inherits it` | `inherited_by_assistant` |

The variable name is printed. The value never is.

Liveness is `op vault list --format json` under the variable, never `whoami`: #167 found live that
a stale `OP_SESSION_*` can leave `whoami` naming the account while the vault list says no one is
signed in (`setup.rs`, the same rule). `shell_session` (§7.2) is the one check; doctor and §5.2's
"already live" both call it (FMECA H3).

## 4. Reuse and expiry

### 4.1 App path

There is nothing to carry. Each `op` child asks the app; the app decides whether this terminal is
still authorized (I4). `sign_in_here` (main.rs) changes only its wording under `SignInKind::App`:
"Approve 1Password's prompt. This terminal then stays signed in while the 1Password app keeps it
authorized." It never says "for this command only" there. `EnvRunner` adds no session.

### 4.2 Shell path

The shell exports `OP_SESSION_<id>`. opv inherits it and every `op` child inherits it from opv.
opv adds nothing. `EnvRunner` still sets `OP_ACCOUNT` per environment, which selects the right
`OP_SESSION_<id>` when several are exported (FR-40, unchanged).

### 4.3 Expiry

A CLI session ends after 30 minutes idle (found live, `runner.rs`). op then reports one of
`OP_CLI.signed_out`'s wordings. `diagnose` maps it as follows:

| Path and situation | Behaviour | Cause, state | Next | Exit |
|---|---|---|---|---|
| App; authorization lapsed | op raises the app's prompt; approved, the call goes on | none | none | 0 |
| App; prompt unanswered for 60 s | stops | `op_not_signed_in`, `app_prompt_unanswered` | approve in the 1Password app, then run the command again | 7 |
| App; app locked, closed or integration off | stops | `op_not_signed_in`, `app_locked` | unlock 1Password; turn on Developer > Integrate with 1Password CLI | 7 |
| Shell; expired; terminal, no `--json` | one stderr line, then today's in-command sign-in (`may_sign_in`) and the command goes on | none | stderr: `this shell's 1Password session (<var>) expired; to refresh the shell: <refresh>` | the command's |
| Shell; expired; `--json`, no TTY, MCP | stops, never prompts (FR-40) | `op_not_signed_in`, `expired` | `<refresh>` | 7 |
| Per-command | unchanged | `op_not_signed_in`, `signed_out` | `login_then` | 7 |

"Shell" means `Host::op_session_in_env()` names a variable for the call's account. Today that
case renders `signed_out`. The expired variable stays in the shell; it is harmless, and the
refresh replaces it. `signin_command` already removes inherited `OP_SESSION_*` from `op signin`.

## 5. `opv login --shell`

### 5.1 Synopsis

```text
opv login [<env>] [--account <id>] [--add] [--no-record] --shell[=posix|fish|powershell]
```

- `require_equals = true`. Without it, `opv login --shell dev` would read `dev` as the shell.
- `bash`, `zsh` and `sh` are aliases of `posix`; `pwsh` is an alias of `powershell`.
- Without a value: `Host::shell`, from `$SHELL`; on native Windows, `powershell`. `$SHELL` names the
  login shell, not always the running one, so docs show the explicit form for fish and PowerShell.
- `conflicts_with = "command"`: `--shell` never runs a child.

### 5.2 Output per shell

stdout carries one line per session variable and nothing else. op's variable name is kept
(`session_vars`): `OP_SESSION_<id>` with an account; both it and `OP_SESSION` without one.

| Shell | Line | How the person runs it (`<refresh>`) |
|---|---|---|
| posix | `export OP_SESSION_<id>=<token>` | `eval "$(opv login --shell)"` |
| fish | `set -gx OP_SESSION_<id> <token>` | `opv login --shell=fish \| source` |
| powershell (withheld, FMECA H5) | `$env:OP_SESSION_<id> = '<token>'` | `opv login --shell=powershell \| Out-String \| Invoke-Expression` |

**PowerShell is withheld pending the owner's decision (FMECA H5, §11 Q1).** With script-block
logging (event 4104) on, `Invoke-Expression` writes the token's line to the event log, which
breaks the fixed "never in logs" rule. Native Windows op probably prints `$env:` lines, which
`session_assignment` rejects today. The lanes build `posix` and `fish`. `--shell=powershell` is
`choice_required` until the owner decides.

`<refresh>` carries `--account <id>` when the account did not come from `.opv` or the
environment's `account` setting.

Everything for the person goes to stderr through `LoginConsole`, which already writes there:
`Signed in to <label> in this shell. The session ends after 30 minutes idle; run <refresh> again
then.` Under `SignInKind::App`, stdout is empty, the exit is 0, and stderr says: `The 1Password app
integration is on: commands in this terminal already reuse its unlock. Nothing to set.`

When the shell already holds a live session for the account (`shell_session` is `Live`: a vault
list succeeds under it, §3.3), stdout is empty, there is no prompt and the exit is 0: `Already
signed in in this shell.` `Expired` goes on to the sign-in. A `whoami` that succeeds is never
enough (FMECA H3).

**Owner decision pending (FMECA H4).** The lines above export the session, so every process the
person starts from that shell inherits it: an assistant's own shell can `op read` any secret with no
prompt, and an install script can harvest it. The review recommends emitting a non-exported shell
variable plus an `opv` shell function that passes it to opv alone. The function is
`opv() { OP_SESSION_<id>="$__opv_session_<id>" command opv "$@"; }`, and fish has the same with
`set -g` and `function opv`. The trade-off is that plain `op` and scripts in that shell are no longer
signed in. `export_lines`' signature is the same either way; only its text changes.

### 5.3 Quoting

- **The name** must match `^OP_SESSION(_[A-Za-z0-9_]+)?$` (`session_assignment` already enforces
  it), so it needs no quoting in any shell.
- **The token** has already passed `session_assignment`'s charset, `[A-Za-z0-9._/+=-]+`. Anything
  else is `Cause::Bug`, and nothing is printed.
- **posix and fish:** the token goes through `shell_word_for(token, false)`. For that charset it
  prints the token bare. A future charset change would get POSIX single quotes. fish reads
  `'…'\''…'` the same way.
- **powershell:** always `'` + `token.replace('\'', "''")` + `'`. `shell_word` is not enough
  here: a bare word on the right of `=` is parsed as a command.

### 5.4 Account, `.opv`, environment

`--shell` goes through the same steps as the subshell: `choose_account_with` (`--account`, `.opv`,
`OP_ACCOUNT`, the menu), the `note (…)` findings, `run_recording`'s H2 rule (`.opv` records the
account only after the sign-in succeeds; `--no-record` leaves it alone), and the environment's
`account` when `<env>` is given. The only difference is the last step. Instead of
`backend.child(command)`, opv takes the session (`Backend::take_session`) and writes §5.2's lines.
`opv login -- <cmd>` and the plain subshell are unchanged.

### 5.5 Refusals

Checked in this order, all before any prompt and any `op` call. Each prints nothing on stdout, so
the `eval` gets an empty string. The cause goes to stderr.

| Situation | Cause code | Exit |
|---|---|---|
| `--json`, `--shell` with `-- <cmd>`, `--shell=<unknown>` such as `--shell=dev` (`--shell dev` is valid: auto shell, env `dev`; FMECA L7) | `usage` (clap; login has no `--json`) | 2 |
| `CI` or `GITHUB_ACTIONS` | `terminal_required` (`ci`) | 6 |
| stdin or stderr is not a terminal | `terminal_required` (`no_tty`) | 6 |
| a service-account or Connect credential is set | `own_session_required` | 7 |
| an agent marker (`refuse_if_agent`, `Cmd::LoginShell`) | `person_only` | 6 |
| stdout is a terminal, a regular file, or anything but a pipe | `shell_eval_required` (new) | 6 |
| no value, and `$SHELL` is `Shell::Other` | `choice_required` (`--shell`, `posix`/`fish`/`powershell`) | 2 |

`shell_eval_required` reads "this prints a 1Password session for your shell to evaluate, so it
only writes to a pipe". Next is `<refresh>`. The check is `fstat` `S_ISFIFO` on Unix and
`GetFileType == FILE_TYPE_PIPE` on Windows. bash and zsh `$(…)`, fish `| source` and PowerShell
pipelines all hand opv a pipe (inferred, covered by §8).

### 5.6 Where the token goes

- It is read once from `op signin`'s captured stdout (`run_prompted`), and kept as a
  `SecretValue`.
- It is registered with the scrubber (`scrub::register_credentials_from`) before anything else
  runs, so `--verbose`, error excerpts and panics mask it.
- It is written once, in a `Zeroizing` buffer, then flushed. `login_shell::run` never writes it:
  it returns the lines (`ShellEmit`, §7.4), and main's `Cmd::Login { shell: Some(_) }` arm
  writes them to the raw stdout lock (`PipeSafe`'s inner handle), not through `OutputGuard`. The
  guard would mask them: `scrub.rs`'s `OP_SESSION_\w*=` rule, plus the registered token, mean the
  shell would `eval` `********` (FMECA H2). This is the only write that bypasses the guard. main
  checks `stdout_kind()` again right before it, and every other byte of the command still goes
  through the guard. A failed write, including EPIPE, which `PipeSafe` otherwise swallows, is
  `terminal_lost`, and nothing is retried.
- It never goes to argv (op gets it only through a child's environment), a file, `history`,
  receipts or the MCP server.

## 6. Security properties

| Property | Status | How |
|---|---|---|
| Shell history | enforced | The typed line holds no token. A bare `opv login --shell` is refused (stdout is a terminal). A pipe to another reader (`\| cat`, `\| tee`) still passes `S_ISFIFO`: FMECA M1. `set -x`, `fish_trace` and `Set-PSDebug -Trace` echo the evaluated line to stderr: out of scope, documented. |
| Never on disk, argv, logs or stderr from opv | enforced | §5.6, plus the canary scan (§8). |
| `/proc/<pid>/environ` | out of scope, mitigated | The same user and root can read any child's environment, as with today's subshell and op's own `eval $(op signin)`. Mitigation: opv now removes `OP_SESSION*` from every non-`op` child it starts (`flyctl`, `gh`, `az`, `kubectl`), on top of the app strip. Children the person starts from the shell (editors, build tools, assistants) inherit it: owner decision H4 (§5.2). |
| Token lifetime | mitigated | op's 30-minute idle expiry. opv adds no lifetime and cannot shorten it. The variable dies with the shell. `op signout --account <id>` ends it early. A refresh while the session is live prints nothing (§5.2). |
| Inheritance into `opv run` children | enforced (changed, FMECA H1) | `op run` needs it, and `op run` passes its shell environment to its child. Today only a product with `[products.<p>.local]` runs its app through the delivery step (`run.rs`, `delivery_args`). Otherwise the app gets `OP_SESSION_*` straight from `op run`: the shell's, or opv's in-command session (`add_op_session`). From 0.14 every local `opv run` puts the `local-delivery` step between `op run` and the app. Without a `local` section it runs in inherit mode with no files, and it removes every `OP_*` (`local_delivery::child_env`). `opv login -- <cmd>` passes the session on by design. |
| Assistants started from the shell | mitigated | MCP refuses 1Password writes while `OP_SESSION*` is set (#133, `credential_in_environment`). Doctor warns (§3.3). An assistant's own shell can still run `op`: documented. |
| PowerShell logging | withheld (FMECA H5) | Script-block logging (event 4104) records the `Invoke-Expression` text, which puts the token in a log. `--shell=powershell` waits for owner question 1. |
| Canary scan in tests | enforced | §8.3. A test fails on any leak. |

## 7. Interfaces for the parallel lanes

Merge order: `session-cli-surface` first. The other three rebase onto it and replace its stub
bodies, keeping the signatures. Each lane edits only the files listed for it.

| Lane | Files |
|---|---|
| `session-cli-surface` | `src/main.rs` (flag, wiring, help text), `src/app/mod.rs` (three `pub mod` lines), `src/app/desktop_integration.rs` (new, types only), stub `src/app/doctor_session.rs` and `src/app/login_shell.rs`, `src/cause/{mod,codes,render}.rs` |
| `session-desktop-detect` | `src/host.rs`, `src/app/doctor_session.rs`, two call lines in `src/app/doctor.rs` |
| `session-desktop-reuse` | `src/app/signin.rs`, `session_cause` in `src/adapters/onepassword.rs`, `command_for` in `src/runner.rs`, the `eprintln!` in `sign_in_here` (main.rs), and (FMECA H1) `delivery_args` and its caller in `src/app/run.rs` |
| `session-shell` | `src/app/login_shell.rs`, `src/app/login.rs`, `Backend` in `src/app/setup.rs`, its impl in `src/app/setup_runtime.rs`, and (FMECA H2) the raw stdout write in main's `Cmd::Login` arm |

### 7.1 `session-cli-surface`

```rust
// src/app/desktop_integration.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DesktopIntegration {
    Active,
    Available,
    Unavailable { reason: NoIntegration },
    NotApplicable,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoIntegration { WslLinuxOp, Headless, DisabledByEnv }
/// What one successful `op signin` produced (V1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignInKind { App, Token }
/// What fd 1 is (§5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StdoutKind { Pipe, Terminal, File, Other }

// src/cause/mod.rs: new variant, code `shell_eval_required`, exit 6, retry AfterFix
Cause::ShellEvalRequired { stdout: StdoutKind, shell: crate::host::Shell }
// src/cause/mod.rs: new `Cmd::LoginShell` for `refuse_if_agent`
// render.rs: SessionState::Expired gains Next = login_shell::refresh_command(..)
```

`Cmd::Login` gains `#[arg(long, require_equals = true, num_args = 0..=1,
default_missing_value = "auto", conflicts_with = "command", value_name = "SHELL")] shell:
Option<ShellArg>`. `ShellArg` is a clap `ValueEnum` in main.rs (`Auto`, `Posix`, `Fish`,
`PowerShell`, with the aliases), mapped to `host::Shell`.

### 7.2 `session-desktop-detect`

```rust
// src/host.rs: new fields on Host (Copy stays), set in from_env; HostEnv gains nothing new
impl Host {
    /// `Some(false)` for OP_BIOMETRIC_UNLOCK_ENABLED = false/0, `Some(true)` for true/1.
    pub fn op_biometric_override(&self) -> Option<bool>;
    /// DISPLAY or WAYLAND_DISPLAY is set and non-empty.
    pub fn graphical_session(&self) -> bool;
    /// The OP_SESSION / OP_SESSION_* names set and non-empty, by name only.
    pub fn op_session_in_env(&self) -> bool;
}
pub fn op_session_vars() -> Vec<String>; // names only, sorted

// src/app/doctor_session.rs
pub fn detect(host: &Host, r: &dyn CommandRunner) -> DesktopIntegration;   // §3.2
pub fn classify_static(host: &Host) -> Option<DesktopIntegration>;          // steps 1-4, pure
pub enum ShellSession { Live { var: String }, Expired { var: String } }
/// FMECA H3: decided by `op vault list --format json` under the variable (the #167 rule),
/// never by `whoami`. The one liveness check: doctor and `login_shell::run` both call it.
pub fn shell_session(host: &Host, r: &dyn CommandRunner, account: Option<&str>) -> Option<ShellSession>;
pub fn rows(integration: DesktopIntegration, shell: Option<&ShellSession>, host: &Host) -> Vec<DoctorRow>;
pub struct DoctorRow { pub name: &'static str, pub status: RowStatus, pub text: String,
                       pub fix: Option<String>, pub state: &'static str, pub reason: Option<&'static str> }
pub enum RowStatus { Ok, Warn, Skip }
```

`doctor.rs` maps `DoctorRow` onto its private `Row` and `State` after `op auth`.

### 7.3 `session-desktop-reuse`

```rust
// src/app/signin.rs
pub fn sign_in_notice(kind: Option<SignInKind>, host: &Host) -> &'static str; // §4.1
pub fn reuse_path(host: &Host, account: Option<&str>) -> ReusePath;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReusePath { App, Shell { var: String }, PerCommand }
// SignInKind comes from login_shell::sign_in_kind (session-shell); this lane only reads it.
```

`session_cause` returns `SessionState::Expired` when `ReusePath::Shell` holds for the call's
account. It returns `AppLocked` for `Available`/`Active` hosts beyond today's `op.exe` case.
`command_for` removes `OP_SESSION` and `OP_SESSION_*` when `program != "op"`.

FMECA H1, `src/app/run.rs`: `delivery_args(local: Option<&Local>, selected)`. With `None` it emits
`<opv> local-delivery --key <k>... --`, with no `--declared-only`, `--dir-env` or `--file`. The local
`opv run` path always calls it, so `op run`'s child is always the step, which removes every `OP_*`.
The remote path (`remote_args`) is unchanged; it already passes no `OP_*`.

### 7.4 `session-shell`

```rust
// src/app/login_shell.rs
pub struct ShellLogin<'a> {
    pub fleet: Option<&'a Fleet>,
    pub fallback: Option<&'a str>,
    pub env: Option<&'a str>,
    pub record: Option<(&'a std::path::Path, &'a str)>,
    pub shell: crate::host::Shell,
}
pub fn stdout_kind() -> StdoutKind;
pub fn check_stdout(kind: StdoutKind, shell: Shell) -> Result<(), Error>;
pub fn export_lines(shell: Shell, vars: &[(String, SecretValue)]) -> Result<Zeroizing<String>, Error>;
pub fn refresh_command(shell: Shell, account: Option<&str>) -> String;
pub fn sign_in_kind(vars: &[(String, SecretValue)]) -> SignInKind; // empty: App
/// FMECA H2: what main writes, unguarded, to the raw stdout lock. Empty for App/already live.
pub struct ShellEmit { pub lines: Zeroizing<String> }
pub fn run(req: ShellLogin<'_>, backend: &mut dyn Backend, ui: &mut dyn Interaction)
           -> Result<ShellEmit, Error>; // no `out`: it never touches the guarded writer

// src/app/login.rs: run_recording split; the subshell path calls both halves
pub fn sign_in_recording(fleet: Option<&Fleet>, fallback: Option<&str>, env: Option<&str>,
    record: Option<(&Path, &str)>, backend: &mut dyn Backend, ui: &mut dyn Interaction)
    -> Result<Option<String>, Error>; // the account signed in to
// src/app/setup.rs
trait Backend { fn take_session(&mut self) -> Vec<(String, SecretValue)> { Vec::new() } }
```

## 8. Tests

### 8.1 Simulator (`tests/sim/op.rs`, `world.rs`)

- `op.app_integration: {"enabled": bool, "authorized": bool}`. When enabled, `op signin` exits 0
  with empty stdout (V1). Calls succeed without `OP_SESSION*` while `authorized`. `whoami` uses the
  app shape (no `user_type`, no `shorthand`, O2).
- `op.cli_sessions: true`. `op signin --force` prints `export OP_SESSION_<user>="<SESSION_CANARY>"`
  without prompting. Later calls need that variable with that value. `"expired": true` answers
  with the signed-out recording (05/06/07).
- The call log records, for each call, argv and the **names** of the `OP_*` variables it got.
- `RECORD.md` gains three owner recordings: `whoami` under the app integration (macOS or
  Windows), an expired token's `whoami` and `vault list`, and the variable **names**
  `op run -- env` passes to its child under a CLI session. The sim's `op run` must pass
  `OP_SESSION_*` through as real op does (H1).

### 8.2 End-to-end (`tests/e2e/scenarios/session_reuse.rs`, Linux)

The PTY is `script -qfec '<sh line>' <typescript>` (util-linux). Inside it, stdin and stderr are
the PTY, and `$(…)` gives opv a pipe, exactly as a person's shell does.

| Case | Expect |
|---|---|
| S1 eval, then `opv check dev` and `opv inventory --json` | one `op signin` in the log; both exit 0 |
| S2 `--shell=fish` and `--shell=powershell` into a capture pipe | golden lines; run under `fish`/`pwsh` when installed, skipped otherwise |
| S3 expired, then `opv check dev --json` | exit 7, `op_not_signed_in`, `state: expired`, next is `eval "$(opv login --shell)"` |
| S4 expired, `opv check dev` at the PTY | stderr names the variable and `<refresh>`; one in-command sign-in; exit 0 |
| S5 app integration on | `--shell` stdout empty, exit 0; two commands, no `op signin` |
| S6 already live | stdout empty, no `op signin` |
| S7 refusals (§5.5, one each) | the code and exit listed; stdout empty; a `> file` target stays empty |
| S8 `opv run dev -- env` after eval, for a product **with and without** `[products.<p>.local]` | no `OP_*` in the app's output; no `OP_SESSION*` name on any non-`op` call (H1) |
| S1b eval, then `opv check dev` | the session works: the emitted line is not masked (H2) |
| S6b a stale variable whose `whoami` still succeeds but whose vault list is signed out (#167) | `--shell` signs in and prints a new line; doctor says `expired` (H3) |
| S9 `.opv` | `--account X --shell` records X only after success; `--no-record` leaves it |
| S10 `opv login -- opv check dev` | unchanged (regression) |
| S11 `opv doctor --json` per world state | `op_app_integration` and `op_shell_session` as §3.3 |

Unit tests cover `export_lines` (golden per shell, a quote in the token for PowerShell and POSIX),
`classify_static` (each step of §3.2), `stdout_kind`, and the clap cases (`--shell dev`,
`--shell -- x`).

### 8.3 Canary scan

`SESSION_CANARY` is a unique value per test. A test passes only when the canary appears exactly once
in total, as the expected line in S2's capture pipe or not at all in eval cases. It must be absent
from:

- every stderr, including `--verbose`;
- the `script` typescript;
- every file under the test's temp root (HOME, XDG dirs, project, `.opv`, history, receipts),
  except S2's capture file;
- the sim's argv log.

`Rule::NoCanaryValue` in `tests/e2e/matrix.rs` adds `SESSION_CANARY` to `canaries()`, so every
matrix cell scans for it as well.

## 9. Docs to change

- `requirements.md`: SR-1 gains "Documented exception (#203)", the one stdout of §5.6. FR-40's
  login paragraph drops "No token is printed and nothing is evaluated" for `--shell`. The §8
  sign-in row names the expired-shell Next.
- `main.rs` `LOGIN_QUICK`/`LOGIN_MORE` (drop "No token is printed and nothing needs eval"),
  `Host::signin_command`'s doc comment.
- `docs/usage.md` (sign-in), `docs/local-development.md` (WSL: `eval "$(opv login --shell)"`),
  `docs/guided-setup.md`, `docs/security.md` (§6 table), `docs/mcp.md` (writes refused in such a
  shell).
- `docs/agent-skill.md`, `llms.txt`, the opv skill: an assistant never runs `--shell`; it hands
  `<refresh>` to the person.
- `docs/design/README.md` index, `CHANGELOG.md`.

## 10. For the FMECA reviewer: inferred op behaviour

1. **I1:** `whoami` succeeding with no `OP_SESSION*` means the app. If op ever caches a CLI session
   elsewhere, `Active` is wrong.
2. **O2:** the app-shaped `whoami` has no `user_type`. This is recorded once (0.5.0) and has no
   fixture.
3. **I3:** headless Linux has no integration. A running app on a remote desktop, or an SSH session
   on the same machine, may still serve `op`.
4. **I4:** the app's 10-minute and 12-hour limits come from docs and are untested.
5. The expiry wording matches `OP_CLI.signed_out` for both "session expired" and a token another
   `op signout` revoked. Both are rendered `expired`.
6. bash, zsh, fish and pwsh give opv a pipe for substitution (§5.5). A shell that uses a temp file
   would be refused, safely.
7. `OP_BIOMETRIC_UNLOCK_ENABLED` is not in `--help`. Its accepted values are assumed to be
   `true`/`false`.
8. `$SHELL` is the login shell. A person in fish under a bash login gets POSIX lines, which fish
   rejects without running anything (safe, but confusing).

## 11. Open questions for the owner

1. **PowerShell.** Ship `--shell=powershell` given script-block logging (§6)? Proposed: ship it
   with a stderr warning when the ScriptBlockLogging policy key is set. Native Windows usually has
   the app. *FMECA (H5): don't ship it in 0.14. Withheld until you decide.*
6. **Exported variable or `opv` function (FMECA H4).** See §5.2. *FMECA: the function.*
2. **`OP_ACCOUNT`.** Export it too? Proposed: no. opv sets it per call, and exporting it changes
   plain `op` in that shell (the banner's `op signout --all` conflict).
3. **Linux desktop app.** `app_holds_accounts` excludes Linux today. Proposed: detection treats
   Linux with a display as `Available`, and `opv login --add` routing stays unchanged in 0.14.
4. **Ending a shell session.** Add `opv logout --shell` (prints `unset` lines)? Proposed: not now;
   `exit` or `op signout`.
5. **PTY in tests.** Proposed: `script(1)` on Linux CI, not a new dev-dependency.
