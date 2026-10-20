//! `opv login --shell[=posix|fish|powershell]` (#203, `docs/design/session-reuse.md` §5,
//! §7.4): sign in, then print only the shell's assignment lines for the session, for
//! `eval "$(opv login --shell)"`. Writes only to a pipe.
//!
//! Stub from the `session-cli-surface` lane; `session-shell` fills the bodies and keeps the
//! signatures. [`refresh_command`] and [`check_stdout`] already work, because the error
//! catalog and `main.rs` call them; [`stdout_kind`] answers `Other` until then, so every
//! `--shell` is refused before any prompt.
//!
//! FMECA H2: [`run`] never writes the session. It returns the lines ([`ShellEmit`]), and
//! main's login arm checks stdout again, then hands them to [`write_lines`] with the raw
//! stdout lock, never the `OutputGuard` (whose `OP_SESSION_*=` rule would mask them).

use zeroize::Zeroizing;

use super::desktop_integration::{SignInKind, StdoutKind};
use super::setup::{Backend, Interaction};
use crate::cause::Cause;
use crate::domain::{Fleet, SecretValue};
use crate::error::{Error, shell_word_for};
use crate::host::Shell;

/// One `opv login --shell`: the same inputs as the subshell login (§5.4), plus the shell.
pub struct ShellLogin<'a> {
    pub fleet: Option<&'a Fleet>,
    pub fallback: Option<&'a str>,
    pub env: Option<&'a str>,
    pub record: Option<(&'a std::path::Path, &'a str)>,
    pub shell: crate::host::Shell,
}

/// FMECA H2: what main writes, unguarded, to the raw stdout lock. Empty for the app
/// integration and for a shell whose session is already live (§5.2).
pub struct ShellEmit {
    pub lines: Zeroizing<String>,
}

/// What fd 1 is (§5.5).
pub fn stdout_kind() -> StdoutKind {
    // Safe default until session-shell: never a pipe, so `--shell` is always refused.
    StdoutKind::Other
}

/// §5.5: the session goes only to a pipe; anything else is `shell_eval_required`.
pub fn check_stdout(kind: StdoutKind, shell: Shell) -> Result<(), Error> {
    match kind {
        StdoutKind::Pipe => Ok(()),
        stdout => Err(Cause::ShellEvalRequired { stdout, shell }.into()),
    }
}

/// §5.2, §5.3: one assignment line per session variable, for `shell`.
pub fn export_lines(
    shell: Shell,
    vars: &[(String, SecretValue)],
) -> Result<Zeroizing<String>, Error> {
    let _ = (shell, vars);
    todo!("session-shell")
}

/// §5.2 `<refresh>`: the line a person types to sign this shell in again. `account` is
/// given only when it did not come from `.opv` or the environment's `account` setting.
pub fn refresh_command(shell: Shell, account: Option<&str>) -> String {
    let acct = account
        .map(|a| {
            format!(
                " --account {}",
                shell_word_for(a, shell == Shell::PowerShell)
            )
        })
        .unwrap_or_default();
    match shell {
        Shell::Posix => format!("eval \"$(opv login --shell{acct})\""),
        Shell::Fish => format!("opv login --shell=fish{acct} | source"),
        Shell::PowerShell => {
            format!("opv login --shell=powershell{acct} | Out-String | Invoke-Expression")
        }
        // No syntax for this shell: the explicit POSIX form, which `$SHELL` cannot change.
        Shell::Other => format!("eval \"$(opv login --shell=posix{acct})\""),
    }
}

/// V1: what one successful `op signin` produced. No variables: the app holds it.
pub fn sign_in_kind(vars: &[(String, SecretValue)]) -> SignInKind {
    let _ = vars;
    todo!("session-shell")
}

/// The whole `--shell` login after main's §5.5 refusals: sign in (§5.4), then build the
/// lines (§5.2). Never writes them: main does, with [`write_lines`] (§5.6, FMECA H2).
pub fn run(
    req: ShellLogin<'_>,
    backend: &mut dyn Backend,
    ui: &mut dyn Interaction,
) -> Result<ShellEmit, Error> {
    let _ = (req, backend, ui);
    todo!("session-shell")
}

/// §5.6: the one write of the session, to the raw stdout lock `out`, then a flush. A failed
/// write, EPIPE included, is `terminal_lost`; nothing is retried.
pub fn write_lines(emit: &ShellEmit, out: &mut dyn std::io::Write) -> Result<(), Error> {
    let _ = (emit, out);
    todo!("session-shell")
}
