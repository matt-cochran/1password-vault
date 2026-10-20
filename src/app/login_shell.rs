//! `opv login --shell[=posix|fish|powershell]` (#203, `docs/design/session-reuse.md` §5,
//! §7.4): sign in, then print only the shell's assignment lines for the session, for
//! `eval "$(opv login --shell)"`. Writes only to a pipe.
//!
//! [`refresh_command`] and [`check_stdout`] live here because the error catalog and
//! `main.rs` call them. The session never leaves this module except as the lines [`run`]
//! returns; `main` writes them with [`write_lines`].
//!
//! FMECA H2: [`run`] never writes the session. It returns the lines ([`ShellEmit`]), and
//! main's login arm checks stdout again, then hands them to [`write_lines`] with the raw
//! stdout lock, never the `OutputGuard` (whose `OP_SESSION_*=` rule would mask them).

use zeroize::Zeroizing;

use super::desktop_integration::{SignInKind, StdoutKind};
use super::setup::{Backend, Interaction};
use crate::cause::{Cause, NoTerminal};
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
    #[cfg(unix)]
    {
        unix_stdout_kind()
    }
    #[cfg(windows)]
    {
        windows_stdout_kind()
    }
    #[cfg(not(any(unix, windows)))]
    {
        StdoutKind::Other
    }
}

#[cfg(unix)]
fn unix_stdout_kind() -> StdoutKind {
    use std::io::IsTerminal;
    if std::io::stdout().is_terminal() {
        return StdoutKind::Terminal;
    }
    // SAFETY: `fstat` on fd 1; `st` is fully written on success.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(1, &mut st) } != 0 {
        return StdoutKind::Other;
    }
    match st.st_mode & libc::S_IFMT {
        libc::S_IFIFO => fifo_stdout_kind(),
        libc::S_IFREG => StdoutKind::File,
        _ => StdoutKind::Other,
    }
}

/// M1: a FIFO is only the shell's substitution pipe when the parent holds its read end;
/// `opv login --shell | cat` hands it to another process and must not be `Pipe`.
#[cfg(target_os = "linux")]
fn fifo_stdout_kind() -> StdoutKind {
    match parent_holds_stdout() {
        Some(true) => StdoutKind::Pipe,
        Some(false) => StdoutKind::Other,
        // No /proc to ask: the plain FIFO answer.
        None => StdoutKind::Pipe,
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn fifo_stdout_kind() -> StdoutKind {
    StdoutKind::Pipe
}

#[cfg(target_os = "linux")]
fn parent_holds_stdout() -> Option<bool> {
    let target = std::fs::read_link("/proc/self/fd/1").ok()?;
    let ppid = std::os::unix::process::parent_id();
    let entries = std::fs::read_dir(format!("/proc/{ppid}/fd")).ok()?;
    for entry in entries.flatten() {
        if std::fs::read_link(entry.path()).is_ok_and(|link| link == target) {
            return Some(true);
        }
    }
    Some(false)
}

#[cfg(windows)]
fn windows_stdout_kind() -> StdoutKind {
    use std::io::IsTerminal;
    if std::io::stdout().is_terminal() {
        return StdoutKind::Terminal;
    }
    use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_DISK, FILE_TYPE_PIPE, GetFileType};
    use windows_sys::Win32::System::Console::{GetStdHandle, STD_OUTPUT_HANDLE};
    // SAFETY: plain calls on the process's own stdout handle.
    let handle = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    match unsafe { GetFileType(handle) } {
        FILE_TYPE_PIPE => StdoutKind::Pipe,
        FILE_TYPE_DISK => StdoutKind::File,
        _ => StdoutKind::Other,
    }
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
    match shell {
        Shell::Posix => Ok(posix_lines(vars)),
        Shell::Fish => Ok(fish_lines(vars)),
        // PowerShell is withheld (FMECA H5); `Other` has no syntax of its own.
        Shell::PowerShell | Shell::Other => Err(Cause::ChoiceRequired {
            flag: "--shell".into(),
            candidates: vec!["posix".into(), "fish".into()],
        }
        .into()),
    }
}

/// H4: the session lives in a non-exported variable; the `opv` function is the only reader
/// that puts it in `op`'s environment, for that one call.
fn internal_name(name: &str) -> String {
    format!(
        "__opv_session{}",
        name.strip_prefix("OP_SESSION").unwrap_or(name)
    )
}

fn posix_lines(vars: &[(String, SecretValue)]) -> Zeroizing<String> {
    use std::fmt::Write as _;
    let mut out = Zeroizing::new(String::new());
    for (name, value) in vars {
        let _ = write!(
            &mut *out,
            "{}={}; ",
            internal_name(name),
            shell_word_for(value.expose(), false)
        );
    }
    let _ = write!(&mut *out, "opv() {{ ");
    for (name, _) in vars {
        let _ = write!(&mut *out, "{}=\"${}\" ", name, internal_name(name));
    }
    let _ = writeln!(&mut *out, "command opv \"$@\"; }}");
    out
}

fn fish_lines(vars: &[(String, SecretValue)]) -> Zeroizing<String> {
    use std::fmt::Write as _;
    let mut out = Zeroizing::new(String::new());
    for (name, value) in vars {
        let _ = write!(
            &mut *out,
            "set -g {} {}; ",
            internal_name(name),
            shell_word_for(value.expose(), false)
        );
    }
    let _ = write!(&mut *out, "function opv; ");
    for (name, _) in vars {
        let _ = write!(&mut *out, "{}=", name);
        let _ = write!(&mut *out, "${} ", internal_name(name));
    }
    let _ = writeln!(&mut *out, "command opv $argv; end");
    out
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
    if vars.is_empty() {
        SignInKind::App
    } else {
        SignInKind::Token
    }
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
    out.write_all(emit.lines.as_bytes())
        .and_then(|()| out.flush())
        .map_err(|_| {
            Error::from(Cause::NeedsTerminal {
                why: NoTerminal::NoTty,
            })
        })
}

#[cfg(test)]
#[path = "login_shell_tests.rs"]
mod tests;
