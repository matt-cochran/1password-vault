//! Behaviour of `opv login --shell`'s pure pieces (#203, session-reuse §5.2, §5.5, §5.6).

use zeroize::Zeroizing;

use super::{ShellEmit, export_lines, sign_in_kind, stdout_kind, write_lines};
use crate::app::desktop_integration::{SignInKind, StdoutKind};
use crate::cause::{Cause, NoTerminal};
use crate::domain::SecretValue;
use crate::host::Shell;

fn vars(pairs: &[(&str, &str)]) -> Vec<(String, SecretValue)> {
    pairs
        .iter()
        .map(|(name, value)| (name.to_string(), SecretValue::new(value.to_string())))
        .collect()
}

fn emit(text: &str) -> ShellEmit {
    ShellEmit {
        lines: Zeroizing::new(text.to_string()),
    }
}

/// §5.2: posix output defines the `opv` function the person's shell calls.
#[cfg(unix)]
#[test]
fn posix_lines_define_the_opv_function() {
    let lines = export_lines(Shell::Posix, &vars(&[("OP_SESSION_UNIQ7", "tok")])).unwrap();
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("{}\ncommand -v opv", lines.as_str()))
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "opv");
}

/// H4: the session variable stays in the shell; a child process never sees it.
#[cfg(unix)]
#[test]
fn posix_lines_do_not_export_the_session() {
    let lines = export_lines(Shell::Posix, &vars(&[("OP_SESSION_UNIQ7", "tok")])).unwrap();
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("{}\nenv", lines.as_str()))
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&out.stdout).contains("UNIQ7"));
}

/// §5.3: quoting via `shell_word_for` survives the shell's `eval`.
#[cfg(unix)]
#[test]
fn posix_lines_round_trip_a_token_with_quotes_and_dollar() {
    let token = "a'b$c";
    let lines = export_lines(Shell::Posix, &vars(&[("OP_SESSION_UNIQ7", token)])).unwrap();
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!(
            "{}\nprintf '%s' \"$__opv_session_UNIQ7\"",
            lines.as_str()
        ))
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), token);
}

/// §5.2: fish uses `set -g` (not `-x`) and a `function opv`.
#[test]
fn fish_lines_set_a_global_and_the_opv_function() {
    let lines = export_lines(Shell::Fish, &vars(&[("OP_SESSION_UNIQ7", "tok")])).unwrap();
    assert_eq!(
        lines.as_str(),
        "set -g __opv_session_UNIQ7 tok; function opv; OP_SESSION_UNIQ7=$__opv_session_UNIQ7 \
         command opv $argv; end\n"
    );
}

/// FMECA H5: PowerShell is withheld until the owner decides.
#[test]
fn export_lines_refuses_powershell() {
    let e = export_lines(Shell::PowerShell, &vars(&[("OP_SESSION_ABC", "tok")])).unwrap_err();
    assert_eq!(e.cause().map(|(c, _)| c.code()), Some("choice_required"));
}

/// V1: nothing printed means the app integration holds the session.
#[test]
fn sign_in_kind_is_app_when_nothing_was_printed() {
    assert_eq!(sign_in_kind(&[]), SignInKind::App);
}

/// V1: a printed assignment means a CLI session token.
#[test]
fn sign_in_kind_is_token_when_a_session_was_printed() {
    assert_eq!(
        sign_in_kind(&vars(&[("OP_SESSION_ABC", "tok")])),
        SignInKind::Token
    );
}

#[derive(Default)]
struct Recorder {
    bytes: Vec<u8>,
    flushes: usize,
}

impl std::io::Write for Recorder {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.flushes += 1;
        Ok(())
    }
}

/// §5.6: the lines reach the raw writer exactly.
#[test]
fn write_lines_emits_the_exact_lines() {
    let mut out = Recorder::default();
    write_lines(&emit("OP_SESSION_ABC=1\n"), &mut out).unwrap();
    assert_eq!(out.bytes, b"OP_SESSION_ABC=1\n");
}

/// §5.6: the writer is flushed once the line is written.
#[test]
fn write_lines_flushes_after_writing() {
    let mut out = Recorder::default();
    write_lines(&emit("OP_SESSION_ABC=1\n"), &mut out).unwrap();
    assert_eq!(out.flushes, 1);
}

struct BrokenPipe;

impl std::io::Write for BrokenPipe {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "closed",
        ))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// §5.6: a reader that left means the terminal is gone, not a dependency error.
#[test]
fn write_lines_maps_a_broken_pipe_to_terminal_lost() {
    let e = write_lines(&emit("OP_SESSION_ABC=1\n"), &mut BrokenPipe).unwrap_err();
    assert!(matches!(
        e.cause(),
        Some((
            Cause::NeedsTerminal {
                why: NoTerminal::NoTty
            },
            _
        ))
    ));
}

#[cfg(unix)]
fn pipe_pair() -> [std::os::fd::RawFd; 2] {
    let mut fds = [0; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        panic!("pipe failed");
    }
    fds
}

/// §5.5: a regular file is not a pipe, so the session is refused there.
#[cfg(unix)]
#[test]
fn regular_file_stdout_is_not_a_pipe() {
    use std::os::fd::AsRawFd;
    let file = tempfile::tempfile().unwrap();
    let saved = unsafe { libc::dup(1) };
    unsafe { libc::dup2(file.as_raw_fd(), 1) };
    let kind = stdout_kind();
    unsafe {
        libc::dup2(saved, 1);
        libc::close(saved);
    }
    assert_eq!(kind, StdoutKind::File);
}

/// M1: a FIFO whose read end the parent does not hold (`opv ... | cat`) is not `Pipe`.
#[cfg(unix)]
#[test]
fn a_pipe_the_parent_does_not_hold_is_not_a_pipe() {
    let fds = pipe_pair();
    let saved = unsafe { libc::dup(1) };
    unsafe { libc::dup2(fds[1], 1) };
    let kind = stdout_kind();
    unsafe {
        libc::dup2(saved, 1);
        libc::close(saved);
        libc::close(fds[0]);
        libc::close(fds[1]);
    }
    assert_eq!(kind, StdoutKind::Other);
}

/// M1: the parent holding the read end is what makes the shell's substitution pipe `Pipe`.
#[cfg(target_os = "linux")]
#[test]
fn a_pipe_the_parent_holds_is_a_pipe() {
    let fds = pipe_pair();
    // SAFETY: the child only reads fd 1 and calls `_exit`.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::close(fds[0]);
            libc::dup2(fds[1], 1);
            libc::close(fds[1]);
        }
        let code = match stdout_kind() {
            StdoutKind::Pipe => 0,
            StdoutKind::Other => 1,
            StdoutKind::File => 2,
            StdoutKind::Terminal => 3,
        };
        unsafe { libc::_exit(code) };
    }
    unsafe { libc::close(fds[1]) };
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    unsafe { libc::close(fds[0]) };
    assert_eq!(libc::WEXITSTATUS(status), 0);
}
