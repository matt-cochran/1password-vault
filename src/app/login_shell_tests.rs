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

// --- `run` (§5.2, §5.4): reuse a live shell session, sign in once, or leave it to the app.

mod run {
    use std::cell::RefCell;

    use zeroize::Zeroizing;

    use super::super::{ShellLogin, live_vars, run_with};
    use crate::app::doctor_session::ShellSession;
    use crate::app::setup::{Backend, Interaction, SessionCheck};
    use crate::cause::Cause;
    use crate::domain::SecretValue;
    use crate::error::Error;
    use crate::host::Shell;
    use crate::runner::Output;

    const ACCT: &str = "ALABS000000000000000000001";

    /// A fake `op` for one login: signed out until `sign_in`, which then holds `session`
    /// (empty: the app integration) or fails when `fails`.
    #[derive(Default)]
    struct Fake {
        signed_in: bool,
        fails: bool,
        session: Vec<(String, SecretValue)>,
        sign_ins: Vec<Option<String>>,
        calls: RefCell<Vec<String>>,
        account: Option<String>,
    }

    impl Fake {
        fn signed_out_with(session: &[(&str, &str)]) -> Self {
            Self {
                session: session
                    .iter()
                    .map(|(n, v)| (n.to_string(), SecretValue::new(v.to_string())))
                    .collect(),
                ..Self::default()
            }
        }
    }

    impl Backend for Fake {
        fn native(&self) -> Result<(), Error> {
            Ok(())
        }
        fn call(&self, args: &[&str], _stdin: Option<&[u8]>) -> Result<Output, Error> {
            self.calls.borrow_mut().push(args.join(" "));
            Ok(match args.first() {
                Some(&"--version") => Output::success(b"2.40.0".to_vec()),
                Some(&"vault") if self.signed_in => Output::success(b"[]".to_vec()),
                Some(&"vault") => Output {
                    status: 1,
                    stdout: Zeroizing::new(Vec::new()),
                },
                Some(&"account") => Output::success(br#"[{"url":"x"}]"#.to_vec()),
                _ => panic!("unexpected op call {args:?}"),
            })
        }
        fn session_for(&self, _account: &str) -> SessionCheck {
            if self.signed_in {
                SessionCheck::SignedIn
            } else {
                SessionCheck::NotSignedIn
            }
        }
        fn sign_in(&mut self, account: Option<&str>, _add: bool) -> Result<(), Error> {
            self.sign_ins.push(account.map(str::to_owned));
            if self.fails {
                return Err(Cause::Bug {
                    site: "fake: the sign-in failed",
                }
                .into());
            }
            self.signed_in = true;
            Ok(())
        }
        fn use_account(&mut self, account: Option<&str>) {
            self.account = account.map(str::to_owned);
        }
        fn current_account(&self) -> Option<String> {
            self.account.clone()
        }
        fn account_label(&self, account: &str) -> String {
            if account == ACCT {
                "me@labs.example".into()
            } else {
                account.into()
            }
        }
        fn take_session(&mut self) -> Vec<(String, SecretValue)> {
            if self.signed_in {
                std::mem::take(&mut self.session)
            } else {
                Vec::new()
            }
        }
    }

    #[derive(Default)]
    struct Ui {
        shown: Vec<String>,
    }

    impl Interaction for Ui {
        fn show(&mut self, m: &str) -> Result<(), Error> {
            self.shown.push(m.into());
            Ok(())
        }
        fn confirm(&mut self, _: &str) -> Result<bool, Error> {
            panic!("login --shell never asks to confirm")
        }
        fn secret(&mut self, _: &str) -> Result<SecretValue, Error> {
            panic!("login --shell never reads a secret")
        }
    }

    fn req<'a>(
        fallback: Option<&'a str>,
        record: Option<(&'a std::path::Path, &'a str)>,
        shell: Shell,
    ) -> ShellLogin<'a> {
        ShellLogin {
            fleet: None,
            fallback,
            env: None,
            record,
            shell,
        }
    }

    fn not_live(_: Option<&str>) -> Option<Vec<(String, SecretValue)>> {
        None
    }

    /// A git repository whose `.opv` records `recorded`, if any.
    fn project(recorded: Option<&str>) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        if let Some(a) = recorded {
            crate::config_store::record_account(dir.path(), a).unwrap();
        }
        dir
    }

    /// The canary appears nowhere a person or a log can see: every stderr line and the
    /// error, if any, are free of it.
    fn assert_hidden(canary: &str, ui: &Ui, error: Option<&Error>) {
        for line in &ui.shown {
            assert!(!line.contains(canary), "stderr carried the session: {line}");
        }
        if let Some(e) = error {
            assert!(!format!("{e}").contains(canary));
            assert!(!format!("{e:?}").contains(canary));
        }
    }

    /// §5.2, FMECA H3: a live shell session is reused with no prompt and its lines printed
    /// again.
    #[test]
    fn a_live_shell_session_is_reused_without_a_sign_in() {
        let canary = "LiveCanary7f3a";
        let mut b = Fake::default();
        let mut ui = Ui::default();
        let live = |a: Option<&str>| {
            assert_eq!(a, Some(ACCT));
            Some(vec![(
                "OP_SESSION_UNIQ7".to_string(),
                SecretValue::new(canary.to_string()),
            )])
        };
        let emit = run_with(req(Some(ACCT), None, Shell::Posix), &mut b, &mut ui, &live).unwrap();
        assert!(b.sign_ins.is_empty());
        assert!(b.calls.borrow().is_empty(), "no op call: {:?}", b.calls);
        assert!(
            emit.lines
                .contains(&format!("__opv_session_UNIQ7={canary}; "))
        );
        assert!(ui.shown.iter().any(|l| l.starts_with("Already signed in")));
        assert_hidden(canary, &ui, None);
    }

    /// §5.4: a live session still records the chosen account (H2: the login succeeded).
    #[test]
    fn a_live_shell_session_records_the_account() {
        let dir = project(None);
        let mut b = Fake::default();
        let live = |_: Option<&str>| {
            Some(vec![(
                "OP_SESSION_UNIQ7".to_string(),
                SecretValue::new("tok".to_string()),
            )])
        };
        run_with(
            req(Some(ACCT), Some((dir.path(), ACCT)), Shell::Posix),
            &mut b,
            &mut Ui::default(),
            &live,
        )
        .unwrap();
        assert_eq!(
            crate::config_store::pointer_account(dir.path()).as_deref(),
            Some(ACCT)
        );
    }

    /// §5.4: signed out, one sign-in at op's prompt; the session it printed is the lines.
    #[test]
    fn a_signed_out_shell_signs_in_once_and_prints_the_function() {
        let canary = "SignInCanary9c1e";
        let mut b = Fake::signed_out_with(&[("OP_SESSION_UNIQ7", canary)]);
        let mut ui = Ui::default();
        let emit = run_with(
            req(Some(ACCT), None, Shell::Posix),
            &mut b,
            &mut ui,
            &not_live,
        )
        .unwrap();
        assert_eq!(b.sign_ins, [Some(ACCT.to_string())]);
        assert_eq!(
            emit.lines.as_str(),
            format!(
                "__opv_session_UNIQ7={canary}; opv() {{ OP_SESSION_UNIQ7=\"$__opv_session_UNIQ7\" \
                 command opv \"$@\"; }}\n"
            )
        );
        assert_hidden(canary, &ui, None);
    }

    /// §5.2: the stderr line names the account and the refresh command.
    #[test]
    fn the_sign_in_says_how_to_refresh() {
        let mut b = Fake::signed_out_with(&[("OP_SESSION_UNIQ7", "tok")]);
        let mut ui = Ui::default();
        run_with(
            req(Some(ACCT), None, Shell::Fish),
            &mut b,
            &mut ui,
            &not_live,
        )
        .unwrap();
        let said = ui.shown.last().unwrap();
        assert!(
            said.starts_with("Signed in to me@labs.example in this shell."),
            "{said}"
        );
        assert!(
            said.contains(&format!("opv login --shell=fish --account {ACCT} | source")),
            "{said}"
        );
    }

    /// §5.2: an account `.opv` records now needs no `--account` in the refresh command.
    #[test]
    fn a_recorded_account_is_left_out_of_the_refresh_command() {
        let dir = project(None);
        let mut b = Fake::signed_out_with(&[("OP_SESSION_UNIQ7", "tok")]);
        let mut ui = Ui::default();
        run_with(
            req(Some(ACCT), Some((dir.path(), ACCT)), Shell::Posix),
            &mut b,
            &mut ui,
            &not_live,
        )
        .unwrap();
        assert!(
            ui.shown
                .last()
                .unwrap()
                .contains("run eval \"$(opv login --shell)\" again")
        );
    }

    /// V1, §5.2: a sign-in that printed nothing is the app integration: empty stdout.
    #[test]
    fn the_app_integration_prints_nothing() {
        let mut b = Fake::signed_out_with(&[]);
        let mut ui = Ui::default();
        let emit = run_with(
            req(Some(ACCT), None, Shell::Posix),
            &mut b,
            &mut ui,
            &not_live,
        )
        .unwrap();
        assert!(emit.lines.is_empty());
        assert!(
            ui.shown
                .iter()
                .any(|l| l.starts_with("The 1Password app integration is on"))
        );
    }

    /// §5: op already working with no shell session is the app: no prompt, empty stdout.
    #[test]
    fn the_app_integration_already_unlocked_asks_for_nothing() {
        let mut b = Fake {
            signed_in: true,
            ..Fake::default()
        };
        let emit = run_with(
            req(Some(ACCT), None, Shell::Posix),
            &mut b,
            &mut Ui::default(),
            &not_live,
        )
        .unwrap();
        assert!(b.sign_ins.is_empty());
        assert!(emit.lines.is_empty());
    }

    /// §5.4, H2: the recording branch records the account once the sign-in succeeded.
    #[test]
    fn the_recording_login_records_the_account() {
        let dir = project(None);
        let mut b = Fake::signed_out_with(&[("OP_SESSION_UNIQ7", "tok")]);
        run_with(
            req(Some(ACCT), Some((dir.path(), ACCT)), Shell::Posix),
            &mut b,
            &mut Ui::default(),
            &not_live,
        )
        .unwrap();
        assert_eq!(
            crate::config_store::pointer_account(dir.path()).as_deref(),
            Some(ACCT)
        );
    }

    /// #153: `--no-record` (no `record`) leaves `.opv` as it was.
    #[test]
    fn no_record_leaves_dot_opv_unchanged() {
        let other = "AOTHER00000000000000000002";
        let dir = project(Some(other));
        let before = std::fs::read(dir.path().join(".opv")).unwrap();
        let mut b = Fake::signed_out_with(&[("OP_SESSION_UNIQ7", "tok")]);
        run_with(
            req(Some(ACCT), None, Shell::Posix),
            &mut b,
            &mut Ui::default(),
            &not_live,
        )
        .unwrap();
        assert_eq!(std::fs::read(dir.path().join(".opv")).unwrap(), before);
    }

    /// H2: a failed sign-in prints nothing and records nothing.
    #[test]
    fn a_failed_sign_in_records_nothing() {
        let dir = project(None);
        let mut b = Fake {
            fails: true,
            ..Fake::signed_out_with(&[("OP_SESSION_UNIQ7", "FailCanary51d0")])
        };
        let mut ui = Ui::default();
        let e = run_with(
            req(Some(ACCT), Some((dir.path(), ACCT)), Shell::Posix),
            &mut b,
            &mut ui,
            &not_live,
        )
        .err()
        .unwrap();
        assert!(crate::config_store::pointer_account(dir.path()).is_none());
        assert_hidden("FailCanary51d0", &ui, Some(&e));
    }

    /// FMECA H5: PowerShell is refused before any prompt or op call.
    #[test]
    fn powershell_is_refused_before_any_op_call() {
        let mut b = Fake::signed_out_with(&[("OP_SESSION_UNIQ7", "tok")]);
        let e = run_with(
            req(Some(ACCT), None, Shell::PowerShell),
            &mut b,
            &mut Ui::default(),
            &not_live,
        )
        .err()
        .unwrap();
        assert_eq!(e.cause().map(|(c, _)| c.code()), Some("choice_required"));
        assert!(b.calls.borrow().is_empty());
        assert!(b.sign_ins.is_empty());
    }

    /// Canary: in the default-account case both variables carry the token, still only in
    /// the lines.
    #[test]
    fn the_token_appears_only_in_the_lines() {
        let canary = "OnlyHereCanary3b8d";
        let mut b = Fake::signed_out_with(&[("OP_SESSION", canary), ("OP_SESSION_UNIQ7", canary)]);
        let mut ui = Ui::default();
        let emit = run_with(req(None, None, Shell::Posix), &mut b, &mut ui, &not_live).unwrap();
        assert_eq!(emit.lines.matches(canary).count(), 2);
        assert_hidden(canary, &ui, None);
        assert!(b.take_session().is_empty(), "the session left the backend");
    }

    fn lookup(name: &str) -> Option<String> {
        (name == "OP_SESSION_UNIQ7").then(|| "tok.A/b+c=-_".to_string())
    }

    /// §5.2: a live session for an account is its own variable only.
    #[test]
    fn live_vars_reads_the_live_variable() {
        let vars = live_vars(
            Some(ShellSession::Live {
                var: "OP_SESSION_UNIQ7".into(),
            }),
            Some(ACCT),
            &lookup,
        )
        .unwrap();
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].0, "OP_SESSION_UNIQ7");
        assert_eq!(vars[0].1.expose(), "tok.A/b+c=-_");
    }

    /// Without an account, the generic `OP_SESSION` goes with it, as after a sign-in.
    #[test]
    fn live_vars_without_an_account_adds_the_generic_variable() {
        let vars = live_vars(
            Some(ShellSession::Live {
                var: "OP_SESSION_UNIQ7".into(),
            }),
            None,
            &lookup,
        )
        .unwrap();
        let names: Vec<_> = vars.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["OP_SESSION", "OP_SESSION_UNIQ7"]);
    }

    /// FMECA H3: an expired session goes on to the sign-in.
    #[test]
    fn live_vars_is_none_for_an_expired_session() {
        let expired = ShellSession::Expired {
            var: "OP_SESSION_UNIQ7".into(),
        };
        assert!(live_vars(Some(expired), Some(ACCT), &lookup).is_none());
        assert!(live_vars(None, Some(ACCT), &lookup).is_none());
    }

    /// §5.3: a value outside op's charset is never printed for a shell to evaluate.
    #[test]
    fn live_vars_refuses_a_value_outside_the_session_charset() {
        let bad = |_: &str| Some("tok; rm -rf ~".to_string());
        let live = || {
            Some(ShellSession::Live {
                var: "OP_SESSION_UNIQ7".into(),
            })
        };
        assert!(live_vars(live(), Some(ACCT), &bad).is_none());
        let named = |_: &str| Some("tok".to_string());
        let odd = Some(ShellSession::Live {
            var: "OP_SESSION_$(x)".into(),
        });
        assert!(live_vars(odd, Some(ACCT), &named).is_none());
    }
}
