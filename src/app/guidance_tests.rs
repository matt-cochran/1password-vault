//! FR-26 "Diagnose and Guide": one atomic test per situation per platform (§8 item 25).
//!
//! Each test drives the real read path ([`onepassword::read_item_with`]) or `doctor`
//! against a fake `op` ([`FakeRunner`]) on a fixed [`Host`] (from a [`FakeEnv`]), then
//! asserts the exit category, that the exact command for that shell appears, and that the
//! command is valid syntax for that shell (checked with the real shell when it is
//! installed). Expired session: exit 7 and the sign-in command, never "to see why".

use std::io;

use crate::adapters::onepassword;
use crate::app::doctor;
use crate::app::testutil::*;
use crate::domain::Environment;
use crate::error::Error;
use crate::host::{FakeEnv, Host, Shell};
use crate::runner::Output;
use crate::runner::fake::{FakeRunner, failed_read};

#[derive(Clone, Copy, Debug)]
enum P {
    Linux,
    Wsl,
    MacOs,
    WindowsPowerShell,
    Fish,
    Ci,
}

fn host(p: P) -> Host {
    let env = match p {
        P::Linux => FakeEnv::new("linux")
            .shell("/bin/bash")
            .osrelease("6.8.0-45-generic\n"),
        P::Wsl => FakeEnv::new("linux")
            .shell("/bin/bash")
            .osrelease("6.6.87.2-microsoft-standard-WSL2\n"),
        P::MacOs => FakeEnv::new("macos").shell("/bin/zsh"),
        P::WindowsPowerShell => FakeEnv::new("windows"),
        P::Fish => FakeEnv::new("linux").shell("/usr/bin/fish"),
        P::Ci => FakeEnv::new("linux")
            .shell("/bin/bash")
            .var("CI")
            .var("GITHUB_ACTIONS"),
    };
    Host::from_env(&env)
}

/// The exact sign-in command expected per platform; `None` under CI.
fn expected_signin(p: P) -> Option<&'static str> {
    match p {
        P::Linux | P::Wsl | P::MacOs => Some("eval $(op signin)"),
        P::WindowsPowerShell => Some("Invoke-Expression $(op signin)"),
        P::Fish => Some("eval (op signin)"),
        P::Ci => None,
    }
}

const WHOAMI_USER: &str = r#"{"url":"https://FIXTUREVALUE.1password.com","email":"dev-FIXTUREVALUE@example.com","user_uuid":"UFIXTUREVALUE","account_uuid":"AFIXTUREVALUE","user_type":"HUMAN"}"#;
const ONE_ACCOUNT: &str =
    r#"[{"url":"FIXTUREVALUE.1password.com","email":"dev-FIXTUREVALUE@example.com"}]"#;

fn env() -> Environment {
    fleet().environment("prod").unwrap().clone()
}

/// Situations: what the fake `op` answers after the failed item read.
#[derive(Clone, Copy, Debug)]
enum S {
    /// whoami fails, an account exists (expired OP_SESSION_* or never signed in).
    Expired,
    /// whoami fails and `op account list` is empty.
    NoAccount,
    /// whoami succeeds; the item read failed anyway and `op vault get` fails too (NR-26).
    NotVisible,
    /// `op` is not on PATH.
    OpMissing,
}

fn fake_op(s: S, ci: bool) -> FakeRunner {
    let r = FakeRunner::default();
    let mut q = r.responses.borrow_mut();
    match s {
        S::OpMissing => q.push_back(Err(io::ErrorKind::NotFound.into())),
        S::NotVisible => {
            q.extend(failed_read(1).map(Ok));
            q.push_back(Ok(Output::success(WHOAMI_USER)));
            q.push_back(Ok(Output::failure(1)));
        }
        S::Expired | S::NoAccount => {
            q.extend(failed_read(1).map(Ok));
            q.push_back(Ok(Output::failure(1)));
            if !ci {
                let list = if matches!(s, S::Expired) {
                    ONE_ACCOUNT
                } else {
                    "[]"
                };
                q.push_back(Ok(Output::success(list)));
            }
        }
    }
    drop(q);
    r
}

/// Run the read path; return the error and its rendered text.
fn read_fails(p: P, s: S) -> (Error, String, FakeRunner) {
    let h = host(p);
    let r = fake_op(s, h.ci);
    let e = onepassword::read_item_with(&r, &env(), &h).unwrap_err();
    // What the user sees: the message, then its `Next:` line (NR-19).
    let t = crate::error::report(&e, "-");
    (e, t, r)
}

/// Shell syntax of the suggested sign-in command, by shell rules and, when the shell is
/// installed, by the shell's own parser (`-n`: parse only, never execute).
fn assert_signin_syntax(p: P, text: &str) {
    assert!(!text.contains('!'), "no `!` prefix ever: {text}");
    let Some(cmd) = expected_signin(p) else {
        assert!(
            !text.contains("op signin"),
            "no interactive command under CI: {text}"
        );
        assert!(text.contains("OP_SERVICE_ACCOUNT_TOKEN"), "{text}");
        return;
    };
    let line = text
        .lines()
        .find_map(|l| l.trim_start().strip_prefix("sign in: "))
        .or_else(|| {
            text.lines()
                .find_map(|l| l.trim_start().strip_prefix("then sign in: "))
        })
        .unwrap_or_else(|| panic!("no sign-in line: {text}"));
    assert_eq!(line, cmd, "{p:?}");
    match host(p).shell {
        Shell::Posix => {
            assert!(line.starts_with("eval $(") && line.ends_with(')'), "{line}");
            parses_with("sh", &["-n", "-c", line]);
            parses_with("bash", &["-n", "-c", line]);
            parses_with("zsh", &["-n", "-c", line]);
        }
        Shell::Fish => {
            assert!(!line.contains("$("), "fish has no $(: {line}");
            assert!(line.starts_with("eval (") && line.ends_with(')'), "{line}");
            parses_with("fish", &["--no-execute", "-c", line]);
        }
        Shell::Other => unreachable!("every matrix platform has a known shell"),
        Shell::PowerShell => {
            assert!(line.starts_with("Invoke-Expression "), "{line}");
            assert!(!line.starts_with("eval"), "{line}");
            parses_with(
                "pwsh",
                &[
                    "-NoProfile",
                    "-Command",
                    &format!(
                        "$e=$null; [void][System.Management.Automation.Language.Parser]::ParseInput('{line}',[ref]$null,[ref]$e); if ($e.Count) {{ exit 1 }}"
                    ),
                ],
            );
        }
    }
}

/// When `shell` is installed, it must accept `args` (a parse-only invocation; POSIX shells
/// are skipped on Windows). With `OPV_REQUIRE_SHELLS=1` (set on the Ubuntu CI job) a
/// missing shell fails the test, so the check is never vacuous there.
fn parses_with(shell: &str, args: &[&str]) {
    // On Windows a `bash` on PATH is often the WSL launcher stub, which cannot run a
    // script; POSIX shells are checked on Linux (required in CI) and macOS instead.
    if cfg!(windows) && shell != "pwsh" {
        return;
    }
    match std::process::Command::new(shell)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
    {
        Ok(o) => assert!(o.status.success(), "{shell} rejects {args:?}"),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            assert!(
                std::env::var("OPV_REQUIRE_SHELLS").as_deref() != Ok("1"),
                "{shell} is not installed but OPV_REQUIRE_SHELLS=1"
            );
        }
        Err(e) => panic!("{shell}: {e}"),
    }
}

fn expired(p: P) {
    let (e, t, r) = read_fails(p, S::Expired);
    assert_eq!(e.exit_code(), 7, "{p:?}: {t}");
    assert!(matches!(e, Error::Auth(_)), "{t}");
    assert!(t.contains("not signed in to 1Password"), "{t}");
    assert!(!t.contains("to see why"), "{t}");
    assert_signin_syntax(p, &t);
    assert_no_values(&t);
    // FR-13: one item read; its attempts (NR-3 retries) are not extra reads.
    assert_eq!(
        op_item_reads(&r),
        crate::runner::READ_ATTEMPTS as usize,
        "FR-13"
    );
}

fn no_account(p: P) {
    let (e, t, r) = read_fails(p, S::NoAccount);
    assert_eq!(e.exit_code(), 7, "{p:?}: {t}");
    assert!(!t.contains("to see why"), "{t}");
    assert_signin_syntax(p, &t);
    // NoAccount is unreachable under CI (no `op account list` there), so no CI case.
    assert!(
        t.contains("\n  add one: op account add --address <sign-in address> --email <email>\n"),
        "{t}"
    );
    assert!(
        t.contains(
            "type the Secret Key and password only at op's prompts, never into chat, \
             tickets or files"
        ),
        "{t}"
    );
    // `op account add` comes first, then the sign-in command.
    assert!(t.find("op account add").unwrap() < t.find("then sign in").unwrap());
    if matches!(p, P::Wsl) {
        assert!(t.contains("WSL"), "{t}");
    }
    assert_no_values(&t);
    // FR-13: one item read; its attempts (NR-3 retries) are not extra reads.
    assert_eq!(
        op_item_reads(&r),
        crate::runner::READ_ATTEMPTS as usize,
        "FR-13"
    );
}

fn not_visible(p: P) {
    let (e, t, r) = read_fails(p, S::NotVisible);
    assert_eq!(e.exit_code(), 4, "{p:?}: {t}");
    assert!(matches!(e, Error::Source(_)), "{t}");
    assert!(t.contains("cannot access vault vprd"), "{t}");
    assert!(t.contains("signed in to 1Password as USER"), "{t}");
    assert!(t.contains("grant this identity access to the vault"), "{t}");
    assert!(
        !t.contains("to see why") && !t.contains("example.com"),
        "{t}"
    );
    assert_no_values(&t);
    // FR-13: one item read; its attempts (NR-3 retries) are not extra reads.
    assert_eq!(
        op_item_reads(&r),
        crate::runner::READ_ATTEMPTS as usize,
        "FR-13"
    );
}

fn op_missing(p: P) {
    let (e, t, _) = read_fails(p, S::OpMissing);
    assert_eq!(e.exit_code(), 3, "{p:?}: {t}");
    let want = match p {
        P::MacOs => "install: brew install 1password-cli",
        P::WindowsPowerShell => "install: winget install AgileBits.1Password.CLI",
        P::Ci => "1password/install-cli-action",
        P::Linux | P::Wsl | P::Fish => "https://developer.1password.com/docs/cli/get-started/",
    };
    assert!(t.contains(want), "{p:?}: {t}");
}

/// Doctor uses the same classification as the read path.
fn doctor_expired(p: P) {
    let h = host(p);
    let r = FakeRunner::new([Output::success("2.40.0\n"), Output::failure(1)]);
    if !h.ci {
        r.responses
            .borrow_mut()
            .push_back(Ok(Output::success(ONE_ACCOUNT)));
    }
    let no_fly = crate::config::parse(
        "[profile]\nkind = \"fleet\"\n[environments.dev]\nvault_id = \"v\"\nitem_id = \"i\"\n",
    )
    .unwrap();
    let mut out = Vec::new();
    let e = doctor::run_with(Ok(no_fly), &r, &h, &mut out).unwrap_err();
    let t = text_of(&out);
    assert_eq!(e.exit_code(), 7, "{p:?}: {t}");
    assert!(
        t.contains("FAIL  op auth: authentication error: not signed in"),
        "{t}"
    );
    assert_signin_syntax(p, &t);
    assert_no_values(&t);
    assert!(!r.argv_contains("item"), "doctor never reads an item");
}

fn op_item_reads(r: &FakeRunner) -> usize {
    r.calls
        .borrow()
        .iter()
        .filter(|c| c.program == "op" && c.args.first().map(String::as_str) == Some("item"))
        .count()
}

macro_rules! cases {
    ($($name:ident: $check:ident($p:expr);)*) => {
        $( #[test] fn $name() { $check($p) } )*
    };
}

cases! {
    expired_session_linux: expired(P::Linux);
    expired_session_wsl: expired(P::Wsl);
    expired_session_macos: expired(P::MacOs);
    expired_session_windows_powershell: expired(P::WindowsPowerShell);
    expired_session_fish: expired(P::Fish);
    expired_session_ci: expired(P::Ci);

    no_account_linux: no_account(P::Linux);
    no_account_wsl: no_account(P::Wsl);
    no_account_macos: no_account(P::MacOs);
    no_account_windows_powershell: no_account(P::WindowsPowerShell);
    no_account_fish: no_account(P::Fish);

    not_visible_linux: not_visible(P::Linux);
    not_visible_wsl: not_visible(P::Wsl);
    not_visible_macos: not_visible(P::MacOs);
    not_visible_windows_powershell: not_visible(P::WindowsPowerShell);
    not_visible_fish: not_visible(P::Fish);
    not_visible_ci: not_visible(P::Ci);

    op_missing_linux: op_missing(P::Linux);
    op_missing_wsl: op_missing(P::Wsl);
    op_missing_macos: op_missing(P::MacOs);
    op_missing_windows_powershell: op_missing(P::WindowsPowerShell);
    op_missing_fish: op_missing(P::Fish);
    op_missing_ci: op_missing(P::Ci);

    doctor_expired_linux: doctor_expired(P::Linux);
    doctor_expired_wsl: doctor_expired(P::Wsl);
    doctor_expired_macos: doctor_expired(P::MacOs);
    doctor_expired_windows_powershell: doctor_expired(P::WindowsPowerShell);
    doctor_expired_fish: doctor_expired(P::Fish);
    doctor_expired_ci: doctor_expired(P::Ci);
}

/// FR-26 / FR-10: a non-interactive credential (service account or Connect) whose read and
/// whoami both fail is ambiguous (rejected token or no network): Source (exit 4) naming the
/// variable, no interactive command, no `op account list`; CI or not.
#[test]
fn rejected_or_unreachable_credential_is_source_exit_4() {
    for (fake, var, label) in [
        (
            FakeEnv::new("linux")
                .shell("/bin/bash")
                .var("OP_SERVICE_ACCOUNT_TOKEN"),
            "OP_SERVICE_ACCOUNT_TOKEN",
            "service-account",
        ),
        (
            FakeEnv::new("linux")
                .var("CI")
                .var("OP_SERVICE_ACCOUNT_TOKEN"),
            "OP_SERVICE_ACCOUNT_TOKEN",
            "service-account",
        ),
        (
            FakeEnv::new("linux")
                .shell("/bin/bash")
                .var("OP_CONNECT_HOST")
                .var("OP_CONNECT_TOKEN"),
            "OP_CONNECT_TOKEN",
            "Connect",
        ),
        (
            FakeEnv::new("windows").var("OP_CONNECT_TOKEN"),
            "OP_CONNECT_TOKEN",
            "Connect",
        ),
    ] {
        let h = Host::from_env(&fake);
        let r = FakeRunner::new(failed_read(1).chain([Output::failure(1)]));
        let e = onepassword::read_item_with(&r, &env(), &h).unwrap_err();
        let t = e.to_string();
        assert_eq!(e.exit_code(), 4, "{t}");
        assert!(
            t.contains(&format!(
                "1Password rejected the {label} token or could not be reached: check the \
                 token in {var} and network access"
            )),
            "{t}"
        );
        assert!(!t.contains("op signin") && !t.contains("to see why"), "{t}");
        assert_eq!(
            r.calls.borrow().len(),
            crate::runner::READ_ATTEMPTS as usize + 1,
            "no account list with a credential"
        );
    }
}

/// Connect: item not found while whoami succeeds → Source (exit 4) naming the IDs.
#[test]
fn connect_item_not_found_is_source_exit_4() {
    let h = Host::from_env(
        &FakeEnv::new("linux")
            .shell("/bin/bash")
            .var("OP_CONNECT_HOST")
            .var("OP_CONNECT_TOKEN"),
    );
    let r = FakeRunner::new(failed_read(1).chain([
        Output::success(WHOAMI_USER),
        Output::success(b"{}".to_vec()),
    ]));
    let e = onepassword::read_item_with(&r, &env(), &h).unwrap_err();
    // What the user sees: the message, then its `Next:` line (NR-19).
    let t = crate::error::report(&e, "-");
    assert_eq!(e.exit_code(), 4, "{t}");
    assert!(t.contains("item iprd not found in vault vprd"), "{t}");
    assert!(!t.contains("op signin"), "{t}");
}

/// Connect: whoami failing is never exit 7 with an interactive command.
#[test]
fn connect_whoami_failing_is_not_auth_with_interactive_command() {
    for shell in ["/bin/bash", "/usr/bin/fish"] {
        let h = Host::from_env(&FakeEnv::new("linux").shell(shell).var("OP_CONNECT_HOST"));
        let r = FakeRunner::new(failed_read(1).chain([Output::failure(1)]));
        let e = onepassword::read_item_with(&r, &env(), &h).unwrap_err();
        let t = e.to_string();
        assert_ne!(e.exit_code(), 7, "{t}");
        assert!(!t.contains("op signin") && !t.contains("eval"), "{t}");
    }
}

/// Not signed in (no credential): the sign-in step plus the network fallback line.
#[test]
fn not_signed_in_mentions_network_access() {
    let (e, t, _) = read_fails(P::Linux, S::Expired);
    assert_eq!(e.exit_code(), 7, "{t}");
    assert!(
        t.contains("\n  if you are signed in, check network access to 1Password\n"),
        "{t}"
    );
}

/// An unrecognised `$SHELL` gets the generic `op signin` pointer, never POSIX syntax.
#[test]
fn unknown_shell_gets_generic_signin_hint() {
    for sh in ["/usr/bin/nu", "/bin/tcsh", "/bin/csh"] {
        let h = Host::from_env(&FakeEnv::new("linux").shell(sh));
        let r = fake_op(S::Expired, false);
        let e = onepassword::read_item_with(&r, &env(), &h).unwrap_err();
        let t = e.to_string();
        assert_eq!(e.exit_code(), 7, "{t}");
        assert!(
            t.contains("\n  sign in with `op signin` (see `op signin --help` for your shell)\n"),
            "{sh}: {t}"
        );
        assert!(!t.contains("$(") && !t.contains("eval"), "{sh}: {t}");
    }
}
