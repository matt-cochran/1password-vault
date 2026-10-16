//! FR-26 "Diagnose and Guide": one atomic test per situation per platform (§8 item 25).
//!
//! Each test drives the real read path ([`onepassword::read_item_with`]) or `doctor`
//! against a fake `op` ([`FakeRunner`]) on a fixed [`Host`] (from a [`FakeEnv`]), then
//! asserts the catalog cause (design §4.3) and the step it renders for that platform.
//! Expired session: `op_not_signed_in`, never "to see why".

use crate::adapters::onepassword;
use crate::app::doctor;
use crate::app::testutil::*;
use crate::domain::Environment;
use crate::error::Error;
use crate::host::{FakeEnv, Host};
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

const WHOAMI_USER: &str = r#"{"url":"https://FIXTUREVALUE.1password.com","email":"dev-FIXTUREVALUE@example.com","user_uuid":"UFIXTUREVALUE","account_uuid":"AFIXTUREVALUE","user_type":"HUMAN"}"#;
const ONE_ACCOUNT: &str =
    r#"[{"url":"FIXTUREVALUE.1password.com","email":"dev-FIXTUREVALUE@example.com"}]"#;

fn env() -> Environment {
    fleet().environment("prod").unwrap().clone()
}

/// The prod boundary item the reads address.
fn at() -> crate::domain::Boundary {
    env().boundaries.values().next().unwrap().clone()
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
        S::OpMissing => q.push_back(Err(std::io::ErrorKind::NotFound.into())),
        S::NotVisible => {
            q.push_back(Ok(Output::failure(1)));
            q.push_back(Ok(Output::success(WHOAMI_USER)));
            q.push_back(Ok(Output::failure(1)));
        }
        S::Expired | S::NoAccount => {
            q.push_back(Ok(Output::failure(1)));
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
    let e = onepassword::read_item_with(&r, &env(), &at(), &h).unwrap_err();
    // What the user sees: the message, then its `Next:` line (NR-19).
    let t = crate::error::report(&e, "-", None);
    (e, t, r)
}

fn expired(p: P) {
    let (e, t, r) = read_fails(p, S::Expired);
    // Catalog (design §4.3): the missing session, whose steps the cause renders; under
    // CI no person signs in, so it is the service-account token the run lacks (X8).
    let want = match p {
        P::Ci => "credential_rejected",
        _ => "op_not_signed_in",
    };
    assert_eq!(e.code_str(), want, "{p:?}: {t}");
    assert!(!t.contains("to see why"), "{t}");
    assert_no_values(&t);
    // FR-13: one item read; P16: diagnosed after its first attempt, so never retried here.
    assert_eq!(op_item_reads(&r), 1, "FR-13, P16");
}

/// 04.07: where op keeps its own accounts (Linux, WSL with a native op) the account is
/// added at op's prompt (`opv login --add`); where the 1Password app holds them (macOS,
/// Windows), it is added in the app and the step is `opv login`, never `--add`.
fn no_account(p: P) {
    let (e, t, r) = read_fails(p, S::NoAccount);
    assert_eq!(e.code_str(), "account_not_registered", "{p:?}: {t}");
    let step = e.step("-", "-");
    let want = match p {
        P::MacOs | P::WindowsPowerShell => "opv login",
        _ => "opv login --add",
    };
    assert_eq!(step.next, want, "{p:?}: {t}");
    assert_no_values(&t);
    // FR-13: one item read; P16: diagnosed after its first attempt, so never retried here.
    assert_eq!(op_item_reads(&r), 1, "FR-13, P16");
}

/// 04.20: signed in, the vault does not open: the missing grant on that vault, without
/// op's raw identity words (USER).
fn not_visible(p: P) {
    let (e, t, r) = read_fails(p, S::NotVisible);
    assert_eq!(e.code_str(), "vault_no_access", "{p:?}: {t}");
    assert!(t.contains("vault vprd"), "{t}");
    assert!(!t.contains("USER"), "{t}");
    assert!(
        !t.contains("to see why") && !t.contains("example.com"),
        "{t}"
    );
    assert_no_values(&t);
    // FR-13: one item read; P16: diagnosed after its first attempt, so never retried here.
    assert_eq!(op_item_reads(&r), 1, "FR-13, P16");
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
        // The 1Password app does not approve doctor's vault list.
        r.responses.borrow_mut().push_back(Ok(Output::failure(1)));
    }
    let no_fly = crate::config::parse("[environments.dev]\n").unwrap();
    let mut out = Vec::new();
    let e = doctor::run_with(Ok(no_fly), &r, &h, &mut out).unwrap_err();
    let t = text_of(&out);
    assert_eq!(e.exit_code(), 7, "{p:?}: {t}");
    let want = match p {
        P::Ci => "FAIL  op auth: the service account token in OP_SERVICE_ACCOUNT_TOKEN",
        _ => "FAIL  op auth: you are not signed in to 1Password",
    };
    assert!(t.contains(want), "{t}");
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

/// FR-26, 04.11: a non-interactive credential (service account or Connect) whose read and
/// whoami both fail is the rejected (or unreachable) credential, named by its variables, with
/// no interactive command and no `op account list`; CI or not.
#[test]
fn rejected_or_unreachable_credential_is_credential_rejected() {
    for (fake, var) in [
        (
            FakeEnv::new("linux")
                .shell("/bin/bash")
                .var("OP_SERVICE_ACCOUNT_TOKEN"),
            "OP_SERVICE_ACCOUNT_TOKEN",
        ),
        (
            FakeEnv::new("linux")
                .var("CI")
                .var("OP_SERVICE_ACCOUNT_TOKEN"),
            "OP_SERVICE_ACCOUNT_TOKEN",
        ),
        (
            FakeEnv::new("linux")
                .shell("/bin/bash")
                .var("OP_CONNECT_HOST")
                .var("OP_CONNECT_TOKEN"),
            "OP_CONNECT_HOST and OP_CONNECT_TOKEN",
        ),
        (
            FakeEnv::new("windows").var("OP_CONNECT_TOKEN"),
            "OP_CONNECT_HOST and OP_CONNECT_TOKEN",
        ),
    ] {
        let h = Host::from_env(&fake);
        let r = FakeRunner::new([Output::failure(1), Output::failure(1)]);
        let e = onepassword::read_item_with(&r, &env(), &at(), &h).unwrap_err();
        let t = crate::error::report(&e, "-", None);
        assert_eq!(e.code_str(), "credential_rejected", "{t}");
        assert!(t.contains(var), "{t}");
        assert!(!t.contains("op signin") && !t.contains("opv login"), "{t}");
        assert_eq!(
            r.calls.borrow().len(),
            2,
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
    let r = FakeRunner::new(
        std::iter::once(Output::failure(1))
            .chain([
                Output::success(WHOAMI_USER),
                Output::success(b"{}".to_vec()),
            ])
            .chain(failed_read(1)),
    );
    let e = onepassword::read_item_with(&r, &env(), &at(), &h).unwrap_err();
    // What the user sees: the message, then its `Next:` line (NR-19).
    let t = crate::error::report(&e, "-", None);
    assert_eq!(e.code_str(), "item_not_found", "{t}");
}

/// Connect: whoami failing never gets an interactive command.
#[test]
fn connect_whoami_failing_is_not_auth_with_interactive_command() {
    for shell in ["/bin/bash", "/usr/bin/fish"] {
        let h = Host::from_env(&FakeEnv::new("linux").shell(shell).var("OP_CONNECT_HOST"));
        let r = FakeRunner::new([Output::failure(1), Output::failure(1)]);
        let e = onepassword::read_item_with(&r, &env(), &at(), &h).unwrap_err();
        let t = crate::error::report(&e, "-", None);
        assert!(
            !t.contains("op signin") && !t.contains("eval") && !t.contains("opv login"),
            "{t}"
        );
    }
}

/// Not signed in (no credential): the step is opv's own sign-in, never `op signin`.
#[test]
fn not_signed_in_steps_to_opv_login() {
    let (e, _, _) = read_fails(P::Linux, S::Expired);
    assert!(e.step("-", "-").next.starts_with("opv login"), "{e}");
}

/// An unrecognised `$SHELL` gets the same `opv login`: it needs no shell syntax.
#[test]
fn unknown_shell_gets_the_same_login_command() {
    for sh in ["/usr/bin/nu", "/bin/tcsh", "/bin/csh"] {
        let h = Host::from_env(&FakeEnv::new("linux").shell(sh));
        let r = fake_op(S::Expired, false);
        let e = onepassword::read_item_with(&r, &env(), &at(), &h).unwrap_err();
        assert!(e.step("-", "-").next.starts_with("opv login"), "{sh}: {e}");
    }
}
