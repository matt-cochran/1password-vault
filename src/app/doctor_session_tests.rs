//! #203: desktop-app detection and doctor's session rows (`docs/design/session-reuse.md`
//! §3.2, §3.3; FMECA H3, M2, M3, L1, L6). The op replies are the recorded ones in
//! `tests/fixtures/op` (op 2.40.0) with their markers filled in; the app-shaped `whoami` has
//! no recording yet (O2, an owner recording in §8.1), so it is the recorded `s20` without
//! the two fields O2 says the app leaves out.

use std::io;

use super::*;
use crate::app::account::{is_session_var, session_var_owner};
use crate::host::FakeEnv;
use crate::runner::Output;
use crate::runner::fake::FakeRunner;

const ACCOUNT_LIST: &str = include_str!("../../tests/fixtures/op/success/s01-account-list.stdout");
const VAULT_LIST: &str = include_str!("../../tests/fixtures/op/success/s02-vault-list.stdout");
const WHOAMI_CLI: &str = include_str!("../../tests/fixtures/op/success/s20-whoami.stdout");
const SIGNED_OUT_VAULT_LIST: &str =
    include_str!("../../tests/fixtures/op/failures/06-signed-out-vault-list.stderr");
const VAULT_NOT_FOUND: &str =
    include_str!("../../tests/fixtures/op/failures/08-vault-not-found.stderr");

/// Account 1 and 2 of the recording, with IDs and shorthands opv accepts.
const ACCOUNT_1: &str = "AAAAAAAAAAAAAAAAAAAAAAAAA1";
const ACCOUNT_2: &str = "BBBBBBBBBBBBBBBBBBBBBBBBB2";

fn account_list() -> String {
    ACCOUNT_LIST
        .replace("<ACCOUNT_1>", ACCOUNT_1)
        .replace("<ACCOUNT_2>", ACCOUNT_2)
        .replace("<SHORTHAND_1>", "one")
        .replace("<SHORTHAND_2>", "two")
        .replace("<USER_1>", "USER1")
        .replace("<USER_2>", "USER2")
        .replace("<ADDRESS_1>", "my.1password.com")
        .replace("<EMAIL_1>", "a@example.com")
        .replace("<EMAIL_2>", "b@example.com")
}

/// `s20` as the app integration answers it (O2): no `user_type`, no `shorthand`.
fn whoami_app() -> String {
    let mut v: serde_json::Value = serde_json::from_str(WHOAMI_CLI).unwrap();
    let o = v.as_object_mut().unwrap();
    o.remove("user_type");
    o.remove("shorthand");
    v.to_string()
}

fn host(env: FakeEnv) -> Host {
    Host::from_env(&env.shell("/bin/bash"))
}

fn linux() -> FakeEnv {
    FakeEnv::new("linux")
}

fn desktop_linux() -> FakeEnv {
    linux().var_val("DISPLAY", ":0")
}

fn wsl() -> FakeEnv {
    linux().osrelease("6.6.87.2-microsoft-standard-WSL2")
}

fn args(r: &FakeRunner) -> Vec<String> {
    r.calls.borrow().iter().map(|c| c.args.join(" ")).collect()
}

fn unavailable(reason: NoIntegration) -> Option<DesktopIntegration> {
    Some(DesktopIntegration::Unavailable { reason })
}

// --- host helpers (§7.2) ---

#[test]
fn biometric_override_reads_go_booleans() {
    for v in ["false", "0", "f", "F", "FALSE", "False"] {
        let h = host(linux().var_val("OP_BIOMETRIC_UNLOCK_ENABLED", v));
        assert_eq!(h.op_biometric_override(), Some(false), "{v}");
    }
    for v in ["true", "1", "t", "T", "TRUE", "True", " true "] {
        let h = host(linux().var_val("OP_BIOMETRIC_UNLOCK_ENABLED", v));
        assert_eq!(h.op_biometric_override(), Some(true), "{v}");
    }
    for v in ["no", "off", "yes", ""] {
        let h = host(linux().var_val("OP_BIOMETRIC_UNLOCK_ENABLED", v));
        assert_eq!(h.op_biometric_override(), None, "{v}");
    }
    assert_eq!(host(linux()).op_biometric_override(), None);
}

#[test]
fn a_graphical_session_is_display_or_wayland() {
    assert!(!host(linux()).graphical_session());
    assert!(!host(linux().var_val("DISPLAY", "")).graphical_session());
    assert!(host(linux().var_val("DISPLAY", ":0")).graphical_session());
    assert!(host(linux().var_val("WAYLAND_DISPLAY", "wayland-0")).graphical_session());
}

#[test]
fn a_session_in_env_is_a_non_empty_session_variable() {
    assert!(!host(linux()).op_session_in_env());
    assert!(host(linux().var_val("OP_SESSION_one", "x")).op_session_in_env());
    assert!(host(linux().var_val("OP_SESSION", "x")).op_session_in_env());
    assert!(!host(linux().var_val("OP_SESSION_one", "")).op_session_in_env());
    // FMECA L6: op's delegation flag holds no session.
    assert!(!host(linux().var("OP_SESSION_DELEGATION_ENABLED")).op_session_in_env());
}

#[test]
fn the_app_is_looked_for_only_on_a_linux_desktop() {
    assert!(host(desktop_linux().desktop_app()).desktop_app_running());
    assert!(!host(linux().desktop_app()).desktop_app_running());
    assert!(!host(wsl().var_val("DISPLAY", ":0").desktop_app()).desktop_app_running());
    assert!(!host(FakeEnv::new("macos").desktop_app()).desktop_app_running());
    assert!(!host(desktop_linux().desktop_app().var("CI")).desktop_app_running());
}

// --- account helpers (FMECA M3, L6) ---

#[test]
fn session_vars_are_op_session_and_its_suffixed_names() {
    assert!(is_session_var("OP_SESSION"));
    assert!(is_session_var("OP_SESSION_one"));
    assert!(is_session_var("OP_SESSION_USER1"));
    assert!(!is_session_var("OP_SESSION_"));
    assert!(!is_session_var("OP_SESSIONS"));
    assert!(!is_session_var("OP_SESSION_DELEGATION_ENABLED"));
    assert!(!is_session_var("OP_ACCOUNT"));
    assert!(!is_session_var("XOP_SESSION_one"));
}

#[test]
fn a_session_var_belongs_to_the_account_its_suffix_names() {
    let listed: Vec<Account> = serde_json::from_str(&account_list()).unwrap();
    let owner = |v| session_var_owner(v, &listed).map(|a| a.account_uuid.as_str());
    assert_eq!(owner("OP_SESSION_one"), Some(ACCOUNT_1));
    assert_eq!(owner("OP_SESSION_TWO"), Some(ACCOUNT_2));
    assert_eq!(owner("OP_SESSION_USER2"), Some(ACCOUNT_2));
    assert_eq!(owner("OP_SESSION_gone"), None);
    assert_eq!(owner("OP_SESSION"), None);
    assert_eq!(owner("OP_ACCOUNT"), None);
}

// --- classify_static (§3.2 steps 1-4) ---

#[test]
fn step_1_ci_and_credentials_are_not_applicable() {
    let na = Some(DesktopIntegration::NotApplicable);
    assert_eq!(classify_static(&host(desktop_linux().var("CI"))), na);
    assert_eq!(
        classify_static(&host(FakeEnv::new("macos").var("GITHUB_ACTIONS"))),
        na
    );
    assert_eq!(
        classify_static(&host(
            FakeEnv::new("macos").var_val("OP_SERVICE_ACCOUNT_TOKEN", "x")
        )),
        na
    );
    assert_eq!(
        classify_static(&host(
            FakeEnv::new("windows").var_val("OP_CONNECT_HOST", "x")
        )),
        na
    );
    // Before every other step.
    assert_eq!(
        classify_static(&host(
            wsl().var("CI").var_val("OP_BIOMETRIC_UNLOCK_ENABLED", "0")
        )),
        na
    );
}

#[test]
fn step_2_the_variable_turns_it_off_anywhere() {
    for env in [
        FakeEnv::new("macos"),
        FakeEnv::new("windows"),
        desktop_linux().desktop_app(),
        wsl(),
    ] {
        let h = host(env.var_val("OP_BIOMETRIC_UNLOCK_ENABLED", "false"));
        assert_eq!(
            classify_static(&h),
            unavailable(NoIntegration::DisabledByEnv)
        );
    }
    // A true value changes nothing.
    let h = host(FakeEnv::new("macos").var_val("OP_BIOMETRIC_UNLOCK_ENABLED", "true"));
    assert_eq!(classify_static(&h), None);
}

#[test]
fn step_3_wsl_with_the_linux_op_cannot_reach_the_app() {
    assert_eq!(
        classify_static(&host(wsl())),
        unavailable(NoIntegration::WslLinuxOp)
    );
    // WSLg's display does not help the Linux op.
    assert_eq!(
        classify_static(&host(wsl().var_val("DISPLAY", ":0"))),
        unavailable(NoIntegration::WslLinuxOp)
    );
    assert_eq!(
        classify_static(&host(linux().var("WSL_DISTRO_NAME"))),
        unavailable(NoIntegration::WslLinuxOp)
    );
    // op.exe goes through the Windows app: a probe decides.
    assert_eq!(classify_static(&host(wsl().op_windows_exe())), None);
}

#[test]
fn step_4_linux_without_a_display_is_headless() {
    assert_eq!(
        classify_static(&host(linux())),
        unavailable(NoIntegration::Headless)
    );
    assert_eq!(
        classify_static(&host(linux().desktop_app())),
        unavailable(NoIntegration::Headless)
    );
    assert_eq!(
        classify_static(&host(FakeEnv::new("freebsd"))),
        unavailable(NoIntegration::Headless)
    );
}

#[test]
fn fmeca_m2_a_linux_desktop_without_the_app_has_no_app() {
    assert_eq!(
        classify_static(&host(desktop_linux())),
        unavailable(NoIntegration::NoApp)
    );
    assert_eq!(
        classify_static(&host(linux().var_val("WAYLAND_DISPLAY", "wayland-0"))),
        unavailable(NoIntegration::NoApp)
    );
    // With the app running, a probe decides.
    assert_eq!(classify_static(&host(desktop_linux().desktop_app())), None);
}

#[test]
fn macos_and_windows_need_the_probe() {
    assert_eq!(classify_static(&host(FakeEnv::new("macos"))), None);
    assert_eq!(classify_static(&host(FakeEnv::new("windows"))), None);
}

// --- detect (§3.2 steps 5-7) ---

#[test]
fn a_static_answer_runs_no_op() {
    for env in [linux(), desktop_linux(), wsl(), linux().var("CI")] {
        let r = FakeRunner::new([]);
        let found = detect(&host(env), &r);
        assert!(!matches!(found, DesktopIntegration::Active), "{found:?}");
        assert!(r.calls.borrow().is_empty());
    }
}

#[test]
fn step_5_whoami_without_user_type_is_the_app() {
    let r = FakeRunner::new([Output::success(whoami_app())]);
    assert_eq!(
        detect(&host(FakeEnv::new("macos")), &r),
        DesktopIntegration::Active
    );
    assert_eq!(args(&r), ["whoami --format json"]);
    let r = FakeRunner::new([Output::success(whoami_app())]);
    assert_eq!(
        detect(&host(desktop_linux().desktop_app()), &r),
        DesktopIntegration::Active
    );
}

#[test]
fn step_5_whoami_with_user_type_is_unknown() {
    // I1 is wrong somewhere (a CLI session answered with every variable emptied).
    let r = FakeRunner::new([Output::success(WHOAMI_CLI)]);
    assert_eq!(
        detect(&host(FakeEnv::new("macos")), &r),
        DesktopIntegration::Unknown
    );
    let r = FakeRunner::new([Output::success("not json")]);
    assert_eq!(
        detect(&host(FakeEnv::new("windows")), &r),
        DesktopIntegration::Unknown
    );
}

#[test]
fn step_5_the_probe_empties_every_session_variable() {
    let r = FakeRunner::new([Output::success(whoami_app())]);
    let vars = ["OP_SESSION_one".to_string(), "OP_SESSION".to_string()];
    assert_eq!(probe_app(&r, &vars), DesktopIntegration::Active);
    let calls = r.calls.borrow();
    assert_eq!(
        calls[0].env,
        [
            ("OP_SESSION_one".to_string(), String::new()),
            ("OP_SESSION".to_string(), String::new())
        ]
    );
}

#[test]
fn step_6_a_failed_probe_is_available() {
    for env in [
        FakeEnv::new("macos"),
        FakeEnv::new("windows"),
        wsl().op_windows_exe(),
        desktop_linux().desktop_app(),
    ] {
        let r = FakeRunner::new([]);
        r.push_with_stderr(Output::failure(1), SIGNED_OUT_VAULT_LIST);
        assert_eq!(detect(&host(env), &r), DesktopIntegration::Available);
        // The expected failure attaches to nothing later (NR-31).
        assert!(crate::runner::take_failure().is_none());
    }
}

#[test]
fn step_7_op_missing_or_silent_is_unknown() {
    let r = FakeRunner::new([]);
    r.push_io_error(io::ErrorKind::NotFound);
    assert_eq!(
        detect(&host(FakeEnv::new("macos")), &r),
        DesktopIntegration::Unknown
    );
    let r = FakeRunner::new([]);
    r.push_io_error(io::ErrorKind::TimedOut);
    assert_eq!(
        detect(&host(FakeEnv::new("macos")), &r),
        DesktopIntegration::Unknown
    );
}

// --- shell_session (FMECA H3, M3) ---

fn vars(names: &[&str]) -> Vec<String> {
    names.iter().map(|n| n.to_string()).collect()
}

#[test]
fn no_session_variable_is_no_row_and_no_call() {
    let r = FakeRunner::new([]);
    assert_eq!(shell_session(&host(linux()), &r, None), None);
    assert_eq!(shell_session_in(&r, None, &[]), None);
    assert!(r.calls.borrow().is_empty());
}

#[test]
fn h3_a_vault_list_that_works_is_live() {
    let r = FakeRunner::new([Output::success(account_list()), Output::success(VAULT_LIST)]);
    assert_eq!(
        shell_session_in(&r, None, &vars(&["OP_SESSION_two"])),
        Some(ShellSession::Live {
            var: "OP_SESSION_two".into()
        })
    );
    assert_eq!(
        args(&r),
        [
            "account list --format json".to_string(),
            format!("vault list --format json --account {ACCOUNT_2}")
        ]
    );
}

#[test]
fn h3_a_signed_out_vault_list_is_expired_even_when_whoami_would_answer() {
    // #167: the stale variable's whoami still names the account; whoami is never asked.
    let r = FakeRunner::new([Output::success(account_list())]);
    r.push_with_stderr(Output::failure(1), SIGNED_OUT_VAULT_LIST);
    assert_eq!(
        shell_session_in(&r, Some(ACCOUNT_2), &vars(&["OP_SESSION_two"])),
        Some(ShellSession::Expired {
            var: "OP_SESSION_two".into()
        })
    );
    assert!(
        !args(&r).iter().any(|a| a.starts_with("whoami")),
        "{:?}",
        args(&r)
    );
    assert!(crate::runner::take_failure().is_none());
}

#[test]
fn a_vault_list_failing_for_another_reason_is_no_answer() {
    let r = FakeRunner::new([Output::success(account_list())]);
    r.push_with_stderr(Output::failure(1), VAULT_NOT_FOUND);
    assert_eq!(shell_session_in(&r, None, &vars(&["OP_SESSION_one"])), None);
    let r = FakeRunner::new([Output::success(account_list())]);
    r.push_io_error(io::ErrorKind::TimedOut);
    assert_eq!(shell_session_in(&r, None, &vars(&["OP_SESSION_one"])), None);
}

#[test]
fn m3_the_variable_is_the_one_the_account_owns() {
    let r = FakeRunner::new([Output::success(account_list()), Output::success(VAULT_LIST)]);
    let found = shell_session_in(
        &r,
        Some("b@example.com"),
        &vars(&["OP_SESSION_one", "OP_SESSION_two"]),
    );
    assert_eq!(
        found,
        Some(ShellSession::Live {
            var: "OP_SESSION_two".into()
        })
    );
    assert!(args(&r)[1].ends_with(ACCOUNT_2));
}

#[test]
fn m3_no_variable_for_the_account_is_no_row() {
    let r = FakeRunner::new([Output::success(account_list())]);
    assert_eq!(
        shell_session_in(&r, Some(ACCOUNT_2), &vars(&["OP_SESSION_one"])),
        None
    );
    assert_eq!(r.calls.borrow().len(), 1);
}

#[test]
fn m3_without_a_listing_only_a_lone_variable_is_taken() {
    let r = FakeRunner::new([Output::failure(1), Output::success(VAULT_LIST)]);
    assert_eq!(
        shell_session_in(&r, Some(ACCOUNT_2), &vars(&["OP_SESSION_two"])),
        Some(ShellSession::Live {
            var: "OP_SESSION_two".into()
        })
    );
    assert_eq!(args(&r)[1], "vault list --format json");
    let r = FakeRunner::new([Output::failure(1)]);
    assert_eq!(
        shell_session_in(&r, None, &vars(&["OP_SESSION_one", "OP_SESSION_two"])),
        None
    );
}

#[test]
fn without_an_account_an_owned_variable_comes_first() {
    let r = FakeRunner::new([Output::success(account_list()), Output::success(VAULT_LIST)]);
    let found = shell_session_in(&r, None, &vars(&["OP_SESSION", "OP_SESSION_one"]));
    assert_eq!(
        found,
        Some(ShellSession::Live {
            var: "OP_SESSION_one".into()
        })
    );
}

// --- rows (§3.3) ---

fn one(rows: &[DoctorRow]) -> &DoctorRow {
    assert_eq!(rows.len(), 1, "{rows:?}");
    &rows[0]
}

#[test]
fn active_row() {
    let rows = rows(
        DesktopIntegration::Active,
        None,
        &host(FakeEnv::new("macos")),
    );
    let row = one(&rows);
    assert_eq!(row.name, "op app integration");
    assert_eq!(row.status, RowStatus::Ok);
    assert_eq!(
        row.text,
        "on; commands here reuse the 1Password app's unlock"
    );
    assert_eq!((row.state, row.reason), ("active", None));
}

#[test]
fn available_row() {
    let rows = rows(
        DesktopIntegration::Available,
        None,
        &host(FakeEnv::new("macos")),
    );
    let row = one(&rows);
    assert_eq!(row.status, RowStatus::Warn);
    assert_eq!(
        row.text,
        "not confirmed; approve 1Password's prompt at the next command, or turn on Developer > \
         Integrate with 1Password CLI"
    );
    assert_eq!(row.state, "available");
}

#[test]
fn unavailable_rows_name_why_and_the_refresh() {
    let cases = [
        (
            NoIntegration::WslLinuxOp,
            "WSL with the Linux op",
            "wsl_linux_op",
        ),
        (NoIntegration::Headless, "no graphical session", "headless"),
        (
            NoIntegration::DisabledByEnv,
            "OP_BIOMETRIC_UNLOCK_ENABLED=false",
            "disabled_by_env",
        ),
        (
            NoIntegration::NoApp,
            "the 1Password app is not running",
            "no_app",
        ),
    ];
    for (reason, why, code) in cases {
        let rows = rows(
            DesktopIntegration::Unavailable { reason },
            None,
            &host(linux()),
        );
        let row = one(&rows);
        assert_eq!(row.status, RowStatus::Ok);
        assert_eq!(
            row.text,
            format!("unavailable ({why}); sign in once per shell: eval \"$(opv login --shell)\"")
        );
        assert_eq!((row.state, row.reason), ("unavailable", Some(code)));
        // The JSON reason is the type's own serde name.
        assert_eq!(serde_json::to_value(reason).unwrap(), code);
    }
}

#[test]
fn m2_no_app_never_says_unlock_the_app() {
    let rows = rows(
        DesktopIntegration::Unavailable {
            reason: NoIntegration::NoApp,
        },
        None,
        &host(desktop_linux()),
    );
    let row = one(&rows);
    assert!(!row.text.to_lowercase().contains("unlock"), "{}", row.text);
    assert!(!row.text.contains("Developer"), "{}", row.text);
}

#[test]
fn the_refresh_follows_the_shell() {
    let fish = Host::from_env(&linux().shell("/usr/bin/fish"));
    let rows = rows(
        DesktopIntegration::Unavailable {
            reason: NoIntegration::Headless,
        },
        None,
        &fish,
    );
    assert!(one(&rows).text.ends_with("opv login --shell=fish | source"));
}

#[test]
fn not_applicable_and_unknown_rows() {
    let rows_na = rows(
        DesktopIntegration::NotApplicable,
        None,
        &host(linux().var("CI")),
    );
    assert_eq!(one(&rows_na).status, RowStatus::Skip);
    assert_eq!(one(&rows_na).state, "not_applicable");
    let rows_u = rows(
        DesktopIntegration::Unknown,
        None,
        &host(FakeEnv::new("macos")),
    );
    assert_eq!(one(&rows_u).status, RowStatus::Warn);
    assert_eq!(one(&rows_u).text, "could not tell");
    assert_eq!(one(&rows_u).state, "unknown");
}

fn shell_row(shell: ShellSession, h: &Host) -> DoctorRow {
    let mut all = rows(
        DesktopIntegration::Unavailable {
            reason: NoIntegration::WslLinuxOp,
        },
        Some(&shell),
        h,
    );
    assert_eq!(all.len(), 2);
    all.pop().unwrap()
}

#[test]
fn a_live_shell_session_row_names_the_variable_only() {
    let row = shell_row(
        ShellSession::Live {
            var: "OP_SESSION_two".into(),
        },
        &host(wsl()),
    );
    assert_eq!(row.name, "op shell session");
    assert_eq!(row.status, RowStatus::Ok);
    assert_eq!(row.text, "live in this shell (OP_SESSION_two)");
    assert_eq!((row.state, row.fix.as_deref()), ("live", None));
}

#[test]
fn an_expired_shell_session_row_hands_the_refresh() {
    let row = shell_row(
        ShellSession::Expired {
            var: "OP_SESSION_two".into(),
        },
        &host(wsl()),
    );
    assert_eq!(row.status, RowStatus::Warn);
    assert_eq!(row.text, "expired or signed out (OP_SESSION_two)");
    assert_eq!(row.state, "expired");
    assert_eq!(row.fix.as_deref(), Some("eval \"$(opv login --shell)\""));
}

#[test]
fn an_assistant_in_the_shell_is_warned_about() {
    let row = shell_row(
        ShellSession::Live {
            var: "OP_SESSION_two".into(),
        },
        &host(wsl().var("CLAUDECODE")),
    );
    assert_eq!(row.status, RowStatus::Warn);
    assert_eq!(row.state, "inherited_by_assistant");
    assert!(
        row.text
            .starts_with("an assistant started from this shell inherits it")
    );
}

// --- doctor_rows ---

#[test]
fn doctor_rows_on_a_headless_linux_run_no_op() {
    let r = FakeRunner::new([]);
    let rows = doctor_rows(&host(linux()), &r, None);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].reason, Some("headless"));
    assert!(r.calls.borrow().is_empty());
}
