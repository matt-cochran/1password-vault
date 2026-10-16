//! `opv account list` / `opv account use` (FR-49): one behavioural outcome per test. No
//! `op` call: discovery and the sign-in probe are built directly.

use std::cell::RefCell;
use std::path::Path;

use super::*;
use crate::adapters::onepassword_manifest::{Account, Discovery};
use crate::host::Platform;

fn acct(id: &str, email: &str, address: &str, shorthand: &str, user: &str) -> Account {
    Account {
        account_uuid: id.into(),
        url: format!("https://{address}/"),
        email: email.into(),
        user_uuid: user.into(),
        shorthand: shorthand.into(),
    }
}

fn owner() -> Account {
    acct(
        "AAAA0000000000000000000001",
        "owner@example.com",
        "my-team.1password.com",
        "my-team",
        "USER0000000000000000000001",
    )
}

fn other() -> Account {
    acct(
        "BBBB0000000000000000000002",
        "other@example.com",
        "example.1password.com",
        "example",
        "USER0000000000000000000002",
    )
}

fn none_signed_in(_id: &str) -> Option<bool> {
    None
}

#[allow(clippy::too_many_arguments)]
fn inputs<'a>(
    discovery: Discovery,
    flag: Option<&'a str>,
    env: Option<&'a str>,
    pointer: Option<(&'a str, &'a Path)>,
    manifest: Option<&'a str>,
    platform: Platform,
    signed_in: &'a dyn Fn(&str) -> Option<bool>,
) -> Inputs<'a> {
    Inputs {
        discovery,
        signed_in,
        flag,
        env,
        pointer,
        manifest,
        platform,
        session_vars: Vec::new(),
    }
}

#[test]
fn a_flag_selects_the_account_it_names() {
    let d = Discovery::Listed(vec![owner(), other()]);
    let r = report(&inputs(
        d,
        Some("owner@example.com"),
        None,
        None,
        None,
        Platform::Linux,
        &none_signed_in,
    ));
    assert_eq!(r.selected.as_ref().map(|s| s.by.as_str()), Some("flag"));
}

#[test]
fn an_environment_value_selects_the_account_it_names() {
    let d = Discovery::Listed(vec![owner(), other()]);
    let r = report(&inputs(
        d,
        None,
        Some("BBBB0000000000000000000002"),
        None,
        None,
        Platform::Linux,
        &none_signed_in,
    ));
    assert_eq!(r.selected.as_ref().map(|s| s.by.as_str()), Some("env"));
}

#[test]
fn a_pointer_selects_its_account_and_reports_the_pointer_path_as_source() {
    let d = Discovery::Listed(vec![owner(), other()]);
    let path = Path::new("./.opv");
    let r = report(&inputs(
        d,
        None,
        None,
        Some(("other@example.com", path)),
        None,
        Platform::Linux,
        &none_signed_in,
    ));
    assert_eq!(
        r.selected.as_ref().map(|s| s.source.as_str()),
        Some("./.opv")
    );
}

#[test]
fn a_manifest_value_selects_the_account_it_names() {
    let d = Discovery::Listed(vec![owner(), other()]);
    let r = report(&inputs(
        d,
        None,
        None,
        None,
        Some("USER0000000000000000000002"),
        Platform::Linux,
        &none_signed_in,
    ));
    assert_eq!(r.selected.as_ref().map(|s| s.by.as_str()), Some("manifest"));
}

#[test]
fn a_shorthand_names_an_account_ignoring_case() {
    let d = Discovery::Listed(vec![owner(), other()]);
    let r = report(&inputs(
        d,
        Some("MY-TEAM"),
        None,
        None,
        None,
        Platform::Linux,
        &none_signed_in,
    ));
    assert_eq!(
        r.selected.as_ref().map(|s| s.account_id.as_str()),
        Some("AAAA0000000000000000000001")
    );
}

#[test]
fn a_single_listed_account_is_reported_as_the_only_selection() {
    let d = Discovery::Listed(vec![owner()]);
    let r = report(&inputs(
        d,
        None,
        None,
        None,
        None,
        Platform::Linux,
        &none_signed_in,
    ));
    assert_eq!(r.selected.as_ref().map(|s| s.by.as_str()), Some("only"));
}

#[test]
fn the_only_account_is_marked_selected() {
    let d = Discovery::Listed(vec![owner()]);
    let r = report(&inputs(
        d,
        None,
        None,
        None,
        None,
        Platform::Linux,
        &none_signed_in,
    ));
    assert!(r.accounts[0].selected);
}

#[test]
fn several_accounts_and_no_selection_selects_nothing() {
    let d = Discovery::Listed(vec![owner(), other()]);
    let r = report(&inputs(
        d,
        None,
        None,
        None,
        None,
        Platform::Linux,
        &none_signed_in,
    ));
    assert!(r.selected.is_none());
}

#[test]
fn an_empty_listing_reports_no_accounts() {
    let d = Discovery::Listed(Vec::new());
    let r = report(&inputs(
        d,
        None,
        None,
        None,
        None,
        Platform::Linux,
        &none_signed_in,
    ));
    assert_eq!(r.findings[0].code, "no_accounts");
}

#[test]
fn the_no_accounts_next_step_adds_an_account() {
    let d = Discovery::Listed(Vec::new());
    let r = report(&inputs(
        d,
        None,
        None,
        None,
        None,
        Platform::Linux,
        &none_signed_in,
    ));
    assert_eq!(r.findings[0].next.as_deref(), Some("opv login --add"));
}

#[test]
fn a_flag_that_names_no_listed_account_is_reported_absent() {
    let d = Discovery::Listed(vec![owner()]);
    let r = report(&inputs(
        d,
        Some("nobody@example.com"),
        None,
        None,
        None,
        Platform::Linux,
        &none_signed_in,
    ));
    assert_eq!(r.findings[0].code, "selected_account_absent");
}

#[test]
fn an_absent_non_email_value_next_step_lists_the_accounts() {
    let d = Discovery::Listed(vec![owner()]);
    let r = report(&inputs(
        d,
        Some("NOSUCHID"),
        None,
        None,
        None,
        Platform::Linux,
        &none_signed_in,
    ));
    assert_eq!(r.findings[0].next.as_deref(), Some("opv account list"));
}

#[test]
fn an_absent_email_next_step_adds_that_account() {
    let d = Discovery::Listed(vec![owner()]);
    let r = report(&inputs(
        d,
        Some("new@example.com"),
        None,
        None,
        None,
        Platform::Linux,
        &none_signed_in,
    ));
    assert_eq!(
        r.findings[0].next.as_deref(),
        Some("opv login --add --account new@example.com")
    );
}

#[test]
fn the_absent_finding_names_the_value_and_its_source() {
    let d = Discovery::Listed(vec![owner()]);
    let r = report(&inputs(
        d,
        None,
        Some("ghost@example.com"),
        None,
        None,
        Platform::Linux,
        &none_signed_in,
    ));
    let message = &r.findings[0].message;
    assert!(message.contains("ghost@example.com") && message.contains("OP_ACCOUNT"));
}

#[test]
fn a_signed_out_selection_reports_selected_signed_out() {
    let d = Discovery::Listed(vec![owner()]);
    let signed_out = |_id: &str| Some(false);
    let r = report(&inputs(
        d,
        None,
        None,
        None,
        None,
        Platform::Linux,
        &signed_out,
    ));
    assert_eq!(r.findings[0].code, "selected_signed_out");
}

#[test]
fn a_signed_out_selection_next_step_signs_in_that_account() {
    let d = Discovery::Listed(vec![owner()]);
    let signed_out = |_id: &str| Some(false);
    let r = report(&inputs(
        d,
        None,
        None,
        None,
        None,
        Platform::Linux,
        &signed_out,
    ));
    assert_eq!(
        r.findings[0].next.as_deref(),
        Some("opv login --account AAAA0000000000000000000001")
    );
}

#[test]
fn unavailable_discovery_is_not_human_required() {
    let r = report(&inputs(
        Discovery::Unavailable,
        None,
        None,
        None,
        None,
        Platform::Linux,
        &none_signed_in,
    ));
    assert!(!r.findings[0].human_required);
}

#[test]
fn unavailable_discovery_next_step_runs_doctor() {
    let r = report(&inputs(
        Discovery::Unavailable,
        None,
        None,
        None,
        None,
        Platform::Linux,
        &none_signed_in,
    ));
    assert_eq!(r.findings[0].next.as_deref(), Some("opv doctor"));
}

#[test]
fn missing_op_is_human_required() {
    let r = report(&inputs(
        Discovery::OpMissing,
        None,
        None,
        None,
        None,
        Platform::Linux,
        &none_signed_in,
    ));
    assert!(r.findings[0].human_required);
}

#[test]
fn the_missing_op_finding_says_op_is_not_installed() {
    let r = report(&inputs(
        Discovery::OpMissing,
        None,
        None,
        None,
        None,
        Platform::Linux,
        &none_signed_in,
    ));
    assert!(r.findings[0].message.contains("not installed"));
}

#[test]
fn unavailable_discovery_is_reported_as_unavailable() {
    let r = report(&inputs(
        Discovery::Unavailable,
        None,
        None,
        None,
        None,
        Platform::Linux,
        &none_signed_in,
    ));
    assert_eq!(r.discovery, "unavailable");
}

#[test]
fn missing_op_is_reported_as_op_missing() {
    let r = report(&inputs(
        Discovery::OpMissing,
        None,
        None,
        None,
        None,
        Platform::Linux,
        &none_signed_in,
    ));
    assert_eq!(r.discovery, "op_missing");
}

#[test]
fn the_report_next_is_the_first_findings_next() {
    let r = report(&inputs(
        Discovery::OpMissing,
        None,
        None,
        None,
        None,
        Platform::Linux,
        &none_signed_in,
    ));
    assert_eq!(r.next.as_deref(), Some("opv doctor"));
}

#[test]
fn the_sign_in_probe_runs_for_each_listed_account_and_never_for_an_absent_one() {
    let calls = RefCell::new(Vec::new());
    let probe = |id: &str| {
        calls.borrow_mut().push(id.to_string());
        None
    };
    let d = Discovery::Listed(vec![owner(), other()]);
    let _ = report(&inputs(
        d,
        Some("nobody@example.com"),
        None,
        None,
        None,
        Platform::Linux,
        &probe,
    ));
    assert_eq!(
        *calls.borrow(),
        vec!["AAAA0000000000000000000001", "BBBB0000000000000000000002"]
    );
}

#[test]
fn the_address_drops_the_scheme_and_trailing_slash() {
    let d = Discovery::Listed(vec![owner()]);
    let r = report(&inputs(
        d,
        None,
        None,
        None,
        None,
        Platform::Linux,
        &none_signed_in,
    ));
    assert_eq!(r.accounts[0].address, "my-team.1password.com");
}

#[test]
fn the_platform_is_reported_as_a_lowercase_word() {
    let d = Discovery::Listed(Vec::new());
    let r = report(&inputs(
        d,
        None,
        None,
        None,
        None,
        Platform::Wsl,
        &none_signed_in,
    ));
    assert_eq!(r.platform, "wsl");
}

#[test]
fn cli_accounts_only_is_false_on_macos() {
    let d = Discovery::Listed(Vec::new());
    let r = report(&inputs(
        d,
        None,
        None,
        None,
        None,
        Platform::MacOs,
        &none_signed_in,
    ));
    assert!(!r.cli_accounts_only);
}

#[test]
fn every_listed_account_is_marked_as_cli_sourced() {
    let d = Discovery::Listed(vec![owner()]);
    let r = report(&inputs(
        d,
        None,
        None,
        None,
        None,
        Platform::Linux,
        &none_signed_in,
    ));
    assert_eq!(r.accounts[0].source, "cli");
}

fn text(report: &Report) -> String {
    let mut out = Vec::new();
    render_text(report, &mut out).unwrap();
    String::from_utf8(out).unwrap()
}

fn linux_report(discovery: Discovery) -> Report {
    report(&inputs(
        discovery,
        None,
        None,
        None,
        None,
        Platform::Linux,
        &none_signed_in,
    ))
}

#[test]
fn the_text_table_has_the_five_columns() {
    let out = text(&linux_report(Discovery::Listed(vec![owner()])));
    assert!(
        out.contains("SELECTED")
            && out.contains("ACCOUNT")
            && out.contains("ADDRESS")
            && out.contains("SOURCE")
            && out.contains("SIGNED IN")
    );
}

#[test]
fn the_text_marks_the_selected_account_with_a_star() {
    let out = text(&linux_report(Discovery::Listed(vec![owner()])));
    assert!(out.lines().any(|l| l.starts_with('*')));
}

#[test]
fn the_text_shows_the_account_email_and_id() {
    let out = text(&linux_report(Discovery::Listed(vec![owner()])));
    assert!(out.contains("owner@example.com (AAAA0000000000000000000001)"));
}

#[test]
fn the_text_shows_unknown_when_the_session_probe_cannot_run() {
    let out = text(&linux_report(Discovery::Listed(vec![owner()])));
    assert!(out.lines().any(|l| l.contains("unknown")));
}

#[test]
fn the_text_shows_yes_for_a_signed_in_account() {
    let signed_in = |_id: &str| Some(true);
    let r = report(&inputs(
        Discovery::Listed(vec![owner()]),
        None,
        None,
        None,
        None,
        Platform::Linux,
        &signed_in,
    ));
    assert!(text(&r).lines().any(|l| l.contains("yes")));
}

#[test]
fn the_text_shows_no_for_a_signed_out_account() {
    let signed_out = |_id: &str| Some(false);
    let r = report(&inputs(
        Discovery::Listed(vec![owner()]),
        None,
        None,
        None,
        None,
        Platform::Linux,
        &signed_out,
    ));
    assert!(text(&r).lines().any(|l| l.contains("no")));
}

#[test]
fn the_text_names_the_selection_and_its_source() {
    let r = report(&inputs(
        Discovery::Listed(vec![owner(), other()]),
        Some("owner@example.com"),
        None,
        None,
        None,
        Platform::Linux,
        &none_signed_in,
    ));
    assert!(text(&r).contains("selected by --account"));
}

#[test]
fn the_text_says_when_no_account_is_selected() {
    let r = report(&inputs(
        Discovery::Listed(vec![owner(), other()]),
        None,
        None,
        None,
        None,
        Platform::Linux,
        &none_signed_in,
    ));
    assert!(text(&r).contains("no account selected for this project"));
}

#[test]
fn the_text_explains_that_only_cli_accounts_are_listed_on_linux() {
    let out = text(&linux_report(Discovery::Listed(vec![owner()])));
    assert!(out.contains("Only accounts added to this 1Password CLI are listed; an account that is only in the 1Password app appears after opv login --add."));
}

#[test]
fn the_text_explains_on_wsl_that_the_windows_app_is_invisible() {
    let r = report(&inputs(
        Discovery::Listed(vec![owner()]),
        None,
        None,
        None,
        None,
        Platform::Wsl,
        &none_signed_in,
    ));
    assert!(text(&r).contains("(op in WSL does not see the Windows app's accounts)"));
}

#[test]
fn the_text_prints_each_finding_as_its_code_and_message() {
    let out = text(&linux_report(Discovery::OpMissing));
    assert!(out.lines().any(|l| l.starts_with("op_missing: ")));
}

#[test]
fn the_text_omits_the_cli_only_note_on_macos() {
    let r = report(&inputs(
        Discovery::Listed(vec![owner()]),
        None,
        None,
        None,
        None,
        Platform::MacOs,
        &none_signed_in,
    ));
    assert!(!text(&r).contains("Only accounts added to this 1Password CLI"));
}

fn twin_a() -> Account {
    acct(
        "AAAA0000000000000000000001",
        "shared@example.com",
        "a.1password.com",
        "a",
        "USER0000000000000000000001",
    )
}

fn twin_b() -> Account {
    acct(
        "BBBB0000000000000000000002",
        "shared@example.com",
        "b.1password.com",
        "b",
        "USER0000000000000000000002",
    )
}

fn checkout() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".git")).unwrap();
    dir
}

#[test]
fn an_email_matching_several_accounts_is_ambiguous() {
    let err = use_account(&[twin_a(), twin_b()], "shared@example.com", Path::new(".")).unwrap_err();
    assert_eq!(err.code(), crate::error::Code::AccountAmbiguous);
}

#[test]
fn an_ambiguous_error_next_step_uses_the_first_candidate_id() {
    let err = use_account(&[twin_a(), twin_b()], "shared@example.com", Path::new(".")).unwrap_err();
    assert_eq!(
        err.next_step(),
        Some("opv account use AAAA0000000000000000000001")
    );
}

#[test]
fn an_ambiguous_error_lists_each_candidate_id_and_address() {
    let err = use_account(&[twin_a(), twin_b()], "shared@example.com", Path::new(".")).unwrap_err();
    let msg = err.text();
    assert!(
        msg.contains("AAAA0000000000000000000001")
            && msg.contains("a.1password.com")
            && msg.contains("BBBB0000000000000000000002")
            && msg.contains("b.1password.com")
    );
}

#[test]
fn an_ambiguous_error_never_names_the_shared_email() {
    let err = use_account(&[twin_a(), twin_b()], "shared@example.com", Path::new(".")).unwrap_err();
    assert!(!err.text().contains("shared@example.com"));
}

#[test]
fn an_unknown_account_error_names_who() {
    let err = use_account(&[owner()], "ghost@example.com", Path::new(".")).unwrap_err();
    assert!(err.text().contains("ghost@example.com"));
}

#[test]
fn an_unknown_email_next_step_adds_that_account() {
    let err = use_account(&[owner()], "new@example.com", Path::new(".")).unwrap_err();
    assert_eq!(
        err.next_step(),
        Some("opv login --add --account new@example.com")
    );
}

#[test]
fn an_unknown_non_email_next_step_lists_the_accounts() {
    let err = use_account(&[owner()], "NOSUCHID", Path::new(".")).unwrap_err();
    assert_eq!(err.next_step(), Some("opv account list"));
}

#[test]
fn one_match_returns_the_account_id() {
    let dir = checkout();
    let outcome = use_account(&[owner(), other()], "owner@example.com", dir.path()).unwrap();
    assert_eq!(outcome.account_id, "AAAA0000000000000000000001");
}

#[test]
fn one_match_writes_the_pointer_at_the_repository_root() {
    let dir = checkout();
    let outcome = use_account(&[owner(), other()], "owner@example.com", dir.path()).unwrap();
    assert_eq!(outcome.path, dir.path().join(".opv"));
}

#[test]
fn the_recorded_pointer_names_the_account_id() {
    let dir = checkout();
    let _ = use_account(&[owner(), other()], "owner@example.com", dir.path()).unwrap();
    let text = std::fs::read_to_string(dir.path().join(".opv")).unwrap();
    assert!(text.contains("AAAA0000000000000000000001"));
}

#[test]
fn use_account_matches_a_sign_in_address() {
    let dir = checkout();
    let outcome = use_account(&[owner(), other()], "my-team.1password.com", dir.path()).unwrap();
    assert_eq!(outcome.account_id, "AAAA0000000000000000000001");
}

#[test]
fn a_use_outcome_serializes_its_account_id() {
    let outcome = UseOutcome {
        account_id: "AAAA0000000000000000000001".into(),
        path: std::path::PathBuf::from(".opv"),
    };
    assert!(
        serde_json::to_string(&outcome)
            .unwrap()
            .contains("AAAA0000000000000000000001")
    );
}

#[test]
fn a_serialized_report_never_has_a_secret_named_field() {
    let signed_out = |_id: &str| Some(false);
    let r = report(&inputs(
        Discovery::Listed(vec![owner(), other()]),
        Some("owner@example.com"),
        None,
        None,
        None,
        Platform::Linux,
        &signed_out,
    ));
    let json = serde_json::to_string(&r).unwrap();
    let forbidden = ["value", "token", "password", "session"];
    assert!(!forbidden.iter().any(|f| json.contains(&format!("\"{f}\""))));
}

// Shared sign-in address (review) ---------------------------------------------------------

fn two_at_one_address() -> Vec<Account> {
    serde_json::from_str(
        r#"[{"url":"https://my.1password.com/","email":"a@x.example","account_uuid":"AAAAAAAAAAAAAAAAAAAAAAAAAA"},
            {"url":"https://my.1password.com/","email":"b@x.example","account_uuid":"BBBBBBBBBBBBBBBBBBBBBBBBBB"}]"#,
    )
    .unwrap()
}

#[test]
fn a_selection_matching_several_accounts_is_ambiguous_not_absent() {
    let accounts = two_at_one_address();
    let r = report(&Inputs {
        discovery: Discovery::Listed(accounts),
        signed_in: &|_| None,
        flag: Some("my.1password.com"),
        env: None,
        pointer: None,
        manifest: None,
        platform: Platform::Linux,
        session_vars: Vec::new(),
    });
    assert_eq!(r.findings[0].code, "account_ambiguous");
}

#[test]
fn using_an_unknown_account_says_it_is_not_registered() {
    let dir = tempfile::tempdir().unwrap();
    let e = use_account(&two_at_one_address(), "nobody@x.example", dir.path()).unwrap_err();
    assert_eq!(e.code(), Code::AccountNotRegistered);
}

// --- #142: two accounts on one sign-in address, and session variables in the shell ---

/// The owner's WSL setup: a personal (`my`) and a business (`mcproductlabs`) account, both
/// on my.1password.com.
fn personal() -> Account {
    acct(
        "PERS0000000000000000000001",
        "me@example.com",
        "my.1password.com",
        "my",
        "USERPERS000000000000000001",
    )
}

fn business() -> Account {
    acct(
        "BUSI0000000000000000000002",
        "me@business.example",
        "my.1password.com",
        "mcproductlabs",
        "USERBUSI000000000000000002",
    )
}

fn shared(vars: &[&str]) -> Report {
    report(&Inputs {
        discovery: Discovery::Listed(vec![personal(), business()]),
        signed_in: &none_signed_in,
        flag: Some("BUSI0000000000000000000002"),
        env: None,
        pointer: None,
        manifest: None,
        platform: Platform::Wsl,
        session_vars: vars.iter().map(|v| v.to_string()).collect(),
    })
}

fn codes(r: &Report) -> Vec<&str> {
    r.findings.iter().map(|f| f.code.as_str()).collect()
}

#[test]
fn two_accounts_on_one_address_are_reported() {
    assert!(codes(&shared(&[])).contains(&"shared_sign_in_address"));
}

#[test]
fn the_shared_address_finding_names_each_accounts_shorthand() {
    let r = shared(&[]);
    let f = r
        .findings
        .iter()
        .find(|f| f.code == "shared_sign_in_address")
        .unwrap();
    assert!(
        f.message.contains("my = me@example.com")
            && f.message.contains("mcproductlabs = me@business.example")
    );
}

#[test]
fn a_session_variable_for_the_other_account_is_reported() {
    assert!(codes(&shared(&["OP_SESSION_my"])).contains(&"session_for_other_account"));
}

#[test]
fn a_session_variable_for_the_selected_account_is_fine() {
    assert!(
        !codes(&shared(&["OP_SESSION_mcproductlabs"]))
            .iter()
            .any(|c| c.contains("session"))
    );
}

#[test]
fn a_session_variable_for_no_known_account_is_stale() {
    assert!(codes(&shared(&["OP_SESSION_gone"])).contains(&"stale_session_variable"));
}

/// #157: a sign-in fixes neither a foreign session variable nor a shared address, so
/// advisory findings alone leave the report without a step (it used to be `opv login`).
#[test]
fn advisory_findings_alone_give_the_report_no_next_step() {
    assert_eq!(shared(&["OP_SESSION_my"]).next, None);
}

#[test]
fn a_stale_session_variable_has_no_login_step() {
    let r = shared(&["OP_SESSION_gone"]);
    let f = r
        .findings
        .iter()
        .find(|f| f.code == "stale_session_variable")
        .unwrap();
    assert_eq!(f.next, None);
}

#[test]
fn a_stale_session_variable_says_to_unset_it() {
    let r = shared(&["OP_SESSION_gone"]);
    let f = r
        .findings
        .iter()
        .find(|f| f.code == "stale_session_variable")
        .unwrap();
    assert!(f.message.contains("unset OP_SESSION_gone"));
}

#[test]
fn the_shared_address_finding_has_no_login_step() {
    let r = shared(&[]);
    let f = r
        .findings
        .iter()
        .find(|f| f.code == "shared_sign_in_address")
        .unwrap();
    assert_eq!(f.next, None);
}

/// #157: account_not_registered exits 7 (auth), as its code says.
#[test]
fn an_unknown_account_error_exits_as_its_code_says() {
    let err = use_account(&[owner()], "ghost@example.com", Path::new(".")).unwrap_err();
    assert_eq!(err.exit_code(), err.code().exit_code());
}

#[test]
fn accounts_on_different_addresses_are_not_reported_as_shared() {
    let r = report(&Inputs {
        discovery: Discovery::Listed(vec![owner(), other()]),
        signed_in: &none_signed_in,
        flag: None,
        env: None,
        pointer: None,
        manifest: None,
        platform: Platform::Linux,
        session_vars: Vec::new(),
    });
    assert!(!codes(&r).contains(&"shared_sign_in_address"));
}

#[test]
fn a_bare_op_session_variable_is_stale() {
    assert!(codes(&shared(&["OP_SESSION"])).contains(&"stale_session_variable"));
}
