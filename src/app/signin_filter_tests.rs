use super::*;

/// op 2.40.0 at a closed terminal: the prompt, then its error on the same line.
const PROMPT_THEN_ERROR: &str =
    include_str!("../../tests/fixtures/op_signin/signin_noninteractive.stderr");
const UNREGISTERED: &str = include_str!("../../tests/fixtures/op_signin/unregistered.stderr");
const NOT_SIGNED_IN: &str = include_str!("../../tests/fixtures/op_signin/vault_list.stderr");
const NO_SESSION: &str = include_str!("../../tests/fixtures/op_signin/whoami_out.stderr");
const ADD_NO_TERMINAL: &str =
    include_str!("../../tests/fixtures/op_signin/add_noninteractive.stderr");

/// What reaches the terminal, and the captured messages, feeding `chunks` in order.
fn filtered(chunks: &[&str]) -> (String, Vec<String>) {
    let mut out = Vec::new();
    let mut f = Filter::default();
    for c in chunks {
        f.feed(c.as_bytes(), &mut out).unwrap();
    }
    let messages = f.finish(&mut out).unwrap();
    (String::from_utf8(out).unwrap(), messages)
}

#[test]
fn the_prompt_reaches_the_terminal() {
    let (shown, _) = filtered(&[PROMPT_THEN_ERROR]);
    assert_eq!(
        shown,
        "Enter the password for owner@example.com at my.1password.com: "
    );
}

#[test]
fn the_error_after_the_prompt_is_captured_without_its_timestamp() {
    let (_, messages) = filtered(&[PROMPT_THEN_ERROR]);
    assert_eq!(messages, ["inappropriate ioctl for device"]);
}

#[test]
fn ops_own_directions_never_reach_the_terminal() {
    let (shown, _) = filtered(&[NOT_SIGNED_IN]);
    assert!(!shown.contains("op signin --help"), "{shown}");
}

#[test]
fn a_tag_split_across_reads_is_still_captured() {
    let (shown, messages) = filtered(&["Password: [ERR", "OR] 2026/10/13 03:21:24 bad thing\n"]);
    assert_eq!((shown.as_str(), messages.len()), ("Password: ", 1));
}

#[test]
fn a_bracket_that_is_not_the_tag_is_forwarded() {
    let (shown, _) = filtered(&["[INFO] fine\n", "[[x]\n"]);
    assert_eq!(shown, "[INFO] fine\n[[x]\n");
}

#[test]
fn plain_output_passes_unchanged() {
    let (shown, _) = filtered(&["Enter the Secret Key: ", "\n"]);
    assert_eq!(shown, "Enter the Secret Key: \n");
}

#[test]
fn an_unfinished_error_line_is_still_captured() {
    let (_, messages) = filtered(&["[ERROR] 2026/10/13 03:21:24 cut short"]);
    assert_eq!(messages, ["cut short"]);
}

fn class_of(stderr: &str) -> Failure {
    classify(&filtered(&[stderr]).1, Some(1))
}

#[test]
fn an_unknown_account_is_not_registered() {
    assert_eq!(class_of(UNREGISTERED), Failure::AccountNotRegistered);
}

#[test]
fn no_session_is_not_signed_in() {
    assert_eq!(class_of(NO_SESSION), Failure::NotSignedIn);
}

#[test]
fn not_currently_signed_in_is_not_signed_in() {
    assert_eq!(class_of(NOT_SIGNED_IN), Failure::NotSignedIn);
}

#[test]
fn a_closed_terminal_needs_a_terminal() {
    assert_eq!(class_of(PROMPT_THEN_ERROR), Failure::NoTerminal);
}

#[test]
fn an_add_without_a_terminal_needs_a_terminal() {
    assert_eq!(class_of(ADD_NO_TERMINAL), Failure::NoTerminal);
}

#[test]
fn ctrl_c_is_cancelled() {
    assert_eq!(classify(&[], Some(130)), Failure::Cancelled);
}

#[test]
fn an_unrecognised_failure_is_never_a_wrong_password() {
    assert_eq!(
        classify(&["something new happened".into()], Some(1)),
        Failure::Unexpected
    );
}

fn cause_of(e: &Error) -> crate::cause::Cause {
    e.cause().expect("a catalog cause").0.clone()
}

/// The catalog renders the add step from the account's kind: an email may follow
/// `opv login --add --account`.
#[test]
fn an_unregistered_email_is_named_as_an_email() {
    let e = Failure::AccountNotRegistered.error("signing in", Some("owner@example.com"), "login");
    assert!(
        matches!(
            cause_of(&e),
            crate::cause::Cause::AccountNotOnMachine {
                account: AccountRef::Email(ref m),
                ..
            } if m == "owner@example.com"
        ),
        "{e:?}"
    );
}

/// Audit 04.02: an account ID is never handed to `op account add --email`: it is named as
/// an ID, whose add step is `opv login --add` without `--account`.
#[test]
fn an_unregistered_account_id_is_named_as_an_id() {
    let e = Failure::AccountNotRegistered.error(
        "signing in",
        Some("TTDZ56BHZFH6VFAWGXNBFD3EWU"),
        "login",
    );
    assert!(
        matches!(
            cause_of(&e),
            crate::cause::Cause::AccountNotOnMachine {
                account: AccountRef::Id(_),
                ..
            }
        ),
        "{e:?}"
    );
}

#[test]
fn a_known_account_is_named_in_the_sign_in_cause() {
    let e = Failure::NotSignedIn.error("signing in", Some("ABCDEF"), "setup");
    assert!(
        matches!(
            cause_of(&e),
            crate::cause::Cause::NotSignedIn { account: Some(ref a), .. } if a.as_str() == "ABCDEF"
        ),
        "{e:?}"
    );
}

/// C9, 04.02: a failure the classifier cannot name goes through the 1Password diagnosis of
/// the prompted call, never opv's own guess.
#[test]
fn an_unrecognised_failure_is_diagnosed_from_ops_reply() {
    let e = Failure::Unexpected.error_said("signing in", None, "status", &[], Some(1));
    assert_eq!(e.code_str(), "unrecognized_failure");
}

/// #142: op's own line is the evidence of a diagnosed prompt failure.
#[test]
fn an_unrecognised_failure_shows_ops_own_line() {
    let e = Failure::Unexpected.error_said(
        "signing in",
        None,
        "status",
        &["something op said".to_string()],
        Some(1),
    );
    let shown = crate::error::report(&e);
    assert!(shown.contains("something op said"), "{shown}");
}

/// Audit 04.15: op with the app integration off reports no accounts configured.
#[test]
fn no_accounts_configured_is_not_registered() {
    assert_eq!(
        classify(
            &["No accounts configured for use with 1Password CLI.".into()],
            Some(1)
        ),
        Failure::AccountNotRegistered
    );
}

/// Audit 04.18: an unanswered app approval is the app, not the network.
#[test]
fn an_authorization_timeout_is_the_app_not_the_network() {
    assert_eq!(
        classify(&["authorization timeout".into()], Some(1)),
        Failure::DesktopAppUnavailable
    );
}

/// #142: op's own words stay with a cataloged sign-in failure, as its evidence.
#[test]
fn op_said_is_kept_as_the_evidence() {
    let e = Failure::NotSignedIn.error_said(
        "signing in",
        Some("ABCDEF"),
        "login",
        &["no active session found for account ABCDEF".into()],
        Some(1),
    );
    let said = e.cause().and_then(|(_, up)| up).map(|u| u.said.clone());
    assert_eq!(
        said,
        Some(vec![
            "no active session found for account ABCDEF".to_string()
        ])
    );
}

#[test]
fn an_unreachable_provider_is_safe_to_rerun() {
    let e = Failure::ProviderUnavailable.error("signing in", None, "login");
    assert_eq!(e.exit_code(), 9);
}
