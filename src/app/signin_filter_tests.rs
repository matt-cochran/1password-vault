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

#[test]
fn an_unregistered_accounts_next_step_adds_that_account() {
    let e = Failure::AccountNotRegistered.error("signing in", Some("owner@example.com"), "login");
    assert_eq!(
        e.next_step(),
        Some("opv login --add --account owner@example.com")
    );
}

#[test]
fn a_known_account_is_named_in_the_retry_step() {
    let e = Failure::NotSignedIn.error("signing in", Some("ABCDEF"), "setup");
    assert_eq!(e.next_step(), Some("opv login --account ABCDEF"));
}

#[test]
fn the_message_names_the_running_command() {
    let e = Failure::NotSignedIn.error("signing in", None, "status");
    assert!(e.mentions("during opv status"), "{e}");
}

#[test]
fn an_unreachable_provider_is_safe_to_rerun() {
    let e = Failure::ProviderUnavailable.error("signing in", None, "login");
    assert_eq!(e.exit_code(), 9);
}
