//! #153: which account holds a vault, never claiming "absent" for an unasked account.

use super::*;
use crate::runner::{Output, fake::FakeRunner};

const A: &str = "AAAA0000000000000000000001";
const B: &str = "BBBB0000000000000000000002";

fn accounts() -> Output {
    Output::success(format!(
        r#"[{{"url":"https://my.1password.com","email":"me@family.example","account_uuid":"{A}","shorthand":"my"}},{{"url":"https://my.1password.com","email":"me@labs.example","account_uuid":"{B}","shorthand":"labs"}}]"#
    ))
}

/// `op account list`, then per account: its `vault get`, and when that fails its whoami.
fn locate(responses: Vec<Output>) -> (Result<(), Error>, serde_json::Value) {
    let mut all = vec![accounts()];
    all.extend(responses);
    let r = FakeRunner::new(all);
    let mut out = Vec::new();
    let res = run(&r, "vaultzu64", true, &mut out);
    (res, serde_json::from_slice(&out).unwrap_or_default())
}

#[test]
fn the_account_holding_the_vault_is_found() {
    let (_, doc) = locate(vec![
        Output::failure(1),
        Output::success("{}"),
        Output::success("{}"),
    ]);
    assert_eq!(doc["accounts"][1]["result"], "found");
}

#[test]
fn a_found_vault_is_success() {
    let (res, _) = locate(vec![
        Output::failure(1),
        Output::success("{}"),
        Output::success("{}"),
    ]);
    assert!(res.is_ok());
}

#[test]
fn a_signed_in_account_without_the_vault_is_not_found() {
    let (_, doc) = locate(vec![
        Output::failure(1),
        Output::success("{}"),
        Output::success("{}"),
    ]);
    assert_eq!(doc["accounts"][0]["result"], "not_found");
}

#[test]
fn a_signed_out_account_is_unknown_not_absent() {
    let (_, doc) = locate(vec![
        Output::failure(1),
        Output::failure(1),
        Output::failure(1),
        Output::success("{}"),
    ]);
    assert_eq!(doc["accounts"][0]["result"], "unknown");
}

/// #157: inventory_incomplete exits 4 (source), as its code says.
#[test]
fn an_incomplete_inventory_exits_as_its_code_says() {
    let (res, _) = locate(vec![
        Output::failure(1),
        Output::failure(1),
        Output::failure(1),
        Output::success("{}"),
    ]);
    let e = res.unwrap_err();
    assert_eq!(e.exit_code(), e.code().exit_code());
}

#[test]
fn an_unasked_account_points_at_a_one_off_login() {
    let (res, _) = locate(vec![
        Output::failure(1),
        Output::failure(1),
        Output::failure(1),
        Output::success("{}"),
    ]);
    let e = res.unwrap_err();
    let inv = crate::cause::Invocation::from_cli(&[
        "opv".to_string(),
        "vault".to_string(),
        "locate".to_string(),
        "vaultzu64".to_string(),
    ]);
    let (cause, _) = e.cause().expect("a catalog cause");
    assert_eq!(
        crate::cause::render::next_text(&cause.step(&inv).1, &inv),
        Some(format!(
            "opv login --account {A} --no-record -- opv vault locate vaultzu64"
        ))
    );
}

/// Audit 04.29: an account that could not be asked is never claimed to be signed out (the
/// check may not have finished).
#[test]
fn an_unasked_account_is_not_claimed_signed_out() {
    let (res, _) = locate(vec![
        Output::failure(1),
        Output::failure(1),
        Output::failure(1),
        Output::success("{}"),
    ]);
    let message = res.unwrap_err().to_string();
    assert!(!message.contains("not signed in"), "{message}");
}

/// Audit 04.13: under a service account or Connect, the credential is asked directly.
#[test]
fn a_vault_the_credential_reads_is_found() {
    let r = FakeRunner::new([Output::success("{}")]);
    assert!(with_credential(&r, "vaultzu64", true, &mut Vec::new()).is_ok());
}

/// Audit 04.13: a vault the credential cannot read is a 1Password diagnosis, never a
/// sign-in or account-add step.
#[test]
fn a_vault_the_credential_cannot_read_never_steps_to_login() {
    let r = FakeRunner::new([Output::failure(1)]);
    let e = with_credential(&r, "vaultzu64", false, &mut Vec::new()).unwrap_err();
    let inv = crate::cause::Invocation::from_cli(&[
        "opv".to_string(),
        "vault".to_string(),
        "locate".to_string(),
        "vaultzu64".to_string(),
    ]);
    let next = e
        .cause()
        .and_then(|(c, _)| crate::cause::render::next_text(&c.step(&inv).1, &inv))
        .unwrap_or_default();
    assert!(!next.starts_with("opv login"), "{next}");
}

#[test]
fn a_vault_in_no_account_is_vault_no_access() {
    let (res, _) = locate(vec![
        Output::failure(1),
        Output::success("{}"),
        Output::failure(1),
        Output::success("{}"),
    ]);
    assert_eq!(res.unwrap_err().code().as_str(), "vault_no_access");
}

#[test]
fn a_value_that_is_not_an_id_is_refused_before_any_call() {
    let r = FakeRunner::default();
    let e = run(&r, "not an id", false, &mut Vec::new()).unwrap_err();
    assert_eq!(e.code().as_str(), "usage");
}
