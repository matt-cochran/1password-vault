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

#[test]
fn an_unasked_account_points_at_a_one_off_login() {
    let (res, _) = locate(vec![
        Output::failure(1),
        Output::failure(1),
        Output::failure(1),
        Output::success("{}"),
    ]);
    assert_eq!(
        res.unwrap_err().next_step(),
        Some(format!("opv login --account {A} --no-record -- opv vault locate vaultzu64").as_str())
    );
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
