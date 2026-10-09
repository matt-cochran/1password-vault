//! Per-environment account and deploy credentials (FR-40, SR-1, SR-3).

use super::*;
use crate::app::status;
use crate::app::testutil::*;
use crate::config;
use crate::host::FakeEnv;
use crate::runner::fake::FakeRunner;

const ACCOUNT: &str = "work.1password.com";
const TOKEN: &str = "fo1_FIXTUREVALUE_deploy_token";

/// The fixture with prod in `ACCOUNT`, signing in to Fly with `op://deploy-prd/fly`.
fn fleet_with_credentials() -> Fleet {
    let text = std::fs::read_to_string("tests/fixtures/secrets.toml").unwrap();
    config::parse(&text.replacen(
        "item_id = \"iprd\"\n",
        &format!(
            "item_id = \"iprd\"\naccount = \"{ACCOUNT}\"\ndeploy_credentials = \
             \"op://deploy-prd/fly\"\n"
        ),
        1,
    ))
    .unwrap()
}

fn linux() -> Host {
    Host::from_env(&FakeEnv::new("linux").shell("/bin/bash"))
}

fn deploy_item() -> crate::runner::Output {
    item(&[secret("", "FLY_API_TOKEN", TOKEN)])
}

/// `status prod` through the signed-in runner: the deploy item, the item, Fly's list.
fn status_signed_in() -> (FakeRunner, String) {
    let fl = fleet_with_credentials();
    let r = FakeRunner::new([deploy_item(), complete_item(), fly_empty()]);
    let mut out = Vec::new();
    {
        let env_runner = open_on(&fl, "prod", &r, Reach::Target, &linux).unwrap();
        let _ = status::run(&fl, "prod", &env_runner, &mut out);
    }
    (r, text_of(&out))
}

fn env_of<'c>(c: &'c crate::runner::fake::Call, name: &str) -> Option<&'c str> {
    c.env
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

#[test]
fn account_is_passed_on_every_op_call() {
    let (r, _) = status_signed_in();
    let calls = r.calls.borrow();
    assert!(
        calls
            .iter()
            .filter(|c| c.program == "op")
            .all(|c| env_of(c, "OP_ACCOUNT") == Some(ACCOUNT))
    );
}

#[test]
fn account_is_not_added_under_a_service_account() {
    let fl = fleet_with_credentials();
    let r = FakeRunner::new([complete_item()]);
    let ci = Host::from_env(&FakeEnv::new("linux").var("OP_SERVICE_ACCOUNT_TOKEN"));
    let env_runner = open_on(&fl, "prod", &r, Reach::Store, &|| ci).unwrap();
    crate::adapters::onepassword::read_item(&env_runner, fl.environment("prod").unwrap()).unwrap();
    assert_eq!(env_of(&r.calls.borrow()[0], "OP_ACCOUNT"), None);
}

#[test]
fn deploy_credentials_are_read_by_reference() {
    let (r, _) = status_signed_in();
    assert_eq!(
        r.calls.borrow()[0].args,
        [
            "item",
            "get",
            "fly",
            "--vault",
            "deploy-prd",
            "--format",
            "json"
        ]
    );
}

#[test]
fn store_only_commands_never_read_deploy_credentials() {
    let fl = fleet_with_credentials();
    let r = FakeRunner::new([]);
    let _ = open_on(&fl, "prod", &r, Reach::Store, &linux).unwrap();
    assert!(r.calls.borrow().is_empty());
}

#[test]
fn fly_token_is_in_the_env_of_every_flyctl_call() {
    let (r, _) = status_signed_in();
    let calls = r.calls.borrow();
    let fly: Vec<_> = calls.iter().filter(|c| c.program == "flyctl").collect();
    assert!(
        !fly.is_empty()
            && fly
                .iter()
                .all(|c| env_of(c, "FLY_API_TOKEN") == Some(TOKEN))
    );
}

#[test]
fn fly_token_never_reaches_argv() {
    let (r, _) = status_signed_in();
    assert!(!r.argv_contains(TOKEN));
}

#[test]
fn fly_token_never_reaches_op_calls() {
    let (r, _) = status_signed_in();
    let calls = r.calls.borrow();
    assert!(
        calls
            .iter()
            .filter(|c| c.program != "flyctl")
            .all(|c| c.env.iter().all(|(_, v)| v != TOKEN))
    );
}

#[test]
fn marker_values_never_reach_output() {
    let (_, out) = status_signed_in();
    assert_no_values(&out);
}

#[test]
fn missing_token_field_names_the_field_not_a_value() {
    let fl = fleet_with_credentials();
    let r = FakeRunner::new([item(&[secret("", "OTHER", TOKEN)])]);
    let e = match open_on(&fl, "prod", &r, Reach::Target, &linux) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("a missing field must fail"),
    };
    assert!(
        e.contains("field FLY_API_TOKEN is missing") && !e.contains(MARKER),
        "{e}"
    );
}

#[test]
fn token_of_the_wrong_type_is_refused() {
    let fl = fleet_with_credentials();
    let r = FakeRunner::new([item(&[text("", "FLY_API_TOKEN", TOKEN)])]);
    let e = match open_on(&fl, "prod", &r, Reach::Target, &linux) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("a text token must fail"),
    };
    assert!(e.contains("must be a Password (concealed) field"), "{e}");
}
