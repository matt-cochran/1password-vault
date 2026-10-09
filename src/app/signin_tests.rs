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

/// Owner ruling: `doctor --env` gets the failed deploy sign-in back instead of stopping.
#[test]
fn doctor_gets_a_failed_deploy_sign_in_back() {
    let fl = fleet_with_credentials();
    let r = FakeRunner::new([item(&[secret("", "OTHER", TOKEN)])]);
    let (_, failed) = open_for_doctor_on(&fl, "prod", &r, &linux);
    assert!(failed.is_some_and(|e| e.to_string().contains("field FLY_API_TOKEN is missing")));
}

/// After a failed deploy sign-in, doctor's `op` calls still carry the account.
#[test]
fn doctor_runner_keeps_the_account_after_a_failed_deploy_sign_in() {
    let fl = fleet_with_credentials();
    let r = FakeRunner::new([item(&[secret("", "OTHER", TOKEN)]), complete_item()]);
    let (runner, _) = open_for_doctor_on(&fl, "prod", &r, &linux);
    crate::adapters::onepassword::read_item(&runner, fl.environment("prod").unwrap()).unwrap();
    assert_eq!(env_of(&r.calls.borrow()[1], "OP_ACCOUNT"), Some(ACCOUNT));
}

/// A Kubernetes runtime keeping its secrets in a Key Vault (`secrets_in`) signs `az` in
/// with the deploy credentials: `az` writes the secrets, kubectl uses the kubeconfig.
#[test]
fn key_vault_behind_kubernetes_signs_in_to_azure() {
    let fl = config::parse(
        r#"
[profile]
kind = "simple"
[stores.kv]
azure_key_vault = "kv-opv-fixture"
subscription = "00000000-0000-0000-0000-000000000000"
[environments.dev]
vault_id = "vdev"
item_id = "idev"
deploy_credentials = "op://deploy/azure"
[environments.dev.kubernetes]
context = "kind-opv"
namespace = "opv"
deployment = "api"
secrets_in = "kv"
[keys.API_KEY]
kind = "secret"
environments = ["dev"]
"#,
    )
    .unwrap();
    let target = fl.environment("dev").unwrap().target().unwrap();
    assert_eq!(crate::provider::deploy_provider(target).section(), "azure");
}

/// Signed out of 1Password, the deploy-credential read (the first call of `status prod`)
/// is diagnosed at once and names the environment in its sign-in step, which is the
/// error's `Next:` (FR-40, UX1).
#[test]
fn signed_out_deploy_read_names_opv_login_for_the_environment() {
    let fl = fleet_with_credentials();
    let r = FakeRunner::new([
        crate::runner::Output::failure(1),
        crate::runner::Output::failure(1),
        crate::runner::Output::success(br#"[{"url":"x"}]"#.to_vec()),
    ]);
    let tty = Host::from_env(&FakeEnv::new("linux").shell("/bin/bash").tty());
    let res = crate::host::with_test_host(tty, || {
        open_on(&fl, "prod", &r, Reach::Target, &linux).map(|_| ())
    });
    let e = res.expect_err("signed out");
    assert_eq!(e.default_next("-"), "sign in: opv login prod", "{e:?}");
}

/// `doctor --env` keeps the failed deploy read's scrubbed stderr in `error::report`'s
/// order: the error line, then `  op said: …`, then the rest (NR-31, UX1).
#[test]
fn doctor_deploy_failure_puts_the_excerpt_after_the_error_line() {
    let e = doctor_signed_out_deploy_failure();
    assert_eq!(
        e.text().lines().nth(1),
        Some("  op said: [ERROR] not signed in"),
        "{e:?}"
    );
}

/// The excerpt never replaces the sign-in step, which stays the error's `Next:`.
#[test]
fn doctor_deploy_failure_keeps_opv_login_as_its_step() {
    let e = doctor_signed_out_deploy_failure();
    assert_eq!(e.next_step(), Some("sign in: opv login prod"), "{e:?}");
}

fn doctor_signed_out_deploy_failure() -> Error {
    let fl = fleet_with_credentials();
    let r = FakeRunner::new([]);
    r.push_with_stderr(crate::runner::Output::failure(1), "[ERROR] not signed in");
    r.responses
        .borrow_mut()
        .push_back(Ok(crate::runner::Output::failure(1)));
    r.responses
        .borrow_mut()
        .push_back(Ok(crate::runner::Output::success(
            br#"[{"url":"x"}]"#.to_vec(),
        )));
    let tty = Host::from_env(&FakeEnv::new("linux").shell("/bin/bash").tty());
    crate::host::with_test_host(tty, || open_for_doctor_on(&fl, "prod", &r, &linux).1)
        .expect("signed out")
}
