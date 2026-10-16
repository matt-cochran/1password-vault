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
    let text = text.replacen(
        "[environments.prod]\n",
        &format!("[environments.prod]\naccount = \"{ACCOUNT}\"\n"),
        1,
    );
    config::parse(&text.replacen(
        "state_vault_id = \"sprd\"\n",
        "state_vault_id = \"sprd\"\ndeploy_credentials = \"op://deploy-prd/fly\"\n",
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
    let prod = fl.environment("prod").unwrap();
    crate::adapters::onepassword::read_item(
        &env_runner,
        prod,
        prod.boundaries.values().next().unwrap(),
    )
    .unwrap();
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
    assert!(e.contains("FLY_API_TOKEN") && !e.contains(MARKER), "{e}");
}

#[test]
fn token_of_the_wrong_type_is_refused() {
    let fl = fleet_with_credentials();
    let r = FakeRunner::new([item(&[text("", "FLY_API_TOKEN", TOKEN)])]);
    let e = match open_on(&fl, "prod", &r, Reach::Target, &linux) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("a text token must fail"),
    };
    // R37, I6: a field of another type is named with the type it must be.
    assert!(e.contains("is not a concealed (password) field"), "{e}");
}

/// A Kubernetes runtime keeping its secrets in a Key Vault (`secrets_in`) signs `az` in
/// with the deploy credentials: `az` writes the secrets, kubectl uses the kubeconfig.
#[test]
fn key_vault_behind_kubernetes_signs_in_to_azure() {
    let fl = config::parse(
        r#"
[stores.kv]
azure_key_vault = "kv-opv-fixture"
subscription = "00000000-0000-0000-0000-000000000000"

[environments.dev]
boundaries.app = { vault_id = "vdev", item_id = "idev" }
[environments.dev.targets.app]
state_vault_id = "sdev"
deploy_credentials = "op://deploy/azure"
[environments.dev.targets.app.kubernetes]
context = "kind-opv"
namespace = "opv"
deployment = "api"
env_name = "{KEY}"
secrets_in = "kv"

[products.app.keys.API_KEY]
kind = "secret"
environments = ["dev"]
"#,
    )
    .unwrap();
    let target = fl
        .environment("dev")
        .unwrap()
        .targets
        .values()
        .next()
        .unwrap()
        .config
        .as_ref();
    assert_eq!(crate::provider::deploy_provider(target).section(), "azure");
}

/// Signed out of 1Password, the deploy-credential read (the first call of `status prod`)
/// is diagnosed at once: the missing session, whose Do is the sign-in (FR-40, UX1).
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
    assert_eq!(
        e.do_text().as_deref(),
        Some("sign in to 1Password"),
        "{e:?}"
    );
}

/// `doctor --env` keeps the failed deploy read's scrubbed stderr with the error, as its
/// evidence (NR-31, UX1, design §7.3).
#[test]
fn doctor_deploy_failure_keeps_the_excerpt_beside_the_error() {
    let e = doctor_signed_out_deploy_failure();
    assert_eq!(
        e.cause().and_then(|(_, up)| up).map(|u| u.said.clone()),
        Some(vec!["[ERROR] not signed in".to_string()]),
    );
}

/// M2: the excerpt is never part of the error's text, so no JSON document carries it.
#[test]
fn doctor_deploy_failure_text_has_no_excerpt() {
    let e = doctor_signed_out_deploy_failure();
    assert!(!e.text().contains("said:"), "{e:?}");
}

/// The excerpt never replaces the sign-in step, which stays the error's `Do:` (A3).
#[test]
fn doctor_deploy_failure_keeps_opv_login_as_its_step() {
    let e = doctor_signed_out_deploy_failure();
    assert_eq!(
        e.do_text().as_deref(),
        Some("sign in to 1Password"),
        "{e:?}"
    );
}

/// What `doctor --env` gets from a failed per-target deploy sign-in: the error, with the
/// failed call's scrubbed reply as its evidence (NR-31, M2).
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
    crate::host::with_test_host(tty, || {
        open_targeted(&fl, "prod", None, &r, Reach::Target).err()
    })
    .expect("signed out")
}

// ---- FR-41 plan ids on deploy-credential runs and manifest configurations ----

/// The plan id `opv plan prod --json` reports through `r`.
fn plan_id_of(fl: &Fleet, r: &dyn CommandRunner) -> String {
    let mut out = Vec::new();
    crate::app::sync::plan_with(fl, "prod", r, &mut out, true).unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&out).unwrap();
    doc["plan_id"].as_str().unwrap().to_string()
}

#[test]
fn plan_id_through_deploy_credentials_matches_a_plain_run() {
    let fl = fleet_with_credentials();
    let signed = FakeRunner::new([deploy_item(), complete_item(), fly_empty()]);
    let env_runner = open_on(&fl, "prod", &signed, Reach::Target, &linux).unwrap();
    let through = plan_id_of(&fl, &env_runner);
    let plain = FakeRunner::new([complete_item(), fly_empty()]);
    assert_eq!(through, plan_id_of(&fl, &plain));
}

#[test]
fn plan_id_of_a_manifest_configuration_matches_the_same_file() {
    let file = fleet_with_credentials();
    let mut manifest = file.clone();
    manifest.origin = crate::domain::Origin::Manifest;
    let a = plan_id_of(&file, &FakeRunner::new([complete_item(), fly_empty()]));
    let b = plan_id_of(&manifest, &FakeRunner::new([complete_item(), fly_empty()]));
    assert_eq!(a, b);
}

#[test]
fn plan_of_a_manifest_configuration_names_the_manifest_not_the_file() {
    let mut fl = fleet_with_credentials();
    fl.origin = crate::domain::Origin::Manifest;
    let mut out = Vec::new();
    let r = FakeRunner::new([complete_item(), fly_empty()]);
    crate::app::sync::plan_with(&fl, "prod", &r, &mut out, false).unwrap();
    assert!(text_of(&out).contains("the target or the manifest changed"));
}

// 06.30: a rejected deploy credential names its item by the full reference, vault included.
#[test]
fn a_rejected_deploy_credential_names_the_vault_of_its_item() {
    use crate::cause::{
        CallId, Cause, CredentialProblem, CredentialRef, EnvName, ExitClass, ItemId, Observed,
        Principal, System, TargetName, VaultId,
    };
    let principal = Principal::DeployCredentials {
        vault: crate::cause::VaultId::new("vlt-deploy"),
        item: ItemId::new("fly"),
        env: EnvName::new("prod"),
        target: TargetName::new("web"),
    };
    let seen = Observed::from_failed_call(
        CallId {
            system: System::Fly,
            program: "flyctl".into(),
            words: vec!["auth".into(), "whoami".into()],
        },
        ExitClass::Code { code: 1 },
        principal,
    );
    let rejected: Error = Cause::CredentialRejected {
        system: System::Fly,
        credential: CredentialRef::DeployCredentials {
            vault: VaultId::new(""),
            item: ItemId::new("fly"),
            env: EnvName::new("prod"),
            target: TargetName::new("web"),
        },
        problem: CredentialProblem::Rejected { needs: Vec::new() },
        seen,
    }
    .into();
    let reference = ItemRef {
        vault: "deploy-prd".into(),
        item: "fly".into(),
    };
    assert!(matches!(
        deploy_failed(rejected, &reference).cause(),
        Some((Cause::CredentialRejected {
            credential: CredentialRef::DeployCredentials { vault, .. },
            ..
        }, _)) if vault.as_str() == "deploy-prd"
    ));
}
