//! The federated CI identity setup (#297) against hand-written `az` replies in the Azure
//! CLI's documented shapes; the live-spike recordings replace them when they exist.

use super::{AUDIENCE, GITHUB_ISSUER, app_name, credential_name, mint};
use crate::adapters::azure::{AzureTarget, ConfigRoute};
use crate::runner::Output;
use crate::runner::fake::FakeRunner;
use serde_json::{Value, json};

const TENANT: &str = "11111111-1111-1111-1111-111111111111";
const CLIENT: &str = "22222222-2222-2222-2222-222222222222";
const SUB: &str = "33333333-3333-3333-3333-333333333333";
const OID: &str = "44444444-4444-4444-4444-444444444441";
const SUBJECT: &str = "repo:example-org/example-repo:environment:prod";
const VAULT_ID: &str = "/subscriptions/33333333-3333-3333-3333-333333333333/resourceGroups/opv-fixture-rg/providers/Microsoft.KeyVault/vaults/kv-opv-fixture";

fn target() -> AzureTarget {
    AzureTarget {
        subscription: SUB.into(),
        key_vault: "kv-opv-fixture".into(),
        resource_group: "opv-fixture-rg".into(),
        container_app: "opv-fixture-app".into(),
        container: None,
        identity: "system".into(),
        env_name_template: "FLEET__{PRODUCT}__{KEY}".into(),
        config: ConfigRoute::Env,
        companion_jobs: Vec::new(),
        federated: None,
        vault_uri: Default::default(),
    }
}

fn reply(v: Value) -> Output {
    Output::success(v.to_string().into_bytes())
}

/// The person's own sign-in (`account show`) of type `kind`.
fn account(kind: &str) -> Output {
    reply(json!({"id": SUB, "tenantId": TENANT, "user": {"name": "me@example.com", "type": kind}}))
}

/// What exists before the run: an app, a service principal, a trusted subject.
#[derive(Default)]
struct World {
    app: bool,
    principal: bool,
    trusted: bool,
    access_policy_vault: bool,
}

/// The replies, in call order, of one run against `w`.
fn replies(w: &World) -> Vec<Output> {
    let mut out = vec![account("user"), Output::success(Vec::new())];
    if w.app {
        out.push(reply(json!([{"appId": CLIENT, "displayName": "x"}])));
    } else {
        out.push(reply(json!([])));
        out.push(reply(json!({"appId": CLIENT, "id": "app-object-id"})));
    }
    if w.principal {
        out.push(reply(json!([{"id": OID, "appId": CLIENT}])));
    } else {
        out.push(reply(json!([])));
        out.push(reply(json!({"id": OID, "appId": CLIENT})));
    }
    out.push(reply(json!({
        "id": VAULT_ID,
        "properties": {"enableRbacAuthorization": !w.access_policy_vault}
    })));
    if w.access_policy_vault {
        out.push(Output::success(Vec::new()));
    } else {
        out.push(reply(json!([])));
        out.push(reply(json!({})));
    }
    out.push(reply(json!([])));
    out.push(reply(json!({})));
    if w.trusted {
        out.push(reply(
            json!([{"subject": SUBJECT, "issuer": GITHUB_ISSUER}]),
        ));
    } else {
        out.push(reply(json!([])));
        out.push(reply(json!({})));
    }
    out
}

fn run(
    w: &World,
) -> (
    Result<crate::domain::FederatedIdentity, crate::error::Error>,
    FakeRunner,
) {
    let r = FakeRunner::new(replies(w));
    let got = mint(&target(), SUBJECT, &r);
    (got, r)
}

/// The argv of every call the run made, joined by spaces.
fn calls(r: &FakeRunner) -> Vec<String> {
    r.calls.borrow().iter().map(|c| c.args.join(" ")).collect()
}

fn made(r: &FakeRunner, words: &str) -> bool {
    calls(r).iter().any(|c| c.starts_with(words))
}

#[test]
fn a_new_identity_returns_the_created_app_as_its_client() {
    let (got, _) = run(&World::default());
    assert_eq!(got.unwrap().client_id, CLIENT);
}

#[test]
fn the_tenant_is_the_persons_own_sign_in() {
    let (got, _) = run(&World::default());
    assert_eq!(got.unwrap().tenant_id, TENANT);
}

#[test]
fn the_subscription_is_the_targets() {
    let (got, _) = run(&World::default());
    assert_eq!(got.unwrap().subscription_id, SUB);
}

#[test]
fn the_new_trust_names_exactly_the_subject() {
    let (_, r) = run(&World::default());
    let create = r
        .calls
        .borrow()
        .iter()
        .find(|c| {
            c.args
                .join(" ")
                .starts_with("ad app federated-credential create")
        })
        .map(|c| c.args.clone())
        .unwrap();
    let at = create.iter().position(|a| a == "--parameters").unwrap();
    let p: Value = serde_json::from_str(&create[at + 1]).unwrap();
    assert_eq!(
        p,
        json!({"name": credential_name(SUBJECT), "issuer": GITHUB_ISSUER,
               "subject": SUBJECT, "audiences": [AUDIENCE]})
    );
}

#[test]
fn an_existing_app_is_reused() {
    let (_, r) = run(&World {
        app: true,
        ..World::default()
    });
    assert!(!made(&r, "ad app create"));
}

#[test]
fn an_existing_service_principal_is_reused() {
    let (_, r) = run(&World {
        app: true,
        principal: true,
        ..World::default()
    });
    assert!(!made(&r, "ad sp create"));
}

#[test]
fn a_subject_already_trusted_is_not_created_again() {
    let (_, r) = run(&World {
        app: true,
        principal: true,
        trusted: true,
        ..World::default()
    });
    assert!(!made(&r, "ad app federated-credential create"));
}

#[test]
fn a_rerun_against_what_the_first_run_made_succeeds() {
    let (got, _) = run(&World {
        app: true,
        principal: true,
        trusted: true,
        ..World::default()
    });
    assert!(got.is_ok());
}

#[test]
fn an_rbac_vault_grants_key_vault_secrets_officer_at_the_vault() {
    let (_, r) = run(&World::default());
    assert!(
        calls(&r)
            .iter()
            .any(|c| c.starts_with("role assignment create")
                && c.contains("--role Key Vault Secrets Officer")
                && c.contains(&format!("--scope {VAULT_ID}")))
    );
}

#[test]
fn the_container_app_gets_contributor_at_its_own_scope() {
    let (_, r) = run(&World::default());
    let app = format!(
        "--scope /subscriptions/{SUB}/resourceGroups/opv-fixture-rg/providers/Microsoft.App/containerApps/opv-fixture-app"
    );
    assert!(
        calls(&r)
            .iter()
            .any(|c| c.starts_with("role assignment create")
                && c.contains("--role Contributor")
                && c.contains(&app))
    );
}

#[test]
fn an_access_policy_vault_sets_the_principals_secret_permissions() {
    let (_, r) = run(&World {
        access_policy_vault: true,
        ..World::default()
    });
    assert!(made(&r, "keyvault set-policy -n kv-opv-fixture"));
}

#[test]
fn no_call_creates_a_client_secret() {
    let (_, r) = run(&World::default());
    assert!(!calls(&r).iter().any(|c| c.contains("credential reset")
        || c.contains("--create-password")
        || c.contains("create-for-rbac")));
}

#[test]
fn a_service_principal_sign_in_is_refused() {
    let r = FakeRunner::new([account("servicePrincipal")]);
    let e = mint(&target(), SUBJECT, &r).unwrap_err();
    assert_eq!(e.code_str(), "target_not_signed_in");
}

#[test]
fn a_service_principal_sign_in_creates_nothing() {
    let r = FakeRunner::new([account("servicePrincipal")]);
    let _ = mint(&target(), SUBJECT, &r);
    assert_eq!(calls(&r).len(), 1);
}

#[test]
fn two_apps_with_the_identitys_name_are_refused() {
    let r = FakeRunner::new([
        account("user"),
        Output::success(Vec::new()),
        reply(json!([{"appId": CLIENT}, {"appId": "55555555-5555-5555-5555-555555555555"}])),
    ]);
    let e = mint(&target(), SUBJECT, &r).unwrap_err();
    assert_eq!(e.code_str(), "usage");
}

#[test]
fn the_app_name_carries_the_container_app_and_the_subject() {
    assert_eq!(
        app_name(&target(), SUBJECT),
        "opv-opv-fixture-app-example-org-example-repo-environment-prod"
    );
}

#[test]
fn the_credential_name_uses_only_allowed_characters() {
    assert!(
        credential_name(SUBJECT)
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
    );
}
