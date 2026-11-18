//! `ready`'s per-environment `identity` (#338, design `agent-identity.md` §5, §7.4; FR-69):
//! one scenario per test.

use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::adapters::credential_store::{AgentCredentialSource, AgentKey, FakeCredentialSource};
use crate::adapters::fake_op::FakeOp;
use crate::cause::{AccountId, AgentStore, UsageProblem};
use crate::domain::agent_identity::AgentRecord;
use crate::domain::secret::SecretValue;
use crate::host::{FakeEnv, Host};

const NOW: &str = "2026-11-17T09:00:00Z";
/// A token-shaped canary: it must never reach `ready`'s JSON.
const TOKEN: &str = "ops_CANARYTOKEN-FIXTUREVALUE-eyJzaWduSW5BZGRyZXNzIjoi";
const DEV_VAULT: &str = "vdev0000000000000000000001";
const PROD_VAULT: &str = "vprd0000000000000000000001";

fn name(env: &str) -> String {
    format!("shop-{env}-agent-laptop")
}

fn key(env: &str) -> AgentKey {
    AgentKey::new(
        AccountId::new("AFAKEOP0000000000000000001"),
        "shop",
        EnvName::new(env),
    )
    .unwrap()
}

/// A store holding the agent's token for `dev` only.
fn dev_store() -> Arc<FakeCredentialSource> {
    let source = FakeCredentialSource::new(AgentStore::SecretService);
    source
        .store(&key("dev"), &SecretValue::new(TOKEN.to_string()))
        .unwrap();
    Arc::new(source)
}

fn host(vars: &[(&str, &str)]) -> Host {
    let env = vars
        .iter()
        .fold(FakeEnv::new("linux").shell("/bin/bash"), |e, (k, v)| {
            e.var_val(k, v)
        });
    Host::from_env(&env)
}

fn agent_host() -> Host {
    host(&[("OPV_IDENTITY", "agent")])
}

/// The probe of a process that acts for `dev`'s agent identity (expiring on `expires_on`):
/// rule 3 reads `dev`'s token from the store, as the resolver does; any other environment is
/// the resolver's usage stop (one environment per run), and the index records `dev` only.
fn probe(host: Host, expires_on: &'static str) -> IdentityProbe<'static> {
    let store = dev_store();
    let for_resolve = store.clone();
    IdentityProbe {
        host,
        seams: who::Seams {
            resolve: Box::new(move |_, env| {
                if env != "dev" {
                    return Err(Cause::Usage {
                        problem: UsageProblem::NeedsFlag {
                            flag: "OPV_IDENTITY=agent".into(),
                            needs: "one environment per run (this run already acts for dev)".into(),
                        },
                    }
                    .into());
                }
                for_resolve.resolve(&key(env))?;
                Ok(name(env))
            }),
            source: Box::new(move || store.clone() as Arc<dyn AgentCredentialSource>),
            record: Box::new(move |name, env| {
                Some(AgentRecord {
                    account_name: name.into(),
                    environment: env.into(),
                    machine: "laptop".into(),
                    store: "secret_service".into(),
                    created_on: "2026-08-19".into(),
                    expires_on: expires_on.into(),
                    rotation_successor: None,
                })
            }),
            today: Box::new(|| "2026-11-17".to_string()),
            bound: Duration::from_secs(5),
        },
        acting_for: Box::new(|| Some("dev".to_string())),
        installed: Box::new(|_, env| env == "dev"),
    }
}

/// `dev` alone, or `dev` and `prod`, each run-only with one `app/DATABASE_URL` set.
fn world(envs: &[&str]) -> (FakeOp, crate::domain::Fleet) {
    let op = FakeOp::default();
    op.vaults
        .borrow_mut()
        .push((PROD_VAULT.into(), "myapp-prod".into()));
    let fields = serde_json::json!({
        "title": "t", "category": "SECURE_NOTE",
        "sections": [{"id": "app", "label": "app"}],
        "fields": [{"id": "f1", "type": "CONCEALED",
                    "section": {"id": "app", "label": "app"},
                    "label": "DATABASE_URL", "value": "postgres://db.example/app"}]
    });
    let mut text = String::new();
    for env in envs {
        let vault = if *env == "dev" { DEV_VAULT } else { PROD_VAULT };
        let id = op.insert(vault, fields.clone());
        text.push_str(&format!(
            "[environments.{env}]\nboundaries.app = {{ vault_id = \"{vault}\", item_id = \"{id}\" }}\n"
        ));
    }
    let list: Vec<String> = envs.iter().map(|e| format!("\"{e}\"")).collect();
    text.push_str(&format!(
        "[products.app.keys.DATABASE_URL]\nkind = \"secret\"\nenvironments = [{}]\n",
        list.join(", ")
    ));
    (op, crate::config::parse(&text).unwrap())
}

/// `opv ready --json` (with `gate`) under `probe`: the outcome and the document.
fn ready(
    envs: &[&str],
    gate: bool,
    probe: &IdentityProbe<'_>,
) -> (Result<(), Error>, serde_json::Value, FakeOp) {
    let (op, fleet) = world(envs);
    let mut out = Vec::new();
    let res = run_probed(
        &fleet, None, None, &op, true, None, gate, NOW, probe, &mut out,
    );
    let doc = serde_json::from_slice(&out).unwrap_or(serde_json::Value::Null);
    (res, doc, op)
}

fn identity_of<'d>(doc: &'d serde_json::Value, env: &str) -> &'d serde_json::Value {
    doc["identity"]
        .as_array()
        .and_then(|ids| ids.iter().find(|i| i["environment"] == env))
        .unwrap_or(&serde_json::Value::Null)
}

fn finding<'d>(doc: &'d serde_json::Value, code: &str) -> &'d serde_json::Value {
    doc["findings"]
        .as_array()
        .and_then(|fs| fs.iter().find(|f| f["code"] == code))
        .unwrap_or(&serde_json::Value::Null)
}

// --- the object per identity (§7.4) --------------------------------------------------------

#[test]
fn ready_json_carries_the_agent_identity_object_of_its_environment() {
    let (_, doc, _) = ready(&["dev"], false, &probe(agent_host(), "2027-02-15"));
    assert_eq!(
        identity_of(&doc, "dev"),
        &serde_json::json!({
            "kind": "agent",
            "name": "shop-dev-agent-laptop",
            "environment": "dev",
            "source": "secret_service",
            "read_only": true,
            "expires_on": "2027-02-15",
            "days_left": 90,
            "reach": {"readable": 1, "expected": 1},
            "rate_limit": null,
            "store": {"persistence": "durable", "self_check": "not_run", "self_check_ms": null},
            "state": "agent",
        })
    );
}

#[test]
fn ready_json_carries_the_person_identity_object() {
    let (_, doc, _) = ready(&["dev"], false, &probe(host(&[]), "2027-02-15"));
    assert_eq!(
        identity_of(&doc, "dev"),
        &serde_json::json!({
            "kind": "person",
            "name": null,
            "environment": "dev",
            "source": null,
            "read_only": false,
            "expires_on": null,
            "days_left": null,
            "reach": null,
            "rate_limit": null,
            "store": null,
            "state": "person",
        })
    );
}

#[test]
fn ready_json_carries_the_service_account_identity_object() {
    let sa = host(&[("OP_SERVICE_ACCOUNT_TOKEN", TOKEN)]);
    let (_, doc, _) = ready(&["dev"], false, &probe(sa, "2027-02-15"));
    assert_eq!(
        (
            &identity_of(&doc, "dev")["kind"],
            &identity_of(&doc, "dev")["source"],
            &identity_of(&doc, "dev")["state"],
        ),
        (
            &serde_json::json!("service_account"),
            &serde_json::json!("OP_SERVICE_ACCOUNT_TOKEN"),
            &serde_json::json!("service_account"),
        )
    );
}

#[test]
fn ready_json_carries_one_identity_object_per_environment() {
    let (_, doc, _) = ready(&["dev", "prod"], false, &probe(host(&[]), "2027-02-15"));
    let envs: Vec<&str> = doc["identity"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|i| i["environment"].as_str())
        .collect();
    assert_eq!(envs, ["dev", "prod"]);
}

// --- FR-69 expiry: advisory -------------------------------------------------------------

#[test]
fn an_agent_identity_expiring_within_14_days_is_credential_expiring() {
    let (_, doc, _) = ready(&["dev"], false, &probe(agent_host(), "2026-11-26"));
    let f = finding(&doc, CREDENTIAL_EXPIRING);
    assert_eq!(
        (&f["scope"]["key"], &f["blocking"], &f["prerequisite"]),
        (
            &serde_json::json!(AGENT_IDENTITY),
            &serde_json::json!(false),
            &serde_json::json!("opv access dev --rotate --agent"),
        )
    );
}

#[test]
fn an_expiring_agent_identity_object_is_agent_expiring() {
    let (_, doc, _) = ready(&["dev"], false, &probe(agent_host(), "2026-11-26"));
    assert_eq!(identity_of(&doc, "dev")["state"], "agent_expiring");
}

#[test]
fn an_expired_agent_identity_is_credential_expired() {
    let (_, doc, _) = ready(&["dev"], false, &probe(agent_host(), "2026-11-10"));
    assert_eq!(finding(&doc, CREDENTIAL_EXPIRED)["blocking"], false);
}

#[test]
fn an_expiring_agent_identity_never_fails_the_gate() {
    let (res, _, _) = ready(&["dev"], true, &probe(agent_host(), "2026-11-26"));
    assert!(res.is_ok(), "{res:?}");
}

// --- several environments under the agent (§5) -----------------------------------------

#[test]
fn an_environment_without_an_agent_identity_does_not_stop_ready() {
    let (res, _, _) = ready(&["dev", "prod"], false, &probe(agent_host(), "2027-02-15"));
    assert!(res.is_ok(), "{res:?}");
}

#[test]
fn an_environment_without_an_agent_identity_is_agent_not_installed() {
    let (_, doc, _) = ready(&["dev", "prod"], false, &probe(agent_host(), "2027-02-15"));
    assert_eq!(identity_of(&doc, "prod")["state"], "agent_not_installed");
}

#[test]
fn an_environment_without_an_agent_identity_has_its_own_finding() {
    let (_, doc, _) = ready(&["dev", "prod"], false, &probe(agent_host(), "2027-02-15"));
    assert_eq!(
        finding(&doc, "agent_identity_not_installed")["scope"]["environment"],
        "prod"
    );
}

#[test]
fn the_other_environments_are_still_read() {
    let (_, doc, _) = ready(&["dev", "prod"], false, &probe(agent_host(), "2027-02-15"));
    let read: Vec<&str> = doc["matrix"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["environment"].as_str())
        .collect();
    assert_eq!(read, ["dev"]);
}

#[test]
fn an_environment_without_an_agent_identity_is_never_read() {
    let (_, _, op) = ready(&["dev", "prod"], true, &probe(agent_host(), "2027-02-15"));
    let reads_prod = op
        .calls
        .borrow()
        .iter()
        .any(|c| c.args.iter().any(|a| a == PROD_VAULT));
    assert!(!reads_prod);
}

// --- value-free (ADR-0001 R1) -----------------------------------------------------------

#[test]
fn ready_json_under_the_agent_never_carries_its_token() {
    let (_, doc, _) = ready(&["dev", "prod"], false, &probe(agent_host(), "2026-11-26"));
    assert!(!doc.to_string().contains(TOKEN));
}
