//! `opv access` (#96): who can read each environment's vault, end to end on the stateful
//! fake `op`. People are counted, never named.

use super::*;
use crate::adapters::fake_op::FakeOp;
use serde_json::json;

const DEV: &str = "vdev0000000000000000000001";
const PROD: &str = "vshr0000000000000000000002";

fn fleet() -> crate::domain::Fleet {
    crate::config::parse(&format!(
        "[environments.dev]\nboundaries.app = {{ vault_id = \"{DEV}\", item_id = \"i1\" }}\n\
         [environments.prod]\nboundaries.app = {{ vault_id = \"{PROD}\", item_id = \"i2\" }}\n\
         [environments.prod.targets.app]\nfly.app = \"myapp\"\nfly.secret_name = \"{{KEY}}\"\n\
         state_vault_id = \"sprod\"\n\
         [products.app.keys.A]\nkind = \"secret\"\nenvironments = [\"dev\", \"prod\"]\n"
    ))
    .unwrap()
}

fn member() -> serde_json::Value {
    json!({"type": "MEMBER", "state": "ACTIVE", "name": "Alice Example",
           "email": "alice@example.com", "permissions": ["allow_viewing", "allow_editing", "allow_managing"]})
}

fn service_account(perms: &[&str]) -> serde_json::Value {
    json!({"type": "SERVICE_ACCOUNT", "state": "ACTIVE", "name": "myapp-prod-ci", "permissions": perms})
}

/// `opv access --json` with `prod`'s users (dev: one member).
fn access(prod: Option<serde_json::Value>) -> serde_json::Value {
    let op = FakeOp::default();
    op.vault_users
        .borrow_mut()
        .insert(DEV.into(), json!([member()]));
    if let Some(p) = prod {
        op.vault_users.borrow_mut().insert(PROD.into(), p);
    }
    let mut out = Vec::new();
    run(&fleet(), None, &op, true, &mut out).unwrap();
    serde_json::from_slice(&out).unwrap()
}

fn codes(doc: &serde_json::Value) -> Vec<String> {
    doc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["code"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn a_deployed_environment_without_a_ci_reader_gets_one_finding() {
    assert_eq!(codes(&access(Some(json!([member()])))), ["no_ci_reader"]);
}

#[test]
fn the_finding_carries_the_read_only_create_command() {
    let doc = access(Some(json!([member()])));
    assert!(
        doc["findings"][0]["next"]
            .as_str()
            .unwrap()
            .contains(&format!("--vault {PROD}:read_items"))
    );
}

#[test]
fn a_read_only_service_account_satisfies_prod() {
    assert!(
        codes(&access(Some(json!([
            member(),
            service_account(&["allow_viewing"])
        ]))))
        .is_empty()
    );
}

#[test]
fn a_service_account_that_can_write_is_flagged() {
    assert!(
        codes(&access(Some(json!([service_account(&[
            "allow_viewing",
            "allow_editing"
        ])]))))
        .contains(&"ci_reader_can_write".to_string())
    );
}

#[test]
fn a_vault_you_cannot_manage_is_not_visible() {
    assert_eq!(codes(&access(None)), ["access_not_visible"]);
}

#[test]
fn people_are_counted() {
    assert_eq!(
        access(Some(json!([member()])))["environments"][1]["people"],
        1
    );
}

#[test]
fn no_person_is_ever_named() {
    let doc = access(Some(json!([member(), service_account(&["allow_viewing"])]))).to_string();
    assert!(!doc.contains("Alice") && !doc.contains("alice@example.com"));
}

#[test]
fn the_text_names_the_service_account_and_its_access() {
    let op = FakeOp::default();
    op.vault_users
        .borrow_mut()
        .insert(DEV.into(), json!([member()]));
    op.vault_users
        .borrow_mut()
        .insert(PROD.into(), json!([service_account(&["allow_viewing"])]));
    let mut out = Vec::new();
    run(&fleet(), Some("prod"), &op, false, &mut out).unwrap();
    assert!(
        String::from_utf8(out)
            .unwrap()
            .contains("myapp-prod-ci (read-only)")
    );
}
