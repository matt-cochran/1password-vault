//! `opv inventory` behavior: one read per item, schema 3, value-free output, and the
//! unbound boundary's typed error.

use serde_json::{Value, json};

use super::run;
use crate::adapters::fake_op::FakeOp;
use crate::domain::Fleet;

const VAULT: &str = "vdev0000000000000000000001";
const MARK: &str = "S7MARKER-inventory";

/// One dev environment whose product `api` lives in boundary `core`, with two keys: one
/// present (a value only the fake holds) and one absent from the item.
fn world() -> (FakeOp, Fleet, String) {
    let op = FakeOp::default();
    let id = op.insert(
        VAULT,
        json!({
            "title": "api",
            "category": "LOGIN",
            "fields": [{
                "id": "f-openai",
                "section": {"id": "s-api", "label": "api"},
                "label": "OPENAI_API_KEY",
                "type": "CONCEALED",
                "value": MARK
            }]
        }),
    );
    op.vault_users.borrow_mut().insert(VAULT.into(), json!([]));
    let fleet = crate::config::parse(&format!(
        r#"
[environments.dev]
boundaries.core = {{ vault_id = "{VAULT}", item_id = "{id}" }}

[products.api]
boundary = "core"

[products.api.keys.DATABASE_URL]
kind = "config"
environments = ["dev"]

[products.api.keys.OPENAI_API_KEY]
kind = "secret"
environments = ["dev"]
"#
    ))
    .unwrap();
    (op, fleet, id)
}

/// The item its boundary names, read once per item even for two keys.
#[test]
fn two_keys_in_one_item_are_read_once() {
    let (op, fleet, id) = world();
    let mut out = Vec::new();
    run(&fleet, None, None, &op, None, false, &mut out).unwrap();
    assert_eq!(op.count(&["op", "item", "get", &id, "--vault", VAULT]), 1);
}

/// The JSON is the schema-3 envelope.
#[test]
fn the_json_document_is_schema_three() {
    let (op, fleet, _) = world();
    let mut out = Vec::new();
    run(&fleet, None, None, &op, None, true, &mut out).unwrap();
    let doc: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(doc["schema_version"], 3);
}

/// A declared key with no field reads `absent`, never `empty`.
#[test]
fn a_key_without_a_field_is_absent() {
    let (op, fleet, _) = world();
    let mut out = Vec::new();
    run(&fleet, None, None, &op, None, true, &mut out).unwrap();
    let doc: Value = serde_json::from_slice(&out).unwrap();
    let cell = doc["cells"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["key"] == "DATABASE_URL")
        .unwrap();
    assert_eq!(cell["state"]["state"], "absent");
}

/// A present field is classified `set`, so a gatherer that never reads cannot pass.
#[test]
fn a_present_field_is_set() {
    let (op, fleet, _) = world();
    let mut out = Vec::new();
    run(&fleet, None, None, &op, None, true, &mut out).unwrap();
    let doc: Value = serde_json::from_slice(&out).unwrap();
    let cell = doc["cells"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["key"] == "OPENAI_API_KEY")
        .unwrap();
    assert_eq!(cell["state"]["state"], "set");
}

/// The text matrix never carries a value (SR-1).
#[test]
fn the_text_matrix_carries_no_value() {
    let (op, fleet, _) = world();
    let mut out = Vec::new();
    run(&fleet, None, None, &op, None, false, &mut out).unwrap();
    assert!(!String::from_utf8(out).unwrap().contains(MARK));
}

/// The JSON document never carries a value either.
#[test]
fn the_json_document_carries_no_value() {
    let (op, fleet, _) = world();
    let mut out = Vec::new();
    run(&fleet, None, None, &op, None, true, &mut out).unwrap();
    assert!(!String::from_utf8(out).unwrap().contains(MARK));
}

/// An unbound boundary is the contract's typed `boundary_missing`, not a silent unknown.
#[test]
fn an_unbound_boundary_is_boundary_missing() {
    let op = FakeOp::default();
    let fleet = crate::config::parse(
        r#"
[environments.dev]
boundaries.core = {}

[products.api]
boundary = "core"

[products.api.keys.OPENAI_API_KEY]
kind = "secret"
environments = ["dev"]
"#,
    )
    .unwrap();
    let mut out = Vec::new();
    let error = run(&fleet, None, None, &op, None, false, &mut out).unwrap_err();
    assert_eq!(error.code_str(), "boundary_missing");
}

/// A wanted key with no value is the person's `opv set`, typed in the envelope.
#[test]
fn a_missing_key_is_the_persons_set_command() {
    let (op, fleet, _) = world();
    let mut out = Vec::new();
    run(&fleet, None, None, &op, None, true, &mut out).unwrap();
    let doc: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(
        doc["next"],
        json!({
            "kind": "enter_value",
            "actor": "person",
            "command": "opv set api/DATABASE_URL --env dev"
        })
    );
}

/// A placement whose delivery item carries a receipt shows `delivered`.
#[test]
fn a_delivery_item_with_a_receipt_is_delivered() {
    let op = FakeOp::default();
    let receipts = [("vweb", "iweb"), ("sweb", "dweb")];
    for (id, name) in receipts {
        op.vaults.borrow_mut().push((id.into(), name.into()));
    }
    let boundary = op.insert(
        "vweb",
        json!({"title": "web", "fields": [{
            "id": "f-db", "section": {"id": "s-web", "label": "web"},
            "label": "DATABASE_URL", "type": "CONCEALED", "value": "postgres://fake"
        }]}),
    );
    let receipt = json!({
        "schema": crate::domain::delivery::SCHEMA,
        "revision": "r1",
        "scope": {
            "account_id": "AFAKEOP0000000000000000001",
            "environment": "prod",
            "product": "web",
            "target": "site",
            "provider": "fly",
            "locator": "web-prod"
        },
        "bindings": [],
        "delivered_at": "2026-10-18T00:00:00Z",
        "plan_id": null,
        "opv_version": "0.12.0"
    })
    .to_string();
    let delivery = op.insert(
        "sweb",
        json!({"title": "web", "fields": [{
            "id": "f-receipt", "label": "receipt", "value": receipt
        }]}),
    );
    op.vault_users.borrow_mut().insert("vweb".into(), json!([]));
    let fleet = crate::config::parse(&format!(
        r#"
[environments.prod]
boundaries.web = {{ vault_id = "vweb", item_id = "{boundary}" }}

[environments.prod.targets.site]
fly.app = "web-prod"
fly.secret_name = "{{KEY}}"
state_vault_id = "sweb"
delivery_items = {{ web = "{delivery}" }}

[products.web.keys.DATABASE_URL]
kind = "secret"
environments = ["prod"]
"#
    ))
    .unwrap();
    let mut out = Vec::new();
    run(&fleet, None, None, &op, None, true, &mut out).unwrap();
    let doc: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(doc["deliveries"][0]["state"], "delivered");
}
