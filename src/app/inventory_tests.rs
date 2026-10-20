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

/// `gather` hands back the document `run` renders, so `opv next` can rank it (found by the
/// `core-accepted` walkthrough: `next` had no library route from a read inventory).
#[test]
fn gather_returns_the_read_document() {
    let (op, fleet, _) = world();
    let document = super::gather(&fleet, None, None, &op, None).unwrap();
    let state = document
        .cells
        .iter()
        .find(|c| c.key == "OPENAI_API_KEY")
        .map(|c| c.state.clone());
    assert_eq!(state, Some(crate::domain::value_state::ValueState::Set));
}

/// An environment with no target has nothing to sync to, so its `set` key is delivered and
/// `opv next` never asks for `opv sync` there (rank 6).
#[test]
fn a_set_key_without_a_target_asks_for_no_sync() {
    let (op, fleet, _) = world();
    let (document, signals) = super::gather_for_next(&fleet, None, None, &op, None).unwrap();
    let doc = crate::app::next::next(&document, &signals);
    assert!(!crate::app::next::render_text(&doc).contains("opv sync"));
}

/// The state of the `product`/`key` cell in `env` of a gathered inventory.
fn state_of(
    document: &crate::domain::inventory::Inventory,
    product: &str,
    key: &str,
    env: &str,
) -> Option<crate::domain::value_state::ValueState> {
    document
        .cells
        .iter()
        .find(|c| c.product == product && c.key == key && c.env == env)
        .map(|c| c.state.clone())
}

/// A shared key (`from`) has no field of its own: it reads its source's field in the source
/// product's boundary item, so a set source is a set shared key, never `absent`.
#[test]
fn a_shared_key_takes_its_sources_state() {
    let op = FakeOp::default();
    let item = op.insert(
        VAULT,
        json!({"title": "shared", "fields": [{
            "id": "f-db", "section": {"id": "s-shared", "label": "shared"},
            "label": "DATABASE_URL", "type": "CONCEALED", "value": MARK
        }]}),
    );
    let web = op.insert(VAULT, json!({"title": "web", "fields": []}));
    op.vault_users.borrow_mut().insert(VAULT.into(), json!([]));
    let fleet = crate::config::parse(&format!(
        r#"
[environments.dev]
boundaries.shared = {{ vault_id = "{VAULT}", item_id = "{item}" }}
boundaries.web = {{ vault_id = "{VAULT}", item_id = "{web}" }}

[products.shared]
source_only = true
boundary = "shared"

[products.shared.keys.DATABASE_URL]
kind = "secret"

[products.web]
boundary = "web"

[products.web.keys.DATABASE_URL]
kind = "secret"
from = "shared/DATABASE_URL"
"#
    ))
    .unwrap();
    let document = super::gather(&fleet, None, None, &op, None).unwrap();
    assert_eq!(
        state_of(&document, "web", "DATABASE_URL", "dev"),
        Some(crate::domain::value_state::ValueState::Set)
    );
}

/// A personal key is read from the person's own item (FR-55), not the team boundary item
/// that never holds it: set there, it is `set`.
#[test]
fn a_personal_key_is_read_from_the_persons_own_item() {
    let (op, _, id) = world();
    op.vaults
        .borrow_mut()
        .push(("vpriv0000000000000000000001".into(), "Private".into()));
    op.insert(
        "Private",
        json!({"title": "mine", "category": "SECURE_NOTE", "fields": [{
            "id": "f-llm", "section": {"id": "s-api", "label": "api"},
            "label": "LLM_KEY", "type": "CONCEALED", "value": MARK
        }]}),
    );
    let fleet = crate::config::parse(&format!(
        r#"
[environments.dev]
boundaries.core = {{ vault_id = "{VAULT}", item_id = "{id}" }}
personal_item = "mine"

[products.api]
boundary = "core"

[products.api.keys.OPENAI_API_KEY]
kind = "secret"

[products.api.keys.LLM_KEY]
kind = "secret"
personal = true
"#
    ))
    .unwrap();
    let document = super::gather(&fleet, None, None, &op, None).unwrap();
    assert_eq!(
        state_of(&document, "api", "LLM_KEY", "dev"),
        Some(crate::domain::value_state::ValueState::Set)
    );
}

/// Walkthrough finding 2: with every key's field in place, an `empty` cell in a vault this
/// session can write is the person's `opv set`, as `opv next` ranks it (3).
#[test]
fn an_empty_cell_in_a_writable_vault_is_the_persons_set_command() {
    use crate::domain::inventory::{CellInputs, build};
    use crate::domain::value_state::ValueState;
    let (_, fleet, _) = world();
    let at = |key: &str| ("api".to_string(), key.to_string(), "dev".to_string());
    let cells = CellInputs {
        states: std::collections::BTreeMap::from([
            (at("DATABASE_URL"), ValueState::Set),
            (at("OPENAI_API_KEY"), ValueState::Empty),
        ]),
        capabilities: std::collections::BTreeMap::from([(
            VAULT.to_string(),
            crate::domain::capability::Capability::Write,
        )]),
        ..CellInputs::default()
    };
    assert_eq!(
        super::next_command(&build(&fleet, &cells, None)),
        Some("opv set api/OPENAI_API_KEY --env dev".to_string())
    );
}

// --- #174: where each key lives in 1Password, and the compact text markers ---------------

/// The JSON document `opv inventory --json` renders for `op` and `fleet`.
fn json_document(op: &FakeOp, fleet: &Fleet) -> Value {
    let mut out = Vec::new();
    run(fleet, None, None, op, None, true, &mut out).unwrap();
    serde_json::from_slice(&out).unwrap()
}

/// The rendered JSON key row of `product`/`key`.
fn key_row_of(doc: &Value, product: &str, key: &str) -> Value {
    doc["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["product"] == product && k["key"] == key)
        .expect("the key is declared")
        .clone()
}

/// A key's row names the section its field sits in.
#[test]
fn a_key_row_reports_the_section_that_holds_its_field() {
    let (op, fleet, _) = world();
    let doc = json_document(&op, &fleet);
    assert_eq!(
        key_row_of(&doc, "api", "OPENAI_API_KEY")["location"]["section"],
        "api"
    );
}

/// A key's row names the field label 1Password holds the value under.
#[test]
fn a_key_row_reports_the_field_label_holding_its_value() {
    let (op, fleet, _) = world();
    let doc = json_document(&op, &fleet);
    assert_eq!(
        key_row_of(&doc, "api", "OPENAI_API_KEY")["location"]["field"],
        "OPENAI_API_KEY"
    );
}

/// A key's row links to the boundary item that holds it, never to the field.
#[test]
fn a_key_row_reports_the_item_link_for_its_boundary() {
    let (op, fleet, id) = world();
    let doc = json_document(&op, &fleet);
    assert_eq!(
        key_row_of(&doc, "api", "OPENAI_API_KEY")["location"]["link"],
        format!("op://{VAULT}/{id}")
    );
}

/// The boundary item `marker_fleet`'s three keys share: all present, each under `api`.
fn marker_item(op: &FakeOp) -> String {
    op.insert(
        VAULT,
        json!({
            "title": "api",
            "category": "LOGIN",
            "fields": [
                {"id": "f-plain", "section": {"id": "s-api", "label": "api"},
                 "label": "PLAIN_KEY", "type": "CONCEALED", "value": MARK},
                {"id": "f-signing", "section": {"id": "s-api", "label": "api"},
                 "label": "SIGNING_KEY", "type": "CONCEALED", "value": MARK},
                {"id": "f-tls", "section": {"id": "s-api", "label": "api"},
                 "label": "TLS_KEY", "type": "CONCEALED", "value": MARK}
            ]
        }),
    )
}

/// One dev environment with product `api` and three keys in boundary `core`. With `markers`,
/// `SIGNING_KEY` is `immutable` and `TLS_KEY` is a local file key; without, neither declares
/// an attribute (the same row labels, so the two matrices align).
fn marker_fleet(id: &str, markers: bool) -> Fleet {
    let signing = if markers { "\nimmutable = true" } else { "" };
    let tls = if markers {
        "\nfile = \"tls/private-key\""
    } else {
        ""
    };
    crate::config::parse(&format!(
        r#"
[environments.dev]
boundaries.core = {{ vault_id = "{VAULT}", item_id = "{id}" }}

[products.api]
boundary = "core"

[products.api.keys.PLAIN_KEY]
kind = "secret"
environments = ["dev"]

[products.api.keys.SIGNING_KEY]
kind = "secret"
environments = ["dev"]{signing}

[products.api.keys.TLS_KEY]
kind = "secret"
environments = ["dev"]{tls}
"#
    ))
    .unwrap()
}

/// The text matrix for a three-key `marker_fleet`, with or without the attribute markers.
fn marker_text(markers: bool) -> String {
    let op = FakeOp::default();
    let id = marker_item(&op);
    op.vault_users.borrow_mut().insert(VAULT.into(), json!([]));
    let fleet = marker_fleet(&id, markers);
    let mut out = Vec::new();
    run(&fleet, None, None, &op, None, false, &mut out).unwrap();
    String::from_utf8(out).unwrap()
}

/// The row labelled `label` in a text matrix.
fn row_line(text: &str, label: &str) -> String {
    text.lines()
        .find(|line| line.starts_with(label))
        .unwrap_or_default()
        .to_string()
}

/// An immutable key carries a compact suffix in the text matrix.
#[test]
fn an_immutable_key_is_marked_in_the_text_matrix() {
    assert!(row_line(&marker_text(true), "api/SIGNING_KEY").starts_with("api/SIGNING_KEY!"));
}

/// A file key carries a compact suffix in the text matrix.
#[test]
fn a_file_key_is_marked_in_the_text_matrix() {
    assert!(row_line(&marker_text(true), "api/TLS_KEY").starts_with("api/TLS_KEY@"));
}

/// A key with neither attribute renders exactly as it does when no key has a marker.
#[test]
fn a_key_with_neither_marker_renders_as_without_markers() {
    assert_eq!(
        row_line(&marker_text(true), "api/PLAIN_KEY"),
        row_line(&marker_text(false), "api/PLAIN_KEY")
    );
}
