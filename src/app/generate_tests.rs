//! `opv generate`: self-made secrets into 1Password, never shown, never over a value.

use super::*;
use crate::adapters::fake_op::FakeOp;

const FLEET: &str = r#"[environments.dev]
boundaries.api = { vault_id = "vdev0000000000000000000001", item_id = "ITEM" }

[products.api.keys.SESSION_KEY]
kind = "secret"
environments = ["dev"]
rules = { base64_bytes = 32 }

[products.api.keys.WEBHOOK_HEX]
kind = "secret"
environments = ["dev"]
rules = { hex_bytes = 32 }

[products.api.keys.STRIPE_KEY]
kind = "secret"
environments = ["dev"]
rules = { prefix = "sk_" }

[products.api.keys.PLAIN]
kind = "secret"
environments = ["dev"]
"#;

/// A fake whose dev item already holds `api/WEBHOOK_HEX` = `already-set`.
fn world() -> (crate::domain::Fleet, FakeOp, String) {
    let op = FakeOp::default();
    op.signed_in.set(true);
    let id = op.insert(
        "vdev0000000000000000000001",
        serde_json::json!({
            "title": "myapp · api · dev values", "category": "SECURE_NOTE",
            "sections": [{"id": "api", "label": "api"}],
            "fields": [{"id": "f1", "label": "WEBHOOK_HEX", "type": "CONCEALED",
                        "section": {"id": "api", "label": "api"}, "value": "already-set"}],
        }),
    );
    let fleet = crate::config::parse(&FLEET.replace("ITEM", &id)).unwrap();
    (fleet, op, id)
}

fn spec(fleet: &crate::domain::Fleet, key: &str) -> KeySpec {
    fleet.products["api"].keys[key].clone()
}

fn field(op: &FakeOp, id: &str, label: &str) -> Option<String> {
    op.item(id)["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["label"] == label)
        .and_then(|f| f["value"].as_str().map(str::to_string))
}

#[test]
fn a_base64_key_is_generated_as_base64() {
    let (fleet, _, _) = world();
    assert_eq!(
        recipe("api/SESSION_KEY", &spec(&fleet, "SESSION_KEY")).unwrap(),
        Recipe::Base64(32)
    );
}

#[test]
fn a_provider_key_with_a_prefix_is_refused() {
    let (fleet, _, _) = world();
    assert!(recipe("api/STRIPE_KEY", &spec(&fleet, "STRIPE_KEY")).is_err());
}

#[test]
fn a_key_without_a_byte_length_is_refused() {
    let (fleet, _, _) = world();
    assert!(recipe("api/PLAIN", &spec(&fleet, "PLAIN")).is_err());
}

#[test]
fn a_base64_value_decodes_to_its_byte_count() {
    let v = make(Recipe::Base64(32)).unwrap();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(v.expose())
        .unwrap();
    assert_eq!(bytes.len(), 32);
}

#[test]
fn a_hex_value_has_two_digits_per_byte() {
    assert_eq!(make(Recipe::Hex(32)).unwrap().expose().len(), 64);
}

#[test]
fn two_generated_values_differ() {
    assert_ne!(
        make(Recipe::Base64(32)).unwrap().expose(),
        make(Recipe::Base64(32)).unwrap().expose()
    );
}

#[test]
fn a_generated_value_passes_its_keys_rules() {
    let (fleet, _, _) = world();
    let v = make(Recipe::Base64(32)).unwrap();
    let ok = crate::domain::rules::check(
        "api",
        "SESSION_KEY",
        &spec(&fleet, "SESSION_KEY"),
        "dev",
        fleet.environment("dev").unwrap(),
        &v,
    );
    assert!(ok.is_ok());
}

#[test]
fn generate_writes_the_value_into_1password() {
    let (fleet, op, id) = world();
    run(
        &fleet,
        "dev",
        &["api/SESSION_KEY".into()],
        &op,
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(field(&op, &id, "SESSION_KEY").map(|v| v.len()), Some(44));
}

#[test]
fn generate_never_shows_the_value() {
    let (fleet, op, id) = world();
    let mut out = Vec::new();
    run(&fleet, "dev", &["api/SESSION_KEY".into()], &op, &mut out).unwrap();
    let value = field(&op, &id, "SESSION_KEY").unwrap();
    assert!(!String::from_utf8(out).unwrap().contains(&value));
}

#[test]
fn a_filled_field_is_never_replaced() {
    let (fleet, op, id) = world();
    let _ = run(
        &fleet,
        "dev",
        &["api/WEBHOOK_HEX".into()],
        &op,
        &mut Vec::new(),
    );
    assert_eq!(
        field(&op, &id, "WEBHOOK_HEX").as_deref(),
        Some("already-set")
    );
}

#[test]
fn one_refused_key_writes_nothing_for_the_others() {
    let (fleet, op, id) = world();
    let _ = run(
        &fleet,
        "dev",
        &["api/SESSION_KEY".into(), "api/STRIPE_KEY".into()],
        &op,
        &mut Vec::new(),
    );
    assert_eq!(field(&op, &id, "SESSION_KEY"), None);
}

#[test]
fn an_undeclared_key_is_refused() {
    let (fleet, op, _) = world();
    let e = run(&fleet, "dev", &["api/NOPE".into()], &op, &mut Vec::new()).unwrap_err();
    assert_eq!(e.code().as_str(), "undeclared_key");
}
