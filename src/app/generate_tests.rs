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
        recipe("api", "SESSION_KEY", "dev", &spec(&fleet, "SESSION_KEY")).unwrap(),
        Recipe::Base64(32)
    );
}

#[test]
fn a_provider_key_with_a_prefix_is_refused() {
    let (fleet, _, _) = world();
    assert!(recipe("api", "STRIPE_KEY", "dev", &spec(&fleet, "STRIPE_KEY")).is_err());
}

/// #157: policy_refused exits 6 (policy), as its code says.
#[test]
fn a_refused_key_exits_as_its_code_says() {
    let (fleet, _, _) = world();
    let e = recipe("api", "STRIPE_KEY", "dev", &spec(&fleet, "STRIPE_KEY")).unwrap_err();
    assert!(
        crate::cause::codes::table()
            .iter()
            .any(|r| r.code == e.code_str() && r.exits.contains(&e.exit_code()))
    );
}

#[test]
fn a_key_without_a_byte_length_is_refused() {
    let (fleet, _, _) = world();
    assert!(recipe("api", "PLAIN", "dev", &spec(&fleet, "PLAIN")).is_err());
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
    assert_eq!(e.code_str(), "undeclared_key");
}

// 05.11 (S2): each refusal says its own reason ------------------------------------------

fn why_of(e: &Error) -> &'static str {
    match e.cause() {
        Some((
            Cause::Guard {
                guard: Guard::GenerateRefused { reason, .. },
            },
            _,
        )) => reason.words(),
        _ => "",
    }
}

/// `api/SESSION_KEY` (base64, 32 bytes) changed by `f`.
fn session_key_with(f: impl FnOnce(&mut KeySpec)) -> KeySpec {
    let (fleet, _, _) = world();
    let mut s = spec(&fleet, "SESSION_KEY");
    f(&mut s);
    s
}

#[test]
fn a_personal_key_is_refused_as_personal() {
    let s = session_key_with(|s| s.personal = true);
    let e = recipe("api", "SESSION_KEY", "dev", &s).unwrap_err();
    assert!(why_of(&e).contains("personal"), "{e}");
}

#[test]
fn a_byte_count_out_of_range_is_refused_naming_the_range() {
    let s = session_key_with(|s| s.rules.base64_bytes = Some(8));
    let e = recipe("api", "SESSION_KEY", "dev", &s).unwrap_err();
    assert!(why_of(&e).contains("16 and 1024"), "{e}");
}

#[test]
fn a_refusal_names_the_environment() {
    let (fleet, _, _) = world();
    let e = recipe("api", "STRIPE_KEY", "dev", &spec(&fleet, "STRIPE_KEY")).unwrap_err();
    assert!(matches!(
        e.cause(),
        Some((Cause::Guard { guard: Guard::GenerateRefused { env, .. } }, _))
            if env.as_str() == "dev"
    ));
}

#[test]
fn a_filled_field_is_refused_as_already_holding_a_value() {
    let (fleet, op, _) = world();
    let e = run(
        &fleet,
        "dev",
        &["api/WEBHOOK_HEX".into()],
        &op,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert!(why_of(&e).contains("already holds a value"), "{e}");
}

// 05.39 (S3): argument errors carry their own codes --------------------------------------

#[test]
fn a_key_without_its_product_is_a_usage_error() {
    let (fleet, op, _) = world();
    let e = run(&fleet, "dev", &["SESSION_KEY".into()], &op, &mut Vec::new()).unwrap_err();
    assert_eq!(e.code_str(), "usage");
}

#[test]
fn a_failed_random_source_is_opvs_own_local_io() {
    // F2: the OS random source is local I/O, never a missing tool.
    assert_eq!(random_source_failed().code_str(), "local_io_failed");
}

/// #206 §4.4: an infrastructure key is never generated, even when its shape rule gives a
/// byte count.
#[test]
fn an_infrastructure_key_is_refused_as_infrastructure() {
    let s = session_key_with(|s| s.value_source = Some(crate::domain::ValueSource::Infrastructure));
    let e = recipe("api", "SESSION_KEY", "dev", &s).unwrap_err();
    assert_eq!(why_of(&e), GenerateRefusal::Infrastructure.words());
}
