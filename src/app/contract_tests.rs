//! Behaviour of the contract-as-data builder (deliverable `contract-data`, R10, D-G): one
//! atomic test per observable outcome, one assertion each, through the public functions.
//!
//! Fleets come from `config::parse`. No value, id or rule parameter is ever in scope here.

use super::*;
use crate::config::parse;

/// The `dev` (shared) and `prod` (production) environments, each with the boundary the
/// product `app` lives in.
const ENVS: &str = "[environments.dev]\ntier = \"shared\"\n\
                    boundaries.app = { vault_id = \"vdev0000000000000000000001\", item_id = \"app\" }\n\n\
                    [environments.prod]\ntier = \"production\"\n\
                    boundaries.app = { vault_id = \"vprod000000000000000000001\", item_id = \"app\" }\n\n";

/// A marker that must never appear in the document; it is placed in a key's rule regex.
const MARKER: &str = "S7MARKER";

/// The contract of one product `app` with four keys: a catalog-shaped secret, a
/// catalog-shaped config, a custom-regex secret, and a key `except`ed in `prod`.
fn fleet() -> Fleet {
    parse(&format!(
        "{ENVS}\
         [products.app.keys.STRIPE_KEY]\nkind = \"secret\"\nrules = {{ prefix = \"sk_\" }}\n\n\
         [products.app.keys.URL_KEY]\nkind = \"config\"\nrules = {{ https_url = true }}\n\n\
         [products.app.keys.CUSTOM_KEY]\nkind = \"secret\"\nrules = {{ regex = \"{MARKER}\" }}\n\n\
         [products.app.keys.EXCEPTED_KEY]\nkind = \"secret\"\nexcept = {{ prod = \"no prod account\" }}\n"
    ))
    .expect("the fixture contract parses")
}

/// The key `name` of component `app` in environment `env`.
fn key<'a>(doc: &'a ContractDoc, env: &str, name: &str) -> &'a KeyContract {
    doc.components[0]
        .environments
        .iter()
        .find(|e| e.name == env)
        .and_then(|e| e.keys.iter().find(|k| k.name == name))
        .expect("the key is in the document")
}

#[test]
fn a_declared_key_appears_with_its_name_and_kind() {
    let doc = document(&fleet(), Some("dev"), None);
    let shown = doc.components[0].environments[0]
        .keys
        .iter()
        .find(|k| k.name == "STRIPE_KEY")
        .map(|k| (k.name.clone(), k.kind));
    assert_eq!(
        shown,
        Some(("STRIPE_KEY".to_string(), ContractKind::Secret))
    );
}

#[test]
fn a_key_whose_rules_equal_a_catalog_shape_names_the_shape() {
    let doc = document(&fleet(), Some("dev"), None);
    assert_eq!(
        key(&doc, "dev", "STRIPE_KEY").shape.as_deref(),
        Some("stripe_secret")
    );
}

#[test]
fn a_key_with_custom_rules_has_no_shape_name() {
    let doc = document(&fleet(), Some("dev"), None);
    assert_eq!(key(&doc, "dev", "CUSTOM_KEY").shape, None);
}

#[test]
fn a_rule_regex_marker_never_appears_in_the_document() {
    let doc = document(&fleet(), None, None);
    let text = serde_json::to_string(&doc).expect("the document serializes");
    assert!(!text.contains(MARKER));
}

#[test]
fn an_excepted_environment_is_not_required() {
    let doc = document(&fleet(), Some("prod"), None);
    assert!(!key(&doc, "prod", "EXCEPTED_KEY").required);
}

#[test]
fn the_digest_is_stable_for_the_same_contract() {
    let first = document(&fleet(), None, None);
    let second = document(&fleet(), None, None);
    assert_eq!(first.contract_digest, second.contract_digest);
}

#[test]
fn the_document_validates_against_its_schema() {
    let doc = document(&fleet(), None, None);
    let schema = json_schema(&doc);
    let value = serde_json::to_value(&doc).expect("the document is a value");
    assert!(validate(&schema, &value).is_ok());
}

#[test]
fn check_fails_contract_stale_on_a_changed_copy() {
    let doc = document(&fleet(), None, None);
    let mut changed = serde_json::to_value(&doc).expect("the document is a value");
    changed["components"][0]["environments"][0]["keys"][0]["kind"] = serde_json::json!("config");
    let err = check(&doc, &changed.to_string()).expect_err("a changed copy is stale");
    assert!(matches!(
        err,
        Error::Catalog(cause, _) if matches!(*cause, Cause::ContractStale { .. })
    ));
}

#[test]
fn check_passes_on_an_equal_copy() {
    let doc = document(&fleet(), Some("dev"), None);
    let committed = serde_json::to_string(&doc).expect("the document serializes");
    assert!(check(&doc, &committed).is_ok());
}

#[test]
fn relaxations_delegates_to_the_domain_classifier() {
    let other = "[products.app.keys.OTHER_KEY]\nkind = \"secret\"\n";
    let base = parse(&format!(
        "{ENVS}[products.app.keys.API_KEY]\nkind = \"secret\"\n{other}"
    ))
    .expect("the base contract parses");
    let head = parse(&format!(
        "{ENVS}[products.app.keys.API_KEY]\nkind = \"secret\"\nexcept = {{ prod = \"no prod account\" }}\n{other}"
    ))
    .expect("the head contract parses");
    assert_eq!(
        relaxations(&base, &head),
        vec![Relaxation::new(
            "app",
            "API_KEY",
            Some("prod".to_string()),
            crate::domain::relaxation::RelaxationKind::ExceptProduction,
        )]
    );
}

// --- a tiny draft 2020-12 validator: types, enum, required, properties, items -----------------

fn validate(schema: &serde_json::Value, value: &serde_json::Value) -> Result<(), String> {
    if let Some(kinds) = schema.get("type") {
        let ok = match kinds {
            serde_json::Value::String(t) => type_matches(t, value),
            serde_json::Value::Array(ts) => ts
                .iter()
                .any(|t| t.as_str().is_some_and(|t| type_matches(t, value))),
            _ => false,
        };
        if !ok {
            return Err(format!("type mismatch at {value}"));
        }
    }
    if let Some(choices) = schema.get("enum").and_then(serde_json::Value::as_array)
        && !choices.contains(value)
    {
        return Err(format!("{value} is not in the enum"));
    }
    if let Some(required) = schema.get("required").and_then(serde_json::Value::as_array) {
        let obj = value.as_object().ok_or("required on a non-object")?;
        for r in required {
            if !obj.contains_key(r.as_str().unwrap_or_default()) {
                return Err(format!("missing {r}"));
            }
        }
    }
    if let Some(props) = schema
        .get("properties")
        .and_then(serde_json::Value::as_object)
    {
        let obj = value.as_object().ok_or("properties on a non-object")?;
        if schema.get("additionalProperties") == Some(&serde_json::Value::Bool(false)) {
            for k in obj.keys() {
                if !props.contains_key(k) {
                    return Err(format!("unexpected property {k}"));
                }
            }
        }
        for (k, subschema) in props {
            if let Some(v) = obj.get(k) {
                validate(subschema, v)?;
            }
        }
    }
    if let Some(items) = schema.get("items") {
        let arr = value.as_array().ok_or("items on a non-array")?;
        for v in arr {
            validate(items, v)?;
        }
    }
    Ok(())
}

fn type_matches(t: &str, v: &serde_json::Value) -> bool {
    match t {
        "object" => v.is_object(),
        "array" => v.is_array(),
        "string" => v.is_string(),
        "boolean" => v.is_boolean(),
        "number" => v.is_number(),
        "integer" => v.is_i64() || v.is_u64(),
        "null" => v.is_null(),
        _ => false,
    }
}
