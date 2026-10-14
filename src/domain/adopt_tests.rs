//! Behaviour tests for the FR-53 adoption planner (pure).

use super::*;
use crate::config;
use crate::domain::model::Kind;
use crate::domain::plan::ItemField;

/// A value that must never appear in any `Debug` output.
const MARK: &str = "ADOPTMARKER";

fn fleet() -> Fleet {
    config::parse(
        r#"
[environments.dev]
boundaries.core = { vault_id = "vdev", item_id = "idev" }
modes.api.payments = "off"
[environments.dev.targets.app]
fly.app = "app-dev"
fly.secret_name = "FLEET__{PRODUCT}__{KEY}"
state_vault_id = "sdev"

[environments.prod]
boundaries.core = { vault_id = "vprod", item_id = "iprod" }
[environments.prod.targets.app]
fly.app = "app-prod"
fly.secret_name = "FLEET__{PRODUCT}__{KEY}"
state_vault_id = "sprod"

[products.api]
boundary = "core"
[products.api.keys.DATABASE_URL]
kind = "secret"
environments = ["dev", "prod"]

[products.api.keys.LOG_LEVEL]
kind = "secret"
environments = ["dev", "prod"]

[products.api.keys.PRIVATE_KEY_PEM]
kind = "secret"
environments = ["dev", "prod"]
rules = { transform = "pem_private_key" }

[products.api.keys.PREFIXED]
kind = "secret"
environments = ["dev", "prod"]
rules = { prefix = "sk-" }

[products.api.keys.ENSURED]
kind = "secret"
environments = ["dev", "prod"]
rules = { ensure_prefix = "sk-" }

[products.api.keys.IMMUTABLE_KEY]
kind = "secret"
environments = ["dev", "prod"]
immutable = true

[products.api.keys.MODED]
kind = "secret"
environments = ["dev", "prod"]
rules = { prefix_by_mode = { mode = "payments", values = { test = "sk_test_" }, skip = ["off"] } }

[products.api.keys.FLY_API_TOKEN]
kind = "secret"
environments = ["dev", "prod"]
from = "shared/FLY_API_TOKEN"

[products.web]
boundary = "core"
[products.web.keys.LOG_LEVEL]
kind = "secret"
environments = ["dev", "prod"]

[products.web.keys.FLY_API_TOKEN]
kind = "secret"
environments = ["dev", "prod"]
from = "shared/FLY_API_TOKEN"

[products.shared]
source_only = true
boundary = "core"
[products.shared.keys.FLY_API_TOKEN]
kind = "secret"
environments = ["dev", "prod"]
"#,
    )
    .unwrap()
}

fn field(section: &str, label: &str, value: &str) -> ItemField {
    ItemField {
        section: section.into(),
        label: label.into(),
        kind: Kind::Secret,
        value: SecretValue::new(value.into()),
        concealed: true,
    }
}

fn found(pairs: &[(&str, &str)]) -> BTreeMap<String, SecretValue> {
    pairs
        .iter()
        .map(|(n, v)| ((*n).to_string(), SecretValue::new((*v).to_string())))
        .collect()
}

fn none() -> BTreeSet<(String, String)> {
    BTreeSet::new()
}

fn pairs(items: &[(&str, &str)]) -> BTreeSet<(String, String)> {
    items
        .iter()
        .map(|(p, k)| ((*p).to_string(), (*k).to_string()))
        .collect()
}

fn writes(plan: &AdoptPlan) -> Vec<(&str, &str, &str)> {
    plan.writes
        .iter()
        .map(|(p, k, v)| (p.as_str(), k.as_str(), v.expose()))
        .collect()
}

/// A PEM private key, multi-line, plus its one-line form.
fn pem() -> (String, String) {
    use base64::Engine as _;
    let der: Vec<u8> = std::iter::once(0x30u8)
        .chain((0..150u8).map(|i| i.wrapping_mul(7)))
        .collect();
    let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
    let lines: Vec<&str> = b64
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    let multi = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        lines.join("\n")
    );
    let single = format!("-----BEGIN PRIVATE KEY-----{b64}-----END PRIVATE KEY-----");
    (multi, single)
}

#[test]
fn an_empty_current_field_is_imported() {
    let p = plan(
        &fleet(),
        "dev",
        &[],
        &found(&[("FLEET__API__DATABASE_URL", "postgres://db")]),
        &none(),
        &none(),
    );
    assert_eq!(writes(&p), vec![("api", "DATABASE_URL", "postgres://db")]);
}

fn action_of(p: &AdoptPlan, product: &str, key: &str) -> Action {
    p.rows
        .iter()
        .find(|r| r.product.as_deref() == Some(product) && r.key.as_deref() == Some(key))
        .expect("a row for the key")
        .action
}

#[test]
fn a_matching_value_is_a_match() {
    let p = plan(
        &fleet(),
        "dev",
        &[field("api", "DATABASE_URL", "postgres://db")],
        &found(&[("FLEET__API__DATABASE_URL", "postgres://db")]),
        &none(),
        &none(),
    );
    assert_eq!(action_of(&p, "api", "DATABASE_URL"), Action::Match);
}

#[test]
fn a_pem_with_a_trailing_newline_is_format_only() {
    let (_, single) = pem();
    let with_newline = format!("{single}\n");
    let p = plan(
        &fleet(),
        "dev",
        &[field("api", "PRIVATE_KEY_PEM", &single)],
        &found(&[("FLEET__API__PRIVATE_KEY_PEM", with_newline.as_str())]),
        &none(),
        &none(),
    );
    assert_eq!(action_of(&p, "api", "PRIVATE_KEY_PEM"), Action::FormatOnly);
}

#[test]
fn a_multiline_pem_against_a_one_line_current_is_format_only() {
    let (multi, single) = pem();
    let p = plan(
        &fleet(),
        "dev",
        &[field("api", "PRIVATE_KEY_PEM", &single)],
        &found(&[("FLEET__API__PRIVATE_KEY_PEM", multi.as_str())]),
        &none(),
        &none(),
    );
    assert_eq!(action_of(&p, "api", "PRIVATE_KEY_PEM"), Action::FormatOnly);
}

#[test]
fn a_multiline_pem_is_staged_as_one_line() {
    let (multi, single) = pem();
    let p = plan(
        &fleet(),
        "dev",
        &[],
        &found(&[("FLEET__API__PRIVATE_KEY_PEM", multi.as_str())]),
        &none(),
        &none(),
    );
    assert_eq!(
        writes(&p),
        vec![("api", "PRIVATE_KEY_PEM", single.as_str())]
    );
}

#[test]
fn a_found_value_missing_the_ensure_prefix_is_format_only() {
    let p = plan(
        &fleet(),
        "dev",
        &[field("api", "ENSURED", "sk-abc")],
        &found(&[("FLEET__API__ENSURED", "abc")]),
        &none(),
        &none(),
    );
    assert_eq!(action_of(&p, "api", "ENSURED"), Action::FormatOnly);
}

#[test]
fn a_differing_value_is_kept_by_default() {
    let p = plan(
        &fleet(),
        "dev",
        &[field("api", "DATABASE_URL", "postgres://old")],
        &found(&[("FLEET__API__DATABASE_URL", "postgres://new")]),
        &none(),
        &none(),
    );
    assert_eq!(action_of(&p, "api", "DATABASE_URL"), Action::Differs);
}

#[test]
fn replace_writes_the_found_value() {
    let p = plan(
        &fleet(),
        "dev",
        &[field("api", "DATABASE_URL", "postgres://old")],
        &found(&[("FLEET__API__DATABASE_URL", "postgres://new")]),
        &pairs(&[("api", "DATABASE_URL")]),
        &none(),
    );
    assert_eq!(writes(&p), vec![("api", "DATABASE_URL", "postgres://new")]);
}

#[test]
fn an_immutable_key_named_by_replace_without_rotate_is_held() {
    let p = plan(
        &fleet(),
        "dev",
        &[field("api", "IMMUTABLE_KEY", "old")],
        &found(&[("FLEET__API__IMMUTABLE_KEY", "new")]),
        &pairs(&[("api", "IMMUTABLE_KEY")]),
        &none(),
    );
    assert_eq!(action_of(&p, "api", "IMMUTABLE_KEY"), Action::HeldImmutable);
}

#[test]
fn an_immutable_key_named_by_replace_and_rotate_is_replaced() {
    let p = plan(
        &fleet(),
        "dev",
        &[field("api", "IMMUTABLE_KEY", "old")],
        &found(&[("FLEET__API__IMMUTABLE_KEY", "new")]),
        &pairs(&[("api", "IMMUTABLE_KEY")]),
        &pairs(&[("api", "IMMUTABLE_KEY")]),
    );
    assert_eq!(writes(&p), vec![("api", "IMMUTABLE_KEY", "new")]);
}

#[test]
fn a_value_failing_a_rule_names_the_rule() {
    let p = plan(
        &fleet(),
        "dev",
        &[],
        &found(&[("FLEET__API__PREFIXED", "nope")]),
        &none(),
        &none(),
    );
    assert_eq!(
        action_of(&p, "api", "PREFIXED"),
        Action::FailsRule("prefix")
    );
}

#[test]
fn two_equal_shared_copies_write_the_source_once() {
    let p = plan(
        &fleet(),
        "dev",
        &[],
        &found(&[
            ("FLEET__API__FLY_API_TOKEN", "tok"),
            ("FLEET__WEB__FLY_API_TOKEN", "tok"),
        ]),
        &none(),
        &none(),
    );
    assert_eq!(writes(&p), vec![("shared", "FLY_API_TOKEN", "tok")]);
}

#[test]
fn differing_shared_copies_are_a_conflict() {
    let p = plan(
        &fleet(),
        "dev",
        &[],
        &found(&[
            ("FLEET__API__FLY_API_TOKEN", "tok1"),
            ("FLEET__WEB__FLY_API_TOKEN", "tok2"),
        ]),
        &none(),
        &none(),
    );
    assert_eq!(action_of(&p, "shared", "FLY_API_TOKEN"), Action::Conflict);
}

#[test]
fn a_rendered_target_name_maps_to_its_key() {
    let p = plan(
        &fleet(),
        "dev",
        &[],
        &found(&[("FLEET__API__DATABASE_URL", "x")]),
        &none(),
        &none(),
    );
    let row = &p.rows[0];
    assert_eq!(
        (row.product.as_deref(), row.key.as_deref()),
        (Some("api"), Some("DATABASE_URL"))
    );
}

#[test]
fn a_bare_key_name_maps_to_its_key() {
    let p = plan(
        &fleet(),
        "dev",
        &[],
        &found(&[("DATABASE_URL", "x")]),
        &none(),
        &none(),
    );
    let row = &p.rows[0];
    assert_eq!(
        (row.product.as_deref(), row.key.as_deref()),
        (Some("api"), Some("DATABASE_URL"))
    );
}

#[test]
fn a_bare_name_across_two_products_is_ambiguous() {
    let p = plan(
        &fleet(),
        "dev",
        &[],
        &found(&[("LOG_LEVEL", "info")]),
        &none(),
        &none(),
    );
    assert_eq!(p.rows[0].action, Action::Ambiguous);
}

#[test]
fn an_unknown_name_is_not_declared() {
    let p = plan(
        &fleet(),
        "dev",
        &[],
        &found(&[("GH_DEPLOY_KEY", "x")]),
        &none(),
        &none(),
    );
    assert_eq!(p.rows[0].action, Action::NotDeclared);
}

#[test]
fn a_mode_skipped_key_is_not_applicable() {
    let p = plan(
        &fleet(),
        "dev",
        &[],
        &found(&[("FLEET__API__MODED", "sk_test_x")]),
        &none(),
        &none(),
    );
    assert_eq!(action_of(&p, "api", "MODED"), Action::NotApplicable);
}

#[test]
fn debug_never_prints_a_value() {
    let found_value = format!("{MARK}-found");
    let p = plan(
        &fleet(),
        "dev",
        &[],
        &found(&[("FLEET__API__DATABASE_URL", found_value.as_str())]),
        &none(),
        &none(),
    );
    assert!(!format!("{p:?}").contains(MARK));
}

#[test]
fn action_words_are_stable() {
    let words = [
        Action::Match.word(),
        Action::FormatOnly.word(),
        Action::Import.word(),
        Action::Differs.word(),
        Action::Replace.word(),
        Action::HeldImmutable.word(),
        Action::FailsRule("prefix").word(),
        Action::Conflict.word(),
        Action::Ambiguous.word(),
        Action::NotDeclared.word(),
        Action::NotApplicable.word(),
    ];
    assert_eq!(
        words,
        [
            "match",
            "format_only",
            "import",
            "differs",
            "replace",
            "held_immutable",
            "fails_rule",
            "conflict",
            "ambiguous",
            "not_declared",
            "not_applicable",
        ]
    );
}

#[test]
fn rows_are_sorted_by_product_then_key() {
    let p = plan(
        &fleet(),
        "dev",
        &[],
        &found(&[
            ("FLEET__WEB__FLY_API_TOKEN", "t1"),
            ("FLEET__API__LOG_LEVEL", "l"),
            ("FLEET__API__DATABASE_URL", "d"),
        ]),
        &none(),
        &none(),
    );
    let order: Vec<(&str, &str)> = p
        .rows
        .iter()
        .map(|r| (r.product.as_deref().unwrap(), r.key.as_deref().unwrap()))
        .collect();
    assert_eq!(
        order,
        vec![
            ("api", "DATABASE_URL"),
            ("api", "LOG_LEVEL"),
            ("shared", "FLY_API_TOKEN")
        ]
    );
}

#[test]
fn writes_are_sorted_by_product_then_key() {
    let p = plan(
        &fleet(),
        "dev",
        &[],
        &found(&[
            ("FLEET__WEB__FLY_API_TOKEN", "t1"),
            ("FLEET__API__DATABASE_URL", "d"),
        ]),
        &none(),
        &none(),
    );
    assert_eq!(
        writes(&p),
        vec![
            ("api", "DATABASE_URL", "d"),
            ("shared", "FLY_API_TOKEN", "t1")
        ]
    );
}
