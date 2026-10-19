//! D10/FR-34: `--product` may be omitted when exactly one product that is not source-only
//! has keys desired in the environment, and that product is used. The same rule is applied
//! by `check`, `run` and `open` through one helper. Several is a usage error (exit 2)
//! listing them, with a `Next:` naming the first; a source-only product never qualifies.
//! `config export` (#188) instead exports every product without `--product`, and only the
//! named one with it. One behavioural assertion per test, through a public command.

use super::testutil::*;
use super::{config_export, local, open, run};
use crate::config;
use crate::domain::Fleet;
use crate::runner::Output;
use crate::runner::fake::FakeRunner;

fn cmd(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| s.to_string()).collect()
}

/// Two products whose keys are both desired in prod.
fn two_products() -> Fleet {
    config::parse(
        r#"
[environments.prod]
boundaries.core = { vault_id = "vprd", item_id = "iprd" }

[products.alpha]
boundary = "core"
[products.alpha.keys.ALPHA_SECRET]
kind = "secret"
environments = ["prod"]

[products.beta]
boundary = "core"
[products.beta.keys.BETA_SECRET]
kind = "secret"
environments = ["prod"]
"#,
    )
    .unwrap()
}

/// One runnable product, `api`, plus a source-only `shared` that `api` reads (FR-47).
fn one_product_and_a_source_only() -> Fleet {
    config::parse(
        r#"
[environments.ci]
boundaries.core = { vault_id = "vci", item_id = "ici" }

[products.shared]
source_only = true
boundary = "core"
[products.shared.keys.TOKEN]
kind = "secret"
environments = ["ci"]

[products.api]
boundary = "core"
[products.api.keys.TOKEN]
kind = "secret"
from = "shared/TOKEN"
environments = ["ci"]
[products.api.keys.API_ONLY]
kind = "secret"
environments = ["ci"]
"#,
    )
    .unwrap()
}

/// Fields for the source-only fleet: the shared source and the runnable product's own key.
fn source_only_item() -> Output {
    item(&[
        secret("shared", "TOKEN", MARKER),
        secret("api", "API_ONLY", MARKER),
    ])
}

// ---- one qualifying product: no flag, and that product is used -------------------------

#[test]
fn run_with_one_product_needs_no_flag() {
    let r = FakeRunner::new([Output::success(Vec::new())]);
    let code = run::run_for(&fleet(), "prod", None, None, &cmd(&["env"]), &r).unwrap();
    assert_eq!(code, 0);
}

#[test]
fn config_export_with_one_product_needs_no_flag() {
    let r = FakeRunner::new([complete_item()]);
    let mut out = Vec::new();
    config_export::run(&fleet(), "prod", None, &r, &mut out).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["allumata"]["SIGNUP_POLICY"], "invite_only");
}

#[test]
fn open_with_one_product_needs_no_flag() {
    let r = FakeRunner::new([whoami()]);
    let mut out = Vec::new();
    open::run(&fleet(), "OPENAI_API_KEY", Some("prod"), None, &r, &mut out).unwrap();
    assert!(
        text_of(&out).contains("allumata/OPENAI_API_KEY"),
        "{}",
        text_of(&out)
    );
}

// ---- several qualifying products: usage error (exit 2) ---------------------------------

#[test]
fn run_with_several_products_exits_two() {
    let e = run::run_for(
        &two_products(),
        "prod",
        None,
        None,
        &cmd(&["env"]),
        &FakeRunner::new([]),
    )
    .unwrap_err();
    assert_eq!(e.exit_code(), 2);
}

#[test]
fn open_with_several_products_exits_two() {
    let e = open::run(
        &two_products(),
        "ALPHA_SECRET",
        Some("prod"),
        None,
        &FakeRunner::new([]),
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(e.exit_code(), 2);
}

// ---- a source-only product never qualifies ---------------------------------------------

#[test]
fn run_with_a_source_only_product_needs_no_flag() {
    let r = FakeRunner::new([Output::success(Vec::new())]);
    let code = run::run_for(
        &one_product_and_a_source_only(),
        "ci",
        None,
        None,
        &cmd(&["env"]),
        &r,
    )
    .unwrap();
    assert_eq!(code, 0);
}

#[test]
fn config_export_with_a_source_only_product_needs_no_flag() {
    let r = FakeRunner::new([source_only_item()]);
    let mut out = Vec::new();
    config_export::run(&one_product_and_a_source_only(), "ci", None, &r, &mut out).unwrap();
    assert!(text_of(&out).contains("{}"), "{}", text_of(&out));
}

#[test]
fn open_with_a_source_only_product_needs_no_flag() {
    let r = FakeRunner::new([whoami()]);
    let mut out = Vec::new();
    open::run(
        &one_product_and_a_source_only(),
        "API_ONLY",
        Some("ci"),
        None,
        &r,
        &mut out,
    )
    .unwrap();
    assert!(text_of(&out).contains("api/API_ONLY"), "{}", text_of(&out));
}

// ---- a personal-only product counts as having keys desired -----------------------------

#[test]
fn a_personal_only_product_qualifies() {
    let f = config::parse(
        "[environments.dev]\ntitle = \"Local development\"\n\
         [products.api.keys.MY_TOKEN]\nkind = \"secret\"\nenvironments = [\"dev\"]\npersonal = true\n",
    )
    .unwrap();
    let selected = local::select(&f, "dev", None, true).unwrap();
    assert!(selected.products.contains_key("api"));
}

// ---- config export: every product, or the one --product names (#188) ------------------

/// Two products with a config key each in prod, `beta` reading `MODE` from the source-only
/// `shared`, and `gamma` with a secret only.
fn products_with_config() -> Fleet {
    config::parse(
        r#"
[environments.prod]
boundaries.core = { vault_id = "vprd", item_id = "iprd" }

[products.shared]
source_only = true
boundary = "core"
[products.shared.keys.MODE]
kind = "config"
environments = ["prod"]

[products.alpha]
boundary = "core"
[products.alpha.keys.ALPHA_LEVEL]
kind = "config"
environments = ["prod"]

[products.beta]
boundary = "core"
[products.beta.keys.MODE]
kind = "config"
from = "shared/MODE"
environments = ["prod"]

[products.gamma]
boundary = "core"
[products.gamma.keys.GAMMA_SECRET]
kind = "secret"
environments = ["prod"]
"#,
    )
    .unwrap()
}

/// Every field of [`products_with_config`], less any `(section, label)` in `without`.
fn config_item(without: &[(&str, &str)]) -> Output {
    let fields: Vec<_> = [
        text("shared", "MODE", "strict"),
        text("alpha", "ALPHA_LEVEL", "info"),
        secret("gamma", "GAMMA_SECRET", MARKER),
    ]
    .into_iter()
    .filter(|(s, l, _, _)| !without.contains(&(s.as_str(), l.as_str())))
    .collect();
    item(&fields)
}

fn export_config(product: Option<&str>, item: Output) -> Result<serde_json::Value, String> {
    let r = FakeRunner::new([item]);
    let mut out = Vec::new();
    config_export::run(&products_with_config(), "prod", product, &r, &mut out)
        .map_err(|e| e.code_str().to_string())?;
    Ok(serde_json::from_slice(&out).unwrap())
}

#[test]
fn config_export_with_several_products_exports_each() {
    assert_eq!(
        export_config(None, config_item(&[])),
        Ok(serde_json::json!({
            "alpha": {"ALPHA_LEVEL": "info"},
            "beta": {"MODE": "strict"},
        }))
    );
}

#[test]
fn config_export_with_product_exports_only_that_product() {
    assert_eq!(
        export_config(Some("beta"), config_item(&[])),
        Ok(serde_json::json!({"beta": {"MODE": "strict"}}))
    );
}

#[test]
fn config_export_with_an_unknown_product_is_refused() {
    assert_eq!(
        export_config(Some("delta"), config_item(&[])),
        Err("unknown_product".to_string())
    );
}

#[test]
fn config_export_with_a_source_only_product_is_refused() {
    assert_eq!(
        export_config(Some("shared"), config_item(&[])),
        Err("source_only".to_string())
    );
}

#[test]
fn config_export_with_product_needs_no_item_read_when_the_product_is_unknown() {
    let r = FakeRunner::new([]);
    let _ = config_export::run(
        &products_with_config(),
        "prod",
        Some("delta"),
        &r,
        &mut Vec::new(),
    );
    assert!(r.calls.borrow().is_empty(), "{:?}", argvs(&r));
}

#[test]
fn a_missing_config_key_of_another_product_does_not_block_a_product_export() {
    assert!(export_config(Some("beta"), config_item(&[("alpha", "ALPHA_LEVEL")])).is_ok());
}

#[test]
fn a_missing_source_of_the_product_blocks_its_export() {
    assert_eq!(
        export_config(Some("beta"), config_item(&[("shared", "MODE")])),
        Err("findings".to_string())
    );
}

#[test]
fn a_missing_config_key_of_any_product_blocks_the_export_without_product() {
    assert_eq!(
        export_config(None, config_item(&[("alpha", "ALPHA_LEVEL")])),
        Err("findings".to_string())
    );
}

#[test]
fn config_export_leaves_a_product_without_config_out() {
    let v = export_config(None, config_item(&[])).unwrap();
    assert!(v.get("gamma").is_none(), "{v}");
}

#[test]
fn config_export_leaves_a_source_only_product_out() {
    let v = export_config(None, config_item(&[])).unwrap();
    assert!(v.get("shared").is_none(), "{v}");
}

#[test]
fn config_export_with_several_products_never_contains_a_secret_value() {
    let r = FakeRunner::new([config_item(&[])]);
    let mut out = Vec::new();
    config_export::run(&products_with_config(), "prod", None, &r, &mut out).unwrap();
    assert_no_values(&text_of(&out));
}
