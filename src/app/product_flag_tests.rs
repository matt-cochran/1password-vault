//! D10/FR-34: `--product` may be omitted when exactly one product that is not source-only
//! has keys desired in the environment, and that product is used. The same rule is applied
//! by `check`, `run`, `config export` and `open` through one helper. Several is a usage
//! error (exit 2) listing them, with a `Next:` naming the first; a source-only product never
//! qualifies. One behavioural assertion per test, through a public command.

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
    config_export::run(&fleet(), "prod", &r, &mut out).unwrap();
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
fn config_export_with_several_products_exits_two() {
    let e = config_export::run(
        &two_products(),
        "prod",
        &FakeRunner::new([]),
        &mut Vec::new(),
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
    config_export::run(&one_product_and_a_source_only(), "ci", &r, &mut out).unwrap();
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
