//! Behavioural tests for `opv explain` (E8; FR-56, FR-57, FR-59): the key form names the
//! source, boundary, every delivering target and its readers; the target form names a
//! target's provider, locator, products, deploy credentials, state vault and account.
//!
//! Each test states one observable outcome through the module's public interface. The
//! project is passed explicitly, so the deploy and CI account names are deterministic.

use std::collections::BTreeMap;

use serde_json::Value;

use super::{Asked, run_request};
use crate::app::testutil::{fleet, fleet_with, text_of};
use crate::config;
use crate::domain::Fleet;

/// The text `explain` prints for `asked` in `env`, with account names from `project`.
fn explain_text(f: &Fleet, asked: &Asked<'_>, env: Option<&str>, project: &str) -> String {
    let mut out = Vec::new();
    run_request(f, asked, env, project, &mut out, false).unwrap();
    text_of(&out)
}

/// The JSON document `explain` prints for `asked` in `env`, with account names from `project`.
fn explain_json(f: &Fleet, asked: &Asked<'_>, env: Option<&str>, project: &str) -> Value {
    let mut out = Vec::new();
    run_request(f, asked, env, project, &mut out, true).unwrap();
    serde_json::from_slice(&out).unwrap()
}

/// The value of the `label:` row in explain's text output.
fn row(text: &str, label: &str) -> String {
    let prefix = format!("  {label}:");
    text.lines()
        .find_map(|l| l.strip_prefix(&prefix))
        .map(str::trim)
        .unwrap_or_else(|| panic!("no {label:?} row in:\n{text}"))
        .to_string()
}

/// Every `target:` row's value, in the order explain prints them.
fn target_rows(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.strip_prefix("  target:"))
        .map(|v| v.trim().to_string())
        .collect()
}

/// The fixture plus a second prod target serving only allumata, so a key can be delivered
/// to two named targets in one environment (FR-56).
fn two_targets() -> Fleet {
    fleet_with(
        "[environments.prod.targets.overflow]\n\
         fly.app = \"overflow-prod\"\n\
         fly.secret_name = \"{KEY}\"\n\
         state_vault_id = \"sovf\"\n\
         products = [\"allumata\"]\n",
    )
}

/// A source-only product and a team key that reads it with `from` (FR-45, FR-57).
const SHARED: &str = "\
[environments.prod]
boundaries.shared = { vault_id = \"vshr\", item_id = \"ishr\" }
boundaries.api = { vault_id = \"vapi\", item_id = \"iapi\" }
[environments.prod.targets.app]
fly.app = \"app\"
fly.secret_name = \"FLEET__{PRODUCT}__{KEY}\"
state_vault_id = \"sprod\"
[products.shared]
source_only = true
[products.shared.keys.SHARED_TOKEN]
kind = \"secret\"
environments = [\"prod\"]
[products.api.keys.API_TOKEN]
kind = \"secret\"
environments = [\"prod\"]
from = \"shared/SHARED_TOKEN\"
";

fn shared_fleet() -> Fleet {
    config::parse(SHARED).unwrap()
}

#[test]
fn key_delivered_by_two_targets_lists_both_with_their_rendered_names() {
    let out = explain_text(
        &two_targets(),
        &Asked::Key("allumata/OPENAI_API_KEY"),
        Some("prod"),
        "myproj",
    );
    assert_eq!(
        target_rows(&out),
        vec![
            "overflow (Fly) OPENAI_API_KEY".to_string(),
            "portfolio (Fly) FLEET__ALLUMATA__OPENAI_API_KEY".to_string(),
        ]
    );
}

#[test]
fn key_json_lists_every_delivering_target_with_its_rendered_name() {
    let doc = explain_json(
        &two_targets(),
        &Asked::Key("allumata/OPENAI_API_KEY"),
        Some("prod"),
        "myproj",
    );
    let rendered: Vec<&str> = doc["targets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["rendered_name"].as_str().unwrap())
        .collect();
    assert_eq!(
        rendered,
        vec!["OPENAI_API_KEY", "FLEET__ALLUMATA__OPENAI_API_KEY"]
    );
}

#[test]
fn shared_key_names_the_source_key() {
    let out = explain_text(
        &shared_fleet(),
        &Asked::Key("api/API_TOKEN"),
        Some("prod"),
        "myproj",
    );
    assert_eq!(row(&out, "source"), "from shared/SHARED_TOKEN");
}

#[test]
fn shared_key_names_the_sources_boundary() {
    let out = explain_text(
        &shared_fleet(),
        &Asked::Key("api/API_TOKEN"),
        Some("prod"),
        "myproj",
    );
    assert_eq!(row(&out, "boundary"), "shared (vault vshr, item ishr)");
}

#[test]
fn key_names_its_boundary_vault_and_item_ids() {
    let out = explain_text(
        &fleet(),
        &Asked::Key("allumata/OPENAI_API_KEY"),
        Some("prod"),
        "myproj",
    );
    assert_eq!(row(&out, "boundary"), "allumata (vault vprd, item iprd)");
}

#[test]
fn key_names_the_deploy_and_ci_service_accounts() {
    let out = explain_text(
        &fleet(),
        &Asked::Key("allumata/OPENAI_API_KEY"),
        Some("prod"),
        "myproj",
    );
    assert_eq!(
        row(&out, "readers"),
        "deploy myproj-prod-portfolio-deploy, ci myproj-prod-ci"
    );
}

#[test]
fn key_json_names_the_deploy_and_ci_service_accounts() {
    let doc = explain_json(
        &fleet(),
        &Asked::Key("allumata/OPENAI_API_KEY"),
        Some("prod"),
        "myproj",
    );
    assert_eq!(
        doc["readers"],
        serde_json::json!({"deploy": ["myproj-prod-portfolio-deploy"], "ci": "myproj-prod-ci"})
    );
}

#[test]
fn personal_key_says_it_lives_in_each_persons_own_item() {
    let f = config::parse(
        "[environments.dev]\n\
         [products.app.keys.MY_KEY]\n\
         kind = \"secret\"\n\
         environments = [\"dev\"]\n\
         personal = true\n",
    )
    .unwrap();
    let out = explain_text(&f, &Asked::Key("app/MY_KEY"), Some("dev"), "myproj");
    assert_eq!(row(&out, "personal"), "each person's own item");
}

/// Every fact the target form prints, as label → value.
fn target_facts(text: &str) -> BTreeMap<String, String> {
    [
        "provider",
        "locator",
        "products",
        "deploy credentials",
        "state vault",
        "deploy account",
    ]
    .into_iter()
    .map(|l| (l.to_string(), row(text, l)))
    .collect()
}

#[test]
fn target_form_prints_provider_locator_products_credentials_vault_and_account() {
    let out = explain_text(
        &fleet(),
        &Asked::Target("portfolio"),
        Some("prod"),
        "myproj",
    );
    assert_eq!(
        target_facts(&out),
        BTreeMap::from([
            ("provider".to_string(), "Fly".to_string()),
            (
                "locator".to_string(),
                "app mcproductlabs-portfolio-production".to_string(),
            ),
            (
                "products".to_string(),
                "every product with keys in prod".to_string(),
            ),
            ("deploy credentials".to_string(), "none".to_string()),
            ("state vault".to_string(), "sprd".to_string()),
            (
                "deploy account".to_string(),
                "myproj-prod-portfolio-deploy".to_string(),
            ),
        ])
    );
}

#[test]
fn target_form_names_an_explicit_products_list() {
    let out = explain_text(
        &two_targets(),
        &Asked::Target("overflow"),
        Some("prod"),
        "myproj",
    );
    assert_eq!(row(&out, "products"), "allumata");
}

#[test]
fn target_form_names_a_deploy_credentials_reference() {
    let f = fleet_with(
        "[environments.prod.targets.creds]\n\
         fly.app = \"creds-prod\"\n\
         fly.secret_name = \"{KEY}\"\n\
         state_vault_id = \"scrd\"\n\
         deploy_credentials = \"op://infra-prod/fly-deploy-creds\"\n",
    );
    let out = explain_text(&f, &Asked::Target("creds"), Some("prod"), "myproj");
    assert_eq!(
        row(&out, "deploy credentials"),
        "op://infra-prod/fly-deploy-creds"
    );
}

#[test]
fn target_json_carries_the_same_facts_as_the_text_form() {
    let doc = explain_json(
        &two_targets(),
        &Asked::Target("overflow"),
        Some("prod"),
        "myproj",
    );
    assert_eq!(
        serde_json::json!({
            "provider": doc["provider"],
            "locator": doc["locator"],
            "products": doc["products"],
            "deploy_credentials": doc["deploy_credentials"],
            "state_vault_id": doc["state_vault_id"],
            "deploy_account": doc["deploy_account"],
        }),
        serde_json::json!({
            "provider": "fly",
            "locator": "app overflow-prod",
            "products": "allumata",
            "deploy_credentials": null,
            "state_vault_id": "sovf",
            "deploy_account": "myproj-prod-overflow-deploy",
        })
    );
}
