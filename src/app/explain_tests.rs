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

// --- the leak response (FR-22, G31): the `delivered to` section ---------------------------

use super::run_request_with;
use crate::adapters::fake_op::FakeOp;
use crate::runner::CommandRunner;

/// The `delivered to:` section's lines, trimmed, in the order `explain` prints them.
fn delivered_lines(text: &str) -> Vec<String> {
    text.lines()
        .skip_while(|l| *l != "  delivered to:")
        .skip(1)
        .take_while(|l| l.starts_with("    "))
        .map(|l| l.trim().to_string())
        .collect()
}

/// The environment each `delivered to:` line names, in order.
fn delivered_environments(text: &str) -> Vec<String> {
    delivered_lines(text)
        .iter()
        .map(|l| l.split('/').next().unwrap().to_string())
        .collect()
}

/// The target each `delivered to:` line names, in order.
fn delivered_targets(text: &str) -> Vec<String> {
    delivered_lines(text)
        .iter()
        .map(|l| {
            l.split('/')
                .nth(1)
                .unwrap()
                .split(' ')
                .next()
                .unwrap()
                .to_string()
        })
        .collect()
}

/// `explain`'s text for `asked`, with a runner for the delivery-evidence read.
fn explain_text_with(
    r: &dyn CommandRunner,
    f: &Fleet,
    asked: &Asked<'_>,
    env: Option<&str>,
    project: &str,
) -> String {
    let mut out = Vec::new();
    run_request_with(r, f, asked, env, project, &mut out, false).unwrap();
    text_of(&out)
}

/// `explain`'s JSON for `asked`, with a runner for the delivery-evidence read.
fn explain_json_with(
    r: &dyn CommandRunner,
    f: &Fleet,
    asked: &Asked<'_>,
    env: Option<&str>,
    project: &str,
) -> Value {
    let mut out = Vec::new();
    run_request_with(r, f, asked, env, project, &mut out, true).unwrap();
    serde_json::from_slice(&out).unwrap()
}

/// A `FakeOp` holding one delivery item whose `note` field is `value`, and the ID it was
/// stored under. The note is a value the leak response must never print.
fn op_with_delivery_item(value: &str) -> (FakeOp, String) {
    let op = FakeOp::default();
    let id = op.insert(
        "vshr0000000000000000000002",
        serde_json::json!({
            "title": "opv · delivery · allumata · portfolio",
            "category": "SECURE_NOTE",
            "fields": [{"id": "note", "type": "STRING", "label": "note", "value": value}],
        }),
    );
    (op, id)
}

/// A fleet with one prod target that records `item_id` as `allumata`'s delivery item, in the
/// vault the `FakeOp` can serve.
fn fleet_with_delivery_item(item_id: &str) -> Fleet {
    config::parse(&format!(
        "[environments.prod]\n\
         boundaries.allumata = {{ vault_id = \"vshr0000000000000000000002\", item_id = \"iprd\" }}\n\
         [environments.prod.targets.portfolio]\n\
         fly.app = \"portfolio-prod\"\n\
         fly.secret_name = \"FLEET__{{PRODUCT}}__{{KEY}}\"\n\
         state_vault_id = \"vshr0000000000000000000002\"\n\
         delivery_items = {{ allumata = \"{item_id}\" }}\n\
         [products.allumata.keys.OPENAI_API_KEY]\n\
         kind = \"secret\"\n\
         environments = [\"prod\"]\n"
    ))
    .unwrap()
}

#[test]
fn key_lists_every_environment_it_is_desired_in() {
    // INTEGRATION_ENC_KEY is declared in staging and prod, each with a portfolio target.
    let out = explain_text(
        &fleet(),
        &Asked::Key("allumata/INTEGRATION_ENC_KEY"),
        Some("prod"),
        "myproj",
    );
    assert_eq!(delivered_environments(&out), vec!["prod", "staging"]);
}

#[test]
fn key_lists_every_target_delivering_it() {
    let out = explain_text(
        &two_targets(),
        &Asked::Key("allumata/OPENAI_API_KEY"),
        Some("prod"),
        "myproj",
    );
    assert_eq!(delivered_targets(&out), vec!["overflow", "portfolio"]);
}

#[test]
fn key_lists_the_delivery_item_that_holds_it() {
    let (op, id) = op_with_delivery_item("not a real value");
    let f = fleet_with_delivery_item(&id);
    let out = explain_text_with(
        &op,
        &f,
        &Asked::Key("allumata/OPENAI_API_KEY"),
        Some("prod"),
        "myproj",
    );
    assert_eq!(
        delivered_lines(&out),
        vec![format!(
            "prod/portfolio opv · delivery · allumata · portfolio (item {id})"
        )]
    );
}

#[test]
fn key_text_output_never_shows_a_delivery_item_value() {
    let (op, id) = op_with_delivery_item("S7MARKERDELIVERY0001");
    let f = fleet_with_delivery_item(&id);
    let out = explain_text_with(
        &op,
        &f,
        &Asked::Key("allumata/OPENAI_API_KEY"),
        Some("prod"),
        "myproj",
    );
    assert!(!out.contains("S7MARKER"), "{out}");
}

#[test]
fn key_json_output_never_shows_a_delivery_item_value() {
    let (op, id) = op_with_delivery_item("S7MARKERDELIVERY0002");
    let f = fleet_with_delivery_item(&id);
    let doc = explain_json_with(
        &op,
        &f,
        &Asked::Key("allumata/OPENAI_API_KEY"),
        Some("prod"),
        "myproj",
    );
    assert!(!doc.to_string().contains("S7MARKER"), "{doc}");
}

// --- the plan-id form (FR-41): `explain <plan_id> --env <env>` ---------------------------

use crate::app::sync;
use crate::app::testutil::{OPENAI_FLY, complete_item, complete_with, fly, secret};
use crate::cause::Cause;
use crate::runner::fake::FakeRunner;

/// The runner whose one prod Fly target is planned from the fixture item.
fn plan_runner() -> FakeRunner {
    FakeRunner::new([complete_item(), fly(&[(OPENAI_FLY, "d1")])])
}

/// The same runner with the OpenAI field set to an `S7MARKER` value the explanation must
/// never print.
fn marker_runner() -> FakeRunner {
    FakeRunner::new([
        complete_with(secret(
            "allumata",
            "OPENAI_API_KEY",
            "sk-proj-S7MARKERPLAN0001",
        )),
        fly(&[(OPENAI_FLY, "d1")]),
    ])
}

/// The plan id `opv plan prod --json` prints for `r`'s state: the id `explain <plan_id>`
/// checks the recomputed plan against.
fn recomputed_id(r: &dyn CommandRunner) -> String {
    let f = fleet();
    let mut out = Vec::new();
    sync::plan_targeted(&f, "prod", &[], None, r, &mut out, true).unwrap();
    let doc: Value = serde_json::from_slice(&out).unwrap();
    doc["plan_id"].as_str().unwrap().to_string()
}

/// The step lines the plan-id explanation prints, trimmed, in order.
fn plan_steps(text: &str) -> Vec<String> {
    text.lines()
        .skip_while(|l| !l.starts_with("  plan "))
        .skip(1)
        .take_while(|l| l.starts_with("    "))
        .map(|l| l.trim().to_string())
        .collect()
}

#[test]
fn a_matching_plan_id_lists_every_step() {
    let id = recomputed_id(&plan_runner());
    let text = explain_text_with(
        &plan_runner(),
        &fleet(),
        &Asked::Key(&id),
        Some("prod"),
        "myproj",
    );
    assert_eq!(
        plan_steps(&text),
        vec![
            "portfolio allumata/INTEGRATION_ENC_KEY would_stage".to_string(),
            "portfolio allumata/OPENAI_API_KEY would_stage".to_string(),
        ]
    );
}

#[test]
fn a_plan_id_that_no_longer_matches_is_stale() {
    let mut out = Vec::new();
    let e = run_request_with(
        &plan_runner(),
        &fleet(),
        &Asked::Key("deadbeef"),
        Some("prod"),
        "myproj",
        &mut out,
        false,
    )
    .unwrap_err();
    assert_eq!(e.code_str(), "stale_plan");
}

#[test]
fn a_stale_plan_id_names_the_recomputed_id() {
    let id = recomputed_id(&plan_runner());
    let mut out = Vec::new();
    let e = run_request_with(
        &plan_runner(),
        &fleet(),
        &Asked::Key("deadbeef"),
        Some("prod"),
        "myproj",
        &mut out,
        false,
    )
    .unwrap_err();
    assert!(matches!(e.cause(), Some((Cause::PlanChanged { new, .. }, _)) if new.as_str() == id));
}

#[test]
fn a_plan_explanation_never_shows_a_value() {
    let id = recomputed_id(&marker_runner());
    let text = explain_text_with(
        &marker_runner(),
        &fleet(),
        &Asked::Key(&id),
        Some("prod"),
        "myproj",
    );
    assert!(!text.contains("S7MARKER"), "{text}");
}

#[test]
fn a_plan_id_without_an_environment_names_the_flag() {
    let mut out = Vec::new();
    let e = run_request_with(
        &FakeRunner::new([]),
        &fleet(),
        &Asked::Key("deadbeef"),
        None,
        "myproj",
        &mut out,
        false,
    )
    .unwrap_err();
    assert!(matches!(e.cause(), Some((Cause::ChoiceRequired { flag, .. }, _)) if flag == "--env"));
}
