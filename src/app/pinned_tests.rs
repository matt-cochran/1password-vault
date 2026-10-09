//! `status` and `plan` against a pinned target (Azure Key Vault): exact compare of the
//! store's current value with the desired one (FR-31), and the staged flow (Fly) left
//! unchanged.

use serde_json::{Value, json};

use super::testutil::*;
use crate::config;
use crate::domain::Fleet;
use crate::error::Error;
use crate::runner::Output;
use crate::runner::fake::FakeRunner;

const AZURE: &str = r#"
[profile]
kind = "simple"
[environments.prod]
vault_id = "vprd"
item_id = "iprd"
[environments.prod.azure]
key_vault = "kv-app"
resource_group = "rg-app"
container_app = "ca-app"
identity = "system"
[keys.API_KEY]
kind = "secret"
environments = ["prod"]
[keys.DB_URL]
kind = "secret"
environments = ["prod"]
"#;

const API_KEY: &str = "api-FIXTUREVALUE";
const DB_URL: &str = "postgres://FIXTUREVALUE@db/app";
const VERSION: &str = "46687ce78b76487cb0c1da470360b638";

fn azure() -> Fleet {
    config::parse(AZURE).unwrap()
}

fn azure_item() -> Output {
    item(&[secret("", "API_KEY", API_KEY), secret("", "DB_URL", DB_URL)])
}

/// `az keyvault secret list -o json`: entries opv owns in prod, by Key Vault name.
fn kv_list(names: &[&str]) -> Output {
    let v: Vec<Value> = names
        .iter()
        .map(|n| json!({"name": n, "tags": {"opv-managed": "prod"}}))
        .collect();
    Output::success(serde_json::to_vec(&v).unwrap())
}

/// `az keyvault secret show -o json` holding `value`.
fn kv_show(name: &str, value: &str) -> Output {
    let id = format!("https://kv-app.vault.azure.net/secrets/{name}/{VERSION}");
    Output::success(serde_json::to_vec(&json!({"id": id, "value": value})).unwrap())
}

/// `status prod --json` on `responses`: the TARGET of each row by key, and the runner.
fn azure_status(responses: Vec<Output>) -> (Vec<(String, String)>, FakeRunner) {
    let r = FakeRunner::new(responses);
    let mut out = Vec::new();
    super::status::run_with(&azure(), "prod", &r, &mut out, true).unwrap();
    let doc: Value = serde_json::from_slice(&out).unwrap();
    let targets = doc["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["key"].as_str().unwrap().to_string(),
                row["target"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    (targets, r)
}

fn target_of(targets: &[(String, String)], key: &str) -> String {
    targets.iter().find(|(k, _)| k == key).unwrap().1.clone()
}

fn kv_reads(r: &FakeRunner) -> usize {
    r.calls
        .borrow()
        .iter()
        .filter(|c| {
            c.program == "az"
                && c.args
                    .starts_with(&["keyvault".into(), "secret".into(), "show".into()])
        })
        .count()
}

#[test]
fn azure_status_reports_present_when_store_value_matches() {
    let (targets, _) = azure_status(vec![
        azure_item(),
        kv_list(&["API-KEY", "DB-URL"]),
        kv_show("API-KEY", API_KEY),
        kv_show("DB-URL", DB_URL),
    ]);
    assert_eq!(target_of(&targets, "API_KEY"), "present");
}

#[test]
fn azure_status_reports_would_change_when_store_value_differs() {
    let (targets, _) = azure_status(vec![
        azure_item(),
        kv_list(&["API-KEY", "DB-URL"]),
        kv_show("API-KEY", "api-FIXTUREVALUE-old"),
        kv_show("DB-URL", DB_URL),
    ]);
    assert_eq!(target_of(&targets, "API_KEY"), "would_change");
}

#[test]
fn azure_status_reports_absent_for_missing_store_entry() {
    let (targets, _) = azure_status(vec![
        azure_item(),
        kv_list(&["DB-URL"]),
        kv_show("DB-URL", DB_URL),
    ]);
    assert_eq!(target_of(&targets, "API_KEY"), "absent");
}

/// A listed entry gone by the time it is read (`show` exits 3) is absent.
#[test]
fn azure_status_reports_absent_when_the_listed_entry_is_gone() {
    let (targets, _) = azure_status(vec![
        azure_item(),
        kv_list(&["API-KEY", "DB-URL"]),
        Output::failure(3),
        kv_show("DB-URL", DB_URL),
    ]);
    assert_eq!(target_of(&targets, "API_KEY"), "absent");
}

#[test]
fn azure_status_prints_no_store_value() {
    let r = FakeRunner::new(vec![
        azure_item(),
        kv_list(&["API-KEY", "DB-URL"]),
        kv_show("API-KEY", "api-FIXTUREVALUE-old"),
        kv_show("DB-URL", DB_URL),
    ]);
    let mut out = Vec::new();
    let _ = super::status::run(&azure(), "prod", &r, &mut out);
    assert!(!text_of(&out).contains(MARKER));
}

#[test]
fn azure_plan_reads_each_secret_once() {
    let r = FakeRunner::new(vec![
        azure_item(),
        kv_list(&["API-KEY", "DB-URL"]),
        kv_show("API-KEY", API_KEY),
        kv_show("DB-URL", "changed-FIXTUREVALUE"),
    ]);
    let mut out = Vec::new();
    super::sync::plan_with(&azure(), "prod", &r, &mut out, false).unwrap();
    assert_eq!(kv_reads(&r), 2);
}

#[test]
fn azure_plan_stages_only_the_changed_secret() {
    let r = FakeRunner::new(vec![
        azure_item(),
        kv_list(&["API-KEY", "DB-URL"]),
        kv_show("API-KEY", API_KEY),
        kv_show("DB-URL", "changed-FIXTUREVALUE"),
    ]);
    let mut out = Vec::new();
    super::sync::plan_with(&azure(), "prod", &r, &mut out, true).unwrap();
    let doc: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(doc["stage"], json!(["DB_URL"]));
}

#[test]
fn azure_plan_shows_an_unchanged_secret_as_unchanged() {
    let r = FakeRunner::new(vec![
        azure_item(),
        kv_list(&["API-KEY", "DB-URL"]),
        kv_show("API-KEY", API_KEY),
        kv_show("DB-URL", "changed-FIXTUREVALUE"),
    ]);
    let mut out = Vec::new();
    super::sync::plan_with(&azure(), "prod", &r, &mut out, false).unwrap();
    assert!(
        text_of(&out)
            .lines()
            .any(|l| l.starts_with("API_KEY") && l.ends_with("unchanged")),
        "{}",
        text_of(&out)
    );
}

#[test]
fn fly_plan_makes_no_read_calls() {
    let r = FakeRunner::new(vec![
        complete_item(),
        fly(&[(OPENAI_FLY, "d1"), (ENC_FLY, "d2")]),
    ]);
    let mut out = Vec::new();
    let _ = super::sync::plan_with(&fleet(), "prod", &r, &mut out, false);
    assert_eq!(r.calls.borrow().len(), 2);
}

/// `sync` against a pinned target is still the internal refusal until the pinned flow
/// lands (Task 7); it reads nothing first.
#[test]
fn azure_sync_is_refused_before_any_call() {
    let r = FakeRunner::new(vec![]);
    let mut out = Vec::new();
    let res = super::sync::run(&azure(), "prod", &r, &mut out, &Default::default());
    assert!(matches!(res, Err(Error::Target(m)) if m.contains("pinned sync not implemented")));
}
