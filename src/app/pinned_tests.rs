//! `status` and `plan` against a pinned target (Azure Key Vault): exact compare of the
//! store's current value with the desired one (FR-31), and the staged flow (Fly) left
//! unchanged. The `sync` flow is covered in `azure_tests.rs`.

use serde_json::{Value, json};

use super::testutil::*;
use crate::config;
use crate::domain::Fleet;
use crate::runner::Output;
use crate::runner::fake::FakeRunner;

const AZURE: &str = r#"
[profile]
kind = "simple"
[environments.prod]
vault_id = "vprd"
item_id = "iprd"
[environments.prod.azure]
subscription = "00000000-0000-0000-0000-000000000000"
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

/// The recorded `az` output `name` (R10).
fn recorded(name: &str) -> Value {
    let path = format!("{}/tests/fixtures/azure/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// The preflight's answers (NR-23, NR-25): subscription visible, the recorded vault (renamed
/// to kv-app), its data plane answering, the recorded app.
fn preflight() -> Vec<Output> {
    let mut vault = recorded("keyvault-show.json");
    vault["name"] = json!("kv-app");
    vault["properties"]["vaultUri"] = json!("https://kv-app.vault.azure.net/");
    let json = |v: &Value| Output::success(serde_json::to_vec(v).unwrap());
    vec![
        Output::success(""),
        json(&vault),
        Output::success(""),
        json(&recorded("containerapp-show.json")),
    ]
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

/// `az containerapp show -o json` (the recorded fixture): `status` reads the bindings.
fn ca_show() -> Output {
    Output::success(serde_json::to_vec(&recorded("containerapp-show.json")).unwrap())
}

/// `status prod --json` on `responses` (after the preflight, then the app's bindings): the
/// TARGET of each row by key, and the runner.
fn azure_status(mut responses: Vec<Output>) -> (Vec<(String, String)>, FakeRunner) {
    responses.push(ca_show());
    let r = FakeRunner::new(preflight().into_iter().chain(responses));
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

/// NR-23: `status` checks the target, read-only, before it reads 1Password.
#[test]
fn azure_status_checks_the_subscription_before_reading_1password() {
    let (_, r) = azure_status(vec![
        azure_item(),
        kv_list(&["API-KEY", "DB-URL"]),
        kv_show("API-KEY", API_KEY),
        kv_show("DB-URL", DB_URL),
    ]);
    assert_eq!(
        r.calls.borrow()[0].args[..3],
        ["account", "show", "--subscription"]
    );
}

/// The app with an update in progress, as the preflight reads it.
fn preflight_in_progress() -> Vec<Output> {
    let mut v = preflight();
    let mut app = recorded("containerapp-show.json");
    app["properties"]["provisioningState"] = json!("InProgress");
    v[3] = Output::success(serde_json::to_vec(&app).unwrap());
    v
}

/// A read command never waits on an update in progress (NR-25): the preflight reads the
/// app once and `status` goes on.
#[test]
fn azure_status_does_not_wait_for_an_update_in_progress() {
    let r = FakeRunner::new(preflight_in_progress().into_iter().chain([
        azure_item(),
        kv_list(&["API-KEY", "DB-URL"]),
        kv_show("API-KEY", API_KEY),
        kv_show("DB-URL", DB_URL),
        ca_show(),
    ]));
    let mut out = Vec::new();
    super::status::run_with(&azure(), "prod", &r, &mut out, true).unwrap();
    assert_eq!(r.elapsed.get(), std::time::Duration::ZERO);
}

/// The in-progress note goes to stderr, so `--json` stays one document.
#[test]
fn azure_status_notes_an_update_in_progress_on_stderr() {
    let r = FakeRunner::new(preflight_in_progress().into_iter().chain([
        azure_item(),
        kv_list(&["API-KEY", "DB-URL"]),
        kv_show("API-KEY", API_KEY),
        kv_show("DB-URL", DB_URL),
        ca_show(),
    ]));
    let mut out = Vec::new();
    super::status::run_with(&azure(), "prod", &r, &mut out, true).unwrap();
    assert!(r.notes.borrow()[0].contains("an update is in progress"));
}

#[test]
fn azure_status_prints_no_store_value() {
    let r = FakeRunner::new(preflight().into_iter().chain([
        azure_item(),
        kv_list(&["API-KEY", "DB-URL"]),
        kv_show("API-KEY", "api-FIXTUREVALUE-old"),
        kv_show("DB-URL", DB_URL),
        ca_show(),
    ]));
    let mut out = Vec::new();
    let _ = super::status::run(&azure(), "prod", &r, &mut out);
    assert!(!text_of(&out).contains(MARKER));
}

#[test]
fn azure_plan_reads_each_secret_once() {
    let r = FakeRunner::new(preflight().into_iter().chain([
        azure_item(),
        kv_list(&["API-KEY", "DB-URL"]),
        kv_show("API-KEY", API_KEY),
        kv_show("DB-URL", "changed-FIXTUREVALUE"),
    ]));
    let mut out = Vec::new();
    super::sync::plan_with(&azure(), "prod", &r, &mut out, false).unwrap();
    assert_eq!(kv_reads(&r), 2);
}

#[test]
fn azure_plan_stages_only_the_changed_secret() {
    let r = FakeRunner::new(preflight().into_iter().chain([
        azure_item(),
        kv_list(&["API-KEY", "DB-URL"]),
        kv_show("API-KEY", API_KEY),
        kv_show("DB-URL", "changed-FIXTUREVALUE"),
    ]));
    let mut out = Vec::new();
    super::sync::plan_with(&azure(), "prod", &r, &mut out, true).unwrap();
    let doc: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(doc["stage"], json!(["DB_URL"]));
}

#[test]
fn azure_plan_shows_an_unchanged_secret_as_unchanged() {
    let r = FakeRunner::new(preflight().into_iter().chain([
        azure_item(),
        kv_list(&["API-KEY", "DB-URL"]),
        kv_show("API-KEY", API_KEY),
        kv_show("DB-URL", "changed-FIXTUREVALUE"),
    ]));
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
