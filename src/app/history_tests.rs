//! `opv history` (#95): the report of what opv last wrote, and the no-target case.

use super::*;
use crate::app::testutil::*;
use crate::runner::Output;
use crate::runner::fake::FakeRunner;

fn row(name: &str, state: &'static str, written: Option<&str>) -> HistoryRow {
    HistoryRow {
        product: "api".into(),
        key: name.into(),
        name: format!("FLEET__API__{name}"),
        on_target: state != "absent",
        version: (state != "absent").then(|| "v3".to_string()),
        pending: false,
        written: written.map(str::to_string),
        opv_version: written.map(|_| "0.6.0".to_string()),
        plan: written.map(|_| "7f3c9a1e".to_string()),
        recorded_version: None,
        state,
    }
}

/// Target `web` of `prod` holding `rows`; `stamps`: its store keeps opv's write stamps.
fn part(rows: &[HistoryRow], stamps: bool) -> HistoryPart {
    HistoryPart {
        name: "web".into(),
        label: "Key Vault",
        section: "azure",
        stamps,
        rows: rows.to_vec(),
    }
}

/// The text report of `rows` on a store that keeps no stamps; `several`: `prod` has more
/// than one target.
fn text_with(rows: &[HistoryRow], stamps: bool, several: bool) -> String {
    let mut out = Vec::new();
    report(&mut out, "prod", &part(rows, stamps), several, false).unwrap();
    String::from_utf8(out).unwrap()
}

fn text(rows: &[HistoryRow]) -> String {
    text_with(rows, false, false)
}

fn doc(rows: &[HistoryRow]) -> serde_json::Value {
    let mut out = Vec::new();
    report(&mut out, "prod", &part(rows, false), false, true).unwrap();
    serde_json::from_slice(&out).unwrap()
}

#[test]
fn the_head_names_the_latest_write() {
    let rows = [
        row("A", "stamped", Some("2026-10-01T10:00:00Z")),
        row("B", "stamped", Some("2026-10-12T09:00:00Z")),
    ];
    assert!(
        text(&rows)
            .starts_with("prod/web (Key Vault): last write 2026-10-12T09:00:00Z by plan 7f3c9a1e")
    );
}

#[test]
fn a_store_without_stamps_says_so() {
    assert!(text(&[row("A", "recorded", None)]).contains("keeps no write stamps"));
}

/// 01.03: a store that stamps every write, with no stamp in it yet, never "keeps no write
/// stamps".
#[test]
fn a_stamping_store_without_a_stamp_is_never_said_to_keep_none() {
    assert!(
        !text_with(&[row("A", "recorded", None)], true, false).contains("keeps no write stamps")
    );
}

#[test]
fn a_stamping_store_without_a_stamp_says_nothing_here_was_written_by_opv() {
    assert!(
        text_with(&[row("A", "not_recorded", None)], true, false)
            .contains("no value here carries opv's write stamp yet")
    );
}

/// 01.22: with several targets, the plan step names the one this history is about.
#[test]
fn a_change_outside_opv_on_one_of_several_targets_plans_that_target() {
    assert!(
        text_with(&[row("A", "changed_outside_opv", None)], false, true)
            .ends_with("Next: opv plan prod --target web\n")
    );
}

#[test]
fn a_change_outside_opv_ends_with_the_plan_step() {
    assert!(text(&[row("A", "changed_outside_opv", None)]).ends_with("Next: opv plan prod\n"));
}

#[test]
fn each_key_is_listed_with_its_target_name() {
    assert!(
        text(&[row("TOKEN", "stamped", Some("2026-10-12T09:00:00Z"))])
            .contains("FLEET__API__TOKEN")
    );
}

#[test]
fn the_json_carries_the_latest_plan() {
    assert_eq!(
        doc(&[row("A", "stamped", Some("2026-10-12T09:00:00Z"))])["latest"]["plan"],
        "7f3c9a1e"
    );
}

#[test]
fn the_json_lists_each_row_with_its_state() {
    assert_eq!(
        doc(&[row("A", "not_recorded", None)])["rows"][0]["state"],
        "not_recorded"
    );
}

#[test]
fn an_environment_without_a_target_has_no_history() {
    let fleet = crate::config::parse(
        "[environments.dev]\nboundaries.app = { vault_id = \"v\", item_id = \"i\" }\n\
         [products.app.keys.A]\nkind = \"secret\"\nenvironments = [\"dev\"]\n",
    )
    .unwrap();
    let mut out = Vec::new();
    run(
        &fleet,
        "dev",
        None,
        &crate::runner::fake::FakeRunner::new(Vec::<crate::runner::Output>::new()),
        false,
        &mut out,
    )
    .unwrap();
    assert!(String::from_utf8(out).unwrap().contains("no write history"));
}

// Every target of the environment, or only the `--target` named one (FR-56) ---------------

const TWO_TARGETS: &str = r#"
[environments.multi]
boundaries.allumata = { vault_id = "v", item_id = "i" }

[environments.multi.targets.api]
fly.app = "api-app"
fly.secret_name = "FLEET__{PRODUCT}__{KEY}"
state_vault_id = "s1"

[environments.multi.targets.web]
fly.app = "web-app"
fly.secret_name = "FLEET__{PRODUCT}__{KEY}"
state_vault_id = "s2"

[products.allumata.keys.OPENAI_API_KEY]
kind = "secret"
environments = ["multi"]
"#;

fn multi_item() -> Output {
    item(&[secret("allumata", "OPENAI_API_KEY", "sk-proj-FIXTUREVALUE")])
}

fn multi_run(target: Option<&str>, json: bool) -> (Result<(), Error>, String, FakeRunner) {
    let fleet = crate::config::parse(TWO_TARGETS).unwrap();
    let r = FakeRunner::new([multi_item(), fly_empty(), multi_item(), fly_empty()]);
    let mut out = Vec::new();
    let res = run(&fleet, "multi", target, &r, json, &mut out);
    (res, text_of(&out), r)
}

/// The `env/target` of every report head line.
fn heads(text: &str) -> Vec<&str> {
    text.lines()
        .filter(|l| l.contains("(Fly):"))
        .map(|l| l.split(' ').next().unwrap())
        .collect()
}

#[test]
fn every_target_of_the_environment_is_listed_by_name() {
    let (res, out, _) = multi_run(None, false);
    res.unwrap();
    assert_eq!(heads(&out), ["multi/api", "multi/web"]);
}

#[test]
fn only_the_named_target_is_listed() {
    let (res, out, _) = multi_run(Some("api"), false);
    res.unwrap();
    assert_eq!(heads(&out), ["multi/api"]);
}

#[test]
fn the_json_lists_each_target_by_name() {
    let (res, out, _) = multi_run(None, true);
    res.unwrap();
    let doc: serde_json::Value = serde_json::from_str(&out).unwrap();
    let names: Vec<&str> = doc["targets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["api", "web"]);
}

/// 01.22: a key whose product the target does not deliver is not listed as missing there.
#[test]
fn a_key_the_target_does_not_deliver_is_not_listed() {
    let fleet = crate::config::parse(SCOPED).unwrap();
    let r = FakeRunner::new([scoped_item(), fly_empty()]);
    let mut out = Vec::new();
    run(&fleet, "multi", Some("web"), &r, false, &mut out).unwrap();
    assert!(!text_of(&out).contains("worker/TOKEN"));
}

/// [`TWO_TARGETS`] with a second product only target `api` delivers.
const SCOPED: &str = r#"
[environments.multi]
boundaries.allumata = { vault_id = "v", item_id = "i" }

[environments.multi.targets.api]
fly.app = "api-app"
fly.secret_name = "FLEET__{PRODUCT}__{KEY}"
state_vault_id = "s1"

[environments.multi.targets.web]
fly.app = "web-app"
fly.secret_name = "FLEET__{PRODUCT}__{KEY}"
state_vault_id = "s2"
products = ["allumata"]

[products.allumata.keys.OPENAI_API_KEY]
kind = "secret"
environments = ["multi"]

[products.worker]
boundary = "allumata"

[products.worker.keys.TOKEN]
kind = "secret"
environments = ["multi"]
"#;

fn scoped_item() -> Output {
    item(&[
        secret("allumata", "OPENAI_API_KEY", "sk-proj-FIXTUREVALUE"),
        secret("worker", "TOKEN", "tok-FIXTUREVALUE"),
    ])
}

#[test]
fn a_provider_whose_versions_are_digests_says_so() {
    let fly = crate::adapters::registry::find("fly").unwrap();
    assert!(fly.versions_reveal_values());
}

#[test]
fn version_ids_are_not_value_digests_by_default() {
    let azure = crate::adapters::registry::find("azure").unwrap();
    assert!(!azure.versions_reveal_values());
}
