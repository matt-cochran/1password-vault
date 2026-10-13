//! `opv history` (#95): the report of what opv last wrote, and the no-target case.

use super::*;

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

fn text(rows: &[HistoryRow]) -> String {
    let mut out = Vec::new();
    report(&mut out, "prod", "Key Vault", "azure", false, rows, false).unwrap();
    String::from_utf8(out).unwrap()
}

fn doc(rows: &[HistoryRow]) -> serde_json::Value {
    let mut out = Vec::new();
    report(&mut out, "prod", "Key Vault", "azure", false, rows, true).unwrap();
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
            .starts_with("prod (Key Vault): last write 2026-10-12T09:00:00Z by plan 7f3c9a1e")
    );
}

#[test]
fn a_store_without_stamps_says_so() {
    assert!(text(&[row("A", "recorded", None)]).contains("keeps no write stamps"));
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
        "[profile]\nkind = \"simple\"\n[environments.dev]\nvault_id = \"v\"\nitem_id = \"i\"\n\
         [keys.A]\nkind = \"secret\"\nenvironments = [\"dev\"]\n",
    )
    .unwrap();
    let mut out = Vec::new();
    run(
        &fleet,
        "dev",
        &crate::runner::fake::FakeRunner::new(Vec::<crate::runner::Output>::new()),
        false,
        &mut out,
    )
    .unwrap();
    assert!(String::from_utf8(out).unwrap().contains("no write history"));
}
