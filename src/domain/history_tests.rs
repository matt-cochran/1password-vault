//! Behaviour tests for the value-free key history (#95, FR-42, FR-54). Pure.

use std::collections::BTreeMap;

use super::*;
use crate::domain::plan::StoreEntry;
use crate::domain::provenance::Stamp;

const ENV: &str = "FLEET__API__DB_URL";

fn key<'a>(product: &'a str, key: &'a str, name: &'a str) -> KeyRef<'a> {
    KeyRef { product, key, name }
}

fn stamp(written: &str) -> Stamp {
    Stamp {
        opv_version: "0.5.0".into(),
        written: written.into(),
        env: "prod".into(),
        plan: "7f3c9a1e".into(),
    }
}

fn listed(name: &str, version: Option<&str>) -> StoreEntry {
    StoreEntry {
        name: name.into(),
        version: version.map(str::to_string),
        pending: false,
        stamp: None,
    }
}

fn stamped(name: &str, written: &str) -> StoreEntry {
    StoreEntry {
        stamp: Some(stamp(written)),
        ..listed(name, Some("d1"))
    }
}

fn recorded(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect()
}

fn row<'a>(rows: &'a [HistoryRow], name: &str) -> &'a HistoryRow {
    rows.iter().find(|r| r.name == name).unwrap()
}

// ---- shape -----------------------------------------------------------------------

#[test]
fn build_makes_one_row_per_declared_key() {
    let keys = [key("api", "A", "N_A"), key("api", "B", "N_B")];
    assert_eq!(build(&keys, &[], &BTreeMap::new()).len(), 2);
}

#[test]
fn rows_follow_the_given_key_order() {
    let keys = [
        key("api", "A", "N_A"),
        key("api", "B", "N_B"),
        key("api", "C", "N_C"),
    ];
    let rows = build(&keys, &[], &BTreeMap::new());
    let names: Vec<&str> = rows.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, ["N_A", "N_B", "N_C"]);
}

#[test]
fn a_row_keeps_the_declared_product() {
    let rows = build(&[key("api", "DB_URL", ENV)], &[], &BTreeMap::new());
    assert_eq!(rows[0].product, "api");
}

#[test]
fn a_row_keeps_the_declared_key() {
    let rows = build(&[key("api", "DB_URL", ENV)], &[], &BTreeMap::new());
    assert_eq!(rows[0].key, "DB_URL");
}

#[test]
fn a_row_keeps_the_store_name() {
    let rows = build(&[key("api", "DB_URL", ENV)], &[], &BTreeMap::new());
    assert_eq!(rows[0].name, ENV);
}

#[test]
fn a_store_entry_is_matched_by_its_name() {
    let rows = build(
        &[key("api", "A", "N_A")],
        &[listed("N_B", Some("d1"))],
        &BTreeMap::new(),
    );
    assert_eq!(row(&rows, "N_A").state, "absent");
}

// ---- absent ----------------------------------------------------------------------

#[test]
fn a_declared_key_without_a_store_entry_is_absent() {
    let rows = build(&[key("api", "DB_URL", ENV)], &[], &BTreeMap::new());
    assert_eq!(row(&rows, ENV).state, "absent");
}

#[test]
fn an_absent_key_is_not_on_target() {
    let rows = build(&[key("api", "DB_URL", ENV)], &[], &BTreeMap::new());
    assert!(!row(&rows, ENV).on_target);
}

#[test]
fn an_absent_key_reports_no_store_version() {
    let rows = build(&[key("api", "DB_URL", ENV)], &[], &BTreeMap::new());
    assert_eq!(row(&rows, ENV).version, None);
}

#[test]
fn an_absent_key_is_not_pending() {
    let rows = build(&[key("api", "DB_URL", ENV)], &[], &BTreeMap::new());
    assert!(!row(&rows, ENV).pending);
}

#[test]
fn an_absent_key_has_no_stamp_written_time() {
    let rows = build(&[key("api", "DB_URL", ENV)], &[], &BTreeMap::new());
    assert_eq!(row(&rows, ENV).written, None);
}

// ---- listed entry: version, pending, stamp fields --------------------------------

#[test]
fn a_listed_key_is_on_target() {
    let rows = build(
        &[key("api", "DB_URL", ENV)],
        &[listed(ENV, Some("d1"))],
        &BTreeMap::new(),
    );
    assert!(row(&rows, ENV).on_target);
}

#[test]
fn a_listed_key_reports_the_store_version() {
    let rows = build(
        &[key("api", "DB_URL", ENV)],
        &[listed(ENV, Some("d1"))],
        &BTreeMap::new(),
    );
    assert_eq!(row(&rows, ENV).version.as_deref(), Some("d1"));
}

#[test]
fn a_pending_store_entry_marks_the_row_pending() {
    let mut e = listed(ENV, Some("d1"));
    e.pending = true;
    let rows = build(&[key("api", "DB_URL", ENV)], &[e], &BTreeMap::new());
    assert!(row(&rows, ENV).pending);
}

#[test]
fn a_stamped_entry_is_stamped() {
    let rows = build(
        &[key("api", "DB_URL", ENV)],
        &[stamped(ENV, "2026-10-08T14:02:11Z")],
        &BTreeMap::new(),
    );
    assert_eq!(row(&rows, ENV).state, "stamped");
}

#[test]
fn a_stamped_row_reports_the_stamp_written_time() {
    let rows = build(
        &[key("api", "DB_URL", ENV)],
        &[stamped(ENV, "2026-10-08T14:02:11Z")],
        &BTreeMap::new(),
    );
    assert_eq!(
        row(&rows, ENV).written.as_deref(),
        Some("2026-10-08T14:02:11Z")
    );
}

#[test]
fn a_stamped_row_reports_the_stamp_opv_version() {
    let rows = build(
        &[key("api", "DB_URL", ENV)],
        &[stamped(ENV, "2026-10-08T14:02:11Z")],
        &BTreeMap::new(),
    );
    assert_eq!(row(&rows, ENV).opv_version.as_deref(), Some("0.5.0"));
}

#[test]
fn a_stamped_row_reports_the_stamp_plan() {
    let rows = build(
        &[key("api", "DB_URL", ENV)],
        &[stamped(ENV, "2026-10-08T14:02:11Z")],
        &BTreeMap::new(),
    );
    assert_eq!(row(&rows, ENV).plan.as_deref(), Some("7f3c9a1e"));
}

#[test]
fn an_unstamped_entry_has_no_stamp_written_time() {
    let rows = build(
        &[key("api", "DB_URL", ENV)],
        &[listed(ENV, Some("d1"))],
        &BTreeMap::new(),
    );
    assert_eq!(row(&rows, ENV).written, None);
}

// ---- recorded_version and state from the ledger ----------------------------------

#[test]
fn a_recorded_version_equal_to_the_store_is_recorded() {
    let rows = build(
        &[key("api", "DB_URL", ENV)],
        &[listed(ENV, Some("d1"))],
        &recorded(&[(ENV, "d1")]),
    );
    assert_eq!(row(&rows, ENV).state, "recorded");
}

#[test]
fn a_recorded_version_differing_from_the_store_is_changed_outside_opv() {
    let rows = build(
        &[key("api", "DB_URL", ENV)],
        &[listed(ENV, Some("d1"))],
        &recorded(&[(ENV, "d0")]),
    );
    assert_eq!(row(&rows, ENV).state, "changed_outside_opv");
}

#[test]
fn a_recorded_version_with_no_store_version_is_changed_outside_opv() {
    let rows = build(
        &[key("api", "DB_URL", ENV)],
        &[listed(ENV, None)],
        &recorded(&[(ENV, "d1")]),
    );
    assert_eq!(row(&rows, ENV).state, "changed_outside_opv");
}

#[test]
fn a_listed_key_the_ledger_never_saw_is_not_recorded() {
    let rows = build(
        &[key("api", "DB_URL", ENV)],
        &[listed(ENV, Some("d1"))],
        &BTreeMap::new(),
    );
    assert_eq!(row(&rows, ENV).state, "not_recorded");
}

#[test]
fn a_recorded_row_reports_the_ledger_version() {
    let rows = build(
        &[key("api", "DB_URL", ENV)],
        &[listed(ENV, Some("d1"))],
        &recorded(&[(ENV, "d1")]),
    );
    assert_eq!(row(&rows, ENV).recorded_version.as_deref(), Some("d1"));
}

#[test]
fn an_unrecorded_row_reports_no_ledger_version() {
    let rows = build(
        &[key("api", "DB_URL", ENV)],
        &[listed(ENV, Some("d1"))],
        &BTreeMap::new(),
    );
    assert_eq!(row(&rows, ENV).recorded_version, None);
}

#[test]
fn a_stamped_row_reports_the_ledger_version_too() {
    let rows = build(
        &[key("api", "DB_URL", ENV)],
        &[stamped(ENV, "2026-10-08T14:02:11Z")],
        &recorded(&[(ENV, "d1")]),
    );
    assert_eq!(row(&rows, ENV).recorded_version.as_deref(), Some("d1"));
}

#[test]
fn an_absent_row_still_reports_the_ledger_version() {
    let rows = build(&[key("api", "DB_URL", ENV)], &[], &recorded(&[(ENV, "d1")]));
    assert_eq!(row(&rows, ENV).recorded_version.as_deref(), Some("d1"));
}

// ---- latest_written --------------------------------------------------------------

#[test]
fn latest_written_picks_the_most_recent_stamp() {
    let rows = build(
        &[key("api", "A", "N_A"), key("api", "B", "N_B")],
        &[
            stamped("N_A", "2026-10-08T14:02:11Z"),
            stamped("N_B", "2026-12-01T00:00:00Z"),
        ],
        &BTreeMap::new(),
    );
    assert_eq!(latest_written(&rows), Some("2026-12-01T00:00:00Z"));
}

#[test]
fn latest_written_ignores_rows_without_a_written_time() {
    let rows = build(
        &[key("api", "A", "N_A"), key("api", "B", "N_B")],
        &[
            listed("N_A", Some("d1")),
            stamped("N_B", "2026-10-08T14:02:11Z"),
        ],
        &BTreeMap::new(),
    );
    assert_eq!(latest_written(&rows), Some("2026-10-08T14:02:11Z"));
}

#[test]
fn latest_written_is_none_without_any_stamp() {
    let rows = build(
        &[key("api", "DB_URL", ENV)],
        &[listed(ENV, Some("d1"))],
        &BTreeMap::new(),
    );
    assert_eq!(latest_written(&rows), None);
}

#[test]
fn latest_written_is_none_for_no_rows() {
    assert_eq!(latest_written(&[]), None);
}
