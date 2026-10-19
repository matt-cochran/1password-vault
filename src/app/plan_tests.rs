//! `plan`/`status` JSON target presence (#201 decision 2): a secret opv cannot compare
//! (target [`TargetState::Unknown`]) reads `unknown`, never `present`; `present` is only
//! for a value the target proved identical.

use serde_json::Value;

use super::json_target;
use super::sync;
use super::testutil::*;
use crate::domain::{Kind, TargetState};
use crate::runner::fake::FakeRunner;

/// `json_target` maps an uncomparable secret to `unknown` (the direct acceptance edge).
#[test]
fn json_target_reports_an_uncomparable_secret_as_unknown() {
    assert_eq!(
        json_target(Kind::Secret, TargetState::Unknown),
        Some("unknown")
    );
}

/// `json_target` maps a secret the target proved identical to `present`.
#[test]
fn json_target_reports_a_proven_secret_as_present() {
    assert_eq!(
        json_target(Kind::Secret, TargetState::Present),
        Some("present")
    );
}

/// The observable outcome: `plan --json` reports a Fly secret whose digest opv cannot
/// compute locally (so it stages and compares) as `target_state: "unknown"`.
#[test]
fn plan_json_reports_an_uncomparable_secret_target_as_unknown() {
    let r = FakeRunner::new([complete_item(), fly(&[(OPENAI_FLY, "d1")])]);
    let mut out = Vec::new();
    let _ = sync::plan_with(&fleet(), "prod", &r, &mut out, true);
    let doc: Value = serde_json::from_slice(&out).unwrap();
    let row = doc["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["key"] == "OPENAI_API_KEY")
        .unwrap();
    assert_eq!(row["target_state"], "unknown");
}
