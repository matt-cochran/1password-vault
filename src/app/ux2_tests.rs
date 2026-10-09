//! CLI UX pass 2 (0.5.0): field links (H1), problems first with full reasons (H4), one
//! state vocabulary (H5) and the CI step summary and `changes` field (H8). One behavioural
//! assertion per test; markers never reach a link, the summary or JSON.

use serde_json::Value;

use super::status;
use super::sync::{self, SyncOpts};
use super::testutil::*;
use crate::error::Error;
use crate::runner::Output;
use crate::runner::fake::FakeRunner;

const LINK: &str = "https://start.1password.com/open/i?a=ACC1&v=vprd&i=iprd&h=my.1password.com";

fn whoami() -> Output {
    Output::success(
        br#"{"url":"https://my.1password.com","email":"me-FIXTUREVALUE@example.com","user_uuid":"UFIXTUREVALUE","account_uuid":"ACC1","user_type":"USER"}"#
            .to_vec(),
    )
}

fn missing_openai() -> FakeRunner {
    FakeRunner::new([
        item_without("allumata", "OPENAI_API_KEY"),
        fly_empty(),
        whoami(),
    ])
}

fn status_text(r: &FakeRunner) -> (Result<(), Error>, String) {
    let mut out = Vec::new();
    let res = status::run(&fleet(), "prod", r, &mut out);
    (res, text_of(&out))
}

fn status_json(r: &FakeRunner) -> Value {
    let mut out = Vec::new();
    let _ = status::run_with(&fleet(), "prod", r, &mut out, true);
    serde_json::from_slice(&out).unwrap()
}

fn plan_json(r: &FakeRunner) -> Value {
    let mut out = Vec::new();
    let _ = sync::plan_with(&fleet(), "prod", r, &mut out, true);
    serde_json::from_slice(&out).unwrap()
}

fn plan_text(r: &FakeRunner) -> String {
    let mut out = Vec::new();
    let _ = sync::plan(&fleet(), "prod", r, &mut out);
    text_of(&out)
}

// ---- H1: links to the field in 1Password ---------------------------------------------

#[test]
fn status_links_a_missing_key_to_its_item_and_field() {
    let (_, out) = status_text(&missing_openai());
    assert!(
        out.contains(&format!(
            "    open: {LINK} (section allumata, field OPENAI_API_KEY)"
        )),
        "{out}"
    );
}

#[test]
fn status_link_carries_no_identity_or_value() {
    let (_, out) = status_text(&missing_openai());
    assert_no_values(&out);
}

#[test]
fn status_without_findings_makes_no_link_probe() {
    let r = FakeRunner::new([complete_item(), fly_empty()]);
    let _ = status_text(&r);
    assert!(!called(&r, "op", &["whoami"]));
}

#[test]
fn status_json_blocking_row_has_open_url() {
    let doc = status_json(&missing_openai());
    let row = doc["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["key"] == "OPENAI_API_KEY")
        .unwrap();
    assert_eq!(row["open_url"], LINK);
}

#[test]
fn status_json_saved_row_has_no_open_url() {
    let doc = status_json(&missing_openai());
    let row = doc["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["key"] == "SIGNUP_POLICY")
        .unwrap();
    assert!(row.get("open_url").is_none(), "{row}");
}

#[test]
fn status_json_never_carries_a_value() {
    let mut out = Vec::new();
    let _ = status::run_with(&fleet(), "prod", &missing_openai(), &mut out, true);
    assert_no_values(&text_of(&out));
}

#[test]
fn check_links_a_missing_key_to_its_field() {
    let r = FakeRunner::new([item_without("allumata", "OPENAI_API_KEY"), whoami()]);
    let mut out = Vec::new();
    let _ = super::local::check(&fleet(), "prod", Some("allumata"), &r, &mut out, false);
    assert!(
        text_of(&out).contains(&format!(
            "  open: {LINK} (section allumata, field OPENAI_API_KEY)"
        )),
        "{}",
        text_of(&out)
    );
}

#[test]
fn plan_links_a_missing_key_to_its_field() {
    let out = plan_text(&missing_openai());
    assert!(out.contains(&format!("    open: {LINK} (")), "{out}");
}

#[test]
fn explain_names_the_open_command() {
    let mut out = Vec::new();
    super::explain::run(&fleet(), "allumata/OPENAI_API_KEY", Some("prod"), &mut out).unwrap();
    assert!(
        text_of(&out).contains("open:       opv open allumata/OPENAI_API_KEY --env prod"),
        "{}",
        text_of(&out)
    );
}

// ---- H4: problems first, with the full reason ----------------------------------------

#[test]
fn status_lists_problem_rows_before_saved_rows() {
    let (_, out) = status_text(&missing_openai());
    let pos = |k: &str| out.find(k).unwrap();
    assert!(pos("OPENAI_API_KEY") < pos("INTEGRATION_ENC_KEY"), "{out}");
}

#[test]
fn wrong_kind_says_which_field_type_is_needed() {
    let r = FakeRunner::new([
        complete_with(text("allumata", "OPENAI_API_KEY", OPENAI)),
        fly_empty(),
        whoami(),
    ]);
    let (_, out) = status_text(&r);
    assert!(
        out.contains("wrong kind (stored as text; declared secret: use a concealed field)"),
        "{out}"
    );
}

#[test]
fn plan_with_findings_says_staging_waits_for_the_fix() {
    let out = plan_text(&missing_openai());
    assert!(
        out.contains("would stage once the findings are fixed: "),
        "{out}"
    );
}

// ---- H5: one state vocabulary ---------------------------------------------------------

#[test]
fn plan_explains_unknown_under_the_table() {
    let r = FakeRunner::new([complete_item(), fly(&[(OPENAI_FLY, "d1")])]);
    assert!(
        plan_text(&r).contains("unknown: Fly does not reveal stored values"),
        "{}",
        plan_text(&FakeRunner::new([
            complete_item(),
            fly(&[(OPENAI_FLY, "d1")])
        ]))
    );
}

#[test]
fn plan_shows_an_undesired_key_on_the_target_as_extra() {
    let r = FakeRunner::new([complete_item(), fly(&[(STRIPE_FLY, "d3")])]);
    let out = plan_text(&r);
    assert!(
        out.lines()
            .any(|l| l.contains("STRIPE_SECRET_KEY") && l.ends_with("extra")),
        "{out}"
    );
}

#[test]
fn states_help_defines_every_target_word() {
    for w in [
        "new", "same", "changed", "unknown", "pending", "held", "extra", "drift", "n/a",
    ] {
        assert!(super::STATES_HELP.contains(&format!("\n  {w:<11} ")), "{w}");
    }
}

// ---- H8: CI step summary and `changes` -----------------------------------------------

#[test]
fn plan_writes_a_step_summary_table() {
    let r = FakeRunner::new([complete_item(), fly_empty()]);
    let _ = plan_text(&r);
    assert!(
        r.summaries.borrow()[0].contains("| allumata | OPENAI_API_KEY | secret | saved | new |"),
        "{:?}",
        r.summaries.borrow()
    );
}

#[test]
fn step_summary_carries_no_value_link_or_identity() {
    let r = missing_openai();
    let _ = status_text(&r);
    let md = r.summaries.borrow().join("\n");
    assert!(
        !md.contains(MARKER) && !md.contains("1password.com"),
        "{md}"
    );
}

#[test]
fn sync_writes_its_summary_line_to_the_step_summary() {
    let [st, rel] = fly_preflight_ok();
    let r = FakeRunner::new([
        complete_item(),
        fly_empty(),
        st,
        rel,
        ok(),
        fly(&[(OPENAI_FLY, "d1"), (ENC_FLY, "d2")]),
    ]);
    let _ = sync::run(&fleet(), "prod", &r, &mut Vec::new(), &SyncOpts::default());
    assert!(
        r.summaries.borrow()[0].contains("summary: written 2"),
        "{:?}",
        r.summaries.borrow()
    );
}

#[test]
fn plan_json_changes_is_some_for_a_new_key() {
    let doc = plan_json(&FakeRunner::new([complete_item(), fly_empty()]));
    assert_eq!(doc["changes"], "some");
}

#[test]
fn plan_json_changes_is_unknown_when_only_hidden_values_would_stage() {
    let doc = plan_json(&FakeRunner::new([
        complete_item(),
        fly(&[(OPENAI_FLY, "d1"), (ENC_FLY, "d2")]),
    ]));
    assert_eq!(doc["changes"], "unknown");
}
