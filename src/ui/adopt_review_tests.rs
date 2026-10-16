use super::*;
use serde_json::json;

/// A row with the given action and its default decision; the label is irrelevant unless the
/// test sets it.
fn row(action: &str) -> ReviewRow {
    ReviewRow {
        product: Some("api".into()),
        key: Some("TOKEN".into()),
        label: "api/TOKEN".into(),
        action: action.into(),
        found: Vec::new(),
        immutable: false,
        decision: default_decision(action),
    }
}

// ---- rows_from ----

/// An adopt document as the UI reads it.
fn adopt(v: serde_json::Value) -> crate::ui::docs::AdoptDoc {
    serde_json::from_value(v).unwrap()
}

#[test]
fn rows_from_builds_one_row_per_document_row() {
    let doc = adopt(json!({ "rows": [
        { "found": ["A"], "product": "api", "key": "TOKEN", "action": "import" },
        { "found": ["B"], "product": null, "key": null, "action": "match" },
    ] }));
    assert_eq!(
        rows_from(&doc, &|_, _| String::new(), &|_, _| false).len(),
        2
    );
}

#[test]
fn rows_from_uses_the_label_closure_for_a_keyed_row() {
    let doc = adopt(json!({ "rows": [
        { "found": [], "product": "api", "key": "TOKEN", "action": "import" },
    ] }));
    let label = |p: &str, k: &str| format!("{p}/{k}");
    assert_eq!(rows_from(&doc, &label, &|_, _| false)[0].label, "api/TOKEN");
}

#[test]
fn rows_from_joins_found_names_for_a_keyless_row() {
    let doc = adopt(json!({ "rows": [
        { "found": ["A", "B"], "product": null, "key": null, "action": "match" },
    ] }));
    let label = |_: &str, _: &str| panic!("label must not be called for a keyless row");
    assert_eq!(rows_from(&doc, &label, &|_, _| false)[0].label, "A, B");
}

#[test]
fn rows_from_reads_immutable_from_the_closure() {
    let doc = adopt(json!({ "rows": [
        { "found": [], "product": "api", "key": "TOKEN", "action": "differs" },
    ] }));
    assert!(rows_from(&doc, &|_, _| String::new(), &|_, _| true)[0].immutable);
}

#[test]
fn rows_from_treats_a_keyless_row_as_mutable() {
    let doc = adopt(json!({ "rows": [
        { "found": ["A"], "product": null, "key": null, "action": "match" },
    ] }));
    assert!(!rows_from(&doc, &|_, _| String::new(), &|_, _| true)[0].immutable);
}

#[test]
fn rows_from_keeps_the_found_names() {
    let doc = adopt(json!({ "rows": [
        { "found": ["A", "B"], "product": "api", "key": "TOKEN", "action": "import" },
    ] }));
    assert_eq!(
        rows_from(&doc, &|_, _| String::new(), &|_, _| false)[0].found,
        ["A", "B"]
    );
}

#[test]
fn rows_from_takes_the_default_decision_from_the_action() {
    let doc = adopt(json!({ "rows": [
        { "found": [], "product": "api", "key": "TOKEN", "action": "import" },
    ] }));
    assert_eq!(
        rows_from(&doc, &|_, _| String::new(), &|_, _| false)[0].decision,
        Some(Decision::Take)
    );
}

#[test]
fn rows_from_returns_no_rows_for_a_missing_rows_field() {
    assert!(rows_from(&adopt(json!({})), &|_, _| String::new(), &|_, _| false).is_empty());
}

// ---- default_decision ----

#[test]
fn a_differs_action_defaults_to_keep() {
    assert_eq!(default_decision("differs"), Some(Decision::Keep));
}

#[test]
fn a_match_action_defaults_to_no_decision() {
    assert_eq!(default_decision("match"), None);
}

// ---- toggle ----

#[test]
fn toggling_a_taken_import_skips_it() {
    let mut r = row("import");
    r.decision = Some(Decision::Take);
    assert_eq!(toggle(&r), Some(Decision::Skip));
}

#[test]
fn toggling_a_skipped_import_takes_it() {
    let mut r = row("import");
    r.decision = Some(Decision::Skip);
    assert_eq!(toggle(&r), Some(Decision::Take));
}

#[test]
fn toggling_a_kept_differs_takes_it() {
    let r = row("differs");
    assert_eq!(toggle(&r), Some(Decision::Take));
}

#[test]
fn toggling_a_taken_differs_skips_it() {
    let mut r = row("differs");
    r.decision = Some(Decision::Take);
    assert_eq!(toggle(&r), Some(Decision::Skip));
}

#[test]
fn toggling_a_skipped_differs_keeps_it() {
    let mut r = row("differs");
    r.decision = Some(Decision::Skip);
    assert_eq!(toggle(&r), Some(Decision::Keep));
}

#[test]
fn toggling_an_undecided_row_stays_undecided() {
    let r = row("match");
    assert_eq!(toggle(&r), None);
}

// ---- writes ----

#[test]
fn writes_counts_only_taken_rows() {
    let rows = [
        row("import"),
        row("differs"),
        {
            let mut r = row("import");
            r.decision = Some(Decision::Skip);
            r
        },
        row("match"),
    ];
    assert_eq!(writes(&rows), 1);
}

// ---- command ----

#[test]
fn command_starts_with_adopt_env_and_from() {
    assert_eq!(
        command("staging", "file.env", &[])[..4],
        ["adopt", "staging", "--from", "file.env"]
    );
}

#[test]
fn command_skips_a_skipped_import() {
    let mut r = row("import");
    r.decision = Some(Decision::Skip);
    r.label = "api/TOKEN".into();
    assert_eq!(
        command("staging", "file.env", &[r]),
        [
            "adopt",
            "staging",
            "--from",
            "file.env",
            "--skip",
            "api/TOKEN",
            "--apply"
        ]
    );
}

#[test]
fn command_replaces_a_taken_differs() {
    let mut r = row("differs");
    r.decision = Some(Decision::Take);
    r.label = "api/TOKEN".into();
    assert_eq!(
        command("staging", "file.env", &[r]),
        [
            "adopt",
            "staging",
            "--from",
            "file.env",
            "--replace",
            "api/TOKEN",
            "--apply"
        ]
    );
}

#[test]
fn command_rotates_a_taken_immutable_differs() {
    let mut r = row("differs");
    r.decision = Some(Decision::Take);
    r.immutable = true;
    r.label = "api/TOKEN".into();
    assert_eq!(
        command("staging", "file.env", &[r]),
        [
            "adopt",
            "staging",
            "--from",
            "file.env",
            "--replace",
            "api/TOKEN",
            "--rotate",
            "api/TOKEN",
            "--apply"
        ]
    );
}

#[test]
fn command_leaves_untouched_import_and_differs_rows_to_apply_only() {
    let rows = [row("import"), row("differs")];
    assert_eq!(
        command("staging", "file.env", &rows),
        ["adopt", "staging", "--from", "file.env", "--apply"]
    );
}

#[test]
fn command_ignores_a_row_with_no_decision() {
    let r = row("match");
    assert_eq!(
        command("staging", "file.env", &[r]),
        ["adopt", "staging", "--from", "file.env", "--apply"]
    );
}

#[test]
fn command_always_ends_with_apply() {
    let mut r = row("import");
    r.decision = Some(Decision::Skip);
    assert_eq!(
        command("staging", "file.env", &[r]).last().unwrap(),
        "--apply"
    );
}
