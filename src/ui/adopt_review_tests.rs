use super::*;

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

/// `opv import <env> --from <file> --dry-run --json`, recorded (`tests/fixtures/ui/`).
fn import_doc() -> crate::ui::docs::AdoptDoc {
    let bytes = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/ui/import-local-dry-run.json"),
    )
    .unwrap();
    crate::ui::docs::parse(&bytes).unwrap()
}

#[test]
fn rows_from_builds_one_row_per_document_row() {
    assert_eq!(
        rows_from(&import_doc(), &|_, _| String::new(), &|_, _| false).len(),
        3
    );
}

#[test]
fn rows_from_uses_the_label_closure_for_a_keyed_row() {
    let label = |p: &str, k: &str| format!("{p}/{k}");
    assert_eq!(
        rows_from(&import_doc(), &label, &|_, _| false)[0].label,
        "api/API_TOKEN"
    );
}

#[test]
fn rows_from_joins_found_names_for_a_keyless_row() {
    let label = |p: &str, k: &str| format!("{p}/{k}");
    assert_eq!(
        rows_from(&import_doc(), &label, &|_, _| false)[2].label,
        "STRAY"
    );
}

#[test]
fn rows_from_reads_immutable_from_the_closure() {
    let doc = import_doc();
    assert!(rows_from(&doc, &|_, _| String::new(), &|_, _| true)[1].immutable);
}

#[test]
fn rows_from_treats_a_keyless_row_as_mutable() {
    assert!(!rows_from(&import_doc(), &|_, _| String::new(), &|_, _| true)[2].immutable);
}

#[test]
fn rows_from_keeps_the_found_names() {
    assert_eq!(
        rows_from(&import_doc(), &|_, _| String::new(), &|_, _| false)[0].found,
        ["API_TOKEN"]
    );
}

#[test]
fn rows_from_takes_the_default_decision_from_the_action() {
    assert_eq!(
        rows_from(&import_doc(), &|_, _| String::new(), &|_, _| false)[0].decision,
        Some(Decision::Take)
    );
}

#[test]
fn rows_from_returns_no_rows_for_a_missing_rows_field() {
    let doc: crate::ui::docs::AdoptDoc = serde_json::from_value(serde_json::json!({})).unwrap();
    assert!(rows_from(&doc, &|_, _| String::new(), &|_, _| false).is_empty());
}

// ---- default_decision ----

#[test]
fn a_skipped_already_set_action_defaults_to_keep() {
    assert_eq!(
        default_decision("skipped_already_set"),
        Some(Decision::Keep)
    );
}

#[test]
fn an_imported_action_defaults_to_take() {
    assert_eq!(default_decision("imported"), Some(Decision::Take));
}

#[test]
fn a_not_declared_action_defaults_to_no_decision() {
    assert_eq!(default_decision("not_declared"), None);
}

// ---- toggle ----

#[test]
fn toggling_a_taken_imported_skips_it() {
    let mut r = row("imported");
    r.decision = Some(Decision::Take);
    assert_eq!(toggle(&r), Some(Decision::Skip));
}

#[test]
fn toggling_a_skipped_imported_takes_it() {
    let mut r = row("imported");
    r.decision = Some(Decision::Skip);
    assert_eq!(toggle(&r), Some(Decision::Take));
}

#[test]
fn toggling_a_kept_skipped_already_set_takes_it() {
    let r = row("skipped_already_set");
    assert_eq!(toggle(&r), Some(Decision::Take));
}

#[test]
fn toggling_a_taken_skipped_already_set_skips_it() {
    let mut r = row("skipped_already_set");
    r.decision = Some(Decision::Take);
    assert_eq!(toggle(&r), Some(Decision::Skip));
}

#[test]
fn toggling_a_skipped_skipped_already_set_keeps_it() {
    let mut r = row("skipped_already_set");
    r.decision = Some(Decision::Skip);
    assert_eq!(toggle(&r), Some(Decision::Keep));
}

#[test]
fn toggling_an_undecided_row_stays_undecided() {
    let r = row("not_declared");
    assert_eq!(toggle(&r), None);
}

// ---- writes ----

#[test]
fn writes_counts_only_taken_rows() {
    let rows = [
        row("imported"),
        row("skipped_already_set"),
        {
            let mut r = row("imported");
            r.decision = Some(Decision::Skip);
            r
        },
        row("not_declared"),
    ];
    assert_eq!(writes(&rows), 1);
}

// ---- command ----

#[test]
fn command_starts_with_import_env_and_from() {
    assert_eq!(
        command("staging", "file.env", &[])[..4],
        ["import", "staging", "--from", "file.env"]
    );
}

#[test]
fn command_skips_a_skipped_imported() {
    let mut r = row("imported");
    r.decision = Some(Decision::Skip);
    r.label = "api/TOKEN".into();
    assert_eq!(
        command("staging", "file.env", &[r]),
        [
            "import",
            "staging",
            "--from",
            "file.env",
            "--skip",
            "api/TOKEN"
        ]
    );
}

#[test]
fn command_replaces_a_taken_skipped_already_set() {
    let mut r = row("skipped_already_set");
    r.decision = Some(Decision::Take);
    r.label = "api/TOKEN".into();
    assert_eq!(
        command("staging", "file.env", &[r]),
        [
            "import",
            "staging",
            "--from",
            "file.env",
            "--replace",
            "api/TOKEN"
        ]
    );
}

#[test]
fn command_rotates_a_taken_immutable_skipped_already_set() {
    let mut r = row("skipped_already_set");
    r.decision = Some(Decision::Take);
    r.immutable = true;
    r.label = "api/TOKEN".into();
    assert_eq!(
        command("staging", "file.env", &[r]),
        [
            "import",
            "staging",
            "--from",
            "file.env",
            "--replace",
            "api/TOKEN",
            "--rotate",
            "api/TOKEN"
        ]
    );
}

#[test]
fn command_leaves_untouched_imported_and_skipped_already_set_rows_to_no_flags() {
    let rows = [row("imported"), row("skipped_already_set")];
    assert_eq!(
        command("staging", "file.env", &rows),
        ["import", "staging", "--from", "file.env"]
    );
}

#[test]
fn command_ignores_a_row_with_no_decision() {
    let r = row("not_declared");
    assert_eq!(
        command("staging", "file.env", &[r]),
        ["import", "staging", "--from", "file.env"]
    );
}

#[test]
fn command_never_appends_apply() {
    let mut r = row("imported");
    r.decision = Some(Decision::Skip);
    assert!(!command("staging", "file.env", &[r]).contains(&"--apply".to_string()));
}
