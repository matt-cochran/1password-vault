//! Temp-repo tests for [`super`] (design Part V, row `needs`): each builds a real git
//! repository through the real [`ProcessRunner`] and asserts one public outcome.

use super::*;
use crate::domain::span_of;
use crate::runner::{Call, Outcome, ProcessRunner};
use std::path::Path;

/// A run-only contract that declares `API_KEY` in `dev`.
const DECLARED: &str = "[environments.dev]\n\
boundaries.app = { vault_id = \"vdev0000000000000000000001\", item_id = \"app\" }\n\n\
[products.app.keys.API_KEY]\n\
kind = \"secret\"\n\
environments = [\"dev\"]\n";

fn runner() -> ProcessRunner {
    ProcessRunner::default()
}

/// Run one git command through the real [`ProcessRunner`]; panic unless it exits 0.
fn git(r: &ProcessRunner, dir: &Path, args: &[&str]) {
    let mut argv = vec!["-C", dir.to_str().expect("utf-8 temp path")];
    argv.extend_from_slice(args);
    match r.write(&Call::new("git", &argv)).unwrap() {
        Outcome::Done(_) => {}
        other => panic!("git {args:?} did not exit 0: {other:?}"),
    }
}

/// A fresh repository whose default branch is `main`.
fn repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let r = runner();
    git(&r, dir.path(), &["init", "-q"]);
    git(&r, dir.path(), &["symbolic-ref", "HEAD", "refs/heads/main"]);
    git(
        &r,
        dir.path(),
        &["config", "user.email", "test@example.com"],
    );
    git(&r, dir.path(), &["config", "user.name", "Test"]);
    dir
}

/// Write `text` at `path` under `dir`, creating its parent directories.
fn write(dir: &Path, path: &str, text: &str) {
    let full = dir.join(path);
    if let Some(parent) = full.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(full, text).unwrap();
}

fn fleet(text: &str) -> Fleet {
    crate::config::parse(text).expect("the contract loads")
}

/// The `needs` report for `dir` against `text`, scanning the working tree.
fn report(dir: &Path, text: &str) -> NeedsReport {
    needs(&runner(), dir, &crate::scan::WorkTree, &fleet(text), None)
}

/// The state of `name`, or `None` when it is not a row.
fn state_of(report: &NeedsReport, name: &str) -> Option<NeedState> {
    report.rows.iter().find(|r| r.name == name).map(|r| r.state)
}

/// `DECLARED` plus one ignore annotation for `name` with `span`.
fn with_ignore(name: &str, span: &str) -> String {
    format!(
        "{DECLARED}\n[products.app.ignore]\n{name} = {{ reason = \"false positive\", span = \"{span}\" }}\n"
    )
}

// --- one test per state --------------------------------------------------------------------

#[test]
fn an_observed_name_the_contract_does_not_declare_is_undeclared() {
    let dir = repo();
    write(dir.path(), ".env.example", "UNDECLARED_TOKEN=whatever\n");
    let report = report(dir.path(), DECLARED);
    assert_eq!(
        state_of(&report, "UNDECLARED_TOKEN"),
        Some(NeedState::Undeclared)
    );
}

#[test]
fn a_declared_name_no_code_reads_is_declared_unobserved() {
    let dir = repo();
    write(dir.path(), "src/lib.rs", "fn main() {}\n");
    let report = report(dir.path(), DECLARED);
    assert_eq!(
        state_of(&report, "API_KEY"),
        Some(NeedState::DeclaredUnobserved)
    );
}

#[test]
fn a_computed_name_read_is_ambiguous() {
    let dir = repo();
    write(
        dir.path(),
        "src/lib.rs",
        "fn read(name: &str) { let _ = std::env::var(name); }\n",
    );
    let report = report(dir.path(), DECLARED);
    assert!(report.rows.iter().any(|r| r.state == NeedState::Ambiguous));
}

#[test]
fn a_name_both_declared_and_read_is_declared() {
    let dir = repo();
    write(dir.path(), ".env.example", "API_KEY=whatever\n");
    let report = report(dir.path(), DECLARED);
    assert_eq!(state_of(&report, "API_KEY"), Some(NeedState::Declared));
}

// --- names delivered by a target's template ------------------------------------------------

/// A contract that declares `web/API_KEY` in `prod` and delivers it to a Fly target as
/// `E2E__WEB__API_KEY`.
const DELIVERED: &str = "[environments.prod]\n\
boundaries.web = { vault_id = \"vprod000000000000000000001\", item_id = \"web\" }\n\n\
[environments.prod.targets.fly]\n\
fly.app = \"e2e-app-prod\"\n\
fly.secret_name = \"E2E__{PRODUCT}__{KEY}\"\n\n\
[products.web]\n\
boundary = \"web\"\n\n\
[products.web.keys.API_KEY]\n\
kind = \"secret\"\n\
environments = [\"prod\"]\n";

#[test]
fn a_name_delivered_by_a_target_template_is_declared() {
    let dir = repo();
    write(
        dir.path(),
        "src/lib.rs",
        "fn read() { let _ = std::env::var(\"E2E__WEB__API_KEY\"); }\n",
    );
    let report = report(dir.path(), DELIVERED);
    let row = report.rows.iter().find(|r| r.files == ["src/lib.rs:1"]);
    assert_eq!(
        row.map(|r| (r.state, r.product.as_deref(), r.name.as_str())),
        Some((NeedState::Declared, Some("web"), "API_KEY"))
    );
}

#[test]
fn a_key_read_only_by_its_delivered_name_is_observed() {
    let dir = repo();
    write(
        dir.path(),
        "src/lib.rs",
        "fn read() { let _ = std::env::var(\"E2E__WEB__API_KEY\"); }\n",
    );
    let report = report(dir.path(), DELIVERED);
    assert!(
        !report
            .rows
            .iter()
            .any(|r| r.state == NeedState::DeclaredUnobserved)
    );
}

#[test]
fn a_name_matching_no_template_stays_undeclared() {
    let dir = repo();
    write(
        dir.path(),
        "src/lib.rs",
        "fn read() { let _ = std::env::var(\"E2E__API__API_KEY\"); }\n",
    );
    let report = report(dir.path(), DELIVERED);
    assert_eq!(
        state_of(&report, "E2E__API__API_KEY"),
        Some(NeedState::Undeclared)
    );
}

#[test]
fn the_gate_passes_when_the_default_branch_delivers_the_name() {
    let dir = repo();
    write(
        dir.path(),
        "src/lib.rs",
        "fn read() { let _ = std::env::var(\"E2E__WEB__API_KEY\"); }\n",
    );
    let current = fleet(DECLARED);
    let base = fleet(DELIVERED);
    let report = needs(
        &runner(),
        dir.path(),
        &crate::scan::WorkTree,
        &current,
        None,
    );
    assert!(gate(&report, Some(&base), &current).is_ok());
}

// --- ignore annotations --------------------------------------------------------------------

#[test]
fn an_ignore_whose_span_changed_shows_the_name_again_as_undeclared() {
    let dir = repo();
    write(
        dir.path(),
        "src/lib.rs",
        "fn read() { let _ = std::env::var(\"JUNK_TOKEN\"); }\n",
    );
    let report = report(dir.path(), &with_ignore("JUNK_TOKEN", "deadbeefdeadbeef"));
    assert_eq!(state_of(&report, "JUNK_TOKEN"), Some(NeedState::Undeclared));
}

#[test]
fn a_stale_ignore_is_marked_annotation_stale() {
    let dir = repo();
    write(
        dir.path(),
        "src/lib.rs",
        "fn read() { let _ = std::env::var(\"JUNK_TOKEN\"); }\n",
    );
    let report = report(dir.path(), &with_ignore("JUNK_TOKEN", "deadbeefdeadbeef"));
    let stale = report
        .rows
        .iter()
        .find(|r| r.name == "JUNK_TOKEN")
        .map(|r| r.annotation_stale);
    assert_eq!(stale, Some(true));
}

#[test]
fn an_ignore_with_the_current_span_hides_the_name() {
    let dir = repo();
    write(dir.path(), ".env.example", "JUNK_TOKEN=whatever\n");
    let span = span_of(".env.example", "JUNK_TOKEN");
    let report = report(dir.path(), &with_ignore("JUNK_TOKEN", &span));
    assert_eq!(state_of(&report, "JUNK_TOKEN"), None);
}

// --- the gate ------------------------------------------------------------------------------

#[test]
fn the_gate_fails_on_an_undeclared_name_the_default_branch_lacks() {
    let dir = repo();
    write(dir.path(), ".env.example", "UNDECLARED_TOKEN=whatever\n");
    let report = report(dir.path(), DECLARED);
    assert!(gate(&report, None, &fleet(DECLARED)).is_err());
}

#[test]
fn the_gate_passes_when_the_default_branch_declares_the_name() {
    let dir = repo();
    write(dir.path(), ".env.example", "UNDECLARED_TOKEN=whatever\n");
    let report = report(dir.path(), DECLARED);
    let base = fleet(&format!(
        "{DECLARED}[products.app.keys.UNDECLARED_TOKEN]\nkind = \"secret\"\nenvironments = [\"dev\"]\n"
    ));
    assert!(gate(&report, Some(&base), &base).is_ok());
}

// --- value boundary canary -----------------------------------------------------------------

#[test]
fn the_canary_marker_never_appears_in_the_text_report() {
    let dir = repo();
    write(dir.path(), ".env.example", "API_KEY=S7MARKER-needs\n");
    let report = report(dir.path(), DECLARED);
    let mut out = Vec::new();
    render_text(&report, &mut out).unwrap();
    assert!(!String::from_utf8(out).unwrap().contains("S7MARKER"));
}

#[test]
fn the_canary_marker_never_appears_in_the_json_report() {
    let dir = repo();
    write(dir.path(), ".env.example", "API_KEY=S7MARKER-needs\n");
    let report = report(dir.path(), DECLARED);
    assert!(!serde_json::to_string(&report).unwrap().contains("S7MARKER"));
}
