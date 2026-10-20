//! Core tests for [`super`] (design row `scan-core`): a tiny in-test [`Pattern`] over a
//! temporary git repository, through the real [`ProcessRunner`]. Each test makes exactly
//! one behavioural assertion on the public [`Scan`] outcome.

use super::*;
use crate::runner::{Outcome, ProcessRunner};
use std::path::Path;

/// A tiny pattern for the core: every non-empty line is an observed name on its line.
struct Lines;

impl Pattern for Lines {
    fn language(&self) -> &'static str {
        "test"
    }

    fn applies(&self, path: &str) -> bool {
        path.ends_with(".env")
    }

    fn scan(&self, path: &str, text: &str) -> Vec<Observation> {
        text.lines()
            .enumerate()
            .filter(|(_, line)| !line.trim().is_empty())
            .map(|(i, line)| Observation {
                name: Some(line.trim().to_string()),
                file: path.to_string(),
                line: i + 1,
                kind: Kind::Observed,
            })
            .collect()
    }
}

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

fn write(dir: &Path, name: &str, text: &str) {
    std::fs::write(dir.join(name), text).unwrap();
}

fn commit(dir: &Path, name: &str, message: &str) {
    let r = runner();
    git(&r, dir, &["add", name]);
    git(&r, dir, &["commit", "-q", "--no-gpg-sign", "-m", message]);
}

fn collect(dir: &Path) -> Scan {
    let patterns: Vec<&dyn Pattern> = vec![&Lines];
    Scan::collect(&runner(), dir, &WorkTree, &patterns)
}

// --- the walker ----------------------------------------------------------------------------

#[test]
fn a_valid_name_is_observed() {
    let dir = repo();
    write(dir.path(), "app.env", "API_KEY\n");
    let scan = collect(dir.path());
    assert_eq!(scan.observations[0].name.as_deref(), Some("API_KEY"));
}

#[test]
fn a_gitignored_file_is_skipped() {
    let dir = repo();
    write(dir.path(), ".gitignore", "ignored.env\n");
    write(dir.path(), "kept.env", "API_KEY\n");
    write(dir.path(), "ignored.env", "SECRET_FILE\n");
    let scan = collect(dir.path());
    assert!(scan.observations.iter().all(|o| o.file != "ignored.env"));
}

#[test]
fn a_file_in_node_modules_is_skipped() {
    let dir = repo();
    std::fs::create_dir_all(dir.path().join("node_modules/pkg")).unwrap();
    write(dir.path(), "node_modules/pkg/index.env", "PACKAGE_KEY\n");
    let scan = collect(dir.path());
    assert!(scan.observations.is_empty());
}

// --- the name grammar and the ignore list --------------------------------------------------

#[test]
fn an_invalid_name_is_dropped() {
    let dir = repo();
    write(dir.path(), "app.env", "lower_case\n");
    let scan = collect(dir.path());
    assert!(scan.observations.is_empty());
}

#[test]
fn an_invalid_name_is_counted_as_skipped() {
    let dir = repo();
    write(dir.path(), "app.env", "lower_case\n");
    let scan = collect(dir.path());
    assert_eq!(scan.coverage.skipped_patterns, 1);
}

#[test]
fn a_runtime_name_is_dropped() {
    let dir = repo();
    write(dir.path(), "app.env", "PATH\n");
    let scan = collect(dir.path());
    assert!(scan.observations.is_empty());
}

#[test]
fn a_runtime_name_is_counted_as_skipped() {
    let dir = repo();
    write(dir.path(), "app.env", "PATH\n");
    let scan = collect(dir.path());
    assert_eq!(scan.coverage.skipped_patterns, 1);
}

// --- coverage ------------------------------------------------------------------------------

#[test]
fn coverage_counts_the_scanned_files() {
    let dir = repo();
    write(dir.path(), "a.env", "API_KEY\n");
    write(dir.path(), "b.env", "OTHER_KEY\n");
    let scan = collect(dir.path());
    assert_eq!(scan.coverage.files, 2);
}

#[test]
fn coverage_names_the_languages_scanned() {
    let dir = repo();
    write(dir.path(), "app.env", "API_KEY\n");
    let scan = collect(dir.path());
    assert_eq!(scan.coverage.languages, vec!["test".to_string()]);
}

// --- a revision tree -----------------------------------------------------------------------

#[test]
fn a_revision_tree_reads_the_committed_text_not_the_working_tree() {
    let dir = repo();
    write(dir.path(), "app.env", "COMMITTED_KEY\n");
    commit(dir.path(), "app.env", "committed");
    write(dir.path(), "app.env", "WORKING_KEY\n");
    let patterns: Vec<&dyn Pattern> = vec![&Lines];
    let scan = Scan::collect(&runner(), dir.path(), &Revision("HEAD"), &patterns);
    assert_eq!(scan.observations[0].name.as_deref(), Some("COMMITTED_KEY"));
}

// --- a directory without git (`opv needs --scan`) ------------------------------------------

#[test]
fn a_dir_tree_lists_a_file_outside_any_git_repository() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("svc")).unwrap();
    write(&dir.path().join("svc"), "app.env", "API_KEY\n");
    let patterns: Vec<&dyn Pattern> = vec![&Lines];
    let scan = Scan::collect(&runner(), dir.path(), &DirTree, &patterns);
    assert_eq!(scan.observations[0].file, "svc/app.env");
}

#[test]
fn a_dir_tree_prunes_a_skipped_directory() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("node_modules")).unwrap();
    write(&dir.path().join("node_modules"), "dep.env", "DEP_KEY\n");
    assert!(DirTree.files(&runner(), dir.path()).is_empty());
}
