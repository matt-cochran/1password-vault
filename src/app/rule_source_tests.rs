//! Temp-repo tests for [`super`] (design row `rule-source`): each builds a real git
//! repository, commits a contract on the default branch, and asserts one status.

use super::*;
use crate::domain::plan::{PlanOptions, RuleGate, build_with_gate};
use crate::domain::{ItemField, KeyState, Kind, SecretValue};
use crate::runner::{Outcome, ProcessRunner};
use std::path::Path;

/// A run-only configuration: no value, no target.
const BASE: &str = "[environments.dev]\nboundaries.app = { vault_id = \"vdev0000000000000000000001\", item_id = \"app\" }\n\n[products.app.keys.API_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\n";

/// `BASE` with `API_KEY.rules.prefix` set to `prefix`.
fn with_rule(prefix: &str) -> String {
    format!("{BASE}rules = {{ prefix = \"{prefix}\" }}\n")
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

/// A fresh repository whose default branch is `main` (no `origin/HEAD` yet).
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

fn write_contract(dir: &Path, text: &str) {
    std::fs::write(dir.join("secrets.toml"), text).unwrap();
}

fn commit(dir: &Path, message: &str) {
    let r = runner();
    git(&r, dir, &["add", "secrets.toml"]);
    git(&r, dir, &["commit", "-q", "--no-gpg-sign", "-m", message]);
}

fn set_origin_head(dir: &Path, branch: &str) {
    let r = runner();
    let target = format!("refs/remotes/origin/{branch}");
    git(
        &r,
        dir,
        &["symbolic-ref", "refs/remotes/origin/HEAD", &target],
    );
}

fn load(dir: &Path) -> Fleet {
    crate::config::load(dir.join("secrets.toml")).unwrap()
}

// --- rule status ---------------------------------------------------------------------------

#[test]
fn a_rule_committed_on_the_default_branch_is_committed() {
    let dir = repo();
    write_contract(dir.path(), &with_rule("sk-"));
    commit(dir.path(), "contract");
    set_origin_head(dir.path(), "main");
    let working = load(dir.path());
    let source = rule_source(&runner(), dir.path(), &working).unwrap();
    assert_eq!(
        source.status(&working, "app", "API_KEY"),
        RuleStatus::Committed
    );
}

#[test]
fn a_rule_only_in_the_working_tree_is_pending_review() {
    let dir = repo();
    write_contract(dir.path(), BASE);
    commit(dir.path(), "base");
    set_origin_head(dir.path(), "main");
    write_contract(dir.path(), &with_rule("sk-"));
    let working = load(dir.path());
    let source = rule_source(&runner(), dir.path(), &working).unwrap();
    assert_eq!(
        source.status(&working, "app", "API_KEY"),
        RuleStatus::PendingReview
    );
}

#[test]
fn a_rule_only_on_another_branch_is_pending_review() {
    let dir = repo();
    write_contract(dir.path(), BASE);
    commit(dir.path(), "base");
    set_origin_head(dir.path(), "main");
    let r = runner();
    git(&r, dir.path(), &["checkout", "-q", "-b", "feature"]);
    write_contract(dir.path(), &with_rule("sk-"));
    commit(dir.path(), "rule on feature");
    let working = load(dir.path());
    let source = rule_source(&r, dir.path(), &working).unwrap();
    assert_eq!(
        source.status(&working, "app", "API_KEY"),
        RuleStatus::PendingReview
    );
}

#[test]
fn a_rule_hand_edited_into_the_working_tree_is_pending_review() {
    let dir = repo();
    write_contract(dir.path(), &with_rule("sk-"));
    commit(dir.path(), "contract");
    set_origin_head(dir.path(), "main");
    write_contract(dir.path(), &with_rule("pk-"));
    let working = load(dir.path());
    let source = rule_source(&runner(), dir.path(), &working).unwrap();
    assert_eq!(
        source.status(&working, "app", "API_KEY"),
        RuleStatus::PendingReview
    );
}

// --- rule gate over a real repository (design row `rule-gate`) -----------------------------

/// Build one `API_KEY` value through [`build_with_gate`] with an agent gate whose pending
/// answer comes from the real [`RuleSource`]: the key reports `RulesPendingReview` exactly
/// when the working rule is not the committed one.
fn gated_state(source: &RuleSource, working: &Fleet) -> KeyState {
    let item = vec![ItemField {
        section: "app".into(),
        label: "API_KEY".into(),
        kind: Kind::Secret,
        value: SecretValue::new("sk-live".into()),
        concealed: true,
    }];
    let empty = std::collections::BTreeSet::new();
    let opts = PlanOptions {
        target: None,
        rotate: &empty,
        prune_immutable: &empty,
        digest: &|_| None,
        target_check: &|_, _| None,
        current: None,
    };
    let gate = RuleGate {
        agent: true,
        pending: &|p, k| source.status(working, p, k) == RuleStatus::PendingReview,
    };
    build_with_gate(working, "dev", item, &[], &opts, &gate)
        .rows
        .iter()
        .find(|r| r.key == "API_KEY")
        .unwrap()
        .state
        .clone()
}

#[test]
fn an_agent_holds_a_rule_only_in_the_working_tree_pending() {
    let dir = repo();
    write_contract(dir.path(), BASE);
    commit(dir.path(), "base");
    set_origin_head(dir.path(), "main");
    write_contract(dir.path(), &with_rule("sk-"));
    let working = load(dir.path());
    let source = rule_source(&runner(), dir.path(), &working).unwrap();
    assert_eq!(gated_state(&source, &working), KeyState::RulesPendingReview);
}

#[test]
fn an_agent_leaves_a_hand_edited_rule_pending() {
    let dir = repo();
    write_contract(dir.path(), &with_rule("sk-"));
    commit(dir.path(), "contract");
    set_origin_head(dir.path(), "main");
    write_contract(dir.path(), &with_rule("pk-"));
    let working = load(dir.path());
    let source = rule_source(&runner(), dir.path(), &working).unwrap();
    assert_eq!(gated_state(&source, &working), KeyState::RulesPendingReview);
}

#[test]
fn an_agent_evaluates_a_rule_committed_on_the_default_branch() {
    let dir = repo();
    write_contract(dir.path(), &with_rule("sk-"));
    commit(dir.path(), "contract");
    set_origin_head(dir.path(), "main");
    let working = load(dir.path());
    let source = rule_source(&runner(), dir.path(), &working).unwrap();
    assert_eq!(gated_state(&source, &working), KeyState::Ready);
}

// --- default branch and manifest -----------------------------------------------------------

#[test]
fn an_origin_head_names_the_default_branch() {
    let dir = repo();
    set_origin_head(dir.path(), "trunk");
    assert_eq!(default_branch(&runner(), dir.path()), "trunk");
}

#[test]
fn a_repository_without_origin_head_uses_main() {
    let dir = repo();
    assert_eq!(default_branch(&runner(), dir.path()), "main");
}

#[test]
fn a_manifest_key_is_pending_review() {
    let fleet =
        crate::config::parse_at(BASE, crate::config::Source::Manifest("opv · app")).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let source = rule_source(&runner(), dir.path(), &fleet).unwrap();
    assert_eq!(
        source.status(&fleet, "app", "API_KEY"),
        RuleStatus::PendingReview
    );
}

#[test]
fn a_manifest_configuration_is_a_manifest_source() {
    let fleet =
        crate::config::parse_at(BASE, crate::config::Source::Manifest("opv · app")).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let source = rule_source(&runner(), dir.path(), &fleet).unwrap();
    assert!(matches!(source, RuleSource::Manifest));
}
