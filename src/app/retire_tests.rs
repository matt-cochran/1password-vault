//! Temp-repo tests for [`super`] (design Part V, row `retire`): each builds a real git
//! repository through the real [`ProcessRunner`] and asserts one public outcome.

use super::*;
use crate::runner::{Call, Outcome, ProcessRunner};
use std::path::Path;

/// A contract with a `shared` `dev` and a `production` `prod`, both carrying `API_KEY`.
const TWO_ENVS: &str = "[environments.dev]\n\
tier = \"shared\"\n\
boundaries.app = { vault_id = \"vdev0000000000000000000001\", item_id = \"app\" }\n\n\
[environments.prod]\n\
tier = \"production\"\n\
boundaries.app = { vault_id = \"vprod000000000000000000001\", item_id = \"app\" }\n\n\
[products.app.keys.API_KEY]\n\
kind = \"secret\"\n\
environments = [\"dev\", \"prod\"]\n";

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

/// Commit `path` at `HEAD`.
fn commit(dir: &Path, path: &str) {
    let r = runner();
    git(&r, dir, &["add", path]);
    git(&r, dir, &["commit", "-q", "--no-gpg-sign", "-m", "work"]);
}

fn fleet(text: &str) -> Fleet {
    crate::config::parse(text).expect("the contract loads")
}

/// A `deployed` map naming `envs` at `HEAD`, in the shape the caller passes.
fn deployed(envs: &[&str]) -> BTreeMap<String, Option<String>> {
    envs.iter()
        .map(|e| ((*e).to_string(), Some("HEAD".to_string())))
        .collect()
}

/// A synthetic halt, to make a run stop part-way in a test.
fn stopped() -> Error {
    Cause::NeedsUndeclared {
        names: vec!["STOP".into()],
        product: None,
    }
    .into()
}

/// Retire with a step recorder, returning the report and the steps recorded so far.
fn run(
    fleet: &Fleet,
    dir: &Path,
    deployed: &BTreeMap<String, Option<String>>,
) -> (Result<RetireReport, Error>, Vec<RetireStep>) {
    let mut steps = Vec::new();
    let mut out = Vec::new();
    let result = retire(
        fleet,
        &runner(),
        dir,
        "app",
        "API_KEY",
        deployed,
        &mut |step| {
            steps.push(step);
            Ok(())
        },
        &mut out,
    );
    (result, steps)
}

// --- the deployed-revision gate ------------------------------------------------------------

#[test]
fn a_key_still_read_at_the_deployed_revision_refuses_with_the_dedicated_code() {
    let dir = repo();
    write(
        dir.path(),
        "src/lib.rs",
        "fn read() { let _ = std::env::var(\"API_KEY\"); }\n",
    );
    commit(dir.path(), "src/lib.rs");
    let (result, _) = run(&fleet(TWO_ENVS), dir.path(), &deployed(&["dev"]));
    assert_eq!(result.unwrap_err().code_str(), "retire_still_read");
}

#[test]
fn a_still_read_key_names_the_file_that_reads_it() {
    let dir = repo();
    write(
        dir.path(),
        "src/lib.rs",
        "fn read() { let _ = std::env::var(\"API_KEY\"); }\n",
    );
    commit(dir.path(), "src/lib.rs");
    let (result, _) = run(&fleet(TWO_ENVS), dir.path(), &deployed(&["dev"]));
    assert!(result.unwrap_err().mentions("src/lib.rs:1"));
}

#[test]
fn a_missing_deployed_receipt_refuses_with_the_same_code() {
    let dir = repo();
    write(dir.path(), "src/lib.rs", "fn main() {}\n");
    commit(dir.path(), "src/lib.rs");
    let no_receipt = BTreeMap::from([("dev".to_string(), None)]);
    let (result, _) = run(&fleet(TWO_ENVS), dir.path(), &no_receipt);
    assert_eq!(result.unwrap_err().code_str(), "retire_still_read");
}

#[test]
fn a_key_read_only_in_the_working_tree_proceeds() {
    let dir = repo();
    write(dir.path(), "src/lib.rs", "fn main() {}\n");
    commit(dir.path(), "src/lib.rs");
    write(
        dir.path(),
        "src/lib.rs",
        "fn read() { let _ = std::env::var(\"API_KEY\"); }\n",
    );
    let (result, _) = run(&fleet(TWO_ENVS), dir.path(), &deployed(&["dev"]));
    assert!(result.is_ok());
}

// --- the step order ------------------------------------------------------------------------

#[test]
fn shared_tiers_are_pruned_before_production() {
    let dir = repo();
    write(dir.path(), "src/lib.rs", "fn main() {}\n");
    commit(dir.path(), "src/lib.rs");
    let (result, _) = run(&fleet(TWO_ENVS), dir.path(), &deployed(&["prod", "dev"]));
    assert_eq!(
        result.unwrap().pruned,
        vec!["dev".to_string(), "prod".to_string()]
    );
}

#[test]
fn the_last_step_marks_the_key_retired() {
    let dir = repo();
    write(dir.path(), "src/lib.rs", "fn main() {}\n");
    commit(dir.path(), "src/lib.rs");
    let (_, steps) = run(&fleet(TWO_ENVS), dir.path(), &deployed(&["dev"]));
    assert_eq!(steps.last(), Some(&RetireStep::MarkRetired));
}

// --- resumability --------------------------------------------------------------------------

#[test]
fn a_re_run_after_a_partial_run_prunes_only_the_rest() {
    let dir = repo();
    write(dir.path(), "src/lib.rs", "fn main() {}\n");
    commit(dir.path(), "src/lib.rs");
    let both = deployed(&["dev", "prod"]);
    let mut out = Vec::new();
    // The first run prunes `dev`, then stops before pruning `prod`.
    let _ = retire(
        &fleet(TWO_ENVS),
        &runner(),
        dir.path(),
        "app",
        "API_KEY",
        &both,
        &mut |step| match step {
            RetireStep::Prune { ref env } if env == "prod" => Err(stopped()),
            _ => Ok(()),
        },
        &mut out,
    );
    // The caller's plan no longer holds the key in `dev`, so it retries with `prod` only.
    let rest = BTreeMap::from([("prod".to_string(), Some("HEAD".to_string()))]);
    let (second, _) = run(&fleet(TWO_ENVS), dir.path(), &rest);
    assert_eq!(second.unwrap().pruned, vec!["prod".to_string()]);
}

// --- the retiring prune guard ---------------------------------------------------------------

#[test]
fn the_prune_step_releases_a_retiring_key() {
    let step = RetireStep::Prune {
        env: "dev".to_string(),
    };
    assert!(step.retiring_prune());
}
