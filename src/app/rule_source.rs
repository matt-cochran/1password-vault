//! Which rules count (H1, design Part V default 2, R3): a rule is evaluated only when it
//! is committed on the repository's default branch. A rule in the working tree alone — a
//! local edit, a commit on another branch, a shell edit of `secrets.toml` — is
//! [`RuleStatus::PendingReview`], and a project whose contract is a 1Password manifest has
//! no default branch at all ([`RuleSource::Manifest`]).
//!
//! Nothing here reads or reports a value: only the contract's names and rules, the rule
//! status per key, and the branch name.

use std::path::Path;

use crate::cause::ConfigSource;
use crate::domain::Fleet;
use crate::error::Error;
use crate::runner::{Call, CommandRunner, PROBE_TIMEOUT};

/// Whether one key's rules are committed on the repository's default branch, and therefore
/// count for an assistant, or exist only in the working tree / another branch and await
/// review.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleStatus {
    /// The working tree's rules for the key equal the default-branch contract's.
    Committed,
    /// The key, or its rules, exist only outside the default-branch contract.
    PendingReview,
}

/// Where a project's rules come from (H1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleSource {
    /// The contract as committed on `branch`. `contract` is `None` when that branch has no
    /// such file: no key is then committed.
    DefaultBranch {
        /// The repository's default branch, e.g. `main`.
        branch: String,
        /// The parsed contract at that branch, when it has one.
        contract: Option<Fleet>,
    },
    /// A project manifest in 1Password: there is no repository file to compare against.
    Manifest,
}

impl RuleSource {
    /// The status of `key`'s rules in `working`: [`RuleStatus::Committed`] only when the
    /// working tree's rules for `(product, key)` equal the default-branch contract's.
    pub fn status(&self, working: &Fleet, product: &str, key: &str) -> RuleStatus {
        let Self::DefaultBranch {
            contract: Some(contract),
            ..
        } = self
        else {
            return RuleStatus::PendingReview;
        };
        let committed = rule_of(contract, product, key);
        let working = rule_of(working, product, key);
        match (committed, working) {
            (Some(c), Some(w)) if c == w => RuleStatus::Committed,
            _ => RuleStatus::PendingReview,
        }
    }

    /// The parsed default-branch contract, for rows that read it directly (`relaxations`,
    /// `needs`). `None` for a manifest or a branch without the file.
    pub fn contract(&self) -> Option<&Fleet> {
        match self {
            Self::DefaultBranch { contract, .. } => contract.as_ref(),
            Self::Manifest => None,
        }
    }
}

/// The rules declared for `(product, key)`, or `None` when the key is undeclared there.
fn rule_of<'f>(fleet: &'f Fleet, product: &str, key: &str) -> Option<&'f crate::domain::Rules> {
    fleet
        .products
        .get(product)
        .and_then(|p| p.keys.get(key))
        .map(|k| &k.rules)
}

/// The repository's default branch (H1): `git symbolic-ref --short
/// refs/remotes/origin/HEAD`, with `origin/` stripped, or `main` when there is no git, no
/// repository, or no `origin/HEAD` (a fresh clone, a local-only repo). Nothing is written.
pub fn default_branch(runner: &dyn CommandRunner, repo: &Path) -> String {
    let dir = repo.to_str().unwrap_or(".");
    match runner.probe(
        &Call::new(
            "git",
            &[
                "-C",
                dir,
                "symbolic-ref",
                "--short",
                "refs/remotes/origin/HEAD",
            ],
        ),
        PROBE_TIMEOUT,
    ) {
        Ok(o) if o.status == 0 => {
            let text = String::from_utf8_lossy(&o.stdout);
            let name = text.trim().strip_prefix("origin/").unwrap_or(text.trim());
            if name.is_empty() {
                "main".to_string()
            } else {
                name.to_string()
            }
        }
        _ => "main".to_string(),
    }
}

/// The source of `working`'s rules: [`RuleSource::Manifest`] when the configuration came
/// from 1Password, else the contract read from `repo`'s default branch with `git show` and
/// parsed by [`crate::config::parse`]. `repo` is the repository top; the contract's path is
/// the working file's path relative to it.
pub fn rule_source(
    runner: &dyn CommandRunner,
    repo: &Path,
    working: &Fleet,
) -> Result<RuleSource, Error> {
    let ConfigSource::File { path, .. } = &working.read_from.0 else {
        return Ok(RuleSource::Manifest);
    };
    let branch = default_branch(runner, repo);
    let relative = path.strip_prefix(repo).unwrap_or(path);
    let spec = format!("{branch}:{}", relative.to_string_lossy().replace('\\', "/"));
    let dir = repo.to_str().unwrap_or(".");
    let text = match runner.probe(
        &Call::new("git", &["-C", dir, "show", spec.as_str()]),
        PROBE_TIMEOUT,
    ) {
        Ok(o) if o.status == 0 => String::from_utf8_lossy(&o.stdout).into_owned(),
        _ => {
            return Ok(RuleSource::DefaultBranch {
                branch,
                contract: None,
            });
        }
    };
    let contract = crate::config::parse(&text)?;
    Ok(RuleSource::DefaultBranch {
        branch,
        contract: Some(contract),
    })
}

#[cfg(test)]
#[path = "rule_source_tests.rs"]
mod tests;
