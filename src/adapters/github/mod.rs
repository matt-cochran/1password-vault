//! GitHub Actions adapter wrapping `gh` (FR-46, `docs/design/github-actions-target.md`,
//! spike `docs/design/spike-github-findings.md`).
//!
//! A staged target whose writes are live at once ([`StagedRuntime::live`]): secret-kind keys
//! become Actions secrets, config-kind keys Actions variables ([`StagedStore::variables`]),
//! in one or more repositories, as repository or GitHub-environment values.
//!
//! | fn (in [`gh`]) | argv, per repository |
//! |---|---|
//! | `list_secrets` | `secret list -R <repo> [-e <env>] --json name,updatedAt` |
//! | `set_secrets` | `secret set <NAME> -R <repo> [-e <env>]` (value on stdin), one call per name |
//! | `delete_secrets` | `secret delete <NAME> -R <repo> [-e <env>]` |
//! | `list_variables` | `variable list -R <repo> [-e <env>] --json name,value` |
//! | `set_variables` | `variable set <NAME> -R <repo> [-e <env>]` (value on stdin) |
//! | `delete_variables` | `variable delete <NAME> -R <repo> [-e <env>]` |
//! | `environments` | `api repos/<repo>/environments` (preflight) |
//!
//! Secrets cannot be read back: a listed secret's version is its `updatedAt`, never a digest,
//! so every ready secret is written each sync and a changed `updatedAt` reports it written.
//! With several repositories a name is listed only when every repository has it.

pub mod config;
pub mod gh;
pub mod login;

pub use config::{GithubTarget, PROVIDER};

use std::collections::BTreeMap;

use crate::domain::SecretValue;
use crate::domain::plan::StoreEntry;
use crate::error::Error;
use crate::host::Tool;
use crate::ports::{StagedRuntime, StagedStore, Store, VariableStore};
use crate::runner::CommandRunner;

/// The GitHub CLI binary.
pub const PROGRAM: &str = "gh";

/// Environment pinned on every `gh` call (spike): no prompts, no update notice, no colour,
/// no pager.
pub const PINNED_ENV: &[(&str, &str)] = &[
    ("GH_PROMPT_DISABLED", "1"),
    ("GH_NO_UPDATE_NOTIFIER", "1"),
    ("NO_COLOR", "1"),
    ("GH_PAGER", "cat"),
];

/// The GitHub CLI and how to install it.
pub const GH: Tool = Tool {
    program: PROGRAM,
    ci: "gh is preinstalled on GitHub-hosted runners; elsewhere install it from \
         https://cli.github.com",
    macos: "install: brew install gh",
    windows: "install: winget install -e --id GitHub.cli",
    linux: "install gh from https://github.com/cli/cli/blob/trunk/docs/install_linux.md \
            (the official instructions for this Linux distribution)",
    vendor: "GitHub",
    status_page: "https://www.githubstatus.com",
    pinned_env: PINNED_ENV,
    // Spike Q4, Q5, Q10: a missing repository, environment or name.
    not_found: &["HTTP 404"],
    // Spike Q9: a rejected or missing token.
    signed_out: &["HTTP 401"],
    aliases: &[],
    version_args: &["--version"],
};

/// A GitHub token in the environment, in the order `gh` prefers them (by name only).
pub const CREDENTIAL_VARS: &[&str] = &["GH_TOKEN", "GITHUB_TOKEN"];

/// Largest secret value GitHub accepts, in bytes (spike Q8: the limit is on the encrypted
/// form; 47 952 accepted, 47 953 refused).
pub const MAX_SECRET_BYTES: usize = 47_952;

/// Largest variable value GitHub accepts, in bytes (spike Q8).
pub const MAX_VARIABLE_BYTES: usize = 48_000;

/// Where one target's values live: one or more repositories, as repository values or as
/// the values of one GitHub environment in each.
#[derive(Debug, Clone, Copy)]
pub struct Scope<'a> {
    /// `owner/name`, validated at load; at least one.
    pub repos: &'a [String],
    /// The GitHub environment (`-e`), when the target names one.
    pub environment: Option<&'a str>,
}

/// The `Error::Target` for a GitHub environment missing from one repository (FR-46): opv
/// never creates environments, so the next step is the owner's `gh api` call.
pub(crate) fn missing_environment_error(repo: &str, environment: &str) -> Error {
    Error::Target(
        format!(
            "GitHub environment {environment:?} is missing from repository {repo}; nothing \
             was changed\n  opv never creates GitHub environments because their protection \
             rules are the owner's decision\n  next: {PROGRAM} api -X PUT \
             repos/{repo}/environments/{environment}"
        )
        .into(),
    )
}

/// GitHub as both staged ports (FR-28, FR-46). Each method is the [`gh`] function of the
/// same operation.
pub struct Github<'a> {
    pub runner: &'a dyn CommandRunner,
    pub scope: Scope<'a>,
}

impl Store for Github<'_> {
    fn list(&self) -> Result<Vec<StoreEntry>, Error> {
        gh::list_secrets(self.runner, self.scope)
    }
    fn refusal(&self, name: &str, value: &SecretValue) -> Option<(&'static str, &'static str)> {
        gh::secret_refusal(name, value)
    }
}

impl StagedStore for Github<'_> {
    fn validate(&self, batch: &[(String, &SecretValue)]) -> Result<(), Error> {
        gh::validate_secrets(batch)
    }
    fn write(&self, batch: &[(String, &SecretValue)]) -> Result<(), Error> {
        gh::set_secrets(self.runner, self.scope, batch)
    }
    fn remove(&self, names: &[String]) -> Result<(), Error> {
        gh::delete_secrets(self.runner, self.scope, names)
    }
    fn variables(&self) -> Option<&dyn VariableStore> {
        Some(self)
    }
}

impl VariableStore for Github<'_> {
    fn list(&self) -> Result<BTreeMap<String, String>, Error> {
        gh::list_variables(self.runner, self.scope)
    }
    fn refusal(&self, name: &str, value: &str) -> Option<(&'static str, &'static str)> {
        gh::variable_refusal(name, value)
    }
    fn set(&self, batch: &[(String, &str)]) -> Result<(), Error> {
        gh::set_variables(self.runner, self.scope, batch)
    }
    fn remove(&self, names: &[String]) -> Result<(), Error> {
        gh::delete_variables(self.runner, self.scope, names)
    }
}

impl StagedRuntime for Github<'_> {
    /// Never called: [`StagedRuntime::live`] is true, so `sync --deploy` only says there is
    /// nothing to deploy.
    fn deploy(&self) -> Result<(), Error> {
        Ok(())
    }
    fn live(&self) -> bool {
        true
    }
}
