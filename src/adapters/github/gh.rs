//! The `gh` calls of the GitHub target (FR-46). See the table in the module docs of
//! [`super`] and `docs/design/spike-github-findings.md`.
//!
//! CONTRACT STUB (plan deliverable `gh-store-adapter`): signatures are fixed; bodies are
//! implemented and tested against `tests/fixtures/github/`.

use std::collections::BTreeMap;

use super::Scope;
use crate::domain::SecretValue;
use crate::domain::plan::StoreEntry;
use crate::error::Error;
use crate::runner::CommandRunner;

/// Managed and unmanaged secrets present in **every** repository of `scope`: name, version
/// `Some(updatedAt)`, `pending: false`, no stamp. Sorted by name.
pub fn list_secrets(r: &dyn CommandRunner, scope: Scope<'_>) -> Result<Vec<StoreEntry>, Error> {
    let _ = (r, scope);
    todo!("gh-store-adapter")
}

/// The first GitHub rule `(name, value)` breaks, with its fixed reason (FR-22).
pub fn secret_refusal(name: &str, value: &SecretValue) -> Option<(&'static str, &'static str)> {
    let _ = (name, value);
    todo!("gh-store-adapter")
}

/// Refuses the whole batch, naming the key and rule (never the value), when one entry has a
/// [`secret_refusal`].
pub fn validate_secrets(batch: &[(String, &SecretValue)]) -> Result<(), Error> {
    let _ = batch;
    todo!("gh-store-adapter")
}

/// `gh secret set` per name and repository, value on stdin only.
pub fn set_secrets(
    r: &dyn CommandRunner,
    scope: Scope<'_>,
    batch: &[(String, &SecretValue)],
) -> Result<(), Error> {
    let _ = (r, scope, batch);
    todo!("gh-store-adapter")
}

/// `gh secret delete` per name and repository; a 404 counts as already gone.
pub fn delete_secrets(
    r: &dyn CommandRunner,
    scope: Scope<'_>,
    names: &[String],
) -> Result<(), Error> {
    let _ = (r, scope, names);
    todo!("gh-store-adapter")
}

/// Variables present in every repository with the **same** value; a name whose values
/// differ between repositories is left out (so it is written again).
pub fn list_variables(
    r: &dyn CommandRunner,
    scope: Scope<'_>,
) -> Result<BTreeMap<String, String>, Error> {
    let _ = (r, scope);
    todo!("gh-store-adapter")
}

/// The first GitHub rule a variable `(name, value)` breaks (empty, too large).
pub fn variable_refusal(name: &str, value: &str) -> Option<(&'static str, &'static str)> {
    let _ = (name, value);
    todo!("gh-store-adapter")
}

/// `gh variable set` per name and repository, value on stdin only.
pub fn set_variables(
    r: &dyn CommandRunner,
    scope: Scope<'_>,
    batch: &[(String, &str)],
) -> Result<(), Error> {
    let _ = (r, scope, batch);
    todo!("gh-store-adapter")
}

/// `gh variable delete` per name and repository; a 404 counts as already gone.
pub fn delete_variables(
    r: &dyn CommandRunner,
    scope: Scope<'_>,
    names: &[String],
) -> Result<(), Error> {
    let _ = (r, scope, names);
    todo!("gh-store-adapter")
}

/// Names of the GitHub environments of `repo` (`gh api repos/<repo>/environments`), for
/// preflight. A missing repository is `Error::Target` naming it.
pub fn environments(r: &dyn CommandRunner, repo: &str) -> Result<Vec<String>, Error> {
    let _ = (r, repo);
    todo!("gh-store-adapter")
}

/// `gh auth status` exit status only (its output names the account and is dropped unread).
pub fn auth_status(r: &dyn CommandRunner) -> std::io::Result<bool> {
    let _ = r;
    todo!("gh-store-adapter")
}
