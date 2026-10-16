//! The `gh` calls of the GitHub target (FR-46). See the table in the module docs of
//! [`super`] and `docs/design/spike-github-findings.md`.
//!
//! # Errors (FR-10, FR-26, SR-1)
//!
//! - `gh` missing from PATH: [`Error::Dependency`] with the platform's install line.
//! - A call that exited non-zero is definite (gh reports the HTTP status): a 404 names the
//!   repository (and GitHub environment) as missing or not visible; otherwise the read-only
//!   `gh auth status` tells a sign-in problem ([`Error::Auth`]) from an access problem
//!   ([`Error::Target`]). A write refused this way also lists what this run already wrote
//!   (NR-10).
//! - A write that timed out, was killed or was lost: [`Error::Unknown`] (exit 9, safe to
//!   re-run).
//! - A refused name or value: [`Error::Policy`] naming the key and rule, never the value.

use std::collections::BTreeMap;
use std::io;

use serde::Deserialize;
use serde::de::DeserializeOwned;

use super::{CREDENTIAL_VARS, GH, PROGRAM, Scope};
use crate::domain::SecretValue;
use crate::domain::plan::StoreEntry;
use crate::error::Error;
use crate::host::Host;
use crate::runner::{
    Call, CommandRunner, Outcome, Output, PROBE_TIMEOUT, status_text, unknown_text,
};

/// Fixed rule id for a name GitHub would reject.
const NAME_RULE: &str = "github-name";
/// Fixed reason for [`NAME_RULE`]; never anything read from a value.
const NAME_REASON: &str = "not a valid GitHub secret or variable name (letters, digits and \
                           underscore, starting with a letter or underscore, and never the \
                           GITHUB_ prefix)";
/// Fixed rule id for a secret over [`super::MAX_SECRET_BYTES`].
const SECRET_TOO_LARGE_RULE: &str = "github-secret-too-large";
/// Fixed reason for [`SECRET_TOO_LARGE_RULE`].
const SECRET_TOO_LARGE_REASON: &str =
    "larger than the largest GitHub Actions secret (47 952 bytes)";
/// Fixed rule id for an empty variable.
const VARIABLE_EMPTY_RULE: &str = "github-variable-empty";
/// Fixed reason for [`VARIABLE_EMPTY_RULE`].
const VARIABLE_EMPTY_REASON: &str = "an empty GitHub Actions variable";
/// Fixed rule id for a variable over [`super::MAX_VARIABLE_BYTES`].
const VARIABLE_TOO_LARGE_RULE: &str = "github-variable-too-large";
/// Fixed reason for [`VARIABLE_TOO_LARGE_RULE`].
const VARIABLE_TOO_LARGE_REASON: &str =
    "larger than the largest GitHub Actions variable (48 000 bytes)";

/// One `gh secret list --json name,updatedAt` entry. Unknown fields are ignored.
#[derive(Deserialize)]
struct SecretEntry {
    name: String,
    #[serde(rename = "updatedAt", default)]
    updated_at: String,
}

/// One `gh variable list --json name,value` entry. Unknown fields are ignored.
#[derive(Deserialize)]
struct VariableEntry {
    name: String,
    value: String,
}

/// `gh api repos/<repo>/environments` output.
#[derive(Deserialize)]
struct Environments {
    environments: Vec<Environment>,
}

/// One entry of [`Environments`].
#[derive(Deserialize)]
struct Environment {
    name: String,
}

/// Managed and unmanaged secrets present in **every** repository of `scope`: name, version
/// `Some(updatedAt)`, `pending: false`, no stamp. Sorted by name.
pub fn list_secrets(r: &dyn CommandRunner, scope: Scope<'_>) -> Result<Vec<StoreEntry>, Error> {
    const WHAT: &str = "gh secret list";
    let mut per_repo: Vec<BTreeMap<String, String>> = Vec::new();
    for repo in scope.repos {
        let mut argv = scoped(&["secret", "list"], repo, scope.environment);
        argv.push("--json");
        argv.push("name,updatedAt");
        let out = read_out(
            r,
            WHAT,
            &place(repo, scope.environment),
            &Call::new(PROGRAM, &argv),
        )
        .map_err(|e| missing_environment(r, scope, repo, e))?;
        let entries: Vec<SecretEntry> = parse_json(&out, WHAT)?;
        per_repo.push(
            entries
                .into_iter()
                .map(|e| (e.name, e.updated_at))
                .collect(),
        );
    }
    Ok(intersection(per_repo))
}

/// The first GitHub rule `(name, value)` breaks, with its fixed reason (FR-22).
pub fn secret_refusal(name: &str, value: &SecretValue) -> Option<(&'static str, &'static str)> {
    if !valid_name(name) {
        return Some((NAME_RULE, NAME_REASON));
    }
    if value.expose().len() > super::MAX_SECRET_BYTES {
        return Some((SECRET_TOO_LARGE_RULE, SECRET_TOO_LARGE_REASON));
    }
    None
}

/// Refuses the whole batch, naming the key and rule (never the value), when one entry has a
/// [`secret_refusal`].
pub fn validate_secrets(batch: &[(String, &SecretValue)]) -> Result<(), Error> {
    for (name, value) in batch {
        if let Some((rule, reason)) = secret_refusal(name, value) {
            return Err(Error::Policy(
                format!(
                    "GitHub secret refused for {name:?}: rule {rule} ({reason}); nothing was \
                     sent to GitHub"
                )
                .into(),
            ));
        }
    }
    Ok(())
}

/// `gh secret set` per name and repository, value on stdin only.
pub fn set_secrets(
    r: &dyn CommandRunner,
    scope: Scope<'_>,
    batch: &[(String, &SecretValue)],
) -> Result<(), Error> {
    const WHAT: &str = "gh secret set";
    if batch.is_empty() {
        return Ok(());
    }
    let mut names: Vec<(&str, &SecretValue)> =
        batch.iter().map(|(n, v)| (n.as_str(), *v)).collect();
    names.sort_by_key(|(name, _)| *name);
    let mut written: Vec<(String, String)> = Vec::new();
    for (name, value) in names {
        for repo in scope.repos {
            let argv = scoped(&["secret", "set", name], repo, scope.environment);
            let call = Call::new(PROGRAM, &argv).with_stdin(Some(value.expose().as_bytes()));
            match invoke(r, Effect::Write, WHAT, &call)? {
                Outcome::Done(_) => written.push((repo.clone(), name.to_string())),
                other => {
                    return Err(set_failure(
                        r,
                        WHAT,
                        &place(repo, scope.environment),
                        &other,
                        &written,
                    ));
                }
            }
        }
    }
    Ok(())
}

/// `gh secret delete` per name and repository; a 404 counts as already gone.
pub fn delete_secrets(
    r: &dyn CommandRunner,
    scope: Scope<'_>,
    names: &[String],
) -> Result<(), Error> {
    const WHAT: &str = "gh secret delete";
    for name in names {
        for repo in scope.repos {
            let argv = scoped(
                &["secret", "delete", name.as_str()],
                repo,
                scope.environment,
            );
            let call = Call::new(PROGRAM, &argv);
            match invoke(r, Effect::Write, WHAT, &call)? {
                Outcome::Done(_) => {}
                other => {
                    if !crate::runner::last_failure_not_found() {
                        return Err(delete_failure(
                            r,
                            WHAT,
                            name,
                            &place(repo, scope.environment),
                            &other,
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Variables present in every repository with the **same** value; a name whose values
/// differ between repositories is left out (so it is written again).
pub fn list_variables(
    r: &dyn CommandRunner,
    scope: Scope<'_>,
) -> Result<BTreeMap<String, String>, Error> {
    const WHAT: &str = "gh variable list";
    let mut per_repo: Vec<BTreeMap<String, String>> = Vec::new();
    for repo in scope.repos {
        let mut argv = scoped(&["variable", "list"], repo, scope.environment);
        argv.push("--json");
        argv.push("name,value");
        let out = read_out(
            r,
            WHAT,
            &place(repo, scope.environment),
            &Call::new(PROGRAM, &argv),
        )
        .map_err(|e| missing_environment(r, scope, repo, e))?;
        let entries: Vec<VariableEntry> = parse_json(&out, WHAT)?;
        per_repo.push(entries.into_iter().map(|e| (e.name, e.value)).collect());
    }
    Ok(variable_intersection(per_repo))
}

/// The first GitHub rule a variable `(name, value)` breaks (empty, too large).
pub fn variable_refusal(name: &str, value: &str) -> Option<(&'static str, &'static str)> {
    if !valid_name(name) {
        return Some((NAME_RULE, NAME_REASON));
    }
    if value.is_empty() {
        return Some((VARIABLE_EMPTY_RULE, VARIABLE_EMPTY_REASON));
    }
    if value.len() > super::MAX_VARIABLE_BYTES {
        return Some((VARIABLE_TOO_LARGE_RULE, VARIABLE_TOO_LARGE_REASON));
    }
    None
}

/// `gh variable set` per name and repository, value on stdin only.
pub fn set_variables(
    r: &dyn CommandRunner,
    scope: Scope<'_>,
    batch: &[(String, &str)],
) -> Result<(), Error> {
    const WHAT: &str = "gh variable set";
    if batch.is_empty() {
        return Ok(());
    }
    let mut names: Vec<(&str, &str)> = batch.iter().map(|(n, v)| (n.as_str(), *v)).collect();
    names.sort_by_key(|(name, _)| *name);
    let mut written: Vec<(String, String)> = Vec::new();
    for (name, value) in names {
        for repo in scope.repos {
            let argv = scoped(&["variable", "set", name], repo, scope.environment);
            let call = Call::new(PROGRAM, &argv).with_stdin(Some(value.as_bytes()));
            match invoke(r, Effect::Write, WHAT, &call)? {
                Outcome::Done(_) => written.push((repo.clone(), name.to_string())),
                other => {
                    return Err(set_failure(
                        r,
                        WHAT,
                        &place(repo, scope.environment),
                        &other,
                        &written,
                    ));
                }
            }
        }
    }
    Ok(())
}

/// `gh variable delete` per name and repository; a 404 counts as already gone.
pub fn delete_variables(
    r: &dyn CommandRunner,
    scope: Scope<'_>,
    names: &[String],
) -> Result<(), Error> {
    const WHAT: &str = "gh variable delete";
    for name in names {
        for repo in scope.repos {
            let argv = scoped(
                &["variable", "delete", name.as_str()],
                repo,
                scope.environment,
            );
            let call = Call::new(PROGRAM, &argv);
            match invoke(r, Effect::Write, WHAT, &call)? {
                Outcome::Done(_) => {}
                other => {
                    if !crate::runner::last_failure_not_found() {
                        return Err(delete_failure(
                            r,
                            WHAT,
                            name,
                            &place(repo, scope.environment),
                            &other,
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Names of the GitHub environments of `repo` (`gh api repos/<repo>/environments`), for
/// preflight. A missing repository is `Error::Target` naming it.
pub fn environments(r: &dyn CommandRunner, repo: &str) -> Result<Vec<String>, Error> {
    const WHAT: &str = "gh api";
    let path = format!("repos/{repo}/environments");
    let args = ["api", path.as_str()];
    let out = read_out(r, WHAT, repo, &Call::new(PROGRAM, &args))?;
    let envs: Environments = parse_json(&out, WHAT)?;
    Ok(envs.environments.into_iter().map(|e| e.name).collect())
}

/// A listing that failed in a GitHub environment: when the environment does not exist in
/// `repo` (gh's 404 says only "Not Found"), the error that names it and the command that
/// creates it; any other failure unchanged. One read-only call, only on that failure path.
fn missing_environment(r: &dyn CommandRunner, scope: Scope<'_>, repo: &str, e: Error) -> Error {
    let (Some(env), Error::Target(_)) = (scope.environment, &e) else {
        return e;
    };
    match environments(r, repo) {
        Ok(names) if !names.iter().any(|n| n == env) => super::missing_environment_error(repo, env),
        _ => e,
    }
}

/// `gh auth status` exit status only (its output names the account and is dropped unread).
pub fn auth_status(r: &dyn CommandRunner) -> std::io::Result<bool> {
    r.probe(&Call::new(PROGRAM, &["auth", "status"]), PROBE_TIMEOUT)
        .map(|o| o.status == 0)
}

/// Whether a `gh` call changes the target (NR-2): reads are retried by the runner, writes
/// never are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Effect {
    Read,
    Write,
}

/// Run one `gh` subcommand, mapping a spawn failure to a typed, value-free error: `gh`
/// missing is [`Error::Dependency`] with the platform's install hint; a spent run budget is
/// [`GH::budget_spent`]; anything else is [`Error::Target`].
fn invoke(
    r: &dyn CommandRunner,
    effect: Effect,
    what: &str,
    call: &Call<'_>,
) -> Result<Outcome, Error> {
    let outcome = match effect {
        Effect::Read => r.read(call, &[]),
        Effect::Write => r.write(call),
    };
    outcome.map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => Error::Dependency(
            format!(
                "{PROGRAM} not found on PATH\n  {}",
                Host::detect().install_hint(GH)
            )
            .into(),
        ),
        io::ErrorKind::TimedOut => GH.budget_spent(r, &e),
        kind => Error::Target(format!("{what} could not start {PROGRAM} ({kind})").into()),
    })
}

/// A successful read's stdout, or the typed error for a refused / unanswered one (NR-2,
/// FR-26).
fn read_out(
    r: &dyn CommandRunner,
    what: &str,
    subject: &str,
    call: &Call<'_>,
) -> Result<Output, Error> {
    match invoke(r, Effect::Read, what, call)? {
        Outcome::Done(out) => Ok(out),
        Outcome::Refused(out) => Err(read_failure(r, what, subject, out.status)),
        Outcome::Unknown {
            status: Some(status),
            ..
        } => Err(read_failure(r, what, subject, status)),
        Outcome::Unknown { .. } => Err(GH.unanswered(r, what)),
    }
}

/// A read that exited non-zero: `Error::Target` naming the operation and repository (and
/// environment), with a `gh auth status` diagnosis (exit status only) giving
/// [`Error::Auth`] when it says nobody is signed in. A 404 is a definite "no such
/// repository / environment": named at once, without a probe (S2).
fn read_failure(r: &dyn CommandRunner, what: &str, subject: &str, status: i32) -> Error {
    let failed = format!("{what} failed ({})", status_text(status));
    if crate::runner::last_failure_not_found() {
        return Error::Target(
            format!(
                "{failed} for {subject}: GitHub reports it missing or not visible to this \
                 sign-in\n  next: check the repository (and GitHub environment) name in \
                 secrets.toml and that this account can access it"
            )
            .into(),
        );
    }
    let host = Host::detect();
    match crate::runner::diagnosing(|| auth_status(r)) {
        // Signed in and not a 404: the token or account lacks a right on the repository,
        // or GitHub refused the request itself (gh said why above).
        Ok(true) => Error::Target(
            format!(
                "{failed} for {subject}: signed in to GitHub\n  check that this sign-in can \
                 read and write Actions secrets and variables on {subject} (a fine-grained \
                 token needs Secrets and Variables write; an account needs admin or write \
                 access)"
            )
            .into(),
        ),
        Ok(false) => not_signed_in(&host, Some(&failed)),
        Err(_) => Error::Target(
            format!("{failed} for {subject}; run `{PROGRAM} auth status` to see why").into(),
        ),
    }
}

/// "not signed in to GitHub" with the next step for `host` (FR-26): sign in with
/// `gh auth login`, or set GH_TOKEN/GITHUB_TOKEN when one is in the environment. Text
/// only, never a token.
fn not_signed_in(host: &Host, failed: Option<&str>) -> Error {
    let ctx = match failed {
        Some(f) => format!("{f}; {PROGRAM} auth status failed"),
        None => format!("{PROGRAM} auth status failed"),
    };
    let next = match host.token(CREDENTIAL_VARS) {
        Some(var) => format!(
            "the token in {var} was rejected or has expired; replace it with a fine-grained \
             token with Secrets and Variables write on the listed repositories"
        ),
        None => format!("log in: {PROGRAM} auth login"),
    };
    Error::Auth(format!("not signed in to GitHub ({ctx})\n  {next}\n  then run opv again").into())
}

/// Why a write failed, from its [`Outcome`], never a value.
fn why(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Done(_) => "exit 0".to_string(),
        Outcome::Refused(out) => status_text(out.status),
        Outcome::Unknown {
            status: Some(status),
            ..
        } => status_text(*status),
        Outcome::Unknown { reason, .. } => unknown_text(PROGRAM, reason),
    }
}

/// A failed `set`, naming the operation, subject and what this run already wrote in each
/// repository (NR-10). An exit status is definite: diagnosed like a read ([`read_failure`]).
/// No status (timed out, killed, lost): [`Error::Unknown`] (NR-2, safe to re-run).
fn set_failure(
    r: &dyn CommandRunner,
    what: &str,
    subject: &str,
    outcome: &Outcome,
    written: &[(String, String)],
) -> Error {
    let done = already_written(written);
    match exit_status(outcome) {
        Some(status) => {
            read_failure(r, what, subject, status).map_text(|m| format!("{m}\n  {done}"))
        }
        None => Error::Unknown(
            format!(
                "{what} failed for {subject} ({}); the change may or may not have been \
                 applied\n  {done}\n  next: re-run the same command",
                why(outcome)
            )
            .into(),
        ),
    }
}

/// The exit status of a finished call; `None` when the outcome is unknown.
fn exit_status(outcome: &Outcome) -> Option<i32> {
    match outcome {
        Outcome::Done(out) | Outcome::Refused(out) => Some(out.status),
        Outcome::Unknown { status, .. } => *status,
    }
}

/// A failed `delete` that was not a 404, naming the name and repository: diagnosed like a
/// read when it exited, [`Error::Unknown`] (NR-2, safe to re-run) otherwise.
fn delete_failure(
    r: &dyn CommandRunner,
    what: &str,
    name: &str,
    subject: &str,
    outcome: &Outcome,
) -> Error {
    match exit_status(outcome) {
        Some(status) => read_failure(r, &format!("{what} {name}"), subject, status),
        None => Error::Unknown(
            format!(
                "{what} failed for {name:?} in {subject} ({}); the change may or may not have \
                 been applied\n  next: re-run the same command",
                why(outcome)
            )
            .into(),
        ),
    }
}

/// The NR-10 line: the `(repo, name)` pairs already written, grouped by repository in
/// first-seen order, or `already written: none`.
fn already_written(written: &[(String, String)]) -> String {
    if written.is_empty() {
        return "already written: none".to_string();
    }
    let mut order: Vec<&str> = Vec::new();
    let mut by_repo: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (repo, name) in written {
        if !by_repo.contains_key(repo.as_str()) {
            order.push(repo);
        }
        by_repo.entry(repo).or_default().push(name);
    }
    let parts: Vec<String> = order
        .iter()
        .map(|repo| {
            let names = by_repo.get(*repo).map(|v| v.join(", ")).unwrap_or_default();
            format!("{repo}: {names}")
        })
        .collect();
    format!("already written: {}", parts.join("; "))
}

/// The repositories' common secret names, sorted, each with the latest `updatedAt`.
fn intersection(per_repo: Vec<BTreeMap<String, String>>) -> Vec<StoreEntry> {
    let Some((first, rest)) = per_repo.split_first() else {
        return Vec::new();
    };
    first
        .iter()
        .filter(|(name, _)| rest.iter().all(|m| m.contains_key(*name)))
        .map(|(name, updated)| StoreEntry {
            name: name.clone(),
            version: Some(
                rest.iter()
                    .filter_map(|m| m.get(name))
                    .chain(std::iter::once(updated))
                    .max()
                    .cloned()
                    .unwrap_or_default(),
            ),
            pending: false,
            stamp: None,
        })
        .collect()
}

/// The variables every repository has with the same value.
fn variable_intersection(per_repo: Vec<BTreeMap<String, String>>) -> BTreeMap<String, String> {
    let Some((first, rest)) = per_repo.split_first() else {
        return BTreeMap::new();
    };
    first
        .iter()
        .filter(|(name, value)| rest.iter().all(|m| m.get(*name) == Some(*value)))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

/// `head -R <repo> [-e <env>]`, the `gh` scope flags on every secret/variable call.
fn scoped<'a>(head: &[&'a str], repo: &'a str, environment: Option<&'a str>) -> Vec<&'a str> {
    let mut argv = head.to_vec();
    argv.push("-R");
    argv.push(repo);
    if let Some(env) = environment {
        argv.push("-e");
        argv.push(env);
    }
    argv
}

/// `owner/name`, or `owner/name (environment staging)`: names only, never a value.
fn place(repo: &str, environment: Option<&str>) -> String {
    match environment {
        Some(env) => format!("{repo} (environment {env})"),
        None => repo.to_string(),
    }
}

/// `^[A-Za-z_][A-Za-z0-9_]*$` and never the reserved `GITHUB_` prefix.
fn valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && !name.starts_with("GITHUB_")
}

/// Parse a read's JSON, naming the line and column on failure (never its contents).
fn parse_json<T: DeserializeOwned>(out: &Output, what: &str) -> Result<T, Error> {
    serde_json::from_slice(&out.stdout).map_err(|e| {
        Error::Target(
            format!(
                "{what} returned unexpected JSON (line {}, column {})",
                e.line(),
                e.column()
            )
            .into(),
        )
    })
}

#[cfg(test)]
#[path = "gh_tests.rs"]
mod tests;
