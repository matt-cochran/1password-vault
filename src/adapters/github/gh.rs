//! The `gh` calls of the GitHub target (FR-46). See the table in the module docs of
//! [`super`] and `docs/design/spike-github-findings.md`.
//!
//! # Errors (FR-10, FR-26, SR-1; design `docs/design/error-catalog.md` §5)
//!
//! - `gh` missing from PATH: [`Cause::ToolMissing`] with the platform's install line.
//! - Any other failed call is never classified here: what the runner observed (the exit,
//!   the principal in effect) and gh's raw stderr go to [`super::diagnose`], which names the
//!   cause; gh's scrubbed reply is the evidence. A rejected token is told the rights its
//!   replacement needs. A write that fails after others succeeded is `Partial`, naming what
//!   this run already wrote (NR-10). A listing in a GitHub environment that gh's reply does
//!   not explain is checked against the repository's environments: a missing one is the
//!   owner's setup.
//! - A refused name or value: [`Error::Policy`] naming the key and rule, never the value.

use std::collections::BTreeMap;
use std::io;

use serde::Deserialize;
use serde::de::DeserializeOwned;

use super::{GH, PROGRAM, Scope};
use crate::cause::{
    Cause, CredentialProblem, DiagnoseContext, ResourceKind, ResourceName, ResourceRef, System,
    Unusable, Upstream,
};
use crate::domain::SecretValue;
use crate::domain::plan::StoreEntry;
use crate::error::Error;
use crate::host::Host;
use crate::runner::{Call, CommandRunner, Outcome, Output, PROBE_TIMEOUT};

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
            &context(repo, scope.environment, false),
            token_needs(scope.repos, scope.environment),
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

/// Refuses the whole batch when one entry has a [`secret_refusal`]. `sync` refuses every
/// such value as a blocking row of its plan (`KeysBlocking`) before any write, so one that
/// reaches here is an internal error; nothing was sent to GitHub.
pub fn validate_secrets(batch: &[(String, &SecretValue)]) -> Result<(), Error> {
    if batch
        .iter()
        .any(|(name, value)| secret_refusal(name, value).is_some())
    {
        return Err(Cause::Bug {
            site: "github: a value the plan passed breaks a GitHub secret rule",
        }
        .into());
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
            match invoke(r, Effect::Write, &call)? {
                Outcome::Done(_) => written.push((repo.clone(), name.to_string())),
                _ => {
                    return Err(write_failure(
                        r,
                        WHAT,
                        &context(repo, scope.environment, true),
                        token_needs(scope.repos, scope.environment),
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
            match invoke(r, Effect::Write, &call)? {
                Outcome::Done(_) => {}
                _ => {
                    if !crate::runner::last_failure_not_found() {
                        return Err(write_failure(
                            r,
                            WHAT,
                            &context(repo, scope.environment, true),
                            token_needs(scope.repos, scope.environment),
                            &[],
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
            &context(repo, scope.environment, false),
            token_needs(scope.repos, scope.environment),
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
            match invoke(r, Effect::Write, &call)? {
                Outcome::Done(_) => written.push((repo.clone(), name.to_string())),
                _ => {
                    return Err(write_failure(
                        r,
                        WHAT,
                        &context(repo, scope.environment, true),
                        token_needs(scope.repos, scope.environment),
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
            match invoke(r, Effect::Write, &call)? {
                Outcome::Done(_) => {}
                _ => {
                    if !crate::runner::last_failure_not_found() {
                        return Err(write_failure(
                            r,
                            WHAT,
                            &context(repo, scope.environment, true),
                            token_needs(scope.repos, scope.environment),
                            &[],
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Names of the GitHub environments of `repo` (`gh api repos/<repo>/environments`), for
/// preflight. A failure is diagnosed like any other gh read.
pub fn environments(r: &dyn CommandRunner, repo: &str) -> Result<Vec<String>, Error> {
    const WHAT: &str = "gh api";
    let path = format!("repos/{repo}/environments");
    let args = ["api", path.as_str()];
    let out = read_out(
        r,
        WHAT,
        &context(repo, None, false),
        token_needs(&[repo.to_string()], None),
        &Call::new(PROGRAM, &args),
    )?;
    let envs: Environments = parse_json(&out, WHAT)?;
    Ok(envs.environments.into_iter().map(|e| e.name).collect())
}

/// A listing that failed in a GitHub environment for a reason gh's reply does not name:
/// when the environment is absent from `repo`'s listing (a read, so a fact, not a guess),
/// the owner's setup; any other failure unchanged. One read-only call, only on that path.
fn missing_environment(r: &dyn CommandRunner, scope: Scope<'_>, repo: &str, e: Error) -> Error {
    let Some(env) = scope.environment else {
        return e;
    };
    if !matches!(e.cause(), Some((Cause::Unrecognized { .. }, _))) {
        return e;
    }
    match environments(r, repo) {
        Ok(names) if !names.iter().any(|n| n == env) => missing_environment_error(repo, env),
        _ => e,
    }
}

/// The GitHub environment `environment` is missing from `repo`: only an owner creates it,
/// since its protection rules are theirs to decide (FR-46).
pub(crate) fn missing_environment_error(repo: &str, environment: &str) -> Error {
    Cause::OwnerSetupRequired {
        system: System::GitHub,
        object: ResourceRef {
            kind: ResourceKind::GitHubEnvironment,
            name: ResourceName::new(environment),
            scope: Some(repo.to_string()),
        },
    }
    .into()
}

/// `gh auth status` exit status only (its output names the account and is dropped unread).
pub fn auth_status(r: &dyn CommandRunner) -> std::io::Result<bool> {
    r.probe(&Call::new(PROGRAM, &["auth", "status"]), PROBE_TIMEOUT)
        .map(|o| o.status == 0)
}

/// `gh api user --silent`: a read-only probe whose failures gh words in the recorded phrases
/// (`tests/fixtures/github/failures` 01, 02), for a diagnosis `gh auth status` cannot give.
pub fn user_probe(r: &dyn CommandRunner) -> std::io::Result<bool> {
    r.probe(
        &Call::new(PROGRAM, &["api", "user", "--silent"]),
        PROBE_TIMEOUT,
    )
    .map(|o| o.status == 0)
}

/// gh is not on PATH: the install line for this platform and shell (§4.7).
pub fn tool_missing() -> Error {
    let host = Host::detect();
    Cause::ToolMissing {
        tool: PROGRAM.to_string(),
        platform: host.platform,
        shell: host.shell,
        ci: host.ci,
    }
    .into()
}

/// gh is there but could not be started.
pub fn tool_unusable(kind: io::ErrorKind) -> Error {
    Cause::ToolUnusable {
        tool: PROGRAM.to_string(),
        why: Unusable::SpawnFailed { io: kind.into() },
    }
    .into()
}

/// What a gh call was about, for its diagnosis: the repository, or the GitHub environment in
/// it, and whether the call changes the target.
pub(crate) fn context(repo: &str, environment: Option<&str>, write: bool) -> DiagnoseContext {
    let resource = match environment {
        Some(env) => ResourceRef {
            kind: ResourceKind::GitHubEnvironment,
            name: ResourceName::new(env),
            scope: Some(repo.to_string()),
        },
        None => ResourceRef {
            kind: ResourceKind::Repository,
            name: ResourceName::new(repo),
            scope: None,
        },
    };
    DiagnoseContext {
        resource: Some(resource),
        write,
        ..DiagnoseContext::default()
    }
}

/// The rights a replacement token needs on `repos` (06.20): a GitHub environment's values
/// also need the Environments permission.
pub(crate) fn token_needs(repos: &[String], environment: Option<&str>) -> Vec<String> {
    let on = repos.join(", ");
    let mut needs = vec![format!("Secrets and Variables write on {on}")];
    if environment.is_some() {
        needs.push(format!("Environments read and write on {on}"));
    }
    needs
}

/// The failed gh call the error at hand came from, classified by the GitHub strategy
/// ([`super::diagnose`], design §5) from what the runner observed and gh's raw stderr, with
/// gh's scrubbed reply as the evidence. A rejected token is told which rights its
/// replacement needs (`needs`). `None` when the runner observed no failed call (stdout over
/// the output cap, which is an answer, not a failure).
pub(crate) fn diagnosed(ctx: &DiagnoseContext, needs: Vec<String>) -> Option<Error> {
    let failed = crate::runner::take_failure()?;
    let exit = failed.seen.exit();
    let mut cause = super::diagnose::diagnose(failed.seen.clone(), failed.stderr(), ctx);
    if let Cause::CredentialRejected {
        problem: CredentialProblem::Rejected { needs: n },
        ..
    } = &mut cause
        && n.is_empty()
    {
        *n = needs;
    }
    Some(match failed.excerpt {
        Some(x) => Error::with_evidence(
            cause,
            Upstream {
                source: System::GitHub,
                tool: "GitHub CLI (gh)".to_string(),
                version: None,
                exit,
                said: x.lines,
                removed_advice: false,
                untrusted: true,
            },
        ),
        None => cause.into(),
    })
}

/// A failed gh call diagnosed ([`diagnosed`]); when the runner observed nothing, GitHub
/// did not answer (the runner's own outage wording).
fn failure(r: &dyn CommandRunner, what: &str, ctx: &DiagnoseContext, needs: Vec<String>) -> Error {
    diagnosed(ctx, needs).unwrap_or_else(|| GH.unanswered(r, what))
}

/// Whether a `gh` call changes the target (NR-2): reads are retried by the runner, writes
/// never are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Effect {
    Read,
    Write,
}

/// Run one `gh` subcommand, mapping a spawn failure to a typed, value-free error: `gh`
/// missing is [`Cause::ToolMissing`]; a spent run budget is [`GH::budget_spent`]; anything
/// else is [`Cause::ToolUnusable`].
fn invoke(r: &dyn CommandRunner, effect: Effect, call: &Call<'_>) -> Result<Outcome, Error> {
    let outcome = match effect {
        Effect::Read => r.read(call, &[]),
        Effect::Write => r.write(call),
    };
    outcome.map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => tool_missing(),
        io::ErrorKind::TimedOut => GH.budget_spent(r, &e),
        kind => tool_unusable(kind),
    })
}

/// A successful read's stdout, or the diagnosed failure (NR-2, FR-26).
fn read_out(
    r: &dyn CommandRunner,
    what: &str,
    ctx: &DiagnoseContext,
    needs: Vec<String>,
    call: &Call<'_>,
) -> Result<Output, Error> {
    match invoke(r, Effect::Read, call)? {
        Outcome::Done(out) => Ok(out),
        Outcome::Refused(_) | Outcome::Unknown { .. } => Err(failure(r, what, ctx, needs)),
    }
}

/// A failed write: the diagnosed failure (an unfinished write is `WriteOutcomeUnknown`, safe
/// to re-run), as `Partial` naming what this run already wrote in each repository (NR-10).
fn write_failure(
    r: &dyn CommandRunner,
    what: &str,
    ctx: &DiagnoseContext,
    needs: Vec<String>,
    written: &[(String, String)],
) -> Error {
    let e = failure(r, what, ctx, needs);
    let done = already_written(written);
    match e {
        Error::Catalog(cause, up) if !done.is_empty() => Error::Catalog(
            Box::new(Cause::Partial {
                done,
                approval_used: None,
                approval_scope: None,
                then: cause,
            }),
            up,
        ),
        e => e,
    }
}

/// What this run already wrote (NR-10): one `<repo>: <names>` entry per repository, in
/// first-seen order; empty when nothing was written.
fn already_written(written: &[(String, String)]) -> Vec<String> {
    let mut order: Vec<&str> = Vec::new();
    let mut by_repo: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (repo, name) in written {
        if !by_repo.contains_key(repo.as_str()) {
            order.push(repo);
        }
        by_repo.entry(repo).or_default().push(name);
    }
    order
        .iter()
        .map(|repo| {
            let names = by_repo.get(*repo).map(|v| v.join(", ")).unwrap_or_default();
            format!("{repo}: {names}")
        })
        .collect()
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

/// `^[A-Za-z_][A-Za-z0-9_]*$` and never the reserved `GITHUB_` prefix.
fn valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && !name.starts_with("GITHUB_")
}

/// Parse a read's JSON (`what`: the gh command's words); a reply opv cannot read is
/// `UnexpectedOutput` at its line and column (never its contents), on the runner's own
/// observation of the call (A1).
fn parse_json<T: DeserializeOwned>(out: &Output, what: &str) -> Result<T, Error> {
    serde_json::from_slice(&out.stdout).map_err(|e| {
        let words: Vec<&str> = what
            .split_whitespace()
            .skip_while(|w| *w == PROGRAM)
            .collect();
        match crate::runner::take_unusable_reply(&Call::new(PROGRAM, &words)) {
            Some(seen) => Cause::UnexpectedOutput {
                system: System::GitHub,
                at: Some(crate::cause::Location {
                    line: u32::try_from(e.line()).unwrap_or(u32::MAX),
                    col: u32::try_from(e.column()).unwrap_or(u32::MAX),
                }),
                problem: crate::cause::OutputProblem::Unparseable,
                during: crate::cause::During::Read,
                seen,
            }
            .into(),
            None => Cause::Bug {
                site: "github: a gh reply the runner did not observe",
            }
            .into(),
        }
    })
}

#[cfg(test)]
#[path = "gh_tests.rs"]
mod tests;
