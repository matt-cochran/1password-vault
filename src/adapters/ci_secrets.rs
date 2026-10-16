//! Where a CI job's 1Password token goes (0.9.0, `opv access --create`): a GitHub Actions
//! secret, written through the GitHub adapter's own `gh secret set` (value on stdin only),
//! the same path `opv sync` uses for a GitHub target. Core code names only this module.
//!
//! Every failed gh call is diagnosed by the GitHub strategy (design
//! `docs/design/error-catalog.md` §5), so a rejected `GH_TOKEN` is named as such, never
//! answered with `gh auth login`, which that token makes gh refuse (06.22).

use super::github::{Scope, gh};
use crate::cause::{Cause, CreateKind, DiagnoseContext, Refind, SessionState, System};
use crate::domain::SecretValue;
use crate::error::Error;
use crate::runner::{Call, CommandRunner, CreateOutcome, PROBE_TIMEOUT};

/// The refusal when the CI host's CLI is not signed in and gh's own reply could not be
/// read: nothing was created.
pub fn not_signed_in() -> Error {
    Cause::NotSignedIn {
        system: System::GitHub,
        account: None,
        state: SessionState::SignedOut,
    }
    .into()
}

/// Whether the CI host's CLI is signed in (`gh auth status`, exit status only). A failed
/// status is diagnosed (a rejected shell token, a signed-out gh, …) and returned as the
/// error; `Ok(false)` only when the runner observed nothing to diagnose.
pub fn signed_in(r: &dyn CommandRunner) -> Result<bool, Error> {
    match r.probe(
        &Call::new(super::github::PROGRAM, &["auth", "status"]),
        PROBE_TIMEOUT,
    ) {
        Ok(o) if o.status == 0 => Ok(true),
        Ok(_) => match gh::diagnosed(&DiagnoseContext::default(), Vec::new()) {
            Some(e) => Err(e),
            None => Ok(false),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(gh::tool_missing()),
        Err(e) => Err(gh::diagnosed(&DiagnoseContext::default(), Vec::new())
            .unwrap_or_else(|| gh::tool_unusable(e.kind()))),
    }
}

/// Whether `environment` is missing from `repo` (`None`: a repository secret, never
/// missing). A repository the sign-in cannot see is the adapter's diagnosed error.
pub fn environment_missing(
    r: &dyn CommandRunner,
    repo: &str,
    environment: Option<&str>,
) -> Result<bool, Error> {
    let envs = gh::environments(r, repo)?;
    Ok(environment.is_some_and(|e| !envs.iter().any(|x| x == e)))
}

/// Create the GitHub environment `environment` in `repo` (configuration, not a secret).
/// A non-idempotent create (X5): a refusal is diagnosed; an unknown outcome is
/// `CreateOutcomeUnknown`, never "did not create" (06.04). `opv access --create` checks the
/// repository's environments before it creates one, so running it again finds an
/// environment this call did make ([`Refind::ByTitle`]).
pub fn create_environment(
    r: &dyn CommandRunner,
    repo: &str,
    environment: &str,
) -> Result<(), Error> {
    let path = format!("repos/{repo}/environments/{environment}");
    let args = ["api", "-X", "PUT", path.as_str(), "--silent"];
    let call = Call::new(super::github::PROGRAM, &args);
    let mut ctx = gh::context(repo, Some(environment), true);
    ctx.create = Some((
        CreateKind::GitHubEnvironment,
        environment.to_string(),
        Refind::ByTitle,
    ));
    let outcome = match r.create(&call, CreateKind::GitHubEnvironment) {
        Ok(outcome) => outcome,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(gh::tool_missing()),
        Err(e) => return Err(gh::tool_unusable(e.kind())),
    };
    match outcome {
        CreateOutcome::Done(_) => Ok(()),
        CreateOutcome::Refused(_) => Err(gh::diagnosed(&ctx, Vec::new()).unwrap_or_else(|| {
            Cause::Bug {
                site: "ci_secrets: a refused environment create left no observation",
            }
            .into()
        })),
        CreateOutcome::OutcomeUnknown(seen) => {
            Err(super::github::diagnose::diagnose(seen, "", &ctx).into())
        }
    }
}

/// Store `value` as the secret `name` in `repo` (and `environment`), on stdin only.
pub fn store(
    r: &dyn CommandRunner,
    repo: &str,
    environment: Option<&str>,
    name: &str,
    value: &SecretValue,
) -> Result<(), Error> {
    let repos = [repo.to_string()];
    gh::set_secrets(
        r,
        Scope {
            repos: &repos,
            environment,
        },
        &[(name.to_string(), value)],
    )
}
