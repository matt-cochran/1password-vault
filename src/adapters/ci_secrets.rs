//! Where a CI job's 1Password token goes (0.9.0, `opv access --create`): a GitHub Actions
//! secret, written through the GitHub adapter's own `gh secret set` (value on stdin only),
//! the same path `opv sync` uses for a GitHub target. Core code names only this module.

use super::github::{Scope, gh};
use crate::domain::SecretValue;
use crate::error::Error;
use crate::runner::{Call, CommandRunner, Outcome, PROBE_TIMEOUT};

/// The refusal when the CI host's CLI is not signed in: nothing was created.
pub fn not_signed_in() -> Error {
    Error::Auth("the GitHub CLI is not signed in; nothing was created".into())
        .with_code(crate::error::Code::AuthRequired)
        .with_next("gh auth login")
}

/// Whether the CI host's CLI is signed in (`gh auth status`, exit status only).
pub fn signed_in(r: &dyn CommandRunner) -> Result<bool, Error> {
    match r.probe(
        &Call::new(super::github::PROGRAM, &["auth", "status"]),
        PROBE_TIMEOUT,
    ) {
        Ok(o) => {
            if o.status != 0 {
                let _ = crate::runner::take_failure_excerpt();
            }
            Ok(o.status == 0)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Error::Dependency(
            "the GitHub CLI (gh) is not installed; install it, then sign in with gh auth login"
                .into(),
        )
        .with_next("gh auth login")),
        Err(e) => Err(Error::Dependency(
            format!("cannot run gh ({})", e.kind()).into(),
        )),
    }
}

/// Whether `environment` is missing from `repo` (`None`: a repository secret, never
/// missing). A repository the sign-in cannot see is the adapter's error naming it.
pub fn environment_missing(
    r: &dyn CommandRunner,
    repo: &str,
    environment: Option<&str>,
) -> Result<bool, Error> {
    let envs = gh::environments(r, repo)?;
    Ok(environment.is_some_and(|e| !envs.iter().any(|x| x == e)))
}

/// Create the GitHub environment `environment` in `repo` (configuration, not a secret).
pub fn create_environment(
    r: &dyn CommandRunner,
    repo: &str,
    environment: &str,
) -> Result<(), Error> {
    let path = format!("repos/{repo}/environments/{environment}");
    match r.write(&Call::new(
        super::github::PROGRAM,
        &["api", "-X", "PUT", &path, "--silent"],
    )) {
        Ok(Outcome::Done(_)) => Ok(()),
        _ => Err(Error::Target(
            format!(
                "GitHub did not create environment {environment} in {repo}; nothing else was done"
            )
            .into(),
        )),
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
