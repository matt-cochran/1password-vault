//! `opv access <env> [--target <name>] --create --github <owner/repo> [--github-env <env>]`
//! (0.9.0): create the least-privilege 1Password service account an environment's CI job
//! needs and store its token as a GitHub Actions secret, in one owner command, without the
//! token ever being shown, typed or written to a file.
//!
//! The identity is exactly what `opv access` computes ([`super::access::identity`]): a
//! target's deploy identity (boundary read, its own state vault read and write), or with
//! no `--target` the environment's read-only CI reader. Steps, in order:
//!
//! 1. Preflight, read-only: the GitHub CLI's sign-in, the repository, and the
//!    environment (`--github-env`). A vault the selected 1Password account cannot find
//!    refuses before anything is created: the account could not be granted it.
//! 2. One confirmation, showing the account name, every grant, the repository, the GitHub
//!    environment and the secret name. A missing GitHub environment is created after it
//!    (an environment is configuration, not a secret).
//! 3. `op service-account create <name> --vault <id>:<perms>… --expires-in 90d --raw`. Its
//!    stdout (the token, shown once by 1Password) is held only in a zeroizing
//!    [`SecretValue`] registered with the run's scrubber.
//! 4. The GitHub secret is set with the token on stdin ([`crate::adapters::ci_secrets`]).
//!
//! An owner command: it needs a person's own terminal and 1Password session (never a
//! service account, Connect, CI or an assistant without a terminal). The old service
//! account is never touched: keep it until the new token has produced verified delivery
//! evidence, then remove it in 1Password.

use std::io::Write;

use super::setup::Interaction;
use super::write_err;
use crate::domain::SecretValue;
use crate::domain::access_plan::Permission;
use crate::error::{Code, Error};
use crate::runner::{Call, CommandRunner, Outcome};

/// Where the token goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHub {
    /// `owner/repo`.
    pub repo: String,
    /// The GitHub environment the job declares; `None`: a repository secret.
    pub environment: Option<String>,
    /// The secret's name (`OP_SERVICE_ACCOUNT_TOKEN` by default).
    pub secret: String,
}

/// The default secret name: the variable `op` reads a service-account token from.
pub const SECRET: &str = "OP_SERVICE_ACCOUNT_TOKEN";

fn valid_repo(s: &str) -> bool {
    let mut parts = s.split('/');
    let ok = |p: Option<&str>| {
        p.is_some_and(|p| {
            !p.is_empty()
                && p.len() <= 100
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        })
    };
    ok(parts.next()) && ok(parts.next()) && parts.next().is_none()
}

fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}

fn usage(m: String) -> Error {
    Error::Config(m.into()).with_code(Code::Usage)
}

/// Check the arguments before any call.
pub fn check(gh: &GitHub) -> Result<(), Error> {
    if !valid_repo(&gh.repo) {
        return Err(usage(format!("--github {:?} must be owner/repo", gh.repo)));
    }
    if gh.environment.as_deref().is_some_and(|e| !valid_name(e)) {
        return Err(usage(
            "--github-env must be letters, digits, '-' or '_'".into(),
        ));
    }
    if !valid_name(&gh.secret) || gh.secret.starts_with("GITHUB_") {
        return Err(usage(
            "--secret-name must be letters, digits or '_' and not start with GITHUB_".into(),
        ));
    }
    Ok(())
}

/// A write that must have completed: its stdout, or an error naming `what` (never its
/// output, which for the service account is the token).
fn write(
    r: &dyn CommandRunner,
    call: &Call,
    what: &str,
) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
    match r.write(call) {
        Ok(Outcome::Done(o)) => Ok(o.stdout),
        Ok(Outcome::Refused(o)) => Err(Error::Source(
            format!(
                "{what} failed (exit {}); nothing was printed from it",
                o.status
            )
            .into(),
        )),
        Ok(Outcome::Unknown { .. }) => Err(Error::Unknown(
            format!("{what} may or may not have completed; nothing was printed from it").into(),
        )),
        Err(e) => Err(Error::Dependency(
            format!("cannot run {what} ({})", e.kind()).into(),
        )),
    }
}

/// Which identity to create, and where its token goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<'a> {
    pub env: &'a str,
    /// The target's deploy identity; `None`: the environment's CI reader.
    pub target: Option<&'a str>,
    /// The project naming the service account.
    pub project: &'a str,
    pub github: GitHub,
}

/// Create the identity and store its token. `ui` asks the one question and shows progress.
pub fn run(
    fleet: &crate::domain::Fleet,
    req: &Request<'_>,
    r: &dyn CommandRunner,
    ui: &mut dyn Interaction,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let (env, target, project, gh) = (req.env, req.target, req.project, &req.github);
    check(gh)?;
    super::tidy::require_person(r, "opv access --create")?;
    let id = super::access::identity(fleet, env, target, project, r)?;
    if let Some(vault) = id.not_in_account.first() {
        return Err(Error::Policy(
            format!(
                "vault {vault} is not in the selected 1Password account, so a service account \
                 created here could not be granted it; nothing was created"
            )
            .into(),
        )
        .with_code(Code::PolicyRefused)
        .with_next(format!("opv vault locate {vault}")));
    }
    // Preflight: everything the token's journey needs, before 1Password shows it once.
    use crate::adapters::ci_secrets;
    if !ci_secrets::signed_in(r)? {
        return Err(ci_secrets::not_signed_in());
    }
    let env_missing = ci_secrets::environment_missing(r, &gh.repo, gh.environment.as_deref())
        .map_err(|e| e.map_text(|t| format!("{t}; nothing was created")))?;
    // The one question.
    let who = match target {
        Some(t) => format!("the deploy identity of {env}/{t}"),
        None => format!("the read-only CI reader of {env}"),
    };
    ui.show(&format!(
        "Create 1Password service account {:?} ({who}), valid 90 days, with:",
        id.service_account
    ))?;
    for g in &id.grants {
        let perm = match g.permission {
            Permission::Read => "read",
            Permission::ReadWrite => "read and write",
        };
        ui.show(&format!("  vault {}: {perm}", g.vault_id))?;
    }
    let place = match &gh.environment {
        Some(e) if env_missing => format!("{} environment {e} (created now)", gh.repo),
        Some(e) => format!("{} environment {e}", gh.repo),
        None => format!("{} (repository secret)", gh.repo),
    };
    ui.show(&format!(
        "and store its token as the GitHub secret {} in {place}. The token is never shown.",
        gh.secret
    ))?;
    if id.already_present {
        ui.show(&format!(
            "An account named {:?} already reads these vaults: this makes a second one. Keep the \
             old one until the new token has produced verified delivery evidence (opv delivery \
             verify), then remove the old one in 1Password.",
            id.service_account
        ))?;
    }
    if !ui.confirm("Go ahead?")? {
        return Err(Error::Policy("Stopped. Nothing was created.".into()));
    }
    if let (true, Some(e)) = (env_missing, gh.environment.as_deref()) {
        ci_secrets::create_environment(r, &gh.repo, e)?;
    }
    // The token: created, held in memory only, then sent to GitHub on stdin.
    let mut args: Vec<String> = vec![
        "service-account".into(),
        "create".into(),
        id.service_account.clone(),
    ];
    for g in &id.grants {
        let perm = match g.permission {
            Permission::Read => "read_items",
            Permission::ReadWrite => "read_items,write_items",
        };
        args.extend(["--vault".into(), format!("{}:{perm}", g.vault_id)]);
    }
    args.extend(["--expires-in".into(), "90d".into(), "--raw".into()]);
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let raw = write(r, &Call::new("op", &argv), "op service-account create")?;
    let token = SecretValue::new(String::from_utf8_lossy(&raw).trim().to_string());
    drop(raw);
    // From here on, any output that might echo it is scrubbed (SR-1).
    crate::scrub::register_secret(token.expose());
    if token.expose().is_empty() {
        return Err(Error::Source(
            "1Password created the service account but printed no token; remove it in \
             1Password and run this again"
                .into(),
        ));
    }
    let stored = ci_secrets::store(r, &gh.repo, gh.environment.as_deref(), &gh.secret, &token);
    drop(token);
    if let Err(e) = stored {
        return Err(e.map_text(|t| {
            format!(
                "{t}. The service account {:?} was created, but its token could not be stored \
                 and 1Password shows a token only once: remove that account in 1Password \
                 (Developer > Service accounts), then run this command again",
                id.service_account
            )
        }));
    }
    writeln!(
        out,
        "created {:?} and stored its token as {} in {place}; nothing was printed",
        id.service_account, gh.secret
    )
    .map_err(write_err)?;
    writeln!(
        out,
        "Next: after the next CI run, check the evidence with opv delivery verify {env} --product <product>"
    )
    .map_err(write_err)
}

#[cfg(test)]
#[path = "access_create_tests.rs"]
mod tests;
