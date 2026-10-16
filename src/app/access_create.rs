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
//! 3. `op service-account create <name> --vault <id>:<perms>… --expires-in 90d --raw`, in
//!    the account the vaults were checked in, through the runner's create effect: a refusal
//!    is diagnosed from op's reply, and an unknown outcome is checked with `opv access`,
//!    never re-run (X5). Its stdout (the token, shown once by 1Password) is held only in a
//!    zeroizing [`SecretValue`] registered with the run's scrubber.
//! 4. The GitHub secret is set with the token on stdin ([`crate::adapters::ci_secrets`]).
//!
//! An owner command: it needs a person's own terminal and 1Password session (never a
//! service account, Connect, CI or an assistant without a terminal). The old service
//! account is never touched: keep it until the new token has produced verified delivery
//! evidence, then remove it in 1Password.

use std::io::Write;

use super::setup::Interaction;
use super::write_err;
use crate::adapters::onepassword_diagnose::diagnose;
use crate::cause::render::cmd_text;
use crate::cause::{
    AccountId, Cause, Cmd, CreateKind, DiagnoseContext, EnvName, Guard, Refind, System, TargetName,
    Unusable, Upstream, UsageProblem,
};
use crate::domain::SecretValue;
use crate::domain::access_plan::Permission;
use crate::error::Error;
use crate::runner::{Call, CommandRunner, CreateOutcome};

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

/// A GitHub Actions secret name (07.14): letters, digits or `_`, not starting with a digit
/// or `GITHUB_`. GitHub refuses anything else only after the service account exists.
fn valid_secret_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && !s.as_bytes()[0].is_ascii_digit()
        && !s.starts_with("GITHUB_")
}

fn usage(flag: &str, format: &'static str) -> Error {
    Cause::Usage {
        problem: UsageProblem::ValueFormat {
            flag: flag.to_string(),
            format,
        },
    }
    .into()
}

/// Check the arguments before any call (X23: before anything irreversible).
pub fn check(gh: &GitHub) -> Result<(), Error> {
    if !valid_repo(&gh.repo) {
        return Err(usage("--github", "owner/repo"));
    }
    if gh.environment.as_deref().is_some_and(|e| !valid_name(e)) {
        return Err(usage("--github-env", "letters, digits, '-' or '_'"));
    }
    if !valid_secret_name(&gh.secret) {
        return Err(usage(
            "--secret-name",
            "letters, digits or '_', not starting with a digit or GITHUB_",
        ));
    }
    Ok(())
}

/// The read that shows whether a service account with this identity's name exists (X5):
/// `opv access <env> [--target <t>]` lists every service account that reads its vaults.
fn check_command(env: &str, target: Option<&str>) -> Cmd {
    let mut args = vec![env.to_string()];
    if let Some(t) = target {
        args.extend(["--target".to_string(), t.to_string()]);
    }
    Cmd {
        command: vec!["access".into()],
        args,
    }
}

/// Run `op service-account create` once, through the runner's create effect (07.12, X5):
/// its stdout (the token), or the diagnosed cause. An unknown outcome is
/// `CreateOutcomeUnknown` with a check first, never a re-run: a second create would make a
/// second account, and the first one's token is already lost.
fn create(
    r: &dyn CommandRunner,
    call: &Call,
    ctx: &DiagnoseContext,
) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
    let seen = match r.create(call, CreateKind::ServiceAccount) {
        Ok(CreateOutcome::Done(o)) => return Ok(o.stdout),
        Ok(CreateOutcome::Refused(_)) => crate::runner::take_observed(),
        Ok(CreateOutcome::OutcomeUnknown(seen)) => Some(seen),
        Err(e) => {
            return Err(Cause::ToolUnusable {
                tool: "op".into(),
                why: Unusable::SpawnFailed {
                    io: e.kind().into(),
                },
            }
            .into());
        }
    };
    let (said, truncated) = crate::scrub::Excerpt::parts(crate::runner::take_failure_excerpt());
    // The runner observes every call that failed; a runner that did not cannot be diagnosed.
    let Some(seen) = seen else {
        return Err(Cause::Bug {
            site: "access --create: a refused create the runner did not observe",
        }
        .into());
    };
    let exit = seen.exit();
    // 07.13: a refusal is classified by op's reply (a sign-in, an account, a missing
    // right), and shown; nothing was created.
    // The session strategy: `service-account create` is no item call, and it keeps the
    // context's check-first refind for an unknown outcome.
    let cause = diagnose(seen, &said.join("\n"), ctx);
    Err(if said.is_empty() {
        cause.into()
    } else {
        Error::with_evidence(
            cause,
            Upstream {
                source: crate::cause::System::OnePassword,
                tool: "1Password CLI".into(),
                version: None,
                exit,
                said,
                removed_advice: false,
                truncated,
                untrusted: true,
            },
        )
    })
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
    // #157: the vault's own diagnosed cause (another account, or none), with op's reply;
    // a service account created here could not be granted it, so nothing is created.
    if let Some(vault) = id.not_in_account.first() {
        return Err(vault.error());
    }
    // Preflight: everything the token's journey needs, before 1Password shows it once.
    use crate::adapters::ci_secrets;
    if !ci_secrets::signed_in(r)? {
        return Err(ci_secrets::not_signed_in());
    }
    let env_missing = ci_secrets::environment_missing(r, &gh.repo, gh.environment.as_deref())?;
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
        return Err(Cause::Guard {
            guard: Guard::Declined,
        }
        .into());
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
    let check = check_command(env, target);
    let ctx = DiagnoseContext {
        env: Some(EnvName::new(env)),
        target: target.map(TargetName::new),
        create: Some((
            CreateKind::ServiceAccount,
            id.service_account.clone(),
            Refind::Check(check.clone()),
        )),
        write: true,
        account: id.account.clone().map(AccountId::new),
        ..DiagnoseContext::default()
    };
    // In the account the vaults were checked in (#157), never op's default.
    let er = crate::app::signin::EnvRunner::with_account(r, id.account.clone());
    let raw = create(&er, &Call::new("op", &argv), &ctx)?;
    let token = SecretValue::new(String::from_utf8_lossy(&raw).trim().to_string());
    drop(raw);
    // From here on, any output that might echo it is scrubbed (SR-1).
    crate::scrub::register_secret(token.expose());
    if token.expose().is_empty() {
        // 07.13, C20: the account exists and its token is lost (1Password shows it once):
        // it is revoked, never made again (X5). op has no listing of service accounts, so
        // there is no vendor refind.
        return Err(Cause::SecretNotStored {
            system: System::OnePassword,
            kind: CreateKind::ServiceAccount,
            name: id.service_account.clone(),
            env: EnvName::new(env),
            target: target.map(TargetName::new),
            refind: None,
        }
        .into());
    }
    let stored = ci_secrets::store(r, &gh.repo, gh.environment.as_deref(), &gh.secret, &token);
    drop(token);
    if let Err(e) = stored {
        // The account exists and its token is lost (1Password shows it once): say so
        // whatever GitHub's cause is, before it is reported.
        ui.show(&format!(
            "Service account {:?} was created, but its token could not be stored: remove it in \
             1Password (Developer > Service accounts) before running this again.",
            id.service_account
        ))?;
        return Err(e);
    }
    writeln!(
        out,
        "created {:?} and stored its token as {} in {place}; nothing was printed",
        id.service_account, gh.secret
    )
    .map_err(write_err)?;
    // 07.16: a typed command, filled from what is known. A deploy identity's delivery leaves
    // evidence; the CI reader's is checked by who reads its vaults.
    let next = match target {
        Some(t) => {
            writeln!(out, "After the next CI run, check its delivery evidence:")
                .map_err(write_err)?;
            Cmd {
                command: vec!["delivery".into(), "verify".into()],
                args: vec![env.to_string(), "--target".into(), t.to_string()],
            }
        }
        None => check,
    };
    writeln!(out, "Next: {}", cmd_text(&next)).map_err(write_err)
}

#[cfg(test)]
#[path = "access_create_tests.rs"]
mod tests;
