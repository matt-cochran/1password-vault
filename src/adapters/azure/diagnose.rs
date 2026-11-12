//! The Azure (`az`) diagnosis strategy (design `docs/design/error-catalog.md` §5, §12.4).
//!
//! Azure phrases are deferred until sandbox recordings exist (owner decision 2026-10-16):
//! no recorded Azure failure fixture exists, so this strategy never matches `az` wording.
//! It classifies only what the runner observed about the failed call — a timeout or signal
//! during a create, a write or a read, and a spawn failure — and reports every other
//! failure as `Unrecognized` with the facts it did establish. Azure phrases are added when
//! a recording exists.

use serde_json::Value;

use super::AzureTarget;
use super::az::{self, Effect};
use crate::cause::{Cause, DiagnoseContext, ExitClass, Observed, Principal, System, Unanswered};
use crate::error::Error;
use crate::host::Host;
use crate::provider::{Check, Verdict};
use crate::runner::{CommandRunner, Outcome};

/// Turn what opv observed about one failed `az` call into a cause.
pub fn diagnose(seen: Observed, stderr: &str, ctx: &DiagnoseContext) -> Cause {
    // No Azure phrase is matched yet (owner decision 2026-10-16, error-catalog §12.4).
    let _ = stderr;

    match seen.exit() {
        ExitClass::SpawnFailed => {
            let host = Host::detect();
            Cause::ToolMissing {
                tool: "az".to_string(),
                platform: host.platform,
                shell: host.shell,
                ci: host.ci,
            }
        }
        ExitClass::TimedOut | ExitClass::Signal { .. } | ExitClass::Lost => {
            unknown_outcome(seen, ctx)
        }
        ExitClass::Code { .. } => unrecognized(seen, ctx),
    }
}

/// A call that never produced an outcome: a create, a write or a read (design §4.6).
fn unknown_outcome(seen: Observed, ctx: &DiagnoseContext) -> Cause {
    if let Some((kind, name, refind)) = ctx.create.as_ref() {
        return Cause::CreateOutcomeUnknown {
            system: System::Azure,
            kind: *kind,
            name: name.clone(),
            refind: refind.clone(),
            seen,
        };
    }
    if ctx.write {
        return match ctx.resource.as_ref() {
            Some(subject) => Cause::WriteOutcomeUnknown {
                system: System::Azure,
                subject: subject.clone(),
                seen,
            },
            // A write with no known subject cannot name the outcome; report the facts.
            None => unrecognized(seen, ctx),
        };
    }
    Cause::Unavailable {
        system: System::Azure,
        why: seen.exit().unanswered().unwrap_or(Unanswered::Timeout),
        attempts: seen.attempts(),
        seen,
    }
}

/// Every other `az` failure: opv has no recording, so it says what it does know.
fn unrecognized(seen: Observed, ctx: &DiagnoseContext) -> Cause {
    let established = vec![principal_fact(seen.principal()), exit_fact(seen.exit())];
    Cause::Unrecognized {
        system: System::Azure,
        established,
        env: ctx.env.clone(),
        target: ctx.target.clone(),
        seen,
    }
}

/// Who was signed in or acting, as an established fact (never free text from `az`).
fn principal_fact(principal: &Principal) -> String {
    match principal {
        Principal::Person { .. } => "signed in as a person".to_string(),
        Principal::ServiceAccount { name } => format!("signed in as service account {name}"),
        Principal::ServicePrincipal { .. } => "signed in as a service principal".to_string(),
        Principal::AppIdentity { name } => format!("acting as app identity {name}"),
        Principal::StoreIdentity { name } => format!("acting as store identity {name}"),
        Principal::DeployCredentials { env, target, .. } => {
            format!("acting with deploy credentials of target {target} in environment {env}")
        }
        Principal::ShellToken { var } => format!("the token in {var} was in effect"),
    }
}

/// How the call ended, as an established fact.
fn exit_fact(exit: ExitClass) -> String {
    match exit {
        ExitClass::Code { code } => format!("exit code {code}"),
        ExitClass::Signal { signal } => format!("killed by signal {signal}"),
        ExitClass::TimedOut => "the call timed out".to_string(),
        ExitClass::SpawnFailed => "az could not be started".to_string(),
        ExitClass::Lost => "the call's reply was lost".to_string(),
    }
}

/// The ambient GitHub Actions context of a federated deploy (#297): the repository and
/// environment whose subject the app's federated credential must trust, plus whether the
/// job runs on a self-hosted runner. Every field is read from the job's environment and
/// holds no secret. Tests inject one with [`with_github_context`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GithubContext {
    /// `GITHUB_ACTIONS` is exactly `true`; `CI` alone is not enough (the federated ambient
    /// sign-in only exists in an Actions job that ran `azure/login`).
    pub actions: bool,
    /// `GITHUB_REPOSITORY`, `<owner>/<repo>`.
    pub repository: Option<String>,
    /// `GITHUB_ENVIRONMENT`: the job's GitHub environment, the trust subject's `environment`.
    pub environment: Option<String>,
    /// `RUNNER_ENVIRONMENT` is `self-hosted`.
    pub self_hosted: bool,
    /// `GITHUB_REPOSITORY_OWNER_ID`: the owner's numeric id, in GitHub's immutable subject.
    pub owner_id: Option<String>,
    /// `GITHUB_REPOSITORY_ID`: the repository's numeric id, in GitHub's immutable subject.
    pub repository_id: Option<String>,
}

impl GithubContext {
    /// The subjects the job's OIDC token may carry, GitHub's default first (#323): the
    /// immutable `repo:<owner>@<owner_id>/<repo>@<repo_id>:environment:<env>` when the job
    /// has both ids, then the classic `repo:<owner>/<repo>:environment:<env>`. Empty unless
    /// the job names its repository and environment. The token carries exactly one; which
    /// one is the repository's setting, which doctor does not read.
    pub fn subjects(&self) -> Vec<String> {
        let (Some(repo), Some(env)) = (self.repository.as_deref(), self.environment.as_deref())
        else {
            return Vec::new();
        };
        let mut out = Vec::new();
        if let (Some(owner_id), Some(repo_id), Some((owner, name))) = (
            self.owner_id.as_deref(),
            self.repository_id.as_deref(),
            repo.split_once('/'),
        ) {
            out.push(format!(
                "repo:{owner}@{owner_id}/{name}@{repo_id}:environment:{env}"
            ));
        }
        out.push(format!("repo:{repo}:environment:{env}"));
        out
    }
}

#[cfg(test)]
thread_local! {
    /// Tests force the ambient context without touching the process environment.
    static TEST_GITHUB_CONTEXT: std::cell::RefCell<Option<GithubContext>> =
        const { std::cell::RefCell::new(None) };
}

/// Run `f` with the ambient GitHub context forced to `ctx` (unit tests only).
#[cfg(test)]
pub(crate) fn with_github_context<T>(ctx: GithubContext, f: impl FnOnce() -> T) -> T {
    let prev = TEST_GITHUB_CONTEXT.with(|c| c.replace(Some(ctx)));
    let out = f();
    TEST_GITHUB_CONTEXT.with(|c| c.replace(prev));
    out
}

/// The ambient GitHub Actions context (#297). `GITHUB_ACTIONS=true` alone decides GitHub
/// Actions; `CI` is not enough, because the federated sign-in only exists in an Actions job
/// that ran `azure/login` first.
pub fn github_context() -> GithubContext {
    #[cfg(test)]
    if let Some(ctx) = TEST_GITHUB_CONTEXT.with(|c| c.borrow().clone()) {
        return ctx;
    }
    let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    GithubContext {
        actions: var("GITHUB_ACTIONS").is_some_and(|v| v == "true"),
        repository: var("GITHUB_REPOSITORY"),
        environment: var("GITHUB_ENVIRONMENT"),
        self_hosted: var("RUNNER_ENVIRONMENT").is_some_and(|v| v == "self-hosted"),
        owner_id: var("GITHUB_REPOSITORY_OWNER_ID"),
        repository_id: var("GITHUB_REPOSITORY_ID"),
    }
}

/// The `doctor` checks of a federated Azure target (#297), appended to the target's other
/// checks: one `deploy identity` line that explains the mode, a `federated credential` line
/// that compares the trust subject with the app's credentials when `probe` is asked for,
/// and a `runner` warning on a self-hosted runner. `probe` is `false` when an earlier check
/// already failed, so no `az` call follows a broken sign-in.
pub fn federated_checks(t: &AzureTarget, r: &dyn CommandRunner, probe: bool) -> Vec<Check> {
    let Some(f) = t.federated.as_ref() else {
        return Vec::new();
    };
    let ctx = github_context();
    let mode = format!(
        "federated (tenant {}, client {}, subscription {})",
        f.tenant_id, f.client_id, f.subscription_id
    );
    let mut checks = vec![Check {
        name: "deploy identity".into(),
        outcome: Ok(if ctx.actions {
            Verdict::Ok(mode)
        } else {
            Verdict::Ok(format!(
                "{mode}; CI only: this identity exists in a GitHub Actions job that signed \
                 in with azure/login, so doctor cannot check it here"
            ))
        }),
    }];
    if ctx.self_hosted {
        checks.push(Check {
            name: "runner".into(),
            outcome: Ok(Verdict::Warn(
                "self-hosted: the federated sign-in may stay on disk after the job; the \
                 generated workflow's az logout step (if: always()) removes it"
                    .into(),
            )),
        });
    }
    if !probe || !ctx.actions {
        return checks;
    }
    let subjects = ctx.subjects();
    let Some(subject) = subjects.first() else {
        checks.push(Check {
            name: "federated credential".into(),
            outcome: Ok(Verdict::Warn(
                "cannot check the app's federated credentials: GITHUB_REPOSITORY and \
                 GITHUB_ENVIRONMENT are not both set in this job"
                    .into(),
            )),
        });
        return checks;
    };
    checks.push(match listed_subjects(r, &f.client_id) {
        Ok(listed) => match subjects.iter().find(|s| listed.contains(s)) {
            Some(s) => Check {
                name: "federated credential".into(),
                outcome: Ok(Verdict::Ok(format!(
                    "{s} is trusted by the app's federated credentials"
                ))),
            },
            // The first subject is GitHub's default; a repository that still issues the
            // classic one is named too, so the person can tell which their tokens carry.
            None => Check {
                name: "federated credential".into(),
                outcome: Ok(Verdict::Warn(format!(
                    "the app's federated credentials do not include {subject}{}\n  az ad app \
                     federated-credential create --id {} --parameters \
                     '{{\"name\":\"{}\",\"issuer\":\"https://token.actions.githubusercontent.com\",\
                     \"subject\":\"{subject}\",\"audiences\":[\"api://AzureADTokenExchange\"]}}'",
                    match subjects.get(1) {
                        Some(classic) => format!(
                            " (GitHub's immutable subject; a repository that still issues the \
                             classic subject needs {classic} instead)"
                        ),
                        None => String::new(),
                    },
                    f.client_id,
                    super::federated::credential_name(subject),
                ))),
            },
        },
        // Advisory, like the identity-access check: an app registration the sign-in cannot
        // read does not prove the credential missing, so it is a warning, never a failure.
        Err(e) => Check {
            name: "federated credential".into(),
            outcome: Ok(Verdict::Warn(format!(
                "could not check the app's federated credentials ({e})"
            ))),
        },
    });
    checks
}

/// The subjects of an app's federated credentials (`az ad app federated-credential list
/// --id <client> -o json`, a read). Subjects and issuers are identifiers, never secrets.
fn listed_subjects(r: &dyn CommandRunner, client_id: &str) -> Result<Vec<String>, Error> {
    const OP: &str = "ad app federated-credential list";
    let args = [
        "ad",
        "app",
        "federated-credential",
        "list",
        "--id",
        client_id,
        "-o",
        "json",
    ];
    match az::invoke(r, Effect::Read, OP, &args, None, &[])? {
        Outcome::Done(out) => {
            let list: Vec<Value> = super::preflight::unreadable_json(&out.stdout, OP)?;
            Ok(list
                .iter()
                .filter_map(|c| c["subject"].as_str().map(String::from))
                .collect())
        }
        Outcome::Refused(_) | Outcome::Unknown { .. } => {
            Err(az::failed(r, DiagnoseContext::default()))
        }
    }
}

#[cfg(test)]
#[path = "diagnose_tests.rs"]
mod tests;
