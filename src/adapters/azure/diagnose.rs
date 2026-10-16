//! The Azure (`az`) diagnosis strategy (design `docs/design/error-catalog.md` §5, §12.4).
//!
//! Azure phrases are deferred until sandbox recordings exist (owner decision 2026-10-16):
//! no recorded Azure failure fixture exists, so this strategy never matches `az` wording.
//! It classifies only what the runner observed about the failed call — a timeout or signal
//! during a create, a write or a read, and a spawn failure — and reports every other
//! failure as `Unrecognized` with the facts it did establish. Azure phrases are added when
//! a recording exists.

use crate::cause::{Cause, DiagnoseContext, ExitClass, Observed, Principal, System, Unanswered};
use crate::host::Host;

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

#[cfg(test)]
#[path = "diagnose_tests.rs"]
mod tests;
