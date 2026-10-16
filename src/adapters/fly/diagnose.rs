//! Fly (`flyctl`) diagnosis: the one place that classifies a failed flyctl call (design
//! `docs/design/error-catalog.md` §5).
//!
//! Every external failure becomes a [`Cause`] here, from three facts only: the raw stderr
//! the call produced (matched against the recorded phrases below, before any scrubbing),
//! the exit class the runner observed, and the principal that was in effect. Nothing reads
//! the child's stdout, and no value ever reaches a cause.
//!
//! flyctl has no clock of its own: when the call ends on opv's timeout (or a signal) the
//! outcome depends on what the call was doing — an unknown create, an unknown write, or an
//! unavailable read — never on the text, which may be absent or a fragment.

use crate::cause::{
    Cause, CredentialProblem, CredentialRef, DiagnoseContext, ExitClass, NamedBy, NotFoundState,
    Observed, Principal, ResourceKind, ResourceName, ResourceRef, SessionState, System, Unanswered,
    VaultId,
};

/// Classify one failed `flyctl` call (design §5).
pub fn diagnose(seen: Observed, stderr: &str, ctx: &DiagnoseContext) -> Cause {
    // The runner's budget is the only clock flyctl has. An unfinished call is diagnosed by
    // what it was doing, never by its text (which may be a fragment).
    if let Some(why) = ended_before_reply(&seen) {
        return unknown_outcome(&seen, ctx, why);
    }
    match reading(stderr) {
        Some(Reading::SignedOut) => Cause::NotSignedIn {
            system: System::Fly,
            account: ctx.account.clone(),
            state: SessionState::SignedOut,
        },
        Some(Reading::CredentialRejected) => credential_rejected(&seen, ctx),
        Some(Reading::AppMissing) => {
            let resource = resource(&seen, ctx);
            Cause::NotFound {
                system: System::Fly,
                resource,
                named_by: named_by(ctx),
                state: NotFoundState::Missing,
                seen,
            }
        }
        Some(Reading::Network) => Cause::Unavailable {
            system: System::Fly,
            why: Unanswered::Network,
            attempts: 1,
            seen,
        },
        Some(Reading::TimedOut) => unknown_outcome(&seen, ctx, Unanswered::Timeout),
        None => Cause::Unrecognized {
            system: System::Fly,
            established: established(&seen),
            env: ctx.env.clone(),
            target: ctx.target.clone(),
            seen,
        },
    }
}

/// What a recorded flyctl phrase tells us, before the subject is filled in (§5: the phrase
/// tables are data, one row per cause).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reading {
    /// `no access token available. Please login with 'flyctl auth login'`.
    SignedOut,
    /// `You must be authenticated to view this.` / `Authenticate: token validation error`.
    CredentialRejected,
    /// `failed to list app secrets: app not found`.
    AppMissing,
    /// `Post "...": terminated signal received` (the runner's timeout/signal).
    TimedOut,
    /// `proxyconnect tcp: … connect: connection refused`.
    Network,
}

/// The recorded flyctl failure phrases, matched on the raw stderr (§5: before scrubbing, so
/// a phrase is never lost to redaction). The first row that matches wins, so a specific
/// phrase must come before a broader one.
const PHRASES: &[(Reading, &[&str])] = &[
    (Reading::SignedOut, &["no access token available"]),
    (
        Reading::CredentialRejected,
        &[
            "You must be authenticated to view this.",
            "token validation error",
        ],
    ),
    (Reading::AppMissing, &["app not found"]),
    (
        Reading::TimedOut,
        &["terminated signal received", "context deadline exceeded"],
    ),
    (
        Reading::Network,
        &[
            "connection refused",
            "proxyconnect tcp",
            "dial tcp",
            "no such host",
        ],
    ),
];

/// The first recorded phrase that appears in `stderr`.
fn reading(stderr: &str) -> Option<Reading> {
    PHRASES
        .iter()
        .find(|(_, phrases)| phrases.iter().any(|phrase| stderr.contains(phrase)))
        .map(|(reading, _)| *reading)
}

/// The exit classes that mean the call never got a reply opv can read: opv's timeout or a
/// signal. flyctl has no timeout of its own, so the runner's clock is the only source.
fn ended_before_reply(seen: &Observed) -> Option<Unanswered> {
    match seen.exit() {
        ExitClass::TimedOut | ExitClass::Signal { .. } => Some(Unanswered::Timeout),
        _ => None,
    }
}

/// What to report when the call did not finish (§4.6): a create's outcome and a write's
/// outcome are unknown, a read is simply unavailable.
fn unknown_outcome(seen: &Observed, ctx: &DiagnoseContext, why: Unanswered) -> Cause {
    if let Some((kind, name, refind)) = &ctx.create {
        return Cause::CreateOutcomeUnknown {
            system: System::Fly,
            kind: *kind,
            name: name.clone(),
            refind: refind.clone(),
            seen: seen.clone(),
        };
    }
    if ctx.write {
        return Cause::WriteOutcomeUnknown {
            system: System::Fly,
            subject: resource(seen, ctx),
            seen: seen.clone(),
        };
    }
    Cause::Unavailable {
        system: System::Fly,
        why,
        attempts: 1,
        seen: seen.clone(),
    }
}

/// A rejected credential is the credential the runner reported, never the person's sign-in
/// (§5, "The principal is known"). flyctl's own text never names the variable, so only the
/// principal tells a shell token from the person's login and from deploy credentials.
fn credential_rejected(seen: &Observed, ctx: &DiagnoseContext) -> Cause {
    match seen.principal() {
        Principal::ShellToken { var } => Cause::CredentialRejected {
            system: System::Fly,
            credential: CredentialRef::ShellToken { var: var.clone() },
            problem: CredentialProblem::Rejected { needs: Vec::new() },
            seen: seen.clone(),
        },
        Principal::DeployCredentials { item, env, target } => Cause::CredentialRejected {
            system: System::Fly,
            credential: CredentialRef::DeployCredentials {
                // The runner's principal does not carry the item's vault; the renderer names
                // the item, environment and target that identify the credential.
                vault: VaultId::new(""),
                item: item.clone(),
                env: env.clone(),
                target: target.clone(),
            },
            problem: CredentialProblem::Rejected { needs: Vec::new() },
            seen: seen.clone(),
        },
        // No credential was in effect, so the reply means the person's own login is no
        // longer accepted: flyctl found a token and rejected it, not the signed-out wording.
        _ => Cause::NotSignedIn {
            system: System::Fly,
            account: ctx.account.clone(),
            state: SessionState::Expired,
        },
    }
}

/// The resource a cause is about: what the call site knows, else the app named in the call's
/// own argv (`-a` / `--app`), so a not-found reply still names the app.
fn resource(seen: &Observed, ctx: &DiagnoseContext) -> ResourceRef {
    ctx.resource.clone().unwrap_or_else(|| ResourceRef {
        kind: ResourceKind::FlyApp,
        name: ResourceName::new(app_from_call(seen).unwrap_or_else(|| "app".to_string())),
        scope: None,
    })
}

/// The `-a` / `--app` value in the call's words, when the call carried one.
fn app_from_call(seen: &Observed) -> Option<String> {
    seen.call().words.windows(2).find_map(|pair| match pair {
        [flag, name] if flag == "-a" || flag == "--app" => Some(name.clone()),
        _ => None,
    })
}

/// Where a missing resource's name came from (§4.4). The call site fills this in; a Fly app
/// is declared under a target's `fly.app` field or given with `--fly-app`.
fn named_by(ctx: &DiagnoseContext) -> NamedBy {
    ctx.named_by.clone().unwrap_or(NamedBy::Flag {
        flag: "--fly-app".to_string(),
    })
}

/// What the strategy did establish, for `Unrecognized` (§5). Facts only: the principal in
/// effect and how the call ended, never a guess.
fn established(seen: &Observed) -> Vec<String> {
    let mut facts = Vec::new();
    match seen.principal() {
        Principal::ShellToken { var } => facts.push(format!("the token in {var} was in effect")),
        Principal::DeployCredentials { env, target, .. } => facts.push(format!(
            "deploy credentials of target {target} in environment {env} were in effect"
        )),
        _ => {}
    }
    match seen.exit() {
        ExitClass::TimedOut => facts.push("the call ended on opv's timeout".to_string()),
        ExitClass::Signal { signal } => facts.push(format!("the call ended on signal {signal}")),
        _ => {}
    }
    facts
}

#[cfg(test)]
#[path = "diagnose_tests.rs"]
mod tests;
