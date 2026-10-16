//! GitHub CLI (`gh`) diagnosis: the one place that classifies a failed gh call (design
//! `docs/design/error-catalog.md` §5).
//!
//! Every external failure becomes a [`Cause`] here, from three facts only: the raw stderr
//! the call produced (matched against the recorded phrases below, before any scrubbing),
//! the exit class the runner observed, and the principal that was in effect. Nothing reads
//! the child's stdout, and no value ever reaches a cause.
//!
//! The phrases come only from `tests/fixtures/github/failures/` (see its README). The cases
//! that README leaves to the owner to record (a genuine repository 404, a token missing the
//! Environments permission, rate limiting) have no phrase here yet: until they are recorded
//! they are `Unrecognized`, never a guess. gh checks the credential before it looks up a
//! repository, so with a bad token a missing repository reads as the rejected token.
//!
//! gh has no clock of its own: when the call ends on opv's timeout (or a signal) the outcome
//! depends on what the call was doing — an unknown create, an unknown write, or an
//! unavailable read — never on the text, which may be absent or a fragment.

use crate::cause::{
    Cause, CredentialProblem, CredentialRef, DiagnoseContext, Observed, Principal, ResourceKind,
    ResourceName, ResourceRef, SessionState, System, Unanswered, VarName,
};

/// The shell variable gh reads first, named when its refusal text cannot be read.
const GH_TOKEN: &str = "GH_TOKEN";

/// Classify one failed `gh` call (design §5).
pub fn diagnose(seen: Observed, stderr: &str, ctx: &DiagnoseContext) -> Cause {
    // The runner's budget is the only clock gh has. An unfinished call is diagnosed by what
    // it was doing, never by its text (which may be a fragment).
    if seen.exit().unanswered().is_some() {
        return unknown_outcome(&seen, ctx);
    }
    match reading(stderr) {
        Some(Reading::SignedOut) => Cause::NotSignedIn {
            system: System::GitHub,
            account: ctx.account.clone(),
            state: SessionState::SignedOut,
        },
        Some(Reading::LoginOverridden) => {
            let var = overriding_var(&seen, stderr);
            Cause::CredentialRejected {
                system: System::GitHub,
                credential: CredentialRef::ShellToken { var: var.clone() },
                problem: CredentialProblem::OverriddenByEnvironment { var },
                seen,
            }
        }
        Some(Reading::BadCredentials) => credential_rejected(seen, ctx),
        None => Cause::Unrecognized {
            system: System::GitHub,
            established: established(&seen),
            env: ctx.env.clone(),
            target: ctx.target.clone(),
            seen,
        },
    }
}

/// What a recorded gh phrase tells us, before the subject is filled in (§5: the phrase
/// tables are data, one row per cause).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reading {
    /// `To get started with GitHub CLI, please run:  gh auth login` (recordings 01, 05).
    SignedOut,
    /// `The value of the GH_TOKEN environment variable is being used for authentication.`
    /// from `gh auth login --with-token` (recording 03).
    LoginOverridden,
    /// `gh: Bad credentials (HTTP 401)` (recordings 02, 04).
    BadCredentials,
}

/// The recorded gh failure phrases, matched on the raw stderr (§5: before scrubbing, so a
/// phrase is never lost to redaction). The first row that matches wins.
const PHRASES: &[(Reading, &[&str])] = &[
    (
        Reading::SignedOut,
        &["To get started with GitHub CLI, please run:"],
    ),
    (
        Reading::LoginOverridden,
        &["environment variable is being used for authentication"],
    ),
    (
        Reading::BadCredentials,
        &[
            "Bad credentials (HTTP 401)",
            // `gh secret list|set` with a rejected token (spike Q9,
            // `tests/fixtures/github/stderr-bad_token.txt`).
            "HTTP 401: Bad credentials",
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

/// The variable that made `gh auth login` refuse: the shell token the runner reported, else
/// the name gh's own refusal gives (`The value of the <VAR> environment variable …`).
fn overriding_var(seen: &Observed, stderr: &str) -> VarName {
    if let Principal::ShellToken { var } = seen.principal() {
        return var.clone();
    }
    let named = stderr
        .split("The value of the ")
        .nth(1)
        .and_then(|rest| rest.split(" environment variable").next())
        .filter(|var| !var.is_empty() && var.chars().all(|c| c.is_ascii_uppercase() || c == '_'));
    VarName::new(named.unwrap_or(GH_TOKEN))
}

/// What to report when the call did not finish (§4.6): a create's outcome and a write's
/// outcome are unknown, a read is simply unavailable.
fn unknown_outcome(seen: &Observed, ctx: &DiagnoseContext) -> Cause {
    if let Some((kind, name, refind)) = &ctx.create {
        return Cause::CreateOutcomeUnknown {
            system: System::GitHub,
            kind: *kind,
            name: name.clone(),
            refind: refind.clone(),
            seen: seen.clone(),
        };
    }
    if ctx.write {
        return Cause::WriteOutcomeUnknown {
            system: System::GitHub,
            subject: resource(seen, ctx),
            seen: seen.clone(),
        };
    }
    Cause::Unavailable {
        system: System::GitHub,
        why: seen.exit().unanswered().unwrap_or(Unanswered::Timeout),
        attempts: seen.attempts(),
        seen: seen.clone(),
    }
}

/// A rejected credential is the credential the runner reported, never the person's sign-in
/// (§5, "The principal is known"). gh's `Bad credentials` never names the variable, so only
/// the principal tells a shell token from the person's login and from deploy credentials.
fn credential_rejected(seen: Observed, ctx: &DiagnoseContext) -> Cause {
    let credential = match seen.principal() {
        Principal::ShellToken { var } => CredentialRef::ShellToken { var: var.clone() },
        Principal::DeployCredentials {
            vault,
            item,
            env,
            target,
        } => CredentialRef::DeployCredentials {
            vault: vault.clone(),
            item: item.clone(),
            env: env.clone(),
            target: target.clone(),
        },
        // No credential was in effect, so the reply means the person's stored gh login is no
        // longer accepted.
        _ => {
            return Cause::NotSignedIn {
                system: System::GitHub,
                account: ctx.account.clone(),
                state: SessionState::Expired,
            };
        }
    };
    Cause::CredentialRejected {
        system: System::GitHub,
        credential,
        problem: CredentialProblem::Rejected { needs: Vec::new() },
        seen,
    }
}

/// The resource a cause is about: what the call site knows, else the repository named in the
/// call's own argv (`-R` / `--repo`).
fn resource(seen: &Observed, ctx: &DiagnoseContext) -> ResourceRef {
    ctx.resource.clone().unwrap_or_else(|| ResourceRef {
        kind: ResourceKind::Repository,
        name: ResourceName::new(repo_from_call(seen).unwrap_or_else(|| "repository".to_string())),
        scope: None,
    })
}

/// The `-R` / `--repo` value in the call's words, when the call carried one.
fn repo_from_call(seen: &Observed) -> Option<String> {
    seen.call().words.windows(2).find_map(|pair| match pair {
        [flag, name] if flag == "-R" || flag == "--repo" => Some(name.clone()),
        _ => None,
    })
}

/// What the strategy did establish, for `Unrecognized` (§5). Facts only: the principal in
/// effect, never a guess.
fn established(seen: &Observed) -> Vec<String> {
    match seen.principal() {
        Principal::ShellToken { var } => vec![format!("the token in {var} was in effect")],
        Principal::DeployCredentials { env, target, .. } => vec![format!(
            "deploy credentials of target {target} in environment {env} were in effect"
        )],
        _ => Vec::new(),
    }
}

#[cfg(test)]
#[path = "diagnose_tests.rs"]
mod tests;
