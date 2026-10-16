//! The Kubernetes (`kubectl`) diagnosis strategy (design `docs/design/error-catalog.md` §5).
//! It is the only place that classifies kubectl failures: a data table of raw-stderr phrases
//! plus the outcome the runner observed ([`Observed`]) and what the call site knows
//! ([`DiagnoseContext`]). Recordings that bind this table live in
//! `tests/fixtures/kubernetes/failures/` (see its README).

use crate::cause::{
    Cause, CredentialProblem, CredentialRef, DiagnoseContext, ExitClass, GrantModel, NamedBy,
    NotFoundState, Observed, Principal, ResourceKind, ResourceName, ResourceRef, Right,
    SessionState, System, Unanswered,
};

#[cfg(test)]
#[path = "diagnose_tests.rs"]
mod tests;

/// One classification decision a raw-stderr phrase selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rule {
    /// `You must be logged in to the server` (both 401 phrasings share this prefix).
    SignedOut,
    /// `Error from server (Forbidden): … cannot <verb> resource "<resource>" …`.
    Forbidden,
    /// A kubeconfig context that is not on this machine (`does not exist` on a resource
    /// call, `not found` on the `config get-contexts` probe).
    ContextMissing,
    /// A recorded Kubernetes resource that the server answered `(NotFound)` for.
    NotFound,
    /// External Secrets Operator not installed (`resource type` / raw-discovery NotFound).
    EsoMissing,
    /// The API server did not answer (`connection refused` / `was refused`).
    Network,
}

/// The phrase table: a raw-stderr substring selects a rule. Order matters: the context and
/// External Secrets phrases must precede the generic `(NotFound)` rule, and the misleading
/// `Warning: the server doesn't have a resource type 'secrets'` (single quotes) is never the
/// External Secrets phrase (double quotes).
const PHRASES: &[(&str, Rule)] = &[
    ("You must be logged in to the server", Rule::SignedOut),
    ("(Forbidden)", Rule::Forbidden),
    ("does not exist", Rule::ContextMissing),
    (
        "the server could not find the requested resource",
        Rule::EsoMissing,
    ),
    (
        "the server doesn't have a resource type \"clustersecretstores\"",
        Rule::EsoMissing,
    ),
    ("(NotFound)", Rule::NotFound),
    ("not found", Rule::ContextMissing),
    ("connection refused", Rule::Network),
    ("was refused", Rule::Network),
];

/// Turn what the runner observed about one failed `kubectl` call into a [`Cause`].
pub fn diagnose(seen: Observed, stderr: &str, ctx: &DiagnoseContext) -> Cause {
    // An unknown outcome is an outcome, not a phrase: a timed-out or interrupted create or
    // write may already have been applied, and a read that never answered is unavailable.
    if matches!(seen.exit(), ExitClass::TimedOut | ExitClass::Signal { .. }) {
        return unknown_outcome(seen, ctx);
    }
    for (phrase, rule) in PHRASES {
        if stderr.contains(phrase) {
            return apply(*rule, seen, stderr, ctx);
        }
    }
    // `auth can-i` reports a missing right as exit 1 with no stderr at all.
    if let Some((verb, resource)) = can_i_right(&seen) {
        return missing_right(seen, verb, resource, None, ctx);
    }
    // `api-resources --api-group=external-secrets.io` exits 0 with only the header row when
    // the operator is not installed.
    if is_eso_api_resources(&seen) {
        return eso_missing();
    }
    Cause::Unrecognized {
        system: System::Kubernetes,
        established: established(&seen),
        env: ctx.env.clone(),
        target: ctx.target.clone(),
        seen,
    }
}

fn apply(rule: Rule, seen: Observed, stderr: &str, ctx: &DiagnoseContext) -> Cause {
    match rule {
        Rule::SignedOut => signed_out(seen, ctx),
        Rule::Forbidden => {
            let (verb, resource, namespace) = parse_forbidden(stderr);
            missing_right(seen, verb, resource, namespace, ctx)
        }
        Rule::ContextMissing => context_missing(seen, stderr, ctx),
        Rule::NotFound => not_found(seen, stderr, ctx),
        Rule::EsoMissing => eso_missing(),
        Rule::Network => Cause::Unavailable {
            system: System::Kubernetes,
            why: Unanswered::Network,
            attempts: 1,
            seen,
        },
    }
}

/// A 401. A deploy credential or a shell token in effect is named as the rejected credential,
/// never the person's own sign-in.
fn signed_out(seen: Observed, ctx: &DiagnoseContext) -> Cause {
    let principal = seen.principal().clone();
    match principal {
        Principal::ShellToken { var } => Cause::CredentialRejected {
            system: System::Kubernetes,
            credential: CredentialRef::ShellToken { var },
            problem: CredentialProblem::Rejected { needs: Vec::new() },
            seen,
        },
        Principal::DeployCredentials {
            vault,
            item,
            env,
            target,
        } => Cause::CredentialRejected {
            system: System::Kubernetes,
            credential: CredentialRef::DeployCredentials {
                vault,
                item,
                env,
                target,
            },
            problem: CredentialProblem::Rejected { needs: Vec::new() },
            seen,
        },
        _ => Cause::NotSignedIn {
            system: System::Kubernetes,
            account: ctx.account.clone(),
            state: SessionState::Expired,
        },
    }
}

/// A 403. The verb is the HTTP verb the server saw, so server-side `apply` says `patch` and
/// `kubectl patch` says `get`; the resource and namespace come from the same message.
fn missing_right(
    seen: Observed,
    verb: String,
    resource: String,
    namespace: Option<String>,
    ctx: &DiagnoseContext,
) -> Cause {
    Cause::MissingRight {
        system: System::Kubernetes,
        resource: ctx.resource.clone().unwrap_or_else(|| ResourceRef {
            kind: kind_for(&resource),
            name: ResourceName::new(resource.clone()),
            scope: namespace.clone(),
        }),
        right: Right::Verb {
            verb: verb.clone(),
            resource: resource.clone(),
        },
        grant: GrantModel::K8sRbac {
            verb,
            resource,
            namespace,
        },
        env: ctx.env.clone(),
        target: ctx.target.clone(),
        seen,
    }
}

/// A kubeconfig context that is not on this machine.
fn context_missing(seen: Observed, stderr: &str, ctx: &DiagnoseContext) -> Cause {
    let name = between(stderr, "context \"", "\"")
        .or_else(|| between(stderr, "context ", " not found"))
        .unwrap_or_default();
    Cause::NotFound {
        system: System::Kubernetes,
        resource: ResourceRef {
            kind: ResourceKind::KubeContext,
            name: ResourceName::new(name),
            scope: None,
        },
        named_by: ctx.named_by.clone().unwrap_or(NamedBy::Flag {
            flag: "--context".to_string(),
        }),
        state: NotFoundState::LocalContextMissing,
        seen,
    }
}

/// A resource the server answered `(NotFound)` for. A missing namespace is reported as
/// `namespaces "<ns>" not found`, so the server names the namespace, not the target resource.
fn not_found(seen: Observed, stderr: &str, ctx: &DiagnoseContext) -> Cause {
    let (kind, name) = notfound_target(stderr);
    Cause::NotFound {
        system: System::Kubernetes,
        resource: ResourceRef {
            kind,
            name,
            scope: None,
        },
        named_by: ctx.named_by.clone().unwrap_or(NamedBy::Flag {
            flag: "--context".to_string(),
        }),
        state: NotFoundState::Missing,
        seen,
    }
}

/// External Secrets Operator not installed.
fn eso_missing() -> Cause {
    Cause::OwnerSetupRequired {
        system: System::Kubernetes,
        object: ResourceRef {
            kind: ResourceKind::ExternalStore,
            name: ResourceName::new("External Secrets Operator"),
            scope: None,
        },
    }
}

/// The unknown outcome of a timed-out or interrupted call, by effect.
fn unknown_outcome(seen: Observed, ctx: &DiagnoseContext) -> Cause {
    if let Some((kind, name, refind)) = &ctx.create {
        return Cause::CreateOutcomeUnknown {
            system: System::Kubernetes,
            kind: *kind,
            name: name.clone(),
            refind: refind.clone(),
            seen,
        };
    }
    if ctx.write {
        return Cause::WriteOutcomeUnknown {
            system: System::Kubernetes,
            subject: ctx.resource.clone().unwrap_or_else(placeholder_subject),
            seen,
        };
    }
    Cause::Unavailable {
        system: System::Kubernetes,
        why: Unanswered::Timeout,
        attempts: 1,
        seen,
    }
}

fn placeholder_subject() -> ResourceRef {
    ResourceRef {
        kind: ResourceKind::ExternalStore,
        name: ResourceName::new(""),
        scope: None,
    }
}

/// What the strategy did establish when nothing matched.
fn established(seen: &Observed) -> Vec<String> {
    let ended = match seen.exit() {
        ExitClass::Code { code } => format!("exit code {code}"),
        ExitClass::Signal { signal } => format!("signal {signal}"),
        ExitClass::TimedOut => "a timeout".to_string(),
        ExitClass::SpawnFailed => "kubectl not starting".to_string(),
    };
    vec![format!("the call ended with {ended}")]
}

/// The `auth can-i <verb> <resource>` shape, whose "no" answer has empty stderr.
fn can_i_right(seen: &Observed) -> Option<(String, String)> {
    let words = &seen.call().words;
    let at = words.iter().position(|w| w == "can-i")?;
    let mut named = words[at + 1..].iter().filter(|w| !w.starts_with('-'));
    Some((named.next()?.clone(), named.next()?.clone()))
}

/// The `api-resources --api-group=external-secrets.io` shape.
fn is_eso_api_resources(seen: &Observed) -> bool {
    let words = &seen.call().words;
    words.iter().any(|w| w == "api-resources")
        && words.iter().any(|w| w.contains("external-secrets.io"))
}

/// `cannot <verb> resource "<resource>" … in the namespace "<ns>"`.
fn parse_forbidden(stderr: &str) -> (String, String, Option<String>) {
    let verb = between(stderr, "cannot ", " resource").unwrap_or_default();
    let resource = between(stderr, "resource \"", "\"").unwrap_or_default();
    let namespace = between(stderr, "in the namespace \"", "\"");
    (verb, resource, namespace)
}

/// The resource kind and name out of `Error from server (NotFound): <kind> "<name>" not found`.
fn notfound_target(stderr: &str) -> (ResourceKind, ResourceName) {
    let rest = stderr
        .split_once("(NotFound): ")
        .map(|(_, r)| r)
        .unwrap_or(stderr);
    let kind_word = rest.split_whitespace().next().unwrap_or("");
    let name = between(rest, "\"", "\"").unwrap_or_else(|| kind_word.to_string());
    (kind_for(kind_word), ResourceName::new(name))
}

/// The best-fit catalog kind for a kubectl resource word (`deployments.apps`, `secrets`).
fn kind_for(resource: &str) -> ResourceKind {
    let base = resource.split('.').next().unwrap_or(resource);
    match base {
        "namespaces" | "namespace" => ResourceKind::Namespace,
        "deployments" => ResourceKind::Deployment,
        "contexts" | "context" => ResourceKind::KubeContext,
        _ => ResourceKind::ExternalStore,
    }
}

/// The text between `start` and the next `end`.
fn between(s: &str, start: &str, end: &str) -> Option<String> {
    let rest = s.split_once(start)?.1;
    Some(rest.split_once(end)?.0.to_string())
}
