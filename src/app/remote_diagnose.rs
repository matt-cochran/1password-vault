//! The ssh diagnosis strategy (design §5, #139): the one place that turns a failed remote
//! delivery call into a [`Cause`].
//!
//! Everything here is data plus the [`ExitClass`] and [`Principal`] the runner recorded. The
//! phrases are OpenSSH's own wording, matched on the raw stderr before scrubbing; no line is
//! invented, each comes from `tests/fixtures/ssh/failures/`. The caller passes the pinned
//! connection facts ([`Connection`]) and whether the receiver's handshake completed, because
//! stderr alone cannot tell "the host is unreachable" from "the remote app exited 255".

use std::path::Path;

use crate::cause::{
    Cause, CredentialProblem, CredentialRef, DiagnoseContext, ExitClass, IoKind, Observed,
    Principal, ProfileName, RemotePhase, ResourceKind, ResourceName, ResourceRef, System,
    Unanswered,
};

/// What the caller knows about the pinned connection and the session when ssh failed. The
/// strategy never parses these back out of stderr: the host-key banner truncates the
/// `known_hosts` path, and the remote program is the profile's `opv` path.
#[derive(Debug, Clone)]
pub struct Connection<'a> {
    /// The remote profile's name.
    pub profile: &'a str,
    /// The login user.
    pub user: &'a str,
    /// The host ssh connected to.
    pub host: &'a str,
    /// The port ssh connected to.
    pub port: u16,
    /// The file holding the pinned host key (the full path; the banner truncates it).
    pub known_hosts: &'a Path,
    /// The SSH private key the profile names; `None` is the agent.
    pub identity_file: Option<&'a Path>,
    /// The remote program the pinned command starts (the profile's `opv` path).
    pub remote_program: &'a str,
    /// The receiver finished its handshake: a 255 after it is not a pre-handshake failure.
    pub handshake_done: bool,
    /// The receiver confirmed the whole payload; `false` makes a disconnect a `Delivery`.
    pub payload_confirmed: bool,
}

/// One row of the phrase table (design §5): a system's own wording and the cause class it
/// names. Matched with `contains` on the raw stderr.
struct Phrase {
    needle: &'static str,
    class: Class,
}

/// The cause class a phrase names, before the exit class and handshake decide whether it is
/// reachable. A class is only consulted in the context it can happen in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    CredentialRejected,
    RemoteUnreachable,
    RemoteDisconnected,
    ChildStartFailed,
}

/// The phrase table for this system, from `tests/fixtures/ssh/failures/` (recorded OpenSSH
/// 9.6 output). The host-key banner truncates the pin path, so no phrase holds a path; a
/// quote mismatch is recognised by `Host key verification failed` instead.
const PHRASES: &[Phrase] = &[
    Phrase {
        needle: "Permission denied (publickey)",
        class: Class::CredentialRejected,
    },
    Phrase {
        needle: "not accessible",
        class: Class::CredentialRejected,
    },
    Phrase {
        needle: "REMOTE HOST IDENTIFICATION HAS CHANGED",
        class: Class::RemoteUnreachable,
    },
    Phrase {
        needle: "Host key verification failed",
        class: Class::RemoteUnreachable,
    },
    Phrase {
        needle: "host key is known for",
        class: Class::RemoteUnreachable,
    },
    Phrase {
        needle: "Connection refused",
        class: Class::RemoteUnreachable,
    },
    Phrase {
        needle: "Could not resolve hostname",
        class: Class::RemoteUnreachable,
    },
    Phrase {
        needle: "Connection timed out",
        class: Class::RemoteUnreachable,
    },
    Phrase {
        needle: "closed by remote host",
        class: Class::RemoteDisconnected,
    },
    Phrase {
        needle: "not responding",
        class: Class::RemoteDisconnected,
    },
    Phrase {
        needle: "command not found",
        class: Class::ChildStartFailed,
    },
    Phrase {
        needle: "No such file or directory",
        class: Class::ChildStartFailed,
    },
];

fn mentions(stderr: &str, class: Class) -> bool {
    PHRASES
        .iter()
        .any(|p| p.class == class && stderr.contains(p.needle))
}

/// Turn one failed ssh call into a cause. `stderr` is the raw stderr; `conn` is what the
/// caller knows about the pinned profile; `ctx` says whether the call created or wrote.
pub fn diagnose(
    seen: Observed,
    stderr: &str,
    conn: &Connection<'_>,
    ctx: &DiagnoseContext,
) -> Cause {
    match seen.exit() {
        // An unknown outcome is about the effect, never about the text: a create may have
        // happened, a write may have landed, a read did not happen.
        ExitClass::TimedOut | ExitClass::Signal { .. } => unknown_outcome(seen, conn, ctx),
        ExitClass::Code { code } => classify_code(seen, stderr, conn, ctx, code),
        ExitClass::SpawnFailed => unrecognized(seen, conn, ctx),
    }
}

/// A timed-out or killed attempt: the effect's outcome is unknown.
fn unknown_outcome(seen: Observed, conn: &Connection<'_>, ctx: &DiagnoseContext) -> Cause {
    if let Some((kind, name, refind)) = &ctx.create {
        return Cause::CreateOutcomeUnknown {
            system: System::Ssh,
            kind: *kind,
            name: name.clone(),
            refind: refind.clone(),
            seen,
        };
    }
    if ctx.write {
        return Cause::WriteOutcomeUnknown {
            system: System::Ssh,
            subject: subject(conn, ctx),
            seen,
        };
    }
    let why = match seen.exit() {
        ExitClass::TimedOut => Unanswered::Timeout,
        _ => Unanswered::Network,
    };
    Cause::Unavailable {
        system: System::Ssh,
        why,
        attempts: 1,
        seen,
    }
}

/// Classify a definite exit code. The handshake splits 255; the remote shell's own wording
/// splits 127 from a remote app that happens to exit 127.
fn classify_code(
    seen: Observed,
    stderr: &str,
    conn: &Connection<'_>,
    ctx: &DiagnoseContext,
    code: i32,
) -> Cause {
    if code == 127 && mentions(stderr, Class::ChildStartFailed) {
        return Cause::ChildStartFailed {
            program: conn.remote_program.to_string(),
            workdir: None,
            io: IoKind::NotFound,
            remote: Some(ProfileName::new(conn.profile)),
        };
    }
    if code == 255 {
        if conn.handshake_done {
            if mentions(stderr, Class::RemoteDisconnected) {
                return Cause::RemoteDisconnected {
                    profile: ProfileName::new(conn.profile),
                    host: conn.host.to_string(),
                    during: if conn.payload_confirmed {
                        RemotePhase::Running
                    } else {
                        RemotePhase::Delivery
                    },
                };
            }
            return unrecognized(seen, conn, ctx);
        }
        if mentions(stderr, Class::CredentialRejected) {
            let credential = credential_from(&seen, conn);
            let problem = credential_problem(stderr);
            return Cause::CredentialRejected {
                system: System::Ssh,
                credential,
                problem,
                seen,
            };
        }
        if mentions(stderr, Class::RemoteUnreachable) {
            return Cause::RemoteUnreachable {
                profile: ProfileName::new(conn.profile),
                user: conn.user.to_string(),
                host: conn.host.to_string(),
                port: conn.port,
                known_hosts: conn.known_hosts.to_path_buf(),
                identity_file: conn.identity_file.map(Path::to_path_buf),
            };
        }
    }
    unrecognized(seen, conn, ctx)
}

/// The credential that was rejected: the acting principal, never a person's sign-in when a
/// shell token or deploy credentials were in effect (design §5).
fn credential_from(seen: &Observed, conn: &Connection<'_>) -> CredentialRef {
    match seen.principal() {
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
        _ => CredentialRef::SshIdentity {
            path: conn.identity_file.map(Path::to_path_buf),
        },
    }
}

/// A missing identity file is `Unreadable` (the warning line names it); a refused key is
/// `Rejected`.
fn credential_problem(stderr: &str) -> CredentialProblem {
    if stderr.contains("not accessible") {
        CredentialProblem::Unreadable
    } else {
        CredentialProblem::Rejected { needs: Vec::new() }
    }
}

/// The resource a write was about, when the call site named one.
fn subject(conn: &Connection<'_>, ctx: &DiagnoseContext) -> ResourceRef {
    ctx.resource.clone().unwrap_or_else(|| ResourceRef {
        kind: ResourceKind::Deployment,
        name: ResourceName::new(conn.profile),
        scope: Some(conn.host.to_string()),
    })
}

/// Nothing matched: carry what the strategy did establish, so it is never vaguer than the
/// facts.
fn unrecognized(seen: Observed, conn: &Connection<'_>, ctx: &DiagnoseContext) -> Cause {
    Cause::Unrecognized {
        system: System::Ssh,
        established: established(&seen, conn),
        env: ctx.env.clone(),
        target: ctx.target.clone(),
        seen,
    }
}

fn established(seen: &Observed, conn: &Connection<'_>) -> Vec<String> {
    let mut facts = Vec::new();
    match seen.exit() {
        ExitClass::Code { code } => facts.push(format!("ssh exited {code}")),
        ExitClass::Signal { signal } => facts.push(format!("ssh was killed by signal {signal}")),
        ExitClass::TimedOut => facts.push("ssh timed out".to_string()),
        ExitClass::SpawnFailed => facts.push("ssh could not be started".to_string()),
    }
    facts.push(if conn.handshake_done {
        "the receiver's handshake completed".to_string()
    } else {
        "the receiver's handshake did not complete".to_string()
    });
    facts
}

#[cfg(test)]
#[path = "remote_diagnose_tests.rs"]
mod tests;
