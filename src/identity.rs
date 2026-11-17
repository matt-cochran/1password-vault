//! Which 1Password identity a run uses (#338; design `agent-identity.md` §5, vet R4).
//!
//! The first matching rule wins:
//!
//! 1. `OP_SERVICE_ACCOUNT_TOKEN` or `OP_CONNECT_*` is set: that credential (CI, as today).
//! 2. `OPV_IDENTITY=person`: the person's session.
//! 3. `OPV_IDENTITY=agent`: the agent identity of the environment being operated on, read
//!    through an [`AgentCredentialSource`]. With none installed the run stops with
//!    `agent_identity_not_installed`; it **never** falls back to the person's session (R4).
//! 4. (an agent marker with any agent identity installed: slice S17, not here)
//! 5. Otherwise: the person's session (as today).
//!
//! Any other `OPV_IDENTITY` value is refused (`usage`). Until then [`crate::host::Host`]
//! treats it as the agent, so a mistyped value never reaches a write-capable session.
//!
//! The identity is resolved once per process, before the first `op` call, and cached
//! ([`resolve`], [`Resolver`]). The token is a [`SecretValue`], registered with the scrubber
//! when the store hands it over. It is never put into opv's environment, so a child that runs
//! `env` never shows it; the runner passes it to `op` alone ([`agent_token`], slice S6).
//! Nothing here prints it: [`AgentIdentity`]'s `Debug` and `Display` carry only its name and
//! key (ADR-0001).

use std::fmt;
use std::sync::OnceLock;

use crate::adapters::credential_store::{AgentCredentialSource, AgentKey};
use crate::cause::{Cause, UsageProblem};
use crate::domain::secret::SecretValue;
use crate::error::Error;
use crate::host::{HostEnv, OpCredential, ProcessEnv};

/// The variable that selects the identity (rules 2 and 3).
pub const VAR: &str = "OPV_IDENTITY";

/// What [`VAR`] asks for, read by name and value (it is a flag, never a secret).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Asked {
    /// Unset or empty.
    Nothing,
    Person,
    Agent,
    /// Any other value: refused by [`choose`], treated as the agent by the host.
    Unknown,
}

pub(crate) fn asked(env: &dyn HostEnv) -> Asked {
    match env.flag(VAR).map(|v| v.trim().to_ascii_lowercase()) {
        None => Asked::Nothing,
        Some(v) if v.is_empty() => Asked::Nothing,
        Some(v) if v == "person" => Asked::Person,
        Some(v) if v == "agent" => Asked::Agent,
        Some(_) => Asked::Unknown,
    }
}

/// Rule 1: the non-interactive credential in the environment, by name (service account wins
/// over Connect). Values are never read.
pub(crate) fn env_token(env: &dyn HostEnv) -> Option<OpCredential> {
    if env.is_set("OP_SERVICE_ACCOUNT_TOKEN") {
        Some(OpCredential::ServiceAccount)
    } else if env.is_set("OP_CONNECT_HOST") || env.is_set("OP_CONNECT_TOKEN") {
        Some(OpCredential::Connect)
    } else {
        None
    }
}

/// Which identity the rules pick, before any store is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    /// Rule 1: a service-account or Connect credential in the environment.
    EnvToken(OpCredential),
    /// Rules 2 and 5: the person's session.
    Person,
    /// Rule 3: the agent identity of the environment.
    Agent,
}

/// Rules 1-3 and 5, from `env` alone (no I/O). An unknown [`VAR`] value is refused with
/// `usage` (`OPV_IDENTITY expects person or agent`); the value is not repeated.
pub fn choose(env: &dyn HostEnv) -> Result<Choice, Error> {
    if let Some(c) = env_token(env) {
        return Ok(Choice::EnvToken(c));
    }
    match asked(env) {
        Asked::Nothing | Asked::Person => Ok(Choice::Person),
        Asked::Agent => Ok(Choice::Agent),
        Asked::Unknown => Err(Cause::Usage {
            problem: UsageProblem::ValueFormat {
                flag: VAR.to_string(),
                format: "person or agent",
            },
        }
        .into()),
    }
}

/// The agent identity to read when rule 3 applies: its store key (account/project/env) and
/// its 1Password service-account name (from the value-free index, design §7.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentTarget {
    pub key: AgentKey,
    pub name: String,
}

/// The agent identity this process runs as. Holds the token; prints only the name and key.
pub struct AgentIdentity {
    key: AgentKey,
    name: String,
    token: SecretValue,
}

impl AgentIdentity {
    /// The store key, `account_id/project/env`.
    pub fn key(&self) -> &AgentKey {
        &self.key
    }

    /// The 1Password service-account name (`{project}-{env}-agent-{machine}`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The token, for the runner to hand to `op` alone (slice S6). Never logged or printed.
    pub fn token(&self) -> &SecretValue {
        &self.token
    }
}

impl fmt::Debug for AgentIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentIdentity")
            .field("key", &self.key.user())
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for AgentIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "agent identity {} ({})", self.name, self.key.user())
    }
}

/// The identity this process resolved.
#[derive(Debug)]
pub enum Resolved {
    /// Rule 1.
    EnvToken(OpCredential),
    /// Rules 2 and 5.
    Person,
    /// Rule 3.
    Agent(AgentIdentity),
}

impl Resolved {
    /// What [`crate::host::Host::op_credential`] reports for this identity.
    pub fn op_credential(&self) -> Option<OpCredential> {
        match self {
            Resolved::EnvToken(c) => Some(*c),
            Resolved::Person => None,
            Resolved::Agent(_) => Some(OpCredential::Agent),
        }
    }

    /// The agent identity, under rule 3.
    pub fn agent(&self) -> Option<&AgentIdentity> {
        match self {
            Resolved::Agent(a) => Some(a),
            _ => None,
        }
    }
}

/// Resolves the identity at most once and keeps it. [`resolve`] uses the process's own; tests
/// make their own.
#[derive(Debug, Default)]
pub struct Resolver {
    cell: OnceLock<Resolved>,
}

impl Resolver {
    pub const fn new() -> Self {
        Self {
            cell: OnceLock::new(),
        }
    }

    /// The identity resolved so far, if any.
    pub fn get(&self) -> Option<&Resolved> {
        self.cell.get()
    }

    /// Apply the rules to `env` and, under rule 3, read the token for `target()` from
    /// `source`. The first success is kept: every later call returns it without another
    /// read. `target` is called only under rule 3.
    ///
    /// Under rule 3: no entry is `agent_identity_not_installed`, never the person's session
    /// (R4); a store failure is its own cause (`agent_store_*`). Neither is kept, so a later
    /// call reads again. Once an agent identity is kept, a call whose target is another
    /// identity is refused (`internal_error`): one process never acts as two identities.
    pub fn resolve(
        &self,
        env: &dyn HostEnv,
        source: &dyn AgentCredentialSource,
        target: impl FnOnce() -> Result<AgentTarget, Error>,
    ) -> Result<&Resolved, Error> {
        match self.cell.get() {
            Some(done @ Resolved::Agent(kept)) => {
                return if target()?.key == kept.key {
                    Ok(done)
                } else {
                    Err(Cause::Bug {
                        site: "identity: one process asked for a second agent identity",
                    }
                    .into())
                };
            }
            Some(done) => return Ok(done),
            None => {}
        }
        let resolved = match choose(env)? {
            Choice::EnvToken(c) => Resolved::EnvToken(c),
            Choice::Person => Resolved::Person,
            Choice::Agent => {
                let AgentTarget { key, name } = target()?;
                match source.resolve(&key)? {
                    Some(token) => Resolved::Agent(AgentIdentity { key, name, token }),
                    None => {
                        return Err(Cause::AgentIdentityNotInstalled {
                            env: key.env().clone(),
                        }
                        .into());
                    }
                }
            }
        };
        // A racing first resolve may have won; its answer is the process's.
        let _ = self.cell.set(resolved);
        Ok(self.cell.get().expect("set above"))
    }
}

static PROCESS: Resolver = Resolver::new();

/// Resolve this process's identity from its own environment, once (see
/// [`Resolver::resolve`]). Call it before the first `op` call.
pub fn resolve(
    source: &dyn AgentCredentialSource,
    target: impl FnOnce() -> Result<AgentTarget, Error>,
) -> Result<&'static Resolved, Error> {
    PROCESS.resolve(&ProcessEnv, source, target)
}

/// This process's resolved identity, if [`resolve`] has run and succeeded.
pub fn resolved() -> Option<&'static Resolved> {
    PROCESS.get()
}

/// The agent identity's token, for the runner to hand to `op` (slice S6); `None` unless this
/// process resolved rule 3.
pub fn agent_token() -> Option<&'static SecretValue> {
    resolved()
        .and_then(Resolved::agent)
        .map(AgentIdentity::token)
}

/// The agent identity's service-account name, for diagnosis (`Facts::agent`, so a rejected
/// token is `agent_rejected`); `None` unless this process resolved rule 3.
pub fn agent_name() -> Option<&'static str> {
    resolved()
        .and_then(Resolved::agent)
        .map(AgentIdentity::name)
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod tests;
