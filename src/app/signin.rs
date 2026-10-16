//! Per-environment sign-in for one run (FR-40).
//!
//! [`open`] wraps the run's [`CommandRunner`] for one environment:
//! - every `op` call carries the environment's `account` (`OP_ACCOUNT` in the child's
//!   environment), so two environments in different 1Password accounts work from one
//!   terminal, each with its own `OP_SESSION_<account>`. With a service-account or Connect
//!   credential set, the credential decides the account and none is added.
//! - for `status`, `plan` and `sync` on an environment with `deploy_credentials`, the
//!   provider starts its sign-in first (it may refuse before anything is read), then the
//!   item is read once and the provider signs in. From then on every call of the target
//!   CLI carries what the provider returns (a token, a private configuration directory) in
//!   its child environment only: never argv, never a file opv writes (SR-3, SR-4).
//!
//! Dropping the runner ends the provider's sign-in (SR-4: its RAM directory is removed).

use std::io;
use std::time::Duration;

use crate::adapters::onepassword;
use crate::domain::{Fleet, ItemRef};
use crate::error::Error;
use crate::host::Host;
use crate::provider::{CredentialField, DeployLogin};
use crate::runner::{Call, CommandRunner, CreateOutcome, Outcome, Output};

/// The run's runner, for one environment: its 1Password account on `op` calls and, once
/// signed in, its deploy identity on the target CLI's calls.
pub struct EnvRunner<'a> {
    inner: &'a dyn CommandRunner,
    account: Option<String>,
    login: Option<Box<dyn DeployLogin>>,
    /// The deploy credentials in effect (design §5): calls that use them are observed under
    /// this principal, not the person or a shell token.
    deploy: Option<crate::cause::Principal>,
}

impl<'a> EnvRunner<'a> {
    /// A runner whose `op` calls all use `account` and nothing else (`init` in a chosen
    /// account, before any configuration exists, FR-40).
    pub fn with_account(inner: &'a dyn CommandRunner, account: Option<String>) -> Self {
        EnvRunner {
            inner,
            account,
            login: None,
            deploy: None,
        }
    }
}

/// Whether the command reaches the deployment target (`status`, `plan`, `sync`), and so
/// signs in with the environment's `deploy_credentials`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// 1Password only (`check`, `run`, `config export`, `item skeleton`).
    Store,
    /// 1Password and the target.
    Target,
}

/// The runner for `env_name`; see the module docs. An unknown environment is returned as
/// is (the command reports it).
pub fn open<'a>(
    fleet: &Fleet,
    env_name: &str,
    r: &'a dyn CommandRunner,
    reach: Reach,
) -> Result<EnvRunner<'a>, Error> {
    open_targeted(fleet, env_name, None, r, reach)
}

/// [`open`] for target `target` of the environment (FR-56): with [`Reach::Target`], it signs
/// in with that target's `deploy_credentials`. `None`: the environment's only target, when
/// it has exactly one.
pub fn open_targeted<'a>(
    fleet: &Fleet,
    env_name: &str,
    target: Option<&str>,
    r: &'a dyn CommandRunner,
    reach: Reach,
) -> Result<EnvRunner<'a>, Error> {
    open_at(fleet, env_name, target, r, reach, &Host::detect)
}

/// [`open`] on a given host (tests).
pub fn open_on<'a>(
    fleet: &Fleet,
    env_name: &str,
    r: &'a dyn CommandRunner,
    reach: Reach,
    host: &dyn Fn() -> Host,
) -> Result<EnvRunner<'a>, Error> {
    open_at(fleet, env_name, None, r, reach, host)
}

fn open_at<'a>(
    fleet: &Fleet,
    env_name: &str,
    target: Option<&str>,
    r: &'a dyn CommandRunner,
    reach: Reach,
    host: &dyn Fn() -> Host,
) -> Result<EnvRunner<'a>, Error> {
    let Some(env) = fleet.environments.get(env_name) else {
        return Ok(EnvRunner::new(r, None));
    };
    // A service-account or Connect credential belongs to one account: it decides.
    let account = env
        .account
        .clone()
        .filter(|_| host().op_credential.is_none());
    let mut runner = EnvRunner::new(r, account);
    if reach == Reach::Target {
        runner.deploy_sign_in(fleet, env_name, target)?;
    }
    Ok(runner)
}

/// A deploy sign-in error (FR-40) with its stable code: a credential the target rejected is
/// `deploy_credentials_failed` (exit 7); a missing CLI or field, a refused private
/// directory or an unknown outcome keeps its own code and exit.
///
/// A cataloged rejection of the deploy credentials (diagnosed under their principal, X22)
/// names the item by its full reference: the runner's principal does not carry the vault,
/// this sign-in does (06.30).
fn deploy_failed(e: Error, reference: &ItemRef) -> Error {
    use crate::cause::{Cause, CredentialRef, VaultId};
    let Error::Catalog(cause, upstream) = e;
    let mut cause = *cause;
    if let Cause::CredentialRejected {
        credential: CredentialRef::DeployCredentials { vault, .. },
        ..
    } = &mut cause
        && vault.as_str().is_empty()
    {
        *vault = VaultId::new(reference.vault.clone());
    }
    Error::Catalog(Box::new(cause), upstream)
}

impl<'a> EnvRunner<'a> {
    /// `inner` with `account` on every `op` call; no deploy identity yet.
    pub fn new(inner: &'a dyn CommandRunner, account: Option<String>) -> Self {
        Self {
            inner,
            account,
            login: None,
            deploy: None,
        }
    }

    /// This runner with `login` already signed in (tests and callers that sign in
    /// themselves).
    pub fn with_login(mut self, login: Box<dyn DeployLogin>) -> Self {
        self.login = Some(login);
        self
    }

    /// Read `reference` once (its `fields` only) and sign `login` in with the values; the
    /// values live only in `login` from then on. A failure drops `login`, which removes
    /// anything it kept.
    pub fn signed_in(
        mut self,
        login: Box<dyn DeployLogin>,
        reference: &ItemRef,
        fields: &[CredentialField],
    ) -> Result<Self, Error> {
        self.sign_in_with(login, reference, fields, None)?;
        Ok(self)
    }

    /// `principal`: the deploy credentials of a named target, under which the provider's
    /// sign-in calls are observed, so a rejection addresses that credential and never the
    /// person's own vendor login (X22, 06.01).
    fn sign_in_with(
        &mut self,
        mut login: Box<dyn DeployLogin>,
        reference: &ItemRef,
        fields: &[CredentialField],
        principal: Option<crate::cause::Principal>,
    ) -> Result<(), Error> {
        // The item belongs to this deploy identity (env and target), named by its refusal.
        let values =
            onepassword::read_deploy_credentials(&*self, reference, fields, principal.as_ref())
                .map_err(|e| deploy_failed(e, reference))?;
        let signed = match principal {
            Some(p) => crate::runner::under_deploy(p, || login.sign_in(values, &*self)),
            None => login.sign_in(values, &*self),
        };
        signed.map_err(|e| deploy_failed(e, reference))?;
        self.login = Some(login);
        Ok(())
    }

    /// Sign in with the `deploy_credentials` of target `target` of `env_name` (FR-40,
    /// FR-56), when it has them. `None`: the environment's only target, when it has exactly
    /// one. An unknown target signs nothing in: the command reports it.
    fn deploy_sign_in(
        &mut self,
        fleet: &Fleet,
        env_name: &str,
        target: Option<&str>,
    ) -> Result<(), Error> {
        let Some(env) = fleet.environments.get(env_name) else {
            return Ok(());
        };
        let t = match target {
            Some(name) => env.targets.get_key_value(name),
            None if env.targets.len() == 1 => env.targets.iter().next(),
            None => None,
        };
        let Some((target_name, t, reference)) =
            t.and_then(|(n, t)| Some((n, t, t.deploy_credentials.as_ref()?)))
        else {
            return Ok(());
        };
        // A Key Vault behind a Kubernetes runtime signs `az` in (FR-39, FR-40).
        let provider = crate::provider::deploy_provider(t.config.as_ref());
        // The configuration accepts deploy_credentials only on a provider that has fields
        // for them (config.rs), so a refusal here is an opv bug, not the person's file.
        let fields = provider.deploy_credential_fields().map_err(|_| {
            Error::from(crate::cause::Cause::Bug {
                site: "deploy_credentials accepted for a provider without them",
            })
        })?;
        let login = provider.deploy_login()?;
        let principal = crate::cause::Principal::DeployCredentials {
            vault: crate::cause::VaultId::new(reference.vault.clone()),
            item: crate::cause::ItemId::new(reference.item.clone()),
            env: crate::cause::EnvName::new(env_name),
            target: crate::cause::TargetName::new(target_name.clone()),
        };
        self.sign_in_with(login, reference, fields, Some(principal.clone()))?;
        self.deploy = Some(principal);
        Ok(())
    }

    /// Run `f` under the deploy principal when `program` uses the deploy credentials.
    fn as_principal<T>(&self, program: &str, f: impl FnOnce() -> T) -> T {
        match (&self.deploy, &self.login) {
            (Some(p), Some(login)) if !login.env(program).is_empty() => {
                crate::runner::under_deploy(p.clone(), f)
            }
            _ => f(),
        }
    }

    /// The extra child environment for `program`.
    fn extra(&self, program: &str) -> Vec<(&str, &str)> {
        let mut env = Vec::new();
        if program == "op"
            && let Some(a) = &self.account
        {
            env.push(("OP_ACCOUNT", a.as_str()));
        }
        if let Some(login) = &self.login {
            env.extend(login.env(program));
        }
        env
    }

    /// `env` plus the extra environment for `program` (later entries win).
    fn merged<'e>(&'e self, program: &str, env: &[(&'e str, &'e str)]) -> Vec<(&'e str, &'e str)> {
        let mut all = env.to_vec();
        all.extend(self.extra(program));
        all
    }
}

impl CommandRunner for EnvRunner<'_> {
    fn read(&self, call: &Call, refused: &[i32]) -> io::Result<Outcome> {
        let env = self.merged(call.program, call.env);
        self.as_principal(call.program, || {
            self.inner.read(&Call { env: &env, ..*call }, refused)
        })
    }

    fn write(&self, call: &Call) -> io::Result<Outcome> {
        let env = self.merged(call.program, call.env);
        self.as_principal(call.program, || {
            self.inner.write(&Call { env: &env, ..*call })
        })
    }

    fn create(&self, call: &Call, kind: crate::cause::CreateKind) -> io::Result<CreateOutcome> {
        let env = self.merged(call.program, call.env);
        self.as_principal(call.program, || {
            self.inner.create(&Call { env: &env, ..*call }, kind)
        })
    }

    fn probe(&self, call: &Call, limit: Duration) -> io::Result<Output> {
        let env = self.merged(call.program, call.env);
        self.as_principal(call.program, || {
            self.inner.probe(&Call { env: &env, ..*call }, limit)
        })
    }

    fn pause(&self, d: Duration, note: &str) {
        self.inner.pause(d, note)
    }

    fn note(&self, line: &str) {
        self.inner.note(line)
    }

    fn run_inherited(&self, program: &str, args: &[&str], env: &[(&str, &str)]) -> io::Result<i32> {
        let env = self.merged(program, env);
        self.as_principal(program, || self.inner.run_inherited(program, args, &env))
    }

    fn remaining(&self) -> Option<Duration> {
        self.inner.remaining()
    }

    fn spawns_processes(&self) -> bool {
        self.inner.spawns_processes()
    }

    /// A target write through this runner is the inner runner's (L2: a spent budget after
    /// one never says "before any write").
    fn writes_started(&self) -> bool {
        self.inner.writes_started()
    }

    fn step_summary(&self, markdown: &str) {
        self.inner.step_summary(markdown)
    }

    fn deploy_signed_in(&self) -> bool {
        self.login.is_some() || self.inner.deploy_signed_in()
    }

    fn local_run_supported(&self) -> io::Result<()> {
        self.inner.local_run_supported()
    }

    fn run_inherited_clean(
        &self,
        program: &str,
        args: &[&str],
        env: &[(&str, &str)],
        remove: &[String],
    ) -> io::Result<i32> {
        let env = self.merged(program, env);
        self.inner.run_inherited_clean(program, args, &env, remove)
    }
}

#[cfg(test)]
#[path = "signin_tests.rs"]
mod tests;
