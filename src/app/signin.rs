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
use crate::runner::{Call, CommandRunner, Outcome, Output};

/// The run's runner, for one environment: its 1Password account on `op` calls and, once
/// signed in, its deploy identity on the target CLI's calls.
pub struct EnvRunner<'a> {
    inner: &'a dyn CommandRunner,
    account: Option<String>,
    login: Option<Box<dyn DeployLogin>>,
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
    open_on(fleet, env_name, r, reach, &Host::detect)
}

/// [`open`] on a given host (tests).
pub fn open_on<'a>(
    fleet: &Fleet,
    env_name: &str,
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
        runner.deploy_sign_in(fleet, env_name)?;
    }
    Ok(runner)
}

/// `doctor --env` (owner ruling): like [`open`] for a command that reaches the target, but
/// a deploy sign-in that fails does not stop the run. The runner comes back without a
/// deploy identity, beside the error, so doctor reports it as one check and skips only
/// the target checks that need those credentials.
pub fn open_for_doctor<'a>(
    fleet: &Fleet,
    env_name: &str,
    r: &'a dyn CommandRunner,
) -> (EnvRunner<'a>, Option<Error>) {
    open_for_doctor_on(fleet, env_name, r, &Host::detect)
}

/// [`open_for_doctor`] on a given host (tests).
pub fn open_for_doctor_on<'a>(
    fleet: &Fleet,
    env_name: &str,
    r: &'a dyn CommandRunner,
    host: &dyn Fn() -> Host,
) -> (EnvRunner<'a>, Option<Error>) {
    let mut runner = match open_on(fleet, env_name, r, Reach::Store, host) {
        Ok(runner) => runner,
        Err(e) => return (EnvRunner::new(r, None), Some(e)),
    };
    let failed = runner
        .deploy_sign_in(fleet, env_name)
        .err()
        .map(with_excerpt);
    (runner, failed)
}

/// A deploy sign-in error (FR-40) with its stable code: a credential the target rejected is
/// `deploy_credentials_failed` (exit 7); a missing CLI or field, a refused private
/// directory or an unknown outcome keeps its own code and exit.
fn deploy_failed(e: Error) -> Error {
    match e {
        e @ Error::Auth(_) => e.with_code(crate::error::Code::DeployCredentialsFailed),
        e => e,
    }
}

/// `e` with the failed call's scrubbed stderr excerpt (`  az said: …`, NR-31) after its
/// first line, as doctor runs more calls before it prints and the excerpt would otherwise
/// be dropped. The order is the one `error::report` prints: error line, excerpt, the rest
/// of the text; the next step stays the error's own.
fn with_excerpt(e: Error) -> Error {
    let Some(x) = crate::runner::take_failure_excerpt().filter(|_| e.from_external_call()) else {
        return e;
    };
    // A sign-in or dependency error's step is its first indented line (`default_next`):
    // pin it before the excerpt becomes that line.
    let e = match e {
        Error::Auth(_) | Error::Dependency(_) if e.next_step().is_none() => {
            let step = e.default_next("opv doctor");
            e.with_next(step)
        }
        e => e,
    };
    let excerpt = x.render();
    let excerpt = excerpt.trim_end();
    e.map_text(|t| match t.split_once('\n') {
        Some((head, rest)) => format!("{head}\n{excerpt}\n{rest}"),
        None => format!("{t}\n{excerpt}"),
    })
}

impl<'a> EnvRunner<'a> {
    /// `inner` with `account` on every `op` call; no deploy identity yet.
    pub fn new(inner: &'a dyn CommandRunner, account: Option<String>) -> Self {
        Self {
            inner,
            account,
            login: None,
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

    fn sign_in_with(
        &mut self,
        mut login: Box<dyn DeployLogin>,
        reference: &ItemRef,
        fields: &[CredentialField],
        env_name: Option<&str>,
    ) -> Result<(), Error> {
        let values = onepassword::read_deploy_credentials(&*self, reference, fields, env_name)
            .map_err(deploy_failed)?;
        login.sign_in(values, &*self).map_err(deploy_failed)?;
        self.login = Some(login);
        Ok(())
    }

    /// Sign in with `env_name`'s `deploy_credentials`, when it has them and a target.
    fn deploy_sign_in(&mut self, fleet: &Fleet, env_name: &str) -> Result<(), Error> {
        let Some(env) = fleet.environments.get(env_name) else {
            return Ok(());
        };
        let (Some(t), Some(reference)) = (env.target(), &env.deploy_credentials) else {
            return Ok(());
        };
        // A Key Vault behind a Kubernetes runtime signs `az` in (FR-39, FR-40).
        let provider = crate::provider::deploy_provider(t);
        let fields = provider
            .deploy_credential_fields()
            .map_err(|why| Error::Config(format!("environment {env_name}: {why}").into()))?;
        let login = provider.deploy_login()?;
        self.sign_in_with(login, reference, fields, Some(env_name))
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
        self.inner.read(&Call { env: &env, ..*call }, refused)
    }

    fn write(&self, call: &Call) -> io::Result<Outcome> {
        let env = self.merged(call.program, call.env);
        self.inner.write(&Call { env: &env, ..*call })
    }

    fn probe(&self, call: &Call, limit: Duration) -> io::Result<Output> {
        let env = self.merged(call.program, call.env);
        self.inner.probe(&Call { env: &env, ..*call }, limit)
    }

    fn pause(&self, d: Duration, note: &str) {
        self.inner.pause(d, note)
    }

    fn note(&self, line: &str) {
        self.inner.note(line)
    }

    fn run_inherited(&self, program: &str, args: &[&str], env: &[(&str, &str)]) -> io::Result<i32> {
        let env = self.merged(program, env);
        self.inner.run_inherited(program, args, &env)
    }

    fn remaining(&self) -> Option<Duration> {
        self.inner.remaining()
    }

    fn spawns_processes(&self) -> bool {
        self.inner.spawns_processes()
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
