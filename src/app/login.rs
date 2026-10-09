//! `opv login [<env>] [-- <command>]` (FR-40): sign in to the 1Password account an
//! environment uses, then open a signed-in terminal or run one command.
//!
//! A thin proxy for `op signin`: the password goes only to op's own prompt; the session
//! stays in this process and its child (no token printed, nothing to `eval`); the child's
//! exit code is returned. Like `setup`, an owner command: it needs an interactive terminal
//! and may ask which environment to sign in for.

use super::setup::{Backend, Interaction, prepare};
use crate::domain::Fleet;
use crate::error::Error;

/// The account to sign in to: the environment's (`env` given), else the one account every
/// environment uses (or op's default when none sets one, or there is no configuration).
/// When environments use different accounts, the owner picks an environment.
pub fn account(
    fleet: Option<&Fleet>,
    env: Option<&str>,
    ui: &mut dyn Interaction,
) -> Result<Option<String>, Error> {
    let Some(fleet) = fleet else {
        return match env {
            Some(e) => Err(Error::Config(format!(
                "no secrets.toml found, so environment {e:?} is unknown. Run opv login without \
                 an environment to use your default 1Password account, or pass --config <path>."
            ))),
            None => Ok(None),
        };
    };
    if let Some(e) = env {
        return Ok(fleet.environment(e)?.account.clone());
    }
    let accounts: std::collections::BTreeSet<_> =
        fleet.environments.values().map(|e| &e.account).collect();
    if accounts.len() <= 1 {
        return Ok(accounts.into_iter().next().cloned().flatten());
    }
    let label = |name: &str, account: &Option<String>| {
        format!(
            "{name} ({})",
            account.as_deref().unwrap_or("default 1Password account")
        )
    };
    let choices: Vec<String> = fleet
        .environments
        .iter()
        .map(|(n, e)| label(n, &e.account))
        .collect();
    let picked = ui.choose(
        "These environments use different 1Password accounts. Which environment do you want \
         to sign in for?",
        &choices,
    )?;
    fleet
        .environments
        .iter()
        .find(|(n, e)| label(n, &e.account) == picked)
        .map(|(_, e)| e.account.clone())
        .ok_or_else(|| Error::Config("unknown choice".into()))
}

/// Sign in for `env` and open a terminal (empty `command`) or run `command`; returns its
/// exit code. `fleet` is `None` when no configuration was found.
pub fn run(
    fleet: Option<&Fleet>,
    env: Option<&str>,
    command: &[String],
    backend: &mut dyn Backend,
    ui: &mut dyn Interaction,
) -> Result<i32, Error> {
    let account = account(fleet, env, ui)?;
    backend.use_account(account.as_deref());
    prepare(account.as_deref(), backend, ui)?;
    if command.is_empty() {
        let scope = match (env, &account) {
            (Some(e), Some(a)) => format!(" for {e} ({a})"),
            (Some(e), None) => format!(" for {e}"),
            (None, Some(a)) => format!(" to {a}"),
            (None, None) => String::new(),
        };
        ui.show(&format!(
            "Signed in{scope}. This terminal can run opv check, run, plan and sync. Type exit \
             to leave."
        ))?;
    }
    backend.child(command)
}

#[cfg(test)]
#[path = "login_tests.rs"]
mod tests;
