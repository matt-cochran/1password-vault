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
    account_or(fleet, None, env, ui)
}

/// [`account`], with the account to use when there is no configuration to read yet: a
/// project whose configuration lives in 1Password (FR-44) cannot be read before signing
/// in, so its `.opv` pointer's account (or op's default) is used for any environment.
pub fn account_or(
    fleet: Option<&Fleet>,
    fallback: Option<&str>,
    env: Option<&str>,
    ui: &mut dyn Interaction,
) -> Result<Option<String>, Error> {
    let Some(fleet) = fleet else {
        return Ok(fallback.map(str::to_string));
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
    run_or(fleet, None, env, command, backend, ui)
}

/// [`run`] with [`account_or`]'s fallback account.
pub fn run_or(
    fleet: Option<&Fleet>,
    fallback: Option<&str>,
    env: Option<&str>,
    command: &[String],
    backend: &mut dyn Backend,
    ui: &mut dyn Interaction,
) -> Result<i32, Error> {
    let account = account_or(fleet, fallback, env, ui)?;
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

/// FR-40: the 1Password account this checkout uses, chosen once, in one command. `given`
/// (`--account`: an email, account ID, user ID or sign-in address) is resolved to an
/// account ID; without it, and with no account recorded yet (`.opv`, `OP_ACCOUNT`), a
/// person with several accounts picks one from a list. Where `op` keeps its own accounts
/// (Linux, WSL), an account it does not know yet is added right here, at op's prompts,
/// and signed in in the same step (found in a fresh-account run-through: leaving opv for
/// `op account add` was the worst step). The choice is recorded in `.opv`, so later
/// commands never fall back to op's default account. `None`: nothing to choose.
pub fn choose_account(
    r: &dyn crate::runner::CommandRunner,
    given: Option<&str>,
    start: &std::path::Path,
    backend: &mut dyn Backend,
    ui: &mut dyn Interaction,
) -> Result<Option<String>, Error> {
    use crate::adapters::onepassword_manifest as manifest;
    use crate::host::{Host, Platform};
    let own_op = matches!(Host::detect().platform, Platform::Linux | Platform::Wsl);
    let accounts = manifest::accounts(r);
    const ADD: &str = "Add another 1Password account";
    let uuid = match given {
        Some(who) => match manifest::resolve(&accounts, who) {
            Ok(u) => u,
            Err(_) if own_op && who.contains('@') && crate::config::is_account(who) => {
                let now = add_account(r, backend, ui, Some(who))?;
                manifest::resolve(&now, who)?
            }
            Err(e) => return Err(e),
        },
        None if crate::config_store::pointer_account(start).is_some()
            || crate::config_store::account_env().is_some()
            || accounts.len() == 1 =>
        {
            return Ok(None);
        }
        None if accounts.is_empty() => {
            if !own_op {
                return Ok(None);
            }
            let now = add_account(r, backend, ui, None)?;
            match now.as_slice() {
                [one] => one.account_uuid.clone(),
                _ => return Ok(None),
            }
        }
        None => {
            let mut labels: Vec<String> = accounts
                .iter()
                .map(|a| {
                    format!(
                        "{} ({})",
                        if a.email.is_empty() {
                            &a.account_uuid
                        } else {
                            &a.email
                        },
                        a.url.trim_start_matches("https://").trim_end_matches('/')
                    )
                })
                .collect();
            if own_op {
                labels.push(ADD.to_string());
            }
            let picked = ui.choose(
                "Several 1Password accounts are on this machine. Which one holds this \
                 project's secrets?",
                &labels,
            )?;
            if picked == ADD {
                let now = add_account(r, backend, ui, None)?;
                // The new one: in the list now, not before.
                match now
                    .iter()
                    .find(|a| !accounts.iter().any(|b| b.account_uuid == a.account_uuid))
                {
                    Some(a) => a.account_uuid.clone(),
                    None => return Ok(None),
                }
            } else {
                let at = labels.iter().position(|l| *l == picked).unwrap_or(0);
                accounts[at].account_uuid.clone()
            }
        }
    };
    let path = crate::config_store::record_account(start, &uuid)?;
    ui.show(&format!(
        "This project uses 1Password account {uuid}; recorded in {} (commit it).",
        path.display()
    ))?;
    Ok(Some(uuid))
}

/// Add an account at op's prompts (signed in in the same step); the accounts op knows after.
fn add_account(
    r: &dyn crate::runner::CommandRunner,
    backend: &mut dyn Backend,
    ui: &mut dyn Interaction,
    email: Option<&str>,
) -> Result<Vec<crate::adapters::onepassword_manifest::Account>, Error> {
    ui.show(&format!(
        "Adding {} to 1Password on this machine. Type the sign-in address, Secret Key and \
         password only at 1Password's prompts (your Emergency Kit has them).",
        email.unwrap_or("your account")
    ))?;
    backend.add_account(email)?;
    Ok(crate::adapters::onepassword_manifest::accounts(r))
}

#[cfg(test)]
#[path = "login_tests.rs"]
mod tests;
