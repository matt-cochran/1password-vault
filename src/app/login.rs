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
        let account = account.as_deref().map(|a| backend.account_label(a));
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

/// FR-40, FR-50: the 1Password account this checkout uses, chosen once, in one command.
/// `given` (`--account`: an email, account ID, user ID or sign-in address) is resolved to an
/// account ID; without it, and with no account recorded yet (`.opv`, `OP_ACCOUNT`), the person
/// picks one from a menu, shown even when one account is registered (the one op sees may not
/// be the one they mean, #79), with "Add another 1Password account" always offered. `add`
/// (`opv login --add`) adds an account right away. Where `op` keeps its own accounts (Linux,
/// WSL), an account it does not know yet is added here, at op's prompts, and signed in in the
/// same step. The choice is recorded in `.opv`, so later commands never fall back to op's
/// default account. `None`: nothing to choose.
pub fn choose_account(
    r: &dyn crate::runner::CommandRunner,
    given: Option<&str>,
    add: bool,
    start: &std::path::Path,
    backend: &mut dyn Backend,
    ui: &mut dyn Interaction,
) -> Result<Option<String>, Error> {
    choose_account_with(r, given, add, start, backend, ui, true)
}

/// [`choose_account`]; `record` false (`opv login --no-record`, #153) signs in to the
/// account for this login only and leaves `.opv` as it is, for a one-off look into another
/// account (on a shared sign-in address, the only way to reach the second account through
/// opv's session handling).
pub fn choose_account_with(
    r: &dyn crate::runner::CommandRunner,
    given: Option<&str>,
    add: bool,
    start: &std::path::Path,
    backend: &mut dyn Backend,
    ui: &mut dyn Interaction,
    record: bool,
) -> Result<Option<String>, Error> {
    use crate::adapters::onepassword_manifest as manifest;
    use crate::host::{Host, Platform};
    let platform = Host::detect().platform;
    let own_op = matches!(platform, Platform::Linux | Platform::Wsl);
    let accounts = manifest::accounts(r);
    const ADD: &str = "Add another 1Password account";
    let added = |now: &[manifest::Account]| {
        now.iter()
            .find(|a| !accounts.iter().any(|b| b.account_uuid == a.account_uuid))
            .map(|a| a.account_uuid.clone())
    };
    let uuid = match given {
        _ if add && !own_op => return Err(add_in_app(given)),
        _ if add => {
            let now = add_account(r, backend, ui, given, &accounts)?;
            match given {
                Some(who) => manifest::resolve(&now, who)?,
                None => match added(&now) {
                    Some(u) => u,
                    None => return Ok(None),
                },
            }
        }
        Some(who) => match manifest::resolve(&accounts, who) {
            Ok(u) => u,
            Err(_) if own_op && who.contains('@') && crate::config::is_account(who) => {
                let now = add_account(r, backend, ui, Some(who), &accounts)?;
                manifest::resolve(&now, who)?
            }
            Err(e) => return Err(e),
        },
        None if crate::config_store::pointer_account(start).is_some()
            || crate::config_store::account_env().is_some() =>
        {
            return Ok(None);
        }
        None if accounts.is_empty() => {
            if !own_op {
                return Ok(None);
            }
            let now = add_account(r, backend, ui, None, &accounts)?;
            match now.as_slice() {
                [one] => one.account_uuid.clone(),
                _ => return Ok(None),
            }
        }
        None => {
            let mut labels: Vec<String> = accounts
                .iter()
                .map(|a| {
                    let who = if a.email.is_empty() {
                        &a.account_uuid
                    } else {
                        &a.email
                    };
                    let address = a.url.trim_start_matches("https://").trim_end_matches('/');
                    match manifest::signed_in(r, &a.account_uuid) {
                        Some(true) => format!("{who} ({address}) · signed in"),
                        _ => format!("{who} ({address})"),
                    }
                })
                .collect();
            labels.push(ADD.to_string());
            let wsl = if platform == Platform::Wsl {
                " Accounts in the Windows 1Password app are not listed here until you add them."
            } else {
                ""
            };
            let picked = ui.choose(
                &format!("Which 1Password account holds this project's secrets?{wsl}"),
                &labels,
            )?;
            if picked == ADD {
                if !own_op {
                    return Err(add_in_app(None));
                }
                let now = add_account(r, backend, ui, None, &accounts)?;
                match added(&now) {
                    Some(u) => u,
                    None => return Ok(None),
                }
            } else {
                let at = labels.iter().position(|l| *l == picked).unwrap_or(0);
                accounts[at].account_uuid.clone()
            }
        }
    };
    if !record {
        ui.show(&format!(
            "Signing in to 1Password account {} for this login only; .opv is unchanged.",
            backend.account_label(&uuid)
        ))?;
        return Ok(Some(uuid));
    }
    let path = crate::config_store::record_account(start, &uuid)?;
    ui.show(&format!(
        "This project uses 1Password account {}; recorded in {} (commit it).",
        backend.account_label(&uuid),
        path.display()
    ))?;
    Ok(Some(uuid))
}

/// Where op shares the 1Password app's accounts (macOS, Windows), an account is added in the
/// app, not here.
fn add_in_app(who: Option<&str>) -> Error {
    Error::Config(
        format!(
            "on this system the 1Password CLI uses the 1Password app's accounts, so {} is added \
             in the app",
            who.unwrap_or("another account")
        )
        .into(),
    )
    .with_code(crate::error::Code::AccountNotRegistered)
    .with_do(
        "add the account in the 1Password app and turn on Settings > Developer > Integrate \
         with 1Password CLI",
    )
    .with_next(match who {
        Some(w) => format!("opv login --account {w}"),
        None => "opv login".to_string(),
    })
}

/// Add an account at op's prompts (signed in in the same step); the accounts op knows after.
fn add_account(
    r: &dyn crate::runner::CommandRunner,
    backend: &mut dyn Backend,
    ui: &mut dyn Interaction,
    email: Option<&str>,
    known: &[crate::adapters::onepassword_manifest::Account],
) -> Result<Vec<crate::adapters::onepassword_manifest::Account>, Error> {
    ui.show(&format!(
        "Adding {} to 1Password on this machine. Type the sign-in address, Secret Key and \
         password only at 1Password's prompts (your Emergency Kit has them).",
        email.unwrap_or("your account")
    ))?;
    backend.add_account(email, &free_shorthand(email, known))?;
    Ok(crate::adapters::onepassword_manifest::accounts(r))
}

/// A shorthand for a new account that no account on this machine has: the email's domain
/// (`me@labs.example` → `labs`), else `account`, with `-2`, `-3`… until it is free.
fn free_shorthand(
    email: Option<&str>,
    taken: &[crate::adapters::onepassword_manifest::Account],
) -> String {
    let base: String = email
        .and_then(|e| e.rsplit_once('@'))
        .and_then(|(_, domain)| domain.split('.').next())
        .unwrap_or("")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    let base = if base.is_empty() {
        "account".to_string()
    } else {
        base
    };
    let used = |s: &str| taken.iter().any(|a| a.shorthand.eq_ignore_ascii_case(s));
    std::iter::once(base.clone())
        .chain((2..).map(|n| format!("{base}-{n}")))
        .find(|s| !used(s))
        .expect("an unused shorthand")
}

#[cfg(test)]
#[path = "login_tests.rs"]
mod tests;
