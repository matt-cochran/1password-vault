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
    let fallback = || fallback.map(str::to_string);
    let Some(fleet) = fleet else {
        return Ok(fallback());
    };
    // #160: an environment that names no account uses the project's recorded one, never
    // op's default account.
    if let Some(e) = env {
        return Ok(fleet.environment(e)?.account.clone().or_else(fallback));
    }
    let accounts: std::collections::BTreeSet<_> =
        fleet.environments.values().map(|e| &e.account).collect();
    if accounts.len() <= 1 {
        return Ok(accounts
            .into_iter()
            .next()
            .cloned()
            .flatten()
            .or_else(fallback));
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
        .ok_or_else(|| {
            crate::cause::Cause::Bug {
                site: "login: the menu returned a choice it did not offer",
            }
            .into()
        })
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
    run_recording(fleet, fallback, env, command, None, backend, ui)
}

/// [`run_or`] that records `record`'s account in the project's `.opv` (at or above the
/// folder it names) only once the sign-in succeeded (H2, #160): a failed sign-in leaves
/// `.opv` as it was.
pub fn run_recording(
    fleet: Option<&Fleet>,
    fallback: Option<&str>,
    env: Option<&str>,
    command: &[String],
    record: Option<(&std::path::Path, &str)>,
    backend: &mut dyn Backend,
    ui: &mut dyn Interaction,
) -> Result<i32, Error> {
    let account = sign_in_recording(fleet, fallback, env, record, backend, ui)?;
    if command.is_empty() {
        let label = account.as_deref().map(|a| backend.account_label(a));
        let scope = match (env, &label) {
            (Some(e), Some(a)) => format!(" for {e} ({a})"),
            (Some(e), None) => format!(" for {e}"),
            (None, Some(a)) => format!(" to {a}"),
            (None, None) => String::new(),
        };
        ui.show(&banner(&scope, account.as_deref()))?;
    }
    backend.child(command)
}

/// The first half of [`run_recording`] (#203): sign in for `env` and record `record`'s
/// account once that succeeded, without opening a terminal. Returns the account signed in
/// to; the session stays in `backend` ([`Backend::take_session`]).
pub fn sign_in_recording(
    fleet: Option<&Fleet>,
    fallback: Option<&str>,
    env: Option<&str>,
    record: Option<(&std::path::Path, &str)>,
    backend: &mut dyn Backend,
    ui: &mut dyn Interaction,
) -> Result<Option<String>, Error> {
    let account = login_account(fleet, fallback, env, backend, ui)?;
    signed_in_as(account.as_deref(), record, backend, ui)?;
    Ok(account)
}

/// The account this login signs in to, selected on `backend` for every later call. The
/// account chosen for this login (`opv login --account`, the menu) when the configuration
/// names none. An empty account is no account (H3): op is never asked about `--account ""`.
pub(crate) fn login_account(
    fleet: Option<&Fleet>,
    fallback: Option<&str>,
    env: Option<&str>,
    backend: &mut dyn Backend,
    ui: &mut dyn Interaction,
) -> Result<Option<String>, Error> {
    let account = account_or(fleet, fallback, env, ui)?
        .or_else(|| backend.current_account())
        .filter(|a| !a.trim().is_empty());
    backend.use_account(account.as_deref());
    Ok(account)
}

/// Sign in to `account` (op's prompt only when no session works), then record `record`'s
/// account (H2: only after the sign-in succeeded).
pub(crate) fn signed_in_as(
    account: Option<&str>,
    record: Option<(&std::path::Path, &str)>,
    backend: &mut dyn Backend,
    ui: &mut dyn Interaction,
) -> Result<(), Error> {
    prepare(account, backend, ui)?;
    if let Some((start, uuid)) = record {
        record_chosen(start, uuid, backend, ui)?;
    }
    Ok(())
}

/// The signed-in terminal's banner. With an account, it says the terminal sets
/// `OP_ACCOUNT`, which op reads as `--account` on every command, so `op signout --all`
/// there fails with a flag conflict (recorded case 04) unless `OP_ACCOUNT` is unset for it.
pub fn banner(scope: &str, account: Option<&str>) -> String {
    let base = format!(
        "Signed in{scope}. This terminal can run opv ready, run, plan and sync. Type exit to \
         leave."
    );
    match account {
        Some(a) => format!(
            "{base}\nIt sets OP_ACCOUNT={a}, which op reads as --account, so op and opv here \
             use that account. To sign out of every account, run: env -u OP_ACCOUNT op \
             signout --all"
        ),
        None => base,
    }
}

/// `opv <command>` as the person typed it (opv's own arguments, which never hold a secret),
/// for a step that runs it again inside `opv login`.
/// Empty under the MCP server (`opv mcp serve`), which has no command line to repeat.
pub fn this_command() -> Vec<String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|a| a == "mcp") {
        return Vec::new();
    }
    args
}

/// The words of `opv <command>`, each quoted for a POSIX shell when it needs it.
fn shell_words(command: &[String]) -> String {
    command
        .iter()
        .map(|w| {
            let plain = !w.is_empty()
                && w.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_./:=@,+%".contains(c));
            if plain {
                w.clone()
            } else {
                format!("'{}'", w.replace('\'', r"'\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// `opv login [--account <account>] -- opv <command>`: the command run again inside a login
/// to the selected account (#150), the step the catalog's `NotSignedIn` renders.
pub fn login_then(account: Option<&str>, command: &[String]) -> String {
    let account = account.map_or(String::new(), |a| format!(" --account {a}"));
    if command.is_empty() {
        return format!("opv login{account}");
    }
    format!("opv login{account} -- opv {}", shell_words(command))
}

/// #150: a 1Password write found no session of a person's own. In a person's terminal,
/// opv offers 1Password's sign-in prompt for this code (`op_not_signed_in`) and runs the
/// command again, as its `--dry-run` did; elsewhere the step is the same command inside
/// `opv login --account <account>`, since a sign-in inside an earlier opv command does not
/// carry over.
pub fn write_needs_session(what: &str, account: Option<&str>, command: &[String]) -> Error {
    // The catalog renders the handoff `opv login [--account <id>] -- opv <same command>`.
    let _ = (what, command);
    crate::cause::Cause::NotSignedIn {
        system: crate::cause::System::OnePassword,
        account: account.map(crate::cause::AccountId::new),
        state: crate::cause::SessionState::EndedWithEarlierCommand,
    }
    .into()
}

/// #150: what a `--dry-run` of a 1Password write says about the write itself: it needs a
/// session of the person's own, which the dry run's sign-in does not leave behind.
pub fn dry_run_session_note(account: Option<&str>, command: &[String]) -> String {
    let write: Vec<String> = command
        .iter()
        .filter(|w| *w != "--dry-run")
        .cloned()
        .collect();
    format!(
        "note: the write itself needs your own 1Password login session; a sign-in during this \
         dry run ends with it. Run it in this terminal (opv asks you to sign in), or: {}",
        login_then(account, &write)
    )
}

/// FR-40, FR-50: the 1Password account this checkout uses, chosen once, in one command.
/// `given` (`--account`: an email, account ID, user ID or sign-in address) is resolved to an
/// account ID; without it, and with no account recorded yet (`.opv`, `OP_ACCOUNT`), the person
/// picks one from a menu, shown even when one account is registered (the one op sees may not
/// be the one they mean, #79), with "Add another 1Password account" always offered. `add`
/// (`opv login --add`) adds an account right away. Where `op` keeps its own accounts (Linux,
/// and WSL with a native `op`), an account it does not know yet is added here, at op's
/// prompts, and signed in in the same step; in WSL with the Windows `op.exe` the accounts
/// live in the Windows 1Password app, so adding one is done in the app. The choice is
/// recorded in `.opv`, so later commands never fall back to op's default account. `None`:
/// nothing to choose.
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
    let host = Host::detect();
    let platform = host.platform;
    // On macOS and Windows, and in WSL with the Windows `op.exe`, accounts live in the
    // 1Password app: op's own prompt is not reachable, so adding one is done in the app.
    let own_op = !super::account::app_holds_accounts(platform, host.op_is_windows_exe());
    // #157: an `op account list` that failed is not an empty list: never start adding an
    // account because the list could not be read.
    let accounts = match manifest::discover(r) {
        manifest::Discovery::Listed(found) => found,
        manifest::Discovery::OpMissing => {
            return Err(crate::adapters::onepassword::op_missing(&host));
        }
        manifest::Discovery::Unavailable => return Err(super::account::account_list_failed()),
    };
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
            // Audit 04.15: where the app holds the accounts and op sees none, the account is
            // added in the app; signing in now could only fail.
            if !own_op {
                return Err(add_in_app(None));
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
            // With the Windows `op.exe`, the Windows app's accounts are the ones listed.
            let wsl = if platform == Platform::Wsl && own_op {
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
    // This login signs in to the chosen account whatever is recorded (#160).
    backend.use_account(Some(&uuid));
    // #153: a one-off login outside a project (no repository, no `.opv` above `start`)
    // records nothing: it never creates project configuration.
    if !records(start, record) {
        ui.show(&format!(
            "Signing in to 1Password account {} for this login only; .opv is unchanged.",
            backend.account_label(&uuid)
        ))?;
    }
    // Otherwise the account is recorded after its sign-in succeeds ([`run_recording`]).
    Ok(Some(uuid))
}

/// Whether a login from `start` records its chosen account in `.opv`: asked to (`record`,
/// not `--no-record`) and inside a project.
pub fn records(start: &std::path::Path, record: bool) -> bool {
    record && in_project(start)
}

/// Record `uuid` as the project's account in `.opv` (at or above `start`), after its
/// sign-in succeeded (H2).
pub fn record_chosen(
    start: &std::path::Path,
    uuid: &str,
    backend: &dyn Backend,
    ui: &mut dyn Interaction,
) -> Result<(), Error> {
    let recorded = crate::config_store::record_account(start, uuid)?;
    // #203: only a pointer that actually changed is worth committing, so only then does opv
    // say so.
    if recorded.changed {
        ui.show(&format!(
            "This project uses 1Password account {}; recorded in {} (commit it).",
            backend.account_label(uuid),
            recorded.path.display()
        ))?;
    }
    Ok(())
}

/// Whether `start` is inside a project: a git repository, or a folder with a `.opv` at or
/// above it.
fn in_project(start: &std::path::Path) -> bool {
    start
        .ancestors()
        // G4: test builds never look at or above the system temp folder, so a stray
        // `/tmp/.opv` never decides a test (always true outside tests).
        .take_while(|d| crate::config_store::hermetic(d))
        .any(|d| d.join(".git").exists() || d.join(".opv").symlink_metadata().is_ok())
}

/// Where op shares the 1Password app's accounts (macOS, Windows, WSL with `op.exe`), an
/// account is added in the app, not here: `account_not_registered`, whose step is the app
/// and then `opv login`.
fn add_in_app(who: Option<&str>) -> Error {
    use crate::cause::{AccountRef, AccountSource, Cause};
    Cause::AccountNotOnMachine {
        account: who.map_or(AccountRef::Unnamed, super::account::account_ref),
        selected_by: AccountSource::Flag,
        in_app: true,
    }
    .into()
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
