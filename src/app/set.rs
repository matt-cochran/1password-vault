//! `opv set <[product/]KEY> --env <env>` (design Part V, row `set-cmd`, 0.12.0): a person,
//! in a terminal, enters one value masked; opv writes it into the key's 1Password boundary
//! item through the importer's field writer (stdin only, never argv) and prints the key's
//! new value state.
//!
//! Only a person may run it. An assistant (MCP or an agent-mode shell) and a non-TTY
//! process are refused before the prompt, with a typed cause; neither path reads stdin. No
//! secret value, its length or any part of one ever reaches output, argv, a log, an error
//! or `Debug`.

use std::io::Write;

use super::write_err;
use crate::cause::{Cause, Cmd, EnvName, KeyName, NameKind, NoTerminal, ProductName};
use crate::domain::value_state::{ValueState, classify};
use crate::domain::{Fleet, SecretValue, key_label, rules};
use crate::error::Error;
use crate::host::{HostEnv, refuse_if_agent};
use crate::runner::CommandRunner;

/// The exact command a person is handed when an assistant calls `set`, and the command named
/// by a read-back failure as the one to run again.
fn command(key: &str, env_name: &str) -> Cmd {
    Cmd {
        command: vec!["set".into()],
        args: vec![key.into(), "--env".into(), env_name.into()],
    }
}

/// `opv set`: masked entry of one value. `prompt` is the masked terminal entry (the CLI
/// passes [`crate::app::masked::prompt`]); `Ok(None)` (Ctrl-C) or an empty entry writes
/// nothing.
#[allow(clippy::too_many_arguments)]
pub fn set(
    fleet: &Fleet,
    env: &dyn HostEnv,
    key: &str,
    env_name: &str,
    prompt: &mut dyn FnMut(&str) -> Result<Option<SecretValue>, Error>,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    // An assistant is refused before anything, with the exact command for the person; then
    // a process without a terminal. Neither path calls the prompt (R60).
    refuse_if_agent(env, command(key, env_name))?;
    if !env.interactive() {
        return Err(Cause::NeedsTerminal {
            why: NoTerminal::NoTty,
        }
        .into());
    }
    let environment = fleet.environment(env_name)?;
    let (product, name) = resolve(fleet, key, env_name)?;
    let spec = &fleet.products[&product].keys[&name];
    let Some(entered) = prompt(&key_label(&product, &name))? else {
        return Ok(());
    };
    if entered.expose().trim().is_empty() {
        return Ok(());
    }
    // The state of the value just entered, computed in memory: names only, never the value.
    // A person runs this command, so every declared rule counts (design row `rule-gate`).
    let state = classify(
        Ok(Some(&entered)),
        crate::domain::presence::present_in(spec, env_name),
        true,
        |v| {
            rules::check(&product, &name, spec, env_name, environment, v)
                .map(|_| ())
                .map_err(|f| f.rule)
        },
    );
    super::import::write_values(
        fleet,
        environment,
        &[(product, name, entered)],
        &command(key, env_name),
        r,
    )?;
    writeln!(out, "{}", state_text(&state)).map_err(write_err)?;
    Ok(())
}

/// The declared `(product, key)` that `[product/]KEY` names and `env_name` wants, or the
/// catalog's undeclared/ambiguous cause. A bare `KEY` resolves to the one product that
/// declares it (R22); a key declared but `except`ed here is [`Cause::KeyNotDeclared`].
fn resolve(fleet: &Fleet, key: &str, env_name: &str) -> Result<(String, String), Error> {
    if let Some((product, name)) = key.split_once('/') {
        if let Some(spec) = fleet.products.get(product).and_then(|p| p.keys.get(name)) {
            not_wanted(spec, name, product, env_name)?;
            return Ok((product.to_string(), name.to_string()));
        }
    } else {
        let owners: Vec<String> = fleet
            .products
            .iter()
            .filter(|(_, p)| p.keys.contains_key(key))
            .map(|(p, _)| p.clone())
            .collect();
        match owners.as_slice() {
            [only] => {
                let spec = &fleet.products[only].keys[key];
                not_wanted(spec, key, only, env_name)?;
                return Ok((only.clone(), key.to_string()));
            }
            [] => {}
            // Declared by several products: a person names one in full (R22), never the first.
            many => {
                return Err(Cause::Ambiguous {
                    kind: NameKind::Key,
                    given: key.to_string(),
                    candidates: many.iter().map(|p| key_label(p, key)).collect(),
                }
                .into());
            }
        }
    }
    let labels: Vec<String> = fleet
        .products
        .iter()
        .flat_map(|(p, prod)| {
            prod.keys
                .iter()
                .filter(|(_, s)| s.is_desired_in(env_name))
                .map(move |(k, _)| key_label(p, k))
        })
        .collect();
    Err(super::not_declared(
        NameKind::Key,
        key,
        labels.iter().map(String::as_str),
    ))
}

/// Refuse a declared key that is not wanted in `env_name` (`except`, or an explicit list
/// that leaves it out).
fn not_wanted(
    spec: &crate::domain::KeySpec,
    key: &str,
    product: &str,
    env_name: &str,
) -> Result<(), Error> {
    if spec.is_desired_in(env_name) {
        return Ok(());
    }
    Err(Cause::KeyNotDeclared {
        key: KeyName::new(key),
        env: EnvName::new(env_name),
        product: Some(ProductName::new(product)),
    }
    .into())
}

/// The state's name as it is printed: a word, a rule name or a reason, never a value.
fn state_text(state: &ValueState) -> String {
    match state {
        ValueState::Set => "set".to_string(),
        ValueState::Placeholder => "placeholder".to_string(),
        ValueState::Malformed { rule } => format!("malformed{{{rule}}}"),
        ValueState::Empty => "empty".to_string(),
        ValueState::Absent => "absent".to_string(),
        ValueState::Unreadable { cause } => format!("unreadable{{{}}}", unreadable_text(cause)),
        ValueState::NotWanted { reason } => format!("not_wanted{{{reason}}}"),
        ValueState::Supplied => "supplied".to_string(),
    }
}

/// The cause of an unreadable value, as its state name (never a value).
fn unreadable_text(cause: &crate::domain::value_state::UnreadableCause) -> &'static str {
    use crate::domain::value_state::UnreadableCause::{
        ItemMissing, NoAccess, NotSignedIn, OpFailed,
    };
    match cause {
        NotSignedIn => "not_signed_in",
        NoAccess => "no_access",
        ItemMissing => "item_missing",
        OpFailed => "op_failed",
    }
}

#[cfg(test)]
#[path = "set_tests.rs"]
mod tests;
