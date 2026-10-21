//! `opv set <[product/]KEY> --env <env>` (design Part V, row `set-cmd`, 0.12.0): a person,
//! in a terminal, enters one value masked; opv writes it into the key's 1Password boundary
//! item through the importer's field writer (stdin only, never argv) and prints the key's
//! new value state.
//!
//! Only a person may run it. An assistant (MCP or an agent-mode shell) and a non-TTY
//! process are refused before the prompt, with a typed cause; neither path reads stdin. No
//! secret value, its length or any part of one ever reaches output, argv, a log, an error
//! or `Debug`.

use std::io::{Read, Write};

use super::write_err;
use crate::cause::{
    Cause, Cmd, EnvName, FieldRule, InputKind, KeyName, NameKind, NoTerminal, ProductName,
    SecretFileRule, UsageProblem,
};
use crate::domain::value_state::{ValueState, classify};
use crate::domain::{Fleet, SecretValue, key_label, rules};
use crate::error::Error;
use crate::host::{HostEnv, refuse_if_agent};
use crate::runner::CommandRunner;

/// The largest value `opv set --from-file` reads from a file: 64 KiB. A larger file is
/// refused by its size, never by its content.
const FROM_FILE_MAX_BYTES: u64 = 65_536;

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
    // An infrastructure key has no 1Password value to set (#206 §4.4): said first, from the
    // configuration alone, so nobody is handed a command that cannot succeed.
    if let Ok((product, name)) = resolve(fleet, key, env_name) {
        super::import::refuse_not_stored(fleet, &product, &name, env_name)?;
    }
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

/// `opv set <[product/]KEY> --env <env> --from-file <PATH>` (#217): one file key's value
/// read from a file, so a multi-line value (a PEM, a kubeconfig) is stored byte for byte.
/// Only a person at a terminal may run it, and only for a declared file key; opv reads the
/// exact bytes of a regular file, refusing a symbolic link, anything that is not a regular
/// file, or a file larger than the cap. A group- or world-readable file on Unix is warned
/// about but still written. The bytes are checked with [`rules::check_verbatim`] (they are
/// intended literally, never as a template) and written through op's stdin, then the key's
/// value state is printed. No secret value, its length or any part of one reaches output,
/// argv, a log, an error or `Debug`.
pub fn set_from_file(
    fleet: &Fleet,
    env: &dyn HostEnv,
    key: &str,
    env_name: &str,
    path: &std::path::Path,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    // The same order as `set`: an infrastructure key has no value to store, said from the
    // configuration; then a person at a terminal, refused before the file is touched.
    if let Ok((product, name)) = resolve(fleet, key, env_name) {
        super::import::refuse_not_stored(fleet, &product, &name, env_name)?;
    }
    let by = from_file_command(key, env_name);
    refuse_if_agent(env, by.clone())?;
    if !env.interactive() {
        return Err(Cause::NeedsTerminal {
            why: NoTerminal::NoTty,
        }
        .into());
    }
    let (product, name) = resolve(fleet, key, env_name)?;
    let spec = &fleet.products[&product].keys[&name];
    // D3: the verbatim form is only for a key declared with `file`; any other key keeps the
    // masked entry of `set`, named without `--from-file`.
    if spec.file.is_none() {
        return Err(not_a_file_key(&product, &name, env_name));
    }
    let label = key_label(&product, &name);
    let (entered, file_meta) = read_secret_file(path, &label)?;
    // An empty file writes nothing, like an empty `set` entry.
    if entered.expose().trim().is_empty() {
        return Ok(());
    }
    let environment = fleet.environment(env_name)?;
    // Verbatim: the exact bytes are the value, so the line-shape rules and any transform do
    // not apply. A person runs this command, so every declared rule that still applies counts.
    let state = classify(
        Ok(Some(&entered)),
        crate::domain::presence::present_in(spec, env_name),
        true,
        |v| {
            rules::check_verbatim(&product, &name, spec, env_name, environment, v, true)
                .map(|_| ())
                .map_err(|f| f.rule)
        },
    );
    super::import::write_values(fleet, environment, &[(product, name, entered)], &by, r)?;
    // D2: a file other users can read is still written, then warned about.
    if shared_with_others(&file_meta) {
        writeln!(
            out,
            "warning: {} is readable by other users on this machine; opv stored it, but \
             consider chmod 600 or deleting it",
            path.display()
        )
        .map_err(write_err)?;
    }
    writeln!(out, "{}", state_text(&state)).map_err(write_err)?;
    Ok(())
}

/// True when a group or other users can read the file (Unix mode bits); always false
/// elsewhere, where opv has no mode to check.
#[cfg(unix)]
fn shared_with_others(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o077 != 0
}

#[cfg(not(unix))]
fn shared_with_others(_meta: &std::fs::Metadata) -> bool {
    false
}

/// The `opv set` command for the same key in its file form: the command an assistant is
/// handed, and the one a read-back failure names. The `<PATH>` is a literal placeholder,
/// never the person's real path.
fn from_file_command(key: &str, env_name: &str) -> Cmd {
    let mut cmd = command(key, env_name);
    cmd.args.push("--from-file".into());
    cmd.args.push("<PATH>".into());
    cmd
}

/// The usage error for a key that is not declared with `file` (D3): the person uses the
/// masked entry instead, named without `--from-file`.
fn not_a_file_key(product: &str, name: &str, env_name: &str) -> Error {
    Cause::Usage {
        problem: UsageProblem::UseInstead {
            command: Cmd {
                command: vec!["set".into()],
                args: vec![key_label(product, name), "--env".into(), env_name.into()],
            },
        },
    }
    .into()
}

/// The cause for a path `opv set --from-file` cannot read as one secret file. `rule` is a
/// property of the path or its text, so the cause never carries a byte of the value.
fn secret_file_cause(path: &std::path::Path, field: &str, rule: FieldRule) -> Error {
    Cause::InputInvalid {
        path: path.to_path_buf(),
        kind: InputKind::SecretFile,
        at: None,
        field: field.to_string(),
        rule,
    }
    .into()
}

/// [`secret_file_cause`] for a property of the path itself.
fn file_problem(path: &std::path::Path, field: &str, problem: SecretFileRule) -> Error {
    secret_file_cause(path, field, FieldRule::SecretFile { problem })
}

/// The exact bytes of the regular file at `path` as one secret value, plus the metadata the
/// Unix readability warning reads. A symlink, anything that is not a regular file, an I/O
/// error, a file larger than [`FROM_FILE_MAX_BYTES`], or bytes that are not UTF-8 are each
/// refused with a cause naming `field`; no byte, length or part of the file reaches it.
fn read_secret_file(
    path: &std::path::Path,
    field: &str,
) -> Result<(SecretValue, std::fs::Metadata), Error> {
    let not_regular = || file_problem(path, field, SecretFileRule::NotRegular);
    // The link itself is looked at first: opv reads the file, never what a link points to.
    let meta = std::fs::symlink_metadata(path).map_err(|_| not_regular())?;
    if meta.file_type().is_symlink() {
        return Err(file_problem(path, field, SecretFileRule::Symlink));
    }
    if !meta.is_file() {
        return Err(not_regular());
    }
    let mut file = std::fs::File::open(path).map_err(|_| not_regular())?;
    let opened = file.metadata().map_err(|_| not_regular())?;
    if !opened.is_file() {
        return Err(not_regular());
    }
    // Wiped on every path out, a refusal included.
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    std::io::Read::by_ref(&mut file)
        .take(FROM_FILE_MAX_BYTES + 1)
        .read_to_end(&mut *bytes)
        .map_err(|_| not_regular())?;
    if bytes.len() as u64 > FROM_FILE_MAX_BYTES {
        return Err(file_problem(
            path,
            field,
            SecretFileRule::TooLarge {
                limit: FROM_FILE_MAX_BYTES,
            },
        ));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        secret_file_cause(
            path,
            field,
            FieldRule::Type {
                expected: "UTF-8 text",
            },
        )
    })?;
    Ok((SecretValue::new(text.to_string()), opened))
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
