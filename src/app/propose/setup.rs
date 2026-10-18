//! `opv propose setup` (design Part V, row `propose-setup`): the starter contract `opv init`
//! would write, proposed rather than written. Two sources:
//!
//! - [`from_item`]: the fields of an existing 1Password item, by title, exactly as `init`
//!   reads them (section, label and type only; never a value).
//! - [`from_names`]: the NAMES in a `.env` file, each kind decided by
//!   [`crate::domain::kind_guess`] unless `--config-key` / `--secret-key` overrides it.
//!
//! Pure: a proposal reads no file it was not given and writes nothing. The contract carries
//! no 1Password id (D-G): ids go to `secrets.bindings.toml`, which the apply step writes.
//! Neither a value nor a length, digest or prefix of one is carried.

use std::path::Path;

use sha2::{Digest, Sha256};

use super::Proposal;
use crate::app::config_cmd;
use crate::app::init::{self, FromFile};
use crate::cause::{Cause, GivenBy, UsageProblem};
use crate::config_edit::ConfigDoc;
use crate::domain::Kind;
use crate::error::Error;

/// The product the keys of a names-only `.env` proposal belong to. Its boundary carries no
/// id yet; an apply records the item its fields were read from.
pub const NAMES_PRODUCT: &str = "app";

/// The environment a names-only proposal declares: a `.env` holds a developer's own values.
pub const NAMES_ENV: &str = "local";

/// A setup proposal: init's [`Proposal`] plus the structure an apply creates first.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SetupProposal {
    /// The contract diff, the categorical questions and the content-addressed plan id.
    pub proposal: Proposal,
    /// The structure an apply creates first, by name: the boundary, the item and each field.
    pub structure_steps: Vec<String>,
    /// The `secrets.bindings.toml` text an apply writes: the existing item's ids
    /// (`--from-item`); `None` when nothing exists yet (`--names-from`).
    pub bindings_after: Option<String>,
}

/// Propose the contract `opv init <env> --vault <vault> --item <item>` would write for an
/// existing item, read-only, with the ids split out (D-G). `file_target` is the contract
/// file the diff is against: its text when it exists, else `None` for a first setup.
pub fn from_item(
    r: &dyn crate::runner::CommandRunner,
    env: &str,
    vault: Option<&str>,
    item: Option<&str>,
    file_target: Option<&Path>,
) -> Result<SetupProposal, Error> {
    let vault = vault.ok_or_else(|| needs_flag("--from-item", "--vault <title>"))?;
    let item = item.ok_or_else(|| needs_flag("--from-item", "--item <title>"))?;
    let built = init::plan_item(r, env, vault, item, None)?;
    let mut proposal = build(built.contract, built.steps, file_target)?;
    proposal.bindings_after = (!built.bindings.is_empty()).then(|| built.bindings.render());
    Ok(proposal)
}

/// Propose the contract that declares every valid name in the `.env` file at `path`, each
/// kind by `kind_guess` unless `--config-key` / `--secret-key` names it. Values are read
/// only to tell empty fields apart and are dropped (SR-1, SR-2); a name in both lists is
/// refused, as `init` refuses it. Nothing is read beyond the file and nothing is written.
pub fn from_names(
    path: &Path,
    env: &str,
    config_keys: &[String],
    secret_keys: &[String],
) -> Result<SetupProposal, Error> {
    check_env(env)?;
    let imported = init::read_from(&FromFile {
        path: path.to_path_buf(),
        config: config_keys.to_vec(),
        secret: secret_keys.to_vec(),
        apply: false,
    })?;
    let contract = names_contract(env, &imported)?;
    build(contract, names_steps(&imported), None)
}

/// The contract for a names-only proposal: one environment declaring the product's
/// boundary (without an id yet), then one table per key with its kind.
fn names_contract(env: &str, imported: &init::Imported) -> Result<String, Error> {
    let seed = format!("[environments.{env}]\nboundaries.{NAMES_PRODUCT} = {{}}\n");
    let mut doc = ConfigDoc::parse(&seed)?;
    let environments = vec![env.to_string()];
    for (name, kind) in &imported.kinds {
        doc.add_key(
            NAMES_PRODUCT,
            name,
            &crate::config_edit::NewKey {
                kind: kind_word(*kind),
                environments: &environments,
                rules: &[],
                guidance: None,
                immutable: false,
                from: None,
                personal: false,
                allow_same_value: false,
                except: &[],
                source: None,
                shape: None,
                expires: None,
                lifecycle: None,
            },
        )?;
    }
    Ok(doc.to_string())
}

/// The structure a names-only proposal creates: the boundary, the item and each field.
fn names_steps(imported: &init::Imported) -> Vec<String> {
    let mut steps = vec![
        format!("boundary {NAMES_PRODUCT}"),
        format!("item {NAMES_PRODUCT}"),
    ];
    for (name, kind) in &imported.kinds {
        steps.push(format!("field {NAMES_PRODUCT}/{name} {}", kind_word(*kind)));
    }
    steps
}

/// Write the proposed contract to `path` (`opv propose setup --write`), replacing what the
/// diff was computed against; the contract only, never a value. The ids an existing item
/// has are recorded by `opv apply`, which finds the item by its title.
pub fn write(path: &Path, proposal: &SetupProposal) -> Result<(), Error> {
    init::write_config(path, &proposal.proposal.contract_after, true)
}

/// Assemble the proposal: the diff against `file_target`, the plan id and the structure.
fn build(
    contract: String,
    structure_steps: Vec<String>,
    file_target: Option<&Path>,
) -> Result<SetupProposal, Error> {
    let base = read_base(file_target)?;
    // The plan id mirrors `propose key`: lowercase hex SHA-256 of the kind and the proposed
    // contract text (the environment is already in the text).
    Ok(SetupProposal {
        proposal: Proposal {
            kind: "setup",
            relaxations: Vec::new(),
            diff: config_cmd::diff(&base, &contract),
            questions: Vec::new(),
            plan_id: plan_id(&contract),
            contract_after: contract,
        },
        structure_steps,
        bindings_after: None,
    })
}

/// The text the diff is against: the target contract file, or nothing for a first setup.
fn read_base(file_target: Option<&Path>) -> Result<String, Error> {
    let Some(path) = file_target else {
        return Ok(String::new());
    };
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(crate::config_store::unreadable(
            path,
            &e,
            GivenBy::Discovered,
        )),
    }
}

/// The environment name must be a bare TOML key before it is put in generated text.
fn check_env(env: &str) -> Result<(), Error> {
    let first_ok = env
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric());
    let rest_ok = env
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if first_ok && rest_ok {
        return Ok(());
    }
    Err(Cause::Usage {
        problem: UsageProblem::ValueFormat {
            flag: format!("the environment name {env:?}"),
            format: "letters, digits, _ and -, starting with a letter or digit",
        },
    }
    .into())
}

fn needs_flag(flag: &str, needs: &str) -> Error {
    Cause::Usage {
        problem: UsageProblem::NeedsFlag {
            flag: flag.into(),
            needs: needs.into(),
        },
    }
    .into()
}

fn kind_word(kind: Kind) -> &'static str {
    match kind {
        Kind::Secret => "secret",
        Kind::Config => "config",
    }
}

/// The content-addressed plan id: lowercase hex SHA-256 of the kind and the contract.
fn plan_id(contract: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"setup\n");
    hasher.update(contract.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
#[path = "setup_tests.rs"]
mod tests;
