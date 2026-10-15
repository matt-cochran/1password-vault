//! Declarations an assistant may make through MCP (#133): products and keys (kind,
//! environments, rules, guidance, immutable), environments, and named targets, edited in
//! the local `secrets.toml` only. Nothing here reads or writes 1Password, and no value is
//! accepted: what a declaration needs in 1Password (a boundary vault and item, a target's
//! state vault and delivery items, empty fields) is created by the structural plan a person
//! approves ([`super::structure`], `opv approve`).
//!
//! A declaration works on a configuration that is not bootstrapped yet: it is validated as
//! the file will load once the structural plan records the missing IDs (placeholders, as
//! the plan itself judges it). Shared (`from`) and personal keys, deploy credentials,
//! removals and changes to an existing target are not declarations: they change where
//! values flow or who holds them, and stay with the person (`opv add`, `opv target add`,
//! `opv config edit`). A generated configuration is never edited (FR-52).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::config_store::{ConfigStore, FileStore, Replaced, Snapshot};
use crate::domain::Fleet;
use crate::error::{Code, Error};
use crate::runner::CommandRunner;

/// Guidance is shown to people and other assistants: one short line of plain text.
pub const GUIDANCE_MAX: usize = 300;

/// The file store, validating a text as it will load once the structural plan's IDs are
/// recorded.
struct Declaring(FileStore);

impl ConfigStore for Declaring {
    fn describe(&self) -> String {
        self.0.describe()
    }
    fn read(&self, r: &dyn CommandRunner) -> Result<Snapshot, Error> {
        self.0.read(r)
    }
    fn replace(
        &self,
        r: &dyn CommandRunner,
        base: &Snapshot,
        text: &str,
    ) -> Result<Replaced, Error> {
        self.0.replace(r, base, text)
    }
    fn source(&self) -> crate::config::Source<'_> {
        self.0.source()
    }
    fn parse(&self, text: &str) -> Result<Fleet, Error> {
        crate::config::parse_at(&super::structure::trial_text(text)?, self.0.source())
    }
}

fn store(path: &Path) -> Result<Declaring, Error> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        Error::Config(format!("Cannot read {} ({}).", path.display(), e.kind()).into())
    })?;
    if super::bootstrap::is_generated(&text) {
        return Err(Error::Policy(
            format!(
                "{} is generated; opv does not edit it: declare this in its generator's input",
                path.display()
            )
            .into(),
        )
        .with_code(Code::PolicyRefused));
    }
    Ok(Declaring(FileStore {
        path: PathBuf::from(path),
    }))
}

fn cfg(m: String) -> Error {
    Error::Config(m.into()).with_code(Code::ConfigInvalid)
}

/// A key declaration: names, kind, rules and guidance; never a value.
#[derive(Debug, Clone, Default)]
pub struct Key {
    pub product: String,
    pub key: String,
    /// `secret` or `config`.
    pub kind: String,
    /// Empty: every declared environment.
    pub environments: Vec<String>,
    /// `name=value` or `name` (a flag rule such as `https_url`), as `opv add --rule`.
    pub rules: Vec<String>,
    pub guidance: Option<String>,
    pub immutable: bool,
}

/// Declare or extend `key` in the configuration at `path` (as `opv add`, without `--from`
/// or `--personal`): true when the file changed.
pub fn key(r: &dyn CommandRunner, path: &Path, k: &Key) -> Result<bool, Error> {
    if let Some(g) = &k.guidance
        && (g.chars().count() > GUIDANCE_MAX || g.chars().any(char::is_control))
    {
        return Err(cfg(format!(
            "guidance must be one line of at most {GUIDANCE_MAX} characters"
        )));
    }
    if !["secret", "config"].contains(&k.kind.as_str()) {
        return Err(cfg(format!("kind {:?} must be secret or config", k.kind)));
    }
    let store = store(path)?;
    let before = std::fs::read_to_string(path).unwrap_or_default();
    let args = super::add::AddArgs {
        name: format!("{}/{}", k.product, k.key),
        kind: Some(k.kind.clone()),
        envs: k.environments.clone(),
        rules: k.rules.clone(),
        guidance: k.guidance.clone(),
        immutable: k.immutable,
        json: true,
        ..Default::default()
    };
    super::add::run(&args, &store, r, &mut std::io::sink())?;
    Ok(std::fs::read_to_string(path).unwrap_or_default() != before)
}

/// Declare the environment `name` (an empty table; its boundaries come from the structural
/// plan): true when the file changed.
pub fn environment(r: &dyn CommandRunner, path: &Path, name: &str) -> Result<bool, Error> {
    if !crate::config::is_target_name(name) {
        return Err(cfg(format!(
            "environment name {name:?} must match ^[a-z][a-z0-9-]*$"
        )));
    }
    let store = store(path)?;
    let base = store.read(r)?;
    if has_env(&base.text, name)? {
        return Ok(false);
    }
    let mut doc = crate::config_edit::ConfigDoc::parse(&base.text)?;
    doc.add_environment(name, &format!("[environments.{name}]\n"))?;
    let text = doc.to_string();
    store.parse(&text)?;
    crate::config_store::save(&store, r, &base, &text)?;
    Ok(true)
}

fn has_env(text: &str, name: &str) -> Result<bool, Error> {
    let doc = super::bootstrap::parse_doc(text)?;
    Ok(doc
        .get("environments")
        .and_then(|e| e.as_table_like())
        .is_some_and(|t| t.contains_key(name)))
}

/// A named target declaration: provider options are names and public identifiers (an app,
/// a vault URL, a namespace), never a credential.
#[derive(Debug, Clone, Default)]
pub struct Target {
    pub environment: String,
    pub name: String,
    pub provider: Option<String>,
    /// Provider options by flag name, as `opv target add` takes them (`fly-app`).
    pub fields: BTreeMap<String, String>,
    /// The products it delivers; empty means every product.
    pub products: Vec<String>,
}

/// Declare a new target in the configuration at `path`, without its state vault: the
/// approved structural plan creates the state vault and delivery items and records their
/// IDs. An existing target is never changed. True when the file changed.
pub fn target(r: &dyn CommandRunner, path: &Path, t: &Target) -> Result<bool, Error> {
    use super::target_cmd;
    if !crate::config::is_target_name(&t.name) {
        return Err(cfg(format!(
            "target name {:?} must match ^[a-z][a-z0-9-]*$",
            t.name
        )));
    }
    if t.fields.keys().any(|k| k.contains("credential")) {
        return Err(Error::Policy(
            "deploy credentials are not declared here; a person adds them with opv target add \
             --deploy-credentials in their own terminal"
                .into(),
        )
        .with_code(Code::PolicyRefused));
    }
    let store = store(path)?;
    let base = store.read(r)?;
    let fleet = store.parse(&base.text)?;
    let env = fleet.environment(&t.environment)?;
    if env.targets.contains_key(&t.name) {
        return Ok(false);
    }
    let args = target_cmd::AddArgs {
        env: t.environment.clone(),
        name: t.name.clone(),
        provider: t.provider.clone(),
        fields: t.fields.clone(),
        products: t.products.clone(),
        ..Default::default()
    };
    let (provider, values) = target_cmd::provider_and_values(&args)?;
    let section = provider.init_section(&values).ok_or_else(|| {
        cfg(format!(
            "a {} target cannot be declared here yet; a person adds it with opv target add",
            provider.label()
        ))
    })?;
    let products = target_cmd::checked_products(&fleet, &t.products)?;
    let body = target_cmd::target_table(
        &t.environment,
        &t.name,
        &section,
        &products,
        None,
        None,
        &[],
    );
    let comment = format!(
        "# deploy target {} in {}; declared through opv's MCP tools (its state vault comes from the approved structural plan)",
        t.name, t.environment
    );
    let text = target_cmd::insert_target(&base.text, &t.environment, &t.name, &body, &comment)?;
    store.parse(&text)?;
    crate::config_store::save(&store, r, &base, &text)?;
    Ok(true)
}

/// Record `deploy_credentials` on an existing target in the configuration at `path`
/// (FR-40). `reference` is an `op://<vault>/<item>` reference (an identifier, never a
/// value). The same validated, concurrency-checked edit as every other declaration: every
/// comment and line is kept, a generated configuration is refused, and a concurrent change
/// writes nothing.
pub fn set_target_deploy_credentials(
    r: &dyn CommandRunner,
    path: &Path,
    env: &str,
    target: &str,
    reference: &str,
) -> Result<(), Error> {
    let store = store(path)?;
    let base = store.read(r)?;
    let mut doc = super::bootstrap::parse_doc(&base.text)?;
    let table = doc
        .get_mut("environments")
        .and_then(|e| e.get_mut(env))
        .and_then(|e| e.get_mut("targets"))
        .and_then(|t| t.get_mut(target))
        .and_then(toml_edit::Item::as_table_like_mut)
        .ok_or_else(|| {
            cfg(format!(
                "environment {env} has no target {target:?} opv can edit; add this line by \
                 hand: deploy_credentials = {reference:?}"
            ))
        })?;
    table.insert("deploy_credentials", toml_edit::value(reference));
    let text = doc.to_string();
    store.parse(&text)?;
    crate::config_store::save(&store, r, &base, &text)?;
    Ok(())
}

/// The environment names declared in the file at `path` (for checks before a declaration).
pub fn environments(path: &Path) -> Result<BTreeSet<String>, Error> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        Error::Config(format!("Cannot read {} ({}).", path.display(), e.kind()).into())
    })?;
    let doc = super::bootstrap::parse_doc(&text)?;
    Ok(doc
        .get("environments")
        .and_then(|e| e.as_table_like())
        .map(|t| t.iter().map(|(k, _)| k.to_string()).collect())
        .unwrap_or_default())
}

#[cfg(test)]
#[path = "declare_tests.rs"]
mod tests;
