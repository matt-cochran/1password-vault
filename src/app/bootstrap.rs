//! `opv bootstrap` (FR-52, #77): take a fleet configuration from declared to ready in the
//! selected 1Password account. Per environment: verify the recorded vault and item in that
//! account, or create them (as `init` names them) and record their IDs in `secrets.toml`
//! (comments and order kept), then add every declared field, empty (`item skeleton`).
//! Nothing is synced or deployed, and no value is read or written.
//!
//! An environment may leave out `vault_id` and `item_id` in the file bootstrap reads: they
//! are what it fills in. Recorded IDs the selected account cannot see are never replaced
//! silently (`ids_not_in_account`): `--rebind <env>` asks for new ones.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;

use serde::Serialize;
use toml_edit::{DocumentMut, Item, value};

use super::write_err;
use crate::adapters::onepassword_init::{self as init_op, Lookup};
use crate::error::Error;
use crate::host::Host;
use crate::runner::{Call, CommandRunner, PROBE_TIMEOUT};

/// What bootstrap does for one environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Step {
    /// The recorded vault and item are in the selected account.
    Ok { vault_id: String, item_id: String },
    /// No IDs recorded (or `--rebind`): find or create these, then record their IDs.
    Create { vault: String, item: String },
    /// Recorded IDs the selected account cannot see; nothing is done without `--rebind`.
    IdsNotInAccount { vault_id: String },
}

/// One environment's step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnvPlan {
    pub environment: String,
    #[serde(flatten)]
    pub step: Step,
}

/// Options of `opv bootstrap`.
#[derive(Debug, Default, Clone)]
pub struct Opts {
    /// Print the plan only.
    pub dry_run: bool,
    /// Environments whose recorded IDs are replaced by ones in the selected account.
    pub rebind: BTreeSet<String>,
    /// Print the owner's steps for a read-only CI service account for this environment.
    pub ci_reader: Option<String>,
    /// Environments that get a state vault for delivery receipts (#106).
    pub state: BTreeSet<String>,
    pub json: bool,
}

/// An environment and its recorded vault and item IDs, if any.
type Recorded = (String, Option<String>, Option<String>);

/// The environments of the configuration text, in file order, with their recorded IDs.
fn environments(doc: &DocumentMut) -> Result<Vec<Recorded>, Error> {
    let envs = doc
        .get("environments")
        .and_then(Item::as_table_like)
        .ok_or_else(|| Error::Config("secrets.toml declares no [environments]".into()))?;
    let mut out = Vec::new();
    for (name, t) in envs.iter() {
        let get = |k: &str| {
            t.as_table_like()
                .and_then(|t| t.get(k))
                .and_then(Item::as_str)
                .map(str::to_string)
        };
        let (vault, item) = (get("vault_id"), get("item_id"));
        if vault.is_some() != item.is_some() {
            return Err(Error::Config(
                format!(
                    "environment {name}: give both vault_id and item_id, or neither for opv \
                     bootstrap to create them"
                )
                .into(),
            ));
        }
        out.push((name.to_string(), vault, item));
    }
    Ok(out)
}

/// Whether `vault_id` is a vault the signed-in account can see: `op vault get`, exit status
/// only (its output names the vault and is dropped unread). `None`: cannot tell.
fn vault_visible(r: &dyn CommandRunner, vault_id: &str) -> Option<bool> {
    r.probe(
        &Call::new("op", &["vault", "get", vault_id, "--format", "json"]),
        PROBE_TIMEOUT,
    )
    .ok()
    .map(|o| o.status == 0)
}

/// The plan for every environment of `text` (read-only: one `op vault get` per recorded
/// vault).
pub fn plan(
    r: &dyn CommandRunner,
    text: &str,
    project: &str,
    rebind: &BTreeSet<String>,
) -> Result<Vec<EnvPlan>, Error> {
    let doc: DocumentMut = text.parse().map_err(|e: toml_edit::TomlError| {
        Error::Config(format!("invalid secrets.toml: {e}").into())
    })?;
    let mut plans = Vec::new();
    for (env, vault, item) in environments(&doc)? {
        let create = Step::Create {
            vault: super::init::default_vault(project, &env),
            item: super::init::default_item(project, &env),
        };
        let step = match (vault, item) {
            (Some(_), Some(_)) if rebind.contains(&env) => create,
            (Some(v), Some(i)) => match vault_visible(r, &v) {
                Some(false) => Step::IdsNotInAccount { vault_id: v },
                _ => Step::Ok {
                    vault_id: v,
                    item_id: i,
                },
            },
            _ => create,
        };
        plans.push(EnvPlan {
            environment: env,
            step,
        });
    }
    Ok(plans)
}

/// A file whose first line says it is generated is never rewritten (FR-52).
fn is_generated(text: &str) -> bool {
    text.lines().next().is_some_and(|l| {
        l.trim_start()
            .to_ascii_lowercase()
            .starts_with("# generated")
    })
}

/// The vault titled `title` in the signed-in account, created when missing.
pub(crate) fn ensure_vault(r: &dyn CommandRunner, title: &str) -> Result<init_op::Named, Error> {
    match init_op::find_vault(r, title, &Host::detect)? {
        Lookup::Found(n) => Ok(n),
        Lookup::Missing(_) => init_op::create_vault(r, title),
    }
}

/// The item titled `title` in `vault_id`, created when missing and tagged `tag` (FR-55), so
/// `ready` can tell an item moved or wired to another environment.
fn ensure_item(
    r: &dyn CommandRunner,
    vault_id: &str,
    title: &str,
    tag: &str,
) -> Result<init_op::Named, Error> {
    match init_op::find_item(r, vault_id, title, &Host::detect)? {
        Lookup::Found(n) => Ok(n),
        Lookup::Missing(_) => init_op::create_item_tagged(r, vault_id, title, &[tag.to_string()]),
    }
}

/// The detection tag of an environment's item (FR-55).
pub fn env_tag(project: &str, env: &str) -> String {
    format!("opv-env:{project}/{env}")
}

/// `opv bootstrap` on the configuration file `path`.
pub fn run(
    path: &Path,
    project: &str,
    opts: &Opts,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        Error::Config(format!("cannot read {} ({})", path.display(), e.kind()).into())
            .with_next("opv init <env>")
    })?;
    let plans = plan(r, &text, project, &opts.rebind)?;
    let stale: Vec<&EnvPlan> = plans
        .iter()
        .filter(|p| matches!(p.step, Step::IdsNotInAccount { .. }))
        .collect();
    let creates = plans.iter().any(|p| matches!(p.step, Step::Create { .. }));
    if opts.dry_run || (!stale.is_empty() && !creates) {
        print_plan(out, &plans, opts.json, false)?;
        return match stale.first() {
            Some(p) => Err(stale_error(&p.environment)),
            None => Ok(()),
        };
    }
    // Creating vaults and items and adding fields write to 1Password: a person's own
    // session, never a service account (FR-43).
    super::tidy::require_person(r, "opv bootstrap")?;
    let mut doc: DocumentMut = text.parse().map_err(|e: toml_edit::TomlError| {
        Error::Config(format!("invalid secrets.toml: {e}").into())
    })?;
    let mut recorded: Vec<(String, String, String)> = Vec::new();
    for p in &plans {
        let Step::Create { vault, item } = &p.step else {
            continue;
        };
        let v = ensure_vault(r, vault)?;
        let i = ensure_item(r, &v.id, item, &env_tag(project, &p.environment))?;
        let env = &mut doc["environments"][p.environment.as_str()];
        env["vault_id"] = value(v.id.clone());
        env["item_id"] = value(i.id.clone());
        recorded.push((p.environment.clone(), v.id, i.id));
    }
    // #106: each `--state` environment's state vault, recorded as state_vault_id.
    let mut state_vaults: Vec<(String, String)> = Vec::new();
    for env_name in &opts.state {
        if doc["environments"].get(env_name.as_str()).is_none() {
            return Err(Error::Config(
                format!("--state {env_name}: no such environment").into(),
            ));
        }
        let v = ensure_vault(r, &format!("{project}-{env_name}-state"))?;
        doc["environments"][env_name.as_str()]["state_vault_id"] = value(v.id.clone());
        state_vaults.push((env_name.clone(), v.id));
    }
    let new_text = doc.to_string();
    // The result loads like any hand-written file before it replaces it.
    let fleet = crate::config::parse(&new_text)?;
    if !recorded.is_empty() || !state_vaults.is_empty() {
        if is_generated(&text) {
            print_plan(out, &plans, opts.json, false)?;
            let ids: Vec<String> = recorded
                .iter()
                .map(|(e, v, i)| format!("{e}: vault_id = {v:?}, item_id = {i:?}"))
                .collect();
            return Err(Error::Policy(
                format!(
                    "{} is generated, so opv does not rewrite it; record these IDs in its \
                     generator's input:\n  {}",
                    path.display(),
                    ids.join("\n  ")
                )
                .into(),
            )
            .with_code(crate::error::Code::PolicyRefused)
            .with_next("opv bootstrap --dry-run"));
        }
        super::init::write_atomic(path, &new_text, true)?;
    }
    // Every declared field, empty, in each ready environment's item.
    for p in &plans {
        if matches!(p.step, Step::IdsNotInAccount { .. }) {
            continue;
        }
        super::skeleton::run_as(&fleet, &p.environment, r, &mut std::io::sink(), false)?;
    }
    // FR-55: the signed-in person's own item, with empty fields for the personal keys, in
    // their own vault; nobody else's.
    let mut personal_items: Vec<String> = Vec::new();
    for p in &plans {
        let env_name = &p.environment;
        if !super::personal::declared(&fleet, env_name) {
            continue;
        }
        let team = fleet.environment(env_name)?;
        let Some(vault) = super::personal::private_vault(r, team)? else {
            return Err(Error::Config(
                format!(
                    "environment {env_name}: no personal vault found for your personal keys \
                     (looked for {}); set personal_vault to the title of a vault only you can \
                     open",
                    team.personal_vault
                        .clone()
                        .unwrap_or_else(|| "Private, Employee, Personal".into())
                )
                .into(),
            ));
        };
        let title = super::personal::item_title(team, project);
        let item = ensure_item(r, &vault.id, &title, &env_tag(project, env_name))?;
        let mut mine = super::personal::personal_fleet(&fleet, env_name);
        // Every product's boundary is the personal item here (FR-55).
        let names: Vec<String> = mine
            .products
            .keys()
            .map(|p| mine.boundary_of(p).to_string())
            .collect();
        if let Some(e) = mine.environments.get_mut(env_name.as_str()) {
            e.boundaries = names
                .into_iter()
                .map(|b| {
                    let at = crate::domain::Boundary {
                        vault_id: vault.id.clone(),
                        item_id: item.id.clone(),
                    };
                    (b, at)
                })
                .collect();
        }
        super::skeleton::run_as(&mine, env_name, r, &mut std::io::sink(), false)?;
        personal_items.push(format!(
            "{env_name}: your personal item {title:?} in vault {:?}",
            vault.name
        ));
    }
    print_plan(out, &plans, opts.json, true)?;
    if !opts.json {
        for line in &personal_items {
            writeln!(out, "{line}").map_err(write_err)?;
        }
        writeln!(
            out,
            "every ready environment has its vault, item and empty fields; fill the values in \
             1Password, then check what is left"
        )
        .map_err(write_err)?;
        if let Some(env) = &opts.ci_reader {
            let e = fleet.environment(env)?;
            // One reader per boundary vault for now (FR-59 computes the exact set later).
            for b in e.boundaries.values() {
                ci_reader_steps(out, project, env, &b.vault_id)?;
            }
        }
        for (env, state_vault) in &state_vaults {
            let e = fleet.environment(env)?;
            for b in e.boundaries.values() {
                deploy_identity_steps(out, project, env, &b.vault_id, state_vault)?;
            }
        }
        writeln!(out, "Next: opv ready").map_err(write_err)?;
    }
    match stale.first() {
        Some(p) => Err(stale_error(&p.environment)),
        None => Ok(()),
    }
}

/// The owner's steps for a least-privilege CI reader of `env`'s vault (FR-52): opv prints
/// them and never runs them, because 1Password shows the new token once, to the owner.
fn ci_reader_steps(
    out: &mut dyn Write,
    project: &str,
    env: &str,
    vault_id: &str,
) -> Result<(), Error> {
    let lines = [
        format!("CI reader for {env} (run these yourself; the token is shown once, by 1Password):"),
        format!(
            "  1. op service-account create \"{project}-{env}-ci\" --vault {vault_id}:read_items \
             --expires-in 90d"
        ),
        "  2. store the token it prints as the CI secret OP_SERVICE_ACCOUNT_TOKEN in your CI \
         provider (on GitHub: the repository's Settings > Secrets and variables > Actions), \
         pasting it there yourself"
            .to_string(),
        "  3. keep a separate, protected deploy identity (deploy_credentials) and your own \
         owner access for recovery; never give CI an owner or break-glass credential"
            .to_string(),
    ];
    for l in lines {
        writeln!(out, "{l}").map_err(write_err)?;
    }
    Ok(())
}

/// The owner's steps for `env`'s deploy identity with delivery receipts (#106): read-only on
/// the values vault, read and write on the state vault. Printed, never run (1Password shows
/// the token once, to the owner).
fn deploy_identity_steps(
    out: &mut dyn Write,
    project: &str,
    env: &str,
    vault_id: &str,
    state_vault_id: &str,
) -> Result<(), Error> {
    let lines = [
        format!(
            "{env}: state vault {state_vault_id} recorded as state_vault_id; delivery receipts \
             are kept there, one item per product"
        ),
        format!(
            "  deploy identity (run it yourself; the token is shown once, by 1Password):\n  op \
             service-account create \"{project}-{env}-deploy\" --vault {vault_id}:read_items \
             --vault {state_vault_id}:read_items,write_items --expires-in 90d"
        ),
        "  give the state vault only to identities that can also read the values".to_string(),
    ];
    for l in lines {
        writeln!(out, "{l}").map_err(write_err)?;
    }
    Ok(())
}

/// `ids_not_in_account`: the recorded IDs belong to an account other than the selected one.
fn stale_error(env: &str) -> Error {
    Error::Config(
        format!(
            "environment {env}: its recorded vault is not in the selected 1Password account; \
             opv never falls back to another account"
        )
        .into(),
    )
    .with_code(crate::error::Code::IdsNotInAccount)
    .with_do(format!(
        "either select the account that holds it (opv account list, then opv account use \
         <ID>), or record a new vault and item in this account with opv bootstrap --rebind \
         {env} (values are not moved)"
    ))
    .with_next("opv account list")
}

fn print_plan(out: &mut dyn Write, plans: &[EnvPlan], json: bool, done: bool) -> Result<(), Error> {
    if json {
        let v = serde_json::json!({
            "schema_version": crate::json::SCHEMA_VERSION,
            "environments": plans,
        });
        return writeln!(out, "{v}").map_err(write_err);
    }
    for p in plans {
        let line = match &p.step {
            Step::Ok { vault_id, item_id } => {
                format!("{}: ok (vault {vault_id}, item {item_id})", p.environment)
            }
            Step::Create { vault, item } if done => format!(
                "{}: vault {vault:?} and item {item:?} ready (created or found), IDs recorded",
                p.environment
            ),
            Step::Create { vault, item } => format!(
                "{}: would create vault {vault:?} and item {item:?} (or use them if they exist)",
                p.environment
            ),
            Step::IdsNotInAccount { vault_id } => format!(
                "{}: vault {vault_id} is not in the selected account (ids_not_in_account)",
                p.environment
            ),
        };
        writeln!(out, "{line}").map_err(write_err)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "bootstrap_tests.rs"]
mod tests;
