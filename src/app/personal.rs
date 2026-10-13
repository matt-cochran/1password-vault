//! Personal keys (FR-55): each person's own value, in their own 1Password item.
//!
//! A personal key (`personal = true`) is declared only for an environment without a target
//! and never reaches one. Its value lives in the vault `personal_vault` (or the person's
//! own Private vault) and the item `personal_item` (or `<project> · <env> (personal)`),
//! read tolerated like the team item and never mixed with a team value. This module locates
//! that item and merges its fields over the team item's for `check` and `run`.
//!
//! Names only in every message and error (SR-1): no value is ever printed.

use std::collections::BTreeSet;
use std::path::Path;

use crate::adapters::onepassword;
use crate::adapters::onepassword_init::{self, Lookup};
use crate::adapters::onepassword_tidy;
use crate::config_store;
use crate::domain::convention;
use crate::domain::plan::ItemField;
use crate::domain::{Environment, Fleet, KeySpec, SIMPLE_PRODUCT};
use crate::error::Error;
use crate::host::Host;
use crate::runner::CommandRunner;

/// The vault titles a person's own vault may have, by account type (FR-55).
const PRIVATE_VAULTS: [&str; 3] = ["Private", "Employee", "Personal"];

/// Whether any key declared for `env_name` is personal (FR-55).
pub fn declared(fleet: &Fleet, env_name: &str) -> bool {
    fleet.products.values().any(|p| {
        p.keys
            .values()
            .any(|spec| spec.personal && spec.environments.iter().any(|e| e == env_name))
    })
}

/// The project name a personal item's default title uses (FR-55): the repository's last
/// segment when `dir` is in a repository with a remote, else the directory's own name; the
/// literal `project` when neither yields a valid name.
pub fn project_name(r: &dyn CommandRunner, dir: &Path) -> String {
    config_store::default_project(None, config_store::git_repo(r).as_deref(), dir)
        .unwrap_or_else(|_| "project".to_string())
}

/// The title of `env`'s personal item (FR-55): its `personal_item`, else
/// `<project> · <env> (personal)`.
pub fn item_title(env: &Environment, project: &str) -> String {
    env.personal_item
        .clone()
        .unwrap_or_else(|| format!("{project} · {} (personal)", env.name))
}

/// Locate `env_name`'s personal item for the signed-in person (FR-55).
///
/// `Ok(None)` when no personal key is declared for the environment. Otherwise the vault
/// titled `personal_vault`, or the first of `Private`, `Employee`, `Personal` that exists;
/// then the item titled [`item_title`] in it. The returned environment is the team one with
/// `vault_id` and `item_id` replaced by that item's, so every existing reader works on it.
/// A missing vault or item is the setup error [`not_set_up`]; the caller turns it into
/// findings (`check`) or a configuration error naming the keys (`run`).
pub fn locate(
    r: &dyn CommandRunner,
    fleet: &Fleet,
    env_name: &str,
    project: &str,
) -> Result<Option<Environment>, Error> {
    if !declared(fleet, env_name) {
        return Ok(None);
    }
    let team = fleet.environment(env_name)?;
    let vault = match &team.personal_vault {
        Some(title) => match onepassword_init::find_vault(r, title, &Host::detect)? {
            Lookup::Found(v) => v,
            Lookup::Missing(_) => return Err(not_set_up(env_name)),
        },
        None => {
            let mut found = None;
            for title in PRIVATE_VAULTS {
                match onepassword_init::find_vault(r, title, &Host::detect)? {
                    Lookup::Found(v) => {
                        found = Some(v);
                        break;
                    }
                    Lookup::Missing(_) => continue,
                }
            }
            found.ok_or_else(|| not_set_up(env_name))?
        }
    };
    let item =
        match onepassword_init::find_item(r, &vault.id, &item_title(team, project), &Host::detect)?
        {
            Lookup::Found(i) => i,
            Lookup::Missing(_) => return Err(not_set_up(env_name)),
        };
    let mut personal = team.clone();
    personal.vault_id = vault.id;
    personal.item_id = item.id;
    Ok(Some(personal))
}

/// FR-55: the person has not created their personal item yet (or the vault is missing).
/// Code-free and value-free; `bootstrap` creates it.
fn not_set_up(env_name: &str) -> Error {
    Error::Source(format!("your personal item for {env_name} is not set up yet").into())
        .with_next("opv bootstrap")
}

/// The team fields with every personal key's field removed and the personal item's fields
/// added (FR-55).
///
/// Each personal key's value lives in the person's own item and is read there tolerantly
/// (like the team item, FR-43), never from the team item and never mixed. A field of the
/// team item that a personal key claims (its own, or its `from` source) is removed, so a
/// same-named team field can never stand in for a personal one. When the personal item
/// cannot be located or read, the personal keys simply have no field: `check` reports them
/// missing, and this never errors and never falls back to the team value.
pub fn merged_fields(
    r: &dyn CommandRunner,
    fleet: &Fleet,
    env_name: &str,
    team_fields: Vec<ItemField>,
    project: &str,
) -> Result<Vec<ItemField>, Error> {
    let claimed = claimed_fields(fleet, env_name);
    let mut out: Vec<ItemField> = team_fields
        .into_iter()
        .filter(|f| !claimed.contains(&(f.section.clone(), f.label.clone())))
        .collect();
    let Ok(Some(env)) = locate(r, fleet, env_name, project) else {
        return Ok(out);
    };
    let Ok(item) = onepassword::read_whole(r, &env) else {
        return Ok(out);
    };
    let Ok((layout, _)) = onepassword_tidy::parse(item.raw()) else {
        return Ok(out);
    };
    let personal = convention::read_fields(&layout, &personal_fleet(fleet, env_name), env_name);
    out.extend(
        personal
            .into_iter()
            .filter(|f| claimed.contains(&(f.section.clone(), f.label.clone()))),
    );
    Ok(out)
}

/// Whether `spec` is personal, directly or through a `from` to a personal source
/// (FR-45, FR-55). Load-time rules keep the two in step; this follows both.
pub fn is_personal(fleet: &Fleet, spec: &KeySpec) -> bool {
    spec.personal
        || spec.source().is_some_and(|(sp, sk)| {
            fleet
                .products
                .get(sp)
                .and_then(|p| p.keys.get(sk))
                .is_some_and(|s| s.personal)
        })
}

/// The `op run` reference for a personal `product`/`key` (FR-55): its value lives in
/// `env`'s personal item, addressed by the personal item's IDs, never the team item's.
/// A shared key points at its source's field, exactly as its team counterpart would.
pub fn reference(env: &Environment, product: &str, key: &str, spec: &KeySpec) -> String {
    let (p, k) = spec.source().unwrap_or((product, key));
    let field = if p == SIMPLE_PRODUCT {
        k.to_string()
    } else {
        format!("{p}/{k}")
    };
    format!("op://{}/{}/{field}", env.vault_id, env.item_id)
}

/// Every `(section, label)` field a personal key claims: its source's when it is shared
/// (the value lives in the source key's field), else its own.
fn claimed_fields(fleet: &Fleet, env_name: &str) -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for (product, prod) in &fleet.products {
        for (key, spec) in &prod.keys {
            if !spec.personal || !spec.environments.iter().any(|e| e == env_name) {
                continue;
            }
            out.insert((product.clone(), key.clone()));
            if let Some((p, k)) = spec.source() {
                out.insert((p.to_string(), k.to_string()));
            }
        }
    }
    out
}

/// `fleet` restricted to the personal keys declared for `env_name`, for a tolerant field
/// read whose normalization matches the team item's.
fn personal_fleet(fleet: &Fleet, env_name: &str) -> Fleet {
    let mut out = fleet.clone();
    for prod in out.products.values_mut() {
        prod.keys
            .retain(|_, spec| spec.personal && spec.environments.iter().any(|e| e == env_name));
    }
    out.products.retain(|_, prod| !prod.keys.is_empty());
    out
}

#[cfg(test)]
#[path = "personal_tests.rs"]
mod tests;
