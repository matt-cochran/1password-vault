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
use crate::cause::{
    Cause, DottedPath, NamedBy, NotFoundState, ResourceKind, ResourceName, ResourceRef, System,
};
use crate::config_store;
use crate::domain::convention;
use crate::domain::plan::ItemField;
use crate::domain::{Boundary, Environment, Fleet, KeySpec};
use crate::error::Error;
use crate::host::Host;
use crate::runner::{Call, CommandRunner};

/// The vault titles a person's own vault may have, by account type (FR-55).
const PRIVATE_VAULTS: [&str; 3] = ["Private", "Employee", "Personal"];

/// Whether any key declared for `env_name` is personal (FR-55).
pub fn declared(fleet: &Fleet, env_name: &str) -> bool {
    fleet.products.values().any(|p| {
        p.keys
            .values()
            .any(|spec| spec.personal && spec.is_desired_in(env_name))
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
/// then the item titled [`item_title`] in it. Returned as the vault and item an item read
/// addresses, so every existing reader works on it.
/// A missing vault or item is `NotFound` ([`vault_missing`]); the caller turns it into
/// findings (`check`) or a configuration error naming the keys (`run`).
pub fn locate(
    r: &dyn CommandRunner,
    fleet: &Fleet,
    env_name: &str,
    project: &str,
) -> Result<Option<Boundary>, Error> {
    if !declared(fleet, env_name) {
        return Ok(None);
    }
    let team = fleet.environment(env_name)?;
    let vault = match private_vault(r, team)? {
        Some(v) => v,
        None => return Err(vault_missing(team)),
    };
    let title = item_title(team, project);
    let item = match onepassword_init::find_item(r, &vault.id, &title, &Host::detect)? {
        Lookup::Found(i) => i,
        Lookup::Missing(_) => return Err(item_missing(team, &vault.id, &title)),
    };
    Ok(Some(Boundary {
        vault_id: vault.id,
        item_id: item.id,
    }))
}

/// The vault holding `team`'s personal items: `personal_vault`, or the person's own
/// Private/Employee/Personal vault. One `op vault list` per title tried.
pub(crate) fn private_vault(
    r: &dyn CommandRunner,
    team: &Environment,
) -> Result<Option<onepassword_init::Named>, Error> {
    for title in vault_titles(team) {
        if let Lookup::Found(v) = onepassword_init::find_vault(r, title, &Host::detect)? {
            return Ok(Some(v));
        }
    }
    Ok(None)
}

/// The vault titles a personal item may be in: `personal_vault`, else the person's own
/// vault by any of its names.
fn vault_titles(team: &Environment) -> Vec<&str> {
    match &team.personal_vault {
        Some(t) => vec![t.as_str()],
        None => PRIVATE_VAULTS.to_vec(),
    }
}

/// FR-55, 04.16, R34: no vault with any title a personal item may be in. The vault titles
/// opv looked for are named, and so is the field that sets one (`personal_vault`); the
/// observed call is the last `op vault list` that answered without it.
pub(crate) fn vault_missing(team: &Environment) -> Error {
    let call = Call::new(onepassword::OP, &["vault", "list", "--format", "json"]);
    missing(
        &call,
        ResourceRef {
            kind: ResourceKind::PersonalVault,
            name: ResourceName::new(vault_titles(team).join(", ")),
            scope: None,
        },
        &team.name,
        "personal_vault",
        team.personal_vault.is_some(),
    )
}

/// FR-55, 04.16: no item titled `title` in the person's vault `vault_id`. Value-free;
/// `bootstrap` creates it. The observed call is the `op item list` that answered without it.
fn item_missing(team: &Environment, vault_id: &str, title: &str) -> Error {
    let args = ["item", "list", "--vault", vault_id, "--format", "json"];
    let call = Call::new(onepassword::OP, &args);
    missing(
        &call,
        ResourceRef {
            kind: ResourceKind::Item,
            name: ResourceName::new(title),
            scope: Some(vault_id.to_string()),
        },
        &team.name,
        "personal_item",
        true,
    )
}

/// `resource` is not in the listing `call` answered with (NotFound, taken while the runner
/// still holds that answered call): named by the environment's `field` (`personal_vault`,
/// `personal_item`), which sets the title opv looked for; `set`: whether the field is set,
/// else opv looked for its default names and the Do says to set it.
fn missing(call: &Call, resource: ResourceRef, env_name: &str, field: &str, set: bool) -> Error {
    let path = DottedPath(vec![
        "environments".into(),
        env_name.to_string(),
        field.to_string(),
    ]);
    match crate::runner::take_unusable_reply(call) {
        Some(seen) => Cause::NotFound {
            system: System::OnePassword,
            resource,
            named_by: if set {
                NamedBy::ConfigField { path }
            } else {
                NamedBy::UnsetField { path }
            },
            state: NotFoundState::Missing,
            seen,
        }
        .into(),
        None => Cause::Bug {
            site: "personal: a listing the runner did not observe",
        }
        .into(),
    }
}

/// `e` naming the personal `keys` (product, key) the run needs when it says the person's
/// item or its vault is not set up (J6); any other failure as it is.
pub(crate) fn naming_keys(e: Error, env_name: &str, keys: &[(&str, &str)]) -> Error {
    if !not_set_up(&e) {
        return e;
    }
    let Error::Catalog(then, upstream) = e;
    Error::Catalog(
        Box::new(Cause::PersonalNotSetUp {
            env: crate::cause::EnvName::new(env_name),
            keys: keys
                .iter()
                .map(|(p, k)| crate::cause::ProductKey {
                    product: crate::cause::ProductName::new(*p),
                    key: crate::cause::KeyName::new(*k),
                })
                .collect(),
            then,
        }),
        upstream,
    )
}

/// Whether `e` says the personal item or its vault is not there (not set up yet), as
/// opposed to a sign-in or 1Password not answering.
fn not_set_up(e: &Error) -> bool {
    e.code_str() == "item_not_found"
        || matches!(
            e.cause(),
            Some((
                Cause::NotFound {
                    resource: ResourceRef {
                        kind: ResourceKind::PersonalVault,
                        ..
                    },
                    ..
                },
                _
            ))
        )
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
    // Audit 04.16: a missing personal item leaves the keys missing; any other failure (a
    // sign-in, 1Password not answering) is its own cause and is reported as such.
    let at = match locate(r, fleet, env_name, project) {
        Ok(Some(at)) => at,
        Ok(None) => return Ok(out),
        Err(e) if not_set_up(&e) => return Ok(out),
        Err(e) => return Err(e),
    };
    let team = fleet.environment(env_name)?;
    let item = match onepassword::read_whole(r, team, &at) {
        Ok(item) => item,
        Err(e) if e.code_str() == "item_not_found" => return Ok(out),
        Err(e) => return Err(e),
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
/// the personal item `at`, addressed by its IDs, never a team item's. A shared key points
/// at its source's field, exactly as its team counterpart would.
pub fn reference(at: &Boundary, product: &str, key: &str, spec: &KeySpec) -> String {
    let (p, k) = spec.source().unwrap_or((product, key));
    format!("op://{}/{}/{p}/{k}", at.vault_id, at.item_id)
}

/// Every `(section, label)` field a personal key claims: its source's when it is shared
/// (the value lives in the source key's field), else its own.
fn claimed_fields(fleet: &Fleet, env_name: &str) -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for (product, prod) in &fleet.products {
        for (key, spec) in &prod.keys {
            if !spec.personal || !spec.is_desired_in(env_name) {
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
pub(crate) fn personal_fleet(fleet: &Fleet, env_name: &str) -> Fleet {
    let mut out = fleet.clone();
    for prod in out.products.values_mut() {
        prod.keys
            .retain(|_, spec| spec.personal && spec.is_desired_in(env_name));
        // In the person's own item these are its ordinary keys: the convention lays them out
        // there like any other (it skips personal keys only in the team item).
        for spec in prod.keys.values_mut() {
            spec.personal = false;
        }
    }
    out.products.retain(|_, prod| !prod.keys.is_empty());
    out
}

#[cfg(test)]
#[path = "personal_tests.rs"]
mod tests;
