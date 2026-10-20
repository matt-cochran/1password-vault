//! Retirement (design Part V, row `retire`; #179): needs at the deployed revision, prune by
//! tier, archive, then mark `retired`.
//!
//! `opv propose retire` has already marked the key `lifecycle = "retiring"` in the contract.
//! Two parts carry it out, split by who may write what (owner decision on #179: CI may prune
//! targets; only a person writes 1Password):
//!
//! - [`prune`], the prune step of one environment, is `opv sync <env> --prune --retire`: CI's
//!   (or a person's) delivery command in the one interface (§25), which reads 1Password and
//!   writes targets only. It refuses while the code at `HEAD` (the revision CI deploys)
//!   still reads a retiring key ([`Cause::RetireStillRead`], naming the files), refuses a
//!   production environment while a local or shared one still holds the key
//!   ([`crate::cause::Guard::RetireOutOfOrder`]), and leaves `confirm_env` to the sync's own
//!   guard (`confirm_required` before the first write). It never writes 1Password: no item,
//!   field or archive.
//! - [`retire`] hands a person's whole run the steps in order (prune each environment, every
//!   non-production tier before production, archive the 1Password fields, mark `retired`).
//!   The archive and the mark are a person's `opv apply`, never CI.
//!
//! Progress is the targets' own state, which every sync and `ready` already read: a prune
//! removes the key's name from the target, and a plain sync never adds a `retiring` key back
//! to a target that no longer holds it (`domain::plan`, row `retire-guard`). So a run that
//! stops part-way is resumed by running it again: an environment already pruned has nothing
//! left to prune, and `ready` lists a `retirement_incomplete` finding naming the steps that
//! remain ([`findings`]). No value, length, digest or prefix of one is carried anywhere here.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use serde::Serialize;

use crate::app::needs::{NeedState, needs};
use crate::app::ready::{EnvInput, Finding, Scope};
use crate::app::sync::SyncOpts;
use crate::cause::{Cause, EnvName, Guard, KeyName, ProductName, UsageProblem};
use crate::domain::{Fleet, Kind, Lifecycle, TargetState, Tier, key_label};
use crate::error::Error;
use crate::runner::CommandRunner;
use crate::scan::Revision;

/// One step of a retirement, handed to the caller in the order it is executed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetireStep {
    /// Prune the key's field from this environment's targets.
    Prune { env: String },
    /// Archive the key's 1Password field for this environment.
    Archive { env: String },
    /// Mark the key `lifecycle = "retired"` in the contract. Always last.
    MarkRetired,
}

impl RetireStep {
    /// The `PlanOptions::retiring_prune` value this step's sync runs with: only a
    /// [`RetireStep::Prune`] step may prune a `retiring` key (design Part V, row
    /// `retire-guard`); every other step, and a plain sync, keeps it.
    pub fn retiring_prune(&self) -> bool {
        matches!(self, RetireStep::Prune { .. })
    }
}

/// What a `retire` run handed the caller. Names only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RetireReport {
    pub product: String,
    pub key: String,
    /// The environments pruned this run, in tier order.
    pub pruned: Vec<String>,
    /// The environments archived this run, in tier order.
    pub archived: Vec<String>,
    /// True when the run reached the final [`RetireStep::MarkRetired`].
    pub retired: bool,
}

/// A retirement's tier order: every non-production tier before production.
fn tier_rank(tier: Tier) -> u8 {
    match tier {
        Tier::Production => 1,
        Tier::Local | Tier::Shared => 0,
    }
}

/// Retire `product`/`key` (design Part V, row `retire`): a person's whole run. `deployed` is
/// the caller's state: one entry per environment that still holds the key, `Some(revision)`
/// for the revision its code is deployed at and `None` when no receipt records one. Each
/// step goes to `steps` in order; the caller runs a [`RetireStep::Prune`] as [`prune`] does. Refuses with [`Cause::RetireStillRead`] before any step while an
/// environment's deployed code still reads the key, or while no receipt records the
/// revision its code was deployed at; nothing is pruned in that case. Never returns a
/// value, length, digest or prefix of one.
#[allow(clippy::too_many_arguments)] // the row's public signature, the caller wires each part
pub fn retire(
    fleet: &Fleet,
    r: &dyn CommandRunner,
    repo: &Path,
    product: &str,
    key: &str,
    deployed: &BTreeMap<String, Option<String>>,
    steps: &mut dyn FnMut(RetireStep) -> Result<(), Error>,
    out: &mut dyn Write,
) -> Result<RetireReport, Error> {
    // The environments that still hold the key, every non-production tier before
    // production, then by name: a stable order that makes the run reproducible. An
    // environment the contract does not declare defaults to `shared`.
    let mut envs: Vec<&String> = deployed.keys().collect();
    envs.sort_by(|a, b| {
        let tier = |name: &String| {
            fleet
                .environments
                .get(name.as_str())
                .map(|e| e.tier)
                .unwrap_or(Tier::Shared)
        };
        tier_rank(tier(a))
            .cmp(&tier_rank(tier(b)))
            .then_with(|| a.cmp(b))
    });

    // Refuse, before any step, while any environment's deployed code still reads the key
    // or no receipt records its revision. One pass, so a refusal prunes nothing.
    for env in &envs {
        let Some(rev) = deployed.get(env.as_str()).and_then(|r| r.as_deref()) else {
            return Err(Cause::RetireStillRead {
                key: KeyName::new(key),
                env: EnvName::new(env.as_str()),
                files: Vec::new(),
            }
            .into());
        };
        let report = needs(r, repo, &Revision(rev), fleet, None);
        if let Some(row) = report
            .rows
            .iter()
            .find(|row| row.name == key && row.state == NeedState::Declared)
        {
            return Err(Cause::RetireStillRead {
                key: KeyName::new(key),
                env: EnvName::new(env.as_str()),
                files: row.files.clone(),
            }
            .into());
        }
    }

    // Prune, archive, then mark `retired` last; the caller executes each step in turn.
    let mut report = RetireReport {
        product: product.to_string(),
        key: key.to_string(),
        pruned: Vec::new(),
        archived: Vec::new(),
        retired: false,
    };
    for env in &envs {
        steps(RetireStep::Prune {
            env: env.to_string(),
        })?;
        report.pruned.push((*env).clone());
    }
    for env in &envs {
        steps(RetireStep::Archive {
            env: env.to_string(),
        })?;
        report.archived.push((*env).clone());
    }
    steps(RetireStep::MarkRetired)?;
    report.retired = true;

    writeln!(
        out,
        "retire {product}/{key}: pruned {}; archived {}; marked retired",
        report.pruned.len(),
        report.archived.len()
    )
    .map_err(crate::app::write_err)?;
    Ok(report)
}

/// What the code reads, by declared key, as the needs scan sees it at one revision: the
/// `file:line` locations of each declared key it observes. `None`: the revision could not be
/// scanned (no repository), which refuses like a key still read.
pub struct Readers {
    files: Option<BTreeMap<String, Vec<String>>>,
}

impl Readers {
    /// The needs scan of the repository's `HEAD`: the revision a CI job deploys.
    pub fn at_head(r: &dyn CommandRunner, fleet: &Fleet) -> Self {
        let Some(repo) = crate::config_store::git_toplevel(r) else {
            return Self { files: None };
        };
        let report = needs(r, &repo, &Revision("HEAD"), fleet, None);
        Self::of(
            report
                .rows
                .into_iter()
                .filter(|row| row.state == NeedState::Declared)
                .map(|row| (row.name, row.files))
                .collect(),
        )
    }

    /// The scan's result as given: key → the files that read it.
    pub fn of(files: BTreeMap<String, Vec<String>>) -> Self {
        Self { files: Some(files) }
    }

    /// The files that still read `key`; empty when none does. `None` when the revision could
    /// not be scanned.
    fn reading(&self, key: &str) -> Option<Vec<String>> {
        self.files
            .as_ref()
            .map(|f| f.get(key).cloned().unwrap_or_default())
    }
}

/// The `retiring` keys present in `env_name`, as (product, key), within `product` when
/// given: the keys a `--retire` run releases to the prune.
pub fn retiring_keys(
    fleet: &Fleet,
    env_name: &str,
    product: Option<&str>,
) -> Vec<(String, String)> {
    fleet
        .products
        .iter()
        .filter(|(p, _)| product.is_none_or(|only| only == p.as_str()))
        .flat_map(|(p, prod)| {
            prod.keys
                .iter()
                .filter(|(_, spec)| {
                    spec.lifecycle == Lifecycle::Retiring && spec.is_desired_in(env_name)
                })
                .map(move |(k, _)| (p.clone(), k.clone()))
        })
        .collect()
}

/// The prune step of a retirement in `env_name` (#179): `opv sync <env> --prune --retire`.
///
/// In order, before any write: `--retire` needs `--prune` and cannot take `--expect-plan`
/// (no `opv plan` releases a retiring key, so no plan id covers it); every retiring key the
/// code still reads (`readers`) refuses with [`Cause::RetireStillRead`] naming the files; a
/// production environment refuses while a local or shared environment's target still holds
/// one of the keys ([`Guard::RetireOutOfOrder`]). Then the environment's own sync runs with
/// every retiring key released to the prune list; a `confirm_env` environment refuses there
/// without `--confirm` (`confirm_required`), before its first write. Reads 1Password and
/// writes targets only; never a 1Password item or field.
pub fn prune(
    fleet: &Fleet,
    env_name: &str,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
    opts: &SyncOpts,
    readers: &Readers,
) -> Result<(), Error> {
    check_flags(opts)?;
    fleet.environment(env_name)?;
    let keys = retiring_keys(fleet, env_name, opts.product.as_deref());
    for (_, key) in &keys {
        match readers.reading(key) {
            Some(files) if files.is_empty() => {}
            files => {
                return Err(Cause::RetireStillRead {
                    key: KeyName::new(key),
                    env: EnvName::new(env_name),
                    files: files.unwrap_or_default(),
                }
                .into());
            }
        }
    }
    check_order(fleet, env_name, &keys, r)?;
    if !opts.json {
        let labels: Vec<String> = keys.iter().map(|(p, k)| key_label(p, k)).collect();
        let line = if labels.is_empty() {
            format!("retire: no key is retiring in {env_name}")
        } else {
            format!(
                "retire: {env_name}: {} no longer read at HEAD; released to the prune",
                labels.join(", ")
            )
        };
        writeln!(out, "{line}").map_err(crate::app::write_err)?;
    }
    crate::app::sync::deliver(fleet, env_name, r, out, opts)
}

/// `--retire` needs `--prune` and cannot take `--expect-plan`: no `opv plan` releases a
/// retiring key, so no plan id covers one. Checked before any call.
pub(crate) fn check_flags(opts: &SyncOpts) -> Result<(), Error> {
    if !opts.prune {
        return Err(Cause::Usage {
            problem: UsageProblem::NeedsFlag {
                flag: "--retire".into(),
                needs: "--prune".into(),
            },
        }
        .into());
    }
    if opts.expect_plan.is_some() {
        return Err(Cause::Usage {
            problem: UsageProblem::ConflictsWith {
                a: "--retire".into(),
                b: "--expect-plan".into(),
            },
        }
        .into());
    }
    Ok(())
}

/// The tier order of a retirement (#179): a production environment is pruned only once no
/// local or shared environment's target still holds one of `keys`. A target this session
/// cannot read is noted, never guessed: the needs check already holds production back while
/// the code reads the key.
fn check_order(
    fleet: &Fleet,
    env_name: &str,
    keys: &[(String, String)],
    r: &dyn CommandRunner,
) -> Result<(), Error> {
    if keys.is_empty() || tier_rank(fleet.environment(env_name)?.tier) == 0 {
        return Ok(());
    }
    let mut earlier: Vec<(&String, &crate::domain::Environment)> = fleet
        .environments
        .iter()
        .filter(|(_, e)| tier_rank(e.tier) == 0)
        .collect();
    earlier.sort_by_key(|(name, e)| (e.order.unwrap_or(i64::MAX), (*name).clone()));
    for (name, env) in earlier {
        for target in env.targets.keys() {
            let held: Vec<&(String, String)> = keys
                .iter()
                .filter(|(p, k)| {
                    fleet.products[p].keys[k].is_desired_in(name) && fleet.delivers(name, target, p)
                })
                .collect();
            if held.is_empty() {
                continue;
            }
            let listed = crate::app::open_target(fleet, name, target, r)
                .and_then(|(_, ports)| ports.store().list());
            let listed = match listed {
                Ok(listed) => listed,
                Err(_) => {
                    r.note(&format!(
                        "retire: could not read {name}/{target} to see whether it still holds the retiring keys; run opv sync {name} --prune --retire there first if it does"
                    ));
                    continue;
                }
            };
            for (p, k) in held {
                let wanted = fleet.target_name(name, target, p, k);
                if listed.iter().any(|e| e.name == wanted) {
                    return Err(Cause::Guard {
                        guard: Guard::RetireOutOfOrder {
                            product: ProductName::new(p),
                            key: KeyName::new(k),
                            env: EnvName::new(env_name),
                            first: EnvName::new(name.as_str()),
                        },
                    }
                    .into());
                }
            }
        }
    }
    Ok(())
}

/// The step that finishes a retirement once no target holds the key: a person archives its
/// 1Password fields and marks it `retired` (owner decision on #179: never CI), by the
/// exact `opv apply <plan_id>` of its [`archive_plan`].
pub fn archive_step(fleet: &Fleet, product: &str, key: &str) -> String {
    format!("opv apply {}", archive_plan(fleet, product, key).plan_id)
}

/// Today's UTC date, `YYYY-MM-DD`: the date in an archived section's name.
pub fn today() -> String {
    crate::app::tidy::today()
}

/// The prefix of a retirement's plan id: `rp-` and 16 lowercase hex digits (64 bits), as a
/// structural plan's `sp-`. `opv apply` tells the two apart by it.
pub const PLAN_ID_PREFIX: &str = "rp-";

/// One boundary item a retirement's archive edits, by name and public id only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArchiveItem {
    pub environment: String,
    pub boundary: String,
    #[serde(skip)]
    pub(crate) ids: crate::domain::Boundary,
}

/// The person's last step of retiring `product/key` (#179): move its fields in every
/// boundary item that holds it into an archived section
/// ([`crate::domain::convention::archived_section`]), then mark it `retired`. Names and
/// public ids only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArchivePlan {
    pub plan_id: String,
    pub product: String,
    pub key: String,
    /// One per boundary item, each non-production tier before production, then by name;
    /// an item two environments share is listed once.
    pub items: Vec<ArchiveItem>,
}

/// The archive plan of `product/key`: every environment that declares it, whose boundary
/// for the product is bound. A shared (`from`) or personal key has no field of its own in a
/// team item, so its plan only marks it. The plan id is content-addressed over the key and
/// the items, so a contract change makes an old id stale.
pub fn archive_plan(fleet: &Fleet, product: &str, key: &str) -> ArchivePlan {
    let own_field = fleet
        .products
        .get(product)
        .and_then(|p| p.keys.get(key))
        .filter(|spec| spec.from.is_none() && !spec.personal);
    let boundary = fleet.boundary_of(product).to_string();
    let mut envs: Vec<(&String, &crate::domain::Environment)> = fleet
        .environments
        .iter()
        .filter(|(name, _)| own_field.is_some_and(|spec| spec.is_desired_in(name)))
        .collect();
    envs.sort_by_key(|(name, e)| (tier_rank(e.tier), (*name).clone()));
    let mut items: Vec<ArchiveItem> = Vec::new();
    for (name, env) in envs {
        let Some(Some(b)) = env.boundaries.get(&boundary) else {
            continue;
        };
        if items.iter().any(|i| i.ids == *b) {
            continue;
        }
        items.push(ArchiveItem {
            environment: name.clone(),
            boundary: boundary.clone(),
            ids: b.clone(),
        });
    }
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    hasher.update(format!("retire\n{}\n", key_label(product, key)).as_bytes());
    for i in &items {
        hasher.update(
            format!(
                "{}\t{}\t{}\t{}\n",
                i.environment, i.boundary, i.ids.vault_id, i.ids.item_id
            )
            .as_bytes(),
        );
    }
    let digest = hex::encode(hasher.finalize());
    ArchivePlan {
        plan_id: format!("{PLAN_ID_PREFIX}{}", &digest[..16]),
        product: product.to_string(),
        key: key.to_string(),
        items,
    }
}

/// The archive plan of every `retiring` key, by product then key.
pub fn archive_plans(fleet: &Fleet) -> Vec<ArchivePlan> {
    fleet
        .products
        .iter()
        .flat_map(|(p, prod)| {
            prod.keys
                .iter()
                .filter(|(_, spec)| spec.lifecycle == Lifecycle::Retiring)
                .map(move |(k, _)| (p, k))
        })
        .map(|(p, k)| archive_plan(fleet, p, k))
        .collect()
}

/// The CI syncs a retirement's archive leaves to run (#179): every environment with a target
/// that delivers a product whose boundary item is one of `edited` (the item ids the archive
/// moved fields in), in tier order then by name. The archive changed those items, so their
/// delivery evidence is older than the source until a sync records it again; this never
/// fakes that evidence. `--confirm <env>` where the environment asks for it.
pub fn resync_after_archive(fleet: &Fleet, edited: &[String]) -> Vec<String> {
    let mut envs: Vec<(&String, &crate::domain::Environment)> = fleet
        .environments
        .iter()
        .filter(|(name, env)| {
            env.targets.keys().any(|target| {
                fleet.products.keys().any(|product| {
                    fleet.delivers(name, target, product)
                        && fleet
                            .boundary(name, product)
                            .is_ok_and(|b| edited.contains(&b.item_id))
                })
            })
        })
        .collect();
    envs.sort_by_key(|(name, e)| (tier_rank(e.tier), (*name).clone()));
    envs.into_iter()
        .map(|(name, env)| {
            if env.confirm_env {
                format!("opv sync {name} --confirm {name}")
            } else {
                format!("opv sync {name}")
            }
        })
        .collect()
}

/// The environments, in the order a retirement prunes them, where a target still holds
/// `product/key` (its name is listed on the target): the prunes left before a person may
/// archive. A target this session cannot read counts as holding it (an archive is never
/// made on a guess) and is noted.
pub fn still_held(fleet: &Fleet, product: &str, key: &str, r: &dyn CommandRunner) -> Vec<String> {
    let Some(spec) = fleet.products.get(product).and_then(|p| p.keys.get(key)) else {
        return Vec::new();
    };
    let mut envs: Vec<(&String, &crate::domain::Environment)> = fleet
        .environments
        .iter()
        .filter(|(name, _)| spec.listed_in(name))
        .collect();
    envs.sort_by_key(|(name, e)| (tier_rank(e.tier), (*name).clone()));
    let mut holding = Vec::new();
    for (name, env) in envs {
        let held = env
            .targets
            .keys()
            .filter(|target| fleet.delivers(name, target, product))
            .any(|target| {
                let wanted = fleet.target_name(name, target, product, key);
                match crate::app::open_target(fleet, name, target, r)
                    .and_then(|(_, ports)| ports.store().list())
                {
                    Ok(listed) => listed.iter().any(|e| e.name == wanted),
                    Err(_) => {
                        r.note(&format!(
                            "retire: could not read {name}/{target} to see whether it still holds {}; counted as holding it",
                            key_label(product, key)
                        ));
                        true
                    }
                }
            });
        if held {
            holding.push(name.clone());
        }
    }
    holding
}

/// What archiving one boundary item did: how many of the key's fields it moved (0 when
/// every one was already archived, and no edit was made).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Archived {
    pub moved: usize,
}

/// Archive `product/key`'s fields in one boundary item (#179): one fresh read, then at most
/// one `op item edit` that moves every field the convention resolves to the key (its chosen
/// field and any duplicate) into `section`. A field already in an archived section is never
/// claimed by a key, so a re-run moves nothing and edits nothing. An item that is the
/// project's manifest, or that holds something a whole-item edit is not proven to keep
/// (I4), is never rewritten. Never reads, prints or changes a value.
pub fn archive_item(
    fleet: &Fleet,
    r: &dyn CommandRunner,
    product: &str,
    key: &str,
    item: &ArchiveItem,
    section: &str,
) -> Result<Archived, Error> {
    use crate::adapters::{onepassword, onepassword_tidy};
    let env = fleet.environment(&item.environment)?;
    let read = onepassword::read_whole_fresh(r, env, &item.ids)?;
    if crate::app::tidy::is_manifest(read.raw()) {
        return Err(Cause::Guard {
            guard: Guard::ArchiveNotRewritable {
                env: EnvName::new(&item.environment),
                holds: "the project's manifest".into(),
            },
        }
        .into());
    }
    let (layout, _) = onepassword_tidy::parse(read.raw())?;
    let part = crate::app::tidy::in_boundary(fleet, &item.boundary);
    let res = crate::domain::convention::resolve(&layout, &part);
    let id = (product.to_string(), key.to_string());
    let mut indices: Vec<usize> = res.chosen.get(&id).copied().into_iter().collect();
    indices.extend(res.duplicates.get(&id).into_iter().flatten().copied());
    indices.sort_unstable();
    if indices.is_empty() {
        return Ok(Archived { moved: 0 });
    }
    if let Some(what) = onepassword_tidy::unprovable(read.raw()) {
        return Err(Cause::Guard {
            guard: Guard::ArchiveNotRewritable {
                env: EnvName::new(&item.environment),
                holds: what.into(),
            },
        }
        .into());
    }
    onepassword::archive_fields(r, env, &item.ids, &read, &indices, section)?;
    Ok(Archived {
        moved: indices.len(),
    })
}

/// Whether a row's target still holds its secret: anything but `absent` (a staged store
/// that shows no digest reports a held name as `unknown`). A config key's target state is
/// never known, so only its last step is listed.
fn holds(row: &crate::domain::Row) -> bool {
    row.kind == Kind::Secret
        && matches!(
            row.target,
            TargetState::Present | TargetState::WouldChange | TargetState::Unknown
        )
}

/// [`findings`] for a `ready` that read only `only` (when given). That read sees no other
/// environment's target, so it cannot know a retirement's remaining steps: it lists only
/// the prune `only` itself still needs, never a remaining-steps list built from one
/// environment (which said only the person's archive was left while other environments
/// still held the key).
pub fn findings_scoped(fleet: &Fleet, envs: &[EnvInput], only: Option<&str>) -> Vec<Finding> {
    let mut out = findings(fleet, envs);
    if let Some(only) = only {
        out.retain(|f| f.scope.environment.as_deref() == Some(only));
    }
    out
}

/// `ready`'s `retirement_incomplete` findings (#179): one per `retiring` key, naming the
/// steps that remain in order. Each environment whose target still holds the key
/// ([`holds`]) is pruned first, local and shared before production, by
/// `opv sync <env> --prune --retire` (CI may run it); then a person archives the fields and
/// marks the key retired. Never blocking. Names only.
pub fn findings(fleet: &Fleet, envs: &[EnvInput]) -> Vec<Finding> {
    let mut out = Vec::new();
    for (product, prod) in &fleet.products {
        for (key, spec) in &prod.keys {
            if spec.lifecycle != Lifecycle::Retiring {
                continue;
            }
            let mut holding: Vec<&str> = envs
                .iter()
                .filter(|env| {
                    env.target.iter().flatten().any(|t| {
                        t.rows.as_ref().is_ok_and(|rows| {
                            rows.iter()
                                .any(|row| &row.product == product && &row.key == key && holds(row))
                        })
                    })
                })
                .map(|env| env.name.as_str())
                .collect();
            holding.sort_by_key(|name| {
                fleet
                    .environments
                    .get(*name)
                    .map_or(0, |e| tier_rank(e.tier))
            });
            let mut steps: Vec<String> = holding
                .iter()
                .map(|env| format!("prune from {env} (opv sync {env} --prune --retire)"))
                .collect();
            steps.push(format!(
                "a person archives its 1Password fields and marks it retired ({})",
                archive_step(fleet, product, key)
            ));
            let (actor, effect, prerequisite) = match holding.first() {
                Some(env) => (
                    "ci",
                    "writes_target",
                    format!("opv sync {env} --prune --retire"),
                ),
                None => (
                    "owner",
                    "writes_1password",
                    archive_step(fleet, product, key),
                ),
            };
            out.push(Finding {
                code: "retirement_incomplete".into(),
                scope: Scope {
                    environment: holding.first().map(|e| e.to_string()),
                    product: Some(product.clone()),
                    key: Some(key.clone()),
                    ..Scope::default()
                },
                blocking: false,
                actor: actor.into(),
                effect: effect.into(),
                prerequisite,
                verify: "opv ready --json".into(),
                message: Some(format!(
                    "the retirement of {} is not finished; remaining: {}",
                    key_label(product, key),
                    steps.join("; then ")
                )),
                act: None,
            });
        }
    }
    out
}

#[cfg(test)]
#[path = "retire_tests.rs"]
mod tests;
