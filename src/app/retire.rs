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
/// 1Password fields and marks it `retired` (owner decision on #179: never CI).
fn archive_step(product: &str, key: &str) -> String {
    format!("opv propose retire {}", key_label(product, key))
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
                archive_step(product, key)
            ));
            let (actor, effect, prerequisite) = match holding.first() {
                Some(env) => (
                    "ci",
                    "writes_target",
                    format!("opv sync {env} --prune --retire"),
                ),
                None => ("owner", "writes_1password", archive_step(product, key)),
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
