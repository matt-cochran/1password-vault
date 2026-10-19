//! Retirement (design Part V, row `retire`): needs at the deployed revision, prune by
//! tier, archive, then mark `retired`.
//!
//! Library only: `opv propose retire` has already marked the key `lifecycle = "retiring"`
//! in the contract. `retire` refuses while the code deployed at an environment's revision
//! still reads the key, then hands the caller the steps in order through `steps`: prune the
//! environments that still hold the key (every non-production tier before production),
//! archive their 1Password fields, and mark the key `retired` last. The caller executes
//! each step (the CLI wires [`RetireStep::Prune`] to the existing `sync --prune` path), so
//! a run that stops part-way is resumed by calling `retire` again with a `deployed` map
//! that no longer lists the environments already pruned.
//!
//! `deployed` is the caller's state: one entry per environment that still holds the key,
//! `Some(revision)` for the revision its code is deployed at and `None` when no receipt
//! records one. Names and `file:line` only: no value, length, digest or prefix of a value
//! is carried anywhere here.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use serde::Serialize;

use crate::app::needs::{NeedState, needs};
use crate::cause::{Cause, EnvName, KeyName};
use crate::domain::{Fleet, Tier};
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

/// Retire `product`/`key` (design Part V, row `retire`). See the module docs for `deployed`
/// and `steps`. Refuses with [`Cause::RetireStillRead`] before any step while an
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

#[cfg(test)]
#[path = "retire_tests.rs"]
mod tests;
