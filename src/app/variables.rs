//! The config channel of a staged target that delivers config itself (FR-46): named
//! variables next to its secrets. Config is never secret (FR-14), so the store reads its values back and
//! `status`, `plan` and `sync` compare them exactly.
//!
//! [`plan`] runs after the item plan, on the same rows: a ready config key of a delivered
//! product gets its target state (`present`, `would_change`, `absent`), or a failing rule
//! when the store would refuse it or its field is concealed (a variable is readable by
//! everyone with read access to the repository). `sync` then sets [`VarPlan::set`] and,
//! under `--prune`, removes [`VarPlan::prune`].

use std::collections::{BTreeMap, BTreeSet};

use crate::domain::rules::Reason;
use crate::domain::{Fleet, KeyState, Kind, SyncPlan, TargetState};
use crate::error::Error;
use crate::ports::VariableStore;
use crate::provider::TargetConfig;

/// Rule id of a config key kept in a concealed field, on a target that publishes config.
pub(crate) const CONCEALED_RULE: &str = "concealed-config";

/// Its fixed reason (FR-22): never the value.
pub(crate) const CONCEALED_REASON: &str = "its 1Password field is concealed, but this target \
     publishes config as plain variables that anyone who can read the target sees; make the \
     field a text field, or declare the key kind = \"secret\"";

/// What a sync does with the config channel. Names are runtime env names.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct VarPlan {
    /// Ready config keys this run delivers: name → desired value.
    pub want: BTreeMap<String, String>,
    /// Names in `want` whose variable is absent or differs.
    pub set: Vec<String>,
    /// Names in `want` whose variable already holds the value.
    pub unchanged: Vec<String>,
    /// Managed config names on the target that no key of this environment wants (FR-8).
    pub prune: Vec<String>,
}

/// Plans the config channel against `vars` and marks `plan`'s config rows (see the module
/// docs). `in_scope` limits writes and prunes to a product's names (`--product`, P20).
/// Every name is the target's own rendering; a product the environment does not deliver
/// (source-only, FR-47, or outside the target's scope, FR-48) is neither written nor pruned.
#[allow(clippy::too_many_arguments)]
pub(crate) fn plan(
    fleet: &Fleet,
    env_name: &str,
    target: &str,
    t: &dyn TargetConfig,
    plan: &mut SyncPlan,
    vars: &dyn VariableStore,
    in_scope: &dyn Fn(&str) -> bool,
) -> Result<VarPlan, Error> {
    let current = vars.list()?;
    let concealed: BTreeSet<(String, String)> = plan.concealed_config.iter().cloned().collect();
    let mut out = VarPlan::default();
    // Config names some key of this environment still claims (ready or blocked): never
    // pruned, so a failing rule never removes the value the app runs with.
    let mut claimed: BTreeSet<String> = BTreeSet::new();
    for row in &mut plan.rows {
        if row.kind != Kind::Config || !fleet.delivers(env_name, target, &row.product) {
            continue;
        }
        let name = t.env_name(&row.product, &row.key);
        if row.state != KeyState::Skipped {
            claimed.insert(name.clone());
        }
        if row.state != KeyState::Ready {
            continue;
        }
        let Some(value) = plan
            .config
            .get(&row.product)
            .and_then(|keys| keys.get(&row.key))
        else {
            continue;
        };
        let pair = (row.product.clone(), row.key.clone());
        if concealed.contains(&pair) {
            row.state = KeyState::RuleFailed(CONCEALED_RULE, Reason::Fixed(CONCEALED_REASON));
            // 01.01: refused here, so not delivered here: `concealed_config` lists only the
            // concealed config this target delivers as a plain value.
            plan.concealed_config.retain(|p| *p != pair);
            continue;
        }
        if let Some((rule, why)) = vars.refusal(&name, value) {
            row.state = KeyState::RuleFailed(rule, Reason::Fixed(why));
            continue;
        }
        row.target = match current.get(&name) {
            Some(v) if v == value => TargetState::Present,
            Some(_) => TargetState::WouldChange,
            None => TargetState::Absent,
        };
        if in_scope(&name) {
            match row.target {
                TargetState::Present => out.unchanged.push(name.clone()),
                _ => out.set.push(name.clone()),
            }
            out.want.insert(name, value.clone());
        }
    }
    let managed: BTreeSet<String> = fleet
        .products
        .iter()
        .filter(|(p, _)| fleet.delivers(env_name, target, p))
        .flat_map(|(p, prod)| {
            prod.keys
                .iter()
                .filter(|(_, spec)| spec.kind == Kind::Config)
                .map(move |(k, _)| t.env_name(p, k))
        })
        .collect();
    out.prune = current
        .keys()
        .filter(|n| managed.contains(*n) && !claimed.contains(*n) && in_scope(n))
        .cloned()
        .collect();
    Ok(out)
}

#[cfg(test)]
#[path = "variables_tests.rs"]
mod tests;
