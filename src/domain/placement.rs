//! Load-time check that delivery evidence is never readable more widely than the values it
//! covers (FR-58, S6; `docs/design/placements-and-access-boundaries.md` §6.3).
//!
//! Pure: [`wider_than_values`] groups targets by state vault and reports, for each target,
//! every boundary another target of the same vault reads and it does not. Evidence lets its
//! reader test guesses against values, so it must not be readable more widely than them.
//! Findings and [`WiderThanValues::sentence`] carry names and boundary ids only: never a
//! value, secret, digest or fingerprint (SR-1).

use std::collections::{BTreeMap, BTreeSet};

/// Error code for a state vault shared by targets that read different boundaries (FR-58).
pub const STATE_VAULT_WIDER_THAN_VALUES: &str = "state_vault_wider_than_values";

/// One target: its environment, name, state vault and the boundaries its deploy identity
/// reads.
pub struct TargetReads<'a> {
    pub environment: &'a str,
    pub target: &'a str,
    pub state_vault_id: &'a str,
    pub boundaries: std::collections::BTreeSet<&'a str>,
}

/// One state vault that is wider than the values its targets read: `target` cannot read
/// `unreadable_boundary`, which another target sharing `state_vault_id` reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WiderThanValues {
    pub state_vault_id: String,
    /// The group's targets as `<environment>/<target>`, sorted.
    pub targets: Vec<String>,
    pub environment: String,
    pub target: String,
    pub unreadable_boundary: String,
}

/// Reports every target whose state vault holds evidence for a boundary it cannot read.
///
/// Targets are grouped by `state_vault_id`; a group with one target yields nothing. In a
/// group of two or more, each target that cannot read a boundary read by another target of
/// the group yields one finding. The result is sorted by `(state_vault_id, target,
/// unreadable_boundary)` and carries no duplicates (FR-58).
pub fn wider_than_values(targets: &[TargetReads<'_>]) -> Vec<WiderThanValues> {
    let mut by_vault: BTreeMap<&str, Vec<&TargetReads<'_>>> = BTreeMap::new();
    for target in targets {
        by_vault
            .entry(target.state_vault_id)
            .or_default()
            .push(target);
    }

    let mut out = Vec::new();
    for (state_vault_id, group) in by_vault {
        if group.len() < 2 {
            continue;
        }
        let mut group_boundaries = BTreeSet::new();
        for target in &group {
            group_boundaries.extend(target.boundaries.iter().copied());
        }
        let mut names: Vec<String> = group
            .iter()
            .map(|t| format!("{}/{}", t.environment, t.target))
            .collect();
        names.sort();
        for target in &group {
            for boundary in group_boundaries.difference(&target.boundaries) {
                out.push(WiderThanValues {
                    state_vault_id: state_vault_id.to_string(),
                    targets: names.clone(),
                    environment: target.environment.to_string(),
                    target: target.target.to_string(),
                    unreadable_boundary: (*boundary).to_string(),
                });
            }
        }
    }

    out.sort_by(|a, b| {
        (
            &a.state_vault_id,
            &a.environment,
            &a.target,
            &a.unreadable_boundary,
        )
            .cmp(&(
                &b.state_vault_id,
                &b.environment,
                &b.target,
                &b.unreadable_boundary,
            ))
    });
    out.dedup();
    out
}

impl WiderThanValues {
    /// The owner-facing message naming the vault, the targets and the unreadable boundary,
    /// with the command that gives the target its own state vault (FR-58, §6.3).
    pub fn sentence(&self) -> String {
        format!(
            "state vault {} is shared by targets {}, but {}/{} cannot read boundary {}; that \
             target's deploy identity would read evidence for values it cannot read. Give each \
             target its own state vault: delete state_vault_id from \
             [environments.{}.targets.{}] and run opv bootstrap.",
            self.state_vault_id,
            self.targets.join(", "),
            self.environment,
            self.target,
            self.unreadable_boundary,
            self.environment,
            self.target,
        )
    }
}

#[cfg(test)]
#[path = "placement_tests.rs"]
mod tests;
