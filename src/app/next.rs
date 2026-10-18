//! `opv next` (design Part V, row `next-cmd`): the one action this session can take,
//! chosen by a fixed priority, then the queue of further actions, then what waits on
//! others, grouped by vault. A deployed-tier vault with one writer is a `single_writer`
//! finding.
//!
//! Pure and deterministic: the same [`Inventory`] and [`Signals`] give byte-identical
//! output. The document carries names and commands only: never a value, length or digest
//! (SR-1).
//!
//! Priority, highest first: (1) an unbound boundary asks for `opv apply` (person); (2) a
//! present key `absent` in a vault this session can write asks for `opv set` (person,
//! `enter_value`); (3) `empty`, (4) `placeholder` and (5) `malformed` do the same; (6) a
//! `set` key whose delivery is stale asks for `opv sync` (`run`, CI when the environment is
//! deployed, else the person); (7) nothing, `none`. An action on a vault whose capability
//! is `read`, `none` or `unknown` waits on others, with the vault named.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::{Value, json};

use crate::domain::capability::Capability;
use crate::domain::inventory::Inventory;
use crate::domain::model::Tier;
use crate::domain::value_state::ValueState;
use crate::json::{NextActor, NextKind};

/// What the caller read beyond the inventory: which cells have current delivery evidence
/// and how many writers each vault has. Value-free (SR-1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Signals {
    /// `(product, key, env)` cells whose delivery evidence is current. A `set` cell not in
    /// this set is stale and asks for `opv sync`. A cell no target of its environment
    /// delivers belongs here (`inventory::gather_for_next`): it has nothing to sync to.
    pub delivered: BTreeSet<(String, String, String)>,
    /// Vault id → the number of writers 1Password reports. A vault absent here is not
    /// judged, so no `single_writer` finding is raised for it.
    pub writers: BTreeMap<String, usize>,
}

/// One action in a `next` document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Action {
    pub kind: NextKind,
    pub actor: NextActor,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,
}

/// Actions that wait on another session's capability, for one vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WaitsOn {
    pub vault: String,
    pub actions: Vec<Action>,
}

/// One advisory finding of a `next` document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub code: &'static str,
    pub env: String,
    pub vault: String,
    pub message: String,
}

/// The `opv next` document.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct NextDoc {
    pub next: Option<Action>,
    pub queue: Vec<Action>,
    pub waits_on: Vec<WaitsOn>,
    pub findings: Vec<Finding>,
}

impl NextDoc {
    /// The schema-3 JSON document: `next` is the typed `{kind, actor, command}` object,
    /// `queue` and `waits_on` carry the further actions and the ones waiting on others,
    /// and `findings` the advisory findings. Deterministic for equal inputs.
    pub fn document(&self) -> Value {
        json!({
            "next": self
                .next
                .as_ref()
                .map_or_else(no_action, action_next),
            "queue": self.queue.iter().map(action_value).collect::<Vec<_>>(),
            "waits_on": self
                .waits_on
                .iter()
                .map(|w| {
                    json!({
                        "vault": w.vault,
                        "actions": w.actions.iter().map(action_value).collect::<Vec<_>>(),
                    })
                })
                .collect::<Vec<_>>(),
            "findings": self.findings,
        })
    }
}

/// The schema-3 `next` for an action: kind, actor and the exact command only.
fn action_next(a: &Action) -> Value {
    json!({"kind": a.kind, "actor": a.actor, "command": a.command})
}

/// The schema-3 `next` when there is nothing to do: `kind = none`, the person, no command.
fn no_action() -> Value {
    json!({"kind": NextKind::None, "actor": NextActor::Person, "command": null})
}

/// One action as the full JSON object (its vault and cell names too).
fn action_value(a: &Action) -> Value {
    serde_json::to_value(a).expect("an action serializes")
}

/// The `opv next` document for `inv`: the fixed-priority action this session can take, the
/// queue of the rest, what waits on others by vault, and the `single_writer` findings.
pub fn next(inv: &Inventory, signals: &Signals) -> NextDoc {
    let mut mine: Vec<(u8, Action)> = Vec::new();
    let mut waiting: Vec<(u8, Action)> = Vec::new();

    // Rank 1: a declared, unbound boundary is always this session's to surface, because
    // `opv apply` (person) is what binds it and no vault capability gates it yet.
    for env in &inv.environments {
        for bound in env.boundaries.values() {
            if bound.is_none() {
                mine.push((
                    1,
                    Action {
                        kind: NextKind::Apply,
                        actor: NextActor::Person,
                        command: "opv apply".to_string(),
                        product: None,
                        key: None,
                        env: Some(env.env.clone()),
                        vault: None,
                    },
                ));
            }
        }
    }

    // Ranks 2-6: one candidate per cell, in the inventory's stable order.
    for cell in &inv.cells {
        let rank = match &cell.state {
            ValueState::Absent => 2,
            ValueState::Empty => 3,
            ValueState::Placeholder => 4,
            ValueState::Malformed { .. } => 5,
            ValueState::Set
                if !signals.delivered.contains(&(
                    cell.product.clone(),
                    cell.key.clone(),
                    cell.env.clone(),
                )) =>
            {
                6
            }
            _ => continue,
        };
        let vault = vault_of(inv, &cell.env, &cell.boundary);
        let action = match rank {
            6 => Action {
                kind: NextKind::Run,
                actor: if deployed(tier_of(inv, &cell.env)) {
                    NextActor::Ci
                } else {
                    NextActor::Person
                },
                command: format!("opv sync {}", cell.env),
                product: Some(cell.product.clone()),
                key: Some(cell.key.clone()),
                env: Some(cell.env.clone()),
                vault: vault.clone(),
            },
            _ => Action {
                kind: NextKind::EnterValue,
                actor: NextActor::Person,
                command: format!("opv set {}/{} --env {}", cell.product, cell.key, cell.env),
                product: Some(cell.product.clone()),
                key: Some(cell.key.clone()),
                env: Some(cell.env.clone()),
                vault,
            },
        };
        if cell.capability == Capability::Write {
            mine.push((rank, action));
        } else {
            waiting.push((rank, action));
        }
    }

    // Stable sort keeps the inventory order within one rank.
    mine.sort_by_key(|(rank, _)| *rank);
    waiting.sort_by_key(|(rank, _)| *rank);

    let next = mine.first().map(|(_, a)| a.clone());
    let queue = mine.into_iter().skip(1).map(|(_, a)| a).collect();

    let mut groups: BTreeMap<String, Vec<Action>> = BTreeMap::new();
    for (_, action) in waiting {
        let vault = action
            .vault
            .clone()
            .unwrap_or_else(|| "unbound".to_string());
        groups.entry(vault).or_default().push(action);
    }
    let waits_on = groups
        .into_iter()
        .map(|(vault, actions)| WaitsOn { vault, actions })
        .collect();

    NextDoc {
        next,
        queue,
        waits_on,
        findings: single_writer(inv, signals),
    }
}

/// The vault id a cell's environment binds its boundary to; `None` while it is unbound.
fn vault_of(inv: &Inventory, env: &str, boundary: &str) -> Option<String> {
    inv.environments
        .iter()
        .find(|e| e.env == env)
        .and_then(|e| e.boundaries.get(boundary))
        .and_then(Option::as_ref)
        .map(|b| b.vault_id.clone())
}

/// The tier of an environment; `shared` when the inventory does not name it (never guessed
/// to be `local`, which is the only tier that changes the actor).
fn tier_of(inv: &Inventory, env: &str) -> Tier {
    inv.environments
        .iter()
        .find(|e| e.env == env)
        .map_or(Tier::Shared, |e| e.tier)
}

/// A deployed tier: `shared` or `production`, never `local`.
fn deployed(tier: Tier) -> bool {
    matches!(tier, Tier::Shared | Tier::Production)
}

/// One `single_writer` finding per deployed-tier vault whose user list reports exactly one
/// writer. A vault the inventory does not mention, or whose writer count was not read, is
/// not judged. Names and a count only, never a person (SR-1).
fn single_writer(inv: &Inventory, signals: &Signals) -> Vec<Finding> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for env in &inv.environments {
        if !deployed(env.tier) {
            continue;
        }
        for bound in env.boundaries.values() {
            let Some(ids) = bound else {
                continue;
            };
            if !seen.insert(ids.vault_id.clone()) {
                continue;
            }
            if signals.writers.get(&ids.vault_id).copied() == Some(1) {
                out.push(Finding {
                    code: "single_writer",
                    env: env.env.clone(),
                    vault: ids.vault_id.clone(),
                    message: format!(
                        "vault {} (environment {}) is deployed and has one writer; a second \
                         writer is needed for emergencies",
                        ids.vault_id, env.env
                    ),
                });
            }
        }
    }
    out
}

/// The human text of a `next` document: the one action first, then the queue, then what
/// waits on others by vault, then the findings. Names and commands only (SR-1).
pub fn render_text(doc: &NextDoc) -> String {
    let mut out = String::new();
    match &doc.next {
        Some(a) => {
            out.push_str("next: ");
            out.push_str(&a.command);
            out.push('\n');
        }
        None => out.push_str("next: none\n"),
    }
    if !doc.queue.is_empty() {
        out.push_str("then:\n");
        for a in &doc.queue {
            out.push_str("  ");
            out.push_str(&a.command);
            out.push('\n');
        }
    }
    if !doc.waits_on.is_empty() {
        out.push_str("waiting on others:\n");
        for w in &doc.waits_on {
            out.push_str("  vault ");
            out.push_str(&w.vault);
            out.push_str(":\n");
            for a in &w.actions {
                out.push_str("    ");
                out.push_str(&a.command);
                out.push('\n');
            }
        }
    }
    if !doc.findings.is_empty() {
        out.push_str("findings:\n");
        for f in &doc.findings {
            out.push_str("  ");
            out.push_str(f.code);
            out.push_str(": ");
            out.push_str(&f.message);
            out.push('\n');
        }
    }
    out
}

#[cfg(test)]
#[path = "next_tests.rs"]
mod tests;
