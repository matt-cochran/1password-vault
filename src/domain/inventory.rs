//! Inventory document (design Part V, row `inventory-doc`): keys × environments as a pure
//! value document. No I/O: the caller reads each cell's state and each vault's capability,
//! and this module folds them into a stable, serializable matrix.
//!
//! A cell carries the value state (never a value, length or digest, SR-1), the capability
//! this session has on the vault that holds it, and — for a vault the session cannot read
//! (`capability = none`) — the state the newest receipt recorded, with that receipt's age.
//! A key the contract does not want in an environment is `not_wanted` whatever was read.
//! Order is stable: products, keys and environments in name order (the [`Fleet`] maps are
//! `BTreeMap`s).

use std::collections::BTreeMap;

use serde::Serialize;

use super::capability::{Capability, UnknownSource};
use super::model::{Fleet, Kind, Lifecycle, Tier, ValueSource};
use super::presence::{Presence, present_in};
use super::value_state::ValueState;

/// The live inputs the builder folds into an [`Inventory`]: what session read for each cell
/// and what it can do with each vault. Names, states and capabilities only — never a value.
#[derive(Debug, Clone, Default)]
pub struct CellInputs {
    /// `(product, key, env)` → the live value state read for that cell. A cell with no entry
    /// is [`ValueState::Absent`].
    pub states: BTreeMap<(String, String, String), ValueState>,
    /// Vault id → what this session can do with that vault ([`Capability`]). A vault with no
    /// entry is `unknown` rather than guessed.
    pub capabilities: BTreeMap<String, Capability>,
}

/// The newest saved receipt as the builder needs it: the value state it recorded for the
/// cells a session could not read itself, when it was generated and how old it is. Value-free
/// (states and integers only).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReceiptView {
    /// `(product, key, env)` → the state the receipt recorded for that cell.
    pub states: BTreeMap<(String, String, String), ValueState>,
    /// The receipt's RFC 3339 UTC `generated_at`.
    pub generated_at: String,
    /// Whole seconds between `generated_at` and now; `None` when it was not an opv stamp.
    pub age_seconds: Option<u64>,
}

/// The vault and item ids of one bound boundary, as the document shows them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BoundaryIds {
    pub vault_id: String,
    pub item_id: String,
}

/// The receipt a substituted cell's state came from: when it was generated and its age.
/// A time and a count, never a value (SR-1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReceiptUse {
    pub generated_at: String,
    pub age_seconds: Option<u64>,
}

/// A key's presence in one environment, from [`present_in`]. Serialized snake_case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceView {
    Present,
    NotWanted { reason: String },
    Absent,
}

impl From<Presence> for PresenceView {
    fn from(presence: Presence) -> Self {
        match presence {
            Presence::Present => Self::Present,
            Presence::NotWanted { reason } => Self::NotWanted { reason },
            Presence::Absent => Self::Absent,
        }
    }
}

/// One environment column: its name, its tier and each declared boundary with its ids, or
/// `null` while it is declared and not bound yet (D-G, before the first `opv apply`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnvironmentColumn {
    pub env: String,
    pub tier: Tier,
    pub boundaries: BTreeMap<String, Option<BoundaryIds>>,
}

/// One key row: the key's attributes. `presence` is per environment, from the contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyRow {
    pub product: String,
    pub key: String,
    pub kind: String,
    pub source: Option<String>,
    pub presence: BTreeMap<String, PresenceView>,
    pub lifecycle: String,
    pub expires: Option<String>,
}

/// One cell of the matrix: the state of one key in one environment, the capability on the
/// vault that holds it, and (when the session cannot read it) the receipt the state came
/// from. `boundary` names the row of the environment's `boundaries` it belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Cell {
    pub product: String,
    pub key: String,
    pub env: String,
    pub boundary: String,
    pub state: ValueState,
    pub capability: Capability,
    pub from_receipt: Option<ReceiptUse>,
}

/// The inventory document: the environment columns, the key rows and the cells, each in
/// product, key, environment name order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Inventory {
    pub environments: Vec<EnvironmentColumn>,
    pub keys: Vec<KeyRow>,
    pub cells: Vec<Cell>,
}

/// Build the inventory of `fleet` from the live `cells` and, for environments whose vault
/// this session cannot read, the newest `receipt`.
///
/// The capability of a cell is the capability of its product's boundary vault in that
/// environment. A cell whose capability is exactly [`Capability::None`] (the session is not
/// a member) takes its state from `receipt` when the receipt recorded one, with the receipt's
/// age; otherwise the live state is used. A `not_wanted` key is `not_wanted` from the
/// contract, never from a read.
pub fn build(fleet: &Fleet, cells: &CellInputs, receipt: Option<&ReceiptView>) -> Inventory {
    let environments: Vec<EnvironmentColumn> = fleet
        .environments
        .iter()
        .map(|(env, e)| EnvironmentColumn {
            env: env.clone(),
            tier: e.tier,
            boundaries: e
                .boundaries
                .iter()
                .map(|(name, bound)| {
                    (
                        name.clone(),
                        bound.as_ref().map(|b| BoundaryIds {
                            vault_id: b.vault_id.clone(),
                            item_id: b.item_id.clone(),
                        }),
                    )
                })
                .collect(),
        })
        .collect();

    let mut keys = Vec::new();
    let mut matrix = Vec::new();
    for (product, p) in &fleet.products {
        for (key, spec) in &p.keys {
            let boundary = fleet.boundary_of(product).to_string();
            let mut presence = BTreeMap::new();
            for (env, e) in &fleet.environments {
                let here = present_in(spec, env);
                presence.insert(env.clone(), PresenceView::from(here.clone()));

                let capability = e
                    .boundaries
                    .get(&boundary)
                    .and_then(Option::as_ref)
                    .and_then(|b| cells.capabilities.get(&b.vault_id).copied())
                    .unwrap_or(Capability::Unknown {
                        source: UnknownSource::NoPermissionsInReply,
                    });

                let at = || (product.clone(), key.clone(), env.clone());
                let live = || {
                    cells
                        .states
                        .get(&at())
                        .cloned()
                        .unwrap_or(ValueState::Absent)
                };
                // A vault this session cannot read, with no receipt state: unreadable, never
                // absent (a failed read is never absence).
                let unread = || ValueState::Unreadable {
                    cause: crate::domain::value_state::UnreadableCause::NoAccess,
                };
                let (state, from_receipt) = match here {
                    Presence::NotWanted { reason } => (ValueState::NotWanted { reason }, None),
                    _ if capability == Capability::None => match receipt {
                        Some(r) => match r.states.get(&at()) {
                            Some(state) => (
                                state.clone(),
                                Some(ReceiptUse {
                                    generated_at: r.generated_at.clone(),
                                    age_seconds: r.age_seconds,
                                }),
                            ),
                            None => (unread(), None),
                        },
                        None => (unread(), None),
                    },
                    _ => (live(), None),
                };

                matrix.push(Cell {
                    product: product.clone(),
                    key: key.clone(),
                    env: env.clone(),
                    boundary: boundary.clone(),
                    state,
                    capability,
                    from_receipt,
                });
            }
            keys.push(KeyRow {
                product: product.clone(),
                key: key.clone(),
                kind: kind_word(spec.kind).to_string(),
                source: spec.value_source.map(|s| source_word(s).to_string()),
                presence,
                lifecycle: lifecycle_word(spec.lifecycle).to_string(),
                expires: spec.expires.map(|d| d.to_string()),
            });
        }
    }

    Inventory {
        environments,
        keys,
        cells: matrix,
    }
}

/// The document's word for a key kind.
fn kind_word(kind: Kind) -> &'static str {
    match kind {
        Kind::Secret => "secret",
        Kind::Config => "config",
    }
}

/// The document's word for a key's value source.
fn source_word(source: ValueSource) -> &'static str {
    match source {
        ValueSource::Person => "person",
        ValueSource::Generated => "generated",
        ValueSource::Derived => "derived",
    }
}

/// The document's word for a key's lifecycle.
fn lifecycle_word(lifecycle: Lifecycle) -> &'static str {
    match lifecycle {
        Lifecycle::Active => "active",
        Lifecycle::Retiring => "retiring",
        Lifecycle::Retired => "retired",
    }
}

#[cfg(test)]
#[path = "inventory_tests.rs"]
mod tests;
