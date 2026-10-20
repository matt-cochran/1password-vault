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
use super::model::{Fleet, KeySpec, Kind, Lifecycle, Rules, Tier, ValueSource};
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
    /// `(product, key, env)` → the vault that holds the cell when it is not the product's
    /// boundary vault: a personal key's own item (FR-55). Its capability is that vault's.
    pub vaults: BTreeMap<(String, String, String), String>,
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
/// The declared attributes added below (immutable, allow_same_value, `rules` names,
/// guidance, roles, file and the target names) are omitted while unset, so a key that
/// declares none renders exactly as before. Names only: a rule's parameter, guidance text
/// and a target name are never a value (SR-1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyRow {
    pub product: String,
    pub key: String,
    pub kind: String,
    pub source: Option<String>,
    pub presence: BTreeMap<String, PresenceView>,
    pub lifecycle: String,
    pub expires: Option<String>,
    /// Staged only when absent on the target unless explicitly rotated (FR-16).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub immutable: bool,
    /// The same value in several environments is intended (#92).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub allow_same_value: bool,
    /// The names of the validation rules the key declares (`prefix`, `regex`, `enum`, …),
    /// never a rule's parameters ([`rule_names`]).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<String>,
    /// The declared guidance for a person (FR-15): a provider and where the value lives.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub guidance: String,
    /// The process roles the key is delivered to under `opv run` (#136); `None`: every role.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
    /// A local file key's relative path (#136); `None`: delivered as a variable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Each target that delivers this key, as `"<env>/<target>"` → the name the target
    /// delivers it under ([`Fleet::target_name`], [`target_names`]). Names only.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub targets: BTreeMap<String, String>,
    /// Each target that delivers this key, as `"<env>/<target>"` → the delivery state of the
    /// key's name there ([`delivery_state`], #174): from that placement's evidence line for
    /// the name, never from a value. Empty until the caller reads the evidence.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub delivery: BTreeMap<String, DeliveryState>,
}

/// The delivery state of one key's name on one target (#174), from the placement's
/// evidence line for that name. A closed set of words; never a value, version or digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryState {
    /// opv wrote or proved the name (a `v1` line) and nothing newer is known.
    Delivered,
    /// A person attested the name (an `a1` line, #201): unchanged since attested, not proven.
    Attested,
    /// The name holds a value supplied to `opv sync --supply-stdin` (#206), not a 1Password one.
    Supplied,
    /// No evidence line for the name (no delivery item, or a line opv cannot read as
    /// evidence: another format tag is never counted as proven).
    NotDelivered,
    /// The line is older than what it should vouch for: another source field, another store
    /// version than the target lists, or a source item edited since the last sync.
    Stale,
    /// The placement's delivery item could not be read: neither delivered nor not delivered.
    Unreadable,
}

impl DeliveryState {
    /// The document's word for the state, as JSON serializes it.
    pub fn word(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::Attested => "attested",
            Self::Supplied => "supplied",
            Self::NotDelivered => "not_delivered",
            Self::Stale => "stale",
            Self::Unreadable => "unreadable",
        }
    }
}

/// A placement's delivery item that could not be read. Like
/// [`super::value_state::ReadError`], it has no conversion to a [`DeliveryState`], to
/// [`PlacementEvidence`] or to an `Option`, so a failed read can only become
/// [`DeliveryState::Unreadable`] through [`delivery_state`], never `delivered` or
/// `not_delivered` (the compile-fail doctests below prove it).
///
/// ```
/// use opv::domain::inventory::{DeliveryState, EvidenceUnreadable, delivery_state};
/// let e = EvidenceUnreadable::new();
/// let state = delivery_state(Err(&e), "API_KEY", None, &Default::default(), None);
/// assert_eq!(state, DeliveryState::Unreadable);
/// ```
///
/// ```compile_fail
/// use opv::domain::inventory::{DeliveryState, EvidenceUnreadable};
/// let _s: DeliveryState = EvidenceUnreadable::new().into();
/// ```
///
/// ```compile_fail
/// use opv::domain::inventory::{EvidenceUnreadable, PlacementEvidence};
/// let _o: Option<PlacementEvidence> = EvidenceUnreadable::new().into();
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EvidenceUnreadable {
    _read_failed: (),
}

impl EvidenceUnreadable {
    /// A delivery item read that failed.
    pub fn new() -> Self {
        Self::default()
    }
}

/// How one evidence line was recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceKind {
    /// opv's own write or proof (`v1`).
    Proven,
    /// A person's attestation (`a1`, #201).
    Attested,
    /// A supplied value (#206).
    Supplied,
}

/// One name's evidence line as the inventory needs it: how it was recorded, the 1Password
/// field it vouches for and the store version it was recorded at. Not serializable: the
/// store version never leaves memory (SR-1).
#[derive(Clone, PartialEq, Eq)]
pub struct EvidenceLine {
    pub kind: EvidenceKind,
    pub source: super::delivery::Source,
    pub store_version: String,
}

impl std::fmt::Debug for EvidenceLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvidenceLine")
            .field("kind", &self.kind)
            .finish()
    }
}

impl From<&super::delivery::Evidence> for EvidenceLine {
    fn from(e: &super::delivery::Evidence) -> Self {
        let kind = if e.supplied.is_some() {
            EvidenceKind::Supplied
        } else if e.attested() {
            EvidenceKind::Attested
        } else {
            EvidenceKind::Proven
        };
        Self {
            kind,
            source: e.source.clone(),
            store_version: e.store_version.clone(),
        }
    }
}

/// A placement's delivery item as read: each name's evidence line and the source item
/// versions its last full sync recorded (item id → version, the `source versions` field).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlacementEvidence {
    pub lines: BTreeMap<String, EvidenceLine>,
    pub source_versions: BTreeMap<String, u64>,
}

impl PlacementEvidence {
    /// The evidence of a delivery item: its decoded `evidence` lines and its `source
    /// versions` text (`v1|<item id>|<version>` per line; any other line is skipped).
    pub fn new(evidence: &[super::delivery::Evidence], source_versions: Option<&str>) -> Self {
        let mut versions = BTreeMap::new();
        for line in source_versions.unwrap_or_default().lines() {
            let mut parts = line.split('|');
            if parts.next() != Some("v1") {
                continue;
            }
            if let (Some(id), Some(Ok(version)), None) = (
                parts.next(),
                parts.next().map(str::parse::<u64>),
                parts.next(),
            ) {
                versions.insert(id.to_string(), version);
            }
        }
        Self {
            lines: evidence
                .iter()
                .map(|e| (e.name.clone(), EvidenceLine::from(e)))
                .collect(),
            source_versions: versions,
        }
    }
}

/// The delivery state of the store name `name` on one placement (#174).
///
/// `placement` is the read of the placement's delivery item: `Err` when it failed
/// (`unreadable`), `Ok(None)` when no delivery item is recorded (`not_delivered`).
/// `expected` is the 1Password field the name is bound to now; `current_versions` is each
/// source item's version as this session read it (item id → version); `listed_version` is
/// the store's version of the name, when the target was listed. Then, in order: no line is
/// `not_delivered`; a line for another field, at another store version than listed, or
/// recorded before its source item's current version is `stale`; otherwise the line's own
/// kind (`delivered`, `attested`, `supplied`). Anything not known is not judged.
pub fn delivery_state(
    placement: Result<Option<&PlacementEvidence>, &EvidenceUnreadable>,
    name: &str,
    expected: Option<&super::delivery::Source>,
    current_versions: &BTreeMap<String, u64>,
    listed_version: Option<&str>,
) -> DeliveryState {
    let evidence = match placement {
        Err(_) => return DeliveryState::Unreadable,
        Ok(None) => return DeliveryState::NotDelivered,
        Ok(Some(evidence)) => evidence,
    };
    let Some(line) = evidence.lines.get(name) else {
        return DeliveryState::NotDelivered;
    };
    if expected.is_some_and(|source| *source != line.source) {
        return DeliveryState::Stale;
    }
    if listed_version.is_some_and(|listed| listed != line.store_version) {
        return DeliveryState::Stale;
    }
    let item = &line.source.item_id;
    if let (Some(recorded), Some(current)) = (
        evidence.source_versions.get(item),
        current_versions.get(item),
    ) && recorded < current
    {
        return DeliveryState::Stale;
    }
    match line.kind {
        EvidenceKind::Proven => DeliveryState::Delivered,
        EvidenceKind::Attested => DeliveryState::Attested,
        EvidenceKind::Supplied => DeliveryState::Supplied,
    }
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
    /// A shared key (FR-45): the `<product>/<KEY>` whose field holds the value. The cell's
    /// state, capability and boundary are that source's, and the value is entered there.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// A personal key (FR-55): its state is read from the person's own item, which no
    /// `opv set` writes (that writes the team boundary item).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub personal: bool,
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
/// environment (a shared key's: its source product's; a personal key's: its own item's
/// vault, from `cells.vaults`). A key the contract leaves out of an environment (an explicit
/// `environments` list without it and no `except`) has no cell there. A cell whose
/// capability is exactly [`Capability::None`] (the session is not a member) takes its state
/// from `receipt` when the receipt recorded one, with the receipt's age; otherwise the live
/// state is used. A `not_wanted` key is `not_wanted` from the
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
            // A shared key (FR-45) has no field of its own: its state is its source's field,
            // in the source product's boundary item of the same environment (FR-57).
            let (at_product, at_key) = spec.source().unwrap_or((product, key));
            let boundary = fleet.boundary_of(at_product).to_string();
            let mut presence = BTreeMap::new();
            for (env, e) in &fleet.environments {
                let here = present_in(spec, env);
                presence.insert(env.clone(), PresenceView::from(here.clone()));
                // A key the contract does not declare for this environment has no cell: there
                // is no value to hold, so nothing for a reader to rank or fill.
                if here == Presence::Absent {
                    continue;
                }

                let at = || (at_product.to_string(), at_key.to_string(), env.clone());
                let vault = cells.vaults.get(&at()).cloned().or_else(|| {
                    e.boundaries
                        .get(&boundary)
                        .and_then(Option::as_ref)
                        .map(|b| b.vault_id.clone())
                });
                let capability = vault
                    .and_then(|v| cells.capabilities.get(&v).copied())
                    .unwrap_or(Capability::Unknown {
                        source: UnknownSource::NoPermissionsInReply,
                    });

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
                    // #206: supplied at sync, never stored: nothing in 1Password to read.
                    _ if spec.value_source
                        == Some(crate::domain::model::ValueSource::Infrastructure) =>
                    {
                        (ValueState::Supplied, None)
                    }
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
                    from: spec.from.clone(),
                    personal: spec.personal,
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
                immutable: spec.immutable,
                allow_same_value: spec.allow_same_value,
                rules: rule_names(&spec.rules),
                guidance: spec.guidance.clone(),
                roles: spec.roles.clone(),
                file: spec.file.clone(),
                targets: target_names(fleet, product, key, spec),
                delivery: BTreeMap::new(),
            });
        }
    }

    Inventory {
        environments,
        keys,
        cells: matrix,
    }
}

/// The names of the validation rules `rules` declares, in a fixed order, and never their
/// parameters (#174): a parameter such as `prefix` could hold a value-shaped string, so
/// only the rule's name is reported (SR-1).
fn rule_names(rules: &Rules) -> Vec<String> {
    let mut names = Vec::new();
    for (set, name) in [
        (rules.prefix.is_some(), "prefix"),
        (rules.not_prefix.is_some(), "not_prefix"),
        (rules.ensure_prefix.is_some(), "ensure_prefix"),
        (rules.regex.is_some(), "regex"),
        (rules.r#enum.is_some(), "enum"),
        (rules.base64_bytes.is_some(), "base64_bytes"),
        (rules.hex_bytes.is_some(), "hex_bytes"),
        (rules.email_list, "email_list"),
        (rules.https_url, "https_url"),
        (rules.prefix_by_mode.is_some(), "prefix_by_mode"),
        (!rules.refuse_in.is_empty(), "refuse_in"),
        (rules.transform.is_some(), "transform"),
    ] {
        if set {
            names.push(name.to_string());
        }
    }
    names
}

/// Every target of `fleet` that delivers `product`'s `key`, as `"<env>/<target>"` → the
/// name the target renders for it ([`Fleet::target_name`]): for every environment the key
/// is wanted in and every target that delivers the product. Names only, never a value.
fn target_names(
    fleet: &Fleet,
    product: &str,
    key: &str,
    spec: &KeySpec,
) -> BTreeMap<String, String> {
    let mut targets = BTreeMap::new();
    for (env, e) in &fleet.environments {
        if !spec.is_desired_in(env) {
            continue;
        }
        for target in e.targets.keys() {
            if !fleet.delivers(env, target, product) {
                continue;
            }
            targets.insert(
                format!("{env}/{target}"),
                fleet.target_name(env, target, product, key),
            );
        }
    }
    targets
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
        ValueSource::Infrastructure => "infrastructure",
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
