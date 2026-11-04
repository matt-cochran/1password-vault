//! Provisioning sets and producers (#253, #262; `docs/design/owner-value-ingestion.md` §3,
//! §4.5): the value-free contract types the loader builds from `[sets]` and `[producers]`,
//! and the pure set-state classifier `opv provision` and `ready` share.
//!
//! A set is a group of declared keys of one boundary (one 1Password item, D1) that are made
//! and written together. Membership is the only mark a key carries (no key attribute
//! changes). Nothing here holds a value: a classification reads [`ValueState`]s only.

use std::collections::BTreeMap;
use std::time::Duration;

use super::value_state::{UnreadableCause, ValueState};

/// The longest a producer may run (vet F10): a `timeout` above it is refused at load.
pub const MAX_PRODUCER_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// A declared key, `product/KEY`: a set member or a producer input.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyRef {
    pub product: String,
    pub key: String,
}

impl KeyRef {
    /// `"<product>/<KEY>"` split at its first `/`; `None` without one or with an empty part.
    pub fn parse(s: &str) -> Option<Self> {
        let (product, key) = s.split_once('/')?;
        (!product.is_empty() && !key.is_empty()).then(|| Self {
            product: product.to_string(),
            key: key.to_string(),
        })
    }
}

impl std::fmt::Display for KeyRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.product, self.key)
    }
}

/// `[sets.<name>]`: keys of one boundary provisioned together (D1, D2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionSet {
    /// The environments the set is provisioned in; never empty. Every member is wanted in
    /// each of them.
    pub environments: Vec<String>,
    /// The boundary every member lives in (one item per environment, D1).
    pub boundary: String,
    /// Each member and how its value is made; never empty.
    pub members: BTreeMap<KeyRef, MemberSource>,
}

/// How a set member's value is made (§5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberSource {
    /// Output `output` of the declared producer `producer` (§5.2).
    Producer { producer: String, output: String },
    /// A CSPRNG generator (§5.1).
    Generate(Generator),
}

/// The closed set of generators (§5.1); no token generator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Generator {
    /// `generate = "rules"`: the key's own byte-count rule ([`super::KeySpec::has_generate_recipe`]).
    Rules,
    /// `generate = { hex_bytes = N }`, N in 16..=1024.
    HexBytes(u16),
    /// `generate = { base64_bytes = N }`, N in 16..=1024.
    Base64Bytes(u16),
}

/// `[producers.<name>]`: a program opv spawns to make values (§5.2, `opv.produce/1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Producer {
    /// The argv, run without a shell; never empty, never `op` or `opv` as `command[0]`.
    pub command: Vec<String>,
    /// The lowercase hex SHA-256 of the project file `command` names, checked at load
    /// (vet F17); `None` when `command` names no project file.
    pub sha256: Option<String>,
    /// The output names the producer returns, in declared order; never empty.
    pub outputs: Vec<String>,
    /// Input name → the key whose value is sent on stdin (D5-B): a key of the boundary of
    /// every set the producer serves, wanted in each of its environments.
    pub inputs: BTreeMap<String, KeyRef>,
    /// The hosts an `open_url` notice may name.
    pub open_url_hosts: Vec<String>,
    /// How long the producer may run; at most [`MAX_PRODUCER_TIMEOUT`].
    pub timeout: Duration,
}

/// A set's state in one environment (§4.5, also `ready`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SetState {
    /// No member holds a value.
    Absent,
    /// Every member holds a value that passes its rules.
    Complete,
    /// Some but not all members hold a value.
    Partial,
    /// Every member holds a value, and at least one fails its rules.
    Inconsistent,
}

/// Why a set has no state: a member value opv could not judge. Never folded into
/// [`SetState::Absent`] (a failed read is not an absent value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unclassifiable {
    /// opv could not read a member.
    Unreadable { cause: UnreadableCause },
    /// A member is not a stored value here (not wanted, or supplied at sync); the load
    /// rules refuse such a member, so this is a caller's mismatch.
    NotStored,
}

/// The state of a set from its members' value states (§4.5). An empty field or a known
/// placeholder holds no value; a malformed value holds one that fails its rules. An
/// unreadable or not-stored member makes the set [`Unclassifiable`]. No members: `Absent`.
pub fn classify<'a>(
    members: impl IntoIterator<Item = &'a ValueState>,
) -> Result<SetState, Unclassifiable> {
    let (mut total, mut held, mut failing) = (0usize, 0usize, 0usize);
    for state in members {
        total += 1;
        match state {
            ValueState::Absent | ValueState::Empty | ValueState::Placeholder => {}
            ValueState::Set => held += 1,
            ValueState::Malformed { .. } => {
                held += 1;
                failing += 1;
            }
            ValueState::Unreadable { cause } => {
                return Err(Unclassifiable::Unreadable {
                    cause: cause.clone(),
                });
            }
            ValueState::NotWanted { .. } | ValueState::Supplied => {
                return Err(Unclassifiable::NotStored);
            }
        }
    }
    Ok(match held {
        0 => SetState::Absent,
        n if n < total => SetState::Partial,
        _ if failing > 0 => SetState::Inconsistent,
        _ => SetState::Complete,
    })
}

#[cfg(test)]
#[path = "provision_tests.rs"]
mod tests;
