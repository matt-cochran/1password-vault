//! Value-free key history (#95): one row per declared key, joining what the environment
//! declares, what the target's store lists and what opv's version ledger recorded (FR-54),
//! with the provenance stamp the store carries on the entry (FR-42).
//!
//! A row holds names, versions, times and a state only: never a value, a value length or a
//! fingerprint (SR-1). Pure: no target, no I/O.

use std::collections::BTreeMap;

use crate::domain::plan::StoreEntry;

/// A declared key to build a history row for: its product, its own name and the store name
/// it renders in this environment.
pub struct KeyRef<'a> {
    pub product: &'a str,
    pub key: &'a str,
    pub name: &'a str,
}

/// One value-free history row per declared key (#95). See [`build`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct HistoryRow {
    pub product: String,
    pub key: String,
    pub name: String,
    pub on_target: bool,
    pub version: Option<String>,
    pub pending: bool,
    pub written: Option<String>,
    pub opv_version: Option<String>,
    pub plan: Option<String>,
    pub recorded_version: Option<String>,
    pub state: &'static str,
}

/// Build one history row per key in `keys`, in that order. The store entry is the one whose
/// name equals [`KeyRef::name`]; `state` is `absent` with no entry, `stamped` when the entry
/// carries a stamp, else `recorded` when the ledger has the name at the entry's version,
/// else `changed_outside_opv` when the ledger has the name at another version (or at any
/// version while the entry has none), else `not_recorded`.
pub fn build(
    keys: &[KeyRef<'_>],
    listed: &[StoreEntry],
    recorded: &BTreeMap<String, String>,
) -> Vec<HistoryRow> {
    keys.iter()
        .map(|k| {
            let entry = listed.iter().find(|e| e.name == k.name);
            let stamp = entry.and_then(|e| e.stamp.as_ref());
            let state = match entry {
                None => "absent",
                Some(e) if e.stamp.is_some() => "stamped",
                Some(e) => match recorded.get(&e.name) {
                    Some(v) if e.version.as_deref() == Some(v.as_str()) => "recorded",
                    Some(_) => "changed_outside_opv",
                    None => "not_recorded",
                },
            };
            HistoryRow {
                product: k.product.to_string(),
                key: k.key.to_string(),
                name: k.name.to_string(),
                on_target: entry.is_some(),
                version: entry.and_then(|e| e.version.clone()),
                pending: entry.is_some_and(|e| e.pending),
                written: stamp.map(|s| s.written.clone()),
                opv_version: stamp.map(|s| s.opv_version.clone()),
                plan: stamp.map(|s| s.plan.clone()),
                recorded_version: recorded.get(k.name).cloned(),
                state,
            }
        })
        .collect()
}

/// The most recent stamp time among the rows (`written`, as text; they sort by time), or
/// `None`.
pub fn latest_written(rows: &[HistoryRow]) -> Option<&str> {
    rows.iter().filter_map(|r| r.written.as_deref()).max()
}

#[cfg(test)]
#[path = "history_tests.rs"]
mod tests;
