//! Runtime-side types for the pinned flow (FR-29, FR-31, FR-33). Names only, never values:
//! config values live in [`RuntimeChange::set`] only, and its `Debug` prints names.

use std::collections::BTreeMap;
use std::fmt;

/// How a runtime binds one managed env name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Binding {
    /// Plain env value (config). The value is not kept: only a SHA-256 hex digest of it,
    /// so `status` can tell "matches" from "differs" without holding the value.
    Plain { digest: String },
    /// Reference to a store entry pinned to `version`.
    Pinned { store_name: String, version: String },
    /// A reference opv cannot interpret (unversioned URL, other vault, other secret source).
    Other,
}

/// What the runtime binds today, read once before a change (FR-31).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeSnapshot {
    /// env name → binding, managed names only.
    pub bindings: BTreeMap<String, Binding>,
    /// SHA-256 of the canonical JSON of everything outside managed names (FR-31).
    pub unmanaged_fingerprint: String,
    /// The runtime's raw spec, kept for read-modify-write. Holds no secret values
    /// (Key Vault references and config only); `Debug` prints its length only.
    pub spec: RawSpec,
}

/// A runtime's raw spec. Config values may appear in it, so `Debug` prints its length only.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct RawSpec(pub serde_json::Value);

impl fmt::Debug for RawSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RawSpec({} bytes)", self.0.to_string().len())
    }
}

/// One change to apply to the runtime's bindings.
pub struct RuntimeChange {
    /// env name → (store name, version) to bind.
    pub pin: BTreeMap<String, (String, String)>,
    /// env name → config value to set. Config only, never secrets.
    pub set: BTreeMap<String, String>,
    /// env names to remove.
    pub unbind: Vec<String>,
}

impl fmt::Debug for RuntimeChange {
    /// Names only: `set` values are never printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeChange")
            .field("pin", &self.pin)
            .field("set", &self.set.keys().collect::<Vec<_>>())
            .field("unbind", &self.unbind)
            .finish()
    }
}

/// The runtime revision an apply produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revision(pub String);

/// The outcome of waiting on a revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health {
    Healthy,
    Unhealthy(String),
    TimedOut,
}

/// A store entry the runtime cannot read (advisory, R6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessFinding {
    pub store_name: String,
    /// Names the store and the command that grants access. Names and ids only, never values.
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_change_debug_names_only() {
        let mut c = RuntimeChange {
            pin: Default::default(),
            set: Default::default(),
            unbind: vec![],
        };
        c.set.insert("LOG_LEVEL".into(), "opv-marker-config".into());
        assert!(!format!("{c:?}").contains("opv-marker-config"));
    }

    #[test]
    fn raw_spec_debug_prints_length_only() {
        let s = RawSpec(serde_json::json!({"value": "opv-marker-config"}));
        assert!(!format!("{s:?}").contains("opv-marker-config"));
    }
}
