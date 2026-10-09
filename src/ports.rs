//! Target ports (FR-12, FR-28), split by flow. Core logic reaches a target only through
//! these traits; a target is one store plus one runtime of the same flow:
//!
//! - **staged** (Fly): the store stages pending changes and the runtime deploys them
//!   ([`StagedStore`] + [`StagedRuntime`]); Fly implements both.
//! - **pinned** (clouds): the store writes versions and the runtime binds each env name to
//!   one pinned version ([`PinnedStore`] + [`PinnedRuntime`]), FR-29, FR-31, FR-33.
//!
//! Both store kinds share [`Store`], which is all `status` and `plan` need. See
//! `docs/design/multi-cloud-targets.md` §3.

use crate::domain::{
    AccessFinding, Health, Revision, RuntimeChange, RuntimeSnapshot, SecretValue, Stamp, StoreEntry,
};
use crate::error::Error;

/// Where secret values are written: the operations every flow shares.
///
/// Every name a store port takes or returns is a runtime env name, as the template renders
/// it (FR-8). A store that spells names differently (Key Vault: `_` becomes `-`) maps them
/// inside its adapter, so core code never handles store spellings.
pub trait Store {
    /// Every entry with its version and pending flag. Never values.
    fn list(&self) -> Result<Vec<StoreEntry>, Error>;
    /// The first rule this store would refuse for `(name, value)`, with its fixed reason
    /// (FR-22), so `status` and `plan` show what `sync` would refuse.
    fn refusal(&self, name: &str, value: &SecretValue) -> Option<(&'static str, &'static str)>;
}

/// A store whose writes are pending until the runtime deploys them: Fly secrets.
pub trait StagedStore: Store {
    /// Refuses the whole batch before any write, naming the key and rule, never the value.
    fn validate(&self, batch: &[(String, &SecretValue)]) -> Result<(), Error>;
    /// Writes the batch as a pending change, values on stdin only (SR-3).
    fn write(&self, batch: &[(String, &SecretValue)]) -> Result<(), Error>;
    /// Removes `names` as a pending change.
    fn remove(&self, names: &[String]) -> Result<(), Error>;
}

/// A store whose writes are versions the runtime pins to: Key Vault.
pub trait PinnedStore: Store {
    /// Current value and version, for compare-before-write (FR-31). None when absent.
    fn read(&self, name: &str) -> Result<Option<(SecretValue, String)>, Error>;
    /// One new version, value on stdin, tagged opv-managed=<env> and with `stamp`, opv's
    /// run metadata (FR-42; never a value), where the store records metadata; returns the
    /// version id.
    fn write_one(&self, name: &str, value: &SecretValue, stamp: &Stamp) -> Result<String, Error>;
    /// Refuses an entry without the ownership tag (FR-32).
    fn delete(&self, name: &str) -> Result<(), Error>;
    /// Removes versions of `name` other than `keep_version` once a healthy revision binds
    /// `keep_version` (FR-32). Called only after a healthy revision. A store that keeps
    /// version history inside one entry (Key Vault) implements it as a no-op: old versions
    /// stay as history and are never disabled or deleted; a store whose versions are
    /// separate objects (Kubernetes Secrets) deletes the unreferenced ones.
    fn collect_superseded(&self, name: &str, keep_version: &str) -> Result<(), Error>;
    /// Whether `version` of `name` exists, to diagnose a binding that cannot resolve it
    /// (read-only). `None` when the store cannot tell.
    fn has_version(&self, _name: &str, _version: &str) -> Result<Option<bool>, Error> {
        Ok(None)
    }
}

/// What runs the app in the staged flow: the Fly app.
pub trait StagedRuntime {
    /// Makes pending store changes live (FR-7). Called only under `--deploy`.
    fn deploy(&self) -> Result<(), Error>;
}

/// What runs the app in the pinned flow: a Container App.
pub trait PinnedRuntime {
    /// The current managed bindings and the fingerprint of everything else (FR-31).
    fn bindings(&self) -> Result<RuntimeSnapshot, Error>;
    /// Applies `change` onto `snapshot` (read-modify-write) and returns the new revision.
    fn apply(&self, change: &RuntimeChange, snapshot: &RuntimeSnapshot) -> Result<Revision, Error>;
    /// Waits for `revision` to become healthy, unhealthy, or time out (FR-33).
    fn await_healthy(&self, revision: &Revision) -> Result<Health, Error>;
    /// Advisory only (R6): used by doctor, never gates a deploy.
    fn check_access(&self, names: &[String]) -> Result<Vec<AccessFinding>, Error>;
    /// True when config is routed like secrets (`config = "store"`): written to the store
    /// and bound by reference. False: config is a plain env value (FR-14).
    fn config_in_store(&self) -> bool;
    /// The runtime in messages, e.g. `container app ca-app`. Names only.
    fn describe(&self) -> String;
    /// The command that shows why `revision` is not healthy, for the "next:" line (FR-26).
    fn inspect_hint(&self, revision: &Revision) -> String;
    /// How env name `name`, pinned to `version` of the store, reaches the app, when it
    /// passes through more than one object (FR-39), e.g. `DB_URL → Key Vault kv (v…) →
    /// ExternalSecret opv-… → env DB_URL`. Names and version ids only.
    fn chain(&self, _name: &str, _version: &str) -> Option<String> {
        None
    }
}

/// A target's store and runtime adapters, returned by `TargetConfig::open`. The variant is
/// the flow: staged (one store and one runtime that deploys staged changes) or pinned.
pub enum Ports<'a> {
    Staged {
        store: Box<dyn StagedStore + 'a>,
        runtime: Box<dyn StagedRuntime + 'a>,
    },
    Pinned {
        store: Box<dyn PinnedStore + 'a>,
        runtime: Box<dyn PinnedRuntime + 'a>,
    },
}

impl Ports<'_> {
    /// The store as the operations every flow shares, for `status` and `plan`.
    pub fn store(&self) -> &dyn Store {
        match self {
            Ports::Staged { store, .. } => store.as_ref(),
            Ports::Pinned { store, .. } => store.as_ref(),
        }
    }
}
