//! Target ports (FR-12, FR-28). Core logic reaches a target only through these two traits;
//! a target is one [`SecretStore`] plus one [`Runtime`], and Fly implements both.
//!
//! P0 carries exactly the operations the current engine calls. P1 adds `read`, `bindings`,
//! `apply`, `check_access` and `await_healthy` when the first cloud target needs them (see
//! `docs/design/multi-cloud-targets.md` §3).

use crate::domain::{SecretValue, StoreEntry};
use crate::error::Error;

/// Where secret values are written: Fly secrets today.
pub trait SecretStore {
    /// Every entry with its version and pending flag. Never values.
    fn list(&self) -> Result<Vec<StoreEntry>, Error>;
    /// The first rule this store would refuse for `(name, value)`, with its fixed reason
    /// (FR-22), so `status` and `plan` show what `sync` would refuse.
    fn refusal(&self, name: &str, value: &SecretValue) -> Option<(&'static str, &'static str)>;
    /// Refuses the whole batch before any write, naming the key and rule, never the value.
    fn validate(&self, batch: &[(String, &SecretValue)]) -> Result<(), Error>;
    /// Writes the batch as a pending change, values on stdin only (SR-3).
    fn write(&self, batch: &[(String, &SecretValue)]) -> Result<(), Error>;
    /// Removes `names` as a pending change.
    fn remove(&self, names: &[String]) -> Result<(), Error>;
}

/// What runs the app: the Fly app today.
pub trait Runtime {
    /// Makes pending store changes live (FR-7). Called only under `--deploy`.
    fn deploy(&self) -> Result<(), Error>;
}
