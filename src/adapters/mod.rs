//! Vendor adapters behind the `CommandRunner` seam (FR-12). Each wraps an official CLI.
//!
//! Deployment providers live in one module each (`fly/`, `azure/`, `kubernetes/`) and are reached only
//! through the plug-in contract in `crate::provider`, via [`registry`] (FR-37).

pub mod azure;
/// Stateful fake `op` for manifest tests.
#[cfg(any(test, feature = "fake"))]
pub mod fake_op;
pub mod fly;
pub mod kubernetes;
pub mod onepassword;
/// Dev-time title lookup and value-free item read, for `opv init` only (FR-23).
pub(crate) mod onepassword_init;
/// The project manifest (configuration in 1Password, FR-44).
pub mod onepassword_manifest;
/// Tolerant item parse and the tidy write (FR-43).
pub mod onepassword_tidy;
pub(crate) mod probe;
pub mod registry;
