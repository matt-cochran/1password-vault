//! Vendor adapters behind the `CommandRunner` seam (FR-12). Each wraps an official CLI.
//!
//! Deployment providers live in one module each (`fly/`, `azure/`) and are reached only
//! through the plug-in contract in `crate::provider`, via [`registry`] (FR-37).

pub mod azure;
pub mod fly;
pub mod onepassword;
/// Dev-time title lookup and value-free item read, for `opv init` only (FR-23).
pub(crate) mod onepassword_init;
pub(crate) mod probe;
pub mod registry;
