//! The Azure provider: Key Vault (store) + Container Apps (runtime), pinned flow (FR-28 to
//! FR-33, `docs/design/multi-cloud-targets.md`).
//!
//! Layout: `config.rs` holds the section parsing, name rules and the `TargetConfig` impl,
//! whose `open` returns `Ports::Pinned` over the store adapter `keyvault.rs` and the
//! runtime adapter `containerapp.rs`. Both run `az` through the shared plumbing in `az.rs`
//! (spawn, failure diagnosis, `/dev/stdin` check, pacing).

mod az;
pub mod config;
pub mod containerapp;
pub mod keyvault;

pub use config::{AzureTarget, ConfigRoute, PROVIDER};
