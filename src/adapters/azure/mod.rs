//! The Azure provider: Key Vault (store) + Container Apps (runtime), pinned flow (FR-28 to
//! FR-33, `docs/design/multi-cloud-targets.md`).
//!
//! Layout: `config.rs` holds the section parsing, name rules and the `TargetConfig` impl,
//! whose `open` returns `Ports::Pinned` over the store adapter `keyvault.rs` and the
//! runtime adapter `containerapp.rs`. Both run `az` through the shared plumbing in `az.rs`
//! (spawn, failure diagnosis, `/dev/stdin` check, pacing). `preflight.rs` holds the
//! read-only checks run before a command touches the target, the vault URI read from
//! Azure, and the `doctor` lines (NR-23, NR-25, FR-26, FR-33). `store.rs` is the named
//! `[stores.<name>]` Key Vault (`azure_key_vault`) other runtimes bind (FR-39).
//! `resource.rs` is the engine a Container App and a Container Apps Job share (bindings,
//! fingerprint, edit, identity and access; M4); `job.rs` is a companion job of the app
//! (`docs/design/azure-jobs.md`), and `companions.rs` the runtime `open` returns for a target
//! with `azure.companion_jobs`: the app and its jobs, synced and deployed together.

mod az;
mod companions;
pub mod config;
pub mod containerapp;
pub mod diagnose;
pub mod handoff;
pub mod job;
pub mod keyvault;
pub mod login;
pub mod preflight;
mod resource;
pub mod store;
#[cfg(windows)]
pub(crate) mod winsec;

pub use config::{AzureTarget, ConfigRoute, PROVIDER};
