//! The Azure provider: Key Vault (store) + Container Apps (runtime), pinned flow (FR-28 to
//! FR-33, `docs/design/multi-cloud-targets.md`).
//!
//! Layout: `config.rs` holds the section parsing, name rules and the `TargetConfig` impl;
//! the store adapter lands as `keyvault.rs` (with the `az` wrapper as `az.rs`) and the
//! runtime adapter as `containerapp.rs`, after which `AzureTarget::open` returns
//! `Ports::Pinned`.

pub mod config;

pub use config::{AzureTarget, ConfigRoute, PROVIDER};
