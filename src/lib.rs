//! opv: orchestrates secrets from 1Password into runtime targets (Fly.io first).
//!
//! It is not an independent secrets store or encryption service. See the security
//! model in `docs/usage.md` for runtime access, Azure credential-cache exceptions,
//! and memory/redaction limits.

pub mod adapters;
pub mod app;
pub mod approval;
pub mod cause;
pub mod config;
pub mod config_edit;
pub mod config_store;
pub mod domain;
pub mod error;
pub mod hardening;
pub mod host;
pub mod json;
pub mod output;
pub mod ports;
pub mod provider;
pub mod ramdir;
pub mod runner;
pub mod schema;
pub mod scrub;
#[cfg(feature = "ui")]
pub mod ui;

pub use error::Error;

/// The user documentation, for links in messages: a binary install has no `docs/` folder
/// (review #17).
pub const DOCS_URL: &str = "https://github.com/matt-cochran/1password-vault/blob/main/docs";

#[cfg(feature = "mcp")]
pub mod mcp;
