//! opv: orchestrates secrets from 1Password into runtime targets (Fly.io first).
//!
//! It never stores, encrypts or serves secret values; see `docs/design/requirements.md` §7 and §9.

pub mod adapters;
pub mod app;
pub mod config;
pub mod config_edit;
pub mod config_store;
pub mod domain;
pub mod error;
pub mod host;
pub mod ports;
pub mod provider;
pub mod runner;
pub mod scrub;

pub use error::Error;

/// The user documentation, for links in messages: a binary install has no `docs/` folder
/// (review #17).
pub const DOCS_URL: &str = "https://github.com/matt-cochran/1password-vault/blob/main/docs";
