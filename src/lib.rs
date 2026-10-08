//! opv: orchestrates secrets from 1Password into runtime targets (Fly.io first).
//!
//! It never stores, encrypts or serves secret values; see `docs/design/requirements.md` §7 and §9.

pub mod adapters;
pub mod app;
pub mod config;
pub mod domain;
pub mod error;
pub mod host;
pub mod ports;
pub mod runner;

pub use error::Error;
