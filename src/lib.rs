//! secretctl: orchestrates secrets from 1Password into runtime targets (Fly.io first).
//!
//! It never stores, encrypts or serves secret values; see `OVERVIEW.md` §7 and §9.

pub mod adapters;
pub mod app;
pub mod config;
pub mod domain;
pub mod error;
pub mod runner;

pub use error::Error;
