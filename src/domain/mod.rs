//! Pure domain types. Nothing here knows about `op`, `flyctl` or subprocesses (FR-12).

pub mod model;
pub mod secret;

pub use model::{Environment, Fleet, KeySpec, Kind, PrefixByMode, Product, Rules};
pub use secret::SecretValue;
