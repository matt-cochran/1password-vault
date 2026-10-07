//! Pure domain types. Nothing here knows about `op`, `flyctl` or subprocesses (FR-12).

pub mod model;
pub mod secret;

pub use model::{
    Environment, Fleet, FlyTarget, KeySpec, Kind, OneOrMany, PrefixByMode, Product, Rules,
};
pub use secret::SecretValue;
pub mod plan;
pub mod rules;
pub use plan::{FlySecret, ItemField, KeyState, Row, SyncPlan, TargetState, build as build_plan};
