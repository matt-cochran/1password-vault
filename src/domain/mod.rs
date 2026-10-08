//! Pure domain types. Nothing here knows about `op`, `flyctl` or subprocesses (FR-12).

pub mod model;
pub mod secret;

pub use model::{
    AzureTarget, ConfigRoute, Environment, Fleet, FlyTarget, KeySpec, Kind, OneOrMany,
    PrefixByMode, Product, Profile, Rules, SIMPLE_PRODUCT, SIMPLE_TEMPLATE, Target, key_label,
};
pub use secret::SecretValue;
pub mod plan;
pub mod rules;
pub use plan::{ItemField, KeyState, Row, StoreEntry, SyncPlan, TargetState, build as build_plan};
