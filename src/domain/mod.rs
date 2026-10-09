//! Pure domain types. Nothing here knows about a vendor CLI or subprocesses (FR-12).

pub mod model;
pub mod secret;

pub use model::{
    Environment, Fleet, KeySpec, Kind, OneOrMany, PrefixByMode, Product, Profile, Rules,
    SIMPLE_PRODUCT, SIMPLE_TEMPLATE, key_label,
};
pub use secret::SecretValue;
pub mod plan;
pub mod rules;
pub mod runtime;
pub use plan::{ItemField, KeyState, Row, StoreEntry, SyncPlan, TargetState, build as build_plan};
pub use runtime::{
    AccessFinding, Binding, Health, RawSpec, Revision, RuntimeChange, RuntimeSnapshot,
};
