//! Pure domain types. Nothing here knows about a vendor CLI or subprocesses (FR-12).

pub mod access;
pub mod access_plan;
pub mod catalog;
pub mod convention;
pub mod delivery;
pub mod health;
pub mod history;
pub mod import;
pub mod intent;
pub mod kind_guess;
pub mod ledger;
pub mod model;
pub mod naming;
pub mod placement;
pub mod presence;
pub mod relaxation;
pub mod secret;
pub mod value_state;

#[cfg(test)]
#[path = "tier_tests.rs"]
mod tier_tests;

pub use model::{
    Boundary, Date, Environment, Fleet, ItemRef, KeySpec, Kind, Lifecycle, OneOrMany, Origin,
    PrefixByMode, Product, Rules, Target, Tier, ValueSource, boundary_missing, key_label,
};
pub use secret::SecretValue;
pub mod plan;
pub mod provenance;
pub mod rules;
pub mod runtime;
pub use plan::{ItemField, KeyState, Row, StoreEntry, SyncPlan, TargetState, build as build_plan};
pub use provenance::Stamp;
pub use runtime::{
    AccessFinding, Binding, Health, RawSpec, Revision, RuntimeChange, RuntimeSnapshot,
};

#[cfg(test)]
#[path = "key_attrs_tests.rs"]
mod key_attrs_tests;
