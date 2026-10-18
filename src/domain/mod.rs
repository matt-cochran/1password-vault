//! Pure domain types. Nothing here knows about a vendor CLI or subprocesses (FR-12).

pub mod access;
pub mod access_plan;
pub mod adopt;
pub mod catalog;
pub mod convention;
pub mod delivery;
pub mod health;
pub mod history;
pub mod intent;
pub mod kind_guess;
pub mod ledger;
pub mod model;
pub mod naming;
pub mod placement;
pub mod secret;

pub use model::{
    Boundary, Environment, Fleet, ItemRef, KeySpec, Kind, OneOrMany, Origin, PrefixByMode, Product,
    Rules, Target, boundary_missing, key_label,
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
