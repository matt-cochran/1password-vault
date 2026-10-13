//! `opv ui` (#82): a terminal user interface over opv's own JSON documents. It browses every
//! environment (from the configuration, never a fixed list), product and key with secret
//! values never fetched, and runs actions as the same `opv` commands a person would type,
//! behind the same plan-and-confirm steps. Design: `docs/design/opv-ui-mockups.md`.

pub mod adopt_review;
pub mod app;
pub mod config_forms;
pub mod forms;
pub mod model;
pub mod render;
pub mod run;
pub mod screens;
