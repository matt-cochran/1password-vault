//! Behaviour tests for the placement names and self-explaining notes (FR-57, FR-58, E8).
//! Pure: this module derives text only (see `naming.rs`).

use super::*;

#[test]
fn boundary_vault_is_project_boundary_env() {
    assert_eq!(
        boundary_vault("portfolio", "api", "prod"),
        "portfolio-api-prod"
    );
}

#[test]
fn boundary_item_is_project_boundary_env_values() {
    assert_eq!(
        boundary_item("portfolio", "api", "prod"),
        "portfolio · api · prod values"
    );
}

#[test]
fn state_vault_is_project_env_target_state() {
    assert_eq!(
        state_vault("portfolio", "prod", "shared"),
        "portfolio-prod-shared-state"
    );
}

#[test]
fn delivery_item_is_opv_delivery_product_target() {
    assert_eq!(
        delivery_item("api", "shared"),
        "opv · delivery · api · shared"
    );
}

#[test]
fn boundary_notes_join_the_products_in_the_given_order() {
    assert_eq!(
        boundary_notes("portfolio", "prod", &["worker", "api"]),
        "Values for worker, api in prod (portfolio), managed by opv. The project's configuration names this item by its ID. Edit values here; do not rename this item, move it to another vault, or share this vault more widely than the people and deploy identities that need these values."
    );
}

#[test]
fn state_vault_notes_name_the_target_environment_and_project() {
    assert_eq!(
        state_vault_notes("portfolio", "prod", "shared"),
        "Delivery evidence for target shared in prod (portfolio), written by opv: one item per product. Only identities that can read those products' values should read this vault. Do not edit its items by hand."
    );
}

#[test]
fn delivery_item_notes_name_the_product_target_and_environment() {
    assert_eq!(
        delivery_item_notes("api", "shared", "prod"),
        "Delivery evidence for api on target shared in prod, written by opv after each confirmed sync: an evidence key and keyed fingerprints, never a value. opv delivery verify reads it. Do not edit by hand."
    );
}
