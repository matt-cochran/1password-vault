//! The one place opv derives the titles of the vaults and items it creates, and the
//! self-explaining notes it writes inside them (FR-57, FR-58, E8). Pure: no `op`, no I/O,
//! no clock, so a title or note is one tested function rather than a literal repeated at
//! each call site.
//!
//! The placement model is in `docs/design/placements-and-access-boundaries.md`:
//!
//! - §4.1 fixes the boundary vault and item titles, `<project>-<boundary>-<env>` and
//!   `<project> · <boundary> · <env> values`;
//! - §6.3 fixes the per-target state vault, `<project>-<env>-<target>-state`;
//! - §5.3 fixes the per-placement delivery item, `opv · delivery · <product> · <target>`;
//! - §2.1 ("1Password explains itself") fixes the notes: what each vault or item holds,
//!   which configuration owns it, and what not to do by hand.
//!
//! Item titles separate their parts with " · " (space, U+00B7, space). Notes carry names
//! and instructions only: never a value, digest or fingerprint (SR-1).

/// The item-title separator: a space, U+00B7 (middle dot), a space.
const SEP: &str = " · ";

/// Title of the vault holding one boundary's values: `{project}-{boundary}-{env}` (FR-57).
pub fn boundary_vault(project: &str, boundary: &str, env: &str) -> String {
    format!("{project}-{boundary}-{env}")
}

/// Title of the one values item in a boundary vault: `{project} · {boundary} · {env} values`
/// (FR-57).
pub fn boundary_item(project: &str, boundary: &str, env: &str) -> String {
    format!("{project}{SEP}{boundary}{SEP}{env} values")
}

/// Title of a target's state vault: `{project}-{env}-{target}-state` (FR-58, §6.3).
pub fn state_vault(project: &str, env: &str, target: &str) -> String {
    format!("{project}-{env}-{target}-state")
}

/// Title of one placement's delivery item: `opv · delivery · {product} · {target}`
/// (FR-58, §5.3).
pub fn delivery_item(product: &str, target: &str) -> String {
    format!("opv{SEP}delivery{SEP}{product}{SEP}{target}")
}

/// The note inside a boundary's values item: what it holds, for which products, and what
/// not to do by hand (E8, §2.1). `products` are the products in this boundary, joined with
/// `", "` in the given order.
pub fn boundary_notes(project: &str, env: &str, products: &[&str]) -> String {
    let products = products.join(", ");
    format!(
        "Values for {products} in {env} ({project}), managed by opv. The project's configuration \
         names this item by its ID. Edit values here; do not rename this item, move it to another \
         vault, or share this vault more widely than the people and deploy identities that need \
         these values."
    )
}

/// The note inside a target's state vault: the delivery evidence it holds and who may read
/// it (E8, §2.1).
pub fn state_vault_notes(project: &str, env: &str, target: &str) -> String {
    format!(
        "Delivery evidence for target {target} in {env} ({project}), written by opv: one item per \
         product. Only identities that can read those products' values should read this vault. Do \
         not edit its items by hand."
    )
}

/// The note inside one placement's delivery item: what evidence it holds and what not to do
/// by hand (E8, §2.1).
pub fn delivery_item_notes(product: &str, target: &str, env: &str) -> String {
    format!(
        "Delivery evidence for {product} on target {target} in {env}, written by opv after each \
         confirmed sync: an evidence key and keyed fingerprints, never a value. opv delivery \
         verify reads it. Do not edit by hand."
    )
}

#[cfg(test)]
#[path = "naming_tests.rs"]
mod tests;
