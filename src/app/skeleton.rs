//! The empty fields a boundary item lacks (FR-19), for the structural plan and its apply
//! ([`super::structure`]; 0.11.0's `item skeleton`, removed in 0.12.0).
//!
//! Every key declared for an environment (all products, mode-skipped keys included) that
//! has no field yet gets an empty field of its declared kind. Existing fields are never
//! touched, whatever their kind or value.

use crate::adapters::{onepassword, onepassword_tidy};
use crate::domain::{Fleet, Kind, convention};
use crate::error::Error;
use crate::runner::CommandRunner;

/// The refusal for boundary item `b` of `env` that is the project's manifest (M2): nothing
/// is written; it names the boundary and the item's IDs, and the fix is a values item of
/// its own (03.19).
fn manifest_as_boundary(
    env: &crate::domain::Environment,
    b: &crate::domain::Boundary,
    env_name: &str,
    raw: &[u8],
) -> Error {
    #[derive(serde::Deserialize)]
    struct Titled {
        #[serde(default)]
        title: String,
    }
    let title = serde_json::from_slice::<Titled>(raw)
        .map(|t| t.title)
        .unwrap_or_default();
    let name = env
        .boundaries
        .iter()
        .find(|(_, x)| x.as_ref() == Some(b))
        .map_or_else(String::new, |(n, _)| format!("boundaries.{n} "));
    crate::cause::Cause::ConfigNotEditable {
        source: crate::cause::ConfigSource::Manifest {
            project: title.strip_prefix("opv · ").unwrap_or(&title).to_string(),
            title,
            vault: crate::cause::VaultId::new(b.vault_id.clone()),
        },
        reason: crate::cause::NotEditable::ManifestItemAsBoundary {
            env: crate::cause::EnvName::new(env_name),
            boundary: format!("{name}(item {})", b.item_id),
        },
    }
    .into()
}

/// A field to add: product, key and kind.
pub(crate) type Field = (String, String, Kind);

/// The declared fields of `fleet`'s products in `env_name` that boundary item `b` lacks,
/// with the fresh read they were judged on (the read the structural apply's write is built
/// from). Names and kinds only; the item's values stay in the zeroized read (#133: the
/// structural plan lists these without writing).
pub(crate) fn missing_fields(
    fleet: &Fleet,
    env: &crate::domain::Environment,
    b: &crate::domain::Boundary,
    env_name: &str,
    r: &dyn CommandRunner,
) -> Result<(onepassword::Item, Vec<Field>), Error> {
    let item = onepassword::read_whole_fresh(r, env, b)?;
    // M2: the project manifest (FR-44) holds the configuration; it never gets key fields.
    if super::tidy::is_manifest(item.raw()) {
        return Err(manifest_as_boundary(env, b, env_name, item.raw()));
    }
    let (layout, _) = onepassword_tidy::parse(item.raw())?;
    let found = convention::resolve(&layout, fleet).chosen;
    let missing: Vec<(String, String, Kind)> = fleet
        .products
        .iter()
        .flat_map(|(product, p)| {
            p.keys
                .iter()
                // A shared key (FR-45) reads its source's field and never gets one of its
                // own. Task X (self-healing): keep this filter wherever fields are created.
                .filter(|(_, spec)| spec.from.is_none())
                // FR-55: a personal key's field lives in each person's own item.
                .filter(|(_, spec)| !spec.personal)
                .filter(|(_, spec)| spec.is_desired_in(env_name))
                .map(move |(key, spec)| (product.clone(), key.clone(), spec.kind))
        })
        .filter(|(product, key, _)| !found.contains_key(&(product.clone(), key.clone())))
        .collect();
    Ok((item, missing))
}

/// Every key of `fleet`'s products that gets a field of its own in `env_name`'s boundary
/// items: no shared (`from`) and no personal key (FR-45, FR-55).
pub(crate) fn declared_fields(fleet: &Fleet, env_name: &str) -> Vec<(String, String, Kind)> {
    fleet
        .products
        .iter()
        .flat_map(|(product, p)| {
            p.keys
                .iter()
                .filter(|(_, spec)| spec.from.is_none() && !spec.personal)
                .filter(|(_, spec)| spec.is_desired_in(env_name))
                .map(move |(key, spec)| (product.clone(), key.clone(), spec.kind))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::testutil::*;

    /// 03.19: the refusal names the boundary that records the manifest item.
    #[test]
    fn a_manifest_boundary_refusal_names_the_boundary() {
        let f = fleet();
        let env = &f.environments["prod"];
        let (name, b) = env.bound_boundaries().next().unwrap();
        let e = manifest_as_boundary(env, b, "prod", r#"{"title":"opv · app"}"#.as_bytes());
        assert!(
            e.to_string().contains(&format!("boundaries.{name} ")),
            "{e}"
        );
    }
}
