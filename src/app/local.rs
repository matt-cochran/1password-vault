//! Local-only validation. One item read, no deployment store, names-only output.
use crate::domain::Fleet;
use crate::error::Error;

/// Select configuration before any subprocess call. Does not read values.
pub fn select(
    fleet: &Fleet,
    env: &str,
    product: Option<&str>,
    required: bool,
) -> Result<Fleet, Error> {
    fleet.environment(env)?;
    // D10/FR-34: one product with keys desired in `env` needs no `--product`; the rule
    // lives in `super::pick_product`. `doctor` (required = false) keeps the whole
    // environment when the choice is ambiguous instead of failing.
    let chosen = match product {
        Some(p) => Some(super::pick_product(fleet, env, Some(p))?),
        None => match super::pick_product(fleet, env, None) {
            Ok(p) => Some(p),
            Err(_) if !required => None,
            Err(e) => return Err(e),
        },
    };
    let mut selected = fleet.clone();
    selected.environments.retain(|name, _| name == env);
    if let Some(p) = chosen.as_deref() {
        // The sources of the product's shared keys (FR-45) stay, alone: the read then
        // covers their sections too, and their findings are reported once, on them.
        let sources = fleet.sources_of(p);
        selected
            .products
            .retain(|name, _| name == p || sources.iter().any(|(s, _)| s == name));
        for (name, prod) in selected.products.iter_mut().filter(|(n, _)| *n != p) {
            prod.keys
                .retain(|k, _| sources.contains(&(name.clone(), k.clone())));
        }
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `shared` is source-only; `api` is the only product that can be chosen (FR-47).
    #[test]
    fn select_ignores_a_source_only_product_for_the_single_product_shortcut() {
        let f = crate::config::parse(
            r#"
[environments.ci]
boundaries.core = { vault_id = "vci", item_id = "ici" }
[environments.ci.targets.app]
fly.app = "app"
fly.secret_name = "FLEET__{PRODUCT}__{KEY}"
state_vault_id = "sci"
[products.shared]
source_only = true
boundary = "core"
[products.shared.keys.TOKEN]
kind = "secret"
environments = ["ci"]
[products.api]
boundary = "core"
[products.api.keys.TOKEN]
kind = "secret"
environments = ["ci"]
"#,
        )
        .unwrap();
        let selected = select(&f, "ci", None, true).unwrap();
        assert_eq!(
            selected.products.keys().cloned().collect::<Vec<_>>(),
            vec!["api".to_string()]
        );
    }
}
