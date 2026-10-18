//! The exact JSON documents the 0.11.0 MCP tools print (j8), kept until those tools are
//! removed (row `mcp-propose-a`); 0.12.0's CLI prints `opv contract` and `opv propose
//! structure` documents of its own.
//!
//! These are pure builders: given the same plan, applied report or configuration, the MCP
//! server (`src/mcp.rs`) produces the same document byte for byte. Names, checked identifiers and 1Password links only; never a
//! value, a message or upstream output.

use crate::domain::Kind;
use serde_json::{Value, json};

/// A declared name, safe to echo: non-empty, at most 128 bytes, ASCII letters, digits and
/// `_.-/` only. Everything that reaches a document passes through here or a stricter check.
pub(crate) fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-/".contains(&b))
}

/// The configuration metadata of `fleet`: environment names, key names and kinds, and each
/// target's provider and delivered products. No values, rules, vault identifiers, locators
/// or credential references (`opv_configuration`).
pub(crate) fn configuration_projection(fleet: &crate::domain::Fleet) -> Value {
    let environments: Vec<_> = fleet
        .environments
        .iter()
        .filter(|(n, _)| identifier(n))
        .map(|(name, e)| json!({"name": name, "requires_confirmation": e.confirm_env}))
        .collect();
    let keys: Vec<_> = fleet.products.iter().filter(|(n, _)| identifier(n)).flat_map(|(product, p)| p.keys.iter().filter(|(n, _)| identifier(n)).map(move |(key, spec)| json!({"product": product, "key": key, "kind": match spec.kind { Kind::Secret => "secret", Kind::Config => "config" }}))).collect();
    // #133: the declared connectors (targets): provider, the products each delivers,
    // and whether its state vault and deploy identity are declared. Never a locator,
    // vault ID or credential reference.
    let targets: Vec<_> = fleet
        .environments
        .iter()
        .filter(|(n, _)| identifier(n))
        .flat_map(|(env, e)| {
            e.targets
                .iter()
                .filter(|(n, _)| identifier(n))
                .map(move |(name, t)| {
                    let products: Vec<&str> = fleet
                        .products
                        .keys()
                        .filter(|p| identifier(p) && fleet.delivers(env, name, p))
                        .map(String::as_str)
                        .collect();
                    json!({
                        "environment": env,
                        "name": name,
                        "provider": t.config.provider().section(),
                        "products": products,
                        "state_vault_recorded": !t.state_vault_id.is_empty(),
                        "deploy_credentials_declared": t.deploy_credentials.is_some(),
                    })
                })
        })
        .collect();
    json!({"ok": true, "environments": environments, "keys": keys, "targets": targets, "changes_available": false})
}

/// The structural plan, field by field: identifiers only (`opv_structure_plan`).
pub(crate) fn plan_projection(p: &crate::app::structure::Plan) -> Value {
    use crate::app::bootstrap::{BoundaryStep, StateStep};
    let id_ok = |s: &str| crate::config::is_id(s) && s.len() <= 64;
    let mut vaults = Vec::new();
    for e in p.environments.iter().filter(|e| identifier(&e.environment)) {
        for b in e.boundaries.iter().filter(|b| identifier(&b.boundary)) {
            let products: Vec<&str> = b
                .products
                .iter()
                .map(String::as_str)
                .filter(|n| identifier(n))
                .collect();
            vaults.push(match &b.step {
                BoundaryStep::Create { vault, item } => json!({"environment": e.environment, "boundary": b.boundary, "products": products, "action": "create", "vault": vault, "item": item}),
                BoundaryStep::Ok { vault_id, item_id } if id_ok(vault_id) && id_ok(item_id) => json!({"environment": e.environment, "boundary": b.boundary, "products": products, "action": "ok", "vault_id": vault_id, "item_id": item_id}),
                _ => json!({"environment": e.environment, "boundary": b.boundary, "products": products, "action": "review"}),
            });
        }
        for st in e.state_vaults.iter().filter(|st| identifier(&st.target)) {
            vaults.push(match &st.step {
                StateStep::Create { vault } => json!({"environment": e.environment, "target": st.target, "action": "create", "vault": vault}),
                StateStep::Ok { vault_id } if id_ok(vault_id) => json!({"environment": e.environment, "target": st.target, "action": "ok", "vault_id": vault_id}),
                _ => json!({"environment": e.environment, "target": st.target, "action": "review"}),
            });
        }
    }
    let delivery: Vec<Value> = p.delivery_items.iter()
        .filter(|d| [&d.environment, &d.target, &d.product].iter().all(|n| identifier(n)))
        .map(|d| json!({"environment": d.environment, "target": d.target, "product": d.product, "item": d.item}))
        .collect();
    let fields: Vec<Value> = p.fields.iter()
        .filter(|f| [&f.environment, &f.boundary, &f.product, &f.key].iter().all(|n| identifier(n)))
        .map(|f| json!({"environment": f.environment, "boundary": f.boundary, "product": f.product, "key": f.key, "kind": f.kind}))
        .collect();
    let (v, i, f) = p.counts();
    let empty = p.is_empty();
    json!({
        "ok": true,
        "plan_id": p.plan_id,
        "account_id": p.account_id,
        "complete": empty,
        "counts": {"vaults": v, "items": i, "fields": f},
        "structure": vaults,
        "delivery_items": delivery,
        "fields": fields,
        "generated_config": p.generated,
        "changes_available": !empty,
        "human_action": if empty {
            "Nothing to create. A person enters any missing values in 1Password; check with opv_ready.".to_string()
        } else {
            "Show this plan to the person. They apply it by running `opv apply` in their own terminal.".to_string()
        },
    })
}

#[cfg(test)]
#[path = "agent_view_tests.rs"]
mod tests;
