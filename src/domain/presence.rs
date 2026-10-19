//! Presence (design Part V, row `presence`): which environments a declared key belongs to.
//!
//! Since 0.12.0 a key's `environments` list is optional: absent means the key is present in
//! every environment of the fleet. `except` removes the key from a named environment with a
//! person's reason, resolving it as [`Presence::NotWanted`] there. An explicit list that
//! leaves an environment out without an `except` is a likely mistake: [`gaps`] reports it as
//! the `environment_gap` warning and the configuration still loads.

use super::model::{Fleet, KeySpec};

/// Where a declared key stands in one environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Presence {
    /// Declared and wanted here.
    Present,
    /// Removed from this environment by `except`, with the declared reason.
    NotWanted { reason: String },
    /// An explicit `environments` list leaves this environment out, with no `except`.
    Absent,
}

/// Where `key` stands in `env`.
pub fn present_in(key: &KeySpec, env: &str) -> Presence {
    match &key.environments {
        None => match key.except.get(env) {
            Some(reason) => Presence::NotWanted {
                reason: reason.clone(),
            },
            None => Presence::Present,
        },
        Some(list) => {
            if list.iter().any(|e| e == env) {
                Presence::Present
            } else {
                match key.except.get(env) {
                    Some(reason) => Presence::NotWanted {
                        reason: reason.clone(),
                    },
                    None => Presence::Absent,
                }
            }
        }
    }
}

/// Whether `key` is wanted in `env`: [`Present`](Presence::Present) and nothing else.
pub fn desired_in(key: &KeySpec, env: &str) -> bool {
    present_in(key, env) == Presence::Present
}

/// Every `(product, key, env)` an explicit `environments` list leaves out without an
/// `except`: the `environment_gap` warning (the configuration still loads).
pub fn gaps(fleet: &Fleet) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for (product, p) in &fleet.products {
        for (key, spec) in &p.keys {
            let Some(list) = &spec.environments else {
                continue;
            };
            for env in fleet.environments.keys() {
                if !list.iter().any(|e| e == env) && !spec.except.contains_key(env) {
                    out.push((product.clone(), key.clone(), env.clone()));
                }
            }
        }
    }
    out
}

#[cfg(test)]
#[path = "presence_tests.rs"]
mod tests;
