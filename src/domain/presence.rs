//! Presence (design Part V, row `presence`): which environments a declared key belongs to.
//!
//! Since 0.12.0 a key's `environments` list is optional: absent means the key is present in
//! every environment of the fleet. `except` removes the key from a named environment with a
//! person's reason, resolving it as [`Presence::NotWanted`] there. An explicit list that
//! leaves an environment out without an `except` is a likely mistake: [`gaps`] reports it as
//! the `environment_gap` warning and the configuration still loads.

use super::model::{Fleet, KeySpec, Lifecycle};

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
    presence_of(
        key.environments.as_deref(),
        key.except.get(env).map(String::as_str),
        env,
    )
}

/// Where a key stands in `env` from the parts of its declaration: its explicit
/// `environments` list (`None` when absent) and its `except` reason for `env`, if any. The
/// one rule [`present_in`] applies; a caller that reads the raw document before it loads
/// (the structural plan, `app::bootstrap`) applies it here too.
pub fn presence_of(list: Option<&[String]>, except: Option<&str>, env: &str) -> Presence {
    let not_wanted = |reason: &str| Presence::NotWanted {
        reason: reason.to_string(),
    };
    match list {
        None => except.map_or(Presence::Present, not_wanted),
        Some(list) if list.iter().any(|e| e == env) => Presence::Present,
        Some(_) => except.map_or(Presence::Absent, not_wanted),
    }
}

/// Whether a key declared with these parts is wanted in `env`: [`presence_of`] says
/// [`Present`](Presence::Present) and its `lifecycle` is not `retired` (#179: a retired key
/// keeps its declaration but is wanted nowhere). [`KeySpec::is_desired_in`] is this rule.
pub fn wanted(
    list: Option<&[String]>,
    except: Option<&str>,
    lifecycle: Lifecycle,
    env: &str,
) -> bool {
    lifecycle != Lifecycle::Retired && presence_of(list, except, env) == Presence::Present
}

/// Whether `key` is wanted in `env`: [`Present`](Presence::Present) and nothing else.
pub fn desired_in(key: &KeySpec, env: &str) -> bool {
    present_in(key, env) == Presence::Present
}

/// Every `(product, key, env)` an explicit `environments` list leaves out without an
/// `except`: the `environment_gap` warning (the configuration still loads). An environment
/// the key's `refuse_in` names is a deliberate exclusion, never a gap (#243).
pub fn gaps(fleet: &Fleet) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for (product, p) in &fleet.products {
        for (key, spec) in &p.keys {
            let Some(list) = &spec.environments else {
                continue;
            };
            for env in fleet.environments.keys() {
                if !list.iter().any(|e| e == env)
                    && !spec.except.contains_key(env)
                    && !spec.rules.refuse_in.iter().any(|e| e == env)
                {
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
