//! Relaxation classification (design Part V, row `relaxations`): how a working contract
//! weakens the contract committed on the repository's default branch.
//!
//! Pure: [`relaxations`] takes the two [`Fleet`]s (the default-branch contract from
//! [`crate::app::rule_source::RuleSource::contract`] and the working contract) and never
//! runs git. It lists names only: a [`Relaxation`] carries the product, the key, the
//! environment when one is involved, the kind and a fixed reason. No rule parameter, no
//! value and no digest of a value is carried or rendered.

use std::collections::BTreeSet;

use crate::domain::model::{Fleet, KeySpec, Kind, OneOrMany, Rules, Tier};
use crate::domain::presence::{self, Presence};

/// The closed set of contract relaxations opv recognises (design Part V, row `relaxations`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RelaxationKind {
    /// `allow_same_value` was added.
    AllowSameValueAdded,
    /// A new `except` of an environment whose tier is production.
    ExceptProduction,
    /// The key is present in fewer environments.
    PresenceNarrowed,
    /// A rule or shape was removed or loosened.
    RuleRemoved,
    /// A key's `kind` changed from `secret` to `config`.
    SecretToConfig,
}

impl RelaxationKind {
    /// The fixed, value-free reason listed with this kind.
    pub fn reason(self) -> &'static str {
        match self {
            Self::AllowSameValueAdded => "allow_same_value added",
            Self::ExceptProduction => "except of a production-tier environment",
            Self::PresenceNarrowed => "presence narrowed",
            Self::RuleRemoved => "a rule or shape removed",
            Self::SecretToConfig => "secret → config",
        }
    }
}

/// One relaxation of the working contract against the default branch.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Relaxation {
    pub product: String,
    pub key: String,
    /// The environment this relaxation concerns, when it is per-environment.
    pub env: Option<String>,
    pub kind: RelaxationKind,
    /// A fixed reason (a constant from [`RelaxationKind::reason`]).
    pub reason: &'static str,
}

impl Relaxation {
    /// A relaxation of `product`/`key` carrying its kind's fixed reason.
    pub fn new(
        product: impl Into<String>,
        key: impl Into<String>,
        env: Option<String>,
        kind: RelaxationKind,
    ) -> Self {
        Self {
            product: product.into(),
            key: key.into(),
            env,
            kind,
            reason: kind.reason(),
        }
    }
}

/// Every relaxation the working contract `head` makes against the default-branch contract
/// `base`, sorted by `(product, key, env, kind)` for stable bytes. A key removed entirely is
/// not a relaxation here: retirement handles it.
pub fn relaxations(base: &Fleet, head: &Fleet) -> Vec<Relaxation> {
    let envs: BTreeSet<&str> = base
        .environments
        .keys()
        .chain(head.environments.keys())
        .map(String::as_str)
        .collect();
    let mut out = Vec::new();
    for (product, base_product) in &base.products {
        let Some(head_product) = head.products.get(product) else {
            continue;
        };
        for (key, base_key) in &base_product.keys {
            let Some(head_key) = head_product.keys.get(key) else {
                continue;
            };
            out.extend(key_relaxations(
                product, key, base_key, head_key, &envs, base, head,
            ));
        }
    }
    out.sort();
    out
}

/// The relaxations of one `(product, key)` that still exists in `head`.
fn key_relaxations(
    product: &str,
    key: &str,
    base: &KeySpec,
    head: &KeySpec,
    envs: &BTreeSet<&str>,
    base_fleet: &Fleet,
    head_fleet: &Fleet,
) -> Vec<Relaxation> {
    let mut out = Vec::new();
    if base.kind == Kind::Secret && head.kind == Kind::Config {
        out.push(Relaxation::new(
            product,
            key,
            None,
            RelaxationKind::SecretToConfig,
        ));
    }
    if !base.allow_same_value && head.allow_same_value {
        out.push(Relaxation::new(
            product,
            key,
            None,
            RelaxationKind::AllowSameValueAdded,
        ));
    }
    if rules_loosened(&base.rules, &head.rules) {
        out.push(Relaxation::new(
            product,
            key,
            None,
            RelaxationKind::RuleRemoved,
        ));
    }
    for env in envs {
        let env = *env;
        if presence::present_in(base, env) != Presence::Present
            || presence::present_in(head, env) == Presence::Present
        {
            continue;
        }
        let kind = if new_production_except(base, head, base_fleet, head_fleet, env) {
            RelaxationKind::ExceptProduction
        } else {
            RelaxationKind::PresenceNarrowed
        };
        out.push(Relaxation::new(product, key, Some(env.to_string()), kind));
    }
    out
}

/// Whether `env` is dropped by a `head`-only `except` whose environment is production.
fn new_production_except(
    base: &KeySpec,
    head: &KeySpec,
    base_fleet: &Fleet,
    head_fleet: &Fleet,
    env: &str,
) -> bool {
    !base.except.contains_key(env)
        && head.except.contains_key(env)
        && tier_of(head_fleet, base_fleet, env) == Tier::Production
}

/// An environment's tier, from `head` when it declares it, else from `base`.
fn tier_of(head: &Fleet, base: &Fleet, env: &str) -> Tier {
    head.environments
        .get(env)
        .or_else(|| base.environments.get(env))
        .map(|environment| environment.tier)
        .unwrap_or_default()
}

/// Whether `head` drops or loosens a rule that `base` set: a required field unset, a
/// prohibition dropped, an allow-list widened, or an allow-list removed. Compared field by
/// field; the field's parameters are never carried into the result.
fn rules_loosened(base: &Rules, head: &Rules) -> bool {
    unset(&base.prefix, &head.prefix)
        || unset(&base.ensure_prefix, &head.ensure_prefix)
        || unset(&base.regex, &head.regex)
        || unset(&base.transform, &head.transform)
        || unset(&base.base64_bytes, &head.base64_bytes)
        || unset(&base.hex_bytes, &head.hex_bytes)
        || unset(&base.prefix_by_mode, &head.prefix_by_mode)
        || unset(&base.r#enum, &head.r#enum)
        || (base.email_list && !head.email_list)
        || (base.https_url && !head.https_url)
        || dropped_entries(base.not_prefix.as_ref(), head.not_prefix.as_ref())
        || dropped_strings(&base.refuse_in, &head.refuse_in)
        || widened_strings(base.r#enum.as_ref(), head.r#enum.as_ref())
}

/// Set in `base`, unset in `head`.
fn unset<T>(base: &Option<T>, head: &Option<T>) -> bool {
    base.is_some() && head.is_none()
}

/// A prohibition list (`not_prefix`) that lost an entry in `head`.
fn dropped_entries(base: Option<&OneOrMany>, head: Option<&OneOrMany>) -> bool {
    let Some(base) = base else {
        return false;
    };
    let base: Vec<&str> = base.iter().collect();
    let head: Vec<&str> = head.map(|h| h.iter().collect()).unwrap_or_default();
    base.iter().any(|entry| !head.contains(entry))
}

/// A prohibition list (`refuse_in`) that lost an entry in `head`.
fn dropped_strings(base: &[String], head: &[String]) -> bool {
    base.iter().any(|entry| !head.contains(entry))
}

/// An allow-list (`enum`) that gained an entry in `head`.
fn widened_strings(base: Option<&Vec<String>>, head: Option<&Vec<String>>) -> bool {
    let Some(base) = base else {
        return false;
    };
    let head = head.map(Vec::as_slice).unwrap_or_default();
    head.iter().any(|entry| !base.contains(entry))
}

#[cfg(test)]
#[path = "relaxation_tests.rs"]
mod tests;
