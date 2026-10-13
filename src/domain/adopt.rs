//! FR-53 adoption planner. Pure: no `op`, no target calls, no I/O.
//!
//! Callers pass the item's current fields and the values found elsewhere (a dotenv file or a
//! readable target). The planner maps each found name to a declared key, normalises both
//! sides with the key's rules and reports one action per destination field. Values appear
//! only in `writes`, wrapped in `SecretValue`; `Debug` prints names only.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::domain::model::{Environment, Fleet};
use crate::domain::plan::ItemField;
use crate::domain::rules;
use crate::domain::secret::SecretValue;

/// What `adopt` decided for one destination field (FR-53).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Found and current agree byte for byte.
    Match,
    /// Equal after normalisation; nothing to write.
    FormatOnly,
    /// The current field is missing or empty: write the normalised found value.
    Import,
    /// Different values; 1Password is kept unless `--replace` names the key.
    Differs,
    /// `--replace` names the key: write the normalised found value.
    Replace,
    /// Immutable key named by `--replace` but not `--rotate`: held, nothing written.
    HeldImmutable,
    /// The found value fails a rule; the rule name is stable.
    FailsRule(&'static str),
    /// Two found copies of one field normalise differently.
    Conflict,
    /// A bare name matches several declared keys.
    Ambiguous,
    /// The found name matches no declared key for this environment.
    NotDeclared,
    /// The key does not apply in this environment.
    NotApplicable,
}

impl Action {
    /// The stable word printed for this action.
    pub fn word(&self) -> &'static str {
        match self {
            Action::Match => "match",
            Action::FormatOnly => "format_only",
            Action::Import => "import",
            Action::Differs => "differs",
            Action::Replace => "replace",
            Action::HeldImmutable => "held_immutable",
            Action::FailsRule(_) => "fails_rule",
            Action::Conflict => "conflict",
            Action::Ambiguous => "ambiguous",
            Action::NotDeclared => "not_declared",
            Action::NotApplicable => "not_applicable",
        }
    }
}

/// One destination field's finding. `found` holds the source names that landed on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdoptRow {
    pub found: Vec<String>,
    pub product: Option<String>,
    pub key: Option<String>,
    pub action: Action,
}

/// The adoption plan: rows (names only) and the writes to apply.
pub struct AdoptPlan {
    pub rows: Vec<AdoptRow>,
    pub writes: Vec<(String, String, SecretValue)>,
}

impl fmt::Debug for AdoptPlan {
    /// Names only: a write's value is never printed (SR-1).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let writes: Vec<(&str, &str)> = self
            .writes
            .iter()
            .map(|(p, k, _)| (p.as_str(), k.as_str()))
            .collect();
        f.debug_struct("AdoptPlan")
            .field("rows", &self.rows)
            .field("writes", &writes)
            .finish()
    }
}

/// How a found name resolved to a declared key.
enum Mapped {
    /// A declared `(product, key)` (before any `from` redirection).
    Key(String, String),
    /// A bare name matching several declared keys.
    Ambiguous,
    /// No declared key for this environment.
    NotDeclared,
}

/// Every declared key of `env_name`, as `(product, key)`.
fn declared_for(fleet: &Fleet, env_name: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (product, p) in &fleet.products {
        for (key, spec) in &p.keys {
            if spec.environments.iter().any(|e| e == env_name) {
                out.push((product.clone(), key.clone()));
            }
        }
    }
    out
}

/// Map a found name to a declared key (FR-53): the rendered target name first, else the
/// bare key name; several bare matches are ambiguous, none is not-declared.
fn map_name(env: &Environment, declared: &[(String, String)], name: &str) -> Mapped {
    let target: Vec<&(String, String)> = declared
        .iter()
        .filter(|(p, k)| env.target_name(p, k).as_deref() == Some(name))
        .collect();
    match target.as_slice() {
        [one] => return Mapped::Key(one.0.clone(), one.1.clone()),
        [_, _, ..] => return Mapped::Ambiguous,
        [] => {}
    }
    let bare: Vec<&(String, String)> = declared.iter().filter(|(_, k)| k == name).collect();
    match bare.as_slice() {
        [] => Mapped::NotDeclared,
        [one] => Mapped::Key(one.0.clone(), one.1.clone()),
        _ => Mapped::Ambiguous,
    }
}

/// The field a found value is planned for: the key's own field, or its shared source's
/// `(product, key)` (FR-45).
fn destination(fleet: &Fleet, product: &str, key: &str) -> (String, String) {
    match fleet.products[product].keys[key].source() {
        Some((sp, sk)) => (sp.to_string(), sk.to_string()),
        None => (product.to_string(), key.to_string()),
    }
}

/// Plan the adoption of `found` values into the item of `env_name` (FR-53).
///
/// Panics only if `env_name` is not a defined environment (callers check first), like
/// [`crate::domain::plan::build_with`].
pub fn plan(
    fleet: &Fleet,
    env_name: &str,
    item: &[ItemField],
    found: &BTreeMap<String, SecretValue>,
    replace: &BTreeSet<(String, String)>,
    rotate: &BTreeSet<(String, String)>,
) -> AdoptPlan {
    let env = fleet
        .environments
        .get(env_name)
        .unwrap_or_else(|| panic!("undefined environment {env_name}"));
    let declared = declared_for(fleet, env_name);

    let mut rows: Vec<AdoptRow> = Vec::new();
    // Destination field -> the found values that landed on it, in name order.
    let mut groups: BTreeMap<(String, String), Vec<(&str, &SecretValue)>> = BTreeMap::new();
    for (name, value) in found {
        match map_name(env, &declared, name) {
            Mapped::Key(product, key) => {
                let dest = destination(fleet, &product, &key);
                groups.entry(dest).or_default().push((name.as_str(), value));
            }
            Mapped::Ambiguous => rows.push(AdoptRow {
                found: vec![name.clone()],
                product: None,
                key: None,
                action: Action::Ambiguous,
            }),
            Mapped::NotDeclared => rows.push(AdoptRow {
                found: vec![name.clone()],
                product: None,
                key: None,
                action: Action::NotDeclared,
            }),
        }
    }

    let mut writes: Vec<(String, String, SecretValue)> = Vec::new();
    for ((product, key), entries) in &groups {
        let spec = &fleet.products[product].keys[key];

        // Normalise every found value with the destination key's rules (FR-53).
        let mut normalised: Vec<SecretValue> = Vec::new();
        let mut failed: Option<&'static str> = None;
        let mut not_applicable = false;
        for (_, value) in entries {
            match rules::check(product, key, spec, env_name, env, value) {
                Ok(Some(v)) => normalised.push(v),
                Ok(None) => not_applicable = true,
                Err(f) => failed = failed.or(Some(f.rule)),
            }
        }

        let (action, write) = if let Some(rule) = failed {
            (Action::FailsRule(rule), false)
        } else if not_applicable || normalised.is_empty() {
            (Action::NotApplicable, false)
        } else if normalised
            .iter()
            .any(|v| v.expose() != normalised[0].expose())
        {
            (Action::Conflict, false)
        } else {
            let raw_all_equal = entries
                .iter()
                .all(|(_, v)| v.expose() == entries[0].1.expose());
            let found_raw = entries[0].1.expose();
            let current = item
                .iter()
                .find(|f| f.section == *product && f.label == *key);
            match current {
                None => (Action::Import, true),
                Some(c) if c.value.expose().is_empty() => (Action::Import, true),
                Some(c) if raw_all_equal && found_raw == c.value.expose() => (Action::Match, false),
                Some(c) => {
                    let current_norm = rules::check(product, key, spec, env_name, env, &c.value);
                    let format_only = matches!(
                        current_norm,
                        Ok(Some(ref cv)) if cv.expose() == normalised[0].expose()
                    );
                    if format_only {
                        (Action::FormatOnly, false)
                    } else if replace.contains(&(product.clone(), key.clone())) {
                        if spec.immutable && !rotate.contains(&(product.clone(), key.clone())) {
                            (Action::HeldImmutable, false)
                        } else {
                            (Action::Replace, true)
                        }
                    } else {
                        (Action::Differs, false)
                    }
                }
            }
        };

        if write {
            let value = normalised
                .into_iter()
                .next()
                .expect("a normalised value to write");
            writes.push((product.clone(), key.clone(), value));
        }
        rows.push(AdoptRow {
            found: entries.iter().map(|(n, _)| (*n).to_string()).collect(),
            product: Some(product.clone()),
            key: Some(key.clone()),
            action,
        });
    }

    rows.sort_by(|a, b| (&a.product, &a.key, &a.found).cmp(&(&b.product, &b.key, &b.found)));
    writes.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    AdoptPlan { rows, writes }
}

#[cfg(test)]
#[path = "adopt_tests.rs"]
mod tests;
