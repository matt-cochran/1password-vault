//! Settings health (#92): likely-wrong values that are present and pass their rules, found
//! from the values opv already read.
//!
//! Pure: [`check`] takes each environment's fields as the caller read them and returns
//! value-free findings. Values are compared in memory with [`SecretValue::expose`] only;
//! no finding, message or error ever holds a value or any part of one (SR-1). Every
//! finding is a warning: the setting may be intended, and the person decides.
//!
//! In scope: a field whose `(section, label)` is a declared key listing that environment.
//! Personal keys (FR-55) and empty values are never looked at. Intentional sameness across
//! environments is declared with `allow_same_value = true`; one value read by several keys
//! within an environment is a shared value (`from`, FR-45), which has one field and so is
//! never a duplicate here.

use std::collections::BTreeMap;

use crate::domain::plan::ItemField;
use crate::domain::{Fleet, KeySpec, Kind};

/// One environment's values, as the caller read them (the team item; never a personal one).
pub struct EnvValues<'a> {
    pub name: &'a str,
    /// Display name (FR-55), used only to tell a production environment.
    pub title: Option<&'a str>,
    /// The environment has a target (it deploys).
    pub deployed: bool,
    pub fields: &'a [ItemField],
}

/// One likely-wrong setting. Names only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthFinding {
    pub code: &'static str,
    /// The environments involved, in the order given to [`check`].
    pub environments: Vec<String>,
    pub product: String,
    pub key: String,
    /// The second key, for `same_value_under_two_keys`.
    pub other: Option<(String, String)>,
    /// One sentence for a person: what looks wrong and what to do. Never a value.
    pub message: String,
}

pub const SAME_ACROSS: &str = "same_value_across_environments";
pub const SAME_UNDER_TWO: &str = "same_value_under_two_keys";
pub const PLACEHOLDER: &str = "placeholder_value";
pub const WHITESPACE: &str = "whitespace_around_value";
pub const LOCAL_ADDRESS: &str = "local_address_in_deployed_environment";
pub const TEST_KEY: &str = "test_key_in_production";
pub const LIVE_KEY: &str = "live_key_outside_production";

/// The codes, in the order findings are reported.
const ORDER: [&str; 7] = [
    SAME_ACROSS,
    SAME_UNDER_TWO,
    PLACEHOLDER,
    WHITESPACE,
    LOCAL_ADDRESS,
    TEST_KEY,
    LIVE_KEY,
];

/// Every likely-wrong setting in `envs`, deterministic: by code (in [`ORDER`]), then
/// environment order, product and key.
pub fn check(fleet: &Fleet, envs: &[EnvValues<'_>]) -> Vec<HealthFinding> {
    let mut out = Vec::new();
    same_across(fleet, envs, &mut out);
    for env in envs {
        let fields: Vec<(&ItemField, &KeySpec)> = in_scope(fleet, env).collect();
        same_under_two(env, &fields, &mut out);
        for (f, spec) in &fields {
            per_value(env, f, spec, &mut out);
        }
    }
    let env_index = |name: &str| {
        envs.iter()
            .position(|e| e.name == name)
            .unwrap_or(usize::MAX)
    };
    out.sort_by(|a, b| {
        let code = |c: &str| ORDER.iter().position(|o| *o == c).unwrap_or(usize::MAX);
        (
            code(a.code),
            a.environments.first().map_or(usize::MAX, |e| env_index(e)),
            &a.product,
            &a.key,
        )
            .cmp(&(
                code(b.code),
                b.environments.first().map_or(usize::MAX, |e| env_index(e)),
                &b.product,
                &b.key,
            ))
    });
    out
}

/// The declared, non-personal, non-empty fields of `env`, with their specs.
fn in_scope<'a>(
    fleet: &'a Fleet,
    env: &'a EnvValues<'a>,
) -> impl Iterator<Item = (&'a ItemField, &'a KeySpec)> + 'a {
    env.fields.iter().filter_map(move |f| {
        let spec = fleet.products.get(&f.section)?.keys.get(&f.label)?;
        let declared_here = spec.environments.iter().any(|e| e == env.name);
        (declared_here && !spec.personal && !f.value.expose().is_empty()).then_some((f, spec))
    })
}

/// `product/KEY`.
fn label(product: &str, key: &str) -> String {
    crate::domain::key_label(product, key)
}

fn finding(
    code: &'static str,
    environments: Vec<String>,
    f: &ItemField,
    other: Option<(String, String)>,
    message: String,
) -> HealthFinding {
    HealthFinding {
        code,
        environments,
        product: f.section.clone(),
        key: f.label.clone(),
        other,
        message,
    }
}

/// A secret with the identical value in two or more environments, per group of equal
/// values, unless the key allows it.
fn same_across(fleet: &Fleet, envs: &[EnvValues<'_>], out: &mut Vec<HealthFinding>) {
    // (product, key) -> [(environment, field)], in environment order.
    let mut by_key: BTreeMap<(&str, &str), Vec<(&str, &ItemField)>> = BTreeMap::new();
    for env in envs {
        for (f, spec) in in_scope(fleet, env) {
            if spec.kind == Kind::Secret && !spec.allow_same_value {
                by_key
                    .entry((f.section.as_str(), f.label.as_str()))
                    .or_default()
                    .push((env.name, f));
            }
        }
    }
    for ((product, key), seen) in by_key {
        let mut grouped = vec![false; seen.len()];
        for i in 0..seen.len() {
            if grouped[i] {
                continue;
            }
            let mut group = vec![seen[i].0.to_string()];
            for j in i + 1..seen.len() {
                if !grouped[j] && seen[j].1.value.expose() == seen[i].1.value.expose() {
                    grouped[j] = true;
                    group.push(seen[j].0.to_string());
                }
            }
            if group.len() < 2 {
                continue;
            }
            let message = format!(
                "{} has the same value in {}; give each environment its own, or set \
                 allow_same_value = true on the key if that is intended",
                label(product, key),
                group.join(" and ")
            );
            out.push(finding(SAME_ACROSS, group, seen[i].1, None, message));
        }
    }
}

/// Two different secrets in one environment holding the identical value.
fn same_under_two(
    env: &EnvValues<'_>,
    fields: &[(&ItemField, &KeySpec)],
    out: &mut Vec<HealthFinding>,
) {
    let mut secrets: Vec<&ItemField> = fields
        .iter()
        .filter(|(_, spec)| spec.kind == Kind::Secret)
        .map(|(f, _)| *f)
        .collect();
    secrets.sort_by(|a, b| (&a.section, &a.label).cmp(&(&b.section, &b.label)));
    for (i, a) in secrets.iter().enumerate() {
        for b in &secrets[i + 1..] {
            if a.value.expose() != b.value.expose() {
                continue;
            }
            let message = format!(
                "{} and {} hold the same value in {}; if one value is meant for both, keep it \
                 once and point the other key at it with from, else fix the wrong one",
                label(&a.section, &a.label),
                label(&b.section, &b.label),
                env.name
            );
            out.push(finding(
                SAME_UNDER_TWO,
                vec![env.name.to_string()],
                a,
                Some((b.section.clone(), b.label.clone())),
                message,
            ));
        }
    }
}

/// The checks of one value on its own.
fn per_value(env: &EnvValues<'_>, f: &ItemField, spec: &KeySpec, out: &mut Vec<HealthFinding>) {
    let value = f.value.expose();
    let name = label(&f.section, &f.label);
    let here = || vec![env.name.to_string()];
    if spec.kind == Kind::Secret && is_placeholder(value) {
        out.push(finding(
            PLACEHOLDER,
            here(),
            f,
            None,
            format!(
                "{name} in {} looks like a placeholder, not a real secret; set the real value",
                env.name
            ),
        ));
    }
    if has_stray_whitespace(value) {
        out.push(finding(
            WHITESPACE,
            here(),
            f,
            None,
            format!(
                "{name} in {} starts or ends with a space, tab or newline, usually a copy-paste \
                 slip; remove it",
                env.name
            ),
        ));
    }
    if env.deployed && points_at_local(value) {
        out.push(finding(
            LOCAL_ADDRESS,
            here(),
            f,
            None,
            // 01.25: the check matches every local-only address, not only localhost.
            format!(
                "{name} in {} points at a local-only address (localhost, 127.0.0.1, 0.0.0.0, \
                 [::1] or host.docker.internal), but {} deploys; set the deployed address",
                env.name, env.name
            ),
        ));
    }
    let production = is_production(env);
    if production
        && ["sk_test_", "pk_test_", "rk_test_"]
            .iter()
            .any(|p| value.starts_with(p))
    {
        out.push(finding(
            TEST_KEY,
            here(),
            f,
            None,
            format!(
                "{name} in {} is a test-mode key in production; set the live key",
                env.name
            ),
        ));
    }
    if !production
        && ["sk_live_", "rk_live_"]
            .iter()
            .any(|p| value.starts_with(p))
    {
        out.push(finding(
            LIVE_KEY,
            here(),
            f,
            None,
            // 01.25: production is told only by the environment's name or title.
            format!(
                "{name} in {} is a live key, but {} is not named as production; use a \
                 test-mode key there, or ignore this if {} is production",
                env.name, env.name, env.name
            ),
        ));
    }
}

/// A known placeholder: a stock word, a run of x, `<…>`, or `your…here`.
fn is_placeholder(value: &str) -> bool {
    const WORDS: [&str; 16] = [
        "changeme",
        "change-me",
        "change_me",
        "replaceme",
        "replace-me",
        "replace_me",
        "todo",
        "tbd",
        "placeholder",
        "example",
        "dummy",
        "secret",
        "password",
        "null",
        "none",
        "undefined",
    ];
    // Compared in place: no copy of the value is made (it would not be zeroized).
    let v = value.trim();
    WORDS.iter().any(|w| v.eq_ignore_ascii_case(w))
        || (v.len() >= 3 && v.bytes().all(|c| c == b'x' || c == b'X'))
        || (v.len() >= 2 && v.starts_with('<') && v.ends_with('>'))
        || (v.len() >= 8
            && v.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("your"))
            && v.get(v.len() - 4..)
                .is_some_and(|s| s.eq_ignore_ascii_case("here")))
}

/// `needle` in `hay`, ASCII case-insensitively, without copying `hay`.
fn contains_ignore_case(hay: &str, needle: &str) -> bool {
    hay.as_bytes()
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle.as_bytes()))
}

/// Leading or trailing whitespace on a single-line value (a multi-line value such as a PEM
/// key is left alone).
fn has_stray_whitespace(value: &str) -> bool {
    let body = value.trim_end_matches(['\n', '\r']);
    !body.contains('\n') && value != value.trim()
}

fn points_at_local(value: &str) -> bool {
    [
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "host.docker.internal",
        "[::1]",
    ]
    .iter()
    .any(|l| contains_ignore_case(value, l))
}

/// A production environment by its name or title: `prod`, but not `preprod` or `nonprod`.
fn is_production(env: &EnvValues<'_>) -> bool {
    let named = |s: &str| {
        let s = s.to_ascii_lowercase();
        s.contains("prod")
            && !s.contains("preprod")
            && !s.contains("pre-prod")
            && !s.contains("nonprod")
    };
    named(env.name) || env.title.is_some_and(named)
}

#[cfg(test)]
#[path = "health_tests.rs"]
mod tests;
