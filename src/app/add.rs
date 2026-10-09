//! `opv add <[product/]KEY> --kind secret|config [--env e …] [--rule name=value …]` (H2).
//!
//! Declares one key in the configuration without hand-editing it, or adds environments to
//! a key already declared. The configuration is a `secrets.toml` or a project manifest in
//! 1Password; both are edited through [`ConfigStore`] the same way (FR-44). The text is
//! edited in place ([`crate::config_edit`]): comments, blank lines and order are kept. The edited text is validated with the same loader as a
//! hand-written file before anything is written, so a name that would collide on any
//! environment's target (FR-30), an unknown rule or a bad rule value is refused and the file
//! is left alone. The write is atomic (a file: a temporary file, then a rename; a manifest:
//! one item edit) and refused when someone changed the configuration since it was read.
//!
//! Makes no target call and reads no item: the field itself is added by `opv item skeleton` and
//! its value typed in 1Password (FR-11, SR-5). Names, kinds and rules only, never a value.

use std::io::Write;

use toml_edit::Value;

use super::write_err;
use crate::config;
use crate::config_edit::{ConfigDoc, NewKey};
use crate::config_store::{self, ConfigStore};
use crate::domain::Rules;
use crate::error::Error;
use crate::runner::CommandRunner;

/// `opv add` arguments.
#[derive(Debug, Clone, Default)]
pub struct AddArgs {
    /// `[product/]KEY`.
    pub name: String,
    /// `secret` or `config`; required for a new key.
    pub kind: Option<String>,
    /// Environments; empty means every declared environment.
    pub envs: Vec<String>,
    /// `name=value` or `name` (a flag rule such as `https_url`).
    pub rules: Vec<String>,
    pub guidance: Option<String>,
    pub immutable: bool,
}

fn cfg(msg: String) -> Error {
    Error::Config(msg.into())
}

/// Run `add` against the configuration in `store` (a file or a manifest; `r` reaches a
/// manifest). A refusal names `opv add --help` as its next step unless it names its own.
pub fn run(
    args: &AddArgs,
    store: &dyn ConfigStore,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    run_inner(args, store, r, out).map_err(|e| match e {
        e @ Error::Config(_) => e.or_next(|| "opv add --help".into()),
        other => other,
    })
}

fn run_inner(
    args: &AddArgs,
    store: &dyn ConfigStore,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let base = store.read(r)?;
    let original = &base.text;
    let place = store.describe();
    let fleet = store.parse(original).map_err(|e| match e {
        e @ Error::Config(_) => e
            .map_text(|m| super::on_first_line(&m, " (fix it first; nothing written)"))
            .or_next(|| "opv config edit".into()),
        other => other,
    })?;
    let fleet_profile = !fleet.is_simple();
    let (product, key) = split_name(&args.name, fleet_profile, &fleet)?;
    let mut doc = ConfigDoc::parse(original)?;
    let envs = environments(&args.envs, &doc, &fleet)?;
    let label = match product {
        Some(p) => format!("{p}/{key}"),
        None => key.to_string(),
    };

    let summary = if doc.has_key(product, key) {
        let existing = doc.key_environments(product, key);
        let declared = fleet
            .products
            .get(product.unwrap_or(crate::domain::SIMPLE_PRODUCT))
            .and_then(|p| p.keys.get(key))
            .map(|k| kind_word(k.kind))
            .unwrap_or("secret");
        if let Some(k) = &args.kind
            && k != declared
        {
            return Err(cfg(format!(
                "{label} is already declared as {declared}; opv add never changes a key's \
                 kind: edit {place} by hand (opv config edit)"
            )));
        }
        if !args.rules.is_empty() || args.guidance.is_some() || args.immutable {
            return Err(cfg(format!(
                "{label} is already declared; opv add only adds environments to it: change \
                 its rules, guidance or immutable in {place} by hand (opv config edit)"
            )));
        }
        let new: Vec<String> = envs.into_iter().filter(|e| !existing.contains(e)).collect();
        if new.is_empty() {
            let first = existing.first().map_or("<env>", String::as_str);
            writeln!(
                out,
                "{label} is already declared for {}; nothing changed",
                existing.join(", ")
            )
            .map_err(write_err)?;
            return writeln!(out, "Next: {}", check_command(first, product)).map_err(write_err);
        }
        for e in &new {
            doc.add_key_env(product, key, e)?;
        }
        (
            format!("added {} to {label} in {place}", new.join(", ")),
            new,
        )
    } else {
        let kind = match args.kind.as_deref() {
            Some(k @ ("secret" | "config")) => k,
            Some(other) => {
                return Err(cfg(format!(
                    "--kind must be secret or config, got {other:?}"
                )));
            }
            None => {
                return Err(cfg(format!(
                    "{label} is a new key: pass --kind secret (a concealed field) or --kind \
                     config (a text field)"
                )));
            }
        };
        let rules = args
            .rules
            .iter()
            .map(|r| rule(r))
            .collect::<Result<Vec<_>, _>>()?;
        for (i, (n, _)) in rules.iter().enumerate() {
            if rules[..i].iter().any(|(m, _)| m == n) {
                return Err(cfg(format!("--rule {n} is given twice")));
            }
        }
        doc.add_key(
            product,
            key,
            &NewKey {
                kind,
                environments: &envs,
                rules: &rules,
                guidance: args.guidance.as_deref(),
                immutable: args.immutable,
            },
        )?;
        let mut parts = vec![kind.to_string(), envs.join(", ")];
        parts.extend(
            rules
                .iter()
                .map(|(n, v)| format!("{n} = {}", v.to_string().trim())),
        );
        if args.immutable {
            parts.push("immutable".into());
        }
        (
            format!("added {label} to {place} ({})", parts.join("; ")),
            envs,
        )
    };
    let (line, envs) = summary;

    let text = doc.to_string();
    // The same validation as a hand-written file: names on every target (collisions
    // included, FR-30), rules, environments.
    store.parse(&text).map_err(|e| match e {
        e @ Error::Config(_) => e.map_text(|m| {
            format!("{m} (in the configuration opv add would write; nothing written)")
        }),
        other => other,
    })?;
    config_store::save(store, r, &base, &text)?;

    let first = &envs[0];
    let w = |out: &mut dyn Write, s: String| writeln!(out, "{s}").map_err(write_err);
    w(out, line)?;
    w(
        out,
        format!(
            "then: opv item skeleton <env> adds the empty field to each environment's item ({}); \
             type the value in 1Password and run {}",
            envs.join(", "),
            check_command(first, product)
        ),
    )?;
    w(out, format!("Next: opv item skeleton {first}"))
}

fn check_command(env: &str, product: Option<&str>) -> String {
    match product {
        Some(p) => format!("opv check {env} --product {p}"),
        None => format!("opv check {env}"),
    }
}

fn kind_word(k: crate::domain::Kind) -> &'static str {
    match k {
        crate::domain::Kind::Secret => "secret",
        crate::domain::Kind::Config => "config",
    }
}

/// `product/KEY` under the fleet profile, `KEY` under the simple one; both names checked
/// like the loader checks them.
fn split_name<'a>(
    name: &'a str,
    fleet_profile: bool,
    fleet: &crate::domain::Fleet,
) -> Result<(Option<&'a str>, &'a str), Error> {
    let (product, key) = match name.split_once('/') {
        Some((p, k)) => (Some(p), k),
        None => (None, name),
    };
    match (fleet_profile, product) {
        (true, None) => {
            let known: Vec<&str> = fleet.products.keys().map(String::as_str).collect();
            let example = known.first().copied().unwrap_or("api");
            return Err(cfg(format!(
                "the fleet profile declares keys per product: opv add {example}/{key} \
                 (products: {})",
                if known.is_empty() {
                    "none yet".to_string()
                } else {
                    known.join(", ")
                }
            )));
        }
        (false, Some(_)) => {
            return Err(cfg(format!(
                "the simple profile has no products: opv add {key}"
            )));
        }
        _ => {}
    }
    if let Some(p) = product
        && !config::is_product_name(p)
    {
        return Err(cfg(format!("product {p:?} must match ^[a-z][a-z0-9_-]*$")));
    }
    if !config::is_env_name(key) {
        return Err(cfg(format!("key {key:?} must match ^[A-Z][A-Z0-9_]*$")));
    }
    Ok((product, key))
}

/// The environments to declare: the given ones (each defined, duplicates dropped), or every
/// environment in file order.
fn environments(
    given: &[String],
    doc: &ConfigDoc,
    fleet: &crate::domain::Fleet,
) -> Result<Vec<String>, Error> {
    if given.is_empty() {
        return Ok(doc.environments());
    }
    let mut out: Vec<String> = Vec::new();
    for e in given {
        fleet.environment(e)?;
        if !out.contains(e) {
            out.push(e.clone());
        }
    }
    Ok(out)
}

/// `--rule name=value` (or `--rule name` for a flag rule) to a rules entry. The value is
/// read as TOML when that is a valid value for the rule (`base64_bytes=32`,
/// `enum=["a","b"]`), else as text (`prefix=sk_`), else as a comma-separated list
/// (`enum=debug,info`). The rule names and types are the loader's own (`Rules`).
fn rule(spec: &str) -> Result<(String, Value), Error> {
    let (name, raw) = match spec.split_once('=') {
        Some((n, v)) => (n.trim(), Some(v)),
        None => (spec.trim(), None),
    };
    if name.is_empty() {
        return Err(cfg(format!("--rule {spec:?}: expected name=value")));
    }
    let candidates: Vec<Value> = match raw {
        None => vec![Value::from(true)],
        Some(raw) => {
            let mut c = Vec::new();
            if let Ok(v) = raw.trim().parse::<Value>() {
                c.push(v);
            }
            c.push(Value::from(raw));
            c.push(Value::Array(
                raw.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .collect(),
            ));
            c
        }
    };
    let mut first = None;
    for mut v in candidates {
        v.decor_mut().clear();
        let probe = format!("{name} = {v}");
        match toml::from_str::<Rules>(&probe) {
            Ok(_) => return Ok((name.to_string(), v)),
            Err(e) => {
                first.get_or_insert_with(|| e.message().trim().to_string());
            }
        }
    }
    Err(cfg(format!(
        "--rule {name}: {}; see {}/configuration.md#rules-reference",
        first.unwrap_or_default(),
        crate::DOCS_URL
    )))
}

#[cfg(test)]
#[path = "add_tests.rs"]
mod tests;
