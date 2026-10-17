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
//! Makes no target call and reads no item: a person's `opv check <env> --product <p>` adds
//! the empty field and its value is typed in 1Password (FR-11, SR-5). Names, kinds and rules
//! only, never a value.

use std::io::Write;

use toml_edit::Value;

use super::write_err;
use crate::cause::render::cmd_text;
use crate::cause::{Cause, Cmd, NameKind, UsageProblem};
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
    /// `--from <product>/<KEY>`: read the value of another key (a shared value, FR-45).
    pub from: Option<String>,
    /// `--personal`: each person's own value (FR-55).
    pub personal: bool,
    /// `--allow-same-value`: the same value in several environments is intended (#92).
    pub allow_same_value: bool,
    /// `--json`: print `{key, product, kind, environments, saved_in, changed, next}` (A5).
    pub json: bool,
}

/// `add --json` (A5): what was declared, names and kinds only.
#[allow(clippy::too_many_arguments)]
fn write_json(
    out: &mut dyn Write,
    product: &str,
    key: &str,
    kind: &str,
    envs: &[String],
    place: &str,
    changed: bool,
    next: &str,
) -> Result<(), Error> {
    let doc = serde_json::json!({
        "schema_version": crate::json::SCHEMA_VERSION,
        "product": product,
        "key": key,
        "kind": kind,
        "environments": envs,
        "saved_in": place,
        "changed": changed,
        "next": next,
    });
    writeln!(out, "{doc}").map_err(write_err)
}

fn usage(problem: UsageProblem) -> Error {
    Cause::Usage { problem }.into()
}

/// Run `add` against the configuration in `store` (a file or a manifest; `r` reaches a
/// manifest). Every refusal is a catalog cause with its own step; nothing is written.
pub fn run(
    args: &AddArgs,
    store: &dyn ConfigStore,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    // The text the write is built from: for the manifest, a person's fresh read (I3, C1).
    let base = store.read_for_write(r)?;
    let original = &base.text;
    let place = store.describe();
    // A configuration that does not load is reported as the loader's own cause (its field,
    // line and fix); add has written nothing yet (C14).
    let fleet = store.parse(original)?;
    let (product, key) = split_name(&args.name, &fleet)?;
    let (product, key) = (product.as_str(), key.as_str());
    let mut doc = ConfigDoc::parse(original)?;
    let envs = environments(&args.envs, &doc, &fleet)?;
    let label = format!("{product}/{key}");

    let summary = if doc.has_key(product, key) {
        let existing = doc.key_environments(product, key);
        let declared = fleet
            .products
            .get(product)
            .and_then(|p| p.keys.get(key))
            .map(|k| kind_word(k.kind))
            .unwrap_or("secret");
        // add only adds environments to a declared key; anything else is a hand edit.
        let changes_more = args.kind.as_deref().is_some_and(|k| k != declared)
            || !args.rules.is_empty()
            || args.guidance.is_some()
            || args.immutable
            || args.from.is_some()
            || args.personal
            || args.allow_same_value;
        if changes_more {
            return Err(Cause::AlreadyDeclared {
                kind: NameKind::Key,
                name: label,
            }
            .into());
        }
        let new: Vec<String> = envs.into_iter().filter(|e| !existing.contains(e)).collect();
        if new.is_empty() {
            let first = existing.first().map_or("<env>", String::as_str);
            let next = cmd_text(&check_cmd(first, product));
            if args.json {
                return write_json(out, product, key, declared, &existing, &place, false, &next);
            }
            writeln!(
                out,
                "{label} is already declared for {}; nothing changed",
                existing.join(", ")
            )
            .map_err(write_err)?;
            return writeln!(out, "Next: {next}").map_err(write_err);
        }
        for e in &new {
            doc.add_key_env(product, key, e)?;
        }
        (
            format!("added {} to {label} in {place}", new.join(", ")),
            new,
            declared.to_string(),
        )
    } else {
        let kind = match args.kind.as_deref() {
            Some(k @ ("secret" | "config")) => k,
            Some(_) => {
                return Err(usage(UsageProblem::ValueFormat {
                    flag: "--kind".into(),
                    format: "secret or config",
                }));
            }
            None => {
                return Err(usage(UsageProblem::NeedsFlag {
                    flag: format!("the new key {label}"),
                    needs: "--kind secret (a concealed field) or --kind config (a text field)"
                        .into(),
                }));
            }
        };
        let rules = args
            .rules
            .iter()
            .map(|r| rule(r))
            .collect::<Result<Vec<_>, _>>()?;
        for (i, (n, _)) in rules.iter().enumerate() {
            if rules[..i].iter().any(|(m, _)| m == n) {
                return Err(usage(UsageProblem::ConflictsWith {
                    a: format!("--rule {n}"),
                    b: format!("a second --rule {n}"),
                }));
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
                from: args.from.as_deref(),
                personal: args.personal,
                allow_same_value: args.allow_same_value,
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
        if let Some(f) = &args.from {
            parts.push(format!("from {f}"));
        }
        if args.personal {
            parts.push("personal".into());
        }
        if args.allow_same_value {
            parts.push("allow_same_value".into());
        }
        (
            format!("added {label} to {place} ({})", parts.join("; ")),
            envs,
            kind.to_string(),
        )
    };
    let (line, envs, kind) = summary;

    let text = doc.to_string();
    // The same validation as a hand-written file: names on every target (collisions
    // included, FR-30), rules, environments. Nothing is written when it fails.
    store.parse(&text).map_err(proposed)?;
    config_store::save(store, r, &base, &text)?;

    let first = &envs[0];
    let check = cmd_text(&check_cmd(first, product));
    if args.json {
        return write_json(out, product, key, &kind, &envs, &place, true, &check);
    }
    let open = Cmd {
        command: vec!["open".into()],
        args: vec![label.clone(), "--env".into(), first.clone()],
    };
    let w = |out: &mut dyn Write, s: String| writeln!(out, "{s}").map_err(write_err);
    w(out, line)?;
    // A person's check creates the empty field and links to it (05.38: the field is made
    // only when the check runs signed in as a person).
    w(
        out,
        format!(
            "then: {check} adds the field to the item when you are signed in ({}); fill it \
             in with {}",
            envs.join(", "),
            cmd_text(&open)
        ),
    )?;
    w(out, format!("Next: {check}"))
}

/// A loader refusal of the text add proposed (and did not write) is the catalog's
/// `ConfigProposalInvalid`, whose message says nothing was written (F2, C14). Its line
/// number points into text that was never saved, so it is dropped; the field and the rule
/// stay, and the field came from opv's proposal only (`from_proposal`).
fn proposed(e: Error) -> Error {
    let Error::Catalog(cause, upstream) = e;
    let cause = match *cause {
        Cause::ConfigInvalid {
            source,
            field,
            rule,
            ..
        } => Cause::ConfigProposalInvalid {
            source,
            field,
            rule,
            from_proposal: true,
        },
        other => other,
    };
    Error::Catalog(Box::new(cause), upstream)
}

/// `opv check <env> --product <p>`, the read that adds the empty field for a person.
fn check_cmd(env: &str, product: &str) -> Cmd {
    Cmd {
        command: vec!["check".into()],
        args: vec![env.to_string(), "--product".into(), product.to_string()],
    }
}

fn kind_word(k: crate::domain::Kind) -> &'static str {
    match k {
        crate::domain::Kind::Secret => "secret",
        crate::domain::Kind::Config => "config",
    }
}

/// `product/KEY`, both names checked like the loader checks them. A bare `KEY` names the
/// key exactly one product declares (05.20); declared by several, it is ambiguous; declared
/// by none, it needs its product.
fn split_name(name: &str, fleet: &crate::domain::Fleet) -> Result<(String, String), Error> {
    let Some((product, key)) = name.split_once('/') else {
        let owners: Vec<&str> = fleet
            .products
            .iter()
            .filter(|(_, p)| p.keys.contains_key(name))
            .map(|(n, _)| n.as_str())
            .collect();
        return match owners.as_slice() {
            [only] => Ok((only.to_string(), name.to_string())),
            [] => Err(usage(UsageProblem::ValueFormat {
                flag: format!("the new key {name}"),
                format: "PRODUCT/KEY: a bare KEY names a key one product already declares",
            })),
            _ => Err(Cause::Ambiguous {
                kind: NameKind::Key,
                given: name.to_string(),
                candidates: owners.iter().map(|p| format!("{p}/{name}")).collect(),
            }
            .into()),
        };
    };
    if !config::is_product_name(product) {
        return Err(usage(UsageProblem::ValueFormat {
            flag: format!("the product {product:?}"),
            format: "a name matching ^[a-z][a-z0-9_-]*$",
        }));
    }
    if !config::is_env_name(key) {
        return Err(usage(UsageProblem::ValueFormat {
            flag: format!("the key {key:?}"),
            format: "a name matching ^[A-Z][A-Z0-9_]*$",
        }));
    }
    Ok((product.to_string(), key.to_string()))
}

/// The environments to declare: the given ones (each defined, duplicates dropped), or every
/// environment in file order. An undeclared one is `NotDeclared` (R21): a unique close name
/// gives the same command with it; an environment is declared before its keys.
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
        super::environment(fleet, e)?;
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
        return Err(usage(UsageProblem::ValueFormat {
            flag: "--rule".into(),
            format: "name=value (or the name of a flag rule)",
        }));
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
    for mut v in candidates {
        v.decor_mut().clear();
        let probe = format!("{name} = {v}");
        if toml::from_str::<Rules>(&probe).is_ok() {
            return Ok((name.to_string(), v));
        }
    }
    Err(usage(UsageProblem::ValueFormat {
        flag: format!("--rule {name}"),
        format: "a rule name and value from the rules reference (configuration.md)",
    }))
}

#[cfg(test)]
#[path = "add_tests.rs"]
mod tests;
