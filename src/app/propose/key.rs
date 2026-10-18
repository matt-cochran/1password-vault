//! `opv propose key|env|retire` (design Part V, row `propose-key`): edit a
//! [`ConfigDoc`] in memory from a categorical [`Intent`], validate the result with the same
//! loader as a hand-written file, and return the contract diff, the relaxations it makes
//! against the default branch (listed first), the questions it asks and a content-addressed
//! plan id.
//!
//! Pure: [`propose`] reads no file and runs no command. Only [`write`] touches the contract
//! file. No rule parameter, no value and no digest of a value is ever carried.

use std::path::Path;

use sha2::{Digest, Sha256};
use toml_edit::Value;

use super::{Proposal, Question};
use crate::cause::{Cause, GivenBy, NameKind, UsageProblem};
use crate::config;
use crate::config::bindings::Bindings;
use crate::config_edit::{ConfigDoc, NewKey};
use crate::domain::catalog;
use crate::domain::intent::{self, FieldKind, Intent, ProductName, SourceKind};
use crate::domain::relaxation;
use crate::domain::{Fleet, Kind, Rules, Tier};
use crate::error::Error;

fn usage(problem: UsageProblem) -> Error {
    Cause::Usage { problem }.into()
}

/// What a person's command line adds to a key intent beyond the categorical document: rule
/// parameters (`--rule`, reviewed in the pull request and counted only once committed on the
/// default branch). An assistant's intent never carries one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Extras {
    /// `name=value` or `name` (a flag rule), as [`rule`] reads them.
    pub rules: Vec<String>,
}

/// The proposal a categorical intent implies for `contract_text`, against the
/// default-branch contract `base` (whose relaxations the proposal lists first). `bindings`
/// are the ids of `secrets.bindings.toml`, used only to validate; the diff never holds an id.
pub fn propose(
    contract_text: &str,
    bindings: &Bindings,
    base: Option<&Fleet>,
    intent: &Intent,
) -> Result<Proposal, Error> {
    propose_with(contract_text, bindings, base, intent, &Extras::default())
}

/// [`propose`] with a person's [`Extras`] for a key intent (ignored for `env` and
/// `retire`).
pub fn propose_with(
    contract_text: &str,
    bindings: &Bindings,
    base: Option<&Fleet>,
    intent: &Intent,
    extras: &Extras,
) -> Result<Proposal, Error> {
    let rules: Vec<(String, Value)> = extras
        .rules
        .iter()
        .map(|spec| rule(spec))
        .collect::<Result<_, _>>()?;
    // The contract carries no ids (D-G): validate it with its bindings filled in.
    let fleet = config::parse(&config::bindings::merge(contract_text, bindings))?;
    let mut doc = ConfigDoc::parse(contract_text)?;
    let mut questions = Vec::new();
    let kind = match intent {
        Intent::Key {
            key,
            product,
            field_kind,
            environments: named,
            except,
            source,
            shape,
            from,
            personal,
            allow_same_value,
            immutable,
            expires,
            lifecycle,
            guidance,
        } => {
            let product = resolve_product(product.as_ref(), key.as_str(), &fleet)?;
            let named: Vec<String> = named.iter().map(|e| e.to_string()).collect();
            let declared = environments(&named, &doc, &fleet)?;
            // An absent `environments` means every environment (Part V, `presence`): write
            // no list at all unless the intent names some.
            let written: &[String] = if named.is_empty() { &[] } else { &declared };
            let shape_name = shape.as_ref().map(|s| s.as_str());
            let kind = key_kind(*field_kind, shape_name)?;
            let except: Vec<(String, String)> = except
                .iter()
                .map(|(env, reason)| (env.to_string(), reason.0.clone()))
                .collect();
            let excluded: Vec<String> = except.iter().map(|(env, _)| env.clone()).collect();
            let expires_text = expires.map(|d| d.to_string());
            doc.add_key(
                &product,
                key.as_str(),
                &NewKey {
                    kind,
                    environments: written,
                    rules: &rules,
                    guidance: guidance.as_ref().map(|g| g.text.as_str()),
                    immutable: *immutable,
                    from: from.as_ref().map(|r| r.as_str()),
                    personal: *personal,
                    allow_same_value: *allow_same_value,
                    except: &except,
                    source: source.map(source_word),
                    shape: shape_name,
                    expires: expires_text.as_deref(),
                    lifecycle: lifecycle.map(lifecycle_word),
                },
            )?;
            questions = production_questions(&fleet, &named, &excluded);
            "key"
        }
        Intent::Env { env, tier } => {
            doc.add_environment(env.as_str(), &environment_text(env.as_str(), *tier))?;
            "env"
        }
        Intent::Retire { key, product, .. } => {
            let product = resolve_product(product.as_ref(), key.as_str(), &fleet)?;
            doc.set_key_lifecycle(&product, key.as_str(), "retiring")?;
            "retire"
        }
        _ => {
            return Err(usage(UsageProblem::ValueFormat {
                flag: "kind".into(),
                format: "key, env or retire",
            }));
        }
    };
    let proposed = doc.to_string();
    // The same validation as a hand-written file: a proposal that would not load is refused
    // before anything is written.
    let proposed_fleet = config::parse(&config::bindings::merge(&proposed, bindings))?;
    let diff = crate::app::config_cmd::diff(contract_text, &proposed);
    let relaxations = base
        .map(|base| relaxation::relaxations(base, &proposed_fleet))
        .unwrap_or_default();
    Ok(Proposal {
        kind,
        relaxations,
        diff,
        questions,
        plan_id: plan_id(kind, &proposed),
        contract_after: proposed,
    })
}

/// Write `proposal_text` to the contract file `path` only, atomically, and only when the
/// file still holds what was read. No other file is touched.
pub fn write(path: &Path, proposal_text: &str) -> Result<(), Error> {
    let original = std::fs::read_to_string(path)
        .map_err(|e| crate::config_store::unreadable(path, &e, GivenBy::Discovered))?;
    crate::config_edit::replace(path, &original, proposal_text)
}

/// The content-addressed plan id: lowercase hex SHA-256 of the kind and the proposed
/// contract text.
fn plan_id(kind: &str, proposed: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(kind.as_bytes());
    hasher.update(b"\n");
    hasher.update(proposed.as_bytes());
    hex::encode(hasher.finalize())
}

/// `product/KEY` resolution: the intent's product, or the one product that already
/// declares the key. A new key without a product needs one named.
fn resolve_product(
    product: Option<&ProductName>,
    key: &str,
    fleet: &Fleet,
) -> Result<String, Error> {
    if let Some(product) = product {
        return Ok(product.as_str().to_string());
    }
    let owners: Vec<&str> = fleet
        .products
        .iter()
        .filter(|(_, p)| p.keys.contains_key(key))
        .map(|(name, _)| name.as_str())
        .collect();
    match owners.as_slice() {
        [only] => Ok((*only).to_string()),
        [] => Err(usage(UsageProblem::ValueFormat {
            flag: format!("the key {key}"),
            format: "PRODUCT/KEY: a bare KEY names a key one product already declares",
        })),
        _ => Err(Cause::Ambiguous {
            kind: NameKind::Key,
            given: key.to_string(),
            candidates: owners.iter().map(|p| format!("{p}/{key}")).collect(),
        }
        .into()),
    }
}

/// The kind of a new or changed key: the `--kind` attribute, else the shape's catalog kind.
fn key_kind(field_kind: Option<FieldKind>, shape: Option<&str>) -> Result<&'static str, Error> {
    match field_kind {
        Some(FieldKind::Secret) => Ok("secret"),
        Some(FieldKind::Config) => Ok("config"),
        None => match shape.and_then(catalog::lookup) {
            Some(shape) => Ok(match shape.kind {
                Kind::Secret => "secret",
                Kind::Config => "config",
            }),
            None => Err(usage(UsageProblem::NeedsFlag {
                flag: "the new key".into(),
                needs: "--kind secret or --kind config (or a catalog --shape)".into(),
            })),
        },
    }
}

fn source_word(source: SourceKind) -> &'static str {
    match source {
        SourceKind::Person => "person",
        SourceKind::Generated => "generated",
        SourceKind::Derived => "derived",
    }
}

fn lifecycle_word(lifecycle: intent::Lifecycle) -> &'static str {
    match lifecycle {
        intent::Lifecycle::Active => "active",
        intent::Lifecycle::Retiring => "retiring",
        intent::Lifecycle::Retired => "retired",
    }
}

/// The TOML fragment declaring `[environments.<env>]` with its tier.
fn environment_text(env: &str, tier: Option<intent::Tier>) -> String {
    match tier {
        Some(tier) => format!(
            "[environments.{env}]\ntier = \"{}\"\n",
            match tier {
                intent::Tier::Local => "local",
                intent::Tier::Shared => "shared",
                intent::Tier::Production => "production",
            }
        ),
        None => format!("[environments.{env}]\n"),
    }
}

/// One question per production-tier environment the new key is present in (an absent list
/// means every environment; `except` removes one).
fn production_questions(fleet: &Fleet, named: &[String], except: &[String]) -> Vec<Question> {
    let present: Vec<&str> = if named.is_empty() {
        fleet.environments.keys().map(String::as_str).collect()
    } else {
        named.iter().map(String::as_str).collect()
    };
    present
        .into_iter()
        .filter(|env| !except.iter().any(|e| e == env))
        .filter(|env| {
            fleet
                .environments
                .get(*env)
                .is_some_and(|e| e.tier == Tier::Production)
        })
        .map(|env| Question {
            env: env.to_string(),
            ask: "a value, or except?".to_string(),
        })
        .collect()
}

/// The environments to declare: the given ones (each defined, duplicates dropped), or every
/// environment in file order. An undeclared one is `NotDeclared` (R21): a unique close name
/// gives the same command with it; an environment is declared before its keys.
pub(crate) fn environments(
    given: &[String],
    doc: &ConfigDoc,
    fleet: &Fleet,
) -> Result<Vec<String>, Error> {
    if given.is_empty() {
        return Ok(doc.environments());
    }
    let mut out: Vec<String> = Vec::new();
    for e in given {
        crate::app::environment(fleet, e)?;
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
pub(crate) fn rule(spec: &str) -> Result<(String, Value), Error> {
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
#[path = "key_tests.rs"]
mod tests;
