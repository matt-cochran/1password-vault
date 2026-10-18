//! `opv contract`: the contract as data (Part V, R10; owner decision D-G).
//!
//! The contract is emitted as machine-readable data, never as generated code: per component
//! (product) and environment, each key's `name` (the environment variable the code reads),
//! `kind` (`secret` or `config`), the catalog shape name whose rules equal the key's rules
//! (or `null`), and whether it is required there (contract × presence). The document carries
//! a `contract_digest`: the lowercase hex SHA-256 of the canonical JSON of the document
//! without the digest. It holds names and categories only: never a 1Password id, a rule
//! parameter or any part of a value (SR-1).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cause::Cause;
use crate::domain::catalog;
use crate::domain::model::{Fleet, KeySpec, Kind, Rules};
use crate::domain::presence::{self, Presence};
use crate::domain::relaxation::{self, Relaxation};
use crate::error::Error;

/// The kind of a key in the document: `secret` or `config` (the same categories opv uses,
/// without the model's own type, which is not serialized).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContractKind {
    /// A concealed field: a secret.
    Secret,
    /// A text field: config.
    Config,
}

impl ContractKind {
    /// The category of a key's [`Kind`].
    pub fn of(kind: Kind) -> Self {
        match kind {
            Kind::Secret => Self::Secret,
            Kind::Config => Self::Config,
        }
    }
}

/// One key of one component in one environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyContract {
    /// The environment variable name the code reads.
    pub name: String,
    /// `secret` or `config`.
    pub kind: ContractKind,
    /// The catalog shape name whose rules equal the key's rules, when one does; never the
    /// rule parameters. `null` for a key with custom rules.
    pub shape: Option<String>,
    /// Whether the key is present (not `except`ed) in this environment (contract × presence).
    pub required: bool,
}

/// One environment's contract for one component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentContract {
    /// The environment's name.
    pub name: String,
    /// The component's keys in this environment, in name order.
    pub keys: Vec<KeyContract>,
}

/// One component (product) and its environments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentContract {
    /// The component's name (the product).
    pub name: String,
    /// The component's contract in each environment, in name order.
    pub environments: Vec<EnvironmentContract>,
}

/// `opv contract [--env e] [--component p]`'s document, printed compact for `--json` and
/// indented for a person. The CLI and `opv_state` section `contract` both answer through here.
pub fn write_document(
    fleet: &Fleet,
    env: Option<&str>,
    component: Option<&str>,
    json: bool,
    out: &mut dyn std::io::Write,
) -> Result<(), Error> {
    let doc = serde_json::to_value(document(fleet, env, component)).map_err(|_| -> Error {
        Cause::Bug {
            site: "contract: the document did not serialize",
        }
        .into()
    })?;
    let text = if json {
        doc.to_string()
    } else {
        serde_json::to_string_pretty(&doc).unwrap_or_else(|_| doc.to_string())
    };
    writeln!(out, "{text}").map_err(super::write_err)
}

/// The contract as data (R10, D-G): names and categories only, plus the contract digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractDoc {
    /// The components, in name order.
    pub components: Vec<ComponentContract>,
    /// Lowercase hex SHA-256 of the canonical JSON of the document without this field.
    /// Skipped while empty, so it is exactly the bytes [`ContractDoc::seal`] digests.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub contract_digest: String,
}

impl ContractDoc {
    /// The canonical JSON of the document without the digest: compact serialization, where
    /// every collection is already in a stable name order.
    fn canonical(&self) -> String {
        let mut copy = self.clone();
        copy.contract_digest.clear();
        serde_json::to_string(&copy).expect("the contract document serializes")
    }

    /// The document with its digest filled in from its own canonical bytes.
    fn seal(mut self) -> Self {
        self.contract_digest = hex::encode(Sha256::digest(self.canonical().as_bytes()));
        self
    }
}

/// The contract as data (R10, D-G): per component and environment, each key's name, kind,
/// shape name and whether it is required there, plus the contract digest. `env` and
/// `component` narrow the document to one environment or one component.
pub fn document(fleet: &Fleet, env: Option<&str>, component: Option<&str>) -> ContractDoc {
    let components = fleet
        .products
        .iter()
        .filter(|(name, _)| component.is_none_or(|c| c == name.as_str()))
        .map(|(name, product)| ComponentContract {
            name: name.clone(),
            environments: fleet
                .environments
                .keys()
                .filter(|e| env.is_none_or(|x| x == e.as_str()))
                .map(|env_name| EnvironmentContract {
                    name: env_name.clone(),
                    keys: product
                        .keys
                        .iter()
                        .map(|(key, spec)| key_contract(key, spec, env_name))
                        .collect(),
                })
                .collect(),
        })
        .collect();
    ContractDoc {
        components,
        contract_digest: String::new(),
    }
    .seal()
}

/// One key's contract in one environment.
fn key_contract(name: &str, spec: &KeySpec, env: &str) -> KeyContract {
    KeyContract {
        name: name.to_string(),
        kind: ContractKind::of(spec.kind),
        shape: shape_name(&spec.rules),
        required: presence::present_in(spec, env) == Presence::Present,
    }
}

/// The catalog shape name whose rules equal `rules`, if any (the first in name order).
fn shape_name(rules: &Rules) -> Option<String> {
    catalog::names()
        .into_iter()
        .find(|name| catalog::lookup(name).is_some_and(|shape| &shape.rules == rules))
        .map(str::to_string)
}

/// A JSON Schema (draft 2020-12) of the document's own shape: an object with `components`
/// (each with `name` and `environments`, each with `name` and `keys`, each with `name`,
/// `kind`, `shape` and `required`), plus the optional `contract_digest`.
pub fn json_schema(_doc: &ContractDoc) -> serde_json::Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "opv contract",
        "type": "object",
        "required": ["components"],
        "additionalProperties": false,
        "properties": {
            "contract_digest": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
            "components": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["name", "environments"],
                    "additionalProperties": false,
                    "properties": {
                        "name": { "type": "string" },
                        "environments": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["name", "keys"],
                                "additionalProperties": false,
                                "properties": {
                                    "name": { "type": "string" },
                                    "keys": {
                                        "type": "array",
                                        "items": {
                                            "type": "object",
                                            "required": ["name", "kind", "required"],
                                            "additionalProperties": false,
                                            "properties": {
                                                "name": { "type": "string" },
                                                "kind": { "enum": ["secret", "config"] },
                                                "shape": { "type": ["string", "null"] },
                                                "required": { "type": "boolean" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    })
}

/// Compare a committed copy (JSON text) with the current document. Any difference, including
/// text that is not a contract document at all, is `Cause::ContractStale`.
pub fn check(doc: &ContractDoc, committed: &str) -> Result<(), Error> {
    let parsed: ContractDoc = match serde_json::from_str(committed) {
        Ok(doc) => doc,
        Err(_) => return Err(stale_contract()),
    };
    if parsed.canonical() == doc.canonical() {
        Ok(())
    } else {
        Err(stale_contract())
    }
}

/// The stale-committed-copy refusal. The path is filled in by a caller that knows it; the
/// pure comparison does not.
fn stale_contract() -> Error {
    Cause::ContractStale { path: None }.into()
}

/// Every relaxation the working contract `head` makes against the default-branch contract
/// `base` (Part V, `relaxations`): a pure delegation to the domain classifier.
pub fn relaxations(base: &Fleet, head: &Fleet) -> Vec<Relaxation> {
    relaxation::relaxations(base, head)
}

#[cfg(test)]
#[path = "contract_tests.rs"]
mod tests;
