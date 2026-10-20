//! The categorical intent document (deliverable `intent`, design R2 and §25.2): the one
//! form `opv_propose` accepts.
//!
//! The document names things and chooses among closed attributes. It can never carry a rule
//! parameter (a regex, a prefix, an `enum=` list) or a value: an unknown field is refused,
//! and a catalog shape is the only way to ask for a rule-backed key. Free text (guidance and
//! an `except` reason) is screened before it is accepted, so a pasted value is refused with
//! [`Cause::ValueInTextField`] naming the field and the detector and never the text.
//!
//! [`parse`] is the one entry point (a JSON document in, a typed [`Intent`] out); [`json_schema`]
//! is the hand-built JSON Schema draft 2020-12 MCP advertises. Everything here is pure: no
//! I/O, no vendor, no clock.

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use serde::de::Deserializer;
use serde::{Deserialize, Serialize};

use crate::cause::{Cause, ConfigSource, DottedPath, FieldRule, GivenBy, PatternId};
use crate::domain::Date;
use crate::domain::catalog;
use crate::error::Error;

/// A name opv validated at its source, shown as it is. Each name kind is its own type, so a
/// key name can never be passed where an environment is meant.
macro_rules! text_newtype {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Wrap text the caller already knows is a name; [`parse`] checks the grammar.
            pub fn new(s: impl Into<String>) -> Self {
                Self(s.into())
            }
            /// The name as written.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

text_newtype!(ProductName, "A product name, `^[a-z][a-z0-9-]*$`.");
text_newtype!(KeyName, "A key name, `^[A-Z][A-Z0-9_]*$`.");
text_newtype!(EnvName, "An environment name, `^[a-z][a-z0-9-]*$`.");
text_newtype!(TargetName, "A target name, `^[a-z][a-z0-9-]*$`.");
text_newtype!(
    ShapeName,
    "A catalog shape name (checked against [`crate::domain::catalog`])."
);
text_newtype!(KeyRef, "A reference to a key: `[product/]KEY`.");

/// The field kind a key is stored as (design §2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    Secret,
    Config,
}

/// Who or what produces a value (design §2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Person,
    Generated,
    Derived,
    /// Produced by infrastructure and supplied at sync, never stored (#206).
    Infrastructure,
}

/// An environment's tier (design §2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Local,
    Shared,
    Production,
}

/// A key's lifecycle (design §10.2): retire moves through the states in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    Active,
    Retiring,
    Retired,
}

/// Who wrote a piece of accepted free text: only the assistant may, and it is stored labelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuidanceOrigin {
    AssistantWritten,
}

/// One line of guidance, accepted only after screening (C7, P-2). It is stored with its
/// origin so a reader can tell the assistant wrote it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Guidance {
    pub text: String,
    pub origin: GuidanceOrigin,
}

impl Guidance {
    /// Wrap text a caller already screened.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            origin: GuidanceOrigin::AssistantWritten,
        }
    }
}

impl<'de> Deserialize<'de> for Guidance {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Guidance::new(String::deserialize(d)?))
    }
}

/// An `except` reason: one screened line, like guidance, but not labelled assistant-written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reason(pub String);

impl<'de> Deserialize<'de> for Reason {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Reason(String::deserialize(d)?))
    }
}

/// The categorical intent document (R2). One `kind` per document; every other field is a
/// name, an enumerated attribute, a reference or screened free text.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Intent {
    /// A new or changed key.
    Key {
        key: KeyName,
        #[serde(default)]
        product: Option<ProductName>,
        /// The `--kind` attribute (secret or config); `field_kind` because `kind` is the tag.
        #[serde(default)]
        field_kind: Option<FieldKind>,
        #[serde(default)]
        environments: Vec<EnvName>,
        /// Environments this key is absent from, each with a screened reason.
        #[serde(default)]
        except: BTreeMap<EnvName, Reason>,
        #[serde(default)]
        source: Option<SourceKind>,
        #[serde(default)]
        shape: Option<ShapeName>,
        #[serde(default)]
        from: Option<KeyRef>,
        #[serde(default)]
        personal: bool,
        #[serde(default)]
        allow_same_value: bool,
        #[serde(default)]
        immutable: bool,
        #[serde(default)]
        expires: Option<Date>,
        #[serde(default)]
        lifecycle: Option<Lifecycle>,
        #[serde(default)]
        guidance: Option<Guidance>,
    },
    /// A new environment, inheriting every `all` key.
    Env {
        env: EnvName,
        #[serde(default)]
        tier: Option<Tier>,
    },
    /// A new target.
    Target {
        env: EnvName,
        name: TargetName,
        /// The provider name whose options are given; the options themselves are not values.
        #[serde(default)]
        provider: Option<String>,
        #[serde(default)]
        products: Vec<ProductName>,
        #[serde(default)]
        role: Option<String>,
        #[serde(default)]
        deploy_credentials: Option<String>,
        /// The provider's options by flag name, as `opv target add` takes them (`fly-app`):
        /// public names and identifiers, checked against the provider's option table.
        #[serde(default)]
        options: BTreeMap<String, String>,
        #[serde(default)]
        guidance: Option<Guidance>,
    },
    /// Retirement in order: needs, prune, archive.
    Retire {
        key: KeyName,
        #[serde(default)]
        product: Option<ProductName>,
        #[serde(default)]
        guidance: Option<Guidance>,
    },
    /// First setup: the contract from an existing item or from a `.env`'s names.
    Setup {
        #[serde(default)]
        from_item: Option<EnvName>,
        #[serde(default)]
        vault: Option<String>,
        #[serde(default)]
        item: Option<String>,
        #[serde(default)]
        names_from: Option<String>,
        #[serde(default)]
        config_key: Vec<String>,
        #[serde(default)]
        secret_key: Vec<String>,
        #[serde(default)]
        file: bool,
        #[serde(default)]
        project: Option<String>,
        #[serde(default)]
        account: Option<String>,
        #[serde(default)]
        guidance: Option<Guidance>,
    },
    /// The structure the contract declares, or new ids for an environment.
    Structure {
        #[serde(default)]
        rebind: Vec<EnvName>,
        #[serde(default)]
        guidance: Option<Guidance>,
    },
    /// Generated values for rule-backed keys.
    Generate {
        env: EnvName,
        #[serde(default)]
        keys: Vec<KeyRef>,
        #[serde(default)]
        guidance: Option<Guidance>,
    },
    /// A person's attestation of held immutable keys on one staged target (#201): their
    /// evidence recorded at the target's current version without a write.
    Attest {
        env: EnvName,
        target: TargetName,
        /// `product/KEY` each; at least one.
        keys: Vec<KeyRef>,
    },
}

/// Parse the one JSON intent document (design §25.2). An unknown field is refused before
/// deserialization, so no rule parameter or value can reach the typed document.
pub fn parse(json: &str) -> Result<Intent, Error> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|_| bad("intent", FieldRule::Syntax))?;
    reject_unknown_fields(&value)?;
    let intent: Intent =
        serde_json::from_str(json).map_err(|_| bad("intent", FieldRule::Syntax))?;
    validate(&intent)?;
    Ok(intent)
}

/// The fields each kind accepts; an unknown one is refused naming itself.
fn allowed_fields(kind: &str) -> Option<&'static [&'static str]> {
    Some(match kind {
        "key" => &[
            "kind",
            "key",
            "product",
            "field_kind",
            "environments",
            "except",
            "source",
            "shape",
            "from",
            "personal",
            "allow_same_value",
            "immutable",
            "expires",
            "lifecycle",
            "guidance",
        ],
        "env" => &["kind", "env", "tier"],
        "target" => &[
            "kind",
            "env",
            "name",
            "provider",
            "products",
            "role",
            "deploy_credentials",
            "options",
            "guidance",
        ],
        "retire" => &["kind", "key", "product", "guidance"],
        "setup" => &[
            "kind",
            "from_item",
            "vault",
            "item",
            "names_from",
            "config_key",
            "secret_key",
            "file",
            "project",
            "account",
            "guidance",
        ],
        "structure" => &["kind", "rebind", "guidance"],
        "generate" => &["kind", "env", "keys", "guidance"],
        "attest" => &["kind", "env", "target", "keys"],
        _ => return None,
    })
}

/// Refuse any top-level field the kind does not accept (a `regex`, `rule`, `value`, …).
fn reject_unknown_fields(value: &serde_json::Value) -> Result<(), Error> {
    let Some(obj) = value.as_object() else {
        return Ok(());
    };
    let Some(kind) = obj.get("kind").and_then(serde_json::Value::as_str) else {
        return Ok(());
    };
    let Some(allowed) = allowed_fields(kind) else {
        return Ok(());
    };
    for field in obj.keys() {
        if !allowed.contains(&field.as_str()) {
            return Err(bad(field, FieldRule::Unknown { suggestion: None }));
        }
    }
    Ok(())
}

/// Check the grammar of every name, that each shape is in the catalog, and screen free text.
fn validate(intent: &Intent) -> Result<(), Error> {
    match intent {
        Intent::Key {
            key,
            product,
            environments,
            except,
            shape,
            guidance,
            ..
        } => {
            check_key("key", key)?;
            if let Some(p) = product {
                check_product("product", p)?;
            }
            for (i, env) in environments.iter().enumerate() {
                check_env(&format!("environments[{i}]"), env)?;
            }
            for (env, reason) in except {
                check_env(&format!("except.{env}"), env)?;
                screen(&format!("except.{env}"), &reason.0)?;
            }
            if let Some(s) = shape {
                check_shape("shape", s)?;
            }
            if let Some(g) = guidance {
                screen("guidance", &g.text)?;
            }
        }
        Intent::Env { env, .. } => check_env("env", env)?,
        Intent::Target {
            env,
            name,
            provider,
            products,
            role,
            deploy_credentials,
            options,
            guidance,
        } => {
            check_env("env", env)?;
            check_target("name", name)?;
            if let Some(p) = provider {
                check_word("provider", p)?;
            }
            if let Some(r) = role {
                check_word("role", r)?;
            }
            if let Some(d) = deploy_credentials {
                check_reference("deploy_credentials", d)?;
            }
            for (i, p) in products.iter().enumerate() {
                check_product(&format!("products[{i}]"), p)?;
            }
            for (flag, value) in options {
                check_word(&format!("options.{flag}"), flag)?;
                screen(&format!("options.{flag}"), value)?;
            }
            if let Some(g) = guidance {
                screen("guidance", &g.text)?;
            }
        }
        Intent::Retire {
            key,
            product,
            guidance,
        } => {
            check_key("key", key)?;
            if let Some(p) = product {
                check_product("product", p)?;
            }
            if let Some(g) = guidance {
                screen("guidance", &g.text)?;
            }
        }
        Intent::Setup {
            from_item,
            vault,
            item,
            names_from,
            config_key,
            secret_key,
            project,
            account,
            guidance,
            ..
        } => {
            if let Some(env) = from_item {
                check_env("from_item", env)?;
            }
            for (field, text) in [
                ("vault", vault),
                ("item", item),
                ("names_from", names_from),
                ("project", project),
                ("account", account),
            ] {
                if let Some(t) = text {
                    screen(field, t)?;
                }
            }
            for (i, k) in config_key.iter().enumerate() {
                check_key(&format!("config_key[{i}]"), &KeyName::new(k.clone()))?;
            }
            for (i, k) in secret_key.iter().enumerate() {
                check_key(&format!("secret_key[{i}]"), &KeyName::new(k.clone()))?;
            }
            if let Some(g) = guidance {
                screen("guidance", &g.text)?;
            }
        }
        Intent::Structure { rebind, guidance } => {
            for (i, env) in rebind.iter().enumerate() {
                check_env(&format!("rebind[{i}]"), env)?;
            }
            if let Some(g) = guidance {
                screen("guidance", &g.text)?;
            }
        }
        Intent::Generate { env, guidance, .. } => {
            check_env("env", env)?;
            if let Some(g) = guidance {
                screen("guidance", &g.text)?;
            }
        }
        Intent::Attest { env, target, keys } => {
            check_env("env", env)?;
            check_target("target", target)?;
            if keys.is_empty() {
                return Err(bad("keys", FieldRule::Missing));
            }
            for (i, k) in keys.iter().enumerate() {
                let field = format!("keys[{i}]");
                let Some((p, key)) = k.as_str().split_once('/') else {
                    return Err(bad(
                        &field,
                        FieldRule::Type {
                            expected: "<product>/<KEY>",
                        },
                    ));
                };
                check_product(&field, &ProductName::new(p))?;
                check_key(&field, &KeyName::new(key))?;
            }
        }
    }
    Ok(())
}

fn check_product(field: &str, name: &ProductName) -> Result<(), Error> {
    if product_ok(name.as_str()) {
        Ok(())
    } else {
        Err(bad(
            field,
            FieldRule::Pattern {
                id: PatternId::ProductName,
            },
        ))
    }
}

fn check_key(field: &str, name: &KeyName) -> Result<(), Error> {
    if key_ok(name.as_str()) {
        Ok(())
    } else {
        Err(bad(
            field,
            FieldRule::Pattern {
                id: PatternId::KeyName,
            },
        ))
    }
}

fn check_env(field: &str, name: &EnvName) -> Result<(), Error> {
    if lower_dash_ok(name.as_str()) {
        Ok(())
    } else {
        Err(bad(
            field,
            FieldRule::Pattern {
                id: PatternId::TargetName,
            },
        ))
    }
}

fn check_target(field: &str, name: &TargetName) -> Result<(), Error> {
    if lower_dash_ok(name.as_str()) {
        Ok(())
    } else {
        Err(bad(
            field,
            FieldRule::Pattern {
                id: PatternId::TargetName,
            },
        ))
    }
}

fn check_shape(field: &str, name: &ShapeName) -> Result<(), Error> {
    if catalog::lookup(name.as_str()).is_some() {
        Ok(())
    } else {
        Err(bad(field, FieldRule::Unknown { suggestion: None }))
    }
}

/// A provider or role word: `^[a-z][a-z0-9-]*$`, never free text.
fn check_word(field: &str, word: &str) -> Result<(), Error> {
    if lower_dash_ok(word) {
        Ok(())
    } else {
        Err(bad(
            field,
            FieldRule::Pattern {
                id: PatternId::TargetName,
            },
        ))
    }
}

/// An `op://<vault>/<item>` reference: the prefix, then screened like free text so no value
/// can ride in it.
fn check_reference(field: &str, reference: &str) -> Result<(), Error> {
    if !reference.starts_with("op://") {
        return Err(bad(
            field,
            FieldRule::Type {
                expected: "an op://<vault>/<item> reference",
            },
        ));
    }
    screen(field, reference)
}

/// `^[a-z][a-z0-9-]*$`.
fn lower_dash_ok(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some('a'..='z'))
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// `^[A-Z][A-Z0-9_]*$`.
fn key_ok(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some('A'..='Z'))
        && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// `^[a-z][a-z0-9-]*$`.
fn product_ok(s: &str) -> bool {
    lower_dash_ok(s)
}

/// The pattern prefixes a pasted value may carry (C7, P-2). `-----BEGIN` is a PEM header and
/// is reported by [`Detector::PemHeader`], so it is not listed here (it is screened first).
const KNOWN_PREFIXES: &[&str] = &[
    "sk_live_",
    "sk_test_",
    "sk-",
    "ghp_",
    "gho_",
    "github_pat_",
    "xoxb-",
    "xoxp-",
    "AKIA",
    "AIza",
];

/// The stable names of the guidance detectors (C7, P-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Detector {
    KnownPrefix,
    PemHeader,
    HighEntropy,
}

impl Detector {
    fn name(self) -> &'static str {
        match self {
            Detector::KnownPrefix => "known_prefix",
            Detector::PemHeader => "pem_header",
            Detector::HighEntropy => "high_entropy",
        }
    }
}

/// Screen one line of free text: at most 200 characters, one line, no value shape (C7, P-2).
fn screen(field: &str, text: &str) -> Result<(), Error> {
    if text.contains('\n') || text.contains('\r') {
        return Err(bad(
            field,
            FieldRule::Type {
                expected: "one line",
            },
        ));
    }
    if text.chars().count() > 200 {
        return Err(bad(
            field,
            FieldRule::Type {
                expected: "one line of at most 200 characters",
            },
        ));
    }
    match detect(text) {
        Some(detector) => Err(value_in_text(field, detector.name())),
        None => Ok(()),
    }
}

/// The detector that matched `text`, if any. PEM is checked first so a block header names
/// `pem_header`; a prefix token names `known_prefix`; a long, varied token names `high_entropy`.
fn detect(text: &str) -> Option<Detector> {
    if text.contains("-----BEGIN") {
        return Some(Detector::PemHeader);
    }
    if text
        .split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '(' | ',' | ':' | '='))
        .any(|token| KNOWN_PREFIXES.iter().any(|p| token.starts_with(p)))
    {
        return Some(Detector::KnownPrefix);
    }
    if text
        .split_whitespace()
        .any(|token| token.chars().count() >= 20 && entropy_bits(token) > 4.0)
    {
        return Some(Detector::HighEntropy);
    }
    None
}

/// Shannon entropy in bits per character.
fn entropy_bits(token: &str) -> f64 {
    let n = token.chars().count() as f64;
    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in token.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    counts
        .values()
        .map(|&count| {
            let p = count as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// A [`Cause::ConfigInvalid`] for one intent field, before it is applied.
fn bad(field: &str, rule: FieldRule) -> Error {
    Cause::ConfigInvalid {
        source: ConfigSource::File {
            path: "intent.json".into(),
            given_by: GivenBy::Discovered,
        },
        at: None,
        field: DottedPath(vec![field.to_string()]),
        rule,
    }
    .into()
}

/// A refusal that names the field and the detector, never the text (C7, P-2).
fn value_in_text(field: &str, detector: &'static str) -> Error {
    Cause::ValueInTextField {
        field: DottedPath(vec![field.to_string()]),
        detector,
    }
    .into()
}

/// The JSON Schema draft 2020-12 MCP advertises for `opv_propose` (design §25.2). One `oneOf`
/// arm per kind; every closed attribute is an `enum`, every name carries its `pattern`, and a
/// shape is limited to the catalog's names.
pub fn json_schema() -> serde_json::Value {
    let name = |pattern: &str| serde_json::json!({ "type": "string", "pattern": pattern });
    let key = || name("^[A-Z][A-Z0-9_]*$");
    let product = || name("^[a-z][a-z0-9-]*$");
    let env = || name("^[a-z][a-z0-9-]*$");
    let target = || name("^[a-z][a-z0-9-]*$");
    let guidance = || serde_json::json!({ "type": "string", "maxLength": 200 });
    let strings = || serde_json::json!({ "type": "array", "items": { "type": "string" } });
    let products = || serde_json::json!({ "type": "array", "items": product() });
    let envs = || serde_json::json!({ "type": "array", "items": env() });
    let object = |properties: serde_json::Value, required: serde_json::Value| {
        serde_json::json!({
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": false
        })
    };

    let key_kind = object(
        serde_json::json!({
            "kind": { "enum": ["key"] },
            "key": key(),
            "product": product(),
            "field_kind": { "enum": ["secret", "config"] },
            "environments": envs(),
            "except": {
                "type": "object",
                "additionalProperties": guidance()
            },
            "source": { "enum": ["person", "generated", "derived", "infrastructure"] },
            "shape": { "enum": catalog::names() },
            "from": { "type": "string" },
            "personal": { "type": "boolean" },
            "allow_same_value": { "type": "boolean" },
            "immutable": { "type": "boolean" },
            "expires": name("^[0-9]{4}-[0-9]{2}-[0-9]{2}$"),
            "lifecycle": { "enum": ["active", "retiring", "retired"] },
            "guidance": guidance()
        }),
        serde_json::json!(["kind", "key"]),
    );
    let env_kind = object(
        serde_json::json!({
            "kind": { "enum": ["env"] },
            "env": env(),
            "tier": { "enum": ["local", "shared", "production"] }
        }),
        serde_json::json!(["kind", "env"]),
    );
    let target_kind = object(
        serde_json::json!({
            "kind": { "enum": ["target"] },
            "env": env(),
            "name": target(),
            "provider": { "type": "string" },
            "products": products(),
            "role": { "type": "string" },
            "deploy_credentials": { "type": "string" },
            "options": { "type": "object", "propertyNames": { "pattern": "^[a-z][a-z0-9-]*$" }, "additionalProperties": { "type": "string", "maxLength": 200 } },
            "guidance": guidance()
        }),
        serde_json::json!(["kind", "env", "name"]),
    );
    let retire_kind = object(
        serde_json::json!({
            "kind": { "enum": ["retire"] },
            "key": key(),
            "product": product(),
            "guidance": guidance()
        }),
        serde_json::json!(["kind", "key"]),
    );
    let setup_kind = object(
        serde_json::json!({
            "kind": { "enum": ["setup"] },
            "from_item": env(),
            "vault": { "type": "string" },
            "item": { "type": "string" },
            "names_from": { "type": "string" },
            "config_key": strings(),
            "secret_key": strings(),
            "file": { "type": "boolean" },
            "project": { "type": "string" },
            "account": { "type": "string" },
            "guidance": guidance()
        }),
        serde_json::json!(["kind"]),
    );
    let structure_kind = object(
        serde_json::json!({
            "kind": { "enum": ["structure"] },
            "rebind": envs(),
            "guidance": guidance()
        }),
        serde_json::json!(["kind"]),
    );
    let generate_kind = object(
        serde_json::json!({
            "kind": { "enum": ["generate"] },
            "env": env(),
            "keys": strings(),
            "guidance": guidance()
        }),
        serde_json::json!(["kind", "env"]),
    );
    let attest_kind = object(
        serde_json::json!({
            "kind": { "enum": ["attest"] },
            "env": env(),
            "target": target(),
            "keys": {
                "type": "array",
                "minItems": 1,
                "items": name("^[a-z][a-z0-9-]*/[A-Z][A-Z0-9_]*$")
            }
        }),
        serde_json::json!(["kind", "env", "target", "keys"]),
    );

    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "opv intent document",
        "type": "object",
        "oneOf": [
            key_kind,
            env_kind,
            target_kind,
            retire_kind,
            setup_kind,
            structure_kind,
            generate_kind,
            attest_kind
        ]
    })
}

#[cfg(test)]
#[path = "intent_tests.rs"]
mod tests;
