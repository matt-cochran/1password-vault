//! Fleet configuration model (§10.2). Holds names, IDs and rules; never values (FR-1).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::provider::TargetConfig;

/// Field kind. In 1Password a concealed field is a secret and a text field is config (FR-14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Secret,
    Config,
}

/// Declarative validation rules for one key (FR-15). Every rule is optional.
/// Evaluated by the rules engine (`domain::rules`); this type only carries them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Rules {
    pub prefix: Option<String>,
    pub not_prefix: Option<OneOrMany>,
    /// Accept the value with or without this prefix and stage exactly one occurrence (FR-24).
    pub ensure_prefix: Option<String>,
    /// Full match required of the text after `ensure_prefix`; valid only with it (FR-24).
    pub pattern: Option<String>,
    pub regex: Option<String>,
    #[serde(rename = "enum")]
    pub r#enum: Option<Vec<String>>,
    pub base64_bytes: Option<usize>,
    pub hex_bytes: Option<usize>,
    pub email_list: bool,
    pub https_url: bool,
    pub prefix_by_mode: Option<PrefixByMode>,
    pub refuse_in: Vec<String>,
    pub transform: Option<String>,
}

/// A string or a list of strings in TOML (`x = "a"` or `x = ["a", "b"]`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        let (one, many): (Option<&str>, &[String]) = match self {
            Self::One(s) => (Some(s.as_str()), &[]),
            Self::Many(v) => (None, v.as_slice()),
        };
        one.into_iter().chain(many.iter().map(String::as_str))
    }

    /// True when the value starts with any listed prefix.
    pub fn any_prefix_of(&self, v: &str) -> bool {
        self.iter().any(|p| v.starts_with(p))
    }

    /// Config validation: at least one entry, none empty.
    pub fn is_valid(&self) -> bool {
        self.iter().next().is_some() && self.iter().all(|s| !s.is_empty())
    }
}

/// Required prefix chosen by an environment mode, e.g. `payments = "test"` → `sk_test_`.
/// Modes listed in `skip` mean the key is not required in that environment.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrefixByMode {
    pub mode: String,
    pub values: BTreeMap<String, OneOrMany>,
    #[serde(default)]
    pub skip: Vec<String>,
}

/// One declared key of a product.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeySpec {
    pub kind: Kind,
    pub environments: Vec<String>,
    #[serde(default)]
    pub rules: Rules,
    /// Staged only when absent on the target unless explicitly rotated (FR-16).
    #[serde(default)]
    pub immutable: bool,
    #[serde(default)]
    pub guidance: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Product {
    pub keys: BTreeMap<String, KeySpec>,
}

/// One deployment environment: one 1Password item (by IDs, FR-13) and, optionally, one
/// deployment target.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Environment {
    /// The environment's name in the configuration (for messages: `opv login <name>`).
    pub name: String,
    pub vault_id: String,
    pub item_id: String,
    /// The deployment target (FR-28, FR-37): `None` when the environment declares none.
    pub target: Option<Box<dyn TargetConfig>>,
    /// product → mode name → mode value, e.g. `allumata.payments = "off"`.
    pub modes: BTreeMap<String, BTreeMap<String, String>>,
    /// The 1Password account every `op` call for this environment uses (FR-40): a sign-in
    /// address or account ID. `None`: op's default (or the service account in CI).
    pub account: Option<String>,
    /// The item holding this environment's least-privilege deploy identity (FR-40), read
    /// by `status`, `plan` and `sync` to sign the target CLI in for the run only.
    pub deploy_credentials: Option<ItemRef>,
}

/// An `op://<vault>/<item>` reference to a whole item, by IDs or names (FR-40).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemRef {
    pub vault: String,
    pub item: String,
}

impl std::fmt::Display for ItemRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "op://{}/{}", self.vault, self.item)
    }
}

impl ItemRef {
    /// Parse `op://<vault>/<item>`: exactly a vault and an item, each non-empty, unpadded,
    /// free of control characters and not starting with `-` (safe as an argument). A field,
    /// a query (`?attribute=`) or any other form is refused with the reason.
    pub fn parse(s: &str) -> Result<Self, &'static str> {
        let rest = s
            .strip_prefix("op://")
            .ok_or("must be an op://<vault>/<item> reference")?;
        if rest.contains('?') {
            return Err("must name an item, without a query (op://<vault>/<item>)");
        }
        let parts: Vec<&str> = rest.split('/').collect();
        let [vault, item] = parts.as_slice() else {
            return Err("must name exactly a vault and an item (op://<vault>/<item>), not a field");
        };
        for part in [vault, item] {
            if part.is_empty() {
                return Err("needs a non-empty vault and item (op://<vault>/<item>)");
            }
            if part.trim() != *part {
                return Err("has leading or trailing whitespace in the vault or item");
            }
            if part.starts_with('-') || part.chars().any(char::is_control) {
                return Err("vault and item may not start with - or hold control characters");
            }
        }
        Ok(Self {
            vault: (*vault).to_string(),
            item: (*item).to_string(),
        })
    }
}

impl Environment {
    /// The environment's deployment target, or `None` when it has none.
    pub fn target(&self) -> Option<&dyn TargetConfig> {
        self.target.as_deref()
    }

    /// Target name (the runtime env var name) for `product`/`key`, or `None` when the
    /// environment has no target.
    pub fn target_name(&self, product: &str, key: &str) -> Option<String> {
        self.target().map(|t| t.env_name(product, key))
    }
}

/// Which `profile.kind` the configuration declared (§10.2, FR-20).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Profile {
    /// Products with sections in the item and a target name template (§10.2). The default.
    #[default]
    Fleet,
    /// A flat `[keys]` map (FR-20): unsectioned item fields, target name = key name.
    Simple,
}

/// Name of the one implicit product a simple-profile file desugars into (FR-20). Empty, so
/// it can never collide with a fleet product name (`^[a-z][a-z0-9_-]*$`) or a 1Password
/// section label (always non-empty), and it is never shown to the user: see
/// [`key_label`].
pub const SIMPLE_PRODUCT: &str = "";

/// Target name template of a simple-profile environment: the key name itself (FR-20).
pub const SIMPLE_TEMPLATE: &str = "{KEY}";

/// The user-facing name of `product`/`key`: `product/KEY` under the fleet profile, `KEY`
/// under the simple profile (whose implicit product is [`SIMPLE_PRODUCT`]).
pub fn key_label(product: &str, key: &str) -> String {
    if product == SIMPLE_PRODUCT {
        key.to_string()
    } else {
        format!("{product}/{key}")
    }
}

/// A validated configuration. Build it with `config::load` or `config::parse`.
///
/// A simple-profile file (FR-20) is desugared into the same model: one product named
/// [`SIMPLE_PRODUCT`] holding every key, unsectioned item fields (section
/// [`SIMPLE_PRODUCT`]), and a target name template of [`SIMPLE_TEMPLATE`], so the planner, rules,
/// stage-and-compare and prune logic are shared unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fleet {
    pub environments: BTreeMap<String, Environment>,
    pub products: BTreeMap<String, Product>,
    pub profile: Profile,
}

impl Fleet {
    /// True for a `profile.kind = "simple"` file (FR-20).
    pub fn is_simple(&self) -> bool {
        self.profile == Profile::Simple
    }

    /// Look up an environment by a (possibly user-supplied) name.
    pub fn environment(&self, env: &str) -> Result<&Environment, Error> {
        self.environments.get(env).ok_or_else(|| {
            let known: Vec<&str> = self.environments.keys().map(String::as_str).collect();
            Error::Config(format!(
                "undefined environment {env:?} (defined: {})",
                known.join(", ")
            ))
        })
    }

    /// Target name (runtime env var name) for `product`/`key` in `env`.
    ///
    /// # Panics
    /// If `env` is not a defined environment with a target. Callers resolve it first.
    pub fn target_name(&self, env: &str, product: &str, key: &str) -> String {
        match self.environments.get(env).and_then(|e| e.target()) {
            Some(t) => t.env_name(product, key),
            None => panic!("target_name: environment {env:?} undefined or without a target"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_label_hides_the_implicit_product() {
        assert_eq!(key_label(SIMPLE_PRODUCT, "JWT_KEY"), "JWT_KEY");
        assert_eq!(key_label("api", "JWT_KEY"), "api/JWT_KEY");
    }
}
