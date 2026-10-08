//! Fleet configuration model (§10.2). Holds names, IDs and rules; never values (FR-1).

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::error::Error;

/// Field kind. In 1Password a concealed field is a secret and a text field is config (FR-14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Secret,
    Config,
}

/// Declarative validation rules for one key (FR-15). Every rule is optional.
/// Evaluated by the rules engine (`domain::rules`); this type only carries them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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

/// The Fly.io target of one environment (§10.3). Optional: an environment used only for
/// `run`, `config export` and `item skeleton` needs no Fly app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlyTarget {
    pub app: String,
    /// Fly secret name template containing `{PRODUCT}` and `{KEY}`; defines the managed set (FR-8).
    pub secret_name_template: String,
}

impl FlyTarget {
    /// Fly secret name for `product`/`key`: `{PRODUCT}` becomes the upper-cased product with
    /// `-` replaced by `_`, `{KEY}` becomes the key verbatim.
    pub fn target_name(&self, product: &str, key: &str) -> String {
        let product = product.to_ascii_uppercase().replace('-', "_");
        self.secret_name_template
            .replace("{PRODUCT}", &product)
            .replace("{KEY}", key)
    }
}

/// The deployment target of one environment (FR-12, FR-28). Target-neutral domain names;
/// today the only variant is Fly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Fly(FlyTarget),
}

impl Target {
    /// Short, user-facing target name (`"Fly"`).
    pub fn label(&self) -> &'static str {
        match self {
            Self::Fly(_) => "Fly",
        }
    }

    /// Store name for `product`/`key` on this target.
    pub fn target_name(&self, product: &str, key: &str) -> String {
        match self {
            Self::Fly(f) => f.target_name(product, key),
        }
    }
}

/// One deployment environment: one 1Password item (by IDs, FR-13) and, optionally, one
/// deployment target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Environment {
    pub vault_id: String,
    pub item_id: String,
    /// The deployment target (FR-28): `None` when the environment declares none.
    pub target: Option<Target>,
    /// product → mode name → mode value, e.g. `allumata.payments = "off"`.
    pub modes: BTreeMap<String, BTreeMap<String, String>>,
}

impl Environment {
    /// The environment's deployment target, or `None` when it has none.
    pub fn target(&self) -> Option<&Target> {
        self.target.as_ref()
    }

    /// Store name for `product`/`key`, or `None` when the environment has no target.
    pub fn target_name(&self, product: &str, key: &str) -> Option<String> {
        self.target().map(|t| t.target_name(product, key))
    }
}

/// Which `profile.kind` the configuration declared (§10.2, FR-20).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Profile {
    /// Products with sections in the item and a Fly name template (§10.2). The default.
    #[default]
    Fleet,
    /// A flat `[keys]` map (FR-20): unsectioned item fields, Fly name = key name.
    Simple,
}

/// Name of the one implicit product a simple-profile file desugars into (FR-20). Empty, so
/// it can never collide with a fleet product name (`^[a-z][a-z0-9_-]*$`) or a 1Password
/// section label (always non-empty), and it is never shown to the user: see
/// [`key_label`].
pub const SIMPLE_PRODUCT: &str = "";

/// Fly name template of a simple-profile environment: the key name itself (FR-20).
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
/// [`SIMPLE_PRODUCT`]), and a Fly template of [`SIMPLE_TEMPLATE`], so the planner, rules,
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

    /// The environment and its target; `Error::Config` naming the environment when it is
    /// undefined or has no `fly` section (status, `fly plan`, `fly sync` need one).
    pub fn target(&self, env: &str) -> Result<(&Environment, &Target), Error> {
        let e = self.environment(env)?;
        match &e.target {
            Some(t) => Ok((e, t)),
            None if self.is_simple() => Err(Error::Config(format!(
                "environment {env:?} has no fly section (add fly.app to use status and the \
                 fly commands)"
            ))),
            None => Err(Error::Config(format!(
                "environment {env:?} has no fly section (add fly.app and fly.secret_name to \
                 use status and the fly commands)"
            ))),
        }
    }

    /// Store name for `product`/`key` in `env`; `Error::Config` if `env` is undefined
    /// or has no target.
    pub fn try_target_name(&self, env: &str, product: &str, key: &str) -> Result<String, Error> {
        Ok(self.target(env)?.1.target_name(product, key))
    }

    /// Store name for `product`/`key` in `env`.
    ///
    /// # Panics
    /// If `env` is not a defined environment with a target. Callers resolve it first.
    pub fn target_name(&self, env: &str, product: &str, key: &str) -> String {
        match self.environments.get(env).and_then(|e| e.target.as_ref()) {
            Some(t) => t.target_name(product, key),
            None => panic!("fly_name: environment {env:?} undefined or without fly"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_name_normalizes_product() {
        let e = Environment {
            vault_id: "v".into(),
            item_id: "i".into(),
            target: Some(Target::Fly(FlyTarget {
                app: "a".into(),
                secret_name_template: "FLEET__{PRODUCT}__{KEY}".into(),
            })),
            modes: BTreeMap::new(),
        };
        assert_eq!(
            e.target_name("my-app", "API_KEY").as_deref(),
            Some("FLEET__MY_APP__API_KEY")
        );
        let no_fly = Environment { target: None, ..e };
        assert_eq!(no_fly.target_name("my-app", "API_KEY"), None);
    }

    #[test]
    fn simple_template_renders_the_key_name_itself() {
        let t = FlyTarget {
            app: "a".into(),
            secret_name_template: SIMPLE_TEMPLATE.into(),
        };
        assert_eq!(t.target_name(SIMPLE_PRODUCT, "JWT_KEY"), "JWT_KEY");
    }

    #[test]
    fn key_label_hides_the_implicit_product() {
        assert_eq!(key_label(SIMPLE_PRODUCT, "JWT_KEY"), "JWT_KEY");
        assert_eq!(key_label("api", "JWT_KEY"), "api/JWT_KEY");
    }
}
