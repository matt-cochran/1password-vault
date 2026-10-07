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
    pub fn fly_name(&self, product: &str, key: &str) -> String {
        let product = product.to_ascii_uppercase().replace('-', "_");
        self.secret_name_template
            .replace("{PRODUCT}", &product)
            .replace("{KEY}", key)
    }
}

/// One deployment environment: one 1Password item (by IDs, FR-13) and, optionally, one Fly app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Environment {
    pub vault_id: String,
    pub item_id: String,
    /// `None` when the environment has no `fly` section.
    pub fly: Option<FlyTarget>,
    /// product → mode name → mode value, e.g. `allumata.payments = "off"`.
    pub modes: BTreeMap<String, BTreeMap<String, String>>,
}

impl Environment {
    /// Fly secret name for `product`/`key`, or `None` when the environment has no Fly target.
    pub fn fly_name(&self, product: &str, key: &str) -> Option<String> {
        self.fly.as_ref().map(|f| f.fly_name(product, key))
    }
}

/// A validated fleet configuration. Build it with `config::load` or `config::parse`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fleet {
    pub environments: BTreeMap<String, Environment>,
    pub products: BTreeMap<String, Product>,
}

impl Fleet {
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

    /// The environment and its Fly target; `Error::Config` naming the environment when it is
    /// undefined or has no `fly` section (status, `fly plan`, `fly sync` need one).
    pub fn fly_target(&self, env: &str) -> Result<(&Environment, &FlyTarget), Error> {
        let e = self.environment(env)?;
        match &e.fly {
            Some(f) => Ok((e, f)),
            None => Err(Error::Config(format!(
                "environment {env:?} has no fly section (add fly.app and fly.secret_name to \
                 use status and the fly commands)"
            ))),
        }
    }

    /// Fly secret name for `product`/`key` in `env`; `Error::Config` if `env` is undefined
    /// or has no Fly target.
    pub fn try_fly_name(&self, env: &str, product: &str, key: &str) -> Result<String, Error> {
        Ok(self.fly_target(env)?.1.fly_name(product, key))
    }

    /// Fly secret name for `product`/`key` in `env`.
    ///
    /// # Panics
    /// If `env` is not a defined environment with a Fly target. Callers resolve it first.
    pub fn fly_name(&self, env: &str, product: &str, key: &str) -> String {
        match self.environments.get(env).and_then(|e| e.fly.as_ref()) {
            Some(f) => f.fly_name(product, key),
            None => panic!("fly_name: environment {env:?} undefined or without fly"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fly_name_normalizes_product() {
        let e = Environment {
            vault_id: "v".into(),
            item_id: "i".into(),
            fly: Some(FlyTarget {
                app: "a".into(),
                secret_name_template: "FLEET__{PRODUCT}__{KEY}".into(),
            }),
            modes: BTreeMap::new(),
        };
        assert_eq!(
            e.fly_name("my-app", "API_KEY").as_deref(),
            Some("FLEET__MY_APP__API_KEY")
        );
        let no_fly = Environment { fly: None, ..e };
        assert_eq!(no_fly.fly_name("my-app", "API_KEY"), None);
    }
}
