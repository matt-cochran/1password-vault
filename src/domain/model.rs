//! Fleet configuration model (§10.2). Holds names, IDs and rules; never values (FR-1).

use std::collections::BTreeMap;

use serde::Deserialize;

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
    pub not_prefix: Option<String>,
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

/// Required prefix chosen by an environment mode, e.g. `payments = "test"` → `sk_test_`.
/// Modes listed in `skip` mean the key is not required in that environment.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrefixByMode {
    pub mode: String,
    pub values: BTreeMap<String, String>,
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

/// One deployment environment: one 1Password item (by IDs, FR-13) and one Fly app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Environment {
    pub vault_id: String,
    pub item_id: String,
    pub fly_app: String,
    /// Fly secret name template containing `{PRODUCT}` and `{KEY}`; defines the managed set (FR-8).
    pub secret_name_template: String,
    /// product → mode name → mode value, e.g. `allumata.payments = "off"`.
    pub modes: BTreeMap<String, BTreeMap<String, String>>,
}

impl Environment {
    /// Fly secret name for `product`/`key`: `{PRODUCT}` becomes the upper-cased product with
    /// `-` replaced by `_`, `{KEY}` becomes the key verbatim.
    pub fn fly_name(&self, product: &str, key: &str) -> String {
        let product = product.to_ascii_uppercase().replace('-', "_");
        self.secret_name_template
            .replace("{PRODUCT}", &product)
            .replace("{KEY}", key)
    }
}

/// A validated fleet configuration. Build it with `config::load` or `config::parse`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fleet {
    pub environments: BTreeMap<String, Environment>,
    pub products: BTreeMap<String, Product>,
}

impl Fleet {
    /// Fly secret name for `product`/`key` in `env`.
    ///
    /// # Panics
    /// If `env` is not a defined environment. Callers resolve the environment first.
    pub fn fly_name(&self, env: &str, product: &str, key: &str) -> String {
        match self.environments.get(env) {
            Some(e) => e.fly_name(product, key),
            None => panic!("fly_name: undefined environment {env:?}"),
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
            fly_app: "a".into(),
            secret_name_template: "FLEET__{PRODUCT}__{KEY}".into(),
            modes: BTreeMap::new(),
        };
        assert_eq!(e.fly_name("my-app", "API_KEY"), "FLEET__MY_APP__API_KEY");
    }
}
