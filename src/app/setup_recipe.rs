//! Metadata-only recipes for owner-guided setup. No defaults contain credentials.
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::config;
use crate::domain::{Kind, Rules};
use crate::error::Error;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recipe {
    pub title: String,
    pub environment: String,
    pub vault: String,
    pub item: String,
    #[serde(default = "output_default")]
    pub output: PathBuf,
    #[serde(default)]
    pub legacy_env: Option<PathBuf>,
    pub fields: Vec<Field>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Field {
    pub key: String,
    #[serde(default)]
    pub product: Option<String>,
    pub title: String,
    pub description: String,
    pub source: String,
    #[serde(default = "secret_default")]
    pub kind: Kind,
    #[serde(default)]
    pub immutable: bool,
    #[serde(default)]
    pub rules: Rules,
    #[serde(default)]
    pub multiline: bool,
}

fn output_default() -> PathBuf {
    PathBuf::from("secrets.toml")
}
fn secret_default() -> Kind {
    Kind::Secret
}

pub fn discover(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .map(|p| p.join("opv.setup.toml"))
        .find(|p| p.is_file())
}

impl Recipe {
    pub fn parse(text: &str) -> Result<Self, Error> {
        // Do not repeat input: a mistaken value in a recipe is still private.
        let recipe: Self = toml::from_str(text).map_err(|_| Error::Config(
            "[SETUP-RECIPE] The setup recipe is not valid. Use the documented recipe format; values belong in 1Password, not this file.".into()
        ))?;
        if recipe.fields.is_empty()
            || recipe.title.trim().is_empty()
            || recipe.vault.trim().is_empty()
            || recipe.item.trim().is_empty()
        {
            return Err(Error::Config(
                "[SETUP-RECIPE] Give the recipe a title, vault, item, and at least one setting."
                    .into(),
            ));
        }
        let fleet = recipe.fields.iter().any(|f| f.product.is_some());
        if recipe.legacy_env.is_some()
            && recipe
                .fields
                .iter()
                .filter_map(|f| f.product.as_ref())
                .collect::<BTreeSet<_>>()
                .len()
                > 1
        {
            return Err(Error::Config("[SETUP-RECIPE] Import a legacy file for one product at a time. A shared variable must not be copied into several products automatically.".into()));
        }
        let mut seen = BTreeSet::new();
        for f in &recipe.fields {
            if f.title.trim().is_empty()
                || f.description.trim().is_empty()
                || f.source.trim().is_empty()
                || f.product.is_some() != fleet
                || !seen.insert((f.product.clone(), f.key.clone()))
            {
                return Err(Error::Config("[SETUP-RECIPE] Each setting needs a unique key, a plain-language title, a reason and a source. Use product names on every setting or none.".into()));
            }
        }
        // Reuse all normal name, rules, context-key and configuration validation.
        config::parse(&recipe.manifest("setup-vault", "setup-item")?)?;
        Ok(recipe)
    }

    pub fn manifest(&self, vault: &str, item: &str) -> Result<String, Error> {
        let mut root = toml::Table::new();
        let fleet = self.fields.iter().any(|f| f.product.is_some());
        root.insert(
            "profile".into(),
            toml::Value::Table(toml::Table::from_iter([(
                "kind".into(),
                toml::Value::String(if fleet { "fleet" } else { "simple" }.into()),
            )])),
        );
        let env = toml::Table::from_iter([
            ("vault_id".into(), toml::Value::String(vault.into())),
            ("item_id".into(), toml::Value::String(item.into())),
        ]);
        root.insert(
            "environments".into(),
            toml::Value::Table(toml::Table::from_iter([(
                self.environment.clone(),
                toml::Value::Table(env),
            )])),
        );
        let mut products = toml::Table::new();
        let mut flat = toml::Table::new();
        for f in &self.fields {
            let mut key = toml::Table::new();
            key.insert(
                "kind".into(),
                toml::Value::String(
                    match f.kind {
                        Kind::Secret => "secret",
                        Kind::Config => "config",
                    }
                    .into(),
                ),
            );
            key.insert(
                "environments".into(),
                toml::Value::Array(vec![toml::Value::String(self.environment.clone())]),
            );
            key.insert("immutable".into(), toml::Value::Boolean(f.immutable));
            key.insert(
                "guidance".into(),
                toml::Value::String(format!(
                    "{}: {} Where to find it: {}",
                    f.title, f.description, f.source
                )),
            );
            key.insert(
                "rules".into(),
                toml::Value::try_from(&f.rules)
                    .map_err(|_| Error::Config("Could not render setup rules.".into()))?,
            );
            if let Some(product) = &f.product {
                let p = products
                    .entry(product.clone())
                    .or_insert_with(|| toml::Value::Table(toml::Table::new()))
                    .as_table_mut()
                    .expect("product table");
                let keys = p
                    .entry("keys")
                    .or_insert_with(|| toml::Value::Table(toml::Table::new()))
                    .as_table_mut()
                    .expect("key table");
                keys.insert(f.key.clone(), toml::Value::Table(key));
            } else {
                flat.insert(f.key.clone(), toml::Value::Table(key));
            }
        }
        root.insert(
            if fleet { "products" } else { "keys" }.into(),
            toml::Value::Table(if fleet { products } else { flat }),
        );
        toml::to_string_pretty(&root)
            .map_err(|_| Error::Config("Could not render setup declarations.".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn text() -> String {
        "title='Example'\nenvironment='dev'\nvault='Development'\nitem='api'\n[[fields]]\nkey='API_KEY'\ntitle='API login'\ndescription='Lets the API call the provider.'\nsource='Your provider account.'\n".into()
    }
    #[test]
    fn recipe_creates_valid_targetless_manifest_with_guidance() {
        let recipe = Recipe::parse(&text()).unwrap();
        let config = config::parse(&recipe.manifest("vault-id", "item-id").unwrap()).unwrap();
        assert!(config.environment("dev").unwrap().target().is_none());
        assert!(
            config.products[""].keys["API_KEY"]
                .guidance
                .contains("API login")
        );
    }
    #[test]
    fn invalid_recipe_does_not_quote_input() {
        let error = Recipe::parse(&(text() + "value='synthetic-private'\n"))
            .err()
            .unwrap();
        assert!(!error.to_string().contains("synthetic-private"));
    }
    #[test]
    fn inherited_authentication_keys_cannot_be_declared() {
        assert!(Recipe::parse(&text().replace("API_KEY", "OP_SESSION")).is_err());
    }
}
