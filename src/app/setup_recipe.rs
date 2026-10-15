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
    /// The product the setting belongs to (FR-60: every key is a product's); required.
    #[serde(default)]
    pub product: String,
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

/// `opv setup` found no recipe (P3): never a dead end. It offers `init` for an existing
/// item, the generic recipe (docs/guided-setup.md) with the exact command that uses it, and
/// `--recipe` for a recipe kept elsewhere.
pub fn missing(start: &Path) -> Error {
    Error::Config(
        format!(
            "this project has no setup recipe: no opv.setup.toml in {} or any parent directory.\n  \
             New project?  copy the generic recipe from {}/guided-setup.md into opv.setup.toml \
             (names and instructions only, never values), then run: opv setup\n  \
             Recipe kept elsewhere?  opv setup --recipe <path>",
            start.display(),
            crate::DOCS_URL
        )
        .into(),
    )
    .with_next("opv init dev")
}

impl Recipe {
    pub fn parse(text: &str) -> Result<Self, Error> {
        // Do not repeat input: a mistaken value in a recipe is still private.
        let recipe: Self = toml::from_str(text).map_err(|_| Error::Config(
            "The setup recipe is not valid. Use the documented recipe format; values belong in 1Password, not this file.".into()
        ))?;
        if recipe.fields.is_empty()
            || recipe.title.trim().is_empty()
            || recipe.vault.trim().is_empty()
            || recipe.item.trim().is_empty()
        {
            return Err(Error::Config(
                "Give the recipe a title, vault, item, and at least one setting.".into(),
            ));
        }
        if recipe.fields.iter().any(|f| f.product.trim().is_empty()) {
            return Err(Error::Config(
                "Give every setting its product, as product = \"api\" (the app it belongs to)."
                    .into(),
            ));
        }
        if recipe.legacy_env.is_some()
            && recipe
                .fields
                .iter()
                .map(|f| &f.product)
                .collect::<BTreeSet<_>>()
                .len()
                > 1
        {
            return Err(Error::Config("Import a legacy file for one product at a time. A shared variable must not be copied into several products automatically.".into()));
        }
        let mut seen = BTreeSet::new();
        for f in &recipe.fields {
            if f.title.trim().is_empty()
                || f.description.trim().is_empty()
                || f.source.trim().is_empty()
                || !seen.insert((f.product.clone(), f.key.clone()))
            {
                return Err(Error::Config("Each setting needs a unique key, a plain-language title, a reason and a source.".into()));
            }
        }
        // Reuse all normal name, rules, context-key and configuration validation.
        config::parse(&recipe.manifest("setup-vault", "setup-item")?)?;
        Ok(recipe)
    }

    /// The configuration for the recipe's one item (FR-57): one boundary,
    /// `boundaries.<product>` for one product, else `boundary = "core"` on each product and
    /// `boundaries.core`. No target: `opv target add` adds one.
    pub fn manifest(&self, vault: &str, item: &str) -> Result<String, Error> {
        let mut products = toml::Table::new();
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
            let p = products
                .entry(f.product.clone())
                .or_insert_with(|| toml::Value::Table(toml::Table::new()))
                .as_table_mut()
                .expect("product table");
            let keys = p
                .entry("keys")
                .or_insert_with(|| toml::Value::Table(toml::Table::new()))
                .as_table_mut()
                .expect("key table");
            keys.insert(f.key.clone(), toml::Value::Table(key));
        }
        let boundary = super::init::item_boundary(products.keys().map(String::as_str))
            .ok_or_else(|| Error::Config("Give the recipe at least one setting.".into()))?
            .to_string();
        if products.len() > 1 {
            for (_, p) in products.iter_mut() {
                p.as_table_mut()
                    .expect("product table")
                    .insert("boundary".into(), toml::Value::String(boundary.clone()));
            }
        }
        let ids = toml::Table::from_iter([
            ("vault_id".into(), toml::Value::String(vault.into())),
            ("item_id".into(), toml::Value::String(item.into())),
        ]);
        let env = toml::Table::from_iter([(
            "boundaries".into(),
            toml::Value::Table(toml::Table::from_iter([(
                boundary,
                toml::Value::Table(ids),
            )])),
        )]);
        let root = toml::Table::from_iter([
            (
                "environments".into(),
                toml::Value::Table(toml::Table::from_iter([(
                    self.environment.clone(),
                    toml::Value::Table(env),
                )])),
            ),
            ("products".into(), toml::Value::Table(products)),
        ]);
        toml::to_string_pretty(&root)
            .map_err(|_| Error::Config("Could not render setup declarations.".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn text() -> String {
        "title='Example'\nenvironment='dev'\nvault='Development'\nitem='api'\n[[fields]]\nkey='API_KEY'\nproduct='api'\ntitle='API login'\ndescription='Lets the API call the provider.'\nsource='Your provider account.'\n".into()
    }
    fn two_products() -> String {
        text()
            + "[[fields]]\nkey='SESSION_KEY'\nproduct='web'\ntitle='Sessions'\ndescription='Signs sessions.'\nsource='Generate one.'\n"
    }
    fn loaded(text: &str) -> crate::domain::Fleet {
        let recipe = Recipe::parse(text).unwrap();
        config::parse(&recipe.manifest("vault-id", "item-id").unwrap()).unwrap()
    }
    #[test]
    fn one_product_records_its_own_boundary() {
        let boundaries: Vec<String> = loaded(&text()).environments["dev"]
            .boundaries
            .keys()
            .cloned()
            .collect();
        assert_eq!(boundaries, ["api"]);
    }
    #[test]
    fn several_products_record_the_core_boundary() {
        let boundaries: Vec<String> = loaded(&two_products()).environments["dev"]
            .boundaries
            .keys()
            .cloned()
            .collect();
        assert_eq!(boundaries, ["core"]);
    }
    #[test]
    fn several_products_each_name_the_core_boundary() {
        let fleet = loaded(&two_products());
        assert_eq!(
            [fleet.boundary_of("api"), fleet.boundary_of("web")],
            ["core", "core"]
        );
    }
    #[test]
    fn the_manifest_has_no_target() {
        assert!(loaded(&text()).environments["dev"].targets.is_empty());
    }
    #[test]
    fn the_manifest_keeps_the_guidance() {
        assert!(
            loaded(&text()).products["api"].keys["API_KEY"]
                .guidance
                .contains("API login")
        );
    }
    #[test]
    fn a_setting_without_a_product_is_refused_naming_product() {
        let error = Recipe::parse(&text().replace("product='api'\n", ""))
            .err()
            .unwrap();
        assert!(error.to_string().contains("product = \"api\""), "{error}");
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

    /// P3: no recipe is not a dead end; init is offered for an existing item.
    #[test]
    fn missing_recipe_offers_init_for_an_existing_item() {
        let e = missing(Path::new("/project"));
        assert_eq!(e.next_step(), Some("opv init dev"), "{e}");
    }

    /// P3: and the generic recipe with the exact command that uses it.
    #[test]
    fn missing_recipe_offers_the_generic_recipe_and_its_command() {
        let e = missing(Path::new("/project")).to_string();
        assert!(
            e.contains("guided-setup.md into opv.setup.toml") && e.contains("then run: opv setup"),
            "{e}"
        );
    }
}
