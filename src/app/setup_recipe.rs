//! Metadata-only recipes for owner-guided setup. No defaults contain credentials.
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::cause::{Cause, DottedPath, FieldRule, InputKind, Location};
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

/// A validated recipe that cannot be rendered as declarations: an invariant of
/// [`Recipe::parse_at`] (its settings are non-empty and plain TOML), so an opv bug.
fn unrenderable() -> Error {
    Cause::Bug {
        site: "a validated setup recipe could not be rendered",
    }
    .into()
}

pub fn discover(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .map(|p| p.join(FILE))
        .find(|p| p.is_file())
}

/// The recipe file `opv setup` looks for in a directory.
pub const FILE: &str = "opv.setup.toml";

/// `opv setup` found no recipe (P3, 05.23): the recipe file is the missing input, named
/// where opv looked first. The catalog's Do is to add it and its Next the same command;
/// never a guessed `opv init <env>`.
pub fn missing(start: &Path) -> Error {
    invalid(
        &start.join(FILE),
        None,
        FILE.to_string(),
        FieldRule::Missing,
    )
}

/// A recipe problem at `field`: the catalog's `InputInvalid` for the setup recipe (R67).
fn invalid(path: &Path, at: Option<Location>, field: String, rule: FieldRule) -> Error {
    Cause::InputInvalid {
        path: path.to_path_buf(),
        kind: InputKind::SetupRecipe,
        at,
        field,
        rule,
    }
    .into()
}

/// `text`'s 1-based line and column of byte `at`.
fn location(text: &str, at: usize) -> Option<Location> {
    let before = text.get(..at)?;
    let line = before.matches('\n').count() + 1;
    let col = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
    Some(Location {
        line: u32::try_from(line).ok()?,
        col: u32::try_from(col).ok()?,
    })
}

/// The name in backticks after `marker` in `message` (serde's `unknown field `x``).
fn ticked_after(message: &str, marker: &str) -> Option<String> {
    let rest = &message[message.find(marker)? + marker.len()..];
    let inner = rest.strip_prefix('`')?;
    Some(inner[..inner.find('`')?].to_string())
}

/// A TOML or serde error in the recipe as the field and rule it names (05.22): the field's
/// name and the line, never the line's text (a mistaken value is still private).
fn toml_invalid(path: &Path, text: &str, e: &toml::de::Error) -> Error {
    let message = e.message();
    let at = e.span().and_then(|s| location(text, s.start));
    let (field, rule) = if let Some(f) = ticked_after(message, "unknown field ") {
        (f, FieldRule::Unknown { suggestion: None })
    } else if let Some(f) = ticked_after(message, "missing field ") {
        (f, FieldRule::Missing)
    } else if message.starts_with("duplicate key") {
        (
            ticked_after(message, "duplicate key ").unwrap_or_else(|| "a key".into()),
            FieldRule::DuplicateKey,
        )
    } else {
        ("the TOML".to_string(), FieldRule::Syntax)
    };
    invalid(path, at, field, rule)
}

impl Recipe {
    /// [`Recipe::parse_at`] for the recipe at `opv.setup.toml`.
    pub fn parse(text: &str) -> Result<Self, Error> {
        Self::parse_at(Path::new(FILE), text)
    }

    /// The recipe in `text`, read from `path` (named in its errors with the line and the
    /// field, 05.22).
    pub fn parse_at(path: &Path, text: &str) -> Result<Self, Error> {
        // Do not repeat input: a mistaken value in a recipe is still private.
        let recipe: Self = toml::from_str(text).map_err(|e| toml_invalid(path, text, &e))?;
        let bad = |field: &str, rule| Err(invalid(path, None, field.to_string(), rule));
        for (field, value) in [
            ("title", &recipe.title),
            ("vault", &recipe.vault),
            ("item", &recipe.item),
        ] {
            if value.trim().is_empty() {
                return bad(field, FieldRule::Empty);
            }
        }
        if recipe.fields.is_empty() {
            return bad("fields", FieldRule::Missing);
        }
        if let Some(f) = recipe.fields.iter().find(|f| f.product.trim().is_empty()) {
            return bad(&format!("fields {}: product", f.key), FieldRule::Missing);
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
            // A shared variable must not be copied into several products automatically.
            return bad(
                "legacy_env",
                FieldRule::ConflictsWith {
                    field: DottedPath(vec!["settings of more than one product".into()]),
                },
            );
        }
        let mut seen = BTreeSet::new();
        for f in &recipe.fields {
            let setting = format!("fields {}/{}", f.product, f.key);
            for (name, value) in [
                ("title", &f.title),
                ("description", &f.description),
                ("source", &f.source),
            ] {
                if value.trim().is_empty() {
                    return bad(&format!("{setting}: {name}"), FieldRule::Empty);
                }
            }
            if !seen.insert((f.product.clone(), f.key.clone())) {
                return bad(&setting, FieldRule::DuplicateKey);
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
                toml::Value::try_from(&f.rules).map_err(|_| unrenderable())?,
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
            .ok_or_else(unrenderable)?
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
        toml::to_string_pretty(&root).map_err(|_| unrenderable())
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
    fn refusal(text: &str) -> Cause {
        Recipe::parse_at(Path::new("/p/opv.setup.toml"), text)
            .err()
            .expect("refused")
            .cause()
            .expect("a catalog cause")
            .0
            .clone()
    }
    fn field_and_rule(c: &Cause) -> Option<(&str, &FieldRule)> {
        match c {
            Cause::InputInvalid { field, rule, .. } => Some((field.as_str(), rule)),
            _ => None,
        }
    }
    #[test]
    fn a_setting_without_a_product_is_refused_naming_product() {
        let c = refusal(&text().replace("product='api'\n", ""));
        assert_eq!(
            field_and_rule(&c),
            Some(("fields API_KEY: product", &FieldRule::Missing))
        );
    }
    #[test]
    fn invalid_recipe_does_not_quote_input() {
        let c = refusal(&(text() + "value='synthetic-private'\n"));
        assert!(
            !c.message().contains("synthetic-private"),
            "{}",
            c.message()
        );
    }
    // 05.22: an unknown field is named, with its line.
    #[test]
    fn an_unknown_field_is_named() {
        let c = refusal(&(text() + "value='synthetic-private'\n"));
        assert_eq!(
            field_and_rule(&c),
            Some(("value", &FieldRule::Unknown { suggestion: None }))
        );
    }
    // 05.22: the line of the unknown field is given.
    #[test]
    fn an_unknown_field_is_placed_at_its_line() {
        let c = refusal(&(text() + "value='synthetic-private'\n"));
        assert!(
            matches!(
                c,
                Cause::InputInvalid {
                    at: Some(Location { line: 11, .. }),
                    ..
                }
            ),
            "{c:?}"
        );
    }
    // 05.22: a setting missing its description names the setting and the field.
    #[test]
    fn a_setting_without_a_description_names_the_setting() {
        let c = refusal(&text().replace("Lets the API call the provider.", " "));
        assert_eq!(
            field_and_rule(&c),
            Some(("fields api/API_KEY: description", &FieldRule::Empty))
        );
    }
    // 05.22: a setting declared twice is named as a duplicate.
    #[test]
    fn a_setting_declared_twice_is_a_duplicate() {
        let twice = text() + &text()[text().find("[[fields]]").unwrap()..];
        let c = refusal(&twice);
        assert_eq!(
            field_and_rule(&c),
            Some(("fields api/API_KEY", &FieldRule::DuplicateKey))
        );
    }
    #[test]
    fn inherited_authentication_keys_cannot_be_declared() {
        assert!(Recipe::parse(&text().replace("API_KEY", "OP_SESSION")).is_err());
    }

    fn missing_cause() -> Cause {
        missing(Path::new("/project"))
            .cause()
            .expect("a catalog cause")
            .0
            .clone()
    }

    /// 05.23: no recipe names the recipe file that is missing, where opv looked.
    #[test]
    fn missing_recipe_names_the_recipe_file() {
        assert!(
            matches!(missing_cause(), Cause::InputInvalid { path, rule: FieldRule::Missing, .. }
                if path == Path::new("/project/opv.setup.toml"))
        );
    }

    /// 05.23: its Next is never a guessed `opv init dev`.
    #[test]
    fn missing_recipe_does_not_guess_an_environment() {
        let inv = crate::cause::Invocation::from_cli(&["opv".into(), "setup".into()]);
        assert_eq!(missing_cause().step(&inv).1, crate::cause::Next::Rerun);
    }
}
