//! Owner-guided, resumable local setup. Existing automation commands never prompt.
use super::setup_recipe::{Field, Recipe};
use crate::adapters::onepassword::{WipeOnDrop, serialize_exact};
use crate::config;
use crate::domain::{Kind, SecretValue};
use crate::error::Error;
use crate::runner::Output;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub trait Backend {
    fn native(&self) -> Result<(), Error>;
    fn call(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Output, Error>;
    fn sign_in(&mut self, account: Option<&str>, add_account: bool) -> Result<(), Error>;
    /// Use `account` for every later call (`opv login`, FR-40).
    fn use_account(&mut self, _account: Option<&str>) {}
    /// Run `command` signed in (a signed-in shell when empty); its exit code (`opv login`).
    fn child(&self, _command: &[String]) -> Result<i32, Error> {
        Err(Error::Dependency(
            "[LOGIN-COMMAND] This backend cannot start a command.".into(),
        ))
    }
}
pub trait Interaction {
    fn show(&mut self, message: &str) -> Result<(), Error>;
    fn confirm(&mut self, question: &str) -> Result<bool, Error>;
    fn secret(&mut self, title: &str) -> Result<SecretValue, Error>;
    fn choose(&mut self, question: &str, choices: &[String]) -> Result<String, Error> {
        Err(settings_error(&format!(
            "{question} Choose --product {}.",
            choices.join(" or --product ")
        )))
    }
}

fn settings_error(message: &str) -> Error {
    Error::Config(message.to_string().into())
}
fn source_error(message: &str) -> Error {
    Error::Source(message.to_string().into())
}

#[derive(Deserialize)]
struct Name {
    id: String,
    #[serde(default, alias = "title")]
    name: String,
}
fn list(output: &Output) -> Result<Vec<Name>, Error> {
    serde_json::from_slice(&output.stdout).map_err(|_| source_error("The CLI returned an invalid list. No response contents printed. Update op or run opv doctor to check its installation."))
}
fn match_name(rows: Vec<Name>, name: &str, what: &str) -> Result<Option<String>, Error> {
    let mut matches = rows.into_iter().filter(|r| r.name == name);
    let first = matches.next();
    if matches.next().is_some() {
        return Err(settings_error(&format!(
            "More than one {what} is named {name:?}. Rename the duplicate in 1Password, then rerun setup. Nothing overwritten."
        )));
    }
    if let Some(row) = first {
        if !config::is_id(&row.id) {
            return Err(source_error(
                "The CLI returned an invalid ID. No data printed.",
            ));
        }
        Ok(Some(row.id))
    } else {
        Ok(None)
    }
}
fn successful(backend: &dyn Backend, args: &[&str], input: Option<&[u8]>) -> Result<Output, Error> {
    let output = backend.call(args, input)?;
    if output.status != 0 {
        return Err(source_error(
            "1Password could not complete this step. Confirm that this account has access to the selected vault and that your connection works, then rerun setup. Existing credentials are preserved.",
        ));
    }
    Ok(output)
}
fn version(backend: &dyn Backend) -> Result<String, Error> {
    let output = backend.call(&["--version"], None)?;
    let value = std::str::from_utf8(&output.stdout)
        .ok()
        .map(str::trim)
        .unwrap_or("");
    let numbers = value
        .split('.')
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .ok();
    if output.status != 0 || numbers.as_ref().is_none_or(|n| n.len() != 3) {
        return Err(Error::Dependency("Cannot recognize the Linux/native op installation. Run op --version, then reinstall the official CLI if needed.".into()));
    }
    let numbers = numbers.expect("checked");
    if (numbers[0], numbers[1], numbers[2]) < super::doctor::OP_TESTED_MIN {
        return Err(Error::Dependency(
            "Update 1Password CLI to 2.40.0 or newer, then rerun setup.".into(),
        ));
    }
    Ok(value.to_owned())
}

/// Authentication stays in the owner process, never in a printed export command.
pub fn prepare(
    account: Option<&str>,
    backend: &mut dyn Backend,
    ui: &mut dyn Interaction,
) -> Result<Output, Error> {
    backend.native()?;
    ui.show(&format!("1Password CLI: ready ({})", version(backend)?))?;
    let mut vaults = backend.call(&["vault", "list", "--format", "json"], None)?;
    if vaults.status != 0 {
        let who = backend.call(&["whoami", "--format", "json"], None)?;
        if who.status == 0 {
            return Err(source_error(
                "You are signed in, but vault access failed. Check your connection and account access to the setup vault, then rerun the command.",
            ));
        }
        ui.show("Sign in to 1Password. Your password goes only to its own prompt.")?;
        let accounts = backend.call(&["account", "list", "--format", "json"], None)?;
        let none = accounts.status == 0
            && serde_json::from_slice::<Vec<serde::de::IgnoredAny>>(&accounts.stdout)
                .is_ok_and(|a| a.is_empty());
        if none {
            ui.show("First, add your 1Password account at its prompts. Find its details in your 1Password Emergency Kit.")?;
            backend.sign_in(account, true)?;
        }
        backend.sign_in(account, false)?;
        vaults = successful(backend, &["vault", "list", "--format", "json"], None)?;
    }
    Ok(vaults)
}

fn field_indices(doc: &mut Value, definitions: &[Field]) -> Result<Vec<usize>, Error> {
    if doc.get("category").and_then(Value::as_str) != Some("SECURE_NOTE") {
        return Err(settings_error(
            "The existing item must be a Secure Note. Choose a separate setup item; this item was not changed.",
        ));
    }
    if doc.get("fields").is_none() {
        doc["fields"] = json!([]);
    }
    if !doc["fields"].is_array() {
        return Err(source_error(
            "Invalid item fields. Existing item was not changed.",
        ));
    }
    if doc.get("sections").is_none() {
        doc["sections"] = json!([]);
    }
    if !doc["sections"].is_array() {
        return Err(source_error(
            "Invalid item sections. Existing item was not changed.",
        ));
    }
    let mut indices = Vec::new();
    for definition in definitions {
        let matches: Vec<_> = doc["fields"]
            .as_array()
            .expect("fields")
            .iter()
            .enumerate()
            .filter(|(_, field)| {
                let section = field
                    .get("section")
                    .and_then(|s| s.get("label"))
                    .and_then(Value::as_str);
                field.get("label").and_then(Value::as_str) == Some(&definition.key)
                    && section == definition.product.as_deref()
            })
            .map(|(i, _)| i)
            .collect();
        if matches.len() > 1 {
            return Err(settings_error(&format!(
                "Duplicate setting {}. Rename its duplicate in 1Password, then rerun setup.",
                definition.key
            )));
        }
        if let Some(&index) = matches.first() {
            let expected = match definition.kind {
                Kind::Secret => "CONCEALED",
                Kind::Config => "STRING",
            };
            if doc["fields"][index].get("type").and_then(Value::as_str) != Some(expected) {
                return Err(settings_error(&format!(
                    "{} has the wrong field type. In 1Password change it to {} while keeping the value, then rerun setup.",
                    definition.title,
                    if definition.kind == Kind::Secret {
                        "Password / concealed"
                    } else {
                        "Text"
                    }
                )));
            }
            indices.push(index);
        } else {
            let field_id = unique_id(&doc["fields"], &format!("opv_{}", definition.key));
            let mut field = json!({"id":field_id,"label":definition.key,"type":match definition.kind {Kind::Secret=>"CONCEALED",Kind::Config=>"STRING"},"value":""});
            if let Some(product) = &definition.product {
                let sections = doc["sections"].as_array_mut().expect("sections");
                let section = if let Some(section) = sections
                    .iter()
                    .find(|s| s.get("label").and_then(Value::as_str) == Some(product))
                {
                    section.clone()
                } else {
                    let section = json!({"id":unique_id(&Value::Array(sections.clone()), &format!("opv_{product}")),"label":product});
                    sections.push(section.clone());
                    section
                };
                field["section"] = section;
            }
            let fields = doc["fields"].as_array_mut().expect("fields");
            indices.push(fields.len());
            fields.push(field);
        }
    }
    Ok(indices)
}

fn unique_id(rows: &Value, base: &str) -> String {
    let mut candidate = base.to_owned();
    let mut suffix = 1;
    while rows.as_array().is_some_and(|rows| {
        rows.iter()
            .any(|row| row.get("id").and_then(Value::as_str) == Some(&candidate))
    }) {
        candidate = format!("{base}_{suffix}");
        suffix += 1;
    }
    candidate
}

fn has_value(doc: &Value, index: usize) -> bool {
    doc["fields"][index]
        .get("value")
        .and_then(Value::as_str)
        .is_some_and(|v| !v.is_empty())
}

fn expanded(path: &Path) -> Result<PathBuf, Error> {
    if let Some(tail) = path.to_str().and_then(|s| s.strip_prefix("~/")) {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .ok_or_else(|| {
                settings_error("Cannot locate your home directory for the existing settings file.")
            })?;
        Ok(PathBuf::from(home).join(tail))
    } else {
        Ok(path.to_owned())
    }
}

fn read_legacy(path: &Path) -> Result<BTreeMap<String, SecretValue>, Error> {
    let info = fs::symlink_metadata(path).map_err(|_| settings_error("Cannot read the existing settings file. Leave it intact and fill the missing values privately in 1Password."))?;
    if !info.file_type().is_file() || info.len() > 1024 * 1024 {
        return Err(settings_error(
            "The existing settings must be a regular file smaller than 1 MiB. No file contents imported.",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if info.permissions().mode() & 0o077 != 0 {
            return Err(settings_error(
                "The existing settings file is not private. Set its permissions to 600, then rerun setup. No values imported.",
            ));
        }
    }
    let raw = Zeroizing::new(fs::read_to_string(path).map_err(|_| {
        settings_error("Cannot read this settings file as UTF-8. Nothing imported.")
    })?);
    super::setup_import::parse(&raw)
}

fn config_compatible(path: &Path, expected: &str) -> Result<(), Error> {
    if path.exists() && config::load(path)? != config::parse(expected)? {
        return Err(settings_error(
            "The output configuration already contains different declarations. Choose a separate recipe output / --config path, or review the existing file. Setup never overwrites it.",
        ));
    }
    Ok(())
}

/// Return 0 when ready, 8 when saved with missing fields, 6 when the owner stops.
pub fn run(
    recipe_path: &Path,
    output_override: Option<&Path>,
    account: Option<&str>,
    product: Option<&str>,
    backend: &mut dyn Backend,
    ui: &mut dyn Interaction,
) -> Result<i32, Error> {
    let text = fs::read_to_string(recipe_path).map_err(|_| settings_error("Cannot read the setup recipe. Run opv setup --recipe <path>, or add opv.setup.toml to your repository."))?;
    let recipe = Recipe::parse(&text)?;
    let products: Vec<_> = recipe
        .fields
        .iter()
        .filter_map(|f| f.product.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let selected = match (products.len(), product) {
        (0, None) => None,
        (0, Some(_)) => {
            return Err(settings_error(
                "This recipe is for one app. Omit --product.",
            ));
        }
        (_, Some(p)) if products.iter().any(|v| v == p) => Some(p.to_owned()),
        (_, Some(_)) => {
            return Err(settings_error(&format!(
                "Unknown product. Choose one of: {}.",
                products.join(", ")
            )));
        }
        (1, None) => Some(products[0].clone()),
        (_, None) => Some(ui.choose("Which product are you working on?", &products)?),
    };
    let active: Vec<_> = recipe
        .fields
        .iter()
        .filter(|f| f.product.as_deref() == selected.as_deref())
        .cloned()
        .collect();
    let parent = recipe_path.parent().unwrap_or_else(|| Path::new("."));
    let output = output_override
        .map(Path::to_owned)
        .unwrap_or_else(|| parent.join(&recipe.output));
    if output.exists() {
        let existing = config::load(&output)?;
        let env = existing.environment(&recipe.environment)?;
        config_compatible(&output, &recipe.manifest(&env.vault_id, &env.item_id)?)?;
    }
    ui.show(&format!("\n{}\nWe will save your existing settings in 1Password and prepare local commands.\nNo infrastructure will be applied or deployed.\n", recipe.title))?;
    let vaults = prepare(account, backend, ui)?;
    let vault = match_name(list(&vaults)?, &recipe.vault, "vault")?.ok_or_else(|| settings_error(&format!("You are signed in, but vault {:?} is missing. Create that vault in the 1Password app or select the account that contains it, then rerun setup.", recipe.vault)))?;
    ui.show(&format!("Signed in. Using vault {}.", recipe.vault))?;
    let items = successful(
        backend,
        &["item", "list", "--vault", &vault, "--format", "json"],
        None,
    )?;
    let mut item_id = match_name(list(&items)?, &recipe.item, "item")?;
    let raw = if let Some(id) = &item_id {
        successful(
            backend,
            &["item", "get", id, "--vault", &vault, "--format", "json"],
            None,
        )?
    } else {
        ui.show(&format!(
            "Your setup item is missing. I can create {} and its fields for you.",
            recipe.item
        ))?;
        Output::success(br#"{"category":"SECURE_NOTE","fields":[],"sections":[]}"#.to_vec())
    };
    let mut doc = WipeOnDrop(serde_json::from_slice(&raw.stdout).map_err(|_| {
        source_error("The item response is invalid. No contents printed; no item changed.")
    })?);
    let before = serialize_exact(&doc.0)?;
    let indices = field_indices(&mut doc.0, &active)?;
    let mut import = BTreeMap::new();
    if let Some(path) = &recipe.legacy_env {
        let path = expanded(path)?;
        let path = if path.is_absolute() {
            path
        } else {
            parent.join(path)
        };
        if path.exists() && indices.iter().any(|&i| !has_value(&doc.0, i)) {
            ui.show(&format!("\nFound existing settings at {}. We can copy only missing declared values; the file stays intact.", path.display()))?;
            if ui.confirm("Copy these existing settings privately?")? {
                match read_legacy(&path) {
                    Ok(values) => import = values,
                    Err(error) => ui.show(&format!("{error}\nContinue below without importing. Your original file is unchanged."))?,
                }
            }
        }
    }
    for (field, &index) in active.iter().zip(&indices) {
        if has_value(&doc.0, index) {
            ui.show(&format!("Saved: {} (existing value kept)", field.title))?;
            continue;
        }
        if let Some(value) = import.get(&field.key).filter(|v| !v.expose().is_empty()) {
            doc.0["fields"][index]["value"] = Value::String(value.expose().to_owned());
            ui.show(&format!("Copied: {} (value hidden)", field.title))?;
            continue;
        }
        ui.show(&format!(
            "\n{}\n{}\nWhere to find it: {}",
            field.title, field.description, field.source
        ))?;
        if field.multiline {
            ui.show("This needs its exact complete multiline value. Use the private file import, or finish this field in the 1Password app. We will not generate a replacement.")?;
        } else {
            ui.show("Enter the existing value privately, or press Enter to finish it later.")?;
            let value = ui.secret(&field.title)?;
            if !value.expose().is_empty() {
                doc.0["fields"][index]["value"] = Value::String(value.expose().to_owned());
            }
        }
    }
    drop(import);
    let missing: Vec<_> = active
        .iter()
        .zip(&indices)
        .filter(|(_, i)| !has_value(&doc.0, **i))
        .map(|(f, _)| f.title.as_str())
        .collect();
    let payload = serialize_exact(&doc.0)?;
    if item_id.is_none() || *payload != *before {
        ui.show(&format!(
            "\nSave {} in {}. {} of {} settings filled. Existing filled values are kept.",
            recipe.item,
            recipe.vault,
            indices.len() - missing.len(),
            indices.len()
        ))?;
        if !ui.confirm("Save this progress in 1Password?")? {
            ui.show("Stopped. Nothing saved.")?;
            return Ok(6);
        }
        if let Some(id) = &item_id {
            config_compatible(&output, &recipe.manifest(&vault, id)?)?;
            successful(
                backend,
                &["item", "edit", id, "--vault", &vault, "--format", "json"],
                Some(&payload),
            )?;
        } else {
            let created = successful(
                backend,
                &[
                    "item",
                    "create",
                    "-",
                    "--vault",
                    &vault,
                    "--title",
                    &recipe.item,
                    "--format",
                    "json",
                ],
                Some(&payload),
            )?;
            let created = WipeOnDrop(serde_json::from_slice(&created.stdout).map_err(|_| source_error("The create response is invalid. The item may have been saved; rerun setup to find and resume it."))?);
            item_id = created
                .0
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| config::is_id(id))
                .map(str::to_owned);
            if item_id.is_none() {
                return Err(source_error(
                    "The new item ID was not returned. The item may have been saved; rerun setup to resume without duplicating it.",
                ));
            }
        }
    }
    let manifest = recipe.manifest(&vault, item_id.as_deref().expect("existing or created"))?;
    config::parse(&manifest)?;
    config_compatible(&output, &manifest)?;
    if !output.exists() {
        super::init::write_atomic(&output, &manifest, false)?;
    }
    ui.show(&format!(
        "\nLocal configuration ready: {} (IDs and declarations only)",
        output.display()
    ))?;
    if missing.is_empty() {
        ui.show(&format!(
            "All settings are saved. Next: opv --config {} check {}{}",
            quoted(&output),
            recipe.environment,
            active
                .first()
                .and_then(|f| f.product.as_ref())
                .map_or(String::new(), |p| format!(" --product {p}"))
        ))?;
        // Actual value/rule validation is deliberately explicit; never claim the
        // external provider credentials work merely because their fields are filled.
        ui.show("The check validates field types and rules. Provider access is verified by the command you run next.")?;
        Ok(0)
    } else {
        ui.show(&format!("Saved progress. Still needed: {}.\nFill those fields privately in 1Password, or rerun this same setup command. No infrastructure changed.", missing.join(", ")))?;
        Ok(8)
    }
}

fn quoted(path: &Path) -> String {
    let value = path.to_string_lossy();
    match crate::host::Host::detect().shell {
        crate::host::Shell::PowerShell => format!("'{}'", value.replace('\'', "''")),
        _ => format!("'{}'", value.replace('\'', "'\\''")),
    }
}

#[cfg(test)]
#[path = "setup_tests.rs"]
mod tests;
