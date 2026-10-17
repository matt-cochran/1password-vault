//! The configuration forms of `opv ui` (#97): the fields a person fills in to declare a key
//! (`opv add`) or an environment (`opv init <env> --add-env`), and the exact `opv` argument
//! list each form runs. Pure: names, kinds and choices only, and never a value.

/// Whether a declared key is a concealed secret or plain configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KindChoice {
    Secret,
    Config,
}

/// The fields of the `opv add` form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddKeyForm {
    pub product: Option<String>,
    pub key: String,
    pub kind: KindChoice,
    pub environments: Vec<String>,
    pub guidance: String,
    pub personal: bool,
    pub allow_same_value: bool,
}

/// The fields of the `opv init <env> --add-env` form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddEnvForm {
    pub name: String,
    pub vault: String,
    pub item: String,
}

/// `["add", label, "--kind", "secret"|"config"]` where label is "product/KEY" when product is Some, else "KEY"; then "--env" and the environments joined with "," when not empty; then "--guidance" and the trimmed guidance when it is not empty; then "--personal" when personal; then "--allow-same-value" when allow_same_value.
/// Err(one English sentence) when: key is not ^[A-Z][A-Z0-9_]*$; product is None, or not ^[a-z][a-z0-9_-]*$; personal and allow_same_value are both set; personal and kind is Config.
pub fn add_key_command(form: &AddKeyForm) -> Result<Vec<String>, String> {
    if !is_key_name(&form.key) {
        return Err(format!(
            "key {:?} is not a valid name: start with a capital letter and use A-Z, 0-9 or _.",
            form.key
        ));
    }
    if let Some(product) = &form.product
        && !is_product_name(product)
    {
        return Err(format!(
            "product {product:?} is not a valid name: start with a lowercase letter and use \
             a-z, 0-9, _ or -."
        ));
    }
    if form.product.is_none() {
        return Err("keys are declared per product: use PRODUCT/KEY.".to_string());
    }
    if form.personal && form.allow_same_value {
        return Err("personal and allow_same_value cannot both be set.".to_string());
    }
    if form.personal && form.kind == KindChoice::Config {
        return Err("personal keys must be secret, not config.".to_string());
    }
    let label = match &form.product {
        Some(product) => format!("{product}/{}", form.key),
        None => form.key.clone(),
    };
    let kind = match form.kind {
        KindChoice::Secret => "secret",
        KindChoice::Config => "config",
    };
    let mut out = vec![
        "add".to_string(),
        label,
        "--kind".to_string(),
        kind.to_string(),
    ];
    if !form.environments.is_empty() {
        out.push("--env".to_string());
        out.push(form.environments.join(","));
    }
    let guidance = form.guidance.trim();
    if !guidance.is_empty() {
        out.push("--guidance".to_string());
        out.push(guidance.to_string());
    }
    if form.personal {
        out.push("--personal".to_string());
    }
    if form.allow_same_value {
        out.push("--allow-same-value".to_string());
    }
    Ok(out)
}

/// `["init", name, "--add-env"]` then "--vault" vault when vault (trimmed) is not empty, then "--item" item when item (trimmed) is not empty.
/// Err(one English sentence) when name is not ^[A-Za-z0-9][A-Za-z0-9_-]*$ or name is already in `existing`.
pub fn add_env_command(form: &AddEnvForm, existing: &[String]) -> Result<Vec<String>, String> {
    if !is_env_name(&form.name) {
        return Err(format!(
            "environment name {:?} is not a valid name: start with a letter or digit and use \
             A-Z, a-z, 0-9, _ or -.",
            form.name
        ));
    }
    if existing.iter().any(|name| name == &form.name) {
        return Err(format!("environment {} already exists.", form.name));
    }
    let mut out = vec![
        "init".to_string(),
        form.name.clone(),
        "--add-env".to_string(),
    ];
    let vault = form.vault.trim();
    if !vault.is_empty() {
        out.push("--vault".to_string());
        out.push(vault.to_string());
    }
    let item = form.item.trim();
    if !item.is_empty() {
        out.push("--item".to_string());
        out.push(item.to_string());
    }
    Ok(out)
}

/// `^[A-Z][A-Z0-9_]*$`, checked by hand (never a regex).
fn is_key_name(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some('A'..='Z'))
        && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// `^[a-z][a-z0-9_-]*$`, checked by hand.
fn is_product_name(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some('a'..='z'))
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// `^[A-Za-z0-9][A-Za-z0-9_-]*$`, checked by hand.
fn is_env_name(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

#[cfg(test)]
#[path = "config_forms_tests.rs"]
mod tests;
