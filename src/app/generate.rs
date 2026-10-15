//! `opv generate <env> <product/KEY>…` (0.9.0): make a self-generated secret (an encryption
//! key, a signing or session secret) and write it straight into its 1Password field, so no
//! person or assistant ever sees, copies or pastes it.
//!
//! Only keys whose rules say what the value is: `base64_bytes = N` (N random bytes,
//! standard padded base64) or `hex_bytes = N` (N random bytes, lowercase hex), from the
//! operating system's CSPRNG. Provider-issued keys (anything with a prefix rule, or no
//! byte-length rule) are refused: those come from the provider, typed by a person.
//!
//! A field that already holds a value is never overwritten: rotation is a separate,
//! reviewed step. The write is one item edit, read back and verified (the same writer as
//! `opv adopt --apply`), and only by a person's own 1Password session. The value lives only
//! in a zeroizing [`SecretValue`]; output names the key, never the value.

use std::io::Write;

use base64::Engine as _;

use super::write_err;
use crate::domain::{KeySpec, SecretValue, key_label};
use crate::error::{Code, Error};
use crate::runner::CommandRunner;

/// How a key's value is generated: its encoding and byte count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recipe {
    Base64(usize),
    Hex(usize),
}

impl Recipe {
    /// One line for the person: `base64, 32 bytes`.
    pub fn describe(self) -> String {
        match self {
            Recipe::Base64(n) => format!("base64, {n} random bytes"),
            Recipe::Hex(n) => format!("hex, {n} random bytes"),
        }
    }
}

/// The recipe a key's rules give, or why opv will not generate it.
pub fn recipe(label: &str, spec: &KeySpec) -> Result<Recipe, Error> {
    let r = &spec.rules;
    let refuse = |why: &str| {
        Error::Config(format!("{label}: {why}; opv generates only self-made secrets").into())
            .with_code(Code::PolicyRefused)
            .with_do("ask the person to create the value at its provider and type it in 1Password")
            .with_next(format!("opv open {label}"))
    };
    if r.prefix.is_some() || r.ensure_prefix.is_some() || r.prefix_by_mode.is_some() {
        return Err(refuse("its prefix rule says the provider issues it"));
    }
    if spec.personal || spec.from.is_some() {
        return Err(refuse("it is a personal or shared key"));
    }
    match (r.base64_bytes, r.hex_bytes) {
        (Some(n), None) if (16..=1024).contains(&n) => Ok(Recipe::Base64(n)),
        (None, Some(n)) if (16..=1024).contains(&n) => Ok(Recipe::Hex(n)),
        (Some(_) | None, Some(_) | None) if r.base64_bytes.is_some() || r.hex_bytes.is_some() => {
            Err(refuse(
                "its byte count must be 16 to 1024, from one of base64_bytes or hex_bytes",
            ))
        }
        _ => Err(refuse(
            "its rules give no byte length (base64_bytes or hex_bytes), so the provider issues it",
        )),
    }
}

/// A fresh value for `recipe` from the operating system's CSPRNG.
pub fn make(recipe: Recipe) -> Result<SecretValue, Error> {
    let n = match recipe {
        Recipe::Base64(n) | Recipe::Hex(n) => n,
    };
    let mut bytes = zeroize::Zeroizing::new(vec![0u8; n]);
    getrandom::fill(&mut bytes).map_err(|_| {
        Error::Dependency("the operating system's random source failed; nothing was written".into())
    })?;
    let text = match recipe {
        Recipe::Base64(_) => base64::engine::general_purpose::STANDARD.encode(&*bytes),
        Recipe::Hex(_) => hex::encode(&*bytes),
    };
    Ok(SecretValue::new(text))
}

/// Generate each `product/KEY` in `env_name` and write it into 1Password.
pub fn run(
    fleet: &crate::domain::Fleet,
    env_name: &str,
    keys: &[String],
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let env = fleet.environment(env_name)?;
    // Everything is checked before anything is written.
    let mut chosen: Vec<(String, String, Recipe)> = Vec::new();
    for k in keys {
        let (product, key) = k.split_once('/').ok_or_else(|| {
            Error::Config(format!("{k:?} must be <product>/<KEY>").into()).with_code(Code::Usage)
        })?;
        let spec = fleet
            .products
            .get(product)
            .and_then(|p| p.keys.get(key))
            .ok_or_else(|| {
                Error::Config(format!("{k} is not declared").into()).with_code(Code::UndeclaredKey)
            })?;
        if !spec.environments.iter().any(|e| e == env_name) {
            return Err(
                Error::Config(format!("{k} is not declared for {env_name}").into())
                    .with_code(Code::UndeclaredKey),
            );
        }
        chosen.push((
            product.into(),
            key.into(),
            recipe(&key_label(product, key), spec)?,
        ));
    }
    super::tidy::require_person(r, "opv generate")?;
    // Never over a value: what 1Password holds now, read fresh.
    let read = super::tidy::read(fleet, env_name, r)?;
    for (product, key, _) in &chosen {
        let filled = read
            .fields
            .iter()
            .any(|f| f.section == *product && f.label == *key && !f.value.expose().is_empty());
        if filled {
            return Err(Error::Policy(
                format!(
                    "{} already has a value in 1Password; opv generate never replaces one \
                     (rotation is a reviewed step); nothing was written",
                    key_label(product, key)
                )
                .into(),
            )
            .with_code(Code::PolicyRefused)
            .with_next(format!("opv explain {}", key_label(product, key))));
        }
    }
    let writes: Vec<(String, String, SecretValue)> = chosen
        .iter()
        .map(|(p, k, rcp)| make(*rcp).map(|v| (p.clone(), k.clone(), v)))
        .collect::<Result<_, _>>()?;
    super::adopt::write_values(fleet, env, &writes, r)?;
    for (p, k, rcp) in &chosen {
        writeln!(
            out,
            "generated {} in 1Password ({}); the value was never shown",
            key_label(p, k),
            rcp.describe()
        )
        .map_err(write_err)?;
    }
    writeln!(out, "Next: opv status {env_name}").map_err(write_err)
}

#[cfg(test)]
#[path = "generate_tests.rs"]
mod tests;
