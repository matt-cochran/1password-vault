//! `opv generate <env> <product/KEY>…` (0.9.0): make a self-generated secret (an encryption
//! key, a signing or session secret) and write it straight into its 1Password field, so no
//! person or assistant ever sees, copies or pastes it.
//!
//! Only keys whose rules say what the value is: `base64_bytes = N` (N random bytes,
//! standard padded base64), `hex_bytes = N` (N random bytes, lowercase hex), from the
//! operating system's CSPRNG, or `age_identity = true` (a fresh X25519 identity, whose
//! public `age1…` recipient is printed and whose secret is only stored). Provider-issued
//! keys (anything with a prefix rule, or no byte-length rule) are refused: those come from
//! the provider, typed by a person.
//!
//! A field that already holds a value is never overwritten: rotation is a separate,
//! reviewed step. The write is one item edit, read back and verified (the same writer as
//! `opv adopt --apply`), and only by a person's own 1Password session. The value lives only
//! in a zeroizing [`SecretValue`]; output names the key, never the value.

use std::io::Write;

use base64::Engine as _;
use secrecy::ExposeSecret;

use super::write_err;
use crate::cause::{
    Cause, EnvName, GenerateRefusal, Guard, IoKind, KeyName, NameKind, ProductName, UsageProblem,
};
use crate::domain::{KeySpec, SecretValue, key_label};
use crate::error::Error;
use crate::runner::CommandRunner;

#[path = "generate_ssh.rs"]
pub(crate) mod generate_ssh;

/// How a key's value is generated: its encoding and byte count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recipe {
    Base64(usize),
    Hex(usize),
    /// A fresh age X25519 identity (`AGE-SECRET-KEY-1…`), whose public `age1…`
    /// recipient is printed for the sealed target's `recipients` (§7.1).
    AgeIdentity,
    /// A fresh Ed25519 OpenSSH keypair (#294), encoded the way `ssh-keygen` writes one.
    SshEd25519,
}

impl Recipe {
    /// One line for the person: `base64, 32 bytes`.
    pub fn describe(self) -> String {
        match self {
            Recipe::Base64(n) => format!("base64, {n} random bytes"),
            Recipe::Hex(n) => format!("hex, {n} random bytes"),
            Recipe::AgeIdentity => "an age X25519 identity".to_string(),
            Recipe::SshEd25519 => "an Ed25519 OpenSSH key".to_string(),
        }
    }
}

/// Why opv does not generate `product/key` in `env`, as the catalog's guard (R64). Each
/// reason is said apart (05.11): a provider-issued key, a personal one, a shared one, a
/// byte count out of range, a field that already holds a value, an infrastructure key.
fn refused(product: &str, key: &str, env: &str, reason: GenerateRefusal) -> Error {
    Cause::Guard {
        guard: Guard::GenerateRefused {
            product: ProductName::new(product),
            key: KeyName::new(key),
            env: EnvName::new(env),
            reason,
        },
    }
    .into()
}

/// The recipe a key's rules give, or why opv will not generate `product/key` in `env`.
pub fn recipe(product: &str, key: &str, env: &str, spec: &KeySpec) -> Result<Recipe, Error> {
    let r = &spec.rules;
    let refuse = |reason: GenerateRefusal| Err(refused(product, key, env, reason));
    // An infrastructure key is never stored (#206 §4.4), whatever its rules say: said
    // first, since its shape rule may well give a byte count.
    if super::deliver_only::is_infrastructure(spec) {
        return refuse(GenerateRefusal::Infrastructure);
    }
    if spec.personal {
        return refuse(GenerateRefusal::Personal);
    }
    if let Some(from) = &spec.from {
        return refuse(GenerateRefusal::Shared { from: from.clone() });
    }
    if r.prefix.is_some() || r.ensure_prefix.is_some() || r.prefix_by_mode.is_some() {
        return refuse(GenerateRefusal::ProviderIssued);
    }
    // An identity carries its meaning in the flag, not a byte count: exactly one format, a
    // secret, and an SSH key delivered as a file (0.18.3).
    if r.age_identity || r.ssh_ed25519 {
        if !spec.has_generate_recipe() {
            return refuse(GenerateRefusal::NoByteCount);
        }
        return Ok(if r.age_identity {
            Recipe::AgeIdentity
        } else {
            Recipe::SshEd25519
        });
    }
    // The positive shape is decided by the same domain predicate the config validator uses
    // ([`KeySpec::has_generate_recipe`]), so the two can never disagree. Everything that is
    // left is a key with exactly one in-range byte count.
    if !spec.has_generate_recipe() {
        return if r.base64_bytes.is_some() || r.hex_bytes.is_some() {
            refuse(GenerateRefusal::ByteCountOutOfRange)
        } else {
            refuse(GenerateRefusal::NoByteCount)
        };
    }
    match (r.base64_bytes, r.hex_bytes) {
        (Some(n), None) => Ok(Recipe::Base64(n)),
        (None, Some(n)) => Ok(Recipe::Hex(n)),
        _ => refuse(GenerateRefusal::NoByteCount),
    }
}

/// The operating system's random source failed (F2): opv's own local I/O, never a tool.
fn random_source_failed() -> Error {
    Cause::LocalIo {
        op: crate::cause::LocalOp::RandomSource,
        path: std::path::PathBuf::new(),
        io: IoKind::Other,
        delivery: None,
    }
    .into()
}

/// A fresh value for `recipe` from the operating system's CSPRNG.
pub fn make(recipe: Recipe) -> Result<SecretValue, Error> {
    let n = match recipe {
        Recipe::Base64(n) | Recipe::Hex(n) => n,
        Recipe::AgeIdentity => return Ok(make_identity().0),
        Recipe::SshEd25519 => return Ok(generate_ssh::make_ed25519()?.0),
    };
    let mut bytes = zeroize::Zeroizing::new(vec![0u8; n]);
    getrandom::fill(&mut bytes).map_err(|_| -> Error { random_source_failed() })?;
    let text = match recipe {
        Recipe::Base64(_) => base64::engine::general_purpose::STANDARD.encode(&*bytes),
        Recipe::Hex(_) => hex::encode(&*bytes),
        Recipe::AgeIdentity | Recipe::SshEd25519 => {
            unreachable!("handled by the early return above")
        }
    };
    Ok(SecretValue::new(text))
}

/// A fresh age X25519 identity, as the secret text to store and its public `age1…`
/// recipient. `age`'s identity zeroizes on drop, and the text lives in a [`SecretValue`].
fn make_identity() -> (SecretValue, String) {
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public().to_string();
    (
        SecretValue::new(identity.to_string().expose_secret().to_owned()),
        recipient,
    )
}

/// Generate each `product/KEY` in `env_name` and write it into 1Password.
pub fn run(
    fleet: &crate::domain::Fleet,
    env_name: &str,
    keys: &[String],
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    run_on(fleet, env_name, keys, r, crate::host::Host::detect(), out)
}

/// [`run`] with the person's own-session check judged by `host` (the host `opv apply` was
/// given), never by this process's variables.
pub fn run_on(
    fleet: &crate::domain::Fleet,
    env_name: &str,
    keys: &[String],
    r: &dyn CommandRunner,
    host: crate::host::Host,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let env = fleet.environment(env_name)?;
    // Everything is checked before anything is written.
    let chosen = plan(fleet, env_name, keys)?;
    super::tidy::require_person_on(r, "opv apply", host)?;
    // Never over a value: what 1Password holds now, read fresh.
    let read = super::tidy::read(fleet, env_name, r)?;
    for (product, key, _) in &chosen {
        let filled = read
            .fields
            .iter()
            .any(|f| f.section == *product && f.label == *key && !f.value.expose().is_empty());
        if filled {
            return Err(refused(product, key, env_name, GenerateRefusal::HasValue));
        }
    }
    let mut writes: Vec<(String, String, SecretValue)> = Vec::with_capacity(chosen.len());
    let mut public_lines: Vec<Vec<String>> = Vec::with_capacity(chosen.len());
    for (p, k, rcp) in &chosen {
        match rcp {
            Recipe::AgeIdentity => {
                let (value, recipient) = make_identity();
                writes.push((p.clone(), k.clone(), value));
                public_lines.push(vec![recipient]);
            }
            Recipe::SshEd25519 => {
                let (value, ssh_public) = generate_ssh::make_ed25519()?;
                // The private key is a secret before it can reach a write or an error path.
                crate::scrub::register_secret(value.expose());
                writes.push((p.clone(), k.clone(), value));
                public_lines.push(vec![ssh_public.openssh, ssh_public.fingerprint]);
            }
            _ => {
                writes.push((p.clone(), k.clone(), make(*rcp)?));
                public_lines.push(Vec::new());
            }
        }
    }
    // A read-back failure names the apply that generates (05.10): run again, a value that
    // landed is refused as already there, never replaced.
    let by = crate::cause::Cmd {
        command: vec!["apply".into()],
        args: keys
            .iter()
            .flat_map(|k| ["--generate".to_string(), format!("{env_name}:{k}")])
            .collect(),
    };
    super::import::write_values(fleet, env, &writes, &by, r)?;
    for ((p, k, rcp), lines) in chosen.iter().zip(&public_lines) {
        writeln!(
            out,
            "generated {} in 1Password ({}); the value was never shown",
            key_label(p, k),
            rcp.describe()
        )
        .map_err(write_err)?;
        // Only public material is shown: an age recipient, or an SSH public key and its
        // fingerprint, so the person can put it in the consumer's trust configuration.
        for line in lines {
            writeln!(out, "{line}").map_err(write_err)?;
        }
    }
    let next = crate::cause::Cmd {
        command: vec!["status".into()],
        args: vec![env_name.to_string()],
    };
    writeln!(out, "Next: {}", crate::cause::render::cmd_text(&next)).map_err(write_err)
}

/// The recipe chosen for each `product/KEY` in `env_name`, after every name and declaration
/// is checked. Shared by [`run`] and the MCP `opv_generate` tool so both agree on what is
/// generated; never reads or writes 1Password.
pub fn plan(
    fleet: &crate::domain::Fleet,
    env_name: &str,
    keys: &[String],
) -> Result<Vec<(String, String, Recipe)>, Error> {
    fleet.environment(env_name)?;
    let mut chosen: Vec<(String, String, Recipe)> = Vec::new();
    for k in keys {
        let (product, key) = k.split_once('/').ok_or_else(|| -> Error {
            Cause::Usage {
                problem: UsageProblem::ValueFormat {
                    flag: k.clone(),
                    format: "<product>/<KEY>",
                },
            }
            .into()
        })?;
        // Declared at all, then declared for this environment: each names the keys that
        // are (05.39), so a typo gets the same command with the right name.
        let spec = fleet.products.get(product).and_then(|p| p.keys.get(key));
        let Some(spec) = spec.filter(|s| s.is_desired_in(env_name)) else {
            let declared: Vec<String> = fleet
                .products
                .iter()
                .flat_map(|(p, prod)| {
                    prod.keys
                        .iter()
                        .filter(|(_, s)| s.is_desired_in(env_name))
                        .map(move |(k, _)| key_label(p, k))
                })
                .collect();
            return Err(super::not_declared(
                NameKind::Key,
                k,
                declared.iter().map(String::as_str),
            ));
        };
        // A set member is written only together with its set (#253 §5.6): refused from the
        // configuration alone, before the recipe, so no 1Password call is ever made.
        super::import::refuse_set_member(fleet, product, key, env_name)?;
        chosen.push((
            product.into(),
            key.into(),
            recipe(product, key, env_name, spec)?,
        ));
    }
    Ok(chosen)
}

#[cfg(test)]
#[path = "generate_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "generate_age_tests.rs"]
mod age_tests;

#[cfg(test)]
#[path = "generate_ssh_tests.rs"]
mod ssh_tests;
