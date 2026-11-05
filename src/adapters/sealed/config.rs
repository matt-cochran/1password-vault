//! The sealed target's configuration contract (design `sealed-target` §3, §3.1, D11, D12,
//! G4, T1, T5, T14).
//!
//! [`SealedTarget::parse`] applies the rules of one section; [`check_fleet`] applies the
//! rules that span targets: recipients and signers are never shared across trust groups,
//! rendered bundle paths are unique, `{product}` is in `sealed.out` when a target delivers
//! more than one product, `deploy_credentials` is required, and a sealed target never
//! delivers an age identity or a key read from its own signing item. Every refusal names
//! the field and the rule; a recipient or signer is named by its fingerprint only.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::bundle::crypto::{parse_recipient, recipient_fingerprint, signer_fingerprint};
use crate::cause::{ConfigCheck, DottedPath, FieldRule};
use crate::config::section_invalid;
use crate::domain::{Fleet, ItemRef};
use crate::error::Error;
use crate::provider::{FleetRefusal, Placement};

/// The placeholder `sealed.out` renders per product.
pub const PRODUCT: &str = "{product}";

/// The section as written (§3).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Raw {
    out: String,
    env_name: String,
    recipients: Vec<String>,
    signer: String,
    #[serde(default)]
    trust_group: Option<String>,
}

/// Which targets may share recipients and signers (D11). Without `sealed.trust_group` a
/// target's group is its environment, so a key is shared only within one environment; a
/// named group is a separate namespace from environment names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustGroup {
    Environment(String),
    Named(String),
}

/// A parsed and validated sealed target. Recipients and the signer are public keys, kept
/// with their fingerprints, which are what messages show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedTarget {
    /// The environment whose section this is: the header's `environment` and the signer's
    /// principal.
    pub env: String,
    /// `sealed.out`: relative, no `..`, may hold `{product}`.
    pub out: String,
    /// `sealed.env_name`: holds `{KEY}`, may hold `{PRODUCT}`.
    pub env_name_template: String,
    /// The canonical `age1…` recipient strings, in the order written.
    pub recipients: Vec<String>,
    /// `sha256:<16 hex>` of each recipient, in the same order.
    pub recipient_fingerprints: Vec<String>,
    /// `SHA256:…` of `sealed.signer`.
    pub signer_fingerprint: String,
    /// `sealed.signer` in OpenSSH form without its comment, which a listed bundle's
    /// signature is verified against (T10, R7).
    pub signer_key: String,
    pub trust_group: TrustGroup,
    /// The configuration file's directory, which `sealed.out` is relative to without
    /// `--sealed-root`.
    pub config_dir: PathBuf,
    /// `opv sync --sealed-root <dir>` (D12), for this run; `None` from the configuration.
    pub out_root: Option<PathBuf>,
    /// The target's name and what it delivers, set when the configuration is read
    /// ([`crate::provider::TargetConfig::set_placement`]).
    pub placement: Placement,
}

/// `field` of the `sealed` section, refused for `rule`.
fn bad(field: &str, rule: FieldRule) -> Error {
    section_invalid(&format!("sealed.{field}"), rule)
}

fn expected(field: &str, words: &'static str) -> Error {
    bad(field, FieldRule::Type { expected: words })
}

/// `sealed.out` (§3.1-5): relative, with no `..`, `.` or empty part, no absolute, drive or
/// home prefix, no backslash or NUL, and no placeholder but `{product}`.
pub fn is_relative_out(s: &str) -> bool {
    let bytes = s.as_bytes();
    let drive = bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic();
    let placeholders_ok = s.replace(PRODUCT, "").chars().all(|c| c != '{' && c != '}');
    !s.is_empty()
        && !s.starts_with('/')
        && !s.starts_with('~')
        && !drive
        && !s.contains('\\')
        && !s.contains('\0')
        && placeholders_ok
        && s.split('/').all(|p| !p.is_empty() && p != "." && p != "..")
}

/// A trust group name: lower-case letters, digits and `-`, starting with a letter or digit,
/// at most 63 characters.
fn is_group_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && !s.starts_with('-')
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// `sealed.env_name`: holds `{KEY}`, no placeholder but `{KEY}` and `{PRODUCT}`, and never
/// starts with `OP_` (FR-35).
fn is_env_template(s: &str) -> bool {
    s.contains("{KEY}")
        && s.replace("{KEY}", "")
            .replace("{PRODUCT}", "")
            .chars()
            .all(|c| c != '{' && c != '}')
        && !s.starts_with("OP_")
}

impl SealedTarget {
    /// The section of environment `env`, with `config_dir` the configuration file's
    /// directory (§3.1-1, -3, -5, -6; D11).
    pub(super) fn parse(raw: Raw, env: &str, config_dir: PathBuf) -> Result<Self, Error> {
        if !is_relative_out(&raw.out) {
            return Err(expected(
                "out",
                "a relative path without .., such as sealed/{product}.opv-sealed",
            ));
        }
        if !is_env_template(&raw.env_name) {
            return Err(expected(
                "env_name",
                "a template containing {KEY} (and optionally {PRODUCT}), not starting with OP_",
            ));
        }
        if raw.recipients.is_empty() {
            return Err(bad("recipients", FieldRule::Empty));
        }
        let mut recipients = Vec::new();
        let mut recipient_fingerprints = Vec::new();
        for text in &raw.recipients {
            let r = parse_recipient(text.trim())
                .map_err(|_| expected("recipients", "a list of age1… X25519 recipients"))?;
            let canonical = r.to_string();
            if recipients.contains(&canonical) {
                return Err(expected(
                    "recipients",
                    "a list of distinct age1… X25519 recipients",
                ));
            }
            recipient_fingerprints.push(recipient_fingerprint(&r));
            recipients.push(canonical);
        }
        let signer = ssh_key::PublicKey::from_openssh(raw.signer.trim())
            .ok()
            .filter(|k| k.algorithm() == ssh_key::Algorithm::Ed25519)
            .ok_or_else(|| expected("signer", "one ssh-ed25519 OpenSSH public key"))?;
        let trust_group = match raw.trust_group {
            None => TrustGroup::Environment(env.to_string()),
            Some(g) if is_group_name(&g) => TrustGroup::Named(g),
            Some(_) => {
                return Err(expected(
                    "trust_group",
                    "a trust group name: lower-case letters, digits and -, at most 63 characters",
                ));
            }
        };
        Ok(SealedTarget {
            env: env.to_string(),
            out: raw.out,
            env_name_template: raw.env_name,
            recipients,
            recipient_fingerprints,
            signer_fingerprint: signer_fingerprint(&signer),
            signer_key: ssh_key::PublicKey::new(signer.key_data().clone(), "")
                .to_openssh()
                .map_err(|_| expected("signer", "one ssh-ed25519 OpenSSH public key"))?,
            trust_group,
            config_dir,
            out_root: None,
            placement: Placement::default(),
        })
    }

    /// The env var name of `product`/`key`: `{PRODUCT}` is the upper-cased product with `-`
    /// as `_`, `{KEY}` the key.
    pub fn env_name_of(&self, product: &str, key: &str) -> String {
        let product = product.to_ascii_uppercase().replace('-', "_");
        self.env_name_template
            .replace("{PRODUCT}", &product)
            .replace("{KEY}", key)
    }

    /// `sealed.out` rendered for `product`, still relative.
    pub fn out_of(&self, product: &str) -> String {
        self.out.replace(PRODUCT, product)
    }

    /// Where `product`'s bundle is written (D12): under `sealed_root` when `opv sync
    /// --sealed-root <dir>` gives one, else beside the configuration file.
    pub fn bundle_path(&self, product: &str, sealed_root: Option<&Path>) -> PathBuf {
        let base = sealed_root.unwrap_or(&self.config_dir);
        base.join(self.out_of(product))
    }

    /// Where this run writes `product`'s bundle: [`SealedTarget::bundle_path`] under the
    /// run's `--sealed-root`, when given ([`crate::provider::TargetConfig::set_out_root`]).
    pub fn written_path(&self, product: &str) -> PathBuf {
        self.bundle_path(product, self.out_root.as_deref())
    }
}

/// One sealed target of the fleet, with its place in the configuration.
struct Entry<'f> {
    env: &'f str,
    name: &'f str,
    sealed: &'f SealedTarget,
    deploy_credentials: Option<&'f ItemRef>,
}

impl Entry<'_> {
    fn path(&self, tail: &[&str]) -> Vec<String> {
        ["environments", self.env, "targets", self.name]
            .iter()
            .chain(tail)
            .map(|s| s.to_string())
            .collect()
    }

    fn sealed_path(&self, field: &str) -> Vec<String> {
        self.path(&["sealed", field])
    }
}

/// The §3.1 rules across the sealed targets of `fleet` (D11, G4, T1, T14).
pub fn check_fleet(fleet: &Fleet) -> Result<(), Box<FleetRefusal>> {
    let entries: Vec<Entry<'_>> = fleet
        .environments
        .iter()
        .flat_map(|(env, e)| {
            e.targets.iter().filter_map(move |(name, t)| {
                t.config
                    .as_any()
                    .downcast_ref::<SealedTarget>()
                    .map(|sealed| Entry {
                        env,
                        name,
                        sealed,
                        deploy_credentials: t.deploy_credentials.as_ref(),
                    })
            })
        })
        .collect();
    for (i, entry) in entries.iter().enumerate() {
        shared_across_groups(entry, &entries[..i])?;
        check_target(fleet, entry)?;
    }
    unique_bundle_paths(fleet, &entries)
}

/// §3.1-2 and §3.1-4 under D11: no recipient and no signer of `entry` belongs to a target
/// of another trust group among `earlier`.
fn shared_across_groups(entry: &Entry<'_>, earlier: &[Entry<'_>]) -> Result<(), Box<FleetRefusal>> {
    for other in earlier
        .iter()
        .filter(|o| o.sealed.trust_group != entry.sealed.trust_group)
    {
        let shared = entry
            .sealed
            .recipient_fingerprints
            .iter()
            .find(|fp| other.sealed.recipient_fingerprints.contains(fp));
        if let Some(fp) = shared {
            return Err(Box::new(FleetRefusal {
                path: entry.sealed_path("recipients"),
                rule: FieldRule::Check {
                    check: ConfigCheck::SealedRecipientShared {
                        recipient: fp.clone(),
                        other_env: other.env.to_string(),
                        other_target: other.name.to_string(),
                    },
                },
            }));
        }
        if entry.sealed.signer_fingerprint == other.sealed.signer_fingerprint {
            return Err(Box::new(FleetRefusal {
                path: entry.sealed_path("signer"),
                rule: FieldRule::Check {
                    check: ConfigCheck::SealedSignerShared {
                        signer: entry.sealed.signer_fingerprint.clone(),
                        other_env: other.env.to_string(),
                        other_target: other.name.to_string(),
                    },
                },
            }));
        }
    }
    Ok(())
}

/// The rules of one target that need the products: `deploy_credentials` (§3.1-7),
/// `{product}` (§3.1-5), no `OP_*` name (§3.1-6), no age identity (§3.1-8, T14) and no key
/// read from the signing item (G4).
fn check_target(fleet: &Fleet, entry: &Entry<'_>) -> Result<(), Box<FleetRefusal>> {
    let Some(signer_item) = entry.deploy_credentials else {
        return Err(Box::new(FleetRefusal {
            path: entry.path(&["deploy_credentials"]),
            rule: FieldRule::Missing,
        }));
    };
    let delivered: Vec<&String> = fleet
        .products
        .keys()
        .filter(|p| fleet.delivers(entry.env, entry.name, p))
        .collect();
    if delivered.len() > 1 && !entry.sealed.out.contains(PRODUCT) {
        return Err(Box::new(FleetRefusal {
            path: entry.sealed_path("out"),
            rule: FieldRule::Type {
                expected: "a path containing {product}, since the target delivers more than one product",
            },
        }));
    }
    for product in delivered {
        for (key, spec) in &fleet.products[product].keys {
            if !spec.is_desired_in(entry.env) {
                continue;
            }
            let key_path = || {
                ["products", product, "keys", key]
                    .map(String::from)
                    .to_vec()
            };
            let target = entry.name.to_string();
            // A shared key carries its source's value, so its source's rules and item count.
            let (value_product, source) = match spec.source() {
                Some((sp, sk)) => (sp, fleet.products.get(sp).and_then(|p| p.keys.get(sk))),
                None => (product.as_str(), None),
            };
            if spec.rules.age_identity || source.is_some_and(|s| s.rules.age_identity) {
                return Err(Box::new(FleetRefusal {
                    path: key_path(),
                    rule: FieldRule::Check {
                        check: ConfigCheck::SealedDeliversIdentity { target },
                    },
                }));
            }
            let in_signer_item = fleet
                .boundary(entry.env, value_product)
                .is_ok_and(|b| b.vault_id == signer_item.vault && b.item_id == signer_item.item);
            if in_signer_item {
                return Err(Box::new(FleetRefusal {
                    path: key_path(),
                    rule: FieldRule::Check {
                        check: ConfigCheck::SealedDeliversSigner { target },
                    },
                }));
            }
            if entry.sealed.env_name_of(product, key).starts_with("OP_") {
                return Err(Box::new(FleetRefusal {
                    path: entry.sealed_path("env_name"),
                    rule: FieldRule::Reserved {
                        set: vec!["OP_*".to_string()],
                    },
                }));
            }
        }
    }
    Ok(())
}

/// §3.1-5: every rendered bundle path is unique across the whole configuration.
fn unique_bundle_paths(fleet: &Fleet, entries: &[Entry<'_>]) -> Result<(), Box<FleetRefusal>> {
    let mut seen: Vec<(PathBuf, &Entry<'_>)> = Vec::new();
    for entry in entries {
        for product in fleet
            .products
            .keys()
            .filter(|p| fleet.delivers(entry.env, entry.name, p))
        {
            let path = entry.sealed.bundle_path(product, None);
            if let Some((_, other)) = seen.iter().find(|(p, _)| *p == path) {
                return Err(Box::new(FleetRefusal {
                    path: entry.sealed_path("out"),
                    rule: FieldRule::Collision {
                        rendered: entry.sealed.out_of(product),
                        other: DottedPath(other.sealed_path("out")),
                    },
                }));
            }
            seen.push((path, entry));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
