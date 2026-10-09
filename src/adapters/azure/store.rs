//! `[stores.<name>]` with `azure_key_vault = "<vault>"`: a Key Vault other runtimes keep
//! their secrets in (FR-39, `docs/design/multi-cloud-targets.md` §13).
//!
//! ```toml
//! [stores.prod-vault]
//! azure_key_vault = "kv-myapp-prod"
//! subscription    = "00000000-0000-0000-0000-000000000000"
//! # secret_store  = "prod-vault"   # the in-cluster ClusterSecretStore (default: the store name)
//! ```
//!
//! The store port is the Key Vault adapter unchanged ([`KeyVault`]); its checks are the
//! Azure target's vault checks ([`preflight::store_checks`]), so a store and an `azure`
//! section are judged the same way.

use std::any::Any;
use std::collections::BTreeSet;

use serde::Deserialize;
use serde::de::{self, Deserializer};

use super::AzureTarget;
use super::config::{PROVIDER, Subscription, key_vault_char};
use super::keyvault::KeyVault;
use super::preflight::{self, Vault};
use crate::error::Error;
use crate::host::Host;
use crate::ports::PinnedStore;
use crate::provider::{Check, Provider, Section, StoreConfig, StoreNameRules, store_eq_as};
use crate::runner::CommandRunner;

/// The store kind key.
pub const KIND: &str = "azure_key_vault";

/// A named Key Vault store (FR-39).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyVaultStore {
    /// `[stores.<name>]`.
    pub name: String,
    pub vault: String,
    /// A subscription id, passed as `--subscription` on every call (NR-7).
    pub subscription: String,
    /// The in-cluster `ClusterSecretStore` that reads this vault.
    pub secret_store: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    #[serde(deserialize_with = "vault_name")]
    azure_key_vault: String,
    subscription: Subscription,
    #[serde(default, deserialize_with = "secret_store")]
    secret_store: Option<String>,
}

/// A Key Vault name as Azure allows it: 3 to 24 letters, digits and `-`, starting with a
/// letter, ending with a letter or digit, no `--`.
fn vault_name<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let s = String::deserialize(d)?;
    let b = s.as_bytes();
    let ok = (3..=24).contains(&b.len())
        && b[0].is_ascii_alphabetic()
        && b[b.len() - 1].is_ascii_alphanumeric()
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
        && !s.contains("--");
    if ok {
        Ok(s)
    } else {
        Err(de::Error::custom(format!(
            "azure_key_vault {s:?} must be a Key Vault name: 3 to 24 letters, digits and -, \
             starting with a letter (az keyvault list -o table shows yours)"
        )))
    }
}

/// A Kubernetes object name (DNS-1123 subdomain): what a `ClusterSecretStore` may be called.
fn secret_store<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    let s = String::deserialize(d)?;
    let alnum = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    let b = s.as_bytes();
    let ok = (1..=253).contains(&b.len())
        && b.iter().all(|&c| alnum(c) || c == b'-' || c == b'.')
        && alnum(b[0])
        && alnum(b[b.len() - 1]);
    if ok {
        Ok(Some(s))
    } else {
        Err(de::Error::custom(format!(
            "secret_store {s:?} must be a ClusterSecretStore name: lower-case letters, digits, \
             - and . (kubectl get clustersecretstores lists them)"
        )))
    }
}

/// Parses `[stores.<name>]` of kind [`KIND`].
pub fn parse(section: &Section<'_>) -> Result<Box<dyn StoreConfig>, Error> {
    let raw: Raw = section.deserialize()?;
    let name = section.env().to_string();
    Ok(Box::new(KeyVaultStore {
        secret_store: raw.secret_store.unwrap_or_else(|| name.clone()),
        name,
        vault: raw.azure_key_vault,
        subscription: raw.subscription.0,
    }))
}

impl KeyVaultStore {
    fn vault_ref(&self) -> Vault {
        Vault {
            name: self.vault.clone(),
            subscription: self.subscription.clone(),
            vault_field: format!("stores.{}.azure_key_vault", self.name),
            subscription_field: format!("stores.{}.subscription", self.name),
        }
    }
}

impl StoreConfig for KeyVaultStore {
    fn provider(&self) -> &'static dyn Provider {
        &PROVIDER
    }

    fn kind(&self) -> &'static str {
        KIND
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn describe(&self) -> String {
        format!("Key Vault {}", self.vault)
    }

    fn locator(&self) -> &str {
        &self.vault
    }

    fn bridge_name(&self) -> &str {
        &self.secret_store
    }

    fn store_name(&self, env_name: &str) -> String {
        AzureTarget::key_vault_name(env_name)
    }

    fn name_rules(&self) -> StoreNameRules {
        StoreNameRules {
            label: "Key Vault name",
            max_len: 127,
            allowed: key_vault_char,
            edge: key_vault_char,
            pattern: "^[0-9A-Za-z-]{1,127}$",
            // R3: Key Vault names are case-insensitive.
            case_insensitive: true,
        }
    }

    fn open<'a>(
        &'a self,
        env: &'a str,
        managed: BTreeSet<String>,
        r: &'a dyn CommandRunner,
    ) -> Box<dyn PinnedStore + 'a> {
        Box::new(KeyVault {
            runner: r,
            vault: &self.vault,
            subscription: &self.subscription,
            env,
            managed,
        })
    }

    fn preflight(&self, r: &dyn CommandRunner) -> Result<(), Error> {
        preflight::store_checks(&self.vault_ref(), r).map(|_| ())
    }

    fn doctor(&self, r: &dyn CommandRunner, host: &dyn Fn() -> Host) -> Vec<Check> {
        preflight::store_doctor(&self.vault_ref(), r, host)
    }

    fn explain(&self, env_name: &str) -> Vec<(&'static str, String)> {
        vec![
            ("store", format!("{} (Key Vault {})", self.name, self.vault)),
            ("key vault name", AzureTarget::key_vault_name(env_name)),
        ]
    }

    fn same_store(&self, other: &dyn StoreConfig) -> bool {
        other
            .as_any()
            .downcast_ref::<KeyVaultStore>()
            .is_some_and(|o| o.vault.eq_ignore_ascii_case(&self.vault))
    }

    fn eq_dyn(&self, other: &dyn StoreConfig) -> bool {
        store_eq_as(self, other)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn clone_box(&self) -> Box<dyn StoreConfig> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse as parse_config;

    fn toml(store: &str) -> String {
        format!(
            r#"
[profile]
kind = "simple"
[stores.prod-vault]
{store}
[environments.prod]
vault_id = "v"
item_id = "i"
"#
        )
    }

    const OK: &str = r#"azure_key_vault = "kv-myapp-prod"
subscription = "00000000-0000-0000-0000-000000000000""#;

    fn err(store: &str) -> String {
        match parse_config(&toml(store)) {
            Err(Error::Config(m)) => m,
            other => panic!("expected a config error, got {other:?}"),
        }
    }

    #[test]
    fn store_without_subscription_is_refused() {
        assert!(
            err(r#"azure_key_vault = "kv-myapp-prod""#).contains("missing field `subscription`")
        );
    }

    #[test]
    fn store_with_a_bad_subscription_points_at_its_line() {
        let e = err(&OK.replace("00000000-0000-0000-0000-000000000000", "prod"));
        assert!(e.contains("line 6, column 16"), "{e}");
    }

    #[test]
    fn store_with_a_bad_vault_name_names_the_rule() {
        assert!(err(&OK.replace("kv-myapp-prod", "-kv")).contains("must be a Key Vault name"));
    }

    #[test]
    fn store_with_an_unknown_field_is_refused() {
        assert!(err(&format!("{OK}\nresource_group = \"rg\"")).contains("unknown field"));
    }

    #[test]
    fn store_with_a_bad_secret_store_names_the_rule() {
        let e = err(&format!("{OK}\nsecret_store = \"Prod_Vault\""));
        assert!(e.contains("must be a ClusterSecretStore name"), "{e}");
    }

    #[test]
    fn secret_store_defaults_to_the_store_name() {
        let s = parse(&Section::new(
            "prod-vault",
            &toml::de::DeValue::parse(&format!("{{ {} }}", OK.replace('\n', ", "))).unwrap(),
            "",
        ))
        .unwrap();
        assert_eq!(s.bridge_name(), "prod-vault");
    }
}
