//! `[environments.<env>.azure]` parsing, Key Vault name rules and the Azure
//! `TargetConfig` (FR-28, FR-30, FR-37).

use std::any::Any;

use serde::Deserialize;

use crate::config::{check_ident, is_id};
use crate::domain::{Profile, SIMPLE_TEMPLATE};
use crate::error::Error;
use crate::host::Host;
use crate::ports::Ports;
use crate::provider::{Check, NameRules, Provider, Section, StoreNameRules, TargetConfig, eq_as};
use crate::runner::CommandRunner;

/// The registered Azure provider.
pub static PROVIDER: AzureProvider = AzureProvider;

/// The Azure provider (section `azure`).
#[derive(Debug)]
pub struct AzureProvider;

/// Where the Container App reads configuration (FR-30): plain env vars (`Env`) or
/// Key Vault references only (`Store`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConfigRoute {
    #[default]
    Env,
    Store,
}

/// The Azure Key Vault + Container Apps target of one environment (FR-28, FR-30).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AzureTarget {
    pub key_vault: String,
    pub resource_group: String,
    pub container_app: String,
    /// R1: required only when the app has more than one container.
    pub container: Option<String>,
    /// "system" or a user-assigned identity resource id (R6).
    pub identity: String,
    /// Env-name template; `{KEY}` under the simple profile.
    pub env_name_template: String,
    pub config: ConfigRoute,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAzure {
    key_vault: String,
    resource_group: String,
    container_app: String,
    #[serde(default)]
    container: Option<String>,
    identity: String,
    #[serde(default)]
    env_name: Option<String>,
    #[serde(default)]
    config: Option<String>,
}

fn cfg(msg: String) -> Error {
    Error::Config(msg)
}

impl Provider for AzureProvider {
    fn section(&self) -> &'static str {
        "azure"
    }

    fn label(&self) -> &'static str {
        "Azure"
    }

    fn parse(
        &self,
        section: &Section<'_>,
        profile: Profile,
    ) -> Result<Box<dyn TargetConfig>, Error> {
        let env = section.env();
        let a: RawAzure = section.deserialize()?;
        let template = match (profile, a.env_name.clone()) {
            (Profile::Fleet, Some(t)) if t.contains("{PRODUCT}") && t.contains("{KEY}") => t,
            (Profile::Fleet, Some(t)) => {
                return Err(cfg(format!(
                    "environment {env}: azure.env_name {t:?} must contain {{PRODUCT}} and {{KEY}}"
                )));
            }
            (Profile::Fleet, None) => {
                return Err(cfg(format!(
                    "environment {env}: azure.env_name is required under the fleet profile"
                )));
            }
            (Profile::Simple, Some(_)) => {
                return Err(cfg(format!(
                    "environment {env}: azure.env_name is not allowed under the simple \
                     profile (the env name is the key name)"
                )));
            }
            (Profile::Simple, None) => SIMPLE_TEMPLATE.into(),
        };
        Ok(Box::new(azure_target(env, a, template)?))
    }

    fn doctor_checks(&self) -> &'static [&'static str] {
        &[]
    }

    fn setup_hint(&self, _profile: Profile) -> String {
        "configure azure.key_vault, azure.resource_group, azure.container_app and azure.identity"
            .into()
    }

    fn init_section(&self, _name: &str, _profile: Profile) -> Option<String> {
        None
    }
}

/// Check the identifiers of an `azure` section and build the target (FR-28, FR-30).
fn azure_target(name: &str, a: RawAzure, template: String) -> Result<AzureTarget, Error> {
    let mut ids = vec![
        ("azure.key_vault", a.key_vault.as_str()),
        ("azure.resource_group", a.resource_group.as_str()),
        ("azure.container_app", a.container_app.as_str()),
    ];
    if let Some(c) = &a.container {
        ids.push(("azure.container", c.as_str()));
    }
    for (field, value) in ids {
        check_ident(name, field, value, is_id, "^[A-Za-z0-9][A-Za-z0-9._-]*$")?;
    }
    check_ident(
        name,
        "azure.identity",
        &a.identity,
        is_azure_identity,
        "\"system\" or a resource id of [A-Za-z0-9._/-] not starting with -",
    )?;
    let config = match a.config.as_deref() {
        None | Some("env") => ConfigRoute::Env,
        Some("store") => ConfigRoute::Store,
        Some(v) => {
            return Err(cfg(format!(
                "environment {name}: azure.config must be \"env\" or \"store\", got {v:?}"
            )));
        }
    };
    Ok(AzureTarget {
        key_vault: a.key_vault,
        resource_group: a.resource_group,
        container_app: a.container_app,
        container: a.container,
        identity: a.identity,
        env_name_template: template,
        config,
    })
}

/// `"system"` or a user-assigned identity resource id: like `is_id` but `/` is allowed
/// (and may lead), and nothing may start with `-`.
fn is_azure_identity(s: &str) -> bool {
    !s.starts_with('-')
        && !s.is_empty()
        && s.chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '/'))
}

fn key_vault_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-'
}

impl AzureTarget {
    /// Env var name for `product`/`key`: `{PRODUCT}` becomes the upper-cased product with
    /// `-` replaced by `_`, `{KEY}` becomes the key verbatim.
    pub fn env_name_of(&self, product: &str, key: &str) -> String {
        let product = product.to_ascii_uppercase().replace('-', "_");
        self.env_name_template
            .replace("{PRODUCT}", &product)
            .replace("{KEY}", key)
    }

    /// Key Vault secret name for an env name: `_` becomes `-` (spec section 5).
    pub fn key_vault_name(env_name: &str) -> String {
        env_name.replace('_', "-")
    }
}

impl TargetConfig for AzureTarget {
    fn provider(&self) -> &'static dyn Provider {
        &PROVIDER
    }

    fn env_name(&self, product: &str, key: &str) -> String {
        self.env_name_of(product, key)
    }

    fn store_name(&self, env_name: &str) -> String {
        Self::key_vault_name(env_name)
    }

    fn name_rules(&self) -> NameRules {
        NameRules {
            env_label: "env name",
            store: Some(StoreNameRules {
                label: "Key Vault name",
                max_len: 127,
                allowed: key_vault_char,
                pattern: "^[0-9A-Za-z-]{1,127}$",
                // R3: Key Vault names are case-insensitive.
                case_insensitive: true,
            }),
        }
    }

    fn same_target(&self, other: &dyn TargetConfig) -> bool {
        other
            .as_any()
            .downcast_ref::<AzureTarget>()
            .is_some_and(|o| {
                o.key_vault == self.key_vault && o.env_name_template == self.env_name_template
            })
    }

    fn shared_target_error(&self, first: &str, second: &str) -> String {
        format!(
            "environments {first} and {second} both use Key Vault {:?} with azure.env_name {:?}",
            self.key_vault, self.env_name_template
        )
    }

    fn open<'a>(&'a self, _env: &'a str, _r: &'a dyn CommandRunner) -> Result<Ports<'a>, Error> {
        // Placeholder until keyvault.rs and containerapp.rs are wired in (FR-28).
        Err(Error::Config(
            "the Azure target is not supported yet".into(),
        ))
    }

    fn preflight(&self, _r: &dyn CommandRunner) -> Result<(), Error> {
        Ok(())
    }

    fn doctor(&self, _r: &dyn CommandRunner, _host: &dyn Fn() -> Host) -> Vec<Check> {
        Vec::new()
    }

    fn explain(&self, product: &str, key: &str) -> Vec<(&'static str, String)> {
        let env = self.env_name_of(product, key);
        let store = Self::key_vault_name(&env);
        vec![("env name", env), ("key vault name", store)]
    }

    fn eq_dyn(&self, other: &dyn TargetConfig) -> bool {
        eq_as(self, other)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn clone_box(&self) -> Box<dyn TargetConfig> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse;
    use crate::domain::SIMPLE_PRODUCT;

    /// The Azure target of `env`; panics when it is not one.
    fn azure_of<'f>(f: &'f crate::domain::Fleet, env: &str) -> &'f AzureTarget {
        f.environments[env]
            .target()
            .and_then(|t| t.as_any().downcast_ref::<AzureTarget>())
            .expect("not azure")
    }

    const AZURE_ENV: &str = r#"
[environments.prod]
vault_id = "v"
item_id = "i"
[environments.prod.azure]
key_vault = "kv-myapp-prod"
resource_group = "rg-myapp"
container_app = "ca-myapp"
identity = "system"
env_name = "FLEET__{PRODUCT}__{KEY}"
"#;

    const KEYS: &str = r#"
[products.api.keys.DB_URL]
kind = "secret"
environments = ["prod"]
"#;

    fn azure_doc(env: &str, keys: &str) -> String {
        format!("[profile]\nkind = \"fleet\"\n{env}{keys}")
    }

    fn azure_env_with(from: &str, to: &str) -> String {
        assert!(AZURE_ENV.contains(from), "mutation did not match: {from:?}");
        azure_doc(&AZURE_ENV.replace(from, to), KEYS)
    }

    /// FR-2, FR-37: a mistyped field in the provider section shows the file's line and
    /// column, the line itself and the field, like any other TOML error.
    #[test]
    fn azure_section_type_error_points_at_the_field() {
        let bad = azure_env_with("identity = \"system\"", "identity = 5");
        assert_eq!(
            parse(&bad).unwrap_err().to_string(),
            "configuration error: invalid secrets.toml: TOML parse error at line 11, column 12\n   \
             |\n11 | identity = 5\n   |            ^\ninvalid type: integer `5`, expected a string\n"
        );
    }

    fn azure_err(text: &str) -> String {
        parse(text).unwrap_err().to_string()
    }

    #[test]
    fn loads_azure_target() {
        let f = parse(&azure_doc(AZURE_ENV, KEYS)).unwrap();
        assert_eq!(
            f.environments["prod"].target().unwrap().provider().label(),
            "Azure"
        );
    }

    #[test]
    fn azure_config_route_defaults_to_env() {
        let f = parse(&azure_doc(AZURE_ENV, KEYS)).unwrap();
        let a = azure_of(&f, "prod");
        assert_eq!(a.config, ConfigRoute::Env);
    }

    #[test]
    fn azure_config_route_store_is_accepted() {
        let f = parse(&azure_env_with(
            "identity = \"system\"",
            "identity = \"system\"\nconfig = \"store\"",
        ))
        .unwrap();
        let a = azure_of(&f, "prod");
        assert_eq!(a.config, ConfigRoute::Store);
    }

    #[test]
    fn azure_renders_env_name_from_template() {
        let f = parse(&azure_doc(AZURE_ENV, KEYS)).unwrap();
        assert_eq!(f.target_name("prod", "api", "DB_URL"), "FLEET__API__DB_URL");
    }

    #[test]
    fn azure_store_name_replaces_underscores_with_dashes() {
        assert_eq!(
            AzureTarget::key_vault_name("FLEET__API__DB_URL"),
            "FLEET--API--DB-URL"
        );
    }

    #[test]
    fn rejects_key_vault_name_collision_by_product_dash_or_underscore() {
        let keys = r#"
[products.a-b.keys.C]
kind = "secret"
environments = ["prod"]
[products.a_b.keys.C]
kind = "secret"
environments = ["prod"]
"#;
        let e = azure_err(&azure_doc(AZURE_ENV, keys));
        assert!(e.contains("both map to Key Vault name"), "{e}");
    }

    #[test]
    fn rejects_key_vault_name_over_127_chars() {
        let long = "K".repeat(120);
        let keys =
            format!("[products.api.keys.{long}]\nkind = \"secret\"\nenvironments = [\"prod\"]\n");
        let e = azure_err(&azure_doc(AZURE_ENV, &keys));
        assert!(e.contains("api/KKKK") && e.contains("{1,127}"), "{e}");
    }

    #[test]
    fn rejects_azure_identifier_with_leading_dash() {
        let e = azure_err(&azure_env_with(
            "resource_group = \"rg-myapp\"",
            "resource_group = \"-rg\"",
        ));
        assert!(e.contains("azure.resource_group"), "{e}");
    }

    #[test]
    fn rejects_empty_azure_identifier() {
        let e = azure_err(&azure_env_with(
            "key_vault = \"kv-myapp-prod\"",
            "key_vault = \"\"",
        ));
        assert!(e.contains("azure.key_vault is empty"), "{e}");
    }

    #[test]
    fn azure_identity_accepts_a_resource_id() {
        let id = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/uai";
        let f = parse(&azure_env_with(
            "identity = \"system\"",
            &format!("identity = \"{id}\""),
        ))
        .unwrap();
        let a = azure_of(&f, "prod");
        assert_eq!(a.identity, id);
    }

    #[test]
    fn rejects_azure_identity_with_shell_metacharacters() {
        let e = azure_err(&azure_env_with(
            "identity = \"system\"",
            "identity = \"a;rm\"",
        ));
        assert!(e.contains("azure.identity"), "{e}");
    }

    #[test]
    fn rejects_azure_env_name_without_placeholders() {
        let e = azure_err(&azure_env_with("FLEET__{PRODUCT}__{KEY}", "STATIC"));
        assert!(e.contains("azure.env_name"), "{e}");
    }

    #[test]
    fn rejects_missing_env_name_under_fleet_profile() {
        let e = azure_err(&azure_env_with(
            "env_name = \"FLEET__{PRODUCT}__{KEY}\"\n",
            "",
        ));
        assert!(e.contains("azure.env_name is required"), "{e}");
    }

    const SIMPLE_AZURE: &str = r#"
[profile]
kind = "simple"
[environments.prod]
vault_id = "v"
item_id = "i"
[environments.prod.azure]
key_vault = "kv-myapp-prod"
resource_group = "rg-myapp"
container_app = "ca-myapp"
identity = "system"
[keys.JWT_KEY]
kind = "secret"
environments = ["prod"]
"#;

    #[test]
    fn simple_profile_azure_uses_the_key_name_as_env_name() {
        let f = parse(SIMPLE_AZURE).unwrap();
        assert_eq!(f.target_name("prod", SIMPLE_PRODUCT, "JWT_KEY"), "JWT_KEY");
    }

    #[test]
    fn rejects_env_name_under_simple_profile_azure() {
        let e = azure_err(&SIMPLE_AZURE.replace(
            "identity = \"system\"",
            "identity = \"system\"\nenv_name = \"{KEY}\"",
        ));
        assert!(e.contains("azure.env_name is not allowed"), "{e}");
    }

    #[test]
    fn rejects_unknown_config_route() {
        let e = azure_err(&azure_env_with(
            "identity = \"system\"",
            "identity = \"system\"\nconfig = \"plain\"",
        ));
        assert!(
            e.contains("azure.config must be \"env\" or \"store\", got \"plain\""),
            "{e}"
        );
    }

    #[test]
    fn rejects_two_environments_sharing_a_key_vault_and_template() {
        let second = AZURE_ENV
            .replace("environments.prod", "environments.stage")
            .replace("ca-myapp", "ca-other");
        let e = azure_err(&azure_doc(&format!("{AZURE_ENV}{second}"), KEYS));
        assert!(e.contains("both use Key Vault"), "{e}");
    }
}
