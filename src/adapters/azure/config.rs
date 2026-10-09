//! `[environments.<env>.azure]` parsing, Key Vault name rules and the Azure
//! `TargetConfig` (FR-28, FR-30, FR-37).

use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use serde::Deserialize;

use super::containerapp::ContainerApp;
use super::keyvault::KeyVault;
use super::preflight;
use crate::config::{check_ident, is_id};
use crate::domain::{Profile, SIMPLE_TEMPLATE};
use crate::error::Error;
use crate::host::Host;
use crate::ports::Ports;
use crate::provider::{
    Check, InitField, NameRules, Preflight, PreflightMode, Provider, Section, StoreConfig,
    StoreNameRules, TargetConfig, eq_as, init_lines,
};
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
    /// `azure.subscription`: a subscription id, passed as `--subscription` on every call
    /// that reads or changes an Azure resource (NR-7).
    pub subscription: String,
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
    /// The vault's `properties.vaultUri`, read once per run (NR-6); not configuration.
    pub vault_uri: ResolvedUri,
}

/// A value read from Azure once per run and kept for the rest of it. Never part of the
/// configuration, so it never makes two targets unequal.
#[derive(Debug, Clone, Default)]
pub struct ResolvedUri(OnceLock<String>);

impl ResolvedUri {
    /// The value, once resolved.
    pub fn get(&self) -> Option<&str> {
        self.0.get().map(String::as_str)
    }

    /// Keeps `uri` unless a value is already kept.
    pub fn set(&self, uri: String) {
        let _ = self.0.set(uri);
    }
}

impl PartialEq for ResolvedUri {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for ResolvedUri {}

/// `azure.subscription`: checked while the section is read, so a wrong value is reported at
/// its line and column like any other field (FR-2, NR-7).
#[derive(Deserialize)]
#[serde(try_from = "String")]
pub(crate) struct Subscription(pub(crate) String);

impl TryFrom<String> for Subscription {
    type Error = String;

    fn try_from(s: String) -> Result<Self, String> {
        if is_guid(&s) {
            Ok(Self(s.to_ascii_lowercase()))
        } else {
            Err("subscription must be a subscription id like \
                 00000000-0000-0000-0000-000000000000 (az account list -o table shows yours)"
                .into())
        }
    }
}

/// A GUID: 8-4-4-4-12 hex digits.
pub(crate) fn is_guid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && parts
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(p, n)| p.len() == n && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAzure {
    subscription: Subscription,
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

/// The env-name template `opv init` writes under the fleet profile.
const INIT_FLEET_TEMPLATE: &str = "FLEET__{PRODUCT}__{KEY}";

/// `opv init --target azure` options (H3), in the order they are written.
static INIT_FIELDS: [InitField; 8] = [
    InitField {
        field: "subscription",
        help: "Azure subscription id (a GUID; az account list -o table)",
        required: true,
    },
    InitField {
        field: "key_vault",
        help: "Key Vault name the secrets are written to",
        required: true,
    },
    InitField {
        field: "resource_group",
        help: "Resource group of the Container App",
        required: true,
    },
    InitField {
        field: "container_app",
        help: "Container App that reads the secrets",
        required: true,
    },
    InitField {
        field: "container",
        help: "Container in the app (only when it has more than one)",
        required: false,
    },
    InitField {
        field: "identity",
        help: "system (default) or the resource id of a user-assigned identity",
        required: false,
    },
    InitField {
        field: "env_name",
        help: "Env-name template (fleet profile; default FLEET__{PRODUCT}__{KEY})",
        required: false,
    },
    InitField {
        field: "config",
        help: "Where config keys go: env (default) or store",
        required: false,
    },
];

fn cfg(msg: String) -> Error {
    Error::Config(msg.into())
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
        preflight::DOCTOR_CHECKS
    }

    fn setup_hint(&self, _profile: Profile) -> String {
        "configure azure.subscription, azure.key_vault, azure.resource_group, \
         azure.container_app and azure.identity"
            .into()
    }

    fn init_fields(&self) -> &'static [InitField] {
        &INIT_FIELDS
    }

    fn init_section(&self, values: &BTreeMap<&str, String>, profile: Profile) -> Option<String> {
        let mut lines: Vec<(&str, &str)> = Vec::new();
        for f in &INIT_FIELDS {
            let v = match (values.get(f.field), f.field, profile) {
                (Some(v), _, _) => v.as_str(),
                (None, "identity", _) => "system",
                (None, "env_name", Profile::Fleet) => INIT_FLEET_TEMPLATE,
                (None, _, _) => continue,
            };
            lines.push((f.field, v));
        }
        Some(init_lines("azure", lines))
    }

    fn store_kinds(&self) -> &'static [&'static str] {
        &[super::store::KIND]
    }

    fn parse_store(
        &self,
        _kind: &str,
        section: &Section<'_>,
    ) -> Result<Box<dyn StoreConfig>, Error> {
        super::store::parse(section)
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
        subscription: a.subscription.0,
        key_vault: a.key_vault,
        resource_group: a.resource_group,
        container_app: a.container_app,
        container: a.container,
        identity: a.identity,
        env_name_template: template,
        config,
        vault_uri: ResolvedUri::default(),
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

/// How a value reaches the app through Key Vault (FR-29), for `explain`.
const REFERENCE_ROUTE: &str = "Key Vault reference pinned to one version (never a plain env value)";

/// The Container Apps secret that carries the reference (R2), for `explain`.
const APP_SECRET: &str = "opv-<16 hex> per Key Vault version (SHA-256 of key vault name/version); a new version is a new revision";

pub(crate) fn key_vault_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-'
}

impl AzureTarget {
    /// The vault this target writes to, for the shared Key Vault checks.
    pub fn vault_ref(&self) -> preflight::Vault {
        preflight::Vault {
            name: self.key_vault.clone(),
            subscription: self.subscription.clone(),
            vault_field: "azure.key_vault".into(),
            subscription_field: "azure.subscription".into(),
        }
    }

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

// Test-only: health poll interval and limit for targets opened on this thread.
#[cfg(test)]
thread_local! {
    pub(crate) static TEST_WAIT: std::cell::Cell<Option<(std::time::Duration, std::time::Duration)>> =
        const { std::cell::Cell::new(None) };
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
                edge: key_vault_char,
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

    fn open<'a>(
        &'a self,
        env: &'a str,
        managed: BTreeSet<String>,
        r: &'a dyn CommandRunner,
    ) -> Result<Ports<'a>, Error> {
        let app = ContainerApp::new(r, self, managed.clone());
        // Tests shorten the health wait; production has no such switch.
        #[cfg(test)]
        let app = match TEST_WAIT.with(std::cell::Cell::get) {
            Some((every, max)) => app.with_wait(every, max),
            None => app,
        };
        Ok(Ports::Pinned {
            store: Box::new(KeyVault {
                runner: r,
                vault: &self.key_vault,
                subscription: &self.subscription,
                env,
                managed,
            }),
            runtime: Box::new(app),
        })
    }

    fn preflight(&self, r: &dyn CommandRunner, mode: PreflightMode) -> Result<Preflight, Error> {
        preflight::run(self, r, mode)
    }

    fn doctor(&self, r: &dyn CommandRunner, host: &dyn Fn() -> Host) -> Vec<Check> {
        preflight::doctor(self, r, host)
    }

    fn explain(&self, product: &str, key: &str) -> Vec<(&'static str, String)> {
        let env = self.env_name_of(product, key);
        let store = Self::key_vault_name(&env);
        vec![
            ("env name", env),
            ("key vault", self.key_vault.clone()),
            ("key vault name", store),
            ("app secret", APP_SECRET.into()),
            ("routing", REFERENCE_ROUTE.into()),
        ]
    }

    fn explain_config(&self, product: &str, key: &str) -> Option<Vec<(&'static str, String)>> {
        let env = self.env_name_of(product, key);
        Some(match self.config {
            ConfigRoute::Env => vec![
                ("env name", env),
                (
                    "routing",
                    "plain env value on the container app (azure.config = \"env\")".into(),
                ),
            ],
            ConfigRoute::Store => {
                let store = Self::key_vault_name(&env);
                vec![
                    ("env name", env),
                    ("key vault", self.key_vault.clone()),
                    ("key vault name", store),
                    ("app secret", APP_SECRET.into()),
                    (
                        "routing",
                        format!("{REFERENCE_ROUTE} (azure.config = \"store\")"),
                    ),
                ]
            }
        })
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
subscription = "00000000-0000-0000-0000-000000000000"
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
            "configuration error: invalid secrets.toml: TOML parse error at line 12, column 12\n   \
             |\n12 | identity = 5\n   |            ^\ninvalid type: integer `5`, expected a string\n"
        );
    }

    fn azure_err(text: &str) -> String {
        parse(text).unwrap_err().to_string()
    }

    /// NR-7: the subscription is required, and its absence is reported at the section.
    #[test]
    fn missing_subscription_is_a_config_error_naming_the_field() {
        let e = azure_err(&azure_env_with(
            "subscription = \"00000000-0000-0000-0000-000000000000\"\n",
            "",
        ));
        assert!(
            e.contains("TOML parse error at line") && e.contains("missing field `subscription`"),
            "{e}"
        );
    }

    #[test]
    fn subscription_that_is_not_a_guid_points_at_its_line_and_column() {
        let e = azure_err(&azure_env_with(
            "subscription = \"00000000-0000-0000-0000-000000000000\"",
            "subscription = \"my-sub\"",
        ));
        assert!(
            e.contains("line 8, column 16") && e.contains("must be a subscription id"),
            "{e}"
        );
    }

    #[test]
    fn subscription_is_kept_lower_case() {
        let f = parse(&azure_env_with(
            "00000000-0000-0000-0000-000000000000",
            "ABCDEF00-0000-0000-0000-000000000000",
        ))
        .unwrap();
        assert_eq!(
            azure_of(&f, "prod").subscription,
            "abcdef00-0000-0000-0000-000000000000"
        );
    }

    fn explained(config: Option<&str>, secret: bool) -> Vec<(&'static str, String)> {
        let doc = match config {
            Some(c) => azure_env_with(
                "identity = \"system\"",
                &format!("identity = \"system\"\nconfig = \"{c}\""),
            ),
            None => azure_doc(AZURE_ENV, KEYS),
        };
        let f = parse(&doc).unwrap();
        let t = azure_of(&f, "prod");
        if secret {
            t.explain("api", "DB_URL")
        } else {
            t.explain_config("api", "LOG_LEVEL").unwrap()
        }
    }

    fn explained_line(lines: &[(&'static str, String)], label: &str) -> String {
        lines.iter().find(|(l, _)| *l == label).unwrap().1.clone()
    }

    #[test]
    fn explain_azure_key_shows_key_vault_name() {
        assert_eq!(
            explained_line(&explained(None, true), "key vault name"),
            "FLEET--API--DB-URL"
        );
    }

    #[test]
    fn explain_azure_key_shows_the_app_secret_pattern() {
        assert!(
            explained_line(&explained(None, true), "app secret")
                .starts_with("opv-<16 hex> per Key Vault version")
        );
    }

    #[test]
    fn explain_azure_secret_routes_through_a_key_vault_reference() {
        assert!(
            explained_line(&explained(None, true), "routing").starts_with("Key Vault reference")
        );
    }

    #[test]
    fn explain_azure_config_routes_to_a_plain_env_value_by_default() {
        assert!(explained_line(&explained(None, false), "routing").starts_with("plain env value"));
    }

    #[test]
    fn explain_azure_config_with_store_route_routes_through_key_vault() {
        assert!(
            explained_line(&explained(Some("store"), false), "routing")
                .ends_with("(azure.config = \"store\")")
        );
    }

    /// FR-28: an Azure target opens the pinned flow (Key Vault + Container Apps).
    #[test]
    fn azure_target_opens_pinned_ports() {
        let f = parse(&azure_doc(AZURE_ENV, KEYS)).unwrap();
        let mut vault: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/azure/keyvault-show.json"
        ))
        .unwrap();
        vault["properties"]["vaultUri"] = "https://kv-myapp-prod.vault.azure.net/".into();
        let r = crate::runner::fake::FakeRunner::new([crate::runner::Output::success(
            serde_json::to_vec(&vault).unwrap(),
        )]);
        let ports = azure_of(&f, "prod").open("prod", BTreeSet::new(), &r);
        assert!(matches!(ports, Ok(Ports::Pinned { .. })));
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
subscription = "00000000-0000-0000-0000-000000000000"
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
