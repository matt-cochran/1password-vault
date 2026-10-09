//! The provider plug-in contract (FR-37, `docs/design/multi-cloud-targets.md` §11).
//!
//! Every deployment provider lives under `src/adapters/<provider>/`, implements [`Provider`]
//! for its configuration section and [`TargetConfig`] for a validated target, and is
//! registered once in `adapters::registry::PROVIDERS`. Core code (`app/`, `domain/`,
//! `config.rs`) sees only these traits, so adding a provider changes no core code.

use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::de::DeserializeOwned;
use toml::Spanned;
use toml::de::{DeValue, ValueDeserializer};

use crate::domain::{Kind, Profile, SecretValue};
use crate::error::Error;
use crate::host::Host;
use crate::ports::{PinnedStore, Ports};
use crate::runner::CommandRunner;

/// One deployment provider. Registered once in `adapters::registry::PROVIDERS`.
pub trait Provider: Sync {
    /// Config section name under `[environments.<env>]`: "fly", "azure", "kubernetes".
    fn section(&self) -> &'static str;
    /// User-facing name: "Fly", "Azure", "Kubernetes".
    fn label(&self) -> &'static str;
    /// Parses and validates that section (identifiers, templates, required fields). Read
    /// the section with [`Section::deserialize`], so a shape error points at its line.
    fn parse(
        &self,
        section: &Section<'_>,
        profile: Profile,
    ) -> Result<Box<dyn TargetConfig>, Error>;
    /// Environment variables holding this provider's non-interactive credential, by name
    /// (values are never read). [`crate::host::Host::token`] reports which one is set.
    fn credential_vars(&self) -> &'static [&'static str] {
        &[]
    }
    /// Names of the checks [`TargetConfig::doctor`] prints, so `doctor` can list them as
    /// skipped when no environment uses this provider.
    fn doctor_checks(&self) -> &'static [&'static str];
    /// What a person adds to deploy with this provider, e.g. `configure fly.app`. Only the
    /// default provider (`adapters::registry::DEFAULT`) is ever asked.
    fn setup_hint(&self, profile: Profile) -> String;
    /// The fields `opv init --target <section>` takes (FR-23, H3), each as the option
    /// `--<section>-<field>` ([`init_flag`]). Empty when the provider does not support
    /// `init`. A new provider adds its options here; core and the CLI need no change.
    fn init_fields(&self) -> &'static [InitField] {
        &[]
    }
    /// The TOML lines `opv init` writes under `[environments.<env>]` for this target, from
    /// the given `values` (field → value; every required field present), or `None` when the
    /// provider does not support `init`. Fill what the profile needs and the user did not
    /// give (a fleet name template). Nothing is looked up; the result is validated with the
    /// same loader as a hand-written file.
    fn init_section(&self, values: &BTreeMap<&str, String>, profile: Profile) -> Option<String> {
        let _ = (values, profile);
        None
    }
    /// The fields a `deploy_credentials` item holds for this provider, by convention
    /// (FR-40), or the configuration error explaining why it takes none.
    fn deploy_credential_fields(&self) -> Result<&'static [CredentialField], String> {
        Err(format!(
            "{} does not support deploy_credentials",
            self.label()
        ))
    }
    /// Start a deploy sign-in for one run (FR-40). Runs before the credential is read, so a
    /// machine that cannot hold it safely refuses with nothing read or changed.
    fn deploy_login(&self) -> Result<Box<dyn DeployLogin>, Error> {
        Err(Error::Config(
            format!("{} does not support deploy_credentials", self.label()).into(),
        ))
    }
    /// Store kinds this provider declares for `[stores.<name>]` tables (FR-39): the key that
    /// names the kind, e.g. `azure_key_vault = "kv-myapp-prod"`.
    fn store_kinds(&self) -> &'static [&'static str] {
        &[]
    }
    /// Parses a `[stores.<name>]` table of `kind` (one of [`Provider::store_kinds`]). Read it
    /// with [`Section::deserialize`] so a bad field shows its line; [`Section::env`] is the
    /// store's name.
    fn parse_store(
        &self,
        kind: &str,
        section: &Section<'_>,
    ) -> Result<Box<dyn StoreConfig>, Error> {
        Err(Error::Config(
            format!(
                "store {}: {} declares no store kind {kind:?}",
                section.env(),
                self.label()
            )
            .into(),
        ))
    }
    /// The stores of other providers this provider's runtime can bind (`secrets_in`, FR-39).
    fn bindings(&self) -> &'static [StoreBinding] {
        &[]
    }
    /// `target` (parsed by this provider) with its secrets in `store`. Called only for a
    /// pair [`Provider::bindings`] declares.
    fn bind(
        &self,
        target: Box<dyn TargetConfig>,
        store: &dyn StoreConfig,
    ) -> Result<Box<dyn TargetConfig>, Error> {
        let _ = target;
        Err(Error::Config(
            format!(
                "{} cannot keep its secrets in {}",
                self.label(),
                store.describe()
            )
            .into(),
        ))
    }
}

/// One field of a `deploy_credentials` item (FR-40): its label and kind (concealed = secret,
/// text = config, as for every item field, FR-14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialField {
    pub label: &'static str,
    pub kind: Kind,
}

/// A target CLI signed in with an environment's deploy identity for one run (FR-40).
/// Dropping it ends the sign-in and removes anything it kept (SR-4).
pub trait DeployLogin {
    /// Sign in with the item's values, keyed by field label. `r`'s `op` calls already carry
    /// the environment's 1Password account. Values go only to stdin or a child's env (SR-3).
    fn sign_in(
        &mut self,
        values: std::collections::BTreeMap<String, SecretValue>,
        r: &dyn CommandRunner,
    ) -> Result<(), Error>;
    /// Extra environment for every call of `program` in this run (a token for the target
    /// CLI, its private configuration directory). Never argv, never a file.
    fn env(&self, program: &str) -> Vec<(&'static str, &str)>;
}

/// The provider whose CLI an environment's `deploy_credentials` sign in (FR-40): the
/// target's own, or, for a runtime that signs in without them (Kubernetes uses its
/// kubeconfig) but keeps its secrets in another provider's store (`secrets_in`, FR-39),
/// that store's provider (Azure for a Key Vault), whose CLI writes the secrets.
pub fn deploy_provider(target: &dyn TargetConfig) -> &'static dyn Provider {
    let own = target.provider();
    match target.secrets_in() {
        Some(store) if own.deploy_credential_fields().is_err() => store.provider(),
        _ => own,
    }
}

/// One `opv init` option of a provider (H3): `--<section>-<field>` writes
/// `<section>.<field> = "<value>"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitField {
    /// The field under the provider's section, e.g. `key_vault`.
    pub field: &'static str,
    /// What to give, for `opv init --help`.
    pub help: &'static str,
    /// Whether `init --target <section>` needs it.
    pub required: bool,
}

/// The `opv init` option of `field`: `--azure-key-vault` is `azure-key-vault`.
pub fn init_flag(p: &dyn Provider, field: &InitField) -> String {
    format!("{}-{}", p.section(), field.field.replace('_', "-"))
}

/// `<section>.<field> = "<value>"` lines, in the order given, for
/// [`Provider::init_section`]. Values are TOML basic strings.
pub fn init_lines<'a>(
    section: &str,
    values: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> String {
    values
        .into_iter()
        .map(|(field, value)| {
            format!(
                "{section}.{field} = {}\n",
                toml::Value::String(value.to_string())
            )
        })
        .collect()
}

/// One supported (store kind, runtime) pair for `secrets_in` (FR-39).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreBinding {
    /// The store kind, e.g. `azure_key_vault`.
    pub store_kind: &'static str,
    /// How the runtime reaches it, in messages: "External Secrets Operator".
    pub via: &'static str,
}

/// A validated `[stores.<name>]` table (FR-39): a store one or more runtimes keep their
/// secrets in. Core code sees only this trait; the provider that declared the kind owns it.
pub trait StoreConfig: fmt::Debug + Send + Sync {
    /// The provider that declared this store kind.
    fn provider(&self) -> &'static dyn Provider;
    /// The store kind, e.g. `azure_key_vault`.
    fn kind(&self) -> &'static str;
    /// The `[stores.<name>]` name.
    fn name(&self) -> &str;
    /// The store in messages, e.g. `Key Vault kv-myapp-prod`.
    fn describe(&self) -> String;
    /// The store's own identifier (a vault name), which a bridge's settings must name.
    fn locator(&self) -> &str;
    /// The name in-cluster bridges know this store by (an External Secrets
    /// `ClusterSecretStore`); defaults to [`StoreConfig::name`].
    fn bridge_name(&self) -> &str;
    /// Name in the store for a runtime env var name.
    fn store_name(&self, env_name: &str) -> String;
    /// Limits of a store name, checked at load for every environment that uses the store.
    fn name_rules(&self) -> StoreNameRules;
    /// The store port for environment `env` (FR-28); `managed` as for
    /// [`TargetConfig::open`].
    fn open<'a>(
        &'a self,
        env: &'a str,
        managed: BTreeSet<String>,
        r: &'a dyn CommandRunner,
    ) -> Box<dyn PinnedStore + 'a>;
    /// Read-only checks of the store before any write (NR-23, NR-25); `Err` stops.
    fn preflight(&self, r: &dyn CommandRunner) -> Result<(), Error>;
    /// `doctor` lines of the store.
    fn doctor(&self, r: &dyn CommandRunner, host: &dyn Fn() -> Host) -> Vec<Check>;
    /// `explain` lines for an env name kept in this store.
    fn explain(&self, env_name: &str) -> Vec<(&'static str, String)>;
    /// True when `other` is the same store (two names for one vault).
    fn same_store(&self, other: &dyn StoreConfig) -> bool;
    /// Equal configuration (every field).
    fn eq_dyn(&self, other: &dyn StoreConfig) -> bool;
    fn as_any(&self) -> &dyn Any;
    fn clone_box(&self) -> Box<dyn StoreConfig>;
}

impl Clone for Box<dyn StoreConfig> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

impl PartialEq for Box<dyn StoreConfig> {
    fn eq(&self, other: &Self) -> bool {
        self.eq_dyn(other.as_ref())
    }
}

impl Eq for Box<dyn StoreConfig> {}

/// [`StoreConfig::eq_dyn`] for a store type with `PartialEq`.
pub fn store_eq_as<T: PartialEq + 'static>(this: &T, other: &dyn StoreConfig) -> bool {
    other.as_any().downcast_ref::<T>() == Some(this)
}

/// One provider section of `secrets.toml` (`[environments.<env>.<section>]`), with its
/// place in the file so errors point at the offending line.
pub struct Section<'a> {
    env: &'a str,
    value: &'a Spanned<DeValue<'a>>,
    text: &'a str,
}

impl<'a> Section<'a> {
    /// `value` is the section as parsed from `text`, the whole file.
    pub(crate) fn new(env: &'a str, value: &'a Spanned<DeValue<'a>>, text: &'a str) -> Self {
        Self { env, value, text }
    }

    /// The environment this section belongs to (for a `[stores.<name>]` table: the store).
    pub fn env(&self) -> &str {
        self.env
    }

    /// The section as `T`. A missing, unknown or mistyped field is reported like any other
    /// TOML error in the file: line, column, the line itself and the field (FR-2).
    pub fn deserialize<T: DeserializeOwned>(&self) -> Result<T, Error> {
        T::deserialize(ValueDeserializer::from(self.value.clone())).map_err(|mut e| {
            e.set_input(Some(self.text));
            Error::Config(format!("invalid secrets.toml: {e}").into())
        })
    }
}

/// A validated, provider-specific target. Core code sees only this trait.
pub trait TargetConfig: fmt::Debug + Send + Sync {
    /// The provider this target belongs to (its label names it in messages: "on Fly").
    fn provider(&self) -> &'static dyn Provider;
    /// Runtime env var name of `product`/`key`.
    fn env_name(&self, product: &str, key: &str) -> String;
    /// Name in the store for a runtime env var name.
    fn store_name(&self, env_name: &str) -> String;
    /// Name patterns, case sensitivity and limits, checked generically at load (FR-30).
    fn name_rules(&self) -> NameRules;
    /// The named store this target keeps its secrets in (`secrets_in`, FR-39); `None` when
    /// it uses its own store. Its name rules are checked too, across every environment
    /// that uses it.
    fn secrets_in(&self) -> Option<&dyn StoreConfig> {
        None
    }
    /// True when `other` is the same target: two environments on it would manage the same
    /// names, and each would prune what the other stages (FR-8).
    fn same_target(&self, other: &dyn TargetConfig) -> bool;
    /// The configuration error for environments `first` and `second` sharing this target.
    fn shared_target_error(&self, first: &str, second: &str) -> String;
    /// The store and runtime adapters of this target (FR-28). `managed` is every env name
    /// the template renders for a declared key (FR-8); the ports speak those names.
    fn open<'a>(
        &'a self,
        env: &'a str,
        managed: BTreeSet<String>,
        r: &'a dyn CommandRunner,
    ) -> Result<Ports<'a>, Error>;
    /// Read-only checks of the target's own state (NR-23 to NR-25): `Err` stops the
    /// command, and so does a returned check that failed. The other returned checks are
    /// printed one line each, like `doctor`'s; return only those worth a line (warnings), a
    /// passing state is silent. `mode` says whether the command will write: only
    /// [`PreflightMode::Mutate`] may wait for an update in progress (bounded by the run
    /// budget, with progress); [`PreflightMode::Read`] never waits and reports it as a
    /// warning instead.
    fn preflight(&self, r: &dyn CommandRunner, mode: PreflightMode) -> Result<Preflight, Error>;
    /// `doctor` lines: tool versions and sign-in, never identities or values (FR-3).
    fn doctor(&self, r: &dyn CommandRunner, host: &dyn Fn() -> Host) -> Vec<Check>;
    /// `explain` lines for a secret `product`/`key`: (label, value), e.g. ("fly name", ..).
    fn explain(&self, product: &str, key: &str) -> Vec<(&'static str, String)>;
    /// `explain` lines for a config key, when this target routes config itself (Azure:
    /// a plain env value or a Key Vault reference). `None`: config is not deployed here.
    fn explain_config(&self, _product: &str, _key: &str) -> Option<Vec<(&'static str, String)>> {
        None
    }
    /// Equal configuration (every field), for comparing whole configurations.
    fn eq_dyn(&self, other: &dyn TargetConfig) -> bool;
    /// For [`TargetConfig::same_target`] and [`TargetConfig::eq_dyn`] implementations.
    fn as_any(&self) -> &dyn Any;
    /// For `Clone` on `Box<dyn TargetConfig>`.
    fn clone_box(&self) -> Box<dyn TargetConfig>;
}

impl Clone for Box<dyn TargetConfig> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

impl PartialEq for Box<dyn TargetConfig> {
    fn eq(&self, other: &Self) -> bool {
        self.eq_dyn(other.as_ref())
    }
}

impl Eq for Box<dyn TargetConfig> {}

/// [`TargetConfig::eq_dyn`] for a target type with `PartialEq`.
pub fn eq_as<T: PartialEq + 'static>(this: &T, other: &dyn TargetConfig) -> bool {
    other.as_any().downcast_ref::<T>() == Some(this)
}

/// How a provider's names are checked at load (FR-30): every rendered env name must be a
/// valid env-var name; when the store renames it, the store name must fit `store`.
/// Collisions are checked on the store name (case-folded when the store ignores case).
#[derive(Debug, Clone, Copy)]
pub struct NameRules {
    /// The env name in messages: "Fly name", "env name".
    pub env_label: &'static str,
    /// `None` when the store name is the env name.
    pub store: Option<StoreNameRules>,
}

/// Limits of a store name that differs from the env name.
#[derive(Debug, Clone, Copy)]
pub struct StoreNameRules {
    /// The store name in messages: "Key Vault name".
    pub label: &'static str,
    pub max_len: usize,
    pub allowed: fn(char) -> bool,
    /// What the first and last characters may be (a subset of `allowed`).
    pub edge: fn(char) -> bool,
    /// The rule as shown to the user, e.g. `^[0-9A-Za-z-]{1,127}$`.
    pub pattern: &'static str,
    /// Store names differing only in case are the same name.
    pub case_insensitive: bool,
}

/// One named `doctor` check line.
#[derive(Debug)]
pub struct Check {
    pub name: std::borrow::Cow<'static, str>,
    pub outcome: Result<Verdict, Error>,
}

/// Whether the command running a preflight writes to the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreflightMode {
    /// `status` and `plan`: never wait on the target; an update in progress is one note.
    Read,
    /// `sync`: wait for an update in progress before the first write.
    Mutate,
}

/// What a target's read-only state checks found (NR-24): lines to print, and whether a
/// requested deploy has nothing to act on.
#[derive(Debug, Default)]
pub struct Preflight {
    pub checks: Vec<Check>,
    /// Set when the runtime has nothing to restart: `sync --deploy` skips the deploy and
    /// prints this line instead (exit 0).
    pub skip_deploy: Option<String>,
}

/// A passing check: ok, or ok with a warning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Ok(String),
    Warn(String),
}

impl Verdict {
    /// The one-line form `doctor` and preflight print: `ok    <name>: <detail>`.
    pub fn line(&self, name: &str) -> String {
        match self {
            Verdict::Ok(detail) => format!("ok    {name}: {detail}"),
            Verdict::Warn(detail) => format!("warn  {name}: {detail}"),
        }
    }
}
