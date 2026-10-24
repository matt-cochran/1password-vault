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

use crate::domain::runtime::FileMount;
use crate::domain::{Kind, SecretValue};
use crate::error::Error;
use crate::host::{Host, Tool};
use crate::ports::{PinnedStore, Ports};
use crate::runner::CommandRunner;

/// One deployment provider. Registered once in `adapters::registry::PROVIDERS`.
pub trait Provider: Sync {
    /// Config section name under `[environments.<env>.targets.<name>]`: "fly", "azure",
    /// "kubernetes", "github".
    fn section(&self) -> &'static str;
    /// User-facing name: "Fly", "Azure", "Kubernetes".
    fn label(&self) -> &'static str;
    /// The forms this provider's own section checks ask for, as `(marker, words)`: a serde
    /// message of a section field that contains `marker` (`must be a Key Vault name`) is
    /// reported as that field needing `words`, never with the message itself, which quotes
    /// the value (C1, C15).
    fn value_shapes(&self) -> &'static [(&'static str, &'static str)] {
        &[]
    }
    /// The CLIs this provider runs, its own first: the runner takes each one's pinned
    /// environment and not-found phrases from here, and `Next:` lines starting with one
    /// count as runnable. A store another provider declares brings that provider's CLI.
    fn tools(&self) -> &'static [&'static Tool];
    /// Parses and validates that section (identifiers, templates, required fields). Read
    /// the section with [`Section::deserialize`], so a shape error points at its line.
    fn parse(&self, section: &Section<'_>) -> Result<Box<dyn TargetConfig>, Error>;
    /// Whether a stored value's version, as the store lists it, is derived from the value
    /// (a digest): then opv never shows it, as it is equal for equal values and can be used
    /// to test a guess (`opv history`, #95). Version ids and timestamps are not.
    fn versions_reveal_values(&self) -> bool {
        false
    }
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
    fn setup_hint(&self) -> String;
    /// The provider's CLI setup step for a GitHub Actions job, as YAML text indented under
    /// `steps:` (one list entry), or `None` when CI needs no provider-specific setup. Core
    /// code prints it through this trait, so it never names a provider (FR-37).
    fn ci_setup_step(&self) -> Option<&'static str> {
        None
    }
    /// The fields `opv target add` takes for this provider (FR-56, H3), each as the option
    /// `--<section>-<field>` ([`init_flag`]). Empty when the provider does not support
    /// `target add`. A new provider adds its options here; core and the CLI need no change.
    fn init_fields(&self) -> &'static [InitField] {
        &[]
    }
    /// The TOML lines `opv target add` writes under `[environments.<env>.targets.<name>]`
    /// for this target, from the given `values` (field → value; every required field
    /// present), or `None` when the provider does not support `target add`. Fill what the target needs and the
    /// user did not give (a name template). Nothing is looked up; the result is validated
    /// with the same loader as a hand-written file.
    fn init_section(&self, values: &BTreeMap<&str, String>) -> Option<String> {
        let _ = values;
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
    /// machine that cannot hold it safely refuses with nothing read or changed. Only called
    /// for a provider whose [`Provider::deploy_credential_fields`] the configuration
    /// accepted, so this default is never reached.
    fn deploy_login(&self) -> Result<Box<dyn DeployLogin>, Error> {
        Err(unreachable_default(
            "deploy_login of a provider without deploy credentials",
        ))
    }
    /// Mint the least-privilege deploy credential of `target` at the provider and return
    /// its fields by label (FR-40), or `None` when this provider cannot mint one. Called
    /// only after a person confirmed and [`Provider::mint_preflight`] passed. The token is
    /// returned only as a [`SecretValue`], never printed and never put in argv (SR-3).
    fn mint_deploy_credential(
        &self,
        target: &dyn TargetConfig,
        name: &str,
        r: &dyn CommandRunner,
    ) -> Option<Result<BTreeMap<String, SecretValue>, Error>> {
        let _ = (target, name, r);
        None
    }
    /// Read-only checks before minting ([`Provider::mint_deploy_credential`]): `Some` when
    /// this provider can mint, with the result of the preflight (a missing sign-in, a
    /// missing CLI). `None` when it cannot mint at all.
    fn mint_preflight(&self, r: &dyn CommandRunner) -> Option<Result<(), Error>> {
        let _ = r;
        None
    }
    /// How to revoke a credential [`Provider::mint_deploy_credential`] created, for the
    /// error when the token could not be stored (SR-4), or `None` when the provider gives
    /// no such instruction.
    fn mint_cleanup_hint(&self) -> Option<&'static str> {
        None
    }
    /// The provider's own listing that finds a credential [`Provider::mint_deploy_credential`]
    /// made for `target` (A22), for `Cause::SecretNotStored`'s Next; `None` when there is none.
    fn mint_refind(&self, target: &dyn TargetConfig) -> Option<crate::cause::VendorCmd> {
        let _ = target;
        None
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
        // Called only for a kind in `store_kinds`, which is empty here.
        let _ = (kind, section);
        Err(unreachable_default(
            "parse_store of a provider without store kinds",
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
        // Called only for a pair `bindings` declares, which is empty here.
        let _ = (target, store);
        Err(unreachable_default("bind of a provider without bindings"))
    }
}

/// A provider-trait default that the configuration's own checks never let run: reaching it
/// is an opv bug, never the person's configuration.
fn unreachable_default(site: &'static str) -> Error {
    crate::cause::Cause::Bug { site }.into()
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
    /// What to give, for `opv target add --help`.
    pub help: &'static str,
    /// Whether a target of this provider needs it.
    pub required: bool,
}

/// The `opv target add` option of `field`: `--azure-key-vault` is `azure-key-vault`.
pub fn init_flag(p: &dyn Provider, field: &InitField) -> String {
    format!("{}-{}", p.section(), field.field.replace('_', "-"))
}

/// The prefix of the comment a [`Provider::init_section`] returns when it cannot generate
/// the section: the rest of the line is the reason, names only. A caller that inserts the
/// section surfaces that reason instead of a section that fails the load rules.
pub const INIT_SECTION_FAILED: &str = "# opv could not generate this section:";

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

/// One provider section of `secrets.toml` (`[environments.<env>.targets.<name>]`'s
/// `<section>`), with its place in the file so errors point at the offending line.
pub struct Section<'a> {
    env: &'a str,
    value: &'a Spanned<DeValue<'a>>,
    text: &'a str,
    dir: Option<&'a std::path::Path>,
}

impl<'a> Section<'a> {
    /// `value` is the section as parsed from `text`, the whole file.
    pub(crate) fn new(env: &'a str, value: &'a Spanned<DeValue<'a>>, text: &'a str) -> Self {
        Self {
            env,
            value,
            text,
            dir: None,
        }
    }

    /// This section with relative file references resolving against `dir`, the
    /// configuration file's directory (`None`: the working directory).
    pub(crate) fn in_dir(mut self, dir: Option<&'a std::path::Path>) -> Self {
        self.dir = dir;
        self
    }

    /// `path` as the section's file reference: unchanged when absolute or when the
    /// configuration came from no file, else relative to the configuration file's directory.
    pub fn resolve(&self, path: &str) -> std::path::PathBuf {
        match self.dir {
            Some(dir) if !std::path::Path::new(path).is_absolute() => dir.join(path),
            _ => std::path::PathBuf::from(path),
        }
    }

    /// The environment this section belongs to (for a `[stores.<name>]` table: the store).
    pub fn env(&self) -> &str {
        self.env
    }

    /// The section as `T`. A missing, unknown or mistyped field is reported like any other
    /// TOML error in the file: line, column and the field (FR-2), never the line itself
    /// (C1, SR-1).
    pub fn deserialize<T: DeserializeOwned>(&self) -> Result<T, Error> {
        T::deserialize(ValueDeserializer::from(self.value.clone()))
            .map_err(|e| crate::config::toml_invalid(self.text, &e))
    }
}

/// Where one kind of key goes on a target (design §1.1, §1.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Channel {
    /// Written to a store; `label` names it in messages, e.g. `Kubernetes Secret`.
    Store { label: &'static str },
    /// A readable named variable (GitHub Actions variables).
    Variables,
    /// A plain runtime environment variable the target's runtime sets.
    RuntimeEnv,
    /// Deliberately not delivered; `why` completes `no config channel: <why>`. `sync`
    /// refuses it unless the target spells the opt-out out (`config = "none"`).
    None { why: &'static str },
    /// Deliberately not delivered, by the target's own declaration; `sync` warns and goes
    /// on, and `why` completes `no config channel: <why>`.
    Declined { why: &'static str },
}

impl Channel {
    /// The channel's label in messages and JSON (`via`): `Kubernetes Secret`, `GitHub
    /// variable`, `env`, …; `None` when the channel delivers nothing.
    pub fn label(&self) -> Option<&'static str> {
        match self {
            Channel::Store { label } => Some(label),
            Channel::Variables => Some("GitHub variable"),
            Channel::RuntimeEnv => Some("env"),
            Channel::None { .. } | Channel::Declined { .. } => None,
        }
    }
}

/// How a target delivers file keys (design §1.1, §1.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileCapability {
    /// opv writes the bytes to a filesystem the app reads; `dir` names it (a Kubernetes
    /// `secrets_dir`, which may hold `{product}`).
    Native { dir: String },
    /// The app writes the files from the environment (Fly and its shim).
    ViaApp { note: &'static str },
    /// Not delivered as a file; the key goes on the secret channel by name.
    None,
}

/// A target's channels, one per kind of key (design §1.1, §1.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Channels {
    pub secret: Channel,
    pub config: Channel,
    pub files: FileCapability,
}

/// A validated, provider-specific target. Core code sees only this trait.
/// What a provider operation (#234) runs against on a target that offers them: the app the
/// operations are bound to (never the caller's), the CLI that runs them, and the registry host
/// an image of that app lives under. Names only.
#[derive(Debug, Clone)]
pub struct OperationBinding {
    pub app: String,
    pub tool: &'static Tool,
    pub registry: &'static str,
    /// The provider's calls of the operations, so core runs them without naming it.
    pub calls: &'static dyn TargetOperations,
}

/// One machine of a target's app as an operation lists it (#234 §2, O5): ids, names, a
/// state, a region and an image reference only, never its environment or metadata.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ListedMachine {
    pub id: String,
    pub name: String,
    pub state: String,
    pub region: String,
    pub image: String,
}

/// The calls behind `opv target op` (#234), implemented by a provider whose targets offer
/// operations. Each runs under the runner it is given (the target's strict deploy sign-in)
/// with `app` the target's bound app, never a caller input.
pub trait TargetOperations: fmt::Debug + Sync {
    /// `machines`: the app's machines, projected (a read).
    fn machines(&self, r: &dyn CommandRunner, app: &str) -> Result<Vec<ListedMachine>, Error>;
    /// `machine-update`: list the app, refuse a `machine` not in it, then move that machine
    /// to `image` (a write, never retried). `env` and `target` name a refusal.
    fn machine_update(
        &self,
        r: &dyn CommandRunner,
        env: &str,
        target: &str,
        app: &str,
        machine: &str,
        image: &str,
    ) -> Result<(), Error>;
}

pub trait TargetConfig: fmt::Debug + Send + Sync {
    /// The provider this target belongs to (its label names it in messages: "on Fly").
    fn provider(&self) -> &'static dyn Provider;
    /// The binding `opv target op` runs against (#234), or `None` when the target's
    /// provider offers no operations.
    fn operations(&self) -> Option<OperationBinding> {
        None
    }
    /// Runtime env var name of `product`/`key`.
    fn env_name(&self, product: &str, key: &str) -> String;
    /// The target instance, as one stable string (an app, repositories, a vault and app, a
    /// cluster location): what a delivery receipt is bound to, so it never applies to
    /// another target (#106). Names only.
    fn target_locator(&self) -> String;
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
    /// True when `other` is the same target: two targets on it would manage the same names,
    /// and each would prune what the other stages (FR-8). Which products a target delivers
    /// is not the provider's to decide: see [`crate::domain::Fleet::delivers`] (FR-56).
    fn same_target(&self, other: &dyn TargetConfig) -> bool;
    /// The place `self` shares with `other` when [`TargetConfig::same_target`] holds, for
    /// the error: the target's own locator unless the provider names a narrower one.
    fn shared_locator(&self, _other: &dyn TargetConfig) -> String {
        self.target_locator()
    }
    /// True when the place [`TargetConfig::shared_locator`] names is a job a target lists
    /// as a companion: no template tells it apart, so the fix is to list it on one target
    /// only (#252).
    fn shares_job(&self, _other: &dyn TargetConfig) -> bool {
        false
    }
    /// The configuration error for targets `first` and `second` (each named as `<env>
    /// (target <name>)`) sharing this target.
    fn shared_target_error(&self, first: &str, second: &str) -> String;
    /// Where each kind of key goes on this target, and whether it delivers files (design
    /// §1.1, §1.3). Required: a target cannot compile without declaring all three.
    fn channels(&self) -> Channels;
    /// The store and runtime adapters of this target (FR-28). `managed` is every env name
    /// the template renders for a declared key (FR-8); the ports speak those names.
    /// `config` is the subset that belongs to config keys, so a target with a separate
    /// config object (a Kubernetes ConfigMap) never puts a secret there by mistake.
    fn open<'a>(
        &'a self,
        env: &'a str,
        managed: BTreeSet<String>,
        files: &BTreeMap<String, FileMount>,
        config: &BTreeSet<String>,
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
    /// The checks of a target that mounts file keys (design §6.6), run right after
    /// [`TargetConfig::preflight`] with the file keys this target delivers (env name →
    /// product and path, as [`TargetConfig::open`] gets them). Returned like `preflight`'s
    /// checks: `Err` refuses, each check is one line. Default: no file mount, no check.
    fn preflight_files(
        &self,
        _r: &dyn CommandRunner,
        _mode: PreflightMode,
        _files: &BTreeMap<String, FileMount>,
    ) -> Result<Vec<Check>, Error> {
        Ok(Vec::new())
    }
    /// `doctor` lines: tool versions and sign-in, never identities or values (FR-3).
    fn doctor(&self, r: &dyn CommandRunner, host: &dyn Fn() -> Host) -> Vec<Check>;
    /// `explain` lines for a secret `product`/`key`: (label, value), e.g. ("fly name", ..).
    fn explain(&self, product: &str, key: &str) -> Vec<(&'static str, String)>;
    /// `explain` lines for a config key, when this target routes config itself (Azure:
    /// a plain env value or a Key Vault reference). `None`: config is not deployed here.
    fn explain_config(&self, _product: &str, _key: &str) -> Option<Vec<(&'static str, String)>> {
        None
    }
    /// The runtime a pinned target binds (its Deployment, its Container App) as a catalog
    /// subject, with its system and program, for a refusal its own reads showed (a revision
    /// that is unhealthy, still rolling out, or missing; design §4.5). `None`: no runtime.
    fn runtime_subject(
        &self,
    ) -> Option<(
        crate::cause::System,
        &'static str,
        crate::cause::ResourceRef,
    )> {
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

/// The catalog's external system behind `provider`, by its configuration section (for a
/// cause about the provider itself, such as `Guard::ProviderHidesValues`).
pub fn system_of(provider: &dyn Provider) -> crate::cause::System {
    use crate::cause::System;
    match provider.section() {
        "fly" => System::Fly,
        "azure" => System::Azure,
        "kubernetes" => System::Kubernetes,
        _ => System::GitHub,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One target per registered provider (`adapters::registry::PROVIDERS`), so the
    /// contract test sees every provider. One secret key makes the configuration load.
    const ALL_PROVIDERS: &str = r#"
[environments.prod]
boundaries.web = { vault_id = "vweb", item_id = "iweb" }

[environments.prod.targets.fly]
fly.app = "web-prod"
fly.secret_name = "{KEY}"
state_vault_id = "sfly"

[environments.prod.targets.azure]
azure.subscription = "00000000-0000-0000-0000-000000000000"
azure.key_vault = "kv-web"
azure.resource_group = "rg-web"
azure.container_app = "ca-web"
azure.identity = "system"
azure.env_name = "{KEY}"
state_vault_id = "saz"

[environments.prod.targets.kubernetes]
kubernetes.context = "kind-dev"
kubernetes.namespace = "app"
kubernetes.deployment = "web"
kubernetes.env_name = "{KEY}"
state_vault_id = "sk8s"

[environments.prod.targets.github]
github.repo = "org/web"
state_vault_id = "sgh"

[environments.prod.targets.http]
state_vault_id = "shttp"
http.host = "central.example.com"
http.descriptor = "tests/fixtures/https/zonetico/platform_console.binpb"
http.descriptor_sha256 = "ec5b6933b89fc49c1ebeaaa31afc666e9090036c53301648cc657cd18f8a7445"
http.names = { DATABASE_URL = "openrouter" }
http.list.call = "portal.v1.PlatformConsoleService/ListPlatformConnections"
http.list.request = { operator_id = "00000000-0000-4000-8000-000000000000" }
http.list.items = "connections"
http.list.name = "provider"
http.list.version = "version"
http.list.status = "status"
http.list.absent = ["CONNECTION_STATUS_NOT_CONFIGURED", "CONNECTION_STATUS_REVOKED"]
http.list.rejected = ["CONNECTION_STATUS_REJECTED"]
http.put.call = "portal.v1.PlatformConsoleService/SavePlatformConnection"
http.put.request = { operator_id = "00000000-0000-4000-8000-000000000000", provider = "{name}", expected_version = "{version}" }
http.put.value = { field = "secret_value", number = 3, type = "bytes" }
http.put.reply = "connection"
http.put.conflict = ["ALREADY_EXISTS"]

[products.web.keys.DATABASE_URL]
kind = "secret"
environments = ["prod"]
"#;

    /// A section's relative file reference resolves against its configuration file's
    /// directory (design `http-target` §3.1: the descriptor set sits beside the config).
    #[test]
    fn a_relative_reference_resolves_against_the_configuration_directory() {
        let value = toml::de::DeValue::parse("{ x = 1 }").expect("an inline table");
        let section = Section::new("prod", &value, "{ x = 1 }")
            .in_dir(Some(std::path::Path::new("/repo/deploy")));
        assert_eq!(
            section.resolve("opv/api.binpb"),
            std::path::PathBuf::from("/repo/deploy/opv/api.binpb")
        );
    }

    /// The contract test (design §1.1, §1.3): each provider's table, as today's behaviour.
    #[test]
    fn the_contract_lists_every_providers_channels() {
        let fleet = crate::config::parse(ALL_PROVIDERS).expect("the fixture loads");
        let prod = &fleet.environments["prod"].targets;
        let table: Vec<(&str, Channels)> = crate::adapters::registry::PROVIDERS
            .iter()
            .map(|p| {
                let section = p.section();
                (section, prod[section].config.channels())
            })
            .collect();
        assert_eq!(
            table,
            vec![
                (
                    "fly",
                    Channels {
                        secret: Channel::Store {
                            label: "Fly secret"
                        },
                        config: Channel::Declined {
                            why: "set fly.config",
                        },
                        files: FileCapability::ViaApp {
                            note: "env at boot, written to files by the app's shim",
                        },
                    },
                ),
                (
                    "azure",
                    Channels {
                        secret: Channel::Store { label: "Key Vault" },
                        config: Channel::RuntimeEnv,
                        files: FileCapability::None,
                    },
                ),
                (
                    "kubernetes",
                    Channels {
                        secret: Channel::Store {
                            label: "Kubernetes Secret",
                        },
                        config: Channel::RuntimeEnv,
                        files: FileCapability::None,
                    },
                ),
                (
                    "github",
                    Channels {
                        secret: Channel::Store {
                            label: "GitHub secret"
                        },
                        config: Channel::Variables,
                        files: FileCapability::None,
                    },
                ),
                (
                    "http",
                    Channels {
                        secret: Channel::Store {
                            label: "HTTP target"
                        },
                        config: Channel::Declined {
                            why: "the HTTP target delivers secrets only",
                        },
                        files: FileCapability::None,
                    },
                ),
            ]
        );
    }
}
