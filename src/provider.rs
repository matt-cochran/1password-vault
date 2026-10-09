//! The provider plug-in contract (FR-37, `docs/design/multi-cloud-targets.md` §11).
//!
//! Every deployment provider lives under `src/adapters/<provider>/`, implements [`Provider`]
//! for its configuration section and [`TargetConfig`] for a validated target, and is
//! registered once in `adapters::registry::PROVIDERS`. Core code (`app/`, `domain/`,
//! `config.rs`) sees only these traits, so adding a provider changes no core code.

use std::any::Any;
use std::fmt;

use serde::de::DeserializeOwned;
use toml::Spanned;
use toml::de::{DeValue, ValueDeserializer};

use crate::domain::Profile;
use crate::error::Error;
use crate::host::Host;
use crate::ports::Ports;
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
    /// The TOML lines `opv init` writes for a target named `name` (FR-23), or `None` when
    /// the provider does not support `init`.
    fn init_section(&self, name: &str, profile: Profile) -> Option<String>;
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

    /// The environment this section belongs to.
    pub fn env(&self) -> &str {
        self.env
    }

    /// The section as `T`. A missing, unknown or mistyped field is reported like any other
    /// TOML error in the file: line, column, the line itself and the field (FR-2).
    pub fn deserialize<T: DeserializeOwned>(&self) -> Result<T, Error> {
        T::deserialize(ValueDeserializer::from(self.value.clone())).map_err(|mut e| {
            e.set_input(Some(self.text));
            Error::Config(format!("invalid secrets.toml: {e}"))
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
    /// True when `other` is the same target: two environments on it would manage the same
    /// names, and each would prune what the other stages (FR-8).
    fn same_target(&self, other: &dyn TargetConfig) -> bool;
    /// The configuration error for environments `first` and `second` sharing this target.
    fn shared_target_error(&self, first: &str, second: &str) -> String;
    /// The store and runtime adapters of this target (FR-28).
    fn open<'a>(&'a self, env: &'a str, r: &'a dyn CommandRunner) -> Result<Ports<'a>, Error>;
    /// Read-only checks of the target's own state, run by mutating commands before their
    /// first write (NR-23, NR-24): `Err` refuses the run with nothing written, and so does
    /// a returned check that failed. The other returned checks are printed one line each,
    /// like `doctor`'s; return only those worth a line (warnings), a passing state is silent.
    fn preflight(&self, r: &dyn CommandRunner) -> Result<Vec<Check>, Error>;
    /// `doctor` lines: tool versions and sign-in, never identities or values (FR-3).
    fn doctor(&self, r: &dyn CommandRunner, host: &dyn Fn() -> Host) -> Vec<Check>;
    /// `explain` lines for a secret `product`/`key`: (label, value), e.g. ("fly name", ..).
    fn explain(&self, product: &str, key: &str) -> Vec<(&'static str, String)>;
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
    /// The rule as shown to the user, e.g. `^[0-9A-Za-z-]{1,127}$`.
    pub pattern: &'static str,
    /// Store names differing only in case are the same name.
    pub case_insensitive: bool,
}

/// One named `doctor` check line.
#[derive(Debug)]
pub struct Check {
    pub name: &'static str,
    pub outcome: Result<Verdict, Error>,
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
