//! The sealed target's provider (design `sealed-target` §3, §3.2, §8.1, §8.2): parses the
//! `sealed` section, declares the channels and the cross-target load rules.
//!
//! The signing login (lane P2, [`super::login`]) needs `sealed.signer`, so a parsed target
//! keeps a per-signer provider, as the HTTP target keeps a per-host one.
//!
//! Stub left for a later lane, refusing as an internal error that names the lane:
//! - `TargetConfig::open` → lane P3 (`store.rs`: the whole-set `StagedStore` with
//!   `live() == true`, its runtime) and lane C1 (`whole_set()` on the port).

use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, OnceLock};

use super::config::{Raw, SealedTarget, check_fleet};
use crate::cause::Cause;
use crate::domain::runtime::FileMount;
use crate::error::Error;
use crate::host::Host;
use crate::ports::Ports;
use crate::provider::{
    Channel, Channels, Check, CredentialField, DeployLogin, FileCapability, FleetRefusal,
    NameRules, Preflight, PreflightMode, Provider, Section, TargetConfig, eq_as,
};
use crate::runner::CommandRunner;

/// The label of the sealed bundle in messages, for both channels (§3.2).
pub const LABEL: &str = "sealed bundle";

/// The registered `sealed` provider: parses sections only, so it carries no signer.
pub static PROVIDER: SealedProvider = SealedProvider {
    signer: String::new(),
};

/// The sealed target's provider. `signer` is `SHA256:…` of the configuration's
/// `sealed.signer`; it is empty on [`PROVIDER`] and set on the per-signer provider a parsed
/// target answers with.
#[derive(Debug)]
pub struct SealedProvider {
    signer: String,
}

/// The fields the signing item holds (D3, D13: a 1Password SSH Key item).
pub const SIGNER_FIELDS: &[CredentialField] = super::login::FIELDS;

/// The per-signer provider of `signer`, interned so a process leaks at most one per distinct
/// signer.
fn provider_for(signer: &str) -> &'static SealedProvider {
    static CACHE: OnceLock<Mutex<BTreeMap<String, &'static SealedProvider>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut cache = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(provider) = cache.get(signer) {
        return provider;
    }
    let provider: &'static SealedProvider = Box::leak(Box::new(SealedProvider {
        signer: signer.to_string(),
    }));
    cache.insert(signer.to_string(), provider);
    provider
}

/// The refusal of a capability a later lane of 0.18.0 builds (never reached in a release).
fn not_yet(site: &'static str) -> Error {
    Cause::Bug { site }.into()
}

impl Provider for SealedProvider {
    fn section(&self) -> &'static str {
        "sealed"
    }

    fn system(&self) -> crate::cause::System {
        crate::cause::System::Sealed
    }

    fn label(&self) -> &'static str {
        LABEL
    }

    fn tools(&self) -> &'static [&'static crate::host::Tool] {
        // Sealing and signing run in process; no vendor CLI.
        &[]
    }

    fn parse(&self, section: &Section<'_>) -> Result<Box<dyn TargetConfig>, Error> {
        let raw: Raw = section.deserialize()?;
        let target = SealedTarget::parse(raw, section.env(), section.resolve(""))?;
        Ok(Box::new(target))
    }

    fn doctor_checks(&self) -> &'static [&'static str] {
        &[]
    }

    fn setup_hint(&self) -> String {
        "configure sealed.out, sealed.env_name, sealed.recipients and sealed.signer".to_string()
    }

    fn deploy_credential_fields(&self) -> Result<&'static [CredentialField], String> {
        Ok(SIGNER_FIELDS)
    }

    /// The SSH Key login, which refuses a key other than `sealed.signer` (T2). Only a
    /// parsed target's provider knows the signer; the registered one is never asked.
    fn deploy_login(&self) -> Result<Box<dyn DeployLogin>, Error> {
        if self.signer.is_empty() {
            return Err(not_yet("sealed deploy_login on the registered provider"));
        }
        Ok(Box::new(super::login::SealedLogin::new(
            self.signer.clone(),
        )))
    }

    fn check_fleet(&self, fleet: &crate::domain::Fleet) -> Result<(), Box<FleetRefusal>> {
        check_fleet(fleet)
    }
}

impl TargetConfig for SealedTarget {
    fn provider(&self) -> &'static dyn Provider {
        provider_for(&self.signer_fingerprint)
    }

    fn env_name(&self, product: &str, key: &str) -> String {
        self.env_name_of(product, key)
    }

    fn target_locator(&self) -> String {
        format!("bundle {}", self.out)
    }

    fn store_name(&self, env_name: &str) -> String {
        env_name.to_string()
    }

    fn name_rules(&self) -> NameRules {
        NameRules {
            env_label: "sealed env name",
            store: None,
        }
    }

    fn same_target(&self, other: &dyn TargetConfig) -> bool {
        other
            .as_any()
            .downcast_ref::<SealedTarget>()
            .is_some_and(|o| o.out == self.out && o.config_dir == self.config_dir)
    }

    fn shared_target_error(&self, first: &str, second: &str) -> String {
        format!(
            "{first} and {second} both write the sealed bundle {}; each would replace the other's",
            self.out
        )
    }

    /// Config and secrets both travel in the bundle (T15); files go to the runtime's
    /// `secrets_dir_env` directory, per product (T5).
    fn channels(&self) -> Channels {
        Channels {
            secret: Channel::Store { label: LABEL },
            config: Channel::Store { label: LABEL },
            files: FileCapability::Native {
                dir: "$<secrets_dir_env> on the runtime ({product})".to_string(),
            },
        }
    }

    fn open<'a>(
        &'a self,
        _env: &'a str,
        _managed: BTreeSet<String>,
        _files: &BTreeMap<String, FileMount>,
        _config: &BTreeSet<String>,
        _r: &'a dyn CommandRunner,
    ) -> Result<Ports<'a>, Error> {
        Err(not_yet(
            "sealed open: the bundle store is lane st-p3 (whole-set port lane st-c1)",
        ))
    }

    fn preflight(&self, _r: &dyn CommandRunner, _mode: PreflightMode) -> Result<Preflight, Error> {
        Ok(Preflight::default())
    }

    fn doctor(&self, _r: &dyn CommandRunner, _host: &dyn Fn() -> Host) -> Vec<Check> {
        Vec::new()
    }

    fn explain(&self, product: &str, key: &str) -> Vec<(&'static str, String)> {
        vec![
            ("sealed bundle", self.out_of(product)),
            ("sealed env name", self.env_name_of(product, key)),
        ]
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
