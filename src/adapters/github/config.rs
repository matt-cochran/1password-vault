//! The GitHub provider: `[environments.<env>.github]` parsing and validation, GitHub name
//! rules, product scope, doctor, preflight and the port wiring (FR-46, FR-48).
//!
//! CONTRACT STUB (plan deliverable `github-target-config`): the struct and the provider
//! static are fixed; the trait bodies are implemented with unit tests.

use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};

use crate::domain::Profile;
use crate::error::Error;
use crate::host::Host;
use crate::ports::Ports;
use crate::provider::{
    Check, InitField, NameRules, Preflight, PreflightMode, Provider, Section, TargetConfig,
};
use crate::runner::CommandRunner;

/// The registered GitHub provider.
pub static PROVIDER: GithubProvider = GithubProvider;

/// The GitHub provider (section `github`).
#[derive(Debug)]
pub struct GithubProvider;

/// The GitHub Actions target of one environment (FR-46).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubTarget {
    /// `owner/name` of every repository written, from `repo` or `repos`; at least one, no
    /// duplicates (case-insensitive, as GitHub treats them).
    pub repos: Vec<String>,
    /// The GitHub environment whose secrets and variables are written; `None`: repository
    /// secrets and variables.
    pub environment: Option<String>,
    /// The products whose keys this target receives (FR-48); `None`: every product.
    pub products: Option<BTreeSet<String>>,
    /// Name template with `{KEY}` and optionally `{PRODUCT}`; default `{KEY}`.
    pub secret_name_template: String,
    pub profile: Profile,
}

impl Provider for GithubProvider {
    fn section(&self) -> &'static str {
        "github"
    }
    fn label(&self) -> &'static str {
        "GitHub"
    }
    fn tools(&self) -> &'static [&'static crate::host::Tool] {
        &[&super::GH]
    }
    fn parse(
        &self,
        section: &Section<'_>,
        profile: Profile,
    ) -> Result<Box<dyn TargetConfig>, Error> {
        let _ = (section, profile);
        todo!("github-target-config")
    }
    fn doctor_checks(&self) -> &'static [&'static str] {
        &["gh", "gh auth"]
    }
    fn setup_hint(&self, profile: Profile) -> String {
        let _ = profile;
        "configure github.repo".into()
    }
    fn init_fields(&self) -> &'static [InitField] {
        &[]
    }
    fn init_section(&self, values: &BTreeMap<&str, String>, profile: Profile) -> Option<String> {
        let _ = (values, profile);
        None
    }
}

impl TargetConfig for GithubTarget {
    fn provider(&self) -> &'static dyn Provider {
        &PROVIDER
    }
    fn env_name(&self, product: &str, key: &str) -> String {
        let _ = (product, key);
        todo!("github-target-config")
    }
    fn store_name(&self, env_name: &str) -> String {
        env_name.to_string()
    }
    fn name_rules(&self) -> NameRules {
        NameRules {
            env_label: "GitHub name",
            store: None,
        }
    }
    fn serves(&self, product: &str) -> bool {
        self.products.as_ref().is_none_or(|p| p.contains(product))
    }
    fn same_target(&self, other: &dyn TargetConfig) -> bool {
        let _ = other;
        todo!("github-target-config")
    }
    fn shared_target_error(&self, first: &str, second: &str) -> String {
        let _ = (first, second);
        todo!("github-target-config")
    }
    fn open<'a>(
        &'a self,
        _env: &'a str,
        _managed: BTreeSet<String>,
        r: &'a dyn CommandRunner,
    ) -> Result<Ports<'a>, Error> {
        let gh = || super::Github {
            runner: r,
            scope: super::Scope {
                repos: &self.repos,
                environment: self.environment.as_deref(),
            },
        };
        Ok(Ports::Staged {
            store: Box::new(gh()),
            runtime: Box::new(gh()),
        })
    }
    fn preflight(&self, r: &dyn CommandRunner, mode: PreflightMode) -> Result<Preflight, Error> {
        let _ = (r, mode);
        todo!("github-target-config")
    }
    fn doctor(&self, r: &dyn CommandRunner, host: &dyn Fn() -> Host) -> Vec<Check> {
        let _ = (r, host);
        todo!("github-target-config")
    }
    fn explain(&self, product: &str, key: &str) -> Vec<(&'static str, String)> {
        let _ = (product, key);
        todo!("github-target-config")
    }
    fn eq_dyn(&self, other: &dyn TargetConfig) -> bool {
        crate::provider::eq_as(self, other)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn clone_box(&self) -> Box<dyn TargetConfig> {
        Box::new(self.clone())
    }
}
