//! A target's `kubernetes` section parsing, Kubernetes name rules, doctor checks and the
//! port wiring (FR-37, FR-38, `docs/design/multi-cloud-targets.md` §12).
//!
//! Every identifier is checked while the section is deserialized, so a bad value is reported
//! like any other TOML error: line, column, the line itself (FR-2).

use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use super::external::{self, Bridge, ExternalStore};
use super::runtime::{DEPLOY_RIGHTS, POLL_EVERY, WAIT_MAX, missing_rights};
use super::{
    Effect, Failed, KUBECTL, KubeDeployment, KubeSecrets, KubeTarget, Kubectl, PROGRAM,
    valid_label_value,
};
use crate::adapters::probe::{spawn_tool, version_in};
use crate::cause::{Cause, FieldRule, Unusable};
use crate::config::{TEMPLATE_WORDS, section_invalid};
use crate::error::Error;
use crate::host::Host;
use crate::ports::Ports;
use crate::provider::{
    Channel, Channels, Check, FileCapability, InitField, NameRules, Preflight, PreflightMode,
    Provider, Section, StoreBinding, StoreConfig, StoreNameRules, TargetConfig, Verdict, eq_as,
    init_lines,
};
use crate::runner::CommandRunner;

/// The registered Kubernetes provider.
pub static PROVIDER: KubernetesProvider = KubernetesProvider;

/// The Kubernetes provider (section `kubernetes`).
#[derive(Debug)]
pub struct KubernetesProvider;

/// The `doctor` check names, in the order they print.
const CHECKS: [&str; 4] = [
    "kubectl",
    "kubernetes context",
    "kubernetes cluster",
    "kubernetes access",
];

/// The env-name template `opv init` writes when none is given.
const INIT_FLEET_TEMPLATE: &str = "FLEET__{PRODUCT}__{KEY}";

/// `opv target add` options of the Kubernetes provider (H3), in the order they are written.
static INIT_FIELDS: [InitField; 6] = [
    InitField {
        field: "context",
        help: "kubeconfig context (kubectl config get-contexts -o name)",
        required: true,
    },
    InitField {
        field: "namespace",
        help: "Namespace of the Deployment",
        required: true,
    },
    InitField {
        field: "deployment",
        help: "Deployment that reads the secrets",
        required: true,
    },
    InitField {
        field: "container",
        help: "Container in the Deployment (only when it has more than one)",
        required: false,
    },
    InitField {
        field: "env_name",
        help: "Env-name template (default FLEET__{PRODUCT}__{KEY}; {KEY} for bare names)",
        required: false,
    },
    InitField {
        field: "config",
        help: "Where config keys go: env (default) or store",
        required: false,
    },
];

/// A DNS-1123 label as shown to the user.
const LABEL_PATTERN: &str = "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ (at most 63 characters)";

/// Where the Deployment reads configuration keys: plain `value` env entries (`Env`) or
/// Secrets like secret keys (`Store`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfigRoute {
    #[default]
    Env,
    Store,
}

/// The Kubernetes target of one environment (FR-38).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubernetesTarget {
    /// Context, namespace, Deployment, container and the opv environment (the
    /// `opv-managed` label value), as the adapters use them.
    pub target: KubeTarget,
    /// Env-name template with `{KEY}` and optionally `{PRODUCT}`.
    pub env_name_template: String,
    pub config: ConfigRoute,
    /// The named store secrets live in (`secrets_in`, FR-39), bound through the External
    /// Secrets Operator; `None`: opv's own immutable Secrets.
    pub store: Option<Box<dyn StoreConfig>>,
}

/// The `secrets_in` pairs this runtime supports (FR-39).
static BINDINGS: [StoreBinding; 1] = [StoreBinding {
    store_kind: "azure_key_vault",
    via: "External Secrets Operator",
}];

/// The section as written. Its identifiers are checked once it is read
/// ([`Raw::checked`]), so each refusal is a typed configuration cause (C15).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    context: String,
    namespace: String,
    deployment: String,
    #[serde(default)]
    container: Option<String>,
    #[serde(default)]
    env_name: Option<String>,
    #[serde(default)]
    config: ConfigRoute,
}

/// A Kubernetes name (DNS-1123 label), in words.
const LABEL_WORDS: &str = "a Kubernetes name: lower-case letters, digits and -, starting and ending with a letter or digit, at most 63 characters";
/// A kubeconfig context name, in words.
const CONTEXT_WORDS: &str = "a kubeconfig context name: letters, digits and _ . : / @ + -, not starting with - (kubectl config get-contexts -o name lists them)";

impl Raw {
    /// The section's identifiers checked (FR-37): the context goes into argv (never read as
    /// a flag, no whitespace or shell metacharacters; cloud context names hold `:`, `/` and
    /// `@`); namespace, Deployment and container are DNS-1123 labels; `env_name` is
    /// required and contains `{KEY}` (`{PRODUCT}` is optional; two keys rendering one name
    /// are refused at load, FR-30). Returns the template.
    fn checked(&mut self) -> Result<String, Error> {
        let bad = |field: &str, words: &'static str| {
            section_invalid(
                &format!("kubernetes.{field}"),
                FieldRule::Type { expected: words },
            )
        };
        if !is_context(&self.context) {
            return Err(bad("context", CONTEXT_WORDS));
        }
        let labels = [
            ("namespace", Some(&self.namespace)),
            ("deployment", Some(&self.deployment)),
            ("container", self.container.as_ref()),
        ];
        for (field, value) in labels {
            if value.is_some_and(|v| !valid_label_value(v)) {
                return Err(bad(field, LABEL_WORDS));
            }
        }
        match self.env_name.take() {
            Some(t) if t.contains("{KEY}") => Ok(t),
            Some(_) => Err(bad("env_name", TEMPLATE_WORDS)),
            None => Err(section_invalid("kubernetes.env_name", FieldRule::Missing)),
        }
    }
}

pub(crate) fn is_context(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '/' | '@' | '+' | '-')
        })
}

impl Raw {
    fn target(self, env: &str, env_name_template: String) -> KubernetesTarget {
        KubernetesTarget {
            target: KubeTarget {
                context: self.context,
                namespace: self.namespace,
                deployment: self.deployment,
                container: self.container,
                env: env.to_string(),
            },
            env_name_template,
            config: self.config,
            store: None,
        }
    }
}

impl Provider for KubernetesProvider {
    fn section(&self) -> &'static str {
        "kubernetes"
    }

    fn label(&self) -> &'static str {
        "Kubernetes"
    }

    fn tools(&self) -> &'static [&'static crate::host::Tool] {
        &[&KUBECTL]
    }

    fn parse(&self, section: &Section<'_>) -> Result<Box<dyn TargetConfig>, Error> {
        let env = section.env();
        let mut raw: Raw = section.deserialize()?;
        let t = raw.checked()?;
        Ok(Box::new(raw.target(env, t)))
    }

    fn doctor_checks(&self) -> &'static [&'static str] {
        &CHECKS
    }

    fn ci_setup_step(&self) -> Option<&'static str> {
        None
    }

    fn deploy_credential_fields(
        &self,
    ) -> Result<&'static [crate::provider::CredentialField], String> {
        Err(
            "deploy_credentials is not supported for Kubernetes: kubectl uses your \
             kubeconfig (kubernetes.context) to sign in; remove deploy_credentials and give \
             that context a least-privilege identity (with secrets_in naming a Key Vault, \
             deploy_credentials signs in the az that writes it)"
                .into(),
        )
    }

    fn setup_hint(&self) -> String {
        "configure kubernetes.context, kubernetes.namespace, kubernetes.deployment and \
         kubernetes.env_name"
            .into()
    }

    fn init_fields(&self) -> &'static [InitField] {
        &INIT_FIELDS
    }

    fn init_section(&self, values: &BTreeMap<&str, String>) -> Option<String> {
        let mut lines: Vec<(&str, &str)> = Vec::new();
        for f in &INIT_FIELDS {
            let v = match (values.get(f.field), f.field) {
                (Some(v), _) => v.as_str(),
                (None, "env_name") => INIT_FLEET_TEMPLATE,
                (None, _) => continue,
            };
            lines.push((f.field, v));
        }
        Some(init_lines("kubernetes", lines))
    }

    fn bindings(&self) -> &'static [StoreBinding] {
        &BINDINGS
    }

    fn bind(
        &self,
        target: Box<dyn TargetConfig>,
        store: &dyn StoreConfig,
    ) -> Result<Box<dyn TargetConfig>, Error> {
        let Some(t) = target.as_any().downcast_ref::<KubernetesTarget>() else {
            return Err(Cause::Bug {
                site: "kubernetes: bind was given a target of another provider",
            }
            .into());
        };
        Ok(Box::new(KubernetesTarget {
            store: Some(store.clone_box()),
            ..t.clone()
        }))
    }
}

/// A store name character: lower-case letters, digits and `-` (DNS-1123).
fn store_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'
}

impl KubernetesTarget {
    /// Env var name for `product`/`key`: `{PRODUCT}` becomes the upper-cased product with
    /// `-` replaced by `_`, `{KEY}` becomes the key verbatim.
    pub fn env_name_of(&self, product: &str, key: &str) -> String {
        let product = product.to_ascii_uppercase().replace('-', "_");
        self.env_name_template
            .replace("{PRODUCT}", &product)
            .replace("{KEY}", key)
    }
}

impl TargetConfig for KubernetesTarget {
    fn runtime_subject(
        &self,
    ) -> Option<(
        crate::cause::System,
        &'static str,
        crate::cause::ResourceRef,
    )> {
        Some((
            crate::cause::System::Kubernetes,
            PROGRAM,
            self.target.deployment_ref(),
        ))
    }
    fn target_locator(&self) -> String {
        format!(
            "context {} namespace {} deployment {}",
            self.target.context, self.target.namespace, self.target.deployment
        )
    }

    fn provider(&self) -> &'static dyn Provider {
        &PROVIDER
    }

    fn env_name(&self, product: &str, key: &str) -> String {
        self.env_name_of(product, key)
    }

    fn store_name(&self, env_name: &str) -> String {
        match &self.store {
            Some(s) => s.store_name(env_name),
            None => super::store_name(env_name),
        }
    }

    fn secrets_in(&self) -> Option<&dyn StoreConfig> {
        self.store.as_deref()
    }

    fn name_rules(&self) -> NameRules {
        if self.store.is_some() {
            // The store's own rules are checked too (config.rs); here, its spelling must
            // also name the ExternalSecret `opv-<lower-cased name>-<10>` and be the `opv-key`
            // label value.
            return NameRules {
                env_label: "env name",
                store: Some(StoreNameRules {
                    label: "Kubernetes name",
                    max_len: 63,
                    allowed: |c| c.is_ascii_alphanumeric() || c == '-',
                    edge: |c| c.is_ascii_alphanumeric(),
                    pattern: "^[0-9A-Za-z]([-0-9A-Za-z]*[0-9A-Za-z])?$ (at most 63 characters; \
                              it names the ExternalSecret once lower-cased)",
                    case_insensitive: true,
                }),
            };
        }
        NameRules {
            env_label: "env name",
            store: Some(StoreNameRules {
                // The store name is the `opv-key` label value and the middle of the Secret
                // name `opv-<store>-<10 hex>`: a label (≤ 63) keeps that name ≤ 253.
                label: "Kubernetes name",
                max_len: 63,
                allowed: store_char,
                edge: |c| c.is_ascii_lowercase() || c.is_ascii_digit(),
                pattern: LABEL_PATTERN,
                case_insensitive: true,
            }),
        }
    }

    fn same_target(&self, other: &dyn TargetConfig) -> bool {
        other
            .as_any()
            .downcast_ref::<KubernetesTarget>()
            .is_some_and(|o| {
                let (a, b) = (&self.target, &o.target);
                a.context == b.context
                    && a.namespace == b.namespace
                    && a.deployment == b.deployment
                    && self.env_name_template == o.env_name_template
            })
    }

    fn shared_target_error(&self, first: &str, second: &str) -> String {
        let t = &self.target;
        format!(
            "environments {first} and {second} both use Kubernetes deployment {:?} in namespace \
             {:?} (context {:?}) with kubernetes.env_name {:?}; each would prune what the other \
             binds",
            t.deployment, t.namespace, t.context, self.env_name_template
        )
    }

    /// Today: immutable Secret versions; config is a plain env value or the store, and a
    /// file key is delivered by name as a secret (design §1.1).
    fn channels(&self) -> Channels {
        Channels {
            secret: Channel::Store {
                label: "Kubernetes Secret",
            },
            config: match self.config {
                ConfigRoute::Store => Channel::Store {
                    label: "Kubernetes Secret",
                },
                ConfigRoute::Env => Channel::RuntimeEnv,
            },
            files: FileCapability::None,
        }
    }

    fn open<'a>(
        &'a self,
        env: &'a str,
        managed: BTreeSet<String>,
        r: &'a dyn CommandRunner,
    ) -> Result<Ports<'a>, Error> {
        // The rollout and ExternalSecret waits have their own limit, and end earlier when
        // the run budget runs short, so their own message comes first (NR-4).
        let wait = WAIT_MAX;
        if let Some(store) = &self.store {
            let bridge = Bridge {
                store: store.open(env, managed.clone(), r),
                cluster_store: store.bridge_name().to_string(),
                describe: store.describe(),
                locator: store.locator().to_string(),
            };
            return Ok(Ports::Pinned {
                store: Box::new(ExternalStore::new(
                    store.open(env, managed.clone(), r),
                    r,
                    &self.target,
                )),
                runtime: Box::new(
                    KubeDeployment::new(r, &self.target, managed)
                        .with_wait(POLL_EVERY, wait, move |d| r.pause(d, ""))
                        .with_config_in_store(self.config == ConfigRoute::Store)
                        .with_external(bridge),
                ),
            });
        }
        Ok(Ports::Pinned {
            store: Box::new(KubeSecrets::new(r, &self.target, managed.clone())),
            runtime: Box::new(
                KubeDeployment::new(r, &self.target, managed)
                    .with_wait(POLL_EVERY, wait, move |d| r.pause(d, ""))
                    .with_config_in_store(self.config == ConfigRoute::Store),
            ),
        })
    }

    /// Every kubectl failure is diagnosed per call (context, reachability, refusal). With
    /// a named store (FR-39): the store's own checks, then the External Secrets Operator,
    /// the ClusterSecretStore and the right to create ExternalSecrets, before any write.
    fn preflight(&self, r: &dyn CommandRunner, mode: PreflightMode) -> Result<Preflight, Error> {
        if mode == PreflightMode::Mutate {
            self.deploy_rights(r)?;
        }
        let Some(store) = &self.store else {
            return Ok(Preflight::default());
        };
        store.preflight(r)?;
        let checks = external::preflight(
            &Kubectl::new(r, &self.target),
            store.bridge_name(),
            store.locator(),
            &store.describe(),
            mode,
        )?;
        Ok(Preflight {
            checks,
            skip_deploy: None,
        })
    }

    fn doctor(&self, r: &dyn CommandRunner, host: &dyn Fn() -> Host) -> Vec<Check> {
        let mut checks = vec![Check {
            name: CHECKS[0].into(),
            outcome: kubectl_version(r, host),
        }];
        if checks[0].outcome.is_err() {
            checks.extend(CHECKS[1..].iter().map(|&name| Check {
                name: name.into(),
                outcome: Ok(Verdict::Warn(
                    "not checked (kubectl not available, see the kubectl line above)".into(),
                )),
            }));
            return checks;
        }
        let context = self.context_check(r, host);
        let context_ok = context.is_ok();
        checks.push(Check {
            name: CHECKS[1].into(),
            outcome: context,
        });
        let cluster = if context_ok {
            self.cluster_check(r, host)
        } else {
            Ok(Verdict::Warn(
                "not checked (context missing, see the line above)".into(),
            ))
        };
        let reachable = matches!(cluster, Ok(Verdict::Ok(_)));
        checks.push(Check {
            name: CHECKS[2].into(),
            outcome: cluster,
        });
        checks.push(Check {
            name: CHECKS[3].into(),
            outcome: if reachable {
                self.access_check(r)
            } else {
                Ok(Verdict::Warn("not checked (cluster not reachable)".into()))
            },
        });
        if let Some(store) = &self.store {
            checks.extend(store.doctor(r, host));
            if reachable {
                checks.extend(external::doctor(
                    &Kubectl::new(r, &self.target),
                    store.bridge_name(),
                    store.locator(),
                    &store.describe(),
                ));
            } else {
                checks.extend(external::DOCTOR_CHECKS.iter().map(|&name| Check {
                    name: name.into(),
                    outcome: Ok(Verdict::Warn("not checked (cluster not reachable)".into())),
                }));
            }
        }
        checks
    }

    fn explain(&self, product: &str, key: &str) -> Vec<(&'static str, String)> {
        let env = self.env_name_of(product, key);
        let k8s = super::store_name(&env);
        if let Some(store) = &self.store {
            let mut lines = vec![("env name", env.clone())];
            lines.extend(store.explain(&env));
            lines.extend([
                (
                    "external secret",
                    format!(
                        "opv-{k8s}-<first {} characters of the pinned version id>, refreshInterval \
                         0, through ClusterSecretStore {}",
                        external::ID_LEN,
                        store.bridge_name()
                    ),
                ),
                (
                    "kubernetes target",
                    format!(
                        "deployment {} in namespace {} (context {})",
                        self.target.deployment, self.target.namespace, self.target.context
                    ),
                ),
                (
                    "chain",
                    format!(
                        "{env} → {} (pinned version) → ExternalSecret opv-{k8s}-<version> → \
                         Secret of the same name → env {env}",
                        store.describe()
                    ),
                ),
            ]);
            return lines;
        }
        vec![
            ("env name", env),
            (
                "kubernetes secret",
                format!(
                    "opv-{k8s}-<{} random characters per version>",
                    super::VERSION_LEN
                ),
            ),
            (
                "kubernetes target",
                format!(
                    "deployment {} in namespace {} (context {})",
                    self.target.deployment, self.target.namespace, self.target.context
                ),
            ),
        ]
    }

    fn explain_config(&self, product: &str, key: &str) -> Option<Vec<(&'static str, String)>> {
        Some(match self.config {
            ConfigRoute::Env => vec![
                ("env name", self.env_name_of(product, key)),
                (
                    "routing",
                    "plain env value on the deployment (kubernetes.config = \"env\")".into(),
                ),
            ],
            ConfigRoute::Store => {
                let mut lines = self.explain(product, key);
                let routing = match &self.store {
                    Some(s) => format!(
                        "{} version pinned through an ExternalSecret (kubernetes.config = \
                         \"store\")",
                        s.describe()
                    ),
                    None => {
                        "Secret reference pinned to one version (kubernetes.config = \"store\")"
                            .into()
                    }
                };
                lines.push(("routing", routing));
                lines
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

/// `kubectl version --client`: present, and which version (only a strict version token is
/// ever printed).
fn kubectl_version(r: &dyn CommandRunner, host: &dyn Fn() -> Host) -> Result<Verdict, Error> {
    let o = spawn_tool(r, KUBECTL, host, &["version", "--client"])?;
    if o.status != 0 {
        return Err(Cause::ToolUnusable {
            tool: PROGRAM.into(),
            why: Unusable::VersionUnreadable,
        }
        .into());
    }
    Ok(match version_in(&o.stdout) {
        Some(v) => Verdict::Ok(format!("version {v}")),
        None => Verdict::Ok("present, version not recognised".into()),
    })
}

impl KubernetesTarget {
    /// `kubectl config get-contexts <ctx> -o name`: the context is in the kubeconfig. A
    /// failure is the kubectl strategy's: a context missing on this machine asks for its
    /// credentials here, never for a change to the shared `kubernetes.context` (06.26).
    fn context_check(
        &self,
        r: &dyn CommandRunner,
        host: &dyn Fn() -> Host,
    ) -> Result<Verdict, Error> {
        let ctx = self.target.context.as_str();
        let o = spawn_tool(
            r,
            KUBECTL,
            host,
            &["config", "get-contexts", ctx, "-o", "name"],
        )?;
        if o.status == 0 {
            Ok(Verdict::Ok(format!("context {ctx} is in your kubeconfig")))
        } else {
            Err(self.probe_failure())
        }
    }

    /// `kubectl --context <ctx> version --request-timeout=5s`: the API server answers. A
    /// failure is the kubectl strategy's: a 401 is a sign-in, a refused connection an
    /// outage (nothing was changed), anything else unrecognised with kubectl's reply.
    fn cluster_check(
        &self,
        r: &dyn CommandRunner,
        host: &dyn Fn() -> Host,
    ) -> Result<Verdict, Error> {
        let ctx = self.target.context.as_str();
        let o = spawn_tool(
            r,
            KUBECTL,
            host,
            &["--context", ctx, "version", "--request-timeout=5s"],
        )?;
        if o.status == 0 {
            Ok(Verdict::Ok(format!("API server for context {ctx} answers")))
        } else {
            Err(self.probe_failure())
        }
    }

    /// The doctor probe that just failed, as the kubectl strategy classifies it.
    fn probe_failure(&self) -> Error {
        match Failed::take(&self.target.env, Effect::Read) {
            Ok(mut f) => {
                f.name_subjects(&self.target, self.target.namespace_ref());
                f.into_error()
            }
            Err(e) => e,
        }
    }

    /// Every right sync needs (FR-32), asked with `kubectl auth can-i`: a missing one fails
    /// with the first refusal the kubectl strategy typed (a missing right, naming the
    /// grant); rights that cannot be checked are a warning. With a named store opv writes
    /// no Secrets itself; the ExternalSecret rights have their own line (`external secrets
    /// access`).
    fn access_check(&self, r: &dyn CommandRunner) -> Result<Verdict, Error> {
        let external = self.store.is_some();
        let needed = |_: &str, resource: &str| !external || resource != "secrets";
        match missing_rights(&Kubectl::new(r, &self.target), false, needed) {
            Ok(found) => match found.into_iter().next() {
                None => Ok(Verdict::Ok(format!(
                    "has every right sync needs in namespace {}",
                    self.target.namespace
                ))),
                Some((_, refused)) => Err(refused),
            },
            Err(e) => Ok(Verdict::Warn(format!("rights not checked: {e}"))),
        }
    }

    /// `sync` (Mutate): the rights only a deploy uses after the new revision is live
    /// ([`DEPLOY_RIGHTS`]), checked before the first write, so a missing one never fails a
    /// deploy that succeeded (FR-32, NR-1). Only a namespace admin can grant it, so the
    /// refusal is a person's step (06.13).
    fn deploy_rights(&self, r: &dyn CommandRunner) -> Result<(), Error> {
        let external = self.store.is_some();
        let pick = |verb: &str, resource: &str| {
            DEPLOY_RIGHTS.contains(&(verb, resource))
                || (external && verb == "delete" && resource == external::RESOURCE)
        };
        let found = missing_rights(&Kubectl::new(r, &self.target), external, pick)?;
        match found.into_iter().next() {
            None => Ok(()),
            Some((_, refused)) => Err(refused),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse;
    use crate::domain::Fleet;
    use crate::runner::Output;
    use crate::runner::fake::FakeRunner;

    const ENV: &str = r#"

[environments.dev]
[environments.dev.targets.app]
state_vault_id = "s"
[environments.dev.targets.app.kubernetes]
context = "kind-opv"
namespace = "myapp"
deployment = "api"
env_name = "FLEET__{PRODUCT}__{KEY}"
"#;

    const KEYS: &str = r#"
[products.api.keys.DB_URL]
kind = "secret"
environments = ["dev"]
"#;

    fn doc(env: &str, keys: &str) -> String {
        crate::config::testing::bounded(&format!("{env}{keys}"))
    }

    /// The fleet document with `from` replaced by `to` in the environment.
    fn with(from: &str, to: &str) -> String {
        assert!(ENV.contains(from), "mutation did not match: {from:?}");
        doc(&ENV.replace(from, to), KEYS)
    }

    fn err(text: &str) -> String {
        parse(text).unwrap_err().to_string()
    }

    fn kube_of<'f>(f: &'f Fleet, env: &str) -> &'f KubernetesTarget {
        f.environments[env]
            .targets
            .values()
            .find_map(|t| t.config.as_any().downcast_ref::<KubernetesTarget>())
            .expect("not kubernetes")
    }

    fn fleet() -> Fleet {
        parse(&doc(ENV, KEYS)).unwrap()
    }

    fn target() -> KubernetesTarget {
        kube_of(&fleet(), "dev").clone()
    }

    #[test]
    fn loads_kubernetes_target() {
        assert_eq!(
            target().target,
            KubeTarget {
                context: "kind-opv".into(),
                namespace: "myapp".into(),
                deployment: "api".into(),
                container: None,
                env: "dev".into(),
            }
        );
    }

    #[test]
    fn config_route_defaults_to_env() {
        assert_eq!(target().config, ConfigRoute::Env);
    }

    #[test]
    fn config_route_store_is_accepted() {
        let f = parse(&with("api\"\n", "api\"\nconfig = \"store\"\n")).unwrap();
        assert_eq!(kube_of(&f, "dev").config, ConfigRoute::Store);
    }

    #[test]
    fn container_is_read_when_set() {
        let f = parse(&with("api\"\n", "api\"\ncontainer = \"web\"\n")).unwrap();
        assert_eq!(kube_of(&f, "dev").target.container.as_deref(), Some("web"));
    }

    #[test]
    fn context_accepts_a_cloud_context_name() {
        let arn = "arn:aws:eks:eu-west-1:123456789012:cluster/prod";
        let f = parse(&with("\"kind-opv\"", &format!("\"{arn}\""))).unwrap();
        assert_eq!(kube_of(&f, "dev").target.context, arn);
    }

    #[test]
    fn invalid_namespace_points_at_its_line() {
        // C15: a typed ConfigInvalid at the field's key, in words, never the value (C1).
        assert_eq!(
            err(&with("\"myapp\"", "\"My_App\"")),
            "secrets.toml at line 9, column 1: environments.dev.targets.app.kubernetes.namespace \
             must be a Kubernetes name: lower-case letters, digits and -, starting and ending with \
             a letter or digit, at most 63 characters"
        );
    }

    #[test]
    fn invalid_deployment_points_at_its_line() {
        let e = err(&with("\"api\"", "\"api-\""));
        assert!(e.contains("line 10, column 1:"), "{e}");
    }

    #[test]
    fn invalid_container_points_at_its_line() {
        let e = err(&with("api\"\n", "api\"\ncontainer = \"-web\"\n"));
        assert!(e.contains("line 11, column 1:"), "{e}");
    }

    #[test]
    fn namespace_over_63_characters_is_refused() {
        let e = err(&with("\"myapp\"", &format!("\"{}\"", "a".repeat(64))));
        assert!(e.contains("kubernetes.namespace"), "{e}");
    }

    #[test]
    fn context_with_leading_dash_points_at_its_line() {
        let e = err(&with("\"kind-opv\"", "\"--kubeconfig=/x\""));
        assert!(e.contains("line 8, column 1:"), "{e}");
    }

    #[test]
    fn context_with_whitespace_is_refused() {
        let e = err(&with("\"kind-opv\"", "\"kind opv\""));
        assert!(
            e.contains("kubernetes.context must be a kubeconfig context name"),
            "{e}"
        );
    }

    #[test]
    fn context_with_shell_metacharacter_is_refused() {
        let e = err(&with("\"kind-opv\"", "\"kind;rm\""));
        assert!(!e.contains("kind;rm"), "{e}");
    }

    #[test]
    fn empty_context_is_refused() {
        let e = err(&with("\"kind-opv\"", "\"\""));
        assert!(e.contains("kubernetes.context must be"), "{e}");
    }

    #[test]
    fn env_name_without_placeholders_points_at_its_line() {
        let e = err(&with("FLEET__{PRODUCT}__{KEY}", "STATIC"));
        assert!(
            e.contains("line 11, column 1:") && e.contains("a template containing {KEY}"),
            "{e}"
        );
    }

    #[test]
    fn missing_env_name_under_fleet_profile_is_refused() {
        let e = err(&with("env_name = \"FLEET__{PRODUCT}__{KEY}\"\n", ""));
        assert!(e.contains("kubernetes.env_name is required"), "{e}");
    }

    #[test]
    fn unknown_config_route_points_at_its_line() {
        let e = err(&with("api\"\n", "api\"\nconfig = \"plain\"\n"));
        assert!(
            e.contains("line 11, column 10") && e.contains("must be one of env, store"),
            "{e}"
        );
    }

    #[test]
    fn unknown_field_points_at_its_line() {
        let e = err(&with("api\"\n", "api\"\nreplicas = 2\n"));
        assert!(e.contains("line 11, column 1"), "{e}");
    }

    /// One product `app` on a `{KEY}` template.
    const BARE: &str = r#"
[environments.dev]
boundaries.app = { vault_id = "v", item_id = "i" }
[environments.dev.targets.app]
state_vault_id = "s"
kubernetes.context = "kind-opv"
kubernetes.namespace = "myapp"
kubernetes.deployment = "api"
kubernetes.env_name = "{KEY}"
[products.app.keys.JWT_KEY]
kind = "secret"
environments = ["dev"]
"#;

    /// A key ending in `_` renders a Kubernetes name ending in `-`: refused at load, at the
    /// key's declaration, not at sync.
    #[test]
    fn key_ending_in_underscore_is_refused_at_its_line() {
        let e = err(&BARE.replace("keys.JWT_KEY]", "keys.JWT_KEY_]"));
        assert!(
            e.contains(
                "renders a Kubernetes name for app/JWT_KEY_ that is not starting and ending"
            ) && e.contains("line 10, column 20"),
            "{e}"
        );
    }

    #[test]
    fn fleet_key_ending_in_underscore_is_refused_at_its_line() {
        let e = err(&doc(ENV, &KEYS.replace("DB_URL]", "DB_URL_]")));
        assert!(
            e.contains("renders a Kubernetes name for api/DB_URL_ that is not starting and ending")
                && e.contains("line 13, column 20"),
            "{e}"
        );
    }

    #[test]
    fn store_name_lower_cases_and_dashes() {
        assert_eq!(
            target().store_name("FLEET__API__DB_URL"),
            "fleet--api--db-url"
        );
    }

    #[test]
    fn rejects_kubernetes_name_collision_by_product_dash_or_underscore() {
        let keys = "[products.a-b.keys.C]\nkind = \"secret\"\nenvironments = [\"dev\"]\n\
                    [products.a_b.keys.C]\nkind = \"secret\"\nenvironments = [\"dev\"]\n";
        let e = err(&doc(ENV, keys));
        assert!(
            e.contains("renders Kubernetes name fleet--a-b--c for both"),
            "{e}"
        );
    }

    #[test]
    fn rejects_kubernetes_name_over_63_characters() {
        let long = "K".repeat(60);
        let keys =
            format!("[products.api.keys.{long}]\nkind = \"secret\"\nenvironments = [\"dev\"]\n");
        let e = err(&doc(ENV, &keys));
        assert!(
            e.contains("that is 72 characters long, over the 63 allowed"),
            "{e}"
        );
    }

    #[test]
    fn rejects_two_environments_sharing_a_deployment_and_template() {
        let second = ENV.replace("environments.dev", "environments.stage");
        let e = err(&doc(&format!("{ENV}{second}"), KEYS));
        assert!(e.contains("manages the same names on Kubernetes "), "{e}");
    }

    #[test]
    fn two_environments_on_different_namespaces_are_accepted() {
        let second = ENV
            .replace("environments.dev", "environments.stage")
            .replace("\"myapp\"", "\"myapp-stage\"")
            .replace("state_vault_id = \"s\"", "state_vault_id = \"s-stage\"");
        assert!(parse(&doc(&format!("{ENV}{second}"), KEYS)).is_ok());
    }

    #[test]
    fn open_returns_pinned_ports() {
        let t = target();
        let r = FakeRunner::new([]);
        assert!(matches!(
            t.open("dev", BTreeSet::new(), &r),
            Ok(Ports::Pinned { .. })
        ));
    }

    #[test]
    fn open_makes_no_calls() {
        let t = target();
        let r = FakeRunner::new([]);
        let _ = t.open("dev", BTreeSet::new(), &r);
        assert!(r.calls.borrow().is_empty());
    }

    #[test]
    fn credential_vars_are_none() {
        assert!(PROVIDER.credential_vars().is_empty());
    }

    #[test]
    fn explain_lines_name_env_secret_and_target() {
        assert_eq!(
            target().explain("api", "DB_URL"),
            [
                ("env name", "FLEET__API__DB_URL".to_string()),
                (
                    "kubernetes secret",
                    "opv-fleet--api--db-url-<10 random characters per version>".to_string()
                ),
                (
                    "kubernetes target",
                    "deployment api in namespace myapp (context kind-opv)".to_string()
                ),
            ]
        );
    }

    // doctor ---------------------------------------------------------------------------

    fn host() -> Host {
        Host::from_env(&crate::host::FakeEnv::new("macos"))
    }

    fn ok(s: &str) -> Output {
        Output::success(s.as_bytes().to_vec())
    }

    /// kubectl version, context, cluster, then eight `auth can-i` answers.
    fn healthy() -> Vec<Output> {
        let mut v = vec![
            ok("Client Version: v1.31.2\nKustomize Version: v5.4.2\n"),
            ok("kind-opv\n"),
            ok("Client Version: v1.31.2\nServer Version: v1.31.0\n"),
        ];
        v.extend((0..8).map(|_| ok("yes\n")));
        v
    }

    /// `name: ok|warn|FAIL detail` per check.
    fn doctor_lines(r: &FakeRunner) -> Vec<String> {
        target()
            .doctor(r, &host)
            .into_iter()
            .map(|c| match c.outcome {
                Ok(Verdict::Ok(d)) => format!("{}: ok {d}", c.name),
                Ok(Verdict::Warn(d)) => format!("{}: warn {d}", c.name),
                Err(e) => format!("{}: FAIL {e}", c.name),
            })
            .collect()
    }

    #[test]
    fn doctor_lines_on_a_healthy_cluster() {
        let r = FakeRunner::new(healthy());
        assert_eq!(
            doctor_lines(&r),
            [
                "kubectl: ok version v1.31.2",
                "kubernetes context: ok context kind-opv is in your kubeconfig",
                "kubernetes cluster: ok API server for context kind-opv answers",
                "kubernetes access: ok has every right sync needs in namespace myapp",
            ]
        );
    }

    #[test]
    fn doctor_names_an_unauthorized_cluster_as_a_sign_in() {
        let r = FakeRunner::new([
            ok("Client Version: v1.31.2\nKustomize Version: v5.4.2\n"),
            ok("kind-opv\n"),
        ]);
        r.push_with_stderr(
            Output::failure(1),
            "error: You must be logged in to the server (Unauthorized)\n",
        );
        let checks = target().doctor(&r, &host);
        assert_eq!(
            checks[2].outcome.as_ref().map_err(Error::code_str).err(),
            Some("target_not_signed_in")
        );
    }

    #[test]
    fn doctor_check_names_match_the_provider_list() {
        let r = FakeRunner::new(healthy());
        let checks = target().doctor(&r, &host);
        let names: Vec<&str> = checks.iter().map(|c| c.name.as_ref()).collect();
        assert_eq!(names, PROVIDER.doctor_checks());
    }

    #[test]
    fn doctor_names_the_install_command_when_kubectl_is_missing() {
        let r = FakeRunner::default();
        r.push_io_error(std::io::ErrorKind::NotFound);
        assert_eq!(
            doctor_lines(&r)[0],
            // R56: the catalog's message; the install line is its Do.
            "kubectl: FAIL kubectl is not installed, or not on PATH"
        );
    }

    #[test]
    fn doctor_skips_cluster_checks_when_kubectl_is_missing() {
        let r = FakeRunner::default();
        r.push_io_error(std::io::ErrorKind::NotFound);
        let _ = doctor_lines(&r);
        assert_eq!(r.calls.borrow().len(), 1);
    }

    /// The doctor check `i` when kubectl answers the healthy replies up to it, then fails
    /// it with `stderr` (a recorded reply, `tests/fixtures/kubernetes/failures/`).
    fn doctor_failure(i: usize, stderr: &str) -> Error {
        let r = FakeRunner::default();
        for out in healthy().into_iter().take(i) {
            r.push_with_stderr(out, "");
        }
        r.push_with_stderr(Output::failure(1), stderr);
        target()
            .doctor(&r, &host)
            .swap_remove(i)
            .outcome
            .unwrap_err()
    }

    const CONTEXT_MISSING: &str = "error: context kind-opv not found\n";

    /// 06.26: a context missing on this machine is set up here, not renamed for everyone.
    #[test]
    fn doctor_names_a_context_missing_on_this_machine() {
        assert!(matches!(
            doctor_failure(1, CONTEXT_MISSING).cause(),
            Some((
                Cause::NotFound {
                    state: crate::cause::NotFoundState::LocalContextMissing,
                    ..
                },
                _
            ))
        ));
    }

    /// 06.26: the Do never edits the shared `kubernetes.context`.
    #[test]
    fn doctor_never_asks_to_change_the_shared_context() {
        let action = doctor_failure(1, CONTEXT_MISSING).do_text();
        assert!(!action.unwrap_or_default().contains("kubernetes.context"));
    }

    #[test]
    fn doctor_reports_an_unreachable_cluster_as_provider_unavailable() {
        let refused = "The connection to the server 127.0.0.1:9 was refused - did you specify \
                       the right host or port?\n";
        assert_eq!(
            doctor_failure(2, refused).code_str(),
            "provider_unavailable"
        );
    }

    /// 06.37: the outage text does not repeat its category.
    #[test]
    fn doctor_outage_text_names_no_category() {
        let refused = "The connection to the server 127.0.0.1:9 was refused\n";
        assert!(
            !doctor_failure(2, refused)
                .to_string()
                .contains("provider unavailable:")
        );
    }

    #[test]
    fn doctor_skips_access_when_the_cluster_is_unreachable() {
        let mut g = healthy();
        g[2] = Output::failure(1);
        let r = FakeRunner::new(g);
        assert_eq!(
            doctor_lines(&r)[3],
            "kubernetes access: warn not checked (cluster not reachable)"
        );
    }

    /// I4: every right sync needs is required; a missing one fails as the right refused.
    #[test]
    fn doctor_fails_a_missing_right_as_permission_denied() {
        let mut g = healthy();
        g[5] = Output {
            status: 1,
            stdout: zeroize::Zeroizing::new(b"no\n".to_vec()),
        };
        let r = FakeRunner::new(g);
        let checks = target().doctor(&r, &host);
        assert_eq!(
            checks[3].outcome.as_ref().map_err(Error::code_str).err(),
            Some("permission_denied")
        );
    }

    /// The `kubectl auth can-i` answers of `preflight` (Mutate): `no` for `denied`.
    fn deploy_rights(denied: &str) -> Vec<Output> {
        DEPLOY_RIGHTS
            .iter()
            .map(|(verb, resource)| {
                if format!("{verb} {resource}") == denied {
                    Output {
                        status: 1,
                        stdout: zeroize::Zeroizing::new(b"no\n".to_vec()),
                    }
                } else {
                    Output::success("yes\n")
                }
            })
            .collect()
    }

    /// I4, 06.13: sync refuses before its first write when a right only the deploy uses is
    /// missing, and only a namespace admin can grant it.
    #[test]
    fn sync_preflight_refusal_without_a_right_needs_a_person() {
        let r = FakeRunner::new(deploy_rights("list pods"));
        let e = target().preflight(&r, PreflightMode::Mutate).unwrap_err();
        assert!(e.human_required());
    }

    /// Signed in but missing a right: a person grants it; not a sign-in.
    #[test]
    fn sync_preflight_refusal_without_a_right_is_permission_denied() {
        let r = FakeRunner::new(deploy_rights("list pods"));
        let e = target().preflight(&r, PreflightMode::Mutate).unwrap_err();
        assert_eq!(e.code_str(), "permission_denied");
    }

    #[test]
    fn sync_preflight_refusal_names_the_grant() {
        let r = FakeRunner::new(deploy_rights("delete secrets"));
        let e = target().preflight(&r, PreflightMode::Mutate).unwrap_err();
        assert!(matches!(
            e.cause(),
            Some((Cause::MissingRight { grant: crate::cause::GrantModel::K8sRbac {
                verb, resource, namespace }, .. }, _))
                if verb == "delete" && resource == "secrets" && namespace.as_deref() == Some("myapp")
        ));
    }

    #[test]
    fn read_preflight_asks_for_no_rights() {
        let r = FakeRunner::default();
        target().preflight(&r, PreflightMode::Read).unwrap();
        assert!(r.calls.borrow().is_empty());
    }

    #[test]
    fn doctor_asks_only_auth_can_i_for_access() {
        let r = FakeRunner::new(healthy());
        let _ = doctor_lines(&r);
        let can_i = r
            .calls
            .borrow()
            .iter()
            .skip(3)
            .filter(|c| c.args.iter().any(|a| a == "can-i"))
            .count();
        assert_eq!(can_i, 8);
    }

    // named stores and secrets_in (FR-39) ------------------------------------------------

    const STORE: &str = r#"[stores.prod-vault]
azure_key_vault = "kv-myapp-prod"
subscription = "00000000-0000-0000-0000-000000000000"
"#;

    /// `[stores.prod-vault]`, environment `dev` with target `app` on Kubernetes (`{KEY}`)
    /// with `extra` added to its section, and keys `keys`.
    fn bound(extra: &str, keys: &str) -> String {
        crate::config::testing::bounded(&format!(
            r#"{STORE}[environments.dev]
[environments.dev.targets.app]
state_vault_id = "s"
[environments.dev.targets.app.kubernetes]
context = "kind-opv"
namespace = "myapp"
deployment = "api"
env_name = "{{KEY}}"
{extra}
{keys}"#
        ))
    }

    const DB_URL: &str =
        "[products.app.keys.DB_URL]\nkind = \"secret\"\nenvironments = [\"dev\"]\n";

    fn bound_target(extra: &str) -> KubernetesTarget {
        kube_of(&parse(&bound(extra, DB_URL)).unwrap(), "dev").clone()
    }

    #[test]
    fn secrets_in_binds_the_named_store() {
        let t = bound_target("secrets_in = \"prod-vault\"");
        assert_eq!(
            t.secrets_in().map(|s| s.describe()),
            Some("Key Vault kv-myapp-prod".into())
        );
    }

    #[test]
    fn without_secrets_in_the_target_keeps_its_own_store() {
        assert!(bound_target("").secrets_in().is_none());
    }

    #[test]
    fn bound_target_names_entries_in_the_store_spelling() {
        let t = bound_target("secrets_in = \"prod-vault\"");
        assert_eq!(t.store_name("DB_URL"), "DB-URL");
    }

    #[test]
    fn bound_store_defaults_its_cluster_secret_store_to_the_store_name() {
        let t = bound_target("secrets_in = \"prod-vault\"");
        assert_eq!(
            t.secrets_in().map(|s| s.bridge_name().to_string()),
            Some("prod-vault".into())
        );
    }

    #[test]
    fn unknown_store_lists_the_defined_ones() {
        let e = err(&bound("secrets_in = \"staging-vault\"", DB_URL));
        assert!(
            e.contains("names store staging-vault, which is not declared (declared: prod-vault)"),
            "{e}"
        );
    }

    #[test]
    fn unknown_store_points_at_the_secrets_in_line() {
        let e = err(&bound("secrets_in = \"staging-vault\"", DB_URL));
        assert!(e.contains("line 13, column 1"), "{e}");
    }

    #[test]
    fn secrets_in_that_is_not_a_string_is_refused() {
        let e = err(&bound("secrets_in = 3", DB_URL));
        assert!(
            e.contains("secrets_in must be the name of a [stores.<name>] table"),
            "{e}"
        );
    }

    fn on(section: &str, body: &str) -> String {
        crate::config::testing::bounded(&format!(
            "{STORE}[environments.dev]\n[environments.dev.targets.app]\nstate_vault_id = \"s\"\n\
             [environments.dev.targets.app.{section}]\n{body}\nsecrets_in = \"prod-vault\"\n{DB_URL}"
        ))
    }

    #[test]
    fn secrets_in_on_fly_lists_the_supported_pairs() {
        let e = err(&on("fly", "app = \"my-app\"\nsecret_name = \"{KEY}\""));
        assert!(
            e.contains(
                "(supported pairs: azure_key_vault → kubernetes (External Secrets Operator))"
            ),
            "{e}"
        );
    }

    #[test]
    fn secrets_in_on_azure_is_an_unsupported_pair() {
        let body = "subscription = \"00000000-0000-0000-0000-000000000000\"\nkey_vault = \
                    \"kv-a\"\nresource_group = \"rg\"\ncontainer_app = \"ca\"\nidentity = \"system\"\nenv_name = \"{KEY}\"";
        let e = err(&on("azure", body));
        assert!(
            e.contains("which a azure target cannot keep its secrets in"),
            "{e}"
        );
    }

    #[test]
    fn store_without_a_kind_lists_the_known_kinds() {
        let text = bound("", DB_URL).replace("azure_key_vault = \"kv-myapp-prod\"\n", "");
        assert!(err(&text).contains("names no store kind (one of azure_key_vault"));
    }

    #[test]
    fn store_name_that_is_not_a_dns_label_is_refused_at_its_line() {
        let text = bound("", DB_URL).replace("[stores.prod-vault]", "[stores.Prod_Vault]");
        let e = err(&text);
        assert!(
            e.contains("line 1") && e.contains("stores.Prod_Vault must be"),
            "{e}"
        );
    }

    #[test]
    fn key_whose_store_spelling_ends_in_a_dash_is_refused() {
        let keys = "[products.app.keys.DB_URL_]\nkind = \"secret\"\nenvironments = [\"dev\"]\n";
        let e = err(&bound("secrets_in = \"prod-vault\"", keys));
        assert!(
            e.contains("not starting and ending with a letter or digit"),
            "{e}"
        );
    }

    #[test]
    fn two_environments_sharing_a_store_and_names_are_refused() {
        let text = format!(
            "{}[environments.prod]\n\
             [environments.prod.targets.app]\nstate_vault_id = \"s2\"\n\
             [environments.prod.targets.app.kubernetes]\ncontext = \"kind-opv\"\nnamespace = \"other\"\n\
             deployment = \"api\"\nenv_name = \"{{KEY}}\"\nsecrets_in = \"prod-vault\"\n",
            bound("secrets_in = \"prod-vault\"", "")
        ) + "[products.app.keys.DB_URL]\nkind = \"secret\"\nenvironments = [\"dev\", \"prod\"]\n";
        let e = err(&crate::config::testing::bounded(&text));
        assert!(
            e.contains("keeps Key Vault name db-url for app/DB_URL in Key Vault kv-myapp-prod, where environment dev keeps it for app/DB_URL"),
            "{e}"
        );
    }

    #[test]
    fn a_long_key_that_fits_key_vault_but_not_a_kubernetes_label_is_refused() {
        let long = format!("K{}", "A".repeat(70));
        let keys =
            format!("[products.app.keys.{long}]\nkind = \"secret\"\nenvironments = [\"dev\"]\n");
        let e = err(&bound("secrets_in = \"prod-vault\"", &keys));
        assert!(
            e.contains("that is 71 characters long, over the 63 allowed"),
            "{e}"
        );
    }

    #[test]
    fn bound_target_explains_the_chain() {
        let t = bound_target("secrets_in = \"prod-vault\"");
        let chain = t
            .explain("app", "DB_URL")
            .into_iter()
            .find(|(label, _)| *label == "chain")
            .map(|(_, v)| v);
        assert_eq!(
            chain.as_deref(),
            Some(
                "DB_URL → Key Vault kv-myapp-prod (pinned version) → ExternalSecret \
                 opv-db-url-<version> → Secret of the same name → env DB_URL"
            )
        );
    }
}
