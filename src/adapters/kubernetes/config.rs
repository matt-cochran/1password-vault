//! `[environments.<env>.kubernetes]` parsing, Kubernetes name rules, doctor checks and the
//! port wiring (FR-37, FR-38, `docs/design/multi-cloud-targets.md` §12).
//!
//! Every identifier is checked while the section is deserialized, so a bad value is reported
//! like any other TOML error: line, column, the line itself (FR-2).

use std::any::Any;
use std::collections::BTreeSet;
use std::fmt;

use serde::Deserialize;
use serde::de::{self, Deserializer, IgnoredAny};

use super::runtime::{POLL_EVERY, WAIT_MAX};
use super::{KUBECTL, KubeDeployment, KubeSecrets, KubeTarget, PROGRAM, valid_label_value};
use crate::adapters::probe::{spawn_tool, version_in};
use crate::domain::{AccessFinding, Profile, SIMPLE_TEMPLATE};
use crate::error::Error;
use crate::host::Host;
use crate::ports::{PinnedRuntime, Ports};
use crate::provider::{
    Check, NameRules, Preflight, PreflightMode, Provider, Section, StoreNameRules, TargetConfig,
    Verdict, eq_as,
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
    /// Env-name template; `{KEY}` under the simple profile.
    pub env_name_template: String,
    pub config: ConfigRoute,
}

/// The section as written. `E` is how `env_name` is read: a template under the fleet
/// profile, a refusal under the simple one.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw<E> {
    #[serde(deserialize_with = "context")]
    context: String,
    #[serde(deserialize_with = "namespace")]
    namespace: String,
    #[serde(deserialize_with = "deployment")]
    deployment: String,
    #[serde(default, deserialize_with = "container")]
    container: Option<String>,
    #[serde(default = "none")]
    env_name: Option<E>,
    #[serde(default)]
    config: ConfigRoute,
}

fn none<E>() -> Option<E> {
    None
}

/// A fleet `env_name`: must contain `{PRODUCT}` and `{KEY}`.
struct Template(String);

impl<'de> Deserialize<'de> for Template {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let t = String::deserialize(d)?;
        if t.contains("{PRODUCT}") && t.contains("{KEY}") {
            Ok(Self(t))
        } else {
            Err(de::Error::custom(format!(
                "kubernetes.env_name {t:?} must contain {{PRODUCT}} and {{KEY}}"
            )))
        }
    }
}

/// A simple-profile `env_name`: always refused, pointing at its line.
struct Refused;

impl<'de> Deserialize<'de> for Refused {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        IgnoredAny::deserialize(d)?;
        Err(de::Error::custom(
            "kubernetes.env_name is not allowed under the simple profile (the env name is the \
             key name)",
        ))
    }
}

/// A DNS-1123 label field (namespace, Deployment, container names).
fn label<'de, D: Deserializer<'de>>(field: &str, d: D) -> Result<String, D::Error> {
    let s = String::deserialize(d)?;
    if valid_label_value(&s) {
        Ok(s)
    } else {
        Err(de::Error::custom(format!(
            "kubernetes.{field} {s:?} must be a Kubernetes name: {LABEL_PATTERN}"
        )))
    }
}

fn namespace<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    label("namespace", d)
}

fn deployment<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    label("deployment", d)
}

fn container<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    label("container", d).map(Some)
}

/// The context goes into argv: non-empty, never read as a flag, no whitespace or shell
/// metacharacters (cloud context names hold `:`, `/` and `@`, so those are allowed).
fn context<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let s = String::deserialize(d)?;
    if is_context(&s) {
        Ok(s)
    } else {
        Err(de::Error::custom(format!(
            "kubernetes.context {s:?} must be a kubeconfig context name: \
             ^[A-Za-z0-9_.:/@+][A-Za-z0-9_.:/@+-]*$ (see `kubectl config get-contexts -o name`)"
        )))
    }
}

pub(crate) fn is_context(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '/' | '@' | '+' | '-')
        })
}

impl<E> Raw<E> {
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

    fn parse(
        &self,
        section: &Section<'_>,
        profile: Profile,
    ) -> Result<Box<dyn TargetConfig>, Error> {
        let env = section.env();
        let target =
            match profile {
                Profile::Fleet => {
                    let mut raw: Raw<Template> = section.deserialize()?;
                    let Some(Template(t)) = raw.env_name.take() else {
                        return Err(Error::Config(format!(
                        "environment {env}: kubernetes.env_name is required under the fleet \
                         profile (for example \"FLEET__{{PRODUCT}}__{{KEY}}\")"
                    ).into()));
                    };
                    raw.target(env, t)
                }
                Profile::Simple => {
                    let raw: Raw<Refused> = section.deserialize()?;
                    raw.target(env, SIMPLE_TEMPLATE.into())
                }
            };
        Ok(Box::new(target))
    }

    fn doctor_checks(&self) -> &'static [&'static str] {
        &CHECKS
    }

    fn setup_hint(&self, profile: Profile) -> String {
        match profile {
            Profile::Simple => {
                "configure kubernetes.context, kubernetes.namespace and kubernetes.deployment"
                    .into()
            }
            Profile::Fleet => "configure kubernetes.context, kubernetes.namespace, \
                               kubernetes.deployment and kubernetes.env_name"
                .into(),
        }
    }

    fn init_section(&self, _name: &str, _profile: Profile) -> Option<String> {
        None
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

    /// `kubectl --context <c> --namespace <ns> <rest>`, for fix lines.
    fn command(&self, rest: &str) -> String {
        format!(
            "{PROGRAM} --context {} --namespace {} {rest}",
            self.target.context, self.target.namespace
        )
    }
}

impl TargetConfig for KubernetesTarget {
    fn provider(&self) -> &'static dyn Provider {
        &PROVIDER
    }

    fn env_name(&self, product: &str, key: &str) -> String {
        self.env_name_of(product, key)
    }

    fn store_name(&self, env_name: &str) -> String {
        super::store_name(env_name)
    }

    fn name_rules(&self) -> NameRules {
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

    fn open<'a>(
        &'a self,
        _env: &'a str,
        managed: BTreeSet<String>,
        r: &'a dyn CommandRunner,
    ) -> Result<Ports<'a>, Error> {
        // The rollout wait ends inside the run budget (NR-4), not after a fixed 600 s.
        let wait = r.remaining().unwrap_or(WAIT_MAX);
        Ok(Ports::Pinned {
            store: Box::new(KubeSecrets::new(r, &self.target, managed.clone())),
            runtime: Box::new(
                KubeDeployment::new(r, &self.target, managed)
                    .with_wait(POLL_EVERY, wait, move |d| r.pause(d, ""))
                    .with_config_in_store(self.config == ConfigRoute::Store),
            ),
        })
    }

    fn preflight(&self, _r: &dyn CommandRunner, _mode: PreflightMode) -> Result<Preflight, Error> {
        // Every kubectl failure is diagnosed per call (context, reachability, refusal).
        Ok(Preflight::default())
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
            outcome: Ok(if reachable {
                self.access_check(r)
            } else {
                Verdict::Warn("not checked (cluster not reachable)".into())
            }),
        });
        checks
    }

    fn explain(&self, product: &str, key: &str) -> Vec<(&'static str, String)> {
        let env = self.env_name_of(product, key);
        let store = super::store_name(&env);
        vec![
            ("env name", env),
            (
                "kubernetes secret",
                format!("opv-{store}-<10 hex of the value's SHA-256>"),
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
                lines.push((
                    "routing",
                    "Secret reference pinned to one version (kubernetes.config = \"store\")".into(),
                ));
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
        return Err(Error::Dependency(
            format!("{PROGRAM} version --client failed (exit {})", o.status).into(),
        ));
    }
    Ok(match version_in(&o.stdout) {
        Some(v) => Verdict::Ok(format!("version {v}")),
        None => Verdict::Ok("present, version not recognised".into()),
    })
}

impl KubernetesTarget {
    /// `kubectl config get-contexts <ctx> -o name`: the context is in the kubeconfig.
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
            Err(Error::Config(
                format!(
                    "context \"{ctx}\" is not in your kubeconfig (KUBECONFIG or ~/.kube/config); \
                 nothing was changed\n  next: kubectl config get-contexts -o name lists the \
                 contexts; set kubernetes.context in secrets.toml to one of them"
                )
                .into(),
            ))
        }
    }

    /// `kubectl --context <ctx> version --request-timeout=5s`: the API server answers.
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
            Err(Error::Unknown(
                format!(
                    "provider unavailable: the Kubernetes API server for context \"{ctx}\" did not \
                 answer (unreachable, or your credentials for it expired); nothing was \
                 changed\n  next: `kubectl --context {ctx} cluster-info` shows the cause; fix \
                 it, then re-run `opv doctor`"
                )
                .into(),
            ))
        }
    }

    /// `kubectl auth can-i` for the rights sync needs. Advisory (R6): a missing right is a
    /// warning naming the exact grant, never a failure.
    fn access_check(&self, r: &dyn CommandRunner) -> Verdict {
        let rt = KubeDeployment::new(r, &self.target, BTreeSet::new());
        match rt.check_access(&[]) {
            Ok(found) if found.is_empty() => Verdict::Ok(format!(
                "has every right sync needs in namespace {}",
                self.target.namespace
            )),
            Ok(found) => Verdict::Warn(self.access_fix(&found).to_string()),
            Err(e) => Verdict::Warn(format!("rights not checked: {e}")),
        }
    }

    fn access_fix(&self, found: &[AccessFinding]) -> AccessFix<'_> {
        AccessFix {
            target: self,
            found: found.to_vec(),
        }
    }
}

/// The missing rights and the commands that grant exactly them.
struct AccessFix<'a> {
    target: &'a KubernetesTarget,
    found: Vec<AccessFinding>,
}

impl fmt::Display for AccessFix<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reasons: Vec<&str> = self.found.iter().map(|a| a.reason.as_str()).collect();
        write!(f, "{} (advisory; sync needs it)", reasons.join("; "))?;
        f.write_str("\n  fix (as a namespace admin):")?;
        for resource in ["secrets", "deployments", "replicasets", "pods"] {
            let verbs: Vec<&str> = self
                .found
                .iter()
                .filter_map(|a| {
                    let (verb, res) = a.store_name.split_once(' ')?;
                    (res == resource).then_some(verb)
                })
                .collect();
            if verbs.is_empty() {
                continue;
            }
            let role = format!("opv-{resource}");
            write!(
                f,
                "\n    {}\n    {}",
                self.target.command(&format!(
                    "create role {role} --verb={} --resource={resource}",
                    verbs.join(",")
                )),
                self.target.command(&format!(
                    "create rolebinding {role} --role={role} --user=<your user>"
                ))
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse;
    use crate::domain::{Fleet, SIMPLE_PRODUCT};
    use crate::runner::Output;
    use crate::runner::fake::FakeRunner;

    const ENV: &str = r#"
[environments.dev]
vault_id = "v"
item_id = "i"
[environments.dev.kubernetes]
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
        format!("[profile]\nkind = \"fleet\"\n{env}{keys}")
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
            .target()
            .and_then(|t| t.as_any().downcast_ref::<KubernetesTarget>())
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
        assert_eq!(
            err(&with("\"myapp\"", "\"My_App\"")),
            "configuration error: invalid secrets.toml: TOML parse error at line 9, column 13\n  \
             |\n9 | namespace = \"My_App\"\n  |             ^^^^^^^^\nkubernetes.namespace \
             \"My_App\" must be a Kubernetes name: ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ (at most 63 \
             characters)\n"
        );
    }

    #[test]
    fn invalid_deployment_points_at_its_line() {
        let e = err(&with("\"api\"", "\"api-\""));
        assert!(e.contains("line 10, column 14"), "{e}");
    }

    #[test]
    fn invalid_container_points_at_its_line() {
        let e = err(&with("api\"\n", "api\"\ncontainer = \"-web\"\n"));
        assert!(e.contains("line 11, column 13"), "{e}");
    }

    #[test]
    fn namespace_over_63_characters_is_refused() {
        let e = err(&with("\"myapp\"", &format!("\"{}\"", "a".repeat(64))));
        assert!(e.contains("kubernetes.namespace"), "{e}");
    }

    #[test]
    fn context_with_leading_dash_points_at_its_line() {
        let e = err(&with("\"kind-opv\"", "\"--kubeconfig=/x\""));
        assert!(e.contains("line 8, column 11"), "{e}");
    }

    #[test]
    fn context_with_whitespace_is_refused() {
        let e = err(&with("\"kind-opv\"", "\"kind opv\""));
        assert!(e.contains("kubernetes.context \"kind opv\""), "{e}");
    }

    #[test]
    fn context_with_shell_metacharacter_is_refused() {
        let e = err(&with("\"kind-opv\"", "\"kind;rm\""));
        assert!(e.contains("kubernetes.context \"kind;rm\""), "{e}");
    }

    #[test]
    fn empty_context_is_refused() {
        let e = err(&with("\"kind-opv\"", "\"\""));
        assert!(e.contains("kubernetes.context \"\""), "{e}");
    }

    #[test]
    fn env_name_without_placeholders_points_at_its_line() {
        let e = err(&with("FLEET__{PRODUCT}__{KEY}", "STATIC"));
        assert!(
            e.contains("line 11, column 12") && e.contains("must contain {PRODUCT} and {KEY}"),
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
            e.contains("line 11, column 10") && e.contains("unknown variant `plain`"),
            "{e}"
        );
    }

    #[test]
    fn unknown_field_points_at_its_line() {
        let e = err(&with("api\"\n", "api\"\nreplicas = 2\n"));
        assert!(e.contains("line 11, column 1"), "{e}");
    }

    const SIMPLE: &str = r#"
[profile]
kind = "simple"
[environments.dev]
vault_id = "v"
item_id = "i"
[environments.dev.kubernetes]
context = "kind-opv"
namespace = "myapp"
deployment = "api"
[keys.JWT_KEY]
kind = "secret"
environments = ["dev"]
"#;

    #[test]
    fn simple_profile_uses_the_key_name_as_env_name() {
        let f = parse(SIMPLE).unwrap();
        assert_eq!(f.target_name("dev", SIMPLE_PRODUCT, "JWT_KEY"), "JWT_KEY");
    }

    /// A key ending in `_` renders a Kubernetes name ending in `-`: refused at load, at the
    /// key's declaration, not at sync.
    #[test]
    fn key_ending_in_underscore_is_refused_at_its_line() {
        let e = err(&SIMPLE.replace("[keys.JWT_KEY]", "[keys.JWT_KEY_]"));
        assert!(
            e.contains("JWT_KEY_ renders Kubernetes name \"jwt-key-\"")
                && e.contains("line 11, column 7"),
            "{e}"
        );
    }

    #[test]
    fn fleet_key_ending_in_underscore_is_refused_at_its_line() {
        let e = err(&doc(ENV, &KEYS.replace("DB_URL]", "DB_URL_]")));
        assert!(
            e.contains("api/DB_URL_ renders Kubernetes name \"fleet--api--db-url-\"")
                && e.contains("line 13, column 20"),
            "{e}"
        );
    }

    #[test]
    fn env_name_under_simple_profile_points_at_its_line() {
        let e = err(&SIMPLE.replace("api\"\n", "api\"\nenv_name = \"{KEY}\"\n"));
        assert!(
            e.contains("line 11, column 12")
                && e.contains("kubernetes.env_name is not allowed under the simple profile"),
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
            e.contains("both map to Kubernetes name fleet--a-b--c"),
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
            e.contains("renders Kubernetes name of 72 characters"),
            "{e}"
        );
    }

    #[test]
    fn rejects_two_environments_sharing_a_deployment_and_template() {
        let second = ENV.replace("environments.dev", "environments.stage");
        let e = err(&doc(&format!("{ENV}{second}"), KEYS));
        assert!(e.contains("both use Kubernetes deployment \"api\""), "{e}");
    }

    #[test]
    fn two_environments_on_different_namespaces_are_accepted() {
        let second = ENV
            .replace("environments.dev", "environments.stage")
            .replace("\"myapp\"", "\"myapp-stage\"");
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
                    "opv-fleet--api--db-url-<10 hex of the value's SHA-256>".to_string()
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
                Err(e) => match e.next_step() {
                    Some(n) => format!("{}: FAIL {e}\n  fix: {n}", c.name),
                    None => format!("{}: FAIL {e}", c.name),
                },
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
            "kubectl: FAIL dependency error: kubectl not found on PATH\n  install: brew install \
             kubectl"
        );
    }

    #[test]
    fn doctor_skips_cluster_checks_when_kubectl_is_missing() {
        let r = FakeRunner::default();
        r.push_io_error(std::io::ErrorKind::NotFound);
        let _ = doctor_lines(&r);
        assert_eq!(r.calls.borrow().len(), 1);
    }

    #[test]
    fn doctor_fails_a_missing_context_with_the_listing_command() {
        let mut g = healthy();
        g[1] = Output::failure(1);
        let r = FakeRunner::new(g);
        assert!(doctor_lines(&r)[1].contains("fix: kubectl config get-contexts -o name"));
    }

    #[test]
    fn doctor_reports_an_unreachable_cluster_as_provider_unavailable() {
        let mut g = healthy();
        g[2] = Output::failure(1);
        let r = FakeRunner::new(g);
        let l = &doctor_lines(&r)[2];
        assert!(
            l.contains("FAIL outcome unknown: provider unavailable"),
            "{l}"
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

    #[test]
    fn doctor_warns_a_missing_right_with_the_exact_grant() {
        let mut g = healthy();
        g[5] = Output {
            status: 1,
            stdout: zeroize::Zeroizing::new(b"no\n".to_vec()),
        };
        let r = FakeRunner::new(g);
        assert_eq!(
            doctor_lines(&r)[3],
            "kubernetes access: warn your kubectl identity cannot delete Secrets, so --prune \
             cannot remove old versions (advisory; sync needs it)\n  fix (as a namespace admin):\
             \n    kubectl --context kind-opv --namespace myapp create role opv-secrets \
             --verb=delete --resource=secrets\n    kubectl --context kind-opv --namespace myapp \
             create rolebinding opv-secrets --role=opv-secrets --user=<your user>"
        );
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
}
