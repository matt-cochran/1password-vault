//! Kubernetes target (FR-38) wrapping `kubectl`: Secrets are the store, a Deployment is the
//! runtime. Design: `docs/design/multi-cloud-targets.md` §12; live recon that binds this
//! adapter: `docs/design/spike-k8s-findings.md` (K1–K7).
//!
//! - **Store** ([`KubeSecrets`]): one immutable Secret per value version, named
//!   `opv-<store name>-<id>` and labelled `opv-managed=<env>`, `opv-key=<store name>`; the value
//!   is base64 in `data.value`. The id is the version (FR-29): 10 random base32 characters from
//!   the OS RNG, never derived from the value, so a name, label or annotation discloses nothing
//!   about it (SR-1). Compare-before-write reads the bound value and compares it in constant
//!   time; an unchanged value writes nothing.
//! - **Runtime** ([`KubeDeployment`]): managed env entries of one container bind
//!   `valueFrom.secretKeyRef {name: <secret>, key: value}` (secrets) or `value` (config). The
//!   Deployment is written back with `replace` carrying its `resourceVersion` (FR-31, K3).
//!
//! Every call names `--context`, `--namespace` and `--request-timeout` (NR-4, NR-7) and runs
//! with `NO_COLOR=1`; `KUBECONFIG` is inherited. Values travel only inside the stdin manifest
//! (SR-3); outputs that could echo a value are never requested (`-o name` on writes, jsonpath
//! names and labels on lists, K1/K2).
//!
//! A failing call is classified by the kubectl strategy ([`diagnose`], design §5) from what
//! the runner observed and kubectl's reply; only when it cannot tell, `kubectl --context
//! <ctx> version --request-timeout=5s` (read-only, FR-26, K6) says whether the API server
//! answers at all.

pub mod config;
pub mod diagnose;
pub mod external;
pub mod files;
pub mod runtime;
pub mod store;

#[cfg(test)]
mod converge_tests;
#[cfg(test)]
mod eso_tests;

use std::io;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::cause::{
    Cause, DiagnoseContext, DottedPath, EnvName, ExitClass, GrantModel, NamedBy, Observed,
    ResourceKind, ResourceName, ResourceRef, System, Unanswered, Upstream,
};
use crate::error::Error;
use crate::host::{Host, Tool};
use crate::runner::{
    Call, CommandRunner, Outcome, Output, PROBE_TIMEOUT, READ_TIMEOUT, WRITE_TIMEOUT,
};

pub use config::{ConfigRoute, KubernetesTarget, PROVIDER};
pub use runtime::KubeDeployment;
pub use store::KubeSecrets;

/// The Kubernetes CLI binary.
pub const PROGRAM: &str = "kubectl";

/// The Kubernetes CLI and how to install it (FR-26).
pub const KUBECTL: Tool = Tool {
    program: PROGRAM,
    ci: "install kubectl in the CI job (GitHub Actions: uses: azure/setup-kubectl)",
    macos: "install: brew install kubectl",
    windows: "install: winget install -e --id Kubernetes.kubectl",
    linux: "install kubectl from https://kubernetes.io/docs/tasks/tools/ \
            (the official instructions for this Linux distribution)",
    vendor: "the Kubernetes cluster",
    status_page: "your cluster provider's status page",
    pinned_env: PINNED_ENV,
    // The API's `NotFound` reason.
    not_found: &["(NotFound)"],
    // kubectl's words for a 401 from the API server (expired or missing credentials).
    signed_out: &["You must be logged in to the server", "(Unauthorized)"],
    aliases: &[],
    version_args: &["version", "--client"],
};
/// The `data` key every opv Secret stores its value under.
pub const VALUE_KEY: &str = "value";
/// Ownership label: the opv environment that wrote the Secret (FR-32).
pub const LABEL_MANAGED: &str = "opv-managed";
/// The store name the Secret is a version of.
pub const LABEL_KEY: &str = "opv-key";
/// opv's provenance stamp as an annotations object (FR-42): names, a version, a UTC time
/// and a plan id, never a value.
pub fn annotations(stamp: &crate::domain::Stamp) -> Value {
    Value::Object(
        stamp
            .pairs()
            .iter()
            .map(|(k, v)| ((*k).to_string(), Value::String((*v).to_string())))
            .collect(),
    )
}

/// Characters of the random version id in a Secret name.
pub const VERSION_LEN: usize = 10;
/// Alphabet of version ids: lower-case RFC 4648 base32 (5 bits per character, 50 in all).
const ID_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
/// Environment every call runs with (NR-7); `KUBECONFIG` is inherited untouched.
const PINNED_ENV: &[(&str, &str)] = &[("NO_COLOR", "1")];

/// One configured Kubernetes target, as the integration step builds it from config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubeTarget {
    /// kubeconfig context, passed as `--context` on every call.
    pub context: String,
    /// Namespace, passed as `--namespace` on every call.
    pub namespace: String,
    /// The Deployment opv binds env entries on.
    pub deployment: String,
    /// The container whose env opv manages; optional when the pod has one container.
    pub container: Option<String>,
    /// The opv environment name: the `opv-managed` label value.
    pub env: String,
}

impl KubeTarget {
    /// The Deployment opv binds, as a catalog subject. Its scope is the namespace's name,
    /// which a step passes to `kubectl --namespace` as it is (never display words).
    pub(crate) fn deployment_ref(&self) -> ResourceRef {
        ResourceRef {
            kind: ResourceKind::Deployment,
            name: ResourceName::new(self.deployment.clone()),
            scope: Some(self.namespace.clone()),
        }
    }

    /// The ExternalSecret `name` in this target's namespace, as a catalog subject.
    pub(crate) fn external_ref(&self, name: &str) -> ResourceRef {
        ResourceRef {
            kind: ResourceKind::ExternalStore,
            name: ResourceName::new(name),
            scope: Some(self.namespace.clone()),
        }
    }

    /// The namespace (where opv's Secrets live), as a catalog subject.
    pub(crate) fn namespace_ref(&self) -> ResourceRef {
        ResourceRef {
            kind: ResourceKind::Namespace,
            name: ResourceName::new(self.namespace.clone()),
            scope: Some(format!("context {}", self.context)),
        }
    }
}

/// The configuration field (`kubernetes.<field>`) that names a resource.
fn field(name: &str) -> NamedBy {
    NamedBy::ConfigField {
        path: DottedPath(vec!["kubernetes".into(), name.into()]),
    }
}

/// A failed kubectl call as the kubectl strategy ([`diagnose::diagnose`]) classified it:
/// the cause, what the runner observed, and the call's scrubbed reply for the evidence box.
pub(crate) struct Failed {
    pub cause: Cause,
    pub seen: Observed,
    said: Vec<String>,
    truncated: bool,
}

impl Failed {
    /// Classify the kubectl call that just failed on this thread (made for environment
    /// `env`). Phrases match the call's reply; it leaves opv only through the scrubbed
    /// evidence box, never in opv's own words (SR-1).
    pub(crate) fn take(env: &str, effect: Effect) -> Result<Failed, Error> {
        // A runner that reported the call unanswered without observing it (an in-memory
        // double) has it recorded as lost: its outcome is only unknown (NR-2).
        let Some(failed) =
            crate::runner::take_failure().or_else(|| crate::host::lost_call(PROGRAM))
        else {
            return Err(Cause::Bug {
                site: "kubernetes: a failed kubectl call left no observation",
            }
            .into());
        };
        let ctx = DiagnoseContext {
            env: Some(EnvName::new(env)),
            write: effect == Effect::Write,
            ..Default::default()
        };
        let cause = diagnose::diagnose(failed.seen.clone(), failed.stderr(), &ctx);
        let (said, truncated) = crate::scrub::Excerpt::parts(failed.excerpt);
        Ok(Failed {
            cause,
            seen: failed.seen,
            said,
            truncated,
        })
    }

    /// Name the target's own subjects: a missing namespace or Deployment points at the
    /// configuration field that names it (`kubernetes.namespace`, `kubernetes.deployment`),
    /// and a write's unknown outcome is about `about`.
    pub(crate) fn name_subjects(&mut self, t: &KubeTarget, about: ResourceRef) {
        match &mut self.cause {
            Cause::NotFound {
                resource, named_by, ..
            } => match resource.kind {
                ResourceKind::Namespace => {
                    *named_by = field("namespace");
                    resource.scope = Some(format!("context {}", t.context));
                }
                ResourceKind::Deployment => {
                    *named_by = field("deployment");
                    resource.scope = Some(t.namespace.clone());
                }
                ResourceKind::KubeContext => *named_by = field("context"),
                _ => {}
            },
            Cause::WriteOutcomeUnknown { subject, .. } => *subject = about,
            // The refused right is on this target's Deployment or in its namespace; `auth
            // can-i` answers "no" without naming the namespace it asked about.
            Cause::MissingRight {
                resource,
                grant:
                    GrantModel::K8sRbac {
                        resource: kind,
                        namespace,
                        ..
                    },
                ..
            } => {
                namespace.get_or_insert_with(|| t.namespace.clone());
                *resource = if kind.starts_with("deployments") {
                    t.deployment_ref()
                } else {
                    t.namespace_ref()
                };
            }
            _ => {}
        }
    }

    /// The error, with kubectl's reply as untrusted evidence when it wrote one.
    pub(crate) fn into_error(self) -> Error {
        if self.said.is_empty() {
            return self.cause.into();
        }
        let up = Upstream {
            source: System::Kubernetes,
            tool: PROGRAM.to_string(),
            version: None,
            exit: self.seen.exit(),
            said: self.said,
            truncated: self.truncated,
            removed_advice: false,
            untrusted: true,
        };
        Error::with_evidence(self.cause, up)
    }
}

/// The store name for an env name: lower case, `_` → `-` (`FLEET__API__DB_URL` →
/// `fleet--api--db-url`). Idempotent on store names.
pub fn store_name(env_name: &str) -> String {
    env_name.to_ascii_lowercase().replace('_', "-")
}

/// A fresh version id: [`VERSION_LEN`] base32 characters from the OS RNG. It is never
/// derived from the value, so a Secret's name is no fingerprint of it (FR-38, SR-1).
pub fn new_version() -> Result<String, Error> {
    let mut bits = getrandom::u64().map_err(|_| {
        Error::from(Cause::LocalIo {
            op: crate::cause::LocalOp::RandomSource,
            path: std::path::PathBuf::new(),
            io: crate::cause::IoKind::Other,
        })
    })?;
    let mut id = String::with_capacity(VERSION_LEN);
    for _ in 0..VERSION_LEN {
        id.push(char::from(ID_ALPHABET[(bits & 31) as usize]));
        bits >>= 5;
    }
    Ok(id)
}

/// The Secret holding version `version` of `store`: `opv-<store>-<version>`.
pub fn secret_name(store: &str, version: &str) -> String {
    format!("opv-{store}-{version}")
}

/// `(store, version)` of an opv Secret name, or `None` when `name` is not one (NR-6).
pub fn split_secret_name(name: &str) -> Option<(&str, &str)> {
    let rest = name.strip_prefix("opv-")?;
    let cut = rest.len().checked_sub(VERSION_LEN + 1)?;
    let (store, tail) = rest.split_at(cut);
    let version = tail.strip_prefix('-')?;
    let id = version.bytes().all(|b| ID_ALPHABET.contains(&b));
    (id && valid_label_value(store)).then_some((store, version))
}

/// A DNS-1123 label: 1–63 of `a-z0-9-`, starting and ending alphanumeric. Store names must
/// be one, as they are both a label value and part of a Secret name.
pub fn valid_label_value(s: &str) -> bool {
    let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let bytes = s.as_bytes();
    (1..=63).contains(&bytes.len())
        && bytes.iter().all(|&b| alnum(b) || b == b'-')
        && alnum(bytes[0])
        && alnum(bytes[bytes.len() - 1])
}

/// Hex SHA-256 of a plain env value, for [`crate::domain::Binding::Plain`].
pub(crate) fn digest_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// Parse `out` as JSON (`what`: the kubectl call's words); a reply opv cannot read is
/// `UnexpectedOutput` at its position (serde messages can quote input, so never them).
pub(crate) fn parse_json(out: &Output, what: &str) -> Result<Value, Error> {
    serde_json::from_slice(&out.stdout).map_err(|e| {
        let at = crate::cause::Location {
            line: u32::try_from(e.line()).unwrap_or(u32::MAX),
            col: u32::try_from(e.column()).unwrap_or(u32::MAX),
        };
        unusable_reply(
            what,
            Some(at),
            crate::cause::OutputProblem::Unparseable,
            crate::cause::During::Read,
        )
    })
}

/// stdout as UTF-8 text (jsonpath outputs: names and labels only).
pub(crate) fn text<'o>(out: &'o Output, what: &str) -> Result<&'o str, Error> {
    std::str::from_utf8(&out.stdout).map_err(|_| {
        unusable_reply(
            what,
            None,
            crate::cause::OutputProblem::Unparseable,
            crate::cause::During::Read,
        )
    })
}

/// The kubectl call `what` (its words, `kubectl get deployment api`) answered with a reply
/// opv cannot use (A1): `UnexpectedOutput` on the runner's own observation of that call.
pub(crate) fn unusable_reply(
    what: &str,
    at: Option<crate::cause::Location>,
    problem: crate::cause::OutputProblem,
    during: crate::cause::During,
) -> Error {
    unusable(what, |seen| Cause::UnexpectedOutput {
        system: System::Kubernetes,
        at,
        problem,
        during,
        seen,
    })
}

/// `cause` built on the runner's own observation of the kubectl call `what`, which answered
/// (design §4.6, A1).
pub(crate) fn unusable(what: &str, cause: impl FnOnce(Observed) -> Cause) -> Error {
    let words: Vec<&str> = what
        .split_whitespace()
        .skip_while(|w| *w == PROGRAM)
        .collect();
    match crate::runner::take_unusable_reply(&Call::new(PROGRAM, &words)) {
        Some(seen) => cause(seen).into(),
        None => Cause::Bug {
            site: "kubernetes: a kubectl reply the runner did not observe",
        }
        .into(),
    }
}

/// Read or write: decides retry (the runner's) and what a failure means (NR-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Effect {
    Read,
    Write,
}

/// `kubectl` scoped to one target: every call carries the target's context and namespace.
pub(crate) struct Kubectl<'a> {
    pub runner: &'a dyn CommandRunner,
    pub target: &'a KubeTarget,
}

impl<'a> Kubectl<'a> {
    pub fn new(runner: &'a dyn CommandRunner, target: &'a KubeTarget) -> Self {
        Self { runner, target }
    }

    /// `--context <c> --namespace <ns> --request-timeout=<s>s <args...>` (NR-4, NR-7).
    fn scoped(&self, effect: Effect, args: &[&str]) -> Vec<String> {
        let limit = match effect {
            Effect::Read => READ_TIMEOUT,
            Effect::Write => WRITE_TIMEOUT,
        };
        let mut argv = vec![
            "--context".to_string(),
            self.target.context.clone(),
            "--namespace".to_string(),
            self.target.namespace.clone(),
            format!("--request-timeout={}s", limit.as_secs()),
        ];
        argv.extend(args.iter().map(|a| a.to_string()));
        argv
    }

    /// The runnable command a `next:` line names: `kubectl --context c --namespace ns <rest>`.
    pub fn command(&self, rest: &str) -> String {
        format!(
            "{PROGRAM} --context {} --namespace {} {rest}",
            self.target.context, self.target.namespace
        )
    }

    /// One scoped call; only a spawn failure is an `Err` here.
    pub fn call(
        &self,
        effect: Effect,
        what: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
        refused: &[i32],
    ) -> Result<Outcome, Error> {
        let argv = self.scoped(effect, args);
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        let call = Call {
            program: PROGRAM,
            args: &argv,
            stdin,
            env: PINNED_ENV,
            limit: None,
        };
        match effect {
            Effect::Read => self.runner.read(&call, refused),
            // An apply or replace can wait on admission webhooks and a busy API server; it
            // is bounded per request by --request-timeout and as a whole by the rollout
            // write limit and the run budget (NR-4), never killed at the plain write limit.
            Effect::Write => self.runner.write(&call.rollout()),
        }
        .map_err(|e| spawn_error(self.runner, what, &e))
    }

    /// [`Self::call`] whose every non-success is diagnosed into a typed error.
    pub fn run(
        &self,
        effect: Effect,
        what: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
    ) -> Result<Output, Error> {
        match self.call(effect, what, args, stdin, &[])? {
            Outcome::Done(out) => Ok(out),
            _ => Err(self.fail(effect)),
        }
    }

    /// The typed error for the call that just did not succeed (design §5). A write's
    /// unknown outcome is about the target's namespace (where its Secrets live).
    pub fn fail(&self, effect: Effect) -> Error {
        self.explain(self.failed(effect), effect, self.target.namespace_ref())
    }

    /// Take the failed call's observation now, before a read-back that reconciles it
    /// (NR-2) makes calls of its own; [`Self::explain`] turns it into the error later.
    pub fn failed(&self, effect: Effect) -> Result<Failed, Error> {
        Failed::take(&self.target.env, effect)
    }

    /// The error for a failure taken by [`Self::failed`]. The probe explains the failed
    /// call; its reply stays with the error (NR-31).
    pub fn explain(
        &self,
        failed: Result<Failed, Error>,
        effect: Effect,
        about: ResourceRef,
    ) -> Error {
        match failed {
            Ok(f) => crate::runner::diagnosing(|| self.diagnose_failure(f, effect, about)),
            Err(e) => e,
        }
    }

    /// The kubectl strategy ([`diagnose::diagnose`]) classifies the failed call from what
    /// the runner observed and its own reply. Only when it cannot tell does opv ask the API
    /// server for its version: no answer means the server is unreachable (a read is
    /// unavailable, a write's outcome unknown).
    fn diagnose_failure(&self, mut failed: Failed, effect: Effect, about: ResourceRef) -> Error {
        if matches!(failed.cause, Cause::Unrecognized { .. })
            && matches!(failed.seen.exit(), ExitClass::Code { .. })
        {
            let version = [
                "--context",
                self.target.context.as_str(),
                "version",
                "--request-timeout=5s",
            ];
            match self.probe(&version) {
                Err(e) => return e,
                Ok(Some(o)) if o.status != 0 => {
                    let seen = failed.seen.clone();
                    failed.cause = match effect {
                        Effect::Read => Cause::Unavailable {
                            system: System::Kubernetes,
                            why: Unanswered::Network,
                            attempts: seen.attempts(),
                            seen,
                        },
                        Effect::Write => Cause::WriteOutcomeUnknown {
                            system: System::Kubernetes,
                            subject: about.clone(),
                            seen,
                        },
                    };
                }
                Ok(_) => {}
            }
        }
        failed.name_subjects(self.target, about);
        failed.into_error()
    }

    /// A diagnosis probe; `Ok(None)` when it could not run for a reason other than a
    /// missing binary (the diagnosis then goes on without it).
    fn probe(&self, args: &[&str]) -> Result<Option<Output>, Error> {
        let call = Call {
            program: PROGRAM,
            args,
            stdin: None,
            env: PINNED_ENV,
            limit: None,
        };
        match self.runner.probe(&call, PROBE_TIMEOUT) {
            Ok(o) => Ok(Some(o)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                Err(spawn_error(self.runner, "kubectl", &e))
            }
            Err(_) => Ok(None),
        }
    }

    /// The Deployment as JSON (`get deployment <d> -o json`, a read). It holds config
    /// values and Secret names only, never secret values.
    pub fn get_deployment(&self) -> Result<Value, Error> {
        let d = self.target.deployment.as_str();
        let what = format!("kubectl get deployment {d}");
        let out = self.run(
            Effect::Read,
            &what,
            &["get", "deployment", d, "-o", "json"],
            None,
        )?;
        parse_json(&out, &what)
    }
}

/// `kubectl` could not be started: missing ⇒ `Dependency` with the install command.
fn spawn_error(r: &dyn CommandRunner, _what: &str, e: &io::Error) -> Error {
    match e.kind() {
        io::ErrorKind::NotFound => {
            let host = Host::detect();
            Cause::ToolMissing {
                tool: PROGRAM.to_string(),
                platform: host.platform,
                shell: host.shell,
                ci: host.ci,
            }
            .into()
        }
        // A spent run budget: the call never started (NR-2 once a write had).
        io::ErrorKind::TimedOut => KUBECTL.budget_spent(r, e),
        kind => Cause::ToolUnusable {
            tool: PROGRAM.to_string(),
            why: crate::cause::Unusable::SpawnFailed { io: kind.into() },
        }
        .into(),
    }
}

/// Index of the managed container in `deployment`'s pod template: the configured one, or
/// the only one (R1 as for Azure).
pub(crate) fn container_index(deployment: &Value, t: &KubeTarget) -> Result<usize, Error> {
    let names: Vec<&str> = deployment
        .pointer("/spec/template/spec/containers")
        .and_then(Value::as_array)
        .map(|cs| {
            cs.iter()
                .map(|c| c.get("name").and_then(Value::as_str).unwrap_or(""))
                .collect()
        })
        .unwrap_or_default();
    let found = match &t.container {
        Some(want) => names.iter().position(|n| n == want),
        None if names.len() == 1 => Some(0),
        None => None,
    };
    found.ok_or_else(|| {
        // `kubernetes.container` must name one of the Deployment's containers (R1).
        let allowed: Vec<String> = names.iter().map(|n| n.to_string()).collect();
        let rule = match &t.container {
            Some(c) => crate::cause::FieldRule::Check {
                check: crate::cause::ConfigCheck::NotOneOf {
                    closest: match crate::app::suggest::close(c, names.iter().copied()).as_slice() {
                        [one] => Some(one.to_string()),
                        _ => None,
                    },
                    allowed,
                },
            },
            None => crate::cause::FieldRule::Missing,
        };
        Error::from(Cause::ConfigInvalid {
            source: crate::domain::model::ReadFrom::default().0,
            at: None,
            field: DottedPath(vec!["kubernetes".into(), "container".into()]),
            rule,
        })
    })
}

/// The managed container's `env` array (absent ⇒ empty).
pub(crate) fn container_env(deployment: &Value, index: usize) -> Vec<Value> {
    deployment
        .pointer(&format!("/spec/template/spec/containers/{index}/env"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// The Secret an env entry binds through `valueFrom.secretKeyRef` with key `value`.
pub(crate) fn secret_ref(entry: &Value) -> Option<&str> {
    let r = entry.pointer("/valueFrom/secretKeyRef")?;
    (r.get("key").and_then(Value::as_str) == Some(VALUE_KEY))
        .then(|| r.get("name").and_then(Value::as_str))
        .flatten()
}

#[cfg(test)]
pub(crate) mod testutil {
    //! Recorded K1 fixtures (`tests/fixtures/kubernetes/`) and fake-runner helpers.

    use std::collections::BTreeSet;

    use serde_json::Value;

    use super::KubeTarget;
    use crate::runner::Output;
    use crate::runner::fake::FakeRunner;

    pub const DEPLOYMENT: &str =
        include_str!("../../../tests/fixtures/kubernetes/deployment-get.json");
    pub const DEPLOYMENT_BEFORE: &str =
        include_str!("../../../tests/fixtures/kubernetes/deployment-get-before.json");
    pub const REPLICASETS: &str =
        include_str!("../../../tests/fixtures/kubernetes/replicaset-list.json");
    pub const SECRET_NAMES: &str =
        include_str!("../../../tests/fixtures/kubernetes/secret-names.tsv");
    /// A value no output, argv or message may ever contain.
    pub const MARK: &str = "opv-k8s-LEAKCANARY";

    /// The spike's target: context `kind-opv`, namespace `opv-spike`, Deployment `api`.
    pub fn target() -> KubeTarget {
        KubeTarget {
            context: "kind-opv".into(),
            namespace: "opv-spike".into(),
            deployment: "api".into(),
            container: None,
            env: "dev".into(),
        }
    }

    /// The managed env names of the recorded Deployment.
    pub fn managed() -> BTreeSet<String> {
        ["FLEET__API__DB_URL", "LOG_LEVEL", "K7", "NEW_KEY"]
            .into_iter()
            .map(String::from)
            .collect()
    }

    pub fn ok(s: &str) -> Output {
        Output::success(s.as_bytes().to_vec())
    }

    pub fn json(v: &Value) -> Output {
        ok(&v.to_string())
    }

    /// The recorded Deployment, edited by `f`.
    pub fn deployment_with(f: impl FnOnce(&mut Value)) -> Value {
        let mut d: Value = serde_json::from_str(DEPLOYMENT).unwrap();
        f(&mut d);
        d
    }

    /// argv (after the scope flags) of call `i`.
    pub fn args(r: &FakeRunner, i: usize) -> Vec<String> {
        r.calls.borrow()[i].args.clone()
    }

    /// Every recorded call's argv, program first, joined.
    pub fn all_argv(r: &FakeRunner) -> String {
        r.calls
            .borrow()
            .iter()
            .map(|c| format!("{} {}", c.program, c.args.join(" ")))
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn err_text(e: &crate::error::Error) -> String {
        format!("{e} {e:?}")
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::testutil::*;
    use super::*;
    use crate::runner::fake::FakeRunner;

    fn kubectl_get_deployment(r: &FakeRunner) -> Result<Value, Error> {
        let t = target();
        Kubectl::new(r, &t).get_deployment()
    }

    #[test]
    fn store_name_lower_cases_and_dashes_underscores() {
        assert_eq!(store_name("FLEET__API__DB_URL"), "fleet--api--db-url");
    }

    #[test]
    fn new_version_is_a_parseable_secret_name_suffix() {
        let v = new_version().unwrap();
        assert_eq!(
            split_secret_name(&secret_name("db-url", &v)),
            Some(("db-url", v.as_str()))
        );
    }

    #[test]
    fn new_versions_differ_between_calls() {
        assert_ne!(new_version().unwrap(), new_version().unwrap());
    }

    #[test]
    fn split_secret_name_returns_store_and_version() {
        assert_eq!(
            split_secret_name("opv-fleet--api--db-url-q3vz7kd2mx"),
            Some(("fleet--api--db-url", "q3vz7kd2mx"))
        );
    }

    #[test]
    fn split_secret_name_rejects_a_version_outside_base32() {
        assert_eq!(split_secret_name("opv-db-url-q3vz7kd2m0"), None);
    }

    #[test]
    fn label_value_rejects_leading_dash() {
        assert!(!valid_label_value("-db-url"));
    }

    #[test]
    fn every_call_names_context_and_namespace() {
        let r = FakeRunner::new([ok(DEPLOYMENT)]);
        kubectl_get_deployment(&r).unwrap();
        assert_eq!(
            args(&r, 0)[..5],
            [
                "--context",
                "kind-opv",
                "--namespace",
                "opv-spike",
                "--request-timeout=60s"
            ]
        );
    }

    #[test]
    fn every_call_runs_without_color() {
        let r = FakeRunner::new([ok(DEPLOYMENT)]);
        kubectl_get_deployment(&r).unwrap();
        assert!(
            r.calls.borrow()[0]
                .env
                .contains(&("NO_COLOR".into(), "1".into()))
        );
    }

    /// A `get deployment` that fails every attempt with `stderr` (a recorded reply,
    /// `tests/fixtures/kubernetes/failures/`), then `probes` answer the diagnosis.
    fn failing_get(stderr: &str, probes: Vec<Output>) -> Error {
        let r = FakeRunner::default();
        for _ in 0..crate::runner::READ_ATTEMPTS {
            r.push_with_stderr(Output::failure(1), stderr);
        }
        for p in probes {
            r.push_with_stderr(p, "");
        }
        kubectl_get_deployment(&r).unwrap_err()
    }

    const FORBIDDEN_GET: &str = "Error from server (Forbidden): deployments.apps \"api\" is \
        forbidden: User \"system:serviceaccount:opv-rec:opv-norbac\" cannot get resource \
        \"deployments\" in API group \"apps\" in the namespace \"opv-spike\"\n";
    const NOTFOUND_DEPLOYMENT: &str =
        "Error from server (NotFound): deployments.apps \"api\" not found\n";
    const NOTFOUND_NAMESPACE: &str =
        "Error from server (NotFound): namespaces \"opv-spike\" not found\n";
    const CONTEXT_MISSING: &str = "error: context \"kind-opv\" does not exist\n";
    const UNAUTHORIZED: &str = "error: You must be logged in to the server (Unauthorized)\n";
    const REFUSED: &str = "The connection to the server 127.0.0.1:9 was refused - did you \
        specify the right host or port?\n";

    /// NR-31: a refused `kubectl` read keeps its own reply, as untrusted evidence.
    #[test]
    fn failed_read_keeps_kubectl_reply_as_evidence() {
        let e = failing_get(FORBIDDEN_GET, vec![]);
        assert_eq!(
            e.cause().and_then(|(_, up)| up).map(|u| u.said.clone()),
            Some(vec![FORBIDDEN_GET.trim_end().to_string()])
        );
    }

    /// 06.13: a refusal on a reachable cluster names the right that is missing.
    #[test]
    fn forbidden_read_is_permission_denied() {
        assert_eq!(
            failing_get(FORBIDDEN_GET, vec![]).code_str(),
            "permission_denied"
        );
    }

    /// 06.13: only a namespace admin can grant it, so a person acts first.
    #[test]
    fn forbidden_read_needs_a_person() {
        assert!(failing_get(FORBIDDEN_GET, vec![]).human_required());
    }

    #[test]
    fn forbidden_read_names_the_verb_and_resource_to_grant() {
        assert!(matches!(
            failing_get(FORBIDDEN_GET, vec![]).cause(),
            Some((Cause::MissingRight { grant: GrantModel::K8sRbac { verb, resource, .. }, .. }, _))
                if verb == "get" && resource == "deployments"
        ));
    }

    /// 06.13: a missing Deployment points at the field that names it.
    #[test]
    fn missing_deployment_points_at_kubernetes_deployment() {
        assert!(matches!(
            failing_get(NOTFOUND_DEPLOYMENT, vec![]).cause(),
            Some((Cause::NotFound { named_by: NamedBy::ConfigField { path }, .. }, _))
                if path.to_string() == "kubernetes.deployment"
        ));
    }

    /// I4: a missing Deployment's listing step passes the namespace's name to
    /// `kubectl --namespace`, never display words ("namespace X (context Y)").
    #[test]
    fn missing_deployment_lists_the_deployments_of_the_namespace_by_name() {
        let e = failing_get(NOTFOUND_DEPLOYMENT, vec![]);
        let next = e
            .cause()
            .map(|(c, _)| c.step(&crate::cause::Invocation::default()).1);
        assert!(
            matches!(&next, Some(crate::cause::Next::Vendor(v))
                if v.args.ends_with(&["--namespace".to_string(), target().namespace])),
            "{next:?}"
        );
    }

    /// 06.13: the server names a missing namespace even for a namespaced read.
    #[test]
    fn missing_namespace_points_at_kubernetes_namespace() {
        assert!(matches!(
            failing_get(NOTFOUND_NAMESPACE, vec![]).cause(),
            Some((Cause::NotFound { named_by: NamedBy::ConfigField { path }, .. }, _))
                if path.to_string() == "kubernetes.namespace"
        ));
    }

    /// 06.26: a context missing here is fetched on this machine, not renamed for everyone.
    #[test]
    fn missing_context_is_missing_on_this_machine() {
        assert!(matches!(
            failing_get(CONTEXT_MISSING, vec![]).cause(),
            Some((
                Cause::NotFound {
                    state: crate::cause::NotFoundState::LocalContextMissing,
                    ..
                },
                _
            ))
        ));
    }

    /// A 401 is a sign-in to redo, never an outage that re-running gets past.
    #[test]
    fn unauthorized_cluster_is_a_sign_in() {
        assert_eq!(
            failing_get(UNAUTHORIZED, vec![]).code_str(),
            "target_not_signed_in"
        );
    }

    #[test]
    fn refused_connection_exits_9() {
        assert_eq!(failing_get(REFUSED, vec![]).exit_code(), 9);
    }

    #[test]
    fn refused_connection_is_coded_provider_unavailable() {
        assert_eq!(
            failing_get(REFUSED, vec![]).code_str(),
            "provider_unavailable"
        );
    }

    /// 06.37: the outage text does not repeat its category.
    #[test]
    fn outage_text_names_no_category() {
        assert!(
            !failing_get(REFUSED, vec![])
                .to_string()
                .contains("provider unavailable:")
        );
    }

    /// An unrecognised reply on a server that does not answer its version is an outage.
    #[test]
    fn unrecognised_failure_on_an_unreachable_cluster_exits_9() {
        let e = failing_get("", vec![Output::failure(1)]);
        assert_eq!(e.exit_code(), 9);
    }

    /// An unrecognised reply on a reachable cluster is shown, not guessed at.
    #[test]
    fn unrecognised_failure_on_a_reachable_cluster_is_unrecognized() {
        let e = failing_get("Error from server (Teapot): no\n", vec![ok("v1.36")]);
        assert_eq!(e.code_str(), "unrecognized_failure");
    }

    /// 06.14: a write whose cluster stopped answering may have landed: outcome unknown,
    /// never "provider unavailable" (which means nothing was changed).
    #[test]
    fn write_on_an_unreachable_cluster_is_outcome_unknown() {
        let r = FakeRunner::default();
        r.push_with_stderr(Output::failure(1), "");
        r.push_with_stderr(Output::failure(1), "");
        let t = target();
        let k = Kubectl::new(&r, &t);
        let _ = k.call(Effect::Write, "kubectl apply", &["apply"], None, &[]);
        assert_eq!(k.fail(Effect::Write).code_str(), "outcome_unknown");
    }

    #[test]
    fn missing_kubectl_is_a_dependency_error() {
        let r = FakeRunner::default();
        r.push_io_error(io::ErrorKind::NotFound);
        assert!(kubectl_get_deployment(&r).is_err_and(|e| e.code_str() == "dependency_missing"));
    }

    fn kubectl_hint(os: &str) -> String {
        Host::from_env(&crate::host::FakeEnv::new(os)).install_hint(KUBECTL)
    }

    #[test]
    fn kubectl_install_hint_on_macos_uses_brew() {
        assert_eq!(kubectl_hint("macos"), "install: brew install kubectl");
    }

    #[test]
    fn kubectl_install_hint_on_windows_uses_winget() {
        assert_eq!(
            kubectl_hint("windows"),
            "install: winget install -e --id Kubernetes.kubectl"
        );
    }

    #[test]
    fn kubectl_install_hint_on_linux_points_at_official_instructions() {
        assert!(kubectl_hint("linux").contains("https://kubernetes.io/docs/tasks/tools/"));
    }

    #[test]
    fn container_is_the_only_one_when_unset() {
        let d: Value = serde_json::from_str(DEPLOYMENT).unwrap();
        assert_eq!(container_index(&d, &target()).unwrap(), 0);
    }

    #[test]
    fn unknown_container_lists_the_containers() {
        let d: Value = serde_json::from_str(DEPLOYMENT).unwrap();
        let t = KubeTarget {
            container: Some("web".into()),
            ..target()
        };
        // `kubernetes.container` must name one of the Deployment's containers.
        assert!(matches!(
            container_index(&d, &t).map_err(|e| e.cause().map(|(c, _)| c.clone())),
            Err(Some(Cause::ConfigInvalid {
                rule: crate::cause::FieldRule::Check {
                    check: crate::cause::ConfigCheck::NotOneOf { allowed, .. }
                },
                ..
            })) if allowed == ["agnhost"]
        ));
    }
}
