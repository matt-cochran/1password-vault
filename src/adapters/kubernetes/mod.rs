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
//! A failing call is diagnosed read-only (FR-26, K6): `kubectl config get-contexts <ctx> -o
//! name` (fails ⇒ the context is missing, [`Error::Config`]), then `kubectl --context <ctx>
//! version --request-timeout=5s` (fails ⇒ the cluster is unreachable, [`Error::Unknown`],
//! exit 9, NR-28); otherwise the step itself was refused ([`Error::Target`]).

pub mod config;
pub mod external;
pub mod runtime;
pub mod store;

#[cfg(test)]
mod converge_tests;
#[cfg(test)]
mod eso_tests;

use std::io;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::Error;
use crate::host::{Host, Tool};
use crate::runner::{
    Call, CommandRunner, Outcome, Output, PROBE_TIMEOUT, READ_TIMEOUT, WRITE_TIMEOUT, status_text,
    unknown_text,
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
};
/// The `data` key every opv Secret stores its value under.
pub const VALUE_KEY: &str = "value";
/// Ownership label: the opv environment that wrote the Secret (FR-32).
pub const LABEL_MANAGED: &str = "opv-managed";
/// The store name the Secret is a version of.
pub const LABEL_KEY: &str = "opv-key";
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

/// The store name for an env name: lower case, `_` → `-` (`FLEET__API__DB_URL` →
/// `fleet--api--db-url`). Idempotent on store names.
pub fn store_name(env_name: &str) -> String {
    env_name.to_ascii_lowercase().replace('_', "-")
}

/// A fresh version id: [`VERSION_LEN`] base32 characters from the OS RNG. It is never
/// derived from the value, so a Secret's name is no fingerprint of it (FR-38, SR-1).
pub fn new_version() -> Result<String, Error> {
    let mut bits =
        getrandom::u64().map_err(|e| {
            Error::Dependency(format!(
            "the operating system's random number generator failed ({e}); nothing was written"
        ).into())
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

/// Parse `out` as JSON; serde messages can quote input, so report the position only.
pub(crate) fn parse_json(out: &Output, what: &str) -> Result<Value, Error> {
    serde_json::from_slice(&out.stdout).map_err(|e| {
        Error::Target(
            format!(
                "{what} returned unexpected JSON (line {}, column {})",
                e.line(),
                e.column()
            )
            .into(),
        )
    })
}

/// stdout as UTF-8 text (jsonpath outputs: names and labels only).
pub(crate) fn text<'o>(out: &'o Output, what: &str) -> Result<&'o str, Error> {
    std::str::from_utf8(&out.stdout)
        .map_err(|_| Error::Target(format!("{what} returned output that is not UTF-8").into()))
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
        };
        match effect {
            Effect::Read => self.runner.read(&call, refused),
            Effect::Write => self.runner.write(&call),
        }
        .map_err(|e| spawn_error(what, &e))
    }

    /// [`Self::call`] whose every non-success is diagnosed into a typed error.
    pub fn run(
        &self,
        effect: Effect,
        what: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
        hint: &str,
    ) -> Result<Output, Error> {
        match self.call(effect, what, args, stdin, &[])? {
            Outcome::Done(out) => Ok(out),
            other => Err(self.fail(effect, what, other, hint)),
        }
    }

    /// The typed error for a call that did not succeed (NR-2, NR-28, FR-26).
    pub fn fail(&self, effect: Effect, what: &str, outcome: Outcome, hint: &str) -> Error {
        let why = match outcome {
            Outcome::Done(_) => return Error::Target(format!("{what}: unexpected success").into()),
            Outcome::Refused(out) => status_text(out.status),
            Outcome::Unknown {
                status: Some(status),
                ..
            } => status_text(status),
            Outcome::Unknown { reason, .. } => unknown_text(PROGRAM, reason),
        };
        self.diagnose(effect, what, &why, hint)
    }

    /// Read-only diagnosis of a failed step (K6): missing context ⇒ `Config`; unreachable
    /// API server ⇒ `Unknown` (exit 9, "provider unavailable", NR-28); otherwise the step
    /// itself was refused ⇒ `Target` naming the next command. A failed write whose cause
    /// cannot be told is `Unknown` (it may have been applied).
    pub fn diagnose(&self, effect: Effect, what: &str, why: &str, hint: &str) -> Error {
        // The probes explain the failed call; its excerpt stays with the error (NR-31).
        crate::runner::diagnosing(|| self.diagnose_failure(effect, what, why, hint))
    }

    fn diagnose_failure(&self, effect: Effect, what: &str, why: &str, hint: &str) -> Error {
        let t = self.target;
        let ctx = t.context.as_str();
        let contexts = ["config", "get-contexts", ctx, "-o", "name"];
        match self.probe(&contexts) {
            Err(e) => return e,
            Ok(Some(o)) if o.status != 0 => {
                return Error::Config(
                    format!(
                        "kubectl context \"{ctx}\" is not in your kubeconfig ({what} failed); \
                     nothing was changed\n  next: kubectl config get-contexts"
                    )
                    .into(),
                );
            }
            _ => {}
        }
        let version = ["--context", ctx, "version", "--request-timeout=5s"];
        let reachable = matches!(self.probe(&version), Ok(Some(o)) if o.status == 0);
        let preserved = match effect {
            Effect::Read => "nothing was changed by this step",
            Effect::Write => "the change may or may not have been applied",
        };
        if !reachable {
            return Error::Unknown(
                format!(
                    "provider unavailable: the Kubernetes API server for context \"{ctx}\" did \
                 not answer (unreachable, or your credentials for it expired); {what} failed \
                 ({why}); {preserved}\n  next: `kubectl --context {ctx} cluster-info` shows \
                 the cause; fix it, then re-run the same command"
                )
                .into(),
            );
        }
        if effect == Effect::Write && !why.starts_with("exit ") {
            return Error::Unknown(
                format!("{what}: {why}; {preserved}\n  next: re-run the same command").into(),
            );
        }
        let preserved = match effect {
            Effect::Read => preserved,
            Effect::Write => "kubectl refused the change",
        };
        Error::Target(
            format!(
                "{what} failed ({why}) for deployment {} in namespace {} (context {ctx}); \
             {preserved}\n  next: {}",
                t.deployment,
                t.namespace,
                self.command(hint)
            )
            .into(),
        )
    }

    /// A diagnosis probe; `Ok(None)` when it could not run for a reason other than a
    /// missing binary (the diagnosis then goes on without it).
    fn probe(&self, args: &[&str]) -> Result<Option<Output>, Error> {
        let call = Call {
            program: PROGRAM,
            args,
            stdin: None,
            env: PINNED_ENV,
        };
        match self.runner.probe(&call, PROBE_TIMEOUT) {
            Ok(o) => Ok(Some(o)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Err(spawn_error("kubectl", &e)),
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
            &format!("get deployment {d}"),
        )?;
        parse_json(&out, &what)
    }
}

/// `kubectl` could not be started: missing ⇒ `Dependency` with the install command.
fn spawn_error(what: &str, e: &io::Error) -> Error {
    match e.kind() {
        io::ErrorKind::NotFound => Error::Dependency(
            format!(
                "{PROGRAM} not found on PATH\n  {}",
                Host::detect().install_hint(KUBECTL)
            )
            .into(),
        ),
        io::ErrorKind::TimedOut => Error::Target(format!("{what}: {e}").into()),
        kind => Error::Target(format!("{what} could not start {PROGRAM} ({kind})").into()),
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
        let want = match &t.container {
            Some(c) => format!("has no container \"{c}\""),
            None => "has more than one container".to_string(),
        };
        Error::Config(
            format!(
                "deployment {} {want}; its containers: {}\n  next: set `container` in the \
             kubernetes section of environment {} to one of them",
                t.deployment,
                names.join(", "),
                t.env
            )
            .into(),
        )
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
    use crate::runner::fake::{FakeRunner, failed_read};

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

    /// NR-31: a refused `kubectl` read keeps its own stderr through the diagnosis probes.
    #[test]
    fn failed_read_leaves_a_kubectl_said_excerpt() {
        let r = FakeRunner::default();
        for _ in 0..crate::runner::READ_ATTEMPTS {
            r.push_with_stderr(
                Output::failure(1),
                "Error from server (Forbidden): deployments.apps \"api\" is forbidden\n",
            );
        }
        r.push_with_stderr(ok("context/kind-opv\n"), "");
        r.push_with_stderr(ok("v1.36"), "");
        let _ = kubectl_get_deployment(&r);
        assert_eq!(
            crate::runner::take_failure_excerpt().map(|x| x.render()),
            Some("  kubectl said: Error from server (Forbidden): deployments.apps \"api\" is forbidden\n".into())
        );
    }

    #[test]
    fn unreachable_cluster_before_writes_exits_9() {
        let r =
            FakeRunner::new(failed_read(1).chain([ok("context/kind-opv\n"), Output::failure(1)]));
        assert_eq!(kubectl_get_deployment(&r).unwrap_err().exit_code(), 9);
    }

    #[test]
    fn unreachable_cluster_error_says_provider_unavailable() {
        let r =
            FakeRunner::new(failed_read(1).chain([ok("context/kind-opv\n"), Output::failure(1)]));
        assert!(
            err_text(&kubectl_get_deployment(&r).unwrap_err()).contains("provider unavailable")
        );
    }

    #[test]
    fn missing_context_is_a_config_error() {
        let r = FakeRunner::new(failed_read(1).chain([Output::failure(1)]));
        assert!(matches!(
            kubectl_get_deployment(&r),
            Err(Error::Config(m)) if m.mentions("kubectl config get-contexts")
        ));
    }

    #[test]
    fn refused_read_on_reachable_cluster_names_the_next_command() {
        let r = FakeRunner::new(failed_read(1).chain([ok("context/kind-opv\n"), ok("v1.36")]));
        assert!(matches!(
            kubectl_get_deployment(&r),
            Err(Error::Target(m))
                if m.next() == Some("kubectl --context kind-opv --namespace opv-spike get deployment api")
        ));
    }

    #[test]
    fn missing_kubectl_is_a_dependency_error() {
        let r = FakeRunner::default();
        r.push_io_error(io::ErrorKind::NotFound);
        assert!(matches!(
            kubectl_get_deployment(&r),
            Err(Error::Dependency(m)) if m.starts_with("kubectl not found on PATH")
        ));
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
        assert!(matches!(
            container_index(&d, &t),
            Err(Error::Config(m)) if m.contains("its containers: agnhost")
        ));
    }
}
