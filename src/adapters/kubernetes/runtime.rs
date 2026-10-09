//! A Kubernetes Deployment as a [`PinnedRuntime`] (FR-29, FR-31, FR-33, FR-38).
//!
//! | op | argv (after the scope flags) | effect |
//! |---|---|---|
//! | `bindings` | `get deployment <d> -o json` | read |
//! | `apply` | `replace -f - -o jsonpath={.metadata.generation}` (whole Deployment on stdin, with its `resourceVersion`) | write |
//! | `await_healthy` | per poll: `get deployment`; while not rolled out, `get replicasets -o json` and `get pods -l <selector> -o jsonpath=<name, owner, waiting reasons>` | reads |
//! | `check_access` | `auth can-i <verb> <resource>` for get/create/delete/list secrets, get/update deployments, list replicasets and pods | reads |
//!
//! `apply` edits only managed env entries of the managed container: `valueFrom.secretKeyRef
//! {name: opv-<store>-<version>, key: value}` for secrets, `value` for config. Kubernetes
//! rejects the `replace` when the Deployment changed since it was read (K3), which is reported
//! as "changed while opv applied; nothing applied; safe to re-run".
//!
//! A pod that cannot start leaves the rollout "progressing" until the 600 s progress deadline
//! (K4), so `await_healthy` fails fast when a pod of the new ReplicaSet waits with
//! `CreateContainerConfigError`, `ImagePullBackOff`, `ErrImagePull` or `CrashLoopBackOff`.
//! The revision is the Deployment's `metadata.generation` after the replace.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::external::{self, Bridge, Listed, Sync, external_name, split_external_name};
use super::{
    Effect, KubeTarget, Kubectl, LABEL_MANAGED, VALUE_KEY, container_env, container_index,
    digest_hex, secret_name, secret_ref, split_secret_name, store_name, text, valid_label_value,
};
use crate::domain::{
    AccessFinding, Binding, Health, RawSpec, Revision, RuntimeChange, RuntimeSnapshot,
};
use crate::error::Error;
use crate::ports::PinnedRuntime;
use crate::runner::{CommandRunner, Outcome};

/// Time between rollout polls.
pub const POLL_EVERY: Duration = Duration::from_secs(5);
/// Longest wait for a rollout; the integration passes the remaining run budget (NR-4).
pub const WAIT_MAX: Duration = Duration::from_secs(600);
/// A progress line at least this often while waiting (NR-4).
pub const PROGRESS_EVERY: Duration = Duration::from_secs(15);
/// Pod waiting reasons that mean the new ReplicaSet will not become ready by itself (K4).
pub const STUCK_REASONS: [&str; 4] = [
    "CreateContainerConfigError",
    "ImagePullBackOff",
    "ErrImagePull",
    "CrashLoopBackOff",
];

const GENERATION_PATH: &str = "jsonpath={.metadata.generation}";
const PODS_PATH: &str = r#"jsonpath={range .items[*]}{.metadata.name}{"\t"}{.metadata.ownerReferences[0].name}{"\t"}{range .status.initContainerStatuses[*]}{.state.waiting.reason}{" "}{end}{range .status.containerStatuses[*]}{.state.waiting.reason}{" "}{end}{"\n"}{end}"#;
const REVISION_ANNOTATION: &str = "deployment.kubernetes.io/revision";

/// The operator rights opv needs, each with its fixed reason (advisory, R6).
const ACCESS: [(&str, &str, &str); 8] = [
    (
        "get",
        "secrets",
        "your kubectl identity cannot read Secrets in this namespace",
    ),
    (
        "create",
        "secrets",
        "your kubectl identity cannot create Secrets in this namespace",
    ),
    (
        "delete",
        "secrets",
        "your kubectl identity cannot delete Secrets, so --prune cannot remove old versions",
    ),
    (
        "get",
        "deployments",
        "your kubectl identity cannot read Deployments in this namespace",
    ),
    (
        "update",
        "deployments",
        "your kubectl identity cannot update Deployments, so --deploy cannot repin",
    ),
    (
        "list",
        "secrets",
        "your kubectl identity cannot list Secrets, so opv cannot find the versions it wrote",
    ),
    (
        "list",
        "replicasets",
        "your kubectl identity cannot list ReplicaSets, so --prune cannot tell which versions a rollback needs",
    ),
    (
        "list",
        "pods",
        "your kubectl identity cannot list Pods, so --deploy cannot see a stuck rollout early",
    ),
];

/// The rights opv needs on ExternalSecrets when secrets come from a named store (FR-39).
const EXTERNAL_ACCESS: [(&str, &str, &str); 4] = [
    (
        "get",
        external::RESOURCE,
        "your kubectl identity cannot read ExternalSecrets, so opv cannot tell when one is Ready",
    ),
    (
        "list",
        external::RESOURCE,
        "your kubectl identity cannot list ExternalSecrets, so opv cannot see which versions are bound",
    ),
    (
        "create",
        external::RESOURCE,
        "your kubectl identity cannot create ExternalSecrets, so sync cannot bind a new version",
    ),
    (
        "delete",
        external::RESOURCE,
        "your kubectl identity cannot delete ExternalSecrets, so superseded versions are never removed",
    ),
];

/// Time between ExternalSecret readiness polls (the operator syncs within seconds, E1).
const READY_POLL: Duration = Duration::from_secs(2);

/// The Secret each pinned name binds in opv's own Secrets mode: `opv-<store>-<version>`.
fn native_secrets(change: &RuntimeChange) -> Result<BTreeMap<String, String>, Error> {
    change
        .pin
        .iter()
        .map(|(name, (store, version))| {
            if !valid_label_value(store)
                || split_secret_name(&secret_name(store, version))
                    != Some((store.as_str(), version.as_str()))
            {
                return Err(Error::Target(
                    format!(
                        "refusing to pin {name} to an invalid Secret version; nothing applied\n  \
                     next: re-run the same command"
                    )
                    .into(),
                ));
            }
            Ok((name.clone(), secret_name(store, version)))
        })
        .collect()
}

/// The Deployment of one Kubernetes target.
pub struct KubeDeployment<'a> {
    k: Kubectl<'a>,
    /// Managed env names (from the template, FR-8).
    managed: BTreeSet<String>,
    sleep: Box<dyn Fn(Duration) + 'a>,
    note: Box<dyn Fn(&str) + 'a>,
    poll_every: Duration,
    wait_max: Duration,
    /// `kubernetes.config = "store"`: config keys are Secrets bound by reference.
    config_in_store: bool,
    /// Secrets come from a named store through ExternalSecrets (FR-39); `None`: opv's own
    /// immutable Secrets.
    external: Option<Bridge<'a>>,
}

impl<'a> KubeDeployment<'a> {
    pub fn new(
        runner: &'a dyn CommandRunner,
        target: &'a KubeTarget,
        managed: BTreeSet<String>,
    ) -> Self {
        Self {
            k: Kubectl::new(runner, target),
            managed,
            // The runner's clock and stderr: a wait never passes the run budget (NR-4).
            sleep: Box::new(move |d| runner.pause(d, "")),
            note: Box::new(move |line| runner.note(line)),
            poll_every: POLL_EVERY,
            wait_max: WAIT_MAX,
            config_in_store: false,
            external: None,
        }
    }

    /// Bind secrets from a named store through the External Secrets Operator (FR-39):
    /// pinning version V of K applies the ExternalSecret of V, waits until it is Ready,
    /// then binds its Secret.
    pub fn with_external(mut self, bridge: Bridge<'a>) -> Self {
        self.external = Some(bridge);
        self
    }

    /// Route config keys through Secrets like secret keys (`kubernetes.config = "store"`).
    pub fn with_config_in_store(mut self, yes: bool) -> Self {
        self.config_in_store = yes;
        self
    }

    /// Poll every `poll_every`, give up after `wait_max`, sleeping with `sleep` (tests pass
    /// a recorder and never sleep).
    pub fn with_wait(
        mut self,
        poll_every: Duration,
        wait_max: Duration,
        sleep: impl Fn(Duration) + 'a,
    ) -> Self {
        self.poll_every = poll_every;
        self.wait_max = wait_max;
        self.sleep = Box::new(sleep);
        self
    }

    /// Where progress lines go (the runner's stderr by default).
    pub fn with_progress(mut self, note: impl Fn(&str) + 'a) -> Self {
        self.note = Box::new(note);
        self
    }

    fn t(&self) -> &KubeTarget {
        self.k.target
    }

    /// The managed entries of the managed container's env, in order.
    fn managed_env(&self, doc: &Value) -> Result<Vec<Value>, Error> {
        let i = container_index(doc, self.t())?;
        Ok(container_env(doc, i)
            .into_iter()
            .filter(|e| self.is_managed(e))
            .collect())
    }

    fn is_managed(&self, entry: &Value) -> bool {
        entry
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|n| self.managed.contains(n))
    }

    /// SHA-256 of the canonical JSON of `spec` without the managed env entries (FR-31).
    fn fingerprint(&self, doc: &Value) -> Result<String, Error> {
        let i = container_index(doc, self.t())?;
        let mut spec = doc.get("spec").cloned().unwrap_or(Value::Null);
        if let Some(env) = spec
            .pointer_mut(&format!("/template/spec/containers/{i}/env"))
            .and_then(Value::as_array_mut)
        {
            env.retain(|e| !self.is_managed(e));
        }
        Ok(hex::encode(Sha256::digest(spec.to_string().as_bytes())))
    }

    /// The rollout state of `doc` for generation `generation`, as `kubectl rollout status` judges
    /// it: `Ok(None)` when done, `Ok(Some(state))` while waiting, `Err(state)` when failed.
    fn rollout(&self, doc: &Value, generation: u64) -> Result<Option<String>, String> {
        let num = |p: &str| doc.pointer(p).and_then(Value::as_u64).unwrap_or(0);
        if doc.pointer("/spec/paused").and_then(Value::as_bool) == Some(true) {
            return Err("it is paused (spec.paused), so no new pods start".into());
        }
        if !observed(doc, generation) {
            return Ok(Some("waiting for the new generation to be observed".into()));
        }
        let stalled = doc
            .pointer("/status/conditions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|c| {
                c.get("type").and_then(Value::as_str) == Some("Progressing")
                    && c.get("reason").and_then(Value::as_str) == Some("ProgressDeadlineExceeded")
            });
        if stalled {
            return Err("its progress deadline passed (ProgressDeadlineExceeded)".into());
        }
        let replicas = doc
            .pointer("/spec/replicas")
            .and_then(Value::as_u64)
            .unwrap_or(1);
        let updated = num("/status/updatedReplicas");
        let current = num("/status/replicas");
        let available = num("/status/availableReplicas");
        Ok(if updated < replicas {
            Some(format!("{updated} of {replicas} new replicas updated"))
        } else if current > updated {
            Some(format!(
                "{} old replicas pending termination",
                current - updated
            ))
        } else if available < updated {
            Some(format!(
                "{available} of {updated} updated replicas available"
            ))
        } else {
            None
        })
    }

    /// A pod of the new ReplicaSet waiting with a [`STUCK_REASONS`] reason, described.
    fn stuck_pod(&self, doc: &Value) -> Result<Option<String>, Error> {
        let d = self.t().deployment.as_str();
        let revision = doc
            .pointer("/metadata/annotations")
            .and_then(|a| a.get(REVISION_ANNOTATION))
            .and_then(Value::as_str);
        let what = "kubectl get replicasets";
        let out = self.k.run(
            Effect::Read,
            what,
            &["get", "replicasets", "-o", "json"],
            None,
            "get replicasets",
        )?;
        let sets = super::parse_json(&out, what)?;
        let newest = sets
            .get("items")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .find(|rs| {
                let owned = rs
                    .pointer("/metadata/ownerReferences")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .any(|o| {
                        o.get("kind").and_then(Value::as_str) == Some("Deployment")
                            && o.get("name").and_then(Value::as_str) == Some(d)
                    });
                let rev = rs
                    .pointer("/metadata/annotations")
                    .and_then(|a| a.get(REVISION_ANNOTATION))
                    .and_then(Value::as_str);
                owned && revision.is_some() && rev == revision
            })
            .and_then(|rs| rs.pointer("/metadata/name").and_then(Value::as_str));
        let Some(newest) = newest else {
            return Ok(None);
        };
        let mut args = vec!["get", "pods"];
        let selector = selector(doc);
        if let Some(sel) = &selector {
            args.extend(["-l", sel.as_str()]);
        }
        args.extend(["-o", PODS_PATH]);
        let what = "kubectl get pods";
        let out = self.k.run(Effect::Read, what, &args, None, "get pods")?;
        for line in text(&out, what)?.lines() {
            let mut cols = line.splitn(3, '\t');
            let (pod, owner, reasons) = (
                cols.next().unwrap_or(""),
                cols.next().unwrap_or(""),
                cols.next().unwrap_or(""),
            );
            if owner != newest {
                continue;
            }
            if let Some(reason) = reasons
                .split_whitespace()
                .find(|r| STUCK_REASONS.contains(r))
            {
                return Ok(Some(format!(
                    "pod {pod} of the new ReplicaSet {newest} is waiting with {reason}; the \
                     previous ReplicaSet keeps serving; nothing pruned\n  next: fix the cause \
                     (`{}`) and re-run, or roll back with `{}`",
                    self.k.command(&format!("describe pod {pod}")),
                    self.k.command(&format!("rollout undo deployment/{d}"))
                )));
            }
        }
        Ok(None)
    }

    /// Applies the ExternalSecret of every pinned version, then waits until each is Ready
    /// (its Secret exists, E1), so the Deployment never binds a missing Secret (NR-1).
    /// Returns env name → Secret name. `store` in a pin is the name in the named store.
    fn bind_external(
        &self,
        bridge: &Bridge<'_>,
        change: &RuntimeChange,
    ) -> Result<BTreeMap<String, String>, Error> {
        let t = self.t();
        let mut names = BTreeMap::new();
        for (name, (remote, version)) in &change.pin {
            let store = store_name(remote);
            let Some(es) = external_name(&store, version) else {
                return Err(Error::Target(
                    format!(
                        "refusing to pin {name} to a store version that cannot name an \
                     ExternalSecret; nothing applied\n  next: re-run the same command"
                    )
                    .into(),
                ));
            };
            let body = external::manifest(t, &es, &store, remote, version, &bridge.cluster_store);
            external::apply(&self.k, &es, &body)?;
            names.insert(name.clone(), (es, version.clone()));
        }
        for (name, (es, version)) in &names {
            self.await_synced(bridge, es, name, version)?;
        }
        Ok(names.into_iter().map(|(n, (es, _))| (n, es)).collect())
    }

    /// Polls ExternalSecret `es` until it is Ready, within the run budget (NR-4), with a
    /// progress line at least every [`PROGRESS_EVERY`]. `SecretSyncedError` fails at once
    /// with opv's own diagnosis (E3).
    fn await_synced(
        &self,
        bridge: &Bridge<'_>,
        es: &str,
        env_name: &str,
        version: &str,
    ) -> Result<(), Error> {
        let d = self.t().deployment.as_str();
        let poll = READY_POLL.min(self.poll_every);
        let mut waited = Duration::ZERO;
        let mut next_note = PROGRESS_EVERY;
        loop {
            let last =
                match external::get(&self.k, es)?
                    .as_ref()
                    .map(external::sync_state)
                {
                    None => {
                        return Err(Error::Target(format!(
                        "ExternalSecret {es} disappeared after opv applied it; deployment {d} \
                         was not changed\n  next: re-run the same command"
                    ).into()));
                    }
                    Some(Sync::Synced) => return Ok(()),
                    Some(Sync::Failed) => {
                        return Err(external::diagnose_failed(
                            &self.k, bridge, es, env_name, version,
                        ));
                    }
                    Some(Sync::Waiting(state)) => state,
                };
            if waited >= self.wait_max {
                return Err(Error::Target(format!(
                    "ExternalSecret {es} was not Ready within {} s ({last}); deployment {d} was \
                     not changed\n  next: `{}`, then run the same command again",
                    self.wait_max.as_secs(),
                    self.k
                        .command(&format!("describe {} {es}", external::RESOURCE))
                ).into()));
            }
            if waited >= next_note {
                (self.note)(&format!(
                    "waiting for ExternalSecret {es} to sync from {} ({} s): {last}",
                    bridge.describe,
                    waited.as_secs()
                ));
                next_note += PROGRESS_EVERY;
            }
            (self.sleep)(poll);
            waited += poll;
        }
    }

    fn generation(&self, out: &[u8], what: &str) -> Result<Revision, Error> {
        let s = std::str::from_utf8(out).unwrap_or("").trim();
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || s.len() > 19 {
            return Err(Error::Target(
                format!(
                    "{what} succeeded but returned no Deployment generation; the change was \
                 applied and nothing was pruned\n  next: {}",
                    self.k.command(&format!(
                        "rollout status deployment/{}",
                        self.t().deployment
                    ))
                )
                .into(),
            ));
        }
        Ok(Revision(s.to_string()))
    }
}

/// The controller has seen generation `generation` (and any later one) of `doc`. Until it
/// has, the revision annotation still names the previous ReplicaSet, so pods are not judged.
fn observed(doc: &Value, generation: u64) -> bool {
    let num = |p: &str| doc.pointer(p).and_then(Value::as_u64).unwrap_or(0);
    num("/status/observedGeneration") >= num("/metadata/generation").max(generation)
}

/// `k=v,…` from the Deployment's `spec.selector.matchLabels`, or `None` when it has none or
/// a label holds characters a selector cannot carry (NR-6).
fn selector(doc: &Value) -> Option<String> {
    let labels = doc.pointer("/spec/selector/matchLabels")?.as_object()?;
    let safe = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_./".contains(&b))
    };
    let pairs: Option<Vec<String>> = labels
        .iter()
        .map(|(k, v)| {
            let v = v.as_str()?;
            (safe(k) && safe(v)).then(|| format!("{k}={v}"))
        })
        .collect();
    pairs.filter(|p| !p.is_empty()).map(|p| p.join(","))
}

/// `kubectl auth can-i` printed "no" (possibly followed by a reason).
pub(crate) fn answered_no(stdout: &[u8]) -> bool {
    std::str::from_utf8(stdout)
        .ok()
        .and_then(|s| s.split_whitespace().next())
        == Some("no")
}

/// How one managed env entry binds its name. With `external` (the opv ExternalSecrets by
/// name, FR-39), a bound Secret is an ExternalSecret's and its version is the store version
/// the ExternalSecret pins; one whose ExternalSecret is gone shows its name's id, which no
/// store version equals, so the next deploy re-pins it.
fn binding_of(
    entry: &Value,
    env_name: &str,
    external: Option<&BTreeMap<String, Listed>>,
) -> Binding {
    if let Some(r) = secret_ref(entry) {
        let pinned = match external {
            None => split_secret_name(r).map(|(s, v)| (s.to_string(), v.to_string())),
            Some(es) => match es.get(r) {
                Some(l) => Some((l.key.clone(), l.version.clone())),
                None => split_external_name(r).map(|(s, id)| (s.to_string(), id.to_string())),
            },
        };
        return match pinned {
            Some((store, version)) if store == store_name(env_name) => Binding::Pinned {
                store_name: store,
                version,
            },
            _ => Binding::Other,
        };
    }
    if entry.get("valueFrom").is_some() {
        return Binding::Other;
    }
    let value = entry.get("value").and_then(Value::as_str).unwrap_or("");
    Binding::Plain {
        digest: digest_hex(value),
    }
}

/// Replace the entry named `name` in `env`, or append it. Later duplicates of the name are
/// dropped: Kubernetes lets the last one win, which would hide the new binding.
fn upsert(env: &mut Vec<Value>, entry: Value) {
    let name = entry.get("name").cloned();
    let same = |e: &Value| e.get("name") == name.as_ref();
    match env.iter().position(same) {
        Some(i) => {
            let mut at = 0;
            env.retain(|e| {
                let keep = at <= i || !same(e);
                at += 1;
                keep
            });
            env[i] = entry;
        }
        None => env.push(entry),
    }
}

impl PinnedRuntime for KubeDeployment<'_> {
    fn bindings(&self) -> Result<RuntimeSnapshot, Error> {
        let doc = self.k.get_deployment()?;
        let external = match &self.external {
            None => None,
            Some(_) => {
                let selector = format!("{LABEL_MANAGED}={}", self.t().env);
                Some(
                    external::list(&self.k, &selector)?
                        .into_iter()
                        .map(|l| (l.name.clone(), l))
                        .collect::<BTreeMap<_, _>>(),
                )
            }
        };
        let bindings = self
            .managed_env(&doc)?
            .iter()
            .filter_map(|e| {
                let name = e.get("name")?.as_str()?;
                Some((name.to_string(), binding_of(e, name, external.as_ref())))
            })
            .collect();
        // The revision is the generation the current spec produced (`apply` returns the
        // same), rolled out or not.
        let revision = doc
            .pointer("/metadata/generation")
            .and_then(Value::as_u64)
            .map(|g| Revision(g.to_string()));
        Ok(RuntimeSnapshot {
            bindings,
            unmanaged_fingerprint: self.fingerprint(&doc)?,
            revision,
            spec: RawSpec(doc),
        })
    }

    /// Edits the managed env entries of `snapshot`'s Deployment and replaces it with the
    /// snapshot's `resourceVersion`, so a Deployment changed since the read is never
    /// overwritten (FR-31, K3). Config values travel only in the stdin document.
    fn apply(&self, change: &RuntimeChange, snapshot: &RuntimeSnapshot) -> Result<Revision, Error> {
        let t = self.t();
        let d = t.deployment.as_str();
        let names = change
            .pin
            .keys()
            .chain(change.set.keys())
            .chain(change.unbind.iter());
        if let Some(bad) = names.clone().find(|n| !self.managed.contains(*n)) {
            return Err(Error::Target(
                format!(
                    "refusing to change env name {bad} on deployment {d}: opv manages only the \
                 names its template renders; nothing applied\n  next: run opv explain {bad}"
                )
                .into(),
            ));
        }
        let mut doc = snapshot.spec.0.clone();
        let rv =
            doc.pointer("/metadata/resourceVersion")
                .and_then(Value::as_str)
                .map(String::from)
                .ok_or_else(|| {
                    Error::Target(format!(
                    "deployment {d} has no resourceVersion; nothing applied\n  next: re-run \
                     the same command"
                ).into())
                })?;
        let i = container_index(&doc, t)?;
        let secrets = match &self.external {
            None => native_secrets(change)?,
            Some(bridge) => self.bind_external(bridge, change)?,
        };
        let mut env = container_env(&doc, i);
        env.retain(|e| {
            let n = e.get("name").and_then(Value::as_str).unwrap_or("");
            !change.unbind.iter().any(|u| u == n)
        });
        for (name, secret) in &secrets {
            upsert(
                &mut env,
                json!({"name": name, "valueFrom": {"secretKeyRef":
                    {"name": secret, "key": VALUE_KEY}}}),
            );
        }
        for (name, value) in &change.set {
            upsert(&mut env, json!({"name": name, "value": value}));
        }
        let container = doc
            .pointer_mut(&format!("/spec/template/spec/containers/{i}"))
            .and_then(Value::as_object_mut)
            .ok_or_else(|| Error::Target(format!("deployment {d} has no containers").into()))?;
        container.insert("env".into(), Value::Array(env));
        if let Some(o) = doc.as_object_mut() {
            o.remove("status");
        }
        let body = Zeroizing::new(serde_json::to_vec(&doc).unwrap_or_default());
        let what = format!("kubectl replace deployment {d}");
        let replace = ["replace", "-f", "-", "-o", GENERATION_PATH];
        let outcome = self
            .k
            .call(Effect::Write, &what, &replace, Some(&body), &[])?;
        if let Outcome::Done(out) = outcome {
            return self.generation(&out.stdout, &what);
        }
        // Reconcile by reading back (NR-2, K3); the read-back explains the failure, so the
        // replace's excerpt stays (NR-31).
        let Ok(fresh) = crate::runner::diagnosing(|| self.k.get_deployment()) else {
            return Err(self.k.fail(
                Effect::Write,
                &what,
                outcome,
                "auth can-i update deployments",
            ));
        };
        let moved = fresh
            .pointer("/metadata/resourceVersion")
            .and_then(Value::as_str)
            != Some(rv.as_str());
        if !moved {
            return Err(self.k.fail(
                Effect::Write,
                &what,
                outcome,
                "auth can-i update deployments",
            ));
        }
        if self.managed_env(&fresh)? == self.managed_env(&doc)? {
            let generation = fresh
                .pointer("/metadata/generation")
                .and_then(Value::as_u64)
                .map(|g| g.to_string())
                .unwrap_or_default();
            return self.generation(generation.as_bytes(), &what);
        }
        Err(Error::Target(
            format!(
                "deployment {d} changed while opv applied; nothing applied; safe to re-run\n  \
             next: re-run the same command"
            )
            .into(),
        ))
    }

    /// Polls the rollout of `revision` (a generation): healthy when rolled out as `kubectl
    /// rollout status` judges it; unhealthy at once when the progress deadline passed or a
    /// pod of the new ReplicaSet is stuck (K4); a timeout is an error naming the last state.
    fn await_healthy(&self, revision: &Revision) -> Result<Health, Error> {
        let d = self.t().deployment.as_str();
        let generation: u64 = revision.0.parse().map_err(|_| {
            Error::Target(
                format!(
                    "deployment {d}: revision {} is not a generation",
                    revision.0
                )
                .into(),
            )
        })?;
        let mut waited = Duration::ZERO;
        let mut next_note = PROGRESS_EVERY;
        loop {
            let doc = self.k.get_deployment()?;
            let last = match self.rollout(&doc, generation) {
                Ok(None) => return Ok(Health::Healthy),
                Err(state) => {
                    return Ok(Health::Unhealthy(format!(
                        "deployment {d} did not roll out generation {generation}: {state}; the \
                         previous ReplicaSet keeps serving; nothing pruned\n  next: {}",
                        self.k.command(&format!("rollout status deployment/{d}"))
                    )));
                }
                Ok(Some(state)) => state,
            };
            if observed(&doc, generation)
                && let Some(stuck) = self.stuck_pod(&doc)?
            {
                return Ok(Health::Unhealthy(stuck));
            }
            if waited >= self.wait_max {
                return Err(Error::Target(
                    format!(
                        "deployment {d} did not finish rolling out generation {generation} within \
                     {} s ({last}); the previous ReplicaSet keeps serving; nothing pruned\n  \
                     next: {}",
                        self.wait_max.as_secs(),
                        self.k.command(&format!("rollout status deployment/{d}"))
                    )
                    .into(),
                ));
            }
            if waited >= next_note {
                (self.note)(&format!(
                    "waiting for deployment {d} to roll out ({} s): {last}",
                    waited.as_secs()
                ));
                next_note += PROGRESS_EVERY;
            }
            (self.sleep)(self.poll_every);
            waited += self.poll_every;
        }
    }

    fn config_in_store(&self) -> bool {
        self.config_in_store
    }

    fn describe(&self) -> String {
        let t = self.t();
        format!("deployment {} in namespace {}", t.deployment, t.namespace)
    }

    fn inspect_hint(&self, _revision: &Revision) -> String {
        self.k.command(&format!(
            "rollout status deployment/{}",
            self.t().deployment
        ))
    }

    fn chain(&self, name: &str, version: &str) -> Option<String> {
        let bridge = self.external.as_ref()?;
        let es = external_name(&store_name(name), version)?;
        let id = external::external_id(version)?;
        Some(format!(
            "{name} → {} ({id}…) → ExternalSecret {es} → env {name}",
            bridge.describe
        ))
    }

    /// The operator's own rights (`kubectl auth can-i`, K5): exit 0 yes, exit 1 no. Pods
    /// need no Secret access of their own (the kubelet resolves `secretKeyRef`), so `names`
    /// do not matter; each finding names the verb and resource. Advisory only (R6).
    fn check_access(&self, _names: &[String]) -> Result<Vec<AccessFinding>, Error> {
        let mut found = Vec::new();
        let rights: Vec<(&str, &str, &str)> = match self.external {
            None => ACCESS.to_vec(),
            Some(_) => ACCESS
                .iter()
                .copied()
                .filter(|(_, resource, _)| *resource != "secrets")
                .chain(EXTERNAL_ACCESS)
                .collect(),
        };
        for (verb, resource, reason) in rights {
            let what = format!("kubectl auth can-i {verb} {resource}");
            match self.k.call(
                Effect::Read,
                &what,
                &["auth", "can-i", verb, resource],
                None,
                &[1],
            )? {
                Outcome::Done(_) => {}
                // Exit 1 with "no" is a denial (K5); exit 1 without it is a failed call
                // (an unreachable cluster also exits 1, K6), diagnosed below.
                Outcome::Refused(o) if o.status == 1 && answered_no(&o.stdout) => {
                    found.push(AccessFinding {
                        store_name: format!("{verb} {resource}"),
                        reason: reason.into(),
                    })
                }
                other => {
                    return Err(self.k.fail(
                        Effect::Read,
                        &what,
                        other,
                        &format!("auth can-i {verb} {resource}"),
                    ));
                }
            }
        }
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::super::testutil::*;
    use super::*;
    use crate::runner::Output;
    use crate::runner::fake::{FakeRunner, failed_read};

    fn with_rt<T>(r: &FakeRunner, f: impl FnOnce(&KubeDeployment) -> T) -> T {
        let (t, m) = (target(), managed());
        let rt = KubeDeployment::new(r, &t, m)
            .with_wait(POLL_EVERY, Duration::from_secs(20), |_| {})
            .with_progress(|_| {});
        f(&rt)
    }

    fn snapshot() -> RuntimeSnapshot {
        let r = FakeRunner::new([ok(DEPLOYMENT)]);
        with_rt(&r, |rt| rt.bindings()).unwrap()
    }

    fn change() -> RuntimeChange {
        let mut c = RuntimeChange {
            pin: BTreeMap::new(),
            set: BTreeMap::new(),
            unbind: vec![],
        };
        c.pin.insert(
            "FLEET__API__DB_URL".into(),
            ("fleet--api--db-url".into(), "s7aw2ylfpc".into()),
        );
        c.set.insert("LOG_LEVEL".into(), MARK.into());
        c
    }

    fn sent(r: &FakeRunner) -> Value {
        let calls = r.calls.borrow();
        serde_json::from_slice(calls[0].stdin.as_ref().unwrap()).unwrap()
    }

    fn sent_env(r: &FakeRunner) -> Value {
        sent(r)["spec"]["template"]["spec"]["containers"][0]["env"].clone()
    }

    /// The recorded Deployment mid-rollout of generation 6: one new replica not yet ready.
    fn rolling() -> Value {
        deployment_with(|d| {
            d["metadata"]["generation"] = json!(6);
            d["metadata"]["annotations"][REVISION_ANNOTATION] = json!("5");
            d["status"]["observedGeneration"] = json!(6);
            d["status"]["updatedReplicas"] = json!(1);
            d["status"]["replicas"] = json!(2);
            d["status"]["availableReplicas"] = json!(1);
        })
    }

    fn pods(lines: &str) -> Output {
        ok(lines)
    }

    #[test]
    fn bindings_reads_pinned_secret() {
        assert_eq!(
            snapshot().bindings["FLEET__API__DB_URL"],
            Binding::Pinned {
                store_name: "fleet--api--db-url".into(),
                version: "q3vz7kd2mx".into()
            }
        );
    }

    #[test]
    fn bindings_reads_config_as_digest() {
        assert_eq!(
            snapshot().bindings["LOG_LEVEL"],
            Binding::Plain {
                digest: digest_hex("opv-k8s-config-marker")
            }
        );
    }

    #[test]
    fn deployment_without_env_has_no_bindings() {
        let r = FakeRunner::new([ok(DEPLOYMENT_BEFORE)]);
        assert!(with_rt(&r, |rt| rt.bindings()).unwrap().bindings.is_empty());
    }

    #[test]
    fn bindings_lists_managed_names_only() {
        let r = FakeRunner::new([json(&deployment_with(|d| {
            d["spec"]["template"]["spec"]["containers"][0]["env"]
                .as_array_mut()
                .unwrap()
                .push(json!({"name": "UNMANAGED", "value": "x"}));
        }))]);
        let snap = with_rt(&r, |rt| rt.bindings()).unwrap();
        assert!(!snap.bindings.contains_key("UNMANAGED"));
    }

    #[test]
    fn fingerprint_ignores_managed_entries() {
        let r = FakeRunner::new([json(&deployment_with(|d| {
            d["spec"]["template"]["spec"]["containers"][0]["env"][1]["value"] = json!("other");
        }))]);
        let other = with_rt(&r, |rt| rt.bindings()).unwrap();
        assert_eq!(
            other.unmanaged_fingerprint,
            snapshot().unmanaged_fingerprint
        );
    }

    #[test]
    fn fingerprint_changes_with_unmanaged_spec() {
        let r = FakeRunner::new([json(&deployment_with(|d| {
            d["spec"]["replicas"] = json!(3);
        }))]);
        let other = with_rt(&r, |rt| rt.bindings()).unwrap();
        assert_ne!(
            other.unmanaged_fingerprint,
            snapshot().unmanaged_fingerprint
        );
    }

    #[test]
    fn apply_carries_resource_version() {
        let r = FakeRunner::new([ok("6")]);
        with_rt(&r, |rt| rt.apply(&change(), &snapshot())).unwrap();
        assert_eq!(sent(&r)["metadata"]["resourceVersion"], json!("974"));
    }

    #[test]
    fn apply_replaces_from_stdin_asking_for_the_generation() {
        let r = FakeRunner::new([ok("6")]);
        with_rt(&r, |rt| rt.apply(&change(), &snapshot())).unwrap();
        assert_eq!(
            args(&r, 0)[5..],
            [
                "replace",
                "-f",
                "-",
                "-o",
                "jsonpath={.metadata.generation}"
            ]
        );
    }

    #[test]
    fn apply_returns_the_generation_as_revision() {
        let r = FakeRunner::new([ok("6")]);
        assert_eq!(
            with_rt(&r, |rt| rt.apply(&change(), &snapshot())).unwrap(),
            Revision("6".into())
        );
    }

    #[test]
    fn apply_pins_the_secret_by_reference() {
        let r = FakeRunner::new([ok("6")]);
        with_rt(&r, |rt| rt.apply(&change(), &snapshot())).unwrap();
        assert_eq!(
            sent_env(&r)[0],
            json!({"name": "FLEET__API__DB_URL", "valueFrom": {"secretKeyRef":
                {"name": "opv-fleet--api--db-url-s7aw2ylfpc", "key": "value"}}})
        );
    }

    #[test]
    fn apply_sends_config_value_on_stdin_only() {
        let r = FakeRunner::new([ok("6")]);
        with_rt(&r, |rt| rt.apply(&change(), &snapshot())).unwrap();
        assert!(!r.argv_contains(MARK) && sent_env(&r)[1]["value"] == json!(MARK));
    }

    #[test]
    fn apply_appends_a_new_binding() {
        let mut c = change();
        c.pin
            .insert("NEW_KEY".into(), ("new-key".into(), "abcdef2345".into()));
        let r = FakeRunner::new([ok("6")]);
        with_rt(&r, |rt| rt.apply(&c, &snapshot())).unwrap();
        assert_eq!(sent_env(&r)[3]["name"], json!("NEW_KEY"));
    }

    #[test]
    fn apply_unbinds_removed_names() {
        let mut c = change();
        c.unbind.push("K7".into());
        let r = FakeRunner::new([ok("6")]);
        with_rt(&r, |rt| rt.apply(&c, &snapshot())).unwrap();
        assert_eq!(sent_env(&r).as_array().unwrap().len(), 2);
    }

    #[test]
    fn apply_refuses_to_change_an_unmanaged_name() {
        let mut c = change();
        c.set.insert("PATH".into(), "x".into());
        let r = FakeRunner::default();
        assert!(with_rt(&r, |rt| rt.apply(&c, &snapshot())).is_err());
    }

    #[test]
    fn apply_refuses_an_invalid_version() {
        let mut c = change();
        c.pin.insert("K7".into(), ("k7".into(), "../x".into()));
        let r = FakeRunner::default();
        assert!(with_rt(&r, |rt| rt.apply(&c, &snapshot())).is_err());
    }

    #[test]
    fn resource_version_conflict_is_safe_to_rerun_error() {
        let moved = deployment_with(|d| d["metadata"]["resourceVersion"] = json!("990"));
        let r = FakeRunner::new([Output::failure(1), json(&moved)]);
        let e = with_rt(&r, |rt| rt.apply(&change(), &snapshot())).unwrap_err();
        assert!(matches!(e, Error::Target(m)
            if m.contains("deployment api changed while opv applied; nothing applied; safe to re-run")));
    }

    #[test]
    fn lost_apply_that_landed_returns_the_new_generation() {
        let r = FakeRunner::default();
        r.push_unknown("lost");
        let landed = {
            let probe = FakeRunner::new([ok("6")]);
            with_rt(&probe, |rt| rt.apply(&change(), &snapshot())).unwrap();
            let mut d = sent(&probe);
            d["metadata"]["resourceVersion"] = json!("1001");
            d["metadata"]["generation"] = json!(6);
            d
        };
        r.responses.borrow_mut().push_back(Ok(json(&landed)));
        assert_eq!(
            with_rt(&r, |rt| rt.apply(&change(), &snapshot())).unwrap(),
            Revision("6".into())
        );
    }

    #[test]
    fn lost_apply_that_did_not_land_exits_9() {
        let r = FakeRunner::default();
        r.push_unknown("lost");
        r.responses.borrow_mut().extend([
            Ok(ok(DEPLOYMENT)),
            Ok(ok("context/kind-opv")),
            Ok(ok("v1.36")),
        ]);
        let e = with_rt(&r, |rt| rt.apply(&change(), &snapshot())).unwrap_err();
        assert_eq!(e.exit_code(), 9);
    }

    #[test]
    fn await_healthy_reports_healthy_when_rolled_out() {
        let r = FakeRunner::new([ok(DEPLOYMENT)]);
        assert_eq!(
            with_rt(&r, |rt| rt.await_healthy(&Revision("5".into()))).unwrap(),
            Health::Healthy
        );
    }

    #[test]
    fn await_healthy_waits_for_the_generation_to_be_observed() {
        let unseen = deployment_with(|d| d["status"]["observedGeneration"] = json!(4));
        let r = FakeRunner::new([json(&unseen), ok(DEPLOYMENT)]);
        with_rt(&r, |rt| rt.await_healthy(&Revision("5".into()))).unwrap();
        assert_eq!(r.calls.borrow().len(), 2);
    }

    /// Generation 6 written, not yet observed: the revision annotation still names the
    /// previous ReplicaSet (`5`, api-69c77668f6 in the fixture).
    fn unobserved() -> Value {
        deployment_with(|d| {
            d["metadata"]["generation"] = json!(6);
            d["metadata"]["annotations"][REVISION_ANNOTATION] = json!("5");
            d["status"]["observedGeneration"] = json!(5);
        })
    }

    #[test]
    fn await_healthy_does_not_judge_pods_before_the_new_generation_is_observed() {
        let observed = deployment_with(|d| {
            d["metadata"]["generation"] = json!(6);
            d["status"]["observedGeneration"] = json!(6);
        });
        let r = FakeRunner::new([json(&unobserved()), json(&observed)]);
        assert_eq!(
            with_rt(&r, |rt| rt.await_healthy(&Revision("6".into()))).unwrap(),
            Health::Healthy
        );
    }

    #[test]
    fn await_healthy_reports_a_paused_deployment() {
        let paused = deployment_with(|d| d["spec"]["paused"] = json!(true));
        let r = FakeRunner::new([json(&paused)]);
        assert!(matches!(
            with_rt(&r, |rt| rt.await_healthy(&Revision("5".into()))),
            Ok(Health::Unhealthy(m)) if m.contains("paused")
        ));
    }

    #[test]
    fn stuck_pod_names_the_rollback_command() {
        let r = FakeRunner::new([
            json(&rolling()),
            ok(REPLICASETS),
            pods("api-69c77668f6-x1\tapi-69c77668f6\tImagePullBackOff \n"),
        ]);
        assert!(matches!(
            with_rt(&r, |rt| rt.await_healthy(&Revision("6".into()))),
            Ok(Health::Unhealthy(m))
                if m.contains("next:") && m.contains("rollout undo deployment/api")
        ));
    }

    #[test]
    fn await_healthy_fails_fast_on_create_container_config_error() {
        let r = FakeRunner::new([
            json(&rolling()),
            ok(REPLICASETS),
            pods("api-69c77668f6-x1\tapi-69c77668f6\tCreateContainerConfigError \n"),
        ]);
        assert!(matches!(
            with_rt(&r, |rt| rt.await_healthy(&Revision("6".into()))),
            Ok(Health::Unhealthy(m)) if m.contains("CreateContainerConfigError")
        ));
    }

    #[test]
    fn await_healthy_ignores_old_replicaset_pods() {
        let r = FakeRunner::new([
            json(&rolling()),
            ok(REPLICASETS),
            pods("api-678ff74b67-x1\tapi-678ff74b67\tCrashLoopBackOff \n"),
            ok(DEPLOYMENT),
        ]);
        assert_eq!(
            with_rt(&r, |rt| rt.await_healthy(&Revision("5".into()))).unwrap(),
            Health::Healthy
        );
    }

    #[test]
    fn await_healthy_selects_pods_by_the_deployment_selector() {
        let r = FakeRunner::new([json(&rolling()), ok(REPLICASETS), pods(""), ok(DEPLOYMENT)]);
        with_rt(&r, |rt| rt.await_healthy(&Revision("5".into()))).unwrap();
        assert_eq!(args(&r, 2)[5..9], ["get", "pods", "-l", "app=api"]);
    }

    #[test]
    fn await_healthy_reports_progress_deadline_exceeded() {
        let stalled = deployment_with(|d| {
            d["status"]["conditions"][1]["reason"] = json!("ProgressDeadlineExceeded");
            d["status"]["updatedReplicas"] = json!(0);
        });
        let r = FakeRunner::new([json(&stalled)]);
        assert!(matches!(
            with_rt(&r, |rt| rt.await_healthy(&Revision("5".into()))),
            Ok(Health::Unhealthy(m)) if m.contains("ProgressDeadlineExceeded")
        ));
    }

    #[test]
    fn await_healthy_sleeps_the_poll_interval_between_reads() {
        let slept = RefCell::new(Vec::new());
        let (t, m) = (target(), managed());
        let r = FakeRunner::new([json(&rolling()), ok(REPLICASETS), pods(""), ok(DEPLOYMENT)]);
        KubeDeployment::new(&r, &t, m)
            .with_wait(POLL_EVERY, WAIT_MAX, |d| slept.borrow_mut().push(d))
            .with_progress(|_| {})
            .await_healthy(&Revision("5".into()))
            .unwrap();
        assert_eq!(*slept.borrow(), [POLL_EVERY]);
    }

    #[test]
    fn await_healthy_times_out_naming_the_rollout_command() {
        let r = FakeRunner::default();
        for _ in 0..5 {
            r.responses.borrow_mut().extend([
                Ok(json(&rolling())),
                Ok(ok(REPLICASETS)),
                Ok(pods("")),
            ]);
        }
        let e = with_rt(&r, |rt| rt.await_healthy(&Revision("6".into()))).unwrap_err();
        assert!(matches!(e, Error::Target(m) if m.mentions("rollout status deployment/api")));
    }

    #[test]
    fn await_healthy_prints_progress_while_waiting() {
        let lines = RefCell::new(Vec::new());
        let (t, m) = (target(), managed());
        let r = FakeRunner::default();
        for _ in 0..5 {
            r.responses.borrow_mut().extend([
                Ok(json(&rolling())),
                Ok(ok(REPLICASETS)),
                Ok(pods("")),
            ]);
        }
        let _ = KubeDeployment::new(&r, &t, m)
            .with_wait(POLL_EVERY, Duration::from_secs(20), |_| {})
            .with_progress(|l| lines.borrow_mut().push(l.to_string()))
            .await_healthy(&Revision("6".into()));
        assert_eq!(lines.borrow().len(), 1);
    }

    #[test]
    fn check_access_reports_each_denied_right() {
        let r = FakeRunner::new([ok("yes"), ok("yes")]);
        r.responses.borrow_mut().push_back(Ok(Output {
            status: 1,
            stdout: zeroize::Zeroizing::new(b"no\n".to_vec()),
        }));
        r.responses
            .borrow_mut()
            .extend((0..5).map(|_| Ok(ok("yes"))));
        let found = with_rt(&r, |rt| rt.check_access(&[])).unwrap();
        assert_eq!(
            found
                .iter()
                .map(|f| f.store_name.as_str())
                .collect::<Vec<_>>(),
            ["delete secrets"]
        );
    }

    #[test]
    fn check_access_on_unreachable_cluster_exits_9() {
        // `auth can-i` exits 1 without printing "no" when the API server is down (K6).
        let r = FakeRunner::new([
            Output::failure(1),
            ok("context/kind-opv"),
            Output::failure(1),
        ]);
        assert_eq!(
            with_rt(&r, |rt| rt.check_access(&[]))
                .unwrap_err()
                .exit_code(),
            9
        );
    }

    #[test]
    fn apply_drops_later_duplicates_of_a_managed_name() {
        let doubled = deployment_with(|d| {
            d["spec"]["template"]["spec"]["containers"][0]["env"]
                .as_array_mut()
                .unwrap()
                .push(json!({"name": "LOG_LEVEL", "value": "shadow"}));
        });
        let r = FakeRunner::new([json(&doubled), ok("6")]);
        with_rt(&r, |rt| {
            let snap = rt.bindings().unwrap();
            rt.apply(&change(), &snap).unwrap();
        });
        let env = serde_json::from_slice::<Value>(r.calls.borrow()[1].stdin.as_ref().unwrap())
            .unwrap()["spec"]["template"]["spec"]["containers"][0]["env"]
            .clone();
        let count = env
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["name"] == "LOG_LEVEL")
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn check_access_asks_kubectl_auth_can_i() {
        let r = FakeRunner::new((0..8).map(|_| ok("yes")));
        with_rt(&r, |rt| rt.check_access(&[])).unwrap();
        assert_eq!(args(&r, 0)[5..], ["auth", "can-i", "get", "secrets"]);
    }

    #[test]
    fn unreachable_cluster_on_bindings_exits_9() {
        let r = FakeRunner::new(failed_read(1).chain([ok("context/kind-opv"), Output::failure(1)]));
        assert_eq!(with_rt(&r, |rt| rt.bindings()).unwrap_err().exit_code(), 9);
    }
}
