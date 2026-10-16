//! Secrets from a named store bound into a Deployment through the External Secrets Operator
//! (FR-39, `docs/design/multi-cloud-targets.md` §13; live recon
//! `docs/design/spike-eso-findings.md`, E1–E5).
//!
//! For version `V` of store entry `K` opv applies one `ExternalSecret` (`external-secrets.io/v1`):
//!
//! ```yaml
//! metadata: { name: opv-<k>-<first 10 of V>, labels: { opv-managed: <env>, opv-key: <k> } }
//! spec:
//!   refreshInterval: "0"                       # fetched once: pinned (FR-29, E1)
//!   secretStoreRef: { kind: ClusterSecretStore, name: <store's secret_store> }
//!   target: { name: <same>, creationPolicy: Owner }
//!   data: [ { secretKey: value, remoteRef: { key: <K in the store>, version: V } } ]
//! ```
//!
//! `<k>` is the Kubernetes spelling of the store name (lower case). The name comes from the
//! store's version id, which is random (Key Vault), never from the value (SR-1). The
//! operator creates the Secret of the same name, owned by the ExternalSecret, so deleting
//! the ExternalSecret deletes the Secret (E4); opv never deletes those Secrets itself.
//!
//! | op | argv (after the scope flags) | effect |
//! |---|---|---|
//! | apply | `apply -f - --server-side --field-manager=opv -o name` (manifest on stdin; no value in it) | write |
//! | ready | `get externalsecrets.external-secrets.io <n> --ignore-not-found -o json` | read |
//! | list | `get externalsecrets.external-secrets.io -l <selector> -o json` | read |
//! | delete | `delete externalsecrets.external-secrets.io <names…> --ignore-not-found` | write |
//! | preflight | `get --raw /apis/external-secrets.io/v1`, `get clustersecretstores.external-secrets.io <s> --ignore-not-found -o json`, `auth can-i create externalsecrets.external-secrets.io` | reads |
//!
//! Every failure to sync is `Ready=False/SecretSyncedError` with the same message (E3), so
//! opv diagnoses it itself: does the version exist in the store (if not, re-running pins a
//! fresh one); otherwise the ClusterSecretStore or its identity is at fault (missing, not
//! Ready, naming another vault, or a credential expired or denied behind a cached Ready
//! status), which a cluster admin fixes. The operator's own text is never printed (SR-1).

use std::cell::OnceCell;
use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::store::referenced_names;
use super::{Effect, KubeTarget, Kubectl, LABEL_KEY, LABEL_MANAGED, VALUE_KEY, store_name};
use crate::cause::{Cause, ResourceKind, ResourceName, ResourceRef, StoreObject, System};
use crate::domain::SecretValue;
use crate::domain::plan::StoreEntry;
use crate::error::Error;
use crate::ports::{PinnedStore, Store};
use crate::provider::{Check, PreflightMode, Verdict};
use crate::runner::Outcome;

/// The External Secrets API opv writes (served by ESO 0.17 and later; tested with 2.11).
pub const API: &str = "external-secrets.io/v1";
/// The ExternalSecret resource, fully qualified (other CRDs share the short name).
pub const RESOURCE: &str = "externalsecrets.external-secrets.io";
/// The ClusterSecretStore resource, fully qualified.
pub const STORE_RESOURCE: &str = "clustersecretstores.external-secrets.io";
/// Characters of the store version id in an ExternalSecret name.
pub const ID_LEN: usize = 10;

/// The id part of an ExternalSecret name for store version `version`: its first
/// [`ID_LEN`] characters, which must be lower-case letters or digits (Key Vault versions
/// are 32 hex digits).
pub fn external_id(version: &str) -> Option<&str> {
    let id = version.get(..ID_LEN)?;
    id.bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        .then_some(id)
}

/// `opv-<store>-<id>`: the ExternalSecret (and Secret) of `version` of `store` (a
/// Kubernetes store name), or `None` when the version cannot name one.
pub fn external_name(store: &str, version: &str) -> Option<String> {
    let id = external_id(version)?;
    super::valid_label_value(store).then(|| format!("opv-{store}-{id}"))
}

/// `(store, id)` of an opv ExternalSecret name.
pub fn split_external_name(name: &str) -> Option<(&str, &str)> {
    let rest = name.strip_prefix("opv-")?;
    let cut = rest.len().checked_sub(ID_LEN + 1)?;
    let (store, tail) = rest.split_at(cut);
    let id = tail.strip_prefix('-')?;
    let ok = id
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    (ok && super::valid_label_value(store)).then_some((store, id))
}

/// What the Kubernetes runtime needs to bind a named store's versions (FR-39).
pub struct Bridge<'a> {
    /// The named store, for diagnosis only: does a version exist?
    pub store: Box<dyn PinnedStore + 'a>,
    /// The `ClusterSecretStore` the ExternalSecrets read through.
    pub cluster_store: String,
    /// The store in messages: `Key Vault kv-myapp-prod`.
    pub describe: String,
    /// The store's own identifier (vault name), which the ClusterSecretStore must name.
    pub locator: String,
}

/// One opv ExternalSecret as listed: names, labels and the pinned version only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub name: String,
    /// The `opv-key` label: the Kubernetes store name.
    pub key: String,
    /// `spec.data[0].remoteRef.version`.
    pub version: String,
}

/// The opv ExternalSecrets matching `selector`. ExternalSecrets hold no values (only
/// references), so `-o json` is safe here, unlike for Secrets (K2).
pub(crate) fn list(k: &Kubectl<'_>, selector: &str) -> Result<Vec<Listed>, Error> {
    let what = "kubectl get externalsecrets";
    let out = k.run(
        Effect::Read,
        what,
        &["get", RESOURCE, "-l", selector, "-o", "json"],
        None,
    )?;
    let doc = super::parse_json(&out, what)?;
    Ok(doc
        .get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|es| {
            let name = es.pointer("/metadata/name")?.as_str()?;
            let key = es.pointer("/metadata/labels")?.get(LABEL_KEY)?.as_str()?;
            let version = es.pointer("/spec/data/0/remoteRef/version")?.as_str()?;
            let (store, _) = split_external_name(name)?;
            (store == key).then(|| Listed {
                name: name.into(),
                key: key.into(),
                version: version.into(),
            })
        })
        .collect())
}

/// The ExternalSecret manifest. It carries names, a version id and opv's provenance stamp
/// (FR-42) only, never a value.
pub(crate) fn manifest(
    t: &KubeTarget,
    name: &str,
    store: &str,
    remote_key: &str,
    version: &str,
    cluster_store: &str,
    stamp: Option<&crate::domain::Stamp>,
) -> Vec<u8> {
    let mut doc = json!({
        "apiVersion": API,
        "kind": "ExternalSecret",
        "metadata": {
            "name": name,
            "namespace": t.namespace,
            "labels": { LABEL_MANAGED: t.env, LABEL_KEY: store },
        },
        "spec": {
            "refreshInterval": "0",
            "secretStoreRef": { "kind": "ClusterSecretStore", "name": cluster_store },
            "target": { "name": name, "creationPolicy": "Owner" },
            "data": [{
                "secretKey": VALUE_KEY,
                "remoteRef": { "key": remote_key, "version": version },
            }],
        },
    });
    if let Some(s) = stamp {
        doc["metadata"]["annotations"] = super::annotations(s);
    }
    doc.to_string().into_bytes()
}

/// Applies the ExternalSecret `name` (server-side, idempotent). A lost outcome is
/// reconciled by reading it back (NR-2).
pub(crate) fn apply(k: &Kubectl<'_>, name: &str, body: &[u8]) -> Result<(), Error> {
    let what = format!("kubectl apply externalsecret {name}");
    let args = [
        "apply",
        "-f",
        "-",
        "--server-side",
        "--field-manager=opv",
        "-o",
        "name",
    ];
    match k.call(Effect::Write, &what, &args, Some(body), &[])? {
        Outcome::Done(out) => {
            let echoed = super::text(&out, &what)?.trim().to_string();
            if echoed.rsplit('/').next() == Some(name) {
                Ok(())
            } else {
                // The apply answered without naming what it wrote (A1): its outcome is unknown.
                Err(super::unusable(&what, |seen| Cause::WriteOutcomeUnknown {
                    system: System::Kubernetes,
                    subject: k.target.external_ref(name),
                    seen,
                }))
            }
        }
        // The read-back explains the failure, so the apply's excerpt stays (NR-31).
        _ => {
            let failed = k.failed(Effect::Write);
            match crate::runner::diagnosing(|| get(k, name)) {
                Ok(Some(_)) => Ok(()),
                _ => Err(k.explain(failed, Effect::Write, k.target.namespace_ref())),
            }
        }
    }
}

/// The ExternalSecret `name` as JSON, `None` when it does not exist.
pub(crate) fn get(k: &Kubectl<'_>, name: &str) -> Result<Option<Value>, Error> {
    let what = format!("kubectl get externalsecret {name}");
    let out = k.run(
        Effect::Read,
        &what,
        &["get", RESOURCE, name, "--ignore-not-found", "-o", "json"],
        None,
    )?;
    if super::text(&out, &what)?.trim().is_empty() {
        return Ok(None);
    }
    super::parse_json(&out, &what).map(Some)
}

/// `(status, reason, message)` of the `Ready` condition of an External Secrets object.
pub(crate) fn ready(obj: &Value) -> Option<(String, String, String)> {
    let c = obj
        .pointer("/status/conditions")?
        .as_array()?
        .iter()
        .find(|c| c.get("type").and_then(Value::as_str) == Some("Ready"))?;
    let field = |f: &str| c.get(f).and_then(Value::as_str).unwrap_or("").to_string();
    Some((field("status"), field("reason"), field("message")))
}

/// When the operator last reported on `obj`: its `status.refreshTime` and the Ready
/// condition's `lastTransitionTime` (the operator's clock), to tell a new report from one
/// read before.
pub(crate) fn reported_at(obj: &Value) -> String {
    let refresh = obj
        .pointer("/status/refreshTime")
        .and_then(Value::as_str)
        .unwrap_or("");
    let transition = obj
        .pointer("/status/conditions")
        .and_then(Value::as_array)
        .and_then(|cs| {
            cs.iter()
                .find(|c| c.get("type").and_then(Value::as_str) == Some("Ready"))
        })
        .and_then(|c| c.get("lastTransitionTime"))
        .and_then(Value::as_str)
        .unwrap_or("");
    format!("{refresh}|{transition}")
}

/// Where an ExternalSecret stands.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Sync {
    /// `Ready=True`: the Secret exists and holds the pinned version.
    Synced,
    /// `Ready=False/SecretSyncedError` (E3): the operator could not read the version.
    Failed,
    /// Not reconciled yet; the state to show while waiting.
    Waiting(String),
}

/// The sync state of an ExternalSecret object.
pub(crate) fn sync_state(obj: &Value) -> Sync {
    match ready(obj) {
        Some((s, _, _)) if s == "True" => Sync::Synced,
        Some((_, reason, _)) if reason == "SecretSyncedError" => Sync::Failed,
        Some((s, reason, _)) => Sync::Waiting(format!("Ready={s} ({reason})")),
        None => Sync::Waiting("not reconciled yet".into()),
    }
}

/// The state of the ClusterSecretStore.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum StoreState {
    Missing,
    /// Not `Ready=True`: the condition's reason and message.
    NotReady(String),
    /// Ready; `false` when none of its provider settings names the store (a vault URL
    /// for another vault).
    Ready {
        names_store: bool,
    },
}

/// `get clustersecretstores.external-secrets.io <name>` (spec and status only; a
/// ClusterSecretStore holds references to credentials, never their values).
pub(crate) fn store_state(
    k: &Kubectl<'_>,
    cluster_store: &str,
    locator: &str,
) -> Result<StoreState, Error> {
    let what = format!("kubectl get clustersecretstore {cluster_store}");
    let out = k.run(
        Effect::Read,
        &what,
        &[
            "get",
            STORE_RESOURCE,
            cluster_store,
            "--ignore-not-found",
            "-o",
            "json",
        ],
        None,
    )?;
    if super::text(&out, &what)?.trim().is_empty() {
        return Ok(StoreState::Missing);
    }
    let doc = super::parse_json(&out, &what)?;
    Ok(match ready(&doc) {
        Some((s, _, _)) if s == "True" => {
            let mut seen = BTreeSet::new();
            if let Some(p) = doc.pointer("/spec/provider") {
                collect(p, &mut seen);
            }
            let want = locator.to_ascii_lowercase();
            StoreState::Ready {
                names_store: seen.iter().any(|s| s.to_ascii_lowercase().contains(&want)),
            }
        }
        // The condition's message is operator-written text: never echoed (06.52). Its
        // reason is a CamelCase code, kept only when it is one.
        Some((s, reason, _)) => StoreState::NotReady(match reason_code(&reason) {
            Some(r) => format!("Ready={}, reason {r}", reason_code(&s).unwrap_or("?")),
            None => format!("Ready={}", reason_code(&s).unwrap_or("?")),
        }),
        None => StoreState::NotReady("it reports no Ready condition yet".into()),
    })
}

/// `s` when it is a condition code (`True`, `InvalidProviderConfig`): letters only, at most
/// 64 characters; `None` for anything else, which is never shown.
fn reason_code(s: &str) -> Option<&str> {
    (!s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphabetic())).then_some(s)
}

/// The ClusterSecretStore `name` (or the operator itself) as the object a cluster admin
/// sets up: opv cannot fix it, so the step is a person's (06.15, 06.25, 06.52).
fn owner_setup(name: &str) -> Error {
    Cause::OwnerSetupRequired {
        system: System::Kubernetes,
        object: ResourceRef {
            kind: ResourceKind::ExternalStore,
            name: ResourceName::new(name),
            scope: None,
        },
    }
    .into()
}

/// The operator object: not installed, or too old to serve the API opv writes.
const OPERATOR: &str = "External Secrets Operator";
/// The operator object when it is installed but does not serve [`API`].
const OPERATOR_V1: &str = "External Secrets Operator serving external-secrets.io/v1";

fn collect(v: &Value, out: &mut BTreeSet<String>) {
    match v {
        Value::String(s) => {
            out.insert(s.clone());
        }
        Value::Array(a) => a.iter().for_each(|x| collect(x, out)),
        Value::Object(o) => o.values().for_each(|x| collect(x, out)),
        _ => {}
    }
}

/// The ExternalSecret could not read version `version` of `env_name`: opv's own diagnosis
/// (E3). Read-only. A store that is missing, not Ready, names another vault, or whose
/// identity the operator reports as expired, rejected or denied is fixed by a cluster
/// admin, never by opv (06.15); the operator's own text is classified, never echoed (06.52).
pub(crate) fn diagnose_failed(
    k: &Kubectl<'_>,
    bridge: &Bridge<'_>,
    es: &str,
    env_name: &str,
    version: &str,
) -> Error {
    let t = k.target;
    match bridge.store.has_version(env_name, version) {
        // The version was deleted or purged after opv wrote it; the Deployment is unchanged,
        // and re-running writes and pins a fresh version.
        Ok(Some(false)) => {
            return Cause::ChangedBeforeWrite {
                object: StoreObject::Resource {
                    resource: t.external_ref(es),
                    changed: Vec::new(),
                },
            }
            .into();
        }
        // The version could not be checked: that failure is the cause opv can name.
        Err(e) => return e,
        Ok(_) => {}
    }
    match store_state(k, &bridge.cluster_store, &bridge.locator) {
        // Every state of the store and of its credential is a cluster admin's to fix; the
        // operator's events only told opv that the store is at fault.
        Ok(_) => owner_setup(&bridge.cluster_store),
        Err(e) => e,
    }
}

/// `get --raw /apis/external-secrets.io/v1`: the operator's API is served at v1 (discovery,
/// which every signed-in identity may read). Not served: a cataloged cause naming what
/// to install or upgrade.
pub(crate) fn operator_served(k: &Kubectl<'_>) -> Result<(), Error> {
    let what = "kubectl get --raw /apis/external-secrets.io/v1";
    let path = "/apis/external-secrets.io/v1";
    match k.call(Effect::Read, what, &["get", "--raw", path], None, &[1])? {
        Outcome::Done(out) => {
            let doc = super::parse_json(&out, what)?;
            let served = doc
                .get("resources")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .any(|r| r.get("name").and_then(Value::as_str) == Some("externalsecrets"));
            if served {
                Ok(())
            } else {
                Err(not_served(false))
            }
        }
        Outcome::Refused(_) => {
            // Taken before the probes below: the refusal's own words decide.
            let failed = k.failed(Effect::Read);
            let missing = matches!(
                &failed,
                Ok(f) if matches!(f.cause, Cause::OwnerSetupRequired { .. })
            );
            let group = ["get", "--raw", "/apis/external-secrets.io"];
            let probe = || k.call(Effect::Read, what, &group, None, &[1]);
            match crate::runner::diagnosing(probe)? {
                Outcome::Done(_) => Err(not_served(true)),
                // The API server said the API is not there, or its discovery list has no
                // such group: the operator is not installed. Any other refusal (403 first
                // among them) proves nothing about the operator.
                _ if missing || group_absent(k) => Err(not_served(false)),
                _ => Err(k.explain(failed, Effect::Read, k.target.namespace_ref())),
            }
        }
        _ => Err(k.fail(Effect::Read)),
    }
}

/// True when API discovery (`get --raw /apis`, readable by every signed-in identity)
/// answers and lists no external-secrets.io group: the operator is definitely absent. An
/// unreadable list proves nothing, so it is false.
fn group_absent(k: &Kubectl<'_>) -> bool {
    let what = "kubectl get --raw /apis";
    let listed = crate::runner::diagnosing(|| {
        k.call(Effect::Read, what, &["get", "--raw", "/apis"], None, &[1])
    });
    let Ok(Outcome::Done(out)) = listed else {
        return false;
    };
    let Ok(doc) = super::parse_json(&out, what) else {
        return false;
    };
    doc.get("groups")
        .and_then(Value::as_array)
        .is_some_and(|groups| {
            !groups
                .iter()
                .any(|g| g.get("name").and_then(Value::as_str) == Some("external-secrets.io"))
        })
}

/// The operator is not installed (`old`: installed, but it does not serve [`API`]): a
/// cluster admin installs or upgrades it (06.25).
fn not_served(old: bool) -> Error {
    owner_setup(if old { OPERATOR_V1 } else { OPERATOR })
}

/// `auth can-i <verb> externalsecrets.external-secrets.io`: `Ok(None)` when allowed, else
/// the kubectl strategy's typed refusal (a missing right, naming the grant).
pub(crate) fn can_i(k: &Kubectl<'_>, verb: &str) -> Result<Option<Error>, Error> {
    let what = format!("kubectl auth can-i {verb} {RESOURCE}");
    match k.call(
        Effect::Read,
        &what,
        &["auth", "can-i", verb, RESOURCE],
        None,
        &[1],
    )? {
        Outcome::Done(_) => Ok(None),
        Outcome::Refused(o) if o.status == 1 && super::runtime::answered_no(&o.stdout) => {
            Ok(Some(k.fail(Effect::Read)))
        }
        _ => Err(k.fail(Effect::Read)),
    }
}

/// The External Secrets checks before a command touches the target (NR-23): the operator
/// serves v1, the ClusterSecretStore exists and is Ready, and this identity may create
/// ExternalSecrets. Under [`PreflightMode::Mutate`] each failure refuses before any write;
/// under [`PreflightMode::Read`] a store that is not Ready or a missing right is a warning.
pub(crate) fn preflight(
    k: &Kubectl<'_>,
    cluster_store: &str,
    locator: &str,
    describe: &str,
    mode: PreflightMode,
) -> Result<Vec<Check>, Error> {
    operator_served(k)?;
    let mut checks = Vec::new();
    let name = format!("cluster secret store {cluster_store}");
    let refuse_or_warn = |checks: &mut Vec<Check>, msg: String| match mode {
        PreflightMode::Mutate => Err(owner_setup(cluster_store)),
        PreflightMode::Read => {
            checks.push(Check {
                name: name.clone().into(),
                outcome: Ok(Verdict::Warn(msg)),
            });
            Ok(())
        }
    };
    let css_cmd = k.command(&format!("describe {STORE_RESOURCE} {cluster_store}"));
    match store_state(k, cluster_store, locator)? {
        StoreState::Missing => return Err(owner_setup(cluster_store)),
        StoreState::NotReady(why) => refuse_or_warn(
            &mut checks,
            format!("ClusterSecretStore {cluster_store} is not Ready ({why}) (`{css_cmd}`)"),
        )?,
        StoreState::Ready { names_store: false } => checks.push(Check {
            name: name.clone().into(),
            outcome: Ok(Verdict::Warn(format!(
                "ClusterSecretStore {cluster_store} is Ready, but its settings never name \
                 {locator}; check that it reads {describe} (`{css_cmd}`)"
            ))),
        }),
        StoreState::Ready { names_store: true } => {}
    }
    if let Some(refused) = can_i(k, "create")? {
        match mode {
            PreflightMode::Mutate => return Err(refused),
            PreflightMode::Read => checks.push(Check {
                name: "external secrets access".into(),
                outcome: Ok(Verdict::Warn(refused.to_string())),
            }),
        }
    }
    Ok(checks)
}

/// The `doctor` check names of the External Secrets binding, in order.
pub const DOCTOR_CHECKS: [&str; 3] = [
    "external secrets operator",
    "cluster secret store",
    "external secrets access",
];

/// `doctor` lines of the External Secrets binding (advisory where a check is a right).
pub(crate) fn doctor(
    k: &Kubectl<'_>,
    cluster_store: &str,
    locator: &str,
    describe: &str,
) -> Vec<Check> {
    let check = |name: &'static str, outcome| Check {
        name: name.into(),
        outcome,
    };
    let served = operator_served(k).map(|()| Verdict::Ok(format!("serves {API}")));
    if served.is_err() {
        let skip = || {
            Ok(Verdict::Warn(
                "not checked (the operator is not served, see the line above)".into(),
            ))
        };
        return vec![
            check(DOCTOR_CHECKS[0], served),
            check(DOCTOR_CHECKS[1], skip()),
            check(DOCTOR_CHECKS[2], skip()),
        ];
    }
    let css_cmd = k.command(&format!("describe {STORE_RESOURCE} {cluster_store}"));
    let css = store_state(k, cluster_store, locator).and_then(|s| match s {
        StoreState::Missing | StoreState::NotReady(_) => Err(owner_setup(cluster_store)),
        StoreState::Ready { names_store: false } => Ok(Verdict::Warn(format!(
            "{cluster_store} is Ready, but its settings never name {locator}; check that it \
             reads {describe} (`{css_cmd}`)"
        ))),
        StoreState::Ready { names_store: true } => Ok(Verdict::Ok(format!(
            "{cluster_store} is Ready and reads {describe}"
        ))),
    });
    let mut missing = Vec::new();
    let mut failed = None;
    for verb in ["get", "list", "create", "delete"] {
        match can_i(k, verb) {
            Ok(None) => {}
            Ok(Some(_)) => missing.push(verb),
            Err(e) => {
                failed = Some(e);
                break;
            }
        }
    }
    let access = match (failed, missing.is_empty()) {
        (Some(e), _) => Verdict::Warn(format!("rights not checked: {e}")),
        (None, true) => Verdict::Ok(format!(
            "can get, list, create and delete ExternalSecrets in namespace {}",
            k.target.namespace
        )),
        (None, false) => Verdict::Warn(format!(
            "your kubectl identity cannot {} ExternalSecrets in namespace {}",
            missing.join(", "),
            k.target.namespace
        )),
    };
    vec![
        check(DOCTOR_CHECKS[0], served),
        check(DOCTOR_CHECKS[1], css),
        check(DOCTOR_CHECKS[2], Ok(access)),
    ]
}

/// A named store as the Kubernetes target's store port (FR-39): values and versions live in
/// the named store (`inner`, unchanged); the ExternalSecrets that bind them belong to the
/// cluster, so superseded and pruned versions are collected here, before (prune) or instead
/// of (superseded) touching the store. Called only after a healthy rollout (FR-32).
pub struct ExternalStore<'a> {
    inner: Box<dyn PinnedStore + 'a>,
    k: Kubectl<'a>,
    /// Every string in the Deployment and its ReplicaSets, read once.
    referenced: OnceCell<BTreeSet<String>>,
    /// The orphan sweep ran this command.
    swept: OnceCell<()>,
}

impl<'a> ExternalStore<'a> {
    pub fn new(
        inner: Box<dyn PinnedStore + 'a>,
        runner: &'a dyn crate::runner::CommandRunner,
        target: &'a KubeTarget,
    ) -> Self {
        Self {
            inner,
            k: Kubectl::new(runner, target),
            referenced: OnceCell::new(),
            swept: OnceCell::new(),
        }
    }

    fn referenced(&self) -> Result<&BTreeSet<String>, Error> {
        if let Some(r) = self.referenced.get() {
            return Ok(r);
        }
        let seen = referenced_names(&self.k)?;
        Ok(self.referenced.get_or_init(|| seen))
    }

    /// Deletes the ExternalSecrets in `doomed` that neither the Deployment nor any
    /// ReplicaSet references (their Secrets follow, E4). A lost delete is reconciled by
    /// listing again (NR-2).
    fn delete_unreferenced(&self, doomed: Vec<Listed>, selector: &str) -> Result<(), Error> {
        if doomed.is_empty() {
            return Ok(());
        }
        let referenced = self.referenced()?;
        let names: Vec<&str> = doomed
            .iter()
            .map(|l| l.name.as_str())
            .filter(|n| !referenced.contains(*n))
            .collect();
        if names.is_empty() {
            return Ok(());
        }
        let what = "kubectl delete externalsecrets";
        let mut args = vec!["delete", RESOURCE];
        args.extend(&names);
        args.push("--ignore-not-found");
        match self.k.call(Effect::Write, what, &args, None, &[])? {
            Outcome::Done(_) => Ok(()),
            _ => {
                let failed = self.k.failed(Effect::Write);
                match crate::runner::diagnosing(|| list(&self.k, selector)) {
                    Ok(left) if !left.iter().any(|l| names.contains(&l.name.as_str())) => Ok(()),
                    _ => Err(self
                        .k
                        .explain(failed, Effect::Write, self.k.target.namespace_ref())),
                }
            }
        }
    }

    fn env_selector(&self) -> String {
        format!("{LABEL_MANAGED}={}", self.k.target.env)
    }

    fn key_selector(&self, name: &str) -> String {
        format!(
            "{LABEL_MANAGED}={},{LABEL_KEY}={}",
            self.k.target.env,
            store_name(name)
        )
    }

    /// Once per command: unreferenced ExternalSecrets of this environment whose key the
    /// store no longer holds (a pruned key whose versions a rollback needed until now).
    fn sweep(&self) -> Result<(), Error> {
        if self.swept.get().is_some() {
            return Ok(());
        }
        let held: BTreeSet<String> = self
            .inner
            .list()?
            .iter()
            .map(|e| store_name(&e.name))
            .collect();
        let selector = self.env_selector();
        let orphans = list(&self.k, &selector)?
            .into_iter()
            .filter(|l| !held.contains(&l.key))
            .collect();
        self.delete_unreferenced(orphans, &selector)?;
        let _ = self.swept.set(());
        Ok(())
    }
}

impl Store for ExternalStore<'_> {
    fn list(&self) -> Result<Vec<StoreEntry>, Error> {
        self.inner.list()
    }

    /// The store's own rules first, then what a Kubernetes Secret and env var can hold.
    fn refusal(&self, name: &str, value: &SecretValue) -> Option<(&'static str, &'static str)> {
        self.inner
            .refusal(name, value)
            .or_else(|| super::store::refusal(name, value))
    }
}

impl PinnedStore for ExternalStore<'_> {
    fn read(&self, name: &str) -> Result<Option<(SecretValue, String)>, Error> {
        self.inner.read(name)
    }

    fn write_one(
        &self,
        name: &str,
        value: &SecretValue,
        stamp: &crate::domain::Stamp,
    ) -> Result<String, Error> {
        // `sync` refuses every such value as a blocking row before any write (its pinned
        // plan asks this store's `refusal`), so one that reaches here is opv's bug.
        if super::store::refusal(name, value).is_some() {
            return Err(Cause::Bug {
                site: "kubernetes: a value the plan passed breaks a Secret rule",
            }
            .into());
        }
        self.inner.write_one(name, value, stamp)
    }

    /// The ExternalSecrets of `name` nothing references, then the store entry (FR-32): a
    /// run stopped in between finds the entry still listed and finishes the next time.
    fn delete(&self, name: &str) -> Result<bool, Error> {
        let selector = self.key_selector(name);
        let all = list(&self.k, &selector)?;
        self.delete_unreferenced(all, &selector)?;
        self.inner.delete(name)
    }

    /// The store's own collection (a no-op for Key Vault, which keeps history), then every
    /// ExternalSecret of `name` but `keep_version`'s that nothing references.
    fn collect_superseded(&self, name: &str, keep_version: &str) -> Result<(), Error> {
        self.inner.collect_superseded(name, keep_version)?;
        let keep = external_name(&store_name(name), keep_version);
        let selector = self.key_selector(name);
        let doomed = list(&self.k, &selector)?
            .into_iter()
            .filter(|l| Some(&l.name) != keep.as_ref())
            .collect();
        self.delete_unreferenced(doomed, &selector)?;
        self.sweep()
    }

    fn has_version(&self, name: &str, version: &str) -> Result<Option<bool>, Error> {
        self.inner.has_version(name, version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ES_READY: &str =
        include_str!("../../../tests/fixtures/external-secrets/externalsecret-ready.json");
    const ES_ERROR: &str =
        include_str!("../../../tests/fixtures/external-secrets/externalsecret-sync-error.json");

    #[test]
    fn external_name_takes_the_first_ten_characters_of_the_version() {
        assert_eq!(
            external_name("fleet--api--db-url", "46687ce78b76487cb0c1da470360b638").as_deref(),
            Some("opv-fleet--api--db-url-46687ce78b")
        );
    }

    #[test]
    fn external_name_refuses_a_short_version() {
        assert_eq!(external_name("db-url", "46687"), None);
    }

    #[test]
    fn split_external_name_returns_store_and_id() {
        assert_eq!(
            split_external_name("opv-fleet--api--db-url-46687ce78b"),
            Some(("fleet--api--db-url", "46687ce78b"))
        );
    }

    #[test]
    fn recorded_ready_externalsecret_is_synced() {
        assert_eq!(
            sync_state(&serde_json::from_str(ES_READY).unwrap()),
            Sync::Synced
        );
    }

    #[test]
    fn recorded_sync_error_is_failed() {
        assert_eq!(
            sync_state(&serde_json::from_str(ES_ERROR).unwrap()),
            Sync::Failed
        );
    }

    #[test]
    fn manifest_pins_the_version_once() {
        let t = super::super::testutil::target();
        let doc: Value = serde_json::from_slice(&manifest(
            &t,
            "opv-db-url-46687ce78b",
            "db-url",
            "DB-URL",
            "46687ce78b76487cb0c1da470360b638",
            "prod-vault",
            None,
        ))
        .unwrap();
        assert_eq!(
            (
                doc["spec"]["refreshInterval"].as_str(),
                doc["spec"]["data"][0]["remoteRef"]["version"].as_str()
            ),
            (Some("0"), Some("46687ce78b76487cb0c1da470360b638"))
        );
    }

    /// FR-42: an ExternalSecret opv writes carries its provenance stamp as annotations.
    #[test]
    fn manifest_carries_the_provenance_stamp() {
        let t = super::super::testutil::target();
        let stamp = crate::domain::provenance::fixture();
        let doc: Value = serde_json::from_slice(&manifest(
            &t,
            "opv-x-0123456789",
            "x",
            "X",
            "0123456789ab",
            "s",
            Some(&stamp),
        ))
        .unwrap();
        assert_eq!(doc["metadata"]["annotations"]["opv-plan"], "7f3c9a1e");
    }

    #[test]
    fn manifest_owns_its_target_secret() {
        let t = super::super::testutil::target();
        let doc: Value = serde_json::from_slice(&manifest(
            &t,
            "opv-x-0123456789",
            "x",
            "X",
            "0123456789ab",
            "s",
            None,
        ))
        .unwrap();
        assert_eq!(doc["spec"]["target"]["creationPolicy"], "Owner");
    }

    // diagnosis of SecretSyncedError (E3) ----------------------------------------------

    use crate::runner::Output;
    use crate::runner::fake::FakeRunner;

    /// A store that answers only `has_version`.
    struct Stub(Option<bool>);

    impl Store for Stub {
        fn list(&self) -> Result<Vec<StoreEntry>, Error> {
            unreachable!()
        }
        fn refusal(&self, _: &str, _: &SecretValue) -> Option<(&'static str, &'static str)> {
            None
        }
    }

    impl PinnedStore for Stub {
        fn read(&self, _: &str) -> Result<Option<(SecretValue, String)>, Error> {
            unreachable!()
        }
        fn write_one(
            &self,
            _: &str,
            _: &SecretValue,
            _: &crate::domain::Stamp,
        ) -> Result<String, Error> {
            unreachable!()
        }
        fn delete(&self, _: &str) -> Result<bool, Error> {
            unreachable!()
        }
        fn collect_superseded(&self, _: &str, _: &str) -> Result<(), Error> {
            unreachable!()
        }
        fn has_version(&self, _: &str, _: &str) -> Result<Option<bool>, Error> {
            Ok(self.0)
        }
    }

    const STORE_READY: &str =
        include_str!("../../../tests/fixtures/external-secrets/clustersecretstore-ready.json");

    /// The diagnosis when the store says `exists` and kubectl answers `outputs`.
    fn diagnosis(exists: Option<bool>, outputs: Vec<Output>) -> String {
        let e = diagnosis_error(exists, outputs);
        crate::error::report(&e)
    }

    /// The diagnosis error itself.
    fn diagnosis_error(exists: Option<bool>, outputs: Vec<Output>) -> Error {
        let r = FakeRunner::new(outputs);
        let t = super::super::testutil::target();
        let bridge = Bridge {
            store: Box::new(Stub(exists)),
            cluster_store: "prod-vault".into(),
            describe: "Key Vault kv-opv-fixture".into(),
            locator: "kv-opv-fixture".into(),
        };
        let k = Kubectl::new(&r, &t);
        diagnose_failed(
            &k,
            &bridge,
            "opv-db-url-46687ce78b",
            "DB_URL",
            "46687ce78b76487cb0c1da470360b638",
        )
    }

    fn store_with(f: impl FnOnce(&mut Value)) -> Output {
        let mut v: Value = serde_json::from_str(STORE_READY).unwrap();
        f(&mut v);
        Output::success(v.to_string().into_bytes())
    }

    #[test]
    fn missing_version_is_named_as_the_cause() {
        // The version was removed after opv wrote it: the target changed before the write.
        assert_eq!(
            diagnosis_error(Some(false), vec![]).code_str(),
            "target_changed"
        );
    }

    #[test]
    fn missing_version_reruns_the_same_command() {
        // Re-running writes and pins a fresh version.
        let e = diagnosis_error(Some(false), vec![]);
        let next = e
            .cause()
            .map(|(c, _)| c.step(&crate::cause::Invocation::default()).1);
        assert_eq!(next, Some(crate::cause::Next::Rerun));
    }

    /// The object a cluster admin is asked to set up, when the error is that.
    fn owner_object(e: &Error) -> Option<String> {
        match e.cause() {
            Some((Cause::OwnerSetupRequired { object, .. }, _)) => {
                Some(object.name.as_str().to_string())
            }
            _ => None,
        }
    }

    fn not_ready_store() -> Output {
        store_with(|v| {
            v["status"]["conditions"][0]["status"] = json!("False");
            v["status"]["conditions"][0]["message"] = json!("unable to authenticate");
        })
    }

    #[test]
    fn store_not_ready_is_the_cluster_admins_to_fix() {
        let e = diagnosis_error(Some(true), vec![not_ready_store()]);
        assert_eq!(owner_object(&e).as_deref(), Some("prod-vault"));
    }

    /// 06.52: the store's Ready message is operator-written text, never echoed.
    #[test]
    fn store_not_ready_message_is_never_shown() {
        assert!(!diagnosis(Some(true), vec![not_ready_store()]).contains("unable to authenticate"));
    }

    #[test]
    fn store_not_ready_state_keeps_only_status_and_reason() {
        let r = FakeRunner::new([not_ready_store()]);
        let t = super::super::testutil::target();
        assert_eq!(
            store_state(&Kubectl::new(&r, &t), "prod-vault", "kv-opv-fixture").unwrap(),
            StoreState::NotReady("Ready=False, reason Valid".into())
        );
    }

    #[test]
    fn store_for_another_vault_is_the_cluster_admins_to_fix() {
        let out = store_with(|v| {
            v["spec"]["provider"]["azurekv"]["vaultUrl"] =
                json!("https://kv-other.vault.azure.net/");
        });
        let e = diagnosis_error(Some(true), vec![out]);
        assert_eq!(owner_object(&e).as_deref(), Some("prod-vault"));
    }

    #[test]
    fn missing_store_is_the_cluster_admins_to_fix() {
        let e = diagnosis_error(Some(true), vec![Output::success(Vec::new())]);
        assert_eq!(owner_object(&e).as_deref(), Some("prod-vault"));
    }

    /// 06.15: found live, an expired client secret behind a store still cached as Ready;
    /// only a cluster admin can renew it, so a person acts first.
    #[test]
    fn ready_store_that_cannot_read_needs_a_person() {
        assert!(diagnosis_error(Some(true), vec![store_with(|_| {})]).human_required());
    }

    #[test]
    fn store_that_cannot_tell_versions_still_gets_the_cluster_store_checked() {
        let e = diagnosis_error(None, vec![store_with(|_| {})]);
        assert_eq!(owner_object(&e).as_deref(), Some("prod-vault"));
    }

    /// 06.25: an operator that is not installed is a cluster admin's to install, never a
    /// dependency opv names a repository-local document for.
    #[test]
    fn operator_not_installed_is_the_cluster_admins_to_install() {
        let r = FakeRunner::default();
        r.push_with_stderr(
            Output::failure(1),
            "Error from server (NotFound): the server could not find the requested resource\n",
        );
        r.push_with_stderr(
            Output::failure(1),
            "Error from server (NotFound): the server could not find the requested resource\n",
        );
        let t = super::super::testutil::target();
        let e = operator_served(&Kubectl::new(&r, &t)).unwrap_err();
        assert_eq!(owner_object(&e).as_deref(), Some(OPERATOR));
    }

    #[test]
    fn a_no_to_creating_external_secrets_is_permission_denied() {
        let r = FakeRunner::new([Output {
            status: 1,
            stdout: b"no\n".to_vec().into(),
        }]);
        let t = super::super::testutil::target();
        let refused = can_i(&Kubectl::new(&r, &t), "create").unwrap();
        assert_eq!(refused.map(|e| e.code_str()), Some("permission_denied"));
    }

    #[test]
    fn operator_not_installed_needs_a_person() {
        let r = FakeRunner::default();
        r.push_with_stderr(
            Output::failure(1),
            "Error from server (NotFound): the server could not find the requested resource\n",
        );
        r.push_with_stderr(Output::failure(1), "");
        let t = super::super::testutil::target();
        assert!(
            operator_served(&Kubectl::new(&r, &t))
                .unwrap_err()
                .human_required()
        );
    }
}
