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
//! opv diagnoses it itself: does the version exist in the store, is the ClusterSecretStore
//! Ready and does it name the store.

use std::cell::OnceCell;
use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::store::referenced_names;
use super::{Effect, KubeTarget, Kubectl, LABEL_KEY, LABEL_MANAGED, VALUE_KEY, store_name};
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
        &format!("auth can-i list {RESOURCE}"),
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

/// The ExternalSecret manifest. It carries names and a version id only, never a value.
pub(crate) fn manifest(
    t: &KubeTarget,
    name: &str,
    store: &str,
    remote_key: &str,
    version: &str,
    cluster_store: &str,
) -> Vec<u8> {
    json!({
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
    })
    .to_string()
    .into_bytes()
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
                Err(Error::Target(
                    format!(
                        "{what} did not confirm the ExternalSecret it wrote; nothing else was \
                     changed\n  next: check with `{}`, then re-run the same command",
                        k.command(&format!("get {RESOURCE} {name} -o name"))
                    )
                    .into(),
                ))
            }
        }
        // The read-back explains the failure, so the apply's excerpt stays (NR-31).
        other => match crate::runner::diagnosing(|| get(k, name)) {
            Ok(Some(_)) => Ok(()),
            _ => Err(k.fail(
                Effect::Write,
                &what,
                other,
                &format!("auth can-i create {RESOURCE}"),
            )),
        },
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
        &format!("describe {RESOURCE} {name}"),
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
        &format!("auth can-i get {STORE_RESOURCE}"),
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
        Some((s, reason, message)) => {
            StoreState::NotReady(format!("Ready={s}, reason {reason}: {message}"))
        }
        None => StoreState::NotReady("it reports no Ready condition yet".into()),
    })
}

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
/// (E3) naming the cause and the next step. Read-only.
pub(crate) fn diagnose_failed(
    k: &Kubectl<'_>,
    bridge: &Bridge<'_>,
    es: &str,
    env_name: &str,
    version: &str,
) -> Error {
    let t = k.target;
    let css = &bridge.cluster_store;
    let head = format!(
        "ExternalSecret {es} could not read version {version} of {env_name} from {} \
         (SecretSyncedError); deployment {} was not changed",
        bridge.describe, t.deployment
    );
    let describe = k.command(&format!("describe {RESOURCE} {es}"));
    match bridge.store.has_version(env_name, version) {
        Ok(Some(false)) => {
            return Error::Target(
                format!(
                    "{head}\n  cause: {} has no version {version} of {env_name} (deleted or purged \
                 after opv wrote it)\n  next: run opv sync {} --deploy again; it writes and pins a \
                 fresh version",
                    bridge.describe, t.env
                )
                .into(),
            );
        }
        Err(e) => {
            return Error::Target(
                format!(
                    "{head}\n  cause not found: could not check the version in {} ({e})\n  next: \
                 `{describe}`",
                    bridge.describe
                )
                .into(),
            );
        }
        Ok(_) => {}
    }
    let css_cmd = k.command(&format!("describe {STORE_RESOURCE} {css}"));
    match store_state(k, css, &bridge.locator) {
        Ok(StoreState::Missing) => Error::Target(format!(
            "{head}\n  cause: ClusterSecretStore {css} does not exist\n  next: create it (see \
             docs/agent-setup.md), or set secret_store in the store's [stores.<name>] table to \
             the one that reads {}",
            bridge.describe
        ).into()),
        Ok(StoreState::NotReady(why)) => Error::Target(format!(
            "{head}\n  cause: ClusterSecretStore {css} is not Ready ({why})\n  next: `{css_cmd}`; \
             fix its credentials, then run the same command again"
        ).into()),
        Ok(StoreState::Ready { names_store: false }) => Error::Target(format!(
            "{head}\n  cause: ClusterSecretStore {css} is Ready but its settings never name {} \
             (a vault URL for another vault?)\n  next: `{css_cmd}`; point it at {}, or set \
             secret_store to the ClusterSecretStore that does",
            bridge.locator, bridge.describe
        ).into()),
        Ok(StoreState::Ready { names_store: true }) => Error::Target(format!(
            "{head}\n  cause: the version exists and ClusterSecretStore {css} is Ready, so its \
             identity most likely cannot read this secret (for Key Vault: no \"Key Vault Secrets \
             User\" role on the vault, or a vault firewall)\n  next: `{describe}`, then grant the \
             store's identity read access and run the same command again"
        ).into()),
        Err(e) => Error::Target(format!(
            "{head}\n  cause not found: could not read ClusterSecretStore {css} ({e})\n  next: \
             `{describe}`"
        ).into()),
    }
}

/// `get --raw /apis/external-secrets.io/v1`: the operator's API is served at v1 (discovery,
/// which every signed-in identity may read). Not served: [`Error::Dependency`] naming what
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
        Outcome::Refused(out) => {
            let group = ["get", "--raw", "/apis/external-secrets.io"];
            let probe = || k.call(Effect::Read, what, &group, None, &[1]);
            match crate::runner::diagnosing(probe)? {
                Outcome::Done(_) => Err(not_served(true)),
                _ => match k.diagnose(
                    Effect::Read,
                    what,
                    &crate::runner::status_text(out.status),
                    "api-resources --api-group=external-secrets.io",
                ) {
                    // Context and cluster are fine: the API group is simply absent.
                    Error::Target(_) => Err(not_served(false)),
                    other => Err(other),
                },
            }
        }
        other => Err(k.fail(
            Effect::Read,
            what,
            other,
            "api-resources --api-group=external-secrets.io",
        )),
    }
}

fn not_served(old: bool) -> Error {
    if old {
        Error::Dependency(
            "the External Secrets Operator in this cluster does not serve external-secrets.io/v1, \
             which opv writes; nothing was changed\n  next: upgrade it (opv is tested with 2.11): \
             helm upgrade external-secrets external-secrets/external-secrets -n external-secrets"
                .into(),
        )
    } else {
        Error::Dependency(
            "the External Secrets Operator is not installed in this cluster (no \
             external-secrets.io/v1 API); nothing was changed\n  next: helm install \
             external-secrets external-secrets/external-secrets -n external-secrets \
             --create-namespace (see docs/agent-setup.md)"
                .into(),
        )
    }
}

/// `auth can-i <verb> externalsecrets.external-secrets.io`: `Ok(true)` when allowed.
pub(crate) fn can_i(k: &Kubectl<'_>, verb: &str) -> Result<bool, Error> {
    let what = format!("kubectl auth can-i {verb} {RESOURCE}");
    match k.call(
        Effect::Read,
        &what,
        &["auth", "can-i", verb, RESOURCE],
        None,
        &[1],
    )? {
        Outcome::Done(_) => Ok(true),
        Outcome::Refused(o) if o.status == 1 && super::runtime::answered_no(&o.stdout) => Ok(false),
        other => Err(k.fail(
            Effect::Read,
            &what,
            other,
            &format!("auth can-i {verb} {RESOURCE}"),
        )),
    }
}

/// The `create role` / `create rolebinding` pair granting `verbs` on ExternalSecrets.
fn grant(k: &Kubectl<'_>, verbs: &str) -> String {
    format!(
        "`{}` and `{}`",
        k.command(&format!(
            "create role opv-external-secrets --verb={verbs} --resource={RESOURCE}"
        )),
        k.command(
            "create rolebinding opv-external-secrets --role=opv-external-secrets --user=<you>"
        )
    )
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
        PreflightMode::Mutate => Err(Error::Target(msg.into())),
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
        StoreState::Missing => {
            return Err(Error::Target(
                format!(
                    "ClusterSecretStore {cluster_store} does not exist, so no ExternalSecret can \
                 read {describe}; nothing was changed\n  next: create it (see \
                 docs/agent-setup.md), or set secret_store in the store's [stores.<name>] \
                 table to the ClusterSecretStore that reads {describe}"
                )
                .into(),
            ));
        }
        StoreState::NotReady(why) => refuse_or_warn(
            &mut checks,
            format!(
                "ClusterSecretStore {cluster_store} is not Ready ({why}); nothing was \
                 changed\n  next: `{css_cmd}`; fix it, then run the same command again"
            ),
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
    if !can_i(k, "create")? {
        let msg = format!(
            "your kubectl identity cannot create ExternalSecrets in namespace {}; nothing was \
             changed\n  next: ask an admin to grant it: {}",
            k.target.namespace,
            grant(k, "get,list,create,delete")
        );
        match mode {
            PreflightMode::Mutate => return Err(Error::Auth(msg.into())),
            PreflightMode::Read => checks.push(Check {
                name: "external secrets access".into(),
                outcome: Ok(Verdict::Warn(msg)),
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
        StoreState::Missing => Err(Error::Target(
            format!(
                "{cluster_store} does not exist\n  next: create it (see docs/agent-setup.md), or \
             set secret_store in the store's [stores.<name>] table"
            )
            .into(),
        )),
        StoreState::NotReady(why) => Err(Error::Target(
            format!("{cluster_store} is not Ready ({why})\n  next: `{css_cmd}`").into(),
        )),
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
            Ok(true) => {}
            Ok(false) => missing.push(verb),
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
            "your kubectl identity cannot {} ExternalSecrets in namespace {}\n  next: {}",
            missing.join(", "),
            k.target.namespace,
            grant(k, &missing.join(","))
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
            other => match crate::runner::diagnosing(|| list(&self.k, selector)) {
                Ok(left) if !left.iter().any(|l| names.contains(&l.name.as_str())) => Ok(()),
                _ => Err(self.k.fail(
                    Effect::Write,
                    what,
                    other,
                    &format!("auth can-i delete {RESOURCE}"),
                )),
            },
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

    fn write_one(&self, name: &str, value: &SecretValue) -> Result<String, Error> {
        if let Some((rule, reason)) = super::store::refusal(name, value) {
            return Err(Error::Policy(format!("{name}: {rule}: {reason}").into()));
        }
        self.inner.write_one(name, value)
    }

    /// The ExternalSecrets of `name` nothing references, then the store entry (FR-32): a
    /// run stopped in between finds the entry still listed and finishes the next time.
    fn delete(&self, name: &str) -> Result<(), Error> {
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
        fn write_one(&self, _: &str, _: &SecretValue) -> Result<String, Error> {
            unreachable!()
        }
        fn delete(&self, _: &str) -> Result<(), Error> {
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
        let r = FakeRunner::new(outputs);
        let t = super::super::testutil::target();
        let bridge = Bridge {
            store: Box::new(Stub(exists)),
            cluster_store: "prod-vault".into(),
            describe: "Key Vault kv-opv-fixture".into(),
            locator: "kv-opv-fixture".into(),
        };
        let k = Kubectl::new(&r, &t);
        let e = diagnose_failed(
            &k,
            &bridge,
            "opv-db-url-46687ce78b",
            "DB_URL",
            "46687ce78b76487cb0c1da470360b638",
        );
        crate::error::report(&e, "opv doctor", None)
    }

    fn store_with(f: impl FnOnce(&mut Value)) -> Output {
        let mut v: Value = serde_json::from_str(STORE_READY).unwrap();
        f(&mut v);
        Output::success(v.to_string().into_bytes())
    }

    #[test]
    fn missing_version_is_named_as_the_cause() {
        assert!(
            diagnosis(Some(false), vec![])
                .contains("has no version 46687ce78b76487cb0c1da470360b638 of DB_URL")
        );
    }

    #[test]
    fn missing_version_names_sync_deploy_as_the_next_step() {
        assert!(diagnosis(Some(false), vec![]).contains("Next: opv sync dev --deploy\n"));
    }

    #[test]
    fn store_not_ready_is_named_with_its_message() {
        let out = store_with(|v| {
            v["status"]["conditions"][0]["status"] = json!("False");
            v["status"]["conditions"][0]["message"] = json!("unable to authenticate");
        });
        assert!(
            diagnosis(Some(true), vec![out])
                .contains("is not Ready (Ready=False, reason Valid: unable to authenticate)")
        );
    }

    #[test]
    fn store_for_another_vault_is_named() {
        let out = store_with(|v| {
            v["spec"]["provider"]["azurekv"]["vaultUrl"] =
                json!("https://kv-other.vault.azure.net/");
        });
        assert!(
            diagnosis(Some(true), vec![out]).contains("its settings never name kv-opv-fixture")
        );
    }

    #[test]
    fn missing_store_is_named() {
        assert!(
            diagnosis(Some(true), vec![Output::success(Vec::new())])
                .contains("ClusterSecretStore prod-vault does not exist")
        );
    }

    #[test]
    fn recorded_ready_store_that_names_the_vault_points_at_the_identity() {
        let out = store_with(|_| {});
        assert!(diagnosis(Some(true), vec![out]).contains("its identity most likely cannot read"));
    }

    #[test]
    fn store_that_cannot_tell_versions_still_gets_the_cluster_store_checked() {
        let out = store_with(|_| {});
        assert!(diagnosis(None, vec![out]).contains("its identity most likely cannot read"));
    }
}
