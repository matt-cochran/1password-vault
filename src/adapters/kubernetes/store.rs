//! Kubernetes Secrets — and, when `kubernetes.config = "configmap"`, ConfigMaps — as a
//! [`PinnedStore`] (FR-29, FR-32, FR-38; delivery-transports §11.1, K3).
//!
//! | op | argv (after the scope flags) | effect |
//! |---|---|---|
//! | `list` | `get <secret\|configmap> -l opv-managed=<env> -o jsonpath=<name, opv-key>` | read |
//! | `read` | `get deployment <d> -o json`, then `get <secret\|configmap> <s> --ignore-not-found -o jsonpath=<opv-managed, data.value>` | read |
//! | `write_one` | `read` (above); if the bound value differs or none is bound, `apply -f - --server-side --field-manager=opv -o name` of a new `opv-<store>-<random id>` (manifest on stdin); a lost apply is reconciled with `get <secret\|configmap> <s> --ignore-not-found -o jsonpath=<opv-managed, data.value>` | reads, write |
//! | `delete` | `get <secret\|configmap> -l opv-managed=<env>,opv-key=<store> …`, `get deployment`, `get replicasets -o json`, then `delete <secret\|configmap> <names…> --ignore-not-found` | reads, write |
//!
//! Lists never ask for `-o json` (it returns `data`, K2) and writes ask for `-o name` (`-o
//! json` echoes `data`, K1). Version ids are random (FR-38, SR-1): nothing in a name, label or
//! annotation is derived from a value, so listing Secrets cannot confirm a guessed value.
//! Compare-before-write therefore reads the value the Deployment binds and compares it in
//! constant time; a matching value is never written again. A write whose outcome is lost and
//! cannot be confirmed may leave one unreferenced version behind; `collect_superseded` deletes it
//! after the next healthy rollout (NR-1).

use std::cell::OnceCell;
use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use super::{
    Effect, KubeTarget, Kubectl, LABEL_KEY, LABEL_MANAGED, VALUE_KEY, container_env,
    container_index, new_version, secret_name, split_secret_name, store_name, text,
    valid_label_value,
};
use crate::domain::provenance::{STAMP_ENV, STAMP_PLAN, STAMP_VERSION, STAMP_WRITTEN};
use crate::domain::{SecretValue, Stamp};

/// The annotation keys of a stamp, in [`LIST_PATH`]'s order.
const STAMP_KEYS: [&str; 4] = [STAMP_VERSION, STAMP_WRITTEN, STAMP_ENV, STAMP_PLAN];
use crate::cause::{Cause, Guard};
use crate::domain::plan::StoreEntry;
use crate::error::Error;
use crate::ports::{PinnedStore, Store};
use crate::runner::{CommandRunner, Outcome};

/// Largest value opv writes: a Secret object is limited to 1 MiB, minus room for metadata.
pub const VALUE_LIMIT: usize = 1024 * 1024 - 16 * 1024;

const LIST_PATH: &str = concat!(
    r#"jsonpath={range .items[*]}{.metadata.name}{"\t"}{.metadata.labels.opv-key}"#,
    r#"{"\t"}{.metadata.annotations.opv-version}{"\t"}{.metadata.annotations.opv-written}"#,
    r#"{"\t"}{.metadata.annotations.opv-env}{"\t"}{.metadata.annotations.opv-plan}{"\n"}{end}"#,
);
const VALUE_PATH: &str = r#"jsonpath={.metadata.labels.opv-managed}{"\t"}{.data.value}"#;

/// The kind of object a [`KubeSecrets`] store reads and writes (delivery-transports §11.1,
/// K3). Name scheme, ownership labels, provenance annotations, immutability, the
/// compare-before-write and the clean-up of superseded versions are the same for both; only
/// the kubectl resource, the manifest's `kind`/`type` and the value encoding differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    Secret,
    ConfigMap,
}

impl ObjectKind {
    /// The singular name `kubectl get|delete <kind>` takes, and the prefix `apply -o name`
    /// echoes (`secret/…`, `configmap/…`).
    fn singular(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::ConfigMap => "configmap",
        }
    }

    /// The `kind` of the manifest this store applies.
    fn kind(self) -> &'static str {
        match self {
            Self::Secret => "Secret",
            Self::ConfigMap => "ConfigMap",
        }
    }

    /// The field of an unreadable value, in the message.
    fn value_label(self) -> &'static str {
        match self {
            Self::Secret => "Secret value",
            Self::ConfigMap => "ConfigMap value",
        }
    }

    /// The object name an env entry binds through `valueFrom.<ref>` with key `value`.
    fn bound_ref(self, entry: &Value) -> Option<&str> {
        let key = match self {
            Self::Secret => "secretKeyRef",
            Self::ConfigMap => "configMapKeyRef",
        };
        let r = entry.pointer(&format!("/valueFrom/{key}"))?;
        (r.get("key").and_then(Value::as_str) == Some(VALUE_KEY))
            .then(|| r.get("name").and_then(Value::as_str))
            .flatten()
    }

    /// The stored [`VALUE_PATH`] field as bytes: base64 for a Secret, plain text for a
    /// ConfigMap.
    fn decode(self, stored: &str) -> Option<Zeroizing<Vec<u8>>> {
        match self {
            Self::Secret => STANDARD.decode(stored.trim()).ok().map(Zeroizing::new),
            Self::ConfigMap => Some(Zeroizing::new(stored.as_bytes().to_vec())),
        }
    }
}

/// The Secrets (and ConfigMaps) of one Kubernetes target.
pub struct KubeSecrets<'a> {
    k: Kubectl<'a>,
    /// Managed env names (from the template, FR-8): the names this port speaks.
    managed: BTreeSet<String>,
    /// store name → version the Deployment binds, read once per command.
    bound: OnceCell<BTreeMap<String, String>>,
    /// Every string of the Deployment and its ReplicaSets, read once, after the healthy
    /// rollout that precedes any delete.
    referenced: OnceCell<BTreeSet<String>>,
    /// The opv objects of this environment as `list` read them this run: `(object name,
    /// store name, stamp)`.
    listed: OnceCell<Vec<(String, String, Option<Stamp>)>>,
    /// Source of new version ids: the OS RNG ([`new_version`]); fixed in tests.
    ids: fn() -> Result<String, Error>,
    /// The kind this store reads and writes.
    kind: ObjectKind,
    /// Config keys' own store when the target routes config to a ConfigMap (K3): `read`,
    /// `write_one` and `delete` route each name in `config_names` to it.
    config: Option<Box<KubeSecrets<'a>>>,
    /// The env names of config keys (from the configuration, never inferred from what the
    /// Deployment binds): only these ever go to the ConfigMap store, so a secret never
    /// becomes a ConfigMap.
    config_names: BTreeSet<String>,
}

impl<'a> KubeSecrets<'a> {
    pub fn new(
        runner: &'a dyn CommandRunner,
        target: &'a KubeTarget,
        managed: BTreeSet<String>,
    ) -> Self {
        Self {
            k: Kubectl::new(runner, target),
            managed,
            bound: OnceCell::new(),
            referenced: OnceCell::new(),
            listed: OnceCell::new(),
            ids: new_version,
            kind: ObjectKind::Secret,
            config: None,
            config_names: BTreeSet::new(),
        }
    }

    /// The same store drawing version ids from `ids` (tests pin them).
    #[cfg(test)]
    pub(crate) fn with_ids(mut self, ids: fn() -> Result<String, Error>) -> Self {
        self.ids = ids;
        self
    }

    /// The same store reading and writing `kind` (K3): the ConfigMap store `open` routes
    /// config keys to, and the tests.
    pub fn with_kind(mut self, kind: ObjectKind) -> Self {
        self.kind = kind;
        self
    }

    /// Give this store a second, ConfigMap-kind store for the config keys' env names
    /// `names` (K3). With no `config` store every name stays here.
    pub fn with_config(mut self, config: KubeSecrets<'a>, names: BTreeSet<String>) -> Self {
        self.config = Some(Box::new(config));
        self.config_names = names;
        self
    }

    fn t(&self) -> &KubeTarget {
        self.k.target
    }

    /// The ConfigMap store `name` belongs to: when this store has one and `name` is a config
    /// key's (K3). `read`, `write_one` and `delete` delegate there. The kind comes from the
    /// configuration, never from what the Deployment binds today, so a new secret key is
    /// never written as a ConfigMap.
    fn config_store(&self, name: &str) -> Result<Option<&KubeSecrets<'a>>, Error> {
        Ok(self
            .config
            .as_deref()
            .filter(|_| self.config_names.contains(name)))
    }

    /// `(secret name, store name)` of every opv Secret matching `selector`. Entries whose
    /// name is not `opv-<opv-key>-<version>` are ignored (NR-6).
    fn names(&self, selector: &str) -> Result<Vec<(String, String)>, Error> {
        Ok(self
            .stamped(selector)?
            .into_iter()
            .map(|(name, key, _)| (name, key))
            .collect())
    }

    /// [`Self::names`] with each Secret's provenance stamp (FR-42), when it carries one.
    fn stamped(&self, selector: &str) -> Result<Vec<(String, String, Option<Stamp>)>, Error> {
        let what = format!("kubectl get {}", self.kind.singular());
        let out = self.k.run(
            Effect::Read,
            &what,
            &["get", self.kind.singular(), "-l", selector, "-o", LIST_PATH],
            None,
        )?;
        Ok(text(&out, &what)?
            .lines()
            .filter_map(|line| {
                let mut fields = line.split('\t');
                let (name, key) = (fields.next()?, fields.next()?);
                let (store, _) = split_secret_name(name)?;
                let rest: Vec<&str> = fields.collect();
                let stamp = Stamp::parse(|k| {
                    let at = STAMP_KEYS.iter().position(|s| *s == k)?;
                    rest.get(at).copied()
                });
                (store == key).then(|| (name.to_string(), key.to_string(), stamp))
            })
            .collect())
    }

    /// `(opv-managed label, value)` of Secret `name` (`""` when unlabelled), `None` when it
    /// does not exist. The value is decoded into zeroized memory only (K2).
    fn held(&self, name: &str) -> Result<Option<(String, SecretValue)>, Error> {
        let what = format!("kubectl get {} {name}", self.kind.singular());
        let out = self.k.run(
            Effect::Read,
            &what,
            &[
                "get",
                self.kind.singular(),
                name,
                "--ignore-not-found",
                "-o",
                VALUE_PATH,
            ],
            None,
        )?;
        let Some((env, stored)) = text(&out, &what)?.split_once('\t') else {
            return Ok(None);
        };
        // Not a UTF-8 value under data.<VALUE_KEY>: it was changed outside opv.
        let unreadable = || {
            super::unusable_reply(
                &what,
                None,
                crate::cause::OutputProblem::InvalidValue {
                    what: self.kind.value_label(),
                },
                crate::cause::During::Read,
            )
        };
        let bytes = self.kind.decode(stored).ok_or_else(unreadable)?;
        let value = std::str::from_utf8(&bytes).map_err(|_| unreadable())?;
        Ok(Some((env.to_string(), SecretValue::new(value.to_string()))))
    }

    /// store name → version bound by the managed container (one Deployment read).
    fn bound(&self) -> Result<&BTreeMap<String, String>, Error> {
        if let Some(b) = self.bound.get() {
            return Ok(b);
        }
        let d = self.k.get_deployment()?;
        let i = container_index(&d, self.t())?;
        let map = container_env(&d, i)
            .iter()
            .filter_map(|e| self.kind.bound_ref(e))
            .filter_map(split_secret_name)
            .map(|(s, v)| (s.to_string(), v.to_string()))
            .collect();
        Ok(self.bound.get_or_init(|| map))
    }

    /// The immutable manifest for `value`; the only place a value is encoded. It also
    /// carries opv's provenance stamp as annotations (FR-42; never a value).
    fn manifest(
        &self,
        name: &str,
        store: &str,
        value: &SecretValue,
        stamp: &Stamp,
    ) -> Zeroizing<Vec<u8>> {
        let t = self.t();
        let mut head = json!({
            "apiVersion": "v1",
            "kind": self.kind.kind(),
            "metadata": {
                "name": name,
                "namespace": t.namespace,
                "labels": { LABEL_MANAGED: t.env, LABEL_KEY: store },
                "annotations": super::annotations(stamp),
            },
            "immutable": true,
        });
        if self.kind == ObjectKind::Secret {
            // A ConfigMap has no `type` (delivery-transports §11.1).
            head["type"] = json!("Opaque");
        }
        let head = head.to_string();
        let encoded_len = match self.kind {
            ObjectKind::Secret => value.expose().len().div_ceil(3) * 4 + 2,
            ObjectKind::ConfigMap => value.expose().len() + 2,
        };
        let mut doc = Zeroizing::new(String::with_capacity(head.len() + encoded_len + 32));
        doc.push_str(&head[..head.len() - 1]);
        doc.push_str(&format!(",\"data\":{{\"{VALUE_KEY}\":"));
        match self.kind {
            ObjectKind::Secret => {
                doc.push('"');
                STANDARD.encode_string(value.expose().as_bytes(), &mut doc);
                doc.push('"');
            }
            // ConfigMap data holds the plain text, JSON-escaped in zeroized memory.
            ObjectKind::ConfigMap => push_json_string(&mut doc, value.expose()),
        }
        doc.push_str("}}");
        Zeroizing::new(std::mem::take(&mut *doc).into_bytes())
    }

    /// The newest version of `name` that this run's `list` saw and the Deployment does not
    /// bind (written by an earlier `sync` without `--deploy`), when it holds exactly
    /// `value` (constant-time compare): reused, so staged runs never pile up versions and
    /// the next `--deploy` binds the one already written (FR-29).
    fn pending_with(&self, name: &str, value: &SecretValue) -> Result<Option<String>, Error> {
        let Some(listed) = self.listed.get() else {
            return Ok(None);
        };
        let store = store_name(name);
        let bound = self.bound()?.get(&store).cloned();
        let newest = listed
            .iter()
            .filter(|(secret, key, _)| {
                *key == store && split_secret_name(secret).map(|(_, v)| v) != bound.as_deref()
            })
            .max_by(|a, b| {
                a.2.as_ref()
                    .map(|s| &s.written)
                    .cmp(&b.2.as_ref().map(|s| &s.written))
            });
        let Some((secret, _, _)) = newest else {
            return Ok(None);
        };
        Ok(match self.held(secret)? {
            Some((env, held)) if env == self.t().env && same(&held, value) => {
                split_secret_name(secret).map(|(_, v)| v.to_string())
            }
            _ => None,
        })
    }

    /// Every string in the Deployment and in every ReplicaSet of the namespace (read once).
    fn referenced(&self) -> Result<&BTreeSet<String>, Error> {
        if let Some(seen) = self.referenced.get() {
            return Ok(seen);
        }
        let seen = referenced_names(&self.k)?;
        Ok(self.referenced.get_or_init(|| seen))
    }
}

/// Every string in the Deployment and in every ReplicaSet of the namespace: a Secret (or
/// ExternalSecret) named by any of them is still referenced (FR-32; superset of "its
/// ReplicaSets").
pub(crate) fn referenced_names(k: &Kubectl<'_>) -> Result<BTreeSet<String>, Error> {
    let mut seen = BTreeSet::new();
    strings(&k.get_deployment()?, &mut seen);
    let what = "kubectl get replicasets";
    let out = k.run(
        Effect::Read,
        what,
        &["get", "replicasets", "-o", "json"],
        None,
    )?;
    strings(&super::parse_json(&out, what)?, &mut seen);
    Ok(seen)
}

/// Collect every string value in `v`.
fn strings(v: &Value, out: &mut BTreeSet<String>) {
    match v {
        Value::String(s) => {
            out.insert(s.clone());
        }
        Value::Array(a) => a.iter().for_each(|x| strings(x, out)),
        Value::Object(o) => o.values().for_each(|x| strings(x, out)),
        _ => {}
    }
}

/// Exact, constant-time equality of two values (FR-31, SR-1).
fn same(a: &SecretValue, b: &SecretValue) -> bool {
    a.expose().as_bytes().ct_eq(b.expose().as_bytes()).into()
}

/// Write `s` as a JSON string into `out` (zeroized memory), escaping what JSON requires; a
/// ConfigMap's `data` is plain text, so it is never base64-encoded (K3).
fn push_json_string(out: &mut String, s: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str("\\u00");
                out.push(HEX[(c as usize >> 4) & 0xf] as char);
                out.push(HEX[c as usize & 0xf] as char);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The first rule a Kubernetes target refuses `(name, value)` for, with its fixed reason
/// (FR-22). Never inspects more than the value's length and NUL bytes.
pub fn refusal(name: &str, value: &SecretValue) -> Option<(&'static str, &'static str)> {
    let v = value.expose();
    if !valid_label_value(&store_name(name)) {
        Some((
            "kubernetes-name-invalid",
            "is not a valid Kubernetes name once lower-cased with `_` as `-` (1 to 63 of \
             a-z, 0-9 and -, starting and ending with a letter or digit)",
        ))
    } else if v.as_bytes().contains(&0) {
        Some((
            "kubernetes-env-nul",
            "contains a NUL byte, which an environment variable cannot hold",
        ))
    } else if v.len() > VALUE_LIMIT {
        Some((
            "kubernetes-secret-limit",
            "is longer than a Kubernetes Secret can hold (1 MiB)",
        ))
    } else {
        None
    }
}

impl Store for KubeSecrets<'_> {
    /// One entry per managed env name with opv Secrets labelled for this environment (the
    /// port speaks env names; a Secret of a name the template does not render is not
    /// listed). The version comes from `read` (the binding), never from the list.
    fn list(&self) -> Result<Vec<StoreEntry>, Error> {
        let selector = format!("{LABEL_MANAGED}={}", self.t().env);
        // store name → the latest stamp among its versions (FR-42).
        let mut stores: BTreeMap<String, Option<Stamp>> = BTreeMap::new();
        let listed = self.stamped(&selector)?;
        for (_, store, stamp) in &listed {
            let latest = stores.entry(store.clone()).or_default();
            if stamp.as_ref().map(|s| &s.written) > latest.as_ref().map(|s| &s.written) {
                *latest = stamp.clone();
            }
        }
        let _ = self.listed.set(listed);
        let mut out: Vec<StoreEntry> = self
            .managed
            .iter()
            .filter_map(|n| {
                let stamp = stores.get(&store_name(n))?;
                Some(StoreEntry {
                    name: n.clone(),
                    version: None,
                    pending: false,
                    stamp: stamp.clone(),
                })
            })
            .collect();
        if let Some(config) = &self.config {
            out.extend(config.list()?);
            out.sort_by(|a, b| a.name.cmp(&b.name));
        }
        Ok(out)
    }

    fn refusal(&self, name: &str, value: &SecretValue) -> Option<(&'static str, &'static str)> {
        refusal(name, value)
    }
}

impl PinnedStore for KubeSecrets<'_> {
    /// The value and version the Deployment binds for `name`; `None` when it binds none or
    /// the bound Secret is gone (the next write re-creates it).
    fn read(&self, name: &str) -> Result<Option<(SecretValue, String)>, Error> {
        if let Some(store) = self.config_store(name)? {
            return store.read(name);
        }
        let store = store_name(name);
        let Some(version) = self.bound()?.get(&store).cloned() else {
            return Ok(None);
        };
        let held = self.held(&secret_name(&store, &version))?;
        Ok(held.map(|(_, value)| (value, version)))
    }

    /// Writes a new version `opv-<store>-<random id>` and returns the id, unless the
    /// Deployment already binds this exact value (constant-time compare): then it writes
    /// nothing and returns the bound version, so a matching value never gets a second version.
    /// A lost write is reconciled by reading the new Secret back (NR-2); if that fails too, the
    /// next run writes another id and the unreferenced one is collected after a healthy rollout.
    fn write_one(&self, name: &str, value: &SecretValue, stamp: &Stamp) -> Result<String, Error> {
        if let Some(store) = self.config_store(name)? {
            return store.write_one(name, value, stamp);
        }
        // `sync` refuses every such value as a blocking row before any write (its pinned
        // plan asks this store's `refusal`), so one that reaches here is opv's bug.
        if refusal(name, value).is_some() {
            return Err(crate::cause::Cause::Bug {
                site: "kubernetes: a value the plan passed breaks a Secret rule",
            }
            .into());
        }
        if let Some((current, version)) = self.read(name)?
            && same(&current, value)
        {
            return Ok(version);
        }
        if let Some(version) = self.pending_with(name, value)? {
            return Ok(version);
        }
        let t = self.t();
        let store = store_name(name);
        let version = (self.ids)()?;
        let secret = secret_name(&store, &version);
        let what = format!("kubectl apply {} {secret}", self.kind.singular());
        let body = self.manifest(&secret, &store, value, stamp);
        let apply = [
            "apply",
            "-f",
            "-",
            "--server-side",
            "--field-manager=opv",
            "-o",
            "name",
        ];
        match self
            .k
            .call(Effect::Write, &what, &apply, Some(&body), &[])?
        {
            Outcome::Done(out) => {
                let echoed = text(&out, &what)?.trim();
                if echoed != format!("{}/{secret}", self.kind.singular()) {
                    // The apply answered without confirming the Secret it wrote.
                    let subject = crate::cause::ResourceRef {
                        kind: crate::cause::ResourceKind::Secret,
                        name: crate::cause::ResourceName::new(secret.clone()),
                        scope: Some(t.namespace.clone()),
                    };
                    return Err(super::unusable(&what, |seen| Cause::WriteOutcomeUnknown {
                        system: crate::cause::System::Kubernetes,
                        subject,
                        seen,
                    }));
                }
                Ok(version)
            }
            // Reconcile by reading back (NR-2): the Secret may have been written. The
            // read-back explains the failure, so the apply's excerpt stays (NR-31).
            _ => {
                let failed = self.k.failed(Effect::Write);
                match crate::runner::diagnosing(|| self.held(&secret)) {
                    Ok(Some((env, held))) if env == t.env && same(&held, value) => Ok(version),
                    _ => Err(self.k.explain(failed, Effect::Write, t.namespace_ref())),
                }
            }
        }
    }

    /// Deletes every version of `name` labelled for this environment that neither the
    /// Deployment nor any ReplicaSet references (FR-32). Called only after a healthy
    /// rollout; a version still in a ReplicaSet's history is kept for `rollout undo`.
    fn delete(&self, name: &str) -> Result<bool, Error> {
        if let Some(store) = self.config_store(name)? {
            return store.delete(name);
        }
        self.delete_unreferenced(name, None).map(|kept| kept == 0)
    }

    /// Deletes the superseded versions of a re-pinned `name`: every version but
    /// `keep_version` that neither the Deployment nor any ReplicaSet references (FR-32).
    /// Only Secrets labelled for this environment are ever candidates.
    fn collect_superseded(&self, name: &str, keep_version: &str) -> Result<(), Error> {
        if let Some(store) = self.config_store(name)? {
            return store.collect_superseded(name, keep_version);
        }
        self.delete_unreferenced(name, Some(keep_version)).map(drop)
    }
}

impl KubeSecrets<'_> {
    /// The versions of `name` labelled `opv-managed=<env>`, except `keep`, that no
    /// Deployment or ReplicaSet references, deleted in one call (reconciled by listing
    /// again when its outcome is lost, NR-2). Returns how many versions other than `keep`
    /// are kept because a Deployment or ReplicaSet references them.
    fn delete_unreferenced(&self, name: &str, keep: Option<&str>) -> Result<usize, Error> {
        let t = self.t();
        let store = store_name(name);
        if !valid_label_value(&store) {
            // Not a valid Kubernetes name, so opv never wrote it (06.28: no `opv explain` of
            // an env name, which it does not take).
            return Err(Cause::Guard {
                guard: Guard::NotManagedByOpv { name: name.into() },
            }
            .into());
        }
        let kept = keep.map(|v| secret_name(&store, v));
        let selector = format!("{LABEL_MANAGED}={},{LABEL_KEY}={store}", t.env);
        let versions: Vec<(String, String)> = self
            .names(&selector)?
            .into_iter()
            .filter(|(n, _)| kept.as_ref() != Some(n))
            .collect();
        if versions.is_empty() {
            return Ok(0);
        }
        let referenced = self.referenced()?;
        let doomed: Vec<&str> = versions
            .iter()
            .map(|(n, _)| n.as_str())
            .filter(|n| !referenced.contains(*n))
            .collect();
        let kept = versions.len() - doomed.len();
        if doomed.is_empty() {
            return Ok(kept);
        }
        let what = format!("kubectl delete {} ({store})", self.kind.singular());
        let mut args = vec!["delete", self.kind.singular()];
        args.extend(&doomed);
        args.push("--ignore-not-found");
        match self.k.call(Effect::Write, &what, &args, None, &[])? {
            Outcome::Done(_) => Ok(kept),
            _ => {
                let failed = self.k.failed(Effect::Write);
                match crate::runner::diagnosing(|| self.names(&selector)) {
                    Ok(left) if !left.iter().any(|(n, _)| doomed.contains(&n.as_str())) => Ok(kept),
                    _ => Err(self
                        .k
                        .explain(failed, Effect::Write, self.k.target.namespace_ref())),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use super::*;
    use crate::runner::Output;
    use crate::runner::fake::FakeRunner;

    fn sv(v: &str) -> SecretValue {
        SecretValue::new(v.to_string())
    }

    fn with_store<T>(r: &FakeRunner, f: impl FnOnce(&KubeSecrets) -> T) -> T {
        let t = target();
        f(&KubeSecrets::new(r, &t, managed()).with_ids(fixed_id))
    }

    /// The version id every test write draws.
    const ID: &str = "abcdefghij";

    fn fixed_id() -> Result<String, Error> {
        Ok(ID.to_string())
    }

    /// The Secret a test write of `NEW_KEY` creates.
    fn new_key_secret() -> String {
        secret_name("new-key", ID)
    }

    /// The bound K1 Secret's `get` output when it holds `value`.
    fn held(value: &str) -> Output {
        ok(&format!("dev\t{}", STANDARD.encode(value)))
    }

    fn stdin_text(r: &FakeRunner, i: usize) -> String {
        String::from_utf8(r.calls.borrow()[i].stdin.clone().expect("stdin")).unwrap()
    }

    /// The K1 Secret's name for value `opv-k8s-marker-1`.
    const DB_URL_SECRET: &str = "opv-fleet--api--db-url-q3vz7kd2mx";

    #[test]
    fn list_returns_one_entry_per_store_name() {
        let r = FakeRunner::new([ok(SECRET_NAMES)]);
        let names: Vec<String> = with_store(&r, |s| s.list())
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, ["FLEET__API__DB_URL"]);
    }

    #[test]
    fn list_never_asks_for_secret_data() {
        let r = FakeRunner::new([ok(SECRET_NAMES)]);
        with_store(&r, |s| s.list()).unwrap();
        assert!(!args(&r, 0).contains(&"json".to_string()));
    }

    #[test]
    fn list_selects_this_environment() {
        let r = FakeRunner::new([ok(SECRET_NAMES)]);
        with_store(&r, |s| s.list()).unwrap();
        assert!(args(&r, 0).contains(&"opv-managed=dev".to_string()));
    }

    /// A version written by an earlier sync without `--deploy` (unbound) and listed.
    const PENDING: &str = "opv-fleet--api--db-url-p3ndingv2x\tfleet--api--db-url\n";

    /// M2: a second sync without `--deploy` reuses the unbound version holding the value.
    #[test]
    fn pending_version_with_the_same_value_writes_nothing() {
        let r = FakeRunner::new([
            ok(PENDING),
            ok(DEPLOYMENT),
            held("opv-k8s-marker-1"),
            held(MARK),
        ]);
        with_store(&r, |s| {
            s.list()?;
            s.write_one("FLEET__API__DB_URL", &sv(MARK), &stamp())
        })
        .unwrap();
        assert!(!all_argv(&r).contains("apply"));
    }

    #[test]
    fn pending_version_with_the_same_value_is_returned() {
        let r = FakeRunner::new([
            ok(PENDING),
            ok(DEPLOYMENT),
            held("opv-k8s-marker-1"),
            held(MARK),
        ]);
        let v = with_store(&r, |s| {
            s.list()?;
            s.write_one("FLEET__API__DB_URL", &sv(MARK), &stamp())
        });
        assert_eq!(v.unwrap(), "p3ndingv2x");
    }

    #[test]
    fn unchanged_bound_value_writes_nothing() {
        let r = FakeRunner::new([ok(DEPLOYMENT), held("opv-k8s-marker-1")]);
        with_store(&r, |s| {
            s.write_one("FLEET__API__DB_URL", &sv("opv-k8s-marker-1"), &stamp())
        })
        .unwrap();
        assert!(!all_argv(&r).contains("apply"));
    }

    #[test]
    fn unchanged_bound_value_returns_the_bound_version() {
        let r = FakeRunner::new([ok(DEPLOYMENT), held("opv-k8s-marker-1")]);
        let v = with_store(&r, |s| {
            s.write_one("FLEET__API__DB_URL", &sv("opv-k8s-marker-1"), &stamp())
        });
        assert_eq!(v.unwrap(), "q3vz7kd2mx");
    }

    #[test]
    fn changed_bound_value_writes_a_new_version() {
        let secret = secret_name("fleet--api--db-url", ID);
        let r = FakeRunner::new([
            ok(DEPLOYMENT),
            held("opv-k8s-marker-1"),
            ok(&format!("secret/{secret}")),
        ]);
        let v = with_store(&r, |s| {
            s.write_one("FLEET__API__DB_URL", &sv("opv-k8s-marker-2"), &stamp())
        });
        assert_eq!(v.unwrap(), ID);
    }

    #[test]
    fn write_returns_the_new_id_as_version() {
        let r = FakeRunner::new([ok(DEPLOYMENT), ok(&format!("secret/{}", new_key_secret()))]);
        let v = with_store(&r, |s| s.write_one("NEW_KEY", &sv(MARK), &stamp()));
        assert_eq!(v.unwrap(), ID);
    }

    fn stamp() -> crate::domain::Stamp {
        crate::domain::provenance::fixture()
    }

    /// FR-42: the new Secret carries opv's provenance stamp as annotations.
    #[test]
    fn written_secret_carries_the_provenance_stamp() {
        let doc = written(MARK, new_version);
        assert_eq!(doc["metadata"]["annotations"]["opv-plan"], "7f3c9a1e");
    }

    /// FR-42, SR-1: the stamp never carries the value (marker test).
    #[test]
    fn provenance_annotations_never_carry_the_value() {
        let doc = written(MARK, new_version);
        assert!(!doc["metadata"]["annotations"].to_string().contains(MARK));
    }

    /// FR-42: `list` reads the latest provenance stamp back from the annotations.
    #[test]
    fn list_reads_the_provenance_stamp_from_annotations() {
        let line = format!(
            "{DB_URL_SECRET}\tfleet--api--db-url\t0.5.0\t2026-10-08T14:02:11Z\tprod\t7f3c9a1e\n"
        );
        let r = FakeRunner::new([ok(&line)]);
        let listed = with_store(&r, |s| s.list()).unwrap();
        assert_eq!(listed[0].stamp, Some(stamp()));
    }

    /// The manifest the write sent, as JSON (stdin of call 1: call 0 reads the Deployment).
    fn written(value: &str, ids: fn() -> Result<String, Error>) -> Value {
        let r = FakeRunner::new([ok(DEPLOYMENT), ok("secret/x")]);
        let t = target();
        let s = KubeSecrets::new(&r, &t, managed()).with_ids(ids);
        let _ = s.write_one("NEW_KEY", &sv(value), &stamp());
        serde_json::from_str(&stdin_text(&r, 1)).unwrap()
    }

    #[test]
    fn same_value_written_twice_gets_different_names() {
        let name = |d: Value| d["metadata"]["name"].as_str().unwrap().to_string();
        assert_ne!(
            name(written(MARK, new_version)),
            name(written(MARK, new_version))
        );
    }

    #[test]
    fn no_value_hash_prefix_appears_in_secret_metadata() {
        use sha2::{Digest as _, Sha256};
        let prefix = &hex::encode(Sha256::digest(MARK.as_bytes()))[..6];
        let meta = written(MARK, new_version)["metadata"].to_string();
        assert!(!meta.contains(prefix), "{meta}");
    }

    /// SR-1, FR-42: names, ownership labels and the provenance stamp; nothing else.
    #[test]
    fn written_metadata_is_name_namespace_ownership_labels_and_stamp_only() {
        let doc = written(MARK, fixed_id);
        assert_eq!(
            doc["metadata"],
            json!({
                "name": new_key_secret(),
                "namespace": "opv-spike",
                "labels": {"opv-managed": "dev", "opv-key": "new-key"},
                "annotations": {
                    "opv-version": "0.5.0",
                    "opv-written": "2026-10-08T14:02:11Z",
                    "opv-env": "prod",
                    "opv-plan": "7f3c9a1e",
                },
            })
        );
    }

    /// "May or may not exist" is an unknown outcome (exit 9), not a target refusal.
    #[test]
    fn an_unconfirmed_apply_is_outcome_unknown() {
        let r = FakeRunner::new([ok(DEPLOYMENT), ok("secret/x")]);
        let e = with_store(&r, |s| s.write_one("NEW_KEY", &sv(MARK), &stamp())).unwrap_err();
        assert_eq!(e.code_str(), "outcome_unknown", "{e:?}");
    }

    #[test]
    fn write_sends_manifest_on_stdin_and_no_value_in_argv() {
        let r = FakeRunner::new([ok(DEPLOYMENT), ok("secret/x")]);
        let _ = with_store(&r, |s| s.write_one("NEW_KEY", &sv(MARK), &stamp()));
        assert!(!r.argv_contains(MARK) && stdin_text(&r, 1).contains(&STANDARD.encode(MARK)));
    }

    /// A failed apply whose stderr echoes the Secret manifest shows the value masked.
    #[test]
    fn failed_apply_excerpt_masks_the_manifest_value() {
        let r = FakeRunner::default();
        r.push_with_stderr(ok(DEPLOYMENT), "");
        let manifest = format!(r#"{{"data":{{"value":"{}"}}}}"#, STANDARD.encode(MARK));
        r.push_with_stderr(
            Output::failure(1),
            &format!("error: invalid object {manifest}\n"),
        );
        r.push_with_stderr(ok(""), "");
        r.push_with_stderr(ok("context/kind-opv\n"), "");
        r.push_with_stderr(ok("v1.36"), "");
        let e = with_store(&r, |s| s.write_one("NEW_KEY", &sv(MARK), &stamp())).unwrap_err();
        assert_eq!(
            e.cause().and_then(|(_, up)| up).map(|u| u.said.clone()),
            Some(vec![
                r#"error: invalid object {"data":{"value":"********"}}"#.to_string()
            ])
        );
    }

    /// `--verbose` shows the apply's argv and result shape, never the manifest on stdin.
    #[test]
    fn verbose_write_never_shows_the_manifest() {
        let r = FakeRunner::new([ok(""), ok("secret/x")]);
        r.verbose.set(true);
        let _ = with_store(&r, |s| s.write_one("NEW_KEY", &sv(MARK), &stamp()));
        let notes = r.notes.take().join("\n");
        assert!(
            !notes.contains(&STANDARD.encode(MARK)) && !notes.contains("\"data\""),
            "{notes}"
        );
    }

    #[test]
    fn write_applies_server_side_as_opv_asking_for_names_only() {
        let r = FakeRunner::new([
            ok(DEPLOYMENT),
            ok(&format!("secret/{}\n", new_key_secret())),
        ]);
        with_store(&r, |s| s.write_one("NEW_KEY", &sv(MARK), &stamp())).unwrap();
        assert_eq!(
            args(&r, 1)[5..],
            [
                "apply",
                "-f",
                "-",
                "--server-side",
                "--field-manager=opv",
                "-o",
                "name"
            ]
        );
    }

    #[test]
    fn written_secret_is_immutable() {
        assert_eq!(written(MARK, fixed_id)["immutable"], json!(true));
    }

    #[test]
    fn written_value_round_trips_byte_exact() {
        let value = "ü\r\n  trailing\n";
        let doc = written(value, fixed_id);
        let b64 = doc["data"]["value"].as_str().unwrap();
        assert_eq!(STANDARD.decode(b64).unwrap(), value.as_bytes());
    }

    #[test]
    fn lost_write_is_reconciled_by_reading_the_secret_back() {
        let r = FakeRunner::new([ok(DEPLOYMENT)]);
        r.push_unknown("lost");
        r.responses
            .borrow_mut()
            .push_back(Ok(ok(&format!("dev\t{}", STANDARD.encode(MARK)))));
        let v = with_store(&r, |s| s.write_one("NEW_KEY", &sv(MARK), &stamp()));
        assert_eq!(v.unwrap(), ID);
    }

    #[test]
    fn lost_write_found_holding_another_value_is_not_confirmed() {
        let r = FakeRunner::new([ok(DEPLOYMENT)]);
        r.push_unknown("lost");
        r.responses.borrow_mut().extend([
            Ok(ok(&format!("dev\t{}", STANDARD.encode("other")))),
            Ok(ok("context/kind-opv")),
            Ok(ok("v1.36")),
        ]);
        assert!(with_store(&r, |s| s.write_one("NEW_KEY", &sv(MARK), &stamp())).is_err());
    }

    #[test]
    fn lost_write_still_absent_exits_9() {
        let r = FakeRunner::new([ok(DEPLOYMENT)]);
        r.push_unknown("lost");
        r.responses
            .borrow_mut()
            .extend([Ok(ok("")), Ok(ok("context/kind-opv")), Ok(ok("v1.36"))]);
        let e = with_store(&r, |s| s.write_one("NEW_KEY", &sv(MARK), &stamp())).unwrap_err();
        assert_eq!(e.exit_code(), 9);
    }

    #[test]
    fn write_error_never_names_the_value() {
        let r = FakeRunner::new([ok(DEPLOYMENT)]);
        r.push_unknown("lost");
        r.responses
            .borrow_mut()
            .extend([Ok(ok("")), Ok(ok("context/kind-opv")), Ok(ok("v1.36"))]);
        let e = with_store(&r, |s| s.write_one("NEW_KEY", &sv(MARK), &stamp())).unwrap_err();
        assert!(!err_text(&e).contains(MARK));
    }

    #[test]
    fn refused_value_makes_no_call() {
        let r = FakeRunner::default();
        let _ = with_store(&r, |s| s.write_one("NEW_KEY", &sv("a\0b"), &stamp()));
        assert!(r.calls.borrow().is_empty());
    }

    #[test]
    fn nul_byte_is_refused() {
        assert_eq!(
            refusal("NEW_KEY", &sv("a\0b")).map(|(rule, _)| rule),
            Some("kubernetes-env-nul")
        );
    }

    #[test]
    fn name_that_is_no_label_value_is_refused() {
        assert_eq!(
            refusal("_LEADING", &sv("v")).map(|(rule, _)| rule),
            Some("kubernetes-name-invalid")
        );
    }

    #[test]
    fn value_over_the_secret_limit_is_refused() {
        assert_eq!(
            refusal("BIG", &sv(&"x".repeat(VALUE_LIMIT + 1))).map(|(rule, _)| rule),
            Some("kubernetes-secret-limit")
        );
    }

    #[test]
    fn read_returns_the_bound_value_and_version() {
        let r = FakeRunner::new([
            ok(DEPLOYMENT),
            ok(&format!("dev\t{}", STANDARD.encode("opv-k8s-marker-1"))),
        ]);
        let (v, ver) = with_store(&r, |s| s.read("FLEET__API__DB_URL"))
            .unwrap()
            .unwrap();
        assert_eq!(
            (v.expose(), ver.as_str()),
            ("opv-k8s-marker-1", "q3vz7kd2mx")
        );
    }

    #[test]
    fn read_of_unbound_name_is_none() {
        let r = FakeRunner::new([ok(DEPLOYMENT)]);
        assert!(with_store(&r, |s| s.read("NEW_KEY")).unwrap().is_none());
    }

    #[test]
    fn read_of_missing_bound_secret_is_none() {
        let r = FakeRunner::new([ok(DEPLOYMENT), ok("")]);
        assert!(
            with_store(&r, |s| s.read("FLEET__API__DB_URL"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn read_of_undecodable_secret_never_names_its_content() {
        let r = FakeRunner::new([ok(DEPLOYMENT), ok(&format!("dev\t{MARK}"))]);
        let e = with_store(&r, |s| s.read("FLEET__API__DB_URL")).unwrap_err();
        let shown = crate::error::report(&e);
        assert!(
            shown.contains(DB_URL_SECRET) && !shown.contains(MARK),
            "{shown}"
        );
    }

    #[test]
    fn read_reads_the_deployment_once_per_command() {
        let r = FakeRunner::new([ok(DEPLOYMENT), ok(""), ok("")]);
        with_store(&r, |s| {
            s.read("FLEET__API__DB_URL").unwrap();
            s.read("K7").unwrap();
        });
        assert_eq!(r.calls.borrow().len(), 3);
    }

    /// The deployment no longer binds the K1 Secret; replica set api-678ff74b67 still does.
    fn unbound_deployment() -> Output {
        json(&deployment_with(|d| {
            d["spec"]["template"]["spec"]["containers"][0]["env"] = json!([]);
        }))
    }

    #[test]
    fn prune_keeps_secrets_referenced_by_any_replicaset() {
        let r = FakeRunner::new([
            ok(&format!("{DB_URL_SECRET}\tfleet--api--db-url\n")),
            unbound_deployment(),
            ok(REPLICASETS),
        ]);
        with_store(&r, |s| s.delete("FLEET__API__DB_URL")).unwrap();
        assert!(!all_argv(&r).contains("delete"));
    }

    #[test]
    fn prune_deletes_unreferenced_versions_of_the_key_only() {
        let stale = "opv-fleet--api--db-url-s7aw2ylfpc";
        let r = FakeRunner::new([
            ok(&format!(
                "{DB_URL_SECRET}\tfleet--api--db-url\n{stale}\tfleet--api--db-url\n"
            )),
            ok(DEPLOYMENT),
            ok(REPLICASETS),
            ok(&format!("secret/{stale}")),
        ]);
        with_store(&r, |s| s.delete("FLEET__API__DB_URL")).unwrap();
        assert_eq!(
            args(&r, 3)[5..],
            ["delete", "secret", stale, "--ignore-not-found"]
        );
    }

    #[test]
    fn prune_selects_by_both_ownership_labels() {
        let r = FakeRunner::new([ok("")]);
        with_store(&r, |s| s.delete("FLEET__API__DB_URL")).unwrap();
        assert!(args(&r, 0).contains(&"opv-managed=dev,opv-key=fleet--api--db-url".to_string()));
    }

    #[test]
    fn lost_delete_is_reconciled_by_listing_again() {
        let stale = "opv-fleet--api--db-url-s7aw2ylfpc";
        let r = FakeRunner::new([
            ok(&format!("{stale}\tfleet--api--db-url\n")),
            ok(DEPLOYMENT),
            ok(REPLICASETS),
        ]);
        r.push_unknown("lost");
        r.responses.borrow_mut().push_back(Ok(ok("")));
        assert!(with_store(&r, |s| s.delete("FLEET__API__DB_URL")).is_ok());
    }

    /// A re-pinned key: superseded versions nothing references are deleted, the pinned one
    /// is never a candidate (FR-32).
    #[test]
    fn collect_superseded_deletes_unreferenced_versions_but_the_pinned_one() {
        let stale = "opv-fleet--api--db-url-s7aw2ylfpc";
        let pinned = "opv-fleet--api--db-url-aaaaaaaaaa";
        let r = FakeRunner::new([
            ok(&format!(
                "{pinned}\tfleet--api--db-url\n{stale}\tfleet--api--db-url\n"
            )),
            unbound_deployment(),
            ok("{\"items\": []}"),
            ok(&format!("secret/{stale}")),
        ]);
        with_store(&r, |s| {
            s.collect_superseded("FLEET__API__DB_URL", "aaaaaaaaaa")
        })
        .unwrap();
        assert_eq!(
            args(&r, 3)[5..],
            ["delete", "secret", stale, "--ignore-not-found"]
        );
    }

    #[test]
    fn collect_superseded_keeps_versions_a_replicaset_references() {
        let r = FakeRunner::new([
            ok(&format!("{DB_URL_SECRET}\tfleet--api--db-url\n")),
            unbound_deployment(),
            ok(REPLICASETS),
        ]);
        with_store(&r, |s| {
            s.collect_superseded("FLEET__API__DB_URL", "aaaaaaaaaa")
        })
        .unwrap();
        assert!(!all_argv(&r).contains("delete"));
    }

    #[test]
    fn list_names_only_managed_env_names() {
        let r = FakeRunner::new([ok("opv-other-s7aw2ylfpc\tother\n")]);
        assert!(with_store(&r, |s| s.list()).unwrap().is_empty());
    }

    // ConfigMap store (K3, delivery-transports §11.1) ---------------------------------

    /// ConfigMap recordings (namespace `opv-rec`, env names `API__LOG_LEVEL` /
    /// `API__OTEL_RESOURCE`).
    const APPLY_CONFIGMAP_CREATED: &str = include_str!(
        "../../../tests/fixtures/kubernetes/success/05-apply-configmap-created.stdout"
    );
    const APPLY_CONFIGMAP_SECOND: &str =
        include_str!("../../../tests/fixtures/kubernetes/success/05-apply-configmap-second.stdout");
    const GET_CONFIGMAP_VALUE: &str =
        include_str!("../../../tests/fixtures/kubernetes/success/05-get-configmap-value.stdout");
    const LIST_CONFIGMAPS: &str =
        include_str!("../../../tests/fixtures/kubernetes/success/05-list-configmaps.stdout");
    const DELETE_CONFIGMAP_ONE: &str =
        include_str!("../../../tests/fixtures/kubernetes/success/17-delete-configmap-one.stdout");
    const FORBIDDEN_APPLY_CONFIGMAP: &str = include_str!(
        "../../../tests/fixtures/kubernetes/failures/08-forbidden-apply-configmap.stderr"
    );
    const FORBIDDEN_GET_CONFIGMAP: &str = include_str!(
        "../../../tests/fixtures/kubernetes/failures/08-forbidden-get-configmap.stderr"
    );

    /// The recorded Deployment with the ConfigMap version `abcdefghij` bound to
    /// `API__LOG_LEVEL`.
    fn configmap_deployment() -> Output {
        json(&deployment_with(|d| {
            d["spec"]["template"]["spec"]["containers"][0]["env"][1] = json!({
                "name": "API__LOG_LEVEL",
                "valueFrom": {
                    "configMapKeyRef": {"key": "value", "name": "opv-api--log-level-abcdefghij"},
                },
            });
        }))
    }

    fn with_configmap_store<T>(r: &FakeRunner, f: impl FnOnce(&KubeSecrets) -> T) -> T {
        let t = target();
        f(&KubeSecrets::new(r, &t, managed())
            .with_ids(fixed_id)
            .with_kind(ObjectKind::ConfigMap))
    }

    /// The manifest a ConfigMap write sent (call 1: call 0 reads the Deployment).
    fn written_configmap(value: &str) -> Value {
        let r = FakeRunner::new([ok(DEPLOYMENT), ok(APPLY_CONFIGMAP_CREATED)]);
        let _ = with_configmap_store(&r, |s| {
            s.write_one("API__OTEL_RESOURCE", &sv(value), &stamp())
        });
        serde_json::from_str(&stdin_text(&r, 1)).unwrap()
    }

    #[test]
    fn configmap_write_manifest_is_a_configmap() {
        assert_eq!(written_configmap(MARK)["kind"], json!("ConfigMap"));
    }

    #[test]
    fn configmap_write_manifest_has_no_type() {
        assert!(written_configmap(MARK).get("type").is_none());
    }

    #[test]
    fn configmap_write_holds_the_plain_value_not_base64() {
        assert_eq!(written_configmap(MARK)["data"]["value"], json!(MARK));
    }

    #[test]
    fn configmap_write_sends_the_value_on_stdin_only() {
        let r = FakeRunner::new([ok(DEPLOYMENT), ok(APPLY_CONFIGMAP_CREATED)]);
        let _ = with_configmap_store(&r, |s| {
            s.write_one("API__OTEL_RESOURCE", &sv(MARK), &stamp())
        });
        assert!(!r.argv_contains(MARK) && stdin_text(&r, 1).contains(MARK));
    }

    #[test]
    fn unchanged_configmap_value_writes_nothing() {
        let r = FakeRunner::new([configmap_deployment(), ok(GET_CONFIGMAP_VALUE)]);
        let _ = with_configmap_store(&r, |s| {
            s.write_one("API__LOG_LEVEL", &sv("S7MARKER-log-level"), &stamp())
        });
        assert!(!all_argv(&r).contains("apply"));
    }

    #[test]
    fn changed_configmap_value_writes_a_new_version() {
        let r = FakeRunner::new([
            configmap_deployment(),
            ok(GET_CONFIGMAP_VALUE),
            ok(APPLY_CONFIGMAP_SECOND),
        ]);
        let v = with_configmap_store(&r, |s| {
            s.write_one("API__LOG_LEVEL", &sv("S7MARKER-log-level-2"), &stamp())
        });
        assert_eq!(v.unwrap(), ID);
    }

    #[test]
    fn superseded_configmap_versions_are_deleted_with_delete_configmap() {
        let r = FakeRunner::new([
            ok(LIST_CONFIGMAPS),
            ok(DEPLOYMENT),
            ok(REPLICASETS),
            ok(DELETE_CONFIGMAP_ONE),
        ]);
        let _ = with_configmap_store(&r, |s| s.delete_unreferenced("API__LOG_LEVEL", None));
        assert!(all_argv(&r).contains("delete configmap"));
    }

    /// K3: on a `config = "configmap"` target a config key is read from the ConfigMap
    /// store (only that store reads the Deployment).
    #[test]
    fn config_route_reads_a_config_key_from_the_configmap_store() {
        let r = FakeRunner::new([configmap_deployment(), ok(GET_CONFIGMAP_VALUE)]);
        let t = target();
        let config = KubeSecrets::new(&r, &t, managed())
            .with_ids(fixed_id)
            .with_kind(ObjectKind::ConfigMap);
        let names = BTreeSet::from(["API__LOG_LEVEL".to_string()]);
        let store = KubeSecrets::new(&r, &t, managed()).with_config(config, names);
        assert!(store.read("API__LOG_LEVEL").unwrap().is_some());
    }

    /// K3: on a `config = "configmap"` target a secret key nothing binds yet is still
    /// written as a Secret, never a ConfigMap.
    #[test]
    fn config_route_writes_a_new_secret_key_as_a_secret() {
        let r = FakeRunner::new([ok(DEPLOYMENT), ok("secret/x")]);
        let t = target();
        let config = KubeSecrets::new(&r, &t, managed())
            .with_ids(fixed_id)
            .with_kind(ObjectKind::ConfigMap);
        let names = BTreeSet::from(["API__LOG_LEVEL".to_string()]);
        let store = KubeSecrets::new(&r, &t, managed())
            .with_ids(fixed_id)
            .with_config(config, names);
        let _ = store.write_one("NEW_KEY", &sv(MARK), &stamp());
        let sent: Value = serde_json::from_str(&stdin_text(&r, 1)).unwrap();
        assert_eq!(sent["kind"], json!("Secret"));
    }

    #[test]
    fn forbidden_configmap_apply_is_a_permission_denied() {
        let r = FakeRunner::default();
        r.push_with_stderr(ok(DEPLOYMENT), "");
        r.push_with_stderr(Output::failure(1), FORBIDDEN_APPLY_CONFIGMAP);
        (0..crate::runner::READ_ATTEMPTS)
            .for_each(|_| r.push_with_stderr(Output::failure(1), FORBIDDEN_GET_CONFIGMAP));
        let e = with_configmap_store(&r, |s| s.write_one("API__LOG_LEVEL", &sv(MARK), &stamp()))
            .unwrap_err();
        assert_eq!(e.code_str(), "permission_denied");
    }
}
