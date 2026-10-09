//! Kubernetes Secrets as a [`PinnedStore`] (FR-29, FR-32, FR-38).
//!
//! | op | argv (after the scope flags) | effect |
//! |---|---|---|
//! | `list` | `get secret -l opv-managed=<env> -o jsonpath=<name, opv-key>` | read |
//! | `read` | `get deployment <d> -o json`, then `get secret <s> --ignore-not-found -o jsonpath=<opv-managed, data.value>` | read |
//! | `write_one` | `read` (above); if the bound value differs or none is bound, `apply -f - --server-side --field-manager=opv -o name` of a new `opv-<store>-<random id>` (manifest on stdin); a lost apply is reconciled with `get secret <s> --ignore-not-found -o jsonpath=<opv-managed, data.value>` | reads, write |
//! | `delete` | `get secret -l opv-managed=<env>,opv-key=<store> …`, `get deployment`, `get replicasets -o json`, then `delete secret <names…> --ignore-not-found` | reads, write |
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
    container_index, new_version, secret_name, secret_ref, split_secret_name, store_name, text,
    valid_label_value,
};
use crate::domain::SecretValue;
use crate::domain::plan::StoreEntry;
use crate::error::Error;
use crate::ports::{PinnedStore, Store};
use crate::runner::{CommandRunner, Outcome};

/// Largest value opv writes: a Secret object is limited to 1 MiB, minus room for metadata.
pub const VALUE_LIMIT: usize = 1024 * 1024 - 16 * 1024;

const LIST_PATH: &str =
    r#"jsonpath={range .items[*]}{.metadata.name}{"\t"}{.metadata.labels.opv-key}{"\n"}{end}"#;
const VALUE_PATH: &str = r#"jsonpath={.metadata.labels.opv-managed}{"\t"}{.data.value}"#;

/// The Secrets of one Kubernetes target.
pub struct KubeSecrets<'a> {
    k: Kubectl<'a>,
    /// Managed env names (from the template, FR-8): the names this port speaks.
    managed: BTreeSet<String>,
    /// store name → version the Deployment binds, read once per command.
    bound: OnceCell<BTreeMap<String, String>>,
    /// Every string of the Deployment and its ReplicaSets, read once, after the healthy
    /// rollout that precedes any delete.
    referenced: OnceCell<BTreeSet<String>>,
    /// Source of new version ids: the OS RNG ([`new_version`]); fixed in tests.
    ids: fn() -> Result<String, Error>,
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
            ids: new_version,
        }
    }

    /// The same store drawing version ids from `ids` (tests pin them).
    #[cfg(test)]
    pub(crate) fn with_ids(mut self, ids: fn() -> Result<String, Error>) -> Self {
        self.ids = ids;
        self
    }

    fn t(&self) -> &KubeTarget {
        self.k.target
    }

    /// `(secret name, store name)` of every opv Secret matching `selector`. Entries whose
    /// name is not `opv-<opv-key>-<version>` are ignored (NR-6).
    fn names(&self, selector: &str) -> Result<Vec<(String, String)>, Error> {
        let what = "kubectl get secret";
        let out = self.k.run(
            Effect::Read,
            what,
            &["get", "secret", "-l", selector, "-o", LIST_PATH],
            None,
            "auth can-i list secrets",
        )?;
        Ok(text(&out, what)?
            .lines()
            .filter_map(|line| {
                let (name, key) = line.split_once('\t')?;
                let (store, _) = split_secret_name(name)?;
                (store == key).then(|| (name.to_string(), key.to_string()))
            })
            .collect())
    }

    /// `(opv-managed label, value)` of Secret `name` (`""` when unlabelled), `None` when it
    /// does not exist. The value is decoded into zeroized memory only (K2).
    fn held(&self, name: &str) -> Result<Option<(String, SecretValue)>, Error> {
        let what = format!("kubectl get secret {name}");
        let out = self.k.run(
            Effect::Read,
            &what,
            &[
                "get",
                "secret",
                name,
                "--ignore-not-found",
                "-o",
                VALUE_PATH,
            ],
            None,
            &format!("get secret {name} -o name"),
        )?;
        let Some((env, b64)) = text(&out, &what)?.split_once('\t') else {
            return Ok(None);
        };
        let unreadable = || {
            Error::Target(format!(
                "secret {name} does not hold a UTF-8 value under data.{VALUE_KEY} (it was \
                 changed outside opv); nothing was changed\n  next: inspect it with `{}`",
                self.k.command(&format!("get secret {name} --show-labels"))
            ))
        };
        let bytes = Zeroizing::new(STANDARD.decode(b64.trim()).map_err(|_| unreadable())?);
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
            .filter_map(secret_ref)
            .filter_map(split_secret_name)
            .map(|(s, v)| (s.to_string(), v.to_string()))
            .collect();
        Ok(self.bound.get_or_init(|| map))
    }

    /// The immutable Secret manifest for `value`; the only place a value is encoded.
    fn manifest(&self, name: &str, store: &str, value: &SecretValue) -> Zeroizing<Vec<u8>> {
        let t = self.t();
        let head = json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": name,
                "namespace": t.namespace,
                "labels": { LABEL_MANAGED: t.env, LABEL_KEY: store },
            },
            "immutable": true,
            "type": "Opaque",
        })
        .to_string();
        let b64_len = value.expose().len().div_ceil(3) * 4;
        let mut doc = Zeroizing::new(String::with_capacity(head.len() + b64_len + 32));
        doc.push_str(&head[..head.len() - 1]);
        doc.push_str(&format!(",\"data\":{{\"{VALUE_KEY}\":\""));
        STANDARD.encode_string(value.expose().as_bytes(), &mut doc);
        doc.push_str("\"}}");
        Zeroizing::new(std::mem::take(&mut *doc).into_bytes())
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
        "get replicasets",
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
        let stores: BTreeSet<String> = self
            .names(&selector)?
            .into_iter()
            .map(|(_, store)| store)
            .collect();
        Ok(self
            .managed
            .iter()
            .filter(|n| stores.contains(&store_name(n)))
            .map(|n| StoreEntry {
                name: n.clone(),
                version: None,
                pending: false,
            })
            .collect())
    }

    fn refusal(&self, name: &str, value: &SecretValue) -> Option<(&'static str, &'static str)> {
        refusal(name, value)
    }
}

impl PinnedStore for KubeSecrets<'_> {
    /// The value and version the Deployment binds for `name`; `None` when it binds none or
    /// the bound Secret is gone (the next write re-creates it).
    fn read(&self, name: &str) -> Result<Option<(SecretValue, String)>, Error> {
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
    fn write_one(&self, name: &str, value: &SecretValue) -> Result<String, Error> {
        if let Some((rule, reason)) = refusal(name, value) {
            return Err(Error::Policy(format!("{name}: {rule}: {reason}")));
        }
        if let Some((current, version)) = self.read(name)?
            && same(&current, value)
        {
            return Ok(version);
        }
        let t = self.t();
        let store = store_name(name);
        let version = (self.ids)()?;
        let secret = secret_name(&store, &version);
        let what = format!("kubectl apply secret {secret}");
        let body = self.manifest(&secret, &store, value);
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
                if echoed != format!("secret/{secret}") {
                    return Err(Error::Target(format!(
                        "{what} did not confirm the secret it wrote; it may or may not \
                         exist and nothing else was changed\n  next: check with `{}`, then \
                         re-run the same command",
                        self.k.command(&format!("get secret {secret} -o name"))
                    )));
                }
                Ok(version)
            }
            // Reconcile by reading back (NR-2): the Secret may have been written.
            other => match self.held(&secret) {
                Ok(Some((env, held))) if env == t.env && same(&held, value) => Ok(version),
                _ => Err(self
                    .k
                    .fail(Effect::Write, &what, other, "auth can-i create secrets")),
            },
        }
    }

    /// Deletes every version of `name` labelled for this environment that neither the
    /// Deployment nor any ReplicaSet references (FR-32). Called only after a healthy
    /// rollout; a version still in a ReplicaSet's history is kept for `rollout undo`.
    fn delete(&self, name: &str) -> Result<(), Error> {
        self.delete_unreferenced(name, None)
    }

    /// Deletes the superseded versions of a re-pinned `name`: every version but
    /// `keep_version` that neither the Deployment nor any ReplicaSet references (FR-32).
    /// Only Secrets labelled for this environment are ever candidates.
    fn collect_superseded(&self, name: &str, keep_version: &str) -> Result<(), Error> {
        self.delete_unreferenced(name, Some(keep_version))
    }
}

impl KubeSecrets<'_> {
    /// The versions of `name` labelled `opv-managed=<env>`, except `keep`, that no
    /// Deployment or ReplicaSet references, deleted in one call (reconciled by listing
    /// again when its outcome is lost, NR-2).
    fn delete_unreferenced(&self, name: &str, keep: Option<&str>) -> Result<(), Error> {
        let t = self.t();
        let store = store_name(name);
        if !valid_label_value(&store) {
            return Err(Error::Config(format!(
                "{name}: kubernetes-name-invalid: not a valid Kubernetes name, so opv never \
                 wrote it; nothing was deleted\n  next: run opv explain {name}"
            )));
        }
        let kept = keep.map(|v| secret_name(&store, v));
        let selector = format!("{LABEL_MANAGED}={},{LABEL_KEY}={store}", t.env);
        let versions: Vec<(String, String)> = self
            .names(&selector)?
            .into_iter()
            .filter(|(n, _)| kept.as_ref() != Some(n))
            .collect();
        if versions.is_empty() {
            return Ok(());
        }
        let referenced = self.referenced()?;
        let doomed: Vec<&str> = versions
            .iter()
            .map(|(n, _)| n.as_str())
            .filter(|n| !referenced.contains(*n))
            .collect();
        if doomed.is_empty() {
            return Ok(());
        }
        let what = format!("kubectl delete secret ({store})");
        let mut args = vec!["delete", "secret"];
        args.extend(&doomed);
        args.push("--ignore-not-found");
        match self.k.call(Effect::Write, &what, &args, None, &[])? {
            Outcome::Done(_) => Ok(()),
            other => match self.names(&selector) {
                Ok(left) if !left.iter().any(|(n, _)| doomed.contains(&n.as_str())) => Ok(()),
                _ => Err(self
                    .k
                    .fail(Effect::Write, &what, other, "auth can-i delete secrets")),
            },
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

    #[test]
    fn unchanged_bound_value_writes_nothing() {
        let r = FakeRunner::new([ok(DEPLOYMENT), held("opv-k8s-marker-1")]);
        with_store(&r, |s| {
            s.write_one("FLEET__API__DB_URL", &sv("opv-k8s-marker-1"))
        })
        .unwrap();
        assert!(!all_argv(&r).contains("apply"));
    }

    #[test]
    fn unchanged_bound_value_returns_the_bound_version() {
        let r = FakeRunner::new([ok(DEPLOYMENT), held("opv-k8s-marker-1")]);
        let v = with_store(&r, |s| {
            s.write_one("FLEET__API__DB_URL", &sv("opv-k8s-marker-1"))
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
            s.write_one("FLEET__API__DB_URL", &sv("opv-k8s-marker-2"))
        });
        assert_eq!(v.unwrap(), ID);
    }

    #[test]
    fn write_returns_the_new_id_as_version() {
        let r = FakeRunner::new([ok(DEPLOYMENT), ok(&format!("secret/{}", new_key_secret()))]);
        let v = with_store(&r, |s| s.write_one("NEW_KEY", &sv(MARK)));
        assert_eq!(v.unwrap(), ID);
    }

    /// The manifest the write sent, as JSON (stdin of call 1: call 0 reads the Deployment).
    fn written(value: &str, ids: fn() -> Result<String, Error>) -> Value {
        let r = FakeRunner::new([ok(DEPLOYMENT), ok("secret/x")]);
        let t = target();
        let s = KubeSecrets::new(&r, &t, managed()).with_ids(ids);
        let _ = s.write_one("NEW_KEY", &sv(value));
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

    #[test]
    fn written_metadata_is_name_namespace_and_ownership_labels_only() {
        let doc = written(MARK, fixed_id);
        assert_eq!(
            doc["metadata"],
            json!({
                "name": new_key_secret(),
                "namespace": "opv-spike",
                "labels": {"opv-managed": "dev", "opv-key": "new-key"},
            })
        );
    }

    #[test]
    fn write_sends_manifest_on_stdin_and_no_value_in_argv() {
        let r = FakeRunner::new([ok(DEPLOYMENT), ok("secret/x")]);
        let _ = with_store(&r, |s| s.write_one("NEW_KEY", &sv(MARK)));
        assert!(!r.argv_contains(MARK) && stdin_text(&r, 1).contains(&STANDARD.encode(MARK)));
    }

    #[test]
    fn write_applies_server_side_as_opv_asking_for_names_only() {
        let r = FakeRunner::new([
            ok(DEPLOYMENT),
            ok(&format!("secret/{}\n", new_key_secret())),
        ]);
        with_store(&r, |s| s.write_one("NEW_KEY", &sv(MARK))).unwrap();
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
        let v = with_store(&r, |s| s.write_one("NEW_KEY", &sv(MARK)));
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
        assert!(with_store(&r, |s| s.write_one("NEW_KEY", &sv(MARK))).is_err());
    }

    #[test]
    fn lost_write_still_absent_exits_9() {
        let r = FakeRunner::new([ok(DEPLOYMENT)]);
        r.push_unknown("lost");
        r.responses
            .borrow_mut()
            .extend([Ok(ok("")), Ok(ok("context/kind-opv")), Ok(ok("v1.36"))]);
        let e = with_store(&r, |s| s.write_one("NEW_KEY", &sv(MARK))).unwrap_err();
        assert_eq!(e.exit_code(), 9);
    }

    #[test]
    fn write_error_never_names_the_value() {
        let r = FakeRunner::new([ok(DEPLOYMENT)]);
        r.push_unknown("lost");
        r.responses
            .borrow_mut()
            .extend([Ok(ok("")), Ok(ok("context/kind-opv")), Ok(ok("v1.36"))]);
        let e = with_store(&r, |s| s.write_one("NEW_KEY", &sv(MARK))).unwrap_err();
        assert!(!err_text(&e).contains(MARK));
    }

    #[test]
    fn refused_value_makes_no_call() {
        let r = FakeRunner::default();
        let _ = with_store(&r, |s| s.write_one("NEW_KEY", &sv("a\0b")));
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
        assert!(matches!(e, Error::Target(m) if m.contains(DB_URL_SECRET) && !m.contains(MARK)));
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
}
