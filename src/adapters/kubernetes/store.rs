//! Kubernetes Secrets as a [`PinnedStore`] (FR-29, FR-32, FR-38).
//!
//! | op | argv (after the scope flags) | effect |
//! |---|---|---|
//! | `list` | `get secret -l opv-managed=<env> -o jsonpath=<name, opv-key>` | read |
//! | `read` | `get deployment <d> -o json`, then `get secret <s> --ignore-not-found -o jsonpath=<opv-managed, data.value>` | read |
//! | `write_one` | `get secret <s> --ignore-not-found -o jsonpath=<name, opv-managed>`, then if absent `apply -f - --server-side --field-manager=opv -o name` (manifest on stdin) | read, write |
//! | `delete` | `get secret -l opv-managed=<env>,opv-key=<store> …`, `get deployment`, `get replicasets -o json`, then `delete secret <names…> --ignore-not-found` | reads, write |
//!
//! Lists never ask for `-o json` (it returns `data`, K2) and writes ask for `-o name` (`-o
//! json` echoes `data`, K1). The desired version is computed from the value hash, so
//! compare-before-write is a name lookup: an existing Secret is never re-written.

use std::cell::OnceCell;
use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::{
    Effect, KubeTarget, Kubectl, LABEL_KEY, LABEL_MANAGED, VALUE_KEY, container_env,
    container_index, secret_name, secret_ref, split_secret_name, store_name, text,
    valid_label_value, version_of,
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
const OWNER_PATH: &str = r#"jsonpath={.metadata.name}{"\t"}{.metadata.labels.opv-managed}"#;
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
        }
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

    /// The `opv-managed` label of Secret `name`, `Some("")` when unlabelled, `None` when
    /// it does not exist.
    fn owner(&self, name: &str) -> Result<Option<String>, Error> {
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
                OWNER_PATH,
            ],
            None,
            &format!("get secret {name}"),
        )?;
        let s = text(&out, &what)?.trim_end_matches('\n');
        Ok(match s.split_once('\t') {
            Some((n, env)) if n == name => Some(env.to_string()),
            _ if s.is_empty() => None,
            _ => Some(String::new()),
        })
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

    /// Every string in the Deployment and in every ReplicaSet of the namespace: a Secret
    /// named by any of them is still referenced (FR-32; superset of "its ReplicaSets").
    fn referenced(&self) -> Result<&BTreeSet<String>, Error> {
        if let Some(seen) = self.referenced.get() {
            return Ok(seen);
        }
        let mut seen = BTreeSet::new();
        strings(&self.k.get_deployment()?, &mut seen);
        let what = "kubectl get replicasets";
        let out = self.k.run(
            Effect::Read,
            what,
            &["get", "replicasets", "-o", "json"],
            None,
            "get replicasets",
        )?;
        strings(&super::parse_json(&out, what)?, &mut seen);
        Ok(self.referenced.get_or_init(|| seen))
    }
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
        let secret = secret_name(&store, &version);
        let what = format!("kubectl get secret {secret}");
        let out = self.k.run(
            Effect::Read,
            &what,
            &[
                "get",
                "secret",
                &secret,
                "--ignore-not-found",
                "-o",
                VALUE_PATH,
            ],
            None,
            &format!("get secret {secret} -o name"),
        )?;
        let Some((_, b64)) = text(&out, &what)?.split_once('\t') else {
            return Ok(None);
        };
        let corrupt = || {
            Error::Target(format!(
                "secret {secret} does not hold the value its name promises (it was replaced \
                 outside opv); nothing was changed\n  next: inspect it with `{}`; to repair, \
                 delete it and re-run at once (pods starting in between cannot read it)",
                self.k
                    .command(&format!("get secret {secret} --show-labels"))
            ))
        };
        let bytes = Zeroizing::new(STANDARD.decode(b64.trim()).map_err(|_| corrupt())?);
        let value = std::str::from_utf8(&bytes).map_err(|_| corrupt())?;
        let value = SecretValue::new(value.to_string());
        if version_of(&value) != version {
            return Err(corrupt());
        }
        Ok(Some((value, version)))
    }

    /// Writes `opv-<store>-<hash>` unless it exists; returns the hash (the version). An
    /// existing Secret of this environment is never re-written; one labelled for another
    /// environment (or none) is refused (FR-32).
    fn write_one(&self, name: &str, value: &SecretValue) -> Result<String, Error> {
        if let Some((rule, reason)) = refusal(name, value) {
            return Err(Error::Policy(format!("{name}: {rule}: {reason}")));
        }
        let t = self.t();
        let store = store_name(name);
        let version = version_of(value);
        let secret = secret_name(&store, &version);
        match self.owner(&secret)? {
            Some(env) if env == t.env => return Ok(version),
            Some(env) => {
                let owner = if env.is_empty() {
                    "no opv environment (it has no opv-managed label)".to_string()
                } else {
                    format!("opv environment \"{env}\"")
                };
                return Err(Error::Target(format!(
                    "secret {secret} in namespace {} belongs to {owner}, not \"{}\"; nothing \
                     was written\n  next: give each environment its own namespace, or {}",
                    t.namespace,
                    t.env,
                    self.k
                        .command(&format!("label secret {secret} {LABEL_MANAGED}={}", t.env))
                )));
            }
            None => {}
        }
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
            other => match self.owner(&secret) {
                Ok(Some(env)) if env == t.env => Ok(version),
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
        f(&KubeSecrets::new(r, &t, managed()))
    }

    fn stdin_text(r: &FakeRunner, i: usize) -> String {
        String::from_utf8(r.calls.borrow()[i].stdin.clone().expect("stdin")).unwrap()
    }

    /// The K1 Secret's name for value `opv-k8s-marker-1`.
    const DB_URL_SECRET: &str = "opv-fleet--api--db-url-f85b191f16";

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
    fn write_is_skipped_when_hash_named_secret_exists() {
        let r = FakeRunner::new([ok(&format!("{DB_URL_SECRET}\tdev"))]);
        with_store(&r, |s| {
            s.write_one("FLEET__API__DB_URL", &sv("opv-k8s-marker-1"))
        })
        .unwrap();
        assert_eq!(r.calls.borrow().len(), 1);
    }

    #[test]
    fn write_returns_the_hash_as_version() {
        let r = FakeRunner::new([ok(&format!("{DB_URL_SECRET}\tdev"))]);
        let v = with_store(&r, |s| {
            s.write_one("FLEET__API__DB_URL", &sv("opv-k8s-marker-1"))
        });
        assert_eq!(v.unwrap(), "f85b191f16");
    }

    #[test]
    fn write_sends_manifest_on_stdin_and_no_value_in_argv() {
        let r = FakeRunner::new([ok(""), ok("secret/x")]);
        let _ = with_store(&r, |s| s.write_one("NEW_KEY", &sv(MARK)));
        assert!(!r.argv_contains(MARK) && stdin_text(&r, 1).contains(&STANDARD.encode(MARK)));
    }

    #[test]
    fn write_applies_server_side_as_opv_asking_for_names_only() {
        let name = secret_name("new-key", &version_of(&sv(MARK)));
        let r = FakeRunner::new([ok(""), ok(&format!("secret/{name}\n"))]);
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
    fn written_secret_is_immutable_and_labelled() {
        let name = secret_name("new-key", &version_of(&sv(MARK)));
        let r = FakeRunner::new([ok(""), ok(&format!("secret/{name}"))]);
        with_store(&r, |s| s.write_one("NEW_KEY", &sv(MARK))).unwrap();
        let doc: Value = serde_json::from_str(&stdin_text(&r, 1)).unwrap();
        assert_eq!(
            (&doc["immutable"], &doc["metadata"]["labels"]),
            (
                &json!(true),
                &json!({"opv-managed": "dev", "opv-key": "new-key"})
            )
        );
    }

    #[test]
    fn written_value_round_trips_byte_exact() {
        let value = "ü\r\n  trailing\n";
        let name = secret_name("new-key", &version_of(&sv(value)));
        let r = FakeRunner::new([ok(""), ok(&format!("secret/{name}"))]);
        with_store(&r, |s| s.write_one("NEW_KEY", &sv(value))).unwrap();
        let doc: Value = serde_json::from_str(&stdin_text(&r, 1)).unwrap();
        let b64 = doc["data"]["value"].as_str().unwrap();
        assert_eq!(STANDARD.decode(b64).unwrap(), value.as_bytes());
    }

    #[test]
    fn write_refuses_secret_owned_by_another_environment() {
        let r = FakeRunner::new([ok(&format!("{DB_URL_SECRET}\tprod"))]);
        let e = with_store(&r, |s| {
            s.write_one("FLEET__API__DB_URL", &sv("opv-k8s-marker-1"))
        });
        assert!(matches!(e, Err(Error::Target(m)) if m.contains("\"prod\"")));
    }

    #[test]
    fn lost_write_is_reconciled_by_reading_the_secret_back() {
        let name = secret_name("new-key", &version_of(&sv(MARK)));
        let r = FakeRunner::new([ok("")]);
        r.push_unknown("lost");
        r.responses
            .borrow_mut()
            .push_back(Ok(ok(&format!("{name}\tdev"))));
        let v = with_store(&r, |s| s.write_one("NEW_KEY", &sv(MARK)));
        assert_eq!(v.unwrap(), version_of(&sv(MARK)));
    }

    #[test]
    fn lost_write_still_absent_exits_9() {
        let r = FakeRunner::new([ok("")]);
        r.push_unknown("lost");
        r.responses
            .borrow_mut()
            .extend([Ok(ok("")), Ok(ok("context/kind-opv")), Ok(ok("v1.36"))]);
        let e = with_store(&r, |s| s.write_one("NEW_KEY", &sv(MARK))).unwrap_err();
        assert_eq!(e.exit_code(), 9);
    }

    #[test]
    fn write_error_never_names_the_value() {
        let r = FakeRunner::new([ok("")]);
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
            ("opv-k8s-marker-1", "f85b191f16")
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
    fn read_refuses_content_that_does_not_match_its_hash() {
        let r = FakeRunner::new([
            ok(DEPLOYMENT),
            ok(&format!("dev\t{}", STANDARD.encode(MARK))),
        ]);
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
        let stale = "opv-fleet--api--db-url-0123456789";
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
        let stale = "opv-fleet--api--db-url-0123456789";
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
        let stale = "opv-fleet--api--db-url-0123456789";
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
        let r = FakeRunner::new([ok("opv-other-0123456789\tother\n")]);
        assert!(with_store(&r, |s| s.list()).unwrap().is_empty());
    }
}
