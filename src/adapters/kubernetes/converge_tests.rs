//! Interruption matrix for the Kubernetes adapters (NR-1, resilience §4): a stateful fake
//! cluster interprets the adapters' `kubectl` calls; a pinned-flow sync (write versions →
//! repin → await health → prune) is interrupted at every call, with and without the call's
//! effect, then re-run. The end state must equal the uninterrupted run's, and no state may
//! bind a missing Secret.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};

use super::testutil::{DEPLOYMENT, REPLICASETS, managed, target};
use super::{KubeDeployment, KubeSecrets, store_name};
use crate::domain::{Binding, Health, RuntimeChange, SecretValue};
use crate::error::Error;
use crate::ports::{PinnedRuntime, PinnedStore};
use crate::runner::{Call, CommandRunner, Outcome, Output};

const STALE: &str = "opv-fleet--api--db-url-0123456789";
const DESIRED: [(&str, &str); 2] = [
    ("FLEET__API__DB_URL", "opv-k8s-marker-2"),
    ("NEW_KEY", "opv-k8s-marker-3"),
];
const CONFIG: (&str, &str) = ("LOG_LEVEL", "opv-k8s-config-2");

#[derive(Clone, Copy, Debug, PartialEq)]
enum Cut {
    /// The call took effect, its result was lost.
    AfterEffect,
    /// The call was killed before it took effect.
    BeforeEffect,
}

/// Secret name → (opv-managed, opv-key, base64 data).
type Secrets = BTreeMap<String, (String, String, String)>;

struct Cluster {
    secrets: RefCell<Secrets>,
    deployment: RefCell<Value>,
    replicasets: RefCell<Vec<Value>>,
    /// Pods of the newest ReplicaSet never start (K4).
    broken_image: bool,
    calls: Cell<usize>,
    cut: Cell<Option<(usize, Cut)>>,
    /// A Deployment template referenced a Secret that did not exist.
    dangling: Cell<bool>,
    argv: RefCell<Vec<Vec<String>>>,
}

impl Cluster {
    fn new() -> Self {
        let rs: Value = serde_json::from_str(REPLICASETS).unwrap();
        let mut secrets = Secrets::new();
        let mut add = |name: &str, key: &str, value: &str| {
            secrets.insert(
                name.into(),
                ("dev".into(), key.into(), STANDARD.encode(value)),
            );
        };
        add(
            "opv-fleet--api--db-url-f85b191f16",
            "fleet--api--db-url",
            "opv-k8s-marker-1",
        );
        add("opv-k7-73571418f2", "k7", "opv-k8s-k7");
        add(STALE, "fleet--api--db-url", "opv-k8s-stale");
        Self {
            secrets: RefCell::new(secrets),
            deployment: RefCell::new(serde_json::from_str(DEPLOYMENT).unwrap()),
            replicasets: RefCell::new(rs["items"].as_array().unwrap().clone()),
            broken_image: false,
            calls: Cell::new(0),
            cut: Cell::new(None),
            dangling: Cell::new(false),
            argv: RefCell::new(Vec::new()),
        }
    }

    /// What `sync` leaves behind: Secret names and the managed env entries.
    fn state(&self) -> (BTreeSet<String>, Vec<Value>) {
        let env = self.deployment.borrow()["spec"]["template"]["spec"]["containers"][0]["env"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        (self.secrets.borrow().keys().cloned().collect(), env)
    }

    fn template_refs(template: &Value) -> Vec<String> {
        template["spec"]["containers"][0]["env"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|e| e.pointer("/valueFrom/secretKeyRef/name")?.as_str())
            .map(String::from)
            .collect()
    }

    fn check_dangling(&self) {
        let d = self.deployment.borrow();
        let secrets = self.secrets.borrow();
        if Self::template_refs(&d["spec"]["template"])
            .iter()
            .any(|n| !secrets.contains_key(n))
        {
            self.dangling.set(true);
        }
    }

    /// Run one kubectl call against the state: (exit status, stdout).
    fn exec(&self, args: &[String], stdin: Option<&[u8]>) -> (i32, String) {
        assert_eq!(args[0], "--context", "unscoped call: {args:?}");
        assert_eq!(args[2], "--namespace", "unscoped call: {args:?}");
        let a: Vec<&str> = args[5..].iter().map(String::as_str).collect();
        let out = match a.as_slice() {
            ["get", "secret", "-l", sel, "-o", _] => {
                let mut want = BTreeMap::new();
                for kv in sel.split(',') {
                    let (k, v) = kv.split_once('=').unwrap();
                    want.insert(k, v);
                }
                self.secrets
                    .borrow()
                    .iter()
                    .filter(|(_, (env, key, _))| {
                        want.get("opv-managed") == Some(&env.as_str())
                            && want.get("opv-key").is_none_or(|k| *k == key)
                    })
                    .map(|(n, (_, key, _))| format!("{n}\t{key}\n"))
                    .collect()
            }
            ["get", "secret", name, "--ignore-not-found", "-o", path] => {
                match self.secrets.borrow().get(*name) {
                    None => String::new(),
                    Some((env, _, data)) if path.contains(".data.value") => {
                        format!("{env}\t{data}")
                    }
                    Some((env, _, _)) => format!("{name}\t{env}"),
                }
            }
            [
                "apply",
                "-f",
                "-",
                "--server-side",
                "--field-manager=opv",
                "-o",
                "name",
            ] => {
                let doc: Value = serde_json::from_slice(stdin.unwrap()).unwrap();
                let name = doc["metadata"]["name"].as_str().unwrap().to_string();
                let labels = &doc["metadata"]["labels"];
                let entry = (
                    labels["opv-managed"].as_str().unwrap().to_string(),
                    labels["opv-key"].as_str().unwrap().to_string(),
                    doc["data"]["value"].as_str().unwrap().to_string(),
                );
                let mut secrets = self.secrets.borrow_mut();
                match secrets.get(&name) {
                    Some(old) if *old != entry => return (1, String::new()),
                    _ => secrets.insert(name.clone(), entry),
                };
                format!("secret/{name}\n")
            }
            ["get", "deployment", "api", "-o", "json"] => self.deployment.borrow().to_string(),
            ["replace", "-f", "-", "-o", _] => return self.replace(stdin.unwrap()),
            ["get", "replicasets", "-o", "json"] => {
                json!({ "items": *self.replicasets.borrow() }).to_string()
            }
            ["get", "pods", "-l", _, "-o", _] => {
                let rs = self.replicasets.borrow();
                let newest = rs.last().unwrap()["metadata"]["name"].as_str().unwrap();
                let reason = if self.broken_image {
                    "CreateContainerConfigError "
                } else {
                    ""
                };
                format!("{newest}-pod\t{newest}\t{reason}\n")
            }
            ["delete", "secret", rest @ ..] => {
                let d = self.deployment.borrow();
                let live = Self::template_refs(&d["spec"]["template"]);
                for n in rest.iter().filter(|n| !n.starts_with("--")) {
                    if live.iter().any(|l| l == n) {
                        self.dangling.set(true);
                    }
                    self.secrets.borrow_mut().remove(*n);
                }
                String::new()
            }
            ["auth", "can-i", ..] => "yes".into(),
            other => panic!("fake cluster: unexpected kubectl {other:?}"),
        };
        (0, out)
    }

    fn replace(&self, stdin: &[u8]) -> (i32, String) {
        let new: Value = serde_json::from_slice(stdin).unwrap();
        let mut d = self.deployment.borrow_mut();
        if new["metadata"]["resourceVersion"] != d["metadata"]["resourceVersion"] {
            return (1, String::new());
        }
        let rv: u64 = d["metadata"]["resourceVersion"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let template_changed = new["spec"]["template"] != d["spec"]["template"];
        let mut generation = d["metadata"]["generation"].as_u64().unwrap();
        if template_changed {
            generation += 1;
            let rev = d["metadata"]["annotations"]["deployment.kubernetes.io/revision"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
                + 1;
            let name = format!("api-rev{rev}");
            self.replicasets.borrow_mut().push(json!({
                "metadata": {
                    "name": name,
                    "ownerReferences": [{"kind": "Deployment", "name": "api"}],
                    "annotations": {"deployment.kubernetes.io/revision": rev.to_string()},
                },
                "spec": {"template": new["spec"]["template"]},
            }));
            d["metadata"]["annotations"]["deployment.kubernetes.io/revision"] =
                json!(rev.to_string());
        }
        d["spec"] = new["spec"].clone();
        d["metadata"]["generation"] = json!(generation);
        d["metadata"]["resourceVersion"] = json!((rv + 1).to_string());
        let ok = !self.broken_image;
        d["status"] = json!({
            "observedGeneration": generation,
            "replicas": if ok { 1 } else { 2 },
            "updatedReplicas": 1,
            "availableReplicas": if ok { 1 } else { 0 },
            "conditions": [{"type": "Progressing", "status": "True", "reason": "ReplicaSetUpdated"}],
        });
        drop(d);
        self.check_dangling();
        (0, generation.to_string())
    }

    /// Count the call; run it unless it is cut before its effect; report whether it was cut.
    fn step(&self, call: &Call) -> (bool, (i32, String)) {
        let n = self.calls.get();
        self.calls.set(n + 1);
        let args: Vec<String> = call.args.iter().map(|s| s.to_string()).collect();
        self.argv.borrow_mut().push(args.clone());
        match self.cut.get() {
            Some((k, Cut::BeforeEffect)) if k == n => (true, (0, String::new())),
            Some((k, Cut::AfterEffect)) if k == n => (true, self.exec(&args, call.stdin)),
            _ => (false, self.exec(&args, call.stdin)),
        }
    }
}

impl CommandRunner for Cluster {
    fn read(&self, call: &Call, _refused: &[i32]) -> io::Result<Outcome> {
        Ok(match self.step(call) {
            (true, _) => Outcome::Unknown {
                reason: "lost",
                status: None,
            },
            (false, (0, out)) => Outcome::Done(Output::success(out.into_bytes())),
            (false, (status, _)) => Outcome::Refused(Output::failure(status)),
        })
    }

    fn write(&self, call: &Call) -> io::Result<Outcome> {
        Ok(match self.step(call) {
            (true, _) => Outcome::Unknown {
                reason: "lost",
                status: None,
            },
            (false, (0, out)) => Outcome::Done(Output::success(out.into_bytes())),
            (false, (status, _)) => Outcome::Unknown {
                reason: "failed-write",
                status: Some(status),
            },
        })
    }

    /// The cluster is reachable and the context exists.
    fn probe(&self, _call: &Call, _limit: Duration) -> io::Result<Output> {
        Ok(Output::success(b"ok".to_vec()))
    }

    fn run_inherited(&self, _: &str, _: &[&str], _: &[(&str, &str)]) -> io::Result<i32> {
        unreachable!("the fake cluster runs no inherited child")
    }
}

/// The pinned flow over the adapters, as Task 7's `run_pinned` orders it with
/// `--deploy --prune`: compare and write versions, repin, await health, then prune.
fn sync(c: &Cluster) -> Result<(), Error> {
    let (t, m) = (target(), managed());
    let store = KubeSecrets::new(c, &t);
    let rt = KubeDeployment::new(c, &t, &m)
        .with_wait(Duration::from_secs(5), Duration::from_secs(30), |_| {})
        .with_progress(|_| {});
    let mut pins = BTreeMap::new();
    for (env, v) in DESIRED {
        let value = SecretValue::new(v.into());
        let version = match store.read(env)? {
            Some((cur, ver)) if cur.expose() == value.expose() => ver,
            _ => store.write_one(env, &value)?,
        };
        pins.insert(env.to_string(), (store_name(env), version));
    }
    let snap = rt.bindings()?;
    let mut change = RuntimeChange {
        pin: BTreeMap::new(),
        set: BTreeMap::new(),
        unbind: vec![],
    };
    for (env, (store, version)) in &pins {
        let want = Binding::Pinned {
            store_name: store.clone(),
            version: version.clone(),
        };
        if snap.bindings.get(env) != Some(&want) {
            change
                .pin
                .insert(env.clone(), (store.clone(), version.clone()));
        }
    }
    let want = Binding::Plain {
        digest: super::digest_hex(CONFIG.1),
    };
    if snap.bindings.get(CONFIG.0) != Some(&want) {
        change.set.insert(CONFIG.0.into(), CONFIG.1.into());
    }
    if !(change.pin.is_empty() && change.set.is_empty()) {
        let rev = rt.apply(&change, &snap)?;
        match rt.await_healthy(&rev)? {
            Health::Healthy => {}
            other => return Err(Error::Target(format!("revision {} is {other:?}", rev.0))),
        }
    }
    for env in pins.keys() {
        store.delete(env)?;
    }
    Ok(())
}

fn reference() -> (Cluster, usize) {
    let c = Cluster::new();
    sync(&c).unwrap();
    let n = c.calls.get();
    (c, n)
}

#[test]
fn kubernetes_sync_converges_after_interruption_at_every_call() {
    let (want, n) = reference();
    let mut diverged = Vec::new();
    for k in 0..n {
        for cut in [Cut::AfterEffect, Cut::BeforeEffect] {
            let c = Cluster::new();
            c.cut.set(Some((k, cut)));
            let _ = sync(&c);
            c.cut.set(None);
            let rerun = sync(&c);
            if rerun.is_err() || c.state() != want.state() {
                diverged.push((k, cut, rerun.err().map(|e| e.to_string())));
            }
        }
    }
    assert!(diverged.is_empty(), "{diverged:?}");
}

#[test]
fn no_interruption_leaves_a_reference_to_a_missing_secret() {
    let (_, n) = reference();
    let dangling: Vec<_> = (0..n)
        .flat_map(|k| [(k, Cut::AfterEffect), (k, Cut::BeforeEffect)])
        .filter(|&(k, cut)| {
            let c = Cluster::new();
            c.cut.set(Some((k, cut)));
            let _ = sync(&c);
            c.dangling.get()
        })
        .collect();
    assert!(dangling.is_empty(), "{dangling:?}");
}

#[test]
fn second_sync_changes_nothing() {
    let (c, _) = reference();
    let writes = |c: &Cluster| {
        c.argv
            .borrow()
            .iter()
            .filter(|a| ["apply", "replace", "delete"].contains(&a[5].as_str()))
            .count()
    };
    let before = writes(&c);
    sync(&c).unwrap();
    assert_eq!(writes(&c), before);
}

#[test]
fn sync_prunes_the_unreferenced_stale_version() {
    let (c, _) = reference();
    assert!(!c.secrets.borrow().contains_key(STALE));
}

#[test]
fn rollout_failure_prunes_nothing() {
    let c = Cluster {
        broken_image: true,
        ..Cluster::new()
    };
    let _ = sync(&c);
    assert!(c.secrets.borrow().contains_key(STALE));
}
