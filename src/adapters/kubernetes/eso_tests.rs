//! Key Vault → Kubernetes Deployment through the External Secrets Operator (FR-39), end to
//! end through `app::sync` and `app::status` with the real adapters.
//!
//! [`Sim`] is a stateful fake of `op`, `az` (Key Vault entries with versions and tags) and
//! `kubectl` (a Deployment with its ReplicaSets, Secrets, ExternalSecrets, a
//! ClusterSecretStore, discovery and `auth can-i`), plus the operator itself: an
//! ExternalSecret is reconciled once it has been read [`World::reads_before_sync`] times,
//! creating its Secret from the pinned Key Vault version (E1) or failing with
//! `SecretSyncedError` (E3); deleting an ExternalSecret deletes its Secret (E4). Call `k` of
//! a run can be made to fail with an unknown outcome, after its effect for writes, to drive
//! the interruption matrix (NR-1).

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::time::Duration;

use serde_json::{Value, json};

use super::external::{RESOURCE, STORE_RESOURCE};
use super::testutil::DEPLOYMENT;
use crate::app::status;
use crate::app::sync::{self, SyncOpts};
use crate::app::testutil::{item_json, secret, text, text_of};
use crate::config;
use crate::domain::Fleet;
use crate::error::Error;
use crate::runner::{Call, CommandRunner, Outcome, Output};

const VAULT: &str = "kv-opv-fixture";
const STORE: &str = "prod-vault";

const API_V1: &str = "api-FIXTUREVALUE-1";
const API_V2: &str = "api-FIXTUREVALUE-2";
const DB: &str = "postgres://FIXTUREVALUE@db/app";
const OLD: &str = "old-FIXTUREVALUE";
const LOG: &str = "info-FIXTUREVALUE";
/// Every secret value a test item holds.
const SECRETS: [&str; 4] = [API_V1, API_V2, DB, OLD];

/// `OLD_KEY` is desired in `old_in`: "dev" keeps it, "staging" makes a sync of dev prune it.
fn toml(old_in: &str, config_route: &str) -> String {
    format!(
        r#"
[profile]
kind = "simple"
[stores.{STORE}]
azure_key_vault = "{VAULT}"
subscription = "00000000-0000-0000-0000-000000000000"
[environments.dev]
vault_id = "vdev"
item_id = "idev"
[environments.dev.kubernetes]
context = "kind-opv"
namespace = "opv-spike"
deployment = "api"
secrets_in = "{STORE}"
{config_route}
[environments.staging]
vault_id = "vstg"
item_id = "istg"
[keys.API_KEY]
kind = "secret"
environments = ["dev"]
[keys.DB_URL]
kind = "secret"
environments = ["dev"]
[keys.LOG_LEVEL]
kind = "config"
environments = ["dev"]
[keys.OLD_KEY]
kind = "secret"
environments = ["{old_in}"]
"#
    )
}

fn fleet_a() -> Fleet {
    config::parse(&toml("dev", "")).unwrap()
}

fn fleet_b() -> Fleet {
    config::parse(&toml("staging", "")).unwrap()
}

fn fleet_store() -> Fleet {
    config::parse(&toml("dev", "config = \"store\"")).unwrap()
}

fn item_with(api: &str) -> Vec<u8> {
    item_json(&[
        secret("", "API_KEY", api),
        secret("", "DB_URL", DB),
        text("", "LOG_LEVEL", LOG),
        secret("", "OLD_KEY", OLD),
    ])
}

struct KvEntry {
    name: String,
    /// (version id, value), oldest first.
    versions: Vec<(String, String)>,
    tag: String,
}

/// What `op`, `az` and `kubectl` act on.
struct World {
    item: Vec<u8>,
    /// lower-cased Key Vault name → entry.
    kv: BTreeMap<String, KvEntry>,
    serial: u32,
    deployment: Value,
    replicasets: Vec<Value>,
    /// Secret name → (owning ExternalSecret, value).
    secrets: BTreeMap<String, (Option<String>, String)>,
    /// ExternalSecret name → object (with `status` once reconciled).
    externals: BTreeMap<String, Value>,
    /// ExternalSecret name → reads seen while it was not reconciled.
    pending_reads: BTreeMap<String, u32>,
    /// Reads of a new ExternalSecret that show it pending before the operator acts.
    reads_before_sync: u32,
    /// The ClusterSecretStore, `None` when it does not exist.
    cluster_store: Option<Value>,
    /// The operator serves external-secrets.io/v1.
    operator: bool,
    /// `auth can-i create externalsecrets` answers yes.
    may_create: bool,
    /// The store's identity cannot read anything (every sync fails, E3).
    denied: bool,
    /// Kubernetes keeps old ReplicaSets (`revisionHistoryLimit` > 0).
    keep_history: bool,
    /// Pods of a new ReplicaSet never start.
    broken_image: bool,
}

struct Rec {
    program: String,
    args: Vec<String>,
    stdin: Option<Vec<u8>>,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Fail {
    /// The outcome is lost after the call took effect (writes) or before (reads).
    After,
    /// The call never reached the target.
    Before,
}

struct Sim {
    world: RefCell<World>,
    calls: RefCell<Vec<Rec>>,
    notes: RefCell<Vec<String>>,
    fail_at: Cell<Option<(usize, Fail)>>,
    /// A Deployment or ReplicaSet template referenced a Secret that did not exist.
    dangling: RefCell<Vec<String>>,
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn has(args: &[String], prefix: &[&str]) -> bool {
    args.len() >= prefix.len() && args.iter().zip(prefix).all(|(a, p)| a == p)
}

fn ok(s: impl Into<Vec<u8>>) -> Output {
    Output::success(s.into())
}

fn ok_json(v: &Value) -> Output {
    ok(serde_json::to_vec(v).unwrap())
}

fn ready_store() -> Value {
    json!({
        "metadata": {"name": STORE},
        "spec": {"provider": {"azurekv": {"vaultUrl": format!("https://{VAULT}.vault.azure.net/")}}},
        "status": {"conditions": [{"type": "Ready", "status": "True", "reason": "Valid",
                                   "message": "store validated"}]},
    })
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

/// The args of a kubectl call after its five scope flags.
fn kube_args(c: &Rec) -> &[String] {
    &c.args[5..]
}

impl Sim {
    fn new(item: Vec<u8>) -> Self {
        let mut d: Value = serde_json::from_str(DEPLOYMENT).unwrap();
        d["spec"]["template"]["spec"]["containers"][0]["env"] =
            json!([{"name": "PORT", "value": "80"}]);
        let rs = json!({
            "metadata": {
                "name": "api-rev5",
                "ownerReferences": [{"kind": "Deployment", "name": "api"}],
                "annotations": {"deployment.kubernetes.io/revision": "5"},
            },
            "spec": {"template": d["spec"]["template"].clone()},
        });
        Self {
            world: RefCell::new(World {
                item,
                kv: BTreeMap::new(),
                serial: 0,
                deployment: d,
                replicasets: vec![rs],
                secrets: BTreeMap::new(),
                externals: BTreeMap::new(),
                pending_reads: BTreeMap::new(),
                reads_before_sync: 1,
                cluster_store: Some(ready_store()),
                operator: true,
                may_create: true,
                denied: false,
                keep_history: true,
                broken_image: false,
            }),
            calls: RefCell::default(),
            notes: RefCell::default(),
            fail_at: Cell::new(None),
            dangling: RefCell::default(),
        }
    }

    fn reset(&self) {
        self.calls.borrow_mut().clear();
        self.notes.borrow_mut().clear();
    }

    fn handle(&self, call: &Call<'_>) -> Output {
        let args: Vec<String> = call.args.iter().map(|a| a.to_string()).collect();
        let stdin = call.stdin.map(<[u8]>::to_vec);
        let out = match call.program {
            "op" => ok(self.world.borrow().item.clone()),
            "az" => self.az(&args, stdin.as_deref()),
            "kubectl" => self.kubectl(&args, stdin.as_deref()),
            other => panic!("Sim: unexpected program {other}"),
        };
        self.calls.borrow_mut().push(Rec {
            program: call.program.to_string(),
            args,
            stdin,
        });
        self.check();
        out
    }

    fn az(&self, args: &[String], stdin: Option<&[u8]>) -> Output {
        let mut w = self.world.borrow_mut();
        let name = flag(args, "--name").map(str::to_ascii_lowercase);
        if has(args, &["account", "show"]) || has(args, &["version"]) {
            return ok(Vec::new());
        }
        if has(args, &["keyvault", "secret", "list"]) {
            let v: Vec<Value> =
                w.kv.values()
                    .map(|e| json!({"name": e.name, "tags": {"opv-managed": e.tag}}))
                    .collect();
            return ok_json(&json!(v));
        }
        if has(args, &["keyvault", "secret", "show-deleted"]) {
            return Output::failure(3);
        }
        if has(args, &["keyvault", "secret", "show"]) {
            let Some(e) = w.kv.get(name.as_deref().unwrap()) else {
                return Output::failure(3);
            };
            let found = match flag(args, "--version") {
                Some(v) => e.versions.iter().find(|(id, _)| id == v),
                None => e.versions.last(),
            };
            let Some((ver, value)) = found else {
                return Output::failure(3);
            };
            let id = format!("https://{VAULT}.vault.azure.net/secrets/{}/{ver}", e.name);
            return if flag(args, "--query") == Some("id") {
                ok(id)
            } else {
                ok_json(&json!({"id": id, "value": value}))
            };
        }
        if has(args, &["keyvault", "secret", "set"]) {
            w.serial += 1;
            // 32 hex digits whose first ten differ between versions, like Key Vault's.
            let ver = format!(
                "{:010x}{:022x}",
                u64::from(w.serial) * 0x9e37_79b9,
                w.serial
            );
            let display = flag(args, "--name").unwrap().to_string();
            let tag = flag(args, "--tags")
                .unwrap()
                .trim_start_matches("opv-managed=")
                .to_string();
            let value = String::from_utf8(stdin.unwrap().to_vec()).unwrap();
            let e = w.kv.entry(name.unwrap()).or_insert(KvEntry {
                name: display.clone(),
                versions: Vec::new(),
                tag: tag.clone(),
            });
            e.versions.push((ver.clone(), value));
            e.tag = tag;
            return ok(format!(
                "https://{VAULT}.vault.azure.net/secrets/{display}/{ver}"
            ));
        }
        if has(args, &["keyvault", "secret", "delete"]) {
            w.kv.remove(name.as_deref().unwrap());
            return ok(Vec::new());
        }
        if has(args, &["keyvault", "show"]) {
            let path = format!(
                "{}/tests/fixtures/azure/keyvault-show.json",
                env!("CARGO_MANIFEST_DIR")
            );
            let mut v: Value =
                serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
            v["name"] = json!(VAULT);
            v["properties"]["vaultUri"] = json!(format!("https://{VAULT}.vault.azure.net/"));
            return ok_json(&v);
        }
        panic!("Sim: unexpected az call {args:?}");
    }

    /// The operator reconciles ExternalSecret `name` (E1, E3).
    fn reconcile(w: &mut World, name: &str) {
        let es = w.externals[name].clone();
        let remote = &es["spec"]["data"][0]["remoteRef"];
        let key = remote["key"].as_str().unwrap().to_ascii_lowercase();
        let ver = remote["version"].as_str().unwrap();
        let store_ready = w
            .cluster_store
            .as_ref()
            .and_then(|s| s.pointer("/status/conditions/0/status"))
            .and_then(Value::as_str)
            == Some("True");
        let value =
            w.kv.get(&key)
                .and_then(|e| e.versions.iter().find(|(id, _)| id == ver))
                .map(|(_, v)| v.clone())
                .filter(|_| store_ready && !w.denied);
        let status = match value {
            Some(v) => {
                let target = es["spec"]["target"]["name"].as_str().unwrap().to_string();
                w.secrets
                    .insert(target.clone(), (Some(name.to_string()), v));
                json!({"binding": {"name": target}, "conditions": [{"type": "Ready",
                    "status": "True", "reason": "SecretSynced", "message": "secret synced"}]})
            }
            None => json!({"binding": {"name": ""}, "conditions": [{"type": "Ready",
                "status": "False", "reason": "SecretSyncedError",
                "message": "could not get secret data from provider"}]}),
        };
        w.externals.get_mut(name).unwrap()["status"] = status;
    }

    fn kubectl(&self, args: &[String], stdin: Option<&[u8]>) -> Output {
        assert_eq!(args[0], "--context", "unscoped call: {args:?}");
        assert_eq!(args[2], "--namespace", "unscoped call: {args:?}");
        let a: Vec<&str> = args[5..].iter().map(String::as_str).collect();
        let mut w = self.world.borrow_mut();
        match a.as_slice() {
            ["get", "--raw", "/apis/external-secrets.io/v1"] if w.operator => ok_json(&json!({
                "groupVersion": "external-secrets.io/v1",
                "resources": [{"name": "externalsecrets"}, {"name": "clustersecretstores"}],
            })),
            ["get", "--raw", _] => Output::failure(1),
            ["get", r, n, "--ignore-not-found", "-o", "json"] if *r == STORE_RESOURCE => {
                match &w.cluster_store {
                    Some(s) if s["metadata"]["name"] == *n => ok_json(s),
                    _ => ok(Vec::new()),
                }
            }
            ["auth", "can-i", "create", _] if !w.may_create => Output {
                status: 1,
                stdout: b"no\n".to_vec().into(),
            },
            ["auth", "can-i", ..] => ok("yes"),
            ["get", "deployment", "api", "-o", "json"] => ok_json(&w.deployment),
            ["get", "replicasets", "-o", "json"] => ok_json(&json!({"items": w.replicasets})),
            ["get", "pods", "-l", _, "-o", _] => {
                let newest = w.replicasets.last().unwrap()["metadata"]["name"]
                    .as_str()
                    .unwrap()
                    .to_string();
                let reason = if w.broken_image {
                    "CreateContainerConfigError "
                } else {
                    ""
                };
                ok(format!("{newest}-pod\t{newest}\t{reason}\n"))
            }
            ["get", r, "-l", sel, "-o", "json"] if *r == RESOURCE => {
                let want: BTreeMap<&str, &str> =
                    sel.split(',').filter_map(|kv| kv.split_once('=')).collect();
                let items: Vec<&Value> = w
                    .externals
                    .values()
                    .filter(|e| {
                        want.iter()
                            .all(|(k, v)| e["metadata"]["labels"][*k].as_str() == Some(*v))
                    })
                    .collect();
                ok_json(&json!({"items": items}))
            }
            ["get", r, n, "--ignore-not-found", "-o", "json"] if *r == RESOURCE => {
                if !w.externals.contains_key(*n) {
                    return ok(Vec::new());
                }
                if w.externals[*n].get("status").is_none() {
                    let limit = w.reads_before_sync;
                    let seen = w.pending_reads.entry(n.to_string()).or_default();
                    *seen += 1;
                    if *seen > limit {
                        Self::reconcile(&mut w, n);
                    }
                }
                ok_json(&w.externals[*n])
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
                assert_eq!(
                    doc["kind"], "ExternalSecret",
                    "opv applies only ExternalSecrets"
                );
                let name = doc["metadata"]["name"].as_str().unwrap().to_string();
                match w.externals.get_mut(&name) {
                    Some(old) if old["spec"] == doc["spec"] => {}
                    Some(old) => {
                        old["spec"] = doc["spec"].clone();
                        old.as_object_mut().unwrap().remove("status");
                    }
                    None => {
                        w.externals.insert(name.clone(), doc);
                    }
                }
                ok(format!("externalsecret.external-secrets.io/{name}\n"))
            }
            ["replace", "-f", "-", "-o", _] => {
                drop(w);
                self.replace(stdin.unwrap())
            }
            ["delete", r, rest @ ..] if *r == RESOURCE => {
                for n in rest.iter().filter(|n| !n.starts_with("--")) {
                    w.externals.remove(*n);
                    // The owned Secret is garbage-collected with it (E4).
                    w.secrets
                        .retain(|_, (owner, _)| owner.as_deref() != Some(*n));
                }
                ok(Vec::new())
            }
            other => panic!("Sim: unexpected kubectl {other:?}"),
        }
    }

    fn replace(&self, stdin: &[u8]) -> Output {
        let new: Value = serde_json::from_slice(stdin).unwrap();
        let mut w = self.world.borrow_mut();
        if new["metadata"]["resourceVersion"] != w.deployment["metadata"]["resourceVersion"] {
            return Output::failure(1);
        }
        let rv: u64 = w.deployment["metadata"]["resourceVersion"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let mut generation = w.deployment["metadata"]["generation"].as_u64().unwrap();
        if new["spec"]["template"] != w.deployment["spec"]["template"] {
            generation += 1;
            let rev = w.deployment["metadata"]["annotations"]["deployment.kubernetes.io/revision"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
                + 1;
            if !w.keep_history {
                w.replicasets.clear();
            }
            w.replicasets.push(json!({
                "metadata": {
                    "name": format!("api-rev{rev}"),
                    "ownerReferences": [{"kind": "Deployment", "name": "api"}],
                    "annotations": {"deployment.kubernetes.io/revision": rev.to_string()},
                },
                "spec": {"template": new["spec"]["template"]},
            }));
            w.deployment["metadata"]["annotations"]["deployment.kubernetes.io/revision"] =
                json!(rev.to_string());
        }
        w.deployment["spec"] = new["spec"].clone();
        w.deployment["metadata"]["generation"] = json!(generation);
        w.deployment["metadata"]["resourceVersion"] = json!((rv + 1).to_string());
        let healthy = !w.broken_image;
        w.deployment["status"] = json!({
            "observedGeneration": generation,
            "replicas": if healthy { 1 } else { 2 },
            "updatedReplicas": 1,
            "availableReplicas": if healthy { 1 } else { 0 },
            "conditions": [{"type": "Progressing", "status": "True", "reason": "ReplicaSetUpdated"}],
        });
        ok(generation.to_string())
    }

    /// NR-1: no template the cluster may run (the Deployment's, or a ReplicaSet's kept for
    /// rollback) references a Secret that does not exist.
    fn check(&self) {
        let w = self.world.borrow();
        let templates = std::iter::once(&w.deployment["spec"]["template"])
            .chain(w.replicasets.iter().map(|rs| &rs["spec"]["template"]));
        for t in templates {
            for r in template_refs(t) {
                if !w.secrets.contains_key(&r) {
                    self.dangling.borrow_mut().push(r);
                }
            }
        }
    }

    fn matches(c: &Rec, program: &str, prefix: &[&str]) -> bool {
        c.program == program
            && if program == "kubectl" {
                has(kube_args(c), prefix)
            } else {
                has(&c.args, prefix)
            }
    }

    fn index_of(&self, program: &str, prefix: &[&str]) -> Option<usize> {
        self.calls
            .borrow()
            .iter()
            .position(|c| Self::matches(c, program, prefix))
    }

    fn count(&self, program: &str, prefix: &[&str]) -> usize {
        self.calls
            .borrow()
            .iter()
            .filter(|c| Self::matches(c, program, prefix))
            .count()
    }

    /// Writes of the last run: Key Vault sets and deletes, kubectl apply, replace, delete.
    fn writes(&self) -> usize {
        self.count("az", &["keyvault", "secret", "set"])
            + self.count("az", &["keyvault", "secret", "delete"])
            + self.count("kubectl", &["apply"])
            + self.count("kubectl", &["replace"])
            + self.count("kubectl", &["delete"])
    }

    /// The env the Deployment runs with (name → the value its Secret holds, or the plain
    /// value), the Key Vault entries' latest values, and the ExternalSecrets nothing
    /// references. Version ids differ between runs; none of this may.
    fn end_state(
        &self,
    ) -> (
        BTreeMap<String, String>,
        BTreeMap<String, String>,
        Vec<String>,
    ) {
        let w = self.world.borrow();
        let mut env = BTreeMap::new();
        for e in w.deployment["spec"]["template"]["spec"]["containers"][0]["env"]
            .as_array()
            .unwrap()
        {
            let name = e["name"].as_str().unwrap().to_string();
            let value = match e
                .pointer("/valueFrom/secretKeyRef/name")
                .and_then(Value::as_str)
            {
                Some(s) => w
                    .secrets
                    .get(s)
                    .map_or("<missing>".to_string(), |(_, v)| v.clone()),
                None => e["value"].as_str().unwrap_or_default().to_string(),
            };
            env.insert(name, value);
        }
        let kv =
            w.kv.iter()
                .map(|(n, e)| (n.clone(), e.versions.last().unwrap().1.clone()))
                .collect();
        let mut live: BTreeSet<String> = template_refs(&w.deployment["spec"]["template"])
            .into_iter()
            .collect();
        for rs in &w.replicasets {
            live.extend(template_refs(&rs["spec"]["template"]));
        }
        let orphans = w
            .externals
            .keys()
            .filter(|n| !live.contains(*n))
            .cloned()
            .collect();
        (env, kv, orphans)
    }

    /// The managed env entry `name` of the Deployment.
    fn env_entry(&self, name: &str) -> Value {
        self.world.borrow().deployment["spec"]["template"]["spec"]["containers"][0]["env"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["name"] == name)
            .cloned()
            .unwrap_or(Value::Null)
    }

    /// The Secret (and ExternalSecret) name the Deployment binds `name` to.
    fn bound_name(&self, name: &str) -> String {
        self.env_entry(name)["valueFrom"]["secretKeyRef"]["name"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    /// The ExternalSecret the Deployment binds `name` through.
    fn bound_external(&self, name: &str) -> Value {
        let es = self.bound_name(name);
        self.world
            .borrow()
            .externals
            .get(&es)
            .cloned()
            .unwrap_or(Value::Null)
    }

    fn latest(&self, kv_name: &str) -> String {
        self.world.borrow().kv[&kv_name.to_ascii_lowercase()]
            .versions
            .last()
            .unwrap()
            .0
            .clone()
    }

    fn step(&self, call: &Call<'_>, write: bool) -> Option<Outcome> {
        let k = self.calls.borrow().len();
        match self.fail_at.get() {
            Some((at, mode)) if at == k => {
                if write && mode == Fail::After {
                    self.handle(call);
                } else {
                    self.calls.borrow_mut().push(Rec {
                        program: call.program.to_string(),
                        args: call.args.iter().map(|a| a.to_string()).collect(),
                        stdin: call.stdin.map(<[u8]>::to_vec),
                    });
                }
                Some(Outcome::Unknown {
                    reason: "lost",
                    status: None,
                })
            }
            _ => None,
        }
    }
}

impl CommandRunner for Sim {
    fn read(&self, call: &Call<'_>, _refused: &[i32]) -> io::Result<Outcome> {
        if let Some(o) = self.step(call, false) {
            return Ok(o);
        }
        let out = self.handle(call);
        Ok(match out.status {
            0 => Outcome::Done(out),
            _ => Outcome::Refused(out),
        })
    }

    fn write(&self, call: &Call<'_>) -> io::Result<Outcome> {
        if let Some(o) = self.step(call, true) {
            return Ok(o);
        }
        let out = self.handle(call);
        Ok(match out.status {
            0 => Outcome::Done(out),
            s => Outcome::Unknown {
                reason: "failed-write",
                status: Some(s),
            },
        })
    }

    /// Sign-in, context and reachability probes all pass.
    fn probe(&self, call: &Call<'_>, _limit: Duration) -> io::Result<Output> {
        if self.step(call, false).is_some() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(ok("ok"))
    }

    fn pause(&self, _: Duration, note: &str) {
        if !note.is_empty() {
            self.notes.borrow_mut().push(note.to_string());
        }
    }

    fn note(&self, line: &str) {
        self.notes.borrow_mut().push(line.to_string());
    }

    fn run_inherited(&self, _: &str, _: &[&str], _: &[(&str, &str)]) -> io::Result<i32> {
        unreachable!("sync never runs a child")
    }
}

fn deploy() -> SyncOpts {
    SyncOpts {
        deploy: true,
        ..Default::default()
    }
}

fn deploy_prune() -> SyncOpts {
    SyncOpts {
        deploy: true,
        prune: true,
        ..Default::default()
    }
}

fn sync_on(sim: &Sim, fleet: &Fleet, opts: &SyncOpts) -> (Result<(), Error>, String) {
    sim.reset();
    let mut out = Vec::new();
    let res = sync::run(fleet, "dev", sim, &mut out, opts);
    (res, text_of(&out))
}

fn status_on(sim: &Sim, fleet: &Fleet) -> (Result<(), Error>, String) {
    sim.reset();
    let mut out = Vec::new();
    let res = status::run(fleet, "dev", sim, &mut out);
    (res, text_of(&out))
}

/// A world opv has synced and deployed with `fleet_a` and API_KEY = v1.
fn converged() -> Sim {
    let sim = Sim::new(item_with(API_V1));
    let (res, out) = sync_on(&sim, &fleet_a(), &deploy());
    assert!(res.is_ok(), "setup sync failed: {res:?}\n{out}");
    sim
}

// ---- binding ----

#[test]
fn deploy_binds_each_secret_to_the_value_of_its_pinned_version() {
    let sim = converged();
    let (env, _, _) = sim.end_state();
    assert_eq!(
        (
            env["API_KEY"].as_str(),
            env["DB_URL"].as_str(),
            env["OLD_KEY"].as_str()
        ),
        (API_V1, DB, OLD)
    );
}

#[test]
fn bound_external_secret_pins_the_key_vault_version_once() {
    let sim = converged();
    let es = sim.bound_external("API_KEY");
    assert_eq!(
        (
            es["spec"]["refreshInterval"].as_str(),
            es["spec"]["data"][0]["remoteRef"]["version"]
                .as_str()
                .map(String::from)
        ),
        (Some("0"), Some(sim.latest("API-KEY")))
    );
}

#[test]
fn bound_external_secret_is_named_from_the_key_vault_version() {
    let sim = converged();
    let v = sim.latest("API-KEY");
    assert_eq!(
        sim.bound_name("API_KEY"),
        format!("opv-api-key-{}", &v[..10])
    );
}

#[test]
fn bound_external_secret_reads_through_the_named_cluster_secret_store() {
    let sim = converged();
    assert_eq!(
        sim.bound_external("DB_URL")["spec"]["secretStoreRef"]["name"],
        STORE
    );
}

#[test]
fn external_secrets_are_labelled_with_the_environment_and_key() {
    let sim = converged();
    assert_eq!(
        sim.bound_external("DB_URL")["metadata"]["labels"],
        json!({"opv-managed": "dev", "opv-key": "db-url"})
    );
}

#[test]
fn config_stays_a_plain_env_value_by_default() {
    let sim = converged();
    assert_eq!(sim.env_entry("LOG_LEVEL")["value"], LOG);
}

#[test]
fn config_routed_to_the_store_is_bound_through_an_external_secret() {
    let sim = Sim::new(item_with(API_V1));
    let (res, _) = sync_on(&sim, &fleet_store(), &deploy());
    assert!(
        res.is_ok() && sim.bound_external("LOG_LEVEL")["spec"].is_object(),
        "{res:?}"
    );
}

#[test]
fn second_sync_writes_nothing() {
    let sim = converged();
    let (res, _) = sync_on(&sim, &fleet_a(), &deploy());
    assert_eq!((res.is_ok(), sim.writes()), (true, 0));
}

#[test]
fn sync_without_deploy_applies_no_external_secret() {
    let sim = Sim::new(item_with(API_V1));
    let (res, _) = sync_on(&sim, &fleet_a(), &SyncOpts::default());
    assert_eq!((res.is_ok(), sim.count("kubectl", &["apply"])), (true, 0));
}

#[test]
fn deployment_is_repinned_only_after_its_external_secrets_are_ready() {
    let sim = Sim::new(item_with(API_V1));
    let (res, _) = sync_on(&sim, &fleet_a(), &deploy());
    let last_ready_read = sim.calls.borrow().iter().rposition(is_ready_read).unwrap();
    let replace = sim.index_of("kubectl", &["replace"]).unwrap();
    assert!(res.is_ok() && last_ready_read < replace, "{res:?}");
}

/// `get externalsecrets.external-secrets.io <name> --ignore-not-found -o json`.
fn is_ready_read(c: &Rec) -> bool {
    c.program == "kubectl"
        && has(kube_args(c), &["get", RESOURCE])
        && c.args.iter().any(|a| a == "--ignore-not-found")
}

#[test]
fn waiting_for_an_external_secret_reports_progress() {
    let sim = Sim::new(item_with(API_V1));
    // 2 s per poll: the operator acts after 50 s, a progress line is due every 15 s.
    sim.world.borrow_mut().reads_before_sync = 25;
    let (res, _) = sync_on(&sim, &fleet_a(), &deploy());
    let notes = sim.notes.borrow();
    assert!(
        res.is_ok()
            && notes
                .iter()
                .any(|n| n.starts_with("waiting for ExternalSecret opv-")),
        "{res:?} {notes:?}"
    );
}

// ---- refusals before any write ----

fn refused(setup: impl FnOnce(&mut World)) -> (Sim, Error) {
    let sim = Sim::new(item_with(API_V1));
    setup(&mut sim.world.borrow_mut());
    let (res, _) = sync_on(&sim, &fleet_a(), &deploy());
    (sim, res.unwrap_err())
}

fn not_ready(w: &mut World) {
    let c = &mut w.cluster_store.as_mut().unwrap()["status"]["conditions"][0];
    c["status"] = json!("False");
    c["reason"] = json!("InvalidProviderConfig");
    c["message"] = json!("unable to validate store");
}

#[test]
fn cluster_secret_store_not_ready_refuses_before_any_write() {
    let (sim, _) = refused(not_ready);
    assert_eq!(sim.writes(), 0);
}

#[test]
fn cluster_secret_store_not_ready_refusal_names_its_message() {
    let (_, e) = refused(not_ready);
    assert!(e.to_string().contains("unable to validate store"), "{e}");
}

#[test]
fn missing_cluster_secret_store_refuses_before_any_write() {
    let (sim, e) = refused(|w| w.cluster_store = None);
    assert!(
        sim.writes() == 0
            && e.to_string()
                .contains("ClusterSecretStore prod-vault does not exist"),
        "{e}"
    );
}

#[test]
fn operator_not_installed_is_a_dependency_error() {
    let (_, e) = refused(|w| w.operator = false);
    assert_eq!(e.exit_code(), 3, "{e}");
}

#[test]
fn identity_that_cannot_create_external_secrets_is_refused_before_any_write() {
    let (sim, e) = refused(|w| w.may_create = false);
    assert!(sim.writes() == 0 && e.exit_code() == 7, "{e}");
}

// ---- SecretSyncedError (E3) ----

#[test]
fn sync_error_names_the_store_identity_as_the_cause() {
    let (_, e) = refused(|w| w.denied = true);
    assert!(
        e.to_string()
            .contains("its identity most likely cannot read this secret"),
        "{e}"
    );
}

#[test]
fn sync_error_leaves_the_deployment_unchanged() {
    let (sim, _) = refused(|w| w.denied = true);
    assert_eq!(sim.count("kubectl", &["replace"]), 0);
}

// ---- prune and collection (FR-32) ----

#[test]
fn prune_deletes_the_external_secret_after_the_repin_and_before_the_key_vault_entry() {
    let sim = converged();
    sim.world.borrow_mut().keep_history = false;
    let (res, _) = sync_on(&sim, &fleet_b(), &deploy_prune());
    let replace = sim.index_of("kubectl", &["replace"]).unwrap();
    let es_delete = sim.index_of("kubectl", &["delete"]).unwrap();
    let kv_delete = sim
        .index_of("az", &["keyvault", "secret", "delete"])
        .unwrap();
    assert!(
        res.is_ok() && replace < es_delete && es_delete < kv_delete,
        "{res:?}"
    );
}

#[test]
fn prune_keeps_an_external_secret_a_rollback_needs() {
    let sim = converged();
    let old = sim.bound_name("OLD_KEY");
    let (res, _) = sync_on(&sim, &fleet_b(), &deploy_prune());
    assert!(
        res.is_ok() && sim.world.borrow().externals.contains_key(&old),
        "{res:?}"
    );
}

#[test]
fn external_secret_of_a_pruned_key_is_collected_once_no_rollback_needs_it() {
    let sim = converged();
    let old = sim.bound_name("OLD_KEY");
    let (res, _) = sync_on(&sim, &fleet_b(), &deploy_prune());
    assert!(res.is_ok(), "{res:?}");
    // Kubernetes trims the ReplicaSet history; the next deploy changes API_KEY.
    {
        let mut w = sim.world.borrow_mut();
        let newest = w.replicasets.pop().unwrap();
        w.replicasets = vec![newest];
        w.keep_history = false;
        w.item = item_with(API_V2);
    }
    let (res, _) = sync_on(&sim, &fleet_b(), &deploy());
    assert!(
        res.is_ok() && !sim.world.borrow().externals.contains_key(&old),
        "{res:?}"
    );
}

#[test]
fn superseded_external_secret_is_deleted_after_a_healthy_rollout() {
    let sim = converged();
    let before = sim.bound_name("API_KEY");
    {
        let mut w = sim.world.borrow_mut();
        w.keep_history = false;
        w.item = item_with(API_V2);
    }
    let (res, _) = sync_on(&sim, &fleet_a(), &deploy());
    assert!(
        res.is_ok() && !sim.world.borrow().externals.contains_key(&before),
        "{res:?}"
    );
}

#[test]
fn failed_rollout_prunes_nothing() {
    let sim = converged();
    {
        let mut w = sim.world.borrow_mut();
        w.keep_history = false;
        w.broken_image = true;
    }
    let (res, _) = sync_on(&sim, &fleet_b(), &deploy_prune());
    assert!(
        res.is_err() && sim.world.borrow().kv.contains_key("old-key"),
        "{res:?}"
    );
}

// ---- status ----

#[test]
fn status_shows_the_chain_of_each_bound_key() {
    let sim = converged();
    let v = sim.latest("DB-URL");
    let (_, out) = status_on(&sim, &fleet_a());
    let want = format!(
        "chain: DB_URL → Key Vault {VAULT} ({}…) → ExternalSecret opv-db-url-{} → env DB_URL",
        &v[..10],
        &v[..10]
    );
    assert!(out.contains(&want), "{out}");
}

#[test]
fn status_of_a_converged_environment_has_nothing_pending() {
    let sim = converged();
    let (_, out) = status_on(&sim, &fleet_a());
    assert!(!out.contains("pending deploy"), "{out}");
}

#[test]
fn status_reports_a_changed_secret_as_pending_deploy() {
    let sim = converged();
    sim.world.borrow_mut().item = item_with(API_V2);
    let (res, _) = sync_on(&sim, &fleet_a(), &SyncOpts::default());
    assert!(res.is_ok(), "{res:?}");
    let (_, out) = status_on(&sim, &fleet_a());
    assert!(
        out.contains("pending deploy (opv sync dev --deploy): API_KEY"),
        "{out}"
    );
}

#[test]
fn status_warns_without_refusing_when_the_cluster_secret_store_is_not_ready() {
    let sim = converged();
    not_ready(&mut sim.world.borrow_mut());
    let (res, _) = status_on(&sim, &fleet_a());
    let notes = sim.notes.borrow();
    assert!(
        res.is_ok()
            && notes
                .iter()
                .any(|n| n.contains("ClusterSecretStore prod-vault is not Ready")),
        "{res:?} {notes:?}"
    );
}

// ---- doctor ----

fn doctor_out(sim: &Sim) -> String {
    let mut out = Vec::new();
    let host = crate::host::Host::from_env(&crate::host::FakeEnv::new("linux"));
    let _ = crate::app::doctor::run_with(Ok(fleet_a()), sim, &host, &mut out);
    text_of(&out)
}

#[test]
fn doctor_checks_the_cluster_secret_store() {
    let sim = Sim::new(item_with(API_V1));
    let out = doctor_out(&sim);
    assert!(
        out.contains(
            "ok    cluster secret store: prod-vault is Ready and reads Key Vault kv-opv-fixture"
        ),
        "{out}"
    );
}

#[test]
fn doctor_checks_the_key_vault_of_the_store() {
    let sim = Sim::new(item_with(API_V1));
    let out = doctor_out(&sim);
    assert!(
        out.contains("ok    key vault: kv-opv-fixture answers at"),
        "{out}"
    );
}

#[test]
fn doctor_reports_a_missing_operator() {
    let sim = Sim::new(item_with(API_V1));
    sim.world.borrow_mut().operator = false;
    let out = doctor_out(&sim);
    assert!(out.contains("FAIL  external secrets operator: dependency error: the External Secrets Operator is not installed"), "{out}");
}

#[test]
fn doctor_json_lists_the_external_secrets_checks() {
    let sim = Sim::new(item_with(API_V1));
    let mut out = Vec::new();
    let _ = crate::app::doctor::run_scoped_as(Ok(fleet_a()), None, None, true, &sim, &mut out);
    let doc: serde_json::Value = serde_json::from_slice(&out).expect("one JSON document");
    let names: Vec<&str> = doc["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .filter_map(|c| c["name"].as_str())
        .collect();
    assert!(
        [
            "external secrets operator",
            "cluster secret store",
            "key vault"
        ]
        .iter()
        .all(|n| names.contains(n)),
        "{names:?}"
    );
}

// ---- no value anywhere but the Key Vault write's stdin (SR-1..SR-3) ----

#[test]
fn no_secret_value_reaches_argv_manifests_labels_or_output() {
    let sim = converged();
    sim.world.borrow_mut().item = item_with(API_V2);
    let (res, sync_out) = sync_on(&sim, &fleet_b(), &deploy_prune());
    let mut seen = vec![sync_out];
    for c in sim.calls.borrow().iter() {
        seen.push(c.args.join(" "));
        if !(c.program == "az" && has(&c.args, &["keyvault", "secret", "set"])) {
            seen.push(String::from_utf8_lossy(c.stdin.as_deref().unwrap_or_default()).into());
        }
    }
    seen.push(status_on(&sim, &fleet_b()).1);
    let w = sim.world.borrow();
    seen.extend(w.externals.values().map(Value::to_string));
    seen.push(w.deployment.to_string());
    let leaks: Vec<&String> = seen
        .iter()
        .filter(|s| SECRETS.iter().any(|v| s.contains(v)))
        .collect();
    assert!(res.is_ok() && leaks.is_empty(), "{res:?} {leaks:?}");
}

// ---- interruption matrix (NR-1) ----

/// Every call of the reference run from `start`, failed as Unknown both ways, then re-run
/// cleanly: the re-run succeeds with the reference's end state, and no state in between
/// binds a missing Secret. Returns the calls that broke this.
fn matrix(start: &dyn Fn() -> Sim, fleet: &Fleet, opts: &SyncOpts) -> Vec<String> {
    let reference = start();
    let (res, out) = sync_on(&reference, fleet, opts);
    assert!(res.is_ok(), "reference run failed: {res:?}\n{out}");
    let want = reference.end_state();
    let n = reference.calls.borrow().len();
    let mut bad = Vec::new();
    for k in 0..n {
        for mode in [Fail::After, Fail::Before] {
            let sim = start();
            sim.fail_at.set(Some((k, mode)));
            let _ = sync_on(&sim, fleet, opts);
            sim.fail_at.set(None);
            let (res, _) = sync_on(&sim, fleet, opts);
            let dangling = sim.dangling.borrow().clone();
            if res.is_err() || sim.end_state() != want || !dangling.is_empty() {
                bad.push(format!("call {k} {mode:?}: {res:?} dangling {dangling:?}"));
            }
        }
    }
    bad
}

#[test]
fn first_sync_converges_after_interruption_at_every_call() {
    let start = || Sim::new(item_with(API_V1));
    let bad = matrix(&start, &fleet_a(), &deploy_prune());
    assert!(bad.is_empty(), "{bad:#?}");
}

#[test]
fn change_and_prune_converge_after_interruption_at_every_call() {
    let start = || {
        let sim = converged();
        {
            let mut w = sim.world.borrow_mut();
            w.keep_history = false;
            w.item = item_with(API_V2);
        }
        sim
    };
    let bad = matrix(&start, &fleet_b(), &deploy_prune());
    assert!(bad.is_empty(), "{bad:#?}");
}

// ---- output contract (UX1) ----

/// UX1 (NR-18): the External Secrets path ends with the summary line every provider prints.
#[test]
fn sync_through_external_secrets_ends_with_the_shared_summary_line() {
    let sim = Sim::new(item_with(API_V1));
    let (_, out) = sync_on(&sim, &fleet_a(), &deploy_prune());
    let last = out.lines().last().unwrap_or_default();
    let re = regex::Regex::new(
        r"^summary: written \d+ · deployed \S+ · pruned \d+ · pending \d+ · unchanged \d+ · skipped \d+$",
    )
    .unwrap();
    assert!(re.is_match(last), "{out}");
}

/// UX1 (FR-21): `status --json` carries each bound key's chain beside its `target_name`.
#[test]
fn status_json_carries_the_chain_beside_target_name() {
    let sim = converged();
    sim.reset();
    let mut out = Vec::new();
    let _ = status::run_scoped(&fleet_a(), "dev", None, &sim, &mut out, true);
    let doc: Value = serde_json::from_slice(&out).unwrap();
    let row = doc["rows"]
        .as_array()
        .and_then(|rows| rows.iter().find(|r| r["key"] == "DB_URL"))
        .cloned()
        .unwrap_or_default();
    assert!(
        row["target_name"] == "DB_URL"
            && row["chain"]
                .as_str()
                .is_some_and(|c| c.contains("→ ExternalSecret opv-db-url-")),
        "{doc}"
    );
}

/// UX1 (NR-19): a refusal on the External Secrets path names a runnable next step.
#[test]
fn cluster_secret_store_not_ready_refusal_names_a_next_step() {
    let (_, e) = refused(not_ready);
    assert!(
        e.next_step()
            .is_some_and(|n| n.contains("kubectl") && n.contains("describe")),
        "{e:?}"
    );
}

// ---- sync --json (P2, NR-18) ----

fn deploy_json() -> SyncOpts {
    SyncOpts {
        deploy: true,
        json: true,
        ..Default::default()
    }
}

/// `sync --deploy --json` on Key Vault → Kubernetes prints one document: the target names
/// written and the deploy through the operator, with nothing left to do.
#[test]
fn sync_json_reports_key_vault_writes_and_the_deploy() {
    let sim = Sim::new(item_with(API_V1));
    let (res, out) = sync_on(&sim, &fleet_a(), &deploy_json());
    let doc: Value = serde_json::from_str(&out).expect("one JSON document");
    assert_eq!(
        (
            res.is_ok(),
            doc["provider"].clone(),
            doc["written"].clone(),
            doc["deployed"].clone(),
            doc["next"].clone()
        ),
        (
            true,
            json!("kubernetes"),
            json!(["API_KEY", "DB_URL", "OLD_KEY"]),
            json!(true),
            Value::Null
        ),
        "{out}"
    );
}

/// SR-1: the `sync --json` document carries names only, never a value.
#[test]
fn sync_json_carries_no_value() {
    let sim = Sim::new(item_with(API_V1));
    let (_, out) = sync_on(&sim, &fleet_a(), &deploy_json());
    assert!(
        SECRETS.iter().chain([&LOG]).all(|v| !out.contains(v)),
        "{out}"
    );
}
