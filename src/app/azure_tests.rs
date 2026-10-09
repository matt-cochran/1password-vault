//! `sync` and `status` against an Azure target (Key Vault + Container Apps), end to end
//! through the real adapters (FR-29, FR-31, FR-32, FR-33, NR-1, NR-2).
//!
//! [`Sim`] is a stateful fake of the `op` and `az` CLIs: Key Vault entries with versions and
//! tags, one Container App with its revisions. Every call is recorded (argv and stdin), so
//! the tests assert what reached argv and what went in the stdin documents, and call `k`
//! of a run can be made to fail with an unknown outcome (after its effect, for writes) to
//! drive the interruption matrix (NR-1).

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::io;
use std::time::Duration;

use serde_json::{Value, json};

use super::sync::{self, SyncOpts};
use super::testutil::*;
use crate::config;
use crate::domain::Fleet;
use crate::error::Error;
use crate::runner::{Call, CommandRunner, Outcome, Output};

const APP: &str = "opv-fixture-app";
const VAULT: &str = "kv-opv-fixture";

/// `OLD_KEY` is desired in prod under [`fleet_a`] and only in staging under [`fleet_b`], so
/// a sync of prod with `fleet_b` prunes it.
fn toml(old_key_envs: &str, config_route: &str) -> String {
    format!(
        r#"
[profile]
kind = "simple"
[environments.prod]
vault_id = "vprd"
item_id = "iprd"
[environments.prod.azure]
subscription = "00000000-0000-0000-0000-000000000000"
key_vault = "{VAULT}"
resource_group = "opv-fixture-rg"
container_app = "{APP}"
identity = "system"
{config_route}
[environments.staging]
vault_id = "vstg"
item_id = "istg"
[keys.API_KEY]
kind = "secret"
environments = ["prod"]
[keys.DB_URL]
kind = "secret"
environments = ["prod"]
[keys.LOG_LEVEL]
kind = "config"
environments = ["prod"]
[keys.OLD_KEY]
kind = "secret"
environments = {old_key_envs}
"#
    )
}

fn fleet_a() -> Fleet {
    config::parse(&toml(r#"["prod"]"#, "")).unwrap()
}

fn fleet_b() -> Fleet {
    config::parse(&toml(r#"["staging"]"#, "")).unwrap()
}

fn fleet_store() -> Fleet {
    config::parse(&toml(r#"["prod"]"#, r#"config = "store""#)).unwrap()
}

const API_V1: &str = "api-FIXTUREVALUE-1";
const API_V2: &str = "api-FIXTUREVALUE-2";
const DB: &str = "postgres://FIXTUREVALUE@db/app";
const LOG_V1: &str = "info-FIXTUREVALUE";
const LOG_V2: &str = "debug-FIXTUREVALUE";
const OLD: &str = "old-FIXTUREVALUE";

/// The 1Password item: API_KEY = `api`, LOG_LEVEL = `log`, plus DB_URL and OLD_KEY.
fn item_with(api: &str, log: &str) -> Vec<u8> {
    item(&[
        secret("", "API_KEY", api),
        secret("", "DB_URL", DB),
        text("", "LOG_LEVEL", log),
        secret("", "OLD_KEY", OLD),
    ])
    .stdout
    .to_vec()
}

struct KvEntry {
    /// Key Vault spelling, as first written.
    name: String,
    /// (version id, value), oldest first.
    versions: Vec<(String, String)>,
    tag: String,
}

/// The fake world `op` and `az` act on.
struct World {
    item: Vec<u8>,
    /// lower-cased Key Vault name → entry.
    kv: BTreeMap<String, KvEntry>,
    app: Value,
    revisions: BTreeMap<String, Value>,
    serial: u32,
    /// New revisions fail to provision.
    fail_revisions: bool,
    /// New revisions stay provisioning (the health wait times out).
    stall_revisions: bool,
}

/// One recorded call.
struct Rec {
    program: String,
    args: Vec<String>,
    stdin: Option<Vec<u8>>,
}

#[derive(Clone, Copy, PartialEq)]
enum Fail {
    /// The call's outcome is lost after it took effect (a write) or before (a read).
    After,
    /// The call never reached the target.
    Before,
}

/// A stateful fake `op` + `az`.
struct Sim {
    world: RefCell<World>,
    calls: RefCell<Vec<Rec>>,
    /// Fail the call with this 0-based index, counted from the last [`Sim::reset`].
    fail_at: Cell<Option<(usize, Fail)>>,
    /// Invariant breaks seen after any call: a serving binding to a missing version.
    violations: RefCell<Vec<String>>,
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

fn ok_json(v: &Value) -> Output {
    Output::success(serde_json::to_vec(v).unwrap())
}

fn revision(name: &str, template: &Value, failed: bool, stalled: bool) -> Value {
    let (prov, run, health) = if failed {
        ("Failed", "Failed", "Unhealthy")
    } else if stalled {
        ("Provisioning", "Activating", "None")
    } else {
        ("Provisioned", "Running", "Healthy")
    };
    json!({
        "name": name,
        "properties": {
            "provisioningState": prov,
            "runningState": run,
            "healthState": health,
            "template": template,
        }
    })
}

impl Sim {
    /// The recorded Container App with no managed env and no opv secrets, one healthy
    /// revision serving it.
    fn new(item: Vec<u8>) -> Self {
        let path = format!(
            "{}/tests/fixtures/azure/containerapp-show.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut app: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        app["properties"]["template"]["containers"][0]["env"] =
            json!([{"name": "PORT", "value": "80"}]);
        app["properties"]["configuration"]["secrets"] = json!([{"name": "plain-one"}]);
        let first = format!("{APP}--0000001");
        app["properties"]["latestRevisionName"] = json!(first);
        app["properties"]["latestReadyRevisionName"] = json!(first);
        let rev = revision(&first, &app["properties"]["template"], false, false);
        Self {
            world: RefCell::new(World {
                item,
                kv: BTreeMap::new(),
                app,
                revisions: BTreeMap::from([(first, rev)]),
                serial: 1,
                fail_revisions: false,
                stall_revisions: false,
            }),
            calls: RefCell::default(),
            fail_at: Cell::new(None),
            violations: RefCell::default(),
        }
    }

    /// Forget recorded calls (the world stays), so the next run is counted from 0.
    fn reset(&self) {
        self.calls.borrow_mut().clear();
    }

    fn set_item(&self, item: Vec<u8>) {
        self.world.borrow_mut().item = item;
    }

    fn handle(&self, call: &Call<'_>) -> Output {
        let args: Vec<String> = call.args.iter().map(|a| a.to_string()).collect();
        let stdin = call.stdin.map(<[u8]>::to_vec);
        let out = if call.program == "op" {
            Output::success(self.world.borrow().item.clone())
        } else {
            self.az(&args, stdin.as_deref())
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
            return Output::success(Vec::new());
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
            let (ver, value) = e.versions.last().unwrap();
            let id = format!("https://{VAULT}.vault.azure.net/secrets/{}/{ver}", e.name);
            return if flag(args, "--query") == Some("id") {
                Output::success(id.into_bytes())
            } else {
                ok_json(&json!({"id": id, "value": value}))
            };
        }
        if has(args, &["keyvault", "secret", "set"]) {
            w.serial += 1;
            let ver = format!("{:032x}", w.serial);
            let display = flag(args, "--name").unwrap().to_string();
            let tag = flag(args, "--tags")
                .unwrap()
                .trim_start_matches("opv-managed=");
            let value = String::from_utf8(stdin.unwrap().to_vec()).unwrap();
            let e = w.kv.entry(name.unwrap()).or_insert(KvEntry {
                name: display.clone(),
                versions: Vec::new(),
                tag: tag.into(),
            });
            e.versions.push((ver.clone(), value));
            e.tag = tag.into();
            let id = format!("https://{VAULT}.vault.azure.net/secrets/{display}/{ver}");
            return Output::success(id.into_bytes());
        }
        if has(args, &["keyvault", "secret", "delete"]) {
            w.kv.remove(name.as_deref().unwrap());
            return Output::success(Vec::new());
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
        if has(args, &["containerapp", "revision", "show"]) {
            return match w.revisions.get(flag(args, "--revision").unwrap()) {
                Some(r) => ok_json(r),
                None => Output::failure(3),
            };
        }
        if has(args, &["containerapp", "show"]) {
            return ok_json(&w.app);
        }
        if has(args, &["containerapp", "update"]) {
            let mut doc: Value = serde_json::from_slice(stdin.unwrap()).unwrap();
            let p = &w.app["properties"];
            let (mut latest, mut ready) = (
                p["latestRevisionName"].clone(),
                p["latestReadyRevisionName"].clone(),
            );
            if doc["properties"]["template"] != w.app["properties"]["template"] {
                w.serial += 1;
                let rev = format!("{APP}--{:07}", w.serial);
                let (failed, stalled) = (w.fail_revisions, w.stall_revisions);
                let r = revision(&rev, &doc["properties"]["template"], failed, stalled);
                w.revisions.insert(rev.clone(), r);
                latest = json!(rev);
                if !failed && !stalled {
                    ready = json!(rev);
                }
            }
            doc["properties"]["latestRevisionName"] = latest;
            doc["properties"]["latestReadyRevisionName"] = ready;
            w.app = doc;
            return ok_json(&w.app);
        }
        panic!("Sim: unexpected az call {args:?}");
    }

    /// NR-1 invariant: every env var the serving revision binds to a Key Vault reference
    /// resolves to a version that exists.
    fn check(&self) {
        let w = self.world.borrow();
        let ready = w.app["properties"]["latestReadyRevisionName"]
            .as_str()
            .unwrap_or_default();
        let Some(rev) = w.revisions.get(ready) else {
            return;
        };
        for (env, value) in resolve(&w, &rev["properties"]["template"]) {
            if value == MISSING {
                self.violations
                    .borrow_mut()
                    .push(format!("{env} bound to a missing version"));
            }
        }
    }

    fn argvs(&self) -> Vec<String> {
        self.calls
            .borrow()
            .iter()
            .map(|c| format!("{} {}", c.program, c.args.join(" ")))
            .collect()
    }

    fn index_of(&self, prefix: &[&str]) -> Option<usize> {
        self.calls
            .borrow()
            .iter()
            .position(|c| c.program == "az" && has(&c.args, prefix))
    }

    fn called(&self, prefix: &[&str]) -> bool {
        self.index_of(prefix).is_some()
    }

    /// The `containerapp update` stdin document.
    fn update_doc(&self) -> Value {
        let calls = self.calls.borrow();
        let c = calls
            .iter()
            .find(|c| has(&c.args, &["containerapp", "update"]))
            .expect("no containerapp update");
        serde_json::from_slice(c.stdin.as_ref().unwrap()).unwrap()
    }

    /// The managed container's env entry `name` in the update document.
    fn updated_env(&self, name: &str) -> Value {
        let doc = self.update_doc();
        doc["properties"]["template"]["containers"][0]["env"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["name"] == name)
            .cloned()
            .unwrap_or(Value::Null)
    }

    /// The latest version id of a Key Vault entry.
    fn version(&self, kv_name: &str) -> String {
        let w = self.world.borrow();
        w.kv[&kv_name.to_ascii_lowercase()]
            .versions
            .last()
            .unwrap()
            .0
            .clone()
    }

    /// Re-point the binding of `env` to `version` by hand, as someone in the portal would.
    fn repin_by_hand(&self, env: &str, version: &str) {
        let mut w = self.world.borrow_mut();
        let secret_ref = w.app["properties"]["template"]["containers"][0]["env"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["name"] == env)
            .unwrap()["secretRef"]
            .clone();
        for s in w.app["properties"]["configuration"]["secrets"]
            .as_array_mut()
            .unwrap()
        {
            if s["name"] == secret_ref {
                let url = s["keyVaultUrl"].as_str().unwrap();
                let base = &url[..url.rfind('/').unwrap()];
                s["keyVaultUrl"] = json!(format!("{base}/{version}"));
            }
        }
    }

    /// What the app runs with, by managed env name, plus every Key Vault entry's current
    /// value: version ids differ between runs, values must not.
    fn end_state(&self) -> (BTreeMap<String, String>, BTreeMap<String, String>) {
        let w = self.world.borrow();
        let env = resolve(&w, &w.app["properties"]["template"])
            .into_iter()
            .filter(|(n, _)| n != "PORT")
            .collect();
        let kv =
            w.kv.iter()
                .map(|(n, e)| (n.clone(), e.versions.last().unwrap().1.clone()))
                .collect();
        (env, kv)
    }
}

const MISSING: &str = "<missing version>";

/// env name → value the template gives it: a plain value, or the Key Vault value its
/// reference resolves to (suffixed `@old` when not the entry's latest version).
fn resolve(w: &World, template: &Value) -> BTreeMap<String, String> {
    let secrets = w.app["properties"]["configuration"]["secrets"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut out = BTreeMap::new();
    for e in template["containers"][0]["env"].as_array().unwrap() {
        let name = e["name"].as_str().unwrap().to_string();
        if let Some(v) = e["value"].as_str() {
            out.insert(name, v.to_string());
            continue;
        }
        let r = e["secretRef"].as_str().unwrap();
        let value = secrets
            .iter()
            .find(|s| s["name"] == r)
            .and_then(|s| s["keyVaultUrl"].as_str())
            .and_then(|url| {
                let mut parts = url.rsplit('/');
                let (ver, kv) = (parts.next()?, parts.next()?);
                let entry = w.kv.get(&kv.to_ascii_lowercase())?;
                let (_, v) = entry.versions.iter().find(|(id, _)| id == ver)?;
                let latest = entry.versions.last()?.0 == ver;
                Some(if latest {
                    v.clone()
                } else {
                    format!("{v}@old")
                })
            })
            .unwrap_or_else(|| MISSING.to_string());
        out.insert(name, value);
    }
    out
}

impl Sim {
    /// Counts this call; on the failing index, returns the unknown outcome (a write takes
    /// effect first when the failure is `After`).
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
    fn read(&self, call: &Call<'_>, refused: &[i32]) -> io::Result<Outcome> {
        if let Some(o) = self.step(call, false) {
            return Ok(o);
        }
        let out = self.handle(call);
        Ok(match out.status {
            0 => Outcome::Done(out),
            s if refused.contains(&s) => Outcome::Refused(out),
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

    fn probe(&self, call: &Call<'_>, _limit: Duration) -> io::Result<Output> {
        if self.step(call, false).is_some() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(self.handle(call))
    }

    fn pause(&self, _: Duration, _: &str) {}

    fn note(&self, _: &str) {}

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
    let res = sync::run(fleet, "prod", sim, &mut out, opts);
    (res, text_of(&out))
}

/// A world opv has already synced and deployed (`fleet_a`, API_KEY = v1, LOG_LEVEL = v1).
fn converged() -> Sim {
    converged_with(&fleet_a())
}

fn converged_with(fleet: &Fleet) -> Sim {
    let sim = Sim::new(item_with(API_V1, LOG_V1));
    let (res, out) = sync_on(&sim, fleet, &deploy());
    assert!(res.is_ok(), "setup sync failed: {res:?}\n{out}");
    sim.reset();
    sim
}

/// A converged world whose item now holds API_KEY v2.
fn api_changed() -> Sim {
    let sim = converged();
    sim.set_item(item_with(API_V2, LOG_V1));
    sim
}

/// A converged world whose binding of API_KEY was moved by hand to an older version.
fn drifted() -> Sim {
    let sim = api_changed();
    let old = sim.version("API-KEY");
    let (res, _) = sync_on(&sim, &fleet_a(), &deploy());
    assert!(res.is_ok());
    sim.repin_by_hand("API_KEY", &old);
    sim.reset();
    sim
}

// ---- the brief's table ----

#[test]
fn no_change_writes_nothing_and_does_not_deploy() {
    let sim = converged();
    sync_on(&sim, &fleet_a(), &deploy()).0.unwrap();
    let writes =
        sim.called(&["keyvault", "secret", "set"]) || sim.called(&["containerapp", "update"]);
    assert!(!writes, "{:?}", sim.argvs());
}

#[test]
fn changed_secret_writes_new_version_and_reports_pending_without_deploy() {
    let sim = api_changed();
    let (_, out) = sync_on(&sim, &fleet_a(), &SyncOpts::default());
    assert!(
        out.lines()
            .any(|l| l == "pending deploy (pass --deploy): API_KEY"),
        "{out}"
    );
}

#[test]
fn changed_secret_without_deploy_leaves_the_app_unchanged() {
    let sim = api_changed();
    sync_on(&sim, &fleet_a(), &SyncOpts::default()).0.unwrap();
    assert!(!sim.called(&["containerapp", "update"]));
}

#[test]
fn deploy_pins_new_version() {
    let sim = api_changed();
    sync_on(&sim, &fleet_a(), &deploy()).0.unwrap();
    let version = sim.version("API-KEY");
    assert!(
        sim.update_doc()
            .to_string()
            .contains(&format!("/API-KEY/{version}"))
    );
}

#[test]
fn deploy_sets_changed_config_as_env_value() {
    let sim = converged();
    sim.set_item(item_with(API_V1, LOG_V2));
    sync_on(&sim, &fleet_a(), &deploy()).0.unwrap();
    assert_eq!(
        sim.updated_env("LOG_LEVEL"),
        json!({"name": "LOG_LEVEL", "value": LOG_V2})
    );
}

#[test]
fn config_routed_to_store_is_written_to_key_vault() {
    let sim = Sim::new(item_with(API_V1, LOG_V1));
    sync_on(&sim, &fleet_store(), &deploy()).0.unwrap();
    assert_eq!(
        sim.end_state().1.get("log-level"),
        Some(&LOG_V1.to_string())
    );
}

#[test]
fn config_routed_to_store_is_bound_by_reference() {
    let sim = Sim::new(item_with(API_V1, LOG_V1));
    sync_on(&sim, &fleet_store(), &deploy()).0.unwrap();
    assert!(sim.updated_env("LOG_LEVEL").get("value").is_none());
}

#[test]
fn unchanged_config_routed_to_store_writes_no_version() {
    let sim = converged_with(&fleet_store());
    sync_on(&sim, &fleet_store(), &deploy()).0.unwrap();
    assert!(
        !sim.called(&["keyvault", "secret", "set"]),
        "{:?}",
        sim.argvs()
    );
}

#[test]
fn drift_is_reported_by_status() {
    let sim = drifted();
    let mut out = Vec::new();
    super::status::run(&fleet_a(), "prod", &sim, &mut out).unwrap();
    assert!(
        text_of(&out)
            .lines()
            .any(|l| l == sync::drift_line("prod", "API_KEY")),
        "{}",
        text_of(&out)
    );
}

#[test]
fn drift_is_flagged_in_status_json() {
    let sim = drifted();
    let mut out = Vec::new();
    super::status::run_with(&fleet_a(), "prod", &sim, &mut out, true).unwrap();
    let doc: Value = serde_json::from_slice(&out).unwrap();
    let row = doc["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["key"] == "API_KEY")
        .cloned()
        .unwrap();
    assert_eq!(
        (
            row["binding"].clone(),
            row["pending_deploy"].clone(),
            row["drift"].clone()
        ),
        (json!("stale"), json!(true), json!(true))
    );
}

#[test]
fn drift_is_left_without_deploy() {
    let sim = drifted();
    sync_on(&sim, &fleet_a(), &SyncOpts::default()).0.unwrap();
    assert!(!sim.called(&["containerapp", "update"]));
}

#[test]
fn drift_is_overwritten_with_deploy() {
    let sim = drifted();
    sync_on(&sim, &fleet_a(), &deploy()).0.unwrap();
    assert_eq!(sim.end_state().0["API_KEY"], API_V2);
}

#[test]
fn failed_revision_names_doctor_access_check() {
    let sim = api_changed();
    sim.world.borrow_mut().fail_revisions = true;
    let (res, _) = sync_on(&sim, &fleet_a(), &deploy());
    assert!(
        matches!(&res, Err(Error::Target(m)) if m.mentions("opv doctor --env prod")
            && m.contains("previous revision keeps serving")),
        "{res:?}"
    );
}

#[test]
fn unhealthy_revision_prunes_nothing() {
    let sim = converged();
    sim.world.borrow_mut().fail_revisions = true;
    let _ = sync_on(&sim, &fleet_b(), &deploy_prune());
    assert!(
        !sim.called(&["keyvault", "secret", "delete"]),
        "{:?}",
        sim.argvs()
    );
}

#[test]
fn prune_with_deploy_deletes_after_healthy_revision() {
    let sim = converged();
    sync_on(&sim, &fleet_b(), &deploy_prune()).0.unwrap();
    let update = sim.index_of(&["containerapp", "update"]).unwrap();
    let healthy = sim
        .calls
        .borrow()
        .iter()
        .enumerate()
        .skip(update)
        .find(|(_, c)| has(&c.args, &["containerapp", "revision", "show"]))
        .map(|(i, _)| i)
        .unwrap();
    assert!(sim.index_of(&["keyvault", "secret", "delete"]) > Some(healthy));
}

#[test]
fn prune_with_deploy_unbinds_and_deletes_the_entry() {
    let sim = converged();
    sync_on(&sim, &fleet_b(), &deploy_prune()).0.unwrap();
    let (env, kv) = sim.end_state();
    assert!(!env.contains_key("OLD_KEY") && !kv.contains_key("old-key"));
}

#[test]
fn prune_without_deploy_only_reports() {
    let sim = converged();
    let (_, out) = sync_on(
        &sim,
        &fleet_b(),
        &SyncOpts {
            prune: true,
            ..Default::default()
        },
    );
    assert!(
        out.lines()
            .any(|l| l == "not pruned without --deploy: OLD_KEY"),
        "{out}"
    );
}

#[test]
fn not_desired_without_prune_is_kept() {
    let sim = converged();
    let (_, out) = sync_on(&sim, &fleet_b(), &deploy());
    assert!(
        out.lines()
            .any(|l| l == "not desired here, kept (pass --prune to remove): OLD_KEY"),
        "{out}"
    );
}

#[test]
fn refused_sync_makes_no_az_calls() {
    let sim = Sim::new(
        item(&[secret("", "API_KEY", API_V1), text("", "LOG_LEVEL", LOG_V1)])
            .stdout
            .to_vec(),
    );
    let _ = sync_on(&sim, &fleet_a(), &deploy());
    assert!(
        sim.calls.borrow().iter().all(|c| c.program != "az"),
        "{:?}",
        sim.argvs()
    );
}

#[test]
fn refused_sync_names_the_missing_key() {
    let sim = Sim::new(
        item(&[secret("", "API_KEY", API_V1), text("", "LOG_LEVEL", LOG_V1)])
            .stdout
            .to_vec(),
    );
    let (res, _) = sync_on(&sim, &fleet_a(), &deploy());
    assert!(
        matches!(&res, Err(Error::Policy(m)) if m.starts_with("sync refused, nothing staged: DB_URL")),
        "{res:?}"
    );
}

/// NR-1: a run that loses call k (for every k, after its effect for writes), then one clean
/// re-run, ends where a clean run ends, and no serving binding ever names a missing version.
#[test]
fn azure_sync_converges_after_interruption_at_every_call() {
    let scenario = || {
        let sim = converged();
        sim.set_item(item_with(API_V2, LOG_V2));
        sim
    };
    let clean = scenario();
    sync_on(&clean, &fleet_b(), &deploy_prune()).0.unwrap();
    let calls = clean.calls.borrow().len();
    let expected = clean.end_state();
    let mut diverged = Vec::new();
    for k in 0..calls {
        for mode in [Fail::After, Fail::Before] {
            let sim = scenario();
            sim.fail_at.set(Some((k, mode)));
            let _ = sync_on(&sim, &fleet_b(), &deploy_prune());
            sim.fail_at.set(None);
            let rerun = sync_on(&sim, &fleet_b(), &deploy_prune()).0;
            if rerun.is_err() || sim.end_state() != expected || !sim.violations.borrow().is_empty()
            {
                diverged.push(format!(
                    "k={k} {}: {rerun:?} {:?}",
                    if mode == Fail::After {
                        "after"
                    } else {
                        "before"
                    },
                    sim.violations.borrow()
                ));
            }
        }
    }
    assert!(diverged.is_empty(), "{diverged:#?}");
}

/// NR-2: an update whose outcome is lost after Azure applied it is confirmed by reading
/// the app back, and the run completes.
#[test]
fn unknown_apply_is_reconciled_by_reading_the_revision() {
    let update = {
        let probe = api_changed();
        sync_on(&probe, &fleet_a(), &deploy()).0.unwrap();
        probe.index_of(&["containerapp", "update"]).unwrap()
    };
    let sim = api_changed();
    sim.fail_at.set(Some((update, Fail::After)));
    let (res, out) = sync_on(&sim, &fleet_a(), &deploy());
    assert!(
        res.is_ok() && out.contains("the update was applied"),
        "{res:?}\n{out}"
    );
}

/// NR-2: when the read-back does not show the change, the outcome stays unknown (exit 9).
#[test]
fn unknown_apply_that_did_not_land_exits_9() {
    let update = {
        let probe = api_changed();
        sync_on(&probe, &fleet_a(), &deploy()).0.unwrap();
        probe.index_of(&["containerapp", "update"]).unwrap()
    };
    let sim = api_changed();
    sim.fail_at.set(Some((update, Fail::Before)));
    let (res, _) = sync_on(&sim, &fleet_a(), &deploy());
    assert_eq!(res.map_err(|e| e.exit_code()), Err(9));
}

#[test]
fn values_never_reach_argv() {
    let sims = [
        {
            let s = api_changed();
            sync_on(&s, &fleet_a(), &deploy()).0.unwrap();
            s
        },
        {
            let s = converged();
            sync_on(&s, &fleet_b(), &deploy_prune()).0.unwrap();
            s
        },
        {
            let s = Sim::new(item_with(API_V1, LOG_V1));
            sync_on(&s, &fleet_store(), &deploy()).0.unwrap();
            s
        },
    ];
    let leaked: Vec<String> = sims
        .iter()
        .flat_map(Sim::argvs)
        .filter(|a| a.contains(MARKER))
        .collect();
    assert!(leaked.is_empty(), "{leaked:?}");
}

#[test]
fn secret_is_never_routed_to_plain_env() {
    let sim = Sim::new(item_with(API_V1, LOG_V1));
    sync_on(&sim, &fleet_a(), &deploy()).0.unwrap();
    let plain: Vec<Value> = ["API_KEY", "DB_URL", "OLD_KEY"]
        .iter()
        .map(|n| sim.updated_env(n))
        .filter(|e| e.get("value").is_some() || e.get("secretRef").is_none())
        .collect();
    assert!(plain.is_empty(), "{plain:?}");
}

#[test]
fn sync_output_holds_no_value() {
    let sim = api_changed();
    let (_, out) = sync_on(&sim, &fleet_a(), &deploy());
    assert_no_values(&out);
}

#[test]
fn env_routed_config_is_named_with_its_reader() {
    let sim = converged();
    let (_, out) = sync_on(&sim, &fleet_a(), &deploy());
    assert!(
        out.lines()
            .any(|l| l
                == format!("env-routed (visible to readers of container app {APP}): LOG_LEVEL")),
        "{out}"
    );
}

/// A deploy with nothing to change still confirms the latest revision: one that failed is
/// never reported as done.
#[test]
fn no_change_deploy_reports_a_failed_latest_revision() {
    let sim = api_changed();
    sim.world.borrow_mut().fail_revisions = true;
    let _ = sync_on(&sim, &fleet_a(), &deploy());
    let (res, _) = sync_on(&sim, &fleet_a(), &deploy());
    assert!(matches!(res, Err(Error::Target(_))), "{res:?}");
}

/// Shortens the health wait for targets opened on this thread; no test waits 300 s.
fn short_wait() {
    crate::adapters::azure::config::TEST_WAIT
        .with(|w| w.set(Some((Duration::from_secs(1), Duration::from_secs(2)))));
}

#[test]
fn timed_out_revision_names_revision_and_keeps_previous_serving() {
    short_wait();
    let sim = api_changed();
    sim.world.borrow_mut().stall_revisions = true;
    let (res, _) = sync_on(&sim, &fleet_a(), &deploy());
    let new_rev = format!("{APP}--{:07}", sim.world.borrow().serial);
    assert!(
        matches!(&res, Err(Error::Target(m)) if m.contains(&new_rev)
            && m.contains("previous revision keeps serving")
            && m.contains("not healthy yet")),
        "{res:?}"
    );
}

#[test]
fn no_change_deploy_with_failed_latest_revision_says_opv_changed_nothing() {
    let sim = api_changed();
    sim.world.borrow_mut().fail_revisions = true;
    let _ = sync_on(&sim, &fleet_a(), &deploy());
    let (res, _) = sync_on(&sim, &fleet_a(), &deploy());
    assert!(
        matches!(&res, Err(Error::Target(m)) if m.starts_with("nothing to change; the latest revision")
            && m.contains("(with these settings) is unhealthy")
            && m.contains("opv changed nothing")
            && m.next().is_some_and(|n| n.starts_with("az containerapp revision show"))),
        "{res:?}"
    );
}

/// A world synced with config in the store, whose LOG_LEVEL key is then withdrawn.
fn config_withdrawn() -> (Sim, Fleet) {
    let sim = converged_with(&fleet_store());
    let fleet = config::parse(&toml(r#"["prod"]"#, r#"config = "store""#).replace(
        "[keys.LOG_LEVEL]\nkind = \"config\"\nenvironments = [\"prod\"]",
        "[keys.LOG_LEVEL]\nkind = \"config\"\nenvironments = [\"staging\"]",
    ))
    .unwrap();
    (sim, fleet)
}

#[test]
fn prune_with_deploy_deletes_withdrawn_config_entry_from_the_store() {
    let (sim, fleet) = config_withdrawn();
    sync_on(&sim, &fleet, &deploy_prune()).0.unwrap();
    assert!(!sim.end_state().1.contains_key("log-level"));
}

#[test]
fn withdrawn_config_entry_is_kept_without_prune() {
    let (sim, fleet) = config_withdrawn();
    sync_on(&sim, &fleet, &deploy()).0.unwrap();
    assert!(sim.end_state().1.contains_key("log-level"));
}

#[test]
fn withdrawn_config_entry_is_not_deleted_before_a_healthy_revision() {
    let (sim, fleet) = config_withdrawn();
    sim.world.borrow_mut().fail_revisions = true;
    let _ = sync_on(&sim, &fleet, &deploy_prune());
    assert!(!sim.called(&["keyvault", "secret", "delete"]));
}

// ---- UX1: the run summary is the same on every provider (P2, NR-18) ----

#[test]
fn azure_sync_summary_names_the_deployed_revision() {
    let sim = api_changed();
    let (_, out) = sync_on(&sim, &fleet_a(), &deploy());
    assert!(
        out.lines().any(
            |l| l.starts_with("summary: written 1 · deployed opv-fixture-app--")
                && l.ends_with(" · pruned 0 · pending 0 · unchanged 2 · skipped 0")
        ),
        "{out}"
    );
}

#[test]
fn azure_sync_without_deploy_names_the_deploy_command_last() {
    let sim = api_changed();
    let (_, out) = sync_on(&sim, &fleet_a(), &SyncOpts::default());
    assert_eq!(
        out.lines().last(),
        Some("Next: opv sync prod --deploy"),
        "{out}"
    );
}
