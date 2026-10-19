//! Kubernetes files and ConfigMaps end to end (delivery-transports §6, §11.1 K6): the real
//! `opv` binary against `opv-sim`, on the test application in `tests/e2e/app`, whose `k8s`
//! target sets `kubernetes.secrets_dir = "/run/secrets/{product}"` and `kubernetes.config =
//! "configmap"`. The `web` product delivers two secret file keys (`TLS_CERTIFICATE`,
//! `TLS_PRIVATE_KEY`), one config file key (`OTEL_RESOURCE`) and one config key bound as env
//! (`LOG_LEVEL`). The world's Deployment `e2e-app` has the shape of the K1 recording
//! (`tests/fixtures/kubernetes/success/07-get-deployment-before-files`): containers `e2e-app`
//! and `sidecar`, `runAsUser`/`runAsGroup` 10001 and, unless a scenario changes it, `fsGroup`
//! 10001.
//!
//! Each scenario copies the app's world and configuration into a scratch directory, changes
//! the world where it needs to, and runs opv there with a scratch HOME and `OPV_NO_SKILL=1`.
//! Every value of the world that `tests/e2e/app` marks (`test-marker-e2e-…`) becomes an
//! `S7MARKER` marker, so one substring check finds a value printed, passed in argv or left
//! in the Deployment (the canary scan). A test asserts once, on a public outcome: the exit
//! code, the `--json` document, the calls opv made, the world it left, or the committed
//! snapshot (`tests/e2e/snapshots/k8s_files/<name>.snap`, rewritten with
//! `UPDATE_SNAPSHOTS=1`; compared on Linux only).
//!
//! What each scenario reaches through the recordings (`tests/fixtures/kubernetes/README.md`):
//! - `plan`: the design §6.7 lines; nothing is written.
//! - `deploy`: K-R7 (`apply` of the ConfigMaps), K-R1 (the `replace` with the volume), K-R3
//!   (the read-back), then `status` and its `chain:` lines, and a `plan` with nothing left.
//! - `unreadable`: no `fsGroup`, a non-root user: `mount_unreadable` before any write.
//! - `root`: `runAsUser: 0`: synced, with the root warning.
//! - `foreign_mount`: another volume mounted above the directory: `policy_refused`.
//! - `volume_refused` (K-R2): an `opv-files-` volume an earlier configuration left at the
//!   same directory; opv's own mount makes two at one path and the API server's 422 is
//!   `update_refused`.
//! - `source_missing` (K-R4): the team's own projected volume names a ConfigMap that does
//!   not exist, so the new pod waits in `ContainerCreating` (not a reason opv treats as
//!   stuck). opv reports the rollout as still in progress when its wait ends
//!   (`update_refused`, `in_progress`); the progress deadline itself was not recorded.
//! - `configmap_right_missing`: no `delete configmaps`: `permission_denied` before any write.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};

const APP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/e2e/app");
/// The project's account: it holds every vault of the app.
const PROJECT: &str = "AE2EDEVACCOUNT000000000001";
/// The marker every value of a scenario's world carries.
const MARK: &str = "S7MARKER";
const NS: &str = "/kubernetes/contexts/e2e-cluster/namespaces/e2e-prod";

const PLAN: &[&str] = &["plan", "prod", "--target", "k8s"];
const STATUS: &[&str] = &["status", "prod", "--target", "k8s"];
const SYNC: &[&str] = &[
    "sync",
    "prod",
    "--confirm",
    "prod",
    "--target",
    "k8s",
    "--deploy",
];
/// [`SYNC`] whose rollout wait ends early: a rollout that never finishes is reported then.
const SYNC_SHORT: &[&str] = &[
    "sync",
    "prod",
    "--confirm",
    "prod",
    "--target",
    "k8s",
    "--deploy",
    "--timeout",
    "8",
];

/// A scratch HOME, project and world, and the simulator installed under every tool name.
struct Scenario {
    root: tempfile::TempDir,
}

impl Scenario {
    /// The app's world with every value an `S7MARKER` marker, changed by `edit`.
    fn new(edit: fn(&mut Value)) -> Self {
        let s = Self {
            root: tempfile::tempdir().expect("temp dir"),
        };
        for dir in ["world", "home", "project"] {
            std::fs::create_dir_all(s.root.path().join(dir)).expect("scenario dir");
        }
        let mut world: Value = serde_json::from_str(
            &std::fs::read_to_string(Path::new(APP).join("world.json")).expect("world"),
        )
        .expect("world");
        mark_values(&mut world);
        edit(&mut world);
        std::fs::write(s.world().join("world.json"), world.to_string()).expect("world");
        std::fs::write(s.world().join("faults.toml"), "").expect("faults");
        std::fs::copy(
            Path::new(APP).join("secrets.toml"),
            s.project().join("secrets.toml"),
        )
        .expect("config");
        std::fs::copy(
            Path::new(APP).join("secrets.bindings.toml"),
            s.project().join("secrets.bindings.toml"),
        )
        .expect("config");
        std::fs::write(
            s.project().join(".opv"),
            format!("account = \"{PROJECT}\"\n"),
        )
        .expect(".opv");
        let installed = Command::new(env!("CARGO_BIN_EXE_opv-sim"))
            .arg("install")
            .arg(s.bin())
            .env("OPV_SIM_WORLD", s.world())
            .status()
            .expect("opv-sim install");
        assert!(installed.success(), "opv-sim install failed");
        s
    }

    fn world(&self) -> PathBuf {
        self.root.path().join("world")
    }

    fn project(&self) -> PathBuf {
        self.root.path().join("project")
    }

    fn bin(&self) -> PathBuf {
        self.root.path().join("bin")
    }

    /// `opv <args>` in the project, against the simulator only.
    fn opv(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_opv"))
            .args(args)
            .current_dir(self.project())
            .env_clear()
            .env("PATH", format!("{}:/usr/bin:/bin", self.bin().display()))
            .env("HOME", self.root.path().join("home"))
            .env("OPV_NO_SKILL", "1")
            .env("OPV_SIM_WORLD", self.world())
            .stdin(Stdio::null())
            .output()
            .expect("run opv")
    }

    /// The `--json` document of `opv <args> --json`.
    fn json(&self, args: &[&str]) -> Value {
        let mut args = args.to_vec();
        args.push("--json");
        let out = self.opv(&args);
        serde_json::Deserializer::from_slice(&out.stdout)
            .into_iter::<Value>()
            .next()
            .and_then(Result::ok)
            .unwrap_or_default()
    }

    /// The calls the simulator answered so far, one line each (argv only).
    fn calls(&self) -> String {
        std::fs::read_to_string(self.world().join("calls.log")).unwrap_or_default()
    }

    /// The world as the run left it.
    fn left(&self) -> Value {
        serde_json::from_str(
            &std::fs::read_to_string(self.world().join("world.json")).expect("world"),
        )
        .expect("world")
    }

    /// The Deployment as the run left it.
    fn deployment(&self) -> Value {
        self.left()
            .pointer(&format!("{NS}/deployments/0"))
            .cloned()
            .unwrap_or_default()
    }
}

/// Every string of the world that holds a value marker (`test-marker-e2e-…`,
/// `…_e2e_marker_…`) becomes an `S7MARKER` marker of the same suffix.
fn mark_values(v: &mut Value) {
    match v {
        Value::String(s) if s.contains("test-marker-e2e-") || s.contains("_e2e_marker_") => {
            *s = format!("{MARK}VALUE-{s}");
        }
        Value::Array(a) => a.iter_mut().for_each(mark_values),
        Value::Object(o) => o.values_mut().for_each(mark_values),
        _ => {}
    }
}

/// Everything a run printed.
fn shown(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

// --- the worlds -------------------------------------------------------------------------

fn pod_spec(w: &mut Value) -> &mut Value {
    w.pointer_mut(&format!("{NS}/deployments/0/spec/template/spec"))
        .expect("the e2e Deployment")
}

/// The app's world as committed: `fsGroup` 10001, so the files are readable.
fn readable(_: &mut Value) {}

/// No `fsGroup`, user and group 10001 (K-R5 `nofsgroup`): the 0440 root-owned files are
/// unreadable.
fn unreadable(w: &mut Value) {
    pod_spec(w)["securityContext"] = json!({"runAsUser": 10001, "runAsGroup": 10001});
}

/// The workload runs as root (K-R5 `root`).
fn root(w: &mut Value) {
    pod_spec(w)["securityContext"] = json!({"runAsUser": 0});
}

/// Another volume is mounted at `/run/secrets`, above the files' directory.
fn foreign_mount(w: &mut Value) {
    let spec = pod_spec(w);
    spec["volumes"] = json!([{"name": "tls", "secret": {"secretName": "e2e-app-tls"}}]);
    spec["containers"][0]["volumeMounts"] =
        json!([{"name": "tls", "mountPath": "/run/secrets", "readOnly": true}]);
}

/// An `opv-files-` volume an earlier configuration left at `/run/secrets/web`: not opv's
/// volume for `web`, and not foreign either, so opv adds its own mount beside it.
fn volume_left_behind(w: &mut Value) {
    let spec = pod_spec(w);
    spec["volumes"] = json!([{"name": "opv-files-legacy", "emptyDir": {}}]);
    spec["containers"][0]["volumeMounts"] =
        json!([{"name": "opv-files-legacy", "mountPath": "/run/secrets/web"}]);
}

/// The team's own projected volume names a ConfigMap the namespace does not hold.
fn source_missing(w: &mut Value) {
    let spec = pod_spec(w);
    spec["volumes"] = json!([{"name": "settings", "projected": {"sources": [
        {"configMap": {"name": "e2e-app-settings"}}]}}]);
    spec["containers"][0]["volumeMounts"] =
        json!([{"name": "settings", "mountPath": "/etc/e2e-app", "readOnly": true}]);
}

/// opv's identity may not delete ConfigMaps.
fn configmap_right_missing(w: &mut Value) {
    w["kubernetes"]["contexts"]["e2e-cluster"]["denied"] = json!(["delete configmaps"]);
}

// --- snapshots ----------------------------------------------------------------------------

/// What a snapshot must not depend on: the scenario's path, the random version ids of
/// opv's objects, the plan ids built from them and the write time of the stamp.
#[cfg(target_os = "linux")]
fn normalize(s: &Scenario, text: &str) -> String {
    let root = s.root.path().display().to_string();
    let text = text.replace(&root, "<SCENARIO>");
    let re = |p: &str| regex::Regex::new(p).expect("regex");
    let text = re(r"(opv-[a-z0-9-]+-)[a-z2-7]{10}\b").replace_all(&text, "${1}<id>");
    let text = re(r"\bplan [0-9a-f]{8}\b").replace_all(&text, "plan <plan>");
    let text = re(r"--expect-plan [0-9a-f]{8}\b").replace_all(&text, "--expect-plan <plan>");
    let text = re(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ").replace_all(&text, "<time>");
    re(r"\bin \d+(\.\d+)? ?(ms|s)\b")
        .replace_all(&text, "in <delay>")
        .into_owned()
}

/// `steps` run in order on one fresh world, as one snapshot.
#[cfg(target_os = "linux")]
fn record(world: fn(&mut Value), steps: &[&[&str]]) -> String {
    let s = Scenario::new(world);
    let mut snap = String::new();
    for args in steps {
        let out = s.opv(args);
        snap.push_str(&format!(
            "# opv {}\n## exit: {}\n## stdout\n{}\n## stderr\n{}\n",
            args.join(" "),
            out.status.code().map_or("killed".into(), |c| c.to_string()),
            normalize(&s, &String::from_utf8_lossy(&out.stdout)),
            normalize(&s, &String::from_utf8_lossy(&out.stderr)),
        ));
    }
    snap
}

/// The recorded runs equal the committed snapshot `name` (rewritten under
/// `UPDATE_SNAPSHOTS=1`).
#[cfg(target_os = "linux")]
fn snapshot_test(name: &str, world: fn(&mut Value), steps: &[&[&str]]) {
    const SNAPSHOTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/e2e/snapshots/k8s_files");
    let got = record(world, steps);
    let path = Path::new(SNAPSHOTS).join(format!("{name}.snap"));
    if std::env::var("UPDATE_SNAPSHOTS").is_ok_and(|v| v == "1") {
        std::fs::create_dir_all(SNAPSHOTS).expect("snapshots dir");
        std::fs::write(&path, &got).expect("write snapshot");
        return;
    }
    let want = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(
        got,
        want,
        "{} differs from its snapshot; review and rerun with UPDATE_SNAPSHOTS=1",
        path.display()
    );
}

#[cfg(target_os = "linux")]
mod snapshots {
    use super::*;

    #[test]
    fn plan_matches_its_snapshot() {
        snapshot_test("plan", readable, &[PLAN]);
    }

    #[test]
    fn deploy_then_status_and_plan_match_their_snapshot() {
        snapshot_test("deploy", readable, &[SYNC, STATUS, PLAN]);
    }

    #[test]
    fn unreadable_matches_its_snapshot() {
        snapshot_test("unreadable", unreadable, &[PLAN, SYNC]);
    }

    #[test]
    fn root_matches_its_snapshot() {
        snapshot_test("root", root, &[SYNC]);
    }

    #[test]
    fn foreign_mount_matches_its_snapshot() {
        snapshot_test("foreign_mount", foreign_mount, &[SYNC]);
    }

    #[test]
    fn volume_refused_matches_its_snapshot() {
        snapshot_test("volume_refused", volume_left_behind, &[SYNC]);
    }

    #[test]
    fn source_missing_matches_its_snapshot() {
        snapshot_test("source_missing", source_missing, &[SYNC_SHORT]);
    }

    #[test]
    fn configmap_right_missing_matches_its_snapshot() {
        snapshot_test("configmap_right_missing", configmap_right_missing, &[SYNC]);
    }
}

// --- plan: the design §6.7 lines ------------------------------------------------------------

#[test]
fn plan_names_the_mounted_path_of_a_file_key() {
    let out = Scenario::new(readable).opv(PLAN);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains(
            "prod/k8s: would write: web/TLS_PRIVATE_KEY (E2E__WEB__TLS_PRIVATE_KEY → file \
             /run/secrets/web/tls/private-key)\n"
        ),
        "{}",
        shown(&out)
    );
}

#[test]
fn plan_names_a_config_key_as_a_configmap_bound_to_env() {
    let out = Scenario::new(readable).opv(PLAN);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains(
            "prod/k8s: would write: web/LOG_LEVEL (E2E__WEB__LOG_LEVEL → ConfigMap, env)\n"
        ),
        "{}",
        shown(&out)
    );
}

#[test]
fn plan_names_the_volume_a_deploy_would_add() {
    let out = Scenario::new(readable).opv(PLAN);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains(
            "prod/k8s: would deploy: volume opv-files-web, read-only at /run/secrets/web \
             (3 files)\n"
        ),
        "{}",
        shown(&out)
    );
}

#[test]
fn plan_writes_nothing() {
    let s = Scenario::new(readable);
    s.opv(PLAN);
    assert!(
        !s.calls().contains(" apply ") && !s.calls().contains(" replace "),
        "{}",
        s.calls()
    );
}

#[test]
fn plan_warns_about_an_unreadable_workload() {
    let out = Scenario::new(unreadable).opv(PLAN);
    assert!(
        shown(&out).contains(
            "deployment e2e-app sets no fsGroup and runs as 10001: the mounted files (0440, \
             root-owned) would be unreadable"
        ),
        "{}",
        shown(&out)
    );
}

// --- sync --deploy, then status and plan -------------------------------------------------------

#[test]
fn sync_deploy_of_files_and_configmaps_succeeds() {
    let out = Scenario::new(readable).opv(SYNC);
    assert_eq!(out.status.code(), Some(0), "{}", shown(&out));
}

#[test]
fn sync_deploy_mounts_the_volume_read_only_in_the_target_container() {
    let s = Scenario::new(readable);
    s.opv(SYNC);
    assert_eq!(
        s.deployment()["spec"]["template"]["spec"]["containers"][0]["volumeMounts"],
        json!([{"name": "opv-files-web", "mountPath": "/run/secrets/web", "readOnly": true}])
    );
}

#[test]
fn sync_deploy_gives_the_sidecar_no_mount() {
    let s = Scenario::new(readable);
    s.opv(SYNC);
    assert_eq!(
        s.deployment()["spec"]["template"]["spec"]["containers"][1].get("volumeMounts"),
        None
    );
}

#[test]
fn sync_deploy_leaves_no_file_key_as_an_env_entry() {
    let s = Scenario::new(readable);
    s.opv(SYNC);
    let env = s.deployment()["spec"]["template"]["spec"]["containers"][0]["env"].to_string();
    assert!(!env.contains("E2E__WEB__TLS_"), "{env}");
}

#[test]
fn sync_deploy_binds_the_config_key_by_configmap_key_ref() {
    let s = Scenario::new(readable);
    s.opv(SYNC);
    let env = s.deployment()["spec"]["template"]["spec"]["containers"][0]["env"].clone();
    let log_level = env
        .as_array()
        .into_iter()
        .flatten()
        .find(|e| e["name"] == "E2E__WEB__LOG_LEVEL")
        .cloned()
        .unwrap_or_default();
    assert!(
        log_level
            .pointer("/valueFrom/configMapKeyRef/name")
            .is_some(),
        "{log_level}"
    );
}

#[test]
fn sync_deploy_puts_no_value_in_the_replaced_deployment() {
    let s = Scenario::new(readable);
    s.opv(SYNC);
    let deployment = s.deployment().to_string();
    assert!(!deployment.contains(MARK), "{deployment}");
}

#[test]
fn status_after_deploy_chains_a_file_key_to_its_file() {
    let s = Scenario::new(readable);
    s.opv(SYNC);
    let out = s.opv(STATUS);
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        text.lines().any(|l| l.starts_with(
            "prod/k8s: chain: web/TLS_PRIVATE_KEY (E2E__WEB__TLS_PRIVATE_KEY) → secret \
             opv-e2e--web--tls-private-key-"
        ) && l.ends_with(" → file /run/secrets/web/tls/private-key")),
        "{text}"
    );
}

#[test]
fn status_after_deploy_chains_a_config_key_through_its_configmap() {
    let s = Scenario::new(readable);
    s.opv(SYNC);
    let out = s.opv(STATUS);
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        text.lines().any(|l| l.starts_with(
            "prod/k8s: chain: web/LOG_LEVEL (E2E__WEB__LOG_LEVEL) → configmap \
             opv-e2e--web--log-level-"
        ) && l.ends_with(" → env E2E__WEB__LOG_LEVEL")),
        "{text}"
    );
}

#[test]
fn plan_after_deploy_has_nothing_to_write() {
    let s = Scenario::new(readable);
    s.opv(SYNC);
    let out = s.opv(PLAN);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains(" · 0 to write · "),
        "{}",
        shown(&out)
    );
}

#[test]
fn plan_json_row_of_a_file_key_is_delivered_as_a_file() {
    let doc = Scenario::new(readable).json(PLAN);
    let row = doc["rows"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|r| r["key"] == "TLS_PRIVATE_KEY")
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        (&row["delivered_as"], &row["form"], &row["path"]),
        (
            &json!("file"),
            &json!("verbatim"),
            &json!("tls/private-key")
        ),
        "{doc}"
    );
}

#[test]
fn plan_json_row_of_a_config_key_is_via_configmap() {
    let doc = Scenario::new(readable).json(PLAN);
    let row = doc["rows"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|r| r["key"] == "LOG_LEVEL")
        .cloned()
        .unwrap_or_default();
    assert_eq!(row["via"], "ConfigMap", "{doc}");
}

// --- refusals ---------------------------------------------------------------------------------

#[test]
fn sync_to_an_unreadable_workload_is_mount_unreadable() {
    let doc = Scenario::new(unreadable).json(SYNC);
    assert_eq!(doc["error"]["code"], "mount_unreadable", "{doc}");
}

#[test]
fn sync_to_an_unreadable_workload_writes_nothing() {
    let s = Scenario::new(unreadable);
    s.opv(SYNC);
    assert!(
        !s.calls().contains(" apply ") && !s.calls().contains(" replace "),
        "{}",
        s.calls()
    );
}

#[test]
fn sync_to_a_root_workload_succeeds() {
    let out = Scenario::new(root).opv(SYNC);
    assert_eq!(out.status.code(), Some(0), "{}", shown(&out));
}

#[test]
fn sync_to_a_root_workload_warns() {
    let out = Scenario::new(root).opv(SYNC);
    assert!(
        shown(&out).contains(
            "deployment e2e-app runs as root: every mounted file is readable by any process \
             in the container; run as a non-root user with fsGroup"
        ),
        "{}",
        shown(&out)
    );
}

#[test]
fn sync_over_a_foreign_mount_is_policy_refused() {
    let doc = Scenario::new(foreign_mount).json(SYNC);
    assert_eq!(doc["error"]["code"], "policy_refused", "{doc}");
}

#[test]
fn sync_over_a_foreign_mount_writes_nothing() {
    let s = Scenario::new(foreign_mount);
    s.opv(SYNC);
    assert!(!s.calls().contains(" apply "), "{}", s.calls());
}

#[test]
fn a_volume_the_api_server_refuses_is_update_refused() {
    let doc = Scenario::new(volume_left_behind).json(SYNC);
    assert_eq!(doc["error"]["code"], "update_refused", "{doc}");
}

#[test]
fn a_volume_the_api_server_refuses_is_a_validation_refusal() {
    let doc = Scenario::new(volume_left_behind).json(SYNC);
    assert_eq!(doc["error"]["subject"]["why"]["why"], "validation", "{doc}");
}

#[test]
fn a_missing_source_leaves_the_rollout_in_progress() {
    let doc = Scenario::new(source_missing).json(SYNC_SHORT);
    assert_eq!(
        doc["error"]["subject"]["why"]["why"], "in_progress",
        "{doc}"
    );
}

#[test]
fn a_missing_source_is_read_from_the_waiting_pods() {
    let s = Scenario::new(source_missing);
    s.opv(SYNC_SHORT);
    assert!(s.calls().contains(" get pods "), "{}", s.calls());
}

#[test]
fn a_missing_configmap_right_is_permission_denied() {
    let doc = Scenario::new(configmap_right_missing).json(SYNC);
    assert_eq!(doc["error"]["code"], "permission_denied", "{doc}");
}

#[test]
fn a_missing_configmap_right_writes_nothing() {
    let s = Scenario::new(configmap_right_missing);
    s.opv(SYNC);
    assert!(!s.calls().contains(" apply "), "{}", s.calls());
}

// --- the canary scan --------------------------------------------------------------------------

/// A world edit and the commands run on it, in order.
type Run = (fn(&mut Value), Vec<Vec<&'static str>>);

/// Every world and the commands it runs, as the scenarios above run them.
fn every_run() -> Vec<Run> {
    vec![
        (
            readable,
            vec![SYNC.to_vec(), STATUS.to_vec(), PLAN.to_vec()],
        ),
        (unreadable, vec![PLAN.to_vec(), SYNC.to_vec()]),
        (root, vec![SYNC.to_vec()]),
        (foreign_mount, vec![SYNC.to_vec()]),
        (volume_left_behind, vec![SYNC.to_vec()]),
        (source_missing, vec![SYNC_SHORT.to_vec()]),
        (configmap_right_missing, vec![SYNC.to_vec()]),
    ]
}

#[test]
fn every_scenario_world_holds_its_values_as_s7marker_markers() {
    let s = Scenario::new(readable);
    let world = std::fs::read_to_string(s.world().join("world.json")).expect("world");
    assert!(world.contains(&format!(
        "{MARK}VALUE-test-marker-e2e-prod-web-tls-private-key"
    )));
}

#[test]
fn no_scenario_prints_a_value() {
    let mut printed = String::new();
    for (world, steps) in every_run() {
        let s = Scenario::new(world);
        for args in &steps {
            printed.push_str(&shown(&s.opv(args)));
            let mut json = args.clone();
            json.push("--json");
            printed.push_str(&shown(&s.opv(&json)));
        }
    }
    assert!(!printed.contains(MARK), "{printed}");
}

#[test]
fn no_scenario_passes_a_value_in_argv() {
    let mut argv = String::new();
    for (world, steps) in every_run() {
        let s = Scenario::new(world);
        for args in &steps {
            s.opv(args);
        }
        argv.push_str(&s.calls());
    }
    assert!(!argv.contains(MARK), "{argv}");
}
