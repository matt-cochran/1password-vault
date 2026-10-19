//! `opv changed` and `status --fail-on-drift` end to end (delivery-transports §2.2, §11.1 C4):
//! the real `opv` binary against `opv-sim`, on the test application in `tests/e2e/app`.
//!
//! Each scenario copies the app's world and configuration into a scratch directory and runs
//! opv there with a scratch HOME and `OPV_NO_SKILL=1`. Every value in the scenario's world is
//! an `S7MARKER` marker, so one substring check finds any value printed anywhere. A test
//! asserts once, on a public outcome: the exit code, the `--json` document, the calls opv
//! made, or the committed snapshot (`tests/e2e/snapshots/changed/<name>.snap`, rewritten with
//! `UPDATE_SNAPSHOTS=1`).
//!
//! What the simulator reaches, and what it does not:
//! - `no_record`: the app's targets record no delivery item, so `changed` reads only the
//!   `op item list --vault` replies (recording s05) and never `op read`. Reached.
//! - an `op` failure keeping its own exit: a signed-out `op item list` (recording 07). Reached.
//! - `unchanged` and `changed`: both read the delivery item's `source versions` field with
//!   `op read op://<state vault>/<delivery item>/source versions`. No `op read` reply is
//!   recorded under `tests/fixtures/op/` (success or failure), so opv-sim answers it as
//!   unsupported (exit 87) and these states are not reached here; they stay covered by
//!   `src/app/changed_tests.rs`. Recording one `op read` of a non-secret field would make
//!   them reachable.
//! - `status --fail-on-drift` exiting 8 (`target_drift`): not reachable. Drift is a pinned
//!   binding whose version differs from the store's current one. The only pinned target
//!   opv-sim models is plain Kubernetes, whose store takes the current version from the
//!   Deployment's own binding (`src/adapters/kubernetes/store.rs` `read`), so the two never
//!   differ; Azure Key Vault and External Secrets, where they can, are not simulated. The
//!   flag's other side is reached: a target with nothing pinned does not fail.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;

const APP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/e2e/app");
const SNAPSHOTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/e2e/snapshots/changed");
/// The project's account: it holds every vault of the app.
const PROJECT: &str = "AE2EDEVACCOUNT000000000001";
/// The marker every value of a scenario's world carries.
const MARK: &str = "S7MARKER";

/// A scratch HOME, project and world, and the simulator installed under every tool name.
struct Scenario {
    root: tempfile::TempDir,
}

impl Scenario {
    /// The app's world with every value an `S7MARKER` marker, and `faults` as its faults.
    fn new(faults: &str) -> Self {
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
        std::fs::write(s.world().join("world.json"), world.to_string()).expect("world");
        std::fs::write(s.world().join("faults.toml"), faults).expect("faults");
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
            .env("OPV_TEST_SUID_DUMPABLE", "0")
            .stdin(Stdio::null())
            .output()
            .expect("run opv")
    }

    /// The calls the simulator answered so far, one line each.
    fn calls(&self) -> Vec<String> {
        std::fs::read_to_string(self.world().join("calls.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// What a snapshot must not depend on: the scenario's path.
    fn normalize(&self, s: &str) -> String {
        // macOS resolves the temp directory through a symlink (/var → /private/var).
        let root = self.root.path().display().to_string();
        let real = std::fs::canonicalize(self.root.path())
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| root.clone());
        s.replace(&real, "<SCENARIO>")
            .replace(&root, "<SCENARIO>")
            .replace(" (op in WSL does not see the Windows app's accounts)", "")
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

/// `faults.toml` with one fault.
fn fault(program: &str, call: &str, kind: &str) -> String {
    format!("[[fault]]\nprogram = \"{program}\"\ncall = \"{call}\"\nkind = \"{kind}\"\n")
}

/// `op item list` answered as signed out (recording 07).
fn signed_out() -> String {
    fault("op", "item list", "signed_out")
}

fn document(out: &Output) -> Value {
    serde_json::Deserializer::from_slice(&out.stdout)
        .into_iter::<Value>()
        .next()
        .and_then(Result::ok)
        .unwrap_or_default()
}

/// Everything a run printed.
fn shown(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// The command's text run and `--json` run, each on a fresh world, as one snapshot.
fn record(faults: &str, args: &[&str]) -> String {
    let mut snap = format!("# opv {}\n", args.join(" "));
    let mut json = args.to_vec();
    json.push("--json");
    for (mode, args) in [("text", args.to_vec()), ("json", json)] {
        let s = Scenario::new(faults);
        let out = s.opv(&args);
        snap.push_str(&format!(
            "\n## {mode} exit: {}\n## {mode} stdout\n{}\n## {mode} stderr\n{}",
            out.status.code().map_or("killed".into(), |c| c.to_string()),
            s.normalize(&String::from_utf8_lossy(&out.stdout)),
            s.normalize(&String::from_utf8_lossy(&out.stderr)),
        ));
    }
    snap
}

/// The recorded runs equal the committed snapshot `name` (rewritten under
/// `UPDATE_SNAPSHOTS=1`).
fn snapshot_test(name: &str, faults: &str, args: &[&str]) {
    let got = record(faults, args);
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

#[test]
fn every_scenario_world_holds_its_values_as_s7marker_markers() {
    let s = Scenario::new("");
    let world = std::fs::read_to_string(s.world().join("world.json")).expect("world");
    assert!(world.contains(&format!("{MARK}VALUE-test-marker-e2e-")));
}

// ---------------------------------------------------------------------------------------
// no_record: the app's targets record no delivery item.
// ---------------------------------------------------------------------------------------

#[test]
fn changed_with_no_delivery_item_matches_its_snapshot() {
    snapshot_test("no_record", "", &["changed", "prod"]);
}

#[test]
fn changed_with_no_delivery_item_exits_10() {
    let out = Scenario::new("").opv(&["changed", "prod"]);
    assert_eq!(out.status.code(), Some(10), "{}", shown(&out));
}

#[test]
fn changed_with_no_delivery_item_is_an_ok_result() {
    let out = Scenario::new("").opv(&["changed", "prod", "--json"]);
    assert_eq!(document(&out)["ok"], true, "{}", shown(&out));
}

#[test]
fn changed_with_no_delivery_item_reports_every_placement_as_no_record() {
    let out = Scenario::new("").opv(&["changed", "prod", "--json"]);
    let states: Vec<Value> = document(&out)["placements"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|p| p["state"].clone())
        .collect();
    assert_eq!(states, vec![Value::from("no_record"); 3], "{}", shown(&out));
}

#[test]
fn changed_with_no_delivery_item_steps_to_apply() {
    let out = Scenario::new("").opv(&["changed", "prod", "--json"]);
    assert_eq!(
        document(&out)["next"]["command"],
        "opv apply",
        "{}",
        shown(&out)
    );
}

#[test]
fn changed_lists_each_source_vault_once_and_reads_nothing_else() {
    let s = Scenario::new("");
    s.opv(&["changed", "prod"]);
    let want: Vec<String> = ["vE2ESHAREDPROD0000000000001", "vE2EWEBPROD000000000000001"]
        .iter()
        .map(|v| format!("op item list --vault {v} --format json --account {PROJECT}"))
        .collect();
    assert_eq!(s.calls(), want);
}

#[test]
fn changed_with_no_delivery_item_prints_no_value() {
    let out = Scenario::new("").opv(&["changed", "prod"]);
    assert!(!shown(&out).contains(MARK), "{}", shown(&out));
}

#[test]
fn changed_json_with_no_delivery_item_prints_no_value() {
    let out = Scenario::new("").opv(&["changed", "prod", "--json"]);
    assert!(!shown(&out).contains(MARK), "{}", shown(&out));
}

// ---------------------------------------------------------------------------------------
// unreadable: an `op` failure keeps its own exit, never 0 or 10.
// ---------------------------------------------------------------------------------------

#[test]
fn changed_signed_out_matches_its_snapshot() {
    snapshot_test("signed_out", &signed_out(), &["changed", "prod"]);
}

#[test]
fn changed_signed_out_keeps_the_sign_in_exit() {
    let out = Scenario::new(&signed_out()).opv(&["changed", "prod"]);
    assert_eq!(out.status.code(), Some(7), "{}", shown(&out));
}

#[test]
fn changed_signed_out_is_op_not_signed_in() {
    let out = Scenario::new(&signed_out()).opv(&["changed", "prod", "--json"]);
    assert_eq!(
        document(&out)["error"]["code"],
        "op_not_signed_in",
        "{}",
        shown(&out)
    );
}

#[test]
fn changed_signed_out_prints_no_value() {
    let out = Scenario::new(&signed_out()).opv(&["changed", "prod"]);
    assert!(!shown(&out).contains(MARK), "{}", shown(&out));
}

#[test]
fn changed_json_signed_out_prints_no_value() {
    let out = Scenario::new(&signed_out()).opv(&["changed", "prod", "--json"]);
    assert!(!shown(&out).contains(MARK), "{}", shown(&out));
}

// ---------------------------------------------------------------------------------------
// status --fail-on-drift: a target with nothing pinned never fails on drift.
// ---------------------------------------------------------------------------------------

#[test]
fn status_fail_on_drift_on_a_target_with_nothing_pinned_exits_0() {
    let out = Scenario::new("").opv(&["status", "prod", "--target", "fly", "--fail-on-drift"]);
    assert_eq!(out.status.code(), Some(0), "{}", shown(&out));
}

#[test]
fn status_fail_on_drift_prints_no_value() {
    let out = Scenario::new("").opv(&["status", "prod", "--target", "fly", "--fail-on-drift"]);
    assert!(!shown(&out).contains(MARK), "{}", shown(&out));
}
