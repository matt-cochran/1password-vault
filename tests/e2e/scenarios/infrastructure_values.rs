//! T15 `infrastructure_values` (#206, `docs/design/deliver-only.md`): the real `opv` binary
//! against `opv-sim`, a value Terraform produced piped to `opv sync --supply-stdin`, delivered
//! to the Fly target and recorded in the placement's delivery item, never in 1Password.
//!
//! Each scenario copies the e2e app's world into a scratch directory with its own
//! configuration: prod delivers product `web` to the Fly target only (an infrastructure key
//! needs a staged target), `web/TF_DATABASE_URL` is an infrastructure key, and the placement's
//! delivery item is recorded in the Fly state vault. Every supplied value carries the
//! `S7MARKER` marker. One assertion per test.
//!
//! Reached: the supply, verify, a scheduled sync that holds the value, drift on the target
//! (`status --fail-on-drift`), the repair by re-supply, the adoption refusal (`Unproven`)
//! and its rotation, and the refusal of an empty supply. Not reached here: the stream and
//! admission refusals (core unit tests) and the concurrency cases (`src/app/supply_tests.rs`).

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};

const APP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/e2e/app");
const PROJECT: &str = "AE2EDEVACCOUNT000000000001";
const MARK: &str = "S7MARKER";
const STATE_VAULT: &str = "vE2ESTATEFLY00000000000001";
const DELIVERY_ITEM: &str = "iE2EDELIVERYWEBFLY00000001";
const NAME: &str = "E2E__WEB__TF_DATABASE_URL";
const DB: &str = "postgresql://S7MARKER-e2e-db-0001@db.example/app";
const DB2: &str = "postgresql://S7MARKER-e2e-db-0002@db.example/app";

const CONFIG: &str = r#"
[environments.prod]
title = "Production"
order = 1
boundaries.web = {}

[environments.prod.targets.fly]
fly.app = "e2e-app-prod"
fly.secret_name = "E2E__{PRODUCT}__{KEY}"

[products.web]
boundary = "web"

[products.web.keys.API_KEY]
kind = "secret"
environments = ["prod"]

[products.web.keys.TF_DATABASE_URL]
kind = "secret"
source = "infrastructure"
environments = ["prod"]
rules = { regex = "postgres(ql)?://.+" }
"#;

struct Scenario {
    root: tempfile::TempDir,
}

impl Scenario {
    fn new() -> Self {
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
        world["op"]["items"]
            .as_array_mut()
            .expect("items")
            .push(json!({
                "id": DELIVERY_ITEM,
                "title": "opv · delivery · web · fly",
                "version": 1,
                "vault": {"id": STATE_VAULT, "name": "e2e-app · fly · state"},
                "category": "SECURE_NOTE",
                "fields": [{"id": "notesPlain", "type": "STRING", "purpose": "NOTES",
                            "label": "notesPlain", "value": ""}]
            }));
        std::fs::write(s.world().join("world.json"), world.to_string()).expect("world");
        std::fs::write(s.world().join("faults.toml"), "").expect("faults");
        std::fs::write(s.project().join("secrets.toml"), CONFIG).expect("config");
        std::fs::write(
            s.project().join("secrets.bindings.toml"),
            format!(
                "environments.prod.boundaries.web.item_id = \"iE2EWEBPROD000000000000001\"\n\
                 environments.prod.boundaries.web.vault_id = \"vE2EWEBPROD000000000000001\"\n\
                 environments.prod.targets.fly.state_vault_id = \"{STATE_VAULT}\"\n\
                 environments.prod.targets.fly.delivery_items.web = \"{DELIVERY_ITEM}\"\n"
            ),
        )
        .expect("bindings");
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

    /// `opv <args>` with `stdin` on standard input (none: an empty, closed one).
    fn opv_with(&self, args: &[&str], stdin: &str) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_opv"))
            .args(args)
            .current_dir(self.project())
            .env_clear()
            .env("OP_BIOMETRIC_UNLOCK_ENABLED", "false")
            .env("PATH", format!("{}:/usr/bin:/bin", self.bin().display()))
            .env("HOME", self.root.path().join("home"))
            .env("OPV_NO_SKILL", "1")
            .env("OPV_SIM_WORLD", self.world())
            .env("OPV_TEST_SUID_DUMPABLE", "0")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run opv");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(stdin.as_bytes())
            .expect("write stdin");
        child.wait_with_output().expect("opv output")
    }

    fn opv(&self, args: &[&str]) -> Output {
        self.opv_with(args, "")
    }

    /// `opv sync prod --supply-stdin` of `value` at `serial`, with `extra` flags.
    fn supply(&self, value: &str, serial: u64, extra: &[&str]) -> Output {
        let doc = json!({"schema": "opv.supply/1", "env": "prod", "serial": serial,
                         "values": {"web/TF_DATABASE_URL": value}});
        let mut args = vec!["sync", "prod", "--supply-stdin"];
        args.extend_from_slice(extra);
        self.opv_with(&args, &format!("{doc}\n"))
    }

    /// Someone sets the name on Fly directly, outside opv: a new digest.
    fn set_on_fly(&self, digest: &str) {
        let path = self.world().join("world.json");
        let mut world: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("world")).expect("world");
        let secrets = world["fly"]["apps"]["e2e-app-prod"]["secrets"]
            .as_array_mut()
            .expect("secrets");
        secrets.retain(|s| s["name"] != NAME);
        secrets.push(json!({"name": NAME, "digest": digest, "status": "Deployed"}));
        std::fs::write(&path, world.to_string()).expect("world");
    }
}

fn document(out: &Output) -> Value {
    serde_json::Deserializer::from_slice(&out.stdout)
        .into_iter::<Value>()
        .next()
        .and_then(Result::ok)
        .unwrap_or_default()
}

fn shown(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// A world where the value was supplied once at serial 10.
fn supplied() -> Scenario {
    let s = Scenario::new();
    let out = s.supply(DB, 10, &[]);
    assert_eq!(out.status.code(), Some(0), "{}", shown(&out));
    s
}

fn verify_state(s: &Scenario) -> Value {
    let out = s.opv(&["delivery", "verify", "prod", "--json"]);
    document(&out)["placements"][0]["state"].clone()
}

#[test]
fn infrastructure_values_a_supply_exits_0() {
    let s = Scenario::new();
    let out = s.supply(DB, 10, &[]);
    assert_eq!(out.status.code(), Some(0), "{}", shown(&out));
}

#[test]
fn infrastructure_values_a_supply_shows_no_value() {
    let s = Scenario::new();
    let out = s.supply(DB, 10, &["--json"]);
    assert!(!shown(&out).contains(MARK), "{}", shown(&out));
}

#[test]
fn infrastructure_values_a_supply_puts_no_value_in_any_call() {
    let s = supplied();
    let calls = std::fs::read_to_string(s.world().join("calls.log")).unwrap_or_default();
    assert!(!calls.contains("S7MARKER-e2e-db"), "{calls}");
}

#[test]
fn infrastructure_values_a_supply_is_verified() {
    let s = supplied();
    assert_eq!(verify_state(&s), "verified");
}

#[test]
fn infrastructure_values_a_scheduled_sync_holds_the_value() {
    let s = supplied();
    let out = s.opv(&["sync", "prod"]);
    assert_eq!(out.status.code(), Some(0), "{}", shown(&out));
}

#[test]
fn infrastructure_values_plan_shows_the_key_supplied_at_sync() {
    let s = supplied();
    let out = s.opv(&["plan", "prod", "--json"]);
    let row = document(&out)["rows"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|r| r["key"] == "TF_DATABASE_URL")
        .cloned()
        .unwrap_or_default();
    assert_eq!(row["target_state"], "as_supplied", "{}", shown(&out));
}

#[test]
fn infrastructure_values_drift_fails_status() {
    let s = supplied();
    s.set_on_fly("00000000000dead1");
    let out = s.opv(&["status", "prod", "--fail-on-drift"]);
    assert_eq!(out.status.code(), Some(8), "{}", shown(&out));
}

#[test]
fn infrastructure_values_a_re_supply_repairs_drift() {
    let s = supplied();
    s.set_on_fly("00000000000dead1");
    let out = s.supply(DB, 10, &[]);
    assert_eq!(out.status.code(), Some(0), "{}", shown(&out));
}

#[test]
fn infrastructure_values_a_new_value_is_verified() {
    let s = supplied();
    let out = s.supply(DB2, 11, &[]);
    assert_eq!(out.status.code(), Some(0), "{}", shown(&out));
}

#[test]
fn infrastructure_values_adoption_is_unproven() {
    let s = Scenario::new();
    s.set_on_fly("00000000000beef1");
    let out = s.supply(DB, 10, &["--json"]);
    assert_eq!(
        document(&out)["error"]["subject"]["guard"]["reason"]["reason"],
        "unproven",
        "{}",
        shown(&out)
    );
}

#[test]
fn infrastructure_values_adoption_rotates_once() {
    let s = Scenario::new();
    s.set_on_fly("00000000000beef1");
    let out = s.supply(DB, 10, &["--rotate", "web/TF_DATABASE_URL"]);
    assert_eq!(out.status.code(), Some(0), "{}", shown(&out));
}

#[test]
fn infrastructure_values_an_empty_supply_is_input_invalid() {
    let s = Scenario::new();
    let out = s.opv(&["sync", "prod", "--supply-stdin", "--json"]);
    assert_eq!(
        document(&out)["error"]["code"],
        "input_invalid",
        "{}",
        shown(&out)
    );
}
