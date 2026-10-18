//! The live-run audit's scenarios (report 09) as simulator scenarios (design §13.5).
//!
//! The audit ran `opv` 0.10.0 against hand-written stubs. Each scenario here runs the real
//! binary against `opv-sim` on the test application (`tests/e2e/app`): a scratch HOME, no
//! real credential, `OPV_NO_SKILL=1`, and only recorded tool replies (`tests/fixtures/*/
//! failures`). The audit's names map onto the app: environment `prod` (with `confirm_env`) and
//! `dev`, products `web` and `shared`, targets `fly`, `k8s` and `gh`, remote profile `builder`.
//!
//! Each test is one audit scenario (`live_09_<scenario>_…`) with one assertion: what the
//! catalog (docs/design/error-catalog.md §4) says should happen. A test opv still fails is
//! `#[ignore]`d with the remaining defect as its reason.
//!
//! Not here:
//! - no recording for the reply: 8 and 93 (a refused `op vault create`), 35 (a Fly
//!   `secrets list` that lags behind a write), 43 (`op run`), 75 (a refused `op item get`);
//! - covered by the fault matrix (`tests/e2e/matrix.rs`) with nothing to add: 15, 16, 19, 20,
//!   21, 59, 61, 68, 70, 71b, and 1b and 92 (the same runs as 1 and 72);
//! - wording only, outside the asserted surfaces: 4, 4b, 60, 62, 69, 90, 93b, H1–H74, and the
//!   MCP calls whose reply is the transport's own error (missing or unknown arguments, an
//!   unknown tool).

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};

const APP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/e2e/app");
const DEV_ACCOUNT: &str = "AE2EDEVACCOUNT000000000001";
const OPS_ACCOUNT: &str = "AE2EOPSACCOUNT000000000002";
/// An account ID no simulated `op` knows (a marker, not a real ID).
const UNKNOWN_ACCOUNT: &str = "AE2EUNKNOWNACCOUNT00000099";

/// A scratch HOME, a project holding the app's `secrets.toml`, a directory outside it, the
/// world and the simulator installed under every tool name.
struct Scenario {
    root: tempfile::TempDir,
}

impl Scenario {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let s = Self { root };
        for dir in ["world", "home", "project", "elsewhere"] {
            std::fs::create_dir_all(s.root.path().join(dir)).unwrap();
        }
        std::fs::copy(
            Path::new(APP).join("world.json"),
            s.world().join("world.json"),
        )
        .unwrap();
        std::fs::write(s.world().join("faults.toml"), "").unwrap();
        std::fs::copy(Path::new(APP).join("secrets.toml"), s.config()).unwrap();
        std::fs::copy(
            Path::new(APP).join("secrets.bindings.toml"),
            s.config().with_file_name("secrets.bindings.toml"),
        )
        .unwrap();
        s
    }

    /// The world's `faults.toml`.
    fn faults(self, faults: &str) -> Self {
        std::fs::write(self.world().join("faults.toml"), faults).unwrap();
        self
    }

    /// The project's `.opv`, selecting `account`.
    fn account(self, account: &str) -> Self {
        std::fs::write(
            self.project().join(".opv"),
            format!("account = \"{account}\"\n"),
        )
        .unwrap();
        self
    }

    /// The project's `secrets.toml`, edited.
    /// The configuration edited as one text with its ids filled in; the ids of the edited
    /// text go back to `secrets.bindings.toml` (D-G).
    fn edit_config(self, edit: impl FnOnce(String) -> String) -> Self {
        let text = opv::config::read_merged(&self.config()).unwrap();
        opv::config::bindings::write_split(&self.config(), &edit(text)).unwrap();
        self
    }

    /// No configuration anywhere.
    fn without_config(self) -> Self {
        std::fs::remove_file(self.config()).unwrap();
        self
    }

    /// The world, edited.
    fn edit_world(self, edit: impl FnOnce(&mut Value)) -> Self {
        let path = self.world().join("world.json");
        let mut world: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        edit(&mut world);
        std::fs::write(&path, world.to_string()).unwrap();
        self
    }

    fn world(&self) -> PathBuf {
        self.root.path().join("world")
    }

    fn project(&self) -> PathBuf {
        self.root.path().join("project")
    }

    fn config(&self) -> PathBuf {
        self.project().join("secrets.toml")
    }

    fn config_arg(&self) -> String {
        self.config().display().to_string()
    }

    fn bin(&self) -> PathBuf {
        self.root.path().join("bin")
    }

    fn command(&self, cwd: &Path, env: &[(&str, &str)]) -> Command {
        let installed = Command::new(env!("CARGO_BIN_EXE_opv-sim"))
            .arg("install")
            .arg(self.bin())
            .env("OPV_SIM_WORLD", self.world())
            .output()
            .unwrap();
        assert!(installed.status.success(), "{installed:?}");
        let mut c = Command::new(env!("CARGO_BIN_EXE_opv"));
        c.current_dir(cwd)
            .env_clear()
            .env("PATH", format!("{}:/usr/bin:/bin", self.bin().display()))
            .env("HOME", self.root.path().join("home"))
            .env("OPV_NO_SKILL", "1")
            .env("OPV_SIM_WORLD", self.world())
            .stdin(Stdio::null());
        for (k, v) in env {
            c.env(k, v);
        }
        c
    }

    /// `opv <args>` in the project, with no terminal.
    fn opv(&self, args: &[&str]) -> Run {
        self.opv_env(args, &[])
    }

    fn opv_env(&self, args: &[&str], env: &[(&str, &str)]) -> Run {
        Run(self
            .command(&self.project(), env)
            .args(args)
            .output()
            .unwrap())
    }

    /// `opv --config <secrets.toml> <args>` from a directory that does not discover it.
    fn opv_config(&self, args: &[&str]) -> Run {
        Run(self
            .command(&self.root.path().join("elsewhere"), &[])
            .arg("--config")
            .arg(self.config())
            .args(args)
            .output()
            .unwrap())
    }

    /// `opv <args>` from a directory with no configuration above it.
    fn opv_elsewhere(&self, args: &[&str]) -> Run {
        Run(self
            .command(&self.root.path().join("elsewhere"), &[])
            .args(args)
            .output()
            .unwrap())
    }

    /// One MCP `tools/call` on `opv mcp serve --project <project>`: the tool's document.
    fn mcp(&self, tool: &str, arguments: Value) -> Value {
        let mut child = self
            .command(&self.project(), &[])
            .args(["mcp", "serve", "--project"])
            .arg(self.project())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let mut reply = |stdin: &mut std::process::ChildStdin, message: Value, id: Option<u64>| {
            writeln!(stdin, "{message}").unwrap();
            stdin.flush().unwrap();
            let id = id?;
            lines
                .by_ref()
                .map_while(Result::ok)
                .filter_map(|l| serde_json::from_str::<Value>(&l).ok())
                .find(|m| m["id"] == id)
        };
        reply(
            &mut stdin,
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-11-25", "capabilities": {},
                "clientInfo": {"name": "opv-live-audit", "version": "1"}}}),
            Some(1),
        );
        reply(
            &mut stdin,
            json!({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}),
            None,
        );
        let result = reply(
            &mut stdin,
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                   "params": {"name": tool, "arguments": arguments}}),
            Some(2),
        );
        let _ = child.kill();
        let _ = child.wait();
        let text = result
            .as_ref()
            .and_then(|r| r.pointer("/result/content/0/text"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        serde_json::from_str(text).unwrap_or_else(|_| json!({ "raw": result }))
    }
}

/// One finished run of `opv`.
struct Run(Output);

impl Run {
    fn stdout(&self) -> String {
        String::from_utf8_lossy(&self.0.stdout).into_owned()
    }

    fn stderr(&self) -> String {
        String::from_utf8_lossy(&self.0.stderr).into_owned()
    }

    /// Everything printed, for assertion messages.
    fn shown(&self) -> String {
        format!("stdout:\n{}\nstderr:\n{}", self.stdout(), self.stderr())
    }

    fn exit(&self) -> Option<i32> {
        self.0.status.code()
    }

    /// The first JSON document on stdout.
    fn doc(&self) -> Value {
        serde_json::Deserializer::from_slice(&self.0.stdout)
            .into_iter::<Value>()
            .next()
            .and_then(Result::ok)
            .unwrap_or_default()
    }

    fn code(&self) -> String {
        self.doc()["error"]["code"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    /// The step: the document's `error.next` or `next`, else the text's last `Next:` line.
    fn next(&self) -> Option<String> {
        let doc = self.doc();
        if let Some(n) = doc
            .pointer("/error/next/command")
            .or_else(|| doc.pointer("/next/command"))
            .and_then(Value::as_str)
        {
            return Some(n.to_string());
        }
        format!("{}\n{}", self.stdout(), self.stderr())
            .lines()
            .filter_map(|l| l.strip_prefix("Next: "))
            .next_back()
            .map(str::to_string)
    }

    /// The first marker value of the world that this run printed.
    fn canary(&self) -> Option<String> {
        let all = format!("{}{}", self.stdout(), self.stderr());
        canaries().into_iter().find(|c| all.contains(c.as_str()))
    }
}

/// Every marker value of the world (`test-marker-e2e-…`, `…_e2e_marker_…`).
fn canaries() -> Vec<String> {
    fn walk(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::String(s) if s.contains("test-marker-e2e-") || s.contains("_e2e_marker_") => {
                out.push(s.clone())
            }
            Value::Array(a) => a.iter().for_each(|v| walk(v, out)),
            Value::Object(o) => o.values().for_each(|v| walk(v, out)),
            _ => {}
        }
    }
    let world: Value =
        serde_json::from_str(&std::fs::read_to_string(Path::new(APP).join("world.json")).unwrap())
            .unwrap();
    let mut out = Vec::new();
    walk(&world, &mut out);
    out
}

/// The words of a command line, sorted: two steps with the same flags in another order match.
fn words(line: &str) -> Vec<String> {
    let mut w: Vec<String> = line.split_whitespace().map(str::to_string).collect();
    w.sort();
    w
}

/// `opv <args>` as sorted words, with `--config <path>` when `config` is given.
fn expected(args: &[&str], config: Option<&str>) -> Vec<String> {
    let mut line = format!("opv {}", args.join(" "));
    if let Some(c) = config {
        line.push_str(&format!(" --config {c}"));
    }
    words(&line)
}

/// Whether the step carries `--config <path>`.
fn keeps_config(next: Option<&str>, path: &str) -> bool {
    next.is_some_and(|n| n.contains(&format!("--config {path}")))
}

/// Empty the field `label` of the item `item` in the world.
fn blank(item: &'static str, label: &'static str) -> impl FnOnce(&mut Value) {
    move |w| {
        for i in w["op"]["items"].as_array_mut().unwrap() {
            if i["id"] == item {
                for f in i["fields"].as_array_mut().unwrap() {
                    if f["label"] == label {
                        f["value"] = json!("");
                    }
                }
            }
        }
    }
}

const WEB_PROD_ITEM: &str = "iE2EWEBPROD000000000000001";

fn fault(program: &str, call: &str, kind: &str) -> String {
    format!("[[fault]]\nprogram = \"{program}\"\ncall = \"{call}\"\nkind = \"{kind}\"\n")
}

/// A rule prod's stored `LOG_LEVEL` ("warn") breaks.
fn prod_log_level_invalid(c: String) -> String {
    c.replace(
        "rules = { enum = [\"debug\", \"info\", \"warn\"] }",
        "rules = { enum = [\"debug\", \"info\"] }",
    )
}

// --- no configuration (scenarios 1–7) ---------------------------------------------------------

#[test]
fn live_09_01_status_with_no_configuration_is_config_not_found() {
    let out = Scenario::new()
        .without_config()
        .opv_elsewhere(&["status", "prod", "--json"]);
    assert_eq!(out.code(), "config_not_found", "{}", out.shown());
}

#[test]
fn live_09_03b_status_prod_with_no_configuration_steps_to_the_setup_proposal_of_prod() {
    let out = Scenario::new()
        .without_config()
        .opv_elsewhere(&["status", "prod", "--json"]);
    assert_eq!(
        out.next().as_deref(),
        Some("opv propose setup --from-item prod"),
        "{}",
        out.shown()
    );
}

#[test]
fn live_09_02_status_signed_out_with_no_configuration_fails_on_the_configuration_first() {
    let out = Scenario::new()
        .without_config()
        .faults(&fault("op", "", "signed_out"))
        .opv_elsewhere(&["status", "prod"]);
    assert_eq!(out.exit(), Some(2), "{}", out.shown());
}

#[test]
fn live_09_03_a_misplaced_json_flag_steps_to_the_corrected_command() {
    let out = Scenario::new().opv(&["--json", "status", "prod"]);
    assert_eq!(
        out.next().as_deref(),
        Some("opv status prod --json"),
        "{}",
        out.shown()
    );
}

#[test]
fn live_09_05_plan_with_no_configuration_is_config_not_found() {
    let out = Scenario::new()
        .without_config()
        .opv_elsewhere(&["plan", "prod", "--json"]);
    assert_eq!(out.code(), "config_not_found", "{}", out.shown());
}

#[test]
fn live_09_06_ready_with_no_configuration_exits_2() {
    let out = Scenario::new().without_config().opv_elsewhere(&["ready"]);
    assert_eq!(out.exit(), Some(2), "{}", out.shown());
}

#[test]
fn live_09_07_version_with_no_configuration_exits_0() {
    let out = Scenario::new().without_config().opv_elsewhere(&["version"]);
    assert_eq!(out.exit(), Some(0), "{}", out.shown());
}

#[test]
fn live_09_81_contract_with_no_configuration_is_config_not_found() {
    let out = Scenario::new()
        .without_config()
        .opv_elsewhere(&["contract", "--json"]);
    assert_eq!(out.code(), "config_not_found", "{}", out.shown());
}

// --- person-only steps without a terminal (9, 10, 25–27, 30, 42, 58, 89, 94) -------------------

#[test]
fn live_09_09_login_without_a_terminal_exits_6() {
    let out = Scenario::new().opv(&["login"]);
    assert_eq!(out.exit(), Some(6), "{}", out.shown());
}

#[test]
fn live_09_10_login_prod_without_a_terminal_hands_the_same_command_to_the_person() {
    let out = Scenario::new().opv(&["login", "prod"]);
    assert_eq!(
        out.next().as_deref(),
        Some("opv login prod"),
        "{}",
        out.shown()
    );
}

#[test]
fn live_09_42_run_with_an_undeclared_remote_profile_is_refused_before_the_terminal_gate() {
    let out = Scenario::new().opv(&["run", "prod", "--product", "web", "--remote", "nosuch"]);
    assert_eq!(out.exit(), Some(2), "{}", out.shown());
}

#[test]
fn live_09_58_access_create_without_a_terminal_exits_6() {
    let out = Scenario::new().account(DEV_ACCOUNT).opv(&[
        "access",
        "prod",
        "--create",
        "--github",
        "e2e-org/e2e-app",
    ]);
    assert_eq!(out.exit(), Some(6), "{}", out.shown());
}

#[test]
fn live_09_89_login_under_ci_exits_6() {
    let out = Scenario::new().opv_env(&["login", "prod"], &[("CI", "true")]);
    assert_eq!(out.exit(), Some(6), "{}", out.shown());
}

#[test]
fn live_09_94_login_add_without_a_terminal_exits_6() {
    let out = Scenario::new().opv(&["login", "--add"]);
    assert_eq!(out.exit(), Some(6), "{}", out.shown());
}

// --- steps keep --config (11, 14, 18, 22, 33, 34, 95) -----------------------------------------

#[test]
fn live_09_11_status_with_an_invalid_value_keeps_config_in_its_next() {
    let s = Scenario::new().edit_config(prod_log_level_invalid);
    let out = s.opv_config(&["status", "prod", "--json"]);
    assert!(
        keeps_config(out.next().as_deref(), &s.config_arg()),
        "{}",
        out.shown()
    );
}

#[test]
fn live_09_14_a_product_typo_substitutes_the_product_and_keeps_config() {
    let s = Scenario::new();
    let out = s.opv_config(&["status", "prod", "--product", "wb", "--json"]);
    assert_eq!(
        out.next().as_deref().map(words),
        Some(expected(
            &["status", "prod", "--product", "web", "--json"],
            Some(&s.config_arg())
        )),
        "{}",
        out.shown()
    );
}

#[test]
fn live_09_18_status_with_a_missing_value_keeps_config_in_its_next() {
    let s = Scenario::new().edit_world(blank(WEB_PROD_ITEM, "API_KEY"));
    let out = s.opv_config(&["status", "prod", "--target", "fly", "--json"]);
    assert!(
        keeps_config(out.next().as_deref(), &s.config_arg()),
        "{}",
        out.shown()
    );
}

#[test]
fn live_09_22_plan_with_a_missing_value_keeps_config_in_its_next() {
    let s = Scenario::new().edit_world(blank(WEB_PROD_ITEM, "API_KEY"));
    let out = s.opv_config(&["plan", "prod", "--json"]);
    assert!(
        keeps_config(out.next().as_deref(), &s.config_arg()),
        "{}",
        out.shown()
    );
}

#[test]
fn live_09_33_a_clean_plan_keeps_config_in_its_next() {
    let s = Scenario::new();
    let out = s.opv_config(&["plan", "prod", "--json"]);
    assert!(
        keeps_config(out.next().as_deref(), &s.config_arg()),
        "{}",
        out.shown()
    );
}

/// The plan's Next, followed verbatim from the same directory, finds the configuration.
#[test]
fn live_09_34_following_the_plans_next_finds_the_configuration() {
    let s = Scenario::new();
    let next = s
        .opv_config(&["plan", "prod", "--json"])
        .next()
        .unwrap_or_default();
    let argv: Vec<&str> = next.split_whitespace().skip(1).chain(["--json"]).collect();
    let out = s.opv_elsewhere(&argv);
    assert_ne!(out.code(), "config_not_found", "{next}\n{}", out.shown());
}

#[test]
fn live_09_95_a_confirm_mismatch_keeps_config_in_its_next() {
    let s = Scenario::new();
    let out = s.opv_config(&["sync", "prod", "--confirm", "dev", "--json"]);
    assert!(
        keeps_config(out.next().as_deref(), &s.config_arg()),
        "{}",
        out.shown()
    );
}

// --- checks, plans and syncs (12, 17, 23, 24, 28, 29, 31, 32, 36) -----------------------------

#[test]
fn live_09_12_status_with_a_missing_value_exits_8() {
    let out = Scenario::new()
        .edit_world(blank(WEB_PROD_ITEM, "API_KEY"))
        .opv(&["status", "prod"]);
    assert_eq!(out.exit(), Some(8), "{}", out.shown());
}

#[test]
fn live_09_17_status_for_every_environment_prints_no_value() {
    let out = Scenario::new().account(DEV_ACCOUNT).opv(&["status"]);
    assert_eq!(out.canary(), None, "{}", out.shown());
}

#[test]
fn live_09_23_plan_json_with_a_missing_value_exits_8() {
    let out = Scenario::new()
        .edit_world(blank(WEB_PROD_ITEM, "API_KEY"))
        .opv(&["plan", "prod", "--target", "fly", "--json"]);
    assert_eq!(out.exit(), Some(8), "{}", out.shown());
}

#[test]
fn live_09_24_sync_dry_run_steps_to_plan() {
    let out = Scenario::new().opv(&["sync", "prod", "--dry-run"]);
    assert_eq!(
        out.next().as_deref(),
        Some("opv plan prod"),
        "{}",
        out.shown()
    );
}

#[test]
fn live_09_28_sync_with_a_blocking_key_is_keys_blocking() {
    let out = Scenario::new()
        .edit_world(blank(WEB_PROD_ITEM, "API_KEY"))
        .opv(&["sync", "prod", "--confirm", "prod", "--json"]);
    assert_eq!(out.code(), "keys_blocking", "{}", out.shown());
}

#[test]
fn live_09_29_sync_with_an_outdated_expected_plan_is_stale_plan() {
    let out = Scenario::new().opv(&[
        "sync",
        "prod",
        "--confirm",
        "prod",
        "--expect-plan",
        "deadbeef",
        "--json",
    ]);
    assert_eq!(out.code(), "stale_plan", "{}", out.shown());
}

#[test]
fn live_09_31_status_with_every_value_valid_exits_0() {
    let out = Scenario::new().opv(&["status", "prod"]);
    assert_eq!(out.exit(), Some(0), "{}", out.shown());
}

#[test]
fn live_09_32_status_json_prints_no_value() {
    let out = Scenario::new().opv(&["status", "prod", "--json"]);
    assert_eq!(out.canary(), None, "{}", out.shown());
}

#[test]
fn live_09_36_sync_json_prints_no_value() {
    let out = Scenario::new().opv(&[
        "sync",
        "prod",
        "--confirm",
        "prod",
        "--target",
        "fly",
        "--json",
    ]);
    assert_eq!(out.canary(), None, "{}", out.shown());
}

// --- name typos (13, 51, 52, 57, 83–87) --------------------------------------------------------

#[test]
fn live_09_13_a_transposed_environment_steps_to_the_same_command_with_it_corrected() {
    let out = Scenario::new().opv(&["status", "prdo"]);
    assert_eq!(
        out.next().as_deref(),
        Some("opv status prod"),
        "{}",
        out.shown()
    );
}

#[test]
fn live_09_51_an_explain_key_typo_steps_to_the_declared_key() {
    let out = Scenario::new().opv(&["explain", "API_KY", "--env", "prod"]);
    assert_eq!(
        out.next().as_deref(),
        Some("opv explain web/API_KEY --env prod"),
        "{}",
        out.shown()
    );
}

#[test]
fn live_09_52_an_explain_target_typo_steps_to_the_declared_target() {
    let out = Scenario::new().opv(&["explain", "--target", "fl", "--env", "prod"]);
    assert_eq!(
        out.next().as_deref().map(words),
        Some(expected(
            &["explain", "--target", "fly", "--env", "prod"],
            None
        )),
        "{}",
        out.shown()
    );
}

#[test]
fn live_09_57_an_access_target_typo_keeps_the_environment() {
    let out = Scenario::new()
        .account(DEV_ACCOUNT)
        .opv(&["access", "prod", "--target", "fl"]);
    assert_eq!(
        out.next().as_deref().map(words),
        Some(expected(&["access", "prod", "--target", "fly"], None)),
        "{}",
        out.shown()
    );
}

#[test]
fn live_09_83_a_subcommand_typo_steps_to_the_corrected_command() {
    let out = Scenario::new().opv(&["stauts", "prod"]);
    assert_eq!(
        out.next().as_deref(),
        Some("opv status prod"),
        "{}",
        out.shown()
    );
}

#[test]
fn live_09_84_a_status_target_typo_steps_to_the_declared_target() {
    let out = Scenario::new().opv(&["status", "prod", "--target", "fl"]);
    assert_eq!(
        out.next().as_deref().map(words),
        Some(expected(&["status", "prod", "--target", "fly"], None)),
        "{}",
        out.shown()
    );
}

#[test]
fn live_09_85_an_open_key_typo_steps_to_the_declared_key() {
    let out = Scenario::new().opv(&["open", "web/API_KY", "--env", "prod"]);
    assert_eq!(
        out.next().as_deref().map(words),
        Some(expected(&["open", "web/API_KEY", "--env", "prod"], None)),
        "{}",
        out.shown()
    );
}

/// A write with a misspelt environment steps to its read, never to the write.
#[test]
fn live_09_86_a_sync_environment_typo_steps_to_the_plan() {
    let out = Scenario::new().opv(&["sync", "pro"]);
    assert_eq!(
        out.next().as_deref(),
        Some("opv plan prod"),
        "{}",
        out.shown()
    );
}

#[test]
fn live_09_87_a_role_typo_steps_to_the_declared_role() {
    let out = Scenario::new().opv(&[
        "run",
        "dev",
        "--preview",
        "--product",
        "web",
        "--role",
        "srve",
    ]);
    assert_eq!(
        out.next().as_deref().map(words),
        Some(expected(
            &[
                "run",
                "dev",
                "--preview",
                "--product",
                "web",
                "--role",
                "serve"
            ],
            None
        )),
        "{}",
        out.shown()
    );
}

// --- configuration errors (M-*) ----------------------------------------------------------------

#[test]
fn live_09_m_syntax_a_toml_syntax_error_is_config_invalid() {
    let out = Scenario::new()
        .edit_config(|c| c.replacen("kind = \"secret\"", "kind = \"secret", 1))
        .opv(&["status", "prod", "--json"]);
    assert_eq!(out.code(), "config_invalid", "{}", out.shown());
}

#[test]
fn live_09_m_unknown_a_misspelt_field_is_config_invalid() {
    let out = Scenario::new()
        .edit_config(|c| c.replace("guidance = \"the service", "guidence = \"the service"))
        .opv(&["status", "prod", "--json"]);
    assert_eq!(out.code(), "config_invalid", "{}", out.shown());
}

#[test]
fn live_09_m_badkey_a_malformed_key_name_is_config_invalid() {
    let out = Scenario::new()
        .edit_config(|c| c.replace("products.web.keys.API_KEY]", "products.web.keys.api-key]"))
        .opv(&["status", "prod", "--json"]);
    assert_eq!(out.code(), "config_invalid", "{}", out.shown());
}

#[test]
fn live_09_m_unknown2_fly_app_spelt_with_an_underscore_is_config_invalid() {
    let out = Scenario::new()
        .edit_config(|c| c.replace("fly.app = ", "fly_app = "))
        .opv(&["status", "prod", "--json"]);
    assert_eq!(out.code(), "config_invalid", "{}", out.shown());
}

#[test]
fn live_09_m_rm_profile_a_profile_table_is_config_invalid() {
    let out = Scenario::new()
        .edit_config(|c| format!("{c}\n[profile]\nkind = \"fleet\"\n"))
        .opv(&["status", "prod", "--json"]);
    assert_eq!(out.code(), "config_invalid", "{}", out.shown());
}

#[test]
fn live_09_m_rm_vault_an_environment_vault_id_is_config_invalid() {
    let out = Scenario::new()
        .edit_config(|c| {
            c.replace(
                "order = 2\n",
                "order = 2\nvault_id = \"vE2EWEBPROD000000000000001\"\n",
            )
        })
        .opv(&["status", "prod", "--json"]);
    assert_eq!(out.code(), "config_invalid", "{}", out.shown());
}

#[test]
fn live_09_m_rm_pattern_a_pattern_rule_is_config_invalid() {
    let out = Scenario::new()
        .edit_config(|c| {
            c.replace(
                "rules = { enum = [\"debug\", \"info\", \"warn\"] }",
                "rules = { pattern = \"^[a-z]+$\" }",
            )
        })
        .opv(&["status", "prod", "--json"]);
    assert_eq!(out.code(), "config_invalid", "{}", out.shown());
}

#[test]
fn live_09_m_json_a_removed_form_under_json_keeps_json_in_its_next() {
    let out = Scenario::new()
        .edit_config(|c| format!("{c}\n[profile]\nkind = \"fleet\"\n"))
        .opv(&["status", "prod", "--json"]);
    assert_eq!(
        out.next().as_deref(),
        Some("opv status prod --json"),
        "{}",
        out.shown()
    );
}

// --- run (40, 41, 44, 45) ----------------------------------------------------------------------

#[test]
fn live_09_40_the_run_preview_prints_no_value() {
    let out = Scenario::new().opv(&[
        "run",
        "dev",
        "--preview",
        "--product",
        "web",
        "--role",
        "serve",
    ]);
    assert_eq!(out.canary(), None, "{}", out.shown());
}

#[test]
fn live_09_41_the_run_preview_json_prints_no_value() {
    let out = Scenario::new().opv(&[
        "run",
        "dev",
        "--preview",
        "--product",
        "web",
        "--role",
        "serve",
        "--json",
    ]);
    assert_eq!(out.canary(), None, "{}", out.shown());
}

#[test]
fn live_09_44_run_without_a_command_exits_2() {
    let out = Scenario::new().opv(&["run", "dev", "--product", "web", "--role", "serve"]);
    assert_eq!(out.exit(), Some(2), "{}", out.shown());
}

#[test]
fn live_09_45_run_with_op_missing_exits_3() {
    let out = Scenario::new()
        .faults("[[fault]]\nprogram = \"op\"\nkind = \"tool_missing\"\n")
        .opv(&[
            "run",
            "dev",
            "--product",
            "web",
            "--role",
            "serve",
            "--",
            "/bin/true",
        ]);
    assert_eq!(out.exit(), Some(3), "{}", out.shown());
}

// --- explain, target list, access, doctor, config, schema (50, 53–56, 63, 64, 80, 82) ---------

#[test]
fn live_09_50_explain_a_bare_key_declared_once_exits_0() {
    let out = Scenario::new().opv(&["explain", "API_KEY", "--env", "prod"]);
    assert_eq!(out.exit(), Some(0), "{}", out.shown());
}

#[test]
fn live_09_53_explain_json_prints_no_value() {
    let out = Scenario::new().opv(&["explain", "web/API_KEY", "--env", "dev", "--json"]);
    assert_eq!(out.canary(), None, "{}", out.shown());
}

#[test]
fn live_09_54_explain_without_a_key_exits_2() {
    let out = Scenario::new().opv(&["explain"]);
    assert_eq!(out.exit(), Some(2), "{}", out.shown());
}

#[test]
fn live_09_55_target_list_exits_0() {
    let out = Scenario::new().opv(&["target", "list", "--env", "prod"]);
    assert_eq!(out.exit(), Some(0), "{}", out.shown());
}

#[test]
fn live_09_56_access_signed_in_exits_0() {
    let out = Scenario::new().account(DEV_ACCOUNT).opv(&["access"]);
    assert_eq!(out.exit(), Some(0), "{}", out.shown());
}

#[test]
fn live_09_63_doctor_prints_no_value() {
    let out = Scenario::new().account(DEV_ACCOUNT).opv(&["doctor"]);
    assert_eq!(out.canary(), None, "{}", out.shown());
}

#[test]
fn live_09_64_doctor_for_prod_json_prints_no_value() {
    let out = Scenario::new()
        .account(DEV_ACCOUNT)
        .opv(&["doctor", "--env", "prod", "--json"]);
    assert_eq!(out.canary(), None, "{}", out.shown());
}

#[test]
fn live_09_80_config_describe_exits_0() {
    let out = Scenario::new().opv(&["contract"]);
    assert_eq!(out.exit(), Some(0), "{}", out.shown());
}

#[test]
fn live_09_82_schema_exits_0() {
    let out = Scenario::new().opv(&["schema"]);
    assert_eq!(out.exit(), Some(0), "{}", out.shown());
}

#[test]
fn live_09_91_open_a_declared_key_exits_0() {
    let out = Scenario::new().opv(&["open", "web/API_KEY", "--env", "prod"]);
    assert_eq!(out.exit(), Some(0), "{}", out.shown());
}

// --- accounts, vaults and 1Password failures (65–67, 71–74, 76–78, 88) -------------------------

/// #153a: the vault is looked up in the machine's other accounts, so the step selects the
/// account that holds it instead of sending the person to `opv vault locate`.
#[test]
fn live_09_65_a_vault_outside_the_selected_account_steps_to_the_account_that_holds_it() {
    let out = Scenario::new()
        .account(OPS_ACCOUNT)
        .opv(&["status", "prod", "--json"]);
    let selects = format!("opv account use {DEV_ACCOUNT}");
    assert_eq!(
        out.next().as_deref(),
        Some(selects.as_str()),
        "{}",
        out.shown()
    );
}

#[test]
fn live_09_66_vault_locate_of_a_known_vault_exits_0() {
    let out = Scenario::new().opv(&["vault", "locate", "vE2EWEBPROD000000000000001"]);
    assert_eq!(out.exit(), Some(0), "{}", out.shown());
}

/// mig-final-op: every account op knows answered "not here", so the account that holds it
/// is not added (`account_not_registered`, exit 7, step `opv login --add`); `NotFound`
/// (exit 4) would step back to this same `vault locate`.
#[test]
fn live_09_67_vault_locate_of_a_vault_in_no_account_is_account_not_registered() {
    let out = Scenario::new().opv(&["vault", "locate", "vE2ENOSUCHVAULT00000000001"]);
    assert_eq!(out.exit(), Some(7), "{}", out.shown());
}

#[test]
fn live_09_71_account_list_json_exits_0() {
    let out = Scenario::new().opv(&["account", "list", "--json"]);
    assert_eq!(out.exit(), Some(0), "{}", out.shown());
}

/// A `.opv` naming an account op does not know steps to adding it, never to `account list`:
/// at op's prompt on Linux, in the 1Password app (then `opv login`) where the app holds the
/// accounts (macOS).
#[test]
fn live_09_72_an_unknown_selected_account_steps_to_login_add() {
    let out = Scenario::new()
        .account(UNKNOWN_ACCOUNT)
        .opv(&["account", "list", "--json"]);
    let want = if cfg!(target_os = "macos") {
        "opv login"
    } else {
        "opv login --add"
    };
    assert_eq!(out.next().as_deref(), Some(want), "{}", out.shown());
}

#[test]
fn live_09_73_status_with_an_unknown_selected_account_is_account_not_registered() {
    let out = Scenario::new()
        .account(UNKNOWN_ACCOUNT)
        .opv(&["status", "prod", "--json"]);
    assert_eq!(out.exit(), Some(7), "{}", out.shown());
}

#[test]
fn live_09_74_malformed_item_json_is_unexpected_output() {
    let out = Scenario::new()
        .faults(&fault("op", "item get", "malformed_output"))
        .opv(&["status", "prod", "--json"]);
    assert_eq!(out.code(), "unexpected_output", "{}", out.shown());
}

#[test]
fn live_09_76_a_vault_that_does_not_exist_steps_to_vault_locate() {
    let out = Scenario::new()
        .edit_config(|c| c.replace("vE2EWEBPROD000000000000001", "vE2ENOSUCHVAULT00000000001"))
        .opv(&["status", "prod", "--json"]);
    assert_eq!(
        out.next().as_deref(),
        Some("opv vault locate vE2ENOSUCHVAULT00000000001"),
        "{}",
        out.shown()
    );
}

#[test]
fn live_09_77_op_hanging_past_the_timeout_exits_9() {
    let out = Scenario::new()
        .faults(
            "[[fault]]\nprogram = \"op\"\ncall = \"item get\"\nkind = \"timeout\"\nseconds = 30\n",
        )
        .opv(&["--timeout", "3", "status", "prod"]);
    assert_eq!(out.exit(), Some(9), "{}", out.shown());
}

#[test]
fn live_09_78_flyctl_hanging_past_the_timeout_exits_9() {
    let out = Scenario::new()
        .faults(
            "[[fault]]\nprogram = \"flyctl\"\ncall = \"secrets list\"\nkind = \"timeout\"\nseconds = 30\n",
        )
        .opv(&["--timeout", "4", "status", "prod", "--target", "fly"]);
    assert_eq!(out.exit(), Some(9), "{}", out.shown());
}

/// A rejected service-account token under CI is the credential, not a sign-in.
#[test]
fn live_09_88_a_rejected_service_account_token_under_ci_is_credential_rejected() {
    let out = Scenario::new().opv_env(
        &["status", "prod", "--json"],
        &[
            ("CI", "true"),
            ("OP_SERVICE_ACCOUNT_TOKEN", "ops_e2e_marker_rejected_token"),
        ],
    );
    assert_eq!(out.code(), "credential_rejected", "{}", out.shown());
}

// --- MCP --------------------------------------------------------------------------------------

/// The step of the finding `code` in an `opv_ready` document.
fn ready_step(doc: &Value, code: &str) -> Option<String> {
    doc["findings"]
        .as_array()?
        .iter()
        .find(|f| f["code"] == code)
        .and_then(|f| f["step"].as_str())
        .map(str::to_string)
}

#[test]
fn live_09_mcp_ready_with_an_unknown_selected_account_steps_to_login_add() {
    let doc = Scenario::new()
        .account(UNKNOWN_ACCOUNT)
        .mcp("opv_ready", json!({}));
    // Where the 1Password app holds the accounts (macOS), the account is added there.
    let want = if cfg!(target_os = "macos") {
        "opv login"
    } else {
        "opv login --add"
    };
    assert_eq!(
        ready_step(&doc, "selected_account_absent").as_deref(),
        Some(want),
        "{doc}"
    );
}

#[test]
fn live_09_mcp_ready_prod_with_an_unknown_selected_account_steps_to_login_add() {
    let doc = Scenario::new()
        .account(UNKNOWN_ACCOUNT)
        .mcp("opv_ready", json!({"environment": "prod"}));
    // Where the 1Password app holds the accounts (macOS), the account is added there.
    let want = if cfg!(target_os = "macos") {
        "opv login"
    } else {
        "opv login --add"
    };
    assert_eq!(
        ready_step(&doc, "selected_account_absent").as_deref(),
        Some(want),
        "{doc}"
    );
}

#[test]
fn live_09_mcp_ready_with_an_undeclared_environment_is_unknown_env() {
    let doc = Scenario::new()
        .account(DEV_ACCOUNT)
        .mcp("opv_ready", json!({"environment": "prdo"}));
    assert_eq!(doc["error"]["code"], "unknown_env", "{doc}");
}

#[test]
fn live_09_mcp_configuration_prints_no_value() {
    let doc = Scenario::new()
        .account(DEV_ACCOUNT)
        .mcp("opv_configuration", json!({}));
    let text = doc.to_string();
    assert_eq!(
        canaries().into_iter().find(|c| text.contains(c.as_str())),
        None,
        "{doc}"
    );
}

#[test]
fn live_09_mcp_deployment_plan_prints_no_value() {
    let doc = Scenario::new()
        .account(DEV_ACCOUNT)
        .mcp("opv_deployment_plan", json!({"environment": "prod"}));
    let text = doc.to_string();
    assert_eq!(
        canaries().into_iter().find(|c| text.contains(c.as_str())),
        None,
        "{doc}"
    );
}

#[test]
fn live_09_mcp_changed_with_no_delivery_item_is_an_ok_answer() {
    let doc = Scenario::new()
        .account(DEV_ACCOUNT)
        .mcp("opv_changed", json!({"environment": "prod"}));
    assert_eq!(doc["ok"], true, "{doc}");
}

#[test]
fn live_09_mcp_changed_with_no_delivery_item_says_it_changed() {
    let doc = Scenario::new()
        .account(DEV_ACCOUNT)
        .mcp("opv_changed", json!({"environment": "prod"}));
    assert_eq!(doc["changed"], true, "{doc}");
}

#[test]
fn live_09_mcp_changed_prints_no_value() {
    let doc = Scenario::new()
        .account(DEV_ACCOUNT)
        .mcp("opv_changed", json!({"environment": "prod"}));
    let text = doc.to_string();
    assert_eq!(
        canaries().into_iter().find(|c| text.contains(c.as_str())),
        None,
        "{doc}"
    );
}

#[test]
fn live_09_mcp_propose_target_with_a_secrets_dir_and_a_role_is_proposed() {
    let doc = Scenario::new().account(DEV_ACCOUNT).mcp(
        "opv_propose",
        json!({
            "kind": "target",
            "env": "prod",
            "name": "cluster",
            "options": {
                "kubernetes-context": "e2e-cluster",
                "kubernetes-namespace": "e2e-prod",
                "kubernetes-deployment": "e2e-worker",
                "kubernetes-secrets-dir": "/run/secrets/{product}",
            },
            "role": "serve",
        }),
    );
    assert_eq!(doc["ok"], true, "{doc}");
}

#[test]
fn live_09_mcp_deployment_plan_for_a_path_is_unknown_env() {
    let doc = Scenario::new()
        .account(DEV_ACCOUNT)
        .mcp("opv_deployment_plan", json!({"environment": "../etc"}));
    assert_eq!(doc["error"]["code"], "unknown_env", "{doc}");
}

#[test]
fn live_09_mcp_deployment_plan_with_a_target_typo_is_unknown_target() {
    let doc = Scenario::new().account(DEV_ACCOUNT).mcp(
        "opv_deployment_plan",
        json!({"environment": "prod", "targets": ["fl"]}),
    );
    assert_eq!(doc["error"]["code"], "unknown_target", "{doc}");
}

#[test]
fn live_09_mcp_deployment_plan_rotating_an_undeclared_key_is_undeclared_key() {
    let doc = Scenario::new().account(DEV_ACCOUNT).mcp(
        "opv_deployment_plan",
        json!({"environment": "prod", "rotate": ["web/NOPE"]}),
    );
    assert_eq!(doc["error"]["code"], "undeclared_key", "{doc}");
}

#[test]
fn live_09_mcp_access_for_an_undeclared_environment_is_unknown_env() {
    let doc = Scenario::new()
        .account(DEV_ACCOUNT)
        .mcp("opv_access", json!({"environment": "nope"}));
    assert_eq!(doc["error"]["code"], "unknown_env", "{doc}");
}

#[test]
fn live_09_mcp_structure_plan_prints_no_value() {
    let doc = Scenario::new()
        .account(DEV_ACCOUNT)
        .mcp("opv_structure_plan", json!({}));
    let text = doc.to_string();
    assert_eq!(
        canaries().into_iter().find(|c| text.contains(c.as_str())),
        None,
        "{doc}"
    );
}

/// The agent's own argument error is for the agent to fix, not a person.
#[test]
fn live_09_mcp_propose_key_with_a_malformed_name_is_not_for_a_person() {
    let doc = Scenario::new().account(DEV_ACCOUNT).mcp(
        "opv_propose",
        json!({"kind": "key", "product": "web", "key": "bad-key", "field_kind": "secret"}),
    );
    assert_eq!(doc["error"]["human_required"], false, "{doc}");
}

#[test]
fn live_09_mcp_propose_key_with_an_unknown_field_kind_is_not_for_a_person() {
    let doc = Scenario::new().account(DEV_ACCOUNT).mcp(
        "opv_propose",
        json!({"kind": "key", "product": "web", "key": "NEW_KEY", "field_kind": "secrit"}),
    );
    assert_eq!(doc["error"]["human_required"], false, "{doc}");
}

#[test]
fn live_09_mcp_propose_key_for_an_undeclared_environment_is_unknown_env() {
    let doc = Scenario::new().account(DEV_ACCOUNT).mcp(
        "opv_propose",
        json!({"kind": "key", "product": "web", "key": "NEW_KEY", "field_kind": "secret",
               "environments": ["prdo"]}),
    );
    assert_eq!(doc["error"]["code"], "unknown_env", "{doc}");
}

#[test]
fn live_09_mcp_propose_env_with_a_capitalised_name_is_not_for_a_person() {
    let doc = Scenario::new()
        .account(DEV_ACCOUNT)
        .mcp("opv_propose", json!({"kind": "env", "env": "Dev"}));
    assert_eq!(doc["error"]["human_required"], false, "{doc}");
}

#[test]
fn live_09_mcp_propose_target_already_declared_is_already_declared() {
    let doc = Scenario::new().account(DEV_ACCOUNT).mcp(
        "opv_propose",
        json!({"kind": "target", "env": "prod", "name": "fly", "options": {"fly-app": "x"}}),
    );
    assert_eq!(doc["error"]["code"], "already_declared", "{doc}");
}

#[test]
fn live_09_mcp_propose_target_with_an_unknown_provider_is_not_for_a_person() {
    let doc = Scenario::new().account(DEV_ACCOUNT).mcp(
        "opv_propose",
        json!({"kind": "target", "env": "prod", "name": "web", "provider": "heroku"}),
    );
    assert_eq!(doc["error"]["human_required"], false, "{doc}");
}

#[test]
fn live_09_mcp_propose_target_fly_without_an_app_is_not_for_a_person() {
    let doc = Scenario::new().account(DEV_ACCOUNT).mcp(
        "opv_propose",
        json!({"kind": "target", "env": "prod", "name": "web", "provider": "fly"}),
    );
    assert_eq!(doc["error"]["human_required"], false, "{doc}");
}

/// opv knows why it refuses: the key has no byte-length rule, so it is the provider's.
#[test]
fn live_09_mcp_propose_generate_of_a_provider_issued_key_is_policy_refused() {
    let doc = Scenario::new().account(DEV_ACCOUNT).mcp(
        "opv_propose",
        json!({"kind": "generate", "env": "prod", "keys": ["web/API_KEY"]}),
    );
    assert_eq!(doc["error"]["code"], "policy_refused", "{doc}");
}

#[test]
fn live_09_mcp_delivery_preview_of_an_undeclared_profile_is_unknown_profile() {
    let doc = Scenario::new().account(DEV_ACCOUNT).mcp(
        "opv_delivery_preview",
        json!({"environment": "prod", "product": "web", "role": "serve", "remote": "nosuch"}),
    );
    assert_eq!(doc["error"]["code"], "unknown_profile", "{doc}");
}

#[test]
fn live_09_mcp_delivery_preview_of_an_undeclared_environment_is_unknown_env() {
    let doc = Scenario::new()
        .account(DEV_ACCOUNT)
        .mcp("opv_delivery_preview", json!({"environment": "prdo"}));
    assert_eq!(doc["error"]["code"], "unknown_env", "{doc}");
}
