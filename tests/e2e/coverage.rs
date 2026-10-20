//! The error catalog's coverage gates (design §13.4), the milestone gate of the catalog.
//!
//! - **Every `Cause` variant is reached end to end**: by a fault-matrix cell
//!   (`tests/e2e/snapshots/*.snap`, tests/e2e/matrix.rs) or by one of the scenarios below
//!   (`tests/e2e/snapshots/scenarios/<case>.snap`). A variant is read off a `--json` or MCP
//!   error document: its `subject` holds exactly the variant's fields (read from
//!   `src/cause/mod.rs`), and its `code` is one the variant reports. The few that cannot be
//!   reached end to end are in [`UNREACHABLE`], each with its reason.
//! - **Every call the matrix discovers is faulted** with every fault kind, or listed in
//!   `snapshots/SKIPPED.md` with its reason.
//! - **MCP equals the CLI**: for each scenario an MCP tool reaches, the tool's whole answer,
//!   a failure included, is the CLI's whole `--json` document (owner decision, design §25.2).
//! - **Every flow document of §25.1/§25.2 is pinned** (`flows`): a text, `--json` and, where a
//!   tool exists, MCP run of each `propose` kind, `import`, `needs`, `contract` and `explain`,
//!   on a world whose every value is an `S7MARKER` marker; no scenario snapshot may hold one.
//! - **Every core document of §25.1 is pinned** (`core`): a text and `--json` run of
//!   `inventory`, `next`, `ready --gate`, `doctor --env prod` (R9) and `access`, on a marked
//!   world with vault members; `next`'s MCP half is `opv_next`.
//!
//! Each scenario runs the real `opv` against `opv-sim` on the test application
//! (`tests/e2e/app`): a scratch `HOME`, `OPV_NO_SKILL=1`, no real credential, only recorded
//! tool replies. Its snapshot holds the text run, the `--json` run and, when an MCP tool
//! reaches the same situation, the tool's answer; each run gets a fresh world. Rewrite the
//! snapshots with `UPDATE_SNAPSHOTS=1` and review the diff. The gates read the committed
//! snapshots, so they are cheap and independent of test order.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use serde_json::{Value, json};

const ROOT: &str = env!("CARGO_MANIFEST_DIR");
const OPV: &str = env!("CARGO_BIN_EXE_opv");
const SIM: &str = env!("CARGO_BIN_EXE_opv-sim");
pub(crate) const DEV_ACCOUNT: &str = "AE2EDEVACCOUNT000000000001";
/// The canary every value of a flow scenario carries (its world and its dotenv files): no
/// snapshot may hold it.
pub(crate) const MARK: &str = "S7MARKER";

/// The variants no end-to-end run can reach, and why. Keep it short: prefer a scenario.
const UNREACHABLE: &[(&str, &str)] = &[
    // Reached by 0.11.0's explicit repair `opv tidy`, removed in 0.12.0 (a tidy proposal is
    // deferred: it has no planner); a person's read that tidies reports a conflict
    // as a note and goes on (src/app/tidy.rs), and opv-sim changes nothing between two reads.
    (
        "ConcurrentEdit",
        "only opv tidy failed on a tidy conflict; reads note it and go on",
    ),
    // design §13.4: reachable only through a bug in opv itself.
    (
        "Bug",
        "an internal error: reachable only through a bug in opv",
    ),
    // Built by the External Secrets preflight when a ClusterSecretStore is not Ready
    // (src/adapters/kubernetes/external.rs); no committed scenario drives that store into a
    // write.
    (
        "StoreNotReady",
        "no scenario drives a not-ready ClusterSecretStore into a write",
    ),
    // The receiver speaks protocol 1 (src/app/remote_delivery.rs PROTOCOL); another
    // protocol's handshake would be invented output: there is no recording of one.
    (
        "RemoteVersionMismatch",
        "no recording of a receiver speaking another protocol",
    ),
    // A Windows named pipe only (src/adapters/azure/handoff.rs); Azure is deferred for 0.10.0
    // and opv-sim answers `az` as not installed.
    (
        "HandoffPipeContested",
        "Windows-only named pipe; Azure has no simulator",
    ),
    // opv-sim's world changes only through opv's own calls, so nothing changes between two
    // reads of one run (tidy's stamp, a file edited mid-run, a Deployment moved).
    (
        "ChangedBeforeWrite",
        "nothing changes the simulated world between two reads of a run",
    ),
    // Built only after `op service-account create` (src/app/access_create.rs), which opv-sim
    // does not model and nobody has recorded.
    (
        "SecretNotStored",
        "no recording of `op service-account create`",
    ),
    // Drift is a pinned binding whose version differs from the store's current one. The only
    // pinned target opv-sim models is plain Kubernetes, whose store takes the current version
    // from the Deployment's own binding (src/adapters/kubernetes/store.rs `read`), so the two
    // never differ. Where they can (Azure Key Vault through External Secrets,
    // src/adapters/azure/keyvault.rs, src/adapters/kubernetes/external.rs, or the K5 volume
    // bindings) opv-sim models nothing; reached by src/app/azure_tests.rs. The flag's other
    // side, a target with nothing pinned exiting 0, is scenarios/changed.rs. Drop this when a
    // scenario or the K5 bindings make it reachable.
    (
        "TargetDrift",
        "drift needs a pinned store opv-sim does not model (Azure Key Vault/ESO)",
    ),
    // A result, not a failure: `opv changed` reports it as `ok: true` with exit 10 in its
    // own document (src/app/changed.rs), never as an error, so no error snapshot exists. Its
    // states are snapshotted as successful results in scenarios/changed.rs
    // (snapshots/changed/).
    (
        "SourceChanged",
        "a successful result (exit 10), never an error document",
    ),
    // An unknown plan id reaches `PlanUnknown` only inside `opv apply` (a structural
    // `sp-…` the run did not recompute, or a retirement `rp-…` no `retiring` key has,
    // src/app/apply.rs `apply_retire`), and `opv apply` refuses a run with no terminal before
    // it reads anything: the harness gives opv none (scenarios/apply_needs_terminal.snap), and
    // no MCP tool applies. Reached by src/app/apply_tests.rs
    // (`an_unknown_retirement_plan_id_is_refused`).
    (
        "PlanUnknown",
        "only opv apply reaches it, and only at a person's terminal, which the harness never gives",
    ),
];

fn snapshots() -> PathBuf {
    Path::new(ROOT).join("tests/e2e/snapshots")
}

pub(crate) fn scenario_snapshots() -> PathBuf {
    snapshots().join("scenarios")
}

pub(crate) fn updating() -> bool {
    std::env::var("UPDATE_SNAPSHOTS").is_ok_and(|v| v == "1")
}

// --- the scenario harness -------------------------------------------------------------------

/// A scenario directory: the world, a scratch `HOME`, the project (the app's `secrets.toml`
/// and a `.opv` selecting the dev account), a directory outside it, and the simulator
/// installed under every tool name.
pub(crate) struct Scenario {
    root: tempfile::TempDir,
    env: Vec<(String, String)>,
    cwd: &'static str,
    /// Signal the run (`TERM`, `INT`) once the simulator logs a call holding the text.
    interrupt: Option<(&'static str, &'static str)>,
    /// Installed on the first run, once `faults.toml` is final (a `tool_missing` fault with
    /// no call leaves the tool out).
    installed: std::cell::Cell<bool>,
    /// Run after the install, before the first command.
    after_install: Vec<fn(&Scenario)>,
}

impl Scenario {
    pub(crate) fn new() -> Self {
        let root = tempfile::tempdir().expect("temp dir");
        let s = Self {
            root,
            env: Vec::new(),
            cwd: "project",
            interrupt: None,
            installed: std::cell::Cell::new(false),
            after_install: Vec::new(),
        };
        for d in ["world", "home", "project", "elsewhere", "bin"] {
            std::fs::create_dir_all(s.path(d)).expect("scenario dir");
        }
        let app = Path::new(ROOT).join("tests/e2e/app");
        std::fs::copy(app.join("world.json"), s.path("world/world.json")).expect("world");
        std::fs::write(s.path("world/faults.toml"), "").expect("faults");
        std::fs::copy(app.join("secrets.toml"), s.path("project/secrets.toml")).expect("config");
        std::fs::copy(
            app.join("secrets.bindings.toml"),
            s.path("project/secrets.bindings.toml"),
        )
        .expect("bindings");
        std::fs::write(
            s.path("project/.opv"),
            format!("account = \"{DEV_ACCOUNT}\"\n"),
        )
        .expect(".opv");
        s
    }

    pub(crate) fn install(&self) {
        if self.installed.replace(true) {
            return;
        }
        let ok = Command::new(SIM)
            .arg("install")
            .arg(self.path("bin"))
            .env("OPV_SIM_WORLD", self.path("world"))
            .status()
            .expect("opv-sim install")
            .success();
        assert!(ok, "opv-sim install failed");
        for f in &self.after_install {
            f(self);
        }
    }

    fn after_install(mut self, f: fn(&Scenario)) -> Self {
        self.after_install.push(f);
        self
    }

    pub(crate) fn path(&self, sub: &str) -> PathBuf {
        self.root.path().join(sub)
    }

    fn faults(self, faults: &str) -> Self {
        std::fs::write(self.path("world/faults.toml"), faults).expect("faults");
        self
    }

    /// The project's `.opv`, replaced (`None`: no `.opv`).
    pub(crate) fn dot_opv(self, text: Option<&str>) -> Self {
        let p = self.path("project/.opv");
        match text {
            Some(t) => std::fs::write(&p, t).expect(".opv"),
            None => std::fs::remove_file(&p).expect(".opv"),
        }
        self
    }

    pub(crate) fn without_config(self) -> Self {
        std::fs::remove_file(self.path("project/secrets.toml")).expect("config");
        self
    }

    /// The project's `secrets.toml`, edited as one text with its ids filled in; the ids of
    /// the edited text go back to `secrets.bindings.toml` (D-G).
    fn config(self, edit: impl FnOnce(String) -> String) -> Self {
        let p = self.path("project/secrets.toml");
        let text = opv::config::read_merged(&p).expect("config");
        opv::config::bindings::write_split(&p, &edit(text)).expect("config");
        self
    }

    /// The world, edited.
    pub(crate) fn world(self, edit: impl FnOnce(&mut Value)) -> Self {
        let p = self.path("world/world.json");
        let mut w: Value =
            serde_json::from_str(&std::fs::read_to_string(&p).expect("world")).expect("world");
        edit(&mut w);
        std::fs::write(&p, w.to_string()).expect("world");
        self
    }

    pub(crate) fn var(mut self, k: &str, v: &str) -> Self {
        self.env.push((k.into(), v.into()));
        self
    }

    /// The manifest route: no `secrets.toml`, `OPV_PROJECT=e2e-app`, the dev account.
    fn manifest_route(self) -> Self {
        self.without_config()
            .var("OPV_PROJECT", "e2e-app")
            .var("OP_ACCOUNT", DEV_ACCOUNT)
    }

    /// A file under the scenario root (parents made).
    pub(crate) fn file(self, rel: &str, text: &str) -> Self {
        let p = self.path(rel);
        std::fs::create_dir_all(p.parent().expect("parent")).expect("parent");
        std::fs::write(&p, text).expect("file");
        self
    }

    pub(crate) fn mode(self, rel: &str, mode: u32) -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(self.path(rel), std::fs::Permissions::from_mode(mode))
            .expect("chmod");
        self
    }

    fn dir(self, rel: &str, mode: u32) -> Self {
        let p = self.path(rel);
        std::fs::create_dir_all(&p).expect("dir");
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).expect("chmod");
        self
    }

    /// `ssh` that keeps the world in reach: `remote-send` clears the environment before it
    /// starts ssh, so the simulator is told where the world is here.
    fn ssh_in_world(self) -> Self {
        self.after_install(|s| {
            let ssh = s.path("bin/ssh");
            let _ = std::fs::remove_file(&ssh);
            std::fs::write(
                &ssh,
                format!(
                    "#!/bin/bash\nexport OPV_SIM_WORLD='{}'\nexec -a ssh '{SIM}' \"$@\"\n",
                    s.path("world").display()
                ),
            )
            .expect("ssh");
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        })
    }

    /// The project as a git checkout of the app's repository.
    pub(crate) fn git_checkout(self) -> Self {
        for args in [
            &["init", "-q"][..],
            &[
                "remote",
                "add",
                "origin",
                "https://github.com/e2e-org/e2e-app.git",
            ][..],
        ] {
            let ok = Command::new("git")
                .args(args)
                .current_dir(self.path("project"))
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", self.path("home"))
                .status()
                .expect("git")
                .success();
            assert!(ok, "git {args:?}");
        }
        self
    }

    /// The project's git checkout with everything staged committed, so `HEAD` holds it
    /// (the revision CI deploys: what a retirement's needs check scans).
    fn committed(self) -> Self {
        let ok = Command::new("git")
            .args(["commit", "-qm", "the app"])
            .current_dir(self.path("project"))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.path("home"))
            .env("GIT_AUTHOR_NAME", "e2e")
            .env("GIT_AUTHOR_EMAIL", "e2e@example.test")
            .env("GIT_COMMITTER_NAME", "e2e")
            .env("GIT_COMMITTER_EMAIL", "e2e@example.test")
            .status()
            .expect("git commit")
            .success();
        assert!(ok, "git commit");
        self
    }

    /// Every value of the world marked: a string holding a value marker (`test-marker-e2e-…`)
    /// becomes `S7MARKERVALUE-<it>`, so the canary gate finds any value a run prints.
    pub(crate) fn marked(self) -> Self {
        fn mark(v: &mut Value) {
            match v {
                Value::String(s) if s.contains("test-marker-e2e-") => {
                    *s = format!("{MARK}VALUE-{s}");
                }
                Value::Array(a) => a.iter_mut().for_each(mark),
                Value::Object(o) => o.values_mut().for_each(mark),
                _ => {}
            }
        }
        self.world(mark)
    }

    /// A dotenv file in the project, readable by its owner only, every value a marker.
    pub(crate) fn dotenv(self, rel: &str, names: &[&str]) -> Self {
        let text: String = names
            .iter()
            .map(|n| format!("{n}={MARK}VALUE-dotenv-{}\n", n.to_ascii_lowercase()))
            .collect();
        let rel = format!("project/{rel}");
        self.file(&rel, &text).mode(&rel, 0o600)
    }

    /// A file of the project's git checkout, staged so the scanner's tree holds it.
    pub(crate) fn tracked(self, rel: &str, text: &str) -> Self {
        let s = self.file(&format!("project/{rel}"), text);
        let ok = Command::new("git")
            .args(["add", rel])
            .current_dir(s.path("project"))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", s.path("home"))
            .status()
            .expect("git add")
            .success();
        assert!(ok, "git add {rel}");
        s
    }

    pub(crate) fn command(&self) -> Command {
        self.install();
        let mut c = Command::new(OPV);
        c.current_dir(self.path(self.cwd))
            .env_clear()
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.path("bin").display()),
            )
            .env("HOME", self.path("home"))
            .env("OPV_NO_SKILL", "1")
            .env("OPV_SIM_WORLD", self.path("world"))
            // Doctor's core-dump check reads this, not the host's `fs.suid_dumpable`.
            .env("OPV_TEST_SUID_DUMPABLE", "0")
            .stdin(Stdio::null());
        for (k, v) in &self.env {
            c.env(k, v);
        }
        c
    }

    /// `opv <args>`; `{root}` in an argument is the scenario root.
    pub(crate) fn opv(&self, args: &[String]) -> Run {
        let root = self.root.path().display().to_string();
        let args: Vec<String> = args.iter().map(|a| a.replace("{root}", &root)).collect();
        let out = match self.interrupt {
            None => self.command().args(&args).output().expect("run opv"),
            Some((call, signal)) => self.interrupted(&args, call, signal),
        };
        Run {
            code: out.status.code(),
            stdout: self.normalize(&String::from_utf8_lossy(&out.stdout)),
            stderr: self.normalize(&String::from_utf8_lossy(&out.stderr)),
        }
    }

    /// `opv <args>`, sent `signal` once the simulator logs a call holding `call`.
    fn interrupted(&self, args: &[String], call: &str, signal: &str) -> std::process::Output {
        let child = self
            .command()
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run opv");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while !std::fs::read_to_string(self.path("world/calls.log"))
            .unwrap_or_default()
            .contains(call)
        {
            assert!(std::time::Instant::now() < deadline, "{call} never called");
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let ok = Command::new("kill")
            .args([format!("-{signal}"), child.id().to_string()])
            .status()
            .expect("kill")
            .success();
        assert!(ok, "kill");
        child.wait_with_output().expect("output")
    }

    /// One MCP `tools/call` on `opv mcp serve --project <project>`: the tool's answer.
    pub(crate) fn mcp(&self, tool: &str, arguments: &Value) -> Value {
        let mut child = self
            .command()
            .args(["mcp", "serve", "--project"])
            .arg(self.path("project"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("mcp serve");
        let mut stdin = child.stdin.take().expect("stdin");
        let mut lines = BufReader::new(child.stdout.take().expect("stdout")).lines();
        let mut send = |message: Value, id: Option<u64>| {
            writeln!(stdin, "{message}").expect("write");
            stdin.flush().expect("flush");
            let id = id?;
            lines
                .by_ref()
                .map_while(Result::ok)
                .filter_map(|l| serde_json::from_str::<Value>(&l).ok())
                .find(|m| m["id"] == id)
        };
        send(
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-11-25", "capabilities": {},
                "clientInfo": {"name": "opv-coverage", "version": "1"}}}),
            Some(1),
        );
        send(
            json!({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}),
            None,
        );
        let result = send(
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
        let text = self.normalize(text);
        serde_json::from_str(&text).unwrap_or_else(|_| json!({ "raw": result }))
    }

    /// What a snapshot must not depend on: the scenario's path and the host's platform.
    pub(crate) fn normalize(&self, s: &str) -> String {
        // macOS resolves the temp directory through a symlink (/var → /private/var), so
        // opv may print either spelling of the scenario's path.
        let root = self.root.path().display().to_string();
        let real = std::fs::canonicalize(self.root.path())
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| root.clone());
        let s = s.replace(&real, "<SCENARIO>").replace(&root, "<SCENARIO>");
        let s = re(r#""platform":"(linux|wsl|macos|windows)""#)
            .replace_all(&s, r#""platform":"<platform>""#);
        let s = re(r"\bin \d+(\.\d+)? ?(ms|s)\b").replace_all(&s, "in <delay>");
        let s = re(r"rcpt-[0-9a-f]+").replace_all(&s, "rcpt-<id>");
        // A Kubernetes object's version id is random (src/adapters/kubernetes/mod.rs
        // `new_version`).
        let s = re(r"\b(opv-e2e-[a-z0-9-]*-)[a-z2-7]{10}\b").replace_all(&s, "${1}<id>");
        // opv's own version changes every release; a snapshot must not.
        let s = s.replace(
            &format!(r#""opv_version":"{}""#, env!("CARGO_PKG_VERSION")),
            r#""opv_version":"<version>""#,
        );
        let s = s.replace(" (op in WSL does not see the Windows app's accounts)", "");
        // Doctor's app-integration row reads the host (WSL, a display; #203).
        let s = re(r"(?m)^(ok|warn|skip) +op app integration: [^\n]*\n")
            .replace_all(&s, "<host app-integration check>\n");
        re(r#"\{"name":"op app integration"[^}]*\}"#)
            .replace_all(&s, r#"{"name":"op app integration","host":true}"#)
            .into_owned()
    }
}

fn re(pattern: &str) -> regex::Regex {
    regex::Regex::new(pattern).expect("regex")
}

pub(crate) struct Run {
    pub(crate) code: Option<i32>,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

// --- the scenarios --------------------------------------------------------------------------

/// One scenario: a fresh world, the command (`--json` is appended for the JSON run), and the
/// MCP tool call that meets the same situation, when one does.
struct Case {
    scenario: Scenario,
    args: Vec<String>,
    mcp: Option<(&'static str, Value)>,
}

fn case(scenario: Scenario, args: &[&str]) -> Case {
    Case {
        scenario,
        args: args.iter().map(|a| a.to_string()).collect(),
        mcp: None,
    }
}

impl Case {
    fn mcp(mut self, tool: &'static str, arguments: Value) -> Self {
        self.mcp = Some((tool, arguments));
        self
    }
}

/// `faults.toml` with one fault.
fn fault(program: &str, call: &str, kind: &str) -> String {
    format!("[[fault]]\nprogram = \"{program}\"\ncall = \"{call}\"\nkind = \"{kind}\"\n")
}

/// The line holding `needle` removed from `text` (the first one).
fn without_line(text: String, needle: &str) -> String {
    let mut done = false;
    text.lines()
        .filter(|l| {
            let drop = !done && l.contains(needle);
            done |= drop;
            !drop
        })
        .map(|l| format!("{l}\n"))
        .collect()
}

/// Each item with `id`, edited.
fn item(w: &mut Value, id: &str, edit: impl Fn(&mut Value)) {
    for i in w["op"]["items"].as_array_mut().expect("items") {
        if i["id"] == id {
            edit(i);
        }
    }
}

const MANIFEST_ITEM: &str = "iE2EMANIFEST00000000000001";
const WEB_PROD_ITEM: &str = "iE2EWEBPROD000000000000001";
const WEB_DEV_ITEM: &str = "iE2EWEBDEV0000000000000001";

mod cases {
    use super::*;

    // §4.1 configuration

    pub fn config_not_found() -> Case {
        case(Scenario::new().without_config(), &["contract"])
            .mcp("opv_state", json!({"section": "contract"}))
    }

    pub fn config_unreadable() -> Case {
        // The given path is a folder (a mode would not stop a root builder).
        case(Scenario::new(), &["--config", "{root}/project", "contract"])
    }

    pub fn config_invalid() -> Case {
        case(
            Scenario::new().config(|c| c.replacen("[environments.dev]", "[environments.dev\n", 1)),
            &["contract"],
        )
        .mcp("opv_state", json!({"section": "contract"}))
    }

    pub fn boundary_missing() -> Case {
        case(
            Scenario::new().config(|c| {
                without_line(
                    c,
                    r#"boundaries.shared = { vault_id = "vE2ESHAREDPROD0000000000001""#,
                )
            }),
            &["contract"],
        )
        .mcp("opv_state", json!({"section": "contract"}))
    }

    /// A target whose state vault is not bound yet (D-G, before the first `opv apply`): the
    /// contract loads, and a command that reads the target's delivery evidence names
    /// `opv apply`.
    pub fn state_vault_missing() -> Case {
        case(
            Scenario::new()
                .config(|c| without_line(c, r#"state_vault_id = "vE2ESTATEFLY00000000000001""#)),
            &["changed", "prod"],
        )
        .mcp("opv_state", json!({"section": "changed", "env": "prod"}))
    }

    pub fn state_vault_too_wide() -> Case {
        case(
            Scenario::new().config(|c| {
                c.replacen(
                    "# A source-only home for a value",
                    "[environments.staging]\ntitle = \"Staging\"\norder = 3\n\
                     boundaries.web = { vault_id = \"vE2EWEBDEV0000000000000001\", item_id = \"iE2EWEBDEV0000000000000001\" }\n\n\
                     [environments.staging.targets.fly]\nfly.app = \"e2e-app-staging\"\n\
                     fly.secret_name = \"E2E__{PRODUCT}__{KEY}\"\n\
                     state_vault_id = \"vE2ESTATEFLY00000000000001\"\nroles = [\"serve\"]\n\n\
                     # A source-only home for a value",
                    1,
                )
                .replace(
                    "[products.web.keys.API_KEY]\nkind = \"secret\"\nenvironments = [\"dev\", \"prod\"]",
                    "[products.web.keys.API_KEY]\nkind = \"secret\"\nenvironments = [\"dev\", \"prod\", \"staging\"]",
                )
            }),
            &["contract"],
        )
        .mcp("opv_state", json!({"section": "contract"}))
    }

    pub fn config_not_editable() -> Case {
        case(
            Scenario::new().config(|c| format!("# generated by hand-tool\n{c}")),
            &["propose", "env", "staging", "--write"],
        )
    }

    pub fn manifest_not_found() -> Case {
        case(
            Scenario::new()
                .manifest_route()
                .var("OPV_PROJECT", "no-such-app"),
            &["contract"],
        )
        // L7: MCP honours OPV_PROJECT as the CLI does.
        .mcp("opv_state", json!({"section": "contract"}))
    }

    pub fn manifest_ambiguous() -> Case {
        case(
            Scenario::new().manifest_route().world(|w| {
                let items = w["op"]["items"].as_array_mut().expect("items");
                let mut copy = items
                    .iter()
                    .find(|i| i["id"] == MANIFEST_ITEM)
                    .expect("manifest")
                    .clone();
                copy["id"] = json!("iE2EMANIFEST00000000000002");
                items.push(copy);
            }),
            &["contract"],
        )
    }

    pub fn item_unusable() -> Case {
        case(
            Scenario::new()
                .without_config()
                .dot_opv(Some(&format!(
                    "account = \"{DEV_ACCOUNT}\"\nproject = \"e2e-app\"\n"
                )))
                .world(|w| {
                    item(w, MANIFEST_ITEM, |i| {
                        i["fields"]
                            .as_array_mut()
                            .expect("fields")
                            .retain(|f| f["id"] != "notesPlain" && f["purpose"] != "NOTES");
                    })
                }),
            &["contract"],
        )
        .mcp("opv_state", json!({"section": "contract"}))
    }

    // §4.2 names and usage

    pub fn not_declared() -> Case {
        case(Scenario::new(), &["ready", "nope"])
            .mcp("opv_state", json!({"section": "ready", "env": "nope"}))
    }

    pub fn key_not_declared() -> Case {
        // OTEL_RESOURCE is declared for prod only.
        case(
            Scenario::new(),
            &["explain", "web/OTEL_RESOURCE", "--env", "dev"],
        )
        .mcp(
            "opv_explain",
            json!({"key": "web/OTEL_RESOURCE", "env": "dev"}),
        )
    }

    pub fn ambiguous() -> Case {
        case(
            Scenario::new(),
            &["explain", "DATABASE_URL", "--env", "prod"],
        )
        .mcp("opv_explain", json!({"key": "DATABASE_URL", "env": "prod"}))
    }

    pub fn choice_required() -> Case {
        case(
            Scenario::new(),
            &["run", "dev", "--preview", "--product", "web"],
        )
        .mcp(
            "opv_state",
            json!({"section": "delivery_preview", "env": "dev", "product": "web"}),
        )
    }

    pub fn nothing_in_scope() -> Case {
        case(Scenario::new(), &["plan", "dev"])
            .mcp("opv_state", json!({"section": "plan", "env": "dev"}))
    }

    pub fn usage() -> Case {
        case(Scenario::new(), &["ready", "dev", "--bogus"])
    }

    pub fn already_declared() -> Case {
        case(
            Scenario::new(),
            &["propose", "target", "prod", "fly", "--fly-app", "x"],
        )
    }

    pub fn config_proposal_invalid() -> Case {
        case(
            Scenario::new(),
            &[
                "propose",
                "key",
                "web/NEW_KEY",
                "--kind",
                "secret",
                "--from",
                "web/NOPE",
            ],
        )
    }

    pub fn source_only() -> Case {
        case(
            Scenario::new(),
            &["run", "dev", "--preview", "--product", "shared"],
        )
        .mcp(
            "opv_state",
            json!({"section": "delivery_preview", "env": "dev", "product": "shared"}),
        )
    }

    // §4.3 sessions and accounts

    pub fn account_ambiguous() -> Case {
        // Both accounts sign in at this address.
        case(
            Scenario::new().dot_opv(Some("account = \"e2e.1password.com\"\n")),
            &["access"],
        )
        .mcp("opv_state", json!({"section": "access"}))
    }

    /// I8: two accounts on the machine and no `.opv`: a person picks (pick_account_at).
    pub fn account_required() -> Case {
        case(
            Scenario::new()
                .without_config()
                .dot_opv(None)
                .git_checkout(),
            &["contract"],
        )
        .mcp("opv_state", json!({"section": "contract"}))
    }

    // §4.5 guards, §4.8 person-only steps, §4.9 plans

    pub fn guard() -> Case {
        // The builder profile allows dev only (O9: it may name no deployed environment).
        case(
            Scenario::new(),
            &[
                "run",
                "prod",
                "--preview",
                "--product",
                "web",
                "--role",
                "serve",
                "--remote",
                "builder",
            ],
        )
        // No MCP half: `opv_state` section `delivery_preview` takes env and product only
        // (design §25.2); a remote profile's preview is the person's `opv run --preview`.
    }

    pub fn needs_terminal() -> Case {
        case(
            Scenario::new(),
            &["access", "prod", "--create", "--github", "e2e-org/e2e-app"],
        )
    }

    pub fn confirm_mismatch() -> Case {
        case(Scenario::new(), &["sync", "prod", "--confirm", "dev"])
    }

    pub fn keys_blocking() -> Case {
        case(
            Scenario::new().world(|w| {
                item(w, WEB_PROD_ITEM, |i| {
                    for f in i["fields"].as_array_mut().expect("fields") {
                        if f["label"] == "API_KEY" {
                            f["value"] = json!("");
                        }
                    }
                })
            }),
            &["sync", "prod", "--confirm", "prod"],
        )
    }

    pub fn values_needed() -> Case {
        case(
            Scenario::new().world(|w| {
                item(w, WEB_PROD_ITEM, |i| {
                    for f in i["fields"].as_array_mut().expect("fields") {
                        if f["label"] == "API_KEY" {
                            f["value"] = json!("");
                        }
                    }
                })
            }),
            &["status", "prod"],
        )
    }

    pub fn plan_changed() -> Case {
        case(
            Scenario::new(),
            &["sync", "prod", "--expect-plan", "deadbeef"],
        )
    }

    /// A dotenv file others can read is refused before it is read.
    pub fn local_file_too_open() -> Case {
        case(
            Scenario::new()
                .file("project/legacy.env", "API_KEY=e2e-test-marker\n")
                .mode("project/legacy.env", 0o644),
            &["import", "prod", "--from", "legacy.env", "--dry-run"],
        )
    }

    /// The Codex configuration folder cannot be made (its parent is read-only).
    pub fn private_dir_failed() -> Case {
        let s = Scenario::new().dir("readonly", 0o500);
        let codex = s.path("readonly/codex");
        case(
            s.var("CODEX_HOME", codex.to_str().expect("utf-8 path")),
            &["mcp", "install", "--client", "codex"],
        )
    }

    pub fn title_lookup() -> Case {
        case(
            Scenario::new().world(|w| {
                let vaults = w["op"]["vaults"].as_array_mut().expect("vaults");
                let first = vaults[0].clone();
                for id in ["vE2EDUPA000000000000000001", "vE2EDUPB000000000000000002"] {
                    let mut v = first.clone();
                    v["id"] = json!(id);
                    v["name"] = json!("e2e-app-shared-dev");
                    vaults.push(v);
                }
            }),
            &[
                "propose",
                "setup",
                "--from-item",
                "dev",
                "--vault",
                "e2e-app-shared-dev",
                "--item",
                "e2e-app · shared · dev values",
            ],
        )
    }

    pub fn input_invalid() -> Case {
        case(
            Scenario::new().dir("project/dir.env", 0o700),
            &["import", "dev", "--from", "dir.env", "--dry-run"],
        )
    }

    pub fn input_unreadable() -> Case {
        case(
            Scenario::new(),
            &["import", "dev", "--from", "missing.env", "--dry-run"],
        )
    }

    // §4.6 outcomes, §4.7 tools, §4.10 delivery

    pub fn unrecognized() -> Case {
        // The recorded 404 of a listing in a GitHub environment, while the repository's
        // environments read still lists that environment: opv cannot tell why (X13).
        case(
            Scenario::new()
                .faults("[[fault]]\nprogram = \"gh\"\ncall = \"secret list\"\nkind = \"not_found\"\n")
                .world(|w| {
                    w["github"]["repos"]["e2e-org/e2e-app"]["environments"]["production"]
                        ["listed_after_not_found"] = Value::Bool(true);
                }),
            &["plan", "prod", "--target", "gh"],
        )
    }

    pub fn partial() -> Case {
        // fly and gh are written, then Kubernetes refuses the first Secret (403).
        case(
            Scenario::new().faults(&fault("kubectl", "apply", "forbidden")),
            &["sync", "prod", "--confirm", "prod"],
        )
    }

    pub fn tool_missing() -> Case {
        // A tool_missing fault with no call: op is not installed.
        case(
            Scenario::new().faults("[[fault]]\nprogram = \"op\"\nkind = \"tool_missing\"\n"),
            &["ready", "dev"],
        )
        .mcp("opv_state", json!({"section": "ready", "env": "dev"}))
    }

    pub fn tool_unusable() -> Case {
        // flyctl is a file that cannot be run.
        case(
            Scenario::new().after_install(|s| {
                for t in ["flyctl", "fly"] {
                    let p = s.path("bin").join(t);
                    let _ = std::fs::remove_file(&p);
                    std::fs::write(&p, "").expect("flyctl");
                }
            }),
            &["plan", "prod", "--target", "fly"],
        )
        .mcp(
            "opv_state",
            json!({"section": "plan", "env": "prod", "target": "fly"}),
        )
    }

    pub fn owner_setup_required() -> Case {
        // The repository has no `production` environment: only its owner makes one.
        case(
            Scenario::new().world(|w| {
                w["github"]["repos"]["e2e-org/e2e-app"]["environments"]
                    .as_object_mut()
                    .expect("environments")
                    .remove("production");
            }),
            &["plan", "prod", "--target", "gh"],
        )
        .mcp(
            "opv_state",
            json!({"section": "plan", "env": "prod", "target": "gh"}),
        )
    }

    pub fn write_outcome_unknown() -> Case {
        case(
            Scenario::new().faults(&fault("flyctl", "secrets import", "applied_but_reply_lost")),
            &["sync", "prod", "--confirm", "prod", "--target", "fly"],
        )
    }

    pub fn target_refused() -> Case {
        // K-R4: the team's own projected volume names a ConfigMap the namespace does not
        // hold, so the new pod waits in `ContainerCreating` and the rollout is still in
        // progress when the wait ends.
        case(
            Scenario::new().world(|w| {
                let spec = pod_spec(w);
                spec["volumes"] = json!([{"name": "settings", "projected": {"sources": [
                    {"configMap": {"name": "e2e-app-settings"}}]}}]);
                spec["containers"][0]["volumeMounts"] =
                    json!([{"name": "settings", "mountPath": "/etc/e2e-app", "readOnly": true}]);
            }),
            &[
                "sync",
                "prod",
                "--confirm",
                "prod",
                "--target",
                "k8s",
                "--product",
                "web",
                "--deploy",
                "--timeout",
                "5",
            ],
        )
    }

    /// J7: a value Fly's import parser would mangle is a blocking row of the plan, so
    /// `sync` refuses with `keys_blocking` before the write-side guard could fire.
    pub fn fly_value_rule_refused() -> Case {
        case(
            Scenario::new().world(|w| {
                web_prod_api_key(w, |f| f["value"] = json!("sk-a\"#e2e-marker"));
            }),
            &["sync", "prod", "--confirm", "prod", "--target", "fly"],
        )
    }

    /// J7: a value larger than a GitHub secret can hold is a blocking row of the plan, so
    /// `sync` refuses with `keys_blocking` before the write-side guard could fire.
    pub fn github_value_rule_refused() -> Case {
        case(
            Scenario::new().world(|w| {
                web_prod_api_key(w, |f| f["value"] = json!("x".repeat(50_000)));
            }),
            &["sync", "prod", "--confirm", "prod", "--target", "gh"],
        )
    }

    /// J7: a value an environment variable cannot hold is a blocking row of the plan, so
    /// `sync` refuses with `keys_blocking` before the write-side guard could fire.
    pub fn kubernetes_value_rule_refused() -> Case {
        case(
            Scenario::new().world(|w| {
                web_prod_api_key(w, |f| f["value"] = json!("x".repeat(1024 * 1024 + 1)));
            }),
            &["sync", "prod", "--confirm", "prod", "--target", "k8s"],
        )
    }

    /// The e2e Deployment's pod spec in `w` (tests/e2e/app/world.json).
    fn pod_spec(w: &mut Value) -> &mut Value {
        w.pointer_mut(
            "/kubernetes/contexts/e2e-cluster/namespaces/e2e-prod/deployments/0/spec/template/spec",
        )
        .expect("the e2e Deployment")
    }

    const K8S_SYNC: &[&str] = &[
        "sync",
        "prod",
        "--confirm",
        "prod",
        "--target",
        "k8s",
        "--deploy",
    ];

    /// Design §6.6: no `fsGroup` and a non-root user, so the mounted 0440 files would be
    /// unreadable; refused before any write.
    pub fn k8s_mount_unreadable() -> Case {
        case(
            Scenario::new().world(|w| {
                pod_spec(w)["securityContext"] = json!({"runAsUser": 10001, "runAsGroup": 10001});
            }),
            K8S_SYNC,
        )
    }

    /// Design §6.8: another volume is mounted above the files' directory.
    pub fn k8s_mount_path_in_use() -> Case {
        case(
            Scenario::new().world(|w| {
                let spec = pod_spec(w);
                spec["volumes"] = json!([{"name": "tls", "secret": {"secretName": "e2e-app-tls"}}]);
                spec["containers"][0]["volumeMounts"] =
                    json!([{"name": "tls", "mountPath": "/run/secrets", "readOnly": true}]);
            }),
            K8S_SYNC,
        )
    }

    /// K-R2: an `opv-files-` volume left at the files' directory, so the replace carries two
    /// mounts at one path and the API server refuses it (422).
    pub fn k8s_volume_refused() -> Case {
        case(
            Scenario::new().world(|w| {
                let spec = pod_spec(w);
                spec["volumes"] = json!([{"name": "opv-files-legacy", "emptyDir": {}}]);
                spec["containers"][0]["volumeMounts"] =
                    json!([{"name": "opv-files-legacy", "mountPath": "/run/secrets/web"}]);
            }),
            K8S_SYNC,
        )
    }

    /// Design §6.5: no `delete configmaps` on a `configmap` target; refused before any write.
    pub fn k8s_configmap_right_missing() -> Case {
        case(
            Scenario::new().world(|w| {
                w["kubernetes"]["contexts"]["e2e-cluster"]["denied"] = json!(["delete configmaps"]);
            }),
            K8S_SYNC,
        )
    }

    pub fn budget_spent() -> Case {
        // fly is written, then op hangs past the run's 3-second budget.
        case(
            Scenario::new().faults(
                "[[fault]]\nprogram = \"op\"\ncall = \"whoami\"\nkind = \"timeout\"\nseconds = 5\n",
            ),
            &[
                "sync",
                "prod",
                "--confirm",
                "prod",
                "--target",
                "fly",
                "--target",
                "gh",
                "--timeout",
                "3",
            ],
        )
    }

    pub fn interrupted() -> Case {
        let mut s = Scenario::new().faults(
            "[[fault]]\nprogram = \"op\"\ncall = \"item get\"\nkind = \"timeout\"\nseconds = 30\n",
        );
        s.interrupt = Some(("item get", "TERM"));
        case(s, &["config", "export", "prod"])
    }

    /// The edit answers with garbled output and is not applied (opv-sim answers a malformed
    /// reply without saving the world).
    fn web_dev_api_key(w: &mut Value, edit: fn(&mut Value)) {
        item(w, "iE2EWEBDEV0000000000000001", |i| {
            for f in i["fields"].as_array_mut().expect("fields") {
                if f["label"] == "API_KEY" {
                    edit(f);
                }
            }
        });
    }

    /// The production item's API_KEY, edited (the value a target's own rules judge).
    fn web_prod_api_key(w: &mut Value, edit: impl Fn(&mut Value)) {
        item(w, WEB_PROD_ITEM, |i| {
            for f in i["fields"].as_array_mut().expect("fields") {
                if f["label"] == "API_KEY" {
                    edit(f);
                }
            }
        });
    }

    pub fn read_back_missing() -> Case {
        case(
            Scenario::new()
                .faults(&fault("op", "item edit", "malformed_output"))
                .world(|w| web_dev_api_key(w, |f| f["value"] = json!("")))
                .file(
                    "project/.env.dev",
                    "API_KEY=test-marker-e2e-adopted-value\n",
                )
                .mode("project/.env.dev", 0o600),
            &["import", "dev", "--from", ".env.dev"],
        )
    }

    pub fn local_io() -> Case {
        // A folder where `.opv` belongs: opv writes only a plain file there (a mode would not
        // stop a root builder).
        case(
            Scenario::new().dot_opv(None).dir("project/.opv", 0o700),
            &["account", "use", "AE2EOPSACCOUNT000000000002"],
        )
    }

    pub fn delivery_unverified() -> Case {
        case(
            Scenario::new(),
            &["delivery", "verify", "prod", "--target", "fly"],
        )
    }

    pub fn in_no_account_on_the_machine() -> Case {
        // #153a: every account on the machine is asked; none holds the vault.
        case(
            Scenario::new().faults(&fault(
                "op",
                "vault get vE2ESHAREDDEV00000000000001",
                "not_found",
            )),
            &["propose", "structure"],
        )
    }

    pub fn signed_out_access() -> Case {
        case(
            Scenario::new().faults(&fault("op", "whoami", "signed_out")),
            &["access"],
        )
        .mcp("opv_state", json!({"section": "access"}))
    }

    // MCP parity: `opv_state` section `changed`; the target options of `opv target add` (its MCP tool,
    // `opv_declare_target`, was removed in 0.12.0: a target is proposed with `opv_propose`).

    /// `opv changed` of an undeclared environment: the same refusal over MCP.
    pub fn changed_not_declared() -> Case {
        case(Scenario::new(), &["changed", "nope"])
            .mcp("opv_state", json!({"section": "changed", "env": "nope"}))
    }

    /// `op item list` answered as signed out (recording 07): the same sign-in refusal over
    /// MCP, naming the same `opv changed` re-run.
    pub fn changed_signed_out() -> Case {
        case(
            Scenario::new().faults(&fault("op", "item list", "signed_out")),
            &["changed", "prod"],
        )
        .mcp("opv_state", json!({"section": "changed", "env": "prod"}))
    }

    // 0.12.0 inspect commands (row cli-sweep-b); no MCP tool of theirs exists yet.

    /// `opv inventory` of an undeclared environment: refused before any item is read.
    pub fn inventory_not_declared() -> Case {
        case(Scenario::new(), &["inventory", "--env", "nope"])
    }

    /// `opv next` when 1Password refuses the vault user list as signed out: the read stops
    /// with the sign-in error, never a guessed capability.
    pub fn next_signed_out() -> Case {
        case(
            Scenario::new().faults(&fault("op", "vault user list", "signed_out")),
            &["next"],
        )
    }

    /// A relative `kubernetes.secrets_dir`: refused by the loader before anything is written.
    pub fn declare_target_secrets_dir_invalid() -> Case {
        case(
            Scenario::new(),
            &[
                "propose",
                "target",
                "prod",
                "cluster",
                "--kubernetes-context",
                "e2e-cluster",
                "--kubernetes-deployment",
                "e2e-app",
                "--kubernetes-namespace",
                "e2e-prod",
                "--kubernetes-secrets-dir",
                "run/secrets",
                "--role",
                "serve",
            ],
        )
    }

    // §25.1 flows: the person-only commands' refusals, the inspect gates and the intent's
    // screen. `apply` and `set` need a person at a terminal; the harness gives opv no
    // terminal (stdin is null), so it pins both refusals: no terminal, and an assistant.

    pub fn apply_needs_terminal() -> Case {
        case(Scenario::new().marked(), &["apply"])
    }

    pub fn apply_person_only() -> Case {
        case(Scenario::new().marked().var("OPV_AGENT", "1"), &["apply"])
    }

    pub fn set_needs_terminal() -> Case {
        case(
            Scenario::new().marked(),
            &["set", "web/API_KEY", "--env", "dev"],
        )
    }

    pub fn set_person_only() -> Case {
        case(
            Scenario::new().marked().var("OPV_AGENT", "1"),
            &["set", "web/API_KEY", "--env", "dev"],
        )
    }

    /// The code reads a name the contract does not declare: the needs gate fails.
    pub fn needs_undeclared() -> Case {
        case(
            Scenario::new()
                .marked()
                .git_checkout()
                .tracked("src/main.rs", READS_UNDECLARED),
            &["needs", "--gate"],
        )
    }

    /// #179: a retiring key the code at `HEAD` still reads: the retirement's prune
    /// (`opv sync <env> --prune --retire`) refuses before any write, naming the file.
    pub fn retire_still_read() -> Case {
        case(
            Scenario::new()
                .marked()
                .config(|t| {
                    t.replacen(
                        "[products.web.keys.API_KEY]\n",
                        "[products.web.keys.API_KEY]\nlifecycle = \"retiring\"\n",
                        1,
                    )
                })
                .git_checkout()
                .tracked("src/main.rs", READS_UNDECLARED)
                .committed(),
            &["sync", "prod", "--prune", "--retire", "--confirm", "prod"],
        )
    }

    /// A committed contract copy that is not the current contract document.
    pub fn contract_stale() -> Case {
        case(
            Scenario::new()
                .marked()
                .file("project/contract.json", "{\"components\": []}\n"),
            &["contract", "--check", "contract.json"],
        )
    }

    /// Free text of an intent document carrying what looks like a value (a PEM header): the
    /// CLI's `--intent` and `opv_propose` refuse the same document, naming the field only.
    pub fn value_in_text_field() -> Case {
        case(
            Scenario::new()
                .marked()
                .file("project/intent.json", &value_intent().to_string()),
            &["propose", "--intent", "intent.json"],
        )
        .mcp("opv_propose", value_intent())
    }
}

/// A Rust file reading one declared name (`API_KEY`) and one the contract does not declare.
const READS_UNDECLARED: &str = "fn main() {\n    let _ = std::env::var(\"API_KEY\");\n    \
                                let _ = std::env::var(\"NEW_THING\");\n}\n";

/// A key intent whose guidance carries a PEM header and a value marker.
fn value_intent() -> Value {
    json!({"kind": "key", "product": "web", "key": "NEW_KEY", "field_kind": "secret",
           "environments": ["dev"],
           "guidance": format!("paste -----BEGIN {MARK}VALUE-guidance here")})
}

/// A scenario whose command has no `--json`: its variant is the one declared, pinned by the
/// text snapshot.
mod text_cases {
    use super::*;

    /// `target credentials --create` records the minted item in a secrets.toml, which a
    /// manifest project does not have: refused before anything is minted (02.01).
    pub fn config_source_mismatch() -> Case {
        case(
            Scenario::new().manifest_route(),
            &[
                "target",
                "credentials",
                "prod",
                "--target",
                "fly",
                "--create",
            ],
        )
    }

    pub fn needs_own_session() -> Case {
        let s = Scenario::new();
        let world: Value = serde_json::from_str(
            &std::fs::read_to_string(s.path("world/world.json")).expect("world"),
        )
        .expect("world");
        let token = world["op"]["service_account_tokens"][0]["token"]
            .as_str()
            .or_else(|| world["op"]["service_account_tokens"][0].as_str())
            .expect("a service-account token marker")
            .to_string();
        case(
            s.var("OP_SERVICE_ACCOUNT_TOKEN", &token),
            &[
                "config",
                "import",
                "--vault",
                "e2e-manifest",
                "--project",
                "e2e-other",
            ],
        )
    }

    pub fn create_outcome_unknown() -> Case {
        case(
            Scenario::new()
                .var("OP_ACCOUNT", DEV_ACCOUNT)
                .faults(&fault("op", "item create", "applied_but_reply_lost")),
            &[
                "config",
                "import",
                "--vault",
                "e2e-manifest",
                "--project",
                "e2e-other",
            ],
        )
    }

    pub fn copies_differ() -> Case {
        case(
            Scenario::new()
                .var("OPV_PROJECT", "e2e-app")
                .var("OP_ACCOUNT", DEV_ACCOUNT)
                .config(|c| {
                    c.replacen(
                        "guidance = \"the service's own API key\"",
                        "guidance = \"changed\"",
                        1,
                    )
                }),
            &["config", "check", "--file", "secrets.toml"],
        )
    }

    /// #178: a file project whose generator wrote a configuration that differs from the
    /// committed `secrets.toml` (one key's guidance changed): the check names both files and
    /// leaves the direction to the person.
    pub fn regenerated_file_differs() -> Case {
        let committed = std::fs::read_to_string(Path::new(ROOT).join("tests/e2e/app/secrets.toml"))
            .expect("app contract");
        let regenerated = committed.replacen(
            "guidance = \"the service's own API key\"",
            "guidance = \"regenerated\"",
            1,
        );
        assert_ne!(regenerated, committed, "the regenerated file must differ");
        case(
            Scenario::new()
                .marked()
                .file("project/generated/secrets.toml", &regenerated),
            &[
                "--config",
                "secrets.toml",
                "config",
                "check",
                "--file",
                "generated/secrets.toml",
            ],
        )
    }

    pub fn manifest_exists() -> Case {
        case(
            Scenario::new().var("OP_ACCOUNT", DEV_ACCOUNT),
            &[
                "config",
                "import",
                "--vault",
                "e2e-manifest",
                "--project",
                "e2e-app",
            ],
        )
    }

    pub fn personal_not_set_up() -> Case {
        case(
            Scenario::new().world(|w| {
                w["op"]["items"]
                    .as_array_mut()
                    .expect("items")
                    .retain(|i| i["id"] != "iE2EPERSONAL00000000000001");
            }),
            &[
                "run",
                "dev",
                "--product",
                "web",
                "--role",
                "serve",
                "--",
                "true",
            ],
        )
    }

    /// The `opv run dev --product web --role serve -- <command>` that starts `local-delivery`
    /// hands it in `OPV_RUN_OUTER`, so its errors' steps name that run (X25), as in use.
    fn run_outer() -> String {
        json!({
            "env": "dev", "product": "web", "profile": null, "command": ["run"],
            "args": ["dev", "--product", "web", "--role", "serve"], "has_child": true
        })
        .to_string()
    }

    pub fn child_start_failed() -> Case {
        case(
            Scenario::new()
                .var("A", "test-marker-e2e-local-delivery")
                .var("OPV_RUN_OUTER", &run_outer()),
            &["local-delivery", "--key", "A", "--", "/nonexistent/cmd"],
        )
    }

    /// The plan `opv run dev --product web --role serve --remote builder`
    /// hands `remote-send` (the step after `op run`, which opv-sim does not model).
    fn remote_plan(workdir: &str, command: &[&str]) -> String {
        json!({
            "profile": "builder", "host": "builder.example.test", "port": 22, "user": "deploy",
            "host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIe2eMarkerHostKeyNotARealKey000000",
            "identity_file": null, "opv": "/usr/local/bin/opv",
            "header": {
                "keys": ["API_KEY", "DATABASE_URL", "LOG_LEVEL", "SESSION_SECRET"], "files": [],
                "dir_env": "WEB_SECRETS_DIR", "workdir": workdir, "command": command,
                "outer": {"env": "dev", "product": "web", "profile": "builder",
                          "command": ["run"],
                          "args": ["dev", "--product", "web", "--role", "serve", "--remote",
                                   "builder"],
                          "has_child": false}}
        })
        .to_string()
    }

    fn remote_send(s: Scenario, plan: String) -> Case {
        let s = s
            .ssh_in_world()
            .var("API_KEY", "test-marker-e2e-remote")
            .var("DATABASE_URL", "test-marker-e2e-remote")
            .var("LOG_LEVEL", "test-marker-e2e-remote")
            .var("SESSION_SECRET", "test-marker-e2e-remote");
        Case {
            scenario: s,
            args: vec!["remote-send".into(), "--plan".into(), plan],
            mcp: None,
        }
    }

    pub fn remote_unreachable() -> Case {
        remote_send(
            Scenario::new().faults("[[fault]]\nprogram = \"ssh\"\nkind = \"connection_refused\"\n"),
            remote_plan(
                "/srv/e2e-app",
                &[
                    "/usr/local/bin/opv",
                    "run",
                    "--env",
                    "dev",
                    "--product",
                    "web",
                ],
            ),
        )
    }

    pub fn remote_disconnected() -> Case {
        remote_send(
            Scenario::new()
                .faults("[[fault]]\nprogram = \"ssh\"\nkind = \"drop_mid_run\"\n")
                .world(|w| {
                    w["hosts"]["builder.example.test"]["commands"]["/usr/local/bin/opv"] =
                        json!(OPV);
                }),
            remote_plan("/tmp", &["sleep", "5"]),
        )
    }

    pub fn ram_dir_unavailable() -> Case {
        case(
            Scenario::new()
                .var("TLS_CERTIFICATE", "test-marker-e2e-local-delivery")
                .var("OPV_RUN_OUTER", &run_outer()),
            &[
                "local-delivery",
                "--key",
                "TLS_CERTIFICATE",
                "--file",
                "TLS_CERTIFICATE=tls/certificate",
                "--declared-only",
                "--dir-env",
                "WEB_SECRETS_DIR",
                "--",
                "true",
            ],
        )
    }

    /// The committed bindings are not the ones the last `opv apply` recorded (D-G): the
    /// apply record's digest differs (the record is `secrets.applied.json`, beside the
    /// bindings).
    pub fn bindings_unapplied() -> Case {
        case(
            Scenario::new()
                .marked()
                .dot_opv(None)
                .var("OPV_PROJECT", "e2e-app")
                .var("OP_ACCOUNT", DEV_ACCOUNT)
                .file(
                    "project/secrets.applied.json",
                    "{\"plan_id\":\"sp-0000000000000000\",\"contract_digest\":\"00\",\
                     \"bindings_digest\":\"00\"}\n",
                ),
            &["config", "check", "--file", "secrets.toml"],
        )
    }
}

/// The flow documents of §25.1 and §25.2, each a successful run (or the MCP tool's own
/// refusal): the text run, the `--json` run and, where a tool exists, the MCP answer. Every
/// value in their world and dotenv files is an `S7MARKER` marker (the canary gate).
mod flow_cases {
    use super::*;

    fn flow() -> Scenario {
        Scenario::new().marked()
    }

    pub fn flow_propose_key() -> Case {
        case(
            flow(),
            &[
                "propose",
                "key",
                "web/NEW_KEY",
                "--kind",
                "secret",
                "--env",
                "dev",
            ],
        )
        .mcp(
            "opv_propose",
            json!({"kind": "key", "product": "web", "key": "NEW_KEY",
                   "field_kind": "secret", "environments": ["dev"]}),
        )
    }

    pub fn flow_propose_env() -> Case {
        case(flow(), &["propose", "env", "staging", "--tier", "shared"]).mcp(
            "opv_propose",
            json!({"kind": "env", "env": "staging", "tier": "shared"}),
        )
    }

    pub fn flow_propose_target() -> Case {
        case(
            flow(),
            &[
                "propose",
                "target",
                "prod",
                "fly2",
                "--fly-app",
                "e2e-app-prod2",
                "--role",
                "serve",
            ],
        )
        .mcp(
            "opv_propose",
            json!({"kind": "target", "env": "prod", "name": "fly2", "role": "serve",
                   "options": {"fly-app": "e2e-app-prod2"}}),
        )
    }

    pub fn flow_propose_retire() -> Case {
        case(flow(), &["propose", "retire", "web/MIGRATION_TOKEN"]).mcp(
            "opv_propose",
            json!({"kind": "retire", "product": "web", "key": "MIGRATION_TOKEN"}),
        )
    }

    /// First setup from a `.env`'s names, in a project with no contract yet.
    pub fn flow_propose_setup() -> Case {
        case(
            flow()
                .without_config()
                .dotenv("local.env", &["API_KEY", "LOG_LEVEL", "NEW_THING"]),
            &["propose", "setup", "--names-from", "local.env"],
        )
        .mcp(
            "opv_propose",
            json!({"kind": "setup", "names_from": "local.env"}),
        )
    }

    pub fn flow_propose_structure() -> Case {
        case(flow(), &["propose", "structure"]).mcp("opv_propose", json!({"kind": "structure"}))
    }

    /// A rule-backed key (a byte length) with no field yet: the structure adds it and
    /// generates its value.
    pub fn flow_propose_generate() -> Case {
        case(
            flow().config(|c| {
                format!(
                    "{c}\n[products.web.keys.SIGNING_KEY]\nkind = \"secret\"\n\
                     environments = [\"dev\"]\nrules = {{ base64_bytes = 32 }}\n"
                )
            }),
            &["propose", "generate", "dev", "web/SIGNING_KEY"],
        )
        .mcp(
            "opv_propose",
            json!({"kind": "generate", "env": "dev", "keys": ["web/SIGNING_KEY"]}),
        )
    }

    /// `--intent` takes the document `opv_propose` takes.
    pub fn flow_propose_intent() -> Case {
        let intent = json!({"kind": "env", "env": "staging", "tier": "shared"});
        case(
            flow().file("project/intent.json", &intent.to_string()),
            &["propose", "--intent", "intent.json"],
        )
        .mcp("opv_propose", intent)
    }

    /// A person's import into the shared dev environment: one key is empty and is imported,
    /// one is already set, one fails its rule, one is not declared. `opv_import_local`
    /// refuses the same environment: its tier is not `local`.
    pub fn flow_import() -> Case {
        case(
            flow()
                .world(|w| {
                    item(w, WEB_DEV_ITEM, |i| {
                        for f in i["fields"].as_array_mut().expect("fields") {
                            if f["label"] == "SESSION_SECRET" {
                                f["value"] = json!("");
                            }
                        }
                    })
                })
                .dotenv(
                    "local.env",
                    &["API_KEY", "LOG_LEVEL", "SESSION_SECRET", "NEW_THING"],
                ),
            &["import", "dev", "--from", "local.env"],
        )
        .mcp(
            "opv_import_local",
            json!({"env": "dev", "file": "local.env"}),
        )
    }

    /// The same import into a `local`-tier dev environment, where `opv_import_local` writes
    /// (and tags the item `assistant_imported`).
    pub fn flow_import_local() -> Case {
        case(
            flow()
                .config(|c| {
                    c.replacen(
                        "title = \"Local development\"",
                        "title = \"Local development\"\ntier = \"local\"",
                        1,
                    )
                })
                .world(|w| {
                    item(w, WEB_DEV_ITEM, |i| {
                        for f in i["fields"].as_array_mut().expect("fields") {
                            if f["label"] == "SESSION_SECRET" {
                                f["value"] = json!("");
                            }
                        }
                    })
                })
                .dotenv("local.env", &["API_KEY", "SESSION_SECRET"]),
            &["import", "dev", "--from", "local.env"],
        )
        .mcp(
            "opv_import_local",
            json!({"env": "dev", "file": "local.env"}),
        )
    }

    /// Code ↔ contract: one declared name read, one undeclared, the rest unobserved.
    pub fn flow_needs() -> Case {
        case(
            flow()
                .git_checkout()
                .tracked("src/main.rs", READS_UNDECLARED),
            &["needs"],
        )
    }

    pub fn flow_contract() -> Case {
        case(flow(), &["contract", "--env", "dev", "--component", "web"])
    }

    /// A key declared in one environment, so neither form needs `--env` (the tool's input
    /// is a key or a plan id only).
    pub fn flow_explain() -> Case {
        case(flow(), &["explain", "web/PERSONAL_LLM_KEY"])
            .mcp("opv_explain", json!({"key": "web/PERSONAL_LLM_KEY"}))
    }
}

/// The core documents of §25.1 (`inventory`, `next`, `ready --gate`, `doctor`'s R9 rows,
/// `access`), each over one world where this session's own user (`UE2EDEVUSER…`, the
/// `whoami` user) is a member of the vaults it reads, so op answers `vault user list` with the
/// owner's writer recording (s23):
///
/// - web prod: the session is the only writer (one writer: `single_writer`; a production
///   vault this session can write: doctor's R9 warning);
/// - shared prod: the session is not a member (capability `none`: its cells are
///   `unreadable`);
/// - shared dev and web dev: the session and the ops user write;
/// - web dev's `SESSION_SECRET` is empty (`empty`) and its `LOG_LEVEL` is `changeme`
///   (`placeholder`); its `API_KEY` field is removed, so that key is `absent` there; every
///   other value is an `S7MARKER` marker (`set`). `web/DATABASE_URL` (`from`) reads its
///   source `shared/DATABASE_URL`; `web/PERSONAL_LLM_KEY` is read from the personal item;
///   a key an explicit `environments` list leaves out has no cell there.
///
/// `next`'s MCP half is `opv_next` (row mcp-propose).
mod core_cases {
    use super::*;

    const ME: &str = "UE2EDEVUSER000000000000001";
    const OPS: &str = "UE2EOPSUSER000000000000002";

    fn member(id: &str, name: &str, email: &str) -> Value {
        json!({"id": id, "name": name, "email": email})
    }

    fn core() -> Scenario {
        Scenario::new().marked().world(|w| {
            let me = member(ME, "E2E Dev", "dev@example.com");
            let ops = member(OPS, "E2E Ops", "ops@example.test");
            for v in w["op"]["vaults"].as_array_mut().expect("vaults") {
                let users = match v["id"].as_str().unwrap_or_default() {
                    "vE2EWEBPROD000000000000001" => json!([me]),
                    "vE2ESHAREDPROD0000000000001" => json!([ops]),
                    "vE2ESHAREDDEV00000000000001"
                    | "vE2EWEBDEV0000000000000001"
                    | "vE2EPRIVATE000000000000001" => json!([me, ops]),
                    _ => continue,
                };
                v["users"] = users;
            }
            item(w, WEB_DEV_ITEM, |i| {
                let fields = i["fields"].as_array_mut().expect("fields");
                fields.retain(|f| f["label"] != "API_KEY");
                for f in fields {
                    match f["label"].as_str() {
                        Some("SESSION_SECRET") => f["value"] = json!(""),
                        Some("LOG_LEVEL") => f["value"] = json!("changeme"),
                        _ => {}
                    }
                }
            })
        })
    }

    pub fn core_inventory() -> Case {
        case(core(), &["inventory"])
    }

    /// The MCP half is `opv_next`, the same document as `opv next --json`.
    pub fn core_next() -> Case {
        case(core(), &["next"]).mcp("opv_next", json!({}))
    }

    /// The gate fails on dev's empty and placeholder values (`gate_failed`).
    pub fn core_ready_gate() -> Case {
        case(core(), &["ready", "--gate"])
    }

    /// R9: this session can write the production vault web prod, and the shell is signed in
    /// to the production targets' platforms.
    pub fn core_doctor() -> Case {
        case(core(), &["doctor", "--env", "prod"])
    }

    pub fn core_access() -> Case {
        case(core(), &["access"])
    }
}

// --- one scenario's snapshot ----------------------------------------------------------------

/// The scenario's runs, as its snapshot: text, `--json` (unless `text_only`), MCP.
fn record(name: &str, build: fn() -> Case, text_only: bool) -> String {
    let c = build();
    let mut s = format!("# {name}: opv {}\n", c.args.join(" "));
    let text = c.scenario.opv(&c.args);
    let mut runs = vec![("text", text)];
    if !text_only {
        let c = build();
        let mut args = c.args.clone();
        let at = args.iter().position(|a| a == "--").unwrap_or(args.len());
        args.insert(at, "--json".into());
        runs.push(("json", c.scenario.opv(&args)));
    }
    for (mode, r) in runs {
        s.push_str(&format!(
            "\n## {mode} exit: {}\n## {mode} stdout\n{}\n## {mode} stderr\n{}",
            r.code.map_or("killed".into(), |c| c.to_string()),
            r.stdout,
            r.stderr
        ));
    }
    if let Some((tool, args)) = c.mcp {
        let c = build();
        let answer = c.scenario.mcp(tool, &args);
        s.push_str(&format!("\n## mcp {tool} {args}\n{answer}\n"));
    }
    s
}

fn snapshot_path(name: &str) -> PathBuf {
    scenario_snapshots().join(format!("{name}.snap"))
}

/// Scenarios whose messages are platform advice by design (how to install op, where an
/// in-memory folder lives, the Linux-only core-dump check): their committed snapshot is the Linux one, so other hosts skip
/// the comparison. The variant still counts as reached from the committed snapshot.
const LINUX_WORDED: [&str; 3] = ["core_doctor", "ram_dir_unavailable", "tool_missing"];

fn snapshot_test(name: &str, build: fn() -> Case, text_only: bool) {
    if !cfg!(target_os = "linux") && LINUX_WORDED.contains(&name) {
        return;
    }
    if name == "private_dir_failed" && skip_under_root(effective_uid()) {
        eprintln!(
            "skipped: private_dir_failed needs a non-root user: root ignores directory modes"
        );
        return;
    }
    let got = record(name, build, text_only);
    let path = snapshot_path(name);
    if updating() {
        std::fs::create_dir_all(scenario_snapshots()).expect("snapshots dir");
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

/// The sections of a snapshot, by their `## ` heading.
fn sections(snap: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut head: Option<String> = None;
    let mut body = String::new();
    for line in snap.lines() {
        if let Some(h) = line.strip_prefix("## ") {
            if let Some(prev) = head.take() {
                out.insert(prev, std::mem::take(&mut body));
            }
            head = Some(h.to_string());
        } else if head.is_some() {
            body.push_str(line);
            body.push('\n');
        }
    }
    if let Some(prev) = head {
        out.insert(prev, body);
    }
    out
}

fn one_document(s: &str) -> Option<Value> {
    let mut docs = serde_json::Deserializer::from_str(s).into_iter::<Value>();
    let first = docs.next()?.ok()?;
    docs.next().is_none().then_some(first)
}

/// The `--json` document of a snapshot.
fn json_document(snap: &str) -> Option<Value> {
    one_document(sections(snap).get("json stdout")?)
}

/// The MCP answer of a scenario snapshot.
fn mcp_answer(snap: &str) -> Option<Value> {
    let s = sections(snap);
    let (_, body) = s.iter().find(|(h, _)| h.starts_with("mcp "))?;
    one_document(body)
}

fn committed(name: &str) -> String {
    std::fs::read_to_string(snapshot_path(name)).unwrap_or_default()
}

/// The variant of the committed scenario's `--json` error.
fn variant_test(name: &str, want: &str) {
    let got = json_document(&committed(name))
        .and_then(|d| d.get("error").cloned())
        .and_then(|e| identify(&e));
    assert_eq!(got.as_deref(), Some(want), "{name}");
}

/// Gate 3: every MCP tool's whole answer, a failure included, is the CLI's whole `--json`
/// document (design §25.2: the same document as the command).
fn mcp_equals_cli_test(name: &str) {
    let snap = committed(name);
    let cli = json_document(&snap);
    let mcp = mcp_answer(&snap);
    assert_eq!(
        mcp, cli,
        "{name}: the MCP answer is not the CLI's --json document"
    );
}

macro_rules! scenarios {
    (
        json: [$($j:ident => $jv:ident),* $(,)?],
        text: [$($t:ident => $tv:ident),* $(,)?],
        mcp: [$($m:ident),* $(,)?],
        flows: [$($f:ident),* $(,)?],
        core: [$($c:ident),* $(,)?] $(,)?
    ) => {
        /// Every scenario: its name, the variant it reaches, whether it has `--json`.
        const SCENARIOS: &[(&str, &str, bool)] = &[
            $((stringify!($j), stringify!($jv), true),)*
            $((stringify!($t), stringify!($tv), false),)*
        ];
        /// The scenarios an MCP tool also reaches.
        const MCP_SCENARIOS: &[&str] = &[$(stringify!($m)),*];
        /// The flow documents (§25.1, §25.2): a text, `--json` and MCP run each, no variant.
        const FLOWS: &[&str] = &[$(stringify!($f)),*];
        mod flows {
            $(
                #[test]
                fn $f() {
                    super::snapshot_test(stringify!($f), super::flow_cases::$f, false);
                }
            )*
        }
        /// The core documents (§25.1): a text and `--json` run each.
        const CORE: &[&str] = &[$(stringify!($c)),*];
        mod core {
            $(
                #[test]
                fn $c() {
                    super::snapshot_test(stringify!($c), super::core_cases::$c, false);
                }
            )*
        }
        mod reach {
            $(
                mod $j {
                    #[test]
                    fn matches_its_snapshot() {
                        super::super::snapshot_test(
                            stringify!($j),
                            super::super::cases::$j,
                            false,
                        );
                    }
                    #[test]
                    fn reaches_its_variant() {
                        super::super::variant_test(stringify!($j), stringify!($jv));
                    }
                }
            )*
            $(
                mod $t {
                    #[test]
                    fn matches_its_snapshot() {
                        super::super::snapshot_test(
                            stringify!($t),
                            super::super::text_cases::$t,
                            true,
                        );
                    }
                }
            )*
        }
        mod mcp_equals_cli {
            $(
                #[test]
                fn $m() {
                    super::mcp_equals_cli_test(stringify!($m));
                }
            )*
        }
    };
}

scenarios! {
    json: [
        config_not_found => ConfigNotFound,
        config_unreadable => ConfigUnreadable,
        config_invalid => ConfigInvalid,
        boundary_missing => BoundaryMissing,
        state_vault_missing => StateVaultMissing,
        state_vault_too_wide => StateVaultTooWide,
        config_not_editable => ConfigNotEditable,
        manifest_not_found => ManifestNotFound,
        manifest_ambiguous => ManifestAmbiguous,
        item_unusable => ItemUnusable,
        not_declared => NotDeclared,
        key_not_declared => KeyNotDeclared,
        ambiguous => Ambiguous,
        choice_required => ChoiceRequired,
        nothing_in_scope => NothingInScope,
        usage => Usage,
        already_declared => AlreadyDeclared,
        config_proposal_invalid => ConfigProposalInvalid,
        source_only => SourceOnly,
        account_ambiguous => AccountAmbiguous,
        account_required => AccountRequired,
        guard => Guard,
        needs_terminal => NeedsTerminal,
        confirm_mismatch => ConfirmMismatch,
        keys_blocking => KeysBlocking,
        values_needed => ValuesNeeded,
        plan_changed => PlanChanged,
        local_file_too_open => LocalFileTooOpen,
        private_dir_failed => PrivateDirFailed,
        title_lookup => TitleLookup,
        input_invalid => InputInvalid,
        input_unreadable => InputUnreadable,
        unrecognized => Unrecognized,
        partial => Partial,
        tool_missing => ToolMissing,
        delivery_unverified => DeliveryUnverified,
        local_io => LocalIo,
        tool_unusable => ToolUnusable,
        owner_setup_required => OwnerSetupRequired,
        write_outcome_unknown => WriteOutcomeUnknown,
        target_refused => TargetRefused,
        fly_value_rule_refused => KeysBlocking,
        github_value_rule_refused => KeysBlocking,
        kubernetes_value_rule_refused => KeysBlocking,
        budget_spent => Partial,
        interrupted => Interrupted,
        read_back_missing => ReadBackMissing,
        in_no_account_on_the_machine => InOtherAccount,
        signed_out_access => NotSignedIn,
        changed_not_declared => NotDeclared,
        changed_signed_out => NotSignedIn,
        inventory_not_declared => NotDeclared,
        next_signed_out => NotSignedIn,
        declare_target_secrets_dir_invalid => ConfigProposalInvalid,
        k8s_mount_unreadable => MountUnreadable,
        k8s_mount_path_in_use => Guard,
        k8s_volume_refused => TargetRefused,
        k8s_configmap_right_missing => MissingRight,
        apply_needs_terminal => NeedsTerminal,
        apply_person_only => PersonOnly,
        set_needs_terminal => NeedsTerminal,
        set_person_only => PersonOnly,
        needs_undeclared => NeedsUndeclared,
        retire_still_read => RetireStillRead,
        contract_stale => ContractStale,
        value_in_text_field => ValueInTextField,
    ],
    text: [
        config_source_mismatch => ConfigSourceMismatch,
        needs_own_session => NeedsOwnSession,
        create_outcome_unknown => CreateOutcomeUnknown,
        copies_differ => CopiesDiffer,
        regenerated_file_differs => RegeneratedFileDiffers,
        remote_unreachable => RemoteUnreachable,
        remote_disconnected => RemoteDisconnected,
        manifest_exists => ManifestExists,
        personal_not_set_up => PersonalNotSetUp,
        child_start_failed => ChildStartFailed,
        ram_dir_unavailable => RamDirUnavailable,
        bindings_unapplied => BindingsUnapplied,
    ],
    mcp: [
        config_not_found,
        config_invalid,
        boundary_missing,
        state_vault_missing,
        state_vault_too_wide,
        item_unusable,
        not_declared,
        choice_required,
        nothing_in_scope,
        source_only,
        account_ambiguous,
        account_required,
        tool_missing,
        tool_unusable,
        owner_setup_required,
        signed_out_access,
        manifest_not_found,
        changed_not_declared,
        changed_signed_out,
        key_not_declared,
        ambiguous,
    ],
    flows: [
        flow_propose_key,
        flow_propose_env,
        flow_propose_target,
        flow_propose_retire,
        flow_propose_setup,
        flow_propose_structure,
        flow_propose_generate,
        flow_propose_intent,
        flow_import,
        flow_import_local,
        flow_needs,
        flow_contract,
        flow_explain,
    ],
    core: [
        core_inventory,
        core_next,
        core_ready_gate,
        core_doctor,
        core_access,
    ],
}

// --- the core documents: what each committed snapshot shows -----------------------------------

/// The `--json` document of a committed core scenario.
fn core_document(name: &str) -> Value {
    json_document(&committed(name)).unwrap_or(Value::Null)
}

#[test]
fn core_inventory_shows_set_absent_placeholder_and_unreadable_cells() {
    let states: BTreeSet<String> = core_document("core_inventory")["cells"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|c| c["state"]["state"].as_str().map(str::to_string))
        .collect();
    let want: BTreeSet<String> = ["set", "absent", "placeholder", "unreadable"]
        .into_iter()
        .map(str::to_string)
        .collect();
    assert!(want.is_subset(&states), "{states:?}");
}

/// `opv_next`'s answer is the whole `opv next --json` document (design §25.2).
#[test]
fn core_next_mcp_is_the_clis_whole_json_document() {
    let snap = committed("core_next");
    assert_eq!(mcp_answer(&snap), json_document(&snap));
}

#[test]
fn core_ready_gate_reaches_gate_failed() {
    variant_test("core_ready_gate", "GateFailed");
}

/// The warnings `opv doctor --env prod --json` raises under one check name.
fn doctor_warnings(name: &str) -> usize {
    core_document("core_doctor")["checks"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|c| c["name"] == name && c["status"] == "warn")
        .count()
}

#[test]
fn core_doctor_warns_that_this_session_reads_the_production_vault() {
    assert_eq!(doctor_warnings("production vault"), 1);
}

#[test]
fn core_doctor_warns_of_each_production_login() {
    assert_eq!(doctor_warnings("production login"), 3);
}

/// The vault `id` of environment `env` in `opv access --json`.
fn access_vault(env: &str, id: &str) -> Value {
    core_document("core_access")["environments"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| e["environment"] == env)
        .flat_map(|e| e["vaults"].as_array().cloned().unwrap_or_default())
        .find(|v| v["vault_id"] == id)
        .unwrap_or(Value::Null)
}

#[test]
fn core_access_marks_the_production_vault_this_session_writes() {
    let v = access_vault("prod", "vE2EWEBPROD000000000000001");
    assert_eq!(
        (v["production"].clone(), v["capability"].clone()),
        (json!(true), json!("write"))
    );
}

#[test]
fn core_access_raises_single_writer_for_the_vault_with_one_writer() {
    let raised = core_document("core_access")["environments"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|e| e["findings"].as_array().cloned().unwrap_or_default())
        .any(|f| {
            f["code"] == "single_writer"
                && f["message"]
                    .as_str()
                    .is_some_and(|m| m.contains("vE2EWEBPROD000000000000001"))
        });
    assert!(raised);
}

// --- the catalog, read from its source ------------------------------------------------------

/// Every `Cause` variant and the fields its document's `subject` holds (`seen` and the
/// `cause` tag are never shown), read from `src/cause/mod.rs`.
fn variants() -> &'static BTreeMap<String, BTreeSet<String>> {
    static V: OnceLock<BTreeMap<String, BTreeSet<String>>> = OnceLock::new();
    V.get_or_init(|| {
        let src = std::fs::read_to_string(Path::new(ROOT).join("src/cause/mod.rs"))
            .expect("src/cause/mod.rs");
        let start = src.find("pub enum Cause {").expect("enum Cause") + "pub enum Cause {".len();
        let field = re(r"^(?:pub\s+)?([a-z_][a-z0-9_]*)\s*:");
        let variant = re(r"^([A-Z][A-Za-z0-9]*)\s*(\{)?");
        let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut current = String::new();
        let mut depth = 0i32;
        let mut skip_field = false;
        for line in src[start..].lines() {
            let l = line.trim();
            if l.is_empty() || l.starts_with("//") {
                continue;
            }
            if l.starts_with('#') {
                // A field serde does not serialize is not part of the subject.
                if l.starts_with("#[serde(skip") {
                    skip_field = true;
                }
                continue;
            }
            if skip_field {
                skip_field = false;
                if field.is_match(l) {
                    continue;
                }
            }
            if depth == 0 {
                if l.starts_with('}') {
                    break;
                }
                if let Some(c) = variant.captures(l) {
                    current = c[1].to_string();
                    out.entry(current.clone()).or_default();
                }
            } else if depth == 1
                && let Some(c) = field.captures(l)
                && &c[1] != "seen"
            {
                out.get_mut(&current)
                    .expect("variant")
                    .insert(c[1].to_string());
            }
            depth += l.matches('{').count() as i32 - l.matches('}').count() as i32;
        }
        out
    })
}

/// The codes each variant reports, read from `Cause::code`; empty for a variant whose code is
/// the one it wraps (`Partial`, `PersonalNotSetUp`).
fn variant_codes() -> &'static BTreeMap<String, BTreeSet<String>> {
    static C: OnceLock<BTreeMap<String, BTreeSet<String>>> = OnceLock::new();
    C.get_or_init(|| {
        let src = std::fs::read_to_string(Path::new(ROOT).join("src/cause/mod.rs"))
            .expect("src/cause/mod.rs");
        let start = src.find("pub fn code(&self)").expect("Cause::code");
        let end = start + src[start..].find("pub fn exit_code").expect("exit_code");
        let mention = re(r"(?:^|[\s|(])([A-Z][A-Za-z0-9]*) \{");
        let literal = re(r#""([a-z_]+)""#);
        let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut current: Vec<String> = Vec::new();
        for line in src[start..end].lines() {
            let named: Vec<String> = mention
                .captures_iter(line)
                .map(|c| c[1].to_string())
                .filter(|v| variants().contains_key(v))
                .collect();
            if !named.is_empty() {
                current = named;
                for v in &current {
                    out.entry(v.clone()).or_default();
                }
            }
            for c in literal.captures_iter(line) {
                for v in &current {
                    out.entry(v.clone()).or_default().insert(c[1].to_string());
                }
            }
        }
        out
    })
}

/// The variant an error object (or a `then` inside one) was rendered from: the one whose
/// fields are exactly the subject's keys, and whose codes include `code` when several match.
fn identify_with(subject: &Value, code: &str) -> Option<String> {
    let keys: BTreeSet<String> = subject.as_object()?.keys().cloned().collect();
    let by_fields: Vec<&String> = variants()
        .iter()
        .filter(|(_, f)| **f == keys)
        .map(|(v, _)| v)
        .collect();
    match by_fields.as_slice() {
        [one] => Some((*one).clone()),
        many => {
            let by_code: Vec<&&String> = many
                .iter()
                .filter(|v| {
                    variant_codes()
                        .get(v.as_str())
                        .is_some_and(|c| c.contains(code))
                })
                .collect();
            match by_code.as_slice() {
                [one] => Some((**one).clone()),
                _ => None,
            }
        }
    }
}

fn identify(error: &Value) -> Option<String> {
    identify_with(error.get("subject")?, error.get("code")?.as_str()?)
}

/// Every variant an error object shows: its own, and those of the causes it wraps (`then`).
fn shown(error: &Value, out: &mut BTreeSet<String>) {
    let code = error
        .get("code")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mut subject = error.get("subject");
    while let Some(s) = subject {
        if let Some(v) = identify_with(s, code) {
            out.insert(v);
        }
        subject = s.get("then");
    }
}

/// Every variant some committed snapshot reaches: the matrix cells' documents, the scenarios'
/// `--json` documents and MCP answers, and the text-only scenarios' declared variants.
fn reached() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut snaps: Vec<PathBuf> = Vec::new();
    for dir in [snapshots(), scenario_snapshots()] {
        if let Ok(d) = std::fs::read_dir(dir) {
            snaps.extend(
                d.filter_map(Result::ok)
                    .map(|e| e.path())
                    .filter(|p| p.extension().is_some_and(|x| x == "snap")),
            );
        }
    }
    for p in snaps {
        let snap = std::fs::read_to_string(&p).unwrap_or_default();
        for doc in [json_document(&snap), mcp_answer(&snap)]
            .into_iter()
            .flatten()
        {
            if let Some(e) = doc.get("error").filter(|e| e.is_object()) {
                shown(e, &mut out);
            }
        }
    }
    for (name, variant, json) in SCENARIOS {
        if !json && snapshot_path(name).exists() {
            out.insert(variant.to_string());
        }
    }
    // `opv login --shell` has no `--json`: its refusals are read off the text its snapshot
    // holds (session-reuse §8.2, scenarios/session_reuse.rs).
    for (name, variant, says) in crate::scenarios::session_reuse::REACHED {
        if committed(name).contains(says) {
            out.insert(variant.to_string());
        }
    }
    out
}

fn unreachable_listed() -> BTreeSet<String> {
    UNREACHABLE.iter().map(|(v, _)| v.to_string()).collect()
}

// --- gate 1: every variant is reached ------------------------------------------------------

#[test]
fn every_cause_variant_is_reached_by_a_cell_or_a_scenario() {
    let reached = reached();
    let missing: Vec<&String> = variants()
        .keys()
        .filter(|v| !reached.contains(*v) && !unreachable_listed().contains(*v))
        .collect();
    assert!(
        missing.is_empty(),
        "no cell or scenario reaches {missing:?}"
    );
}

#[test]
fn no_variant_listed_unreachable_is_reached() {
    let reached = reached();
    let stale: Vec<String> = unreachable_listed()
        .into_iter()
        .filter(|v| reached.contains(v))
        .collect();
    assert!(stale.is_empty(), "remove {stale:?} from UNREACHABLE");
}

#[test]
fn every_variant_listed_unreachable_is_a_cause_variant() {
    let unknown: Vec<String> = unreachable_listed()
        .into_iter()
        .filter(|v| !variants().contains_key(v))
        .collect();
    assert!(unknown.is_empty(), "not Cause variants: {unknown:?}");
}

#[test]
fn every_document_variant_is_told_apart_by_its_fields_and_code() {
    // Two variants with the same fields must not share a code, or a document could be
    // either: the gate would count the wrong one.
    let mut clash = Vec::new();
    for (a, fa) in variants() {
        for (b, fb) in variants() {
            let ca = variant_codes().get(a).cloned().unwrap_or_default();
            let cb = variant_codes().get(b).cloned().unwrap_or_default();
            if a < b && fa == fb && (ca.is_empty() || cb.is_empty() || !ca.is_disjoint(&cb)) {
                clash.push((a.clone(), b.clone()));
            }
        }
    }
    assert!(
        clash.is_empty(),
        "variants a document cannot tell apart: {clash:?}"
    );
}

#[test]
fn every_scenario_snapshot_belongs_to_a_scenario() {
    let names: BTreeSet<&str> = SCENARIOS
        .iter()
        .map(|(n, _, _)| *n)
        .chain(FLOWS.iter().copied())
        .chain(CORE.iter().copied())
        .chain(crate::scenarios::assistant::SNAPSHOTS.iter().copied())
        .chain(crate::scenarios::consistency::SNAPSHOTS.iter().copied())
        .chain(crate::scenarios::session_reuse::SNAPSHOTS.iter().copied())
        .collect();
    let orphans: Vec<String> = std::fs::read_dir(scenario_snapshots())
        .map(|d| {
            d.filter_map(Result::ok)
                .filter_map(|e| e.file_name().to_str().map(str::to_string))
                .filter_map(|n| n.strip_suffix(".snap").map(str::to_string))
                .filter(|n| !names.contains(n.as_str()))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        orphans.is_empty(),
        "snapshots without a scenario: {orphans:?}"
    );
}

/// The canary: no scenario snapshot holds a value. Every flow scenario's values are
/// `S7MARKER` markers, and every other world value carries `test-marker-e2e-`. The MCP
/// heading line is the request the harness sent (`value_in_text_field` sends a marker on
/// purpose), not something opv printed.
#[test]
fn no_scenario_snapshot_holds_a_value() {
    let holding: Vec<String> = std::fs::read_dir(scenario_snapshots())
        .expect("scenario snapshots")
        .filter_map(Result::ok)
        .filter(|e| {
            std::fs::read_to_string(e.path())
                .unwrap_or_default()
                .lines()
                .filter(|l| !l.starts_with("## mcp "))
                .any(|l| l.contains(MARK) || l.contains("test-marker-e2e-"))
        })
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .collect();
    assert!(holding.is_empty(), "snapshots holding a value: {holding:?}");
}

#[test]
fn every_mcp_scenario_is_a_json_scenario() {
    let json: BTreeSet<&str> = SCENARIOS
        .iter()
        .filter(|(_, _, j)| *j)
        .map(|(n, _, _)| *n)
        .collect();
    let stray: Vec<&&str> = MCP_SCENARIOS
        .iter()
        .filter(|n| !json.contains(**n))
        .collect();
    assert!(stray.is_empty(), "{stray:?}");
}

// --- gate 2: every discovered call is faulted ----------------------------------------------

/// A `const NAME: &[&str] = &[...]` list of tests/e2e/matrix.rs.
fn matrix_list(name: &str) -> BTreeSet<String> {
    let src = std::fs::read_to_string(Path::new(ROOT).join("tests/e2e/matrix.rs"))
        .expect("tests/e2e/matrix.rs");
    let head = format!("const {name}: &[&str] = &[");
    let start = src.find(&head).expect("the list") + head.len();
    let end = start + src[start..].find("];").expect("end of the list");
    re(r#""([a-z_]+)""#)
        .captures_iter(&src[start..end])
        .map(|c| c[1].to_string())
        .collect()
}

/// The committed cells' names (`snapshots/cells.rs`).
fn cell_names() -> BTreeSet<String> {
    let src = std::fs::read_to_string(snapshots().join("cells.rs")).expect("cells.rs");
    re(r"(?m)^\s+([a-z0-9_]+) =>")
        .captures_iter(&src)
        .map(|c| c[1].to_string())
        .collect()
}

/// The skipped candidates of `SKIPPED.md`: name → why.
fn skips() -> BTreeMap<String, String> {
    std::fs::read_to_string(snapshots().join("SKIPPED.md"))
        .unwrap_or_default()
        .lines()
        .filter(|l| l.starts_with("| `"))
        .filter_map(|l| {
            let cols: Vec<&str> = l.split('|').map(str::trim).collect();
            Some((
                cols.get(1)?.trim_matches('`').to_string(),
                cols.get(5)?.to_string(),
            ))
        })
        .collect()
}

/// Each discovered call (a cell name without its fault) and the kinds it was given.
fn kinds_by_call() -> BTreeMap<String, BTreeSet<String>> {
    let kinds = matrix_list("KINDS");
    let ssh = matrix_list("SSH_KINDS");
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for name in cell_names().into_iter().chain(skips().into_keys()) {
        if let Some(kind) = kinds
            .iter()
            .chain(&ssh)
            .find(|k| name.ends_with(&format!("__{k}")))
        {
            let call = name[..name.len() - kind.len() - 2].to_string();
            out.entry(call).or_default().insert(kind.clone());
        }
    }
    out
}

#[test]
fn every_discovered_call_is_faulted_with_every_kind() {
    let kinds = matrix_list("KINDS");
    let ssh = matrix_list("SSH_KINDS");
    let dropped: Vec<String> = kinds_by_call()
        .into_iter()
        .flat_map(|(call, got)| {
            let want: BTreeSet<String> = if call.contains("__ssh_") {
                kinds.union(&ssh).cloned().collect()
            } else {
                kinds.clone()
            };
            want.difference(&got)
                .map(|k| format!("{call}__{k}"))
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(
        dropped.is_empty(),
        "candidates neither a cell nor skipped: {dropped:?}"
    );
}

#[test]
fn every_cell_and_skip_names_a_known_fault_kind() {
    let kinds: BTreeSet<String> = matrix_list("KINDS")
        .union(&matrix_list("SSH_KINDS"))
        .cloned()
        .collect();
    let unknown: Vec<String> = cell_names()
        .into_iter()
        .chain(skips().into_keys())
        .filter(|n| !kinds.iter().any(|k| n.ends_with(&format!("__{k}"))))
        .collect();
    assert!(unknown.is_empty(), "{unknown:?}");
}

#[test]
fn no_candidate_is_both_a_cell_and_skipped() {
    let skips = skips();
    let both: Vec<String> = cell_names()
        .into_iter()
        .filter(|c| skips.contains_key(c))
        .collect();
    assert!(both.is_empty(), "{both:?}");
}

/// E4: a skip says which recording is missing (or that the call is not modelled, or that a
/// missing tool already fails at an earlier call), so the gap is visible; recordings are
/// never invented (CONTRIBUTING).
#[test]
fn every_skipped_candidate_states_why() {
    let why = re(
        r"^(no `[a-z_]+` reply recorded for `[a-z]+ [^`]+` under tests/fixtures/[a-z]+/failures \(opv-sim exit 86\)|`[a-z]+ [^`]+` is not modelled by opv-sim \(exit 87\)|`[a-z]+ [^`]+` fails or answers nothing without the fault, so it has no output for `malformed_output` to damage \(opv-sim exit 88\)|a missing `[a-z]+` is missing for every call: opv fails at its first one, `[a-z]+ [^`]+`, so this run is the one of `[a-z0-9_]+`)$",
    );
    let vague: Vec<String> = skips()
        .into_iter()
        .filter(|(_, w)| !why.is_match(w))
        .map(|(n, w)| format!("{n}: {w:?}"))
        .collect();
    assert!(vague.is_empty(), "{vague:?}");
}

#[test]
fn every_call_no_fault_can_target_states_why() {
    let text = std::fs::read_to_string(snapshots().join("SKIPPED.md")).unwrap_or_default();
    let section = text
        .split("## Calls no fault can target")
        .nth(1)
        .unwrap_or_default();
    let vague: Vec<&str> = section
        .lines()
        .filter(|l| l.starts_with("- "))
        .filter(|l| !re(r"^- [a-z_]+: [a-z]+ \(.+\)$").is_match(l))
        .collect();
    assert!(vague.is_empty(), "{vague:?}");
}

// --- I8: MCP with two accounts and no .opv --------------------------------------------------

/// I8: the MCP server in a checkout with no `.opv`, on a machine with two 1Password accounts,
/// never uses op's default: `account_required` (config_store `pick_account_at`).
#[test]
fn i8_mcp_with_two_accounts_and_no_dot_opv_is_account_required() {
    let c = cases::account_required();
    let (tool, args) = c.mcp.clone().expect("an MCP call");
    let answer = c.scenario.mcp(tool, &args);
    assert_eq!(answer["error"]["code"], "account_required", "{answer}");
}

/// The effective uid of this test process (never root off Unix).
#[cfg(unix)]
fn effective_uid() -> u32 {
    // SAFETY: `geteuid` only reads the process's effective user id.
    unsafe { libc::geteuid() as u32 }
}

#[cfg(not(unix))]
fn effective_uid() -> u32 {
    1
}

/// `private_dir_failed` needs a real directory mode, which root ignores: skip it as root.
fn skip_under_root(euid: u32) -> bool {
    euid == 0
}

#[test]
fn non_root_does_not_skip_private_dir() {
    assert!(!skip_under_root(1000));
}
