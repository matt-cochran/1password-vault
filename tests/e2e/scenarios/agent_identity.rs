//! The agent identity end to end (#338, design `agent-identity.md` §4.3, §12 S12; ADR-0001):
//! the real `opv` against `opv-sim`, with a fake credential store in the scenario directory
//! (`OPV_FAKE_AGENT_STORE`, a `fake`-feature hook: the host's own store is never touched).
//!
//! The shared setup is one world: a person creates the read-only agent identity of `dev` and
//! of `prod` with `opv access <env> --create --agent` at a pseudo-terminal (the token goes
//! from `op service-account create` into the fake store, never through output), then the
//! agent runs `opv run`, `plan`, `ready`, `status`, `doctor` and `access --rotate --agent`
//! under `OPV_IDENTITY=agent`, text and `--json`, and reads `opv_state` over MCP. The agent's
//! own environment also carries a person's `OP_SESSION_*` and `OP_ACCOUNT`, as a shell where
//! the person signed in would.
//!
//! The canaries: the service-account token the simulator issued (`ops_SIMTOKEN…`) and every
//! world value (`S7MARKERVALUE-…`, [`Scenario::marked`]). Each test asserts one behaviour:
//!
//! - no stdout, stderr or `--json` document of any agent run, and no MCP reply, holds the
//!   token or a value, and neither does any file opv wrote under `HOME` or the project;
//! - `op run`'s own environment under the agent holds the agent's token (one the simulator
//!   issued) and no `OP_SESSION*`, `OP_CONNECT_*` or `OP_ACCOUNT`;
//! - the app `opv run` starts sees no `OP_*` at all, and does get its values;
//! - the snapshot (`snapshots/scenarios/agent_identity.snap`) pins the `plan` and `status`
//!   causes under the reader grants, and the agent causes each reached once: not installed,
//!   exists, rejected, store unavailable, store locked. It is normalized so no host state
//!   reaches it: the machine name, the store's kind and dates are placeholders.
//!
//! `opv access --rotate --agent` is not built yet (S9): its run is checked for leaks only.
//! The doctor `identity` row (S10) is not merged, so nothing here asserts it.

use std::path::Path;
use std::process::Stdio;
use std::sync::OnceLock;

use serde_json::{Value, json};

use crate::coverage::{Run, Scenario, scenario_snapshots, updating};

/// The scenario snapshot this module writes (`tests/e2e/snapshots/scenarios/`).
pub(crate) const SNAPSHOTS: &[&str] = &["agent_identity"];

/// Every token `opv-sim` issues starts so (`tests/sim/op.rs`, `service-account create`).
const TOKEN_CANARY: &str = "ops_SIMTOKEN";
/// Every world value of a marked world holds this ([`Scenario::marked`]).
const VALUE_CANARY: &str = "S7MARKER";
/// The machine part every create here names.
const MACHINE: &str = "e2e";
/// A person's session and account in the agent's shell: never to reach `op run` under it.
const SESSION_CANARY: &str = "S12SESSIONCANARYvalue";

/// The app `opv run` starts: it writes its own environment to `app-env.txt` and prints
/// nothing.
const APP: &[&str] = &["/bin/sh", "-c", "/usr/bin/env > {root}/app-env.txt"];

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

/// `a` with `--json` before any `--`.
fn json_args(a: &[&str]) -> Vec<String> {
    let mut v = args(a);
    let at = v.iter().position(|x| x == "--").unwrap_or(v.len());
    v.insert(at, "--json".into());
    v
}

/// The app's two shared vaults have 27-character IDs, and the token-scoped binding check of
/// `--create --agent` accepts only 1Password's 26 (`src/app/reader_grants.rs` `id`): this
/// world gives them 26, in the world and in the bindings alike.
const VAULT_IDS: [(&str, &str); 2] = [
    ("vE2ESHAREDDEV00000000000001", "vE2ESHAREDDEV0000000000001"),
    ("vE2ESHAREDPROD0000000000001", "vE2ESHAREDPROD000000000001"),
];

/// A marked world with its fake store in the scenario directory. (The agent's `op` calls are
/// token-only, so their environment loses `OPV_SIM_WORLD`: the simulator finds its world
/// through the file `opv-sim install` writes beside it on `PATH`, `tests/sim/world.rs`.)
fn world() -> Scenario {
    let s = Scenario::new().marked();
    for rel in ["world/world.json", "project/secrets.bindings.toml"] {
        let p = s.path(rel);
        let mut text = std::fs::read_to_string(&p).expect("app file");
        for (from, to) in VAULT_IDS {
            text = text.replace(from, to);
        }
        std::fs::write(&p, text).expect("app file");
    }
    // A service account can never be granted a Personal or Private vault (design §3.1), so
    // the app's personal key is left out: under the agent it could never be read (with it,
    // `opv run` stops at `personal vault e2e-dev-private was not found`).
    let s = s.config(|text| {
        let personal = regex::Regex::new(
            r"(?ms)^personal_(vault|item) *=[^\n]*\n|^\[products\.web\.keys\.PERSONAL_LLM_KEY\]\n.*?\n\n",
        )
        .expect("regex");
        // The TLS keys are delivered as variables, not files: file delivery needs a
        // RAM-backed runtime folder, which only Linux runners give (sealed.rs `ram`).
        personal
            .replace_all(&text, "")
            .replace("file = \"tls/certificate\"\n", "")
            .replace("file = \"tls/private-key\"\n", "")
    });
    let store = s.path("store").display().to_string();
    s.var("OPV_FAKE_AGENT_STORE", &store)
}

/// `opv <args>` with stdin and stdout on a pseudo-terminal (a person's own terminal), each
/// line of `answers` typed in advance. stderr stays piped.
fn at_terminal(s: &Scenario, args: &[String], answers: &str) -> Run {
    use std::io::Write as _;
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

    let root = s.path("").display().to_string();
    let root = root.trim_end_matches('/');
    let args: Vec<String> = args.iter().map(|a| a.replace("{root}", root)).collect();
    let (mut master, mut slave): (libc::c_int, libc::c_int) = (-1, -1);
    // SAFETY: openpty writes two new descriptors; null name, termios and size are allowed.
    let made = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(made, 0, "openpty: {}", std::io::Error::last_os_error());
    // SAFETY: both descriptors were just opened and are owned here alone.
    let (master, slave) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
    // SAFETY: termios is plain data; tcgetattr fills it.
    let mut term = unsafe { std::mem::zeroed::<libc::termios>() };
    // SAFETY: the descriptor is open.
    assert_eq!(unsafe { libc::tcgetattr(slave.as_raw_fd(), &mut term) }, 0);
    term.c_lflag &= !(libc::ECHO | libc::ECHONL);
    term.c_oflag &= !libc::ONLCR;
    // SAFETY: as above.
    assert_eq!(
        unsafe { libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, &term) },
        0
    );
    let mut writer = std::fs::File::from(master.try_clone().expect("pty"));
    writer.write_all(answers.as_bytes()).expect("type answers");
    let mut cmd = s.command();
    cmd.args(&args)
        .stdin(Stdio::from(slave.try_clone().expect("pty stdin")))
        .stdout(Stdio::from(slave.try_clone().expect("pty stdout")))
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn opv at a terminal");
    drop(cmd);
    drop(slave);
    drop(writer);
    let mut out = Vec::new();
    let mut reader = std::fs::File::from(master);
    match std::io::Read::read_to_end(&mut reader, &mut out) {
        Ok(_) => {}
        Err(e) if e.raw_os_error() == Some(libc::EIO) => {}
        Err(e) => panic!("read the pty: {e}"),
    }
    let status = child.wait().expect("wait opv");
    let mut err = Vec::new();
    if let Some(mut stderr) = child.stderr.take() {
        std::io::Read::read_to_end(&mut stderr, &mut err).expect("stderr");
    }
    Run {
        code: status.code(),
        stdout: normalize(s, &String::from_utf8_lossy(&out).replace("\r\n", "\n")),
        stderr: normalize(s, &String::from_utf8_lossy(&err)),
    }
}

/// A person's `opv access <env> --create --agent --name e2e`, answered yes.
fn create(s: &Scenario, env: &str, json: bool) -> Run {
    let mut a = vec!["access", env, "--create", "--agent", "--name", MACHINE];
    if env == "prod" {
        a.extend(["--confirm", "prod"]);
    }
    let a = if json { json_args(&a) } else { args(&a) };
    at_terminal(s, &a, "y\n")
}

/// The scenario under the agent identity, from here on: `OPV_IDENTITY=agent`, with a
/// person's session and account in the shell.
fn as_agent(s: Scenario) -> Scenario {
    s.var("OPV_IDENTITY", "agent")
        .var("OP_SESSION_e2edev", SESSION_CANARY)
        .var("OP_ACCOUNT", crate::coverage::DEV_ACCOUNT)
}

/// What no snapshot may depend on, beyond the harness's own normalization: the machine name
/// (a run resolves the identity's name from the host), the store's kind (the host's), dates
/// (the identity's expiry is today + 90 days) and the token marker's counter.
fn normalize(s: &Scenario, text: &str) -> String {
    let text = s.normalize(text);
    let re = |p: &str| regex::Regex::new(p).expect("regex");
    let text = re(r"-agent-[A-Za-z0-9-]+").replace_all(&text, "-agent-<machine>");
    let text =
        re(r"(the )?login keyring \(Secret Service\)|secret_service").replace_all(&text, "<store>");
    let text = re(r"\b\d{4}-\d{2}-\d{2}\b([^T]|$)").replace_all(&text, "<date>$1");
    re(r"ops_SIMTOKEN[A-Za-z0-9]*")
        .replace_all(&text, "ops_SIMTOKEN<n>")
        .into_owned()
}

/// `opv <args>` headless (the harness's own run), normalized.
fn headless(s: &Scenario, a: &[String]) -> Run {
    let r = s.opv(a);
    Run {
        code: r.code,
        stdout: normalize(s, &r.stdout),
        stderr: normalize(s, &r.stderr),
    }
}

/// Everything the shared world's runs left: each run by label, the MCP reply, what the
/// simulator recorded of `op run`'s environment, the app's environment, and every file opv
/// wrote under `HOME` and the project.
struct Shared {
    /// The raw runs, before normalization (a canary must be looked for in what opv printed).
    raw: Vec<(String, Run)>,
    mcp: String,
    op_run_env: Value,
    app_env: String,
    files: Vec<(String, String)>,
    /// What the fake store holds: the issued tokens (the canary's positive partner).
    store: Vec<String>,
}

/// The agent's commands: label and arguments (`--json` is added for the JSON half).
fn agent_commands() -> Vec<(&'static str, Vec<&'static str>)> {
    let mut run = vec!["run", "dev", "--product", "web", "--role", "serve", "--"];
    run.extend(APP);
    vec![
        ("run dev", run),
        ("plan dev", vec!["plan", "dev"]),
        ("plan prod", vec!["plan", "prod"]),
        ("ready dev", vec!["ready", "dev"]),
        ("status dev", vec!["status", "dev"]),
        ("status prod", vec!["status", "prod"]),
        ("doctor dev", vec!["doctor", "--env", "dev"]),
        ("rotate dev", vec!["access", "dev", "--rotate", "--agent"]),
    ]
}

fn shared() -> &'static Shared {
    static SHARED: OnceLock<Shared> = OnceLock::new();
    SHARED.get_or_init(|| {
        let s = world();
        let mut raw = Vec::new();
        for env in ["dev", "prod"] {
            let r = create(&s, env, false);
            assert_eq!(r.code, Some(0), "create {env}: {}{}", r.stdout, r.stderr);
        }
        let s = as_agent(s);
        for (label, a) in agent_commands() {
            raw.push((format!("{label} text"), s.opv(&args(&a))));
            // `opv run` has `--json` only with `--preview`.
            let json = if label == "run dev" {
                json_args(&[
                    "run",
                    "--preview",
                    "dev",
                    "--product",
                    "web",
                    "--role",
                    "serve",
                ])
            } else {
                json_args(&a)
            };
            raw.push((format!("{label} --json"), s.opv(&json)));
        }
        let mcp = s
            .mcp("opv_state", &json!({"section": "plan", "env": "prod"}))
            .to_string();
        let read = |p: &Path| std::fs::read_to_string(p).unwrap_or_default();
        let op_run_env =
            serde_json::from_str(&read(&s.path("world/op-run-env.json"))).unwrap_or(Value::Null);
        let mut files = Vec::new();
        for dir in ["home", "project"] {
            walk(&s.path(dir), &mut files);
        }
        let mut store = Vec::new();
        walk(&s.path("store"), &mut store);
        Shared {
            raw,
            mcp,
            op_run_env,
            app_env: read(&s.path("app-env.txt")),
            files,
            store: store.into_iter().map(|(_, v)| v).collect(),
        }
    })
}

/// Every regular file under `dir`: its path and its text (lossy).
fn walk(dir: &Path, out: &mut Vec<(String, String)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.filter_map(Result::ok) {
        let p = e.path();
        if p.is_dir() {
            walk(&p, out);
        } else if let Ok(b) = std::fs::read(&p) {
            out.push((
                p.display().to_string(),
                String::from_utf8_lossy(&b).into_owned(),
            ));
        }
    }
}

/// The labels of the runs whose stdout or stderr holds `needle`.
fn runs_holding(needle: &str) -> Vec<String> {
    shared()
        .raw
        .iter()
        .filter(|(_, r)| r.stdout.contains(needle) || r.stderr.contains(needle))
        .map(|(l, _)| l.clone())
        .collect()
}

/// The names of an environment dump (`NAME=value` lines).
fn names(dump: &str) -> Vec<String> {
    dump.lines()
        .filter_map(|l| l.split_once('=').map(|(n, _)| n.to_string()))
        .collect()
}

// --- the canaries ----------------------------------------------------------------------------

/// The token canary is real: the store holds the issued token, so its absence below is opv's
/// doing.
#[test]
fn the_store_holds_the_issued_token() {
    assert!(
        shared().store.iter().any(|t| t.starts_with(TOKEN_CANARY)),
        "{} entries",
        shared().store.len()
    );
}

#[test]
fn no_agent_run_prints_the_token() {
    assert_eq!(runs_holding(TOKEN_CANARY), Vec::<String>::new());
}

#[test]
fn no_agent_run_prints_a_value() {
    assert_eq!(runs_holding(VALUE_CANARY), Vec::<String>::new());
}

#[test]
fn no_agent_run_prints_the_persons_session() {
    assert_eq!(runs_holding(SESSION_CANARY), Vec::<String>::new());
}

/// Every `--json` run printed exactly one document (so the canaries above read a document).
#[test]
fn every_json_run_is_one_document() {
    let not_one: Vec<&String> = shared()
        .raw
        .iter()
        .filter(|(l, _)| l.ends_with("--json"))
        .filter(|(_, r)| {
            serde_json::Deserializer::from_str(&r.stdout)
                .into_iter::<Value>()
                .count()
                != 1
        })
        .map(|(l, _)| l)
        .collect();
    assert!(not_one.is_empty(), "{not_one:?}");
}

#[test]
fn the_mcp_reply_holds_no_token_or_value() {
    let m = &shared().mcp;
    assert!(
        !m.contains(TOKEN_CANARY) && !m.contains(VALUE_CANARY) && !m.contains(SESSION_CANARY),
        "{m}"
    );
}

/// The MCP read ran as the agent and answered a plan, not an error before any read.
#[test]
fn the_mcp_read_answers_the_plan() {
    let m: Value = serde_json::from_str(&shared().mcp).expect("mcp reply");
    assert!(
        m.get("plan_id").is_some() || m.get("changes").is_some(),
        "{m}"
    );
}

#[test]
fn no_file_opv_wrote_holds_the_token_or_a_value() {
    let holding: Vec<&String> = shared()
        .files
        .iter()
        .filter(|(_, t)| t.contains(TOKEN_CANARY) || t.contains(VALUE_CANARY))
        .map(|(p, _)| p)
        .collect();
    assert!(holding.is_empty(), "{holding:?}");
}

// --- op run's environment and the app's --------------------------------------------------------

/// The one `op run` of the shared world.
fn op_run() -> &'static Value {
    let runs = shared().op_run_env.as_array().expect("op run was called");
    assert_eq!(runs.len(), 1, "{runs:?}");
    &runs[0]
}

#[test]
fn op_run_holds_the_agents_token() {
    assert_eq!(op_run()["token"], "service_account");
}

#[test]
fn op_run_holds_no_session_connect_or_account() {
    let leaked: Vec<&str> = op_run()["names"]
        .as_array()
        .expect("names")
        .iter()
        .filter_map(Value::as_str)
        .filter(|n| {
            n.starts_with("OP_SESSION") || n.starts_with("OP_CONNECT_") || *n == "OP_ACCOUNT"
        })
        .collect();
    assert!(leaked.is_empty(), "{leaked:?}");
}

#[test]
fn the_app_sees_no_op_variable() {
    let op: Vec<String> = names(&shared().app_env)
        .into_iter()
        .filter(|n| n.starts_with("OP_"))
        .collect();
    assert!(op.is_empty(), "{op:?}");
}

/// The positive partner: the app ran and got its value through the agent's `op run`.
#[test]
fn the_app_gets_its_value() {
    assert!(
        shared()
            .app_env
            .lines()
            .any(|l| l.starts_with("API_KEY=") && l.contains(VALUE_CANARY)),
        "{:?}",
        names(&shared().app_env)
    );
}

// --- the snapshot ------------------------------------------------------------------------------

/// One run as snapshot sections; headings end in `text`/`--json` so the coverage gates read
/// the JSON runs' error documents.
fn section(snap: &mut String, label: &str, run: &Run) {
    snap.push_str(&format!(
        "\n## {label} exit: {}\n## {label} stdout\n{}\n## {label} stderr\n{}",
        run.code.map_or("killed".into(), |c| c.to_string()),
        run.stdout,
        run.stderr,
    ));
}

/// A fresh world where `env`'s identity was created, then `edit` applied, under the agent.
fn installed(env: &str, edit: impl FnOnce(&Scenario)) -> Scenario {
    let s = world();
    let r = create(&s, env, false);
    assert_eq!(r.code, Some(0), "create: {}{}", r.stdout, r.stderr);
    edit(&s);
    as_agent(s)
}

/// The world's service accounts removed: 1Password no longer knows the token (revoked).
fn revoke(s: &Scenario) {
    let p = s.path("world/world.json");
    let mut w: Value =
        serde_json::from_str(&std::fs::read_to_string(&p).expect("world")).expect("world");
    w["op"]["service_accounts"] = json!([]);
    std::fs::write(&p, w.to_string()).expect("world");
}

fn transcript() -> String {
    let mut snap = String::from(
        "# agent_identity: the read-only agent identity through the real binary (#338)\n",
    );
    // A person's create, and the second create that finds it.
    for json in [false, true] {
        let s = world();
        let mode = if json { "--json" } else { "text" };
        section(
            &mut snap,
            &format!("create dev {mode}"),
            &create(&s, "dev", json),
        );
        section(
            &mut snap,
            &format!("create again {mode}"),
            &create(&s, "dev", json),
        );
    }
    // The reader grants' plan and status, under the agent.
    let mode_args = |json: bool, a: &[&str]| if json { json_args(a) } else { args(a) };
    for (label, a) in [
        ("plan prod", &["plan", "prod"][..]),
        ("status prod", &["status", "prod"][..]),
    ] {
        for json in [false, true] {
            let s = installed("prod", |_| {});
            let mode = if json { "--json" } else { "text" };
            section(
                &mut snap,
                &format!("{label} {mode}"),
                &headless(&s, &mode_args(json, a)),
            );
        }
    }
    // The agent causes, each once.
    type Setup = fn() -> Scenario;
    let cases: [(&str, Setup); 4] = [
        ("not installed", || as_agent(world())),
        ("rejected", || installed("prod", revoke)),
        ("store unavailable", || {
            installed("prod", |_| {}).var("OPV_FAKE_AGENT_STORE_FAULT", "unavailable")
        }),
        ("store locked", || {
            installed("prod", |_| {}).var("OPV_FAKE_AGENT_STORE_FAULT", "locked")
        }),
    ];
    for (label, setup) in cases {
        for json in [false, true] {
            let mode = if json { "--json" } else { "text" };
            let s = setup();
            section(
                &mut snap,
                &format!("{label} {mode}"),
                &headless(&s, &mode_args(json, &["plan", "prod"])),
            );
        }
    }
    snap
}

#[test]
fn the_agent_identity_scenarios_match_their_snapshot() {
    let got = transcript();
    let path = scenario_snapshots().join(format!("{}.snap", SNAPSHOTS[0]));
    if updating() {
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
