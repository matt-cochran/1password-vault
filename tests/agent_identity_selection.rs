//! Rule 4 of identity selection (#338, design `agent-identity.md` §5, D3, vet R4, R9): in agent
//! mode (an agent marker, here `CLAUDECODE=1`) with no `OPV_IDENTITY`, a run uses the agent
//! identity this machine records for the project, automatically. Once any is installed, an
//! environment without one stops with `agent_identity_not_installed` and never falls back to
//! the person's session. With none installed, the run is the person's, as before.
//!
//! The real `opv` binary runs against `opv-sim` on the test application (`tests/e2e/app`): a
//! scratch `HOME` holding the value-free index (`~/.config/opv/agent-identities.toml`), a fake
//! credential store in the scenario (`OPV_FAKE_AGENT_STORE`, never the host's own), stdin
//! null and stdout piped (an agent's shell), in a new session without a terminal. Each test
//! is one scenario and one assertion.
#![cfg(all(unix, feature = "fake"))]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;

const ROOT: &str = env!("CARGO_MANIFEST_DIR");
const OPV: &str = env!("CARGO_BIN_EXE_opv");
const SIM: &str = env!("CARGO_BIN_EXE_opv-sim");
const ACCOUNT: &str = "AE2EDEVACCOUNT000000000001";
/// The project's name: the scratch directory's, as `opv` names a project outside a repository.
const PROJECT: &str = "project";
/// The installed agent identity's token: one `opv-sim` accepts (`tests/e2e/app/world.json`).
const AGENT_TOKEN: &str = "ops_e2e_marker_service_account_token";

/// A copy of the test application and its world, with `opv-sim` installed and no agent
/// identity yet.
struct Project {
    root: tempfile::TempDir,
}

impl Project {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("temp dir");
        let p = Self { root };
        for d in ["world", "home", PROJECT, "bin", "store"] {
            std::fs::create_dir_all(p.path(d)).expect("dir");
        }
        let app = Path::new(ROOT).join("tests/e2e/app");
        for (from, to) in [
            ("world.json", "world/world.json"),
            ("secrets.toml", "project/secrets.toml"),
            ("secrets.bindings.toml", "project/secrets.bindings.toml"),
        ] {
            std::fs::copy(app.join(from), p.path(to)).expect("app file");
        }
        std::fs::write(p.path("world/faults.toml"), "").expect("faults");
        std::fs::write(p.path("project/.opv"), format!("account = \"{ACCOUNT}\"\n")).expect(".opv");
        let ok = Command::new(SIM)
            .arg("install")
            .arg(p.path("bin"))
            .env("OPV_SIM_WORLD", p.path("world"))
            .status()
            .expect("opv-sim install")
            .success();
        assert!(ok, "opv-sim install failed");
        p
    }

    fn path(&self, sub: &str) -> PathBuf {
        self.root.path().join(sub)
    }

    /// `env`'s agent identity recorded in the index and its token in the fake store, as
    /// `opv access <env> --create --agent` leaves them.
    fn installed(self, env: &str) -> Self {
        self.indexed(env).stored(env)
    }

    /// `env`'s agent identity recorded in the value-free index only.
    fn indexed(self, env: &str) -> Self {
        let path = self.path("home/.config/opv/agent-identities.toml");
        std::fs::create_dir_all(path.parent().expect("parent")).expect("config dir");
        let mut text = std::fs::read_to_string(&path).unwrap_or_default();
        text.push_str(&format!(
            "[[identity]]\nproject = \"{PROJECT}\"\naccount_id = \"{ACCOUNT}\"\n\
             account_name = \"{PROJECT}-{env}-agent-e2e\"\nenvironment = \"{env}\"\n\
             machine = \"e2e\"\nstore = \"secret_service\"\ncreated_on = \"2026-11-17\"\n\
             expires_on = \"2027-02-15\"\n\n"
        ));
        std::fs::write(&path, text).expect("index");
        self
    }

    /// `env`'s token in the fake store only: one file named by the hex of
    /// `account/project/env`.
    fn stored(self, env: &str) -> Self {
        let user = format!("{ACCOUNT}/{PROJECT}/{env}");
        let name: String = user.bytes().map(|b| format!("{b:02x}")).collect();
        std::fs::write(self.path("store").join(name), AGENT_TOKEN).expect("store entry");
        self
    }

    /// `opv <args>` in an agent's shell, with `extra` variables set too.
    fn opv(&self, args: &[&str], extra: &[(&str, &str)]) -> Output {
        use std::os::unix::process::CommandExt as _;
        let mut c = Command::new(OPV);
        c.current_dir(self.path(PROJECT))
            .args(args)
            .env_clear()
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.path("bin").display()),
            )
            .env("HOME", self.path("home"))
            .env("OPV_NO_SKILL", "1")
            .env("OPV_SIM_WORLD", self.path("world"))
            .env("OPV_TEST_SUID_DUMPABLE", "0")
            .env("OP_BIOMETRIC_UNLOCK_ENABLED", "false")
            .env("OPV_FAKE_AGENT_STORE", self.path("store"))
            .env("CLAUDECODE", "1")
            .envs(extra.iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: `setsid` is async-signal-safe and touches no memory of the parent.
        unsafe {
            c.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        c.output().expect("run opv")
    }

    /// `opv run dev` of the web server, which starts `/bin/true` under `op run`.
    fn run_dev(&self, extra: &[(&str, &str)]) -> Output {
        let args = [
            "run",
            "dev",
            "--product",
            "web",
            "--role",
            "serve",
            "--",
            "/bin/true",
        ];
        self.opv(&args, extra)
    }

    /// The `error.code` of `opv <args> --json`.
    fn error_code(&self, args: &[&str], extra: &[(&str, &str)]) -> Option<String> {
        let out = self.opv(args, extra);
        let doc: Value = serde_json::from_slice(&out.stdout).ok()?;
        doc.pointer("/error/code")?.as_str().map(str::to_string)
    }

    /// Whether the last `op run` was given a service-account token (`opv-sim` records its
    /// environment value-free, `op-run-env.json`): `None` when no `op run` was made.
    fn op_run_had_token(&self) -> Option<bool> {
        let text = std::fs::read_to_string(self.path("world/op-run-env.json")).ok()?;
        let runs: Vec<Value> = serde_json::from_str(&text).ok()?;
        let last = runs.last()?;
        Some(last["token"].as_str() != Some("absent"))
    }

    /// Every `op` call the simulator logged.
    fn op_calls(&self) -> Vec<String> {
        std::fs::read_to_string(self.path("world/calls.log"))
            .unwrap_or_default()
            .lines()
            .filter(|l| l.split_whitespace().next() == Some("op"))
            .map(str::to_string)
            .collect()
    }

    /// Every `op` write the simulator logged: a create, edit, delete or grant.
    fn op_writes(&self) -> Vec<String> {
        self.op_calls()
            .into_iter()
            .filter(|line| {
                line.split_whitespace()
                    .take(4)
                    .any(|w| matches!(w, "create" | "edit" | "delete" | "grant"))
            })
            .collect()
    }
}

fn printed(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

// --- rule 4 selects the agent ---

#[test]
fn a_marker_with_an_installed_identity_hands_op_the_agents_token() {
    let p = Project::new().installed("dev");
    let _ = p.run_dev(&[]);
    assert_eq!(p.op_run_had_token(), Some(true));
}

#[test]
fn a_marker_with_an_installed_identity_reports_the_agent_in_ready() {
    let p = Project::new().installed("dev");
    let out = p.opv(&["ready", "dev", "--json"], &[]);
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
    let kinds: Vec<Value> = doc
        .pointer("/identity")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(|o| o["kind"].clone()).collect())
        .unwrap_or_default();
    assert_eq!(kinds, vec![Value::from("agent")], "{}", printed(&out));
}

// --- an environment with none of its own stops (R4) ---

#[test]
fn an_environment_without_its_own_identity_stops_with_agent_identity_not_installed() {
    let p = Project::new().installed("dev");
    let code = p.error_code(&["plan", "prod", "--json"], &[]);
    assert_eq!(code.as_deref(), Some("agent_identity_not_installed"));
}

#[test]
fn an_environment_without_its_own_identity_never_calls_op_as_the_person() {
    let p = Project::new().installed("dev");
    let _ = p.opv(&["plan", "prod", "--json"], &[]);
    assert_eq!(p.op_calls(), Vec::<String>::new());
}

#[test]
fn an_indexed_identity_missing_from_the_store_stops_with_agent_identity_not_installed() {
    let p = Project::new().indexed("dev");
    let code = p.error_code(&["plan", "dev", "--json"], &[]);
    assert_eq!(code.as_deref(), Some("agent_identity_not_installed"));
}

// --- with nothing installed, the person, as today ---

#[test]
fn a_marker_with_nothing_installed_runs_op_as_the_person() {
    let p = Project::new();
    let _ = p.run_dev(&[]);
    assert_eq!(p.op_run_had_token(), Some(false));
}

#[test]
fn a_marker_with_nothing_installed_warns_assistant_on_person_session() {
    let p = Project::new();
    let out = p.opv(&["ready", "dev", "--json"], &[]);
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
    let state = doc.pointer("/identity/0/state").cloned();
    assert_eq!(
        state,
        Some(Value::from("assistant_on_person_session")),
        "{}",
        printed(&out)
    );
}

// --- the overrides ---

#[test]
fn opv_identity_person_runs_op_as_the_person_despite_an_installed_identity() {
    let p = Project::new().installed("dev");
    let _ = p.run_dev(&[("OPV_IDENTITY", "person")]);
    assert_eq!(p.op_run_had_token(), Some(false));
}

#[test]
fn an_env_token_wins_over_an_installed_identity() {
    // Indexed for `prod` only: under rule 4 `dev` would stop; the token in the environment
    // (rule 1) is used instead.
    let p = Project::new().installed("prod");
    let token = [("OP_SERVICE_ACCOUNT_TOKEN", AGENT_TOKEN)];
    let code = p.error_code(&["plan", "dev", "--json"], &token);
    assert_ne!(code.as_deref(), Some("agent_identity_not_installed"));
}

// --- the refusals see the auto-selected identity ---

#[test]
fn set_under_the_auto_selected_agent_is_refused_with_own_session_required() {
    let p = Project::new().installed("dev");
    let code = p.error_code(&["set", "web/API_KEY", "--env", "dev", "--json"], &[]);
    assert_eq!(code.as_deref(), Some("own_session_required"));
}

#[test]
fn sync_under_the_auto_selected_agent_is_refused_with_own_session_required() {
    let p = Project::new().installed("dev");
    let code = p.error_code(&["sync", "dev", "--json"], &[]);
    assert_eq!(code.as_deref(), Some("own_session_required"));
}

#[test]
fn set_under_the_auto_selected_agent_makes_no_op_write() {
    let p = Project::new().installed("dev");
    let _ = p.opv(&["set", "web/API_KEY", "--env", "dev", "--json"], &[]);
    assert_eq!(p.op_writes(), Vec::<String>::new());
}

// --- the canary ---

#[test]
fn no_auto_selected_run_prints_the_agents_token() {
    let p = Project::new().installed("dev");
    let mut all = printed(&p.run_dev(&[]));
    for args in [
        &["plan", "dev", "--json"][..],
        &["ready", "dev", "--json"],
        &["doctor", "--env", "dev", "--json"],
        &["plan", "prod", "--json"],
    ] {
        all.push_str(&printed(&p.opv(args, &[])));
    }
    assert!(!all.contains(AGENT_TOKEN), "the agent's token was printed");
}
