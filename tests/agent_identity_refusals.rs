//! The agent identity is read-only (#338, design `agent-identity.md` §5-§6, D4, D12): every
//! write path and `sync` is refused under `OPV_IDENTITY=agent` with `own_session_required`,
//! and `opv-sim` sees no `op` write. The real `opv` binary runs against `opv-sim` on the test
//! application (`tests/e2e/app`): a scratch `HOME`, `OPV_NO_SKILL=1`, a new session without a
//! controlling terminal, and stdin and stdout either pipes (an agent's shell) or a
//! pseudo-terminal (a person command typed after `!`, vet R10), so a terminal check never
//! answers in the identity's place.
//!
//! The lib-only write paths have unit tests beside their code: tidy (`tidy_tests.rs`), the
//! structural apply (`structure_tests.rs`), `generate` (`generate_tests.rs`) and MCP
//! `opv_import_local` (`mcp_propose_tests.rs`).
#![cfg(all(unix, feature = "fake"))]

use std::io::Read as _;
use std::os::fd::{FromRawFd as _, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;

const ROOT: &str = env!("CARGO_MANIFEST_DIR");
const OPV: &str = env!("CARGO_BIN_EXE_opv");
const SIM: &str = env!("CARGO_BIN_EXE_opv-sim");
const ACCOUNT: &str = "AE2EDEVACCOUNT000000000001";
/// The installed agent identity's token: one `opv-sim` accepts (`tests/e2e/app/world.json`).
const AGENT_TOKEN: &str = "ops_e2e_marker_service_account_token";

/// A one-member set on `dev` (`opv provision gen --env dev`).
const GEN_SET: &str = r#"
[products.web.keys.GEN_SECRET]
kind = "secret"
environments = ["dev"]

[sets.gen]
environments = ["dev"]

[sets.gen.members]
"web/GEN_SECRET" = { generate = { hex_bytes = 32 } }
"#;

/// How the run's stdin and stdout are connected.
#[derive(Clone, Copy)]
enum Io {
    /// Pipes: an agent's shell.
    Headless,
    /// A pseudo-terminal: a person command typed after `!`.
    Terminal,
}

/// What a refused run left behind: its error code and the `op` writes the simulator saw.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    code: Option<String>,
    op_writes: Vec<String>,
}

/// The refusal every write path gives under the agent identity, with nothing written.
fn refused() -> Outcome {
    Outcome {
        code: Some("own_session_required".into()),
        op_writes: Vec::new(),
    }
}

/// A copy of the test application and its world, with `opv-sim` installed.
struct Project {
    root: tempfile::TempDir,
}

impl Project {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("temp dir");
        let p = Self { root };
        for d in ["world", "home", "project", "bin"] {
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
        // The agent identity of `dev` and `prod` is installed, in a fake store in the
        // scenario (`OPV_FAKE_AGENT_STORE`, never the host's own): a run resolves it before
        // its first `op` call, then refuses the write. One file per entry, named by the hex
        // of `account/project/env`; the token is one the simulator accepts.
        for env in ["dev", "prod"] {
            let user = format!("{ACCOUNT}/project/{env}");
            let name: String = user.bytes().map(|b| format!("{b:02x}")).collect();
            std::fs::create_dir_all(p.path("store")).expect("store");
            std::fs::write(p.path("store").join(name), AGENT_TOKEN).expect("store entry");
        }
        std::fs::write(p.path("project/.opv"), format!("account = \"{ACCOUNT}\"\n")).expect(".opv");
        let dotenv = p.path("project/dev.env");
        std::fs::write(&dotenv, "API_KEY=test-marker-e2e-agent-import\n").expect("dotenv");
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&dotenv, std::fs::Permissions::from_mode(0o600)).expect("chmod");
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

    /// `text` appended to the project's `secrets.toml`.
    fn with_config(self, text: &str) -> Self {
        let p = self.path("project/secrets.toml");
        let mut config = std::fs::read_to_string(&p).expect("config");
        config.push_str(text);
        std::fs::write(&p, config).expect("config");
        self
    }

    fn command(&self, args: &[&str]) -> Command {
        use std::os::unix::process::CommandExt as _;
        let mut c = Command::new(OPV);
        c.current_dir(self.path("project"))
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
            .env("OPV_IDENTITY", "agent")
            .env("OPV_FAKE_AGENT_STORE", self.path("store"))
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
        c
    }

    /// `opv <args>` under the agent identity, then what it left behind.
    fn agent(&self, io: Io, args: &[&str]) -> Outcome {
        let (stdout, stderr) = match io {
            Io::Headless => {
                let out = self
                    .command(args)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .output()
                    .expect("run opv");
                (
                    String::from_utf8_lossy(&out.stdout).into_owned(),
                    String::from_utf8_lossy(&out.stderr).into_owned(),
                )
            }
            Io::Terminal => self.on_terminal(args),
        };
        Outcome {
            code: error_code(&stdout).or_else(|| text_code(&stderr)),
            op_writes: self.op_writes(),
        }
    }

    /// `opv <args>` with stdin and stdout on a fresh pseudo-terminal: what it printed there,
    /// and on stderr.
    fn on_terminal(&self, args: &[&str]) -> (String, String) {
        let (master, slave) = pty();
        let mut child = self
            .command(args)
            .stdin(Stdio::from(slave.try_clone().expect("pty")))
            .stdout(Stdio::from(slave))
            .spawn()
            .expect("run opv");
        // The parent's copies of the terminal side are gone; the read ends with the child.
        let mut master = std::fs::File::from(master);
        let mut printed = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match master.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => printed.extend_from_slice(&buf[..n]),
            }
        }
        let mut stderr = String::new();
        if let Some(mut e) = child.stderr.take() {
            let _ = e.read_to_string(&mut stderr);
        }
        child.wait().expect("wait opv");
        (String::from_utf8_lossy(&printed).into_owned(), stderr)
    }

    /// Every `op` call the simulator logged that writes: a create, edit or delete.
    fn op_writes(&self) -> Vec<String> {
        calls(&self.path("world/calls.log"))
            .into_iter()
            .filter(|line| {
                let words: Vec<&str> = line.split_whitespace().collect();
                words.first() == Some(&"op")
                    && words
                        .iter()
                        .take(4)
                        .any(|w| matches!(*w, "create" | "edit" | "delete" | "grant"))
            })
            .collect()
    }

    /// Every call the simulator logged, of any tool.
    fn calls(&self) -> Vec<String> {
        calls(&self.path("world/calls.log"))
    }
}

fn calls(log: &Path) -> Vec<String> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

/// A pseudo-terminal pair: (controller, terminal side).
fn pty() -> (OwnedFd, OwnedFd) {
    let (mut master, mut slave) = (0, 0);
    // SAFETY: openpty writes two new descriptors into the out-pointers; null name, termios
    // and window size are allowed.
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0, "openpty: {}", std::io::Error::last_os_error());
    // SAFETY: both descriptors were just opened and are owned here alone.
    unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) }
}

/// The `error.code` of the one JSON document in `stdout`.
fn error_code(stdout: &str) -> Option<String> {
    let doc: Value = serde_json::from_str(stdout.trim()).ok()?;
    doc.pointer("/error/code")?.as_str().map(str::to_string)
}

/// A command with no `--json` names its refusal in text: `own_session_required` is the
/// line "must be used in your own session" (`src/cause/render.rs`).
fn text_code(stderr: &str) -> Option<String> {
    stderr
        .contains("must be used in your own session")
        .then(|| "own_session_required".to_string())
}

// --- the person commands (a terminal, so the terminal check never answers first) ---

#[test]
fn apply_under_the_agent_is_refused_without_an_op_write() {
    let p = Project::new();
    assert_eq!(p.agent(Io::Terminal, &["apply", "--json"]), refused());
}

#[test]
fn apply_attest_under_the_agent_is_refused_without_an_op_write() {
    let p = Project::new();
    let args = ["apply", "--attest", "prod:fly:web/API_KEY", "--json"];
    assert_eq!(p.agent(Io::Terminal, &args), refused());
}

#[test]
fn set_under_the_agent_is_refused_without_an_op_write() {
    let p = Project::new();
    let args = ["set", "web/API_KEY", "--env", "dev", "--json"];
    assert_eq!(p.agent(Io::Terminal, &args), refused());
}

#[test]
fn set_from_file_under_the_agent_is_refused_without_an_op_write() {
    let p = Project::new();
    let args = [
        "set",
        "web/TLS_CERTIFICATE",
        "--env",
        "dev",
        "--from-file",
        "dev.env",
        "--json",
    ];
    assert_eq!(p.agent(Io::Terminal, &args), refused());
}

#[test]
fn provision_under_the_agent_is_refused_without_an_op_write() {
    let p = Project::new().with_config(GEN_SET);
    let args = ["provision", "gen", "--env", "dev", "--json"];
    assert_eq!(p.agent(Io::Terminal, &args), refused());
}

#[test]
fn access_create_under_the_agent_is_refused_without_an_op_write() {
    let p = Project::new();
    let args = [
        "access",
        "prod",
        "--create",
        "--github",
        "e2e-org/e2e-app",
        "--json",
    ];
    assert_eq!(p.agent(Io::Terminal, &args), refused());
}

#[test]
fn access_rotate_under_the_agent_is_refused_without_an_op_write() {
    let p = Project::new();
    let args = [
        "access",
        "prod",
        "--rotate",
        "--github",
        "e2e-org/e2e-app",
        "--json",
    ];
    assert_eq!(p.agent(Io::Terminal, &args), refused());
}

#[test]
fn target_credentials_create_under_the_agent_is_refused_without_an_op_write() {
    let p = Project::new();
    let args = [
        "target",
        "credentials",
        "prod",
        "--target",
        "fly",
        "--create",
    ];
    assert_eq!(p.agent(Io::Terminal, &args), refused());
}

#[test]
fn target_credentials_rotate_under_the_agent_is_refused_without_an_op_write() {
    let p = Project::new();
    let args = [
        "target",
        "credentials",
        "prod",
        "--target",
        "fly",
        "--rotate",
    ];
    assert_eq!(p.agent(Io::Terminal, &args), refused());
}

#[test]
fn config_import_under_the_agent_is_refused_without_an_op_write() {
    let p = Project::new();
    let args = ["config", "import", "--vault", "vE2ESHAREDDEV00000000000001"];
    assert_eq!(p.agent(Io::Terminal, &args), refused());
}

// --- the commands an agent's shell reaches (pipes, no terminal) ---

#[test]
fn import_under_the_agent_is_refused_without_an_op_write() {
    let p = Project::new();
    let args = ["import", "dev", "--from", "dev.env", "--json"];
    assert_eq!(p.agent(Io::Headless, &args), refused());
}

#[test]
fn sync_under_the_agent_is_refused_without_an_op_write() {
    let p = Project::new();
    assert_eq!(p.agent(Io::Headless, &["sync", "dev", "--json"]), refused());
}

#[test]
fn sync_of_a_confirmed_environment_under_the_agent_is_refused_without_an_op_write() {
    let p = Project::new();
    let args = ["sync", "prod", "--confirm", "prod", "--json"];
    assert_eq!(p.agent(Io::Headless, &args), refused());
}

#[test]
fn sync_under_the_agent_makes_no_call() {
    let p = Project::new();
    let _ = p.agent(Io::Headless, &["sync", "dev", "--json"]);
    assert_eq!(p.calls(), Vec::<String>::new());
}

#[test]
fn sync_under_the_agent_never_suggests_another_identity() {
    let p = Project::new();
    let out = p
        .command(&["sync", "dev"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .output()
        .expect("run opv");
    let printed = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!printed.contains("OPV_IDENTITY"), "{printed}");
}

#[test]
fn sync_under_the_agent_hands_the_deploy_to_a_person_or_ci() {
    let p = Project::new();
    let out = p
        .command(&["sync", "dev"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .output()
        .expect("run opv");
    let printed = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        printed.contains(
            "run it in your own terminal, signed in as yourself, or let CI's deploy job run it"
        ),
        "{printed}"
    );
}
