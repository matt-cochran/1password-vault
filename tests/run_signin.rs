//! #266: `opv run` signed out, as the real binary with a fake `op` on PATH. Without a
//! terminal (an agent shell, no CLI session, no desktop app) the run stops before `op run`
//! with opv's typed sign-in step and none of op's own advice. At a terminal (a `script(1)`
//! PTY) opv signs in at op's prompt and replays the run in the same process: `op run` gets
//! the fresh session, and the app (behind opv's local delivery step) does not (design
//! agent-signin-readiness §2.2 item 4, FMECA item 4, E14b). Test markers only: the session
//! is a fake canary, never a real credential.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

/// The fake session `op signin` prints (never a real one).
const CANARY: &str = "SESSIONCANARY0replay266";

/// Like op 2.40.0: every call without an `OP_SESSION_*` fails as op does when signed out,
/// except `signin`, which prints the session line. With a session, the item read is empty
/// under a service-account identity (nothing to tidy) and `run` execs the command after
/// `--` with the environment it was given, as `op run` does. Each call's first word and
/// whether it had a session go to `LOG` (names only).
const FAKE_OP: &str = r#"#!/bin/sh
signed=no
for v in $(env | cut -d= -f1); do case "$v" in OP_SESSION_*) signed=yes ;; esac; done
echo "$1 $signed" >> "LOG"
case "$1" in
  --version) echo 2.40.0; exit 0 ;;
  signin) echo 'export OP_SESSION_canaryacct="CANARY"'; exit 0 ;;
  account) echo '[]'; exit 0 ;;
esac
if [ "$signed" = no ]; then
  echo "[ERROR] 2026/11/04 10:00:00 You are not currently signed in. Please run \`op signin --help\` for instructions" >&2
  exit 1
fi
case "$1" in
  item) echo '{"fields":[]}'; exit 0 ;;
  whoami) echo '{"user_type":"SERVICE_ACCOUNT"}'; exit 0 ;;
  run) ;;
  *) echo '[]'; exit 0 ;;
esac
while [ "$1" != -- ]; do shift; done
shift
exec "$@"
"#;

const CONFIG: &str = "[environments.dev]\nboundaries.plain = {}\n\
    [products.plain.keys.API_TOKEN]\nkind = \"secret\"\n";

const BINDINGS: &str = "environments.dev.boundaries.plain.vault_id = \"v1\"\n\
    environments.dev.boundaries.plain.item_id = \"i1\"\n";

/// A project with the fake `op` in `bin/`; the fake logs to `op.log`.
struct World {
    root: tempfile::TempDir,
}

impl World {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let log = root.path().join("op.log");
        let script = FAKE_OP
            .replace("LOG", log.to_str().unwrap())
            .replace("CANARY", CANARY);
        // Written to a temporary name and renamed, so no other thread's fork holds it open
        // for writing when it is executed (ETXTBSY).
        let tmp = bin.join("op.tmp");
        std::fs::write(&tmp, script).unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::rename(&tmp, bin.join("op")).unwrap();
        // Found by discovery from the working directory, so no `--config` joins the step.
        std::fs::write(root.path().join("secrets.toml"), CONFIG).unwrap();
        std::fs::write(root.path().join("secrets.bindings.toml"), BINDINGS).unwrap();
        World { root }
    }

    fn path(&self) -> &Path {
        self.root.path()
    }

    /// The fake's log lines (`<first word> <yes|no>`).
    fn log(&self) -> Vec<String> {
        std::fs::read_to_string(self.path().join("op.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// The `op run` calls, with whether each had a session.
    fn op_runs(&self) -> Vec<String> {
        self.log()
            .into_iter()
            .filter(|l| l.starts_with("run "))
            .collect()
    }

    /// A clean environment: the fake `op` first on PATH, no CI, no 1Password variable.
    fn command(&self, program: &str) -> Command {
        let mut cmd = Command::new(program);
        cmd.env_clear()
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.path().join("bin").display()),
            )
            .env("HOME", self.path())
            .env("TERM", "dumb")
            .env("OPV_NO_SKILL", "1")
            .current_dir(self.path());
        cmd
    }

    /// `opv run dev --product plain -- <child>` with no terminal: stdin `/dev/null`,
    /// stdout and stderr pipes.
    fn headless(&self, child: &[&str]) -> Output {
        self.command(env!("CARGO_BIN_EXE_opv"))
            .args(["run", "dev", "--product", "plain", "--"])
            .args(child)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    /// The same run at a terminal: inside a `script(1)` PTY. `None` without `script`.
    fn at_terminal(&self, child: &str) -> Option<Output> {
        // `-qec <cmd> <file>` is util-linux `script`; BSD/macOS `script` takes other flags.
        if !cfg!(target_os = "linux") {
            return None;
        }
        let script = ["/usr/bin/script", "/bin/script"]
            .into_iter()
            .find(|p| Path::new(p).exists())?;
        let line = format!(
            "{} run dev --product plain -- {child}",
            env!("CARGO_BIN_EXE_opv")
        );
        Some(
            self.command(script)
                .args(["-qec", &line, "/dev/null"])
                .env("SHELL", "/bin/sh")
                .stdin(Stdio::null())
                .output()
                .unwrap(),
        )
    }
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

// ---- headless (E11-E13): typed, no prompt, no op advice ---------------------------------

#[test]
fn a_headless_signed_out_run_exits_7() {
    let w = World::new();
    assert_eq!(w.headless(&["true"]).status.code(), Some(7));
}

#[test]
fn a_headless_signed_out_run_never_starts_op_run() {
    let w = World::new();
    let _ = w.headless(&["true"]);
    assert_eq!(w.op_runs(), Vec::<String>::new());
}

#[test]
fn a_headless_signed_out_run_never_shows_ops_advice() {
    let w = World::new();
    let err = stderr(&w.headless(&["true"]));
    assert!(!err.contains("op signin --help"), "{err}");
}

#[test]
fn a_headless_signed_out_run_steps_to_login_with_a_placeholder() {
    let w = World::new();
    let err = stderr(&w.headless(&["printf", "child-words-266"]));
    assert_eq!(
        err.lines().last(),
        Some("Next: opv login -- opv run dev --product plain -- <command>"),
        "{err}"
    );
}

/// SR-3: the child's words may hold a credential; the step never repeats them.
#[test]
fn a_headless_signed_out_run_never_repeats_the_childs_words() {
    let w = World::new();
    let err = stderr(&w.headless(&["printf", "child-words-266"]));
    assert!(!err.contains("child-words-266"), "{err}");
}

// ---- at a terminal (E14, E14b, E15): sign in, replay once ----------------------------------

#[test]
fn a_terminal_run_signs_in_and_starts_op_run_once() {
    let w = World::new();
    if w.at_terminal("true").is_none() {
        return;
    }
    assert_eq!(w.op_runs().len(), 1, "{:?}", w.log());
}

/// E14b, the env canary: `op run` received the fresh session (above), and the app,
/// started behind opv's local delivery step, never sees it.
#[test]
fn a_replayed_runs_app_never_sees_the_fresh_session() {
    let w = World::new();
    let Some(out) = w.at_terminal("env") else {
        return;
    };
    let seen = String::from_utf8_lossy(&out.stdout);
    assert!(
        seen.contains("API_TOKEN=op://") && !seen.contains(CANARY),
        "the app's environment holds the key: {}, and no session: {}",
        seen.contains("API_TOKEN=op://"),
        !seen.contains(CANARY)
    );
}

/// The fresh session reached `op run`'s own environment (the canary's positive partner).
#[test]
fn a_replayed_op_run_carries_the_fresh_session() {
    let w = World::new();
    if w.at_terminal("true").is_none() {
        return;
    }
    assert_eq!(w.op_runs().first().map(String::as_str), Some("run yes"));
}

#[test]
fn a_replayed_run_passes_the_childs_exit_code() {
    let w = World::new();
    let Some(out) = w.at_terminal("sh -c 'exit 3'") else {
        return;
    };
    assert_eq!(out.status.code(), Some(3));
}
