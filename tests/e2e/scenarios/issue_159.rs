//! #159: `opv --verbose bootstrap --file <f> --project <p> --rebind staging --rebind prod
//! --dry-run --json`, with both environments' values vaults outside the selected account and
//! the state vaults inside it. Expected: one JSON document, `create` for every boundary, `ok`
//! for every state vault; any failure has its own `error.code` and names its call.
//!
//! The reported "You are signed in, but vault access failed … setup vault" came from no
//! bootstrap code: only `opv login`'s own sign-in (`setup::prepare`) wrote it, when the
//! command ran as `opv login --account <id> -- opv … bootstrap …`. That failure happened
//! before the child started, so the child's `--json` and `--verbose` never applied.
//!
//! The world is `tests/e2e/app/world.json` with every values vault moved to the second
//! account; the configuration is the app's, with `dev` renamed `staging`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const APP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/e2e/app");
/// The selected account: it holds the state vaults, not the values vaults.
const SELECTED: &str = "AE2EDEVACCOUNT000000000001";
const OTHER: &str = "AE2EOPSACCOUNT000000000002";

/// A scratch HOME, project and world, and the simulator installed under every tool name.
struct Scenario {
    root: tempfile::TempDir,
}

impl Scenario {
    /// `faults` is the world's `faults.toml` (empty for none).
    fn new(faults: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        let s = Self { root };
        for dir in ["world", "home", "project"] {
            std::fs::create_dir_all(s.root.path().join(dir)).unwrap();
        }
        let mut world: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(Path::new(APP).join("world.json")).unwrap(),
        )
        .unwrap();
        for vault in world["op"]["vaults"].as_array_mut().unwrap() {
            if vault["name"].as_str().unwrap().ends_with(" values") {
                vault["account"] = OTHER.into();
            }
        }
        std::fs::write(s.world().join("world.json"), world.to_string()).unwrap();
        std::fs::write(s.world().join("faults.toml"), faults).unwrap();
        let config = std::fs::read_to_string(Path::new(APP).join("secrets.toml"))
            .unwrap()
            .replace("[environments.dev]", "[environments.staging]")
            .replace("[\"dev\", \"prod\"]", "[\"staging\", \"prod\"]")
            .replace("[\"dev\"]", "[\"staging\"]");
        std::fs::write(s.project().join("fleet.toml"), config).unwrap();
        let bindings = std::fs::read_to_string(Path::new(APP).join("secrets.bindings.toml"))
            .unwrap()
            .replace("environments.dev.", "environments.staging.");
        std::fs::write(s.project().join("secrets.bindings.toml"), bindings).unwrap();
        std::fs::write(
            s.project().join(".opv"),
            format!("account = \"{SELECTED}\"\n"),
        )
        .unwrap();
        let installed = Command::new(env!("CARGO_BIN_EXE_opv-sim"))
            .arg("install")
            .arg(s.bin())
            .env("OPV_SIM_WORLD", s.world())
            .status()
            .unwrap();
        assert!(installed.success());
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

    fn path(&self) -> String {
        format!("{}:/usr/bin:/bin", self.bin().display())
    }

    /// `opv <args>` in the project, against the simulator only.
    fn opv(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_opv"))
            .args(args)
            .current_dir(self.project())
            .env_clear()
            .env("PATH", self.path())
            .env("HOME", self.root.path().join("home"))
            .env("OPV_NO_SKILL", "1")
            .env("OPV_SIM_WORLD", self.world())
            .output()
            .unwrap()
    }
}

/// The command of the report.
const REBOUND: &[&str] = &[
    "--verbose",
    "bootstrap",
    "--file",
    "fleet.toml",
    "--project",
    "e2e-app",
    "--rebind",
    "staging",
    "--rebind",
    "prod",
    "--dry-run",
    "--json",
];

/// Every JSON document on stdout.
fn documents(out: &Output) -> Vec<serde_json::Value> {
    serde_json::Deserializer::from_slice(&out.stdout)
        .into_iter::<serde_json::Value>()
        .collect::<Result<_, _>>()
        .unwrap_or_default()
}

fn document(out: &Output) -> serde_json::Value {
    documents(out).into_iter().next().unwrap_or_default()
}

/// The `action` of every entry of `list` (`boundaries`, `state_vaults`) in every environment.
fn actions(doc: &serde_json::Value, list: &str) -> Vec<String> {
    doc["environments"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|e| e[list].as_array().cloned().unwrap_or_default())
        .map(|b| b["action"].as_str().unwrap_or_default().to_string())
        .collect()
}

#[test]
fn both_environments_rebound_print_one_json_document() {
    let out = Scenario::new("").opv(REBOUND);
    assert_eq!(
        documents(&out).len(),
        1,
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn both_environments_rebound_plan_every_boundary_as_create() {
    let doc = document(&Scenario::new("").opv(REBOUND));
    assert_eq!(actions(&doc, "boundaries"), ["create"; 4]);
}

#[test]
fn both_environments_rebound_find_every_state_vault_ok() {
    let doc = document(&Scenario::new("").opv(REBOUND));
    assert_eq!(actions(&doc, "state_vaults"), ["ok"; 3]);
}

/// op's own reply to `op vault get` decides the cause: "not currently signed in" is a
/// sign-in, never `ids_not_in_account`, even when a bare `op whoami` answers.
const VAULT_GET_SIGNED_OUT: &str =
    "[[fault]]\nprogram = \"op\"\ncall = \"vault get\"\nkind = \"signed_out\"\n";

#[test]
fn a_signed_out_vault_get_is_op_not_signed_in() {
    let doc = document(&Scenario::new(VAULT_GET_SIGNED_OUT).opv(REBOUND));
    assert_eq!(doc["error"]["code"], "op_not_signed_in");
}

/// `--verbose` shows the failing call itself, not only the error.
#[test]
fn a_signed_out_vault_get_shows_its_failing_call_under_verbose() {
    let out = Scenario::new(VAULT_GET_SIGNED_OUT).opv(REBOUND);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr
            .lines()
            .any(|l| l.starts_with("op vault get ") && l.ends_with("exit 1")),
        "{stderr}"
    );
}

/// The reported path: `opv login --account <id> -- opv … bootstrap … --json`, whose own
/// vault list fails before the child runs. Login needs a terminal, so it runs under
/// `script` (util-linux), where stdout and stderr share the terminal.
#[cfg(target_os = "linux")]
#[test]
fn a_login_that_fails_before_its_json_child_answers_with_an_error_code() {
    let s = Scenario::new(
        "[[fault]]\nprogram = \"op\"\ncall = \"vault list\"\nkind = \"signed_out\"\n",
    );
    let opv = env!("CARGO_BIN_EXE_opv");
    let mut line = format!(
        "env -i PATH={} HOME={} OPV_NO_SKILL=1 OPV_SIM_WORLD={} {opv} login --account {SELECTED} -- {opv}",
        s.path(),
        s.root.path().join("home").display(),
        s.world().display()
    );
    for a in REBOUND {
        line.push(' ');
        line.push_str(a);
    }
    let Ok(out) = Command::new("script")
        .args(["-qec", &line, "/dev/null"])
        .current_dir(s.project())
        .stdin(std::process::Stdio::null())
        .output()
    else {
        return; // no `script` on this machine: nothing to run the terminal under
    };
    let transcript = String::from_utf8_lossy(&out.stdout).into_owned();
    let code = transcript
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l.trim()).ok())
        .find_map(|d| d["error"]["code"].as_str().map(str::to_string));
    assert!(code.is_some(), "{transcript}");
}

/// #159 (mig-setup-init): login's own `op vault list` failing with op's "not currently signed
/// in" reply is diagnosed from that reply, `op_not_signed_in`, no longer a Legacy
/// `source_error` worded by setup.
#[cfg(target_os = "linux")]
#[test]
fn a_login_whose_vault_list_is_signed_out_is_op_not_signed_in() {
    let s = Scenario::new(
        "[[fault]]\nprogram = \"op\"\ncall = \"vault list\"\nkind = \"signed_out\"\n",
    );
    let opv = env!("CARGO_BIN_EXE_opv");
    let mut line = format!(
        "env -i PATH={} HOME={} OPV_NO_SKILL=1 OPV_SIM_WORLD={} {opv} login --account {SELECTED} -- {opv}",
        s.path(),
        s.root.path().join("home").display(),
        s.world().display()
    );
    for a in REBOUND {
        line.push(' ');
        line.push_str(a);
    }
    let Ok(out) = Command::new("script")
        .args(["-qec", &line, "/dev/null"])
        .current_dir(s.project())
        .stdin(std::process::Stdio::null())
        .output()
    else {
        return; // no `script` on this machine: nothing to run the terminal under
    };
    let transcript = String::from_utf8_lossy(&out.stdout).into_owned();
    let code = transcript
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l.trim()).ok())
        .find_map(|d| d["error"]["code"].as_str().map(str::to_string));
    assert_eq!(code.as_deref(), Some("op_not_signed_in"), "{transcript}");
}
