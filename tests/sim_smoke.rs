//! `opv-sim` (design §13.1): the simulator answers from its world, copies failure replies
//! from the recordings, applies writes it then loses the reply to, refuses what it does not
//! model, and a real `opv check` runs against it.
#![cfg(all(unix, feature = "fake"))]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const SCENARIO: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/sim/scenarios/check");
const ACCOUNT: &str = "ASIMACCOUNT000000000000001";
const VAULT: &str = "vsimdev00000000000000000001";
const ITEM: &str = "isimdev00000000000000000001";

/// A scenario directory (the `check` world plus `faults`) and a `bin` directory with the
/// simulator installed under every tool name.
struct Sim {
    root: tempfile::TempDir,
}

impl Sim {
    fn new(faults: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        let world = root.path().join("world");
        std::fs::create_dir_all(&world).unwrap();
        std::fs::copy(
            Path::new(SCENARIO).join("world.json"),
            world.join("world.json"),
        )
        .unwrap();
        std::fs::write(world.join("faults.toml"), faults).unwrap();
        let status = Command::new(env!("CARGO_BIN_EXE_opv-sim"))
            .args(["install", root.path().join("bin").to_str().unwrap()])
            .env("OPV_SIM_WORLD", &world)
            .status()
            .unwrap();
        assert!(status.success());
        Self { root }
    }

    fn world_dir(&self) -> PathBuf {
        self.root.path().join("world")
    }

    fn bin(&self) -> PathBuf {
        self.root.path().join("bin")
    }

    /// Run the simulated `tool` with `args` and `stdin`.
    fn run(&self, tool: &str, args: &[&str], stdin: &[u8]) -> Output {
        let mut child = Command::new(self.bin().join(tool))
            .args(args)
            .env_clear()
            .env("OPV_SIM_WORLD", self.world_dir())
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(stdin).unwrap();
        child.wait_with_output().unwrap()
    }

    fn world(&self) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(self.world_dir().join("world.json")).unwrap())
            .unwrap()
    }
}

fn recording(case: &str) -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(case),
    )
    .unwrap()
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[test]
fn op_whoami_answers_for_the_signed_in_account() {
    let out = Sim::new("").run("op", &["whoami", "--format", "json"], b"");
    let who: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(who["account_uuid"], ACCOUNT);
}

#[test]
fn a_signed_out_fault_replies_with_the_recorded_stderr() {
    let sim = Sim::new("[[fault]]\nprogram = \"op\"\ncall = \"whoami\"\nkind = \"signed_out\"\n");
    let out = sim.run(
        "op",
        &["whoami", "--account", ACCOUNT, "--format", "json"],
        b"",
    );
    let expected =
        recording("op/failures/05-signed-out-whoami.stderr").replace("<ACCOUNT_2>", ACCOUNT);
    assert_eq!((out.status.code(), text(&out.stderr)), (Some(1), expected));
}

#[test]
fn flyctl_secrets_list_of_a_missing_app_replies_with_the_recorded_not_found() {
    let out = Sim::new("").run(
        "flyctl",
        &["secrets", "list", "--app", "no-such-app", "--json"],
        b"",
    );
    assert_eq!(
        (out.status.code(), text(&out.stderr)),
        (
            Some(1),
            recording("fly/failures/06-app-not-found-secrets-list.stderr")
        )
    );
}

#[test]
fn an_applied_write_whose_reply_is_lost_stays_in_the_world() {
    let sim = Sim::new(
        "[[fault]]\nprogram = \"op\"\ncall = \"item edit\"\nkind = \"applied_but_reply_lost\"\n",
    );
    let mut item = sim.world()["op"]["items"][0].clone();
    item["fields"][1]["value"] = "test-marker-edited".into();
    sim.run(
        "op",
        &["item", "edit", ITEM, "--vault", VAULT, "--format", "json"],
        &serde_json::to_vec(&item).unwrap(),
    );
    assert_eq!(
        sim.world()["op"]["items"][0]["fields"][1]["value"],
        "test-marker-edited"
    );
}

#[test]
fn an_unsupported_command_fails_loudly() {
    let out = Sim::new("").run("op", &["document", "get", "x"], b"");
    assert_eq!(
        (out.status.code(), text(&out.stderr)),
        (
            Some(87),
            "opv-sim: unsupported op document get x\n".to_string()
        )
    );
}

#[test]
fn opv_check_passes_against_the_simulated_op() {
    let sim = Sim::new("");
    let project = sim.root.path().join("project");
    let home = sim.root.path().join("home");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::copy(
        Path::new(SCENARIO).join("secrets.toml"),
        project.join("secrets.toml"),
    )
    .unwrap();
    // The project's account, so no `.opv` above the temp directory is read.
    std::fs::write(project.join(".opv"), format!("account = \"{ACCOUNT}\"\n")).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_opv"))
        .args(["--config", "secrets.toml", "check", "dev"])
        .current_dir(&project)
        .env_clear()
        .env("PATH", format!("{}:/usr/bin:/bin", sim.bin().display()))
        .env("HOME", &home)
        .env("OPV_NO_SKILL", "1")
        .env("OPV_SIM_WORLD", sim.world_dir())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}{}",
        text(&out.stdout),
        text(&out.stderr)
    );
}
