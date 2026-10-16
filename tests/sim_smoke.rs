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

    /// Replace the world's `op` section with `op`.
    fn with_op(self, op: serde_json::Value) -> Self {
        let mut world = self.world();
        world["op"] = op;
        std::fs::write(
            self.world_dir().join("world.json"),
            serde_json::to_vec(&world).unwrap(),
        )
        .unwrap();
        self
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

/// The success recording `case` (`op/success/<case>.stdout`) parsed.
fn success(case: &str) -> serde_json::Value {
    serde_json::from_str(&recording(&format!("op/success/{case}.stdout"))).unwrap()
}

/// The field names of a JSON object, in order.
fn keys(v: &serde_json::Value) -> Vec<String> {
    v.as_object().unwrap().keys().cloned().collect()
}

/// A world whose account, vault, item and vault user hold the recordings' own marker values,
/// so the simulator's reply can be compared with a recording byte for byte.
fn recorded_world() -> serde_json::Value {
    serde_json::json!({
        "default_account": "<ACCOUNT_2>",
        "accounts": [
            {"id": "<ACCOUNT_1>", "shorthand": "<SHORTHAND_1>", "url": "<ADDRESS_1>",
             "email": "<EMAIL_1>", "user": "<USER_1>", "user_type": "HUMAN", "signed_in": false},
            {"id": "<ACCOUNT_2>", "shorthand": "<SHORTHAND_2>", "url": "<ADDRESS_1>",
             "email": "<EMAIL_2>", "user": "<USER_2>", "user_type": "HUMAN", "signed_in": true}
        ],
        "vaults": [{"id": "<ID_3>", "name": "<NAME_3>", "account": "<ACCOUNT_2>",
                    "content_version": 2, "created_at": "<TIME_5>", "updated_at": "<TIME_6>",
                    "description": "<DESCRIPTION_1>", "attribute_version": 1,
                    "type": "USER_CREATED",
                    "users": [{"id": "<USER_2>", "name": "<NAME_8>", "email": "<EMAIL_2>",
                               "type": "MEMBER", "state": "ACTIVE",
                               "permissions": ["allow_viewing", "allow_editing",
                                               "allow_managing"]}]}],
        "items": [{"id": "<ID_8>", "title": "<TITLE_1>", "tags": ["<TAG_1>"], "version": 1,
                   "vault": {"id": "<ID_3>", "name": "<NAME_3>"}, "category": "SECURE_NOTE",
                   "created_at": "<TIME_6>", "updated_at": "<TIME_6>",
                   "additional_information": "<INFO_1>",
                   "fields": [{"id": "notesPlain", "type": "STRING", "purpose": "NOTES",
                               "label": "notesPlain", "value": "test-marker-recorded"}]}]
    })
}

#[test]
fn op_whoami_answers_for_the_signed_in_account() {
    let out = Sim::new("").run("op", &["whoami", "--format", "json"], b"");
    let who: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(who["account_uuid"], ACCOUNT);
}

#[test]
fn op_vault_list_reply_has_exactly_the_recorded_field_set() {
    let out = Sim::new("").run("op", &["vault", "list", "--format", "json"], b"");
    let reply: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(keys(&reply[0]), keys(&success("s02-vault-list")[0]));
}

#[test]
fn op_vault_list_reply_has_one_row_per_world_vault() {
    let out = Sim::new("").run("op", &["vault", "list", "--format", "json"], b"");
    let reply: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(reply.as_array().map(Vec::len), Some(1));
}

#[test]
fn op_vault_list_reply_counts_the_world_items_in_each_vault() {
    let out = Sim::new("").run("op", &["vault", "list", "--format", "json"], b"");
    let reply: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(reply[0]["items"], 1);
}

#[test]
fn op_vault_get_reply_has_the_world_vault_id() {
    let out = Sim::new("").run("op", &["vault", "get", VAULT, "--format", "json"], b"");
    let reply: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(reply["id"], VAULT);
}

#[test]
fn op_vault_get_of_the_recorded_vault_is_the_recording_byte_for_byte() {
    let sim = Sim::new("").with_op(recorded_world());
    let out = sim.run("op", &["vault", "get", "<ID_3>", "--format", "json"], b"");
    assert_eq!(
        text(&out.stdout),
        recording("op/success/s03-vault-get.stdout")
    );
}

#[test]
fn op_vault_user_list_of_the_recorded_vault_is_the_recording_byte_for_byte() {
    let sim = Sim::new("").with_op(recorded_world());
    let out = sim.run(
        "op",
        &["vault", "user", "list", "<ID_3>", "--format", "json"],
        b"",
    );
    assert_eq!(
        text(&out.stdout),
        recording("op/success/s04-vault-user-list.stdout")
    );
}

#[test]
fn op_item_list_of_the_recorded_vault_is_the_recording_byte_for_byte() {
    let sim = Sim::new("").with_op(recorded_world());
    let out = sim.run(
        "op",
        &["item", "list", "--vault", "<ID_3>", "--format", "json"],
        b"",
    );
    assert_eq!(
        text(&out.stdout),
        recording("op/success/s05-item-list.stdout")
    );
}

#[test]
fn op_item_list_reply_has_exactly_the_recorded_field_set() {
    let out = Sim::new("").run(
        "op",
        &["item", "list", "--vault", VAULT, "--format", "json"],
        b"",
    );
    let reply: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(keys(&reply[0]), keys(&success("s05-item-list")[0]));
}

#[test]
fn op_account_list_of_the_recorded_accounts_is_the_recording_byte_for_byte() {
    let sim = Sim::new("").with_op(recorded_world());
    let out = sim.run("op", &["account", "list", "--format", "json"], b"");
    assert_eq!(
        text(&out.stdout),
        recording("op/success/s01-account-list.stdout")
    );
}

#[test]
fn op_whoami_of_the_recorded_account_is_the_default_recording_byte_for_byte() {
    let sim = Sim::new("").with_op(recorded_world());
    let out = sim.run("op", &["whoami", "--format", "json"], b"");
    assert_eq!(
        text(&out.stdout),
        recording("op/success/s07-whoami-default.stdout")
    );
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

/// R2-1 (snapshot review): `op vault list` names no vault, so no `not_found` reply is
/// recorded for it (opv-sim exit 86), never a `vault get` reply about a vault named `list`.
#[test]
fn a_not_found_on_op_vault_list_has_no_recording() {
    let sim =
        Sim::new("[[fault]]\nprogram = \"op\"\ncall = \"vault list\"\nkind = \"not_found\"\n");
    let out = sim.run("op", &["vault", "list", "--format", "json"], b"");
    assert_eq!(out.status.code(), Some(86));
}

/// R2-5 (snapshot review): a `not_found` on a listing in a GitHub environment is that
/// environment missing, so the repository's environments read no longer lists it.
#[test]
fn a_not_found_on_a_github_environment_listing_removes_the_environment() {
    let sim =
        Sim::new("[[fault]]\nprogram = \"gh\"\ncall = \"secret list\"\nkind = \"not_found\"\n");
    let mut world = sim.world();
    world["github"] = serde_json::json!({"repos": {"o/r": {"secrets": {}, "variables": {},
        "environments": {"production": {"secrets": {}, "variables": {}}}}}});
    std::fs::write(
        sim.world_dir().join("world.json"),
        serde_json::to_vec(&world).unwrap(),
    )
    .unwrap();
    sim.run(
        "gh",
        &[
            "secret",
            "list",
            "-R",
            "o/r",
            "-e",
            "production",
            "--json",
            "name,updatedAt",
        ],
        b"",
    );
    assert_eq!(
        sim.world()["github"]["repos"]["o/r"]["environments"],
        serde_json::json!({})
    );
}

/// An environment marked `listed_after_not_found` keeps its place after the 404, so a
/// scenario can reach the reply opv does not recognise.
#[test]
fn a_not_found_leaves_an_environment_marked_listed_after_not_found() {
    let sim =
        Sim::new("[[fault]]\nprogram = \"gh\"\ncall = \"secret list\"\nkind = \"not_found\"\n");
    let mut world = sim.world();
    world["github"] = serde_json::json!({"repos": {"o/r": {"secrets": {}, "variables": {},
        "environments": {"production": {"secrets": {}, "variables": {},
        "listed_after_not_found": true}}}}});
    std::fs::write(
        sim.world_dir().join("world.json"),
        serde_json::to_vec(&world).unwrap(),
    )
    .unwrap();
    sim.run(
        "gh",
        &[
            "secret",
            "list",
            "-R",
            "o/r",
            "-e",
            "production",
            "--json",
            "name,updatedAt",
        ],
        b"",
    );
    assert!(sim.world()["github"]["repos"]["o/r"]["environments"]["production"].is_object());
}

/// A second `not_found` in an environment already removed answers the same recorded 404.
#[test]
fn a_second_not_found_in_a_removed_environment_answers_the_recorded_404() {
    let sim =
        Sim::new("[[fault]]\nprogram = \"gh\"\ncall = \"secret list\"\nkind = \"not_found\"\n");
    let mut world = sim.world();
    world["github"] = serde_json::json!({"repos": {"o/r": {"secrets": {}, "variables": {},
        "environments": {"production": {"secrets": {}, "variables": {}}}}}});
    std::fs::write(
        sim.world_dir().join("world.json"),
        serde_json::to_vec(&world).unwrap(),
    )
    .unwrap();
    let list = [
        "secret",
        "list",
        "-R",
        "o/r",
        "-e",
        "production",
        "--json",
        "name,updatedAt",
    ];
    sim.run("gh", &list, b"");
    assert_eq!(sim.run("gh", &list, b"").status.code(), Some(1));
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
