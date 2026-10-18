//! `opv env add`, `opv structure plan` and `opv config describe`
//! (j8): the same work and the same documents as their MCP tools.

use super::*;
use crate::adapters::fake_op::FakeOp;
use crate::app::structure;
use crate::runner::CommandRunner;
use std::path::{Path, PathBuf};

const ACCOUNT: &str = "ACCOUNTAAA000000000000AAAA";
const VAULT_ID: &str = "vdev0000000000000000000001";
const ITEM_ID: &str = "item00000000000000000aaaaaa";
const CONFIG: &str = r#"[environments.dev]

[products.web]
boundary = "core"

[products.web.keys.SESSION_KEY]
kind = "secret"
environments = ["dev"]
"#;

fn workspace() -> (tempfile::TempDir, PathBuf, FakeOp) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.toml");
    std::fs::write(&path, CONFIG).unwrap();
    (dir, path, FakeOp::default())
}

fn scope_of(path: &Path) -> Scope {
    Scope {
        path: path.to_path_buf(),
        project: "myapp".into(),
        account: ACCOUNT.into(),
    }
}

fn plan_id_of(path: &Path, op: &dyn CommandRunner) -> String {
    let text = std::fs::read_to_string(path).unwrap();
    structure::plan(op, &text, "myapp", ACCOUNT)
        .unwrap()
        .plan_id
}

// env add ----------------------------------------------------------------------------------

#[test]
fn env_add_declares_the_environment_in_secrets_toml() {
    let (dir, path, op) = workspace();
    env_add(&op, dir.path(), "staging", false, &mut Vec::new()).unwrap();
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .contains("[environments.staging]")
    );
}

#[test]
fn env_add_again_reports_no_change() {
    let (dir, _path, op) = workspace();
    env_add(&op, dir.path(), "staging", false, &mut Vec::new()).unwrap();
    let mut buf = Vec::new();
    env_add(&op, dir.path(), "staging", false, &mut buf).unwrap();
    assert!(String::from_utf8(buf).unwrap().contains("nothing changed"));
}

#[test]
fn env_add_json_marks_the_change() {
    let (dir, _path, op) = workspace();
    let mut buf = Vec::new();
    env_add(&op, dir.path(), "staging", true, &mut buf).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&buf).unwrap()["changed"],
        true
    );
}

// structure plan ---------------------------------------------------------------------------

#[test]
fn structure_plan_json_is_the_shared_projection() {
    let (_d, path, op) = workspace();
    let mut buf = Vec::new();
    plan_scoped(&op, &scope_of(&path), true, &mut buf).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    let p = structure::plan(&op, &text, "myapp", ACCOUNT).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&buf).unwrap(),
        agent_view::plan_projection(&p)
    );
}

#[test]
fn structure_plan_text_points_at_opv_apply() {
    let (_d, path, op) = workspace();
    let mut buf = Vec::new();
    plan_scoped(&op, &scope_of(&path), false, &mut buf).unwrap();
    assert!(
        String::from_utf8(buf)
            .unwrap()
            .ends_with("Next: opv apply\n")
    );
}

// config describe --------------------------------------------------------------------------

const LINKED: &str = r#"[environments.dev]
boundaries.core = { vault_id = "vdev0000000000000000000001", item_id = "item00000000000000000aaaaaa" }

[environments.dev.targets.web]
fly.app = "myapp-web-dev"
fly.secret_name = "MYAPP__WEB__{KEY}"
state_vault_id = "vdev0000000000000000000009"
products = ["web"]

[products.web]
boundary = "core"

[products.web.keys.SESSION_KEY]
kind = "secret"
environments = ["dev"]
"#;

#[test]
fn config_describe_json_has_no_vault_or_item_id() {
    let fleet = crate::config::parse(LINKED).unwrap();
    let mut buf = Vec::new();
    config_describe(&fleet, true, &mut buf).unwrap();
    let text = String::from_utf8(buf).unwrap();
    assert!(
        !text.contains(VAULT_ID) && !text.contains(ITEM_ID),
        "{text}"
    );
}

#[test]
fn config_describe_text_names_the_environment_and_key() {
    let fleet = crate::config::parse(LINKED).unwrap();
    let mut buf = Vec::new();
    config_describe(&fleet, false, &mut buf).unwrap();
    let text = String::from_utf8(buf).unwrap();
    assert!(text.contains("environment dev") && text.contains("key web/SESSION_KEY secret"));
}

// 0.10.0 error catalog (05.12, 05.13, 05.37) -----------------------------------------------

/// Apply the current plan, authorized by a closure as `opv apply` does (no approval file).
fn apply_plan(path: &Path, op: &FakeOp) {
    let id = plan_id_of(path, op);
    structure::apply(op, path, "myapp", ACCOUNT, &id, &mut |_| Ok(())).unwrap();
}

/// 05.13: a complete structure has nothing to approve.
#[test]
fn a_complete_structure_plan_steps_to_ready() {
    let (_d, path, op) = workspace();
    apply_plan(&path, &op);
    let mut buf = Vec::new();
    plan_scoped(&op, &scope_of(&path), false, &mut buf).unwrap();
    assert!(
        String::from_utf8(buf)
            .unwrap()
            .ends_with("Next: opv ready\n")
    );
}

/// 05.37: the environment being added is named in the step, never a placeholder.
#[test]
fn env_add_without_a_file_steps_to_init_of_that_environment() {
    let dir = tempfile::tempdir().unwrap();
    let e = env_add(
        &FakeOp::default(),
        dir.path(),
        "staging",
        false,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(e.next_text().unwrap_or_default(), "opv init staging");
}
