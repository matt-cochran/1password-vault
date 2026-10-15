//! `opv env add`, `opv structure plan`, `opv structure apply` and `opv config describe`
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
fn structure_plan_text_points_at_the_approve_command() {
    let (_d, path, op) = workspace();
    let mut buf = Vec::new();
    plan_scoped(&op, &scope_of(&path), false, &mut buf).unwrap();
    let id = plan_id_of(&path, &op);
    assert!(
        String::from_utf8(buf)
            .unwrap()
            .contains(&format!("opv approve {id}"))
    );
}

// structure apply --------------------------------------------------------------------------

fn refuse(name: &str) -> Result<(), Error> {
    Err(Error::Policy(format!("no approval for {name}").into()).with_code(Code::ApprovalRequired))
}

#[test]
fn structure_apply_without_approval_is_refused() {
    let (_d, path, op) = workspace();
    let id = plan_id_of(&path, &op);
    let e = apply_authorized(
        &op,
        &scope_of(&path),
        &id,
        &mut |_| refuse(&id),
        false,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(e.code(), Code::ApprovalRequired);
}

#[test]
fn a_refused_apply_creates_no_vault() {
    let (_d, path, op) = workspace();
    let id = plan_id_of(&path, &op);
    let _ = apply_authorized(
        &op,
        &scope_of(&path),
        &id,
        &mut |_| refuse(&id),
        false,
        &mut Vec::new(),
    );
    assert_eq!(op.count(&["op", "vault", "create"]), 0);
}

#[test]
fn a_stale_plan_is_refused() {
    let (_d, path, op) = workspace();
    let id = plan_id_of(&path, &op);
    std::fs::write(&path, format!("{CONFIG}\n# changed\n")).unwrap();
    let e = apply_authorized(
        &op,
        &scope_of(&path),
        &id,
        &mut |_| Ok(()),
        false,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(e.code(), Code::StalePlan);
}

#[test]
fn a_stale_plan_names_the_new_plan_id_in_its_next_step() {
    let (_d, path, op) = workspace();
    let id = plan_id_of(&path, &op);
    std::fs::write(&path, format!("{CONFIG}\n# changed\n")).unwrap();
    let new = plan_id_of(&path, &op);
    let e = apply_authorized(
        &op,
        &scope_of(&path),
        &id,
        &mut |_| Ok(()),
        false,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert!(e.next_step().unwrap_or_default().contains(&new));
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
