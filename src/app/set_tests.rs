//! `opv set` (design row `set-cmd`): one atomic test per outcome, through the public
//! `set` seam with the stateful fake `op`. No test asserts on private implementation or
//! call sequence.

use super::*;
use crate::adapters::fake_op::FakeOp;
use crate::host::FakeEnv;

const MARK: &str = "sk-proj-SETMARKER-new";

/// A dev environment on the fake's `myapp-dev` vault: api/OPENAI_API_KEY (secret, empty,
/// a `sk-` prefix rule).
fn world() -> (FakeOp, Fleet) {
    let op = FakeOp::default();
    let id = op.insert(
        "vdev0000000000000000000001",
        serde_json::json!({
            "title": "myapp · dev values", "category": "SECURE_NOTE",
            "sections": [{"id": "api", "label": "api"}],
            "fields": [
                {"id": "f1", "section": {"id": "api", "label": "api"}, "type": "CONCEALED",
                 "label": "OPENAI_API_KEY", "value": ""}
            ]
        }),
    );
    let fleet = crate::config::parse(&format!(
        "[environments.dev]\nboundaries.api = {{ vault_id = \"vdev0000000000000000000001\", \
         item_id = \"{id}\" }}\n[products.api.keys.OPENAI_API_KEY]\nkind = \"secret\"\n\
         environments = [\"dev\"]\nrules = {{ prefix = \"sk-\" }}\n"
    ))
    .unwrap();
    (op, fleet)
}

/// The value of the key's field in the fake's item.
fn field_in(op: &FakeOp, id: &str, label: &str) -> String {
    op.item(id)["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["label"] == label)
        .and_then(|f| f["value"].as_str())
        .unwrap_or_default()
        .to_string()
}

/// A prompt that answers with `value`.
fn accepting(value: &str) -> impl FnMut(&str) -> Result<Option<SecretValue>, Error> + '_ {
    move |_| Ok(Some(SecretValue::new(value.to_string())))
}

#[test]
fn agent_mode_refuses_with_person_only_before_prompting() {
    let (op, fleet) = world();
    let env = FakeEnv::new("linux").mcp();
    let mut never = |_: &str| -> Result<Option<SecretValue>, Error> { panic!("prompted") };
    let err = set(
        &fleet,
        &env,
        "api/OPENAI_API_KEY",
        "dev",
        &mut never,
        &op,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(err.code_str(), "person_only");
}

#[test]
fn a_non_tty_refuses_the_terminal_before_prompting() {
    let (op, fleet) = world();
    let env = FakeEnv::new("linux");
    let mut never = |_: &str| -> Result<Option<SecretValue>, Error> { panic!("prompted") };
    let err = set(
        &fleet,
        &env,
        "api/OPENAI_API_KEY",
        "dev",
        &mut never,
        &op,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(err.code_str(), "terminal_required");
}

#[test]
fn an_accepted_value_is_written_to_the_field() {
    let (op, fleet) = world();
    let id = fleet.environments["dev"].boundaries["api"]
        .as_ref()
        .unwrap()
        .item_id
        .clone();
    set(
        &fleet,
        &FakeEnv::new("linux").tty(),
        "api/OPENAI_API_KEY",
        "dev",
        &mut accepting(MARK),
        &op,
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(field_in(&op, &id, "OPENAI_API_KEY"), MARK);
}

#[test]
fn the_entered_value_is_in_no_process_argument() {
    let (op, fleet) = world();
    set(
        &fleet,
        &FakeEnv::new("linux").tty(),
        "api/OPENAI_API_KEY",
        "dev",
        &mut accepting(MARK),
        &op,
        &mut Vec::new(),
    )
    .unwrap();
    assert!(
        !op.calls
            .borrow()
            .iter()
            .any(|c| c.args.iter().any(|a| a.contains(MARK)))
    );
}

#[test]
fn the_output_names_the_new_state_set() {
    let (op, fleet) = world();
    let mut out = Vec::new();
    set(
        &fleet,
        &FakeEnv::new("linux").tty(),
        "api/OPENAI_API_KEY",
        "dev",
        &mut accepting(MARK),
        &op,
        &mut out,
    )
    .unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "set\n");
}

#[test]
fn a_cancelled_prompt_writes_nothing() {
    let (op, fleet) = world();
    let mut cancel = |_: &str| -> Result<Option<SecretValue>, Error> { Ok(None) };
    set(
        &fleet,
        &FakeEnv::new("linux").tty(),
        "api/OPENAI_API_KEY",
        "dev",
        &mut cancel,
        &op,
        &mut Vec::new(),
    )
    .unwrap();
    assert!(op.calls.borrow().is_empty());
}

#[test]
fn an_undeclared_key_is_refused() {
    let (op, fleet) = world();
    let mut never = |_: &str| -> Result<Option<SecretValue>, Error> { panic!("prompted") };
    let err = set(
        &fleet,
        &FakeEnv::new("linux").tty(),
        "api/NOPE",
        "dev",
        &mut never,
        &op,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(err.code_str(), "undeclared_key");
}

// Infrastructure keys (#206 §4.4) ----------------------------------------------------------

/// prod with a Fly target delivering api, whose api/DATABASE_URL is an infrastructure key.
fn infrastructure_fleet() -> Fleet {
    crate::config::parse(
        r#"[environments.prod]
boundaries.api = { vault_id = "vprod", item_id = "iprodapi" }

[environments.prod.targets.web]
fly.app = "web-prod"
fly.secret_name = "{KEY}"
products = ["api"]
state_vault_id = "sprod"

[products.api.keys.DATABASE_URL]
kind = "secret"
source = "infrastructure"
environments = ["prod"]
rules = { regex = "postgres(ql)?://.+" }
"#,
    )
    .unwrap()
}

#[test]
fn an_infrastructure_key_is_refused_as_not_stored_before_prompting() {
    let fleet = infrastructure_fleet();
    let mut never = |_: &str| -> Result<Option<SecretValue>, Error> { panic!("prompted") };
    let err = set(
        &fleet,
        &FakeEnv::new("linux").tty(),
        "api/DATABASE_URL",
        "prod",
        &mut never,
        &FakeOp::default(),
        &mut Vec::new(),
    )
    .unwrap_err();
    let doc = crate::error::document(&err, &crate::error::invocation(), false);
    assert_eq!(doc["subject"]["guard"]["guard"], "not_stored");
}

// `opv set --from-file` (#217) -------------------------------------------------------------

/// A dev environment on the fake's `myapp-dev` vault: api/PEM (secret, a file key).
fn file_world() -> (FakeOp, Fleet) {
    let op = FakeOp::default();
    let id = op.insert(
        "vdev0000000000000000000001",
        serde_json::json!({
            "title": "myapp · dev values", "category": "SECURE_NOTE",
            "sections": [{"id": "api", "label": "api"}],
            "fields": [
                {"id": "f1", "section": {"id": "api", "label": "api"}, "type": "CONCEALED",
                 "label": "PEM", "value": ""}
            ]
        }),
    );
    let fleet = crate::config::parse(&format!(
        "[environments.dev]\nboundaries.api = {{ vault_id = \"vdev0000000000000000000001\", \
         item_id = \"{id}\" }}\n[products.api.keys.PEM]\nkind = \"secret\"\n\
         file = \"private-key\"\nenvironments = [\"dev\"]\n"
    ))
    .unwrap();
    (op, fleet)
}

/// The item id the dev environment's api boundary is bound to.
fn boundary_item(fleet: &Fleet) -> String {
    fleet.environments["dev"].boundaries["api"]
        .as_ref()
        .unwrap()
        .item_id
        .clone()
}

#[test]
fn a_multi_line_file_is_written_byte_for_byte() {
    let (op, fleet) = file_world();
    let id = boundary_item(&fleet);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private-key.pem");
    std::fs::write(&path, "line one\nline two\n").unwrap();
    set_from_file(
        &fleet,
        &FakeEnv::new("linux").tty(),
        "api/PEM",
        "dev",
        &path,
        &op,
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(field_in(&op, &id, "PEM"), "line one\nline two\n");
}

#[test]
fn a_non_file_key_is_refused() {
    let (op, fleet) = world();
    let err = set_from_file(
        &fleet,
        &FakeEnv::new("linux").tty(),
        "api/OPENAI_API_KEY",
        "dev",
        std::path::Path::new("/nonexistent/never"),
        &op,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(err.code_str(), "usage");
}

#[cfg(unix)]
#[test]
fn a_symlink_is_refused() {
    let (op, fleet) = file_world();
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("real.pem");
    std::fs::write(&target, "x\n").unwrap();
    let link = dir.path().join("link.pem");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let err = set_from_file(
        &fleet,
        &FakeEnv::new("linux").tty(),
        "api/PEM",
        "dev",
        &link,
        &op,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(err.code_str(), "input_invalid");
}

#[test]
fn a_directory_is_refused() {
    let (op, fleet) = file_world();
    let dir = tempfile::tempdir().unwrap();
    let err = set_from_file(
        &fleet,
        &FakeEnv::new("linux").tty(),
        "api/PEM",
        "dev",
        dir.path(),
        &op,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(err.code_str(), "input_invalid");
}

#[test]
fn a_file_over_the_cap_is_refused() {
    let (op, fleet) = file_world();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.pem");
    std::fs::write(&path, vec![b'a'; FROM_FILE_MAX_BYTES as usize + 1]).unwrap();
    let err = set_from_file(
        &fleet,
        &FakeEnv::new("linux").tty(),
        "api/PEM",
        "dev",
        &path,
        &op,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(err.code_str(), "input_invalid");
}

#[test]
fn agent_mode_is_refused_before_the_file_is_read() {
    let (op, fleet) = file_world();
    let err = set_from_file(
        &fleet,
        &FakeEnv::new("linux").mcp(),
        "api/PEM",
        "dev",
        std::path::Path::new("/nonexistent/never-read.pem"),
        &op,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(err.code_str(), "person_only");
}

#[test]
fn a_non_tty_is_refused_before_the_file_is_read() {
    let (op, fleet) = file_world();
    let err = set_from_file(
        &fleet,
        &FakeEnv::new("linux"),
        "api/PEM",
        "dev",
        std::path::Path::new("/nonexistent/never-read.pem"),
        &op,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(err.code_str(), "terminal_required");
}

#[cfg(unix)]
#[test]
fn a_group_or_world_readable_file_prints_a_warning() {
    use std::os::unix::fs::PermissionsExt;
    let (op, fleet) = file_world();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private-key.pem");
    std::fs::write(&path, "x\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let mut out = Vec::new();
    set_from_file(
        &fleet,
        &FakeEnv::new("linux").tty(),
        "api/PEM",
        "dev",
        &path,
        &op,
        &mut out,
    )
    .unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap().lines().next(),
        Some(
            format!(
                "warning: {} is readable by other users on this machine; opv stored it, but \
                 consider chmod 600 or deleting it",
                path.display()
            )
            .as_str()
        )
    );
}

#[cfg(unix)]
#[test]
fn a_private_file_prints_no_warning() {
    use std::os::unix::fs::PermissionsExt;
    let (op, fleet) = file_world();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private-key.pem");
    std::fs::write(&path, "x\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut out = Vec::new();
    set_from_file(
        &fleet,
        &FakeEnv::new("linux").tty(),
        "api/PEM",
        "dev",
        &path,
        &op,
        &mut out,
    )
    .unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "set\n");
}
