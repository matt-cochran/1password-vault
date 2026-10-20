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
