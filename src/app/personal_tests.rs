//! FR-55 personal keys: locating a person's own item and merging its fields, through a
//! stateful fake `op` that stores vaults and items.

use std::path::Path;

use serde_json::json;

use super::*;
use crate::adapters::fake_op::FakeOp;
use crate::domain::Kind;
use crate::domain::plan::ItemField;
use crate::domain::secret::SecretValue;
use crate::error::Error;
use crate::runner::Output;
use crate::runner::fake::FakeRunner;

/// An environment without a target holding one personal key.
fn personal_fleet() -> Fleet {
    crate::config::parse(
        r#"
[environments.dev]
[products.api.keys.OPENAI_API_KEY]
kind = "secret"
environments = ["dev"]
personal = true
"#,
    )
    .unwrap()
}

#[test]
fn declared_is_true_when_a_key_for_the_env_is_personal() {
    assert!(declared(&personal_fleet(), "dev"));
}

#[test]
fn project_name_falls_back_to_the_directory_name() {
    let op = FakeOp::default();
    assert_eq!(project_name(&op, Path::new("/x/myapp")), "myapp");
}

#[test]
fn item_title_defaults_to_project_env_and_personal() {
    let f = personal_fleet();
    assert_eq!(
        item_title(&f.environments["dev"], "myapp"),
        "myapp · dev (personal)"
    );
}

fn personal_item(op: &FakeOp, vault: &str) -> String {
    op.insert(
        vault,
        serde_json::json!({
            "title": "myapp · dev (personal)",
            "category": "SECURE_NOTE",
            "fields": []
        }),
    )
}

/// A personal item titled by [`item_title`] holding one field.
fn item_with(section: &str, label: &str, ty: &str, value: &str) -> serde_json::Value {
    json!({
        "title": "myapp · dev (personal)",
        "category": "SECURE_NOTE",
        "version": 1,
        "fields": [{
            "id": format!("f_{label}"),
            "type": ty,
            "label": label,
            "value": value,
            "section": {"id": format!("s_{section}"), "label": section}
        }]
    })
}

fn team_field(label: &str, value: &str) -> ItemField {
    ItemField {
        section: "api".into(),
        label: label.into(),
        kind: Kind::Secret,
        value: SecretValue::new(value.to_string()),
        concealed: true,
    }
}

#[test]
fn merged_fields_takes_a_personal_key_from_the_personal_item() {
    let op = FakeOp::default();
    op.vaults
        .borrow_mut()
        .push(("vpriv0000000000000000000001".into(), "Private".into()));
    op.insert(
        "Private",
        item_with("api", "OPENAI_API_KEY", "CONCEALED", "sk-personal"),
    );
    let merged = merged_fields(&op, &personal_fleet(), "dev", vec![], "myapp").unwrap();
    assert_eq!(merged[0].value.expose(), "sk-personal");
}

#[test]
fn merged_fields_never_takes_the_team_item_field_for_a_personal_key() {
    let op = FakeOp::default();
    op.vaults
        .borrow_mut()
        .push(("vpriv0000000000000000000001".into(), "Private".into()));
    op.insert(
        "Private",
        item_with("api", "OPENAI_API_KEY", "CONCEALED", "sk-personal"),
    );
    let team = vec![team_field("OPENAI_API_KEY", "sk-team")];
    let merged = merged_fields(&op, &personal_fleet(), "dev", team, "myapp").unwrap();
    assert_eq!(merged[0].value.expose(), "sk-personal");
}

#[test]
fn check_shows_the_personal_key_as_a_row() {
    let op = FakeOp::default();
    op.vaults
        .borrow_mut()
        .push(("vpriv0000000000000000000001".into(), "Private".into()));
    let mut personal = item_with("api", "OPENAI_API_KEY", "CONCEALED", "sk-personal");
    personal["title"] = json!("My Keys");
    op.insert("Private", personal);
    // A team key keeps api's boundary in use; the personal key is added beside it.
    let team_id = op.insert(
        "myapp-dev",
        json!({
            "title": "dev", "category": "SECURE_NOTE", "version": 1,
            "fields": [{
                "id": "f_API_KEY", "type": "CONCEALED", "label": "API_KEY",
                "value": "team-value",
                "section": {"id": "s_api", "label": "api"}
            }]
        }),
    );
    let f = crate::config::parse(&format!(
        r#"
[environments.dev]
personal_item = "My Keys"
boundaries.api = {{ vault_id = "vdev0000000000000000000001", item_id = "{team_id}" }}
[products.api.keys.API_KEY]
kind = "secret"
environments = ["dev"]
[products.api.keys.OPENAI_API_KEY]
kind = "secret"
environments = ["dev"]
personal = true
"#
    ))
    .unwrap();
    let mut out = Vec::new();
    crate::app::local::check(&f, "dev", Some("api"), &op, &mut out, false).unwrap();
    assert!(String::from_utf8(out).unwrap().contains("OPENAI_API_KEY"));
}

/// A run whose personal item does not exist: the `git` probe, then three empty `op vault
/// list` answers (Private, Employee, Personal).
fn run_without_a_personal_item() -> (FakeRunner, Error) {
    let r = FakeRunner::new([
        Output::failure(2),
        Output::success(br#"[{"id":"vpriv0000000000000000000001","name":"Private"}]"#.to_vec()),
        Output::success(b"[]".to_vec()),
    ]);
    let e = crate::app::run::run(&personal_fleet(), "dev", "api", &["env".to_string()], &r)
        .unwrap_err();
    (r, e)
}

#[test]
fn run_stops_before_the_command_when_the_personal_item_is_missing() {
    let (r, _e) = run_without_a_personal_item();
    assert!(
        !r.calls
            .borrow()
            .iter()
            .any(|c| c.program == "op" && c.args.first().map(String::as_str) == Some("run"))
    );
}

#[test]
fn run_reports_personals_own_cause_when_the_personal_item_is_missing() {
    // `run` passes on personal's own cause for the missing item, never one of its own.
    let (_r, e) = run_without_a_personal_item();
    assert!(
        matches!(e.cause(), Some((crate::cause::Cause::NotFound { .. }, _))),
        "{e}"
    );
}

#[test]
fn reference_points_at_the_personal_item() {
    let f = personal_fleet();
    let env = crate::domain::Boundary {
        vault_id: "vpriv0000000000000000000001".into(),
        item_id: "ipriv0000000000000000000001".into(),
    };
    let spec = &f.products["api"].keys["OPENAI_API_KEY"];
    assert_eq!(
        reference(&env, "api", "OPENAI_API_KEY", spec),
        "op://vpriv0000000000000000000001/ipriv0000000000000000000001/api/OPENAI_API_KEY"
    );
}

#[test]
fn merged_fields_follows_a_shared_personal_key_to_its_source() {
    let op = FakeOp::default();
    op.vaults
        .borrow_mut()
        .push(("vpriv0000000000000000000001".into(), "Private".into()));
    op.insert(
        "Private",
        item_with("api", "OPENAI_API_KEY", "CONCEALED", "sk-personal"),
    );
    let f = crate::config::parse(
        r#"
[environments.dev]
[products.api.keys.OPENAI_API_KEY]
kind = "secret"
environments = ["dev"]
personal = true
[products.api.keys.SHARED_KEY]
kind = "secret"
environments = ["dev"]
personal = true
from = "api/OPENAI_API_KEY"
"#,
    )
    .unwrap();
    let team = vec![team_field("SHARED_KEY", "sk-team")];
    let merged = merged_fields(&op, &f, "dev", team, "myapp").unwrap();
    assert_eq!(merged[0].label, "OPENAI_API_KEY");
}

#[test]
fn merged_fields_leaves_a_personal_key_missing_without_a_personal_item() {
    let op = FakeOp::default();
    op.vaults
        .borrow_mut()
        .push(("vpriv0000000000000000000001".into(), "Private".into()));
    let team = vec![team_field("OPENAI_API_KEY", "sk-team")];
    let merged = merged_fields(&op, &personal_fleet(), "dev", team, "myapp").unwrap();
    assert!(merged.is_empty());
}

#[test]
fn locate_finds_the_private_vault_and_item() {
    let op = FakeOp::default();
    op.vaults
        .borrow_mut()
        .push(("vpriv0000000000000000000001".into(), "Private".into()));
    let id = personal_item(&op, "Private");
    let found = locate(&op, &personal_fleet(), "dev", "myapp")
        .unwrap()
        .unwrap();
    assert_eq!(found.item_id, id);
}

#[test]
fn locate_prefers_personal_vault() {
    let op = FakeOp::default();
    op.vaults
        .borrow_mut()
        .push(("vpriv0000000000000000000001".into(), "Private".into()));
    op.vaults
        .borrow_mut()
        .push(("vteam0000000000000000000001".into(), "TeamKeys".into()));
    let _decoy = personal_item(&op, "Private");
    let id = personal_item(&op, "TeamKeys");
    let f = crate::config::parse(
        r#"
[environments.dev]
personal_vault = "TeamKeys"
[products.api.keys.OPENAI_API_KEY]
kind = "secret"
environments = ["dev"]
personal = true
"#,
    )
    .unwrap();
    let found = locate(&op, &f, "dev", "myapp").unwrap().unwrap();
    assert_eq!(found.item_id, id);
}

#[test]
fn locate_reports_setup_missing_when_the_item_does_not_exist() {
    let op = FakeOp::default();
    op.vaults
        .borrow_mut()
        .push(("vpriv0000000000000000000001".into(), "Private".into()));
    let e = locate(&op, &personal_fleet(), "dev", "myapp").unwrap_err();
    assert_eq!(e.code_str(), "item_not_found");
}

#[test]
fn item_title_uses_personal_item_when_set() {
    let f = crate::config::parse(
        r#"
[environments.dev]
personal_item = "My Keys"
[products.api.keys.OPENAI_API_KEY]
kind = "secret"
environments = ["dev"]
personal = true
"#,
    )
    .unwrap();
    assert_eq!(item_title(&f.environments["dev"], "myapp"), "My Keys");
}

/// The `git` probe, then `op vault list` failing while nobody is signed in (`op whoami` and
/// `op account list` fail too): the run's cause is the sign-in, not a missing item.
#[test]
fn a_signed_out_run_is_not_told_its_personal_item_is_missing() {
    let mut replies = vec![Output::failure(2)];
    replies.extend((0..12).map(|_| Output::failure(1)));
    let r = FakeRunner::new(replies);
    let e = crate::app::run::run(&personal_fleet(), "dev", "api", &["env".to_string()], &r)
        .unwrap_err();
    assert_ne!(e.code(), crate::error::Code::ItemNotFound);
}

// --- audit 04.16: the setup error names what opv looked for; other failures surface ---

#[test]
fn a_missing_personal_item_is_named_by_its_title() {
    let op = FakeOp::default();
    op.vaults
        .borrow_mut()
        .push(("vpriv0000000000000000000001".into(), "Private".into()));
    let e = locate(&op, &personal_fleet(), "dev", "myapp").unwrap_err();
    let shown = crate::error::report(&e);
    assert!(shown.contains("myapp · dev (personal)"), "{shown}");
}

#[test]
fn a_missing_personal_vault_is_named_by_the_titles_tried() {
    let op = FakeOp::default();
    let e = locate(&op, &personal_fleet(), "dev", "myapp").unwrap_err();
    let shown = crate::error::report(&e);
    assert!(shown.contains("Private"), "{shown}");
}

/// C19, R34: a missing personal vault steps to the field that names another one.
#[test]
fn a_missing_personal_vault_names_the_personal_vault_field() {
    let op = FakeOp::default();
    let e = locate(&op, &personal_fleet(), "dev", "myapp").unwrap_err();
    let shown = crate::error::report(&e);
    assert!(shown.contains("environments.dev.personal_vault"), "{shown}");
}

#[test]
fn merged_fields_reports_a_failure_that_is_not_a_missing_item() {
    let op = FakeOp::default();
    op.signed_in.set(false);
    let team = vec![team_field("OPENAI_API_KEY", "sk-team")];
    assert!(merged_fields(&op, &personal_fleet(), "dev", team, "myapp").is_err());
}
