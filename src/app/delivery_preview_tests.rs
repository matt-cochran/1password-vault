//! Behaviour tests for `opv run --role`, `opv run --preview` and the shared preview
//! builder (#136, items 1 and 2). One atomic scenario per test, one assertion each.

use serde_json::json;

use super::*;
use crate::app::testutil::*;
use crate::runner::Output;
use crate::runner::fake::FakeRunner;

fn words(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| s.to_string()).collect()
}

fn delivered_names(sel: &Selection<'_>) -> Vec<String> {
    sel.delivered
        .iter()
        .map(|(key, _)| (*key).clone())
        .collect()
}

/// A runner whose session probe answers "signed in" (the only `op` call the preview makes).
fn signed_in() -> FakeRunner {
    FakeRunner::new([Output::success(b"{\"user_type\":\"USER\"}".to_vec())])
}

fn product(fleet: &Fleet) -> &Product {
    &fleet.products["allumata"]
}

// --- process roles: selection ---------------------------------------------------------

#[test]
fn a_key_scoped_to_another_role_is_not_delivered() {
    let fleet = role_fleet();
    let env = fleet.environment("prod").unwrap();
    let sel = select("prod", env, "allumata", product(&fleet), Some("serve")).unwrap();
    assert!(!delivered_names(&sel).contains(&"DATABASE_URL_UNPOOLED".to_string()));
}

#[test]
fn a_key_scoped_to_another_role_is_reported_withheld() {
    let fleet = role_fleet();
    let env = fleet.environment("prod").unwrap();
    let sel = select("prod", env, "allumata", product(&fleet), Some("serve")).unwrap();
    assert_eq!(sel.withheld, vec![&"DATABASE_URL_UNPOOLED".to_string()]);
}

#[test]
fn a_key_scoped_to_the_named_role_is_delivered() {
    let fleet = role_fleet();
    let env = fleet.environment("prod").unwrap();
    let sel = select("prod", env, "allumata", product(&fleet), Some("migrate")).unwrap();
    assert!(delivered_names(&sel).contains(&"DATABASE_URL_UNPOOLED".to_string()));
}

#[test]
fn a_key_without_roles_is_delivered_to_every_role() {
    let fleet = role_fleet();
    let env = fleet.environment("prod").unwrap();
    let sel = select("prod", env, "allumata", product(&fleet), Some("serve")).unwrap();
    assert!(delivered_names(&sel).contains(&"OPENAI_API_KEY".to_string()));
}

// --- process roles: fail-closed refusals before any 1Password read --------------------

#[test]
fn a_run_without_a_role_is_refused_when_a_key_names_roles() {
    let r = FakeRunner::new([]);
    let e = crate::app::run::run_with_role(
        &role_fleet(),
        "prod",
        "allumata",
        None,
        &words(&["env"]),
        &r,
    )
    .unwrap_err();
    assert_eq!(e.code_str(), "choice_required");
}

#[test]
fn a_run_without_a_role_makes_no_1password_call() {
    let r = FakeRunner::new([]);
    let _ = crate::app::run::run_with_role(
        &role_fleet(),
        "prod",
        "allumata",
        None,
        &words(&["env"]),
        &r,
    );
    assert!(r.calls.borrow().is_empty());
}

#[test]
fn a_run_naming_an_undeclared_role_is_refused() {
    let r = FakeRunner::new([]);
    let e = crate::app::run::run_with_role(
        &role_fleet(),
        "prod",
        "allumata",
        Some("deploy"),
        &words(&["env"]),
        &r,
    )
    .unwrap_err();
    assert_eq!(e.code_str(), "unknown_role");
}

/// The role refusal rendered for the person's command line `argv`.
fn role_refusal(argv: &[&str]) -> String {
    let e = build(&role_fleet(), "prod", Some("allumata"), None, &signed_in()).unwrap_err();
    let inv = crate::cause::Invocation::from_cli(&words(argv));
    match e.cause() {
        Some((c, _)) => crate::cause::render::render_text(c, None, &inv, false, false),
        None => e.to_string(),
    }
}

/// 07.11: a preview without --role is never told to run a command.
#[test]
fn a_preview_without_a_role_is_never_sent_to_a_real_run() {
    let text = role_refusal(&["opv", "run", "prod", "--product", "allumata", "--preview"]);
    assert!(!text.contains("-- <command>"), "{text}");
}

/// 07.11: a remote run without --role is never told to pass a command.
#[test]
fn a_remote_run_without_a_role_is_never_given_a_command() {
    let text = role_refusal(&["opv", "run", "prod", "--remote", "builder"]);
    assert!(!text.contains("-- <command>"), "{text}");
}

/// 07.11: the refusal names the roles to pick from.
#[test]
fn a_run_without_a_role_names_the_declared_roles() {
    let text = role_refusal(&["opv", "run", "prod", "--preview"]);
    assert!(text.contains("migrate, serve"), "{text}");
}

#[test]
fn a_run_naming_an_undeclared_role_makes_no_1password_call() {
    let r = FakeRunner::new([]);
    let _ = crate::app::run::run_with_role(
        &role_fleet(),
        "prod",
        "allumata",
        Some("deploy"),
        &words(&["env"]),
        &r,
    );
    assert!(r.calls.borrow().is_empty());
}

// --- process roles: config validation -------------------------------------------------

#[test]
fn an_empty_roles_list_is_refused_at_load() {
    let text = std::fs::read_to_string("tests/fixtures/secrets.toml").unwrap();
    let e = crate::config::parse(&format!(
        "{text}\n[products.allumata.keys.BAD_ROLES]\nkind = \"secret\"\nenvironments = [\"prod\"]\nroles = []\n"
    ))
    .unwrap_err();
    assert!(e.to_string().contains("roles must name at least one role"));
}

#[test]
fn a_role_name_outside_the_pattern_is_refused_at_load() {
    let text = std::fs::read_to_string("tests/fixtures/secrets.toml").unwrap();
    let e = crate::config::parse(&format!(
        "{text}\n[products.allumata.keys.BAD_ROLES]\nkind = \"secret\"\nenvironments = [\"prod\"]\nroles = [\"Serve\"]\n"
    ))
    .unwrap_err();
    assert!(e.to_string().contains("must match"));
}

// --- process roles: the op run environment and the local delivery step ----------------

#[test]
fn a_withheld_key_is_absent_from_the_op_run_environment() {
    let r = FakeRunner::new([Output::success(Vec::new())]);
    crate::app::run::run_with_role(
        &role_fleet(),
        "prod",
        "allumata",
        Some("serve"),
        &words(&["env"]),
        &r,
    )
    .unwrap();
    let env = r.calls.borrow()[0].env.clone();
    assert!(!env.iter().any(|(name, _)| name == "DATABASE_URL_UNPOOLED"));
}

#[test]
fn a_withheld_file_key_is_absent_from_the_local_delivery_step() {
    let r = FakeRunner::new([Output::success(Vec::new())]);
    crate::app::run::run_with_role(
        &role_local_fleet(),
        "prod",
        "allumata",
        Some("serve"),
        &words(&["app"]),
        &r,
    )
    .unwrap();
    let args = r.calls.borrow()[0].args.clone();
    assert!(!args.iter().any(|a| a.contains("MIGRATE_PEM")));
}

// --- the metadata-only preview document ----------------------------------------------

#[test]
fn the_preview_document_is_schema_version_one() {
    let doc = build(
        &role_fleet(),
        "prod",
        Some("allumata"),
        Some("serve"),
        &signed_in(),
    )
    .unwrap();
    assert_eq!(doc["schema_version"], json!(1));
}

#[test]
fn the_preview_names_a_keys_source() {
    let doc = build(
        &role_fleet(),
        "prod",
        Some("allumata"),
        Some("serve"),
        &signed_in(),
    )
    .unwrap();
    let key = doc["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["key"] == "SERVE_TOKEN")
        .unwrap();
    assert_eq!(key["source"], json!("allumata/SERVE_TOKEN"));
}

#[test]
fn the_preview_names_a_keys_environment_destination() {
    let doc = build(
        &role_fleet(),
        "prod",
        Some("allumata"),
        Some("serve"),
        &signed_in(),
    )
    .unwrap();
    let key = doc["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["key"] == "SERVE_TOKEN")
        .unwrap();
    assert_eq!(key["destination"], json!("env:SERVE_TOKEN"));
}

#[test]
fn the_preview_names_a_file_keys_relative_destination() {
    let doc = build(
        &role_local_fleet(),
        "prod",
        Some("allumata"),
        Some("migrate"),
        &signed_in(),
    )
    .unwrap();
    let key = doc["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["key"] == "MIGRATE_PEM")
        .unwrap();
    assert_eq!(key["destination"], json!("file:db/migrate-pem"));
}

#[test]
fn the_preview_reports_a_keys_declared_roles() {
    let doc = build(
        &role_fleet(),
        "prod",
        Some("allumata"),
        Some("migrate"),
        &signed_in(),
    )
    .unwrap();
    let key = doc["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["key"] == "DATABASE_URL_UNPOOLED")
        .unwrap();
    assert_eq!(key["roles"], json!(["migrate"]));
}

#[test]
fn the_preview_lists_the_keys_a_role_withholds() {
    let doc = build(
        &role_fleet(),
        "prod",
        Some("allumata"),
        Some("serve"),
        &signed_in(),
    )
    .unwrap();
    assert_eq!(doc["withheld_by_role"], json!(["DATABASE_URL_UNPOOLED"]));
}

#[test]
fn the_preview_reports_the_environment_mode() {
    let doc = build(
        &role_local_fleet(),
        "prod",
        Some("allumata"),
        Some("serve"),
        &signed_in(),
    )
    .unwrap();
    assert_eq!(doc["environment_mode"], json!("declared_only"));
}

#[test]
fn the_preview_reports_the_secrets_directory_variable() {
    let doc = build(
        &role_local_fleet(),
        "prod",
        Some("allumata"),
        Some("serve"),
        &signed_in(),
    )
    .unwrap();
    assert_eq!(doc["secrets_dir_env"], json!("APP_SECRETS_DIR"));
}

#[test]
fn the_preview_reports_this_platforms_file_delivery_support() {
    let doc = build(
        &role_fleet(),
        "prod",
        Some("allumata"),
        Some("serve"),
        &signed_in(),
    )
    .unwrap();
    assert_eq!(
        doc["file_delivery"]["supported"],
        json!(crate::app::local_delivery::runtime_dir_support().is_ok())
    );
}

#[test]
fn the_preview_reports_a_known_session_as_present_and_signed_in() {
    let doc = build(
        &role_fleet(),
        "prod",
        Some("allumata"),
        Some("serve"),
        &signed_in(),
    )
    .unwrap();
    assert_eq!(
        doc["prerequisites"],
        json!({"op": "yes", "signed_in": "yes"})
    );
}

#[test]
fn an_undeterminable_session_is_reported_unknown_not_missing() {
    let r = FakeRunner::new([]);
    r.push_unknown("timeout");
    let doc = build(&role_fleet(), "prod", Some("allumata"), Some("serve"), &r).unwrap();
    assert_eq!(
        doc["prerequisites"],
        json!({"op": "unknown", "signed_in": "unknown"})
    );
}

#[test]
fn a_missing_op_cli_is_reported_missing_but_the_session_unknown() {
    let r = FakeRunner::new([]);
    r.push_io_error(std::io::ErrorKind::NotFound);
    let doc = build(&role_fleet(), "prod", Some("allumata"), Some("serve"), &r).unwrap();
    assert_eq!(
        doc["prerequisites"],
        json!({"op": "no", "signed_in": "unknown"})
    );
}

#[test]
fn the_preview_never_reads_a_value() {
    let r = signed_in();
    let _ = build(&role_fleet(), "prod", Some("allumata"), Some("serve"), &r).unwrap();
    let reads_a_value = r.calls.borrow().iter().any(|call| {
        call.program == "op"
            && matches!(
                call.args.first().map(String::as_str),
                Some("read" | "run" | "item")
            )
    });
    assert!(!reads_a_value);
}
