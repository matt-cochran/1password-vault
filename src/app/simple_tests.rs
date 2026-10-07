//! Simple-profile (FR-20) command tests against `tests/fixtures/simple.toml`.
//!
//! Every command (status, fly plan, fly sync, item skeleton, config export, run) runs with
//! a [`FakeRunner`]. Items hold unsectioned fields only; every value carries
//! [`MARKER`](super::testutil::MARKER). The managed set is exactly the declared keys:
//! an undeclared Fly name is reported as unmanaged and never pruned (FR-8, SR-6), and a
//! command reads one whole item by IDs (FR-13).

use serde_json::Value;

use super::testutil::*;
use super::{config_export, run, skeleton, status, sync};
use crate::config;
use crate::domain::Fleet;
use crate::error::Error;
use crate::runner::Output;
use crate::runner::fake::FakeRunner;

const DB: &str = "postgres://FIXTUREVALUE@db.internal/app";
const LOG: &str = "info";
const APP: &str = "myapp-production";
/// A secret another tool set on the same Fly app; not declared in the file.
const FOREIGN: &str = "SENTRY_DSN";
/// Declared for staging only, so a managed name that is not desired in prod.
const STAGING_ONLY: &str = "STAGING_DEBUG_TOKEN";

fn simple() -> Fleet {
    config::load("tests/fixtures/simple.toml").unwrap()
}

/// An unsectioned field (testutil treats an empty section as "no section").
fn top_secret(label: &str, v: &str) -> Field {
    secret("", label, v)
}
fn top_text(label: &str, v: &str) -> Field {
    text("", label, v)
}

/// Every key desired in prod, correctly typed and rule-valid (STRIPE is mode-skipped).
fn prod_fields() -> Vec<Field> {
    vec![
        top_secret("DATABASE_URL", DB),
        top_secret("JWT_KEY", &enc()),
        top_text("LOG_LEVEL", LOG),
    ]
}
fn prod_item() -> Output {
    item(&prod_fields())
}
fn prod_item_without(label: &str) -> Output {
    let fs: Vec<Field> = prod_fields()
        .into_iter()
        .filter(|(_, l, _, _)| l != label)
        .collect();
    item(&fs)
}

fn out_of(f: impl FnOnce(&mut Vec<u8>) -> Result<(), Error>) -> (Result<(), Error>, String) {
    let mut out = Vec::new();
    let res = f(&mut out);
    (res, text_of(&out))
}

fn status_of(r: &FakeRunner, json: bool) -> (Result<(), Error>, String) {
    out_of(|o| status::run_with(&simple(), "prod", r, o, json))
}
fn plan_of(r: &FakeRunner, json: bool) -> (Result<(), Error>, String) {
    out_of(|o| sync::plan_with(&simple(), "prod", r, o, json))
}
fn sync_of(r: &FakeRunner, opts: &sync::SyncOpts) -> (Result<(), Error>, String) {
    out_of(|o| sync::run(&simple(), "prod", r, o, opts))
}

/// item, list A, import, list B, then spare responses so an unexpected call is recorded.
fn fake_sync(item: Output, a: Output, b: Output) -> FakeRunner {
    FakeRunner::new([item, a, ok(), b, ok(), ok(), ok()])
}

fn prune() -> sync::SyncOpts {
    sync::SyncOpts {
        prune: true,
        ..Default::default()
    }
}

fn unset_argv(r: &FakeRunner) -> Option<Vec<String>> {
    r.calls
        .borrow()
        .iter()
        .find(|c| c.program == "flyctl" && c.args.get(1).is_some_and(|a| a == "unset"))
        .map(|c| c.args.clone())
}

fn json_doc(s: &str) -> Value {
    serde_json::from_str(s.trim()).unwrap()
}

// ---------- status ----------

#[test]
fn status_reads_one_item_by_ids_and_lists_the_app_once() {
    let r = FakeRunner::new([prod_item(), fly_empty()]);
    status_of(&r, false).0.unwrap();
    assert_eq!(
        argvs(&r),
        vec![
            "op item get iprd --vault vprd --format json".to_string(),
            format!("flyctl secrets list --app {APP} --json"),
        ]
    );
}

#[test]
fn status_table_has_no_product_column() {
    let r = FakeRunner::new([prod_item(), fly_empty()]);
    let (_, out) = status_of(&r, false);
    let header = out.lines().next().unwrap();
    assert!(
        header.starts_with("KEY ") && !header.contains("PRODUCT"),
        "{out}"
    );
}

#[test]
fn status_row_starts_with_the_key_name() {
    let r = FakeRunner::new([prod_item(), fly_empty()]);
    let (_, out) = status_of(&r, false);
    assert!(out.lines().any(|l| l.starts_with("JWT_KEY ")), "{out}");
}

#[test]
fn status_complete_item_is_clean_and_value_free() {
    let r = FakeRunner::new([prod_item(), fly_empty()]);
    let (res, out) = status_of(&r, false);
    res.unwrap();
    assert!(out.contains("3 saved, 2 not yet on Fly"), "{out}");
    assert_no_values(&out);
}

#[test]
fn status_missing_key_is_a_finding_naming_the_key_with_guidance() {
    let r = FakeRunner::new([prod_item_without("DATABASE_URL"), fly_empty()]);
    let (res, out) = status_of(&r, false);
    assert!(matches!(res, Err(Error::Findings(1))), "{res:?}");
    assert!(
        out.contains("guidance: Fly Postgres / connection string"),
        "{out}"
    );
}

#[test]
fn status_ignores_sectioned_fields_under_simple() {
    let mut fs = prod_fields();
    fs.push(secret(
        "api",
        "DATABASE_URL",
        "postgres://FIXTUREVALUE-sectioned",
    ));
    let r = FakeRunner::new([item(&fs), fly_empty()]);
    let (res, out) = status_of(&r, false);
    res.unwrap();
    assert!(!out.contains("extra field"), "{out}");
}

#[test]
fn status_names_an_undeclared_unsectioned_field_without_a_product() {
    let mut fs = prod_fields();
    fs.push(top_secret("UNDECLARED_KEY", "x-FIXTUREVALUE"));
    let r = FakeRunner::new([item(&fs), fly_empty()]);
    let (_, out) = status_of(&r, false);
    assert!(
        out.contains("warning: extra field UNDECLARED_KEY is in the 1Password item"),
        "{out}"
    );
}

#[test]
fn status_mode_rule_failure_names_the_key_alone() {
    // staging: payments = "test", so STRIPE_SECRET_KEY needs sk_test_.
    let fs = vec![
        top_secret("DATABASE_URL", DB),
        top_secret("JWT_KEY", &enc()),
        top_secret("STRIPE_SECRET_KEY", "sk_live_FIXTUREVALUE"),
        top_secret(STAGING_ONLY, "t-FIXTUREVALUE"),
        top_text("LOG_LEVEL", LOG),
    ];
    let r = FakeRunner::new([item(&fs), fly_empty()]);
    let (res, out) = out_of(|o| status::run(&simple(), "staging", &r, o));
    assert!(matches!(res, Err(Error::Findings(1))), "{res:?}");
    assert!(
        out.lines().any(|l| l.starts_with("STRIPE_SECRET_KEY")
            && l.contains("failed prefix_by_mode (wrong prefix for mode test)")),
        "{out}"
    );
}

#[test]
fn status_json_product_is_null_in_every_row() {
    let r = FakeRunner::new([prod_item(), fly_empty()]);
    let (_, out) = status_of(&r, true);
    let doc = json_doc(&out);
    let rows = doc["rows"].as_array().unwrap();
    assert!(!rows.is_empty());
    assert!(rows.iter().all(|r| r["product"].is_null()), "{out}");
}

#[test]
fn status_json_fly_name_is_the_key_name() {
    let r = FakeRunner::new([prod_item(), fly_empty()]);
    let (_, out) = status_of(&r, true);
    let doc = json_doc(&out);
    let jwt = doc["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["key"] == "JWT_KEY")
        .unwrap();
    assert_eq!(jwt["fly_name"], "JWT_KEY");
}

#[test]
fn status_json_extra_product_is_null() {
    let mut fs = prod_fields();
    fs.push(top_secret("UNDECLARED_KEY", "x-FIXTUREVALUE"));
    let r = FakeRunner::new([item(&fs), fly_empty()]);
    let (_, out) = status_of(&r, true);
    let doc = json_doc(&out);
    assert_eq!(doc["extras"][0]["key"], "UNDECLARED_KEY");
    assert!(doc["extras"][0]["product"].is_null());
}

// ---------- fly plan ----------

#[test]
fn plan_counts_an_undeclared_fly_name_as_unmanaged() {
    let r = FakeRunner::new([prod_item(), fly(&[(FOREIGN, "d-f")])]);
    let (_, out) = plan_of(&r, false);
    assert!(out.contains("1 unmanaged on Fly (never touched)"), "{out}");
}

#[test]
fn plan_never_lists_an_undeclared_fly_name_to_prune() {
    let r = FakeRunner::new([prod_item(), fly(&[(FOREIGN, "d-f")])]);
    let (_, out) = plan_of(&r, false);
    assert!(
        !out.contains(&format!("to prune (with --prune): {FOREIGN}")),
        "{out}"
    );
    assert!(out.contains("0 to prune"), "{out}");
}

#[test]
fn plan_lists_a_declared_key_not_desired_here_to_prune() {
    let r = FakeRunner::new([prod_item(), fly(&[(STAGING_ONLY, "d-s")])]);
    let (_, out) = plan_of(&r, false);
    assert!(
        out.contains(&format!("to prune (with --prune): {STAGING_ONLY}")),
        "{out}"
    );
}

#[test]
fn plan_reads_the_item_once() {
    let r = FakeRunner::new([prod_item(), fly_empty()]);
    plan_of(&r, false).0.unwrap();
    assert_eq!(op_calls(&r), 1);
}

#[test]
fn plan_table_has_no_product_column() {
    let r = FakeRunner::new([prod_item(), fly_empty()]);
    let (_, out) = plan_of(&r, false);
    assert!(out.lines().next().unwrap().starts_with("KEY "), "{out}");
}

#[test]
fn plan_json_prune_holds_only_declared_names() {
    let r = FakeRunner::new([prod_item(), fly(&[(FOREIGN, "d-f"), (STAGING_ONLY, "d-s")])]);
    let (_, out) = plan_of(&r, true);
    assert_eq!(json_doc(&out)["prune"], serde_json::json!([STAGING_ONLY]));
}

#[test]
fn plan_json_held_product_is_null() {
    let r = FakeRunner::new([prod_item(), fly(&[("JWT_KEY", "d-j")])]);
    let (_, out) = plan_of(&r, true);
    let doc = json_doc(&out);
    assert_eq!(doc["held"][0]["key"], "JWT_KEY");
    assert!(doc["held"][0]["product"].is_null(), "{out}");
}

// ---------- fly sync ----------

#[test]
fn sync_stages_under_the_key_names() {
    let r = fake_sync(
        prod_item(),
        fly_empty(),
        fly(&[("DATABASE_URL", "d1"), ("JWT_KEY", "d2")]),
    );
    sync_of(&r, &Default::default()).0.unwrap();
    let stdin = import_stdin(&r).unwrap();
    assert!(
        stdin.starts_with("DATABASE_URL=") && stdin.contains("\nJWT_KEY="),
        "names only checked"
    );
}

#[test]
fn sync_puts_no_value_in_argv_or_output() {
    let r = fake_sync(
        prod_item(),
        fly_empty(),
        fly(&[("DATABASE_URL", "d1"), ("JWT_KEY", "d2")]),
    );
    let (res, out) = sync_of(&r, &prune());
    res.unwrap();
    assert_no_values_in_argv(&r);
    assert_no_values(&out);
}

#[test]
fn sync_reads_the_item_once() {
    let r = fake_sync(
        prod_item(),
        fly_empty(),
        fly(&[("DATABASE_URL", "d1"), ("JWT_KEY", "d2")]),
    );
    sync_of(&r, &Default::default()).0.unwrap();
    assert_eq!(op_calls(&r), 1);
}

/// Required (FR-8, SR-6): `--prune` never touches a name the file does not declare.
#[test]
fn sync_prune_never_touches_an_undeclared_fly_name() {
    let on_fly = [("DATABASE_URL", "d1"), ("JWT_KEY", "d2"), (FOREIGN, "d-f")];
    let r = fake_sync(prod_item(), fly(&on_fly), fly(&on_fly));
    let (res, out) = sync_of(&r, &prune());
    res.unwrap();
    assert_eq!(unset_argv(&r), None, "{:?}", argvs(&r));
    assert!(!r.argv_contains(FOREIGN), "{:?}", argvs(&r));
    assert!(!out.contains("pruned"), "{out}");
}

#[test]
fn sync_prune_unsets_only_the_declared_key_not_desired_here() {
    let on_fly = [
        ("DATABASE_URL", "d1"),
        ("JWT_KEY", "d2"),
        (FOREIGN, "d-f"),
        (STAGING_ONLY, "d-s"),
    ];
    let r = fake_sync(prod_item(), fly(&on_fly), fly(&on_fly));
    sync_of(&r, &prune()).0.unwrap();
    assert_eq!(
        unset_argv(&r).unwrap(),
        ["secrets", "unset", STAGING_ONLY, "--app", APP, "--stage"]
    );
}

#[test]
fn sync_refusal_names_the_key_alone() {
    let r = fake_sync(prod_item_without("JWT_KEY"), fly_empty(), fly_empty());
    let e = sync_of(&r, &Default::default()).0.unwrap_err();
    assert!(
        e.to_string().ends_with("nothing staged: JWT_KEY (missing)"),
        "{e}"
    );
}

#[test]
fn sync_holds_an_immutable_key_present_on_fly() {
    let on_fly = [("DATABASE_URL", "d1"), ("JWT_KEY", "d2")];
    let r = fake_sync(prod_item(), fly(&on_fly), fly(&on_fly));
    sync_of(&r, &Default::default()).0.unwrap();
    assert!(!import_stdin(&r).unwrap().contains("JWT_KEY="));
}

#[test]
fn sync_rotate_takes_the_bare_key_name() {
    let on_fly = [("DATABASE_URL", "d1"), ("JWT_KEY", "d2")];
    let r = fake_sync(prod_item(), fly(&on_fly), fly(&on_fly));
    let opts = sync::SyncOpts {
        rotate: vec!["JWT_KEY".into()],
        ..Default::default()
    };
    sync_of(&r, &opts).0.unwrap();
    assert!(import_stdin(&r).unwrap().contains("JWT_KEY="));
}

#[test]
fn sync_rotate_with_a_product_is_a_config_error_before_any_call() {
    let r = FakeRunner::new([]);
    let opts = sync::SyncOpts {
        rotate: vec!["app/JWT_KEY".into()],
        ..Default::default()
    };
    let e = sync_of(&r, &opts).0.unwrap_err();
    assert!(
        matches!(&e, Error::Config(m) if m.contains("expected KEY")),
        "{e}"
    );
    assert!(r.calls.borrow().is_empty());
}

#[test]
fn sync_prune_immutable_takes_the_bare_key_name() {
    let fleet = config::parse(
        &std::fs::read_to_string("tests/fixtures/simple.toml")
            .unwrap()
            .replace(
                "environments = [\"staging\"]",
                "environments = [\"staging\"]\nimmutable = true",
            ),
    )
    .unwrap();
    let on_fly = [
        ("DATABASE_URL", "d1"),
        ("JWT_KEY", "d2"),
        (STAGING_ONLY, "d-s"),
    ];
    let r = fake_sync(prod_item(), fly(&on_fly), fly(&on_fly));
    let opts = sync::SyncOpts {
        prune: true,
        prune_immutable: vec![STAGING_ONLY.into()],
        ..Default::default()
    };
    sync::run(&fleet, "prod", &r, &mut Vec::new(), &opts).unwrap();
    assert!(unset_argv(&r).unwrap().contains(&STAGING_ONLY.to_string()));
}

// ---------- item skeleton ----------

#[test]
fn skeleton_adds_missing_keys_as_top_level_fields() {
    let r = FakeRunner::new([prod_item_without("DATABASE_URL"), ok()]);
    let (res, out) = out_of(|o| skeleton::run(&simple(), "prod", &r, o));
    res.unwrap();
    // Every key declared for prod: STRIPE (mode-skipped) and DATABASE_URL are missing.
    assert!(out.contains("added DATABASE_URL (secret, empty)"), "{out}");
    assert!(
        out.contains("added STRIPE_SECRET_KEY (secret, empty)"),
        "{out}"
    );
}

#[test]
fn skeleton_writes_fields_without_a_section() {
    let r = FakeRunner::new([prod_item_without("DATABASE_URL"), ok()]);
    out_of(|o| skeleton::run(&simple(), "prod", &r, o))
        .0
        .unwrap();
    let calls = r.calls.borrow();
    let tpl: Value = serde_json::from_slice(calls[1].stdin.as_ref().unwrap()).unwrap();
    let f = tpl["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["label"] == "DATABASE_URL")
        .unwrap();
    assert!(f.get("section").is_none(), "{f}");
}

#[test]
fn skeleton_with_every_field_present_makes_no_write() {
    let mut fs = prod_fields();
    fs.push(top_secret("STRIPE_SECRET_KEY", ""));
    let r = FakeRunner::new([item(&fs)]);
    let (res, out) = out_of(|o| skeleton::run(&simple(), "prod", &r, o));
    res.unwrap();
    assert!(out.contains("nothing to add"), "{out}");
    assert_eq!(r.calls.borrow().len(), 1);
}

// ---------- config export ----------

#[test]
fn config_export_is_a_flat_key_map() {
    let r = FakeRunner::new([prod_item()]);
    let (res, out) = out_of(|o| config_export::run(&simple(), "prod", &r, o));
    res.unwrap();
    assert_eq!(json_doc(&out), serde_json::json!({"LOG_LEVEL": "info"}));
}

#[test]
fn config_export_never_contacts_fly() {
    let r = FakeRunner::new([prod_item()]);
    out_of(|o| config_export::run(&simple(), "prod", &r, o))
        .0
        .unwrap();
    assert_eq!(
        argvs(&r),
        vec!["op item get iprd --vault vprd --format json"]
    );
}

// ---------- run ----------

fn cmd(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| s.to_string()).collect()
}

#[test]
fn run_passes_unsectioned_references_for_desired_keys() {
    let r = FakeRunner::new([Output::success(Vec::new())]);
    run::run_for(&simple(), "prod", None, &cmd(&["env"]), &r).unwrap();
    let env = r.calls.borrow()[0].env.clone();
    assert_eq!(
        env,
        vec![
            (
                "DATABASE_URL".to_string(),
                "op://vprd/iprd/DATABASE_URL".to_string()
            ),
            ("JWT_KEY".to_string(), "op://vprd/iprd/JWT_KEY".to_string()),
            (
                "LOG_LEVEL".to_string(),
                "op://vprd/iprd/LOG_LEVEL".to_string()
            ),
        ]
    );
}

#[test]
fn run_execs_op_run_with_the_command() {
    let r = FakeRunner::new([Output::success(Vec::new())]);
    run::run_for(&simple(), "prod", None, &cmd(&["env", "-0"]), &r).unwrap();
    assert_eq!(argvs(&r), vec!["op run -- env -0"]);
}

#[test]
fn run_with_product_under_simple_is_a_config_error_before_any_call() {
    let r = FakeRunner::new([]);
    let e = run::run_for(&simple(), "prod", Some("api"), &cmd(&["env"]), &r).unwrap_err();
    assert!(
        matches!(&e, Error::Config(m) if m.contains("--product")),
        "{e}"
    );
    assert!(r.calls.borrow().is_empty());
}

#[test]
fn run_without_product_under_fleet_is_a_config_error_before_any_call() {
    let r = FakeRunner::new([]);
    let e = run::run_for(&fleet(), "staging", None, &cmd(&["env"]), &r).unwrap_err();
    assert!(
        matches!(&e, Error::Config(m) if m.contains("--product")),
        "{e}"
    );
    assert!(r.calls.borrow().is_empty());
}
