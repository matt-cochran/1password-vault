//! Shared keys (FR-45): a key declared with `from = "<product>/<KEY>"` reads its source's
//! field in the same environment's item and is written, exported and reported under its
//! own name. Synthetic values only; every value carries [`MARKER`].

use super::testutil::*;
use crate::domain::{KeyState, Kind, SecretValue, StoreEntry, build_plan};
use crate::error::Error;
use crate::runner::Output;
use crate::runner::fake::FakeRunner;
use std::collections::BTreeSet;

const DB: &str = "postgres://FIXTUREVALUE@db/app";
const API_DB: &str = "FLEET__API__DATABASE_URL";
const WORKER_DB: &str = "FLEET__WORKER__DATABASE_URL";

/// The fixture plus `api/DATABASE_URL` and `worker/DATABASE_URL` shared from it, with
/// `worker_rules` as the worker key's own rules (`{}` for none).
fn shared_fleet(worker_rules: &str) -> crate::domain::Fleet {
    fleet_with(&format!(
        "[products.api.keys.DATABASE_URL]\nkind = \"secret\"\nenvironments = [\"staging\", \"prod\"]\n\
         guidance = \"Neon / connection string\"\n\n\
         [products.worker.keys.DATABASE_URL]\nkind = \"secret\"\nfrom = \"api/DATABASE_URL\"\n\
         environments = [\"prod\"]\nrules = {worker_rules}\n"
    ))
}

fn fleet_shared() -> crate::domain::Fleet {
    shared_fleet("{}")
}

/// Every prod key, plus the one shared database field.
fn fields_with_db() -> Vec<Field> {
    let mut f = complete_fields();
    f.push(secret("api", "DATABASE_URL", DB));
    f
}

/// item, list A, the two preflight reads, import, list B, then spares.
fn fake_sync(item: Output) -> FakeRunner {
    let [st, rel] = fly_preflight_ok();
    let b = fly(&[
        (OPENAI_FLY, "d-openai"),
        (ENC_FLY, "d-enc"),
        (API_DB, "d-db"),
        (WORKER_DB, "d-db"),
    ]);
    FakeRunner::new([item, fly_empty(), st, rel, ok(), b, ok(), ok(), ok()])
}

fn sync(fleet: &crate::domain::Fleet, r: &FakeRunner) -> (Result<(), Error>, String) {
    let mut out = Vec::new();
    let res = super::sync::run(fleet, "prod", r, &mut out, &Default::default());
    (res, text_of(&out))
}

fn status(fleet: &crate::domain::Fleet, item: Output) -> (Result<(), Error>, String) {
    let r = FakeRunner::new([item, fly_empty()]);
    let mut out = Vec::new();
    let res = super::status::run(fleet, "prod", &r, &mut out);
    (res, text_of(&out))
}

/// The names (left of `=`) the staging import carried on stdin.
fn imported_names(r: &FakeRunner) -> BTreeSet<String> {
    import_stdin(r)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_once('=').map(|(n, _)| n.to_string()))
        .collect()
}

#[test]
fn run_exports_a_shared_key_under_its_own_name_from_the_source_field() {
    let r = FakeRunner::new([Output::success(Vec::new())]);
    super::run::run(&fleet_shared(), "prod", "worker", &["env".into()], &r).unwrap();
    assert!(r.calls.borrow()[0].env.contains(&(
        "DATABASE_URL".to_string(),
        "op://vprd/iprd/api/DATABASE_URL".to_string()
    )));
}

#[test]
fn sync_writes_both_target_names_from_one_field() {
    let r = fake_sync(item(&fields_with_db()));
    sync(&fleet_shared(), &r).0.unwrap();
    let names = imported_names(&r);
    assert!(
        names.contains(API_DB) && names.contains(WORKER_DB),
        "{names:?}"
    );
}

#[test]
fn sync_of_a_shared_key_puts_no_value_in_argv() {
    let r = fake_sync(item(&fields_with_db()));
    sync(&fleet_shared(), &r).0.unwrap();
    assert_no_values_in_argv(&r);
}

#[test]
fn sync_of_a_shared_key_prints_no_value() {
    let r = fake_sync(item(&fields_with_db()));
    let (_, out) = sync(&fleet_shared(), &r);
    assert_no_values(&out);
}

#[test]
fn status_reports_a_missing_source_once() {
    let (res, _) = status(&fleet_shared(), complete_item());
    assert!(matches!(res, Err(Error::Findings(1, _))), "{res:?}");
}

#[test]
fn status_lists_the_keys_a_missing_source_affects() {
    let (_, out) = status(&fleet_shared(), complete_item());
    assert!(out.contains("    affects worker/DATABASE_URL"), "{out}");
}

#[test]
fn status_shows_a_shared_key_with_its_source() {
    let (_, out) = status(&fleet_shared(), item(&fields_with_db()));
    assert!(out.contains("    shared from api/DATABASE_URL"), "{out}");
}

#[test]
fn status_of_a_shared_key_prints_no_value() {
    let (_, out) = status(&fleet_shared(), item(&fields_with_db()));
    assert_no_values(&out);
}

#[test]
fn shared_key_own_rule_fails_on_the_shared_value() {
    let f = shared_fleet("{ prefix = \"mysql://\" }");
    let fields = vec![crate::domain::ItemField {
        section: "api".into(),
        label: "DATABASE_URL".into(),
        kind: Kind::Secret,
        value: SecretValue::new(DB.into()),
        concealed: true,
    }];
    let none: &[StoreEntry] = &[];
    let plan = build_plan(&f, "prod", fields, none, &BTreeSet::new(), &|_| None);
    let row = plan
        .rows
        .iter()
        .find(|r| r.product == "worker" && r.key == "DATABASE_URL")
        .unwrap();
    assert!(
        matches!(row.state, KeyState::RuleFailed("prefix", _)),
        "{row:?}"
    );
}

#[test]
fn leftover_field_of_a_shared_key_is_an_extra() {
    let mut fields = fields_with_db();
    fields.push(secret("worker", "DATABASE_URL", DB));
    let (_, out) = status(&fleet_shared(), item(&fields));
    assert!(
        out.contains("extra field worker/DATABASE_URL is in the 1Password item"),
        "{out}"
    );
}

#[test]
fn product_check_reports_the_missing_source_of_its_shared_key() {
    let r = FakeRunner::new([complete_item()]);
    let mut out = Vec::new();
    let _ = super::local::check(&fleet_shared(), "prod", Some("worker"), &r, &mut out, false);
    assert!(
        text_of(&out).contains("api/DATABASE_URL: missing (affects worker/DATABASE_URL)"),
        "{}",
        text_of(&out)
    );
}

#[test]
fn explain_shows_the_shared_chain() {
    let mut out = Vec::new();
    super::explain::run(
        &fleet_shared(),
        "worker/DATABASE_URL",
        Some("prod"),
        &mut out,
    )
    .unwrap();
    assert!(
        text_of(&out).contains("op://vprd/iprd/api/DATABASE_URL"),
        "{}",
        text_of(&out)
    );
}

#[test]
fn explain_of_a_source_names_the_keys_sharing_it() {
    let mut out = Vec::new();
    super::explain::run(&fleet_shared(), "api/DATABASE_URL", Some("prod"), &mut out).unwrap();
    assert!(
        text_of(&out).contains("shared by:") && text_of(&out).contains("worker/DATABASE_URL"),
        "{}",
        text_of(&out)
    );
}

#[test]
fn skeleton_creates_no_field_for_a_shared_key() {
    let r = FakeRunner::new([complete_item(), ok()]);
    let mut out = Vec::new();
    super::skeleton::run(&fleet_shared(), "prod", &r, &mut out).unwrap();
    assert!(!text_of(&out).contains("worker/"), "{}", text_of(&out));
}

#[test]
fn rotating_an_immutable_source_restages_the_keys_sharing_it() {
    let f = fleet_with(
        "[products.worker.keys.INTEGRATION_ENC_KEY]\nkind = \"secret\"\n\
         from = \"allumata/INTEGRATION_ENC_KEY\"\nenvironments = [\"prod\"]\n",
    );
    let fields = vec![crate::domain::ItemField {
        section: "allumata".into(),
        label: "INTEGRATION_ENC_KEY".into(),
        kind: Kind::Secret,
        value: SecretValue::new(enc()),
        concealed: true,
    }];
    let listed = |n: &str| StoreEntry {
        name: n.into(),
        version: None,
        pending: false,
        stamp: None,
    };
    let on_store = [
        listed(ENC_FLY),
        listed("FLEET__WORKER__INTEGRATION_ENC_KEY"),
    ];
    let rotate = BTreeSet::from([("allumata".to_string(), "INTEGRATION_ENC_KEY".to_string())]);
    let plan = build_plan(&f, "prod", fields, &on_store, &rotate, &|_| None);
    assert!(
        plan.stage
            .iter()
            .any(|(n, _)| n == "FLEET__WORKER__INTEGRATION_ENC_KEY"),
        "{plan:?}"
    );
}
