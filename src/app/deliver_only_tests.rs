//! The core of deliver-only infrastructure values (#206, `docs/design/deliver-only.md`,
//! tests T2 to T6 and the core half of T13): one atomic scenario per test, one assertion on
//! a public outcome. Supplied values are `S7MARKER-…` canaries; no test puts one in argv,
//! the environment or a file.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use super::*;
use crate::cause::{Cause, FieldRule, Guard, SupplyEntry, SupplyRefusal, SupplyRule};
use crate::domain::delivery::{Evidence, Source, SuppliedMark};
use crate::domain::ledger::{Ledger, hmac_hex};
use crate::domain::plan::{CurrentState, ItemField, PlanOptions, StoreEntry, SyncPlan};

/// The database URL canary: matches `DATABASE_URL`'s regex.
const DB: &str = "postgresql://S7MARKER-db-0001@db.example/app";
/// Another value of the same key, for a changed value.
const DB2: &str = "postgresql://S7MARKER-db-0002@db.example/app";
/// The webhook secret canary, given without its `whsec_` prefix (`ensure_prefix`).
const HOOK: &str = "S7MARKER-hook-0001";
/// The worker URL canary.
const JOBS: &str = "https://S7MARKER-jobs-0001.example";
/// The marker every canary holds: no text opv shows may contain it.
const MARK: &str = "S7MARKER";
/// The evidence key of the web placement's ledger.
const EVIDENCE_KEY: &str = "evidence-key-for-tests-0001";

/// `prod` has Fly targets `web` (api, names `APP_<KEY>`) and `jobs` (worker); `staging` has
/// `web`; `qa` has a target but no infrastructure key; `dev` has none.
const FLEET: &str = r#"
[environments.prod]
boundaries.api = { vault_id = "vprod", item_id = "iprodapi" }
boundaries.worker = { vault_id = "vprod", item_id = "iprodwrk" }

[environments.prod.targets.web]
fly.app = "web-prod"
fly.secret_name = "APP_{KEY}"
products = ["api"]
state_vault_id = "sprod"

[environments.prod.targets.jobs]
fly.app = "jobs-prod"
fly.secret_name = "{KEY}"
products = ["worker"]
state_vault_id = "sprodjobs"

[environments.staging]
boundaries.api = { vault_id = "vstg", item_id = "istgapi" }
boundaries.worker = { vault_id = "vstg", item_id = "istgwrk" }

[environments.staging.targets.web]
fly.app = "web-staging"
fly.secret_name = "APP_{KEY}"
products = ["api"]
state_vault_id = "sstg"

[environments.qa]
boundaries.api = { vault_id = "vqa", item_id = "iqaapi" }
boundaries.worker = { vault_id = "vqa", item_id = "iqawrk" }

[environments.qa.targets.web]
fly.app = "web-qa"
fly.secret_name = "APP_{KEY}"
products = ["api"]
state_vault_id = "sqa"

[environments.dev]
boundaries.api = { vault_id = "vdev", item_id = "idevapi" }
boundaries.worker = { vault_id = "vdev", item_id = "idevwrk" }

[products.api.keys.DATABASE_URL]
kind = "secret"
source = "infrastructure"
environments = ["staging", "prod"]
rules = { regex = "postgres(ql)?://.+" }

[products.api.keys.STRIPE_WEBHOOK_SECRET]
kind = "secret"
source = "infrastructure"
environments = ["staging", "prod"]
immutable = true
rules = { ensure_prefix = "whsec_" }

[products.api.keys.TOKEN]
kind = "secret"

[products.worker.keys.JOBS_URL]
kind = "secret"
source = "infrastructure"
environments = ["prod"]
rules = { https_url = true }

[products.worker.keys.WORKER_TOKEN]
kind = "secret"
"#;

fn fleet() -> Fleet {
    crate::config::parse(FLEET).expect("the fixture loads")
}

fn limits() -> Limits {
    Limits::new(Instant::now() + Duration::from_secs(60))
}

/// One `opv.supply/1` document for `env` with `serial` and `values` (a JSON object body).
fn doc(env: &str, serial: u64, values: &str) -> String {
    format!(
        r#"{{"schema": "opv.supply/1", "env": "{env}", "serial": {serial}, "values": {{{values}}}}}"#
    )
}

/// Both of api's prod values in one document.
fn api_doc(serial: u64) -> String {
    doc(
        "prod",
        serial,
        &format!(r#""api/DATABASE_URL": "{DB}", "api/STRIPE_WEBHOOK_SECRET": "{HOOK}""#),
    )
}

fn read_text(text: &str) -> Result<RawSupply, Error> {
    read(&mut text.as_bytes(), false, &limits())
}

/// The selected targets of a whole-environment run of `prod`.
fn all_targets() -> Vec<String> {
    vec!["web".to_string(), "jobs".to_string()]
}

/// Read and admit `text` for `env` on `targets`, with `product` and `rotate`.
fn admit_with(
    text: &str,
    env: &str,
    targets: &[String],
    product: Option<&str>,
    rotate: &BTreeSet<(String, String)>,
) -> Result<Supply, Error> {
    let raw = read_text(text)?;
    admit(
        &fleet(),
        &Scope {
            env,
            targets,
            product,
            rotate,
        },
        raw,
    )
}

/// Read and admit `text` for prod's `web` target alone.
fn admit_web(text: &str) -> Result<Supply, Error> {
    admit_with(text, "prod", &["web".to_string()], None, &BTreeSet::new())
}

fn stream_rule(e: &Error) -> Option<SupplyRule> {
    match e.parts().0 {
        Cause::InputInvalid {
            rule: FieldRule::Supply { supply },
            ..
        } => Some(supply.clone()),
        _ => None,
    }
}

fn reason(e: &Error) -> Option<SupplyRefusal> {
    match e.parts().0 {
        Cause::Guard {
            guard: Guard::SupplyRefused { reason, .. },
        } => Some(reason.clone()),
        _ => None,
    }
}

fn entry(e: &Error) -> Option<SupplyEntry> {
    match e.parts().0 {
        Cause::Guard {
            guard: Guard::SupplyRefused { entry, .. },
        } => Some(entry.clone()),
        _ => None,
    }
}

fn rule_of(r: Result<RawSupply, Error>) -> Option<SupplyRule> {
    r.err().as_ref().and_then(stream_rule)
}

fn reason_of(r: Result<Supply, Error>) -> Option<SupplyRefusal> {
    r.err().as_ref().and_then(reason)
}

fn rotate(keys: &[(&str, &str)]) -> BTreeSet<(String, String)> {
    keys.iter()
        .map(|(p, k)| (p.to_string(), k.to_string()))
        .collect()
}

/// Every text opv could show for `e`: the report (message, Do, Next), the `--json` error
/// document and the `Debug` form.
fn shown(e: &Error) -> String {
    let doc = crate::error::document(e, &crate::error::invocation(), true);
    format!("{}\n{doc}\n{e:?}", crate::error::report(e))
}

/// A reader that counts its calls and ends at once.
struct Counting<'a>(&'a std::cell::Cell<usize>);

impl Read for Counting<'_> {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        self.0.set(self.0.get() + 1);
        Ok(0)
    }
}

/// A reader that never ends: it blocks until the test process exits.
struct Unclosed {
    rx: std::sync::mpsc::Receiver<()>,
    /// Held so `rx` never disconnects.
    _tx: std::sync::mpsc::Sender<()>,
}

impl Read for Unclosed {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        let _ = self.rx.recv();
        Ok(0)
    }
}

fn unclosed() -> Unclosed {
    let (_tx, rx) = std::sync::mpsc::channel();
    Unclosed { rx, _tx }
}

// --- T4: the stream ----------------------------------------------------------------------

#[test]
fn a_terminal_stdin_is_refused() {
    let r = read(&mut "".as_bytes(), true, &limits());
    assert_eq!(rule_of(r), Some(SupplyRule::StdinIsTerminal));
}

#[test]
fn a_terminal_stdin_is_refused_before_a_byte_is_read() {
    let calls = std::cell::Cell::new(0);
    let _ = read(&mut Counting(&calls), true, &limits());
    assert_eq!(calls.get(), 0);
}

#[test]
fn an_empty_stdin_holds_no_documents() {
    assert_eq!(rule_of(read_text("")), Some(SupplyRule::NoDocuments));
}

#[test]
fn whitespace_alone_holds_no_documents() {
    assert_eq!(rule_of(read_text(" \n\t\n")), Some(SupplyRule::NoDocuments));
}

#[test]
fn invalid_json_is_refused_at_its_position() {
    let text = format!("{}\n{{\"schema\": ", api_doc(1));
    assert_eq!(
        rule_of(read_text(&text)),
        Some(SupplyRule::NotJson { line: 2, col: 11 })
    );
}

#[test]
fn a_non_object_document_is_not_a_supply_document() {
    assert_eq!(rule_of(read_text("[1, 2]")), Some(SupplyRule::WrongSchema));
}

#[test]
fn a_supply_over_the_total_limit_is_refused() {
    let r = read(
        &mut api_doc(1).as_bytes(),
        false,
        &Limits {
            total: 16,
            ..limits()
        },
    );
    assert_eq!(rule_of(r), Some(SupplyRule::TooLarge { limit: 16 }));
}

#[test]
fn a_supply_of_exactly_the_total_limit_is_read() {
    let text = api_doc(1);
    let r = read(
        &mut text.as_bytes(),
        false,
        &Limits {
            total: text.len(),
            ..limits()
        },
    );
    assert!(r.is_ok());
}

#[test]
fn the_design_limit_is_one_mebibyte() {
    let text = " ".repeat(TOTAL_LIMIT + 1);
    assert_eq!(
        rule_of(read_text(&text)),
        Some(SupplyRule::TooLarge { limit: 1_048_576 })
    );
}

#[test]
fn a_supply_over_the_name_limit_is_refused() {
    let r = read(
        &mut api_doc(1).as_bytes(),
        false,
        &Limits {
            names: 1,
            ..limits()
        },
    );
    assert_eq!(rule_of(r), Some(SupplyRule::TooManyNames { limit: 1 }));
}

#[test]
fn an_unknown_field_is_refused() {
    let text = r#"{"schema": "opv.supply/1", "env": "prod", "serial": 1, "values": {"api/DATABASE_URL": "x"}, "extra": 1}"#;
    assert_eq!(rule_of(read_text(text)), Some(SupplyRule::UnknownField));
}

#[test]
fn a_field_given_twice_is_refused() {
    let text = r#"{"schema": "opv.supply/1", "env": "prod", "env": "staging", "serial": 1, "values": {"api/DATABASE_URL": "x"}}"#;
    assert_eq!(rule_of(read_text(text)), Some(SupplyRule::UnknownField));
}

#[test]
fn another_schema_is_refused() {
    let text = doc("prod", 1, r#""api/DATABASE_URL": "x""#).replace("opv.supply/1", "opv.supply/2");
    assert_eq!(rule_of(read_text(&text)), Some(SupplyRule::WrongSchema));
}

#[test]
fn a_missing_schema_is_refused() {
    let text = r#"{"env": "prod", "serial": 1, "values": {"api/DATABASE_URL": "x"}}"#;
    assert_eq!(rule_of(read_text(text)), Some(SupplyRule::WrongSchema));
}

#[test]
fn a_missing_serial_is_refused() {
    let text = r#"{"schema": "opv.supply/1", "env": "prod", "values": {"api/DATABASE_URL": "x"}}"#;
    assert_eq!(rule_of(read_text(text)), Some(SupplyRule::MissingSerial));
}

#[test]
fn a_serial_given_as_text_is_refused() {
    let text =
        doc("prod", 1, r#""api/DATABASE_URL": "x""#).replace("\"serial\": 1", "\"serial\": \"1\"");
    assert_eq!(rule_of(read_text(&text)), Some(SupplyRule::MissingSerial));
}

#[test]
fn a_negative_serial_is_refused() {
    let text =
        doc("prod", 1, r#""api/DATABASE_URL": "x""#).replace("\"serial\": 1", "\"serial\": -1");
    assert_eq!(rule_of(read_text(&text)), Some(SupplyRule::MissingSerial));
}

#[test]
fn empty_values_are_refused() {
    assert_eq!(
        rule_of(read_text(&doc("prod", 1, ""))),
        Some(SupplyRule::NoValues)
    );
}

#[test]
fn missing_values_are_refused() {
    let text = r#"{"schema": "opv.supply/1", "env": "prod", "serial": 1}"#;
    assert_eq!(rule_of(read_text(text)), Some(SupplyRule::NoValues));
}

#[test]
fn values_that_are_not_an_object_are_refused() {
    let text = r#"{"schema": "opv.supply/1", "env": "prod", "serial": 1, "values": ["x"]}"#;
    assert_eq!(rule_of(read_text(text)), Some(SupplyRule::NoValues));
}

#[test]
fn a_stdin_left_open_past_the_deadline_times_out() {
    let deadline = Instant::now() + Duration::from_millis(50);
    let mut input = until(unclosed(), deadline);
    let r = read(
        &mut input,
        false,
        &Limits {
            deadline,
            ..limits()
        },
    );
    assert_eq!(rule_of(r), Some(SupplyRule::Timeout));
}

#[test]
fn a_read_after_the_deadline_times_out() {
    let r = read(
        &mut api_doc(1).as_bytes(),
        false,
        &Limits {
            deadline: Instant::now(),
            ..limits()
        },
    );
    assert_eq!(rule_of(r), Some(SupplyRule::Timeout));
}

#[test]
fn a_deadline_reader_passes_a_closed_stream_through() {
    let mut input = until(
        std::io::Cursor::new(api_doc(1).into_bytes()),
        limits().deadline,
    );
    assert!(read(&mut input, false, &limits()).is_ok());
}

#[test]
fn a_null_value_is_not_a_string() {
    let text = doc(
        "prod",
        1,
        r#""api/DATABASE_URL": null, "api/STRIPE_WEBHOOK_SECRET": "x""#,
    );
    assert_eq!(reason_of(admit_web(&text)), Some(SupplyRefusal::NotAString));
}

#[test]
fn a_number_value_is_not_a_string() {
    let text = doc("prod", 1, r#""api/DATABASE_URL": 5"#);
    assert_eq!(reason_of(admit_web(&text)), Some(SupplyRefusal::NotAString));
}

#[test]
fn a_value_holding_nul_is_not_a_string() {
    let text = doc(
        "prod",
        1,
        r#""api/DATABASE_URL": "postgresql://S7MARKER\u0000db""#,
    );
    assert_eq!(reason_of(admit_web(&text)), Some(SupplyRefusal::NotAString));
}

#[test]
fn an_empty_value_is_refused() {
    let text = doc("prod", 1, r#""api/DATABASE_URL": """#);
    assert_eq!(reason_of(admit_web(&text)), Some(SupplyRefusal::Empty));
}

#[test]
fn a_value_shorter_than_the_guard_masks_is_refused() {
    let text = doc("prod", 1, r#""api/DATABASE_URL": "pg://x""#);
    assert_eq!(reason_of(admit_web(&text)), Some(SupplyRefusal::TooShort));
}

#[test]
fn a_placeholder_value_is_refused() {
    let text = doc("prod", 1, r#""api/DATABASE_URL": "changeme""#);
    assert_eq!(
        reason_of(admit_web(&text)),
        Some(SupplyRefusal::Placeholder)
    );
}

#[test]
fn a_value_is_taken_byte_exact() {
    let padded = format!(" {DB}\n");
    let text = doc(
        "prod",
        1,
        &format!(
            r#""api/DATABASE_URL": "{}", "api/STRIPE_WEBHOOK_SECRET": "{HOOK}""#,
            padded.replace('\n', "\\n")
        ),
    );
    let supply = admit_web(&text).unwrap();
    assert_eq!(
        supply
            .get("api", "DATABASE_URL")
            .map(|s| s.value.expose().to_string()),
        Some(padded)
    );
}

// --- T3: names ---------------------------------------------------------------------------

#[test]
fn two_documents_supply_both_targets() {
    let jobs = doc("prod", 9, &format!(r#""worker/JOBS_URL": "{JOBS}""#));
    let text = format!("{}\n{jobs}", api_doc(4));
    let supply = admit_with(&text, "prod", &all_targets(), None, &BTreeSet::new()).unwrap();
    assert_eq!(
        supply.names().collect::<Vec<_>>(),
        [
            ("api", "DATABASE_URL"),
            ("api", "STRIPE_WEBHOOK_SECRET"),
            ("worker", "JOBS_URL")
        ]
    );
}

#[test]
fn each_value_keeps_its_documents_serial() {
    let jobs = doc("prod", 9, &format!(r#""worker/JOBS_URL": "{JOBS}""#));
    let text = format!("{}{jobs}", api_doc(4));
    let supply = admit_with(&text, "prod", &all_targets(), None, &BTreeSet::new()).unwrap();
    assert_eq!(supply.get("worker", "JOBS_URL").map(|s| s.serial), Some(9));
}

#[test]
fn an_undeclared_name_is_reported_by_position() {
    let text = doc(
        "prod",
        1,
        &format!(r#""api/DATABASE_URL": "{DB}", "api/NOPE": "{DB}""#),
    );
    assert_eq!(
        entry(&admit_web(&text).unwrap_err()),
        Some(SupplyEntry::Position {
            document: 1,
            index: 2
        })
    );
}

#[test]
fn an_undeclared_name_offers_the_closest_infrastructure_key() {
    let text = doc("prod", 1, &format!(r#""api/DATABASE_UR": "{DB}""#));
    assert_eq!(
        reason_of(admit_web(&text)),
        Some(SupplyRefusal::Undeclared {
            closest: Some("api/DATABASE_URL".to_string())
        })
    );
}

#[test]
fn a_bare_key_is_refused_offering_its_canonical_name() {
    let text = doc("prod", 1, &format!(r#""DATABASE_URL": "{DB}""#));
    assert_eq!(
        reason_of(admit_web(&text)),
        Some(SupplyRefusal::Undeclared {
            closest: Some("api/DATABASE_URL".to_string())
        })
    );
}

#[test]
fn a_rendered_target_name_is_refused_offering_its_canonical_name() {
    let text = doc("prod", 1, &format!(r#""APP_DATABASE_URL": "{DB}""#));
    assert_eq!(
        reason_of(admit_web(&text)),
        Some(SupplyRefusal::Undeclared {
            closest: Some("api/DATABASE_URL".to_string())
        })
    );
}

#[test]
fn a_key_from_1password_is_not_opted_in() {
    let text = doc("prod", 1, &format!(r#""api/TOKEN": "{DB}""#));
    assert_eq!(reason_of(admit_web(&text)), Some(SupplyRefusal::NotOptedIn));
}

#[test]
fn a_name_twice_in_one_object_is_a_duplicate() {
    let text = doc(
        "prod",
        1,
        &format!(r#""api/DATABASE_URL": "{DB}", "api/DATABASE_URL": "{DB2}""#),
    );
    assert_eq!(reason_of(admit_web(&text)), Some(SupplyRefusal::Duplicate));
}

#[test]
fn a_name_in_two_documents_is_a_duplicate() {
    let again = doc("prod", 2, &format!(r#""api/DATABASE_URL": "{DB2}""#));
    let text = format!("{}{again}", api_doc(1));
    assert_eq!(reason_of(admit_web(&text)), Some(SupplyRefusal::Duplicate));
}

#[test]
fn a_supply_missing_a_key_in_scope_names_it() {
    let text = doc("prod", 1, &format!(r#""api/DATABASE_URL": "{DB}""#));
    assert_eq!(
        reason_of(admit_web(&text)),
        Some(SupplyRefusal::NotSupplied {
            keys: vec!["api/STRIPE_WEBHOOK_SECRET".to_string()]
        })
    );
}

#[test]
fn a_whole_environment_run_must_supply_every_target() {
    let r = admit_with(&api_doc(1), "prod", &all_targets(), None, &BTreeSet::new());
    assert_eq!(
        reason_of(r),
        Some(SupplyRefusal::NotSupplied {
            keys: vec!["worker/JOBS_URL".to_string()]
        })
    );
}

#[test]
fn a_run_narrowed_by_product_needs_only_that_product() {
    let r = admit_with(
        &api_doc(1),
        "prod",
        &all_targets(),
        Some("api"),
        &BTreeSet::new(),
    );
    assert!(r.is_ok());
}

// --- T2: scope ---------------------------------------------------------------------------

#[test]
fn a_document_for_another_environment_names_it() {
    let text = api_doc(1).replace("\"env\": \"prod\"", "\"env\": \"staging\"");
    assert_eq!(
        reason_of(admit_web(&text)),
        Some(SupplyRefusal::WrongEnvironment {
            document_env: Some(EnvName::new("staging"))
        })
    );
}

#[test]
fn a_document_for_an_undeclared_environment_names_none() {
    let text = api_doc(1).replace("\"env\": \"prod\"", "\"env\": \"production\"");
    assert_eq!(
        reason_of(admit_web(&text)),
        Some(SupplyRefusal::WrongEnvironment { document_env: None })
    );
}

#[test]
fn a_document_without_an_environment_is_for_another_one() {
    let text = api_doc(1).replace("\"env\": \"prod\", ", "");
    assert_eq!(
        reason_of(admit_web(&text)),
        Some(SupplyRefusal::WrongEnvironment { document_env: None })
    );
}

#[test]
fn a_key_not_in_the_environment_is_refused() {
    let text = doc("qa", 1, &format!(r#""api/DATABASE_URL": "{DB}""#));
    let r = admit_with(&text, "qa", &["web".to_string()], None, &BTreeSet::new());
    assert_eq!(reason_of(r), Some(SupplyRefusal::NotInEnvironment));
}

#[test]
fn a_key_outside_the_selected_product_is_out_of_scope() {
    let r = admit_with(
        &api_doc(1),
        "prod",
        &all_targets(),
        Some("worker"),
        &BTreeSet::new(),
    );
    assert_eq!(
        reason_of(r),
        Some(SupplyRefusal::OutOfScope {
            targets: vec![TargetName::new("web"), TargetName::new("jobs")],
            product: Some(ProductName::new("worker")),
        })
    );
}

#[test]
fn a_key_outside_the_selected_target_is_out_of_scope() {
    let r = admit_with(
        &api_doc(1),
        "prod",
        &["jobs".to_string()],
        None,
        &BTreeSet::new(),
    );
    assert_eq!(
        reason_of(r),
        Some(SupplyRefusal::OutOfScope {
            targets: vec![TargetName::new("jobs")],
            product: None,
        })
    );
}

#[test]
fn rotating_an_unsupplied_infrastructure_key_is_refused() {
    let text = doc("prod", 1, &format!(r#""worker/JOBS_URL": "{JOBS}""#));
    let r = admit_with(
        &text,
        "prod",
        &["jobs".to_string()],
        None,
        &rotate(&[("api", "DATABASE_URL")]),
    );
    assert_eq!(reason_of(r), Some(SupplyRefusal::RotateWithoutValue));
}

#[test]
fn rotating_a_supplied_key_is_admitted() {
    let r = admit_with(
        &api_doc(1),
        "prod",
        &["web".to_string()],
        None,
        &rotate(&[("api", "DATABASE_URL")]),
    );
    assert!(r.is_ok());
}

#[test]
fn an_undefined_environment_is_refused_before_admission() {
    let r = admit_with(
        &api_doc(1),
        "nowhere",
        &["web".to_string()],
        None,
        &BTreeSet::new(),
    );
    assert!(r.is_err_and(|e| reason(&e).is_none()));
}

// --- T5: rules, through the planner ----------------------------------------------------------

/// prod's `web` target as the store lists it: `listed` (name, version).
fn store(listed: &[(&str, &str)]) -> Vec<StoreEntry> {
    listed
        .iter()
        .map(|(n, v)| StoreEntry {
            name: n.to_string(),
            version: Some(v.to_string()),
            pending: false,
            stamp: None,
        })
        .collect()
}

/// web's ledger: per name, (store version, the value its fingerprint is of, the supplied
/// serial when the line records a supplied value).
fn ledger(lines: &[(&str, &str, &str, Option<u64>)]) -> Ledger {
    let evidence: Vec<Evidence> = lines
        .iter()
        .map(|(name, version, value, serial)| Evidence {
            name: name.to_string(),
            store_version: version.to_string(),
            fingerprint: hmac_hex(EVIDENCE_KEY.as_bytes(), value.as_bytes()),
            source: Source {
                item_id: "supplied".into(),
                field: "api/KEY".into(),
            },
            attested_at: None,
            supplied: serial.map(|serial| SuppliedMark {
                serial,
                at: "2026-10-19T00:00:00Z".into(),
            }),
        })
        .collect();
    Ledger::from_evidence(Some(SecretValue::new(EVIDENCE_KEY.into())), &evidence)
}

/// The plan of prod's `web` target with `supply` appended, judged by `ledger` as
/// `plan_item_with` judges a staged store.
fn plan_web(
    supply: &Supply,
    listed: &[StoreEntry],
    ledger: &Ledger,
    rotate: &BTreeSet<(String, String)>,
) -> SyncPlan {
    let fleet = fleet();
    let versions: std::collections::BTreeMap<String, String> = listed
        .iter()
        .filter_map(|e| e.version.clone().map(|v| (e.name.clone(), v)))
        .collect();
    let current =
        |n: &str, v: &SecretValue| -> Option<CurrentState> { ledger.check(n, versions.get(n)?, v) };
    let none = BTreeSet::new();
    crate::domain::plan::build_with(
        &fleet,
        "prod",
        item_fields(&fleet, supply),
        listed,
        &PlanOptions {
            target: Some("web"),
            rotate,
            prune_immutable: &none,
            digest: &|_| None,
            target_check: &|_, _| None,
            current: Some(&current),
            retiring_prune: false,
        },
    )
}

fn web_name(p: &str, k: &str) -> String {
    fleet().target_name("prod", "web", p, k)
}

/// The refusal of `supply` (admitted for web) against `listed` and `ledger`.
fn judged(
    supply: &Supply,
    listed: &[(&str, &str)],
    ledger: &Ledger,
    rotate: &BTreeSet<(String, String)>,
) -> Option<SupplyRefusal> {
    let listed = store(listed);
    let plan = plan_web(supply, &listed, ledger, rotate);
    refusal(
        &plan,
        supply,
        std::slice::from_ref(ledger),
        rotate,
        &web_name,
    )
    .as_ref()
    .and_then(reason)
}

/// api's prod supply with `db` as the database URL, at `serial`.
fn supply_db(db: &str, serial: u64) -> Supply {
    let text = doc(
        "prod",
        serial,
        &format!(r#""api/DATABASE_URL": "{db}", "api/STRIPE_WEBHOOK_SECRET": "{HOOK}""#),
    );
    admit_web(&text).unwrap()
}

/// The webhook secret as staged: `ensure_prefix` added.
fn hook_staged() -> String {
    format!("whsec_{HOOK}")
}

#[test]
fn a_supplied_value_failing_its_rule_is_refused_as_the_producers() {
    let supply = supply_db("mysql://S7MARKER-not-postgres", 1);
    assert_eq!(
        judged(&supply, &[], &Ledger::default(), &BTreeSet::new()),
        Some(SupplyRefusal::RuleFailed {
            rule: "regex".to_string()
        })
    );
}

#[test]
fn a_supplied_value_gets_its_ensure_prefix() {
    let supply = supply_db(DB, 1);
    let plan = plan_web(&supply, &[], &Ledger::default(), &BTreeSet::new());
    let name = web_name("api", "STRIPE_WEBHOOK_SECRET");
    assert_eq!(
        plan.stage
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.expose().to_string()),
        Some(hook_staged())
    );
}

#[test]
fn supplied_item_fields_are_concealed_secrets() {
    let fields = item_fields(&fleet(), &supply_db(DB, 1));
    assert!(fields.iter().all(|f| f.kind == Kind::Secret && f.concealed));
}

// --- §4.3 and §5.1: the target state and the serial (the core of T7 and T8) -------------------

fn db_name() -> String {
    web_name("api", "DATABASE_URL")
}

fn hook_name() -> String {
    web_name("api", "STRIPE_WEBHOOK_SECRET")
}

#[test]
fn names_absent_on_the_target_are_written() {
    assert_eq!(
        judged(&supply_db(DB, 1), &[], &Ledger::default(), &BTreeSet::new()),
        None
    );
}

#[test]
fn a_listed_name_without_supplied_evidence_is_unproven() {
    let (db, hook) = (db_name(), hook_name());
    assert_eq!(
        judged(
            &supply_db(DB, 1),
            &[(&db, "v1"), (&hook, "v1")],
            &Ledger::default(),
            &BTreeSet::new()
        ),
        Some(SupplyRefusal::Unproven)
    );
}

#[test]
fn a_listed_name_with_only_a_1password_line_is_unproven() {
    let (db, hook) = (db_name(), hook_name());
    let l = ledger(&[
        (&db, "v1", DB, None),
        (&hook, "v1", &hook_staged(), Some(1)),
    ]);
    assert_eq!(
        judged(
            &supply_db(DB, 1),
            &[(&db, "v1"), (&hook, "v1")],
            &l,
            &BTreeSet::new()
        ),
        Some(SupplyRefusal::Unproven)
    );
}

#[test]
fn a_rotation_writes_a_name_without_evidence() {
    let (db, hook) = (db_name(), hook_name());
    assert_eq!(
        judged(
            &supply_db(DB, 1),
            &[(&db, "v1"), (&hook, "v1")],
            &Ledger::default(),
            &rotate(&[("api", "DATABASE_URL"), ("api", "STRIPE_WEBHOOK_SECRET")])
        ),
        None
    );
}

#[test]
fn the_same_value_at_the_recorded_version_needs_no_write() {
    let (db, hook) = (db_name(), hook_name());
    let l = ledger(&[
        (&db, "v1", DB, Some(1)),
        (&hook, "v1", &hook_staged(), Some(1)),
    ]);
    assert_eq!(
        judged(
            &supply_db(DB, 2),
            &[(&db, "v1"), (&hook, "v1")],
            &l,
            &BTreeSet::new()
        ),
        None
    );
}

#[test]
fn the_same_value_at_the_recorded_version_is_not_staged() {
    let (db, hook) = (db_name(), hook_name());
    let l = ledger(&[
        (&db, "v1", DB, Some(1)),
        (&hook, "v1", &hook_staged(), Some(1)),
    ]);
    let plan = plan_web(
        &supply_db(DB, 1),
        &store(&[(&db, "v1"), (&hook, "v1")]),
        &l,
        &BTreeSet::new(),
    );
    assert!(plan.stage.is_empty());
}

#[test]
fn a_changed_value_of_a_mutable_key_is_written() {
    let (db, hook) = (db_name(), hook_name());
    let l = ledger(&[
        (&db, "v1", DB, Some(1)),
        (&hook, "v1", &hook_staged(), Some(1)),
    ]);
    assert_eq!(
        judged(
            &supply_db(DB2, 2),
            &[(&db, "v1"), (&hook, "v1")],
            &l,
            &BTreeSet::new()
        ),
        None
    );
}

#[test]
fn a_changed_value_of_an_immutable_key_is_refused() {
    let (db, hook) = (db_name(), hook_name());
    let l = ledger(&[
        (&db, "v1", DB, Some(1)),
        (&hook, "v1", "whsec_S7MARKER-old-hook", Some(1)),
    ]);
    assert_eq!(
        judged(
            &supply_db(DB, 2),
            &[(&db, "v1"), (&hook, "v1")],
            &l,
            &BTreeSet::new()
        ),
        Some(SupplyRefusal::ImmutableDiffers)
    );
}

#[test]
fn a_rotation_writes_a_changed_immutable_key() {
    let (db, hook) = (db_name(), hook_name());
    let l = ledger(&[
        (&db, "v1", DB, Some(1)),
        (&hook, "v1", "whsec_S7MARKER-old-hook", Some(1)),
    ]);
    assert_eq!(
        judged(
            &supply_db(DB, 2),
            &[(&db, "v1"), (&hook, "v1")],
            &l,
            &rotate(&[("api", "STRIPE_WEBHOOK_SECRET")])
        ),
        None
    );
}

#[test]
fn a_drifted_mutable_key_is_written_to_repair_it() {
    let (db, hook) = (db_name(), hook_name());
    let l = ledger(&[
        (&db, "v1", DB, Some(1)),
        (&hook, "v1", &hook_staged(), Some(1)),
    ]);
    assert_eq!(
        judged(
            &supply_db(DB, 2),
            &[(&db, "v9"), (&hook, "v1")],
            &l,
            &BTreeSet::new()
        ),
        None
    );
}

#[test]
fn a_drifted_immutable_key_is_unproven() {
    let (db, hook) = (db_name(), hook_name());
    let l = ledger(&[
        (&db, "v1", DB, Some(1)),
        (&hook, "v1", &hook_staged(), Some(1)),
    ]);
    assert_eq!(
        judged(
            &supply_db(DB, 2),
            &[(&db, "v1"), (&hook, "v9")],
            &l,
            &BTreeSet::new()
        ),
        Some(SupplyRefusal::Unproven)
    );
}

#[test]
fn an_older_serial_is_stale() {
    let (db, hook) = (db_name(), hook_name());
    let l = ledger(&[
        (&db, "v1", DB, Some(7)),
        (&hook, "v1", &hook_staged(), Some(7)),
    ]);
    assert_eq!(
        judged(
            &supply_db(DB2, 6),
            &[(&db, "v1"), (&hook, "v1")],
            &l,
            &BTreeSet::new()
        ),
        Some(SupplyRefusal::Stale {
            recorded: 7,
            supplied: 6
        })
    );
}

#[test]
fn a_rotation_overrides_a_stale_serial() {
    let (db, hook) = (db_name(), hook_name());
    let l = ledger(&[
        (&db, "v1", DB, Some(7)),
        (&hook, "v1", &hook_staged(), Some(1)),
    ]);
    assert_eq!(
        judged(
            &supply_db(DB2, 6),
            &[(&db, "v1"), (&hook, "v1")],
            &l,
            &rotate(&[("api", "DATABASE_URL")])
        ),
        None
    );
}

#[test]
fn an_equal_serial_with_the_same_value_is_idempotent() {
    let (db, hook) = (db_name(), hook_name());
    let l = ledger(&[
        (&db, "v1", DB, Some(7)),
        (&hook, "v1", &hook_staged(), Some(7)),
    ]);
    assert_eq!(
        judged(
            &supply_db(DB, 7),
            &[(&db, "v1"), (&hook, "v1")],
            &l,
            &BTreeSet::new()
        ),
        None
    );
}

#[test]
fn an_equal_serial_with_another_value_is_reused() {
    let (db, hook) = (db_name(), hook_name());
    let l = ledger(&[
        (&db, "v1", DB, Some(7)),
        (&hook, "v1", &hook_staged(), Some(7)),
    ]);
    assert_eq!(
        judged(
            &supply_db(DB2, 7),
            &[(&db, "v1"), (&hook, "v1")],
            &l,
            &BTreeSet::new()
        ),
        Some(SupplyRefusal::SerialReused { serial: 7 })
    );
}

#[test]
fn a_rotation_overrides_a_reused_serial() {
    let (db, hook) = (db_name(), hook_name());
    let l = ledger(&[
        (&db, "v1", DB, Some(7)),
        (&hook, "v1", &hook_staged(), Some(7)),
    ]);
    assert_eq!(
        judged(
            &supply_db(DB2, 7),
            &[(&db, "v1"), (&hook, "v1")],
            &l,
            &rotate(&[("api", "DATABASE_URL")])
        ),
        None
    );
}

#[test]
fn an_equal_serial_while_drifted_repairs_the_drift() {
    let (db, hook) = (db_name(), hook_name());
    let l = ledger(&[
        (&db, "v1", DB, Some(7)),
        (&hook, "v1", &hook_staged(), Some(7)),
    ]);
    assert_eq!(
        judged(
            &supply_db(DB, 7),
            &[(&db, "v9"), (&hook, "v1")],
            &l,
            &BTreeSet::new()
        ),
        None
    );
}

// --- T6: a stored field ----------------------------------------------------------------------

fn field(product: &str, key: &str) -> ItemField {
    ItemField {
        section: product.into(),
        label: key.into(),
        kind: Kind::Secret,
        value: SecretValue::new(DB.into()),
        concealed: true,
    }
}

#[test]
fn a_1password_field_of_an_infrastructure_key_is_refused() {
    let r = refuse_stored(&fleet(), "prod", &[field("api", "DATABASE_URL")]);
    assert_eq!(
        r.err().as_ref().and_then(reason),
        Some(SupplyRefusal::Stored {
            boundary: "api".to_string()
        })
    );
}

#[test]
fn a_1password_field_of_an_ordinary_key_is_kept() {
    assert!(refuse_stored(&fleet(), "prod", &[field("api", "TOKEN")]).is_ok());
}

#[test]
fn a_stored_field_is_refused_by_name() {
    let r = refuse_stored(&fleet(), "prod", &[field("api", "DATABASE_URL")]);
    assert_eq!(
        r.err().as_ref().and_then(entry),
        Some(SupplyEntry::Named {
            product: ProductName::new("api"),
            key: KeyName::new("DATABASE_URL")
        })
    );
}

#[test]
fn a_stored_field_points_at_the_proposal_that_archives_it() {
    let r = refuse_stored(&fleet(), "prod", &[field("api", "DATABASE_URL")]);
    assert_eq!(
        r.err().and_then(|e| e.next_text()),
        Some("opv propose key api/DATABASE_URL --source infrastructure".to_string())
    );
}

#[test]
fn infrastructure_is_recognised_from_the_declaration() {
    let f = fleet();
    assert!(is_infrastructure(&f.products["api"].keys["DATABASE_URL"]));
}

#[test]
fn a_key_from_1password_is_not_infrastructure() {
    let f = fleet();
    assert!(!is_infrastructure(&f.products["api"].keys["TOKEN"]));
}

// --- T5: refused at load (§2.2) --------------------------------------------------------------

/// The fixture's DATABASE_URL declaration body.
const DB_OK: &str = "kind = \"secret\"\nsource = \"infrastructure\"\nenvironments = [\"staging\", \"prod\"]\nrules = { regex = \"postgres(ql)?://.+\" }\n";

/// The fixture with DATABASE_URL's declaration body replaced by `body`.
fn with_db(body: &str) -> String {
    FLEET.replace(DB_OK, body)
}

/// The field and rule a configuration is refused with.
fn load_refusal(text: &str) -> Option<(String, FieldRule)> {
    match crate::config::parse(text).err()?.parts().0 {
        Cause::ConfigInvalid { field, rule, .. } => Some((field.to_string(), rule.clone())),
        _ => None,
    }
}

fn conflicts(field: &str) -> FieldRule {
    FieldRule::ConflictsWith {
        field: crate::cause::DottedPath(field.split('.').map(str::to_string).collect()),
    }
}

#[test]
fn the_fixture_declares_the_body_the_load_tests_replace() {
    assert_eq!(FLEET.matches(DB_OK).count(), 1);
}

#[test]
fn an_immutable_infrastructure_key_loads() {
    assert!(crate::config::parse(&with_db(&format!("{DB_OK}immutable = true\n"))).is_ok());
}

#[test]
fn infrastructure_with_from_is_refused_at_source() {
    let body = format!("{DB_OK}from = \"api/TOKEN\"\n");
    assert_eq!(
        load_refusal(&with_db(&body)),
        Some((
            "products.api.keys.DATABASE_URL.source".to_string(),
            conflicts("products.api.keys.DATABASE_URL.from")
        ))
    );
}

#[test]
fn a_key_reading_an_infrastructure_key_is_refused_at_its_from() {
    let text = format!(
        "{FLEET}\n[products.worker.keys.DB]\nkind = \"secret\"\nenvironments = [\"prod\"]\nfrom = \"api/DATABASE_URL\"\n"
    );
    assert_eq!(
        load_refusal(&text),
        Some((
            "products.worker.keys.DB.from".to_string(),
            conflicts("products.api.keys.DATABASE_URL.source")
        ))
    );
}

#[test]
fn infrastructure_config_is_refused() {
    let body = DB_OK.replace("kind = \"secret\"", "kind = \"config\"");
    assert_eq!(
        load_refusal(&with_db(&body)),
        Some((
            "products.api.keys.DATABASE_URL.source".to_string(),
            conflicts("products.api.keys.DATABASE_URL.kind")
        ))
    );
}

#[test]
fn a_personal_infrastructure_key_is_refused() {
    let body = format!("{DB_OK}personal = true\n");
    assert_eq!(
        load_refusal(&with_db(&body)),
        Some((
            "products.api.keys.DATABASE_URL.source".to_string(),
            conflicts("products.api.keys.DATABASE_URL.personal")
        ))
    );
}

#[test]
fn infrastructure_without_environments_is_refused() {
    let body = DB_OK.replace("environments = [\"staging\", \"prod\"]\n", "");
    assert_eq!(
        load_refusal(&with_db(&body)),
        Some((
            "products.api.keys.DATABASE_URL.environments".to_string(),
            FieldRule::Missing
        ))
    );
}

#[test]
fn infrastructure_in_an_environment_without_a_target_is_refused() {
    let body = DB_OK.replace("[\"staging\", \"prod\"]", "[\"dev\", \"prod\"]");
    assert_eq!(
        load_refusal(&with_db(&body)),
        Some((
            "products.api.keys.DATABASE_URL.environments".to_string(),
            FieldRule::Type {
                expected: "infrastructure only in environments with targets"
            }
        ))
    );
}

#[test]
fn infrastructure_without_a_shape_rule_is_refused_at_source() {
    let body = DB_OK.replace("rules = { regex = \"postgres(ql)?://.+\" }\n", "");
    assert_eq!(
        load_refusal(&with_db(&body)).map(|(f, _)| f),
        Some("products.api.keys.DATABASE_URL.source".to_string())
    );
}

#[test]
fn a_not_prefix_rule_alone_is_no_shape_rule() {
    let body = DB_OK.replace(
        "rules = { regex = \"postgres(ql)?://.+\" }",
        "rules = { not_prefix = \"sk_\" }",
    );
    assert_eq!(
        load_refusal(&with_db(&body)).map(|(f, _)| f),
        Some("products.api.keys.DATABASE_URL.source".to_string())
    );
}

#[test]
fn infrastructure_with_allow_same_value_is_refused() {
    let body = format!("{DB_OK}allow_same_value = true\n");
    assert_eq!(
        load_refusal(&with_db(&body)),
        Some((
            "products.api.keys.DATABASE_URL.allow_same_value".to_string(),
            conflicts("products.api.keys.DATABASE_URL.source")
        ))
    );
}

#[test]
fn infrastructure_in_a_source_only_product_is_refused() {
    let text = format!(
        "{FLEET}\n[products.shared]\nsource_only = true\n[products.shared.keys.URL]\nkind = \"secret\"\nsource = \"infrastructure\"\nenvironments = [\"prod\"]\nrules = {{ https_url = true }}\n"
    );
    assert_eq!(
        load_refusal(&text),
        Some((
            "products.shared.keys.URL.source".to_string(),
            conflicts("products.shared.source_only")
        ))
    );
}

#[test]
fn infrastructure_delivered_by_a_pinned_target_is_refused() {
    let text = FLEET.replace(
        "[environments.staging.targets.web]\nfly.app = \"web-staging\"\nfly.secret_name = \"APP_{KEY}\"\n",
        "[environments.staging.targets.web]\nkubernetes.context = \"kind-opv\"\nkubernetes.namespace = \"opv\"\nkubernetes.deployment = \"api\"\nkubernetes.env_name = \"APP_{KEY}\"\n",
    );
    assert_eq!(
        load_refusal(&text).map(|(f, _)| f),
        Some("products.api.keys.DATABASE_URL.source".to_string())
    );
}

#[test]
fn a_load_refusal_is_placed_at_its_line() {
    let text = with_db(&format!("{DB_OK}allow_same_value = true\n"));
    let line = text
        .lines()
        .position(|l| l == "allow_same_value = true")
        .and_then(|i| u32::try_from(i + 1).ok());
    let at = match crate::config::parse(&text)
        .err()
        .map(|e| e.parts().0.clone())
    {
        Some(Cause::ConfigInvalid { at, .. }) => at.map(|l| l.line),
        _ => None,
    };
    assert_eq!(at, line);
}

// --- T13 (core): no supplied value in any text opv shows ---------------------------------------

#[test]
fn debug_of_a_supply_shows_names_only() {
    let supply = supply_db(DB, 1);
    assert!(!format!("{supply:?} {supply:#?}").contains(MARK));
}

#[test]
fn debug_of_a_supplied_value_shows_its_name_only() {
    let supply = supply_db(DB, 1);
    let s = supply.get("api", "DATABASE_URL").unwrap();
    assert!(!format!("{s:?} {s:#?}").contains(MARK));
}

#[test]
fn debug_of_a_raw_supply_shows_counts_only() {
    let raw = read_text(&api_doc(1)).unwrap();
    assert!(!format!("{raw:?} {raw:#?}").contains(MARK));
}

#[test]
fn debug_of_a_deadline_reader_shows_nothing_it_passed() {
    let mut input = until(
        std::io::Cursor::new(api_doc(1).into_bytes()),
        limits().deadline,
    );
    let mut first = [0u8; 4];
    let _ = input.read(&mut first);
    assert!(!format!("{input:?}").contains(MARK));
}

#[test]
fn a_value_is_registered_with_the_output_guard_as_it_is_parsed() {
    // Refused at admission (not opted in), yet already masked by the output guard.
    let canary = "S7MARKER-registered-at-parse-0001";
    let _ = admit_web(&doc("prod", 1, &format!(r#""api/TOKEN": "{canary}""#)));
    assert!(!crate::scrub::guard_scrub(&format!("x {canary} y")).contains(MARK));
}

#[test]
fn a_value_in_invalid_json_is_never_quoted() {
    let text = format!(
        r#"{{"schema": "opv.supply/1", "env": "prod", "values": {{"api/DATABASE_URL": {DB}}}}}"#
    );
    let e = read_text(&text).unwrap_err();
    assert!(!shown(&e).contains(MARK));
}

#[test]
fn a_value_where_a_name_belongs_is_never_echoed() {
    let text = doc("prod", 1, &format!(r#""{DB}": "{DB2}""#));
    let e = admit_web(&text).unwrap_err();
    assert!(!shown(&e).contains(MARK));
}

#[test]
fn a_value_where_the_environment_belongs_is_never_echoed() {
    let text = api_doc(1).replace("\"env\": \"prod\"", &format!("\"env\": \"{DB}\""));
    let e = admit_web(&text).unwrap_err();
    assert!(!shown(&e).contains(MARK));
}

/// Inputs refused by the stream or by admission, each holding canaries where a value, a
/// name, a schema, a serial or an environment belongs.
fn refused_inputs() -> Vec<String> {
    vec![
        format!("{}{{\"schema\": \"{DB}", api_doc(1)),
        format!(
            r#"{{"schema": "{DB}", "env": "prod", "serial": 1, "values": {{"api/DATABASE_URL": "{DB}"}}}}"#
        ),
        format!(
            r#"{{"schema": "opv.supply/1", "env": "prod", "serial": "{DB}", "values": {{"api/DATABASE_URL": "{DB}"}}}}"#
        ),
        format!(
            r#"{{"schema": "opv.supply/1", "env": "prod", "serial": 1, "values": {{"api/DATABASE_URL": "{DB}"}}, "{DB}": 1}}"#
        ),
        format!(r#"{{"schema": "opv.supply/1", "env": "prod", "serial": 1, "values": ["{DB}"]}}"#),
        format!("[\"{DB}\"]"),
        doc("prod", 1, &format!(r#""api/TOKEN": "{DB}""#)),
        doc(
            "prod",
            1,
            &format!(r#""api/DATABASE_URL": "{DB}", "api/DATABASE_URL": "{DB2}""#),
        ),
        doc("prod", 1, &format!(r#""api/DATABASE_URL": "{DB}""#)),
        doc("prod", 1, r#""api/DATABASE_URL": "S7MARK""#),
        doc("prod", 1, &format!(r#""worker/JOBS_URL": "{JOBS}""#)),
        doc("staging", 1, &format!(r#""api/DATABASE_URL": "{DB}""#)),
        doc("prod", 1, &format!(r#""{DB}": "{DB2}""#)),
    ]
}

#[test]
fn every_leak_case_is_refused() {
    // The leak test below is only as strong as its cases: each one must be refused.
    assert!(refused_inputs().iter().all(|c| admit_web(c).is_err()));
}

#[test]
fn no_refusal_or_stream_error_shows_a_supplied_value() {
    let fleet = fleet();
    let mut errors: Vec<Error> = refused_inputs()
        .iter()
        .filter_map(|c| admit_web(c).err())
        .collect();
    let supply = supply_db("mysql://S7MARKER-not-postgres", 1);
    errors.extend(refusal(
        &plan_web(&supply, &[], &Ledger::default(), &BTreeSet::new()),
        &supply,
        &[],
        &BTreeSet::new(),
        &web_name,
    ));
    errors.extend(refuse_stored(&fleet, "prod", &[field("api", "DATABASE_URL")]).err());
    let leaked: Vec<String> = errors
        .iter()
        .map(shown)
        .filter(|t| t.contains(MARK))
        .collect();
    assert_eq!(leaked, Vec::<String>::new());
}

// --- the catalog rows -------------------------------------------------------------------------

fn not_opted_in() -> Error {
    admit_web(&doc("prod", 1, &format!(r#""api/TOKEN": "{DB}""#))).unwrap_err()
}

#[test]
fn a_supply_refusal_is_policy_refused_with_exit_6() {
    let e = not_opted_in();
    assert_eq!((e.code_str(), e.exit_code()), ("policy_refused", 6));
}

#[test]
fn a_supply_refusal_is_the_supply_refused_guard() {
    let doc = crate::error::document(&not_opted_in(), &crate::error::invocation(), false);
    assert_eq!(doc["subject"]["guard"]["guard"], "supply_refused");
}

#[test]
fn a_stream_problem_is_input_invalid() {
    assert_eq!(read_text("").unwrap_err().code_str(), "input_invalid");
}

#[test]
fn a_supply_refusal_names_the_entry_and_the_reason() {
    assert_eq!(
        not_opted_in().text(),
        "opv refuses the supplied value of api/TOKEN for environment prod: its value comes from 1Password; only an infrastructure key takes a supplied value"
    );
}

#[test]
fn an_undeclared_name_is_shown_by_position() {
    let e = admit_web(&doc("prod", 1, &format!(r#""api/NOPE": "{DB}""#))).unwrap_err();
    assert!(e.text().contains("document 1, entry 1"));
}

#[test]
fn a_not_opted_in_key_points_at_explain() {
    assert_eq!(
        not_opted_in().next_text(),
        Some("opv explain api/TOKEN --env prod".to_string())
    );
}

#[test]
fn a_stream_problem_names_the_document() {
    let e = read_text(r#"{"schema": "opv.supply/1", "env": "prod", "values": {"a/B": "x"}}"#)
        .unwrap_err();
    assert_eq!(
        e.text(),
        "the supply <stdin>: document 1 has no serial (a whole number from the producer's own object)"
    );
}

#[test]
fn attesting_an_infrastructure_key_has_its_own_reason() {
    assert!(
        crate::cause::AttestRefusal::NotStored
            .words()
            .contains("never stored")
    );
}
