//! `opv sync --supply-stdin` end to end (#206, `docs/design/deliver-only.md`, the sync lane's
//! tests T1, T7 to T12, T14 and its half of T13): a supply read from a byte stream, admitted
//! for the run's scope, delivered to Fly through the staged store, and recorded as `s1`
//! evidence lines in the placement's delivery item. 1Password is the stateful fake; Fly is
//! a small store that lists a digest and a staged flag per name. Every supplied value holds
//! [`MARK`]; no output, receipt, evidence or error may contain one. One scenario and one
//! assertion per test.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::io;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::adapters::fake_op::FakeOp;
use crate::app::deliver_only::{Limits, read};
use crate::app::sync::{self, SyncOpts};
use crate::app::testutil::{fly_app_ok, fly_releases, ok};
use crate::cause::{Cause, Guard, SupplyRefusal};
use crate::domain::Fleet;
use crate::error::Error;
use crate::runner::{Call, CommandRunner, Outcome, Output};

/// The marker every supplied canary holds.
const MARK: &str = "S7MARKER";
const DB: &str = "postgresql://S7MARKER-db-0001@db.example/app";
const DB2: &str = "postgresql://S7MARKER-db-0002@db.example/app";
const HOOK: &str = "S7MARKER-hook-0001";
const HOOK2: &str = "S7MARKER-hook-0002";
const VALUES: &str = "vdev0000000000000000000001";
const STATE: &str = "vshr0000000000000000000002";
const APP: &str = "web-prod";
const DB_NAME: &str = "APP_DATABASE_URL";
const HOOK_NAME: &str = "APP_STRIPE_WEBHOOK_SECRET";

fn digest(v: &str) -> String {
    hex::encode(Sha256::digest(v))[..16].to_string()
}

/// A hook run when the delivery item is read for the n-th time (1-based).
type OnRead = Box<dyn Fn(&FakeOp)>;

/// 1Password (the stateful fake) plus one Fly app's secrets.
struct World {
    op: FakeOp,
    /// name → (value, staged).
    fly: RefCell<BTreeMap<String, (String, bool)>>,
    /// Every flyctl call, as its args joined by spaces.
    fly_calls: RefCell<Vec<String>>,
    /// The next `secrets import` fails before it reaches Fly.
    fail_import: Cell<bool>,
    /// Every 1Password write to the delivery item fails.
    fail_state_write: Cell<bool>,
    /// The digest Fly lists for every name, instead of the real one.
    digest_override: RefCell<Option<String>>,
    /// The delivery item's id, and how often it was read.
    state_item: String,
    state_reads: Cell<usize>,
    on_state_read: RefCell<Vec<(usize, OnRead)>>,
}

impl World {
    fn fly(&self, args: &[&str], stdin: Option<&[u8]>) -> Output {
        self.fly_calls.borrow_mut().push(args.join(" "));
        match args {
            ["status", ..] => fly_app_ok(),
            ["releases", ..] => fly_releases("complete"),
            ["secrets", "list", ..] => {
                let over = self.digest_override.borrow().clone();
                let v: Vec<Value> = self
                    .fly
                    .borrow()
                    .iter()
                    .map(|(n, (value, staged))| {
                        json!({"name": n,
                               "digest": over.clone().unwrap_or_else(|| digest(value)),
                               "status": if *staged { "Staged" } else { "Deployed" }})
                    })
                    .collect();
                Output::success(serde_json::to_vec(&v).unwrap())
            }
            ["secrets", "import", ..] => {
                if self.fail_import.replace(false) {
                    return Output::failure(1);
                }
                let text = String::from_utf8(stdin.unwrap().to_vec()).unwrap();
                let mut secrets = self.fly.borrow_mut();
                for line in text.lines() {
                    let (name, quoted) = line.split_once('=').unwrap();
                    let value = quoted.trim_matches('"').to_string();
                    let same = secrets.get(name).is_some_and(|(v, _)| *v == value);
                    if !same {
                        secrets.insert(name.to_string(), (value, true));
                    }
                }
                ok()
            }
            ["secrets", "deploy", ..] => {
                for (_, staged) in self.fly.borrow_mut().values_mut() {
                    *staged = false;
                }
                ok()
            }
            other => panic!("unexpected flyctl call {other:?}"),
        }
    }

    /// How many `secrets import` calls Fly saw.
    fn imports(&self) -> usize {
        self.fly_calls
            .borrow()
            .iter()
            .filter(|c| c.starts_with("secrets import"))
            .count()
    }

    /// The value Fly holds for `name`.
    fn on_fly(&self, name: &str) -> Option<String> {
        self.fly.borrow().get(name).map(|(v, _)| v.clone())
    }

    /// Someone sets `name` on Fly directly, outside opv.
    fn set_on_fly(&self, name: &str, value: &str) {
        self.fly
            .borrow_mut()
            .insert(name.to_string(), (value.to_string(), false));
    }

    /// The delivery item as 1Password holds it.
    fn state(&self) -> Value {
        self.op.item(&self.state_item)
    }

    /// The value of the delivery item's field `label`.
    fn state_field(&self, label: &str) -> Option<String> {
        self.state()["fields"]
            .as_array()?
            .iter()
            .find(|f| f["label"] == label)
            .and_then(|f| f["value"].as_str().map(str::to_string))
    }

    /// The receipt the delivery item holds.
    fn receipt(&self) -> Value {
        serde_json::from_str(&self.state_field("receipt").unwrap_or_default())
            .unwrap_or(Value::Null)
    }
}

/// Set field `label` of the delivery item to `value` (adding it), as another run would.
fn put_state_field(op: &FakeOp, id: &str, label: &str, value: &str) {
    let mut items = op.items.borrow_mut();
    let item = items.iter_mut().find(|i| i["id"] == id).unwrap();
    let fields = item["fields"].as_array_mut().unwrap();
    fields.retain(|f| f["label"] != label);
    fields.push(json!({"id": label, "label": label, "type": "CONCEALED", "value": value}));
    let v = item["version"].as_u64().unwrap_or(0) + 1;
    item["version"] = json!(v);
    op.cache.borrow_mut().remove(id);
}

impl CommandRunner for World {
    fn read(&self, call: &Call<'_>, refused: &[i32]) -> io::Result<Outcome> {
        if call.program == "op" || call.program == "git" {
            if call.args.starts_with(&["item", "get"])
                && call.args.get(2) == Some(&self.state_item.as_str())
            {
                let n = self.state_reads.get() + 1;
                self.state_reads.set(n);
                for (at, hook) in self.on_state_read.borrow().iter() {
                    if *at == n {
                        hook(&self.op);
                    }
                }
            }
            return self.op.read(call, refused);
        }
        let out = self.fly(call.args, call.stdin);
        Ok(if out.status == 0 {
            Outcome::Done(out)
        } else {
            Outcome::Refused(out)
        })
    }

    fn write(&self, call: &Call<'_>) -> io::Result<Outcome> {
        if call.program == "op"
            && self.fail_state_write.get()
            && call.args.iter().any(|a| *a == self.state_item)
        {
            return Ok(Outcome::Unknown {
                reason: "failed-write",
                status: Some(1),
            });
        }
        if call.program == "op" || call.program == "git" {
            return self.op.write(call);
        }
        let out = self.fly(call.args, call.stdin);
        Ok(if out.status == 0 {
            Outcome::Done(out)
        } else {
            Outcome::Unknown {
                reason: "failed-write",
                status: Some(out.status),
            }
        })
    }

    fn writes_started(&self) -> bool {
        false
    }

    fn probe(&self, call: &Call<'_>, limit: Duration) -> io::Result<Output> {
        if call.program == "op" {
            return self.op.probe(call, limit);
        }
        Ok(ok())
    }

    fn pause(&self, _: Duration, _: &str) {}

    fn note(&self, _: &str) {}

    fn run_inherited(&self, _: &str, _: &[&str], _: &[(&str, &str)]) -> io::Result<i32> {
        unreachable!("sync never runs a child")
    }
}

/// prod on Fly app `web-prod` (target `web`, names `APP_<KEY>`): api's DATABASE_URL and
/// STRIPE_WEBHOOK_SECRET (immutable) are infrastructure keys, TOKEN is stored. With
/// `item` false, the placement has no delivery item recorded.
fn world_with(item: bool, immutable_hook: bool) -> (World, Fleet) {
    let op = FakeOp::default();
    let values = op.insert(
        VALUES,
        json!({
            "title": "myapp · prod values", "category": "SECURE_NOTE",
            "sections": [{"id": "api", "label": "api"}],
            "fields": [{"id": "api-TOKEN", "section": {"id": "api", "label": "api"},
                        "type": "CONCEALED", "label": "TOKEN", "value": "tok-FIXTUREVALUE-1"}]
        }),
    );
    let state = op.insert(
        STATE,
        json!({"title": crate::domain::naming::delivery_item("api", "web"),
               "category": "SECURE_NOTE",
               "fields": [{"id": "notesPlain", "type": "STRING", "purpose": "NOTES",
                           "label": "notesPlain",
                           "value": crate::domain::naming::delivery_item_notes("api", "web", "prod")}]}),
    );
    let items = if item {
        format!("delivery_items = {{ api = \"{state}\" }}\n")
    } else {
        String::new()
    };
    let fleet = crate::config::parse(&format!(
        "[environments.prod]\n\
         boundaries.api = {{ vault_id = \"{VALUES}\", item_id = \"{values}\" }}\n\
         [environments.prod.targets.web]\nstate_vault_id = \"{STATE}\"\n\
         fly.app = \"{APP}\"\nfly.secret_name = \"APP_{{KEY}}\"\n{items}\
         [products.api.keys.DATABASE_URL]\nkind = \"secret\"\nsource = \"infrastructure\"\n\
         environments = [\"prod\"]\nrules = {{ regex = \"postgres(ql)?://.+\" }}\n\
         [products.api.keys.STRIPE_WEBHOOK_SECRET]\nkind = \"secret\"\nsource = \"infrastructure\"\n\
         environments = [\"prod\"]\nimmutable = {immutable_hook}\nrules = {{ ensure_prefix = \"whsec_\" }}\n\
         [products.api.keys.TOKEN]\nkind = \"secret\"\nenvironments = [\"prod\"]\n"
    ))
    .unwrap();
    let w = World {
        op,
        fly: RefCell::default(),
        fly_calls: RefCell::default(),
        fail_import: Cell::new(false),
        fail_state_write: Cell::new(false),
        digest_override: RefCell::default(),
        state_item: state,
        state_reads: Cell::new(0),
        on_state_read: RefCell::default(),
    };
    (w, fleet)
}

fn world() -> (World, Fleet) {
    world_with(true, true)
}

/// One `opv.supply/1` document for prod.
fn doc(serial: u64, values: &[(&str, &str)]) -> String {
    let values: serde_json::Map<String, Value> = values
        .iter()
        .map(|(k, v)| (k.to_string(), json!(v)))
        .collect();
    json!({"schema": "opv.supply/1", "env": "prod", "serial": serial, "values": values}).to_string()
}

/// Both values in two documents, as Terraform and the Stripe helper print them.
fn both(serial: u64, db: &str, hook: &str) -> String {
    format!(
        "{}\n{}\n",
        doc(serial, &[("api/DATABASE_URL", db)]),
        doc(serial, &[("api/STRIPE_WEBHOOK_SECRET", hook)])
    )
}

/// `opv sync prod --supply-stdin` with `opts`, `text` on standard input: the result and
/// stdout.
fn supply(w: &World, fleet: &Fleet, opts: SyncOpts, text: &str) -> (Result<(), Error>, String) {
    let _person = crate::app::tidy::activate();
    let mut out = Vec::new();
    let limits = Limits::new(Instant::now() + Duration::from_secs(60));
    let res = read(&mut text.as_bytes(), false, &limits).and_then(|raw| {
        sync::run_supplying(
            fleet,
            "prod",
            w,
            &mut out,
            &SyncOpts {
                supply_stdin: true,
                ..opts
            },
            raw,
        )
    });
    (res, String::from_utf8(out).unwrap())
}

/// The database URL changed at the older serial 9, the webhook secret unchanged at 10.
fn stale_db() -> String {
    format!(
        "{}\n{}\n",
        doc(9, &[("api/DATABASE_URL", DB2)]),
        doc(10, &[("api/STRIPE_WEBHOOK_SECRET", HOOK)])
    )
}

/// A supplying sync of both values at `serial`, no flags.
fn supply_both(w: &World, fleet: &Fleet, serial: u64, db: &str, hook: &str) -> Result<(), Error> {
    supply(w, fleet, SyncOpts::default(), &both(serial, db, hook)).0
}

fn rotating(keys: &[&str]) -> SyncOpts {
    SyncOpts {
        rotate: keys.iter().map(|k| k.to_string()).collect(),
        ..SyncOpts::default()
    }
}

/// A scheduled sync, no supply.
fn scheduled(w: &World, fleet: &Fleet) -> (Result<(), Error>, String) {
    let _person = crate::app::tidy::activate();
    let mut out = Vec::new();
    let res = sync::run(fleet, "prod", w, &mut out, &SyncOpts::default());
    (res, String::from_utf8(out).unwrap())
}

/// A world where both values were supplied once at serial 10.
fn supplied() -> (World, Fleet) {
    let (w, fleet) = world();
    supply_both(&w, &fleet, 10, DB, HOOK).unwrap();
    (w, fleet)
}

/// The refusal reason of a supplying sync's error.
fn reason(e: &Error) -> Option<SupplyRefusal> {
    match e.cause()?.0 {
        Cause::Guard {
            guard: Guard::SupplyRefused { reason, .. },
        } => Some(reason.clone()),
        Cause::Partial { then, .. } => match then.as_ref() {
            Cause::Guard {
                guard: Guard::SupplyRefused { reason, .. },
            } => Some(reason.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// The catalog code of an error.
fn code(e: &Error) -> String {
    crate::error::document(e, &crate::error::invocation(), false)["code"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// Every text a run of `w` could show or keep: its stdout, its error's document, the
/// delivery item and every 1Password call's argv and stdin.
fn everything(w: &World, out: &str, res: &Result<(), Error>) -> String {
    let err = match res {
        Err(e) => {
            crate::error::document(e, &crate::error::invocation(), true).to_string()
                + &e.to_string()
        }
        Ok(()) => String::new(),
    };
    let calls: String =
        w.op.calls
            .borrow()
            .iter()
            .map(|c| {
                c.args.join(" ")
                    + &c.stdin
                        .as_ref()
                        .map(|s| String::from_utf8_lossy(s).to_string())
                        .unwrap_or_default()
            })
            .collect();
    format!("{out}{err}{}{calls}", w.state())
}

// --- T1: the positive path ---------------------------------------------------------------

#[test]
fn t1_two_documents_deliver_the_database_url() {
    let (w, _fleet) = supplied();
    assert_eq!(w.on_fly(DB_NAME).as_deref(), Some(DB));
}

#[test]
fn t1_the_webhook_secret_is_delivered_with_its_ensured_prefix() {
    let (w, _fleet) = supplied();
    assert_eq!(w.on_fly(HOOK_NAME), Some(format!("whsec_{HOOK}")));
}

#[test]
fn t1_a_supplied_name_gets_an_s1_line() {
    let (w, _fleet) = supplied();
    assert!(
        w.state_field(DB_NAME)
            .unwrap_or_default()
            .starts_with("s1|")
    );
}

#[test]
fn t1_the_s1_line_records_the_serial() {
    let (w, _fleet) = supplied();
    let line = w.state_field(DB_NAME).unwrap_or_default();
    assert_eq!(line.split('|').nth(4), Some("10"));
}

#[test]
fn t1_the_s1_line_names_the_key_not_a_1password_item() {
    let (w, _fleet) = supplied();
    let line = w.state_field(DB_NAME).unwrap_or_default();
    assert_eq!(line.split('|').nth(3), Some("api/DATABASE_URL"));
}

#[test]
fn t1_the_revision_lists_the_supplied_names() {
    let (w, _fleet) = supplied();
    assert_eq!(w.receipt()["supplied"], json!([DB_NAME, HOOK_NAME]));
}

#[test]
fn t1_a_supplied_binding_names_supplied_as_its_source() {
    let (w, _fleet) = supplied();
    let bindings = w.receipt()["bindings"].clone();
    let db = bindings
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["name"] == DB_NAME)
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        db["source"],
        json!({"item_id": "supplied", "field": "api/DATABASE_URL"})
    );
}

#[test]
fn t1_the_values_item_is_unchanged() {
    let (w, fleet) = world();
    let id = fleet.environments["prod"].boundaries["api"]
        .as_ref()
        .unwrap()
        .item_id
        .clone();
    let before = w.op.item(&id);
    supply_both(&w, &fleet, 10, DB, HOOK).unwrap();
    assert_eq!(w.op.item(&id), before);
}

#[test]
fn t1_the_receipt_file_marks_the_supplied_names() {
    let (w, fleet) = world();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("web.receipt.json");
    let opts = SyncOpts {
        receipt: Some(path.clone()),
        ..SyncOpts::default()
    };
    supply(&w, &fleet, opts, &both(10, DB, HOOK)).0.unwrap();
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        doc["deliveries"][0]["supplied"],
        json!([DB_NAME, HOOK_NAME])
    );
}

#[test]
fn t1_an_admission_refusal_reads_no_1password() {
    let (w, fleet) = world();
    let _ = supply(
        &w,
        &fleet,
        SyncOpts::default(),
        &doc(10, &[("api/DATABASE_URL", DB)]),
    );
    assert!(w.op.calls.borrow().is_empty());
}

#[test]
fn t1_an_incomplete_supply_is_not_supplied() {
    let (w, fleet) = world();
    let (res, _) = supply(
        &w,
        &fleet,
        SyncOpts::default(),
        &doc(10, &[("api/DATABASE_URL", DB)]),
    );
    assert!(matches!(
        reason(&res.unwrap_err()),
        Some(SupplyRefusal::NotSupplied { .. })
    ));
}

// --- T7: every cell of §4.3 ----------------------------------------------------------------

#[test]
fn t7_a_name_listed_without_evidence_is_unproven() {
    let (w, fleet) = world_with(true, false);
    w.set_on_fly(DB_NAME, "postgresql://set-by-terraform");
    let res = supply_both(&w, &fleet, 10, DB, HOOK);
    assert_eq!(reason(&res.unwrap_err()), Some(SupplyRefusal::Unproven));
}

#[test]
fn t7_an_unproven_name_writes_nothing() {
    let (w, fleet) = world_with(true, false);
    w.set_on_fly(DB_NAME, "postgresql://set-by-terraform");
    let _ = supply_both(&w, &fleet, 10, DB, HOOK);
    assert_eq!(w.imports(), 0);
}

#[test]
fn t7_rotation_writes_a_name_listed_without_evidence() {
    let (w, fleet) = world_with(true, false);
    w.set_on_fly(DB_NAME, "postgresql://set-by-terraform");
    supply(
        &w,
        &fleet,
        rotating(&["api/DATABASE_URL"]),
        &both(10, DB, HOOK),
    )
    .0
    .unwrap();
    assert_eq!(w.on_fly(DB_NAME).as_deref(), Some(DB));
}

#[test]
fn t7_an_immutable_name_listed_without_evidence_is_unproven() {
    let (w, fleet) = world();
    w.set_on_fly(HOOK_NAME, "whsec_set-by-the-helper");
    let res = supply_both(&w, &fleet, 10, DB, HOOK);
    assert_eq!(reason(&res.unwrap_err()), Some(SupplyRefusal::Unproven));
}

#[test]
fn t7_a_proven_same_value_is_not_written_again() {
    let (w, fleet) = supplied();
    let before = w.imports();
    supply_both(&w, &fleet, 11, DB, HOOK).unwrap();
    assert_eq!(w.imports(), before);
}

#[test]
fn t7_a_proven_changed_value_is_written() {
    let (w, fleet) = supplied();
    supply_both(&w, &fleet, 11, DB2, HOOK).unwrap();
    assert_eq!(w.on_fly(DB_NAME).as_deref(), Some(DB2));
}

#[test]
fn t7_a_changed_immutable_value_is_refused() {
    let (w, fleet) = supplied();
    let res = supply_both(&w, &fleet, 11, DB, HOOK2);
    assert_eq!(
        reason(&res.unwrap_err()),
        Some(SupplyRefusal::ImmutableDiffers)
    );
}

#[test]
fn t7_a_rotated_immutable_value_is_written() {
    let (w, fleet) = supplied();
    supply(
        &w,
        &fleet,
        rotating(&["api/STRIPE_WEBHOOK_SECRET"]),
        &both(11, DB, HOOK2),
    )
    .0
    .unwrap();
    assert_eq!(w.on_fly(HOOK_NAME), Some(format!("whsec_{HOOK2}")));
}

#[test]
fn t7_a_drifted_name_is_repaired() {
    let (w, fleet) = supplied();
    w.set_on_fly(DB_NAME, "postgresql://edited-elsewhere");
    supply_both(&w, &fleet, 10, DB, HOOK).unwrap();
    assert_eq!(w.on_fly(DB_NAME).as_deref(), Some(DB));
}

#[test]
fn t7_a_drifted_immutable_name_is_unproven() {
    let (w, fleet) = supplied();
    w.set_on_fly(HOOK_NAME, "whsec_edited-elsewhere");
    let res = supply_both(&w, &fleet, 11, DB, HOOK);
    assert_eq!(reason(&res.unwrap_err()), Some(SupplyRefusal::Unproven));
}

#[test]
fn t7_rotating_a_key_the_run_does_not_supply_is_refused() {
    let (w, fleet) = world();
    let (res, _) = supply(
        &w,
        &fleet,
        rotating(&["api/DATABASE_URL"]),
        &doc(10, &[("api/STRIPE_WEBHOOK_SECRET", HOOK)]),
    );
    assert_eq!(
        reason(&res.unwrap_err()),
        Some(SupplyRefusal::RotateWithoutValue)
    );
}

// --- T8: idempotency and staleness (§5.1, §5.2) ---------------------------------------------

#[test]
fn t8_the_same_supply_twice_writes_nothing() {
    let (w, fleet) = supplied();
    let before = w.imports();
    supply_both(&w, &fleet, 10, DB, HOOK).unwrap();
    assert_eq!(w.imports(), before);
}

#[test]
fn t8_the_same_supply_twice_keeps_the_delivery_item() {
    let (w, fleet) = supplied();
    let before = w.state();
    supply_both(&w, &fleet, 10, DB, HOOK).unwrap();
    assert_eq!(w.state(), before);
}

#[test]
fn t8_a_lower_serial_is_stale() {
    let (w, fleet) = supplied();
    let res = supply_both(&w, &fleet, 9, DB2, HOOK);
    assert_eq!(
        reason(&res.unwrap_err()),
        Some(SupplyRefusal::Stale {
            recorded: 10,
            supplied: 9
        })
    );
}

#[test]
fn t8_rotation_overrides_a_stale_serial() {
    let (w, fleet) = supplied();
    supply(&w, &fleet, rotating(&["api/DATABASE_URL"]), &stale_db())
        .0
        .unwrap();
    assert_eq!(w.on_fly(DB_NAME).as_deref(), Some(DB2));
}

#[test]
fn t8_a_rotation_prints_its_line_with_the_serial() {
    let (w, fleet) = supplied();
    let (_, out) = supply(&w, &fleet, rotating(&["api/DATABASE_URL"]), &stale_db());
    assert!(
        out.contains("rotated api/DATABASE_URL at serial 9"),
        "{out}"
    );
}

#[test]
fn t8_an_equal_serial_with_another_value_is_reused() {
    let (w, fleet) = supplied();
    let res = supply_both(&w, &fleet, 10, DB2, HOOK);
    assert_eq!(
        reason(&res.unwrap_err()),
        Some(SupplyRefusal::SerialReused { serial: 10 })
    );
}

#[test]
fn t8_rotation_overrides_a_reused_serial() {
    let (w, fleet) = supplied();
    supply(
        &w,
        &fleet,
        rotating(&["api/DATABASE_URL"]),
        &both(10, DB2, HOOK),
    )
    .0
    .unwrap();
    assert_eq!(w.on_fly(DB_NAME).as_deref(), Some(DB2));
}

// --- T9: concurrency (§5.3, S9) ------------------------------------------------------------

/// The delivery item's read by `record` (its 2nd: the ledger read in the plan is the 1st)
/// is followed by a change from another run; the re-read sees it.
fn changed_after_read(w: &World, n: usize, label: &'static str, value: String) {
    let id = w.state_item.clone();
    w.on_state_read.borrow_mut().push((
        n,
        Box::new(move |op: &FakeOp| put_state_field(op, &id, label, &value)),
    ));
}

#[test]
fn t9_a_change_between_reads_keeps_the_other_runs_line() {
    let (w, fleet) = world();
    // Another run's line for a name outside this run's write, recorded between the reads.
    changed_after_read(&w, 3, "notes elsewhere", "kept".to_string());
    supply_both(&w, &fleet, 10, DB, HOOK).unwrap();
    assert!(w.state_field(DB_NAME).is_some_and(|l| l.starts_with("s1|")));
}

#[test]
fn t9_a_second_change_is_item_changed() {
    let (w, fleet) = world();
    changed_after_read(&w, 3, "notes elsewhere", "one".to_string());
    changed_after_read(&w, 4, "notes elsewhere", "two".to_string());
    let res = supply_both(&w, &fleet, 10, DB, HOOK);
    assert_eq!(code(&res.unwrap_err()), "item_changed");
}

#[test]
fn t9_a_higher_serial_on_re_read_fails_the_run_as_stale() {
    let (w, fleet) = world();
    let newer = format!(
        "s1|{}|{}|api/DATABASE_URL|99|2026-10-19T00:00:00Z",
        digest(DB2),
        "ff"
    );
    changed_after_read(&w, 3, DB_NAME, newer);
    let res = supply_both(&w, &fleet, 10, DB, HOOK);
    assert_eq!(
        reason(&res.unwrap_err()),
        Some(SupplyRefusal::Stale {
            recorded: 99,
            supplied: 10
        })
    );
}

#[test]
fn t9_a_higher_serial_on_re_read_is_kept() {
    let (w, fleet) = world();
    let newer = format!(
        "s1|{}|{}|api/DATABASE_URL|99|2026-10-19T00:00:00Z",
        digest(DB2),
        "ff"
    );
    changed_after_read(&w, 3, DB_NAME, newer.clone());
    let _ = supply_both(&w, &fleet, 10, DB, HOOK);
    assert_eq!(w.state_field(DB_NAME), Some(newer));
}

#[test]
fn t9_a_higher_serial_on_re_read_is_partial() {
    let (w, fleet) = world();
    let newer = format!(
        "s1|{}|{}|api/DATABASE_URL|99|2026-10-19T00:00:00Z",
        digest(DB2),
        "ff"
    );
    changed_after_read(&w, 3, DB_NAME, newer);
    let res = supply_both(&w, &fleet, 10, DB, HOOK);
    assert!(matches!(
        res.unwrap_err().cause().map(|c| c.0),
        Some(Cause::Partial { .. })
    ));
}

// --- T10: failures never report success (§5.4, S1) ----------------------------------------

#[test]
fn t10_a_failed_target_write_is_partial_or_refused_with_no_receipt() {
    let (w, fleet) = world();
    w.fail_import.set(true);
    let _ = supply_both(&w, &fleet, 10, DB, HOOK);
    assert_eq!(w.receipt(), Value::Null);
}

#[test]
fn t10_a_failed_record_exits_8() {
    let (w, fleet) = world();
    w.fail_state_write.set(true);
    let res = supply_both(&w, &fleet, 10, DB, HOOK);
    let e = res.unwrap_err();
    assert_eq!(e.exit_code(), 8, "{e:?}");
}

#[test]
fn t10_an_unencodable_version_exits_8() {
    let (w, fleet) = world();
    *w.digest_override.borrow_mut() = Some("ab|cd".into());
    let res = supply_both(&w, &fleet, 10, DB, HOOK);
    let e = res.unwrap_err();
    assert_eq!(e.exit_code(), 8, "{e:?}");
}

#[test]
fn t10_no_delivery_item_refuses_before_any_write() {
    let (w, fleet) = world_with(false, true);
    let _ = supply_both(&w, &fleet, 10, DB, HOOK);
    assert_eq!(w.imports(), 0);
}

#[test]
fn t10_no_delivery_item_exits_8() {
    let (w, fleet) = world_with(false, true);
    let res = supply_both(&w, &fleet, 10, DB, HOOK);
    let e = res.unwrap_err();
    assert_eq!(e.exit_code(), 8, "{e:?}");
}

#[test]
fn t10_a_retry_after_a_failed_target_write_mints_the_revision() {
    let (w, fleet) = world();
    w.fail_import.set(true);
    let _ = supply_both(&w, &fleet, 10, DB, HOOK);
    supply_both(&w, &fleet, 10, DB, HOOK).unwrap();
    assert_eq!(w.receipt()["supplied"], json!([DB_NAME, HOOK_NAME]));
}

// --- T11: without a supply (§6.4) -------------------------------------------------------------

#[test]
fn t11_a_scheduled_sync_keeps_the_revision() {
    let (w, fleet) = supplied();
    let before = w.receipt()["revision"].clone();
    scheduled(&w, &fleet).0.unwrap();
    assert_eq!(w.receipt()["revision"], before);
}

#[test]
fn t11_a_scheduled_sync_writes_no_supplied_name() {
    let (w, fleet) = supplied();
    let before = w.imports();
    scheduled(&w, &fleet).0.unwrap();
    assert_eq!(w.imports(), before);
}

#[test]
fn t11_a_scheduled_sync_carries_the_s1_line() {
    let (w, fleet) = supplied();
    let before = w.state_field(DB_NAME);
    scheduled(&w, &fleet).0.unwrap();
    assert_eq!(w.state_field(DB_NAME), before);
}

#[test]
fn t11_a_scheduled_sync_over_drift_mints_nothing_and_says_why() {
    let (w, fleet) = supplied();
    w.set_on_fly(DB_NAME, "postgresql://edited-elsewhere");
    let (_, out) = scheduled(&w, &fleet);
    assert!(
        out.contains("supplied at sync, not supplied by this run: APP_DATABASE_URL"),
        "{out}"
    );
}

#[test]
fn t11_a_scheduled_sync_over_drift_exits_0() {
    let (w, fleet) = supplied();
    w.set_on_fly(DB_NAME, "postgresql://edited-elsewhere");
    assert!(scheduled(&w, &fleet).0.is_ok());
}

#[test]
fn t11_a_scheduled_sync_before_any_supply_is_not_missing() {
    let (w, fleet) = world();
    assert!(scheduled(&w, &fleet).0.is_ok());
}

/// `opv status prod --fail-on-drift`.
fn status_drift(w: &World, fleet: &Fleet) -> Result<(), Error> {
    let mut out = Vec::new();
    crate::app::status::run_targeted(fleet, "prod", &[], None, w, &mut out, false, true)
}

#[test]
fn t11_status_fail_on_drift_passes_as_supplied() {
    let (w, fleet) = supplied();
    assert!(status_drift(&w, &fleet).is_ok());
}

#[test]
fn t11_status_fail_on_drift_fails_on_a_drifted_supplied_name() {
    let (w, fleet) = supplied();
    w.set_on_fly(DB_NAME, "postgresql://edited-elsewhere");
    assert!(status_drift(&w, &fleet).is_err());
}

/// `opv plan prod --json`.
fn plan_doc(w: &World, fleet: &Fleet) -> Value {
    let _person = crate::app::tidy::activate();
    let mut out = Vec::new();
    sync::plan_rotating(fleet, "prod", &[], None, &[], w, &mut out, true).unwrap();
    serde_json::from_slice(&out).unwrap()
}

/// The `--json` row of `key` in a plan document.
fn row(doc: &Value, key: &str) -> Value {
    doc["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["key"] == key)
        .cloned()
        .unwrap_or_default()
}

#[test]
fn t11_plan_shows_an_unsupplied_key_as_supplied_at_sync() {
    let (w, fleet) = world();
    assert_eq!(
        row(&plan_doc(&w, &fleet), "DATABASE_URL")["state"],
        "supplied_at_sync"
    );
}

#[test]
fn t11_plan_shows_a_delivered_supplied_name_as_supplied() {
    let (w, fleet) = supplied();
    assert_eq!(
        row(&plan_doc(&w, &fleet), "DATABASE_URL")["target_state"],
        "as_supplied"
    );
}

#[test]
fn t11_plan_shows_a_listed_name_without_evidence_as_not_recorded() {
    let (w, fleet) = world();
    w.set_on_fly(DB_NAME, "postgresql://set-by-terraform");
    assert_eq!(
        row(&plan_doc(&w, &fleet), "DATABASE_URL")["target_state"],
        "not_recorded"
    );
}

#[test]
fn t11_plan_rows_mark_the_value_state_supplied() {
    let (w, fleet) = world();
    assert_eq!(
        row(&plan_doc(&w, &fleet), "DATABASE_URL")["value_state"],
        "supplied"
    );
}

/// `opv delivery verify prod --json`.
fn verify_doc(w: &World, fleet: &Fleet) -> Value {
    let mut out = Vec::new();
    let _ = crate::app::delivery::verify(fleet, "prod", None, &[], None, w, true, &mut out);
    serde_json::from_slice(&out).unwrap()
}

/// The verify state of `name`.
fn name_state(doc: &Value, name: &str) -> Value {
    doc["placements"][0]["names"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["name"] == name)
        .map(|n| n["state"].clone())
        .unwrap_or_default()
}

#[test]
fn t11_verify_says_verified_after_a_supply() {
    let (w, fleet) = supplied();
    assert_eq!(verify_doc(&w, &fleet)["placements"][0]["state"], "verified");
}

#[test]
fn t11_verify_marks_a_supplied_name() {
    let (w, fleet) = supplied();
    let doc = verify_doc(&w, &fleet);
    let db = doc["placements"][0]["names"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["name"] == DB_NAME)
        .cloned()
        .unwrap_or_default();
    assert_eq!(db["supplied"], true);
}

#[test]
fn t11_verify_says_drifted_on_target() {
    let (w, fleet) = supplied();
    w.set_on_fly(DB_NAME, "postgresql://edited-elsewhere");
    assert_eq!(
        name_state(&verify_doc(&w, &fleet), DB_NAME),
        "drifted_on_target"
    );
}

#[test]
fn t11_verify_says_missing_on_target() {
    let (w, fleet) = supplied();
    w.fly.borrow_mut().remove(DB_NAME);
    assert_eq!(
        name_state(&verify_doc(&w, &fleet), DB_NAME),
        "missing_on_target"
    );
}

// --- T12: the state vault only ----------------------------------------------------------------

#[test]
fn t12_a_supplying_sync_writes_only_the_delivery_item() {
    let (w, fleet) = world();
    supply_both(&w, &fleet, 10, DB, HOOK).unwrap();
    let writes: Vec<Vec<String>> =
        w.op.calls
            .borrow()
            .iter()
            .filter(|c| c.args.first().is_some_and(|a| a == "item"))
            .filter(|c| c.args.get(1).is_some_and(|a| a == "edit" || a == "create"))
            .map(|c| c.args.clone())
            .collect();
    assert!(
        writes
            .iter()
            .all(|a| a.get(2) == Some(&w.state_item) && a.contains(&STATE.to_string())),
        "{writes:?}"
    );
}

// --- T13: the canary stays out ---------------------------------------------------------------

#[test]
fn t13_a_supplying_sync_shows_no_value() {
    let (w, fleet) = world();
    let (res, out) = supply(&w, &fleet, SyncOpts::default(), &both(10, DB, HOOK));
    assert!(!everything(&w, &out, &res).contains(MARK));
}

#[test]
fn t13_a_supplying_sync_with_json_shows_no_value() {
    let (w, fleet) = world();
    let opts = SyncOpts {
        json: true,
        ..SyncOpts::default()
    };
    let (res, out) = supply(&w, &fleet, opts, &both(10, DB, HOOK));
    assert!(!everything(&w, &out, &res).contains(MARK));
}

#[test]
fn t13_a_refused_supply_shows_no_value() {
    let (w, fleet) = supplied();
    let (res, out) = supply(&w, &fleet, SyncOpts::default(), &both(9, DB2, HOOK));
    assert!(!everything(&w, &out, &res).contains(MARK));
}

#[test]
fn t13_an_unverified_supply_shows_no_value() {
    let (w, fleet) = world();
    w.fail_state_write.set(true);
    let (res, out) = supply(&w, &fleet, SyncOpts::default(), &both(10, DB, HOOK));
    assert!(!everything(&w, &out, &res).contains(MARK));
}

#[test]
fn t13_a_receipt_file_holds_no_value() {
    let (w, fleet) = world();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("web.receipt.json");
    let opts = SyncOpts {
        receipt: Some(path.clone()),
        ..SyncOpts::default()
    };
    supply(&w, &fleet, opts, &both(10, DB, HOOK)).0.unwrap();
    assert!(!std::fs::read_to_string(&path).unwrap().contains(MARK));
}

#[test]
fn t13_plan_and_verify_after_a_supply_show_no_value() {
    let (w, fleet) = supplied();
    let text = plan_doc(&w, &fleet).to_string() + &verify_doc(&w, &fleet).to_string();
    assert!(!text.contains(MARK));
}

// --- T14: one plan id with and without the values ------------------------------------------

/// The plan id `opv plan prod --json` shows.
fn plan_id(w: &World, fleet: &Fleet) -> String {
    plan_doc(w, fleet)["plan_id"].as_str().unwrap().to_string()
}

#[test]
fn t14_a_first_supply_matches_the_value_free_plan() {
    let (w, fleet) = world();
    let id = plan_id(&w, &fleet);
    let opts = SyncOpts {
        expect_plan: Some(id),
        ..SyncOpts::default()
    };
    assert!(supply(&w, &fleet, opts, &both(10, DB, HOOK)).0.is_ok());
}

#[test]
fn t14_an_unchanged_supply_matches_the_value_free_plan() {
    let (w, fleet) = supplied();
    let id = plan_id(&w, &fleet);
    let opts = SyncOpts {
        expect_plan: Some(id),
        ..SyncOpts::default()
    };
    assert!(supply(&w, &fleet, opts, &both(10, DB, HOOK)).0.is_ok());
}

#[test]
fn t14_a_changed_supply_matches_the_value_free_plan() {
    let (w, fleet) = supplied();
    let id = plan_id(&w, &fleet);
    let opts = SyncOpts {
        expect_plan: Some(id),
        ..SyncOpts::default()
    };
    assert!(supply(&w, &fleet, opts, &both(11, DB2, HOOK)).0.is_ok());
}

#[test]
fn t14_the_plan_id_is_the_same_whatever_the_supplied_value() {
    let (w, fleet) = supplied();
    let before = plan_id(&w, &fleet);
    supply_both(&w, &fleet, 11, DB2, HOOK).unwrap();
    assert_eq!(plan_id(&w, &fleet), before);
}

// --- T11: ready --gate (§6.4) -----------------------------------------------------------------

/// What `ready --gate` refuses for api/DATABASE_URL supplied at sync with `target` state.
fn gated(target: crate::domain::TargetState) -> Vec<(String, String, &'static str)> {
    let (_, fleet) = world();
    let row = crate::domain::Row {
        product: "api".into(),
        key: "DATABASE_URL".into(),
        kind: crate::domain::Kind::Secret,
        state: crate::domain::KeyState::SuppliedAtSync,
        target,
        guidance: String::new(),
        source: None,
        shared_by: Vec::new(),
    };
    let none = std::collections::BTreeSet::new();
    let delivered = std::collections::BTreeSet::from(["api".to_string()]);
    crate::app::ready::gate_keys(
        &fleet,
        "prod",
        &[row],
        &none,
        &delivered,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &std::collections::BTreeSet::new(),
    )
}

#[test]
fn t11_ready_gate_passes_a_name_as_supplied() {
    assert!(gated(crate::domain::TargetState::AsSupplied).is_empty());
}

#[test]
fn t11_ready_gate_fails_a_name_not_recorded() {
    assert_eq!(
        gated(crate::domain::TargetState::Unrecorded)[0].2,
        "supplied_not_delivered"
    );
}

#[test]
fn t11_ready_gate_fails_an_absent_supplied_name() {
    assert_eq!(
        gated(crate::domain::TargetState::Absent)[0].2,
        "supplied_not_delivered"
    );
}

#[test]
fn t11_ready_gate_fails_a_drifted_supplied_name() {
    assert_eq!(
        gated(crate::domain::TargetState::Unknown)[0].2,
        "supplied_drifted"
    );
}

#[test]
fn t11_ready_gate_failure_on_a_supplied_name_never_asks_to_fill_1password() {
    let e: Error = Cause::GateFailed {
        env: crate::cause::EnvName::new("prod"),
        keys: vec![(
            crate::cause::ProductName::new("api"),
            crate::cause::KeyName::new("DATABASE_URL"),
            "supplied_not_delivered",
        )],
    }
    .into();
    let doc = crate::error::document(&e, &crate::error::invocation(), false);
    assert_eq!(doc["next"]["command"], "opv plan prod");
}
