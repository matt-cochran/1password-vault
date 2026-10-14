//! Delivery receipts (#106) end to end: `opv sync` mints a revision per product into the
//! state vault, `opv delivery verify` checks it read-only. 1Password is the stateful fake;
//! Fly is a small store that lists a digest and a staged flag per name. Every value holds
//! [`MARK`]; no output, receipt or error may contain one, nor any digest.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::*;
use crate::adapters::fake_op::FakeOp;
use crate::app::sync::{self, SyncOpts};
use crate::app::testutil::{fly_app_ok, fly_releases, ok};
use crate::runner::{Call, Outcome, Output};

const MARK: &str = "DELIVERYMARK";
const VALUES: &str = "vdev0000000000000000000001";
const STATE: &str = "vshr0000000000000000000002";

fn digest(v: &str) -> String {
    hex::encode(Sha256::digest(v))[..16].to_string()
}

/// 1Password (the stateful fake) plus a Fly app's secrets: name → (value, staged).
struct World {
    op: FakeOp,
    fly: RefCell<BTreeMap<String, (String, bool)>>,
    /// The next `secrets import` fails before it reaches Fly.
    fail_import: std::cell::Cell<bool>,
}

impl World {
    fn fly(&self, args: &[&str], stdin: Option<&[u8]>) -> Output {
        match args {
            ["status", ..] => fly_app_ok(),
            ["releases", ..] => fly_releases("complete"),
            ["secrets", "list", ..] => {
                let v: Vec<Value> = self
                    .fly
                    .borrow()
                    .iter()
                    .map(|(n, (value, staged))| {
                        json!({"name": n, "digest": digest(value),
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
                for line in text.lines() {
                    let (name, quoted) = line.split_once('=').unwrap();
                    let value = quoted.trim_matches('"').to_string();
                    let same = self
                        .fly
                        .borrow()
                        .get(name)
                        .is_some_and(|(v, _)| *v == value);
                    if !same {
                        self.fly
                            .borrow_mut()
                            .insert(name.to_string(), (value, true));
                    }
                }
                ok()
            }
            other => panic!("unexpected flyctl call {other:?}"),
        }
    }

    /// Change the value of `section/label` in the values item, as a person would.
    fn set_value(&self, section: &str, label: &str, value: &str) {
        let mut items = self.op.items.borrow_mut();
        let item = items
            .iter_mut()
            .find(|i| i["vault"]["id"] == VALUES)
            .unwrap();
        for f in item["fields"].as_array_mut().unwrap() {
            if f["section"]["label"] == section && f["label"] == label {
                f["value"] = json!(value);
            }
        }
        let v = item["version"].as_u64().unwrap_or(0) + 1;
        item["version"] = json!(v);
    }
}

impl CommandRunner for World {
    fn read(&self, call: &Call<'_>, refused: &[i32]) -> io::Result<Outcome> {
        if call.program == "op" || call.program == "git" {
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

    fn probe(&self, call: &Call<'_>, limit: std::time::Duration) -> io::Result<Output> {
        if call.program == "op" {
            return self.op.probe(call, limit);
        }
        Ok(ok())
    }

    fn pause(&self, _: std::time::Duration, _: &str) {}

    fn note(&self, _: &str) {}

    fn run_inherited(&self, _: &str, _: &[&str], _: &[(&str, &str)]) -> io::Result<i32> {
        unreachable!("sync and verify never run a child")
    }
}

fn field(section: &str, label: &str, value: &str) -> Value {
    json!({"id": format!("{section}-{label}"), "section": {"id": section, "label": section},
           "type": "CONCEALED", "label": label, "value": value})
}

/// prod on Fly app `myapp`, state vault STATE; api (TOKEN, SHARED from shared/KEY) and web
/// (SESSION, SHARED from shared/KEY); shared is source-only.
fn world() -> (World, Fleet) {
    let op = FakeOp::default();
    let id = op.insert(
        VALUES,
        json!({
            "title": "myapp · prod values", "category": "SECURE_NOTE",
            "sections": [{"id": "api", "label": "api"}, {"id": "web", "label": "web"},
                         {"id": "shared", "label": "shared"}],
            "fields": [
                field("api", "TOKEN", &format!("tok-{MARK}")),
                field("web", "SESSION", &format!("ses-{MARK}")),
                field("shared", "KEY", &format!("key-{MARK}")),
            ]
        }),
    );
    let fleet = crate::config::parse(&format!(
        "[profile]\nkind = \"fleet\"\n\
         [environments.prod]\nvault_id = \"{VALUES}\"\nitem_id = \"{id}\"\n\
         state_vault_id = \"{STATE}\"\nfly.app = \"myapp\"\n\
         fly.secret_name = \"FLEET__{{PRODUCT}}__{{KEY}}\"\n\
         [products.shared]\nsource_only = true\n\
         [products.shared.keys.KEY]\nkind = \"secret\"\nenvironments = [\"prod\"]\n\
         [products.api.keys.TOKEN]\nkind = \"secret\"\nenvironments = [\"prod\"]\n\
         [products.api.keys.SHARED]\nkind = \"secret\"\nenvironments = [\"prod\"]\nfrom = \"shared/KEY\"\n\
         [products.web.keys.SESSION]\nkind = \"secret\"\nenvironments = [\"prod\"]\n\
         [products.web.keys.SHARED]\nkind = \"secret\"\nenvironments = [\"prod\"]\nfrom = \"shared/KEY\"\n"
    ))
    .unwrap();
    let w = World {
        op,
        fly: RefCell::default(),
        fail_import: std::cell::Cell::new(false),
    };
    (w, fleet)
}

fn sync_with(w: &World, fleet: &Fleet, opts: SyncOpts) -> (Result<(), Error>, String) {
    let mut out = Vec::new();
    let res = sync::run(fleet, "prod", w, &mut out, &opts);
    (res, String::from_utf8(out).unwrap())
}

fn sync_all(w: &World, fleet: &Fleet) -> Result<(), Error> {
    sync_with(w, fleet, SyncOpts::default()).0
}

/// `opv delivery verify prod --json` → product → (state, revision).
fn verify_doc(w: &World, fleet: &Fleet) -> Value {
    let mut out = Vec::new();
    let _ = verify(fleet, "prod", None, None, w, true, &mut out);
    serde_json::from_slice(&out).unwrap()
}

fn state_of(doc: &Value, product: &str) -> String {
    doc["products"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["product"] == product)
        .map(|p| p["state"].as_str().unwrap().to_string())
        .unwrap_or_default()
}

fn revision_of(doc: &Value, product: &str) -> Option<String> {
    doc["products"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["product"] == product)
        .and_then(|p| p["revision"].as_str().map(str::to_string))
}

/// A synced world (both products delivered).
fn delivered() -> (World, Fleet) {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = world();
    sync_all(&w, &fleet).unwrap();
    (w, fleet)
}

#[test]
fn a_confirmed_sync_makes_a_product_verified() {
    let (w, fleet) = delivered();
    assert_eq!(state_of(&verify_doc(&w, &fleet), "api"), "verified");
}

#[test]
fn every_delivered_product_gets_its_own_revision() {
    let (w, fleet) = delivered();
    let doc = verify_doc(&w, &fleet);
    assert_ne!(revision_of(&doc, "api"), revision_of(&doc, "web"));
}

#[test]
fn an_unchanged_resync_keeps_the_revision() {
    let (w, fleet) = delivered();
    let before = revision_of(&verify_doc(&w, &fleet), "api");
    sync_all(&w, &fleet).unwrap();
    assert_eq!(revision_of(&verify_doc(&w, &fleet), "api"), before);
}

#[test]
fn a_rotated_value_is_a_source_change() {
    let (w, fleet) = delivered();
    w.set_value("api", "TOKEN", &format!("tok2-{MARK}"));
    assert_eq!(state_of(&verify_doc(&w, &fleet), "api"), "changed");
}

#[test]
fn a_rotation_leaves_another_product_verified() {
    let (w, fleet) = delivered();
    w.set_value("api", "TOKEN", &format!("tok2-{MARK}"));
    assert_eq!(state_of(&verify_doc(&w, &fleet), "web"), "verified");
}

#[test]
fn a_shared_value_change_invalidates_every_consumer() {
    let (w, fleet) = delivered();
    w.set_value("shared", "KEY", &format!("key2-{MARK}"));
    let doc = verify_doc(&w, &fleet);
    assert_eq!(
        (state_of(&doc, "api"), state_of(&doc, "web")),
        ("changed".to_string(), "changed".to_string())
    );
}

#[test]
fn a_resync_after_rotation_mints_a_new_revision() {
    let (w, fleet) = delivered();
    let before = revision_of(&verify_doc(&w, &fleet), "api");
    w.set_value("api", "TOKEN", &format!("tok2-{MARK}"));
    sync_all(&w, &fleet).unwrap();
    assert_ne!(revision_of(&verify_doc(&w, &fleet), "api"), before);
}

#[test]
fn an_edit_on_the_target_outside_opv_is_drift() {
    let (w, fleet) = delivered();
    w.fly.borrow_mut().insert(
        "FLEET__API__TOKEN".into(),
        ("edited-elsewhere".into(), false),
    );
    let doc = verify_doc(&w, &fleet);
    let names = doc["products"][0]["names"].to_string() + &doc["products"][1]["names"].to_string();
    assert!(names.contains("drifted_on_target"), "{doc}");
}

#[test]
fn a_name_removed_from_the_target_is_missing() {
    let (w, fleet) = delivered();
    w.fly.borrow_mut().remove("FLEET__WEB__SESSION");
    let doc = verify_doc(&w, &fleet);
    assert!(doc.to_string().contains("missing_on_target"), "{doc}");
}

#[test]
fn a_staged_delivery_is_reported_as_not_yet_deployed() {
    let (w, fleet) = delivered();
    let doc = verify_doc(&w, &fleet);
    assert_eq!(doc["products"][0]["deployed"], "staged");
}

#[test]
fn an_interrupted_sync_mints_nothing() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = world();
    w.fail_import.set(true);
    let _ = sync_all(&w, &fleet);
    assert_eq!(state_of(&verify_doc(&w, &fleet), "api"), "not_delivered");
}

#[test]
fn the_retry_after_an_interruption_mints_the_revision() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = world();
    w.fail_import.set(true);
    let _ = sync_all(&w, &fleet);
    sync_all(&w, &fleet).unwrap();
    assert_eq!(state_of(&verify_doc(&w, &fleet), "api"), "verified");
}

#[test]
fn a_product_scoped_sync_records_only_that_product() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = world();
    let opts = SyncOpts {
        product: Some("api".into()),
        ..SyncOpts::default()
    };
    sync_with(&w, &fleet, opts).0.unwrap();
    assert_eq!(state_of(&verify_doc(&w, &fleet), "web"), "not_delivered");
}

#[test]
fn a_new_key_changes_the_binding_set() {
    let (w, _) = delivered();
    let (_, mut fleet2) = world();
    let api = fleet2.products.get_mut("api").unwrap();
    let mut spec = api.keys["TOKEN"].clone();
    spec.from = None;
    api.keys.insert("EXTRA".into(), spec);
    let doc = verify_doc(&w, &fleet2);
    assert_eq!(state_of(&doc, "api"), "not_delivered");
}

#[test]
fn another_target_cannot_reuse_the_revision() {
    let (w, fleet) = delivered();
    let mut moved = fleet.clone();
    let env = moved.environments.get_mut("prod").unwrap();
    let other = crate::config::parse(&format!(
        "[profile]\nkind = \"fleet\"\n[environments.prod]\nvault_id = \"{VALUES}\"\nitem_id = \"x\"\n\
         fly.app = \"another-app\"\nfly.secret_name = \"FLEET__{{PRODUCT}}__{{KEY}}\"\n[products.api.keys.TOKEN]\nkind = \"secret\"\nenvironments = [\"prod\"]\n"
    ))
    .unwrap();
    env.targets = other.environments["prod"].targets.clone();
    let doc = verify_doc(&w, &moved);
    assert_eq!(state_of(&doc, "api"), "not_delivered");
}

#[test]
fn the_receipt_file_holds_each_delivery() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = world();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("prod.receipt.json");
    let opts = SyncOpts {
        receipt: Some(path.clone()),
        ..SyncOpts::default()
    };
    sync_with(&w, &fleet, opts).0.unwrap();
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(doc["deliveries"].as_array().unwrap().len(), 2);
}

/// The error `verify` returns for a receipt file holding each delivery twice (FR-58).
fn duplicate_receipt_error() -> Error {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = world();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("prod.receipt.json");
    let opts = SyncOpts {
        receipt: Some(path.clone()),
        ..SyncOpts::default()
    };
    sync_with(&w, &fleet, opts).0.unwrap();
    let mut doc: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let copies = doc["deliveries"].as_array().unwrap().clone();
    doc["deliveries"].as_array_mut().unwrap().extend(copies);
    std::fs::write(&path, serde_json::to_string(&doc).unwrap()).unwrap();
    verify(&fleet, "prod", None, Some(&path), &w, true, &mut Vec::new()).unwrap_err()
}

#[test]
fn a_duplicate_scope_in_the_receipt_file_is_a_usage_error() {
    assert_eq!(duplicate_receipt_error().code(), crate::error::Code::Usage);
}

#[test]
fn a_duplicate_scope_error_tells_the_caller_to_keep_one() {
    assert_eq!(
        duplicate_receipt_error().text(),
        "the receipt file holds 2 receipts for the same environment, product and target; keep one"
    );
}

#[test]
fn a_kept_receipt_that_is_no_longer_current_is_superseded() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = world();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("prod.receipt.json");
    let opts = SyncOpts {
        receipt: Some(path.clone()),
        ..SyncOpts::default()
    };
    sync_with(&w, &fleet, opts).0.unwrap();
    w.set_value("api", "TOKEN", &format!("tok2-{MARK}"));
    sync_all(&w, &fleet).unwrap();
    let mut out = Vec::new();
    let _ = verify(&fleet, "prod", Some("api"), Some(&path), &w, true, &mut out);
    let doc: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(doc["products"][0]["state"], "superseded");
}

#[test]
fn nothing_shown_holds_a_value_or_a_digest() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = world();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("prod.receipt.json");
    let opts = SyncOpts {
        receipt: Some(path.clone()),
        ..SyncOpts::default()
    };
    let (_, sync_out) = sync_with(&w, &fleet, opts);
    let mut verify_out = Vec::new();
    let _ = verify(
        &fleet,
        "prod",
        None,
        Some(&path),
        &w,
        false,
        &mut verify_out,
    );
    let all = sync_out
        + &std::fs::read_to_string(&path).unwrap()
        + &String::from_utf8(verify_out).unwrap();
    let digests: Vec<String> = w.fly.borrow().values().map(|(v, _)| digest(v)).collect();
    assert!(
        !all.contains(MARK) && digests.iter().all(|d| !all.contains(d.as_str())),
        "{all}"
    );
}
