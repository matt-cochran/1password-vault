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
use crate::runner::fake::FakeRunner;
use crate::runner::{Call, Outcome, Output};

const MARK: &str = "DELIVERYMARK";
const VALUES: &str = "vdev0000000000000000000001";
const STATE: &str = "vshr0000000000000000000002";

fn digest(v: &str) -> String {
    hex::encode(Sha256::digest(v))[..16].to_string()
}

/// One Fly app's secrets: name → (value, staged).
type Secrets = BTreeMap<String, (String, bool)>;

/// 1Password (the stateful fake) plus Fly apps' secrets, by app.
struct World {
    op: FakeOp,
    fly: RefCell<BTreeMap<String, Secrets>>,
    /// The next `secrets import` fails before it reaches Fly.
    fail_import: std::cell::Cell<bool>,
    /// Every 1Password write that names this item ID fails (#201: a partial apply).
    fail_op_write_on: RefCell<Option<String>>,
}

/// The value of `--app` in a flyctl call.
fn app_of(args: &[&str]) -> String {
    args.iter()
        .position(|a| *a == "--app")
        .map(|i| args[i + 1].to_string())
        .unwrap_or_default()
}

impl World {
    /// Fly app `app`'s secrets, for a test to change as someone outside opv would.
    fn app(&self, app: &str) -> std::cell::RefMut<'_, Secrets> {
        std::cell::RefMut::map(self.fly.borrow_mut(), |f| {
            f.entry(app.to_string()).or_default()
        })
    }

    fn fly(&self, args: &[&str], stdin: Option<&[u8]>) -> Output {
        let app = app_of(args);
        match args {
            ["status", ..] => fly_app_ok(),
            ["releases", ..] => fly_releases("complete"),
            ["secrets", "list", ..] => {
                let v: Vec<Value> = self
                    .app(&app)
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
                let mut secrets = self.app(&app);
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
        let failing = self.fail_op_write_on.borrow().clone();
        if call.program == "op"
            && failing.is_some_and(|id| call.args.iter().any(|a| a.contains(id.as_str())))
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

/// The values item (api, web and shared sections) in VALUES; returns its ID.
fn values_item(op: &FakeOp) -> String {
    op.insert(
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
    )
}

/// An empty delivery item in STATE, as `opv bootstrap` creates it; returns its ID.
fn delivery_item(op: &FakeOp, product: &str, target: &str) -> String {
    op.insert(
        STATE,
        json!({"title": crate::domain::naming::delivery_item(product, target),
               "category": "SECURE_NOTE",
               "fields": [{"id": "notesPlain", "type": "STRING", "purpose": "NOTES",
                           "label": "notesPlain",
                           "value": crate::domain::naming::delivery_item_notes(product, target, "prod")}]}),
    )
}

/// The products: api (TOKEN, SHARED from shared/KEY) and web (SESSION, SHARED from
/// shared/KEY); shared is source-only.
const PRODUCTS: &str = "[products.shared]\nsource_only = true\n\
     [products.shared.keys.KEY]\nkind = \"secret\"\nenvironments = [\"prod\"]\n\
     [products.api.keys.TOKEN]\nkind = \"secret\"\nenvironments = [\"prod\"]\n\
     [products.api.keys.SHARED]\nkind = \"secret\"\nenvironments = [\"prod\"]\nfrom = \"shared/KEY\"\n\
     [products.web.keys.SESSION]\nkind = \"secret\"\nenvironments = [\"prod\"]\n\
     [products.web.keys.SHARED]\nkind = \"secret\"\nenvironments = [\"prod\"]\nfrom = \"shared/KEY\"\n";

/// prod's boundaries, all in the one values item `id`.
fn boundaries(id: &str) -> String {
    format!(
        "[environments.prod]\n\
         boundaries.shared = {{ vault_id = \"{VALUES}\", item_id = \"{id}\" }}\n\
         boundaries.api = {{ vault_id = \"{VALUES}\", item_id = \"{id}\" }}\n\
         boundaries.web = {{ vault_id = \"{VALUES}\", item_id = \"{id}\" }}\n"
    )
}

/// Target `name` on Fly app `app`, its state vault STATE, with `items` (product → ID).
fn target_toml(name: &str, app: &str, items: &[(&str, &str)]) -> String {
    let items: Vec<String> = items
        .iter()
        .map(|(p, i)| format!("{p} = \"{i}\""))
        .collect();
    format!(
        "[environments.prod.targets.{name}]\nstate_vault_id = \"{STATE}\"\n\
         fly.app = \"{app}\"\nfly.secret_name = \"FLEET__{{PRODUCT}}__{{KEY}}\"\n\
         delivery_items = {{ {} }}\n",
        items.join(", ")
    )
}

/// prod on Fly app `myapp` (target `app`), state vault STATE holding api's and web's
/// delivery items.
fn world() -> (World, Fleet) {
    let op = FakeOp::default();
    let id = values_item(&op);
    let (api, web) = (
        delivery_item(&op, "api", "app"),
        delivery_item(&op, "web", "app"),
    );
    let fleet = crate::config::parse(&format!(
        "{}{}{PRODUCTS}",
        boundaries(&id),
        target_toml("app", "myapp", &[("api", &api), ("web", &web)])
    ))
    .unwrap();
    let w = World {
        op,
        fly: RefCell::default(),
        fail_import: std::cell::Cell::new(false),
        fail_op_write_on: RefCell::default(),
    };
    (w, fleet)
}

/// `world()` with api/TOKEN declared immutable.
fn world_with_immutable_token() -> (World, Fleet) {
    let (w, mut fleet) = world();
    let token = fleet
        .products
        .get_mut("api")
        .unwrap()
        .keys
        .get_mut("TOKEN")
        .unwrap();
    token.immutable = true;
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
    let _ = verify(fleet, "prod", None, &[], None, w, true, &mut out);
    serde_json::from_slice(&out).unwrap()
}

fn state_of(doc: &Value, product: &str) -> String {
    doc["placements"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["product"] == product)
        .map(|p| p["state"].as_str().unwrap().to_string())
        .unwrap_or_default()
}

fn revision_of(doc: &Value, product: &str) -> Option<String> {
    doc["placements"]
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

/// #201: an immutable key the sync holds, which opv delivered and Fly still lists at the
/// recorded version with the same value, is proved identical by the placement's ledger,
/// so a change elsewhere in the binding set still mints a revision.
#[test]
fn a_held_immutable_key_identical_on_fly_counts_toward_the_receipt() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = world_with_immutable_token();
    sync_all(&w, &fleet).unwrap();
    let before = revision_of(&verify_doc(&w, &fleet), "api");
    w.set_value("shared", "KEY", &format!("key2-{MARK}"));
    sync_all(&w, &fleet).unwrap();
    assert_ne!(revision_of(&verify_doc(&w, &fleet), "api"), before);
}

/// #201, the staging run: an immutable key already on Fly when the placement has no
/// evidence line for it is held, and Fly's digest cannot be computed locally (D0), so
/// nothing proves it identical and the product gets no revision.
#[test]
fn a_held_immutable_key_with_no_evidence_line_blocks_the_receipt() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = world_with_immutable_token();
    w.app("myapp")
        .insert("FLEET__API__TOKEN".into(), (format!("tok-{MARK}"), false));
    sync_all(&w, &fleet).unwrap();
    assert_eq!(state_of(&verify_doc(&w, &fleet), "api"), "not_delivered");
}

#[test]
fn an_edit_on_the_target_outside_opv_is_drift() {
    let (w, fleet) = delivered();
    w.app("myapp").insert(
        "FLEET__API__TOKEN".into(),
        ("edited-elsewhere".into(), false),
    );
    let doc = verify_doc(&w, &fleet);
    let names =
        doc["placements"][0]["names"].to_string() + &doc["placements"][1]["names"].to_string();
    assert!(names.contains("drifted_on_target"), "{doc}");
}

#[test]
fn a_name_removed_from_the_target_is_missing() {
    let (w, fleet) = delivered();
    w.app("myapp").remove("FLEET__WEB__SESSION");
    let doc = verify_doc(&w, &fleet);
    assert!(doc.to_string().contains("missing_on_target"), "{doc}");
}

#[test]
fn a_staged_delivery_is_reported_as_not_yet_deployed() {
    let (w, fleet) = delivered();
    let doc = verify_doc(&w, &fleet);
    assert_eq!(doc["placements"][0]["deployed"], "staged");
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
fn the_binding_set_of_a_secrets_fly_target_includes_its_config_keys() {
    let fleet = crate::config::parse(
        "[environments.prod]\n\
         boundaries.p = { vault_id = \"v\", item_id = \"i\" }\n\
         [environments.prod.targets.app]\n\
         state_vault_id = \"s\"\n\
         fly.app = \"myapp\"\n\
         fly.secret_name = \"FLEET__{PRODUCT}__{KEY}\"\n\
         fly.config = \"secrets\"\n\
         delivery_items = { p = \"di\" }\n\
         [products.p.keys.SIGNUP_POLICY]\n\
         kind = \"config\"\n\
         environments = [\"prod\"]\n",
    )
    .unwrap();
    let names: Vec<String> = bindings(&fleet, "prod", "app", "p")
        .unwrap()
        .into_iter()
        .map(|b| b.name)
        .collect();
    assert_eq!(names, vec!["FLEET__P__SIGNUP_POLICY".to_string()]);
}

#[test]
fn another_app_cannot_reuse_the_revision() {
    let (w, fleet) = delivered();
    let mut moved = fleet.clone();
    let t = moved
        .environments
        .get_mut("prod")
        .unwrap()
        .targets
        .get_mut("app")
        .unwrap();
    let other = crate::config::parse(&format!(
        "[environments.prod]\n\
         boundaries.api = {{ vault_id = \"{VALUES}\", item_id = \"x\" }}\n\
         [environments.prod.targets.app]\nstate_vault_id = \"{STATE}\"\n\
         fly.app = \"another-app\"\nfly.secret_name = \"FLEET__{{PRODUCT}}__{{KEY}}\"\n\
         [products.api.keys.TOKEN]\nkind = \"secret\"\nenvironments = [\"prod\"]\n"
    ))
    .unwrap();
    t.config = other.environments["prod"].targets["app"].config.clone_box();
    let doc = verify_doc(&w, &moved);
    assert_eq!(state_of(&doc, "api"), "not_delivered");
}

#[test]
fn a_placement_without_a_recorded_delivery_item_is_not_delivered() {
    let _person = crate::app::tidy::activate();
    let (w, mut fleet) = world();
    fleet
        .environments
        .get_mut("prod")
        .unwrap()
        .targets
        .get_mut("app")
        .unwrap()
        .delivery_items
        .remove("api");
    sync_all(&w, &fleet).unwrap();
    assert_eq!(state_of(&verify_doc(&w, &fleet), "api"), "not_delivered");
}

#[test]
fn sync_never_looks_a_delivery_item_up_by_title() {
    let (w, _) = delivered();
    assert_eq!(w.op.count(&["op", "item", "list"]), 0);
}

#[test]
fn a_delivery_item_keeps_its_notes() {
    let (w, fleet) = delivered();
    let id = &fleet.environments["prod"].targets["app"].delivery_items["api"];
    assert!(
        w.op.item(id)["fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["purpose"] == "NOTES")
    );
}

/// The delivery item's recorded `source versions` text, if the field is there.
fn source_versions(w: &World, fleet: &Fleet, product: &str) -> Option<String> {
    let id = &fleet.environments["prod"].targets["app"].delivery_items[product];
    w.op.item(id)["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["label"] == "source versions")
        .and_then(|f| f["value"].as_str())
        .map(str::to_string)
}

#[test]
fn a_confirmed_sync_records_each_source_items_version() {
    let (w, fleet) = delivered();
    let source = fleet.environments["prod"].boundaries["api"]
        .as_ref()
        .unwrap();
    let expected = format!(
        "v1|{}|{}\n",
        source.item_id,
        w.op.item(&source.item_id)["version"]
    );
    assert_eq!(source_versions(&w, &fleet, "api"), Some(expected));
}

#[test]
fn an_unconfirmed_sync_keeps_the_recorded_source_versions() {
    let (w, fleet) = delivered();
    let source = fleet.environments["prod"].boundaries["api"]
        .as_ref()
        .unwrap();
    let before = format!(
        "v1|{}|{}\n",
        source.item_id,
        w.op.item(&source.item_id)["version"]
    );
    w.set_value("api", "TOKEN", &format!("tok2-{MARK}"));
    w.fail_import.set(true);
    let _ = sync_all(&w, &fleet);
    assert_eq!(source_versions(&w, &fleet, "api"), Some(before));
}

#[test]
fn changed_is_unchanged_after_a_confirmed_sync() {
    let (w, fleet) = delivered();
    let source = fleet.environments["prod"].boundaries["api"]
        .as_ref()
        .unwrap();
    let delivery = &fleet.environments["prod"].targets["app"].delivery_items["api"];
    let list = format!(
        "[{{\"id\":\"{}\",\"version\":{}}},{{\"id\":\"{delivery}\",\"version\":9}},\
         {{\"id\":\"itm-deploy-creds\",\"version\":8}}]",
        source.item_id,
        w.op.item(&source.item_id)["version"]
    );
    let r = FakeRunner::new([
        Output::success(list),
        Output::success(source_versions(&w, &fleet, "api").unwrap()),
        Output::success(source_versions(&w, &fleet, "web").unwrap()),
    ]);
    let res = crate::app::changed::run(&fleet, "prod", None, &[], &r, false, &mut Vec::new());
    assert_eq!(res.unwrap(), 0);
}

#[test]
fn writing_one_placement_never_touches_another() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = world();
    let web = fleet.environments["prod"].targets["app"].delivery_items["web"].clone();
    let before = w.op.item(&web);
    let opts = SyncOpts {
        product: Some("api".into()),
        ..SyncOpts::default()
    };
    sync_with(&w, &fleet, opts).0.unwrap();
    assert_eq!(w.op.item(&web), before);
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
    verify(
        &fleet,
        "prod",
        None,
        &[],
        Some(&path),
        &w,
        true,
        &mut Vec::new(),
    )
    .unwrap_err()
}

/// The catalog cause of `e`.
fn cause_of(e: &Error) -> crate::cause::Cause {
    match e.cause() {
        Some((c, _)) => c.clone(),
        None => panic!("not a catalog cause: {e}"),
    }
}

/// The Next of `e` for `opv delivery verify prod`.
fn verify_next(e: &Error) -> crate::cause::Next {
    let argv: Vec<String> = ["opv", "delivery", "verify", "prod"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    cause_of(e)
        .step(&crate::cause::Invocation::from_cli(&argv))
        .1
}

/// 01.09: a duplicate is an invalid receipt input (was `duplicate_scope` text with a slug
/// in it and `--help` as its step), whose rule is "keep one".
#[test]
fn a_duplicate_scope_in_the_receipt_file_is_a_duplicate_in_the_receipt() {
    assert!(matches!(
        cause_of(&duplicate_receipt_error()),
        crate::cause::Cause::InputInvalid {
            kind: crate::cause::InputKind::Receipt,
            rule: crate::cause::FieldRule::DuplicateKey,
            ..
        }
    ));
}

#[test]
fn a_duplicate_scope_error_names_the_receipt_file() {
    assert!(matches!(
        cause_of(&duplicate_receipt_error()),
        crate::cause::Cause::InputInvalid { path, .. } if path.ends_with("prod.receipt.json")
    ));
}

#[test]
fn a_duplicate_scope_error_reruns_the_same_verify_after_the_edit() {
    assert_eq!(
        verify_next(&duplicate_receipt_error()),
        crate::cause::Next::Rerun
    );
}

/// 01.06: an unverified placement is `delivery_unverified`, not `findings`.
#[test]
fn an_unverified_placement_is_delivery_unverified() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = world();
    let e = verify(
        &fleet,
        "prod",
        Some("api"),
        &[],
        None,
        &w,
        false,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(cause_of(&e).code(), "delivery_unverified");
}

/// 01.06: a delivery never made is "not recorded", stepped to a scoped plan, never an
/// unscoped `opv sync`.
#[test]
fn a_placement_never_delivered_steps_to_the_targets_plan() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = world();
    let e = verify(
        &fleet,
        "prod",
        Some("api"),
        &[],
        None,
        &w,
        false,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(
        verify_next(&e),
        crate::cause::Next::Check(crate::cause::Cmd {
            command: vec!["plan".into()],
            args: vec!["prod".into(), "--target".into(), "app".into()],
        })
    );
}

/// 01.06: a value changed on the target is `ChangedOnTarget`.
#[test]
fn an_edit_on_the_target_is_changed_on_target() {
    let (w, fleet) = delivered();
    w.app("myapp").insert(
        "FLEET__API__TOKEN".into(),
        ("edited-elsewhere".into(), false),
    );
    let e = verify(
        &fleet,
        "prod",
        Some("api"),
        &[],
        None,
        &w,
        false,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert!(matches!(
        cause_of(&e),
        crate::cause::Cause::DeliveryUnverified {
            state: crate::cause::Unverified::ChangedOnTarget,
            ..
        }
    ));
}

/// 01.17: the text report words states, never a snake_case slug.
#[test]
fn the_text_report_words_its_states() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = world();
    let mut out = Vec::new();
    let _ = verify(&fleet, "prod", Some("api"), &[], None, &w, false, &mut out);
    assert!(
        !String::from_utf8(out).unwrap().contains("not_delivered"),
        "slug in the text report"
    );
}

/// A13: a named target that delivers a product with no secret says so.
#[test]
fn a_named_target_that_delivers_no_secret_says_so() {
    let (w, fleet) = no_secrets();
    let e = verify(
        &fleet,
        "prod",
        None,
        &["app".to_string()],
        None,
        &w,
        false,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert!(matches!(
        cause_of(&e),
        crate::cause::Cause::NothingInScope {
            what: crate::cause::Scope::NoSecretDelivered { target },
            ..
        } if target.as_str() == "app"
    ));
}

/// 01.18: with `--target`, nothing in scope names that target.
#[test]
fn nothing_to_verify_on_a_named_target_names_it() {
    // Neither target of `two_targets` delivers web.
    let (w, fleet) = two_targets();
    let e = verify(
        &fleet,
        "prod",
        Some("web"),
        &["a".to_string()],
        None,
        &w,
        false,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert!(matches!(
        cause_of(&e),
        crate::cause::Cause::NothingInScope {
            what: crate::cause::Scope::NoTargetDelivers { target },
            ..
        } if target.as_str() == "a"
    ));
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
    let _ = verify(
        &fleet,
        "prod",
        Some("api"),
        &[],
        Some(&path),
        &w,
        true,
        &mut out,
    );
    let doc: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(doc["placements"][0]["state"], "superseded");
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
        &[],
        Some(&path),
        &w,
        false,
        &mut verify_out,
    );
    let all = sync_out
        + &std::fs::read_to_string(&path).unwrap()
        + &String::from_utf8(verify_out).unwrap();
    let digests: Vec<String> = w.app("myapp").values().map(|(v, _)| digest(v)).collect();
    assert!(
        !all.contains(MARK) && digests.iter().all(|d| !all.contains(d.as_str())),
        "{all}"
    );
}

// ---- Placements (FR-58, #114): one product on two targets of one environment ---------

/// prod with api on two targets, `a` (Fly app `app-a`) and `b` (`app-b`), each with api's
/// own delivery item in STATE.
fn two_targets() -> (World, Fleet) {
    let op = FakeOp::default();
    let id = values_item(&op);
    let (a, b) = (
        delivery_item(&op, "api", "a"),
        delivery_item(&op, "api", "b"),
    );
    let fleet = crate::config::parse(&format!(
        "{}{}{}{PRODUCTS}",
        boundaries(&id),
        target_toml("a", "app-a", &[("api", &a)])
            .replace("delivery_items", "products = [\"api\"]\ndelivery_items"),
        target_toml("b", "app-b", &[("api", &b)])
            .replace("delivery_items", "products = [\"api\"]\ndelivery_items"),
    ))
    .unwrap();
    let w = World {
        op,
        fly: RefCell::default(),
        fail_import: std::cell::Cell::new(false),
        fail_op_write_on: RefCell::default(),
    };
    (w, fleet)
}

/// prod with target `app` that delivers `api`, whose only key is config: the target
/// delivers a product but no secret.
fn no_secrets() -> (World, Fleet) {
    let op = FakeOp::default();
    let id = values_item(&op);
    let api = delivery_item(&op, "api", "app");
    let fleet = crate::config::parse(&format!(
        "[environments.prod]\nboundaries.api = {{ vault_id = \"{VALUES}\", item_id = \"{id}\" }}\n\
         {}[products.api]\n[products.api.keys.MODE]\nkind = \"config\"\n\
         environments = [\"prod\"]\n",
        target_toml("app", "myapp", &[("api", &api)])
            .replace("delivery_items", "products = [\"api\"]\ndelivery_items"),
    ))
    .unwrap();
    let w = World {
        op,
        fly: RefCell::default(),
        fail_import: std::cell::Cell::new(false),
        fail_op_write_on: RefCell::default(),
    };
    (w, fleet)
}

/// `opv sync prod --target <t>`.
fn sync_target(w: &World, fleet: &Fleet, target: &str) {
    let opts = SyncOpts {
        targets: vec![target.to_string()],
        ..SyncOpts::default()
    };
    sync_with(w, fleet, opts).0.unwrap();
}

/// `opv delivery verify prod --product api --json` → target → (state, deployed).
fn placements(w: &World, fleet: &Fleet) -> BTreeMap<String, (String, String)> {
    let mut out = Vec::new();
    let _ = verify(fleet, "prod", Some("api"), &[], None, w, true, &mut out);
    let doc: Value = serde_json::from_slice(&out).unwrap();
    doc["placements"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p["target"].as_str().unwrap().to_string(),
                (
                    p["state"].as_str().unwrap().to_string(),
                    p["deployed"].as_str().unwrap().to_string(),
                ),
            )
        })
        .collect()
}

fn states(w: &World, fleet: &Fleet) -> Vec<(String, String)> {
    placements(w, fleet)
        .into_iter()
        .map(|(t, (state, _))| (t, state))
        .collect()
}

/// api delivered to `a`, then to `b`.
fn on_both() -> (World, Fleet) {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = two_targets();
    sync_target(&w, &fleet, "a");
    sync_target(&w, &fleet, "b");
    (w, fleet)
}

/// Change api/TOKEN in 1Password, as a person would.
fn rotate_token(w: &World) {
    w.set_value("api", "TOKEN", &format!("tok2-{MARK}"));
}

/// The plan of target `target`: what plan and status judge from.
fn plan_of(w: &World, fleet: &Fleet, target: &str) -> crate::domain::plan::SyncPlan {
    let (_, ports) = crate::app::open_target(fleet, "prod", target, w).unwrap();
    let none = std::collections::BTreeSet::new();
    crate::app::read_and_plan(fleet, "prod", Some(target), w, Some(&ports), &none, &none)
        .unwrap()
        .0
}

/// The plan's judgement of api/TOKEN on target `target`.
fn token_on(w: &World, fleet: &Fleet, target: &str) -> crate::domain::plan::TargetState {
    plan_of(w, fleet, target)
        .rows
        .iter()
        .find(|r| r.product == "api" && r.key == "TOKEN")
        .unwrap()
        .target
}

#[test]
fn a_product_recorded_on_two_targets_stays_verified_on_both() {
    let (w, fleet) = on_both();
    assert_eq!(
        states(&w, &fleet),
        [
            ("a".to_string(), "verified".to_string()),
            ("b".to_string(), "verified".to_string())
        ]
    );
}

#[test]
fn verify_target_narrows_to_one_placement() {
    let (w, fleet) = on_both();
    let mut out = Vec::new();
    let _ = verify(
        &fleet,
        "prod",
        Some("api"),
        &["b".to_string()],
        None,
        &w,
        true,
        &mut out,
    );
    let doc: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(doc["placements"][0]["target"], "b");
}

#[test]
fn verify_target_returns_only_that_placement() {
    let (w, fleet) = on_both();
    let mut out = Vec::new();
    let _ = verify(
        &fleet,
        "prod",
        Some("api"),
        &["b".to_string()],
        None,
        &w,
        true,
        &mut out,
    );
    let doc: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(doc["placements"].as_array().unwrap().len(), 1);
}

#[test]
fn a_stale_revision_on_b_leaves_a_verified() {
    let (w, fleet) = on_both();
    rotate_token(&w);
    sync_target(&w, &fleet, "a");
    assert_eq!(placements(&w, &fleet)["a"].0, "verified");
}

#[test]
fn a_stale_revision_on_b_is_changed() {
    let (w, fleet) = on_both();
    rotate_token(&w);
    sync_target(&w, &fleet, "a");
    assert_eq!(placements(&w, &fleet)["b"].0, "changed");
}

#[test]
fn staged_and_deployed_are_per_placement() {
    let (w, fleet) = on_both();
    for (_, staged) in w.app("app-a").values_mut() {
        *staged = false;
    }
    let p = placements(&w, &fleet);
    assert_eq!(
        (p["a"].1.as_str(), p["b"].1.as_str()),
        ("deployed", "staged")
    );
}

#[test]
fn drift_on_b_is_not_drift_on_a() {
    let (w, fleet) = on_both();
    w.app("app-b").insert(
        "FLEET__API__TOKEN".into(),
        ("edited-elsewhere".into(), false),
    );
    assert_eq!(
        (
            plan_of(&w, &fleet, "a").drift,
            plan_of(&w, &fleet, "b").drift
        ),
        (Vec::new(), vec!["FLEET__API__TOKEN".to_string()])
    );
}

#[test]
fn the_ledger_judges_each_placement_by_its_own_evidence() {
    let (w, fleet) = on_both();
    rotate_token(&w);
    sync_target(&w, &fleet, "a");
    use crate::domain::plan::TargetState;
    assert_eq!(
        (token_on(&w, &fleet, "a"), token_on(&w, &fleet, "b")),
        (TargetState::Present, TargetState::WouldChange)
    );
}

#[test]
fn receipt_selection_is_independent_of_order() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = two_targets();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("prod.receipt.json");
    let opts = SyncOpts {
        receipt: Some(path.clone()),
        ..SyncOpts::default()
    };
    sync_with(&w, &fleet, opts).0.unwrap();
    let mut doc: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    doc["deliveries"].as_array_mut().unwrap().reverse();
    std::fs::write(&path, serde_json::to_string(&doc).unwrap()).unwrap();
    let mut out = Vec::new();
    let _ = verify(
        &fleet,
        "prod",
        Some("api"),
        &[],
        Some(&path),
        &w,
        true,
        &mut out,
    );
    let doc: Value = serde_json::from_slice(&out).unwrap();
    let states: Vec<&str> = doc["placements"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["state"].as_str().unwrap())
        .collect();
    assert_eq!(states, ["verified", "verified"]);
}

#[test]
fn no_op_argument_holds_a_value_digest_or_fingerprint() {
    let (w, fleet) = on_both();
    let _ = placements(&w, &fleet);
    let secrets: Vec<String> =
        w.op.items
            .borrow()
            .iter()
            .flat_map(|i| i["fields"].as_array().cloned().unwrap_or_default())
            .filter(|f| f["type"] == "CONCEALED")
            .filter_map(|f| f["value"].as_str().map(str::to_string))
            .chain(w.app("app-a").values().map(|(v, _)| digest(v)))
            .collect();
    let argv: Vec<String> =
        w.op.calls
            .borrow()
            .iter()
            .flat_map(|c| c.args.clone())
            .collect();
    // An evidence line's store version and fingerprint; any other concealed value whole.
    let parts: Vec<&str> = secrets
        .iter()
        .flat_map(|s| match s.strip_prefix("v1|") {
            Some(line) => line.split('|').take(2).collect::<Vec<_>>(),
            None => vec![s.as_str()],
        })
        .collect();
    assert!(
        parts.iter().all(|s| argv.iter().all(|a| !a.contains(s))),
        "{argv:?}"
    );
}

#[test]
fn sync_never_reads_or_writes_an_opv_state_section() {
    let (w, _) = on_both();
    assert!(!w.op.saw("opv · state"));
}

// ---- The binding set: exactly what the target delivers (FR-58) ----------------------

/// [`world`] plus api/STRIPE, a key the `payments = "off"` mode skips in prod.
fn with_a_mode_skipped_key() -> (World, Fleet) {
    let (w, fleet) = world();
    let api = fleet.environments["prod"].targets["app"].delivery_items["api"].clone();
    let web = fleet.environments["prod"].targets["app"].delivery_items["web"].clone();
    let id = fleet.environments["prod"].boundaries["api"]
        .as_ref()
        .unwrap()
        .item_id
        .clone();
    let fleet = crate::config::parse(&format!(
        "{}modes.api.payments = \"off\"\n{}{PRODUCTS}\
         [products.api.keys.STRIPE]\nkind = \"secret\"\nenvironments = [\"prod\"]\n\
         rules = {{ prefix_by_mode = {{ mode = \"payments\", values = {{ test = \"sk_test_\" }}, skip = [\"off\"] }} }}\n",
        boundaries(&id),
        target_toml("app", "myapp", &[("api", &api), ("web", &web)])
    ))
    .unwrap();
    (w, fleet)
}

#[test]
fn a_mode_skipped_key_is_not_in_the_binding_set() {
    let (_, fleet) = with_a_mode_skipped_key();
    let names: Vec<String> = bindings(&fleet, "prod", "app", "api")
        .unwrap()
        .into_iter()
        .map(|b| b.name)
        .collect();
    assert_eq!(names, ["FLEET__API__SHARED", "FLEET__API__TOKEN"]);
}

#[test]
fn a_product_with_a_mode_skipped_key_mints_a_revision() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = with_a_mode_skipped_key();
    sync_all(&w, &fleet).unwrap();
    assert_eq!(state_of(&verify_doc(&w, &fleet), "api"), "verified");
}

#[test]
fn a_receipt_path_that_cannot_be_written_stages_nothing() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = world();
    let dir = tempfile::tempdir().unwrap();
    let opts = SyncOpts {
        receipt: Some(dir.path().join("no-such-dir").join("prod.receipt.json")),
        ..SyncOpts::default()
    };
    let _ = sync_with(&w, &fleet, opts);
    assert!(w.fly.borrow().values().all(BTreeMap::is_empty));
}

#[test]
fn a_receipt_path_that_is_a_directory_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    assert!(check_receipt_path(dir.path()).is_err());
}

#[test]
fn verify_of_a_misspelt_product_is_unknown_product() {
    let (w, fleet) = delivered();
    let mut out = Vec::new();
    let e = verify(&fleet, "prod", Some("apii"), &[], None, &w, false, &mut out).unwrap_err();
    assert_eq!(e.code_str(), "unknown_product");
}

#[test]
fn verify_with_nothing_in_scope_fails() {
    let (w, fleet) = delivered();
    let mut out = Vec::new();
    // `shared` is source-only: no target delivers it.
    let res = verify(
        &fleet,
        "prod",
        Some("shared"),
        &[],
        None,
        &w,
        false,
        &mut out,
    );
    assert!(res.is_err());
}

/// A receipt is never minted or judged under a guessed account.
#[test]
fn an_account_whoami_cannot_name_is_an_error() {
    let r = crate::runner::fake::FakeRunner::new([Output::success("{}")]);
    assert!(account_id(&r).is_err());
}

/// M3, §4.4: a key whose roles miss the target's roles is not in the target's binding set,
/// so a confirmed sync of the rest can mint a receipt.
#[test]
fn a_key_withheld_by_the_targets_roles_is_not_bound() {
    let text = crate::app::testutil::role_fixture_text().replacen(
        "state_vault_id = \"sprd\"\nroles = [\"serve\", \"migrate\"]",
        "state_vault_id = \"sprd\"\nroles = [\"serve\"]",
        1,
    );
    let fleet =
        crate::config::parse(&format!("{text}\n{}", crate::app::testutil::ROLE_KEYS)).unwrap();
    let names: Vec<String> = bindings(&fleet, "prod", "portfolio", "allumata")
        .unwrap()
        .into_iter()
        .map(|b| b.name)
        .collect();
    assert!(!names.contains(&"FLEET__ALLUMATA__DATABASE_URL_UNPOOLED".to_string()));
}

/// #201: a person's attestation, on this module's world.
#[path = "attest_tests.rs"]
mod attest_tests;
