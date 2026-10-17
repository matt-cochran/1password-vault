//! Named targets in one run (FR-56, D1 "every target, one plan id"): `status`, `plan` and
//! `sync` cover every target of the environment in name order, `--target` narrows them,
//! one plan id covers exactly the targets planned, rows name their target, and each target
//! keeps its own delivery evidence (FR-58). 1Password is the stateful fake; Fly is a small
//! store per app that lists a digest and a staged flag per name.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::io;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::*;
use crate::adapters::fake_op::FakeOp;
use crate::app::sync::{self, SyncOpts};
use crate::app::testutil::{fly_app_ok, fly_releases, ok};
use crate::runner::{Call, Outcome, Output};

const MARK: &str = "PLACEMENTMARK";
const VALUES: &str = "vdev0000000000000000000001";
const STATE_EAST: &str = "vste0000000000000000000003";
const STATE_WEST: &str = "vstw0000000000000000000004";
const NAME: &str = "FLEET__API__TOKEN";

fn digest(v: &str) -> String {
    hex::encode(Sha256::digest(v))[..16].to_string()
}

/// One Fly app's secrets: name → (value, staged).
type Secrets = BTreeMap<String, (String, bool)>;

/// 1Password plus one Fly app per target, by app name.
struct World {
    op: FakeOp,
    fly: RefCell<BTreeMap<String, Secrets>>,
    /// The next `secrets import` to this app fails before it reaches Fly.
    fail_import: RefCell<Option<String>>,
    /// The `--receipt` file of a sync.
    dir: tempfile::TempDir,
    item_id: String,
    imports: Cell<usize>,
}

impl World {
    fn app_of<'a>(args: &[&'a str]) -> &'a str {
        let at = args.iter().position(|a| *a == "--app").expect("--app");
        args[at + 1]
    }

    fn fly(&self, args: &[&str], stdin: Option<&[u8]>) -> Output {
        match args {
            ["status", ..] => fly_app_ok(),
            ["releases", ..] => fly_releases("complete"),
            ["secrets", "list", ..] => {
                let fly = self.fly.borrow();
                let v: Vec<Value> = fly
                    .get(Self::app_of(args))
                    .into_iter()
                    .flatten()
                    .map(|(n, (value, staged))| {
                        json!({"name": n, "digest": digest(value),
                               "status": if *staged { "Staged" } else { "Deployed" }})
                    })
                    .collect();
                Output::success(serde_json::to_vec(&v).unwrap())
            }
            ["secrets", "import", ..] => {
                let app = Self::app_of(args);
                if self.fail_import.borrow().as_deref() == Some(app) {
                    return Output::failure(1);
                }
                self.imports.set(self.imports.get() + 1);
                let text = String::from_utf8(stdin.unwrap().to_vec()).unwrap();
                let mut fly = self.fly.borrow_mut();
                let secrets = fly.entry(app.to_string()).or_default();
                for line in text.lines() {
                    let (name, quoted) = line.split_once('=').unwrap();
                    let value = quoted.trim_matches('"').to_string();
                    secrets.insert(name.to_string(), (value, true));
                }
                ok()
            }
            other => panic!("unexpected flyctl call {other:?}"),
        }
    }

    /// The names app `app` holds.
    fn names_on(&self, app: &str) -> Vec<String> {
        self.fly
            .borrow()
            .get(app)
            .map(|s| s.keys().cloned().collect())
            .unwrap_or_default()
    }

    fn receipt_path(&self) -> std::path::PathBuf {
        self.dir.path().join("receipts.json")
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
            Outcome::Refused(out)
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
        unreachable!("status, plan and sync never run a child")
    }
}

/// prod's values item (product api, key TOKEN) and the two targets' state vaults.
fn world() -> World {
    let op = FakeOp::default();
    op.vaults.borrow_mut().extend([
        (STATE_EAST.into(), "state-east".into()),
        (STATE_WEST.into(), "state-west".into()),
    ]);
    let item_id = op.insert(
        VALUES,
        json!({
            "title": "myapp · api · prod values", "category": "SECURE_NOTE",
            "sections": [{"id": "api", "label": "api"}],
            "fields": [{"id": "api-TOKEN", "section": {"id": "api", "label": "api"},
                        "type": "CONCEALED", "label": "TOKEN", "value": format!("tok-{MARK}")}]
        }),
    );
    World {
        op,
        fly: RefCell::default(),
        fail_import: RefCell::new(None),
        dir: tempfile::tempdir().unwrap(),
        item_id,
        imports: Cell::new(0),
    }
}

/// One Fly target table, with api's delivery item in its state vault (FR-58), as
/// `opv bootstrap` records it.
fn target_toml(w: &World, name: &str, state: &str) -> String {
    let title = crate::domain::naming::delivery_item("api", name);
    let found =
        w.op.items
            .borrow()
            .iter()
            .find(|i| i["title"] == title.as_str() && i["vault"]["id"] == state)
            .and_then(|i| i["id"].as_str().map(str::to_string));
    let item = found.unwrap_or_else(|| {
        w.op.insert(
            state,
            json!({"title": title, "category": "SECURE_NOTE", "fields": []}),
        )
    });
    format!(
        "[environments.prod.targets.{name}]\nfly.app = \"myapp-{name}\"\n\
         fly.secret_name = \"FLEET__{{PRODUCT}}__{{KEY}}\"\nstate_vault_id = \"{state}\"\n\
         delivery_items = {{ api = \"{item}\" }}\n\n"
    )
}

/// prod with `targets` (each `(name, state vault)`), delivering api/TOKEN to every one.
fn fleet_of(w: &World, targets: &[(&str, &str)]) -> Fleet {
    let mut text = format!(
        "[environments.prod]\nboundaries.api = {{ vault_id = \"{VALUES}\", item_id = \"{}\" }}\n\n",
        w.item_id
    );
    for (name, state) in targets {
        text.push_str(&target_toml(w, name, state));
    }
    text.push_str("[products.api.keys.TOKEN]\nkind = \"secret\"\nenvironments = [\"prod\"]\n");
    crate::config::parse(&text).unwrap()
}

/// prod on targets east and west.
fn both(w: &World) -> Fleet {
    fleet_of(w, &[("east", STATE_EAST), ("west", STATE_WEST)])
}

fn targets(names: &[&str]) -> Vec<String> {
    names.iter().map(|n| n.to_string()).collect()
}

fn sync_with(w: &World, fleet: &Fleet, opts: SyncOpts) -> (Result<(), Error>, String) {
    let _person = tidy::activate();
    let mut out = Vec::new();
    let res = sync::run(fleet, "prod", w, &mut out, &opts);
    (res, String::from_utf8(out).unwrap())
}

fn plan_doc(w: &World, fleet: &Fleet, only: &[&str]) -> Value {
    let mut out = Vec::new();
    sync::plan_targeted(fleet, "prod", &targets(only), None, w, &mut out, true).unwrap();
    serde_json::from_slice(&out).unwrap()
}

fn plan_id(w: &World, fleet: &Fleet, only: &[&str]) -> String {
    plan_doc(w, fleet, only)["plan_id"]
        .as_str()
        .unwrap()
        .to_string()
}

fn status_text(w: &World, fleet: &Fleet) -> String {
    let mut out = Vec::new();
    let _ = status::run_targeted(fleet, "prod", &[], None, w, &mut out, false, false);
    String::from_utf8(out).unwrap()
}

fn status_doc(w: &World, fleet: &Fleet) -> Value {
    let mut out = Vec::new();
    let _ = status::run_targeted(fleet, "prod", &[], None, w, &mut out, true, false);
    serde_json::from_slice(&out).unwrap()
}

fn row_targets(doc: &Value) -> Vec<String> {
    doc["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["target"].as_str().unwrap_or_default().to_string())
        .collect()
}

#[test]
fn one_sync_writes_every_target_of_the_environment() {
    let w = world();
    sync_with(&w, &both(&w), SyncOpts::default()).0.unwrap();
    assert_eq!(
        (w.names_on("myapp-east"), w.names_on("myapp-west")),
        (vec![NAME.to_string()], vec![NAME.to_string()])
    );
}

#[test]
fn one_product_on_two_targets_gets_two_receipts_whose_scopes_differ_only_in_target() {
    let w = world();
    let opts = SyncOpts {
        receipt: Some(w.receipt_path()),
        ..SyncOpts::default()
    };
    sync_with(&w, &both(&w), opts).0.unwrap();
    let doc: Value =
        serde_json::from_str(&std::fs::read_to_string(w.receipt_path()).unwrap()).unwrap();
    // The locator is the target's own app, so it follows the target.
    let scopes: Vec<(String, String, String, String, String)> = doc["deliveries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            let s = &d["scope"];
            let f = |k: &str| s[k].as_str().unwrap().to_string();
            (
                f("account_id"),
                f("environment"),
                f("product"),
                f("provider"),
                f("target"),
            )
        })
        .collect();
    let account = scopes.first().map(|s| s.0.clone()).unwrap_or_default();
    let scope = |t: &str| {
        (
            account.clone(),
            "prod".to_string(),
            "api".to_string(),
            "fly".to_string(),
            t.to_string(),
        )
    };
    assert_eq!(scopes, vec![scope("east"), scope("west")]);
}

#[test]
fn target_flag_narrows_the_sync_to_that_target() {
    let w = world();
    let opts = SyncOpts {
        targets: targets(&["east"]),
        ..SyncOpts::default()
    };
    sync_with(&w, &both(&w), opts).0.unwrap();
    assert!(w.names_on("myapp-west").is_empty());
}

#[test]
fn target_flag_narrows_the_plan_to_that_target() {
    let w = world();
    assert_eq!(row_targets(&plan_doc(&w, &both(&w), &["west"])), ["west"]);
}

#[test]
fn plan_without_target_covers_every_target_in_name_order() {
    let w = world();
    assert_eq!(row_targets(&plan_doc(&w, &both(&w), &[])), ["east", "west"]);
}

#[test]
fn plan_id_is_the_same_for_the_same_configuration_and_state() {
    let w = world();
    let fleet = both(&w);
    assert_eq!(plan_id(&w, &fleet, &[]), plan_id(&w, &fleet, &[]));
}

#[test]
fn plan_id_changes_when_a_target_is_added() {
    let w = world();
    let one = fleet_of(&w, &[("east", STATE_EAST)]);
    assert_ne!(plan_id(&w, &one, &[]), plan_id(&w, &both(&w), &[]));
}

#[test]
fn plan_id_of_one_target_differs_from_the_plan_id_of_all() {
    let w = world();
    let fleet = both(&w);
    assert_ne!(plan_id(&w, &fleet, &["east"]), plan_id(&w, &fleet, &[]));
}

#[test]
fn expect_plan_applies_a_plan_made_for_the_same_targets() {
    let w = world();
    let fleet = both(&w);
    let opts = SyncOpts {
        expect_plan: Some(plan_id(&w, &fleet, &[])),
        ..SyncOpts::default()
    };
    assert!(sync_with(&w, &fleet, opts).0.is_ok());
}

#[test]
fn expect_plan_refuses_a_plan_made_for_other_targets() {
    let w = world();
    let fleet = both(&w);
    let opts = SyncOpts {
        expect_plan: Some(plan_id(&w, &fleet, &["east"])),
        ..SyncOpts::default()
    };
    let err = sync_with(&w, &fleet, opts).0.unwrap_err();
    assert_eq!(err.code_str(), "stale_plan");
}

#[test]
fn a_refused_plan_writes_no_target() {
    let w = world();
    let fleet = both(&w);
    let opts = SyncOpts {
        expect_plan: Some(plan_id(&w, &fleet, &["east"])),
        ..SyncOpts::default()
    };
    let _ = sync_with(&w, &fleet, opts);
    assert_eq!(w.imports.get(), 0);
}

#[test]
fn status_table_starts_with_a_target_column() {
    let w = world();
    let text = status_text(&w, &both(&w));
    let header = text
        .lines()
        .find(|l| l.contains("PRODUCT"))
        .unwrap_or_default();
    assert!(header.starts_with("TARGET "), "{text}");
}

#[test]
fn status_rows_name_their_target() {
    let w = world();
    let text = status_text(&w, &both(&w));
    let firsts: Vec<&str> = text
        .lines()
        .skip_while(|l| !l.starts_with("TARGET "))
        .skip(1)
        .filter_map(|l| l.split_whitespace().next())
        .filter(|w| ["east", "west"].contains(w))
        .collect();
    assert_eq!(firsts, ["east", "west"]);
}

#[test]
fn status_count_lines_name_each_target() {
    let w = world();
    let text = status_text(&w, &both(&w));
    let counts: Vec<&str> = text
        .lines()
        .take(2)
        .map(|l| l.split(':').next().unwrap_or_default())
        .collect();
    assert_eq!(counts, ["prod/east", "prod/west"]);
}

#[test]
fn status_json_rows_carry_their_target() {
    let w = world();
    assert_eq!(row_targets(&status_doc(&w, &both(&w))), ["east", "west"]);
}

#[test]
fn plan_text_rows_carry_their_target() {
    let w = world();
    let mut out = Vec::new();
    sync::plan_targeted(&both(&w), "prod", &[], None, &w, &mut out, false).unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.lines()
            .any(|l| l.starts_with("west ") && l.contains("TOKEN")),
        "{text}"
    );
}

#[test]
fn sync_json_lists_name_their_target() {
    let w = world();
    let opts = SyncOpts {
        json: true,
        ..SyncOpts::default()
    };
    let (_, out) = sync_with(&w, &both(&w), opts);
    let doc: Value = serde_json::from_str(&out).unwrap();
    let written: Vec<&str> = doc["written"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["target"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(written, ["east", "west"]);
}

#[test]
fn sync_summaries_name_each_target() {
    let w = world();
    let (_, out) = sync_with(&w, &both(&w), SyncOpts::default());
    let summaries: Vec<&str> = out
        .lines()
        .filter(|l| l.contains("summary: "))
        .map(|l| l.split(": ").next().unwrap_or_default())
        .collect();
    assert_eq!(summaries, ["prod/east", "prod/west"]);
}

#[test]
fn an_unknown_target_is_unknown_target() {
    let w = world();
    let opts = SyncOpts {
        targets: targets(&["north"]),
        ..SyncOpts::default()
    };
    let err = sync_with(&w, &both(&w), opts).0.unwrap_err();
    assert_eq!(err.code_str(), "unknown_target");
}

/// 01.04: a misspelt --target steps to the plan of the unique close target, every scope
/// flag kept and --deploy, --prune and --confirm dropped; never a write to a guessed target.
#[test]
fn a_misspelt_target_on_sync_steps_to_the_plan_of_the_close_one() {
    let w = world();
    let opts = SyncOpts {
        targets: targets(&["wes"]),
        ..SyncOpts::default()
    };
    let err = sync_with(&w, &both(&w), opts).0.unwrap_err();
    let (cause, _) = err.cause().expect("a cataloged cause");
    let argv: Vec<String> = "opv sync prod --target wes --deploy --prune --confirm prod"
        .split_whitespace()
        .map(str::to_string)
        .collect();
    let inv = crate::cause::Invocation::from_cli(&argv);
    assert_eq!(
        crate::cause::render::next_text(&cause.step(&inv).1, &inv),
        Some("opv plan prod --target west".into())
    );
}

/// 01.04, X2: with no close target the step is the listing, never the first target.
#[test]
fn an_unknown_target_with_no_close_one_steps_to_the_listing() {
    let w = world();
    let opts = SyncOpts {
        targets: targets(&["north"]),
        ..SyncOpts::default()
    };
    let err = sync_with(&w, &both(&w), opts).0.unwrap_err();
    let (cause, _) = err.cause().expect("a cataloged cause");
    let argv: Vec<String> = "opv sync prod --target north --deploy"
        .split_whitespace()
        .map(str::to_string)
        .collect();
    let inv = crate::cause::Invocation::from_cli(&argv);
    assert_eq!(
        crate::cause::render::next_text(&cause.step(&inv).1, &inv),
        Some("opv target list".into())
    );
}

#[test]
fn an_unknown_target_error_lists_the_environments_targets() {
    let w = world();
    let mut out = Vec::new();
    let err = sync::plan_targeted(
        &both(&w),
        "prod",
        &targets(&["north"]),
        None,
        &w,
        &mut out,
        false,
    )
    .unwrap_err();
    assert!(err.to_string().contains("(declared: east, west)"), "{err}");
}

#[test]
fn a_failing_target_stops_the_run_before_a_later_target_writes() {
    let w = world();
    *w.fail_import.borrow_mut() = Some("myapp-east".into());
    let _ = sync_with(&w, &both(&w), SyncOpts::default());
    assert!(w.names_on("myapp-west").is_empty());
}

#[test]
fn a_failing_later_target_names_the_targets_already_synced() {
    let w = world();
    *w.fail_import.borrow_mut() = Some("myapp-west".into());
    let err = sync_with(&w, &both(&w), SyncOpts::default()).0.unwrap_err();
    assert!(
        err.to_string().contains("already written: prod/east"),
        "{err}"
    );
}

#[test]
fn no_output_carries_a_value() {
    let w = world();
    let opts = SyncOpts {
        json: true,
        ..SyncOpts::default()
    };
    let (_, out) = sync_with(&w, &both(&w), opts);
    assert!(!out.contains(MARK), "{out}");
}

// --- approved sync (0.9.0): a person approves one sync plan, the assistant runs it once ---

use crate::app::approve::{self as approve_cmd, SyncScope};

const PROJECT: &str = "myapp";
const ACCOUNT: &str = "ACCOUNTAAA000000000000AAAA";

fn east_scope() -> SyncScope {
    SyncScope {
        env: "prod".into(),
        targets: targets(&["east"]),
        product: None,
        deploy: false,
        prune: false,
        rotate: Vec::new(),
    }
}

/// A person's `opv approve <id> --sync prod --target east` typed back, recorded in `dir`.
fn approve_in(dir: &std::path::Path, w: &World, fleet: &Fleet, scope: &SyncScope, id: &str) {
    struct Typed(String);
    impl approve_cmd::Review for Typed {
        fn show(&mut self, _: &str) -> Result<(), Error> {
            Ok(())
        }
        fn ask(&mut self, _: &str) -> Result<String, Error> {
            Ok(self.0.clone())
        }
    }
    approve_cmd::run_sync(
        w,
        fleet,
        PROJECT,
        ACCOUNT,
        scope,
        id,
        1_000,
        &mut Typed(id.to_string()),
        &mut |p, key, project, account, now| {
            crate::approval::record_scoped_in(&dir.join("approvals"), p, key, project, account, now)
        },
    )
    .unwrap();
}

/// The assistant's approved sync of `scope` with plan `id`, consuming from `dir`.
fn approved_sync(
    dir: &std::path::Path,
    w: &World,
    fleet: &Fleet,
    scope: &SyncScope,
    id: &str,
) -> Result<(), Error> {
    let _person = tidy::activate();
    approve_cmd::run_approved_sync(
        fleet,
        scope,
        id,
        PROJECT,
        ACCOUNT,
        1_010,
        w,
        &mut Vec::new(),
        true,
        None,
        &mut |p, key, project, account, now| {
            crate::approval::consume_scoped_in(
                &dir.join("approvals"),
                p,
                key,
                project,
                account,
                now,
            )
        },
    )
}

#[test]
fn an_approved_sync_writes_the_approved_target() {
    let (w, dir) = (world(), tempfile::tempdir().unwrap());
    let fleet = both(&w);
    let id = plan_id(&w, &fleet, &["east"]);
    approve_in(dir.path(), &w, &fleet, &east_scope(), &id);
    approved_sync(dir.path(), &w, &fleet, &east_scope(), &id).unwrap();
    assert_eq!(w.names_on("myapp-east"), [NAME]);
}

#[test]
fn an_approved_sync_never_writes_another_target() {
    let (w, dir) = (world(), tempfile::tempdir().unwrap());
    let fleet = both(&w);
    let id = plan_id(&w, &fleet, &["east"]);
    approve_in(dir.path(), &w, &fleet, &east_scope(), &id);
    approved_sync(dir.path(), &w, &fleet, &east_scope(), &id).unwrap();
    assert!(w.names_on("myapp-west").is_empty());
}

#[test]
fn a_sync_without_an_approval_writes_nothing() {
    let (w, dir) = (world(), tempfile::tempdir().unwrap());
    let fleet = both(&w);
    let id = plan_id(&w, &fleet, &["east"]);
    let _ = approved_sync(dir.path(), &w, &fleet, &east_scope(), &id);
    assert_eq!(w.imports.get(), 0);
}

#[test]
fn a_sync_without_an_approval_names_the_approve_command() {
    let (w, dir) = (world(), tempfile::tempdir().unwrap());
    let fleet = both(&w);
    let id = plan_id(&w, &fleet, &["east"]);
    let e = approved_sync(dir.path(), &w, &fleet, &east_scope(), &id).unwrap_err();
    assert_eq!(
        e.next_text().unwrap_or_default(),
        format!("opv approve {id} --sync prod --target east")
    );
}

#[test]
fn an_approval_is_used_once() {
    let (w, dir) = (world(), tempfile::tempdir().unwrap());
    let fleet = both(&w);
    let id = plan_id(&w, &fleet, &["east"]);
    approve_in(dir.path(), &w, &fleet, &east_scope(), &id);
    approved_sync(dir.path(), &w, &fleet, &east_scope(), &id).unwrap();
    // The plan after a sync is "nothing to do" with a new id; replay the old one.
    let again = approved_sync(dir.path(), &w, &fleet, &east_scope(), &id);
    assert!(again.is_err());
}

#[test]
fn an_approval_without_deploy_does_not_cover_a_deploying_sync() {
    let (w, dir) = (world(), tempfile::tempdir().unwrap());
    let fleet = both(&w);
    let id = plan_id(&w, &fleet, &["east"]);
    approve_in(dir.path(), &w, &fleet, &east_scope(), &id);
    let deploying = SyncScope {
        deploy: true,
        ..east_scope()
    };
    let e = approved_sync(dir.path(), &w, &fleet, &deploying, &id).unwrap_err();
    assert_eq!(e.code_str(), "approval_required");
}

#[test]
fn a_stale_plan_is_refused_before_the_approval_is_used() {
    let (w, dir) = (world(), tempfile::tempdir().unwrap());
    let fleet = both(&w);
    let id = plan_id(&w, &fleet, &["east"]);
    approve_in(dir.path(), &w, &fleet, &east_scope(), &id);
    // Someone declares and fills a second key meanwhile: the plan now writes two names.
    let item = w.op.item(&w.item_id);
    let mut fields = item["fields"].as_array().cloned().unwrap_or_default();
    fields.push(
        json!({"id": "api-OTHER", "section": {"id": "api", "label": "api"},
                       "type": "CONCEALED", "label": "OTHER", "value": "other"}),
    );
    for i in w.op.items.borrow_mut().iter_mut() {
        if i["id"] == w.item_id.as_str() {
            i["fields"] = json!(fields);
        }
    }
    let mut fleet = fleet;
    let other = fleet.products["api"].keys["TOKEN"].clone();
    fleet
        .products
        .get_mut("api")
        .unwrap()
        .keys
        .insert("OTHER".into(), other);
    let e = approved_sync(dir.path(), &w, &fleet, &east_scope(), &id).unwrap_err();
    assert_eq!(e.code_str(), "stale_plan");
}

#[test]
fn approving_a_sync_never_shows_a_value() {
    struct Seen(Vec<String>, String);
    impl approve_cmd::Review for Seen {
        fn show(&mut self, line: &str) -> Result<(), Error> {
            self.0.push(line.to_string());
            Ok(())
        }
        fn ask(&mut self, _: &str) -> Result<String, Error> {
            Ok(self.1.clone())
        }
    }
    let w = world();
    let fleet = both(&w);
    let id = plan_id(&w, &fleet, &["east"]);
    let mut ui = Seen(Vec::new(), id.clone());
    let _ = approve_cmd::run_sync(
        &w,
        &fleet,
        PROJECT,
        ACCOUNT,
        &east_scope(),
        &id,
        1_000,
        &mut ui,
        &mut |_, _, _, _, _| Ok(()),
    );
    assert!(!ui.0.join("\n").contains(MARK));
}

#[test]
fn approving_a_sync_lists_each_name_it_writes() {
    struct Seen(Vec<String>, String);
    impl approve_cmd::Review for Seen {
        fn show(&mut self, line: &str) -> Result<(), Error> {
            self.0.push(line.to_string());
            Ok(())
        }
        fn ask(&mut self, _: &str) -> Result<String, Error> {
            Ok(self.1.clone())
        }
    }
    let w = world();
    let fleet = both(&w);
    let id = plan_id(&w, &fleet, &["east"]);
    let mut ui = Seen(Vec::new(), id.clone());
    let _ = approve_cmd::run_sync(
        &w,
        &fleet,
        PROJECT,
        ACCOUNT,
        &east_scope(),
        &id,
        1_000,
        &mut ui,
        &mut |_, _, _, _, _| Ok(()),
    );
    assert!(
        ui.0.iter().any(|l| l.contains("write api/TOKEN on east")),
        "{:?}",
        ui.0
    );
}

// --- rotation (FR-16): plan --rotate and an approved sync --rotate ---

const LOCK: &str = "FLEET__API__LOCK";

/// Add an immutable `api/LOCK`, present on east, to the world's item and its Fly app.
fn world_with_lock() -> World {
    let w = world();
    {
        let mut items = w.op.items.borrow_mut();
        for i in items.iter_mut() {
            if i["id"] == w.item_id.as_str() {
                let mut fields = i["fields"].as_array().cloned().unwrap_or_default();
                fields.push(json!({
                    "id": "api-LOCK", "section": {"id": "api", "label": "api"},
                    "type": "CONCEALED", "label": "LOCK", "value": format!("lock-{MARK}")
                }));
                i["fields"] = json!(fields);
            }
        }
    }
    w.fly.borrow_mut().insert(
        "myapp-east".into(),
        BTreeMap::from([(LOCK.to_string(), (format!("lock-{MARK}"), false))]),
    );
    w
}

/// [`fleet_of`] with an immutable `api/LOCK`, so `--rotate api/LOCK` is valid.
fn fleet_with_lock(w: &World) -> Fleet {
    let mut fleet = fleet_of(w, &[("east", STATE_EAST)]);
    let mut lock = fleet.products["api"].keys["TOKEN"].clone();
    lock.immutable = true;
    fleet
        .products
        .get_mut("api")
        .unwrap()
        .keys
        .insert("LOCK".into(), lock);
    fleet
}

fn plan_doc_rotating(w: &World, fleet: &Fleet, only: &[&str], rotate: &[&str]) -> Value {
    let mut out = Vec::new();
    let rotate: Vec<String> = rotate.iter().map(|s| s.to_string()).collect();
    sync::plan_rotating(
        fleet,
        "prod",
        &targets(only),
        None,
        &rotate,
        w,
        &mut out,
        true,
    )
    .unwrap();
    serde_json::from_slice(&out).unwrap()
}

fn plan_id_rotating(w: &World, fleet: &Fleet, only: &[&str], rotate: &[&str]) -> String {
    plan_doc_rotating(w, fleet, only, rotate)["plan_id"]
        .as_str()
        .unwrap()
        .to_string()
}

fn lock_row(doc: &Value) -> &Value {
    doc["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["key"] == "LOCK")
        .unwrap()
}

#[test]
fn a_plan_with_rotate_marks_the_rotated_row() {
    let w = world_with_lock();
    let fleet = fleet_with_lock(&w);
    let doc = plan_doc_rotating(&w, &fleet, &["east"], &["api/LOCK"]);
    assert_eq!(lock_row(&doc)["rotate"], json!(true), "{doc}");
}

#[test]
fn a_plan_with_rotate_stages_the_rotated_row() {
    let w = world_with_lock();
    let fleet = fleet_with_lock(&w);
    let doc = plan_doc_rotating(&w, &fleet, &["east"], &["api/LOCK"]);
    assert_eq!(lock_row(&doc)["action"], json!("would_stage"), "{doc}");
}

#[test]
fn a_plan_with_rotate_has_a_different_id() {
    let w = world_with_lock();
    let fleet = fleet_with_lock(&w);
    let plain = plan_doc_rotating(&w, &fleet, &["east"], &[]);
    let rotated = plan_doc_rotating(&w, &fleet, &["east"], &["api/LOCK"]);
    assert_ne!(plain["plan_id"], rotated["plan_id"]);
}

#[test]
fn a_plan_with_rotate_names_the_row_rotate() {
    let w = world_with_lock();
    let fleet = fleet_with_lock(&w);
    let mut out = Vec::new();
    let rotate = vec!["api/LOCK".to_string()];
    sync::plan_rotating(
        &fleet,
        "prod",
        &targets(&["east"]),
        None,
        &rotate,
        &w,
        &mut out,
        false,
    )
    .unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.lines()
            .any(|l| l.contains("LOCK") && l.ends_with("rotate")),
        "{text}"
    );
}

#[test]
fn an_approval_without_rotation_does_not_cover_a_rotating_approved_sync() {
    let w = world_with_lock();
    let fleet = fleet_with_lock(&w);
    let dir = tempfile::tempdir().unwrap();
    let id = plan_id_rotating(&w, &fleet, &["east"], &["api/LOCK"]);
    // The same plan id, but an approval recorded for a scope without rotation.
    crate::approval::record_scoped_in(
        &dir.path().join("approvals"),
        &id,
        &east_scope().key(),
        PROJECT,
        ACCOUNT,
        1_000,
    )
    .unwrap();
    let rotating = SyncScope {
        rotate: vec!["api/LOCK".into()],
        ..east_scope()
    };
    let e = approved_sync(dir.path(), &w, &fleet, &rotating, &id).unwrap_err();
    assert_eq!(e.code_str(), "approval_required");
}

#[test]
fn an_approval_with_the_same_rotation_covers_a_rotating_approved_sync() {
    let w = world_with_lock();
    let fleet = fleet_with_lock(&w);
    let dir = tempfile::tempdir().unwrap();
    let rotating = SyncScope {
        rotate: vec!["api/LOCK".into()],
        ..east_scope()
    };
    let id = plan_id_rotating(&w, &fleet, &["east"], &["api/LOCK"]);
    crate::approval::record_scoped_in(
        &dir.path().join("approvals"),
        &id,
        &rotating.key(),
        PROJECT,
        ACCOUNT,
        1_000,
    )
    .unwrap();
    let res = approved_sync(dir.path(), &w, &fleet, &rotating, &id);
    assert!(res.is_ok(), "{res:?}");
}

#[test]
fn an_approved_rotating_sync_writes_the_rotated_key() {
    let w = world_with_lock();
    let fleet = fleet_with_lock(&w);
    let dir = tempfile::tempdir().unwrap();
    let rotating = SyncScope {
        rotate: vec!["api/LOCK".into()],
        ..east_scope()
    };
    let id = plan_id_rotating(&w, &fleet, &["east"], &["api/LOCK"]);
    approve_in(dir.path(), &w, &fleet, &rotating, &id);
    approved_sync(dir.path(), &w, &fleet, &rotating, &id).unwrap();
    assert_eq!(w.names_on("myapp-east"), [LOCK, NAME]);
}

#[test]
fn approving_a_rotation_lists_the_rotated_key() {
    struct Seen(Vec<String>, String);
    impl approve_cmd::Review for Seen {
        fn show(&mut self, line: &str) -> Result<(), Error> {
            self.0.push(line.to_string());
            Ok(())
        }
        fn ask(&mut self, _: &str) -> Result<String, Error> {
            Ok(self.1.clone())
        }
    }
    let w = world_with_lock();
    let fleet = fleet_with_lock(&w);
    let rotating = SyncScope {
        rotate: vec!["api/LOCK".into()],
        ..east_scope()
    };
    let id = plan_id_rotating(&w, &fleet, &["east"], &["api/LOCK"]);
    let mut ui = Seen(Vec::new(), id.clone());
    let _ = approve_cmd::run_sync(
        &w,
        &fleet,
        PROJECT,
        ACCOUNT,
        &rotating,
        &id,
        1_000,
        &mut ui,
        &mut |_, _, _, _, _| Ok(()),
    );
    assert!(
        ui.0.iter().any(|l| l == "  rotate api/LOCK on east"),
        "{:?}",
        ui.0
    );
}

// --- opv_sync (0.9.0): the MCP side of an approved sync ---

#[cfg(feature = "mcp")]
fn mcp_sync(w: &World, fleet: &Fleet, dir: &std::path::Path, id: &str) -> Value {
    let _person = tidy::activate();
    let args = crate::mcp::SyncScopeArgs {
        environment: "prod".into(),
        plan_id: id.into(),
        targets: targets(&["east"]),
        product: None,
        deploy: false,
        prune: false,
        rotate: Vec::new(),
        verbose: false,
    };
    crate::mcp::sync_approved(
        fleet,
        &args,
        PROJECT,
        ACCOUNT,
        w,
        1_010,
        std::iter::empty(),
        &mut |p, key, project, account, now| {
            crate::approval::consume_scoped_in(
                &dir.join("approvals"),
                p,
                key,
                project,
                account,
                now,
            )
        },
    )
}

#[cfg(feature = "mcp")]
#[test]
fn opv_sync_writes_an_approved_plan() {
    let (w, dir) = (world(), tempfile::tempdir().unwrap());
    let fleet = both(&w);
    let id = plan_id(&w, &fleet, &["east"]);
    approve_in(dir.path(), &w, &fleet, &east_scope(), &id);
    let answer = mcp_sync(&w, &fleet, dir.path(), &id);
    assert_eq!(answer["written"], json!([NAME]), "{answer}");
}

#[cfg(feature = "mcp")]
#[test]
fn opv_sync_runs_the_approved_rotation() {
    let w = world_with_lock();
    // The target holds an older value, so the rotation is a real write.
    w.fly
        .borrow_mut()
        .get_mut("myapp-east")
        .unwrap()
        .insert(LOCK.into(), ("lock-old".into(), false));
    let fleet = fleet_with_lock(&w);
    let dir = tempfile::tempdir().unwrap();
    let rotating = SyncScope {
        rotate: vec!["api/LOCK".into()],
        ..east_scope()
    };
    let id = plan_id_rotating(&w, &fleet, &["east"], &["api/LOCK"]);
    approve_in(dir.path(), &w, &fleet, &rotating, &id);
    let _person = tidy::activate();
    let args = crate::mcp::SyncScopeArgs {
        environment: "prod".into(),
        plan_id: id,
        targets: targets(&["east"]),
        product: None,
        deploy: false,
        prune: false,
        rotate: vec!["api/LOCK".into()],
        verbose: false,
    };
    let answer = crate::mcp::sync_approved(
        &fleet,
        &args,
        PROJECT,
        ACCOUNT,
        &w,
        1_010,
        std::iter::empty(),
        &mut |p, key, project, account, now| {
            crate::approval::consume_scoped_in(
                &dir.path().join("approvals"),
                p,
                key,
                project,
                account,
                now,
            )
        },
    );
    assert!(
        answer["written"]
            .as_array()
            .is_some_and(|a| a.contains(&json!(LOCK))),
        "{answer}"
    );
}

#[cfg(feature = "mcp")]
#[test]
fn opv_sync_never_returns_a_value() {
    let (w, dir) = (world(), tempfile::tempdir().unwrap());
    let fleet = both(&w);
    let id = plan_id(&w, &fleet, &["east"]);
    approve_in(dir.path(), &w, &fleet, &east_scope(), &id);
    assert!(
        !mcp_sync(&w, &fleet, dir.path(), &id)
            .to_string()
            .contains(MARK)
    );
}

#[cfg(feature = "mcp")]
#[test]
fn opv_sync_without_an_approval_returns_the_approve_command() {
    let (w, dir) = (world(), tempfile::tempdir().unwrap());
    let fleet = both(&w);
    let id = plan_id(&w, &fleet, &["east"]);
    assert_eq!(
        mcp_sync(&w, &fleet, dir.path(), &id)["error"]["next"],
        json!(format!("opv approve {id} --sync prod --target east"))
    );
}

#[cfg(feature = "mcp")]
#[test]
fn opv_sync_without_an_approval_writes_nothing() {
    let (w, dir) = (world(), tempfile::tempdir().unwrap());
    let fleet = both(&w);
    let id = plan_id(&w, &fleet, &["east"]);
    let _ = mcp_sync(&w, &fleet, dir.path(), &id);
    assert_eq!(w.imports.get(), 0);
}

#[cfg(feature = "mcp")]
#[test]
fn opv_sync_refuses_an_op_credential_in_its_environment() {
    let (w, dir) = (world(), tempfile::tempdir().unwrap());
    let fleet = both(&w);
    let id = plan_id(&w, &fleet, &["east"]);
    approve_in(dir.path(), &w, &fleet, &east_scope(), &id);
    let args = crate::mcp::SyncScopeArgs {
        environment: "prod".into(),
        plan_id: id,
        targets: targets(&["east"]),
        product: None,
        deploy: false,
        prune: false,
        rotate: Vec::new(),
        verbose: false,
    };
    let answer = crate::mcp::sync_approved(
        &fleet,
        &args,
        PROJECT,
        ACCOUNT,
        &w,
        1_010,
        std::iter::once(("OP_SERVICE_ACCOUNT_TOKEN".to_string(), "x".to_string())),
        &mut |_, _, _, _, _| Ok(()),
    );
    assert_eq!(answer["error"]["code"], "own_session_required");
}

#[cfg(feature = "mcp")]
#[test]
fn opv_sync_refuses_a_plan_id_that_is_not_one() {
    let (w, dir) = (world(), tempfile::tempdir().unwrap());
    let fleet = both(&w);
    assert_eq!(
        mcp_sync(&w, &fleet, dir.path(), "../../etc")["error"]["code"],
        "usage"
    );
}
