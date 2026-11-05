//! A whole-set store (design `sealed-target` §5.3, FMECA T3, T4; lane st-c1): `sync`
//! rewrites the complete set whenever a member is staged, pruned or mismatched, before the
//! plan id is computed, and never removes a name; `--sealed-root` (D12) moves where a
//! sealed target writes its bundle.
//!
//! The store is an in-memory fake that returns `whole_set() == true` and, like a sealed
//! bundle, gives every name a new version on each write. 1Password is [`FakeOp`], so the
//! delivery evidence (the version ledger) is real and a second sync sees `present` rows.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::rc::Rc;
use std::time::Duration;

use super::*;
use crate::adapters::fake_op::FakeOp;
use crate::app::testutil::{fly_app_ok, fly_releases};
use crate::ports::Store;
use crate::runner::{Outcome, Output};

const VALUES: &str = "vdev0000000000000000000001";
const STATE: &str = "vshr0000000000000000000002";
const A: &str = "FLEET__API__A_KEY";
const B: &str = "FLEET__API__B_KEY";
const OLD: &str = "FLEET__API__OLD_KEY";

/// 1Password through [`FakeOp`]; `flyctl` (the target's preflight) answers healthy.
struct World {
    op: FakeOp,
    values_id: String,
}

impl World {
    fn answer(&self, call: &Call<'_>) -> Option<Output> {
        if call.program == "op" || call.program == "git" {
            return None;
        }
        Some(match call.args {
            ["releases", ..] => fly_releases("complete"),
            _ => fly_app_ok(),
        })
    }

    /// The reads of the values item this run made (FR-13: one per scope).
    fn values_reads(&self) -> usize {
        self.op
            .calls
            .borrow()
            .iter()
            .filter(|c| c.program == "op" && c.args.contains(&self.values_id))
            .filter(|c| c.args.iter().any(|a| a == "get"))
            .count()
    }
}

impl CommandRunner for World {
    fn read(&self, call: &Call<'_>, refused: &[i32]) -> io::Result<Outcome> {
        match self.answer(call) {
            Some(o) => Ok(Outcome::Done(o)),
            None => self.op.read(call, refused),
        }
    }
    fn write(&self, call: &Call<'_>) -> io::Result<Outcome> {
        match self.answer(call) {
            Some(o) => Ok(Outcome::Done(o)),
            None => self.op.write(call),
        }
    }
    fn probe(&self, call: &Call<'_>, limit: Duration) -> io::Result<Output> {
        match self.answer(call) {
            Some(o) => Ok(o),
            None => self.op.probe(call, limit),
        }
    }
    fn pause(&self, _: Duration, _: &str) {}
    fn note(&self, _: &str) {}
    fn run_inherited(&self, _: &str, _: &[&str], _: &[(&str, &str)]) -> io::Result<i32> {
        unreachable!("sync never runs a child")
    }
}

/// What the fake whole-set store holds and what was asked of it.
#[derive(Default)]
struct Held {
    /// name → version, as listed.
    listed: BTreeMap<String, String>,
    revision: u32,
    /// The names of each write, in order.
    writes: Vec<BTreeSet<String>>,
    removes: usize,
}

#[derive(Clone, Default)]
struct WholeStore(Rc<RefCell<Held>>);

impl Store for WholeStore {
    fn list(&self) -> Result<Vec<StoreEntry>, Error> {
        Ok(self
            .0
            .borrow()
            .listed
            .iter()
            .map(|(n, v)| StoreEntry {
                name: n.clone(),
                version: Some(v.clone()),
                pending: false,
                stamp: None,
            })
            .collect())
    }
    fn refusal(&self, _: &str, _: &SecretValue) -> Option<(&'static str, &'static str)> {
        None
    }
}

impl StagedStore for WholeStore {
    fn validate(&self, _: &[(String, &SecretValue)]) -> Result<(), Error> {
        Ok(())
    }
    /// Like a sealed bundle: the batch replaces the set, every name at a new version.
    fn write(&self, batch: &[(String, &SecretValue)]) -> Result<(), Error> {
        let mut h = self.0.borrow_mut();
        h.revision += 1;
        let v = format!("r{}", h.revision);
        h.listed = batch.iter().map(|(n, _)| (n.clone(), v.clone())).collect();
        h.writes
            .push(batch.iter().map(|(n, _)| n.clone()).collect());
        Ok(())
    }
    fn remove(&self, _: &[String]) -> Result<(), Error> {
        self.0.borrow_mut().removes += 1;
        Ok(())
    }
    fn variables(&self) -> Option<&dyn crate::ports::VariableStore> {
        None
    }
    fn whole_set(&self) -> bool {
        true
    }
}

struct Live;

impl StagedRuntime for Live {
    fn deploy(&self) -> Result<(), Error> {
        unreachable!("a live runtime is never deployed")
    }
    fn live(&self) -> bool {
        true
    }
}

/// dev on target `app` (state vault and api's delivery item as `opv bootstrap` leaves
/// them), api/A_KEY and api/B_KEY desired in dev, api/OLD_KEY in staging only.
fn world() -> (World, Fleet) {
    let op = FakeOp::default();
    let field = |id: &str, label: &str, value: &str| serde_json::json!({"id": id, "section": {"id": "api", "label": "api"}, "type": "CONCEALED", "label": label, "value": value});
    let values_id = op.insert(
        VALUES,
        serde_json::json!({
            "title": "t", "category": "SECURE_NOTE",
            "sections": [{"id": "api", "label": "api"}],
            "fields": [
                field("f1", "A_KEY", "tok-FIXTUREVALUE-a"),
                field("f2", "B_KEY", "tok-FIXTUREVALUE-b"),
            ]
        }),
    );
    let state = op.insert(
        STATE,
        serde_json::json!({"title": "opv · delivery · api · app", "category": "SECURE_NOTE", "fields": []}),
    );
    let fleet = crate::config::parse(&format!(
        "[environments.dev]\n\
         boundaries.api = {{ vault_id = \"{VALUES}\", item_id = \"{values_id}\" }}\n\
         [environments.dev.targets.app]\nfly.app = \"a\"\nfly.secret_name = \"FLEET__{{PRODUCT}}__{{KEY}}\"\n\
         state_vault_id = \"{STATE}\"\ndelivery_items = {{ api = \"{state}\" }}\n\
         [environments.staging]\nboundaries.api = {{ vault_id = \"{VALUES}\", item_id = \"{values_id}\" }}\n\
         [products.api.keys.A_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\n\
         [products.api.keys.B_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\n\
         [products.api.keys.OLD_KEY]\nkind = \"secret\"\nenvironments = [\"staging\"]\n"
    ))
    .unwrap();
    (World { op, values_id }, fleet)
}

/// One target's run against `store`: `(plan id, report)`; `apply == false` stops after the
/// read-only plan.
fn run_on(
    w: &World,
    fleet: &Fleet,
    store: &WholeStore,
    opts: &SyncOpts,
    apply_it: bool,
) -> (String, Option<Report>) {
    let t = fleet.environments["dev"].targets["app"].config.as_ref();
    let ports = Ports::Staged {
        store: Box::new(store.clone()),
        runtime: Box::new(Live),
    };
    let none = BTreeSet::new();
    let receipts = RefCell::new(Vec::new());
    let c = Ctx {
        fleet,
        env_name: "dev",
        target: "app",
        t,
        r: w,
        opts,
        rotate: &none,
        prune_immutable: &none,
        scope: None,
        names: KeyNames::new(fleet, "dev", "app").unwrap(),
        confirm_missing: false,
        receipts: &receipts,
        supply: None,
    };
    let mut out = Vec::new();
    let planned = prepare(&c, &ports, &mut out).unwrap();
    let id = planned.id.clone();
    if !apply_it {
        return (id, None);
    }
    let report = apply(&c, &ports, planned.prepared, &id, &mut out).unwrap();
    (id, Some(report))
}

fn set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|n| n.to_string()).collect()
}

/// A first sync of A and B, recorded; the store then lists both, `present` to the ledger.
fn synced() -> (World, Fleet, WholeStore) {
    let (w, fleet) = world();
    let store = WholeStore::default();
    run_on(&w, &fleet, &store, &SyncOpts::default(), true);
    (w, fleet, store)
}

/// The store also lists the retired api/OLD_KEY, at the current revision.
fn with_retired(store: &WholeStore) {
    let mut h = store.0.borrow_mut();
    let v = format!("r{}", h.revision);
    h.listed.insert(OLD.into(), v);
}

#[test]
fn a_second_sync_with_nothing_changed_writes_nothing() {
    let (w, fleet, store) = synced();
    run_on(&w, &fleet, &store, &SyncOpts::default(), true);
    assert_eq!(store.0.borrow().writes.len(), 1);
}

#[test]
fn retiring_one_name_rewrites_the_whole_set_without_it() {
    let (w, fleet, store) = synced();
    with_retired(&store);
    run_on(&w, &fleet, &store, &SyncOpts::default(), true);
    assert_eq!(store.0.borrow().writes.last(), Some(&set(&[A, B])));
}

#[test]
fn a_mismatch_of_one_member_rewrites_every_member() {
    let (w, fleet, store) = synced();
    store
        .0
        .borrow_mut()
        .listed
        .insert(A.into(), "replaced-elsewhere".into());
    run_on(&w, &fleet, &store, &SyncOpts::default(), true);
    assert_eq!(store.0.borrow().writes.last(), Some(&set(&[A, B])));
}

#[test]
fn the_plan_id_is_the_same_across_two_runs_over_the_same_state() {
    let (w, fleet, store) = synced();
    with_retired(&store);
    let first = run_on(&w, &fleet, &store, &SyncOpts::default(), false).0;
    let second = run_on(&w, &fleet, &store, &SyncOpts::default(), false).0;
    assert_eq!(first, second);
}

#[test]
fn the_plan_id_covers_the_whole_set_a_prune_rewrites() {
    let (w, fleet, store) = synced();
    let unchanged = run_on(&w, &fleet, &store, &SyncOpts::default(), false).0;
    with_retired(&store);
    let prune = SyncOpts {
        prune: true,
        ..SyncOpts::default()
    };
    let resealed = run_on(&w, &fleet, &store, &prune, false).0;
    assert_ne!(unchanged, resealed);
}

#[test]
fn opv_plan_derives_the_id_sync_derives_on_a_whole_set_store() {
    let (w, fleet, store) = synced();
    with_retired(&store);
    let sync_id = run_on(&w, &fleet, &store, &SyncOpts::default(), false).0;
    let ports = Ports::Staged {
        store: Box::new(store.clone()),
        runtime: Box::new(Live),
    };
    let plan_id = plan_part_on(&fleet, &w, &ports);
    assert_eq!(plan_id, sync_id);
}

/// `opv plan`'s id for target `app` through `ports`.
fn plan_part_on(fleet: &Fleet, w: &World, ports: &Ports<'_>) -> String {
    let none = BTreeSet::new();
    plan_part_with(fleet, "dev", "app", None, &none, w, ports)
        .unwrap()
        .id
}

#[test]
fn remove_is_never_called_on_a_whole_set_store() {
    let (w, fleet, store) = synced();
    with_retired(&store);
    let prune = SyncOpts {
        prune: true,
        ..SyncOpts::default()
    };
    run_on(&w, &fleet, &store, &prune, true);
    assert_eq!(store.0.borrow().removes, 0);
}

/// The plan of a re-seal, whole set included, reads the values item once (FR-13). The
/// delivery record after the write re-reads it for its source versions, as on any target.
#[test]
fn a_whole_set_replan_reads_1password_values_once() {
    let (w, fleet, store) = synced();
    with_retired(&store);
    w.op.calls.borrow_mut().clear();
    run_on(&w, &fleet, &store, &SyncOpts::default(), false);
    assert_eq!(w.values_reads(), 1);
}

#[test]
fn the_retired_name_is_reported_pruned() {
    let (w, fleet, store) = synced();
    with_retired(&store);
    let report = run_on(&w, &fleet, &store, &SyncOpts::default(), true)
        .1
        .unwrap();
    assert_eq!(report.pruned, vec![OLD.to_string()]);
}

// --- --sealed-root (D12) -------------------------------------------------------------------

const RECIPIENT: &str = "age13ts5aywwye8k4qr653hu89n89lt2eexd7szjadl9u3m47fzneggstxdxvs";
const SIGNER: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGNsg+yKsUThHH7nZ6IW5uovkXhn/YPafac8XHSwvmSJ opv-sealed-1";

fn sealed_fleet() -> Fleet {
    crate::config::parse(&format!(
        r#"
[environments.prod]
boundaries.api = {{ vault_id = "{VALUES}", item_id = "i1" }}

[environments.prod.targets.box]
state_vault_id = "sprod"
deploy_credentials = "op://Ops Prod/opv-sealed-prod-signer"
sealed.out = "sealed/prod/{{product}}.opv-sealed"
sealed.env_name = "{{KEY}}"
sealed.recipients = ["{RECIPIENT}"]
sealed.signer = "{SIGNER}"

[products.api.keys.TOKEN]
kind = "secret"
environments = ["prod"]
"#
    ))
    .unwrap()
}

fn written_path(fleet: &Fleet) -> std::path::PathBuf {
    fleet.environments["prod"].targets["box"]
        .config
        .as_any()
        .downcast_ref::<crate::adapters::sealed::config::SealedTarget>()
        .unwrap()
        .written_path("api")
}

#[test]
fn sealed_root_moves_the_written_bundle_under_the_root() {
    let rooted = with_out_root(&sealed_fleet(), std::path::Path::new("/checkout/store"));
    assert_eq!(
        written_path(&rooted),
        std::path::PathBuf::from("/checkout/store/sealed/prod/api.opv-sealed")
    );
}
