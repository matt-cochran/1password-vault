//! The version ledger end to end (FR-54, FR-58, D11): after a confirmed write the deliverer
//! records the name's evidence line in the placement's delivery item; a later plan judges
//! that name exactly from those lines. There is no second store: nothing reads or writes a
//! section of the values item.

use std::collections::BTreeSet;

use crate::adapters::fake_op::FakeOp;
use crate::domain::plan::{StoreEntry, TargetState};
use crate::domain::{Fleet, SecretValue};

const NAME: &str = "FLEET__API__TOKEN";
const VALUES: &str = "vdev0000000000000000000001";
const STATE: &str = "vshr0000000000000000000002";

/// dev on Fly app `a`, api/TOKEN in the values item, and api's delivery item on target
/// `app` recorded in the state vault (as `opv bootstrap` leaves it). Returns the values
/// item's ID too.
fn world() -> (FakeOp, Fleet, String) {
    let op = FakeOp::default();
    let id = op.insert(
        VALUES,
        serde_json::json!({
            "title": "t", "category": "SECURE_NOTE",
            "sections": [{"id": "api", "label": "api"}],
            "fields": [{"id": "f1", "section": {"id": "api", "label": "api"}, "type": "CONCEALED", "label": "TOKEN", "value": "tok-FIXTUREVALUE-1"}]
        }),
    );
    let state = op.insert(
        STATE,
        serde_json::json!({"title": "opv · delivery · api · app", "category": "SECURE_NOTE", "fields": []}),
    );
    let fleet = crate::config::parse(&format!(
        "[environments.dev]\n\
         boundaries.api = {{ vault_id = \"{VALUES}\", item_id = \"{id}\" }}\n\
         [environments.dev.targets.app]\nfly.app = \"a\"\nfly.secret_name = \"FLEET__{{PRODUCT}}__{{KEY}}\"\n\
         state_vault_id = \"{STATE}\"\ndelivery_items = {{ api = \"{state}\" }}\n\
         [products.api.keys.TOKEN]\nkind = \"secret\"\nenvironments = [\"dev\"]\n"
    ))
    .unwrap();
    (op, fleet, id)
}

fn listed(version: &str) -> Vec<StoreEntry> {
    vec![StoreEntry {
        name: NAME.into(),
        version: Some(version.into()),
        pending: false,
        stamp: None,
    }]
}

/// A sync wrote NAME, and the store now lists it at `version`.
fn record(op: &FakeOp, fleet: &Fleet, version: &str) {
    let written = BTreeSet::from([NAME.to_string()]);
    super::delivery::record(
        fleet,
        "dev",
        "app",
        None,
        &written,
        &BTreeSet::new(),
        &listed(version),
        "plan",
        op,
    )
    .unwrap();
}

/// Someone changes api/TOKEN in 1Password after the sync.
fn change_value(op: &FakeOp, id: &str) {
    let mut items = op.items.borrow_mut();
    let item = items.iter_mut().find(|i| i["id"] == id).unwrap();
    item["fields"][0]["value"] = serde_json::json!("tok-FIXTUREVALUE-2");
    op.cache.borrow_mut().remove(id);
}

/// What the plan of target `app` says of NAME when the store lists it at `version`.
fn planned_target(op: &FakeOp, fleet: &Fleet, version: &str) -> TargetState {
    let read = crate::app::tidy::read(fleet, "dev", op).unwrap();
    let ledgers = super::delivery::ledgers(fleet, "dev", "app", op);
    let none = BTreeSet::new();
    let p = crate::domain::plan::build_with(
        fleet,
        "dev",
        read.fields,
        &listed(version),
        &crate::domain::plan::PlanOptions {
            target: Some("app"),
            rotate: &none,
            prune_immutable: &none,
            digest: &|_| None,
            target_check: &|_, _| None,
            current: Some(&|n: &str, v: &SecretValue| {
                ledgers.iter().find_map(|l| l.check(n, version, v))
            }),
        },
    );
    p.rows[0].target
}

#[test]
fn a_recorded_name_at_the_same_version_is_exactly_same() {
    let (op, fleet, _) = world();
    record(&op, &fleet, "d1");
    assert_eq!(planned_target(&op, &fleet, "d1"), TargetState::Present);
}

#[test]
fn a_changed_value_at_the_same_version_exactly_would_change() {
    let (op, fleet, id) = world();
    record(&op, &fleet, "d1");
    change_value(&op, &id);
    assert_eq!(planned_target(&op, &fleet, "d1"), TargetState::WouldChange);
}

#[test]
fn another_version_stays_unknown() {
    let (op, fleet, _) = world();
    record(&op, &fleet, "d1");
    assert_eq!(planned_target(&op, &fleet, "d2"), TargetState::Unknown);
}

#[test]
fn a_service_account_records_evidence_too() {
    let (op, fleet, _) = world();
    crate::host::with_test_host(
        crate::host::Host::from_env(
            &crate::host::FakeEnv::new("linux").var("OP_SERVICE_ACCOUNT_TOKEN"),
        ),
        || record(&op, &fleet, "d1"),
    );
    assert_eq!(planned_target(&op, &fleet, "d1"), TargetState::Present);
}

#[test]
fn the_evidence_holds_no_value() {
    let (op, fleet, _) = world();
    record(&op, &fleet, "d1");
    let state = op.item(&fleet.environments["dev"].targets["app"].delivery_items["api"]);
    assert!(!state.to_string().contains("FIXTUREVALUE"), "{state}");
}

#[test]
fn a_sync_leaves_the_values_item_unchanged() {
    let (op, fleet, id) = world();
    let before = op.item(&id);
    record(&op, &fleet, "d1");
    assert_eq!(op.item(&id), before);
}

#[test]
fn no_values_item_section_is_read_as_a_ledger() {
    let (op, fleet, id) = world();
    {
        // A section left by an older opv: no longer special, so it is never a ledger.
        let mut items = op.items.borrow_mut();
        let item = items.iter_mut().find(|i| i["id"] == id).unwrap();
        item["sections"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"id": "state", "label": "opv · state"}));
        let fp = crate::domain::ledger::hmac_hex(b"k", b"tok-FIXTUREVALUE-1");
        let fields = item["fields"].as_array_mut().unwrap();
        fields.push(serde_json::json!({"id": "s0", "section": {"id": "state", "label": "opv · state"}, "type": "CONCEALED", "label": "ledger key", "value": "k"}));
        fields.push(serde_json::json!({"id": "s1", "section": {"id": "state", "label": "opv · state"}, "type": "STRING", "label": NAME, "value": format!("v1:d1:{fp}")}));
    }
    let mut fleet = fleet;
    fleet
        .environments
        .get_mut("dev")
        .unwrap()
        .targets
        .get_mut("app")
        .unwrap()
        .delivery_items
        .clear();
    assert_eq!(planned_target(&op, &fleet, "d1"), TargetState::Unknown);
}
