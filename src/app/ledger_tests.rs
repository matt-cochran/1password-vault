//! The version ledger end to end (FR-54): a person's sync records what it wrote; a later plan
//! judges those names exactly; a service account never records.

use crate::adapters::fake_op::FakeOp;
use crate::domain::ledger::{Ledger, STATE_SECTION};
use crate::domain::plan::{StoreEntry, TargetState};
use crate::domain::{Fleet, SecretValue};

const NAME: &str = "FLEET__API__TOKEN";

fn world() -> (FakeOp, Fleet) {
    let op = FakeOp::default();
    let id = op.insert(
        "vdev0000000000000000000001",
        serde_json::json!({
            "title": "t", "category": "SECURE_NOTE",
            "sections": [{"id": "api", "label": "api"}],
            "fields": [{"id": "f1", "section": {"id": "api", "label": "api"}, "type": "CONCEALED", "label": "TOKEN", "value": "tok-FIXTUREVALUE-1"}]
        }),
    );
    let fleet = crate::config::parse(&format!(
        "[profile]\nkind = \"fleet\"\n[environments.dev]\nvault_id = \"vdev0000000000000000000001\"\n\
         item_id = \"{id}\"\nfly.app = \"a\"\nfly.secret_name = \"FLEET__{{PRODUCT}}__{{KEY}}\"\n\
         [products.api.keys.TOKEN]\nkind = \"secret\"\nenvironments = [\"dev\"]\n"
    ))
    .unwrap();
    (op, fleet)
}

fn listed(version: &str) -> Vec<StoreEntry> {
    vec![StoreEntry {
        name: NAME.into(),
        version: Some(version.into()),
        pending: false,
        stamp: None,
    }]
}

fn record(op: &FakeOp, fleet: &Fleet, value: &str, version: &str) {
    let v = SecretValue::new(value.into());
    super::sync::record_ledger(
        fleet,
        "dev",
        &[(NAME.to_string(), &v)],
        &listed(version),
        op,
    );
}

fn ledger_of(op: &FakeOp, fleet: &Fleet) -> Ledger {
    let item = op.item(&fleet.environments["dev"].item_id);
    let raw = serde_json::to_vec(&item).unwrap();
    let (layout, _) = crate::adapters::onepassword_tidy::parse(&raw).unwrap();
    Ledger::from_layout(&layout)
}

#[test]
fn a_persons_sync_records_the_written_name() {
    let _on = crate::app::tidy::activate();
    let (op, fleet) = world();
    record(&op, &fleet, "tok-FIXTUREVALUE-1", "d1");
    let v = SecretValue::new("tok-FIXTUREVALUE-1".into());
    assert_eq!(
        ledger_of(&op, &fleet).check(NAME, "d1", &v),
        Some(crate::domain::plan::CurrentState::Same)
    );
}

#[test]
fn the_ledger_holds_no_value() {
    let _on = crate::app::tidy::activate();
    let (op, fleet) = world();
    record(&op, &fleet, "tok-FIXTUREVALUE-1", "d1");
    let item = op.item(&fleet.environments["dev"].item_id);
    let state: Vec<&serde_json::Value> = item["fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["section"]["label"] == STATE_SECTION)
        .collect();
    assert!(!state.iter().any(|f| f.to_string().contains("FIXTUREVALUE")));
}

#[test]
fn a_service_account_never_records() {
    let _on = crate::app::tidy::activate();
    let (op, fleet) = world();
    crate::host::with_test_host(
        crate::host::Host::from_env(
            &crate::host::FakeEnv::new("linux").var("OP_SERVICE_ACCOUNT_TOKEN"),
        ),
        || record(&op, &fleet, "tok-FIXTUREVALUE-1", "d1"),
    );
    assert!(
        op.calls
            .borrow()
            .iter()
            .all(|c| c.args.first().map(String::as_str) != Some("item")
                || c.args.get(1).map(String::as_str) != Some("edit"))
    );
}

fn planned_target(op: &FakeOp, fleet: &Fleet, version: &str) -> TargetState {
    let read = crate::app::tidy::read(fleet, "dev", op).unwrap();
    let none = std::collections::BTreeSet::new();
    let p = crate::domain::plan::build_with(
        fleet,
        "dev",
        read.fields,
        &listed(version),
        &crate::domain::plan::PlanOptions {
            rotate: &none,
            prune_immutable: &none,
            digest: &|_| None,
            target_check: &|_, _| None,
            current: Some(&|n: &str, v: &SecretValue| read.ledger.check(n, version, v)),
        },
    );
    p.rows[0].target
}

#[test]
fn a_recorded_name_at_the_same_version_is_exactly_same() {
    let _on = crate::app::tidy::activate();
    let (op, fleet) = world();
    record(&op, &fleet, "tok-FIXTUREVALUE-1", "d1");
    assert_eq!(planned_target(&op, &fleet, "d1"), TargetState::Present);
}

#[test]
fn a_changed_value_at_the_same_version_exactly_would_change() {
    let _on = crate::app::tidy::activate();
    let (op, fleet) = world();
    record(&op, &fleet, "tok-FIXTUREVALUE-0", "d1");
    assert_eq!(planned_target(&op, &fleet, "d1"), TargetState::WouldChange);
}

#[test]
fn another_version_stays_unknown() {
    let _on = crate::app::tidy::activate();
    let (op, fleet) = world();
    record(&op, &fleet, "tok-FIXTUREVALUE-1", "d1");
    assert_eq!(planned_target(&op, &fleet, "d2"), TargetState::Unknown);
}
