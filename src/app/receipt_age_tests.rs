//! Receipt staleness and age: one behavioural outcome per test (design row `receipts`).

use super::*;

/// A receipt that saw `items` at `revision`, built without a full readiness run.
fn saved(items: &[(&str, u64)], revision: Option<&str>) -> Receipt {
    let mut receipt = Receipt::default();
    receipt.item_versions = items
        .iter()
        .map(|(id, v)| ((*id).to_string(), *v))
        .collect();
    receipt.revision = revision.map(str::to_string);
    receipt
}

#[test]
fn a_receipt_whose_item_versions_are_unchanged_is_fresh() {
    let receipt = saved(&[("item1", 3)], Some("abc123"));
    let current = BTreeMap::from([("item1".to_string(), 3)]);
    assert_eq!(staleness(&receipt, &current), Staleness::Fresh);
}

#[test]
fn a_receipt_whose_item_version_moved_is_stale_naming_the_item() {
    let receipt = saved(&[("item1", 3)], Some("abc123"));
    let current = BTreeMap::from([("item1".to_string(), 4)]);
    assert_eq!(
        staleness(&receipt, &current),
        Staleness::Stale {
            items: vec!["item1".into()]
        }
    );
}

#[test]
fn a_receipt_without_a_revision_is_reported_as_missing_revision() {
    let receipt = saved(&[("item1", 3)], None);
    assert!(age(&receipt, "2026-01-02T03:04:05Z").missing_revision());
}

#[test]
fn the_saved_receipt_carries_the_generated_at_clock() {
    use crate::adapters::fake_op::FakeOp;
    let op = FakeOp::default();
    let item = serde_json::json!({
        "title": "t",
        "category": "SECURE_NOTE",
        "sections": [{"id": "app", "label": "app"}],
        "fields": [{"id": "f1", "type": "CONCEALED", "section": {"id": "app", "label": "app"},
                    "label": "DATABASE_URL", "value": "value-not-in-the-receipt"}]
    });
    let id = op.insert("vdev0000000000000000000001", item);
    let fleet = crate::config::parse(&format!(
        "[environments.dev]\n\
         boundaries.app = {{ vault_id = \"vdev0000000000000000000001\", item_id = \"{id}\" }}\n\
         [products.app.keys.DATABASE_URL]\nkind = \"secret\"\nenvironments = [\"dev\"]\n"
    ))
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("receipt.json");
    let mut out = Vec::new();
    crate::app::ready::run_at(
        &fleet,
        None,
        Some("dev"),
        &op,
        true,
        Some(&path),
        false,
        "2026-01-02T03:04:05Z",
        &mut out,
    )
    .unwrap();
    let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(saved["generated_at"], "2026-01-02T03:04:05Z");
}
