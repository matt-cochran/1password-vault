//! `opv propose structure|generate|rebind` (design Part V, row `propose-structure`): one
//! atomic test per behaviour, each with exactly one assertion on a public outcome.
//!
//! Every reply comes from the shared fake `op` (`FakeOp`) and the fixtures copied from
//! `src/app/structure_tests.rs`; no tool output is invented.

use std::path::PathBuf;

use super::*;
use crate::adapters::fake_op::FakeOp;
use crate::config::bindings::write_split;

const ACCOUNT: &str = "ACCOUNTAAA000000000000AAAA";

/// Two products in dev, staging and prod; `core` is recorded in dev only, so staging and
/// prod must create its vault and item. Copied from `src/app/structure_tests.rs`.
const FLEET: &str = r#"[environments.dev]
boundaries.core = { vault_id = "vdev0000000000000000000001", item_id = "ITEM" }

[environments.staging]

[environments.prod]

[products.web]
boundary = "core"

[products.web.keys.SESSION_KEY]
kind = "secret"
environments = ["dev", "staging", "prod"]

[products.api]
boundary = "core"

[products.api.keys.DATABASE_URL]
kind = "secret"
environments = ["dev", "staging", "prod"]
"#;

/// One settled boundary and one present, rule-backed key: nothing is left to plan.
const CLEAN: &str = r#"[environments.dev]
boundaries.app = { vault_id = "vdev0000000000000000000001", item_id = "ITEM" }

[products.app]
boundary = "app"

[products.app.keys.API_KEY]
kind = "secret"
environments = ["dev"]
rules = { base64_bytes = 32 }
"#;

/// A contract that still carries its ids inline, with `ITEM` as the item-id placeholder.
const INLINE: &str = r#"[environments.dev]
boundaries.app = { vault_id = "vdev0000000000000000000001", item_id = "ITEM" }

[products.app]
boundary = "app"

[products.app.keys.API_KEY]
kind = "secret"
environments = ["dev"]
"#;

fn item(boundary: &str, label: &str) -> serde_json::Value {
    serde_json::json!({
        "title": "myapp · {boundary} · dev values",
        "category": "SECURE_NOTE",
        "sections": [{"id": boundary, "label": boundary}],
        "fields": [{"id": "f1", "label": label, "type": "CONCEALED",
                    "section": {"id": boundary, "label": boundary}, "value": "set"}],
    })
}

/// A checkout holding [`FLEET`], its bindings written out, and a dev item.
fn fleet_world() -> (tempfile::TempDir, PathBuf, FakeOp) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.toml");
    let op = FakeOp::default();
    let id = op.insert("vdev0000000000000000000001", item("core", "SESSION_KEY"));
    write_split(&path, &FLEET.replace("ITEM", &id)).unwrap();
    (dir, path, op)
}

/// A checkout holding [`CLEAN`], its bindings written out, and the settled dev item.
fn clean_world() -> (tempfile::TempDir, PathBuf, FakeOp) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.toml");
    let op = FakeOp::default();
    let id = op.insert("vdev0000000000000000000001", item("app", "API_KEY"));
    write_split(&path, &CLEAN.replace("ITEM", &id)).unwrap();
    (dir, path, op)
}

/// A checkout holding [`INLINE`] verbatim: the ids are still in the contract.
fn inline_world() -> (tempfile::TempDir, PathBuf, FakeOp) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.toml");
    let op = FakeOp::default();
    let id = op.insert("vdev0000000000000000000001", item("app", "API_KEY"));
    std::fs::write(&path, INLINE.replace("ITEM", &id)).unwrap();
    (dir, path, op)
}

// The one-time move (D-G) ------------------------------------------------------------------

#[test]
fn inline_ids_yield_a_move_step() {
    let (_d, path, op) = inline_world();
    let p = propose_structure(&op, &path, "myapp", ACCOUNT, &[], &[]).unwrap();
    assert!(p.steps.iter().any(|s| matches!(s, Step::MoveIds { .. })));
}

#[test]
fn the_moved_contract_carries_no_vault_id() {
    let (_d, path, op) = inline_world();
    let p = propose_structure(&op, &path, "myapp", ACCOUNT, &[], &[]).unwrap();
    assert!(!p.contract_after.unwrap().contains("vault_id"));
}

#[test]
fn the_new_bindings_hold_the_moved_id() {
    let (_d, path, op) = inline_world();
    let p = propose_structure(&op, &path, "myapp", ACCOUNT, &[], &[]).unwrap();
    assert!(
        p.bindings_after
            .unwrap()
            .contains("environments.dev.boundaries.app.vault_id")
    );
}

// The structure the contract declares ------------------------------------------------------

#[test]
fn a_missing_boundary_item_is_a_structure_step() {
    let (_d, path, op) = fleet_world();
    let p = propose_structure(&op, &path, "myapp", ACCOUNT, &[], &[]).unwrap();
    assert!(p.steps.iter().any(|s| matches!(
        s,
        Step::CreateBoundary { environment, boundary, .. }
            if environment == "staging" && boundary == "core"
    )));
}

#[test]
fn rebind_drops_the_environments_boundary_ids() {
    let (_d, path, op) = clean_world();
    let p = propose_structure(&op, &path, "myapp", ACCOUNT, &["dev".to_string()], &[]).unwrap();
    assert!(
        !p.bindings_after
            .unwrap()
            .contains("environments.dev.boundaries.")
    );
}

#[test]
fn generate_lists_the_requested_key() {
    let (_d, path, op) = clean_world();
    let generate = vec![("dev".to_string(), vec!["app/API_KEY".to_string()])];
    let p = propose_structure(&op, &path, "myapp", ACCOUNT, &[], &generate).unwrap();
    assert!(p.steps.iter().any(|s| matches!(
        s,
        Step::Generate { env, product, key }
            if env == "dev" && product == "app" && key == "API_KEY"
    )));
}

#[test]
fn a_settled_contract_has_no_steps() {
    let (_d, path, op) = clean_world();
    let p = propose_structure(&op, &path, "myapp", ACCOUNT, &[], &[]).unwrap();
    assert!(p.steps.is_empty());
}

#[test]
fn the_same_state_gives_the_same_plan_id() {
    let (_d, path, op) = clean_world();
    let generate = vec![("dev".to_string(), vec!["app/API_KEY".to_string()])];
    let a = propose_structure(&op, &path, "myapp", ACCOUNT, &[], &generate).unwrap();
    let b = propose_structure(&op, &path, "myapp", ACCOUNT, &[], &generate).unwrap();
    assert_eq!(a.plan_id, b.plan_id);
}

#[test]
fn the_plan_id_golden_is_stable() {
    let (_d, path, op) = clean_world();
    let generate = vec![("dev".to_string(), vec!["app/API_KEY".to_string()])];
    let p = propose_structure(&op, &path, "myapp", ACCOUNT, &[], &generate).unwrap();
    assert_eq!(p.plan_id, "sp-0ded5fd55ccda5bf");
}
