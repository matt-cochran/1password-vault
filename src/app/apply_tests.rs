//! `opv apply` (design Part V, row `apply-core`): one atomic test per behaviour, each with
//! exactly one assertion on a public outcome.
//!
//! Every reply comes from the shared fake `op` (`FakeOp`) and the fixtures copied from
//! `src/app/propose/structure_tests.rs`; no tool output is invented.

use std::path::PathBuf;

use super::*;
use crate::adapters::fake_op::FakeOp;
use crate::config::bindings::{self, write_split};
use crate::host::FakeEnv;

const ACCOUNT: &str = "ACCOUNTAAA000000000000AAAA";
const MARKER: &str = "S7MARKER-apply";

/// Two products in dev, staging and prod; `core` is recorded in dev only, so staging and
/// prod must create its vault and item. Copied from `src/app/propose/structure_tests.rs`.
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
                    "section": {"id": boundary, "label": boundary}, "value": MARKER}],
    })
}

fn empty_item(boundary: &str, label: &str) -> serde_json::Value {
    let mut v = item(boundary, label);
    v["fields"][0]["value"] = serde_json::json!("");
    v
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

/// A checkout whose one rule-backed field is present but empty, ready to generate.
fn generate_world() -> (tempfile::TempDir, PathBuf, FakeOp) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.toml");
    let op = FakeOp::default();
    let id = op.insert("vdev0000000000000000000001", empty_item("app", "API_KEY"));
    write_split(&path, &CLEAN.replace("ITEM", &id)).unwrap();
    (dir, path, op)
}

/// A person at a terminal: not an assistant, stdin and stdout are a TTY.
fn tty() -> FakeEnv {
    FakeEnv::new("linux").tty()
}

#[allow(clippy::too_many_arguments)]
fn run_apply(
    op: &FakeOp,
    env: &dyn crate::host::HostEnv,
    path: &std::path::Path,
    plan_id: Option<&str>,
    opts: ApplyOpts,
    confirm: &mut dyn FnMut(&StructureProposal) -> bool,
    out: &mut Vec<u8>,
) -> Result<Applied, Error> {
    apply(op, env, path, "myapp", ACCOUNT, plan_id, opts, confirm, out)
}

// Refusals before anything is read or prompted ----------------------------------------------

#[test]
fn agent_mode_refuses_person_only() {
    let (_d, path, op) = fleet_world();
    let env = FakeEnv::new("linux").var("CLAUDECODE");
    let e = run_apply(
        &op,
        &env,
        &path,
        None,
        ApplyOpts::default(),
        &mut |_| true,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(e.code_str(), "person_only");
}

#[test]
fn agent_mode_reads_no_state() {
    let (_d, path, op) = fleet_world();
    let env = FakeEnv::new("linux").var("CLAUDECODE");
    let _ = run_apply(
        &op,
        &env,
        &path,
        None,
        ApplyOpts::default(),
        &mut |_| true,
        &mut Vec::new(),
    );
    assert!(op.calls.borrow().is_empty());
}

#[test]
fn a_non_tty_is_refused() {
    let (_d, path, op) = fleet_world();
    let e = run_apply(
        &op,
        &FakeEnv::new("linux"),
        &path,
        None,
        ApplyOpts::default(),
        &mut |_| true,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(e.code_str(), "terminal_required");
}

// Recompute and refuse a stale id -----------------------------------------------------------

#[test]
fn a_different_plan_id_is_refused_stale() {
    let (_d, path, op) = fleet_world();
    let e = run_apply(
        &op,
        &tty(),
        &path,
        Some("sp-0000000000000000"),
        ApplyOpts::default(),
        &mut |_| true,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(e.code_str(), "stale_plan");
}

// Confirm -----------------------------------------------------------------------------------

#[test]
fn a_declined_confirm_creates_no_vault() {
    let (_d, path, op) = fleet_world();
    let _ = run_apply(
        &op,
        &tty(),
        &path,
        None,
        ApplyOpts::default(),
        &mut |_| false,
        &mut Vec::new(),
    );
    assert_eq!(op.count(&["op", "vault", "create"]), 0);
}

#[test]
fn a_declined_confirm_writes_no_record() {
    let (d, path, op) = fleet_world();
    let _ = run_apply(
        &op,
        &tty(),
        &path,
        None,
        ApplyOpts::default(),
        &mut |_| false,
        &mut Vec::new(),
    );
    let record = bindings::read_record(&d.path().join(bindings::APPLIED)).unwrap();
    assert!(record.is_none());
}

// The steps the existing executors run ------------------------------------------------------

#[test]
fn an_accepted_plan_creates_the_missing_item() {
    let (_d, path, op) = fleet_world();
    run_apply(
        &op,
        &tty(),
        &path,
        None,
        ApplyOpts::default(),
        &mut |_| true,
        &mut Vec::new(),
    )
    .unwrap();
    assert!(
        op.items
            .borrow()
            .iter()
            .any(|i| i["title"] == "myapp · core · staging values")
    );
}

#[test]
fn an_inline_move_leaves_no_id_in_the_contract() {
    let (_d, path, op) = inline_world();
    run_apply(
        &op,
        &tty(),
        &path,
        None,
        ApplyOpts::default(),
        &mut |_| true,
        &mut Vec::new(),
    )
    .unwrap();
    assert!(!std::fs::read_to_string(&path).unwrap().contains("vault_id"));
}

#[test]
fn an_inline_move_records_the_id_in_the_bindings_file() {
    let (d, path, op) = inline_world();
    run_apply(
        &op,
        &tty(),
        &path,
        None,
        ApplyOpts::default(),
        &mut |_| true,
        &mut Vec::new(),
    )
    .unwrap();
    let text = std::fs::read_to_string(d.path().join(bindings::FILE)).unwrap();
    assert!(text.contains("environments.dev.boundaries.app.vault_id"));
}

#[test]
fn a_requested_generation_fills_the_empty_field() {
    let (_d, path, op) = generate_world();
    let opts = ApplyOpts {
        generate: vec![("dev".to_string(), vec!["app/API_KEY".to_string()])],
        ..ApplyOpts::default()
    };
    run_apply(
        &op,
        &tty(),
        &path,
        None,
        opts,
        &mut |_| true,
        &mut Vec::new(),
    )
    .unwrap();
    let filled = op.items.borrow().iter().any(|i| {
        i["fields"].as_array().is_some_and(|fs| {
            fs.iter()
                .any(|f| f["label"] == "API_KEY" && !f["value"].as_str().unwrap_or("").is_empty())
        })
    });
    assert!(filled);
}

// The apply record and convergence ----------------------------------------------------------

#[test]
fn the_apply_record_holds_the_plan_id() {
    let (d, path, op) = clean_world();
    let proposal =
        crate::app::propose::structure::propose_structure(&op, &path, "myapp", ACCOUNT, &[], &[])
            .unwrap();
    run_apply(
        &op,
        &tty(),
        &path,
        Some(&proposal.plan_id),
        ApplyOpts::default(),
        &mut |_| true,
        &mut Vec::new(),
    )
    .unwrap();
    let record = bindings::read_record(&d.path().join(bindings::APPLIED))
        .unwrap()
        .unwrap();
    assert_eq!(record.plan_id, proposal.plan_id);
}

#[test]
fn a_second_apply_finds_no_steps() {
    let (_d, path, op) = fleet_world();
    run_apply(
        &op,
        &tty(),
        &path,
        None,
        ApplyOpts::default(),
        &mut |_| true,
        &mut Vec::new(),
    )
    .unwrap();
    let again = run_apply(
        &op,
        &tty(),
        &path,
        None,
        ApplyOpts::default(),
        &mut |_| true,
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(again.steps_run, 0);
}

// The value boundary ------------------------------------------------------------------------

#[test]
fn the_plan_output_never_holds_a_value() {
    let (_d, path, op) = fleet_world();
    let mut out = Vec::new();
    run_apply(
        &op,
        &tty(),
        &path,
        None,
        ApplyOpts::default(),
        &mut |_| true,
        &mut out,
    )
    .unwrap();
    assert!(!String::from_utf8(out).unwrap().contains(MARKER));
}

#[test]
fn the_apply_report_never_holds_a_value() {
    let (_d, path, op) = fleet_world();
    let applied = run_apply(
        &op,
        &tty(),
        &path,
        None,
        ApplyOpts::default(),
        &mut |_| true,
        &mut Vec::new(),
    )
    .unwrap();
    assert!(!format!("{applied:?}").contains(MARKER));
}
