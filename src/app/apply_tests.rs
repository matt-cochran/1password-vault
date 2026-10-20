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

/// Every `plan_id` value anywhere in a JSON document, in document order.
fn plan_ids(v: &serde_json::Value) -> Vec<String> {
    match v {
        serde_json::Value::Object(o) => o
            .iter()
            .flat_map(|(k, v)| match (k.as_str(), v.as_str()) {
                ("plan_id", Some(id)) => vec![id.to_string()],
                _ => plan_ids(v),
            })
            .collect(),
        serde_json::Value::Array(a) => a.iter().flat_map(plan_ids).collect(),
        _ => Vec::new(),
    }
}

#[test]
fn the_proposals_only_plan_id_is_the_one_apply_accepts() {
    let (_d, path, op) = fleet_world();
    let proposal =
        crate::app::propose::structure::propose_structure(&op, &path, "myapp", ACCOUNT, &[], &[])
            .unwrap();
    let ids = plan_ids(&serde_json::to_value(&proposal).unwrap());
    let applied = run_apply(
        &op,
        &tty(),
        &path,
        ids.first().map(String::as_str),
        ApplyOpts::default(),
        &mut |_| false,
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(ids, vec![applied.plan_id]);
}

/// #183: the plan id covers the project, so a plan proposed under one project name is
/// never applied under another (no vault is created with the other name).
#[test]
fn apply_with_another_project_than_the_proposal_is_refused() {
    let (_d, path, op) = fleet_world();
    let proposal =
        crate::app::propose::structure::propose_structure(&op, &path, "myapp", ACCOUNT, &[], &[])
            .unwrap();
    let e = apply(
        &op,
        &tty(),
        &path,
        "otherapp",
        ACCOUNT,
        Some(&proposal.plan_id),
        ApplyOpts::default(),
        &mut |_| true,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(e.code_str(), "stale_plan");
}

/// #183: `--project` names the project of a file configuration's structural plan.
#[test]
fn a_given_project_names_the_scope_of_a_file_configuration() {
    let (d, _path, op) = fleet_world();
    std::fs::write(
        d.path().join(crate::config_store::DOT_FILE),
        format!("account = \"{ACCOUNT}\"\n"),
    )
    .unwrap();
    let scope = crate::app::structure::scope(d.path(), &op, Some("mcproductlabs-infra")).unwrap();
    assert_eq!(scope.project, "mcproductlabs-infra");
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

// Manifest projects (D-G): the ids live in the manifest's `opv-bindings` block ---------------

/// The checkout's `.opv`: the project and the account its manifest is found in.
fn dot_opv(dir: &std::path::Path) {
    std::fs::write(
        dir.join(crate::config_store::DOT_FILE),
        format!("project = \"myapp\"\naccount = \"{ACCOUNT}\"\n"),
    )
    .unwrap();
}

/// A checkout whose configuration is the manifest `opv · myapp` with `contract` as its
/// contract block and `block` as its `opv-bindings` block, found by the checkout's `.opv`.
/// Returns the manifest's item id and its configuration.
fn manifest_in(
    op: &FakeOp,
    contract: &str,
    block: Option<&str>,
) -> (tempfile::TempDir, String, ConfigAt) {
    use crate::adapters::onepassword_manifest::template;
    use crate::config_store::{Found, Request, locate, manifest_tags, manifest_title};
    let mut notes = format!("```toml\n{contract}```\n");
    if let Some(ids) = block {
        notes.push_str(&format!("```toml opv-bindings\n{ids}```\n"));
    }
    let mut item = template(
        &manifest_title("myapp"),
        "myapp",
        &manifest_tags(None, &[]),
        "",
    );
    item["fields"][0]["value"] = serde_json::json!(notes);
    let id = op.insert("myapp-dev", item);
    let dir = tempfile::tempdir().unwrap();
    dot_opv(dir.path());
    let req = Request {
        start: dir.path().to_path_buf(),
        ..Request::default()
    };
    let Found::Manifest(m) = locate(&req, op).unwrap() else {
        unreachable!("no secrets.toml in a fresh directory")
    };
    (dir, id, ConfigAt::Manifest(m))
}

/// A manifest project whose contract block still holds [`INLINE`]'s ids.
fn inline_manifest_world() -> (tempfile::TempDir, String, ConfigAt, FakeOp) {
    let op = FakeOp::default();
    let item_id = op.insert("vdev0000000000000000000001", item("app", "API_KEY"));
    let (dir, id, at) = manifest_in(&op, &INLINE.replace("ITEM", &item_id), None);
    (dir, id, at, op)
}

/// A manifest project holding [`FLEET`], its ids in the `opv-bindings` block.
fn fleet_manifest_world() -> (tempfile::TempDir, String, ConfigAt, FakeOp) {
    let op = FakeOp::default();
    let item_id = op.insert("vdev0000000000000000000001", item("core", "SESSION_KEY"));
    let (contract, ids) = bindings::split(&FLEET.replace("ITEM", &item_id));
    let (dir, id, at) = manifest_in(&op, &contract, Some(&ids.render()));
    (dir, id, at, op)
}

/// `opv apply` of whatever the manifest project `at` needs, confirmed.
fn apply_manifest(op: &FakeOp, at: &ConfigAt) -> Result<Applied, Error> {
    apply_at(
        op,
        &tty(),
        at,
        "myapp",
        ACCOUNT,
        None,
        ApplyOpts::default(),
        &mut |_| true,
        &mut Vec::new(),
    )
}

/// The notes of the manifest item `id`.
fn notes_of(op: &FakeOp, id: &str) -> String {
    op.item(id)["fields"][0]["value"]
        .as_str()
        .unwrap()
        .to_string()
}

#[test]
fn a_manifest_with_inline_ids_proposes_the_move() {
    let (_d, _id, at, op) = inline_manifest_world();
    let proposal =
        crate::app::propose::structure::propose_structure_at(&op, &at, "myapp", ACCOUNT, &[], &[])
            .unwrap();
    assert!(
        proposal
            .steps
            .iter()
            .any(|s| matches!(s, Step::MoveIds { .. }))
    );
}

#[test]
fn a_manifest_move_leaves_no_id_in_the_contract_block() {
    let (_d, id, at, op) = inline_manifest_world();
    apply_manifest(&op, &at).unwrap();
    let contract = crate::adapters::onepassword_manifest::config_text(&notes_of(&op, &id));
    assert!(!contract.contains("vault_id"));
}

#[test]
fn a_manifest_move_records_the_id_in_the_bindings_block() {
    let (_d, id, at, op) = inline_manifest_world();
    apply_manifest(&op, &at).unwrap();
    let block = crate::adapters::onepassword_manifest::bindings_text(&notes_of(&op, &id));
    assert!(
        block
            .unwrap_or_default()
            .contains("environments.dev.boundaries.app.vault_id")
    );
}

#[test]
fn an_accepted_manifest_plan_creates_the_missing_item() {
    let (_d, _id, at, op) = fleet_manifest_world();
    apply_manifest(&op, &at).unwrap();
    assert!(
        op.items
            .borrow()
            .iter()
            .any(|i| i["title"] == "myapp · core · staging values")
    );
}

#[test]
fn a_manifest_apply_records_a_created_boundary_in_the_bindings_block() {
    let (_d, id, at, op) = fleet_manifest_world();
    apply_manifest(&op, &at).unwrap();
    let block = crate::adapters::onepassword_manifest::bindings_text(&notes_of(&op, &id));
    assert!(
        block
            .unwrap_or_default()
            .contains("environments.staging.boundaries.core.item_id")
    );
}

#[test]
fn a_manifest_apply_writes_no_local_record() {
    let (d, _id, at, op) = fleet_manifest_world();
    apply_manifest(&op, &at).unwrap();
    assert!(!d.path().join(bindings::APPLIED).exists());
}

#[test]
fn a_second_manifest_apply_finds_no_steps() {
    let (_d, _id, at, op) = fleet_manifest_world();
    apply_manifest(&op, &at).unwrap();
    assert_eq!(apply_manifest(&op, &at).unwrap().steps_run, 0);
}

#[test]
fn scope_accepts_a_manifest() {
    let op = FakeOp::default();
    let (dir, _id, _at) = manifest_in(&op, &INLINE.replace("ITEM", "item"), None);
    let scope = crate::app::structure::scope(dir.path(), &op, None).unwrap();
    assert!(matches!(scope.config, ConfigAt::Manifest(_)));
}

// A retirement's apply (#179): `opv apply rp-…` archives the key's fields, then marks it ----

/// `app/OLD_KEY` is retiring in a shared `dev` and a production `prod`, each with its own
/// boundary item; `app/API_KEY` stays active.
const RETIRING: &str = r#"[environments.dev]
tier = "shared"
boundaries.app = { vault_id = "vdev0000000000000000000001", item_id = "DEVITEM" }

[environments.prod]
tier = "production"
boundaries.app = { vault_id = "vshr0000000000000000000002", item_id = "PRODITEM" }

[products.app.keys.API_KEY]
kind = "secret"

[products.app.keys.OLD_KEY]
kind = "secret"
lifecycle = "retiring"
"#;

const DATE: &str = "2026-10-19";
const ARCHIVED: &str = "archived · 2026-10-19 · retired app/OLD_KEY";

/// A boundary item holding `API_KEY` and, in section `old_section`, `OLD_KEY`; both carry
/// the canary value.
fn retiring_item(old_section: &str) -> serde_json::Value {
    serde_json::json!({
        "title": "myapp · app · values",
        "category": "SECURE_NOTE",
        "sections": [{"id": "app", "label": "app"}, {"id": "old", "label": old_section}],
        "fields": [
            {"id": "f1", "label": "API_KEY", "type": "CONCEALED",
             "section": {"id": "app", "label": "app"}, "value": MARKER},
            {"id": "f2", "label": "OLD_KEY", "type": "CONCEALED",
             "section": {"id": "old", "label": old_section}, "value": MARKER},
        ],
    })
}

/// A checkout holding [`RETIRING`] (with `header` above it) and the two items, `OLD_KEY` in
/// section `old_section` of each. Returns the dev and prod item ids too.
fn retiring_world_with(
    header: &str,
    old_section: &str,
) -> (tempfile::TempDir, PathBuf, FakeOp, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.toml");
    let op = FakeOp::default();
    let dev = op.insert("vdev0000000000000000000001", retiring_item(old_section));
    let prod = op.insert("vshr0000000000000000000002", retiring_item(old_section));
    let text = format!("{header}{RETIRING}")
        .replace("DEVITEM", &dev)
        .replace("PRODITEM", &prod);
    write_split(&path, &text).unwrap();
    (dir, path, op, dev, prod)
}

fn retiring_world() -> (tempfile::TempDir, PathBuf, FakeOp, String, String) {
    retiring_world_with("", "app")
}

/// The retirement plan id of `app/OLD_KEY` in the contract at `path`.
fn retire_id(path: &std::path::Path) -> String {
    let fleet = crate::config::load(path).unwrap();
    crate::app::retire::archive_plan(&fleet, "app", "OLD_KEY").plan_id
}

/// Run `opv apply <rp-…>` on `r` with `held` as the environments a target still holds the
/// key in, confirming.
fn run_retire_on(
    r: &dyn CommandRunner,
    env: &dyn crate::host::HostEnv,
    path: &std::path::Path,
    held: &[&str],
    out: &mut Vec<u8>,
) -> Result<RetireApplied, Error> {
    let id = retire_id(path);
    let at = ConfigAt::File(path.to_path_buf());
    let mut still_held = |_: &crate::domain::Fleet, _: &str, _: &str| {
        held.iter().map(|e| e.to_string()).collect::<Vec<_>>()
    };
    apply_retire(r, env, &at, &id, DATE, &mut still_held, &mut |_| true, out)
}

fn run_retire(op: &FakeOp, path: &std::path::Path) -> Result<RetireApplied, Error> {
    run_retire_on(op, &tty(), path, &[], &mut Vec::new())
}

/// The section label of field `label` in item `id`.
fn section_of(op: &FakeOp, id: &str, label: &str) -> String {
    let item = op.item(id);
    let field = item["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["label"] == label)
        .cloned()
        .unwrap();
    field["section"]["label"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// A runner that answers as `op` does but fails the `n`-th `item edit` (1-based).
struct FailingEdit<'a> {
    op: &'a FakeOp,
    fail_at: usize,
    edits: std::cell::Cell<usize>,
}

impl CommandRunner for FailingEdit<'_> {
    fn read(
        &self,
        call: &crate::runner::Call,
        refused: &[i32],
    ) -> std::io::Result<crate::runner::Outcome> {
        self.op.read(call, refused)
    }
    fn write(&self, call: &crate::runner::Call) -> std::io::Result<crate::runner::Outcome> {
        if call.args.starts_with(&["item", "edit"]) {
            let n = self.edits.get() + 1;
            self.edits.set(n);
            if n == self.fail_at {
                return Ok(crate::runner::Outcome::Refused(
                    crate::runner::Output::failure(1),
                ));
            }
        }
        self.op.write(call)
    }
    fn probe(
        &self,
        call: &crate::runner::Call,
        limit: std::time::Duration,
    ) -> std::io::Result<crate::runner::Output> {
        self.op.probe(call, limit)
    }
    fn pause(&self, d: std::time::Duration, note: &str) {
        self.op.pause(d, note);
    }
    fn note(&self, line: &str) {
        self.op.note(line);
    }
    fn run_inherited(
        &self,
        program: &str,
        args: &[&str],
        env: &[(&str, &str)],
    ) -> std::io::Result<i32> {
        self.op.run_inherited(program, args, env)
    }
}

/// A run whose second item edit (prod's) fails, after dev's was archived.
fn half_archived(op: &FakeOp, path: &std::path::Path) -> Result<RetireApplied, Error> {
    let failing = FailingEdit {
        op,
        fail_at: 2,
        edits: std::cell::Cell::new(0),
    };
    run_retire_on(&failing, &tty(), path, &[], &mut Vec::new())
}

#[test]
fn a_retirement_refuses_while_a_target_still_holds_the_key() {
    let (_d, path, op, _, _) = retiring_world();
    let e = run_retire_on(&op, &tty(), &path, &["prod"], &mut Vec::new()).unwrap_err();
    assert_eq!(e.code_str(), "policy_refused");
}

#[test]
fn a_held_refusal_names_the_ci_prune_step() {
    let (_d, path, op, _, _) = retiring_world();
    let e = run_retire_on(&op, &tty(), &path, &["prod"], &mut Vec::new()).unwrap_err();
    assert!(e.mentions("opv sync prod --prune --retire"));
}

#[test]
fn a_held_refusal_edits_no_item() {
    let (_d, path, op, _, _) = retiring_world();
    let _ = run_retire_on(&op, &tty(), &path, &["dev"], &mut Vec::new());
    assert_eq!(op.count(&["op", "item", "edit"]), 0);
}

#[test]
fn a_retirement_moves_the_field_into_the_archived_section() {
    let (_d, path, op, _, prod) = retiring_world();
    run_retire(&op, &path).unwrap();
    assert_eq!(section_of(&op, &prod, "OLD_KEY"), ARCHIVED);
}

#[test]
fn a_retirement_keeps_the_archived_value() {
    let (_d, path, op, dev, _) = retiring_world();
    run_retire(&op, &path).unwrap();
    let item = op.item(&dev);
    let old = item["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["label"] == "OLD_KEY")
        .cloned()
        .unwrap();
    assert_eq!(old["value"], MARKER);
}

#[test]
fn a_retirement_leaves_the_active_key_in_place() {
    let (_d, path, op, dev, _) = retiring_world();
    run_retire(&op, &path).unwrap();
    assert_eq!(section_of(&op, &dev, "API_KEY"), "app");
}

#[test]
fn a_retirement_edits_each_item_once() {
    let (_d, path, op, _, _) = retiring_world();
    run_retire(&op, &path).unwrap();
    assert_eq!(op.count(&["op", "item", "edit"]), 2);
}

#[test]
fn an_already_archived_field_is_skipped() {
    let (_d, path, op, _, _) =
        retiring_world_with("", "archived · 2026-01-02 · retired app/OLD_KEY");
    run_retire(&op, &path).unwrap();
    assert_eq!(op.count(&["op", "item", "edit"]), 0);
}

#[test]
fn a_retirement_marks_the_key_retired() {
    let (_d, path, op, _, _) = retiring_world();
    run_retire(&op, &path).unwrap();
    let fleet = crate::config::load(&path).unwrap();
    assert_eq!(
        fleet.products["app"].keys["OLD_KEY"].lifecycle,
        crate::domain::Lifecycle::Retired
    );
}

#[test]
fn a_partial_archive_reports_what_was_archived() {
    let (_d, path, op, _, _) = retiring_world();
    let e = half_archived(&op, &path).unwrap_err();
    assert!(e.mentions("app/OLD_KEY archived in dev"));
}

#[test]
fn a_partial_archive_leaves_the_key_retiring() {
    let (_d, path, op, _, _) = retiring_world();
    let _ = half_archived(&op, &path);
    let fleet = crate::config::load(&path).unwrap();
    assert_eq!(
        fleet.products["app"].keys["OLD_KEY"].lifecycle,
        crate::domain::Lifecycle::Retiring
    );
}

#[test]
fn a_re_run_after_a_partial_archive_finishes_the_retirement() {
    let (_d, path, op, _, _) = retiring_world();
    let _ = half_archived(&op, &path);
    assert!(run_retire(&op, &path).unwrap().retired);
}

#[test]
fn a_re_run_after_a_partial_archive_skips_the_archived_item() {
    let (_d, path, op, _, _) = retiring_world();
    let _ = half_archived(&op, &path);
    assert_eq!(
        run_retire(&op, &path).unwrap().already_archived,
        vec!["dev"]
    );
}

#[test]
fn a_retirement_in_agent_mode_is_refused() {
    let (_d, path, op, _, _) = retiring_world();
    let env = FakeEnv::new("linux").var("CLAUDECODE").tty();
    let e = run_retire_on(&op, &env, &path, &[], &mut Vec::new()).unwrap_err();
    assert_eq!(e.code_str(), "person_only");
}

#[test]
fn a_retirement_without_a_terminal_is_refused() {
    let (_d, path, op, _, _) = retiring_world();
    let e = run_retire_on(&op, &FakeEnv::new("linux"), &path, &[], &mut Vec::new()).unwrap_err();
    assert_eq!(e.code_str(), "terminal_required");
}

#[test]
fn a_retirement_under_ci_writes_no_item() {
    let (_d, path, op, _, _) = retiring_world();
    let env = FakeEnv::new("linux").var("CI").var("GITHUB_ACTIONS");
    let _ = run_retire_on(&op, &env, &path, &[], &mut Vec::new());
    assert!(op.calls.borrow().is_empty());
}

#[test]
fn a_generated_configuration_returns_the_generator_route() {
    let (_d, path, op, _, _) = retiring_world_with("# generated by gen.py\n", "app");
    let e = run_retire(&op, &path).unwrap_err();
    assert_eq!(e.code_str(), "config_not_editable");
}

#[test]
fn a_generated_configuration_is_not_edited() {
    let (_d, path, op, _, _) = retiring_world_with("# generated by gen.py\n", "app");
    let before = std::fs::read_to_string(&path).unwrap();
    let _ = run_retire(&op, &path);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
}

#[test]
fn an_unknown_retirement_plan_id_is_refused() {
    let (_d, path, op, _, _) = retiring_world();
    let at = ConfigAt::File(path.clone());
    let e = apply_retire(
        &op,
        &tty(),
        &at,
        "rp-0000000000000000",
        DATE,
        &mut |_, _, _| Vec::new(),
        &mut |_| true,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(e.code_str(), "plan_unknown");
}

#[test]
fn a_declined_retirement_edits_no_item() {
    let (_d, path, op, _, _) = retiring_world();
    let at = ConfigAt::File(path.clone());
    apply_retire(
        &op,
        &tty(),
        &at,
        &retire_id(&path),
        DATE,
        &mut |_, _, _| Vec::new(),
        &mut |_| false,
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(op.count(&["op", "item", "edit"]), 0);
}

#[test]
fn the_retirement_output_never_holds_a_value() {
    let (_d, path, op, _, _) = retiring_world();
    let mut out = Vec::new();
    run_retire_on(&op, &tty(), &path, &[], &mut out).unwrap();
    assert!(!String::from_utf8(out).unwrap().contains(MARKER));
}

#[test]
fn the_retirement_report_never_holds_a_value() {
    let (_d, path, op, _, _) = retiring_world();
    let applied = run_retire(&op, &path).unwrap();
    assert!(!serde_json::to_string(&applied).unwrap().contains(MARKER));
}

#[test]
fn a_partial_archive_error_never_holds_a_value() {
    let (_d, path, op, _, _) = retiring_world();
    let e = half_archived(&op, &path).unwrap_err();
    assert!(!crate::error::report(&e).contains(MARKER));
}
