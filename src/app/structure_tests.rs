//! #133: the structural plan and its apply, on the fake `op`.

use std::cell::Cell;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use super::*;
use crate::adapters::fake_op::FakeOp;
use crate::runner::fake::FakeRunner;
use crate::runner::{Call, Outcome, Output};

const ACCOUNT: &str = "ACCOUNTAAA000000000000AAAA";
const MARKER: &str = "sk_live_STRUCTUREMARKER133";

/// Three products in dev, staging and prod. `web` and `api` share the `core` boundary,
/// which dev already records (an existing shared item holding a filled value); `billing`
/// is an optional integration in its own boundary, staging and prod only. prod has two
/// independent Fly targets, each delivering one product.
const FLEET: &str = r#"[environments.dev]
boundaries.core = { vault_id = "vdev0000000000000000000001", item_id = "ITEM" }

[environments.staging]

[environments.prod]

[environments.prod.targets.web]
fly.app = "myapp-web-prod"
fly.secret_name = "FLEET__{PRODUCT}__{KEY}"
products = ["web"]

[environments.prod.targets.api]
fly.app = "myapp-api-prod"
fly.secret_name = "FLEET__{PRODUCT}__{KEY}"
products = ["api"]

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

[products.billing.keys.STRIPE_KEY]
kind = "secret"
environments = ["staging", "prod"]
"#;

/// A checkout holding [`FLEET`], and a fake whose dev `core` item already has a filled
/// `web/SESSION_KEY` (the marker value) and lacks `api/DATABASE_URL`.
fn workspace_with(text: &str) -> (tempfile::TempDir, PathBuf, FakeOp) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.toml");
    let op = FakeOp::default();
    let id = op.insert(
        "vdev0000000000000000000001",
        serde_json::json!({
            "title": "myapp · core · dev values",
            "category": "SECURE_NOTE",
            "sections": [{"id": "web", "label": "web"}],
            "fields": [{"id": "f1", "label": "SESSION_KEY", "type": "CONCEALED",
                        "section": {"id": "web", "label": "web"}, "value": MARKER}],
        }),
    );
    crate::config::bindings::write_split(&path, &text.replace("ITEM", &id)).unwrap();
    (dir, path, op)
}

fn workspace() -> (tempfile::TempDir, PathBuf, FakeOp) {
    workspace_with(FLEET)
}

fn text(path: &std::path::Path) -> String {
    crate::config::read_merged(path).unwrap()
}

fn plan_of(path: &std::path::Path, op: &dyn CommandRunner) -> Plan {
    plan(op, &text(path), "myapp", ACCOUNT).unwrap()
}

fn approve_all(_: &Plan) -> Result<(), Error> {
    Ok(())
}

fn apply_reviewed(path: &std::path::Path, op: &dyn CommandRunner) -> Result<Applied, Error> {
    let id = plan_of(path, op).plan_id;
    apply(op, path, "myapp", ACCOUNT, &id, &mut approve_all)
}

// The plan ---------------------------------------------------------------------------------

#[test]
fn a_plan_id_is_well_formed() {
    let (_d, path, op) = workspace();
    assert!(is_plan_id(&plan_of(&path, &op).plan_id));
}

#[test]
fn the_same_configuration_plans_the_same_id() {
    let (_d, path, op) = workspace();
    assert_eq!(plan_of(&path, &op).plan_id, plan_of(&path, &op).plan_id);
}

#[test]
fn another_account_plans_another_id() {
    let (_d, path, op) = workspace();
    let other = plan(&op, &text(&path), "myapp", "ACCOUNTBBB000000000000BBBB").unwrap();
    assert_ne!(other.plan_id, plan_of(&path, &op).plan_id);
}

#[test]
fn another_project_plans_another_id() {
    let (_d, path, op) = workspace();
    let other = plan(&op, &text(&path), "other", ACCOUNT).unwrap();
    assert_ne!(other.plan_id, plan_of(&path, &op).plan_id);
}

#[test]
fn a_changed_configuration_plans_another_id() {
    let (_d, path, op) = workspace();
    let before = plan_of(&path, &op).plan_id;
    std::fs::write(
        &path,
        std::fs::read_to_string(&path).unwrap() + "\n# a comment\n",
    )
    .unwrap();
    assert_ne!(plan_of(&path, &op).plan_id, before);
}

#[test]
fn a_value_entered_in_1password_never_changes_the_plan_id() {
    let (_d, path, op) = workspace();
    let before = plan_of(&path, &op).plan_id;
    let item = op.items.borrow()[0]["id"].as_str().unwrap().to_string();
    {
        let mut items = op.items.borrow_mut();
        let i = items.iter_mut().find(|i| i["id"] == item.as_str()).unwrap();
        i["fields"][0]["value"] = serde_json::json!("another value");
    }
    assert_eq!(plan_of(&path, &op).plan_id, before);
}

#[test]
fn the_plan_never_holds_a_value() {
    let (_d, path, op) = workspace();
    let json = serde_json::to_string(&plan_of(&path, &op)).unwrap();
    assert!(!json.contains(MARKER), "{json}");
}

#[test]
fn planning_writes_nothing() {
    let (_d, path, op) = workspace();
    let _ = plan_of(&path, &op);
    let writes = [
        ["op", "vault", "create"],
        ["op", "item", "create"],
        ["op", "item", "edit"],
    ];
    assert_eq!(writes.iter().map(|w| op.count(w)).sum::<usize>(), 0);
}

#[test]
fn an_existing_boundary_plans_only_its_missing_field() {
    let (_d, path, op) = workspace();
    let dev: Vec<String> = plan_of(&path, &op)
        .fields
        .into_iter()
        .filter(|f| f.environment == "dev")
        .map(|f| format!("{}/{}", f.product, f.key))
        .collect();
    assert_eq!(dev, ["api/DATABASE_URL"]);
}

#[test]
fn an_optional_integration_gets_its_own_boundary_where_it_is_declared() {
    let (_d, path, op) = workspace();
    let p = plan_of(&path, &op);
    let staging: Vec<&str> = p
        .environments
        .iter()
        .find(|e| e.environment == "staging")
        .unwrap()
        .boundaries
        .iter()
        .map(|b| b.boundary.as_str())
        .collect();
    assert_eq!(staging, ["billing", "core"]);
}

#[test]
fn each_independent_target_plans_its_own_delivery_item() {
    let (_d, path, op) = workspace();
    let items: Vec<String> = plan_of(&path, &op)
        .delivery_items
        .into_iter()
        .map(|d| format!("{}/{}", d.target, d.product))
        .collect();
    assert_eq!(items, ["api/api", "web/web"]);
}

#[test]
fn a_recorded_vault_outside_the_account_refuses_the_plan() {
    // The environment names its account, as the structural apply's runner selects one.
    let (_d, path, op) = workspace_with(
        &FLEET
            .replace("vdev0000000000000000000001", "vother000000000000000000001")
            .replace(
                "[environments.dev]\n",
                &format!("[environments.dev]\naccount = \"{ACCOUNT}\"\n"),
            ),
    );
    let e = plan(&Probed::new(op), &text(&path), "myapp", ACCOUNT).unwrap_err();
    assert_eq!(e.code_str(), "ids_not_in_account");
}

#[test]
fn a_plan_without_an_account_id_is_refused() {
    let (_d, path, op) = workspace();
    let e = plan(&op, &text(&path), "myapp", "").unwrap_err();
    assert_eq!(e.code_str(), "op_not_signed_in");
}

/// A runner whose `op vault get` probes cannot run: visibility is unknown.
struct ProbeFails(FakeOp);

impl CommandRunner for ProbeFails {
    fn read(&self, call: &Call, refused: &[i32]) -> io::Result<Outcome> {
        self.0.read(call, refused)
    }
    fn write(&self, call: &Call) -> io::Result<Outcome> {
        self.0.write(call)
    }
    fn probe(&self, call: &Call, limit: Duration) -> io::Result<Output> {
        if call.args.starts_with(&["vault", "get"]) {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.0.probe(call, limit)
    }
    fn pause(&self, _: Duration, _: &str) {}
    fn note(&self, _: &str) {}
    fn run_inherited(&self, _: &str, _: &[&str], _: &[(&str, &str)]) -> io::Result<i32> {
        Err(io::ErrorKind::PermissionDenied.into())
    }
}

#[test]
fn an_unknown_vault_visibility_refuses_the_plan() {
    let (_d, path, op) = workspace();
    let r = ProbeFails(op);
    assert!(plan(&r, &text(&path), "myapp", ACCOUNT).is_err());
}

// The apply --------------------------------------------------------------------------------

#[test]
fn apply_records_every_created_id_in_the_configuration() {
    let (_d, path, op) = workspace();
    apply_reviewed(&path, &op).unwrap();
    assert!(crate::config::parse(&text(&path)).is_ok());
}

#[test]
fn after_apply_nothing_is_left_to_plan() {
    let (_d, path, op) = workspace();
    apply_reviewed(&path, &op).unwrap();
    assert!(plan_of(&path, &op).is_empty());
}

#[test]
fn a_second_apply_creates_nothing() {
    let (_d, path, op) = workspace();
    apply_reviewed(&path, &op).unwrap();
    let again = apply_reviewed(&path, &op).unwrap();
    assert!(again.created.is_empty() && again.fields_added.is_empty());
}

#[test]
fn apply_keeps_an_existing_value() {
    let (_d, path, op) = workspace();
    apply_reviewed(&path, &op).unwrap();
    assert!(
        serde_json::to_string(&*op.items.borrow())
            .unwrap()
            .contains(MARKER)
    );
}

#[test]
fn the_apply_report_never_holds_a_value() {
    let (_d, path, op) = workspace();
    let json = serde_json::to_string(&apply_reviewed(&path, &op).unwrap()).unwrap();
    assert!(!json.contains(MARKER), "{json}");
}

#[test]
fn a_created_boundary_carries_a_link_for_key_entry() {
    let (_d, path, op) = workspace();
    let applied = apply_reviewed(&path, &op).unwrap();
    let b = applied
        .created
        .iter()
        .find(|c| c.kind == "boundary")
        .unwrap();
    assert!(
        b.link
            .as_deref()
            .is_some_and(|l| l.starts_with("https://start.1password.com/open/i?"))
    );
}

#[test]
fn a_stale_plan_id_is_refused() {
    let (_d, path, op) = workspace();
    let id = plan_of(&path, &op).plan_id;
    std::fs::write(
        &path,
        std::fs::read_to_string(&path).unwrap() + "\n# changed after review\n",
    )
    .unwrap();
    let e = apply(&op, &path, "myapp", ACCOUNT, &id, &mut approve_all).unwrap_err();
    assert_eq!(e.code_str(), "stale_plan");
}

#[test]
fn a_stale_plan_creates_nothing() {
    let (_d, path, op) = workspace();
    let id = plan_of(&path, &op).plan_id;
    std::fs::write(
        &path,
        std::fs::read_to_string(&path).unwrap() + "\n# changed after review\n",
    )
    .unwrap();
    let _ = apply(&op, &path, "myapp", ACCOUNT, &id, &mut approve_all);
    assert_eq!(op.count(&["op", "vault", "create"]), 0);
}

#[test]
fn a_plan_approved_for_another_account_is_stale() {
    let (_d, path, op) = workspace();
    let id = plan(&op, &text(&path), "myapp", "ACCOUNTBBB000000000000BBBB")
        .unwrap()
        .plan_id;
    let e = apply(&op, &path, "myapp", ACCOUNT, &id, &mut approve_all).unwrap_err();
    assert_eq!(e.code_str(), "stale_plan");
}

#[test]
fn a_refused_authorization_creates_nothing() {
    let (_d, path, op) = workspace();
    let id = plan_of(&path, &op).plan_id;
    let mut refuse = |_: &Plan| -> Result<(), Error> {
        Err(changed("sp-0000000000000000", "sp-1111111111111111"))
    };
    let _ = apply(&op, &path, "myapp", ACCOUNT, &id, &mut refuse);
    assert_eq!(op.count(&["op", "vault", "create"]), 0);
}

#[test]
fn a_service_account_cannot_apply() {
    let (_d, path, op) = workspace();
    let id = plan_of(&path, &op).plan_id;
    op.signed_in.set(true);
    let r = ServiceAccount(op);
    assert!(apply(&r, &path, "myapp", ACCOUNT, &id, &mut approve_all).is_err());
}

/// #157: the approval is single-use, so a service account's apply never spends it.
#[test]
fn a_service_account_apply_leaves_the_approval_unspent() {
    let (_d, path, op) = workspace();
    let id = plan_of(&path, &op).plan_id;
    let r = ServiceAccount(op);
    let spent = Cell::new(false);
    let mut authorize = |_: &Plan| -> Result<(), Error> {
        spent.set(true);
        Ok(())
    };
    let _ = apply(&r, &path, "myapp", ACCOUNT, &id, &mut authorize);
    assert!(!spent.get());
}

/// #157: signed out, a recorded vault is not called outside the account.
#[test]
fn a_signed_out_plan_is_op_not_signed_in() {
    let (_d, path, op) = workspace();
    op.signed_in.set(false);
    let e = plan(&op, &text(&path), "myapp", ACCOUNT).unwrap_err();
    assert_eq!(e.code_str(), "op_not_signed_in");
}

/// The fake `op`, signed in as a service account.
struct ServiceAccount(FakeOp);

impl CommandRunner for ServiceAccount {
    fn read(&self, call: &Call, refused: &[i32]) -> io::Result<Outcome> {
        self.0.read(call, refused)
    }
    fn write(&self, call: &Call) -> io::Result<Outcome> {
        self.0.write(call)
    }
    fn probe(&self, call: &Call, limit: Duration) -> io::Result<Output> {
        if call.args.first() == Some(&"whoami") {
            return Ok(Output::success(r#"{"user_type":"SERVICE_ACCOUNT"}"#));
        }
        self.0.probe(call, limit)
    }
    fn pause(&self, _: Duration, _: &str) {}
    fn note(&self, _: &str) {}
    fn run_inherited(&self, _: &str, _: &[&str], _: &[(&str, &str)]) -> io::Result<i32> {
        Err(io::ErrorKind::PermissionDenied.into())
    }
}

/// The fake `op` whose `n`th create (vault or item) fails, and whose failures carry a
/// secret-looking line on stdout.
struct FailingCreate {
    op: FakeOp,
    n: u32,
    seen: Cell<u32>,
}

impl CommandRunner for FailingCreate {
    fn read(&self, call: &Call, refused: &[i32]) -> io::Result<Outcome> {
        self.op.read(call, refused)
    }
    fn write(&self, call: &Call) -> io::Result<Outcome> {
        if call.args.get(1) == Some(&"create") {
            self.seen.set(self.seen.get() + 1);
            if self.seen.get() == self.n {
                return Ok(Outcome::Refused(Output {
                    status: 1,
                    stdout: zeroize::Zeroizing::new(
                        format!("OP_SESSION_my={MARKER}\n").into_bytes(),
                    ),
                }));
            }
        }
        self.op.write(call)
    }
    fn probe(&self, call: &Call, limit: Duration) -> io::Result<Output> {
        self.op.probe(call, limit)
    }
    fn pause(&self, _: Duration, _: &str) {}
    fn note(&self, _: &str) {}
    fn run_inherited(&self, _: &str, _: &[&str], _: &[(&str, &str)]) -> io::Result<i32> {
        Err(io::ErrorKind::PermissionDenied.into())
    }
}

fn failing_at(n: u32) -> (tempfile::TempDir, PathBuf, FailingCreate) {
    let (d, path, op) = workspace();
    (
        d,
        path,
        FailingCreate {
            op,
            n,
            seen: Cell::new(0),
        },
    )
}

#[test]
fn a_partial_apply_keeps_the_ids_it_created() {
    let (_d, path, r) = failing_at(3);
    let before = text(&path);
    let _ = apply_reviewed(&path, &r);
    assert_ne!(text(&path), before);
}

#[test]
fn a_partial_apply_failure_never_shows_upstream_output() {
    let (_d, path, r) = failing_at(3);
    let e = apply_reviewed(&path, &r).unwrap_err();
    assert!(!format!("{e:?}{e}").contains(MARKER));
}

#[test]
fn after_a_partial_apply_a_new_plan_finishes_the_structure() {
    let (_d, path, r) = failing_at(3);
    let _ = apply_reviewed(&path, &r);
    apply_reviewed(&path, &r.op).unwrap();
    assert!(plan_of(&path, &r.op).is_empty());
}

#[test]
fn a_recovered_apply_creates_no_duplicate_vault() {
    let (_d, path, r) = failing_at(3);
    let _ = apply_reviewed(&path, &r);
    apply_reviewed(&path, &r.op).unwrap();
    let names: Vec<String> =
        r.op.vaults
            .borrow()
            .iter()
            .map(|(_, n)| n.clone())
            .collect();
    let unique: BTreeSet<&String> = names.iter().collect();
    assert_eq!(unique.len(), names.len());
}

#[test]
fn a_generated_configuration_is_never_rewritten() {
    let (_d, path, op) = workspace_with(&format!("# generated by infra\n{FLEET}"));
    let before = text(&path);
    apply_reviewed(&path, &op).unwrap();
    assert_eq!(text(&path), before);
}

#[test]
fn a_generated_configuration_gets_the_ids_for_its_generator() {
    let (_d, path, op) = workspace_with(&format!("# generated by infra\n{FLEET}"));
    let applied = apply_reviewed(&path, &op).unwrap();
    assert!(
        applied
            .generator_ids
            .iter()
            .any(|l| l.contains("boundaries.core"))
    );
}

#[test]
fn a_configuration_changed_during_apply_is_never_overwritten() {
    let (_d, path, op) = workspace();
    let id = plan_of(&path, &op).plan_id;
    let p2 = path.clone();
    let mut edit_during = move |_: &Plan| -> Result<(), Error> {
        std::fs::write(&p2, std::fs::read_to_string(&p2).unwrap() + "# edited\n").unwrap();
        Ok(())
    };
    let e = apply(&op, &path, "myapp", ACCOUNT, &id, &mut edit_during).unwrap_err();
    assert_eq!(e.code_str(), "config_changed");
}

// End to end (#133 acceptance) -------------------------------------------------------------

/// An assistant declares a new product key and a new target, plans, and a person confirms
/// and applies it (authorized by a closure, as `opv apply` does); what is left is entering
/// values in 1Password.
fn end_to_end() -> (tempfile::TempDir, PathBuf, FakeOp, Result<Applied, Error>) {
    let (d, path, op) = workspace();
    let mut key = super::super::declare::Key {
        product: "billing".into(),
        key: "WEBHOOK_SECRET".into(),
        kind: "secret".into(),
        environments: vec!["prod".into()],
        guidance: Some("Stripe dashboard > Webhooks".into()),
        ..Default::default()
    };
    super::super::declare::key(&op, &path, &key).unwrap();
    key.key = "PUBLISHABLE_KEY".into();
    key.kind = "config".into();
    super::super::declare::key(&op, &path, &key).unwrap();
    let target = super::super::declare::Target {
        environment: "prod".into(),
        name: "billing".into(),
        provider: Some("fly".into()),
        fields: [("fly-app".to_string(), "myapp-billing-prod".to_string())].into(),
        products: vec!["billing".into()],
        roles: vec![],
    };
    super::super::declare::target(&op, &path, &target).unwrap();
    let id = plan_of(&path, &op).plan_id;
    let res = apply(&op, &path, "myapp", ACCOUNT, &id, &mut approve_all);
    (d, path, op, res)
}

#[test]
fn end_to_end_the_confirmed_plan_applies() {
    let (_d, _path, _op, res) = end_to_end();
    assert!(res.is_ok(), "{res:?}");
}

#[test]
fn end_to_end_the_new_target_gets_its_delivery_item() {
    let (_d, path, _op, _) = end_to_end();
    let fleet = crate::config::parse(&text(&path)).unwrap();
    assert!(
        fleet.environments["prod"].targets["billing"]
            .delivery_items
            .contains_key("billing")
    );
}

#[test]
fn end_to_end_every_declared_field_exists_empty() {
    let (_d, path, op, _) = end_to_end();
    let fleet = crate::config::parse(&text(&path)).unwrap();
    let b = fleet.boundary("prod", "billing").unwrap();
    let labels: BTreeSet<String> = op.item(&b.item_id)["fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["value"].as_str().unwrap_or_default().is_empty())
        .filter_map(|f| f["label"].as_str().map(str::to_string))
        .collect();
    assert!(
        ["STRIPE_KEY", "WEBHOOK_SECRET", "PUBLISHABLE_KEY"]
            .iter()
            .all(|k| labels.contains(*k)),
        "{labels:?}"
    );
}

#[test]
fn end_to_end_nothing_structural_is_left() {
    let (_d, path, op, _) = end_to_end();
    assert!(plan_of(&path, &op).is_empty());
}

#[test]
fn end_to_end_the_existing_shared_value_is_kept() {
    let (_d, _path, op, _) = end_to_end();
    assert!(
        serde_json::to_string(&*op.items.borrow())
            .unwrap()
            .contains(MARKER)
    );
}

// 0.10.0 error catalog (C2, 05.02, 05.14, 05.15, X4) ----------------------------------------

/// op 2.40.0's recorded reply to `op vault get <vault>` for a vault the account does not
/// hold (tests/fixtures/op/failures, case 14).
const NOT_A_VAULT_HERE: &str =
    include_str!("../../tests/fixtures/op/failures/14-vault-in-other-account.stderr");

/// The fake `op`, whose failed `op vault get` probes go through the observing fake runner
/// with op's recorded reply, as the real runner observes them.
struct Probed {
    op: FakeOp,
    get: FakeRunner,
}

impl Probed {
    fn new(op: FakeOp) -> Self {
        Probed {
            op,
            get: FakeRunner::default(),
        }
    }
}

impl CommandRunner for Probed {
    fn read(&self, call: &Call, refused: &[i32]) -> io::Result<Outcome> {
        self.op.read(call, refused)
    }
    fn write(&self, call: &Call) -> io::Result<Outcome> {
        self.op.write(call)
    }
    fn probe(&self, call: &Call, limit: Duration) -> io::Result<Output> {
        let answer = self.op.probe(call, limit)?;
        match call.args {
            ["vault", "get", vault, ..] if call.program == "op" && answer.status != 0 => {
                self.get.push_with_stderr(
                    Output::failure(1),
                    &NOT_A_VAULT_HERE.replace("<VAULT_B>", vault),
                );
                self.get.probe(call, limit)
            }
            _ => Ok(answer),
        }
    }
    fn pause(&self, _: Duration, _: &str) {}
    fn note(&self, _: &str) {}
    fn run_inherited(&self, _: &str, _: &[&str], _: &[(&str, &str)]) -> io::Result<i32> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// C2: an id that is not a structural plan id is unknown, not a changed plan.
#[test]
fn a_malformed_plan_id_is_plan_unknown() {
    let (_d, path, op) = workspace();
    let e = apply(&op, &path, "myapp", ACCOUNT, "not-a-plan", &mut approve_all).unwrap_err();
    assert_eq!(e.code_str(), "plan_unknown");
}

/// 05.15: a changed plan steps to its read, never to an approval an agent cannot give.
#[test]
fn a_stale_plan_id_steps_to_the_new_structural_plan() {
    let (_d, path, op) = workspace();
    let id = plan_of(&path, &op).plan_id;
    std::fs::write(
        &path,
        std::fs::read_to_string(&path).unwrap() + "\n# changed after review\n",
    )
    .unwrap();
    let e = apply(&op, &path, "myapp", ACCOUNT, &id, &mut approve_all).unwrap_err();
    assert_eq!(e.next_text().unwrap_or_default(), "opv structure plan");
}

/// 05.14, X4: after the approval was used, the step reads the new plan, never this apply
/// or the bootstrap dry run.
#[test]
fn a_configuration_changed_during_apply_steps_to_the_new_plan() {
    let (_d, path, op) = workspace();
    let id = plan_of(&path, &op).plan_id;
    let p2 = path.clone();
    let mut edit_during = move |_: &Plan| -> Result<(), Error> {
        std::fs::write(&p2, std::fs::read_to_string(&p2).unwrap() + "# edited\n").unwrap();
        Ok(())
    };
    let e = apply(&op, &path, "myapp", ACCOUNT, &id, &mut edit_during).unwrap_err();
    assert_eq!(e.next_text().unwrap_or_default(), "opv structure plan");
}

/// 05.14, X20: the failure says the approval is used up.
#[test]
fn a_configuration_changed_during_apply_never_claims_an_approval() {
    let (_d, path, op) = workspace();
    let id = plan_of(&path, &op).plan_id;
    let p2 = path.clone();
    let mut edit_during = move |_: &Plan| -> Result<(), Error> {
        std::fs::write(&p2, std::fs::read_to_string(&p2).unwrap() + "# edited\n").unwrap();
        Ok(())
    };
    let e = apply(&op, &path, "myapp", ACCOUNT, &id, &mut edit_during).unwrap_err();
    assert!(!e.to_string().contains("approval"), "{e}");
}

/// X4: a create that fails after the plan was authorized never steps to the apply again.
#[test]
fn a_partial_apply_steps_to_the_new_plan() {
    let (_d, path, r) = failing_at(3);
    let e = apply_reviewed(&path, &r).unwrap_err();
    assert_eq!(e.next_text().unwrap_or_default(), "opv structure plan");
}

/// X20: a partial apply names what it already created.
#[test]
fn a_partial_apply_names_what_it_created() {
    let (_d, path, r) = failing_at(3);
    let e = apply_reviewed(&path, &r).unwrap_err();
    assert!(e.to_string().contains("already written: boundary"));
}

/// 05.02: a checkout without a secrets.toml is never sent to opv bootstrap.
#[test]
fn a_checkout_without_a_file_never_steps_to_bootstrap() {
    let dir = tempfile::tempdir().unwrap();
    let e = scope(dir.path(), &FakeOp::default()).unwrap_err();
    assert!(!e.next_text().unwrap_or_default().contains("bootstrap"));
}
