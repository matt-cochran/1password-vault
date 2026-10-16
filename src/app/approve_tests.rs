//! #133: `opv approve` records an approval only for the current plan, typed back.

use std::cell::RefCell;

use super::*;
use crate::adapters::fake_op::FakeOp;

const ACCOUNT: &str = "ACCOUNTAAA000000000000AAAA";

const FLEET: &str = r#"[environments.dev]

[products.api.keys.API_TOKEN]
kind = "secret"
environments = ["dev"]
"#;

struct Typed {
    answer: String,
    shown: RefCell<Vec<String>>,
}

impl Review for Typed {
    fn show(&mut self, line: &str) -> Result<(), Error> {
        self.shown.borrow_mut().push(line.to_string());
        Ok(())
    }
    fn ask(&mut self, _: &str) -> Result<String, Error> {
        Ok(self.answer.clone())
    }
}

fn setup(text: &str) -> (tempfile::TempDir, Scope, FakeOp) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.toml");
    std::fs::write(&path, text).unwrap();
    let scope = Scope {
        path,
        project: "myapp".into(),
        account: ACCOUNT.into(),
    };
    (dir, scope, FakeOp::default())
}

fn current_id(scope: &Scope, op: &FakeOp) -> String {
    let text = std::fs::read_to_string(&scope.path).unwrap();
    structure::plan(op, &text, &scope.project, &scope.account)
        .unwrap()
        .plan_id
}

/// The approvals `approve` recorded, as `plan project account`.
fn approve(scope: &Scope, op: &FakeOp, id: &str, answer: &str) -> (Result<(), Error>, Vec<String>) {
    let mut recorded = Vec::new();
    let mut ui = Typed {
        answer: answer.into(),
        shown: RefCell::new(Vec::new()),
    };
    let res = run(op, scope, id, 1_000, &mut ui, &mut |p, proj, acct, _| {
        recorded.push(format!("{p} {proj} {acct}"));
        Ok(())
    });
    (res, recorded)
}

#[test]
fn typing_the_plan_id_back_records_the_approval_for_its_scope() {
    let (_d, scope, op) = setup(FLEET);
    let id = current_id(&scope, &op);
    let (_, recorded) = approve(&scope, &op, &id, &id);
    assert_eq!(recorded, [format!("{id} myapp {ACCOUNT}")]);
}

#[test]
fn any_other_answer_records_nothing() {
    let (_d, scope, op) = setup(FLEET);
    let id = current_id(&scope, &op);
    let (_, recorded) = approve(&scope, &op, &id, "y");
    assert!(recorded.is_empty());
}

#[test]
fn a_stale_plan_id_is_refused() {
    let (_d, scope, op) = setup(FLEET);
    let (res, _) = approve(&scope, &op, "sp-0000000000000000", "sp-0000000000000000");
    assert_eq!(res.unwrap_err().code().as_str(), "stale_plan");
}

#[test]
fn a_stale_plan_id_records_nothing() {
    let (_d, scope, op) = setup(FLEET);
    let (_, recorded) = approve(&scope, &op, "sp-0000000000000000", "sp-0000000000000000");
    assert!(recorded.is_empty());
}

#[test]
fn a_malformed_plan_id_is_a_usage_error() {
    let (_d, scope, op) = setup(FLEET);
    let (res, _) = approve(&scope, &op, "approve-everything", "approve-everything");
    assert_eq!(res.unwrap_err().code().as_str(), "usage");
}

#[test]
fn the_review_names_each_vault_it_would_create() {
    let (_d, scope, op) = setup(FLEET);
    let id = current_id(&scope, &op);
    let mut ui = Typed {
        answer: String::new(),
        shown: RefCell::new(Vec::new()),
    };
    let _ = run(&op, &scope, &id, 1_000, &mut ui, &mut |_, _, _, _| Ok(()));
    assert!(
        ui.shown
            .borrow()
            .iter()
            .any(|l| l.contains("create vault \"myapp-api-dev\""))
    );
}

// 0.10.0 error catalog (05.16, 05.24, 05.33, X1, X4) -----------------------------------------

/// 05.24: a sync plan id given without --sync says what it needs.
#[test]
fn a_sync_plan_id_without_sync_says_it_needs_sync() {
    let (_d, scope, op) = setup(FLEET);
    let (res, _) = approve(&scope, &op, "3f9c0a1b", "3f9c0a1b");
    assert!(res.unwrap_err().to_string().contains("--sync <env>"));
}

/// 05.33: after approving, the CLI path is named too.
#[test]
fn approving_names_the_apply_command() {
    let (_d, scope, op) = setup(FLEET);
    let id = current_id(&scope, &op);
    let mut ui = Typed {
        answer: id.clone(),
        shown: RefCell::new(Vec::new()),
    };
    run(&op, &scope, &id, 1_000, &mut ui, &mut |_, _, _, _| Ok(())).unwrap();
    assert_eq!(
        ui.shown.borrow().last().cloned(),
        Some(format!(
            "Next: opv structure apply {id} (or let the assistant apply it)"
        ))
    );
}

/// 05.33: one of a thing is singular.
#[test]
fn one_vault_is_singular() {
    assert_eq!(count(1, "vault"), "1 vault");
}

fn row(action: Option<&str>, state: &str) -> serde_json::Value {
    serde_json::json!({
        "product": "api", "key": "API_TOKEN", "target": "web",
        "action": action, "state": state,
    })
}

/// 05.16: a missing value is shown, with what it does to the sync.
#[test]
fn the_sync_review_names_a_missing_value() {
    let lines = review_lines(&[row(None, "missing")], false);
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("  missing api/API_TOKEN"))
    );
}

/// 05.16: "every managed name already matches" is never said over a missing value.
#[test]
fn the_sync_review_never_claims_a_match_over_a_missing_value() {
    let lines = review_lines(&[row(None, "missing")], false);
    assert!(!lines.iter().any(|l| l.contains("already matches")));
}

/// 05.16: a held row is shown.
#[test]
fn the_sync_review_names_a_held_row() {
    let lines = review_lines(&[row(Some("held"), "saved")], false);
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("  held api/API_TOKEN on web"))
    );
}

fn east() -> SyncScope {
    SyncScope {
        env: "prod".into(),
        targets: vec!["east".into()],
        product: None,
        deploy: false,
        prune: false,
        rotate: vec!["api/JWT_KEY".into()],
    }
}

/// X1: the approval store reads back the typed scope of a sync scope key.
#[test]
fn a_sync_scope_key_reads_back_as_its_typed_scope() {
    assert_eq!(
        crate::approval::plan_scope(&east().key()),
        east().plan_scope()
    );
}

/// X4: a failure after the approval was used steps to the read of what remains in the
/// same scope, never to `--approved` again.
#[test]
fn a_failure_after_an_approved_sync_steps_to_the_plan_of_its_scope() {
    let e: Error = Cause::ChangedBeforeWrite {
        object: crate::cause::StoreObject::File {
            path: "secrets.toml".into(),
        },
    }
    .into();
    assert_eq!(
        after_used_approval(e, "0a1b2c3d", &east())
            .step("", "")
            .next,
        "opv plan prod --target east --rotate api/JWT_KEY"
    );
}

#[test]
fn a_malformed_plan_id_is_a_usage_error_before_any_terminal() {
    // 09.27: checked before the terminal gate, so it is exit 2, never terminal_required.
    assert_eq!(check_structural_id("nonsense").unwrap_err().exit_code(), 2);
}
