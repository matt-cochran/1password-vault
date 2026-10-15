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
