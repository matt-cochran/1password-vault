use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::config;
use crate::domain::plan::{self, ItemField};
use crate::domain::{Fleet, SecretValue};

const NAME: &str = "FLEET__ALLUMATA__SIGNUP_POLICY";

/// A variable store holding `vars` that refuses nothing.
struct FakeVars {
    vars: BTreeMap<String, String>,
    listed: RefCell<u32>,
}

impl FakeVars {
    fn with(vars: &[(&str, &str)]) -> Self {
        Self {
            vars: vars
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect(),
            listed: RefCell::new(0),
        }
    }
}

impl VariableStore for FakeVars {
    fn list(&self) -> Result<BTreeMap<String, String>, Error> {
        *self.listed.borrow_mut() += 1;
        Ok(self.vars.clone())
    }
    fn refusal(&self, _name: &str, _value: &str) -> Option<(&'static str, &'static str)> {
        None
    }
    fn set(&self, _batch: &[(String, &str)]) -> Result<(), Error> {
        unreachable!("planning never writes")
    }
    fn remove(&self, _names: &[String]) -> Result<(), Error> {
        unreachable!("planning never writes")
    }
}

fn fleet() -> Fleet {
    config::load("tests/fixtures/secrets.toml").unwrap()
}

fn signup(value: &str, concealed: bool) -> ItemField {
    ItemField {
        section: "allumata".into(),
        label: "SIGNUP_POLICY".into(),
        kind: Kind::Config,
        value: SecretValue::new(value.into()),
        concealed,
    }
}

/// The staging plan of an item holding only SIGNUP_POLICY, and its variable plan.
fn planned(field: Option<ItemField>, vars: &FakeVars) -> (SyncPlan, VarPlan) {
    let f = fleet();
    let mut p = plan::build(
        &f,
        "staging",
        field.into_iter().collect(),
        &[],
        &BTreeSet::new(),
        &|_| None,
    );
    let (name, t) = f.environments["staging"]
        .targets
        .iter()
        .next()
        .map(|(n, t)| (n.clone(), t.config.as_ref()))
        .unwrap();
    let v = super::plan(&f, "staging", &name, t, &mut p, vars, &|_| true).unwrap();
    (p, v)
}

fn row_state(p: &SyncPlan) -> &KeyState {
    &p.rows
        .iter()
        .find(|r| r.key == "SIGNUP_POLICY")
        .unwrap()
        .state
}

fn row_target(p: &SyncPlan) -> TargetState {
    p.rows
        .iter()
        .find(|r| r.key == "SIGNUP_POLICY")
        .unwrap()
        .target
}

#[test]
fn an_absent_variable_is_set() {
    let (_, v) = planned(Some(signup("open", false)), &FakeVars::with(&[]));
    assert_eq!(v.set, [NAME]);
}

#[test]
fn an_equal_variable_is_unchanged() {
    let (_, v) = planned(
        Some(signup("open", false)),
        &FakeVars::with(&[(NAME, "open")]),
    );
    assert_eq!(v.unchanged, [NAME]);
}

#[test]
fn a_differing_variable_is_set() {
    let vars = FakeVars::with(&[(NAME, "invite_only")]);
    let (_, v) = planned(Some(signup("open", false)), &vars);
    assert_eq!(v.set, [NAME]);
}

#[test]
fn a_differing_variable_shows_would_change() {
    let vars = FakeVars::with(&[(NAME, "invite_only")]);
    let (p, _) = planned(Some(signup("open", false)), &vars);
    assert_eq!(row_target(&p), TargetState::WouldChange);
}

#[test]
fn an_equal_variable_shows_present() {
    let (p, _) = planned(
        Some(signup("open", false)),
        &FakeVars::with(&[(NAME, "open")]),
    );
    assert_eq!(row_target(&p), TargetState::Present);
}

#[test]
fn a_concealed_config_field_fails_its_rule() {
    let (p, _) = planned(Some(signup("open", true)), &FakeVars::with(&[]));
    assert_eq!(
        row_state(&p),
        &KeyState::RuleFailed(CONCEALED_RULE, Reason::Fixed(CONCEALED_REASON))
    );
}

/// 01.01: a key this target refuses is not "delivered as a plain environment value".
#[test]
fn a_refused_concealed_config_field_is_not_listed_as_delivered() {
    let (p, _) = planned(Some(signup("open", true)), &FakeVars::with(&[]));
    assert!(p.concealed_config.is_empty());
}

#[test]
fn a_concealed_config_field_is_never_set() {
    let (_, v) = planned(Some(signup("open", true)), &FakeVars::with(&[]));
    assert!(v.want.is_empty());
}

#[test]
fn a_store_refusal_fails_the_row() {
    struct RefuseAll;
    impl VariableStore for RefuseAll {
        fn list(&self) -> Result<BTreeMap<String, String>, Error> {
            Ok(BTreeMap::new())
        }
        fn refusal(&self, _: &str, _: &str) -> Option<(&'static str, &'static str)> {
            Some(("fake-rule", "fake reason"))
        }
        fn set(&self, _: &[(String, &str)]) -> Result<(), Error> {
            unreachable!()
        }
        fn remove(&self, _: &[String]) -> Result<(), Error> {
            unreachable!()
        }
    }
    let f = fleet();
    let mut p = plan::build(
        &f,
        "staging",
        vec![signup("open", false)],
        &[],
        &BTreeSet::new(),
        &|_| None,
    );
    let (name, t) = f.environments["staging"]
        .targets
        .iter()
        .next()
        .map(|(n, t)| (n.clone(), t.config.as_ref()))
        .unwrap();
    super::plan(&f, "staging", &name, t, &mut p, &RefuseAll, &|_| true).unwrap();
    assert_eq!(
        row_state(&p),
        &KeyState::RuleFailed("fake-rule", Reason::Fixed("fake reason"))
    );
}

#[test]
fn a_failing_key_keeps_its_variable_from_prune() {
    // `banned` breaks the key's enum rule: the row blocks, and its variable stays.
    let vars = FakeVars::with(&[(NAME, "open")]);
    let (_, v) = planned(Some(signup("banned", false)), &vars);
    assert!(v.prune.is_empty());
}

#[test]
fn a_managed_variable_no_key_wants_is_pruned() {
    let f = fleet();
    // prod declares SIGNUP_POLICY too; drop it from staging to make it undesired there.
    let mut f2 = f.clone();
    f2.products
        .get_mut("allumata")
        .unwrap()
        .keys
        .get_mut("SIGNUP_POLICY")
        .unwrap()
        .environments
        .retain(|e| e != "staging");
    let mut p = plan::build(&f2, "staging", vec![], &[], &BTreeSet::new(), &|_| None);
    let (name, t) = f2.environments["staging"]
        .targets
        .iter()
        .next()
        .map(|(n, t)| (n.clone(), t.config.as_ref()))
        .unwrap();
    let vars = FakeVars::with(&[(NAME, "open")]);
    let v = super::plan(&f2, "staging", &name, t, &mut p, &vars, &|_| true).unwrap();
    assert_eq!(v.prune, [NAME]);
}

#[test]
fn an_unmanaged_variable_is_never_pruned() {
    let vars = FakeVars::with(&[("OTHER_TOOL_SETTING", "x")]);
    let (_, v) = planned(Some(signup("open", false)), &vars);
    assert!(v.prune.is_empty());
}

#[test]
fn an_out_of_scope_name_is_neither_set_nor_pruned() {
    let f = fleet();
    let mut p = plan::build(
        &f,
        "staging",
        vec![signup("open", false)],
        &[],
        &BTreeSet::new(),
        &|_| None,
    );
    let (name, t) = f.environments["staging"]
        .targets
        .iter()
        .next()
        .map(|(n, t)| (n.clone(), t.config.as_ref()))
        .unwrap();
    let v = super::plan(
        &f,
        "staging",
        &name,
        t,
        &mut p,
        &FakeVars::with(&[]),
        &|_| false,
    )
    .unwrap();
    assert_eq!(v, VarPlan::default());
}

#[test]
fn planning_lists_the_variables_once() {
    let vars = FakeVars::with(&[]);
    planned(Some(signup("open", false)), &vars);
    assert_eq!(*vars.listed.borrow(), 1);
}

// Wording found in the live smoke (FR-46, FR-47) ----------------------------------------

#[test]
fn an_undelivered_row_reads_not_applicable() {
    let row = crate::domain::Row {
        product: "shared".into(),
        key: "DEPLOY_TOKEN".into(),
        kind: Kind::Secret,
        state: KeyState::Ready,
        target: TargetState::NotDelivered,
        guidance: String::new(),
        source: None,
        shared_by: Vec::new(),
    };
    assert_eq!(crate::app::target_word(&row, false, None), "n/a");
}

#[test]
fn the_unknown_legend_of_a_live_target_says_it_writes_again() {
    let mut out = Vec::new();
    crate::app::print_legend(&mut out, &["unknown"], "GitHub", true).unwrap();
    assert!(
        String::from_utf8(out)
            .unwrap()
            .contains("every sync writes them again"),
    );
}

#[test]
fn the_unknown_legend_of_a_staging_target_keeps_its_digest_wording() {
    let mut out = Vec::new();
    crate::app::print_legend(&mut out, &["unknown"], "Fly", false).unwrap();
    assert!(
        String::from_utf8(out)
            .unwrap()
            .contains("sync stages them and compares digests"),
    );
}
