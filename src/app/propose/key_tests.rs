//! `opv propose key|env|retire` (design Part V, row `propose-key`): one atomic test per
//! behaviour, each with exactly one assertion on a public outcome.
//!
//! The intent comes from `intent::parse` (the one document form); the fleets come from
//! `config::parse`. No test here passes a runner: `propose` has no runner parameter, which
//! is the purity proof; `write` is the only function that touches a file.

use std::fs;

use super::*;
use crate::config::bindings::Bindings;
use crate::domain::intent;
use crate::domain::relaxation::RelaxationKind;

/// The `dev` (shared) environment and one product `app` with a key that lists `dev`, so a
/// new environment does not need a boundary of its own.
const DEV: &str = "[environments.dev]\ntier = \"shared\"\n\
                   boundaries.app = { vault_id = \"vdev0000000000000000000001\", item_id = \"app\" }\n\n\
                   [products.app.keys.EXISTING_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\n";

/// `DEV` plus a production environment `prod`; `EXISTING_KEY` lists neither, so it is
/// present in every environment (the presence default) and asks its production question.
const DEV_PROD: &str = "[environments.dev]\ntier = \"shared\"\n\
                        boundaries.app = { vault_id = \"vdev0000000000000000000001\", item_id = \"app\" }\n\n\
                        [environments.prod]\ntier = \"production\"\n\
                        boundaries.app = { vault_id = \"vprod000000000000000000001\", item_id = \"app\" }\n\n\
                        [products.app.keys.EXISTING_KEY]\nkind = \"secret\"\n";

/// Two products on `dev`/`prod`: `app` and `web` each have one key with an explicit list
/// and one present everywhere (no list), so the extend behaviour is observable per key.
const EXTEND: &str = "[environments.dev]\ntier = \"shared\"\n\
                      boundaries.app = { vault_id = \"vdev0000000000000000000001\", item_id = \"app\" }\n\
                      boundaries.web = { vault_id = \"vdev0000000000000000000001\", item_id = \"web\" }\n\n\
                      [environments.prod]\ntier = \"production\"\n\
                      boundaries.app = { vault_id = \"vprod000000000000000000001\", item_id = \"app\" }\n\n\
                      [products.app.keys.EXPLICIT_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\n\n\
                      [products.app.keys.ALL_KEY]\nkind = \"config\"\n\n\
                      [products.web.keys.WEB_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\n";

fn key_intent(json: &str) -> intent::Intent {
    intent::parse(json).expect("the intent parses")
}

/// The non-blank `+` lines a proposal's diff adds, without their marker.
fn added(diff: &str) -> Vec<&str> {
    diff.lines()
        .filter_map(|l| l.strip_prefix('+'))
        .filter(|l| !l.is_empty())
        .collect()
}

#[test]
fn a_key_proposal_diff_adds_the_key() {
    let intent =
        key_intent(r#"{"kind":"key","key":"NEW_KEY","product":"app","field_kind":"secret"}"#);
    let proposal = propose(DEV, &Bindings::default(), None, &intent).unwrap();
    assert!(proposal.diff.contains("+[products.app.keys.NEW_KEY]"));
}

#[test]
fn a_key_reaching_a_new_environment_declares_its_products_boundary_there() {
    let contract = format!("{DEV}\n[environments.prod]\ntier = \"production\"\n");
    let intent = key_intent(
        r#"{"kind":"key","key":"EXISTING_KEY","product":"app","field_kind":"secret","environments":["dev","prod"]}"#,
    );
    let proposal = propose(&contract, &Bindings::default(), None, &intent).unwrap();
    assert!(added(&proposal.diff).contains(&"boundaries.app = {}"));
}

#[test]
fn a_new_key_without_environments_writes_no_environments_line() {
    let intent =
        key_intent(r#"{"kind":"key","key":"NEW_KEY","product":"app","field_kind":"secret"}"#);
    let proposal = propose(DEV, &Bindings::default(), None, &intent).unwrap();
    assert!(!proposal.diff.contains("+environments"));
}

#[test]
fn a_production_tier_environment_yields_the_question() {
    let intent =
        key_intent(r#"{"kind":"key","key":"NEW_KEY","product":"app","field_kind":"secret"}"#);
    let proposal = propose(DEV_PROD, &Bindings::default(), None, &intent).unwrap();
    assert_eq!(
        proposal.questions,
        vec![Question {
            env: "prod".to_string(),
            ask: "a value, or except?".to_string(),
        }]
    );
}

#[test]
fn an_expiry_date_reaches_the_proposed_contract() {
    let intent = key_intent(
        r#"{"kind":"key","key":"NEW_KEY","product":"app","field_kind":"secret","expires":"2027-01-31"}"#,
    );
    let proposal = propose(DEV, &Bindings::default(), None, &intent).unwrap();
    assert!(added(&proposal.diff).contains(&"expires = \"2027-01-31\""));
}

#[test]
fn a_key_excepted_from_a_production_environment_asks_nothing() {
    let intent = key_intent(
        r#"{"kind":"key","key":"NEW_KEY","product":"app","field_kind":"secret","except":{"prod":"no prod account"}}"#,
    );
    let proposal = propose(DEV_PROD, &Bindings::default(), None, &intent).unwrap();
    assert!(proposal.questions.is_empty());
}

#[test]
fn an_allow_same_value_change_lists_it_first() {
    let working = "[environments.dev]\ntier = \"shared\"\n\
                   boundaries.app = { vault_id = \"vdev0000000000000000000001\", item_id = \"app\" }\n\n\
                   [products.app.keys.EXISTING_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\n";
    let base = crate::config::parse(working).unwrap();
    let intent = key_intent(
        r#"{"kind":"key","key":"EXISTING_KEY","product":"app","field_kind":"secret","allow_same_value":true}"#,
    );
    let proposal = propose(working, &Bindings::default(), Some(&base), &intent).unwrap();
    assert_eq!(
        proposal.relaxations[0].kind,
        RelaxationKind::AllowSameValueAdded
    );
}

#[test]
fn a_shape_writes_the_catalogs_rules() {
    let intent =
        key_intent(r#"{"kind":"key","key":"NEW_KEY","product":"app","shape":"base64_bytes_32"}"#);
    let proposal = propose(DEV, &Bindings::default(), None, &intent).unwrap();
    assert!(
        added(&proposal.diff)
            .iter()
            .any(|l| l.contains("base64_bytes = 32"))
    );
}

#[test]
fn an_env_proposal_adds_the_environment_with_its_tier() {
    let intent = key_intent(r#"{"kind":"env","env":"staging","tier":"production"}"#);
    let proposal = propose(DEV, &Bindings::default(), None, &intent).unwrap();
    assert_eq!(
        added(&proposal.diff),
        vec!["[environments.staging]", "tier = \"production\""]
    );
}

/// #179: a new environment inherits every key with no list, so its products' boundaries are
/// declared there and the proposal loads.
#[test]
fn an_env_proposal_declares_the_boundary_of_an_inherited_key() {
    let intent = key_intent(r#"{"kind":"env","env":"qa","tier":"shared"}"#);
    let proposal = propose(DEV_PROD, &Bindings::default(), None, &intent).unwrap();
    assert_eq!(
        added(&proposal.diff),
        vec![
            "[environments.qa]",
            "tier = \"shared\"",
            "boundaries.app = {}"
        ]
    );
}

#[test]
fn a_retire_proposal_marks_the_key_retiring() {
    let intent = key_intent(r#"{"kind":"retire","key":"EXISTING_KEY","product":"app"}"#);
    let proposal = propose(DEV, &Bindings::default(), None, &intent).unwrap();
    assert!(
        added(&proposal.diff)
            .iter()
            .any(|l| l.contains("lifecycle = \"retiring\""))
    );
}

#[test]
fn the_same_intent_twice_gives_the_same_plan_id() {
    let intent =
        key_intent(r#"{"kind":"key","key":"NEW_KEY","product":"app","field_kind":"secret"}"#);
    let first = propose(DEV, &Bindings::default(), None, &intent).unwrap();
    let second = propose(DEV, &Bindings::default(), None, &intent).unwrap();
    assert_eq!(first.plan_id, second.plan_id);
}

#[test]
fn propose_leaves_the_contract_on_disk_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.toml");
    fs::write(&path, DEV).unwrap();
    let intent =
        key_intent(r#"{"kind":"key","key":"NEW_KEY","product":"app","field_kind":"secret"}"#);
    propose(
        &fs::read_to_string(&path).unwrap(),
        &Bindings::default(),
        None,
        &intent,
    )
    .unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), DEV);
}

#[test]
fn write_replaces_the_contract_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.toml");
    fs::write(&path, DEV).unwrap();
    let changed = format!("{DEV}\n");
    write(&path, &changed).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), changed);
}

#[test]
fn write_leaves_every_other_file_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.toml");
    let other = dir.path().join("notes.txt");
    fs::write(&path, DEV).unwrap();
    fs::write(&other, "notes").unwrap();
    write(&path, &format!("{DEV}\n")).unwrap();
    assert_eq!(fs::read_to_string(&other).unwrap(), "notes");
}

// #179 B4: one proposal extends an environment to every explicit-list key -----------------

#[test]
fn an_extend_proposal_adds_the_environment_to_an_explicit_list_key() {
    let intent = key_intent(r#"{"kind":"extend","env":"prod","product":"app"}"#);
    let proposal = propose(EXTEND, &Bindings::default(), None, &intent).unwrap();
    assert!(added(&proposal.diff).contains(&"environments = [\"dev\", \"prod\"]"));
}

#[test]
fn an_extend_proposal_leaves_a_key_without_an_explicit_list_untouched() {
    let intent = key_intent(r#"{"kind":"extend","env":"prod","product":"app"}"#);
    let proposal = propose(EXTEND, &Bindings::default(), None, &intent).unwrap();
    assert!(!added(&proposal.diff).iter().any(|l| l.contains("ALL_KEY")));
}

#[test]
fn an_extend_proposal_without_a_product_reaches_every_products_explicit_list_keys() {
    let intent = key_intent(r#"{"kind":"extend","env":"prod"}"#);
    let proposal = propose(EXTEND, &Bindings::default(), None, &intent).unwrap();
    let changed = added(&proposal.diff)
        .iter()
        .filter(|l| **l == "environments = [\"dev\", \"prod\"]")
        .count();
    assert_eq!(changed, 2);
}

#[test]
fn an_extend_proposal_reports_the_extend_kind() {
    let intent = key_intent(r#"{"kind":"extend","env":"prod","product":"app"}"#);
    let proposal = propose(EXTEND, &Bindings::default(), None, &intent).unwrap();
    assert_eq!(proposal.kind, "extend");
}

#[test]
fn an_extend_to_an_already_listed_environment_changes_nothing() {
    let intent = key_intent(r#"{"kind":"extend","env":"dev","product":"app"}"#);
    let proposal = propose(EXTEND, &Bindings::default(), None, &intent).unwrap();
    assert!(added(&proposal.diff).is_empty());
}

#[test]
fn an_extend_to_an_undeclared_environment_is_refused() {
    let intent = key_intent(r#"{"kind":"extend","env":"staging","product":"app"}"#);
    let e = propose(EXTEND, &Bindings::default(), None, &intent).unwrap_err();
    assert_eq!(e.code_str(), "unknown_env");
}

#[test]
fn an_extend_of_an_undeclared_product_is_refused() {
    let intent = key_intent(r#"{"kind":"extend","env":"prod","product":"ghost"}"#);
    let e = propose(EXTEND, &Bindings::default(), None, &intent).unwrap_err();
    assert_eq!(e.code_str(), "unknown_product");
}

#[test]
fn an_extend_on_a_generated_configuration_returns_the_fragment() {
    let generated = format!("# GENERATED by fleet_secrets.py from catalog.json\n{EXTEND}");
    let intent = key_intent(r#"{"kind":"extend","env":"prod","product":"app"}"#);
    let proposal = propose(&generated, &Bindings::default(), None, &intent).unwrap();
    assert!(proposal.for_generator.is_some());
}

#[test]
fn a_contract_without_ids_is_validated_with_its_bindings() {
    let (contract, bindings) = crate::config::bindings::split(DEV);
    let intent =
        key_intent(r#"{"kind":"key","key":"NEW_KEY","product":"app","field_kind":"secret"}"#);
    assert!(propose(&contract, &bindings, None, &intent).is_ok());
}
