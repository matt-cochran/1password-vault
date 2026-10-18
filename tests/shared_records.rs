//! FR-47 source-only products (shared records) and the core of FR-48 product scope, through
//! the public interface: one fleet fixture with a `shared` source-only product whose
//! `FLY_API_TOKEN` feeds `api` and `web` with `from`, on a Fly fleet environment.
//! Synthetic values only; every value carries `FIXTUREVALUE`.

use std::collections::BTreeSet;

use opv::domain::plan::{self, ItemField};
use opv::domain::{Fleet, Kind, SecretValue, StoreEntry, SyncPlan};
use opv::runner::fake::FakeRunner;

const FIXTURE: &str = "tests/fixtures/shared_records/secrets.toml";
const API: &str = "FLEET__API__FLY_API_TOKEN";
const WEB: &str = "FLEET__WEB__FLY_API_TOKEN";
const SHARED: &str = "FLEET__SHARED__FLY_API_TOKEN";

fn fleet() -> Fleet {
    opv::config::load(FIXTURE).unwrap()
}

fn field(section: &str, label: &str) -> ItemField {
    ItemField {
        section: section.into(),
        label: label.into(),
        kind: Kind::Secret,
        value: SecretValue::new("FIXTUREVALUE".into()),
        concealed: true,
    }
}

/// The item holding every key of the fixture, ready and rule-valid.
fn item() -> Vec<ItemField> {
    vec![
        field("api", "FLY_API_TOKEN"),
        field("shared", "FLY_API_TOKEN"),
        field("shared", "UNUSED_TOKEN"),
        field("web", "FLY_API_TOKEN"),
    ]
}

fn entry(name: &str) -> StoreEntry {
    StoreEntry {
        name: name.into(),
        version: None,
        pending: false,
        stamp: None,
    }
}

fn plan(item: Vec<ItemField>, on_store: &[StoreEntry]) -> SyncPlan {
    let none = BTreeSet::new();
    plan::build(&fleet(), "ci", item, on_store, &none, &|_| None)
}

#[test]
fn a_source_only_key_renders_no_staged_name() {
    let p = plan(item(), &[]);
    let staged: Vec<&str> = p.stage.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(staged, vec![API, WEB]);
}

#[test]
fn a_source_only_key_present_on_the_target_is_not_pruned() {
    let p = plan(item(), &[entry(SHARED)]);
    assert!(p.prune.is_empty());
}

#[test]
fn an_unused_source_only_key_is_reported_as_unreferenced() {
    let p = plan(item(), &[]);
    assert_eq!(
        p.unreferenced_sources,
        vec![("shared".to_string(), "UNUSED_TOKEN".to_string())]
    );
}

#[test]
fn run_refuses_a_source_only_product() {
    let r = FakeRunner::new([]);
    let e = opv::app::run::run(&fleet(), "ci", "shared", &["env".to_string()], &r).unwrap_err();
    assert_eq!(e.code_str(), "source_only");
}

#[test]
fn run_source_only_error_names_a_product_that_references_it() {
    let r = FakeRunner::new([]);
    let e = opv::app::run::run(&fleet(), "ci", "shared", &["env".to_string()], &r).unwrap_err();
    assert!(
        e.next_text()
            .as_deref()
            .is_some_and(|n| n.contains("--product api"))
    );
}

#[test]
fn local_selection_refuses_a_source_only_product() {
    let e = opv::app::local::select(&fleet(), "ci", Some("shared"), true).unwrap_err();
    assert_eq!(e.code_str(), "source_only");
}
