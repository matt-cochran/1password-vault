//! `opv propose setup` (design Part V, row `propose-setup`): one atomic test per behaviour,
//! each with exactly one assertion on a public outcome. A `.env` value never reaches the
//! serialized proposal; a contract built from an item carries no id (D-G).

use std::path::PathBuf;

use super::*;
use crate::adapters::fake_op::FakeOp;
use crate::app::testutil::{self, Field};

/// A private `.env` in a fresh directory (a private file, as `read_legacy` requires).
fn env_file(text: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dev.env");
    std::fs::write(&path, text).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    (dir, path)
}

/// The key names a contract diff declares, in the order it writes them.
fn declared(diff: &str) -> Vec<String> {
    diff.lines()
        .filter_map(|l| l.strip_prefix('+'))
        .filter_map(|l| l.strip_prefix("[products."))
        .filter_map(|l| l.split_once(".keys."))
        .map(|(_, rest)| rest.trim_end_matches(']').to_string())
        .collect()
}

/// A private `.env` and an existing `secrets.toml` in a fresh directory: the setup a person
/// runs against a project that already has a contract.
fn env_with_contract(dotenv: &str, contract: &str) -> (tempfile::TempDir, PathBuf, PathBuf) {
    let (dir, env) = env_file(dotenv);
    let toml = dir.path().join("secrets.toml");
    std::fs::write(&toml, contract).unwrap();
    (dir, env, toml)
}

/// An existing contract: `dev` of tier shared with one declared secret, no ids (D-G).
const EXISTING_CONTRACT: &str = r#"[environments.dev]
tier = "shared"
boundaries.app = {}

[products.app.keys.ALPHA]
kind = "secret"
environments = ["dev"]
"#;

/// A `FakeOp` holding one item built by [`testutil::item_json`] (an `op item get` reply).
fn op_with_item(fields: &[Field]) -> FakeOp {
    let op = FakeOp::default();
    let item: serde_json::Value = serde_json::from_slice(&testutil::item_json(fields)).unwrap();
    op.insert("myapp-dev", item);
    op
}

const ITEM_TITLE: &str = "fleet";

fn item_fields() -> Vec<Field> {
    vec![
        testutil::secret("api", "OPENAI_API_KEY", &format!("sk-{}", testutil::MARKER)),
        testutil::text("api", "SIGNUP_POLICY", testutil::POLICY),
    ]
}

// From a `.env`'s names ------------------------------------------------------------------

#[test]
fn names_declare_every_name() {
    let (_dir, path) = env_file("ALPHA=one\nBETA=two\n");
    let p = from_names(&path, "dev", &[], &[]).unwrap();
    assert_eq!(declared(&p.proposal.diff), ["ALPHA", "BETA"]);
}

#[test]
fn names_declare_an_environment_of_tier_local() {
    let (_dir, path) = env_file("ALPHA=one\n");
    let p = from_names(&path, NAMES_ENV, &[], &[]).unwrap();
    let fleet = crate::config::parse(&p.proposal.contract_after).unwrap();
    assert_eq!(
        fleet.environments[NAMES_ENV].tier,
        crate::domain::Tier::Local
    );
}

#[test]
fn names_apply_a_secret_key_override() {
    let (_dir, path) = env_file("APP_PORT=8080\n");
    let p = from_names(&path, "dev", &[], &["APP_PORT".to_string()]).unwrap();
    assert!(p.proposal.diff.contains("+kind = \"secret\""));
}

#[test]
fn a_name_in_both_lists_is_refused() {
    let (_dir, path) = env_file("ALPHA=one\n");
    let both = vec!["ALPHA".to_string()];
    assert!(from_names(&path, "dev", &both, &both).is_err());
}

#[test]
fn a_dotenv_value_never_reaches_the_serialized_proposal() {
    let (_dir, path) = env_file("LEAK_CHECK=S7MARKER\n");
    let p = from_names(&path, "dev", &[], &[]).unwrap();
    assert!(!serde_json::to_string(&p).unwrap().contains("S7MARKER"));
}

// Against an existing contract -------------------------------------------------------------

#[test]
fn names_against_an_existing_contract_add_only_undeclared_keys() {
    let (_dir, path, toml) = env_with_contract("ALPHA=one\nBETA=two\n", EXISTING_CONTRACT);
    let p = from_names_in(&path, "dev", &[], &[], Some(&toml)).unwrap();
    assert_eq!(declared(&p.proposal.diff), ["BETA"]);
}

#[test]
fn names_against_an_existing_contract_never_re_propose_its_environment_table() {
    let (_dir, path, toml) = env_with_contract("BETA=two\n", EXISTING_CONTRACT);
    let p = from_names_in(&path, "dev", &[], &[], Some(&toml)).unwrap();
    assert!(!p.proposal.diff.contains("+[environments.dev]"));
}

#[test]
fn names_into_a_named_environment_keep_its_tier() {
    let (_dir, path, toml) = env_with_contract("BETA=two\n", EXISTING_CONTRACT);
    let p = from_names_in(&path, "dev", &[], &[], Some(&toml)).unwrap();
    let fleet = crate::config::parse(&p.proposal.contract_after).unwrap();
    assert_eq!(fleet.environments["dev"].tier, crate::domain::Tier::Shared);
}

#[test]
fn names_into_a_fresh_setup_declare_the_named_environment() {
    let (_dir, path) = env_file("BETA=two\n");
    let p = from_names_in(&path, "staging", &[], &[], None).unwrap();
    let fleet = crate::config::parse(&p.proposal.contract_after).unwrap();
    assert!(fleet.environments.contains_key("staging"));
}

#[test]
fn a_names_proposal_names_the_value_import_step() {
    let (_dir, path, _toml) = env_with_contract("BETA=two\n", EXISTING_CONTRACT);
    let p = from_names_in(&path, "dev", &[], &[], None).unwrap();
    assert!(
        p.next
            .as_deref()
            .is_some_and(|s| s.starts_with("opv import dev --from "))
    );
}

#[test]
fn an_existing_contracts_names_proposal_never_carries_a_dotenv_value() {
    let (_dir, path, toml) = env_with_contract("LEAK_CHECK=S7MARKER\n", EXISTING_CONTRACT);
    let p = from_names_in(&path, "dev", &[], &[], Some(&toml)).unwrap();
    assert!(!serde_json::to_string(&p).unwrap().contains("S7MARKER"));
}

// From an item ---------------------------------------------------------------------------

#[test]
fn item_fields_are_declared() {
    let op = op_with_item(&item_fields());
    let p = from_item(&op, "dev", Some("myapp-dev"), Some(ITEM_TITLE), None).unwrap();
    assert_eq!(
        declared(&p.proposal.diff),
        ["OPENAI_API_KEY", "SIGNUP_POLICY"]
    );
}

#[test]
fn the_contract_holds_no_item_or_vault_id() {
    let op = op_with_item(&item_fields());
    let p = from_item(&op, "dev", Some("myapp-dev"), Some(ITEM_TITLE), None).unwrap();
    assert!(!p.proposal.diff.contains("vault_id") && !p.proposal.diff.contains("item_id"));
}

#[test]
fn an_item_proposal_carries_the_items_ids_for_the_bindings_file() {
    let op = op_with_item(&item_fields());
    let p = from_item(&op, "dev", Some("myapp-dev"), Some(ITEM_TITLE), None).unwrap();
    assert!(p.bindings_after.is_some_and(|b| b.contains("item_id")));
}
