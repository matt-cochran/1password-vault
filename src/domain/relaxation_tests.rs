//! Relaxation classification (design Part V, row `relaxations`): one atomic test per kind
//! through the public `relaxations` classifier. Fleets come from `config::parse`.
//!
//! One assertion per test: the classifier's outcome. No value, rule parameter or digest is
//! ever in scope here.

use super::{Relaxation, RelaxationKind, relaxations};
use crate::config::parse;

/// The `dev` (shared) and `prod` (production) environments of every fixture, each with the
/// boundary the product `app` lives in.
const ENVS: &str = "[environments.dev]\ntier = \"shared\"\n\
                    boundaries.app = { vault_id = \"vdev0000000000000000000001\", item_id = \"app\" }\n\n\
                    [environments.prod]\ntier = \"production\"\n\
                    boundaries.app = { vault_id = \"vprod000000000000000000001\", item_id = \"app\" }\n\n";

/// A contract with the two environments and one product `app` whose single key `API_KEY`
/// is declared by `key_body`.
fn contract(key_body: &str) -> String {
    format!("{ENVS}[products.app.keys.API_KEY]\n{key_body}")
}

/// `contract`, plus a second key `OTHER_KEY` that stays in every environment so a narrowed
/// `API_KEY` does not leave an environment's boundary unused.
fn contract_with_other(key_body: &str) -> String {
    format!(
        "{ENVS}[products.app.keys.API_KEY]\n{key_body}\n\
         [products.app.keys.OTHER_KEY]\nkind = \"secret\"\n"
    )
}

/// Classify the working contract `head` against the default-branch contract `base`.
fn diff(base: &str, head: &str) -> Vec<Relaxation> {
    let base = parse(base).expect("base contract parses");
    let head = parse(head).expect("head contract parses");
    relaxations(&base, &head)
}

#[test]
fn an_unchanged_contract_lists_no_relaxations() {
    let body = "kind = \"secret\"\n";
    assert_eq!(diff(&contract(body), &contract(body)), Vec::new());
}

#[test]
fn a_new_except_of_a_production_environment_is_listed() {
    assert_eq!(
        diff(
            &contract_with_other("kind = \"secret\""),
            &contract_with_other("kind = \"secret\"\nexcept = { prod = \"no prod account\" }"),
        ),
        vec![Relaxation::new(
            "app",
            "API_KEY",
            Some("prod".to_string()),
            RelaxationKind::ExceptProduction,
        )],
    );
}

#[test]
fn a_new_except_of_a_shared_environment_is_presence_narrowed() {
    assert_eq!(
        diff(
            &contract_with_other("kind = \"secret\""),
            &contract_with_other("kind = \"secret\"\nexcept = { dev = \"no dev account\" }"),
        ),
        vec![Relaxation::new(
            "app",
            "API_KEY",
            Some("dev".to_string()),
            RelaxationKind::PresenceNarrowed,
        )],
    );
}

#[test]
fn adding_allow_same_value_is_listed() {
    assert_eq!(
        diff(
            &contract("kind = \"secret\"\n"),
            &contract("kind = \"secret\"\nallow_same_value = true\n"),
        ),
        vec![Relaxation::new(
            "app",
            "API_KEY",
            None,
            RelaxationKind::AllowSameValueAdded,
        )],
    );
}

#[test]
fn removing_a_rules_table_is_listed() {
    assert_eq!(
        diff(
            &contract("kind = \"secret\"\nrules = { prefix = \"sk_\" }\n"),
            &contract("kind = \"secret\"\n"),
        ),
        vec![Relaxation::new(
            "app",
            "API_KEY",
            None,
            RelaxationKind::RuleRemoved,
        )],
    );
}

#[test]
fn changing_a_key_from_secret_to_config_is_listed() {
    assert_eq!(
        diff(
            &contract("kind = \"secret\"\n"),
            &contract("kind = \"config\"\n"),
        ),
        vec![Relaxation::new(
            "app",
            "API_KEY",
            None,
            RelaxationKind::SecretToConfig,
        )],
    );
}

#[test]
fn a_key_removed_from_the_contract_is_not_a_relaxation() {
    let head = format!("{ENVS}[products.app.keys.OTHER_KEY]\nkind = \"secret\"\n");
    assert_eq!(diff(&contract("kind = \"secret\"\n"), &head), Vec::new());
}

#[test]
fn several_relaxations_come_back_sorted_by_key() {
    let base = format!(
        "{ENVS}[products.app.keys.A_KEY]\nkind = \"secret\"\n\n\
         [products.app.keys.B_KEY]\nkind = \"secret\"\n"
    );
    let head = format!(
        "{ENVS}[products.app.keys.A_KEY]\nkind = \"config\"\n\n\
         [products.app.keys.B_KEY]\nkind = \"config\"\n"
    );
    assert_eq!(
        diff(&base, &head),
        vec![
            Relaxation::new("app", "A_KEY", None, RelaxationKind::SecretToConfig),
            Relaxation::new("app", "B_KEY", None, RelaxationKind::SecretToConfig),
        ],
    );
}
