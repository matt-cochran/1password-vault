//! The environment `tier` (FR-59): one test per rule. Each test names one outcome through
//! `config::parse` or `is_production`. No value is involved.

use crate::cause::Cause;
use crate::config::parse;
use crate::domain::Tier;
use crate::domain::health::{EnvValues, is_production};

/// The field the `config_invalid` refusal of `text` names.
fn refused_at(text: &str) -> String {
    let error = parse(text).expect_err("expected a refusal");
    let (cause, _) = error.cause().expect("every error has a cause");
    match cause {
        Cause::ConfigInvalid { field, .. } => field.to_string(),
        other => panic!("expected ConfigInvalid, got {other:?}"),
    }
}

#[test]
fn an_explicit_tier_parses() {
    let fleet = parse("[environments.dev]\ntier = \"production\"\n").unwrap();
    assert_eq!(fleet.environments["dev"].tier, Tier::Production);
}

#[test]
fn an_absent_tier_on_a_production_named_environment_is_production() {
    let fleet = parse("[environments.prod]\n").unwrap();
    assert_eq!(fleet.environments["prod"].tier, Tier::Production);
}

#[test]
fn an_absent_tier_otherwise_is_shared() {
    let fleet = parse("[environments.dev]\n").unwrap();
    assert_eq!(fleet.environments["dev"].tier, Tier::Shared);
}

#[test]
fn local_with_a_target_is_refused_naming_the_environment() {
    let text = "[environments.dev]\ntier = \"local\"\n\n\
                [environments.dev.targets.web]\n\
                fly.app = \"app-dev\"\n\
                fly.secret_name = \"FLEET__{PRODUCT}__{KEY}\"\n\
                state_vault_id = \"sdev\"\n";
    assert_eq!(refused_at(text), "environments.dev.tier");
}

#[test]
fn local_with_confirm_env_is_refused_naming_the_environment() {
    let text = "[environments.dev]\ntier = \"local\"\nconfirm_env = true\n";
    assert_eq!(refused_at(text), "environments.dev.tier");
}

#[test]
fn is_production_follows_the_tier() {
    let values = EnvValues {
        name: "dev",
        title: None,
        deployed: false,
        fields: &[],
        tier: Tier::Production,
        assistant_imported: false,
    };
    assert!(is_production(&values));
}
