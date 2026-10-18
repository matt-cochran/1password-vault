//! Presence rules (design Part V, row `presence`): one atomic test per rule.
//! Each test asserts one public outcome through `presence`, `config::parse` or `plan::build`.

use std::collections::BTreeSet;

use crate::cause::Cause;
use crate::config::parse;
use crate::domain::model::{KeySpec, Kind, Rules};
use crate::domain::plan;
use crate::domain::presence::{self, Presence};

/// A key spec with the given `environments` (absent when `None`) and `except`.
fn key(environments: Option<&[&str]>, except: &[(&str, &str)]) -> KeySpec {
    KeySpec {
        kind: Kind::Secret,
        environments: environments.map(|es| es.iter().map(|s| (*s).to_string()).collect()),
        except: except
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
        rules: Rules::default(),
        immutable: false,
        guidance: String::new(),
        from: None,
        personal: false,
        allow_same_value: false,
        file: None,
        roles: None,
    }
}

fn cause(text: &str) -> Cause {
    match parse(text) {
        Err(e) => match e.cause() {
            Some((c, _)) => c.clone(),
            None => panic!("expected a catalog cause, got {e:?}"),
        },
        Ok(_) => panic!("expected a refusal"),
    }
}

fn field_of(text: &str) -> String {
    match cause(text) {
        Cause::ConfigInvalid { field, .. } => field.to_string(),
        other => panic!("expected ConfigInvalid, got {other:?}"),
    }
}

#[test]
fn a_key_without_environments_is_present_in_every_environment() {
    assert_eq!(
        presence::present_in(&key(None, &[]), "dev"),
        Presence::Present
    );
}

#[test]
fn an_except_environment_is_not_wanted_with_its_reason() {
    assert_eq!(
        presence::present_in(&key(None, &[("dev", "no dev account")]), "dev"),
        Presence::NotWanted {
            reason: "no dev account".to_string()
        }
    );
}

#[test]
fn an_explicit_list_leaving_an_environment_out_is_an_environment_gap() {
    let text = "[environments.dev]\n\
                [environments.prod]\n\
                boundaries.api = { vault_id = \"v\", item_id = \"i\" }\n\
                [products.api.keys.SECRET]\n\
                kind = \"secret\"\n\
                environments = [\"prod\"]\n";
    let fleet = parse(text).expect("the gap still loads");
    assert_eq!(
        presence::gaps(&fleet),
        vec![("api".to_string(), "SECRET".to_string(), "dev".to_string())]
    );
}

#[test]
fn an_empty_except_reason_is_refused_naming_the_field() {
    let text = "[environments.dev]\n\
                [environments.prod]\n\
                [products.api.keys.SECRET]\n\
                kind = \"secret\"\n\
                environments = [\"prod\"]\n\
                except = { dev = \"\" }\n";
    assert_eq!(field_of(text), "products.api.keys.SECRET.except.dev");
}

#[test]
fn an_except_naming_an_undeclared_environment_is_refused() {
    let text = "[environments.prod]\n\
                [products.api.keys.SECRET]\n\
                kind = \"secret\"\n\
                environments = [\"prod\"]\n\
                except = { dev = \"why\" }\n";
    assert_eq!(field_of(text), "products.api.keys.SECRET.except.dev");
}

#[test]
fn an_environments_list_and_except_for_the_same_environment_are_refused() {
    let text = "[environments.prod]\n\
                [products.api.keys.SECRET]\n\
                kind = \"secret\"\n\
                environments = [\"prod\"]\n\
                except = { prod = \"why\" }\n";
    assert_eq!(field_of(text), "products.api.keys.SECRET.except.prod");
}

#[test]
fn a_plan_skips_a_not_wanted_key() {
    let text = "[environments.dev]\n\
                [products.api.keys.SECRET]\n\
                kind = \"secret\"\n\
                except = { dev = \"retired here\" }\n";
    let fleet = parse(text).expect("the config loads");
    let plan = plan::build(&fleet, "dev", Vec::new(), &[], &BTreeSet::new(), &|_| None);
    assert!(plan.rows.iter().all(|r| r.key != "SECRET"));
}
