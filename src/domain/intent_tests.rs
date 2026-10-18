//! Behaviour of the categorical intent document (deliverable `intent`): one observable
//! outcome per test. Everything here goes through the public `parse` and `json_schema`.
//!
//! The JSON documents below are the intent form itself (a pure input type), not recorded
//! external tool output; no tool output is invented here.

use std::collections::BTreeSet;

use super::*;

/// A tiny valid tidy document carrying `text` as its guidance.
fn with_guidance(text: &str) -> String {
    format!(r#"{{"kind":"tidy","env":"prod","guidance":"{text}"}}"#)
}

// --- every kind parses ----------------------------------------------------------

#[test]
fn a_key_intent_parses() {
    assert!(parse(r#"{"kind":"key","key":"OPENAI_API_KEY"}"#).is_ok());
}

#[test]
fn an_env_intent_parses() {
    assert!(parse(r#"{"kind":"env","env":"prod","tier":"production"}"#).is_ok());
}

#[test]
fn a_target_intent_parses() {
    assert!(parse(r#"{"kind":"target","env":"prod","name":"portfolio","provider":"fly"}"#).is_ok());
}

#[test]
fn a_retire_intent_parses() {
    assert!(parse(r#"{"kind":"retire","key":"OPENAI_API_KEY"}"#).is_ok());
}

#[test]
fn a_setup_intent_parses() {
    assert!(parse(r#"{"kind":"setup","from_item":"prod","vault":"v","item":"i"}"#).is_ok());
}

#[test]
fn a_structure_intent_parses() {
    assert!(parse(r#"{"kind":"structure","rebind":["prod"]}"#).is_ok());
}

#[test]
fn a_generate_intent_parses() {
    assert!(
        parse(r#"{"kind":"generate","env":"prod","keys":["allumata/OPENAI_API_KEY"]}"#).is_ok()
    );
}

#[test]
fn a_tidy_intent_parses() {
    assert!(parse(r#"{"kind":"tidy","env":"prod"}"#).is_ok());
}

// --- grammar, shapes and forbidden fields ---------------------------------------

#[test]
fn a_bad_key_name_is_refused() {
    let e = parse(r#"{"kind":"key","key":"openai-key"}"#).unwrap_err();
    assert_eq!(e.code_str(), "config_invalid");
}

#[test]
fn an_unknown_shape_is_refused_naming_the_field() {
    let e = parse(r#"{"kind":"key","key":"OPENAI_API_KEY","shape":"not_a_shape"}"#).unwrap_err();
    assert!(e.to_string().contains("shape"));
}

#[test]
fn a_regex_field_is_refused_naming_the_field() {
    let e = parse(r#"{"kind":"key","key":"OPENAI_API_KEY","regex":"^sk_"}"#).unwrap_err();
    assert!(e.to_string().contains("regex"));
}

// --- guidance screening ---------------------------------------------------------

#[test]
fn a_known_prefix_guidance_is_refused_naming_the_detector() {
    let e = parse(&with_guidance("sk_live_abc123")).unwrap_err();
    assert!(e.to_string().contains("known_prefix"));
}

#[test]
fn a_pem_header_guidance_is_refused_naming_the_detector() {
    let e = parse(&with_guidance("-----BEGIN OPENSSH PRIVATE KEY-----")).unwrap_err();
    assert!(e.to_string().contains("pem_header"));
}

#[test]
fn a_high_entropy_guidance_is_refused_naming_the_detector() {
    let e = parse(&with_guidance("aBcDeFgHiJkLmNoPqRsT")).unwrap_err();
    assert!(e.to_string().contains("high_entropy"));
}

#[test]
fn a_detector_refusal_has_the_value_in_text_field_code() {
    let e = parse(&with_guidance("sk_live_abc123")).unwrap_err();
    assert_eq!(e.code_str(), "value_in_text_field");
}

#[test]
fn a_detector_refusal_never_contains_the_guidance() {
    let e = parse(&with_guidance("sk_live_abc123")).unwrap_err();
    assert!(!e.to_string().contains("sk_live_abc123"));
}

#[test]
fn guidance_over_200_characters_is_refused() {
    let e = parse(&with_guidance(&"a".repeat(201))).unwrap_err();
    assert_eq!(e.code_str(), "config_invalid");
}

#[test]
fn a_multi_line_guidance_is_refused() {
    let e = parse(r#"{"kind":"tidy","env":"prod","guidance":"line one\nline two"}"#).unwrap_err();
    assert_eq!(e.code_str(), "config_invalid");
}

// --- the schema -----------------------------------------------------------------

#[test]
fn the_schema_lists_the_eight_kinds() {
    let schema = json_schema();
    let kinds: BTreeSet<String> = schema["oneOf"]
        .as_array()
        .expect("oneOf")
        .iter()
        .map(|arm| {
            arm["properties"]["kind"]["enum"][0]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    assert_eq!(
        kinds,
        BTreeSet::from([
            "key".to_string(),
            "env".to_string(),
            "target".to_string(),
            "retire".to_string(),
            "setup".to_string(),
            "structure".to_string(),
            "generate".to_string(),
            "tidy".to_string(),
        ])
    );
}

#[test]
fn a_known_prefix_inside_a_sentence_is_refused() {
    let e = parse(&with_guidance("use the key sk_live_abc123 here")).unwrap_err();
    assert_eq!(e.code_str(), "value_in_text_field");
}

#[test]
fn deploy_credentials_that_are_not_a_reference_are_refused() {
    let e = parse(
        r#"{"kind":"target","env":"prod","name":"web","provider":"fly","deploy_credentials":"hunter2"}"#,
    )
    .unwrap_err();
    assert_eq!(e.code_str(), "config_invalid");
}

#[test]
fn a_value_in_a_setup_vault_field_is_refused() {
    let e =
        parse(r#"{"kind":"setup","from_item":"prod","vault":"ghp_abcdefghijklmnop"}"#).unwrap_err();
    assert_eq!(e.code_str(), "value_in_text_field");
}

#[test]
fn a_provider_that_is_not_a_word_is_refused() {
    let e =
        parse(r#"{"kind":"target","env":"prod","name":"web","provider":"fly; rm"}"#).unwrap_err();
    assert_eq!(e.code_str(), "config_invalid");
}
