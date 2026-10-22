//! HTTP deploy credentials (design `http-target` §4.1): the four fixed item fields, the
//! control-character refusal, the three header pairs and their scrubbing. One behavioral
//! assertion per test.

use std::collections::BTreeMap;

use super::*;
use crate::domain::SecretValue;
use crate::runner::fake::FakeRunner;

const HOST: &str = "central.zonetico.com";
const BASE_URL: &str = "https://central.zonetico.com/api";
const TOKEN: &str = "CANARY-token-abcdef";
const CLIENT_ID: &str = "CANARY-client-id-abcdef";
const CLIENT_SECRET: &str = "CANARY-client-secret-abcdef";

fn values(token: &str) -> BTreeMap<String, SecretValue> {
    BTreeMap::from([
        (
            "base_url".to_string(),
            SecretValue::new(BASE_URL.to_string()),
        ),
        ("token".to_string(), SecretValue::new(token.to_string())),
        (
            "cf_access_client_id".to_string(),
            SecretValue::new(CLIENT_ID.to_string()),
        ),
        (
            "cf_access_client_secret".to_string(),
            SecretValue::new(CLIENT_SECRET.to_string()),
        ),
    ])
}

fn signed_in() -> HttpLogin {
    let mut l = HttpLogin::new(HOST);
    l.sign_in(values(TOKEN), &FakeRunner::default()).unwrap();
    l
}

#[test]
fn the_item_has_four_fixed_fields() {
    assert_eq!(FIELDS.len(), 4);
}

#[test]
fn base_url_is_a_text_field() {
    assert_eq!(FIELDS[0].kind, Kind::Config);
}

#[test]
fn the_token_is_concealed() {
    assert_eq!(FIELDS[1].kind, Kind::Secret);
}

#[test]
fn the_access_client_id_is_concealed() {
    assert_eq!(FIELDS[2].kind, Kind::Secret);
}

#[test]
fn the_access_client_secret_is_concealed() {
    assert_eq!(FIELDS[3].kind, Kind::Secret);
}

#[test]
fn a_missing_field_is_refused() {
    let mut l = HttpLogin::new(HOST);
    assert!(l.sign_in(BTreeMap::new(), &FakeRunner::default()).is_err());
}

#[test]
fn a_control_character_in_the_token_is_refused() {
    let mut l = HttpLogin::new(HOST);
    assert!(
        l.sign_in(values("CANARY-tok\nen-abcdef"), &FakeRunner::default())
            .is_err()
    );
}

#[test]
fn a_control_character_in_the_access_client_id_is_refused() {
    let mut v = values(TOKEN);
    v.insert(
        "cf_access_client_id".to_string(),
        SecretValue::new("CANARY-id\n-abcdef".to_string()),
    );
    assert!(
        HttpLogin::new(HOST)
            .sign_in(v, &FakeRunner::default())
            .is_err()
    );
}

#[test]
fn a_control_character_in_the_access_client_secret_is_refused() {
    let mut v = values(TOKEN);
    v.insert(
        "cf_access_client_secret".to_string(),
        SecretValue::new("CANARY-secret\n-abcdef".to_string()),
    );
    assert!(
        HttpLogin::new(HOST)
            .sign_in(v, &FakeRunner::default())
            .is_err()
    );
}

#[test]
fn the_base_url_host_must_match_the_target_host() {
    let mut l = HttpLogin::new("other.zonetico.com");
    assert!(l.sign_in(values(TOKEN), &FakeRunner::default()).is_err());
}

#[test]
fn env_https_yields_exactly_the_three_headers() {
    let l = signed_in();
    assert_eq!(
        l.env("https"),
        vec![
            ("Authorization", "Bearer CANARY-token-abcdef"),
            ("CF-Access-Client-Id", CLIENT_ID),
            ("CF-Access-Client-Secret", CLIENT_SECRET),
        ]
    );
}

#[test]
fn env_op_is_empty() {
    let l = signed_in();
    assert!(l.env("op").is_empty());
}

#[test]
fn destination_is_unavailable_before_sign_in() {
    assert!(HttpLogin::new(HOST).destination().is_none());
}

#[test]
fn destination_is_parsed_from_the_item() {
    let l = signed_in();
    assert_eq!(
        l.destination(),
        Some(&Destination {
            host: HOST.to_string(),
            prefix: "/api".to_string(),
        })
    );
}

#[test]
fn the_token_is_registered_as_a_secret_for_the_output_guard() {
    let _ = signed_in();
    assert_eq!(
        crate::scrub::guard_scrub("x CANARY-token-abcdef"),
        "x ********"
    );
}

#[test]
fn the_access_client_id_is_registered_as_a_secret_for_the_output_guard() {
    let _ = signed_in();
    assert_eq!(
        crate::scrub::guard_scrub("x CANARY-client-id-abcdef"),
        "x ********"
    );
}

#[test]
fn the_access_client_secret_is_registered_as_a_secret_for_the_output_guard() {
    let _ = signed_in();
    assert_eq!(
        crate::scrub::guard_scrub("x CANARY-client-secret-abcdef"),
        "x ********"
    );
}

#[test]
fn a_refused_token_is_not_in_the_error() {
    let mut l = HttpLogin::new(HOST);
    let e = l
        .sign_in(values("CANARY-tok\nen-abcdef"), &FakeRunner::default())
        .unwrap_err();
    assert!(!e.text().contains("CANARY-tok"));
}
