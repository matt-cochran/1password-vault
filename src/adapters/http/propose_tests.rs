//! Behaviour of `propose::section` against the pinned Zonetico descriptor (design
//! `http-target` §7): the pinned hash, the suggested list/put tables and determinism. Every
//! test carries one assertion; canaries are obvious (`CANARY-...`).

use super::*;
use crate::adapters::http::config;

/// The fixture descriptor recorded from Zonetico (`tests/fixtures/https/zonetico/README.md`).
const DESCRIPTOR: &[u8] =
    include_bytes!("../../../tests/fixtures/https/zonetico/platform_console.binpb");

/// The service the fixture records.
const SERVICE: &str = "portal.v1.PlatformConsoleService";

/// The descriptor's pinned sha256 (the fixture README).
const SHA256: &str = "ec5b6933b89fc49c1ebeaaa31afc666e9090036c53301648cc657cd18f8a7445";

/// The path the generated section names.
const DESCRIPTOR_PATH: &str = "deploy/opv/platform_console.binpb";

/// The host the person gives.
const HOST: &str = "central.zonetico.com";

/// The names the person gives: one env key to one remote name, deliberately unsorted.
const NAMES: &str = "OPENROUTER_API_KEY=openrouter,ANTHROPIC_API_KEY=anthropic";

/// The section for the fixture service.
fn generated() -> String {
    section(DESCRIPTOR, DESCRIPTOR_PATH, SERVICE, HOST, NAMES)
        .expect("the fixture service generates")
}

#[test]
fn fills_in_the_pinned_sha256_of_the_descriptor() {
    assert!(generated().contains(SHA256));
}

#[test]
fn suggests_the_secret_value_field_with_its_number_and_type() {
    assert!(generated().contains("field = \"secret_value\", number = 3, type = \"bytes\""));
}

#[test]
fn suggests_the_list_rpc_for_the_list_table() {
    assert!(
        generated().contains("call = \"portal.v1.PlatformConsoleService/ListPlatformConnections\"")
    );
}

#[test]
fn suggests_the_save_rpc_for_the_put_table() {
    assert!(
        generated().contains("call = \"portal.v1.PlatformConsoleService/SavePlatformConnection\"")
    );
}

#[test]
fn writes_the_given_host() {
    assert!(generated().contains("http.host = \"central.zonetico.com\""));
}

#[test]
fn produces_byte_identical_text_for_the_same_descriptor() {
    assert_eq!(generated(), generated());
}

#[test]
fn refuses_a_service_that_is_not_in_the_descriptor() {
    let error = section(
        DESCRIPTOR,
        DESCRIPTOR_PATH,
        "portal.v1.NoSuchService",
        HOST,
        NAMES,
    )
    .expect_err("an unknown service is refused");
    assert!(error.contains("portal.v1.NoSuchService"));
}

#[test]
fn writes_the_given_names_sorted_by_environment_name() {
    assert!(generated().contains(
        "http.names = { ANTHROPIC_API_KEY = \"anthropic\", OPENROUTER_API_KEY = \"openrouter\" }"
    ));
}

#[test]
fn refuses_an_empty_names_value() {
    let error = section(DESCRIPTOR, DESCRIPTOR_PATH, SERVICE, HOST, "")
        .expect_err("an empty names value is refused");
    assert!(error.contains("pair 1"));
}

#[test]
fn refuses_a_names_pair_without_an_equals_sign() {
    let error = section(
        DESCRIPTOR,
        DESCRIPTOR_PATH,
        SERVICE,
        HOST,
        "OPENROUTER_API_KEY",
    )
    .expect_err("a pair without `=` is refused");
    assert!(error.contains("pair 1"));
}

#[test]
fn refuses_a_names_pair_with_an_empty_side() {
    let error = section(DESCRIPTOR, DESCRIPTOR_PATH, SERVICE, HOST, "A_ONE=a,")
        .expect_err("a pair with an empty side is refused");
    assert!(error.contains("pair 2"));
}

#[test]
fn refuses_a_names_pair_whose_key_is_not_an_environment_name() {
    let error = section(DESCRIPTOR, DESCRIPTOR_PATH, SERVICE, HOST, "lower=remote")
        .expect_err("a lowercase key is refused");
    assert!(error.contains("pair 1"));
}

#[test]
fn refuses_a_names_value_that_repeats_a_key() {
    let error = section(
        DESCRIPTOR,
        DESCRIPTOR_PATH,
        SERVICE,
        HOST,
        "A_ONE=a,A_ONE=b",
    )
    .expect_err("a repeated key is refused");
    assert!(error.contains("A_ONE"));
}

#[test]
fn a_refused_names_value_is_never_echoed_whole() {
    let value = "OPENROUTER_API_KEY=sk_live_S3CRETVALU3,no-equals";
    let error = section(DESCRIPTOR, DESCRIPTOR_PATH, SERVICE, HOST, value)
        .expect_err("the malformed value is refused");
    assert!(!error.contains(value));
}

#[test]
fn generated_section_parses_with_the_generated_names() {
    let text = generated();
    let document: toml::Table = toml::from_str(&text).expect("the generated section is valid TOML");
    let section = document
        .get("http")
        .and_then(toml::Value::as_table)
        .cloned()
        .expect("the generated output has an http table");
    let result = config::parse(&section, |_| Ok(DESCRIPTOR.to_vec()));
    assert!(
        result.is_ok(),
        "the generated section did not load: {result:?}"
    );
}
