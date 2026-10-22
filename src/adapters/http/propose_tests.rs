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

/// The section for the fixture service.
fn generated() -> String {
    section(DESCRIPTOR, DESCRIPTOR_PATH, SERVICE).expect("the fixture service generates")
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
fn produces_byte_identical_text_for_the_same_descriptor() {
    assert_eq!(generated(), generated());
}

#[test]
fn refuses_a_service_that_is_not_in_the_descriptor() {
    let error = section(DESCRIPTOR, DESCRIPTOR_PATH, "portal.v1.NoSuchService")
        .expect_err("an unknown service is refused");
    assert!(error.contains("portal.v1.NoSuchService"));
}

#[test]
fn generated_section_parses_after_the_host_and_names_are_filled_in() {
    let text = generated().replace("<HOST>", "central.zonetico.com");
    let document: toml::Table = toml::from_str(&text).expect("the generated section is valid TOML");
    let mut section = document
        .get("http")
        .and_then(toml::Value::as_table)
        .cloned()
        .expect("the generated output has an http table");
    let mut names = toml::Table::new();
    names.insert(
        "OPENROUTER_API_KEY".to_string(),
        toml::Value::String("openrouter".to_string()),
    );
    section.insert("names".to_string(), toml::Value::Table(names));
    let result = config::parse(&section, |_| Ok(DESCRIPTOR.to_vec()));
    assert!(
        result.is_ok(),
        "the generated section did not load: {result:?}"
    );
}
