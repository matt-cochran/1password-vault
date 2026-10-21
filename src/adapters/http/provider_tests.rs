//! Behaviour of the HTTP provider (design `http-target` §3, §4, §7): the section, the parse
//! flow, the deploy credentials and the opened ports. Every test carries one assertion.

use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::provider::Provider;
use crate::runner::fake::FakeRunner;

/// The design §3.1 example, as the `http` section of a target. The descriptor path is the
/// fixture's, relative to the crate root, so the provider's own read finds it; its sha256 is
/// the fixture's (`tests/fixtures/https/zonetico/README.md`).
const EXAMPLE: &str = r#"
host = "central.zonetico.com"
descriptor = "tests/fixtures/https/zonetico/platform_console.binpb"
descriptor_sha256 = "ec5b6933b89fc49c1ebeaaa31afc666e9090036c53301648cc657cd18f8a7445"

[names]
OPENROUTER_API_KEY = "openrouter"

[list]
call = "portal.v1.PlatformConsoleService/ListPlatformConnections"
request = { operator_id = "00000000-0000-4000-8000-000000000000" }
items = "connections"
name = "provider"
version = "version"
status = "status"
absent = ["CONNECTION_STATUS_NOT_CONFIGURED", "CONNECTION_STATUS_REVOKED"]
rejected = ["CONNECTION_STATUS_REJECTED"]

[put]
call = "portal.v1.PlatformConsoleService/SavePlatformConnection"
request = { operator_id = "00000000-0000-4000-8000-000000000000", provider = "{name}", expected_version = "{version}" }
value = { field = "secret_value", number = 3, type = "bytes" }
reply = "connection"
conflict = ["ALREADY_EXISTS"]
"#;

/// `body` as a provider section. The leaked text and value outlive the returned `Section`.
fn section_of(body: &str) -> Section<'static> {
    let table: toml::Table = toml::from_str(body).expect("the section body is valid TOML");
    let text: &'static str = Box::leak(toml::Value::Table(table).to_string().into_boxed_str());
    let value: &'static _ = Box::leak(Box::new(
        toml::de::DeValue::parse(text).expect("the inline table parses"),
    ));
    Section::new("dev", value, text)
}

fn section() -> Section<'static> {
    section_of(EXAMPLE)
}

fn parsed() -> Box<dyn TargetConfig> {
    PROVIDER.parse(&section()).expect("the example parses")
}

// provider -------------------------------------------------------------------------------

#[test]
fn provider_section_is_http() {
    assert_eq!(PROVIDER.section(), "http");
}

#[test]
fn provider_label_is_https() {
    assert_eq!(PROVIDER.label(), "HTTPS");
}

#[test]
fn provider_parses_the_design_example() {
    assert!(PROVIDER.parse(&section()).is_ok());
}

#[test]
fn provider_refuses_a_bad_host_as_a_config_invalid() {
    let bad = EXAMPLE.replace(
        "host = \"central.zonetico.com\"",
        "host = \"UPPER.zonetico.com\"",
    );
    let e = PROVIDER
        .parse(&section_of(&bad))
        .expect_err("the bad host is refused");
    assert_eq!(e.code_str(), "config_invalid");
}

#[test]
fn provider_names_the_refused_host_field() {
    let bad = EXAMPLE.replace(
        "host = \"central.zonetico.com\"",
        "host = \"UPPER.zonetico.com\"",
    );
    let e = PROVIDER
        .parse(&section_of(&bad))
        .expect_err("the bad host is refused");
    assert!(e.to_string().contains("http.host"), "{e}");
}

#[test]
fn provider_offers_the_deploy_credential_fields() {
    assert_eq!(
        PROVIDER.deploy_credential_fields().expect("the fields"),
        super::super::login::FIELDS
    );
}

#[test]
fn provider_init_fields_are_descriptor_and_service() {
    assert_eq!(
        PROVIDER
            .init_fields()
            .iter()
            .map(|f| f.field)
            .collect::<Vec<_>>(),
        ["descriptor", "service"]
    );
}

#[test]
fn provider_builds_a_deploy_login() {
    assert!(PROVIDER.deploy_login().is_ok());
}

// config ---------------------------------------------------------------------------------

#[test]
fn config_opens_a_staged_port_that_is_live() {
    let r = FakeRunner::default();
    let config = parsed();
    let ports = config
        .open(
            "prod",
            BTreeSet::new(),
            &BTreeMap::new(),
            &BTreeSet::new(),
            &r,
        )
        .expect("the ports open");
    assert!(matches!(ports, Ports::Staged { runtime, .. } if runtime.live()));
}

#[test]
fn config_maps_the_env_name_to_the_remote_name() {
    assert_eq!(parsed().store_name("OPENROUTER_API_KEY"), "openrouter");
}

#[test]
fn config_locator_names_the_host() {
    assert!(
        parsed()
            .target_locator()
            .contains("host central.zonetico.com")
    );
}

#[test]
fn config_reports_the_host_in_explain() {
    assert_eq!(
        parsed().explain("app", "OPENROUTER_API_KEY")[0],
        ("http host", "central.zonetico.com".to_string())
    );
}

#[test]
fn config_declares_secrets_on_the_store_channel() {
    assert_eq!(
        parsed().channels().secret,
        Channel::Store {
            label: "HTTP target"
        }
    );
}

#[test]
fn config_env_name_is_the_key() {
    assert_eq!(
        parsed().env_name("app", "OPENROUTER_API_KEY"),
        "OPENROUTER_API_KEY"
    );
}
