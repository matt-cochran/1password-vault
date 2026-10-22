//! Behaviour of `config::parse` against the pinned Zonetico descriptor (design `http-target`
//! §3.1, §3.2): the example section loads, and each load rule refuses its violation by field
//! path. Every test carries one assertion; canaries are obvious (`CANARY-...`).

use super::*;

/// The fixture descriptor recorded from Zonetico (`tests/fixtures/https/zonetico/README.md`).
const DESCRIPTOR: &[u8] =
    include_bytes!("../../../tests/fixtures/https/zonetico/platform_console.binpb");

/// The design §3.1 example, as the `http` section of a target.
const EXAMPLE: &str = r#"
host = "central.zonetico.com"
descriptor = "deploy/opv/platform_console.binpb"
descriptor_sha256 = "ec5b6933b89fc49c1ebeaaa31afc666e9090036c53301648cc657cd18f8a7445"

[names]
OPENROUTER_API_KEY = "openrouter"
TAVILY_API_KEY = "tavily"
STRIPE_SECRET_KEY = "stripe"

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

/// The example as a mutable table.
fn example() -> toml::Table {
    toml::from_str(EXAMPLE).expect("the design §3.1 section is valid TOML")
}

/// `parse` with the fixture descriptor behind the closure.
fn parsed(section: &toml::Table) -> Result<HttpTarget, Vec<(String, String)>> {
    parse(section, |_| Ok(DESCRIPTOR.to_vec()))
}

/// The violations of a refused section.
fn refused(section: &toml::Table) -> Vec<(String, String)> {
    parsed(section).expect_err("the section must be refused")
}

/// Whether `field` is named among the violations.
fn refused_at(errors: &[(String, String)], field: &str) -> bool {
    errors.iter().any(|(path, _)| path == field)
}

#[test]
fn parses_the_design_example_section() {
    assert!(parsed(&example()).is_ok());
}

#[test]
fn carries_the_host_from_the_design_example() {
    assert_eq!(
        parsed(&example()).expect("parses").host,
        "central.zonetico.com"
    );
}

#[test]
fn carries_the_value_field_number_from_the_design_example() {
    assert_eq!(parsed(&example()).expect("parses").put.value.number, 3);
}

#[test]
fn refuses_a_descriptor_whose_hash_does_not_match_the_pin() {
    let mut section = example();
    section["descriptor_sha256"] = "0".repeat(64).into();
    assert!(refused_at(&refused(&section), "http.descriptor"));
}

#[test]
fn reports_a_descriptor_read_failure_from_the_closure() {
    let errors = parse(&example(), |_| {
        Err("descriptor file could not be read".to_string())
    })
    .expect_err("the read failure is a violation");
    assert!(refused_at(&errors, "http.descriptor"));
}

#[test]
fn refuses_a_list_method_absent_from_the_descriptor() {
    let mut section = example();
    section["list"]["call"] = "portal.v1.PlatformConsoleService/NoSuchMethod".into();
    assert!(refused_at(&refused(&section), "http.list.call"));
}

#[test]
fn refuses_a_put_method_absent_from_the_descriptor() {
    let mut section = example();
    section["put"]["call"] = "portal.v1.PlatformConsoleService/NoSuchMethod".into();
    assert!(refused_at(&refused(&section), "http.put.call"));
}

#[test]
fn refuses_a_value_field_absent_from_the_request_message() {
    let mut section = example();
    section["put"]["value"]["field"] = "no_such_field".into();
    assert!(refused_at(&refused(&section), "http.put.value.field"));
}

#[test]
fn refuses_a_value_field_whose_number_differs_from_the_descriptor() {
    let mut section = example();
    section["put"]["value"]["number"] = 99.into();
    assert!(refused_at(&refused(&section), "http.put.value.number"));
}

#[test]
fn refuses_a_value_field_whose_type_differs_from_the_descriptor() {
    let mut section = example();
    section["put"]["value"]["type"] = "string".into();
    assert!(refused_at(&refused(&section), "http.put.value.type"));
}

#[test]
fn refuses_a_value_field_that_is_not_string_or_bytes() {
    let mut section = example();
    section["put"]["value"]["field"] = "expected_version".into();
    assert!(refused_at(&refused(&section), "http.put.value.field"));
}

#[test]
fn refuses_a_value_type_that_is_not_string_or_bytes() {
    let mut section = example();
    section["put"]["value"]["type"] = "number".into();
    assert!(refused_at(&refused(&section), "http.put.value.type"));
}

#[test]
fn refuses_a_put_template_that_sets_the_value_field() {
    let mut section = example();
    section["put"]["request"]
        .as_table_mut()
        .expect("request is a table")
        .insert("secret_value".to_string(), "CANARY-NOT-A-SECRET".into());
    assert!(refused_at(
        &refused(&section),
        "http.put.request.secret_value"
    ));
}

#[test]
fn refuses_an_unknown_field_in_a_request_template() {
    let mut section = example();
    section["list"]["request"]
        .as_table_mut()
        .expect("request is a table")
        .insert("no_such_field".to_string(), "CANARY-NOT-A-SECRET".into());
    assert!(refused_at(
        &refused(&section),
        "http.list.request.no_such_field"
    ));
}

#[test]
fn refuses_a_partial_placeholder_in_a_request_template() {
    let mut section = example();
    section["put"]["request"]["provider"] = "prefix-{name}".into();
    assert!(refused_at(&refused(&section), "http.put.request.provider"));
}

#[test]
fn refuses_a_placeholder_that_is_not_name_or_version() {
    let mut section = example();
    section["put"]["request"]["provider"] = "{operator_id}".into();
    assert!(refused_at(&refused(&section), "http.put.request.provider"));
}

#[test]
fn refuses_a_credential_reference_in_a_request_template() {
    let mut section = example();
    section["put"]["request"]["provider"] = "{token}".into();
    assert!(refused_at(&refused(&section), "http.put.request.provider"));
}

#[test]
fn refuses_a_request_template_leaf_of_the_wrong_type() {
    let mut section = example();
    section["list"]["request"]["operator_id"] = 5.into();
    assert!(refused_at(
        &refused(&section),
        "http.list.request.operator_id"
    ));
}

#[test]
fn refuses_an_items_path_that_is_not_a_repeated_message() {
    let mut section = example();
    section["list"]["items"] = "connections.provider".into();
    assert!(refused_at(&refused(&section), "http.list.items"));
}

#[test]
fn refuses_a_name_path_that_is_not_a_string() {
    let mut section = example();
    section["list"]["name"] = "version".into();
    assert!(refused_at(&refused(&section), "http.list.name"));
}

#[test]
fn refuses_a_version_path_that_is_not_an_integer() {
    let mut section = example();
    section["list"]["version"] = "provider".into();
    assert!(refused_at(&refused(&section), "http.list.version"));
}

#[test]
fn refuses_a_status_path_that_is_not_an_enum() {
    let mut section = example();
    section["list"]["status"] = "provider".into();
    assert!(refused_at(&refused(&section), "http.list.status"));
}

#[test]
fn refuses_a_role_path_absent_from_the_entry() {
    let mut section = example();
    section["list"]["name"] = "no_such_field".into();
    assert!(refused_at(&refused(&section), "http.list.name"));
}

#[test]
fn refuses_an_absent_value_that_is_not_in_the_status_enum() {
    let mut section = example();
    section["list"]["absent"] = toml::Value::Array(vec!["NOT_A_STATUS".into()]);
    assert!(refused_at(&refused(&section), "http.list.absent[0]"));
}

#[test]
fn refuses_a_rejected_value_that_is_not_in_the_status_enum() {
    let mut section = example();
    section["list"]["rejected"] = toml::Value::Array(vec!["NOT_A_STATUS".into()]);
    assert!(refused_at(&refused(&section), "http.list.rejected[0]"));
}

#[test]
fn refuses_a_reply_path_that_is_not_a_message() {
    let mut section = example();
    section["put"]["reply"] = "message".into();
    assert!(refused_at(&refused(&section), "http.put.reply"));
}

#[test]
fn refuses_an_empty_names_mapping() {
    let mut section = example();
    section["names"]
        .as_table_mut()
        .expect("names is a table")
        .clear();
    assert!(refused_at(&refused(&section), "http.names"));
}

#[test]
fn refuses_two_env_names_that_map_to_one_remote_name() {
    let mut section = example();
    section["names"]
        .as_table_mut()
        .expect("names is a table")
        .insert("SECOND_KEY".to_string(), "openrouter".into());
    assert!(refused_at(&refused(&section), "http.names"));
}

#[test]
fn refuses_a_host_that_is_a_url() {
    let mut section = example();
    section["host"] = "https://central.zonetico.com".into();
    assert!(refused_at(&refused(&section), "http.host"));
}

#[test]
fn refuses_a_host_that_is_an_ip_literal() {
    let mut section = example();
    section["host"] = "127.0.0.1".into();
    assert!(refused_at(&refused(&section), "http.host"));
}

#[test]
fn refuses_a_host_with_a_port() {
    let mut section = example();
    section["host"] = "central.zonetico.com:443".into();
    assert!(refused_at(&refused(&section), "http.host"));
}

#[test]
fn refuses_a_host_with_a_trailing_dot() {
    let mut section = example();
    section["host"] = "central.zonetico.com.".into();
    assert!(refused_at(&refused(&section), "http.host"));
}

#[test]
fn refuses_an_uppercase_host() {
    let mut section = example();
    section["host"] = "Central.Zonetico.com".into();
    assert!(refused_at(&refused(&section), "http.host"));
}

#[test]
fn refuses_a_conflict_entry_that_is_not_a_grpc_status_name() {
    let mut section = example();
    section["put"]["conflict"] = toml::Value::Array(vec!["NOT_A_CODE".into()]);
    assert!(refused_at(&refused(&section), "http.put.conflict[0]"));
}
