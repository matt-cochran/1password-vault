//! Tests for [`super::encode_request`] (design `http-target` §5.1, §3.2): the recorded
//! Zonetico request, the role-field decode, the template refusals and the source guard.

use prost_reflect::{DescriptorPool, DynamicMessage, MethodDescriptor, Value};
use zeroize::Zeroizing;

use super::encode_request;
use crate::adapters::http::descriptor;
use crate::adapters::http::model::{ValueField, ValueKind};
use crate::domain::secret::SecretValue;

const DESCRIPTOR_SHA256: &str = "ec5b6933b89fc49c1ebeaaa31afc666e9090036c53301648cc657cd18f8a7445";
const SAVE_METHOD: &str = "portal.v1.PlatformConsoleService/SavePlatformConnection";
const CANARY: &str = "CANARY-NOT-A-SECRET-0123456789";

fn pool() -> DescriptorPool {
    descriptor::load(
        include_bytes!("../../../tests/fixtures/https/zonetico/platform_console.binpb"),
        DESCRIPTOR_SHA256,
    )
    .expect("the pinned fixture descriptor")
}

fn method(pool: &DescriptorPool) -> MethodDescriptor {
    descriptor::method(pool, SAVE_METHOD).expect("SavePlatformConnection in the fixture")
}

/// Parse a literal template document (design `http-target` §3.1).
fn parse(source: &str) -> toml::Value {
    toml::from_str(source).expect("a literal template")
}

fn template() -> toml::Value {
    parse(
        r#"
operator_id = "00000000-0000-4000-8000-000000000000"
provider = "{name}"
expected_version = "{version}"
"#,
    )
}

fn value_field() -> ValueField {
    ValueField { field: String::from("secret_value"), number: 3, kind: ValueKind::Bytes }
}

/// Encode the fixture template with the recorded inputs; the one place tests build inputs.
fn encode(pool: &DescriptorPool, template: &toml::Value) -> Result<Zeroizing<Vec<u8>>, String> {
    encode_request(
        pool,
        &method(pool),
        template,
        "openrouter",
        4,
        &value_field(),
        &SecretValue::new(String::from(CANARY)),
    )
}

/// The refusal text, or a panic when the request was accepted.
fn refusal(result: Result<Zeroizing<Vec<u8>>, String>) -> String {
    match result {
        Err(error) => error,
        Ok(_) => panic!("expected the request to be refused"),
    }
}

#[test]
fn recorded_request_save_bytes_are_reproduced() {
    let encoded = encode(&pool(), &template()).expect("the fixture request encodes");
    assert_eq!(
        encoded.as_slice(),
        &include_bytes!("../../../tests/fixtures/https/zonetico/request-save.bin")[..]
    );
}

#[test]
fn frame_starts_with_the_uncompressed_flag() {
    let encoded = encode(&pool(), &template()).expect("the fixture request encodes");
    assert_eq!(encoded[0], 0x00);
}

#[test]
fn frame_length_matches_the_message_bytes() {
    let encoded = encode(&pool(), &template()).expect("the fixture request encodes");
    let declared = u32::from_be_bytes([encoded[1], encoded[2], encoded[3], encoded[4]]) as usize;
    assert_eq!(declared, encoded.len() - 5);
}

#[test]
fn decoded_frame_carries_the_substituted_name() {
    let pool = pool();
    let encoded = encode(&pool, &template()).expect("the fixture request encodes");
    let decoded =
        DynamicMessage::decode(method(&pool).input(), &encoded[5..]).expect("a valid request");
    assert_eq!(
        decoded.get_field_by_name("provider").as_deref(),
        Some(&Value::String(String::from("openrouter")))
    );
}

#[test]
fn decoded_frame_carries_the_substituted_version() {
    let pool = pool();
    let encoded = encode(&pool, &template()).expect("the fixture request encodes");
    let decoded =
        DynamicMessage::decode(method(&pool).input(), &encoded[5..]).expect("a valid request");
    assert_eq!(decoded.get_field_by_name("expected_version").as_deref(), Some(&Value::I64(4)));
}

#[test]
fn decoded_frame_carries_the_secret_value_bytes() {
    let pool = pool();
    let encoded = encode(&pool, &template()).expect("the fixture request encodes");
    let decoded =
        DynamicMessage::decode(method(&pool).input(), &encoded[5..]).expect("a valid request");
    let value = decoded.get_field_by_name("secret_value").expect("secret_value is set");
    assert_eq!(&value.as_bytes().expect("bytes")[..], CANARY.as_bytes());
}

#[test]
fn template_setting_the_value_field_is_refused() {
    let bad = parse(
        r#"
operator_id = "00000000-0000-4000-8000-000000000000"
provider = "{name}"
expected_version = "{version}"
secret_value = "CANARY-IN-TEMPLATE"
"#,
    );
    let error = refusal(encode(&pool(), &bad));
    assert!(error.contains("secret_value"));
}

#[test]
fn value_field_with_the_wrong_number_is_refused() {
    let field = ValueField { number: 5, ..value_field() };
    let error = refusal(encode_request(
        &pool(),
        &method(&pool()),
        &template(),
        "openrouter",
        4,
        &field,
        &SecretValue::new(String::from(CANARY)),
    ));
    assert!(error.contains("secret_value"));
}

#[test]
fn value_field_with_the_wrong_type_is_refused() {
    let field = ValueField { kind: ValueKind::String, ..value_field() };
    let error = refusal(encode_request(
        &pool(),
        &method(&pool()),
        &template(),
        "openrouter",
        4,
        &field,
        &SecretValue::new(String::from(CANARY)),
    ));
    assert!(error.contains("secret_value"));
}

#[test]
fn unknown_template_field_is_refused() {
    let bad = parse(
        r#"
operator_id = "00000000-0000-4000-8000-000000000000"
provider = "{name}"
expected_version = "{version}"
bogus = "x"
"#,
    );
    let error = refusal(encode(&pool(), &bad));
    assert!(error.contains("bogus"));
}

#[test]
fn a_refusal_never_echoes_the_secret_value() {
    let bad = parse(
        r#"
operator_id = "00000000-0000-4000-8000-000000000000"
provider = "{name}"
bogus = "x"
"#,
    );
    let error = refusal(encode(&pool(), &bad));
    assert!(!error.contains(CANARY));
}

#[test]
fn the_codec_source_does_not_mention_serde_json() {
    assert!(!include_str!("grpc_encode.rs").contains("serde_json"));
}

#[test]
fn the_codec_source_does_not_stringify_a_value() {
    assert!(!include_str!("grpc_encode.rs").contains("to_string()"));
}
