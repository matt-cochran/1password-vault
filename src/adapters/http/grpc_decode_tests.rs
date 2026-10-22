//! Behaviour tests for the gRPC-Web reply decoder (design `http-target` §5.1), against
//! the recorded Zonetico replies in `tests/fixtures/https/zonetico/`.
//!
//! Every fixture is loaded as its recorded `.json` headers plus `.body` bytes, so the
//! tests exercise both status shapes: a `0x80` body trailer (Zonetico production) and
//! trailers-only headers (`tonic-web-only/`).

use std::path::{Path, PathBuf};

use prost_reflect::{DynamicMessage, ReflectMessage};
use serde_json::Value as Json;
use zeroize::Zeroizing;

use super::*;
use crate::adapters::http::descriptor;
use crate::runner_https::HttpsReply;

const DESCRIPTOR_SHA256: &str = "ec5b6933b89fc49c1ebeaaa31afc666e9090036c53301648cc657cd18f8a7445";
const LIST_CALL: &str = "portal.v1.PlatformConsoleService/ListPlatformConnections";
const SAVE_CALL: &str = "portal.v1.PlatformConsoleService/SavePlatformConnection";

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/https/zonetico")
}

fn pool() -> prost_reflect::DescriptorPool {
    let bytes = std::fs::read(fixture_dir().join("platform_console.binpb"))
        .expect("the recorded descriptor is present");
    descriptor::load(&bytes, DESCRIPTOR_SHA256).expect("the recorded descriptor loads")
}

fn fixture(dir: &str, case: &str) -> HttpsReply {
    let root = fixture_dir().join(dir);
    let json: Json = serde_json::from_slice(
        &std::fs::read(root.join(format!("{case}.json"))).expect("the reply json is present"),
    )
    .expect("the reply json parses");
    let body = std::fs::read(
        root.join(
            json["body_file"]
                .as_str()
                .expect("the reply names its body file"),
        ),
    )
    .expect("the reply body is present");

    let mut reply = HttpsReply {
        status: json["status"].as_u64().expect("the http status") as u16,
        content_type: None,
        grpc_status: None,
        grpc_message: None,
        body: Zeroizing::new(body),
    };
    for header in json["headers"].as_array().expect("the header list") {
        let name = header[0].as_str().expect("a header name");
        let value = header[1].as_str().expect("a header value");
        match name {
            "content-type" => reply.content_type = Some(value.to_string()),
            "grpc-status" => reply.grpc_status = Some(value.parse().expect("a gRPC status")),
            "grpc-message" => reply.grpc_message = Some(value.to_string()),
            _ => {}
        }
    }
    reply
}

fn decode_fixture(dir: &str, case: &str, method: &str) -> DecodedReply {
    decode_reply(&pool(), method, &fixture(dir, case)).expect("the recorded reply decodes")
}

fn connection(message: &DynamicMessage, index: usize) -> DynamicMessage {
    let RoleValue::Messages(connections) =
        read_role(message, "connections", RoleKind::Messages).expect("connections are messages")
    else {
        panic!("connections is a repeated message field");
    };
    connections[index].clone()
}

fn text(message: &DynamicMessage, path: &str) -> String {
    match read_role(message, path, RoleKind::String).expect("the field is a string") {
        RoleValue::String(value) => value,
        _ => panic!("the field is a string"),
    }
}

fn number(message: &DynamicMessage, path: &str) -> i64 {
    match read_role(message, path, RoleKind::Int).expect("the field is an integer") {
        RoleValue::Int(value) => value,
        _ => panic!("the field is an integer"),
    }
}

fn status_name(message: &DynamicMessage, path: &str) -> String {
    match read_role(message, path, RoleKind::Enum).expect("the field is an enum") {
        RoleValue::Enum(value) => value,
        _ => panic!("the field is an enum"),
    }
}

#[test]
fn reads_list_ok_connections_with_their_roles() {
    let decoded = decode_fixture("", "list-ok", LIST_CALL);
    let message = decoded
        .message
        .as_ref()
        .expect("a successful reply has a message");
    let entries: Vec<(String, String, i64)> = (0..3)
        .map(|index| {
            let connection = connection(message, index);
            (
                text(&connection, "provider"),
                status_name(&connection, "status"),
                number(&connection, "version"),
            )
        })
        .collect();
    assert_eq!(
        entries,
        vec![
            (
                "openrouter".to_string(),
                "CONNECTION_STATUS_VERIFIED".to_string(),
                4
            ),
            (
                "tavily".to_string(),
                "CONNECTION_STATUS_NOT_CONFIGURED".to_string(),
                0
            ),
            (
                "stripe".to_string(),
                "CONNECTION_STATUS_REVOKED".to_string(),
                7
            ),
        ]
    );
}

#[test]
fn reads_tonic_web_only_list_ok_connections_with_their_roles() {
    let decoded = decode_fixture("tonic-web-only", "list-ok", LIST_CALL);
    let message = decoded
        .message
        .as_ref()
        .expect("a successful reply has a message");
    let entries: Vec<(String, String, i64)> = (0..3)
        .map(|index| {
            let connection = connection(message, index);
            (
                text(&connection, "provider"),
                status_name(&connection, "status"),
                number(&connection, "version"),
            )
        })
        .collect();
    assert_eq!(
        entries,
        vec![
            (
                "openrouter".to_string(),
                "CONNECTION_STATUS_VERIFIED".to_string(),
                4
            ),
            (
                "tavily".to_string(),
                "CONNECTION_STATUS_NOT_CONFIGURED".to_string(),
                0
            ),
            (
                "stripe".to_string(),
                "CONNECTION_STATUS_REVOKED".to_string(),
                7
            ),
        ]
    );
}

#[test]
fn reads_save_ok_verified_connection_status() {
    let decoded = decode_fixture("", "save-ok-verified", SAVE_CALL);
    let message = decoded
        .message
        .as_ref()
        .expect("a successful reply has a message");
    assert_eq!(
        status_name(message, "connection.status"),
        "CONNECTION_STATUS_VERIFIED"
    );
}

#[test]
fn reads_save_ok_rejected_connection_status() {
    let decoded = decode_fixture("", "save-ok-rejected", SAVE_CALL);
    let message = decoded
        .message
        .as_ref()
        .expect("a successful reply has a message");
    assert_eq!(
        status_name(message, "connection.status"),
        "CONNECTION_STATUS_REJECTED"
    );
}

#[test]
fn reads_a_string_field_by_path() {
    let decoded = decode_fixture("", "save-ok-verified", SAVE_CALL);
    let message = decoded
        .message
        .as_ref()
        .expect("a successful reply has a message");
    assert_eq!(text(message, "connection.provider"), "openrouter");
}

#[test]
fn reads_an_int_field_by_path() {
    let decoded = decode_fixture("", "save-ok-verified", SAVE_CALL);
    let message = decoded
        .message
        .as_ref()
        .expect("a successful reply has a message");
    assert_eq!(number(message, "connection.version"), 5);
}

#[test]
fn reads_an_absent_int_as_the_proto3_default() {
    let decoded = decode_fixture("", "list-ok", LIST_CALL);
    let message = decoded
        .message
        .as_ref()
        .expect("a successful reply has a message");
    assert_eq!(number(&connection(message, 1), "version"), 0);
}

#[test]
fn reads_a_singular_message_field() {
    let decoded = decode_fixture("", "save-ok-verified", SAVE_CALL);
    let message = decoded
        .message
        .as_ref()
        .expect("a successful reply has a message");
    let RoleValue::Message(connection) =
        read_role(message, "connection", RoleKind::Message).expect("connection is a message")
    else {
        panic!("connection is a message field");
    };
    assert_eq!(
        connection.descriptor().full_name(),
        "portal.v1.PlatformConnection"
    );
}

#[test]
fn rejects_a_wrong_field_type_naming_the_path() {
    let decoded = decode_fixture("", "save-ok-verified", SAVE_CALL);
    let message = decoded
        .message
        .as_ref()
        .expect("a successful reply has a message");
    let error = read_role(message, "connection.provider", RoleKind::Int)
        .expect_err("a string is not an integer");
    assert!(error.contains("connection.provider"));
}

#[test]
fn withholds_the_message_on_an_error_status() {
    let decoded = decode_fixture("", "err-already-exists", SAVE_CALL);
    assert!(decoded.message.is_none());
}

macro_rules! error_reply {
    ($name:ident, $dir:literal, $case:ident, $code:literal, $message:literal) => {
        #[test]
        fn $name() {
            let case = stringify!($case).replace('_', "-");
            let decoded = decode_fixture($dir, &case, SAVE_CALL);
            assert_eq!(
                (decoded.status, decoded.grpc_message.as_deref()),
                ($code, Some($message))
            );
        }
    };
}

error_reply!(
    reads_already_exists_from_a_body_trailer,
    "",
    err_already_exists,
    6,
    "This connection changed; reload before saving"
);
error_reply!(
    reads_unauthenticated_from_a_body_trailer,
    "",
    err_unauthenticated,
    16,
    "Sign in again"
);
error_reply!(
    reads_invalid_argument_from_a_body_trailer,
    "",
    err_invalid_argument,
    3,
    "Paste the full key (16 characters or more)"
);
error_reply!(
    reads_permission_denied_from_a_body_trailer,
    "",
    err_permission_denied,
    7,
    "Platform operator required"
);

error_reply!(
    reads_already_exists_from_headers,
    "tonic-web-only",
    err_already_exists,
    6,
    "This connection changed; reload before saving"
);
error_reply!(
    reads_unauthenticated_from_headers,
    "tonic-web-only",
    err_unauthenticated,
    16,
    "Sign in again"
);
error_reply!(
    reads_invalid_argument_from_headers,
    "tonic-web-only",
    err_invalid_argument,
    3,
    "Paste the full key (16 characters or more)"
);
error_reply!(
    reads_permission_denied_from_headers,
    "tonic-web-only",
    err_permission_denied,
    7,
    "Platform operator required"
);

#[test]
fn refuses_a_text_content_type() {
    let reply = HttpsReply {
        status: 200,
        content_type: Some("application/grpc-web-text".to_string()),
        grpc_status: None,
        grpc_message: None,
        body: Zeroizing::new(Vec::new()),
    };
    let error = decode_reply(&pool(), LIST_CALL, &reply).expect_err("text is not accepted");
    assert!(error.to_string().contains("grpc-web-text"));
}

#[test]
fn accepts_a_plain_grpc_web_content_type() {
    let reply = HttpsReply {
        status: 200,
        content_type: Some("application/grpc-web".to_string()),
        grpc_status: Some(0),
        grpc_message: None,
        body: Zeroizing::new(Vec::new()),
    };
    let decoded = decode_reply(&pool(), LIST_CALL, &reply).expect("plain grpc-web is accepted");
    assert_eq!(decoded.status, 0);
}

#[test]
fn refuses_a_compressed_frame() {
    let reply = HttpsReply {
        status: 200,
        content_type: Some("application/grpc-web+proto".to_string()),
        grpc_status: None,
        grpc_message: None,
        body: Zeroizing::new(vec![0x01, 0, 0, 0, 0]),
    };
    let error =
        decode_reply(&pool(), LIST_CALL, &reply).expect_err("a compressed frame is refused");
    assert!(error.to_string().contains("compressed"));
}

#[test]
fn grpc_decode_source_has_no_json_conversion() {
    assert!(!include_str!("grpc_decode.rs").contains("serde_json"));
}
