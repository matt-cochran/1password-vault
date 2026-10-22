//! Behaviour of the HTTP store (design `http-target` §6, §8) against the recorded Zonetico
//! replies in `tests/fixtures/https/zonetico/`. Every test carries one assertion; canaries
//! are obvious (`CANARY-...`).

use std::path::{Path, PathBuf};

use prost_reflect::DescriptorPool;
use serde_json::Value as Json;
use zeroize::Zeroizing;

use super::*;
use crate::adapters::http::descriptor;
use crate::domain::StoreEntry;
use crate::domain::secret::SecretValue;
use crate::ports::{StagedStore, Store};
use crate::runner::fake::FakeRunner;
use crate::runner_https::HttpsReply;

/// The fixture descriptor recorded from Zonetico (`tests/fixtures/https/zonetico/README.md`).
const DESCRIPTOR: &[u8] =
    include_bytes!("../../../tests/fixtures/https/zonetico/platform_console.binpb");

/// The fixture descriptor's sha256 (`tests/fixtures/https/zonetico/README.md`).
const DESCRIPTOR_SHA256: &str = "ec5b6933b89fc49c1ebeaaa31afc666e9090036c53301648cc657cd18f8a7445";

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

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/https/zonetico")
}

fn pool() -> DescriptorPool {
    descriptor::load(DESCRIPTOR, DESCRIPTOR_SHA256).expect("the recorded descriptor loads")
}

fn target() -> HttpTarget {
    let table: toml::Table =
        toml::from_str(EXAMPLE).expect("the design §3.1 section is valid TOML");
    crate::adapters::http::config::parse(&table, |_| Ok(DESCRIPTOR.to_vec()))
        .expect("the design §3.1 section loads")
}

fn store_of(r: &FakeRunner) -> HttpStore<'_> {
    HttpStore::new(
        r,
        pool(),
        target(),
        Destination {
            host: "central.zonetico.com".to_string(),
            prefix: String::new(),
        },
    )
}

fn secret(value: &str) -> SecretValue {
    SecretValue::new(value.to_string())
}

/// The recorded reply `case` as its `.json` headers plus `.body` bytes.
fn fixture(case: &str) -> HttpsReply {
    let root = fixture_dir();
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
        match header[0].as_str().expect("a header name") {
            "content-type" => reply.content_type = Some(header[1].as_str().unwrap().to_string()),
            "grpc-status" => reply.grpc_status = header[1].as_str().unwrap().parse().ok(),
            "grpc-message" => reply.grpc_message = Some(header[1].as_str().unwrap().to_string()),
            _ => {}
        }
    }
    reply
}

/// The one value every write test stages.
const CANARY: &str = "CANARY-NOT-A-SECRET-0123456789";

// list -----------------------------------------------------------------------------------

#[test]
fn list_posts_to_the_configured_method_path() {
    let r = FakeRunner::default();
    r.push_https_reply(&fixture("list-ok"));
    store_of(&r).list().expect("the list succeeds");
    assert_eq!(
        r.calls.borrow()[0].args,
        [
            "POST",
            "central.zonetico.com/portal.v1.PlatformConsoleService/ListPlatformConnections"
        ]
    );
}

#[test]
fn list_keeps_a_name_the_application_reports_configured() {
    let r = FakeRunner::default();
    r.push_https_reply(&fixture("list-ok"));
    let entries = store_of(&r).list().expect("the list succeeds");
    assert_eq!(
        entries,
        [StoreEntry {
            name: "OPENROUTER_API_KEY".to_string(),
            version: Some("4".to_string()),
            pending: false,
            stamp: None,
        }]
    );
}

#[test]
fn list_drops_a_name_the_application_reports_absent() {
    let r = FakeRunner::default();
    r.push_https_reply(&fixture("list-ok"));
    let entries = store_of(&r).list().expect("the list succeeds");
    assert!(!entries.iter().any(|e| e.name == "TAVILY_API_KEY"));
}

#[test]
fn list_drops_a_name_the_application_reports_revoked() {
    let r = FakeRunner::default();
    r.push_https_reply(&fixture("list-ok"));
    let entries = store_of(&r).list().expect("the list succeeds");
    assert!(!entries.iter().any(|e| e.name == "STRIPE_SECRET_KEY"));
}

// write ----------------------------------------------------------------------------------

#[test]
fn write_sends_the_version_the_last_list_reported() {
    let r = FakeRunner::default();
    r.push_https_reply(&fixture("list-ok"));
    r.push_https_reply(&fixture("save-ok-verified"));
    let store = store_of(&r);
    store.list().expect("the list succeeds");
    let value = secret(CANARY);
    store
        .write(&[("OPENROUTER_API_KEY".to_string(), &value)])
        .expect("the write succeeds");
    assert_eq!(
        r.calls.borrow()[1].stdin.as_deref(),
        Some(include_bytes!("../../../tests/fixtures/https/zonetico/request-save.bin").as_slice())
    );
}

#[test]
fn write_posts_to_the_configured_method_path() {
    let r = FakeRunner::default();
    r.push_https_reply(&fixture("save-ok-verified"));
    let value = secret(CANARY);
    store_of(&r)
        .write(&[("OPENROUTER_API_KEY".to_string(), &value)])
        .expect("the write succeeds");
    assert_eq!(
        r.calls.borrow()[0].args,
        [
            "POST",
            "central.zonetico.com/portal.v1.PlatformConsoleService/SavePlatformConnection"
        ]
    );
}

#[test]
fn write_maps_a_conflict_to_target_changed() {
    let r = FakeRunner::default();
    r.push_https_reply(&fixture("err-already-exists"));
    let value = secret(CANARY);
    let e = store_of(&r)
        .write(&[("OPENROUTER_API_KEY".to_string(), &value)])
        .expect_err("the conflict is an error");
    assert_eq!(e.code_str(), "target_changed");
}

#[test]
fn write_maps_unauthenticated_to_credential_rejected() {
    let r = FakeRunner::default();
    r.push_https_reply(&fixture("err-unauthenticated"));
    let value = secret(CANARY);
    let e = store_of(&r)
        .write(&[("OPENROUTER_API_KEY".to_string(), &value)])
        .expect_err("the refusal is an error");
    assert_eq!(e.code_str(), "deploy_credentials_failed");
}

#[test]
fn write_maps_permission_denied_to_credential_rejected() {
    let r = FakeRunner::default();
    r.push_https_reply(&fixture("err-permission-denied"));
    let value = secret(CANARY);
    let e = store_of(&r)
        .write(&[("OPENROUTER_API_KEY".to_string(), &value)])
        .expect_err("the refusal is an error");
    assert_eq!(e.code_str(), "deploy_credentials_failed");
}

#[test]
fn write_maps_invalid_argument_to_update_refused() {
    let r = FakeRunner::default();
    r.push_https_reply(&fixture("err-invalid-argument"));
    let value = secret(CANARY);
    let e = store_of(&r)
        .write(&[("OPENROUTER_API_KEY".to_string(), &value)])
        .expect_err("the refusal is an error");
    assert_eq!(e.code_str(), "update_refused");
}

#[test]
fn write_reports_an_unknown_outcome_when_the_call_never_answers() {
    let r = FakeRunner::default();
    r.push_unknown("timeout");
    let value = secret(CANARY);
    let e = store_of(&r)
        .write(&[("OPENROUTER_API_KEY".to_string(), &value)])
        .expect_err("the lost write is an error");
    assert_eq!(e.code_str(), "outcome_unknown");
}

// check_written --------------------------------------------------------------------------

#[test]
fn check_written_refuses_a_status_the_application_reports_rejected() {
    let r = FakeRunner::default();
    r.push_https_reply(&fixture("save-ok-rejected"));
    let store = store_of(&r);
    let value = secret(CANARY);
    store
        .write(&[("OPENROUTER_API_KEY".to_string(), &value)])
        .expect("the write succeeds");
    let e = store
        .check_written(&["OPENROUTER_API_KEY".to_string()])
        .expect_err("the rejected entry is unhealthy");
    assert_eq!(e.code_str(), "target_unhealthy");
}

// refusal --------------------------------------------------------------------------------

#[test]
fn refusal_refuses_a_value_shorter_than_sixteen_characters() {
    let r = FakeRunner::default();
    assert!(
        store_of(&r)
            .refusal("OPENROUTER_API_KEY", &secret("short"))
            .is_some()
    );
}

#[test]
fn refusal_accepts_a_value_of_sixteen_characters() {
    let r = FakeRunner::default();
    assert_eq!(
        store_of(&r).refusal("OPENROUTER_API_KEY", &secret("0123456789abcdef")),
        None
    );
}

#[test]
fn refusal_refuses_a_value_with_a_control_character() {
    let r = FakeRunner::default();
    assert!(
        store_of(&r)
            .refusal("OPENROUTER_API_KEY", &secret("0123456789abcde\nf"))
            .is_some()
    );
}

// remove ---------------------------------------------------------------------------------

#[test]
fn remove_refuses_a_name() {
    let r = FakeRunner::default();
    assert!(
        store_of(&r)
            .remove(&["OPENROUTER_API_KEY".to_string()])
            .is_err()
    );
}

#[test]
fn remove_makes_no_https_call() {
    let r = FakeRunner::default();
    let _ = store_of(&r).remove(&["OPENROUTER_API_KEY".to_string()]);
    assert!(r.calls.borrow().is_empty());
}

// variables ------------------------------------------------------------------------------

#[test]
fn variables_are_not_delivered() {
    let r = FakeRunner::default();
    assert!(store_of(&r).variables().is_none());
}
