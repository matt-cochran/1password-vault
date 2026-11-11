//! `opv generate` age identity recipe: #293 acceptance tests (sealed-target §7.1).
//!
//! These exercise the public generation path against a stateful fake `op`: the issue's
//! probe contract, the stored identity and its printed `age1…` recipient, the value rule
//! that rejects a malformed stored identity, the no-overwrite guard, independent identities
//! per environment, and the promise that a secret never reaches argv or output.

use super::*;
use crate::adapters::fake_op::FakeOp;

/// The probe contract from the issue (#293): one generated age identity.
const PROBE: &str = r#"[environments.example]
boundaries.demo = {}

[products.demo]
boundary = "demo"

[products.demo.keys.EXAMPLE_IDENTITY]
kind = "secret"
source = "generated"
rules = { age_identity = true }
"#;

/// Two environments holding the same generated identity key, each with its own item.
const FLEET: &str = r#"[environments.dev]
boundaries.api = { vault_id = "vdev0000000000000000000001", item_id = "DEVID" }

[environments.prod]
boundaries.api = { vault_id = "vdev0000000000000000000001", item_id = "PRODID" }

[products.api.keys.EXAMPLE_IDENTITY]
kind = "secret"
source = "generated"
environments = ["dev", "prod"]
rules = { age_identity = true }
"#;

/// A fake signed-in person with one empty item per environment.
fn world() -> (crate::domain::Fleet, FakeOp) {
    let op = FakeOp::default();
    op.signed_in.set(true);
    let dev = op.insert(
        "vdev0000000000000000000001",
        serde_json::json!({
            "title": "myapp · api · dev values", "category": "SECURE_NOTE",
            "sections": [{"id": "api", "label": "api"}],
            "fields": [],
        }),
    );
    let prod = op.insert(
        "vdev0000000000000000000001",
        serde_json::json!({
            "title": "myapp · api · prod values", "category": "SECURE_NOTE",
            "sections": [{"id": "api", "label": "api"}],
            "fields": [],
        }),
    );
    let fleet = crate::config::parse(&FLEET.replace("DEVID", &dev).replace("PRODID", &prod))
        .expect("the fixture contract parses");
    (fleet, op)
}

/// The item ID `env` lives in, looked up from the parsed contract.
fn item_id(fleet: &crate::domain::Fleet, env: &str) -> String {
    fleet.environments[env].boundaries["api"]
        .as_ref()
        .expect("the boundary is declared")
        .item_id
        .as_str()
        .to_string()
}

fn field(op: &FakeOp, id: &str, label: &str) -> Option<String> {
    op.item(id)["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["label"] == label)
        .and_then(|f| f["value"].as_str().map(str::to_string))
}

/// Generate `api/EXAMPLE_IDENTITY` in `env`, returning what generation printed.
fn generate(fleet: &crate::domain::Fleet, op: &FakeOp, env: &str) -> Vec<u8> {
    let mut out = Vec::new();
    run(fleet, env, &["api/EXAMPLE_IDENTITY".into()], op, &mut out).expect("generation succeeds");
    out
}

fn why_of(e: &Error) -> &'static str {
    match e.cause() {
        Some((
            Cause::Guard {
                guard: Guard::GenerateRefused { reason, .. },
            },
            _,
        )) => reason.words(),
        _ => "",
    }
}

// R1: the issue's probe contract loads, and the contract-as-data surface accepts it.

#[test]
fn the_issue_probe_contract_is_accepted_by_the_contract_document() {
    let fleet = crate::config::parse(PROBE).expect("the probe contract parses");
    let mut out = Vec::new();
    crate::app::contract::write_document(&fleet, Some("example"), Some("demo"), true, &mut out)
        .expect("opv contract --json accepts the probe contract");
    let doc: serde_json::Value =
        serde_json::from_slice(&out).expect("the contract document is JSON");
    assert_eq!(
        doc["components"][0]["environments"][0]["keys"][0]["name"],
        "EXAMPLE_IDENTITY"
    );
}

// R2: the stored value is an age identity and output shows exactly its public recipient.

#[test]
fn generating_an_age_identity_stores_a_parseable_age_x25519_identity() {
    let (fleet, op) = world();
    let id = item_id(&fleet, "dev");
    generate(&fleet, &op, "dev");
    let stored = field(&op, &id, "EXAMPLE_IDENTITY").expect("a value was written");
    assert!(stored.parse::<age::x25519::Identity>().is_ok());
}

#[test]
fn generating_an_age_identity_prints_its_written_recipient_exactly_once() {
    let (fleet, op) = world();
    let id = item_id(&fleet, "dev");
    let out = generate(&fleet, &op, "dev");
    let stored = field(&op, &id, "EXAMPLE_IDENTITY").expect("a value was written");
    let recipient = stored
        .parse::<age::x25519::Identity>()
        .expect("the stored value is an identity")
        .to_public()
        .to_string();
    let shown = String::from_utf8(out).expect("output is UTF-8");
    assert_eq!(shown.lines().filter(|line| *line == recipient).count(), 1);
}

// R3: a malformed stored identity fails the age_identity rule, and the reason never quotes
// the value.

fn malformed_identity_failure(value: &str) -> crate::domain::rules::RuleFailure {
    let fleet = crate::config::parse(PROBE).expect("the probe contract parses");
    let spec = fleet.products["demo"].keys["EXAMPLE_IDENTITY"].clone();
    let env = fleet
        .environment("example")
        .expect("the environment is declared");
    crate::domain::rules::check(
        "demo",
        "EXAMPLE_IDENTITY",
        &spec,
        "example",
        env,
        &SecretValue::new(value.to_string()),
    )
    .expect_err("a malformed identity fails its rule")
}

#[test]
fn a_malformed_stored_identity_fails_the_age_identity_rule() {
    assert_eq!(
        malformed_identity_failure("not-an-age-identity").rule,
        "age_identity"
    );
}

#[test]
fn a_malformed_stored_identity_failure_reason_does_not_contain_the_value() {
    let value = "AGE-SECRET-KEY-1ZQXMARKERZQX";
    let failure = malformed_identity_failure(value);
    assert!(!format!("{failure} {failure:?} {failure:#?}").contains("ZQXMARKERZQX"));
}

// R4: generation never overwrites a value, and each environment gets its own identity.

#[test]
fn a_second_generate_for_the_same_key_refuses_as_already_holding_a_value() {
    let (fleet, op) = world();
    generate(&fleet, &op, "dev");
    let e = run(
        &fleet,
        "dev",
        &["api/EXAMPLE_IDENTITY".into()],
        &op,
        &mut Vec::new(),
    )
    .expect_err("a filled field is refused");
    assert_eq!(why_of(&e), GenerateRefusal::HasValue.words());
}

#[test]
fn a_second_generate_for_the_same_key_keeps_the_first_identity() {
    let (fleet, op) = world();
    let id = item_id(&fleet, "dev");
    generate(&fleet, &op, "dev");
    let first = field(&op, &id, "EXAMPLE_IDENTITY").expect("the first value was written");
    let _ = run(
        &fleet,
        "dev",
        &["api/EXAMPLE_IDENTITY".into()],
        &op,
        &mut Vec::new(),
    );
    assert_eq!(field(&op, &id, "EXAMPLE_IDENTITY"), Some(first));
}

#[test]
fn two_environments_get_independent_age_identities() {
    let (fleet, op) = world();
    let dev = item_id(&fleet, "dev");
    let prod = item_id(&fleet, "prod");
    generate(&fleet, &op, "dev");
    generate(&fleet, &op, "prod");
    assert_ne!(
        field(&op, &dev, "EXAMPLE_IDENTITY"),
        field(&op, &prod, "EXAMPLE_IDENTITY")
    );
}

// R5: the identity never appears in output or in any argv the fake runner saw.

#[test]
fn the_generated_identity_never_appears_in_output() {
    let (fleet, op) = world();
    let id = item_id(&fleet, "dev");
    let out = generate(&fleet, &op, "dev");
    let stored = field(&op, &id, "EXAMPLE_IDENTITY").expect("a value was written");
    assert!(
        !String::from_utf8(out)
            .expect("output is UTF-8")
            .contains(&stored)
    );
}

#[test]
fn the_generated_identity_never_appears_in_any_argv() {
    let (fleet, op) = world();
    let id = item_id(&fleet, "dev");
    generate(&fleet, &op, "dev");
    let stored = field(&op, &id, "EXAMPLE_IDENTITY").expect("a value was written");
    assert!(
        !op.calls
            .borrow()
            .iter()
            .flat_map(|call| call.args.iter())
            .any(|arg| arg.contains(&stored))
    );
}
