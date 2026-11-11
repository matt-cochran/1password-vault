//! `opv generate` Ed25519 OpenSSH recipe: focused behaviour tests (#294).
//!
//! The #294 acceptance for an `ssh_ed25519 = true` key: the generated private key signs an
//! SSHSIG that its own public half verifies, two environments get two different keys, a
//! second generation for one environment never replaces the first, and an invalid stored
//! value fails the `ssh_ed25519` rule without the failure quoting the value. Every valid
//! key is built in-test (`generate_ssh::make_ed25519`); no key text is committed.

use super::*;
use crate::adapters::fake_op::FakeOp;
use crate::cause::{Cause, GenerateRefusal, Guard};
use crate::domain::{Fleet, SecretValue};

/// A dev/prod fleet whose `api/SIGNING_KEY` is a generated Ed25519 OpenSSH key.
const TWO_ENVS: &str = r#"[environments.dev]
boundaries.api = { vault_id = "vdev0000000000000000000001", item_id = "IDEV" }

[environments.prod]
boundaries.api = { vault_id = "vdev0000000000000000000001", item_id = "IPROD" }

[products.api.keys.SIGNING_KEY]
kind = "secret"
environments = ["dev", "prod"]
rules = { ssh_ed25519 = true }
file = "signing-key"
"#;

/// An empty boundary item carrying the product's section.
fn empty_item() -> serde_json::Value {
    serde_json::json!({
        "title": "myapp · api · values", "category": "SECURE_NOTE",
        "sections": [{"id": "api", "label": "api"}],
        "fields": [],
    })
}

/// Two items (dev, prod) and the fleet whose boundaries name them.
fn two_env_world() -> (Fleet, FakeOp, String, String) {
    let op = FakeOp::default();
    op.signed_in.set(true);
    let dev = op.insert("vdev0000000000000000000001", empty_item());
    let prod = op.insert("vdev0000000000000000000001", empty_item());
    let fleet =
        crate::config::parse(&TWO_ENVS.replace("IDEV", &dev).replace("IPROD", &prod)).unwrap();
    (fleet, op, dev, prod)
}

/// The stored value of `label` in `id`, if any.
fn field(op: &FakeOp, id: &str, label: &str) -> Option<String> {
    op.item(id)["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["label"] == label)
        .and_then(|f| f["value"].as_str().map(str::to_string))
}

/// The `GenerateRefused` reason in `e`, or empty for another cause.
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

// --- R1: the generated key is a working signer ------------------------------------------

#[test]
fn a_generated_key_signs_a_message_its_public_half_verifies() {
    let (value, public) = generate_ssh::make_ed25519().unwrap();
    let private = ssh_key::PrivateKey::from_openssh(value.expose()).unwrap();
    let signature = private
        .sign("opv-acceptance", ssh_key::HashAlg::Sha512, b"the message")
        .unwrap();
    let verifier = ssh_key::PublicKey::from_openssh(&public.openssh).unwrap();
    assert!(
        verifier
            .verify("opv-acceptance", b"the message", &signature)
            .is_ok()
    );
}

// --- R2: two environments, one key, no replacement --------------------------------------

#[test]
fn generating_one_key_for_two_environments_gives_two_different_keys() {
    let (fleet, op, dev, prod) = two_env_world();
    run(
        &fleet,
        "dev",
        &["api/SIGNING_KEY".into()],
        &op,
        &mut Vec::new(),
    )
    .unwrap();
    run(
        &fleet,
        "prod",
        &["api/SIGNING_KEY".into()],
        &op,
        &mut Vec::new(),
    )
    .unwrap();
    assert_ne!(
        field(&op, &dev, "SIGNING_KEY"),
        field(&op, &prod, "SIGNING_KEY")
    );
}

#[test]
fn generating_twice_for_one_environment_refuses_the_second_as_already_holding_a_value() {
    let (fleet, op, _dev, _prod) = two_env_world();
    run(
        &fleet,
        "dev",
        &["api/SIGNING_KEY".into()],
        &op,
        &mut Vec::new(),
    )
    .unwrap();
    let e = run(
        &fleet,
        "dev",
        &["api/SIGNING_KEY".into()],
        &op,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(why_of(&e), GenerateRefusal::HasValue.words());
}

#[test]
fn generating_twice_for_one_environment_keeps_the_first_key() {
    let (fleet, op, dev, _prod) = two_env_world();
    run(
        &fleet,
        "dev",
        &["api/SIGNING_KEY".into()],
        &op,
        &mut Vec::new(),
    )
    .unwrap();
    let first = field(&op, &dev, "SIGNING_KEY");
    let _ = run(
        &fleet,
        "dev",
        &["api/SIGNING_KEY".into()],
        &op,
        &mut Vec::new(),
    );
    assert_eq!(field(&op, &dev, "SIGNING_KEY"), first);
}

// --- R3: an invalid stored value fails the ssh_ed25519 rule, quietly ---------------------

/// A one-environment fleet whose `api/SIGNING_KEY` is an `ssh_ed25519` key.
const SSH_FLEET: &str = r#"[environments.dev]
boundaries.api = { vault_id = "vdev0000000000000000000001", item_id = "idev" }

[products.api.keys.SIGNING_KEY]
kind = "secret"
environments = ["dev"]
rules = { ssh_ed25519 = true }
file = "signing-key"
"#;

/// Check `value` against the fleet's `ssh_ed25519` rule.
fn check_ssh(value: &str) -> Result<(), crate::domain::rules::RuleFailure> {
    let fleet = crate::config::parse(SSH_FLEET).unwrap();
    let spec = fleet.products["api"].keys["SIGNING_KEY"].clone();
    crate::domain::rules::check(
        "api",
        "SIGNING_KEY",
        &spec,
        "dev",
        fleet.environment("dev").unwrap(),
        &SecretValue::new(value.into()),
    )
    .map(|_| ())
}

/// An `ssh-rsa` OpenSSH private key, built in-test from opaque bytes (no committed text).
fn rsa_ssh_fixture() -> String {
    use ssh_key::private::{KeypairData, OpaqueKeypair};
    use ssh_key::public::OpaquePublicKey;
    use ssh_key::{Algorithm, LineEnding, PrivateKey};
    let keypair = OpaqueKeypair::new(
        vec![1u8; 32],
        OpaquePublicKey::new(vec![2u8; 32], Algorithm::Rsa { hash: None }),
    );
    PrivateKey::new(KeypairData::Other(keypair), "")
        .unwrap()
        .to_openssh(LineEnding::LF)
        .unwrap()
        .to_string()
}

#[test]
fn a_garbage_ssh_ed25519_value_fails_the_ssh_ed25519_rule() {
    assert_eq!(
        check_ssh("not an OpenSSH key").unwrap_err().rule,
        "ssh_ed25519"
    );
}

#[test]
fn an_rsa_stored_value_fails_the_ssh_ed25519_rule() {
    assert_eq!(
        check_ssh(&rsa_ssh_fixture()).unwrap_err().rule,
        "ssh_ed25519"
    );
}

#[test]
fn an_ssh_ed25519_rule_failure_never_quotes_the_value() {
    let value = "ZQXMARKERZQX-not-an-openssh-key";
    let failure = check_ssh(value).unwrap_err();
    assert!(!format!("{failure} {failure:?} {failure:#?}").contains("ZQXMARKERZQX"));
}
