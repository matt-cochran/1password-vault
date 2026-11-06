//! The sealed target's SSH Key deploy credential and the seal effect (design `sealed-target`
//! §6.2, T2, T16), through the shipped sign-in (`signin::open_on` over `FakeRunner`). One
//! behavioural assertion each. Every key is a stock-tool test fixture
//! (`tests/fixtures/sealed/kat/`) or a fixed test seed.

use base64::Engine;
use serde_json::json;
use ssh_key::LineEnding;
use ssh_key::PrivateKey;
use ssh_key::private::Ed25519Keypair;

use crate::app::signin::{Reach, open_on};
use crate::bundle::allowed_signers::AllowedSigners;
use crate::bundle::crypto::{
    Expect, parse_recipient, parse_signing_key, recipient_fingerprint, verify_bundle,
};
use crate::bundle::format::{Header, Name};
use crate::domain::Fleet;
use crate::host::{FakeEnv, Host};
use crate::runner::fake::FakeRunner;
use crate::runner::{CommandRunner, Output, ProcessRunner, SealCall, SealFailure};

/// A second, unrelated ed25519 public key (a test key from `config_tests.rs`).
const OTHER_SIGNER: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJDLU/HvYSykUVjDt+27aTNV6+QD1JsXLLZpsfXVJg4x opv-sealed-2";

fn kat(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sealed/kat")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// The fixture's `age1…` recipient line (the file opens with a `#` label line).
fn recipient_line() -> String {
    kat("age-recipient.txt")
        .lines()
        .find(|l| l.starts_with("age1"))
        .expect("fixture recipient")
        .to_string()
}

fn recipient() -> age::x25519::Recipient {
    parse_recipient(&recipient_line()).expect("fixture recipient")
}

/// One prod environment with one sealed target whose `sealed.signer` is `signer`.
fn fleet(signer: &str) -> Fleet {
    let recipient = recipient_line();
    crate::config::parse(&format!(
        r#"
[environments.prod]
boundaries.api = {{ vault_id = "vapi", item_id = "iapi" }}

[environments.prod.targets.box]
state_vault_id = "sprod"
deploy_credentials = "op://Ops Prod/opv-sealed-prod-signer"
sealed.out = "sealed/prod/{{product}}.opv-sealed"
sealed.env_name = "{{KEY}}"
sealed.recipients = ["{recipient}"]
sealed.signer = "{}"

[products.api.keys.DATABASE_URL]
kind = "secret"
"#,
        signer.trim()
    ))
    .expect("the sealed fixture configuration loads")
}

/// The fixture signer's own public key.
fn fixture_signer() -> String {
    kat("signer_ed25519.pub")
}

/// The fixture key as RFC 8410 PKCS#8 PEM (what `op` returns by default, T16).
fn fixture_pkcs8() -> String {
    kat("signer_ed25519.pkcs8.pem")
}

/// A valid ed25519 PKCS#8 PEM of a key other than the fixture's.
fn other_pkcs8() -> String {
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(&[7u8; 32]);
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    format!("-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n")
}

/// The SSH Key item as `op item get --format json` returns it: `value` (PKCS#8) and, when
/// given, `ssh_formats.openssh.value`.
fn ssh_key_item(pkcs8: &str, openssh: Option<&str>) -> Output {
    let mut private = json!({
        "id": "private_key", "type": "SSHKEY", "label": "private key", "value": pkcs8,
    });
    if let Some(openssh) = openssh {
        private["ssh_formats"] = json!({"openssh": {"value": openssh}});
    }
    Output::success(
        serde_json::to_vec(&json!({
            "id": "isigner", "title": "opv-sealed-prod-signer", "category": "SSH_KEY",
            "fields": [
                private,
                {"id": "public_key", "type": "STRING", "label": "public key", "value": fixture_signer()},
            ],
        }))
        .unwrap(),
    )
}

fn linux() -> Host {
    Host::from_env(&FakeEnv::new("linux").shell("/bin/bash"))
}

fn header() -> Header {
    let recipient = recipient();
    let signer = parse_signing_key(&kat("signer_ed25519")).expect("fixture signer");
    Header {
        format: "opv-sealed/1".to_string(),
        project: "fleet".to_string(),
        environment: "prod".to_string(),
        product: "api".to_string(),
        target: "box".to_string(),
        revision: 1,
        created_at: "2026-11-04T12:00:00Z".to_string(),
        opv_version: "0.18.0".to_string(),
        plan_id: "plan_test0001".to_string(),
        contract_digest: "sha256:00".to_string(),
        recipients: vec![recipient_fingerprint(&recipient)],
        signer: signer.fingerprint(),
        names: vec![Name {
            name: "DATABASE_URL".to_string(),
            destination: "env:DATABASE_URL".to_string(),
        }],
        secrets_dir_env: None,
        child_environment: None,
        supplied: None,
    }
}

const ENTRIES: [(&str, &[u8]); 1] = [("DATABASE_URL", b"test-marker-database-url")];

/// Seal the fixture batch through `r`.
fn seal_through(r: &dyn CommandRunner) -> Result<Vec<u8>, SealFailure> {
    let recipients = [recipient()];
    let header = header();
    r.seal_bundle(&SealCall::new(&header, &ENTRIES, &recipients))
}

fn verifies(bundle: &[u8]) -> bool {
    let signers = AllowedSigners::parse(kat("allowed_signers").as_bytes()).expect("signers");
    let expect = Expect {
        environment: "prod",
        product: "api",
        project: None,
        min_revision: None,
    };
    verify_bundle(bundle, &signers, &expect).is_ok()
}

#[test]
fn a_key_other_than_sealed_signer_is_refused_before_any_value_is_read() {
    let fl = fleet(OTHER_SIGNER);
    let openssh = kat("signer_ed25519");
    let r = FakeRunner::new([ssh_key_item(&fixture_pkcs8(), Some(&openssh))]);
    let e = open_on(&fl, "prod", &r, Reach::Target, &linux)
        .err()
        .expect("the mismatch is refused");
    let field = match e.parts().0 {
        crate::cause::Cause::InputInvalid { kind, field, .. } => format!("{kind:?} {field}"),
        other => format!("{other:?}"),
    };
    // Exit 2, the item's public key named, and the deploy item the only call made.
    assert_eq!(
        (e.exit_code(), field, r.calls.borrow().len()),
        (2, "DeployCredentials public key".to_string(), 1)
    );
}

#[test]
fn the_openssh_form_is_preferred_over_pkcs8() {
    // `value` holds another key: only the OpenSSH form matches `sealed.signer`.
    let fl = fleet(&fixture_signer());
    let openssh = kat("signer_ed25519");
    let r = FakeRunner::new([ssh_key_item(&other_pkcs8(), Some(&openssh))]);
    assert!(open_on(&fl, "prod", &r, Reach::Target, &linux).is_ok());
}

#[test]
fn pkcs8_is_read_when_the_item_has_no_openssh_form() {
    let fl = fleet(&fixture_signer());
    let r = FakeRunner::new([ssh_key_item(&fixture_pkcs8(), None)]);
    assert!(open_on(&fl, "prod", &r, Reach::Target, &linux).is_ok());
}

#[test]
fn a_signed_in_run_seals_a_bundle_that_verify_accepts() {
    // The signing key is the item's (`value` is another key, so the fake's own fixture
    // fallback would not be the one in use if the login's key failed to arrive).
    let fl = fleet(&fixture_signer());
    let openssh = kat("signer_ed25519");
    let r = FakeRunner::new([ssh_key_item(&other_pkcs8(), Some(&openssh))]);
    let runner = open_on(&fl, "prod", &r, Reach::Target, &linux).expect("signed in");
    let bundle = seal_through(&runner).expect("sealed");
    assert!(verifies(&bundle));
}

#[test]
fn the_login_hands_its_key_to_the_seal_effect() {
    let fl = fleet(&fixture_signer());
    let openssh = kat("signer_ed25519");
    let r = FakeRunner::new([ssh_key_item(&other_pkcs8(), Some(&openssh))]);
    let runner = open_on(&fl, "prod", &r, Reach::Target, &linux).expect("signed in");
    seal_through(&runner).expect("sealed");
    let seal = r
        .calls
        .borrow()
        .iter()
        .find(|c| c.program == crate::runner::seal::PROGRAM)
        .map(|c| c.env.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>());
    assert_eq!(seal, Some(vec![crate::runner::seal::KEY.to_string()]));
}

#[test]
fn the_fake_never_records_the_signing_key() {
    let fl = fleet(&fixture_signer());
    let openssh = kat("signer_ed25519");
    let r = FakeRunner::new([ssh_key_item(&fixture_pkcs8(), Some(&openssh))]);
    let runner = open_on(&fl, "prod", &r, Reach::Target, &linux).expect("signed in");
    seal_through(&runner).expect("sealed");
    let leaked = r
        .calls
        .borrow()
        .iter()
        .filter(|c| c.program == crate::runner::seal::PROGRAM)
        .any(|c| c.env.iter().any(|(_, v)| v.contains("PRIVATE KEY")));
    assert!(!leaked);
}

#[test]
fn the_fake_alone_seals_with_the_fixture_key() {
    let bundle = seal_through(&FakeRunner::default()).expect("sealed");
    assert!(verifies(&bundle));
}

#[test]
fn a_runner_without_a_sealed_sign_in_seals_nothing() {
    let r = ProcessRunner::default();
    assert!(matches!(seal_through(&r), Err(SealFailure::NotSignedIn(_))));
}

#[test]
fn a_seal_call_debug_names_no_value() {
    let recipients = [recipient()];
    let header = header();
    let key = kat("signer_ed25519");
    let env = [(crate::runner::seal::KEY, key.as_str())];
    let call = SealCall {
        env: &env,
        ..SealCall::new(&header, &ENTRIES, &recipients)
    };
    let shown = format!("{call:?}");
    assert!(!shown.contains("test-marker") && !shown.contains("PRIVATE KEY"));
}

#[test]
fn an_encrypted_or_foreign_key_is_refused_as_the_private_key_field() {
    // A non-ed25519-shaped PEM in the OpenSSH slot: refused by field, never quoted.
    let fl = fleet(&fixture_signer());
    let not_a_key = PrivateKey::from(Ed25519Keypair::from_seed(&[9; 32]))
        .to_openssh(LineEnding::LF)
        .expect("openssh")
        .replace("OPENSSH PRIVATE KEY", "RSA PRIVATE KEY");
    let r = FakeRunner::new([ssh_key_item(&fixture_pkcs8(), Some(&not_a_key))]);
    let e = open_on(&fl, "prod", &r, Reach::Target, &linux)
        .err()
        .expect("refused");
    let field = match e.parts().0 {
        crate::cause::Cause::InputInvalid { field, .. } => field.clone(),
        other => format!("{other:?}"),
    };
    assert_eq!(field, "private key");
}
