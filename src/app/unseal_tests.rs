//! `opv unseal` without `--exec` (lane st-u1, design sealed-target §4.2, §10), against the
//! stock-tool known-answer bundle in `tests/fixtures/sealed/kat/`: one behavioural
//! assertion each.

use std::path::PathBuf;

use secrecy::ExposeSecret;

use super::*;

fn kat(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sealed/kat")
        .join(name)
}

/// The KAT bundle's own scope (`prod/api`, revision 7) with the fixture identity and signers.
fn request(verify_only: bool) -> Request {
    Request {
        bundle: kat("bundle.opv-sealed"),
        env: "prod".into(),
        product: "api".into(),
        project: None,
        signers: kat("allowed_signers"),
        identity: Some(IdentitySource::File(kat("age-identity.txt"))),
        min_revision: None,
        verify_only,
        json: false,
    }
}

fn ram_ok() -> Result<PathBuf, RamDir> {
    Ok(PathBuf::from("/run/user/1000"))
}

fn unseal(req: &Request) -> Result<String, Error> {
    let mut out = Vec::new();
    run_with(req, &ram_ok, &mut out)?;
    Ok(String::from_utf8(out).unwrap())
}

fn code(req: &Request) -> &'static str {
    unseal(req).expect_err("refused").code_str()
}

/// The KAT payload's values, decrypted by the codec directly.
fn kat_values() -> Vec<String> {
    let req = request(false);
    open(&req)
        .expect("the KAT bundle opens")
        .values
        .iter()
        .map(|(_, v)| String::from_utf8(v.to_vec()).unwrap())
        .collect()
}

#[test]
fn verify_only_accepts_the_kat_bundle_with_the_fixture_identity_and_signers() {
    let out = unseal(&request(true)).expect("verified");
    assert!(
        out.starts_with("verified prod/api revision 7 (project fleet, target box)"),
        "{out}"
    );
}

#[test]
fn a_wrong_environment_is_refused() {
    let mut req = request(true);
    req.env = "staging".into();
    assert_eq!(code(&req), "sealed_scope_mismatch");
}

#[test]
fn a_revision_below_the_floor_is_refused() {
    let mut req = request(true);
    req.min_revision = Some(8);
    assert_eq!(code(&req), "sealed_revision_below_floor");
}

/// A changed ciphertext byte fails the signature before the identity is even read: the
/// identity file named here does not exist, so reaching decryption would refuse it instead.
#[test]
fn a_tampered_bundle_is_refused_before_decryption() {
    let dir = tempfile::tempdir().unwrap();
    let mut bytes = std::fs::read(kat("bundle.opv-sealed")).unwrap();
    let at = bytes
        .windows(4)
        .position(|w| w == b"YWdl")
        .expect("the age block");
    bytes[at] = b'Z';
    let tampered = dir.path().join("bundle.opv-sealed");
    std::fs::write(&tampered, &bytes).unwrap();
    let mut req = request(false);
    req.bundle = tampered;
    req.identity = Some(IdentitySource::File(dir.path().join("no-identity")));
    assert_eq!(code(&req), "sealed_signature_invalid");
}

#[test]
fn the_output_holds_no_value() {
    let values = kat_values();
    let mut req = request(false);
    let text = unseal(&req).unwrap();
    req.json = true;
    let json = unseal(&req).unwrap();
    let leaked: Vec<&String> = values
        .iter()
        .filter(|v| text.contains(v.as_str()) || json.contains(v.as_str()))
        .collect();
    assert!(
        !values.is_empty() && leaked.is_empty(),
        "values in the output"
    );
}

#[test]
fn json_emits_one_document() {
    let mut req = request(true);
    req.json = true;
    let out = unseal(&req).unwrap();
    let docs: Vec<serde_json::Value> = serde_json::Deserializer::from_str(&out)
        .into_iter()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(
        docs.len() == 1 && docs[0]["schema"] == "opv.unseal/1",
        "{out}"
    );
}

/// R2: with file keys, `--verify-only` reports a missing RAM-backed runtime directory.
#[test]
fn verify_only_refuses_file_keys_without_a_ram_dir() {
    let mut out = Vec::new();
    let err = run_with(&request(true), &|| Err(RamDir::NotTmpfs), &mut out).unwrap_err();
    assert_eq!(err.code_str(), "ram_dir_unavailable");
}

/// U4: an identity whose recipient the header does not list is refused before decryption.
#[test]
fn verify_only_refuses_an_identity_that_is_not_a_recipient() {
    let dir = tempfile::tempdir().unwrap();
    let other = dir.path().join("other.txt");
    // A fresh identity, which the KAT bundle was not sealed to.
    std::fs::write(
        &other,
        age::x25519::Identity::generate()
            .to_string()
            .expose_secret(),
    )
    .unwrap();
    let mut req = request(true);
    req.identity = Some(IdentitySource::File(other));
    assert_eq!(code(&req), "sealed_not_a_recipient");
}

/// Every codec refusal `opv unseal` can meet keeps its code as a cause.
#[test]
fn the_cause_keeps_the_codec_code() {
    use crate::bundle::crypto::SignatureRefusal;
    use crate::bundle::format::FormatError;
    let from = IdentityFrom::Env { var: "ID".into() };
    for e in [
        CryptoError::Malformed(FormatError::CarriageReturn),
        CryptoError::AgeMalformed,
        CryptoError::Signature(SignatureRefusal::Invalid),
        CryptoError::ScopeMismatch {
            field: "product",
            expected: "api".into(),
            found: "web".into(),
        },
        CryptoError::RevisionBelowFloor {
            revision: 1,
            floor: 2,
        },
        CryptoError::IdentityUnusable("x"),
        CryptoError::NotARecipient,
        CryptoError::PayloadMismatch(FormatError::PayloadNamesMismatch),
    ] {
        let cause = sealed_refusal(
            std::path::Path::new("b"),
            std::path::Path::new("s"),
            Some(&from),
            &e,
        );
        assert_eq!(cause.code(), e.code());
    }
}

// --- security review 0.18.0 S2, S4: variables and project ---

/// A bundle signed by the KAT signer for `prod/api` that delivers `API_TOKEN` to `env:<var>`
/// and `TLS_KEY` to a file, written into `dir`. The codec's own `seal` refuses such a
/// header, so it is assembled by hand, as a crafted bundle would be.
fn crafted(dir: &std::path::Path, var: &str) -> PathBuf {
    use crate::bundle::crypto::{encrypt, parse_signing_key, sign};
    use crate::bundle::format::{FORMAT_LINE, Name, canonical_header, encode_payload};
    let identity =
        crypto::parse_identity(&std::fs::read_to_string(kat("age-identity.txt")).unwrap()).unwrap();
    let key = parse_signing_key(&std::fs::read_to_string(kat("signer_ed25519")).unwrap()).unwrap();
    let header = Header {
        format: "opv-sealed/1".into(),
        project: "fleet".into(),
        environment: "prod".into(),
        product: "api".into(),
        target: "box".into(),
        revision: 7,
        created_at: "2026-11-05T00:00:00Z".into(),
        opv_version: "0.18.0".into(),
        plan_id: "plan_test0001".into(),
        contract_digest: "sha256:00".into(),
        recipients: vec![crypto::recipient_fingerprint(&identity.recipient())],
        signer: key.fingerprint(),
        names: vec![
            Name {
                name: "API_TOKEN".into(),
                destination: format!("env:{var}"),
            },
            Name {
                name: "TLS_KEY".into(),
                destination: "file:tls/key".into(),
            },
        ],
        secrets_dir_env: Some("SECRETS_DIR".into()),
        child_environment: None,
    };
    let line = canonical_header(&header).unwrap();
    let entries: [(&str, &[u8]); 2] = [("API_TOKEN", b"marker-a"), ("TLS_KEY", b"marker-b")];
    let payload = encode_payload(&line, &entries).unwrap();
    let mut bundle = FORMAT_LINE.to_vec();
    bundle.extend_from_slice(&line);
    bundle.push(b'\n');
    bundle.extend_from_slice(&encrypt(&[identity.recipient()], &payload).unwrap());
    let signature = sign(&key, &bundle).unwrap();
    bundle.extend_from_slice(&signature);
    let path = dir.join("crafted.opv-sealed");
    std::fs::write(&path, bundle).unwrap();
    path
}

/// `--exec` on a crafted bundle naming `var`. The bundle has a file key and no RAM
/// directory is offered, so had the variable passed, the refusal would be
/// `ram_dir_unavailable` and nothing would start either way.
fn exec_code(var: &str, identity: IdentitySource) -> &'static str {
    let tmp = tempfile::tempdir().unwrap();
    let mut req = request(false);
    req.bundle = crafted(tmp.path(), var);
    req.identity = Some(identity);
    let no_dir = || Err(RamDir::Unset);
    super::super::unseal_exec::run_with(&req, &["true".to_string()], &no_dir)
        .expect_err("refused")
        .code_str()
}

fn kat_identity() -> IdentitySource {
    IdentitySource::File(kat("age-identity.txt"))
}

#[test]
fn a_bundle_naming_an_op_session_variable_is_refused_before_exec() {
    assert_eq!(
        exec_code("OP_SESSION_x", kat_identity()),
        "sealed_malformed"
    );
}

#[test]
fn a_bundle_naming_a_lowercase_op_variable_is_refused_before_exec() {
    assert_eq!(exec_code("op_x", kat_identity()), "sealed_malformed");
}

/// The identity variable is never read: the refusal comes at verification.
#[test]
fn a_bundle_naming_the_identity_variable_is_refused_before_exec() {
    assert_eq!(
        exec_code("APP_IDENTITY", IdentitySource::Env("APP_IDENTITY".into())),
        "sealed_malformed"
    );
}

#[test]
fn a_crafted_bundle_with_an_ordinary_variable_reaches_delivery() {
    assert_eq!(
        exec_code("API_TOKEN", kat_identity()),
        "ram_dir_unavailable"
    );
}

#[test]
fn a_project_mismatch_is_refused() {
    let mut req = request(true);
    req.project = Some("other".into());
    assert_eq!(code(&req), "sealed_scope_mismatch");
}

#[test]
fn the_bundles_own_project_is_accepted() {
    let mut req = request(true);
    req.project = Some("fleet".into());
    assert!(unseal(&req).is_ok());
}
