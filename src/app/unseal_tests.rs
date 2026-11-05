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
