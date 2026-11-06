//! Behavioural tests for the sealed bundle's cryptography (design sealed-target §6, §9.2,
//! §10 items 1, 3, 5 and the codec refusals). Each test asserts one outcome. The KATs use
//! the stock-tool fixtures in `tests/fixtures/sealed/kat/`; every refusal of [`open`] is
//! checked through a counting decryptor and asserts that decryption was never attempted.
//! Every key here is a test fixture.

use std::cell::Cell;
use std::path::PathBuf;

use secrecy::ExposeSecret;
use ssh_key::private::Ed25519Keypair;
use ssh_key::{HashAlg, LineEnding, PrivateKey};
use zeroize::Zeroizing;

use super::allowed_signers::{AllowedSigners, SignersError};
use super::crypto::{
    CryptoError, Decrypt, Expect, Identity, SignatureRefusal, SigningKey, check_recipient, decrypt,
    encrypt, open, open_with, parse_identity, parse_recipient, parse_signing_key,
    recipient_fingerprint, seal, sign, verify, verify_bundle,
};
use super::format::{FormatError, Header, Name, canonical_header};

fn kat(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sealed/kat")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn kat_str(name: &str) -> String {
    String::from_utf8(kat(name)).expect("utf-8")
}

fn identity() -> Identity {
    parse_identity(&kat_str("age-identity.txt")).expect("fixture identity")
}

/// A second identity that no fixture bundle lists.
fn stranger() -> Identity {
    parse_identity(
        age::x25519::Identity::generate()
            .to_string()
            .expose_secret(),
    )
    .expect("generated identity")
}

fn signer() -> SigningKey {
    parse_signing_key(&kat_str("signer_ed25519")).expect("fixture signer")
}

/// A second, deterministic test signer.
fn other_signer() -> SigningKey {
    let key = PrivateKey::from(Ed25519Keypair::from_seed(&[7; 32]));
    parse_signing_key(&key.to_openssh(LineEnding::LF).expect("openssh")).expect("signer")
}

fn signers_line(principals: &str, key: &SigningKey) -> String {
    format!(
        "{principals} namespaces=\"opv-sealed\" {}\n",
        key.public_key().to_openssh().expect("openssh")
    )
}

fn header(environment: &str, recipient: &Identity, key: &SigningKey) -> Header {
    Header {
        format: "opv-sealed/1".to_string(),
        project: "fleet".to_string(),
        environment: environment.to_string(),
        product: "api".to_string(),
        target: "box".to_string(),
        revision: 10,
        created_at: "2026-11-04T12:00:00Z".to_string(),
        opv_version: "0.18.0".to_string(),
        plan_id: "plan_test0001".to_string(),
        contract_digest: "sha256:00".to_string(),
        recipients: vec![recipient_fingerprint(&recipient.recipient())],
        signer: key.fingerprint(),
        names: vec![
            Name {
                name: "API_TOKEN".to_string(),
                destination: "env:API_TOKEN".to_string(),
            },
            Name {
                name: "TLS_KEY".to_string(),
                destination: "file:tls/key".to_string(),
            },
        ],
        secrets_dir_env: Some("SECRETS_DIR".to_string()),
        child_environment: None,
    }
}

const ENTRIES: [(&str, &[u8]); 2] = [
    ("API_TOKEN", b"marker-api-token"),
    ("TLS_KEY", b"\x00\x01binary\xffmarker"),
];

fn prod_bundle() -> Vec<u8> {
    let id = identity();
    let key = signer();
    seal(
        &header("prod", &id, &key),
        &ENTRIES,
        &[id.recipient()],
        &key,
    )
    .expect("seal")
}

fn prod_signers() -> String {
    signers_line("prod", &signer())
}

const PROD: Expect<'static> = Expect {
    environment: "prod",
    product: "api",
    project: None,
    min_revision: None,
};

/// An identity that counts decryption attempts.
struct Counting {
    identity: Identity,
    attempts: Cell<usize>,
}

impl Decrypt for Counting {
    fn recipient_fingerprint(&self) -> String {
        self.identity.recipient_fingerprint()
    }

    fn decrypt(&self, armored: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        self.attempts.set(self.attempts.get() + 1);
        Decrypt::decrypt(&self.identity, armored)
    }
}

/// Run the runtime's path (parse the signers file, then open) with a counting identity and
/// return the refusal with the number of decryption attempts.
fn refuse_with(
    bundle: &[u8],
    signers: &str,
    expect: &Expect<'_>,
    identity: Identity,
) -> (CryptoError, usize) {
    let counting = Counting {
        identity,
        attempts: Cell::new(0),
    };
    let result = AllowedSigners::parse(signers.as_bytes())
        .map_err(CryptoError::Signers)
        .and_then(|signers| open_with(bundle, &counting, &signers, expect));
    match result {
        Ok(_) => panic!("the bundle was accepted"),
        Err(error) => (error, counting.attempts.get()),
    }
}

fn refuse(bundle: &[u8], signers: &str, expect: &Expect<'_>) -> (CryptoError, usize) {
    refuse_with(bundle, signers, expect, identity())
}

/// Assemble a bundle by hand: any header line, any payload bytes, signed with any
/// namespace and hash by the fixture signer, bypassing [`seal`]'s guards.
fn hand_bundle(
    header_line: &[u8],
    payload: &[u8],
    recipient: &Identity,
    namespace: &str,
    hash: HashAlg,
) -> Vec<u8> {
    let age = encrypt(&[recipient.recipient()], payload).expect("encrypt");
    let mut signed = b"opv-sealed v1\n".to_vec();
    signed.extend_from_slice(header_line);
    signed.push(b'\n');
    signed.extend_from_slice(&age);
    let signature = PrivateKey::from_openssh(kat("signer_ed25519"))
        .expect("key")
        .sign(namespace, hash, &signed)
        .expect("sign")
        .to_pem(LineEnding::LF)
        .expect("pem");
    signed.extend_from_slice(signature.as_bytes());
    signed
}

/// A payload framed by hand, with any header digest and names.
fn hand_payload(digest: &[u8], entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = b"OPV-SEALED-PAYLOAD 1\n".to_vec();
    out.extend_from_slice(digest);
    out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for (name, value) in entries {
        out.extend_from_slice(&(name.len() as u16).to_be_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
    }
    out.extend_from_slice(b"END\n");
    out
}

fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha256::digest(data).to_vec()
}

/// Replace the first occurrence of `from` with `to`.
fn replace(bundle: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let at = bundle
        .windows(from.len())
        .position(|w| w == from)
        .expect("needle");
    [&bundle[..at], to, &bundle[at + from.len()..]].concat()
}

// --- KATs against the stock tools (§10 items 1 and 5) ---

#[test]
fn signing_the_kat_message_with_the_openssh_key_matches_ssh_keygen() {
    let sig = sign(&signer(), &kat("message.txt")).expect("sign");
    assert_eq!(sig, kat("message.txt.sig"));
}

#[test]
fn signing_the_kat_message_with_the_pkcs8_key_matches_ssh_keygen() {
    let key = parse_signing_key(&kat_str("signer_ed25519.pkcs8.pem")).expect("pkcs8");
    assert_eq!(
        sign(&key, &kat("message.txt")).expect("sign"),
        kat("message.txt.sig")
    );
}

#[test]
fn the_ssh_keygen_signature_verifies_for_prod() {
    let signers = AllowedSigners::parse(&kat("allowed_signers")).expect("signers");
    let key = verify(
        &signers,
        "prod",
        &kat("message.txt"),
        &kat("message.txt.sig"),
    );
    assert_eq!(
        key.map(|k| k.fingerprint(HashAlg::Sha256).to_string()),
        Ok("SHA256:WukzcBfSQ/h2lb+LBUQqZV32GZGju50eutYraFc51OY".to_string())
    );
}

#[test]
fn the_ssh_keygen_signature_is_refused_for_staging() {
    let signers = AllowedSigners::parse(&kat("allowed_signers")).expect("signers");
    let refusal = verify(
        &signers,
        "staging",
        &kat("message.txt"),
        &kat("message.txt.sig"),
    )
    .map(|_| ());
    assert_eq!(
        refusal,
        Err(SignatureRefusal::OtherPrincipal {
            principal: "staging".to_string()
        })
    );
}

#[test]
fn the_age_cli_ciphertext_decrypts_with_the_fixture_identity() {
    let plain = decrypt(&kat("ciphertext.age"), &identity()).expect("decrypt");
    assert_eq!(plain.as_slice(), kat("plaintext.txt").as_slice());
}

#[test]
fn the_stock_tool_bundle_opens_with_exact_names_and_bytes() {
    let signers = AllowedSigners::parse(&kat("allowed_signers")).expect("signers");
    let opened = open(&kat("bundle.opv-sealed"), &identity(), &signers, &PROD).expect("open");
    let values: Vec<(String, Vec<u8>)> = opened
        .values
        .iter()
        .map(|(name, value)| (name.clone(), value.to_vec()))
        .collect();
    assert_eq!(
        values,
        vec![
            (
                "DATABASE_URL".to_string(),
                b"postgres://kat:not-a-secret@db.invalid/kat".to_vec()
            ),
            (
                "TLS_KEY".to_string(),
                b"-----BEGIN TEST KEY-----\nnot-a-secret\n-----END TEST KEY-----\n".to_vec()
            ),
        ]
    );
}

#[test]
fn the_stock_tool_bundle_reports_its_signer_fingerprint() {
    let signers = AllowedSigners::parse(&kat("allowed_signers")).expect("signers");
    let opened = open(&kat("bundle.opv-sealed"), &identity(), &signers, &PROD).expect("open");
    assert_eq!(
        opened.signer,
        "SHA256:WukzcBfSQ/h2lb+LBUQqZV32GZGju50eutYraFc51OY"
    );
}

// --- keys and recipients ---

#[test]
fn the_fixture_identity_derives_the_fixture_recipient() {
    assert_eq!(
        identity().recipient().to_string(),
        kat_str("age-recipient.txt").trim()
    );
}

#[test]
fn an_identity_file_with_two_identities_is_refused() {
    let line = kat_str("age-identity.txt");
    let two = format!("{line}\n{line}");
    assert_eq!(
        parse_identity(&two).err(),
        Some(CryptoError::IdentityUnusable("more than one identity"))
    );
}

#[test]
fn a_plugin_identity_is_refused() {
    let plugin = "AGE-PLUGIN-YUBIKEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ";
    assert_eq!(
        parse_identity(plugin).err().map(|e| e.code()),
        Some("sealed_identity_unusable")
    );
}

#[test]
fn an_empty_identity_is_refused() {
    assert_eq!(
        parse_identity("# nothing here\n").err(),
        Some(CryptoError::IdentityUnusable("no AGE-SECRET-KEY-1… line"))
    );
}

#[test]
fn the_fixture_recipient_parses_as_x25519() {
    let text = kat_str("age-recipient.txt");
    assert_eq!(
        parse_recipient(text.trim()).map(|r| r.to_string()).ok(),
        Some(text.trim().to_string())
    );
}

#[test]
fn an_ssh_recipient_is_refused() {
    let ssh = kat_str("signer_ed25519.pub");
    assert_eq!(
        parse_recipient(ssh.trim()).err(),
        Some(CryptoError::RecipientUnsupported("an SSH recipient"))
    );
}

#[test]
fn a_plugin_recipient_is_refused() {
    assert_eq!(
        parse_recipient("age1yubikey1qwt50d05nh5vutpdzmlg5wn80xq5negm4uj9ghv0snvdd3yysf5yw3rhl3t")
            .err(),
        Some(CryptoError::RecipientUnsupported("a plugin recipient"))
    );
}

#[test]
fn a_hybrid_post_quantum_recipient_is_refused() {
    assert_eq!(
        parse_recipient("age1pq1qqqqqqqqqqqqqqqqqqqqqqqqqqqq").err(),
        Some(CryptoError::RecipientUnsupported(
            "a hybrid post-quantum recipient"
        ))
    );
}

#[test]
fn the_pkcs8_and_openssh_forms_are_one_key() {
    let pkcs8 = parse_signing_key(&kat_str("signer_ed25519.pkcs8.pem")).expect("pkcs8");
    assert_eq!(pkcs8.fingerprint(), signer().fingerprint());
}

#[test]
fn an_encrypted_openssh_key_is_refused() {
    const ENCRYPTED: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCOmCw2oq
UY2QbOi6VzixkAAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIJbP+z4JfIVq1Ybz
sDNpWaIgudK86e21OEiE4qtcBH8+AAAAkGGdC3PgckT6gzH1K7EqQiuGvqC/jPK2rYb2fT
kqmFwk2N0e/afmJKy4xLBbnUwB630igBhmjEexvseYC4Y6QDoPPnVrIBJdTCyoeBtLwHQu
qslBAOjgdsjhG8oyAd/BpB4sBG70joiwuUzGzE6sNcYiPttLcJy4ogL/pcjZB4we+fjhqT
LXQmK70k1B2J8Oiw==
-----END OPENSSH PRIVATE KEY-----
";
    assert_eq!(
        parse_signing_key(ENCRYPTED).err().map(|e| e.code()),
        Some("input_invalid")
    );
}

#[test]
fn a_pkcs8_key_of_another_type_is_refused() {
    use base64::Engine;
    let der = [0x30u8; 48];
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        base64::engine::general_purpose::STANDARD.encode(der)
    );
    assert_eq!(
        parse_signing_key(&pem).err(),
        Some(CryptoError::SigningKeyInvalid(
            "the PKCS#8 key is not an unencrypted ed25519 key"
        ))
    );
}

#[test]
fn a_public_key_is_not_a_signing_key() {
    assert_eq!(
        parse_signing_key(&kat_str("signer_ed25519.pub")).err(),
        Some(CryptoError::SigningKeyInvalid(
            "not an OpenSSH or PKCS#8 private key"
        ))
    );
}

// --- seal and open ---

#[test]
fn a_sealed_bundle_opens_to_the_exact_values() {
    let signers = AllowedSigners::parse(prod_signers().as_bytes()).expect("signers");
    let opened = open(&prod_bundle(), &identity(), &signers, &PROD).expect("open");
    let values: Vec<(&str, &[u8])> = opened
        .values
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_slice()))
        .collect();
    assert_eq!(values, ENTRIES.to_vec());
}

#[test]
fn a_bundle_with_an_empty_value_round_trips() {
    let id = identity();
    let key = signer();
    let entries: [(&str, &[u8]); 2] = [("API_TOKEN", b""), ("TLS_KEY", b"x")];
    let bundle = seal(
        &header("prod", &id, &key),
        &entries,
        &[id.recipient()],
        &key,
    )
    .expect("seal");
    let signers = AllowedSigners::parse(prod_signers().as_bytes()).expect("signers");
    let opened = open(&bundle, &id, &signers, &PROD).expect("open");
    assert!(opened.values[0].1.is_empty());
}

#[test]
fn a_bundle_at_the_revision_floor_opens() {
    let signers = AllowedSigners::parse(prod_signers().as_bytes()).expect("signers");
    let expect = Expect {
        min_revision: Some(10),
        ..PROD
    };
    assert!(open(&prod_bundle(), &identity(), &signers, &expect).is_ok());
}

#[test]
fn a_signer_listed_with_a_principal_list_opens_the_bundle() {
    let signers =
        AllowedSigners::parse(signers_line("staging,prod", &signer()).as_bytes()).expect("ok");
    assert!(open(&prod_bundle(), &identity(), &signers, &PROD).is_ok());
}

#[test]
fn verify_only_needs_no_identity() {
    let signers = AllowedSigners::parse(prod_signers().as_bytes()).expect("signers");
    let verified = verify_bundle(&prod_bundle(), &signers, &PROD).expect("verified");
    assert_eq!(verified.signer, signer().fingerprint());
}

#[test]
fn verify_only_with_a_non_member_identity_is_not_a_recipient() {
    let signers = AllowedSigners::parse(prod_signers().as_bytes()).expect("signers");
    let verified = verify_bundle(&prod_bundle(), &signers, &PROD).expect("verified");
    assert_eq!(
        check_recipient(&verified, &stranger()),
        Err(CryptoError::NotARecipient)
    );
}

#[test]
fn seal_refuses_entries_that_differ_from_the_header_names() {
    let id = identity();
    let key = signer();
    let entries: [(&str, &[u8]); 1] = [("API_TOKEN", b"x")];
    assert_eq!(
        seal(
            &header("prod", &id, &key),
            &entries,
            &[id.recipient()],
            &key
        )
        .err(),
        Some(CryptoError::SealMismatch("names"))
    );
}

#[test]
fn seal_refuses_a_header_naming_another_signer() {
    let id = identity();
    assert_eq!(
        seal(
            &header("prod", &id, &other_signer()),
            &ENTRIES,
            &[id.recipient()],
            &signer()
        )
        .err(),
        Some(CryptoError::SealMismatch("signer"))
    );
}

#[test]
fn an_opened_bundle_debug_shows_no_value() {
    let signers = AllowedSigners::parse(prod_signers().as_bytes()).expect("signers");
    let opened = open(&prod_bundle(), &identity(), &signers, &PROD).expect("open");
    assert!(!format!("{opened:?}").contains("marker"));
}

#[test]
fn the_wrong_principal_refusal_names_principal_and_namespace() {
    let (error, _) = refuse(&prod_bundle(), &signers_line("staging", &signer()), &PROD);
    let message = error.to_string();
    assert!(message.contains("`prod`") && message.contains("namespaces=\"opv-sealed\""));
}

// --- codec refusals (§10): each before any decryption ---

#[test]
fn a_bundle_without_a_signature_block_is_refused_before_decryption() {
    let bundle = prod_bundle();
    let needle = b"-----BEGIN SSH SIGNATURE-----";
    let at = bundle
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("block");
    assert_eq!(
        refuse(&bundle[..at], &prod_signers(), &PROD),
        (CryptoError::Malformed(FormatError::NoSignatureBlock), 0)
    );
}

#[test]
fn a_signer_not_listed_is_refused_before_decryption() {
    let id = identity();
    let key = other_signer();
    let bundle = seal(
        &header("prod", &id, &key),
        &ENTRIES,
        &[id.recipient()],
        &key,
    )
    .expect("ok");
    assert_eq!(
        refuse(&bundle, &prod_signers(), &PROD),
        (
            CryptoError::Signature(SignatureRefusal::NotListed {
                principal: "prod".to_string()
            }),
            0
        )
    );
}

#[test]
fn a_staging_signer_on_a_prod_header_is_refused_before_decryption() {
    let signers = format!(
        "{}{}",
        signers_line("prod", &other_signer()),
        signers_line("staging", &signer())
    );
    assert_eq!(
        refuse(&prod_bundle(), &signers, &PROD),
        (
            CryptoError::Signature(SignatureRefusal::OtherPrincipal {
                principal: "prod".to_string()
            }),
            0
        )
    );
}

#[test]
fn another_namespace_is_refused_before_decryption() {
    let id = identity();
    let key = signer();
    let line = canonical_header(&header("prod", &id, &key)).expect("header");
    let payload = hand_payload(&sha256(&line), &ENTRIES);
    let bundle = hand_bundle(&line, &payload, &id, "git", HashAlg::Sha512);
    assert_eq!(
        refuse(&bundle, &prod_signers(), &PROD),
        (CryptoError::Signature(SignatureRefusal::WrongNamespace), 0)
    );
}

#[test]
fn a_sha256_signature_is_refused_before_decryption() {
    let id = identity();
    let key = signer();
    let line = canonical_header(&header("prod", &id, &key)).expect("header");
    let payload = hand_payload(&sha256(&line), &ENTRIES);
    let bundle = hand_bundle(&line, &payload, &id, "opv-sealed", HashAlg::Sha256);
    assert_eq!(
        refuse(&bundle, &prod_signers(), &PROD),
        (CryptoError::Signature(SignatureRefusal::WrongHash), 0)
    );
}

#[test]
fn an_rsa_signers_line_is_refused_before_decryption() {
    let signers = format!(
        "{}prod namespaces=\"opv-sealed\" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7\n",
        prod_signers()
    );
    assert_eq!(
        refuse(&prod_bundle(), &signers, &PROD),
        (
            CryptoError::Signers(SignersError::KeyType {
                line: 2,
                key_type: "ssh-rsa".to_string()
            }),
            0
        )
    );
}

#[test]
fn a_cert_authority_signers_line_is_refused_before_decryption() {
    let key = signer().public_key().to_openssh().expect("openssh");
    let signers = format!("prod cert-authority,namespaces=\"opv-sealed\" {key}\n");
    assert_eq!(
        refuse(&prod_bundle(), &signers, &PROD),
        (
            CryptoError::Signers(SignersError::Option {
                line: 1,
                option: "cert-authority".to_string()
            }),
            0
        )
    );
}

#[test]
fn one_flipped_header_byte_is_refused_before_decryption() {
    let bundle = replace(&prod_bundle(), b"plan_test0001", b"plan_test0002");
    assert_eq!(
        refuse(&bundle, &prod_signers(), &PROD),
        (CryptoError::Signature(SignatureRefusal::Invalid), 0)
    );
}

#[test]
fn one_flipped_ciphertext_byte_is_refused_before_decryption() {
    let mut bundle = prod_bundle();
    let begin = b"-----BEGIN AGE ENCRYPTED FILE-----\n";
    let at = bundle
        .windows(begin.len())
        .position(|w| w == begin)
        .expect("age")
        + begin.len()
        + 70;
    bundle[at] = if bundle[at] == b'A' { b'B' } else { b'A' };
    assert_eq!(
        refuse(&bundle, &prod_signers(), &PROD),
        (CryptoError::Signature(SignatureRefusal::Invalid), 0)
    );
}

#[test]
fn a_v2_format_line_is_refused_before_decryption() {
    let bundle = replace(&prod_bundle(), b"opv-sealed v1\n", b"opv-sealed v2\n");
    assert_eq!(
        refuse(&bundle, &prod_signers(), &PROD),
        (CryptoError::Malformed(FormatError::UnknownFormatLine), 0)
    );
}

#[test]
fn an_unknown_header_field_is_refused_before_decryption() {
    let bundle = replace(
        &prod_bundle(),
        b"\"target\":\"box\"",
        b"\"target\":\"box\",\"zz\":1",
    );
    assert_eq!(
        refuse(&bundle, &prod_signers(), &PROD),
        (CryptoError::Malformed(FormatError::UnknownHeaderField), 0)
    );
}

#[test]
fn a_duplicate_header_key_is_refused_before_decryption() {
    let bundle = replace(
        &prod_bundle(),
        b"\"target\":\"box\"",
        b"\"target\":\"box\",\"target\":\"box\"",
    );
    assert_eq!(
        refuse(&bundle, &prod_signers(), &PROD),
        (CryptoError::Malformed(FormatError::DuplicateHeaderKey), 0)
    );
}

#[test]
fn a_cr_byte_is_refused_before_decryption() {
    let bundle = replace(&prod_bundle(), b"opv-sealed v1\n", b"opv-sealed v1\r\n");
    assert_eq!(
        refuse(&bundle, &prod_signers(), &PROD),
        (CryptoError::Malformed(FormatError::CarriageReturn), 0)
    );
}

#[test]
fn a_header_over_64_kib_is_refused_before_decryption() {
    let padding = format!("\"plan_id\":\"{}\"", "p".repeat(65 * 1024));
    let bundle = replace(
        &prod_bundle(),
        b"\"plan_id\":\"plan_test0001\"",
        padding.as_bytes(),
    );
    assert_eq!(
        refuse(&bundle, &prod_signers(), &PROD),
        (CryptoError::Malformed(FormatError::HeaderTooLarge), 0)
    );
}

#[test]
fn a_parent_directory_destination_is_refused_before_decryption() {
    let id = identity();
    let key = signer();
    let mut bad = header("prod", &id, &key);
    bad.names[1].destination = "file:../x".to_string();
    let line = canonical_header(&bad).expect("header");
    let payload = hand_payload(&sha256(&line), &ENTRIES);
    let bundle = hand_bundle(&line, &payload, &id, "opv-sealed", HashAlg::Sha512);
    assert!(matches!(
        refuse(&bundle, &prod_signers(), &PROD),
        (CryptoError::Malformed(FormatError::BadFilePath(_)), 0)
    ));
}

#[test]
fn a_header_naming_another_signer_is_refused_before_decryption() {
    let id = identity();
    let line = canonical_header(&header("prod", &id, &other_signer())).expect("header");
    let payload = hand_payload(&sha256(&line), &ENTRIES);
    let bundle = hand_bundle(&line, &payload, &id, "opv-sealed", HashAlg::Sha512);
    assert_eq!(
        refuse(&bundle, &prod_signers(), &PROD),
        (CryptoError::Signature(SignatureRefusal::SignerMismatch), 0)
    );
}

#[test]
fn a_wrong_environment_is_refused_before_decryption() {
    let id = identity();
    let key = signer();
    let bundle = seal(
        &header("staging", &id, &key),
        &ENTRIES,
        &[id.recipient()],
        &key,
    )
    .expect("seal");
    let (error, attempts) = refuse(&bundle, &signers_line("staging", &key), &PROD);
    assert_eq!((error.code(), attempts), ("sealed_scope_mismatch", 0));
}

#[test]
fn a_wrong_product_is_refused_before_decryption() {
    let expect = Expect {
        product: "worker",
        ..PROD
    };
    assert_eq!(
        refuse(&prod_bundle(), &prod_signers(), &expect),
        (
            CryptoError::ScopeMismatch {
                field: "product",
                expected: "worker".to_string(),
                found: "api".to_string()
            },
            0
        )
    );
}

#[test]
fn a_revision_below_the_floor_is_refused_before_decryption() {
    let expect = Expect {
        min_revision: Some(11),
        ..PROD
    };
    assert_eq!(
        refuse(&prod_bundle(), &prod_signers(), &expect),
        (
            CryptoError::RevisionBelowFloor {
                revision: 10,
                floor: 11
            },
            0
        )
    );
}

#[test]
fn an_unlisted_recipient_is_refused_before_decryption() {
    assert_eq!(
        refuse_with(&prod_bundle(), &prod_signers(), &PROD, stranger()),
        (CryptoError::NotARecipient, 0)
    );
}

// --- refusals after decryption, before delivery ---

#[test]
fn a_listed_recipient_without_a_matching_stanza_is_refused_by_age() {
    let id = identity();
    let key = signer();
    let line = canonical_header(&header("prod", &id, &key)).expect("header");
    let payload = hand_payload(&sha256(&line), &ENTRIES);
    let bundle = hand_bundle(&line, &payload, &stranger(), "opv-sealed", HashAlg::Sha512);
    assert_eq!(
        refuse(&bundle, &prod_signers(), &PROD),
        (CryptoError::NotARecipient, 1)
    );
}

#[test]
fn a_payload_digest_mismatch_is_refused_after_decryption() {
    let id = identity();
    let key = signer();
    let line = canonical_header(&header("prod", &id, &key)).expect("header");
    let payload = hand_payload(&[0u8; 32], &ENTRIES);
    let bundle = hand_bundle(&line, &payload, &id, "opv-sealed", HashAlg::Sha512);
    assert_eq!(
        refuse(&bundle, &prod_signers(), &PROD),
        (
            CryptoError::PayloadMismatch(FormatError::PayloadDigestMismatch),
            1
        )
    );
}

#[test]
fn an_op_name_in_the_payload_is_refused_after_decryption() {
    let id = identity();
    let key = signer();
    let mut op = header("prod", &id, &key);
    op.names[0] = Name {
        name: "OP_SERVICE_ACCOUNT_TOKEN".to_string(),
        destination: "env:SERVICE_ACCOUNT_TOKEN".to_string(),
    };
    let line = canonical_header(&op).expect("header");
    let entries: [(&str, &[u8]); 2] = [("OP_SERVICE_ACCOUNT_TOKEN", b"x"), ("TLS_KEY", b"y")];
    let payload = hand_payload(&sha256(&line), &entries);
    let bundle = hand_bundle(&line, &payload, &id, "opv-sealed", HashAlg::Sha512);
    assert_eq!(
        refuse(&bundle, &prod_signers(), &PROD),
        (CryptoError::PayloadMismatch(FormatError::OpName), 1)
    );
}

/// G4 by value (security review 0.18.0): the signing key is never sealed, whichever form the
/// value holds and however the configuration names the item it is read from.
#[test]
fn seal_refuses_a_value_that_is_its_own_signing_key() {
    let id = identity();
    let key = signer();
    for pem in [
        kat_str("signer_ed25519"),
        kat_str("signer_ed25519.pkcs8.pem"),
    ] {
        let entries: [(&str, &[u8]); 2] = [("API_TOKEN", b"marker"), ("TLS_KEY", pem.as_bytes())];
        let err = seal(
            &header("prod", &id, &key),
            &entries,
            &[id.recipient()],
            &key,
        )
        .err();
        assert_eq!(err, Some(CryptoError::SealsSigningKey("TLS_KEY".into())));
        assert!(!err.unwrap().to_string().contains("PRIVATE KEY"));
    }
}

/// Another ed25519 key is an ordinary value: only the bundle's own signer is refused.
#[test]
fn seal_keeps_a_value_that_is_another_signing_key() {
    let id = identity();
    let key = signer();
    let other = PrivateKey::from(Ed25519Keypair::from_seed(&[9; 32]))
        .to_openssh(LineEnding::LF)
        .expect("openssh");
    let entries: [(&str, &[u8]); 2] = [("API_TOKEN", b"marker"), ("TLS_KEY", other.as_bytes())];
    assert!(
        seal(
            &header("prod", &id, &key),
            &entries,
            &[id.recipient()],
            &key
        )
        .is_ok()
    );
}

/// Windows: age armors with CRLF there; the bundle's age block is LF-only everywhere.
#[test]
fn crlf_armor_is_normalised_to_lf() {
    assert_eq!(
        super::crypto::lf_only_for_tests(b"a\r\nb\r\n".to_vec()),
        b"a\nb\n".to_vec()
    );
}
