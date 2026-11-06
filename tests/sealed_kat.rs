//! Known-answer tests for the sealed target's crypto dependencies (design sealed-target §6,
//! lane S0, #271). They prove the API fit of `age` and `ssh-key` against fixtures made by the
//! stock tools (`age` 1.1.1, `ssh-keygen` from OpenSSH 9.6) in `tests/fixtures/sealed/kat/`.
//! Every key there is an obviously fake test fixture.

use std::io::{BufReader, Read, Write};
use std::iter;
use std::path::PathBuf;
use std::str::FromStr;

use age::armor::{ArmoredReader, ArmoredWriter, Format};
use age::x25519;
use base64::Engine;
use ssh_key::private::Ed25519Keypair;
use ssh_key::{HashAlg, LineEnding, PrivateKey, PublicKey, SshSig};

const NAMESPACE: &str = "opv-sealed";

fn kat(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sealed/kat")
        .join(name)
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(kat(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn read_str(name: &str) -> String {
    String::from_utf8(read(name)).unwrap()
}

/// The one x25519 identity line of the fixture file (`#` lines are comments).
fn identity() -> x25519::Identity {
    let text = read_str("age-identity.txt");
    let line = text
        .lines()
        .find(|l| l.starts_with("AGE-SECRET-KEY-1"))
        .expect("identity line");
    x25519::Identity::from_str(line).expect("x25519 identity")
}

fn recipient() -> x25519::Recipient {
    x25519::Recipient::from_str(read_str("age-recipient.txt").trim()).expect("x25519 recipient")
}

fn decrypt(ciphertext: &[u8], id: &x25519::Identity) -> Result<Vec<u8>, age::DecryptError> {
    let decryptor = age::Decryptor::new(ArmoredReader::new(BufReader::new(ciphertext)))?;
    assert!(
        !decryptor.is_scrypt(),
        "a passphrase stanza is never accepted"
    );
    let mut reader = decryptor.decrypt(iter::once(id as &dyn age::Identity))?;
    let mut out = Vec::new();
    reader.read_to_end(&mut out).expect("read plaintext");
    Ok(out)
}

#[test]
fn age_identity_matches_recipient() {
    assert_eq!(identity().to_public().to_string(), recipient().to_string());
}

#[test]
fn age_decrypts_the_stock_cli_ciphertext() {
    let plain = decrypt(&read("ciphertext.age"), &identity()).expect("decrypt");
    assert_eq!(plain, read("plaintext.txt"));
}

#[test]
fn age_round_trips_armored_to_one_x25519_recipient() {
    let r = recipient();
    let encryptor =
        age::Encryptor::with_recipients(iter::once(&r as &dyn age::Recipient)).expect("encryptor");
    let mut armored = Vec::new();
    let armor = ArmoredWriter::wrap_output(&mut armored, Format::AsciiArmor).expect("armor");
    let mut w = encryptor.wrap_output(armor).expect("stream");
    w.write_all(b"round trip").unwrap();
    w.finish().unwrap().finish().unwrap();
    // The crate armors with CRLF on Windows; opv's `bundle::crypto::encrypt` normalises
    // that to LF (tested there). This test only proves the API fit.
    let text = String::from_utf8(armored.clone())
        .unwrap()
        .replace("\r\n", "\n");
    assert!(text.starts_with("-----BEGIN AGE ENCRYPTED FILE-----\n"));
    assert_eq!(decrypt(&armored, &identity()).unwrap(), b"round trip");
}

#[test]
fn age_refuses_a_different_identity() {
    let other = x25519::Identity::generate();
    assert!(decrypt(&read("ciphertext.age"), &other).is_err());
}

#[test]
fn sshsig_from_ssh_keygen_verifies_with_namespace() {
    let public = PublicKey::from_openssh(&read_str("signer_ed25519.pub")).expect("public key");
    let sig = SshSig::from_pem(read("message.txt.sig")).expect("sshsig");
    assert_eq!(sig.namespace(), NAMESPACE);
    assert_eq!(sig.hash_alg(), HashAlg::Sha512);
    let msg = read("message.txt");
    public.verify(NAMESPACE, &msg, &sig).expect("verify");
    assert!(public.verify("git", &msg, &sig).is_err(), "wrong namespace");
    assert!(
        public.verify(NAMESPACE, b"tampered", &sig).is_err(),
        "wrong message"
    );
}

#[test]
fn sshsig_sign_in_process_matches_ssh_keygen() {
    let private = PrivateKey::from_openssh(read("signer_ed25519")).expect("openssh private key");
    assert!(!private.is_encrypted());
    let msg = read("message.txt");
    let sig = private
        .sign(NAMESPACE, HashAlg::Sha512, &msg)
        .expect("sign");
    // Ed25519 is deterministic, so the in-process SSHSIG is byte-identical to ssh-keygen's.
    let pem = sig.to_pem(LineEnding::LF).expect("pem");
    assert_eq!(pem, read_str("message.txt.sig"));
    private
        .public_key()
        .verify(NAMESPACE, &msg, &sig)
        .expect("verify");
}

/// T16 fallback: if `op` hands over the PKCS#8 form (`BEGIN PRIVATE KEY`), its 48-byte DER is
/// a fixed 16-byte prefix plus the 32-byte seed (RFC 8410), which yields the same key.
#[test]
fn pkcs8_ed25519_form_yields_the_same_key() {
    const PREFIX: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    let pem = read_str("signer_ed25519.pkcs8.pem");
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .expect("base64");
    assert_eq!(der.len(), 48);
    assert_eq!(der[..16], PREFIX);
    let seed: [u8; 32] = der[16..].try_into().unwrap();
    let from_pkcs8 = PrivateKey::from(Ed25519Keypair::from_seed(&seed));
    let from_openssh = PrivateKey::from_openssh(read("signer_ed25519")).unwrap();
    assert_eq!(
        from_pkcs8.public_key().key_data(),
        from_openssh.public_key().key_data()
    );
}

/// The strict `allowed_signers` subset of design §4.2: `<principals> namespaces="opv-sealed"
/// ssh-ed25519 <base64> [comment]`, with principal = environment. `ssh-keygen -Y verify -I prod
/// -n opv-sealed` accepts this fixture (README), and its key verifies the fixture signature.
#[test]
fn allowed_signers_fixture_is_the_strict_subset() {
    let text = read_str("allowed_signers");
    assert!(!text.contains('\r'));
    let line = text.lines().next().unwrap();
    let mut fields = line.split(' ');
    assert_eq!(fields.next(), Some("prod"));
    assert_eq!(fields.next(), Some("namespaces=\"opv-sealed\""));
    let key = format!("{} {}", fields.next().unwrap(), fields.next().unwrap());
    let public = PublicKey::from_openssh(&key).expect("signer key");
    let sig = SshSig::from_pem(read("message.txt.sig")).unwrap();
    public
        .verify(NAMESPACE, &read("message.txt"), &sig)
        .expect("verify");
}
