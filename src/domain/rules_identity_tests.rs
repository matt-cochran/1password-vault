//! Identity value rules (`age_identity`, `ssh_ed25519`): focused behaviour tests (#293,
//! #294). Valid fixtures are generated in-test, never committed as key text.

use super::*;
use crate::config::parse;
use crate::domain::model::{Fleet, Kind, Rules};
use secrecy::ExposeSecret;
use ssh_key::private::{Ed25519Keypair, KeypairData, OpaqueKeypair};
use ssh_key::public::OpaquePublicKey;
use ssh_key::{Algorithm, AlgorithmName, LineEnding, PrivateKey};

fn fleet() -> Fleet {
    parse(&crate::config::merged_text("tests/fixtures/secrets.toml")).unwrap()
}

/// The value checked as a key with `rules`; an `ssh_ed25519` key is a file key delivered as a
/// file, the only way 0.18.3 delivers a private SSH key.
fn with(rules: Rules, v: &str) -> Result<Option<String>, RuleFailure> {
    let f = fleet();
    let as_file = rules.ssh_ed25519;
    let spec = KeySpec {
        kind: Kind::Secret,
        environments: Some(vec!["prod".into(), "staging".into()]),
        except: Default::default(),
        rules,
        immutable: false,
        guidance: String::new(),
        from: None,
        personal: false,
        allow_same_value: false,
        file: as_file.then(|| "ssh-key".into()),
        roles: None,
        value_source: None,
        expires: None,
        lifecycle: Default::default(),
    };
    crate::domain::rules::check_verbatim(
        "allumata",
        "K",
        &spec,
        "prod",
        &f.environments["prod"],
        &SecretValue::new(v.into()),
        as_file,
    )
    .map(|o| o.map(|s| s.expose().to_string()))
}

fn age_rules() -> Rules {
    Rules {
        age_identity: true,
        ..Rules::default()
    }
}

fn ssh_rules() -> Rules {
    Rules {
        ssh_ed25519: true,
        ..Rules::default()
    }
}

fn age_fixture() -> String {
    let identity = age::x25519::Identity::generate();
    identity.to_string().expose_secret().to_owned()
}

fn ssh_fixture() -> String {
    PrivateKey::from(Ed25519Keypair::from_seed(&[7u8; 32]))
        .to_openssh(LineEnding::LF)
        .unwrap()
        .to_string()
}

fn non_ed25519_ssh_fixture() -> String {
    let algorithm = Algorithm::Other(AlgorithmName::new("ssh-not-ed25519@example.com").unwrap());
    let keypair = OpaqueKeypair::new(
        vec![1u8; 32],
        OpaquePublicKey::new(vec![2u8; 32], algorithm),
    );
    PrivateKey::new(KeypairData::Other(keypair), "")
        .unwrap()
        .to_openssh(LineEnding::LF)
        .unwrap()
        .to_string()
}

/// An encrypted Ed25519 key from ssh-key's own format example. It is not a real secret and
/// is never decrypted here; it exercises only the encrypted refusal.
const ENCRYPTED_SSH_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBKH96ujW
umB6/WnTNPjTeaAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN
796jTiQfZfG1KaT0PtFDJ/XFSqtiAAAAoFzvbvyFMhAiwBOXF0mhUUacPUCMZXivG2up2c
hEnAw1b6BLRPyWbY5cC2n9ggD4ivJ1zSts6sBgjyiXQAReyrP35myYvT/OIB/NpwZM/xIJ
N7MHSUzlkX4adBrga3f7GS4uv4ChOoxC4XsE5HsxtGsq1X8jzqLlZTmOcxkcEneYQexrUc
bQP0o+gL5aKK8cQgiIlXeDbRjqhc4+h4EF6lY=
-----END OPENSSH PRIVATE KEY-----
";

#[test]
fn a_valid_age_identity_passes_the_age_identity_rule() {
    assert!(with(age_rules(), &age_fixture()).unwrap().is_some());
}

#[test]
fn an_invalid_age_identity_fails_with_the_age_identity_rule() {
    assert_eq!(
        with(age_rules(), "not-an-age-identity").unwrap_err().rule,
        "age_identity"
    );
}

#[test]
fn an_invalid_age_identity_failure_reason_is_fixed() {
    assert!(matches!(
        with(age_rules(), "not-an-age-identity").unwrap_err().reason,
        Reason::Fixed(_)
    ));
}

#[test]
fn an_invalid_age_identity_failure_never_quotes_the_value() {
    let value = "ZQXMARKERZQX-not-an-age-identity";
    let failure = with(age_rules(), value).unwrap_err();
    assert!(!format!("{failure} {failure:?} {failure:#?}").contains("ZQXMARKERZQX"));
}

#[test]
fn a_valid_ssh_ed25519_value_with_its_trailing_newline_is_staged_byte_exact() {
    let value = ssh_fixture();
    assert_eq!(with(ssh_rules(), &value).unwrap().unwrap(), value);
}

#[test]
fn a_malformed_ssh_ed25519_value_fails_with_the_ssh_ed25519_rule() {
    assert_eq!(
        with(ssh_rules(), "not an OpenSSH key").unwrap_err().rule,
        "ssh_ed25519"
    );
}

#[test]
fn an_encrypted_ssh_ed25519_value_fails_with_the_ssh_ed25519_rule() {
    assert_eq!(
        with(ssh_rules(), ENCRYPTED_SSH_KEY).unwrap_err().rule,
        "ssh_ed25519"
    );
}

#[test]
fn a_non_ed25519_ssh_value_fails_with_the_ssh_ed25519_rule() {
    assert_eq!(
        with(ssh_rules(), &non_ed25519_ssh_fixture())
            .unwrap_err()
            .rule,
        "ssh_ed25519"
    );
}

#[test]
fn a_malformed_ssh_ed25519_failure_reason_is_fixed() {
    assert!(matches!(
        with(ssh_rules(), "not an OpenSSH key").unwrap_err().reason,
        Reason::Fixed(_)
    ));
}
