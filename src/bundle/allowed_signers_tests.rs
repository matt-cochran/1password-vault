//! Behavioural tests for the strict `allowed_signers` subset (design sealed-target §4.2,
//! §5.8.4 G5, §10 item 7; FMECA T1, T13). Each test asserts one outcome. The agreement
//! table replays `ssh-keygen -Y verify -f <file> -I <principal> -n opv-sealed` (OpenSSH
//! 9.6p1) on the KAT signature, recorded 2026-11-04.

use ssh_key::private::Ed25519Keypair;
use ssh_key::{PrivateKey, PublicKey};

use super::allowed_signers::{AllowedSigners, Lookup, SignersError};

const KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINirgorYlQN+Od5eAtpJBIy1wIOCvlfQf17IXdMtzyP5";

fn key() -> PublicKey {
    PublicKey::from_openssh(KEY).expect("fixture key")
}

fn parse(text: &str) -> Result<AllowedSigners, SignersError> {
    AllowedSigners::parse(text.as_bytes())
}

fn lookup(text: &str, principal: &str) -> Lookup {
    parse(text)
        .expect("accepted")
        .lookup(principal, key().key_data())
}

fn refusal(text: &str) -> SignersError {
    parse(text).expect_err("refused")
}

// --- §10 item 7: agreement with ssh-keygen on every accepted line ---

/// `(file, principal, ssh-keygen accepted)`, as recorded with OpenSSH 9.6p1.
fn ssh_keygen_table() -> Vec<(String, &'static str, bool)> {
    let single = format!("prod namespaces=\"opv-sealed\" {KEY} c\n");
    let list = format!("staging,prod namespaces=\"opv-sealed\" {KEY}\n");
    let staging = format!("staging namespaces=\"opv-sealed\" {KEY}\n");
    let spaced = format!("# c\n\n  \tprod\tnamespaces=\"opv-sealed\"   {KEY}  c c\n");
    let upper = format!("prod NAMESPACES=\"opv-sealed\" {KEY}\n");
    let no_newline = format!("prod namespaces=\"opv-sealed\" {KEY}");
    let mut table = Vec::new();
    for (file, answers) in [
        (single, [true, false, false]),
        (list, [true, true, false]),
        (staging, [false, true, false]),
        (spaced, [true, false, false]),
        (upper, [true, false, false]),
        (no_newline, [true, false, false]),
    ] {
        for (principal, accepted) in ["prod", "staging", "stag"].into_iter().zip(answers) {
            table.push((file.clone(), principal, accepted));
        }
    }
    table
}

#[test]
fn accepted_lines_agree_with_ssh_keygen_verify() {
    let disagreements: Vec<(String, &str)> = ssh_keygen_table()
        .into_iter()
        .filter(|(file, principal, accepted)| {
            (lookup(file, principal) == Lookup::Trusted) != *accepted
        })
        .map(|(file, principal, _)| (file, principal))
        .collect();
    assert_eq!(disagreements, Vec::<(String, &str)>::new());
}

#[test]
fn the_kat_fixture_file_trusts_its_key_for_prod() {
    let text = std::fs::read(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/sealed/kat/allowed_signers"),
    )
    .expect("fixture");
    let signers = AllowedSigners::parse(&text).expect("accepted");
    assert_eq!(signers.lookup("prod", key().key_data()), Lookup::Trusted);
}

#[test]
fn a_principal_list_trusts_each_listed_environment() {
    let text = format!("staging-a,staging-b namespaces=\"opv-sealed\" {KEY}\n");
    assert_eq!(lookup(&text, "staging-b"), Lookup::Trusted);
}

#[test]
fn a_key_listed_only_for_staging_is_another_principal_on_prod() {
    let text = format!("staging namespaces=\"opv-sealed\" {KEY}\n");
    assert_eq!(lookup(&text, "prod"), Lookup::OtherPrincipal);
}

#[test]
fn a_principal_matches_only_by_exact_equality() {
    let text = format!("production namespaces=\"opv-sealed\" {KEY}\n");
    assert_eq!(lookup(&text, "prod"), Lookup::OtherPrincipal);
}

#[test]
fn an_unknown_key_is_not_listed() {
    let other = PrivateKey::from(Ed25519Keypair::from_seed(&[7; 32]))
        .public_key()
        .to_openssh()
        .expect("openssh");
    let text = format!("prod namespaces=\"opv-sealed\" {other}\n");
    assert_eq!(lookup(&text, "prod"), Lookup::NotListed);
}

#[test]
fn comments_and_blank_lines_are_skipped() {
    let signers = parse("# only a comment\n\n   \n").expect("accepted");
    assert!(signers.lines().is_empty());
}

// --- §4.2 / T13: every other form is refused by name, with its line number ---

#[test]
fn a_line_without_namespaces_is_refused() {
    let text = format!("prod {KEY}\n");
    assert_eq!(refusal(&text), SignersError::MissingNamespaces { line: 1 });
}

#[test]
fn a_cert_authority_option_is_refused_by_name() {
    let text = format!("prod cert-authority,namespaces=\"opv-sealed\" {KEY}\n");
    assert_eq!(
        refusal(&text),
        SignersError::Option {
            line: 1,
            option: "cert-authority".to_string()
        }
    );
}

#[test]
fn a_valid_before_option_is_refused_by_name() {
    let text = format!("prod namespaces=\"opv-sealed\",valid-before=\"20300101\" {KEY}\n");
    assert_eq!(
        refusal(&text),
        SignersError::Option {
            line: 1,
            option: "valid-before".to_string()
        }
    );
}

#[test]
fn a_valid_after_option_is_refused_by_name() {
    let text = format!("prod valid-after=\"20200101\",namespaces=\"opv-sealed\" {KEY}\n");
    assert_eq!(
        refusal(&text),
        SignersError::Option {
            line: 1,
            option: "valid-after".to_string()
        }
    );
}

#[test]
fn an_unknown_option_is_refused_by_name() {
    let text = format!("prod namespaces=\"opv-sealed\",no-touch-required {KEY}\n");
    assert_eq!(
        refusal(&text),
        SignersError::Option {
            line: 1,
            option: "no-touch-required".to_string()
        }
    );
}

#[test]
fn a_git_namespace_is_refused() {
    let text = format!("prod namespaces=\"git\" {KEY}\n");
    assert_eq!(refusal(&text), SignersError::WrongNamespace { line: 1 });
}

#[test]
fn a_namespace_list_is_refused() {
    let text = format!("prod namespaces=\"git,opv-sealed\" {KEY}\n");
    assert_eq!(refusal(&text), SignersError::WrongNamespace { line: 1 });
}

#[test]
fn a_repeated_namespaces_option_is_refused() {
    let text = format!("prod namespaces=\"opv-sealed\",namespaces=\"opv-sealed\" {KEY}\n");
    assert_eq!(
        refusal(&text),
        SignersError::DuplicateNamespaces { line: 1 }
    );
}

#[test]
fn an_rsa_line_is_refused_by_key_type() {
    let text = "prod namespaces=\"opv-sealed\" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7\n";
    assert_eq!(
        refusal(text),
        SignersError::KeyType {
            line: 1,
            key_type: "ssh-rsa".to_string()
        }
    );
}

#[test]
fn an_ecdsa_line_is_refused_by_key_type() {
    let text = "prod namespaces=\"opv-sealed\" ecdsa-sha2-nistp256 AAAAE2VjZHNh\n";
    assert_eq!(
        refusal(text),
        SignersError::KeyType {
            line: 1,
            key_type: "ecdsa-sha2-nistp256".to_string()
        }
    );
}

#[test]
fn a_key_blob_of_another_type_is_refused() {
    let text = "prod namespaces=\"opv-sealed\" ssh-ed25519 AAAAB3NzaC1yc2EAAAADAQABAAABAQC7\n";
    assert_eq!(refusal(text), SignersError::BadKey { line: 1 });
}

#[test]
fn a_star_pattern_principal_is_refused() {
    let text = format!("staging-* namespaces=\"opv-sealed\" {KEY}\n");
    assert_eq!(refusal(&text), SignersError::PrincipalPattern { line: 1 });
}

#[test]
fn a_negated_principal_is_refused() {
    let text = format!("!prod,staging namespaces=\"opv-sealed\" {KEY}\n");
    assert_eq!(refusal(&text), SignersError::PrincipalPattern { line: 1 });
}

#[test]
fn an_empty_principal_in_a_list_is_refused() {
    let text = format!("staging,,prod namespaces=\"opv-sealed\" {KEY}\n");
    assert_eq!(refusal(&text), SignersError::EmptyPrincipal { line: 1 });
}

#[test]
fn quoted_principals_are_refused() {
    let text = format!("\"prod\" namespaces=\"opv-sealed\" {KEY}\n");
    assert_eq!(refusal(&text), SignersError::QuotedPrincipals { line: 1 });
}

#[test]
fn a_line_without_a_key_is_incomplete() {
    assert_eq!(
        refusal("prod namespaces=\"opv-sealed\" ssh-ed25519\n"),
        SignersError::Incomplete { line: 1 }
    );
}

#[test]
fn a_crlf_line_is_refused_with_its_line_number() {
    let text = format!("# trusted\nprod namespaces=\"opv-sealed\" {KEY}\r\n");
    assert_eq!(refusal(&text), SignersError::CarriageReturn { line: 2 });
}

#[test]
fn one_bad_line_refuses_the_whole_file() {
    let text = format!(
        "prod namespaces=\"opv-sealed\" {KEY}\nstaging cert-authority,namespaces=\"opv-sealed\" {KEY}\n"
    );
    assert!(parse(&text).is_err());
}

#[test]
fn a_refusal_names_the_line() {
    let text = format!("\n\nprod {KEY}\n");
    assert!(refusal(&text).to_string().contains("line 3"));
}
