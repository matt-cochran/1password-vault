//! The runtime's trusted signers: a strict subset of OpenSSH `allowed_signers` (design
//! sealed-target §4.2, §5.8.4 G5; FMECA T1, T13).
//!
//! The only accepted line is
//! `<principal>[,<principal>…] namespaces="opv-sealed" ssh-ed25519 <base64> [comment]`.
//! `#` comments and blank lines are skipped; fields are separated by spaces or tabs, as
//! `ssh-keygen` reads them. Everything else is refused by name with its line number:
//! any option but `namespaces` (`cert-authority`, `valid-before`, `valid-after`, unknown
//! ones), a missing `namespaces=`, a namespace other than `opv-sealed`, a key type other
//! than `ssh-ed25519`, principal patterns (`*`, `?`, `!`) and quoted principals, and a CR
//! byte anywhere. The whole file is refused when one line is, so a half-read trust file
//! never counts.
//!
//! A line vouches for a key only for the principals it lists: [`AllowedSigners::lookup`]
//! matches a principal by exact equality, which is `ssh-keygen -Y verify -I <env>`
//! semantics on these lines (the tests replay `ssh-keygen`'s recorded answers).

use ssh_key::{Algorithm, PublicKey, public::KeyData};

use super::format::NAMESPACE;

/// The one key type a signer line may carry.
pub const KEY_TYPE: &str = "ssh-ed25519";

/// One accepted signer line: the principals it vouches for and its ed25519 key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerLine {
    /// The 1-based line number in the file, for messages.
    pub line: usize,
    /// The principals (environment names) this key may sign for.
    pub principals: Vec<String>,
    /// The public key. Public keys are not secrets.
    pub key: PublicKey,
}

/// A parsed `allowed_signers` file of the strict subset.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AllowedSigners {
    lines: Vec<SignerLine>,
}

/// The answer to "may this key sign for this principal?".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup {
    /// A line lists the principal and the key.
    Trusted,
    /// The key is listed, but only for other principals (T1: a staging signer on prod).
    OtherPrincipal,
    /// No line holds the key.
    NotListed,
}

/// Why a signers file was refused. Names a field or option, never key material.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignersError {
    #[error(
        "the allowed_signers file contains a CR byte (line {line}); save it with LF line endings"
    )]
    CarriageReturn { line: usize },
    #[error("the allowed_signers file is not UTF-8 (line {line})")]
    NotUtf8 { line: usize },
    #[error(
        "allowed_signers line {line} is incomplete: expected `<principals> namespaces=\"opv-sealed\" ssh-ed25519 <key>`"
    )]
    Incomplete { line: usize },
    #[error("allowed_signers line {line} has no namespaces=\"opv-sealed\" option")]
    MissingNamespaces { line: usize },
    #[error("allowed_signers line {line} names namespaces other than exactly \"opv-sealed\"")]
    WrongNamespace { line: usize },
    #[error("allowed_signers line {line} repeats the namespaces option")]
    DuplicateNamespaces { line: usize },
    #[error("allowed_signers line {line} has option `{option}`, which opv does not accept")]
    Option { line: usize, option: String },
    #[error("allowed_signers line {line} has key type `{key_type}`; only ssh-ed25519 is accepted")]
    KeyType { line: usize, key_type: String },
    #[error("allowed_signers line {line} has a key opv cannot read")]
    BadKey { line: usize },
    #[error("allowed_signers line {line} has an empty principal")]
    EmptyPrincipal { line: usize },
    #[error("allowed_signers line {line} has a principal pattern; list each environment by name")]
    PrincipalPattern { line: usize },
    #[error("allowed_signers line {line} quotes its principals; list them without quotes")]
    QuotedPrincipals { line: usize },
}

impl AllowedSigners {
    /// Parse a whole file of the strict subset. Any refused line refuses the file.
    pub fn parse(text: &[u8]) -> Result<Self, SignersError> {
        let mut lines = Vec::new();
        for (index, raw) in text.split(|&b| b == b'\n').enumerate() {
            let line = index + 1;
            if raw.contains(&b'\r') {
                return Err(SignersError::CarriageReturn { line });
            }
            let raw = std::str::from_utf8(raw).map_err(|_| SignersError::NotUtf8 { line })?;
            if let Some(signer) = parse_line(line, raw)? {
                lines.push(signer);
            }
        }
        Ok(Self { lines })
    }

    /// The accepted lines, in file order.
    pub fn lines(&self) -> &[SignerLine] {
        &self.lines
    }

    /// Whether `key` may sign for `principal`: some line must list both, the principal by
    /// exact equality.
    pub fn lookup(&self, principal: &str, key: &KeyData) -> Lookup {
        let mut listed = false;
        for line in self.lines.iter().filter(|l| l.key.key_data() == key) {
            if line.principals.iter().any(|p| p == principal) {
                return Lookup::Trusted;
            }
            listed = true;
        }
        if listed {
            Lookup::OtherPrincipal
        } else {
            Lookup::NotListed
        }
    }
}

fn is_separator(c: char) -> bool {
    c == ' ' || c == '\t'
}

/// Split off the next whitespace-separated field.
fn next_field(rest: &str) -> Option<(&str, &str)> {
    let rest = rest.trim_start_matches(is_separator);
    if rest.is_empty() {
        return None;
    }
    let end = rest.find(is_separator).unwrap_or(rest.len());
    Some((&rest[..end], &rest[end..]))
}

fn parse_line(line: usize, raw: &str) -> Result<Option<SignerLine>, SignersError> {
    let body = raw.trim_start_matches(is_separator);
    if body.is_empty() || body.starts_with('#') {
        return Ok(None);
    }
    let (principals, rest) = next_field(body).ok_or(SignersError::Incomplete { line })?;
    let principals = parse_principals(line, principals)?;
    let (options, rest) = next_field(rest).ok_or(SignersError::Incomplete { line })?;
    if looks_like_key_type(options) {
        return Err(SignersError::MissingNamespaces { line });
    }
    parse_options(line, options)?;
    let (key_type, rest) = next_field(rest).ok_or(SignersError::Incomplete { line })?;
    if key_type != KEY_TYPE {
        return Err(SignersError::KeyType {
            line,
            key_type: key_type.to_string(),
        });
    }
    let (blob, _comment) = next_field(rest).ok_or(SignersError::Incomplete { line })?;
    let key = PublicKey::from_openssh(&format!("{KEY_TYPE} {blob}"))
        .map_err(|_| SignersError::BadKey { line })?;
    if key.algorithm() != Algorithm::Ed25519 {
        return Err(SignersError::BadKey { line });
    }
    Ok(Some(SignerLine {
        line,
        principals,
        key,
    }))
}

/// A comma-separated list of exact principals (G5): no patterns, no quotes, no empty item.
fn parse_principals(line: usize, field: &str) -> Result<Vec<String>, SignersError> {
    if field.contains('"') {
        return Err(SignersError::QuotedPrincipals { line });
    }
    let mut principals = Vec::new();
    for principal in field.split(',') {
        if principal.is_empty() {
            return Err(SignersError::EmptyPrincipal { line });
        }
        if principal.contains(['*', '?', '!']) {
            return Err(SignersError::PrincipalPattern { line });
        }
        principals.push(principal.to_string());
    }
    Ok(principals)
}

/// The options field must hold exactly `namespaces="opv-sealed"` (name case-insensitive, as
/// `ssh-keygen` reads it). Every other option is refused by its name.
fn parse_options(line: usize, field: &str) -> Result<(), SignersError> {
    let mut namespaces = false;
    for option in split_options(field) {
        let (name, value) = match option.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (option, None),
        };
        if !name.eq_ignore_ascii_case("namespaces") {
            return Err(SignersError::Option {
                line,
                option: name.to_ascii_lowercase(),
            });
        }
        if namespaces {
            return Err(SignersError::DuplicateNamespaces { line });
        }
        let expected = format!("\"{NAMESPACE}\"");
        if value != Some(expected.as_str()) {
            return Err(SignersError::WrongNamespace { line });
        }
        namespaces = true;
    }
    if namespaces {
        Ok(())
    } else {
        Err(SignersError::MissingNamespaces { line })
    }
}

/// Split an options field on commas outside double quotes.
fn split_options(field: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut quoted = false;
    let mut start = 0;
    for (i, c) in field.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ',' if !quoted => {
                out.push(&field[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&field[start..]);
    out
}

/// A field that is a key type rather than options: the line skipped `namespaces=`.
fn looks_like_key_type(field: &str) -> bool {
    field.starts_with("ssh-")
        || field.starts_with("ecdsa-")
        || field.starts_with("sk-")
        || field.starts_with("rsa-")
}
