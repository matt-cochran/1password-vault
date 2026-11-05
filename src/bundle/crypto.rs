//! The sealed bundle's cryptography (design sealed-target §6, lane B2): age to X25519
//! recipients, SSHSIG ed25519 in namespace `opv-sealed` with sha512, and [`open`], which
//! verifies before it decrypts.
//!
//! Verification order (§9.2): size bounds, LF-only and the format line, the block split and
//! the canonical header ([`parse_envelope`]); then the SSHSIG over every byte above the
//! signature block, from a signer listed for the header's environment; then scope and
//! revision; then the identity's membership in the header's recipients; only then age
//! decryption; then the payload binding. Nothing is decrypted before the signature verified.
//!
//! Keys and values never reach `Debug`, `Display` or an error: [`Identity`] and
//! [`SigningKey`] have no `Debug`, [`OpenedBundle`]'s `Debug` prints names only, and every
//! refusal names a field. Values and decoded key bytes live in [`Zeroizing`] buffers;
//! age's `x25519::Identity` and `ssh_key::PrivateKey` zeroize on drop.

use std::io::{BufReader, Read, Write};
use std::iter;
use std::str::FromStr;

use age::armor::{ArmoredReader, ArmoredWriter, Format};
use age::x25519;
use base64::Engine;
use sha2::{Digest, Sha256};
use ssh_key::private::Ed25519Keypair;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey, PublicKey, SshSig};
use zeroize::Zeroizing;

use super::allowed_signers::{AllowedSigners, Lookup, SignersError};
use super::format::{
    self, FORMAT_LINE, FormatError, Header, NAMESPACE, Payload, decode_payload, parse_envelope,
};

/// The RFC 8410 DER prefix of an unencrypted ed25519 PKCS#8 key; the 32-byte seed follows.
const PKCS8_ED25519_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
const PKCS8_BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
const PKCS8_END: &str = "-----END PRIVATE KEY-----";
const OPENSSH_BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const IDENTITY_PREFIX: &str = "AGE-SECRET-KEY-1";

/// Why the crypto layer refused. Each variant maps to one `error.code` of design §4.2
/// ([`CryptoError::code`]); none carries a key, a value or a recipient string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// The bundle's bytes break the codec (`sealed_malformed`).
    #[error("{0}")]
    Malformed(FormatError),
    /// The signature did not verify for the header's environment (`sealed_signature_invalid`).
    #[error("{0}")]
    Signature(SignatureRefusal),
    /// The `allowed_signers` file was refused (`sealed_signature_invalid`).
    #[error("{0}")]
    Signers(SignersError),
    /// The header's environment or product differs from the expected one
    /// (`sealed_scope_mismatch`).
    #[error("the bundle's {field} is `{found}`, expected `{expected}`")]
    ScopeMismatch {
        field: &'static str,
        expected: String,
        found: String,
    },
    /// The header's revision is below the deploy's floor (`sealed_revision_below_floor`).
    #[error("the bundle's revision {revision} is below the floor {floor}")]
    RevisionBelowFloor { revision: u64, floor: u64 },
    /// The identity is not one `AGE-SECRET-KEY-1…` line (`sealed_identity_unusable`).
    #[error("the age identity is unusable: {0}")]
    IdentityUnusable(&'static str),
    /// The identity's recipient is not in the header, or no age stanza matched it
    /// (`sealed_not_a_recipient`).
    #[error("the age identity is not a recipient of this bundle")]
    NotARecipient,
    /// The age block, though signed, is not a readable age file (`sealed_malformed`).
    #[error("the age block is not a readable age file")]
    AgeMalformed,
    /// The decrypted payload does not bind to the verified header (`sealed_payload_mismatch`).
    #[error("{0}")]
    PayloadMismatch(FormatError),
    /// A recipient string is not an X25519 age recipient; names its kind only.
    #[error("the age recipient is not accepted: {0}")]
    RecipientUnsupported(&'static str),
    /// The signing key is not an unencrypted ed25519 key in OpenSSH or PKCS#8 form.
    #[error("the signing key is not accepted: {0}")]
    SigningKeyInvalid(&'static str),
    /// Sealing inputs disagree with the header they are sealed under.
    #[error("the sealed {0} differ from the header")]
    SealMismatch(&'static str),
    /// A value of the batch is the bundle's own signing key (G4): a sealed target never
    /// seals it, however its configuration names the key. Names the key, never the value.
    #[error("the value of {0} is the bundle's own signing key")]
    SealsSigningKey(String),
    /// age or ssh-key failed while producing output.
    #[error("the {0} step failed")]
    Internal(&'static str),
}

impl CryptoError {
    /// The design's `error.code` for this refusal (§4.2).
    pub fn code(&self) -> &'static str {
        match self {
            Self::Malformed(_) | Self::AgeMalformed => "sealed_malformed",
            Self::Signature(_) | Self::Signers(_) => "sealed_signature_invalid",
            Self::ScopeMismatch { .. } => "sealed_scope_mismatch",
            Self::RevisionBelowFloor { .. } => "sealed_revision_below_floor",
            Self::IdentityUnusable(_) => "sealed_identity_unusable",
            Self::NotARecipient => "sealed_not_a_recipient",
            Self::PayloadMismatch(_) => "sealed_payload_mismatch",
            Self::RecipientUnsupported(_)
            | Self::SigningKeyInvalid(_)
            | Self::SealsSigningKey(_) => "input_invalid",
            Self::SealMismatch(_) | Self::Internal(_) => "bug",
        }
    }
}

/// Why a signature was refused. The messages name the expected principal and namespace so
/// the fix is obvious (T1b).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignatureRefusal {
    #[error("the signature block is not a readable SSHSIG")]
    Unreadable,
    #[error("the signature's namespace is not \"opv-sealed\"")]
    WrongNamespace,
    #[error("the signature's hash is not sha512")]
    WrongHash,
    #[error("the signature's key is not ssh-ed25519")]
    WrongAlgorithm,
    #[error(
        "no allowed_signers line for principal `{principal}` with namespaces=\"opv-sealed\" holds the signing key"
    )]
    NotListed { principal: String },
    #[error(
        "the signing key is listed only for other principals; add `{principal}` to its allowed_signers line (namespaces=\"opv-sealed\")"
    )]
    OtherPrincipal { principal: String },
    #[error("the signature does not verify over the bundle")]
    Invalid,
    #[error("the header's signer differs from the key that signed it")]
    SignerMismatch,
}

// ---------------------------------------------------------------------------------------
// age: X25519 recipients and identities
// ---------------------------------------------------------------------------------------

/// An X25519 age identity. No `Debug`, no `Display`; the secret zeroizes on drop.
pub struct Identity(x25519::Identity);

impl Identity {
    /// The identity's public recipient.
    pub fn recipient(&self) -> x25519::Recipient {
        self.0.to_public()
    }
}

/// Parse an identity file's text: `#` comments and blank lines, and exactly one
/// `AGE-SECRET-KEY-1…` line. Plugin, passphrase and second identities are refused.
pub fn parse_identity(text: &str) -> Result<Identity, CryptoError> {
    let mut found: Option<x25519::Identity> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.starts_with(IDENTITY_PREFIX) {
            return Err(CryptoError::IdentityUnusable(
                "the line is not AGE-SECRET-KEY-1…",
            ));
        }
        if found.is_some() {
            return Err(CryptoError::IdentityUnusable("more than one identity"));
        }
        let identity = x25519::Identity::from_str(line)
            .map_err(|_| CryptoError::IdentityUnusable("the key does not decode"))?;
        found = Some(identity);
    }
    found
        .map(Identity)
        .ok_or(CryptoError::IdentityUnusable("no AGE-SECRET-KEY-1… line"))
}

/// Parse one recipient string. Only X25519 (`age1…`) is accepted; SSH, plugin and hybrid
/// post-quantum recipients are refused by kind (§6.1).
pub fn parse_recipient(text: &str) -> Result<x25519::Recipient, CryptoError> {
    if text.starts_with("ssh-") || text.starts_with("ecdsa-") || text.starts_with("sk-") {
        return Err(CryptoError::RecipientUnsupported("an SSH recipient"));
    }
    if let Some(rest) = text.strip_prefix("age1") {
        // Bech32 data never contains `1`, so a second separator marks a typed HRP.
        if rest.starts_with("pq1") {
            return Err(CryptoError::RecipientUnsupported(
                "a hybrid post-quantum recipient",
            ));
        }
        if rest.contains('1') {
            return Err(CryptoError::RecipientUnsupported("a plugin recipient"));
        }
    }
    x25519::Recipient::from_str(text)
        .map_err(|_| CryptoError::RecipientUnsupported("not an age1… X25519 recipient"))
}

/// The header's recipient fingerprint: `sha256:` and the first 16 hex digits of the sha256
/// of the recipient string (§5.2).
pub fn recipient_fingerprint(recipient: &x25519::Recipient) -> String {
    let digest = Sha256::digest(recipient.to_string().as_bytes());
    format!("sha256:{}", &hex::encode(digest)[..16])
}

/// Encrypt `plaintext` to `recipients` as an armored, LF-only age file.
pub fn encrypt(recipients: &[x25519::Recipient], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let encryptor =
        age::Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))
            .map_err(|_| CryptoError::Internal("age encrypt"))?;
    let mut armored = Vec::new();
    let armor = ArmoredWriter::wrap_output(&mut armored, Format::AsciiArmor)
        .map_err(|_| CryptoError::Internal("age armor"))?;
    let mut writer = encryptor
        .wrap_output(armor)
        .map_err(|_| CryptoError::Internal("age encrypt"))?;
    writer
        .write_all(plaintext)
        .and_then(|()| writer.finish())
        .and_then(|armor| armor.finish())
        .map_err(|_| CryptoError::Internal("age encrypt"))?;
    Ok(armored)
}

/// Decrypt an armored age file with exactly one X25519 identity. A passphrase (scrypt)
/// stanza is refused before any decryption.
pub fn decrypt(armored: &[u8], identity: &Identity) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let decryptor = age::Decryptor::new(ArmoredReader::new(BufReader::new(armored)))
        .map_err(|_| CryptoError::AgeMalformed)?;
    if decryptor.is_scrypt() {
        return Err(CryptoError::NotARecipient);
    }
    let mut reader = decryptor
        .decrypt(iter::once(&identity.0 as &dyn age::Identity))
        .map_err(|e| match e {
            age::DecryptError::NoMatchingKeys => CryptoError::NotARecipient,
            _ => CryptoError::AgeMalformed,
        })?;
    // The plaintext is shorter than its armor, so this buffer never reallocates and leaves
    // no unzeroized copy behind.
    let mut out = Zeroizing::new(Vec::with_capacity(armored.len()));
    reader
        .read_to_end(&mut out)
        .map_err(|_| CryptoError::AgeMalformed)?;
    Ok(out)
}

// ---------------------------------------------------------------------------------------
// SSHSIG ed25519
// ---------------------------------------------------------------------------------------

/// An unencrypted ed25519 signing key. No `Debug`; `ssh_key::PrivateKey` zeroizes on drop.
pub struct SigningKey(PrivateKey);

impl SigningKey {
    /// The public half.
    pub fn public_key(&self) -> &PublicKey {
        self.0.public_key()
    }

    /// The OpenSSH `SHA256:…` fingerprint the header's `signer` carries.
    pub fn fingerprint(&self) -> String {
        signer_fingerprint(self.0.public_key())
    }
}

/// The OpenSSH `SHA256:…` fingerprint of a public key.
pub fn signer_fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

/// Parse a signing key from 1Password's SSH Key item (T16): the OpenSSH form
/// (`ssh_formats.openssh.value`, or `?ssh-format=openssh`) or the default PKCS#8 form
/// (`value`, RFC 8410). Encrypted, non-ed25519 and any other shape are refused.
pub fn parse_signing_key(pem: &str) -> Result<SigningKey, CryptoError> {
    let pem = pem.trim();
    if pem.starts_with(OPENSSH_BEGIN) {
        let key = PrivateKey::from_openssh(pem)
            .map_err(|_| CryptoError::SigningKeyInvalid("the OpenSSH key does not decode"))?;
        if key.is_encrypted() {
            return Err(CryptoError::SigningKeyInvalid("the key is encrypted"));
        }
        if key.algorithm() != Algorithm::Ed25519 {
            return Err(CryptoError::SigningKeyInvalid("the key is not ed25519"));
        }
        return Ok(SigningKey(key));
    }
    if pem.starts_with(PKCS8_BEGIN) {
        return parse_pkcs8(pem);
    }
    Err(CryptoError::SigningKeyInvalid(
        "not an OpenSSH or PKCS#8 private key",
    ))
}

fn parse_pkcs8(pem: &str) -> Result<SigningKey, CryptoError> {
    let mut lines = pem.lines().map(str::trim);
    if lines.next() != Some(PKCS8_BEGIN) {
        return Err(CryptoError::SigningKeyInvalid("malformed PKCS#8 armor"));
    }
    // Sized up front: growing the buffer would free unzeroized copies of the key's base64.
    let mut body = Zeroizing::new(String::with_capacity(pem.len()));
    let mut ended = false;
    for line in lines {
        if ended {
            if !line.is_empty() {
                return Err(CryptoError::SigningKeyInvalid("malformed PKCS#8 armor"));
            }
        } else if line == PKCS8_END {
            ended = true;
        } else {
            body.push_str(line);
        }
    }
    if !ended {
        return Err(CryptoError::SigningKeyInvalid("malformed PKCS#8 armor"));
    }
    let der = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(body.as_bytes())
            .map_err(|_| CryptoError::SigningKeyInvalid("malformed PKCS#8 armor"))?,
    );
    if der.len() != PKCS8_ED25519_PREFIX.len() + 32 || der[..16] != PKCS8_ED25519_PREFIX {
        return Err(CryptoError::SigningKeyInvalid(
            "the PKCS#8 key is not an unencrypted ed25519 key",
        ));
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&der[16..]);
    Ok(SigningKey(PrivateKey::from(Ed25519Keypair::from_seed(
        &seed,
    ))))
}

/// Sign `message` as an SSHSIG in namespace `opv-sealed` with sha512, returned as its LF
/// PEM block (`-----BEGIN SSH SIGNATURE-----` … `-----END SSH SIGNATURE-----\n`).
pub fn sign(key: &SigningKey, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let signature = key
        .0
        .sign(NAMESPACE, HashAlg::Sha512, message)
        .map_err(|_| CryptoError::Internal("sign"))?;
    let pem = signature
        .to_pem(LineEnding::LF)
        .map_err(|_| CryptoError::Internal("sign"))?;
    Ok(pem.into_bytes())
}

/// Verify an SSHSIG PEM block over `message` for `principal`: namespace `opv-sealed`,
/// sha512, an ed25519 key that an `allowed_signers` line lists for `principal` exactly.
/// Returns the verifying key.
pub fn verify(
    signers: &AllowedSigners,
    principal: &str,
    message: &[u8],
    signature_pem: &[u8],
) -> Result<PublicKey, SignatureRefusal> {
    let signature = SshSig::from_pem(signature_pem).map_err(|_| SignatureRefusal::Unreadable)?;
    if signature.namespace() != NAMESPACE {
        return Err(SignatureRefusal::WrongNamespace);
    }
    if signature.hash_alg() != HashAlg::Sha512 {
        return Err(SignatureRefusal::WrongHash);
    }
    if signature.algorithm() != Algorithm::Ed25519 {
        return Err(SignatureRefusal::WrongAlgorithm);
    }
    match signers.lookup(principal, signature.public_key()) {
        Lookup::Trusted => {}
        Lookup::OtherPrincipal => {
            return Err(SignatureRefusal::OtherPrincipal {
                principal: principal.to_string(),
            });
        }
        Lookup::NotListed => {
            return Err(SignatureRefusal::NotListed {
                principal: principal.to_string(),
            });
        }
    }
    let key = PublicKey::new(signature.public_key().clone(), "");
    key.verify(NAMESPACE, message, &signature)
        .map_err(|_| SignatureRefusal::Invalid)?;
    Ok(key)
}

// ---------------------------------------------------------------------------------------
// Bundles: seal, verify, open
// ---------------------------------------------------------------------------------------

/// What the runtime requires of a bundle before it is decrypted (§4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Expect<'a> {
    /// `--env`; also the principal the signer must be listed for.
    pub environment: &'a str,
    /// `--product`.
    pub product: &'a str,
    /// `--project`; `None` leaves the header's project unchecked (security review 0.18.0
    /// S4: with per-environment principals it binds a bundle to one project).
    pub project: Option<&'a str>,
    /// `--min-revision`; `None` sets no floor.
    pub min_revision: Option<u64>,
}

/// A bundle whose signature, scope and revision checked out. Nothing is decrypted yet;
/// this is what `--verify-only` reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBundle {
    /// The verified header.
    pub header: Header,
    /// The verifying key's `SHA256:…` fingerprint.
    pub signer: String,
    header_line: Vec<u8>,
    age: Vec<u8>,
}

/// An opened bundle: the verified header, the signer and recipient fingerprints, and the
/// values in header order. Its `Debug` prints names, never values.
pub struct OpenedBundle {
    /// The verified header.
    pub header: Header,
    /// The verifying key's `SHA256:…` fingerprint.
    pub signer: String,
    /// The identity's `sha256:…` recipient fingerprint.
    pub recipient: String,
    /// Each name with its zeroizing value, in header order.
    pub values: Payload,
}

impl std::fmt::Debug for OpenedBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedBundle")
            .field("header", &self.header)
            .field("signer", &self.signer)
            .field("recipient", &self.recipient)
            .field(
                "values",
                &self.values.iter().map(|(n, _)| n).collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// Seal a whole batch under `header`: frame the payload, encrypt it to `recipients`, sign
/// the format line, header and age block with `key`, and assemble the envelope. The header's
/// `recipients`, `signer` and names must match the inputs (§5.3: asserted before signing).
pub fn seal(
    header: &Header,
    entries: &[(&str, &[u8])],
    recipients: &[x25519::Recipient],
    key: &SigningKey,
) -> Result<Vec<u8>, CryptoError> {
    let mut fingerprints: Vec<String> = recipients.iter().map(recipient_fingerprint).collect();
    fingerprints.sort();
    if fingerprints != header.recipients {
        return Err(CryptoError::SealMismatch("recipients"));
    }
    if key.fingerprint() != header.signer {
        return Err(CryptoError::SealMismatch("signer"));
    }
    if !entries
        .iter()
        .map(|(name, _)| *name)
        .eq(header.names.iter().map(|n| n.name.as_str()))
    {
        return Err(CryptoError::SealMismatch("names"));
    }
    // G4 by value: the configuration check compares `deploy_credentials` with the boundary
    // by ids, which a name reference never matches; the key itself never matches here.
    if let Some((name, _)) = entries.iter().find(|(_, v)| is_signing_key(v, key)) {
        return Err(CryptoError::SealsSigningKey((*name).to_string()));
    }
    let header_line = format::canonical_header(header).map_err(CryptoError::Malformed)?;
    let payload = format::encode_payload(&header_line, entries).map_err(CryptoError::Malformed)?;
    let age = encrypt(recipients, &payload)?;
    let mut signed = Vec::with_capacity(FORMAT_LINE.len() + header_line.len() + 1 + age.len());
    signed.extend_from_slice(FORMAT_LINE);
    signed.extend_from_slice(&header_line);
    signed.push(b'\n');
    signed.extend_from_slice(&age);
    let signature = sign(key, &signed)?;
    format::encode_envelope(&header_line, &age, &signature).map_err(CryptoError::Malformed)
}

/// Whether `value` is `key` itself, in either form 1Password returns (OpenSSH or PKCS#8):
/// the same public key, so a re-encoded copy matches too. Never formats the value.
fn is_signing_key(value: &[u8], key: &SigningKey) -> bool {
    std::str::from_utf8(value)
        .ok()
        .and_then(|text| parse_signing_key(text).ok())
        .is_some_and(|found| found.public_key().key_data() == key.public_key().key_data())
}

/// Verify a bundle without decrypting it: the codec checks, then the SSHSIG over the format
/// line, header and ciphertext from a signer listed for the header's environment, then the
/// header's signer, environment, product and revision.
pub fn verify_bundle(
    bundle: &[u8],
    signers: &AllowedSigners,
    expect: &Expect<'_>,
) -> Result<VerifiedBundle, CryptoError> {
    let envelope = parse_envelope(bundle).map_err(CryptoError::Malformed)?;
    let header = envelope.header;
    let key = verify(
        signers,
        &header.environment,
        &envelope.signed,
        &envelope.signature,
    )
    .map_err(CryptoError::Signature)?;
    let signer = signer_fingerprint(&key);
    if signer != header.signer {
        return Err(CryptoError::Signature(SignatureRefusal::SignerMismatch));
    }
    if header.environment != expect.environment {
        return Err(CryptoError::ScopeMismatch {
            field: "environment",
            expected: expect.environment.to_string(),
            found: header.environment,
        });
    }
    if header.product != expect.product {
        return Err(CryptoError::ScopeMismatch {
            field: "product",
            expected: expect.product.to_string(),
            found: header.product,
        });
    }
    if let Some(project) = expect.project
        && header.project != project
    {
        return Err(CryptoError::ScopeMismatch {
            field: "project",
            expected: project.to_string(),
            found: header.project,
        });
    }
    if let Some(floor) = expect.min_revision
        && header.revision < floor
    {
        return Err(CryptoError::RevisionBelowFloor {
            revision: header.revision,
            floor,
        });
    }
    Ok(VerifiedBundle {
        header,
        signer,
        header_line: envelope.header_line,
        age: envelope.age,
    })
}

/// Whether the identity's recipient is listed in the verified header (U4). Nothing is
/// decrypted.
pub fn check_recipient(
    verified: &VerifiedBundle,
    identity: &Identity,
) -> Result<String, CryptoError> {
    listed_recipient(verified, &recipient_fingerprint(&identity.recipient()))
}

fn listed_recipient(verified: &VerifiedBundle, fingerprint: &str) -> Result<String, CryptoError> {
    if verified.header.recipients.iter().any(|r| r == fingerprint) {
        Ok(fingerprint.to_string())
    } else {
        Err(CryptoError::NotARecipient)
    }
}

/// Verify, then decrypt: [`verify_bundle`], the identity's membership in the header's
/// recipients, age decryption with that one identity, and the payload's binding to the
/// verified header. Every refusal before decryption leaves the ciphertext untouched.
pub fn open(
    bundle: &[u8],
    identity: &Identity,
    signers: &AllowedSigners,
    expect: &Expect<'_>,
) -> Result<OpenedBundle, CryptoError> {
    open_with(bundle, identity, signers, expect)
}

/// The decryption step of [`open`], behind a seam so the tests can prove it is never reached
/// on a refusal.
pub(super) trait Decrypt {
    /// The `sha256:…` fingerprint of the identity's recipient.
    fn recipient_fingerprint(&self) -> String;
    /// Decrypt the armored age block.
    fn decrypt(&self, armored: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError>;
}

impl Decrypt for Identity {
    fn recipient_fingerprint(&self) -> String {
        recipient_fingerprint(&self.recipient())
    }

    fn decrypt(&self, armored: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        decrypt(armored, self)
    }
}

pub(super) fn open_with(
    bundle: &[u8],
    decryptor: &dyn Decrypt,
    signers: &AllowedSigners,
    expect: &Expect<'_>,
) -> Result<OpenedBundle, CryptoError> {
    let verified = verify_bundle(bundle, signers, expect)?;
    let recipient = listed_recipient(&verified, &decryptor.recipient_fingerprint())?;
    let payload = decryptor.decrypt(&verified.age)?;
    let values = decode_payload(&verified.header.names, &verified.header_line, &payload)
        .map_err(CryptoError::PayloadMismatch)?;
    Ok(OpenedBundle {
        header: verified.header,
        signer: verified.signer,
        recipient,
        values,
    })
}
