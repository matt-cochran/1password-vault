//! The `opv-sealed/1` bundle codec (design sealed-target §5.1–§5.3, §10): one LF-only file
//! of a format line, a canonical value-free header, an age armor block and an SSHSIG armor
//! block, plus the binary payload framing that binds the values to the signed header.
//!
//! The module is pure: it never runs crypto, reads configuration, touches the filesystem or
//! formats a value. Lane st-b2 adds age and SSHSIG over these parts; this codec only splits,
//! assembles, canonicalizes and frames. Every refusal is a named [`FormatError`]; mapping
//! them to opv causes is lane st-u1's job.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The first line of a bundle: the protocol and its version.
pub const FORMAT_LINE: &[u8] = b"opv-sealed v1\n";
/// The header's `format` value; it must agree with [`FORMAT_LINE`].
pub const FORMAT: &str = "opv-sealed/1";
/// The SSHSIG namespace pinned by the design.
pub const NAMESPACE: &str = "opv-sealed";
/// The age armor's first line (exactly what `age -a` emits).
pub const AGE_BEGIN: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE-----\n";
/// The age armor's last line.
pub const AGE_END: &[u8] = b"-----END AGE ENCRYPTED FILE-----\n";
/// The SSHSIG armor's first line (exactly what `ssh-keygen -Y sign` emits).
pub const SSH_BEGIN: &[u8] = b"-----BEGIN SSH SIGNATURE-----\n";
/// The SSHSIG armor's last line.
pub const SSH_END: &[u8] = b"-----END SSH SIGNATURE-----\n";
/// The payload's first line.
pub const PAYLOAD_MAGIC: &[u8] = b"OPV-SEALED-PAYLOAD 1\n";
/// The payload's last line.
pub const PAYLOAD_END: &[u8] = b"END\n";

/// The header is at most 64 KiB.
pub const MAX_HEADER: usize = 64 * 1024;
/// A payload has at most 256 names.
pub const MAX_NAMES: usize = 256;
/// A payload value is at most 1 MiB.
pub const MAX_VALUE: usize = 1 << 20;
/// The whole bundle is at most 8 MiB.
pub const MAX_BUNDLE: usize = 8 * 1024 * 1024;
/// A relative file path has at most four `/`-separated parts.
pub const MAX_PATH_PARTS: usize = 4;

/// One delivered name and where it goes: `env:<NAME>` or `file:<relative path>`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Name {
    pub name: String,
    pub destination: String,
}

/// The signed, plaintext, value-free header (design §5.2). Keys are canonicalized on
/// serialization; `source_versions` is deliberately absent (C20).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub format: String,
    pub project: String,
    pub environment: String,
    pub product: String,
    pub target: String,
    pub revision: u64,
    pub created_at: String,
    pub opv_version: String,
    pub plan_id: String,
    pub contract_digest: String,
    pub recipients: Vec<String>,
    pub signer: String,
    pub names: Vec<Name>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets_dir_env: Option<String>,
    /// The product's `local.environment` when it was sealed (#279 S5): `declared_only`
    /// gives the command only the bundle's variables and the basic environment. Absent in
    /// bundles sealed before 0.18.1, which means `inherit`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child_environment: Option<ChildEnvironment>,
}

/// What `opv unseal --exec` passes on from the runtime's environment (#137, #279 S5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChildEnvironment {
    /// The whole environment, minus `OP_*` and the identity variable.
    Inherit,
    /// Only the bundle's variables and the basic environment (PATH, HOME, locale, ...).
    DeclaredOnly,
}

impl Header {
    /// Whether the command gets only the bundle's variables and the basic environment; a
    /// header without the field (sealed before 0.18.1) inherits.
    pub fn declared_only(&self) -> bool {
        self.child_environment == Some(ChildEnvironment::DeclaredOnly)
    }
}

/// Why a bundle part was refused. One variant per named refusal in the design; names and
/// structure only, never a value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FormatError {
    #[error("the bundle is larger than 8 MiB")]
    BundleTooLarge,
    #[error("the bundle contains a CR byte")]
    CarriageReturn,
    #[error("the first line is not `opv-sealed v1`")]
    UnknownFormatLine,
    #[error("the header is larger than 64 KiB")]
    HeaderTooLarge,
    #[error("the header is not valid JSON")]
    HeaderMalformed,
    #[error("the header has an unknown field")]
    UnknownHeaderField,
    #[error("the header has a duplicate key")]
    DuplicateHeaderKey,
    #[error("the header does not re-serialize to identical bytes")]
    HeaderNotCanonical,
    #[error("the header's format does not agree with the first line")]
    FormatMismatch,
    #[error("the header's names are not sorted")]
    NamesNotSorted,
    #[error("the header's recipients are not sorted")]
    RecipientsNotSorted,
    #[error("a second header line appears before the age block")]
    SecondHeader,
    #[error("the age block is missing")]
    MissingAgeBlock,
    #[error("the signature block is missing")]
    NoSignatureBlock,
    #[error("the envelope has bytes after the signature block")]
    TrailingData,
    #[error("a file path is not allowed: {0}")]
    BadFilePath(&'static str),
    #[error("a destination is not `env:` or `file:`: {0}")]
    BadDestination(String),
    #[error("a variable name is not allowed: {0}")]
    BadVariable(String),
    #[error("the payload is malformed")]
    PayloadMalformed,
    #[error("a payload value is larger than 1 MiB")]
    ValueTooLarge,
    #[error("the payload has more than 256 names")]
    TooManyNames,
    #[error("the payload's header digest differs from the header")]
    PayloadDigestMismatch,
    #[error("the payload's names differ from the header")]
    PayloadNamesMismatch,
    #[error("an `OP_` name appears in the payload")]
    OpName,
    #[error("the signature is invalid")]
    SignatureInvalid,
    #[error("the signer is not listed for the environment")]
    SignerNotListed,
    #[error("the signer is listed only for another principal")]
    SignerWrongPrincipal,
    #[error("the signature namespace is not `opv-sealed`")]
    WrongNamespace,
    #[error("an RSA signer line is not allowed")]
    RsaSigner,
    #[error("a `cert-authority` signer option is not allowed")]
    CertAuthorityOption,
    #[error("the header environment differs from the expected one")]
    WrongEnvironment,
    #[error("the header product differs from the expected one")]
    WrongProduct,
    #[error("the revision is below the floor")]
    RevisionBelowFloor,
    #[error("the identity is not a listed recipient")]
    UnlistedRecipient,
}

/// A decoded payload: each name and its zeroizing value, in header order.
pub type Payload = Vec<(String, Zeroizing<Vec<u8>>)>;

/// A split bundle: the parsed header, the exact bytes the SSHSIG covers, and the two armor
/// blocks. The value-free bytes stay in the caller's buffer; `signed` is the exact input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// The parsed, canonical header.
    pub header: Header,
    /// The header's canonical JSON bytes, without the trailing LF.
    pub header_line: Vec<u8>,
    /// Every byte above `-----BEGIN SSH SIGNATURE-----`: format line, header and age block.
    pub signed: Vec<u8>,
    /// The age armor block, including its `BEGIN`/`END` lines.
    pub age: Vec<u8>,
    /// The SSHSIG armor block, including its `BEGIN`/`END` lines.
    pub signature: Vec<u8>,
}

/// The canonical JSON bytes of `header`: keys sorted, no insignificant whitespace, integers
/// only. Two readers of the same header get the same bytes (§5.1, T9).
pub fn canonical_header(header: &Header) -> Result<Vec<u8>, FormatError> {
    let value = serde_json::to_value(header).map_err(|_| FormatError::HeaderMalformed)?;
    serde_json::to_vec(&canonicalize(value)).map_err(|_| FormatError::HeaderMalformed)
}

/// Parse a signed header line, check its fields and require that re-serializing the parsed
/// header reproduces the exact input bytes. Any non-canonical form is [`FormatError::HeaderNotCanonical`].
pub fn parse_header(line: &[u8]) -> Result<Header, FormatError> {
    if line.len() > MAX_HEADER {
        return Err(FormatError::HeaderTooLarge);
    }
    let text = std::str::from_utf8(line).map_err(|_| FormatError::HeaderMalformed)?;
    let header: Header = serde_json::from_str(text).map_err(header_error)?;
    check_header(&header)?;
    if canonical_header(&header)? != line {
        return Err(FormatError::HeaderNotCanonical);
    }
    Ok(header)
}

/// The `sha256:` contract digest over the canonical JSON of the sorted `(name, destination)`
/// list, `secrets_dir_env`, the recipients and the signer (§5.2), and `child_environment`
/// when it is `declared_only` (#279 S5; an `inherit` contract keeps its 0.18.0 digest).
pub fn contract_digest(
    names: &[Name],
    secrets_dir_env: Option<&str>,
    recipients: &[String],
    signer: &str,
    declared_only: bool,
) -> String {
    let mut object = serde_json::Map::new();
    let mut sorted = names.to_vec();
    sorted.sort();
    object.insert(
        "names".to_string(),
        serde_json::to_value(sorted).unwrap_or(Value::Null),
    );
    object.insert(
        "recipients".to_string(),
        serde_json::to_value(recipients).unwrap_or(Value::Null),
    );
    object.insert("signer".to_string(), Value::String(signer.to_string()));
    if let Some(env) = secrets_dir_env {
        object.insert(
            "secrets_dir_env".to_string(),
            Value::String(env.to_string()),
        );
    }
    if declared_only {
        object.insert(
            "child_environment".to_string(),
            Value::String("declared_only".to_string()),
        );
    }
    let bytes = serde_json::to_vec(&canonicalize(Value::Object(object))).unwrap_or_default();
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// Check a `name -> destination` pair's destination. `env:` variables obey
/// [`check_variable`]; `file:` paths obey the T6 path rule.
pub fn check_destination(destination: &str) -> Result<(), FormatError> {
    if let Some(path) = destination.strip_prefix("file:") {
        check_file_path(path)
    } else if let Some(var) = destination.strip_prefix("env:") {
        check_variable(var)
    } else {
        Err(FormatError::BadDestination(destination.to_string()))
    }
}

/// A variable a bundle sets in the app's environment (an `env:` destination or
/// `secrets_dir_env`; security review 0.18.0 S2, S3): `^[A-Za-z_][A-Za-z0-9_]*$`, and never
/// `OP_*` in any case, the 1Password CLI's own environment. The runtime also refuses the
/// `--identity-env` variable, which only it knows.
pub fn check_variable(var: &str) -> Result<(), FormatError> {
    let mut chars = var.chars();
    let shaped = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !shaped || var.get(..3).is_some_and(|p| p.eq_ignore_ascii_case("OP_")) {
        return Err(FormatError::BadVariable(var.to_string()));
    }
    Ok(())
}

/// The configuration's relative file path (T6): at most [`MAX_PATH_PARTS`] `/`-separated
/// parts, each `^[a-z0-9]+(-[a-z0-9]+)*$`, with no NUL and no backslash. Absolute paths,
/// `.`, `..` and empty parts are refused.
pub fn check_file_path(path: &str) -> Result<(), FormatError> {
    if path.contains('\0') {
        return Err(FormatError::BadFilePath("contains NUL"));
    }
    if path.contains('\\') {
        return Err(FormatError::BadFilePath("contains backslash"));
    }
    if path.starts_with('/') {
        return Err(FormatError::BadFilePath("is absolute"));
    }
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() > MAX_PATH_PARTS {
        return Err(FormatError::BadFilePath("has more than four parts"));
    }
    if parts.iter().any(|part| !valid_path_part(part)) {
        return Err(FormatError::BadFilePath("has a part outside the rule"));
    }
    Ok(())
}

/// A payload name: `OP_*` names are opv's own environment and can never be delivered.
pub fn check_name(name: &str) -> Result<(), FormatError> {
    if name.starts_with("OP_") {
        return Err(FormatError::OpName);
    }
    if name.is_empty() {
        return Err(FormatError::PayloadMalformed);
    }
    Ok(())
}

/// Split and check a whole bundle. The file is read once: the first line is the format, the
/// second the canonical header, then the age block, then the SSHSIG block. The signature's
/// bytes are exactly everything above it ([`Envelope::signed`]).
pub fn parse_envelope(data: &[u8]) -> Result<Envelope, FormatError> {
    if data.len() > MAX_BUNDLE {
        return Err(FormatError::BundleTooLarge);
    }
    if data.contains(&b'\r') {
        return Err(FormatError::CarriageReturn);
    }
    let chunks: Vec<&[u8]> = data.split_inclusive(|&b| b == b'\n').collect();
    match chunks.first() {
        Some(line) if *line == FORMAT_LINE => {}
        _ => return Err(FormatError::UnknownFormatLine),
    }
    let header_chunk = chunks.get(1).ok_or(FormatError::HeaderMalformed)?;
    let header_line = header_chunk
        .strip_suffix(b"\n")
        .ok_or(FormatError::HeaderMalformed)?;
    let header = parse_header(header_line)?;

    match chunks.get(2) {
        Some(block) if block.starts_with(AGE_BEGIN) => {}
        Some(block) if block.starts_with(b"{") => return Err(FormatError::SecondHeader),
        _ => return Err(FormatError::MissingAgeBlock),
    }
    let age_start = 2;
    let age_end = chunks
        .iter()
        .position(|block| block.starts_with(AGE_END))
        .ok_or(FormatError::MissingAgeBlock)?;
    if age_end < age_start {
        return Err(FormatError::MissingAgeBlock);
    }
    let signature_start = age_end + 1;
    match chunks.get(signature_start) {
        Some(block) if block.starts_with(SSH_BEGIN) => {}
        _ => return Err(FormatError::NoSignatureBlock),
    }
    let signature_end = chunks
        .iter()
        .position(|block| block.starts_with(SSH_END))
        .ok_or(FormatError::NoSignatureBlock)?;
    if signature_end < signature_start {
        return Err(FormatError::NoSignatureBlock);
    }
    if signature_end + 1 != chunks.len() {
        return Err(FormatError::TrailingData);
    }

    let age = chunks[age_start..=age_end].concat();
    let signature = chunks[signature_start..=signature_end].concat();
    let signed = chunks[..=age_end].concat();
    Ok(Envelope {
        header,
        header_line: header_line.to_vec(),
        signed,
        age,
        signature,
    })
}

/// Assemble a bundle from a canonical header line and the two armor blocks. The signature
/// block must be over the returned bytes above it (the caller signs; this codec does not).
pub fn encode_envelope(
    header_line: &[u8],
    age: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>, FormatError> {
    if header_line.contains(&b'\r') || age.contains(&b'\r') || signature.contains(&b'\r') {
        return Err(FormatError::CarriageReturn);
    }
    parse_header(header_line)?;
    if !age.starts_with(AGE_BEGIN) {
        return Err(FormatError::MissingAgeBlock);
    }
    if !age.ends_with(AGE_END) {
        return Err(FormatError::MissingAgeBlock);
    }
    if !signature.starts_with(SSH_BEGIN) {
        return Err(FormatError::NoSignatureBlock);
    }
    if !signature.ends_with(SSH_END) {
        return Err(FormatError::NoSignatureBlock);
    }
    let mut out =
        Vec::with_capacity(FORMAT_LINE.len() + header_line.len() + 1 + age.len() + signature.len());
    out.extend_from_slice(FORMAT_LINE);
    out.extend_from_slice(header_line);
    out.push(b'\n');
    out.extend_from_slice(age);
    out.extend_from_slice(signature);
    if out.len() > MAX_BUNDLE {
        return Err(FormatError::BundleTooLarge);
    }
    Ok(out)
}

/// Frame a whole batch: [`PAYLOAD_MAGIC`], `sha256(header_line)`, the name count (u32,
/// big-endian), then per name its length (u16, big-endian), its bytes, its value length
/// (u32, big-endian) and its exact bytes, then [`PAYLOAD_END`]. Values are never decoded to
/// `String`.
pub fn encode_payload(
    header_line: &[u8],
    entries: &[(&str, &[u8])],
) -> Result<Zeroizing<Vec<u8>>, FormatError> {
    if entries.len() > MAX_NAMES {
        return Err(FormatError::TooManyNames);
    }
    let mut out = Zeroizing::new(Vec::new());
    out.extend_from_slice(PAYLOAD_MAGIC);
    out.extend_from_slice(&Sha256::digest(header_line));
    out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for (name, value) in entries {
        check_name(name)?;
        if name.len() > u16::MAX as usize {
            return Err(FormatError::PayloadMalformed);
        }
        if value.len() > MAX_VALUE {
            return Err(FormatError::ValueTooLarge);
        }
        out.extend_from_slice(&(name.len() as u16).to_be_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
    }
    out.extend_from_slice(PAYLOAD_END);
    Ok(out)
}

/// Check and read a payload. The header digest and the name list must equal the verified
/// header's (§5.3, C17). Every value is read into a [`Zeroizing`] buffer.
pub fn decode_payload(
    expected_names: &[Name],
    header_line: &[u8],
    payload: &[u8],
) -> Result<Payload, FormatError> {
    let mut rest = payload;
    rest = strip(rest, PAYLOAD_MAGIC).ok_or(FormatError::PayloadMalformed)?;
    if rest.len() < 32 + 4 {
        return Err(FormatError::PayloadMalformed);
    }
    if rest[..32] != Sha256::digest(header_line)[..] {
        return Err(FormatError::PayloadDigestMismatch);
    }
    rest = &rest[32..];
    let count = u32::from_be_bytes(rest[..4].try_into().unwrap_or([0; 4])) as usize;
    rest = &rest[4..];
    if count > MAX_NAMES {
        return Err(FormatError::TooManyNames);
    }
    if count != expected_names.len() {
        return Err(FormatError::PayloadNamesMismatch);
    }
    let mut values = Vec::with_capacity(count);
    for expected in expected_names {
        if rest.len() < 2 {
            return Err(FormatError::PayloadMalformed);
        }
        let name_len = u16::from_be_bytes(rest[..2].try_into().unwrap_or([0; 2])) as usize;
        rest = &rest[2..];
        if rest.len() < name_len + 4 {
            return Err(FormatError::PayloadMalformed);
        }
        let name = std::str::from_utf8(&rest[..name_len])
            .map_err(|_| FormatError::PayloadMalformed)?
            .to_string();
        rest = &rest[name_len..];
        if name != expected.name {
            return Err(FormatError::PayloadNamesMismatch);
        }
        check_name(&name)?;
        let value_len = u32::from_be_bytes(rest[..4].try_into().unwrap_or([0; 4])) as usize;
        rest = &rest[4..];
        if value_len > MAX_VALUE {
            return Err(FormatError::ValueTooLarge);
        }
        if rest.len() < value_len {
            return Err(FormatError::PayloadMalformed);
        }
        let mut value = Zeroizing::new(vec![0u8; value_len]);
        value.copy_from_slice(&rest[..value_len]);
        rest = &rest[value_len..];
        values.push((name, value));
    }
    if rest != PAYLOAD_END {
        return Err(FormatError::PayloadMalformed);
    }
    Ok(values)
}

fn strip<'a>(data: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    data.strip_prefix(prefix)
}

fn check_header(header: &Header) -> Result<(), FormatError> {
    if header.format != FORMAT {
        return Err(FormatError::FormatMismatch);
    }
    if header.names.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(FormatError::NamesNotSorted);
    }
    for name in &header.names {
        check_destination(&name.destination)?;
    }
    if let Some(var) = &header.secrets_dir_env {
        check_variable(var)?;
    }
    if header.recipients.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(FormatError::RecipientsNotSorted);
    }
    Ok(())
}

fn valid_path_part(part: &str) -> bool {
    if part.is_empty() {
        return false;
    }
    // `^[a-z0-9]+(-[a-z0-9]+)*$`: alphanumerics separated by single hyphens, no leading or
    // trailing hyphen.
    let mut after_hyphen = true;
    for byte in part.bytes() {
        match byte {
            b'a'..=b'z' | b'0'..=b'9' => after_hyphen = false,
            b'-' if !after_hyphen => after_hyphen = true,
            _ => return false,
        }
    }
    !after_hyphen
}

fn header_error(error: serde_json::Error) -> FormatError {
    let message = error.to_string();
    if message.contains("unknown field") {
        FormatError::UnknownHeaderField
    } else if message.contains("duplicate field") {
        FormatError::DuplicateHeaderKey
    } else {
        FormatError::HeaderMalformed
    }
}

/// Serialize a JSON value deterministically: object keys sorted, arrays in order, no
/// whitespace.
fn canonicalize(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut pairs: Vec<(String, Value)> = map
                .into_iter()
                .map(|(key, value)| (key, canonicalize(value)))
                .collect();
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(pairs.into_iter().collect())
        }
        Value::Array(items) => Value::Array(items.into_iter().map(canonicalize).collect()),
        other => other,
    }
}
