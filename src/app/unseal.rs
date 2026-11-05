//! `opv unseal` (#271, design `sealed-target` §4.2): the runtime command. It reads a sealed
//! bundle, the `allowed_signers` file and an age identity, and nothing else: no
//! configuration, no `op`, no runner call, no socket.
//!
//! This lane (st-u1) verifies and inspects. Without `--exec` it never prints a value:
//!
//! - `--verify-only` checks the signature, header, scope and revision without decrypting;
//!   with an identity it also checks that the identity's recipient is listed in the header
//!   (U4), and when the bundle has file keys it checks for a RAM-backed runtime directory
//!   (vet R2), so a staging smoke test catches a wrong signer file, a wrong identity or a
//!   missing tmpfs mount before production starts.
//! - Without it, the bundle is also decrypted in memory and its payload checked against the
//!   signed header; the values are dropped (zeroized) unread.
//!
//! The order is the codec's (§9.2): the bundle and signers are verified before the identity
//! is read, and the identity's membership is checked before anything is decrypted.
//!
//! [`open`] is the seam lane st-u2's `--exec` delivers from: the same checks, returning the
//! opened bundle with its zeroizing values.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde_json::json;
use zeroize::Zeroizing;

use super::write_err;
use crate::bundle::crypto::{self, CryptoError, Expect, Identity, OpenedBundle, VerifiedBundle};
use crate::bundle::format::{Header, MAX_BUNDLE};
use crate::cause::{Cause, IdentityFrom, RamDir, RamPurpose, SealedRefusal, sealed_refusal};
use crate::error::Error;

/// The largest `allowed_signers` file read.
const MAX_SIGNERS: u64 = 1 << 20;
/// The largest identity read (one line and its comments).
const MAX_IDENTITY: u64 = 64 * 1024;

/// Where the age identity comes from (D4): a file, or a variable read once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentitySource {
    /// `--identity-file <path>`.
    File(PathBuf),
    /// `--identity-env <VAR>`.
    Env(String),
}

impl IdentitySource {
    fn from(&self) -> IdentityFrom {
        match self {
            IdentitySource::File(path) => IdentityFrom::File { path: path.clone() },
            IdentitySource::Env(var) => IdentityFrom::Env { var: var.clone() },
        }
    }
}

/// One `opv unseal` invocation.
#[derive(Debug, Clone)]
pub struct Request {
    pub bundle: PathBuf,
    pub env: String,
    pub product: String,
    pub signers: PathBuf,
    pub identity: Option<IdentitySource>,
    pub min_revision: Option<u64>,
    pub verify_only: bool,
    pub json: bool,
}

impl Request {
    fn expect(&self) -> Expect<'_> {
        Expect {
            environment: &self.env,
            product: &self.product,
            min_revision: self.min_revision,
        }
    }

    fn refused(&self, err: &CryptoError) -> Error {
        let from = self.identity.as_ref().map(IdentitySource::from);
        sealed_refusal(&self.bundle, &self.signers, from.as_ref(), err).into()
    }
}

/// `opv unseal` without `--exec`: verify (and, unless `--verify-only`, decrypt and check)
/// the bundle, print one stderr start line, and print the verified header on `out`. Never a
/// value.
pub fn run(req: &Request, out: &mut dyn Write) -> Result<i32, Error> {
    run_with(req, &crate::app::local_delivery::runtime_dir_support, out)
}

/// What the RAM-directory check found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeDir {
    /// A RAM-backed runtime directory is available for the file keys.
    RamBacked,
    /// The bundle has no file keys.
    NotNeeded,
    /// Not checked (only `--verify-only` checks it; `--exec` checks before any file).
    NotChecked,
}

impl RuntimeDir {
    fn word(self) -> &'static str {
        match self {
            RuntimeDir::RamBacked => "ram_backed",
            RuntimeDir::NotNeeded => "not_needed",
            RuntimeDir::NotChecked => "not_checked",
        }
    }
}

/// [`run`] with the RAM-directory check injected (tests).
pub(crate) fn run_with(
    req: &Request,
    ram_dir: &dyn Fn() -> Result<PathBuf, RamDir>,
    out: &mut dyn Write,
) -> Result<i32, Error> {
    let inputs = Inputs::read(req)?;
    let verified = inputs.verify(req)?;
    start_line(&verified.header, &verified.signer);
    let (recipient, decrypted, runtime) = if req.verify_only {
        let recipient = match &req.identity {
            Some(source) => {
                let identity = load_identity(req, source)?;
                Some(member(req, &verified, &identity)?)
            }
            None => None,
        };
        let runtime = if has_file_keys(&verified.header) {
            ram_dir().map_err(|why| -> Error {
                Cause::RamDirUnavailable {
                    remote: None,
                    why,
                    purpose: RamPurpose::FileDelivery,
                    env: None,
                    product: None,
                }
                .into()
            })?;
            RuntimeDir::RamBacked
        } else {
            RuntimeDir::NotNeeded
        };
        (recipient, false, runtime)
    } else {
        let opened = inputs.open(req, &verified)?;
        // The values are dropped here, zeroized, never read.
        (Some(opened.recipient.clone()), true, RuntimeDir::NotChecked)
    };
    let report = Report {
        header: &verified.header,
        signer: &verified.signer,
        recipient: recipient.as_deref(),
        decrypted,
        runtime,
    };
    if req.json {
        writeln!(out, "{}", report.json()).map_err(write_err)?;
    } else {
        report.text(out).map_err(write_err)?;
    }
    Ok(0)
}

/// Verify, then decrypt: the bundle and signers are read and verified, then the identity is
/// read, its membership checked, the payload decrypted and bound to the header. The seam
/// `--exec` (lane st-u2) delivers from; it prints nothing.
pub fn open(req: &Request) -> Result<OpenedBundle, Error> {
    let inputs = Inputs::read(req)?;
    let verified = inputs.verify(req)?;
    inputs.open(req, &verified)
}

/// The one stderr line at start (observability, §4.2): scope, revision, signer and the
/// number of names. Never a value.
pub fn start_line(header: &Header, signer: &str) {
    let _ = writeln!(crate::output::stderr(), "{}", start_text(header, signer));
}

fn start_text(header: &Header, signer: &str) -> String {
    let n = header.names.len();
    format!(
        "opv unseal: {}/{} revision {} signer {signer} {n} {}",
        header.environment,
        header.product,
        header.revision,
        if n == 1 { "name" } else { "names" }
    )
}

/// The bundle's bytes and the parsed signers file, each read once.
struct Inputs {
    bundle: Vec<u8>,
    signers: crate::bundle::allowed_signers::AllowedSigners,
}

impl Inputs {
    fn read(req: &Request) -> Result<Self, Error> {
        Ok(Inputs {
            bundle: read_bundle(req)?,
            signers: read_signers(req)?,
        })
    }

    /// Verify the bundle without decrypting it.
    fn verify(&self, req: &Request) -> Result<VerifiedBundle, Error> {
        crypto::verify_bundle(&self.bundle, &self.signers, &req.expect())
            .map_err(|e| req.refused(&e))
    }

    /// Read the identity, check it is a listed recipient, then the codec's own
    /// verify-then-decrypt and payload binding over the same bytes.
    fn open(&self, req: &Request, verified: &VerifiedBundle) -> Result<OpenedBundle, Error> {
        let source = req.identity.as_ref().ok_or_else(|| -> Error {
            Cause::Bug {
                site: "unseal decrypts only with an identity",
            }
            .into()
        })?;
        let identity = load_identity(req, source)?;
        let fingerprint = member(req, verified, &identity)?;
        crypto::open(&self.bundle, &identity, &self.signers, &req.expect()).map_err(|e| match e {
            // No age stanza matched, though the header lists the recipient.
            CryptoError::NotARecipient => not_a_recipient(req, Some(fingerprint.clone())),
            e => req.refused(&e),
        })
    }
}

/// The identity's recipient fingerprint when the header lists it.
fn member(req: &Request, verified: &VerifiedBundle, identity: &Identity) -> Result<String, Error> {
    crypto::check_recipient(verified, identity).map_err(|e| match e {
        CryptoError::NotARecipient => not_a_recipient(
            req,
            Some(crypto::recipient_fingerprint(&identity.recipient())),
        ),
        e => req.refused(&e),
    })
}

fn not_a_recipient(req: &Request, recipient: Option<String>) -> Error {
    Cause::SealedRefused {
        bundle: req.bundle.clone(),
        refusal: SealedRefusal::NotARecipient { recipient },
    }
    .into()
}

fn read_bundle(req: &Request) -> Result<Vec<u8>, Error> {
    // One byte over the limit is enough for the codec to refuse the size.
    read_limited(&req.bundle, MAX_BUNDLE as u64 + 1).map_err(|e| -> Error {
        Cause::SealedRefused {
            bundle: req.bundle.clone(),
            refusal: SealedRefusal::Malformed {
                detail: format!("the file cannot be read ({})", e.kind()),
            },
        }
        .into()
    })
}

fn read_signers(req: &Request) -> Result<crate::bundle::allowed_signers::AllowedSigners, Error> {
    let text = read_limited(&req.signers, MAX_SIGNERS).map_err(|e| -> Error {
        Cause::SealedRefused {
            bundle: req.bundle.clone(),
            refusal: SealedRefusal::SignatureInvalid {
                signers: req.signers.clone(),
                detail: format!("the allowed_signers file cannot be read ({})", e.kind()),
            },
        }
        .into()
    })?;
    crate::bundle::allowed_signers::AllowedSigners::parse(&text)
        .map_err(|e| req.refused(&CryptoError::Signers(e)))
}

fn read_limited(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    std::fs::File::open(path)?
        .take(limit)
        .read_to_end(&mut buf)?;
    Ok(buf)
}

/// Read the identity into zeroizing memory and parse it. A variable is read once; it is
/// never an argument (SR-3).
fn load_identity(req: &Request, source: &IdentitySource) -> Result<Identity, Error> {
    let unusable = |detail: String| -> Error {
        Cause::SealedRefused {
            bundle: req.bundle.clone(),
            refusal: SealedRefusal::IdentityUnusable {
                from: source.from(),
                detail,
            },
        }
        .into()
    };
    let bytes: Zeroizing<Vec<u8>> = match source {
        IdentitySource::File(path) => {
            // Sized so reading never reallocates and leaves no unzeroized copy behind.
            let mut buf = Zeroizing::new(Vec::with_capacity(MAX_IDENTITY as usize + 1));
            std::fs::File::open(path)
                .and_then(|f| f.take(MAX_IDENTITY).read_to_end(&mut buf))
                .map_err(|e| unusable(format!("the file cannot be read ({})", e.kind())))?;
            buf
        }
        IdentitySource::Env(var) => match std::env::var_os(var) {
            None => return Err(unusable("the variable is not set".into())),
            Some(v) => match v.into_string() {
                Ok(s) => Zeroizing::new(s.into_bytes()),
                Err(v) => {
                    // Zeroize the bytes that are not UTF-8 too.
                    drop(Zeroizing::new(v.into_encoded_bytes()));
                    return Err(unusable("the value is not UTF-8".into()));
                }
            },
        },
    };
    let text = std::str::from_utf8(&bytes).map_err(|_| unusable("it is not UTF-8".into()))?;
    crypto::parse_identity(text).map_err(|e| req.refused(&e))
}

/// Whether any name is delivered as a file (`file:` destination).
pub fn has_file_keys(header: &Header) -> bool {
    header
        .names
        .iter()
        .any(|n| n.destination.starts_with("file:"))
}

/// What `opv unseal` prints: the verified header and what was checked. Value-free.
struct Report<'a> {
    header: &'a Header,
    signer: &'a str,
    recipient: Option<&'a str>,
    decrypted: bool,
    runtime: RuntimeDir,
}

impl Report<'_> {
    /// The `opv.unseal/1` document (design §4.2), without `overridden`, which only
    /// `--exec` has.
    fn json(&self) -> serde_json::Value {
        let h = self.header;
        json!({
            "schema": "opv.unseal/1",
            "bundle": {
                "format": h.format,
                "project": h.project,
                "environment": h.environment,
                "product": h.product,
                "target": h.target,
                "revision": h.revision,
                "created_at": h.created_at,
                "opv_version": h.opv_version,
                "plan_id": h.plan_id,
                "contract_digest": h.contract_digest,
                "signer": self.signer,
                "recipient": self.recipient,
            },
            "names": h.names.iter().map(|n| json!({
                "name": n.name,
                "destination": n.destination,
            })).collect::<Vec<_>>(),
            "checked": {
                "signature": true,
                "recipient": self.recipient.is_some(),
                "payload": self.decrypted,
                "runtime_dir": self.runtime.word(),
            },
        })
    }

    fn text(&self, out: &mut dyn Write) -> std::io::Result<()> {
        let h = self.header;
        writeln!(
            out,
            "verified {}/{} revision {} (project {}, target {})",
            h.environment, h.product, h.revision, h.project, h.target
        )?;
        writeln!(out, "  signer      {}", self.signer)?;
        match self.recipient {
            Some(r) => writeln!(out, "  recipient   {r} (this identity)")?,
            None => writeln!(out, "  recipient   not checked (no identity given)")?,
        }
        writeln!(
            out,
            "  sealed      {} by opv {}, plan {}",
            h.created_at, h.opv_version, h.plan_id
        )?;
        writeln!(out, "  contract    {}", h.contract_digest)?;
        writeln!(
            out,
            "  payload     {}",
            if self.decrypted {
                "decrypted in memory; matches the signed header"
            } else {
                "not decrypted (--verify-only)"
            }
        )?;
        let runtime = match self.runtime {
            RuntimeDir::RamBacked => Some("RAM-backed, ready for the file keys"),
            RuntimeDir::NotNeeded => Some("not needed (no file keys)"),
            RuntimeDir::NotChecked => None,
        };
        if let Some(r) = runtime {
            writeln!(out, "  runtime dir {r}")?;
        }
        let width = h.names.iter().map(|n| n.name.len()).max().unwrap_or(0);
        writeln!(out, "names ({}):", h.names.len())?;
        for n in &h.names {
            writeln!(out, "  {:width$}  {}", n.name, n.destination)?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "unseal_tests.rs"]
mod unseal_tests;
