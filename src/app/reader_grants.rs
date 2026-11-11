//! Immutable native issuance proof for a read-only CI reader (#304).
//!
//! The receipt is authority only when its bytes are approved through protected source
//! and their digest is pinned independently of untrusted job inputs. A digest is not a
//! signature. Provider access availability and delivery are separate from this proof.
use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cause::{Cause, EnvName, LocalOp, UsageProblem};
use crate::domain::{Fleet, SecretValue};
use crate::error::Error;
use crate::runner::{Call, CommandRunner, Outcome};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const LIFETIME: u64 = 90 * 24 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultGrant {
    pub vault_id: String,
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    pub environment: String,
    pub role: String,
    pub account_id: String,
    pub vaults: Vec<VaultGrant>,
    pub can_create_vaults: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub receipt_schema: u32,
    pub revision: u32,
    pub proof: String,
    pub service_account_id: String,
    pub contract: Contract,
    pub contract_sha256: String,
    pub issued_at: u64,
    /// Evidence validity limit, not independently observed native token expiry.
    pub not_after: u64,
}

#[derive(Deserialize)]
struct NativeIdentity {
    user_uuid: String,
    account_uuid: String,
    user_type: String,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn id(s: &str) -> bool {
    s.len() == 26 && s.bytes().all(|c| c.is_ascii_alphanumeric())
}

pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn contract_digest(c: &Contract) -> String {
    digest(&serde_json::to_vec(c).expect("public contract serializes"))
}

pub fn refusal(env: &str, reason: &str) -> Error {
    Cause::ReaderGrantsUnverified {
        env: EnvName::new(env),
        reason: reason.into(),
    }
    .into()
}

pub fn contract(fleet: &Fleet, env: &str) -> Result<Contract, Error> {
    let account = fleet
        .environment(env)?
        .account
        .as_deref()
        .filter(|a| id(a))
        .ok_or_else(|| refusal(env, "immutable_account_id_required"))?;
    let vaults: BTreeSet<_> = fleet
        .bound_boundaries(env)?
        .into_iter()
        .map(|(_, b)| b.vault_id.clone())
        .collect();
    if vaults.is_empty() || vaults.iter().any(|v| !id(v)) {
        return Err(refusal(env, "immutable_vault_ids_required"));
    }
    Ok(Contract {
        environment: env.into(),
        role: "ci_reader".into(),
        account_id: account.into(),
        can_create_vaults: false,
        vaults: vaults
            .into_iter()
            .map(|vault_id| VaultGrant {
                vault_id,
                permissions: vec!["read_items".into()],
            })
            .collect(),
    })
}

/// Public metadata only, issued under exactly this token. Unknown fields are discarded;
/// neither raw native JSON nor raw stderr is ever emitted by this interface.
fn metadata(
    r: &dyn CommandRunner,
    token: &SecretValue,
    args: &[&str],
) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    let env = [("OP_SERVICE_ACCOUNT_TOKEN", token.expose())];
    match r.read(
        &Call {
            env: &env,
            ..Call::new("op", args)
        },
        &[],
    ) {
        Ok(Outcome::Done(o)) if o.status == 0 => Some(o.stdout),
        _ => None,
    }
}

fn identity(r: &dyn CommandRunner, token: &SecretValue) -> Option<NativeIdentity> {
    let raw = metadata(r, token, &["whoami", "--format", "json"])?;
    let native: NativeIdentity = serde_json::from_slice(&raw).ok()?;
    (native.user_type == "SERVICE_ACCOUNT" && id(&native.user_uuid) && id(&native.account_uuid))
        .then_some(native)
}

/// Check actual native vault UUIDs before issuing a public receipt. A mutable name
/// shaped like an ID is insufficient; malformed or duplicate metadata fails closed.
fn issuance_vaults(r: &dyn CommandRunner, token: &SecretValue) -> Option<BTreeSet<String>> {
    #[derive(Deserialize)]
    struct Vault {
        id: String,
    }
    let raw = metadata(r, token, &["vault", "list", "--format", "json"])?;
    let vaults: Vec<Vault> = serde_json::from_slice(&raw).ok()?;
    let actual: BTreeSet<_> = vaults.iter().map(|v| v.id.clone()).collect();
    (actual.len() == vaults.len() && actual.iter().all(|v| id(v))).then_some(actual)
}

pub fn issued(c: &Contract, token: &SecretValue, r: &dyn CommandRunner) -> Result<Receipt, Error> {
    let native = identity(r, token)
        .ok_or_else(|| refusal(&c.environment, "native_service_identity_unverified"))?;
    if native.account_uuid != c.account_id {
        return Err(refusal(&c.environment, "native_account_mismatch"));
    }
    let actual = issuance_vaults(r, token)
        .ok_or_else(|| refusal(&c.environment, "native_issuance_access_unverified"))?;
    let expected: BTreeSet<_> = c.vaults.iter().map(|v| v.vault_id.clone()).collect();
    if actual != expected {
        return Err(refusal(&c.environment, "native_create_vault_set_mismatch"));
    }
    let issued_at = now();
    Ok(Receipt {
        receipt_schema: 1,
        revision: 1,
        proof: "native_immutable_issuance".into(),
        service_account_id: native.user_uuid,
        contract: c.clone(),
        contract_sha256: contract_digest(c),
        issued_at,
        not_after: issued_at + LIFETIME,
    })
}

fn io_error(op: LocalOp, path: &Path, e: std::io::Error) -> Error {
    Cause::LocalIo {
        op,
        path: path.into(),
        io: e.kind().into(),
        delivery: None,
    }
    .into()
}

/// No overwrites: replacing an identity requires a new reviewed receipt path.
pub fn preflight_destination(path: &Path) -> Result<(), Error> {
    if path.exists()
        || !path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .is_dir()
    {
        return Err(Cause::Usage {
            problem: UsageProblem::ValueFormat {
                flag: "--grant-receipt".into(),
                format: "a new file in an existing directory",
            },
        }
        .into());
    }
    Ok(())
}

pub fn save(path: &Path, receipt: &Receipt) -> Result<String, Error> {
    let bytes = serde_json::to_vec_pretty(receipt).expect("public receipt serializes");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| io_error(LocalOp::Write, path, e))?;
    file.write_all(&bytes)
        .map_err(|e| io_error(LocalOp::Write, path, e))?;
    Ok(digest(&bytes))
}

fn validate(
    expected: &Contract,
    bytes: &[u8],
    trusted_digest: &str,
    at: u64,
) -> Result<Receipt, &'static str> {
    if trusted_digest.len() != 64 || digest(bytes) != trusted_digest {
        return Err("untrusted_or_tampered_receipt");
    }
    let receipt: Receipt = serde_json::from_slice(bytes).map_err(|_| "receipt_invalid")?;
    if receipt.receipt_schema != 1
        || receipt.revision != 1
        || receipt.proof != "native_immutable_issuance"
    {
        return Err("receipt_not_supported");
    }
    if receipt.contract != *expected || receipt.contract_sha256 != contract_digest(expected) {
        return Err("contract_mismatch");
    }
    if !id(&receipt.service_account_id) {
        return Err("immutable_identity_required");
    }
    if receipt.issued_at > at
        || receipt.not_after <= at
        || receipt.not_after <= receipt.issued_at
        || receipt.not_after - receipt.issued_at > LIFETIME
    {
        return Err("receipt_stale_or_future");
    }
    Ok(receipt)
}

#[allow(clippy::too_many_arguments)] // Mirrors the CLI boundary; no ambient credential selection.
pub fn verify(
    fleet: &Fleet,
    env: &str,
    path: &Path,
    trusted_digest: &str,
    token: &SecretValue,
    r: &dyn CommandRunner,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), Error> {
    verify_at(fleet, env, path, trusted_digest, token, r, json, out, now())
}

#[allow(clippy::too_many_arguments)] // Private clock seam for deterministic wire qualification.
fn verify_at(
    fleet: &Fleet,
    env: &str,
    path: &Path,
    trusted_digest: &str,
    token: &SecretValue,
    r: &dyn CommandRunner,
    json: bool,
    out: &mut dyn Write,
    checked_at: u64,
) -> Result<(), Error> {
    let expected = contract(fleet, env)?;
    let bytes = std::fs::read(path).map_err(|e| io_error(LocalOp::Read, path, e))?;
    let result = (|| {
        let receipt = validate(&expected, &bytes, trusted_digest, checked_at)?;
        let native = identity(r, token).ok_or("native_identity_unverified")?;
        if native.user_uuid != receipt.service_account_id
            || native.account_uuid != expected.account_id
        {
            return Err("native_identity_mismatch");
        }
        #[derive(Deserialize)]
        struct Vault {
            id: String,
        }
        let raw = metadata(r, token, &["vault", "list", "--format", "json"])
            .ok_or("native_access_incomplete")?;
        let vaults: Vec<Vault> =
            serde_json::from_slice(&raw).map_err(|_| "native_access_incomplete")?;
        let actual: BTreeSet<_> = vaults.iter().map(|v| v.id.as_str()).collect();
        let wanted: BTreeSet<_> = expected
            .vaults
            .iter()
            .map(|v| v.vault_id.as_str())
            .collect();
        if actual != wanted || actual.len() != vaults.len() {
            return Err("native_vault_set_mismatch");
        }
        Ok(receipt)
    })();
    let reason = result.as_ref().err().copied();
    let report = serde_json::json!({
        "reader_grants": {
            "status": if result.is_ok() { "verified" } else { "not_verified" },
            "proof": "native_immutable_issuance", "finding": reason,
            "retrospective_effective_grants": "not_supported",
            "current_read_access": if result.is_ok() { "verified" } else { "not_verified" },
            "credential_expiry": "not_verified", "delivery": "not_verified",
            "receipt_sha256": result.as_ref().ok().map(|_| digest(&bytes)), "contract": expected,
            "contract_sha256": contract_digest(&expected),
            "service_account_id": result.as_ref().ok().map(|r| &r.service_account_id),
            "issued_at": result.as_ref().ok().map(|r| r.issued_at),
            "not_after": result.as_ref().ok().map(|r| r.not_after),
            "checked_at": checked_at
        }
    });
    if json {
        writeln!(out, "{report}")
    } else {
        writeln!(
            out,
            "reader grants: {} ({})",
            if result.is_ok() {
                "verified immutable issuance"
            } else {
                "not verified"
            },
            reason.unwrap_or("native_identity_and_read_access")
        )
    }
    .map_err(super::write_err)?;
    result.map(|_| ()).map_err(|reason| refusal(env, reason))
}

#[cfg(test)]
#[path = "reader_grants_tests.rs"]
mod tests;
