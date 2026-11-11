//! The value-free records of a CI identity `opv access --create` or `--rotate` just issued
//! (#296, #304, FR-70; docs/design/ci-reader-grants.md, Design steps 1–2), written beside
//! the contract in `secrets.bindings.toml`: the service account's expiry date, and its
//! grant receipt (who it is, in which account, which vaults with which permissions opv
//! asked for, and the digest of the grant table opv computed).
//!
//! The receipt's identity comes from `op whoami` run with the new token in that child's
//! environment only (never argv, SR-3), through the runner. A whoami that fails, is
//! incomplete or does not report a service account records no receipt and says why; the
//! token is already stored by then and is never undone. A project whose configuration lives
//! in a 1Password manifest has no bindings file, so nothing is recorded, and this says so.
//!
//! Names, ids, dates and a digest only: no token, value or session is recorded (SR-1).

use std::collections::BTreeMap;
use std::io::Write;

use super::write_err;
use crate::cause::{Cause, ConfigSource};
use crate::domain::access_plan::Grant;
use crate::domain::grant_receipt::{
    self, GrantReceipt, IssuedBy, ProviderRead, ReceiptVault, SERVICE_ACCOUNT,
};
use crate::domain::{Fleet, SecretValue};
use crate::error::Error;
use crate::runner::{Call, CommandRunner, Outcome};

/// What was just issued.
pub(crate) struct Issue<'a> {
    pub env: &'a str,
    /// The target whose CI identity it is; `None`: the environment's CI reader.
    pub target: Option<&'a str>,
    /// The service account's name, as created.
    pub service_account: &'a str,
    /// The grants opv computed and asked 1Password for.
    pub grants: &'a [Grant],
    pub issued_by: IssuedBy,
    /// The lifetime asked for (`--expires-in`), in days.
    pub validity_days: i64,
}

/// Why no receipt was recorded, as one fixed phrase (never op's reply, never a value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NoReceipt {
    WhoamiFailed,
    Incomplete,
    NotAServiceAccount,
}

impl NoReceipt {
    fn text(self) -> &'static str {
        match self {
            NoReceipt::WhoamiFailed => "op whoami under the new token failed",
            NoReceipt::Incomplete => "op whoami under the new token named no complete identity",
            NoReceipt::NotAServiceAccount => {
                "op whoami under the new token does not report a service account"
            }
        }
    }
}

/// The line said when the configuration lives in a 1Password manifest.
const MANIFEST_NOTE: &str = "no expiry or grant receipt recorded: this project's configuration \
                             lives in a 1Password manifest, which has no secrets.bindings.toml";

/// Record the expiry and the grant receipt of what was just issued, once its token has been
/// stored (and, for a rotation, verified). `token` is the new service account's token,
/// already registered with the run's scrubber; it reaches only `op whoami`'s environment.
pub(crate) fn record(
    fleet: &Fleet,
    r: &dyn CommandRunner,
    token: &SecretValue,
    issue: &Issue<'_>,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let path = match &fleet.read_from.0 {
        ConfigSource::File { path, .. } if path.is_file() => path,
        ConfigSource::Manifest { .. } => {
            return writeln!(out, "{MANIFEST_NOTE}").map_err(write_err);
        }
        // A fleet parsed from no file: nowhere to record.
        ConfigSource::File { .. } => return Ok(()),
    };
    // One clock reading for both records: the receipt's issue time and the expiry date.
    let issued_at = crate::domain::provenance::utc_now();
    let expires_on = issued_at
        .get(..10)
        .and_then(|today| crate::domain::credential::add_days(today, issue.validity_days))
        .ok_or_else(|| -> Error {
            Cause::Bug {
                site: "access_receipt::record: no expiry date",
            }
            .into()
        })?;
    let (expiry_key, receipt_key) = match issue.target {
        Some(t) => (
            crate::domain::credential::ci_identity_expires_path(issue.env, t),
            crate::domain::credential::ci_identity_receipt_path(issue.env, t),
        ),
        None => (
            crate::domain::credential::ci_reader_expires_path(issue.env),
            crate::domain::credential::ci_reader_receipt_path(issue.env),
        ),
    };
    super::target_credentials::record_expiry(path, &expiry_key, &expires_on)?;
    let identity = match whoami(r, token) {
        Ok(identity) => identity,
        Err(why) => {
            return writeln!(
                out,
                "no grant receipt recorded for {:?}: {}; its token is stored",
                issue.service_account,
                why.text()
            )
            .map_err(write_err);
        }
    };
    let receipt = GrantReceipt {
        schema: grant_receipt::SCHEMA.to_string(),
        account_id: identity.account_id,
        service_account_user_id: identity.user_id,
        service_account_name: issue.service_account.to_string(),
        vaults: vaults(issue.grants),
        issued_at,
        issued_by: issue.issued_by,
        expires_on,
        contract_grants: grant_receipt::contract_grants(issue.grants),
    };
    let mut bindings = crate::config::bindings::read_sibling(path)?;
    bindings.insert_receipt(receipt_key, &receipt);
    crate::config::bindings::write_sibling(path, &bindings)?;
    writeln!(
        out,
        "recorded the grant receipt of {:?} in {}",
        issue.service_account,
        crate::config::bindings::FILE
    )
    .map_err(write_err)
}

/// `op whoami` with `token` in the child's environment only (never argv, SR-3), parsed: the
/// service account's identity, or why it is not one.
fn whoami(
    r: &dyn CommandRunner,
    token: &SecretValue,
) -> Result<grant_receipt::Identity, NoReceipt> {
    let child_env = [("OP_SERVICE_ACCOUNT_TOKEN", token.expose())];
    let call = Call {
        env: &child_env,
        ..Call::new("op", &["whoami", "--format", "json"])
    };
    let stdout = match r.read(&call, &[]) {
        Ok(Outcome::Done(o)) => o.stdout,
        Ok(_) | Err(_) => {
            // The failure is reported by a fixed phrase; nothing waits for its observation.
            let _ = crate::runner::take_observed();
            return Err(NoReceipt::WhoamiFailed);
        }
    };
    match grant_receipt::parse_whoami(&String::from_utf8_lossy(&stdout)) {
        ProviderRead::Complete(identity) if identity.user_type == SERVICE_ACCOUNT => Ok(identity),
        ProviderRead::Complete(_) => Err(NoReceipt::NotAServiceAccount),
        ProviderRead::Incomplete => Err(NoReceipt::Incomplete),
    }
}

/// Each vault the grants name, sorted by id, with the permission names asked for it in the
/// order the create command writes them.
fn vaults(grants: &[Grant]) -> Vec<ReceiptVault> {
    let mut by_vault: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for grant in grants {
        let names = by_vault.entry(grant.vault_id.as_str()).or_default();
        for name in grant_receipt::permission_names(grant.permission) {
            if !names.iter().any(|n| n == name) {
                names.push((*name).to_string());
            }
        }
    }
    by_vault
        .into_iter()
        .map(|(id, permissions)| ReceiptVault {
            id: id.to_string(),
            permissions,
        })
        .collect()
}
