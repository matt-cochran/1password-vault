//! The CI reader's grant receipt and its verification (#304, FR-70;
//! docs/design/ci-reader-grants.md).
//!
//! Pure: no I/O, no subprocess and no clock. A receipt records, at issuance, which service
//! account opv created, in which account, with which vault grants, and a digest of the grant
//! table opv computed then. [`evaluate`] compares it with the token's own view (its identity
//! and its vault list, parsed by [`parse_whoami`] and [`parse_vault_list`]) and with the grants
//! the contract requires now, and reports seven checks. An unknown or incomplete answer is
//! never [`Outcome::Verified`].
//!
//! Names, ids, dates and a digest only: nothing here carries a secret value (SR-1).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::domain::Date;
use crate::domain::access_plan::{Grant, Permission};

/// The receipt schema this module reads and writes.
pub const SCHEMA: &str = "opv.grant-receipt/1";

/// The identity type a CI reader's token must report.
pub const SERVICE_ACCOUNT: &str = "SERVICE_ACCOUNT";

/// The permission name 1Password grants for reading items.
const READ_ITEMS: &str = "read_items";

/// The 1Password permission names opv asks for when it issues `permission`, in the order it
/// writes them in the grant command.
pub fn permission_names(permission: Permission) -> &'static [&'static str] {
    match permission {
        Permission::Read => &[READ_ITEMS],
        Permission::ReadWrite => &[READ_ITEMS, "write_items"],
    }
}

/// Which owner command issued the receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IssuedBy {
    #[serde(rename = "access --create")]
    Create,
    #[serde(rename = "access --rotate")]
    Rotate,
}

/// One vault grant as issued: the vault id and the permission names asked for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptVault {
    pub id: String,
    pub permissions: Vec<String>,
}

/// The issuance receipt of one CI reader, stored in the value-free bindings file at
/// `environments.<env>.ci_reader.receipt` (or a target's `ci_identity.receipt`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantReceipt {
    pub schema: String,
    pub account_id: String,
    pub service_account_user_id: String,
    pub service_account_name: String,
    pub vaults: Vec<ReceiptVault>,
    /// `YYYY-MM-DDTHH:MM:SSZ`, as the issuing run recorded it.
    pub issued_at: String,
    pub issued_by: IssuedBy,
    /// `YYYY-MM-DD`.
    pub expires_on: String,
    /// [`contract_grants`] of the grant table opv computed at issuance.
    pub contract_grants: String,
}

impl GrantReceipt {
    /// The receipt as a TOML table body (`schema = …` lines, `vaults` as an array of inline
    /// tables), for the bindings file's `…receipt` table.
    pub fn to_toml(&self) -> String {
        let mut table = toml_edit::Table::new();
        let mut put = |key: &str, value: &str| {
            table.insert(key, toml_edit::value(value));
        };
        put("schema", &self.schema);
        put("account_id", &self.account_id);
        put("service_account_user_id", &self.service_account_user_id);
        put("service_account_name", &self.service_account_name);
        let mut vaults = toml_edit::Array::new();
        for vault in &self.vaults {
            let mut inline = toml_edit::InlineTable::new();
            inline.insert("id", vault.id.as_str().into());
            let permissions: toml_edit::Array =
                vault.permissions.iter().map(String::as_str).collect();
            inline.insert("permissions", permissions.into());
            vaults.push(inline);
        }
        table.insert("vaults", toml_edit::value(vaults));
        table.insert("issued_at", toml_edit::value(self.issued_at.as_str()));
        let issued_by = match self.issued_by {
            IssuedBy::Create => "access --create",
            IssuedBy::Rotate => "access --rotate",
        };
        table.insert("issued_by", toml_edit::value(issued_by));
        table.insert("expires_on", toml_edit::value(self.expires_on.as_str()));
        table.insert(
            "contract_grants",
            toml_edit::value(self.contract_grants.as_str()),
        );
        table.to_string()
    }

    /// Parse a receipt table body. A text that is not a well-formed receipt is
    /// [`Reason::ReceiptInvalid`]; no parser message (which could echo the text) is kept.
    pub fn from_toml(text: &str) -> Result<GrantReceipt, Reason> {
        let receipt: GrantReceipt = toml::from_str(text).map_err(|_| Reason::ReceiptInvalid)?;
        receipt.validate()?;
        Ok(receipt)
    }

    /// `Ok` when the receipt is of [`SCHEMA`], names an identity, has a valid expiry date and
    /// a `sha256:` digest; otherwise [`Reason::ReceiptInvalid`].
    pub fn validate(&self) -> Result<(), Reason> {
        let digest_ok = self
            .contract_grants
            .strip_prefix("sha256:")
            .is_some_and(|hex| {
                hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            });
        let ok = self.schema == SCHEMA
            && !self.account_id.is_empty()
            && !self.service_account_user_id.is_empty()
            && self.vaults.iter().all(|v| !v.id.is_empty())
            && self.expires_on.parse::<Date>().is_ok()
            && digest_ok;
        if ok {
            Ok(())
        } else {
            Err(Reason::ReceiptInvalid)
        }
    }
}

/// The required grant table: each vault id with the union of the permission names its grants
/// ask for. Sorted by vault id, names sorted.
fn grant_table(grants: &[Grant]) -> BTreeMap<&str, BTreeSet<&'static str>> {
    let mut table: BTreeMap<&str, BTreeSet<&'static str>> = BTreeMap::new();
    for grant in grants {
        table
            .entry(grant.vault_id.as_str())
            .or_default()
            .extend(permission_names(grant.permission));
    }
    table
}

/// The canonical digest of a computed grant table: `sha256:<lowercase hex>` over one line
/// per vault, sorted by vault id, `<vault id>\t<permission names sorted, comma-joined>\n`.
/// Independent of grant order; not a hash of any secret.
pub fn contract_grants(grants: &[Grant]) -> String {
    let mut canonical = String::new();
    for (vault, names) in grant_table(grants) {
        canonical.push_str(vault);
        canonical.push('\t');
        canonical.push_str(&names.into_iter().collect::<Vec<_>>().join(","));
        canonical.push('\n');
    }
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(canonical.as_bytes()))
    )
}

/// A provider read: its parsed data, or [`Incomplete`](Self::Incomplete) when the read
/// failed or its reply lacked something the check needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderRead<T> {
    Complete(T),
    Incomplete,
}

/// The token's own identity, as its identity reply reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub user_id: String,
    pub account_id: String,
    pub user_type: String,
}

/// What the token itself showed: its identity and the ids of the vaults it can open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observations {
    pub identity: ProviderRead<Identity>,
    pub vaults: ProviderRead<BTreeSet<String>>,
}

/// The identity reply's JSON (`user_uuid`, `account_uuid`, `user_type`). A reply that is not
/// an object or lacks any of the three as a non-empty string is incomplete.
pub fn parse_whoami(stdout: &str) -> ProviderRead<Identity> {
    let Ok(Value::Object(reply)) = serde_json::from_str::<Value>(stdout) else {
        return ProviderRead::Incomplete;
    };
    let field = |name: &str| {
        reply
            .get(name)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    match (
        field("user_uuid"),
        field("account_uuid"),
        field("user_type"),
    ) {
        (Some(user_id), Some(account_id), Some(user_type)) => ProviderRead::Complete(Identity {
            user_id,
            account_id,
            user_type,
        }),
        _ => ProviderRead::Incomplete,
    }
}

/// The vault list reply's JSON: an array of objects, each with a non-empty string `id`. Any
/// entry without one makes the whole list incomplete (a partial list must not pass).
pub fn parse_vault_list(stdout: &str) -> ProviderRead<BTreeSet<String>> {
    let Ok(Value::Array(entries)) = serde_json::from_str::<Value>(stdout) else {
        return ProviderRead::Incomplete;
    };
    let ids: Option<BTreeSet<String>> = entries
        .iter()
        .map(|entry| {
            entry
                .get("id")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        })
        .collect();
    ids.map_or(ProviderRead::Incomplete, ProviderRead::Complete)
}

/// Why a check is not verified. The serialised names are the design's fixed reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    ReceiptMissing,
    ReceiptInvalid,
    NotAServiceAccount,
    WrongAccount,
    IdentityMismatch,
    ProviderReadIncomplete,
    ExtraVault,
    MissingVault,
    ContractChanged,
    WritePermission,
    PermissionMismatch,
    Expired,
}

/// One check's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "state", content = "reason", rename_all = "snake_case")]
pub enum Outcome {
    Verified,
    NotVerified(Reason),
    NotSupported,
}

/// The seven checks of `opv access --verify`, in the design's order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Report {
    pub receipt: Outcome,
    pub identity: Outcome,
    pub vault_set: Outcome,
    pub contract: Outcome,
    pub permissions_issued: Outcome,
    /// Always [`Outcome::NotSupported`]: 1Password shows no permission level for a service
    /// account after issuance (spike #304 Q2, Q3).
    pub permissions_live: Outcome,
    pub freshness: Outcome,
}

impl Report {
    /// Every check `not_supported`: a project whose configuration has no bindings file to
    /// hold a receipt.
    pub fn not_supported() -> Report {
        Report {
            receipt: Outcome::NotSupported,
            identity: Outcome::NotSupported,
            vault_set: Outcome::NotSupported,
            contract: Outcome::NotSupported,
            permissions_issued: Outcome::NotSupported,
            permissions_live: Outcome::NotSupported,
            freshness: Outcome::NotSupported,
        }
    }

    /// The checks by name, in the design's order.
    pub fn checks(&self) -> [(&'static str, Outcome); 7] {
        [
            ("receipt", self.receipt),
            ("identity", self.identity),
            ("vault_set", self.vault_set),
            ("contract", self.contract),
            ("permissions_issued", self.permissions_issued),
            ("permissions_live", self.permissions_live),
            ("freshness", self.freshness),
        ]
    }

    /// True when every check except `permissions_live` is verified.
    pub fn passes(&self) -> bool {
        self.checks()
            .iter()
            .filter(|(name, _)| *name != "permissions_live")
            .all(|(_, outcome)| *outcome == Outcome::Verified)
    }
}

/// Evaluate the seven checks for one CI reader. `receipt` is the committed receipt (None when
/// absent), `required` the grants the contract requires now for this reader, `observed` the
/// token's own view, `today` the caller's `YYYY-MM-DD` (an unreadable `today` never shows a
/// receipt fresh).
pub fn evaluate(
    receipt: Option<&GrantReceipt>,
    required: &[Grant],
    observed: &Observations,
    today: &str,
) -> Report {
    let receipt = match receipt {
        None => Err(Reason::ReceiptMissing),
        Some(r) => r.validate().map(|()| r),
    };
    Report {
        receipt: match receipt {
            Ok(_) => Outcome::Verified,
            Err(reason) => Outcome::NotVerified(reason),
        },
        identity: identity(receipt, &observed.identity),
        vault_set: vault_set(receipt, required, &observed.vaults),
        contract: outcome(receipt.and_then(|r| {
            if r.contract_grants == contract_grants(required) {
                Ok(())
            } else {
                Err(Reason::ContractChanged)
            }
        })),
        permissions_issued: outcome(receipt.and_then(|r| permissions_issued(r, required))),
        permissions_live: Outcome::NotSupported,
        freshness: outcome(receipt.and_then(|r| freshness(r, today))),
    }
}

fn outcome(result: Result<(), Reason>) -> Outcome {
    match result {
        Ok(()) => Outcome::Verified,
        Err(reason) => Outcome::NotVerified(reason),
    }
}

/// The token's type first (it needs no receipt), then the receipt's account and user ids.
fn identity(receipt: Result<&GrantReceipt, Reason>, seen: &ProviderRead<Identity>) -> Outcome {
    let ProviderRead::Complete(seen) = seen else {
        return Outcome::NotVerified(Reason::ProviderReadIncomplete);
    };
    if seen.user_type != SERVICE_ACCOUNT {
        return Outcome::NotVerified(Reason::NotAServiceAccount);
    }
    outcome(receipt.and_then(|r| {
        if seen.account_id != r.account_id {
            Err(Reason::WrongAccount)
        } else if seen.user_id != r.service_account_user_id {
            Err(Reason::IdentityMismatch)
        } else {
            Ok(())
        }
    }))
}

/// The token's vaults against the contract's (needs no receipt), then against the receipt's.
/// An extra vault is reported before a missing one.
fn vault_set(
    receipt: Result<&GrantReceipt, Reason>,
    required: &[Grant],
    seen: &ProviderRead<BTreeSet<String>>,
) -> Outcome {
    let ProviderRead::Complete(seen) = seen else {
        return Outcome::NotVerified(Reason::ProviderReadIncomplete);
    };
    let seen: BTreeSet<&str> = seen.iter().map(String::as_str).collect();
    let compare = |expected: BTreeSet<&str>| {
        if !seen.is_subset(&expected) {
            Err(Reason::ExtraVault)
        } else if !expected.is_subset(&seen) {
            Err(Reason::MissingVault)
        } else {
            Ok(())
        }
    };
    let contract: BTreeSet<&str> = required.iter().map(|g| g.vault_id.as_str()).collect();
    outcome(compare(contract).and_then(|()| {
        let receipt = receipt?;
        compare(receipt.vaults.iter().map(|v| v.id.as_str()).collect())
    }))
}

/// A CI reader is read only: any issued name other than `read_items` is a write permission.
/// Otherwise each vault's issued names must equal the contract's.
fn permissions_issued(receipt: &GrantReceipt, required: &[Grant]) -> Result<(), Reason> {
    if receipt
        .vaults
        .iter()
        .flat_map(|v| &v.permissions)
        .any(|name| name != READ_ITEMS)
    {
        return Err(Reason::WritePermission);
    }
    let mut issued: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for vault in &receipt.vaults {
        issued
            .entry(vault.id.as_str())
            .or_default()
            .extend(vault.permissions.iter().map(String::as_str));
    }
    let wanted: BTreeMap<&str, BTreeSet<&str>> = grant_table(required)
        .into_iter()
        .map(|(vault, names)| (vault, names.into_iter().collect()))
        .collect();
    if issued == wanted {
        Ok(())
    } else {
        Err(Reason::PermissionMismatch)
    }
}

/// Fresh while `expires_on` is after `today`.
fn freshness(receipt: &GrantReceipt, today: &str) -> Result<(), Reason> {
    match (receipt.expires_on.parse::<Date>(), today.parse::<Date>()) {
        (Ok(expires), Ok(today)) if expires > today => Ok(()),
        _ => Err(Reason::Expired),
    }
}

#[cfg(test)]
#[path = "grant_receipt_tests.rs"]
mod tests;
