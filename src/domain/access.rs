//! Who can read each environment's 1Password vault (#96): the CI-reader view of the
//! readiness receipt (FR-52, a least-privilege CI reader).
//!
//! Pure: [`analyse`] takes the JSON of `op vault user list <vault> --format json` exactly
//! as the caller read it, and [`findings`] turns the result into advisory findings. Counts
//! and findings never carry a person's name or email; only service-account names are named.
//!
//! 1Password's `op vault user list` reports the `type` and `state` strings used here. The
//! `SERVICE_ACCOUNT` type string is from 1Password's documentation and has not yet been
//! confirmed against a live account.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

/// A service account that can read an environment's vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Reader {
    pub name: String,
    pub read_only: bool,
}

/// What opv can see about who reads one environment's vault. Counts only for people and
/// guests; no person's name or email is kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnvAccess {
    pub environment: String,
    pub vault_id: String,
    pub deployed: bool,
    pub visible: bool,
    pub people: usize,
    pub guests: usize,
    pub service_accounts: Vec<Reader>,
}

/// One advisory finding about an environment's vault access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccessFinding {
    pub code: &'static str,
    pub environment: String,
    pub message: String,
    pub next: Option<String>,
}

const ACCESS_NOT_VISIBLE: &str = "access_not_visible";
/// #153: a needed vault that `op vault get` cannot find in the selected account.
pub const VAULT_NOT_IN_ACCOUNT: &str = "vault_not_in_account";
const NO_CI_READER: &str = "no_ci_reader";
const CI_READER_CAN_WRITE: &str = "ci_reader_can_write";
/// 0.9.0: several service accounts with one name read a vault, as after `opv access
/// --create` made a replacement: the older one waits to be removed in 1Password.
pub const PENDING_REVOKE: &str = "pending_revoke";

/// `users`: Some(parsed JSON array) when the list could be read, None when it could not (not
/// visible to this person).
pub fn analyse(
    environment: &str,
    vault_id: &str,
    deployed: bool,
    users: Option<&Value>,
) -> EnvAccess {
    let mut access = EnvAccess {
        environment: environment.to_string(),
        vault_id: vault_id.to_string(),
        deployed,
        visible: false,
        people: 0,
        guests: 0,
        service_accounts: Vec::new(),
    };
    let users = match users {
        Some(Value::Array(users)) => users,
        _ => return access,
    };
    access.visible = true;
    for user in users {
        let Some(user) = user.as_object() else {
            continue;
        };
        if user.get("state").and_then(Value::as_str) != Some("ACTIVE") {
            continue;
        }
        match user.get("type").and_then(Value::as_str) {
            Some("MEMBER") => access.people += 1,
            Some("GUEST") => access.guests += 1,
            Some("SERVICE_ACCOUNT") => access.service_accounts.push(reader(user)),
            _ => {}
        }
    }
    access
}

/// One ACTIVE service-account entry: its name (or a placeholder) and whether it can only
/// read. Reading means `allow_viewing` without `allow_editing` or `allow_managing`.
fn reader(user: &serde_json::Map<String, Value>) -> Reader {
    let name = user
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .unwrap_or("(unnamed)")
        .to_string();
    let permissions = user.get("permissions").and_then(Value::as_array);
    let allows = |wanted: &str| {
        permissions.is_some_and(|granted| granted.iter().any(|p| p.as_str() == Some(wanted)))
    };
    Reader {
        name,
        read_only: allows("allow_viewing") && !allows("allow_editing") && !allows("allow_managing"),
    }
}

/// Findings for the analysed environments, in input order, then by code order:
/// access_not_visible, no_ci_reader, ci_reader_can_write, pending_revoke. `project` names
/// the suggested service account.
pub fn findings(project: &str, envs: &[EnvAccess]) -> Vec<AccessFinding> {
    let mut out = Vec::new();
    for access in envs {
        if !access.visible {
            out.push(AccessFinding {
                code: ACCESS_NOT_VISIBLE,
                environment: access.environment.clone(),
                message: format!(
                    "cannot see who can read the {} vault; managing the vault is needed to \
                     view its access list",
                    access.environment
                ),
                next: None,
            });
            continue;
        }
        if access.deployed && !access.service_accounts.iter().any(|s| s.read_only) {
            out.push(AccessFinding {
                code: NO_CI_READER,
                environment: access.environment.clone(),
                message: format!(
                    "{} deploys but has no read-only service account for CI",
                    access.environment
                ),
                // The token goes straight into the CI secret, never shown (0.9.0).
                next: Some(format!(
                    "opv access {} --create --github <owner/repo>",
                    access.environment
                )),
            });
        }
        for account in &access.service_accounts {
            if account.read_only {
                continue;
            }
            out.push(AccessFinding {
                code: CI_READER_CAN_WRITE,
                environment: access.environment.clone(),
                message: format!(
                    "the service account {} can write to the {} vault; CI only needs read \
                     access",
                    account.name, access.environment
                ),
                next: None,
            });
        }
        let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
        for account in &access.service_accounts {
            *seen.entry(account.name.as_str()).or_default() += 1;
        }
        for (name, n) in seen.into_iter().filter(|(_, n)| *n > 1) {
            out.push(AccessFinding {
                code: PENDING_REVOKE,
                environment: access.environment.clone(),
                message: format!(
                    "{n} service accounts named {name} can read the {} vault: keep the newest \
                     until its token has produced verified delivery evidence, then remove the \
                     older ones in 1Password (Developer > Service accounts)",
                    access.environment
                ),
                next: Some(format!("opv delivery verify {}", access.environment)),
            });
        }
    }
    out
}

#[cfg(test)]
#[path = "access_tests.rs"]
mod tests;
