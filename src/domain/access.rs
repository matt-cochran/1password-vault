//! Who can read each environment's 1Password vault (#96): the CI-reader view of the
//! readiness receipt (FR-52, a least-privilege CI reader).
//!
//! Pure: [`analyse`] takes the JSON of `op vault user list <vault> --format json` exactly
//! as the caller read it, and [`findings`] turns the result into advisory findings. [`analyse`]
//! carries the names of the vault's writers, as the reply reports them (design row
//! `access-writers`); counts and findings never carry a person's name or email, only
//! service-account names are named.
//!
//! 1Password's `op vault user list` reports the `type` and `state` strings used here. The
//! `SERVICE_ACCOUNT` type string is from 1Password's documentation and has not yet been
//! confirmed against a live account.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

use crate::cause::Cmd;
use crate::cause::render::cmd_text;

/// A service account that can read an environment's vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Reader {
    pub name: String,
    pub read_only: bool,
}

/// What opv can see about who reads one environment's vault. Counts only for people and
/// guests; a person's name is kept only in [`writers`](Self::writers), never an email.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnvAccess {
    pub environment: String,
    pub vault_id: String,
    pub deployed: bool,
    /// The environment is a deployed tier (shared or production), so the vault needs a
    /// second writer (row `access-writers`). Separate from `deployed`, which gates the CI
    /// reader finding.
    pub deployed_tier: bool,
    pub visible: bool,
    pub people: usize,
    pub guests: usize,
    pub service_accounts: Vec<Reader>,
    /// Who can write the vault, as the reply reports them (`allow_editing`), in reply order;
    /// empty when the vault is not visible.
    pub writers: Vec<String>,
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
/// Part V, row `access-writers`: a deployed-tier vault with exactly one writer, so losing
/// that one writer's access leaves nobody to fix the tier's values.
pub const SINGLE_WRITER: &str = "single_writer";

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
        deployed_tier: false,
        visible: false,
        people: 0,
        guests: 0,
        service_accounts: Vec::new(),
        writers: Vec::new(),
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
        if user
            .get("permissions")
            .and_then(Value::as_array)
            .is_some_and(|granted| granted.iter().any(|p| p.as_str() == Some("allow_editing")))
        {
            access.writers.push(named(user));
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
    let name = named(user);
    let permissions = user.get("permissions").and_then(Value::as_array);
    let allows = |wanted: &str| {
        permissions.is_some_and(|granted| granted.iter().any(|p| p.as_str() == Some(wanted)))
    };
    Reader {
        name,
        read_only: allows("allow_viewing") && !allows("allow_editing") && !allows("allow_managing"),
    }
}

/// The entry's name, or a placeholder when 1Password reports none.
fn named(user: &serde_json::Map<String, Value>) -> String {
    user.get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .unwrap_or("(unnamed)")
        .to_string()
}

/// Findings for the analysed vaults, in input order, then by code order: access_not_visible,
/// no_ci_reader, single_writer, ci_reader_can_write, pending_revoke. Each names the vault
/// and the environment that needs it (07.10); a step is a typed opv command.
pub fn findings(envs: &[EnvAccess]) -> Vec<AccessFinding> {
    let mut out = Vec::new();
    for access in envs {
        let env = access.environment.as_str();
        let vault = format!("vault {} (environment {env})", access.vault_id);
        if !access.visible {
            // 07.36: what the person does is a Do for someone else, so there is no command.
            out.push(AccessFinding {
                code: ACCESS_NOT_VISIBLE,
                environment: env.to_string(),
                message: format!(
                    "cannot see who can read {vault}: viewing its access list needs the Manage \
                     permission on it, so ask a manager of the vault to run opv access {env}"
                ),
                next: None,
            });
            continue;
        }
        if access.deployed && !access.service_accounts.iter().any(|s| s.read_only) {
            out.push(AccessFinding {
                code: NO_CI_READER,
                environment: env.to_string(),
                message: format!("{env} deploys but has no read-only service account for CI"),
                // The token goes straight into the CI secret, never shown (0.9.0).
                next: Some(format!("opv access {env} --create --github <owner/repo>")),
            });
        }
        // Correction 17: a deployed-tier vault needs a second writer to fix a value when
        // the first is unavailable. `next` is none: only 1Password can add a writer.
        if access.deployed_tier && access.writers.len() == 1 {
            out.push(AccessFinding {
                code: SINGLE_WRITER,
                environment: env.to_string(),
                message: format!(
                    "{vault} has only one writer; a deployed tier needs a second writer to fix \
                     a value when the first is unavailable"
                ),
                next: None,
            });
        }
        for account in &access.service_accounts {
            if account.read_only {
                continue;
            }
            // 07.35: any writing service account, not only a CI reader, can be the one seen.
            out.push(AccessFinding {
                code: CI_READER_CAN_WRITE,
                environment: env.to_string(),
                message: format!(
                    "service account {} can write to boundary {vault}; opv's readers need read \
                     only. If {} is this project's CI reader, recreate it read-only (the Owner \
                     runs: line below)",
                    account.name, account.name
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
                environment: env.to_string(),
                message: format!(
                    "{n} service accounts named {name} can read {vault}: keep the newest until \
                     its token has produced verified delivery evidence, then remove the older \
                     ones in 1Password (Developer > Service accounts)"
                ),
                // 07.10: the environment, never the vault ID.
                next: Some(cmd_text(&Cmd {
                    command: vec!["delivery".into(), "verify".into()],
                    args: vec![env.to_string()],
                })),
            });
        }
    }
    out
}

#[cfg(test)]
#[path = "access_tests.rs"]
mod tests;
