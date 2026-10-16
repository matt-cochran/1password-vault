//! `opv vault locate <vault ID> [--json]` (#153): which of the 1Password accounts this CLI
//! knows holds a vault. For each account, one `op vault get <id> --account <account ID>`
//! (exit status only: its output names the vault and is dropped unread); an account whose
//! check fails is asked whether it is signed in at all, so "not here" is never claimed for
//! an account that could not be asked. Names and IDs only; never a value. Read-only: it
//! never prompts or signs in.

use std::io::Write;

use serde::Serialize;
use serde_json::json;

use super::write_err;
use crate::adapters::onepassword_manifest::{self as manifest, Account, Discovery};
use crate::error::{Code, Error};
use crate::runner::{Call, CommandRunner, PROBE_TIMEOUT};

/// What one account says about the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Row {
    pub account_id: String,
    pub shorthand: Option<String>,
    pub sign_in: String,
    /// `found`, `not_found` (signed in, not there) or `unknown` (not signed in, or the
    /// check could not run).
    pub result: &'static str,
}

fn row(a: &Account, result: &'static str) -> Row {
    Row {
        account_id: a.account_uuid.clone(),
        shorthand: Some(a.shorthand.clone()).filter(|s| !s.is_empty()),
        sign_in: a
            .url
            .trim_start_matches("https://")
            .trim_end_matches('/')
            .to_string(),
        result,
    }
}

/// Ask each account in turn whether it holds `vault`.
pub fn rows(r: &dyn CommandRunner, accounts: &[Account], vault: &str) -> Vec<Row> {
    accounts
        .iter()
        .map(|a| {
            let args = [
                "vault",
                "get",
                vault,
                "--account",
                a.account_uuid.as_str(),
                "--format",
                "json",
            ];
            let call = Call::new("op", &args);
            match r.probe(&call, PROBE_TIMEOUT) {
                Ok(o) if o.status == 0 => row(a, "found"),
                Ok(_) => {
                    let _ = crate::runner::take_failure_excerpt();
                    match manifest::signed_in(r, &a.account_uuid) {
                        Some(true) => row(a, "not_found"),
                        _ => row(a, "unknown"),
                    }
                }
                Err(_) => row(a, "unknown"),
            }
        })
        .collect()
}

/// `opv vault locate <vault>`.
pub fn run(
    r: &dyn CommandRunner,
    vault: &str,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), Error> {
    if !crate::config::is_id(vault) {
        return Err(Error::Config(format!("{vault:?} is not a vault ID").into())
            .with_code(Code::Usage)
            .with_next("opv vault locate --help"));
    }
    let accounts = match manifest::discover(r) {
        Discovery::Listed(a) => a,
        Discovery::OpMissing => {
            return Err(crate::adapters::onepassword::op_missing(
                &crate::host::Host::detect(),
            ));
        }
        Discovery::Unavailable => {
            return Err(Error::Source(
                "op account list failed, so opv cannot tell which accounts to ask".into(),
            )
            .with_next("opv doctor"));
        }
    };
    let rows = rows(r, &accounts, vault);
    let found: Vec<&Row> = rows.iter().filter(|r| r.result == "found").collect();
    let unknown: Vec<&Row> = rows.iter().filter(|r| r.result == "unknown").collect();
    if json {
        let doc = json!({
            "schema_version": crate::json::SCHEMA_VERSION,
            "vault_id": vault,
            "accounts": rows,
            "complete": unknown.is_empty(),
        });
        writeln!(out, "{doc}").map_err(write_err)?;
    } else {
        for row in &rows {
            let name = row.shorthand.as_deref().unwrap_or("-");
            writeln!(
                out,
                "{} ({name}, {}): {}",
                row.account_id,
                row.sign_in,
                row.result.replace('_', " ")
            )
            .map_err(write_err)?;
        }
    }
    if let Some(hit) = found.first() {
        if !json {
            writeln!(
                out,
                "vault {vault} is in account {}; select that account for the project \
                 (opv account use {}) or fix the vault_id in the configuration",
                hit.account_id, hit.account_id
            )
            .map_err(write_err)?;
        }
        return Ok(());
    }
    if let Some(first) = unknown.first() {
        return Err(Error::Source(
            format!(
                "vault {vault} is not in any signed-in account; {} account(s) could not be \
                 asked because they are not signed in",
                unknown.len()
            )
            .into(),
        )
        .with_code(Code::InventoryIncomplete)
        .with_do("sign in to that account for this check only (your project's .opv is not changed)")
        .with_next(format!(
            "opv login --account {} --no-record -- opv vault locate {vault}",
            first.account_id
        )));
    }
    Err(Error::Source(
        format!(
            "vault {vault} is in none of the {} accounts this 1Password CLI knows; it may \
             have been deleted, or be in an account not added here",
            rows.len()
        )
        .into(),
    )
    .with_code(Code::VaultNoAccess)
    .with_do("check the vault ID in the configuration, or add the account that holds it")
    .with_next("opv login --add"))
}

#[cfg(test)]
#[path = "vault_locate_tests.rs"]
mod tests;
