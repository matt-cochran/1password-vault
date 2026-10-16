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
use crate::cause::{AccountId, Cause, UsageProblem};
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
        return Err(Cause::Usage {
            problem: UsageProblem::ValueFormat {
                flag: "VAULT_ID".into(),
                format: "a 1Password vault ID (26 letters and digits)",
            },
        }
        .into());
    }
    // Audit 04.13: a service account or Connect decides the account itself, and `op
    // account list` says nothing about it: ask the credential once.
    if crate::host::Host::detect().op_credential.is_some() {
        return with_credential(r, vault, json, out);
    }
    let accounts = match manifest::discover(r) {
        Discovery::Listed(a) => a,
        Discovery::OpMissing => {
            return Err(crate::adapters::onepassword::op_missing(
                &crate::host::Host::detect(),
            ));
        }
        Discovery::Unavailable => return Err(super::account::account_list_failed()),
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
    // Audit 04.29: an account that could not be asked (not signed in, or the check did not
    // finish) is unlisted, never "not signed in" by guess; the step signs in to it for this
    // check only.
    if !unknown.is_empty() {
        return Err(Cause::InventoryIncomplete {
            unlisted: unknown
                .iter()
                .map(|r| AccountId::new(r.account_id.clone()))
                .collect(),
        }
        .into());
    }
    // Audit 04.07: an account is added at op's prompt only where op keeps its own accounts.
    let (add, next) = if super::account::app_holds_accounts_here() {
        ("add that account in the 1Password app", "opv login")
    } else {
        ("add that account to op here", "opv login --add")
    };
    Err(Error::Source(
        format!(
            "vault {vault} is in none of the {} accounts this 1Password CLI knows; it may \
             have been deleted, or be in an account not added here",
            rows.len()
        )
        .into(),
    )
    .with_code(Code::VaultNoAccess)
    .with_do(format!(
        "check the vault ID in the configuration; if another account holds it, {add}"
    ))
    .with_next(next))
}

/// `opv vault locate` under a service account or Connect (audit 04.13): one `op vault get`
/// with the credential, which decides the account. Found, or the 1Password diagnosis of the
/// failed call; never a sign-in step.
fn with_credential(
    r: &dyn CommandRunner,
    vault: &str,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let args = ["vault", "get", vault, "--format", "json"];
    let found = match r.probe(&Call::new("op", &args), PROBE_TIMEOUT) {
        Ok(o) => o.status == 0,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(crate::adapters::onepassword::op_missing(
                &crate::host::Host::detect(),
            ));
        }
        Err(_) => false,
    };
    if !found {
        let excerpt = crate::runner::take_failure_excerpt();
        if let Some(seen) = crate::runner::take_observed() {
            let stderr = excerpt.map(|e| e.lines.join("\n")).unwrap_or_default();
            let ctx = crate::cause::DiagnoseContext {
                resource: Some(crate::cause::ResourceRef {
                    kind: crate::cause::ResourceKind::Vault,
                    name: crate::cause::ResourceName::new(vault),
                    scope: None,
                }),
                named_by: Some(crate::cause::NamedBy::Flag {
                    flag: "VAULT_ID".into(),
                }),
                ..crate::cause::DiagnoseContext::default()
            };
            let exit = seen.exit();
            let cause = crate::adapters::onepassword_diagnose::diagnose(seen, &stderr, &ctx);
            if stderr.is_empty() {
                return Err(cause.into());
            }
            // op's own (scrubbed) reply is the evidence.
            return Err(Error::with_evidence(
                cause,
                crate::cause::Upstream {
                    source: crate::cause::System::OnePassword,
                    tool: "1Password CLI".into(),
                    version: None,
                    exit,
                    said: stderr.lines().map(str::to_string).collect(),
                    removed_advice: false,
                    untrusted: true,
                },
            ));
        }
    }
    if json {
        let doc = json!({
            "schema_version": crate::json::SCHEMA_VERSION,
            "vault_id": vault,
            "accounts": [],
            "credential": true,
            "found": found,
            "complete": true,
        });
        writeln!(out, "{doc}").map_err(write_err)?;
    } else if found {
        writeln!(
            out,
            "vault {vault} is readable with the 1Password credential set here (service account \
             or Connect), which decides the account"
        )
        .map_err(write_err)?;
    }
    if found {
        Ok(())
    } else {
        // Every failed probe is observed by the runner (design §5).
        Err(Cause::Bug {
            site: "vault locate: a failed credential probe left no observation",
        }
        .into())
    }
}

#[cfg(test)]
#[path = "vault_locate_tests.rs"]
mod tests;
