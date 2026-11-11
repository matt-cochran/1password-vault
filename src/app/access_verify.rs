//! `opv access <env> [--target <t>] --verify [--json]` (#304, FR-70;
//! docs/design/ci-reader-grants.md): prove, under the CI identity's own token, that it is the
//! service account opv issued, in the right account, with exactly the contract's vaults.
//!
//! Two reads and nothing else: `op whoami` and `op vault list`, both under whatever
//! 1Password identity the process has (in CI, `OP_SERVICE_ACCOUNT_TOKEN`). No item read, no
//! write, no owner session, no prompt. The committed receipt comes from the contract's
//! sibling `secrets.bindings.toml`; the required grants are computed from the contract
//! without a call. A manifest project holds no receipt: every check is `not_supported`.
//!
//! Exit 0 only when [`Report::passes`]; otherwise `grants_not_verified` (exit 6), whose Next
//! is the owner's `--rotate`. Names, ids and fixed reason words only (SR-1).

use std::io::Write;

use super::write_err;
use crate::adapters::onepassword::read_op;
use crate::cause::{Cause, ConfigSource, EnvName, Scope, TargetName};
use crate::domain::grant_receipt::{
    GrantReceipt, Observations, Outcome, ProviderRead, Reason, Report, evaluate, parse_vault_list,
    parse_whoami,
};
use crate::error::Error;
use crate::host::Host;
use crate::runner::CommandRunner;

/// The `--json` and text note that `permissions_live` is never waived silently.
pub const ISSUANCE_NOTE: &str = "permission levels are proven only at issuance: 1Password \
     shows no permission level for a service account afterwards";

/// Why a manifest project's checks are all `not_supported`.
pub const MANIFEST_WHY: &str = "the configuration lives in a 1Password manifest, which has no \
     secrets.bindings.toml to hold a grant receipt";

/// Run `opv access <env> [--target <t>] --verify`.
pub fn run(
    fleet: &crate::domain::Fleet,
    env: &str,
    target: Option<&str>,
    project: Option<&str>,
    r: &dyn CommandRunner,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), Error> {
    // The project only names the service accounts; no check depends on it, so it is never
    // looked up with a call (the two reads below are the only ones).
    let dir = std::env::current_dir().unwrap_or_default();
    let project = match project {
        Some(name) => crate::config_store::default_project(Some(name), None, &dir)?,
        None => crate::config_store::default_project(None, None, &dir)
            .unwrap_or_else(|_| "project".to_string()),
    };
    let required = super::access::required_grants(fleet, env, target, &project)?;
    if required.is_empty() {
        let what = match target {
            Some(t) => Scope::NoTargetDelivers {
                target: TargetName::new(t),
            },
            None => Scope::NoProductHasKeys,
        };
        return Err(Cause::NothingInScope {
            env: EnvName::new(env),
            what,
        }
        .into());
    }
    let (report, why) = match &fleet.read_from.0 {
        ConfigSource::Manifest { .. } => (Report::not_supported(), Some(MANIFEST_WHY)),
        ConfigSource::File { path, .. } => {
            let receipt = crate::config::bindings::read_receipt(path, env, target)?;
            let er = super::signin::open(fleet, env, r, super::signin::Reach::Store)?;
            let observed = observe(&er)?;
            let today = super::retire::today();
            (
                verify(receipt.as_deref(), &required, &observed, &today),
                None,
            )
        }
    };
    print(out, env, target, &report, why, json)?;
    match first_failure(&report, why.is_some()) {
        None => Ok(()),
        Some((check, reason)) => Err(Cause::GrantsNotVerified {
            env: EnvName::new(env),
            target: target.map(TargetName::new),
            check,
            reason,
        }
        .into()),
    }
}

/// The seven checks for the receipt text found (`None`: absent). A text that is not a
/// well-formed receipt is `receipt_invalid` wherever a missing one would be
/// `receipt_missing`.
pub fn verify(
    receipt: Option<&str>,
    required: &[crate::domain::access_plan::Grant],
    observed: &Observations,
    today: &str,
) -> Report {
    let parsed = receipt.map(GrantReceipt::from_toml);
    match parsed {
        None => evaluate(None, required, observed, today),
        Some(Ok(receipt)) => evaluate(Some(&receipt), required, observed, today),
        Some(Err(_)) => {
            let invalid = |o: Outcome| match o {
                Outcome::NotVerified(Reason::ReceiptMissing) => {
                    Outcome::NotVerified(Reason::ReceiptInvalid)
                }
                other => other,
            };
            let r = evaluate(None, required, observed, today);
            Report {
                receipt: invalid(r.receipt),
                identity: invalid(r.identity),
                vault_set: invalid(r.vault_set),
                contract: invalid(r.contract),
                permissions_issued: invalid(r.permissions_issued),
                permissions_live: invalid(r.permissions_live),
                freshness: invalid(r.freshness),
            }
        }
    }
}

/// The token's own view: `op whoami` and `op vault list`, each `--format json`. A read that
/// fails, or whose reply lacks what a check needs, is incomplete (never verified). A read
/// that never answered is 1Password unavailable (exit 9), as for every op read.
fn observe(r: &dyn CommandRunner) -> Result<Observations, Error> {
    let identity = read(r, &["whoami", "--format", "json"])?;
    let vaults = read(r, &["vault", "list", "--format", "json"])?;
    Ok(Observations {
        identity: identity.map_or(ProviderRead::Incomplete, |s| parse_whoami(&s)),
        vaults: vaults.map_or(ProviderRead::Incomplete, |s| parse_vault_list(&s)),
    })
}

fn read(r: &dyn CommandRunner, args: &[&str]) -> Result<Option<String>, Error> {
    let o = read_op(r, args, &Host::detect)?;
    Ok((o.status == 0).then(|| String::from_utf8_lossy(&o.stdout).into_owned()))
}

/// The first check that keeps the report from passing, with its reason word; `None` when it
/// passes. `permissions_live` is never the failure: it is always `not_supported`.
fn first_failure(report: &Report, manifest: bool) -> Option<(&'static str, &'static str)> {
    if report.passes() {
        return None;
    }
    if manifest {
        return Some(("receipt", "not_supported"));
    }
    report
        .checks()
        .into_iter()
        .filter(|(name, _)| *name != "permissions_live")
        .find_map(|(name, outcome)| match outcome {
            Outcome::Verified => None,
            Outcome::NotVerified(reason) => Some((name, reason_name(reason))),
            Outcome::NotSupported => Some((name, "not_supported")),
        })
}

/// The design's fixed reason word.
pub fn reason_name(reason: Reason) -> &'static str {
    match reason {
        Reason::ReceiptMissing => "receipt_missing",
        Reason::ReceiptInvalid => "receipt_invalid",
        Reason::NotAServiceAccount => "not_a_service_account",
        Reason::WrongAccount => "wrong_account",
        Reason::IdentityMismatch => "identity_mismatch",
        Reason::ProviderReadIncomplete => "provider_read_incomplete",
        Reason::ExtraVault => "extra_vault",
        Reason::MissingVault => "missing_vault",
        Reason::ContractChanged => "contract_changed",
        Reason::WritePermission => "write_permission",
        Reason::PermissionMismatch => "permission_mismatch",
        Reason::Expired => "expired",
    }
}

/// A check's state word and reason word.
fn words(outcome: Outcome) -> (&'static str, Option<&'static str>) {
    match outcome {
        Outcome::Verified => ("verified", None),
        Outcome::NotVerified(reason) => ("not_verified", Some(reason_name(reason))),
        Outcome::NotSupported => ("not_supported", None),
    }
}

/// The seven checks with state and reason, then the issuance note (and, for a manifest
/// project, why nothing could be checked). `--json` prints one document of names only.
fn print(
    out: &mut dyn Write,
    env: &str,
    target: Option<&str>,
    report: &Report,
    why: Option<&str>,
    json: bool,
) -> Result<(), Error> {
    if json {
        let checks: Vec<serde_json::Value> = report
            .checks()
            .into_iter()
            .map(|(name, outcome)| {
                let (state, reason) = words(outcome);
                serde_json::json!({ "name": name, "state": state, "reason": reason })
            })
            .collect();
        let doc = serde_json::json!({
            "environment": env,
            "target": target,
            "checks": checks,
            "passes": report.passes(),
            "permission_levels": "proven_at_issuance_only",
            "note": ISSUANCE_NOTE,
            "not_supported_because": why,
        });
        return writeln!(out, "{doc}").map_err(write_err);
    }
    let who = match target {
        Some(t) => format!("{env} target {t}: CI identity grants"),
        None => format!("{env}: CI reader grants"),
    };
    writeln!(out, "{who}").map_err(write_err)?;
    for (name, outcome) in report.checks() {
        let line = match (name, words(outcome)) {
            ("permissions_live", (state, _)) => {
                format!("{state} (1Password shows no service-account permission level)")
            }
            (_, (state, Some(reason))) => format!("{state} ({reason})"),
            (_, (state, None)) => state.to_string(),
        };
        writeln!(out, "  {name:<19}{line}").map_err(write_err)?;
    }
    if let Some(why) = why {
        writeln!(out, "Not supported: {why}.").map_err(write_err)?;
    }
    writeln!(out, "Note: {ISSUANCE_NOTE}.").map_err(write_err)
}

#[cfg(test)]
#[path = "access_verify_tests.rs"]
mod tests;
