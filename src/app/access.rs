//! `opv access [<env>] [--target <name>] [--project <p>] [--json]` (FR-52, FR-59): who
//! needs which vault, per boundary and per target, and who can read it today. Read-only: it
//! makes one `op vault user list <vault>` call per needed vault, compares the readers with
//! the configuration's needs, and prints the owner's exact commands for the missing grants
//! (1Password fixes a service account's vaults at creation, so one command creates one
//! principal with all its vaults). It never runs a create or grant command.
//!
//! Results state what was checked and what could not be classified, and never say "clean"
//! (S7, FR-59). Only service-account names appear; no person's name, and no value, digest
//! or fingerprint, is built here (SR-1).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

use super::write_err;
use crate::adapters::onepassword_init;
use crate::domain::access::{AccessFinding, Reader, analyse, findings};
use crate::domain::access_plan::{
    AccessReport, CiNeeds, Grant, GrantCheck, GrantState, ObservedVault, Permission, Principal,
    TargetNeeds, compare, create_command, required,
};
use crate::error::Error;
use crate::host::Host;
use crate::runner::CommandRunner;

/// The raw `op vault user list` JSON per vault id; `None` when the vault is not visible.
type Observations = BTreeMap<String, Option<serde_json::Value>>;
/// The service-account readers per vault id; `None` when the vault is not visible.
type Readers = BTreeMap<String, Option<Vec<Reader>>>;

/// What one environment needs: one entry per target and one CI reader (FR-59).
struct Needs<'a> {
    name: &'a str,
    /// The 1Password account the vaults were checked in, named in findings (#157).
    account: String,
    /// The environment's configured account, which the checks run in; `None`: the run's.
    account_id: Option<String>,
    targets: Vec<TargetNeeds<'a>>,
    ci: Vec<CiNeeds<'a>>,
}

/// One environment's comparison and the owner commands for its missing grants (FR-59).
struct EnvReport {
    name: String,
    report: AccessReport,
    commands: Vec<String>,
    findings: Vec<AccessFinding>,
}

/// Run `opv access`.
pub fn run(
    fleet: &crate::domain::Fleet,
    only: Option<&str>,
    target: Option<&str>,
    project: Option<&str>,
    r: &dyn CommandRunner,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), Error> {
    if let Some(e) = only {
        fleet.environment(e)?;
    }
    let dir = std::env::current_dir().unwrap_or_default();
    let project = match project {
        Some(name) => crate::config_store::default_project(Some(name), None, &dir)?,
        None => super::personal::project_name(r, &dir),
    };
    let mut ordered: Vec<(&String, &crate::domain::Environment)> = fleet
        .environments
        .iter()
        .filter(|(name, _)| only.is_none_or(|o| o == name.as_str()))
        .collect();
    ordered.sort_by_key(|(name, env)| (env.order.unwrap_or(i64::MAX), (*name).clone()));
    if let Some(t) = target
        && !ordered.iter().any(|(_, env)| env.targets.contains_key(t))
    {
        let known: Vec<&str> = ordered
            .iter()
            .flat_map(|(_, env)| env.targets.keys().map(String::as_str))
            .collect();
        return Err(Error::Config(
            format!(
                "no target {t:?} in the selected environments (targets: {})",
                known.join(", ")
            )
            .into(),
        )
        .with_code(crate::error::Code::Usage)
        .with_next("opv access"));
    }
    if let Some(t) = target {
        ordered.retain(|(_, env)| env.targets.contains_key(t));
    }
    let needs = plan_needs(fleet, &ordered, target)?;
    // #157: each environment's vaults are checked in its own 1Password account, and a
    // missing session there is the cause, not every vault being outside the account.
    let mut sessions: BTreeSet<Option<String>> = BTreeSet::new();
    let mut envs = Vec::with_capacity(needs.len());
    for need in &needs {
        let er = crate::app::signin::EnvRunner::with_account(r, need.account_id.clone());
        if sessions.insert(need.account_id.clone()) {
            crate::adapters::onepassword::require_session(&er, &Host::detect, "opv access")?;
        }
        let (observations, readers) = observe(&er, std::slice::from_ref(need))?;
        let missing = missing_vaults(&er, &readers);
        envs.push(build(need, &project, &observations, &readers, &missing));
    }
    report(out, &envs, json)
}

/// One principal's identity (0.9.0, `opv access --create`): its service-account name, every
/// grant it needs (1Password fixes a service account's vaults at creation), whether such an
/// account already reads them all, and the vaults the selected account cannot find (then
/// no account can be created here).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub service_account: String,
    pub grants: Vec<Grant>,
    pub already_present: bool,
    pub not_in_account: Vec<String>,
}

/// The identity of `target`'s deploy principal in `env`, or of `env`'s CI reader when
/// `target` is `None`. Reads only: one `op vault user list` per needed vault, and `op vault
/// get` for each unreadable one.
pub fn identity(
    fleet: &crate::domain::Fleet,
    env: &str,
    target: Option<&str>,
    project: &str,
    r: &dyn CommandRunner,
) -> Result<Identity, Error> {
    let environment = fleet.environment(env)?;
    if let Some(t) = target
        && !environment.targets.contains_key(t)
    {
        return Err(
            Error::Config(format!("environment {env} has no target {t:?}").into())
                .with_code(crate::error::Code::Usage)
                .with_next(format!("opv access {env}")),
        );
    }
    let name = fleet
        .environments
        .keys()
        .find(|n| n.as_str() == env)
        .expect("checked above");
    let ordered = [(name, environment)];
    let needs = plan_needs(fleet, &ordered, target)?;
    let need = &needs[0];
    let all = required(project, &need.targets, &need.ci);
    let wanted = match target {
        Some(t) => Principal::Deploy {
            environment: env.to_string(),
            target: t.to_string(),
        },
        None => Principal::CiReader {
            environment: env.to_string(),
        },
    };
    let grants: Vec<Grant> = all.into_iter().filter(|g| g.principal == wanted).collect();
    let Some(first) = grants.first() else {
        return Err(Error::Config(
            format!("{env} needs no vault for this identity; there is nothing to create").into(),
        )
        .with_next(format!("opv access {env}")));
    };
    let service_account = first.service_account.clone();
    let er = crate::app::signin::EnvRunner::with_account(r, need.account_id.clone());
    crate::adapters::onepassword::require_session(&er, &Host::detect, "opv access")?;
    let (_, readers) = observe(&er, &needs)?;
    let missing = missing_vaults(&er, &readers);
    let observed: Vec<ObservedVault> = grants
        .iter()
        .map(|g| ObservedVault {
            vault_id: &g.vault_id,
            readers: readers.get(&g.vault_id).and_then(|r| r.as_deref()),
        })
        .collect();
    let report = compare(&grants, &observed);
    let already_present = report.checks.iter().all(|c| c.state == GrantState::Present);
    let not_in_account: Vec<String> = grants
        .iter()
        .filter(|g| missing.contains(&g.vault_id))
        .map(|g| g.vault_id.clone())
        .collect();
    Ok(Identity {
        service_account,
        grants,
        already_present,
        not_in_account,
    })
}

/// Build each environment's needs from the configuration (FR-59): a target reads exactly
/// the boundaries of the products it delivers and of the `from` sources its keys name,
/// plus its own state vault; the CI reader reads every boundary of the environment.
/// `--target` keeps only that target and omits the CI reader.
fn plan_needs<'a>(
    fleet: &'a crate::domain::Fleet,
    ordered: &[(&'a String, &'a crate::domain::Environment)],
    target: Option<&str>,
) -> Result<Vec<Needs<'a>>, Error> {
    let mut needs = Vec::with_capacity(ordered.len());
    for (name, env) in ordered {
        let env_name = name.as_str();
        let mut targets = Vec::new();
        for (target_name, spec) in &env.targets {
            if target.is_some_and(|only| only != target_name) {
                continue;
            }
            let mut boundary_vaults: BTreeSet<&str> = BTreeSet::new();
            for (product, p) in &fleet.products {
                if !fleet.delivers(env_name, target_name, product) {
                    continue;
                }
                let desired = p
                    .keys
                    .values()
                    .filter(|k| k.environments.iter().any(|e| e == env_name));
                for key in desired {
                    let needer = key.source().map_or(product.as_str(), |(source, _)| source);
                    boundary_vaults.insert(fleet.boundary(env_name, needer)?.vault_id.as_str());
                }
            }
            targets.push(TargetNeeds {
                environment: env_name,
                target: target_name.as_str(),
                boundary_vaults,
                state_vault: spec.state_vault_id.as_str(),
            });
        }
        let ci = if target.is_some() {
            Vec::new()
        } else {
            vec![CiNeeds {
                environment: env_name,
                boundary_vaults: env
                    .boundaries
                    .values()
                    .map(|b| b.vault_id.as_str())
                    .collect(),
            }]
        };
        needs.push(Needs {
            name: env_name,
            account: account_label(env.account.as_deref()),
            account_id: env.account.clone(),
            targets,
            ci,
        });
    }
    Ok(needs)
}

/// Observe each distinct needed vault once with `op vault user list <vault> --format json`
/// (FR-59). A vault whose user list cannot be read has no readers (not visible).
fn observe(r: &dyn CommandRunner, needs: &[Needs<'_>]) -> Result<(Observations, Readers), Error> {
    let mut wanted: BTreeSet<&str> = BTreeSet::new();
    for need in needs {
        for target in &need.targets {
            wanted.extend(target.boundary_vaults.iter().copied());
            wanted.insert(target.state_vault);
        }
        for ci in &need.ci {
            wanted.extend(ci.boundary_vaults.iter().copied());
        }
    }
    let mut observations = BTreeMap::new();
    let mut readers = BTreeMap::new();
    for vault in wanted {
        let users = onepassword_init::vault_users(r, vault, &Host::detect)?;
        let access = analyse("", vault, false, users.as_ref());
        readers.insert(
            vault.to_string(),
            access.visible.then_some(access.service_accounts),
        );
        observations.insert(vault.to_string(), users);
    }
    Ok((observations, readers))
}

/// #153: of the vaults whose user list could not be read, the ones `op vault get` cannot
/// find either: not in the selected account, or not open to this person at all. A vault
/// that exists but whose access list needs a manager stays `not visible`. One exit-status
/// probe per such vault; its output names the vault and is dropped unread.
fn missing_vaults(r: &dyn CommandRunner, readers: &Readers) -> BTreeSet<String> {
    readers
        .iter()
        .filter(|(_, seen)| seen.is_none())
        .filter(|(vault, _)| {
            r.probe(
                &crate::runner::Call::new(
                    "op",
                    &["vault", "get", vault.as_str(), "--format", "json"],
                ),
                crate::runner::PROBE_TIMEOUT,
            )
            .is_ok_and(|o| {
                if o.status != 0 {
                    let _ = crate::runner::take_failure_excerpt();
                }
                o.status != 0
            })
        })
        .map(|(vault, _)| vault.clone())
        .collect()
}

/// Compare one environment's needs with what was observed, and collect the owner commands
/// for the missing grants and the findings that still apply (FR-59).
fn build(
    need: &Needs<'_>,
    project: &str,
    observations: &Observations,
    readers: &Readers,
    missing: &BTreeSet<String>,
) -> EnvReport {
    let grants = required(project, &need.targets, &need.ci);
    let boundary: BTreeSet<&str> = need
        .targets
        .iter()
        .flat_map(|t| t.boundary_vaults.iter().copied())
        .chain(
            need.ci
                .iter()
                .flat_map(|c| c.boundary_vaults.iter().copied()),
        )
        .collect();
    let mut needed: BTreeSet<&str> = boundary.clone();
    needed.extend(need.targets.iter().map(|t| t.state_vault));
    let observed: Vec<ObservedVault> = needed
        .iter()
        .map(|vault| ObservedVault {
            vault_id: vault,
            readers: readers.get(*vault).and_then(|r| r.as_deref()),
        })
        .collect();
    let mut report = compare(&grants, &observed);
    for check in &mut report.checks {
        if check.state == GrantState::NotVisible && missing.contains(&check.grant.vault_id) {
            check.state = GrantState::NotInAccount;
        }
    }
    let commands = owner_commands(&report.checks);
    let mut env_findings = Vec::new();
    for vault in needed.iter().filter(|v| missing.contains(**v)) {
        env_findings.push(crate::domain::access::AccessFinding {
            code: crate::domain::access::VAULT_NOT_IN_ACCOUNT,
            environment: need.name.to_string(),
            message: format!(
                "vault {vault} is not in 1Password account {}, or you cannot open it; no \
                 service-account command is printed for an identity that needs it, because it \
                 could not succeed here. Find the account that holds it, then fix the \
                 configured vault_id or select that account",
                need.account
            ),
            next: Some(format!("opv vault locate {vault}")),
        });
    }
    for vault in needed.iter().filter(|v| !missing.contains(**v)) {
        let access = analyse(
            vault,
            vault,
            false,
            observations.get(*vault).and_then(|o| o.as_ref()),
        );
        for finding in findings(&[access]) {
            // A deploy identity writes its own state vault by design (FR-59); the CI-reader
            // warning is about writing values, so it applies to the boundary vaults only.
            if finding.code == "ci_reader_can_write" && !boundary.contains(*vault) {
                continue;
            }
            env_findings.push(finding);
        }
    }
    EnvReport {
        name: need.name.to_string(),
        report,
        commands,
        findings: env_findings,
    }
}

/// The account a check ran in (#157): the environment's, else `OP_ACCOUNT`, else the
/// checkout's `.opv` pointer, else op's default.
fn account_label(configured: Option<&str>) -> String {
    configured
        .map(str::to_string)
        .or_else(crate::config_store::account_env)
        .or_else(|| {
            crate::config_store::pointer_account(&std::env::current_dir().unwrap_or_default())
        })
        .unwrap_or_else(|| "(op's default account)".to_string())
}

/// One command per principal with at least one missing grant, over all of that principal's
/// grants (FR-59): 1Password fixes a service account's vaults at creation.
fn owner_commands(checks: &[GrantCheck]) -> Vec<String> {
    let mut commands = Vec::new();
    let mut start = 0;
    while start < checks.len() {
        let principal = &checks[start].grant.principal;
        let mut end = start;
        while end < checks.len() && &checks[end].grant.principal == principal {
            end += 1;
        }
        let group = &checks[start..end];
        // 1Password fixes a service account's vaults and permissions at creation, so a
        // missing grant and a reader that can write where it should only read are both fixed
        // by recreating the account with its full grant list (FR-59).
        // #153: never print a command that cannot succeed in this account.
        let runnable = !group
            .iter()
            .any(|check| check.state == GrantState::NotInAccount);
        if runnable
            && group.iter().any(|check| {
                matches!(
                    check.state,
                    GrantState::Missing | GrantState::ReadOnlyNeeded
                )
            })
        {
            let grants: Vec<Grant> = group.iter().map(|check| check.grant.clone()).collect();
            if let Some(command) = create_command(&grants) {
                commands.push(command);
            }
        }
        start = end;
    }
    commands
}

/// Print the per-principal grants, then the extra readers, then what was checked and what
/// could not be classified, then the owner commands. `--json` prints the documented
/// document (FR-59); it never says "clean".
fn report(out: &mut dyn Write, envs: &[EnvReport], json: bool) -> Result<(), Error> {
    if json {
        let environments: Vec<serde_json::Value> = envs
            .iter()
            .map(|env| {
                serde_json::json!({
                    "environment": env.name,
                    "report": env.report,
                    "commands": env.commands,
                    "findings": env.findings.iter().map(|f| serde_json::json!({
                        "code": f.code, "message": f.message, "next": f.next,
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();
        let doc = serde_json::json!({ "environments": environments });
        return writeln!(out, "{doc}").map_err(write_err);
    }
    for env in envs {
        writeln!(out, "{}:", env.name).map_err(write_err)?;
        let mut start = 0;
        while start < env.report.checks.len() {
            let principal = &env.report.checks[start].grant.principal;
            writeln!(out, "  {}:", principal_label(principal)).map_err(write_err)?;
            let mut end = start;
            while end < env.report.checks.len()
                && &env.report.checks[end].grant.principal == principal
            {
                let check = &env.report.checks[end];
                writeln!(
                    out,
                    "    {}: {}: {}",
                    check.grant.vault_id,
                    permission_label(check.grant.permission),
                    state_label(&check.state)
                )
                .map_err(write_err)?;
                end += 1;
            }
            start = end;
        }
        for extra in &env.report.extra {
            writeln!(
                out,
                "  extra reader {} on {}",
                extra.service_account, extra.vault_id
            )
            .map_err(write_err)?;
        }
        for finding in &env.findings {
            writeln!(out, "  {}: {}", finding.code, finding.message).map_err(write_err)?;
            if let Some(next) = &finding.next {
                writeln!(out, "    {next}").map_err(write_err)?;
            }
        }
        writeln!(
            out,
            "  checked: {}, unclassified: {}",
            env.report.checked, env.report.unclassified
        )
        .map_err(write_err)?;
        for command in &env.commands {
            writeln!(out, "Owner runs: {command}").map_err(write_err)?;
        }
    }
    Ok(())
}

/// How a principal is named in text output (FR-59).
fn principal_label(principal: &Principal) -> String {
    match principal {
        Principal::Deploy {
            environment,
            target,
        } => format!("deploy {environment}/{target}"),
        Principal::CiReader { environment } => format!("ci reader {environment}"),
    }
}

/// How a permission is named in text output (FR-59).
fn permission_label(permission: Permission) -> &'static str {
    match permission {
        Permission::Read => "read",
        Permission::ReadWrite => "read-write",
    }
}

/// How a grant state is named in text output (FR-59).
fn state_label(state: &GrantState) -> &'static str {
    match state {
        GrantState::Present => "present",
        GrantState::Missing => "missing",
        GrantState::ReadOnlyNeeded => "read-only needed",
        GrantState::NotVisible => "not visible",
        GrantState::NotInAccount => "not in this account",
    }
}

#[cfg(test)]
#[path = "access_tests.rs"]
mod tests;
