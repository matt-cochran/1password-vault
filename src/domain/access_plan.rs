//! Who needs which 1Password vault, computed from the configuration and compared with what
//! 1Password shows (FR-59; docs/design/placements-and-access-boundaries.md §6).
//!
//! Pure: [`required`] derives each principal's grants from the boundaries and targets the
//! configuration declares; [`compare`] compares them with the readers 1Password reports per
//! vault. Every result states what was checked and what could not be classified, and never
//! reports "clean" for access it could not inspect (S7, FR-59). Only service-account names
//! are ever carried; no person's name, and no value, digest or fingerprint, is built here
//! (SR-1).

use std::collections::BTreeSet;

use crate::domain::access::Reader;

/// A deploy identity or a CI reader that needs vault access (FR-59).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Principal {
    Deploy { environment: String, target: String },
    CiReader { environment: String },
}

/// The access a principal needs on one vault (FR-59).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    Read,
    ReadWrite,
}

/// One vault grant the configuration requires for one principal (FR-59).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Grant {
    pub principal: Principal,
    pub service_account: String,
    pub vault_id: String,
    pub permission: Permission,
}

/// What one deployment target needs: read on each boundary vault, read-write on its own
/// state vault (FR-59).
pub struct TargetNeeds<'a> {
    pub environment: &'a str,
    pub target: &'a str,
    pub boundary_vaults: std::collections::BTreeSet<&'a str>,
    pub state_vault: &'a str,
}

/// What one environment's CI jobs need: read on each boundary vault (FR-59).
pub struct CiNeeds<'a> {
    pub environment: &'a str,
    pub boundary_vaults: std::collections::BTreeSet<&'a str>,
}

/// One vault as observed: `readers` is None when its user list could not be read.
pub struct ObservedVault<'a> {
    pub vault_id: &'a str,
    pub readers: Option<&'a [Reader]>,
}

/// How one required grant compares with what was observed (FR-59).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantState {
    Present,
    Missing,
    ReadOnlyNeeded,
    NotVisible,
    /// #153: the vault is not in the selected account, or this person cannot open it at
    /// all (`op vault get` fails): no owner command for this principal can succeed here.
    NotInAccount,
}

/// One required grant and its observed state.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GrantCheck {
    pub grant: Grant,
    pub state: GrantState,
}

/// A reader on an observed, visible vault that no required grant names (FR-59).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Extra {
    pub vault_id: String,
    pub service_account: String,
}

/// The comparison result: what was checked and what could not be classified (FR-59).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AccessReport {
    pub checks: Vec<GrantCheck>,
    pub extra: Vec<Extra>,
    pub checked: usize,
    pub unclassified: usize,
}

/// The name of a target's deploy identity: `{project}-{environment}-{target}-deploy`
/// (FR-59).
pub fn deploy_account(project: &str, environment: &str, target: &str) -> String {
    format!("{project}-{environment}-{target}-deploy")
}

/// The name of an environment's CI reader: `{project}-{environment}-ci` (FR-59).
pub fn ci_account(project: &str, environment: &str) -> String {
    format!("{project}-{environment}-ci")
}

/// Every grant the configuration requires, sorted by (principal, vault_id) and without
/// duplicates (FR-59).
pub fn required(project: &str, targets: &[TargetNeeds<'_>], ci: &[CiNeeds<'_>]) -> Vec<Grant> {
    let mut grants: BTreeSet<(Principal, String, String, Permission)> = BTreeSet::new();
    for target in targets {
        let principal = Principal::Deploy {
            environment: target.environment.to_string(),
            target: target.target.to_string(),
        };
        let service_account = deploy_account(project, target.environment, target.target);
        for vault in &target.boundary_vaults {
            grants.insert((
                principal.clone(),
                (*vault).to_string(),
                service_account.clone(),
                Permission::Read,
            ));
        }
        grants.insert((
            principal,
            target.state_vault.to_string(),
            service_account,
            Permission::ReadWrite,
        ));
    }
    for entry in ci {
        let principal = Principal::CiReader {
            environment: entry.environment.to_string(),
        };
        let service_account = ci_account(project, entry.environment);
        for vault in &entry.boundary_vaults {
            grants.insert((
                principal.clone(),
                (*vault).to_string(),
                service_account.clone(),
                Permission::Read,
            ));
        }
    }
    grants
        .into_iter()
        .map(|(principal, vault_id, service_account, permission)| Grant {
            principal,
            service_account,
            vault_id,
            permission,
        })
        .collect()
}

/// Compare the required grants with the observed vaults, naming every extra reader and
/// stating what was checked and what could not be classified (FR-59, S7).
pub fn compare(required: &[Grant], observed: &[ObservedVault<'_>]) -> AccessReport {
    let mut checks = Vec::with_capacity(required.len());
    let mut checked = 0;
    let mut unclassified = 0;
    for grant in required {
        let state = state_of(grant, observed);
        if state == GrantState::NotVisible {
            unclassified += 1;
        } else {
            checked += 1;
        }
        checks.push(GrantCheck {
            grant: grant.clone(),
            state,
        });
    }
    let mut extra: BTreeSet<(String, String)> = BTreeSet::new();
    for vault in observed {
        let Some(readers) = vault.readers else {
            continue;
        };
        for reader in readers {
            let named = required.iter().any(|grant| {
                grant.vault_id == vault.vault_id && grant.service_account == reader.name
            });
            if !named {
                extra.insert((vault.vault_id.to_string(), reader.name.clone()));
            }
        }
    }
    AccessReport {
        checks,
        extra: extra
            .into_iter()
            .map(|(vault_id, service_account)| Extra {
                vault_id,
                service_account,
            })
            .collect(),
        checked,
        unclassified,
    }
}

/// The state of one required grant: a vault not observed or with unknown readers is
/// [`GrantState::NotVisible`]; no reader with the service account's name is
/// [`GrantState::Missing`]; a read grant whose reader can write is
/// [`GrantState::ReadOnlyNeeded`]; anything else is [`GrantState::Present`] (FR-59).
fn state_of(grant: &Grant, observed: &[ObservedVault<'_>]) -> GrantState {
    let Some(vault) = observed
        .iter()
        .find(|vault| vault.vault_id == grant.vault_id)
    else {
        return GrantState::NotVisible;
    };
    let Some(readers) = vault.readers else {
        return GrantState::NotVisible;
    };
    let Some(reader) = readers
        .iter()
        .find(|reader| reader.name == grant.service_account)
    else {
        return GrantState::Missing;
    };
    if grant.permission == Permission::Read && !reader.read_only {
        GrantState::ReadOnlyNeeded
    } else {
        GrantState::Present
    }
}

/// The owner's command creating one principal's service account with all its vault grants
/// at once (1Password fixes a service account's vaults at creation). `None` for no grants
/// (FR-59).
pub fn create_command(grants_of_one_principal: &[Grant]) -> Option<String> {
    let first = grants_of_one_principal.first()?;
    let mut command = format!("op service-account create \"{}\"", first.service_account);
    for grant in grants_of_one_principal {
        let permission = match grant.permission {
            Permission::Read => "read_items",
            Permission::ReadWrite => "read_items,write_items",
        };
        command.push_str(&format!(" --vault {}:{permission}", grant.vault_id));
    }
    command.push_str(" --expires-in 90d");
    Some(command)
}

#[cfg(test)]
#[path = "access_plan_tests.rs"]
mod tests;
