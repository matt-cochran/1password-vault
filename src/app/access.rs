//! `opv access [<env>] [--target <name>] [--project <p>] [--json]` (FR-52, FR-59): who
//! needs which vault, per boundary and per target, and who can read it today. Read-only: it
//! makes one `op vault user list <vault>` call per needed vault (and, for a list it cannot
//! read, one `op vault get` probe, both diagnosed in the environment's own account, #157),
//! compares the readers with
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
use crate::adapters::onepassword_diagnose::{Facts, locate_owner};
use crate::adapters::onepassword_diagnose_items::diagnose_item_call;
use crate::adapters::onepassword_init;
use crate::cause::render::next_text;
use crate::cause::{
    AccountId, Cause, DiagnoseContext, DottedPath, EnvName, ExitClass, NameKind, NamedBy, Observed,
    ResourceKind, ResourceName, ResourceRef, Scope, System, TargetName, Upstream,
};
use crate::domain::Tier;
use crate::domain::access::{AccessFinding, Reader, VAULT_NOT_IN_ACCOUNT, analyse, findings};
use crate::domain::access_plan::{
    AccessReport, CiNeeds, Grant, GrantCheck, GrantState, ObservedVault, Permission, Principal,
    TargetNeeds, compare, create_command, required,
};
use crate::domain::capability::{self, Capability, UnknownSource};
use crate::error::Error;
use crate::host::Host;
use crate::runner::CommandRunner;

/// The raw `op vault user list` JSON per vault id; `None` when the vault is not visible.
type Observations = BTreeMap<String, Option<serde_json::Value>>;
/// The service-account readers per vault id; `None` when the vault is not visible.
type Readers = BTreeMap<String, Option<Vec<Reader>>>;
/// The diagnosed cause per vault whose user list could not be read (#153, #157).
type Unreadable = BTreeMap<String, VaultCause>;
/// What the session can do with each needed vault (design Part V, row `capability`).
type Capabilities = BTreeMap<String, Capability>;

/// Why one needed vault's user list could not be read, as the 1Password diagnosis
/// classified the failed calls in the environment's own account (#157, design §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultCause {
    pub vault: String,
    /// `op vault get` could not find the vault in this account: no owner command for an
    /// identity that needs it could succeed here (#153).
    pub elsewhere: bool,
    pub cause: Cause,
    pub upstream: Option<Upstream>,
}

impl VaultCause {
    /// The cause as the command's error, with op's reply as its evidence.
    pub fn error(&self) -> Error {
        match &self.upstream {
            Some(up) => Error::with_evidence(self.cause.clone(), up.clone()),
            None => self.cause.clone().into(),
        }
    }

    /// The cause as an access finding: its message and Do, and its typed Next.
    fn finding(&self, environment: &str) -> AccessFinding {
        let inv = crate::error::invocation();
        let mut message = self.cause.message();
        if let Some(action) = self.cause.do_text(&inv) {
            message = format!("{message}; {action}");
        }
        AccessFinding {
            code: if self.elsewhere {
                VAULT_NOT_IN_ACCOUNT
            } else {
                self.cause.code()
            },
            environment: environment.to_string(),
            message,
            next: next_text(&self.cause.step(&inv).1, &inv),
        }
    }
}

/// What one environment needs: one entry per target and one CI reader (FR-59).
struct Needs<'a> {
    name: &'a str,
    /// The environment's configured account, which the checks run in (#157); `None`: the
    /// run's (`OP_ACCOUNT`, the `.opv` pointer, else op's default).
    account_id: Option<String>,
    /// The configuration field that names each needed vault, for a diagnosis's Do.
    fields: BTreeMap<&'a str, DottedPath>,
    targets: Vec<TargetNeeds<'a>>,
    ci: Vec<CiNeeds<'a>>,
    /// The environment's tier; a `local` tier is not deployed, so it needs no second writer.
    tier: Tier,
}

/// One environment's comparison and the owner commands for its missing grants (FR-59).
struct EnvReport {
    name: String,
    report: AccessReport,
    commands: Vec<String>,
    findings: Vec<AccessFinding>,
    /// One entry per needed vault that could be read (Part V, row `access-writers`).
    vaults: Vec<VaultAccess>,
}

/// One needed vault as `opv access` shows it (Part V, row `access-writers`): its tier
/// marking, this session's capability, and who can write it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct VaultAccess {
    vault_id: String,
    /// `true` when the environment that needs it is production-tier.
    production: bool,
    /// What this session can do with the vault (Part V, row `capability`).
    capability: Capability,
    /// Who can write it, as `op vault user list` reports them (`allow_editing`), in reply
    /// order; empty when the list is not visible.
    writers: Vec<String>,
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
        return Err(target_not_declared(t, &known));
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
        let (observations, readers, unreadable, capabilities) = observe(&er, need)?;
        envs.push(build(
            need,
            &project,
            &observations,
            &readers,
            &unreadable,
            &capabilities,
        ));
    }
    report(out, &envs, json)
}

/// One principal's identity (0.9.0, `opv access --create`): its service-account name, every
/// grant it needs (1Password fixes a service account's vaults at creation), whether such an
/// account already reads them all, the account the vaults were checked in (the create runs
/// there too), and the needed vaults that account cannot find (then no account can be
/// created here), each with its diagnosed cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub service_account: String,
    pub grants: Vec<Grant>,
    pub already_present: bool,
    pub account: Option<String>,
    pub not_in_account: Vec<VaultCause>,
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
        let known: Vec<&str> = environment.targets.keys().map(String::as_str).collect();
        return Err(target_not_declared(t, &known));
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
        // 07.34: the identity reads no vault, so there is nothing to create.
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
    };
    let service_account = first.service_account.clone();
    let er = crate::app::signin::EnvRunner::with_account(r, need.account_id.clone());
    crate::adapters::onepassword::require_session(&er, &Host::detect, "opv access")?;
    let (_, readers, unreadable, _capabilities) = observe(&er, need)?;
    let observed: Vec<ObservedVault> = grants
        .iter()
        .map(|g| ObservedVault {
            vault_id: &g.vault_id,
            readers: readers.get(&g.vault_id).and_then(|r| r.as_deref()),
        })
        .collect();
    let report = compare(&grants, &observed);
    let already_present = report.checks.iter().all(|c| c.state == GrantState::Present);
    let mut not_in_account: Vec<VaultCause> = Vec::new();
    for g in &grants {
        if let Some(v) = unreadable.get(&g.vault_id).filter(|v| v.elsewhere)
            && !not_in_account.contains(v)
        {
            not_in_account.push(v.clone());
        }
    }
    Ok(Identity {
        service_account,
        grants,
        already_present,
        account: need.account_id.clone(),
        not_in_account,
    })
}

/// 07.34: a `--target` no selected environment declares; a unique close name is offered.
fn target_not_declared(given: &str, known: &[&str]) -> Error {
    let close = super::suggest::close(given, known.iter().copied());
    Cause::NotDeclared {
        kind: NameKind::Target,
        given: given.to_string(),
        candidates: known.iter().map(|k| (*k).to_string()).collect(),
        closest: crate::cause::Closest::unique(&close),
    }
    .into()
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
        let mut fields: BTreeMap<&str, DottedPath> = BTreeMap::new();
        for (boundary, b) in env.bound_boundaries() {
            fields
                .entry(b.vault_id.as_str())
                .or_insert_with(|| field(&[env_name, "boundaries", boundary, "vault_id"]));
        }
        for (target_name, spec) in &env.targets {
            if let Some(vault) = &spec.state_vault_id {
                fields.entry(vault.as_str()).or_insert_with(|| {
                    field(&[env_name, "targets", target_name, "state_vault_id"])
                });
            }
            if target.is_some_and(|only| only != target_name) {
                continue;
            }
            let mut boundary_vaults: BTreeSet<&str> = BTreeSet::new();
            for (product, p) in &fleet.products {
                if !fleet.delivers(env_name, target_name, product) {
                    continue;
                }
                let desired = p.keys.values().filter(|k| k.is_desired_in(env_name));
                for key in desired {
                    let needer = key.source().map_or(product.as_str(), |(source, _)| source);
                    boundary_vaults.insert(fleet.boundary(env_name, needer)?.vault_id.as_str());
                }
            }
            targets.push(TargetNeeds {
                environment: env_name,
                target: target_name.as_str(),
                boundary_vaults,
                state_vault: fleet.state_vault(env_name, spec)?,
            });
        }
        let ci = if target.is_some() {
            Vec::new()
        } else {
            vec![CiNeeds {
                environment: env_name,
                boundary_vaults: fleet
                    .bound_boundaries(env_name)?
                    .into_iter()
                    .map(|(_, b)| b.vault_id.as_str())
                    .collect(),
            }]
        };
        needs.push(Needs {
            name: env_name,
            account_id: env.account.clone(),
            fields,
            targets,
            ci,
            tier: env.tier,
        });
    }
    Ok(needs)
}

/// `environments.<path…>`, the configuration field a diagnosis names.
fn field(path: &[&str]) -> DottedPath {
    DottedPath(
        std::iter::once("environments")
            .chain(path.iter().copied())
            .map(str::to_string)
            .collect(),
    )
}

/// Observe each distinct needed vault of one environment once with `op vault user list
/// <vault> --format json` (FR-59). A vault whose user list cannot be read has no readers
/// (not visible); its failure is then diagnosed (#153, #157) after one `op vault get` probe
/// that tells "exists here, but its list needs the Manage permission" from "not in this
/// account". A failure of the session itself stops the command: no vault was classified.
fn observe(
    r: &dyn CommandRunner,
    need: &Needs<'_>,
) -> Result<(Observations, Readers, Unreadable, Capabilities), Error> {
    let mut wanted: BTreeSet<&str> = BTreeSet::new();
    for target in &need.targets {
        wanted.extend(target.boundary_vaults.iter().copied());
        wanted.insert(target.state_vault);
    }
    for ci in &need.ci {
        wanted.extend(ci.boundary_vaults.iter().copied());
    }
    let me = onepassword_init::session_user(r, &Host::detect);
    let mut observations = BTreeMap::new();
    let mut readers = BTreeMap::new();
    let mut unreadable = BTreeMap::new();
    let mut capabilities = BTreeMap::new();
    for vault in wanted {
        let users = onepassword_init::vault_users(r, vault, &Host::detect)?;
        let access = analyse(need.name, vault, false, users.as_ref());
        let mut diagnosed = None;
        if !access.visible
            && let Some(found) = diagnose_vault(r, need, vault)
        {
            if is_session(&found.cause) {
                return Err(found.error());
            }
            diagnosed = Some(found);
        }
        // The capability comes from this session's own entry in the user list; a refused
        // listing is only `none` when the diagnosis says the vault is not in this account.
        let capability = match users.as_ref() {
            Some(list) => match me.as_deref() {
                Some(me) => capability::classify(Some(list), me),
                None => Capability::Unknown {
                    source: UnknownSource::NoSessionUser,
                },
            },
            None => diagnosed
                .as_ref()
                .and_then(|found| capability::from_refusal(&found.cause))
                .unwrap_or(Capability::Unknown {
                    source: UnknownSource::UserListRefused,
                }),
        };
        if let Some(found) = diagnosed {
            unreadable.insert(vault.to_string(), found);
        }
        readers.insert(
            vault.to_string(),
            access.visible.then_some(access.service_accounts),
        );
        observations.insert(vault.to_string(), users);
        capabilities.insert(vault.to_string(), capability);
    }
    Ok((observations, readers, unreadable, capabilities))
}

/// The failed call the runner observed last, with its scrubbed reply and whether that was
/// truncated; taken once.
fn failed_call() -> Option<(Observed, (Vec<String>, bool))> {
    let seen = crate::runner::take_observed()?;
    let said = crate::scrub::Excerpt::parts(crate::runner::take_failure_excerpt());
    Some((seen, said))
}

/// #153, #157: diagnose an unreadable vault in the environment's own account. The user
/// list's failure is taken first, then `op vault get` probes the vault: when it finds it,
/// the list's refusal is a missing Manage permission; when it does not, op's reply says
/// whether the vault is in another account (or nowhere). `None` when the runner observed
/// neither call (nothing to diagnose: the vault stays unclassified, never guessed).
fn diagnose_vault(r: &dyn CommandRunner, need: &Needs<'_>, vault: &str) -> Option<VaultCause> {
    let list = failed_call();
    let found = r
        .probe(
            &crate::runner::Call::new("op", &["vault", "get", vault, "--format", "json"]),
            crate::runner::PROBE_TIMEOUT,
        )
        .is_ok_and(|o| o.status == 0);
    let get = if found { None } else { failed_call() };
    let account = checked_account(need.account_id.as_deref());
    let ctx = DiagnoseContext {
        env: Some(EnvName::new(need.name)),
        resource: Some(ResourceRef {
            kind: ResourceKind::Vault,
            name: ResourceName::new(vault),
            scope: account.as_ref().map(ToString::to_string),
        }),
        named_by: need
            .fields
            .get(vault)
            .map(|path| NamedBy::ConfigField { path: path.clone() }),
        account,
        ..DiagnoseContext::default()
    };
    let facts = Facts {
        vault_readable: found,
        ..Facts::from_process_env()
    };
    let (seen, (said, truncated)) = get.or(list)?;
    let exit = seen.exit();
    // #153a: a vault in another account names that account.
    let cause = locate_owner(r, diagnose_item_call(seen, &said.join("\n"), &ctx, &facts));
    let elsewhere =
        !found && matches!(cause, Cause::InOtherAccount { .. } | Cause::NotFound { .. });
    let upstream = (!said.is_empty()).then(|| op_reply(exit, said, truncated));
    Some(VaultCause {
        vault: vault.to_string(),
        elsewhere,
        cause,
        upstream,
    })
}

/// A failure of the session or account itself: no vault of this environment can be
/// classified, so it is the command's error (#157), never a per-vault finding.
fn is_session(cause: &Cause) -> bool {
    matches!(
        cause,
        Cause::NotSignedIn { .. }
            | Cause::AccountNotOnMachine { .. }
            | Cause::CredentialRejected { .. }
    )
}

/// op's scrubbed reply, attributed and marked untrusted (design §7.3).
fn op_reply(exit: ExitClass, said: Vec<String>, truncated: bool) -> Upstream {
    Upstream {
        source: System::OnePassword,
        tool: "1Password CLI".to_string(),
        version: None,
        exit,
        said,
        removed_advice: false,
        truncated,
        untrusted: true,
    }
}

/// The account a check runs in, as an ID when one is selected: the environment's, else
/// `OP_ACCOUNT`, else the checkout's `.opv` pointer; `None`: op's default account.
fn checked_account(configured: Option<&str>) -> Option<AccountId> {
    configured
        .map(str::to_string)
        .or_else(crate::config_store::account_env)
        .or_else(|| {
            crate::config_store::pointer_account(&std::env::current_dir().unwrap_or_default())
        })
        .map(AccountId::new)
}

/// Compare one environment's needs with what was observed, and collect the owner commands
/// for the missing grants and the findings that still apply (FR-59).
fn build(
    need: &Needs<'_>,
    project: &str,
    observations: &Observations,
    readers: &Readers,
    unreadable: &Unreadable,
    capabilities: &Capabilities,
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
    let elsewhere = |vault: &str| unreadable.get(vault).is_some_and(|v| v.elsewhere);
    let mut report = compare(&grants, &observed);
    for check in &mut report.checks {
        if check.state == GrantState::NotVisible && elsewhere(&check.grant.vault_id) {
            check.state = GrantState::NotInAccount;
        }
    }
    let commands = owner_commands(&report.checks);
    // A deployed-tier vault needs a second writer; a local tier does not (design row
    // `access-writers`).
    let deployed = need.tier != Tier::Local;
    let mut env_findings = Vec::new();
    let mut no_writer = Vec::new();
    let mut vaults = Vec::new();
    for vault in &needed {
        // #157: a vault the diagnosis classified carries that cause; no owner command is
        // printed for an identity needing a vault outside this account (#153).
        if let Some(diagnosed) = unreadable.get(*vault) {
            env_findings.push(diagnosed.finding(need.name));
            continue;
        }
        // 07.10: the environment is the environment, and the vault is named on its own.
        let mut access = analyse(
            need.name,
            vault,
            false,
            observations.get(*vault).and_then(|o| o.as_ref()),
        );
        access.deployed_tier = deployed;
        // Part V, row `access-writers`: the tier marking, this session's capability and who
        // 1Password reports can write the vault, in the text output and `--json` alike.
        vaults.push(VaultAccess {
            vault_id: (*vault).to_string(),
            production: need.tier == Tier::Production,
            capability: capabilities
                .get(*vault)
                .copied()
                .unwrap_or(Capability::Unknown {
                    source: UnknownSource::UserListRefused,
                }),
            writers: access.writers.clone(),
        });
        // A production vault whose readable user list names no writer: nobody can fix a
        // value there (row `access-writers`).
        if need.tier == Tier::Production && access.visible && access.writers.is_empty() {
            no_writer.push(crate::domain::access::no_writer(vault, need.name));
        }
        for finding in findings(&[access]) {
            // The CI-reader warning is about the CI reader; `--target` leaves it out.
            if finding.code == "no_ci_reader" && need.ci.is_empty() {
                continue;
            }
            // A deploy identity writes its own state vault by design (FR-59); the CI-reader
            // warning is about writing values, so it applies to the boundary vaults only.
            if finding.code == "ci_reader_can_write" && !boundary.contains(*vault) {
                continue;
            }
            env_findings.push(finding);
        }
    }
    // After every vault's own findings: the per-vault causes keep their place.
    env_findings.extend(no_writer);
    EnvReport {
        name: need.name.to_string(),
        report,
        commands,
        findings: env_findings,
        vaults,
    }
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

/// Print the per-principal grants, then the extra readers, then each readable vault's tier
/// marking, this session's capability and writers, then the findings, what was checked and
/// what could not be classified, then the owner commands. `--json` prints the documented
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
                    "vaults": env.vaults,
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
        for vault in &env.vaults {
            writeln!(out, "  {}", vault_line(vault)).map_err(write_err)?;
        }
        for finding in &env.findings {
            writeln!(out, "  {}: {}", finding.code, finding.message).map_err(write_err)?;
            if let Some(next) = &finding.next {
                writeln!(out, "    next: {next}").map_err(write_err)?;
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

/// One vault's line in text output (row `access-writers`): what `--json` carries as
/// `production`, `capability` and `writers`. Names and permissions only, never a value.
fn vault_line(vault: &VaultAccess) -> String {
    let production = if vault.production {
        " (production)"
    } else {
        ""
    };
    let writers = if vault.writers.is_empty() {
        "none listed".to_string()
    } else {
        vault.writers.join(", ")
    };
    format!(
        "vault {}{production}: this session {}; writers: {writers}",
        vault.vault_id,
        capability_label(vault.capability)
    )
}

/// How this session's capability is named in text output (row `capability`).
fn capability_label(capability: Capability) -> &'static str {
    match capability {
        Capability::Write => "can write",
        Capability::Read => "can read, not write",
        Capability::None => "is not a member",
        Capability::Unknown {
            source: UnknownSource::NoPermissionsInReply,
        } => "has unknown access (1Password listed no permissions)",
        Capability::Unknown {
            source: UnknownSource::UserListRefused,
        } => "has unknown access (listing users needs Manage)",
        Capability::Unknown {
            source: UnknownSource::NoSessionUser,
        } => "has unknown access (op whoami named no user)",
    }
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
