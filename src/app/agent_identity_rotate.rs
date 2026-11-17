//! `opv access [<env>] --rotate --agent [--revoked <name>] [--confirm <env>]` (#338, design
//! `agent-identity.md` §7.3, vet R8): replace the read-only agent identity of `<env>` on
//! this machine, or with no environment every identity this machine's index records for the
//! project, each with a fresh service account `<base>-YYYYMMDD` that has the same read-only
//! grants and a 90-day lifetime.
//!
//! One question covers the whole batch. Then, per identity and in this order:
//!
//! 1. the #324 marker (`rotation_successor`) is written in the index, before the account can
//!    exist, so an interrupted run is detected;
//! 2. `op service-account create <successor> --vault <id>:read_items… --expires-in 90d`;
//! 3. the token-scoped binding check ([`super::reader_grants::issued`]): its own account and
//!    exactly these vaults;
//! 4. only then is the old token replaced in the OS store;
//! 5. it is read back and checked again under the stored token;
//! 6. the index entry takes the successor's name and expiry, and the marker is cleared.
//!
//! A failure before step 4 leaves the old token working, and its message names the
//! successor to remove. A marker left by an earlier run refuses that identity with
//! `secret_not_stored` (`--revoked <name>` once it is revoked), a production-tier identity
//! without `--confirm <env>` is skipped with a note, and the others go on. One `Do:` line at
//! the end names every old account: op cannot delete a service account, so the person
//! revokes them in 1Password. Nothing printed ever holds a token (ADR-0001).

use std::io::Write;
use std::path::Path;

use super::agent_identity::{self, IndexEntry};
use super::reader_grants::{Contract, VaultGrant};
use super::setup::Interaction;
use super::write_err;
use crate::adapters::credential_store::{AgentCredentialSource, AgentKey};
use crate::cause::render::cmd_text;
use crate::cause::{
    AccountId, Cause, Cmd, CreateKind, DiagnoseContext, EnvName, Guard, Refind, System,
    UsageProblem,
};
use crate::domain::{Fleet, SecretValue};
use crate::error::Error;
use crate::runner::{Call, CommandRunner};

/// The lifetime asked of 1Password and recorded as the expiry (FR-69, D5).
const VALIDITY_DAYS: i64 = 90;

/// What to rotate, and where the tokens and the index live.
pub struct Request<'a> {
    /// Only this environment's identity; `None`: every identity of `project` in the index.
    pub env: Option<&'a str>,
    /// The project naming the service accounts.
    pub project: &'a str,
    /// `--revoked <name>`: the successor an interrupted run left, which the person revoked.
    pub revoked: Option<&'a str>,
    /// `--confirm <env>`: the production-tier environment the person named again (D6).
    pub confirm: Option<&'a str>,
    /// This machine's OS credential store.
    pub store: &'a dyn AgentCredentialSource,
    /// The value-free index ([`super::agent_identity`], §7.5).
    pub index: &'a Path,
    /// Print one JSON document instead of lines.
    pub json: bool,
}

/// One identity that passed every check before the question.
struct Planned {
    entry: IndexEntry,
    successor: String,
    contract: Contract,
    key: AgentKey,
    /// The 1Password account the vaults were checked in, for the create.
    account: Option<String>,
}

/// One identity that was not rotated, and why.
struct NotRotated {
    name: String,
    env: String,
    error: Error,
    /// Skipped on purpose (production without `--confirm`), not failed.
    skipped: bool,
}

/// One identity that was rotated.
struct Rotated {
    old: String,
    new: String,
    env: String,
    expires_on: String,
}

fn env_cmd(command: &str, env: Option<&str>, extra: &[&str]) -> Cmd {
    Cmd {
        command: vec![command.into()],
        args: env
            .into_iter()
            .chain(extra.iter().copied())
            .map(str::to_string)
            .collect(),
    }
}

/// `opv access <env> --rotate --agent --revoked <successor>`.
fn rotate_again_cmd(env: &str, successor: &str) -> Cmd {
    env_cmd(
        "access",
        Some(env),
        &["--rotate", "--agent", "--revoked", successor],
    )
}

/// The account's immutable ID from the person's own session (`op whoami`), in `er`'s
/// account: the binding check compares each new token's account with it.
fn person_account_uuid(er: &dyn CommandRunner, env: &str) -> Result<String, Error> {
    #[derive(serde::Deserialize)]
    struct Who {
        account_uuid: String,
    }
    let call = Call::new("op", &["whoami", "--format", "json"]);
    let uuid = match er.read(&call, &[]) {
        Ok(crate::runner::Outcome::Done(o)) if o.status == 0 => {
            serde_json::from_slice::<Who>(&o.stdout)
                .ok()
                .map(|w| w.account_uuid)
        }
        _ => None,
    };
    uuid.filter(|a| a.len() == 26 && a.bytes().all(|b| b.is_ascii_alphanumeric()))
        .ok_or_else(|| super::reader_grants::refusal(env, "immutable_account_id_required"))
}

/// The identities the request names: `env`'s, or every one of the project.
fn selected(req: &Request<'_>) -> Result<Vec<IndexEntry>, Error> {
    let index = agent_identity::load(req.index)?;
    let picked: Vec<IndexEntry> = index
        .identities
        .into_iter()
        .filter(|e| e.project == req.project)
        .filter(|e| req.env.is_none_or(|env| e.record.environment == env))
        .collect();
    if picked.is_empty() {
        return Err(match req.env {
            Some(env) => Cause::AgentIdentityNotInstalled {
                env: EnvName::new(env),
            }
            .into(),
            None => Cause::Usage {
                problem: UsageProblem::UseInstead {
                    command: env_cmd("access", Some("<env>"), &["--create", "--agent"]),
                },
            }
            .into(),
        });
    }
    Ok(picked)
}

/// Everything about one identity that can be known before the question: the production
/// guard, an interrupted rotation, the grants and the account.
fn plan(
    fleet: &Fleet,
    req: &Request<'_>,
    entry: IndexEntry,
    r: &dyn CommandRunner,
    ui: &mut dyn Interaction,
) -> Result<Planned, NotRotated> {
    let env = entry.record.environment.clone();
    let name = entry.record.account_name.clone();
    let fail = |error: Error| NotRotated {
        name: name.clone(),
        env: env.clone(),
        error,
        skipped: false,
    };
    let environment = fleet.environment(&env).map_err(fail)?;
    // D6: a production-tier identity needs `--confirm <env>`; in a batch it is skipped.
    let guarded = environment.tier == crate::domain::Tier::Production || environment.confirm_env;
    if guarded && req.confirm != Some(env.as_str()) {
        ui.show(&format!(
            "Note: skipped {name:?}: {env} is production-tier, so it is rotated only with \
             {}",
            cmd_text(&env_cmd(
                "access",
                Some(&env),
                &["--rotate", "--agent", "--confirm", &env]
            ))
        ))
        .map_err(fail)?;
        return Err(NotRotated {
            skipped: true,
            ..fail(
                Cause::NeedsConfirm {
                    env: EnvName::new(&env),
                }
                .into(),
            )
        });
    }
    // #324: an earlier run that wrote its marker and never finished may have made the
    // successor, whose token nobody holds. It is revoked first, and `--revoked` says so.
    if let Some(pending) = entry.record.rotation_successor.clone()
        && req.revoked != Some(pending.as_str())
    {
        ui.show(&format!(
            "An earlier opv access --rotate --agent was creating the service account \
             {pending:?} for {env} and did not finish, so its token may be lost. Revoke \
             {pending:?} in 1Password (Developer > Service accounts) if it exists, then rotate \
             again: {}",
            cmd_text(&rotate_again_cmd(&env, &pending))
        ))
        .map_err(fail)?;
        return Err(fail(
            Cause::SecretNotStored {
                system: System::OnePassword,
                kind: CreateKind::ServiceAccount,
                name: pending,
                env: EnvName::new(&env),
                target: None,
                refind: None,
            }
            .into(),
        ));
    }
    let id = super::access::identity(fleet, &env, None, req.project, r).map_err(fail)?;
    if let Some(vault) = id.not_in_account.first() {
        return Err(fail(vault.error()));
    }
    let er = crate::app::signin::EnvRunner::with_account(r, id.account.clone());
    let account_uuid = person_account_uuid(&er, &env).map_err(fail)?;
    if account_uuid != entry.account_id {
        return Err(fail(super::reader_grants::refusal(
            &env,
            "native_account_mismatch",
        )));
    }
    let key = AgentKey::new(
        AccountId::new(account_uuid.clone()),
        req.project,
        EnvName::new(&env),
    )
    .ok_or_else(|| {
        fail(
            Cause::Usage {
                problem: UsageProblem::ValueFormat {
                    flag: "--project".into(),
                    format: "letters, digits, '-' or '_'",
                },
            }
            .into(),
        )
    })?;
    let base = crate::domain::access_plan::agent_account(req.project, &env, &entry.record.machine);
    let successor = format!("{base}-{}", super::credentials_rotate::date_suffix());
    let mut vaults: Vec<VaultGrant> = Vec::new();
    for g in &id.grants {
        if !vaults.iter().any(|v| v.vault_id == g.vault_id) {
            vaults.push(VaultGrant {
                vault_id: g.vault_id.clone(),
                permissions: vec!["read_items".into()],
            });
        }
    }
    Ok(Planned {
        contract: Contract {
            environment: env,
            role: "agent".into(),
            account_id: account_uuid,
            vaults,
            can_create_vaults: false,
        },
        entry,
        successor,
        key,
        account: id.account,
    })
}

/// The line for a successor whose token is no longer, or never was, kept (FM8, X5).
fn successor_lost(successor: &str, env: &str, what: &str) -> String {
    format!(
        "Service account {successor:?} was created, but {what}. 1Password shows a token only \
         once, so opv does not try again: remove {successor:?} in 1Password (Developer > \
         Service accounts), then run {}",
        cmd_text(&rotate_again_cmd(env, successor))
    )
}

/// Steps 1 to 6 for one identity (module docs). Every failure leaves the marker, so the
/// next run refuses until the successor is revoked.
fn rotate_one(
    p: &Planned,
    req: &Request<'_>,
    r: &dyn CommandRunner,
    ui: &mut dyn Interaction,
) -> Result<Rotated, Error> {
    let env = p.contract.environment.as_str();
    let successor = p.successor.as_str();
    let store = agent_identity::store_name(req.store.describe().store);
    // 1. The marker, on disk before the account can exist (#324).
    let mut marked = p.entry.clone();
    marked.record.rotation_successor = Some(successor.to_string());
    agent_identity::record(req.index, marked)?;
    // 2. The successor: the same read-only grants, 90 days.
    let mut args: Vec<String> = vec!["service-account".into(), "create".into(), successor.into()];
    for v in &p.contract.vaults {
        args.extend(["--vault".into(), format!("{}:read_items", v.vault_id)]);
    }
    args.extend(["--expires-in".into(), "90d".into(), "--raw".into()]);
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let ctx = DiagnoseContext {
        env: Some(EnvName::new(env)),
        create: Some((
            CreateKind::ServiceAccount,
            successor.to_string(),
            Refind::Check(env_cmd("access", Some(env), &[])),
        )),
        write: true,
        account: p.account.clone().map(AccountId::new),
        ..DiagnoseContext::default()
    };
    let er = crate::app::signin::EnvRunner::with_account(r, p.account.clone());
    let raw = super::credentials_rotate::create(&er, &Call::new("op", &argv), &ctx)?;
    let token = SecretValue::new(String::from_utf8_lossy(&raw).trim().to_string());
    drop(raw);
    crate::scrub::register_secret(token.expose());
    if token.expose().is_empty() {
        return Err(Cause::SecretNotStored {
            system: System::OnePassword,
            kind: CreateKind::ServiceAccount,
            name: successor.to_string(),
            env: EnvName::new(env),
            target: None,
            refind: None,
        }
        .into());
    }
    // 3. Bind, before anything replaces the old token (FM5).
    if let Err(e) = super::reader_grants::issued(&p.contract, &token, r) {
        drop(token);
        ui.show(&format!(
            "{} The old token of {:?} is kept and still works.",
            successor_lost(
                successor,
                env,
                &format!(
                    "under its token it is not exactly what was asked (account {} and these {} \
                     vaults, read only), so nothing was stored",
                    p.contract.account_id,
                    p.contract.vaults.len()
                )
            ),
            p.entry.record.account_name
        ))?;
        return Err(e);
    }
    // 4. Replace the old token, once (X5).
    let stored = req.store.store(&p.key, &token);
    drop(token);
    if let Err(e) = stored {
        ui.show(&successor_lost(
            successor,
            env,
            &format!("its token could not be kept in {store}"),
        ))?;
        return Err(e);
    }
    // 5. Read back and check again, under the stored token.
    let checked = match req.store.resolve(&p.key) {
        Ok(Some(back)) => super::reader_grants::issued(&p.contract, &back, r).map(|_| ()),
        Ok(None) => Err(Cause::AgentStoreUnavailable {
            store: req.store.describe().store,
        }
        .into()),
        Err(e) => Err(e),
    };
    if let Err(e) = checked {
        ui.show(&successor_lost(
            successor,
            env,
            &format!("its token did not read back from {store} and pass the check"),
        ))?;
        return Err(e);
    }
    // 6. The index takes the successor, its expiry, and no marker.
    let today = super::retire::today();
    let expires_on = crate::domain::credential::add_days(&today, VALIDITY_DAYS).unwrap_or_default();
    let mut done = p.entry.clone();
    done.record.account_name = successor.to_string();
    done.record.created_on = today;
    done.record.expires_on = expires_on.clone();
    done.record.rotation_successor = None;
    if let Err(e) = agent_identity::record(req.index, done) {
        ui.show(&format!(
            "The token of {successor:?} is kept and checked in {store}, but this machine's list \
             of agent identities could not be updated."
        ))?;
        return Err(e);
    }
    Ok(Rotated {
        old: p.entry.record.account_name.clone(),
        new: successor.to_string(),
        env: env.to_string(),
        expires_on,
    })
}

/// Rotate the agent identity of `req.env`, or every one of the project on this machine.
/// `ui` shows notes and asks the one question; `out` gets the summary (or the JSON
/// document). The first failure is returned after the summary, so the `Do:` line is printed
/// whatever else failed.
pub fn run(
    fleet: &Fleet,
    req: &Request<'_>,
    r: &dyn CommandRunner,
    ui: &mut dyn Interaction,
    out: &mut dyn Write,
) -> Result<(), Error> {
    if let (Some(env), Some(c)) = (req.env, req.confirm)
        && c != env
    {
        return Err(Cause::ConfirmMismatch {
            given: c.to_string(),
            env: EnvName::new(env),
        }
        .into());
    }
    super::tidy::require_person(r, "opv access --rotate --agent")?;
    let source = req.store.preflight()?;
    let entries = selected(req)?;
    let mut planned = Vec::new();
    let mut not_rotated: Vec<NotRotated> = Vec::new();
    for entry in entries {
        match plan(fleet, req, entry, r, ui) {
            Ok(p) => planned.push(p),
            Err(n) => not_rotated.push(n),
        }
    }
    if planned.is_empty() {
        return Err(not_rotated
            .into_iter()
            .next()
            .map(|n| n.error)
            .unwrap_or_else(|| {
                Cause::Bug {
                    site: "access --rotate --agent: nothing selected and nothing refused",
                }
                .into()
            }));
    }
    // The one question.
    let count = planned.len();
    let what = if count == 1 {
        "Replace 1 agent identity on this machine with a fresh one".to_string()
    } else {
        format!("Replace {count} agent identities on this machine, each with a fresh one")
    };
    ui.show(&format!(
        "{what} valid {VALIDITY_DAYS} days and the same read-only vaults:"
    ))?;
    let width = planned
        .iter()
        .map(|p| p.entry.record.account_name.len())
        .max()
        .unwrap_or(0);
    for p in &planned {
        let vaults = p.contract.vaults.len();
        ui.show(&format!(
            "  {:<width$}  -> {}  ({}, {vaults} vault{})",
            p.entry.record.account_name,
            p.successor,
            p.contract.environment,
            if vaults == 1 { "" } else { "s" }
        ))?;
    }
    if !ui.confirm("Go ahead?")? {
        return Err(Cause::Guard {
            guard: Guard::Declined,
        }
        .into());
    }
    let mut rotated: Vec<Rotated> = Vec::new();
    for p in &planned {
        match rotate_one(p, req, r, ui) {
            Ok(done) => rotated.push(done),
            Err(error) => not_rotated.push(NotRotated {
                name: p.entry.record.account_name.clone(),
                env: p.contract.environment.clone(),
                error,
                skipped: false,
            }),
        }
    }
    let store = agent_identity::store_name(source.store);
    let olds: Vec<&str> = rotated.iter().map(|d| d.old.as_str()).collect();
    let next = env_cmd("doctor", None, &[]);
    let next = match req.env {
        Some(env) => env_cmd("doctor", None, &["--env", env]),
        None => next,
    };
    let done = match rotated.as_slice() {
        [] => None,
        [one] => Some(format!(
            "created and checked {:?}; replaced its token in {store}; nothing was printed",
            one.new
        )),
        many => Some(format!(
            "created and checked {} successors; replaced {} tokens in {store}; nothing was printed",
            many.len(),
            if many.len() == 2 { "both" } else { "their" }
        )),
    };
    let revoke = (!olds.is_empty()).then(|| {
        format!(
            "revoke these in 1Password (Developer > Service accounts); opv cannot: {}",
            olds.join(", ")
        )
    });
    if req.json {
        let doc = serde_json::json!({
            "kind": "agent",
            "store": agent_identity::store_id(source.store),
            "rotated": rotated.iter().map(|d| serde_json::json!({
                "from": d.old,
                "to": d.new,
                "environment": d.env,
                "read_only": true,
                "expires_on": d.expires_on,
            })).collect::<Vec<_>>(),
            "not_rotated": not_rotated.iter().map(|n| serde_json::json!({
                "name": n.name,
                "environment": n.env,
                "skipped": n.skipped,
                "code": n.error.cause().map(|(c, _)| c.code()),
            })).collect::<Vec<_>>(),
            "revoke": olds,
            "next": cmd_text(&next),
        });
        if let Some(line) = &done {
            ui.show(line)?;
        }
        if let Some(line) = &revoke {
            ui.show(&format!("Do: {line}"))?;
        }
        writeln!(out, "{doc}").map_err(write_err)?;
    } else {
        if let Some(line) = &done {
            writeln!(out, "{line}").map_err(write_err)?;
        }
        for n in not_rotated.iter().filter(|n| !n.skipped) {
            let code = n.error.cause().map_or("error", |(c, _)| c.code());
            writeln!(out, "not rotated {:?} ({}): {code}", n.name, n.env).map_err(write_err)?;
        }
        if let Some(line) = &revoke {
            writeln!(out, "Do: {line}").map_err(write_err)?;
        }
        if !rotated.is_empty() {
            writeln!(out, "Next: {}", cmd_text(&next)).map_err(write_err)?;
        }
    }
    // A skip is a note when something else was rotated; a failure is the run's result.
    match not_rotated.into_iter().find(|n| !n.skipped) {
        Some(n) => Err(n.error),
        None => Ok(()),
    }
}

#[cfg(test)]
#[path = "agent_identity_rotate_tests.rs"]
mod tests;
