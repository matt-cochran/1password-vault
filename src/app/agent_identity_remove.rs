//! `opv access [<env>] --remove --agent` (#338, design `agent-identity.md` §7, S18): remove
//! the read-only agent identity of `<env>` from this machine, or with no environment every
//! identity this machine's index records for the project.
//!
//! One question covers the whole batch. Then, per identity: its token is deleted from the OS
//! store, and only then its entry from the value-free index (§7.5). A store delete that fails
//! keeps the index entry, so the identity is still listed and the run can be repeated. A
//! store with no entry for an indexed identity has nothing to delete: the index entry is
//! removed and the line says so.
//!
//! op cannot delete a service account, so one `Do:` line at the end names every account the
//! person deletes in the 1Password web app (with the successor an interrupted rotation may
//! have left). Removing the token here ends this machine's use of it; only deleting the
//! account ends its access. Nothing printed ever holds a token (ADR-0001).

use std::io::Write;
use std::path::Path;

use super::agent_identity::{self, IndexEntry};
use super::setup::Interaction;
use super::write_err;
use crate::adapters::credential_store::{AgentCredentialSource, AgentKey};
use crate::cause::render::cmd_text;
use crate::cause::{AccountId, Cause, Cmd, EnvName, Guard, IoKind, LocalOp, UsageProblem};
use crate::error::Error;
use crate::runner::CommandRunner;

/// What to remove, and where the tokens and the index live.
pub struct Request<'a> {
    /// Only this environment's identity; `None`: every identity of `project` in the index.
    pub env: Option<&'a str>,
    /// The project naming the service accounts.
    pub project: &'a str,
    /// This machine's OS credential store.
    pub store: &'a dyn AgentCredentialSource,
    /// The value-free index ([`super::agent_identity`], §7.5).
    pub index: &'a Path,
    /// Print one JSON document instead of lines.
    pub json: bool,
}

/// One identity that was removed.
struct Removed {
    name: String,
    env: String,
    /// The store held its token (deleted), or held none (only the index entry went).
    token_deleted: bool,
    /// The successor an interrupted rotation may have created, which is deleted too.
    pending: Option<String>,
}

/// One identity that was not removed, and why.
struct NotRemoved {
    name: String,
    env: String,
    error: Error,
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

fn index_error(op: LocalOp, path: &Path, kind: std::io::ErrorKind) -> Error {
    Cause::LocalIo {
        op,
        path: path.to_path_buf(),
        io: IoKind::from(kind),
        delivery: None,
    }
    .into()
}

/// Drop `gone`'s entry (same account, project and environment) from the index at `path`,
/// through a temporary file and a rename; the file stays the user's own (0600 on Unix).
fn forget(path: &Path, gone: &IndexEntry) -> Result<(), Error> {
    let mut index = agent_identity::load(path)?;
    index.identities.retain(|e| {
        !(e.account_id == gone.account_id
            && e.project == gone.project
            && e.record.environment == gone.record.environment)
    });
    let text = toml::to_string(&index)
        .map_err(|_| index_error(LocalOp::Write, path, std::io::ErrorKind::InvalidData))?;
    crate::config_edit::write_atomic(path, &text, || Ok(()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| index_error(LocalOp::Write, path, e.kind()))?;
    }
    Ok(())
}

/// The store entry's key for `entry`, or `usage` when a recorded part cannot name one.
fn key_of(entry: &IndexEntry) -> Result<AgentKey, Error> {
    AgentKey::new(
        AccountId::new(entry.account_id.clone()),
        entry.project.clone(),
        EnvName::new(&entry.record.environment),
    )
    .ok_or_else(|| {
        Cause::Usage {
            problem: UsageProblem::ValueFormat {
                flag: "--project".into(),
                format: "letters, digits, '-' or '_'",
            },
        }
        .into()
    })
}

/// The store entry first, then the index entry. A failed store delete keeps the index entry.
fn remove_one(entry: &IndexEntry, req: &Request<'_>) -> Result<Removed, Error> {
    let key = key_of(entry)?;
    let token_deleted = req.store.delete(&key)?;
    forget(req.index, entry)?;
    Ok(Removed {
        name: entry.record.account_name.clone(),
        env: entry.record.environment.clone(),
        token_deleted,
        pending: entry.record.rotation_successor.clone(),
    })
}

/// Remove the agent identity of `req.env`, or every one of the project on this machine.
/// `ui` asks the one question; `out` gets the summary (or the JSON document). The first
/// failure is returned after the summary, so the `Do:` line is printed whatever else failed.
pub fn run(
    req: &Request<'_>,
    r: &dyn CommandRunner,
    ui: &mut dyn Interaction,
    out: &mut dyn Write,
) -> Result<(), Error> {
    super::tidy::require_person(r, "opv access --remove --agent")?;
    let source = req.store.preflight()?;
    let entries = selected(req)?;
    let store = agent_identity::store_name(source.store);

    // The one question.
    let count = entries.len();
    ui.show(&if count == 1 {
        format!("Remove 1 agent identity from this machine: its token in {store} and its entry:")
    } else {
        format!(
            "Remove {count} agent identities from this machine: their tokens in {store} and \
             their entries:"
        )
    })?;
    let width = entries
        .iter()
        .map(|e| e.record.account_name.len())
        .max()
        .unwrap_or(0);
    for e in &entries {
        ui.show(&format!(
            "  {:<width$}  ({})",
            e.record.account_name, e.record.environment
        ))?;
    }
    if !ui.confirm("Go ahead?")? {
        return Err(Cause::Guard {
            guard: Guard::Declined,
        }
        .into());
    }

    let mut removed: Vec<Removed> = Vec::new();
    let mut not_removed: Vec<NotRemoved> = Vec::new();
    for e in &entries {
        match remove_one(e, req) {
            Ok(done) => removed.push(done),
            Err(error) => not_removed.push(NotRemoved {
                name: e.record.account_name.clone(),
                env: e.record.environment.clone(),
                error,
            }),
        }
    }

    // Every account the person deletes in 1Password: each removed identity's, and the
    // successor an interrupted rotation may have made.
    let accounts: Vec<&str> = removed
        .iter()
        .flat_map(|d| std::iter::once(d.name.as_str()).chain(d.pending.as_deref()))
        .collect();
    let delete = (!accounts.is_empty()).then(|| {
        format!(
            "delete these in the 1Password web app (Developer > Service accounts); opv cannot: \
             {}",
            accounts.join(", ")
        )
    });
    let next = match req.env {
        Some(env) => env_cmd("doctor", None, &["--env", env]),
        None => env_cmd("doctor", None, &[]),
    };
    let line_of = |d: &Removed| {
        if d.token_deleted {
            format!(
                "removed {:?} ({}): deleted its token from {store} and its entry; nothing was \
                 printed",
                d.name, d.env
            )
        } else {
            format!(
                "removed {:?} ({}): {store} held no token for it, so only its entry was \
                 removed",
                d.name, d.env
            )
        }
    };
    let not_line = |n: &NotRemoved| {
        let code = n.error.cause().map_or("error", |(c, _)| c.code());
        format!(
            "not removed {:?} ({}): {code}; its token could not be deleted from {store}, so \
             its entry is kept",
            n.name, n.env
        )
    };
    if req.json {
        let doc = serde_json::json!({
            "kind": "agent",
            "store": agent_identity::store_id(source.store),
            "removed": removed.iter().map(|d| serde_json::json!({
                "name": d.name,
                "environment": d.env,
                "token": if d.token_deleted { "deleted" } else { "absent" },
            })).collect::<Vec<_>>(),
            "not_removed": not_removed.iter().map(|n| serde_json::json!({
                "name": n.name,
                "environment": n.env,
                "code": n.error.cause().map(|(c, _)| c.code()),
                "index_entry_kept": true,
            })).collect::<Vec<_>>(),
            "delete": accounts,
            "next": cmd_text(&next),
        });
        for d in &removed {
            ui.show(&line_of(d))?;
        }
        for n in &not_removed {
            ui.show(&not_line(n))?;
        }
        if let Some(line) = &delete {
            ui.show(&format!("Do: {line}"))?;
        }
        writeln!(out, "{doc}").map_err(write_err)?;
    } else {
        for d in &removed {
            writeln!(out, "{}", line_of(d)).map_err(write_err)?;
        }
        for n in &not_removed {
            writeln!(out, "{}", not_line(n)).map_err(write_err)?;
        }
        if let Some(line) = &delete {
            writeln!(out, "Do: {line}").map_err(write_err)?;
        }
        if !removed.is_empty() {
            writeln!(out, "Next: {}", cmd_text(&next)).map_err(write_err)?;
        }
    }
    match not_removed.into_iter().next() {
        Some(n) => Err(n.error),
        None => Ok(()),
    }
}

#[cfg(test)]
#[path = "agent_identity_remove_tests.rs"]
mod tests;
