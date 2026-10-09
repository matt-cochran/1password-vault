//! Azure Key Vault store adapter (FR-29, FR-30, FR-32, SR-3).
//!
//! Key Vault is a [`PinnedStore`](crate::ports::PinnedStore): every write makes a new
//! version and the runtime pins an env var to one version id (FR-29). Four operations,
//! each one `az` call (all of them through the runner, R1):
//!
//! | fn | argv |
//! |---|---|
//! | `list` | `keyvault secret list --vault-name <vault> -o json` |
//! | `read` | `keyvault secret show --vault-name <vault> --name <name> -o json` |
//! | `write_one` | `keyvault secret set --vault-name <vault> --name <name> --file /dev/stdin --encoding utf-8 --tags opv-managed=<env> --query id -o tsv` |
//! | `delete` | `keyvault secret delete --vault-name <vault> --name <name> -o none` |
//!
//! Values travel on stdin only (`--file /dev/stdin --encoding utf-8`), never in argv, env
//! or a temp file (SR-1..SR-4). The write asks for `--query id -o tsv` because
//! `keyvault secret set` echoes the value on stdout (R11), so the value never comes back.
//!
//! `list` and `read` are reads (the runner retries them); a `show` that exits 3 is a
//! definite "absent", never retried. `set` and `delete` are writes (never retried
//! blindly, NR-2). Every non-zero exit is diagnosed through [`az::diagnose`]; a failed
//! `set` is first checked with a read-only `show-deleted` (stderr is discarded) so a
//! soft-deleted name gets the recover command (FR-32).

use std::collections::{BTreeMap, BTreeSet};
use std::io;

use serde::Deserialize;

use crate::domain::SecretValue;
use crate::domain::plan::StoreEntry;
use crate::error::Error;
use crate::host::{Host, Tool};
use crate::ports::{PinnedStore, Store};
use crate::runner::{Call, CommandRunner, Outcome, Output, unknown_text};

use super::az;

/// Largest value Key Vault accepts, in bytes (FR-30).
pub const VALUE_LIMIT: usize = 25 * 1024;

/// The refusal rule name for a value Key Vault cannot store (FR-22).
pub const STORE_LIMIT: &str = "store_limit";

/// Key Vault as both pinned store ports (FR-28): each method is the operation of the same
/// name.
pub struct KeyVault<'a> {
    pub runner: &'a dyn CommandRunner,
    pub vault: &'a str,
    pub env: &'a str,
    pub template_names: &'a BTreeSet<String>,
}

/// One `keyvault secret list --json` entry. Unknown fields are ignored (R10).
#[derive(Deserialize)]
struct ListEntry {
    name: String,
    #[serde(default)]
    tags: Option<BTreeMap<String, String>>,
}

/// The fields `keyvault secret show --json` that opv uses.
#[derive(Deserialize)]
struct ShowEntry {
    id: String,
    value: String,
}

impl Store for KeyVault<'_> {
    fn list(&self) -> Result<Vec<StoreEntry>, Error> {
        self.list_managed()
    }

    fn refusal(&self, _name: &str, value: &SecretValue) -> Option<(&'static str, &'static str)> {
        refusal(value)
    }
}

impl PinnedStore for KeyVault<'_> {
    fn read(&self, name: &str) -> Result<Option<(SecretValue, String)>, Error> {
        self.read_secret(name)
    }

    fn write_one(&self, name: &str, value: &SecretValue) -> Result<String, Error> {
        self.write_secret(name, value)
    }

    fn delete(&self, name: &str) -> Result<(), Error> {
        self.delete_secret(name)
    }
}

/// The first rule Key Vault would refuse `value` for, with its fixed reason (FR-22, FR-30),
/// or `None`. Never inspects or names the value.
pub fn refusal(value: &SecretValue) -> Option<(&'static str, &'static str)> {
    let len = value.expose().len();
    if len > VALUE_LIMIT {
        Some((STORE_LIMIT, "longer than the Key Vault limit of 25 KB"))
    } else if len == 0 {
        Some((STORE_LIMIT, "Key Vault cannot store an empty value"))
    } else {
        None
    }
}

/// Whether a call to the target changes it (NR-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Effect {
    Read,
    Write,
}

/// Run one `az` call through the runner. Only a spawn error or a spent budget is an
/// `Err`; anything the process returned is an [`Outcome`] for the caller to read.
fn invoke(
    r: &dyn CommandRunner,
    effect: Effect,
    op: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
    refused: &[i32],
) -> Result<Outcome, Error> {
    let call = Call::new(az::PROGRAM, args).with_stdin(stdin);
    let res = match effect {
        Effect::Read => r.read(&call, refused),
        Effect::Write => r.write(&call),
    };
    res.map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => Error::Dependency(format!(
            "{} not found on PATH\n  {}",
            az::PROGRAM,
            Host::detect().install_hint(Tool::Az)
        )),
        io::ErrorKind::TimedOut => Error::Target(format!("az {op}: {e}")),
        kind => Error::Target(format!("az {op} could not start {} ({kind})", az::PROGRAM)),
    })
}

/// A read's output, or the diagnosed error for a non-zero exit / unknown outcome.
fn read_output(
    r: &dyn CommandRunner,
    op: &str,
    target: &str,
    outcome: Outcome,
) -> Result<Output, Error> {
    match outcome {
        Outcome::Done(out) => Ok(out),
        Outcome::Refused(_) => Err(az::diagnose(r, op, target)),
        Outcome::Unknown { reason, .. } => Err(Error::Target(format!(
            "az {op}: {}",
            unknown_text(az::PROGRAM, reason)
        ))),
    }
}

/// A write's output, or the diagnosed error. A write that never finished (timeout, kill,
/// lost) is [`Error::Unknown`]: it may or may not have been applied (NR-2).
fn write_output(
    r: &dyn CommandRunner,
    op: &str,
    target: &str,
    outcome: Outcome,
) -> Result<Output, Error> {
    match outcome {
        Outcome::Done(out) => Ok(out),
        Outcome::Refused(_)
        | Outcome::Unknown {
            status: Some(_), ..
        } => Err(az::diagnose(r, op, target)),
        Outcome::Unknown { reason, .. } => Err(Error::Unknown(format!(
            "az {op}: {}; the change may or may not have been applied\n  next: re-run the same command",
            unknown_text(az::PROGRAM, reason)
        ))),
    }
}

impl KeyVault<'_> {
    /// Managed entries: tagged `opv-managed=<env>` and named in the managed template set
    /// (FR-8). Version comes from `show` / the binding, never `list`; nothing is pending.
    fn list_managed(&self) -> Result<Vec<StoreEntry>, Error> {
        const OP: &str = "keyvault secret list";
        let args = [
            "keyvault",
            "secret",
            "list",
            "--vault-name",
            self.vault,
            "-o",
            "json",
            az::ONLY_SHOW_ERRORS,
        ];
        let out = read_output(
            self.runner,
            OP,
            self.vault,
            invoke(self.runner, Effect::Read, OP, &args, None, &[])?,
        )?;
        // serde_json messages can quote input fragments, so report only the position.
        let entries: Vec<ListEntry> = serde_json::from_slice(&out.stdout).map_err(|e| {
            Error::Target(format!(
                "az {OP} returned unexpected JSON (line {}, column {})",
                e.line(),
                e.column()
            ))
        })?;
        Ok(entries
            .into_iter()
            .filter(|e| self.is_managed(e))
            .map(|e| StoreEntry {
                name: e.name,
                version: None,
                pending: false,
            })
            .collect())
    }

    /// True when opv owns `e`: its name is in the managed set and it carries this
    /// environment's tag (FR-8, FR-32).
    fn is_managed(&self, e: &ListEntry) -> bool {
        self.template_names.contains(&e.name)
            && e.tags
                .as_ref()
                .and_then(|t| t.get("opv-managed"))
                .is_some_and(|v| v == self.env)
    }

    /// The current value and version id, or `None` when Key Vault exits 3 (`SecretNotFound`).
    fn read_secret(&self, name: &str) -> Result<Option<(SecretValue, String)>, Error> {
        const OP: &str = "keyvault secret show";
        let args = [
            "keyvault",
            "secret",
            "show",
            "--vault-name",
            self.vault,
            "--name",
            name,
            "-o",
            "json",
            az::ONLY_SHOW_ERRORS,
        ];
        let outcome = invoke(self.runner, Effect::Read, OP, &args, None, &[3])?;
        let out = match outcome {
            Outcome::Refused(out) if out.status == 3 => return Ok(None),
            other => read_output(self.runner, OP, self.vault, other)?,
        };
        let entry: ShowEntry = serde_json::from_slice(&out.stdout).map_err(|e| {
            Error::Target(format!(
                "az {OP} returned unexpected JSON (line {}, column {})",
                e.line(),
                e.column()
            ))
        })?;
        Ok(Some((
            SecretValue::new(entry.value),
            version_from_id(&entry.id),
        )))
    }

    /// One new version, value on stdin, tagged `opv-managed=<env>`; returns its version id.
    fn write_secret(&self, name: &str, value: &SecretValue) -> Result<String, Error> {
        const OP: &str = "keyvault secret set";
        az::stdin_supported()?;
        let tag = format!("opv-managed={}", self.env);
        let args = [
            "keyvault",
            "secret",
            "set",
            "--vault-name",
            self.vault,
            "--name",
            name,
            "--file",
            "/dev/stdin",
            "--encoding",
            "utf-8",
            "--tags",
            tag.as_str(),
            "--query",
            "id",
            "-o",
            "tsv",
            az::ONLY_SHOW_ERRORS,
        ];
        let outcome = invoke(
            self.runner,
            Effect::Write,
            OP,
            &args,
            Some(value.expose().as_bytes()),
            &[],
        )?;
        match outcome {
            Outcome::Done(out) => {
                let id = std::str::from_utf8(&out.stdout).map_err(|_| {
                    Error::Target(format!("az {OP} returned a non-UTF-8 version id"))
                })?;
                Ok(version_from_id(id))
            }
            Outcome::Unknown {
                status: Some(_), ..
            } => {
                if self.is_soft_deleted(name)? {
                    Err(soft_deleted_error(name, self.vault))
                } else {
                    Err(az::diagnose(self.runner, OP, self.vault))
                }
            }
            Outcome::Unknown { reason, .. } => Err(Error::Unknown(format!(
                "az {OP}: {}; the change may or may not have been applied\n  next: re-run the same command",
                unknown_text(az::PROGRAM, reason)
            ))),
            Outcome::Refused(_) => Err(az::diagnose(self.runner, OP, self.vault)),
        }
    }

    /// A follow-up read-only probe: `show-deleted` exits 0 only when `name` is
    /// soft-deleted but recoverable (stderr is discarded, so this is how opv tells).
    fn is_soft_deleted(&self, name: &str) -> Result<bool, Error> {
        const OP: &str = "keyvault secret show-deleted";
        let args = [
            "keyvault",
            "secret",
            "show-deleted",
            "--vault-name",
            self.vault,
            "--name",
            name,
            "-o",
            "none",
            az::ONLY_SHOW_ERRORS,
        ];
        match invoke(self.runner, Effect::Read, OP, &args, None, &[])? {
            Outcome::Done(_) => Ok(true),
            _ => Ok(false),
        }
    }

    /// Delete only an entry opv owns: `list` first, then the write (FR-32).
    fn delete_secret(&self, name: &str) -> Result<(), Error> {
        const OP: &str = "keyvault secret delete";
        let managed = self.list_managed()?;
        if !managed.iter().any(|e| e.name == name) {
            return Err(Error::Policy(format!(
                "{name}: not tagged opv-managed={}; refusing to delete",
                self.env
            )));
        }
        let args = [
            "keyvault",
            "secret",
            "delete",
            "--vault-name",
            self.vault,
            "--name",
            name,
            "-o",
            "none",
            az::ONLY_SHOW_ERRORS,
        ];
        write_output(
            self.runner,
            OP,
            self.vault,
            invoke(self.runner, Effect::Write, OP, &args, None, &[])?,
        )?;
        Ok(())
    }
}

/// The last path segment of a Key Vault id, i.e. its version (FR-29).
fn version_from_id(id: &str) -> String {
    id.trim().rsplit('/').next().unwrap_or_default().to_owned()
}

/// The soft-deleted refusal names the exact recover command; opv never recovers itself
/// (FR-32).
fn soft_deleted_error(name: &str, vault: &str) -> Error {
    Error::Target(format!(
        "{name} is soft-deleted in Key Vault {vault}; recover it with: \
         az keyvault secret recover --vault-name {vault} --name {name}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::{PinnedStore, Store};
    use crate::runner::fake::FakeRunner;

    const VAULT: &str = "kv-opv-fixture";
    const MARKER: &str = "opv-marker-kv";
    const NAME: &str = "FLEET--API--DB-URL";
    const VERSION: &str = "46687ce78b76487cb0c1da470360b638";
    const LIST_FIXTURE: &str = include_str!("../../tests/fixtures/azure/keyvault-secret-list.json");
    const SHOW_FIXTURE: &str = include_str!("../../tests/fixtures/azure/keyvault-secret-show.json");

    fn names(set: &[&str]) -> BTreeSet<String> {
        set.iter().map(|s| (*s).to_string()).collect()
    }

    fn vault<'a>(
        r: &'a FakeRunner,
        env: &'a str,
        template_names: &'a BTreeSet<String>,
    ) -> KeyVault<'a> {
        KeyVault {
            runner: r,
            vault: VAULT,
            env,
            template_names,
        }
    }

    fn id(version: &str) -> String {
        format!("https://{VAULT}.vault.azure.net/secrets/{NAME}/{version}")
    }

    #[test]
    fn write_sends_value_on_stdin_only() {
        let r = FakeRunner::new([Output::success(id(VERSION))]);
        let templates = names(&[]);
        let kv = vault(&r, "prod", &templates);
        kv.write_one(NAME, &SecretValue::new(MARKER.into()))
            .unwrap();
        let calls = r.calls.borrow();
        assert_eq!(calls[0].stdin.as_deref(), Some(MARKER.as_bytes()));
        assert!(
            !calls
                .iter()
                .any(|c| c.args.iter().any(|a| a.contains(MARKER)))
        );
    }

    #[test]
    fn write_tags_entry_with_environment() {
        let r = FakeRunner::new([Output::success(id(VERSION))]);
        let templates = names(&[]);
        let kv = vault(&r, "prod", &templates);
        kv.write_one(NAME, &SecretValue::new(MARKER.into()))
            .unwrap();
        assert!(
            r.calls.borrow()[0]
                .args
                .iter()
                .any(|a| a == "opv-managed=prod")
        );
    }

    #[test]
    fn write_returns_version_from_id() {
        let r = FakeRunner::new([Output::success(id(VERSION))]);
        let templates = names(&[]);
        let kv = vault(&r, "prod", &templates);
        let version = kv
            .write_one(NAME, &SecretValue::new(MARKER.into()))
            .unwrap();
        assert_eq!(version, VERSION);
    }

    #[test]
    fn read_missing_secret_is_none() {
        let r = FakeRunner::new([Output::failure(3)]);
        let templates = names(&[]);
        let kv = vault(&r, "prod", &templates);
        assert!(kv.read(NAME).unwrap().is_none());
    }

    #[test]
    fn read_returns_value_and_version() {
        let r = FakeRunner::new([Output::success(SHOW_FIXTURE)]);
        let templates = names(&[NAME]);
        let kv = vault(&r, "prod", &templates);
        let (value, version) = kv.read(NAME).unwrap().unwrap();
        assert_eq!(
            (value.expose(), version.as_str()),
            ("opv-fixture-marker-1", VERSION)
        );
    }

    #[test]
    fn list_keeps_only_tagged_template_names() {
        let mut entries: Vec<serde_json::Value> = serde_json::from_str(LIST_FIXTURE).unwrap();
        let mut other_env = entries[0].clone();
        other_env["tags"]["opv-managed"] = "prod".into();
        let mut other_name = entries[0].clone();
        other_name["name"] = "OTHER--NAME".into();
        entries.push(other_env);
        entries.push(other_name);
        let body = serde_json::to_vec(&entries).unwrap();
        let r = FakeRunner::new([Output::success(body)]);
        let templates = names(&[NAME]);
        let kv = vault(&r, "dev", &templates);
        let kept: Vec<String> = kv.list().unwrap().into_iter().map(|e| e.name).collect();
        assert_eq!(kept, vec![NAME.to_string()]);
    }

    #[test]
    fn list_ignores_unknown_json_fields() {
        let mut entries: Vec<serde_json::Value> = serde_json::from_str(LIST_FIXTURE).unwrap();
        entries[0]["futureField"] = serde_json::json!({"nested": true});
        let body = serde_json::to_vec(&entries).unwrap();
        let r = FakeRunner::new([Output::success(body)]);
        let templates = names(&[NAME]);
        let kv = vault(&r, "dev", &templates);
        assert_eq!(kv.list().unwrap().len(), 1);
    }

    #[test]
    fn value_at_limit_is_accepted() {
        let value = SecretValue::new("a".repeat(VALUE_LIMIT));
        assert!(refusal(&value).is_none());
    }

    #[test]
    fn value_over_limit_is_refused_by_store_limit() {
        let value = SecretValue::new("a".repeat(VALUE_LIMIT + 1));
        assert_eq!(
            refusal(&value),
            Some((STORE_LIMIT, "longer than the Key Vault limit of 25 KB"))
        );
    }

    #[test]
    fn delete_refuses_untagged_entry() {
        let r = FakeRunner::new([Output::success(LIST_FIXTURE)]);
        let templates = names(&[NAME]);
        let kv = vault(&r, "prod", &templates);
        let err = kv.delete(NAME).unwrap_err();
        assert!(matches!(err, Error::Policy(msg) if msg.contains("not tagged opv-managed=prod")));
    }

    #[test]
    fn soft_deleted_name_error_names_recover_command() {
        let r = FakeRunner::new([Output::failure(1), Output::success("")]);
        let templates = names(&[]);
        let kv = vault(&r, "prod", &templates);
        let err = kv
            .write_one("MY-SECRET", &SecretValue::new(MARKER.into()))
            .unwrap_err();
        assert!(matches!(err, Error::Target(msg) if msg.contains(
            "az keyvault secret recover --vault-name kv-opv-fixture --name MY-SECRET"
        )));
    }

    #[test]
    fn failed_call_when_signed_out_is_auth_error() {
        let r = FakeRunner::new([Output::failure(1)]);
        let err = az::diagnose(&r, "keyvault secret show", VAULT);
        assert!(matches!(err, Error::Auth(msg) if msg.contains("az login")));
    }

    #[test]
    fn failed_call_when_signed_in_is_target_error() {
        let r = FakeRunner::new([Output::success("")]);
        let err = az::diagnose(&r, "keyvault secret show", VAULT);
        assert!(matches!(err, Error::Target(msg) if msg.contains(VAULT)));
    }

    #[cfg(windows)]
    #[test]
    fn write_on_windows_fails_closed_naming_wsl() {
        let r = FakeRunner::new([]);
        let templates = names(&[]);
        let kv = vault(&r, "prod", &templates);
        let err = kv
            .write_one(NAME, &SecretValue::new(MARKER.into()))
            .unwrap_err();
        assert!(matches!(err, Error::Dependency(msg) if msg.contains("WSL")));
    }
}
