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
//! | `write_one` | `keyvault secret set --vault-name <vault> --name <name> --file /dev/stdin --encoding utf-8 --tags opv-managed=<env> opv-version=<v> opv-written=<utc> opv-env=<env> opv-plan=<id> --query id -o tsv`, then polls `secret show --query id -o tsv` until the new version shows (NR-30) |
//! | `delete` | `keyvault secret delete --vault-name <vault> --name <name> -o none` |
//! | `has_version` | `keyvault secret show --vault-name <vault> --name <name> --version <v> --query id -o tsv` (diagnosis only) |
//!
//! Every call also carries `--subscription <azure.subscription>` (NR-7).
//!
//! Values travel on stdin only (`--file /dev/stdin --encoding utf-8`; on native Windows a
//! user-only named pipe, see `handoff`), never in argv, env
//! or a temp file (SR-1..SR-4). The write asks for `--query id -o tsv` because
//! `keyvault secret set` echoes the value on stdout (R11), so the value never comes back.
//!
//! `list` and `read` are reads (the runner retries them); a `show` that exits 3 is a
//! definite "absent", never retried. `set` and `delete` are writes (never retried
//! blindly, NR-2). Every non-zero exit is diagnosed through [`az::diagnose`]; a failed
//! `set` is first checked with a read-only `show-deleted` (stderr is discarded) so a
//! soft-deleted name gets the recover command (FR-32). A `set` that fails for a reason that
//! is neither a soft-delete nor a sign-out may be a role grant still propagating; it is
//! retried once, only after `secret list` proves the vault answers (NR-25).

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde::Deserialize;

use crate::domain::plan::StoreEntry;
use crate::domain::{SecretValue, Stamp};
use crate::error::Error;
use crate::ports::{PinnedStore, Store};
use crate::runner::{CommandRunner, Outcome, unknown_text};

use super::AzureTarget;
use super::az::{self, Effect, invoke, read_output, write_output};

/// Largest value Key Vault accepts, in bytes (FR-30).
pub const VALUE_LIMIT: usize = 25 * 1024;

/// The refusal rule name for a value Key Vault cannot store (FR-22).
pub const STORE_LIMIT: &str = "store_limit";

/// How long to wait for a role grant to reach the vault before giving up (NR-25).
const ACCESS_WAIT: Duration = Duration::from_secs(300);
/// Pause between access polls, and between progress lines (NR-25).
const ACCESS_POLL: Duration = Duration::from_secs(15);
/// How long to wait for a written version to show up (NR-30).
const CONFIRM_WAIT: Duration = Duration::from_secs(30);
/// Pause between confirmation polls (NR-30).
const CONFIRM_POLL: Duration = Duration::from_secs(2);

/// Key Vault as both pinned store ports (FR-28): each method is the operation of the same
/// name.
pub struct KeyVault<'a> {
    pub runner: &'a dyn CommandRunner,
    pub vault: &'a str,
    /// `azure.subscription`, passed as `--subscription` on every call (NR-7).
    pub subscription: &'a str,
    pub env: &'a str,
    /// The managed env names (from the template, FR-8). The ports speak env names; each
    /// is stored under its Key Vault spelling ([`AzureTarget::key_vault_name`]).
    pub managed: BTreeSet<String>,
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

    fn write_one(&self, name: &str, value: &SecretValue, stamp: &Stamp) -> Result<String, Error> {
        self.write_secret(name, value, stamp)
    }

    fn delete(&self, name: &str) -> Result<(), Error> {
        self.delete_secret(name)
    }

    /// Key Vault keeps every version inside one entry as history; superseded versions are
    /// left as they are, never disabled or deleted (FR-32).
    fn collect_superseded(&self, _name: &str, _keep_version: &str) -> Result<(), Error> {
        Ok(())
    }

    /// `keyvault secret show --version <v> --query id -o tsv` (a read): exit 3 is "no such
    /// version". The value is never asked for.
    fn has_version(&self, name: &str, version: &str) -> Result<Option<bool>, Error> {
        self.version_exists(name, version).map(Some)
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

impl KeyVault<'_> {
    /// `args` plus `--subscription <id>` (NR-7).
    fn scoped<'s>(&'s self, args: &[&'s str]) -> Vec<&'s str> {
        let mut v = args.to_vec();
        v.extend(["--subscription", self.subscription]);
        v
    }

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
            invoke(
                self.runner,
                Effect::Read,
                OP,
                &self.scoped(&args),
                None,
                &[],
            )?,
        )?;
        // serde_json messages can quote input fragments, so report only the position.
        let entries: Vec<ListEntry> = serde_json::from_slice(&out.stdout).map_err(|e| {
            Error::Target(
                format!(
                    "az {OP} returned unexpected JSON (line {}, column {})",
                    e.line(),
                    e.column()
                )
                .into(),
            )
        })?;
        Ok(entries
            .into_iter()
            .filter_map(|e| {
                self.managed_name(&e).map(|name| StoreEntry {
                    name: name.to_owned(),
                    version: None,
                    pending: false,
                    stamp: e
                        .tags
                        .as_ref()
                        .and_then(|t| Stamp::parse(|k| t.get(k).map(String::as_str))),
                })
            })
            .collect())
    }

    /// The managed env name stored as `e` when opv owns it: its Key Vault spelling matches
    /// one of the managed names (Key Vault names are case-insensitive, R3) and it carries
    /// this environment's tag (FR-8, FR-32).
    fn managed_name(&self, e: &ListEntry) -> Option<&str> {
        let tagged = e
            .tags
            .as_ref()
            .and_then(|t| t.get("opv-managed"))
            .is_some_and(|v| v == self.env);
        if !tagged {
            return None;
        }
        self.managed
            .iter()
            .find(|t| AzureTarget::key_vault_name(t).eq_ignore_ascii_case(&e.name))
            .map(String::as_str)
    }

    /// The current value and version id, or `None` when Key Vault exits 3 (`SecretNotFound`).
    fn read_secret(&self, name: &str) -> Result<Option<(SecretValue, String)>, Error> {
        let name = &AzureTarget::key_vault_name(name);
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
        let outcome = invoke(
            self.runner,
            Effect::Read,
            OP,
            &self.scoped(&args),
            None,
            &[3],
        )?;
        let out = match outcome {
            Outcome::Refused(out) if out.status == 3 => return Ok(None),
            other => read_output(self.runner, OP, self.vault, other)?,
        };
        let entry: ShowEntry = serde_json::from_slice(&out.stdout).map_err(|e| {
            Error::Target(
                format!(
                    "az {OP} returned unexpected JSON (line {}, column {})",
                    e.line(),
                    e.column()
                )
                .into(),
            )
        })?;
        let version = version_from_id(&entry.id).ok_or_else(|| no_version_error(name))?;
        Ok(Some((SecretValue::new(entry.value), version)))
    }

    /// One new version, value on stdin, tagged `opv-managed=<env>` plus the provenance
    /// stamp (`opv-version`, `opv-written`, `opv-env`, `opv-plan`; FR-42, never a value);
    /// returns its version id once Key Vault shows it (NR-30).
    ///
    /// A `set` that exits non-zero while the name is not soft-deleted and `az` is signed in
    /// may be a role grant still propagating (NR-25). That one failure is retried once,
    /// but only after a read (`secret list`) proves the vault now answers.
    fn write_secret(
        &self,
        name: &str,
        value: &SecretValue,
        stamp: &Stamp,
    ) -> Result<String, Error> {
        let name = &AzureTarget::key_vault_name(name);
        const OP: &str = "keyvault secret set";
        let tag = format!("opv-managed={}", self.env);
        let stamps: Vec<String> = stamp
            .pairs()
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        let mut args = vec![
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
        ];
        args.extend(stamps.iter().map(String::as_str));
        args.extend(["--query", "id", "-o", "tsv", az::ONLY_SHOW_ERRORS]);
        let set = || {
            invoke(
                self.runner,
                Effect::Write,
                OP,
                &self.scoped(&args),
                Some(value.expose().as_bytes()),
                &[],
            )
        };
        let mut outcome = set()?;
        if matches!(
            outcome,
            Outcome::Unknown {
                status: Some(_),
                ..
            }
        ) {
            // These reads explain the failed set, so its excerpt stays (NR-31).
            if crate::runner::diagnosing(|| self.is_soft_deleted(name))? {
                return Err(soft_deleted_error(name, self.vault));
            }
            if !crate::runner::diagnosing(|| az::signed_in(self.runner))? {
                return Err(az::not_logged_in(None));
            }
            self.await_access()?;
            outcome = set()?;
        }
        match outcome {
            Outcome::Done(out) => {
                let version = std::str::from_utf8(&out.stdout)
                    .ok()
                    .and_then(version_from_id)
                    .ok_or_else(|| no_version_error(name))?;
                self.confirm_version(name, &version)?;
                Ok(version)
            }
            Outcome::Unknown {
                status: Some(_), ..
            }
            | Outcome::Refused(_) => Err(az::diagnose(self.runner, OP, self.vault)),
            Outcome::Unknown { reason, .. } => Err(Error::Unknown(format!(
                "az {OP}: {}; the change may or may not have been applied\n  next: re-run the same command",
                unknown_text(az::PROGRAM, reason)
            ).into())),
        }
    }

    /// Poll `secret list` (a read) until the vault answers, for up to [`ACCESS_WAIT`], with a
    /// progress line every [`ACCESS_POLL`] (NR-25).
    fn await_access(&self) -> Result<(), Error> {
        const OP: &str = "keyvault secret list";
        let args = [
            "keyvault",
            "secret",
            "list",
            "--vault-name",
            self.vault,
            "-o",
            "none",
            az::ONLY_SHOW_ERRORS,
        ];
        let mut waited = Duration::ZERO;
        loop {
            if let Outcome::Done(_) = invoke(
                self.runner,
                Effect::Read,
                OP,
                &self.scoped(&args),
                None,
                &[],
            )? {
                return Ok(());
            }
            if waited >= ACCESS_WAIT {
                return Err(Error::Auth(format!(
                    "Key Vault {vault} still refuses this account after {secs} s; nothing was \
                     changed; ask an owner to grant access, then re-run: az role assignment \
                     create --role \"Key Vault Secrets Officer\" --assignee <you> --scope <vault id>",
                    vault = self.vault,
                    secs = waited.as_secs()
                ).into()));
            }
            waited += ACCESS_POLL;
            self.runner.pause(
                ACCESS_POLL,
                &format!(
                    "waiting for Key Vault access on {} ({} s)…",
                    self.vault,
                    waited.as_secs()
                ),
            );
        }
    }

    /// Poll `secret show --query id` (a read) until it returns the version just written,
    /// every [`CONFIRM_POLL`] for up to [`CONFIRM_WAIT`] (NR-30).
    fn confirm_version(&self, name: &str, version: &str) -> Result<(), Error> {
        const OP: &str = "keyvault secret show";
        let args = [
            "keyvault",
            "secret",
            "show",
            "--vault-name",
            self.vault,
            "--name",
            name,
            "--query",
            "id",
            "-o",
            "tsv",
            az::ONLY_SHOW_ERRORS,
        ];
        let suffix = format!("/{version}");
        let mut waited = Duration::ZERO;
        loop {
            match invoke(
                self.runner,
                Effect::Read,
                OP,
                &self.scoped(&args),
                None,
                &[3],
            )? {
                Outcome::Done(out) => {
                    let seen = String::from_utf8_lossy(&out.stdout);
                    if seen.trim().ends_with(&suffix) {
                        return Ok(());
                    }
                }
                Outcome::Refused(out) if out.status == 3 => {}
                other => {
                    read_output(self.runner, OP, self.vault, other)?;
                }
            }
            if waited >= CONFIRM_WAIT {
                return Err(Error::Unknown(
                    format!(
                        "Key Vault accepted version {version} of {name} but does not show it yet; \
                     nothing else was changed; re-run to confirm"
                    )
                    .into(),
                ));
            }
            self.runner.pause(CONFIRM_POLL, "");
            waited += CONFIRM_POLL;
        }
    }

    /// Whether `version` of `name` exists (exit 3: it does not).
    fn version_exists(&self, name: &str, version: &str) -> Result<bool, Error> {
        const OP: &str = "keyvault secret show";
        let name = &AzureTarget::key_vault_name(name);
        let args = [
            "keyvault",
            "secret",
            "show",
            "--vault-name",
            self.vault,
            "--name",
            name,
            "--version",
            version,
            "--query",
            "id",
            "-o",
            "tsv",
            az::ONLY_SHOW_ERRORS,
        ];
        match invoke(
            self.runner,
            Effect::Read,
            OP,
            &self.scoped(&args),
            None,
            &[3],
        )? {
            Outcome::Refused(out) if out.status == 3 => Ok(false),
            other => read_output(self.runner, OP, self.vault, other).map(|_| true),
        }
    }

    /// A follow-up read-only probe: `show-deleted` exits 0 only when `name` is
    /// soft-deleted but recoverable; exit 1 or 3 means it is not (stderr is discarded, so
    /// this is how opv tells). A probe that never finished says nothing either way.
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
        match invoke(
            self.runner,
            Effect::Read,
            OP,
            &self.scoped(&args),
            None,
            &[1, 3],
        )? {
            Outcome::Done(_) => Ok(true),
            Outcome::Refused(_) => Ok(false),
            Outcome::Unknown { .. } => Err(Error::Unknown(
                format!(
                    "could not tell whether {name} is soft-deleted in Key Vault {}; nothing was \
                 changed; re-run to check again",
                    self.vault
                )
                .into(),
            )),
        }
    }

    /// Delete only an entry opv owns: `list` first, then the write (FR-32).
    fn delete_secret(&self, name: &str) -> Result<(), Error> {
        const OP: &str = "keyvault secret delete";
        let managed = self.list_managed()?;
        if !managed.iter().any(|e| e.name.eq_ignore_ascii_case(name)) {
            return Err(Error::Policy(
                format!(
                    "{name}: not tagged opv-managed={}; refusing to delete",
                    self.env
                )
                .into(),
            ));
        }
        let name = &AzureTarget::key_vault_name(name);
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
            invoke(
                self.runner,
                Effect::Write,
                OP,
                &self.scoped(&args),
                None,
                &[],
            )?,
        )?;
        Ok(())
    }
}

/// The version in a Key Vault id: its last path segment, which must be 32 lower-case hex
/// characters (FR-29); anything else is `None`.
fn version_from_id(id: &str) -> Option<String> {
    let v = id.trim().rsplit('/').next()?;
    let ok = v.len() == 32 && v.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    ok.then(|| v.to_owned())
}

/// Key Vault answered without a usable version, so nothing can be pinned (NR-6).
fn no_version_error(name: &str) -> Error {
    Error::Target(
        format!("Key Vault returned no version for {name}; nothing was bound; re-run").into(),
    )
}

/// The soft-deleted refusal names the exact recover command; opv never recovers itself
/// (FR-32).
fn soft_deleted_error(name: &str, vault: &str) -> Error {
    Error::Target(
        format!(
            "{name} is soft-deleted in Key Vault {vault}; recover it with: \
         az keyvault secret recover --vault-name {vault} --name {name}"
        )
        .into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::{PinnedStore, Store};
    use crate::runner::Output;
    use crate::runner::fake::FakeRunner;

    const VAULT: &str = "kv-opv-fixture";
    const SUBSCRIPTION: &str = "00000000-0000-0000-0000-000000000000";
    const MARKER: &str = "opv-marker-kv";
    const NAME: &str = "FLEET--API--DB-URL";
    const VERSION: &str = "46687ce78b76487cb0c1da470360b638";
    const LIST_FIXTURE: &str =
        include_str!("../../../tests/fixtures/azure/keyvault-secret-list.json");
    const SHOW_FIXTURE: &str =
        include_str!("../../../tests/fixtures/azure/keyvault-secret-show.json");

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
            subscription: SUBSCRIPTION,
            env,
            managed: template_names.clone(),
        }
    }

    fn id(version: &str) -> String {
        format!("https://{VAULT}.vault.azure.net/secrets/{NAME}/{version}")
    }

    /// A `set` answer then a `show` that already shows the version.
    fn written() -> Vec<Output> {
        vec![Output::success(id(VERSION)), Output::success(id(VERSION))]
    }

    fn secret() -> SecretValue {
        SecretValue::new(MARKER.into())
    }

    fn stamp() -> Stamp {
        crate::domain::provenance::fixture()
    }

    /// FR-42: a write records opv's run metadata as tags on the new version.
    #[test]
    fn write_tags_version_with_provenance_stamp() {
        let r = FakeRunner::new(written());
        let templates = names(&[]);
        vault(&r, "prod", &templates)
            .write_one(NAME, &secret(), &stamp())
            .unwrap();
        assert!(
            r.calls.borrow()[0]
                .args
                .iter()
                .any(|a| a == "opv-plan=7f3c9a1e")
        );
    }

    /// FR-42: `list` reads the provenance stamp back from an entry's tags.
    #[test]
    fn list_reads_provenance_stamp_from_tags() {
        let doc = r#"[{"name":"FLEET--API--DB-URL","tags":{"opv-managed":"prod",
            "opv-version":"0.5.0","opv-written":"2026-10-08T14:02:11Z","opv-env":"prod",
            "opv-plan":"7f3c9a1e"}}]"#;
        let r = FakeRunner::new([Output::success(doc)]);
        let templates = names(&["FLEET__API__DB_URL"]);
        let listed = vault(&r, "prod", &templates).list().unwrap();
        assert_eq!(listed[0].stamp, Some(stamp()));
    }

    #[test]
    fn write_sends_value_on_stdin() {
        let r = FakeRunner::new(written());
        let templates = names(&[]);
        vault(&r, "prod", &templates)
            .write_one(NAME, &secret(), &stamp())
            .unwrap();
        assert_eq!(
            r.calls.borrow()[0].stdin.as_deref(),
            Some(MARKER.as_bytes())
        );
    }

    /// NR-7: the store is scoped to the configured subscription, writes included.
    #[test]
    fn every_key_vault_call_carries_the_subscription() {
        let r = FakeRunner::new(written());
        let templates = names(&[]);
        vault(&r, "prod", &templates)
            .write_one(NAME, &secret(), &stamp())
            .unwrap();
        assert!(r.calls.borrow().iter().all(|c| {
            c.args
                .ends_with(&["--subscription".into(), SUBSCRIPTION.into()])
        }));
    }

    #[test]
    fn write_keeps_value_out_of_argv() {
        let r = FakeRunner::new(written());
        let templates = names(&[]);
        vault(&r, "prod", &templates)
            .write_one(NAME, &secret(), &stamp())
            .unwrap();
        assert!(!r.argv_contains(MARKER));
    }

    #[test]
    fn write_tags_entry_with_environment() {
        let r = FakeRunner::new(written());
        let templates = names(&[]);
        let kv = vault(&r, "prod", &templates);
        kv.write_one(NAME, &SecretValue::new(MARKER.into()), &stamp())
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
        let r = FakeRunner::new(written());
        let templates = names(&[]);
        let kv = vault(&r, "prod", &templates);
        let version = kv
            .write_one(NAME, &SecretValue::new(MARKER.into()), &stamp())
            .unwrap();
        assert_eq!(version, VERSION);
    }

    #[test]
    fn read_missing_secret_is_none() {
        let r = FakeRunner::new([Output::failure(3)]);
        let templates = names(&[]);
        let kv = vault(&r, "prod", &templates);
        assert_eq!(kv.read(NAME).unwrap().map(|(_, v)| v), None);
    }

    #[test]
    fn read_of_missing_secret_does_not_probe_show_deleted() {
        let r = FakeRunner::new([Output::failure(3)]);
        let templates = names(&[]);
        vault(&r, "prod", &templates).read(NAME).unwrap();
        assert!(!r.argv_contains("show-deleted"));
    }

    #[test]
    fn read_with_garbled_id_is_target_error() {
        let body = SHOW_FIXTURE.replace(VERSION, "not-a-version");
        let r = FakeRunner::new([Output::success(body)]);
        let templates = names(&[]);
        let err = vault(&r, "prod", &templates).read(NAME).unwrap_err();
        assert!(matches!(err, Error::Target(m) if m.contains("returned no version")));
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
            .write_one("MY-SECRET", &SecretValue::new(MARKER.into()), &stamp())
            .unwrap_err();
        assert!(matches!(err, Error::Target(msg) if msg.contains(
            "az keyvault secret recover --vault-name kv-opv-fixture --name MY-SECRET"
        )));
    }

    #[test]
    fn list_matches_template_names_ignoring_case() {
        let r = FakeRunner::new([Output::success(LIST_FIXTURE)]);
        let lower = NAME.to_lowercase();
        let templates = names(&[lower.as_str()]);
        let kept: Vec<String> = vault(&r, "dev", &templates)
            .list()
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(kept, vec![lower]);
    }

    /// The ports speak env names: a Key Vault entry is listed under the managed env name
    /// whose Key Vault spelling it is.
    #[test]
    fn list_names_entries_by_their_managed_env_name() {
        let r = FakeRunner::new([Output::success(LIST_FIXTURE)]);
        let templates = names(&["FLEET__API__DB_URL"]);
        let kept: Vec<String> = vault(&r, "dev", &templates)
            .list()
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(kept, ["FLEET__API__DB_URL"]);
    }

    #[test]
    fn read_asks_for_the_key_vault_spelling_of_an_env_name() {
        let r = FakeRunner::new([Output::success(SHOW_FIXTURE)]);
        let templates = names(&[]);
        vault(&r, "dev", &templates)
            .read("FLEET__API__DB_URL")
            .unwrap();
        assert!(r.calls.borrow()[0].args.iter().any(|a| a == NAME));
    }

    #[test]
    fn delete_of_tagged_entry_succeeds() {
        let r = FakeRunner::new([Output::success(LIST_FIXTURE), Output::success("")]);
        let templates = names(&[NAME]);
        let result = vault(&r, "dev", &templates).delete(NAME);
        assert!(result.is_ok());
    }

    #[test]
    fn write_with_unknown_outcome_and_no_status_is_unknown_error() {
        let r = FakeRunner::default();
        r.push_unknown("timeout");
        let templates = names(&[]);
        let err = vault(&r, "prod", &templates)
            .write_one(NAME, &secret(), &stamp())
            .unwrap_err();
        assert!(matches!(err, Error::Unknown(_)));
    }

    #[test]
    fn write_with_empty_id_is_target_error() {
        let r = FakeRunner::new([Output::success("")]);
        let templates = names(&[]);
        let err = vault(&r, "prod", &templates)
            .write_one(NAME, &secret(), &stamp())
            .unwrap_err();
        assert!(matches!(err, Error::Target(m) if m.contains("returned no version for")));
    }

    #[test]
    fn write_with_garbled_id_is_target_error() {
        let r = FakeRunner::new([Output::success(id("XYZ"))]);
        let templates = names(&[]);
        let err = vault(&r, "prod", &templates)
            .write_one(NAME, &secret(), &stamp())
            .unwrap_err();
        assert!(matches!(err, Error::Target(m) if m.contains("nothing was bound")));
    }

    const STALE: &str = "11111111111111111111111111111111";

    #[test]
    fn write_waits_until_new_version_shows() {
        let r = FakeRunner::new([
            Output::success(id(VERSION)),
            Output::success(id(STALE)),
            Output::success(id(VERSION)),
        ]);
        let templates = names(&[]);
        let version = vault(&r, "prod", &templates)
            .write_one(NAME, &secret(), &stamp())
            .unwrap();
        assert_eq!(version, VERSION);
    }

    #[test]
    fn write_polls_for_the_new_version_every_two_seconds() {
        let r = FakeRunner::new([
            Output::success(id(VERSION)),
            Output::success(id(STALE)),
            Output::success(id(VERSION)),
        ]);
        let templates = names(&[]);
        vault(&r, "prod", &templates)
            .write_one(NAME, &secret(), &stamp())
            .unwrap();
        assert_eq!(r.elapsed.get(), Duration::from_secs(2));
    }

    #[test]
    fn write_whose_version_never_shows_is_unknown_error() {
        let stale = (0..16).map(|_| Output::success(id(STALE)));
        let r = FakeRunner::new(std::iter::once(Output::success(id(VERSION))).chain(stale));
        let templates = names(&[]);
        let err = vault(&r, "prod", &templates)
            .write_one(NAME, &secret(), &stamp())
            .unwrap_err();
        assert!(matches!(err, Error::Unknown(m) if m.contains(
            "accepted version 46687ce78b76487cb0c1da470360b638 of FLEET--API--DB-URL but does not show it yet"
        )));
    }

    /// `set` fails, `show-deleted` says no, `az account show` says signed in.
    fn failed_set() -> Vec<Output> {
        vec![Output::failure(1), Output::failure(1), Output::success("")]
    }

    #[test]
    fn write_retries_set_once_after_vault_starts_answering() {
        let responses = failed_set()
            .into_iter()
            .chain(crate::runner::fake::failed_read(1).chain(crate::runner::fake::failed_read(1)))
            .chain([Output::success("[]")])
            .chain(written());
        let r = FakeRunner::new(responses);
        let templates = names(&[]);
        let version = vault(&r, "prod", &templates)
            .write_one(NAME, &secret(), &stamp())
            .unwrap();
        assert_eq!(version, VERSION);
    }

    #[test]
    fn write_after_grant_sends_set_exactly_twice() {
        let responses = failed_set()
            .into_iter()
            .chain(crate::runner::fake::failed_read(1).chain(crate::runner::fake::failed_read(1)))
            .chain([Output::success("[]")])
            .chain(written());
        let r = FakeRunner::new(responses);
        let templates = names(&[]);
        vault(&r, "prod", &templates)
            .write_one(NAME, &secret(), &stamp())
            .unwrap();
        let sets = r
            .calls
            .borrow()
            .iter()
            .filter(|c| c.args.iter().any(|a| a == "set"))
            .count();
        assert_eq!(sets, 2);
    }

    #[test]
    fn write_reports_progress_while_waiting_for_access() {
        let responses = failed_set()
            .into_iter()
            .chain(crate::runner::fake::failed_read(1))
            .chain([Output::success("[]")])
            .chain(written());
        let r = FakeRunner::new(responses);
        let templates = names(&[]);
        vault(&r, "prod", &templates)
            .write_one(NAME, &secret(), &stamp())
            .unwrap();
        let notes = r.notes.borrow();
        let waits: Vec<&String> = notes.iter().filter(|n| n.starts_with("waiting")).collect();
        assert_eq!(
            waits,
            ["waiting for Key Vault access on kv-opv-fixture (15 s)…"]
        );
    }

    #[test]
    fn write_without_access_after_five_minutes_is_auth_error_naming_the_role() {
        let polls = (0..21).flat_map(|_| crate::runner::fake::failed_read(1));
        let r = FakeRunner::new(failed_set().into_iter().chain(polls));
        let templates = names(&[]);
        let err = vault(&r, "prod", &templates)
            .write_one(NAME, &secret(), &stamp())
            .unwrap_err();
        assert!(matches!(err, Error::Auth(m) if m.contains(
            "az role assignment create --role \"Key Vault Secrets Officer\" --assignee <you> --scope <vault id>"
        )));
    }

    #[test]
    fn failed_set_when_signed_out_is_auth_error_without_waiting() {
        let r = FakeRunner::new([Output::failure(1), Output::failure(1), Output::failure(1)]);
        let templates = names(&[]);
        let err = vault(&r, "prod", &templates)
            .write_one(NAME, &secret(), &stamp())
            .unwrap_err();
        assert!(matches!(err, Error::Auth(m) if m.mentions("az login")));
    }

    #[test]
    fn show_deleted_probe_that_never_finishes_is_unknown_error() {
        let r = FakeRunner::new([Output::failure(1)]);
        r.push_unknowns("timeout", 3);
        let templates = names(&[]);
        let err = vault(&r, "prod", &templates)
            .write_one(NAME, &secret(), &stamp())
            .unwrap_err();
        assert!(matches!(err, Error::Unknown(m) if m.contains("soft-deleted")));
    }

    #[test]
    fn show_deleted_probe_of_a_new_name_is_not_retried() {
        let r = FakeRunner::new([Output::failure(1), Output::failure(1), Output::failure(1)]);
        let templates = names(&[]);
        let _ = vault(&r, "prod", &templates).write_one(NAME, &secret(), &stamp());
        let probes = r
            .calls
            .borrow()
            .iter()
            .filter(|c| c.args.iter().any(|a| a == "show-deleted"))
            .count();
        assert_eq!(probes, 1);
    }

    #[test]
    fn failed_call_when_signed_out_is_auth_error() {
        let r = FakeRunner::new([Output::failure(1)]);
        let err = az::diagnose(&r, "keyvault secret show", VAULT);
        assert!(matches!(err, Error::Auth(msg) if msg.mentions("az login")));
    }

    #[test]
    fn failed_call_when_signed_in_is_target_error() {
        let r = FakeRunner::new([Output::success("")]);
        let err = az::diagnose(&r, "keyvault secret show", VAULT);
        assert!(matches!(err, Error::Target(msg) if msg.contains(VAULT)));
    }
}
