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
//! | `delete` | `keyvault secret set-attributes --vault-name <vault> --name <name> --tags <its tags> opv-pruned=<env> -o none`, then `keyvault secret delete --vault-name <vault> --name <name> -o none` |
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
//! blindly, NR-2). Every non-zero exit is diagnosed through [`az::failed`]; a failed
//! `set` is first checked with a read-only `show-deleted --query tags` (stderr is discarded):
//! a soft-deleted name opv's own prune deleted (tagged `opv-pruned=<env>`) is recovered and
//! written; any other gets the recover command (FR-32). A `set` that fails for a reason that
//! is neither a soft-delete nor a sign-out may be a role grant still propagating; it is
//! retried once, only after `secret list` proves the vault answers (NR-25).

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde::Deserialize;

use crate::cause::{
    Cause, DiagnoseContext, DottedPath, Guard, NamedBy, NotFoundState, Refusal, ResourceKind,
    ResourceName, ResourceRef, System,
};
use crate::domain::plan::StoreEntry;
use crate::domain::{SecretValue, Stamp};
use crate::error::Error;
use crate::ports::{PinnedStore, Store};
use crate::runner::{CommandRunner, Outcome, Wait};

use super::AzureTarget;
use super::az::{self, Effect, invoke, read_output, write_output};
use super::preflight::{missing_in_reply, unreadable_json, unusable};

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
/// How long a recovery of a secret opv pruned may take before opv gives up (FR-32).
const RECOVER_WAIT: Duration = Duration::from_secs(120);

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

    fn delete(&self, name: &str) -> Result<bool, Error> {
        self.delete_secret(name).map(|()| true)
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

    /// What every call of this vault is about, for its diagnosis.
    fn ctx(&self) -> DiagnoseContext {
        az::about(
            ResourceKind::KeyVault,
            self.vault,
            format!("subscription {}", self.subscription),
            Some(self.env),
        )
    }

    /// Managed entries: tagged `opv-managed=<env>` and named in the managed template set
    /// (FR-8). Version comes from `show` / the binding, never `list`; nothing is pending.
    fn list_managed(&self) -> Result<Vec<StoreEntry>, Error> {
        Ok(self
            .list_entries()?
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

    /// Every entry of `keyvault secret list`, with its tags (names and tags only).
    fn list_entries(&self) -> Result<Vec<ListEntry>, Error> {
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
            self.ctx(),
            invoke(
                self.runner,
                Effect::Read,
                OP,
                &self.scoped(&args),
                None,
                &[],
            )?,
        )?;
        unreadable_json(&out.stdout, OP)
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
            other => read_output(self.runner, self.ctx(), other)?,
        };
        let entry: ShowEntry = unreadable_json(&out.stdout, OP)?;
        let version =
            version_from_id(&entry.id).ok_or_else(|| missing_in_reply(OP, "version id"))?;
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
            match crate::runner::diagnosing(|| self.deleted_tags(name))? {
                // Only a secret opv's own prune deleted is recovered (FR-32).
                Some(tags) if self.pruned_by_opv(&tags) => {
                    self.recover(name)?;
                    outcome = set()?;
                }
                Some(_) => return Err(self.soft_deleted(name)),
                None => {
                    if !crate::runner::diagnosing(|| az::signed_in(self.runner))? {
                        let up = az::take_failure().and_then(|(_, up)| up);
                        return Err(az::report(az::signed_out(), up));
                    }
                    self.await_access()?;
                    outcome = set()?;
                }
            }
        }
        match outcome {
            Outcome::Done(out) => {
                let version = std::str::from_utf8(&out.stdout)
                    .ok()
                    .and_then(version_from_id)
                    .ok_or_else(|| self.unconfirmed(OP, name))?;
                self.confirm_version(name, &version)?;
                Ok(version)
            }
            Outcome::Unknown { .. } | Outcome::Refused(_) => {
                Err(az::failed(self.runner, az::writing(self.ctx())))
            }
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
        let wait = Wait::new(self.runner, ACCESS_WAIT);
        loop {
            let outcome = invoke(
                self.runner,
                Effect::Read,
                OP,
                &self.scoped(&args),
                None,
                &[],
            )?;
            if matches!(outcome, Outcome::Done(_)) {
                return Ok(());
            }
            // Still refused, or no answer: what the last poll observed, with az's reply
            // (no recording tells a missing grant from a missing vault or a firewall).
            if wait.over(self.runner, ACCESS_POLL) {
                return Err(az::failed(self.runner, self.ctx()));
            }
            let waited = wait.elapsed(self.runner) + ACCESS_POLL;
            wait.pause(
                self.runner,
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
        let wait = Wait::new(self.runner, CONFIRM_WAIT);
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
                    read_output(self.runner, self.ctx(), other)?;
                }
            }
            if wait.over(self.runner, CONFIRM_POLL) {
                // Accepted, but not shown yet: whether the version stuck is not known.
                return Err(self.unconfirmed(OP, name));
            }
            wait.pause(self.runner, CONFIRM_POLL, "");
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
            other => read_output(self.runner, self.ctx(), other).map(|_| true),
        }
    }

    /// A follow-up read-only probe: `show-deleted` exits 0 only when `name` is
    /// soft-deleted but recoverable, and then prints only the deleted secret's tags
    /// (`--query tags`, never its value); exit 1 or 3 means it is not (stderr is discarded,
    /// so this is how opv tells). A probe that never finished says nothing either way.
    fn deleted_tags(&self, name: &str) -> Result<Option<BTreeMap<String, String>>, Error> {
        const OP: &str = "keyvault secret show-deleted";
        let args = [
            "keyvault",
            "secret",
            "show-deleted",
            "--vault-name",
            self.vault,
            "--name",
            name,
            "--query",
            "tags",
            "-o",
            "json",
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
            // `null` or no output: deleted, without tags.
            Outcome::Done(out) => Ok(Some(
                serde_json::from_slice::<Option<BTreeMap<String, String>>>(&out.stdout)
                    .ok()
                    .flatten()
                    .unwrap_or_default(),
            )),
            Outcome::Refused(_) => Ok(None),
            Outcome::Unknown { .. } => Err(az::failed(self.runner, self.ctx())),
        }
    }

    /// Whether a deleted secret's `tags` prove opv's own prune for this environment deleted
    /// it: `opv-managed=<env>` (opv wrote it) and [`PRUNED_TAG`]`=<env>` (opv marked it
    /// just before deleting it). A secret anyone else deleted lacks the second tag.
    fn pruned_by_opv(&self, tags: &BTreeMap<String, String>) -> bool {
        let is_env = |k: &str| tags.get(k).is_some_and(|v| v == self.env);
        is_env("opv-managed") && is_env(PRUNED_TAG)
    }

    /// Recover a secret opv's own prune deleted (FR-32): `keyvault secret recover`, a
    /// write (never retried, NR-2; az waits until the secret is back).
    fn recover(&self, name: &str) -> Result<(), Error> {
        const OP: &str = "keyvault secret recover";
        let args = [
            "keyvault",
            "secret",
            "recover",
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
            self.ctx(),
            invoke(
                self.runner,
                Effect::Write,
                OP,
                &self.scoped(&args),
                None,
                &[],
            )?,
        )?;
        self.await_recovered(name)?;
        self.runner.note(&format!(
            "recovered {name} in Key Vault {} (deleted by an earlier opv prune)",
            self.vault
        ));
        Ok(())
    }

    /// `recover` returns before the secret is back, and a `set` meanwhile is refused
    /// (`ObjectIsBeingRecovered`, found live): poll `secret show --query id` (a read; exit
    /// 3 is "not back yet") every [`CONFIRM_POLL`] for up to [`RECOVER_WAIT`].
    fn await_recovered(&self, name: &str) -> Result<(), Error> {
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
        let wait = Wait::new(self.runner, RECOVER_WAIT);
        loop {
            match invoke(
                self.runner,
                Effect::Read,
                OP,
                &self.scoped(&args),
                None,
                &[3],
            )? {
                Outcome::Done(_) => return Ok(()),
                Outcome::Refused(out) if out.status == 3 => {}
                other => {
                    read_output(self.runner, self.ctx(), other)?;
                }
            }
            if wait.over(self.runner, CONFIRM_POLL) {
                // Key Vault's own recovery of the secret is still running.
                return Err(unusable(OP, |seen| Cause::TargetRefused {
                    system: System::Azure,
                    subject: self.secret_ref(name),
                    why: Refusal::InProgress,
                    env: Some(crate::cause::EnvName::new(self.env)),
                    target: None,
                    seen,
                }));
            }
            wait.pause(self.runner, CONFIRM_POLL, "");
        }
    }

    /// Delete only an entry opv owns: `list` first, then the write (FR-32).
    fn delete_secret(&self, name: &str) -> Result<(), Error> {
        const OP: &str = "keyvault secret delete";
        let entries = self.list_entries()?;
        let Some(entry) = entries.iter().find(|e| {
            self.managed_name(e)
                .is_some_and(|m| m.eq_ignore_ascii_case(name))
        }) else {
            // 06.42: the refusal names the vault.
            return Err(Cause::Guard {
                guard: Guard::NotManagedByOpv {
                    name: format!("{name} in Key Vault {}", self.vault),
                },
            }
            .into());
        };
        let name = &AzureTarget::key_vault_name(name);
        self.mark_pruned(name, entry.tags.as_ref())?;
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
            self.ctx(),
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

impl KeyVault<'_> {
    /// Secret `name` (its Key Vault spelling) of this vault, as the subject of a cause.
    fn secret_ref(&self, name: &str) -> ResourceRef {
        ResourceRef {
            kind: ResourceKind::KeyVaultSecret,
            name: ResourceName::new(name),
            scope: Some(self.vault.to_string()),
        }
    }

    /// A write of `name` that Key Vault accepted without confirming the version it made
    /// (NR-30): whether it stuck is not known, and re-running is safe (NR-2).
    fn unconfirmed(&self, what: &str, name: &str) -> Error {
        unusable(what, |seen| Cause::WriteOutcomeUnknown {
            system: System::Azure,
            subject: self.secret_ref(name),
            seen,
        })
    }

    /// The failed `set` of `name`, soft-deleted and not by opv's prune: opv leaves it alone
    /// and names the recover command (FR-32), `az`'s reply as evidence.
    fn soft_deleted(&self, name: &str) -> Error {
        let Some((seen, up)) = az::take_failure() else {
            return az::unobserved(self.runner);
        };
        let deleted = Cause::NotFound {
            system: System::Azure,
            resource: self.secret_ref(name),
            named_by: NamedBy::ConfigField {
                path: DottedPath(vec!["azure".into(), "key_vault".into()]),
            },
            state: NotFoundState::SoftDeleted,
            seen,
        };
        az::report(deleted, up)
    }

    /// Tag the current version [`PRUNED_TAG`]`=<env>` just before opv deletes it, keeping
    /// its other tags (`--tags` replaces them): the proof, kept by the soft-deleted secret,
    /// that opv itself deleted it and may recover it (FR-32). A write, never retried; if it
    /// fails, nothing is deleted.
    fn mark_pruned(
        &self,
        name: &str,
        tags: Option<&BTreeMap<String, String>>,
    ) -> Result<(), Error> {
        const OP: &str = "keyvault secret set-attributes";
        let mut all = tags.cloned().unwrap_or_default();
        all.insert(PRUNED_TAG.to_owned(), self.env.to_owned());
        let pairs: Vec<String> = all.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let mut args = vec![
            "keyvault",
            "secret",
            "set-attributes",
            "--vault-name",
            self.vault,
            "--name",
            name,
            "--tags",
        ];
        args.extend(pairs.iter().map(String::as_str));
        args.extend(["-o", "none", az::ONLY_SHOW_ERRORS]);
        write_output(
            self.runner,
            self.ctx(),
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

/// Tag opv sets on a secret just before its prune deletes it (FR-32).
const PRUNED_TAG: &str = "opv-pruned";

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

    /// 06.38: a reply opv cannot read is an unexpected output, whose step is to update az.
    #[test]
    fn list_with_unreadable_json_is_unexpected_output() {
        let r = FakeRunner::new([Output::success("{not json")]);
        let templates = names(&[]);
        let err = vault(&r, "prod", &templates).list().unwrap_err();
        assert_eq!(err.code_str(), "unexpected_output");
    }

    #[test]
    fn read_with_garbled_id_is_unexpected_output() {
        let body = SHOW_FIXTURE.replace(VERSION, "not-a-version");
        let r = FakeRunner::new([Output::success(body)]);
        let templates = names(&[]);
        let err = vault(&r, "prod", &templates).read(NAME).unwrap_err();
        assert_eq!(err.code_str(), "unexpected_output");
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
        assert_eq!(err.code_str(), "policy_refused");
    }

    /// 06.42: the delete refusal names the vault the entry is in.
    #[test]
    fn delete_refusal_names_the_vault() {
        let r = FakeRunner::new([Output::success(LIST_FIXTURE)]);
        let templates = names(&[NAME]);
        let kv = vault(&r, "prod", &templates);
        let err = kv.delete(NAME).unwrap_err();
        assert!(
            err.to_string().contains("in Key Vault kv-opv-fixture"),
            "{err}"
        );
    }

    #[test]
    fn soft_deleted_name_error_names_recover_command() {
        let r = FakeRunner::new([Output::failure(1), Output::success("")]);
        let templates = names(&[]);
        let kv = vault(&r, "prod", &templates);
        let err = kv
            .write_one("MY-SECRET", &SecretValue::new(MARKER.into()), &stamp())
            .unwrap_err();
        assert!(
            crate::error::report(&err, "-", None).contains(
                "az keyvault secret recover --vault-name kv-opv-fixture --name MY-SECRET"
            )
        );
    }

    /// Found live: a soft-deleted name is a resource opv will not touch, never a re-run.
    #[test]
    fn soft_deleted_name_is_not_found_and_not_rerun() {
        let r = FakeRunner::new([Output::failure(1), Output::success("")]);
        let templates = names(&[]);
        let kv = vault(&r, "prod", &templates);
        let err = kv
            .write_one("MY-SECRET", &SecretValue::new(MARKER.into()), &stamp())
            .unwrap_err();
        assert_eq!(err.code_str(), "resource_not_found");
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
        let r = FakeRunner::new([
            Output::success(LIST_FIXTURE),
            Output::success(""),
            Output::success(""),
        ]);
        let templates = names(&[NAME]);
        let result = vault(&r, "dev", &templates).delete(NAME);
        assert!(result.is_ok());
    }

    fn argv(r: &FakeRunner, i: usize) -> Vec<String> {
        r.calls.borrow()[i].args.clone()
    }

    /// FR-32: before deleting, opv marks the entry opv-pruned=<env>, keeping its tags.
    #[test]
    fn delete_marks_the_entry_pruned_keeping_its_tags_first() {
        let r = FakeRunner::new([
            Output::success(LIST_FIXTURE),
            Output::success(""),
            Output::success(""),
        ]);
        let templates = names(&[NAME]);
        vault(&r, "dev", &templates).delete(NAME).unwrap();
        let a = argv(&r, 1);
        let at = a.iter().position(|x| x == "--tags").unwrap();
        assert_eq!(
            (&a[2], &a[at + 1..at + 4]),
            (
                &"set-attributes".to_string(),
                &[
                    "file-encoding=utf-8".to_string(),
                    "opv-managed=dev".into(),
                    "opv-pruned=dev".into()
                ][..]
            )
        );
    }

    /// FR-32: if the mark cannot be written, nothing is deleted.
    #[test]
    fn delete_without_the_pruned_mark_deletes_nothing() {
        // The failed mark is diagnosed (az signed in); any further call would get these.
        let r = FakeRunner::new([
            Output::success(LIST_FIXTURE),
            Output::failure(1),
            Output::success("{}"),
            Output::success(""),
            Output::success(""),
        ]);
        let templates = names(&[NAME]);
        let _ = vault(&r, "dev", &templates).delete(NAME);
        assert!(
            !r.calls
                .borrow()
                .iter()
                .any(|c| c.args.contains(&"delete".to_string()))
        );
    }

    fn deleted_tags(tags: &str) -> Output {
        Output::success(tags.to_string())
    }

    /// FR-32: a name opv's own prune deleted is recovered, then written.
    #[test]
    fn write_recovers_a_secret_opv_pruned_itself() {
        let mut q = vec![
            Output::failure(1),
            deleted_tags(r#"{"opv-managed":"prod","opv-pruned":"prod"}"#),
            Output::success(""),
            Output::success(id(VERSION)),
        ];
        q.extend(written());
        let r = FakeRunner::new(q);
        let templates = names(&[]);
        let v = vault(&r, "prod", &templates)
            .write_one("MY-SECRET", &secret(), &stamp())
            .unwrap();
        assert_eq!((argv(&r, 2)[2].as_str(), v.as_str()), ("recover", VERSION));
    }

    /// Found live: `recover` returns before the secret is back; opv waits for it before
    /// writing.
    #[test]
    fn write_after_recover_waits_until_the_secret_is_back() {
        let mut q = vec![
            Output::failure(1),
            deleted_tags(r#"{"opv-managed":"prod","opv-pruned":"prod"}"#),
            Output::success(""),
            Output::failure(3),
            Output::success(id(VERSION)),
        ];
        q.extend(written());
        let r = FakeRunner::new(q);
        let templates = names(&[]);
        vault(&r, "prod", &templates)
            .write_one("MY-SECRET", &secret(), &stamp())
            .unwrap();
        assert_eq!(argv(&r, 5)[2], "set");
    }

    /// FR-32: a secret someone else deleted (no opv-pruned mark) is never recovered.
    #[test]
    fn write_never_recovers_a_secret_deleted_by_someone_else() {
        let r = FakeRunner::new([
            Output::failure(1),
            deleted_tags(r#"{"opv-managed":"prod"}"#),
        ]);
        let templates = names(&[]);
        let _ = vault(&r, "prod", &templates).write_one("MY-SECRET", &secret(), &stamp());
        assert!(
            !r.calls
                .borrow()
                .iter()
                .any(|c| c.args.contains(&"recover".to_string()))
        );
    }

    /// FR-32: another environment's prune mark does not count.
    #[test]
    fn write_never_recovers_a_secret_another_environment_pruned() {
        let r = FakeRunner::new([
            Output::failure(1),
            deleted_tags(r#"{"opv-managed":"prod","opv-pruned":"staging"}"#),
        ]);
        let templates = names(&[]);
        let _ = vault(&r, "prod", &templates).write_one("MY-SECRET", &secret(), &stamp());
        assert!(
            !r.calls
                .borrow()
                .iter()
                .any(|c| c.args.contains(&"recover".to_string()))
        );
    }

    /// The probe asks for the deleted secret's tags only, never its value.
    #[test]
    fn show_deleted_asks_for_tags_only() {
        let r = FakeRunner::new([Output::failure(1), deleted_tags("null")]);
        let templates = names(&[]);
        let _ = vault(&r, "prod", &templates).write_one("MY-SECRET", &secret(), &stamp());
        let a = argv(&r, 1);
        assert_eq!(
            a.iter()
                .position(|x| x == "--query")
                .map(|i| a[i + 1].as_str()),
            Some("tags")
        );
    }

    #[test]
    fn write_with_unknown_outcome_and_no_status_is_unknown_error() {
        let r = FakeRunner::default();
        r.push_unknown("timeout");
        let templates = names(&[]);
        let err = vault(&r, "prod", &templates)
            .write_one(NAME, &secret(), &stamp())
            .unwrap_err();
        assert_eq!(err.code_str(), "outcome_unknown");
    }

    #[test]
    fn write_with_empty_id_is_unknown_outcome() {
        let r = FakeRunner::new([Output::success("")]);
        let templates = names(&[]);
        let err = vault(&r, "prod", &templates)
            .write_one(NAME, &secret(), &stamp())
            .unwrap_err();
        assert_eq!(err.code_str(), "outcome_unknown");
    }

    #[test]
    fn write_with_garbled_id_is_unknown_outcome() {
        let r = FakeRunner::new([Output::success(id("XYZ"))]);
        let templates = names(&[]);
        let err = vault(&r, "prod", &templates)
            .write_one(NAME, &secret(), &stamp())
            .unwrap_err();
        assert_eq!(err.exit_code(), 9);
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
        assert_eq!(err.code_str(), "outcome_unknown");
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
        // Elapsed time, the failed reads' backoff included (NR-4), not a sum of sleeps.
        assert_eq!(
            waits,
            ["waiting for Key Vault access on kv-opv-fixture (18 s)…"]
        );
    }

    /// After five minutes of refusals opv cannot tell a missing grant from a missing vault
    /// or a firewall without az's wording, which no recording backs (§12.4): az's reply is
    /// shown as it is, not blamed on a role.
    #[test]
    fn write_without_access_after_five_minutes_shows_azs_reply_unrecognized() {
        let polls = (0..21).flat_map(|_| crate::runner::fake::failed_read(1));
        let r = FakeRunner::new(failed_set().into_iter().chain(polls));
        let templates = names(&[]);
        // Under deploy credentials, so no probe of the person's own sign-in follows.
        let deploy = crate::cause::Principal::DeployCredentials {
            vault: crate::cause::VaultId::new("vlt-deploy"),
            item: crate::cause::ItemId::new("azure-deploy"),
            env: crate::cause::EnvName::new("prod"),
            target: crate::cause::TargetName::new("web"),
        };
        let err = crate::runner::under_deploy(deploy, || {
            vault(&r, "prod", &templates).write_one(NAME, &secret(), &stamp())
        })
        .unwrap_err();
        assert_eq!(err.code_str(), "unrecognized_failure");
    }

    #[test]
    fn write_whose_access_polls_never_answer_is_provider_unavailable() {
        let r = FakeRunner::new(failed_set());
        r.push_unknowns("timeout", 200);
        let templates = names(&[]);
        let err = vault(&r, "prod", &templates)
            .write_one(NAME, &secret(), &stamp())
            .unwrap_err();
        assert_eq!(err.code_str(), "provider_unavailable");
    }

    #[test]
    fn failed_set_when_signed_out_is_not_signed_in_without_waiting() {
        let r = FakeRunner::new([Output::failure(1), Output::failure(1), Output::failure(1)]);
        let templates = names(&[]);
        let err = vault(&r, "prod", &templates)
            .write_one(NAME, &secret(), &stamp())
            .unwrap_err();
        assert_eq!(err.code_str(), "target_not_signed_in");
    }

    #[test]
    fn show_deleted_probe_that_never_finishes_reports_the_failed_set() {
        let r = FakeRunner::new([Output::failure(1)]);
        r.push_unknowns("timeout", 3);
        r.push_with_stderr(Output::success(""), "");
        let templates = names(&[]);
        let err = vault(&r, "prod", &templates)
            .write_one(NAME, &secret(), &stamp())
            .unwrap_err();
        assert_eq!(err.code_str(), "unrecognized_failure");
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
}
