//! Azure Container Apps runtime adapter wrapping `az` (FR-29, FR-31, FR-33; R1, R2, R6–R11).
//!
//! | fn | argv | stdin |
//! |---|---|---|
//! | `bindings` | `containerapp show -g <rg> -n <app> -o json` | — |
//! | `apply` | `containerapp show …`, `containerapp revision show … --revision <latest ready>`, then `containerapp update -g <rg> -n <app> --yaml /dev/stdin -o json` | the whole spec as JSON |
//! | `await_healthy` | `containerapp revision show -g <rg> -n <app> --revision <rev> -o json`, then `containerapp show …` | — |
//! | `check_access` | `containerapp show …`, `identity show --ids <id> -o json` (user-assigned identity whose principal the app does not list), `keyvault show -n <vault> -o json`, `role assignment list --assignee <principal> --scope <vault id> --include-inherited --include-groups -o json` (RBAC vaults only) | — |
//!
//! Every call adds `--only-show-errors` and `--subscription <azure.subscription>` (NR-7); the
//! runner adds the hardened `az` environment (R7). Reads go through `runner.read` (retried),
//! the update through `runner.write` (never retried, NR-2). `az` records each command's argv
//! under `~/.azure/commands/`, so argv holds names and ids only: config values travel inside
//! the stdin document of `apply`, never in argv (SR-3, R7), and no temp file is written
//! (SR-4).
//!
//! # Bindings and the unmanaged fingerprint (FR-31)
//!
//! One container is managed (R1): `azure.container`, or the only container. Each env var of
//! that container whose name is in `managed` is a [`Binding`]: a `value` is `Plain` with its
//! SHA-256 (the value is not kept), a `secretRef` to a Container Apps secret whose
//! `keyVaultUrl` is `<vault_uri>/secrets/<name>/<version>` is `Pinned`, anything else is
//! `Other`. The unmanaged fingerprint is the SHA-256 of the canonical JSON (serde_json maps
//! are sorted) of the spec without the managed env entries, without the `opv-` secrets and
//! without read-only status fields.
//!
//! # Apply (R2, R11 Q5, Q16)
//!
//! `apply` re-reads the app; when the unmanaged fingerprint moved since `snapshot` it refuses
//! and names the JSON pointers that changed (never values). Otherwise it edits the fresh
//! spec: each pin becomes a secret named [`secret_name`] (per version, so a repin changes
//! the env var's `secretRef`, a template change that makes Azure start a new revision) and an
//! env entry `{name, secretRef}`; each set becomes `{name, value}`; each unbind removes the
//! env entry. An `opv-` secret is superseded, and removed in the same document, only when
//! neither the edited template nor the template of the app's `latestReadyRevisionName` (the
//! revision serving now, read with `revision show`) references it. A previous apply whose
//! revision is not ready yet therefore never costs the serving revision its secret; the
//! leftover goes on a later apply (convergent, NR-1). Unmanaged plain secrets are sent as
//! `show` returned them, without a value; Azure keeps their value (Q5).
//!
//! # Health (R8) and post-apply verification (R9)
//!
//! Healthy = the revision is `Provisioned`, `Running`/`RunningAtMaxScale` with health
//! `Healthy` (or `ScaledToZero`, Q15), and the app names it `latestReadyRevisionName`.
//! Failed = `provisioningState Failed`, `runningState Failed` or `healthState Unhealthy`.
//! Polls every [`POLL_EVERY`] up to [`WAIT_MAX`], within the run budget (NR-4), printing a
//! progress line at least every [`PROGRESS_EVERY`]; sleep and progress are injectable.
//! Unhealthy and timed out are [`Health`] data; the sync flow turns them into errors. Only a
//! failed `az` call is an error here.
//! Once healthy, the `show` that confirmed it is fingerprinted again: a change outside the
//! managed names since the pre-update read is reported (Container Apps has no etag, Q8).
//!
//! # Access (R6)
//!
//! Advisory (doctor): an RBAC vault needs one of [`READ_ROLES`] for the app identity (or a
//! group it is in) at the vault scope or above; an access-policy vault needs a policy for it
//! with secret `get`. Full `az` objects are parsed (no `--query` projections), and each
//! finding names the vault and the command that grants access.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::az::{self, Effect};
use super::{AzureTarget, ConfigRoute, preflight};
use crate::domain::{
    AccessFinding, Binding, Health, RawSpec, Revision, RuntimeChange, RuntimeSnapshot,
};
use crate::error::Error;
use crate::ports::PinnedRuntime;
use crate::runner::{CommandRunner, Outcome, Output, status_text, unknown_text};

/// Delay between two health polls (R8).
pub const POLL_EVERY: Duration = Duration::from_secs(5);
/// Longest wait for a new revision (R8); the run budget may end it sooner (NR-4).
pub const WAIT_MAX: Duration = Duration::from_secs(300);
/// Longest gap between two progress lines while waiting (NR-4).
pub const PROGRESS_EVERY: Duration = Duration::from_secs(15);
/// Roles that let an identity read Key Vault secret values (R6).
pub const READ_ROLES: &[&str] = &[
    "Key Vault Secrets User",
    "Key Vault Secrets Officer",
    "Key Vault Administrator",
];

/// Prefix of the Container Apps secrets opv owns (R2).
const SECRET_PREFIX: &str = "opv-";
/// Status fields under `properties` that change without anyone editing the app.
const READ_ONLY: &[&str] = &[
    "provisioningState",
    "runningStatus",
    "latestRevisionName",
    "latestReadyRevisionName",
    "latestRevisionFqdn",
    "outboundIpAddresses",
    "eventStreamEndpoint",
];
const SECRETS: &str = "/properties/configuration/secrets";
/// Changed paths named in one error before "and N more".
const MAX_PATHS: usize = 5;

/// One Container App as the pinned-flow runtime (FR-28).
pub struct ContainerApp<'a> {
    pub runner: &'a dyn CommandRunner,
    pub target: &'a AzureTarget,
    /// Managed env names (from the template, FR-8).
    pub managed: BTreeSet<String>,
    poll_every: Duration,
    wait_max: Duration,
    /// The spec `apply` read just before its update, for the R9 check.
    applied_from: RefCell<Option<Value>>,
}

impl<'a> ContainerApp<'a> {
    pub fn new(
        runner: &'a dyn CommandRunner,
        target: &'a AzureTarget,
        managed: BTreeSet<String>,
    ) -> Self {
        Self {
            runner,
            target,
            managed,
            poll_every: POLL_EVERY,
            wait_max: WAIT_MAX,
            applied_from: RefCell::new(None),
        }
    }

    /// Replaces the health-poll interval and limit ([`POLL_EVERY`], [`WAIT_MAX`]).
    pub fn with_wait(mut self, poll_every: Duration, wait_max: Duration) -> Self {
        self.poll_every = poll_every;
        self.wait_max = wait_max;
        self
    }

    fn app(&self) -> &str {
        &self.target.container_app
    }

    fn rg(&self) -> &str {
        &self.target.resource_group
    }

    fn subject(&self) -> String {
        format!(
            "container app {} in resource group {}",
            self.app(),
            self.rg()
        )
    }

    fn show_hint(&self) -> String {
        format!(
            "az containerapp show -g {} -n {} --subscription {}",
            self.rg(),
            self.app(),
            self.target.subscription
        )
    }

    /// `base` plus `--only-show-errors` (R7) and `--subscription` (NR-7).
    fn argv(&self, base: &[&str]) -> Vec<String> {
        let mut v: Vec<String> = base.iter().map(|s| s.to_string()).collect();
        v.push(az::ONLY_SHOW_ERRORS.into());
        v.extend(["--subscription".into(), self.target.subscription.clone()]);
        v
    }

    /// One `az` call with typed, value-free errors. Child stderr is never captured (SR-1);
    /// a non-zero exit is diagnosed with `az account show` ([`Self::diagnose`]).
    fn az(
        &self,
        effect: Effect,
        what: &str,
        subject: &str,
        hint: &str,
        base: &[&str],
        stdin: Option<&[u8]>,
    ) -> Result<Output, Error> {
        let owned = self.argv(base);
        let args: Vec<&str> = owned.iter().map(String::as_str).collect();
        let outcome = az::invoke(self.runner, effect, what, &args, stdin, &[])?;
        match outcome {
            Outcome::Done(out) => Ok(out),
            Outcome::Refused(out) => Err(self.diagnose(effect, what, subject, hint, out.status)),
            Outcome::Unknown {
                status: Some(status),
                ..
            } => Err(self.diagnose(effect, what, subject, hint, status)),
            Outcome::Unknown { reason, .. } if effect == Effect::Write => Err(Error::Unknown(
                format!(
                    "az {what}: {}; the update may or may not have been applied, and Azure keeps \
                     the previous revision serving until a new one is ready\n  next: re-run \
                     the same command",
                    unknown_text(az::PROGRAM, reason)
                )
                .into(),
            )),
            Outcome::Unknown { reason, .. } => Err(Error::Target(
                format!(
                    "az {what}: {}; nothing was changed\n  next: re-run the same command",
                    unknown_text(az::PROGRAM, reason)
                )
                .into(),
            )),
        }
    }

    /// The error for a call that exited `status` (FR-26): `az account show`, exit status
    /// only, tells "not signed in" (Auth) from "signed in but refused" (Target; Unknown for
    /// the update, which may have reached Azure).
    fn diagnose(
        &self,
        effect: Effect,
        what: &str,
        subject: &str,
        hint: &str,
        status: i32,
    ) -> Error {
        let failed = format!("az {what} failed ({})", status_text(status));
        // The probe explains the failed call; its excerpt stays with the error (NR-31).
        match (
            crate::runner::diagnosing(|| az::signed_in(self.runner)),
            effect,
        ) {
            (Ok(false), _) => az::not_logged_in(Some(&failed)),
            (Ok(true), Effect::Read) => Error::Target(
                format!(
                    "{failed}: signed in to Azure, but {subject} could not be read; nothing was \
                 changed\n  next: check that it exists and that your account can read it: \
                 `{hint}`"
                )
                .into(),
            ),
            (Err(_), Effect::Read) => Error::Target(
                format!("{failed}; nothing was changed\n  next: run `{hint}` to see why").into(),
            ),
            (_, Effect::Write) => Error::Unknown(
                format!(
                    "{failed} for {subject}; the update may or may not have been applied, and \
                 Azure keeps the previous revision serving until a new one is ready\n  next: \
                 check that the app identity can read the referenced Key Vault secrets (opv \
                 doctor checks this) and `{hint}`, then re-run the same command"
                )
                .into(),
            ),
        }
    }

    fn show(&self) -> Result<Value, Error> {
        const WHAT: &str = "containerapp show";
        let out = self.az(
            Effect::Read,
            WHAT,
            &self.subject(),
            &self.show_hint(),
            &[
                "containerapp",
                "show",
                "-g",
                self.rg(),
                "-n",
                self.app(),
                "-o",
                "json",
            ],
            None,
        )?;
        parse(&out, WHAT)
    }

    fn revision_show(&self, rev: &str) -> Result<Value, Error> {
        const WHAT: &str = "containerapp revision show";
        let hint = format!(
            "az containerapp revision show -g {} -n {} --revision {rev}",
            self.rg(),
            self.app()
        );
        let out = self.az(
            Effect::Read,
            WHAT,
            &format!("revision {rev} of {}", self.subject()),
            &hint,
            &[
                "containerapp",
                "revision",
                "show",
                "-g",
                self.rg(),
                "-n",
                self.app(),
                "--revision",
                rev,
                "-o",
                "json",
            ],
            None,
        )?;
        parse(&out, WHAT)
    }

    /// The index of the managed container (R1).
    fn container_index(&self, spec: &Value) -> Result<usize, Error> {
        let names: Vec<&str> = spec
            .pointer("/properties/template/containers")
            .and_then(Value::as_array)
            .map(|cs| {
                cs.iter()
                    .map(|c| c["name"].as_str().unwrap_or(""))
                    .collect()
            })
            .unwrap_or_default();
        let next = "next: set azure.container in secrets.toml to one of those names";
        match &self.target.container {
            Some(want) => names.iter().position(|n| n == want).ok_or_else(|| {
                Error::Config(
                    format!(
                        "container app {} has no container {want} (it has: {}); nothing was \
                     changed\n  {next}",
                        self.app(),
                        names.join(", ")
                    )
                    .into(),
                )
            }),
            None if names.len() == 1 => Ok(0),
            None => Err(Error::Config(
                format!(
                    "container app {} runs {} containers ({}) and opv cannot tell which one to \
                 manage; nothing was changed\n  {next}",
                    self.app(),
                    names.len(),
                    names.join(", ")
                )
                .into(),
            )),
        }
    }

    fn is_managed(&self, env: &Value) -> bool {
        env["name"]
            .as_str()
            .is_some_and(|n| self.managed.contains(n))
    }

    /// `spec` without managed env entries, `opv-` secrets and read-only fields (FR-31).
    fn strip(&self, spec: &Value, idx: usize) -> Value {
        let mut v = spec.clone();
        if let Some(o) = v.as_object_mut() {
            o.remove("systemData");
        }
        if let Some(p) = v.get_mut("properties").and_then(Value::as_object_mut) {
            for k in READ_ONLY {
                p.remove(*k);
            }
        }
        if let Some(env) = v
            .pointer_mut(&format!("/properties/template/containers/{idx}/env"))
            .and_then(Value::as_array_mut)
        {
            env.retain(|e| !self.is_managed(e));
        }
        if let Some(s) = v.pointer_mut(SECRETS).and_then(Value::as_array_mut) {
            s.retain(|s| !is_opv_secret(s));
        }
        v
    }

    fn stripped(&self, spec: &Value) -> Result<Value, Error> {
        Ok(self.strip(spec, self.container_index(spec)?))
    }

    /// The vault's `properties.vaultUri` as read from Azure, without a trailing slash
    /// (NR-6; `https://<vault>.vault.azure.net` in the public cloud): kept by the preflight,
    /// else read once.
    fn vault_uri(&self) -> Result<String, Error> {
        preflight::vault_uri_of(self.target, self.runner)
    }

    /// `Pinned` for `<vault_uri>/secrets/<name>/<version>`, else `None`.
    fn reference(base: &str, url: &str) -> Option<Binding> {
        let prefix = format!("{}/secrets/", base.trim_end_matches('/'));
        let head = url.get(..prefix.len())?;
        if !head.eq_ignore_ascii_case(&prefix) {
            return None;
        }
        let mut parts = url[prefix.len()..].split('/');
        match (parts.next(), parts.next(), parts.next()) {
            (Some(name), Some(version), None) if !name.is_empty() && !version.is_empty() => {
                Some(Binding::Pinned {
                    store_name: name.into(),
                    version: version.into(),
                })
            }
            _ => None,
        }
    }

    fn snapshot_from(&self, spec: Value) -> Result<RuntimeSnapshot, Error> {
        let idx = self.container_index(&spec)?;
        let base = self.vault_uri()?;
        let empty = Vec::new();
        let secrets = spec
            .pointer(SECRETS)
            .and_then(Value::as_array)
            .unwrap_or(&empty);
        let env = spec
            .pointer(&format!("/properties/template/containers/{idx}/env"))
            .and_then(Value::as_array)
            .unwrap_or(&empty);
        let mut bindings = BTreeMap::new();
        for e in env.iter().filter(|e| self.is_managed(e)) {
            let binding = if let Some(v) = e.get("value").and_then(Value::as_str) {
                Binding::Plain {
                    digest: hex::encode(Sha256::digest(v)),
                }
            } else if let Some(r) = e.get("secretRef").and_then(Value::as_str) {
                secrets
                    .iter()
                    .find(|s| s["name"].as_str() == Some(r))
                    .and_then(|s| s["keyVaultUrl"].as_str())
                    .and_then(|u| Self::reference(&base, u))
                    .unwrap_or(Binding::Other)
            } else {
                Binding::Other
            };
            bindings.insert(e["name"].as_str().unwrap_or_default().to_string(), binding);
        }
        let unmanaged_fingerprint = fingerprint(&self.strip(&spec, idx));
        let revision = spec
            .pointer("/properties/latestRevisionName")
            .and_then(Value::as_str)
            .filter(|r| !r.is_empty())
            .map(|r| Revision(r.into()));
        Ok(RuntimeSnapshot {
            bindings,
            unmanaged_fingerprint,
            revision,
            spec: RawSpec(spec),
        })
    }

    /// JSON pointers of the unmanaged nodes that differ between two specs (names only).
    fn changed_paths(&self, before: &Value, after: &Value) -> Result<String, Error> {
        let mut out = Vec::new();
        diff(
            &self.stripped(before)?,
            &self.stripped(after)?,
            "",
            &mut out,
        );
        let more = out.len().saturating_sub(MAX_PATHS);
        out.truncate(MAX_PATHS);
        let mut s = out.join(", ");
        if more > 0 {
            s.push_str(&format!(" and {more} more"));
        }
        Ok(s)
    }

    /// The fresh spec with `change` applied (R2, Q5). Superseded secrets stay; see
    /// [`prune_superseded`].
    fn edit(&self, doc: &mut Value, idx: usize, change: &RuntimeChange) -> Result<(), Error> {
        let env = array_field(&mut doc["properties"]["template"]["containers"][idx], "env");
        for (name, (store, version)) in &change.pin {
            upsert(
                env,
                json!({"name": name, "secretRef": secret_name(store, version)}),
            );
        }
        for (name, value) in &change.set {
            upsert(env, json!({"name": name, "value": value}));
        }
        env.retain(|e| {
            !e["name"]
                .as_str()
                .is_some_and(|n| change.unbind.iter().any(|u| u == n))
        });
        let base = self.vault_uri()?;
        let base = base.trim_end_matches('/');
        let secrets = array_field(&mut doc["properties"]["configuration"], "secrets");
        for (store, version) in change.pin.values() {
            upsert(
                secrets,
                json!({
                    "name": secret_name(store, version),
                    "keyVaultUrl": format!("{base}/secrets/{store}/{version}"),
                    "identity": self.target.identity,
                }),
            );
        }
        Ok(())
    }

    /// The `secretRef`s of the revision serving now (`latestReadyRevisionName`), read from
    /// that revision's own template: the app's template may already belong to a newer
    /// revision that is not ready yet. Empty when no revision is ready.
    fn serving_refs(&self, app: &Value) -> Result<BTreeSet<String>, Error> {
        match app
            .pointer("/properties/latestReadyRevisionName")
            .and_then(Value::as_str)
            .filter(|r| !r.is_empty())
        {
            Some(ready) => Ok(env_refs(&self.revision_show(ready)?)),
            None => Ok(BTreeSet::new()),
        }
    }

    /// R9: once healthy, the unmanaged part must still match the spec `apply` read.
    fn verify_unchanged(&self, rev: &str, now: &Value) -> Result<(), Error> {
        let Some(before) = self.applied_from.borrow_mut().take() else {
            return Ok(());
        };
        if fingerprint(&self.stripped(&before)?) == fingerprint(&self.stripped(now)?) {
            return Ok(());
        }
        Err(Error::Target(
            format!(
                "container app {} changed while opv applied ({}); check those settings\n  revision \
             {rev} is healthy and serving; opv changed only its managed env names and their \
             opv- secrets\n  next: find out who else changed the app (another deploy?), then \
             run opv status",
                self.app(),
                self.changed_paths(&before, now)?
            )
            .into(),
        ))
    }

    /// The app identity's principal id (R6), or the finding when the app has none that opv
    /// can use. A user-assigned identity must be attached to the app; its principal comes
    /// from the app (`identity.userAssignedIdentities`), else from `az identity show`.
    fn principal(&self, app: &Value) -> Result<Result<String, String>, Error> {
        let (rg, name, kv) = (self.rg(), self.app(), &self.target.key_vault);
        let id = &self.target.identity;
        if id.eq_ignore_ascii_case("system") {
            return Ok(app
                .pointer("/identity/principalId")
                .and_then(Value::as_str)
                .filter(|p| !p.is_empty())
                .map(String::from)
                .ok_or_else(|| {
                    format!(
                        "container app {name} has no system-assigned identity to read Key Vault \
                         {kv} with; assign one: `az containerapp identity assign -g {rg} -n \
                         {name} --system-assigned`, then grant it read access to {kv}"
                    )
                }));
        }
        let attached = app
            .pointer("/identity/userAssignedIdentities")
            .and_then(Value::as_object)
            .and_then(|m| m.iter().find(|(k, _)| k.eq_ignore_ascii_case(id)))
            .map(|(_, v)| v);
        let Some(entry) = attached else {
            return Ok(Err(format!(
                "container app {name} does not have the user-assigned identity {id} that \
                 secrets.toml names; attach it: `az containerapp identity assign -g {rg} -n \
                 {name} --user-assigned {id}`"
            )));
        };
        if let Some(p) = entry["principalId"].as_str().filter(|p| !p.is_empty()) {
            return Ok(Ok(p.to_string()));
        }
        let out = self.az(
            Effect::Read,
            "identity show",
            &format!("managed identity {id}"),
            &format!("az identity show --ids {id}"),
            &["identity", "show", "--ids", id, "-o", "json"],
            None,
        )?;
        Ok(parse(&out, "identity show")?["principalId"]
            .as_str()
            .filter(|p| !p.is_empty())
            .map(String::from)
            .ok_or_else(|| {
                format!(
                    "the user-assigned identity {id} has no principal id; check it with `az \
                     identity show --ids {id}`"
                )
            }))
    }
}

impl PinnedRuntime for ContainerApp<'_> {
    fn bindings(&self) -> Result<RuntimeSnapshot, Error> {
        self.snapshot_from(self.show()?)
    }

    fn apply(&self, change: &RuntimeChange, snapshot: &RuntimeSnapshot) -> Result<Revision, Error> {
        if let Some(name) = change
            .pin
            .keys()
            .chain(change.set.keys())
            .chain(&change.unbind)
            .find(|n| !self.managed.contains(*n))
        {
            return Err(Error::Config(
                format!(
                    "{name} is not a managed env name of container app {}; nothing was changed\n  \
                 next: run opv plan to see the managed names, then run opv again",
                    self.app()
                )
                .into(),
            ));
        }
        let fresh = self.show()?;
        single_revision_mode(self.target, &fresh)?;
        let fresh = self.snapshot_from(fresh)?;
        if fresh.unmanaged_fingerprint != snapshot.unmanaged_fingerprint {
            return Err(Error::Target(
                format!(
                    "container app {} changed outside opv since it was read ({}); nothing was \
                 changed\n  next: run opv plan to review the app as it is now, then run the \
                 same command again",
                    self.app(),
                    self.changed_paths(&snapshot.spec.0, &fresh.spec.0)?
                )
                .into(),
            ));
        }
        let mut doc = fresh.spec.0.clone();
        let idx = self.container_index(&doc)?;
        self.edit(&mut doc, idx, change)?;
        prune_superseded(&mut doc, &self.serving_refs(&fresh.spec.0)?);
        let body = Zeroizing::new(serde_json::to_vec(&doc).map_err(|_| {
            Error::Target(
                format!(
                    "could not encode the update for container app {}; nothing was changed\n  \
                 next: run opv again",
                    self.app()
                )
                .into(),
            )
        })?);
        const WHAT: &str = "containerapp update";
        let out = self.az(
            Effect::Write,
            WHAT,
            &self.subject(),
            &self.show_hint(),
            &[
                "containerapp",
                "update",
                "-g",
                self.rg(),
                "-n",
                self.app(),
                "--yaml",
                "/dev/stdin",
                "-o",
                "json",
            ],
            Some(&body),
        )?;
        *self.applied_from.borrow_mut() = Some(fresh.spec.0);
        let applied = "the update was applied; Azure keeps the previous revision serving until \
                       the new one is ready";
        parse_with(&out, WHAT, applied)?
            .pointer("/properties/latestRevisionName")
            .and_then(Value::as_str)
            .map(|r| Revision(r.into()))
            .ok_or_else(|| {
                Error::Target(
                    format!(
                        "az {WHAT} named no new revision for container app {}; {applied}\n  next: \
                     `{}` to see its revisions, then run opv status",
                        self.app(),
                        self.show_hint()
                    )
                    .into(),
                )
            })
    }

    fn await_healthy(&self, revision: &Revision) -> Result<Health, Error> {
        let rev = revision.0.as_str();
        let mut waited = Duration::ZERO;
        let mut reported: Option<Duration> = None;
        loop {
            let r = self.revision_show(rev)?;
            let state = |k: &str| {
                r.pointer(&format!("/properties/{k}"))
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string()
            };
            let (prov, run, health) = (
                state("provisioningState"),
                state("runningState"),
                state("healthState"),
            );
            if prov == "Failed" || run == "Failed" || health == "Unhealthy" {
                return Ok(Health::Unhealthy(format!(
                    "revision {rev}: provisioningState {prov}, runningState {run}, healthState \
                     {health}; see why with `az containerapp revision show -g {} -n {} \
                     --revision {rev}`",
                    self.rg(),
                    self.app()
                )));
            }
            let mut last = format!("{prov}/{run}/{health}");
            let up = prov == "Provisioned"
                && (run == "ScaledToZero"
                    || (matches!(run.as_str(), "Running" | "RunningAtMaxScale")
                        && health == "Healthy"));
            if up {
                let app = self.show()?;
                let ready = app
                    .pointer("/properties/latestReadyRevisionName")
                    .and_then(Value::as_str);
                if ready == Some(rev) {
                    self.verify_unchanged(rev, &app)?;
                    return Ok(Health::Healthy);
                }
                last.push_str(&format!(
                    ", still serving {}",
                    ready.unwrap_or("no revision")
                ));
            }
            if waited >= self.wait_max {
                return Ok(Health::TimedOut);
            }
            let note = if reported.is_none_or(|at| waited - at >= PROGRESS_EVERY) {
                reported = Some(waited);
                format!(
                    "waiting for revision {rev} of container app {}: {last}, {} s",
                    self.app(),
                    waited.as_secs()
                )
            } else {
                String::new()
            };
            self.runner.pause(self.poll_every, &note);
            waited += self.poll_every;
        }
    }

    fn config_in_store(&self) -> bool {
        self.target.config == ConfigRoute::Store
    }

    fn describe(&self) -> String {
        format!("container app {}", self.app())
    }

    fn inspect_hint(&self, revision: &Revision) -> String {
        format!(
            "az containerapp revision show -g {} -n {} --revision {}",
            self.rg(),
            self.app(),
            revision.0
        )
    }

    fn check_access(&self, names: &[String]) -> Result<Vec<AccessFinding>, Error> {
        let each = |reason: String| {
            names
                .iter()
                .map(|n| AccessFinding {
                    store_name: n.clone(),
                    reason: reason.clone(),
                })
                .collect()
        };
        let app = self.show()?;
        let principal = match self.principal(&app)? {
            Ok(p) => p,
            Err(reason) => return Ok(each(reason)),
        };
        let kv = &self.target.key_vault;
        let kv_subject = format!("Key Vault {kv}");
        let kv_hint = format!(
            "az keyvault show -n {kv} --subscription {}",
            self.target.subscription
        );
        let out = self.az(
            Effect::Read,
            "keyvault show",
            &kv_subject,
            &kv_hint,
            &["keyvault", "show", "-n", kv, "-o", "json"],
            None,
        )?;
        let vault = parse(&out, "keyvault show")?;
        let rbac = vault
            .pointer("/properties/enableRbacAuthorization")
            .and_then(Value::as_bool);
        if rbac != Some(true) {
            return Ok(if policy_grants_get(&vault, &principal) {
                Vec::new()
            } else {
                each(format!(
                    "the app identity (principal {principal}) has no access policy with secret \
                     get on Key Vault {kv}; grant it: `az keyvault set-policy -n {kv} \
                     --object-id {principal} --secret-permissions get`"
                ))
            });
        }
        let scope =
            vault["id"].as_str().ok_or_else(|| {
                Error::Target(format!(
                "az keyvault show returned no id for Key Vault {kv}; nothing was changed\n  \
                 next: check it with `{kv_hint}`"
            ).into())
            })?;
        let out = self.az(
            Effect::Read,
            "role assignment list",
            &kv_subject,
            &kv_hint,
            &[
                "role",
                "assignment",
                "list",
                "--assignee",
                &principal,
                "--scope",
                scope,
                "--include-inherited",
                "--include-groups",
                "-o",
                "json",
            ],
            None,
        )?;
        let roles = parse(&out, "role assignment list")?;
        let has_role = roles.as_array().is_some_and(|rs| {
            rs.iter()
                .filter_map(|r| r["roleDefinitionName"].as_str())
                .any(|r| READ_ROLES.contains(&r))
        });
        Ok(if has_role {
            Vec::new()
        } else {
            each(format!(
                "the app identity (principal {principal}) has no Key Vault secrets read role on \
                 Key Vault {kv}; grant it: `az role assignment create --assignee-object-id \
                 {principal} --assignee-principal-type ServicePrincipal --role \"Key Vault \
                 Secrets User\" --scope {scope}` (a new grant can take a few minutes to apply)"
            ))
        })
    }
}

/// Refuses an app not in single-revision mode (NR-25): opv pins by replacing the one
/// active revision.
pub(crate) fn single_revision_mode(t: &AzureTarget, app: &Value) -> Result<(), Error> {
    match app
        .pointer("/properties/configuration/activeRevisionsMode")
        .and_then(Value::as_str)
        .filter(|m| !m.eq_ignore_ascii_case("single"))
    {
        Some(mode) => Err(Error::Config(
            format!(
                "container app {app} runs in {mode} revision mode; opv supports single-revision \
             mode only; nothing was changed\n  next: `az containerapp revision set-mode -g {rg} \
             -n {app} --mode single --subscription {sub}`, or keep managing this app's \
             revisions by hand",
                app = t.container_app,
                rg = t.resource_group,
                sub = t.subscription
            )
            .into(),
        )),
        None => Ok(()),
    }
}

/// Whether an access-policy vault (full `keyvault show` object) lets `principal` get secrets.
fn policy_grants_get(vault: &Value, principal: &str) -> bool {
    vault
        .pointer("/properties/accessPolicies")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|p| {
            p["objectId"]
                .as_str()
                .is_some_and(|o| o.eq_ignore_ascii_case(principal))
        })
        .filter_map(|p| p.pointer("/permissions/secrets").and_then(Value::as_array))
        .flatten()
        .filter_map(Value::as_str)
        .any(|p| p.eq_ignore_ascii_case("get") || p.eq_ignore_ascii_case("all"))
}

/// The Container Apps secret name for one Key Vault version (R2): `opv-` and the first 16
/// hex chars of SHA-256(lower-case store name + `/` + version). Per version, so a repin is
/// a template change and Azure starts a new revision (Q16).
pub fn secret_name(store_name: &str, version: &str) -> String {
    let digest = hex::encode(Sha256::digest(format!(
        "{}/{version}",
        store_name.to_ascii_lowercase()
    )));
    format!("{SECRET_PREFIX}{}", &digest[..16])
}

/// Parses a read's output; nothing has changed when it fails.
fn parse(out: &Output, what: &str) -> Result<Value, Error> {
    parse_with(out, what, "nothing was changed")
}

/// Parses `out`; `state` says what is true when the JSON is unreadable.
fn parse_with(out: &Output, what: &str, state: &str) -> Result<Value, Error> {
    // serde_json messages can quote input fragments, so report only the position.
    serde_json::from_slice(&out.stdout).map_err(|e| {
        Error::Target(format!(
            "az {what} returned JSON opv cannot read (line {}, column {}); {state}\n  next: update \
             the Azure CLI (`az upgrade`), then run opv again",
            e.line(),
            e.column()
        ).into())
    })
}

/// SHA-256 hex of the canonical JSON: serde_json maps are sorted by key.
fn fingerprint(v: &Value) -> String {
    hex::encode(Sha256::digest(v.to_string()))
}

/// Removes each `opv-` secret that neither the edited template nor `serving` (the
/// references of the revision serving now) uses (R2, NR-1).
fn prune_superseded(doc: &mut Value, serving: &BTreeSet<String>) {
    let used = env_refs(doc);
    if let Some(secrets) = doc.pointer_mut(SECRETS).and_then(Value::as_array_mut) {
        secrets.retain(|s| {
            let name = s["name"].as_str().unwrap_or_default();
            !is_opv_secret(s) || used.contains(name) || serving.contains(name)
        });
    }
}

fn is_opv_secret(s: &Value) -> bool {
    s["name"]
        .as_str()
        .is_some_and(|n| n.starts_with(SECRET_PREFIX))
}

/// Every `secretRef` of every container and init container.
fn env_refs(doc: &Value) -> BTreeSet<String> {
    ["containers", "initContainers"]
        .iter()
        .filter_map(|k| doc["properties"]["template"][k].as_array())
        .flatten()
        .filter_map(|c| c["env"].as_array())
        .flatten()
        .filter_map(|e| e["secretRef"].as_str().map(String::from))
        .collect()
}

/// `obj[key]` as an array, created when absent or null.
fn array_field<'v>(obj: &'v mut Value, key: &str) -> &'v mut Vec<Value> {
    if !obj[key].is_array() {
        obj[key] = json!([]);
    }
    obj[key].as_array_mut().expect("just made an array")
}

/// Replaces the entry with the same `name` in place, or appends.
fn upsert(list: &mut Vec<Value>, entry: Value) {
    match list.iter_mut().find(|e| e["name"] == entry["name"]) {
        Some(e) => *e = entry,
        None => list.push(entry),
    }
}

/// Appends the JSON pointer of every node that differs between `a` and `b`.
fn diff(a: &Value, b: &Value, path: &str, out: &mut Vec<String>) {
    let at = |k: &str| format!("{path}/{}", k.replace('~', "~0").replace('/', "~1"));
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            let keys: BTreeSet<&String> = x.keys().chain(y.keys()).collect();
            for k in keys {
                match (x.get(k), y.get(k)) {
                    (Some(p), Some(q)) => diff(p, q, &at(k), out),
                    _ => out.push(at(k)),
                }
            }
        }
        (Value::Array(x), Value::Array(y)) if x.len() == y.len() => {
            for (i, (p, q)) in x.iter().zip(y).enumerate() {
                diff(p, q, &at(&i.to_string()), out);
            }
        }
        _ if a != b => out.push(if path.is_empty() {
            "/".into()
        } else {
            path.into()
        }),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::io;
    use std::time::Duration;

    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::adapters::azure::{AzureTarget, ConfigRoute};
    use crate::domain::Binding;
    use crate::runner::Output;
    use crate::runner::fake::{FakeRunner, failed_read};

    /// The config value recorded in the show fixture (a marker, R10).
    const CONFIG_MARK: &str = "opv-fixture-config-marker";
    const NEW_CONFIG: &str = "opv-marker-config-new";
    const VAULT_URI: &str = "https://kv-opv-fixture.vault.azure.net";
    const SUBSCRIPTION: &str = "00000000-0000-0000-0000-000000000000";
    const DB_URL: &str = "FLEET__API__DB_URL";
    const DB_STORE: &str = "FLEET--API--DB-URL";
    /// Version id bound in the show fixture, and the one the update fixture repins to.
    const OLD_VERSION: &str = "46687ce78b76487cb0c1da470360b638";
    const NEW_VERSION: &str = "127c341a4e8e4388b2312b4ae6a63007";
    /// Secret name recorded for NEW_VERSION in the update fixture (R2, Q16).
    const NEW_SECRET: &str = "opv-5ecdfe5c4e0ce510";
    const OLD_SECRET: &str = "opv-8fdafc4d16ff6017";
    const REV: &str = "opv-fixture-app--0000002";
    const USER_IDENTITY: &str = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/opv-fixture-rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/opv-fixture-id";

    fn fixture(name: &str) -> Value {
        let path = format!("{}/tests/fixtures/azure/{name}", env!("CARGO_MANIFEST_DIR"));
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn show() -> Value {
        fixture("containerapp-show.json")
    }

    fn update_out() -> Value {
        fixture("containerapp-update.json")
    }

    /// The recorded revision: its template references `OLD_SECRET`.
    fn serving_revision() -> Value {
        fixture("containerapp-revision-show.json")
    }

    /// What `apply` reads and gets back, in order: the app, the revision serving now (when
    /// one is ready), the update output.
    fn apply_responses(fresh: &Value, serving: &Value) -> Vec<Output> {
        let mut v = vec![out(fresh)];
        if fresh["properties"]["latestReadyRevisionName"].is_string() {
            v.push(out(serving));
        }
        v.push(out(&update_out()));
        v
    }

    /// The recorded revision with its states replaced (R10: edited copy of a recon output).
    fn revision(provisioning: &str, running: &str, health: &str) -> Value {
        let mut v = fixture("containerapp-revision-show.json");
        v["name"] = json!(REV);
        v["properties"]["provisioningState"] = json!(provisioning);
        v["properties"]["runningState"] = json!(running);
        v["properties"]["healthState"] = json!(health);
        v
    }

    fn healthy_revision() -> Value {
        revision("Provisioned", "Running", "Healthy")
    }

    /// The show fixture once `REV` is the latest ready revision.
    fn show_ready() -> Value {
        let mut v = show();
        v["properties"]["latestReadyRevisionName"] = json!(REV);
        v
    }

    fn out(v: &Value) -> Output {
        Output::success(serde_json::to_vec(v).unwrap())
    }

    /// A vault URI the preflight already read.
    fn kept(uri: &str) -> super::super::config::ResolvedUri {
        let kept = super::super::config::ResolvedUri::default();
        kept.set(uri.into());
        kept
    }

    fn target() -> AzureTarget {
        AzureTarget {
            subscription: SUBSCRIPTION.into(),
            key_vault: "kv-opv-fixture".into(),
            resource_group: "opv-fixture-rg".into(),
            container_app: "opv-fixture-app".into(),
            container: None,
            identity: "system".into(),
            env_name_template: "FLEET__{PRODUCT}__{KEY}".into(),
            config: ConfigRoute::Env,
            vault_uri: kept(VAULT_URI),
        }
    }

    fn managed() -> BTreeSet<String> {
        [DB_URL, "LOG_LEVEL"]
            .into_iter()
            .map(String::from)
            .collect()
    }

    fn adapter<'a>(
        r: &'a FakeRunner,
        t: &'a AzureTarget,
        m: &'a BTreeSet<String>,
    ) -> ContainerApp<'a> {
        ContainerApp::new(r, t, m.clone())
            .with_wait(Duration::from_secs(5), Duration::from_secs(10))
    }

    fn no_change() -> RuntimeChange {
        RuntimeChange {
            pin: BTreeMap::new(),
            set: BTreeMap::new(),
            unbind: vec![],
            stamp: None,
        }
    }

    fn repin() -> RuntimeChange {
        let mut c = no_change();
        c.pin
            .insert(DB_URL.into(), (DB_STORE.into(), NEW_VERSION.into()));
        c
    }

    fn set_config() -> RuntimeChange {
        let mut c = no_change();
        c.set.insert("LOG_LEVEL".into(), NEW_CONFIG.into());
        c
    }

    /// Snapshot of `spec` as `bindings` reads it.
    fn snapshot_of(spec: &Value) -> RuntimeSnapshot {
        let (t, m) = (target(), managed());
        let r = FakeRunner::new([out(spec)]);
        adapter(&r, &t, &m).bindings().unwrap()
    }

    /// Runs `apply(change)` against `before` (the snapshot) and `fresh` (the re-read).
    fn apply_on(
        before: &Value,
        fresh: &Value,
        change: &RuntimeChange,
    ) -> (FakeRunner, Result<Revision, Error>) {
        apply_serving(before, fresh, &serving_revision(), change)
    }

    /// `apply_on` with `serving` as the revision `latestReadyRevisionName` names.
    fn apply_serving(
        before: &Value,
        fresh: &Value,
        serving: &Value,
        change: &RuntimeChange,
    ) -> (FakeRunner, Result<Revision, Error>) {
        let snap = snapshot_of(before);
        let (t, m) = (target(), managed());
        let r = FakeRunner::new(apply_responses(fresh, serving));
        let res = adapter(&r, &t, &m).apply(change, &snap);
        (r, res)
    }

    /// The stdin document of the one call that carried stdin (the update).
    fn stdin_doc(r: &FakeRunner) -> Value {
        let calls = r.calls.borrow();
        let update = calls.iter().find(|c| c.stdin.is_some()).unwrap();
        serde_json::from_slice(update.stdin.as_ref().unwrap()).unwrap()
    }

    /// The document `apply` sent on stdin.
    fn sent(change: &RuntimeChange) -> Value {
        sent_from(&show(), change)
    }

    fn sent_from(spec: &Value, change: &RuntimeChange) -> Value {
        let (r, res) = apply_on(spec, spec, change);
        res.unwrap();
        stdin_doc(&r)
    }

    fn sent_env(doc: &Value) -> Vec<Value> {
        doc["properties"]["template"]["containers"][0]["env"]
            .as_array()
            .unwrap()
            .clone()
    }

    fn sent_secrets(doc: &Value) -> Vec<Value> {
        doc["properties"]["configuration"]["secrets"]
            .as_array()
            .unwrap()
            .clone()
    }

    fn bindings_of(spec: &Value) -> BTreeMap<String, Binding> {
        snapshot_of(spec).bindings
    }

    fn with_two_containers() -> Value {
        let mut v = show();
        let mut sidecar = v["properties"]["template"]["containers"][0].clone();
        sidecar["name"] = json!("sidecar");
        sidecar["env"] = json!([]);
        v["properties"]["template"]["containers"]
            .as_array_mut()
            .unwrap()
            .push(sidecar);
        v
    }

    fn err_text<T: std::fmt::Debug>(r: Result<T, Error>) -> String {
        r.unwrap_err().to_string()
    }

    // ---- bindings ----

    #[test]
    fn bindings_reads_pinned_reference() {
        assert_eq!(
            bindings_of(&show())[DB_URL],
            Binding::Pinned {
                store_name: DB_STORE.into(),
                version: OLD_VERSION.into()
            }
        );
    }

    #[test]
    fn bindings_reads_plain_config_as_sha256_digest() {
        assert_eq!(
            bindings_of(&show())["LOG_LEVEL"],
            Binding::Plain {
                digest: hex::encode(Sha256::digest(CONFIG_MARK))
            }
        );
    }

    #[test]
    fn bindings_reads_plain_config_as_digest_only() {
        assert!(!format!("{:?}", snapshot_of(&show())).contains(CONFIG_MARK));
    }

    #[test]
    fn bindings_marks_unversioned_reference_as_other() {
        let mut v = show();
        v["properties"]["configuration"]["secrets"][1]["keyVaultUrl"] =
            json!(format!("{VAULT_URI}/secrets/{DB_STORE}"));
        assert_eq!(bindings_of(&v)[DB_URL], Binding::Other);
    }

    #[test]
    fn bindings_marks_reference_to_another_vault_as_other() {
        let mut v = show();
        v["properties"]["configuration"]["secrets"][1]["keyVaultUrl"] = json!(format!(
            "https://kv-elsewhere.vault.azure.net/secrets/{DB_STORE}/{OLD_VERSION}"
        ));
        assert_eq!(bindings_of(&v)[DB_URL], Binding::Other);
    }

    #[test]
    fn bindings_leave_unmanaged_env_names_out() {
        let m: BTreeSet<String> = [DB_URL.to_string()].into();
        let t = target();
        let r = FakeRunner::new([out(&show())]);
        let snap = adapter(&r, &t, &m).bindings().unwrap();
        assert!(!snap.bindings.contains_key("LOG_LEVEL"));
    }

    #[test]
    fn bindings_with_two_containers_and_no_container_setting_is_config_error() {
        let (t, m) = (target(), managed());
        let r = FakeRunner::new([out(&with_two_containers())]);
        assert!(matches!(
            adapter(&r, &t, &m).bindings(),
            Err(Error::Config(_))
        ));
    }

    #[test]
    fn two_containers_error_lists_the_container_names() {
        let (t, m) = (target(), managed());
        let r = FakeRunner::new([out(&with_two_containers())]);
        assert!(err_text(adapter(&r, &t, &m).bindings()).contains("opv-fixture-app, sidecar"));
    }

    #[test]
    fn bindings_read_the_configured_container() {
        let mut t = target();
        t.container = Some("sidecar".into());
        let m = managed();
        let r = FakeRunner::new([out(&with_two_containers())]);
        assert!(adapter(&r, &t, &m).bindings().unwrap().bindings.is_empty());
    }

    #[test]
    fn fingerprint_ignores_read_only_fields() {
        let mut moved = show();
        moved["properties"]["latestRevisionName"] = json!("opv-fixture-app--0000009");
        moved["properties"]["provisioningState"] = json!("InProgress");
        moved["systemData"]["lastModifiedAt"] = json!("2026-10-09T00:00:00");
        assert_eq!(
            snapshot_of(&moved).unmanaged_fingerprint,
            snapshot_of(&show()).unmanaged_fingerprint
        );
    }

    #[test]
    fn fingerprint_ignores_managed_env_values() {
        let mut moved = show();
        moved["properties"]["template"]["containers"][0]["env"][1]["value"] = json!(NEW_CONFIG);
        assert_eq!(
            snapshot_of(&moved).unmanaged_fingerprint,
            snapshot_of(&show()).unmanaged_fingerprint
        );
    }

    #[test]
    fn fingerprint_covers_unmanaged_settings() {
        let mut moved = show();
        moved["properties"]["configuration"]["ingress"]["targetPort"] = json!(8080);
        assert_ne!(
            snapshot_of(&moved).unmanaged_fingerprint,
            snapshot_of(&show()).unmanaged_fingerprint
        );
    }

    #[test]
    fn bindings_when_signed_out_is_auth_error() {
        let (t, m) = (target(), managed());
        let r = FakeRunner::new(failed_read(1).chain([Output::failure(1)]));
        assert!(matches!(
            adapter(&r, &t, &m).bindings(),
            Err(Error::Auth(_))
        ));
    }

    #[test]
    fn bindings_when_signed_in_is_target_error() {
        let (t, m) = (target(), managed());
        let r = FakeRunner::new(failed_read(3).chain([Output::success("")]));
        assert!(matches!(
            adapter(&r, &t, &m).bindings(),
            Err(Error::Target(_))
        ));
    }

    #[test]
    fn missing_az_is_dependency_error() {
        let (t, m) = (target(), managed());
        let r = FakeRunner::default();
        r.push_io_error(io::ErrorKind::NotFound);
        assert!(matches!(
            adapter(&r, &t, &m).bindings(),
            Err(Error::Dependency(_))
        ));
    }

    // ---- apply ----

    #[test]
    fn apply_sends_spec_on_stdin_and_no_values_in_argv() {
        let (r, _) = apply_on(&show(), &show(), &set_config());
        assert!(!r.argv_contains(NEW_CONFIG));
    }

    #[test]
    fn apply_sends_config_value_inside_the_stdin_spec() {
        assert!(
            sent_env(&sent(&set_config()))
                .contains(&json!({"name": "LOG_LEVEL", "value": NEW_CONFIG}))
        );
    }

    #[test]
    fn apply_updates_through_dev_stdin() {
        let (r, _) = apply_on(&show(), &show(), &set_config());
        assert_eq!(
            r.calls.borrow().last().unwrap().args,
            [
                "containerapp",
                "update",
                "-g",
                "opv-fixture-rg",
                "-n",
                "opv-fixture-app",
                "--yaml",
                "/dev/stdin",
                "-o",
                "json",
                "--only-show-errors",
                "--subscription",
                SUBSCRIPTION
            ]
        );
    }

    #[test]
    fn secret_name_hashes_lower_case_store_name_and_version() {
        assert_eq!(secret_name(DB_STORE, NEW_VERSION), NEW_SECRET);
    }

    #[test]
    fn apply_names_secret_per_version() {
        assert!(
            sent_env(&sent(&repin())).contains(&json!({"name": DB_URL, "secretRef": NEW_SECRET}))
        );
    }

    #[test]
    fn apply_pins_reference_with_version() {
        assert!(sent_secrets(&sent(&repin())).contains(&json!({
            "name": NEW_SECRET,
            "keyVaultUrl": format!("{VAULT_URI}/secrets/{DB_STORE}/{NEW_VERSION}"),
            "identity": "system"
        })));
    }

    #[test]
    fn apply_writes_user_assigned_identity_verbatim() {
        let mut t = target();
        t.identity = USER_IDENTITY.into();
        let m = managed();
        let snap = snapshot_of(&show());
        let r = FakeRunner::new(apply_responses(&show(), &serving_revision()));
        adapter(&r, &t, &m).apply(&repin(), &snap).unwrap();
        let doc = stdin_doc(&r);
        assert!(
            sent_secrets(&doc)
                .iter()
                .any(|s| s["identity"] == json!(USER_IDENTITY))
        );
    }

    #[test]
    fn apply_keeps_secret_the_serving_revision_references() {
        assert!(
            sent_secrets(&sent(&repin()))
                .iter()
                .any(|s| s["name"] == json!(OLD_SECRET))
        );
    }

    #[test]
    fn apply_removes_superseded_opv_secret() {
        let mut v = show();
        v["properties"]["configuration"]["secrets"]
            .as_array_mut()
            .unwrap()
            .push(json!({"identity": "system", "keyVaultUrl": format!("{VAULT_URI}/secrets/{DB_STORE}/0000"), "name": "opv-0000000000000000"}));
        assert!(
            !sent_secrets(&sent_from(&v, &repin()))
                .iter()
                .any(|s| s["name"] == json!("opv-0000000000000000"))
        );
    }

    /// A previous apply whose revision is not ready yet: the app template binds `PENDING`
    /// while the serving revision (the recorded one) still binds `OLD_SECRET`.
    const PENDING: &str = "opv-1111111111111111";

    fn with_pending_revision() -> Value {
        let mut v = show();
        v["properties"]["configuration"]["secrets"]
            .as_array_mut()
            .unwrap()
            .push(json!({"identity": "system", "keyVaultUrl": format!("{VAULT_URI}/secrets/{DB_STORE}/1111"), "name": PENDING}));
        v["properties"]["template"]["containers"][0]["env"][0]["secretRef"] = json!(PENDING);
        v["properties"]["latestRevisionName"] = json!("opv-fixture-app--0000003");
        v
    }

    #[test]
    fn apply_keeps_secret_of_serving_revision_while_a_newer_one_is_not_ready() {
        let v = with_pending_revision();
        assert!(
            sent_secrets(&sent_from(&v, &repin()))
                .iter()
                .any(|s| s["name"] == json!(OLD_SECRET))
        );
    }

    #[test]
    fn apply_removes_secret_of_unready_revision_once_superseded() {
        let v = with_pending_revision();
        assert!(
            !sent_secrets(&sent_from(&v, &repin()))
                .iter()
                .any(|s| s["name"] == json!(PENDING))
        );
    }

    #[test]
    fn apply_reads_the_latest_ready_revision() {
        let (r, _) = apply_on(&show(), &show(), &repin());
        assert!(
            r.calls.borrow()[1]
                .args
                .windows(2)
                .any(|w| w == ["--revision", "opv-fixture-app--jrh59ni"])
        );
    }

    #[test]
    fn apply_without_ready_revision_removes_unreferenced_opv_secret() {
        let mut v = show();
        v["properties"]["latestReadyRevisionName"] = Value::Null;
        assert!(
            !sent_secrets(&sent_from(&v, &repin()))
                .iter()
                .any(|s| s["name"] == json!(OLD_SECRET))
        );
    }

    #[test]
    fn apply_refuses_labels_revision_mode() {
        let mut v = show();
        v["properties"]["configuration"]["activeRevisionsMode"] = json!("Labels");
        let (_, res) = apply_on(&v, &v, &repin());
        assert!(matches!(res, Err(Error::Config(_))));
    }

    #[test]
    fn apply_keeps_unmanaged_env_vars_unchanged() {
        let mut v = show();
        v["properties"]["template"]["containers"][0]["env"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name": "OTHER", "value": "opv-marker-unmanaged"}));
        assert!(
            sent_env(&sent_from(&v, &set_config()))
                .contains(&json!({"name": "OTHER", "value": "opv-marker-unmanaged"}))
        );
    }

    #[test]
    fn apply_keeps_unmanaged_plain_secret_without_its_value() {
        assert!(sent_secrets(&sent(&repin())).contains(&json!({"name": "plain-one"})));
    }

    #[test]
    fn apply_unbind_removes_the_env_entry() {
        let mut c = no_change();
        c.unbind.push("LOG_LEVEL".into());
        assert!(
            !sent_env(&sent(&c))
                .iter()
                .any(|e| e["name"] == json!("LOG_LEVEL"))
        );
    }

    #[test]
    fn apply_refuses_when_unmanaged_part_changed_and_names_the_path() {
        let mut fresh = show();
        fresh["properties"]["configuration"]["ingress"]["targetPort"] = json!(8080);
        let (_, res) = apply_on(&show(), &fresh, &repin());
        assert!(err_text(res).contains("/properties/configuration/ingress/targetPort"));
    }

    #[test]
    fn apply_sends_nothing_when_unmanaged_part_changed() {
        let mut fresh = show();
        fresh["properties"]["configuration"]["ingress"]["targetPort"] = json!(8080);
        let (r, _) = apply_on(&show(), &fresh, &repin());
        assert_eq!(r.calls.borrow().len(), 1);
    }

    #[test]
    fn apply_refuses_multiple_revision_mode() {
        let mut v = show();
        v["properties"]["configuration"]["activeRevisionsMode"] = json!("Multiple");
        let (_, res) = apply_on(&v, &v, &repin());
        assert!(matches!(res, Err(Error::Config(_))));
    }

    #[test]
    fn apply_refuses_to_change_an_unmanaged_name() {
        let mut c = no_change();
        c.set.insert("OTHER".into(), NEW_CONFIG.into());
        let (_, res) = apply_on(&show(), &show(), &c);
        assert!(matches!(res, Err(Error::Config(_))));
    }

    #[test]
    fn apply_returns_latest_revision_name() {
        let (_, res) = apply_on(&show(), &show(), &repin());
        assert_eq!(res.unwrap(), Revision(REV.into()));
    }

    #[test]
    fn failed_update_when_signed_out_is_auth_error() {
        let snap = snapshot_of(&show());
        let (t, m) = (target(), managed());
        let r = FakeRunner::new([
            out(&show()),
            out(&serving_revision()),
            Output::failure(1),
            Output::failure(1),
        ]);
        assert!(matches!(
            adapter(&r, &t, &m).apply(&repin(), &snap),
            Err(Error::Auth(_))
        ));
    }

    #[test]
    fn failed_update_when_signed_in_is_unknown_outcome() {
        let snap = snapshot_of(&show());
        let (t, m) = (target(), managed());
        let r = FakeRunner::new([
            out(&show()),
            out(&serving_revision()),
            Output::failure(1),
            Output::success(""),
        ]);
        assert!(matches!(
            adapter(&r, &t, &m).apply(&repin(), &snap),
            Err(Error::Unknown(_))
        ));
    }

    /// NR-7: the configured subscription scopes every call.
    #[test]
    fn every_az_call_carries_the_configured_subscription() {
        let (r, _) = apply_on(&show(), &show(), &repin());
        assert!(r.calls.borrow().iter().all(|c| {
            c.args
                .ends_with(&["--subscription".into(), SUBSCRIPTION.into()])
        }));
    }

    #[test]
    fn every_az_call_carries_only_show_errors() {
        // The hardened env (R7) is the runner's pinned_env, tested in runner.rs.
        let (r, _) = apply_on(&show(), &show(), &repin());
        assert!(
            r.calls
                .borrow()
                .iter()
                .all(|c| c.program == "az" && c.args.iter().any(|a| a == "--only-show-errors"))
        );
    }

    // ---- await_healthy ----

    fn await_with(responses: Vec<Value>) -> Result<Health, Error> {
        let (t, m) = (target(), managed());
        let r = FakeRunner::new(responses.iter().map(out).collect::<Vec<_>>());
        adapter(&r, &t, &m).await_healthy(&Revision(REV.into()))
    }

    #[test]
    fn await_healthy_reports_healthy() {
        assert_eq!(
            await_with(vec![healthy_revision(), show_ready()]).unwrap(),
            Health::Healthy
        );
    }

    #[test]
    fn await_healthy_reads_the_named_revision() {
        let (t, m) = (target(), managed());
        let r = FakeRunner::new([out(&healthy_revision()), out(&show_ready())]);
        adapter(&r, &t, &m)
            .await_healthy(&Revision(REV.into()))
            .unwrap();
        assert!(
            r.calls.borrow()[0]
                .args
                .windows(2)
                .any(|w| w == ["--revision", REV])
        );
    }

    #[test]
    fn await_healthy_accepts_probe_less_revision() {
        // The recorded revision has `probes: []` and reports Healthy (Q7).
        let v = healthy_revision();
        assert_eq!(await_with(vec![v, show_ready()]).unwrap(), Health::Healthy);
    }

    #[test]
    fn scaled_to_zero_ready_revision_is_healthy() {
        let mut v = revision("Provisioned", "ScaledToZero", "Healthy");
        v["properties"]["replicas"] = json!(0);
        assert_eq!(await_with(vec![v, show_ready()]).unwrap(), Health::Healthy);
    }

    #[test]
    fn await_healthy_waits_for_latest_ready_revision() {
        assert_eq!(
            await_with(vec![
                healthy_revision(),
                show(),
                healthy_revision(),
                show_ready()
            ])
            .unwrap(),
            Health::Healthy
        );
    }

    #[test]
    fn await_healthy_sleeps_the_poll_interval_between_reads() {
        let (t, m) = (target(), managed());
        let r = FakeRunner::new([
            out(&revision("Provisioning", "Activating", "None")),
            out(&healthy_revision()),
            out(&show_ready()),
        ]);
        ContainerApp::new(&r, &t, m)
            .with_wait(Duration::from_secs(5), Duration::from_secs(300))
            .await_healthy(&Revision(REV.into()))
            .unwrap();
        assert_eq!(r.elapsed.get(), Duration::from_secs(5));
    }

    #[test]
    fn await_healthy_reports_failed_provisioning() {
        assert!(matches!(
            await_with(vec![revision("Failed", "Failed", "None")]),
            Ok(Health::Unhealthy(_))
        ));
    }

    #[test]
    fn await_healthy_reports_unhealthy_revision() {
        assert!(matches!(
            await_with(vec![revision("Provisioned", "Running", "Unhealthy")]),
            Ok(Health::Unhealthy(_))
        ));
    }

    #[test]
    fn await_healthy_times_out() {
        let starting = revision("Provisioned", "Running", "None");
        assert_eq!(
            await_with(vec![starting.clone(), starting.clone(), starting]).unwrap(),
            Health::TimedOut
        );
    }

    #[test]
    fn await_healthy_reports_failed_running_state() {
        assert!(matches!(
            await_with(vec![revision("Provisioned", "Failed", "None")]),
            Ok(Health::Unhealthy(_))
        ));
    }

    #[test]
    fn unhealthy_report_names_the_revision() {
        let Ok(Health::Unhealthy(why)) =
            await_with(vec![revision("Provisioned", "Running", "Unhealthy")])
        else {
            panic!("expected Unhealthy");
        };
        assert!(why.contains(REV));
    }

    /// Progress lines printed while waiting `polls` reads that never get ready.
    fn progress_over(polls: usize) -> Vec<String> {
        let (t, m) = (target(), managed());
        let starting = revision("Provisioning", "Activating", "None");
        let r = FakeRunner::new((0..polls).map(|_| out(&starting)));
        ContainerApp::new(&r, &t, m)
            .with_wait(
                Duration::from_secs(5),
                Duration::from_secs(5 * (polls as u64 - 1)),
            )
            .await_healthy(&Revision(REV.into()))
            .unwrap();
        r.notes.into_inner()
    }

    #[test]
    fn waiting_prints_progress_every_fifteen_seconds() {
        assert_eq!(progress_over(8).len(), 3);
    }

    #[test]
    fn progress_line_names_revision_states_and_elapsed_time() {
        assert_eq!(
            progress_over(5)[1],
            format!(
                "waiting for revision {REV} of container app opv-fixture-app: \
                 Provisioning/Activating/None, 15 s"
            )
        );
    }

    #[test]
    fn concurrent_unmanaged_change_after_apply_is_reported() {
        let snap = snapshot_of(&show());
        let (t, m) = (target(), managed());
        let mut after = show_ready();
        after["properties"]["configuration"]["ingress"]["targetPort"] = json!(8080);
        let r = FakeRunner::new([
            out(&show()),
            out(&serving_revision()),
            out(&update_out()),
            out(&healthy_revision()),
            out(&after),
        ]);
        let ca = adapter(&r, &t, &m);
        let rev = ca.apply(&repin(), &snap).unwrap();
        assert!(err_text(ca.await_healthy(&rev)).contains("changed while opv applied"));
    }

    // ---- check_access ----

    /// The principal of the user-assigned identity in `identity-show.json` (constructed).
    const USER_PRINCIPAL: &str = "33333333-3333-3333-3333-333333333333";

    fn constructed(name: &str) -> Value {
        fixture(&format!("constructed/{name}"))
    }

    fn access_with(identity: &str, responses: Vec<Output>) -> (FakeRunner, Vec<AccessFinding>) {
        let mut t = target();
        t.identity = identity.into();
        let m = managed();
        let r = FakeRunner::new(responses);
        let found = adapter(&r, &t, &m)
            .check_access(&[DB_STORE.into(), "FLEET--API--TOKEN".into()])
            .unwrap();
        (r, found)
    }

    /// The system identity against the recorded RBAC vault and `roles` (a recorded list).
    fn rbac_access(roles: &str) -> (FakeRunner, Vec<AccessFinding>) {
        access_with(
            "system",
            vec![
                out(&show()),
                out(&fixture("keyvault-show.json")),
                out(&fixture(roles)),
            ],
        )
    }

    /// The app with `USER_IDENTITY` attached; `principal` as the app lists it.
    fn show_with_user_identity(principal: Option<&str>) -> Value {
        let mut v = show();
        let mut entry = json!({"clientId": "55555555-5555-5555-5555-555555555555"});
        if let Some(p) = principal {
            entry["principalId"] = json!(p);
        }
        // ARM may change the id's case: the lookup ignores it.
        v["identity"] = json!({
            "type": "UserAssigned",
            "userAssignedIdentities": {USER_IDENTITY.replace("resourceGroups", "resourcegroups"): entry}
        });
        v
    }

    #[test]
    fn check_access_passes_with_secrets_user_role() {
        assert!(rbac_access("role-assignment-list.json").1.is_empty());
    }

    #[test]
    fn check_access_reports_each_name_without_role() {
        assert_eq!(
            rbac_access("role-assignment-list-empty.json")
                .1
                .iter()
                .map(|f| f.store_name.as_str())
                .collect::<Vec<_>>(),
            [DB_STORE, "FLEET--API--TOKEN"]
        );
    }

    #[test]
    fn missing_role_finding_names_the_vault_and_the_grant_command() {
        let reason = rbac_access("role-assignment-list-empty.json").1[0]
            .reason
            .clone();
        assert!(reason.contains(
            "on Key Vault kv-opv-fixture; grant it: `az role assignment create \
             --assignee-object-id 22222222-2222-2222-2222-222222222222"
        ));
    }

    #[test]
    fn check_access_lists_roles_at_the_vault_scope_including_groups() {
        let (r, _) = rbac_access("role-assignment-list.json");
        assert_eq!(
            r.calls.borrow()[2].args[3..],
            [
                "--assignee",
                "22222222-2222-2222-2222-222222222222",
                "--scope",
                "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/opv-fixture-rg/providers/Microsoft.KeyVault/vaults/kv-opv-fixture",
                "--include-inherited",
                "--include-groups",
                "-o",
                "json",
                "--only-show-errors",
                "--subscription",
                SUBSCRIPTION
            ]
        );
    }

    #[test]
    fn check_access_passes_with_access_policy_get() {
        let (_, found) = access_with(
            "system",
            vec![
                out(&show()),
                out(&constructed("keyvault-show-access-policy.json")),
            ],
        );
        assert!(found.is_empty());
    }

    #[test]
    fn access_policy_for_another_principal_is_a_finding() {
        let mut v = show();
        v["identity"]["principalId"] = json!("66666666-6666-6666-6666-666666666666");
        let (_, found) = access_with(
            "system",
            vec![
                out(&v),
                out(&constructed("keyvault-show-access-policy.json")),
            ],
        );
        assert!(
            found[0]
                .reason
                .contains("az keyvault set-policy -n kv-opv-fixture")
        );
    }

    #[test]
    fn check_access_reads_user_assigned_principal_from_the_app() {
        let (r, _) = access_with(
            USER_IDENTITY,
            vec![
                out(&show_with_user_identity(Some(USER_PRINCIPAL))),
                out(&fixture("keyvault-show.json")),
                out(&fixture("role-assignment-list.json")),
            ],
        );
        assert!(r.calls.borrow()[2].args.iter().any(|a| a == USER_PRINCIPAL));
    }

    #[test]
    fn check_access_reads_user_assigned_principal_from_identity_show() {
        let (r, _) = access_with(
            USER_IDENTITY,
            vec![
                out(&show_with_user_identity(None)),
                out(&constructed("identity-show.json")),
                out(&fixture("keyvault-show.json")),
                out(&fixture("role-assignment-list.json")),
            ],
        );
        assert!(r.calls.borrow()[3].args.iter().any(|a| a == USER_PRINCIPAL));
    }

    #[test]
    fn unattached_user_identity_finding_names_the_assign_command() {
        let (_, found) = access_with(USER_IDENTITY, vec![out(&show())]);
        assert!(found[0].reason.contains(&format!(
            "az containerapp identity assign -g opv-fixture-rg -n opv-fixture-app \
             --user-assigned {USER_IDENTITY}"
        )));
    }

    #[test]
    fn check_access_without_identity_reports_each_name() {
        let mut v = show();
        v["identity"] = json!({"type": "None"});
        let (_, found) = access_with("system", vec![out(&v)]);
        assert_eq!(found.len(), 2);
    }
}
