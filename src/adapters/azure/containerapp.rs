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
//! env entry and its `opv-` secret (the name is pruned once the revision is healthy, so the
//! app must not keep a reference to the Key Vault entry opv deletes; FR-32). An `opv-` secret is superseded, and removed in the same document, only when
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
//!
//! The read, bindings, fingerprint, edit, identity and access code is the engine a Container
//! Apps Job shares (`resource.rs`, M4); this file adds what only an app has: revisions,
//! health and the read-back of a failed update.

use std::cell::RefCell;
use std::collections::BTreeSet;

use std::time::Duration;

use serde_json::Value;
use zeroize::Zeroizing;

use super::az::{self, Effect};
#[cfg_attr(not(test), allow(unused_imports))]
use super::resource::diff_paths;
use super::resource::{
    Kind, Resource, SECRETS, env_refs, fingerprint, is_opv_secret, parse, reference,
};
pub use super::resource::{READ_ROLES, secret_name};
use super::{AzureTarget, ConfigRoute, preflight};
use crate::cause::{
    Cause, DiagnoseContext, During, EnvName, OutputProblem, Principal, Refusal, ResourceRef, System,
};
use crate::domain::{AccessFinding, Binding, Health, Revision, RuntimeChange, RuntimeSnapshot};
use crate::error::Error;
use crate::ports::PinnedRuntime;
use crate::runner::{CommandRunner, Outcome, Output, Wait};

/// Delay between two health polls (R8).
pub const POLL_EVERY: Duration = Duration::from_secs(5);
/// Longest wait for a new revision (R8); the run budget may end it sooner (NR-4).
pub const WAIT_MAX: Duration = Duration::from_secs(300);
/// Longest gap between two progress lines while waiting (NR-4).
pub const PROGRESS_EVERY: Duration = Duration::from_secs(15);

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
    /// `latestRevisionName` just before the update, to tell a refused update from one
    /// whose outcome is unknown (NR-2).
    before_update: RefCell<Option<String>>,
    /// The opv environment this app serves, for the commands an error names.
    env: Option<&'a str>,
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
            before_update: RefCell::new(None),
            env: None,
        }
    }

    /// The opv environment this app serves, named in the `opv plan` an error suggests.
    pub fn for_env(mut self, env: &'a str) -> Self {
        self.env = Some(env);
        self
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

    /// This app for the shared engine (M4).
    fn res(&self) -> Resource<'_> {
        Resource {
            runner: self.runner,
            target: self.target,
            kind: Kind::App,
            name: self.app(),
            managed: &self.managed,
            env: self.env,
        }
    }

    /// This app, as the subject of a cause.
    fn app_ref(&self) -> ResourceRef {
        self.res().subject()
    }

    /// A call about this app, for its diagnosis.
    fn app_ctx(&self) -> DiagnoseContext {
        self.res().ctx()
    }

    fn show(&self) -> Result<Value, Error> {
        self.res().show()
    }

    /// One `az` call with typed, value-free errors; a call that did not succeed is
    /// diagnosed ([`Self::diagnose`]) from what opv observed, `az`'s reply as evidence.
    fn az(
        &self,
        effect: Effect,
        what: &str,
        ctx: DiagnoseContext,
        base: &[&str],
        stdin: Option<&[u8]>,
    ) -> Result<Output, Error> {
        let owned = self.res().argv(base);
        let args: Vec<&str> = owned.iter().map(String::as_str).collect();
        match (
            az::invoke(self.runner, effect, what, &args, stdin, &[])?,
            effect,
        ) {
            (Outcome::Done(out), _) => Ok(out),
            (Outcome::Refused(_) | Outcome::Unknown { .. }, Effect::Read) => {
                Err(az::failed(self.runner, ctx))
            }
            (
                Outcome::Refused(_)
                | Outcome::Unknown {
                    status: Some(_), ..
                },
                Effect::Write,
            ) => Err(self.failed_update(ctx)),
            // The update never answered: it may or may not have been applied (NR-2); the
            // Azure strategy makes that `WriteOutcomeUnknown` from the runner's facts.
            (Outcome::Unknown { status: None, .. }, Effect::Write) => {
                Err(az::failed(self.runner, az::writing(ctx)))
            }
        }
    }

    /// An update that exited non-zero (FR-26), read back inside the diagnosis so its reply
    /// stays the evidence (NR-31). The same latest revision and no update in progress means
    /// Azure applied nothing (06.03, Q14): a definite refusal that re-running would only
    /// repeat, decided by opv's own read-back, never by `az`'s wording. Signed out of the
    /// person's own Azure sign-in is that sign-in. Anything else leaves the outcome unknown
    /// (NR-2), which `sync` reconciles by reading the bindings back.
    fn failed_update(&self, ctx: DiagnoseContext) -> Error {
        // Taken first: a read-back that fails must not take the update's observation.
        let Some((seen, up)) = az::take_failure() else {
            return az::unobserved(self.runner);
        };
        if crate::runner::diagnosing(|| self.read_back()) {
            let refused = Cause::TargetRefused {
                system: System::Azure,
                subject: self.app_ref(),
                why: Refusal::NoRevision,
                env: ctx.env,
                target: ctx.target,
                seen,
            };
            return az::report(refused, up);
        }
        let own = matches!(seen.principal(), Principal::Person { .. });
        if own
            && crate::runner::diagnosing(|| az::signed_in(self.runner))
                .is_ok_and(|signed_in| !signed_in)
        {
            return az::report(az::signed_out(), up);
        }
        // opv's own read-back shows a new revision or an update in progress, or could not
        // read the app: whether the update was applied is not known (NR-2).
        let unknown = Cause::WriteOutcomeUnknown {
            system: System::Azure,
            subject: self.app_ref(),
            seen,
        };
        az::report(unknown, up)
    }

    /// After a failed update: true when the app still names the revision it had before and
    /// no update is in progress (Azure applied nothing); false when it shows a new revision,
    /// an update in progress, or cannot be read.
    fn read_back(&self) -> bool {
        let Ok(app) = self.show() else {
            return false;
        };
        let latest = app
            .pointer("/properties/latestRevisionName")
            .and_then(Value::as_str)
            .filter(|r| !r.is_empty());
        let before = self.before_update.borrow();
        provisioning_state(&app) != "InProgress" && latest == before.as_deref()
    }

    fn revision_show(&self, rev: &str) -> Result<Value, Error> {
        const WHAT: &str = "containerapp revision show";
        let out = self.az(
            Effect::Read,
            WHAT,
            self.app_ctx(),
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
    fn verify_unchanged(&self, now: &Value) -> Result<(), Error> {
        let Some(before) = self.applied_from.borrow_mut().take() else {
            return Ok(());
        };
        if fingerprint(&self.res().stripped(&before)?) == fingerprint(&self.res().stripped(now)?) {
            return Ok(());
        }
        // Someone else changed the app's unmanaged settings while opv applied: opv's own
        // `containerapp show` says so (R9). opv's update is live by now.
        let paths = self.res().changed_paths(&before, now);
        Err(preflight::unusable("containerapp show", |seen| {
            Cause::TargetRefused {
                system: System::Azure,
                subject: self.app_ref(),
                why: Refusal::ChangedOutsideOpv {
                    paths,
                    after_apply: true,
                },
                env: self.env.map(EnvName::new),
                target: None,
                seen,
            }
        }))
    }
}

impl PinnedRuntime for ContainerApp<'_> {
    fn bindings(&self) -> Result<RuntimeSnapshot, Error> {
        self.res().snapshot_from(self.show()?)
    }

    fn apply(&self, change: &RuntimeChange, snapshot: &RuntimeSnapshot) -> Result<Revision, Error> {
        // The plan is built from the managed names only.
        if change
            .pin
            .keys()
            .chain(change.set.keys())
            .chain(&change.unbind)
            .any(|n| !self.managed.contains(n))
        {
            return Err(Cause::Bug {
                site: "azure: a container app change names an env name opv does not manage",
            }
            .into());
        }
        let fresh = self.show()?;
        single_revision_mode(self.target, &fresh, self.env)?;
        let fresh = self.res().snapshot_from(fresh)?;
        if fresh.unmanaged_fingerprint != snapshot.unmanaged_fingerprint {
            let paths = self.res().changed_paths(&snapshot.spec.0, &fresh.spec.0);
            return Err(preflight::unusable("containerapp show", |seen| {
                Cause::TargetRefused {
                    system: System::Azure,
                    subject: self.app_ref(),
                    why: Refusal::ChangedOutsideOpv {
                        paths,
                        after_apply: false,
                    },
                    env: self.env.map(EnvName::new),
                    target: None,
                    seen,
                }
            }));
        }
        let mut doc = fresh.spec.0.clone();
        let idx = self.res().container_index(&doc)?;
        self.res().edit(&mut doc, idx, change)?;
        prune_superseded(&mut doc, &self.serving_refs(&fresh.spec.0)?);
        let body = Zeroizing::new(serde_json::to_vec(&doc).map_err(|_| encode_bug())?);
        *self.before_update.borrow_mut() = fresh.revision.as_ref().map(|r| r.0.clone());
        const WHAT: &str = "containerapp update";
        let out = self.az(
            Effect::Write,
            WHAT,
            self.app_ctx(),
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
        // The update exited 0, so the change is applied: a reply opv cannot read, or one
        // without the new revision, is a reply it cannot use (A1), and says so.
        preflight::reply_json::<Value>(&out.stdout, WHAT, During::AppliedWrite)?
            .pointer("/properties/latestRevisionName")
            .and_then(Value::as_str)
            .map(|r| Revision(r.into()))
            .ok_or_else(|| {
                preflight::bad_reply(
                    WHAT,
                    OutputProblem::Empty {
                        what: "properties.latestRevisionName",
                    },
                    During::AppliedWrite,
                )
            })
    }

    fn await_healthy(&self, revision: &Revision) -> Result<Health, Error> {
        let rev = revision.0.as_str();
        let wait = Wait::new(self.runner, self.wait_max);
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
                    self.verify_unchanged(&app)?;
                    return Ok(Health::Healthy);
                }
                last.push_str(&format!(
                    ", still serving {}",
                    ready.unwrap_or("no revision")
                ));
            }
            let waited = wait.elapsed(self.runner);
            if wait.over(self.runner, self.poll_every) {
                return Ok(Health::TimedOut);
            }
            let note = if reported.is_none_or(|at| waited.saturating_sub(at) >= PROGRESS_EVERY) {
                reported = Some(waited);
                format!(
                    "waiting for revision {rev} of container app {}: {last}, {} s",
                    self.app(),
                    waited.as_secs()
                )
            } else {
                String::new()
            };
            wait.pause(self.runner, self.poll_every, &note);
        }
    }

    /// The app's `opv-` secrets that point at the Key Vault entries of `names` and that no
    /// container references any more, removed in one update (a configuration change only, so
    /// no new revision). Normally the apply that unbound a name already removed its secret;
    /// this also covers a secret left by an earlier run.
    fn release(&self, names: &[String]) -> Result<(), Error> {
        let app = self.show()?;
        let base = self.res().vault_uri()?;
        let used = env_refs(&app);
        let doomed = |s: &Value| {
            let name = s["name"].as_str().unwrap_or_default();
            is_opv_secret(s)
                && !used.contains(name)
                && s["keyVaultUrl"]
                    .as_str()
                    .and_then(|u| reference(&base, u))
                    .is_some_and(|b| match b {
                        Binding::Pinned { store_name, .. } => names.iter().any(|n| {
                            AzureTarget::key_vault_name(n).eq_ignore_ascii_case(&store_name)
                        }),
                        _ => false,
                    })
        };
        let mut doc = app.clone();
        let Some(secrets) = doc.pointer_mut(SECRETS).and_then(Value::as_array_mut) else {
            return Ok(());
        };
        let before = secrets.len();
        secrets.retain(|s| !doomed(s));
        if secrets.len() == before {
            return Ok(());
        }
        let body = Zeroizing::new(serde_json::to_vec(&doc).map_err(|_| encode_bug())?);
        *self.before_update.borrow_mut() = app
            .pointer("/properties/latestRevisionName")
            .and_then(Value::as_str)
            .map(String::from);
        self.az(
            Effect::Write,
            "containerapp update",
            self.app_ctx(),
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
        )
        .map(drop)
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
        self.res().check_access(names)
    }
}

/// Refuses an app not in single-revision mode (NR-25): opv pins by replacing the one
/// active revision. `app`: the reply of the `containerapp show` just made, which the
/// refusal is observed on; `env`: the environment being written, when known.
pub(crate) fn single_revision_mode(
    t: &AzureTarget,
    app: &Value,
    env: Option<&str>,
) -> Result<(), Error> {
    match app
        .pointer("/properties/configuration/activeRevisionsMode")
        .and_then(Value::as_str)
        .filter(|m| !m.eq_ignore_ascii_case("single"))
    {
        // Only an owner of the app changes its revision mode (the Do names `az
        // containerapp revision set-mode --mode single`); opv never does.
        Some(mode) => Err(preflight::unusable("containerapp show", |seen| {
            Cause::TargetRefused {
                system: System::Azure,
                subject: preflight::app_ref(t),
                why: Refusal::RevisionMode {
                    mode: mode.to_lowercase(),
                    resource_group: t.resource_group.to_string(),
                    subscription: t.subscription.to_string(),
                },
                env: env.map(EnvName::new),
                target: None,
                seen,
            }
        })),
        None => Ok(()),
    }
}

/// A JSON value opv built itself could not be encoded: nothing was sent.
fn encode_bug() -> Error {
    Cause::Bug {
        site: "azure: encoding a container app update",
    }
    .into()
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

/// The app's `properties.provisioningState`, or `unknown`.
fn provisioning_state(app: &Value) -> &str {
    app.pointer("/properties/provisioningState")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
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

    fn unbind_db() -> RuntimeChange {
        let mut c = no_change();
        c.unbind.push(DB_URL.into());
        c
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
        let e = adapter(&r, &t, &m).bindings().unwrap_err();
        assert_eq!(e.code_str(), "config_invalid");
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
        let e = adapter(&r, &t, &m).bindings().unwrap_err();
        assert_eq!(e.code_str(), "target_not_signed_in");
    }

    #[test]
    /// 06.02: signed in per `az account show` is no proof the app is missing or a role is;
    /// opv shows az's reply instead of guessing.
    fn bindings_when_signed_in_shows_azs_reply_unrecognized() {
        let (t, m) = (target(), managed());
        let r = FakeRunner::new(failed_read(3).chain([Output::success("")]));
        let e = adapter(&r, &t, &m).bindings().unwrap_err();
        assert_eq!(e.code_str(), "unrecognized_failure");
    }

    #[test]
    fn missing_az_is_dependency_error() {
        let (t, m) = (target(), managed());
        let r = FakeRunner::default();
        r.push_io_error(io::ErrorKind::NotFound);
        let e = adapter(&r, &t, &m).bindings().unwrap_err();
        assert_eq!(e.code_str(), "dependency_missing");
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
        assert_eq!(
            res.err().map(|e| e.code_str()),
            Some("owner_setup_required")
        );
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
    fn apply_refuses_when_unmanaged_part_changed_outside_opv() {
        let mut fresh = show();
        fresh["properties"]["configuration"]["ingress"]["targetPort"] = json!(8080);
        let (_, res) = apply_on(&show(), &fresh, &repin());
        assert!(err_text(res).contains("was changed outside opv since opv read it"));
    }

    /// I5: the refusal names the setting that changed (its path, never its value).
    #[test]
    fn apply_refusal_names_the_changed_setting() {
        let mut fresh = show();
        fresh["properties"]["configuration"]["ingress"]["targetPort"] = json!(8080);
        let (_, res) = apply_on(&show(), &fresh, &repin());
        assert!(err_text(res).contains("(changed: properties.configuration.ingress.targetPort)"));
    }

    #[test]
    fn changed_paths_name_array_items_by_index() {
        let mut out = Vec::new();
        diff_paths(
            &json!({"a": [{"b": 1}, {"b": 2}]}),
            &json!({"a": [{"b": 1}, {"b": 3}]}),
            "",
            &mut out,
        );
        assert_eq!(out, vec!["a[1].b".to_string()]);
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
        assert_eq!(
            res.err().map(|e| e.code_str()),
            Some("owner_setup_required")
        );
    }

    #[test]
    fn apply_refuses_to_change_an_unmanaged_name() {
        let mut c = no_change();
        c.set.insert("OTHER".into(), NEW_CONFIG.into());
        let (_, res) = apply_on(&show(), &show(), &c);
        assert_eq!(res.err().map(|e| e.code_str()), Some("internal_error"));
    }

    #[test]
    fn apply_returns_latest_revision_name() {
        let (_, res) = apply_on(&show(), &show(), &repin());
        assert_eq!(res.unwrap(), Revision(REV.into()));
    }

    #[test]
    fn failed_update_when_signed_out_is_not_signed_in() {
        let snap = snapshot_of(&show());
        let (t, m) = (target(), managed());
        // The update fails, its read-back fails, then `az account show` fails.
        let r = FakeRunner::new(
            [out(&show()), out(&serving_revision()), Output::failure(1)]
                .into_iter()
                .chain(failed_read(1))
                .chain([Output::failure(1)]),
        );
        let e = adapter(&r, &t, &m).apply(&repin(), &snap).unwrap_err();
        assert_eq!(e.code_str(), "target_not_signed_in");
    }

    /// The app read back after a failed update: `provisioning` and `latest` as given.
    fn read_back(provisioning: &str, latest: &str) -> Value {
        let mut v = show();
        v["properties"]["provisioningState"] = json!(provisioning);
        v["properties"]["latestRevisionName"] = json!(latest);
        v
    }

    /// An update that exits 1, then `back` as the read-back, then `az account show` signed
    /// in (asked only when the read-back does not settle it).
    fn failed_update(r: &FakeRunner, back: &Value) -> Result<Revision, Error> {
        let snap = snapshot_of(&show());
        let (t, m) = (target(), managed());
        for o in [out(&show()), out(&serving_revision())] {
            r.responses.borrow_mut().push_back(Ok(o));
        }
        r.push_with_stderr(
            Output::failure(1),
            "ERROR: secret reference cannot be resolved",
        );
        r.responses.borrow_mut().push_back(Ok(out(back)));
        r.responses.borrow_mut().push_back(Ok(Output::success("")));
        adapter(r, &t, &m).apply(&repin(), &snap)
    }

    fn latest_of(v: &Value) -> String {
        v["properties"]["latestRevisionName"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// The read-back shows a new revision in progress: the update may have landed (NR-2).
    #[test]
    fn failed_update_whose_read_back_shows_progress_is_unknown_outcome() {
        let r = FakeRunner::default();
        let back = read_back("InProgress", "opv-fixture-app--new");
        assert_eq!(
            failed_update(&r, &back).map_err(|e| e.code_str()),
            Err("outcome_unknown")
        );
    }

    /// Q14: same revision and provisioning `Failed`: Azure refused it, nothing applied.
    #[test]
    fn refused_update_is_a_target_error() {
        let r = FakeRunner::default();
        let back = read_back("Failed", &latest_of(&show()));
        assert_eq!(failed_update(&r, &back).map_err(|e| e.exit_code()), Err(5));
    }

    /// 06.03: a missing write right leaves the app `Succeeded` on its old revision; opv's
    /// read-back shows nothing was applied, so it is a refusal, never "outcome unknown".
    #[test]
    fn update_refused_while_the_app_stays_succeeded_is_a_refusal() {
        let r = FakeRunner::default();
        let back = read_back("Succeeded", &latest_of(&show()));
        let e = failed_update(&r, &back).unwrap_err();
        assert_eq!(e.code_str(), "update_refused");
    }

    #[test]
    fn refused_update_has_the_update_refused_code() {
        let r = FakeRunner::default();
        let back = read_back("Failed", &latest_of(&show()));
        let e = failed_update(&r, &back).unwrap_err();
        assert_eq!(e.code_str(), "update_refused");
    }

    /// NR-31: the read-back runs inside the diagnosis, so the update's stderr stays.
    #[test]
    fn refused_update_keeps_the_az_excerpt() {
        let r = FakeRunner::default();
        let back = read_back("Failed", &latest_of(&show()));
        let e = failed_update(&r, &back).unwrap_err();
        assert!(e.cause().and_then(|(_, up)| up).is_some());
    }

    /// I6: a read that never answers before any write is Azure's outage (exit 9).
    #[test]
    fn unanswered_read_before_any_write_is_provider_unavailable() {
        let (t, m) = (target(), managed());
        let r = FakeRunner::default();
        r.push_unknowns("timeout", crate::runner::READ_ATTEMPTS);
        let e = adapter(&r, &t, &m).bindings().unwrap_err();
        assert_eq!(e.code_str(), "provider_unavailable");
    }

    #[test]
    fn unanswered_read_names_azure() {
        let (t, m) = (target(), managed());
        let r = FakeRunner::default();
        r.push_unknowns("timeout", crate::runner::READ_ATTEMPTS);
        let e = adapter(&r, &t, &m).bindings().unwrap_err();
        // The catalog's Unavailable names the system; its Do points at its status page.
        assert!(e.to_string().contains("Azure did not answer"), "{e}");
    }

    /// I2: after this run's first write an unanswered read is exit 9 and never claims
    /// that nothing was changed.
    #[test]
    fn unanswered_read_after_a_write_never_says_nothing_was_changed() {
        let (t, m) = (target(), managed());
        let r = FakeRunner::default();
        r.target_writes.set(true);
        r.push_unknowns("timeout", crate::runner::READ_ATTEMPTS);
        let e = adapter(&r, &t, &m).bindings().unwrap_err();
        assert!(!e.mentions("nothing was changed"), "{e}");
    }

    #[test]
    fn read_after_a_write_with_the_budget_spent_is_unknown_outcome() {
        let (t, m) = (target(), managed());
        let r = FakeRunner::default();
        r.target_writes.set(true);
        r.budget.set(Duration::ZERO);
        // 02.06: opv's own budget ran out: budget_spent (exit 9), never a target refusal.
        assert_eq!(
            adapter(&r, &t, &m).bindings().unwrap_err().code_str(),
            "budget_spent"
        );
    }

    /// I3: an unbound name's `opv-` secret leaves the app in the same update, even while the
    /// serving revision still references it, so no Key Vault entry opv deletes stays
    /// referenced.
    #[test]
    fn apply_removes_the_secret_of_an_unbound_name() {
        let doc = sent(&unbind_db());
        assert!(
            !sent_secrets(&doc)
                .iter()
                .any(|s| s["name"] == json!(OLD_SECRET))
        );
    }

    /// A healthy app still holding a secret for an entry about to be deleted drops it.
    #[test]
    fn release_drops_a_secret_pointing_at_a_deleted_entry() {
        let (t, m) = (target(), managed());
        let mut app = show();
        // The template no longer binds DB_URL; its opv- secret is still configured.
        let idx = 0;
        app["properties"]["template"]["containers"][idx]["env"]
            .as_array_mut()
            .unwrap()
            .retain(|e| e["name"] != json!(DB_URL));
        let r = FakeRunner::new([out(&app), out(&update_out())]);
        adapter(&r, &t, &m).release(&[DB_URL.into()]).unwrap();
        assert!(
            !sent_secrets(&stdin_doc(&r))
                .iter()
                .any(|s| s["name"] == json!(OLD_SECRET))
        );
    }

    #[test]
    fn release_with_nothing_left_to_drop_makes_no_update() {
        let (t, m) = (target(), managed());
        let r = FakeRunner::new([out(&show())]);
        adapter(&r, &t, &m)
            .release(&["UNKNOWN_NAME".into()])
            .unwrap();
        assert_eq!(r.calls.borrow().len(), 1);
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

    /// I3: the wait measures elapsed time, reads included, not only its sleeps: with each
    /// read taking 60 s a 120 s wait gives up after its second read.
    #[test]
    fn await_healthy_counts_the_time_its_reads_take() {
        let (t, m) = (target(), managed());
        let starting = revision("Provisioned", "Running", "None");
        let r = FakeRunner::new([out(&starting), out(&starting)]);
        r.call_cost.set(Duration::from_secs(60));
        let rt = ContainerApp::new(&r, &t, m).with_wait(POLL_EVERY, Duration::from_secs(120));
        assert_eq!(
            rt.await_healthy(&Revision(REV.into())).unwrap(),
            Health::TimedOut
        );
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

    /// `await_healthy` after an apply during which someone changed the ingress port.
    fn changed_during_apply() -> Error {
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
        ca.await_healthy(&rev).unwrap_err()
    }

    #[test]
    fn concurrent_unmanaged_change_after_apply_is_reported() {
        assert_eq!(changed_during_apply().code_str(), "update_refused");
    }

    /// I5: an update that exited 0 with a reply opv cannot read says the change was made.
    #[test]
    fn unreadable_update_reply_says_the_change_was_applied() {
        let snap = snapshot_of(&show());
        let (t, m) = (target(), managed());
        let r = FakeRunner::new([
            out(&show()),
            out(&serving_revision()),
            Output::success("not json"),
        ]);
        let err = adapter(&r, &t, &m).apply(&repin(), &snap).unwrap_err();
        assert!(
            err.to_string().contains("the change was applied at Azure"),
            "{err}"
        );
    }

    /// I5: after the apply, the change is reported as live, not as "not overwritten".
    #[test]
    fn concurrent_change_after_apply_says_opvs_update_is_live() {
        assert!(
            changed_during_apply()
                .to_string()
                .contains("while opv's update was applied")
        );
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
