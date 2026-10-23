//! A Container Apps Job that mirrors its app (`azure.companion_jobs`, #238,
//! `docs/design/azure-jobs.md` §4): its reads and its writes.
//!
//! | fn | argv | stdin |
//! |---|---|---|
//! | `bindings` | `containerapp job show -g <rg> -n <job> -o json` | — |
//! | `principal` | none, or `identity show --ids <id> -o json` (user-assigned identity whose principal the job does not list) | — |
//! | `apply` | `containerapp job show …`, then `containerapp job update -g <rg> -n <job> --yaml /dev/stdin -o json` | the whole document as JSON |
//! | `release` | `containerapp job show …`, then the same update when it holds a secret to drop | the whole document as JSON |
//!
//! Every call adds `--only-show-errors` and `--subscription <azure.subscription>` (NR-7). A
//! job is read with the app's engine ([`super::resource`]), so its bindings and unmanaged
//! fingerprint follow the app's rules (FR-31) with the job's own read-only fields (J2). Its
//! bindings come from `job show` only, never from an execution: an execution's template
//! references one execution-scoped `cappjob-<job>` secret, not the job's own (J10). A new job
//! lists `configuration.secrets: null`, which reads as no secrets (J2); an unmanaged plain
//! secret is listed by name only (J6). `job show` returns no secret value (J7).
//!
//! A write edits the fresh document with the app's engine: each pin is a Key Vault reference
//! under the app's per-version [`secret_name`](super::resource::secret_name) (J8) and an env
//! `secretRef`; an unmanaged plain secret goes back as `show` listed it, without a value, and
//! Azure keeps it (J5, J6). A job has no serving revision, so every `opv-` secret the edited
//! template does not reference is removed in the same update (J9). The update's reply already
//! reads `Succeeded` (J11): opv settles from it and never polls. A failed update is read back
//! like the app's, against the job's whole document (no revision, no etag: J2).

use std::collections::BTreeSet;

use serde_json::Value;

use super::resource::{Kind, Resource, provisioning_state, prune_superseded};
use super::{AzureTarget, preflight};
use crate::cause::{Cause, During, OutputProblem, Refusal, System};
use crate::domain::{RuntimeChange, RuntimeSnapshot};
use crate::error::Error;
use crate::runner::{CommandRunner, Output};

const UPDATE: &str = "containerapp job update";

/// One Container Apps Job in the app's resource group and subscription (D1).
pub struct ContainerAppJob<'a> {
    pub runner: &'a dyn CommandRunner,
    /// The app's target: its vault, `azure.identity` (D5) and `azure.container` (D6).
    pub target: &'a AzureTarget,
    pub name: &'a str,
    /// Managed env names (from the template, FR-8).
    pub managed: BTreeSet<String>,
    /// The opv environment this job serves, for the commands an error names.
    env: Option<&'a str>,
}

impl<'a> ContainerAppJob<'a> {
    pub fn new(
        runner: &'a dyn CommandRunner,
        target: &'a AzureTarget,
        name: &'a str,
        managed: BTreeSet<String>,
    ) -> Self {
        Self {
            runner,
            target,
            name,
            managed,
            env: None,
        }
    }

    /// The opv environment this job serves, named in the commands an error suggests.
    pub fn for_env(mut self, env: &'a str) -> Self {
        self.env = Some(env);
        self
    }

    /// This job for the shared engine (M4).
    fn res(&self) -> Resource<'_> {
        Resource {
            runner: self.runner,
            target: self.target,
            kind: Kind::Job,
            name: self.name,
            managed: &self.managed,
            env: self.env,
        }
    }

    /// The job's bindings and unmanaged fingerprint, read from `job show` (J10). `revision`
    /// is `None`: a job has no revisions.
    pub fn bindings(&self) -> Result<RuntimeSnapshot, Error> {
        let res = self.res();
        res.snapshot_from(res.show()?)
    }

    /// The principal id of the job's identity, from the `job show` that `snapshot` holds,
    /// or the finding when the job has none that opv can use. `system` is the job's own
    /// identity, never the app's (D5).
    pub fn principal(&self, snapshot: &RuntimeSnapshot) -> Result<Result<String, String>, Error> {
        self.res().principal(&snapshot.spec.0)
    }

    pub fn describe(&self) -> String {
        format!("container app job {}", self.name)
    }

    /// Writes `change` to the job in one update and settles it (design §4 step 5). The job
    /// is re-read first: when its unmanaged part moved since `snapshot`, nothing is written.
    pub fn apply(&self, change: &RuntimeChange, snapshot: &RuntimeSnapshot) -> Result<(), Error> {
        let res = self.res();
        let fresh = res.recheck(res.show()?, snapshot)?;
        let before = res.mark(&fresh.spec.0);
        let mut doc = fresh.spec.0;
        let idx = res.container_index(&doc)?;
        res.edit(&mut doc, idx, change)?;
        prune_superseded(&mut doc, &BTreeSet::new());
        self.settle(&res.update(&doc, before.as_deref())?)
    }

    /// Drops the job's `opv-` secrets that point at the Key Vault entries of `names` and that
    /// it no longer references, in one update (FR-32, before any Key Vault delete).
    pub fn release(&self, names: &[String]) -> Result<(), Error> {
        let res = self.res();
        let show = res.show()?;
        let Some(doc) = res.released(&show, names)? else {
            return Ok(());
        };
        self.settle(&res.update(&doc, res.mark(&show).as_deref())?)
    }

    /// The update's own reply decides (J11): `Succeeded` is done; `Failed` is Azure's
    /// refusal; any other state is a change still in progress, which opv does not wait for.
    fn settle(&self, out: &Output) -> Result<(), Error> {
        let reply: Value = preflight::reply_json(&out.stdout, UPDATE, During::AppliedWrite)?;
        let why = match provisioning_state(&reply) {
            "Succeeded" => return Ok(()),
            "unknown" => {
                return Err(preflight::bad_reply(
                    UPDATE,
                    OutputProblem::Empty {
                        what: "properties.provisioningState",
                    },
                    During::AppliedWrite,
                ));
            }
            "Failed" => Refusal::Validation,
            _ => Refusal::InProgress { revision: None },
        };
        Err(preflight::unusable(UPDATE, |seen| Cause::TargetRefused {
            system: System::Azure,
            subject: self.res().subject(),
            why,
            env: self.env.map(crate::cause::EnvName::new),
            target: None,
            seen,
        }))
    }
}

#[cfg(test)]
#[path = "job_tests.rs"]
mod tests;
