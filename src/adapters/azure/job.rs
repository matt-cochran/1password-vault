//! A Container Apps Job that mirrors its app (`azure.companion_jobs`, #238,
//! `docs/design/azure-jobs.md` §4): the read side.
//!
//! | fn | argv | stdin |
//! |---|---|---|
//! | `bindings` | `containerapp job show -g <rg> -n <job> -o json` | — |
//! | `principal` | none, or `identity show --ids <id> -o json` (user-assigned identity whose principal the job does not list) | — |
//!
//! Every call adds `--only-show-errors` and `--subscription <azure.subscription>` (NR-7). A
//! job is read with the app's engine ([`super::resource`]), so its bindings and unmanaged
//! fingerprint follow the app's rules (FR-31) with the job's own read-only fields (J2). Its
//! bindings come from `job show` only, never from an execution: an execution's template
//! references one execution-scoped `cappjob-<job>` secret, not the job's own (J10). A new job
//! lists `configuration.secrets: null`, which reads as no secrets (J2); an unmanaged plain
//! secret is listed by name only (J6). `job show` returns no secret value (J7).

use std::collections::BTreeSet;

use super::AzureTarget;
use super::resource::{Kind, Resource};
use crate::domain::RuntimeSnapshot;
use crate::error::Error;
use crate::runner::CommandRunner;

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
}

#[cfg(test)]
#[path = "job_tests.rs"]
mod tests;
