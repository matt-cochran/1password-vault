//! A Container App and its companion jobs as one pinned-flow runtime (`azure.companion_jobs`,
//! #238, `docs/design/azure-jobs.md` §4).
//!
//! | fn | what it adds to the app's own calls |
//! |---|---|
//! | `bindings` | `containerapp job show …` per job; on a disagreement, `keyvault secret show --name <n> --query id -o tsv` (the id only) |
//! | `apply` | per job: `containerapp job show …`, `keyvault show …` once and `role assignment list --assignee-object-id …` (the access gate), then `containerapp job update …` |
//! | `release` | each job's release, then the app's |
//!
//! **Bindings (H1).** A name the app and every job bind alike is reported as is. When they
//! disagree, Key Vault's current version decides: the binding reported is that of a resource
//! **not** at it (the app first, then the jobs in config order), so a stale resource reads
//! as `Pinned{old}` and core re-pins and flags it. A name some resources bind and others do
//! not, or plain values that differ, read as [`Binding::Other`], so core both pins and
//! unbinds it on every resource that needs it. The fingerprint is the SHA-256 of the app's
//! followed by each job's; the raw spec is `{"app": …, "jobs": {<job>: …}}`, with no values.
//!
//! **Apply (D2, D7, D8).** Every resource is re-read and re-checked first. Each one gets its
//! own sub-change (only what it does not already bind), and one whose sub-change is empty
//! is not updated. The access gate runs for every job that will be updated and will hold a
//! Key Vault reference, before any update: a definite "no access" refuses the whole apply
//! with `MissingRight` naming the job's identity; a check that cannot decide warns and goes
//! on. Then the jobs are updated in config order, then the app. A stop after a job was
//! updated is `Partial`, naming what landed; the next run finds whatever is behind through
//! the merge rule and updates only that. Health stays the app's.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::AzureTarget;
use super::containerapp::ContainerApp;
use super::job::ContainerAppJob;
use super::keyvault::KeyVault;
use super::preflight::{self, JobAccess};
use super::resource::{Kind, Resource};
use crate::cause::{
    Cause, EnvName, GrantModel, Principal, ResourceKind, ResourceName, ResourceRef, Right, System,
};
use crate::domain::runtime::RawSpec;
use crate::domain::{AccessFinding, Binding, Health, Revision, RuntimeChange, RuntimeSnapshot};
use crate::error::Error;
use crate::ports::PinnedRuntime;
use crate::runner::CommandRunner;

/// The app (`azure.container_app`) and its companion jobs, in config order.
pub struct AppWithJobs<'a> {
    pub app: ContainerApp<'a>,
    pub jobs: Vec<ContainerAppJob<'a>>,
    /// The target's vault, read for the current version of a name the resources disagree on.
    pub store: KeyVault<'a>,
    pub runner: &'a dyn CommandRunner,
    pub target: &'a AzureTarget,
    pub env: &'a str,
}

impl AppWithJobs<'_> {
    /// The shared engine over the app (`None`) or the job `job`.
    fn res<'b>(&'b self, job: Option<&'b ContainerAppJob<'_>>) -> Resource<'b> {
        let (kind, name, managed) = match job {
            Some(j) => (Kind::Job, j.name, &j.managed),
            None => (
                Kind::App,
                self.target.container_app.as_str(),
                &self.app.managed,
            ),
        };
        Resource {
            runner: self.runner,
            target: self.target,
            kind,
            name,
            managed,
            env: Some(self.env),
        }
    }

    /// The H1 merge of one name's bindings across the app and its jobs (config order).
    fn merge(
        &self,
        name: &str,
        all: &[(String, Option<&Binding>)],
    ) -> Result<Option<Binding>, Error> {
        let first = all[0].1;
        if all.iter().all(|(_, b)| *b == first) {
            return Ok(first.cloned());
        }
        let present: Vec<(&String, &Binding)> =
            all.iter().filter_map(|(w, b)| b.map(|b| (w, b))).collect();
        if present.len() < all.len()
            || present
                .iter()
                .all(|(_, b)| matches!(b, Binding::Plain { .. }))
        {
            return Ok(Some(Binding::Other));
        }
        let current = self.store.current_version(name)?;
        let store_name = AzureTarget::key_vault_name(name);
        let behind = present.iter().find(|(_, b)| match b {
            Binding::Pinned {
                store_name: s,
                version,
            } => !s.eq_ignore_ascii_case(&store_name) || Some(version) != current.as_ref(),
            _ => true,
        });
        let Some((who, binding)) = behind else {
            // Every resource is at the current version, yet they differ: the app's.
            return Ok(first.cloned());
        };
        if let (Binding::Pinned { version, .. }, Some(now)) = (binding, &current) {
            self.runner.note(&format!(
                "{who} binds {name} at {version}; Key Vault is at {now}"
            ));
        }
        Ok(Some((*binding).clone()))
    }

    /// The app's and each job's own snapshot, read now.
    fn read_all(&self) -> Result<(RuntimeSnapshot, Vec<RuntimeSnapshot>), Error> {
        let app = self.app.bindings()?;
        let jobs = self
            .jobs
            .iter()
            .map(ContainerAppJob::bindings)
            .collect::<Result<Vec<_>, _>>()?;
        Ok((app, jobs))
    }

    /// Re-reads every resource and checks it against its part of `snapshot` (step 1):
    /// nothing is written when any of them changed outside opv.
    fn recheck(
        &self,
        snapshot: &RuntimeSnapshot,
    ) -> Result<(RuntimeSnapshot, Vec<RuntimeSnapshot>), Error> {
        let spec = &snapshot.spec.0;
        let res = self.res(None);
        let app = res.recheck(res.show()?, &res.snapshot_from(spec["app"].clone())?)?;
        let mut jobs = Vec::new();
        for j in &self.jobs {
            let res = self.res(Some(j));
            let before = res.snapshot_from(spec["jobs"][j.name].clone())?;
            jobs.push(res.recheck(res.show()?, &before)?);
        }
        Ok((app, jobs))
    }

    /// The access gate for job `j` (A4, D7, D8; M1): `Err` refuses the whole apply.
    fn gate(
        &self,
        j: &ContainerAppJob<'_>,
        now: &RuntimeSnapshot,
        kv: &Result<Value, Error>,
    ) -> Result<(), Error> {
        let (name, vault) = (j.name, &self.target.key_vault);
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let access = match kv {
            Ok(kv) => preflight::job_access(self.target, self.runner, name, &now.spec.0, kv, secs),
            Err(e) => JobAccess::Undetermined(format!("keyvault show failed: {e}")),
        };
        match access {
            JobAccess::Granted { fresh: None, .. } => Ok(()),
            JobAccess::Granted {
                fresh: Some((at, by)),
                ..
            } => {
                self.runner.note(&format!(
                    "container app job {name}'s identity was granted access to Key Vault \
                     {vault} at {at} UTC; a new grant can take a few minutes to apply: an \
                     execution of {name} started before {by} UTC may fail to read its secrets"
                ));
                Ok(())
            }
            JobAccess::Undetermined(why) => {
                self.runner.note(&format!(
                    "could not confirm that container app job {name}'s identity can read Key \
                     Vault {vault} ({why}); its next execution may fail; check with `opv doctor \
                     --env {}`",
                    self.env
                ));
                Ok(())
            }
            JobAccess::Missing(why) => {
                self.runner.note(&why);
                self.runner.note(&format!(
                    "nothing was updated; to deploy container app {} alone now, remove {name} \
                     from azure.companion_jobs for one deploy and add it back after the grant",
                    self.target.container_app
                ));
                Err(self.missing_right(j, now, kv.as_ref().ok()))
            }
        }
    }

    /// `MissingRight` asked of job `j`'s identity, not of whoever runs opv (#238).
    fn missing_right(
        &self,
        j: &ContainerAppJob<'_>,
        now: &RuntimeSnapshot,
        kv: Option<&Value>,
    ) -> Error {
        let principal = j.principal(now).ok().and_then(Result::ok);
        let who = match &principal {
            Some(p) => format!("container app job {} (principal {p})", j.name),
            None => format!("container app job {}", j.name),
        };
        let rbac = kv
            .and_then(|v| v.pointer("/properties/enableRbacAuthorization"))
            .and_then(Value::as_bool)
            == Some(true);
        let grant = match kv.and_then(|v| v["id"].as_str()) {
            Some(scope) if rbac => GrantModel::Rbac {
                role: "Key Vault Secrets User".into(),
                scope: scope.into(),
            },
            _ => GrantModel::AccessPolicy {
                permissions: vec!["get".into()],
            },
        };
        let what = match (&principal, rbac) {
            (None, _) => "containerapp job show",
            (Some(_), true) => "role assignment list",
            (Some(_), false) => "keyvault show",
        };
        preflight::unusable(what, |seen| Cause::MissingRight {
            system: System::Azure,
            resource: ResourceRef {
                kind: ResourceKind::KeyVault,
                name: ResourceName::new(&self.target.key_vault),
                scope: Some(format!("subscription {}", self.target.subscription)),
            },
            right: Right::Read,
            grant,
            env: Some(EnvName::new(self.env)),
            target: None,
            seen,
            grantee: Some(Principal::AppIdentity { name: who }),
        })
    }
}

/// What of `change` a resource binding `bound` still needs (step 2).
fn sub_change(change: &RuntimeChange, bound: &BTreeMap<String, Binding>) -> RuntimeChange {
    let pin = change
        .pin
        .iter()
        .filter(|(n, (s, v))| {
            !matches!(bound.get(*n), Some(Binding::Pinned { store_name, version })
                if store_name.eq_ignore_ascii_case(s) && version == v)
        })
        .map(|(n, sv)| (n.clone(), sv.clone()))
        .collect();
    let set = change
        .set
        .iter()
        .filter(|(n, value)| {
            let digest = hex::encode(Sha256::digest(value.as_bytes()));
            !matches!(bound.get(*n), Some(Binding::Plain { digest: d }) if *d == digest)
        })
        .map(|(n, v)| (n.clone(), v.clone()))
        .collect();
    RuntimeChange {
        pin,
        set,
        unbind: change
            .unbind
            .iter()
            .filter(|n| bound.contains_key(*n))
            .cloned()
            .collect(),
        stamp: change.stamp.clone(),
    }
}

fn is_empty(c: &RuntimeChange) -> bool {
    c.pin.is_empty() && c.set.is_empty() && c.unbind.is_empty()
}

/// The env names a sub-change touches, for the notes and `Partial`.
fn names_of(c: &RuntimeChange) -> String {
    let names: BTreeSet<&String> = c.pin.keys().chain(c.set.keys()).chain(&c.unbind).collect();
    names.into_iter().cloned().collect::<Vec<_>>().join(", ")
}

/// `e` as `Partial` when `done` (the jobs already updated) is not empty (§4 table).
fn partial(done: &[String], e: Error) -> Error {
    match e {
        Error::Catalog(cause, up) if !done.is_empty() => Error::Catalog(
            Box::new(Cause::Partial {
                done: done.to_vec(),
                scope: None,
                then: cause,
            }),
            up,
        ),
        e => e,
    }
}

impl PinnedRuntime for AppWithJobs<'_> {
    fn bindings(&self) -> Result<RuntimeSnapshot, Error> {
        let (app, jobs) = self.read_all()?;
        let mut names: BTreeSet<&String> = app.bindings.keys().collect();
        names.extend(jobs.iter().flat_map(|j| j.bindings.keys()));
        let mut bindings = BTreeMap::new();
        for name in names {
            let mut all = vec![(self.app.describe(), app.bindings.get(name))];
            all.extend(
                self.jobs
                    .iter()
                    .zip(&jobs)
                    .map(|(j, s)| (j.describe(), s.bindings.get(name))),
            );
            if let Some(b) = self.merge(name, &all)? {
                bindings.insert(name.clone(), b);
            }
        }
        let mut fp = Sha256::new();
        fp.update(app.unmanaged_fingerprint.as_bytes());
        let mut specs = Map::new();
        for (j, s) in self.jobs.iter().zip(jobs) {
            fp.update(s.unmanaged_fingerprint.as_bytes());
            specs.insert(j.name.to_string(), s.spec.0);
        }
        Ok(RuntimeSnapshot {
            bindings,
            unmanaged_fingerprint: hex::encode(fp.finalize()),
            revision: app.revision,
            spec: RawSpec(json!({"app": app.spec.0, "jobs": specs})),
        })
    }

    fn apply(&self, change: &RuntimeChange, snapshot: &RuntimeSnapshot) -> Result<Revision, Error> {
        let (app, jobs) = self.recheck(snapshot)?;
        let subs: Vec<RuntimeChange> = jobs
            .iter()
            .map(|s| sub_change(change, &s.bindings))
            .collect();
        // The access gate, for every job before any update (A4, D7).
        let mut kv: Option<Result<Value, Error>> = None;
        for ((j, now), sub) in self.jobs.iter().zip(&jobs).zip(&subs) {
            let pinned_after = now
                .bindings
                .iter()
                .any(|(n, b)| matches!(b, Binding::Pinned { .. }) && !sub.unbind.contains(n));
            if is_empty(sub) || (sub.pin.is_empty() && !pinned_after) {
                continue;
            }
            let kv = kv.get_or_insert_with(|| {
                let res = self.res(None);
                let args = [
                    "keyvault",
                    "show",
                    "-n",
                    &self.target.key_vault,
                    "-o",
                    "json",
                ];
                res.read("keyvault show", res.ctx(), &args)
            });
            self.gate(j, now, kv)?;
        }
        // Jobs first (D2), then the app.
        let mut done = Vec::new();
        for ((j, now), sub) in self.jobs.iter().zip(&jobs).zip(&subs) {
            if is_empty(sub) {
                continue;
            }
            j.apply(sub, now).map_err(|e| partial(&done, e))?;
            let names = names_of(sub);
            self.runner.note(&format!(
                "{} pins {names}; its next execution uses them",
                j.describe()
            ));
            done.push(format!("{}: {names}", j.describe()));
        }
        let own = sub_change(change, &app.bindings);
        if !is_empty(&own) {
            return self.app.apply(&own, &app).map_err(|e| partial(&done, e));
        }
        if !done.is_empty() {
            self.runner.note(&format!(
                "{} unchanged; only its jobs changed",
                self.app.describe()
            ));
        }
        app.revision
            .ok_or_else(|| preflight::missing_in_reply("containerapp show", "latestRevisionName"))
    }

    fn await_healthy(&self, revision: &Revision) -> Result<Health, Error> {
        self.app.await_healthy(revision)
    }

    fn check_access(&self, names: &[String]) -> Result<Vec<AccessFinding>, Error> {
        self.app.check_access(names)
    }

    fn config_in_store(&self) -> bool {
        self.app.config_in_store()
    }

    fn describe(&self) -> String {
        self.app.describe()
    }

    fn inspect_hint(&self, revision: &Revision) -> String {
        self.app.inspect_hint(revision)
    }

    /// Every job, then the app, before any Key Vault delete (FR-32).
    fn release(&self, names: &[String]) -> Result<(), Error> {
        for j in &self.jobs {
            j.release(names)?;
        }
        self.app.release(names)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pinned(v: &str) -> Binding {
        Binding::Pinned {
            store_name: "API-KEY".into(),
            version: v.into(),
        }
    }

    #[test]
    fn a_sub_change_keeps_only_what_the_resource_lacks() {
        let change = RuntimeChange {
            pin: BTreeMap::from([
                (
                    "API_KEY".to_string(),
                    ("API-KEY".to_string(), "v2".to_string()),
                ),
                (
                    "DB_URL".to_string(),
                    ("DB-URL".to_string(), "v1".to_string()),
                ),
            ]),
            set: BTreeMap::new(),
            unbind: vec!["OLD_KEY".into()],
            stamp: None,
        };
        let bound = BTreeMap::from([
            ("API_KEY".to_string(), pinned("v2")),
            ("DB_URL".to_string(), pinned("v1")),
        ]);
        let sub = sub_change(&change, &bound);
        assert_eq!(sub.pin.keys().collect::<Vec<_>>(), ["DB_URL"]);
        assert!(sub.unbind.is_empty());
        assert_eq!(names_of(&sub), "DB_URL");
    }
}
