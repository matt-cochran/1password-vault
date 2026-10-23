//! The engine shared by a Container App and a Container Apps Job (M4, `docs/design/azure-jobs.md`
//! §4): the `show` read, the managed container (R1), bindings and the unmanaged fingerprint
//! (FR-31), the edit of a fresh spec (R2), the identity's principal and its access to Key Vault
//! (R6). One [`Resource`] describes which of the two it reads; everything here is the same for
//! both, so app and job behaviour cannot drift apart. `containerapp.rs` and `job.rs` add what
//! only one of them has (revisions and health; settling).
//!
//! | fn | argv | stdin |
//! |---|---|---|
//! | `show` | `<noun> show -g <rg> -n <name> -o json` (`containerapp` or `containerapp job`) | — |
//! | `principal` | `identity show --ids <id> -o json` (user-assigned identity whose principal the resource does not list) | — |
//! | `check_access` | `<noun> show …`, then as `principal`, `keyvault show -n <vault> -o json`, `role assignment list --assignee <principal> --scope <vault id> --include-inherited --include-groups -o json` (RBAC vaults only) | — |
//!
//! Every call adds `--only-show-errors` and `--subscription <azure.subscription>` (NR-7). All
//! calls here are reads (`runner.read`, retried); the updates stay with each resource.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::az::{self, Effect};
use super::{AzureTarget, preflight};
use crate::cause::{
    Cause, ConfigCheck, DiagnoseContext, DottedPath, EnvName, FieldRule, ResourceKind,
    ResourceName, ResourceRef,
};
use crate::domain::{AccessFinding, Binding, RawSpec, Revision, RuntimeChange, RuntimeSnapshot};
use crate::error::Error;
use crate::runner::{CommandRunner, Outcome, Output};

/// Roles that let an identity read Key Vault secret values (R6).
pub const READ_ROLES: &[&str] = &[
    "Key Vault Secrets User",
    "Key Vault Secrets Officer",
    "Key Vault Administrator",
];

/// Prefix of the Container Apps secrets opv owns (R2).
pub(super) const SECRET_PREFIX: &str = "opv-";
pub(super) const SECRETS: &str = "/properties/configuration/secrets";

/// Which Container Apps resource the engine reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    App,
    /// A Container Apps Job: no revisions, no etag (J2).
    Job,
}

impl Kind {
    /// The `az` command group: `containerapp` or `containerapp job` (J1).
    fn noun(self) -> &'static [&'static str] {
        match self {
            Kind::App => &["containerapp"],
            Kind::Job => &["containerapp", "job"],
        }
    }

    /// The resource in words: `container app`, `container app job`.
    fn words(self) -> &'static str {
        match self {
            Kind::App => "container app",
            Kind::Job => "container app job",
        }
    }

    /// Status fields under `properties` that change without anyone editing the resource
    /// (`systemData` is removed for both); a job's are J2's.
    fn read_only(self) -> &'static [&'static str] {
        match self {
            Kind::App => &[
                "provisioningState",
                "runningStatus",
                "latestRevisionName",
                "latestReadyRevisionName",
                "latestRevisionFqdn",
                "outboundIpAddresses",
                "eventStreamEndpoint",
            ],
            Kind::Job => &[
                "provisioningState",
                "outboundIpAddresses",
                "eventStreamEndpoint",
            ],
        }
    }
}

/// One Container App or Container Apps Job in the target's resource group and subscription.
pub(super) struct Resource<'a> {
    pub runner: &'a dyn CommandRunner,
    pub target: &'a AzureTarget,
    pub kind: Kind,
    pub name: &'a str,
    /// Managed env names (from the template, FR-8).
    pub managed: &'a BTreeSet<String>,
    /// The opv environment this resource serves, for the commands an error names.
    pub env: Option<&'a str>,
}

impl Resource<'_> {
    fn rg(&self) -> &str {
        &self.target.resource_group
    }

    /// This resource, as the subject of a cause.
    pub fn subject(&self) -> ResourceRef {
        ResourceRef {
            kind: match self.kind {
                Kind::App => ResourceKind::ContainerApp,
                Kind::Job => ResourceKind::ContainerAppJob,
            },
            name: ResourceName::new(self.name),
            scope: Some(format!(
                "resource group {} (subscription {})",
                self.rg(),
                self.target.subscription
            )),
        }
    }

    /// A call about this resource, for its diagnosis.
    pub fn ctx(&self) -> DiagnoseContext {
        DiagnoseContext {
            env: self.env.map(EnvName::new),
            resource: Some(self.subject()),
            ..DiagnoseContext::default()
        }
    }

    /// A call about the target's Key Vault, for its diagnosis.
    fn vault_ctx(&self) -> DiagnoseContext {
        az::about(
            ResourceKind::KeyVault,
            &self.target.key_vault,
            format!("subscription {}", self.target.subscription),
            self.env,
        )
    }

    /// `base` plus `--only-show-errors` (R7) and `--subscription` (NR-7).
    pub fn argv(&self, base: &[&str]) -> Vec<String> {
        let mut v: Vec<String> = base.iter().map(|s| s.to_string()).collect();
        v.push(az::ONLY_SHOW_ERRORS.into());
        v.extend(["--subscription".into(), self.target.subscription.clone()]);
        v
    }

    /// One `az` read, parsed; a call that did not succeed is diagnosed from what opv
    /// observed, `az`'s reply as evidence.
    fn read(&self, what: &str, ctx: DiagnoseContext, base: &[&str]) -> Result<Value, Error> {
        let owned = self.argv(base);
        let args: Vec<&str> = owned.iter().map(String::as_str).collect();
        match az::invoke(self.runner, Effect::Read, what, &args, None, &[])? {
            Outcome::Done(out) => parse(&out, what),
            Outcome::Refused(_) | Outcome::Unknown { .. } => Err(az::failed(self.runner, ctx)),
        }
    }

    /// `<noun> show -g <rg> -n <name> -o json`.
    pub fn show(&self) -> Result<Value, Error> {
        let noun = self.kind.noun();
        let what = format!("{} show", noun.join(" "));
        let mut base = noun.to_vec();
        base.extend(["show", "-g", self.rg(), "-n", self.name, "-o", "json"]);
        self.read(&what, self.ctx(), &base)
    }

    /// The index of the managed container (R1; D6 for a job).
    pub fn container_index(&self, spec: &Value) -> Result<usize, Error> {
        let names: Vec<&str> = spec
            .pointer("/properties/template/containers")
            .and_then(Value::as_array)
            .map(|cs| {
                cs.iter()
                    .map(|c| c["name"].as_str().unwrap_or(""))
                    .collect()
            })
            .unwrap_or_default();
        // azure.container must name one of the resource's containers; with no
        // azure.container the resource must run exactly one.
        let invalid = || {
            Error::from(Cause::ConfigInvalid {
                source: crate::domain::model::ReadFrom::default().0,
                at: None,
                field: DottedPath(vec!["azure".into(), "container".into()]),
                rule: FieldRule::Check {
                    check: ConfigCheck::NotOneOf {
                        allowed: names.iter().map(|n| n.to_string()).collect(),
                        closest: None,
                    },
                },
            })
        };
        match &self.target.container {
            Some(want) => names.iter().position(|n| n == want).ok_or_else(invalid),
            None if names.len() == 1 => Ok(0),
            None => Err(invalid()),
        }
    }

    fn is_managed(&self, env: &Value) -> bool {
        env["name"]
            .as_str()
            .is_some_and(|n| self.managed.contains(n))
    }

    /// `spec` without managed env entries, `opv-` secrets and read-only fields (FR-31).
    pub fn strip(&self, spec: &Value, idx: usize) -> Value {
        let mut v = spec.clone();
        if let Some(o) = v.as_object_mut() {
            o.remove("systemData");
        }
        if let Some(p) = v.get_mut("properties").and_then(Value::as_object_mut) {
            for k in self.kind.read_only() {
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

    pub fn stripped(&self, spec: &Value) -> Result<Value, Error> {
        Ok(self.strip(spec, self.container_index(spec)?))
    }

    /// The unmanaged settings that differ between `before` and `now`, as JSON paths
    /// (`properties.template.scale.maxReplicas`), never their values; empty when either
    /// spec has no container to compare.
    pub fn changed_paths(&self, before: &Value, now: &Value) -> Vec<String> {
        let mut out = Vec::new();
        if let (Ok(a), Ok(b)) = (self.stripped(before), self.stripped(now)) {
            diff_paths(&a, &b, "", &mut out);
        }
        out
    }

    /// The vault's `properties.vaultUri` as read from Azure, without a trailing slash
    /// (NR-6; `https://<vault>.vault.azure.net` in the public cloud): kept by the preflight,
    /// else read once.
    pub fn vault_uri(&self) -> Result<String, Error> {
        preflight::vault_uri_of(self.target, self.runner)
    }

    /// Bindings and the unmanaged fingerprint of `spec` (FR-31). A `secrets: null` reads as
    /// no secrets (J2). `revision` is the app's `latestRevisionName`; a job has none.
    pub fn snapshot_from(&self, spec: Value) -> Result<RuntimeSnapshot, Error> {
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
                    .and_then(|u| reference(&base, u))
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

    /// The fresh spec with `change` applied (R2, Q5). Superseded secrets stay; the caller
    /// removes them.
    pub fn edit(&self, doc: &mut Value, idx: usize, change: &RuntimeChange) -> Result<(), Error> {
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
        // FR-32, NR-1: an unbound name is pruned once the new revision is healthy, so its
        // `opv-` secret goes in this same document; the resource never holds a reference to
        // a Key Vault entry opv is about to delete.
        let unbound: BTreeSet<String> = env
            .iter()
            .filter(|e| {
                e["name"]
                    .as_str()
                    .is_some_and(|n| change.unbind.iter().any(|u| u == n))
            })
            .filter_map(|e| e["secretRef"].as_str().map(String::from))
            .collect();
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
        let used = env_refs(doc);
        if let Some(secrets) = doc.pointer_mut(SECRETS).and_then(Value::as_array_mut) {
            secrets.retain(|s| {
                let name = s["name"].as_str().unwrap_or_default();
                !is_opv_secret(s) || !unbound.contains(name) || used.contains(name)
            });
        }
        Ok(())
    }

    /// The identity's principal id (R6), or the finding when the resource has none that opv
    /// can use. A user-assigned identity must be attached; its principal comes from the
    /// resource (`identity.userAssignedIdentities`, keys matched without case: a job lists
    /// `resourcegroups`, J12), else from `az identity show`.
    pub fn principal(&self, res: &Value) -> Result<Result<String, String>, Error> {
        let (rg, name, kv) = (self.rg(), self.name, &self.target.key_vault);
        let (words, noun) = (self.kind.words(), self.kind.noun().join(" "));
        let id = &self.target.identity;
        if id.eq_ignore_ascii_case("system") {
            return Ok(res
                .pointer("/identity/principalId")
                .and_then(Value::as_str)
                .filter(|p| !p.is_empty())
                .map(String::from)
                .ok_or_else(|| {
                    format!(
                        "{words} {name} has no system-assigned identity to read Key Vault {kv} \
                         with; assign one: `az {noun} identity assign -g {rg} -n {name} \
                         --system-assigned`, then grant it read access to {kv}"
                    )
                }));
        }
        let attached = res
            .pointer("/identity/userAssignedIdentities")
            .and_then(Value::as_object)
            .and_then(|m| m.iter().find(|(k, _)| k.eq_ignore_ascii_case(id)))
            .map(|(_, v)| v);
        let Some(entry) = attached else {
            return Ok(Err(format!(
                "{words} {name} does not have the user-assigned identity {id} that the \
                 configuration names; attach it: `az {noun} identity assign -g {rg} -n {name} \
                 --user-assigned {id}`"
            )));
        };
        if let Some(p) = entry["principalId"].as_str().filter(|p| !p.is_empty()) {
            return Ok(Ok(p.to_string()));
        }
        let ctx = DiagnoseContext {
            env: self.env.map(EnvName::new),
            ..DiagnoseContext::default()
        };
        Ok(self.read(
            "identity show",
            ctx,
            &["identity", "show", "--ids", id, "-o", "json"],
        )?["principalId"]
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

    /// Advisory access check (R6): one finding per name the identity cannot read.
    pub fn check_access(&self, names: &[String]) -> Result<Vec<AccessFinding>, Error> {
        let each = |reason: String| {
            names
                .iter()
                .map(|n| AccessFinding {
                    store_name: n.clone(),
                    reason: reason.clone(),
                })
                .collect()
        };
        let who = match self.kind {
            Kind::App => "the app identity",
            Kind::Job => "the job identity",
        };
        let res = self.show()?;
        let principal = match self.principal(&res)? {
            Ok(p) => p,
            Err(reason) => return Ok(each(reason)),
        };
        let kv = &self.target.key_vault;
        let vault = self.read(
            "keyvault show",
            self.vault_ctx(),
            &["keyvault", "show", "-n", kv, "-o", "json"],
        )?;
        let rbac = vault
            .pointer("/properties/enableRbacAuthorization")
            .and_then(Value::as_bool);
        if rbac != Some(true) {
            return Ok(if policy_grants_get(&vault, &principal) {
                Vec::new()
            } else {
                each(format!(
                    "{who} (principal {principal}) has no access policy with secret get on Key \
                     Vault {kv}; grant it: `az keyvault set-policy -n {kv} --object-id \
                     {principal} --secret-permissions get`"
                ))
            });
        }
        let scope = vault["id"]
            .as_str()
            .ok_or_else(|| preflight::missing_in_reply("keyvault show", "id"))?;
        let roles = self.read(
            "role assignment list",
            self.vault_ctx(),
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
        )?;
        let has_role = roles.as_array().is_some_and(|rs| {
            rs.iter()
                .filter_map(|r| r["roleDefinitionName"].as_str())
                .any(|r| READ_ROLES.contains(&r))
        });
        Ok(if has_role {
            Vec::new()
        } else {
            each(format!(
                "{who} (principal {principal}) has no Key Vault secrets read role on Key Vault \
                 {kv}; grant it: `az role assignment create --assignee-object-id {principal} \
                 --assignee-principal-type ServicePrincipal --role \"Key Vault Secrets User\" \
                 --scope {scope}` (a new grant can take a few minutes to apply)"
            ))
        })
    }
}

/// `Pinned` for `<vault_uri>/secrets/<name>/<version>`, else `None`.
pub(super) fn reference(base: &str, url: &str) -> Option<Binding> {
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
/// a template change and Azure starts a new revision (Q16); a job keeps the same names so
/// that it shares one binding reader with its app (J8).
pub fn secret_name(store_name: &str, version: &str) -> String {
    let digest = hex::encode(Sha256::digest(format!(
        "{}/{version}",
        store_name.to_ascii_lowercase()
    )));
    format!("{SECRET_PREFIX}{}", &digest[..16])
}

/// Parses the reply of `az <what>`, or reports a reply opv cannot read (A1).
pub(super) fn parse(out: &Output, what: &str) -> Result<Value, Error> {
    preflight::unreadable_json(&out.stdout, what)
}

/// Pushes onto `out` the path (under `at`) of each leaf where `a` and `b` differ: object
/// keys joined by `.`, array items as `[i]`; an array that changed length is one path.
pub(super) fn diff_paths(a: &Value, b: &Value, at: &str, out: &mut Vec<String>) {
    if a == b {
        return;
    }
    let here = || {
        if at.is_empty() {
            "(the whole app)".to_string()
        } else {
            at.to_string()
        }
    };
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            let keys: BTreeSet<&String> = x.keys().chain(y.keys()).collect();
            for k in keys {
                let path = if at.is_empty() {
                    k.clone()
                } else {
                    format!("{at}.{k}")
                };
                let null = Value::Null;
                diff_paths(
                    x.get(k).unwrap_or(&null),
                    y.get(k).unwrap_or(&null),
                    &path,
                    out,
                );
            }
        }
        (Value::Array(x), Value::Array(y)) if x.len() == y.len() => {
            for (i, (p, q)) in x.iter().zip(y).enumerate() {
                diff_paths(p, q, &format!("{at}[{i}]"), out);
            }
        }
        _ => out.push(here()),
    }
}

/// SHA-256 hex of the canonical JSON: serde_json maps are sorted by key.
pub(super) fn fingerprint(v: &Value) -> String {
    hex::encode(Sha256::digest(v.to_string()))
}

pub(super) fn is_opv_secret(s: &Value) -> bool {
    s["name"]
        .as_str()
        .is_some_and(|n| n.starts_with(SECRET_PREFIX))
}

/// Every `secretRef` of every container and init container.
pub(super) fn env_refs(doc: &Value) -> BTreeSet<String> {
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
