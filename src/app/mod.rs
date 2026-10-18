//! Application use cases, one module per command (§6.2).
//!
//! Rules shared by every command:
//! - The environment name is resolved with [`Fleet::environment`] before any subprocess
//!   call, so an unknown name is `NotDeclared` and `plan::build` never sees one.
//! - A command that reads 1Password makes exactly one `op item get` (FR-13); a failed `op`
//!   call adds only the free `op whoami` / `op account list` diagnosis (FR-26). The read is
//!   tolerant, and a signed-in person's run may tidy the item (a check read, one edit, a
//!   verifying read; FR-43, [`tidy`]); a service account or CI never writes.
//! - Output names products, keys, kinds, rules and target names, never values (SR-1).

pub mod access;
pub mod access_create;
pub mod account;
pub mod add;
pub mod agent_view;
pub mod approve;
#[cfg(test)]
mod azure_tests;
pub mod bootstrap;
pub mod changed;
#[cfg(test)]
mod characterization_tests;
pub(crate) mod ci_summary;
pub mod ci_workflow;
pub mod config_cmd;
pub mod config_export;
pub mod contract;
pub mod declare;
pub mod delivery;
pub mod delivery_preview;
pub mod doctor;
pub mod explain;
pub mod generate;
#[cfg(test)]
mod github_tests;
#[cfg(test)]
mod guidance_tests;
pub mod guide;
pub mod history;
pub mod import;
pub mod import_local;
pub mod init;
#[cfg(test)]
pub(crate) mod json_tests;
#[cfg(test)]
mod ledger_tests;
pub mod local;
pub mod local_delivery;
pub mod login;
pub mod masked;
pub mod mcp_install;
pub mod needs;
pub mod open;
pub mod personal;
#[cfg(test)]
mod pinned_tests;
#[cfg(test)]
#[path = "placement_tests.rs"]
mod placement_tests;
pub(crate) mod preflight;
#[cfg(test)]
#[path = "product_flag_tests.rs"]
mod product_flag_tests;
pub mod propose;
pub mod ready;
pub mod receipt_age;
pub mod remote_delivery;
pub mod remote_diagnose;
pub mod repair;
pub mod rule_source;
pub mod run;
pub mod setup;
mod setup_import;
pub mod setup_recipe;
pub mod setup_runtime;
#[cfg(test)]
mod shared_tests;
pub mod signin;
pub(crate) mod signin_filter;
#[cfg(test)]
mod simple_tests;
pub mod skeleton;
pub mod skill;
#[cfg(test)]
mod skill_tests;
#[cfg(test)]
mod staged_tests;
pub mod status;
pub mod structure;
pub mod structure_cmd;
pub mod suggest;
pub mod sync;
pub mod target_cmd;
pub mod target_credentials;
pub(crate) mod tidy;
#[cfg(test)]
mod ux2_tests;
#[cfg(test)]
mod ux_tests;
pub(crate) mod variables;
pub mod vault_locate;
pub mod version;

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{self, Write};

use crate::adapters::onepassword;
use crate::domain::plan;
use crate::domain::{
    Environment, Fleet, KeySpec, KeyState, Kind, Row, SecretValue, StoreEntry, SyncPlan,
    TargetState, key_label,
};
use crate::error::Error;
use crate::ports::{PinnedStore, Ports, Store};
use crate::provider::{Channels, FileCapability, TargetConfig};
use crate::runner::CommandRunner;

/// Store digests are not computable locally (D0 Q4, ruling P1): every key present on the
/// target is `Unknown` to the planner, and change detection is stage-and-compare in `sync`.
fn no_digest(_: &SecretValue) -> Option<String> {
    None
}

/// Read the environment's boundary items once each (FR-13, FR-57), list the store of target
/// `target` once when `ports` are given, and build the plan for that target (`None`: no
/// target). `env_name` must already be resolved, and the target opened, by the caller (so a
/// missing target is `NothingInScope` before any call).
///
/// With a store, every ready secret is also checked against the store's own rules
/// ([`Store::refusal`]), so `status` and `plan` show a value `sync` would refuse as a
/// failing rule naming product/KEY. A pinned store is also read once per ready secret it
/// lists, and the value compared exactly (FR-31); a staged store (Fly) is never read.
#[allow(clippy::too_many_arguments)]
pub(crate) fn read_and_plan(
    fleet: &Fleet,
    env_name: &str,
    target: Option<&str>,
    r: &dyn CommandRunner,
    ports: Option<&Ports<'_>>,
    rotate: &BTreeSet<(String, String)>,
    prune_immutable: &BTreeSet<(String, String)>,
) -> Result<(SyncPlan, Vec<StoreEntry>), Error> {
    let read = tidy::read(fleet, env_name, r)?;
    let ledgers = placement_ledgers(fleet, env_name, target, ports, r);
    let (mut plan, listed) = plan_item_with(
        fleet,
        env_name,
        target,
        read.fields,
        ports,
        rotate,
        prune_immutable,
        &ledgers,
    )?;
    plan.tidy = read.changes;
    plan.tidy_error = read.tidy_error;
    Ok((plan, listed))
}

/// The item fields, the item's `version` and each boundary item's `version` by id (C2):
/// [`read_item_fields`]'s result.
pub(crate) type ItemRead = (Vec<plan::ItemField>, Option<u64>, BTreeMap<String, u64>);

/// A plan, its store listing, the item's `version` and each boundary item's `version` by id
/// (C2): [`read_and_plan_versioned`]'s result.
pub(crate) type VersionedPlan = (
    SyncPlan,
    Vec<StoreEntry>,
    Option<u64>,
    BTreeMap<String, u64>,
);

/// [`read_and_plan`] that also returns the item's `version` integer and the `version` read
/// from each boundary item by id (C2), for the plan id (FR-41) and the delivery recording.
/// Still one item read (FR-13), plus a person's tidy (FR-43): the version is the tidied
/// item's, so a plan that tidied and the sync after it agree.
#[allow(clippy::too_many_arguments)]
pub(crate) fn read_and_plan_versioned(
    fleet: &Fleet,
    env_name: &str,
    target: Option<&str>,
    r: &dyn CommandRunner,
    ports: Option<&Ports<'_>>,
    rotate: &BTreeSet<(String, String)>,
    prune_immutable: &BTreeSet<(String, String)>,
) -> Result<VersionedPlan, Error> {
    let read = tidy::read(fleet, env_name, r)?;
    let ledgers = placement_ledgers(fleet, env_name, target, ports, r);
    let (mut plan, listed) = plan_item_with(
        fleet,
        env_name,
        target,
        read.fields,
        ports,
        rotate,
        prune_immutable,
        &ledgers,
    )?;
    plan.tidy = read.changes;
    plan.tidy_error = read.tidy_error;
    Ok((plan, listed, read.version, read.item_versions))
}

/// The environment's item fields, `version` integer (FR-41) and per-boundary-item versions
/// (C2): its one read by IDs (FR-13), tolerant and tidied when a person runs opv (FR-43,
/// [`tidy::read`]).
pub(crate) fn read_item_fields(
    fleet: &Fleet,
    env_name: &str,
    r: &dyn CommandRunner,
) -> Result<ItemRead, Error> {
    let read = tidy::read(fleet, env_name, r)?;
    Ok((read.fields, read.version, read.item_versions))
}

/// The plan id (FR-41) of `plan`, built against `listed` on target `target` behind `ports`
/// from item version `item_version`. A staged store's versions are value digests (Fly), so
/// only a pinned store's version ids go in (SR-1).
#[allow(clippy::too_many_arguments)]
pub(crate) fn plan_id_of(
    fleet: &Fleet,
    env_name: &str,
    target: &str,
    product: Option<&str>,
    item_version: Option<u64>,
    plan: &SyncPlan,
    listed: &[StoreEntry],
    ports: &Ports<'_>,
    rotate: &BTreeSet<(String, String)>,
    own_plan: Option<&str>,
) -> String {
    let name_of = |p: &str, k: &str| {
        let t = fleet.environments.get(env_name)?.targets.get(target)?;
        Some(t.config.env_name(p, k))
    };
    // The route each name takes (M4, §4.3): a file key on a Native target is
    // `file:<path>`; every other key is on its kind's channel.
    let routes = |p: &str, k: &str| -> Option<String> {
        let t = fleet.environments.get(env_name)?.targets.get(target)?;
        let spec = fleet.products.get(p)?.keys.get(k)?;
        if let Some(path) = &spec.file
            && matches!(t.config.channels().files, FileCapability::Native { .. })
        {
            return Some(format!("file:{path}"));
        }
        Some(match spec.kind {
            Kind::Secret => "secret".to_string(),
            Kind::Config => "config".to_string(),
        })
    };
    crate::domain::provenance::plan_id(
        &crate::domain::provenance::PlanIdInput {
            env: env_name,
            product,
            item_version,
            listed,
            version_ids: matches!(ports, Ports::Pinned { .. }),
            rotate,
            name_of: &name_of,
            routes: &routes,
            own_plan,
        },
        plan,
    )
}

/// [`read_and_plan`] for a local check of the products in `fleet` only, with no target.
/// The item is read (and tidied) against `full`, the whole configuration, so fields of
/// products outside `fleet` are never mistaken for strays; they cannot block the check,
/// because the plan covers `fleet` only.
pub(crate) fn read_and_plan_products(
    fleet: &Fleet,
    full: &Fleet,
    env_name: &str,
    r: &dyn CommandRunner,
) -> Result<SyncPlan, Error> {
    fleet.environment(env_name)?;
    let read = tidy::read_for(fleet, full, env_name, r)?;
    let none = BTreeSet::new();
    let mut plan = plan_item(fleet, env_name, None, read.fields, None, &none, &none)?.0;
    plan.tidy = read.changes;
    plan.tidy_error = read.tidy_error;
    Ok(plan)
}

/// The plan of `fields` for target `target` of `env_name` (`None`: no target).
#[allow(clippy::too_many_arguments)]
pub(crate) fn plan_item(
    fleet: &Fleet,
    env_name: &str,
    target: Option<&str>,
    fields: Vec<plan::ItemField>,
    ports: Option<&Ports<'_>>,
    rotate: &BTreeSet<(String, String)>,
    prune_immutable: &BTreeSet<(String, String)>,
) -> Result<(SyncPlan, Vec<StoreEntry>), Error> {
    plan_item_with(
        fleet,
        env_name,
        target,
        fields,
        ports,
        rotate,
        prune_immutable,
        &[],
    )
}

/// The version ledgers of target `target`'s placements (FR-54, FR-58, D11): one per product
/// whose delivery item is recorded, built from that item's evidence lines. Only a staged
/// store needs one (a pinned store's values are read and compared exactly). A state item
/// that cannot be read leaves its names unknown, with a note; it never fails the command.
pub(crate) fn placement_ledgers(
    fleet: &Fleet,
    env_name: &str,
    target: Option<&str>,
    ports: Option<&Ports<'_>>,
    r: &dyn CommandRunner,
) -> Vec<crate::domain::ledger::Ledger> {
    match (target, ports) {
        (Some(t), Some(Ports::Staged { .. })) => delivery::ledgers(fleet, env_name, t, r),
        _ => Vec::new(),
    }
}

/// [`plan_item`] with the placements' version ledgers (FR-54, D11): on a staged store that
/// cannot show values, a name the store still holds at the version opv recorded is compared
/// exactly through its fingerprint, and a name at another version is drift. Each name is
/// judged by its own placement's ledger.
#[allow(clippy::too_many_arguments)]
pub(crate) fn plan_item_with(
    fleet: &Fleet,
    env_name: &str,
    target: Option<&str>,
    fields: Vec<plan::ItemField>,
    ports: Option<&Ports<'_>>,
    rotate: &BTreeSet<(String, String)>,
    prune_immutable: &BTreeSet<(String, String)>,
    ledgers: &[crate::domain::ledger::Ledger],
) -> Result<(SyncPlan, Vec<StoreEntry>), Error> {
    let store: Option<&dyn Store> = ports.map(Ports::store);
    let mut on_target = match store {
        Some(s) => s.list()?,
        None => Vec::new(),
    };
    let refusal = |n: &str, v: &SecretValue| store.and_then(|s| s.refusal(n, v));
    // The first failed read; the planner itself cannot fail.
    let failed: RefCell<Option<Error>> = RefCell::new(None);
    // name → the store's current version, from each read (the pinned flow binds it).
    let versions: RefCell<BTreeMap<String, String>> = RefCell::new(BTreeMap::new());
    let read = |pinned: &dyn PinnedStore, name: &str, desired: &SecretValue| {
        if failed.borrow().is_some() {
            return None;
        }
        match pinned.read(name) {
            Ok(Some((current, version))) => {
                versions.borrow_mut().insert(name.to_string(), version);
                Some(compare(&current, desired))
            }
            Ok(None) => Some(plan::CurrentState::Absent),
            Err(e) => {
                failed.replace(Some(e));
                None
            }
        }
    };
    let pinned = match ports {
        Some(Ports::Pinned { store, .. }) => Some(store.as_ref()),
        _ => None,
    };
    let current = pinned.map(|s| move |n: &str, v: &SecretValue| read(s, n, v));
    // A staged store: the ledger judges a name the store still holds at the recorded version.
    let listed_versions: BTreeMap<String, String> = on_target
        .iter()
        .filter_map(|e| e.version.clone().map(|v| (e.name.clone(), v)))
        .collect();
    let by_ledger = match pinned {
        None if !ledgers.is_empty() => Some(move |n: &str, v: &SecretValue| {
            let now = listed_versions.get(n)?;
            ledgers.iter().find_map(|l| l.check(n, now, v))
        }),
        _ => None,
    };
    let p = plan::build_with(
        fleet,
        env_name,
        fields,
        &on_target,
        &plan::PlanOptions {
            target,
            rotate,
            prune_immutable,
            digest: &no_digest,
            target_check: &refusal,
            current: current
                .as_ref()
                .map(|c| c as &plan::CurrentCheck<'_>)
                .or(by_ledger.as_ref().map(|c| c as &plan::CurrentCheck<'_>)),
        },
    );
    let mut p = p;
    if let (None, Some(t)) = (pinned, target)
        && !ledgers.is_empty()
    {
        let managed = managed_names(fleet, env_name, t).unwrap_or_default();
        let drifted: BTreeSet<String> = ledgers.iter().flat_map(|l| l.drift(&on_target)).collect();
        p.drift = on_target
            .iter()
            .map(|e| e.name.clone())
            .filter(|n| drifted.contains(n) && managed.contains(n))
            .collect();
    }
    if let Some(e) = failed.into_inner() {
        return Err(e);
    }
    // A pinned store's list carries no versions; the reads above found them.
    let versions = versions.into_inner();
    for e in &mut on_target {
        if let Some(v) = versions.get(&e.name) {
            e.version = Some(v.clone());
        }
    }
    Ok((p, on_target))
}

/// Exact, constant-time compare of a stored value with the desired one (FR-31, SR-1).
pub(crate) fn compare(current: &SecretValue, desired: &SecretValue) -> plan::CurrentState {
    use subtle::ConstantTimeEq as _;
    if bool::from(
        current
            .expose()
            .as_bytes()
            .ct_eq(desired.expose().as_bytes()),
    ) {
        plan::CurrentState::Same
    } else {
        plan::CurrentState::Differs
    }
}

/// An error's own Do and Next, in words (design §6.1: no step override): the document's
/// `do` and `next`, rendered from its cause against the invocation. `doctor` and `ready`
/// show these and never a step of their own (07.06, 07.07).
pub(crate) fn own_step(e: &Error) -> (Option<String>, Option<String>) {
    let doc = crate::error::document(e, &crate::error::invocation(), false);
    (
        doc["do"].as_str().map(str::to_string),
        // Schema 3: the typed `next` carries the command in its own field.
        doc["next"]["command"].as_str().map(str::to_string),
    )
}

pub(crate) fn write_err(e: io::Error) -> Error {
    crate::cause::Cause::LocalIo {
        op: crate::cause::LocalOp::Stdout,
        path: std::path::PathBuf::new(),
        io: e.kind().into(),
    }
    .into()
}

/// Additive fields of the FR-21 document.
#[derive(Default)]
pub(crate) struct JsonExtra<'a> {
    /// `plan --json`: the plan id `sync --expect-plan` checks (FR-41).
    pub plan_id: Option<&'a str>,
    /// `status --json` on a pinned target: opv's latest provenance stamp (FR-42).
    pub provenance: Option<&'a crate::domain::Stamp>,
    /// The command to run next on success (`plan`: the sync); `null` otherwise.
    pub next: Option<&'a str>,
    /// The 1Password item link, set as `open_url` on each blocking row (H1); IDs only.
    pub link: Option<&'a str>,
}

/// One target's part of a `status` or `plan` document (FR-56).
pub(crate) struct JsonPart<'a> {
    /// The target's name.
    pub target: &'a str,
    pub plan: &'a SyncPlan,
    /// A pinned target's bindings (R5), keyed by name on the target.
    pub pinned: Option<&'a BTreeMap<String, PinnedRow>>,
    /// `--rotate` entries the part was planned with (`plan` only); sets `rotate` on the
    /// matching rows. `None` for `status`.
    pub rotate: Option<&'a BTreeSet<(String, String)>>,
    /// The config channel's writes (FR-46, `plan` only): a variable the sync sets or
    /// prunes is that row's action, so the plan shows every write the sync makes (#150).
    pub vars: Option<&'a variables::VarPlan>,
}

/// FR-21: one names-only JSON document for `status --json` and `plan --json`. Every row
/// names its product (FR-20 removed).
///
/// `schema_version` is 2 (since 0.10.0); adding a field keeps the version. Rows carry names, states and
/// counts only (SR-1): no value, value fragment, value length or guidance text. Errors
/// before this point leave stdout empty, so a caller only gets a document on success.
///
/// `parts` holds one part per target of the run, in name order (FR-56): every row and
/// held entry names its `target`; `stage`, `prune`, `drift` and `totals` add up the
/// targets; `undelivered` lists the keys none of them delivers. A pinned part adds the
/// per-row binding fields (R5): `binding`, `pending_deploy` and `drift`, keyed by env name.
/// They are absent for a staged target.
///
/// `target_name` is the row's name on its target for every provider, and `target_state`
/// its presence there. `product` is
/// set when `--product` scoped the document (NR-16). `extra` adds `plan_id` (`plan`) and
/// `provenance` (`status`), each left out when unset, and `next`.
///
/// Added in 0.5.0 (H1, H8): `open_url` on each blocking row, the 1Password item link to fix
/// it in (`extra.link`, IDs only); `changes` (`none`, `some` or `unknown`) says whether a
/// sync would change the target. `unknown` means only keys whose values the target hides
/// (Fly) would be staged, so a nightly drift check can tell "certainly in sync" apart.
pub(crate) fn write_json(
    out: &mut dyn Write,
    fleet: &Fleet,
    env_name: &str,
    parts: &[JsonPart<'_>],
    product: Option<&str>,
    extra: &JsonExtra<'_>,
) -> Result<(), Error> {
    let env = fleet.environment(env_name)?;
    let mut rows: Vec<JsonRow> = Vec::new();
    let mut held: Vec<JsonHeld> = Vec::new();
    let mut extras: Vec<JsonName> = Vec::new();
    let mut unreferenced: Vec<JsonName> = Vec::new();
    let mut undelivered: Option<Vec<JsonName>> = None;
    let mut drift = Vec::new();
    let mut tidy = Vec::new();
    let mut tidy_error = None;
    let mut stage = Vec::new();
    let mut prune = Vec::new();
    let mut totals = JsonTotals {
        rows: 0,
        findings: 0,
        extras: 0,
        to_stage: 0,
        held: 0,
        to_prune: 0,
    };
    let mut changed = "none";
    for part in parts {
        let plan = part.plan;
        let on = env.targets.get(part.target);
        let name_of = |p: &str, k: &str| on.map(|t| t.config.env_name(p, k));
        let channels = on.map(|t| t.config.channels());
        let part_rows = json_rows(fleet, part, &name_of, extra.link, channels.as_ref());
        changed = match (changed, changes(plan, &part_rows, part.pinned)) {
            ("some", _) | (_, "some") => "some",
            ("unknown", _) | (_, "unknown") => "unknown",
            _ => "none",
        };
        rows.extend(part_rows);
        held.extend(plan.held_immutable.iter().map(|(product, key)| JsonHeld {
            target: part.target.to_string(),
            product: Some(String::from(product)),
            key: key.clone(),
            target_name: name_of(product, key),
        }));
        for (product, key) in &plan.extras {
            if !extras.iter().any(|e| e.is(product, key)) {
                extras.push(JsonName::new(product, key));
            }
        }
        for (product, key) in &plan.unreferenced_sources {
            if !unreferenced.iter().any(|e| e.is(product, key)) {
                unreferenced.push(JsonName::new(product, key));
            }
        }
        // Undelivered: declared here, and delivered by none of the targets.
        let mine = json_names(&plan.undelivered);
        undelivered = Some(match undelivered {
            None => mine,
            Some(before) => before
                .into_iter()
                .filter(|n| {
                    mine.iter()
                        .any(|m| m.product == n.product && m.key == n.key)
                })
                .collect(),
        });
        drift.extend(plan.drift.iter().cloned());
        tidy.extend(json_tidy(&plan.tidy));
        tidy_error = tidy_error.or(plan.tidy_error);
        stage.extend(plan.stage.iter().map(|(n, _)| n.clone()));
        prune.extend(plan.prune.iter().cloned());
        totals.rows += plan.rows.len();
        totals.findings += plan.blocking();
        totals.to_stage += plan.stage.len();
        totals.held += plan.held_immutable.len();
        totals.to_prune += plan.prune.len();
    }
    totals.extras = extras.len();
    let doc = JsonDoc {
        schema_version: crate::json::SCHEMA_VERSION,
        environment: env_name.to_string(),
        product: product.map(str::to_string),
        changes: changed,
        rows,
        extras,
        undelivered: undelivered.unwrap_or_default(),
        unreferenced_sources: unreferenced,
        drift,
        tidy,
        tidy_error,
        stage,
        held,
        prune,
        totals,
        plan_id: extra.plan_id.map(str::to_string),
        provenance: extra.provenance.map(|s| JsonStamp {
            opv_version: s.opv_version.clone(),
            written: s.written.clone(),
            plan_id: s.plan.clone(),
        }),
        next: extra.next.map(str::to_string),
    };
    // The document is plain strings and numbers: serializing it cannot fail.
    let text = serde_json::to_string(&doc).map_err(|_| -> Error {
        crate::cause::Cause::Bug {
            site: "the --json document did not serialize",
        }
        .into()
    })?;
    writeln!(out, "{text}").map_err(write_err)
}

/// The JSON rows of one target's part, each naming the target (FR-56).
fn json_rows(
    fleet: &Fleet,
    part: &JsonPart<'_>,
    name_of: &dyn Fn(&str, &str) -> Option<String>,
    link: Option<&str>,
    channels: Option<&Channels>,
) -> Vec<JsonRow> {
    let plan = part.plan;
    let (var_set, var_prune): (&[String], &[String]) = match part.vars {
        Some(v) => (&v.set, &v.prune),
        None => (&[], &[]),
    };
    let staged: HashSet<&str> = plan
        .stage
        .iter()
        .map(|(n, _)| n.as_str())
        .chain(var_set.iter().map(String::as_str))
        .collect();
    let pruned: HashSet<&str> = plan
        .prune
        .iter()
        .chain(var_prune)
        .map(String::as_str)
        .collect();
    let held_keys: HashSet<(&str, &str)> = plan
        .held_immutable
        .iter()
        .map(|(p, k)| (p.as_str(), k.as_str()))
        .collect();
    let held_from_prune: HashSet<&str> = plan
        .held_from_prune
        .iter()
        .map(|(_, _, n)| n.as_str())
        .collect();
    plan.rows
        .iter()
        .map(|r| {
            let target_name = name_of(&r.product, &r.key);
            let action = row_action(
                r,
                target_name.as_deref(),
                &staged,
                &pruned,
                &held_keys,
                &held_from_prune,
            );
            let bound = target_name
                .as_deref()
                .and_then(|n| part.pinned.and_then(|m| m.get(n)));
            let rotate = part.rotate.is_some_and(|s| rotated(s, r));
            // A file key names how it arrives (M4, §4.5): the exact bytes on a Native
            // target, the transform's one-line form (or the plain env value) elsewhere.
            let spec = fleet
                .products
                .get(&r.product)
                .and_then(|p| p.keys.get(&r.key));
            let native =
                channels.is_some_and(|ch| matches!(ch.files, FileCapability::Native { .. }));
            let (via, delivered_as, form, path) =
                if let Some(file) = spec.and_then(|s| s.file.as_deref()) {
                    let label = channels.and_then(|ch| {
                        let channel = match r.kind {
                            Kind::Config => &ch.config,
                            Kind::Secret => &ch.secret,
                        };
                        channel.label()
                    });
                    if native {
                        (
                            label,
                            Some("file"),
                            Some("verbatim".to_string()),
                            Some(file.to_string()),
                        )
                    } else {
                        (
                            label,
                            Some("env"),
                            spec.and_then(|s| s.rules.transform.clone()),
                            None,
                        )
                    }
                } else {
                    match channels {
                        Some(ch) => {
                            let channel = match r.kind {
                                Kind::Config => &ch.config,
                                Kind::Secret => &ch.secret,
                            };
                            match channel.label() {
                                Some(label) => (Some(label), Some("env"), None, None),
                                None => (None, None, None, None),
                            }
                        }
                        None => (None, None, None, None),
                    }
                };
            JsonRow {
                binding: bound.map(|b| b.binding),
                pending_deploy: bound.map(|b| b.pending_deploy),
                drift: bound.map(|b| b.drift),
                chain: bound.and_then(|b| b.chain.clone()),
                open_url: link.filter(|_| is_blocking(r)).map(str::to_string),
                target: Some(part.target.to_string()),
                rotate,
                via,
                delivered_as,
                form,
                path,
                ..JsonRow::new(r, target_name, json_target(r.kind, r.target), action)
            }
        })
        .collect()
}

/// Whether a sync would change the target (H8): `some` when a key is new or certainly
/// changed, a name would be pruned or a binding is pending; else `unknown` when keys whose
/// values the target hides (Fly) would be staged; else `none`.
fn changes(
    plan: &SyncPlan,
    rows: &[JsonRow],
    pinned: Option<&BTreeMap<String, PinnedRow>>,
) -> &'static str {
    let staged: Vec<&JsonRow> = rows
        .iter()
        .filter(|r| r.action == Some("would_stage"))
        .collect();
    let certain = staged.iter().any(|r| r.target_state != Some("present"))
        || !plan.prune.is_empty()
        || pinned.is_some_and(|m| m.values().any(|b| b.pending_deploy));
    if certain {
        "some"
    } else if staged.is_empty() {
        "none"
    } else {
        // Staged although "present": the target cannot compare values (Fly, P1).
        "unknown"
    }
}

#[derive(serde::Serialize)]
struct JsonDoc {
    schema_version: u32,
    environment: String,
    /// `--product`, or null for the whole environment.
    product: Option<String>,
    /// `none`, `some` or `unknown` (H8).
    changes: &'static str,
    rows: Vec<JsonRow>,
    extras: Vec<JsonName>,
    /// Keys declared for this environment that its target does not deliver (FR-48);
    /// absent when there are none.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    undelivered: Vec<JsonName>,
    /// Keys of a source-only product that no `from` points at (FR-47,
    /// `unreferenced-source`); absent when there are none.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    unreferenced_sources: Vec<JsonName>,
    /// Target names changed outside opv since its last recorded sync (FR-54); absent when
    /// none.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    drift: Vec<String>,
    /// What this run tidied in 1Password (FR-43), names only; absent when nothing was.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tidy: Vec<JsonTidy>,
    /// The error code of a tidy that did not complete (FR-43); absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    tidy_error: Option<&'static str>,
    stage: Vec<String>,
    held: Vec<JsonHeld>,
    prune: Vec<String>,
    totals: JsonTotals,
    /// `plan --json` only: the plan id `sync --expect-plan` checks (FR-41).
    #[serde(skip_serializing_if = "Option::is_none")]
    plan_id: Option<String>,
    /// `status --json` on a pinned target that opv stamped: the latest stamp (FR-42).
    #[serde(skip_serializing_if = "Option::is_none")]
    provenance: Option<JsonStamp>,
    /// The command to run next on success (`plan`: the sync); `null` otherwise.
    next: Option<String>,
}

#[derive(serde::Serialize)]
struct JsonStamp {
    opv_version: String,
    written: String,
    plan_id: String,
}

/// The one row shape of every names-only document: `status`, `plan` and `check` (A6).
#[derive(serde::Serialize)]
pub(crate) struct JsonRow {
    /// The name of the row's target (FR-56); null where no target is read (`check`).
    target: Option<String>,
    product: Option<String>,
    key: String,
    kind: &'static str,
    /// The key's kind channel (`secret` / `config`, design §6.7); always present.
    channel: &'static str,
    /// The channel's label (`Kubernetes Secret`, `GitHub variable`, `env`, …), when the
    /// channel delivers; left out otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    via: Option<&'static str>,
    /// How the value reaches the app (`env` / `file`); left out otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    delivered_as: Option<&'static str>,
    /// The file transform's name (`verbatim` for a file on a Native target, the declared
    /// transform's name when one applies); absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    form: Option<String>,
    /// The file's path on the target (M4); absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    state: &'static str,
    rule: Option<&'static str>,
    /// Why `rule` failed (FR-22): from the rule's fixed set or the configuration only.
    reason: Option<String>,
    target_name: Option<String>,
    /// The row's state on its target: `present`, `absent`, `would_change` or null.
    target_state: Option<&'static str>,
    action: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    binding: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pending_deploy: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    drift: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain: Option<String>,
    /// The 1Password item link to fix a blocking row in (H1); IDs only.
    #[serde(skip_serializing_if = "Option::is_none")]
    open_url: Option<String>,
    /// A shared key's source, `product/KEY` (FR-45).
    #[serde(skip_serializing_if = "Option::is_none")]
    shared_from: Option<String>,
    /// True when this `plan` was made with `--rotate` for this row's key (FR-16); absent
    /// otherwise, so a plan without rotation is unchanged.
    #[serde(skip_serializing_if = "is_false")]
    rotate: bool,
}

/// Serialize a `false` boolean field only when true (`rotate`).
fn is_false(b: &bool) -> bool {
    !*b
}

impl JsonRow {
    /// `r` with its name on the target, its presence there and the plan's action; no
    /// target named (`check`; [`json_rows`] sets it for `status` and `plan`).
    pub(crate) fn new(
        r: &Row,
        target_name: Option<String>,
        target_state: Option<&'static str>,
        action: Option<&'static str>,
    ) -> JsonRow {
        JsonRow {
            target: None,
            product: Some(String::from(&r.product)),
            key: r.key.clone(),
            kind: kind_label(r.kind),
            channel: kind_label(r.kind),
            via: None,
            delivered_as: None,
            form: None,
            path: None,
            state: json_state(&r.state),
            rule: json_rule(&r.state),
            reason: json_reason(&r.state),
            target_name,
            target_state,
            action,
            binding: None,
            pending_deploy: None,
            drift: None,
            chain: None,
            open_url: None,
            shared_from: json_source(r),
            rotate: false,
        }
    }
}

/// Whether `--rotate` names `r`'s key, or the key it shares its value from (FR-16, FR-45).
pub(crate) fn rotated(set: &BTreeSet<(String, String)>, r: &Row) -> bool {
    set.contains(&(r.product.clone(), r.key.clone()))
        || r.source
            .as_ref()
            .is_some_and(|(p, k)| set.contains(&(p.clone(), k.clone())))
}

/// The `shared_from` of a JSON row (FR-45).
pub(crate) fn json_source(r: &Row) -> Option<String> {
    r.source.as_ref().map(|(p, k)| key_label(p, k))
}

/// One desired row's binding on a pinned target (R5): `binding` is `current` (bound as
/// desired), `stale` (bound, but the next `--deploy` changes it) or `unbound`.
pub(crate) struct PinnedRow {
    pub binding: &'static str,
    pub pending_deploy: bool,
    pub drift: bool,
    /// How the bound name reaches the app when it passes through more than one object
    /// (FR-39), e.g. Key Vault → ExternalSecret → env. Names and version ids only.
    pub chain: Option<String>,
}

/// One tidy change: a stable action word and the field or section it is about.
#[derive(serde::Serialize)]
pub(crate) struct JsonTidy {
    action: &'static str,
    name: String,
}

/// The `tidy` array of a JSON document (FR-43).
pub(crate) fn json_tidy(changes: &[crate::domain::convention::Change]) -> Vec<JsonTidy> {
    changes
        .iter()
        .map(|c| JsonTidy {
            action: c.action(),
            name: c.subject().to_string(),
        })
        .collect()
}

#[derive(serde::Serialize)]
struct JsonName {
    product: Option<String>,
    key: String,
}

impl JsonName {
    fn new(product: &str, key: &str) -> JsonName {
        JsonName {
            product: Some(String::from(product)),
            key: key.to_string(),
        }
    }

    fn is(&self, product: &str, key: &str) -> bool {
        self.product.as_deref() == Some(product) && self.key == key
    }
}

#[derive(serde::Serialize)]
struct JsonHeld {
    target: String,
    product: Option<String>,
    key: String,
    target_name: Option<String>,
}

#[derive(serde::Serialize)]
struct JsonTotals {
    rows: usize,
    findings: usize,
    extras: usize,
    to_stage: usize,
    held: usize,
    to_prune: usize,
}

/// Machine-readable row state, spelled with underscores (FR-21).
fn json_state(s: &KeyState) -> &'static str {
    match s {
        KeyState::Missing => "missing",
        KeyState::WrongKind => "wrong_kind",
        KeyState::RuleFailed(..) => "failing_rule",
        KeyState::Ready => "saved",
        KeyState::Skipped => "skipped",
        KeyState::SourceBlocked => "source_blocked",
        KeyState::RulesPendingReview => "rules_pending_review",
    }
}

/// The name of the failing rule, next to the state (FR-22).
fn json_rule(s: &KeyState) -> Option<&'static str> {
    match s {
        KeyState::RuleFailed(rule, _) => Some(rule),
        _ => None,
    }
}

/// Why the rule failed, as a separate field next to `rule` (FR-22). Never the value.
fn json_reason(s: &KeyState) -> Option<String> {
    match s {
        KeyState::RuleFailed(_, reason) => Some(reason.to_string()),
        _ => None,
    }
}

/// Target presence: secrets are present/absent/would-change; config only where the target
/// delivers it itself (FR-46), otherwise none.
fn json_target(kind: Kind, target: TargetState) -> Option<&'static str> {
    match (kind, target) {
        (Kind::Config, TargetState::Unknown) => None,
        // Read and checked, never written to this target (FR-47, FR-48).
        (_, TargetState::NotDelivered) => Some("not_delivered"),
        (_, TargetState::Absent) => Some("absent"),
        (_, TargetState::WouldChange) => Some("would_change"),
        (_, _) => Some("present"),
    }
}

/// What a `plan` would do with this row: stage, prune or hold it.
fn row_action(
    r: &Row,
    target_name: Option<&str>,
    staged: &HashSet<&str>,
    pruned: &HashSet<&str>,
    held_keys: &HashSet<(&str, &str)>,
    held_from_prune: &HashSet<&str>,
) -> Option<&'static str> {
    if held_keys.contains(&(r.product.as_str(), r.key.as_str())) {
        return Some("held");
    }
    let name = target_name?;
    if staged.contains(name) {
        Some("would_stage")
    } else if pruned.contains(name) {
        Some("would_prune")
    } else if held_from_prune.contains(name) {
        Some("held")
    } else {
        None
    }
}

pub(crate) fn kind_label(k: Kind) -> &'static str {
    match k {
        Kind::Secret => "secret",
        Kind::Config => "config",
    }
}

/// The STATE cell: a failing rule reads `failed <rule> (<reason>)` (FR-22).
pub(crate) fn state_label(s: &KeyState) -> String {
    match s {
        KeyState::Missing => "missing".into(),
        KeyState::WrongKind => "wrong kind".into(),
        KeyState::RuleFailed(rule, reason) => format!("failed {rule} ({reason})"),
        KeyState::Ready => "saved".into(),
        KeyState::Skipped => "skipped".into(),
        KeyState::SourceBlocked => "blocked by source".into(),
        KeyState::RulesPendingReview => "rules pending review".into(),
    }
}

/// [`state_label`] with the full fix reason for a wrong kind (H4): which field type the
/// key is stored in, and which one its declared kind needs. Field-type metadata only,
/// never a value.
pub(crate) fn row_state_label(r: &Row) -> String {
    match (&r.state, r.kind) {
        (KeyState::WrongKind, Kind::Secret) => {
            "wrong kind (stored as text; declared secret: use a concealed field)".into()
        }
        (KeyState::WrongKind, Kind::Config) => {
            "wrong kind (stored as concealed; declared config: use a text field)".into()
        }
        (s, _) => state_label(s),
    }
}

/// The ON TARGET word of a row (H5), from one closed set on every provider and in both
/// `status` and `plan`: `new`, `same`, `changed`, `unknown`, `pending`, `held`, `extra`,
/// `drift` or `n/a`. `held` marks an immutable key kept as it is; `binding` is the row's
/// binding on a pinned target, when known. `opv help states` defines each word.
pub(crate) fn target_word(r: &Row, held: bool, binding: Option<&PinnedRow>) -> &'static str {
    match (r.kind, r.target, &r.state) {
        // Read and checked here, never written to this target (FR-47, FR-48).
        (_, TargetState::NotDelivered, _) => "n/a",
        // Config has a target state only where the target delivers it itself (FR-46).
        (Kind::Config, TargetState::Unknown, _) | (Kind::Config, _, KeyState::Skipped) => "n/a",
        (Kind::Config, TargetState::Absent, _) => "new",
        (Kind::Config, TargetState::WouldChange, _) => "changed",
        (Kind::Config, TargetState::Present, _) => "same",
        (Kind::Secret, TargetState::Absent, KeyState::Skipped) => "n/a",
        (Kind::Secret, _, KeyState::Skipped) => "extra",
        (Kind::Secret, TargetState::Absent, _) => "new",
        _ if held => "held",
        (Kind::Secret, TargetState::WouldChange, _) => "changed",
        _ if binding.is_some_and(|b| b.drift) => "drift",
        _ if binding.is_some_and(|b| b.pending_deploy) => "pending",
        (Kind::Secret, TargetState::Present, _) => "same",
        (Kind::Secret, TargetState::Unknown, _) => "unknown",
    }
}

/// The ON TARGET cell of `r`, naming its channel (design §1.3, FM-02): a config row reads
/// `<word>, via <label>` (or `via <label>` when the word is `n/a`), or
/// `not delivered (no config channel)` when the target's config channel delivers nothing.
/// A file key then names its form (M4, §4.5): `file (verbatim)` on a Native target, or
/// `env (<transform>)`/`env`. A secret row otherwise keeps its word.
pub(crate) fn target_cell(
    r: &Row,
    word: &str,
    channels: &Channels,
    spec: Option<&KeySpec>,
) -> String {
    let word = if r.kind != Kind::Config {
        word.to_string()
    } else {
        match channels.config.label() {
            Some(label) if word == "n/a" => format!("via {label}"),
            Some(label) => format!("{word}, via {label}"),
            None => "not delivered (no config channel)".to_string(),
        }
    };
    let Some(_) = spec.and_then(|s| s.file.as_deref()) else {
        return word;
    };
    let form = match channels.files {
        FileCapability::Native { .. } => "file (verbatim)".to_string(),
        _ => match spec.and_then(|s| s.rules.transform.as_deref()) {
            Some(t) => format!("env ({t})"),
            None => "env".to_string(),
        },
    };
    format!("{word} · {form}")
}

/// File-key destination lines for one target (design §1.3, M4): a `warning` for a target
/// that does not honour file destinations, a `note` for one where the app writes the
/// files from the environment. One per file key of the plan, in row order.
pub(crate) fn file_destination_lines(
    fleet: &Fleet,
    env_name: &str,
    target: &str,
    channels: &Channels,
    plan: &SyncPlan,
) -> Vec<String> {
    plan.rows
        .iter()
        .filter(|r| {
            fleet
                .products
                .get(&r.product)
                .and_then(|p| p.keys.get(&r.key))
                .is_some_and(|s| s.file.is_some())
        })
        .map(|r| match channels.files {
            FileCapability::Native { .. } => String::new(),
            FileCapability::ViaApp { note } => format!(
                "{}: note: {} file via the app ({})",
                placement(env_name, target),
                key_label(&r.product, &r.key),
                note
            ),
            FileCapability::None => format!(
                "{}: warning: {} file destination not honoured on {}",
                placement(env_name, target),
                key_label(&r.product, &r.key),
                target
            ),
        })
        .filter(|l| !l.is_empty())
        .collect()
}

/// The source and target words and what each means, one line per word (`opv help states`,
/// H5). The JSON `state` and `target_state` fields keep their own stable spellings.
pub const STATES_HELP: &str = "\
SOURCE: the key in 1Password
  saved       stored and passes every rule. Either field type is accepted: a config key
              stored concealed is delivered as a plain value, opv never prints its value,
              and status warns about it once
  missing     no field with this name in the item's section
  failed      fails a rule; the rule and the reason follow, e.g. failed prefix (expected sk-)
  skipped     not required in this environment (its rules leave it out)
  blocked by source
              shares another key's value (shared from <product>/<KEY>) and that key has a
              finding; fixed with it, not counted again

ON TARGET: the key on its deployment target (the TARGET column names the target)
  new         not on the target yet; the next sync writes it
  same        on the target with the same value; nothing to write
  changed     on the target with another value; the next sync writes it
  unknown     on the target, but the target does not reveal values, so opv cannot compare;
              sync writes it again (a staging target stages it and compares digests)
  pending     written, not yet live; the next sync --deploy rolls it out
  held        immutable and already set; kept as it is (replace with --rotate)
  rotate      an immutable key this plan replaces because --rotate named it
  extra       on the target but not wanted in this environment; not pruned without --prune
  drift       the running app is bound to something other than what opv last wrote
  n/a         not delivered to the target (skipped keys not on the target); a config row
              never reads plain n/a: it names its channel (`via env`, `via GitHub
              variable`) or reads `not delivered (no config channel)`

Missing and failed are findings: status, plan and check exit 8 and print an
open: link to the item in 1Password (opv open <[product/]KEY> --env <env>).";

pub(crate) fn is_blocking(r: &Row) -> bool {
    matches!(
        r.state,
        KeyState::Missing | KeyState::WrongKind | KeyState::RuleFailed(..)
    )
}

/// A shared key's provenance (FR-45), for a row's own line: ` (shared from api/KEY)` on a
/// key that shares another's value, ` (affects worker/KEY, ...)` on a source with a
/// finding, so the finding is reported once with every key it holds up. Names only.
pub(crate) fn shared_note(r: &Row) -> String {
    match shared_text(r) {
        Some(t) => format!(" ({t})"),
        None => String::new(),
    }
}

/// [`shared_note`] without the parentheses: `shared from api/KEY` or `affects worker/KEY`.
pub(crate) fn shared_text(r: &Row) -> Option<String> {
    if let Some((p, k)) = &r.source {
        return Some(format!("shared from {}", key_label(p, k)));
    }
    if is_blocking(r) && !r.shared_by.is_empty() {
        let keys: Vec<String> = r.shared_by.iter().map(|(p, k)| key_label(p, k)).collect();
        return Some(format!("affects {}", keys.join(", ")));
    }
    None
}

/// Missing keys, and keys whose value fails a rule (including an empty skeleton field
/// nobody filled in), get their declared guidance printed under the row (FR-17, spec §7.4;
/// FR-26: the reason, in the STATE column, plus the key's guidance).
fn wants_guidance(r: &Row) -> bool {
    matches!(r.state, KeyState::Missing | KeyState::RuleFailed(..)) && !r.guidance.is_empty()
}

/// Print `rows`, each with the name of its target, as a table `TARGET PRODUCT KEY KIND
/// STATE ON TARGET` (FR-56), problems first (H4): the blocking rows (missing, wrong kind,
/// failed), then the rest, each group in the given order (targets in name order, keys in
/// declared order). Under each missing or failing row its guidance; the way to the field
/// is the findings' `Next: opv open …` (H1). `word` renders the last column, the row's
/// state on its target. Rows hold names only.
pub(crate) fn print_rows(
    out: &mut dyn Write,
    rows: &[(&str, &Row)],
    word: impl Fn(&str, &Row) -> String,
) -> Result<(), Error> {
    let header: Vec<String> = ["TARGET", "PRODUCT", "KEY", "KIND", "STATE", "ON TARGET"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let ordered = problems_first(rows, |(_, r)| r);
    let cells: Vec<Vec<String>> = ordered
        .iter()
        .map(|(t, r)| {
            [
                t.to_string(),
                r.product.clone(),
                r.key.clone(),
                kind_label(r.kind).to_string(),
                row_state_label(r),
                word(t, r),
            ]
            .into_iter()
            .collect()
        })
        .collect();
    let last = header.len() - 1;
    let mut w = vec![0usize; last];
    for c in std::iter::once(&header).chain(&cells) {
        for (i, wi) in w.iter_mut().enumerate() {
            *wi = (*wi).max(c[i].len());
        }
    }
    let line = |c: &[String]| {
        let mut s = String::new();
        for (i, wi) in w.iter().enumerate() {
            s.push_str(&format!("{:<wi$}  ", c[i]));
        }
        s.push_str(&c[last]);
        s.trim_end().to_string()
    };
    writeln!(out, "{}", line(&header)).map_err(write_err)?;
    for ((_, r), c) in ordered.iter().zip(&cells) {
        writeln!(out, "{}", line(c)).map_err(write_err)?;
        if let Some(t) = shared_text(r) {
            writeln!(out, "    {t}").map_err(write_err)?;
        }
        if wants_guidance(r) {
            writeln!(out, "    guidance: {}", r.guidance).map_err(write_err)?;
        }
        // The item link is left to `Next: opv open …` (found live: it read like a secret).
    }
    Ok(())
}

/// The blocking rows (and keys blocked by their source) first, then the others, each in
/// their original order (H4, FR-45). `row` gives each entry's row.
pub(crate) fn problems_first<T>(rows: &[T], row: impl Fn(&T) -> &Row) -> Vec<&T> {
    // A key blocked by its source (FR-45) is a problem too, fixed at the source.
    let (mut bad, good): (Vec<&T>, Vec<&T>) = rows.iter().partition(|e| {
        let r = row(e);
        is_blocking(r) || r.state == KeyState::SourceBlocked
    });
    bad.extend(good);
    bad
}

/// The 1Password private link to the boundary item holding `product`'s values in
/// `env_name` (H1, FR-57), with the signed-in account from one free `op whoami` probe when
/// it answers. IDs only, never a value.
pub(crate) fn item_url(
    fleet: &Fleet,
    env_name: &str,
    product: &str,
    r: &dyn CommandRunner,
) -> Result<String, Error> {
    let b = fleet.boundary(env_name, product)?;
    let account = onepassword::account(r);
    Ok(onepassword::item_link(
        account.as_ref(),
        &b.vault_id,
        &b.item_id,
    ))
}

/// [`item_url`] of the first blocking row's product (else the first row's), for the plan
/// and status link (H1); `None` when there are no rows.
pub(crate) fn rows_item_url(
    fleet: &Fleet,
    env_name: &str,
    rows: &[Row],
    r: &dyn CommandRunner,
) -> Result<Option<String>, Error> {
    let Some(row) = rows.iter().find(|r| is_blocking(r)).or(rows.first()) else {
        return Ok(None);
    };
    item_url(fleet, env_name, &row.product, r).map(Some)
}

/// The findings error of `status`, `plan` and `check` (C4, 09.11, 09.18, 09.22): the
/// blocking keys of `rows` as the catalog's `ValuesNeeded` (exit 8), whose step opens the
/// first of them with the invocation's `--config` kept. Callers pass rows with at least one
/// blocking key.
pub(crate) fn findings_error(rows: &[Row], env_name: &str) -> Error {
    crate::cause::Cause::ValuesNeeded {
        env: crate::cause::EnvName::new(env_name),
        rows: rows
            .iter()
            .filter(|r| is_blocking(r))
            .map(value_row)
            .collect(),
    }
    .into()
}

/// One blocking row as the catalog names it: product, key and what is wrong, never a value.
pub(crate) fn value_row(row: &Row) -> crate::cause::ValueRow {
    use crate::cause::{KeyName, ProductName, ValueRow, ValueState};
    let state = match &row.state {
        KeyState::RuleFailed(rule, _) if *rule == variables::CONCEALED_RULE => {
            ValueState::ConcealedConfig
        }
        KeyState::RuleFailed(rule, why) => ValueState::RuleFailed {
            rule,
            reason: Some(why.to_string()),
        },
        KeyState::WrongKind if row.kind == Kind::Secret => ValueState::StoredAsText,
        KeyState::WrongKind => ValueState::ConcealedConfig,
        _ => ValueState::Missing,
    };
    ValueRow {
        product: ProductName::new(&row.product),
        key: KeyName::new(&row.key),
        target: None,
        state,
    }
}

/// One line under a status or plan table explaining `unknown` when a row shows it (H5).
pub(crate) fn print_legend(
    out: &mut dyn Write,
    words: &[&str],
    target_label: &str,
    live: bool,
) -> Result<(), Error> {
    if words.contains(&"unknown") {
        // A target whose writes are live (FR-46) is simply written again; a staging one
        // stages and compares digests.
        let then = if live {
            "every sync writes them again"
        } else {
            "sync stages them and compares digests"
        };
        writeln!(
            out,
            "unknown: {target_label} does not reveal stored values, so opv cannot compare them; \
             {then} (opv help states)"
        )
        .map_err(write_err)?;
    }
    Ok(())
}

/// Whether `ports`' writes are live at once (FR-46), for the wording of `unknown`.
pub(crate) fn live_writes(ports: &Ports<'_>) -> bool {
    matches!(ports, Ports::Staged { runtime, .. } if runtime.live())
}

/// Print each undeclared item field as a warning; extras are never staged or pruned.
pub(crate) fn print_extras(out: &mut dyn Write, plan: &SyncPlan) -> Result<(), Error> {
    for (section, label) in &plan.extras {
        writeln!(
            out,
            "warning: extra field {} is in the 1Password item but not declared",
            key_label(section, label)
        )
        .map_err(write_err)?;
    }
    let labels = |pairs: &[(String, String)]| -> String {
        pairs
            .iter()
            .map(|(p, k)| key_label(p, k))
            .collect::<Vec<_>>()
            .join(", ")
    };
    if !plan.undelivered.is_empty() {
        writeln!(
            out,
            "not delivered here: {} (the target's products list leaves their product out; \
             add it there to deliver them)",
            labels(&plan.undelivered)
        )
        .map_err(write_err)?;
    }
    if !plan.drift.is_empty() {
        writeln!(
            out,
            "changed outside opv since its last sync: {} (set on the target by another tool \
             or a person; the next sync writes 1Password's values back)",
            plan.drift.join(", ")
        )
        .map_err(write_err)?;
    }
    if !plan.unreferenced_sources.is_empty() {
        writeln!(
            out,
            "warning: unreferenced shared value {}: no key points at it with from; point a \
             key at it or remove it",
            labels(&plan.unreferenced_sources)
        )
        .map_err(write_err)?;
    }
    Ok(())
}

/// `product/KEY` pairs as JSON names.
fn json_names(pairs: &[(String, String)]) -> Vec<JsonName> {
    pairs
        .iter()
        .map(|(product, key)| JsonName {
            product: Some(String::from(product)),
            key: key.clone(),
        })
        .collect()
}

/// FR-47: a source-only product named on its own in `env`. It holds canonical values for
/// other products' keys and is never run, checked or planned on its own; the cause's step
/// names a product that reads it, when one does.
pub(crate) fn source_only(fleet: &Fleet, product: &str, env: Option<&str>) -> Error {
    crate::cause::Cause::SourceOnly {
        product: crate::cause::ProductName::new(product),
        env: env.map(crate::cause::EnvName::new),
        reader: fleet
            .referencing_product(product)
            .map(crate::cause::ProductName::new),
    }
    .into()
}

/// `--product` on `status`, `plan` and `sync` (NR-16, P12, P20): refused for an undeclared
/// product, before any call.
/// `--product` (or `OPV_PRODUCT`) of `opv <verb> [<env>]`: an undeclared one ends with the
/// same read-only command on the closest declared product (I4).
pub(crate) fn check_product(
    fleet: &Fleet,
    product: Option<&str>,
    env: Option<&str>,
) -> Result<(), Error> {
    let Some(p) = product else { return Ok(()) };
    if !fleet.products.contains_key(p) {
        // The cause's own step: the same command with a unique close product, else a
        // listing; never the first product (X2).
        return Err(undefined_product(fleet, p, env));
    }
    if fleet.products[p].source_only {
        return Err(source_only(fleet, p, env));
    }
    Ok(())
}

/// D10/FR-34: the product a command acts on in `env`. `given` (a `--product` value, or
/// the product part of `open`'s target) is validated when present. Without it, exactly one
/// product that is not source-only and has a key desired in `env` is used; otherwise
/// [`product_choice`]'s cause.
pub(crate) fn pick_product(fleet: &Fleet, env: &str, given: Option<&str>) -> Result<String, Error> {
    if let Some(p) = given {
        check_product(fleet, Some(p), Some(env))?;
        return Ok(p.to_string());
    }
    let env_def = fleet.environment(env)?;
    // FR-47: a source-only product holds shared values for other products' keys and is
    // never run on its own, so it never qualifies. FR-15: a key refused here is not desired.
    let mut candidates: Vec<&str> = Vec::new();
    for (name, product) in &fleet.products {
        if !product.source_only
            && product.keys.values().any(|spec| {
                crate::domain::rules::applies(spec, env, env_def, name)
                    && !crate::domain::rules::refused_in(spec, env)
            })
        {
            candidates.push(name.as_str());
        }
    }
    product_choice(env, &candidates)
}

/// The product of a command that names none (R23, R24): the one candidate, `ChoiceRequired`
/// listing several (a person picks; never the first, X2), or `NothingInScope` when no
/// product has keys desired in `env`: choosing a product cannot help then, declaring a key
/// does (07.23).
pub(crate) fn product_choice(env: &str, candidates: &[&str]) -> Result<String, Error> {
    use crate::cause::{Cause, EnvName, Scope};
    match candidates {
        [only] => Ok((*only).to_string()),
        [] => Err(Cause::NothingInScope {
            env: EnvName::new(env),
            what: Scope::NoProductHasKeys,
        }
        .into()),
        many => Err(Cause::ChoiceRequired {
            flag: "--product".into(),
            candidates: many.iter().map(|p| (*p).to_string()).collect(),
        }
        .into()),
    }
}

/// `given`, a `kind` name the configuration does not declare (R21): the declared names, and
/// a unique close one when there is exactly one (`Closest::unique`), which the cause's Next
/// substitutes into the command as typed; with none, Next is a listing (X2: never a guess).
pub(crate) fn not_declared<'a>(
    kind: crate::cause::NameKind,
    given: &str,
    declared: impl IntoIterator<Item = &'a str>,
) -> Error {
    let candidates: Vec<String> = declared.into_iter().map(str::to_string).collect();
    let close = suggest::close(given, candidates.iter().map(String::as_str));
    crate::cause::Cause::NotDeclared {
        kind,
        given: given.to_string(),
        closest: crate::cause::Closest::unique(&close),
        candidates,
    }
    .into()
}

/// The environment `name` of the configuration, or `NotDeclared` (R21). Its Next is the
/// command as typed with a unique close name substituted, never another command (07.32).
pub(crate) fn environment<'f>(fleet: &'f Fleet, name: &str) -> Result<&'f Environment, Error> {
    fleet.environments.get(name).ok_or_else(|| {
        not_declared(
            crate::cause::NameKind::Environment,
            name,
            fleet.environments.keys().map(String::as_str),
        )
    })
}

/// An undeclared `--product` (R21): the declared products, and the same command with a
/// unique close product as the Next (else a listing). `env` is kept for the callers that
/// name the command's environment; the step comes from the invocation.
pub(crate) fn undefined_product(fleet: &Fleet, p: &str, _env: Option<&str>) -> Error {
    not_declared(
        crate::cause::NameKind::Product,
        p,
        fleet.products.keys().map(String::as_str),
    )
}

/// The target names `product`'s declared keys render on target `target_name` of `env_name`
/// (its share of the managed set, FR-8).
pub(crate) fn product_names(
    fleet: &Fleet,
    env_name: &str,
    target_name: &str,
    product: &str,
) -> Result<HashSet<String>, Error> {
    let (_, t) = target(fleet, env_name, target_name)?;
    if !fleet.delivers(env_name, target_name, product) {
        return Ok(HashSet::new());
    }
    Ok(fleet
        .products
        .get(product)
        .map(|p| p.keys.keys().map(|k| t.env_name(product, k)).collect())
        .unwrap_or_default())
}

/// `plan` limited to one product: its rows, extras, writes, prunes and held keys only, so
/// other products can neither block nor be touched (NR-16, P12, P20). `names` is the
/// product's share of the managed set ([`product_names`]).
///
/// The rows of the sources its shared keys read (FR-45) stay too: a source's finding blocks
/// the product's keys, and is reported on the source's row only. Their names are not the
/// product's, so they are neither written nor pruned.
pub(crate) fn scope_plan(plan: &mut SyncPlan, product: &str, names: &HashSet<String>) {
    let sources: HashSet<(String, String)> = plan
        .rows
        .iter()
        .filter(|r| r.product == product)
        .filter_map(|r| r.source.clone())
        .collect();
    plan.rows
        .retain(|r| r.product == product || sources.contains(&(r.product.clone(), r.key.clone())));
    plan.extras.retain(|(section, _)| section == product);
    plan.stage.retain(|(n, _)| names.contains(n));
    plan.held_immutable.retain(|(p, _)| p == product);
    plan.prune.retain(|n| names.contains(n));
    plan.held_from_prune.retain(|(p, _, _)| p == product);
    plan.config.retain(|p, _| p == product);
    plan.no_channel.retain(|k| k.product == product);
    plan.concealed_config.retain(|(p, _)| p == product);
}

/// Target name → `product/KEY` of every declared key, so output names a key the way the
/// configuration does, with the target's name second: `product/KEY (TARGET_NAME)` (P19).
pub(crate) struct KeyNames {
    /// The target's name (FR-56).
    target: String,
    labels: BTreeMap<String, String>,
}

impl KeyNames {
    pub(crate) fn new(fleet: &Fleet, env_name: &str, target_name: &str) -> Result<KeyNames, Error> {
        let (_, t) = target(fleet, env_name, target_name)?;
        Ok(KeyNames {
            target: target_name.to_string(),
            labels: fleet
                .products
                .iter()
                .filter(|(p, _)| fleet.delivers(env_name, target_name, p))
                .flat_map(|(p, prod)| {
                    prod.keys
                        .keys()
                        .map(move |k| (t.env_name(p, k), key_label(p, k)))
                })
                .collect(),
        })
    }

    /// `product/KEY` of env name `name`; `None` when it is no declared key's.
    pub(crate) fn key(&self, name: &str) -> Option<&str> {
        self.labels.get(name).map(String::as_str)
    }

    /// `product/KEY (NAME)`; the bare name when it is no declared key's.
    pub(crate) fn label(&self, name: &str) -> String {
        match self.labels.get(name) {
            Some(key) if key != name => format!("{key} ({name})"),
            _ => name.to_string(),
        }
    }

    /// `{target, product, key, target_name}` for a name on the target (A6, FR-56);
    /// `product` and `key` are null for a name no declared key renders.
    pub(crate) fn json_ref(&self, name: &str) -> serde_json::Value {
        let (product, key) = match self.labels.get(name).map(|l| (l, l.split_once('/'))) {
            Some((_, Some((p, k)))) => (Some(p), Some(k)),
            Some((l, None)) => (None, Some(l.as_str())),
            None => (None, None),
        };
        serde_json::json!({
            "target": self.target,
            "product": product,
            "key": key,
            "target_name": name,
        })
    }

    /// [`KeyNames::json_ref`] of each name.
    pub(crate) fn json_refs<S: AsRef<str>>(
        &self,
        names: impl IntoIterator<Item = S>,
    ) -> Vec<serde_json::Value> {
        names
            .into_iter()
            .map(|n| self.json_ref(n.as_ref()))
            .collect()
    }

    /// [`KeyNames::label`] of each name, comma-separated.
    pub(crate) fn join<S: AsRef<str>>(&self, names: impl IntoIterator<Item = S>) -> String {
        names
            .into_iter()
            .map(|n| self.label(n.as_ref()))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// `N key` / `N keys`.
pub(crate) fn plural(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        format!("{n} {one}")
    } else {
        format!("{n} {many}")
    }
}

/// The one-line count summary `status` prints first for each target, and `status` without
/// an environment prints per target of each environment (NR-16, P22, FR-56): `prod/web: 4
/// keys · 3 saved · 1 skipped · 0 findings · 1 not yet on Fly`. Names and counts only.
pub(crate) fn count_line(env_name: &str, target: &str, rows: &[Row], target_label: &str) -> String {
    let saved = rows.iter().filter(|r| r.state == KeyState::Ready);
    let absent = saved
        .clone()
        .filter(|r| r.kind == Kind::Secret && r.target == TargetState::Absent)
        .count();
    let skipped = rows.iter().filter(|r| r.state == KeyState::Skipped).count();
    let findings = rows.iter().filter(|r| is_blocking(r)).count();
    format!(
        "{}: {} · {} saved · {skipped} skipped · {} · {absent} not yet on {target_label}",
        placement(env_name, target),
        plural(rows.len(), "key", "keys"),
        saved.count(),
        plural(findings, "finding", "findings"),
    )
}

/// The targets a run of `verb` covers in `env` (FR-56): every target of the environment,
/// or only those `--target` names (repeatable), in name order without repeats. An unknown
/// name is `NotDeclared` listing the environment's targets; an environment without a
/// target is [`no_target`]'s error.
pub(crate) fn resolve_targets(
    fleet: &Fleet,
    env: &str,
    requested: &[String],
    _verb: &str,
) -> Result<Vec<String>, Error> {
    let e = fleet.environment(env)?;
    if e.targets.is_empty() {
        return Err(no_target(fleet, env));
    }
    let names: Vec<&str> = e.targets.keys().map(String::as_str).collect();
    if let Some(unknown) = requested.iter().find(|n| !e.targets.contains_key(*n)) {
        return Err(unknown_target(e, unknown));
    }
    Ok(names
        .into_iter()
        .filter(|n| requested.is_empty() || requested.iter().any(|r| r == n))
        .map(str::to_string)
        .collect())
}

/// The runner for each of `names`, the targets of one run (FR-40, FR-56). A run over one
/// target uses `r`, which the CLI signed in with that target's deploy credentials; a run
/// over several signs in here, once per target, so each target's calls carry its own
/// deploy identity and never another's. `None`: use `r`.
pub(crate) fn target_runners<'a>(
    fleet: &Fleet,
    env: &str,
    names: &[String],
    r: &'a dyn CommandRunner,
) -> Result<Vec<Option<signin::EnvRunner<'a>>>, Error> {
    if names.len() < 2 {
        return Ok(names.iter().map(|_| None).collect());
    }
    names
        .iter()
        .map(|n| signin::open_targeted(fleet, env, Some(n), r, signin::Reach::Target).map(Some))
        .collect()
}

/// `w` with every line it writes prefixed by `prefix`: the detail lines of one target in a
/// run over several (`prod/web: would stage: …`, FR-56).
pub(crate) struct Prefixed<'w> {
    inner: &'w mut dyn Write,
    prefix: String,
    at_start: bool,
}

impl<'w> Prefixed<'w> {
    pub(crate) fn new(inner: &'w mut dyn Write, prefix: String) -> Self {
        Prefixed {
            inner,
            prefix,
            at_start: true,
        }
    }
}

impl Write for Prefixed<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        for line in buf.split_inclusive(|b| *b == b'\n') {
            if self.at_start {
                self.inner.write_all(self.prefix.as_bytes())?;
            }
            self.inner.write_all(line)?;
            self.at_start = line.ends_with(b"\n");
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// `<env>/<target>`: how output names one target of a run (FR-56).
pub(crate) fn placement(env: &str, target: &str) -> String {
    format!("{env}/{target}")
}

/// The environment and its target `name` (FR-56); `NotDeclared` when the environment is
/// undefined or has no target of that name, and [`no_target`]'s cause when it has none
/// (status, plan and sync need one).
pub(crate) fn target<'f>(
    fleet: &'f Fleet,
    env: &str,
    name: &str,
) -> Result<(&'f Environment, &'f dyn TargetConfig), Error> {
    let e = fleet.environment(env)?;
    if e.targets.is_empty() {
        return Err(no_target(fleet, env));
    }
    match e.targets.get(name) {
        Some(t) => Ok((e, t.config.as_ref())),
        None => Err(unknown_target(e, name)),
    }
}

/// A `--target` the environment does not declare (R21): its targets, and the same command
/// with a unique close target substituted, else the target listing (X2: never the first).
fn unknown_target(e: &Environment, name: &str) -> Error {
    not_declared(
        crate::cause::NameKind::Target,
        name,
        e.targets.keys().map(String::as_str),
    )
}

/// The error for an environment without a target (run-only, FR-56; R25): it names the
/// products that would need one, and the step to add one is the cause's, once (07.33).
pub(crate) fn no_target(fleet: &Fleet, env: &str) -> Error {
    crate::cause::Cause::NothingInScope {
        env: crate::cause::EnvName::new(env),
        what: crate::cause::Scope::NoTargets {
            products: fleet
                .products
                .iter()
                .filter(|(_, p)| !p.source_only)
                .map(|(name, _)| crate::cause::ProductName::new(name.as_str()))
                .collect(),
        },
    }
    .into()
}

/// Resolve target `name` of the environment and open its ports, before any call.
/// Mutating commands run [`preflight`] before their first write.
pub(crate) fn open_target<'a>(
    fleet: &'a Fleet,
    env_name: &'a str,
    name: &str,
    r: &'a dyn CommandRunner,
) -> Result<(&'a dyn TargetConfig, Ports<'a>), Error> {
    let (_, t) = target(fleet, env_name, name)?;
    let managed = managed_names(fleet, env_name, name)?.into_iter().collect();
    let files = file_mounts(fleet, env_name, name)?;
    let config = config_names(fleet, env_name, name)?;
    Ok((t, t.open(env_name, managed, &files, &config, r)?))
}

/// The env names target `name` renders for config keys of the products it delivers: the
/// subset of its managed set that is config, never secret (FR-14, design §6.2).
pub(crate) fn config_names(
    fleet: &Fleet,
    env_name: &str,
    name: &str,
) -> Result<BTreeSet<String>, Error> {
    let (_, t) = target(fleet, env_name, name)?;
    Ok(fleet
        .products
        .iter()
        .filter(|(p, _)| fleet.delivers(env_name, name, p))
        .flat_map(|(p, prod)| {
            prod.keys
                .iter()
                .filter(|(_, s)| s.kind == Kind::Config)
                .map(move |(k, _)| t.env_name(p, k))
        })
        .collect())
}

/// Every name target `name` renders for a declared key of a product it delivers: its
/// managed set (FR-8, §10).
pub(crate) fn managed_names(
    fleet: &Fleet,
    env_name: &str,
    name: &str,
) -> Result<HashSet<String>, Error> {
    let (_, t) = target(fleet, env_name, name)?;
    Ok(fleet
        .products
        .iter()
        .filter(|(p, _)| fleet.delivers(env_name, name, p))
        .flat_map(|(p, prod)| prod.keys.keys().map(move |k| t.env_name(p, k)))
        .collect())
}

/// Every file key target `name` of `env_name` delivers, by rendered name (M4, §4.2): the
/// [`FileMount`](crate::domain::runtime::FileMount) of each key with a `file`, respecting
/// the target's roles and the key's environment and mode exactly as a delivery does.
/// Names only.
pub(crate) fn file_mounts(
    fleet: &Fleet,
    env_name: &str,
    name: &str,
) -> Result<BTreeMap<String, crate::domain::runtime::FileMount>, Error> {
    let (_, t) = target(fleet, env_name, name)?;
    let env = fleet.environment(env_name)?;
    let served = env.targets.get(name).and_then(|t| t.roles.as_deref());
    let mut out = BTreeMap::new();
    for (p, prod) in &fleet.products {
        if !fleet.delivers(env_name, name, p) {
            continue;
        }
        for (k, s) in &prod.keys {
            let Some(path) = s.file.as_deref() else {
                continue;
            };
            if !crate::domain::rules::applies(s, env_name, env, p) {
                continue;
            }
            if let (Some(roles), Some(served)) = (&s.roles, served)
                && !roles.iter().any(|r| served.contains(r))
            {
                continue;
            }
            out.insert(
                t.env_name(p, k),
                crate::domain::runtime::FileMount {
                    product: p.clone(),
                    path: path.to_string(),
                },
            );
        }
    }
    Ok(out)
}

/// Names on the target that the template does not render for any declared key: other
/// tools' secrets, which opv never touches (FR-5 "unmanaged on <target>", §10.3).
pub(crate) fn unmanaged_on_target<'a>(
    fleet: &Fleet,
    env_name: &str,
    name: &str,
    on_target: &'a [StoreEntry],
) -> Result<Vec<&'a str>, Error> {
    let managed = managed_names(fleet, env_name, name)?;
    Ok(on_target
        .iter()
        .map(|s| s.name.as_str())
        .filter(|n| !managed.contains(*n))
        .collect())
}

/// FR-12, §8 item 27: use cases reach a target only through the ports. `init` writes a
/// provider section by design (FR-37), so it may name an adapter.
#[cfg(test)]
#[test]
fn use_cases_name_no_target_adapter() {
    let mut hits = Vec::new();
    for dir in ["src/app", "src/domain"] {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            let exempt = ["init.rs", "characterization_tests.rs"];
            if exempt.iter().any(|x| p.ends_with(x)) {
                continue;
            }
            let s = production_code(&std::fs::read_to_string(&p).unwrap());
            // Built at runtime so this test does not match itself.
            let needles = [["fly", "::"].concat(), ["adapters::", "fly"].concat()];
            if needles.iter().any(|n| s.contains(n.as_str())) {
                hits.push(p);
            }
        }
    }
    assert!(hits.is_empty(), "a target adapter named in core: {hits:?}");
}

/// The production code of a source file: comments dropped, and every item gated by
/// `#[cfg(test)]` (a function, a `mod x { … }` block, a `mod x;` declaration, a
/// `thread_local!`) removed; the code after it is kept and checked (FR-37). A file whose
/// inner attribute is `#![cfg(test)]` has none. String literals are kept, so a provider
/// named in one is found; braces inside them, in char literals or in comments never count.
#[cfg(test)]
fn production_code(src: &str) -> String {
    let code = Lexed::new(src);
    if code.text.trim_start().starts_with("#![cfg(test)]") {
        return String::new();
    }
    let (text, real) = (&code.text, &code.real);
    let gate = "#[cfg(test)]";
    let mut out = String::new();
    let mut i = 0;
    while i < text.len() {
        if real[i] && text[i..].starts_with(gate) {
            i = skip_item(text, real, i + gate.len());
            continue;
        }
        let ch = text[i..].chars().next().unwrap_or(' ');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Source with comments replaced by spaces; `real[i]` is false inside string and char
/// literals, so only real code opens or closes a block.
#[cfg(test)]
struct Lexed {
    text: String,
    real: Vec<bool>,
}

#[cfg(test)]
impl Lexed {
    fn new(src: &str) -> Self {
        let b = src.as_bytes();
        let mut text = Vec::with_capacity(b.len());
        let mut real = Vec::with_capacity(b.len());
        let push = |text: &mut Vec<u8>, real: &mut Vec<bool>, c: u8, r: bool| {
            text.push(c);
            real.push(r);
        };
        let mut i = 0;
        while i < b.len() {
            let ident_before = i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
            if b[i..].starts_with(b"//") {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            } else if b[i..].starts_with(b"/*") {
                let end = src[i + 2..].find("*/").map_or(b.len(), |e| i + 2 + e + 2);
                (i..end).for_each(|_| push(&mut text, &mut real, b' ', true));
                i = end;
            } else if !ident_before && (b[i] == b'r' || b[i..].starts_with(b"br")) && {
                let s = i + if b[i] == b'b' { 2 } else { 1 };
                let hashes = b[s..].iter().take_while(|c| **c == b'#').count();
                b.get(s + hashes) == Some(&b'"')
            } {
                let s = i + if b[i] == b'b' { 2 } else { 1 };
                let hashes = b[s..].iter().take_while(|c| **c == b'#').count();
                let close = format!("\"{}", "#".repeat(hashes));
                let body = s + hashes + 1;
                let end = src[body..]
                    .find(&close)
                    .map_or(b.len(), |e| body + e + close.len());
                (i..end).for_each(|j| push(&mut text, &mut real, b[j], false));
                i = end;
            } else if b[i] == b'"' {
                let mut j = i + 1;
                while j < b.len() && b[j] != b'"' {
                    j += if b[j] == b'\\' { 2 } else { 1 };
                }
                let end = (j + 1).min(b.len());
                (i..end).for_each(|k| push(&mut text, &mut real, b[k], false));
                i = end;
            } else if b[i] == b'\''
                && (b.get(i + 1) == Some(&b'\\') || b.get(i + 2) == Some(&b'\''))
            {
                let mut j = i + 1;
                if b[j] == b'\\' {
                    j += 2;
                }
                while j < b.len() && b[j] != b'\'' {
                    j += 1;
                }
                let end = (j + 1).min(b.len());
                (i..end).for_each(|k| push(&mut text, &mut real, b[k], false));
                i = end;
            } else {
                push(&mut text, &mut real, b[i], true);
                i += 1;
            }
        }
        Self {
            text: String::from_utf8_lossy(&text).into_owned(),
            real,
        }
    }
}

/// The index just past the item that starts after `from` (further attributes included):
/// at its `;` outside any bracket, or at the `}` that closes its first block.
#[cfg(test)]
fn skip_item(text: &str, real: &[bool], from: usize) -> usize {
    let b = text.as_bytes();
    let mut depth = 0usize;
    let mut i = from;
    while i < b.len() {
        if !real[i] {
            i += 1;
            continue;
        }
        match b[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' => depth = depth.saturating_sub(1),
            b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return i + 1;
                }
            }
            b';' if depth == 0 => return i + 1,
            _ => {}
        }
        i += 1;
    }
    b.len()
}

/// The first provider word in the production code of `src` (FR-37, FR-39), if any.
#[cfg(test)]
fn provider_named(src: &str) -> Option<String> {
    let words = [
        "fly",
        "azure",
        "kubernetes",
        "keyvault",
        "containerapp",
        "kubectl",
        "flyctl",
        // The GitHub provider by its module and target type; plain "GitHub" stays allowed
        // (CI detection, documentation links).
        "githubtarget",
        // Store kinds and bindings (FR-39): core sees only `StoreConfig`.
        "azure_key_vault",
        "external-secrets",
        "externalsecrets?",
        "clustersecretstores?",
    ];
    let re = regex::Regex::new(&format!(
        r"(?i)\b({})\b|\b(az|gh)\s|\bgithub::",
        words.join("|")
    ))
    .unwrap();
    re.find(&production_code(src))
        .map(|m| m.as_str().to_string())
}

/// FR-37, FR-39: `app/`, `domain/`, `config.rs`, `config/`, `config_store.rs` and
/// `config_edit.rs` never name a provider, its CLI, its store or a store kind or binding;
/// provider lines come from `TargetConfig`. Only `init` writes a provider section by design.
#[cfg(test)]
#[test]
fn core_modules_name_no_provider() {
    let mut files: Vec<std::path::PathBuf> =
        ["src/config.rs", "src/config_store.rs", "src/config_edit.rs"]
            .iter()
            .map(std::path::PathBuf::from)
            .collect();
    for dir in ["src/app", "src/domain", "src/config"] {
        for e in std::fs::read_dir(dir).unwrap() {
            files.push(e.unwrap().path());
        }
    }
    let hits: Vec<String> = files
        .iter()
        .filter(|p| {
            let name = p.file_name().unwrap().to_string_lossy();
            name != "init.rs" && !name.ends_with("_tests.rs")
        })
        .filter_map(|p| {
            provider_named(&std::fs::read_to_string(p).unwrap())
                .map(|m| format!("{}: {m:?}", p.display()))
        })
        .collect();
    assert!(hits.is_empty(), "a provider named in core: {hits:?}");
}

/// The guard keeps reading after a test-only `mod x;` declaration (FR-37).
#[cfg(test)]
#[test]
fn guard_flags_a_provider_named_after_a_test_module_declaration() {
    let src = "#[cfg(test)]\npub(crate) mod t;\nfn f() -> &'static str { \"azure\" }\n";
    assert_eq!(provider_named(src).as_deref(), Some("azure"));
}

/// The guard keeps reading after a test-only block (FR-37).
#[cfg(test)]
#[test]
fn guard_flags_a_provider_named_after_a_test_block() {
    let src = "#[cfg(test)]\nthread_local! { static T: u8 = 0; }\n\
               #[cfg(test)]\nmod tests { fn t() { let _ = \"}\"; } }\n\
               const P: &str = \"kubectl\";\n";
    assert_eq!(provider_named(src).as_deref(), Some("kubectl"));
}

/// A provider named only inside a test-gated item is not production code.
#[cfg(test)]
#[test]
fn guard_ignores_a_provider_named_in_a_test_item() {
    let src = "fn f() {}\n#[cfg(test)]\n#[test]\nfn t() { let _ = \"fly\"; }\n";
    assert_eq!(provider_named(src), None);
}

#[cfg(test)]
pub(crate) mod testutil {
    //! Fixtures for command tests: items are built in code with obviously fake, rule-valid
    //! values (ruling P7). Every value contains [`MARKER`] so leaks are easy to assert.

    use base64::Engine as _;
    use serde_json::{Value, json};

    use crate::config;
    use crate::domain::Fleet;
    use crate::runner::Output;
    use crate::runner::fake::FakeRunner;

    /// How many findings `e` reports: the blocking keys of a `ValuesNeeded` (C4); `None`
    /// for any other error.
    pub fn findings_of(e: &crate::error::Error) -> Option<usize> {
        match e.parts().0 {
            crate::cause::Cause::ValuesNeeded { rows, .. } => Some(rows.len()),
            _ => None,
        }
    }

    /// The Next of `e`, rendered for `opv` with no flags (C4: catalog errors too).
    pub fn next_of_error(e: &crate::error::Error) -> String {
        e.next_text().unwrap_or_default()
    }

    pub const MARKER: &str = "FIXTUREVALUE";
    pub const OPENAI: &str = "sk-proj-FIXTUREVALUE";
    pub const POLICY: &str = "invite_only";
    pub const OPENAI_FLY: &str = "FLEET__ALLUMATA__OPENAI_API_KEY";
    pub const ENC_FLY: &str = "FLEET__ALLUMATA__INTEGRATION_ENC_KEY";
    pub const STRIPE_FLY: &str = "FLEET__ALLUMATA__STRIPE_SECRET_KEY";

    /// `opv explain <key>` as the CLI runs it, with a fixed project, so the service
    /// account names in the output never depend on the checkout's directory.
    pub fn explain(
        fleet: &Fleet,
        key: &str,
        env: Option<&str>,
        out: &mut dyn std::io::Write,
        json: bool,
    ) -> Result<(), crate::error::Error> {
        let asked = crate::app::explain::Asked::Key(key);
        crate::app::explain::run_request(fleet, &asked, env, "myapp", out, json)
    }

    pub fn fleet() -> Fleet {
        config::load("tests/fixtures/secrets.toml").unwrap()
    }

    /// The fixture fleet plus extra TOML appended (e.g. another key).
    pub fn fleet_with(extra: &str) -> Fleet {
        let text = crate::config::merged_text("tests/fixtures/secrets.toml");
        config::parse(&format!("{text}\n{extra}")).unwrap()
    }

    /// `text` with every `[environments.<env>.targets.<name>]` table removed: a remote
    /// profile may only name environments with no deployment target (O9, R1).
    pub fn without_targets(text: &str) -> String {
        let mut out = String::new();
        let mut in_target = false;
        for line in text.lines() {
            if line.starts_with('[') {
                in_target = line.starts_with("[environments.") && line.contains(".targets.");
            }
            if !in_target {
                out.push_str(line);
                out.push('\n');
            }
        }
        out
    }

    /// The fixture with every deployment target removed (see [`without_targets`]).
    pub fn fleet_without_targets(extra: &str) -> Fleet {
        let text = crate::config::merged_text("tests/fixtures/secrets.toml");
        config::parse(&format!("{}\n{extra}", without_targets(&text))).unwrap()
    }

    /// Two prod keys scoped to the process roles `serve` and `migrate` (#136).
    pub const ROLE_KEYS: &str = "\
[products.allumata.keys.SERVE_TOKEN]
kind = \"secret\"
environments = [\"prod\"]
roles = [\"serve\"]

[products.allumata.keys.DATABASE_URL_UNPOOLED]
kind = \"secret\"
environments = [\"prod\"]
roles = [\"migrate\"]
";

    /// The fixture TOML with `roles` on every target. The committed fixture declares no
    /// role-scoped keys, so its targets carry no roles; a test that appends [`ROLE_KEYS`]
    /// (or any role-scoped key) needs this text, or the load is refused (M3, §4.4).
    pub fn role_fixture_text() -> String {
        crate::config::merged_text("tests/fixtures/secrets.toml")
            .replace(
                "state_vault_id = \"sstg\"",
                "state_vault_id = \"sstg\"\nroles = [\"serve\", \"migrate\"]",
            )
            .replace(
                "state_vault_id = \"sprd\"",
                "state_vault_id = \"sprd\"\nroles = [\"serve\", \"migrate\"]",
            )
    }

    /// [`role_fixture_text`] plus extra TOML appended (e.g. [`ROLE_KEYS`]).
    pub fn role_fleet_with(extra: &str) -> Fleet {
        config::parse(&format!("{}\n{extra}", role_fixture_text())).unwrap()
    }

    /// The fixture fleet plus the two role-scoped keys.
    pub fn role_fleet() -> Fleet {
        role_fleet_with(ROLE_KEYS)
    }

    /// [`role_fleet`] plus a local delivery section and a `migrate`-scoped file key.
    pub fn role_local_fleet() -> Fleet {
        role_fleet_with(&format!(
            "{ROLE_KEYS}\n[products.allumata.keys.MIGRATE_PEM]
kind = \"secret\"
environments = [\"prod\"]
roles = [\"migrate\"]
file = \"db/migrate-pem\"

[products.allumata.local]
environment = \"declared_only\"
secrets_dir_env = \"APP_SECRETS_DIR\"
"
        ))
    }

    /// 32 bytes, base64. The bytes spell the marker, so a decoded leak is detectable too.
    pub fn enc() -> String {
        let mut b = *b"FIXTUREVALUEFIXTUREVALUEFIXTUREV";
        b[31] = b'!';
        base64::engine::general_purpose::STANDARD.encode(b)
    }

    /// One field: (section, label, `CONCEALED`/`STRING`, value; `None` = empty field).
    pub type Field = (String, String, &'static str, Option<String>);

    pub fn secret(section: &str, label: &str, v: &str) -> Field {
        (section.into(), label.into(), "CONCEALED", Some(v.into()))
    }
    pub fn text(section: &str, label: &str, v: &str) -> Field {
        (section.into(), label.into(), "STRING", Some(v.into()))
    }

    /// Every key desired in prod, correctly typed and rule-valid.
    pub fn complete_fields() -> Vec<Field> {
        vec![
            secret("allumata", "OPENAI_API_KEY", OPENAI),
            secret("allumata", "INTEGRATION_ENC_KEY", &enc()),
            text("allumata", "SIGNUP_POLICY", POLICY),
        ]
    }

    /// `op item get --format json` output for `fields`, shaped like the D0 fixture.
    pub fn item_json(fields: &[Field]) -> Vec<u8> {
        let mut sections: Vec<Value> = Vec::new();
        let mut fs: Vec<Value> = vec![json!({
            "id": "notesPlain", "type": "STRING", "purpose": "NOTES", "label": "notesPlain"
        })];
        for (s, l, ty, v) in fields {
            // An empty section is an unsectioned field (FR-43).
            let mut f = if s.is_empty() {
                json!({"id": l.to_lowercase(), "type": ty, "label": l})
            } else {
                if !sections.iter().any(|x| x["id"] == s.as_str()) {
                    sections.push(json!({"id": s, "label": s}));
                }
                json!({
                    "id": format!("{s}_{}", l.to_lowercase()),
                    "section": {"id": s, "label": s},
                    "type": ty,
                    "label": l,
                })
            };
            if let Some(v) = v {
                f["value"] = json!(v);
            }
            fs.push(f);
        }
        serde_json::to_vec(&json!({
            "id": "iprd", "title": "fleet", "version": 1,
            "vault": {"id": "vprd", "name": "fleet-prod"},
            "category": "SECURE_NOTE",
            "sections": sections,
            "fields": fs,
        }))
        .unwrap()
    }

    pub fn item(fields: &[Field]) -> Output {
        Output::success(item_json(fields))
    }
    pub fn complete_item() -> Output {
        item(&complete_fields())
    }
    pub fn item_without(section: &str, label: &str) -> Output {
        let fs: Vec<Field> = complete_fields()
            .into_iter()
            .filter(|(s, l, _, _)| !(s == section && l == label))
            .collect();
        item(&fs)
    }
    /// `fields` with the entry for `label` replaced.
    pub fn complete_with(f: Field) -> Output {
        let mut fs: Vec<Field> = complete_fields()
            .into_iter()
            .filter(|(s, l, _, _)| !(*s == f.0 && *l == f.1))
            .collect();
        fs.push(f);
        item(&fs)
    }

    /// `flyctl secrets list --json` output: (name, digest).
    pub fn fly(entries: &[(&str, &str)]) -> Output {
        let v: Vec<Value> = entries
            .iter()
            .map(|(n, d)| json!({"name": n, "digest": d, "status": "Deployed"}))
            .collect();
        Output::success(serde_json::to_vec(&v).unwrap())
    }
    /// `flyctl secrets list --json` output with explicit Fly status: (name, digest, status).
    pub fn fly_st(entries: &[(&str, &str, &str)]) -> Output {
        let v: Vec<Value> = entries
            .iter()
            .map(|(n, d, st)| json!({"name": n, "digest": d, "status": st}))
            .collect();
        Output::success(serde_json::to_vec(&v).unwrap())
    }
    pub fn fly_empty() -> Output {
        Output::success(b"[]".to_vec())
    }
    pub fn ok() -> Output {
        Output::success(Vec::new())
    }

    /// Recorded `flyctl status --app <app> --json` of a deployed app with one started
    /// machine (`tests/fixtures/fly/status-deployed.json`, NR-24).
    pub fn fly_app_ok() -> Output {
        fly_status("deployed")
    }
    /// Recorded `flyctl status --json` for `kind`: "deployed", "suspended" or "pending"
    /// (`tests/fixtures/fly/status-<kind>.json`).
    pub fn fly_status(kind: &str) -> Output {
        let doc = match kind {
            "deployed" => include_str!("../../tests/fixtures/fly/status-deployed.json"),
            "suspended" => include_str!("../../tests/fixtures/fly/status-suspended.json"),
            "pending" => include_str!("../../tests/fixtures/fly/status-pending.json"),
            other => panic!("no recorded status fixture for {other}"),
        };
        Output::success(doc)
    }
    /// The recorded deployed status with every machine set to `state` (derived: the
    /// recording has only a started machine).
    pub fn fly_app_machines(state: &str) -> Output {
        let mut v: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/fly/status-deployed.json"
        ))
        .unwrap();
        for m in v["Machines"].as_array_mut().unwrap() {
            m["state"] = json!(state);
        }
        Output::success(serde_json::to_vec(&v).unwrap())
    }
    /// `flyctl status --json` of a deleted app (constructed: no recording, `dead` is
    /// documented by flyctl but not reproducible without deleting an app).
    pub fn fly_app_dead() -> Output {
        Output::success(
            r#"{"Name":"app","Status":"dead","Machines":[],"PlatformVersion":"machines"}"#,
        )
    }
    /// Recorded `flyctl releases --json` (`tests/fixtures/fly/releases-deployed.json`).
    /// `"running"` is derived from it by setting `InProgress` on the latest release (no
    /// recording of a deploy under way).
    pub fn fly_releases(status: &str) -> Output {
        let doc = include_str!("../../tests/fixtures/fly/releases-deployed.json");
        if status == "complete" {
            return Output::success(doc);
        }
        let mut v: Value = serde_json::from_str(doc).unwrap();
        v[0]["InProgress"] = json!(true);
        v[0]["Status"] = json!(status);
        Output::success(serde_json::to_vec(&v).unwrap())
    }
    /// The two Fly preflight reads of a healthy app with no deploy running (NR-24).
    pub fn fly_preflight_ok() -> [Output; 2] {
        [fly_app_ok(), fly_releases("complete")]
    }

    /// `op whoami --format json` of a person: the account delivery evidence is bound to.
    pub fn whoami() -> Output {
        Output::success(
            r#"{"url":"https://my.1password.com","email":"dev@example.com","user_uuid":"UFIXTURE","account_uuid":"AFIXTURE","user_type":"HUMAN"}"#,
        )
    }

    /// What a sync's delivery recording asks `op` when no product gets a revision (a name
    /// this run did not confirm, or the target lists no version for it): `op whoami` and
    /// the boundary item read fresh (`boundary`).
    pub fn delivery_not_recorded(boundary: Output) -> [Output; 2] {
        [whoami(), boundary]
    }

    pub fn op_calls(r: &FakeRunner) -> usize {
        r.calls
            .borrow()
            .iter()
            .filter(|c| c.program == "op")
            .count()
    }

    /// True if some call to `program` has argv starting with `prefix`.
    pub fn called(r: &FakeRunner, program: &str, prefix: &[&str]) -> bool {
        r.calls.borrow().iter().any(|c| {
            c.program == program
                && c.args.len() >= prefix.len()
                && c.args.iter().zip(prefix).all(|(a, p)| a == p)
        })
    }

    /// `program args...` of every call, for exact-sequence assertions.
    pub fn argvs(r: &FakeRunner) -> Vec<String> {
        r.calls
            .borrow()
            .iter()
            .map(|c| format!("{} {}", c.program, c.args.join(" ")))
            .collect()
    }

    /// Stdin of the staging import, as text (it carries values by design).
    pub fn import_stdin(r: &FakeRunner) -> Option<String> {
        r.calls
            .borrow()
            .iter()
            .find(|c| c.program == "flyctl" && c.args.iter().any(|a| a == "import"))
            .map(|c| String::from_utf8(c.stdin.clone().unwrap_or_default()).unwrap())
    }

    /// No value (marker, or the base64 form) in any argv or env value (SR-3).
    pub fn assert_no_values_in_argv(r: &FakeRunner) {
        assert!(!r.argv_contains(MARKER), "value in argv: {:?}", argvs(r));
        assert!(!r.argv_contains(&enc()), "value in argv: {:?}", argvs(r));
        for c in r.calls.borrow().iter() {
            assert!(c.env.iter().all(|(_, v)| !v.contains(MARKER)));
        }
    }

    /// Output or error text must not contain any fixture value.
    pub fn assert_no_values(s: &str) {
        assert!(!s.contains(MARKER), "value leaked: {s}");
        assert!(!s.contains(&enc()), "value leaked: {s}");
    }

    pub fn text_of(out: &[u8]) -> String {
        String::from_utf8(out.to_vec()).unwrap()
    }
}

#[cfg(test)]
mod source_only_tests {
    //! FR-47: a source-only product's keys render no target name anywhere in the app layer.

    use super::*;

    const CFG: &str = r#"
[environments.ci]
boundaries.shared = { vault_id = "vci", item_id = "ici" }
boundaries.api = { vault_id = "vci", item_id = "ici" }
[environments.ci.targets.app]
fly.app = "app"
fly.secret_name = "FLEET__{PRODUCT}__{KEY}"
state_vault_id = "sci"
[products.shared]
source_only = true
[products.shared.keys.SHARED_TOKEN]
kind = "secret"
environments = ["ci"]
[products.api.keys.API_TOKEN]
kind = "secret"
environments = ["ci"]
"#;

    fn fleet() -> Fleet {
        crate::config::parse(CFG).unwrap()
    }

    #[test]
    fn managed_names_skip_a_source_only_product() {
        let names = managed_names(&fleet(), "ci", "app").unwrap();
        assert_eq!(names, HashSet::from(["FLEET__API__API_TOKEN".to_string()]));
    }

    #[test]
    fn product_names_is_empty_for_a_source_only_product() {
        let names = product_names(&fleet(), "ci", "app", "shared").unwrap();
        assert!(names.is_empty());
    }

    #[test]
    fn key_names_has_no_label_for_a_source_only_name() {
        let names = KeyNames::new(&fleet(), "ci", "app").unwrap();
        assert_eq!(
            names.label("FLEET__SHARED__SHARED_TOKEN"),
            "FLEET__SHARED__SHARED_TOKEN"
        );
    }
}
