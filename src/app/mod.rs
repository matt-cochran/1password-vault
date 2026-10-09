//! Application use cases, one module per command (§6.2).
//!
//! Rules shared by every command:
//! - The environment name is resolved with [`Fleet::environment`] before any subprocess
//!   call, so an unknown name is `Error::Config` and `plan::build` never sees one.
//! - A command that reads 1Password makes exactly one `op item get` (FR-13); a failed `op`
//!   call adds only the free `op whoami` / `op account list` diagnosis (FR-26). The read is
//!   tolerant, and a signed-in person's run may tidy the item (a check read, one edit, a
//!   verifying read; FR-43, [`tidy`]); a service account or CI never writes.
//! - Output names products, keys, kinds, rules and target names, never values (SR-1).

pub mod add;
#[cfg(test)]
mod azure_tests;
#[cfg(test)]
mod characterization_tests;
pub(crate) mod ci_summary;
pub mod config_cmd;
pub mod config_export;
pub mod doctor;
pub mod explain;
#[cfg(test)]
mod guidance_tests;
pub mod guide;
pub mod init;
#[cfg(test)]
pub(crate) mod json_tests;
pub mod local;
pub mod login;
pub mod open;
#[cfg(test)]
mod pinned_tests;
pub(crate) mod preflight;
pub mod run;
pub mod setup;
mod setup_import;
pub mod setup_recipe;
pub mod setup_runtime;
#[cfg(test)]
mod shared_tests;
pub mod signin;
#[cfg(test)]
mod simple_tests;
pub mod skeleton;
#[cfg(test)]
mod staged_tests;
pub mod status;
pub(crate) mod suggest;
pub mod sync;
pub(crate) mod tidy;
#[cfg(test)]
mod ux2_tests;
#[cfg(test)]
mod ux_tests;

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{self, Write};

use crate::adapters::{onepassword, registry};
use crate::domain::plan;
use crate::domain::{
    Environment, Fleet, KeyState, Kind, Row, SIMPLE_PRODUCT, SecretValue, StoreEntry, SyncPlan,
    TargetState, key_label,
};
use crate::error::Error;
use crate::ports::{PinnedStore, Ports, Store};
use crate::provider::TargetConfig;
use crate::runner::CommandRunner;

/// Store digests are not computable locally (D0 Q4, ruling P1): every key present on the
/// target is `Unknown` to the planner, and change detection is stage-and-compare in `sync`.
fn no_digest(_: &SecretValue) -> Option<String> {
    None
}

/// Read the environment's item once (FR-13), list the target's store once when `ports` are
/// given, and build the plan. `env_name` must already be resolved, and the target opened,
/// by the caller (so a missing target is `Error::Config` before any call).
///
/// With a store, every ready secret is also checked against the store's own rules
/// ([`Store::refusal`]), so `status` and `plan` show a value `sync` would refuse as a
/// failing rule naming product/KEY. A pinned store is also read once per ready secret it
/// lists, and the value compared exactly (FR-31); a staged store (Fly) is never read.
pub(crate) fn read_and_plan(
    fleet: &Fleet,
    env_name: &str,
    r: &dyn CommandRunner,
    ports: Option<&Ports<'_>>,
    rotate: &BTreeSet<(String, String)>,
    prune_immutable: &BTreeSet<(String, String)>,
) -> Result<(SyncPlan, Vec<StoreEntry>), Error> {
    let read = tidy::read(fleet, env_name, r)?;
    let (mut plan, listed) =
        plan_item(fleet, env_name, read.fields, ports, rotate, prune_immutable)?;
    plan.tidy = read.changes;
    plan.tidy_error = read.tidy_error.map(crate::error::Code::as_str);
    Ok((plan, listed))
}

/// [`read_and_plan`] that also returns the item's `version` integer, for the plan id
/// (FR-41). Still one item read (FR-13), plus a person's tidy (FR-43): the version is the
/// tidied item's, so a plan that tidied and the sync after it agree.
pub(crate) fn read_and_plan_versioned(
    fleet: &Fleet,
    env_name: &str,
    r: &dyn CommandRunner,
    ports: Option<&Ports<'_>>,
    rotate: &BTreeSet<(String, String)>,
    prune_immutable: &BTreeSet<(String, String)>,
) -> Result<(SyncPlan, Vec<StoreEntry>, Option<u64>), Error> {
    let read = tidy::read(fleet, env_name, r)?;
    let (mut plan, listed) =
        plan_item(fleet, env_name, read.fields, ports, rotate, prune_immutable)?;
    plan.tidy = read.changes;
    plan.tidy_error = read.tidy_error.map(crate::error::Code::as_str);
    Ok((plan, listed, read.version))
}

/// The environment's item fields: its one read by IDs (FR-13), tolerant and tidied when a
/// person runs opv (FR-43, [`tidy::read`]).
pub(crate) fn read_fields(
    fleet: &Fleet,
    env_name: &str,
    r: &dyn CommandRunner,
) -> Result<Vec<plan::ItemField>, Error> {
    Ok(read_item_fields(fleet, env_name, r)?.0)
}

/// [`read_fields`] with the item's `version` integer (FR-41).
pub(crate) fn read_item_fields(
    fleet: &Fleet,
    env_name: &str,
    r: &dyn CommandRunner,
) -> Result<(Vec<plan::ItemField>, Option<u64>), Error> {
    let read = tidy::read(fleet, env_name, r)?;
    Ok((read.fields, read.version))
}

/// The plan id (FR-41) of `plan`, built against `listed` on the target behind `ports`
/// from item version `item_version`. A staged store's versions are value digests (Fly), so
/// only a pinned store's version ids go in (SR-1).
pub(crate) fn plan_id_of(
    env_name: &str,
    product: Option<&str>,
    item_version: Option<u64>,
    plan: &SyncPlan,
    listed: &[StoreEntry],
    ports: &Ports<'_>,
) -> String {
    crate::domain::provenance::plan_id(
        &crate::domain::provenance::PlanIdInput {
            env: env_name,
            product,
            item_version,
            listed,
            version_ids: matches!(ports, Ports::Pinned { .. }),
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
    let read = tidy::read(full, env_name, r)?;
    let none = BTreeSet::new();
    let mut plan = plan_item(fleet, env_name, read.fields, None, &none, &none)?.0;
    plan.tidy = read.changes;
    plan.tidy_error = read.tidy_error.map(crate::error::Code::as_str);
    Ok(plan)
}

pub(crate) fn plan_item(
    fleet: &Fleet,
    env_name: &str,
    fields: Vec<plan::ItemField>,
    ports: Option<&Ports<'_>>,
    rotate: &BTreeSet<(String, String)>,
    prune_immutable: &BTreeSet<(String, String)>,
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
    let p = plan::build_with(
        fleet,
        env_name,
        fields,
        &on_target,
        &plan::PlanOptions {
            rotate,
            prune_immutable,
            digest: &no_digest,
            target_check: &refusal,
            current: current.as_ref().map(|c| c as &plan::CurrentCheck<'_>),
        },
    );
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

/// A failed write to the output stream. A closed pipe never gets here: `main` swallows
/// `BrokenPipe` so the command still returns its own result (e.g. `status | head`).
/// `text` with `note` appended to its first line (before a snippet or `fix:` lines).
pub(crate) fn on_first_line(text: &str, note: &str) -> String {
    match text.split_once('\n') {
        Some((first, rest)) => format!("{first}{note}\n{rest}"),
        None => format!("{text}{note}"),
    }
}

pub(crate) fn write_err(e: io::Error) -> Error {
    Error::Dependency(format!("cannot write output ({})", e.kind()).into())
}

/// The `product` of a JSON row: `None` (JSON `null`) for the simple profile's implicit
/// product, which is never shown (FR-20).
pub(crate) fn json_product(product: &str) -> Option<String> {
    (product != SIMPLE_PRODUCT).then(|| product.to_string())
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

/// FR-21: one names-only JSON document for `status --json` and `plan --json`.
///
/// Under the simple profile (FR-20) `product` is `null` in rows, extras and held entries,
/// matching the text table, which has no PRODUCT column there.
///
/// `schema_version` is 1; adding a field keeps the version. Rows carry names, states and
/// counts only (SR-1): no value, value fragment, value length or guidance text. Errors
/// before this point leave stdout empty, so a caller only gets a document on success.
///
/// `pinned` adds the per-row binding fields of a pinned target (R5): `binding`,
/// `pending_deploy` and `drift`, keyed by env name. They are absent for a staged target.
///
/// `target_name` is the row's name on the target for every provider; `fly_name` holds the
/// same value and is kept for scripts written before 0.5.0 (deprecated, P4). `product` is
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
    plan: &SyncPlan,
    pinned: Option<&BTreeMap<String, PinnedRow>>,
    product: Option<&str>,
    extra: &JsonExtra<'_>,
) -> Result<(), Error> {
    let env = fleet.environment(env_name)?;
    let staged: HashSet<&str> = plan.stage.iter().map(|(n, _)| n.as_str()).collect();
    let pruned: HashSet<&str> = plan.prune.iter().map(String::as_str).collect();
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

    let rows: Vec<JsonRow> = plan
        .rows
        .iter()
        .map(|r| {
            let target_name = env.target_name(&r.product, &r.key);
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
                .and_then(|n| pinned.and_then(|m| m.get(n)));
            JsonRow {
                binding: bound.map(|b| b.binding),
                pending_deploy: bound.map(|b| b.pending_deploy),
                drift: bound.map(|b| b.drift),
                chain: bound.and_then(|b| b.chain.clone()),
                open_url: extra.link.filter(|_| is_blocking(r)).map(str::to_string),
                ..JsonRow::new(r, target_name, json_target(r.kind, r.target), action)
            }
        })
        .collect();

    let changes = changes(plan, &rows, pinned);
    let doc = JsonDoc {
        schema_version: crate::json::SCHEMA_VERSION,
        environment: env_name.to_string(),
        product: product.map(str::to_string),
        changes,
        rows,
        extras: plan
            .extras
            .iter()
            .map(|(product, key)| JsonName {
                product: json_product(product),
                key: key.clone(),
            })
            .collect(),
        tidy: json_tidy(&plan.tidy),
        tidy_error: plan.tidy_error,
        stage: plan.stage.iter().map(|(n, _)| n.clone()).collect(),
        held: plan
            .held_immutable
            .iter()
            .map(|(product, key)| JsonHeld {
                product: json_product(product),
                key: key.clone(),
                target_name: env.target_name(product, key),
                fly_name: env.target_name(product, key),
            })
            .collect(),
        prune: plan.prune.clone(),
        totals: JsonTotals {
            rows: plan.rows.len(),
            findings: plan.blocking(),
            extras: plan.extras.len(),
            to_stage: plan.stage.len(),
            held: plan.held_immutable.len(),
            to_prune: plan.prune.len(),
        },
        plan_id: extra.plan_id.map(str::to_string),
        provenance: extra.provenance.map(|s| JsonStamp {
            opv_version: s.opv_version.clone(),
            written: s.written.clone(),
            plan_id: s.plan.clone(),
        }),
        next: extra.next.map(str::to_string),
    };
    let text = serde_json::to_string(&doc)
        .map_err(|e| Error::Dependency(format!("cannot serialize JSON ({e})").into()))?;
    writeln!(out, "{text}").map_err(write_err)
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
    let certain = staged.iter().any(|r| r.target != Some("present"))
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
    product: Option<String>,
    key: String,
    kind: &'static str,
    state: &'static str,
    rule: Option<&'static str>,
    /// Why `rule` failed (FR-22): from the rule's fixed set or the configuration only.
    reason: Option<String>,
    target_name: Option<String>,
    /// Deprecated alias of `target_name` (P4).
    fly_name: Option<String>,
    target: Option<&'static str>,
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
    /// A shared key's source, `product/KEY` (`KEY` under the simple profile) (FR-45).
    #[serde(skip_serializing_if = "Option::is_none")]
    shared_from: Option<String>,
}

impl JsonRow {
    /// `r` with its name on the target, its target presence and the plan's action.
    pub(crate) fn new(
        r: &Row,
        target_name: Option<String>,
        target: Option<&'static str>,
        action: Option<&'static str>,
    ) -> JsonRow {
        JsonRow {
            product: json_product(&r.product),
            key: r.key.clone(),
            kind: kind_label(r.kind),
            state: json_state(&r.state),
            rule: json_rule(&r.state),
            reason: json_reason(&r.state),
            fly_name: target_name.clone(),
            target_name,
            target,
            action,
            binding: None,
            pending_deploy: None,
            drift: None,
            chain: None,
            open_url: None,
            shared_from: json_source(r),
        }
    }
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

#[derive(serde::Serialize)]
struct JsonHeld {
    product: Option<String>,
    key: String,
    target_name: Option<String>,
    /// Deprecated alias of `target_name` (P4).
    fly_name: Option<String>,
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

/// Target presence: secrets are present/absent/would-change; config is not a target secret.
fn json_target(kind: Kind, target: TargetState) -> Option<&'static str> {
    match (kind, target) {
        (Kind::Config, _) => None,
        (Kind::Secret, TargetState::Absent) => Some("absent"),
        (Kind::Secret, TargetState::WouldChange) => Some("would_change"),
        (Kind::Secret, _) => Some("present"),
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

/// The TARGET word of a row (H5), from one closed set on every provider and in both
/// `status` and `plan`: `new`, `same`, `changed`, `unknown`, `pending`, `held`, `extra`,
/// `drift` or `n/a`. `held` marks an immutable key kept as it is; `binding` is the row's
/// binding on a pinned target, when known. `opv help states` defines each word.
pub(crate) fn target_word(r: &Row, held: bool, binding: Option<&PinnedRow>) -> &'static str {
    match (r.kind, r.target, &r.state) {
        (Kind::Config, _, _) => "n/a",
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

/// The source and target words and what each means, one line per word (`opv help states`,
/// H5). The JSON `state` and `target` fields keep their own stable spellings.
pub const STATES_HELP: &str = "\
SOURCE: the key in 1Password
  saved       stored in the right kind of field and passes every rule
  missing     no field with this name in the item's section
  wrong kind  a text field where a secret needs a concealed one, or the reverse
  failed      fails a rule; the rule and the reason follow, e.g. failed prefix (expected sk-)
  skipped     not required in this environment (its rules leave it out)

TARGET: the key on the deployment target
  new         not on the target yet; the next sync writes it
  same        on the target with the same value; nothing to write
  changed     on the target with another value; the next sync writes it
  unknown     on the target, but the target does not reveal values, so opv cannot compare;
              sync stages it and compares digests
  pending     written, not yet live; the next sync --deploy rolls it out
  held        immutable and already set; kept as it is (replace with --rotate)
  extra       on the target but not wanted in this environment; not pruned without --prune
  drift       the running app is bound to something other than what opv last wrote
  n/a         not a target secret (config keys, and skipped keys not on the target)

Missing, wrong kind and failed are findings: status, plan and check exit 8 and print an
open: link to the item in 1Password (opv open <[product/]KEY> --env <env>).";

/// `product/KEY` (`KEY` under the simple profile) of every row in `rows` matching `pred`,
/// for names-only messages.
pub(crate) fn row_names(rows: &[Row], pred: impl Fn(&Row) -> bool) -> Vec<String> {
    rows.iter()
        .filter(|r| pred(r))
        .map(|r| format!("{} ({})", key_label(&r.product, &r.key), row_state_label(r)))
        .collect()
}

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

/// Print `rows` as a table `PRODUCT KEY KIND STATE TARGET`, problems first (H4): the
/// blocking rows (missing, wrong kind, failed), then the rest, each group in declared
/// order. Under each missing or failing row its guidance; under each blocking row, when
/// `link` is given, `open:` and the 1Password item link with the section and field to fix
/// (H1). `target` renders the last column. Rows hold names only. Under the simple profile
/// (FR-20) there is no PRODUCT column: the table is `KEY KIND STATE TARGET`.
pub(crate) fn print_rows(
    out: &mut dyn Write,
    fleet: &Fleet,
    rows: &[Row],
    target: impl Fn(&Row) -> String,
    link: Option<&str>,
) -> Result<(), Error> {
    let skip = usize::from(fleet.is_simple());
    let header: Vec<String> = ["PRODUCT", "KEY", "KIND", "STATE", "TARGET"]
        .iter()
        .skip(skip)
        .map(|s| s.to_string())
        .collect();
    let ordered = problems_first(rows);
    let cells: Vec<Vec<String>> = ordered
        .iter()
        .map(|r| {
            [
                r.product.clone(),
                r.key.clone(),
                kind_label(r.kind).to_string(),
                row_state_label(r),
                target(r),
            ]
            .into_iter()
            .skip(skip)
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
    for (r, c) in ordered.iter().zip(&cells) {
        writeln!(out, "{}", line(c)).map_err(write_err)?;
        if let Some(t) = shared_text(r) {
            writeln!(out, "    {t}").map_err(write_err)?;
        }
        if wants_guidance(r) {
            writeln!(out, "    guidance: {}", r.guidance).map_err(write_err)?;
        }
        if let Some(url) = link.filter(|_| is_blocking(r)) {
            writeln!(out, "    open: {url} ({})", field_locator(r)).map_err(write_err)?;
        }
    }
    Ok(())
}

/// The blocking rows (and keys blocked by their source) first, then the others, each in
/// their original order (H4, FR-45).
pub(crate) fn problems_first(rows: &[Row]) -> Vec<&Row> {
    // A key blocked by its source (FR-45) is a problem too, fixed at the source.
    let (mut bad, good): (Vec<&Row>, Vec<&Row>) = rows
        .iter()
        .partition(|r| is_blocking(r) || r.state == KeyState::SourceBlocked);
    bad.extend(good);
    bad
}

/// Where a key lives inside its item: `section api, field KEY`, or `field KEY` under the
/// simple profile, whose fields are unsectioned (FR-20). 1Password links reach the item;
/// this names the field to fix in it.
pub(crate) fn field_locator(r: &Row) -> String {
    if r.product == SIMPLE_PRODUCT {
        format!("field {}", r.key)
    } else {
        format!("section {}, field {}", r.product, r.key)
    }
}

/// The 1Password private link to `env_name`'s item (H1), with the signed-in account from
/// one free `op whoami` probe when it answers. IDs only, never a value.
pub(crate) fn item_url(
    fleet: &Fleet,
    env_name: &str,
    r: &dyn CommandRunner,
) -> Result<String, Error> {
    let env = fleet.environment(env_name)?;
    let account = onepassword::account(r);
    Ok(onepassword::item_link(
        account.as_ref(),
        &env.vault_id,
        &env.item_id,
    ))
}

/// The `Findings` error of `status`, `plan` and `check`: the fix is a person's (`Do:`, A3)
/// and `Next:` opens the first blocking key in 1Password (H1).
pub(crate) fn findings_error(n: usize, rows: &[Row], env_name: &str) -> Error {
    Error::findings(n, open_next(rows, env_name)).with_do("fix the keys above in 1Password")
}

/// The next step for findings (H1): open the first blocking key's field in 1Password.
pub(crate) fn open_next(rows: &[Row], env_name: &str) -> String {
    match rows.iter().find(|r| is_blocking(r)) {
        Some(r) => format!(
            "opv open {} --env {env_name}",
            key_label(&r.product, &r.key)
        ),
        None => format!("opv status {env_name}"),
    }
}

/// One line under a status or plan table explaining `unknown` when a row shows it (H5).
pub(crate) fn print_legend(
    out: &mut dyn Write,
    words: &[&str],
    target_label: &str,
) -> Result<(), Error> {
    if words.contains(&"unknown") {
        writeln!(
            out,
            "unknown: {target_label} does not reveal stored values, so opv cannot compare them; \
             sync stages them and compares digests (opv help states)"
        )
        .map_err(write_err)?;
    }
    Ok(())
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
    Ok(())
}

/// `--product` on `status`, `plan` and `sync` (NR-16, P12, P20): refused under the simple
/// profile, which has no products (FR-20), and for an undeclared product. Before any call.
pub(crate) fn check_product(fleet: &Fleet, product: Option<&str>) -> Result<(), Error> {
    let Some(p) = product else { return Ok(()) };
    if fleet.is_simple() {
        return Err(Error::Config(
            "--product is not used under the simple profile; run the command without it".into(),
        )
        .with_code(crate::error::Code::UnknownProduct)
        .with_next("opv status"));
    }
    if !fleet.products.contains_key(p) {
        return Err(undefined_product(fleet, p, None));
    }
    Ok(())
}

/// An undeclared `--product`: the declared ones, the closest named, and a `Next:` step that
/// checks the closest (else the first) product's keys, read-only (H10). `env` is the
/// environment of the command when known; otherwise the first one declared.
pub(crate) fn undefined_product(fleet: &Fleet, p: &str, env: Option<&str>) -> Error {
    let all: Vec<&str> = fleet.products.keys().map(String::as_str).collect();
    let close = suggest::close(p, all.iter().copied());
    let hint = close
        .first()
        .map(|c| format!("; did you mean {c}?"))
        .unwrap_or_default();
    let pick = close
        .first()
        .or(all.first())
        .copied()
        .unwrap_or("<product>");
    Error::Config(
        format!(
            "undefined product {p:?}; choose one of: {}{hint}",
            all.join(", ")
        )
        .into(),
    )
    .with_code(crate::error::Code::UnknownProduct)
    .with_next(check_command(fleet, env, Some(pick)))
}

/// A read-only command that lists every declared key by name: `status` of the first
/// environment with a target, else `check` of the first environment (and product).
pub(crate) fn list_keys_command(fleet: &Fleet) -> String {
    if let Some((name, _)) = fleet
        .environments
        .iter()
        .find(|(_, e)| e.target().is_some())
    {
        return format!("opv status {name}");
    }
    let first = fleet.products.keys().next().map(String::as_str);
    check_command(fleet, None, first)
}

/// `opv check <env> [--product <p>]`: a read-only look at one product's keys in `env` (the
/// first environment declared when `env` is unknown), for `Next:` steps.
pub(crate) fn check_command(fleet: &Fleet, env: Option<&str>, product: Option<&str>) -> String {
    let env = env
        .filter(|e| fleet.environments.contains_key(*e))
        .or_else(|| fleet.environments.keys().next().map(String::as_str))
        .unwrap_or("<env>");
    match product.filter(|_| !fleet.is_simple()) {
        Some(p) => format!("opv check {env} --product {p}"),
        None => format!("opv check {env}"),
    }
}

/// The target names `product`'s declared keys render in `env_name` (its share of the managed
/// set, FR-8).
pub(crate) fn product_names(
    fleet: &Fleet,
    env_name: &str,
    product: &str,
) -> Result<HashSet<String>, Error> {
    let (_, t) = target(fleet, env_name)?;
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
}

/// Target name → `product/KEY` of every declared key, so output names a key the way the
/// configuration does, with the target's name second: `product/KEY (TARGET_NAME)` (P19).
pub(crate) struct KeyNames(BTreeMap<String, String>);

impl KeyNames {
    pub(crate) fn new(fleet: &Fleet, env_name: &str) -> Result<KeyNames, Error> {
        let (_, t) = target(fleet, env_name)?;
        Ok(KeyNames(
            fleet
                .products
                .iter()
                .flat_map(|(p, prod)| {
                    prod.keys
                        .keys()
                        .map(move |k| (t.env_name(p, k), key_label(p, k)))
                })
                .collect(),
        ))
    }

    /// `product/KEY (NAME)`; the bare name when it is no declared key's, or when the label
    /// is the name itself (simple profile).
    pub(crate) fn label(&self, name: &str) -> String {
        match self.0.get(name) {
            Some(key) if key != name => format!("{key} ({name})"),
            _ => name.to_string(),
        }
    }

    /// `{product, key, target_name}` for a target name (A6); `product` is null under the
    /// simple profile, `product` and `key` for a name no declared key renders.
    pub(crate) fn json_ref(&self, name: &str) -> serde_json::Value {
        let (product, key) = match self.0.get(name).map(|l| (l, l.split_once('/'))) {
            Some((_, Some((p, k)))) => (Some(p), Some(k)),
            Some((l, None)) => (None, Some(l.as_str())),
            None => (None, None),
        };
        serde_json::json!({"product": product, "key": key, "target_name": name})
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

/// The one-line count summary `status` prints first, and `status` without an environment
/// prints per environment (NR-16, P22): `prod: 4 keys · 3 saved · 1 skipped · 0 findings ·
/// 1 not yet on Fly`. Names and counts only.
pub(crate) fn count_line(env_name: &str, rows: &[Row], target_label: &str) -> String {
    let saved = rows.iter().filter(|r| r.state == KeyState::Ready);
    let absent = saved
        .clone()
        .filter(|r| r.kind == Kind::Secret && r.target == TargetState::Absent)
        .count();
    let skipped = rows.iter().filter(|r| r.state == KeyState::Skipped).count();
    let findings = rows.iter().filter(|r| is_blocking(r)).count();
    format!(
        "{env_name}: {} · {} saved · {skipped} skipped · {} · {absent} not yet on {target_label}",
        plural(rows.len(), "key", "keys"),
        saved.count(),
        plural(findings, "finding", "findings"),
    )
}

/// The environment and its target; `Error::Config` naming the environment when it is
/// undefined or has no target section (status, plan and sync need one). The hint names
/// what the default provider needs (FR-37).
pub(crate) fn target<'f>(
    fleet: &'f Fleet,
    env: &str,
) -> Result<(&'f Environment, &'f dyn TargetConfig), Error> {
    let e = fleet.environment(env)?;
    if let Some(t) = e.target() {
        return Ok((e, t));
    }
    let local = if fleet.is_simple() {
        format!("opv check {env} and opv run {env} -- <command>")
    } else {
        format!("opv check {env} --product <name> and opv run {env} --product <name> -- <command>")
    };
    let sections: Vec<&str> = registry::PROVIDERS.iter().map(|p| p.section()).collect();
    Err(Error::Config(
        format!(
            "environment {env:?} has no deployment target. For local settings use {local}. To \
             deploy, add one target section ({}) to environment {env} in secrets.toml first \
             ({DOCS}/configuration.md).",
            sections.join(", ")
        )
        .into(),
    )
    .with_code(crate::error::Code::NoTarget)
    .with_do(format!(
        "to deploy, add a {} section to environment {env} in secrets.toml ({DOCS}/configuration.md)",
        sections.join(", ")
    ))
    .with_next(check_command(
        fleet,
        Some(env),
        fleet.products.keys().next().map(String::as_str),
    )))
}

/// Where the user documentation lives (for next steps that are a page to read).
pub(crate) const DOCS: &str = "https://github.com/matt-cochran/1password-vault/blob/main/docs";

/// Resolve the environment's target and open its ports, before any call. Mutating
/// commands run [`preflight`] before their first write.
pub(crate) fn open_target<'a>(
    fleet: &'a Fleet,
    env_name: &'a str,
    r: &'a dyn CommandRunner,
) -> Result<(&'a dyn TargetConfig, Ports<'a>), Error> {
    let (_, t) = target(fleet, env_name)?;
    let managed = managed_names(fleet, env_name)?.into_iter().collect();
    Ok((t, t.open(env_name, managed, r)?))
}

/// Every name the target renders for a declared key: the managed set (FR-8, §10).
pub(crate) fn managed_names(fleet: &Fleet, env_name: &str) -> Result<HashSet<String>, Error> {
    let (_, t) = target(fleet, env_name)?;
    Ok(fleet
        .products
        .iter()
        .flat_map(|(p, prod)| prod.keys.keys().map(move |k| t.env_name(p, k)))
        .collect())
}

/// Names on the target that the template does not render for any declared key: other
/// tools' secrets, which opv never touches (FR-5 "unmanaged on <target>", §10.3).
pub(crate) fn unmanaged_on_target<'a>(
    fleet: &Fleet,
    env_name: &str,
    on_target: &'a [StoreEntry],
) -> Result<Vec<&'a str>, Error> {
    let managed = managed_names(fleet, env_name)?;
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
        // Store kinds and bindings (FR-39): core sees only `StoreConfig`.
        "azure_key_vault",
        "external-secrets",
        "externalsecrets?",
        "clustersecretstores?",
    ];
    let re = regex::Regex::new(&format!(r"(?i)\b({})\b|\baz\s", words.join("|"))).unwrap();
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

    pub const MARKER: &str = "FIXTUREVALUE";
    pub const OPENAI: &str = "sk-proj-FIXTUREVALUE";
    pub const POLICY: &str = "invite_only";
    pub const OPENAI_FLY: &str = "FLEET__ALLUMATA__OPENAI_API_KEY";
    pub const ENC_FLY: &str = "FLEET__ALLUMATA__INTEGRATION_ENC_KEY";
    pub const STRIPE_FLY: &str = "FLEET__ALLUMATA__STRIPE_SECRET_KEY";

    pub fn fleet() -> Fleet {
        config::load("tests/fixtures/secrets.toml").unwrap()
    }

    /// The fixture fleet plus extra TOML appended (e.g. another key).
    pub fn fleet_with(extra: &str) -> Fleet {
        let text = std::fs::read_to_string("tests/fixtures/secrets.toml").unwrap();
        config::parse(&format!("{text}\n{extra}")).unwrap()
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
            // An empty section is an unsectioned field (simple profile, FR-20).
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
