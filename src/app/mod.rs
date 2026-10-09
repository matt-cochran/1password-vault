//! Application use cases, one module per command (§6.2).
//!
//! Rules shared by every command:
//! - The environment name is resolved with [`Fleet::environment`] before any subprocess
//!   call, so an unknown name is `Error::Config` and `plan::build` never sees one.
//! - A command that reads 1Password makes exactly one `op item get` (FR-13); a failed `op`
//!   call adds only the free `op whoami` / `op account list` diagnosis (FR-26).
//! - Output names products, keys, kinds, rules and target names, never values (SR-1).

pub mod add;
#[cfg(test)]
mod azure_tests;
#[cfg(test)]
mod characterization_tests;
pub mod config_export;
pub mod doctor;
pub mod explain;
#[cfg(test)]
mod guidance_tests;
pub mod init;
pub mod local;
#[cfg(test)]
mod pinned_tests;
pub(crate) mod preflight;
pub mod run;
pub mod setup;
mod setup_import;
pub mod setup_recipe;
pub mod setup_runtime;
#[cfg(test)]
mod simple_tests;
pub mod skeleton;
pub mod status;
pub(crate) mod suggest;
pub mod sync;
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
    let fields = read_fields(fleet, env_name, r)?;
    plan_item(fleet, env_name, fields, ports, rotate, prune_immutable)
}

/// The environment's item fields: its one read by IDs (FR-13).
pub(crate) fn read_fields(
    fleet: &Fleet,
    env_name: &str,
    r: &dyn CommandRunner,
) -> Result<Vec<plan::ItemField>, Error> {
    let env = fleet.environment(env_name)?;
    Ok(onepassword::read_item_as(r, env, fleet.profile)?.fields)
}

/// [`read_and_plan`] for a local check of the products in `fleet` only, with no target: the
/// item read skips other products' sections, so their fields can neither block nor fail it.
pub(crate) fn read_and_plan_products(
    fleet: &Fleet,
    env_name: &str,
    r: &dyn CommandRunner,
) -> Result<SyncPlan, Error> {
    let env = fleet.environment(env_name)?;
    let sections: BTreeSet<String> = fleet.products.keys().cloned().collect();
    let item = if fleet.is_simple() {
        onepassword::read_item_as(r, env, fleet.profile)?
    } else {
        onepassword::read_item_in_sections(r, env, fleet.profile, &sections)?
    };
    let none = BTreeSet::new();
    Ok(plan_item(fleet, env_name, item.fields, None, &none, &none)?.0)
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
pub(crate) fn write_err(e: io::Error) -> Error {
    Error::Dependency(format!("cannot write output ({})", e.kind()).into())
}

/// The `product` of a JSON row: `None` (JSON `null`) for the simple profile's implicit
/// product, which is never shown (FR-20).
fn json_product(product: &str) -> Option<String> {
    (product != SIMPLE_PRODUCT).then(|| product.to_string())
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
/// set when `--product` scoped the document (NR-16).
pub(crate) fn write_json(
    out: &mut dyn Write,
    fleet: &Fleet,
    env_name: &str,
    plan: &SyncPlan,
    pinned: Option<&BTreeMap<String, PinnedRow>>,
    product: Option<&str>,
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
                product: json_product(&r.product),
                key: r.key.clone(),
                kind: kind_label(r.kind),
                state: json_state(&r.state),
                rule: json_rule(&r.state),
                reason: json_reason(&r.state),
                fly_name: target_name.clone(),
                target_name,
                target: json_target(r.kind, r.target),
                action,
            }
        })
        .collect();

    let doc = JsonDoc {
        schema_version: 1,
        environment: env_name.to_string(),
        product: product.map(str::to_string),
        rows,
        extras: plan
            .extras
            .iter()
            .map(|(product, key)| JsonName {
                product: json_product(product),
                key: key.clone(),
            })
            .collect(),
        stage: plan.stage.iter().map(|(n, _)| n.clone()).collect(),
        held: plan
            .held_immutable
            .iter()
            .map(|(product, key)| JsonHeld {
                product: json_product(product),
                key: key.clone(),
                fly_name: env.target_name(product, key),
                target_name: env.target_name(product, key),
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
    };
    let text = serde_json::to_string(&doc)
        .map_err(|e| Error::Dependency(format!("cannot serialize JSON ({e})").into()))?;
    writeln!(out, "{text}").map_err(write_err)
}

#[derive(serde::Serialize)]
struct JsonDoc {
    schema_version: u32,
    environment: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    product: Option<String>,
    rows: Vec<JsonRow>,
    extras: Vec<JsonName>,
    stage: Vec<String>,
    held: Vec<JsonHeld>,
    prune: Vec<String>,
    totals: JsonTotals,
}

#[derive(serde::Serialize)]
struct JsonRow {
    product: Option<String>,
    key: String,
    kind: &'static str,
    state: &'static str,
    rule: Option<&'static str>,
    /// Why `rule` failed (FR-22): from the rule's fixed set or the configuration only.
    reason: Option<String>,
    /// Deprecated alias of `target_name` (P4).
    fly_name: Option<String>,
    target_name: Option<String>,
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

#[derive(serde::Serialize)]
struct JsonName {
    product: Option<String>,
    key: String,
}

#[derive(serde::Serialize)]
struct JsonHeld {
    product: Option<String>,
    key: String,
    /// Deprecated alias of `target_name` (P4).
    fly_name: Option<String>,
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
    }
}

/// `product/KEY` (`KEY` under the simple profile) of every row in `rows` matching `pred`,
/// for names-only messages.
pub(crate) fn row_names(rows: &[Row], pred: impl Fn(&Row) -> bool) -> Vec<String> {
    rows.iter()
        .filter(|r| pred(r))
        .map(|r| {
            format!(
                "{} ({})",
                key_label(&r.product, &r.key),
                state_label(&r.state)
            )
        })
        .collect()
}

pub(crate) fn is_blocking(r: &Row) -> bool {
    matches!(
        r.state,
        KeyState::Missing | KeyState::WrongKind | KeyState::RuleFailed(..)
    )
}

/// Missing keys, and keys whose value fails a rule (including an empty skeleton field
/// nobody filled in), get their declared guidance printed under the row (FR-17, spec §7.4;
/// FR-26: the reason, in the STATE column, plus the key's guidance).
fn wants_guidance(r: &Row) -> bool {
    matches!(r.state, KeyState::Missing | KeyState::RuleFailed(..)) && !r.guidance.is_empty()
}

/// Print `rows` as a table `PRODUCT KEY KIND STATE TARGET`, with guidance on the line after
/// each missing row. `target` renders the last column. Rows hold names only. Under the
/// simple profile (FR-20) there is no PRODUCT column: the table is `KEY KIND STATE TARGET`.
pub(crate) fn print_rows(
    out: &mut dyn Write,
    fleet: &Fleet,
    rows: &[Row],
    target: impl Fn(&Row) -> String,
) -> Result<(), Error> {
    let skip = usize::from(fleet.is_simple());
    let header: Vec<String> = ["PRODUCT", "KEY", "KIND", "STATE", "TARGET"]
        .iter()
        .skip(skip)
        .map(|s| s.to_string())
        .collect();
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            [
                r.product.clone(),
                r.key.clone(),
                kind_label(r.kind).to_string(),
                state_label(&r.state),
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
    for (r, c) in rows.iter().zip(&cells) {
        writeln!(out, "{}", line(c)).map_err(write_err)?;
        if wants_guidance(r) {
            writeln!(out, "    guidance: {}", r.guidance).map_err(write_err)?;
        }
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
            "--product is not used under the simple profile".into(),
        ));
    }
    if !fleet.products.contains_key(p) {
        let all: Vec<&str> = fleet.products.keys().map(String::as_str).collect();
        return Err(Error::Config(
            format!("undefined product {p:?}; choose one of: {}", all.join(", ")).into(),
        ));
    }
    Ok(())
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
pub(crate) fn scope_plan(plan: &mut SyncPlan, product: &str, names: &HashSet<String>) {
    plan.rows.retain(|r| r.product == product);
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
             deploy, add one target section ({}) to environment {env} in secrets.toml first.",
            sections.join(", ")
        )
        .into(),
    )
    .with_next(format!("{DOCS}/configuration.md")))
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

/// The production code of a source file: comment lines dropped, and everything from the
/// first `#[cfg(test)]` item that is not a `mod x;` declaration cut off.
#[cfg(test)]
fn production_code(src: &str) -> String {
    let lines: Vec<&str> = src.lines().collect();
    let mut kept = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        if l.trim() == "#[cfg(test)]" {
            let next = lines.get(i + 1).map_or("", |n| n.trim());
            if !(next.starts_with("mod ") && next.ends_with(';')) {
                break;
            }
        }
        if !l.trim_start().starts_with("//") {
            kept.push(*l);
        }
    }
    kept.join("\n")
}

/// FR-37, FR-39: `app/`, `domain/` and `config.rs` never name a provider, its CLI, its store
/// or a store kind or binding;
/// provider lines come from `TargetConfig`. Only `init` writes a provider section by design.
#[cfg(test)]
#[test]
fn core_modules_name_no_provider() {
    let mut files = vec![std::path::PathBuf::from("src/config.rs")];
    for dir in ["src/app", "src/domain"] {
        for e in std::fs::read_dir(dir).unwrap() {
            files.push(e.unwrap().path());
        }
    }
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
    let hits: Vec<String> = files
        .iter()
        .filter(|p| {
            let name = p.file_name().unwrap().to_string_lossy();
            name != "init.rs" && !name.ends_with("_tests.rs")
        })
        .filter_map(|p| {
            let code = production_code(&std::fs::read_to_string(p).unwrap());
            re.find(&code)
                .map(|m| format!("{}: {:?}", p.display(), m.as_str()))
        })
        .collect();
    assert!(hits.is_empty(), "a provider named in core: {hits:?}");
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
