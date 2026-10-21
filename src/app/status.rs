//! `status <env>` use case (FR-17, spec §7.3, ruling P17).
//!
//! A one-line count summary first (NR-16), then one row per product × key with its
//! 1Password state and target state, guidance under each missing row, extras as warnings.
//! Names only. Exits `Findings(n)` for the n rows that are missing, of the wrong kind or
//! failing a rule; extras alone exit 0. `--product` limits all of it to one product (P12);
//! without an environment, one count line per environment (P22). Read-only: one `op item get` and one store list
//! (plus the free `op whoami` diagnosis when the read fails). A pinned target is also read
//! value by value (FR-31) and its bindings once, for the pending-deploy, drift and
//! env-routed lines (FR-29).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

use super::sync::{drift_line, pinned_diff, pinned_want};
use super::tidy::Mode;
use super::{
    JsonExtra, JsonPart, KeyNames, PinnedRow, Prefixed, check_product, ci_summary, count_line,
    findings_error, is_blocking, open_target, personal, placement, plan_item, plural, preflight,
    print_extras, print_legend, print_rows, product_names, read_and_plan, resolve_targets,
    rows_item_url, scope_plan, target_cell, target_runners, target_word, write_err, write_json,
};
use crate::cause::{Cause, Cmd, EnvName, TargetName};
use crate::domain::provenance::latest;
use crate::domain::{Binding, Fleet, KeyState, Row, StoreEntry, SyncPlan};
use crate::error::Error;
use crate::ports::{PinnedRuntime, PinnedStore, Ports};
use crate::provider::TargetConfig;
use crate::runner::CommandRunner;

pub fn run(
    fleet: &Fleet,
    env_name: &str,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    run_with(fleet, env_name, r, out, false)
}

/// `status <env> [--json]` for every product.
pub fn run_with(
    fleet: &Fleet,
    env_name: &str,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
    json: bool,
) -> Result<(), Error> {
    run_scoped(fleet, env_name, None, r, out, json)
}

/// `status <env> [--product p] [--json]`. Text starts with the one-line count summary
/// (NR-16), then the rows. With `json`, stdout carries one FR-21 document and nothing
/// else. `product` limits rows, totals and findings to one product (P12). Exit codes are
/// unchanged (`Findings` for blocking rows).
pub fn run_scoped(
    fleet: &Fleet,
    env_name: &str,
    product: Option<&str>,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
    json: bool,
) -> Result<(), Error> {
    run_targeted(fleet, env_name, &[], product, r, out, json, false)
}

/// [`run_scoped`] on every target of the environment, or the targets `--target` names
/// (FR-56, [`resolve_targets`]), in name order. Text starts with one count line per
/// target, then one table whose rows name their target; `--json` is one document whose
/// rows each carry `target`. Findings add up over the targets.
#[allow(clippy::too_many_arguments)]
pub fn run_targeted(
    fleet: &Fleet,
    env_name: &str,
    targets: &[String],
    product: Option<&str>,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
    json: bool,
    fail_on_drift: bool,
) -> Result<(), Error> {
    check_product(fleet, product, Some(env_name))?;
    // Needs a target: `NothingInScope` naming the environment otherwise, before any call.
    let names = resolve_targets(fleet, env_name, targets, "status")?;
    let runners = target_runners(fleet, env_name, &names, r)?;
    let mut parts = Vec::new();
    for (name, signed) in names.iter().zip(&runners) {
        let r: &dyn CommandRunner = match signed {
            Some(s) => s,
            None => r,
        };
        parts.push(status_part(fleet, env_name, name, product, r)?);
    }
    let n: usize = parts
        .iter()
        .map(|p| p.plan.rows.iter().filter(|r| is_blocking(r)).count())
        .sum();
    let all: Vec<Row> = parts
        .iter()
        .flat_map(|p| p.plan.rows.iter().cloned())
        .collect();
    // The 1Password link for the rows to fix (H1): one free `op whoami`, only when needed.
    let link = if n > 0 {
        rows_item_url(fleet, env_name, &all, r)?
    } else {
        None
    };
    let findings = || findings_error(&all, env_name);
    let counts: Vec<String> = parts
        .iter()
        .map(|p| count_line(env_name, &p.name, &p.plan.rows, p.t.provider().label()))
        .collect();
    for (p, count) in parts.iter().zip(&counts) {
        r.step_summary(&ci_summary::table(
            &status_command(env_name, product, &p.name),
            count,
            None,
            &p.name,
            &p.plan.rows,
            |row| p.word(row),
        ));
    }
    if json {
        // FR-42: the latest provenance stamp opv left on any of the targets (pinned only).
        let stamp = parts
            .iter()
            .filter_map(StatusPart::stamp)
            .max_by(|a, b| a.written.cmp(&b.written));
        let doc: Vec<JsonPart<'_>> = parts
            .iter()
            .map(|p| JsonPart {
                target: &p.name,
                plan: &p.plan,
                pinned: p.pinned.as_ref().map(|s| &s.rows),
                rotate: None,
                vars: None,
            })
            .collect();
        write_json(
            out,
            fleet,
            env_name,
            &doc,
            product,
            &JsonExtra {
                plan_id: None,
                provenance: stamp,
                next: None,
                link: link.as_deref(),
            },
        )?;
        if let Some(e) = drift_error(&parts, env_name, fail_on_drift) {
            return Err(e);
        }
        return if n > 0 { Err(findings()) } else { Ok(()) };
    }
    for count in &counts {
        writeln!(out, "{count}").map_err(write_err)?;
    }
    let rows: Vec<(&str, &Row)> = parts
        .iter()
        .flat_map(|p| p.plan.rows.iter().map(move |r| (p.name.as_str(), r)))
        .collect();
    let by_name: BTreeMap<&str, &StatusPart<'_>> =
        parts.iter().map(|p| (p.name.as_str(), p)).collect();
    print_rows(out, &rows, |t, row| by_name[t].word(row))?;
    let mut legends = BTreeSet::new();
    for p in &parts {
        let label = p.t.provider().label();
        if legends.insert((label, p.live)) {
            let words: Vec<String> = p.plan.rows.iter().map(|row| p.word(row)).collect();
            let words: Vec<&str> = words.iter().map(String::as_str).collect();
            print_legend(out, &words, label, p.live)?;
        }
    }
    // Extras are about the 1Password item, the same for every target.
    print_extras(out, &parts[0].plan)?;
    print_no_channel(out, env_name, fleet, &parts)?;
    print_concealed_config(out, &parts)?;
    let several = fleet
        .environments
        .get(env_name)
        .is_some_and(|e| e.targets.len() > 1);
    for p in &parts {
        let mut out = Prefixed::new(out, format!("{}: ", placement(env_name, &p.name)));
        if let Some(pinned) = &p.pinned {
            let deploy = deploy_step(env_name, several.then_some(p.name.as_str()));
            pinned.print(
                &mut out,
                env_name,
                &deploy,
                &KeyNames::new(fleet, env_name, &p.name)?,
            )?;
        }
        if let Some(s) = p.stamp() {
            writeln!(out, "{}: {}", p.t.provider().label(), s.line()).map_err(write_err)?;
        }
    }
    if let Some(e) = drift_error(&parts, env_name, fail_on_drift) {
        return Err(e);
    }
    if n > 0 {
        return Err(findings());
    }
    Ok(())
}

/// The drift finding of `status --fail-on-drift` (C3): the first target whose pinned
/// bindings drifted from 1Password, as the catalog's `TargetDrift` (exit 8,
/// `target_drift`). `None` without the flag, or when nothing drifted.
fn drift_error(parts: &[StatusPart<'_>], env_name: &str, fail_on_drift: bool) -> Option<Error> {
    if !fail_on_drift {
        return None;
    }
    let (target, names) = parts.iter().find_map(|p| {
        let drift = match &p.pinned {
            Some(pinned) => pinned.drift.to_vec(),
            // A staged target's plan names every value changed outside opv since the last
            // sync (FR-54), supplied at sync (#206) or not; each is drift.
            None => p.plan.drift.clone(),
        };
        (!drift.is_empty()).then_some((p.name.as_str(), drift))
    })?;
    Some(
        Cause::TargetDrift {
            env: EnvName::new(env_name),
            target: TargetName::new(target),
            names,
        }
        .into(),
    )
}

/// What `status` read for one target (FR-56).
struct StatusPart<'f> {
    name: String,
    t: &'f dyn TargetConfig,
    fleet: &'f Fleet,
    plan: SyncPlan,
    listed: Vec<StoreEntry>,
    pinned: Option<PinnedStatus>,
    /// The target applies writes at once (FR-46).
    live: bool,
}

impl StatusPart<'_> {
    /// The row's ON TARGET cell, with a config row's channel named (design §1.3, FM-02).
    fn word(&self, row: &Row) -> String {
        let name = self.t.env_name(&row.product, &row.key);
        let binding = self.pinned.as_ref().and_then(|p| p.rows.get(&name));
        let held = self
            .plan
            .held_immutable
            .iter()
            .any(|(p, k)| *p == row.product && *k == row.key);
        let spec = self
            .fleet
            .products
            .get(&row.product)
            .and_then(|p| p.keys.get(&row.key));
        // #201: a key present only through a person's attestation says so.
        let attested = self
            .plan
            .attested
            .iter()
            .any(|(p, k)| *p == row.product && *k == row.key);
        target_cell(
            row,
            if attested {
                "attested"
            } else {
                target_word(row, held, binding)
            },
            &self.t.channels(),
            spec,
        )
    }

    /// FR-42: the latest provenance stamp opv left on the target (pinned targets only).
    fn stamp(&self) -> Option<&crate::domain::Stamp> {
        self.pinned.as_ref().and_then(|_| latest(&self.listed))
    }
}

/// Read target `name` of `env_name` for `status`: its state (read-only, never waiting,
/// NR-23, NR-25), the item and the store listing, through its own ports (FR-56).
fn status_part<'f>(
    fleet: &'f Fleet,
    env_name: &str,
    name: &str,
    product: Option<&str>,
    r: &dyn CommandRunner,
) -> Result<StatusPart<'f>, Error> {
    let (_, t) = super::target(fleet, env_name, name)?;
    let (_, ports) = open_target(fleet, env_name, name, r)?;
    let at = preflight::At {
        fleet,
        env: env_name,
        name,
    };
    preflight::read(at, t, r)?;
    let none = BTreeSet::new();
    let (mut plan, listed) =
        read_and_plan(fleet, env_name, Some(name), r, Some(&ports), &none, &none)?;
    if let Some(p) = product {
        scope_plan(&mut plan, p, &product_names(fleet, env_name, name, p)?);
    }
    // Config delivered as variables (FR-46): each config row's state on the target.
    if let Ports::Staged { store, .. } = &ports
        && let Some(v) = store.variables()
    {
        crate::app::variables::plan(fleet, env_name, name, t, &mut plan, v, &|_| true)?;
    }
    let pinned = match &ports {
        Ports::Pinned { store, runtime } => Some(pinned_status(
            fleet,
            env_name,
            name,
            t,
            &plan,
            &listed,
            store.as_ref(),
            runtime.as_ref(),
        )?),
        Ports::Staged { .. } => None,
    };
    Ok(StatusPart {
        name: name.to_string(),
        t,
        fleet,
        live: super::live_writes(&ports),
        plan,
        listed,
        pinned,
    })
}

/// A config key the target's channel leaves undelivered (design §1.3, FM-02): one warning
/// per key, `<env>/<target>: warning: <product>/<KEY> not delivered (no config channel:
/// <why>)`.
fn print_no_channel(
    out: &mut dyn Write,
    env_name: &str,
    fleet: &Fleet,
    parts: &[StatusPart<'_>],
) -> Result<(), Error> {
    for p in parts {
        for k in &p.plan.no_channel {
            writeln!(
                out,
                "{}: warning: {} not delivered (no config channel: {})",
                placement(env_name, &p.name),
                crate::domain::key_label(&k.product, &k.key),
                k.why
            )
            .map_err(write_err)?;
        }
        for line in
            crate::app::file_destination_lines(fleet, env_name, &p.name, &p.t.channels(), &p.plan)
        {
            writeln!(out, "{line}").map_err(write_err)?;
        }
    }
    Ok(())
}

/// M4 (owner ruling): one warning per config key whose 1Password field is concealed and
/// that some target delivers as a plain environment value; its value is never shown. A
/// target that refuses it (`variables::plan`, a `concealed-config` finding) drops it from
/// its plan's list, so "is delivered" is a typed fact of a part's plan (01.01).
fn print_concealed_config(out: &mut dyn Write, parts: &[StatusPart<'_>]) -> Result<(), Error> {
    let delivered: BTreeSet<&(String, String)> = parts
        .iter()
        .flat_map(|p| &p.plan.concealed_config)
        .collect();
    for (product, key) in delivered {
        writeln!(
            out,
            "warning: {} is concealed in 1Password but declared config; it is delivered as a \
             plain environment value",
            crate::domain::key_label(product, key)
        )
        .map_err(write_err)?;
    }
    Ok(())
}

/// `opv sync <env> --deploy`, the write that applies pending bindings, with `--target` when
/// the environment has several (01.23). Typed (design §10.1); opv never adds `--confirm`.
fn deploy_step(env_name: &str, target: Option<&str>) -> Cmd {
    let mut args = vec![env_name.to_string(), "--deploy".to_string()];
    if let Some(t) = target {
        args.extend(["--target".to_string(), t.to_string()]);
    }
    Cmd {
        command: vec!["sync".to_string()],
        args,
    }
}

/// `opv status <env> --target <t>[ --product p]`.
fn status_command(env_name: &str, product: Option<&str>, target: &str) -> String {
    match product {
        Some(p) => format!("opv status {env_name} --target {target} --product {p}"),
        None => format!("opv status {env_name} --target {target}"),
    }
}

/// `status` without an environment (P22, H11): one count line per target of each
/// environment (`prod/web: …`, FR-56), environments and targets in name order. Every
/// environment is read, a run-only one too (`dev: run-only · 2 keys · 1 finding`), so a
/// green overview means every environment is green. One item read per target (FR-13); each
/// target is also listed as `status <env>` does. A JSON entry adds up its environment's
/// targets. `product` limits
/// every line to that product's keys. An environment that cannot be read is one line
/// naming the error, and the rest are still shown; the first such error is the result,
/// else `Findings` when any environment has findings.
///
/// With `json`, one document instead of lines (A5):
/// `{schema_version, product, environments: [{name, target, state, keys, saved, skipped,
/// findings, error_code, error, next}], totals}`, where `state` is `checked`, `run_only` (read,
/// no target) or `not_checked`. Exit codes are the same.
pub fn overview(
    fleet: &Fleet,
    product: Option<&str>,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
    json: bool,
) -> Result<(), Error> {
    check_product(fleet, product, None)?;
    let o = overview_of(fleet, product, r);
    if json {
        let doc = OverviewDoc {
            schema_version: crate::json::SCHEMA_VERSION,
            product: product.map(str::to_string),
            totals: OverviewTotals {
                environments: o.envs.len(),
                findings: o.findings,
            },
            environments: &o.envs,
        };
        // 01.26: an internal invariant, never a missing dependency.
        let text = serde_json::to_string(&doc).map_err(|_| {
            Error::from(Cause::Bug {
                site: "status overview document serializes",
            })
        })?;
        writeln!(out, "{text}").map_err(write_err)?;
    } else {
        for line in &o.lines {
            writeln!(out, "{line}").map_err(write_err)?;
        }
    }
    o.result(fleet)
}

/// The [`overview`] of one configuration, collected: its lines, one document entry per
/// environment, the first error and the findings count (`status --all` prints several).
pub struct Overview {
    pub lines: Vec<String>,
    pub(crate) envs: Vec<OverviewEnv>,
    first_err: Option<(String, Error)>,
    findings: usize,
    /// The first environment with findings and its blocking rows: the failure names them,
    /// so its step opens a key that has a finding (01.08), never a guessed product.
    first_finding: Option<(String, Vec<Row>)>,
}

impl Overview {
    /// The first error, else `ValuesNeeded` for the first environment with findings (its
    /// blocking keys, so the step opens one of them). `_fleet` is kept for the callers.
    pub fn result(self, _fleet: &Fleet) -> Result<(), Error> {
        if let Some((_, e)) = self.first_err {
            return Err(e);
        }
        match self.first_finding {
            Some((name, rows)) => Err(Cause::ValuesNeeded {
                env: EnvName::new(name),
                rows: rows.iter().map(value_row).collect(),
            }
            .into()),
            None => Ok(()),
        }
    }
}

/// Collect [`overview`]'s lines and entries without printing them.
pub fn overview_of(fleet: &Fleet, product: Option<&str>, r: &dyn CommandRunner) -> Overview {
    let mut o = Overview {
        lines: Vec::new(),
        envs: Vec::new(),
        first_err: None,
        findings: 0,
        first_finding: None,
    };
    for (name, env) in &fleet.environments {
        // Every target of the environment (FR-56), or the item alone for a run-only one.
        let targets: Vec<Option<(&str, &dyn TargetConfig)>> = if env.targets.is_empty() {
            vec![None]
        } else {
            env.targets
                .iter()
                .map(|(n, t)| Some((n.as_str(), t.config.as_ref())))
                .collect()
        };
        let target = env
            .targets
            .values()
            .next()
            .map(|t| t.config.provider().section());
        let read: Result<Vec<_>, Error> = targets
            .into_iter()
            .map(|t| {
                env_rows(fleet, name, t, r).map(|mut rows| {
                    if let Some(p) = product {
                        rows.retain(|row| row.product == p);
                    }
                    (t, rows)
                })
            })
            .collect();
        match read {
            Ok(read) => {
                let mut rows: Vec<Row> = Vec::new();
                for (t, part) in read {
                    o.lines.push(match t {
                        Some((tn, t)) => count_line(name, tn, &part, t.provider().label()),
                        None => run_only_line(name, &part),
                    });
                    rows.extend(part);
                }
                let n = rows.iter().filter(|r| is_blocking(r)).count();
                if n > 0 {
                    o.findings += n;
                    o.first_finding.get_or_insert_with(|| {
                        let blocking = rows.iter().filter(|r| is_blocking(r)).cloned();
                        (name.clone(), blocking.collect())
                    });
                }
                o.envs.push(OverviewEnv {
                    name: name.clone(),
                    target,
                    state: if target.is_some() {
                        "checked"
                    } else {
                        "run_only"
                    },
                    keys: Some(rows.len()),
                    saved: Some(rows.iter().filter(|r| r.state == KeyState::Ready).count()),
                    skipped: Some(rows.iter().filter(|r| r.state == KeyState::Skipped).count()),
                    findings: Some(n),
                    error_code: None,
                    error: None,
                    next: None,
                });
            }
            Err(e) => {
                // The overview knows the environment's name even when the adapter that
                // classified the failure did not (L10).
                let e = e.in_env(name);
                let first = e.to_string().lines().next().unwrap_or_default().to_string();
                // The error's own step (design §6.1), never one rebuilt here.
                let next = super::own_step(&e).1;
                o.lines.push(format!("{name}: not checked ({first})"));
                o.envs.push(OverviewEnv {
                    name: name.clone(),
                    target,
                    state: "not_checked",
                    keys: None,
                    saved: None,
                    skipped: None,
                    findings: None,
                    error_code: Some(e.code_str()),
                    error: Some(first),
                    next,
                });
                o.first_err.get_or_insert((name.clone(), e));
            }
        }
    }
    o
}

use super::value_row;

/// `dev: run-only · 4 keys · 3 saved · 1 skipped · 1 finding` (H11).
fn run_only_line(env_name: &str, rows: &[Row]) -> String {
    let saved = rows.iter().filter(|r| r.state == KeyState::Ready).count();
    let skipped = rows.iter().filter(|r| r.state == KeyState::Skipped).count();
    let n = rows.iter().filter(|r| is_blocking(r)).count();
    format!(
        "{env_name}: run-only · {} · {saved} saved · {skipped} skipped · {}",
        plural(rows.len(), "key", "keys"),
        plural(n, "finding", "findings"),
    )
}

/// The `status --json` overview document (A5, H11).
#[derive(serde::Serialize)]
struct OverviewDoc<'a> {
    schema_version: u32,
    /// `--product`, or null for every product.
    product: Option<String>,
    environments: &'a [OverviewEnv],
    totals: OverviewTotals,
}

#[derive(serde::Serialize)]
struct OverviewTotals {
    environments: usize,
    findings: usize,
}

/// One environment of the overview document: counts, or the code and first line of the
/// error that stopped it (value-free like every error).
#[derive(serde::Serialize)]
pub(crate) struct OverviewEnv {
    name: String,
    /// The target section (`fly`, `azure`, `kubernetes`), or `null` for run-only.
    target: Option<&'static str>,
    /// `checked`, `run_only` or `not_checked`.
    state: &'static str,
    keys: Option<usize>,
    saved: Option<usize>,
    skipped: Option<usize>,
    findings: Option<usize>,
    error_code: Option<&'static str>,
    error: Option<String>,
    /// For an environment that was not checked: the one command that runs as typed to get
    /// past its error (A3), never the error's prose; `null` otherwise.
    next: Option<String>,
}

/// One environment's rows, for [`overview`]: with a target as `status <env>` reads them
/// (item and store list), without one from the item alone, as `check` does. Each
/// environment uses its own 1Password account and, with a target, its deploy credentials,
/// signed out again before the next one (FR-40). `t` is the target (its name and config).
pub(crate) fn env_rows(
    fleet: &Fleet,
    env_name: &str,
    t: Option<(&str, &dyn TargetConfig)>,
    r: &dyn CommandRunner,
) -> Result<Vec<Row>, Error> {
    env_rows_keeping(fleet, env_name, t, r, None, Mode::Tidy)
}

/// A copy of `f` for the settings health checks (#92), which compare values across
/// environments after each item's read. The copy is a [`SecretValue`] like the original:
/// redacted in `Debug`, zeroized on drop, never printed.
fn copy_field(f: &crate::domain::plan::ItemField) -> crate::domain::plan::ItemField {
    crate::domain::plan::ItemField {
        section: f.section.clone(),
        label: f.label.clone(),
        kind: f.kind,
        value: crate::domain::SecretValue::new(f.value.expose().to_string()),
        concealed: f.concealed,
    }
}

/// [`env_rows`], also keeping a copy of the team item's fields in `keep` (#92), and
/// reading the item by `mode` (`ready` never tidies, #113). Still one item read. Personal
/// fields (FR-55) are never kept: they are each person's own.
pub(crate) fn env_rows_keeping(
    fleet: &Fleet,
    env_name: &str,
    t: Option<(&str, &dyn TargetConfig)>,
    r: &dyn CommandRunner,
    keep: Option<&mut Vec<crate::domain::plan::ItemField>>,
    mode: Mode,
) -> Result<Vec<Row>, Error> {
    use crate::app::signin::{Reach, open};
    let none = BTreeSet::new();
    let Some(t) = t else {
        let signed_in = open(fleet, env_name, r, Reach::Store)?;
        let fields = super::tidy::read_as(fleet, env_name, &signed_in, mode)?.fields;
        if let Some(keep) = keep {
            keep.extend(fields.iter().map(copy_field));
        }
        // FR-55: a targetless environment's personal keys live in the person's own item;
        // merge its fields (never a team fallback) before planning the rows.
        let fields = if personal::declared(fleet, env_name) {
            let project =
                personal::project_name(&signed_in, &std::env::current_dir().unwrap_or_default());
            personal::merged_fields(&signed_in, fleet, env_name, fields, &project)?
        } else {
            fields
        };
        return Ok(
            plan_item(fleet, env_name, None, fields, None, &none, &none)?
                .0
                .rows,
        );
    };
    let (target, t) = t;
    let signed_in =
        crate::app::signin::open_targeted(fleet, env_name, Some(target), r, Reach::Target)?;
    let r: &dyn CommandRunner = &signed_in;
    let (_, ports) = open_target(fleet, env_name, target, r)?;
    let at = preflight::At {
        fleet,
        env: env_name,
        name: target,
    };
    preflight::read(at, t, r)?;
    // read_and_plan by `mode`, keeping a copy of the fields before planning consumes them.
    let read = super::tidy::read_as(fleet, env_name, r, mode)?;
    if let Some(keep) = keep {
        keep.extend(read.fields.iter().map(copy_field));
    }
    let ledgers = super::placement_ledgers(fleet, env_name, Some(target), Some(&ports), r);
    let (mut plan, _) = super::plan_item_with(
        fleet,
        env_name,
        Some(target),
        read.fields,
        Some(&ports),
        &none,
        &none,
        &ledgers,
        false,
    )?;
    plan.tidy = read.changes;
    plan.tidy_error = read.tidy_error;
    if let Ports::Staged { store, .. } = &ports
        && let Some(v) = store.variables()
    {
        crate::app::variables::plan(fleet, env_name, target, t, &mut plan, v, &|_| true)?;
    }
    Ok(plan.rows)
}

/// Bindings of a pinned target (FR-29): per desired name whether its binding is current,
/// whether the next `--deploy` changes it, and drift; plus the env-routed config names.
struct PinnedStatus {
    rows: BTreeMap<String, PinnedRow>,
    pending: Vec<String>,
    drift: Vec<String>,
    env_routed: Vec<String>,
    runtime: String,
}

impl PinnedStatus {
    /// `deploy` is the write that applies the pending bindings ([`deploy_step`]).
    fn print(
        &self,
        out: &mut dyn Write,
        env_name: &str,
        deploy: &Cmd,
        names: &KeyNames,
    ) -> Result<(), Error> {
        let mut line = |text: String| writeln!(out, "{text}").map_err(write_err);
        if !self.pending.is_empty() {
            line(format!(
                "pending deploy ({}): {}",
                crate::cause::render::cmd_text(deploy),
                names.join(&self.pending)
            ))?;
        }
        if !self.drift.is_empty() {
            line(drift_line(env_name, &names.join(&self.drift)))?;
        }
        for (name, row) in &self.rows {
            if let Some(chain) = &row.chain {
                let rest = chain.strip_prefix(name.as_str()).unwrap_or(chain);
                line(format!("chain: {}{rest}", names.label(name)))?;
            }
        }
        if !self.env_routed.is_empty() {
            line(format!(
                "env-routed (visible to readers of {}): {}",
                self.runtime,
                names.join(&self.env_routed)
            ))?;
        }
        Ok(())
    }
}

/// Reads the runtime's bindings once and compares them with the plan (no write).
#[allow(clippy::too_many_arguments)]
fn pinned_status(
    fleet: &Fleet,
    env_name: &str,
    target: &str,
    t: &dyn TargetConfig,
    plan: &SyncPlan,
    listed: &[StoreEntry],
    store: &dyn PinnedStore,
    runtime: &dyn PinnedRuntime,
) -> Result<PinnedStatus, Error> {
    let want = pinned_want(
        fleet,
        env_name,
        target,
        t,
        plan,
        listed,
        store,
        runtime.config_in_store(),
    )?;
    let snap = runtime.bindings()?;
    let d = pinned_diff(t, &want, &BTreeMap::new(), &snap, plan, false);
    let pending = d.pending();
    let rows = want
        .store
        .keys()
        .chain(want.plain.keys())
        .map(|n| {
            let is_pending = pending.contains(n.as_str());
            let binding = match (snap.bindings.contains_key(n), is_pending) {
                (_, false) => "current",
                (true, true) => "stale",
                (false, true) => "unbound",
            };
            let chain = match snap.bindings.get(n) {
                Some(Binding::Pinned { version, .. }) if want.store.contains_key(n) => {
                    runtime.chain(n, version)
                }
                _ => None,
            };
            let row = PinnedRow {
                binding,
                pending_deploy: is_pending,
                drift: d.drift.contains(n),
                chain,
            };
            (n.clone(), row)
        })
        .collect();
    Ok(PinnedStatus {
        rows,
        pending: pending.iter().map(|n| n.to_string()).collect(),
        drift: d.drift.iter().cloned().collect(),
        env_routed: want.plain.keys().cloned().collect(),
        runtime: runtime.describe(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::testutil::*;
    use crate::runner::Output;
    use crate::runner::fake::FakeRunner;

    fn status_of(item: Output, fly_list: Output) -> (Result<(), Error>, String, FakeRunner) {
        let r = FakeRunner::new([item, fly_list]);
        let mut out = Vec::new();
        let res = run(&fleet(), "prod", &r, &mut out);
        (res, text_of(&out), r)
    }

    /// Every value-bearing path: saved rows, rule failures, the other kind, missing (with
    /// guidance), extras, and the returned error. The marker must never appear.
    #[test]
    fn status_prints_names_never_values() {
        let extra = secret("allumata", "OPENAI_API_KEYS", "sk-proj-FIXTUREVALUE-typo");
        let cases: Vec<(Vec<Field>, &str)> = vec![
            (complete_fields(), "saved"),
            (
                vec![
                    secret("allumata", "OPENAI_API_KEY", "sk-or-FIXTUREVALUE"),
                    secret("allumata", "INTEGRATION_ENC_KEY", &enc()),
                    text("allumata", "SIGNUP_POLICY", "FIXTUREVALUE"),
                ],
                "failed ",
            ),
            (
                vec![
                    // Stored as the other kind: read tolerantly (FR-43).
                    text("allumata", "OPENAI_API_KEY", OPENAI),
                    secret("allumata", "INTEGRATION_ENC_KEY", &enc()),
                    secret("allumata", "SIGNUP_POLICY", POLICY),
                ],
                "saved",
            ),
            (
                vec![
                    secret("allumata", "INTEGRATION_ENC_KEY", &enc()),
                    text("allumata", "SIGNUP_POLICY", POLICY),
                    extra.clone(),
                ],
                "missing",
            ),
            (
                vec![
                    secret("allumata", "OPENAI_API_KEY", " sk-proj-FIXTUREVALUE\n"),
                    secret("allumata", "INTEGRATION_ENC_KEY", &enc()),
                    text("allumata", "SIGNUP_POLICY", POLICY),
                    extra.clone(),
                ],
                "failed ",
            ),
        ];
        for (fields, expect) in cases {
            let (res, out, _) = status_of(item(&fields), fly(&[(OPENAI_FLY, "d1")]));
            assert!(out.contains("OPENAI_API_KEY"), "{out}");
            assert!(out.contains(expect), "{expect}: {out}");
            assert_no_values(&out);
            if let Err(e) = res {
                assert_no_values(&e.to_string());
                assert_no_values(&format!("{e:?}"));
            }
        }
    }

    #[test]
    fn status_missing_row_prints_guidance_on_next_line() {
        let (res, out, _) = status_of(item_without("allumata", "OPENAI_API_KEY"), fly_empty());
        assert!(
            res.as_ref()
                .err()
                .and_then(crate::app::testutil::findings_of)
                == Some(1),
            "{res:?}"
        );
        let lines: Vec<&str> = out.lines().collect();
        let i = lines
            .iter()
            .position(|l| l.contains("OPENAI_API_KEY") && l.contains("missing"))
            .unwrap();
        assert!(lines[i + 1].contains("OpenAI platform / API keys"), "{out}");
    }

    /// FR-26: a value failing its rule shows the reason and, under it, the key's guidance.
    #[test]
    fn status_rule_failure_prints_guidance_on_next_line() {
        let (res, out, _) = status_of(
            complete_with(secret("allumata", "OPENAI_API_KEY", "sk-or-FIXTUREVALUE")),
            fly_empty(),
        );
        assert!(
            res.as_ref()
                .err()
                .and_then(crate::app::testutil::findings_of)
                == Some(1),
            "{res:?}"
        );
        let lines: Vec<&str> = out.lines().collect();
        let i = lines
            .iter()
            .position(|l| l.contains("OPENAI_API_KEY") && l.contains("failed "))
            .unwrap();
        assert!(lines[i + 1].starts_with("    guidance: "), "{out}");
        assert!(lines[i + 1].contains("OpenAI platform / API keys"), "{out}");
        assert_no_values(&out);
    }

    /// M2: a config key on a target that declines config (Fly) warns once, naming the key
    /// and why (design §1.3, FM-02).
    #[test]
    fn status_warns_once_for_config_undelivered_on_fly() {
        let (_, out, _) = status_of(
            complete_with(secret("allumata", "SIGNUP_POLICY", POLICY)),
            fly_empty(),
        );
        let want = "prod/portfolio: warning: allumata/SIGNUP_POLICY not delivered \
                    (no config channel: set fly.config)";
        assert_eq!(out.lines().filter(|l| *l == want).count(), 1, "{out}");
    }

    /// Review Focus 2: a missing product section reports every desired key missing.
    #[test]
    fn status_missing_section_reports_every_key_missing() {
        let (res, out, _) = status_of(item(&[]), fly_empty());
        assert!(
            res.as_ref()
                .err()
                .and_then(crate::app::testutil::findings_of)
                == Some(3),
            "{res:?}"
        );
        for k in ["OPENAI_API_KEY", "INTEGRATION_ENC_KEY", "SIGNUP_POLICY"] {
            assert!(
                out.lines().any(|l| l.contains(k) && l.contains("missing")),
                "{k}: {out}"
            );
        }
        // prod has payments = "off": the Stripe key is skipped, not missing.
        assert!(
            out.lines()
                .any(|l| l.contains("STRIPE_SECRET_KEY") && l.contains("skipped")),
            "{out}"
        );
    }

    /// P17: extras are warnings; they alone exit 0.
    #[test]
    fn status_extras_alone_exit_zero() {
        let mut fs = complete_fields();
        fs.push(secret("allumata", "OPENAI_API_KEYS", OPENAI));
        let (res, out, _) = status_of(item(&fs), fly_empty());
        res.unwrap();
        assert!(
            out.contains("warning: extra field allumata/OPENAI_API_KEYS"),
            "{out}"
        );
        assert_no_values(&out);
    }

    #[test]
    fn status_complete_is_ok_and_shows_target_state() {
        let (res, out, _) = status_of(complete_item(), fly(&[(OPENAI_FLY, "d1")]));
        res.unwrap();
        let row = |k: &str| out.lines().find(|l| l.contains(k)).unwrap().to_string();
        assert!(row("OPENAI_API_KEY").ends_with("unknown"), "{out}");
        assert!(row("INTEGRATION_ENC_KEY").ends_with("new"), "{out}");
        assert!(
            row("SIGNUP_POLICY").ends_with("not delivered (no config channel)"),
            "{out}"
        );
        assert!(out.contains("PRODUCT") && out.contains("TARGET"), "{out}");
    }

    #[test]
    fn status_reads_item_once_and_lists_once() {
        let (_, _, r) = status_of(complete_item(), fly_empty());
        assert_eq!(op_calls(&r), 1);
        assert_eq!(
            argvs(&r),
            vec![
                "op item get iprd --vault vprd --format json",
                "flyctl secrets list --app mcproductlabs-portfolio-production --json",
            ]
        );
    }

    /// I1: a prod-only SMTP_PASS present (non-empty) in the staging item is a blocking
    /// `refuse_in` row in staging status, naming product and key.
    #[test]
    fn status_refuse_in_is_blocking_in_refused_env() {
        let fl = fleet_with(
            "[products.allumata.keys.SMTP_PASS]\nkind = \"secret\"\n\
             environments = [\"prod\"]\nrules = { refuse_in = [\"staging\"] }\n",
        );
        let fields = vec![
            secret("allumata", "INTEGRATION_ENC_KEY", &enc()),
            secret("allumata", "STRIPE_SECRET_KEY", "sk_test_FIXTUREVALUE"),
            text("allumata", "SIGNUP_POLICY", POLICY),
            secret("allumata", "SMTP_PASS", "FIXTUREVALUE-smtp"),
        ];
        let r = FakeRunner::new([item(&fields), fly_empty()]);
        let mut out = Vec::new();
        let res = run(&fl, "staging", &r, &mut out);
        let out = text_of(&out);
        assert!(
            res.as_ref()
                .err()
                .and_then(crate::app::testutil::findings_of)
                == Some(1),
            "{res:?}"
        );
        assert!(
            out.lines().any(|l| l.starts_with("portfolio  allumata")
                && l.contains("SMTP_PASS")
                && l.contains("failed refuse_in (")),
            "{out}"
        );
        assert_no_values(&out);
    }

    /// I2: a value that passes the rules but cannot travel on a Fly import line shows as a
    /// failing rule (exit 8), not green.
    #[test]
    fn status_shows_import_refusal_as_failing_rule() {
        let (res, out, _) = status_of(
            complete_with(secret("allumata", "OPENAI_API_KEY", "sk-a\"#FIXTUREVALUE")),
            fly_empty(),
        );
        let e = res.unwrap_err();
        assert!(crate::app::testutil::findings_of(&e) == Some(1), "{e}");
        assert_eq!(e.exit_code(), 8);
        assert!(
            out.lines().any(|l| l.contains("OPENAI_API_KEY")
                && l.contains("failed import-hash-after-odd-quotes (")),
            "{out}"
        );
        assert_no_values(&out);
    }

    /// I5: status needs a Fly target; Config naming the environment, before any call.
    #[test]
    fn status_env_without_fly_is_config_error_before_any_call() {
        let fl = fleet_with("[environments.dev]\n");
        let r = FakeRunner::new([]);
        let e = run(&fl, "dev", &r, &mut Vec::new()).unwrap_err();
        // The catalog's no-target cause (R25), naming the environment.
        assert_eq!(e.code_str(), "no_target", "{e}");
        assert!(r.calls.borrow().is_empty());
    }

    #[test]
    fn status_unknown_env_is_config_error_before_any_call() {
        let r = FakeRunner::new([]);
        let e = run(&fleet(), "qa", &r, &mut Vec::new()).unwrap_err();
        assert_eq!(e.code_str(), "unknown_env", "{e}");
        assert!(r.calls.borrow().is_empty());
    }

    #[test]
    fn status_source_failure_is_typed_and_value_free() {
        let r = FakeRunner::new(std::iter::once(Output::failure(1)).chain([Output::success(
            br#"{"email":"x-FIXTUREVALUE@example.com","user_type":"SERVICE_ACCOUNT"}"#.to_vec(),
        )]));
        r.responses
            .borrow_mut()
            .push_back(Ok(crate::runner::Output::failure(1)));
        let mut out = Vec::new();
        let e = run(&fleet(), "prod", &r, &mut out).unwrap_err();
        // Catalog (04.06): the vault does not open in op's default account.
        assert_eq!(e.code_str(), "vault_no_access", "{e}");
        assert_no_values(&e.to_string());
        // One item read, then the free session and vault checks (NR-26, P16: before any
        // retry; the vault is not readable, so none); no Fly call.
        assert_eq!(
            argvs(&r),
            vec![
                "op item get iprd --vault vprd --format json",
                "op whoami --format json",
                "op vault get vprd --format json"
            ]
        );
    }

    /// NR-16: the first line is the count summary.
    #[test]
    fn status_starts_with_a_count_summary() {
        let (res, out, _) = status_of(complete_item(), fly(&[(OPENAI_FLY, "d1")]));
        res.unwrap();
        // prod: OPENAI_API_KEY (on Fly), INTEGRATION_ENC_KEY (absent), SIGNUP_POLICY
        // (config); the Stripe key is skipped.
        assert_eq!(
            out.lines().next().unwrap(),
            "prod/portfolio: 4 keys · 3 saved · 1 skipped · 0 findings · 1 not yet on Fly",
            "{out}"
        );
    }

    /// Findings are counted in the summary line, and exit 8 is unchanged.
    #[test]
    fn status_with_findings_counts_them_first() {
        let (_, out, _) = status_of(item_without("allumata", "OPENAI_API_KEY"), fly_empty());
        assert!(
            out.lines().next().unwrap().contains(" · 1 finding · "),
            "{out}"
        );
    }

    #[test]
    fn status_with_findings_exits_8() {
        let (res, _, _) = status_of(item_without("allumata", "OPENAI_API_KEY"), fly_empty());
        assert_eq!(res.unwrap_err().exit_code(), 8);
    }

    /// NR-19, H1: the next step opens the first key to fix in 1Password.
    #[test]
    fn status_findings_next_step_opens_the_first_key() {
        let (res, _, _) = status_of(item_without("allumata", "OPENAI_API_KEY"), fly_empty());
        assert_eq!(
            crate::app::testutil::next_of_error(&res.unwrap_err()),
            "opv open allumata/OPENAI_API_KEY --env prod"
        );
    }
}

/// #219: on a staged target, a name the plan records as drift (changed outside opv
/// since the last sync) is a `--fail-on-drift` finding even when it is not a name
/// supplied at sync (#206). The world is the ledger's: one normal secret recorded at
/// one store version and listed at another.
#[cfg(test)]
mod staged_drift_tests {
    use std::cell::RefCell;
    use std::collections::{BTreeMap, BTreeSet};
    use std::io;
    use std::time::Duration;

    use crate::adapters::fake_op::FakeOp;
    use crate::app::{delivery, testutil};
    use crate::domain::plan::StoreEntry;
    use crate::domain::Fleet;
    use crate::error::Error;
    use crate::runner::{Call, CommandRunner, Outcome, Output};

    const NAME: &str = "FLEET__API__TOKEN";
    const VALUES: &str = "vdev0000000000000000000001";
    const STATE: &str = "vshr0000000000000000000002";

    /// 1Password (the stateful fake) plus the digests one Fly app lists.
    struct World {
        op: FakeOp,
        fly: RefCell<BTreeMap<String, String>>,
    }

    impl World {
        /// The recorded reply for one `flyctl` call. `status` and `releases` are the
        /// healthy-app fixtures the real preflight reads; only `secrets list` carries
        /// the versions the ledger compares.
        fn fly_output(&self, call: &Call) -> Output {
            match call.args.first().copied() {
                Some("secrets") => {
                    let v: Vec<serde_json::Value> = self
                        .fly
                        .borrow()
                        .iter()
                        .map(|(n, d)| {
                            serde_json::json!({"name": n, "digest": d, "status": "Deployed"})
                        })
                        .collect();
                    Output::success(serde_json::to_vec(&v).unwrap())
                }
                Some("status") => testutil::fly_app_ok(),
                Some("releases") => testutil::fly_releases("complete"),
                _ => Output::success(Vec::new()),
            }
        }
    }

    impl CommandRunner for World {
        fn read(&self, call: &Call, refused: &[i32]) -> io::Result<Outcome> {
            if call.program == "flyctl" {
                return Ok(Outcome::Done(self.fly_output(call)));
            }
            self.op.read(call, refused)
        }

        fn write(&self, call: &Call) -> io::Result<Outcome> {
            if call.program == "flyctl" {
                return Ok(Outcome::Done(self.fly_output(call)));
            }
            self.op.write(call)
        }

        fn probe(&self, call: &Call, limit: Duration) -> io::Result<Output> {
            if call.program == "flyctl" {
                return Ok(self.fly_output(call));
            }
            self.op.probe(call, limit)
        }

        fn pause(&self, _: Duration, _: &str) {}

        fn note(&self, _: &str) {}

        fn run_inherited(&self, _: &str, _: &[&str], _: &[(&str, &str)]) -> io::Result<i32> {
            Err(io::ErrorKind::Unsupported.into())
        }
    }

    /// dev on Fly app `a`, api/TOKEN in the values item, and api's delivery item recorded
    /// in the state vault (as `opv bootstrap` leaves it).
    fn world() -> (World, Fleet) {
        let op = FakeOp::default();
        let id = op.insert(
            VALUES,
            serde_json::json!({
                "title": "t", "category": "SECURE_NOTE",
                "sections": [{"id": "api", "label": "api"}],
                "fields": [{"id": "f1", "section": {"id": "api", "label": "api"},
                            "type": "CONCEALED", "label": "TOKEN",
                            "value": "tok-FIXTUREVALUE-1"}]
            }),
        );
        let state = op.insert(
            STATE,
            serde_json::json!({"title": "opv · delivery · api · app",
                               "category": "SECURE_NOTE", "fields": []}),
        );
        let fleet = crate::config::parse(&format!(
            "[environments.dev]\n\
             boundaries.api = {{ vault_id = \"{VALUES}\", item_id = \"{id}\" }}\n\
             [environments.dev.targets.app]\nfly.app = \"a\"\n\
             fly.secret_name = \"FLEET__{{PRODUCT}}__{{KEY}}\"\n\
             state_vault_id = \"{STATE}\"\ndelivery_items = {{ api = \"{state}\" }}\n\
             [products.api.keys.TOKEN]\nkind = \"secret\"\nenvironments = [\"dev\"]\n"
        ))
        .unwrap();
        (
            World {
                op,
                fly: RefCell::default(),
            },
            fleet,
        )
    }

    fn listed(version: &str) -> Vec<StoreEntry> {
        vec![StoreEntry {
            name: NAME.into(),
            version: Some(version.into()),
            pending: false,
            stamp: None,
        }]
    }

    /// A sync wrote NAME and recorded the store version it was listed at.
    fn record(w: &World, fleet: &Fleet, version: &str) {
        let written = BTreeSet::from([NAME.to_string()]);
        let item = fleet.environments["dev"].boundaries["api"]
            .as_ref()
            .unwrap()
            .item_id
            .clone();
        let source_versions = BTreeMap::from([(
            item.clone(),
            w.op.item(&item)["version"].as_u64().unwrap_or(0),
        )]);
        delivery::record(
            fleet,
            "dev",
            "app",
            None,
            &written,
            &BTreeSet::new(),
            &listed(version),
            &source_versions,
            "plan",
            None,
            &w.op,
        )
        .unwrap();
    }

    /// `opv status dev --fail-on-drift` (`fail_on_drift`).
    fn status(w: &World, fleet: &Fleet, fail_on_drift: bool) -> Result<(), Error> {
        let mut out = Vec::new();
        crate::app::status::run_targeted(fleet, "dev", &[], None, w, &mut out, false, fail_on_drift)
    }

    #[test]
    fn status_fail_on_drift_exits_8_for_a_staged_name_changed_outside_opv() {
        let (w, fleet) = world();
        record(&w, &fleet, "d1");
        w.fly.borrow_mut().insert(NAME.into(), "d2".into());
        assert_eq!(status(&w, &fleet, true).unwrap_err().exit_code(), 8);
    }

    #[test]
    fn status_fail_on_drift_names_a_staged_name_changed_outside_opv() {
        let (w, fleet) = world();
        record(&w, &fleet, "d1");
        w.fly.borrow_mut().insert(NAME.into(), "d2".into());
        assert!(status(&w, &fleet, true).unwrap_err().to_string().contains(NAME));
    }

    #[test]
    fn status_without_fail_on_drift_is_ok_for_a_staged_name_changed_outside_opv() {
        let (w, fleet) = world();
        record(&w, &fleet, "d1");
        w.fly.borrow_mut().insert(NAME.into(), "d2".into());
        assert!(status(&w, &fleet, false).is_ok());
    }

    #[test]
    fn status_fail_on_drift_is_ok_for_a_clean_staged_target() {
        let (w, fleet) = world();
        record(&w, &fleet, "d1");
        w.fly.borrow_mut().insert(NAME.into(), "d1".into());
        assert!(status(&w, &fleet, true).is_ok());
    }
}
