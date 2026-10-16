//! `plan` / `sync` use cases (FR-5..FR-8, FR-16, §6.4).
//!
//! Fly digests cannot be computed locally (D0 Q4), so `sync` is stage-and-compare
//! (ruling P1): read the item once → list A → plan → refuse if anything blocks (nothing
//! staged; `opv explain` named for the first key, NR-17) → validate the import batch →
//! preflight the target's state (NR-23, NR-24; `super::preflight`) → stage → list B, polled
//! until every staged name shows a digest (NR-30) → report each staged key as changed or
//! unchanged by digest → `--prune`: unset the plan's prune list (staged; never
//! an immutable key unless named with `--prune-immutable`) →
//! `--deploy`: deploy when a staged digest changed, a prune happened, or a managed name is
//! still `Staged`/`Partial` on Fly from an earlier run (FR-7). Without `--deploy`
//! nothing is ever deployed. `plan` reads the item once and lists once; it mutates
//! nothing (FR-11).
//!
//! A pinned target (clouds, FR-29) has no staging area: `sync` writes a new store version
//! only for a value that differs (FR-31), reads the runtime's bindings, and only under
//! `--deploy` re-pins them in one revision; it prunes only after that revision is healthy
//! (FR-32). See `run_pinned`.
//!
//! Targets (FR-56, D1 "every target, one plan id"): without `--target` a run covers every
//! target of the environment, in name order; `--target` (repeatable) narrows it. `sync`
//! first plans every target read-only ([`prepare`]: item read, listing, blocking rows),
//! derives one plan id from each target's id and name (`run_plan_id`) and checks
//! `--expect-plan` against it, then applies the targets one by one ([`apply`]), each with
//! its own ports, deploy identity, preflight and delivery evidence. A target that fails
//! stops the run before the next one writes; the error names the targets already synced.

use std::collections::{BTreeSet, HashSet};
use std::io::Write;
use std::time::Duration;

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use super::{
    JsonPart, KeyNames, Prefixed, check_product, ci_summary, compare, findings_error, is_blocking,
    managed_names, open_target, placement, plan_id_of, plan_item, plural, preflight, print_extras,
    print_legend, print_rows, product_names, read_and_plan_versioned, read_item_fields,
    resolve_targets, row_names, rows_item_url, scope_plan, target_runners, target_word,
    unmanaged_on_target, write_err, write_json,
};
use crate::cause::{
    Cause, Closest, Cmd, EnvName, KeyName, NameKind, PlanId, PlanScope, ProductKey, ProductName,
    TargetName, UsageProblem,
};
use crate::domain::plan::CurrentState::Same;
use crate::domain::provenance::run_plan_id;
use crate::domain::rules;
use crate::domain::{
    Binding, Fleet, Health, ItemField, KeyState, Kind, Revision, Row, RuntimeChange,
    RuntimeSnapshot, SecretValue, Stamp, StoreEntry, SyncPlan, TargetState, key_label,
};
use crate::error::{Code, Error, next_line};
use crate::ports::{PinnedRuntime, PinnedStore, Ports, StagedRuntime, StagedStore};
use crate::provider::TargetConfig;
use crate::runner::CommandRunner;

/// Flags of `sync`.
#[derive(Debug, Default, Clone)]
pub struct SyncOpts {
    /// Deploy staged changes (FR-7). Never implied.
    pub deploy: bool,
    /// Unset managed names not desired in this environment (FR-8). Never implied.
    pub prune: bool,
    /// `PRODUCT/KEY` entries: immutable keys to
    /// stage even though present on the target (FR-16).
    pub rotate: Vec<String>,
    /// `PRODUCT/KEY` entries: immutable keys `--prune` may
    /// unset (FR-8, FR-16). Without an
    /// entry an immutable key is never pruned. Requires `prune`.
    pub prune_immutable: Vec<String>,
    /// Write, prune and deploy only this product's managed names (P20).
    pub product: Option<String>,
    /// `--confirm <env>`: required when the environment sets `confirm_env` (NR-20).
    pub confirm: Option<String>,
    /// Print one JSON document (the run report) instead of text lines.
    pub json: bool,
    /// `--expect-plan <id>`: refuse before any write unless the plan re-derives to this id
    /// (FR-41). Also satisfies `confirm_env`: the id is bound to the environment.
    pub expect_plan: Option<String>,
    /// `--receipt <file>`: write the delivery receipts minted by this sync (#106).
    pub receipt: Option<std::path::PathBuf>,
    /// `--target <name>` (repeatable, FR-56): the targets to sync. Empty: every target of
    /// the environment, in name order.
    pub targets: Vec<String>,
}

impl SyncOpts {
    /// The `opv sync` command these options spell (design §10.1: a typed step, never a
    /// string). opv never adds `--confirm` to a step it generates (X4): confirming an
    /// environment is the person's. The global `--config` of this process is kept (09.04).
    fn command(&self, env_name: &str) -> Cmd {
        let mut args = vec![env_name.to_string()];
        for t in &self.targets {
            args.extend(["--target".into(), t.clone()]);
        }
        if self.deploy {
            args.push("--deploy".into());
        }
        if self.prune {
            args.push("--prune".into());
        }
        for k in &self.rotate {
            args.extend(["--rotate".into(), k.clone()]);
        }
        for k in &self.prune_immutable {
            args.extend(["--prune-immutable".into(), k.clone()]);
        }
        if let Some(p) = &self.product {
            args.extend(["--product".into(), p.clone()]);
        }
        if self.json {
            args.push("--json".into());
        }
        if let Some(id) = &self.expect_plan {
            args.extend(["--expect-plan".into(), id.clone()]);
        }
        args.extend(config_flag());
        Cmd {
            command: vec!["sync".into()],
            args,
        }
    }

    /// The scope a run of these options covers, for the read that shows what remains after
    /// a partial failure or a changed plan (R53, R71: `opv plan <env>` with every scope flag
    /// `plan` takes).
    fn scope(&self, env_name: &str) -> PlanScope {
        PlanScope::Sync {
            env: EnvName::new(env_name),
            targets: self.targets.iter().map(TargetName::new).collect(),
            product: self.product.as_ref().map(ProductName::new),
            deploy: self.deploy,
            prune: self.prune,
            rotate: self
                .rotate
                .iter()
                .filter_map(|e| split_key_ref(e))
                .map(|(p, k)| ProductKey {
                    product: ProductName::new(p),
                    key: KeyName::new(k),
                })
                .collect(),
        }
    }
}

/// The global `--config <path>` this process was started with, so a step opv builds runs
/// against the same configuration (09.04). Empty when it was not given.
fn config_flag() -> Vec<String> {
    let args = crate::error::invocation().args;
    let mut words = args.iter();
    while let Some(w) = words.next() {
        if w == "--config" {
            if let Some(p) = words.next() {
                return vec!["--config".into(), p.clone()];
            }
        } else if let Some(p) = w.strip_prefix("--config=") {
            return vec!["--config".into(), p.to_string()];
        }
    }
    Vec::new()
}

/// A step opv built, as the command line it prints.
fn step_text(c: &Cmd) -> String {
    crate::cause::render::cmd_text(c)
}

/// `given` is not a declared name of `kind` (R21): the Next substitutes only a unique close
/// match, and turns a write into its read; never the first candidate (X2, X3).
fn not_declared(kind: NameKind, given: &str, candidates: &[&str]) -> Error {
    Cause::NotDeclared {
        kind,
        given: given.to_string(),
        candidates: candidates.iter().map(|c| c.to_string()).collect(),
        closest: Closest::unique(&super::suggest::close(given, candidates.iter().copied())),
    }
    .into()
}

/// Every `--target` and `--product` name of a plan or sync, checked before any call
/// (01.04): an unknown one is [`not_declared`], never a step on a guessed name.
fn check_names(
    fleet: &Fleet,
    env_name: &str,
    targets: &[String],
    product: Option<&str>,
) -> Result<(), Error> {
    if let Some(p) = product
        && !fleet.products.contains_key(p)
    {
        let all: Vec<&str> = fleet.products.keys().map(String::as_str).collect();
        return Err(not_declared(NameKind::Product, p, &all));
    }
    let env = fleet.environment(env_name)?;
    let all: Vec<&str> = env.targets.keys().map(String::as_str).collect();
    match targets.iter().find(|t| !env.targets.contains_key(*t)) {
        Some(t) if !all.is_empty() => Err(not_declared(NameKind::Target, t, &all)),
        _ => Ok(()),
    }
}

/// `e` after this run already wrote `done` (R53, X20): a cataloged cause becomes
/// [`Cause::Partial`], whose Next is the read of what remains in `scope`, never the write;
/// a Legacy error gets the same names on a line of its own.
fn partial(e: Error, done: &[String], scope: PlanScope) -> Error {
    if done.is_empty() {
        return e;
    }
    match e {
        Error::Catalog(c, up) => {
            let (mut written, then) = match *c {
                Cause::Partial { done, then, .. } => (done, then),
                other => (Vec::new(), Box::new(other)),
            };
            for d in done {
                if !written.contains(d) {
                    written.push(d.clone());
                }
            }
            Error::Catalog(
                Box::new(Cause::Partial {
                    done: written,
                    approval_used: None,
                    approval_scope: Some(scope),
                    then,
                }),
                up,
            )
        }
        e => with_note(e, &format!("already written: {}", done.join(", "))),
    }
}

pub fn run(
    fleet: &Fleet,
    env_name: &str,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
    opts: &SyncOpts,
) -> Result<(), Error> {
    // Every check below happens before any subprocess call, except the confirm_env guard
    // for a missing --confirm: it gates the first write, so one run reports blocking keys
    // and the guard together (H12).
    let guard = confirm_env(fleet, env_name, opts)?;
    if opts.expect_plan.is_some() && !opts.prune_immutable.is_empty() {
        // `opv plan` never prunes an immutable key, so no plan id covers one (01.11): a
        // usage error whose step is never the destructive sync, let alone a confirmed one.
        return Err(Cause::Usage {
            problem: UsageProblem::ConflictsWith {
                a: "--expect-plan".into(),
                b: "--prune-immutable".into(),
            },
        }
        .into());
    }
    // An unknown name is never replaced by a guess, and its step is the read (01.04).
    check_names(fleet, env_name, &opts.targets, opts.product.as_deref())?;
    check_product(fleet, opts.product.as_deref(), "plan", Some(env_name))?;
    // A receipt file that cannot be written fails now, before anything is staged (01.07).
    if let Some(path) = &opts.receipt {
        super::delivery::check_receipt_path(path)?;
    }
    let names = resolve_targets(fleet, env_name, &opts.targets, "plan")?;
    let runners = target_runners(fleet, env_name, &names, r)?;
    let mut opened = Vec::new();
    for (name, signed) in names.iter().zip(&runners) {
        let r: &dyn CommandRunner = match signed {
            Some(s) => s,
            None => r,
        };
        let (t, ports) = open_target(fleet, env_name, name, r)?;
        opened.push((name.as_str(), t, ports, r));
    }
    let rotate = parse_rotate(fleet, env_name, &opts.rotate)?;
    let prune_immutable = parse_prune_immutable(fleet, env_name, opts)?;
    let receipts = std::cell::RefCell::new(Vec::new());
    let mut targets = Vec::new();
    for (target, t, ports, r) in opened {
        let scope = match &opts.product {
            Some(p) => Some(product_names(fleet, env_name, target, p)?),
            None => None,
        };
        let c = Ctx {
            fleet,
            env_name,
            target,
            t,
            r,
            opts,
            rotate: &rotate,
            prune_immutable: &prune_immutable,
            scope,
            names: KeyNames::new(fleet, env_name, target)?,
            confirm_missing: guard.missing,
            receipts: &receipts,
        };
        targets.push((c, ports));
    }
    // 1. Every target's plan, read-only, before any target is written (FR-41, FR-56).
    let mut planned = Vec::new();
    for (c, ports) in &targets {
        planned.push(details(out, c, |d| prepare(c, ports, d))?);
    }
    // 2. One plan id for the whole run, checked before the first write.
    let plan_id = run_plan_id(
        targets
            .iter()
            .zip(&planned)
            .map(|((c, _), p)| (c.target, p.id.as_str())),
    );
    expect_run(env_name, opts, &plan_id)?;
    // 3. Each target in name order; one failing stops the run before the next is written.
    let mut reports: Vec<Report> = Vec::new();
    for ((c, ports), p) in targets.iter().zip(planned) {
        let report = details(out, c, |d| {
            let report = apply(c, ports, p.prepared, &plan_id, d)?;
            if !opts.json {
                writeln!(d, "{}", report.summary()).map_err(write_err)?;
            }
            Ok(report)
        })
        .map_err(|e| after_targets(e, env_name, &targets, reports.len()))?;
        r.step_summary(&report.step_summary(env_name, c.target, opts, &c.names));
        reports.push(report);
    }
    let next = next_after(&reports, env_name, opts);
    if opts.json {
        return write_run_json(
            out,
            env_name,
            opts,
            &targets,
            &reports,
            &plan_id,
            next.as_deref(),
        );
    }
    if let Some(n) = next {
        write!(out, "{}", next_line(&n)).map_err(write_err)?;
    }
    Ok(())
}

/// Run `body` with the detail lines of target `c`: dropped under `--json` (preflight
/// warnings go to stderr, so stdout is one document), else prefixed `<env>/<target>: `.
fn details<T>(
    out: &mut dyn Write,
    c: &Ctx<'_>,
    body: impl FnOnce(&mut dyn Write) -> Result<T, Error>,
) -> Result<T, Error> {
    if c.opts.json {
        return body(&mut std::io::sink());
    }
    body(&mut Prefixed::new(
        out,
        format!("{}: ", placement(c.env_name, c.target)),
    ))
}

/// `e`, from target number `done` of `targets`, naming the targets this run already
/// synced (FR-56): one failing target stops the run before any later one is written.
fn after_targets(e: Error, env_name: &str, targets: &[(Ctx<'_>, Ports<'_>)], done: usize) -> Error {
    if done == 0 {
        return e;
    }
    let synced: Vec<String> = targets[..done]
        .iter()
        .map(|(c, _)| placement(env_name, c.target))
        .collect();
    let rest: Vec<String> = targets[done + 1..]
        .iter()
        .map(|(c, _)| placement(env_name, c.target))
        .collect();
    if matches!(e, Error::Catalog(..))
        && let Some((c, _)) = targets.first()
    {
        return partial(e, &synced, c.opts.scope(env_name));
    }
    let mut note = format!("already synced by this run: {}", synced.join(", "));
    if !rest.is_empty() {
        note.push_str(&format!("; not started: {}", rest.join(", ")));
    }
    with_note(e, &note)
}

/// The command that finishes the run's job (FR-56): [`Report::next`] of all targets
/// together, so a deploy is asked for where a target has names pending and `--prune`
/// where one keeps extras.
fn next_after(reports: &[Report], env_name: &str, opts: &SyncOpts) -> Option<String> {
    let open: Vec<&Report> = reports
        .iter()
        .filter(|r| !r.deploy_skipped && !(r.pending.is_empty() && r.kept.is_empty()))
        .collect();
    Report {
        live: open.iter().all(|r| r.live),
        pending: open
            .iter()
            .flat_map(|r| r.pending.iter().cloned())
            .collect(),
        kept: open.iter().flat_map(|r| r.kept.iter().cloned()).collect(),
        ..Report::default()
    }
    .next(env_name, opts)
}

/// The run report as one document (A6, S4, FR-56): every list holds `{target, product,
/// key, target_name}` objects over all targets, in target order; `targets` holds each
/// target's provider and deploy; `deployed_names` and `written_names` hold bare names.
fn write_run_json(
    out: &mut dyn Write,
    env_name: &str,
    opts: &SyncOpts,
    targets: &[(Ctx<'_>, Ports<'_>)],
    reports: &[Report],
    plan_id: &str,
    next: Option<&str>,
) -> Result<(), Error> {
    let both = || targets.iter().map(|(c, _)| c).zip(reports);
    let refs = |list: fn(&Report) -> &Vec<String>| -> Vec<serde_json::Value> {
        both()
            .flat_map(|(c, r)| c.names.json_refs(list(r)))
            .collect()
    };
    let mut reasons: Vec<&str> = Vec::new();
    for r in reports {
        for why in r.deploy_reason() {
            if !reasons.contains(&why) {
                reasons.push(why);
            }
        }
    }
    let mut doc = serde_json::json!({
        "schema_version": crate::json::SCHEMA_VERSION,
        "environment": env_name,
        "product": opts.product,
        "targets": both().map(|(c, r)| serde_json::json!({
            "target": c.target,
            "provider": c.t.provider().section(),
            "deployed": r.deployed.is_some(),
            "revision": r.deployed.as_deref().filter(|d| *d != DEPLOYED),
        })).collect::<Vec<_>>(),
        "written": refs(|r| &r.written),
        "unchanged": refs(|r| &r.unchanged),
        "held": refs(|r| &r.held),
        "deployed": reports.iter().any(|r| r.deployed.is_some()),
        "deploy_reason": reasons,
        "deployed_names": reports.iter().flat_map(|r| r.deployed_names.iter()).collect::<Vec<_>>(),
        "pending": refs(|r| &r.pending),
        "pruned": refs(|r| &r.pruned),
        "kept": refs(|r| &r.kept),
        "skipped": refs(|r| &r.skipped),
        "written_names": reports.iter().flat_map(|r| r.written.iter()).collect::<Vec<_>>(),
        "next": next,
        "plan_id": plan_id,
    });
    // #106: the receipts minted on each target (FR-58).
    if reports.iter().any(|r| r.delivery.is_some()) {
        let minted: Vec<serde_json::Value> = both()
            .filter_map(|(_, r)| r.delivery.as_ref())
            .flat_map(|d| &d.minted)
            .map(|m| {
                serde_json::json!({
                    "target": m.scope.target,
                    "product": m.scope.product,
                    "revision": m.revision,
                })
            })
            .collect();
        let not_minted: Vec<serde_json::Value> = both()
            .filter_map(|(c, r)| r.delivery.as_ref().map(|d| (c, d)))
            .flat_map(|(c, d)| {
                d.not_minted.iter().map(|n| {
                    serde_json::json!({
                        "target": c.target,
                        "product": n.product,
                        "reason": n.reason,
                    })
                })
            })
            .collect();
        doc["delivery"] = serde_json::json!({"minted": minted, "not_minted": not_minted});
    }
    writeln!(out, "{doc}").map_err(write_err)
}

/// The `confirm_env` guard of one run (NR-20).
struct Guard {
    /// Guarded and `--confirm` was not given: refused right before the first write
    /// ([`Ctx::require_confirm`]), after the read-only checks (H12).
    missing: bool,
}

/// NR-20: an environment with `confirm_env = true` syncs only with `--confirm <env>`; a
/// `--confirm` naming another environment is refused everywhere (a wrong-window typo),
/// before any call. A missing `--confirm` is only recorded here: the read-only part of the
/// run (item read, list, validation) goes first, so one refusal names both (H12).
fn confirm_env(fleet: &Fleet, env_name: &str, opts: &SyncOpts) -> Result<Guard, Error> {
    let env = fleet.environment(env_name)?;
    match opts.confirm.as_deref() {
        // Either name may be the typo: the step is the read, never a confirmed write (01.12).
        Some(c) if c != env_name => Err(Cause::ConfirmMismatch {
            given: c.to_string(),
            env: EnvName::new(env_name),
        }
        .into()),
        // A plan id is bound to its environment, so it is confirmation enough (FR-41).
        confirm => Ok(Guard {
            missing: env.confirm_env && confirm.is_none() && opts.expect_plan.is_none(),
        }),
    }
}

/// One `sync` run's inputs, resolved before any call.
struct Ctx<'a> {
    fleet: &'a Fleet,
    env_name: &'a str,
    /// The target's name (FR-56).
    target: &'a str,
    t: &'a dyn TargetConfig,
    r: &'a dyn CommandRunner,
    opts: &'a SyncOpts,
    rotate: &'a BTreeSet<(String, String)>,
    prune_immutable: &'a BTreeSet<(String, String)>,
    /// `--product`: that product's managed names; nothing else is written, pruned or
    /// unbound (P20).
    scope: Option<HashSet<String>>,
    names: KeyNames,
    /// `confirm_env = true` and no `--confirm` (H12).
    confirm_missing: bool,
    /// The delivery receipts this run minted so far, on every target (#106, FR-58).
    receipts: &'a std::cell::RefCell<Vec<crate::domain::delivery::Receipt>>,
}

impl Ctx<'_> {
    /// A refusal found before the first write; on a guarded environment run without
    /// `--confirm` it also says the flag is needed, so one run reports both (H12).
    fn refusal(&self, e: Error) -> Error {
        if !self.confirm_missing {
            return e;
        }
        let env = self.env_name;
        let guarded = format!(
            "{env} is also guarded (confirm_env = true): syncing it needs a person's confirmation"
        );
        match e {
            e @ Error::Catalog(..) => {
                self.r.note(&guarded);
                e
            }
            e @ Error::Policy(_) => e.map_text(|t| format!("{t}; {guarded}")),
            e => e,
        }
    }

    /// The guard itself (NR-20), after every read-only check and before the first write.
    fn require_confirm(&self) -> Result<(), Error> {
        if !self.confirm_missing {
            return Ok(());
        }
        Err(Cause::NeedsConfirm {
            env: EnvName::new(self.env_name),
        }
        .into())
    }

    /// `plan` limited to `--product`, when given.
    fn scoped(&self, mut plan: SyncPlan) -> SyncPlan {
        if let (Some(p), Some(names)) = (&self.opts.product, &self.scope) {
            scope_plan(&mut plan, p, names);
        }
        plan
    }

    fn in_scope(&self, name: &str) -> bool {
        self.scope.as_ref().is_none_or(|s| s.contains(name))
    }

    /// This target's plan id (FR-41), one input of the run's ([`run_plan_id`]).
    fn target_id(
        &self,
        plan: &SyncPlan,
        listed: &[StoreEntry],
        item_version: Option<u64>,
        ports: &Ports<'_>,
    ) -> String {
        plan_id_of(
            self.fleet,
            self.env_name,
            self.target,
            self.opts.product.as_deref(),
            item_version,
            plan,
            listed,
            ports,
            self.rotate,
            self.opts.expect_plan.as_deref(),
        )
    }
}

/// With `--expect-plan`, refuse a run whose plan id `id` differs (exit 6) before any write,
/// naming the new id (FR-41). The id covers every target the run would sync, so a plan
/// made for other targets never matches (FR-56).
fn expect_run(env_name: &str, opts: &SyncOpts, id: &str) -> Result<(), Error> {
    let Some(expected) = opts.expect_plan.as_deref() else {
        return Ok(());
    };
    if expected.eq_ignore_ascii_case(id) {
        return Ok(());
    }
    // The new id is shown for review; the Next is the plan read in the same scope, never a
    // sync pre-filled with the new id (X4).
    Err(Cause::PlanChanged {
        old: PlanId::new(expected),
        new: PlanId::new(id),
        scope: opts.scope(env_name),
    }
    .into())
}

/// What one `sync` run did (NR-18): target names only, never a value. The same on every
/// provider; printed as the `summary:` line or as the `--json` document.
#[derive(Debug, Default)]
struct Report {
    /// The target applies writes at once (FR-46): nothing to deploy, so no `--deploy` step.
    live: bool,
    /// New values written (staged on a staged target, new versions on a pinned one).
    written: Vec<String>,
    unchanged: Vec<String>,
    /// `Some(revision)` when this run deployed (`yes` where the runtime names none).
    deployed: Option<String>,
    pruned: Vec<String>,
    /// Waiting for a deploy after this run.
    pending: Vec<String>,
    /// Declared but not desired in this environment (skipped by its rules).
    skipped: Vec<String>,
    /// Immutable and present: not rewritten (FR-16).
    held: Vec<String>,
    /// Not desired here and kept, because `--prune` was not given.
    kept: Vec<String>,
    /// The deploy was skipped because the runtime has nothing to restart.
    deploy_skipped: bool,
    /// The id of the plan this run applied (FR-41).
    plan_id: String,
    /// What the deploy applied (S4): this run's writes and prunes, and names left
    /// pending by an earlier run.
    deployed_names: Vec<String>,
    /// Store names written by an earlier run and still waiting for a deploy when this run
    /// started (S4): why a run that wrote nothing deploys.
    earlier: Vec<String>,
    /// Delivery receipts minted (or not) after the confirmed writes (#106).
    delivery: Option<super::delivery::Recorded>,
}

impl Report {
    /// S4: one line, the same words on every provider: `summary: written N · unchanged N
    /// · held N · deployed <rev|yes|no>[ (N pending from an earlier run)] · pending N ·
    /// pruned N · kept N · skipped N`.
    fn summary(&self) -> String {
        let earlier = self.earlier().len();
        let why = if self.deployed.is_some() && earlier > 0 {
            format!(" ({earlier} pending from an earlier run)")
        } else {
            String::new()
        };
        format!(
            "summary: written {} · unchanged {} · held {} · deployed {}{why} · pending {} · \
             pruned {} · kept {} · skipped {}",
            self.written.len(),
            self.unchanged.len(),
            self.held.len(),
            self.deployed.as_deref().unwrap_or("no"),
            self.pending.len(),
            self.pruned.len(),
            self.kept.len(),
            self.skipped.len()
        )
    }

    /// Deployed names left pending by an earlier run.
    fn earlier(&self) -> Vec<&String> {
        self.deployed_names
            .iter()
            .filter(|n| self.earlier.contains(n))
            .collect()
    }

    /// Why the deploy happened (S4): `written`, `pruned`, `pending_from_earlier_run`; empty
    /// when nothing was deployed.
    fn deploy_reason(&self) -> Vec<&'static str> {
        if self.deployed.is_none() {
            return Vec::new();
        }
        let mut why = Vec::new();
        if self.deployed_names.iter().any(|n| self.written.contains(n)) {
            why.push("written");
        }
        if self.deployed_names.iter().any(|n| self.pruned.contains(n)) {
            why.push("pruned");
        }
        if !self.earlier().is_empty() {
            why.push("pending_from_earlier_run");
        }
        why
    }

    /// The CI job summary section of target `target` (H8, FR-56): the summary line and
    /// each list, names only.
    fn step_summary(
        &self,
        env_name: &str,
        target: &str,
        opts: &SyncOpts,
        names: &KeyNames,
    ) -> String {
        let mut heading = format!("opv sync {env_name} --target {target}");
        if let Some(p) = &opts.product {
            heading.push_str(&format!(" --product {p}"));
        }
        let lists = [
            ("written", names.join(&self.written)),
            ("pruned", names.join(&self.pruned)),
            ("pending deploy", names.join(&self.pending)),
            ("held (immutable)", names.join(&self.held)),
            ("extra, not pruned", names.join(&self.kept)),
            ("unchanged", names.join(&self.unchanged)),
        ];
        let lists: Vec<(&str, &str)> = lists.iter().map(|(l, n)| (*l, n.as_str())).collect();
        ci_summary::lists(&heading, &self.summary(), &lists)
    }
}

impl Report {
    /// The command that finishes the job: a deploy for pending names, `--prune` for kept
    /// ones. `None` when nothing is left, or a deploy would not help (nothing to restart).
    fn next(&self, env_name: &str, opts: &SyncOpts) -> Option<String> {
        if self.deploy_skipped || (self.pending.is_empty() && self.kept.is_empty()) {
            return None;
        }
        let o = SyncOpts {
            deploy: !self.live,
            prune: opts.prune || !self.kept.is_empty(),
            rotate: Vec::new(),
            prune_immutable: Vec::new(),
            product: opts.product.clone(),
            confirm: None,
            json: false,
            expect_plan: None,
            receipt: None,
            targets: opts.targets.clone(),
        };
        Some(step_text(&o.command(env_name)))
    }
}

/// [`Report::deployed`] for a runtime that names no revision.
const DEPLOYED: &str = "yes";

/// Target names of the plan's rows that are not desired here (P2 `skipped`).
fn skipped_names(c: &Ctx<'_>, plan: &SyncPlan) -> Result<Vec<String>, Error> {
    Ok(plan
        .rows
        .iter()
        .filter(|r| r.state == KeyState::Skipped)
        .map(|r| c.t.env_name(&r.product, &r.key))
        .collect())
}

/// Target names of the immutable keys held (present, not rotated).
fn held_names(c: &Ctx<'_>, plan: &SyncPlan) -> Result<Vec<String>, Error> {
    Ok(plan
        .held_immutable
        .iter()
        .map(|(p, k)| c.t.env_name(p, k))
        .collect())
}

/// One target's plan in a `sync` run, read-only: what [`apply`] then carries out.
struct Planned {
    prepared: Prepared,
    /// The target's plan id (FR-41), one input of the run's.
    id: String,
}

/// What [`prepare`] read and planned, by the target's kind.
enum Prepared {
    Staged {
        plan: SyncPlan,
        list_a: Vec<StoreEntry>,
        var_plan: Option<super::variables::VarPlan>,
    },
    Pinned {
        plan: SyncPlan,
        listed: Vec<StoreEntry>,
        skip_deploy: Option<String>,
    },
}

/// Read and plan target `c` (no write): the item, the store listing and, on a pinned
/// target, its state (NR-23). Blocking rows refuse here, before any target is written.
fn prepare(c: &Ctx<'_>, ports: &Ports<'_>, out: &mut dyn Write) -> Result<Planned, Error> {
    match ports {
        Ports::Staged { store, .. } => prepare_staged(c, ports, store.as_ref()),
        Ports::Pinned { .. } => prepare_pinned(c, ports, out),
    }
}

/// Carry out `prepared` on target `c` under the run's plan id `plan_id`.
fn apply(
    c: &Ctx<'_>,
    ports: &Ports<'_>,
    prepared: Prepared,
    plan_id: &str,
    out: &mut dyn Write,
) -> Result<Report, Error> {
    match (ports, prepared) {
        (
            Ports::Staged { store, runtime },
            Prepared::Staged {
                plan,
                list_a,
                var_plan,
            },
        ) => run_staged(
            c,
            store.as_ref(),
            runtime.as_ref(),
            Staged {
                plan,
                list_a,
                var_plan,
                plan_id: plan_id.to_string(),
            },
            out,
        ),
        (
            Ports::Pinned { store, runtime },
            Prepared::Pinned {
                plan,
                listed,
                skip_deploy,
            },
        ) => run_pinned(
            c,
            store.as_ref(),
            runtime.as_ref(),
            Pinned {
                plan,
                listed,
                skip_deploy,
                plan_id: plan_id.to_string(),
            },
            out,
        ),
        _ => unreachable!("a target's plan is applied through the ports it was made with"),
    }
}

/// [`prepare`] for a staged target: one item read and list A.
fn prepare_staged(
    c: &Ctx<'_>,
    ports: &Ports<'_>,
    store: &dyn StagedStore,
) -> Result<Planned, Error> {
    let (fleet, env_name, t) = (c.fleet, c.env_name, c.t);
    let (plan, list_a, item_version) = read_and_plan_versioned(
        fleet,
        env_name,
        Some(c.target),
        c.r,
        Some(ports),
        c.rotate,
        c.prune_immutable,
    )?;
    let mut plan = c.scoped(plan);
    // A target that delivers config itself (FR-46): its rows get their state first, so a
    // refused or concealed config key blocks like any other finding.
    let var_plan = match store.variables() {
        Some(v) => Some(super::variables::plan(
            fleet,
            env_name,
            c.target,
            t,
            &mut plan,
            v,
            &|n| c.in_scope(n),
        )?),
        None => None,
    };
    refuse_blocking(&plan, env_name).map_err(|e| c.refusal(e))?;
    Ok(Planned {
        id: c.target_id(&plan, &list_a, item_version, ports),
        prepared: Prepared::Staged {
            plan,
            list_a,
            var_plan,
        },
    })
}

/// A staged target's plan, ready to apply.
struct Staged {
    plan: SyncPlan,
    list_a: Vec<StoreEntry>,
    var_plan: Option<super::variables::VarPlan>,
    /// The run's plan id (FR-41).
    plan_id: String,
}

/// `sync` for a staged target (Fly, §6.4): stage, compare digests, deploy.
fn run_staged(
    c: &Ctx<'_>,
    store: &dyn StagedStore,
    runtime: &dyn StagedRuntime,
    staged: Staged,
    out: &mut dyn Write,
) -> Result<Report, Error> {
    let (fleet, env_name, t, opts) = (c.fleet, c.env_name, c.t, c.opts);
    let Staged {
        plan,
        list_a,
        var_plan,
        plan_id,
    } = staged;
    let vars = store.variables();
    let batch: Vec<(String, &SecretValue)> =
        plan.stage.iter().map(|(n, v)| (n.clone(), v)).collect();
    store.validate(&batch).map_err(|e| c.refusal(e))?;
    c.require_confirm()?;
    // Last read-only step before the first write (NR-23, NR-24).
    let skip_deploy = preflight::run(t, c.r, out, opts.json)?;
    print_extras(out, &plan)?;

    let label = t.provider().label();
    let names = &c.names;
    let mut report = Report {
        live: runtime.live(),
        skipped: skipped_names(c, &plan)?,
        held: held_names(c, &plan)?,
        plan_id,
        ..Report::default()
    };
    // Writes this run completed, named when a later step fails (NR-10).
    let mut done: Vec<String> = Vec::new();
    // Nothing staged by this run: list A is the current state, no second list needed.
    let list_b = if batch.is_empty() {
        list_a.clone()
    } else {
        store.write(&batch)?;
        done.push(format!("staged {} secret(s)", batch.len()));
        confirm(store, &batch, c, &done)?
    };
    // #106, FR-58, D11: what this run wrote (confirmed above) or the plan proved identical,
    // recorded as each placement's evidence lines, which are also its version ledger.
    {
        let written: BTreeSet<String> = batch.iter().map(|(n, _)| n.clone()).collect();
        let identical: BTreeSet<String> = plan
            .rows
            .iter()
            .filter(|row| row.target == TargetState::Present)
            .map(|row| t.env_name(&row.product, &row.key))
            .collect();
        record_delivery(c, &written, &identical, &list_b, &mut report, out)?;
    }
    for (name, _) in &batch {
        let (a, b) = (digest(&list_a, name), digest(&list_b, name));
        // A staged key with no digest after staging is unknown: count it as changed.
        if b.is_none() || a != b {
            report.written.push(name.clone());
        } else {
            report.unchanged.push(name.clone());
        }
    }
    if let (Some(v), Some(vp)) = (vars, &var_plan) {
        if !vp.set.is_empty() {
            let batch: Vec<(String, &str)> = vp
                .set
                .iter()
                .map(|n| (n.clone(), vp.want[n].as_str()))
                .collect();
            v.set(&batch).map_err(|e| after_writes_in(c, e, &done))?;
            done.push(format!("set {} variable(s)", batch.len()));
            report.written.extend(vp.set.iter().cloned());
        }
        report.unchanged.extend(vp.unchanged.iter().cloned());
    }

    let p = |out: &mut dyn Write, s: String| writeln!(out, "{s}").map_err(write_err);
    print_changes(out, names, &report)?;

    // Secrets and, where the target takes config itself, variables (FR-46): one list.
    let var_prune: &[String] = var_plan.as_ref().map_or(&[], |vp| vp.prune.as_slice());
    let all_prune: Vec<String> = plan.prune.iter().chain(var_prune).cloned().collect();
    let mut pruned = Vec::new();
    if !all_prune.is_empty() && opts.prune {
        p(out, format!("will prune: {}", names.join(&all_prune)))?;
        if !plan.prune.is_empty() {
            store
                .remove(&plan.prune)
                .map_err(|e| after_writes_in(c, e, &done))?;
            done.push(format!("pruned {} name(s)", plan.prune.len()));
        }
        if let Some(v) = vars
            && !var_prune.is_empty()
        {
            v.remove(var_prune)
                .map_err(|e| after_writes_in(c, e, &done))?;
            done.push(format!("pruned {} variable(s)", var_prune.len()));
        }
        p(out, format!("pruned: {}", names.join(&all_prune)))?;
        pruned = all_prune;
    } else if !all_prune.is_empty() {
        p(out, kept_line(names, &all_prune))?;
        report.kept = all_prune;
    }
    print_held(out, &plan, names, &report.held)?;

    // Every write above is already live (FR-46): there is no pending state and nothing to
    // deploy, so `--deploy` only says so.
    if runtime.live() {
        report.pruned = pruned;
        if opts.deploy {
            p(out, live_line(label))?;
        }
        return Ok(report);
    }

    // Managed names still staged from an earlier run (e.g. a sync without --deploy, or a
    // failed deploy). Status is only an extra deploy trigger, never change detection.
    let managed = managed_names(fleet, env_name, c.target)?;
    let (pending, others): (Vec<&str>, Vec<&str>) = list_b
        .iter()
        .filter(|s| managed.contains(&s.name) && s.pending)
        .map(|s| s.name.as_str())
        .partition(|n| c.in_scope(n));
    if !others.is_empty() {
        p(
            out,
            format!(
                "pending for other products: {}; a deploy restarts the app with them too",
                names.join(&others)
            ),
        )?;
    }

    // Everything this run leaves for a deploy, in name order without repeats.
    let waiting: BTreeSet<String> = report
        .written
        .iter()
        .chain(&pruned)
        .cloned()
        .chain(pending.iter().map(|n| n.to_string()))
        .collect();
    let waiting: Vec<String> = waiting.into_iter().collect();
    report.earlier = pending
        .iter()
        .filter(|n| !report.written.iter().any(|w| w == *n))
        .map(|n| n.to_string())
        .collect();
    report.pruned = pruned;
    match (waiting.is_empty(), opts.deploy) {
        (true, _) => {}
        (false, true) if skip_deploy.is_some() => {
            p(out, skip_deploy.unwrap_or_default())?;
            report.deploy_skipped = true;
            report.pending = waiting;
        }
        (false, true) => {
            runtime.deploy().map_err(|e| after_writes_in(c, e, &done))?;
            // A pruned name is listed under `pruned:`, never as deployed (09.24).
            let deployed: Vec<String> = waiting
                .iter()
                .filter(|n| !report.pruned.contains(n))
                .cloned()
                .collect();
            if deployed.is_empty() {
                p(
                    out,
                    "deployed: the removal of the names pruned above".into(),
                )?;
            } else {
                p(out, format!("deployed: {}", names.join(&deployed)))?;
            }
            report.deployed = Some(DEPLOYED.into());
            report.deployed_names = deployed;
        }
        (false, false) => {
            p(out, pending_line(names, &waiting))?;
            report.pending = waiting;
        }
    }
    Ok(report)
}

/// #106, FR-58: on target `c` (its own state vault, scope naming the target), a delivery
/// revision per product in scope whose every name this run wrote (`written`, confirmed by the provider) or the plan proved identical, at
/// the versions in `listing`. Never fails the sync: what it could not record is reported.
fn record_delivery(
    c: &Ctx<'_>,
    written: &BTreeSet<String>,
    identical: &BTreeSet<String>,
    listing: &[StoreEntry],
    report: &mut Report,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let (fleet, env_name, opts) = (c.fleet, c.env_name, c.opts);
    let recorded = super::delivery::record(
        fleet,
        env_name,
        c.target,
        opts.product.as_deref(),
        written,
        identical,
        listing,
        &report.plan_id,
        c.r,
    );
    match recorded {
        Ok(rec) => {
            // The file holds every receipt this run minted so far, on every target, so a
            // later target that fails leaves the earlier targets' receipts in it (FR-58).
            c.receipts.borrow_mut().extend(rec.minted.iter().cloned());
            // The writes stand whatever happens to the file (01.07): the receipts are also
            // recorded in 1Password and in the run report, so a file that cannot be saved is
            // a note naming it, never a failure that hides what this sync wrote.
            if let Some(path) = &opts.receipt
                && let Err(e) = super::delivery::write_receipt_file(path, &c.receipts.borrow())
            {
                c.r.note(&format!(
                    "the delivery receipts this sync minted were not saved to {} ({}); this \
                     sync's writes stand",
                    path.display(),
                    error_words(&e)
                ));
            }
            if !opts.json {
                for m in &rec.minted {
                    p_line(
                        out,
                        format!("delivery: {} revision {}", m.scope.product, m.revision),
                    )?;
                }
                for n in &rec.not_minted {
                    p_line(
                        out,
                        format!("delivery: {} not recorded: {}", n.product, n.reason),
                    )?;
                }
            }
            report.delivery = Some(rec);
        }
        Err(e) => c.r.note(&format!(
            "delivery evidence for {} was not recorded ({}); the target holds what this \
             sync wrote, but opv delivery verify cannot vouch for it until a sync records it",
            placement(env_name, c.target),
            error_words(&e)
        )),
    }
    Ok(())
}

/// The first line of `e` in words (never a code slug, 01.19): the cause's message for a
/// cataloged error, else its text.
fn error_words(e: &Error) -> String {
    let text = match e.cause() {
        Some((c, _)) => c.message(),
        None => e.text().to_string(),
    };
    text.lines().next().unwrap_or_default().to_string()
}

/// One line of output.
fn p_line(out: &mut dyn Write, s: String) -> Result<(), Error> {
    writeln!(out, "{s}").map_err(write_err)
}

/// What `sync --deploy` prints on a target whose writes are live at once (FR-46).
pub(crate) fn live_line(label: &str) -> String {
    format!("nothing to deploy: {label} applies each write at once")
}

/// `pending deploy (pass --deploy): …`, the same words on every provider.
fn pending_line(names: &KeyNames, pending: &[String]) -> String {
    format!("pending deploy (pass --deploy): {}", names.join(pending))
}

/// `extra, not pruned (pass --prune to remove): …`, the same words on every provider (H5).
fn kept_line(names: &KeyNames, kept: &[String]) -> String {
    format!(
        "extra, not pruned (pass --prune to remove): {}",
        names.join(kept)
    )
}

/// The immutable keys this run leaves alone: present ones (`--rotate` replaces them) and
/// ones held back from a prune (`--prune-immutable` releases them).
fn print_held(
    out: &mut dyn Write,
    plan: &SyncPlan,
    names: &KeyNames,
    held: &[String],
) -> Result<(), Error> {
    let hint = KEY_REF_HINT;
    if !held.is_empty() {
        writeln!(
            out,
            "held (immutable), not rewritten (pass --rotate {hint} to replace): {}",
            names.join(held)
        )
        .map_err(write_err)?;
    }
    if !plan.held_from_prune.is_empty() {
        writeln!(
            out,
            "held (immutable), not pruned (pass --prune --prune-immutable {hint} to remove): {}",
            held_from_prune(plan)
        )
        .map_err(write_err)?;
    }
    Ok(())
}

/// [`prepare`] for a pinned target: the item, then (blocking rows refuse first, before any
/// call to the target) its state (NR-23, NR-25) and its listing.
fn prepare_pinned(c: &Ctx<'_>, ports: &Ports<'_>, out: &mut dyn Write) -> Result<Planned, Error> {
    let (fleet, env_name, opts) = (c.fleet, c.env_name, c.opts);
    let (fields, item_version) = read_item_fields(fleet, env_name, c.r)?;
    // Blocking rows refuse before any call to the target.
    let copy = fields.iter().map(copy_field).collect();
    let target = Some(c.target);
    refuse_blocking(
        &c.scoped(
            plan_item(
                fleet,
                env_name,
                target,
                copy,
                None,
                c.rotate,
                c.prune_immutable,
            )?
            .0,
        ),
        env_name,
    )
    .map_err(|e| c.refusal(e))?;
    // The target's state, read-only, before its first read (NR-23, NR-25).
    let skip_deploy = preflight::run(c.t, c.r, out, opts.json)?;
    let (plan, listed) = plan_item(
        fleet,
        env_name,
        target,
        fields,
        Some(ports),
        c.rotate,
        c.prune_immutable,
    )?;
    let plan = c.scoped(plan);
    refuse_blocking(&plan, env_name).map_err(|e| c.refusal(e))?;
    Ok(Planned {
        id: c.target_id(&plan, &listed, item_version, ports),
        prepared: Prepared::Pinned {
            plan,
            listed,
            skip_deploy,
        },
    })
}

/// A pinned target's plan, ready to apply.
struct Pinned {
    plan: SyncPlan,
    listed: Vec<StoreEntry>,
    /// Preflight's line to print instead of a deploy (nothing to restart).
    skip_deploy: Option<String>,
    /// The run's plan id (FR-41).
    plan_id: String,
}

/// `sync` for a pinned target (FR-29, FR-31, FR-32, FR-33; spec §6): compare and write new
/// store versions, read the runtime's bindings, and only with `--deploy` re-pin them in one
/// revision; prune only after that revision is healthy.
///
/// Every step is convergent (NR-1): a run stopped anywhere leaves at most unbound store
/// versions (never live) or a revision the platform finishes on its own, and the next run
/// computes what is left from what it reads. A binding never names a version that does not
/// exist: versions are written before they are pinned, and a store entry is deleted only
/// once a healthy revision no longer binds it.
fn run_pinned(
    c: &Ctx<'_>,
    store: &dyn PinnedStore,
    runtime: &dyn PinnedRuntime,
    pinned: Pinned,
    out: &mut dyn Write,
) -> Result<Report, Error> {
    let (fleet, env_name, opts) = (c.fleet, c.env_name, c.opts);
    let names = &c.names;
    let Pinned {
        plan,
        listed,
        skip_deploy,
        plan_id,
    } = pinned;
    // FR-42: what every write below records on the target. Never a value.
    let stamp = Stamp::now(env_name, &plan_id);
    let want = pinned_want(
        fleet,
        env_name,
        c.t,
        &plan,
        &listed,
        store,
        runtime.config_in_store(),
    )?;
    if !want.refused.is_empty() {
        let keys: Vec<&str> = want
            .refused
            .iter()
            .filter_map(|r| r.split(' ').next())
            .collect();
        return Err(c.refusal(blocked(&want.refused, &keys, false, env_name)));
    }
    c.require_confirm()?;
    print_extras(out, &plan)?;
    let p = |out: &mut dyn Write, s: String| writeln!(out, "{s}").map_err(write_err);
    let mut report = Report {
        skipped: skipped_names(c, &plan)?,
        held: held_names(c, &plan)?,
        plan_id,
        ..Report::default()
    };

    // 3. New store versions: not live until a revision binds them (FR-29).
    let mut written = BTreeMap::new();
    for (name, w) in &want.store {
        if let Some(value) = &w.write {
            let version = store.write_one(name, value, &stamp).map_err(|e| {
                let done: Vec<&str> = written.keys().map(String::as_str).collect();
                pinned_partial(c, e, &done, &[])
            })?;
            written.insert(name.clone(), version);
        }
    }
    report.written = written.keys().cloned().collect();
    report.unchanged = want
        .store
        .iter()
        .filter(|(_, w)| w.write.is_none())
        .map(|(n, _)| n.clone())
        .collect();
    print_changes(out, names, &report)?;
    // #106: each written name at the version its confirmed write returned; the others as
    // listed, compared exactly by the plan.
    {
        let confirmed: BTreeSet<String> = written.keys().cloned().collect();
        let identical: BTreeSet<String> = report.unchanged.iter().cloned().collect();
        let mut after: Vec<StoreEntry> = listed.clone();
        for (name, version) in &written {
            match after.iter_mut().find(|e| &e.name == name) {
                Some(e) => e.version = Some(version.clone()),
                None => after.push(StoreEntry {
                    name: name.clone(),
                    version: Some(version.clone()),
                    pending: false,
                    stamp: None,
                }),
            }
        }
        record_delivery(c, &confirmed, &identical, &after, &mut report, out)?;
    }

    // 4–5. What the runtime binds now, and what must change. Under `--product` another
    // product's bindings are never unbound (P20).
    let diff = |snap: &RuntimeSnapshot| {
        let mut d = pinned_diff(c.t, &want, &written, snap, &plan, opts.prune);
        d.not_desired.retain(|n| c.in_scope(n));
        d
    };
    let snap = runtime.bindings()?;
    let d = diff(&snap);
    if !d.drift.is_empty() {
        p(out, drift_line(env_name, &names.join(&d.drift)))?;
    }
    // Pruned like secrets: opv-managed names no longer desired, including config routed to
    // the store (the planner names only secrets).
    let mut prune_set = prune_names(fleet, c.t, &plan, &listed, &want)?;
    prune_set.retain(|n| c.in_scope(n));
    let stray: BTreeSet<&str> = d
        .not_desired
        .iter()
        .chain(&prune_set)
        .map(String::as_str)
        .collect();
    let stray: Vec<String> = stray.into_iter().map(str::to_string).collect();
    if !stray.is_empty() && !opts.prune {
        p(out, kept_line(names, &stray))?;
        report.kept = stray.clone();
    }
    if !stray.is_empty() && opts.prune && !opts.deploy {
        p(
            out,
            format!("not pruned without --deploy: {}", names.join(&stray)),
        )?;
        report.kept = stray.clone();
    }
    print_held(out, &plan, names, &report.held)?;

    // 6. Deploy only with --deploy (FR-7, FR-9).
    let mut change = d.change(c.t, &written);
    change.stamp = Some(stamp.clone());
    let pending = change_names(&change);
    let deletes: &[String] = if opts.prune && opts.deploy {
        &prune_set
    } else {
        &[]
    };
    let env_routed = |out: &mut dyn Write| {
        if want.plain.is_empty() {
            return Ok(());
        }
        p(
            out,
            format!(
                "env-routed (visible to readers of {}): {}",
                runtime.describe(),
                names.join(want.plain.keys())
            ),
        )
    };
    if !opts.deploy {
        if !pending.is_empty() {
            p(out, pending_line(names, &pending))?;
        }
        report.pending = pending;
        env_routed(out)?;
        return Ok(report);
    }
    if let Some(line) = skip_deploy.filter(|_| !pending.is_empty()) {
        p(out, line)?;
        report.pending = pending;
        report.deploy_skipped = true;
        env_routed(out)?;
        return Ok(report);
    }
    // A pruned key is both unbound and deleted: list it once.
    let unbinding: BTreeSet<&String> = change.unbind.iter().chain(deletes).collect();
    if !unbinding.is_empty() {
        p(out, format!("will prune: {}", names.join(unbinding)))?;
    }
    let revision = if !pending.is_empty() {
        let left = |now: &RuntimeSnapshot| change_names(&diff(now).change(c.t, &written));
        apply_reconciled(runtime, &change, &snap, &left, env_name, out)?
    } else if let Some(rev) = &snap.revision {
        // Nothing to change: confirm the revision of the current bindings is healthy, so a
        // run stopped before its health check, or a revision that failed, is never
        // reported as done, and deletes left by an earlier run wait for it (FR-32, NR-1).
        rev.clone()
    } else if deletes.is_empty() {
        env_routed(out)?;
        return Ok(report);
    } else {
        return Err(Error::Target(
            format!(
                "{} reports no revision, so nothing was pruned",
                runtime.describe()
            )
            .into(),
        )
        .with_do(format!(
            "deploy {} once so it has a revision",
            runtime.describe()
        ))
        .with_next(step_text(&c.opts.command(env_name))));
    };
    let health = runtime.await_healthy(&revision)?;
    if pending.is_empty() && !matches!(health, Health::Healthy) {
        // Nothing was applied: say so, so a failure is not read as caused by this run.
        let state = match &health {
            Health::TimedOut => "not healthy yet".to_string(),
            Health::Unhealthy(detail) => format!("unhealthy\n  {detail}"),
            Health::Healthy => unreachable!(),
        };
        return Err(Error::Target(
            format!(
                "nothing to change; the latest revision {} (with these settings) is {state}; \
                 opv changed nothing",
                revision.0
            )
            .into(),
        )
        .with_code(Code::TargetUnhealthy)
        .with_do(format!(
            "{} shows its state; fix the revision",
            runtime.inspect_hint(&revision)
        ))
        .with_next(format!("opv doctor --env {env_name}")));
    }
    match health {
        Health::Healthy => {}
        Health::Unhealthy(detail) => {
            return Err(Error::Target(
                format!("{detail}\n  the previous revision keeps serving; nothing pruned").into(),
            )
            .with_code(Code::TargetUnhealthy)
            .with_do(format!(
                "fix why {} cannot start the new revision (opv doctor checks that it can read \
                 its secrets)",
                runtime.describe()
            ))
            .with_next(format!("opv doctor --env {env_name}")));
        }
        Health::TimedOut => {
            return Err(Error::Target(
                format!(
                    "revision {} of {} is not healthy yet; the previous revision keeps \
                     serving; nothing pruned",
                    revision.0,
                    runtime.describe()
                )
                .into(),
            )
            .with_code(Code::TargetUnhealthy)
            .with_do(format!(
                "{} shows its state; wait until it is healthy",
                runtime.inspect_hint(&revision)
            )));
        }
    }
    if !pending.is_empty() {
        p(
            out,
            format!("deployed revision {}: {}", revision.0, names.join(&pending)),
        )?;
        report.deployed = Some(revision.0.clone());
        report.deployed_names = pending.clone();
        // A store version written earlier and not yet bound; env-routed config and this
        // run's writes are changes of this run.
        report.earlier = pending
            .iter()
            .filter(|n| want.store.contains_key(*n) && !written.contains_key(*n))
            .cloned()
            .collect();
    }
    // Superseded versions (FR-32) of every name the healthy revision pins, not only those
    // re-pinned now, so a run stopped before this step is finished by the next (NR-1). A
    // no-op where the store keeps history.
    let mut bound: BTreeMap<&str, &str> = snap
        .bindings
        .iter()
        .filter_map(|(n, b)| match b {
            Binding::Pinned { version, .. } => Some((n.as_str(), version.as_str())),
            _ => None,
        })
        .collect();
    bound.extend(
        change
            .pin
            .iter()
            .map(|(n, (_, v))| (n.as_str(), v.as_str())),
    );
    // The deploy already succeeded: a collection that fails is a warning naming the fix,
    // never the run's result; the next healthy deploy collects again (FR-32, NR-1).
    for name in want.store.keys() {
        if let Some(version) = bound.get(name.as_str())
            && let Err(e) = store.collect_superseded(name, version)
        {
            let line = format!(
                "warning: superseded versions of {} were not removed: {}; the next healthy \
                 deploy removes them",
                names.join([name]),
                error_words(&e).replace('\n', "\n  ")
            );
            if opts.json {
                c.r.note(&line);
            } else {
                p(out, line)?;
            }
        }
    }
    let mut pruned: Vec<String> = change.unbind.clone();
    if !deletes.is_empty() {
        // Nothing in the runtime may still point at an entry deleted below (FR-32).
        runtime.release(deletes).map_err(|e| match e {
            e @ Error::Catalog(..) => pinned_partial(c, e, &report_written(&report), &[]),
            e => with_note(e, "nothing pruned"),
        })?;
    }
    let mut unbound_kept = Vec::new();
    for name in deletes {
        let gone = store.delete(name).map_err(|e| {
            let done: Vec<&str> = pruned.iter().map(String::as_str).collect();
            match e {
                e @ Error::Catalog(..) => pinned_partial(c, e, &report_written(&report), &done),
                e => with_note(e, &format!("already pruned: {}", none_or(&done))),
            }
        })?;
        if !gone {
            // Kept for rollback by an older revision: unbound, not pruned (FR-32).
            pruned.retain(|n| n != name);
            unbound_kept.push(name.clone());
        } else if !pruned.contains(name) {
            pruned.push(name.clone());
        }
    }
    if !pruned.is_empty() {
        p(out, format!("pruned: {}", names.join(&pruned)))?;
    }
    if !unbound_kept.is_empty() {
        p(
            out,
            format!(
                "unbound, kept for rollback while an older revision references them: {}",
                names.join(&unbound_kept)
            ),
        )?;
    }
    report.pruned = pruned;
    env_routed(out)?;
    Ok(report)
}

/// The drift line (status and sync): a binding older than the store's current version
/// is either a hand re-pin or a sync that ran without `--deploy`; opv cannot tell which.
pub(crate) fn drift_line(env_name: &str, names: &str) -> String {
    format!(
        "drift: {names} point to an older secret version than the store's latest (re-pinned \
         by hand, or synced without --deploy); opv sync {env_name} --deploy repins them"
    )
}

/// Store names to prune: the plan's secrets plus managed config entries (config routed to
/// the store) whose key is no longer desired here. Only entries the store lists as
/// opv-managed for this environment; immutable keys are held as for secrets.
fn prune_names(
    fleet: &Fleet,
    t: &dyn TargetConfig,
    plan: &SyncPlan,
    listed: &[StoreEntry],
    want: &PinnedWant,
) -> Result<Vec<String>, Error> {
    let mut names = plan.prune.clone();
    for (product, p) in &fleet.products {
        for (key, spec) in &p.keys {
            let desired = plan
                .config
                .get(product)
                .is_some_and(|k| k.contains_key(key));
            let name = t.env_name(product, key);
            if spec.kind == Kind::Config
                && !spec.immutable
                && !desired
                && !want.store.contains_key(&name)
                && listed.iter().any(|e| e.name == name)
                && !names.contains(&name)
            {
                names.push(name);
            }
        }
    }
    Ok(names)
}

/// Applies `change`. An apply whose outcome is unknown (NR-2) is reconciled by reading the
/// bindings back (inside the diagnosis, so the failed apply's excerpt stays, NR-31): when
/// they show the change, the run goes on with the revision they name; otherwise the error
/// stays `Unknown` (exit 9) and says what the read showed. A refused apply (a target
/// error: nothing applied) names `opv doctor` as its next step. `left` names what a
/// snapshot still lacks of the change.
fn apply_reconciled(
    runtime: &dyn PinnedRuntime,
    change: &RuntimeChange,
    snap: &RuntimeSnapshot,
    left: &dyn Fn(&RuntimeSnapshot) -> Vec<String>,
    env_name: &str,
    out: &mut dyn Write,
) -> Result<Revision, Error> {
    // An outcome-unknown apply (exit 9, cataloged or not) is read back; a refused one
    // (nothing applied) keeps its own step.
    let unknown = match runtime.apply(change, snap) {
        Err(e) if e.exit_code() == 9 => e,
        Err(e) if e.code_str() == Code::UpdateRefused.as_str() => {
            return Err(e.or_next(|| format!("opv doctor --env {env_name}")));
        }
        other => return other,
    };
    let still_unknown =
        |why: &str| with_note(unknown, &format!("read back: {why}; nothing pruned"));
    let Ok(now) = crate::runner::diagnosing(|| runtime.bindings()) else {
        return Err(still_unknown("could not read the bindings back"));
    };
    match (&now.revision, left(&now).is_empty()) {
        (Some(rev), true) => {
            writeln!(
                out,
                "the update was applied (read back from {})",
                runtime.describe()
            )
            .map_err(write_err)?;
            Ok(rev.clone())
        }
        _ => Err(still_unknown(&format!(
            "{} does not show the change",
            runtime.describe()
        ))),
    }
}

/// What a pinned target should hold for the desired rows of a plan (FR-14, FR-29).
pub(crate) struct PinnedWant {
    /// Store-routed env name (secrets; config when routed to the store) → its store state.
    pub store: BTreeMap<String, StoreWant>,
    /// Env-routed config: env name → value. Config only, never a secret (FR-14).
    pub plain: BTreeMap<String, String>,
    /// `product/KEY (failed <rule> (<reason>))` for config values the store refuses.
    pub refused: Vec<String>,
}

/// One store-routed name: the store's version before this run, and the value to write when
/// the store does not hold the desired one.
pub(crate) struct StoreWant {
    pub current: Option<String>,
    pub write: Option<SecretValue>,
}

/// Bindings to change on a pinned target, and what is reported beside them.
pub(crate) struct PinnedDiff {
    /// env name → version to bind (`None`: written by the next sync, not known yet).
    pub pin: BTreeMap<String, Option<String>>,
    /// Env-routed config whose plain value differs or is missing: env name → value.
    pub set: BTreeMap<String, String>,
    /// Bound managed names no longer desired here (and not held immutable).
    pub not_desired: Vec<String>,
    /// Bound to a store version other than the store's current one.
    pub drift: BTreeSet<String>,
    unbind: bool,
}

impl PinnedDiff {
    /// The runtime change; every pinned version must be known (written or current).
    fn change(&self, t: &dyn TargetConfig, written: &BTreeMap<String, String>) -> RuntimeChange {
        RuntimeChange {
            pin: self
                .pin
                .iter()
                .filter_map(|(n, v)| {
                    let v = v.as_ref().or_else(|| written.get(n))?;
                    Some((n.clone(), (t.store_name(n), v.clone())))
                })
                .collect(),
            set: self.set.clone(),
            unbind: if self.unbind {
                self.not_desired.clone()
            } else {
                Vec::new()
            },
            stamp: None,
        }
    }

    /// Names whose binding changes on the next `--deploy`.
    pub fn pending(&self) -> BTreeSet<&str> {
        self.pin
            .keys()
            .chain(self.set.keys())
            .map(String::as_str)
            .collect()
    }
}

/// Names a change touches, sorted.
fn change_names(c: &RuntimeChange) -> Vec<String> {
    let names: BTreeSet<&String> = c.pin.keys().chain(c.set.keys()).chain(&c.unbind).collect();
    names.into_iter().cloned().collect()
}

/// The desired store and env state of `plan` (FR-14, FR-31). Secrets are always
/// store-routed; config is store-routed when `config_in_store`, and then read and compared
/// like a secret. `listed` carries the versions the plan's reads found.
#[allow(clippy::too_many_arguments)]
pub(crate) fn pinned_want(
    fleet: &Fleet,
    env_name: &str,
    t: &dyn TargetConfig,
    plan: &SyncPlan,
    listed: &[StoreEntry],
    store: &dyn PinnedStore,
    config_in_store: bool,
) -> Result<PinnedWant, Error> {
    fleet.environment(env_name)?;
    let name_of = |p: &str, k: &str| t.env_name(p, k);
    let version = |n: &str| {
        listed
            .iter()
            .find(|e| e.name == n)
            .and_then(|e| e.version.clone())
    };
    let staged: BTreeMap<&str, &SecretValue> =
        plan.stage.iter().map(|(n, v)| (n.as_str(), v)).collect();
    let mut want = PinnedWant {
        store: BTreeMap::new(),
        plain: BTreeMap::new(),
        refused: Vec::new(),
    };
    for row in plan
        .rows
        .iter()
        .filter(|r| r.kind == Kind::Secret && r.state == KeyState::Ready)
    {
        let name = name_of(&row.product, &row.key);
        let write = staged
            .get(name.as_str())
            .map(|v| SecretValue::new(v.expose().to_string()));
        let mut current = version(&name);
        // Present but never read (cannot happen today): read it once for its version.
        if write.is_none() && current.is_none() {
            current = store.read(&name)?.map(|(_, v)| v);
        }
        want.store.insert(name, StoreWant { current, write });
    }
    for (product, keys) in &plan.config {
        for (key, value) in keys {
            let name = name_of(product, key);
            if !config_in_store {
                want.plain.insert(name, value.clone());
                continue;
            }
            let desired = SecretValue::new(value.clone());
            if let Some((rule, why)) = store.refusal(&name, &desired) {
                want.refused.push(format!(
                    "{} (failed {rule} ({why}))",
                    key_label(product, key)
                ));
                continue;
            }
            let (current, same) = match store.read(&name)? {
                Some((v, version)) => (Some(version), compare(&v, &desired) == Same),
                None => (None, false),
            };
            let write = (!same).then_some(desired);
            want.store.insert(name, StoreWant { current, write });
        }
    }
    Ok(want)
}

/// Compares `want` (with this run's `written` versions) to the runtime's bindings.
pub(crate) fn pinned_diff(
    t: &dyn TargetConfig,
    want: &PinnedWant,
    written: &BTreeMap<String, String>,
    snap: &RuntimeSnapshot,
    plan: &SyncPlan,
    unbind: bool,
) -> PinnedDiff {
    let mut d = PinnedDiff {
        pin: BTreeMap::new(),
        set: BTreeMap::new(),
        not_desired: Vec::new(),
        drift: BTreeSet::new(),
        unbind,
    };
    for (name, w) in &want.store {
        // A value still to write (status) has no version to bind yet.
        let target = if w.write.is_some() {
            written.get(name)
        } else {
            w.current.as_ref()
        };
        let bound = snap.bindings.get(name);
        let current = match (bound, target) {
            (
                Some(Binding::Pinned {
                    store_name,
                    version,
                }),
                Some(v),
            ) => store_name.eq_ignore_ascii_case(&t.store_name(name)) && version == v,
            _ => false,
        };
        if let (Some(Binding::Pinned { version, .. }), Some(now)) = (bound, &w.current)
            && version != now
        {
            d.drift.insert(name.clone());
        }
        if !current {
            d.pin.insert(name.clone(), target.cloned());
        }
    }
    for (name, value) in &want.plain {
        let digest = hex::encode(Sha256::digest(value.as_bytes()));
        if !matches!(snap.bindings.get(name), Some(Binding::Plain { digest: d }) if *d == digest) {
            d.set.insert(name.clone(), value.clone());
        }
    }
    let held: BTreeSet<&str> = plan
        .held_from_prune
        .iter()
        .map(|(_, _, n)| n.as_str())
        .collect();
    d.not_desired = snap
        .bindings
        .keys()
        .filter(|n| {
            !want.store.contains_key(*n)
                && !want.plain.contains_key(*n)
                && !held.contains(n.as_str())
        })
        .cloned()
        .collect();
    d
}

/// An item field with its value copied into a new zeroizing wrapper.
fn copy_field(f: &ItemField) -> ItemField {
    ItemField {
        section: f.section.clone(),
        label: f.label.clone(),
        kind: f.kind,
        value: SecretValue::new(f.value.expose().to_string()),
        concealed: f.concealed,
    }
}

/// `err` with `note` (names only) on a line of its own, same category and next step.
fn with_note(err: Error, note: &str) -> Error {
    match err {
        e @ Error::Findings(..) => e,
        e => e.map_text(|m| format!("{m}\n  {note}")),
    }
}

/// A failure on pinned target `c` after this run wrote the store versions `written` and
/// pruned `pruned` (R53, X20): a cataloged cause becomes [`Cause::Partial`] naming them; a
/// Legacy error gets the names on a line of its own.
fn pinned_partial(c: &Ctx<'_>, e: Error, written: &[&str], pruned: &[&str]) -> Error {
    match e {
        e @ Error::Catalog(..) => {
            let done: Vec<String> = written
                .iter()
                .map(|n| format!("{n} (a new version)"))
                .chain(pruned.iter().map(|n| format!("{n} (pruned)")))
                .collect();
            partial(e, &done, c.opts.scope(c.env_name))
        }
        e => with_note(e, &already_written(written)),
    }
}

/// The store names `report` wrote, for [`pinned_partial`].
fn report_written(report: &Report) -> Vec<&str> {
    report.written.iter().map(String::as_str).collect()
}

fn already_written(done: &[&str]) -> String {
    format!(
        "already written (new versions, not live until a deploy binds them): {}",
        none_or(done)
    )
}

fn none_or(names: &[&str]) -> String {
    if names.is_empty() {
        "none".into()
    } else {
        names.join(", ")
    }
}

/// Refuses the whole run, before any write, when a row blocks (FR-15), naming the next
/// command (NR-17): the first value to fill, opened in 1Password (R63), never a sync.
fn refuse_blocking(plan: &SyncPlan, env_name: &str) -> Result<(), Error> {
    let blocking = row_names(&plan.rows, is_blocking);
    let keys: Vec<String> = plan
        .rows
        .iter()
        .filter(|r| is_blocking(r))
        .map(|r| key_label(&r.product, &r.key))
        .collect();
    if keys.is_empty() {
        return Ok(());
    }
    // 1Password shows an empty field only in edit mode (as for `findings_error`).
    let empty = plan.rows.iter().any(|r| {
        matches!(
            r.state,
            KeyState::Missing | KeyState::RuleFailed("nonempty", _)
        )
    });
    let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
    Err(blocked(&blocking, &keys, empty, env_name))
}

/// The refusal of a sync whose values `blocking` need a person (keys_blocking, exit 6;
/// the catalog's `ValuesNeeded` has no exit-6 form yet). "nothing was changed" holds on
/// every target kind, staged or not (01.14).
fn blocked(blocking: &[String], keys: &[&str], empty: bool, env_name: &str) -> Error {
    let mut open = Cmd {
        command: vec!["open".into()],
        args: vec![
            keys.first().copied().unwrap_or_default().to_string(),
            "--env".into(),
            env_name.to_string(),
        ],
    };
    open.args.extend(config_flag());
    let mut action = format!("fix {} in 1Password", keys.join(", "));
    if empty {
        action.push_str(" (click Edit on the item: it hides empty fields until then)");
    }
    Error::Policy(format!("sync refused, nothing was changed: {}", blocking.join(", ")).into())
        .with_code(Code::KeysBlocking)
        .with_do(action)
        .with_next(step_text(&open))
}

/// Longest wait for staged names to show a digest (NR-30).
const CONFIRM_LIMIT: Duration = Duration::from_secs(30);

/// List B (NR-30): the store's list right after staging can lag. Polls, waiting 1 s, 2 s,
/// 4 s, ... on the runner's clock, until every staged name shows a digest or
/// [`CONFIRM_LIMIT`] has passed; a name still without one is then counted as changed,
/// never as unchanged. A read that never answers is reported with what was already done.
fn confirm(
    store: &dyn StagedStore,
    batch: &[(String, &SecretValue)],
    c: &Ctx<'_>,
    done: &[String],
) -> Result<Vec<StoreEntry>, Error> {
    let (r, label) = (c.r, c.t.provider().label());
    let wait = crate::runner::Wait::new(r, CONFIRM_LIMIT);
    let mut delay = Duration::from_secs(1);
    loop {
        let list = store.list().map_err(|e| match e {
            e @ Error::Unknown(_) => with_note(
                e,
                &format!(
                    "{label} did not respond while confirming the staged secrets ({}); not \
                     confirmed",
                    done.join(", ")
                ),
            ),
            e => after_writes_in(c, e, done),
        })?;
        let unseen = batch
            .iter()
            .filter(|(n, _)| digest(&list, n).is_none())
            .count();
        let waited = wait.elapsed(r);
        if unseen == 0 || waited >= CONFIRM_LIMIT {
            return Ok(list);
        }
        let d = delay.min(CONFIRM_LIMIT - waited);
        // No room left in the run budget for another list: count the unseen as changed.
        if wait.over(r, d) {
            return Ok(list);
        }
        wait.pause(
            r,
            d,
            &format!(
                "confirming {unseen} staged secret(s) on {label} ({} s)",
                waited.as_secs()
            ),
        );
        delay *= 2;
    }
}

/// [`after_writes`] on target `c`: a cataloged cause becomes [`Cause::Partial`] naming what
/// had completed, whose Next reads what remains in the run's scope (R53, 01.07).
fn after_writes_in(c: &Ctx<'_>, e: Error, done: &[String]) -> Error {
    match e {
        e @ Error::Catalog(..) => partial(e, done, c.opts.scope(c.env_name)),
        e => after_writes(e, done),
    }
}

/// NR-10: a sign-in lost after this run's first write names what had completed. Other
/// errors already say what is known (NR-2).
fn after_writes(e: Error, done: &[String]) -> Error {
    match e {
        // A cataloged cause names the completed writes as its `Partial` (design §4.6).
        Error::Catalog(c, up) if !done.is_empty() => {
            let cause = Cause::Partial {
                done: done.to_vec(),
                approval_used: None,
                approval_scope: None,
                then: c,
            };
            match up {
                Some(up) => Error::with_evidence(cause, *up),
                None => cause.into(),
            }
        }
        e @ Error::Auth(_) if !done.is_empty() => e.map_text(|m| {
            format!(
                "{m}\n  {} write(s) had completed: {}; re-running the same command is safe",
                done.len(),
                done.join(", ")
            )
        }),
        // A refusal after staging: what is already staged stays staged (and is not live).
        e @ Error::Target(_) if !done.is_empty() => e.map_text(|m| {
            format!(
                "{m}\n  {} write(s) had completed before it: {}",
                done.len(),
                done.join(", ")
            )
        }),
        e => e,
    }
}

/// The per-key change lists, `product/KEY (NAME)` (P19).
fn print_changes(out: &mut dyn Write, names: &KeyNames, report: &Report) -> Result<(), Error> {
    if !report.written.is_empty() {
        writeln!(out, "written: {}", names.join(&report.written)).map_err(write_err)?;
    }
    if !report.unchanged.is_empty() {
        writeln!(out, "unchanged: {}", names.join(&report.unchanged)).map_err(write_err)?;
    }
    Ok(())
}

/// `plan <env>`: rows, prune list and counts; no mutation. Exits `Findings(n)` when
/// n rows would block a sync.
pub fn plan(
    fleet: &Fleet,
    env_name: &str,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    plan_with(fleet, env_name, r, out, false)
}

/// `plan <env> [--json]` for every product.
pub fn plan_with(
    fleet: &Fleet,
    env_name: &str,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
    json: bool,
) -> Result<(), Error> {
    plan_scoped(fleet, env_name, None, r, out, json)
}

/// `plan <env> [--product p] [--json]` (P11, P12). Text: a one-line count summary first
/// (NR-16), the rows, then what a sync would do by name (`would write`/`would stage`,
/// `would prune (needs --prune)`, `held (immutable)`), and last the exact sync command. With
/// `json`, stdout carries one FR-21 document and nothing else. `product` limits rows,
/// totals and findings to one product. Exit codes are unchanged (`Findings` for blocking
/// rows).
pub fn plan_scoped(
    fleet: &Fleet,
    env_name: &str,
    product: Option<&str>,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
    json: bool,
) -> Result<(), Error> {
    plan_targeted(fleet, env_name, &[], product, r, out, json)
}

/// [`plan_scoped`] on every target of the environment, or the targets `--target` names
/// (FR-56, [`resolve_targets`]), in name order, under one plan id that covers exactly the
/// targets planned (FR-41, [`run_plan_id`]). Text: one count line per target, one table
/// whose rows name their target, each target's `would …` lines prefixed `<env>/<target>: `,
/// then the plan id and the sync that applies it.
pub fn plan_targeted(
    fleet: &Fleet,
    env_name: &str,
    targets: &[String],
    product: Option<&str>,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
    json: bool,
) -> Result<(), Error> {
    plan_rotating(fleet, env_name, targets, product, &[], r, out, json)
}

/// [`plan_targeted`] with `--rotate PRODUCT/KEY` entries (FR-16, repeatable): those immutable
/// keys are planned as replaced even though present. The rotate set is part of the plan id,
/// so a plan with rotation never shares an id with one without; validation is exactly
/// [`parse_rotate`], which `sync --rotate` uses too.
#[allow(clippy::too_many_arguments)]
pub fn plan_rotating(
    fleet: &Fleet,
    env_name: &str,
    targets: &[String],
    product: Option<&str>,
    rotate: &[String],
    r: &dyn CommandRunner,
    out: &mut dyn Write,
    json: bool,
) -> Result<(), Error> {
    check_names(fleet, env_name, targets, product)?;
    check_product(fleet, product, "plan", Some(env_name))?;
    let parsed = parse_rotate(fleet, env_name, rotate)?;
    // Needs a target: `Error::Config` naming the environment otherwise, before any call.
    let names = resolve_targets(fleet, env_name, targets, "plan")?;
    let runners = target_runners(fleet, env_name, &names, r)?;
    let mut parts = Vec::new();
    for (name, signed) in names.iter().zip(&runners) {
        let r: &dyn CommandRunner = match signed {
            Some(s) => s,
            None => r,
        };
        parts.push(plan_part(fleet, env_name, name, product, &parsed, r)?);
    }
    let n: usize = parts.iter().map(|p| p.findings()).sum();
    // FR-41: what `sync --expect-plan` re-derives; names and version ids only.
    let id = run_plan_id(parts.iter().map(|p| (p.name.as_str(), p.id.as_str())));
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
    let findings = || findings_error(n, &all, env_name);
    // A clean plan is applied by its id (M13); `--expect-plan` also stands for a guarded
    // environment's `--confirm`. A plan with findings has no sync step at all: its step is
    // the error's, opening the first value to fill (01.05), and opv never confirms (X4).
    let clean = n == 0;
    let sync_next = step_text(
        &SyncOpts {
            // A live target has nothing to deploy (FR-46).
            deploy: parts.iter().any(|p| !p.live),
            prune: parts
                .iter()
                .any(|p| !p.plan.prune.is_empty() || !p.var_plan.prune.is_empty()),
            product: product.map(str::to_string),
            expect_plan: clean.then(|| id.clone()),
            receipt: None,
            targets: targets.to_vec(),
            // The canonical (sorted, deduped) rotate set, so the Next command is stable.
            rotate: parsed.iter().map(|(p, k)| key_label(p, k)).collect(),
            ..SyncOpts::default()
        }
        .command(env_name),
    );
    let counts: Vec<String> = parts.iter().map(|p| p.count(env_name)).collect();
    for (p, count) in parts.iter().zip(&counts) {
        let heading = match product {
            Some(pr) => format!("opv plan {env_name} --target {} --product {pr}", p.name),
            None => format!("opv plan {env_name} --target {}", p.name),
        };
        r.step_summary(&ci_summary::table(
            &heading,
            count,
            Some(plan_changes(&p.plan)),
            &p.name,
            &p.plan.rows,
            |row| p.word(row),
        ));
    }
    if json {
        let doc: Vec<JsonPart<'_>> = parts
            .iter()
            .map(|p| JsonPart {
                target: &p.name,
                plan: &p.plan,
                pinned: None,
                rotate: Some(&p.rotate),
            })
            .collect();
        write_json(
            out,
            fleet,
            env_name,
            &doc,
            product,
            &super::JsonExtra {
                plan_id: clean.then_some(id.as_str()),
                provenance: None,
                next: clean.then_some(sync_next.as_str()),
                link: link.as_deref(),
            },
        )?;
        return if n > 0 { Err(findings()) } else { Ok(()) };
    }
    for count in &counts {
        writeln!(out, "{count}").map_err(write_err)?;
    }
    let rows: Vec<(&str, &Row)> = parts
        .iter()
        .flat_map(|p| p.plan.rows.iter().map(move |r| (p.name.as_str(), r)))
        .collect();
    let by_name: BTreeMap<&str, &PlanPart<'_>> =
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
    for p in &parts {
        let mut out = Prefixed::new(out, format!("{}: ", placement(env_name, &p.name)));
        p.print_changes(&mut out, fleet, env_name, n > 0)?;
    }
    if n > 0 {
        return Err(findings());
    }
    let item_version = parts.last().and_then(|p| p.item_version);
    writeln!(
        out,
        "{}",
        plan_id_line(&id, item_version, fleet.origin.noun())
    )
    .map_err(write_err)?;
    write!(out, "{}", next_line(&sync_next)).map_err(write_err)
}

/// What `plan` planned for one target (FR-56).
struct PlanPart<'f> {
    name: String,
    t: &'f dyn TargetConfig,
    plan: SyncPlan,
    item_version: Option<u64>,
    /// The target applies writes at once (FR-46).
    live: bool,
    /// The config channel (FR-46): what sync would set and prune.
    var_plan: super::variables::VarPlan,
    /// `stage` on a staging target, else `write`.
    verb: &'static str,
    /// This target's plan id (FR-41), one input of the run's.
    id: String,
    /// Names on the target opv does not manage (FR-5, never touched).
    unmanaged: usize,
    /// The canonical `--rotate` set this part was planned with (FR-16).
    rotate: BTreeSet<(String, String)>,
}

impl PlanPart<'_> {
    fn findings(&self) -> usize {
        self.plan.rows.iter().filter(|r| is_blocking(r)).count()
    }

    /// The row's ON TARGET word: `rotate` for a `--rotate`d key, else [`target_word`].
    fn word(&self, row: &Row) -> String {
        if super::rotated(&self.rotate, row) {
            return "rotate".to_string();
        }
        let held = self
            .plan
            .held_immutable
            .iter()
            .any(|(p, k)| *p == row.product && *k == row.key);
        target_word(row, held, None).to_string()
    }

    /// `prod/web: 4 keys · 0 findings · 1 to stage · …` (NR-16).
    fn count(&self, env_name: &str) -> String {
        format!(
            "{}: {} · {} · {} to {} · {} held (immutable) · {} to prune · {} unmanaged \
             on {} (never touched)",
            placement(env_name, &self.name),
            plural(self.plan.rows.len(), "key", "keys"),
            plural(self.findings(), "finding", "findings"),
            self.plan.stage.len() + self.var_plan.set.len(),
            self.verb,
            self.plan.held_immutable.len(),
            self.plan.prune.len() + self.var_plan.prune.len(),
            self.unmanaged,
            self.t.provider().label(),
        )
    }

    /// What a sync would do on this target, by name: `would stage`, `would prune`, `held`.
    fn print_changes(
        &self,
        out: &mut dyn Write,
        fleet: &Fleet,
        env_name: &str,
        blocked: bool,
    ) -> Result<(), Error> {
        let (plan, verb) = (&self.plan, self.verb);
        let names = KeyNames::new(fleet, env_name, &self.name)?;
        let mut line = |s: String| writeln!(out, "{s}").map_err(write_err);
        let staged: Vec<&str> = plan
            .stage
            .iter()
            .map(|(n, _)| n.as_str())
            .chain(self.var_plan.set.iter().map(String::as_str))
            .collect();
        if !staged.is_empty() {
            // Findings block the sync, so nothing is staged until they are fixed (bug 10).
            let when = if blocked {
                " once the findings are fixed"
            } else {
                ""
            };
            line(format!("would {verb}{when}: {}", names.join(&staged)))?;
        }
        let prunes: Vec<String> = plan
            .prune
            .iter()
            .chain(&self.var_plan.prune)
            .cloned()
            .collect();
        if !prunes.is_empty() {
            line(format!(
                "would prune (needs --prune): {}",
                names.join(&prunes)
            ))?;
        }
        let hint = KEY_REF_HINT;
        let held_names: Vec<String> = plan
            .held_immutable
            .iter()
            .map(|(p, k)| self.t.env_name(p, k))
            .collect();
        if !held_names.is_empty() {
            line(format!(
                "held (immutable): {} (pass --rotate {hint} to replace)",
                names.join(&held_names)
            ))?;
        }
        if !plan.held_from_prune.is_empty() {
            line(format!(
                "held (immutable), not pruned (needs --prune --prune-immutable {hint}): {}",
                held_from_prune(plan)
            ))?;
        }
        Ok(())
    }
}

/// Plan target `name` of `env_name` (FR-56): its state (read-only, never waiting, NR-23,
/// NR-25), the item and the store listing through its own ports, and its plan id.
fn plan_part<'f>(
    fleet: &'f Fleet,
    env_name: &str,
    name: &str,
    product: Option<&str>,
    rotate: &BTreeSet<(String, String)>,
    r: &dyn CommandRunner,
) -> Result<PlanPart<'f>, Error> {
    let (_, t) = super::target(fleet, env_name, name)?;
    let (_, ports) = open_target(fleet, env_name, name, r)?;
    preflight::read(t, r)?;
    let none = BTreeSet::new();
    let (mut plan, on_target, item_version) =
        read_and_plan_versioned(fleet, env_name, Some(name), r, Some(&ports), rotate, &none)?;
    let scope = match product {
        Some(p) => {
            let names = product_names(fleet, env_name, name, p)?;
            scope_plan(&mut plan, p, &names);
            Some(names)
        }
        None => None,
    };
    // The config channel (FR-46): state of each config row, and what sync would set/prune.
    let (live, var_plan) = match &ports {
        Ports::Staged { store, runtime } => {
            let vp = match store.variables() {
                Some(v) => Some(super::variables::plan(
                    fleet,
                    env_name,
                    name,
                    t,
                    &mut plan,
                    v,
                    &|n| scope.as_ref().is_none_or(|s| s.contains(n)),
                )?),
                None => None,
            };
            (runtime.live(), vp.unwrap_or_default())
        }
        Ports::Pinned { .. } => (false, super::variables::VarPlan::default()),
    };
    let id = plan_id_of(
        fleet,
        env_name,
        name,
        product,
        item_version,
        &plan,
        &on_target,
        &ports,
        rotate,
        None,
    );
    let verb = match ports {
        Ports::Staged { .. } if !live => "stage",
        _ => "write",
    };
    Ok(PlanPart {
        name: name.to_string(),
        t,
        unmanaged: unmanaged_on_target(fleet, env_name, name, &on_target)?.len(),
        plan,
        item_version,
        live,
        var_plan,
        verb,
        id,
        rotate: rotate.clone(),
    })
}

/// `plan <id> (1Password item v<n>): sync --expect-plan <id> applies exactly this plan`
/// (FR-41).
fn plan_id_line(id: &str, item_version: Option<u64>, config: &str) -> String {
    let item = item_version
        .map(|v| format!("1Password item v{v}"))
        .unwrap_or_else(|| "1Password item".into());
    format!(
        "plan {id} ({item}): sync --expect-plan {id} applies exactly this plan and refuses \
         if the item, the target or {config} changed"
    )
}

/// `changes` for the step summary (H8), as the JSON's: `some` when a staged key is new or
/// certainly changed or a name would be pruned, `unknown` when only keys whose values the
/// target hides would be staged, `none` otherwise.
fn plan_changes(plan: &SyncPlan) -> &'static str {
    let staged = |r: &Row| r.state == KeyState::Ready && r.kind == Kind::Secret;
    let certain = plan
        .rows
        .iter()
        .filter(|r| staged(r))
        .any(|r| matches!(r.target, TargetState::Absent | TargetState::WouldChange))
        || !plan.prune.is_empty();
    if certain {
        "some"
    } else if plan.stage.is_empty() {
        "none"
    } else {
        "unknown"
    }
}

/// `product/KEY (TARGET_NAME)` for every
/// immutable key held back from pruning.
fn held_from_prune(plan: &SyncPlan) -> String {
    plan.held_from_prune
        .iter()
        .map(|(p, k, n)| format!("{} ({n})", key_label(p, k)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn digest<'a>(list: &'a [StoreEntry], name: &str) -> Option<&'a str> {
    list.iter()
        .find(|s| s.name == name)
        .and_then(|s| s.version.as_deref())
}

/// `PRODUCT/KEY`. `None` when the entry has the wrong shape.
fn split_key_ref(entry: &str) -> Option<(&str, &str)> {
    entry
        .split_once('/')
        .filter(|(p, k)| !p.is_empty() && !k.is_empty())
}

/// Every declared key as `--rotate` takes it: `product/KEY`.
fn declared_refs(fleet: &Fleet) -> Vec<String> {
    fleet
        .products
        .iter()
        .flat_map(|(p, spec)| spec.keys.keys().map(move |k| key_label(p, k)))
        .collect()
}

/// The argument placeholder for `--prune-immutable` in hints.
const KEY_REF_HINT: &str = "PRODUCT/KEY";

/// A `--rotate` / `--prune-immutable` entry that is not `PRODUCT/KEY` (R26).
fn key_ref_format(flag: &str) -> Error {
    Cause::Usage {
        problem: UsageProblem::ValueFormat {
            flag: flag.to_string(),
            format: KEY_REF_HINT,
        },
    }
    .into()
}

/// A `--rotate` / `--prune-immutable` entry that names a declared key the flag cannot take,
/// named with why; its step explains that key, a read (the catalog's `Usage` has no form
/// that names the entry yet).
fn key_ref_refused(flag: &str, entry: &str, why: &str, env_name: &str) -> Error {
    let mut explain = Cmd {
        command: vec!["explain".into()],
        args: vec![entry.to_string(), "--env".into(), env_name.to_string()],
    };
    explain.args.extend(config_flag());
    Error::Config(format!("{flag} {entry:?}: {why}").into()).with_next(step_text(&explain))
}

/// The declared key a `--rotate` / `--prune-immutable` entry names (R21: an undeclared one
/// is [`not_declared`], whose step substitutes only a unique close match, in a read).
fn declared_key<'f>(
    fleet: &'f Fleet,
    flag: &str,
    entry: &str,
) -> Result<(&'f str, &'f str, &'f crate::domain::KeySpec), Error> {
    let (product, key) = split_key_ref(entry).ok_or_else(|| key_ref_format(flag))?;
    match fleet
        .products
        .get_key_value(product)
        .and_then(|(p, spec)| spec.keys.get_key_value(key).map(|(k, s)| (p, k, s)))
    {
        Some((p, k, s)) => Ok((p.as_str(), k.as_str(), s)),
        None => {
            let refs = declared_refs(fleet);
            let all: Vec<&str> = refs.iter().map(String::as_str).collect();
            Err(not_declared(NameKind::Key, entry, &all))
        }
    }
}

/// Validate every `--rotate PRODUCT/KEY` before any call (FR-16): it must name a declared,
/// immutable key desired in `env_name`. An unmatched entry is never a silent no-op.
fn parse_rotate(
    fleet: &Fleet,
    env_name: &str,
    entries: &[String],
) -> Result<BTreeSet<(String, String)>, Error> {
    let env = fleet.environment(env_name)?;
    let mut set = BTreeSet::new();
    for e in entries {
        let (product, key, spec) = declared_key(fleet, "--rotate", e)?;
        if !spec.immutable {
            return Err(key_ref_refused(
                "--rotate",
                e,
                "key is not immutable (other keys are staged on every sync)",
                env_name,
            ));
        }
        if !rules::applies(spec, env_name, env, product) {
            return Err(key_ref_refused(
                "--rotate",
                e,
                &format!("key is not desired in environment {env_name:?}"),
                env_name,
            ));
        }
        set.insert((product.to_string(), key.to_string()));
    }
    Ok(set)
}

/// Validate every `--prune-immutable PRODUCT/KEY` before any call: it must name a declared,
/// immutable key that is not desired in `env_name` (a desired key is never pruned, so the
/// entry would be a silent no-op), and `--prune` must be passed too.
fn parse_prune_immutable(
    fleet: &Fleet,
    env_name: &str,
    opts: &SyncOpts,
) -> Result<BTreeSet<(String, String)>, Error> {
    let env = fleet.environment(env_name)?;
    if !opts.prune_immutable.is_empty() && !opts.prune {
        return Err(Cause::Usage {
            problem: UsageProblem::NeedsFlag {
                flag: "--prune-immutable".into(),
                needs: "--prune".into(),
            },
        }
        .into());
    }
    let mut set = BTreeSet::new();
    for e in &opts.prune_immutable {
        let (product, key, spec) = declared_key(fleet, "--prune-immutable", e)?;
        if !spec.immutable {
            return Err(key_ref_refused(
                "--prune-immutable",
                e,
                "key is not immutable (other keys are pruned by --prune alone)",
                env_name,
            ));
        }
        if rules::applies(spec, env_name, env, product) {
            return Err(key_ref_refused(
                "--prune-immutable",
                e,
                &format!("key is desired in environment {env_name:?}, so it is never pruned"),
                env_name,
            ));
        }
        set.insert((product.to_string(), key.to_string()));
    }
    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::testutil::*;
    use crate::runner::fake::FakeRunner;

    fn f() -> Fleet {
        fleet()
    }
    fn opts() -> SyncOpts {
        SyncOpts::default()
    }

    /// FR-46 (live smoke): a target whose writes are live has nothing to deploy, so the
    /// step after a sync that kept names asks for --prune only.
    #[test]
    fn a_live_targets_next_step_has_no_deploy() {
        let r = Report {
            live: true,
            kept: vec!["APP_NAME".into()],
            ..Report::default()
        };
        assert_eq!(
            r.next("ci", &SyncOpts::default()).as_deref(),
            Some("opv sync ci --prune")
        );
    }
    fn fake_with(item: crate::runner::Output, fly_a: crate::runner::Output) -> FakeRunner {
        FakeRunner::new([item, fly_a])
    }
    /// item, list A, the two preflight reads, import, list B, the delivery recording (FR-58:
    /// prod's mode-skipped key is never confirmed, so no revision), then spare responses so
    /// an unexpected call (deploy, unset) is recorded rather than panicking, and the test
    /// can assert it never happened.
    fn fake_sync(
        item: crate::runner::Output,
        a: crate::runner::Output,
        b: crate::runner::Output,
    ) -> FakeRunner {
        let [st, rel] = fly_preflight_ok();
        let again = crate::runner::Output {
            status: item.status,
            stdout: item.stdout.clone(),
        };
        let [me, fresh] = delivery_not_recorded(again);
        FakeRunner::new([item, a, st, rel, ok(), b, me, fresh, ok(), ok(), ok()])
    }
    fn fake_complete() -> FakeRunner {
        fake_sync(
            complete_item(),
            fly_empty(),
            fly(&[(OPENAI_FLY, "d-openai"), (ENC_FLY, "d-enc")]),
        )
    }
    fn sync_out(fleet: &Fleet, r: &FakeRunner, o: &SyncOpts) -> (Result<(), Error>, String) {
        let mut out = Vec::new();
        let res = run(fleet, "prod", r, &mut out, o);
        (res, text_of(&out))
    }

    // ---- fly sync: refusal before staging -------------------------------------------
    //
    // Every refusal test passes --deploy, --prune and a valid --rotate, with a prunable
    // managed name on Fly, and asserts nothing is staged, unset or deployed.

    fn all_flags() -> SyncOpts {
        SyncOpts {
            deploy: true,
            prune: true,
            rotate: vec!["allumata/INTEGRATION_ENC_KEY".into()],
            prune_immutable: vec![],
            ..SyncOpts::default()
        }
    }
    fn assert_nothing_mutated(r: &FakeRunner) {
        for sub in ["import", "unset", "deploy"] {
            assert!(
                !called(r, "flyctl", &["secrets", sub]),
                "{sub}: {:?}",
                argvs(r)
            );
        }
    }

    #[test]
    fn sync_refuses_when_anything_missing_and_stages_nothing() {
        let r = fake_with(
            item_without("allumata", "OPENAI_API_KEY"),
            fly_with_prunable(),
        );
        let e = run(&f(), "prod", &r, &mut Vec::new(), &all_flags()).unwrap_err();
        assert!(matches!(e, Error::Policy(_)), "{e}");
        assert!(e.to_string().contains("OPENAI_API_KEY"), "{e}");
        assert_no_values(&e.to_string());
        assert!(
            r.calls
                .borrow()
                .iter()
                .all(|c| !(c.program == "flyctl" && c.args.contains(&"import".to_string())))
        );
        assert_nothing_mutated(&r);
    }

    /// Review Focus 2: a product section missing from the item → every key Missing, the
    /// sync refuses, and nothing is staged (the only flyctl call is list A).
    #[test]
    fn sync_refuses_when_product_section_missing() {
        let r = fake_with(item(&[]), fly_with_prunable());
        let (res, out) = sync_out(&f(), &r, &all_flags());
        let e = res.unwrap_err();
        assert!(matches!(e, Error::Policy(_)), "{e}");
        for k in ["OPENAI_API_KEY", "INTEGRATION_ENC_KEY", "SIGNUP_POLICY"] {
            assert!(e.to_string().contains(k), "{e}");
        }
        assert_nothing_mutated(&r);
        assert_eq!(
            argvs(&r),
            vec![
                "op item get iprd --vault vprd --format json",
                "flyctl secrets list --app mcproductlabs-portfolio-production --json",
            ]
        );
        assert_no_values(&out);
    }

    #[test]
    fn sync_refuses_on_rule_failure() {
        // A key stored as the other kind is read tolerantly (FR-43), so only rules block.
        let item = complete_with(secret("allumata", "OPENAI_API_KEY", "sk-or-FIXTUREVALUE"));
        let r = fake_with(item, fly_with_prunable());
        let (res, out) = sync_out(&f(), &r, &all_flags());
        let e = res.unwrap_err();
        assert!(matches!(e, Error::Policy(_)), "{e}");
        assert_no_values(&e.to_string());
        assert_no_values(&out);
        assert_nothing_mutated(&r);
    }

    /// A value Fly's import parser would mangle is refused before anything is staged, as a
    /// blocking row naming product/KEY and the import rule (I2).
    #[test]
    fn sync_validates_import_before_staging() {
        let r = fake_with(
            complete_with(secret("allumata", "OPENAI_API_KEY", "sk-a\"#FIXTUREVALUE")),
            fly_with_prunable(),
        );
        let (res, out) = sync_out(&f(), &r, &all_flags());
        let e = res.unwrap_err();
        assert!(matches!(e, Error::Policy(_)), "{e}");
        assert_eq!(e.exit_code(), 6);
        assert!(
            e.to_string()
                .contains("allumata/OPENAI_API_KEY (failed import-hash-after-odd-quotes ("),
            "{e}"
        );
        assert_no_values(&e.to_string());
        assert_no_values(&out);
        assert_nothing_mutated(&r);
        assert_eq!(r.calls.borrow().len(), 2);
    }

    // ---- fly sync: happy path, deploy, change detection -----------------------------

    #[test]
    fn sync_never_deploys_without_flag() {
        let r = fake_complete();
        let (res, out) = sync_out(&f(), &r, &opts());
        res.unwrap();
        let calls = argvs(&r);
        assert!(
            calls.contains(
                &"flyctl secrets import --app mcproductlabs-portfolio-production --stage"
                    .to_string()
            ),
            "{calls:?}"
        );
        assert!(
            r.calls
                .borrow()
                .iter()
                .all(|c| !c.args.iter().any(|a| a == "deploy")),
            "{calls:?}"
        );
        assert!(!called(&r, "flyctl", &["secrets", "unset"]));
        assert_no_values(&out);
    }

    #[test]
    fn sync_call_sequence_is_read_list_stage_list_record() {
        let r = fake_complete();
        sync_out(&f(), &r, &opts()).0.unwrap();
        let app = "mcproductlabs-portfolio-production";
        assert_eq!(
            argvs(&r),
            vec![
                "op item get iprd --vault vprd --format json".to_string(),
                format!("flyctl secrets list --app {app} --json"),
                format!("flyctl status --app {app} --json"),
                format!("flyctl releases --app {app} --json"),
                format!("flyctl secrets import --app {app} --stage"),
                format!("flyctl secrets list --app {app} --json"),
                "op whoami --format json".to_string(),
                "op item get iprd --vault vprd --format json --cache=false".to_string(),
            ]
        );
    }

    /// FR-13: one read of the item for the plan; the delivery recording (FR-58) then asks
    /// for the account and reads the item fresh, never from `op`'s cache.
    #[test]
    fn op_requests_are_one_read_then_the_delivery_recording() {
        let r = fake_complete();
        let _ = run(&f(), "prod", &r, &mut Vec::new(), &opts());
        assert_eq!(
            argvs(&r)
                .into_iter()
                .filter(|a| a.starts_with("op "))
                .collect::<Vec<_>>(),
            vec![
                "op item get iprd --vault vprd --format json",
                "op whoami --format json",
                "op item get iprd --vault vprd --format json --cache=false",
            ]
        );
    }

    #[test]
    fn sync_values_only_on_stdin() {
        let r = fake_complete();
        let (res, out) = sync_out(&f(), &r, &opts());
        res.unwrap();
        assert_no_values_in_argv(&r);
        assert_no_values(&out);
        let stdin = import_stdin(&r).unwrap();
        assert!(stdin.contains(&format!("{OPENAI_FLY}=\"\"\"{OPENAI}\"\"\"")));
        assert!(stdin.contains(ENC_FLY));
        // Config keys are never Fly secrets.
        assert!(!stdin.contains("SIGNUP_POLICY"));
    }

    #[test]
    fn sync_reports_changed_and_unchanged_by_digest() {
        let r = fake_sync(
            complete_item(),
            fly(&[(OPENAI_FLY, "d1")]),
            fly(&[(OPENAI_FLY, "d1"), (ENC_FLY, "d2")]),
        );
        let (res, out) = sync_out(&f(), &r, &opts());
        res.unwrap();
        assert!(
            out.contains("summary: written 1 · unchanged 1 · held 0 · deployed no"),
            "{out}"
        );
        assert!(
            out.contains(&format!(
                "written: allumata/INTEGRATION_ENC_KEY ({ENC_FLY})"
            )),
            "{out}"
        );
        assert!(
            out.contains(&format!(
                "unchanged: allumata/OPENAI_API_KEY ({OPENAI_FLY})"
            )),
            "{out}"
        );
        assert_no_values(&out);
    }

    #[test]
    fn sync_deploys_with_flag_when_changed() {
        let r = fake_complete();
        let o = SyncOpts {
            deploy: true,
            ..opts()
        };
        sync_out(&f(), &r, &o).0.unwrap();
        assert_eq!(
            argvs(&r).last().unwrap(),
            "flyctl secrets deploy --app mcproductlabs-portfolio-production"
        );
    }

    /// FR-7: nothing changed, nothing pruned, everything Deployed → no deploy, even with
    /// `--deploy`.
    #[test]
    fn sync_skips_deploy_when_nothing_pending() {
        let same = || fly_st(&[(OPENAI_FLY, "d1", "Deployed"), (ENC_FLY, "d2", "Deployed")]);
        let r = fake_sync(complete_item(), same(), same());
        let o = SyncOpts {
            deploy: true,
            ..opts()
        };
        let (res, out) = sync_out(&f(), &r, &o);
        res.unwrap();
        assert!(
            !called(&r, "flyctl", &["secrets", "deploy"]),
            "{:?}",
            argvs(&r)
        );
        assert!(
            out.contains(
                "summary: written 0 · unchanged 1 · held 1 · deployed no · pending 0 · pruned 0"
            ),
            "{out}"
        );
    }

    /// A == B, but a managed name is still Staged from an earlier run (a sync without
    /// --deploy, or a failed deploy): `--deploy` must deploy it.
    #[test]
    fn sync_deploys_managed_name_pending_from_earlier_run() {
        for status in ["Staged", "Partial"] {
            let same = || fly_st(&[(OPENAI_FLY, "d1", status), (ENC_FLY, "d2", "Deployed")]);
            let r = fake_sync(complete_item(), same(), same());
            let o = SyncOpts {
                deploy: true,
                ..opts()
            };
            let (res, out) = sync_out(&f(), &r, &o);
            res.unwrap();
            assert_eq!(
                argvs(&r).last().unwrap(),
                "flyctl secrets deploy --app mcproductlabs-portfolio-production",
                "{status}"
            );
            assert!(
                out.contains(&format!("deployed: allumata/OPENAI_API_KEY ({OPENAI_FLY})")),
                "{out}"
            );
        }
    }

    /// With nothing staged (every secret immutable and held) there is no list B; pending
    /// is judged on list A, and `--deploy` still deploys the earlier run's staged name.
    #[test]
    fn sync_deploys_pending_when_nothing_staged() {
        let text = std::fs::read_to_string("tests/fixtures/secrets.toml").unwrap();
        let fl = crate::config::parse(&text.replace(
            "guidance = \"OpenAI platform / API keys\"",
            "guidance = \"OpenAI platform / API keys\"\nimmutable = true",
        ))
        .unwrap();
        let a = || fly_st(&[(ENC_FLY, "d2", "Staged"), (OPENAI_FLY, "d1", "Deployed")]);
        let [st, rel] = fly_preflight_ok();
        let [me, fresh] = delivery_not_recorded(complete_item());
        let r = FakeRunner::new([complete_item(), a(), st, rel, me, fresh, ok(), ok()]);
        let o = SyncOpts {
            deploy: true,
            ..opts()
        };
        let (res, out) = sync_out(&fl, &r, &o);
        res.unwrap();
        let app = "mcproductlabs-portfolio-production";
        assert_eq!(
            argvs(&r),
            vec![
                "op item get iprd --vault vprd --format json".to_string(),
                format!("flyctl secrets list --app {app} --json"),
                format!("flyctl status --app {app} --json"),
                format!("flyctl releases --app {app} --json"),
                "op whoami --format json".to_string(),
                "op item get iprd --vault vprd --format json --cache=false".to_string(),
                format!("flyctl secrets deploy --app {app}"),
            ],
            "{out}"
        );
    }

    /// Another tool's staged secret is not opv's to deploy.
    #[test]
    fn unmanaged_staged_name_does_not_trigger_deploy() {
        let same = || {
            fly_st(&[
                (OPENAI_FLY, "d1", "Deployed"),
                (ENC_FLY, "d2", "Deployed"),
                ("OTHER_TOOL_TOKEN", "d9", "Staged"),
            ])
        };
        let r = fake_sync(complete_item(), same(), same());
        let o = SyncOpts {
            deploy: true,
            ..opts()
        };
        let (res, out) = sync_out(&f(), &r, &o);
        res.unwrap();
        assert!(
            !called(&r, "flyctl", &["secrets", "deploy"]),
            "{:?}",
            argvs(&r)
        );
        assert!(!out.contains("OTHER_TOOL_TOKEN"), "{out}");
    }

    /// Status never suppresses: a changed digest deploys even if Fly says Deployed.
    #[test]
    fn changed_digest_deploys_regardless_of_status() {
        let r = fake_sync(
            complete_item(),
            fly_st(&[(OPENAI_FLY, "d1", "Deployed"), (ENC_FLY, "d2", "Deployed")]),
            fly_st(&[(OPENAI_FLY, "d1b", "Deployed"), (ENC_FLY, "d2", "Deployed")]),
        );
        let o = SyncOpts {
            deploy: true,
            ..opts()
        };
        sync_out(&f(), &r, &o).0.unwrap();
        assert!(called(&r, "flyctl", &["secrets", "deploy"]));
    }

    /// A staged key Fly reports without a digest is unknown, so it counts as changed: a
    /// deploy must not be skipped on missing evidence.
    #[test]
    fn staged_key_without_digest_after_staging_counts_as_changed() {
        let b = || fly(&[(ENC_FLY, "d2")]);
        let [st, rel] = fly_preflight_ok();
        // List B is polled until the 30 s limit (NR-30): six lists, the delivery recording,
        // then the deploy.
        let r = FakeRunner::new([complete_item(), b(), st, rel, ok()]);
        r.responses.borrow_mut().extend(
            (0..6)
                .map(|_| b())
                .chain(delivery_not_recorded(complete_item()))
                .chain([ok()])
                .map(Ok),
        );
        let o = SyncOpts {
            deploy: true,
            ..opts()
        };
        let (res, out) = sync_out(&f(), &r, &o);
        res.unwrap();
        assert!(
            out.contains("summary: written 1 · unchanged 0 · held 1 · deployed yes"),
            "{out}"
        );
        assert!(called(&r, "flyctl", &["secrets", "deploy"]));
    }

    // ---- immutable and --rotate -----------------------------------------------------

    #[test]
    fn immutable_present_on_fly_is_held_not_staged() {
        let a = || fly(&[(ENC_FLY, "d-enc")]);
        let b = fly(&[(ENC_FLY, "d-enc"), (OPENAI_FLY, "d-openai")]);
        let r = fake_sync(complete_item(), a(), b);
        let (res, out) = sync_out(&f(), &r, &opts());
        res.unwrap();
        let stdin = import_stdin(&r).unwrap();
        assert!(!stdin.contains(ENC_FLY), "immutable key staged");
        assert!(stdin.contains(OPENAI_FLY));
        assert!(
            out.contains(&format!(
                "held (immutable), not rewritten (pass --rotate PRODUCT/KEY to replace): \
                 allumata/INTEGRATION_ENC_KEY ({ENC_FLY})"
            )),
            "{out}"
        );
    }

    #[test]
    fn rotate_stages_an_immutable_key() {
        let a = || fly(&[(ENC_FLY, "d-enc")]);
        let b = fly(&[(ENC_FLY, "d-enc2"), (OPENAI_FLY, "d-openai")]);
        let r = fake_sync(complete_item(), a(), b);
        let o = SyncOpts {
            rotate: vec!["allumata/INTEGRATION_ENC_KEY".into()],
            ..opts()
        };
        sync_out(&f(), &r, &o).0.unwrap();
        assert!(import_stdin(&r).unwrap().contains(ENC_FLY));
    }

    #[test]
    fn rotate_entries_are_validated_before_any_call() {
        let fl = fleet_with(
            "[products.allumata.keys.STAGING_ONLY]\nkind = \"secret\"\n\
             environments = [\"staging\"]\nimmutable = true\n",
        );
        for bad in [
            "allumata/NOPE",                // undeclared key
            "nosuch/INTEGRATION_ENC_KEY",   // undeclared product
            "allumata/OPENAI_API_KEY",      // not immutable
            "allumata/STAGING_ONLY",        // not desired in prod
            "allumata-INTEGRATION_ENC_KEY", // malformed
            "allumata/",                    // malformed
        ] {
            let r = FakeRunner::new([]);
            let o = SyncOpts {
                rotate: vec!["allumata/INTEGRATION_ENC_KEY".into(), bad.into()],
                ..all_flags()
            };
            // Exit 2 (configuration and usage), before any call; malformed entries are a
            // cataloged usage error (R26), undeclared ones `NotDeclared` (R21).
            let e = run(&fl, "prod", &r, &mut Vec::new(), &o).unwrap_err();
            assert_eq!(e.exit_code(), 2, "{bad}: {e}");
            assert!(r.calls.borrow().is_empty(), "{bad}: calls made");
        }
    }

    /// A rotate entry for an immutable key that is skipped by mode is not desired.
    #[test]
    fn rotate_rejects_mode_skipped_key() {
        let fl = fleet_with(
            "[products.allumata.keys.STRIPE_WEBHOOK]\nkind = \"secret\"\n\
             environments = [\"staging\", \"prod\"]\nimmutable = true\n\
             rules = { prefix_by_mode = { mode = \"payments\", values = { test = \"whsec_\" }, \
             skip = [\"off\"] } }\n",
        );
        let r = FakeRunner::new([]);
        let o = SyncOpts {
            rotate: vec!["allumata/STRIPE_WEBHOOK".into()],
            ..all_flags()
        };
        let e = run(&fl, "prod", &r, &mut Vec::new(), &o).unwrap_err();
        assert!(matches!(e, Error::Config(_)), "{e}");
        assert!(r.calls.borrow().is_empty());
    }

    // ---- --prune --------------------------------------------------------------------

    fn fly_with_prunable() -> crate::runner::Output {
        // prod has payments = "off", so the Stripe key is managed but not desired → prune.
        fly(&[(STRIPE_FLY, "d-s"), ("OTHER_TOOL_TOKEN", "d-o")])
    }
    /// [`fly_with_prunable`] after this run staged its two keys.
    fn fly_with_prunable_staged() -> crate::runner::Output {
        fly(&[
            (STRIPE_FLY, "d-s"),
            ("OTHER_TOOL_TOKEN", "d-o"),
            (OPENAI_FLY, "d-openai"),
            (ENC_FLY, "d-enc"),
        ])
    }

    #[test]
    fn sync_never_prunes_without_flag() {
        let r = fake_sync(
            complete_item(),
            fly_with_prunable(),
            fly_with_prunable_staged(),
        );
        sync_out(&f(), &r, &opts()).0.unwrap();
        assert!(
            !called(&r, "flyctl", &["secrets", "unset"]),
            "{:?}",
            argvs(&r)
        );
    }

    #[test]
    fn sync_prunes_only_managed_names_with_flag() {
        let r = fake_sync(
            complete_item(),
            fly_with_prunable(),
            fly_with_prunable_staged(),
        );
        let o = SyncOpts {
            prune: true,
            ..opts()
        };
        sync_out(&f(), &r, &o).0.unwrap();
        assert!(
            argvs(&r).contains(&format!(
                "flyctl secrets unset {STRIPE_FLY} --app mcproductlabs-portfolio-production --stage"
            )),
            "{:?}",
            argvs(&r)
        );
        assert!(!r.argv_contains("OTHER_TOOL_TOKEN"));
    }

    #[test]
    fn prune_counts_as_a_change_for_deploy() {
        let a = || fly(&[(OPENAI_FLY, "d1"), (ENC_FLY, "d2"), (STRIPE_FLY, "d3")]);
        let r = fake_sync(complete_item(), a(), a());
        let o = SyncOpts {
            prune: true,
            deploy: true,
            ..opts()
        };
        sync_out(&f(), &r, &o).0.unwrap();
        assert!(called(&r, "flyctl", &["secrets", "unset"]));
        assert!(called(&r, "flyctl", &["secrets", "deploy"]));
    }

    // ---- immutable keys are never pruned unless released (C2) ------------------------

    /// An immutable key declared for staging only, present on the prod Fly app.
    fn fleet_old_immutable() -> Fleet {
        fleet_with(
            "[products.allumata.keys.OLD_ENC]\nkind = \"secret\"\n\
             environments = [\"staging\"]\nimmutable = true\n",
        )
    }
    const OLD_FLY: &str = "FLEET__ALLUMATA__OLD_ENC";

    #[test]
    fn immutable_key_not_desired_is_held_from_prune() {
        let a = || fly(&[(OPENAI_FLY, "d1"), (ENC_FLY, "d2"), (OLD_FLY, "d3")]);
        let r = fake_sync(complete_item(), a(), a());
        let o = SyncOpts {
            prune: true,
            deploy: true,
            ..opts()
        };
        let (res, out) = sync_out(&fleet_old_immutable(), &r, &o);
        res.unwrap();
        assert!(
            !called(&r, "flyctl", &["secrets", "unset"]),
            "{:?}",
            argvs(&r)
        );
        assert!(!r.argv_contains(OLD_FLY));
        assert!(
            out.contains(&format!(
                "held (immutable), not pruned (pass --prune --prune-immutable PRODUCT/KEY to remove): allumata/OLD_ENC ({OLD_FLY})"
            )),
            "{out}"
        );
        assert_no_values(&out);
    }

    #[test]
    fn prune_immutable_releases_the_named_key() {
        let a = || fly(&[(OPENAI_FLY, "d1"), (ENC_FLY, "d2"), (OLD_FLY, "d3")]);
        let r = fake_sync(complete_item(), a(), a());
        let o = SyncOpts {
            prune: true,
            prune_immutable: vec!["allumata/OLD_ENC".into()],
            ..opts()
        };
        let (res, out) = sync_out(&fleet_old_immutable(), &r, &o);
        res.unwrap();
        assert!(
            argvs(&r).contains(&format!(
                "flyctl secrets unset {OLD_FLY} --app mcproductlabs-portfolio-production --stage"
            )),
            "{:?}",
            argvs(&r)
        );
        assert!(!out.contains("held (immutable), not pruned"), "{out}");
    }

    #[test]
    fn plan_shows_immutable_key_held_from_prune() {
        let r = FakeRunner::new([
            complete_item(),
            fly(&[(OPENAI_FLY, "d1"), (ENC_FLY, "d2"), (OLD_FLY, "d3")]),
        ]);
        let mut out = Vec::new();
        plan(&fleet_old_immutable(), "prod", &r, &mut out).unwrap();
        let out = text_of(&out);
        assert!(
            out.contains(&format!(
                "held (immutable), not pruned (needs --prune --prune-immutable PRODUCT/KEY): \
                 allumata/OLD_ENC ({OLD_FLY})"
            )),
            "{out}"
        );
        assert!(out.contains("0 to prune"), "{out}");
        assert!(!out.contains("would prune"), "{out}");
    }

    #[test]
    fn prune_immutable_entries_are_validated_before_any_call() {
        for (bad, prune) in [
            ("allumata/OPENAI_API_KEY", true),      // not immutable
            ("allumata/NOPE", true),                // undeclared
            ("nosuch/OLD_ENC", true),               // undeclared product
            ("allumata/INTEGRATION_ENC_KEY", true), // desired in prod: never pruned
            ("allumata-OLD_ENC", true),             // malformed
            ("allumata/OLD_ENC", false),            // without --prune
        ] {
            let r = FakeRunner::new([]);
            let o = SyncOpts {
                prune,
                prune_immutable: vec![bad.into()],
                ..opts()
            };
            let e = run(&fleet_old_immutable(), "prod", &r, &mut Vec::new(), &o).unwrap_err();
            assert_eq!(e.exit_code(), 2, "{bad}: {e}");
            assert!(r.calls.borrow().is_empty(), "{bad}: calls made");
        }
    }

    // ---- refuse_in (I1) and import refusals in plan (I2) ---------------------------

    /// SMTP_PASS is prod-only and refused in staging (the shape infra generates).
    fn fleet_smtp() -> Fleet {
        fleet_with(
            "[products.allumata.keys.SMTP_PASS]\nkind = \"secret\"\n\
             environments = [\"prod\"]\nrules = { refuse_in = [\"staging\"] }\n",
        )
    }
    fn staging_fields() -> Vec<Field> {
        vec![
            secret("allumata", "INTEGRATION_ENC_KEY", &enc()),
            secret("allumata", "STRIPE_SECRET_KEY", "sk_test_FIXTUREVALUE"),
            text("allumata", "SIGNUP_POLICY", POLICY),
        ]
    }

    #[test]
    fn refuse_in_blocks_plan_and_sync_in_the_refused_env() {
        let mut fs = staging_fields();
        fs.push(secret("allumata", "SMTP_PASS", "FIXTUREVALUE-smtp"));
        let r = FakeRunner::new([item(&fs), fly_empty()]);
        let mut out = Vec::new();
        let e = plan(&fleet_smtp(), "staging", &r, &mut out).unwrap_err();
        let out = text_of(&out);
        assert!(matches!(e, Error::Findings(1, _)), "{e}");
        assert!(
            out.lines()
                .any(|l| l.contains("SMTP_PASS") && l.contains("failed refuse_in (")),
            "{out}"
        );
        assert_no_values(&out);

        let r = FakeRunner::new([item(&fs), fly_empty(), ok(), ok()]);
        let e = run(&fleet_smtp(), "staging", &r, &mut Vec::new(), &opts()).unwrap_err();
        assert!(matches!(e, Error::Policy(_)), "{e}");
        assert!(
            e.to_string()
                .contains("allumata/SMTP_PASS (failed refuse_in ("),
            "{e}"
        );
        assert_no_values(&e.to_string());
        assert_nothing_mutated(&r);

        // Empty (a skeleton field nobody filled) or absent: fine, no row.
        for fs in [
            {
                let mut v = staging_fields();
                v.push(("allumata".into(), "SMTP_PASS".into(), "CONCEALED", None));
                v
            },
            staging_fields(),
        ] {
            let r = FakeRunner::new([item(&fs), fly_empty()]);
            let mut out = Vec::new();
            plan(&fleet_smtp(), "staging", &r, &mut out).unwrap();
            assert!(!text_of(&out).contains("SMTP_PASS"), "{}", text_of(&out));
        }
    }

    #[test]
    fn plan_shows_import_refusal_as_failing_rule() {
        let r = FakeRunner::new([
            complete_with(secret("allumata", "OPENAI_API_KEY", "sk-a\"#FIXTUREVALUE")),
            fly_empty(),
        ]);
        let (res, out) = plan_out(&r);
        let e = res.unwrap_err();
        assert!(matches!(e, Error::Findings(1, _)), "{e}");
        assert_eq!(e.exit_code(), 8);
        assert!(
            out.lines().any(|l| l.contains("OPENAI_API_KEY")
                && l.contains("failed import-hash-after-odd-quotes (")),
            "{out}"
        );
        assert_no_values(&out);
    }

    // ---- environments without fly (I5) ----------------------------------------------

    #[test]
    fn env_without_fly_is_config_error_before_any_call() {
        let fl = fleet_with("[environments.dev]\n");
        let r = FakeRunner::new([]);
        let e = run(&fl, "dev", &r, &mut Vec::new(), &opts()).unwrap_err();
        // The catalog's no-target cause (R25), naming the environment.
        assert_eq!(e.code_str(), "no_target", "{e}");
        let e = plan(&fl, "dev", &r, &mut Vec::new()).unwrap_err();
        assert_eq!(e.code_str(), "no_target", "{e}");
        assert!(r.calls.borrow().is_empty());
    }

    // ---- failures -------------------------------------------------------------------

    #[test]
    fn unknown_env_is_config_error_before_any_call() {
        let r = FakeRunner::new([]);
        let e = run(&f(), "qa", &r, &mut Vec::new(), &opts()).unwrap_err();
        assert_eq!(e.code_str(), "unknown_env", "{e}");
        let e = plan(&f(), "qa", &r, &mut Vec::new()).unwrap_err();
        assert_eq!(e.code_str(), "unknown_env", "{e}");
        assert!(r.calls.borrow().is_empty());
    }

    #[test]
    fn stage_failure_is_target_error_and_stops() {
        let r = FakeRunner::new([
            complete_item(),
            fly_empty(),
            fly_app_ok(),
            fly_releases("complete"),
            crate::runner::Output::failure(1),
            ok(),
            ok(),
        ]);
        let o = SyncOpts {
            deploy: true,
            prune: true,
            ..opts()
        };
        let e = run(&f(), "prod", &r, &mut Vec::new(), &o).unwrap_err();
        assert_eq!(e.exit_code(), 5, "{e}");
        // The failed import is diagnosed from its reply (design §5): no list B, no unset,
        // no deploy, and no login check of its own.
        assert_eq!(r.calls.borrow().len(), 5);
    }

    // ---- fly plan -------------------------------------------------------------------

    fn plan_out(r: &FakeRunner) -> (Result<(), Error>, String) {
        let mut out = Vec::new();
        let res = plan(&f(), "prod", r, &mut out);
        (res, text_of(&out))
    }

    #[test]
    fn plan_makes_no_mutation_and_one_op_call() {
        let r = FakeRunner::new([complete_item(), fly_with_prunable(), ok(), ok()]);
        plan_out(&r).0.unwrap();
        assert_eq!(
            argvs(&r),
            vec![
                "op item get iprd --vault vprd --format json",
                "flyctl secrets list --app mcproductlabs-portfolio-production --json",
            ]
        );
        assert_eq!(op_calls(&r), 1);
    }

    #[test]
    fn plan_prints_rows_targets_and_counts() {
        let r = FakeRunner::new([
            complete_item(),
            fly(&[
                (OPENAI_FLY, "d1"),
                (ENC_FLY, "d2"),
                (STRIPE_FLY, "d3"),
                ("OTHER_TOOL_TOKEN", "d4"),
            ]),
        ]);
        let (res, out) = plan_out(&r);
        res.unwrap();
        assert!(
            out.contains("1 to stage · 1 held (immutable) · 1 to prune"),
            "{out}"
        );
        assert!(out.contains("unknown"), "{out}");
        assert!(out.contains(STRIPE_FLY), "{out}");
        assert!(out.contains("1 unmanaged on Fly"), "{out}");
        assert_no_values(&out);
    }

    #[test]
    fn plan_reports_new_keys_absent_from_fly() {
        let r = FakeRunner::new([complete_item(), fly_empty()]);
        let (res, out) = plan_out(&r);
        res.unwrap();
        assert!(
            out.contains("2 to stage · 0 held (immutable) · 0 to prune"),
            "{out}"
        );
        assert!(out.contains("  new"), "{out}");
    }

    #[test]
    fn plan_with_blocking_rows_is_findings_and_names_only() {
        let r = FakeRunner::new([
            complete_with(secret("allumata", "OPENAI_API_KEY", "sk-or-FIXTUREVALUE")),
            fly_empty(),
        ]);
        let (res, out) = plan_out(&r);
        let e = res.unwrap_err();
        assert!(matches!(e, Error::Findings(1, _)), "{e}");
        assert!(out.contains("failed not_prefix ("), "{out}");
        assert_no_values(&out);
        assert_no_values(&e.to_string());
    }

    // ---- preflight before the first write (NR-10, NR-17, NR-23..NR-28, NR-30) ----------

    const APP: &str = "mcproductlabs-portfolio-production";
    type Out = crate::runner::Output;

    /// Every write call made (import, unset, deploy).
    fn writes(r: &FakeRunner) -> Vec<String> {
        argvs(r)
            .into_iter()
            .filter(|a| ["import", "unset", "deploy"].iter().any(|w| a.contains(w)))
            .collect()
    }
    /// Item and list A succeed (a prunable name on Fly), then `rest`; spare responses so
    /// an unexpected write is recorded, not a panic.
    fn after_list_a(rest: impl IntoIterator<Item = Out>) -> FakeRunner {
        let r = FakeRunner::new([complete_item(), fly_with_prunable()]);
        r.responses.borrow_mut().extend(rest.into_iter().map(Ok));
        r
    }
    fn spare(r: &FakeRunner) {
        r.responses
            .borrow_mut()
            .extend((0..6).map(|_| Ok(fly_with_prunable_staged())));
    }
    fn sync_err(r: &FakeRunner) -> Error {
        spare(r);
        let bash =
            crate::host::Host::from_env(&crate::host::FakeEnv::new("linux").shell("/bin/bash"));
        crate::host::with_test_host(bash, || run(&f(), "prod", r, &mut Vec::new(), &all_flags()))
            .unwrap_err()
    }

    #[test]
    fn preflight_failure_makes_no_write_calls_when_app_dead() {
        let r = after_list_a([fly_app_dead()]);
        sync_err(&r);
        assert_eq!(writes(&r), Vec::<String>::new());
    }

    #[test]
    fn preflight_failure_makes_no_write_calls_when_deploy_still_running() {
        let r = after_list_a([fly_app_ok(), fly_releases("running")]);
        r.budget.set(crate::adapters::fly::DEPLOY_POLL);
        sync_err(&r);
        assert_eq!(writes(&r), Vec::<String>::new());
    }

    #[test]
    fn preflight_failure_makes_no_write_calls_when_fly_does_not_respond() {
        let r = after_list_a([]);
        r.push_unknowns("timeout", crate::runner::READ_ATTEMPTS);
        sync_err(&r);
        assert_eq!(writes(&r), Vec::<String>::new());
    }

    #[test]
    fn preflight_failure_makes_no_write_calls_when_signed_out_of_fly() {
        let r = FakeRunner::new([complete_item()]);
        r.responses.borrow_mut().extend(
            crate::runner::fake::failed_read(1)
                .chain([Out::failure(1)])
                .map(Ok),
        );
        sync_err(&r);
        assert_eq!(writes(&r), Vec::<String>::new());
    }

    #[test]
    fn preflight_failure_makes_no_write_calls_when_flyctl_missing() {
        let r = FakeRunner::new([complete_item()]);
        r.push_io_error(std::io::ErrorKind::NotFound);
        sync_err(&r);
        assert_eq!(writes(&r), Vec::<String>::new());
    }

    #[test]
    fn preflight_failure_makes_no_write_calls_when_1password_does_not_respond() {
        let r = FakeRunner::default();
        r.push_unknowns("timeout", crate::runner::READ_ATTEMPTS);
        sync_err(&r);
        assert_eq!(writes(&r), Vec::<String>::new());
    }

    #[test]
    fn preflight_failure_makes_no_write_calls_when_vault_access_is_missing() {
        let r = FakeRunner::new(crate::runner::fake::failed_read(1).chain([
            Out::success(br#"{"user_type":"USER"}"#.to_vec()),
            Out::failure(1),
        ]));
        sync_err(&r);
        assert_eq!(writes(&r), Vec::<String>::new());
    }

    fn deploy_opts() -> SyncOpts {
        SyncOpts {
            deploy: true,
            ..SyncOpts::default()
        }
    }
    fn no_machines_warning() -> String {
        format!(
            "warn  fly app {APP}: no machines; secrets are staged and apply when machines \
             start (fly scale count 1 --app {APP})\n"
        )
    }
    /// The preflight reads with `status`, the import, list B and the delivery recording.
    fn staged_after(status: Out) -> (FakeRunner, Result<(), Error>, String) {
        let [me, fresh] = delivery_not_recorded(complete_item());
        let r = after_list_a([
            status,
            fly_releases("complete"),
            ok(),
            fly_with_prunable_staged(),
            me,
            fresh,
        ]);
        spare(&r);
        let (res, out) = sync_out(&f(), &r, &deploy_opts());
        (r, res, out)
    }

    #[test]
    fn suspended_fly_app_stages_with_the_no_machines_warning() {
        let (r, res, out) = staged_after(fly_status("suspended"));
        assert!(
            res.is_ok() && out.contains(&no_machines_warning()) && import_stdin(&r).is_some(),
            "{res:?}\n{out}"
        );
    }

    #[test]
    fn suspended_fly_app_with_deploy_skips_the_deploy_and_exits_ok() {
        let (r, res, out) = staged_after(fly_status("suspended"));
        assert!(
            res.is_ok()
                && !called(&r, "flyctl", &["secrets", "deploy"])
                && out.contains(&format!(
                    "deploy skipped: {APP} has no machines; staged secrets apply when machines \
                     start\n"
                )),
            "{res:?}\n{out}"
        );
    }

    #[test]
    fn pending_fly_app_with_deploy_skips_the_deploy_and_exits_ok() {
        let (r, res, out) = staged_after(fly_status("pending"));
        assert!(
            res.is_ok()
                && !called(&r, "flyctl", &["secrets", "deploy"])
                && out.contains(&no_machines_warning())
                && out.contains("deploy skipped:"),
            "{res:?}\n{out}"
        );
    }

    #[test]
    fn stopped_machines_are_reported_not_refused() {
        let (_r, res, out) = staged_after(fly_app_machines("stopped"));
        assert!(
            res.is_ok()
                && out.contains(&format!(
                    "warn  fly app {APP}: machines stopped; secrets are staged and apply when \
                     machines start\n"
                )),
            "{res:?}\n{out}"
        );
    }

    #[test]
    fn dead_fly_app_refuses_with_a_next_step() {
        let r = after_list_a([fly_app_dead()]);
        let e = sync_err(&r);
        assert!(
            e.next_step().is_some_and(
                |n| n.starts_with(&format!("recreate it with `flyctl apps create {APP}`"))
            ),
            "{e:?}"
        );
    }

    #[test]
    fn sync_waits_for_a_running_deploy_then_stages() {
        let r = FakeRunner::new([
            complete_item(),
            fly_empty(),
            fly_app_ok(),
            fly_releases("running"),
            fly_releases("complete"),
            ok(),
            fly(&[(OPENAI_FLY, "d1"), (ENC_FLY, "d2")]),
        ]);
        r.responses
            .borrow_mut()
            .extend(delivery_not_recorded(complete_item()).map(Ok));
        sync_out(&f(), &r, &opts()).0.unwrap();
        assert!(
            called(&r, "flyctl", &["secrets", "import"]),
            "{:?}",
            argvs(&r)
        );
    }

    #[test]
    fn provider_outage_before_writes_exits_9_with_status_page() {
        let r = after_list_a([]);
        r.push_unknowns("timeout", crate::runner::READ_ATTEMPTS);
        let e = sync_err(&r);
        assert_eq!(
            (e.exit_code(), e.to_string()),
            (
                9,
                // R51: the catalog's Unavailable; its Do names the status page.
                "Fly did not answer after 3 attempts: it timed out".to_string()
            )
        );
    }

    /// NR-30: list B right after staging still lacks the staged names; it is read again
    /// until they show a digest.
    #[test]
    fn stale_list_after_stage_is_polled() {
        let [st, rel] = fly_preflight_ok();
        let fresh = fly(&[(OPENAI_FLY, "d-openai"), (ENC_FLY, "d-enc")]);
        let r = FakeRunner::new([
            complete_item(),
            fly_empty(),
            st,
            rel,
            ok(),
            fly_empty(),
            fresh,
        ]);
        r.responses
            .borrow_mut()
            .extend(delivery_not_recorded(complete_item()).map(Ok));
        sync_out(&f(), &r, &opts()).0.unwrap();
        let lists = argvs(&r)
            .iter()
            .filter(|a| a.contains("secrets list"))
            .count();
        assert_eq!(lists, 3);
    }

    /// NR-30: the poll gives up after 30 s on the runner's clock.
    #[test]
    fn stale_list_poll_is_bounded_at_30_seconds() {
        let [st, rel] = fly_preflight_ok();
        let r = FakeRunner::new([complete_item(), fly_empty(), st, rel, ok()]);
        r.responses.borrow_mut().extend(
            (0..6)
                .map(|_| fly_empty())
                .chain(delivery_not_recorded(complete_item()))
                .map(Ok),
        );
        sync_out(&f(), &r, &opts()).0.unwrap();
        assert_eq!(r.elapsed.get(), Duration::from_secs(30));
    }

    /// NR-10: sign-in lost after the stage: the error names the completed write.
    #[test]
    fn auth_loss_after_first_write_names_completed_writes() {
        let r = after_list_a([
            fly_app_ok(),
            fly_releases("complete"),
            ok(),
            fly_with_prunable_staged(),
            whoami(),        // delivery recording: the account
            complete_item(), // delivery recording: the item, fresh
        ]);
        // unset: flyctl's recorded signed-out reply
        r.push_with_stderr(
            Out::failure(1),
            include_str!("../../tests/fixtures/fly/failures/02-signed-out-secrets-list.stderr"),
        );
        let e = sync_err(&r);
        assert!(
            e.to_string()
                .contains("already written: staged 2 secret(s)"),
            "{e}"
        );
    }

    /// NR-17, R63: a refusal names the next command, in one line: the value to fill,
    /// opened in 1Password (01.14; it was `opv explain`, which only describes the key).
    #[test]
    fn refusal_names_the_value_to_open_as_the_next_command() {
        let r = fake_with(
            item_without("allumata", "OPENAI_API_KEY"),
            fly_with_prunable(),
        );
        let e = sync_err(&r);
        assert_eq!(
            e.next_step(),
            Some("opv open allumata/OPENAI_API_KEY --env prod"),
            "{e}"
        );
    }

    /// 01.05: `plan --json` with findings carries no sync step (its step is the error's,
    /// which opens the value to fill), and never a pre-confirmed one.
    #[test]
    fn plan_json_with_findings_has_no_sync_step() {
        let mut fl = f();
        fl.environments.get_mut("prod").unwrap().confirm_env = true;
        let r = FakeRunner::new([
            item_without("allumata", "OPENAI_API_KEY"),
            fly_empty(),
            ok(),
        ]);
        let mut out = Vec::new();
        let _ = plan_scoped(&fl, "prod", None, &r, &mut out, true);
        let doc: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert!(doc["next"].is_null(), "{doc}");
    }

    /// R53, X20 (01.07): a cataloged failure after this run's writes names them, and its
    /// step reads what remains instead of writing again.
    #[test]
    fn a_cataloged_failure_after_writes_is_partial_naming_them() {
        let e = partial(
            Cause::Interrupted {
                signal: 2,
                writes_started: true,
            }
            .into(),
            &["staged 2 secret(s)".to_string()],
            all_flags().scope("prod"),
        );
        assert!(
            matches!(e.cause(), Some((Cause::Partial { done, .. }, _))
                if done == &["staged 2 secret(s)".to_string()]),
            "{e:?}"
        );
    }

    /// R53: the read after a partial failure keeps the run's scope (X1).
    #[test]
    fn a_partial_failure_steps_to_the_plan_of_the_same_scope() {
        let o = SyncOpts {
            targets: vec!["portfolio".into()],
            product: Some("allumata".into()),
            deploy: true,
            ..SyncOpts::default()
        };
        let e = partial(
            Cause::Interrupted {
                signal: 2,
                writes_started: true,
            }
            .into(),
            &["staged 2 secret(s)".to_string()],
            o.scope("prod"),
        );
        let (cause, _) = e.cause().unwrap();
        let inv = crate::cause::Invocation::from_cli(&["opv".to_string(), "sync".to_string()]);
        assert_eq!(
            crate::cause::render::next_text(&cause.step(&inv).1, &inv),
            Some("opv plan prod --target portfolio --product allumata".into())
        );
    }

    /// X4 (01.05, 01.12): a sync step opv builds never carries --confirm, even when the
    /// person passed it.
    #[test]
    fn a_generated_sync_step_never_carries_confirm() {
        let o = SyncOpts {
            confirm: Some("prod".into()),
            ..all_flags()
        };
        assert!(!step_text(&o.command("prod")).contains("--confirm"));
    }

    /// NR-10: a target refusal after staging names what was already staged.
    #[test]
    fn a_target_error_after_staging_names_what_completed() {
        let e = after_writes(
            Error::Target("flyctl secrets deploy failed".into()),
            &["api/TOKEN".to_string()],
        );
        assert!(
            e.text()
                .contains("1 write(s) had completed before it: api/TOKEN")
        );
    }
}
