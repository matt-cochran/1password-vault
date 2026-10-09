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

use std::collections::{BTreeSet, HashSet};
use std::io::Write;
use std::time::Duration;

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use super::{
    KeyNames, check_product, ci_summary, compare, findings_error, is_blocking, item_url,
    managed_names, open_target, plan_item, plural, preflight, print_extras, print_legend,
    print_rows, product_names, read_and_plan, read_fields, row_names, scope_plan, target_word,
    unmanaged_on_target, write_err, write_json,
};
use crate::domain::plan::CurrentState::Same;
use crate::domain::rules;
use crate::domain::{
    Binding, Fleet, Health, ItemField, KeyState, Kind, Revision, Row, RuntimeChange,
    RuntimeSnapshot, SIMPLE_PRODUCT, SecretValue, StoreEntry, SyncPlan, TargetState, key_label,
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
    /// `PRODUCT/KEY` entries (`KEY` under the simple profile, FR-20): immutable keys to
    /// stage even though present on the target (FR-16).
    pub rotate: Vec<String>,
    /// `PRODUCT/KEY` entries (`KEY` under the simple profile): immutable keys `--prune` may
    /// unset (FR-8, FR-16). Without an
    /// entry an immutable key is never pruned. Requires `prune`.
    pub prune_immutable: Vec<String>,
    /// Write, prune and deploy only this product's managed names (P20).
    pub product: Option<String>,
    /// `--confirm <env>`: required when the environment sets `confirm_env` (NR-20).
    pub confirm: Option<String>,
    /// Print one JSON document (the run report) instead of text lines.
    pub json: bool,
}

impl SyncOpts {
    /// The `opv sync` command line these options spell, with `--confirm` when `confirm`.
    fn command(&self, env_name: &str, confirm: bool) -> String {
        let mut c = format!("opv sync {env_name}");
        if self.deploy {
            c.push_str(" --deploy");
        }
        if self.prune {
            c.push_str(" --prune");
        }
        for k in &self.rotate {
            c.push_str(&format!(" --rotate {k}"));
        }
        for k in &self.prune_immutable {
            c.push_str(&format!(" --prune-immutable {k}"));
        }
        if let Some(p) = &self.product {
            c.push_str(&format!(" --product {p}"));
        }
        if self.json {
            c.push_str(" --json");
        }
        if confirm {
            c.push_str(&format!(" --confirm {env_name}"));
        }
        c
    }
}

pub fn run(
    fleet: &Fleet,
    env_name: &str,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
    opts: &SyncOpts,
) -> Result<(), Error> {
    // Every check below happens before any subprocess call.
    let guarded = confirm_env(fleet, env_name, opts)?;
    check_product(fleet, opts.product.as_deref())?;
    let (t, ports) = open_target(fleet, env_name, r)?;
    let rotate = parse_rotate(fleet, env_name, &opts.rotate)?;
    let prune_immutable = parse_prune_immutable(fleet, env_name, opts)?;
    let scope = match &opts.product {
        Some(p) => Some(product_names(fleet, env_name, p)?),
        None => None,
    };
    let c = Ctx {
        fleet,
        env_name,
        t,
        r,
        opts,
        rotate: &rotate,
        prune_immutable: &prune_immutable,
        scope: scope.as_ref(),
        names: KeyNames::new(fleet, env_name)?,
    };
    let mut sink = std::io::sink();
    // `--json`: the detail lines are dropped and preflight warnings go to stderr, so stdout
    // is one document.
    let details: &mut dyn Write = if opts.json { &mut sink } else { &mut *out };
    let report = match &ports {
        Ports::Staged { store, runtime } => {
            run_staged(&c, &ports, store.as_ref(), runtime.as_ref(), details)?
        }
        Ports::Pinned { store, runtime } => {
            run_pinned(&c, &ports, store.as_ref(), runtime.as_ref(), details)?
        }
    };
    let next = report.next(env_name, opts, guarded);
    r.step_summary(&report.step_summary(env_name, opts, &c.names));
    if opts.json {
        return report.write_json(out, env_name, t, opts, &c.names, next.as_deref());
    }
    writeln!(out, "{}", report.summary()).map_err(write_err)?;
    if let Some(n) = next {
        write!(out, "{}", next_line(&n)).map_err(write_err)?;
    }
    Ok(())
}

/// NR-20: an environment with `confirm_env = true` syncs only with `--confirm <env>`; a
/// `--confirm` naming another environment is refused everywhere (a wrong-window typo).
/// Before any call. Returns whether the environment is guarded.
fn confirm_env(fleet: &Fleet, env_name: &str, opts: &SyncOpts) -> Result<bool, Error> {
    let env = fleet.environment(env_name)?;
    let rerun = || opts.command(env_name, true);
    match opts.confirm.as_deref() {
        Some(c) if c != env_name => Err(Error::Policy(
            format!("--confirm {c} does not match environment {env_name}; nothing was changed")
                .into(),
        )
        .with_code(Code::ConfirmMismatch)
        .with_next(rerun())),
        None if env.confirm_env => Err(Error::Policy(
            format!(
                "environment {env_name} is guarded (confirm_env = true): sync needs --confirm \
                 {env_name}; nothing was changed"
            )
            .into(),
        )
        .with_code(Code::ConfirmRequired)
        .with_do(format!(
            "confirm with the user that {env_name} is the environment to change"
        ))
        .with_next(rerun())),
        _ => Ok(env.confirm_env),
    }
}

/// One `sync` run's inputs, resolved before any call.
struct Ctx<'a> {
    fleet: &'a Fleet,
    env_name: &'a str,
    t: &'a dyn TargetConfig,
    r: &'a dyn CommandRunner,
    opts: &'a SyncOpts,
    rotate: &'a BTreeSet<(String, String)>,
    prune_immutable: &'a BTreeSet<(String, String)>,
    /// `--product`: that product's managed names; nothing else is written, pruned or
    /// unbound (P20).
    scope: Option<&'a HashSet<String>>,
    names: KeyNames,
}

impl Ctx<'_> {
    /// `plan` limited to `--product`, when given.
    fn scoped(&self, mut plan: SyncPlan) -> SyncPlan {
        if let (Some(p), Some(names)) = (&self.opts.product, self.scope) {
            scope_plan(&mut plan, p, names);
        }
        plan
    }

    fn in_scope(&self, name: &str) -> bool {
        self.scope.is_none_or(|s| s.contains(name))
    }
}

/// What one `sync` run did (NR-18): target names only, never a value. The same on every
/// provider; printed as the `summary:` line or as the `--json` document.
#[derive(Debug, Default)]
struct Report {
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
    /// What the deploy applied (S4): this run's writes and prunes, and names left
    /// pending by an earlier run.
    deployed_names: Vec<String>,
    /// Store names written by an earlier run and still waiting for a deploy when this run
    /// started (S4): why a run that wrote nothing deploys.
    earlier: Vec<String>,
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

    /// The CI job summary section (H8): the summary line and each list, names only.
    fn step_summary(&self, env_name: &str, opts: &SyncOpts, names: &KeyNames) -> String {
        let mut heading = format!("opv sync {env_name}");
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

    /// The command that finishes the job: a deploy for pending names, `--prune` for kept
    /// ones. `None` when nothing is left, or a deploy would not help (nothing to restart).
    fn next(&self, env_name: &str, opts: &SyncOpts, guarded: bool) -> Option<String> {
        if self.deploy_skipped || (self.pending.is_empty() && self.kept.is_empty()) {
            return None;
        }
        let o = SyncOpts {
            deploy: true,
            prune: opts.prune || !self.kept.is_empty(),
            rotate: Vec::new(),
            prune_immutable: Vec::new(),
            product: opts.product.clone(),
            confirm: None,
            json: false,
        };
        Some(o.command(env_name, guarded))
    }

    /// The run report as one document (A6, S4): every list holds `{product, key,
    /// target_name}` objects in the order of the summary line; `deployed_names` and
    /// `written_names` hold bare target names.
    fn write_json(
        &self,
        out: &mut dyn Write,
        env_name: &str,
        t: &dyn TargetConfig,
        opts: &SyncOpts,
        names: &KeyNames,
        next: Option<&str>,
    ) -> Result<(), Error> {
        let doc = serde_json::json!({
            "schema_version": crate::json::SCHEMA_VERSION,
            "environment": env_name,
            "provider": t.provider().section(),
            "product": opts.product,
            "written": names.json_refs(&self.written),
            "unchanged": names.json_refs(&self.unchanged),
            "held": names.json_refs(&self.held),
            "deployed": self.deployed.is_some(),
            "revision": self.deployed.as_deref().filter(|r| *r != DEPLOYED),
            "deploy_reason": self.deploy_reason(),
            "deployed_names": self.deployed_names,
            "pending": names.json_refs(&self.pending),
            "pruned": names.json_refs(&self.pruned),
            "kept": names.json_refs(&self.kept),
            "skipped": names.json_refs(&self.skipped),
            "written_names": self.written,
            "next": next,
        });
        writeln!(out, "{doc}").map_err(write_err)
    }
}

/// [`Report::deployed`] for a runtime that names no revision.
const DEPLOYED: &str = "yes";

/// Target names of the plan's rows that are not desired here (P2 `skipped`).
fn skipped_names(c: &Ctx<'_>, plan: &SyncPlan) -> Result<Vec<String>, Error> {
    let env = c.fleet.environment(c.env_name)?;
    Ok(plan
        .rows
        .iter()
        .filter(|r| r.state == KeyState::Skipped)
        .filter_map(|r| env.target_name(&r.product, &r.key))
        .collect())
}

/// Target names of the immutable keys held (present, not rotated).
fn held_names(c: &Ctx<'_>, plan: &SyncPlan) -> Result<Vec<String>, Error> {
    let env = c.fleet.environment(c.env_name)?;
    Ok(plan
        .held_immutable
        .iter()
        .filter_map(|(p, k)| env.target_name(p, k))
        .collect())
}

/// `sync` for a staged target (Fly, §6.4): stage, compare digests, deploy.
fn run_staged(
    c: &Ctx<'_>,
    ports: &Ports<'_>,
    store: &dyn StagedStore,
    runtime: &dyn StagedRuntime,
    out: &mut dyn Write,
) -> Result<Report, Error> {
    let (fleet, env_name, t, opts) = (c.fleet, c.env_name, c.t, c.opts);
    let (plan, list_a) = read_and_plan(
        fleet,
        env_name,
        c.r,
        Some(ports),
        c.rotate,
        c.prune_immutable,
    )?;
    let plan = c.scoped(plan);
    refuse_blocking(&plan, env_name)?;
    let batch: Vec<(String, &SecretValue)> =
        plan.stage.iter().map(|(n, v)| (n.clone(), v)).collect();
    store.validate(&batch)?;
    // Last read-only step before the first write (NR-23, NR-24).
    let skip_deploy = preflight::run(t, c.r, out, opts.json)?;
    print_extras(out, &plan)?;

    let label = t.provider().label();
    let names = &c.names;
    let mut report = Report {
        skipped: skipped_names(c, &plan)?,
        held: held_names(c, &plan)?,
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
        confirm(store, &batch, c.r, label, &done)?
    };
    for (name, _) in &batch {
        let (a, b) = (digest(&list_a, name), digest(&list_b, name));
        // A staged key with no digest after staging is unknown: count it as changed.
        if b.is_none() || a != b {
            report.written.push(name.clone());
        } else {
            report.unchanged.push(name.clone());
        }
    }

    let p = |out: &mut dyn Write, s: String| writeln!(out, "{s}").map_err(write_err);
    print_changes(out, names, &report)?;

    let mut pruned = Vec::new();
    if !plan.prune.is_empty() && opts.prune {
        p(out, format!("will prune: {}", names.join(&plan.prune)))?;
        store
            .remove(&plan.prune)
            .map_err(|e| after_writes(e, &done))?;
        done.push(format!("pruned {} name(s)", plan.prune.len()));
        p(out, format!("pruned: {}", names.join(&plan.prune)))?;
        pruned = plan.prune.clone();
    } else if !plan.prune.is_empty() {
        p(out, kept_line(names, &plan.prune))?;
        report.kept = plan.prune.clone();
    }
    print_held(out, fleet, &plan, names, &report.held)?;

    // Managed names still staged from an earlier run (e.g. a sync without --deploy, or a
    // failed deploy). Status is only an extra deploy trigger, never change detection.
    let managed = managed_names(fleet, env_name)?;
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
            runtime.deploy().map_err(|e| after_writes(e, &done))?;
            p(out, format!("deployed: {}", names.join(&waiting)))?;
            report.deployed = Some(DEPLOYED.into());
            report.deployed_names = waiting;
        }
        (false, false) => {
            p(out, pending_line(names, &waiting))?;
            report.pending = waiting;
        }
    }
    Ok(report)
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
    fleet: &Fleet,
    plan: &SyncPlan,
    names: &KeyNames,
    held: &[String],
) -> Result<(), Error> {
    let hint = key_ref_hint(fleet);
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
    ports: &Ports<'_>,
    store: &dyn PinnedStore,
    runtime: &dyn PinnedRuntime,
    out: &mut dyn Write,
) -> Result<Report, Error> {
    let (fleet, env_name, opts) = (c.fleet, c.env_name, c.opts);
    let names = &c.names;
    let fields = read_fields(fleet, env_name, c.r)?;
    // Blocking rows refuse before any call to the target.
    let copy = fields.iter().map(copy_field).collect();
    refuse_blocking(
        &c.scoped(plan_item(fleet, env_name, copy, None, c.rotate, c.prune_immutable)?.0),
        env_name,
    )?;
    // The target's state, read-only, before its first read (NR-23, NR-25).
    let skip_deploy = preflight::run(c.t, c.r, out, opts.json)?;
    let (plan, listed) = plan_item(
        fleet,
        env_name,
        fields,
        Some(ports),
        c.rotate,
        c.prune_immutable,
    )?;
    let plan = c.scoped(plan);
    refuse_blocking(&plan, env_name)?;
    let want = pinned_want(
        fleet,
        env_name,
        &plan,
        &listed,
        store,
        runtime.config_in_store(),
    )?;
    if !want.refused.is_empty() {
        let first = want.refused[0].split(' ').next().unwrap_or_default();
        return Err(Error::Policy(
            format!("sync refused, nothing staged: {}", want.refused.join(", ")).into(),
        )
        .with_code(Code::KeysBlocking)
        .with_do("fix the values named above in 1Password")
        .with_next(format!("opv explain {first} --env {env_name}")));
    }
    print_extras(out, &plan)?;
    let p = |out: &mut dyn Write, s: String| writeln!(out, "{s}").map_err(write_err);
    let mut report = Report {
        skipped: skipped_names(c, &plan)?,
        held: held_names(c, &plan)?,
        ..Report::default()
    };

    // 3. New store versions: not live until a revision binds them (FR-29).
    let mut written = BTreeMap::new();
    for (name, w) in &want.store {
        if let Some(value) = &w.write {
            let version = store.write_one(name, value).map_err(|e| {
                let done: Vec<&str> = written.keys().map(String::as_str).collect();
                with_note(e, &already_written(&done))
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
    let mut prune_set = prune_names(fleet, env_name, &plan, &listed, &want)?;
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
    print_held(out, fleet, &plan, names, &report.held)?;

    // 6. Deploy only with --deploy (FR-7, FR-9).
    let change = d.change(c.t, &written);
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
    let unbinding: Vec<&String> = change.unbind.iter().chain(deletes).collect();
    if !unbinding.is_empty() {
        p(out, format!("will prune: {}", names.join(unbinding)))?;
    }
    let revision = if !pending.is_empty() {
        let left = |now: &RuntimeSnapshot| change_names(&diff(now).change(c.t, &written));
        apply_reconciled(runtime, &change, &snap, &left, out)?
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
        .with_next(format!("opv status {env_name}")));
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
                 its secrets), then run the same command again",
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
    for name in want.store.keys() {
        if let Some(version) = bound.get(name.as_str()) {
            store.collect_superseded(name, version)?;
        }
    }
    let mut pruned: Vec<String> = change.unbind.clone();
    for name in deletes {
        store.delete(name).map_err(|e| {
            let done: Vec<&str> = pruned.iter().map(String::as_str).collect();
            with_note(e, &format!("already pruned: {}", none_or(&done)))
        })?;
        if !pruned.contains(name) {
            pruned.push(name.clone());
        }
    }
    if !pruned.is_empty() {
        p(out, format!("pruned: {}", names.join(&pruned)))?;
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
    env_name: &str,
    plan: &SyncPlan,
    listed: &[StoreEntry],
    want: &PinnedWant,
) -> Result<Vec<String>, Error> {
    let env = fleet.environment(env_name)?;
    let mut names = plan.prune.clone();
    for (product, p) in &fleet.products {
        for (key, spec) in &p.keys {
            let desired = plan
                .config
                .get(product)
                .is_some_and(|k| k.contains_key(key));
            let Some(name) = env.target_name(product, key) else {
                continue;
            };
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
/// bindings back: when they show the change, the run goes on with the revision they name;
/// otherwise the error stays `Unknown` (exit 9) and says what the read showed.
/// `left` names what a snapshot still lacks of the change.
fn apply_reconciled(
    runtime: &dyn PinnedRuntime,
    change: &RuntimeChange,
    snap: &RuntimeSnapshot,
    left: &dyn Fn(&RuntimeSnapshot) -> Vec<String>,
    out: &mut dyn Write,
) -> Result<Revision, Error> {
    let msg = match runtime.apply(change, snap) {
        Err(Error::Unknown(msg)) => msg,
        other => return other,
    };
    let still_unknown = |why: &str| {
        Error::Unknown(
            msg.clone()
                .map_text(|m| format!("{m}\n  read back: {why}; nothing pruned")),
        )
    };
    let Ok(now) = runtime.bindings() else {
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
pub(crate) fn pinned_want(
    fleet: &Fleet,
    env_name: &str,
    plan: &SyncPlan,
    listed: &[StoreEntry],
    store: &dyn PinnedStore,
    config_in_store: bool,
) -> Result<PinnedWant, Error> {
    let env = fleet.environment(env_name)?;
    let name_of = |p: &str, k: &str| env.target_name(p, k).unwrap_or_default();
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
    }
}

/// `err` with `note` (names only) on a line of its own, same category and next step.
fn with_note(err: Error, note: &str) -> Error {
    match err {
        e @ Error::Findings(..) => e,
        e => e.map_text(|m| format!("{m}\n  {note}")),
    }
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
/// command (NR-17).
fn refuse_blocking(plan: &SyncPlan, env_name: &str) -> Result<(), Error> {
    let blocking = row_names(&plan.rows, is_blocking);
    if blocking.is_empty() {
        return Ok(());
    }
    let keys: Vec<String> = plan
        .rows
        .iter()
        .filter(|r| is_blocking(r))
        .map(|r| key_label(&r.product, &r.key))
        .collect();
    Err(
        Error::Policy(format!("sync refused, nothing staged: {}", blocking.join(", ")).into())
            .with_code(Code::KeysBlocking)
            .with_do(format!("fix {} in 1Password", keys.join(", ")))
            .with_next(format!("opv explain {} --env {env_name}", keys[0])),
    )
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
    r: &dyn CommandRunner,
    label: &str,
    done: &[String],
) -> Result<Vec<StoreEntry>, Error> {
    let mut waited = Duration::ZERO;
    let mut delay = Duration::from_secs(1);
    loop {
        let list = store.list().map_err(|e| match e {
            Error::Unknown(_) => Error::Unknown(
                format!(
                    "{label} did not respond while confirming the staged secrets ({}); not \
                     confirmed",
                    done.join(", ")
                )
                .into(),
            ),
            e => after_writes(e, done),
        })?;
        let unseen = batch
            .iter()
            .filter(|(n, _)| digest(&list, n).is_none())
            .count();
        if unseen == 0 || waited >= CONFIRM_LIMIT {
            return Ok(list);
        }
        let d = delay.min(CONFIRM_LIMIT - waited);
        r.pause(
            d,
            &format!(
                "confirming {unseen} staged secret(s) on {label} ({} s)",
                waited.as_secs()
            ),
        );
        waited += d;
        delay *= 2;
    }
}

/// NR-10: a sign-in lost after this run's first write names what had completed. Other
/// errors already say what is known (NR-2).
fn after_writes(e: Error, done: &[String]) -> Error {
    match e {
        e @ Error::Auth(_) if !done.is_empty() => e.map_text(|m| {
            format!(
                "{m}\n  {} write(s) had completed: {}; re-running the same command is safe",
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
    check_product(fleet, product)?;
    // Needs a target: `Error::Config` naming the environment otherwise, before any call.
    let (t, ports) = open_target(fleet, env_name, r)?;
    // The target's state, read-only and never waiting (NR-23, NR-25).
    preflight::read(t, r)?;
    let none = BTreeSet::new();
    let (mut plan, on_target) = read_and_plan(fleet, env_name, r, Some(&ports), &none, &none)?;
    if let Some(p) = product {
        scope_plan(&mut plan, p, &product_names(fleet, env_name, p)?);
    }
    let n = plan.rows.iter().filter(|r| is_blocking(r)).count();
    // The 1Password link for the rows to fix (H1): one free `op whoami`, only when needed.
    let link = if n > 0 {
        Some(item_url(fleet, env_name, r)?)
    } else {
        None
    };
    let findings = || findings_error(n, &plan.rows, env_name);
    let held: BTreeSet<(&str, &str)> = plan
        .held_immutable
        .iter()
        .map(|(p, k)| (p.as_str(), k.as_str()))
        .collect();
    let word = |row: &Row| {
        target_word(
            row,
            held.contains(&(row.product.as_str(), row.key.as_str())),
            None,
        )
        .to_string()
    };
    let sync_next = SyncOpts {
        deploy: true,
        prune: !plan.prune.is_empty(),
        product: product.map(str::to_string),
        ..SyncOpts::default()
    }
    .command(env_name, fleet.environment(env_name)?.confirm_env);
    let verb = match ports {
        Ports::Staged { .. } => "stage",
        Ports::Pinned { .. } => "write",
    };
    let label = t.provider().label();
    let unmanaged = unmanaged_on_target(fleet, env_name, &on_target)?;
    let count = format!(
        "{env_name}: {} · {} · {} to {verb} · {} held (immutable) · {} to prune · {} unmanaged \
         on {label} (never touched)",
        plural(plan.rows.len(), "key", "keys"),
        plural(n, "finding", "findings"),
        plan.stage.len(),
        plan.held_immutable.len(),
        plan.prune.len(),
        unmanaged.len(),
    );
    let heading = match product {
        Some(p) => format!("opv plan {env_name} --product {p}"),
        None => format!("opv plan {env_name}"),
    };
    let changes = plan_changes(&plan);
    r.step_summary(&ci_summary::table(
        &heading,
        &count,
        Some(changes),
        &plan.rows,
        fleet.is_simple(),
        word,
    ));
    if json {
        write_json(
            out,
            fleet,
            env_name,
            &plan,
            None,
            product,
            Some(&sync_next),
            link.as_deref(),
        )?;
        return if n > 0 { Err(findings()) } else { Ok(()) };
    }
    let names = KeyNames::new(fleet, env_name)?;
    writeln!(out, "{count}").map_err(write_err)?;
    print_rows(out, fleet, &plan.rows, word, link.as_deref())?;
    let words: Vec<String> = plan.rows.iter().map(&word).collect();
    let words: Vec<&str> = words.iter().map(String::as_str).collect();
    print_legend(out, &words, label)?;
    print_extras(out, &plan)?;
    let mut line = |s: String| writeln!(out, "{s}").map_err(write_err);
    let staged: Vec<&str> = plan.stage.iter().map(|(n, _)| n.as_str()).collect();
    if !staged.is_empty() {
        // Findings block the sync, so nothing is staged until they are fixed (bug 10).
        let when = if n > 0 {
            " once the findings are fixed"
        } else {
            ""
        };
        line(format!("would {verb}{when}: {}", names.join(&staged)))?;
    }
    if !plan.prune.is_empty() {
        line(format!(
            "would prune (needs --prune): {}",
            names.join(&plan.prune)
        ))?;
    }
    let env = fleet.environment(env_name)?;
    let hint = key_ref_hint(fleet);
    let held_names: Vec<String> = plan
        .held_immutable
        .iter()
        .filter_map(|(p, k)| env.target_name(p, k))
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
            held_from_prune(&plan)
        ))?;
    }
    if n > 0 {
        return Err(findings());
    }
    write!(out, "{}", next_line(&sync_next)).map_err(write_err)
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

/// `product/KEY (TARGET_NAME)` (`KEY (TARGET_NAME)` under the simple profile) for every
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

/// `PRODUCT/KEY` under the fleet profile; `KEY` alone under the simple profile (FR-20),
/// whose implicit product is [`SIMPLE_PRODUCT`]. `None` when the entry has the wrong shape.
fn split_key_ref<'a>(fleet: &Fleet, entry: &'a str) -> Option<(&'a str, &'a str)> {
    if fleet.is_simple() {
        return (!entry.is_empty() && !entry.contains('/')).then_some((SIMPLE_PRODUCT, entry));
    }
    entry
        .split_once('/')
        .filter(|(p, k)| !p.is_empty() && !k.is_empty())
}

/// The expected shape of a `--rotate` / `--prune-immutable` entry, for errors.
fn expected(fleet: &Fleet) -> String {
    if fleet.is_simple() {
        "expected KEY (the simple profile has no products)".into()
    } else {
        "expected PRODUCT/KEY".into()
    }
}

/// The argument placeholder for `--prune-immutable` in hints.
fn key_ref_hint(fleet: &Fleet) -> &'static str {
    if fleet.is_simple() {
        "KEY"
    } else {
        "PRODUCT/KEY"
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
        let bad = |why: String| Error::Config(format!("--rotate {e:?}: {why}").into());
        let (product, key) =
            split_key_ref(fleet, e).ok_or_else(|| bad(expected(fleet)).with_code(Code::Usage))?;
        let spec = fleet
            .products
            .get(product)
            .and_then(|p| p.keys.get(key))
            .ok_or_else(|| bad("not a declared key".into()).with_code(Code::UndeclaredKey))?;
        if !spec.immutable {
            return Err(bad(
                "key is not immutable (other keys are staged on every sync)".into(),
            ));
        }
        if !rules::applies(spec, env_name, env, product) {
            return Err(bad(format!(
                "key is not desired in environment {env_name:?}"
            )));
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
        return Err(Error::Config(
            "--prune-immutable requires --prune (nothing is pruned without it)".into(),
        )
        .with_code(Code::Usage));
    }
    let mut set = BTreeSet::new();
    for e in &opts.prune_immutable {
        let bad = |why: String| Error::Config(format!("--prune-immutable {e:?}: {why}").into());
        let (product, key) =
            split_key_ref(fleet, e).ok_or_else(|| bad(expected(fleet)).with_code(Code::Usage))?;
        let spec = fleet
            .products
            .get(product)
            .and_then(|p| p.keys.get(key))
            .ok_or_else(|| bad("not a declared key".into()).with_code(Code::UndeclaredKey))?;
        if !spec.immutable {
            return Err(bad(
                "key is not immutable (other keys are pruned by --prune alone)".into(),
            ));
        }
        if rules::applies(spec, env_name, env, product) {
            return Err(bad(format!(
                "key is desired in environment {env_name:?}, so it is never pruned"
            )));
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
    fn fake_with(item: crate::runner::Output, fly_a: crate::runner::Output) -> FakeRunner {
        FakeRunner::new([item, fly_a])
    }
    /// item, list A, the two preflight reads, import, list B, then spare responses so an unexpected call (deploy,
    /// unset) is recorded rather than panicking, and the test can assert it never happened.
    fn fake_sync(
        item: crate::runner::Output,
        a: crate::runner::Output,
        b: crate::runner::Output,
    ) -> FakeRunner {
        let [st, rel] = fly_preflight_ok();
        FakeRunner::new([item, a, st, rel, ok(), b, ok(), ok(), ok()])
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
    fn sync_call_sequence_is_read_list_stage_list() {
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
            ]
        );
    }

    #[test]
    fn one_op_request_per_run() {
        let r = fake_complete();
        let _ = run(&f(), "prod", &r, &mut Vec::new(), &opts());
        assert_eq!(
            r.calls
                .borrow()
                .iter()
                .filter(|c| c.program == "op")
                .count(),
            1
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
        let r = FakeRunner::new([complete_item(), a(), st, rel, ok(), ok()]);
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
        // List B is polled until the 30 s limit (NR-30): six lists, then the deploy.
        let r = FakeRunner::new([complete_item(), b(), st, rel, ok()]);
        r.responses
            .borrow_mut()
            .extend((0..6).map(|_| Ok(b())).chain([Ok(ok())]));
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
            let e = run(&fl, "prod", &r, &mut Vec::new(), &o).unwrap_err();
            assert!(matches!(e, Error::Config(_)), "{bad}: {e}");
            assert!(e.to_string().contains(bad), "{bad}: {e}");
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
            assert!(matches!(e, Error::Config(_)), "{bad}: {e}");
            assert!(e.to_string().contains("--prune-immutable"), "{bad}: {e}");
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
        let fl = fleet_with("[environments.dev]\nvault_id = \"vdev\"\nitem_id = \"idev\"\n");
        let r = FakeRunner::new([]);
        let e = run(&fl, "dev", &r, &mut Vec::new(), &opts()).unwrap_err();
        assert!(
            matches!(&e, Error::Config(m) if m.contains("\"dev\"") && m.contains("fly")),
            "{e}"
        );
        let e = plan(&fl, "dev", &r, &mut Vec::new()).unwrap_err();
        assert!(
            matches!(&e, Error::Config(m) if m.contains("\"dev\"")),
            "{e}"
        );
        assert!(r.calls.borrow().is_empty());
    }

    // ---- failures -------------------------------------------------------------------

    #[test]
    fn unknown_env_is_config_error_before_any_call() {
        let r = FakeRunner::new([]);
        let e = run(&f(), "qa", &r, &mut Vec::new(), &opts()).unwrap_err();
        assert!(matches!(e, Error::Config(_)), "{e}");
        let e = plan(&f(), "qa", &r, &mut Vec::new()).unwrap_err();
        assert!(matches!(e, Error::Config(_)), "{e}");
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
        assert!(matches!(e, Error::Target(_)), "{e}");
        // The failed import is followed only by the login check (FR-26): no list B, no
        // unset, no deploy.
        assert_eq!(r.calls.borrow().len(), 6);
        assert_eq!(r.calls.borrow()[5].args, vec!["auth", "whoami"]);
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
    fn staged_after(status: Out) -> (FakeRunner, Result<(), Error>, String) {
        let r = after_list_a([status, fly_releases("complete")]);
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
                "outcome unknown: Fly did not respond after 3 attempts (fly status); nothing \
                 was changed. Check https://status.flyio.net, then re-run"
                    .to_string()
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
        r.responses
            .borrow_mut()
            .extend((0..6).map(|_| Ok(fly_empty())));
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
            Out::failure(1), // unset
            Out::failure(1), // auth whoami: signed out
        ]);
        let e = sync_err(&r);
        assert!(
            matches!(&e, Error::Auth(m) if m.ends_with(
                "1 write(s) had completed: staged 2 secret(s); re-running the same command is safe"
            )),
            "{e}"
        );
    }

    /// NR-17: a refusal names the next command, in one line.
    #[test]
    fn refusal_names_explain_as_the_next_command() {
        let r = fake_with(
            item_without("allumata", "OPENAI_API_KEY"),
            fly_with_prunable(),
        );
        let e = sync_err(&r);
        assert_eq!(
            e.next_step(),
            Some("opv explain allumata/OPENAI_API_KEY --env prod"),
            "{e}"
        );
    }
}
