//! `opv approve <plan_id>` (#133): a person, in their own terminal, reviews the structural
//! plan an agent prepared (`opv_structure_plan`) and approves exactly that plan once.
//!
//! The command re-plans; an id that no longer matches is `stale_plan` and nothing is
//! recorded. It shows every step by name and asks the person to type the plan id back; any
//! other answer records nothing. The approval ([`crate::approval`]) is single-use, expires
//! after fifteen minutes, and names the project and 1Password account, so it applies to no
//! other plan, project or account. There is no flag that skips the question. It is a local
//! gate: the 1Password app's own authorization of each write stays the binding control.

use super::structure::{self, Scope};
use crate::cause::{
    Cause, EnvName, KeyName, PlanId, PlanScope, ProductKey, ProductName, TargetName, UsageProblem,
};
use crate::error::Error;
use crate::runner::CommandRunner;

/// `n` and its noun, `s` added unless `n` is 1 (05.33).
fn count(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

/// Stores one approval: plan id, project, account, now (unix seconds).
pub type Record<'a> = dyn FnMut(&str, &str, &str, u64) -> Result<(), Error> + 'a;

/// Stores or uses up one scoped approval: plan id, scope key, project, account, now.
pub type Scoped<'a> = dyn FnMut(&str, &str, &str, &str, u64) -> Result<(), Error> + 'a;

/// The person's side of the review.
pub trait Review {
    fn show(&mut self, line: &str) -> Result<(), Error>;
    /// The answer typed to `question`, trimmed.
    fn ask(&mut self, question: &str) -> Result<String, Error>;
}

/// Review and approve `plan_id` for `scope`; `record` stores the approval (the real store,
/// or a test's). `now` is unix seconds.
pub fn run(
    r: &dyn CommandRunner,
    scope: &Scope,
    plan_id: &str,
    now: u64,
    ui: &mut dyn Review,
    record: &mut Record<'_>,
) -> Result<(), Error> {
    if !structure::is_plan_id(plan_id) {
        return Err(not_structural(plan_id));
    }
    let text = std::fs::read_to_string(&scope.path).map_err(|e| {
        crate::config_store::unreadable(&scope.path, &e, crate::cause::GivenBy::Discovered)
    })?;
    let p = structure::plan(r, &text, &scope.project, &scope.account)?;
    if p.plan_id != plan_id {
        return Err(structure::changed(plan_id, &p.plan_id));
    }
    if p.is_empty() {
        ui.show("nothing to approve: the structure is complete")?;
        return Ok(());
    }
    let (vaults, items, fields) = p.counts();
    ui.show(&format!(
        "structural plan {plan_id} for project {} in 1Password account {}: {}, {}, {}",
        p.project,
        p.account_id,
        count(vaults, "vault"),
        count(items, "item"),
        count(fields, "empty field"),
    ))?;
    for line in structure::describe(&p) {
        ui.show(&format!("  {line}"))?;
    }
    if p.generated {
        ui.show(&format!(
            "  {} is generated: its IDs are returned for its generator, the file is not changed",
            scope.path.display()
        ))?;
    }
    ui.show(
        "Approving lets the assistant create exactly this, once, within 15 minutes; the \
         1Password app still asks you to authorize each change. No value is read or written.",
    )?;
    let answer = ui.ask(&format!(
        "Type {plan_id} to approve it, or press Enter to cancel:"
    ))?;
    if answer != plan_id {
        ui.show("not approved; nothing was recorded")?;
        return Ok(());
    }
    record(plan_id, &scope.project, &scope.account, now)?;
    ui.show(&format!(
        "approved {plan_id} (single use, 15 minutes); the assistant can apply it now"
    ))?;
    // 05.33: the CLI path too; the plan id is the approved one, never an approval flag.
    ui.show(&format!(
        "Next: {} (or let the assistant apply it)",
        crate::cause::render::cmd_text(&crate::cause::Cmd {
            command: vec!["structure".into(), "apply".into()],
            args: vec![plan_id.to_string()],
        })
    ))
}

/// `plan_id` is not a structural plan id: a sync plan id is approved with `--sync` and the
/// scope the assistant named (05.24), anything else is the wrong form.
/// 09.27: a malformed structural plan id is a usage error, checked before anything asks
/// for a terminal.
pub fn check_structural_id(plan_id: &str) -> Result<(), Error> {
    if structure::is_plan_id(plan_id) {
        Ok(())
    } else {
        Err(not_structural(plan_id))
    }
}

fn not_structural(plan_id: &str) -> Error {
    let problem = if crate::approval::is_sync_id(plan_id) {
        UsageProblem::NeedsFlag {
            flag: format!("sync plan id {plan_id}"),
            needs: "--sync <env> and the same --target, --product, --rotate, --deploy and \
                    --prune the assistant named"
                .into(),
        }
    } else {
        UsageProblem::ValueFormat {
            flag: "the plan id".into(),
            format: crate::approval::PLAN_ID_FORMAT,
        }
    };
    Cause::Usage { problem }.into()
}

/// What an approved sync may do (0.9.0): the environment, its targets, an optional
/// product, the two flags and the `--rotate` set. Immutable pruning and anything else stay
/// with the person's own `opv sync` in their terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncScope {
    pub env: String,
    /// Empty: every target of the environment.
    pub targets: Vec<String>,
    pub product: Option<String>,
    pub deploy: bool,
    pub prune: bool,
    /// `PRODUCT/KEY` entries this sync rotates (FR-16). Part of the scope key, so an
    /// approval recorded without rotation never covers a rotating sync (and the reverse).
    pub rotate: Vec<String>,
}

impl SyncScope {
    /// The approval's scope string; equal scopes give equal strings. The rotate set is
    /// sorted, so its order never changes the key.
    pub fn key(&self) -> String {
        let mut targets = self.targets.clone();
        targets.sort();
        let mut rotate = self.rotate.clone();
        rotate.sort();
        let rot = if rotate.is_empty() {
            String::new()
        } else {
            format!(" rotate={}", rotate.join(","))
        };
        format!(
            "sync {} targets={} product={}{}{}{}",
            self.env,
            if targets.is_empty() {
                "*".to_string()
            } else {
                targets.join(",")
            },
            self.product.as_deref().unwrap_or("*"),
            if self.deploy { " deploy" } else { "" },
            if self.prune { " prune" } else { "" },
            rot,
        )
    }

    /// The typed scope a step built from this approval carries (X1: every scope flag).
    pub fn plan_scope(&self) -> PlanScope {
        let mut rotate: Vec<ProductKey> = self
            .rotate
            .iter()
            .filter_map(|k| {
                k.split_once('/').map(|(p, k)| ProductKey {
                    product: ProductName::new(p),
                    key: KeyName::new(k),
                })
            })
            .collect();
        rotate.sort_by_key(ToString::to_string);
        PlanScope::Sync {
            env: EnvName::new(&self.env),
            targets: self.targets.iter().map(TargetName::new).collect(),
            product: self.product.as_deref().map(ProductName::new),
            deploy: self.deploy,
            prune: self.prune,
            rotate,
        }
    }

    /// The `opv approve` command a person runs for this scope and plan.
    pub fn approve_command(&self, plan_id: &str) -> String {
        let mut c = format!("opv approve {plan_id} --sync {}", self.env);
        for t in &self.targets {
            c.push_str(&format!(" --target {t}"));
        }
        if let Some(p) = &self.product {
            c.push_str(&format!(" --product {p}"));
        }
        let mut rotate = self.rotate.clone();
        rotate.sort();
        for k in &rotate {
            c.push_str(&format!(" --rotate {k}"));
        }
        if self.deploy {
            c.push_str(" --deploy");
        }
        if self.prune {
            c.push_str(" --prune");
        }
        c
    }
}

/// The current sync plan of `scope` (`opv plan --json`): its id and its rows.
pub fn sync_plan(
    fleet: &crate::domain::Fleet,
    scope: &SyncScope,
    r: &dyn CommandRunner,
) -> Result<(String, serde_json::Value), Error> {
    let mut buf = zeroize::Zeroizing::new(Vec::new());
    // A plan with findings still prints its document; only the id matters here.
    let res = super::sync::plan_rotating(
        fleet,
        &scope.env,
        &scope.targets,
        scope.product.as_deref(),
        &scope.rotate,
        r,
        &mut *buf,
        true,
    );
    // The plan's own failure when it has one; a plan that printed no id is opv's bug.
    let fail = |res: Result<(), Error>, site: &'static str| {
        res.err().unwrap_or_else(|| Cause::Bug { site }.into())
    };
    let doc: serde_json::Value = match serde_json::from_slice(&buf) {
        Ok(d) => d,
        Err(_) => return Err(fail(res, "approve: opv plan printed no plan")),
    };
    let Some(id) = doc["plan_id"].as_str().map(str::to_string) else {
        return Err(fail(res, "approve: the sync plan has no id"));
    };
    Ok((id, doc))
}

/// The review of a sync plan's rows (05.16): each write or unset, each row held back
/// (immutable), and each row whose value is not ready, which the sync refuses until it is
/// fixed. "Nothing to write" is said only when every row is ready and nothing is held.
fn review_lines(rows: &[serde_json::Value], prune: bool) -> Vec<String> {
    let s = |row: &serde_json::Value, f: &str, or: &'static str| -> String {
        row[f].as_str().unwrap_or(or).to_string()
    };
    let name = |row: &serde_json::Value| {
        format!(
            "{}/{} on {}",
            s(row, "product", "-"),
            s(row, "key", "?"),
            s(row, "target", "-")
        )
    };
    let mut writes = Vec::new();
    let mut held = Vec::new();
    let mut blocked = Vec::new();
    for row in rows {
        match row["action"].as_str() {
            Some("would_stage") => writes.push(format!(
                "  {} {}",
                if row["rotate"].as_bool() == Some(true) {
                    "rotate"
                } else {
                    "write"
                },
                name(row)
            )),
            Some("would_prune") if prune => writes.push(format!("  unset {}", name(row))),
            Some("held") => held.push(format!(
                "  held {}: immutable, so this sync leaves it as it is",
                name(row)
            )),
            _ => {}
        }
        match row["state"].as_str() {
            None | Some("saved") | Some("skipped") => {}
            Some(state) => blocked.push(format!(
                "  {} {}/{}: the sync is refused until it is fixed in 1Password",
                state.replace('_', " "),
                s(row, "product", "-"),
                s(row, "key", "?"),
            )),
        }
    }
    blocked.dedup();
    let mut out = Vec::new();
    if writes.is_empty() {
        out.push(if held.is_empty() && blocked.is_empty() {
            "  nothing to write: every managed name already matches".to_string()
        } else {
            "  nothing to write".to_string()
        });
    }
    out.extend(writes);
    out.extend(held);
    out.extend(blocked);
    out
}

/// `opv approve <plan_id> --sync <env> …`: review the current sync plan of `scope` and
/// approve exactly it, once, for 15 minutes.
#[allow(clippy::too_many_arguments)]
pub fn run_sync(
    r: &dyn CommandRunner,
    fleet: &crate::domain::Fleet,
    project: &str,
    account: &str,
    scope: &SyncScope,
    plan_id: &str,
    now: u64,
    ui: &mut dyn Review,
    record: &mut Scoped<'_>,
) -> Result<(), Error> {
    let (current, doc) = sync_plan(fleet, scope, r)?;
    if current != plan_id {
        return Err(sync_changed(plan_id, &current, scope));
    }
    ui.show(&format!(
        "sync plan {plan_id} for {} in project {project}{}{}:",
        scope.env,
        if scope.deploy { ", then deploy" } else { "" },
        if scope.prune {
            ", pruning managed names no longer declared"
        } else {
            ""
        },
    ))?;
    let rows = doc["rows"].as_array().cloned().unwrap_or_default();
    for line in review_lines(&rows, scope.prune) {
        ui.show(&line)?;
    }
    ui.show(
        "Approving lets the assistant run exactly this sync once, within 15 minutes; any \
         change to the item, the target or the configuration voids it. No value is shown.",
    )?;
    let answer = ui.ask(&format!(
        "Type {plan_id} to approve it, or press Enter to cancel:"
    ))?;
    if answer != plan_id {
        ui.show("not approved; nothing was recorded")?;
        return Ok(());
    }
    record(plan_id, &scope.key(), project, account, now)?;
    ui.show(&format!(
        "approved sync plan {plan_id} (single use, 15 minutes)"
    ))
}

/// The agent's side of an approved sync (0.9.0): run exactly the sync plan `plan_id` of
/// `scope`, which a person approved with `opv approve <plan_id> --sync …` in their own
/// terminal. A plan that changed since is refused before the approval is used (the person
/// approves the new id); then the approval is used up, and the sync runs bound to the plan
/// (`--expect-plan`), so nothing outside it is written. The scope's `--rotate` set is part
/// of the plan id and of the approval key; immutable pruning is never part of an approved
/// sync.
#[allow(clippy::too_many_arguments)]
pub fn run_approved_sync(
    fleet: &crate::domain::Fleet,
    scope: &SyncScope,
    plan_id: &str,
    project: &str,
    account: &str,
    now: u64,
    r: &dyn CommandRunner,
    out: &mut dyn std::io::Write,
    json: bool,
    receipt: Option<std::path::PathBuf>,
    consume: &mut Scoped<'_>,
) -> Result<(), Error> {
    let (current, _) = sync_plan(fleet, scope, r)?;
    if current != plan_id {
        return Err(sync_changed(plan_id, &current, scope));
    }
    // A refusal is typed by the approval store with this scope (approval_required: a
    // person approves; approval_used: a read of what remains).
    consume(plan_id, &scope.key(), project, account, now)?;
    let opts = super::sync::SyncOpts {
        deploy: scope.deploy,
        prune: scope.prune,
        rotate: scope.rotate.clone(),
        prune_immutable: Vec::new(),
        product: scope.product.clone(),
        confirm: None,
        json,
        expect_plan: Some(plan_id.to_string()),
        receipt,
        targets: scope.targets.clone(),
    };
    super::sync::run(fleet, &scope.env, r, out, &opts)
        .map_err(|e| after_used_approval(e, plan_id, scope))
}

/// The sync plan `plan_id` of `scope` is now `current`: nothing was approved or used, and
/// the read of the new plan carries every scope flag.
fn sync_changed(plan_id: &str, current: &str, scope: &SyncScope) -> Error {
    Cause::PlanChanged {
        old: PlanId::new(plan_id),
        new: PlanId::new(current),
        scope: scope.plan_scope(),
    }
    .into()
}

/// A failure after the approval was used up (X4, X20): whatever ran may have written, and the
/// approval never applies again, so the next step is the read of what remains in the same
/// scope, never `--approved` again. A cataloged cause keeps its message and evidence inside
/// `Partial`; one not yet cataloged is reported as the used approval.
fn after_used_approval(e: Error, plan_id: &str, scope: &SyncScope) -> Error {
    let plan = PlanId::new(plan_id);
    match e {
        Error::Catalog(cause, upstream) => {
            let cause = match *cause {
                Cause::ApprovalUsed { .. } => *cause,
                Cause::Partial { done, then, .. } => Cause::Partial {
                    done,
                    approval_used: Some(plan),
                    approval_scope: Some(scope.plan_scope()),
                    then,
                },
                then => Cause::Partial {
                    done: Vec::new(),
                    approval_used: Some(plan),
                    approval_scope: Some(scope.plan_scope()),
                    then: Box::new(then),
                },
            };
            Error::Catalog(Box::new(cause), upstream)
        }
        _ => Cause::ApprovalUsed {
            plan,
            scope: scope.plan_scope(),
            partial: false,
        }
        .into(),
    }
}

#[cfg(test)]
#[path = "approve_tests.rs"]
mod tests;
