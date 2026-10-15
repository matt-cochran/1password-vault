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
use crate::error::{Code, Error};
use crate::runner::CommandRunner;

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
        return Err(Error::Config(
            format!("{plan_id:?} is not a structural plan id (sp- and 16 hex digits)").into(),
        )
        .with_code(Code::Usage)
        .with_next("opv approve --help"));
    }
    let text = std::fs::read_to_string(&scope.path).map_err(|e| {
        Error::Config(format!("Cannot read {} ({}).", scope.path.display(), e.kind()).into())
    })?;
    let p = structure::plan(r, &text, &scope.project, &scope.account)?;
    if p.plan_id != plan_id {
        return Err(Error::Policy(
            format!(
                "plan {plan_id} is stale: the configuration, the account or what exists in \
                 1Password changed since it was prepared (the plan is now {}); nothing was \
                 approved",
                p.plan_id
            )
            .into(),
        )
        .with_code(Code::StalePlan)
        .with_do("ask the assistant to prepare and show the plan again, then approve the new id")
        .with_next(format!("opv approve {}", p.plan_id)));
    }
    if p.is_empty() {
        ui.show("nothing to approve: the structure is complete")?;
        return Ok(());
    }
    let (vaults, items, fields) = p.counts();
    ui.show(&format!(
        "structural plan {plan_id} for project {} in 1Password account {}: {vaults} vaults, \
         {items} items, {fields} empty fields",
        p.project, p.account_id
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
    ))
}

/// What an approved sync may do (0.9.0): the environment, its targets, an optional
/// product and the two flags. Rotation, immutable pruning and anything else stay with the
/// person's own `opv sync` in their terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncScope {
    pub env: String,
    /// Empty: every target of the environment.
    pub targets: Vec<String>,
    pub product: Option<String>,
    pub deploy: bool,
    pub prune: bool,
}

impl SyncScope {
    /// The approval's scope string; equal scopes give equal strings.
    pub fn key(&self) -> String {
        let mut targets = self.targets.clone();
        targets.sort();
        format!(
            "sync {} targets={} product={}{}{}",
            self.env,
            if targets.is_empty() {
                "*".to_string()
            } else {
                targets.join(",")
            },
            self.product.as_deref().unwrap_or("*"),
            if self.deploy { " deploy" } else { "" },
            if self.prune { " prune" } else { "" },
        )
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
    let res = super::sync::plan_targeted(
        fleet,
        &scope.env,
        &scope.targets,
        scope.product.as_deref(),
        r,
        &mut *buf,
        true,
    );
    let fail = |res: Result<(), Error>, why: &str| {
        res.err()
            .unwrap_or_else(|| Error::Config(why.to_string().into()))
    };
    let doc: serde_json::Value = match serde_json::from_slice(&buf) {
        Ok(d) => d,
        Err(_) => return Err(fail(res, "opv plan printed no plan")),
    };
    let Some(id) = doc["plan_id"].as_str().map(str::to_string) else {
        return Err(fail(res, "the plan has no id"));
    };
    Ok((id, doc))
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
        return Err(Error::Policy(
            format!(
                "plan {plan_id} is stale: the item, the target or the configuration changed (the \
                 plan is now {current}); nothing was approved"
            )
            .into(),
        )
        .with_code(Code::StalePlan)
        .with_do("ask the assistant to show the new plan, then approve the new id")
        .with_next(scope.approve_command(&current)));
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
    let changes: Vec<&serde_json::Value> = rows
        .iter()
        .filter(|r| match r["action"].as_str() {
            Some("would_stage") => true,
            Some("would_prune") => scope.prune,
            _ => false,
        })
        .collect();
    if changes.is_empty() {
        ui.show("  nothing to write: every managed name already matches")?;
    }
    for row in changes {
        ui.show(&format!(
            "  {} {}/{} on {}",
            match row["action"].as_str() {
                Some("would_prune") => "unset",
                _ => "write",
            },
            row["product"].as_str().unwrap_or("-"),
            row["key"].as_str().unwrap_or("?"),
            row["target"].as_str().unwrap_or("-"),
        ))?;
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
/// (`--expect-plan`), so nothing outside it is written. Rotation and immutable pruning are
/// never part of an approved sync.
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
        return Err(Error::Policy(
            format!(
                "plan {plan_id} is stale: the item, the target or the configuration changed (the \
                 plan is now {current}); nothing was changed and the approval was not used"
            )
            .into(),
        )
        .with_code(Code::StalePlan)
        .with_do(
            "show the person the new plan and ask them to approve its id in their own terminal",
        )
        .with_next(scope.approve_command(&current)));
    }
    consume(plan_id, &scope.key(), project, account, now).map_err(|e| {
        e.with_do("ask the person to approve this plan in their own terminal")
            .with_next(scope.approve_command(plan_id))
    })?;
    let opts = super::sync::SyncOpts {
        deploy: scope.deploy,
        prune: scope.prune,
        rotate: Vec::new(),
        prune_immutable: Vec::new(),
        product: scope.product.clone(),
        confirm: None,
        json,
        expect_plan: Some(plan_id.to_string()),
        receipt,
        targets: scope.targets.clone(),
    };
    super::sync::run(fleet, &scope.env, r, out, &opts)
}

#[cfg(test)]
#[path = "approve_tests.rs"]
mod tests;
