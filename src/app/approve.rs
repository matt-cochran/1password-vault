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

#[cfg(test)]
#[path = "approve_tests.rs"]
mod tests;
