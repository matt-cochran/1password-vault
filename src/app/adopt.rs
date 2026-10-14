//! `opv adopt <env> --from <dotenv>|target:<name> [--replace <product/KEY>]... [--apply]
//! [--json]` (FR-53, #78): bring values that already exist elsewhere into the environment's
//! 1Password item, after a review. The plan is [`crate::domain::adopt::plan`]; this module
//! reads the source, prints the plan (names, actions and findings only) and, with `--apply`,
//! writes it into each key's boundary item, one verified edit per item. It never syncs,
//! deploys, prunes, revokes or deletes the source. The bare `--from target` form was
//! removed (FR-60): `--from target:<name>` names the target one way only.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::PathBuf;

use super::write_err;
use crate::adapters::{onepassword, onepassword_tidy};
use crate::domain::adopt::{Action, AdoptPlan};
use crate::domain::convention::{self, KEPT_SECTION, Op, TidyPlan};
use crate::domain::{Boundary, Fleet, Kind, SecretValue, key_label};
use crate::error::{Code, Error};
use crate::ports::Ports;
use crate::runner::CommandRunner;

/// Where the values come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// A dotenv file the owner points at (literal assignments, never executed).
    Dotenv(PathBuf),
    /// The named target of the environment, where it can read values back.
    Target(String),
}

/// The [`Source`] named by `--from <value>` (FR-53, FR-56, FR-60): a dotenv file path, or
/// `target:<name>` for the named target of `env_name`. The bare `target` form was removed
/// and is a usage error that names the environment's targets and the `target:<name>` form.
pub fn source_from(fleet: &Fleet, env_name: &str, from: &str) -> Result<Source, Error> {
    if let Some(name) = from.strip_prefix("target:") {
        if name.is_empty() {
            return Err(bare_target(fleet, env_name));
        }
        super::target(fleet, env_name, name)?;
        return Ok(Source::Target(name.to_string()));
    }
    if from == "target" {
        return Err(bare_target(fleet, env_name));
    }
    Ok(Source::Dotenv(PathBuf::from(from)))
}

/// The usage error for the removed bare `--from target` (FR-60): it names the environment's
/// targets and the one form that works, `--from target:<name>`.
fn bare_target(fleet: &Fleet, env_name: &str) -> Error {
    match super::resolve_targets(fleet, env_name, &[], "adopt") {
        Ok(names) => Error::Config(
            format!(
                "--from target needs a target's name; write --from target:<name> \
                 (targets: {})",
                names.join(", ")
            )
            .into(),
        )
        .with_code(Code::Usage)
        .with_next(format!("opv adopt {env_name} --from target:{}", names[0])),
        Err(e) => e,
    }
}

/// Options of `opv adopt`.
#[derive(Debug, Clone)]
pub struct Opts {
    pub source: Source,
    /// `product/KEY` to replace a differing value.
    pub replace: Vec<String>,
    /// Immutable keys `--replace` may change.
    pub rotate: Vec<String>,
    /// `product/KEY` (or `KEY`) left out of the import (#94).
    pub skip: Vec<String>,
    pub apply: bool,
    pub json: bool,
}

/// `product/KEY` entries as `(product, key)` pairs, each declared.
fn pairs(
    fleet: &Fleet,
    entries: &[String],
    flag: &str,
) -> Result<BTreeSet<(String, String)>, Error> {
    entries
        .iter()
        .map(|e| {
            let (p, k) = match e.split_once('/') {
                Some((p, k)) => (p.to_string(), k.to_string()),
                None => {
                    return Err(Error::Config(
                        format!("{flag} {e:?}: write product/KEY").into(),
                    ));
                }
            };
            if fleet
                .products
                .get(&p)
                .is_none_or(|prod| !prod.keys.contains_key(&k))
            {
                return Err(Error::Config(
                    format!("{flag} {e:?}: not a declared key").into(),
                ));
            }
            Ok((p, k))
        })
        .collect()
}

/// The found values: the dotenv file, or what the target can read back. A target that
/// cannot show values (Fly secrets, GitHub secrets) is refused with the manual way.
fn read_source(
    fleet: &Fleet,
    env_name: &str,
    source: &Source,
    r: &dyn CommandRunner,
) -> Result<BTreeMap<String, SecretValue>, Error> {
    match source {
        Source::Dotenv(path) => super::setup::read_legacy(path),
        Source::Target(name) => {
            let (t, ports) = super::open_target(fleet, env_name, name, r)?;
            let label = t.provider().label();
            match &ports {
                Ports::Pinned { store, .. } => {
                    let mut found = BTreeMap::new();
                    for managed in super::managed_names(fleet, env_name, name)? {
                        if let Some((value, _)) = store.read(&managed)? {
                            found.insert(managed, value);
                        }
                    }
                    Ok(found)
                }
                Ports::Staged { store, .. } => match store.variables() {
                    Some(v) => Ok(v
                        .list()?
                        .into_iter()
                        .map(|(n, val)| (n, SecretValue::new(val)))
                        .collect()),
                    None => Err(Error::Policy(
                        format!(
                            "{label} never shows a stored secret's value, so opv cannot adopt \
                             from it; nothing was read"
                        )
                        .into(),
                    )
                    .with_code(Code::PolicyRefused)
                    .with_do(format!(
                        "put the values in a private dotenv file (chmod 600) from where you \
                         keep them today, or type them in 1Password; {label} keeps working \
                         with its current secrets until you sync"
                    ))
                    .with_next(format!("opv adopt {env_name} --from <file.env>"))),
                },
            }
        }
    }
}

/// `opv adopt`: the plan, and with `apply` the verified write.
pub fn run(
    fleet: &Fleet,
    env_name: &str,
    opts: &Opts,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let replace = pairs(fleet, &opts.replace, "--replace")?;
    let rotate = pairs(fleet, &opts.rotate, "--rotate")?;
    let skip = pairs(fleet, &opts.skip, "--skip")?;
    let plan = plan_skipping(
        fleet,
        env_name,
        &opts.source,
        (&replace, &rotate, &skip),
        opts.apply,
        r,
    )?;
    print(out, env_name, opts, &plan)
}

/// The three key sets of `opv adopt`: `--replace`, `--rotate`, `--skip`.
type KeySets<'a> = (
    &'a BTreeSet<(String, String)>,
    &'a BTreeSet<(String, String)>,
    &'a BTreeSet<(String, String)>,
);

/// [`plan_and_write`] with `--skip`: an import of a key it names becomes `Skipped` and is
/// not written (#94). Only imports are skipped; a replace is already opt-in.
fn plan_skipping(
    fleet: &Fleet,
    env_name: &str,
    source: &Source,
    (replace, rotate, skip): KeySets<'_>,
    apply: bool,
    r: &dyn CommandRunner,
) -> Result<AdoptPlan, Error> {
    let mut plan = plan_and_write(fleet, env_name, source, replace, rotate, false, r)?;
    let named = |p: &Option<String>, k: &Option<String>| match (p, k) {
        (Some(p), Some(k)) => skip.contains(&(p.clone(), k.clone())),
        _ => false,
    };
    for row in &mut plan.rows {
        if row.action == Action::Import && named(&row.product, &row.key) {
            row.action = Action::Skipped;
        }
    }
    plan.writes
        .retain(|(p, k, _)| !skip.contains(&(p.clone(), k.clone())));
    if apply {
        super::tidy::require_person(r, "opv adopt --apply")?;
        if !plan.writes.is_empty() {
            write(fleet, fleet.environment(env_name)?, &plan, r)?;
        }
    }
    Ok(plan)
}

/// The adoption plan for `source`, written (one verified item edit) when `apply`. Also the
/// import step of `opv init --from … --apply` (#90).
pub fn plan_and_write(
    fleet: &Fleet,
    env_name: &str,
    source: &Source,
    replace: &BTreeSet<(String, String)>,
    rotate: &BTreeSet<(String, String)>,
    apply: bool,
    r: &dyn CommandRunner,
) -> Result<AdoptPlan, Error> {
    let env = fleet.environment(env_name)?;
    if apply {
        super::tidy::require_person(r, "opv adopt --apply")?;
    }
    let found = read_source(fleet, env_name, source, r)?;
    // The item as the commands read it (tidied first when a person runs opv).
    let read = super::tidy::read(fleet, env_name, r)?;
    let plan = crate::domain::adopt::plan(fleet, env_name, &read.fields, &found, replace, rotate);
    if apply && !plan.writes.is_empty() {
        write(fleet, env, &plan, r)?;
    }
    Ok(plan)
}

/// Write `plan.writes` in one item edit per boundary item (FR-57), each value into its
/// key's boundary, keeping a replaced value in `opv · kept`, then read each item back and
/// verify every written field holds what was written.
fn write(
    fleet: &Fleet,
    env: &crate::domain::Environment,
    plan: &AdoptPlan,
    r: &dyn CommandRunner,
) -> Result<(), Error> {
    let mut by_boundary: BTreeMap<&str, Vec<&(String, String, SecretValue)>> = BTreeMap::new();
    for w in &plan.writes {
        by_boundary
            .entry(fleet.boundary_of(&w.0))
            .or_default()
            .push(w);
    }
    for (name, writes) in by_boundary {
        let b = fleet.boundary(&env.name, &writes[0].0)?;
        let part = super::tidy::in_boundary(fleet, name);
        write_item(&part, env, b, &writes, r)?;
    }
    Ok(())
}

/// [`write`] into one boundary item `b`, holding `fleet`'s products.
fn write_item(
    fleet: &Fleet,
    env: &crate::domain::Environment,
    b: &Boundary,
    writes: &[&(String, String, SecretValue)],
    r: &dyn CommandRunner,
) -> Result<(), Error> {
    let item = onepassword::read_whole_fresh(r, env, b)?;
    let (layout, _) = onepassword_tidy::parse(item.raw())?;
    let res = convention::resolve(&layout, fleet);
    let date = super::tidy::today();
    let mut ops = Vec::new();
    let mut kept = false;
    for (product, key, value) in writes.iter().copied() {
        let id = (product.clone(), key.clone());
        let kind = fleet.products[product].keys[key].kind;
        match res.chosen.get(&id) {
            Some(&i) => {
                let old = &layout.fields[i].value;
                if !old.expose().is_empty() {
                    ops.push(Op::Add {
                        section: Some(KEPT_SECTION.to_string()),
                        label: format!(
                            "{} (replaced by opv adopt, {date})",
                            key_label(product, key)
                        ),
                        concealed: true,
                        value: Some(SecretValue::new(old.expose().to_string())),
                    });
                    kept = true;
                }
                ops.push(Op::SetValue {
                    index: i,
                    value: SecretValue::new(value.expose().to_string()),
                });
            }
            None => ops.push(Op::Add {
                section: Some(product.clone()),
                label: key.clone(),
                concealed: kind == Kind::Secret,
                value: Some(SecretValue::new(value.expose().to_string())),
            }),
        }
    }
    let tidy = TidyPlan {
        ops,
        changes: Vec::new(),
        kept,
    };
    let template = onepassword_tidy::apply(item.raw(), &tidy)?;
    onepassword_tidy::write(r, env, b, &template)?;
    // Verify by reading back: every written field holds exactly what was written.
    let after = onepassword::read_whole_fresh(r, env, b)?;
    let (layout, _) = onepassword_tidy::parse(after.raw())?;
    let res = convention::resolve(&layout, fleet);
    let missing: Vec<String> = writes
        .iter()
        .copied()
        .filter(|(p, k, v)| {
            res.chosen
                .get(&(p.clone(), k.clone()))
                .is_none_or(|&i| layout.fields[i].value.expose() != v.expose())
        })
        .map(|(p, k, _)| key_label(p, k))
        .collect();
    if !missing.is_empty() {
        return Err(Error::Unknown(
            format!(
                "1Password does not show what opv adopt wrote for {}; re-run the same command \
                 to retry (the plan is recomputed from what is there)",
                missing.join(", ")
            )
            .into(),
        ));
    }
    Ok(())
}

/// Text: a count line, one line per row (names and the action word), the next step.
/// JSON: `{environment, applied, rows: [{found, product, key, action, rule}], counts, next}`.
fn print(out: &mut dyn Write, env_name: &str, opts: &Opts, plan: &AdoptPlan) -> Result<(), Error> {
    let label = |p: &Option<String>, k: &Option<String>| match (p, k) {
        (Some(p), Some(k)) => key_label(p, k),
        _ => "-".into(),
    };
    let count = |a: fn(&Action) -> bool| plan.rows.iter().filter(|r| a(&r.action)).count();
    let writes = plan.writes.len();
    let decide = count(|a| matches!(a, Action::Differs | Action::Conflict | Action::Ambiguous));
    let next = if opts.apply || writes == 0 {
        format!("opv ready {env_name}")
    } else {
        let mut c = format!("opv adopt {env_name}");
        match &opts.source {
            Source::Dotenv(p) => c.push_str(&format!(" --from {}", p.display())),
            Source::Target(name) => c.push_str(&format!(" --from target:{name}")),
        }
        for e in &opts.replace {
            c.push_str(&format!(" --replace {e}"));
        }
        c.push_str(" --apply");
        c
    };
    if opts.json {
        let rows: Vec<serde_json::Value> = plan
            .rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "found": r.found,
                    "product": r.product,
                    "key": r.key,
                    "action": r.action.word(),
                    "rule": match r.action { Action::FailsRule(rule) => Some(rule), _ => None },
                })
            })
            .collect();
        let v = serde_json::json!({
            "schema_version": crate::json::SCHEMA_VERSION,
            "environment": env_name,
            "applied": opts.apply,
            "rows": rows,
            "writes": writes,
            "decisions_needed": decide,
            "next": next,
        });
        return writeln!(out, "{v}").map_err(write_err);
    }
    let verb = if opts.apply { "written" } else { "to write" };
    writeln!(
        out,
        "{env_name}: {} found · {writes} {verb} · {decide} need a decision",
        plan.rows.len()
    )
    .map_err(write_err)?;
    for r in &plan.rows {
        let what = match r.action {
            Action::Match => "same value; nothing to do".to_string(),
            Action::FormatOnly => "same value after the key's rules; nothing to do".to_string(),
            Action::Import => format!("import ({verb})"),
            Action::Replace => format!("replace; the old value is kept in {KEPT_SECTION} ({verb})"),
            Action::Differs => format!(
                "differs: 1Password is kept (--replace {} to take the found value)",
                label(&r.product, &r.key)
            ),
            Action::HeldImmutable => "immutable: also needs --rotate to replace".to_string(),
            Action::FailsRule(rule) => format!("fails rule {rule}: not imported"),
            Action::Conflict => {
                "found copies differ: decide which is right in 1Password".to_string()
            }
            Action::Ambiguous => "matches several declared keys: not imported".to_string(),
            Action::NotDeclared => "not declared: ignored".to_string(),
            Action::NotApplicable => "not required in this environment: ignored".to_string(),
            Action::Skipped => "skipped (--skip): not imported".to_string(),
        };
        writeln!(
            out,
            "  {:<32} {what}  (from {})",
            label(&r.product, &r.key),
            r.found.join(", ")
        )
        .map_err(write_err)?;
    }
    writeln!(out, "Next: {next}").map_err(write_err)
}

#[cfg(test)]
#[path = "adopt_tests.rs"]
mod tests;
