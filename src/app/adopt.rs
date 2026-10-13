//! `opv adopt <env> --from <dotenv>|target [--replace <product/KEY>]... [--apply] [--json]`
//! (FR-53, #78): bring values that already exist elsewhere into the environment's 1Password
//! item, after a review. The plan is [`crate::domain::adopt::plan`]; this module reads the
//! source, prints the plan (names, actions and findings only) and, with `--apply`, writes
//! it in one verified item edit. It never syncs, deploys, prunes, revokes or deletes the
//! source.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::PathBuf;

use super::write_err;
use crate::adapters::{onepassword, onepassword_tidy};
use crate::domain::adopt::{Action, AdoptPlan};
use crate::domain::convention::{self, KEPT_SECTION, Op, TidyPlan};
use crate::domain::{Fleet, Kind, SIMPLE_PRODUCT, SecretValue, key_label};
use crate::error::{Code, Error};
use crate::ports::Ports;
use crate::runner::CommandRunner;

/// Where the values come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// A dotenv file the owner points at (literal assignments, never executed).
    Dotenv(PathBuf),
    /// The environment's own target, where it can read values back.
    Target,
}

/// Options of `opv adopt`.
#[derive(Debug, Clone)]
pub struct Opts {
    pub source: Source,
    /// `product/KEY` (or `KEY` under the simple profile) to replace a differing value.
    pub replace: Vec<String>,
    /// Immutable keys `--replace` may change.
    pub rotate: Vec<String>,
    pub apply: bool,
    pub json: bool,
}

/// `product/KEY` (or `KEY`) entries as `(product, key)` pairs, each declared.
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
                None if fleet.is_simple() => (SIMPLE_PRODUCT.to_string(), e.clone()),
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
        Source::Target => {
            let (t, ports) = super::open_target(fleet, env_name, r)?;
            let label = t.provider().label();
            match &ports {
                Ports::Pinned { store, .. } => {
                    let mut found = BTreeMap::new();
                    for name in super::managed_names(fleet, env_name)? {
                        if let Some((value, _)) = store.read(&name)? {
                            found.insert(name, value);
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
    let env = fleet.environment(env_name)?;
    let replace = pairs(fleet, &opts.replace, "--replace")?;
    let rotate = pairs(fleet, &opts.rotate, "--rotate")?;
    if opts.apply {
        super::tidy::require_person(r, "opv adopt --apply")?;
    }
    let found = read_source(fleet, env_name, &opts.source, r)?;
    // The item as the commands read it (tidied first when a person runs opv).
    let read = super::tidy::read(fleet, env_name, r)?;
    let plan = crate::domain::adopt::plan(fleet, env_name, &read.fields, &found, &replace, &rotate);
    if opts.apply && !plan.writes.is_empty() {
        write(fleet, env, &plan, r)?;
    }
    print(out, env_name, opts, &plan, fleet.is_simple())
}

/// Write `plan.writes` in one item edit, keeping a replaced value in `opv · kept`, then read
/// the item back and verify every written field holds what was written.
fn write(
    fleet: &Fleet,
    env: &crate::domain::Environment,
    plan: &AdoptPlan,
    r: &dyn CommandRunner,
) -> Result<(), Error> {
    let item = onepassword::read_whole_fresh(r, env)?;
    let (layout, _) = onepassword_tidy::parse(item.raw())?;
    let res = convention::resolve(&layout, fleet);
    let date = super::tidy::today();
    let mut ops = Vec::new();
    let mut kept = false;
    for (product, key, value) in &plan.writes {
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
                section: (product != SIMPLE_PRODUCT).then(|| product.clone()),
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
    onepassword_tidy::write(r, env, &template)?;
    // Verify by reading back: every written field holds exactly what was written.
    let after = onepassword::read_whole_fresh(r, env)?;
    let (layout, _) = onepassword_tidy::parse(after.raw())?;
    let res = convention::resolve(&layout, fleet);
    let missing: Vec<String> = plan
        .writes
        .iter()
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
fn print(
    out: &mut dyn Write,
    env_name: &str,
    opts: &Opts,
    plan: &AdoptPlan,
    simple: bool,
) -> Result<(), Error> {
    let label = |p: &Option<String>, k: &Option<String>| match (p, k) {
        (Some(p), Some(k)) if simple || p == SIMPLE_PRODUCT => k.clone(),
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
            Source::Target => c.push_str(" --from target"),
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
