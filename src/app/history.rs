//! `opv history <env> [--target <name>] [--json]` (#95): what opv last wrote to an
//! environment's target, per key, from what is already recorded: the provenance stamp a
//! pinned target keeps on each value (FR-42: opv version, UTC time, plan id) and the
//! version ledger opv's own sync keeps for stores that hide values (FR-54): each
//! placement's delivery evidence (FR-58, D11). Read-only, as `status`: per target, the
//! item reads, each recorded delivery item and one store listing (which holds the stamps).
//! Without `--target`, every target of the environment is shown, each labelled with its
//! name (FR-56); with it, only that one. Names, versions, times and
//! plan ids only, never a value or a fingerprint (SR-1).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

use super::write_err;
use crate::domain::Kind;
use crate::domain::history::{HistoryRow, KeyRef, build, latest_written};
use crate::error::Error;
use crate::runner::CommandRunner;

/// What each state means, for the text output.
fn state_words(state: &str) -> &'static str {
    match state {
        "stamped" => "written by opv",
        "recorded" => "as opv's last sync left it",
        "changed_outside_opv" => "changed outside opv since its last sync",
        "not_recorded" => "on the target; opv has no record of writing it",
        "absent" => "not on the target",
        _ => "",
    }
}

/// Run `opv history <env> [--target <name>]`.
pub fn run(
    fleet: &crate::domain::Fleet,
    env_name: &str,
    target: Option<&str>,
    r: &dyn CommandRunner,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let env = fleet.environment(env_name)?;
    if env.targets.is_empty() {
        if json {
            let doc = serde_json::json!({
                "schema_version": crate::json::SCHEMA_VERSION,
                "environment": env_name,
                "target": null,
                "latest": null,
                "rows": [],
            });
            return writeln!(out, "{doc}").map_err(write_err);
        }
        return writeln!(
            out,
            "{env_name} has no target: opv writes nothing outside 1Password for it, so there \
             is no write history (opv run {env_name} reads 1Password directly)"
        )
        .map_err(write_err);
    }
    // Every target of the environment, or only the `--target` named one (FR-56).
    let requested: Vec<String> = target.map(str::to_string).into_iter().collect();
    let names = super::resolve_targets(fleet, env_name, &requested, "history")?;
    let runners = super::target_runners(fleet, env_name, &names, r)?;
    let mut parts = Vec::new();
    for (name, signed) in names.iter().zip(&runners) {
        let r: &dyn CommandRunner = match signed {
            Some(s) => s,
            None => r,
        };
        parts.push(history_part(fleet, env_name, name, r)?);
    }
    if json && parts.len() > 1 {
        let targets: Vec<serde_json::Value> = parts
            .iter()
            .map(|p| {
                serde_json::json!({
                    "name": p.name,
                    "target": p.section,
                    "latest": latest_doc(&p.rows),
                    "rows": p.rows,
                })
            })
            .collect();
        let doc = serde_json::json!({
            "schema_version": crate::json::SCHEMA_VERSION,
            "environment": env_name,
            "targets": targets,
        });
        return writeln!(out, "{doc}").map_err(write_err);
    }
    for p in &parts {
        report(out, env_name, &p.name, p.label, p.section, &p.rows, json)?;
    }
    Ok(())
}

/// One target's history (FR-56): its name, provider label and section, and its rows.
struct HistoryPart {
    name: String,
    label: &'static str,
    section: &'static str,
    rows: Vec<HistoryRow>,
}

/// Read target `name` of `env_name`: one store listing, the item reads and each recorded
/// delivery item (the placements' ledgers).
fn history_part(
    fleet: &crate::domain::Fleet,
    env_name: &str,
    name: &str,
    r: &dyn CommandRunner,
) -> Result<HistoryPart, Error> {
    let (target, ports) = super::open_target(fleet, env_name, name, r)?;
    let read = super::tidy::read(fleet, env_name, r)?;
    let ledgers = super::placement_ledgers(fleet, env_name, Some(name), Some(&ports), r);
    let recorded: BTreeMap<String, String> = ledgers.iter().flat_map(|l| l.versions()).collect();
    let none = BTreeSet::new();
    let (plan, listed) = super::plan_item_with(
        fleet,
        env_name,
        Some(name),
        read.fields,
        Some(&ports),
        &none,
        &none,
        &ledgers,
    )?;
    // Secrets only: config keys travel as variables, which the stores do not version.
    let names: Vec<(String, String, String)> = plan
        .rows
        .iter()
        .filter(|row| row.kind == Kind::Secret)
        .map(|row| {
            let name = target.env_name(&row.product, &row.key);
            (row.product.clone(), row.key.clone(), name)
        })
        .collect();
    let keys: Vec<KeyRef<'_>> = names
        .iter()
        .map(|(product, key, name)| KeyRef { product, key, name })
        .collect();
    let mut rows = build(&keys, &listed, &recorded);
    // A store whose versions are digests of the value (equal for equal values, usable to
    // test a guess) shows the state only; opv's comparison stays in memory (FR-54).
    if target.provider().versions_reveal_values() {
        for row in &mut rows {
            row.version = None;
            row.recorded_version = None;
        }
    }
    Ok(HistoryPart {
        name: name.to_string(),
        label: target.provider().label(),
        section: target.provider().section(),
        rows,
    })
}

/// Print the history of `rows` (`opv history`'s output, text or JSON). Names only.
fn report(
    out: &mut dyn Write,
    env_name: &str,
    target_name: &str,
    label: &str,
    section: &str,
    rows: &[HistoryRow],
    json: bool,
) -> Result<(), Error> {
    if json {
        let doc = serde_json::json!({
            "schema_version": crate::json::SCHEMA_VERSION,
            "environment": env_name,
            "name": target_name,
            "target": section,
            "latest": latest_doc(rows),
            "rows": rows,
        });
        return writeln!(out, "{doc}").map_err(write_err);
    }
    print_text(out, env_name, target_name, label, rows, latest_row(rows))
}

/// The `latest` object of `rows` (FR-42), or `null` when no row carries a stamp.
fn latest_doc(rows: &[HistoryRow]) -> serde_json::Value {
    latest_row(rows).map_or(serde_json::Value::Null, |r| {
        serde_json::json!({
            "written": r.written,
            "plan": r.plan,
            "opv_version": r.opv_version,
        })
    })
}

/// The row holding the most recent stamp.
fn latest_row(rows: &[HistoryRow]) -> Option<&HistoryRow> {
    let when = latest_written(rows)?;
    rows.iter().find(|r| r.written.as_deref() == Some(when))
}

fn print_text(
    out: &mut dyn Write,
    env_name: &str,
    target_name: &str,
    label: &str,
    rows: &[HistoryRow],
    latest: Option<&HistoryRow>,
) -> Result<(), Error> {
    let place = super::placement(env_name, target_name);
    let head = match latest {
        Some(r) => format!(
            "{place} ({label}): last write {} by plan {} (opv {})",
            r.written.as_deref().unwrap_or("-"),
            r.plan.as_deref().unwrap_or("-"),
            r.opv_version.as_deref().unwrap_or("-")
        ),
        None => format!(
            "{place} ({label}): {label} keeps no write stamps; versions are compared with \
             what opv's own syncs recorded"
        ),
    };
    writeln!(out, "{head}").map_err(write_err)?;
    for r in rows {
        let key = format!("{}/{}", r.product, r.key);
        let mut detail = state_words(r.state).to_string();
        if let Some(w) = &r.written {
            detail.push_str(&format!(" {w}"));
        }
        if let Some(p) = &r.plan {
            detail.push_str(&format!(", plan {p}"));
        }
        if r.pending {
            detail.push_str(" (pending deploy)");
        }
        writeln!(
            out,
            "  {key:<32} {:<28} {:<10} {detail}",
            r.name,
            r.version.as_deref().unwrap_or("-")
        )
        .map_err(write_err)?;
    }
    if rows.is_empty() {
        writeln!(out, "  no secret is declared for {env_name}").map_err(write_err)?;
    }
    if rows.iter().any(|r| r.state == "changed_outside_opv") {
        writeln!(out, "Next: opv plan {env_name}").map_err(write_err)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "history_tests.rs"]
mod tests;
