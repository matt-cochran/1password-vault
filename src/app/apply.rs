//! `opv apply` (design Part V, row `apply-core`): the one actuator a person runs in their
//! own terminal. It recomputes the structural plan from the contract on disk and the actual
//! state, refuses a plan id that no longer matches (`stale_plan`), shows the whole plan,
//! confirms once, and then runs every step in one process with the existing executors: the
//! one-time id move or rebind, the structure, generation, and the apply record.
//!
//! A person's own terminal: an assistant (agent mode) or a run with no terminal is refused
//! before anything is read or prompted. Names, kinds and public ids only: no value, length,
//! digest or prefix of a value is ever printed, held or rendered here.

use std::io::Write;
use std::path::Path;

use serde::Serialize;

use crate::app::propose::structure::{Step, StructureProposal, propose_structure};
use crate::app::structure;
use crate::cause::{Cause, Cmd, GivenBy, NoTerminal};
use crate::error::Error;
use crate::runner::CommandRunner;

/// What a person asked `opv apply` to add on top of the contract's own structure: extra
/// environments to rebind with fresh ids, and `product/KEY` lists to generate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplyOpts {
    pub rebind: Vec<String>,
    pub generate: Vec<(String, Vec<String>)>,
}

/// One generated key, by name only (never its value).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Generated {
    pub environment: String,
    pub product: String,
    pub key: String,
}

/// What `apply` did. Holds names, kinds and public ids only, never a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Applied {
    /// The plan id the person reviewed and ran.
    pub plan_id: String,
    /// True when the person confirmed; false when they declined, and nothing was run.
    pub confirmed: bool,
    /// How many reviewed steps the plan had (move, structure, rebind, generation).
    pub steps_run: usize,
    pub created: Vec<structure::Created>,
    pub fields_added: Vec<structure::FieldStep>,
    /// The keys a generation step filled, by name.
    pub generated: Vec<Generated>,
    /// True when the apply record was written.
    pub record_written: bool,
    /// True when the structure apply wrote new ids into the contract.
    pub config_written: bool,
}

impl Applied {
    /// Nothing was run because the person declined the plan.
    fn declined(p: &StructureProposal) -> Applied {
        Applied {
            plan_id: p.plan_id.clone(),
            confirmed: false,
            steps_run: 0,
            created: Vec::new(),
            fields_added: Vec::new(),
            generated: Vec::new(),
            record_written: false,
            config_written: false,
        }
    }
}

/// The exact `opv apply [<plan_id>]` command, for a refusal that hands it to a person.
fn apply_cmd(plan_id: Option<&str>) -> Cmd {
    Cmd {
        command: vec!["apply".to_string()],
        args: plan_id.into_iter().map(str::to_string).collect(),
    }
}

/// Recompute the plan from the contract on disk and the actual state, refuse a stale id,
/// show the plan, confirm once, then run every step with the existing executors. A person's
/// own terminal only: agent mode and a missing terminal are refused before any read.
#[allow(clippy::too_many_arguments)]
pub fn apply(
    r: &dyn CommandRunner,
    env: &dyn crate::host::HostEnv,
    contract_path: &Path,
    project: &str,
    account: &str,
    plan_id: Option<&str>,
    opts: ApplyOpts,
    confirm: &mut dyn FnMut(&StructureProposal) -> bool,
    out: &mut dyn Write,
) -> Result<Applied, Error> {
    // (1) Refusals first, before anything is read or prompted. An assistant is turned away
    // before a value-free plan is even computed; so is a run with no terminal.
    let cmd = apply_cmd(plan_id);
    crate::host::refuse_if_agent(env, cmd.clone())?;
    if !env.interactive() {
        return Err(Cause::NeedsTerminal {
            why: NoTerminal::NoTty,
        }
        .into());
    }

    // (2) Recompute from what is on disk and what 1Password holds now. A different id means
    // the state moved since the proposal was reviewed.
    let proposal = propose_structure(
        r,
        contract_path,
        project,
        account,
        &opts.rebind,
        &opts.generate,
    )?;
    if let Some(given) = plan_id
        && given != proposal.plan_id
    {
        return Err(structure::changed(given, &proposal.plan_id));
    }

    // (3) Show the plan (steps and names only) and confirm it once.
    for line in describe(&proposal) {
        writeln!(out, "{line}").map_err(crate::app::write_err)?;
    }
    if !confirm(&proposal) {
        return Ok(Applied::declined(&proposal));
    }

    // (4) Run every step in this process, through the existing executors.
    // (4a) The one-time id move and `--rebind`: the two files the plan showed.
    if let Some(text) = &proposal.contract_after {
        crate::config_edit::write_atomic(contract_path, text, || Ok(()))?;
    }
    if let Some(text) = &proposal.bindings_after {
        let ids = crate::config::bindings::Bindings::parse(text)?;
        crate::config::bindings::write_sibling(contract_path, &ids)?;
    }
    // (4b) The structure, with an authorize closure that accepts the plan just confirmed
    // (no approval file). The plan id is the recomputed structural id.
    let confirmed_id = proposal.structure.plan_id.clone();
    let mut authorize = |plan: &structure::Plan| {
        if plan.plan_id == confirmed_id {
            Ok(())
        } else {
            Err(structure::changed(&confirmed_id, &plan.plan_id))
        }
    };
    let applied = structure::apply(
        r,
        contract_path,
        project,
        account,
        &proposal.structure.plan_id,
        &mut authorize,
    )?;
    // (4c) Generation: the existing `generate::run` guards against overwriting a value and
    // writes through the importer's stdin-only field writer.
    let generated = generate_steps(&proposal, r, contract_path, out)?;

    // (5) The apply record: the plan id and the digests of the two files as written.
    let record = crate::config::bindings::ApplyRecord {
        plan_id: proposal.plan_id.clone(),
        contract_digest: crate::config::bindings::digest(&read_bytes(contract_path)?),
        bindings_digest: crate::config::bindings::digest(&bindings_bytes(contract_path)?),
    };
    let record_path = contract_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(crate::config::bindings::APPLIED);
    crate::config::bindings::write_record(&record_path, &record)?;

    Ok(Applied {
        plan_id: proposal.plan_id,
        confirmed: true,
        steps_run: proposal.steps.len(),
        created: applied.created,
        fields_added: applied.fields_added,
        generated,
        record_written: true,
        config_written: applied.config_written,
    })
}

/// One line per reviewed step, plus the plan id: names, kinds and public ids only.
fn describe(p: &StructureProposal) -> Vec<String> {
    let mut out = Vec::new();
    for (n, step) in p.steps.iter().enumerate() {
        let n = n + 1;
        out.push(match step {
            Step::MoveIds { fields } => format!(
                "{n}. move {} inline id(s) into secrets.bindings.toml: {}",
                fields.len(),
                fields.join(", ")
            ),
            Step::CreateBoundary {
                environment,
                boundary,
                vault,
                item,
            } => format!(
                "{n}. create vault {vault:?} and item {item:?} for boundary {boundary} in {environment}"
            ),
            Step::CreateStateVault {
                environment,
                target,
                vault,
            } => format!(
                "{n}. create state vault {vault:?} for target {target} in {environment}"
            ),
            Step::CreateDeliveryItem {
                environment,
                target,
                product,
                item,
            } => format!(
                "{n}. create delivery item {item:?} for {product} on target {target} in {environment}"
            ),
            Step::AddField {
                environment,
                boundary,
                product,
                key,
                field_kind,
            } => format!(
                "{n}. add empty {field_kind} field {product}/{key} to the {boundary} item in {environment}"
            ),
            Step::Rebind { env } => format!("{n}. rebound the ids of {env}"),
            Step::Generate { env, product, key } => {
                format!("{n}. generate a value for {product}/{key} in {env}")
            }
        });
    }
    if out.is_empty() {
        out.push("Nothing to create.".to_string());
    }
    out.push(format!("plan_id: {}", p.plan_id));
    out
}

/// The `Generate` steps grouped by environment, as `product/KEY` labels.
fn grouped_generate(steps: &[Step]) -> Vec<(String, Vec<String>)> {
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for step in steps {
        let Step::Generate { env, product, key } = step else {
            continue;
        };
        let label = format!("{product}/{key}");
        match out.iter_mut().find(|(e, _)| e == env) {
            Some((_, keys)) => keys.push(label),
            None => out.push((env.clone(), vec![label])),
        }
    }
    out
}

/// Run every requested generation through [`crate::app::generate::run`] (which guards
/// against overwriting a value and writes through the importer's stdin path), returning the
/// generated keys by name.
fn generate_steps(
    p: &StructureProposal,
    r: &dyn CommandRunner,
    contract_path: &Path,
    out: &mut dyn Write,
) -> Result<Vec<Generated>, Error> {
    let grouped = grouped_generate(&p.steps);
    if grouped.is_empty() {
        return Ok(Vec::new());
    }
    let fleet = crate::config::load(contract_path)?;
    let mut generated = Vec::new();
    for (env, keys) in &grouped {
        crate::app::generate::run(&fleet, env, keys, r, out)?;
        for label in keys {
            if let Some((product, key)) = label.split_once('/') {
                generated.push(Generated {
                    environment: env.clone(),
                    product: product.to_string(),
                    key: key.to_string(),
                });
            }
        }
    }
    Ok(generated)
}

/// The bytes of the contract file as written.
fn read_bytes(path: &Path) -> Result<Vec<u8>, Error> {
    std::fs::read(path).map_err(|e| unreadable(path, &e))
}

/// The bytes of the contract's sibling bindings file, or none when it does not exist.
fn bindings_bytes(contract_path: &Path) -> Result<Vec<u8>, Error> {
    let path = contract_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(crate::config::bindings::FILE);
    match std::fs::read(&path) {
        Ok(bytes) => Ok(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(unreadable(&path, &e)),
    }
}

fn unreadable(path: &Path, e: &std::io::Error) -> Error {
    Cause::ConfigUnreadable {
        path: path.to_path_buf(),
        io: e.kind().into(),
        given_by: GivenBy::Discovered,
    }
    .into()
}

#[cfg(test)]
#[path = "apply_tests.rs"]
mod tests;
