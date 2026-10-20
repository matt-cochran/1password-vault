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

use crate::app::propose::structure::{Step, StructureProposal, propose_structure_at};
use crate::app::structure::{self, ConfigAt};
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
    /// True when the apply record (`secrets.applied.json`) was written: a file project only.
    pub record_written: bool,
    /// True when the structure apply recorded new ids (bindings file or block).
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
    let at = ConfigAt::File(contract_path.to_path_buf());
    apply_at(r, env, &at, project, account, plan_id, opts, confirm, out)
}

/// [`apply`] to the configuration `at`: a file and its sibling bindings, or a manifest
/// whose ids go to its `opv-bindings` block (D-G). A manifest keeps no local apply record:
/// its two blocks are written in one verified edit of the item (see [`Applied`]).
#[allow(clippy::too_many_arguments)]
pub fn apply_at(
    r: &dyn CommandRunner,
    env: &dyn crate::host::HostEnv,
    at: &ConfigAt,
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
    // Every later check of who runs this apply is judged by the host the caller gave,
    // never by this process's own variables (a library caller's person at a terminal is
    // not refused because the process itself runs under CI).
    let host = crate::host::Host::from_env(env);

    // (2) Recompute from what is on disk and what 1Password holds now. A different id means
    // the state moved since the proposal was reviewed.
    let proposal = propose_structure_at(r, at, project, account, &opts.rebind, &opts.generate)?;
    if let Some(given) = plan_id
        && given != proposal.plan_id
    {
        return Err(structure::changed(given, &proposal.plan_id));
    }

    // (3) Show the plan (steps and names only) and confirm it once.
    for line in describe(&proposal, at) {
        writeln!(out, "{line}").map_err(crate::app::write_err)?;
    }
    if !confirm(&proposal) {
        return Ok(Applied::declined(&proposal));
    }

    // (4) Run every step in this process, through the existing executors.
    // (4a) The one-time id move and `--rebind`: the two files (a manifest's two blocks)
    // the plan showed.
    move_ids(r, at, &proposal)?;
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
    let applied = structure::apply_on(
        r,
        at,
        project,
        account,
        &proposal.structure.plan_id,
        host,
        &mut authorize,
    )?;
    // (4c) Generation: the existing `generate::run` guards against overwriting a value and
    // writes through the importer's stdin-only field writer.
    let generated = generate_steps(&proposal, r, at, host, out)?;

    // (5) The apply record: the plan id and the digests of the two files as written. A
    // manifest has no committed bindings file to check against a record, so none is kept.
    let record_written = match at {
        ConfigAt::File(contract_path) => {
            write_record(contract_path, &proposal.plan_id)?;
            true
        }
        ConfigAt::Manifest(_) => false,
    };

    Ok(Applied {
        plan_id: proposal.plan_id,
        confirmed: true,
        steps_run: proposal.steps.len(),
        created: applied.created,
        fields_added: applied.fields_added,
        generated,
        record_written,
        config_written: applied.config_written,
    })
}

/// What a retirement's apply did (#179, `opv apply rp-…`). Names only, never a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RetireApplied {
    /// The plan id the person reviewed and ran.
    pub plan_id: String,
    /// True when the person confirmed; false when they declined, and nothing was run.
    pub confirmed: bool,
    pub product: String,
    pub key: String,
    /// The archived section the fields went to.
    pub section: String,
    /// The environments whose boundary item had fields moved this run.
    pub archived: Vec<String>,
    /// The environments whose boundary item held no field of the key outside an archived
    /// section: already archived, nothing edited.
    pub already_archived: Vec<String>,
    /// True when the contract now marks the key `lifecycle = "retired"`.
    pub retired: bool,
}

/// `opv apply rp-…` (#179): the person's last step of a retirement. A person's own terminal
/// only: agent mode and a missing terminal are refused before anything is read. Then, in
/// order: the plan id must be the [`retire::archive_plan`] of a key marked `retiring`
/// (else `plan_unknown`); no target may still hold the key (`still_held`, the prunes CI may
/// run; else `policy_refused` naming them); the plan is shown and confirmed once; each
/// boundary item's fields of the key move to the archived section dated `date` (one edit
/// per item, an item already archived is skipped); last, the contract marks the key
/// `lifecycle = "retired"` (its declaration is kept). A generated configuration is never
/// edited (FR-52): its generator gets the diff. A failure after an item was archived is
/// `Partial`, naming what was done; re-running the same command resumes. Never reads into
/// output, prints or keeps a value.
///
/// [`retire::archive_plan`]: crate::app::retire::archive_plan
#[allow(clippy::too_many_arguments)]
pub fn apply_retire(
    r: &dyn CommandRunner,
    env: &dyn crate::host::HostEnv,
    at: &ConfigAt,
    plan_id: &str,
    date: &str,
    still_held: &mut dyn FnMut(&crate::domain::Fleet, &str, &str) -> Vec<String>,
    confirm: &mut dyn FnMut(&crate::app::retire::ArchivePlan) -> bool,
    out: &mut dyn Write,
) -> Result<RetireApplied, Error> {
    use crate::app::retire;
    use crate::cause::{EnvName, Guard, KeyName, PlanScope, ProductName};
    crate::host::refuse_if_agent(env, apply_cmd(Some(plan_id)))?;
    if !env.interactive() {
        return Err(Cause::NeedsTerminal {
            why: NoTerminal::NoTty,
        }
        .into());
    }
    let fleet = load_fleet(r, at)?;
    let Some(plan) = retire::archive_plans(&fleet)
        .into_iter()
        .find(|p| p.plan_id == plan_id)
    else {
        return Err(Cause::PlanUnknown {
            plan: plan_id.to_string(),
            scope: Some(PlanScope::Retire),
        }
        .into());
    };
    let holding = still_held(&fleet, &plan.product, &plan.key);
    if !holding.is_empty() {
        return Err(Cause::Guard {
            guard: Guard::RetireNotPruned {
                product: ProductName::new(&plan.product),
                key: KeyName::new(&plan.key),
                holding: holding.iter().map(EnvName::new).collect(),
            },
        }
        .into());
    }
    let label = crate::domain::key_label(&plan.product, &plan.key);
    let section = crate::domain::convention::archived_section(date, &plan.product, &plan.key);
    for line in describe_retire(&plan, &section) {
        writeln!(out, "{line}").map_err(crate::app::write_err)?;
    }
    let mut applied = RetireApplied {
        plan_id: plan.plan_id.clone(),
        confirmed: false,
        product: plan.product.clone(),
        key: plan.key.clone(),
        section: section.clone(),
        archived: Vec::new(),
        already_archived: Vec::new(),
        retired: false,
    };
    if !confirm(&plan) {
        return Ok(applied);
    }
    applied.confirmed = true;
    // A failure after an item was archived keeps its cause inside `Partial`, naming what
    // was done; its step reads what remains (`ready`), which names this same command.
    let partial = |done: &[String], e: Error| -> Error {
        if done.is_empty() {
            return e;
        }
        let Error::Catalog(cause, upstream) = e;
        let cause = Cause::Partial {
            done: done.to_vec(),
            scope: Some(PlanScope::Retire),
            then: cause,
        };
        Error::Catalog(Box::new(cause), upstream)
    };
    let mut done: Vec<String> = Vec::new();
    for item in &plan.items {
        let moved = retire::archive_item(&fleet, r, &plan.product, &plan.key, item, &section)
            .map_err(|e| partial(&done, e))?
            .moved;
        if moved == 0 {
            writeln!(out, "{}: {label} already archived", item.environment)
                .map_err(crate::app::write_err)?;
            applied.already_archived.push(item.environment.clone());
        } else {
            writeln!(
                out,
                "{}: moved {moved} field(s) of {label} to {section:?}",
                item.environment
            )
            .map_err(crate::app::write_err)?;
            done.push(format!("{label} archived in {}", item.environment));
            applied.archived.push(item.environment.clone());
        }
    }
    mark_retired(r, at, &plan.product, &plan.key).map_err(|e| partial(&done, e))?;
    writeln!(
        out,
        "{label}: lifecycle = \"retired\" (its declaration is kept)"
    )
    .map_err(crate::app::write_err)?;
    applied.retired = true;
    Ok(applied)
}

/// One line per step of a retirement's apply, plus the plan id: names only.
pub fn describe_retire(plan: &crate::app::retire::ArchivePlan, section: &str) -> Vec<String> {
    let label = crate::domain::key_label(&plan.product, &plan.key);
    let mut out: Vec<String> = plan
        .items
        .iter()
        .enumerate()
        .map(|(n, i)| {
            format!(
                "{}. move the fields of {label} in the {} item of {} to section {section:?}",
                n + 1,
                i.boundary,
                i.environment
            )
        })
        .collect();
    out.push(format!(
        "{}. mark {label} lifecycle = \"retired\" in the contract",
        out.len() + 1
    ));
    out.push(format!("plan_id: {}", plan.plan_id));
    out
}

/// The configuration at `at`, loaded as every command loads it.
fn load_fleet(r: &dyn CommandRunner, at: &ConfigAt) -> Result<crate::domain::Fleet, Error> {
    match at {
        ConfigAt::File(contract_path) => crate::config::load(contract_path),
        ConfigAt::Manifest(m) => manifest_fleet(r, at, m),
    }
}

/// Mark `product/key` `lifecycle = "retired"` in the contract at `at` (its declaration is
/// kept), unless it already is. The edited contract must load. A generated configuration
/// is never edited (FR-52): the refusal carries the diff for its generator.
fn mark_retired(
    r: &dyn CommandRunner,
    at: &ConfigAt,
    product: &str,
    key: &str,
) -> Result<(), Error> {
    use crate::config::bindings;
    let merged = at.read_for_write(r)?;
    let (merged_contract, ids) = bindings::split(&merged);
    let original = match at {
        ConfigAt::File(path) => std::fs::read_to_string(path).map_err(|e| unreadable(path, &e))?,
        ConfigAt::Manifest(_) => merged_contract,
    };
    let mut doc = crate::config_edit::ConfigDoc::parse(&original)?;
    doc.set_key_lifecycle(product, key, "retired")?;
    let edited = doc.to_string();
    if edited == original {
        return Ok(());
    }
    crate::config::parse(&bindings::merge(&edited, &ids))?;
    if crate::app::bootstrap::is_generated(&original) {
        let source = match at {
            ConfigAt::File(path) => crate::cause::ConfigSource::File {
                path: path.clone(),
                given_by: GivenBy::Discovered,
            },
            ConfigAt::Manifest(m) => {
                use crate::config_store::ConfigStore;
                m.cause_source()
            }
        };
        return Err(Cause::ConfigNotEditable {
            source,
            reason: crate::cause::NotEditable::Generated {
                generator: crate::app::bootstrap::generated_by(&original).map(Into::into),
                fragment: crate::app::propose::Fragment::between(&original, &edited, &ids).ok(),
            },
        }
        .into());
    }
    match at {
        ConfigAt::File(path) => crate::config_edit::replace(path, &original, &edited),
        ConfigAt::Manifest(m) => m.write_bindings(r, Some(&edited), &ids),
    }
}

/// Write the move's or rebind's contract and bindings to `at`: a file's contract and
/// sibling, or a manifest's contract block and `opv-bindings` block in one verified edit.
fn move_ids(r: &dyn CommandRunner, at: &ConfigAt, p: &StructureProposal) -> Result<(), Error> {
    match at {
        ConfigAt::File(contract_path) => {
            if let Some(text) = &p.contract_after {
                crate::config_edit::write_atomic(contract_path, text, || Ok(()))?;
            }
            if let Some(text) = &p.bindings_after {
                let ids = crate::config::bindings::Bindings::parse(text)?;
                crate::config::bindings::write_sibling(contract_path, &ids)?;
            }
        }
        ConfigAt::Manifest(m) => {
            if let Some(text) = &p.bindings_after {
                let ids = crate::config::bindings::Bindings::parse(text)?;
                m.write_bindings(r, p.contract_after.as_deref(), &ids)?;
            }
        }
    }
    Ok(())
}

/// The apply record beside the contract at `contract_path`: `plan_id` and the digests of
/// the two files as written.
fn write_record(contract_path: &Path, plan_id: &str) -> Result<(), Error> {
    let record = crate::config::bindings::ApplyRecord {
        plan_id: plan_id.to_string(),
        contract_digest: crate::config::bindings::digest(&read_bytes(contract_path)?),
        bindings_digest: crate::config::bindings::digest(&bindings_bytes(contract_path)?),
    };
    let record_path = contract_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(crate::config::bindings::APPLIED);
    crate::config::bindings::write_record(&record_path, &record)
}

/// One line per reviewed step, plus the plan id: names, kinds and public ids only.
pub fn describe(p: &StructureProposal, at: &ConfigAt) -> Vec<String> {
    let home = match at {
        ConfigAt::File(_) => "secrets.bindings.toml",
        ConfigAt::Manifest(_) => "the manifest's opv-bindings block",
    };
    let mut out = Vec::new();
    for (n, step) in p.steps.iter().enumerate() {
        let n = n + 1;
        out.push(match step {
            Step::MoveIds { fields } => format!(
                "{n}. move {} inline id(s) into {home}: {}",
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
    at: &ConfigAt,
    host: crate::host::Host,
    out: &mut dyn Write,
) -> Result<Vec<Generated>, Error> {
    let grouped = grouped_generate(&p.steps);
    if grouped.is_empty() {
        return Ok(Vec::new());
    }
    let fleet = match at {
        ConfigAt::File(contract_path) => crate::config::load(contract_path)?,
        ConfigAt::Manifest(m) => manifest_fleet(r, at, m)?,
    };
    let mut generated = Vec::new();
    for (env, keys) in &grouped {
        crate::app::generate::run_on(&fleet, env, keys, r, host, out)?;
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

/// The manifest's configuration as the structure apply left it (read past `op`'s cache),
/// its account passed to every environment that names none, as [`Found::load`] does.
///
/// [`Found::load`]: crate::config_store::Found::load
fn manifest_fleet(
    r: &dyn CommandRunner,
    at: &ConfigAt,
    m: &crate::config_store::ManifestStore,
) -> Result<crate::domain::Fleet, Error> {
    use crate::config_store::ConfigStore;
    let mut fleet = m.parse(&at.read_for_write(r)?)?;
    if let Some(a) = &m.account {
        for env in fleet.environments.values_mut() {
            if env.account.is_none() {
                env.account = Some(a.clone());
            }
        }
    }
    Ok(fleet)
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
