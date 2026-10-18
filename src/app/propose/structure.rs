//! `opv propose structure|generate|rebind` (design Part V, row `propose-structure`): one
//! structure plan over the contract, its bindings and the actual 1Password state, with the
//! one-time move of inline ids (D-G), the generation of rule-backed values and `--rebind`.
//!
//! Pure: [`propose_structure`] reads the contract file and 1Password and returns the
//! proposal; it never writes either. Only `apply` runs the steps. No value, length, digest
//! or prefix of a value is carried: the steps hold names, kinds and public IDs only.
//!
//! A tidy proposal is deferred past 0.12.0: `src/app/tidy.rs` exposes no pure planner.

use std::path::Path;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::app::bootstrap::{BoundaryStep, StateStep};
use crate::app::structure::ConfigAt;
use crate::app::{generate, structure};
use crate::cause::{Cause, GivenBy};
use crate::config;
use crate::config::bindings::{self, Bindings};
use crate::error::Error;
use crate::runner::CommandRunner;

/// The plan id's prefix and length in hex digits after it: `sp-` and 16 (64 bits).
const PLAN_ID_PREFIX: &str = "sp-";
const PLAN_ID_HEX: usize = 16;

/// One step of a structural proposal, in the order a person reviews it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum Step {
    /// The one-time move of inline ids into `secrets.bindings.toml` (D-G).
    MoveIds { fields: Vec<String> },
    /// A boundary vault and its item to create.
    CreateBoundary {
        environment: String,
        boundary: String,
        vault: String,
        item: String,
    },
    /// A state vault to create.
    CreateStateVault {
        environment: String,
        target: String,
        vault: String,
    },
    /// A delivery item to create.
    CreateDeliveryItem {
        environment: String,
        target: String,
        product: String,
        item: String,
    },
    /// An empty field to add to a boundary item.
    AddField {
        environment: String,
        boundary: String,
        product: String,
        key: String,
        field_kind: &'static str,
    },
    /// New ids for an environment (`--rebind`).
    Rebind { env: String },
    /// A generated value for a rule-backed key.
    Generate {
        env: String,
        product: String,
        key: String,
    },
}

/// The structural proposal: the ordered steps, the detailed structure plan, the two file
/// texts a move or rebind leaves behind, and a content-addressed id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StructureProposal {
    /// The one plan id of the proposal: the id `opv apply <plan_id>` accepts.
    pub plan_id: String,
    pub steps: Vec<Step>,
    /// The detailed structure plan. Its own id is apply's internal check, so the document
    /// leaves it out: the proposal exposes exactly one plan id, the one a person applies.
    #[serde(serialize_with = "structure_without_id")]
    pub structure: structure::Plan,
    /// The contract text with its inline ids taken out, when there were any.
    pub contract_after: Option<String>,
    /// The bindings text after a move or rebind, when either happened.
    pub bindings_after: Option<String>,
}

/// Plan the structure, generation and rebinds `contract_path` implies. Reads only: the
/// contract, its sibling bindings and 1Password; never writes one of them.
pub fn propose_structure(
    r: &dyn CommandRunner,
    contract_path: &Path,
    project: &str,
    account: &str,
    rebind: &[String],
    generate: &[(String, Vec<String>)],
) -> Result<StructureProposal, Error> {
    let at = ConfigAt::File(contract_path.to_path_buf());
    propose_structure_at(r, &at, project, account, rebind, generate)
}

/// [`propose_structure`] for the configuration `at`: a file and its sibling bindings, or a
/// manifest's contract block and its `opv-bindings` block (D-G). Reads only.
pub fn propose_structure_at(
    r: &dyn CommandRunner,
    at: &ConfigAt,
    project: &str,
    account: &str,
    rebind: &[String],
    generate: &[(String, Vec<String>)],
) -> Result<StructureProposal, Error> {
    let (text, bound) = match at {
        ConfigAt::File(contract_path) => (read_contract(contract_path)?, None),
        ConfigAt::Manifest(m) => {
            let (text, ids) = m.read_for_proposal(r)?;
            (text, Some(ids))
        }
    };

    // (1) The one-time id move (D-G). `split` takes the ids out of the text; the dedicated
    // move reader (`load_for_move`, a manifest's `read_for_move`) confirms the inline form
    // and would refuse a broken one.
    let (contract_now, moved) = bindings::split(&text);
    let has_move = !moved.is_empty();
    if has_move {
        let (_fleet, _ids) = match at {
            ConfigAt::File(contract_path) => config::load_for_move(contract_path)?,
            ConfigAt::Manifest(m) => m.read_for_move(r)?,
        };
    }

    // The bindings the proposal leaves behind: the sibling file (a manifest's bindings
    // block) plus the moved ids, with every rebound environment's ids dropped so apply
    // records new ones.
    let bound = match at {
        ConfigAt::File(contract_path) => bindings::read_sibling(contract_path)?,
        ConfigAt::Manifest(_) => bound.unwrap_or_default(),
    };
    let mut after = bound.union(moved.clone());
    for env in rebind {
        after = without_env(&after, env)?;
    }
    let touched = has_move || !rebind.is_empty();

    let merged = bindings::merge(&contract_now, &after);
    // The loader refuses a contract whose vaults and items are not recorded yet; the trial
    // text fills placeholders, so generation can read the declarations before apply.
    let fleet = config::parse(&structure::trial_text(&merged)?)?;

    // (2) The structure the contract declares.
    let plan = structure::plan(r, &merged, project, account)?;
    let mut steps = Vec::new();
    if has_move {
        steps.push(Step::MoveIds {
            fields: field_paths(&moved),
        });
    }
    steps.extend(structure_steps(&plan));
    // (3) `--rebind`: new ids for each named environment.
    for env in rebind {
        steps.push(Step::Rebind { env: env.clone() });
    }
    // (4) Generation: one step per rule-backed key, with its recipe kind only.
    for (env, keys) in generate {
        for (product, key, _recipe) in generate::plan(&fleet, env, keys)? {
            steps.push(Step::Generate {
                env: env.clone(),
                product,
                key,
            });
        }
    }

    let contract_after = has_move.then(|| contract_now.clone());
    let bindings_after = touched.then(|| after.render());
    let plan_id = plan_id(&steps, contract_after.as_deref(), bindings_after.as_deref());

    Ok(StructureProposal {
        plan_id,
        steps,
        structure: plan,
        contract_after,
        bindings_after,
    })
}

/// The structure plan as the proposal document shows it: every field but its own
/// `plan_id`, which `opv apply` never takes, in the plan's own field order.
fn structure_without_id<S: serde::Serializer>(
    plan: &structure::Plan,
    s: S,
) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct Shown<'a> {
        project: &'a str,
        account_id: &'a str,
        environments: &'a [crate::app::bootstrap::EnvPlan],
        delivery_items: &'a [structure::DeliveryStep],
        fields: &'a [structure::FieldStep],
        generated: bool,
    }
    // Every field is named, so a new one in the plan fails to compile here.
    let structure::Plan {
        plan_id: _,
        project,
        account_id,
        environments,
        delivery_items,
        fields,
        generated,
    } = plan;
    Shown {
        project,
        account_id,
        environments,
        delivery_items,
        fields,
        generated: *generated,
    }
    .serialize(s)
}

/// The contract file at `contract_path`, as written.
fn read_contract(contract_path: &Path) -> Result<String, Error> {
    std::fs::read_to_string(contract_path).map_err(|e| {
        Error::from(Cause::ConfigUnreadable {
            path: contract_path.to_path_buf(),
            io: e.kind().into(),
            given_by: GivenBy::Discovered,
        })
    })
}

/// The structure plan's still-to-create boundary vaults and items, state vaults, delivery
/// items and empty fields, as ordered steps.
fn structure_steps(plan: &structure::Plan) -> Vec<Step> {
    let mut out = Vec::new();
    for e in &plan.environments {
        for b in &e.boundaries {
            if let BoundaryStep::Create { vault, item } = &b.step {
                out.push(Step::CreateBoundary {
                    environment: e.environment.clone(),
                    boundary: b.boundary.clone(),
                    vault: vault.clone(),
                    item: item.clone(),
                });
            }
        }
        for s in &e.state_vaults {
            if let StateStep::Create { vault } = &s.step {
                out.push(Step::CreateStateVault {
                    environment: e.environment.clone(),
                    target: s.target.clone(),
                    vault: vault.clone(),
                });
            }
        }
    }
    for d in &plan.delivery_items {
        out.push(Step::CreateDeliveryItem {
            environment: d.environment.clone(),
            target: d.target.clone(),
            product: d.product.clone(),
            item: d.item.clone(),
        });
    }
    for f in &plan.fields {
        out.push(Step::AddField {
            environment: f.environment.clone(),
            boundary: f.boundary.clone(),
            product: f.product.clone(),
            key: f.key.clone(),
            field_kind: f.kind,
        });
    }
    out
}

/// `b` without the environment's boundary ids (`environments.<env>.boundaries.`), so apply
/// finds or creates its vaults and items in the selected account and records them, as
/// 0.11.0's `bootstrap --rebind` did; its targets' state vaults and delivery items keep
/// their ids (#159: a state vault in the account stays `ok`).
fn without_env(b: &Bindings, env: &str) -> Result<Bindings, Error> {
    let prefix = format!("environments.{env}.boundaries.");
    let kept: String = b
        .render()
        .lines()
        .filter(|l| !l.starts_with(&prefix))
        .map(|l| format!("{l}\n"))
        .collect();
    Bindings::parse(&kept)
}

/// The dotted paths of `ids`, in the canonical sorted order of its rendering.
fn field_paths(ids: &Bindings) -> Vec<String> {
    ids.render()
        .lines()
        .filter_map(|l| l.split_once(" = ").map(|(path, _)| path.to_string()))
        .collect()
}

/// The content-addressed plan id: `sp-` and 16 lowercase hex digits of SHA-256 over the
/// canonical JSON of the steps and the two resulting file texts (D-G).
fn plan_id(steps: &[Step], contract_after: Option<&str>, bindings_after: Option<&str>) -> String {
    let json = serde_json::to_vec(steps).unwrap_or_else(|_| unreachable!("steps always serialize"));
    let mut h = Sha256::new();
    h.update((json.len() as u64).to_be_bytes());
    h.update(&json);
    for text in [contract_after, bindings_after] {
        match text {
            Some(t) => {
                h.update((t.len() as u64).to_be_bytes());
                h.update(t.as_bytes());
            }
            None => h.update(0u64.to_be_bytes()),
        }
    }
    let digest = hex(&h.finalize());
    format!("{PLAN_ID_PREFIX}{}", &digest[..PLAN_ID_HEX])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
#[path = "structure_tests.rs"]
mod tests;
