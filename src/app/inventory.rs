//! `opv inventory` (design Part V, row `inventory`): one value-free matrix of every key's
//! state in every environment, with the vault capability and the 1Password ids behind it.
//!
//! Nothing here holds a value: the item is read once per needed boundary (FR-13), each
//! field is classified in memory with [`classify`], and only the resulting [`ValueState`]
//! leaves the read. Text and JSON render the same document; the JSON is the schema-3
//! envelope (`json::finish`) with a typed `next`.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;

use serde::Serialize;
use serde_json::{Value, json};

use super::next::Signals;
use crate::adapters::{onepassword, onepassword_init, onepassword_tidy};
use crate::cause::{Cause, FieldRule, InputKind, LocalOp, Location};
use crate::domain::Fleet;
use crate::domain::capability::{self, Capability, UnknownSource};
use crate::domain::convention;
use crate::domain::inventory::{self, CellInputs, Inventory, PresenceView, ReceiptView};
use crate::domain::presence::present_in;
use crate::domain::rules;
use crate::domain::value_state::{ValueState, classify};
use crate::error::Error;
use crate::host::Host;
use crate::runner::CommandRunner;

/// The state of one placement's delivery evidence, as `opv inventory` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DeliveryRow {
    environment: String,
    target: String,
    product: String,
    /// `delivered` (a receipt is recorded), `not_delivered` (the item exists without one),
    /// `not_recorded` (no delivery item is recorded for this placement) or `unreadable`.
    state: &'static str,
}

/// Read, build and write the inventory (design Part V, row `inventory`).
///
/// `env` and `product` scope the document after they are validated ([`Fleet::environment`],
/// [`super::check_product`]). Every needed boundary item is read once; rules count only when
/// they are committed on the default branch (`rule_source`, as `ready` gates them). The
/// newest saved `receipt` fills cells whose vault this session is not a member of.
pub fn run(
    fleet: &Fleet,
    env: Option<&str>,
    product: Option<&str>,
    r: &dyn CommandRunner,
    receipt: Option<&Path>,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let document = gather(fleet, env, product, r, receipt)?;
    let deliveries = delivery_rows(&scoped(fleet, env), product, r);

    if json {
        let body = body(&document, &deliveries)?;
        let rendered = serde_json::to_vec(&body)
            .map_err(|_| Cause::Bug {
                site: "the inventory document serializes",
            })
            .map(|bytes| crate::json::finish(&bytes, Ok(()), false))?;
        return out.write_all(&rendered).map_err(super::write_err);
    }
    let text = render(&document, &deliveries);
    out.write_all(text.as_bytes()).map_err(super::write_err)
}

/// The fleet narrowed to `env`, when given: an environment scope keeps the read to that
/// environment's items; a product scope only narrows the rendered document (a boundary is
/// read whole for its environment).
fn scoped(fleet: &Fleet, env: Option<&str>) -> Fleet {
    let mut scoped = fleet.clone();
    if let Some(name) = env {
        scoped.environments.retain(|e, _| e == name);
    }
    scoped
}

/// Read and build the inventory document [`run`] renders, without rendering it: the input
/// `opv next` ranks ([`super::next::next`]). Same validation, reads and scope as [`run`].
pub fn gather(
    fleet: &Fleet,
    env: Option<&str>,
    product: Option<&str>,
    r: &dyn CommandRunner,
    receipt: Option<&Path>,
) -> Result<Inventory, Error> {
    read(fleet, env, product, r, receipt).map(|(document, _)| document)
}

/// [`gather`] and the [`Signals`] `opv next` ranks with: the cells whose delivery evidence
/// is current and each vault's writer count, from the same reads (each vault's user list
/// once). A cell no target of its environment delivers counts as delivered: there is
/// nothing to `opv sync` it to, so a `set` key there is done (rank 6 never asks for it).
pub fn gather_for_next(
    fleet: &Fleet,
    env: Option<&str>,
    product: Option<&str>,
    r: &dyn CommandRunner,
    receipt: Option<&Path>,
) -> Result<(Inventory, Signals), Error> {
    let (document, writers) = read(fleet, env, product, r, receipt)?;
    let deliveries = delivery_rows(&scoped(fleet, env), product, r);
    let delivered = delivered_cells(fleet, &document, &deliveries);
    Ok((document, Signals { delivered, writers }))
}

/// The cells whose every delivering target holds a receipt for the cell's product; a cell
/// that no target of its environment delivers is delivered (vacuously: nothing to sync).
fn delivered_cells(
    fleet: &Fleet,
    document: &Inventory,
    deliveries: &[DeliveryRow],
) -> BTreeSet<(String, String, String)> {
    document
        .cells
        .iter()
        .filter(|cell| {
            let Some(environment) = fleet.environments.get(&cell.env) else {
                return false;
            };
            environment
                .targets
                .keys()
                .filter(|target| fleet.delivers(&cell.env, target, &cell.product))
                .all(|target| {
                    deliveries.iter().any(|d| {
                        d.environment == cell.env
                            && &d.target == target
                            && d.product == cell.product
                            && d.state == "delivered"
                    })
                })
        })
        .map(|cell| (cell.product.clone(), cell.key.clone(), cell.env.clone()))
        .collect()
}

/// The number of writers (`allow_editing`) a vault's user list names; `None` when the list
/// was refused or is not an array (the vault is then not judged).
fn writer_count(users: Option<&Value>) -> Option<usize> {
    let entries = users?.as_array()?;
    Some(
        entries
            .iter()
            .filter(|user| {
                user.get("permissions")
                    .and_then(Value::as_array)
                    .is_some_and(|p| p.iter().any(|p| p.as_str() == Some("allow_editing")))
            })
            .count(),
    )
}

/// The reads behind [`gather`]: the document, and each read vault's writer count.
fn read(
    fleet: &Fleet,
    env: Option<&str>,
    product: Option<&str>,
    r: &dyn CommandRunner,
    receipt: Option<&Path>,
) -> Result<(Inventory, BTreeMap<String, usize>), Error> {
    if let Some(name) = env {
        fleet.environment(name)?;
    }
    super::check_product(fleet, product, env)?;
    let scoped = scoped(fleet, env);

    let source = committed_rules(r, &scoped);
    let mut cells = CellInputs::default();
    // Every needed boundary of every scoped environment, each once, and the vaults whose
    // capability must be observed before deciding whether the item can be read at all.
    let mut needs = Vec::new();
    let mut vaults = std::collections::BTreeSet::new();
    for env_name in scoped.environments.keys() {
        for (boundary_name, boundary) in super::tidy::boundaries_needed(&scoped, env_name)? {
            vaults.insert(boundary.vault_id.clone());
            needs.push((env_name.clone(), boundary_name, boundary));
        }
    }
    let me = onepassword_init::session_user(r, &Host::detect);
    let mut writers = BTreeMap::new();
    for vault_id in vaults {
        let users = onepassword_init::vault_users(r, &vault_id, &Host::detect)?;
        if let Some(count) = writer_count(users.as_ref()) {
            writers.insert(vault_id.clone(), count);
        }
        let capability = match me.as_deref() {
            Some(user) => capability::classify(users.as_ref(), user),
            None => Capability::Unknown {
                source: UnknownSource::NoSessionUser,
            },
        };
        cells.capabilities.insert(vault_id, capability);
    }
    read_boundaries(&scoped, &source, r, &needs, &mut cells)?;

    let view = match receipt {
        Some(path) => Some(read_receipt(path)?),
        None => None,
    };
    let mut document = inventory::build(&scoped, &cells, view.as_ref());
    if let Some(name) = product {
        document.keys.retain(|k| k.product == name);
        document.cells.retain(|c| c.product == name);
    }
    Ok((document, writers))
}

/// The committed-rule source, as `ready` reads it: `Manifest` when the contract is in
/// 1Password, the default branch when the repository is readable, and a source that holds
/// no committed rules when it is not (so no rule is evaluated).
fn committed_rules(
    r: &dyn CommandRunner,
    fleet: &Fleet,
) -> Option<crate::app::rule_source::RuleSource> {
    let repo = crate::config_store::git_toplevel(r);
    let root = repo.as_deref().unwrap_or(Path::new("."));
    crate::app::rule_source::rule_source(r, root, fleet).ok()
}

/// Read every needed boundary item of the scoped fleet once, filling `cells.states`. An
/// unbound needed boundary is the contract's [`crate::cause::Cause::BoundaryMissing`], from
/// `boundaries_needed`. A vault this session is not a member of is never read: its cells
/// stay live-absent so the newest receipt can supply them.
fn read_boundaries(
    fleet: &Fleet,
    source: &Option<crate::app::rule_source::RuleSource>,
    r: &dyn CommandRunner,
    needs: &[(String, String, &crate::domain::Boundary)],
    cells: &mut CellInputs,
) -> Result<(), Error> {
    use crate::app::rule_source::RuleStatus;
    for (env_name, boundary_name, boundary) in needs {
        if cells.capabilities.get(&boundary.vault_id) == Some(&Capability::None) {
            continue;
        }
        let environment = fleet.environment(env_name)?;
        let item = onepassword::read_whole(r, environment, boundary)?;
        let (layout, _stamp) = onepassword_tidy::parse(item.raw())?;
        let part = super::tidy::in_boundary(fleet, boundary_name);
        let found = convention::resolve(&layout, &part);
        for (product, declared) in &part.products {
            for (key, spec) in &declared.keys {
                if !spec.is_desired_in(env_name) {
                    continue;
                }
                let read = found
                    .chosen
                    .get(&(product.clone(), key.clone()))
                    .map(|i| &layout.fields[*i].value);
                let committed = source
                    .as_ref()
                    .is_some_and(|s| s.status(fleet, product, key) == RuleStatus::Committed);
                let state = classify(Ok(read), present_in(spec, env_name), committed, |v| {
                    rules::check(product, key, spec, env_name, environment, v)
                        .map(|_| ())
                        .map_err(|f| f.rule)
                });
                cells
                    .states
                    .insert((product.clone(), key.clone(), env_name.clone()), state);
            }
        }
    }
    Ok(())
}

/// One row per placement with a recorded delivery item: its state comes from
/// [`super::delivery::read_state`], never from a value.
fn delivery_rows(fleet: &Fleet, product: Option<&str>, r: &dyn CommandRunner) -> Vec<DeliveryRow> {
    let mut rows = Vec::new();
    for (env_name, environment) in &fleet.environments {
        for (target, t) in &environment.targets {
            for placement in t.delivery_items.keys() {
                if product.is_some_and(|p| p != placement) {
                    continue;
                }
                let state = match super::delivery::read_state(fleet, env_name, target, placement, r)
                {
                    Ok(Some(item)) if item.has_receipt() => "delivered",
                    Ok(Some(_)) => "not_delivered",
                    Ok(None) => "not_recorded",
                    Err(e) => {
                        let why = e.to_string();
                        r.note(&format!(
                            "the delivery evidence of {placement} on {env_name}/{target} could not \
                             be read ({}); its state shows as unreadable",
                            why.lines().next().unwrap_or_default()
                        ));
                        "unreadable"
                    }
                };
                rows.push(DeliveryRow {
                    environment: env_name.clone(),
                    target: target.clone(),
                    product: placement.clone(),
                    state,
                });
            }
        }
    }
    rows
}

/// The newest saved receipt: its value states, its `generated_at` and its age. Accepts the
/// inventory document this command writes (`cells[].state`) and any receipt carrying
/// `generated_at`; a cell without a state is simply not recorded.
fn read_receipt(path: &Path) -> Result<ReceiptView, Error> {
    let invalid = |field: &str, at: Option<Location>, rule: FieldRule| {
        Error::from(Cause::InputInvalid {
            path: path.to_path_buf(),
            kind: InputKind::Receipt,
            at,
            field: field.to_string(),
            rule,
        })
    };
    let text = std::fs::read_to_string(path).map_err(|e| {
        Error::from(Cause::LocalIo {
            op: LocalOp::Read,
            path: path.to_path_buf(),
            io: e.kind().into(),
        })
    })?;
    let doc: Value = serde_json::from_str(&text).map_err(|e| {
        let at = Location {
            line: u32::try_from(e.line()).unwrap_or(u32::MAX),
            col: u32::try_from(e.column()).unwrap_or(u32::MAX),
        };
        invalid("its JSON", Some(at), FieldRule::Syntax)
    })?;
    let generated_at = doc["generated_at"].as_str().unwrap_or_default().to_string();
    let mut states = BTreeMap::new();
    for cell in doc["cells"].as_array().into_iter().flatten() {
        let (Some(product), Some(key), Some(env)) = (
            cell["product"].as_str(),
            cell["key"].as_str(),
            cell["env"].as_str(),
        ) else {
            continue;
        };
        let Ok(state) = serde_json::from_value::<ValueState>(cell["state"].clone()) else {
            continue;
        };
        states.insert(
            (product.to_string(), key.to_string(), env.to_string()),
            state,
        );
    }
    // Reuse the receipt's own age arithmetic: a default receipt carries the stamp we set.
    let mut stamped = crate::app::ready::Receipt::default();
    stamped.generated_at = generated_at.clone();
    let age = crate::app::receipt_age::age(&stamped, &crate::domain::provenance::utc_now());
    Ok(ReceiptView {
        states,
        generated_at,
        age_seconds: age.seconds,
    })
}

/// The schema-3 body: the document, the delivery rows and the typed `next`.
fn body(document: &Inventory, deliveries: &[DeliveryRow]) -> Result<Value, Error> {
    let serde_json::Value::Object(mut fields) =
        serde_json::to_value(document).map_err(|_| Cause::Bug {
            site: "the inventory document serializes",
        })?
    else {
        return Err(Cause::Bug {
            site: "the inventory document is a JSON object",
        }
        .into());
    };
    fields.insert(
        "deliveries".into(),
        serde_json::to_value(deliveries).map_err(|_| Cause::Bug {
            site: "the delivery rows serialize",
        })?,
    );
    fields.insert(
        "schema_version".into(),
        Value::from(crate::json::SCHEMA_VERSION),
    );
    if let Some(command) = next_command(document) {
        fields.insert(
            "next".into(),
            json!({"kind": "enter_value", "actor": "person", "command": command}),
        );
    }
    Ok(Value::Object(fields))
}

/// The first wanted key with no value, as the person's `opv set` command.
fn next_command(document: &Inventory) -> Option<String> {
    for cell in &document.cells {
        if cell.state != ValueState::Absent {
            continue;
        }
        let wanted = document
            .keys
            .iter()
            .find(|k| k.product == cell.product && k.key == cell.key)
            .and_then(|k| k.presence.get(&cell.env))
            .is_some_and(|p| *p == PresenceView::Present);
        if wanted {
            return Some(format!(
                "opv set {}/{} --env {}",
                cell.product, cell.key, cell.env
            ));
        }
    }
    None
}

fn state_word(state: &ValueState) -> String {
    match state {
        ValueState::Absent => "absent".into(),
        ValueState::Empty => "empty".into(),
        ValueState::Placeholder => "placeholder".into(),
        ValueState::Malformed { rule } => format!("malformed({rule})"),
        ValueState::Set => "set".into(),
        ValueState::Unreadable { cause } => {
            let cause = serde_json::to_value(cause)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_else(|| "op_failed".into());
            format!("unreadable({cause})")
        }
        ValueState::NotWanted { .. } => "not_wanted".into(),
    }
}

fn capability_letter(capability: Capability) -> char {
    match capability {
        Capability::Write => 'W',
        Capability::Read => 'R',
        Capability::None => '-',
        Capability::Unknown { .. } => '?',
    }
}

fn tier_word(tier: crate::domain::Tier) -> &'static str {
    match tier {
        crate::domain::Tier::Local => "local",
        crate::domain::Tier::Shared => "shared",
        crate::domain::Tier::Production => "production",
    }
}

/// The compact matrix: one row per key, one column per environment, each cell the state
/// word and the capability letter. Below it, the boundary ids, the delivery rows, the
/// receipt used (if any) and the typed next as a command.
fn render(document: &Inventory, deliveries: &[DeliveryRow]) -> String {
    let mut text = String::new();
    let labels: Vec<String> = document
        .keys
        .iter()
        .map(|k| format!("{}/{}", k.product, k.key))
        .collect();
    let label_width = labels.iter().map(String::len).max().unwrap_or(3).max(3);
    let header: Vec<String> = document
        .environments
        .iter()
        .map(|e| format!("{}[{}]", e.env, tier_word(e.tier)))
        .collect();
    let mut widths: Vec<usize> = header.iter().map(|h| h.len()).collect();
    let mut by_cell: BTreeMap<(&str, &str, &str), &inventory::Cell> = BTreeMap::new();
    for cell in &document.cells {
        by_cell.insert(
            (cell.product.as_str(), cell.key.as_str(), cell.env.as_str()),
            cell,
        );
    }
    for (i, env) in document.environments.iter().enumerate() {
        for key in &document.keys {
            let text = by_cell
                .get(&(key.product.as_str(), key.key.as_str(), env.env.as_str()))
                .map(|c| cell_text(c))
                .unwrap_or_default();
            widths[i] = widths[i].max(text.len());
        }
    }
    let mut head_line = format!("{:<label_width$}", "key");
    for (i, head) in header.iter().enumerate() {
        head_line.push_str(&format!("  {:<w$}", head, w = widths[i]));
    }
    text.push_str(head_line.trim_end());
    text.push('\n');
    for (row, key) in document.keys.iter().enumerate() {
        let mut line = format!("{:<label_width$}", labels[row]);
        for (i, env) in document.environments.iter().enumerate() {
            let cell = by_cell
                .get(&(key.product.as_str(), key.key.as_str(), env.env.as_str()))
                .map(|c| cell_text(c))
                .unwrap_or_default();
            line.push_str(&format!("  {:<w$}", cell, w = widths[i]));
        }
        text.push_str(line.trim_end());
        text.push('\n');
    }
    for env in &document.environments {
        let ids: Vec<String> = env
            .boundaries
            .iter()
            .map(|(name, bound)| match bound {
                Some(b) => format!("{name}={}/{}", b.vault_id, b.item_id),
                None => format!("{name}=unbound"),
            })
            .collect();
        text.push_str(&format!(
            "{}[{}]: {}\n",
            env.env,
            tier_word(env.tier),
            ids.join(" ")
        ));
    }
    for row in deliveries {
        text.push_str(&format!(
            "delivery {}/{}/{}: {}\n",
            row.environment, row.target, row.product, row.state
        ));
    }
    if let Some(cell) = document.cells.iter().find(|c| c.from_receipt.is_some())
        && let Some(use_) = &cell.from_receipt
    {
        match use_.age_seconds {
            Some(age_seconds) => text.push_str(&format!(
                "receipt {} ({}s old)\n",
                use_.generated_at, age_seconds
            )),
            None => text.push_str(&format!("receipt {}\n", use_.generated_at)),
        }
    }
    if let Some(command) = next_command(document) {
        text.push_str(&format!("next: {command}\n"));
    }
    text
}

fn cell_text(cell: &inventory::Cell) -> String {
    let mut out = format!(
        "{}/{}",
        state_word(&cell.state),
        capability_letter(cell.capability)
    );
    if cell.from_receipt.is_some() {
        out.push('*');
    }
    out
}

#[cfg(test)]
#[path = "inventory_tests.rs"]
mod tests;
