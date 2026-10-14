//! Delivery receipts (#106, FR-58, `docs/design/delivery-receipts.md`): value-free,
//! verifiable proof that a product's binding set was delivered to a target, kept per
//! placement (product and target) in the target's state vault (`state_vault_id`).
//!
//! - Each placement has one delivery item, `opv · delivery · <product> · <target>`, created
//!   by `opv bootstrap`, which records its ID in the target's `delivery_items`; nothing here
//!   looks a state item up by title (FR-13), and a placement without a recorded item gets
//!   no evidence. Writing one placement's item never reads or changes another's.
//! - After a sync whose writes the provider confirmed, [`record`] keeps, per confirmed
//!   name, the evidence line `v1|version|fingerprint|item_id|field` (the store's version
//!   and a keyed fingerprint of the 1Password value, key in the same item). Those lines
//!   are also the version ledger `plan` and `status` judge by ([`ledgers`], FR-54, D11).
//!   Once every name of the binding set was confirmed, a revision is minted and its public
//!   receipt kept in the item.
//! - [`verify`] (`opv delivery verify`) is read-only: per placement, it reads the delivery
//!   item, the values and the target's listing, compares in memory and reports per name.
//!
//! Evidence never leaves the state item: no store version, fingerprint, key or value is
//! printed, logged, put in argv or written to a receipt file (SR-1). Only identities that
//! can read the values should be able to read the state vault.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;

use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::write_err;
use crate::adapters::{onepassword, onepassword_tidy};
use crate::domain::delivery::{
    BindingRef, Evidence, Observed, Receipt, SCHEMA, Scope, Source, Verification, decode_evidence,
    encode_evidence, new_revision, select,
};
use crate::domain::ledger::{Ledger, hmac_hex, random_key};
use crate::domain::plan::StoreEntry;
use crate::domain::{Boundary, Fleet, Kind, SecretValue, key_label, rules};
use crate::error::Error;
use crate::runner::CommandRunner;

const RECEIPT_FIELD: &str = "receipt";
const KEY_FIELD: &str = "evidence key";

/// The binding set of `product` on target `target` of `env_name`: exactly the secrets the
/// target delivers for it, by target name, with the 1Password field each value comes from
/// (a shared key names its source, FR-45), in the source's boundary item (FR-57). A key
/// not desired here, skipped by a mode (`prefix_by_mode` skip), or personal (FR-55) is
/// never delivered, so it is never part of the set. Sorted by name.
pub fn bindings(
    fleet: &Fleet,
    env_name: &str,
    target: &str,
    product: &str,
) -> Result<Vec<BindingRef>, Error> {
    let (_, t) = super::target(fleet, env_name, target)?;
    if !fleet.delivers(env_name, target, product) {
        return Ok(Vec::new());
    }
    let Some(prod) = fleet.products.get(product) else {
        return Ok(Vec::new());
    };
    let env = fleet.environment(env_name)?;
    let mut out: Vec<BindingRef> = prod
        .keys
        .iter()
        .filter(|(_, s)| s.kind == Kind::Secret && !s.personal)
        .filter(|(_, s)| rules::applies(s, env_name, env, product))
        .map(|(k, s)| {
            let (sp, sk) = s.source().unwrap_or((product, k));
            Ok(BindingRef {
                name: t.env_name(product, k),
                source: Source {
                    item_id: fleet.boundary(env_name, sp)?.item_id.clone(),
                    field: key_label(sp, sk),
                },
            })
        })
        .collect::<Result<_, Error>>()?;
    out.sort();
    Ok(out)
}

/// The products target `target` of `env_name` delivers that have at least one binding, or
/// `only`.
fn products_in_scope(
    fleet: &Fleet,
    env_name: &str,
    target: &str,
    only: Option<&str>,
) -> Result<Vec<String>, Error> {
    let mut out = Vec::new();
    for p in fleet.products.keys() {
        if only.is_some_and(|o| o != p) {
            continue;
        }
        if !bindings(fleet, env_name, target, p)?.is_empty() {
            out.push(p.clone());
        }
    }
    Ok(out)
}

/// The 1Password account this session reaches (`op whoami`'s account UUID; the same for a
/// person and a service account of that account), or `unknown`.
fn account_id(r: &dyn CommandRunner) -> String {
    let call = crate::runner::Call::new(onepassword::OP, &["whoami", "--format", "json"]);
    let Ok(crate::runner::Outcome::Done(out)) = r.read(&call, &[]) else {
        return "unknown".into();
    };
    serde_json::from_slice::<Value>(&out.stdout)
        .ok()
        .and_then(|v| v["account_uuid"].as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".into())
}

/// The scope a receipt is bound to.
fn scope(
    fleet: &Fleet,
    env_name: &str,
    target: &str,
    product: &str,
    account: &str,
) -> Result<Scope, Error> {
    let (_, t) = super::target(fleet, env_name, target)?;
    Ok(Scope {
        account_id: account.to_string(),
        environment: env_name.to_string(),
        product: product.to_string(),
        target: target.to_string(),
        provider: t.provider().section().to_string(),
        locator: t.target_locator(),
    })
}

/// The values of the boundary items' declared fields (FR-57), by `product/KEY`, each item
/// read once by IDs and **fresh** (never `op`'s local cache): a receipt must never vouch for
/// a value that changed since. Zeroized on drop.
fn values_by_field(
    fleet: &Fleet,
    env_name: &str,
    r: &dyn CommandRunner,
) -> Result<BTreeMap<String, SecretValue>, Error> {
    let env = fleet.environment(env_name)?;
    let mut out = BTreeMap::new();
    for (name, b) in super::tidy::boundaries_needed(fleet, env_name)? {
        let item = onepassword::read_whole_fresh(r, env, b)?;
        let (layout, _) = onepassword_tidy::parse(item.raw())?;
        let part = super::tidy::in_boundary(fleet, &name);
        out.extend(
            crate::domain::convention::read_fields(&layout, &part, env_name)
                .into_iter()
                .map(|f| (key_label(&f.section, &f.label), f.value)),
        );
    }
    Ok(out)
}

/// A placement's delivery item as read: the receipt, the key and the evidence by name.
struct StateItem {
    /// The delivery item's vault and item, as an item read addresses them.
    at: Boundary,
    receipt: Option<Receipt>,
    key: Option<Zeroizing<String>>,
    evidence: Vec<Evidence>,
    raw: Zeroizing<Vec<u8>>,
}

/// Where the delivery item of `product` on target `target` is: the target's state vault and
/// the item ID recorded in its `delivery_items` (FR-13: never a title lookup). `None` when
/// none is recorded.
fn item_at(fleet: &Fleet, env_name: &str, target: &str, product: &str) -> Option<Boundary> {
    let t = fleet.environments.get(env_name)?.targets.get(target)?;
    Some(Boundary {
        vault_id: t.state_vault_id.clone(),
        item_id: t.delivery_items.get(product)?.clone(),
    })
}

/// Read the delivery item of `product` on target `target`, fresh and by its recorded ID;
/// `None` when no item is recorded. Values stay in memory.
fn read_state(
    fleet: &Fleet,
    env_name: &str,
    target: &str,
    product: &str,
    r: &dyn CommandRunner,
) -> Result<Option<StateItem>, Error> {
    let env = fleet.environment(env_name)?;
    let Some(at) = item_at(fleet, env_name, target, product) else {
        return Ok(None);
    };
    let read = onepassword::read_whole_fresh(r, env, &at)?;
    let raw = Zeroizing::new(read.raw().to_vec());
    let doc: Value = serde_json::from_slice(&raw)
        .map_err(|_| Error::Source("the delivery item is not valid JSON".into()))?;
    let mut receipt = None;
    let mut key = None;
    let mut evidence = Vec::new();
    for f in doc["fields"].as_array().into_iter().flatten() {
        let (Some(label), Some(value)) = (f["label"].as_str(), f["value"].as_str()) else {
            continue;
        };
        match label {
            RECEIPT_FIELD => receipt = serde_json::from_str::<Receipt>(value).ok(),
            KEY_FIELD if !value.is_empty() => key = Some(Zeroizing::new(value.to_string())),
            name => {
                if let Some(e) = decode_evidence(name, value) {
                    evidence.push(e);
                }
            }
        }
    }
    Ok(Some(StateItem {
        at,
        receipt,
        key,
        evidence,
        raw,
    }))
}

/// The version ledger of each placement on target `target` whose delivery item is recorded
/// (FR-54, FR-58, D11): its evidence lines under its evidence key. An item that cannot be
/// read is left out with a note: its names stay unknown.
pub(crate) fn ledgers(
    fleet: &Fleet,
    env_name: &str,
    target: &str,
    r: &dyn CommandRunner,
) -> Vec<Ledger> {
    let Some(t) = fleet
        .environments
        .get(env_name)
        .and_then(|e| e.targets.get(target))
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for product in t.delivery_items.keys() {
        match read_state(fleet, env_name, target, product, r) {
            Ok(Some(s)) => out.push(Ledger::from_evidence(
                s.key.map(|k| SecretValue::new(k.to_string())),
                &s.evidence,
            )),
            Ok(None) => {}
            Err(e) => r.note(&format!(
                "the delivery evidence of {product} on {} could not be read ({}); its \
                 names show as unknown",
                super::placement(env_name, target),
                e.code().as_str()
            )),
        }
    }
    out
}

/// Why a product got no revision this run.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct NotMinted {
    pub product: String,
    pub reason: String,
}

/// What [`record`] did, for the sync report.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Recorded {
    pub minted: Vec<Receipt>,
    pub not_minted: Vec<NotMinted>,
}

/// After a confirmed sync of target `target` of `env_name`, for each product in scope
/// (FR-58, D11):
/// - each name of its binding set this run wrote (`written`) or proved identical
///   (`identical`), with its store version in `listed`, gets a fresh evidence line in the
///   placement's delivery item: these lines are the ledger `plan` judges by;
/// - once every name of the binding set was confirmed so, a revision is minted (an
///   unchanged binding set and evidence keep their revision).
///
/// A placement without a recorded delivery item gets nothing (`opv bootstrap` creates it).
/// Only that placement's own item is read and written.
#[allow(clippy::too_many_arguments)]
pub fn record(
    fleet: &Fleet,
    env_name: &str,
    target: &str,
    only: Option<&str>,
    written: &BTreeSet<String>,
    identical: &BTreeSet<String>,
    listed: &[StoreEntry],
    plan_id: &str,
    r: &dyn CommandRunner,
) -> Result<Recorded, Error> {
    let env = fleet.environment(env_name)?;
    let account = account_id(r);
    let values = values_by_field(fleet, env_name, r)?;
    let version_of = |name: &str| {
        listed
            .iter()
            .find(|e| e.name == name)
            .and_then(|e| e.version.clone())
    };
    let mut out = Recorded::default();
    for product in products_in_scope(fleet, env_name, target, only)? {
        let set = bindings(fleet, env_name, target, &product)?;
        let unconfirmed: Vec<&str> = set
            .iter()
            .filter(|b| !written.contains(&b.name) && !identical.contains(&b.name))
            .map(|b| b.name.as_str())
            .collect();
        let unlisted: Vec<&str> = set
            .iter()
            .filter(|b| version_of(&b.name).is_none())
            .map(|b| b.name.as_str())
            .collect();
        let mut why = Vec::new();
        if !unconfirmed.is_empty() {
            why.push(format!(
                "not confirmed by this sync: {}",
                unconfirmed.join(", ")
            ));
        }
        if !unlisted.is_empty() {
            why.push(format!(
                "the target lists no version for: {}",
                unlisted.join(", ")
            ));
        }
        let Some(state) = read_state(fleet, env_name, target, &product, r)? else {
            why.push(format!(
                "no delivery item is recorded for {product} on {}; opv bootstrap creates it",
                super::placement(env_name, target)
            ));
            out.not_minted.push(NotMinted {
                product,
                reason: why.join("; "),
            });
            continue;
        };
        let key = state
            .key
            .clone()
            .unwrap_or_else(|| Zeroizing::new(random_key()));
        // Keep the lines of names still in the binding set; replace each confirmed one.
        let mut evidence: BTreeMap<String, Evidence> = state
            .evidence
            .iter()
            .filter(|e| set.iter().any(|b| b.name == e.name))
            .map(|e| (e.name.clone(), e.clone()))
            .collect();
        let mut unread = false;
        for b in set
            .iter()
            .filter(|b| !unconfirmed.contains(&b.name.as_str()))
        {
            let (Some(version), Some(value)) = (version_of(&b.name), values.get(&b.source.field))
            else {
                unread |= !values.contains_key(&b.source.field);
                continue;
            };
            evidence.insert(
                b.name.clone(),
                Evidence {
                    name: b.name.clone(),
                    store_version: version,
                    fingerprint: hmac_hex(key.as_bytes(), value.expose().as_bytes()),
                    source: b.source.clone(),
                },
            );
        }
        if unread {
            why.push("a source value could not be read from 1Password".into());
        }
        let evidence: Vec<Evidence> = evidence.into_values().collect();
        let this_scope = scope(fleet, env_name, target, &product, &account)?;
        let receipt = if why.is_empty() {
            // Unchanged binding set and evidence: the same delivery, the same revision.
            let unchanged = state.receipt.as_ref().filter(|rec| {
                rec.scope == this_scope
                    && rec.bindings == set
                    && lines(&state.evidence) == lines(&evidence)
            });
            Some(match unchanged {
                Some(rec) => rec.clone(),
                None => {
                    let mut bytes = [0u8; 16];
                    getrandom::fill(&mut bytes).expect("the OS random source");
                    Receipt {
                        schema: SCHEMA.into(),
                        revision: new_revision(bytes),
                        scope: this_scope,
                        bindings: set.clone(),
                        delivered_at: crate::domain::provenance::utc_now(),
                        plan_id: Some(plan_id.to_string()),
                        opv_version: env!("CARGO_PKG_VERSION").into(),
                    }
                }
            })
        } else {
            None
        };
        let kept = receipt.as_ref().or(state.receipt.as_ref());
        let changed = state.key.is_none()
            || lines(&state.evidence) != lines(&evidence)
            || kept.map(|k| &k.revision) != state.receipt.as_ref().map(|k| &k.revision);
        if changed {
            write_state(r, env, &state, kept, &key, &evidence)?;
        }
        match receipt {
            Some(rec) => out.minted.push(rec),
            None => out.not_minted.push(NotMinted {
                product,
                reason: why.join("; "),
            }),
        }
    }
    Ok(out)
}

/// The encoded evidence lines, sorted: what two readings of an item compare by.
fn lines(evidence: &[Evidence]) -> Vec<String> {
    let mut out: Vec<String> = evidence.iter().filter_map(encode_evidence).collect();
    out.sort();
    out
}

/// Rewrite the placement's delivery item `state`: its notes kept, then the receipt (when
/// one was ever minted), the key and one concealed evidence field per name.
fn write_state(
    r: &dyn CommandRunner,
    env: &crate::domain::Environment,
    state: &StateItem,
    receipt: Option<&Receipt>,
    key: &str,
    evidence: &[Evidence],
) -> Result<(), Error> {
    let mut doc: Value = serde_json::from_slice(&state.raw)
        .map_err(|_| Error::Source("the delivery item could not be read".into()))?;
    let mut fields: Vec<Value> = doc["fields"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|f| f["purpose"] == "NOTES")
        .cloned()
        .collect();
    if let Some(receipt) = receipt {
        let receipt_json = serde_json::to_string(receipt)
            .map_err(|_| Error::Config("cannot serialize the delivery receipt".into()))?;
        fields.push(
            json!({"id": "receipt", "label": RECEIPT_FIELD, "type": "STRING", "value": receipt_json}),
        );
    }
    fields
        .push(json!({"id": "evidence-key", "label": KEY_FIELD, "type": "CONCEALED", "value": key}));
    for e in evidence {
        let line = encode_evidence(e).ok_or_else(|| {
            Error::Source(format!("cannot record evidence for {}", e.name).into())
        })?;
        fields.push(json!({"id": e.name, "label": e.name, "type": "CONCEALED", "value": line}));
    }
    doc["fields"] = Value::Array(fields);
    doc.as_object_mut().map(|o| o.remove("sections"));
    let template = Zeroizing::new(
        serde_json::to_vec(&doc)
            .map_err(|_| Error::Config("cannot serialize the delivery item".into()))?,
    );
    onepassword_tidy::write(r, env, &state.at, &template)?;
    Ok(())
}

/// One placement's verification, as `opv delivery verify` reports it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PlacementCheck {
    pub product: String,
    pub target: String,
    #[serde(flatten)]
    pub verification: Verification,
    /// `staged` (written, not yet deployed), `deployed`, or `n/a` (the target applies
    /// writes at once); never part of `state`.
    pub deployed: &'static str,
    /// The receipt this was checked against, when it is not the current delivery.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_revision: Option<String>,
}

/// `opv delivery verify <env> [--product p] [--target t] [--receipt file] [--json]`:
/// read-only. Every placement of the product (each target of `env` that delivers it), or
/// only those on `targets`; each judged on its own (FR-58).
#[allow(clippy::too_many_arguments)]
pub fn verify(
    fleet: &Fleet,
    env_name: &str,
    only: Option<&str>,
    targets: &[String],
    receipt_file: Option<&Path>,
    r: &dyn CommandRunner,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let names = super::resolve_targets(fleet, env_name, targets, "delivery verify")?;
    let from_file: Vec<Receipt> = match receipt_file {
        Some(p) => read_receipt_file(p)?,
        None => Vec::new(),
    };
    let mut checks = Vec::new();
    for target in &names {
        if products_in_scope(fleet, env_name, target, only)?.is_empty() {
            continue;
        }
        checks.extend(verify_target(fleet, env_name, target, only, &from_file, r)?);
    }
    report(out, env_name, &checks, json)?;
    if checks.iter().all(|c| c.verification.state == "verified") {
        Ok(())
    } else {
        let n = checks
            .iter()
            .filter(|c| c.verification.state != "verified")
            .count();
        Err(Error::findings(n, format!("opv sync {env_name}")))
    }
}

/// The placements of target `target` (`only`: that product's), signed in with the target's
/// own deploy identity.
fn verify_target(
    fleet: &Fleet,
    env_name: &str,
    target: &str,
    only: Option<&str>,
    from_file: &[Receipt],
    r: &dyn CommandRunner,
) -> Result<Vec<PlacementCheck>, Error> {
    let signed_in = super::signin::open_targeted(
        fleet,
        env_name,
        Some(target),
        r,
        super::signin::Reach::Target,
    )?;
    let r: &dyn CommandRunner = &signed_in;
    let (_, ports) = super::open_target(fleet, env_name, target, r)?;
    let listed: Vec<StoreEntry> = match &ports {
        crate::ports::Ports::Staged { store, .. } => store.list()?,
        crate::ports::Ports::Pinned { store, .. } => store.list()?,
    };
    let values = values_by_field(fleet, env_name, r)?;
    let account = account_id(r);
    let mut checks = Vec::new();
    for product in products_in_scope(fleet, env_name, target, only)? {
        let expected = bindings(fleet, env_name, target, &product)?;
        let this_scope = scope(fleet, env_name, target, &product, &account)?;
        let state = read_state(fleet, env_name, target, &product, r)?;
        let fingerprints: BTreeMap<String, String> =
            match state.as_ref().and_then(|s| s.key.clone()) {
                Some(key) => expected
                    .iter()
                    .filter_map(|b| {
                        values.get(&b.source.field).map(|v| {
                            (
                                b.name.clone(),
                                hmac_hex(key.as_bytes(), v.expose().as_bytes()),
                            )
                        })
                    })
                    .collect(),
                None => BTreeMap::new(),
            };
        let observed: Vec<Observed<'_>> = expected
            .iter()
            .map(|b| Observed {
                name: &b.name,
                listed_version: listed
                    .iter()
                    .find(|e| e.name == b.name)
                    .and_then(|e| e.version.as_deref()),
                fingerprint_now: fingerprints.get(&b.name).map(String::as_str),
            })
            .collect();
        let recorded = state
            .as_ref()
            .and_then(|s| s.receipt.as_ref().map(|rec| (rec, s.evidence.as_slice())));
        let mut verification =
            crate::domain::delivery::verify(recorded, &this_scope, &expected, &observed);
        let pending = expected
            .iter()
            .any(|b| listed.iter().any(|e| e.name == b.name && e.pending));
        let deployed = match &ports {
            crate::ports::Ports::Staged { runtime, .. } if runtime.live() => "n/a",
            _ if pending => "staged",
            _ => "deployed",
        };
        // A receipt the caller kept: selected by its full scope, independent of order; it
        // must be this very delivery to count.
        let mut receipt_revision = None;
        let kept = select(from_file, &this_scope).map_err(|duplicate| {
            Error::Config(
                format!(
                    "duplicate_scope: the receipt file holds {} receipts for {product} on {}; \
                     keep one",
                    duplicate.count,
                    super::placement(env_name, target)
                )
                .into(),
            )
            .with_code(crate::error::Code::Usage)
        })?;
        if let Some(kept) = kept
            && verification.revision.as_deref() != Some(kept.revision.as_str())
        {
            receipt_revision = Some(kept.revision.clone());
            verification.state = "superseded";
            verification.reason = Some(format!(
                "the receipt's revision {} is not the current delivery",
                kept.revision
            ));
        }
        checks.push(PlacementCheck {
            product,
            target: target.to_string(),
            verification,
            deployed,
            receipt_revision,
        });
    }
    Ok(checks)
}

/// The deliveries a receipt file holds (`{"schema", "deliveries": [...]}`).
fn read_receipt_file(path: &Path) -> Result<Vec<Receipt>, Error> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        Error::Config(format!("cannot read {}: {}", path.display(), e.kind()).into())
    })?;
    let doc: Value = serde_json::from_str(&text).map_err(|_| {
        Error::Config(format!("{} is not a delivery receipt", path.display()).into())
    })?;
    if doc["schema"] != SCHEMA {
        return Err(Error::Config(
            format!("{} is not a {SCHEMA} receipt", path.display()).into(),
        ));
    }
    serde_json::from_value(doc["deliveries"].clone())
        .map_err(|_| Error::Config(format!("{} has no deliveries", path.display()).into()))
}

/// Write the receipts minted by a sync to `path` (`{"schema", "deliveries": [...]}`):
/// names, ids and times only.
pub fn write_receipt_file(path: &Path, minted: &[Receipt]) -> Result<(), Error> {
    let doc = json!({"schema": SCHEMA, "deliveries": minted});
    let text = serde_json::to_string_pretty(&doc)
        .map_err(|_| Error::Config("cannot serialize the delivery receipt".into()))?;
    super::init::write_atomic(path, &format!("{text}\n"), true)
}

fn report(
    out: &mut dyn Write,
    env_name: &str,
    checks: &[PlacementCheck],
    json: bool,
) -> Result<(), Error> {
    if json {
        let doc = json!({
            "schema_version": crate::json::SCHEMA_VERSION,
            "environment": env_name,
            "placements": checks,
        });
        return writeln!(out, "{doc}").map_err(write_err);
    }
    for c in checks {
        let v = &c.verification;
        let rev = v.revision.as_deref().unwrap_or("-");
        writeln!(
            out,
            "{} {}: {} (revision {rev}; {})",
            super::placement(env_name, &c.target),
            c.product,
            v.state,
            c.deployed
        )
        .map_err(write_err)?;
        if let Some(reason) = &v.reason {
            writeln!(out, "  {reason}").map_err(write_err)?;
        }
        for n in v.names.iter().filter(|n| n.state != "verified") {
            writeln!(out, "  {:<32} {}", n.name, n.state).map_err(write_err)?;
        }
    }
    if checks.is_empty() {
        writeln!(out, "{env_name}: no product delivers a secret here").map_err(write_err)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "delivery_tests.rs"]
mod tests;
