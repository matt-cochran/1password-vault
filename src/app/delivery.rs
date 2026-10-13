//! Delivery receipts (#106, `docs/design/delivery-receipts.md`): value-free, verifiable proof
//! that a product's binding set was delivered to a target, kept per product in the
//! environment's state vault (`state_vault_id`).
//!
//! - After a sync whose writes the provider confirmed, [`record`] mints a revision for each
//!   product in scope whose every name was written now or proven identical, and keeps in
//!   the product's state item (`opv · delivery · <product>`) the public receipt and, per
//!   name, the private evidence: the store's version and a keyed fingerprint of the
//!   1Password value (key in the same state item). A product with a name opv could not
//!   confirm gets no revision.
//! - [`verify`] (`opv delivery verify`) is read-only: it reads the state item, the values
//!   item and the target's listing, compares in memory and reports per name.
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
use crate::adapters::{onepassword, onepassword_init, onepassword_tidy};
use crate::domain::delivery::{
    BindingRef, Evidence, Observed, Receipt, SCHEMA, Scope, Source, Verification, decode_evidence,
    encode_evidence, new_revision,
};
use crate::domain::ledger::{hmac_hex, random_key};
use crate::domain::plan::StoreEntry;
use crate::domain::{Fleet, Kind, SIMPLE_PRODUCT, SecretValue};
use crate::error::Error;
use crate::host::Host;
use crate::runner::CommandRunner;

/// The title of a product's state item.
pub fn item_title(product: &str) -> String {
    format!("opv · delivery · {product}")
}
const RECEIPT_FIELD: &str = "receipt";
const KEY_FIELD: &str = "evidence key";

/// `product/KEY`, or `KEY` under the simple profile: the field a value comes from.
fn field_label(product: &str, key: &str) -> String {
    if product == SIMPLE_PRODUCT {
        key.to_string()
    } else {
        format!("{product}/{key}")
    }
}

/// The binding set of `product` in `env_name`: each secret it delivers, by target name,
/// with the 1Password field its value comes from (a shared key names its source, FR-45).
/// Personal keys are never delivered (FR-55). Sorted by name.
pub fn bindings(fleet: &Fleet, env_name: &str, product: &str) -> Result<Vec<BindingRef>, Error> {
    let (env, t) = super::target(fleet, env_name)?;
    if !fleet.delivers(env_name, product) {
        return Ok(Vec::new());
    }
    let Some(prod) = fleet.products.get(product) else {
        return Ok(Vec::new());
    };
    let mut out: Vec<BindingRef> = prod
        .keys
        .iter()
        .filter(|(_, s)| s.kind == Kind::Secret && !s.personal)
        .filter(|(_, s)| s.environments.iter().any(|e| e == env_name))
        .map(|(k, s)| {
            let (sp, sk) = s.source().unwrap_or((product, k));
            BindingRef {
                name: t.env_name(product, k),
                source: Source {
                    item_id: env.item_id.clone(),
                    field: field_label(sp, sk),
                },
            }
        })
        .collect();
    out.sort();
    Ok(out)
}

/// The products `env_name` delivers that have at least one binding, or `only`.
fn products_in_scope(
    fleet: &Fleet,
    env_name: &str,
    only: Option<&str>,
) -> Result<Vec<String>, Error> {
    let mut out = Vec::new();
    for p in fleet.products.keys() {
        if only.is_some_and(|o| o != p) {
            continue;
        }
        if !bindings(fleet, env_name, p)?.is_empty() {
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
fn scope(fleet: &Fleet, env_name: &str, product: &str, account: &str) -> Result<Scope, Error> {
    let (_, t) = super::target(fleet, env_name)?;
    Ok(Scope {
        account_id: account.to_string(),
        environment: env_name.to_string(),
        product: product.to_string(),
        provider: t.provider().section().to_string(),
        locator: t.target_locator(),
    })
}

/// The values of the values item's declared fields, by `product/KEY` (or `KEY`), read
/// once by IDs and **fresh** (never `op`'s local cache): a receipt must never vouch for a
/// value that changed since. Zeroized on drop.
fn values_by_field(
    fleet: &Fleet,
    env_name: &str,
    r: &dyn CommandRunner,
) -> Result<BTreeMap<String, SecretValue>, Error> {
    let env = fleet.environment(env_name)?;
    let item = onepassword::read_whole_fresh(r, env)?;
    let (layout, _) = onepassword_tidy::parse(item.raw())?;
    Ok(
        crate::domain::convention::read_fields(&layout, fleet, env_name)
            .into_iter()
            .map(|f| (field_label(&f.section, &f.label), f.value))
            .collect(),
    )
}

/// A product's state item as read: the receipt, the key and the evidence by name.
struct StateItem {
    environment: crate::domain::Environment,
    receipt: Option<Receipt>,
    key: Option<Zeroizing<String>>,
    evidence: Vec<Evidence>,
    raw: Option<Zeroizing<Vec<u8>>>,
}

/// Read `product`'s state item in the state vault, if it exists. Values stay in memory.
fn read_state(
    fleet: &Fleet,
    env_name: &str,
    product: &str,
    r: &dyn CommandRunner,
) -> Result<Option<StateItem>, Error> {
    let env = fleet.environment(env_name)?;
    let Some(vault) = env.state_vault_id.as_deref() else {
        return Ok(None);
    };
    let item = match onepassword_init::find_item(r, vault, &item_title(product), &Host::detect)? {
        onepassword_init::Lookup::Found(i) => i,
        onepassword_init::Lookup::Missing(_) => return Ok(None),
    };
    let mut state_env = env.clone();
    state_env.vault_id = vault.to_string();
    state_env.item_id = item.id;
    let read = onepassword::read_whole_fresh(r, &state_env)?;
    let raw = Zeroizing::new(read.raw().to_vec());
    let doc: Value = serde_json::from_slice(&raw)
        .map_err(|_| Error::Source("the delivery state item is not valid JSON".into()))?;
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
        environment: state_env,
        receipt,
        key,
        evidence,
        raw: Some(raw),
    }))
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

/// After a confirmed sync of `env_name`: for each product in scope, mint a revision when
/// every binding was written by this run (`written`) or proven identical (`identical`),
/// with its store version in `listed`, and keep the receipt and evidence in the product's
/// state item. A product whose binding set and evidence are unchanged keeps its revision.
#[allow(clippy::too_many_arguments)]
pub fn record(
    fleet: &Fleet,
    env_name: &str,
    only: Option<&str>,
    written: &BTreeSet<String>,
    identical: &BTreeSet<String>,
    listed: &[StoreEntry],
    plan_id: &str,
    r: &dyn CommandRunner,
) -> Result<Recorded, Error> {
    let env = fleet.environment(env_name)?;
    let Some(vault) = env.state_vault_id.clone() else {
        return Ok(Recorded::default());
    };
    let account = account_id(r);
    let values = values_by_field(fleet, env_name, r)?;
    let mut out = Recorded::default();
    for product in products_in_scope(fleet, env_name, only)? {
        let set = bindings(fleet, env_name, &product)?;
        let unconfirmed: Vec<&str> = set
            .iter()
            .filter(|b| !written.contains(&b.name) && !identical.contains(&b.name))
            .map(|b| b.name.as_str())
            .collect();
        let unlisted: Vec<&str> = set
            .iter()
            .filter(|b| {
                !listed
                    .iter()
                    .any(|e| e.name == b.name && e.version.is_some())
            })
            .map(|b| b.name.as_str())
            .collect();
        if !unconfirmed.is_empty() || !unlisted.is_empty() {
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
            out.not_minted.push(NotMinted {
                product,
                reason: why.join("; "),
            });
            continue;
        }
        let state = read_state(fleet, env_name, &product, r)?;
        let key = state
            .as_ref()
            .and_then(|s| s.key.clone())
            .unwrap_or_else(|| Zeroizing::new(random_key()));
        let mut evidence = Vec::new();
        for b in &set {
            let Some(value) = values.get(&b.source.field) else {
                continue;
            };
            let version = listed
                .iter()
                .find(|e| e.name == b.name)
                .and_then(|e| e.version.clone())
                .expect("checked above");
            evidence.push(Evidence {
                name: b.name.clone(),
                store_version: version,
                fingerprint: hmac_hex(key.as_bytes(), value.expose().as_bytes()),
                source: b.source.clone(),
            });
        }
        if evidence.len() != set.len() {
            out.not_minted.push(NotMinted {
                product,
                reason: "a source value could not be read from 1Password".into(),
            });
            continue;
        }
        let this_scope = scope(fleet, env_name, &product, &account)?;
        // Unchanged binding set and evidence: the same delivery, the same revision.
        let unchanged = state.as_ref().and_then(|s| {
            let rec = s.receipt.as_ref()?;
            let same_evidence = {
                let mut a: Vec<String> = s.evidence.iter().filter_map(encode_evidence).collect();
                let mut b: Vec<String> = evidence.iter().filter_map(encode_evidence).collect();
                a.sort();
                b.sort();
                a == b
            };
            (rec.scope == this_scope && rec.bindings == set && same_evidence).then(|| rec.clone())
        });
        let receipt = match unchanged {
            Some(r) => r,
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
        };
        write_state(
            r,
            env,
            &vault,
            &product,
            state.as_ref(),
            &receipt,
            &key,
            &evidence,
        )?;
        out.minted.push(receipt);
    }
    Ok(out)
}

/// Write (creating when missing) `product`'s state item: the receipt, the key, and one
/// concealed evidence field per name. The whole field list is replaced.
#[allow(clippy::too_many_arguments)]
fn write_state(
    r: &dyn CommandRunner,
    env: &crate::domain::Environment,
    vault: &str,
    product: &str,
    state: Option<&StateItem>,
    receipt: &Receipt,
    key: &str,
    evidence: &[Evidence],
) -> Result<(), Error> {
    let (state_env, raw) = match state {
        Some(s) => (s.environment.clone(), s.raw.clone()),
        None => {
            let tag = format!("opv-delivery:{}/{product}", env.name);
            let item =
                onepassword_init::create_item_tagged(r, vault, &item_title(product), &[tag])?;
            let mut e = env.clone();
            e.vault_id = vault.to_string();
            e.item_id = item.id;
            let read = onepassword::read_whole_fresh(r, &e)?;
            (e, Some(Zeroizing::new(read.raw().to_vec())))
        }
    };
    let mut doc: Value = raw
        .as_ref()
        .and_then(|r| serde_json::from_slice(r).ok())
        .ok_or_else(|| Error::Source("the delivery state item could not be read".into()))?;
    let receipt_json = serde_json::to_string(receipt)
        .map_err(|_| Error::Config("cannot serialize the delivery receipt".into()))?;
    let mut fields = vec![
        json!({"id": "receipt", "label": RECEIPT_FIELD, "type": "STRING", "value": receipt_json}),
        json!({"id": "evidence-key", "label": KEY_FIELD, "type": "CONCEALED", "value": key}),
    ];
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
            .map_err(|_| Error::Config("cannot serialize the delivery state item".into()))?,
    );
    onepassword_tidy::write(r, &state_env, &template)?;
    Ok(())
}

/// One product's verification, as `opv delivery verify` reports it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ProductCheck {
    pub product: String,
    #[serde(flatten)]
    pub verification: Verification,
    /// `staged` (written, not yet deployed), `deployed`, or `n/a` (the target applies
    /// writes at once); never part of `state`.
    pub deployed: &'static str,
    /// The receipt this was checked against, when it is not the current delivery.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_revision: Option<String>,
}

/// `opv delivery verify <env> [--product p] [--receipt file] [--json]`: read-only.
pub fn verify(
    fleet: &Fleet,
    env_name: &str,
    only: Option<&str>,
    receipt_file: Option<&Path>,
    r: &dyn CommandRunner,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let env = fleet.environment(env_name)?;
    if env.state_vault_id.is_none() {
        return Err(Error::Config(
            format!(
                "environment {env_name} has no state_vault_id: delivery receipts are kept in a \
                 state vault the deploy identity may write"
            )
            .into(),
        )
        .with_next(format!("opv bootstrap --state {env_name}")));
    }
    let from_file: Vec<Receipt> = match receipt_file {
        Some(p) => read_receipt_file(p)?,
        None => Vec::new(),
    };
    let signed_in = super::signin::open(fleet, env_name, r, super::signin::Reach::Target)?;
    let r: &dyn CommandRunner = &signed_in;
    let (_, ports) = super::open_target(fleet, env_name, r)?;
    let listed: Vec<StoreEntry> = match &ports {
        crate::ports::Ports::Staged { store, .. } => store.list()?,
        crate::ports::Ports::Pinned { store, .. } => store.list()?,
    };
    let values = values_by_field(fleet, env_name, r)?;
    let account = account_id(r);
    let mut checks = Vec::new();
    for product in products_in_scope(fleet, env_name, only)? {
        let expected = bindings(fleet, env_name, &product)?;
        let this_scope = scope(fleet, env_name, &product, &account)?;
        let state = read_state(fleet, env_name, &product, r)?;
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
        // A receipt the caller kept: it must be this very delivery to count.
        let mut receipt_revision = None;
        if let Some(kept) = from_file.iter().find(|k| k.scope.product == product)
            && verification.revision.as_deref() != Some(kept.revision.as_str())
        {
            {
                receipt_revision = Some(kept.revision.clone());
                verification.state = "superseded";
                verification.reason = Some(format!(
                    "the receipt's revision {} is not the current delivery",
                    kept.revision
                ));
            }
        }
        checks.push(ProductCheck {
            product,
            verification,
            deployed,
            receipt_revision,
        });
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
    checks: &[ProductCheck],
    json: bool,
) -> Result<(), Error> {
    if json {
        let doc = json!({
            "schema_version": crate::json::SCHEMA_VERSION,
            "environment": env_name,
            "products": checks,
        });
        return writeln!(out, "{doc}").map_err(write_err);
    }
    for c in checks {
        let v = &c.verification;
        let rev = v.revision.as_deref().unwrap_or("-");
        writeln!(
            out,
            "{env_name} {}: {} (revision {rev}; {})",
            c.product, v.state, c.deployed
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
