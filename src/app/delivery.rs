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
use crate::adapters::{onepassword, onepassword_diagnose, onepassword_tidy};
use crate::cause::{
    Cause, DiagnoseContext, EnvName, FieldRule, InputKind, OutputProblem, ProductName,
    Scope as InScope, System, TargetName, Unverified, Upstream, UsageProblem,
};
use crate::domain::delivery::{
    BindingRef, Evidence, Observed, Receipt, SCHEMA, SUPPLIED, Scope, Source, Verification,
    decode_evidence, encode_evidence, new_revision, select,
};
use crate::domain::ledger::{Ledger, hmac_hex, random_key};
use crate::domain::plan::StoreEntry;
use crate::domain::{Boundary, Fleet, Kind, Lifecycle, SecretValue, key_label, rules};
use crate::error::Error;
use crate::runner::CommandRunner;

const RECEIPT_FIELD: &str = "receipt";
const KEY_FIELD: &str = "evidence key";
/// The non-secret field a sync records for `opv changed` (C2): one `v1|<item_id>|<version>`
/// line per source item, ids and integers only. Written only after a confirmed sync.
const SOURCE_VERSIONS_FIELD: &str = "source versions";
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
    // A config key whose target stores it (`fly.config = "secrets"`) is bound exactly
    // like a secret: the config channel names the same store as the secret channel. A
    // pinned target (Kubernetes, Azure) names one store for both too, but binds its
    // store-routed config through the runtime, not as a secret binding.
    let channels = t.channels();
    let config_in_secret_store = channels.config.label().is_some()
        && channels.config.label() == channels.secret.label()
        && t.runtime_subject().is_none();
    if !fleet.delivers(env_name, target, product) {
        return Ok(Vec::new());
    }
    let Some(prod) = fleet.products.get(product) else {
        return Ok(Vec::new());
    };
    let env = fleet.environment(env_name)?;
    let served = env.targets.get(target).and_then(|t| t.roles.as_deref());
    let mut out: Vec<BindingRef> = prod
        .keys
        .iter()
        .filter(|(_, s)| {
            (s.kind == Kind::Secret || (s.kind == Kind::Config && config_in_secret_store))
                && !s.personal
        })
        .filter(|(_, s)| rules::applies(s, env_name, env, product))
        // A `retired` key is delivered nowhere (design Part V, row `retire`).
        .filter(|(_, s)| s.lifecycle != Lifecycle::Retired)
        // Target roles (M3, delivery-transports §4.4): a key whose roles miss the target's
        // is not desired there, so it is not part of the target's binding set.
        .filter(|(_, s)| match (&s.roles, served) {
            (Some(roles), Some(served)) => roles.iter().any(|r| served.contains(r)),
            _ => true,
        })
        .map(|(k, s)| {
            // #206 §6.3: a supplied value has no 1Password field; its source names it.
            if super::deliver_only::is_infrastructure(s) {
                return Ok(BindingRef {
                    name: t.env_name(product, k),
                    source: Source {
                        item_id: SUPPLIED.to_string(),
                        field: key_label(product, k),
                    },
                });
            }
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

/// The target names of `product`'s `retiring` keys on target `target` of `env_name`.
fn retiring_names(fleet: &Fleet, env_name: &str, target: &str, product: &str) -> BTreeSet<String> {
    fleet
        .products
        .get(product)
        .map(|p| {
            p.keys
                .iter()
                .filter(|(_, s)| s.lifecycle == Lifecycle::Retiring)
                .map(|(k, _)| fleet.target_name(env_name, target, product, k))
                .collect()
        })
        .unwrap_or_default()
}

/// [`bindings`] as the target `listed` holds them: a `retiring` key a retirement already
/// pruned from this target (#179) is no longer delivered here, so it leaves the binding set
/// that is recorded and verified, and the rest still mint (and keep) a revision.
fn held_bindings(
    fleet: &Fleet,
    env_name: &str,
    target: &str,
    product: &str,
    listed: &[StoreEntry],
) -> Result<Vec<BindingRef>, Error> {
    let retiring = retiring_names(fleet, env_name, target, product);
    Ok(bindings(fleet, env_name, target, product)?
        .into_iter()
        .filter(|b| !retiring.contains(&b.name) || listed.iter().any(|e| e.name == b.name))
        .collect())
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

/// Whether target `target` of `env_name` delivers the product in scope at all: `only`
/// when given, otherwise any product. True even when none of the delivered product's keys
/// are secrets, so a target that delivers no secret is told apart from one that delivers
/// no product (A13).
fn delivers_product(fleet: &Fleet, env_name: &str, target: &str, only: Option<&str>) -> bool {
    match only {
        Some(p) => fleet.delivers(env_name, target, p),
        None => fleet
            .products
            .keys()
            .any(|p| fleet.delivers(env_name, target, p)),
    }
}

/// The 1Password account this session reaches (`op whoami`'s account UUID; the same for a
/// person and a service account of that account). A receipt is bound to it, so an account
/// that cannot be told is an error: never a receipt minted or judged under a guess.
fn account_id(r: &dyn CommandRunner) -> Result<String, Error> {
    let call = crate::runner::Call::new(onepassword::OP, &["whoami", "--format", "json"]);
    // An answer that names no account is the runner's own observation of that call (A1).
    let unusable = |problem: OutputProblem| -> Error {
        match crate::runner::take_unusable_reply(&call) {
            Some(seen) => Cause::UnexpectedOutput {
                system: System::OnePassword,
                at: None,
                problem,
                during: crate::cause::During::Read,
                seen,
            }
            .into(),
            None => Cause::Bug {
                site: "delivery: an op whoami reply the runner did not observe",
            }
            .into(),
        }
    };
    let out = match r.read(&call, &[]) {
        Ok(crate::runner::Outcome::Done(out)) => out,
        Ok(crate::runner::Outcome::Refused(_)) | Err(_) => {
            return Err(op_failure(&DiagnoseContext::default()).unwrap_or_else(|| {
                Cause::Bug {
                    site: "delivery: a failed op whoami left no observation",
                }
                .into()
            }));
        }
        Ok(crate::runner::Outcome::Unknown { .. }) => {
            return Err(crate::host::OP_CLI.unanswered(r, "op whoami"));
        }
    };
    let Ok(v) = serde_json::from_slice::<Value>(&out.stdout) else {
        return Err(unusable(OutputProblem::Unparseable));
    };
    v["account_uuid"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| {
            unusable(OutputProblem::Empty {
                what: "account_uuid",
            })
        })
}

/// The cause of the `op` call that just failed, from 1Password's own diagnosis (design §5),
/// with 1Password's reply as evidence; `None` when the runner observed no failed call.
fn op_failure(ctx: &DiagnoseContext) -> Option<Error> {
    let failed = crate::runner::take_failure()?;
    let exit = failed.seen.exit();
    let cause = onepassword_diagnose::diagnose(failed.seen.clone(), failed.stderr(), ctx);
    let (said, truncated) = crate::scrub::Excerpt::parts(failed.excerpt);
    if said.is_empty() {
        return Some(cause.into());
    }
    Some(Error::with_evidence(
        cause,
        Upstream {
            source: System::OnePassword,
            tool: System::OnePassword.label().to_string(),
            version: None,
            exit,
            said,
            removed_advice: false,
            truncated,
            untrusted: true,
        },
    ))
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
pub(crate) struct StateItem {
    /// The delivery item's vault and item, as an item read addresses them.
    at: Boundary,
    receipt: Option<Receipt>,
    key: Option<Zeroizing<String>>,
    evidence: Vec<Evidence>,
    /// The `source versions` text the item held when read (C2): kept when this run does not
    /// mint a receipt and re-emitted unchanged.
    source_versions: Option<String>,
    raw: Zeroizing<Vec<u8>>,
}

impl StateItem {
    /// Whether the delivery item carried a receipt. A value-free fact, for the inventory.
    pub(crate) fn has_receipt(&self) -> bool {
        self.receipt.is_some()
    }
}

/// Where the delivery item of `product` on target `target` is: the target's state vault and
/// the item ID recorded in its `delivery_items` (FR-13: never a title lookup). `None` when
/// none is recorded.
fn item_at(fleet: &Fleet, env_name: &str, target: &str, product: &str) -> Option<Boundary> {
    let t = fleet.environments.get(env_name)?.targets.get(target)?;
    Some(Boundary {
        vault_id: t.state_vault_id.clone()?,
        item_id: t.delivery_items.get(product)?.clone(),
    })
}

/// Read the delivery item of `product` on target `target`, fresh and by its recorded ID;
/// `None` when no item is recorded. Values stay in memory.
pub(crate) fn read_state(
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
    // An item `op` returned that is not JSON is 1Password's output problem: the item parser
    // names it (01.10), never a bare "not valid JSON" with no item.
    let doc: Value =
        serde_json::from_slice(&raw).map_err(|_| match onepassword_tidy::parse(&raw) {
            Err(e) => e,
            Ok(_) => Error::from(Cause::Bug {
                site: "delivery item parses as an item but not as JSON",
            }),
        })?;
    let mut receipt = None;
    let mut key = None;
    let mut evidence = Vec::new();
    let mut source_versions = None;
    for f in doc["fields"].as_array().into_iter().flatten() {
        let (Some(label), Some(value)) = (f["label"].as_str(), f["value"].as_str()) else {
            continue;
        };
        match label {
            RECEIPT_FIELD => receipt = serde_json::from_str::<Receipt>(value).ok(),
            KEY_FIELD if !value.is_empty() => key = Some(Zeroizing::new(value.to_string())),
            SOURCE_VERSIONS_FIELD => source_versions = Some(value.to_string()),
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
        source_versions,
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
            Err(e) => {
                let why = e.to_string();
                let why = why.lines().next().unwrap_or_default();
                r.note(&format!(
                    "the delivery evidence of {product} on {} (state vault {}) could not be \
                     read: {why}; its names show as unknown",
                    super::placement(env_name, target),
                    t.state_vault_id.as_deref().unwrap_or("not bound")
                ))
            }
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

/// What [`record`] did with one name this run supplied (#206, `docs/design/deliver-only.md`
/// §5.4, S1, S9): any outcome but [`SuppliedOutcome::Recorded`] fails the run, since the
/// target may hold the value but opv cannot vouch for it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppliedOutcome {
    /// Its `s1` evidence line is in the placement's delivery item.
    Recorded,
    NotRecorded(NotRecordedWhy),
}

/// Why a supplied name got no `s1` evidence line (#206 §5.4).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotRecordedWhy {
    /// The target lists no version for it.
    Unlisted,
    /// The target lists a version the evidence line cannot hold.
    Unencodable,
    /// The placement has no delivery item.
    NoItem,
    /// The delivery item could not be read or written.
    Failed,
    /// Another run recorded a higher serial for it meanwhile (S9): that newer line is kept.
    NewerSerial { recorded: u64 },
}

/// What [`record`] did, for the sync report.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Recorded {
    pub minted: Vec<Receipt>,
    pub not_minted: Vec<NotMinted>,
    /// Per target name this run supplied (#206): whether its `s1` line was recorded.
    #[serde(skip)]
    pub supplied: BTreeMap<String, SuppliedOutcome>,
}

/// What a supplying sync hands [`record`] (#206): the admitted supply and the run's
/// `--rotate` keys, which also override a newer serial recorded meanwhile (S9).
#[derive(Debug, Clone, Copy)]
pub struct Supplying<'a> {
    pub supply: &'a super::deliver_only::Supply,
    pub rotate: &'a BTreeSet<(String, String)>,
}

/// The evidence of one placement as computed from one reading of its delivery item.
struct Computed {
    key: Zeroizing<String>,
    evidence: Vec<Evidence>,
    attested: Vec<String>,
    why: Vec<String>,
    supplied: BTreeMap<String, SuppliedOutcome>,
}

/// What [`record`] takes for one placement besides the reading of its item.
struct RecordInput<'a> {
    fleet: &'a Fleet,
    env_name: &'a str,
    set: &'a [BindingRef],
    written: &'a BTreeSet<String>,
    identical: &'a BTreeSet<String>,
    listed: &'a [StoreEntry],
    values: &'a BTreeMap<String, SecretValue>,
    supplying: Option<Supplying<'a>>,
    at: &'a str,
}

impl RecordInput<'_> {
    fn version_of(&self, name: &str) -> Option<String> {
        self.listed
            .iter()
            .find(|e| e.name == name)
            .and_then(|e| e.version.clone())
    }

    /// The supplied value of `binding` this run (#206), when it is supplied at sync and
    /// this run supplies it.
    fn supplied(&self, b: &BindingRef) -> Option<&super::deliver_only::Supplied> {
        if b.source.item_id != SUPPLIED {
            return None;
        }
        let (p, k) = b.source.field.split_once('/')?;
        self.supplying?.supply.get(p, k)
    }

    /// Whether this run's `--rotate` names supplied `s`.
    fn rotated(&self, s: &super::deliver_only::Supplied) -> bool {
        self.supplying
            .is_some_and(|x| x.rotate.contains(&(s.product.clone(), s.key.clone())))
    }

    /// The value delivered for a supplied `s` (#206 §4.2): the supplied value after the
    /// key's rules (`transform`, `ensure_prefix`), exactly as the plan staged and the
    /// ledger compares it.
    fn delivered(&self, s: &super::deliver_only::Supplied) -> SecretValue {
        let checked = self.fleet.environment(self.env_name).ok().and_then(|env| {
            let spec = self.fleet.products.get(&s.product)?.keys.get(&s.key)?;
            rules::check(&s.product, &s.key, spec, self.env_name, env, &s.value)
                .ok()
                .flatten()
        });
        checked.unwrap_or_else(|| SecretValue::new(s.value.expose().to_string()))
    }

    /// Whether `b` is supplied at sync but not by this run, and `state` holds its `s1` line
    /// at the version the store lists now (#206 §6.2): its line is carried verbatim and it
    /// counts as confirmed.
    fn carried(&self, b: &BindingRef, state: &StateItem) -> bool {
        b.source.item_id == SUPPLIED
            && self.supplied(b).is_none()
            && !self.written.contains(&b.name)
            && state.evidence.iter().any(|e| {
                e.name == b.name
                    && e.supplied.is_some()
                    && Some(e.store_version.as_str()) == self.version_of(&b.name).as_deref()
            })
    }

    /// Why the placement gets no revision before its item is read: names this run neither
    /// wrote, proved identical nor carried (`carried`), supplied names this run did not
    /// supply, and names the target lists no version for.
    fn reasons(&self, carried: &BTreeSet<&str>) -> Vec<String> {
        let mut unconfirmed = Vec::new();
        let mut not_supplied = Vec::new();
        for b in self.set.iter().filter(|b| {
            !self.written.contains(&b.name)
                && !self.identical.contains(&b.name)
                && !carried.contains(b.name.as_str())
        }) {
            if b.source.item_id == SUPPLIED && self.supplied(b).is_none() {
                not_supplied.push(b.name.as_str());
            } else {
                unconfirmed.push(b.name.as_str());
            }
        }
        let unlisted: Vec<&str> = self
            .set
            .iter()
            .filter(|b| self.version_of(&b.name).is_none())
            .map(|b| b.name.as_str())
            .collect();
        let mut why = Vec::new();
        if !unconfirmed.is_empty() {
            why.push(format!(
                "not confirmed by this sync: {}",
                unconfirmed.join(", ")
            ));
        }
        if !not_supplied.is_empty() {
            why.push(format!(
                "supplied at sync, not supplied by this run: {}",
                not_supplied.join(", ")
            ));
        }
        if !unlisted.is_empty() {
            why.push(format!(
                "the target lists no version for: {}",
                unlisted.join(", ")
            ));
        }
        why
    }

    /// The evidence of the placement from one reading `state` of its delivery item: each
    /// confirmed name's fresh line, every other line of the binding set kept as read.
    fn compute(&self, state: &StateItem) -> Computed {
        let key = state
            .key
            .clone()
            .unwrap_or_else(|| Zeroizing::new(random_key()));
        let mut supplied: BTreeMap<String, SuppliedOutcome> = BTreeMap::new();
        let carried: BTreeSet<&str> = self
            .set
            .iter()
            .filter(|b| self.carried(b, state))
            .map(|b| b.name.as_str())
            .collect();
        let confirmed = |b: &BindingRef| {
            self.written.contains(&b.name)
                || self.identical.contains(&b.name)
                || carried.contains(b.name.as_str())
        };
        let mut why = self.reasons(&carried);
        // Keep the lines of names still in the binding set; replace each confirmed one.
        let mut evidence: BTreeMap<String, Evidence> = state
            .evidence
            .iter()
            .filter(|e| self.set.iter().any(|b| b.name == e.name))
            .map(|e| (e.name.clone(), e.clone()))
            .collect();
        let mut unread = false;
        let mut unrecordable: Vec<&str> = Vec::new();
        for b in self
            .set
            .iter()
            .filter(|b| confirmed(b) && !carried.contains(b.name.as_str()))
        {
            let this_run = self.supplied(b);
            let delivered = this_run.map(|s| self.delivered(s));
            let value = match (&delivered, this_run) {
                (Some(v), _) => Some(v),
                (None, None) if b.source.item_id == SUPPLIED => None,
                (None, _) => self.values.get(&b.source.field),
            };
            let Some(version) = self.version_of(&b.name) else {
                if this_run.is_some() {
                    supplied.insert(
                        b.name.clone(),
                        SuppliedOutcome::NotRecorded(NotRecordedWhy::Unlisted),
                    );
                }
                unread |= value.is_none();
                continue;
            };
            let Some(value) = value else {
                unread = true;
                continue;
            };
            let fingerprint = hmac_hex(key.as_bytes(), value.expose().as_bytes());
            let old = evidence.get(&b.name);
            let line = match this_run {
                Some(s) => {
                    // S9: another run recorded a newer serial since this run planned: its
                    // line is kept and this name is not recorded. `--rotate` overrides it.
                    if let Some(recorded) = old
                        .filter(|_| !self.rotated(s))
                        .and_then(|e| e.supplied.as_ref())
                        .map(|m| m.serial)
                        .filter(|r| *r > s.serial)
                    {
                        supplied.insert(
                            b.name.clone(),
                            SuppliedOutcome::NotRecorded(NotRecordedWhy::NewerSerial { recorded }),
                        );
                        why.push(format!("a newer serial is recorded for: {}", b.name));
                        continue;
                    }
                    // §5.2: the same value at the same version and serial keeps its line.
                    let same = old.filter(|e| {
                        !self.written.contains(&b.name)
                            && e.store_version == version
                            && e.fingerprint == fingerprint
                            && e.source == b.source
                            && e.supplied.as_ref().is_some_and(|m| m.serial == s.serial)
                    });
                    match same {
                        Some(e) => e.clone(),
                        None => Evidence {
                            name: b.name.clone(),
                            store_version: version,
                            fingerprint,
                            source: b.source.clone(),
                            attested_at: None,
                            supplied: Some(crate::domain::delivery::SuppliedMark {
                                serial: s.serial,
                                at: self.at.to_string(),
                            }),
                        },
                    }
                }
                None => {
                    // #201: a name this sync did not write keeps a person's attestation
                    // while its line still says the same version and value; a write records
                    // ordinary evidence.
                    let attested_at = old
                        .filter(|e| {
                            !self.written.contains(&b.name)
                                && e.store_version == version
                                && e.fingerprint == fingerprint
                                && e.source == b.source
                        })
                        .and_then(|e| e.attested_at.clone());
                    Evidence {
                        name: b.name.clone(),
                        store_version: version,
                        fingerprint,
                        source: b.source.clone(),
                        attested_at,
                        supplied: None,
                    }
                }
            };
            // A store version the evidence line cannot hold (empty, or with `|`) is never
            // recorded: the name stays unconfirmed, so no revision vouches for it.
            if encode_evidence(&line).is_none() {
                unrecordable.push(b.name.as_str());
                if this_run.is_some() {
                    supplied.insert(
                        b.name.clone(),
                        SuppliedOutcome::NotRecorded(NotRecordedWhy::Unencodable),
                    );
                }
                continue;
            }
            if this_run.is_some() {
                supplied.insert(b.name.clone(), SuppliedOutcome::Recorded);
            }
            evidence.insert(b.name.clone(), line);
        }
        if unread {
            why.push("a source value could not be read from 1Password".into());
        }
        if !unrecordable.is_empty() {
            why.push(format!(
                "the target lists a version opv cannot record for: {}",
                unrecordable.join(", ")
            ));
        }
        // #201: the names whose evidence is still a person's attestation (sorted).
        let attested: Vec<String> = evidence
            .values()
            .filter(|e| e.attested())
            .map(|e| e.name.clone())
            .collect();
        Computed {
            key,
            evidence: evidence.into_values().collect(),
            attested,
            why,
            supplied,
        }
    }
}

/// After a confirmed sync of target `target` of `env_name`, for each product in scope
/// (FR-58, D11):
/// - each name of its binding set this run wrote (`written`) or proved identical
///   (`identical`), with its store version in `listed`, gets a fresh evidence line in the
///   placement's delivery item: these lines are the ledger `plan` judges by. A name this
///   run supplied (#206, `supplying`) gets an `s1` line from its supplied value; a supplied
///   name this run did not supply keeps its `s1` line verbatim while the store still lists
///   that version (carried), which counts as confirmed;
/// - once every name of the binding set was confirmed so, a revision is minted (an
///   unchanged binding set and evidence keep their revision) and the placement's
///   `source versions` field records each source item's version (C2; supplied names have
///   no source item).
///
/// A placement whose binding set holds a supplied name reads its delivery item again just
/// before writing (#206 §5.3): a change since is recomputed from the fresh reading, and a
/// second change fails with `item_changed`.
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
    source_versions: &BTreeMap<String, u64>,
    plan_id: &str,
    supplying: Option<Supplying<'_>>,
    r: &dyn CommandRunner,
) -> Result<Recorded, Error> {
    let env = fleet.environment(env_name)?;
    let account = account_id(r)?;
    let values = values_by_field(fleet, env_name, r)?;
    let now = crate::domain::provenance::utc_now();
    let mut out = Recorded::default();
    for product in products_in_scope(fleet, env_name, target, only)? {
        // A `retiring` key a retirement already pruned from this target (#179) leaves the
        // binding set, the same set `delivery verify` checks (`held_bindings`).
        let set = held_bindings(fleet, env_name, target, &product, listed)?;
        let input = RecordInput {
            fleet,
            env_name,
            set: &set,
            written,
            identical,
            listed,
            values: &values,
            supplying,
            at: &now,
        };
        let supplied_here: Vec<&BindingRef> =
            set.iter().filter(|b| input.supplied(b).is_some()).collect();
        let Some(mut state) = read_state(fleet, env_name, target, &product, r)? else {
            let mut why = input.reasons(&BTreeSet::new());
            why.push(format!(
                "no delivery item is recorded for {product} on {}; opv apply creates it",
                super::placement(env_name, target)
            ));
            for b in &supplied_here {
                out.supplied.insert(
                    b.name.clone(),
                    SuppliedOutcome::NotRecorded(NotRecordedWhy::NoItem),
                );
            }
            out.not_minted.push(NotMinted {
                product,
                reason: why.join("; "),
            });
            continue;
        };
        let mut computed = input.compute(&state);
        // #206 §5.3: re-read, recompute, write, or `item_changed`.
        if set.iter().any(|b| b.source.item_id == SUPPLIED) {
            let fresh = read_state(fleet, env_name, target, &product, r)?
                .ok_or_else(|| changed_before_write(&state.at))?;
            if fresh.raw != state.raw {
                computed = input.compute(&fresh);
                let again = read_state(fleet, env_name, target, &product, r)?
                    .ok_or_else(|| changed_before_write(&fresh.at))?;
                if again.raw != fresh.raw {
                    return Err(changed_before_write(&fresh.at));
                }
                state = fresh;
            }
        }
        let Computed {
            key,
            evidence,
            attested,
            why,
            supplied,
        } = computed;
        out.supplied.extend(supplied);
        // #206 §6.3: the names of the set supplied at sync (sorted).
        let supplied_names: Vec<String> = set
            .iter()
            .filter(|b| b.source.item_id == SUPPLIED)
            .map(|b| b.name.clone())
            .collect();
        let this_scope = scope(fleet, env_name, target, &product, &account)?;
        let receipt = if why.is_empty() {
            // Unchanged binding set and evidence: the same delivery, the same revision.
            let unchanged = state.receipt.as_ref().filter(|rec| {
                rec.scope == this_scope
                    && rec.bindings == set
                    && rec.attested == attested
                    && rec.supplied == supplied_names
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
                        delivered_at: now.clone(),
                        plan_id: Some(plan_id.to_string()),
                        opv_version: env!("CARGO_PKG_VERSION").into(),
                        attested,
                        supplied: supplied_names,
                    }
                }
            })
        } else {
            None
        };
        let kept = receipt.as_ref().or(state.receipt.as_ref());
        // C2: only a minted receipt records versions; an unconfirmed placement keeps the
        // field it already had.
        let minted_versions = why.is_empty().then(|| versions_text(&set, source_versions));
        let write_versions = minted_versions
            .as_deref()
            .or(state.source_versions.as_deref());
        let changed = state.key.is_none()
            || lines(&state.evidence) != lines(&evidence)
            || kept.map(|k| &k.revision) != state.receipt.as_ref().map(|k| &k.revision)
            || write_versions != state.source_versions.as_deref();
        if changed {
            write_state(r, env, &state, kept, &key, &evidence, write_versions)?;
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

/// The delivery item at `at` changed between opv's readings of it (#206 §5.3).
fn changed_before_write(at: &Boundary) -> Error {
    Cause::ChangedBeforeWrite {
        object: crate::cause::StoreObject::Item {
            vault: crate::cause::VaultId::new(at.vault_id.as_str()),
            item: crate::cause::ItemId::new(at.item_id.as_str()),
        },
    }
    .into()
}

/// One name a person attests on a placement (#201): its binding, the target's current
/// store version, and the keyed fingerprint of its 1Password value under the placement's
/// evidence key. Debug prints the name only.
#[derive(Clone)]
pub(crate) struct Attest {
    pub(crate) binding: BindingRef,
    pub(crate) store_version: String,
    pub(crate) fingerprint: String,
    /// [`key_check`] of the evidence key the fingerprint was made under: a key replaced
    /// since makes the attestation stale.
    pub(crate) key_check: String,
}

/// A keyed check of an evidence key (#201): equal for the same key, and reveals nothing of it.
pub(crate) fn key_check(key: &str) -> String {
    hmac_hex(key.as_bytes(), b"opv-attest-key-check")
}

/// What [`record_attestation`] found in the freshly read delivery item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AttestWrite {
    /// These names were recorded now (empty: each was already attested as planned, so a
    /// retry of the same plan records nothing again).
    Recorded(Vec<String>),
    /// The item changed since the plan was made (its evidence key, or a line for a name):
    /// the plan is stale and nothing was written.
    Changed,
}

impl std::fmt::Debug for Attest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Attest")
            .field("name", &self.binding.name)
            .finish()
    }
}

/// The evidence key of `product`'s delivery item on target `target` (#201): what an
/// attestation fingerprints with. `None` when the placement has no delivery item or no
/// evidence key yet (no sync recorded it).
pub(crate) fn evidence_key(
    fleet: &Fleet,
    env_name: &str,
    target: &str,
    product: &str,
    r: &dyn CommandRunner,
) -> Result<Option<Zeroizing<String>>, Error> {
    Ok(read_state(fleet, env_name, target, product, r)?.and_then(|s| s.key))
}

/// The keyed fingerprint of `value` under `key`: what an evidence line holds.
pub(crate) fn fingerprint(key: &str, value: &SecretValue) -> String {
    hmac_hex(key.as_bytes(), value.expose().as_bytes())
}

/// The 1Password values of the environment's boundary items, by `product/KEY` field.
pub(crate) fn values_of(
    fleet: &Fleet,
    env_name: &str,
    r: &dyn CommandRunner,
) -> Result<BTreeMap<String, SecretValue>, Error> {
    values_by_field(fleet, env_name, r)
}

/// Record a person's attestation of `names` on `product`'s placement on target `target`
/// (#201): each name's evidence line, tagged `a1` with `at`, at the store version and
/// fingerprint the plan computed. The item is read fresh first and checked again: the same
/// evidence key, and for each name either no line (it is recorded) or the very line this
/// plan records (already attested: skipped, so a retry succeeds). Anything else is
/// [`AttestWrite::Changed`] and nothing is written. The receipt is kept as it is: the next
/// sync proves the names through these lines and mints the revision. Nothing is written to
/// the target; only the placement's own delivery item is read and written.
pub(crate) fn record_attestation(
    fleet: &Fleet,
    env_name: &str,
    target: &str,
    product: &str,
    names: &[Attest],
    at: &str,
    r: &dyn CommandRunner,
) -> Result<AttestWrite, Error> {
    let env = fleet.environment(env_name)?;
    let Some(state) = read_state(fleet, env_name, target, product, r)? else {
        return Ok(AttestWrite::Changed);
    };
    let Some(key) = state.key.clone() else {
        return Ok(AttestWrite::Changed);
    };
    let check = key_check(&key);
    let mut evidence: BTreeMap<String, Evidence> = state
        .evidence
        .iter()
        .map(|e| (e.name.clone(), e.clone()))
        .collect();
    let mut recorded = Vec::new();
    for n in names {
        if n.key_check != check {
            return Ok(AttestWrite::Changed);
        }
        match evidence.get(&n.binding.name) {
            None => {}
            Some(e)
                if e.attested()
                    && e.store_version == n.store_version
                    && e.fingerprint == n.fingerprint
                    && e.source == n.binding.source =>
            {
                continue;
            }
            Some(_) => return Ok(AttestWrite::Changed),
        }
        let line = Evidence {
            name: n.binding.name.clone(),
            store_version: n.store_version.clone(),
            fingerprint: n.fingerprint.clone(),
            source: n.binding.source.clone(),
            attested_at: Some(at.to_string()),
            supplied: None,
        };
        if encode_evidence(&line).is_none() {
            return Err(Cause::Bug {
                site: "attest: a store version checked before the write does not encode",
            }
            .into());
        }
        recorded.push(line.name.clone());
        evidence.insert(line.name.clone(), line);
    }
    if recorded.is_empty() {
        return Ok(AttestWrite::Recorded(recorded));
    }
    let evidence: Vec<Evidence> = evidence.into_values().collect();
    write_state(
        r,
        env,
        &state,
        state.receipt.as_ref(),
        &key,
        &evidence,
        state.source_versions.as_deref(),
    )?;
    Ok(AttestWrite::Recorded(recorded))
}

/// The encoded evidence lines, sorted: what two readings of an item compare by.
fn lines(evidence: &[Evidence]) -> Vec<String> {
    let mut out: Vec<String> = evidence.iter().filter_map(encode_evidence).collect();
    out.sort();
    out
}

/// The `source versions` text of `set` (C2): one `v1|<item_id>|<version>` line per distinct
/// source item id, sorted by item id, versions from `source_versions`.
fn versions_text(set: &[BindingRef], source_versions: &BTreeMap<String, u64>) -> String {
    let ids: BTreeSet<&str> = set.iter().map(|b| b.source.item_id.as_str()).collect();
    let mut out = String::new();
    for id in ids {
        if let Some(version) = source_versions.get(id) {
            out.push_str(&format!("v1|{id}|{version}\n"));
        }
    }
    out
}

/// Rewrite the placement's delivery item `state`: its notes kept, then the receipt (when
/// one was ever minted), the recorded source versions (C2), the key and one concealed
/// evidence field per name (a person's attestation is its own `a1` line, #201).
fn write_state(
    r: &dyn CommandRunner,
    env: &crate::domain::Environment,
    state: &StateItem,
    receipt: Option<&Receipt>,
    key: &str,
    evidence: &[Evidence],
    source_versions: Option<&str>,
) -> Result<(), Error> {
    let mut doc: Value = serde_json::from_slice(&state.raw).map_err(|_| {
        Error::from(Cause::Bug {
            site: "delivery item parsed when read, not when rewritten",
        })
    })?;
    let mut fields: Vec<Value> = doc["fields"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|f| f["purpose"] == "NOTES")
        .cloned()
        .collect();
    if let Some(receipt) = receipt {
        let receipt_json = serde_json::to_string(receipt).map_err(|_| {
            Error::from(Cause::Bug {
                site: "delivery receipt serializes",
            })
        })?;
        fields.push(
            json!({"id": "receipt", "label": RECEIPT_FIELD, "type": "STRING", "value": receipt_json}),
        );
    }
    if let Some(text) = source_versions {
        fields.push(
            json!({"id": "source-versions", "label": SOURCE_VERSIONS_FIELD,
                            "type": "STRING", "value": text}),
        );
    }
    fields
        .push(json!({"id": "evidence-key", "label": KEY_FIELD, "type": "CONCEALED", "value": key}));
    for e in evidence {
        // `record` keeps only evidence that encodes.
        let line = encode_evidence(e).ok_or_else(|| {
            Error::from(Cause::Bug {
                site: "kept delivery evidence encodes",
            })
        })?;
        fields.push(json!({"id": e.name, "label": e.name, "type": "CONCEALED", "value": line}));
    }
    doc["fields"] = Value::Array(fields);
    doc.as_object_mut().map(|o| o.remove("sections"));
    let template = Zeroizing::new(serde_json::to_vec(&doc).map_err(|_| {
        Error::from(Cause::Bug {
            site: "delivery item serializes",
        })
    })?);
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
    /// Why the placement is not verified, as a typed fact (`None` exactly when `state` is
    /// `verified`): the failure `opv delivery verify` reports is built from it.
    #[serde(skip)]
    pub unverified: Option<Unverified>,
}

/// Why a placement is not verified (design §4.10), from what the check read: the delivery
/// item, this session's account and the comparison. Never inferred from text.
fn unverified_state(
    state: Option<&StateItem>,
    account: &str,
    v: &Verification,
) -> Option<Unverified> {
    let any = |states: &[&str]| v.names.iter().any(|n| states.contains(&n.state));
    match v.state {
        "verified" => None,
        "changed" if any(&["missing_on_target", "drifted_on_target"]) => {
            Some(Unverified::ChangedOnTarget)
        }
        "changed" => Some(Unverified::ChangedInOnePassword),
        "not_delivered" => match state.and_then(|s| s.receipt.as_ref()) {
            Some(rec) if rec.scope.account_id != account => Some(Unverified::OtherAccount {
                account: crate::cause::AccountId::new(&rec.scope.account_id),
            }),
            _ => Some(Unverified::NotRecorded),
        },
        _ => Some(Unverified::Unverifiable),
    }
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
    // A misspelt product would otherwise match nothing and pass (exit 0) having checked
    // nothing.
    super::check_product(fleet, only, Some(env_name))?;
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
        checks.extend(verify_target(
            fleet,
            env_name,
            target,
            only,
            &from_file,
            receipt_file,
            r,
        )?);
    }
    if checks.is_empty() {
        // 01.18: with `--target`, the one target named; otherwise the environment's. A13:
        // that target delivering a product with no secret is `NoSecretDelivered`; one
        // delivering no product (or not the requested one) stays `NoTargetDelivers`.
        let what = match (names.as_slice(), targets.is_empty()) {
            ([t], false) if delivers_product(fleet, env_name, t, only) => {
                InScope::NoSecretDelivered {
                    target: TargetName::new(t),
                }
            }
            ([t], false) => InScope::NoTargetDelivers {
                target: TargetName::new(t),
            },
            _ => InScope::NoTargets {
                products: match only {
                    Some(p) => vec![ProductName::new(p)],
                    None => fleet.products.keys().map(ProductName::new).collect(),
                },
            },
        };
        return Err(Cause::NothingInScope {
            env: EnvName::new(env_name),
            what,
        }
        .into());
    }
    report(out, env_name, &checks, json)?;
    // 01.06: an unverified placement is `delivery_unverified` with its own typed state (the
    // step follows the state), never `findings` with an unscoped `opv sync`. The first one
    // in report order; the report above lists every placement.
    match checks
        .iter()
        .find_map(|c| c.unverified.clone().map(|state| (c, state)))
    {
        None => Ok(()),
        Some((c, state)) => Err(Cause::DeliveryUnverified {
            env: EnvName::new(env_name),
            target: TargetName::new(&c.target),
            product: ProductName::new(&c.product),
            state,
        }
        .into()),
    }
}

/// The placements of target `target` (`only`: that product's), signed in with the target's
/// own deploy identity. `from_file` holds the receipts of `receipt_file`.
fn verify_target(
    fleet: &Fleet,
    env_name: &str,
    target: &str,
    only: Option<&str>,
    from_file: &[Receipt],
    receipt_file: Option<&Path>,
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
    let account = account_id(r)?;
    let mut checks = Vec::new();
    for product in products_in_scope(fleet, env_name, target, only)? {
        let expected = held_bindings(fleet, env_name, target, &product, &listed)?;
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
        let unverified = unverified_state(state.as_ref(), &account, &verification);
        let deployed = match &ports {
            crate::ports::Ports::Staged { runtime, .. } if runtime.live() => "n/a",
            _ if pending => "staged",
            _ => "deployed",
        };
        // A receipt the caller kept: selected by its full scope, independent of order; it
        // must be this very delivery to count.
        let mut receipt_revision = None;
        let mut unverified = unverified;
        // 01.09: the file is named and the fix is to keep one receipt in it.
        let kept = select(from_file, &this_scope).map_err(|_| {
            Error::from(Cause::InputInvalid {
                path: receipt_file.unwrap_or(Path::new("")).to_path_buf(),
                kind: InputKind::Receipt,
                at: None,
                field: format!(
                    "receipt of {product} on {}",
                    super::placement(env_name, target)
                ),
                rule: FieldRule::DuplicateKey,
            })
        })?;
        if let Some(kept) = kept
            && verification.revision.as_deref() != Some(kept.revision.as_str())
        {
            receipt_revision = Some(kept.revision.clone());
            unverified = Some(Unverified::Superseded {
                receipt: receipt_file.unwrap_or(Path::new("")).to_path_buf(),
            });
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
            unverified,
        });
    }
    Ok(checks)
}

/// The deliveries a receipt file holds (`{"schema", "deliveries": [...]}`).
fn read_receipt_file(path: &Path) -> Result<Vec<Receipt>, Error> {
    let invalid = |field: &str, at: Option<crate::cause::Location>, rule: FieldRule| {
        Error::from(Cause::InputInvalid {
            path: path.to_path_buf(),
            kind: InputKind::Receipt,
            at,
            field: field.to_string(),
            rule,
        })
    };
    let text = std::fs::read_to_string(path).map_err(|_| receipt_flag(path, RECEIPT_READABLE))?;
    let doc: Value = serde_json::from_str(&text).map_err(|e| {
        let at = crate::cause::Location {
            line: u32::try_from(e.line()).unwrap_or(u32::MAX),
            col: u32::try_from(e.column()).unwrap_or(u32::MAX),
        };
        invalid("its JSON", Some(at), FieldRule::Syntax)
    })?;
    if doc["schema"] != SCHEMA {
        return Err(invalid(
            "schema",
            None,
            FieldRule::Type { expected: SCHEMA },
        ));
    }
    serde_json::from_value(doc["deliveries"].clone())
        .map_err(|_| invalid("deliveries", None, FieldRule::Missing))
}

/// What `--receipt` takes, by what was wrong with the path given.
const RECEIPT_READABLE: &str = "a delivery receipt file opv can read";
const RECEIPT_NOT_A_DIRECTORY: &str = "a file path, not a directory";
const RECEIPT_IN_EXISTING_DIRECTORY: &str = "a file in an existing directory";
const RECEIPT_WRITABLE: &str = "a file in a directory opv can write to";

/// `--receipt <path>` given a path that cannot be used as `format` says.
fn receipt_flag(path: &Path, format: &'static str) -> Error {
    Cause::Usage {
        problem: UsageProblem::ValueFormat {
            flag: format!("--receipt {}", path.display()),
            format,
        },
    }
    .into()
}

/// Write the receipts minted by a sync to `path` (`{"schema", "deliveries": [...]}`):
/// names, ids and times only.
/// `--receipt <file>` can be written: its directory exists and takes a new file, and the
/// path is not a directory. Checked before a sync stages anything, so a bad path never
/// fails a run half way. Leaves nothing behind.
pub fn check_receipt_path(path: &Path) -> Result<(), Error> {
    if path.is_dir() {
        return Err(receipt_flag(path, RECEIPT_NOT_A_DIRECTORY));
    }
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    if !dir.is_dir() {
        return Err(receipt_flag(path, RECEIPT_IN_EXISTING_DIRECTORY));
    }
    let probe = dir.join(format!(".opv-receipt-check-{}", std::process::id()));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            Ok(())
        }
        Err(_) => Err(receipt_flag(path, RECEIPT_WRITABLE)),
    }
}

pub fn write_receipt_file(path: &Path, minted: &[Receipt]) -> Result<(), Error> {
    let doc = json!({"schema": SCHEMA, "deliveries": minted});
    let text = serde_json::to_string_pretty(&doc).map_err(|_| {
        Error::from(Cause::Bug {
            site: "delivery receipt file serializes",
        })
    })?;
    super::init::write_atomic(path, &format!("{text}\n"), true)
}

/// A placement or name state in words, for the text report (01.17); `--json` keeps the
/// slugs.
fn state_words(state: &str) -> &str {
    match state {
        "verified" => "verified",
        "not_delivered" => "not delivered",
        "changed" => "changed since it was delivered",
        "superseded" => "superseded by a later delivery",
        "unverifiable" => "cannot be verified",
        "missing_on_target" => "missing on the target",
        "drifted_on_target" => "changed on the target",
        "source_changed" => "changed in 1Password since",
        other => other,
    }
}

/// Whether the delivery is live, in words.
fn deployed_words(deployed: &str) -> &str {
    match deployed {
        "n/a" => "applied at once",
        "staged" => "staged, not yet deployed",
        other => other,
    }
}

/// The comparison's reason, in words (the domain's reasons name scope fields).
fn reason_words(reason: &str) -> String {
    match reason {
        "no delivery recorded" => "no delivery is recorded".to_string(),
        "the binding set changed" => "the set of delivered keys changed".to_string(),
        "recorded for another account_id" => "recorded under another 1Password account".to_string(),
        other => match other.strip_prefix("recorded for another ") {
            Some(field) => format!("recorded for another {}", field.replace('_', " ")),
            None => other.to_string(),
        },
    }
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
            state_words(v.state),
            deployed_words(c.deployed)
        )
        .map_err(write_err)?;
        if let Some(reason) = &v.reason {
            writeln!(out, "  {}", reason_words(reason)).map_err(write_err)?;
        }
        for n in v.names.iter().filter(|n| n.state != "verified") {
            writeln!(out, "  {:<32} {}", n.name, state_words(n.state)).map_err(write_err)?;
        }
        // #201: a name the revision counts on a person's attestation is said so, whatever
        // its state: the ledger proves it unchanged since, not that it was right.
        for n in v.names.iter().filter(|n| n.attested) {
            writeln!(
                out,
                "  {:<32} attested by a person, not proven (docs/attestation.md)",
                n.name
            )
            .map_err(write_err)?;
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
