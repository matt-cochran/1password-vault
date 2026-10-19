//! A person's attestation of held immutable keys (#201, `docs/attestation.md`).
//!
//! On a staged store (Fly) opv cannot compute a stored value's digest, so a name is proven
//! identical only by its placement's delivery ledger: an evidence line at the target's
//! current version with the 1Password value's keyed fingerprint. An immutable key that
//! reached the target before its placement had evidence is held by every sync and never
//! written, so it never gets that line and its product never mints a receipt.
//!
//! The way out is a person's statement: "the target holds 1Password's value". [`propose`]
//! shows what would be recorded (names and the target's version, never a value) under a
//! plan id that binds each name's current version and fingerprint; a person's
//! `opv apply <plan_id> --attest <env>:<target>:<product/KEY>` ([`apply`]) recomputes it,
//! refuses a stale id, confirms once and records each name's evidence line, in the same
//! ledger format sync writes, with an attestation beside it. Nothing is written to the
//! target. The next sync proves the names through those lines and mints the revision, whose
//! receipt lists them as `attested`.
//!
//! Only a person in their own terminal records one: agent mode, CI and a run without a
//! terminal are refused before anything is read (MCP may propose, as with every proposal).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::delivery::{self, Attest};
use super::signin::{self, Reach};
use super::write_err;
use crate::cause::{
    AttestRefusal, Cause, Cmd, EnvName, Guard, KeyName, NameKind, NoTerminal, PlanId, PlanScope,
    ProductKey, ProductName, TargetName, UsageProblem,
};
use crate::domain::delivery::BindingRef;
use crate::domain::ledger::hmac_hex;
use crate::domain::{Fleet, KeyState, TargetState, key_label};
use crate::error::Error;
use crate::ports::Ports;
use crate::runner::CommandRunner;

/// The prefix of an attestation plan id.
const PLAN_ID_PREFIX: &str = "ap-";
/// Hex digits of SHA-256 kept after the prefix.
const PLAN_ID_HEX: usize = 16;

/// One name a proposal would record. Names and the target's version only: never a value,
/// and never a version derived from the value (a Fly digest), which `version_tag` stands for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttestedName {
    pub product: String,
    pub key: String,
    /// The name on the target (`FLEET__API__JWT_SECRET`).
    pub name: String,
    /// The target's current version of the name, when the provider's versions are not
    /// derived from the value; `None` on a provider whose version is a digest (Fly).
    pub version: Option<String>,
    /// A keyed tag of the target's current version (HMAC under the placement's evidence
    /// key, 12 hex digits): it changes when the version does, and reveals nothing of it.
    pub version_tag: String,
}

/// What `opv apply --attest` would record on one target (#201).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttestProposal {
    /// Always `attest`.
    pub kind: &'static str,
    pub environment: String,
    pub target: String,
    pub names: Vec<AttestedName>,
    /// `ap-` and 16 hex digits: binds each name's current version and 1Password value.
    pub plan_id: String,
}

/// What `opv apply --attest` did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Attested {
    pub plan_id: String,
    /// False when the person declined, and nothing was recorded.
    pub confirmed: bool,
    /// The names recorded as attested, as `product/KEY`.
    pub attested: Vec<String>,
}

/// One eligible name with what its record needs: the binding, the version and fingerprint
/// (kept private: never printed).
struct Eligible {
    product: String,
    attest: Attest,
}

/// The `product/KEY` labels as given, split; a label with no `/` is `usage`.
fn split_keys(keys: &[String]) -> Result<Vec<(String, String)>, Error> {
    keys.iter()
        .map(|k| {
            k.split_once('/')
                .filter(|(p, k)| !p.is_empty() && !k.is_empty())
                .map(|(p, k)| (p.to_string(), k.to_string()))
                .ok_or_else(|| {
                    Cause::Usage {
                        problem: UsageProblem::ValueFormat {
                            flag: k.clone(),
                            format: "<product>/<KEY>",
                        },
                    }
                    .into()
                })
        })
        .collect()
}

fn refused(product: &str, key: &str, env: &str, target: &str, reason: AttestRefusal) -> Error {
    Cause::Guard {
        guard: Guard::AttestRefused {
            product: ProductName::new(product),
            key: KeyName::new(key),
            env: EnvName::new(env),
            target: TargetName::new(target),
            reason,
        },
    }
    .into()
}

/// The plan scope of an attestation of `keys` on `target` of `env`: what a stale id's step
/// recomputes.
fn scope(env: &str, target: &str, keys: &[(String, String)]) -> PlanScope {
    PlanScope::Attest {
        env: EnvName::new(env),
        target: TargetName::new(target),
        keys: keys
            .iter()
            .map(|(p, k)| ProductKey {
                product: ProductName::new(p),
                key: KeyName::new(k),
            })
            .collect(),
    }
}

/// Every check, and what each eligible name would record, read fresh: the target's listing,
/// the environment's items and each placement's delivery item. Refuses the first name that
/// cannot be attested. Writes nothing.
fn survey(
    fleet: &Fleet,
    env_name: &str,
    target: &str,
    keys: &[String],
    r: &dyn CommandRunner,
) -> Result<(AttestProposal, Vec<Eligible>), Error> {
    fleet.environment(env_name)?;
    let wanted = split_keys(keys)?;
    if wanted.is_empty() {
        return Err(Cause::Usage {
            problem: UsageProblem::NeedsFlag {
                flag: "--attest".into(),
                needs: "<env>:<target>:<product/KEY>".into(),
            },
        }
        .into());
    }
    let (_, t) = super::target(fleet, env_name, target)?;
    // Declared, and declared for this environment: a typo gets the declared names (05.39).
    for (p, k) in &wanted {
        let declared = fleet
            .products
            .get(p)
            .and_then(|prod| prod.keys.get(k))
            .is_some_and(|s| s.is_desired_in(env_name));
        if !declared {
            let names: Vec<String> = fleet
                .products
                .iter()
                .flat_map(|(p, prod)| {
                    prod.keys
                        .iter()
                        .filter(|(_, s)| s.is_desired_in(env_name))
                        .map(move |(k, _)| key_label(p, k))
                })
                .collect();
            return Err(super::not_declared(
                NameKind::Key,
                &key_label(p, k),
                names.iter().map(String::as_str),
            ));
        }
    }
    // The target is reached with its own deploy identity, read-only.
    let signed_in = signin::open_targeted(fleet, env_name, Some(target), r, Reach::Target)?;
    let r: &dyn CommandRunner = &signed_in;
    let (_, ports) = super::open_target(fleet, env_name, target, r)?;
    if matches!(ports, Ports::Pinned { .. }) {
        let (p, k) = &wanted[0];
        return Err(refused(
            p,
            k,
            env_name,
            target,
            AttestRefusal::ComparedDirectly,
        ));
    }
    let read = super::tidy::read(fleet, env_name, r)?;
    let ledgers = super::placement_ledgers(fleet, env_name, Some(target), Some(&ports), r);
    let none = BTreeSet::new();
    let (plan, listed) = super::plan_item_with(
        fleet,
        env_name,
        Some(target),
        read.fields,
        Some(&ports),
        &none,
        &none,
        &ledgers,
    )?;
    let values = delivery::values_of(fleet, env_name, r)?;
    let hides_versions = t.provider().versions_reveal_values();
    let mut keys_by_product: BTreeMap<String, Option<zeroize::Zeroizing<String>>> = BTreeMap::new();
    let mut names = Vec::new();
    let mut eligible = Vec::new();
    for (p, k) in &wanted {
        let no = |reason| refused(p, k, env_name, target, reason);
        let spec = &fleet.products[p].keys[k];
        let name = t.env_name(p, k);
        let set = delivery::bindings(fleet, env_name, target, p)?;
        let Some(binding) = set.iter().find(|b| b.name == name).cloned() else {
            return Err(no(AttestRefusal::NotDelivered));
        };
        if !spec.immutable {
            return Err(no(AttestRefusal::NotImmutable));
        }
        let Some(version) = listed
            .iter()
            .find(|e| e.name == name)
            .and_then(|e| e.version.clone())
            .filter(|v| !v.is_empty())
        else {
            return Err(no(AttestRefusal::NotOnTarget));
        };
        let row = plan
            .rows
            .iter()
            .find(|row| row.product == *p && row.key == *k);
        match row.map(|row| row.target) {
            Some(TargetState::Present) => return Err(no(AttestRefusal::Proven)),
            Some(TargetState::WouldChange) => return Err(no(AttestRefusal::Differs)),
            _ => {}
        }
        if plan.drift.contains(&name) {
            return Err(no(AttestRefusal::Drifted));
        }
        // A value that is not ready in 1Password (empty, failing its rules) is never
        // attested: the statement is "the target holds 1Password's value".
        let ready = row
            .is_some_and(|row| matches!(row.state, KeyState::Ready | KeyState::RulesPendingReview));
        if !ready
            || !plan
                .held_immutable
                .iter()
                .any(|(hp, hk)| hp == p && hk == k)
        {
            return Err(no(AttestRefusal::NotHeld));
        }
        if !keys_by_product.contains_key(p) {
            let key = delivery::evidence_key(fleet, env_name, target, p, r)?;
            keys_by_product.insert(p.clone(), key);
        }
        let Some(key) = keys_by_product[p].as_ref() else {
            return Err(no(AttestRefusal::NotRecorded));
        };
        let Some(value) = values
            .get(&binding.source.field)
            .filter(|v| !v.expose().is_empty())
        else {
            return Err(no(AttestRefusal::NotHeld));
        };
        let fingerprint = delivery::fingerprint(key, value);
        // The tag binds the version and the value under the placement's own key, so the
        // plan id changes with either and a published id reveals neither.
        let bind = hmac_hex(
            key.as_bytes(),
            format!("opv-attest|{version}|{fingerprint}").as_bytes(),
        );
        let version_tag = hmac_hex(
            key.as_bytes(),
            format!("opv-attest-version|{version}").as_bytes(),
        )[..12]
            .to_string();
        names.push((
            AttestedName {
                product: p.clone(),
                key: k.clone(),
                name: name.clone(),
                version: (!hides_versions).then(|| version.clone()),
                version_tag,
            },
            bind,
        ));
        eligible.push(Eligible {
            product: p.clone(),
            attest: Attest {
                binding: BindingRef {
                    name,
                    source: binding.source,
                },
                store_version: version,
                fingerprint,
            },
        });
    }
    let plan_id = plan_id(env_name, target, &names);
    Ok((
        AttestProposal {
            kind: "attest",
            environment: env_name.to_string(),
            target: target.to_string(),
            names: names.into_iter().map(|(n, _)| n).collect(),
            plan_id,
        },
        eligible,
    ))
}

/// `ap-` and 16 hex digits of SHA-256 over the environment, the target and each name with
/// its keyed binding of version and value, sorted by name.
fn plan_id(env: &str, target: &str, names: &[(AttestedName, String)]) -> String {
    let mut lines: Vec<String> = names
        .iter()
        .map(|(n, bind)| format!("{}/{}|{}|{bind}", n.product, n.key, n.name))
        .collect();
    lines.sort();
    let mut h = Sha256::new();
    h.update(format!("opv-attest/1\n{env}\n{target}\n").as_bytes());
    for l in lines {
        h.update(l.as_bytes());
        h.update(b"\n");
    }
    let digest = hex::encode(h.finalize());
    format!("{PLAN_ID_PREFIX}{}", &digest[..PLAN_ID_HEX])
}

/// What an attestation of `keys` on target `target` of `env_name` would record, and its plan
/// id. Reads only: the target's listing, the environment's items and the placements'
/// delivery items. Every name is checked; the first that cannot be attested is refused
/// (`policy_refused`, guard `attest_refused`).
pub fn propose(
    fleet: &Fleet,
    env_name: &str,
    target: &str,
    keys: &[String],
    r: &dyn CommandRunner,
) -> Result<AttestProposal, Error> {
    survey(fleet, env_name, target, keys, r).map(|(p, _)| p)
}

/// The proposal as text lines: what would be recorded, never a value.
pub fn describe(p: &AttestProposal) -> Vec<String> {
    let mut lines = vec![format!(
        "attest on {}: the target holds 1Password's value of each name below; opv records \
         its delivery evidence at the target's current version and writes nothing to the target",
        super::placement(&p.environment, &p.target)
    )];
    for n in &p.names {
        let version = match &n.version {
            Some(v) => format!("version {v}"),
            None => format!(
                "version tag {} (the target's version is a value digest)",
                n.version_tag
            ),
        };
        lines.push(format!(
            "  {} as {} at {version}",
            key_label(&n.product, &n.key),
            n.name
        ));
    }
    lines.push(
        "an attestation that is wrong is only caught when the app fails: see docs/attestation.md"
            .into(),
    );
    lines.push(format!("plan_id: {}", p.plan_id));
    lines
}

/// `opv apply <plan_id> --attest …` for `p`: the person's step after a proposal.
pub fn apply_step(p: &AttestProposal) -> Cmd {
    let mut args = vec![p.plan_id.clone()];
    for n in &p.names {
        args.push("--attest".into());
        args.push(format!(
            "{}:{}:{}",
            p.environment,
            p.target,
            key_label(&n.product, &n.key)
        ));
    }
    Cmd {
        command: vec!["apply".into()],
        args,
    }
}

/// `opv apply [<plan_id>] --attest <env>:<target>:<product/KEY>…`: a person's own terminal
/// only (agent mode, CI and no terminal are refused before anything is read). Recompute the
/// proposal, refuse a stale `plan_id` (`stale_plan`), show it, confirm once, then record
/// each name's evidence line and attestation in its placement's delivery item. Nothing is
/// written to the target.
#[allow(clippy::too_many_arguments)]
pub fn apply(
    fleet: &Fleet,
    env_name: &str,
    target: &str,
    keys: &[String],
    plan_id: Option<&str>,
    host_env: &dyn crate::host::HostEnv,
    confirm: &mut dyn FnMut(&AttestProposal) -> bool,
    out: &mut dyn Write,
    r: &dyn CommandRunner,
) -> Result<Attested, Error> {
    let wanted = split_keys(keys)?;
    let scope = scope(env_name, target, &wanted);
    let handoff = Cmd {
        command: vec!["apply".into()],
        args: plan_id
            .iter()
            .map(|s| s.to_string())
            .chain(scope.attest_args())
            .collect(),
    };
    // (1) Refusals first, before anything is read or prompted.
    crate::host::refuse_if_agent(host_env, handoff)?;
    let host = crate::host::Host::from_env(host_env);
    if host.ci {
        return Err(Cause::NeedsTerminal {
            why: NoTerminal::Ci,
        }
        .into());
    }
    if !host_env.interactive() {
        return Err(Cause::NeedsTerminal {
            why: NoTerminal::NoTty,
        }
        .into());
    }
    super::tidy::require_person_on(r, "opv apply", host)?;
    // (2) Recompute from what the target, 1Password and the ledger hold now.
    let (proposal, eligible) = survey(fleet, env_name, target, keys, r)?;
    if let Some(given) = plan_id
        && given != proposal.plan_id
    {
        return Err(Cause::PlanChanged {
            old: PlanId::new(given),
            new: PlanId::new(&proposal.plan_id),
            scope,
        }
        .into());
    }
    // (3) Show it, names and versions only, and confirm once.
    for line in describe(&proposal) {
        writeln!(out, "{line}").map_err(write_err)?;
    }
    if !confirm(&proposal) {
        return Ok(Attested {
            plan_id: proposal.plan_id,
            confirmed: false,
            attested: Vec::new(),
        });
    }
    // (4) One write per placement: its own delivery item, read fresh.
    let signed_in = signin::open_targeted(fleet, env_name, Some(target), r, Reach::Target)?;
    let r: &dyn CommandRunner = &signed_in;
    let at = crate::domain::provenance::utc_now();
    let mut by_product: BTreeMap<&str, Vec<Attest>> = BTreeMap::new();
    for e in &eligible {
        by_product
            .entry(e.product.as_str())
            .or_default()
            .push(e.attest.clone());
    }
    for (product, names) in &by_product {
        delivery::record_attestation(fleet, env_name, target, product, names, &at, r)?;
    }
    Ok(Attested {
        plan_id: proposal.plan_id,
        confirmed: true,
        attested: proposal
            .names
            .iter()
            .map(|n| key_label(&n.product, &n.key))
            .collect(),
    })
}
