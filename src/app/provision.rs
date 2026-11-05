//! `opv provision <SET> --env <ENV>` (#253, design `owner-value-ingestion.md` §4).
//!
//! Steps 1-7 of §4.2: the set and environment are resolved, the caller is judged (§6), the
//! set's one item is read fresh (the stamp `S0`) and classified (§4.5), and the value-free
//! plan (§4.3) is shown, checked against the run budget and confirmed by typing the
//! environment back (§4.4). `--dry-run` stops after the plan.
//!
//! Steps 8-12: each producer runs once (§5.2; its consent page opened by opv, its text never
//! shown), generated members are made (§5.1), every made value is validated and producer-made
//! ones compared with the set's other environments (§5.4, §5.5), the set is committed in one
//! checked edit against `S0` (§4.6), and a value-free [`Receipt`] (§7) is returned.
//!
//! No value, length, digest or prefix reaches the plan, the receipt, an error or `Debug`:
//! values live in [`SecretValue`]s and zeroizing buffers and never leave this module except
//! on the producer's stdin and the one item edit's stdin.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use zeroize::Zeroizing;

use super::generate::{self, Recipe};
use super::import::{self, Expected};
use super::open::Opener;
use super::produce_doc::{self, Notice, Parser, Terminal};
use crate::adapters::{onepassword, onepassword_tidy};
use crate::cause::{
    Cause, Cmd, CommandId, EnvName, FieldRule, Guard, InputKind, KeyName, NoTerminal, Principal,
    ProduceRule, ProducerFailure, ProductName, ProvisionRefusal, UnsupportedFeature, UsageProblem,
    ValueRow, VarName,
};
use crate::domain::provision::{
    self as model, Generator, KeyRef, MemberSource, ProvisionSet, SetState,
};
use crate::domain::provision_template::{self as template, Ref, RenderError, Template};
use crate::domain::value_state::{self, ValueState};
use crate::domain::{
    Boundary, Environment, Fleet, Kind, SecretValue, Tier, convention, presence, rules,
};
use crate::error::Error;
use crate::host::{Host, HostEnv, Platform, refuse_if_agent};
use crate::runner::{
    CommandRunner, LineVerdict, ProduceCall, ProducedLine, READ_TIMEOUT, WRITE_TIMEOUT,
};

/// What the command line asks for (§4.1).
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// `<SET>`: a `[sets.<name>]` of the contract.
    pub set: &'a str,
    /// `--env`: one of the set's `environments`.
    pub env: &'a str,
    /// `--dry-run`: the plan only; a read, allowed for an assistant and in CI.
    pub dry_run: bool,
    /// `--replace`: re-make a complete or inconsistent set (D8).
    pub replace: bool,
    /// `--fill-missing`: complete a partial set, keeping every present member (§4.7, D7).
    pub fill_missing: bool,
    /// The project directory (where the contract was read): a producer's cwd and the base
    /// of the project file its `command` names.
    pub project: &'a Path,
}

/// Where the plan is shown and the confirmation typed (§4.4). The CLI passes
/// [`TerminalConsole`]; tests script it.
pub trait ProvisionConsole {
    /// Show the plan's text (names only).
    fn show(&mut self, text: &str) -> Result<(), Error>;
    /// Ask `question` and read the typed-back answer; `None` when the person typed nothing
    /// or closed the input (declined).
    fn type_back(&mut self, question: &str) -> Result<Option<String>, Error>;
    /// Open `url`, a consent page the producer named and opv admitted (`https`, a host in
    /// the producer's `open_url_hosts`, no userinfo), in the person's browser. False when
    /// there is no opener here (SSH, CI, headless) or it could not be started: the caller
    /// then prints the URL for the person to open.
    fn open_url(&mut self, url: &str) -> bool;
}

/// The person's terminal: the plan and the question on stderr (stdout stays the command's
/// document), the answer through the setup console's line reader, a consent page through the
/// desktop's [`Opener`] (`opv open`'s, from [`super::open::opener`]).
pub struct TerminalConsole {
    pub opener: Option<Opener>,
}

impl TerminalConsole {
    /// The console for this host: its opener, or none over SSH, in CI or without a desktop.
    pub fn new(env: &dyn HostEnv) -> Self {
        Self {
            opener: super::open::opener(env),
        }
    }
}

impl ProvisionConsole for TerminalConsole {
    fn show(&mut self, text: &str) -> Result<(), Error> {
        use std::io::Write as _;
        writeln!(std::io::stderr(), "{text}").map_err(|_| {
            Cause::NeedsTerminal {
                why: NoTerminal::NoTty,
            }
            .into()
        })
    }

    fn type_back(&mut self, question: &str) -> Result<Option<String>, Error> {
        super::setup_runtime::type_back(question)
    }

    /// The opener is started directly, detached from the runner: it runs while the producer
    /// is the runner's current child, whose group opv's signals are forwarded to, and a
    /// runner call here would take that place. The URL is its one argument, never a shell
    /// (SR-7); its output is discarded (NR-31). Reaped on a thread.
    fn open_url(&mut self, url: &str) -> bool {
        use std::process::{Command, Stdio};
        let Some(o) = self.opener else {
            return false;
        };
        let child = Command::new(o.program)
            .args(o.args)
            .arg(url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        match child {
            Ok(mut child) => {
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
                true
            }
            Err(_) => false,
        }
    }
}

/// How the run ended without an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// `--dry-run`: the plan; nothing ran, nothing was made or written.
    DryRun(Plan),
    /// The set is complete and `--replace` was not given: nothing to do (exit 0).
    Unchanged(Plan),
    /// The person typed nothing at the confirmation (exit 0); nothing ran.
    Declined(Plan),
    /// The set was made, committed in one checked edit and read back (§4.6).
    Written(Box<(Plan, Receipt)>),
}

impl Outcome {
    /// The receipt's `result` word (§7).
    pub fn result(&self) -> &'static str {
        match self {
            Outcome::DryRun(_) => "dry_run",
            Outcome::Unchanged(_) => "unchanged",
            Outcome::Declined(_) => "declined",
            Outcome::Written(_) => "written",
        }
    }

    /// The plan the run was judged on.
    pub fn plan(&self) -> &Plan {
        match self {
            Outcome::DryRun(p) | Outcome::Unchanged(p) | Outcome::Declined(p) => p,
            Outcome::Written(w) => &w.0,
        }
    }

    /// The value-free receipt (§7), for every outcome but `--dry-run` (whose document is the
    /// plan). Nothing ran for `unchanged` and `declined`: no version after, no producer.
    pub fn receipt(&self) -> Option<Receipt> {
        match self {
            Outcome::DryRun(_) => None,
            Outcome::Written(w) => Some(w.1.clone()),
            Outcome::Unchanged(p) | Outcome::Declined(p) => {
                Some(Receipt::untouched(p, self.result()))
            }
        }
    }
}

/// The receipt (§7): names, versions and the producers' pins only; no value, length, digest
/// or prefix.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Receipt {
    /// `opv.provision/1`.
    pub schema: &'static str,
    pub set: String,
    pub env: String,
    /// The set's state when read (`absent`, `complete`, `inconsistent`), or `replace`.
    pub mode: &'static str,
    /// `written`, `unchanged` or `declined` (a refusal is the error document instead).
    pub result: &'static str,
    /// The edit's version was not one past opv's own read: an edit made just before opv's
    /// may have been replaced (kept in the item's history).
    pub concurrent_edit: bool,
    pub item: ReceiptItem,
    pub members: Vec<ReceiptMember>,
    /// The producers that ran, each once, in run order.
    pub producers: Vec<ReceiptProducer>,
    /// The other environments whose producer-made members were compared (§5.5).
    pub compared_environments: Vec<String>,
    /// The other environments opv could not read, so not compared.
    pub not_compared: Vec<String>,
    /// The command to run next, `opv ready <env>`.
    pub next: String,
}

/// The item written: IDs and versions only.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ReceiptItem {
    pub vault_id: String,
    pub item_id: String,
    /// The stamp `S0` the plan was made on.
    pub version_before: Option<u64>,
    /// The item's version after the edit (the revision plan-bound delivery builds on).
    pub version_after: Option<u64>,
    /// The version the final fresh read verified every written member at.
    pub verified_at: Option<u64>,
}

/// One member: how it was made and its state after the run.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ReceiptMember {
    /// `product/KEY`.
    pub key: String,
    /// `producer`, `generate` or `template`.
    pub made_by: &'static str,
    /// `set` once written; otherwise the state it was read in.
    pub state: &'static str,
}

/// One producer that ran: its name, pin and exit (always 0: any other exit is a refusal).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ReceiptProducer {
    pub name: String,
    pub sha256: Option<String>,
    pub exit: i32,
}

impl Receipt {
    /// The receipt of a run that made and wrote nothing.
    fn untouched(plan: &Plan, result: &'static str) -> Self {
        Self {
            schema: RECEIPT_SCHEMA,
            set: plan.set.clone(),
            env: plan.env.clone(),
            mode: mode(plan),
            result,
            concurrent_edit: false,
            item: ReceiptItem {
                vault_id: plan.item.vault_id.clone(),
                item_id: plan.item.item_id.clone(),
                version_before: plan.item.version,
                version_after: None,
                verified_at: None,
            },
            members: plan
                .members
                .iter()
                .map(|m| ReceiptMember {
                    key: m.key.clone(),
                    made_by: m.made_by.word(),
                    state: m.state,
                })
                .collect(),
            producers: Vec::new(),
            compared_environments: Vec::new(),
            not_compared: Vec::new(),
            next: format!("opv ready {}", plan.env),
        }
    }
}

/// The receipt's schema (§7).
pub const RECEIPT_SCHEMA: &str = "opv.provision/1";

fn mode(plan: &Plan) -> &'static str {
    if plan.replace {
        "replace"
    } else {
        state_word(plan.state)
    }
}

/// The plan (§4.3): names, makers, destinations, hashes and edges only, never a value.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Plan {
    pub set: String,
    pub env: String,
    pub item: PlanItem,
    /// The set's state in this environment (§4.5).
    pub state: SetState,
    pub replace: bool,
    /// `--fill-missing` (§4.7): present members are kept, only missing ones are made.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub fill_missing: bool,
    /// Each member in name order.
    pub members: Vec<PlanMember>,
    /// Each producer that runs, once, in name order (the order they run): those the members
    /// to make name, directly or through a template's `${producer.output}` leaf.
    pub producers: Vec<PlanProducer>,
    pub budget: PlanBudget,
    /// The other environments of the set whose producer-made members are compared for
    /// distinctness (§5.5); empty when none is declared or no member is producer-made.
    pub compare: Vec<String>,
}

/// The set's one item (D1), by IDs, and the version it was read at (the stamp `S0`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PlanItem {
    pub boundary: String,
    pub vault_id: String,
    pub item_id: String,
    pub version: Option<u64>,
}

/// One member: how its value is made and the state of the value it holds now.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PlanMember {
    /// `product/KEY`.
    pub key: String,
    pub made_by: MadeBy,
    /// `absent`, `set` or `malformed`.
    pub state: &'static str,
    /// The rule a held value fails, by name; never the value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
}

/// How a member's value is made (§5).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "maker", rename_all = "snake_case")]
pub enum MadeBy {
    Producer {
        producer: String,
        output: String,
    },
    Generate {
        generator: String,
    },
    /// #262: rendered from other members and producer outputs, named by reference only.
    Template {
        references: Vec<String>,
    },
}

impl MadeBy {
    /// The receipt's `made_by` word (§7).
    pub fn word(&self) -> &'static str {
        match self {
            MadeBy::Producer { .. } => "producer",
            MadeBy::Generate { .. } => "generate",
            MadeBy::Template { .. } => "template",
        }
    }
}

/// One producer as the contract declares it (value-free; `command` is checked at load).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PlanProducer {
    pub name: String,
    pub command: Vec<String>,
    pub sha256: Option<String>,
    pub timeout_seconds: u64,
    /// The keys whose values are sent on its stdin, `product/KEY`.
    pub inputs: Vec<String>,
    pub open_url_hosts: Vec<String>,
}

/// The time the run needs against the time it has (§4.2 step 7, vet F10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct PlanBudget {
    /// The sum of the producers' timeouts.
    pub producers_seconds: u64,
    /// The commit reserve: the runner's read, write and read limits (NR-4).
    pub commit_seconds: u64,
    /// What is left of the run budget; `None` when the runner keeps none.
    pub left_seconds: Option<u64>,
}

impl PlanBudget {
    fn needed(&self) -> u64 {
        self.producers_seconds + self.commit_seconds
    }

    /// False only when the run is known to have less time left than it needs.
    fn fits(&self) -> bool {
        self.left_seconds.is_none_or(|left| left >= self.needed())
    }
}

/// The commit reserve (§4.2 step 7): the fresh read, the one edit and the final read, at
/// the runner's own limits.
const COMMIT_RESERVE: Duration =
    Duration::from_secs(READ_TIMEOUT.as_secs() + WRITE_TIMEOUT.as_secs() + READ_TIMEOUT.as_secs());

/// `opv provision` (§4.2). The contract is loaded (step 1) by the caller. Refusals come
/// before any `op` call where §6 says so; the confirmation comes before anything is made;
/// nothing is written before the one checked edit (step 11).
pub fn provision(
    fleet: &Fleet,
    host_env: &dyn HostEnv,
    req: &Request<'_>,
    r: &dyn CommandRunner,
    console: &mut dyn ProvisionConsole,
) -> Result<Outcome, Error> {
    // Step 2: resolve the set and the environment.
    let set = resolve_set(fleet, req.set)?;
    let environment = fleet.environment(req.env)?;
    if !set.environments.iter().any(|e| e == req.env) {
        return Err(usage(
            "--env",
            "an environment listed in the set's environments",
        ));
    }
    // Steps 3-4: who is running. A dry run is a read and skips them.
    if !req.dry_run {
        who_is_running(set, req, host_env, environment, r)?;
    }
    // Step 5: read the set's item fresh (S0).
    let first = set.members.keys().next().ok_or(Cause::Bug {
        site: "provision set without members",
    })?;
    let b = fleet.boundary(req.env, &first.product)?;
    let item = onepassword::read_whole_fresh(r, environment, b)?;
    if let Some(holds) = onepassword_tidy::unprovable(item.raw()) {
        // A whole-item edit could drop what opv cannot prove it keeps (I4).
        return Err(refused(
            req,
            ProvisionRefusal::ItemNotRewritable {
                holds: holds.into(),
            },
        ));
    }
    let (layout, stamp) = onepassword_tidy::parse(item.raw())?;
    let part = super::tidy::in_boundary(fleet, &set.boundary);
    let res = convention::resolve(&layout, &part);
    let held = Held {
        layout: &layout,
        res: &res,
    };
    if req.fill_missing && req.replace {
        return Err(usage(
            "--fill-missing",
            "either --fill-missing or --replace, not both",
        ));
    }
    let states = member_states(fleet, set, req.env, environment, &held);
    // Step 6: classify.
    let state = model::classify(states.iter().map(|(_, s)| s)).map_err(|_| Cause::Bug {
        site: "provision member not stored",
    })?;
    // §4.7: a partial set completed with --fill-missing makes only its missing members.
    let filling = req.fill_missing && state == SetState::Partial;
    let fill = if filling {
        Fill::read(set, &states, &held)
    } else {
        Fill::everything(set)
    };
    let runs = fill.producers(fleet, set);
    let plan = build_plan(fleet, set, req, b, item.version, state, &states, &runs, r);
    if req.dry_run {
        return Ok(Outcome::DryRun(plan));
    }
    match state {
        SetState::Complete if !req.replace => return Ok(Outcome::Unchanged(plan)),
        // Without --fill-missing opv never fills part of a set, with or without --replace.
        SetState::Partial if !filling => {
            let missing = plan
                .members
                .iter()
                .filter(|m| m.state == "absent")
                .map(|m| m.key.clone())
                .collect();
            return Err(refused(req, ProvisionRefusal::Partial { missing }));
        }
        // A present member failing its rules, or a present template disagreeing with the
        // members, is never kept: --replace is the way (D7).
        SetState::Inconsistent if !req.replace => {
            return Err(refused(
                req,
                ProvisionRefusal::Inconsistent {
                    members: malformed(&plan),
                },
            ));
        }
        SetState::Partial if plan.members.iter().any(|m| m.state == "malformed") => {
            return Err(refused(
                req,
                ProvisionRefusal::Inconsistent {
                    members: malformed(&plan),
                },
            ));
        }
        _ => {}
    }
    if let Some(template) = fill.disagreeing.first() {
        // Two present templates hold different leaves for one missing member or output.
        return Err(refused(
            req,
            ProvisionRefusal::Inconsistent {
                members: vec![template.to_string()],
            },
        ));
    }
    if req.replace
        && let Some(member) = set
            .members
            .keys()
            .find(|m| fleet.products[&m.product].keys[&m.key].immutable)
    {
        return Err(refused(
            req,
            ProvisionRefusal::ImmutableMember {
                member: member.to_string(),
            },
        ));
    }
    // Every producer input must hold a value before anyone is asked to consent.
    inputs_present(fleet, &plan, req, &held)?;
    // Step 7: plan, budget, confirm. The budget is checked before consent (vet F10).
    console.show(&render_plan(&plan))?;
    if !plan.budget.fits() {
        return Err(refused(
            req,
            ProvisionRefusal::BudgetTooSmall {
                needed_seconds: plan.budget.needed(),
                left_seconds: plan.budget.left_seconds.unwrap_or_default(),
            },
        ));
    }
    let question = format!("Type the environment name to provision {} in it:", req.set);
    match console.type_back(&question)? {
        None => Ok(Outcome::Declined(plan)),
        Some(given) if given != req.env => Err(Cause::ConfirmMismatch {
            given,
            env: EnvName::new(req.env),
        }
        .into()),
        Some(_) => {
            let run = Run {
                fleet,
                part: &part,
                set,
                req,
                environment,
                b,
                stamp: &stamp,
                held: &held,
                fill: &fill,
                r,
            };
            let receipt = run.make_and_commit(&plan, console)?;
            Ok(Outcome::Written(Box::new((plan, receipt))))
        }
    }
}

/// The members the plan judged `malformed`, by name.
fn malformed(plan: &Plan) -> Vec<String> {
    plan.members
        .iter()
        .filter(|m| m.state == "malformed")
        .map(|m| m.key.clone())
        .collect()
}

/// The item read at `S0`: its layout and which field holds each key.
struct Held<'a> {
    layout: &'a convention::Layout,
    res: &'a convention::Resolution,
}

impl Held<'_> {
    /// The value `key` holds, `None` when it has no field or an empty one.
    fn value(&self, key: &KeyRef) -> Option<&SecretValue> {
        self.res
            .chosen
            .get(&(key.product.clone(), key.key.clone()))
            .map(|&i| &self.layout.fields[i].value)
            .filter(|v| !v.expose().trim().is_empty())
    }
}

/// A confirmed run (steps 8-12): what it was planned on.
struct Run<'a> {
    fleet: &'a Fleet,
    /// `fleet` limited to the set's boundary (the item's products).
    part: &'a Fleet,
    set: &'a ProvisionSet,
    req: &'a Request<'a>,
    environment: &'a Environment,
    b: &'a Boundary,
    stamp: &'a onepassword_tidy::Stamp,
    held: &'a Held<'a>,
    /// Which members this run makes, and what present templates already hold (§4.7).
    fill: &'a Fill,
    r: &'a dyn CommandRunner,
}

/// What a run makes (§4.7). Without `--fill-missing` (an absent set, or `--replace`) every
/// member is made and nothing held is used. With it, present members are kept; a missing
/// member a present template holds is filled from that leaf, and the intermediates present
/// templates hold are what a rerun producer must give again.
struct Fill {
    /// The members this run makes and writes.
    make: BTreeSet<KeyRef>,
    /// Missing members filled from a present template's leaf.
    from_leaf: BTreeMap<KeyRef, SecretValue>,
    /// The intermediates present templates hold, by `(producer, output)`, with the template
    /// holding them.
    outputs: BTreeMap<(String, String), (KeyRef, SecretValue)>,
    /// Present templates that hold a leaf another present template contradicts.
    disagreeing: Vec<KeyRef>,
}

impl Fill {
    /// Every member is made (an absent set, or `--replace`).
    fn everything(set: &ProvisionSet) -> Self {
        Self {
            make: set.members.keys().cloned().collect(),
            from_leaf: BTreeMap::new(),
            outputs: BTreeMap::new(),
            disagreeing: Vec::new(),
        }
    }

    /// `--fill-missing` on the item read at `S0`: the members holding no value are made;
    /// each present template's leaves (already judged to fit, §4.5) are recovered.
    fn read(set: &ProvisionSet, states: &[(String, ValueState)], held: &Held<'_>) -> Self {
        let make: BTreeSet<KeyRef> = set
            .members
            .keys()
            .zip(states)
            .filter(|(_, (_, s))| !matches!(s, ValueState::Set | ValueState::Malformed { .. }))
            .map(|(k, _)| k.clone())
            .collect();
        let mut fill = Self {
            make,
            from_leaf: BTreeMap::new(),
            outputs: BTreeMap::new(),
            disagreeing: Vec::new(),
        };
        for (k, source) in &set.members {
            let MemberSource::Template(t) = source else {
                continue;
            };
            if fill.make.contains(k) {
                continue;
            }
            let Some(stored) = held.value(k) else {
                continue;
            };
            let Ok(leaves) = template::extract(t, stored.expose().as_bytes()) else {
                // Judged `malformed` at classification, and refused there.
                continue;
            };
            for r in t.references() {
                let Some(v) = leaves.get(r) else { continue };
                let agrees = match r {
                    Ref::Member(m) if fill.make.contains(m) => match fill.from_leaf.get(m) {
                        Some(seen) => same(seen, v),
                        None => {
                            fill.from_leaf.insert(m.clone(), copy(v));
                            true
                        }
                    },
                    Ref::Member(_) => true,
                    Ref::Output { producer, output } => {
                        match fill.outputs.get(&(producer.clone(), output.clone())) {
                            Some((_, seen)) => same(seen, v),
                            None => {
                                fill.outputs.insert(
                                    (producer.clone(), output.clone()),
                                    (k.clone(), copy(v)),
                                );
                                true
                            }
                        }
                    }
                };
                if !agrees && !fill.disagreeing.contains(k) {
                    fill.disagreeing.push(k.clone());
                }
            }
        }
        fill
    }

    /// The producers this run starts, in name order: one a member to make names (unless
    /// it is filled from a leaf), or whose output a template to make uses.
    fn producers<'f>(&self, fleet: &'f Fleet, set: &ProvisionSet) -> Vec<&'f str> {
        fleet
            .producers
            .keys()
            .filter(|name| {
                set.members.iter().any(|(k, m)| {
                    self.make.contains(k)
                        && match m {
                            MemberSource::Producer { producer, .. } => {
                                producer == *name && !self.from_leaf.contains_key(k)
                            }
                            MemberSource::Template(t) => t.uses_producer(name),
                            MemberSource::Generate(_) => false,
                        }
                })
            })
            .map(String::as_str)
            .collect()
    }
}

/// A second [`SecretValue`] of the same value, for the run only.
fn copy(v: &SecretValue) -> SecretValue {
    SecretValue::new(v.expose().to_string())
}

/// The fixed, neutral line after a producer ran and nothing was stored (§4.6, vet F19).
const OUTPUTS_NOT_STORED: &str =
    "the producer's outputs were not stored; what it created at its issuer still exists";

impl Run<'_> {
    fn make_and_commit(
        &self,
        plan: &Plan,
        console: &mut dyn ProvisionConsole,
    ) -> Result<Receipt, Error> {
        // §4.7: a missing member a present template holds is filled from that leaf.
        let mut made: BTreeMap<KeyRef, SecretValue> = self
            .fill
            .from_leaf
            .iter()
            .map(|(k, v)| (k.clone(), copy(v)))
            .collect();
        // Producer outputs only templates use (intermediates): held for this run, never
        // stored.
        let mut intermediates: BTreeMap<(String, String), SecretValue> = BTreeMap::new();
        let mut ran = Vec::new();
        // Step 8: each producer once, in plan order. One attempt; nothing is retried.
        let produced = (|| -> Result<(), Error> {
            for p in &plan.producers {
                let mut outputs = self.produce(p, console)?;
                ran.push(ReceiptProducer {
                    name: p.name.clone(),
                    sha256: p.sha256.clone(),
                    exit: 0,
                });
                for (member, source) in &self.set.members {
                    if let MemberSource::Producer { producer, output } = source
                        && producer == &p.name
                        && self.fill.make.contains(member)
                        && !made.contains_key(member)
                    {
                        let v = outputs.get(output).ok_or(Cause::Bug {
                            site: "provision producer output not admitted",
                        })?;
                        made.insert(member.clone(), copy(v));
                    }
                }
                for (name, v) in std::mem::take(&mut outputs) {
                    if !self.set.members.values().any(
                        |m| matches!(m, MemberSource::Template(t) if t.uses_output(&p.name, &name)),
                    ) {
                        continue;
                    }
                    // §4.7: a rerun's intermediate must equal what the stored template holds.
                    if let Some((template, stored)) =
                        self.fill.outputs.get(&(p.name.clone(), name.clone()))
                        && !same(stored, &v)
                    {
                        return Err(refused(
                            self.req,
                            ProvisionRefusal::Inconsistent {
                                members: vec![template.to_string()],
                            },
                        ));
                    }
                    intermediates.insert((p.name.clone(), name), v);
                }
            }
            Ok(())
        })();
        let result = produced.and_then(|()| {
            self.generate_validate_commit(plan, made, &intermediates, ran.is_empty())
        });
        match result {
            Ok((written, compared, not_compared)) => Ok(Receipt {
                schema: RECEIPT_SCHEMA,
                set: plan.set.clone(),
                env: plan.env.clone(),
                mode: mode(plan),
                result: "written",
                concurrent_edit: written.concurrent_edit,
                item: ReceiptItem {
                    vault_id: plan.item.vault_id.clone(),
                    item_id: plan.item.item_id.clone(),
                    version_before: plan.item.version,
                    version_after: written.version,
                    verified_at: written.version,
                },
                members: plan
                    .members
                    .iter()
                    .map(|m| ReceiptMember {
                        key: m.key.clone(),
                        made_by: m.made_by.word(),
                        state: "set",
                    })
                    .collect(),
                producers: ran,
                compared_environments: compared,
                not_compared,
                next: format!("opv ready {}", plan.env),
            }),
            Err(e) => {
                if !ran.is_empty() && !is_unknown_outcome(&e) {
                    console.show(OUTPUTS_NOT_STORED)?;
                }
                Err(e)
            }
        }
    }

    /// Steps 9-11: generate, render, validate, compare, commit. `made` holds the producer
    /// values (and, for `--fill-missing`, the values recovered from present templates).
    fn generate_validate_commit(
        &self,
        plan: &Plan,
        mut made: BTreeMap<KeyRef, SecretValue>,
        intermediates: &BTreeMap<(String, String), SecretValue>,
        no_producer: bool,
    ) -> Result<(import::Written, Vec<String>, Vec<String>), Error> {
        // Step 9: generators.
        for (member, source) in &self.set.members {
            if let MemberSource::Generate(g) = source
                && self.fill.make.contains(member)
                && !made.contains_key(member)
            {
                made.insert(member.clone(), self.generate(member, *g)?);
            }
        }
        // Step 9 (§5.3): templates, each after the templates it references.
        let order = template::render_order(self.set).map_err(|_| Cause::Bug {
            site: "provision template cycle after load",
        })?;
        let mut unrendered = Vec::new();
        for member in order {
            let Some(MemberSource::Template(t)) = self.set.members.get(&member) else {
                continue;
            };
            if !self.fill.make.contains(&member) {
                continue;
            }
            match self.render(t, &made, intermediates)? {
                Some(v) => {
                    made.insert(member, v);
                }
                None => unrendered.push(member),
            }
        }
        // §4.7: every present template still fits the set as it will be written.
        let changed = self.kept_templates_fit(&made);
        if !changed.is_empty() {
            return Err(refused(
                self.req,
                ProvisionRefusal::Inconsistent {
                    members: changed.iter().map(ToString::to_string).collect(),
                },
            ));
        }
        // Step 10: every member against its rules, collected (NR-17).
        self.validate(&made, &unrendered)?;
        let (compared, not_compared) = if no_producer {
            (Vec::new(), Vec::new())
        } else {
            self.distinct(plan, &made)?
        };
        // Step 11: one checked edit against S0.
        let writes: Vec<(String, String, SecretValue)> = made
            .into_iter()
            .map(|(m, v)| (m.product, m.key, v))
            .collect();
        let refs: Vec<&(String, String, SecretValue)> = writes.iter().collect();
        let members: Vec<(String, String)> = self
            .set
            .members
            .keys()
            .map(|m| (m.product.clone(), m.key.clone()))
            .collect();
        let expected = Expected {
            stamp: self.stamp,
            seen: self.held.layout,
            members: &members,
        };
        let written = import::write_item(
            self.part,
            self.environment,
            self.b,
            &refs,
            None,
            &command(self.req),
            Some(&expected),
            self.r,
        )?;
        Ok((written, compared, not_compared))
    }

    /// One producer attempt (§5.2): the request on stdin, each stdout line through the
    /// `opv.produce/1` parser as it arrives. A consent page is opened by opv; only fixed
    /// lines and the closed error code are ever shown, never the producer's text.
    fn produce(
        &self,
        p: &PlanProducer,
        console: &mut dyn ProvisionConsole,
    ) -> Result<BTreeMap<String, SecretValue>, Error> {
        let producer = self.fleet.producers.get(&p.name).ok_or(Cause::Bug {
            site: "provision producer not declared",
        })?;
        let outputs: Vec<String> = producer
            .outputs
            .iter()
            .filter(|o| {
                self.set.members.values().any(|m| match m {
                    MemberSource::Producer { producer, output } => {
                        producer == &p.name && output == *o
                    }
                    MemberSource::Template(t) => t.uses_output(&p.name, o),
                    MemberSource::Generate(_) => false,
                })
            })
            .cloned()
            .collect();
        let mut inputs = Vec::new();
        for (name, key) in &producer.inputs {
            let v = self.held.value(key).ok_or(Cause::Bug {
                site: "provision input checked before consent",
            })?;
            inputs.push((name.as_str(), v));
        }
        let nonce = nonce()?;
        let request = request_line(self.req, &outputs, &nonce, &inputs);
        let command: Vec<&str> = producer.command.iter().map(String::as_str).collect();
        let file = project_file(self.req.project, &producer.command);
        let call = ProduceCall {
            set: self.req.set,
            producer: &p.name,
            file: &file,
            command: &command,
            cwd: self.req.project,
            request: &request,
            timeout: producer.timeout,
        };
        let context = produce_doc::Context {
            env: self.req.env,
            nonce: &nonce,
            outputs: &outputs,
            open_url_hosts: &producer.open_url_hosts,
        };
        console.show(&format!("running producer {}", p.name))?;
        let mut sink = Sink {
            producer: &p.name,
            file: &file,
            parser: Some(Parser::new(context)),
            result: None,
            console,
            shown: Ok(()),
        };
        let res = self.r.produce(&call, &mut |line| sink.line(line));
        sink.shown?;
        res?;
        sink.result.ok_or_else(|| {
            Cause::Bug {
                site: "provision producer ended without its result",
            }
            .into()
        })
    }

    /// Template `t` rendered from this run's values (members made now, else the present
    /// ones kept) and intermediates, and read back (§5.3). `None` when it does not read
    /// back to its sources (named by [`Run::validate`]).
    fn render(
        &self,
        t: &Template,
        made: &BTreeMap<KeyRef, SecretValue>,
        intermediates: &BTreeMap<(String, String), SecretValue>,
    ) -> Result<Option<SecretValue>, Error> {
        let lookup = |r: &Ref| match r {
            Ref::Member(k) => self.value_of(k, made),
            Ref::Output { producer, output } => {
                intermediates.get(&(producer.clone(), output.clone()))
            }
        };
        let mut bytes = match template::render(t, lookup) {
            Ok(b) => b,
            Err(RenderError::RoundTrip(_)) => return Ok(None),
            Err(RenderError::Missing { .. }) => {
                return Err(Cause::Bug {
                    site: "provision template reference without a value",
                }
                .into());
            }
        };
        // The JSON writer writes UTF-8 only; the buffer moves into the value, no copy.
        match String::from_utf8(std::mem::take(&mut *bytes)) {
            Ok(text) => {
                let v = SecretValue::new(text);
                crate::scrub::register_secret(v.expose());
                Ok(Some(v))
            }
            Err(e) => {
                zeroize::Zeroize::zeroize(&mut e.into_bytes());
                Err(Cause::Bug {
                    site: "provision template rendered other than UTF-8",
                }
                .into())
            }
        }
    }

    /// The value member `k` will hold after this run: made now, or kept when this run does
    /// not make it (`--fill-missing`).
    fn value_of<'v>(
        &'v self,
        k: &KeyRef,
        made: &'v BTreeMap<KeyRef, SecretValue>,
    ) -> Option<&'v SecretValue> {
        made.get(k).or_else(|| {
            if self.fill.make.contains(k) {
                None
            } else {
                self.held.value(k)
            }
        })
    }

    /// The present templates (`--fill-missing` keeps them) that would no longer fit the
    /// members as written: a present template that would change is refused (§4.7).
    fn kept_templates_fit(&self, made: &BTreeMap<KeyRef, SecretValue>) -> Vec<KeyRef> {
        self.set
            .members
            .iter()
            .filter(|(k, _)| !self.fill.make.contains(*k))
            .filter_map(|(k, source)| match source {
                MemberSource::Template(t) => {
                    let stored = self.held.value(k)?;
                    template::fit(t, stored.expose().as_bytes(), |m| self.value_of(m, made))
                        .is_err()
                        .then(|| k.clone())
                }
                _ => None,
            })
            .collect()
    }

    fn generate(&self, member: &KeyRef, g: Generator) -> Result<SecretValue, Error> {
        let recipe = match g {
            Generator::Rules => {
                let spec = &self.fleet.products[&member.product].keys[&member.key];
                generate::recipe(&member.product, &member.key, self.req.env, spec)?
            }
            Generator::HexBytes(n) => Recipe::Hex(usize::from(n)),
            Generator::Base64Bytes(n) => Recipe::Base64(usize::from(n)),
        };
        let v = generate::make(recipe)?;
        crate::scrub::register_secret(v.expose());
        Ok(v)
    }

    /// §5.4: every made value against its key's rules; a placeholder and a secret shorter
    /// than [`crate::scrub::SECRET_MIN`] fail too. Every failing member is named, with its
    /// rule only; any failure drops every value.
    fn validate(
        &self,
        made: &BTreeMap<KeyRef, SecretValue>,
        unrendered: &[KeyRef],
    ) -> Result<(), Error> {
        let mut rows: Vec<ValueRow> = unrendered
            .iter()
            .map(|member| ValueRow {
                product: ProductName::new(&member.product),
                key: KeyName::new(&member.key),
                target: None,
                state: crate::cause::ValueState::RuleFailed {
                    rule: TEMPLATE_RULE,
                    reason: None,
                },
            })
            .collect();
        for (member, value) in made {
            let spec = &self.fleet.products[&member.product].keys[&member.key];
            let failed = if crate::domain::health::is_placeholder(value.expose()) {
                Some(("placeholder", None))
            } else if let Err(f) = rules::check_verbatim(
                &member.product,
                &member.key,
                spec,
                self.req.env,
                self.environment,
                value,
                spec.file.is_some(),
            ) {
                Some((f.rule, Some(f.reason.to_string())))
            } else if spec.kind == Kind::Secret && value.expose().len() < crate::scrub::SECRET_MIN {
                Some(("secret_min", Some(SECRET_TOO_SHORT.to_string())))
            } else {
                None
            };
            if let Some((rule, reason)) = failed {
                rows.push(ValueRow {
                    product: ProductName::new(&member.product),
                    key: KeyName::new(&member.key),
                    target: None,
                    state: crate::cause::ValueState::RuleFailed { rule, reason },
                });
            }
        }
        if rows.is_empty() {
            Ok(())
        } else {
            Err(Cause::KeysBlocking {
                env: EnvName::new(self.req.env),
                rows,
            }
            .into())
        }
    }

    /// §5.5 (vet C21): each producer-made member against the same field in every other
    /// environment of the set. Equal ⇒ `SameAcrossEnvironments`. An environment opv cannot
    /// read is listed as not compared. Generated members are never compared.
    fn distinct(
        &self,
        plan: &Plan,
        made: &BTreeMap<KeyRef, SecretValue>,
    ) -> Result<(Vec<String>, Vec<String>), Error> {
        let produced: Vec<(&KeyRef, &SecretValue)> = made
            .iter()
            .filter(|(m, _)| {
                matches!(
                    self.set.members.get(*m),
                    Some(MemberSource::Producer { .. })
                )
            })
            .collect();
        let (mut compared, mut not_compared) = (Vec::new(), Vec::new());
        let Some(&(first, _)) = produced.first() else {
            return Ok((compared, not_compared));
        };
        for other in &plan.compare {
            let Some((layout, res)) = self.read_other(other, first) else {
                not_compared.push(other.clone());
                continue;
            };
            let there = Held {
                layout: &layout,
                res: &res,
            };
            for (member, value) in &produced {
                if there.value(member).is_some_and(|v| same(v, value)) {
                    return Err(refused(
                        self.req,
                        ProvisionRefusal::SameAcrossEnvironments {
                            member: member.to_string(),
                            other: EnvName::new(other),
                        },
                    ));
                }
            }
            compared.push(other.clone());
        }
        Ok((compared, not_compared))
    }

    /// The set's item in environment `other`, read fresh, or `None` when opv cannot read it.
    fn read_other(
        &self,
        other: &str,
        member: &KeyRef,
    ) -> Option<(convention::Layout, convention::Resolution)> {
        let environment = self.fleet.environment(other).ok()?;
        let b = self.fleet.boundary(other, &member.product).ok()?;
        let item = onepassword::read_whole_fresh(self.r, environment, b).ok()?;
        let (layout, _) = onepassword_tidy::parse(item.raw()).ok()?;
        let res = convention::resolve(&layout, self.part);
        Some((layout, res))
    }
}

/// The rule a template member fails when its document does not read back to its sources
/// (§5.3, §5.4). Never a value.
const TEMPLATE_RULE: &str = "template";

/// The rule-failure reason for a secret below [`crate::scrub::SECRET_MIN`] (§5.4): a fixed
/// phrase built from the constant, never from the value.
const SECRET_TOO_SHORT: &str = "a secret needs at least 8 bytes";

/// Two values equal, compared in constant time (never printed).
fn same(a: &SecretValue, b: &SecretValue) -> bool {
    use subtle::ConstantTimeEq;
    a.expose().as_bytes().ct_eq(b.expose().as_bytes()).into()
}

fn is_unknown_outcome(e: &Error) -> bool {
    matches!(e.cause(), Some((Cause::WriteOutcomeUnknown { .. }, _)))
}

/// The runner's line sink: each line through the parser; a notice shown (and a consent page
/// opened) at once; the result kept; an `error` line refused with its closed code.
struct Sink<'a, 'c> {
    producer: &'a str,
    file: &'a Path,
    parser: Option<Parser<'a>>,
    result: Option<BTreeMap<String, SecretValue>>,
    console: &'c mut dyn ProvisionConsole,
    /// A console failure, reported after the attempt.
    shown: Result<(), Error>,
}

impl Sink<'_, '_> {
    fn line(&mut self, line: ProducedLine<'_>) -> LineVerdict {
        let Some(parser) = self.parser.as_mut() else {
            // A line after the terminal one.
            return LineVerdict::Refuse(
                Cause::InputInvalid {
                    path: self.file.to_path_buf(),
                    kind: InputKind::Produce,
                    at: None,
                    field: "standard output".to_string(),
                    rule: FieldRule::Produce {
                        produce: ProduceRule::ResultNotLast { line: line.number },
                    },
                }
                .into(),
            );
        };
        match parser.feed(line.bytes) {
            Err(e) => LineVerdict::Refuse(e),
            Ok(Some(notice)) => {
                self.notice(&notice);
                LineVerdict::More
            }
            Ok(None) => match self.parser.take().map(Parser::finish) {
                Some(Ok(Terminal::Result(outputs))) => {
                    self.result = Some(outputs);
                    LineVerdict::Terminal
                }
                Some(Ok(Terminal::Error(code))) => LineVerdict::Refuse(
                    Cause::ProducerFailed {
                        producer: self.producer.to_string(),
                        why: ProducerFailure::Reported { code },
                    }
                    .into(),
                ),
                Some(Err(e)) => LineVerdict::Refuse(e),
                None => LineVerdict::Refuse(
                    Cause::Bug {
                        site: "provision parser gone",
                    }
                    .into(),
                ),
            },
        }
    }

    /// Fixed lines only. A consent URL holds public parameters only (OAuth authorization
    /// URLs), and is shown so a person without an opener can copy it.
    fn notice(&mut self, notice: &Notice) {
        let text = match notice {
            Notice::OpenUrl(url) => {
                if self.console.open_url(url) {
                    format!("opening the consent page in your browser: {url}")
                } else {
                    format!("open the consent page in your browser: {url}")
                }
            }
            Notice::Waiting => "waiting for the producer".to_string(),
        };
        if self.shown.is_ok() {
            self.shown = self.console.show(&text);
        }
    }
}

/// This run's nonce (§5.2): `n-` and 26 base32 characters from the OS CSPRNG.
fn nonce() -> Result<String, Error> {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut bytes = [0u8; 26];
    getrandom::fill(&mut bytes).map_err(|_| -> Error {
        Cause::LocalIo {
            op: crate::cause::LocalOp::RandomSource,
            path: PathBuf::new(),
            io: crate::cause::IoKind::Other,
            delivery: None,
        }
        .into()
    })?;
    let mut s = String::from("n-");
    s.extend(
        bytes
            .iter()
            .map(|b| char::from(ALPHABET[usize::from(*b % 32)])),
    );
    Ok(s)
}

/// The one-line `opv.produce/1` request (§5.2), built straight into a zeroizing buffer sized
/// up front (no reallocation leaves a copy behind); no `serde_json::Value` holds an input.
fn request_line(
    req: &Request<'_>,
    outputs: &[String],
    nonce: &str,
    inputs: &[(&str, &SecretValue)],
) -> Zeroizing<Vec<u8>> {
    // Escaping makes a string at most 6 bytes per byte, plus its quotes.
    let quoted = |n: usize| n * 6 + 2;
    let size = 128
        + quoted(req.env.len())
        + quoted(req.set.len())
        + quoted(nonce.len())
        + outputs.iter().map(|o| quoted(o.len()) + 1).sum::<usize>()
        + inputs
            .iter()
            .map(|(n, v)| quoted(n.len()) + quoted(v.expose().len()) + 2)
            .sum::<usize>();
    let mut buf = Zeroizing::new(Vec::with_capacity(size));
    let put_str = |buf: &mut Vec<u8>, s: &str| {
        // Writing a `&str` into a Vec cannot fail.
        let _ = serde_json::to_writer(&mut *buf, s);
    };
    buf.extend_from_slice(b"{\"schema\":\"opv.produce/1\",\"kind\":\"request\",\"env\":");
    put_str(&mut buf, req.env);
    buf.extend_from_slice(b",\"set\":");
    put_str(&mut buf, req.set);
    buf.extend_from_slice(b",\"outputs\":[");
    for (i, o) in outputs.iter().enumerate() {
        if i > 0 {
            buf.push(b',');
        }
        put_str(&mut buf, o);
    }
    buf.extend_from_slice(b"],\"nonce\":");
    put_str(&mut buf, nonce);
    buf.extend_from_slice(b",\"inputs\":{");
    for (i, (name, value)) in inputs.iter().enumerate() {
        if i > 0 {
            buf.push(b',');
        }
        put_str(&mut buf, name);
        buf.push(b':');
        put_str(&mut buf, value.expose());
    }
    buf.extend_from_slice(b"}}\n");
    buf
}

/// The project file the producer's `command` names (the one its `sha256` pins), for a
/// refusal to name; else `command[0]`.
fn project_file(project: &Path, command: &[String]) -> PathBuf {
    command
        .iter()
        .skip(1)
        .find(|a| !a.starts_with('-') && project.join(a).is_file())
        .or(command.first())
        .map(PathBuf::from)
        .unwrap_or_default()
}

/// Every input of every producer in the plan holds a value in the set's item (§5.5: inputs
/// resolve only within this environment's item), else `KeysBlocking` naming each missing
/// one, before the confirmation.
fn inputs_present(
    fleet: &Fleet,
    plan: &Plan,
    req: &Request<'_>,
    held: &Held<'_>,
) -> Result<(), Error> {
    let rows: Vec<ValueRow> = plan
        .producers
        .iter()
        .flat_map(|p| fleet.producers[&p.name].inputs.values())
        .filter(|key| held.value(key).is_none())
        .map(|key| ValueRow {
            product: ProductName::new(&key.product),
            key: KeyName::new(&key.key),
            target: None,
            state: crate::cause::ValueState::Missing,
        })
        .collect();
    if rows.is_empty() {
        Ok(())
    } else {
        Err(Cause::KeysBlocking {
            env: EnvName::new(req.env),
            rows,
        }
        .into())
    }
}

/// The exact command handed to a person (§6), `provision <SET> --env <ENV>`.
fn command(req: &Request<'_>) -> Cmd {
    Cmd {
        command: vec!["provision".into()],
        args: vec![req.set.into(), "--env".into(), req.env.into()],
    }
}

fn usage(flag: &str, format: &'static str) -> Error {
    Cause::Usage {
        problem: UsageProblem::ValueFormat {
            flag: flag.to_string(),
            format,
        },
    }
    .into()
}

fn refused(req: &Request<'_>, reason: ProvisionRefusal) -> Error {
    Cause::Guard {
        guard: Guard::ProvisionRefused {
            set: req.set.to_string(),
            env: EnvName::new(req.env),
            reason,
        },
    }
    .into()
}

fn resolve_set<'f>(fleet: &'f Fleet, name: &str) -> Result<&'f ProvisionSet, Error> {
    fleet
        .sets
        .get(name)
        .ok_or_else(|| usage("<SET>", "a set declared under [sets] in the contract"))
}

/// The first producer a member of `set` names, if any.
fn first_producer(set: &ProvisionSet) -> Option<&str> {
    set.members.values().find_map(|m| match m {
        MemberSource::Producer { producer, .. } => Some(producer.as_str()),
        MemberSource::Generate(_) => None,
        // #262: a template's leaf may name a producer output, which runs for it.
        MemberSource::Template(t) => t.references().into_iter().find_map(|r| match r {
            crate::domain::provision_template::Ref::Output { producer, .. } => {
                Some(producer.as_str())
            }
            crate::domain::provision_template::Ref::Member(_) => None,
        }),
    })
}

/// §4.2 steps 3-4 (§6): an assistant, CI, no terminal, a producer on native Windows, then
/// the identity and, for production, any session or token variable. Each is refused before
/// the item is read; the marker, CI, terminal, platform and D6 checks make no `op` call.
fn who_is_running(
    set: &ProvisionSet,
    req: &Request<'_>,
    host_env: &dyn HostEnv,
    environment: &Environment,
    r: &dyn CommandRunner,
) -> Result<(), Error> {
    refuse_if_agent(host_env, command(req))?;
    let host = Host::from_env(host_env);
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
    if host.platform == Platform::Windows
        && let Some(producer) = first_producer(set)
    {
        return Err(Cause::Unsupported {
            feature: UnsupportedFeature::ProducerOnWindows {
                set: req.set.to_string(),
                producer: producer.to_string(),
            },
        }
        .into());
    }
    // D6: in production the write uses the app's authorization or a sign-in opv prompts
    // for, never a session or token already in the environment. Names only.
    if (environment.tier == Tier::Production || environment.confirm_env)
        && let Some(var) = crate::host::credential_on(host_env)
    {
        return Err(Cause::NeedsOwnSession {
            command: CommandId(format!("provision {} --env {}", req.set, req.env)),
            identity: Principal::ShellToken {
                var: VarName::new(var),
            },
        }
        .into());
    }
    super::tidy::require_person_on(r, "opv provision", host)
}

/// Each member's value state in the item read at `S0`, in name order. The values are
/// judged in memory against every declared rule (a template also against the members it
/// holds, §4.5) and dropped here.
fn member_states(
    fleet: &Fleet,
    set: &ProvisionSet,
    env_name: &str,
    environment: &Environment,
    held: &Held<'_>,
) -> Vec<(String, ValueState)> {
    set.members
        .iter()
        .map(|(m, source)| {
            let spec = &fleet.products[&m.product].keys[&m.key];
            let value = held
                .res
                .chosen
                .get(&(m.product.clone(), m.key.clone()))
                .map(|&i| &held.layout.fields[i].value);
            let state =
                value_state::classify(Ok(value), presence::present_in(spec, env_name), true, |v| {
                    rules::check_verbatim(
                        &m.product,
                        &m.key,
                        spec,
                        env_name,
                        environment,
                        v,
                        spec.file.is_some(),
                    )
                    .map(|_| ())
                    .map_err(|f| f.rule)
                });
            // §4.5: a stored template whose document is not the template's, or whose
            // member leaves differ from the stored members, is malformed.
            let state = match (state, source) {
                (ValueState::Set, MemberSource::Template(t))
                    if held.value(m).is_some_and(|v| {
                        template::fit(t, v.expose().as_bytes(), |k| held.value(k)).is_err()
                    }) =>
                {
                    ValueState::Malformed {
                        rule: TEMPLATE_RULE.to_string(),
                    }
                }
                (state, _) => state,
            };
            (m.to_string(), state)
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn build_plan(
    fleet: &Fleet,
    set: &ProvisionSet,
    req: &Request<'_>,
    b: &Boundary,
    version: Option<u64>,
    state: SetState,
    states: &[(String, ValueState)],
    used: &[&str],
    r: &dyn CommandRunner,
) -> Plan {
    let members = set
        .members
        .values()
        .zip(states)
        .map(|(source, (key, value))| {
            let (state, rule) = match value {
                ValueState::Set => ("set", None),
                ValueState::Malformed { rule } => ("malformed", Some(rule.clone())),
                _ => ("absent", None),
            };
            PlanMember {
                key: key.clone(),
                made_by: made_by(source),
                state,
                rule,
            }
        })
        .collect();
    let producers: Vec<PlanProducer> = used
        .iter()
        .map(|name| {
            let p = &fleet.producers[*name];
            PlanProducer {
                name: (*name).to_string(),
                command: p.command.clone(),
                sha256: p.sha256.clone(),
                timeout_seconds: p.timeout.as_secs(),
                inputs: p.inputs.values().map(ToString::to_string).collect(),
                open_url_hosts: p.open_url_hosts.clone(),
            }
        })
        .collect();
    let budget = PlanBudget {
        producers_seconds: producers.iter().map(|p| p.timeout_seconds).sum(),
        commit_seconds: COMMIT_RESERVE.as_secs(),
        left_seconds: r.remaining().map(|d| d.as_secs()),
    };
    let compare = if producers.is_empty() {
        Vec::new()
    } else {
        set.environments
            .iter()
            .filter(|e| *e != req.env)
            .cloned()
            .collect()
    };
    Plan {
        set: req.set.to_string(),
        env: req.env.to_string(),
        item: PlanItem {
            boundary: set.boundary.clone(),
            vault_id: b.vault_id.clone(),
            item_id: b.item_id.clone(),
            version,
        },
        state,
        replace: req.replace,
        fill_missing: req.fill_missing && state == SetState::Partial,
        members,
        producers,
        budget,
        compare,
    }
}

fn made_by(source: &MemberSource) -> MadeBy {
    match source {
        MemberSource::Producer { producer, output } => MadeBy::Producer {
            producer: producer.clone(),
            output: output.clone(),
        },
        MemberSource::Generate(g) => MadeBy::Generate {
            generator: match g {
                Generator::Rules => "rules".to_string(),
                Generator::HexBytes(n) => format!("hex_bytes {n}"),
                Generator::Base64Bytes(n) => format!("base64_bytes {n}"),
            },
        },
        MemberSource::Template(t) => MadeBy::Template {
            references: t.references().iter().map(ToString::to_string).collect(),
        },
    }
}

fn state_word(state: SetState) -> &'static str {
    match state {
        SetState::Absent => "absent",
        SetState::Complete => "complete",
        SetState::Partial => "partial",
        SetState::Inconsistent => "inconsistent",
    }
}

/// `10m` for whole minutes, else `90s`.
fn span(seconds: u64) -> String {
    if seconds > 0 && seconds.is_multiple_of(60) {
        format!("{}m", seconds / 60)
    } else {
        format!("{seconds}s")
    }
}

/// The plan as the person reads it (§4.3). Names, hashes and limits only.
pub fn render_plan(plan: &Plan) -> String {
    let mut lines = vec![format!(
        "opv provision {} --env {}{}",
        plan.set,
        plan.env,
        if plan.replace {
            " --replace"
        } else if plan.fill_missing {
            " --fill-missing"
        } else {
            ""
        }
    )];
    let version = plan
        .item
        .version
        .map_or_else(|| "version unknown".to_string(), |v| format!("version {v}"));
    lines.push(format!(
        "  item    {} · {}   (vault {}, item {}, {version})",
        plan.item.boundary, plan.env, plan.item.vault_id, plan.item.item_id
    ));
    let held = plan.members.iter().filter(|m| m.state != "absent").count();
    lines.push(format!(
        "  state   {} ({held} of {} members set)",
        state_word(plan.state),
        plan.members.len()
    ));
    for m in &plan.members {
        let how = match &m.made_by {
            MadeBy::Producer { producer, output } => format!("producer {producer} → {output}"),
            MadeBy::Generate { generator } => format!("generate {generator}"),
            MadeBy::Template { references } => format!("template of {}", references.join(", ")),
        };
        if plan.fill_missing && m.state == "set" {
            lines.push(format!("  keep    {}", m.key));
        } else {
            lines.push(format!("  make    {}   {how}", m.key));
        }
    }
    for p in &plan.producers {
        lines.push(format!("  producer {}: {}", p.name, p.command.join(" ")));
        let inputs = if p.inputs.is_empty() {
            "none".to_string()
        } else {
            p.inputs.join(", ")
        };
        lines.push(format!(
            "           sha256 {}   timeout {}   inputs {inputs}",
            p.sha256.as_deref().unwrap_or("(no project file)"),
            span(p.timeout_seconds)
        ));
    }
    let left = plan.budget.left_seconds.map_or_else(
        || "no run limit".to_string(),
        |s| format!("{} left", span(s)),
    );
    lines.push(format!(
        "  budget  {} producer + {} commit of {left}",
        span(plan.budget.producers_seconds),
        span(plan.budget.commit_seconds)
    ));
    lines.push(if plan.producers.is_empty() {
        "  compare generated members only; nothing to compare".to_string()
    } else if plan.compare.is_empty() {
        "  compare no other environment declared".to_string()
    } else {
        format!("  compare {}", plan.compare.join(", "))
    });
    lines.push("  write   one edit of one item; nothing else in the item changes".to_string());
    lines.join("\n")
}

#[cfg(test)]
#[path = "provision_tests.rs"]
mod tests;
