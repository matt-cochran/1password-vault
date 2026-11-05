//! `opv provision <SET> --env <ENV>` (#253, design `owner-value-ingestion.md` §4), part 1:
//! steps 1-7 of §4.2. The set and environment are resolved, the caller is judged (§6), the
//! set's one item is read fresh and classified (§4.5), and the value-free plan (§4.3) is
//! shown, checked against the run budget and confirmed by typing the environment back
//! (§4.4). `--dry-run` stops after the plan.
//!
//! Part 2 (lane iv-a6b) fills in steps 8-12 where [`provision`] returns
//! [`Outcome::Confirmed`]: produce, generate, validate, the checked commit and the receipt,
//! and `--replace`'s re-make. The plan's [`PlanItem::version`] is the stamp `S0` the commit
//! checks against (§4.6).
//!
//! No value, length, digest or prefix reaches the plan, an error or `Debug`: member values
//! are read only to judge their state, and never leave this module.

use std::time::Duration;

use crate::adapters::{onepassword, onepassword_tidy};
use crate::cause::{
    Cause, Cmd, CommandId, EnvName, Guard, NoTerminal, Principal, ProvisionRefusal,
    UnsupportedFeature, UsageProblem, VarName,
};
use crate::domain::provision::{self as model, Generator, MemberSource, ProvisionSet, SetState};
use crate::domain::value_state::{self, ValueState};
use crate::domain::{Environment, Fleet, Tier, convention, presence, rules};
use crate::error::Error;
use crate::host::{Host, HostEnv, Platform, refuse_if_agent};
use crate::runner::{CommandRunner, READ_TIMEOUT, WRITE_TIMEOUT};

/// What the command line asks for (§4.1).
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// `<SET>`: a `[sets.<name>]` of the contract.
    pub set: &'a str,
    /// `--env`: one of the set's `environments`.
    pub env: &'a str,
    /// `--dry-run`: the plan only; a read, allowed for an assistant and in CI.
    pub dry_run: bool,
    /// `--replace`: re-make a complete or inconsistent set (D8); part 2 makes the values.
    pub replace: bool,
}

/// Where the plan is shown and the confirmation typed (§4.4). The CLI passes
/// [`TerminalConsole`]; tests script it.
pub trait ProvisionConsole {
    /// Show the plan's text (names only).
    fn show(&mut self, text: &str) -> Result<(), Error>;
    /// Ask `question` and read the typed-back answer; `None` when the person typed nothing
    /// or closed the input (declined).
    fn type_back(&mut self, question: &str) -> Result<Option<String>, Error>;
}

/// The person's terminal: the plan and the question on stderr (stdout stays the command's
/// document), the answer through the setup console's line reader.
pub struct TerminalConsole;

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
}

/// How the run ended (part 1). Part 2 turns [`Outcome::Confirmed`] into a write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// `--dry-run`: the plan; nothing ran, nothing was made or written.
    DryRun(Plan),
    /// The set is complete and `--replace` was not given: nothing to do (exit 0).
    Unchanged(Plan),
    /// The person typed nothing at the confirmation (exit 0); nothing ran.
    Declined(Plan),
    /// The person typed the environment back: steps 8-12 (lane iv-a6b) make and commit
    /// the set against [`PlanItem::version`].
    Confirmed(Plan),
}

impl Outcome {
    /// The receipt's `result` word (§7) for the outcomes part 1 ends with.
    pub fn result(&self) -> &'static str {
        match self {
            Outcome::DryRun(_) => "dry_run",
            Outcome::Unchanged(_) => "unchanged",
            Outcome::Declined(_) => "declined",
            Outcome::Confirmed(_) => "confirmed",
        }
    }

    /// The plan the run was judged on.
    pub fn plan(&self) -> &Plan {
        match self {
            Outcome::DryRun(p) | Outcome::Unchanged(p) | Outcome::Declined(p) => p,
            Outcome::Confirmed(p) => p,
        }
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
    /// Each member in name order.
    pub members: Vec<PlanMember>,
    /// Each producer the set's members name, once, in name order (the order they run).
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

/// `opv provision` part 1 (§4.2 steps 1-7). The contract is loaded (step 1) by the caller.
/// Refusals come before any `op` call where §6 says so; the confirmation comes before
/// anything is made.
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
        return Err(Cause::Guard {
            guard: Guard::ArchiveNotRewritable {
                env: EnvName::new(req.env),
                holds: holds.into(),
            },
        }
        .into());
    }
    let states = member_states(fleet, set, req.env, environment, item.raw())?;
    // Step 6: classify.
    let state = model::classify(states.iter().map(|(_, s)| s)).map_err(|_| Cause::Bug {
        site: "provision member not stored",
    })?;
    let plan = build_plan(fleet, set, req, b, item.version, state, &states, r);
    if req.dry_run {
        return Ok(Outcome::DryRun(plan));
    }
    match state {
        SetState::Complete if !req.replace => return Ok(Outcome::Unchanged(plan)),
        // Slice A never fills part of a set, with or without --replace.
        SetState::Partial => {
            let missing = plan
                .members
                .iter()
                .filter(|m| m.state == "absent")
                .map(|m| m.key.clone())
                .collect();
            return Err(refused(req, ProvisionRefusal::Partial { missing }));
        }
        SetState::Inconsistent if !req.replace => {
            let members = plan
                .members
                .iter()
                .filter(|m| m.state == "malformed")
                .map(|m| m.key.clone())
                .collect();
            return Err(refused(req, ProvisionRefusal::Inconsistent { members }));
        }
        _ => {}
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
        // Steps 8-12 are part 2 (lane iv-a6b): produce, generate, validate, commit, receipt.
        Some(_) => Ok(Outcome::Confirmed(plan)),
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

/// Each member's value state in the item `raw`, in name order. The values are judged in
/// memory against every declared rule and dropped here.
fn member_states(
    fleet: &Fleet,
    set: &ProvisionSet,
    env_name: &str,
    environment: &Environment,
    raw: &[u8],
) -> Result<Vec<(String, ValueState)>, Error> {
    let (layout, _) = onepassword_tidy::parse(raw)?;
    let part = super::tidy::in_boundary(fleet, &set.boundary);
    let res = convention::resolve(&layout, &part);
    Ok(set
        .members
        .keys()
        .map(|m| {
            let spec = &fleet.products[&m.product].keys[&m.key];
            let held = res
                .chosen
                .get(&(m.product.clone(), m.key.clone()))
                .map(|&i| &layout.fields[i].value);
            let state =
                value_state::classify(Ok(held), presence::present_in(spec, env_name), true, |v| {
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
            (m.to_string(), state)
        })
        .collect())
}

#[allow(clippy::too_many_arguments)]
fn build_plan(
    fleet: &Fleet,
    set: &ProvisionSet,
    req: &Request<'_>,
    b: &crate::domain::Boundary,
    version: Option<u64>,
    state: SetState,
    states: &[(String, ValueState)],
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
    let used: Vec<&str> = fleet
        .producers
        .keys()
        .filter(|name| {
            set.members
                .values()
                .any(|m| matches!(m, MemberSource::Producer { producer, .. } if producer == *name))
        })
        .map(String::as_str)
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
        if plan.replace { " --replace" } else { "" }
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
        lines.push(format!("  make    {}   {how}", m.key));
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
