//! `opv doctor`'s `op identity` row (#338, design `agent-identity.md` §7.4, §8; vet R5, R6,
//! R7; spike S1 §6.1).
//!
//! Which identity this run's `op` calls use, by the rules of [`crate::identity`]: the agent
//! identity (its name, environment, store, expiry, vault reach and rate-limit headroom), a
//! service-account or Connect credential from the environment, or the person's own session.
//! Two assistant warnings sit on top: a token in the environment of a process an assistant
//! runs (`token_in_agent_env`), and an assistant on the person's write-capable session
//! (`assistant_on_person_session`).
//!
//! The work is in two halves. [`before`] runs ahead of `op auth`: under `OPV_IDENTITY=agent` it
//! resolves the environment's agent identity, so every later `op` call carries its token.
//! [`after`] runs once `op auth` has answered: a token-scoped `op vault list`, `op
//! service-account ratelimit`, and the store [`self_check`]. [`row`] turns the facts into one
//! row; it is pure.
//!
//! Value-free (ADR-0001 R1): names, ids, dates, counts and states only. The token is never
//! read here (the resolver holds it), the self-check stores a dummy, and the row never claims
//! "writes none": read-only is the grant's, enforced by 1Password (`docs/reader-grants.md`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::adapters::credential_store::{
    AgentCredentialSource, AgentKey, Persistence, SourceDescription,
};
use crate::adapters::onepassword_ratelimit::{self as ratelimit, RateLimits};
use crate::cause::{AccountId, Cause, EnvName};
use crate::domain::Fleet;
use crate::domain::agent_identity::AgentRecord;
use crate::domain::credential::{DEFAULT_EXPIRY_WINDOW_DAYS, ExpiryState, expiry_state};
use crate::domain::secret::SecretValue;
use crate::error::Error;
use crate::host::{Host, OpCredential};
use crate::runner::{Call, CommandRunner, PROBE_TIMEOUT};

/// The row's name, in text and in `--json`.
pub const ROW: &str = "op identity";

/// The bound on the whole self-check round trip (vet R6): past it, the store is waiting on
/// a prompt or a hung daemon, which is `agent_store_locked`.
pub const SELF_CHECK_BOUND: Duration = crate::adapters::credential_store::READ_TIMEOUT;

/// The self-check entry's name. Never an identity's: an account part is a 26-character ID.
pub const SELF_CHECK_NAME: &str = "opv-doctor-selfcheck";

/// The dummy the self-check stores and reads back. Not a secret, and never the token.
const SELF_CHECK_DUMMY: &str = "opv-doctor-selfcheck-dummy-not-a-secret";

/// Percent of the token's hourly reads used at which the row warns (design §7.4).
const TOKEN_READ_WARN_PCT: u64 = 90;

/// Percent of the account's daily requests remaining below which the row warns (spike
/// §6.1: the account limit is shared with CI and binds first).
const ACCOUNT_REMAINING_WARN_PCT: u64 = 10;

/// The row's level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Warn,
    Fail,
    Skip,
}

/// The row: its level, text, a warning's own step, its JSON `state`, a failure's cause, and
/// the value-free identity object (the same object `ready --json` carries, design §7.4).
#[derive(Debug)]
pub struct IdentityRow {
    pub level: Level,
    pub text: String,
    pub fix: Option<String>,
    pub state: &'static str,
    /// A FAIL's own cause: its Do and Next, and the run's error when it is the first.
    pub error: Option<Error>,
    pub identity: serde_json::Value,
}

/// Which identity the rules picked, after [`before`].
#[derive(Debug)]
pub enum Who {
    /// Rule 1: a service-account or Connect credential in the environment.
    EnvToken(OpCredential),
    /// Rules 2 and 5: the person's session.
    Person,
    /// Rule 3 with no environment in scope: the agent identity is per environment.
    AgentUnscoped,
    /// Rule 3 could not give a token: not installed, a store failure, or a usage refusal.
    AgentUnavailable(Error),
    /// Rule 3: the environment's agent identity, by its service-account name.
    Agent { name: String },
}

impl Who {
    /// Whether `op auth` can run under this identity: not when rule 3 has no token.
    pub fn signs_in(&self) -> bool {
        !matches!(self, Who::AgentUnscoped | Who::AgentUnavailable(_))
    }
}

/// How many of the environment's vaults the token lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reach {
    pub readable: usize,
    pub expected: usize,
}

/// The store self-check's outcome.
#[derive(Debug)]
pub enum SelfCheck {
    /// Stored, read back unchanged and deleted, in `elapsed`.
    Ok { elapsed: Duration },
    /// A step failed: its cause (`agent_store_locked`, `agent_store_unavailable`).
    Failed(Error),
    /// The round trip outlived [`SELF_CHECK_BOUND`]: `agent_store_locked`.
    TimedOut,
}

/// What the row reports about the agent identity in use.
#[derive(Debug)]
pub struct AgentFacts {
    pub name: String,
    pub source: SourceDescription,
    /// From the value-free index (§7.5); `None` when the index has no entry.
    pub expires_on: Option<String>,
    pub reach: Option<Reach>,
    pub rate: Option<RateLimits>,
    /// `op auth` said 1Password rejected the token (`agent_rejected`).
    pub rejected: Option<Cause>,
    pub self_check: SelfCheck,
}

/// Everything [`row`] needs.
#[derive(Debug)]
pub enum Facts {
    Other(Who),
    Agent(Box<AgentFacts>),
}

/// The context [`row`] reads beside the facts.
#[derive(Debug, Clone)]
pub struct Context {
    /// The environment in scope (`--env`).
    pub env: Option<String>,
    /// An assistant marker is present (presentation only, never a control).
    pub marker: bool,
    /// Today, `YYYY-MM-DD`.
    pub today: String,
}

/// Opens the detected credential store.
pub type SourceFn<'a> = Box<dyn Fn() -> Arc<dyn AgentCredentialSource> + 'a>;

/// Reads the index entry of (service-account name, env).
pub type RecordFn<'a> = Box<dyn Fn(&str, &str) -> Option<AgentRecord> + 'a>;

/// Resolves rule 3 for (fleet, env) to the agent identity's service-account name.
pub type ResolveFn<'a> = Box<dyn Fn(&Fleet, &str) -> Result<String, Error> + 'a>;

/// How [`before`] and [`after`] reach the store, the index and the clock. [`Seams::process`]
/// is this machine's; tests give fakes.
pub struct Seams<'a> {
    /// Resolve rule 3 for (fleet, env): the agent identity's service-account name.
    pub resolve: ResolveFn<'a>,
    /// The detected credential store, for the self-check.
    pub source: SourceFn<'a>,
    /// The index entry of (service-account name, env), if recorded.
    pub record: RecordFn<'a>,
    /// Today, `YYYY-MM-DD`.
    pub today: Box<dyn Fn() -> String + 'a>,
    /// The self-check's bound.
    pub bound: Duration,
}

impl std::fmt::Debug for Seams<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Seams")
            .field("bound", &self.bound)
            .finish_non_exhaustive()
    }
}

impl<'a> Seams<'a> {
    /// This machine: the process's resolver, the detected OS store, the index file, the date.
    pub fn process(r: &'a dyn CommandRunner) -> Self {
        Seams {
            resolve: Box::new(move |fleet, env| resolve_process(fleet, env, r)),
            source: Box::new(|| {
                Arc::new(crate::adapters::credential_store::OsCredentialStore::detect())
            }),
            record: Box::new(|name, env| {
                let path = crate::app::agent_identity::index_path()?;
                let index = crate::app::agent_identity::load(&path).ok()?;
                index
                    .identities
                    .into_iter()
                    .find(|e| e.record.account_name == name && e.record.environment == env)
                    .map(|e| e.record)
            }),
            today: Box::new(crate::app::retire::today),
            bound: SELF_CHECK_BOUND,
        }
    }
}

/// Rule 3 for this process, as every command resolves it (`signin::resolve_identity`), then
/// the name the resolver kept.
fn resolve_process(fleet: &Fleet, env: &str, r: &dyn CommandRunner) -> Result<String, Error> {
    let kept = crate::identity::resolved()
        .and_then(crate::identity::Resolved::agent)
        .map(crate::identity::AgentIdentity::key);
    crate::app::signin::resolve_identity_on(
        &crate::host::ProcessEnv,
        fleet,
        env,
        &|| crate::app::personal::project_name(r, &std::env::current_dir().unwrap_or_default()),
        &|| crate::app::agent_identity::machine_name(None),
        kept,
        &|target| {
            let store = crate::adapters::credential_store::OsCredentialStore::detect();
            crate::identity::resolve(&store, || Ok(target)).map(|_| ())
        },
    )?;
    crate::identity::agent_name()
        .map(str::to_string)
        .ok_or_else(|| {
            Cause::Bug {
                site: "doctor: the agent identity resolved without a name",
            }
            .into()
        })
}

/// The identity the rules pick on `host`, resolving rule 3 for `env` (before `op auth`, so
/// its calls carry the agent's token).
pub fn before(host: &Host, fleet: Option<&Fleet>, env: Option<&str>, seams: &Seams<'_>) -> Who {
    match host.op_credential {
        Some(OpCredential::Agent) => match (fleet, env) {
            (Some(f), Some(e)) => match (seams.resolve)(f, e) {
                Ok(name) => Who::Agent { name },
                Err(err) => Who::AgentUnavailable(err),
            },
            _ => Who::AgentUnscoped,
        },
        Some(c) => Who::EnvToken(c),
        None => Who::Person,
    }
}

/// The facts after `op auth` (`auth`, its cause when it failed): for the agent, its index
/// entry, store, reach, rate limits and the store self-check.
pub fn after(
    who: Who,
    auth: Option<&Cause>,
    fleet: Option<&Fleet>,
    env: Option<&str>,
    r: &dyn CommandRunner,
    seams: &Seams<'_>,
) -> Facts {
    let Who::Agent { name } = who else {
        return Facts::Other(who);
    };
    let env = env.unwrap_or_default();
    let rejected = auth.filter(|c| c.code() == "agent_rejected").cloned();
    let signed_in = auth.is_none();
    let source = (seams.source)();
    Facts::Agent(Box::new(AgentFacts {
        expires_on: (seams.record)(&name, env).map(|r| r.expires_on),
        reach: (signed_in)
            .then(|| fleet.and_then(|f| reach(f, env, r)))
            .flatten(),
        rate: signed_in.then(|| ratelimit::read(r)).flatten(),
        rejected,
        source: source.describe(),
        self_check: self_check(source, seams.bound),
        name,
    }))
}

/// The environment's vaults (its bound boundaries) the token lists, from one token-scoped
/// `op vault list` (matched by ID or name). `None` when it cannot be read or the
/// environment binds no vault.
pub(crate) fn reach(fleet: &Fleet, env: &str, r: &dyn CommandRunner) -> Option<Reach> {
    #[derive(serde::Deserialize)]
    struct Vault {
        id: String,
        #[serde(default)]
        name: String,
    }
    let expected: std::collections::BTreeSet<String> = fleet
        .bound_boundaries(env)
        .ok()?
        .into_iter()
        .map(|(_, b)| b.vault_id.clone())
        .collect();
    if expected.is_empty() {
        return None;
    }
    let call = Call::new(
        crate::adapters::onepassword::OP,
        &["vault", "list", "--format", "json"],
    );
    let listed: Vec<Vault> = match r.probe(&call, PROBE_TIMEOUT) {
        Ok(o) if o.status == 0 => serde_json::from_slice(&o.stdout).ok()?,
        _ => {
            let _ = crate::runner::take_failure();
            return None;
        }
    };
    let readable = expected
        .iter()
        .filter(|v| listed.iter().any(|l| &l.id == *v || &l.name == *v))
        .count();
    Some(Reach {
        readable,
        expected: expected.len(),
    })
}

/// The self-check entry's key.
fn self_check_key() -> AgentKey {
    AgentKey::new(
        AccountId::new(SELF_CHECK_NAME),
        SELF_CHECK_NAME,
        EnvName::new("selfcheck"),
    )
    .expect("a fixed, valid key")
}

/// A dummy store, read and delete through `source`, bounded by `bound` (vet R6). The dummy
/// is deleted even when a step fails; a round trip that outlives `bound` is reported at once
/// as [`SelfCheck::TimedOut`] and still deletes its dummy when the store answers.
pub fn self_check(source: Arc<dyn AgentCredentialSource>, bound: Duration) -> SelfCheck {
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::Builder::new()
        .name("opv-doctor-selfcheck".into())
        .spawn(move || {
            let key = self_check_key();
            let start = Instant::now();
            let stored = source.store(&key, &SecretValue::new(SELF_CHECK_DUMMY.to_string()));
            let read = stored.and_then(|()| source.resolve(&key));
            // Always: a failed store may have left a partial entry.
            let deleted = source.delete(&key);
            let outcome = match (read, deleted) {
                (Err(e), _) | (Ok(_), Err(e)) => SelfCheck::Failed(e),
                (Ok(Some(v)), Ok(_)) if v.expose() == SELF_CHECK_DUMMY => SelfCheck::Ok {
                    elapsed: start.elapsed(),
                },
                (Ok(_), Ok(_)) => SelfCheck::Failed(
                    Cause::AgentStoreUnavailable {
                        store: source.describe().store,
                    }
                    .into(),
                ),
            };
            let _ = tx.send(outcome);
        });
    if worker.is_err() {
        return SelfCheck::TimedOut;
    }
    rx.recv_timeout(bound).unwrap_or(SelfCheck::TimedOut)
}

/// The `op access` command for `env`'s agent identity (`--create` or `--rotate`).
fn access(env: &str, verb: &str) -> String {
    format!("opv access {env} --{verb} --agent")
}

/// The one row for `facts` (design §7.4). Pure.
pub fn row(facts: Facts, ctx: &Context) -> IdentityRow {
    match facts {
        Facts::Agent(a) => agent_row(*a, ctx),
        Facts::Other(who) => other_row(who, ctx),
    }
}

fn plain(
    level: Level,
    text: String,
    fix: Option<String>,
    state: &'static str,
    identity: serde_json::Value,
) -> IdentityRow {
    IdentityRow {
        level,
        text,
        fix,
        state,
        error: None,
        identity,
    }
}

fn failed(e: Error, state: &'static str, identity: serde_json::Value) -> IdentityRow {
    IdentityRow {
        level: Level::Fail,
        text: e.to_string(),
        fix: None,
        state,
        error: Some(e),
        identity,
    }
}

fn other_row(who: Who, ctx: &Context) -> IdentityRow {
    let env = ctx.env.as_deref();
    let env_or = env.unwrap_or("<env>");
    let create = env.map(|e| access(e, "create"));
    let id = |kind: &str, source: Option<&str>, read_only: Option<bool>, state: &str| {
        serde_json::json!({
            "kind": kind,
            "name": null,
            "environment": ctx.env,
            "source": source,
            "read_only": read_only,
            "expires_on": null,
            "days_left": null,
            "reach": null,
            "rate_limit": null,
            "store": null,
            "state": state,
        })
    };
    match who {
        Who::EnvToken(c) if ctx.marker => {
            let state = "token_in_agent_env";
            plain(
                Level::Warn,
                format!(
                    "{} is in this process's environment, so an assistant here can read it with \
                     env; use opv access {env_or} --create --agent",
                    c.var()
                ),
                create,
                state,
                id(kind_of(c), Some(c.var()), None, state),
            )
        }
        Who::EnvToken(c) => {
            let (text, state) = match c {
                OpCredential::Connect => (
                    "1Password Connect from OP_CONNECT_HOST and OP_CONNECT_TOKEN".to_string(),
                    "connect",
                ),
                _ => (
                    format!("service account from {}", c.var()),
                    "service_account",
                ),
            };
            plain(
                Level::Ok,
                text,
                None,
                state,
                id(kind_of(c), Some(c.var()), None, state),
            )
        }
        Who::Person if ctx.marker => {
            let state = "assistant_on_person_session";
            plain(
                Level::Warn,
                format!(
                    "an assistant is using your own 1Password session, which can write; for \
                     read-only runs: opv access {env_or} --create --agent (in your own \
                     terminal), then OPV_IDENTITY=agent"
                ),
                create,
                state,
                id("person", None, Some(false), state),
            )
        }
        Who::Person => {
            let state = "person";
            plain(
                Level::Ok,
                "you (your own 1Password session)".into(),
                None,
                state,
                id("person", None, Some(false), state),
            )
        }
        Who::AgentUnscoped => {
            let state = "agent_unscoped";
            plain(
                Level::Skip,
                "OPV_IDENTITY=agent selects one identity per environment; check it with opv \
                 doctor --env <env>"
                    .into(),
                None,
                state,
                id("none", None, None, state),
            )
        }
        Who::AgentUnavailable(e) => {
            let state = match e.code_str() {
                "agent_identity_not_installed" => "agent_not_installed",
                "agent_store_locked" => "agent_store_locked",
                "agent_store_unavailable" => "agent_store_unavailable",
                _ => "agent_unusable",
            };
            failed(e, state, id("none", None, None, state))
        }
        // `after` turns the agent into `Facts::Agent`; without it nothing was checked.
        Who::Agent { name } => {
            let state = "agent";
            plain(
                Level::Skip,
                format!("agent {name}: not checked"),
                None,
                state,
                id("agent", None, Some(true), state),
            )
        }
    }
}

fn kind_of(c: OpCredential) -> &'static str {
    match c {
        OpCredential::Connect => "connect",
        OpCredential::ServiceAccount => "service_account",
        OpCredential::Agent => "agent",
    }
}

/// Why the rate limit is near, if it is: the account's shared daily budget first (it binds
/// first, spike §6.1), then the token's hourly reads.
fn rate_near(name: &str, rate: &RateLimits) -> Option<String> {
    if let Some(a) = rate
        .account_read_write()
        .filter(|a| a.limit > 0 && a.remaining_pct() < ACCOUNT_REMAINING_WARN_PCT)
    {
        return Some(format!(
            "this 1Password account has {} of its {} daily requests left, shared by agent {name}, \
             CI and every other service account on it",
            a.remaining, a.limit
        ));
    }
    rate.token_read()
        .filter(|t| t.limit > 0 && t.used_pct() >= TOKEN_READ_WARN_PCT)
        .map(|t| {
            format!(
                "agent {name} has used {}% of its hourly 1Password reads; CI may share this \
                 account's limit",
                t.used_pct()
            )
        })
}

/// The value-free identity object (design §7.4), for doctor's row and `ready --json`.
pub fn agent_json(a: &AgentFacts, ctx: &Context, state: &str) -> serde_json::Value {
    let days_left = match expiry_state(a.expires_on.as_deref(), &ctx.today, 0) {
        ExpiryState::Ok { days_left } | ExpiryState::Expiring { days_left } => Some(days_left),
        ExpiryState::Expired => Some(0),
        ExpiryState::Unknown => None,
    };
    let (self_check, ms) = match &a.self_check {
        SelfCheck::Ok { elapsed } => ("ok", Some(elapsed.as_millis() as u64)),
        SelfCheck::Failed(_) => ("failed", None),
        SelfCheck::TimedOut => ("timed_out", None),
    };
    let rate = a.rate.as_ref().map(|r| {
        serde_json::json!({
            "hourly_used_pct": r.token_read().map(|t| t.used_pct()),
            "daily_account": r.account_read_write().map(|l| serde_json::json!({
                "limit": l.limit,
                "used": l.used,
                "remaining": l.remaining,
            })),
        })
    });
    serde_json::json!({
        "kind": "agent",
        "name": a.name,
        "environment": ctx.env,
        "source": crate::app::agent_identity::store_id(a.source.store),
        "read_only": true,
        "expires_on": a.expires_on,
        "days_left": days_left,
        "reach": a.reach.map(|r| serde_json::json!({
            "readable": r.readable,
            "expected": r.expected,
        })),
        "rate_limit": rate,
        "store": {
            "persistence": a.source.persistence,
            "self_check": self_check,
            "self_check_ms": ms,
        },
        "state": state,
    })
}

fn agent_row(a: AgentFacts, ctx: &Context) -> IdentityRow {
    let env = ctx.env.clone().unwrap_or_default();
    let rotate = access(&env, "rotate");
    let id = |state: &str| agent_json(&a, ctx, state);
    // FAIL, most fundamental first: 1Password's refusal, the store, its persistence, expiry.
    if let Some(c) = &a.rejected {
        let state = "agent_rejected";
        return failed(c.clone().into(), state, id(state));
    }
    match &a.self_check {
        SelfCheck::TimedOut => {
            let state = "agent_store_locked";
            let e = Cause::AgentStoreLocked {
                store: a.source.store,
            }
            .into();
            return failed(e, state, id(state));
        }
        SelfCheck::Failed(e) => {
            let state = match e.code_str() {
                "agent_store_locked" => "agent_store_locked",
                _ => "agent_store_unavailable",
            };
            let e = Error::from(e.parts().0.clone());
            return failed(e, state, id(state));
        }
        SelfCheck::Ok { .. } => {}
    }
    if let Some(c) = a.source.volatile_cause(Some(EnvName::new(&env))) {
        let state = "agent_store_volatile";
        return failed(c.into(), state, id(state));
    }
    let expiry = expiry_state(
        a.expires_on.as_deref(),
        &ctx.today,
        DEFAULT_EXPIRY_WINDOW_DAYS,
    );
    let date = a.expires_on.clone().unwrap_or_default();
    match expiry {
        ExpiryState::Expired => {
            let state = "agent_expired";
            return plain(
                Level::Fail,
                format!("agent {} expired on {date}", a.name),
                Some(rotate),
                state,
                id(state),
            );
        }
        ExpiryState::Expiring { days_left } => {
            let state = "agent_expiring";
            return plain(
                Level::Warn,
                format!(
                    "agent {} expires in {}",
                    a.name,
                    crate::app::plural(days_left as usize, "day", "days")
                ),
                Some(rotate),
                state,
                id(state),
            );
        }
        ExpiryState::Ok { .. } | ExpiryState::Unknown => {}
    }
    if let Some(text) = a.rate.as_ref().and_then(|r| rate_near(&a.name, r)) {
        let state = "rate_limit_near";
        return plain(Level::Warn, text, None, state, id(state));
    }
    if let Some(r) = a.reach.filter(|r| r.readable < r.expected) {
        let state = "agent_reach_short";
        return plain(
            Level::Warn,
            format!(
                "agent {} reads {} of the {} vaults {env} uses",
                a.name, r.readable, r.expected
            ),
            Some(rotate),
            state,
            id(state),
        );
    }
    let state = "agent";
    plain(Level::Ok, ok_text(&a, &env, expiry), None, state, id(state))
}

/// `agent <name> for <env> (read-only by grant; token from <store>, <persistence>, self-check
/// <ms> ms; reads N of M vaults; expires <date>, in N days; account requests ...)`.
fn ok_text(a: &AgentFacts, env: &str, expiry: ExpiryState) -> String {
    let mut parts = vec!["read-only by grant".to_string()];
    let persistence = match a.source.persistence {
        Persistence::Durable => "durable",
        Persistence::Volatile => "volatile",
    };
    let ms = match &a.self_check {
        SelfCheck::Ok { elapsed } => format!(", self-check {} ms", elapsed.as_millis()),
        _ => String::new(),
    };
    parts.push(format!(
        "token from {}, {persistence}{ms}",
        crate::app::agent_identity::store_name(a.source.store)
    ));
    if let Some(r) = a.reach {
        parts.push(format!("reads {} of {} vaults", r.readable, r.expected));
    }
    match (&a.expires_on, expiry) {
        (Some(d), ExpiryState::Ok { days_left }) => parts.push(format!(
            "expires {d}, in {}",
            crate::app::plural(days_left as usize, "day", "days")
        )),
        _ => parts.push("expiry not recorded on this machine".into()),
    }
    if let Some(l) = a.rate.as_ref().and_then(RateLimits::account_read_write) {
        parts.push(format!(
            "account: {} of {} daily 1Password requests left, shared with CI",
            l.remaining, l.limit
        ));
    }
    format!("agent {} for {env} ({})", a.name, parts.join("; "))
}

#[cfg(test)]
#[path = "doctor_identity_tests.rs"]
mod tests;
