//! The `op identity` row (#338, design `agent-identity.md` §7.4): one scenario per test.

use std::sync::{Arc, Mutex};

use super::*;
use crate::adapters::credential_store::{FakeCredentialSource, FakeFault};
use crate::app::testutil::{MARKER, fleet};
use crate::cause::{AgentStore, CallId, ExitClass, Observed, Principal, System, VarName};
use crate::host::FakeEnv;
use crate::runner::Output;
use crate::runner::fake::FakeRunner;

const NAME: &str = "shop-dev-agent-laptop";
const TODAY: &str = "2026-11-17";
/// A token-shaped canary: it must never reach doctor's text or JSON.
const TOKEN: &str = "ops_CANARYTOKEN-FIXTUREVALUE-eyJzaWduSW5BZGRyZXNzIjoi";

/// The spike's owner run (§6.1): plenty of headroom.
const RATE_OK: &str = r#"[
    {"type":"token","action":"write","limit":100,"used":1,"remaining":99,"reset":3540},
    {"type":"token","action":"read","limit":1000,"used":2,"remaining":998,"reset":3540},
    {"type":"account","action":"read_write","limit":1000,"used":8,"remaining":992,"reset":46800}
]"#;

fn ctx(env: Option<&str>, marker: bool) -> Context {
    Context {
        env: env.map(str::to_string),
        marker,
        today: TODAY.into(),
    }
}

fn durable() -> SourceDescription {
    SourceDescription {
        store: AgentStore::SecretService,
        persistence: Persistence::Durable,
    }
}

/// A healthy agent identity: durable store, self-check ok, 2 of 2 vaults, 90 days left.
fn agent() -> AgentFacts {
    AgentFacts {
        name: NAME.into(),
        source: durable(),
        expires_on: Some("2027-02-15".into()),
        reach: Some(Reach {
            readable: 2,
            expected: 2,
        }),
        rate: ratelimit::parse(RATE_OK.as_bytes()),
        rejected: None,
        self_check: SelfCheck::Ok {
            elapsed: Duration::ZERO,
        },
    }
}

fn agent_row_of(a: AgentFacts) -> IdentityRow {
    row(Facts::Agent(Box::new(a)), &ctx(Some("dev"), true))
}

fn other(who: Who, env: Option<&str>, marker: bool) -> IdentityRow {
    row(Facts::Other(who), &ctx(env, marker))
}

fn rate(account_used: u64, token_used: u64) -> Option<RateLimits> {
    let json = format!(
        r#"[{{"type":"token","action":"read","limit":1000,"used":{token_used},"remaining":{},"reset":1}},
            {{"type":"account","action":"read_write","limit":1000,"used":{account_used},"remaining":{},"reset":1}}]"#,
        1000 - token_used,
        1000 - account_used
    );
    ratelimit::parse(json.as_bytes())
}

fn level_state(r: &IdentityRow) -> (Level, &'static str) {
    (r.level, r.state)
}

/// 1Password's refusal of the agent's token, as the runner observes it.
fn rejected() -> Cause {
    Cause::AgentRejected {
        name: NAME.into(),
        env: None,
        seen: Observed::from_failed_call(
            CallId {
                system: System::OnePassword,
                program: "op".into(),
                words: vec!["whoami".into()],
            },
            ExitClass::Code { code: 1 },
            Principal::ShellToken {
                var: VarName::new("OP_SERVICE_ACCOUNT_TOKEN"),
            },
        ),
    }
}

// --- states (design §7.4) ---------------------------------------------------------------

#[test]
fn a_healthy_agent_identity_is_ok_agent() {
    assert_eq!(level_state(&agent_row_of(agent())), (Level::Ok, "agent"));
}

#[test]
fn the_agent_row_names_identity_environment_store_reach_and_expiry() {
    assert_eq!(
        agent_row_of(agent()).text,
        "agent shop-dev-agent-laptop for dev (read-only by grant; token from login keyring \
         (Secret Service), durable, self-check 0 ms; reads 2 of 2 vaults; expires 2027-02-15, \
         in 90 days; account: 992 of 1000 daily 1Password requests left, shared with CI)"
    );
}

#[test]
fn the_agent_row_never_claims_the_identity_writes_nothing() {
    assert!(!agent_row_of(agent()).text.contains("writes none"));
}

#[test]
fn the_person_without_an_assistant_is_ok_person() {
    assert_eq!(
        level_state(&other(Who::Person, Some("dev"), false)),
        (Level::Ok, "person")
    );
}

#[test]
fn an_environment_service_account_token_is_ok_service_account() {
    let r = other(
        Who::EnvToken(OpCredential::ServiceAccount),
        Some("dev"),
        false,
    );
    assert_eq!(level_state(&r), (Level::Ok, "service_account"));
}

#[test]
fn an_environment_connect_credential_is_ok_connect() {
    assert_eq!(
        level_state(&other(Who::EnvToken(OpCredential::Connect), None, false)),
        (Level::Ok, "connect")
    );
}

#[test]
fn an_env_token_with_an_assistant_marker_warns_token_in_agent_env() {
    let r = other(
        Who::EnvToken(OpCredential::ServiceAccount),
        Some("dev"),
        true,
    );
    assert_eq!(
        (r.level, r.text.as_str()),
        (
            Level::Warn,
            "OP_SERVICE_ACCOUNT_TOKEN is in this process's environment, so an assistant here \
             can read it with env; use opv access dev --create --agent"
        )
    );
}

#[test]
fn the_assistant_on_the_persons_session_warns_assistant_on_person_session() {
    assert_eq!(
        level_state(&other(Who::Person, Some("dev"), true)),
        (Level::Warn, "assistant_on_person_session")
    );
}

#[test]
fn the_assistant_on_the_persons_session_points_to_the_agent_create() {
    assert_eq!(
        other(Who::Person, Some("dev"), true).fix.as_deref(),
        Some("opv access dev --create --agent")
    );
}

#[test]
fn no_agent_identity_for_the_environment_fails_agent_not_installed() {
    let e: Error = Cause::AgentIdentityNotInstalled {
        env: EnvName::new("dev"),
    }
    .into();
    assert_eq!(
        level_state(&other(Who::AgentUnavailable(e), Some("dev"), true)),
        (Level::Fail, "agent_not_installed")
    );
}

#[test]
fn a_locked_store_at_resolve_fails_agent_store_locked() {
    let e: Error = Cause::AgentStoreLocked {
        store: AgentStore::SecretService,
    }
    .into();
    assert_eq!(
        level_state(&other(Who::AgentUnavailable(e), Some("dev"), true)),
        (Level::Fail, "agent_store_locked")
    );
}

#[test]
fn the_agent_without_an_environment_in_scope_is_skipped() {
    assert_eq!(
        level_state(&other(Who::AgentUnscoped, None, true)),
        (Level::Skip, "agent_unscoped")
    );
}

#[test]
fn a_token_1password_rejected_fails_agent_rejected() {
    let a = AgentFacts {
        rejected: Some(rejected()),
        ..agent()
    };
    assert_eq!(
        level_state(&agent_row_of(a)),
        (Level::Fail, "agent_rejected")
    );
}

#[test]
fn a_volatile_store_fails_agent_store_volatile() {
    let a = AgentFacts {
        source: SourceDescription {
            store: AgentStore::KernelKeyring,
            persistence: Persistence::Volatile,
        },
        ..agent()
    };
    assert_eq!(
        level_state(&agent_row_of(a)),
        (Level::Fail, "agent_store_volatile")
    );
}

#[test]
fn a_volatile_store_is_a_failure_of_the_run() {
    let a = AgentFacts {
        source: SourceDescription {
            store: AgentStore::KernelKeyring,
            persistence: Persistence::Volatile,
        },
        ..agent()
    };
    assert_eq!(
        agent_row_of(a).error.map(|e| e.code_str()),
        Some("agent_store_volatile")
    );
}

#[test]
fn a_self_check_timeout_fails_agent_store_locked() {
    let a = AgentFacts {
        self_check: SelfCheck::TimedOut,
        ..agent()
    };
    assert_eq!(
        agent_row_of(a).error.map(|e| e.code_str()),
        Some("agent_store_locked")
    );
}

#[test]
fn fewer_vaults_than_the_environment_uses_warns_agent_reach_short() {
    let a = AgentFacts {
        reach: Some(Reach {
            readable: 1,
            expected: 2,
        }),
        ..agent()
    };
    assert_eq!(
        level_state(&agent_row_of(a)),
        (Level::Warn, "agent_reach_short")
    );
}

// --- expiry (FR-69: warn within 14 days, fail when expired) ------------------------------

#[test]
fn an_agent_expiring_within_fourteen_days_warns_agent_expiring() {
    let a = AgentFacts {
        expires_on: Some("2026-11-26".into()),
        ..agent()
    };
    let r = agent_row_of(a);
    assert_eq!(
        (r.level, r.text.as_str()),
        (Level::Warn, "agent shop-dev-agent-laptop expires in 9 days")
    );
}

#[test]
fn an_expiring_agent_points_to_the_rotation() {
    let a = AgentFacts {
        expires_on: Some("2026-11-26".into()),
        ..agent()
    };
    assert_eq!(
        agent_row_of(a).fix.as_deref(),
        Some("opv access dev --rotate --agent")
    );
}

#[test]
fn an_expired_agent_fails_agent_expired() {
    let a = AgentFacts {
        expires_on: Some("2026-11-17".into()),
        ..agent()
    };
    assert_eq!(
        level_state(&agent_row_of(a)),
        (Level::Fail, "agent_expired")
    );
}

#[test]
fn an_agent_fifteen_days_from_expiry_is_ok() {
    let a = AgentFacts {
        expires_on: Some("2026-12-02".into()),
        ..agent()
    };
    assert_eq!(agent_row_of(a).level, Level::Ok);
}

// --- rate limits (vet R7, spike §6.1) ------------------------------------------------------

#[test]
fn an_account_under_ten_percent_of_its_daily_requests_warns_rate_limit_near() {
    let a = AgentFacts {
        rate: rate(950, 2),
        ..agent()
    };
    assert_eq!(
        level_state(&agent_row_of(a)),
        (Level::Warn, "rate_limit_near")
    );
}

#[test]
fn the_account_rate_warning_says_ci_shares_the_daily_limit() {
    let a = AgentFacts {
        rate: rate(950, 2),
        ..agent()
    };
    assert_eq!(
        agent_row_of(a).text,
        "this 1Password account has 50 of its 1000 daily requests left, shared by agent \
         shop-dev-agent-laptop, CI and every other service account on it"
    );
}

#[test]
fn a_token_past_ninety_percent_of_its_hourly_reads_warns_rate_limit_near() {
    let a = AgentFacts {
        rate: rate(8, 920),
        ..agent()
    };
    assert_eq!(
        agent_row_of(a).text,
        "agent shop-dev-agent-laptop has used 92% of its hourly 1Password reads; CI may share \
         this account's limit"
    );
}

#[test]
fn an_unreadable_rate_limit_leaves_the_row_ok() {
    let a = AgentFacts {
        rate: None,
        ..agent()
    };
    assert_eq!(agent_row_of(a).level, Level::Ok);
}

#[test]
fn an_unreadable_rate_limit_omits_the_figure() {
    let a = AgentFacts {
        rate: None,
        ..agent()
    };
    assert!(!agent_row_of(a).text.contains("requests"));
}

#[test]
fn an_unreadable_ratelimit_call_gives_no_rate_limit() {
    let r = FakeRunner::new(vec![
        Output::success(br#"[{"id":"vstg","name":"Staging"}]"#.to_vec()),
        Output::success(b"op: unknown command \"ratelimit\"\n".to_vec()),
    ]);
    let seams = fake_seams(Arc::new(FakeCredentialSource::new(
        AgentStore::SecretService,
    )));
    let facts = after(
        agent_who(),
        None,
        Some(&fleet()),
        Some("staging"),
        &r,
        &seams,
    );
    assert!(matches!(facts, Facts::Agent(a) if a.rate.is_none()));
}

// --- the store self-check -------------------------------------------------------------------

/// A source that records each operation, and can fail its read or stall it.
struct Recording {
    inner: FakeCredentialSource,
    ops: Mutex<Vec<&'static str>>,
    fail_read: bool,
    stall: Option<Duration>,
}

impl Recording {
    fn new() -> Self {
        Recording {
            inner: FakeCredentialSource::new(AgentStore::SecretService),
            ops: Mutex::new(Vec::new()),
            fail_read: false,
            stall: None,
        }
    }

    fn note(&self, op: &'static str) {
        self.ops.lock().unwrap().push(op);
    }
}

impl AgentCredentialSource for Recording {
    fn describe(&self) -> SourceDescription {
        self.inner.describe()
    }
    fn preflight(&self) -> Result<SourceDescription, Error> {
        self.inner.preflight()
    }
    fn resolve(&self, key: &AgentKey) -> Result<Option<SecretValue>, Error> {
        self.note("resolve");
        if let Some(d) = self.stall {
            std::thread::sleep(d);
        }
        if self.fail_read {
            return Err(Cause::AgentStoreLocked {
                store: AgentStore::SecretService,
            }
            .into());
        }
        self.inner.resolve(key)
    }
    fn store(&self, key: &AgentKey, value: &SecretValue) -> Result<(), Error> {
        self.note("store");
        self.inner.store(key, value)
    }
    fn delete(&self, key: &AgentKey) -> Result<bool, Error> {
        self.note("delete");
        self.inner.delete(key)
    }
}

#[test]
fn the_self_check_round_trip_through_a_working_store_is_ok() {
    let source = Arc::new(FakeCredentialSource::new(AgentStore::SecretService));
    assert!(matches!(
        self_check(source, Duration::from_secs(5)),
        SelfCheck::Ok { .. }
    ));
}

#[test]
fn the_self_check_on_a_locked_store_fails_agent_store_locked() {
    let source = FakeCredentialSource::new(AgentStore::SecretService);
    source.set_fault(Some(FakeFault::Locked));
    let outcome = self_check(Arc::new(source), Duration::from_secs(5));
    assert!(matches!(outcome, SelfCheck::Failed(e) if e.code_str() == "agent_store_locked"));
}

#[test]
fn the_self_check_past_its_bound_times_out() {
    let source = Recording {
        stall: Some(Duration::from_millis(400)),
        ..Recording::new()
    };
    assert!(matches!(
        self_check(Arc::new(source), Duration::from_millis(20)),
        SelfCheck::TimedOut
    ));
}

#[test]
fn the_self_check_on_a_volatile_store_reports_it_volatile() {
    let source = Arc::new(FakeCredentialSource::volatile());
    let a = AgentFacts {
        source: source.describe(),
        self_check: self_check(source, Duration::from_secs(5)),
        ..agent()
    };
    assert_eq!(agent_row_of(a).state, "agent_store_volatile");
}

#[test]
fn the_self_check_deletes_its_dummy_when_the_read_fails() {
    let source = Arc::new(Recording {
        fail_read: true,
        ..Recording::new()
    });
    let _ = self_check(source.clone(), Duration::from_secs(5));
    assert_eq!(*source.ops.lock().unwrap(), ["store", "resolve", "delete"]);
}

#[test]
fn the_self_check_leaves_no_entry_behind() {
    let source = Arc::new(FakeCredentialSource::new(AgentStore::SecretService));
    let _ = self_check(source.clone(), Duration::from_secs(5));
    assert!(source.resolve(&self_check_key()).unwrap().is_none());
}

#[test]
fn the_self_check_never_stores_under_an_identity_key() {
    assert_eq!(
        self_check_key().user(),
        "opv-doctor-selfcheck/opv-doctor-selfcheck/selfcheck"
    );
}

// --- before and after ----------------------------------------------------------------------

fn agent_who() -> Who {
    Who::Agent { name: NAME.into() }
}

/// Seams over `source`: rule 3 reads the token for the agent's key from it, as the process
/// resolver does, and drops it; the index records 2027-02-15.
fn fake_seams(source: Arc<dyn AgentCredentialSource>) -> Seams<'static> {
    let for_resolve = source.clone();
    Seams {
        resolve: Box::new(move |_, env| {
            let key = AgentKey::new(
                AccountId::new("AFAKEOP0000000000000000001"),
                "shop",
                EnvName::new(env),
            )
            .unwrap();
            match for_resolve.resolve(&key)? {
                Some(_token) => Ok(NAME.to_string()),
                None => Err(Cause::AgentIdentityNotInstalled {
                    env: EnvName::new(env),
                }
                .into()),
            }
        }),
        source: Box::new(move || source.clone()),
        record: Box::new(|name, env| {
            Some(AgentRecord {
                account_name: name.into(),
                environment: env.into(),
                machine: "laptop".into(),
                store: "secret_service".into(),
                created_on: "2026-11-17".into(),
                expires_on: "2027-02-15".into(),
                rotation_successor: None,
            })
        }),
        today: Box::new(|| TODAY.to_string()),
        bound: Duration::from_secs(5),
    }
}

/// A fake store holding the agent's token for staging.
fn installed() -> Arc<FakeCredentialSource> {
    let source = FakeCredentialSource::new(AgentStore::SecretService);
    let key = AgentKey::new(
        AccountId::new("AFAKEOP0000000000000000001"),
        "shop",
        EnvName::new("staging"),
    )
    .unwrap();
    source
        .store(&key, &SecretValue::new(TOKEN.to_string()))
        .unwrap();
    Arc::new(source)
}

fn agent_host() -> Host {
    Host::from_env(
        &FakeEnv::new("linux")
            .shell("/bin/bash")
            .var_val("OPV_IDENTITY", "agent")
            .var_val("CLAUDECODE", "1"),
    )
}

#[test]
fn opv_identity_agent_resolves_the_environments_agent_identity() {
    let seams = fake_seams(installed());
    let who = before(&agent_host(), Some(&fleet()), Some("staging"), &seams);
    assert!(matches!(who, Who::Agent { name } if name == NAME));
}

#[test]
fn opv_identity_agent_with_nothing_installed_is_unavailable() {
    let seams = fake_seams(Arc::new(FakeCredentialSource::new(
        AgentStore::SecretService,
    )));
    let who = before(&agent_host(), Some(&fleet()), Some("staging"), &seams);
    assert!(
        matches!(who, Who::AgentUnavailable(e) if e.code_str() == "agent_identity_not_installed")
    );
}

#[test]
fn opv_identity_agent_without_an_environment_is_unscoped() {
    let seams = fake_seams(installed());
    let who = before(&agent_host(), Some(&fleet()), None, &seams);
    assert!(matches!(who, Who::AgentUnscoped));
}

#[test]
fn an_environment_token_wins_over_opv_identity_agent() {
    let host = Host::from_env(
        &FakeEnv::new("linux")
            .var("OP_SERVICE_ACCOUNT_TOKEN")
            .var_val("OPV_IDENTITY", "agent"),
    );
    let seams = fake_seams(installed());
    let who = before(&host, Some(&fleet()), Some("staging"), &seams);
    assert!(matches!(who, Who::EnvToken(OpCredential::ServiceAccount)));
}

#[test]
fn the_agents_reach_counts_the_environments_vaults_the_token_lists() {
    let r = FakeRunner::new(vec![
        Output::success(
            br#"[{"id":"vstg","name":"Staging"},{"id":"vother","name":"Other"}]"#.to_vec(),
        ),
        Output::success(RATE_OK.as_bytes().to_vec()),
    ]);
    let seams = fake_seams(installed());
    let facts = after(
        agent_who(),
        None,
        Some(&fleet()),
        Some("staging"),
        &r,
        &seams,
    );
    let expected = Reach {
        readable: 1,
        expected: 1,
    };
    assert!(matches!(facts, Facts::Agent(a) if a.reach == Some(expected)));
}

#[test]
fn a_failed_sign_in_makes_no_vault_or_ratelimit_call() {
    let r = FakeRunner::new(Vec::new());
    let seams = fake_seams(installed());
    let _ = after(
        agent_who(),
        Some(&rejected()),
        Some(&fleet()),
        Some("staging"),
        &r,
        &seams,
    );
    assert!(r.calls.borrow().is_empty());
}

// --- value-free: no token in text or JSON ---------------------------------------------------

/// Doctor's text and JSON for the identity row of an agent whose token is in the store.
fn rendered_agent() -> (String, String) {
    let seams = fake_seams(installed());
    let who = before(&agent_host(), Some(&fleet()), Some("staging"), &seams);
    let r = FakeRunner::new(vec![
        Output::success(br#"[{"id":"vstg","name":"Staging"}]"#.to_vec()),
        Output::success(RATE_OK.as_bytes().to_vec()),
    ]);
    let facts = after(who, None, Some(&fleet()), Some("staging"), &r, &seams);
    let mut report = super::super::Report::default();
    report.identity(row(facts, &ctx(Some("staging"), true)));
    let mut text = Vec::new();
    super::super::print_text(&report, &mut text, &mut Vec::new()).unwrap();
    let mut json = Vec::new();
    super::super::print_json(&report, None, &mut json).unwrap();
    (
        String::from_utf8(text).unwrap(),
        String::from_utf8(json).unwrap(),
    )
}

#[test]
fn the_agent_row_text_carries_no_token() {
    let (text, _) = rendered_agent();
    assert!(
        !text.contains("CANARYTOKEN") && !text.contains(MARKER),
        "{text}"
    );
}

#[test]
fn the_agent_row_json_carries_no_token() {
    let (_, json) = rendered_agent();
    assert!(
        !json.contains("CANARYTOKEN") && !json.contains(MARKER),
        "{json}"
    );
}

#[test]
fn the_agent_row_json_carries_the_identity_object() {
    let (_, json) = rendered_agent();
    let doc: serde_json::Value = serde_json::from_str(&json).unwrap();
    let mut id = doc["checks"][0]["identity"].clone();
    // Host-specific timing, normalized.
    id["store"]["self_check_ms"] = serde_json::Value::Null;
    assert_eq!(
        id,
        serde_json::json!({
            "kind": "agent",
            "name": NAME,
            "environment": "staging",
            "source": "secret_service",
            "read_only": true,
            "expires_on": "2027-02-15",
            "days_left": 90,
            "reach": {"readable": 1, "expected": 1},
            "rate_limit": {
                "hourly_used_pct": 0,
                "daily_account": {"limit": 1000, "used": 8, "remaining": 992},
            },
            "store": {"persistence": "durable", "self_check": "ok", "self_check_ms": null},
            "state": "agent",
        })
    );
}

#[test]
fn the_agent_row_json_check_carries_its_name_and_state() {
    let (_, json) = rendered_agent();
    let doc: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        (&doc["checks"][0]["name"], &doc["checks"][0]["state"]),
        (&serde_json::json!(ROW), &serde_json::json!("agent"))
    );
}

// --- the whole doctor run ---------------------------------------------------------------------

/// Unscoped `opv doctor` on a Linux host whose environment holds a service-account token
/// (its value a canary) and an assistant marker; `json` prints the document.
fn doctor_with_env_token(json: bool) -> String {
    const WHOAMI: &str = r#"{"url":"https://my.1password.com","user_type":"SERVICE_ACCOUNT"}"#;
    let host = Host::from_env(
        &FakeEnv::new("linux")
            .shell("/bin/bash")
            .var_val("OP_SERVICE_ACCOUNT_TOKEN", TOKEN)
            .var_val("CLAUDECODE", "1"),
    );
    let r = FakeRunner::new(vec![
        Output::success(b"2.40.0\n".to_vec()),
        Output::success(WHOAMI.as_bytes().to_vec()),
        Output::success(b"flyctl v0.4.112 linux/amd64 Commit: ca63052e BuildDate: x\n".to_vec()),
        Output::success(b"ops@example.com\n".to_vec()),
    ]);
    let scope = super::super::Scope {
        json,
        ..super::super::Scope::default()
    };
    let mut out = Vec::new();
    let _ = super::super::run_on(Ok(fleet()), &r, &|| host, scope, &mut out);
    String::from_utf8(out).unwrap()
}

#[test]
fn doctor_warns_on_an_env_token_beside_an_assistant_marker() {
    let out = doctor_with_env_token(false);
    assert!(
        out.lines()
            .any(|l| l.starts_with("warn  op identity: OP_SERVICE_ACCOUNT_TOKEN is in")),
        "{out}"
    );
}

#[test]
fn doctor_text_never_prints_the_env_token() {
    let out = doctor_with_env_token(false);
    assert!(!out.contains("CANARYTOKEN"), "{out}");
}

#[test]
fn doctor_json_never_prints_the_env_token() {
    let out = doctor_with_env_token(true);
    assert!(!out.contains("CANARYTOKEN"), "{out}");
}

#[test]
fn doctor_json_names_the_env_token_state() {
    let doc: serde_json::Value = serde_json::from_str(&doctor_with_env_token(true)).unwrap();
    let state = doc["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == ROW)
        .map(|c| c["state"].clone());
    assert_eq!(state, Some(serde_json::json!("token_in_agent_env")));
}
