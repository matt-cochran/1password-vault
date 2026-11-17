//! Identity selection, rules 1-5 (#338; design `agent-identity.md` §5, vet R4).

use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::adapters::credential_store::{
    AgentCredentialSource, AgentKey, FakeCredentialSource, SourceDescription,
};
use crate::cause::{AccountId, AgentStore, EnvName};
use crate::host::{FakeEnv, Host};
use crate::runner::fake::FakeRunner;

const CANARY: &str = "ops_CANARY-agent-token-7f3a9c";

/// A store that counts its reads, over the fake.
struct Counting {
    inner: FakeCredentialSource,
    reads: AtomicUsize,
}

impl AgentCredentialSource for Counting {
    fn describe(&self) -> SourceDescription {
        self.inner.describe()
    }
    fn preflight(&self) -> Result<SourceDescription, Error> {
        self.inner.preflight()
    }
    fn resolve(&self, key: &AgentKey) -> Result<Option<SecretValue>, Error> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.inner.resolve(key)
    }
    fn store(&self, key: &AgentKey, value: &SecretValue) -> Result<(), Error> {
        self.inner.store(key, value)
    }
    fn delete(&self, key: &AgentKey) -> Result<bool, Error> {
        self.inner.delete(key)
    }
}

fn key(env: &str) -> AgentKey {
    AgentKey::new(AccountId::new("ACCT123"), "shop", EnvName::new(env)).unwrap()
}

fn target(env: &str) -> Result<AgentTarget, Error> {
    Ok(AgentTarget {
        key: key(env),
        name: format!("shop-{env}-agent-laptop"),
    })
}

/// A store holding the canary token for `dev` only.
fn installed() -> Counting {
    let inner = FakeCredentialSource::new(AgentStore::SecretService);
    inner
        .store(&key("dev"), &SecretValue::new(CANARY.to_string()))
        .unwrap();
    Counting {
        inner,
        reads: AtomicUsize::new(0),
    }
}

fn empty() -> Counting {
    Counting {
        inner: FakeCredentialSource::new(AgentStore::SecretService),
        reads: AtomicUsize::new(0),
    }
}

fn env_with(identity: &str) -> FakeEnv {
    FakeEnv::new("linux")
        .shell("/bin/bash")
        .var_val(VAR, identity)
}

fn agent_host() -> Host {
    Host::from_env(&env_with("agent"))
}

#[test]
fn rule_1_an_env_service_account_token_wins_over_opv_identity_agent() {
    let env = env_with("agent").var_val("OP_SERVICE_ACCOUNT_TOKEN", "dummy");
    let resolver = Resolver::new();
    let resolved = resolver.resolve(&env, &installed(), || target("dev"));
    assert_eq!(
        resolved.unwrap().op_credential(),
        Some(OpCredential::ServiceAccount)
    );
}

#[test]
fn rule_2_opv_identity_person_uses_the_persons_session() {
    let resolver = Resolver::new();
    let resolved = resolver.resolve(&env_with("person"), &installed(), || target("dev"));
    assert!(matches!(resolved.unwrap(), Resolved::Person));
}

#[test]
fn rule_3_opv_identity_agent_uses_the_installed_agent_identity_of_the_environment() {
    let resolver = Resolver::new();
    let resolved = resolver.resolve(&env_with("agent"), &installed(), || target("dev"));
    assert_eq!(
        resolved.unwrap().agent().map(AgentIdentity::name),
        Some("shop-dev-agent-laptop")
    );
}

#[test]
fn rule_3_hands_the_runner_the_stored_token() {
    let resolver = Resolver::new();
    let resolved = resolver
        .resolve(&env_with("agent"), &installed(), || target("dev"))
        .unwrap();
    assert_eq!(resolved.agent().map(|a| a.token().expose()), Some(CANARY));
}

#[test]
fn no_variable_and_no_token_is_the_persons_session() {
    let env = FakeEnv::new("linux").shell("/bin/bash");
    let resolver = Resolver::new();
    let resolved = resolver.resolve(&env, &installed(), || target("dev"));
    assert!(matches!(resolved.unwrap(), Resolved::Person));
}

#[test]
fn an_environment_without_an_agent_identity_stops_with_agent_identity_not_installed() {
    let err = Resolver::new()
        .resolve(&env_with("agent"), &installed(), || target("prod"))
        .unwrap_err();
    assert_eq!(err.code_str(), "agent_identity_not_installed");
}

#[test]
fn a_missing_agent_identity_never_falls_back_to_the_persons_session() {
    let resolver = Resolver::new();
    let _ = resolver.resolve(&env_with("agent"), &empty(), || target("dev"));
    assert!(resolver.get().is_none(), "{:?}", resolver.get());
}

#[test]
fn the_identity_is_read_from_the_store_once_per_process() {
    let resolver = Resolver::new();
    let store = installed();
    for _ in 0..3 {
        resolver
            .resolve(&env_with("agent"), &store, || target("dev"))
            .unwrap();
    }
    assert_eq!(store.reads.load(Ordering::SeqCst), 1);
}

#[test]
fn a_process_never_switches_to_a_second_agent_identity() {
    let resolver = Resolver::new();
    let store = installed();
    resolver
        .resolve(&env_with("agent"), &store, || target("dev"))
        .unwrap();
    let err = resolver
        .resolve(&env_with("agent"), &store, || target("prod"))
        .unwrap_err();
    assert_eq!(err.code_str(), "internal_error");
}

#[test]
fn an_unknown_opv_identity_value_is_refused_as_usage() {
    let err = Resolver::new()
        .resolve(&env_with("robot"), &installed(), || target("dev"))
        .unwrap_err();
    assert_eq!(err.code_str(), "usage");
}

#[test]
fn the_host_reports_the_agent_credential_under_opv_identity_agent() {
    assert_eq!(agent_host().op_credential, Some(OpCredential::Agent));
}

#[test]
fn the_host_treats_an_unknown_opv_identity_value_as_the_agent() {
    let host = Host::from_env(&env_with("robot"));
    assert_eq!(host.op_credential, Some(OpCredential::Agent));
}

#[test]
fn the_host_keeps_the_persons_session_under_opv_identity_person() {
    let host = Host::from_env(&env_with("person"));
    assert_eq!(host.op_credential, None);
}

#[test]
fn a_person_only_command_is_refused_with_own_session_required_under_the_agent() {
    let err =
        crate::app::tidy::require_person_on(&FakeRunner::default(), "opv import", agent_host())
            .unwrap_err();
    assert_eq!(err.code_str(), "own_session_required");
}

#[test]
fn the_agent_host_offers_no_person_sign_in() {
    assert_eq!(agent_host().signin_command(Some("dev")), None);
}

#[test]
fn the_agent_identity_debug_never_shows_the_token() {
    let resolver = Resolver::new();
    let resolved = resolver
        .resolve(&env_with("agent"), &installed(), || target("dev"))
        .unwrap();
    assert!(!format!("{resolved:?}").contains(CANARY));
}

#[test]
fn the_agent_identity_display_never_shows_the_token() {
    let resolver = Resolver::new();
    let resolved = resolver
        .resolve(&env_with("agent"), &installed(), || target("dev"))
        .unwrap();
    let shown = resolved
        .agent()
        .map(ToString::to_string)
        .unwrap_or_default();
    assert!(!shown.contains(CANARY), "{shown}");
}

#[test]
fn the_agent_host_debug_never_shows_the_token() {
    let resolver = Resolver::new();
    resolver
        .resolve(&env_with("agent"), &installed(), || target("dev"))
        .unwrap();
    assert!(!format!("{:?}", agent_host()).contains(CANARY));
}

#[test]
fn the_agent_token_is_never_put_into_the_process_environment() {
    let resolver = Resolver::new();
    resolver
        .resolve(&env_with("agent"), &installed(), || target("dev"))
        .unwrap();
    assert!(
        !std::env::vars_os().any(|(_, v)| v.to_string_lossy().contains(CANARY)),
        "the token is in opv's environment"
    );
}

// --- rule 4: agent mode with an agent identity installed for the project (S17) ---

/// An assistant's shell (`CLAUDECODE=1`), no `OPV_IDENTITY`, with an identity installed.
fn auto_env() -> FakeEnv {
    FakeEnv::new("linux")
        .shell("/bin/bash")
        .var_val("CLAUDECODE", "1")
        .agent_installed()
}

fn index_of(projects: &[&str]) -> crate::app::agent_identity::Index {
    use crate::app::agent_identity::{Index, IndexEntry};
    use crate::domain::agent_identity::AgentRecord;
    Index {
        identities: projects
            .iter()
            .map(|p| IndexEntry {
                project: (*p).into(),
                account_id: "ACCT123".into(),
                record: AgentRecord {
                    account_name: format!("{p}-dev-agent-laptop"),
                    environment: "dev".into(),
                    machine: "laptop".into(),
                    store: "secret_service".into(),
                    created_on: "2026-11-17".into(),
                    expires_on: "2027-02-15".into(),
                    rotation_successor: None,
                },
            })
            .collect(),
    }
}

#[test]
fn rule_4_a_marker_with_an_installed_identity_chooses_the_agent() {
    assert_eq!(choose(&auto_env()).unwrap(), Choice::Agent);
}

#[test]
fn rule_4_uses_the_installed_agent_identity_of_the_environment() {
    let (env, resolver) = (auto_env(), Resolver::new());
    let resolved = resolver
        .resolve(&env, &installed(), || target("dev"))
        .unwrap();
    assert_eq!(resolved.agent().map(|a| a.token().expose()), Some(CANARY));
}

#[test]
fn rule_4_an_environment_without_its_own_identity_stops_with_agent_identity_not_installed() {
    let err = Resolver::new()
        .resolve(&auto_env(), &installed(), || target("prod"))
        .unwrap_err();
    assert_eq!(err.code_str(), "agent_identity_not_installed");
}

#[test]
fn rule_4_never_falls_back_to_the_persons_session() {
    let resolver = Resolver::new();
    let _ = resolver.resolve(&auto_env(), &installed(), || target("prod"));
    assert!(resolver.get().is_none(), "{:?}", resolver.get());
}

#[test]
fn a_marker_with_nothing_installed_is_the_persons_session() {
    let env = FakeEnv::new("linux").var_val("CLAUDECODE", "1");
    assert_eq!(choose(&env).unwrap(), Choice::Person);
}

#[test]
fn an_installed_identity_without_a_marker_is_the_persons_session() {
    let env = FakeEnv::new("linux").agent_installed();
    assert_eq!(choose(&env).unwrap(), Choice::Person);
}

#[test]
fn opv_identity_person_overrides_rule_4() {
    let env = auto_env().var_val(VAR, "person");
    assert_eq!(choose(&env).unwrap(), Choice::Person);
}

#[test]
fn an_env_token_wins_over_rule_4() {
    let env = auto_env().var_val("OP_SERVICE_ACCOUNT_TOKEN", "dummy");
    assert_eq!(
        choose(&env).unwrap(),
        Choice::EnvToken(OpCredential::ServiceAccount)
    );
}

#[test]
fn the_host_reports_the_agent_credential_under_rule_4() {
    let host = Host::from_env(&auto_env());
    assert_eq!(host.op_credential, Some(OpCredential::Agent));
}

#[test]
fn a_person_only_command_is_refused_under_rule_4() {
    let host = Host::from_env(&auto_env());
    let err = crate::app::tidy::refuse_agent_on("opv set", host).unwrap_err();
    assert_eq!(err.code_str(), "own_session_required");
}

#[test]
fn the_index_installs_rule_4_for_a_project_it_records() {
    assert!(installed_for(&index_of(&["other", "shop"]), "shop"));
}

#[test]
fn the_index_leaves_rule_4_off_for_a_project_it_does_not_record() {
    assert!(!installed_for(&index_of(&["other"]), "shop"));
}
