//! The agent credential source (design agent-identity §4.2.1, §4.4): the contract through the
//! fake, the bounds, the cause mapping, and the no-value canaries (ADR-0001).

use std::time::Duration;

use super::bounded::on_worker;
use super::*;
use crate::cause::{AccountId, AgentStore, EnvName};
use crate::domain::secret::SecretValue;

/// The only value these tests store: a fixed dummy, never a token.
const DUMMY: &str = "opv-store-dummy-not-a-secret-7Qx";

fn key(env: &str) -> AgentKey {
    AgentKey::new(AccountId::new("ACCT123"), "shop", EnvName::new(env)).expect("a valid key")
}

/// The catalog code of a store error.
fn code(err: &crate::error::Error) -> &'static str {
    err.cause().map(|(c, _)| c.code()).unwrap_or("none")
}

fn dummy() -> SecretValue {
    SecretValue::new(DUMMY.to_owned())
}

fn fake_with_dummy() -> FakeCredentialSource {
    let fake = FakeCredentialSource::new(AgentStore::MacosKeychain);
    fake.store(&key("dev"), &dummy()).expect("the fake stores");
    fake
}

// --- the key ---------------------------------------------------------------------------------

#[test]
fn key_user_name_is_account_project_env() {
    assert_eq!(key("dev").user(), "ACCT123/shop/dev");
}

#[test]
fn key_with_a_slash_in_a_part_is_refused() {
    assert!(AgentKey::new(AccountId::new("ACCT123"), "shop/x", EnvName::new("dev")).is_none());
}

#[test]
fn key_with_a_newline_in_a_part_is_refused() {
    assert!(AgentKey::new(AccountId::new("ACCT123"), "shop", EnvName::new("dev\nget")).is_none());
}

#[test]
fn key_with_an_empty_part_is_refused() {
    assert!(AgentKey::new(AccountId::new(""), "shop", EnvName::new("dev")).is_none());
}

// --- the contract, through the fake ------------------------------------------------------------

#[test]
fn resolve_returns_the_stored_value() {
    let fake = fake_with_dummy();
    let got = fake.resolve(&key("dev")).unwrap().expect("an entry");
    assert_eq!(got.expose(), DUMMY);
}

#[test]
fn resolve_of_a_key_never_stored_is_none() {
    let fake = fake_with_dummy();
    assert!(fake.resolve(&key("prod")).unwrap().is_none());
}

#[test]
fn store_replaces_the_existing_entry() {
    let fake = fake_with_dummy();
    fake.store(
        &key("dev"),
        &SecretValue::new("opv-store-dummy-second".into()),
    )
    .unwrap();
    let got = fake.resolve(&key("dev")).unwrap().expect("an entry");
    assert_eq!(got.expose(), "opv-store-dummy-second");
}

#[test]
fn delete_leaves_no_entry_behind() {
    let fake = fake_with_dummy();
    fake.delete(&key("dev")).unwrap();
    assert!(fake.resolve(&key("dev")).unwrap().is_none());
}

#[test]
fn delete_of_a_key_never_stored_reports_false() {
    let fake = fake_with_dummy();
    assert!(!fake.delete(&key("prod")).unwrap());
}

#[test]
fn locked_store_resolves_as_agent_store_locked() {
    let fake = fake_with_dummy();
    fake.set_fault(Some(FakeFault::Locked));
    let err = fake.resolve(&key("dev")).unwrap_err();
    assert_eq!(code(&err), "agent_store_locked");
}

#[test]
fn missing_store_preflights_as_agent_store_unavailable() {
    let fake = FakeCredentialSource::new(AgentStore::SecretService);
    fake.set_fault(Some(FakeFault::Unavailable));
    let err = fake.preflight().unwrap_err();
    assert_eq!(code(&err), "agent_store_unavailable");
}

#[test]
fn kernel_keyring_fallback_reports_agent_store_volatile() {
    let fake = FakeCredentialSource::volatile();
    let cause = fake.describe().volatile_cause(Some(EnvName::new("dev")));
    assert_eq!(cause.map(|c| c.code()), Some("agent_store_volatile"));
}

#[test]
fn durable_store_reports_no_volatile_cause() {
    let fake = FakeCredentialSource::new(AgentStore::WindowsCredentialManager);
    assert!(fake.describe().volatile_cause(None).is_none());
}

#[test]
fn resolved_value_is_registered_with_the_scrubber() {
    let fake = fake_with_dummy();
    crate::scrub::reset_test_registry();
    let _got = fake.resolve(&key("dev")).unwrap();
    assert!(!crate::scrub::scrub(&format!("x {DUMMY} y")).contains(DUMMY));
}

// --- the OS store's own behaviour, without a platform store -----------------------------------

#[test]
fn machine_with_no_store_resolves_as_agent_store_unavailable() {
    let none = OsCredentialStore::with_backend(Backend::None(AgentStore::SecretService));
    let err = none.resolve(&key("dev")).unwrap_err();
    assert_eq!(code(&err), "agent_store_unavailable");
}

#[test]
fn machine_with_no_store_refuses_to_store_anywhere() {
    let none = OsCredentialStore::with_backend(Backend::None(AgentStore::SecretService));
    let err = none.store(&key("dev"), &dummy()).unwrap_err();
    assert_eq!(code(&err), "agent_store_unavailable");
}

#[test]
fn call_that_outlives_its_bound_times_out() {
    let r = on_worker(Duration::from_millis(50), || {
        std::thread::sleep(Duration::from_secs(2));
        Ok(())
    });
    assert_eq!(r, Err(StoreFailure::TimedOut));
}

#[test]
fn timed_out_call_reports_agent_store_locked() {
    let store = OsCredentialStore::with_backend(Backend::None(AgentStore::SecretService));
    let err = store
        .guarded(|| Err::<(), _>(StoreFailure::TimedOut))
        .unwrap_err();
    assert_eq!(code(&err), "agent_store_locked");
}

#[test]
fn store_that_stalled_once_fails_every_later_call_as_locked() {
    let store = OsCredentialStore::with_backend(Backend::None(AgentStore::SecretService));
    let _ = store.guarded(|| Err::<(), _>(StoreFailure::TimedOut));
    let err = store.guarded(|| Ok(())).unwrap_err();
    assert_eq!(code(&err), "agent_store_locked");
}

#[test]
fn locked_store_does_not_stall_later_calls() {
    let store = OsCredentialStore::with_backend(Backend::None(AgentStore::SecretService));
    let _ = store.guarded(|| Err::<(), _>(StoreFailure::Locked));
    assert!(store.guarded(|| Ok(())).is_ok());
}

#[test]
fn default_read_bound_is_five_seconds() {
    assert_eq!(READ_TIMEOUT, Duration::from_secs(5));
}

#[cfg(target_os = "linux")]
#[test]
fn child_that_outlives_its_bound_is_killed_as_timed_out() {
    let mut cmd = std::process::Command::new("sleep");
    cmd.arg("5");
    let r = bounded::run_child(cmd, b"", Duration::from_millis(100)).map(|o| o.code);
    assert_eq!(r, Err(StoreFailure::TimedOut));
}

#[cfg(target_os = "linux")]
#[test]
fn child_receives_its_input_on_stdin_only() {
    let out = bounded::run_child(
        std::process::Command::new("cat"),
        DUMMY.as_bytes(),
        Duration::from_secs(5),
    )
    .expect("cat runs");
    assert_eq!(out.stdout.as_slice(), DUMMY.as_bytes());
}

#[cfg(target_os = "linux")]
#[test]
fn wsl_script_is_passed_as_the_fixed_text() {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(wsl::encoded_script())
        .unwrap();
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    assert_eq!(
        String::from_utf16(&units).unwrap(),
        include_str!("credential_store/wsl_vault.ps1")
    );
}

// --- no-value canaries (ADR-0001 R1) ----------------------------------------------------------

#[test]
fn resolved_value_never_renders_the_dummy() {
    let got = fake_with_dummy().resolve(&key("dev")).unwrap();
    let text = format!("{got:?} {got:#?} {}", got.as_ref().unwrap());
    assert!(!text.contains(DUMMY), "leaked: {text}");
}

#[test]
fn source_holding_the_dummy_never_renders_it() {
    let fake = fake_with_dummy();
    let text = format!("{fake:?} {fake:#?}");
    assert!(!text.contains(DUMMY), "leaked: {text}");
}

#[test]
fn os_store_never_renders_a_value() {
    let store = OsCredentialStore::detect();
    let text = format!("{store:?} {:?}", store.describe());
    assert!(!text.contains(DUMMY), "leaked: {text}");
}

#[test]
fn store_errors_never_render_the_dummy() {
    let fake = fake_with_dummy();
    let mut text = String::new();
    for fault in [FakeFault::Locked, FakeFault::Unavailable] {
        fake.set_fault(Some(fault));
        let err = fake.resolve(&key("dev")).unwrap_err();
        let message = err.cause().map(|(c, _)| c.message()).unwrap_or_default();
        text.push_str(&format!("{err:?} {err} {message}"));
    }
    let volatile = FakeCredentialSource::volatile()
        .describe()
        .volatile_cause(Some(EnvName::new("dev")))
        .unwrap();
    text.push_str(&format!("{volatile:?} {}", volatile.message()));
    assert!(!text.contains(DUMMY), "leaked: {text}");
}
