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

// --- store selection (WSL interop down, OPV_AGENT_STORE) -----------------------------------

/// Selection over fixed probe answers: `wsl` is the interop preflight (`None` off WSL).
fn selected(
    wsl: Option<Result<(), StoreFailure>>,
    secret_service: Result<(), StoreFailure>,
) -> Selection {
    let preflight = move || wsl.unwrap_or(Ok(()));
    let ss = move || secret_service;
    select_linux(&Probes {
        wsl: wsl
            .is_some()
            .then_some(&preflight as &dyn Fn() -> Result<(), StoreFailure>),
        secret_service: &ss,
    })
}

#[test]
fn wsl_with_answering_interop_keeps_windows_credential_manager() {
    assert_eq!(
        selected(Some(Ok(())), Ok(())),
        Selection {
            store: AgentStore::WindowsCredentialManager,
            reason: StoreReason::Platform,
        }
    );
}

#[test]
fn wsl_interop_down_falls_back_to_an_unlocked_secret_service() {
    assert_eq!(
        selected(Some(Err(StoreFailure::InteropDown)), Ok(())),
        Selection {
            store: AgentStore::SecretService,
            reason: StoreReason::WslInteropDown,
        }
    );
}

#[test]
fn wsl_interop_down_without_a_secret_service_falls_back_to_the_kernel_keyring() {
    assert_eq!(
        selected(
            Some(Err(StoreFailure::InteropDown)),
            Err(StoreFailure::Unavailable)
        ),
        Selection {
            store: AgentStore::KernelKeyring,
            reason: StoreReason::WslInteropDown,
        }
    );
}

#[test]
fn wsl_interop_down_with_a_locked_secret_service_falls_back_to_the_kernel_keyring() {
    let s = selected(
        Some(Err(StoreFailure::InteropDown)),
        Err(StoreFailure::Locked),
    );
    assert_eq!(s.store, AgentStore::KernelKeyring);
}

#[test]
fn wsl_interop_that_times_out_falls_back_as_interop_down() {
    let s = selected(
        Some(Err(StoreFailure::TimedOut)),
        Err(StoreFailure::Unavailable),
    );
    assert_eq!(s.reason, StoreReason::WslInteropDown);
}

#[test]
fn wsl_credential_manager_failing_behind_working_interop_says_so() {
    let s = selected(Some(Err(StoreFailure::Unavailable)), Ok(()));
    assert_eq!(s.reason, StoreReason::CredentialManagerUnusable);
}

#[test]
fn linux_keeps_a_locked_secret_service_so_it_fails_as_locked() {
    assert_eq!(
        selected(None, Err(StoreFailure::Locked)),
        Selection {
            store: AgentStore::SecretService,
            reason: StoreReason::Platform,
        }
    );
}

#[test]
fn linux_without_a_secret_service_uses_the_kernel_keyring() {
    assert_eq!(
        selected(None, Err(StoreFailure::Unavailable)),
        Selection {
            store: AgentStore::KernelKeyring,
            reason: StoreReason::NoSecretService,
        }
    );
}

#[cfg(target_os = "linux")]
#[test]
fn wsl_kernel_keyring_fallback_is_declared_volatile() {
    let store = OsCredentialStore::opened(selected(
        Some(Err(StoreFailure::InteropDown)),
        Err(StoreFailure::Unavailable),
    ));
    let cause = store.describe().volatile_cause(Some(EnvName::new("dev")));
    assert_eq!(cause.map(|c| c.code()), Some("agent_store_volatile"));
}

#[cfg(target_os = "linux")]
#[test]
fn override_names_the_store_without_probing_interop() {
    let d = OsCredentialStore::select(Some(AgentStore::KernelKeyring)).describe();
    assert_eq!(
        (d.store, d.reason),
        (AgentStore::KernelKeyring, StoreReason::Override)
    );
}

#[test]
fn override_wincred_names_windows_credential_manager() {
    assert_eq!(
        parse_store_override(Some("wincred")).unwrap(),
        Some(AgentStore::WindowsCredentialManager)
    );
}

#[test]
fn override_secret_service_names_the_secret_service() {
    assert_eq!(
        parse_store_override(Some("secret-service")).unwrap(),
        Some(AgentStore::SecretService)
    );
}

#[test]
fn override_kernel_keyring_names_the_kernel_keyring() {
    assert_eq!(
        parse_store_override(Some("kernel-keyring")).unwrap(),
        Some(AgentStore::KernelKeyring)
    );
}

#[test]
fn empty_override_chooses_nothing() {
    assert_eq!(parse_store_override(Some("")).unwrap(), None);
}

#[test]
fn unknown_override_is_refused_as_usage() {
    let err = parse_store_override(Some("keychain")).unwrap_err();
    assert_eq!(code(&err), "usage");
}

#[test]
fn unknown_override_refusal_names_the_variable_and_its_values() {
    let err = parse_store_override(Some("keychain")).unwrap_err();
    assert!(
        err.to_string()
            .contains("OPV_AGENT_STORE expects wincred, secret-service or kernel-keyring"),
        "{err}"
    );
}

#[test]
fn store_reason_round_trips_through_its_index_id() {
    let all = [
        StoreReason::Platform,
        StoreReason::Override,
        StoreReason::WslInteropDown,
        StoreReason::CredentialManagerUnusable,
        StoreReason::NoSecretService,
    ];
    assert!(all.iter().all(|r| StoreReason::from_id(Some(r.id())) == *r));
}

// --- WSL interop failures, through a stand-in for powershell.exe ---------------------------

#[cfg(target_os = "linux")]
fn wsl_store(program: &str) -> OsCredentialStore {
    OsCredentialStore::with_backend(Backend::Wsl(wsl::WslVault::with_program(program.into())))
}

/// A stand-in program that exits with `code`, as a script file in `dir`.
#[cfg(target_os = "linux")]
fn exiting_with(dir: &tempfile::TempDir, code: i32) -> String {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.path().join(format!("exit-{code}"));
    std::fs::write(&path, format!("#!/bin/sh\ncat >/dev/null\nexit {code}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path.to_string_lossy().into_owned()
}

#[cfg(target_os = "linux")]
#[test]
fn wsl_shim_failing_like_a_vsock_error_reads_as_interop_down() {
    // The WSL shim exits 1 when its vsock accept fails; the script never exits 1.
    let dir = tempfile::tempdir().unwrap();
    let err = wsl_store(&exiting_with(&dir, 1))
        .resolve(&key("dev"))
        .unwrap_err();
    assert_eq!(code(&err), "agent_store_interop_down");
}

#[cfg(target_os = "linux")]
#[test]
fn wsl_interop_that_will_not_start_reads_as_interop_down() {
    let err = wsl_store("/nonexistent/opv-test/powershell.exe")
        .preflight()
        .unwrap_err();
    assert_eq!(code(&err), "agent_store_interop_down");
}

#[cfg(target_os = "linux")]
#[test]
fn wsl_interop_down_is_never_reported_as_locked() {
    let dir = tempfile::tempdir().unwrap();
    let err = wsl_store(&exiting_with(&dir, 1))
        .store(&key("dev"), &dummy())
        .unwrap_err();
    assert_ne!(code(&err), "agent_store_locked");
}

#[cfg(target_os = "linux")]
#[test]
fn credential_manager_failure_behind_working_interop_reads_as_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let err = wsl_store(&exiting_with(&dir, 4))
        .resolve(&key("dev"))
        .unwrap_err();
    assert_eq!(code(&err), "agent_store_unavailable");
}

#[cfg(target_os = "linux")]
#[test]
fn wsl_interop_down_does_not_stall_later_calls() {
    let dir = tempfile::tempdir().unwrap();
    let store = wsl_store(&exiting_with(&dir, 1));
    let _ = store.resolve(&key("dev"));
    assert!(!store.stalled.load(Ordering::SeqCst));
}

#[test]
fn interop_down_fake_reports_agent_store_interop_down() {
    let fake = FakeCredentialSource::new(AgentStore::WindowsCredentialManager);
    fake.set_fault(Some(FakeFault::InteropDown));
    let err = fake.resolve(&key("dev")).unwrap_err();
    assert_eq!(code(&err), "agent_store_interop_down");
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
