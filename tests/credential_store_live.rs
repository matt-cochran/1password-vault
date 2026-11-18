//! The agent identity's OS credential store, against the real store of this machine (#338,
//! design agent-identity §4.4, spike S1). Never runs by default: set `OPV_LIVE_STORE_TEST=1`.
//!
//! Only a fixed dummy is ever stored, never a token, and every test deletes its entry.
//!
//! Optional, for CI:
//! - `OPV_LIVE_STORE_EXPECT=<store>` (`macos_keychain`, `windows_credential_manager`,
//!   `secret_service`, `kernel_keyring`): the store this machine must detect.
//! - `OPV_LIVE_STORE_LOCKED=1`: the store is a locked Secret Service collection; only the
//!   locked-store test runs, and it must fail as `agent_store_locked` within the bound.

use std::time::{Duration, Instant};

use opv::adapters::credential_store::{
    AgentCredentialSource, AgentKey, OsCredentialStore, READ_TIMEOUT,
};
use opv::cause::{AccountId, EnvName};
use opv::domain::secret::SecretValue;

/// The only value these tests store.
const DUMMY: &str = "opv-live-store-dummy-not-a-secret";

fn enabled() -> bool {
    std::env::var("OPV_LIVE_STORE_TEST").as_deref() == Ok("1")
}

fn locked_case() -> bool {
    std::env::var("OPV_LIVE_STORE_LOCKED").as_deref() == Ok("1")
}

/// A key no real identity uses: the test's name and this process.
fn key(test: &str) -> AgentKey {
    AgentKey::new(
        AccountId::new("opv-live-test"),
        format!("{test}-{}", std::process::id()),
        EnvName::new("dummy"),
    )
    .expect("a valid key")
}

/// Deletes the entry when the test ends, pass or fail.
struct Cleanup<'a>(&'a OsCredentialStore, AgentKey);

impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        let _ = self.0.delete(&self.1);
    }
}

#[test]
fn dummy_round_trips_through_the_real_store() {
    if !enabled() || locked_case() {
        return;
    }
    let store = OsCredentialStore::detect();
    let k = key("round-trip");
    let _cleanup = Cleanup(&store, k.clone());
    store
        .store(&k, &SecretValue::new(DUMMY.into()))
        .expect("the store accepts the dummy");
    let got = store.resolve(&k).expect("the store answers");
    assert_eq!(got.as_ref().map(SecretValue::expose), Some(DUMMY));
}

#[test]
fn deleted_entry_reads_as_absent() {
    if !enabled() || locked_case() {
        return;
    }
    let store = OsCredentialStore::detect();
    let k = key("delete");
    let _cleanup = Cleanup(&store, k.clone());
    store
        .store(&k, &SecretValue::new(DUMMY.into()))
        .expect("the store accepts the dummy");
    store.delete(&k).expect("the store deletes");
    assert!(store.resolve(&k).expect("the store answers").is_none());
}

#[test]
fn machine_detects_the_expected_store() {
    let Ok(expected) = std::env::var("OPV_LIVE_STORE_EXPECT") else {
        return;
    };
    if !enabled() {
        return;
    }
    let store = OsCredentialStore::detect().describe().store;
    let got = serde_json::to_value(store).expect("a store name");
    assert_eq!(got.as_str(), Some(expected.as_str()));
}

#[test]
fn locked_store_fails_as_agent_store_locked_within_the_bound() {
    if !enabled() || !locked_case() {
        return;
    }
    let store = OsCredentialStore::detect();
    let started = Instant::now();
    let code = store
        .resolve(&key("locked"))
        .map(|_| ())
        .map_err(|e| e.cause().map(|(c, _)| c.code()));
    let fast = started.elapsed() < READ_TIMEOUT + Duration::from_secs(1);
    assert_eq!((code, fast), (Err(Some("agent_store_locked")), true));
}
