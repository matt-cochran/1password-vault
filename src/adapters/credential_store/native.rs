//! The platform stores reached through `keyring-core` (spike S1 §4): the macOS login
//! keychain, Windows Credential Manager (generic credentials, local persistence) and, on
//! Linux, a Secret Service collection after a no-prompt lock check.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use keyring_core::{CredentialStore, Entry, Error};
use zeroize::Zeroizing;

use super::bounded::on_worker;
use super::{SERVICE, StoreFailure};
use crate::cause::AgentStore;
use crate::domain::secret::SecretValue;

/// The entry that answers the availability check. It is only ever read, never written.
const PREFLIGHT_USER: &str = "opv-preflight";

pub(super) struct NativeStore {
    store: AgentStore,
    inner: Arc<CredentialStore>,
}

impl NativeStore {
    pub(super) fn store(&self) -> AgentStore {
        self.store
    }

    #[cfg(target_os = "macos")]
    pub(super) fn keychain() -> Result<Self, StoreFailure> {
        let inner = apple_native_keyring_store::keychain::Store::new()
            .map_err(|_| StoreFailure::Unavailable)?;
        Ok(Self {
            store: AgentStore::MacosKeychain,
            inner,
        })
    }

    #[cfg(windows)]
    pub(super) fn credential_manager() -> Result<Self, StoreFailure> {
        let inner =
            windows_native_keyring_store::Store::new().map_err(|_| StoreFailure::Unavailable)?;
        Ok(Self {
            store: AgentStore::WindowsCredentialManager,
            inner,
        })
    }

    /// A Secret Service on the session bus, connected within `timeout` (D-Bus activation of
    /// a provider may start one, which never prompts by itself).
    #[cfg(target_os = "linux")]
    pub(super) fn secret_service(timeout: Duration) -> Result<Self, StoreFailure> {
        let inner = on_worker(timeout, || {
            let store = zbus_secret_service_keyring_store::Store::new()
                .map_err(|_| StoreFailure::Unavailable)?;
            Ok::<Arc<CredentialStore>, _>(store)
        })?;
        Ok(Self {
            store: AgentStore::SecretService,
            inner,
        })
    }

    fn entry(&self, user: &str) -> Result<Entry, StoreFailure> {
        // Windows: local persistence, so the token never roams with a profile to another
        // machine (one identity per machine, D1).
        #[cfg(windows)]
        let mods = Some(HashMap::from([("persistence", "Local")]));
        #[cfg(not(windows))]
        let mods: Option<HashMap<&str, &str>> = None;
        self.inner
            .build(SERVICE, user, mods.as_ref())
            .map_err(|_| StoreFailure::Unavailable)
    }

    /// Run `f` on `entry` on a bounded worker, with the platform's no-prompt guard.
    fn call<T, F>(&self, user: &str, timeout: Duration, f: F) -> Result<T, StoreFailure>
    where
        T: Send + 'static,
        F: FnOnce(&Entry) -> Result<T, StoreFailure> + Send + 'static,
    {
        let entry = self.entry(user)?;
        let store = self.store;
        on_worker(timeout, move || no_prompt_guard(store, || f(&entry)))
    }

    pub(super) fn preflight(&self, timeout: Duration) -> Result<(), StoreFailure> {
        self.call(PREFLIGHT_USER, timeout, |e| match e.get_password() {
            Ok(_) | Err(Error::NoEntry) => Ok(()),
            Err(err) => Err(classify(err)),
        })
    }

    pub(super) fn get(
        &self,
        user: &str,
        timeout: Duration,
    ) -> Result<Option<Zeroizing<String>>, StoreFailure> {
        self.call(user, timeout, |e| match e.get_password() {
            Ok(v) => Ok(Some(Zeroizing::new(v))),
            Err(Error::NoEntry) => Ok(None),
            Err(err) => Err(classify(err)),
        })
    }

    pub(super) fn set(
        &self,
        user: &str,
        value: &SecretValue,
        timeout: Duration,
    ) -> Result<(), StoreFailure> {
        let value = Zeroizing::new(value.expose().to_owned());
        self.call(user, timeout, move |e| {
            e.set_password(&value).map_err(classify)
        })
    }

    pub(super) fn delete(&self, user: &str, timeout: Duration) -> Result<bool, StoreFailure> {
        self.call(user, timeout, |e| match e.delete_credential() {
            Ok(()) => Ok(true),
            Err(Error::NoEntry) => Ok(false),
            Err(err) => Err(classify(err)),
        })
    }
}

/// A store failure's kind. The error itself is dropped unprinted: some variants carry the
/// bytes that were read (`BadEncoding`, `BadDataFormat`), and those are zeroized here.
fn classify(err: Error) -> StoreFailure {
    match err {
        Error::BadEncoding(mut bytes) | Error::BadDataFormat(mut bytes, _) => {
            zeroize::Zeroize::zeroize(&mut bytes);
            StoreFailure::Unavailable
        }
        #[cfg(target_os = "macos")]
        Error::NoStorageAccess(e) | Error::PlatformFailure(e) => macos_failure(&*e),
        #[cfg(not(target_os = "macos"))]
        Error::NoStorageAccess(_) => StoreFailure::Locked,
        _ => StoreFailure::Unavailable,
    }
}

/// macOS: interaction refused (opv disabled it), authorization failed or cancelled read as
/// locked; a missing or broken keychain reads as unavailable.
#[cfg(target_os = "macos")]
fn macos_failure(e: &(dyn std::error::Error + Send + Sync + 'static)) -> StoreFailure {
    const INTERACTION_NOT_ALLOWED: i32 = -25308;
    const AUTH_FAILED: i32 = -25293;
    const USER_CANCELED: i32 = -128;
    match e
        .downcast_ref::<security_framework::base::Error>()
        .map(|e| e.code())
    {
        Some(INTERACTION_NOT_ALLOWED | AUTH_FAILED | USER_CANCELED) => StoreFailure::Locked,
        _ => StoreFailure::Unavailable,
    }
}

/// Run `f` so that the store cannot prompt.
///
/// - macOS: keychain user interaction is disabled for the call, so an ACL or a locked
///   keychain fails with `errSecInteractionNotAllowed` instead of showing a dialog (vet R6).
/// - Secret Service: the default collection's lock state is checked first, without
///   unlocking. A locked collection is `Locked`: unlocking would prompt, and oo7 reports a
///   locked item as absent, which would misread as "not installed" (spike §5.2).
/// - Windows: Credential Manager never prompts for generic credentials.
fn no_prompt_guard<T>(
    store: AgentStore,
    f: impl FnOnce() -> Result<T, StoreFailure>,
) -> Result<T, StoreFailure> {
    #[cfg(target_os = "macos")]
    let _lock = (store == AgentStore::MacosKeychain)
        .then(security_framework::os::macos::keychain::SecKeychain::disable_user_interaction)
        .transpose()
        .map_err(|_| StoreFailure::Unavailable)?;
    #[cfg(target_os = "linux")]
    if store == AgentStore::SecretService {
        super::linux::secret_service_unlocked()?;
    }
    #[cfg(windows)]
    let _ = store;
    f()
}
