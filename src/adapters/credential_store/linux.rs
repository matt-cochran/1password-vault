//! Linux-only store pieces: the Secret Service lock check and the kernel user keyring `@u`
//! (spike S1 §5.1, §5.2).

use std::time::Duration;

use linux_keyutils::{KeyError, KeyPermissionsBuilder, KeyRing, KeyRingIdentifier, Permission};
use zeroize::Zeroizing;

use super::bounded::on_worker;
use super::{SERVICE, StoreFailure};
use crate::domain::secret::SecretValue;

/// `Ok` when the Secret Service's default collection is unlocked. Never unlocks, so never
/// prompts: `Collection::is_locked` answers in milliseconds (spike §5.2). No default
/// collection is `Unavailable`, since creating one would prompt for a password.
pub(super) fn secret_service_unlocked() -> Result<(), StoreFailure> {
    use secret_service::{EncryptionType, blocking::SecretService};
    let ss = SecretService::connect(EncryptionType::Dh).map_err(|_| StoreFailure::Unavailable)?;
    let collection = ss
        .get_default_collection()
        .map_err(|_| StoreFailure::Unavailable)?;
    match collection.is_locked() {
        Ok(false) => Ok(()),
        Ok(true) => Err(StoreFailure::Locked),
        Err(_) => Err(StoreFailure::Unavailable),
    }
}

/// The key's description in `@u`: the service and the entry's user name.
fn description(user: &str) -> String {
    format!("{SERVICE}:{user}")
}

fn user_keyring() -> Result<KeyRing, StoreFailure> {
    KeyRing::from_special_id(KeyRingIdentifier::User, true).map_err(|_| StoreFailure::Unavailable)
}

pub(super) fn keyutils_preflight(timeout: Duration) -> Result<(), StoreFailure> {
    on_worker(timeout, || user_keyring().map(|_| ()))
}

pub(super) fn keyutils_get(
    user: &str,
    timeout: Duration,
) -> Result<Option<Zeroizing<String>>, StoreFailure> {
    let desc = description(user);
    on_worker(timeout, move || {
        let key = match user_keyring()?.search(&desc) {
            Ok(key) => key,
            Err(e) => return absent_or(e),
        };
        let bytes = match key.read_to_vec() {
            Ok(b) => Zeroizing::new(b),
            Err(e) => return absent_or(e),
        };
        let text = std::str::from_utf8(&bytes).map_err(|_| StoreFailure::Unavailable)?;
        Ok(Some(Zeroizing::new(text.to_owned())))
    })
}

/// Store in `@u` with user view, read and search (spike §5.1): without user read, a process
/// outside the writer's session keyring (a systemd user service, a new login) is refused.
/// That widens nothing beyond the same uid (D11). Any older key is invalidated first, so a
/// key another session wrote is replaced, not updated through its permissions.
pub(super) fn keyutils_set(
    user: &str,
    value: &SecretValue,
    timeout: Duration,
) -> Result<(), StoreFailure> {
    let desc = description(user);
    let value = Zeroizing::new(value.expose().as_bytes().to_vec());
    on_worker(timeout, move || {
        let ring = user_keyring()?;
        if let Ok(old) = ring.search(&desc) {
            old.invalidate().map_err(|_| StoreFailure::Unavailable)?;
        }
        let key = ring
            .add_key(&desc, &*value)
            .map_err(|_| StoreFailure::Unavailable)?;
        let perms = KeyPermissionsBuilder::builder()
            .posessor(Permission::ALL)
            .user(Permission::VIEW | Permission::READ | Permission::SEARCH | Permission::WRITE)
            .build();
        if key.set_perms(perms).is_err() {
            let _ = key.invalidate();
            return Err(StoreFailure::Unavailable);
        }
        Ok(())
    })
}

pub(super) fn keyutils_delete(user: &str, timeout: Duration) -> Result<bool, StoreFailure> {
    let desc = description(user);
    on_worker(timeout, move || match user_keyring()?.search(&desc) {
        Ok(key) => key
            .invalidate()
            .map(|()| true)
            .map_err(|_| StoreFailure::Unavailable),
        Err(e) => absent_or(e).map(|_: Option<Zeroizing<String>>| false),
    })
}

/// A missing, expired or revoked key is absent; anything else (no permission, no keyutils in
/// this kernel or container) means the store is unusable.
fn absent_or<T>(e: KeyError) -> Result<Option<T>, StoreFailure> {
    match e {
        KeyError::KeyDoesNotExist | KeyError::KeyExpired | KeyError::KeyRevoked => Ok(None),
        _ => Err(StoreFailure::Unavailable),
    }
}
