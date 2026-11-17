//! An in-memory [`AgentCredentialSource`] for tests: the same contract as the OS store
//! (values wrapped and registered, value-free `Debug`, typed store causes), with a fault
//! that can be switched on.

use std::collections::HashMap;
use std::sync::Mutex;

use zeroize::Zeroizing;

use super::{
    AgentCredentialSource, AgentKey, Persistence, SourceDescription, StoreFailure,
    secret_from_store,
};
use crate::cause::AgentStore;
use crate::domain::secret::SecretValue;
use crate::error::Error;

/// A failure the fake reports from every call while it is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakeFault {
    /// `agent_store_unavailable`.
    Unavailable,
    /// `agent_store_locked` (a lock, a prompt or a timeout).
    Locked,
}

pub struct FakeCredentialSource {
    description: SourceDescription,
    entries: Mutex<HashMap<String, Zeroizing<String>>>,
    fault: Mutex<Option<FakeFault>>,
}

impl std::fmt::Debug for FakeCredentialSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<String> = self.lock_entries().keys().cloned().collect();
        f.debug_struct("FakeCredentialSource")
            .field("description", &self.description)
            .field("entries", &names)
            .finish_non_exhaustive()
    }
}

impl FakeCredentialSource {
    /// A durable fake of `store`.
    pub fn new(store: AgentStore) -> Self {
        Self {
            description: SourceDescription {
                store,
                persistence: Persistence::Durable,
            },
            entries: Mutex::new(HashMap::new()),
            fault: Mutex::new(None),
        }
    }

    /// The kernel keyring fallback: available, but volatile.
    pub fn volatile() -> Self {
        let mut fake = Self::new(AgentStore::KernelKeyring);
        fake.description.persistence = Persistence::Volatile;
        fake
    }

    /// Fail every later call with `fault`, or stop failing with `None`.
    pub fn set_fault(&self, fault: Option<FakeFault>) {
        *self.fault.lock().unwrap_or_else(|p| p.into_inner()) = fault;
    }

    fn lock_entries(&self) -> std::sync::MutexGuard<'_, HashMap<String, Zeroizing<String>>> {
        self.entries.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn check(&self) -> Result<(), Error> {
        let fault = *self.fault.lock().unwrap_or_else(|p| p.into_inner());
        match fault {
            None => Ok(()),
            Some(FakeFault::Unavailable) => Err(StoreFailure::Unavailable
                .cause(self.description.store)
                .into()),
            Some(FakeFault::Locked) => {
                Err(StoreFailure::Locked.cause(self.description.store).into())
            }
        }
    }
}

impl AgentCredentialSource for FakeCredentialSource {
    fn describe(&self) -> SourceDescription {
        self.description
    }

    fn preflight(&self) -> Result<SourceDescription, Error> {
        self.check()?;
        Ok(self.description)
    }

    fn resolve(&self, key: &AgentKey) -> Result<Option<SecretValue>, Error> {
        self.check()?;
        Ok(self
            .lock_entries()
            .get(&key.user())
            .map(|v| secret_from_store(v.to_string())))
    }

    fn store(&self, key: &AgentKey, value: &SecretValue) -> Result<(), Error> {
        self.check()?;
        self.lock_entries()
            .insert(key.user(), Zeroizing::new(value.expose().to_owned()));
        Ok(())
    }

    fn delete(&self, key: &AgentKey) -> Result<bool, Error> {
        self.check()?;
        Ok(self.lock_entries().remove(&key.user()).is_some())
    }
}

/// The variable naming [`DirStore`]'s directory. Read only by builds with the `fake` feature
/// (tests; release builds never enable it), through [`super::machine_store`].
#[cfg(feature = "fake")]
pub const DIR_VAR: &str = "OPV_FAKE_AGENT_STORE";

/// The variable that makes [`DirStore`] fail every call: `unavailable` or `locked`.
#[cfg(feature = "fake")]
pub const FAULT_VAR: &str = "OPV_FAKE_AGENT_STORE_FAULT";

/// A store kept in a directory, one file per entry, so the end-to-end harness can run
/// separate `opv` processes (a create, then runs under the agent identity) against one
/// store. Test builds only: a plaintext file is never a store in a release build (SR-4).
/// It reports itself as a durable Secret Service.
#[cfg(feature = "fake")]
pub struct DirStore {
    dir: std::path::PathBuf,
    fault: Option<FakeFault>,
}

#[cfg(feature = "fake")]
impl std::fmt::Debug for DirStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirStore").finish_non_exhaustive()
    }
}

#[cfg(feature = "fake")]
impl DirStore {
    /// The store in `dir`, failing with [`FAULT_VAR`]'s fault when it names one.
    pub fn from_env(dir: std::path::PathBuf) -> Self {
        let fault = match std::env::var(FAULT_VAR).as_deref() {
            Ok("unavailable") => Some(FakeFault::Unavailable),
            Ok("locked") => Some(FakeFault::Locked),
            _ => None,
        };
        Self { dir, fault }
    }

    fn description() -> SourceDescription {
        SourceDescription {
            store: AgentStore::SecretService,
            persistence: Persistence::Durable,
        }
    }

    fn check(&self) -> Result<(), Error> {
        let store = Self::description().store;
        match self.fault {
            None => Ok(()),
            Some(FakeFault::Unavailable) => Err(StoreFailure::Unavailable.cause(store).into()),
            Some(FakeFault::Locked) => Err(StoreFailure::Locked.cause(store).into()),
        }
    }

    /// The entry's file: the key's user name, hex-encoded (it holds `/`).
    fn path(&self, key: &AgentKey) -> std::path::PathBuf {
        let name: String = key.user().bytes().map(|b| format!("{b:02x}")).collect();
        self.dir.join(name)
    }

    fn failed(&self) -> Error {
        StoreFailure::Unavailable
            .cause(Self::description().store)
            .into()
    }
}

#[cfg(feature = "fake")]
impl AgentCredentialSource for DirStore {
    fn describe(&self) -> SourceDescription {
        Self::description()
    }

    fn preflight(&self) -> Result<SourceDescription, Error> {
        self.check()?;
        Ok(Self::description())
    }

    fn resolve(&self, key: &AgentKey) -> Result<Option<SecretValue>, Error> {
        self.check()?;
        match std::fs::read_to_string(self.path(key)) {
            Ok(v) => Ok(Some(secret_from_store(v))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(self.failed()),
        }
    }

    fn store(&self, key: &AgentKey, value: &SecretValue) -> Result<(), Error> {
        self.check()?;
        std::fs::create_dir_all(&self.dir).map_err(|_| self.failed())?;
        std::fs::write(self.path(key), value.expose()).map_err(|_| self.failed())
    }

    fn delete(&self, key: &AgentKey) -> Result<bool, Error> {
        self.check()?;
        match std::fs::remove_file(self.path(key)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err(self.failed()),
        }
    }
}
