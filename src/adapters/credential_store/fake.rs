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
