//! Where the agent identity's token lives on this machine (design `agent-identity.md` §4.2.1,
//! §4.3, §4.4; spike S1 `spike-338-findings.md` §4, §5).
//!
//! [`AgentCredentialSource`] is the one seam the rest of opv uses: selection, refusals, the
//! runner hand-off and the doctor row depend only on it, so a later source that stores nothing
//! (a 1Password broker, follow-up F3) replaces [`OsCredentialStore`] without touching them.
//!
//! Rules every implementation keeps (ADR-0001, design §4.1 C1-C4):
//! - A value is a [`SecretValue`], registered with the scrubber as a secret the moment it is
//!   read. No type here prints it: no `Debug`, `Display` or error carries it.
//! - Every read is non-interactive and bounded ([`READ_TIMEOUT`], vet R6). A timeout or a lock
//!   is `agent_store_locked`; no usable store is `agent_store_unavailable`.
//! - There is no file fallback, ever (SR-4). The kernel keyring is the only fallback, and it is
//!   declared volatile ([`Persistence::Volatile`], `agent_store_volatile`, vet R5).

mod bounded;
#[cfg(any(test, feature = "fake"))]
mod fake;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod native;
#[cfg(target_os = "linux")]
mod wsl;

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::cause::{AccountId, AgentStore, Cause, EnvName};
use crate::domain::secret::SecretValue;
use crate::error::Error;

#[cfg(any(test, feature = "fake"))]
pub use fake::{FakeCredentialSource, FakeFault};

/// The bound on every store read (vet R6): a read that has not answered by then would be
/// waiting on a prompt or a hung daemon, and opv never waits on either.
pub const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// The bound on a write, a delete and the availability check. These run in the person's
/// terminal at create and rotate; the longer bound covers a cold `powershell.exe` start on
/// WSL (spike §5.3: up to 1.7 s warm), and they still never wait on a prompt.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(15);

/// The service name every entry is stored under (design §4.3, step 1.2).
pub const SERVICE: &str = "opv";

/// Which agent identity an entry holds: one per account, project and environment (design
/// §4.3). Its rendering is the entry's user name, `account_id/project/env`; it holds no value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AgentKey {
    account: AccountId,
    project: String,
    env: EnvName,
}

impl AgentKey {
    /// The key for (account, project, env), or `None` when a part is empty or holds a `/` or a
    /// control character: those would make two identities share an entry, or break the line
    /// framing of the WSL store's stdin protocol.
    pub fn new(account: AccountId, project: impl Into<String>, env: EnvName) -> Option<Self> {
        let project = project.into();
        let ok = |s: &str| !s.is_empty() && !s.contains('/') && !s.chars().any(char::is_control);
        (ok(account.as_str()) && ok(&project) && ok(env.as_str())).then_some(Self {
            account,
            project,
            env,
        })
    }

    pub fn env(&self) -> &EnvName {
        &self.env
    }

    /// The entry's user name in the store: `account_id/project/env`.
    pub fn user(&self) -> String {
        format!("{}/{}/{}", self.account, self.project, self.env)
    }
}

/// Whether the store keeps the token across a restart (spike §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Persistence {
    /// Kept until deleted: the Keychain, Credential Manager, a Secret Service collection.
    Durable,
    /// Lost when the machine (or the WSL VM) stops, or the user's last process exits: the
    /// kernel keyring.
    Volatile,
}

/// What a source is, value-free, for the `identity` row (design §7.4). The identity's name
/// and expiry come from the value-free local index (§7.5), not from the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct SourceDescription {
    pub store: AgentStore,
    pub persistence: Persistence,
}

impl SourceDescription {
    /// `agent_store_volatile` for an identity of `env` held in a volatile store; `None` for
    /// a durable one. The doctor row reports it as a FAIL (vet R5) while reads still work.
    pub fn volatile_cause(&self, env: Option<EnvName>) -> Option<Cause> {
        (self.persistence == Persistence::Volatile).then_some(Cause::AgentStoreVolatile {
            store: self.store,
            env,
        })
    }
}

/// Where an agent identity's token comes from (design §4.2.1). Implementations never prompt
/// and never print a value.
pub trait AgentCredentialSource: Send + Sync {
    /// The source's kind and persistence. No I/O.
    fn describe(&self) -> SourceDescription;

    /// Whether the store can be used now, without prompting: `agent_store_unavailable` when
    /// it is missing, `agent_store_locked` when it is locked or does not answer in time.
    /// A volatile store is available; [`SourceDescription::volatile_cause`] reports it.
    fn preflight(&self) -> Result<SourceDescription, Error>;

    /// The token for `key`, read non-interactively within [`READ_TIMEOUT`], wrapped and
    /// registered with the scrubber. `Ok(None)` when no entry exists for `key` (the caller
    /// reports `agent_identity_not_installed`).
    fn resolve(&self, key: &AgentKey) -> Result<Option<SecretValue>, Error>;

    /// Store `value` for `key`, replacing any entry (create and rotate, a person's act).
    fn store(&self, key: &AgentKey, value: &SecretValue) -> Result<(), Error>;

    /// Remove the entry for `key`. `Ok(false)` when there was none.
    fn delete(&self, key: &AgentKey) -> Result<bool, Error>;
}

/// Wrap a value read from a store: registered with the scrubber as a secret (so the output
/// guard masks it too) before anything else can see it (ADR R3, design §4.1 C3).
pub(crate) fn secret_from_store(value: String) -> SecretValue {
    // `value` moves into the SecretValue: no copy is left behind.
    crate::scrub::register_secret(&value);
    SecretValue::new(value)
}

/// One store operation's outcome before it becomes a [`Cause`]. Never carries a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoreFailure {
    /// No usable store: missing, blocked or failing.
    Unavailable,
    /// The store is locked, or answering would prompt.
    Locked,
    /// The call outlived its bound: a hidden prompt or a hung daemon.
    TimedOut,
}

impl StoreFailure {
    pub(crate) fn cause(self, store: AgentStore) -> Cause {
        match self {
            StoreFailure::Unavailable => Cause::AgentStoreUnavailable { store },
            StoreFailure::Locked | StoreFailure::TimedOut => Cause::AgentStoreLocked { store },
        }
    }
}

/// The backend this machine's OS store uses (spike §4, backend set by platform).
enum Backend {
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    Native(native::NativeStore),
    #[cfg(target_os = "linux")]
    Wsl(wsl::WslVault),
    #[cfg(target_os = "linux")]
    KernelKeyring,
    /// No store opv can use; every call reports `agent_store_unavailable` for this store.
    None(AgentStore),
}

/// The agent identity's token in the operating system's credential store: the macOS
/// Keychain, Windows Credential Manager (natively, or from WSL through interop), a Secret
/// Service collection, or the kernel user keyring as the declared volatile fallback.
pub struct OsCredentialStore {
    backend: Backend,
    read_timeout: Duration,
    write_timeout: Duration,
    /// Set once a call outlived its bound. The abandoned call may still hold the store's
    /// internal lock (spike §5.2), so every later call in this process fails at once.
    stalled: AtomicBool,
}

impl std::fmt::Debug for OsCredentialStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OsCredentialStore")
            .field("store", &self.describe().store)
            .finish_non_exhaustive()
    }
}

impl OsCredentialStore {
    /// This machine's store (spike §4): macOS Keychain; Windows Credential Manager; on WSL
    /// with interop, Windows Credential Manager through `powershell.exe`; on Linux, a Secret
    /// Service when one answers on the session bus, else the kernel user keyring (volatile).
    /// Detection never prompts; the Secret Service probe is bounded by [`READ_TIMEOUT`].
    pub fn detect() -> Self {
        Self::with_backend(detect_backend())
    }

    /// The store an identity was created in (the index records it, design §7.5), so a later
    /// read never lands in another store because the machine's default changed.
    pub fn open(store: AgentStore) -> Self {
        Self::with_backend(open_backend(store))
    }

    /// The same store with other bounds (tests of the timeout path).
    pub fn with_timeouts(mut self, read: Duration, write: Duration) -> Self {
        self.read_timeout = read;
        self.write_timeout = write;
        self
    }

    fn with_backend(backend: Backend) -> Self {
        Self {
            backend,
            read_timeout: READ_TIMEOUT,
            write_timeout: WRITE_TIMEOUT,
            stalled: AtomicBool::new(false),
        }
    }

    /// Run `op` unless an earlier call stalled; a timeout marks the store stalled.
    fn guarded<T>(&self, op: impl FnOnce() -> Result<T, StoreFailure>) -> Result<T, Error> {
        let store = self.describe().store;
        if self.stalled.load(Ordering::SeqCst) {
            return Err(StoreFailure::TimedOut.cause(store).into());
        }
        op().map_err(|failure| {
            if failure == StoreFailure::TimedOut {
                self.stalled.store(true, Ordering::SeqCst);
            }
            failure.cause(store).into()
        })
    }
}

impl AgentCredentialSource for OsCredentialStore {
    fn describe(&self) -> SourceDescription {
        let durable = |store| SourceDescription {
            store,
            persistence: Persistence::Durable,
        };
        match &self.backend {
            #[cfg(any(target_os = "linux", target_os = "macos", windows))]
            Backend::Native(n) => durable(n.store()),
            #[cfg(target_os = "linux")]
            Backend::Wsl(_) => durable(AgentStore::WindowsCredentialManager),
            #[cfg(target_os = "linux")]
            Backend::KernelKeyring => SourceDescription {
                store: AgentStore::KernelKeyring,
                persistence: Persistence::Volatile,
            },
            Backend::None(store) => durable(*store),
        }
    }

    fn preflight(&self) -> Result<SourceDescription, Error> {
        let t = self.write_timeout;
        self.guarded(|| match &self.backend {
            #[cfg(any(target_os = "linux", target_os = "macos", windows))]
            Backend::Native(n) => n.preflight(t),
            #[cfg(target_os = "linux")]
            Backend::Wsl(w) => w.preflight(t),
            #[cfg(target_os = "linux")]
            Backend::KernelKeyring => linux::keyutils_preflight(t),
            Backend::None(_) => Err(StoreFailure::Unavailable),
        })?;
        Ok(self.describe())
    }

    fn resolve(&self, key: &AgentKey) -> Result<Option<SecretValue>, Error> {
        let t = self.read_timeout;
        let user = key.user();
        let raw = self.guarded(|| match &self.backend {
            #[cfg(any(target_os = "linux", target_os = "macos", windows))]
            Backend::Native(n) => n.get(&user, t),
            #[cfg(target_os = "linux")]
            Backend::Wsl(w) => w.get(&user, t),
            #[cfg(target_os = "linux")]
            Backend::KernelKeyring => linux::keyutils_get(&user, t),
            Backend::None(_) => Err(StoreFailure::Unavailable),
        })?;
        // Registered on the caller's thread: the scrubber a test asserts on is per thread.
        Ok(raw.map(|mut v: Zeroizing<String>| secret_from_store(std::mem::take(&mut *v))))
    }

    fn store(&self, key: &AgentKey, value: &SecretValue) -> Result<(), Error> {
        let t = self.write_timeout;
        let user = key.user();
        self.guarded(|| match &self.backend {
            #[cfg(any(target_os = "linux", target_os = "macos", windows))]
            Backend::Native(n) => n.set(&user, value, t),
            #[cfg(target_os = "linux")]
            Backend::Wsl(w) => w.set(&user, value, t),
            #[cfg(target_os = "linux")]
            Backend::KernelKeyring => linux::keyutils_set(&user, value, t),
            Backend::None(_) => {
                let _ = value;
                Err(StoreFailure::Unavailable)
            }
        })
    }

    fn delete(&self, key: &AgentKey) -> Result<bool, Error> {
        let t = self.write_timeout;
        let user = key.user();
        self.guarded(|| match &self.backend {
            #[cfg(any(target_os = "linux", target_os = "macos", windows))]
            Backend::Native(n) => n.delete(&user, t),
            #[cfg(target_os = "linux")]
            Backend::Wsl(w) => w.delete(&user, t),
            #[cfg(target_os = "linux")]
            Backend::KernelKeyring => linux::keyutils_delete(&user, t),
            Backend::None(_) => Err(StoreFailure::Unavailable),
        })
    }
}

#[cfg(target_os = "macos")]
fn detect_backend() -> Backend {
    open_backend(AgentStore::MacosKeychain)
}

#[cfg(windows)]
fn detect_backend() -> Backend {
    open_backend(AgentStore::WindowsCredentialManager)
}

#[cfg(target_os = "linux")]
fn detect_backend() -> Backend {
    if let Some(vault) = wsl::WslVault::detect() {
        return Backend::Wsl(vault);
    }
    match native::NativeStore::secret_service(READ_TIMEOUT) {
        Ok(n) => Backend::Native(n),
        Err(_) => Backend::KernelKeyring,
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn detect_backend() -> Backend {
    Backend::None(AgentStore::SecretService)
}

fn open_backend(store: AgentStore) -> Backend {
    match store {
        #[cfg(target_os = "macos")]
        AgentStore::MacosKeychain => native::NativeStore::keychain()
            .map(Backend::Native)
            .unwrap_or(Backend::None(store)),
        #[cfg(windows)]
        AgentStore::WindowsCredentialManager => native::NativeStore::credential_manager()
            .map(Backend::Native)
            .unwrap_or(Backend::None(store)),
        #[cfg(target_os = "linux")]
        AgentStore::WindowsCredentialManager => wsl::WslVault::detect()
            .map(Backend::Wsl)
            .unwrap_or(Backend::None(store)),
        #[cfg(target_os = "linux")]
        AgentStore::SecretService => native::NativeStore::secret_service(READ_TIMEOUT)
            .map(Backend::Native)
            .unwrap_or(Backend::None(store)),
        #[cfg(target_os = "linux")]
        AgentStore::KernelKeyring => Backend::KernelKeyring,
        other => Backend::None(other),
    }
}

#[cfg(test)]
#[path = "../credential_store_tests.rs"]
mod tests;
