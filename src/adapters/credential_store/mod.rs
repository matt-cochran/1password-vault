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
//!
//! Which store a new identity goes to is chosen once, at create ([`store_for_create`]): the
//! `OPV_AGENT_STORE` override, else this platform's store. On WSL the interop store is
//! probed first (bounded by [`WRITE_TIMEOUT`], no prompt); when interop does not answer, the
//! Linux order applies (an unlocked Secret Service, else the volatile kernel keyring). An
//! existing identity is always read from the store its index entry records
//! ([`recorded_store`]), never from whichever store the machine would pick today.

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

use crate::cause::{AccountId, AgentStore, Cause, EnvName, UsageProblem};
use crate::domain::secret::SecretValue;
use crate::error::Error;

#[cfg(any(test, feature = "fake"))]
pub use fake::{FakeCredentialSource, FakeFault};

/// This machine's default store for the agent identity ([`OsCredentialStore::detect`]),
/// for an identity the index has no entry for. Builds with the `fake` feature (tests only;
/// release builds never enable it) use a [`fake::DirStore`] in the directory
/// `OPV_FAKE_AGENT_STORE` names instead, so the end-to-end scenarios never touch the host's
/// own store.
pub fn machine_store() -> Box<dyn AgentCredentialSource> {
    if let Some(dir) = fake_dir_store() {
        return dir;
    }
    Box::new(OsCredentialStore::detect())
}

/// The store a new identity goes to (`opv access <env> --create --agent`): the store
/// `OPV_AGENT_STORE` names, else the one [`OsCredentialStore::select`] finds usable now. An
/// unknown `OPV_AGENT_STORE` value is refused with `usage` before anything is probed.
pub fn store_for_create() -> Result<Box<dyn AgentCredentialSource>, Error> {
    let choice = parse_store_override(std::env::var(STORE_VAR).ok().as_deref())?;
    if let Some(dir) = fake_dir_store() {
        return Ok(dir);
    }
    Ok(Box::new(OsCredentialStore::select(choice)))
}

/// The store an existing identity was created in, as its index entry records it, with the
/// reason it was chosen. A read never lands in another store: when this store cannot be used
/// now, the caller gets its own cause (`agent_store_interop_down`, `agent_store_locked`, ...).
pub fn recorded_store(store: AgentStore, reason: StoreReason) -> Box<dyn AgentCredentialSource> {
    if let Some(dir) = fake_dir_store() {
        return dir;
    }
    Box::new(OsCredentialStore::open(store).with_reason(reason))
}

#[cfg(feature = "fake")]
fn fake_dir_store() -> Option<Box<dyn AgentCredentialSource>> {
    let dir = std::env::var_os(fake::DIR_VAR).filter(|d| !d.is_empty())?;
    Some(Box::new(fake::DirStore::from_env(dir.into())))
}

#[cfg(not(feature = "fake"))]
fn fake_dir_store() -> Option<Box<dyn AgentCredentialSource>> {
    None
}

/// The variable that names the store a new agent identity goes to.
pub const STORE_VAR: &str = "OPV_AGENT_STORE";

/// The values [`STORE_VAR`] takes, as a usage refusal names them.
const STORE_VAR_FORMAT: &str = "wincred, secret-service or kernel-keyring";

/// [`STORE_VAR`]'s value: `None` when unset or empty, else the store it names. Any other
/// value is `usage` (`OPV_AGENT_STORE expects wincred, secret-service or kernel-keyring`);
/// the value is not repeated.
pub fn parse_store_override(value: Option<&str>) -> Result<Option<AgentStore>, Error> {
    match value.map(str::trim) {
        None | Some("") => Ok(None),
        Some("wincred") => Ok(Some(AgentStore::WindowsCredentialManager)),
        Some("secret-service") => Ok(Some(AgentStore::SecretService)),
        Some("kernel-keyring") => Ok(Some(AgentStore::KernelKeyring)),
        Some(_) => Err(Cause::Usage {
            problem: UsageProblem::ValueFormat {
                flag: STORE_VAR.to_string(),
                format: STORE_VAR_FORMAT,
            },
        }
        .into()),
    }
}

/// Why a store holds (or will hold) the agent identity's token. It is recorded in the index
/// at create, so doctor can say which store and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreReason {
    /// This platform's store.
    Platform,
    /// `OPV_AGENT_STORE` named it.
    Override,
    /// WSL: interop to Windows did not answer, so a Linux store was chosen.
    WslInteropDown,
    /// WSL: Windows Credential Manager answered through interop but failed, so a Linux store
    /// was chosen.
    CredentialManagerUnusable,
    /// Linux: no Secret Service answered, so the kernel keyring was chosen.
    NoSecretService,
}

impl StoreReason {
    /// The reason in a sentence, after the store's name; `None` for [`StoreReason::Platform`].
    pub fn phrase(self) -> Option<&'static str> {
        match self {
            StoreReason::Platform => None,
            StoreReason::Override => Some("chosen with OPV_AGENT_STORE"),
            StoreReason::WslInteropDown => {
                Some("chosen because WSL interop to Windows was not responding")
            }
            StoreReason::CredentialManagerUnusable => {
                Some("chosen because Windows Credential Manager failed through WSL interop")
            }
            StoreReason::NoSecretService => Some("chosen because no Secret Service answered"),
        }
    }

    /// The reason's id in the index and in `--json` (`platform`, `wsl_interop_down`, ...).
    pub fn id(self) -> &'static str {
        match self {
            StoreReason::Platform => "platform",
            StoreReason::Override => "override",
            StoreReason::WslInteropDown => "wsl_interop_down",
            StoreReason::CredentialManagerUnusable => "credential_manager_unusable",
            StoreReason::NoSecretService => "no_secret_service",
        }
    }

    /// The reason an index id names; `Platform` for none or an id this build does not know.
    pub fn from_id(id: Option<&str>) -> Self {
        [
            StoreReason::Override,
            StoreReason::WslInteropDown,
            StoreReason::CredentialManagerUnusable,
            StoreReason::NoSecretService,
        ]
        .into_iter()
        .find(|r| Some(r.id()) == id)
        .unwrap_or(StoreReason::Platform)
    }
}

/// The store selection picked, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selection {
    pub store: AgentStore,
    pub reason: StoreReason,
}

/// What selection learns from a Linux machine. Each probe is bounded and never prompts.
pub(crate) struct Probes<'a> {
    /// WSL with interop on: the interop store's preflight. `None` when this is not WSL (or
    /// interop is off).
    pub wsl: Option<&'a dyn Fn() -> Result<(), StoreFailure>>,
    /// The Secret Service's default collection: `Ok` unlocked, `Locked`, or `Unavailable` /
    /// `TimedOut` when no daemon answers.
    pub secret_service: &'a dyn Fn() -> Result<(), StoreFailure>,
}

/// The Linux selection order (spike S1 §4).
///
/// - WSL with interop: Windows Credential Manager when its preflight answers. Otherwise a
///   Secret Service only when one answers and is unlocked (a locked one would need its
///   password at every WSL start, spike §5.2), else the kernel keyring, declared volatile.
/// - Linux: a Secret Service when one answers, locked or not (a locked one fails as
///   `agent_store_locked` rather than the token landing in a volatile store), else the kernel
///   keyring.
pub(crate) fn select_linux(probes: &Probes<'_>) -> Selection {
    let fell_back = match probes.wsl {
        None => None,
        Some(preflight) => match preflight() {
            Ok(()) => {
                return Selection {
                    store: AgentStore::WindowsCredentialManager,
                    reason: StoreReason::Platform,
                };
            }
            Err(StoreFailure::Unavailable) => Some(StoreReason::CredentialManagerUnusable),
            Err(_) => Some(StoreReason::WslInteropDown),
        },
    };
    let secret_service = (probes.secret_service)();
    let (store, reason) = match (fell_back, secret_service) {
        (Some(reason), Ok(())) => (AgentStore::SecretService, reason),
        (Some(reason), Err(_)) => (AgentStore::KernelKeyring, reason),
        (None, Err(StoreFailure::Unavailable)) => {
            (AgentStore::KernelKeyring, StoreReason::NoSecretService)
        }
        (None, _) => (AgentStore::SecretService, StoreReason::Platform),
    };
    Selection { store, reason }
}

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

    pub fn account(&self) -> &AccountId {
        &self.account
    }

    pub fn project(&self) -> &str {
        &self.project
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
    /// Why this store holds the token.
    pub reason: StoreReason,
}

impl SourceDescription {
    /// A description chosen for this platform's reasons.
    pub fn new(store: AgentStore, persistence: Persistence) -> Self {
        Self {
            store,
            persistence,
            reason: StoreReason::Platform,
        }
    }

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
    /// WSL interop to Windows did not answer: `powershell.exe` would not start, its vsock
    /// failed, or it outlived its bound. Credential Manager never prompts, so this is never
    /// a lock.
    InteropDown,
}

impl StoreFailure {
    pub(crate) fn cause(self, store: AgentStore) -> Cause {
        match self {
            StoreFailure::Unavailable => Cause::AgentStoreUnavailable { store },
            StoreFailure::Locked | StoreFailure::TimedOut => Cause::AgentStoreLocked { store },
            StoreFailure::InteropDown => Cause::AgentStoreInteropDown { store },
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
    reason: StoreReason,
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
    /// This machine's default store (spike §4): macOS Keychain; Windows Credential Manager;
    /// on WSL with interop, Windows Credential Manager through `powershell.exe`, without
    /// starting it; on Linux, a Secret Service when one answers on the session bus, else the
    /// kernel user keyring (volatile). Detection never prompts; the Secret Service probe is
    /// bounded by [`READ_TIMEOUT`].
    pub fn detect() -> Self {
        Self::opened(detect_selection(false))
    }

    /// The store a new identity goes to: `choice` when given (`OPV_AGENT_STORE`), else
    /// [`OsCredentialStore::detect`]'s order, except that on WSL the interop store must answer
    /// a bounded preflight ([`WRITE_TIMEOUT`], no prompt) first; when it does not, the Linux
    /// order applies ([`select_linux`]).
    pub fn select(choice: Option<AgentStore>) -> Self {
        match choice {
            Some(store) => Self::opened(Selection {
                store,
                reason: StoreReason::Override,
            }),
            None => Self::opened(detect_selection(true)),
        }
    }

    /// The store an identity was created in (the index records it, design §7.5), so a later
    /// read never lands in another store because the machine's default changed.
    pub fn open(store: AgentStore) -> Self {
        Self::with_backend(open_backend(store))
    }

    /// The same store, described with `reason` (the index's record of why it was chosen).
    pub fn with_reason(mut self, reason: StoreReason) -> Self {
        self.reason = reason;
        self
    }

    /// The backend for `selection`. A Secret Service that answered the probe but will not
    /// connect falls back to the kernel keyring, unless `OPV_AGENT_STORE` named it.
    fn opened(selection: Selection) -> Self {
        let backend = open_backend(selection.store);
        #[cfg(target_os = "linux")]
        if matches!(backend, Backend::None(AgentStore::SecretService))
            && selection.reason != StoreReason::Override
        {
            let reason = match selection.reason {
                StoreReason::Platform => StoreReason::NoSecretService,
                other => other,
            };
            return Self::with_backend(Backend::KernelKeyring).with_reason(reason);
        }
        Self::with_backend(backend).with_reason(selection.reason)
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
            reason: StoreReason::Platform,
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
        let (store, persistence) = match &self.backend {
            #[cfg(any(target_os = "linux", target_os = "macos", windows))]
            Backend::Native(n) => (n.store(), Persistence::Durable),
            #[cfg(target_os = "linux")]
            Backend::Wsl(_) => (AgentStore::WindowsCredentialManager, Persistence::Durable),
            #[cfg(target_os = "linux")]
            Backend::KernelKeyring => (AgentStore::KernelKeyring, Persistence::Volatile),
            Backend::None(store) => (*store, Persistence::Durable),
        };
        SourceDescription {
            store,
            persistence,
            reason: self.reason,
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

#[cfg(not(target_os = "linux"))]
fn platform(store: AgentStore) -> Selection {
    Selection {
        store,
        reason: StoreReason::Platform,
    }
}

#[cfg(target_os = "macos")]
fn detect_selection(_probe_interop: bool) -> Selection {
    platform(AgentStore::MacosKeychain)
}

#[cfg(windows)]
fn detect_selection(_probe_interop: bool) -> Selection {
    platform(AgentStore::WindowsCredentialManager)
}

/// [`select_linux`] over this machine. With `probe_interop`, WSL's interop store must answer
/// its preflight (bounded by [`WRITE_TIMEOUT`]); without, it is taken unprobed, as a read of
/// the default store always did. `Store::new()` succeeds without reaching a daemon, so the
/// Secret Service is probed for its lock state, bounded by [`READ_TIMEOUT`] and never
/// unlocking.
#[cfg(target_os = "linux")]
fn detect_selection(probe_interop: bool) -> Selection {
    let vault = wsl::WslVault::detect();
    let preflight = || match &vault {
        Some(v) if probe_interop => v.preflight(WRITE_TIMEOUT),
        _ => Ok(()),
    };
    let secret_service = || bounded::on_worker(READ_TIMEOUT, linux::secret_service_unlocked);
    select_linux(&Probes {
        wsl: vault
            .is_some()
            .then_some(&preflight as &dyn Fn() -> Result<(), StoreFailure>),
        secret_service: &secret_service,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn detect_selection(_probe_interop: bool) -> Selection {
    platform(AgentStore::SecretService)
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
