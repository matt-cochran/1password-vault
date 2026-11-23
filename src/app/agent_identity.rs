//! The agent identity on this machine (#338, design `docs/design/agent-identity.md` §7.2,
//! §7.5): the value-free local index of the identities created here, and the machine name
//! that is part of each account's name.
//!
//! The index is `agent-identities.toml` in the user's configuration directory (never the
//! repository): `$XDG_CONFIG_HOME/opv/` when it is set, else `~/.config/opv/` on Linux,
//! `~/Library/Application Support/opv/` on macOS and `%APPDATA%\opv\` on Windows. One
//! `[[identity]]` table per identity holds names, ids, the store's kind and dates. It never
//! holds a token, a value, a digest or a length (ADR-0001 R1).

use std::path::{Path, PathBuf};

use crate::adapters::credential_store::{self, AgentCredentialSource, AgentKey, StoreReason};
use crate::cause::{AgentStore, Cause, IoKind, LocalOp};
use crate::domain::agent_identity::AgentRecord;
use crate::error::Error;

/// The index's file name, inside `<config dir>/opv/`.
pub const INDEX_FILE: &str = "agent-identities.toml";

/// One identity in the index: the project and the 1Password account ID it belongs to, and
/// its [`AgentRecord`]. Together, `(account_id, project, environment)` name the store entry.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IndexEntry {
    pub project: String,
    pub account_id: String,
    #[serde(flatten)]
    pub record: AgentRecord,
}

/// The whole index file.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Index {
    #[serde(default, rename = "identity")]
    pub identities: Vec<IndexEntry>,
}

impl Index {
    /// The entry of `env`'s identity for this account and project, if one is recorded.
    pub fn find(&self, account_id: &str, project: &str, env: &str) -> Option<&IndexEntry> {
        self.identities.iter().find(|e| {
            e.account_id == account_id && e.project == project && e.record.environment == env
        })
    }

    /// Add `entry`, replacing the entry of the same account, project and environment.
    pub fn put(&mut self, entry: IndexEntry) {
        self.identities.retain(|e| {
            !(e.account_id == entry.account_id
                && e.project == entry.project
                && e.record.environment == entry.record.environment)
        });
        self.identities.push(entry);
    }
}

/// The user's configuration directory for opv, from the environment: `None` when no home
/// or application-data directory is known.
pub fn config_dir() -> Option<PathBuf> {
    config_dir_from(&|name| std::env::var_os(name))
}

/// [`config_dir`] over a given environment lookup.
pub fn config_dir_from(var: &dyn Fn(&str) -> Option<std::ffi::OsString>) -> Option<PathBuf> {
    let absolute = |name: &str| var(name).map(PathBuf::from).filter(|p| p.is_absolute());
    if let Some(xdg) = absolute("XDG_CONFIG_HOME") {
        return Some(xdg.join("opv"));
    }
    if cfg!(windows) {
        return absolute("APPDATA").map(|d| d.join("opv"));
    }
    let home = absolute("HOME")?;
    Some(if cfg!(target_os = "macos") {
        home.join("Library").join("Application Support").join("opv")
    } else {
        home.join(".config").join("opv")
    })
}

/// The index file's path on this machine (§7.5).
pub fn index_path() -> Option<PathBuf> {
    config_dir().map(|d| d.join(INDEX_FILE))
}

/// The refusal when no configuration directory is known: nowhere to keep the index.
pub fn no_config_dir() -> Error {
    Cause::LocalIo {
        op: LocalOp::HomeDir,
        path: PathBuf::from("$XDG_CONFIG_HOME/opv"),
        io: IoKind::from(std::io::ErrorKind::NotFound),
        delivery: None,
    }
    .into()
}

fn io_error(op: LocalOp, path: &Path, kind: std::io::ErrorKind) -> Error {
    Cause::LocalIo {
        op,
        path: path.to_path_buf(),
        io: IoKind::from(kind),
        delivery: None,
    }
    .into()
}

/// Read the index; a missing file is an empty index.
pub fn load(path: &Path) -> Result<Index, Error> {
    match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text)
            .map_err(|_| io_error(LocalOp::Read, path, std::io::ErrorKind::InvalidData)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Index::default()),
        Err(e) => Err(io_error(LocalOp::Read, path, e.kind())),
    }
}

/// Record `entry` in the index at `path`, creating its directory, through a temporary file
/// and a rename. The file is the user's own (0600 on Unix), though it holds no value.
pub fn record(path: &Path, entry: IndexEntry) -> Result<(), Error> {
    let mut index = load(path)?;
    index.put(entry);
    let text = toml::to_string(&index)
        .map_err(|_| io_error(LocalOp::Write, path, std::io::ErrorKind::InvalidData))?;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).map_err(|e| io_error(LocalOp::CreateDir, dir, e.kind()))?;
    }
    crate::config_edit::write_atomic(path, &text, || Ok(()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| io_error(LocalOp::Write, path, e.kind()))?;
    }
    Ok(())
}

/// The store's id in the index and in `--json` (`macos_keychain`, `secret_service`, ...).
pub fn store_id(store: AgentStore) -> String {
    serde_json::to_value(store)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// The store an index id names; `None` for an id this build does not know.
pub fn parse_store_id(id: &str) -> Option<AgentStore> {
    [
        AgentStore::MacosKeychain,
        AgentStore::WindowsCredentialManager,
        AgentStore::SecretService,
        AgentStore::KernelKeyring,
    ]
    .into_iter()
    .find(|s| store_id(*s) == id)
}

/// The store, and why it was chosen, that `record` names; `None` for a store id this build
/// does not know.
pub fn recorded_store(record: &AgentRecord) -> Option<(AgentStore, StoreReason)> {
    Some((
        parse_store_id(&record.store)?,
        StoreReason::from_id(record.store_reason.as_deref()),
    ))
}

/// Opens a recorded store (the process's: [`credential_store::recorded_store`]).
pub type OpenRecorded<'a> = &'a dyn Fn(AgentStore, StoreReason) -> Box<dyn AgentCredentialSource>;

/// Opens the machine's default store (the process's: [`credential_store::machine_store`]).
pub type OpenDefault<'a> = &'a dyn Fn() -> Box<dyn AgentCredentialSource>;

/// The store to read `key`'s existing identity from: the one its index entry records, so a
/// read never lands in another store because the machine would choose differently today
/// (WSL interop down, `OPV_AGENT_STORE` set). With no entry, or a store id this build does not
/// know, the machine's default store.
pub fn source_for(
    index: &Index,
    key: &AgentKey,
    open: OpenRecorded<'_>,
    default: OpenDefault<'_>,
) -> Box<dyn AgentCredentialSource> {
    match index
        .find(key.account().as_str(), key.project(), key.env().as_str())
        .and_then(|e| recorded_store(&e.record))
    {
        Some((store, reason)) => open(store, reason),
        None => default(),
    }
}

/// The store the identities of `project` (`env`'s alone when given) are kept in, for
/// `--remove --agent` and `--rotate --agent`: the one store they record, or the machine's
/// default when none is recorded. Identities in more than one store are refused with `usage`
/// unless one environment is named, so no store is written or deleted for an identity it does
/// not hold.
pub fn source_for_scope(
    index: &Index,
    project: &str,
    env: Option<&str>,
    open: OpenRecorded<'_>,
    default: OpenDefault<'_>,
) -> Result<Box<dyn AgentCredentialSource>, Error> {
    let mut stores: Vec<(AgentStore, StoreReason)> = Vec::new();
    for e in index
        .identities
        .iter()
        .filter(|e| e.project == project && env.is_none_or(|v| e.record.environment == v))
    {
        if let Some(s) = recorded_store(&e.record)
            && !stores.iter().any(|(k, _)| *k == s.0)
        {
            stores.push(s);
        }
    }
    match stores.as_slice() {
        [] => Ok(default()),
        [(store, reason)] => Ok(open(*store, *reason)),
        _ => Err(Cause::Usage {
            problem: crate::cause::UsageProblem::NeedsFlag {
                flag: "--agent with no environment".into(),
                needs: "an environment named, because this project's agent identities are \
                        kept in more than one store"
                    .into(),
            },
        }
        .into()),
    }
}

/// [`source_for`] for this process: the user's index (none, or one that cannot be read,
/// gives the machine's default store).
pub fn machine_source_for(key: &AgentKey) -> Box<dyn AgentCredentialSource> {
    let index = index_path().and_then(|p| load(&p).ok()).unwrap_or_default();
    source_for(
        &index,
        key,
        &credential_store::recorded_store,
        &credential_store::machine_store,
    )
}

/// The store's name after "in" or "this machine's": its label without a leading "the".
pub fn store_name(store: AgentStore) -> &'static str {
    let label = store.label();
    label.strip_prefix("the ").unwrap_or(label)
}

/// The machine part of the account name: `--name`, else this host's name (design §7).
pub fn machine_name(given: Option<&str>) -> String {
    given.map_or_else(host_name, str::to_string)
}

#[cfg(unix)]
fn host_name() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: gethostname writes at most `buf.len()` bytes into the buffer it is given.
    let ok = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } == 0;
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    match std::str::from_utf8(&buf[..end]) {
        Ok(name) if ok => name.to_string(),
        _ => String::new(),
    }
}

#[cfg(not(unix))]
fn host_name() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(env: &str) -> IndexEntry {
        IndexEntry {
            project: "shop".into(),
            account_id: "AFAKEOP0000000000000000001".into(),
            record: AgentRecord {
                account_name: format!("shop-{env}-agent-laptop"),
                environment: env.into(),
                machine: "laptop".into(),
                store: "secret_service".into(),
                store_reason: None,
                created_on: "2026-11-17".into(),
                expires_on: "2027-02-15".into(),
                rotation_successor: None,
            },
        }
    }

    #[test]
    fn a_recorded_entry_reads_back_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("opv").join(INDEX_FILE);
        record(&path, entry("dev")).unwrap();
        assert_eq!(load(&path).unwrap().identities, vec![entry("dev")]);
    }

    #[test]
    fn recording_the_same_environment_again_keeps_one_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(INDEX_FILE);
        record(&path, entry("dev")).unwrap();
        record(&path, entry("dev")).unwrap();
        assert_eq!(load(&path).unwrap().identities.len(), 1);
    }

    #[test]
    fn a_missing_index_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            load(&dir.path().join(INDEX_FILE)).unwrap(),
            Index::default()
        );
    }

    #[test]
    fn the_index_lives_under_xdg_config_home() {
        // An absolute path on this platform (`/home/...` has no drive on Windows).
        let base = if cfg!(windows) {
            "C:\\cfg"
        } else {
            "/home/u/.cfg"
        };
        let dir = config_dir_from(&|name| {
            (name == "XDG_CONFIG_HOME").then(|| std::ffi::OsString::from(base))
        });
        assert_eq!(dir, Some(PathBuf::from(base).join("opv")));
    }

    #[test]
    fn a_relative_xdg_config_home_is_ignored() {
        let dir = config_dir_from(&|name| match name {
            "XDG_CONFIG_HOME" => Some("relative".into()),
            "HOME" => Some("/home/u".into()),
            "APPDATA" => Some("C:\\Users\\u\\AppData\\Roaming".into()),
            _ => None,
        });
        assert!(!dir.unwrap().starts_with("relative"));
    }

    #[cfg(unix)]
    #[test]
    fn the_index_file_is_the_users_own() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(INDEX_FILE);
        record(&path, entry("dev")).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn the_store_id_is_its_snake_case_name() {
        assert_eq!(store_id(AgentStore::MacosKeychain), "macos_keychain");
    }

    #[test]
    fn the_store_name_drops_the_leading_article() {
        assert_eq!(store_name(AgentStore::MacosKeychain), "macOS Keychain");
    }

    // --- which store an existing identity is read from -------------------------------------

    use crate::adapters::credential_store::{FakeCredentialSource, FakeFault};
    use crate::cause::{AccountId, EnvName};
    use std::cell::RefCell;

    fn in_store(env: &str, store: &str) -> IndexEntry {
        let mut e = entry(env);
        e.record.store = store.into();
        e
    }

    fn key(env: &str) -> AgentKey {
        AgentKey::new(
            AccountId::new("AFAKEOP0000000000000000001"),
            "shop",
            EnvName::new(env),
        )
        .unwrap()
    }

    /// Opens a recorded store as a fake failing with `fault`, noting each store opened.
    struct Opener {
        opened: RefCell<Vec<&'static str>>,
        fault: Option<FakeFault>,
    }

    impl Opener {
        fn new(fault: Option<FakeFault>) -> Self {
            Self {
                opened: RefCell::new(Vec::new()),
                fault,
            }
        }

        fn open(&self, store: AgentStore, reason: StoreReason) -> Box<dyn AgentCredentialSource> {
            self.opened.borrow_mut().push(store.label());
            let fake = FakeCredentialSource::new(store).with_reason(reason);
            fake.set_fault(self.fault);
            Box::new(fake)
        }

        fn default(&self) -> Box<dyn AgentCredentialSource> {
            self.opened.borrow_mut().push("default");
            Box::new(FakeCredentialSource::volatile())
        }
    }

    fn wincred_index() -> Index {
        Index {
            identities: vec![in_store("dev", "windows_credential_manager")],
        }
    }

    #[test]
    fn an_identity_in_credential_manager_with_interop_down_reads_as_interop_down() {
        let o = Opener::new(Some(FakeFault::InteropDown));
        let source = source_for(&wincred_index(), &key("dev"), &|s, r| o.open(s, r), &|| {
            o.default()
        });
        let err = source.resolve(&key("dev")).unwrap_err();
        assert_eq!(
            err.cause().map(|(c, _)| c.code()),
            Some("agent_store_interop_down")
        );
    }

    #[test]
    fn an_identity_in_credential_manager_with_interop_down_never_reads_another_store() {
        let o = Opener::new(Some(FakeFault::InteropDown));
        let source = source_for(&wincred_index(), &key("dev"), &|s, r| o.open(s, r), &|| {
            o.default()
        });
        let _ = source.resolve(&key("dev"));
        assert_eq!(*o.opened.borrow(), vec!["Windows Credential Manager"]);
    }

    #[test]
    fn an_identity_is_read_with_the_reason_its_store_was_chosen() {
        let mut e = in_store("dev", "kernel_keyring");
        e.record.store_reason = Some("wsl_interop_down".into());
        let index = Index {
            identities: vec![e],
        };
        let o = Opener::new(None);
        let source = source_for(&index, &key("dev"), &|s, r| o.open(s, r), &|| o.default());
        assert_eq!(source.describe().reason, StoreReason::WslInteropDown);
    }

    #[test]
    fn an_identity_the_index_does_not_record_is_read_from_the_default_store() {
        let o = Opener::new(None);
        let _ = source_for(
            &Index::default(),
            &key("dev"),
            &|s, r| o.open(s, r),
            &|| o.default(),
        );
        assert_eq!(*o.opened.borrow(), vec!["default"]);
    }

    #[test]
    fn identities_in_two_stores_need_an_environment_named() {
        let index = Index {
            identities: vec![
                in_store("dev", "windows_credential_manager"),
                in_store("test", "kernel_keyring"),
            ],
        };
        let o = Opener::new(None);
        let r = source_for_scope(&index, "shop", None, &|s, r| o.open(s, r), &|| o.default());
        assert_eq!(
            r.err().and_then(|e| e.cause().map(|(c, _)| c.code())),
            Some("usage")
        );
    }

    #[test]
    fn a_named_environment_opens_its_own_recorded_store() {
        let index = Index {
            identities: vec![
                in_store("dev", "windows_credential_manager"),
                in_store("test", "kernel_keyring"),
            ],
        };
        let o = Opener::new(None);
        let _ = source_for_scope(&index, "shop", Some("test"), &|s, r| o.open(s, r), &|| {
            o.default()
        });
        assert_eq!(*o.opened.borrow(), vec!["the kernel keyring"]);
    }

    #[test]
    fn every_store_id_parses_back_to_its_store() {
        let all = [
            AgentStore::MacosKeychain,
            AgentStore::WindowsCredentialManager,
            AgentStore::SecretService,
            AgentStore::KernelKeyring,
        ];
        assert!(
            all.iter()
                .all(|s| parse_store_id(&store_id(*s)) == Some(*s))
        );
    }
}
