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
        let dir = config_dir_from(&|name| {
            (name == "XDG_CONFIG_HOME").then(|| std::ffi::OsString::from("/home/u/.cfg"))
        });
        assert_eq!(dir, Some(PathBuf::from("/home/u/.cfg/opv")));
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
}
