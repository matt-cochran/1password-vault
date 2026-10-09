//! Azure deploy credentials (FR-40, the SR-4 exception).
//!
//! The item holds a service principal: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` (text) and
//! `AZURE_CLIENT_SECRET` (concealed). The Azure CLI stores a service principal's secret in
//! its configuration directory, so each run signs in inside a private directory of its own
//! (`AZURE_CONFIG_DIR`), leaving the user's own `az login` untouched:
//!
//! | OS | directory | what keeps the stored secret safe |
//! |---|---|---|
//! | Linux, WSL | `$XDG_RUNTIME_DIR/opv-az.<pid>-<random>`, mode 0700 | RAM only (statfs `TMPFS_MAGIC` / `RAMFS_MAGIC`), owned by the user |
//! | Windows | `%LOCALAPPDATA%\Temp\opv-az-<pid>-<random>`, user-only protected ACL | az's DPAPI-encrypted store (`service_principal_entries.bin`); a plaintext `.json` refuses |
//! | macOS | not supported | (no RAM directory or verified encrypted store) |
//!
//! Steps: (1) before anything is read, the platform check (Linux: a RAM-backed
//! `$XDG_RUNTIME_DIR` owned by the user; macOS refuses); (2) directories left by killed runs
//! (their pid gone) are removed; (3) a fresh directory is created and checked private;
//! (4) `az login --service-principal -u <client id> -t <tenant> -p @<hand-off>
//! --only-show-errors -o none` runs once, the secret through the platform's hand-off
//! (stdin, or a user-only named pipe on Windows; SR-3); (5) every `az` call of the run
//! carries `AZURE_CONFIG_DIR`; (6) the directory is removed when the run ends, on success,
//! error and Ctrl-C / SIGTERM (the signal handler), with retries on Windows, where az's
//! helper processes hold files briefly.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

use super::az::{AZ_CLI, Effect, ONLY_SHOW_ERRORS, PROGRAM, invoke_env};
use crate::domain::{Kind, SecretValue};
use crate::error::{Code, Error};
use crate::host::Host;
use crate::provider::{CredentialField, DeployLogin};
use crate::runner::{Outcome, signals, unknown_text};

/// The fields an Azure `deploy_credentials` item holds.
pub const FIELDS: &[CredentialField] = &[
    CredentialField {
        label: "AZURE_TENANT_ID",
        kind: Kind::Config,
    },
    CredentialField {
        label: "AZURE_CLIENT_ID",
        kind: Kind::Config,
    },
    CredentialField {
        label: "AZURE_CLIENT_SECRET",
        kind: Kind::Secret,
    },
];

/// Prefix of the per-run configuration directories.
pub const DIR_PREFIX: &str = if cfg!(windows) { "opv-az-" } else { "opv-az." };

/// The refusal when this machine has no safe place for az's stored secret (nothing read or
/// changed).
pub const NO_RAM_DIR: &str = "deploy credentials for Azure need a private RAM directory \
     ($XDG_RUNTIME_DIR on tmpfs), which this machine doesn't have; nothing was read or \
     changed\n  next: sign in with az login and remove deploy_credentials, or use OIDC in CI";

/// Linux `statfs` magic numbers of the RAM file systems.
const TMPFS_MAGIC: u64 = 0x0102_1994;
const RAMFS_MAGIC: u64 = 0x8584_58f6;

/// The Azure CLI signed in as the environment's service principal, in a private directory
/// removed on drop.
pub struct AzureLogin {
    dir: PrivateDir,
}

/// Start an Azure deploy sign-in: steps 1 to 3 for this platform.
pub fn start() -> Result<AzureLogin, Error> {
    if cfg!(windows) {
        let base = std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join("Temp"));
        return start_windows(base);
    }
    start_in(std::env::var_os("XDG_RUNTIME_DIR"), &ram_backed)
}

/// The Linux path with the runtime directory and the RAM check given (tests).
pub fn start_in(
    runtime: Option<OsString>,
    is_ram: &dyn Fn(&Path) -> io::Result<bool>,
) -> Result<AzureLogin, Error> {
    let refuse = || Error::Policy(NO_RAM_DIR.into()).with_code(Code::RamDirUnavailable);
    let runtime = runtime
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .ok_or_else(refuse)?;
    if !owned_dir(&runtime) || !is_ram(&runtime).unwrap_or(false) {
        return Err(refuse());
    }
    sweep(&runtime);
    let dir = PrivateDir::create(&runtime).map_err(|_| refuse())?;
    Ok(AzureLogin { dir })
}

/// The Windows path: `%LOCALAPPDATA%\Temp` (az's DPAPI-encrypted store keeps the secret
/// safe there; checked after sign-in).
fn start_windows(base: Option<PathBuf>) -> Result<AzureLogin, Error> {
    let base = base
        .filter(|b| b.is_absolute() && b.is_dir())
        .ok_or_else(|| {
            Error::Policy(
                "deploy credentials for Azure need %LOCALAPPDATA%\\Temp for a private az \
             directory, which was not found; nothing was read or changed\n  next: sign in \
             with az login and remove deploy_credentials"
                    .into(),
            )
            .with_code(Code::RamDirUnavailable)
        })?;
    sweep(&base);
    let dir = PrivateDir::create(&base).map_err(|e| {
        Error::Policy(
            format!(
                "cannot create a private az directory under {} ({:?}); nothing was read or \
             changed\n  next: sign in with az login and remove deploy_credentials",
                base.display(),
                e.kind()
            )
            .into(),
        )
        .with_code(Code::RamDirUnavailable)
    })?;
    Ok(AzureLogin { dir })
}

/// Whether `path` is a directory (not a symlink) owned by this user.
fn owned_dir(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::symlink_metadata(path)
            .is_ok_and(|m| m.file_type().is_dir() && m.uid() == rustix::process::geteuid().as_raw())
    }
    #[cfg(not(unix))]
    {
        std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_dir())
    }
}

/// Whether a directory opv just created is private: owned by the user and, on Unix, no
/// group or other access. (On Windows its ACL was set at creation.)
fn private_dir(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        owned_dir(path) && std::fs::symlink_metadata(path).is_ok_and(|m| m.mode() & 0o077 == 0)
    }
    #[cfg(not(unix))]
    {
        owned_dir(path)
    }
}

/// Whether `path` is on a RAM file system (tmpfs or ramfs). Linux only; elsewhere (macOS)
/// no directory qualifies.
pub fn ram_backed(path: &Path) -> io::Result<bool> {
    #[cfg(target_os = "linux")]
    {
        let st = rustix::fs::statfs(path)?;
        #[allow(clippy::unnecessary_cast)]
        let magic = (st.f_type as u64) & 0xffff_ffff;
        Ok(magic == TMPFS_MAGIC || magic == RAMFS_MAGIC)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, TMPFS_MAGIC, RAMFS_MAGIC);
        Ok(false)
    }
}

/// Remove `<prefix><pid>-*` directories whose run is gone (killed before it could clean
/// up). A live run's directory, anything not owned by this user and anything that is not
/// a plain directory are left alone.
fn sweep(base: &Path) {
    let Ok(entries) = std::fs::read_dir(base) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name
            .to_str()
            .and_then(|n| n.strip_prefix(DIR_PREFIX))
            .and_then(|rest| rest.split('-').next())
            .and_then(|p| p.parse::<u32>().ok())
        else {
            continue;
        };
        let path = entry.path();
        if !alive(pid) && owned_dir(&path) {
            remove_with_retries(&path);
        }
    }
}

/// Whether process `pid` exists.
fn alive(pid: u32) -> bool {
    if pid == std::process::id() {
        return true;
    }
    #[cfg(unix)]
    {
        match i32::try_from(pid)
            .ok()
            .and_then(rustix::process::Pid::from_raw)
        {
            None => false,
            Some(p) => !matches!(
                rustix::process::test_kill_process(p),
                Err(e) if e == rustix::io::Errno::SRCH
            ),
        }
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        // SAFETY: query-only handle, closed before returning.
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                return false;
            }
            let mut code = 0u32;
            let ok = GetExitCodeProcess(h, &mut code);
            CloseHandle(h);
            ok != 0 && code == STILL_ACTIVE as u32
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        true
    }
}

/// Remove `path` recursively. On Windows az's helper processes can hold files for a few
/// seconds, so the removal is retried with backoff for up to about 10 s.
fn remove_with_retries(path: &Path) {
    let mut delay = std::time::Duration::from_millis(100);
    let mut waited = std::time::Duration::ZERO;
    loop {
        match std::fs::remove_dir_all(path) {
            Ok(()) => return,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return,
            Err(_) if cfg!(windows) && waited < std::time::Duration::from_secs(10) => {
                std::thread::sleep(delay);
                waited += delay;
                delay = (delay * 2).min(std::time::Duration::from_secs(2));
            }
            Err(_) => return,
        }
    }
}

/// A fresh private directory, removed (with everything az wrote) on drop and on a signal.
struct PrivateDir {
    path: PathBuf,
    utf8: String,
}

impl PrivateDir {
    fn create(base: &Path) -> io::Result<Self> {
        use std::hash::BuildHasher;
        let random =
            std::collections::hash_map::RandomState::new().hash_one(std::time::Instant::now());
        let path = base.join(format!("{DIR_PREFIX}{}-{random:016x}", std::process::id()));
        let utf8 = path
            .to_str()
            .ok_or(io::ErrorKind::InvalidInput)?
            .to_string();
        make_private_dir(&path)?;
        signals::register_cleanup(path.clone());
        let dir = Self { path, utf8 };
        if !private_dir(&dir.path) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(dir)
    }
}

/// Create `path` (never an existing one: a race or a planted link fails), private from the
/// start: mode 0700 on Unix, a protected user-only ACL on Windows.
fn make_private_dir(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
        let sec = super::winsec::UserOnly::new(true)?;
        let w = super::winsec::wide(path.to_str().ok_or(io::ErrorKind::InvalidInput)?);
        // SAFETY: NUL-terminated path; the attributes outlive the call.
        if unsafe { CreateDirectoryW(w.as_ptr(), sec.attributes()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(path)
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        remove_with_retries(&self.path);
        signals::unregister_cleanup(&self.path);
    }
}

impl AzureLogin {
    /// The private configuration directory of this run.
    pub fn dir(&self) -> &Path {
        &self.dir.path
    }

    /// The child environment of every az call of this run.
    fn az_env(&self) -> Vec<(&'static str, &str)> {
        let mut env = vec![("AZURE_CONFIG_DIR", self.dir.utf8.as_str())];
        if cfg!(windows) {
            env.push(("AZURE_CORE_ENCRYPT_TOKEN_CACHE", "true"));
        }
        env
    }
}

/// After sign-in on Windows: az must have stored the service principal encrypted
/// (`service_principal_entries.bin`), never as plaintext `.json`. `windows` selects the
/// check (tests run it everywhere).
fn check_store(dir: &Path, windows: bool) -> Result<(), Error> {
    if !windows {
        return Ok(());
    }
    let plain = dir.join("service_principal_entries.json").exists();
    let encrypted = dir.join("service_principal_entries.bin").exists();
    if plain || !encrypted {
        return Err(Error::Policy(
            "az did not store the deploy credentials encrypted (DPAPI) in opv's private \
             directory, so it was removed; nothing was changed\n  next: remove any az \
             setting that turns off token cache encryption, or sign in with az login and \
             remove deploy_credentials"
                .into(),
        ));
    }
    Ok(())
}

/// A tenant or client ID: argv-safe (GUID or domain), never starting with `-`.
fn is_azure_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

impl DeployLogin for AzureLogin {
    fn sign_in(
        &mut self,
        values: BTreeMap<String, SecretValue>,
        r: &dyn crate::runner::CommandRunner,
    ) -> Result<(), Error> {
        let get = |k: &str| {
            values
                .get(k)
                .ok_or_else(|| Error::Source(format!("deploy credentials: {k} is missing").into()))
        };
        let (tenant, client, secret) = (
            get("AZURE_TENANT_ID")?,
            get("AZURE_CLIENT_ID")?,
            get("AZURE_CLIENT_SECRET")?,
        );
        for (label, v) in [("AZURE_TENANT_ID", tenant), ("AZURE_CLIENT_ID", client)] {
            if !is_azure_id(v.expose()) {
                return Err(Error::Source(
                    format!(
                        "deploy credentials: {label} is not a tenant or client ID (a GUID or \
                     domain); nothing was changed\n  next: correct it in the \
                     deploy_credentials item"
                    )
                    .into(),
                ));
            }
        }
        let args = [
            "login",
            "--service-principal",
            "-u",
            client.expose(),
            "-t",
            tenant.expose(),
            "-p",
            "@/dev/stdin",
            ONLY_SHOW_ERRORS,
            "-o",
            "none",
        ];
        let env = self.az_env();
        let rejected =
            |status: String| {
                Error::Auth(format!(
                "deploy credentials: az login --service-principal failed ({status}); nothing \
                 was changed\n  next: check AZURE_TENANT_ID, AZURE_CLIENT_ID and \
                 AZURE_CLIENT_SECRET in the deploy_credentials item (an expired client \
                 secret is the usual cause)"
            ).into())
            };
        let outcome = invoke_env(
            r,
            Effect::Write,
            "login",
            &args,
            Some(secret.expose().as_bytes()),
            &[],
            &env,
        )
        .map_err(|e| match e {
            Error::Dependency(m) if m.contains("not found on PATH") => Error::Dependency(
                format!(
                    "{PROGRAM} not found on PATH\n  {}",
                    Host::detect().install_hint(AZ_CLI)
                )
                .into(),
            ),
            e => e,
        })?;
        match outcome {
            Outcome::Done(_) => check_store(&self.dir.path, cfg!(windows)),
            Outcome::Refused(o) => Err(rejected(format!("exit {}", o.status))),
            Outcome::Unknown {
                status: Some(s), ..
            } => Err(rejected(format!("exit {s}"))),
            Outcome::Unknown { reason, .. } => Err(Error::Target(
                format!(
                    "deploy credentials: {}; nothing was changed",
                    unknown_text("az login", reason)
                )
                .into(),
            )),
        }
    }

    fn env(&self, program: &str) -> Vec<(&'static str, &str)> {
        if program == PROGRAM {
            self.az_env()
        } else {
            Vec::new()
        }
    }
}

#[cfg(all(test, unix))]
#[path = "login_tests.rs"]
mod tests;
