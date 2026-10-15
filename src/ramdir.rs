//! A private, RAM-backed directory for a run's short-lived files (SR-4): Azure's
//! signed-in configuration (`adapters::azure::login`) and local file delivery under
//! `opv run` (#136). Created fresh under a user-owned `$XDG_RUNTIME_DIR` on tmpfs or ramfs
//! (Linux, WSL; on Windows a user-only protected ACL), mode 0700, never an existing path;
//! removed on drop and on Ctrl-C / SIGTERM; a killed run's directory is swept by the next
//! run that uses the same prefix.

use std::io;
use std::path::{Path, PathBuf};

use crate::runner::signals;

/// Linux `statfs` magic numbers of the RAM file systems.
const TMPFS_MAGIC: u64 = 0x0102_1994;
const RAMFS_MAGIC: u64 = 0x8584_58f6;

/// Whether `path` is a directory (not a symlink) owned by this user.
pub(crate) fn owned_dir(path: &Path) -> bool {
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
pub(crate) fn private_dir(path: &Path) -> bool {
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
/// a plain directory are left alone. Shared with local file delivery (#136).
pub(crate) fn sweep(base: &Path, prefix: &str) {
    let Ok(entries) = std::fs::read_dir(base) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name
            .to_str()
            .and_then(|n| n.strip_prefix(prefix))
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

/// A fresh private directory, removed (with everything written in it) on drop and on a
/// signal. Shared with local file delivery (#136).
pub(crate) struct PrivateDir {
    path: PathBuf,
    utf8: String,
}

impl PrivateDir {
    /// `<base>/<prefix><pid>-<random>`, created private (never an existing path).
    pub(crate) fn create(base: &Path, prefix: &str) -> io::Result<Self> {
        use std::hash::BuildHasher;
        let random =
            std::collections::hash_map::RandomState::new().hash_one(std::time::Instant::now());
        let path = base.join(format!("{prefix}{}-{random:016x}", std::process::id()));
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
        let sec = crate::adapters::azure::winsec::UserOnly::new(true)?;
        let w =
            crate::adapters::azure::winsec::wide(path.to_str().ok_or(io::ErrorKind::InvalidInput)?);
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

impl PrivateDir {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// The path as UTF-8 (checked at creation), for a child's environment.
    pub(crate) fn utf8(&self) -> &str {
        &self.utf8
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        remove_with_retries(&self.path);
        signals::unregister_cleanup(&self.path);
    }
}
