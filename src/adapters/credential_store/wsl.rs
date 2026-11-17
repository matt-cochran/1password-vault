//! WSL: Windows Credential Manager through interop (spike S1 §5.3, §6). It is the one store
//! reachable from WSL that lives outside the WSL VM, so the token survives `wsl --shutdown`.
//!
//! opv runs `powershell.exe` with one fixed script ([`SCRIPT`]) passed whole as
//! `-EncodedCommand`. The operation, the entry's name and the value go over stdin, never
//! argv (ADR R2); the value comes back on stdout straight into zeroized memory. The child's
//! environment is cleared, and its stderr is discarded unread.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;

use base64::Engine as _;
use zeroize::Zeroizing;

use super::bounded::{ChildOutput, run_child};
use super::{SERVICE, StoreFailure};
use crate::domain::secret::SecretValue;

/// The fixed PowerShell script. It never changes at run time.
const SCRIPT: &str = include_str!("wsl_vault.ps1");

/// Where Windows PowerShell 5.1 lives under the default automount root.
const POWERSHELL: &str = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe";

/// The script's exit codes (see `wsl_vault.ps1`).
const EXIT_OK: i32 = 0;
const EXIT_NO_ENTRY: i32 = 3;

pub(super) struct WslVault {
    powershell: PathBuf,
}

impl WslVault {
    /// The interop store when this is WSL, interop is on, and `powershell.exe` is reachable.
    /// File checks only: nothing is spawned until the first call.
    pub(super) fn detect() -> Option<Self> {
        if !is_wsl() || !interop_enabled() {
            return None;
        }
        find_powershell().map(|powershell| Self { powershell })
    }

    fn run(
        &self,
        op: &str,
        user: &str,
        value: Option<&SecretValue>,
        timeout: Duration,
    ) -> Result<ChildOutput, StoreFailure> {
        let mut input = Zeroizing::new(format!("{op}\n{SERVICE}\n{user}\n").into_bytes());
        if let Some(v) = value {
            input.extend_from_slice(v.expose().as_bytes());
        }
        let mut cmd = Command::new(&self.powershell);
        cmd.args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            encoded_script(),
        ]);
        // Nothing of opv's environment reaches Windows; WSL1 and WSL2 interop both work
        // without it, and WSL_INTEROP names the WSL2 interop socket when it is set.
        cmd.env_clear();
        if let Some(sock) = std::env::var_os("WSL_INTEROP") {
            cmd.env("WSL_INTEROP", sock);
        }
        // A Windows directory, so the child never starts in a \\wsl$ path or a removed one.
        if let Some(dir) = self.powershell.parent() {
            cmd.current_dir(dir);
        }
        run_child(cmd, &input, timeout)
    }

    pub(super) fn preflight(&self, timeout: Duration) -> Result<(), StoreFailure> {
        match self.run("probe", "", None, timeout)?.code {
            Some(EXIT_OK) => Ok(()),
            _ => Err(StoreFailure::Unavailable),
        }
    }

    pub(super) fn get(
        &self,
        user: &str,
        timeout: Duration,
    ) -> Result<Option<Zeroizing<String>>, StoreFailure> {
        let out = self.run("get", user, None, timeout)?;
        match out.code {
            Some(EXIT_OK) => {
                let text =
                    std::str::from_utf8(&out.stdout).map_err(|_| StoreFailure::Unavailable)?;
                Ok(Some(Zeroizing::new(text.to_owned())))
            }
            Some(EXIT_NO_ENTRY) => Ok(None),
            _ => Err(StoreFailure::Unavailable),
        }
    }

    pub(super) fn set(
        &self,
        user: &str,
        value: &SecretValue,
        timeout: Duration,
    ) -> Result<(), StoreFailure> {
        match self.run("set", user, Some(value), timeout)?.code {
            Some(EXIT_OK) => Ok(()),
            _ => Err(StoreFailure::Unavailable),
        }
    }

    pub(super) fn delete(&self, user: &str, timeout: Duration) -> Result<bool, StoreFailure> {
        match self.run("delete", user, None, timeout)?.code {
            Some(EXIT_OK) => Ok(true),
            Some(EXIT_NO_ENTRY) => Ok(false),
            _ => Err(StoreFailure::Unavailable),
        }
    }
}

/// [`SCRIPT`] as `-EncodedCommand` takes it: base64 of UTF-16LE. Computed once.
pub(super) fn encoded_script() -> &'static str {
    static ENCODED: OnceLock<String> = OnceLock::new();
    ENCODED.get_or_init(|| {
        let utf16: Vec<u8> = SCRIPT.encode_utf16().flat_map(u16::to_le_bytes).collect();
        base64::engine::general_purpose::STANDARD.encode(utf16)
    })
}

/// WSL 1 or 2 (spike §4): the interop registration, the interop socket, the distro name,
/// or a Microsoft kernel.
fn is_wsl() -> bool {
    Path::new("/proc/sys/fs/binfmt_misc/WSLInterop").exists()
        || std::env::var_os("WSL_INTEROP").is_some()
        || std::env::var_os("WSL_DISTRO_NAME").is_some()
        || std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .is_ok_and(|r| r.to_ascii_lowercase().contains("microsoft"))
}

/// Interop is off when its binfmt registration says `disabled` (`[interop] enabled=false`).
/// WSL 1 may have no registration file; its interop is then tried, and fails closed.
fn interop_enabled() -> bool {
    match std::fs::read_to_string("/proc/sys/fs/binfmt_misc/WSLInterop") {
        Ok(text) => text.lines().next() == Some("enabled"),
        Err(_) => true,
    }
}

/// The fixed path first, then `powershell.exe` on `PATH` (another automount root).
fn find_powershell() -> Option<PathBuf> {
    let fixed = PathBuf::from(POWERSHELL);
    if fixed.is_file() {
        return Some(fixed);
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join("powershell.exe"))
        .find(|p| p.is_file())
}
