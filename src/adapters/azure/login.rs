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
//! --allow-no-subscriptions --only-show-errors -o none` runs once, the secret through the platform's hand-off
//! (stdin, or a user-only named pipe on Windows; SR-3); (5) every `az` call of the run
//! carries `AZURE_CONFIG_DIR`; (6) the directory is removed when the run ends, on success,
//! error and Ctrl-C / SIGTERM (the signal handler), with retries on Windows, where az's
//! helper processes hold files briefly.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

use super::az::{self, Effect, ONLY_SHOW_ERRORS, PROGRAM, invoke_env};
use crate::cause::{Cause, DiagnoseContext, IoKind, Principal, RamDir};
use crate::domain::{Kind, SecretValue};
use crate::error::Error;
use crate::provider::{CredentialField, DeployLogin};
use crate::ramdir::{PrivateDir, owned_dir, ram_backed, sweep};
use crate::runner::Outcome;

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
/// changed), with the reason it has none. The way out is a machine that has one (06.49):
/// removing `deploy_credentials` would change how everyone deploys the environment, for a
/// limit of this machine alone.
fn no_ram_dir(why: RamDir) -> Error {
    Cause::RamDirUnavailable {
        remote: None,
        why,
        env: None,
        product: None,
    }
    .into()
}

/// The Azure CLI signed in as the environment's service principal, in a private directory
/// removed on drop.
pub struct AzureLogin {
    dir: PrivateDir,
}

/// Start an Azure deploy sign-in: steps 1 to 3 for this platform.
pub fn start() -> Result<AzureLogin, Error> {
    if cfg!(target_os = "macos") {
        return Err(no_ram_dir(RamDir::NoneOnPlatform { os: "macOS" }));
    }
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
    let runtime = runtime
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| no_ram_dir(RamDir::Unset))?;
    if !runtime.is_absolute() {
        return Err(no_ram_dir(RamDir::NotAbsolute));
    }
    if !owned_dir(&runtime) {
        return Err(no_ram_dir(RamDir::NotOwned));
    }
    if !is_ram(&runtime).unwrap_or(false) {
        return Err(no_ram_dir(RamDir::NotTmpfs));
    }
    sweep(&runtime, DIR_PREFIX);
    let dir = PrivateDir::create(&runtime, DIR_PREFIX).map_err(|e| {
        Error::from(Cause::PrivateDirFailed {
            dir: runtime.clone(),
            io: e.kind().into(),
        })
    })?;
    Ok(AzureLogin { dir })
}

/// The Windows path: `%LOCALAPPDATA%\Temp` (az's DPAPI-encrypted store keeps the secret
/// safe there; checked after sign-in).
fn start_windows(base: Option<PathBuf>) -> Result<AzureLogin, Error> {
    let base = base
        .filter(|b| b.is_absolute() && b.is_dir())
        .ok_or_else(|| {
            // No %LOCALAPPDATA%\Temp: nowhere to make az's private directory.
            Error::from(Cause::PrivateDirFailed {
                dir: PathBuf::from(r"%LOCALAPPDATA%\Temp"),
                io: IoKind::NotFound,
            })
        })?;
    sweep(&base, DIR_PREFIX);
    let dir = PrivateDir::create(&base, DIR_PREFIX).map_err(|e| {
        Error::from(Cause::PrivateDirFailed {
            dir: base.clone(),
            io: e.kind().into(),
        })
    })?;
    Ok(AzureLogin { dir })
}

/// Sweep the private directories that killed runs left behind (SR-4), at the start of
/// every Azure run whether or not it signs in with deploy credentials (I2): the Linux
/// runtime directory when it is the user's and RAM-backed, `%LOCALAPPDATA%\Temp` on
/// Windows. Best effort; never an error.
pub fn sweep_stale() {
    if cfg!(windows) {
        if let Some(base) = std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join("Temp"))
            && base.is_absolute()
            && base.is_dir()
        {
            sweep(&base, DIR_PREFIX);
        }
        return;
    }
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        && owned_dir(&runtime)
        && ram_backed(&runtime).unwrap_or(false)
    {
        sweep(&runtime, DIR_PREFIX);
    }
}

impl AzureLogin {
    /// The private configuration directory of this run.
    pub fn dir(&self) -> &Path {
        self.dir.path()
    }

    /// The child environment of every az call of this run.
    fn az_env(&self) -> Vec<(&'static str, &str)> {
        let mut env = vec![("AZURE_CONFIG_DIR", self.dir.utf8())];
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
        // az kept the service principal unencrypted (or not at all) in opv's private
        // directory, which is removed when the run ends; nothing was changed.
        return Err(Cause::PrivateDirFailed {
            dir: dir.to_path_buf(),
            io: IoKind::PermissionDenied,
        }
        .into());
    }
    Ok(())
}

impl DeployLogin for AzureLogin {
    fn sign_in(
        &mut self,
        values: BTreeMap<String, SecretValue>,
        r: &dyn crate::runner::CommandRunner,
    ) -> Result<(), Error> {
        // The item was read with every field FIELDS declares (onepassword's
        // read_deploy_credentials refuses one without them), so a missing one is opv's bug.
        let get = |k: &str| {
            values.get(k).ok_or_else(|| {
                Error::from(Cause::Bug {
                    site: "azure: deploy sign-in given values without a declared field",
                })
            })
        };
        let (tenant, client, secret) = (
            get("AZURE_TENANT_ID")?,
            get("AZURE_CLIENT_ID")?,
            get("AZURE_CLIENT_SECRET")?,
        );
        // The IDs are passed as `--name=value`, so no value is read as an option of az; a
        // malformed ID is az's to reject, under the service principal's name (06.18).
        let user = format!("--username={}", client.expose());
        let tenant_arg = format!("--tenant={}", tenant.expose());
        // `--allow-no-subscriptions`: a service principal with no role on any subscription
        // still signs in, so the subscription preflight names the subscription (06.18).
        let args = [
            "login",
            "--service-principal",
            &user,
            &tenant_arg,
            "-p",
            "@/dev/stdin",
            "--allow-no-subscriptions",
            ONLY_SHOW_ERRORS,
            "-o",
            "none",
        ];
        let env = self.az_env();
        // The call is the service principal's, so a failure is never blamed on the
        // person's own sign-in, nor on the credentials without proof (06.18).
        let principal = Principal::ServicePrincipal {
            client_id: client.expose().to_string(),
        };
        let outcome = crate::runner::under_deploy(principal, || {
            invoke_env(
                r,
                Effect::Write,
                "login",
                &args,
                Some(secret.expose().as_bytes()),
                &[],
                &env,
            )
        })?;
        match outcome {
            Outcome::Done(_) => check_store(self.dir.path(), cfg!(windows)),
            // A sign-in changes no target: an exit is shown with az's reply, and a call that
            // never answered is Azure or the network (`Unavailable`), safe to re-run.
            Outcome::Refused(_) | Outcome::Unknown { .. } => {
                Err(az::failed(r, DiagnoseContext::default()))
            }
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
