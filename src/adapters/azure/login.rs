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
use crate::ramdir::{PrivateDir, owned_dir, ram_backed, sweep};
use crate::runner::{Outcome, unknown_text};

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
    sweep(&runtime, DIR_PREFIX);
    let dir = PrivateDir::create(&runtime, DIR_PREFIX).map_err(|_| refuse())?;
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
    sweep(&base, DIR_PREFIX);
    let dir = PrivateDir::create(&base, DIR_PREFIX).map_err(|e| {
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
            Outcome::Done(_) => check_store(self.dir.path(), cfg!(windows)),
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
