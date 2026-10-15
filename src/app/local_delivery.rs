//! Local delivery under `opv run` (#136, #137): the step `op run` starts as its child when a
//! product declares `[products.<p>.local]`, between `op run` (which resolved the product's
//! `op://` references into this process's environment) and the app.
//!
//! - `environment = "declared_only"` (#137): the app's environment is exactly the product's
//!   declared keys plus a fixed set of basics ([`BASICS`]: PATH, HOME, user, shell, locale,
//!   terminal, temporary directory). Nothing else is inherited, so a Cloudflare Worker run
//!   with `CLOUDFLARE_INCLUDE_PROCESS_ENV=true` gets the declared keys as its bindings, not
//!   the developer's whole environment.
//! - Keys with `file` (#136): each value is written to a file at its declared relative path
//!   in a private directory, and the app gets that directory in `local.secrets_dir_env`;
//!   the value is not passed as a variable. The directory is created fresh under a
//!   RAM-backed, user-owned `$XDG_RUNTIME_DIR` (Linux, WSL; elsewhere refused, never a disk
//!   fallback), mode 0700, files 0400, created exclusively without following links. It is
//!   removed when the app exits, on Ctrl-C / SIGTERM, and, if opv itself was killed, by
//!   the next run's sweep (and by the system when the session's runtime directory goes).
//!
//! Always: 1Password's own variables (`OP_*`: sessions, service-account and Connect
//! credentials, the account) never reach the app. Values live only in this process's
//! environment (from `op run`), the files, and the app; they are never printed, logged or
//! put in arguments (SR-1, SR-3). `op run` stays the parent, so it keeps masking values in
//! the app's output.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::Path;

use zeroize::Zeroizing;

use crate::error::{Code, Error};

/// The variables a `declared_only` app still gets from the environment it started in, so
/// tools resolve and print as usual. None of them is a credential. `LC_*` is kept too.
pub const BASICS: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "TERM",
    "COLORTERM",
    "NO_COLOR",
    "LANG",
    "LANGUAGE",
    "TZ",
    "TMPDIR",
];

/// The directory name prefix in `$XDG_RUNTIME_DIR` (swept when its run is gone).
pub const DIR_PREFIX: &str = "opv-run.";

/// What the step does, from `opv run`'s arguments.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Delivery {
    /// The product's selected keys (names only), in the order `opv run` passed them.
    pub keys: Vec<String>,
    pub declared_only: bool,
    /// `(key, relative path)` for each key delivered as a file.
    pub files: Vec<(String, String)>,
    /// The variable naming the files' directory.
    pub dir_env: Option<String>,
    pub command: Vec<String>,
}

fn is_basic(name: &str) -> bool {
    BASICS.contains(&name) || name.starts_with("LC_")
}

/// The app's environment from `inherited` (this process's, holding the resolved values):
/// never an `OP_*` variable, never a key delivered as a file; under `declared_only`, only
/// the selected keys and [`BASICS`]. `dir` is added under `dir_env` when files are
/// delivered.
pub fn child_env(
    d: &Delivery,
    inherited: &[(String, String)],
    dir: Option<&str>,
) -> Vec<(String, String)> {
    let as_file = |n: &str| d.files.iter().any(|(k, _)| k == n);
    let mut out: Vec<(String, String)> = inherited
        .iter()
        .filter(|(k, _)| !k.starts_with("OP_") && !as_file(k))
        .filter(|(k, _)| !d.declared_only || is_basic(k) || d.keys.iter().any(|x| x == k))
        .cloned()
        .collect();
    if let (Some(var), Some(dir)) = (&d.dir_env, dir) {
        out.retain(|(k, _)| k != var);
        out.push((var.clone(), dir.to_string()));
    }
    out
}

fn ram_dir_error() -> Error {
    Error::Policy(
        "file delivery needs a private RAM-backed directory: a user-owned $XDG_RUNTIME_DIR on \
         tmpfs (Linux, WSL). It is not available here, and opv never writes these values to \
         disk instead; nothing was written"
            .into(),
    )
    .with_code(Code::RamDirUnavailable)
    .with_do("run this on Linux or WSL with a session runtime directory (systemd logind sets XDG_RUNTIME_DIR), or deliver these keys as variables (remove file)")
}

/// Write `value` to `dir/<rel>`: each directory component created inside `dir` (0700),
/// the file created exclusively with mode 0400, never through a link.
fn write_file(dir: &Path, rel: &str, value: &[u8]) -> std::io::Result<()> {
    let mut at = dir.to_path_buf();
    let parts: Vec<&str> = rel.split('/').collect();
    for part in &parts[..parts.len() - 1] {
        at.push(part);
        #[cfg(unix)]
        let b = {
            use std::os::unix::fs::DirBuilderExt;
            let mut b = std::fs::DirBuilder::new();
            b.mode(0o700);
            b
        };
        #[cfg(not(unix))]
        let b = std::fs::DirBuilder::new();
        match b.create(&at) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let m = std::fs::symlink_metadata(&at)?;
                if !m.file_type().is_dir() {
                    return Err(std::io::ErrorKind::AlreadyExists.into());
                }
            }
            Err(e) => return Err(e),
        }
    }
    at.push(parts[parts.len() - 1]);
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o400).custom_flags(libc::O_NOFOLLOW);
    }
    let mut f = o.open(&at)?;
    f.write_all(value)?;
    f.sync_all()
}

/// Run the app as `d` says; returns its exit code (128 + the signal that ended it).
pub fn run(d: &Delivery) -> Result<i32, Error> {
    if d.command.is_empty() {
        return Err(Error::Config("no command given".into()).with_code(Code::Usage));
    }
    let inherited: Zeroizing<Vec<(String, String)>> = Zeroizing::new(std::env::vars().collect());
    let mut dir = None;
    if !d.files.is_empty() {
        let runtime = std::env::var_os("XDG_RUNTIME_DIR")
            .filter(|v| !v.is_empty())
            .map(std::path::PathBuf::from)
            .filter(|p| p.is_absolute())
            .ok_or_else(ram_dir_error)?;
        use crate::ramdir::{PrivateDir, owned_dir, ram_backed, sweep};
        if !owned_dir(&runtime) || !ram_backed(&runtime).unwrap_or(false) {
            return Err(ram_dir_error());
        }
        sweep(&runtime, DIR_PREFIX);
        let private = PrivateDir::create(&runtime, DIR_PREFIX).map_err(|_| ram_dir_error())?;
        let values: BTreeMap<&str, &str> = inherited
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        for (key, rel) in &d.files {
            let Some(value) = values.get(key.as_str()) else {
                return Err(Error::Source(
                    format!("{key} was not resolved by op run; nothing was started").into(),
                ));
            };
            write_file(private.path(), rel, value.as_bytes()).map_err(|e| {
                Error::Policy(
                    format!(
                        "cannot write {key}'s file in the private directory ({})",
                        e.kind()
                    )
                    .into(),
                )
                .with_code(Code::PolicyRefused)
            })?;
        }
        dir = Some(private);
    }
    let dir_text = dir
        .as_ref()
        .and_then(|p| p.path().to_str().map(str::to_string));
    let env = Zeroizing::new(child_env(d, &inherited, dir_text.as_deref()));
    let status = std::process::Command::new(&d.command[0])
        .args(&d.command[1..])
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .status()
        .map_err(|e| {
            Error::Dependency(format!("cannot start {} ({:?})", d.command[0], e.kind()).into())
        });
    drop(env);
    drop(dir); // removes the directory and every file in it
    let status = status?;
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return Ok(128 + sig);
        }
    }
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
#[path = "local_delivery_tests.rs"]
mod tests;
