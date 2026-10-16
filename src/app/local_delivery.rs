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

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::cause::{
    Cause, EnvName, Invocation, IoKind, Origin, ProductName, ProfileName, RamDir, UsageProblem,
};
use crate::error::Error;

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

/// The variable `opv run` gives `op run`, which passes it to the local delivery step: the
/// person's run ([`Outer`]) as JSON. Names and flags only; it never reaches the app.
pub const OUTER_VAR: &str = "OPV_RUN_OUTER";

/// The person's `opv run` an internal step serves (design §6.1, X25): the environment, the
/// product, the remote profile and the command line before `--` (opv's own flags and names
/// only, never the child's words). The step's errors render their steps against it, so
/// they never name the hidden step itself or `opv doctor`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outer {
    pub env: String,
    pub product: String,
    pub profile: Option<String>,
    /// The subcommand path (`["run"]`).
    pub command: Vec<String>,
    /// Every flag and argument before `--`, as the person gave them.
    pub args: Vec<String>,
    /// The person passed a command after `--` (rendered only as `-- <command>`).
    pub has_child: bool,
}

impl Outer {
    /// The run of `env` and `product` (to `profile`'s host) that `inv` started.
    pub fn new(env: &str, product: &str, profile: Option<&str>, inv: &Invocation) -> Self {
        Outer {
            env: env.to_string(),
            product: product.to_string(),
            profile: profile.map(str::to_string),
            command: inv.command.clone(),
            args: inv.args.clone(),
            has_child: inv.has_child,
        }
    }

    /// The person's invocation, as the step's errors render it.
    pub fn invocation(&self) -> Invocation {
        Invocation {
            origin: Origin::Cli,
            command: self.command.clone(),
            args: self.args.clone(),
            has_child: self.has_child,
        }
    }

    /// Short names and words, no control character: what a step accepts from its parent.
    pub fn is_valid(&self) -> bool {
        let word = |w: &str| w.len() <= 256 && !w.chars().any(char::is_control);
        let name = |w: &str| !w.is_empty() && w.len() <= 128 && word(w);
        name(&self.env)
            && name(&self.product)
            && self.profile.as_deref().is_none_or(name)
            && self.command.len() <= 4
            && self.args.len() <= 64
            && self.command.iter().chain(&self.args).all(|w| word(w))
    }

    /// The `opv run` this step serves, from [`OUTER_VAR`]; `None` when it is absent or not
    /// valid (the step was started by hand).
    pub fn from_env() -> Option<Self> {
        let text = std::env::var(OUTER_VAR).ok()?;
        serde_json::from_str::<Outer>(&text)
            .ok()
            .filter(Outer::is_valid)
    }

    /// Make the step's errors render against the person's run (design §6.1, X25).
    pub fn install(outer: Option<&Outer>) {
        let inv = match outer {
            Some(o) => o.invocation(),
            // Started by hand: the only honest step is the run's own help.
            None => Invocation {
                origin: Origin::Cli,
                command: vec!["run".into()],
                args: vec!["--help".into()],
                has_child: false,
            },
        };
        crate::error::set_outer_invocation(inv);
    }

    /// No folder for file keys on this machine, or on the profile's host (`remote`), for
    /// the run `outer`: the cause names the run, so its step is that run's preview.
    pub fn ram_dir_unavailable(outer: Option<&Outer>, remote: bool, why: RamDir) -> Error {
        Cause::RamDirUnavailable {
            remote: remote.then(|| {
                ProfileName::new(outer.and_then(|o| o.profile.clone()).unwrap_or_default())
            }),
            why,
            purpose: crate::cause::RamPurpose::FileDelivery,
            env: outer.map(|o| EnvName::new(&o.env)),
            product: outer.map(|o| ProductName::new(&o.product)),
        }
        .into()
    }
}

pub(crate) fn is_basic(name: &str) -> bool {
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
        .filter(|(k, _)| !k.starts_with("OP_") && k != OUTER_VAR && !as_file(k))
        .filter(|(k, _)| !d.declared_only || is_basic(k) || d.keys.iter().any(|x| x == k))
        .cloned()
        .collect();
    if let (Some(var), Some(dir)) = (&d.dir_env, dir) {
        out.retain(|(k, _)| k != var);
        out.push((var.clone(), dir.to_string()));
    }
    out
}

/// The user-owned, RAM-backed `$XDG_RUNTIME_DIR` file delivery needs (#136), or why it is
/// unavailable here. One check for the run's file step and for `run --preview`'s platform
/// report: Linux and WSL on tmpfs/ramfs, never a disk fallback.
pub fn runtime_dir_support() -> Result<std::path::PathBuf, RamDir> {
    if !cfg!(target_os = "linux") {
        return Err(RamDir::NoneOnPlatform {
            os: std::env::consts::OS,
        });
    }
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
        .ok_or(RamDir::Unset)?;
    if !runtime.is_absolute() {
        return Err(RamDir::NotAbsolute);
    }
    use crate::ramdir::{owned_dir, ram_backed};
    if !owned_dir(&runtime) {
        return Err(RamDir::NotOwned);
    }
    if !ram_backed(&runtime).unwrap_or(false) {
        return Err(RamDir::NotTmpfs);
    }
    Ok(runtime)
}

/// Why [`runtime_dir_support`] found no folder, in the preview's words.
pub fn ram_dir_reason(why: &RamDir) -> String {
    match why {
        RamDir::Unset => {
            "$XDG_RUNTIME_DIR is not set (systemd logind sets it on Linux and WSL)".into()
        }
        RamDir::NotAbsolute => "$XDG_RUNTIME_DIR is not an absolute path".into(),
        RamDir::NotOwned => "$XDG_RUNTIME_DIR is not a directory owned by this user".into(),
        RamDir::NotTmpfs => "$XDG_RUNTIME_DIR is not on tmpfs or ramfs (RAM-backed)".into(),
        RamDir::NoneOnPlatform { os } => format!("{os} has no RAM-backed runtime directory"),
    }
}

/// A failure to make, or write into, the private directory at `dir`.
pub(crate) fn private_dir_failed(dir: &Path, e: &std::io::Error) -> Error {
    Cause::PrivateDirFailed {
        dir: dir.to_path_buf(),
        io: IoKind::from(e.kind()),
    }
    .into()
}

/// Write `value` to `dir/<rel>`: each directory component created inside `dir` (0700),
/// the file created exclusively with mode 0400, never through a link.
pub(crate) fn write_file(dir: &Path, rel: &str, value: &[u8]) -> std::io::Result<()> {
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

/// Run the app as `d` says; returns its exit code (128 + the signal that ended it). Errors
/// render their steps against the person's `opv run` ([`Outer`]), never this hidden step.
pub fn run(d: &Delivery) -> Result<i32, Error> {
    let outer = Outer::from_env();
    Outer::install(outer.as_ref());
    if d.command.is_empty() {
        return Err(Cause::Usage {
            problem: UsageProblem::NeedsFlag {
                flag: "run".into(),
                needs: "a command after --".into(),
            },
        }
        .into());
    }
    let inherited: Zeroizing<Vec<(String, String)>> = Zeroizing::new(std::env::vars().collect());
    let mut dir = None;
    if !d.files.is_empty() {
        use crate::ramdir::{PrivateDir, sweep};
        let runtime = runtime_dir_support()
            .map_err(|why| Outer::ram_dir_unavailable(outer.as_ref(), false, why))?;
        sweep(&runtime, DIR_PREFIX);
        let private = PrivateDir::create(&runtime, DIR_PREFIX)
            .map_err(|e| private_dir_failed(&runtime, &e))?;
        let values: BTreeMap<&str, &str> = inherited
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        for (key, rel) in &d.files {
            let Some(value) = values.get(key.as_str()) else {
                // `op run` resolves every reference `opv run` gave it, or starts nothing.
                return Err(Cause::Bug {
                    site: "local-delivery: a file key op run did not resolve",
                }
                .into());
            };
            write_file(private.path(), rel, value.as_bytes())
                .map_err(|e| private_dir_failed(private.path(), &e))?;
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
        .map_err(|e| -> Error {
            Cause::ChildStartFailed {
                program: d.command[0].clone(),
                workdir: None,
                io: IoKind::from(e.kind()),
                remote: None,
            }
            .into()
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
