//! `opv unseal … --exec -- <command>` (#271, design `sealed-target` §5.5, lane st-u2): deliver
//! a verified, decrypted sealed bundle to the command, with no plaintext at rest.
//!
//! - **The child's environment** is the inherited one minus the `--identity-env` variable
//!   and every `OP_*`, plus the bundle's `env:` variables and, with file keys, the bundle's
//!   `secrets_dir_env` naming the RAM directory. A bundle name already inherited is replaced
//!   by the bundle's value, with one stderr line naming it, never a value (R1, D10).
//! - **Variables only, on Unix:** opv builds the environment, drops (zeroizes) its own copies
//!   of the values and replaces itself with the command (`execve`): no process stays holding
//!   values, signals reach the app, and the app is PID 1 in a container.
//! - **With file keys (Linux):** opv stays the parent. The files go into local delivery's
//!   private RAM directory (`opv-unseal.<pid>-<random>` under a RAM-backed, user-owned
//!   `$XDG_RUNTIME_DIR`: 0700, files 0400, `O_EXCL|O_NOFOLLOW`, no disk fallback, swept on
//!   start), removed when the command exits. SIGINT, SIGTERM, SIGHUP and SIGQUIT are
//!   forwarded to the command, and its exit code is passed through. Without a RAM directory
//!   nothing is written or started (`ram_dir_unavailable`, R2).
//! - **Off Unix (R5):** the command is spawned and waited for; file keys are refused as
//!   local delivery refuses them.
//!
//! The process was hardened at start (non-dumpable, zero soft core limit,
//! `src/hardening.rs`); descriptors above stdio are marked close-on-exec just before the
//! command starts.

use std::ffi::OsString;
use std::path::PathBuf;

use zeroize::Zeroize as _;

use super::unseal::{IdentitySource, Request, check_variables, has_file_keys, open, start_line};
use crate::bundle::crypto::OpenedBundle;
use crate::cause::{Cause, IoKind, RamDir, RamPurpose};
use crate::error::Error;

/// The private directory's name prefix in `$XDG_RUNTIME_DIR` (swept when its run is gone).
pub const DIR_PREFIX: &str = "opv-unseal.";

/// `opv unseal … --exec -- <command>`: open the bundle and deliver it to `command`. Returns
/// the command's exit code (128 + the signal that ended it) when opv stays the parent; on
/// Unix with variables only it does not return unless the command cannot start.
pub fn run(req: &Request, command: &[String]) -> Result<i32, Error> {
    run_with(
        req,
        command,
        &crate::app::local_delivery::runtime_dir_support,
    )
}

/// [`run`] with the RAM-directory check injected (tests).
pub(crate) fn run_with(
    req: &Request,
    command: &[String],
    ram_dir: &dyn Fn() -> Result<PathBuf, RamDir>,
) -> Result<i32, Error> {
    let Some(program) = command.first() else {
        return Err(Cause::Bug {
            site: "unseal --exec without a command (clap requires one)",
        }
        .into());
    };
    let opened = open(req)?;
    start_line(&opened.header, &opened.signer);
    let vars = variables(req, &opened)?;
    let files = file_entries(&opened);
    let inherited = Inherited(std::env::vars_os().collect());
    let identity_var = match &req.identity {
        Some(IdentitySource::Env(var)) => Some(var.as_str()),
        _ => None,
    };
    let names: Vec<&str> = vars.iter().map(|(n, _)| *n).collect();
    for name in overridden(&names, &inherited.0, identity_var) {
        let _ = std::io::Write::write_all(&mut crate::output::stderr(), notice(&name).as_bytes());
    }
    // The RAM directory, before any file is written or the command started (R2).
    let dir = if has_file_keys(&opened.header) {
        Some(private_dir(ram_dir)?)
    } else {
        None
    };
    if let Some((private, handle)) = &dir {
        for (rel, value) in &files {
            crate::app::local_delivery::write_file(handle, rel, value)
                .map_err(|e| crate::app::local_delivery::private_dir_failed(private.path(), &e))?;
        }
    }
    let mut env = Inherited(child_env(
        &inherited.0,
        identity_var,
        &vars,
        opened.header.secrets_dir_env.as_deref(),
        dir.as_ref().map(|(p, _)| p.utf8()),
    ));
    drop(inherited);
    let mut cmd = std::process::Command::new(program);
    cmd.args(&command[1..])
        .env_clear()
        .envs(env.0.iter().map(|(k, v)| (k, v)));
    env.0.iter_mut().for_each(|(k, v)| wipe(k, v));
    drop(env);
    drop(vars);
    drop(files);
    drop(opened); // the values, zeroized
    crate::hardening::cloexec_inherited();
    let start_failed = |e: std::io::Error| -> Error {
        Cause::ChildStartFailed {
            program: program.clone(),
            workdir: None,
            io: IoKind::from(e.kind()),
            remote: None,
        }
        .into()
    };
    #[cfg(unix)]
    if dir.is_none() {
        use std::os::unix::process::CommandExt as _;
        // Replaces this process; returns only when the command cannot start.
        let e = cmd.exec();
        return Err(start_failed(e));
    }
    let status = supervise(&mut cmd).map_err(start_failed);
    drop(dir); // removes the directory and every file in it
    status
}

/// Each `env:` destination's variable with its value, in header order. The variables were
/// checked when the bundle was verified ([`check_variables`]); they are checked again here,
/// right before delivery, and a refusal starts nothing.
fn variables<'a>(
    req: &Request,
    opened: &'a OpenedBundle,
) -> Result<Vec<(&'a str, &'a [u8])>, Error> {
    check_variables(req, &opened.header)?;
    let mut out = Vec::new();
    for (n, (name, value)) in opened.header.names.iter().zip(&opened.values) {
        debug_assert_eq!(&n.name, name);
        if let Some(var) = n.destination.strip_prefix("env:") {
            out.push((var, value.as_slice()));
        }
    }
    Ok(out)
}

/// Each `file:` destination's relative path with its value, in header order.
fn file_entries(opened: &OpenedBundle) -> Vec<(&str, &[u8])> {
    opened
        .header
        .names
        .iter()
        .zip(&opened.values)
        .filter_map(|(n, (_, value))| {
            n.destination
                .strip_prefix("file:")
                .map(|rel| (rel, value.as_slice()))
        })
        .collect()
}

/// The bundle variables `inherited` already sets (after the identity variable and `OP_*`
/// are removed), in `names` order: each gets one notice, and `--json` lists them.
pub(crate) fn overridden(
    names: &[&str],
    inherited: &[(OsString, OsString)],
    identity_var: Option<&str>,
) -> Vec<String> {
    names
        .iter()
        .filter(|n| !n.starts_with("OP_") && Some(**n) != identity_var)
        .filter(|n| inherited.iter().any(|(k, _)| k == **n))
        .map(|n| (*n).to_string())
        .collect()
}

/// The stderr notice for a replaced inherited variable: its name, never a value (D10).
fn notice(name: &str) -> String {
    format!("opv unseal: {name} from the bundle replaces the inherited value\n")
}

/// The child's environment: `inherited` without `OP_*`, the identity variable, the bundle's
/// variables and the directory variable; then the bundle's variables and, with a
/// directory, `dir_env` naming it.
fn child_env(
    inherited: &[(OsString, OsString)],
    identity_var: Option<&str>,
    vars: &[(&str, &[u8])],
    dir_env: Option<&str>,
    dir: Option<&str>,
) -> Vec<(OsString, OsString)> {
    let dir_pair = dir_env.zip(dir);
    let replaced = |k: &OsString| {
        vars.iter().any(|(n, _)| k == *n) || dir_pair.is_some_and(|(var, _)| k == var)
    };
    let mut out: Vec<(OsString, OsString)> = inherited
        .iter()
        .filter(|(k, _)| {
            !k.as_encoded_bytes().starts_with(b"OP_")
                && identity_var.is_none_or(|v| k != v)
                && !replaced(k)
        })
        .cloned()
        .collect();
    out.extend(vars.iter().map(|(n, v)| (OsString::from(n), os_value(v))));
    if let Some((var, dir)) = dir_pair {
        out.push((OsString::from(var), OsString::from(dir)));
    }
    out
}

#[cfg(unix)]
fn os_value(v: &[u8]) -> OsString {
    use std::os::unix::ffi::OsStringExt as _;
    OsString::from_vec(v.to_vec())
}

/// Windows variables are UTF-16: a value that is not UTF-8 is delivered with replacement
/// characters (the platform cannot carry its bytes).
#[cfg(not(unix))]
fn os_value(v: &[u8]) -> OsString {
    OsString::from(String::from_utf8_lossy(v).into_owned())
}

/// Overwrite a variable's name and value bytes before they are freed.
fn wipe(k: &mut OsString, v: &mut OsString) {
    for s in [k, v] {
        let mut bytes = std::mem::take(s).into_encoded_bytes();
        bytes.zeroize();
    }
}

/// An environment copy that is wiped when dropped (it holds values, and the identity when
/// `--identity-env` names it).
struct Inherited(Vec<(OsString, OsString)>);

impl Drop for Inherited {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(|(k, v)| wipe(k, v));
    }
}

/// Create the private RAM directory (after sweeping ones left by a killed run) and open it.
fn private_dir(
    ram_dir: &dyn Fn() -> Result<PathBuf, RamDir>,
) -> Result<
    (
        crate::ramdir::PrivateDir,
        crate::app::local_delivery::OpenDir,
    ),
    Error,
> {
    use crate::app::local_delivery::{OpenDir, private_dir_failed};
    use crate::ramdir::{PrivateDir, sweep};
    let runtime = ram_dir().map_err(|why| -> Error {
        Cause::RamDirUnavailable {
            remote: None,
            why,
            purpose: RamPurpose::FileDelivery,
            env: None,
            product: None,
        }
        .into()
    })?;
    sweep(&runtime, DIR_PREFIX);
    let private =
        PrivateDir::create(&runtime, DIR_PREFIX).map_err(|e| private_dir_failed(&runtime, &e))?;
    let open = OpenDir::open_private(private.path())
        .map_err(|e| private_dir_failed(private.path(), &e))?;
    Ok((private, open))
}

/// Spawn the command, forward the stopping signals to it while it runs, and return its exit
/// code (128 + the signal that ended it).
#[cfg(unix)]
fn supervise(cmd: &mut std::process::Command) -> std::io::Result<i32> {
    use signal_hook::consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
    use std::os::unix::process::ExitStatusExt as _;
    use std::sync::{Arc, Mutex};

    /// The running child's pid (`None` once reaped), and a signal that came before it ran.
    #[derive(Default)]
    struct Slot {
        pid: Option<i32>,
        pending: Option<i32>,
    }
    let slot = Arc::new(Mutex::new(Slot::default()));
    fn lock(s: &Mutex<Slot>) -> std::sync::MutexGuard<'_, Slot> {
        s.lock().unwrap_or_else(|e| e.into_inner())
    }
    let mut signals = signal_hook::iterator::Signals::new([SIGINT, SIGTERM, SIGHUP, SIGQUIT])?;
    let handle = signals.handle();
    let forwarder = {
        let slot = Arc::clone(&slot);
        std::thread::spawn(move || {
            for sig in signals.forever() {
                let mut s = lock(&slot);
                match s.pid {
                    // SAFETY: a plain kill on the pid of a child spawned and not yet reaped
                    // (the slot is cleared under this lock before it is reaped).
                    Some(pid) => unsafe {
                        libc::kill(pid, sig);
                    },
                    None => s.pending = Some(sig),
                }
            }
        })
    };
    let spawned = cmd.spawn();
    let result = spawned.and_then(|mut child| {
        let pid = child.id() as i32;
        {
            let mut s = lock(&slot);
            s.pid = Some(pid);
            if let Some(sig) = s.pending.take() {
                // SAFETY: as above; the child was just spawned and is not reaped.
                unsafe { libc::kill(pid, sig) };
            }
        }
        wait_exited(pid);
        lock(&slot).pid = None;
        child.wait()
    });
    handle.close();
    let _ = forwarder.join();
    let status = result?;
    Ok(status
        .signal()
        .map_or_else(|| status.code().unwrap_or(1), |sig| 128 + sig))
}

/// Block until `pid` has exited, without reaping it (`WNOWAIT`), so the forwarder never
/// signals a reaped, reusable pid.
#[cfg(unix)]
fn wait_exited(pid: i32) {
    loop {
        // SAFETY: `info` is a valid, zeroed `siginfo_t`; waitid only writes into it.
        let r = unsafe {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        if r == 0 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return;
        }
    }
}

/// Off Unix: spawn and wait; the console delivers Ctrl-C to the command itself.
#[cfg(not(unix))]
fn supervise(cmd: &mut std::process::Command) -> std::io::Result<i32> {
    let status = cmd.status()?;
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        pairs
            .iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
            .collect()
    }

    #[test]
    fn the_childs_environment_drops_op_and_the_identity_and_takes_the_bundles_values() {
        let inherited = os(&[
            ("PATH", "/bin"),
            ("OP_SESSION_x", "m1"),
            ("APP_ID", "m2"),
            ("PORT", "inherited"),
        ]);
        let vars: [(&str, &[u8]); 1] = [("PORT", b"bundle")];
        let env = child_env(
            &inherited,
            Some("APP_ID"),
            &vars,
            Some("SECRETS_DIR"),
            Some("/r"),
        );
        assert_eq!(
            env,
            os(&[("PATH", "/bin"), ("PORT", "bundle"), ("SECRETS_DIR", "/r")])
        );
    }

    #[test]
    fn overridden_names_only_inherited_bundle_variables() {
        let inherited = os(&[("PORT", "x"), ("APP_ID", "y")]);
        assert_eq!(
            overridden(&["PORT", "API_TOKEN", "APP_ID"], &inherited, Some("APP_ID")),
            vec!["PORT".to_string()]
        );
    }

    #[test]
    fn the_notice_names_the_variable() {
        assert_eq!(
            notice("PORT"),
            "opv unseal: PORT from the bundle replaces the inherited value\n"
        );
    }

    /// T6: every caller of `write_file` gets the path rule, not only the codec's.
    #[cfg(unix)]
    #[test]
    fn write_file_refuses_a_path_that_leaves_the_directory() {
        use crate::app::local_delivery::{OpenDir, write_file};
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("private");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let open = OpenDir::open_private(&dir).unwrap();
        assert_eq!(
            write_file(&open, "../x", b"marker").map_err(|e| e.kind()),
            Err(std::io::ErrorKind::InvalidInput)
        );
    }

    #[test]
    fn write_file_path_rule_refuses_absolute_dot_nul_and_backslash() {
        use crate::app::local_delivery::safe_relative_path;
        let refused = ["/x", "a/../b", "./a", "a//b", "", "a\0b", "a\\b", "a/"];
        assert!(refused.iter().all(|p| !safe_relative_path(p)));
    }

    #[test]
    fn file_keys_without_a_ram_dir_are_refused() {
        let req = Request {
            bundle: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/sealed/kat/bundle.opv-sealed"),
            env: "prod".into(),
            product: "api".into(),
            project: None,
            signers: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/sealed/kat/allowed_signers"),
            identity: Some(IdentitySource::File(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/sealed/kat/age-identity.txt"),
            )),
            min_revision: None,
            verify_only: false,
            json: false,
        };
        let no_dir = || Err(RamDir::Unset);
        let err = run_with(&req, &["true".to_string()], &no_dir).expect_err("refused");
        assert_eq!(err.code_str(), "ram_dir_unavailable");
    }
}
