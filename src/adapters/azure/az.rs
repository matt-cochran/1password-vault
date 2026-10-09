//! Shared `az` (Azure CLI) plumbing for the Azure adapters (FR-10, FR-26, FR-29, SR-3).
//!
//! The Azure CLI exits non-zero for every failure and the runner discards child stderr
//! (SR-1), so sign-in is told apart from a target failure by a separate, read-only
//! `az account show -o none` probe ([`diagnose`]). Values never appear in argv or env:
//! Key Vault writes go through `/dev/stdin` (SR-3), which on native Windows fails closed
//! before any spawn ([`stdin_supported`]).
//!
//! Every adapter call must go through [`CommandRunner::read`] or
//! [`CommandRunner::write`](crate::runner::CommandRunner::write); this module only builds
//! argv and maps failures. The pinned `az` environment (R7, NR-7) is added by the runner.

use std::io;
use std::time::Duration;

use crate::error::Error;
use crate::host::{Host, Tool};
use crate::runner::{Call, CommandRunner, Outcome, Output, PROBE_TIMEOUT, unknown_text};

/// The Azure CLI binary.
pub const PROGRAM: &str = "az";

/// The Azure CLI, with its install line per platform (FR-26).
pub const AZ_CLI: Tool = Tool {
    program: PROGRAM,
    ci: "install the Azure CLI in the CI job (GitHub Actions: uses: azure/cli@v2)",
    macos: "install: brew install azure-cli",
    windows: "install: winget install Microsoft.AzureCLI",
    linux: "install: curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash",
};

/// Global flag that keeps `az` quiet apart from errors (R7).
pub const ONLY_SHOW_ERRORS: &str = "--only-show-errors";

/// Fail closed before any spawn when `action` (e.g. "writing to Key Vault") would need
/// `/dev/stdin` (SR-3): native Windows has no such device, and the document must not touch
/// disk (SR-4), so the user is pointed at WSL or Linux.
pub fn stdin_supported(action: &str) -> Result<(), Error> {
    if cfg!(windows) {
        return Err(Error::Dependency(format!(
            "{action} needs /dev/stdin, which native Windows lacks; nothing was changed\n  \
             next: run opv sync from WSL or Linux"
        )));
    }
    Ok(())
}

/// Waiting and progress output for polling loops, injectable so tests never sleep (NR-25,
/// NR-30).
pub trait Pacer {
    /// Wait `d`.
    fn sleep(&self, d: Duration);
    /// One progress line for the person running opv (stderr, never a value).
    fn note(&self, line: &str);
}

/// The real [`Pacer`]: sleeps the thread and prints progress on stderr.
pub struct SystemPacer;

/// The pacer production code passes to adapters.
pub static SYSTEM_PACER: SystemPacer = SystemPacer;

impl Pacer for SystemPacer {
    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }

    fn note(&self, line: &str) {
        eprintln!("{line}");
    }
}

/// Whether a call changes the target (NR-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Effect {
    Read,
    Write,
}

/// Run one `az` call through the runner. Only a spawn error or a spent budget is an
/// `Err`; anything the process returned is an [`Outcome`] for the caller to read.
pub(crate) fn invoke(
    r: &dyn CommandRunner,
    effect: Effect,
    op: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
    refused: &[i32],
) -> Result<Outcome, Error> {
    let call = Call::new(PROGRAM, args).with_stdin(stdin);
    let res = match effect {
        Effect::Read => r.read(&call, refused),
        Effect::Write => r.write(&call),
    };
    res.map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => Error::Dependency(format!(
            "{PROGRAM} not found on PATH\n  {}",
            Host::detect().install_hint(AZ_CLI)
        )),
        // A spent run budget: the call never started.
        io::ErrorKind::TimedOut => Error::Target(format!(
            "az {op}: {e}; nothing was changed\n  next: re-run with a larger --timeout"
        )),
        kind => Error::Target(format!(
            "az {op} could not start {PROGRAM} ({kind}); nothing was changed\n  next: check \
             that `{PROGRAM} version` runs, then run opv again"
        )),
    })
}

/// A read's output, or the diagnosed error for a non-zero exit / unknown outcome.
pub(crate) fn read_output(
    r: &dyn CommandRunner,
    op: &str,
    target: &str,
    outcome: Outcome,
) -> Result<Output, Error> {
    match outcome {
        Outcome::Done(out) => Ok(out),
        Outcome::Refused(_) => Err(diagnose(r, op, target)),
        Outcome::Unknown { reason, .. } => Err(Error::Target(format!(
            "az {op}: {}",
            unknown_text(PROGRAM, reason)
        ))),
    }
}

/// A write's output, or the diagnosed error. A write that never finished (timeout, kill,
/// lost) is [`Error::Unknown`]: it may or may not have been applied (NR-2).
pub(crate) fn write_output(
    r: &dyn CommandRunner,
    op: &str,
    target: &str,
    outcome: Outcome,
) -> Result<Output, Error> {
    match outcome {
        Outcome::Done(out) => Ok(out),
        Outcome::Refused(_)
        | Outcome::Unknown {
            status: Some(_), ..
        } => Err(diagnose(r, op, target)),
        Outcome::Unknown { reason, .. } => Err(Error::Unknown(format!(
            "az {op}: {}; the change may or may not have been applied\n  next: re-run the same command",
            unknown_text(PROGRAM, reason)
        ))),
    }
}

/// Whether `az account show` succeeds: `Ok(true)` signed in, `Ok(false)` signed out. A
/// missing `az` is [`Error::Dependency`]; a probe that errors or times out says nothing
/// about the sign-in, so it is an [`Error::Target`] that asks for a manual check.
pub(crate) fn signed_in(r: &dyn CommandRunner) -> Result<bool, Error> {
    probe(r, &["account", "show", "-o", "none", ONLY_SHOW_ERRORS])
}

/// Whether the signed-in account can see `subscription` (NR-7): `az account show
/// --subscription <id> -o none`, exit status only (its output names the account, SR-1).
pub(crate) fn sees_subscription(r: &dyn CommandRunner, subscription: &str) -> Result<bool, Error> {
    probe(
        r,
        &[
            "account",
            "show",
            "--subscription",
            subscription,
            "-o",
            "none",
            ONLY_SHOW_ERRORS,
        ],
    )
}

/// A read-only `az` probe decided by exit status alone: `Ok(true)` for exit 0.
fn probe(r: &dyn CommandRunner, args: &[&str]) -> Result<bool, Error> {
    match r.probe(&Call::new(PROGRAM, args), PROBE_TIMEOUT) {
        Ok(o) => Ok(o.status == 0),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(Error::Dependency(format!(
            "{PROGRAM} not found on PATH\n  {}",
            Host::detect().install_hint(AZ_CLI)
        ))),
        Err(e) => Err(Error::Target(format!(
            "could not check the Azure sign-in ({e}); nothing was changed; run az account show"
        ))),
    }
}

/// The error for an `az` call that exited non-zero (FR-26). `az account show -o none`
/// decides by exit status only (its stdout is dropped unread, SR-1): non-zero means not
/// signed in ([`Error::Auth`] naming `az login`); zero means signed in but the operation
/// failed ([`Error::Target`] naming `az <op> for <target>`). A missing `az` is
/// [`Error::Dependency`] with the platform install hint (FR-10); a probe that could not
/// run says so instead of claiming a sign-out.
pub fn diagnose(r: &dyn CommandRunner, op: &str, target: &str) -> Error {
    match signed_in(r) {
        Ok(true) => Error::Target(format!("az {op} failed for {target}")),
        Ok(false) => not_logged_in(None),
        Err(e) => e,
    }
}

/// The sign-in error every Azure adapter returns (FR-26); `failed` names the call that
/// failed first, when there is one.
pub(crate) fn not_logged_in(failed: Option<&str>) -> Error {
    let why = match failed {
        Some(f) => format!("{f}; az account show failed"),
        None => "az account show failed".into(),
    };
    Error::Auth(format!(
        "not logged in to Azure ({why})\n  next: run `az login` (in CI: sign in with \
         azure/login first), then run opv again"
    ))
}

/// A [`Pacer`] for tests that neither waits nor prints.
#[cfg(test)]
pub(crate) struct NoWait;

#[cfg(test)]
impl Pacer for NoWait {
    fn sleep(&self, _d: Duration) {}
    fn note(&self, _line: &str) {}
}

#[cfg(test)]
pub(crate) static NO_WAIT: NoWait = NoWait;

/// A [`Pacer`] for tests: records every sleep and note, never waits.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct RecordingPacer {
    pub sleeps: std::cell::RefCell<Vec<Duration>>,
    pub notes: std::cell::RefCell<Vec<String>>,
}

#[cfg(test)]
impl Pacer for RecordingPacer {
    fn sleep(&self, d: Duration) {
        self.sleeps.borrow_mut().push(d);
    }

    fn note(&self, line: &str) {
        self.notes.borrow_mut().push(line.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::fake::FakeRunner;

    #[test]
    fn probe_that_cannot_run_does_not_claim_signed_out() {
        let r = FakeRunner::default();
        r.push_unknown("timeout");
        let err = diagnose(&r, "keyvault secret show", "kv");
        assert!(matches!(err, Error::Target(m) if m.contains("could not check the Azure sign-in")));
    }
}
