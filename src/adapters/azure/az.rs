//! Shared `az` (Azure CLI) plumbing for the Azure adapters (FR-10, FR-26, FR-29, SR-3).
//!
//! The Azure CLI exits non-zero for every failure and the runner discards child stderr
//! (SR-1), so sign-in is told apart from a target failure by a separate, read-only
//! `az account show -o none` probe ([`diagnose`]). Values never appear in argv or env:
//! a value goes to `az` through the platform's hand-off (SR-3): `/dev/stdin`, or on native
//! Windows a user-only named pipe ([`super::handoff`]).
//!
//! Every adapter call must go through [`CommandRunner::read`] or
//! [`CommandRunner::write`](crate::runner::CommandRunner::write); this module only builds
//! argv and maps failures. The pinned `az` environment (R7, NR-7) is added by the runner.

use std::io;

use super::handoff;
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
    vendor: "Azure",
    status_page: "https://azure.status.microsoft",
};

/// Global flag that keeps `az` quiet apart from errors (R7).
pub const ONLY_SHOW_ERRORS: &str = "--only-show-errors";

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
    invoke_env(r, effect, op, args, stdin, refused, &[])
}

/// [`invoke`] with extra child environment (`AZURE_CONFIG_DIR` of a deploy sign-in). A
/// value in `stdin` reaches `az` through the platform's hand-off: callers write
/// `/dev/stdin` where `az` takes the value's path ([`handoff::deliver`]).
pub(crate) fn invoke_env(
    r: &dyn CommandRunner,
    effect: Effect,
    op: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
    refused: &[i32],
    env: &[(&str, &str)],
) -> Result<Outcome, Error> {
    // Only a real child can read the platform's channel (a Windows pipe); a simulated
    // runner records the value as the call's stdin on every platform.
    let channel: &dyn handoff::Handoff = if r.spawns_processes() {
        handoff::platform()
    } else {
        &handoff::Stdin
    };
    let res = handoff::deliver(channel, args, stdin, &mut |args, stdin| {
        let call = Call {
            program: PROGRAM,
            args,
            stdin,
            env,
        };
        match effect {
            Effect::Read => r.read(&call, refused),
            Effect::Write => r.write(&call),
        }
    })?;
    res.map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => Error::Dependency(
            format!(
                "{PROGRAM} not found on PATH\n  {}",
                Host::detect().install_hint(AZ_CLI)
            )
            .into(),
        ),
        // A spent run budget: the call never started.
        io::ErrorKind::TimedOut => Error::Target(
            format!("az {op}: {e}; nothing was changed\n  next: re-run with a larger --timeout")
                .into(),
        ),
        kind => Error::Target(
            format!(
                "az {op} could not start {PROGRAM} ({kind}); nothing was changed\n  next: check \
             that `{PROGRAM} version` runs, then run opv again"
            )
            .into(),
        ),
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
        Outcome::Unknown { reason, .. } => Err(Error::Target(
            format!("az {op}: {}", unknown_text(PROGRAM, reason)).into(),
        )),
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
        ).into())),
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
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(Error::Dependency(
            format!(
                "{PROGRAM} not found on PATH\n  {}",
                Host::detect().install_hint(AZ_CLI)
            )
            .into(),
        )),
        Err(e) => Err(Error::Target(
            format!(
                "could not check the Azure sign-in ({e}); nothing was changed; run az account show"
            )
            .into(),
        )),
    }
}

/// The error for an `az` call that exited non-zero (FR-26). `az account show -o none`
/// decides by exit status only (its stdout is dropped unread, SR-1): non-zero means not
/// signed in ([`Error::Auth`] naming `az login`); zero means signed in but the operation
/// failed ([`Error::Target`] naming `az <op> for <target>`). A missing `az` is
/// [`Error::Dependency`] with the platform install hint (FR-10); a probe that could not
/// run says so instead of claiming a sign-out.
pub fn diagnose(r: &dyn CommandRunner, op: &str, target: &str) -> Error {
    // The probe explains the failed call; its excerpt stays with the error (NR-31).
    match crate::runner::diagnosing(|| signed_in(r)) {
        Ok(true) => Error::Target(format!("az {op} failed for {target}").into()),
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
    Error::Auth(
        format!(
            "not logged in to Azure ({why})\n  next: run `az login` (in CI: sign in with \
         azure/login first), then run opv again"
        )
        .into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::fake::FakeRunner;

    /// NR-31: a refused `az` call keeps its own stderr through the sign-in diagnosis.
    #[test]
    fn failed_call_leaves_an_az_said_excerpt() {
        let r = FakeRunner::default();
        r.push_with_stderr(
            Output::failure(1),
            "ERROR: (Forbidden) The user does not have secrets set permission on kv-prod\n",
        );
        r.push_with_stderr(Output::success(""), "");
        let outcome = invoke(
            &r,
            Effect::Write,
            "keyvault secret set",
            &["keyvault"],
            None,
            &[],
        );
        let _ = write_output(&r, "keyvault secret set", "kv-prod", outcome.unwrap());
        assert_eq!(
            crate::runner::take_failure_excerpt().map(|x| x.render()),
            Some("  az said: ERROR: (Forbidden) The user does not have secrets set permission on kv-prod\n".into())
        );
    }

    /// NR-19 + NR-31: what opv prints for a failed `az` call is the error line, then the
    /// scrubbed `az said:` excerpt, then exactly one `Next:` line, in that order.
    #[test]
    fn failed_az_call_reports_error_then_excerpt_then_next() {
        let r = FakeRunner::default();
        r.push_with_stderr(
            Output::failure(1),
            "ERROR: (Forbidden) The user does not have secrets set permission on kv-prod\n",
        );
        r.push_with_stderr(Output::success(""), "");
        let outcome = invoke(
            &r,
            Effect::Write,
            "keyvault secret set",
            &["keyvault"],
            None,
            &[],
        );
        let e = write_output(&r, "keyvault secret set", "kv-prod", outcome.unwrap()).unwrap_err();
        let excerpt = crate::runner::take_failure_excerpt();
        assert_eq!(
            crate::error::report(&e, "opv sync prod", excerpt.as_ref()),
            "opv: target error: az keyvault secret set failed for kv-prod\n  \
             az said: ERROR: (Forbidden) The user does not have secrets set permission on kv-prod\n\
             Next: opv sync prod\n"
        );
    }

    #[test]
    fn probe_that_cannot_run_does_not_claim_signed_out() {
        let r = FakeRunner::default();
        r.push_unknown("timeout");
        let err = diagnose(&r, "keyvault secret show", "kv");
        assert!(matches!(err, Error::Target(m) if m.contains("could not check the Azure sign-in")));
    }
}
