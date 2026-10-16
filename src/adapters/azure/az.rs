//! Shared `az` (Azure CLI) plumbing for the Azure adapters (FR-10, FR-26, FR-29, SR-3).
//!
//! A failed `az` call is reported from what opv itself established, never from `az`'s
//! wording (owner decision 2026-10-16, design `docs/design/error-catalog.md` §12.4): the
//! runner's observation of the call goes to the Azure strategy ([`super::diagnose`]), which
//! classifies only runner-level facts, and `az`'s scrubbed reply is shown as evidence. The
//! one probe added here is `az account show -o none` (exit status only): when it fails for
//! the person's own sign-in, the cause is that sign-in. Values never appear in argv or env:
//! a value goes to `az` through the platform's hand-off (SR-3): `/dev/stdin`, or on native
//! Windows a user-only named pipe ([`super::handoff`]).
//!
//! Every adapter call must go through [`CommandRunner::read`] or
//! [`CommandRunner::write`](crate::runner::CommandRunner::write); this module only builds
//! argv and maps failures. The pinned `az` environment (R7, NR-7) is added by the runner.

use std::io;

use super::handoff;
use crate::cause::{
    Cause, DiagnoseContext, EnvName, ExitClass, Observed, Principal, ResourceKind, ResourceName,
    ResourceRef, SessionState, System, Unusable, Upstream,
};
use crate::error::Error;
use crate::host::{Host, Tool};
use crate::runner::{Call, CommandRunner, Outcome, Output, PROBE_TIMEOUT};

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
    pinned_env: &[
        ("AZURE_EXTENSION_USE_DYNAMIC_INSTALL", "no"),
        ("AZURE_CORE_NO_COLOR", "true"),
        ("AZURE_CORE_ONLY_SHOW_ERRORS", "true"),
        ("AZURE_CORE_COLLECT_TELEMETRY", "no"),
        ("AZURE_CORE_OUTPUT", "json"),
    ],
    // Only the runner's retry decision reads these (a missing object is not retried); no
    // Azure cause is chosen from them, since no recording backs them (§12.4).
    not_found: &[
        "SecretNotFound",
        "ResourceNotFound",
        "ResourceGroupNotFound",
    ],
    signed_out: &[],
    aliases: &[],
    version_args: &["version", "--output", "tsv"],
};

/// Global flag that keeps `az` quiet apart from errors (R7).
pub const ONLY_SHOW_ERRORS: &str = "--only-show-errors";

/// The name the evidence box gives `az`'s reply (§7.3).
const TOOL_NAME: &str = "Azure CLI";

/// `az account show -o none`: exit status only.
const SIGNED_IN: [&str; 5] = ["account", "show", "-o", "none", ONLY_SHOW_ERRORS];

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
/// `/dev/stdin` where `az` takes the value's path ([`handoff::deliver`]). `_op` names the
/// call for readers; the runner names it in every report from its argv.
pub(crate) fn invoke_env(
    r: &dyn CommandRunner,
    effect: Effect,
    _op: &str,
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
            limit: None,
        };
        // `containerapp update` waits for the provisioning operation: minutes (NR-4).
        let call = if args.starts_with(&["containerapp", "update"]) {
            call.rollout()
        } else {
            call
        };
        match effect {
            Effect::Read => r.read(&call, refused),
            Effect::Write => r.write(&call),
        }
    })?;
    res.map_err(|e| start_failed(r, &e))
}

/// `az` could not be started: missing, not runnable, or the run budget is spent.
fn start_failed(r: &dyn CommandRunner, e: &io::Error) -> Error {
    match e.kind() {
        io::ErrorKind::NotFound => tool_missing(),
        // A spent run budget: the call never started.
        io::ErrorKind::TimedOut => AZ_CLI.budget_spent(r, e),
        kind => Cause::ToolUnusable {
            tool: PROGRAM.to_string(),
            why: Unusable::SpawnFailed { io: kind.into() },
        }
        .into(),
    }
}

/// `az` is not on PATH (FR-10): the install line for this platform.
pub(crate) fn tool_missing() -> Error {
    let host = Host::detect();
    Cause::ToolMissing {
        tool: PROGRAM.to_string(),
        platform: host.platform,
        shell: host.shell,
        ci: host.ci,
    }
    .into()
}

/// A read's output, or the diagnosed error for a non-zero exit / unknown outcome.
pub(crate) fn read_output(
    r: &dyn CommandRunner,
    ctx: DiagnoseContext,
    outcome: Outcome,
) -> Result<Output, Error> {
    match outcome {
        Outcome::Done(out) => Ok(out),
        Outcome::Refused(_) | Outcome::Unknown { .. } => Err(failed(r, ctx)),
    }
}

/// A write's output, or the diagnosed error. A write that never finished (timeout, kill,
/// lost) is `WriteOutcomeUnknown`: it may or may not have been applied (NR-2).
pub(crate) fn write_output(
    r: &dyn CommandRunner,
    ctx: DiagnoseContext,
    outcome: Outcome,
) -> Result<Output, Error> {
    match outcome {
        Outcome::Done(out) => Ok(out),
        Outcome::Refused(_) | Outcome::Unknown { .. } => Err(failed(r, writing(ctx))),
    }
}

/// What a call is about, for its diagnosis: an Azure resource in `scope`, for opv
/// environment `env` when known.
pub(crate) fn about(
    kind: ResourceKind,
    name: &str,
    scope: String,
    env: Option<&str>,
) -> DiagnoseContext {
    DiagnoseContext {
        env: env.filter(|e| !e.is_empty()).map(EnvName::new),
        resource: Some(ResourceRef {
            kind,
            name: ResourceName::new(name),
            scope: Some(scope),
        }),
        ..DiagnoseContext::default()
    }
}

/// `ctx` for a write: an unknown outcome is then `WriteOutcomeUnknown`.
pub(crate) fn writing(mut ctx: DiagnoseContext) -> DiagnoseContext {
    ctx.write = true;
    ctx
}

/// What the runner kept of the `az` call that just failed: its observation and `az`'s
/// scrubbed reply as evidence. `None` when the runner observed no failed call.
pub(crate) fn take_failure() -> Option<(Observed, Option<Upstream>)> {
    let excerpt = crate::runner::take_failure_excerpt();
    let seen = crate::runner::take_observed()?;
    let up = excerpt.map(|x| Upstream {
        source: System::Azure,
        tool: TOOL_NAME.to_string(),
        version: None,
        exit: seen.exit(),
        said: x.lines,
        removed_advice: false,
        untrusted: true,
    });
    Some((seen, up))
}

/// `cause`, with `az`'s reply as its evidence when there is one.
pub(crate) fn report(cause: Cause, up: Option<Upstream>) -> Error {
    match up {
        Some(up) => Error::with_evidence(cause, up),
        None => cause.into(),
    }
}

/// The error for the `az` call that just failed (FR-26): the person's own sign-in when
/// `az account show` fails, else what the Azure strategy makes of the runner's facts.
pub(crate) fn failed(r: &dyn CommandRunner, ctx: DiagnoseContext) -> Error {
    match take_failure() {
        Some((seen, up)) => diagnosed(r, seen, up, &ctx),
        None => unobserved(r),
    }
}

/// [`failed`] for a failure already taken with [`take_failure`].
pub(crate) fn diagnosed(
    r: &dyn CommandRunner,
    seen: Observed,
    up: Option<Upstream>,
    ctx: &DiagnoseContext,
) -> Error {
    // Only the person's own sign-in is probed: under deploy credentials, `az login` in the
    // person's profile changes nothing (X22). A call that never answered says nothing
    // about the sign-in either.
    let own = matches!(seen.principal(), Principal::Person { .. });
    if own
        && matches!(seen.exit(), ExitClass::Code { .. })
        && crate::runner::diagnosing(|| probe_status(r, &SIGNED_IN)).is_ok_and(|ok| !ok)
    {
        return report(signed_out(), up);
    }
    classified(seen, up, ctx)
}

/// What the Azure strategy makes of a failure taken with [`take_failure`], with no probe.
pub(crate) fn classified(seen: Observed, up: Option<Upstream>, ctx: &DiagnoseContext) -> Error {
    let stderr = up.as_ref().map(|u| u.said.join("\n")).unwrap_or_default();
    report(super::diagnose::diagnose(seen, &stderr, ctx), up)
}

/// A failure the runner did not observe. The runners opv ships observe every failed call;
/// a runner that does not (a test world that loses calls) gets the pre-catalog answer for
/// a call that never answered: outcome unknown, safe to re-run (NR-2, NR-28).
pub(crate) fn unobserved(r: &dyn CommandRunner) -> Error {
    AZ_CLI.unanswered(r, PROGRAM)
}

/// The person is not signed in to Azure (`az account show` failed).
pub(crate) fn signed_out() -> Cause {
    Cause::NotSignedIn {
        system: System::Azure,
        account: None,
        state: SessionState::SignedOut,
    }
}

/// Whether `az account show` succeeds: `Ok(true)` signed in, `Ok(false)` signed out. A
/// missing `az` is `ToolMissing`; a probe that never answered is diagnosed from the
/// runner's observation of it, never called a sign-out.
pub(crate) fn signed_in(r: &dyn CommandRunner) -> Result<bool, Error> {
    probe(r, &SIGNED_IN)
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
    probe_status(r, args).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => tool_missing(),
        // `az` did not answer in time (or was cut off): the runner observed how (NR-28).
        _ => failed(r, DiagnoseContext::default()),
    })
}

/// The probe's exit status as a yes or no, or the error that kept it from answering.
fn probe_status(r: &dyn CommandRunner, args: &[&str]) -> io::Result<bool> {
    r.probe(&Call::new(PROGRAM, args), PROBE_TIMEOUT)
        .map(|o| o.status == 0)
}

#[cfg(test)]
#[path = "az_tests.rs"]
mod tests;
