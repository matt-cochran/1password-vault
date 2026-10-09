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

use crate::error::Error;
use crate::host::{Host, Tool};
use crate::runner::{Call, CommandRunner, PROBE_TIMEOUT};

/// The Azure CLI binary.
pub const PROGRAM: &str = "az";

/// Global flag that keeps `az` quiet apart from errors (R7).
pub const ONLY_SHOW_ERRORS: &str = "--only-show-errors";

/// Fail closed before any spawn when a Key Vault write would need `/dev/stdin` (SR-3):
/// native Windows has no such device, so the user is pointed at WSL or Linux.
pub fn stdin_supported() -> Result<(), Error> {
    if cfg!(windows) {
        return Err(Error::Dependency(
            "writing to Key Vault needs /dev/stdin; run opv sync from WSL or Linux".into(),
        ));
    }
    Ok(())
}

/// The error for an `az` call that exited non-zero (FR-26). `az account show -o none`
/// decides by exit status only (its stdout is dropped unread, SR-1): non-zero means not
/// signed in ([`Error::Auth`] naming `az login`); zero means signed in but the operation
/// failed ([`Error::Target`] naming `az <op> for <target>`). A missing `az` is
/// [`Error::Dependency`] with the platform install hint (FR-10).
pub fn diagnose(r: &dyn CommandRunner, op: &str, target: &str) -> Error {
    match r.probe(
        &Call::new(
            PROGRAM,
            &["account", "show", "-o", "none", ONLY_SHOW_ERRORS],
        ),
        PROBE_TIMEOUT,
    ) {
        Ok(o) if o.status == 0 => Error::Target(format!("az {op} failed for {target}")),
        Ok(_) => Error::Auth("not logged in to Azure; run: az login".into()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Error::Dependency(format!(
            "{PROGRAM} not found on PATH\n  {}",
            Host::detect().install_hint(Tool::Az)
        )),
        Err(_) => Error::Auth("not logged in to Azure; run: az login".into()),
    }
}
