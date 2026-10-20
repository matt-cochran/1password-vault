//! `opv doctor`'s two session rows (#203, `docs/design/session-reuse.md` §3.3, §7.2):
//! `op app integration` and `op shell session`.
//!
//! Stub from the `session-cli-surface` lane; `session-desktop-detect` fills the bodies and
//! keeps the signatures.

use super::desktop_integration::DesktopIntegration;
use crate::host::Host;
use crate::runner::CommandRunner;

/// The `OP_SESSION*` exported in this shell, by name only (§3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellSession {
    Live { var: String },
    Expired { var: String },
}

/// One doctor row (§3.3); `doctor.rs` maps it onto its own row after `op auth`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorRow {
    pub name: &'static str,
    pub status: RowStatus,
    pub text: String,
    pub fix: Option<String>,
    pub state: &'static str,
    pub reason: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowStatus {
    Ok,
    Warn,
    Skip,
}

/// The integration's state on this host (§3.2): [`classify_static`], then one probe.
pub fn detect(host: &Host, r: &dyn CommandRunner) -> DesktopIntegration {
    let _ = (host, r);
    todo!("session-desktop-detect")
}

/// §3.2 steps 1-4, from the host alone; `None` when a probe must decide. Pure.
pub fn classify_static(host: &Host) -> Option<DesktopIntegration> {
    let _ = host;
    todo!("session-desktop-detect")
}

/// The shell's exported session for `account`, when one is in the environment.
pub fn shell_session(
    host: &Host,
    r: &dyn CommandRunner,
    account: Option<&str>,
) -> Option<ShellSession> {
    let _ = (host, r, account);
    todo!("session-desktop-detect")
}

/// The rows for doctor (§3.3).
pub fn rows(
    integration: DesktopIntegration,
    shell: Option<&ShellSession>,
    host: &Host,
) -> Vec<DoctorRow> {
    let _ = (integration, shell, host);
    todo!("session-desktop-detect")
}
