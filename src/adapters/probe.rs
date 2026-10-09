//! Read-only tool probes shared by `doctor` and provider doctor checks (FR-3, FR-26).
//!
//! Tool output is never echoed: only a version string that matches a strict pattern.

use std::io;

use crate::error::Error;
use crate::host::{Host, Tool};
use crate::runner::{Call, CommandRunner, Output, PROBE_TIMEOUT};

/// Run `program args` as a probe; a spawn failure is `Error::Dependency` naming it.
pub(crate) fn spawn(r: &dyn CommandRunner, program: &str, args: &[&str]) -> Result<Output, Error> {
    let call = Call::new(program, args);
    r.probe(&call, PROBE_TIMEOUT).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => Error::Dependency(format!("{program} not found on PATH")),
        kind => Error::Dependency(format!("failed to run {program} ({kind})")),
    })
}

/// [`spawn`] whose "not found" names the install command for this platform (FR-26).
pub(crate) fn spawn_tool(
    r: &dyn CommandRunner,
    tool: Tool,
    host: &dyn Fn() -> Host,
    args: &[&str],
) -> Result<Output, Error> {
    spawn(r, tool.program, args).map_err(|e| match e {
        Error::Dependency(m) if m.ends_with("not found on PATH") => {
            Error::Dependency(format!("{m}\n  {}", host().install_hint(tool)))
        }
        e => e,
    })
}

/// `2.40.0` / `v0.4.112` → (major, minor, patch). Missing parts count as 0; anything else
/// (more than three parts, non-digits) is `None`.
pub(crate) fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let v = v.strip_prefix('v').unwrap_or(v);
    let mut parts = v.split('.').map(|p| p.parse::<u64>().ok());
    let major = parts.next()??;
    let minor = parts.next().unwrap_or(Some(0))?;
    let patch = parts.next().unwrap_or(Some(0))?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

/// The first whitespace-separated token that looks like a version (`2.40.0`, `v0.4.112`),
/// or `None`. Nothing else from tool output is ever printed.
pub(crate) fn version_in(stdout: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(stdout).ok()?;
    s.split_whitespace()
        .find(|t| {
            let digits = t.strip_prefix('v').unwrap_or(t);
            digits.len() <= 32
                && digits.starts_with(|c: char| c.is_ascii_digit())
                && digits.contains('.')
                && digits.chars().all(|c| c.is_ascii_digit() || c == '.')
        })
        .map(str::to_owned)
}
