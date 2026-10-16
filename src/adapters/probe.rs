//! Read-only tool probes shared by `doctor` and provider doctor checks (FR-3, FR-26).
//!
//! Tool output is never echoed: only a version string that matches a strict pattern.

use std::io;

use crate::cause::{Cause, Unusable};
use crate::error::Error;
use crate::host::{Host, Tool};
use crate::runner::{Call, CommandRunner, Output, PROBE_TIMEOUT};

/// Run `tool args` as a probe. A tool that cannot start is a catalog cause (04.14): not on
/// PATH is `ToolMissing` with this host's install line (R56); not executable or failing to
/// start is `ToolUnusable` (R57), never a Rust `ErrorKind` name; a probe that did not answer
/// in time is its system's diagnosis of the observed call (R51).
pub(crate) fn spawn_tool(
    r: &dyn CommandRunner,
    tool: Tool,
    host: &dyn Fn() -> Host,
    args: &[&str],
) -> Result<Output, Error> {
    let call = Call::new(tool.program, args);
    r.probe(&call, PROBE_TIMEOUT)
        .map_err(|e| spawn_failure(&tool, e.kind(), host))
}

/// The cause of a probe of `tool` that failed to run with `kind`.
fn spawn_failure(tool: &Tool, kind: io::ErrorKind, host: &dyn Fn() -> Host) -> Error {
    let unusable = |why| {
        Cause::ToolUnusable {
            tool: tool.program.to_string(),
            why,
        }
        .into()
    };
    match kind {
        io::ErrorKind::NotFound => {
            let h = host();
            Cause::ToolMissing {
                tool: tool.program.to_string(),
                platform: h.platform,
                shell: h.shell,
                ci: h.ci,
            }
            .into()
        }
        io::ErrorKind::PermissionDenied => unusable(Unusable::NotExecutable),
        io::ErrorKind::TimedOut => tool.outage(tool.program),
        kind => unusable(Unusable::SpawnFailed { io: kind.into() }),
    }
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

#[cfg(test)]
#[path = "probe_tests.rs"]
mod tests;
