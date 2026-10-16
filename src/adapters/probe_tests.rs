use std::io;

use super::spawn_tool;
use crate::cause::{Cause, Unusable};
use crate::host::{FakeEnv, Host, OP_CLI};
use crate::runner::fake::FakeRunner;

fn linux() -> Host {
    Host::from_env(&FakeEnv::new("linux").shell("/bin/bash"))
}

fn probe_failing_with(kind: io::ErrorKind) -> Cause {
    let r = FakeRunner::default();
    r.push_io_error(kind);
    let e = spawn_tool(&r, OP_CLI, &linux, &["--version"]).unwrap_err();
    e.cause().expect("a catalog cause").0.clone()
}

// 04.14: a tool that is not on PATH is the catalog's ToolMissing, with the install line.
#[test]
fn a_tool_not_on_path_is_tool_missing() {
    assert!(matches!(
        probe_failing_with(io::ErrorKind::NotFound),
        Cause::ToolMissing { tool, .. } if tool == "op"
    ));
}

// 04.14: "permission denied" is a tool that is not executable, never a Rust ErrorKind name.
#[test]
fn a_tool_that_cannot_execute_is_not_executable() {
    assert!(matches!(
        probe_failing_with(io::ErrorKind::PermissionDenied),
        Cause::ToolUnusable {
            why: Unusable::NotExecutable,
            ..
        }
    ));
}

// 04.14: any other start failure is ToolUnusable, not a missing dependency.
#[test]
fn a_tool_that_fails_to_start_is_unusable() {
    assert!(matches!(
        probe_failing_with(io::ErrorKind::Other),
        Cause::ToolUnusable {
            why: Unusable::SpawnFailed { .. },
            ..
        }
    ));
}
