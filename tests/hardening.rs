//! Linux-only: the first statement of `main` hardens every command (design
//! `docs/design/error-catalog.md` §9.2). Each test runs the real binary and observes, in
//! `/proc/<pid>/status` or `/proc/<pid>/limits`, that it is not dumpable or that its soft
//! core limit is 0 while it runs.
#![cfg(target_os = "linux")]

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// True while `pid` runs non-dumpable or with a zero soft core limit.
fn hardened(pid: u32) -> bool {
    if let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status"))
        && status.lines().any(|line| line == "Dumpable:\t0")
    {
        return true;
    }
    if let Ok(limits) = std::fs::read_to_string(format!("/proc/{pid}/limits")) {
        for line in limits.lines() {
            if line.starts_with("Max core file size") && line.split_whitespace().nth(4) == Some("0")
            {
                return true;
            }
        }
    }
    false
}

/// Wait until `hardened(pid)` holds, or the process exits, or the deadline passes.
fn observed_hardened(child: &mut Child) -> bool {
    let pid = child.id();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if hardened(pid) {
            return true;
        }
        if child.try_wait().ok().flatten().is_some() {
            return false;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    false
}

/// Run `args` and assert the real binary hardens itself while it runs. `keep_alive` holds
/// stdin so a server waits; otherwise stdin is closed.
fn assert_hardened(args: &[&str], keep_alive: bool) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_opv"))
        .args(args)
        .stdin(if keep_alive {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn opv");
    let observed = observed_hardened(&mut child);
    let _ = child.kill();
    let _ = child.wait();
    assert!(observed, "opv {args:?} must run hardened");
}

#[test]
fn hardening_applies_to_the_version_command() {
    assert_hardened(&["version"], false);
}

#[test]
fn hardening_applies_to_the_schema_command() {
    assert_hardened(&["schema"], false);
}

#[test]
fn hardening_applies_to_mcp_serve() {
    assert_hardened(&["mcp", "serve"], true);
}

#[test]
fn hardening_applies_to_local_delivery() {
    assert_hardened(&["local-delivery", "--", "sleep", "30"], false);
}

#[test]
fn hardening_applies_to_remote_receive() {
    assert_hardened(&["remote-receive"], false);
}
