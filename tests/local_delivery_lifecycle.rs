//! #136 A1: the private RAM directory `opv run` creates for a product's `file` keys
//! (`opv-run.<pid>-<random>`) never outlives its run. The directory is created, filled and
//! removed by the delivery step `opv run` starts as `op run`'s child
//! (`opv local-delivery`), so these integration tests drive that step as the real binary
//! with a private tmpfs `$XDG_RUNTIME_DIR` of their own. Test markers only: no real
//! credential is used, and the marker is never printed.
#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// The marker value the step writes to the file; a canary, never a real credential.
const MARKER: &str = "S7MARKERlifecycle0001";

/// The step's file arguments: one key delivered as `github-app/private-key` under the
/// directory named by `APP_SECRETS_DIR`, declared-only.
const FILE_ARGS: &[&str] = &[
    "--key",
    "GITHUB_APP_PRIVATE_KEY",
    "--file",
    "GITHUB_APP_PRIVATE_KEY=github-app/private-key",
    "--dir-env",
    "APP_SECRETS_DIR",
    "--declared-only",
];

/// A private tmpfs directory for `$XDG_RUNTIME_DIR`, owned by this test; `None` where the
/// machine has no RAM directory (the file scenarios are then skipped).
fn runtime_dir() -> Option<tempfile::TempDir> {
    let dir = tempfile::Builder::new().tempdir_in("/dev/shm").ok()?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).ok()?;
    let st = rustix::fs::statfs(dir.path()).ok()?;
    #[allow(clippy::unnecessary_cast)]
    let magic = (st.f_type as u64) & 0xffff_ffff;
    (magic == 0x0102_1994).then_some(dir)
}

/// The `opv-run.*` paths under `rt` now, sorted.
fn run_dirs(rt: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(rt)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("opv-run."))
        })
        .collect();
    v.sort();
    v
}

/// Wait up to `timeout` for `ready`; false on timeout.
fn wait_until(timeout: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    loop {
        if ready() {
            return true;
        }
        if start.elapsed() >= timeout {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The delivery step under `$XDG_RUNTIME_DIR=rt`, running `sh -c script` with the marker.
fn step(rt: &Path, script: &str) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_opv"));
    c.args(["local-delivery"])
        .args(FILE_ARGS)
        .args(["--", "sh", "-c", script])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("XDG_RUNTIME_DIR", rt)
        .env("GITHUB_APP_PRIVATE_KEY", MARKER)
        .stdin(Stdio::null());
    c
}

/// A delivery step in its own process group, so a signal reaches it as a terminal's
/// Ctrl-C or a dropped SSH session reaches `opv run`'s whole foreground group.
fn spawn_in_group(rt: &Path, script: &str) -> Child {
    step(rt, script)
        .process_group(0)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

/// Wait for the step's one directory, or end it and panic (a broken arrangement).
fn wait_for_one_dir(rt: &Path, child: &mut Child, pgid: i32) {
    if !wait_until(Duration::from_secs(5), || run_dirs(rt).len() == 1) {
        unsafe { libc::kill(-pgid, libc::SIGKILL) };
        let _ = child.wait();
        panic!("the delivery step created no opv-run.* directory");
    }
}

/// Signal the step's process group with `sig`; what is left under `rt` once it exits.
fn dirs_left_after_signal(rt: &Path, sig: i32) -> Vec<PathBuf> {
    let mut child = spawn_in_group(rt, "exec sleep 60");
    let pgid = child.id() as i32;
    wait_for_one_dir(rt, &mut child, pgid);
    unsafe { libc::kill(-pgid, sig) };
    let _ = child.wait();
    let _ = wait_until(Duration::from_secs(5), || run_dirs(rt).is_empty());
    run_dirs(rt)
}

#[test]
fn an_interrupt_leaves_no_run_directory() {
    let Some(rt) = runtime_dir() else { return };
    assert!(dirs_left_after_signal(rt.path(), libc::SIGINT).is_empty());
}

#[test]
fn a_terminate_leaves_no_run_directory() {
    let Some(rt) = runtime_dir() else { return };
    assert!(dirs_left_after_signal(rt.path(), libc::SIGTERM).is_empty());
}

#[test]
fn a_hangup_leaves_no_run_directory() {
    let Some(rt) = runtime_dir() else { return };
    assert!(dirs_left_after_signal(rt.path(), libc::SIGHUP).is_empty());
}

/// SIGKILL ends the step before its handler runs: the directory stays until the next run
/// of any product sweeps the directories of processes that are gone.
#[test]
fn a_killed_delivery_step_leaves_a_directory_the_next_run_sweeps() {
    let Some(rt) = runtime_dir() else { return };
    let mut child = spawn_in_group(rt.path(), "exec sleep 60");
    let pgid = child.id() as i32;
    wait_for_one_dir(rt.path(), &mut child, pgid);
    let stale = run_dirs(rt.path()).remove(0);
    unsafe { libc::kill(-pgid, libc::SIGKILL) };
    let _ = child.wait();
    if !stale.exists() {
        panic!("SIGKILL left no directory to sweep: {}", stale.display());
    }
    let status = step(rt.path(), "true")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    if !status.success() {
        panic!("the next delivery step failed: {status}");
    }
    assert!(
        !stale.exists(),
        "the next run did not sweep {}",
        stale.display()
    );
}

#[test]
fn a_missing_command_leaves_no_run_directory() {
    let Some(rt) = runtime_dir() else { return };
    let _ = Command::new(env!("CARGO_BIN_EXE_opv"))
        .args(["local-delivery"])
        .args(FILE_ARGS)
        .arg("--")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("XDG_RUNTIME_DIR", rt.path())
        .env("GITHUB_APP_PRIVATE_KEY", MARKER)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(run_dirs(rt.path()).is_empty());
}

/// Two file keys: the second path (`a/b/c`) nests inside the first's file (`a/b`), so its
/// parent component exists as a file, not a directory: the step refuses after the first
/// write. The whole run fails before the app starts.
const PARTIAL_ARGS: &[&str] = &[
    "--key",
    "ONE",
    "--file",
    "ONE=a/b",
    "--key",
    "TWO",
    "--file",
    "TWO=a/b/c",
    "--dir-env",
    "APP_SECRETS_DIR",
    "--declared-only",
];

fn partial_step(rt: &Path, script: &str) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_opv"));
    c.args(["local-delivery"])
        .args(PARTIAL_ARGS)
        .args(["--", "sh", "-c", script])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("XDG_RUNTIME_DIR", rt)
        .env("ONE", MARKER)
        .env("TWO", MARKER)
        .stdin(Stdio::null());
    c
}

#[test]
fn a_failed_write_after_the_first_file_leaves_no_run_directory() {
    let Some(rt) = runtime_dir() else { return };
    let _ = partial_step(rt.path(), "true").output().unwrap();
    assert!(run_dirs(rt.path()).is_empty());
}

#[test]
fn a_failed_write_after_the_first_file_starts_nothing() {
    let Some(rt) = runtime_dir() else { return };
    let work = tempfile::tempdir().unwrap();
    let started = work.path().join("started");
    let script = format!("touch {}", started.display());
    let _ = partial_step(rt.path(), &script).output().unwrap();
    assert!(!started.exists());
}
