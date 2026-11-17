//! Bounded store calls (vet R6): every call runs where it can be abandoned, so a store that
//! waits on a prompt or a hung daemon costs at most the bound, never the run.

#[cfg(target_os = "linux")]
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::Instant;

#[cfg(target_os = "linux")]
use zeroize::Zeroizing;

use super::StoreFailure;

/// Run `f` on a worker thread and wait at most `timeout`. A late answer is dropped (a value
/// in it is zeroized on drop); the caller treats the store as stalled from then on.
pub(crate) fn on_worker<T, F>(timeout: Duration, f: F) -> Result<T, StoreFailure>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, StoreFailure> + Send + 'static,
{
    let (tx, rx) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("opv-credential-store".into())
        .spawn(move || {
            let _ = tx.send(f());
        })
        .map_err(|_| StoreFailure::Unavailable)?;
    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(StoreFailure::TimedOut),
        // The worker panicked: report the store as unusable, never the panic's text.
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(StoreFailure::Unavailable),
    }
}

#[cfg(target_os = "linux")]
/// A finished child: its exit code and its stdout (which may hold a value, so it is zeroized
/// on drop). Its stderr is discarded unread: opv never shows a platform tool's text here.
pub(crate) struct ChildOutput {
    pub code: Option<i32>,
    pub stdout: Zeroizing<Vec<u8>>,
}

#[cfg(target_os = "linux")]
/// Spawn `cmd` with `input` on its stdin (the only channel a value takes, ADR R2), and wait
/// at most `timeout` for it to exit. On timeout the child is killed.
pub(crate) fn run_child(
    mut cmd: Command,
    input: &[u8],
    timeout: Duration,
) -> Result<ChildOutput, StoreFailure> {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().map_err(|_| StoreFailure::Unavailable)?;
    let deadline = Instant::now() + timeout;

    let mut stdin = child.stdin.take().ok_or(StoreFailure::Unavailable)?;
    let input = Zeroizing::new(input.to_vec());
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
        // Dropping stdin closes it, so the script's ReadToEnd ends.
    });
    let mut stdout = child.stdout.take().ok_or(StoreFailure::Unavailable)?;
    let reader = std::thread::spawn(move || {
        let mut buf = Zeroizing::new(Vec::new());
        let _ = stdout.read_to_end(&mut buf);
        buf
    });

    let code = match wait_until(&mut child, deadline) {
        Some(code) => code,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(StoreFailure::TimedOut);
        }
    };
    let _ = writer.join();
    let stdout = reader.join().map_err(|_| StoreFailure::Unavailable)?;
    Ok(ChildOutput { code, stdout })
}

#[cfg(target_os = "linux")]
/// The child's exit code once it exits before `deadline`; `None` when it is still running.
fn wait_until(child: &mut Child, deadline: Instant) -> Option<Option<i32>> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status.code()),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => return None,
            Err(_) => return Some(None),
        }
    }
}
