//! Checked delivery of a `--json` document to standard output (FR-64, #265).
//!
//! Under `--json` stdout carries exactly one document, or opv exits non-zero and says why
//! on stderr. [`deliver`] writes the framed document through the output guard, checks both
//! the writes and the flush (a line-buffered stdout reports an error at the newline or only
//! on flush), and reports what was lost as [`Lost`], which becomes `LocalIo { op: Stdout }`
//! (`local_io_failed`, exit 74) with the command's own outcome.
//!
//! - `Interrupted`: the write is retried.
//! - `WouldBlock` on Unix: opv waits for the descriptor to take more (`poll(POLLOUT)`) within
//!   the run's remaining `--timeout` budget, then retries. It never clears `O_NONBLOCK`: the
//!   flag belongs to the open file description it shares with its parent.
//! - Anything else, `BrokenPipe` included, and `WouldBlock` on Windows: the delivery is lost.

use std::io::{self, Write};
use std::time::{Duration, Instant};

use crate::cause::{Cause, CommandOutcome, Delivery, IoKind, LocalOp};

/// A document that did not reach standard output: why, and how much of it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lost {
    pub io: IoKind,
    pub bytes_written: u64,
}

impl Lost {
    /// The cause opv reports: `LocalIo { op: Stdout }` naming `command`, its own `outcome`
    /// and the document's size in `bytes`.
    pub fn cause(self, command: String, outcome: CommandOutcome, bytes: u64) -> Cause {
        Cause::LocalIo {
            op: LocalOp::Stdout,
            path: std::path::PathBuf::new(),
            io: self.io,
            delivery: Some(Delivery {
                command,
                outcome,
                bytes_written: self.bytes_written,
                bytes,
            }),
        }
    }
}

/// Write `doc` to this process's standard output, waiting for a non-blocking descriptor
/// until `deadline`. Returns the number of bytes delivered.
pub fn deliver(doc: &[u8], deadline: Instant) -> Result<u64, Lost> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    deliver_to(&mut out, doc, deadline, wait_stdout_writable)
}

/// [`deliver`] to `w`; `wait(remaining)` blocks until `w` can take more bytes or
/// `remaining` passed, and says whether it can.
pub fn deliver_to<W: Write>(
    w: &mut W,
    doc: &[u8],
    deadline: Instant,
    mut wait: impl FnMut(Duration) -> bool,
) -> Result<u64, Lost> {
    // Every byte opv writes passes the output guard (design §8).
    let mut clean = Vec::with_capacity(doc.len());
    {
        let mut guard = crate::output::OutputGuard::new(&mut clean);
        guard
            .write_all(doc)
            .and_then(|()| guard.flush())
            .map_err(|e| Lost {
                io: e.kind().into(),
                bytes_written: 0,
            })?;
    }
    let mut written = 0usize;
    let lost = |e: &io::Error, written: usize| Lost {
        io: e.kind().into(),
        bytes_written: written as u64,
    };
    while written < clean.len() {
        match w.write(&clean[written..]) {
            Ok(0) => {
                return Err(lost(&io::ErrorKind::WriteZero.into(), written));
            }
            Ok(n) => written += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if may_wait(&e) => {
                if !wait_until(deadline, &mut wait) {
                    return Err(lost(&e, written));
                }
            }
            Err(e) => return Err(lost(&e, written)),
        }
    }
    loop {
        match w.flush() {
            Ok(()) => return Ok(written as u64),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if may_wait(&e) => {
                if !wait_until(deadline, &mut wait) {
                    return Err(lost(&e, written));
                }
            }
            Err(e) => return Err(lost(&e, written)),
        }
    }
}

/// A full non-blocking descriptor is waited on, on Unix only.
fn may_wait(e: &io::Error) -> bool {
    cfg!(unix) && e.kind() == io::ErrorKind::WouldBlock
}

fn wait_until(deadline: Instant, wait: &mut impl FnMut(Duration) -> bool) -> bool {
    let remaining = deadline.saturating_duration_since(Instant::now());
    !remaining.is_zero() && wait(remaining)
}

/// Waits until standard output can take more bytes (`poll(POLLOUT)`), at most `remaining`.
#[cfg(unix)]
fn wait_stdout_writable(remaining: Duration) -> bool {
    let mut fd = libc::pollfd {
        fd: libc::STDOUT_FILENO,
        events: libc::POLLOUT,
        revents: 0,
    };
    let ms = remaining.as_millis().clamp(1, i32::MAX as u128) as libc::c_int;
    // SAFETY: one valid `pollfd` on the stack, and its count is 1.
    let r = unsafe { libc::poll(&mut fd, 1, ms) };
    // An error or hang-up is ready too: the next write names it.
    r > 0 || (r < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted)
}

#[cfg(not(unix))]
fn wait_stdout_writable(_remaining: Duration) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A writer that fails its first writes with `errors`, in order, then takes everything;
    /// `flush_error` fails the flush.
    struct Scripted {
        errors: Vec<io::ErrorKind>,
        flush_error: Option<io::ErrorKind>,
        got: Vec<u8>,
    }

    impl Scripted {
        fn new(errors: &[io::ErrorKind]) -> Self {
            Self {
                errors: errors.to_vec(),
                flush_error: None,
                got: Vec::new(),
            }
        }
    }

    impl Write for Scripted {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if !self.errors.is_empty() {
                return Err(self.errors.remove(0).into());
            }
            self.got.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            match self.flush_error {
                Some(k) => Err(k.into()),
                None => Ok(()),
            }
        }
    }

    const DOC: &[u8] = b"{\"schema_version\":3,\"ok\":true}\n";

    fn later() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    #[cfg(unix)]
    #[test]
    fn retries_would_block() {
        let mut w = Scripted::new(&[io::ErrorKind::WouldBlock, io::ErrorKind::WouldBlock]);
        let _ = deliver_to(&mut w, DOC, later(), |_| true);
        assert_eq!(w.got, DOC);
    }

    #[cfg(unix)]
    #[test]
    fn would_block_past_budget_is_lost() {
        let mut w = Scripted::new(&[io::ErrorKind::WouldBlock]);
        let past = Instant::now();
        assert_eq!(
            deliver_to(&mut w, DOC, past, |_| true).map_err(|l| l.io),
            Err(IoKind::WouldBlock)
        );
    }

    #[test]
    fn broken_pipe_is_lost() {
        let mut w = Scripted::new(&[io::ErrorKind::BrokenPipe]);
        assert_eq!(
            deliver_to(&mut w, DOC, later(), |_| true).map_err(|l| l.io),
            Err(IoKind::BrokenPipe)
        );
    }

    #[test]
    fn no_space_is_lost() {
        let mut w = Scripted::new(&[io::ErrorKind::StorageFull]);
        assert_eq!(
            deliver_to(&mut w, DOC, later(), |_| true).map_err(|l| l.io),
            Err(IoKind::NoSpace)
        );
    }

    #[test]
    fn flush_error_is_lost() {
        let mut w = Scripted::new(&[]);
        w.flush_error = Some(io::ErrorKind::StorageFull);
        assert!(deliver_to(&mut w, DOC, later(), |_| true).is_err());
    }

    #[test]
    fn interrupted_is_retried() {
        let mut w = Scripted::new(&[io::ErrorKind::Interrupted]);
        let _ = deliver_to(&mut w, DOC, later(), |_| false);
        assert_eq!(w.got, DOC);
    }

    #[test]
    fn a_lost_document_is_stdout_local_io() {
        let lost = Lost {
            io: IoKind::BrokenPipe,
            bytes_written: 0,
        };
        assert_eq!(
            lost.cause("version".into(), CommandOutcome::Ok, 10).code(),
            "local_io_failed"
        );
    }
}
