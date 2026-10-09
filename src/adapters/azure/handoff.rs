//! How a value reaches `az` without argv, env or a file (SR-3, SR-4, NR-14).
//!
//! `az` reads a value from a path argument (`--file <path>`, `--yaml <path>`, `-p @<path>`).
//! Callers write `/dev/stdin` there; [`deliver`] swaps in what the platform's [`Handoff`]
//! serves:
//! - Linux, WSL, macOS: `/dev/stdin`, with the bytes on the child's stdin.
//! - Windows: a named pipe `\\.\pipe\opv-<random>` whose security grants only the current
//!   user and rejects remote clients. A server thread waits for `az` to connect, writes
//!   the bytes and closes the handle (closing, not disconnecting: a disconnect makes the
//!   Python reader inside `az` fail or read corrupted data). Each connection gets its own
//!   server instance, up to [`MAX_CONNECTIONS`]. If `az` exits without ever connecting,
//!   the hand-off reports it and the value went nowhere.
//!
//!   The pipe's name is visible in az's command line, so before writing a byte the server
//!   checks who connected (M1): `GetNamedPipeClientProcessId` must name the `az` process
//!   opv started (the runner's tracked child) or one of its descendants (`az.cmd` runs
//!   Python as a child), found by walking the client's parent chain in a process
//!   snapshot. Any other client is closed unread, and the call fails afterwards even if
//!   `az` read the value too, so a stolen read never goes unnoticed. (Serving exactly one
//!   connection was the fallback; az may open the path more than once, so the client
//!   check was chosen.)

use std::io;

use crate::error::Error;
use crate::runner::Outcome;

/// The placeholder callers put where `az` takes a value path.
pub const STDIN_PATH: &str = "/dev/stdin";

/// Connections one Windows hand-off serves (az may open the path more than once).
pub const MAX_CONNECTIONS: usize = 3;

/// A way to hand one value to one `az` call.
pub trait Handoff: Sync {
    /// Start serving `data` for the next call.
    fn offer(&self, data: &[u8]) -> Result<Box<dyn Offer>, Error>;
}

/// One value being served.
pub trait Offer {
    /// The path `az` reads the value from.
    fn path(&self) -> &str;
    /// True when the bytes go on the child's stdin.
    fn on_stdin(&self) -> bool;
    /// After the call: stop serving. `Err` when `az` never read the value.
    fn finish(self: Box<Self>) -> Result<(), Error>;
}

/// `/dev/stdin` and the child's stdin (every platform but Windows).
pub struct Stdin;

struct StdinOffer;

impl Offer for StdinOffer {
    fn path(&self) -> &str {
        STDIN_PATH
    }
    fn on_stdin(&self) -> bool {
        true
    }
    fn finish(self: Box<Self>) -> Result<(), Error> {
        Ok(())
    }
}

impl Handoff for Stdin {
    fn offer(&self, _data: &[u8]) -> Result<Box<dyn Offer>, Error> {
        Ok(Box::new(StdinOffer))
    }
}

/// The platform's hand-off.
pub fn platform() -> &'static dyn Handoff {
    #[cfg(windows)]
    {
        &pipe::Pipe
    }
    #[cfg(not(windows))]
    {
        &Stdin
    }
}

/// The call [`deliver`] runs: rewritten argv and the stdin to send.
pub type Run<'a> = dyn FnMut(&[&str], Option<&[u8]>) -> io::Result<Outcome> + 'a;

/// Run one call that reads `data`, if any: every argument equal to [`STDIN_PATH`] (or
/// `@` + it) is replaced by the offer's path, and `run` gets the rewritten argv and the
/// stdin to send. A call that succeeded although `az` never read the value is an error.
pub fn deliver(
    handoff: &dyn Handoff,
    args: &[&str],
    data: Option<&[u8]>,
    run: &mut Run<'_>,
) -> Result<io::Result<Outcome>, Error> {
    let Some(data) = data else {
        return Ok(run(args, None));
    };
    let offer = handoff.offer(data)?;
    let at = format!("@{}", offer.path());
    let at_stdin = format!("@{STDIN_PATH}");
    let rewritten: Vec<&str> = args
        .iter()
        .map(|a| match *a {
            STDIN_PATH => offer.path(),
            a if a == at_stdin => at.as_str(),
            a => a,
        })
        .collect();
    let res = run(&rewritten, offer.on_stdin().then_some(data));
    let served = offer.finish();
    match (&res, served) {
        (Ok(Outcome::Done(_)), Err(e)) => Err(e),
        _ => Ok(res),
    }
}

#[cfg(windows)]
pub(crate) mod pipe {
    //! The Windows named-pipe server (see the module docs above).

    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_PIPE_CONNECTED, GENERIC_READ, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING, PIPE_ACCESS_OUTBOUND, WriteFile,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };
    use zeroize::Zeroizing;

    use super::{MAX_CONNECTIONS, Offer};
    use crate::adapters::azure::winsec::{UserOnly, wide};
    use crate::error::Error;

    pub struct Pipe;

    impl super::Handoff for Pipe {
        fn offer(&self, data: &[u8]) -> Result<Box<dyn Offer>, Error> {
            Ok(Box::new(Server::start(data, started_by_opv)?))
        }
    }

    /// Who may read the value: a client process id is accepted when this returns true.
    pub type Accept = fn(u32) -> bool;

    /// The client is the `az` process opv started for this call, or a descendant of it
    /// (M1). The child is tracked right after it is spawned; a client that connects first
    /// waits for that, up to two seconds.
    fn started_by_opv(client: u32) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let child = loop {
            match crate::runner::signals::current_child() {
                Some(c) => break c,
                None if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                None => return false,
            }
        };
        descends_from(client, child)
    }

    /// Whether `pid` is `ancestor` or below it, by the parent chain of a process snapshot
    /// (at most 16 levels; a parent id that was reused ends the walk).
    fn descends_from(pid: u32, ancestor: u32) -> bool {
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
            TH32CS_SNAPPROCESS,
        };
        if pid == ancestor {
            return true;
        }
        // SAFETY: a snapshot handle closed before returning; entries are plain structs
        // with `dwSize` set as the API requires.
        let parents: std::collections::HashMap<u32, u32> = unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE_VALUE {
                return false;
            }
            let mut map = std::collections::HashMap::new();
            let mut e = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };
            let mut ok = Process32FirstW(snap, &mut e) != 0;
            while ok {
                map.insert(e.th32ProcessID, e.th32ParentProcessID);
                ok = Process32NextW(snap, &mut e) != 0;
            }
            CloseHandle(snap);
            map
        };
        let mut cur = pid;
        for _ in 0..16 {
            match parents.get(&cur) {
                Some(&p) if p == ancestor => return true,
                Some(&p) if p != 0 && p != cur => cur = p,
                _ => return false,
            }
        }
        false
    }

    /// A pipe server for one value.
    pub struct Server {
        path: String,
        served: Arc<AtomicUsize>,
        /// Connections from a client that is not `az` (closed unread, M1).
        refused: Arc<AtomicUsize>,
        done: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    fn pipe_error(what: &str) -> Error {
        Error::Dependency(
            format!(
                "cannot create the private pipe that hands the value to az ({what}, error {}); \
             nothing was changed",
                unsafe { GetLastError() }
            )
            .into(),
        )
    }

    /// One server instance of `path`, user-only.
    fn instance(path: &[u16], sec: &UserOnly, first: bool, size: u32) -> HANDLE {
        let flags = PIPE_ACCESS_OUTBOUND
            | if first {
                FILE_FLAG_FIRST_PIPE_INSTANCE
            } else {
                0
            };
        // SAFETY: path is NUL-terminated; the security attributes outlive the call.
        unsafe {
            CreateNamedPipeW(
                path.as_ptr(),
                flags,
                PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                size,
                0,
                0,
                sec.attributes(),
            )
        }
    }

    impl Server {
        /// Serve `data` to clients `accept` approves (production: [`started_by_opv`]).
        pub fn start(data: &[u8], accept: Accept) -> Result<Self, Error> {
            use std::hash::BuildHasher;
            let random =
                std::collections::hash_map::RandomState::new().hash_one(std::time::Instant::now());
            let path = format!(r"\\.\pipe\opv-{}-{random:016x}", std::process::id());
            let wpath = wide(&path);
            let sec = UserOnly::new(false).map_err(|_| pipe_error("security"))?;
            let size = u32::try_from(data.len().max(4096)).unwrap_or(u32::MAX);
            let first = instance(&wpath, &sec, true, size);
            if first == INVALID_HANDLE_VALUE {
                return Err(pipe_error("create"));
            }
            let first = first as usize;
            let data = Zeroizing::new(data.to_vec());
            let served = Arc::new(AtomicUsize::new(0));
            let refused = Arc::new(AtomicUsize::new(0));
            let done = Arc::new(AtomicBool::new(false));
            let (s, d, x) = (Arc::clone(&served), Arc::clone(&done), Arc::clone(&refused));
            let thread = std::thread::spawn(move || {
                let mut handle = first as HANDLE;
                for n in 0..MAX_CONNECTIONS {
                    // SAFETY: a valid pipe handle owned by this thread.
                    let ok = unsafe { ConnectNamedPipe(handle, std::ptr::null_mut()) } != 0
                        || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
                    if d.load(Ordering::SeqCst) {
                        unsafe { CloseHandle(handle) };
                        return;
                    }
                    let mut client = 0u32;
                    // SAFETY: a connected pipe handle owned by this thread.
                    let known = ok
                        && unsafe { GetNamedPipeClientProcessId(handle, &mut client) } != 0
                        && accept(client);
                    if ok && !known {
                        x.fetch_add(1, Ordering::SeqCst);
                    }
                    if known {
                        let mut off = 0usize;
                        while off < data.len() {
                            let mut wrote = 0u32;
                            let chunk = u32::try_from(data.len() - off).unwrap_or(u32::MAX);
                            // SAFETY: the buffer is valid for `chunk` bytes.
                            let w = unsafe {
                                WriteFile(
                                    handle,
                                    data[off..].as_ptr(),
                                    chunk,
                                    &mut wrote,
                                    std::ptr::null_mut(),
                                )
                            };
                            if w == 0 || wrote == 0 {
                                break;
                            }
                            off += wrote as usize;
                        }
                        if off == data.len() {
                            s.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    // Close, never disconnect: the reader gets every byte, then EOF.
                    unsafe { CloseHandle(handle) };
                    if n + 1 == MAX_CONNECTIONS {
                        return;
                    }
                    handle = instance(&wpath, &sec, false, size);
                    if handle == INVALID_HANDLE_VALUE {
                        return;
                    }
                }
            });
            Ok(Self {
                path,
                served,
                refused,
                done,
                thread: Some(thread),
            })
        }

        /// Connections that received every byte so far.
        pub fn served(&self) -> usize {
            self.served.load(Ordering::SeqCst)
        }
    }

    impl Offer for Server {
        fn path(&self) -> &str {
            &self.path
        }
        fn on_stdin(&self) -> bool {
            false
        }
        fn finish(mut self: Box<Self>) -> Result<(), Error> {
            self.stop();
            if self.refused.load(Ordering::SeqCst) > 0 {
                return Err(Error::Target(
                    "another process connected to opv's private pipe for az and was refused; \
                     nothing was sent to it, but treat this machine as untrusted\n  next: \
                     check the processes running as you, then run opv again"
                        .into(),
                ));
            }
            if self.served() == 0 {
                return Err(Error::Target(
                    "az exited without reading the value from opv's private pipe; nothing was \
                     sent\n  next: check that az version runs, then run opv again"
                        .into(),
                ));
            }
            Ok(())
        }
    }

    impl Server {
        /// Wake a server instance still waiting for a client, and join the thread.
        fn stop(&mut self) {
            self.done.store(true, Ordering::SeqCst);
            let Some(t) = self.thread.take() else { return };
            let w = wide(&self.path);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while !t.is_finished() && std::time::Instant::now() < deadline {
                // SAFETY: opening our own pipe as a client only unblocks ConnectNamedPipe.
                let h = unsafe {
                    CreateFileW(
                        w.as_ptr(),
                        GENERIC_READ,
                        0,
                        std::ptr::null(),
                        OPEN_EXISTING,
                        0,
                        std::ptr::null_mut(),
                    )
                };
                if h != INVALID_HANDLE_VALUE {
                    unsafe { CloseHandle(h) };
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            if t.is_finished() {
                let _ = t.join();
            }
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.stop();
        }
    }

    #[cfg(test)]
    mod tests {
        use std::io::Read;

        use super::*;

        /// The test reads the pipe itself: this process is the approved client.
        fn this_process(pid: u32) -> bool {
            pid == std::process::id()
        }

        #[test]
        fn a_client_reads_the_exact_bytes() {
            let data: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
            let server = Server::start(&data, this_process).unwrap();
            let mut got = Vec::new();
            std::fs::File::open(server.path())
                .unwrap()
                .read_to_end(&mut got)
                .unwrap();
            assert_eq!(got, data);
        }

        #[test]
        fn finish_without_a_reader_is_an_error() {
            let server = Box::new(Server::start(b"x", this_process).unwrap());
            assert!(server.finish().is_err());
        }

        /// M1: a client that is not the az process opv started reads nothing.
        #[test]
        fn an_unknown_client_reads_nothing() {
            let server = Server::start(b"FIXTUREVALUE", |_| false).unwrap();
            let mut got = Vec::new();
            let _ = std::fs::File::open(server.path()).and_then(|mut f| f.read_to_end(&mut got));
            assert!(got.is_empty());
        }

        /// M1: and the call fails, so a stolen read never goes unnoticed.
        #[test]
        fn an_unknown_client_fails_the_call() {
            let server = Server::start(b"FIXTUREVALUE", |_| false).unwrap();
            let _ = std::fs::File::open(server.path()).map(|mut f| f.read_to_end(&mut Vec::new()));
            assert!(Box::new(server).finish().is_err());
        }

        #[test]
        fn the_child_itself_is_its_own_descendant() {
            assert!(descends_from(std::process::id(), std::process::id()));
        }

        #[test]
        fn the_pipe_grants_only_the_current_user() {
            let sddl = crate::adapters::azure::winsec::UserOnly::sddl(false).unwrap();
            assert!(sddl.starts_with("D:P(A;;GA;;;S-1-5-") && sddl.matches("(A;").count() == 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::runner::Output;

    /// A pipe-like hand-off: its own path, nothing on stdin, `read` decides `finish`.
    struct FakePipe {
        read: bool,
    }
    struct FakeOffer {
        read: bool,
    }
    impl Offer for FakeOffer {
        fn path(&self) -> &str {
            r"\\.\pipe\opv-test"
        }
        fn on_stdin(&self) -> bool {
            false
        }
        fn finish(self: Box<Self>) -> Result<(), Error> {
            if self.read {
                Ok(())
            } else {
                Err(Error::Target("never read".into()))
            }
        }
    }
    impl Handoff for FakePipe {
        fn offer(&self, _: &[u8]) -> Result<Box<dyn Offer>, Error> {
            Ok(Box::new(FakeOffer { read: self.read }))
        }
    }

    fn run_with(h: &dyn Handoff, args: &[&str]) -> (Vec<String>, Option<Vec<u8>>, bool) {
        let seen = RefCell::new((Vec::new(), None));
        let res = deliver(h, args, Some(b"FIXTUREVALUE"), &mut |a, s| {
            *seen.borrow_mut() = (
                a.iter().map(|x| x.to_string()).collect(),
                s.map(<[u8]>::to_vec),
            );
            Ok(Outcome::Done(Output::success(Vec::new())))
        });
        let (a, s) = seen.into_inner();
        (a, s, res.is_ok())
    }

    #[test]
    fn stdin_handoff_keeps_dev_stdin_and_sends_the_bytes_on_stdin() {
        let (args, stdin, _) = run_with(&Stdin, &["--file", STDIN_PATH]);
        assert_eq!(
            (args, stdin),
            (
                vec!["--file".into(), STDIN_PATH.into()],
                Some(b"FIXTUREVALUE".to_vec())
            )
        );
    }

    #[test]
    fn pipe_handoff_rewrites_the_path_and_sends_nothing_on_stdin() {
        let (args, stdin, _) = run_with(&FakePipe { read: true }, &["-p", "@/dev/stdin"]);
        assert_eq!(
            (args, stdin),
            (vec!["-p".into(), r"@\\.\pipe\opv-test".into()], None)
        );
    }

    #[test]
    fn a_value_never_read_fails_the_call() {
        let (_, _, ok) = run_with(&FakePipe { read: false }, &["--file", STDIN_PATH]);
        assert!(!ok);
    }
}
