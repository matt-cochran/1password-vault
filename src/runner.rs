//! Subprocess seam for adapters (`op`, `flyctl`, `az`). Adapters depend on [`CommandRunner`],
//! so tests can substitute [`fake::FakeRunner`] and assert what was (and was not) passed.
//!
//! Contract (SR-3, SR-7): secret values go in `stdin` only, never in `args`; programs are
//! invoked directly, never through a shell. `env` is for configuration such as tokens.
//!
//! Every captured call has an effect (NR-2, NR-3): [`CommandRunner::read`] is idempotent and
//! retried with backoff inside the run [`Budget`]; [`CommandRunner::write`] is never retried,
//! and any write that does not finish with exit 0 has an [`Outcome::Unknown`] outcome. A
//! write cannot be retried by mistake because the API that retries does not accept one.
//!
//! Per call (NR-4, NR-5, NR-7, NR-11): a deadline per effect ([`READ_TIMEOUT`],
//! [`WRITE_TIMEOUT`], [`PROBE_TIMEOUT`]) capped by the run budget, stdout capped at
//! [`OUTPUT_CAP`], stdin `/dev/null` unless the call sends some, and the program's
//! [`pinned_env`] on top of the inherited environment (proxy and CA variables pass through
//! untouched, NR-29). Deadlines use monotonic time only (NR-21).

use std::io::{self, Read, Write};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use zeroize::{Zeroize, Zeroizing};

/// Result of a finished process. `stdout` may contain secret values, so it is zeroized on
/// drop (SR-8) and `Debug` prints only its length.
pub struct Output {
    /// Exit status; [`OVER_CAP`] when stdout exceeded [`OUTPUT_CAP`].
    pub status: i32,
    pub stdout: Zeroizing<Vec<u8>>,
}

impl Output {
    pub fn success(stdout: impl Into<Vec<u8>>) -> Self {
        Self {
            status: 0,
            stdout: Zeroizing::new(stdout.into()),
        }
    }

    pub fn failure(status: i32) -> Self {
        Self {
            status,
            stdout: Zeroizing::new(Vec::new()),
        }
    }
}

impl std::fmt::Debug for Output {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Output")
            .field("status", &self.status)
            .field("stdout_len", &self.stdout.len())
            .finish()
    }
}

/// One captured external call. Never put a secret value in `args` (SR-3); it goes in
/// `stdin`. `Debug` shows the program and argv only.
#[derive(Clone, Copy)]
pub struct Call<'a> {
    pub program: &'a str,
    pub args: &'a [&'a str],
    pub stdin: Option<&'a [u8]>,
    pub env: &'a [(&'a str, &'a str)],
}

impl<'a> Call<'a> {
    /// A call with no stdin and no extra env.
    pub fn new(program: &'a str, args: &'a [&'a str]) -> Self {
        Self {
            program,
            args,
            stdin: None,
            env: &[],
        }
    }

    /// The same call sending `stdin`.
    pub fn with_stdin(self, stdin: Option<&'a [u8]>) -> Self {
        Self { stdin, ..self }
    }

    /// `<program> <first two argv words>`: the step name used in retry and signal lines.
    pub fn step(&self) -> String {
        std::iter::once(self.program)
            .chain(self.args.iter().take(2).copied())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl std::fmt::Debug for Call<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let env: Vec<&str> = self.env.iter().map(|(k, _)| *k).collect();
        f.debug_struct("Call")
            .field("program", &self.program)
            .field("args", &self.args)
            .field("stdin_len", &self.stdin.map(<[u8]>::len))
            .field("env_names", &env)
            .finish()
    }
}

/// What a captured call came to (NR-2).
#[derive(Debug)]
pub enum Outcome {
    /// Exit 0.
    Done(Output),
    /// A definite answer that is not success: a read whose exit code is in its `refused`
    /// list, a read still failing after its last attempt, or stdout over [`OUTPUT_CAP`]
    /// (status [`OVER_CAP`]). Nothing changed.
    Refused(Output),
    /// The call may or may not have taken effect. `reason` is `timeout`, `killed`, `lost`
    /// (the call ran but its result could not be collected) or `failed-write` (a write
    /// exited non-zero; `status` holds its exit code).
    Unknown {
        reason: &'static str,
        status: Option<i32>,
    },
}

impl Outcome {
    fn unknown(reason: &'static str) -> Self {
        Outcome::Unknown {
            reason,
            status: None,
        }
    }
}

/// The run budget (`--timeout`, NR-4): no call starts or runs past `deadline`. Monotonic
/// time only (NR-21).
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub deadline: Instant,
}

impl Budget {
    /// A budget of `limit` from now.
    pub fn starting_now(limit: Duration) -> Self {
        Self {
            deadline: Instant::now() + limit,
        }
    }
}

impl Default for Budget {
    fn default() -> Self {
        Self::starting_now(DEFAULT_RUN_TIMEOUT)
    }
}

pub trait CommandRunner {
    /// Idempotent call. Retried up to [`READ_ATTEMPTS`] attempts (backoff 1 s, 2 s, ±25 %
    /// jitter) on any failure whose exit code is not in `refused` (a timeout, a kill or a
    /// lost call included; not opv's own interrupt), within the run budget. A spawn error
    /// (e.g. the program is missing) is an `Err` and is not retried, as is a read the
    /// spent budget never let start (`TimedOut`).
    fn read(&self, call: &Call, refused: &[i32]) -> io::Result<Outcome>;

    /// Non-idempotent call. Never retried. A non-zero exit, timeout or kill is
    /// [`Outcome::Unknown`]. `Err` only when the program could not be started (nothing ran).
    fn write(&self, call: &Call) -> io::Result<Outcome>;

    /// A short read-only diagnosis call (`op whoami`, `flyctl auth whoami`, version
    /// checks; FR-26): killed after `limit` (a `TimedOut` error), never retried; the exit
    /// status is returned as is.
    fn probe(&self, call: &Call, limit: Duration) -> io::Result<Output>;

    /// Run `program` with inherited stdin/stdout/stderr and the given extra `env`, wait, and
    /// return its exit code (`128 + signal` if it was killed by a signal). Used by `run`
    /// (FR-4) to spawn `op run -- <cmd>`. Same contract: no secret values in `args`.
    fn run_inherited(&self, program: &str, args: &[&str], env: &[(&str, &str)]) -> io::Result<i32>;

    /// Check that the native CLI can execute a child for local run (not metadata reads).
    fn local_run_supported(&self) -> io::Result<()> {
        Ok(())
    }

    /// Remove managed parent variables before adding selected references.
    fn run_inherited_clean(
        &self,
        program: &str,
        args: &[&str],
        env: &[(&str, &str)],
        remove: &[String],
    ) -> io::Result<i32> {
        if remove.is_empty() {
            self.run_inherited(program, args, env)
        } else {
            Err(io::ErrorKind::Unsupported.into())
        }
    }
}

/// Limit for one diagnosis call ([`CommandRunner::probe`]).
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(15);
/// Limit for one attempt of a read.
pub const READ_TIMEOUT: Duration = Duration::from_secs(60);
/// Limit for one write.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(120);
/// Default run budget (`--timeout`).
pub const DEFAULT_RUN_TIMEOUT: Duration = Duration::from_secs(900);
/// Captured stdout above this many bytes is refused and the child killed (NR-5).
pub const OUTPUT_CAP: usize = 8 * 1024 * 1024;
/// Attempts per read, the first one included (NR-3).
pub const READ_ATTEMPTS: u32 = 3;
/// `Output::status` of a call whose stdout exceeded [`OUTPUT_CAP`].
pub const OVER_CAP: i32 = -2;
/// Time a child gets after a forwarded SIGINT/SIGTERM before it is killed (NR-12).
pub const SIGNAL_GRACE: Duration = Duration::from_secs(5);

/// Pinned per-CLI environment (NR-7, NR-11), added on top of the inherited environment for
/// every captured call by program name: it neutralises user configuration that changes
/// output or prompts. Proxy and CA variables are never set here (NR-29).
pub fn pinned_env(program: &str) -> &'static [(&'static str, &'static str)] {
    match program {
        "az" => &[
            ("AZURE_EXTENSION_USE_DYNAMIC_INSTALL", "no"),
            ("AZURE_CORE_NO_COLOR", "true"),
            ("AZURE_CORE_ONLY_SHOW_ERRORS", "true"),
            ("AZURE_CORE_COLLECT_TELEMETRY", "no"),
            ("AZURE_CORE_OUTPUT", "json"),
        ],
        "flyctl" => &[("FLY_NO_UPDATE_CHECK", "1"), ("NO_COLOR", "1")],
        "op" => &[("NO_COLOR", "1")],
        _ => &[],
    }
}

/// `exit N`, or the cap for [`OVER_CAP`]: the parenthesised part of "X failed (...)".
pub fn status_text(status: i32) -> String {
    if status == OVER_CAP {
        format!("output over the {} MiB cap", OUTPUT_CAP / (1024 * 1024))
    } else {
        format!("exit {status}")
    }
}

/// A value-free sentence for an [`Outcome::Unknown`] reason of `program`.
pub fn unknown_text(program: &str, reason: &str) -> String {
    match reason {
        "timeout" => format!("{program} did not finish in time and was killed"),
        "killed" => format!("{program} was killed before it finished"),
        "lost" => format!("{program} ran but its result was lost"),
        _ => format!("{program} failed"),
    }
}

/// The `--verbose` line for one call (NR-22): program, argv, duration and outcome. Never
/// stdin or env values (SR-1, SR-3).
pub fn verbose_line(call: &Call, elapsed: Duration, outcome: &str) -> String {
    let mut argv = call.program.to_string();
    for a in call.args {
        argv.push(' ');
        argv.push_str(a);
    }
    format!("{argv} ({:.2} s): {outcome}", elapsed.as_secs_f64())
}

/// What one attempt of a captured call produced.
enum Attempt {
    Exited(Output),
    TimedOut,
    Killed,
    Lost,
    OverCap,
}

impl Attempt {
    fn describe(&self) -> String {
        match self {
            Attempt::Exited(o) => status_text(o.status),
            Attempt::TimedOut => "timeout".into(),
            Attempt::Killed => "killed".into(),
            Attempt::Lost => "lost".into(),
            Attempt::OverCap => status_text(OVER_CAP),
        }
    }
}

/// Clock, budget, diagnostics and one attempt: what the shared read/write/probe logic needs
/// from a runner. [`ProcessRunner`] uses real time; the fake a fake clock.
trait Engine {
    fn now(&self) -> Instant;
    fn deadline(&self) -> Instant;
    fn sleep(&self, d: Duration);
    /// A factor in [-0.25, 0.25] applied to each backoff delay.
    fn jitter(&self) -> f64;
    /// One stderr line (retry notices).
    fn note(&self, line: &str);
    fn attempt(&self, call: &Call, limit: Duration) -> io::Result<Attempt>;
}

fn left(e: &dyn Engine) -> Duration {
    e.deadline().saturating_duration_since(e.now())
}

/// Delay before attempt `n + 1` (n ≥ 1): 1 s, 2 s, 4 s, … scaled by `1 + jitter`.
fn backoff(n: u32, jitter: f64) -> Duration {
    Duration::from_secs(1 << (n - 1)).mul_f64(1.0 + jitter)
}

fn read_on(e: &dyn Engine, call: &Call, refused: &[i32]) -> io::Result<Outcome> {
    let mut n = 1;
    loop {
        let limit = READ_TIMEOUT.min(left(e));
        if limit.is_zero() {
            return Err(budget_spent(call));
        }
        let failed = match e.attempt(call, limit)? {
            Attempt::Exited(o) if o.status == 0 => return Ok(Outcome::Done(o)),
            Attempt::Exited(o) if refused.contains(&o.status) => return Ok(Outcome::Refused(o)),
            Attempt::Exited(o) => Outcome::Refused(o),
            Attempt::OverCap => return Ok(Outcome::Refused(Output::failure(OVER_CAP))),
            // opv's own interrupt never retries: the run is stopping (NR-12).
            Attempt::Killed if signals::stopping() => return Ok(Outcome::unknown("killed")),
            Attempt::Killed => Outcome::unknown("killed"),
            Attempt::TimedOut => Outcome::unknown("timeout"),
            Attempt::Lost => Outcome::unknown("lost"),
        };
        if n >= READ_ATTEMPTS {
            return Ok(failed);
        }
        let delay = backoff(n, e.jitter());
        if delay >= left(e) {
            return Ok(failed);
        }
        n += 1;
        e.note(&format!(
            "retrying {} ({n}/{READ_ATTEMPTS}) in {:.1} s",
            call.step(),
            delay.as_secs_f64()
        ));
        e.sleep(delay);
    }
}

/// The call was never started: the run budget (`--timeout`) is spent.
fn budget_spent(call: &Call) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!("the run budget ran out before {} started", call.step()),
    )
}

fn write_on(e: &dyn Engine, call: &Call) -> io::Result<Outcome> {
    let limit = WRITE_TIMEOUT.min(left(e));
    if limit.is_zero() {
        return Err(budget_spent(call));
    }
    Ok(match e.attempt(call, limit)? {
        Attempt::Exited(o) if o.status == 0 => Outcome::Done(o),
        Attempt::Exited(o) => Outcome::Unknown {
            reason: "failed-write",
            status: Some(o.status),
        },
        Attempt::OverCap => Outcome::unknown("failed-write"),
        Attempt::TimedOut => Outcome::unknown("timeout"),
        Attempt::Killed => Outcome::unknown("killed"),
        Attempt::Lost => Outcome::unknown("lost"),
    })
}

fn probe_on(e: &dyn Engine, call: &Call, limit: Duration) -> io::Result<Output> {
    let limit = limit.min(left(e));
    let timed_out = || {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "{} did not finish within {} s and was killed",
                call.program,
                limit.as_secs_f64()
            ),
        )
    };
    if limit.is_zero() {
        return Err(timed_out());
    }
    match e.attempt(call, limit)? {
        Attempt::Exited(o) => Ok(o),
        Attempt::OverCap => Ok(Output::failure(OVER_CAP)),
        Attempt::TimedOut => Err(timed_out()),
        Attempt::Killed => Err(io::ErrorKind::Interrupted.into()),
        Attempt::Lost => Err(io::ErrorKind::BrokenPipe.into()),
    }
}

fn exit_code(status: ExitStatus) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return 128 + sig;
        }
    }
    status.code().unwrap_or(-1)
}

fn killed_by_signal(status: ExitStatus) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status.signal().is_some()
    }
    #[cfg(not(unix))]
    {
        let _ = status;
        false
    }
}

/// How an exited child is classified before its stdout is collected. Over the cap wins
/// over a signal: a child writing past the cap typically dies of SIGPIPE once the reader
/// drops the pipe, and that is the cap's refusal (NR-5), not an unknown kill.
fn exited_early(status: ExitStatus, over: bool) -> Option<Attempt> {
    if over {
        Some(Attempt::OverCap)
    } else if killed_by_signal(status) {
        Some(Attempt::Killed)
    } else {
        None
    }
}

/// Read to EOF (or past `cap`) into a buffer that is zeroized on drop. `None` when more
/// than `cap` bytes arrived; `over` is set as soon as that happens so the caller can kill
/// the child. Growth copies into a fresh `Zeroizing` allocation, so no unzeroized copy of
/// the data is left behind by `realloc`.
fn read_capped(
    mut r: impl Read,
    cap: usize,
    over: &AtomicBool,
) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(8 * 1024));
    let mut chunk = [0u8; 8 * 1024];
    let res = loop {
        match r.read(&mut chunk) {
            Ok(0) => break Ok(true),
            Ok(n) if out.len() + n > cap => {
                over.store(true, Ordering::SeqCst);
                break Ok(false);
            }
            Ok(n) => {
                if out.len() + n > out.capacity() {
                    let mut bigger = Zeroizing::new(Vec::with_capacity((out.len() + n) * 2));
                    bigger.extend_from_slice(&out);
                    out = bigger;
                }
                out.extend_from_slice(&chunk[..n]);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => break Err(e),
        }
    };
    chunk.zeroize();
    res.map(|complete| complete.then_some(out))
}

/// Read an interactive child's stdout (the owner-run `op signin` in `setup`/`session`) into
/// a zeroized buffer, capped at [`OUTPUT_CAP`] like every captured call (NR-5).
pub(crate) fn read_to_end_zeroizing(r: impl Read) -> io::Result<Zeroizing<Vec<u8>>> {
    let over = AtomicBool::new(false);
    read_capped(r, OUTPUT_CAP, &over)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("output exceeded {} bytes", OUTPUT_CAP),
        )
    })
}

/// Runs real processes with `std::process::Command`. Child stderr is discarded because it
/// may echo values (SR-1); callers map outcomes to typed errors.
///
/// Each captured call is killed at the earlier of its effect's limit and the run budget.
/// `run_inherited` (the user's own command under `op run`) has no limit.
#[derive(Debug, Clone, Copy)]
pub struct ProcessRunner {
    budget: Budget,
    verbose: bool,
    /// Extra per-call limit (tests); `None` uses the effect limits only.
    cap: Option<Duration>,
}

impl ProcessRunner {
    /// A runner for one opv run: `budget` caps every call, `verbose` prints one stderr line
    /// per call (NR-22).
    pub fn new(budget: Budget, verbose: bool) -> Self {
        Self {
            budget,
            verbose,
            cap: None,
        }
    }

    /// A runner whose every captured call is also killed after `limit` (tests use a short
    /// one).
    pub fn with_timeout(limit: Duration) -> Self {
        Self {
            cap: Some(limit),
            ..Self::default()
        }
    }

    fn spawn_attempt(&self, call: &Call, limit: Duration) -> io::Result<Attempt> {
        if signals::stopping() {
            signals::wait_for_exit();
        }
        let limit = self.cap.map_or(limit, |c| c.min(limit));
        let deadline = Instant::now() + limit;
        let mut child = command_for(call).spawn()?;
        signals::track(&child, call.step());
        let child_stdin = child.stdin.take();
        let child_stdout = child.stdout.take().expect("stdout is piped");

        // stdin is written and stdout read on their own threads, so neither pipe can fill up
        // and deadlock, and so a hung child can be killed on time. The threads own their
        // data (stdin is copied into a zeroizing buffer, SR-8) and report over channels, so
        // a pipe kept open by a grandchild can never block this call past the deadline.
        let (wtx, wrx) = mpsc::channel::<io::Result<()>>();
        let input = call.stdin.map(|d| Zeroizing::new(d.to_vec()));
        std::thread::spawn(move || {
            let mut pipe = child_stdin;
            let res = match (pipe.as_mut(), input.as_ref()) {
                (Some(p), Some(data)) => match p.write_all(data) {
                    // The child may exit without reading all input; that is its call.
                    Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
                    other => other,
                },
                _ => Ok(()),
            };
            drop(pipe); // close the pipe so the child sees EOF
            let _ = wtx.send(res);
        });
        let over = Arc::new(AtomicBool::new(false));
        let (rtx, rrx) = mpsc::channel();
        let flag = Arc::clone(&over);
        std::thread::spawn(move || {
            let _ = rtx.send(read_capped(child_stdout, OUTPUT_CAP, &flag));
        });

        let status = loop {
            match signals::reap(&mut child) {
                Ok(Some(st)) => break st,
                Ok(None) => {}
                Err(_) => {
                    signals::kill(&mut child);
                    return Ok(Attempt::Lost);
                }
            }
            if over.load(Ordering::SeqCst) {
                signals::kill(&mut child);
                return Ok(Attempt::OverCap);
            }
            if Instant::now() >= deadline {
                signals::kill(&mut child);
                return Ok(Attempt::TimedOut);
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        if signals::stopping() {
            signals::wait_for_exit();
        }
        if let Some(early) = exited_early(status, over.load(Ordering::SeqCst)) {
            return Ok(early);
        }
        let remaining = || deadline.saturating_duration_since(Instant::now());
        let stdout = match rrx.recv_timeout(remaining()) {
            Ok(Ok(Some(out))) => out,
            Ok(Ok(None)) => return Ok(Attempt::OverCap),
            Ok(Err(_)) => return Ok(Attempt::Lost),
            Err(_) => return Ok(Attempt::TimedOut),
        };
        match wrx.recv_timeout(remaining()) {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return Ok(Attempt::Lost),
            Err(_) => return Ok(Attempt::TimedOut),
        }
        Ok(Attempt::Exited(Output {
            status: exit_code(status),
            stdout,
        }))
    }
}

impl Default for ProcessRunner {
    fn default() -> Self {
        Self::new(Budget::default(), false)
    }
}

/// The process for a captured call: argv as given, the program's [`pinned_env`] then the
/// call's own env on top of the inherited environment, stdin `/dev/null` unless the call
/// sends some (NR-11), stdout piped, stderr discarded (SR-1).
fn command_for(call: &Call) -> Command {
    let mut cmd = Command::new(call.program);
    cmd.args(call.args)
        .envs(pinned_env(call.program).iter().copied())
        .envs(call.env.iter().copied())
        .stdin(if call.stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    cmd
}

/// Pseudo-random jitter without a dependency: a randomly keyed hash of the current instant.
fn random_jitter() -> f64 {
    use std::hash::BuildHasher;
    let h = std::collections::hash_map::RandomState::new().hash_one(Instant::now());
    let unit = (h >> 11) as f64 / (1u64 << 53) as f64;
    (unit * 2.0 - 1.0) * 0.25
}

/// Scale applied to real retry sleeps. Builds with the `fake` feature (tests only; release
/// builds never enable it) read `OPV_TEST_BACKOFF_SCALE` in [0, 1] so process-level tests
/// do not wait out the backoff; everywhere else it is 1.
fn backoff_scale() -> f64 {
    #[cfg(feature = "fake")]
    if let Some(s) = std::env::var("OPV_TEST_BACKOFF_SCALE")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
    {
        return s.clamp(0.0, 1.0);
    }
    1.0
}

impl Engine for ProcessRunner {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn deadline(&self) -> Instant {
        self.budget.deadline
    }
    fn sleep(&self, d: Duration) {
        std::thread::sleep(d.mul_f64(backoff_scale()));
        if signals::stopping() {
            signals::wait_for_exit();
        }
    }
    fn jitter(&self) -> f64 {
        random_jitter()
    }
    fn note(&self, line: &str) {
        let _ = writeln!(io::stderr(), "{line}");
    }
    fn attempt(&self, call: &Call, limit: Duration) -> io::Result<Attempt> {
        let t = Instant::now();
        let res = self.spawn_attempt(call, limit);
        if self.verbose {
            let outcome = match &res {
                Ok(a) => a.describe(),
                Err(e) => format!("not started ({:?})", e.kind()),
            };
            self.note(&verbose_line(call, t.elapsed(), &outcome));
        }
        res
    }
}

/// Read only the executable header, never any credential source.
fn windows_binary(path: &std::path::Path) -> io::Result<bool> {
    let mut header = [0u8; 2];
    match std::fs::File::open(path)?.read_exact(&mut header) {
        Ok(()) => Ok(header == *b"MZ"),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e),
    }
}

/// The first `op` on `paths` (a `PATH` value) must be a native binary: `Unsupported` when it
/// is a Windows executable (WSL with `op` linked to `op.exe`), `Ok` when it is native or
/// absent (a missing `op` is reported by the call that needs it).
fn native_op_on(paths: &std::ffi::OsStr) -> io::Result<()> {
    for dir in std::env::split_paths(paths) {
        let path = dir.join("op");
        if path.is_file() {
            return if windows_binary(&path)? {
                Err(io::ErrorKind::Unsupported.into())
            } else {
                Ok(())
            };
        }
    }
    Ok(())
}

impl CommandRunner for ProcessRunner {
    fn read(&self, call: &Call, refused: &[i32]) -> io::Result<Outcome> {
        read_on(self, call, refused)
    }

    fn write(&self, call: &Call) -> io::Result<Outcome> {
        write_on(self, call)
    }

    fn probe(&self, call: &Call, limit: Duration) -> io::Result<Output> {
        probe_on(self, call, limit)
    }

    fn local_run_supported(&self) -> io::Result<()> {
        if cfg!(windows) {
            return Ok(());
        }
        match std::env::var_os("PATH") {
            Some(paths) => native_op_on(&paths),
            None => Ok(()),
        }
    }

    fn run_inherited_clean(
        &self,
        program: &str,
        args: &[&str],
        env: &[(&str, &str)],
        remove: &[String],
    ) -> io::Result<i32> {
        let mut cmd = Command::new(program);
        for key in remove {
            cmd.env_remove(key);
        }
        let status = cmd
            .args(args)
            .envs(env.iter().copied())
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()?;
        Ok(exit_code(status))
    }

    fn run_inherited(&self, program: &str, args: &[&str], env: &[(&str, &str)]) -> io::Result<i32> {
        let status = Command::new(program)
            .args(args)
            .envs(env.iter().copied())
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()?;
        Ok(exit_code(status))
    }
}

/// SIGINT/SIGTERM handling (NR-12): the signal is forwarded to the running captured child,
/// which gets [`SIGNAL_GRACE`] before it is killed; opv then exits 130 (SIGINT) or 143
/// (SIGTERM) with "interrupted during <step>; safe to re-run". Unix only: on Windows,
/// Ctrl-C keeps its default behaviour (the console delivers it to the child too).
pub mod signals {
    use std::process::{Child, ExitStatus};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Mutex, MutexGuard};

    /// The captured child currently running, by pid.
    static CHILD: Mutex<Option<u32>> = Mutex::new(None);
    /// The step of the most recent captured call.
    static STEP: Mutex<String> = Mutex::new(String::new());
    static STOPPING: AtomicBool = AtomicBool::new(false);

    fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
        m.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(super) fn stopping() -> bool {
        STOPPING.load(Ordering::SeqCst)
    }

    /// Once a signal arrived, no new call starts: the calling thread waits for the handler
    /// to exit the process.
    pub(super) fn wait_for_exit() -> ! {
        loop {
            std::thread::park();
        }
    }

    pub(super) fn track(child: &Child, step: String) {
        *lock(&CHILD) = Some(child.id());
        *lock(&STEP) = step;
    }

    /// `try_wait` under the lock, so the handler never signals a reaped (reusable) pid.
    pub(super) fn reap(child: &mut Child) -> std::io::Result<Option<ExitStatus>> {
        let mut slot = lock(&CHILD);
        let res = child.try_wait();
        if !matches!(res, Ok(None)) && *slot == Some(child.id()) {
            *slot = None;
        }
        res
    }

    /// Kill and reap `child` (timeout, cap, lost).
    pub(super) fn kill(child: &mut Child) {
        let mut slot = lock(&CHILD);
        let _ = child.kill();
        let _ = child.wait();
        if *slot == Some(child.id()) {
            *slot = None;
        }
    }

    /// The line printed when opv is interrupted during `step` (empty: before any call).
    pub fn interrupted_message(step: &str) -> String {
        if step.is_empty() {
            "interrupted; safe to re-run".to_string()
        } else {
            format!("interrupted during {step}; safe to re-run")
        }
    }

    /// Install the handler (once, from `main`). A no-op outside Unix.
    #[cfg(unix)]
    pub fn install() -> std::io::Result<()> {
        use signal_hook::consts::{SIGINT, SIGTERM};
        let mut signals = signal_hook::iterator::Signals::new([SIGINT, SIGTERM])?;
        std::thread::spawn(move || {
            if let Some(sig) = signals.forever().next() {
                STOPPING.store(true, Ordering::SeqCst);
                forward(sig);
                let step = lock(&STEP).clone();
                eprintln!("opv: {}", interrupted_message(&step));
                std::process::exit(128 + sig);
            }
        });
        Ok(())
    }

    #[cfg(not(unix))]
    pub fn install() -> std::io::Result<()> {
        Ok(())
    }

    /// Send `sig` to the current child, wait up to the grace period, then kill it.
    #[cfg(unix)]
    fn forward(sig: i32) {
        let Some(id) = *lock(&CHILD) else { return };
        let Ok(pid) = i32::try_from(id) else { return };
        // SAFETY: a plain syscall on a pid we spawned and have not reaped (the slot is
        // cleared under the same lock when it is reaped).
        unsafe { libc::kill(pid, sig) };
        let t = std::time::Instant::now();
        while t.elapsed() < super::SIGNAL_GRACE {
            if *lock(&CHILD) != Some(id) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let slot = lock(&CHILD);
        if *slot == Some(id) {
            // SAFETY: as above, under the lock that guards reaping.
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
    }
}

#[cfg(any(test, feature = "fake"))]
pub mod fake {
    //! Recording runner for tests. Enable with `--features fake` outside this crate.
    //!
    //! Each attempt pops one queued response. `read` retries exactly like the real runner,
    //! on a fake clock (no real sleep): a read that should fail for good needs
    //! [`READ_ATTEMPTS`](super::READ_ATTEMPTS) failures queued. Queued `io` errors stand
    //! for outcomes: `TimedOut` a timeout, `Interrupted` a kill, `ConnectionAborted` a lost
    //! call, `OutOfMemory` output over the cap; any other kind is a spawn error.

    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::io;
    use std::time::{Duration, Instant};

    use super::{Attempt, CommandRunner, Engine, Outcome, Output};

    /// One recorded invocation, including env names and values so tests can assert what
    /// reached env versus argv. `Debug` shows argv but redacts stdin and env values.
    pub struct Call {
        pub program: String,
        pub args: Vec<String>,
        pub stdin: Option<Vec<u8>>,
        pub env: Vec<(String, String)>,
        /// True for `run_inherited` calls.
        pub inherited: bool,
        pub removed: Vec<String>,
    }

    impl std::fmt::Debug for Call {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let env: Vec<&str> = self.env.iter().map(|(k, _)| k.as_str()).collect();
            f.debug_struct("Call")
                .field("program", &self.program)
                .field("args", &self.args)
                .field("stdin_len", &self.stdin.as_ref().map(Vec::len))
                .field("env_names", &env)
                .field("inherited", &self.inherited)
                .finish()
        }
    }

    /// Returns queued responses in order and records every call.
    pub struct FakeRunner {
        pub calls: RefCell<Vec<Call>>,
        pub responses: RefCell<VecDeque<io::Result<Output>>>,
        pub local_run_error: RefCell<Option<io::ErrorKind>>,
        /// Retry notices the real runner would print on stderr.
        pub notes: RefCell<Vec<String>>,
        start: Instant,
        /// Fake time elapsed (advanced only by retry backoff).
        pub elapsed: Cell<Duration>,
        /// Run budget measured on the fake clock.
        pub budget: Cell<Duration>,
    }

    impl Default for FakeRunner {
        fn default() -> Self {
            Self {
                calls: RefCell::default(),
                responses: RefCell::default(),
                local_run_error: RefCell::new(None),
                notes: RefCell::default(),
                start: Instant::now(),
                elapsed: Cell::new(Duration::ZERO),
                budget: Cell::new(super::DEFAULT_RUN_TIMEOUT),
            }
        }
    }

    /// A read that fails with `status` on every attempt: [`READ_ATTEMPTS`] responses.
    ///
    /// [`READ_ATTEMPTS`]: super::READ_ATTEMPTS
    pub fn failed_read(status: i32) -> impl Iterator<Item = Output> {
        (0..super::READ_ATTEMPTS).map(move |_| Output::failure(status))
    }

    impl FakeRunner {
        /// Queue `n` copies of an unknown outcome (`timeout`, `killed`, `lost`).
        pub fn push_unknowns(&self, reason: &str, n: u32) {
            (0..n).for_each(|_| self.push_unknown(reason));
        }

        pub fn new(responses: impl IntoIterator<Item = Output>) -> Self {
            let r = Self::default();
            r.responses
                .borrow_mut()
                .extend(responses.into_iter().map(Ok));
            r
        }

        /// Queue a spawn failure, e.g. `NotFound` for a missing binary.
        pub fn push_io_error(&self, kind: io::ErrorKind) {
            self.responses
                .borrow_mut()
                .push_back(Err(io::Error::from(kind)));
        }

        /// Queue an unknown outcome: `timeout`, `killed` or `lost`.
        pub fn push_unknown(&self, reason: &str) {
            self.push_io_error(match reason {
                "timeout" => io::ErrorKind::TimedOut,
                "killed" => io::ErrorKind::Interrupted,
                "lost" => io::ErrorKind::ConnectionAborted,
                other => panic!("FakeRunner: unknown reason {other}"),
            });
        }

        fn record(
            &self,
            program: &str,
            args: &[&str],
            stdin: Option<&[u8]>,
            env: &[(&str, &str)],
            inherited: bool,
        ) -> io::Result<Output> {
            self.calls.borrow_mut().push(Call {
                program: program.to_string(),
                args: args.iter().map(|a| a.to_string()).collect(),
                stdin: stdin.map(<[u8]>::to_vec),
                env: env
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                inherited,
                removed: Vec::new(),
            });
            match self.responses.borrow_mut().pop_front() {
                Some(r) => r,
                None => panic!("FakeRunner: no response queued for call to {program}"),
            }
        }

        /// True if `needle` occurs in any recorded program name or argument (SR-3 checks).
        pub fn argv_contains(&self, needle: &str) -> bool {
            self.calls
                .borrow()
                .iter()
                .any(|c| c.program.contains(needle) || c.args.iter().any(|a| a.contains(needle)))
        }
    }

    impl Engine for FakeRunner {
        fn now(&self) -> Instant {
            self.start + self.elapsed.get()
        }
        fn deadline(&self) -> Instant {
            self.start + self.budget.get()
        }
        fn sleep(&self, d: Duration) {
            self.elapsed.set(self.elapsed.get() + d);
        }
        fn jitter(&self) -> f64 {
            0.0
        }
        fn note(&self, line: &str) {
            self.notes.borrow_mut().push(line.to_string());
        }
        fn attempt(&self, call: &super::Call, _limit: Duration) -> io::Result<Attempt> {
            match self.record(call.program, call.args, call.stdin, call.env, false) {
                Ok(o) => Ok(Attempt::Exited(o)),
                Err(e) => match e.kind() {
                    io::ErrorKind::TimedOut => Ok(Attempt::TimedOut),
                    io::ErrorKind::Interrupted => Ok(Attempt::Killed),
                    io::ErrorKind::ConnectionAborted => Ok(Attempt::Lost),
                    io::ErrorKind::OutOfMemory => Ok(Attempt::OverCap),
                    _ => Err(e),
                },
            }
        }
    }

    impl CommandRunner for FakeRunner {
        fn read(&self, call: &super::Call, refused: &[i32]) -> io::Result<Outcome> {
            super::read_on(self, call, refused)
        }

        fn write(&self, call: &super::Call) -> io::Result<Outcome> {
            super::write_on(self, call)
        }

        /// A queued `TimedOut` comes back as that error, like a real probe timeout.
        fn probe(&self, call: &super::Call, _limit: Duration) -> io::Result<Output> {
            self.record(call.program, call.args, call.stdin, call.env, false)
        }

        fn local_run_supported(&self) -> io::Result<()> {
            match *self.local_run_error.borrow() {
                Some(kind) => Err(kind.into()),
                None => Ok(()),
            }
        }

        fn run_inherited_clean(
            &self,
            program: &str,
            args: &[&str],
            env: &[(&str, &str)],
            remove: &[String],
        ) -> io::Result<i32> {
            let result = self.run_inherited(program, args, env);
            if let Some(call) = self.calls.borrow_mut().last_mut() {
                call.removed = remove.to_vec();
            }
            result
        }

        /// Returns the queued response's `status` as the exit code.
        fn run_inherited(
            &self,
            program: &str,
            args: &[&str],
            env: &[(&str, &str)],
        ) -> io::Result<i32> {
            self.record(program, args, None, env, true)
                .map(|o| o.status)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeRunner;
    use super::*;

    fn read_fake(r: &FakeRunner) -> Outcome {
        r.read(&Call::new("op", &["item", "get", "i"]), &[])
            .unwrap()
    }

    // ------------------------------------------------------------ effects (NR-2, NR-3)

    #[test]
    fn read_retries_transient_failure_then_succeeds() {
        let r = FakeRunner::new([Output::failure(1), Output::success("ok")]);
        assert!(matches!(read_fake(&r), Outcome::Done(o) if o.stdout.as_slice() == b"ok"));
    }

    #[test]
    fn read_retries_a_timeout() {
        let r = FakeRunner::default();
        r.push_unknown("timeout");
        r.responses
            .borrow_mut()
            .push_back(Ok(Output::success("ok")));
        assert!(matches!(read_fake(&r), Outcome::Done(_)));
    }

    #[test]
    fn read_retries_a_killed_attempt() {
        let r = FakeRunner::default();
        r.push_unknown("killed");
        r.responses
            .borrow_mut()
            .push_back(Ok(Output::success("ok")));
        assert!(matches!(read_fake(&r), Outcome::Done(_)));
    }

    #[test]
    fn read_after_the_budget_ran_out_never_starts() {
        let r = FakeRunner::new([Output::success("")]);
        r.budget.set(Duration::ZERO);
        let e = r.read(&Call::new("op", &["item", "get"]), &[]).unwrap_err();
        assert_eq!(
            e.to_string(),
            "the run budget ran out before op item get started"
        );
    }

    #[test]
    fn read_does_not_retry_refused_exit() {
        let r = FakeRunner::new([Output::failure(3), Output::success("ok")]);
        let _ = r.read(&Call::new("az", &["keyvault", "secret", "show"]), &[3]);
        assert_eq!(r.calls.borrow().len(), 1);
    }

    #[test]
    fn read_stops_at_three_attempts() {
        let r = FakeRunner::new((0..4).map(|_| Output::failure(1)));
        let _ = read_fake(&r);
        assert_eq!(r.calls.borrow().len(), 3);
    }

    #[test]
    fn read_failing_after_last_attempt_is_refused_with_its_status() {
        let r = FakeRunner::new((0..3).map(|_| Output::failure(1)));
        assert!(matches!(read_fake(&r), Outcome::Refused(o) if o.status == 1));
    }

    #[test]
    fn read_timing_out_after_last_attempt_is_unknown_timeout() {
        let r = FakeRunner::default();
        (0..3).for_each(|_| r.push_unknown("timeout"));
        assert!(matches!(
            read_fake(&r),
            Outcome::Unknown {
                reason: "timeout",
                ..
            }
        ));
    }

    #[test]
    fn read_backs_off_one_then_two_seconds() {
        let r = FakeRunner::new((0..3).map(|_| Output::failure(1)));
        let _ = read_fake(&r);
        assert_eq!(r.elapsed.get(), Duration::from_secs(3));
    }

    #[test]
    fn retry_notice_names_program_subcommand_and_attempt() {
        let r = FakeRunner::new([Output::failure(1), Output::success("")]);
        let _ = read_fake(&r);
        assert_eq!(*r.notes.borrow(), ["retrying op item get (2/3) in 1.0 s"]);
    }

    #[test]
    fn retry_respects_run_budget() {
        let r = FakeRunner::new((0..3).map(|_| Output::failure(1)));
        r.budget.set(Duration::from_secs(2));
        let _ = read_fake(&r);
        assert_eq!(r.calls.borrow().len(), 2);
    }

    #[test]
    fn spawn_error_is_not_retried() {
        let r = FakeRunner::default();
        r.push_io_error(io::ErrorKind::NotFound);
        let e = r.read(&Call::new("op", &["--version"]), &[]).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn write_is_never_retried() {
        let r = FakeRunner::new([Output::failure(1), Output::success("")]);
        let _ = r.write(&Call::new("flyctl", &["secrets", "deploy"]));
        assert_eq!(r.calls.borrow().len(), 1);
    }

    #[test]
    fn failed_write_is_unknown() {
        let r = FakeRunner::new([Output::failure(1)]);
        let o = r
            .write(&Call::new("flyctl", &["secrets", "deploy"]))
            .unwrap();
        assert!(matches!(
            o,
            Outcome::Unknown {
                reason: "failed-write",
                status: Some(1)
            }
        ));
    }

    #[test]
    fn timed_out_write_is_unknown_timeout() {
        let r = FakeRunner::default();
        r.push_unknown("timeout");
        let o = r
            .write(&Call::new("flyctl", &["secrets", "deploy"]))
            .unwrap();
        assert!(matches!(
            o,
            Outcome::Unknown {
                reason: "timeout",
                status: None
            }
        ));
    }

    #[test]
    fn write_after_the_budget_ran_out_never_starts() {
        let r = FakeRunner::new([Output::success("")]);
        r.budget.set(Duration::ZERO);
        let _ = r.write(&Call::new("flyctl", &["secrets", "deploy"]));
        assert!(r.calls.borrow().is_empty());
    }

    #[test]
    fn effect_limits_match_the_requirements() {
        assert_eq!(
            [
                PROBE_TIMEOUT,
                READ_TIMEOUT,
                WRITE_TIMEOUT,
                DEFAULT_RUN_TIMEOUT
            ],
            [15, 60, 120, 900].map(Duration::from_secs)
        );
    }

    // ------------------------------------------------------------ process boundary

    #[cfg(unix)]
    #[test]
    fn output_over_cap_is_refused() {
        let o = ProcessRunner::default()
            .read(&Call::new("yes", &[]), &[])
            .unwrap();
        assert!(matches!(o, Outcome::Refused(o) if o.status == OVER_CAP));
    }

    /// NR-5: a child that dies of SIGPIPE after the reader dropped the pipe past the cap is
    /// refused for the cap, not reported as killed.
    #[cfg(unix)]
    #[test]
    fn sigpipe_after_cap_is_over_cap_not_killed() {
        use std::os::unix::process::ExitStatusExt;
        let sigpipe = ExitStatus::from_raw(13);
        assert!(matches!(
            exited_early(sigpipe, true),
            Some(Attempt::OverCap)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn signal_without_cap_is_killed() {
        use std::os::unix::process::ExitStatusExt;
        assert!(matches!(
            exited_early(ExitStatus::from_raw(9), false),
            Some(Attempt::Killed)
        ));
    }

    #[test]
    fn every_call_carries_pinned_env() {
        let missing: Vec<(&str, &str)> = ["op", "flyctl", "az"]
            .into_iter()
            .flat_map(|p| {
                let cmd = command_for(&Call::new(p, &[]));
                let set: Vec<(String, String)> = cmd
                    .get_envs()
                    .filter_map(|(k, v)| Some((k.to_str()?.to_string(), v?.to_str()?.to_string())))
                    .collect();
                pinned_env(p)
                    .iter()
                    .filter(move |(k, v)| !set.contains(&(k.to_string(), v.to_string())))
                    .copied()
            })
            .collect();
        assert!(missing.is_empty(), "{missing:?}");
    }

    #[test]
    fn az_output_is_pinned_to_json() {
        assert!(pinned_env("az").contains(&("AZURE_CORE_OUTPUT", "json")));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn captured_call_stdin_is_null() {
        let o = ProcessRunner::default()
            .read(&Call::new("readlink", &["/proc/self/fd/0"]), &[])
            .unwrap();
        assert!(matches!(o, Outcome::Done(o) if o.stdout.as_slice() == b"/dev/null\n"));
    }

    #[test]
    fn verbose_line_has_no_stdin_bytes() {
        let call = Call {
            program: "flyctl",
            args: &["secrets", "import", "--app", "a", "--stage"],
            stdin: Some(b"K=VERBOSESTDINMARK"),
            env: &[("FLY_API_TOKEN", "VERBOSEENVMARK")],
        };
        let line = verbose_line(&call, Duration::from_millis(1500), "exit 0");
        assert!(!line.contains("MARK"), "{line}");
    }

    #[test]
    fn verbose_line_names_program_argv_duration_and_outcome() {
        let line = verbose_line(
            &Call::new("op", &["item", "get", "i"]),
            Duration::from_millis(1500),
            "exit 0",
        );
        assert_eq!(line, "op item get i (1.50 s): exit 0");
    }

    #[test]
    fn interrupted_message_names_the_step() {
        assert_eq!(
            signals::interrupted_message("flyctl secrets deploy"),
            "interrupted during flyctl secrets deploy; safe to re-run"
        );
    }

    #[test]
    fn call_debug_hides_stdin_and_env_values() {
        let call = Call {
            program: "op",
            args: &["item", "edit"],
            stdin: Some(b"sk-live-123"),
            env: &[("OP_TOKEN", "tok-secret")],
        };
        let d = format!("{call:?}");
        assert!(!d.contains("sk-live") && !d.contains("tok-secret"), "{d}");
    }

    // ------------------------------------------------------------ carried over

    #[test]
    fn output_debug_hides_stdout() {
        let o = Output::success(b"{\"value\":\"sk-live-123\"}".to_vec());
        let d = format!("{o:?}");
        assert!(!d.contains("sk-live"), "{d}");
        assert!(d.contains("stdout_len"));
    }

    #[test]
    fn fake_records_calls_and_returns_responses_in_order() {
        let r = FakeRunner::new([Output::success("one"), Output::failure(7)]);
        let call = Call {
            program: "op",
            args: &["item", "edit"],
            stdin: Some(b"sk-live-123"),
            env: &[("OP_TOKEN", "tok-secret")],
        };
        let a = r.write(&call).unwrap();
        assert!(matches!(a, Outcome::Done(o) if o.stdout.as_slice() == b"one"));
        let b = r.write(&Call::new("flyctl", &["secrets", "list"])).unwrap();
        assert!(matches!(
            b,
            Outcome::Unknown {
                status: Some(7),
                ..
            }
        ));

        let calls = r.calls.borrow();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].program, "op");
        assert_eq!(calls[0].args, vec!["item", "edit"]);
        assert_eq!(calls[0].stdin.as_deref(), Some(&b"sk-live-123"[..]));
        assert_eq!(calls[0].env, vec![("OP_TOKEN".into(), "tok-secret".into())]);
        let d = format!("{:?}", calls[0]);
        assert!(!d.contains("sk-live") && !d.contains("tok-secret"), "{d}");
        drop(calls);

        assert!(r.argv_contains("secrets"));
        assert!(!r.argv_contains("sk-live"), "stdin must not count as argv");
    }

    #[cfg(unix)]
    #[test]
    fn process_runner_pipes_stdin_to_stdout() {
        let o = ProcessRunner::default()
            .write(&Call::new("cat", &[]).with_stdin(Some(b"hello")))
            .unwrap();
        assert!(matches!(o, Outcome::Done(o) if o.stdout.as_slice() == b"hello"));
    }

    #[cfg(unix)]
    #[test]
    fn process_runner_handles_large_stdin_without_deadlock() {
        let big = vec![b'x'; 4 * 1024 * 1024];
        let o = ProcessRunner::default()
            .write(&Call::new("cat", &[]).with_stdin(Some(&big)))
            .unwrap();
        assert!(matches!(o, Outcome::Done(o) if o.stdout.len() == big.len()));
    }

    #[cfg(unix)]
    #[test]
    fn process_runner_passes_env() {
        let call = Call {
            program: "printenv",
            args: &["OPV_TEST_VAR"],
            stdin: None,
            env: &[("OPV_TEST_VAR", "v1")],
        };
        let o = ProcessRunner::default().read(&call, &[]).unwrap();
        assert!(matches!(o, Outcome::Done(o) if o.stdout.as_slice() == b"v1\n"));
    }

    /// A child that writes to stderr and fails: status propagated, stderr not captured.
    #[cfg(unix)]
    #[test]
    fn process_runner_reports_status_and_drops_stderr() {
        let o = ProcessRunner::default()
            .read(
                &Call::new("sh", &["-c", "echo leaked-value >&2; exit 3"]),
                &[3],
            )
            .unwrap();
        assert!(matches!(o, Outcome::Refused(o) if o.status == 3 && o.stdout.is_empty()));
    }

    #[test]
    fn read_capped_reads_across_growth() {
        let data: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let over = AtomicBool::new(false);
        let out = read_capped(&data[..], OUTPUT_CAP, &over).unwrap().unwrap();
        assert_eq!(out.as_slice(), data.as_slice());
        assert!(
            read_capped(&b""[..], OUTPUT_CAP, &over)
                .unwrap()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn read_capped_stops_past_the_cap() {
        let over = AtomicBool::new(false);
        let res = read_capped(&[0u8; 100][..], 10, &over).unwrap();
        assert!(res.is_none() && over.load(Ordering::SeqCst));
    }

    #[test]
    fn fake_run_inherited_records_env_values_and_returns_status() {
        let r = FakeRunner::new([Output::failure(9)]);
        let code = r
            .run_inherited(
                "op",
                &["run", "--", "server"],
                &[("OPENAI_API_KEY", "op://vprd/iprd/allumata/OPENAI_API_KEY")],
            )
            .unwrap();
        assert_eq!(code, 9);
        let calls = r.calls.borrow();
        assert!(calls[0].inherited && calls[0].stdin.is_none());
        assert_eq!(calls[0].args, vec!["run", "--", "server"]);
        assert_eq!(
            calls[0].env,
            vec![(
                "OPENAI_API_KEY".to_string(),
                "op://vprd/iprd/allumata/OPENAI_API_KEY".to_string()
            )]
        );
        assert!(!format!("{:?}", calls[0]).contains("op://"));
    }

    #[cfg(unix)]
    #[test]
    fn process_runner_run_inherited_returns_exit_code_and_applies_env() {
        let code = ProcessRunner::default()
            .run_inherited("sh", &["-c", "exit 5"], &[])
            .unwrap();
        assert_eq!(code, 5);
        let code = ProcessRunner::default()
            .run_inherited(
                "sh",
                &["-c", "test \"$OPV_TEST_VAR\" = v2"],
                &[("OPV_TEST_VAR", "v2")],
            )
            .unwrap();
        assert_eq!(code, 0);
        let code = ProcessRunner::default()
            .run_inherited("sh", &["-c", "kill -TERM $$"], &[])
            .unwrap();
        assert_eq!(code, 128 + 15);
    }

    #[test]
    fn process_runner_run_inherited_missing_binary_is_io_error() {
        let e = ProcessRunner::default()
            .run_inherited("opv-definitely-not-installed", &[], &[])
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
    }

    #[cfg(unix)]
    fn hung_write_outcome(call: &Call) -> (bool, bool) {
        let t = Instant::now();
        let o = ProcessRunner::with_timeout(Duration::from_millis(200))
            .write(call)
            .unwrap();
        let timed_out = matches!(
            o,
            Outcome::Unknown {
                reason: "timeout",
                ..
            }
        );
        (timed_out, t.elapsed() < Duration::from_secs(5))
    }

    /// A captured call that outlives its limit is killed promptly as a timeout.
    #[cfg(unix)]
    #[test]
    fn process_runner_kills_a_hung_child_at_the_timeout() {
        assert_eq!(
            hung_write_outcome(&Call::new("sleep", &["30"])),
            (true, true)
        );
    }

    /// The stdin writer must not hold the call open past its limit.
    #[cfg(unix)]
    #[test]
    fn process_runner_kills_a_hung_child_with_pending_stdin() {
        let big = vec![b'x'; 1 << 20];
        let call = Call::new("sleep", &["30"]).with_stdin(Some(&big));
        assert_eq!(hung_write_outcome(&call), (true, true));
    }

    /// A grandchild holding stdout open cannot keep the call past its limit.
    #[cfg(unix)]
    #[test]
    fn grandchild_holding_stdout_cannot_outlive_the_timeout() {
        let call = Call::new("sh", &["-c", "sleep 30 & exit 0"]);
        assert_eq!(hung_write_outcome(&call), (true, true));
    }

    /// FR-26: a diagnosis call has its own short limit and is killed at it.
    #[cfg(unix)]
    #[test]
    fn probe_is_killed_at_its_own_limit() {
        let t = Instant::now();
        let e = ProcessRunner::default()
            .probe(&Call::new("sleep", &["30"]), Duration::from_millis(200))
            .unwrap_err();
        assert_eq!(
            (e.kind(), t.elapsed() < Duration::from_secs(5)),
            (io::ErrorKind::TimedOut, true)
        );
    }

    #[cfg(unix)]
    #[test]
    fn probe_returns_a_failing_status_as_is() {
        let o = ProcessRunner::default()
            .probe(&Call::new("sh", &["-c", "exit 3"]), PROBE_TIMEOUT)
            .unwrap();
        assert_eq!(o.status, 3);
    }

    #[test]
    fn process_runner_missing_binary_is_io_error() {
        let e = ProcessRunner::default()
            .read(&Call::new("opv-definitely-not-installed", &[]), &[])
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn recognizes_windows_cli_header_without_execution() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("op");
        std::fs::write(&path, b"MZsynthetic").unwrap();
        assert!(windows_binary(&path).unwrap());
    }

    #[test]
    fn shell_cli_header_is_not_windows_binary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("op");
        std::fs::write(&path, b"#!/bin/sh").unwrap();
        assert!(!windows_binary(&path).unwrap());
    }

    #[test]
    fn windows_op_first_on_path_is_unsupported() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("op"), b"MZ\x90\x00").unwrap();
        let kind = native_op_on(dir.path().as_os_str()).unwrap_err().kind();
        assert_eq!(kind, io::ErrorKind::Unsupported);
    }

    #[test]
    fn native_op_first_on_path_is_supported() {
        let (win, native) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        std::fs::write(native.path().join("op"), b"\x7fELF").unwrap();
        std::fs::write(win.path().join("op"), b"MZ").unwrap();
        let paths = std::env::join_paths([native.path(), win.path()]).unwrap();
        assert!(native_op_on(&paths).is_ok());
    }

    #[test]
    fn missing_op_on_path_is_left_to_the_call() {
        let dir = tempfile::tempdir().unwrap();
        assert!(native_op_on(dir.path().as_os_str()).is_ok());
    }
}
