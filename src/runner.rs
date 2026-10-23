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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
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
    /// A write's own limit (NR-4), for a write that waits for a rollout ([`Call::rollout`]);
    /// `None` is [`WRITE_TIMEOUT`]. Always capped by the run budget. Reads ignore it.
    pub limit: Option<Duration>,
}

impl<'a> Call<'a> {
    /// A call with no stdin and no extra env.
    pub fn new(program: &'a str, args: &'a [&'a str]) -> Self {
        Self {
            program,
            args,
            stdin: None,
            env: &[],
            limit: None,
        }
    }

    /// The same call as a write that waits for a rollout (`flyctl secrets deploy`, `az
    /// containerapp update`, a `kubectl apply`): killed only after [`ROLLOUT_WRITE_TIMEOUT`]
    /// or when the run budget runs out, with a progress line on stderr every
    /// [`PROGRESS_EVERY`] while it runs (NR-4).
    pub fn rollout(self) -> Self {
        Self {
            limit: Some(ROLLOUT_WRITE_TIMEOUT),
            ..self
        }
    }

    /// The same call sending `stdin`.
    pub fn with_stdin(self, stdin: Option<&'a [u8]>) -> Self {
        Self { stdin, ..self }
    }

    /// `<program> <first two argv words>`: the step name used in retry and signal lines.
    pub fn step(&self) -> String {
        std::iter::once(self.program)
            .chain(
                self.args
                    .iter()
                    .take(2)
                    .take_while(|a| !a.starts_with('-'))
                    .copied(),
            )
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

    /// Non-idempotent create (X5, design §5 "Creates are their own runner effect"): one
    /// write attempt, never retried. Exit 0 is [`CreateOutcome::Done`]; a non-zero exit was
    /// a definite refusal ([`CreateOutcome::Refused`], nothing was made). A timeout, a kill,
    /// a lost reply, a signal or a spent budget is [`CreateOutcome::OutcomeUnknown`], never
    /// an error a call site could word as "did not create". `Err` only when the program
    /// could not be started (nothing ran).
    fn create(&self, call: &Call, _kind: crate::cause::CreateKind) -> io::Result<CreateOutcome> {
        runner_create::from_write(self.write(call), call)
    }

    /// One HTTPS read (design `http-target` §5): an idempotent call to
    /// [`crate::runner_https::PROGRAM`] sharing [`CommandRunner::read`]'s retries, budget and
    /// observation (program `https`), whose stdout is the reply envelope. A call that never
    /// answered is [`crate::cause::Cause::Unavailable`]; a reply opv cannot decode is
    /// [`crate::cause::Cause::UnexpectedOutput`].
    fn https_read(
        &self,
        req: &crate::runner_https::HttpsRequest,
    ) -> Result<crate::runner_https::HttpsReply, crate::Error> {
        req.with_call(|call| match self.read(call, &[]) {
            Ok(Outcome::Done(o)) => {
                crate::runner_https::decode_reply(&o.stdout).map_err(|_| https_unusable_reply(call))
            }
            Ok(_) | Err(_) => Err(https_unavailable(call)),
        })
    }

    /// One HTTPS write (design `http-target` §5): a non-idempotent call to
    /// [`crate::runner_https::PROGRAM`] sharing [`CommandRunner::write`]'s single attempt,
    /// `wrote()` and observation. Any outcome other than a decodable exit-0 reply is
    /// [`crate::cause::Cause::WriteOutcomeUnknown`]: the request was sent, so its effect is
    /// unknown and the next `list` shows what happened.
    fn https_write(
        &self,
        req: &crate::runner_https::HttpsRequest,
    ) -> Result<crate::runner_https::HttpsReply, crate::Error> {
        req.with_call(|call| match self.write(call) {
            Ok(Outcome::Done(o)) => crate::runner_https::decode_reply(&o.stdout)
                .map_err(|_| https_write_unknown(call, req)),
            Ok(_) | Err(_) => Err(https_write_unknown(call, req)),
        })
    }

    /// True once this run started a write to a target, which a later read that fails or
    /// never answers must not call "nothing was changed" (NR-2, NR-28). The 1Password tidy
    /// (FR-43) rewrites an item's layout, never a target, so `op` writes do not count. A
    /// runner that records nothing keeps the default, false.
    fn writes_started(&self) -> bool {
        false
    }

    /// A short read-only diagnosis call (`op whoami`, `flyctl auth whoami`, version
    /// checks; FR-26): killed after `limit` (a `TimedOut` error), never retried; the exit
    /// status is returned as is.
    fn probe(&self, call: &Call, limit: Duration) -> io::Result<Output>;

    /// Wait `d` (never past the run budget) before polling again, printing `note` on
    /// stderr first (nothing when it is empty): the confirming read after a write (NR-30),
    /// a target busy with an update (NR-25). The fake advances its clock.
    fn pause(&self, d: Duration, note: &str);

    /// One line for the person running opv on stderr, never on stdout (so `--json` stays
    /// parseable): e.g. a read command's preflight note. Names only, never a value.
    fn note(&self, line: &str);

    /// Append Markdown to the CI job summary (H8): the file `$GITHUB_STEP_SUMMARY` names,
    /// when set. Names and states only, never a value or a link. Best effort: a summary
    /// that cannot be written never fails the command. The default writes nothing.
    fn step_summary(&self, _markdown: &str) {}

    /// True when this run signed in to the target with an environment's deploy
    /// credentials (FR-40). The 1Password tidy (FR-43) never writes under them: only a
    /// person's own sign-in tidies. The default is false.
    fn deploy_signed_in(&self) -> bool {
        false
    }

    /// Run `program` with inherited stdin/stdout/stderr and the given extra `env`, wait, and
    /// return its exit code (`128 + signal` if it was killed by a signal). Used by `run`
    /// (FR-4) to spawn `op run -- <cmd>`. Same contract: no secret values in `args`.
    fn run_inherited(&self, program: &str, args: &[&str], env: &[(&str, &str)]) -> io::Result<i32>;

    /// Time left in the run budget (`--timeout`, NR-4), for waits that must end inside it
    /// (a rollout); `None` when this runner has no budget.
    fn remaining(&self) -> Option<Duration> {
        None
    }

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

    /// True when calls start real child processes. A value handed over through an OS
    /// channel (the Windows named pipe, SR-3) can only be read by a real child, so only
    /// such a runner gets one; a simulated runner keeps the default and receives the value
    /// as the call's stdin, which it records. A runner that wrongly keeps the default only
    /// fails closed (`az` cannot open `/dev/stdin` on Windows); nothing leaks.
    fn spawns_processes(&self) -> bool {
        false
    }
}

/// Append `markdown` to the job summary file at `path` (H8), creating it if needed. Errors
/// are ignored: the summary is a convenience, never part of the command's result.
pub fn append_summary(path: &std::path::Path, markdown: &str) {
    use std::fs::OpenOptions;
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = f.write_all(markdown.as_bytes());
    }
}

/// Limit for one diagnosis call ([`CommandRunner::probe`]).
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(15);
/// Limit for one attempt of a read.
pub const READ_TIMEOUT: Duration = Duration::from_secs(60);
/// Limit for one write.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(120);
/// Limit for one write that waits for a rollout ([`Call::rollout`]): a Fly rolling deploy
/// restarts machines one by one and waits for their health checks; `az containerapp update`
/// waits for the provisioning operation (NR-4). Capped by the run budget.
pub const ROLLOUT_WRITE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// Default run budget (`--timeout`): room for a rollout write of [`ROLLOUT_WRITE_TIMEOUT`]
/// plus the reads and health waits around it.
pub const DEFAULT_RUN_TIMEOUT: Duration = Duration::from_secs(1800);
/// Longest silence on stderr while opv waits: a rollout write or a poll loop prints a
/// progress line at least this often (NR-4).
pub const PROGRESS_EVERY: Duration = Duration::from_secs(15);
/// Captured stdout above this many bytes is refused and the child killed (NR-5).
pub const OUTPUT_CAP: usize = 8 * 1024 * 1024;
/// Attempts per read, the first one included (NR-3).
pub const READ_ATTEMPTS: u32 = 3;
/// Child stderr kept in memory per captured call: the last 64 KiB (NR-31).
pub const STDERR_CAP: usize = 64 * 1024;
/// How long stderr may stay open after the child's stdout is collected (a grandchild can
/// hold it); what arrived by then is kept.
const STDERR_GRACE: Duration = Duration::from_millis(200);
/// `Output::status` of a call whose stdout exceeded [`OUTPUT_CAP`].
pub const OVER_CAP: i32 = -2;
/// Time a child gets after a forwarded SIGINT/SIGTERM before it is killed (NR-12).
pub const SIGNAL_GRACE: Duration = Duration::from_secs(5);

/// Pinned per-CLI environment (NR-7, NR-11), added on top of the inherited environment for
/// every captured call by program name: it neutralises user configuration that changes
/// output or prompts. Proxy and CA variables are never set here (NR-29). Each CLI declares
/// its own ([`crate::host::Tool::pinned_env`]).
pub fn pinned_env(program: &str) -> &'static [(&'static str, &'static str)] {
    crate::host::tool(program).map_or(&[], |t| t.pinned_env)
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
pub(crate) enum Attempt {
    Exited(Output),
    TimedOut,
    /// Ended by this signal (not opv's own timeout kill).
    Killed(i32),
    /// The call ran but its reply could not be collected (its stdout or stdin pipe failed,
    /// or opv could not wait for it). Observed as [`ExitClass::Lost`](crate::cause::ExitClass),
    /// whatever the child's own status, so no diagnosis reports it as a timeout or a kill.
    Lost,
    /// stdout went past [`OUTPUT_CAP`]; the child ended as this.
    OverCap(crate::cause::ExitClass),
}

/// How a child that opv itself ended (`Child::kill`, SIGKILL on Unix) is observed.
const KILLED_BY_OPV: crate::cause::ExitClass = crate::cause::ExitClass::Signal { signal: 9 };

/// How an exited child ended, as observed: the signal that ended it, else its exit code.
fn exit_class_of(status: ExitStatus) -> crate::cause::ExitClass {
    match killed_by_signal(status) {
        Some(signal) => crate::cause::ExitClass::Signal { signal },
        None => crate::cause::ExitClass::Code {
            code: exit_code(status),
        },
    }
}

impl Attempt {
    fn describe(&self) -> String {
        match self {
            Attempt::Exited(o) => status_text(o.status),
            Attempt::TimedOut => "timeout".into(),
            Attempt::Killed(_) => "killed".into(),
            Attempt::Lost => "lost".into(),
            Attempt::OverCap(_) => status_text(OVER_CAP),
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
    /// True with `--verbose` (NR-22, NR-31).
    fn verbose(&self) -> bool;
    /// One attempt, with the child's stderr held in memory (NR-31).
    fn attempt(&self, call: &Call, limit: Duration) -> io::Result<(Attempt, Stderr)>;
    /// A write to `program` started (see [`CommandRunner::writes_started`]).
    fn wrote(&self, program: &str);
}

/// Whether a write to `program` counts as a target write (see
/// [`CommandRunner::writes_started`]).
fn target_write(program: &str) -> bool {
    program != crate::host::OP_CLI.program
}

/// True when the fake HTTPS attempt may spawn `https` from `PATH`: only with the `fake`
/// feature and an active sim world. Without it, and in every release build, the real
/// attempt runs in process, so a program named `https` is never spawned (design §5).
fn https_fake_attempt() -> bool {
    fake_https_attempt(
        cfg!(feature = "fake"),
        std::env::var_os("OPV_SIM_WORLD").is_some(),
    )
}

/// [`https_fake_attempt`] with its inputs explicit, so a test can pin the release path (no
/// `fake` feature) and a fake build with no active sim world.
fn fake_https_attempt(fake: bool, sim_world: bool) -> bool {
    fake && sim_world
}

/// An HTTPS call that never answered, as the catalog's [`crate::cause::Cause::Unavailable`]
/// under [`crate::cause::System::Https`]. The runner already observed the failed attempt;
/// the fallback covers the one case it did not (a read the spent budget never let start).
fn https_unavailable(call: &Call) -> crate::Error {
    use crate::cause::{Cause, System, Unanswered};
    let seen = https_observed(call);
    let why = seen.exit().unanswered().unwrap_or(Unanswered::Network);
    Cause::Unavailable {
        system: System::Https,
        why,
        attempts: seen.attempts(),
        seen,
    }
    .into()
}

/// An HTTPS write the store may have applied: the request was sent, so its effect is unknown
/// ([`crate::cause::Cause::WriteOutcomeUnknown`]).
fn https_write_unknown(call: &Call, req: &crate::runner_https::HttpsRequest) -> crate::Error {
    use crate::cause::{Cause, ResourceKind, ResourceName, ResourceRef, System};
    Cause::WriteOutcomeUnknown {
        system: System::Https,
        subject: ResourceRef {
            kind: ResourceKind::ExternalStore,
            name: ResourceName::new(req.uri.clone()),
            scope: None,
        },
        seen: https_observed(call),
    }
    .into()
}

/// An HTTPS reply opv cannot decode: the call answered, but its stdout is unusable.
fn https_unusable_reply(call: &Call) -> crate::Error {
    use crate::cause::{Cause, During, OutputProblem, System};
    let seen = take_unusable_reply(call).unwrap_or_else(|| https_observed(call));
    Cause::UnexpectedOutput {
        system: System::Https,
        at: None,
        problem: OutputProblem::Unparseable,
        during: During::Read,
        seen,
    }
    .into()
}

/// The runner's observation of `call` after a failed HTTPS attempt, or a fresh one for the
/// budget-spent case the runner never observed.
fn https_observed(call: &Call) -> crate::cause::Observed {
    take_observed().unwrap_or_else(|| {
        observe::failed(call, &Err(io::Error::other("https")))
            .expect("https is an external system the runner observes")
    })
}

/// One attempt through `e`, printing the `--verbose` lines: the call line (NR-22), then the
/// call's scrubbed stderr and the shape of its stdout, never its content (NR-31).
fn attempt_on(e: &dyn Engine, call: &Call, limit: Duration) -> io::Result<(Attempt, Stderr)> {
    let t = e.now();
    let res = e.attempt(call, limit);
    // Every successful `op item get` registers all its values with the scrubber, with or
    // without `--verbose` and whichever path made the read (setup, manifest, tidy, deploy
    // credentials), before its own call's stderr can be shown (M3, SR-1).
    if let Ok((Attempt::Exited(o), _)) = &res
        && o.status == 0
        && call.program == "op"
        && call.args.windows(2).any(|w| w == ["item", "get"])
    {
        crate::scrub::register_item_values(&o.stdout);
    }
    if e.verbose() {
        let outcome = match &res {
            Ok((a, _)) => a.describe(),
            Err(err) => format!("not started ({:?})", err.kind()),
        };
        e.note(&verbose_line(
            call,
            e.now().saturating_duration_since(t),
            &outcome,
        ));
        if let Ok((a, stderr)) = &res {
            // The whole reply, scrubbed (design §7.3); a reply past the cap says so.
            if stderr.truncated {
                e.note(&format!(
                    "    stderr truncated: longer than {} KiB, only its end was kept",
                    STDERR_CAP / 1024
                ));
            }
            for line in crate::scrub::reply_lines(&stderr.bytes, stderr.truncated) {
                e.note(&format!("    stderr: {line}"));
            }
            if let Attempt::Exited(o) = a {
                e.note(&format!("    stdout: {}", stdout_shape(&o.stdout)));
            }
        }
    }
    res
}

/// `<n> bytes`, plus the top-level JSON keys (scrubbed, at most 12) or the array length
/// when stdout is JSON. Never any value (NR-31).
pub fn stdout_shape(stdout: &[u8]) -> String {
    let n = stdout.len();
    let unit = if n == 1 { "byte" } else { "bytes" };
    let mut shape = format!("{n} {unit}");
    let Ok(mut doc) = serde_json::from_slice::<serde_json::Value>(stdout) else {
        return shape;
    };
    match &doc {
        serde_json::Value::Object(m) => {
            // Sorted, as before JSON objects kept their order (A6).
            let mut sorted: Vec<&String> = m.keys().collect();
            sorted.sort();
            let mut keys: Vec<String> = sorted
                .into_iter()
                .take(12)
                .map(|k| crate::scrub::scrub(k))
                .collect();
            if m.len() > 12 {
                keys.push("…".into());
            }
            shape.push_str(&format!(", JSON object with keys: {}", keys.join(", ")));
        }
        serde_json::Value::Array(a) => shape.push_str(&format!(", JSON array of {}", a.len())),
        _ => shape.push_str(", JSON scalar"),
    }
    crate::scrub::wipe_json(&mut doc);
    shape
}

/// A child's stderr, held in memory only (NR-31): the last [`STDERR_CAP`] bytes, zeroized
/// on drop. `Debug` shows its length only.
#[derive(Default)]
pub(crate) struct Stderr {
    bytes: Zeroizing<Vec<u8>>,
    /// Earlier output was dropped to stay within the cap.
    truncated: bool,
}

impl std::fmt::Debug for Stderr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stderr")
            .field("len", &self.bytes.len())
            .field("truncated", &self.truncated)
            .finish()
    }
}

impl Stderr {
    /// Append `data`, keeping only the last [`STDERR_CAP`] bytes. The buffer is allocated
    /// once at twice the cap and never grows, so no unzeroized copy is left by `realloc`.
    fn push(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        if self.bytes.capacity() == 0 {
            self.bytes = Zeroizing::new(Vec::with_capacity(2 * STDERR_CAP));
        }
        let data = if data.len() > STDERR_CAP {
            self.truncated = true;
            &data[data.len() - STDERR_CAP..]
        } else {
            data
        };
        if self.bytes.len() + data.len() > 2 * STDERR_CAP {
            let keep = STDERR_CAP - data.len();
            let start = self.bytes.len() - keep;
            self.bytes.copy_within(start.., 0);
            self.bytes.truncate(keep);
            self.truncated = true;
        }
        self.bytes.extend_from_slice(data);
    }

    /// The last [`STDERR_CAP`] bytes, leaving this buffer empty.
    fn take(&mut self) -> Stderr {
        let mut out = Stderr {
            bytes: std::mem::take(&mut self.bytes),
            truncated: self.truncated,
        };
        if out.bytes.len() > STDERR_CAP {
            let start = out.bytes.len() - STDERR_CAP;
            out.bytes.copy_within(start.., 0);
            out.bytes.truncate(STDERR_CAP);
            out.truncated = true;
        }
        out
    }
}

/// The child's stderr of the last failed captured call on this thread, waiting for opv's
/// error line (NR-31). Raw bytes in zeroizing memory; scrubbed only when shown, so values
/// registered later in the run are scrubbed too.
///
/// Every call (each read attempt, write and probe) takes the next call id and clears the
/// slot when it starts; a failure is stored stamped with its own id, and is handed out only
/// while no later call has started. So an excerpt can only follow the error made from that
/// same failed call. The one exception is [`diagnosing`]: the read-only probes an adapter
/// runs to explain a failure (`op whoami`, `az account show`, …) belong to that failure and
/// neither clear nor replace it.
mod failure {
    use std::cell::{Cell, RefCell};

    use super::Stderr;
    use crate::cause::Observed;

    struct Failed {
        call: u64,
        program: String,
        stderr: Stderr,
    }

    thread_local! {
        static CALL: Cell<u64> = const { Cell::new(0) };
        static DIAGNOSING: Cell<u32> = const { Cell::new(0) };
        static LAST: RefCell<Option<Failed>> = const { RefCell::new(None) };
        static OBSERVED: RefCell<Option<(u64, Observed)>> = const { RefCell::new(None) };
        static ANSWERED: RefCell<Option<(u64, Observed)>> = const { RefCell::new(None) };
    }

    /// True inside [`diagnosing`](super::diagnosing).
    pub(super) fn active() -> bool {
        DIAGNOSING.with(Cell::get) > 0
    }

    /// A call starts: its id, after clearing the slot. `None` inside [`diagnosing`]: the
    /// probe is part of the failure being explained and leaves the slot alone.
    pub(super) fn begin() -> Option<u64> {
        if active() {
            return None;
        }
        LAST.with(|l| l.borrow_mut().take());
        OBSERVED.with(|o| o.borrow_mut().take());
        ANSWERED.with(|o| o.borrow_mut().take());
        Some(CALL.with(|c| {
            c.set(c.get() + 1);
            c.get()
        }))
    }

    /// Call `call` failed with `stderr`; kept only while it is still the latest call.
    pub(super) fn record(call: Option<u64>, program: &str, stderr: Stderr) {
        let Some(call) = call.filter(|id| *id == CALL.with(Cell::get)) else {
            return;
        };
        LAST.with(|l| {
            *l.borrow_mut() = Some(Failed {
                call,
                program: program.to_string(),
                stderr,
            })
        });
    }

    /// Call `call` failed as `seen`; kept only while it is still the latest call.
    pub(super) fn observe(call: Option<u64>, seen: Observed) {
        let Some(call) = call.filter(|id| *id == CALL.with(Cell::get)) else {
            return;
        };
        OBSERVED.with(|o| *o.borrow_mut() = Some((call, seen)));
    }

    /// Call `call` answered with exit 0, as `seen`; kept only while it is still the latest
    /// call, for a caller that finds the reply unusable.
    pub(super) fn answered(call: Option<u64>, seen: Observed) {
        let Some(call) = call.filter(|id| *id == CALL.with(Cell::get)) else {
            return;
        };
        ANSWERED.with(|o| *o.borrow_mut() = Some((call, seen)));
    }

    pub(super) fn take_answered() -> Option<Observed> {
        let (call, seen) = ANSWERED.with(|o| o.borrow_mut().take())?;
        (call == CALL.with(Cell::get)).then_some(seen)
    }

    /// True when the latest call's failure is still held (not yet taken).
    pub(super) fn failure_held() -> bool {
        OBSERVED.with(|o| {
            o.borrow()
                .as_ref()
                .is_some_and(|(call, _)| *call == CALL.with(Cell::get))
        })
    }

    pub(super) fn take_observed() -> Option<Observed> {
        let (call, seen) = OBSERVED.with(|o| o.borrow_mut().take())?;
        (call == CALL.with(Cell::get)).then_some(seen)
    }

    pub(super) fn not_found() -> bool {
        LAST.with(|l| {
            l.borrow().as_ref().is_some_and(|f| {
                f.call == CALL.with(Cell::get) && super::says_not_found(&f.program, &f.stderr.bytes)
            })
        })
    }

    pub(super) fn signed_out() -> bool {
        LAST.with(|l| {
            l.borrow().as_ref().is_some_and(|f| {
                f.call == CALL.with(Cell::get)
                    && super::says_signed_out(&f.program, &f.stderr.bytes)
            })
        })
    }

    /// The latest failed call: its observation, raw reply and scrubbed excerpt; taken once.
    pub(super) fn take_failure() -> Option<super::Failure> {
        let seen = take_observed()?;
        let f = LAST
            .with(|l| l.borrow_mut().take())
            .filter(|f| f.call == CALL.with(Cell::get));
        Some(match f {
            Some(f) => super::Failure {
                seen,
                stderr: zeroize::Zeroizing::new(
                    String::from_utf8_lossy(&f.stderr.bytes).into_owned(),
                ),
                excerpt: crate::scrub::Excerpt::from_stderr(
                    &f.program,
                    &f.stderr.bytes,
                    f.stderr.truncated,
                ),
            },
            None => super::Failure {
                seen,
                stderr: zeroize::Zeroizing::new(String::new()),
                excerpt: None,
            },
        })
    }

    pub(super) fn take() -> Option<crate::scrub::Excerpt> {
        let f = LAST.with(|l| l.borrow_mut().take())?;
        if f.call != CALL.with(Cell::get) {
            return None;
        }
        crate::scrub::Excerpt::from_stderr(&f.program, &f.stderr.bytes, f.stderr.truncated)
    }

    pub(super) struct Diagnosis;

    impl Diagnosis {
        pub(super) fn enter() -> Self {
            DIAGNOSING.with(|d| d.set(d.get() + 1));
            Diagnosis
        }
    }

    impl Drop for Diagnosis {
        fn drop(&mut self) {
            DIAGNOSING.with(|d| d.set(d.get().saturating_sub(1)));
        }
    }
}

/// True when `stderr` of a failed `program` call says the object does not exist (S2): one
/// of the phrases its CLI declares ([`crate::host::Tool::not_found`]). Unrecognised text is
/// not a match, so such a failure keeps its retries. Searched in place, never copied or
/// printed (NR-31).
fn says_not_found(program: &str, stderr: &[u8]) -> bool {
    says(program, stderr, |t| t.not_found)
}

/// True when `stderr` says no one is signed in to `program`'s service: not transient.
fn says_signed_out(program: &str, stderr: &[u8]) -> bool {
    says(program, stderr, |t| t.signed_out)
}

fn says(
    program: &str,
    stderr: &[u8],
    phrases: impl Fn(&crate::host::Tool) -> &'static [&'static str],
) -> bool {
    crate::host::tool(program)
        .into_iter()
        .flat_map(|t| phrases(t).iter())
        .any(|phrase| stderr.windows(phrase.len()).any(|w| w == phrase.as_bytes()))
}

/// True when the last failed captured call on this thread (the one the error at hand came
/// from, as for [`take_failure_excerpt`]) said its object does not exist (S2), so the
/// caller reports it at once instead of retrying.
pub fn last_failure_not_found() -> bool {
    failure::not_found()
}

/// True when the last failed captured call on this thread (as for
/// [`last_failure_not_found`]) said no one is signed in to its service (its CLI's
/// [`crate::host::Tool::signed_out`] phrases), so the diagnosis is a sign-in, not an outage.
pub fn last_failure_signed_out() -> bool {
    failure::signed_out()
}

/// The scrubbed stderr excerpt of the failed call the error at hand came from (a read
/// refused, a write or probe that exited non-zero), if it wrote any; taken once. Any call
/// started after the failure (other than a [`diagnosing`] probe) drops it, so an excerpt
/// never attaches to an error it did not cause (NR-31).
pub fn take_failure_excerpt() -> Option<crate::scrub::Excerpt> {
    failure::take()
}

/// The failed call the error at hand came from, for its system's diagnosis strategy (design
/// §5): what the runner observed, the raw stderr and its scrubbed excerpt. The raw stderr
/// is matched against the recorded phrases before scrubbing (scrubbing may change a phrase)
/// and never leaves the strategy; it lives in zeroizing memory. The excerpt is the evidence.
pub struct Failure {
    pub seen: crate::cause::Observed,
    stderr: Zeroizing<String>,
    pub excerpt: Option<crate::scrub::Excerpt>,
}

impl Failure {
    /// The call's raw stderr ("" when it wrote none), for the diagnosis only.
    pub fn stderr(&self) -> &str {
        &self.stderr
    }
}

/// The one way a diagnosis gets a failed call (design §5, B1): its [`Failure`] (a non-zero
/// exit, a timeout, a kill, a lost reply, a spawn failure, or a streamed child recorded with
/// [`record_streamed`]); taken once, together with its excerpt, and dropped by any later
/// call exactly like [`take_failure_excerpt`]. `None` when the runner observed no failure.
pub fn take_failure() -> Option<Failure> {
    failure::take_failure()
}

/// What the runner observed about the failed call the error at hand came from (a non-zero
/// exit, a timeout, a signal or a spawn failure), with its [`CallId`](crate::cause::CallId)
/// and the principal in effect; taken once, and dropped by any later call exactly like
/// [`take_failure_excerpt`] (design §5 "Sealing").
pub fn take_observed() -> Option<crate::cause::Observed> {
    failure::take_observed()
}

/// The observation behind each example of [`crate::cause::codes::examples`] (the catalog's
/// code table): a fixed failed `op vault get`, classified only, never rendered as an error.
/// Built here so the runner stays the only builder of an observation (the seal).
pub fn catalog_example_observed(principal: crate::cause::Principal) -> crate::cause::Observed {
    crate::cause::Observed::from_failed_call(
        crate::cause::CallId {
            system: crate::cause::System::OnePassword,
            program: "op".into(),
            words: vec!["vault".into(), "get".into(), "vlt-example".into()],
        },
        crate::cause::ExitClass::Code { code: 1 },
        principal,
    )
}

/// The one way to observe a call that **answered** (exit 0, or stdout past the output cap)
/// with a reply the call site cannot use (design §4.6/§4.7, A1): JSON it cannot read, an
/// empty token, an unconfirmed or lost write reply. This is the runner's own observation of
/// `call` (its real exit class and principal), taken once and only while no later call has
/// started. A [`CommandRunner`] that answers without the runner's engine (an in-memory
/// double) leaves none; `call` is then observed as having exited 0. `None` when the latest
/// call failed (its failure is [`take_failure`]'s) or is outside the external systems.
pub fn take_unusable_reply(call: &Call) -> Option<crate::cause::Observed> {
    if let Some(seen) = failure::take_answered() {
        return Some(seen);
    }
    if failure::failure_held() {
        return None;
    }
    observe::answered(call, crate::cause::ExitClass::Code { code: 0 })
}

/// Run `f` with `principal` (an environment's deploy credentials, FR-40) in effect: every
/// call made inside it that fails is observed under it instead of the person or a shell
/// token. The runner that adds a deploy identity to calls (`EnvRunner`) wraps the calls of
/// the programs its sign-in gives an environment to.
pub fn under_deploy<T>(principal: crate::cause::Principal, f: impl FnOnce() -> T) -> T {
    observe::under_deploy(principal, f)
}

/// The deploy credentials [`under_deploy`] put in effect, if any: a sign-in's own check of
/// the item's values names that item.
pub fn deploy_principal() -> Option<crate::cause::Principal> {
    observe::deploy_principal()
}

/// Run `f`, the read-only diagnosis of the call that just failed (FR-26): its probes keep
/// that call's excerpt instead of starting a new one (NR-31). Used only on failure paths.
pub fn diagnosing<T>(f: impl FnOnce() -> T) -> T {
    let _scope = failure::Diagnosis::enter();
    f()
}

/// True inside [`diagnosing`]: a probe's failure is not recorded, so the held failure (if
/// any) is still the call being diagnosed, never the probe's own.
pub fn in_diagnosis() -> bool {
    failure::active()
}

/// Names a failed call and the principal it ran under (design §5): the only place an
/// [`Observed`](crate::cause::Observed) is built.
mod observe {
    use std::cell::RefCell;
    use std::io;

    use super::{Attempt, Call, Stderr};
    use crate::cause::{CallId, ExitClass, Observed, Principal, System, VarName};

    thread_local! {
        static DEPLOY: RefCell<Option<Principal>> = const { RefCell::new(None) };
    }

    /// Restores the principal in effect before [`under_deploy`] when dropped.
    struct Restore(Option<Principal>);

    impl Drop for Restore {
        fn drop(&mut self) {
            let prev = self.0.take();
            DEPLOY.with(|d| *d.borrow_mut() = prev);
        }
    }

    pub(super) fn under_deploy<T>(principal: Principal, f: impl FnOnce() -> T) -> T {
        let prev = DEPLOY.with(|d| d.borrow_mut().replace(principal));
        let _restore = Restore(prev);
        f()
    }

    pub(super) fn deploy_principal() -> Option<Principal> {
        DEPLOY.with(|d| d.borrow().clone())
    }

    /// The external system `program` belongs to, from its file name (`op`, `op.exe`,
    /// `/usr/bin/flyctl`); `None` for a program outside the external systems.
    fn system(program: &str) -> Option<System> {
        let name = std::path::Path::new(program)
            .file_stem()
            .and_then(|n| n.to_str())
            .unwrap_or(program);
        Some(match name {
            "op" => System::OnePassword,
            "flyctl" | "fly" => System::Fly,
            "az" => System::Azure,
            "kubectl" => System::Kubernetes,
            "gh" => System::GitHub,
            "ssh" => System::Ssh,
            "opv" => System::RemoteOpv,
            "https" => System::Https,
            _ => return None,
        })
    }

    /// The call's name (design §5): the program and its words up to `--` (so `op run`'s
    /// child command is never part of it), each `name=value` word cut to its name. stdin is
    /// never read. `None` for a program outside the external systems.
    pub(super) fn call_id(call: &Call) -> Option<CallId> {
        let system = system(call.program)?;
        let words = call
            .args
            .iter()
            .take_while(|w| **w != "--")
            .map(|w| call_word(w))
            .collect();
        Some(CallId {
            system,
            program: call.program.to_string(),
            words,
        })
    }

    /// One argument as the call's identity shows it: a `NAME=value` argument by its name
    /// only (a value is never shown), except a flag whose value is a setting opv chose and
    /// that the call cannot be repeated without (`--request-timeout=60s`).
    fn call_word(w: &str) -> String {
        match w.split_once('=') {
            Some((name, _)) if !KEEPS_VALUE.contains(&name) => name.to_string(),
            _ => w.to_string(),
        }
    }

    /// The flags whose `=value` is opv's own setting, kept in a call's identity.
    const KEEPS_VALUE: &[&str] = &["--request-timeout"];

    /// Shell tokens that override `program`'s own sign-in (design §5).
    fn shell_tokens(program: &str) -> &'static [&'static str] {
        match system(program) {
            Some(System::Fly) => &["FLY_API_TOKEN", "FLY_ACCESS_TOKEN"],
            Some(System::GitHub) => &["GH_TOKEN", "GITHUB_TOKEN"],
            Some(System::OnePassword) => &["OP_SERVICE_ACCOUNT_TOKEN"],
            _ => &[],
        }
    }

    /// True when `var` is set, non-empty, in the child's environment: the call's own env
    /// (later entries win), then the program's pinned env, then opv's own. Only presence is
    /// read; the value is never kept.
    fn in_child_env(call: &Call, var: &str) -> bool {
        let own = call
            .env
            .iter()
            .rev()
            .chain(super::pinned_env(call.program).iter())
            .find(|(k, _)| *k == var)
            .map(|(_, v)| !v.is_empty());
        own.unwrap_or_else(|| std::env::var_os(var).is_some_and(|v| !v.is_empty()))
    }

    /// Who acted: the deploy credentials of [`under_deploy`], else a shell token present
    /// for the program, else the person.
    fn principal(call: &Call) -> Principal {
        if let Some(p) = DEPLOY.with(|d| d.borrow().clone()) {
            return p;
        }
        shell_tokens(call.program)
            .iter()
            .find(|var| in_child_env(call, var))
            .map_or(Principal::Person { account: None }, |var| {
                Principal::ShellToken {
                    var: VarName::new(*var),
                }
            })
    }

    /// How a failed attempt ended; `None` for an answer (exit 0, or stdout over the cap),
    /// which [`answered`] observes instead. A lost reply is a failure: the call ran, its
    /// outcome is unknown.
    fn exit_class(res: &io::Result<(Attempt, Stderr)>) -> Option<ExitClass> {
        match res {
            Err(_) => Some(ExitClass::SpawnFailed),
            Ok((Attempt::Exited(o), _)) if o.status != 0 => {
                Some(ExitClass::Code { code: o.status })
            }
            Ok((Attempt::TimedOut, _)) => Some(ExitClass::TimedOut),
            Ok((Attempt::Killed(signal), _)) => Some(ExitClass::Signal { signal: *signal }),
            Ok((Attempt::Lost, _)) => Some(ExitClass::Lost),
            Ok(_) => None,
        }
    }

    /// The observation of `call`'s attempt `res`, when it failed.
    pub(super) fn failed(call: &Call, res: &io::Result<(Attempt, Stderr)>) -> Option<Observed> {
        let exit = exit_class(res)?;
        Some(Observed::from_failed_call(
            call_id(call)?,
            exit,
            principal(call),
        ))
    }

    /// The observation of a streamed child opv started itself, which ended as `exit`.
    pub(super) fn ended(call: &Call, exit: ExitClass) -> Option<Observed> {
        Some(Observed::from_failed_call(
            call_id(call)?,
            exit,
            principal(call),
        ))
    }

    /// The observation of `call`, which answered (ending as `exit`) with a reply the call
    /// site may find unusable (design §4.6, §4.7, A1).
    pub(super) fn answered(call: &Call, exit: ExitClass) -> Option<Observed> {
        Some(Observed::from_unusable_reply(
            call_id(call)?,
            exit,
            principal(call),
        ))
    }
}

/// Record that a long-lived, streamed child opv started itself (remote delivery's `ssh`,
/// whose stdin carries the payload and heartbeats) ended as `exit` after writing `stderr`,
/// so [`take_failure`] hands it to that system's diagnosis like any captured call (design
/// §5).
pub fn record_streamed(program: &str, args: &[&str], exit: crate::cause::ExitClass, stderr: &[u8]) {
    let id = failure::begin();
    let call = Call::new(program, args);
    if let Some(seen) = observe::ended(&call, exit) {
        failure::observe(id, seen);
    }
    let mut kept = Stderr::default();
    kept.push(stderr);
    failure::record(id, program, kept);
}

/// Keep what the runner saw of `call`'s attempt `res` (call `id`) when it failed.
fn observe_attempt(id: Option<u64>, call: &Call, res: &io::Result<(Attempt, Stderr)>) {
    observe_attempt_n(id, call, res, 1);
}

/// [`observe_attempt`] for a read's `n`-th attempt.
fn observe_attempt_n(id: Option<u64>, call: &Call, res: &io::Result<(Attempt, Stderr)>, n: u32) {
    if let Some(seen) = observe::failed(call, res) {
        failure::observe(id, seen.on_attempt(n));
    }
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
        // Each attempt is its own call: the excerpt belongs to the last one only.
        let id = failure::begin();
        let limit = READ_TIMEOUT.min(left(e));
        if limit.is_zero() {
            return Err(budget_spent(call));
        }
        let res = attempt_on(e, call, limit);
        observe_attempt_n(id, call, &res, n);
        let (attempt, stderr) = res?;
        let failed = match attempt {
            Attempt::Exited(o) if o.status == 0 => {
                answered(id, call, crate::cause::ExitClass::Code { code: 0 });
                return Ok(Outcome::Done(o));
            }
            Attempt::Exited(o) if refused.contains(&o.status) => {
                failure::record(id, call.program, stderr);
                return Ok(Outcome::Refused(o));
            }
            // S2: a missing object is not transient; refused at once, never retried.
            Attempt::Exited(o) if says_not_found(call.program, &stderr.bytes) => {
                failure::record(id, call.program, stderr);
                return Ok(Outcome::Refused(o));
            }
            // Signed out is not transient either: refused at once, never retried.
            Attempt::Exited(o) if says_signed_out(call.program, &stderr.bytes) => {
                failure::record(id, call.program, stderr);
                if call.program == crate::host::OP_CLI.program {
                    note_signed_out(call);
                }
                return Ok(Outcome::Refused(o));
            }
            Attempt::Exited(o) => {
                failure::record(id, call.program, stderr);
                Outcome::Refused(o)
            }
            Attempt::OverCap(exit) => {
                answered(id, call, exit);
                return Ok(Outcome::Refused(Output::failure(OVER_CAP)));
            }
            // opv's own interrupt never retries: the run is stopping (NR-12).
            Attempt::Killed(_) if signals::stopping() => {
                failure::record(id, call.program, stderr);
                return Ok(Outcome::unknown("killed"));
            }
            unfinished => {
                failure::record(id, call.program, stderr);
                unfinished_outcome(&unfinished)
            }
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

fn pause_on(e: &dyn Engine, d: Duration, note: &str) {
    if !note.is_empty() {
        e.note(note);
    }
    e.sleep(d.min(left(e)));
}

/// A poll loop's clock (NR-4): a health, rollout or propagation wait measures elapsed
/// monotonic time (the run budget's, so a fake clock works too), never the sum of its sleeps
/// alone, which misses the time its reads take. It stops at its own limit, or earlier when
/// the run budget has no room left for one more poll and its read, so the wait's own
/// message (naming the state it last saw) comes before the budget error.
pub struct Wait {
    limit: Duration,
    start_left: Option<Duration>,
    slept: std::cell::Cell<Duration>,
}

impl Wait {
    /// A wait of at most `limit` starting now.
    pub fn new(r: &dyn CommandRunner, limit: Duration) -> Self {
        Self {
            limit,
            start_left: r.remaining(),
            slept: std::cell::Cell::new(Duration::ZERO),
        }
    }

    /// The wait's own limit.
    pub fn limit(&self) -> Duration {
        self.limit
    }

    /// Time since the wait started: the run budget's clock, and at least the time slept (a
    /// runner without a budget).
    pub fn elapsed(&self, r: &dyn CommandRunner) -> Duration {
        let measured = self
            .start_left
            .zip(r.remaining())
            .map_or(Duration::ZERO, |(start, now)| start.saturating_sub(now));
        measured.max(self.slept.get())
    }

    /// True when the wait must stop instead of sleeping `next` and polling again: its own
    /// limit is reached, or the run budget cannot hold `next` plus one read.
    pub fn over(&self, r: &dyn CommandRunner, next: Duration) -> bool {
        self.elapsed(r) >= self.limit
            || r.remaining().is_some_and(|left| left < next + READ_TIMEOUT)
    }

    /// Sleep `d` on the runner, printing `note` first (see [`CommandRunner::pause`]).
    pub fn pause(&self, r: &dyn CommandRunner, d: Duration, note: &str) {
        r.pause(d, note);
        self.slept_for(d);
    }

    /// Count `d` slept some other way (a test's sleep hook).
    pub fn slept_for(&self, d: Duration) {
        self.slept.set(self.slept.get() + d);
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
    let id = failure::begin();
    let limit = call.limit.unwrap_or(WRITE_TIMEOUT).min(left(e));
    if limit.is_zero() {
        return Err(budget_spent(call));
    }
    let res = attempt_on(e, call, limit);
    observe_attempt(id, call, &res);
    let (attempt, stderr) = res?;
    e.wrote(call.program);
    Ok(match attempt {
        Attempt::Exited(o) if o.status == 0 => {
            answered(id, call, crate::cause::ExitClass::Code { code: 0 });
            Outcome::Done(o)
        }
        Attempt::Exited(o) => {
            failure::record(id, call.program, stderr);
            Outcome::Unknown {
                reason: "failed-write",
                status: Some(o.status),
            }
        }
        Attempt::OverCap(exit) => {
            answered(id, call, exit);
            Outcome::unknown("failed-write")
        }
        unfinished => {
            failure::record(id, call.program, stderr);
            unfinished_outcome(&unfinished)
        }
    })
}

/// The unknown outcome of an attempt that did not finish: a timeout, a kill or a lost reply.
fn unfinished_outcome(attempt: &Attempt) -> Outcome {
    match attempt {
        Attempt::TimedOut => Outcome::unknown("timeout"),
        Attempt::Killed(_) => Outcome::unknown("killed"),
        _ => Outcome::unknown("lost"),
    }
}

/// Keep, for [`take_unusable_reply`], what the runner saw of `call` (call `id`), which just
/// answered as `exit`: the caller may still find its reply unusable (design §5, A1).
fn answered(id: Option<u64>, call: &Call, exit: crate::cause::ExitClass) {
    if let Some(seen) = observe::answered(call, exit) {
        failure::answered(id, seen);
    }
}

fn probe_on(e: &dyn Engine, call: &Call, limit: Duration) -> io::Result<Output> {
    let id = failure::begin();
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
    let res = attempt_on(e, call, limit);
    observe_attempt(id, call, &res);
    let (attempt, stderr) = res?;
    match attempt {
        Attempt::Exited(o) => {
            if o.status == 0 {
                answered(id, call, crate::cause::ExitClass::Code { code: 0 });
            } else {
                failure::record(id, call.program, stderr);
            }
            Ok(o)
        }
        Attempt::OverCap(exit) => {
            answered(id, call, exit);
            Ok(Output::failure(OVER_CAP))
        }
        unfinished => {
            failure::record(id, call.program, stderr);
            Err(match unfinished {
                Attempt::TimedOut => timed_out(),
                Attempt::Killed(_) => io::ErrorKind::Interrupted.into(),
                _ => io::ErrorKind::BrokenPipe.into(),
            })
        }
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

/// The signal that ended the child, if one did.
fn killed_by_signal(status: ExitStatus) -> Option<i32> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status.signal()
    }
    #[cfg(not(unix))]
    {
        let _ = status;
        None
    }
}

/// How an exited child is classified before its stdout is collected. Over the cap wins
/// over a signal: a child writing past the cap typically dies of SIGPIPE once the reader
/// drops the pipe, and that is the cap's refusal (NR-5), not an unknown kill.
fn exited_early(status: ExitStatus, over: bool) -> Option<Attempt> {
    if over {
        Some(Attempt::OverCap(exit_class_of(status)))
    } else {
        killed_by_signal(status).map(Attempt::Killed)
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

/// Read an interactive child's stdout (the owner-run `op signin` in `setup`/`login`) into
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

/// Runs real processes with `std::process::Command`. Child stderr is held in memory only
/// and shown only scrubbed, on failure or with `--verbose` (SR-1, NR-31); callers map
/// outcomes to typed errors.
///
/// Each captured call is killed at the earlier of its effect's limit and the run budget.
/// `run_inherited` (the user's own command under `op run`) has no limit.
#[derive(Debug, Clone)]
pub struct ProcessRunner {
    budget: Budget,
    verbose: bool,
    /// Extra per-call limit (tests); `None` uses the effect limits only.
    cap: Option<Duration>,
    /// A target write started ([`CommandRunner::writes_started`]).
    wrote: Arc<AtomicBool>,
    /// The project's 1Password account (FR-40, NR-7): every `op` call that names no account
    /// of its own (an environment's `OP_ACCOUNT`) uses it, never op's default.
    account: Arc<Mutex<Option<String>>>,
}

impl ProcessRunner {
    /// Use `account` for every `op` call that names none (see the field).
    pub fn use_account(&self, account: Option<String>) {
        lock(&DEFAULT_ACCOUNT).clone_from(&account);
        *lock(&self.account) = account;
    }

    /// `env` plus the run's account for an `op` call that names none.
    fn with_default_account<'e>(
        &'e self,
        program: &str,
        env: &[(&'e str, &'e str)],
        held: &'e Option<String>,
    ) -> Vec<(&'e str, &'e str)> {
        let mut all = env.to_vec();
        if program == crate::host::OP_CLI.program
            && !env.iter().any(|(k, _)| *k == "OP_ACCOUNT")
            && let Some(a) = held
        {
            all.push(("OP_ACCOUNT", a.as_str()));
        }
        all
    }

    /// A runner for one opv run: `budget` caps every call, `verbose` prints one stderr line
    /// per call (NR-22).
    pub fn new(budget: Budget, verbose: bool) -> Self {
        Self {
            budget,
            verbose,
            cap: None,
            wrote: Arc::new(AtomicBool::new(false)),
            account: Arc::new(Mutex::new(None)),
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

    fn spawn_attempt(&self, call: &Call, limit: Duration) -> io::Result<(Attempt, Stderr)> {
        if signals::stopping() {
            signals::wait_for_exit();
        }
        let limit = self.cap.map_or(limit, |c| c.min(limit));
        let deadline = Instant::now() + limit;
        let held = lock(&self.account).clone();
        let env = self.with_default_account(call.program, call.env, &held);
        let mut child = command_for(&Call { env: &env, ..*call }).spawn()?;
        signals::track(&child);
        let child_stderr = child.stderr.take().expect("stderr is piped");
        // stderr is read on its own thread into a bounded, zeroizing buffer held in memory
        // only (NR-31). The buffer is shared so what arrived is kept even when a grandchild
        // keeps the pipe open.
        let tail = Arc::new(Mutex::new((Stderr::default(), false)));
        let sink = Arc::clone(&tail);
        std::thread::spawn(move || {
            let mut pipe = child_stderr;
            let mut chunk = Zeroizing::new([0u8; 8 * 1024]);
            loop {
                match pipe.read(&mut chunk[..]) {
                    Ok(0) => break,
                    Ok(n) => lock(&sink).0.push(&chunk[..n]),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
            lock(&sink).1 = true;
        });
        let attempt = self.wait_attempt(call, &mut child, deadline)?;
        let grace = Instant::now() + STDERR_GRACE;
        while !lock(&tail).1 && Instant::now() < grace {
            std::thread::sleep(Duration::from_millis(5));
        }
        let stderr = lock(&tail).0.take();
        Ok((attempt, stderr))
    }

    /// Feed stdin, collect stdout and wait for the child within `deadline`.
    fn wait_attempt(
        &self,
        call: &Call,
        child: &mut std::process::Child,
        deadline: Instant,
    ) -> io::Result<Attempt> {
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

        // A rollout write runs for minutes: say it is still running (NR-4).
        let started = Instant::now();
        let mut said = started;
        let status = loop {
            if call.limit.is_some() && said.elapsed() >= PROGRESS_EVERY {
                said = Instant::now();
                Engine::note(
                    self,
                    &format!(
                        "still running {} ({} s)",
                        call.step(),
                        started.elapsed().as_secs()
                    ),
                );
            }
            match signals::reap(child) {
                Ok(Some(st)) => break st,
                Ok(None) => {}
                Err(_) => {
                    signals::kill(child);
                    return Ok(Attempt::Lost);
                }
            }
            if over.load(Ordering::SeqCst) {
                signals::kill(child);
                return Ok(Attempt::OverCap(KILLED_BY_OPV));
            }
            if Instant::now() >= deadline {
                signals::kill(child);
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
            Ok(Ok(None)) => return Ok(Attempt::OverCap(exit_class_of(status))),
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

/// A poisoned lock still holds a usable buffer: a reader thread that panicked only stops
/// adding to it.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Default for ProcessRunner {
    fn default() -> Self {
        Self::new(Budget::default(), false)
    }
}

/// The run's default 1Password account ([`ProcessRunner::use_account`]), and the account of
/// the last `op` call that failed as signed out (its `--account` or `OP_ACCOUNT`, else the
/// default). The automatic sign-in signs in to that account, never to another one that
/// happens to be recorded somewhere (0.9.0: a sign-in to `.opv`'s account could not fix an
/// environment that uses another).
static DEFAULT_ACCOUNT: Mutex<Option<String>> = Mutex::new(None);
static SIGNED_OUT_ACCOUNT: Mutex<Option<String>> = Mutex::new(None);

/// The account an `op` call names: its `--account` value, else its `OP_ACCOUNT`.
fn call_account(call: &Call) -> Option<String> {
    call.args
        .windows(2)
        .find(|w| w[0] == "--account")
        .map(|w| w[1].to_string())
        .or_else(|| {
            call.env
                .iter()
                .rev()
                .find(|(k, _)| *k == "OP_ACCOUNT")
                .map(|(_, v)| v.to_string())
        })
}

fn note_signed_out(call: &Call) {
    let account = call_account(call).or_else(|| lock(&DEFAULT_ACCOUNT).clone());
    *lock(&SIGNED_OUT_ACCOUNT) = account;
}

/// The account to sign in to after a signed-out failure: that call's account, else the
/// run's default. Taken once.
pub fn signed_out_account() -> Option<String> {
    lock(&SIGNED_OUT_ACCOUNT)
        .take()
        .or_else(|| lock(&DEFAULT_ACCOUNT).clone())
}

/// An `op` session opv itself started in this process: an interactive command that found
/// no session signs the person in at op's own prompt and tries once more (found live: a
/// session idle over 30 minutes stopped `opv check` with only "run opv login"). Passed to
/// every `op` call of this process and to nothing else; never printed or written (SR-1,
/// SR-4), and gone when the process exits.
static OP_SESSION: Mutex<Vec<(String, crate::domain::SecretValue)>> = Mutex::new(Vec::new());

/// Use `vars` (`OP_SESSION_<account>`, from `op signin`) for every later `op` call.
pub fn use_op_session(vars: Vec<(String, crate::domain::SecretValue)>) {
    *lock(&OP_SESSION) = vars;
}

/// Add the session from [`use_op_session`] to `cmd` when it runs `op`.
fn add_op_session(cmd: &mut Command, program: &str) {
    if program == "op" {
        for (k, v) in lock(&OP_SESSION).iter() {
            cmd.env(k, v.expose());
        }
    }
}

/// op's credential variables that are not sessions: a service-account or Connect token gives
/// whoever holds it the same 1Password access, so another CLI never inherits one either.
const OP_TOKEN_VARS: &[&str] = &["OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_TOKEN"];

/// FMECA M6: a child that is not `op` gets no 1Password session or token ([`OP_TOKEN_VARS`]),
/// neither one inherited from the shell (`opv login --shell`, `eval $(op signin)`, CI's
/// service-account token) nor one set on `cmd` itself. Applied after every other variable,
/// so it wins. `op` keeps its session: it needs it.
pub fn strip_op_session(cmd: &mut Command, program: &str) {
    strip_session_vars(
        cmd,
        program,
        std::env::vars_os().filter_map(|(k, _)| k.into_string().ok()),
    );
}

/// [`strip_op_session`] with the inherited variable names given (tests: no test sets a
/// process-wide variable).
pub(crate) fn strip_session_vars(
    cmd: &mut Command,
    program: &str,
    inherited: impl Iterator<Item = String>,
) {
    if program == "op" {
        return;
    }
    let set: Vec<String> = cmd
        .get_envs()
        .filter(|(_, v)| v.is_some())
        .filter_map(|(k, _)| k.to_str().map(str::to_string))
        .collect();
    let names: std::collections::BTreeSet<String> = inherited
        .chain(set)
        .filter(|k| crate::app::account::is_session_var(k) || OP_TOKEN_VARS.contains(&k.as_str()))
        .collect();
    for name in names {
        cmd.env_remove(name);
    }
}

/// The process for a captured call: argv as given, the program's [`pinned_env`] then the
/// call's own env on top of the inherited environment, stdin `/dev/null` unless the call
/// sends some (NR-11), stdout piped, stderr piped into memory (SR-1, NR-31).
fn command_for(call: &Call) -> Command {
    let mut cmd = Command::new(call.program);
    cmd.args(with_account(call.program, call.args, call.env))
        .envs(pinned_env(call.program).iter().copied());
    add_op_session(&mut cmd, call.program);
    cmd.envs(call.env.iter().copied());
    strip_op_session(&mut cmd, call.program);
    cmd.stdin(if call.stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    cmd
}

/// `args` for `program`, with `--account <a>` added to an `op` call whose env names an
/// account (`OP_ACCOUNT`, set per environment, FR-40) and whose argv names none. The flag
/// reaches `op` where an environment variable may not (a Windows `op.exe` started from
/// WSL sees no Linux variables), so the call never falls back to op's default account
/// (NR-7). It goes before any `--`, which starts the child command of `op run`.
fn with_account<'a>(program: &str, args: &[&'a str], env: &[(&'a str, &'a str)]) -> Vec<&'a str> {
    let mut out = args.to_vec();
    // `op --version` and `op account ...` are about no one account; op refuses the flag
    // on `--version` (found live).
    let accountless = matches!(args.first(), Some(&"--version") | Some(&"account"));
    if program != crate::host::OP_CLI.program || accountless || args.contains(&"--account") {
        return out;
    }
    let Some(account) = env
        .iter()
        .rev()
        .find(|(k, _)| *k == "OP_ACCOUNT")
        .map(|(_, v)| *v)
    else {
        return out;
    };
    let at = out.iter().position(|a| *a == "--").unwrap_or(out.len());
    out.splice(at..at, ["--account", account]);
    out
}

/// Observe an inherited call (`op run -- <cmd>`, FR-4) that failed to start or exited
/// non-zero, like a captured one. Its child command after `--` is never named.
/// An inherited call (`op run` and the person's command under it) is observed only when it
/// could not be started: its exit code and signals are the person's own command's, never a
/// 1Password failure.
fn observe_inherited(call: &Call, env: &[(&str, &str)], status: &io::Result<ExitStatus>) {
    let id = failure::begin();
    if let Err(e) = status {
        let res: io::Result<(Attempt, Stderr)> = Err(io::Error::from(e.kind()));
        observe_attempt(id, &Call { env, ..*call }, &res);
    }
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

/// The time limit of one attempt. Builds with the `fake` feature (tests only; release builds
/// never enable it) read `OPV_TEST_CALL_LIMIT` (seconds) and stop a call at the lower of it
/// and `limit`, so the end-to-end matrix sees a hanging tool end as opv's own timeout, the
/// runner fact a real hang produces, without waiting out the real limits.
/// `OPV_TEST_CALL_LIMIT_CALL` (`<program> <word>…`) narrows that to the hanging call
/// ([`in_test_limit_scope`]): every other call keeps its real limit, so a slow machine cannot
/// time it out.
fn test_call_limit(limit: Duration, call: &Call) -> Duration {
    #[cfg(feature = "fake")]
    if let Some(s) = std::env::var("OPV_TEST_CALL_LIMIT")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|s| s.is_finite() && *s > 0.0)
        && std::env::var("OPV_TEST_CALL_LIMIT_CALL")
            .ok()
            .is_none_or(|scope| in_test_limit_scope(&scope, call.program, call.args))
    {
        return limit.min(Duration::from_secs_f64(s));
    }
    #[cfg(not(feature = "fake"))]
    let _ = call;
    limit
}

/// Whether a call is in a `<program> <word>…` scope: the same program (`fly` is `flyctl`) and
/// the words in its argv in order, flags and their values anywhere between them.
#[cfg(any(feature = "fake", test))]
fn in_test_limit_scope(scope: &str, program: &str, args: &[&str]) -> bool {
    let name = |p: &str| {
        let base = std::path::Path::new(p)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(p)
            .to_string();
        if base == "fly" { "flyctl".into() } else { base }
    };
    let mut words = scope.split_whitespace();
    if words.next().is_none_or(|p| name(p) != name(program)) {
        return false;
    }
    let mut args = args.iter();
    words.all(|w| args.any(|a| *a == w))
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
    fn verbose(&self) -> bool {
        self.verbose
    }
    fn attempt(&self, call: &Call, limit: Duration) -> io::Result<(Attempt, Stderr)> {
        // HTTPS is a runner effect, never a spawned program (design §5): the real attempt
        // runs in process. Only the fake feature with an active sim world spawns the
        // `https` program from PATH, so a release build can never spawn one.
        if call.program == crate::runner_https::PROGRAM && !https_fake_attempt() {
            return crate::runner_https::real_attempt(call, limit);
        }
        self.spawn_attempt(call, test_call_limit(limit, call))
    }
    fn wrote(&self, program: &str) {
        if target_write(program) {
            self.wrote.store(true, Ordering::SeqCst);
            signals::note_write();
        }
    }
}

/// Read only the executable header, never any credential source.
pub(crate) fn windows_binary(path: &std::path::Path) -> io::Result<bool> {
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
    fn remaining(&self) -> Option<Duration> {
        Some(left(self))
    }

    fn spawns_processes(&self) -> bool {
        true
    }

    fn writes_started(&self) -> bool {
        self.wrote.load(Ordering::SeqCst)
    }

    fn read(&self, call: &Call, refused: &[i32]) -> io::Result<Outcome> {
        read_on(self, call, refused)
    }

    fn write(&self, call: &Call) -> io::Result<Outcome> {
        write_on(self, call)
    }

    fn probe(&self, call: &Call, limit: Duration) -> io::Result<Output> {
        probe_on(self, call, limit)
    }

    fn pause(&self, d: Duration, note: &str) {
        pause_on(self, d, note)
    }

    fn note(&self, line: &str) {
        Engine::note(self, line)
    }

    fn step_summary(&self, markdown: &str) {
        if let Some(path) = std::env::var_os("GITHUB_STEP_SUMMARY").filter(|p| !p.is_empty()) {
            append_summary(std::path::Path::new(&path), markdown);
        }
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
        self.inherited(program, args, env, remove, ChildSession::Strip)
    }

    fn run_inherited(&self, program: &str, args: &[&str], env: &[(&str, &str)]) -> io::Result<i32> {
        self.inherited(program, args, env, &[], ChildSession::Strip)
    }
}

/// Whether an inherited child that is not `op` may keep a 1Password session (FMECA M6).
#[derive(Clone, Copy, PartialEq, Eq)]
enum ChildSession {
    /// Every `OP_SESSION*` is removed ([`strip_op_session`]).
    Strip,
    /// `opv login -- <cmd>`: handing the session to the child is the command's purpose.
    Keep,
}

impl ProcessRunner {
    /// `opv login -- <cmd>` (`setup_runtime::spawn_child`): [`CommandRunner::run_inherited`]
    /// that passes the session on, by design (session-reuse §6). Nothing else uses it.
    pub fn run_signed_in_child(
        &self,
        program: &str,
        args: &[&str],
        env: &[(&str, &str)],
    ) -> io::Result<i32> {
        self.inherited(program, args, env, &[], ChildSession::Keep)
    }

    /// One inherited child: `remove` dropped from the inherited environment, opv's own
    /// session on an `op` child, `env` on top, then (unless `session` keeps it) every
    /// `OP_SESSION*` off a child that is not `op`.
    fn inherited(
        &self,
        program: &str,
        args: &[&str],
        env: &[(&str, &str)],
        remove: &[String],
        session: ChildSession,
    ) -> io::Result<i32> {
        let held = lock(&self.account).clone();
        let env = &self.with_default_account(program, env, &held);
        let mut cmd = Command::new(program);
        for key in remove {
            cmd.env_remove(key);
        }
        add_op_session(&mut cmd, program);
        cmd.args(with_account(program, args, env))
            .envs(env.iter().copied());
        if session == ChildSession::Strip {
            strip_op_session(&mut cmd, program);
        }
        let status = cmd
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status();
        observe_inherited(&Call::new(program, args), env, &status);
        Ok(exit_code(status?))
    }
}

/// SIGINT/SIGTERM/SIGHUP/SIGQUIT handling (NR-12, I2): the signal is forwarded to the
/// running captured child (SIGQUIT as SIGTERM, so no core dump), which gets
/// [`SIGNAL_GRACE`] before it is killed; the registered private directories are removed
/// (SR-4); opv then exits 128 + the signal (130 for SIGINT, 143 for SIGTERM) with
/// "interrupted during <step>; safe to re-run". Core dumps are disabled for every command by
/// [`crate::hardening::harden`], the first statement of `main` (SR-8). On Windows a console control handler (Ctrl-C, Ctrl-Break, closing the
/// console, log-off, shutdown) does the same: the console delivers the event to the child
/// too, so opv waits for it, ends it after the grace period, cleans up and exits 130.
pub mod signals {
    use std::process::{Child, ExitStatus};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Mutex, MutexGuard};

    /// The captured child currently running, by pid.
    static CHILD: Mutex<Option<u32>> = Mutex::new(None);
    /// A target write started in this process: the interruption says so (design §4.6).
    static WRITES_STARTED: AtomicBool = AtomicBool::new(false);

    /// Record that a target write started, for the interruption report.
    pub fn note_write() {
        WRITES_STARTED.store(true, Ordering::SeqCst);
    }
    /// Private directories to remove before the process exits on a signal (SR-4: the
    /// Azure CLI's RAM-only configuration directory of a deploy sign-in, FR-40).
    static CLEANUP: Mutex<Vec<std::path::PathBuf>> = Mutex::new(Vec::new());

    /// `--json`: an interruption also prints the failure document on stdout (A1).
    static JSON: AtomicBool = AtomicBool::new(false);

    /// Record whether stdout is one JSON document, for the interruption report.
    pub fn set_json(json: bool) {
        JSON.store(json, Ordering::SeqCst);
    }

    /// The interruption by signal `sig` as the catalog's cause.
    pub fn interrupted(sig: i32) -> crate::error::Error {
        crate::cause::Cause::Interrupted {
            signal: sig,
            writes_started: WRITES_STARTED.load(Ordering::SeqCst),
        }
        .into()
    }
    static STOPPING: AtomicBool = AtomicBool::new(false);

    /// Run first when opv exits on a signal: `opv ui` puts the terminal back (raw mode off,
    /// main screen) so the report and the shell after it are readable.
    static ON_EXIT: Mutex<Option<fn()>> = Mutex::new(None);

    /// While set, a child in the foreground owns the terminal (`opv ui` running an `opv`
    /// command): the terminal's own keys (Ctrl-C, Ctrl-\) stop that child, not opv.
    static CHILD_OWNS_TERMINAL: AtomicBool = AtomicBool::new(false);

    /// What to run before opv exits on a signal (`None`: nothing).
    pub fn set_on_exit(f: Option<fn()>) {
        *lock(&ON_EXIT) = f;
    }

    /// Whether a foreground child owns the terminal now (see [`ignored`]).
    pub fn set_child_owns_terminal(on: bool) {
        CHILD_OWNS_TERMINAL.store(on, Ordering::SeqCst);
    }

    /// Whether opv ignores `sig` (true: the terminal sent it to a foreground child, which
    /// stops on its own while opv carries on).
    #[cfg(unix)]
    pub fn ignored(sig: i32) -> bool {
        CHILD_OWNS_TERMINAL.load(Ordering::SeqCst) && (sig == libc::SIGINT || sig == libc::SIGQUIT)
    }

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

    /// The pid of the captured child running now, if any: the Windows value pipe accepts
    /// only this process or one of its descendants as its client (M1).
    pub fn current_child() -> Option<u32> {
        *lock(&CHILD)
    }

    pub(super) fn track(child: &Child) {
        *lock(&CHILD) = Some(child.id());
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

    /// Remove `dir` (recursively) if opv exits on a signal before it is removed normally.
    pub fn register_cleanup(dir: std::path::PathBuf) {
        lock(&CLEANUP).push(dir);
    }

    /// `dir` was removed normally: forget it.
    pub fn unregister_cleanup(dir: &std::path::Path) {
        lock(&CLEANUP).retain(|d| d != dir);
    }

    /// Remove every registered directory (best effort): what the signal handler does before
    /// it exits, after the running child was stopped.
    pub fn run_cleanups() {
        run_cleanups_where(|_| true);
    }

    /// [`run_cleanups`] for the registered directories `pick` selects (tests run in
    /// parallel, so one test cleans only its own).
    pub fn run_cleanups_where(pick: impl Fn(&std::path::Path) -> bool) {
        let mut dirs = lock(&CLEANUP);
        dirs.retain(|d| {
            if pick(d) {
                let _ = std::fs::remove_dir_all(d);
                false
            } else {
                true
            }
        });
    }

    /// The signals opv handles (I2: a closed terminal or dropped SSH session sends SIGHUP,
    /// Ctrl-\\ sends SIGQUIT; both would otherwise skip every cleanup).
    #[cfg(unix)]
    pub const HANDLED: [i32; 4] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

    /// What the handler does once a signal or console event arrived: stop new calls, stop
    /// the running child, remove the private directories, report and exit `128 + sig`.
    fn stop_and_exit(sig: i32) -> ! {
        STOPPING.store(true, Ordering::SeqCst);
        if let Some(f) = *lock(&ON_EXIT) {
            f();
        }
        forward(sig);
        run_cleanups();
        let e = interrupted(sig);
        if JSON.load(Ordering::SeqCst) {
            stdout_unlocked(&String::from_utf8_lossy(&crate::json::finish(
                b"",
                Err(&e),
                false,
            )));
        }
        eprint!("{}", crate::error::report(&e));
        std::process::exit(128 + sig);
    }

    /// Write `text` to stdout without taking its lock: `main` holds that lock for the whole
    /// command, so `println!` from the signal thread would wait forever and opv would never
    /// exit. Best effort; the handle is borrowed, never closed.
    fn stdout_unlocked(text: &str) {
        use std::io::Write;
        #[cfg(unix)]
        {
            use std::os::fd::FromRawFd;
            // SAFETY: fd 1 stays open for the life of the process; ManuallyDrop never
            // closes it.
            let mut out = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(1) });
            let _ = out.write_all(text.as_bytes());
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::FromRawHandle;
            use windows_sys::Win32::System::Console::{GetStdHandle, STD_OUTPUT_HANDLE};
            // SAFETY: a plain call; the handle belongs to the process and ManuallyDrop never
            // closes it.
            let h = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
            if h.is_null() || h == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
                return;
            }
            let mut out = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_handle(h) });
            let _ = out.write_all(text.as_bytes());
        }
        #[cfg(not(any(unix, windows)))]
        let _ = std::io::stdout().write_all(text.as_bytes());
    }

    /// Install the handler (once, from `main`).
    #[cfg(unix)]
    pub fn install() -> std::io::Result<()> {
        let mut signals = signal_hook::iterator::Signals::new(HANDLED)?;
        std::thread::spawn(move || {
            if let Some(sig) = signals.forever().find(|s| !ignored(*s)) {
                stop_and_exit(sig);
            }
        });
        Ok(())
    }

    /// Install the console control handler (once, from `main`): Ctrl-C, Ctrl-Break,
    /// closing the console, log-off and shutdown all stop the child, remove the private
    /// directories and exit (I2, SR-4).
    #[cfg(windows)]
    pub fn install() -> std::io::Result<()> {
        use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
        // SAFETY: registers a plain `extern "system"` function that lives for the process.
        if unsafe { SetConsoleCtrlHandler(Some(on_console_event), 1) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Runs on a thread the system creates for the event. Never returns: returning would
    /// let the default handler end the process before the cleanup.
    #[cfg(windows)]
    unsafe extern "system" fn on_console_event(event: u32) -> windows_sys::core::BOOL {
        use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT};
        // Ctrl-C and Ctrl-Break while a foreground child owns the console stop that child
        // (the console delivers them to it too); opv carries on.
        if CHILD_OWNS_TERMINAL.load(Ordering::SeqCst)
            && (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT)
        {
            return 1;
        }
        // Every other event is reported as an interruption (exit 130, like SIGINT).
        stop_and_exit(2)
    }

    #[cfg(not(any(unix, windows)))]
    pub fn install() -> std::io::Result<()> {
        Ok(())
    }

    /// Wait up to the grace period for the console's own event to end the child, then end
    /// it (Windows delivers Ctrl-C and close to every process on the console).
    #[cfg(windows)]
    fn forward(_sig: i32) {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_TERMINATE, TerminateProcess,
        };
        let Some(id) = *lock(&CHILD) else { return };
        let t = std::time::Instant::now();
        while t.elapsed() < super::SIGNAL_GRACE {
            if *lock(&CHILD) != Some(id) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let slot = lock(&CHILD);
        if *slot == Some(id) {
            // SAFETY: a terminate-only handle on a pid we spawned and have not reaped (the
            // slot is cleared under this lock when it is reaped), closed right after.
            unsafe {
                let h = OpenProcess(PROCESS_TERMINATE, 0, id);
                if !h.is_null() {
                    TerminateProcess(h, 1);
                    CloseHandle(h);
                }
            }
        }
    }

    #[cfg(not(any(unix, windows)))]
    fn forward(_sig: i32) {}

    /// Send `sig` to the current child (SIGQUIT as SIGTERM: no core dump), wait up to the
    /// grace period, then kill it.
    #[cfg(unix)]
    fn forward(sig: i32) {
        let Some(id) = *lock(&CHILD) else { return };
        let Ok(pid) = i32::try_from(id) else { return };
        let sig = if sig == libc::SIGQUIT {
            libc::SIGTERM
        } else {
            sig
        };
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
    use std::collections::{HashMap, VecDeque};
    use std::io;
    use std::time::{Duration, Instant};

    use super::{Attempt, CommandRunner, Engine, KILLED_BY_OPV, Outcome, Output, Stderr};

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
        /// `--verbose`: call lines, scrubbed stderr and stdout shape go to `notes`.
        pub verbose: Cell<bool>,
        /// Child stderr per call index (see [`FakeRunner::push_with_stderr`]).
        stderr: RefCell<HashMap<usize, Vec<u8>>>,
        /// Markdown passed to [`CommandRunner::step_summary`], in order.
        pub summaries: RefCell<Vec<String>>,
        /// Fake time each captured call takes (zero by default), so a wait that counts
        /// only its sleeps is caught (NR-4).
        pub call_cost: Cell<Duration>,
        /// A target write started ([`CommandRunner::writes_started`]).
        pub target_writes: Cell<bool>,
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
                verbose: Cell::new(false),
                stderr: RefCell::default(),
                summaries: RefCell::default(),
                call_cost: Cell::new(Duration::ZERO),
                target_writes: Cell::new(false),
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

        /// Queue `out` for the next unanswered call, with `stderr` as the child's stderr.
        pub fn push_with_stderr(&self, out: Output, stderr: &str) {
            let index = self.calls.borrow().len() + self.responses.borrow().len();
            self.stderr
                .borrow_mut()
                .insert(index, stderr.as_bytes().to_vec());
            self.responses.borrow_mut().push_back(Ok(out));
        }

        /// Queue an unknown outcome (`timeout`, `killed`, `lost`) whose child wrote `stderr`.
        pub fn push_unknown_with_stderr(&self, reason: &str, stderr: &str) {
            let index = self.calls.borrow().len() + self.responses.borrow().len();
            self.stderr
                .borrow_mut()
                .insert(index, stderr.as_bytes().to_vec());
            self.push_unknown(reason);
        }

        /// The stderr queued for call `index`, if any.
        fn stderr_of(&self, index: usize) -> Stderr {
            let mut s = Stderr::default();
            if let Some(b) = self.stderr.borrow_mut().remove(&index) {
                s.push(&b);
            }
            s
        }

        /// Queue an HTTPS reply for the next call to [`crate::runner_https::PROGRAM`]: the
        /// reply's envelope is what the call's stdout carries, so `https_read` decodes it.
        pub fn push_https_reply(&self, reply: &crate::runner_https::HttpsReply) {
            self.responses.borrow_mut().push_back(Ok(Output {
                status: 0,
                stdout: crate::runner_https::encode_reply(reply),
            }));
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

    /// The signal a queued `Interrupted` (a kill) stands for: SIGKILL.
    const FAKE_KILL_SIGNAL: i32 = 9;

    /// The outcome a queued `io` error stands for (see the module docs); any other kind is a
    /// spawn error.
    fn attempt_for(kind: io::ErrorKind) -> io::Result<Attempt> {
        Ok(match kind {
            io::ErrorKind::TimedOut => Attempt::TimedOut,
            io::ErrorKind::Interrupted => Attempt::Killed(FAKE_KILL_SIGNAL),
            io::ErrorKind::ConnectionAborted => Attempt::Lost,
            io::ErrorKind::OutOfMemory => Attempt::OverCap(KILLED_BY_OPV),
            _ => return Err(kind.into()),
        })
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
        fn verbose(&self) -> bool {
            self.verbose.get()
        }
        fn wrote(&self, program: &str) {
            if super::target_write(program) {
                self.target_writes.set(true);
            }
        }
        fn attempt(&self, call: &super::Call, _limit: Duration) -> io::Result<(Attempt, Stderr)> {
            self.elapsed.set(self.elapsed.get() + self.call_cost.get());
            let index = self.calls.borrow().len();
            let attempt = match self.record(call.program, call.args, call.stdin, call.env, false) {
                Ok(o) => Attempt::Exited(o),
                Err(e) => attempt_for(e.kind())?,
            };
            Ok((attempt, self.stderr_of(index)))
        }
    }

    impl CommandRunner for FakeRunner {
        fn remaining(&self) -> Option<Duration> {
            Some(super::left(self))
        }

        fn writes_started(&self) -> bool {
            self.target_writes.get()
        }

        fn read(&self, call: &super::Call, refused: &[i32]) -> io::Result<Outcome> {
            super::read_on(self, call, refused)
        }

        fn write(&self, call: &super::Call) -> io::Result<Outcome> {
            super::write_on(self, call)
        }

        fn create(
            &self,
            call: &super::Call,
            _kind: crate::cause::CreateKind,
        ) -> io::Result<super::CreateOutcome> {
            super::runner_create::from_write(super::write_on(self, call), call)
        }

        /// A queued `TimedOut` comes back as that error, like a real probe timeout. A
        /// non-zero exit keeps its stderr for the failure excerpt, like the real probe.
        ///
        /// An `op whoami` probe with nothing queued answers exit 1 (no account known), so a
        /// test that is not about the optional link probe after findings (H1) need not
        /// queue it; its argv is still recorded.
        fn probe(&self, call: &super::Call, _limit: Duration) -> io::Result<Output> {
            if call.program == "op"
                && call.args.first() == Some(&"whoami")
                && self.responses.borrow().is_empty()
            {
                self.responses
                    .borrow_mut()
                    .push_back(Ok(Output::failure(1)));
            }
            let id = super::failure::begin();
            self.elapsed.set(self.elapsed.get() + self.call_cost.get());
            let index = self.calls.borrow().len();
            let res = self.record(call.program, call.args, call.stdin, call.env, false);
            let seen = match &res {
                Ok(o) => Ok((
                    Attempt::Exited(Output::failure(o.status)),
                    Stderr::default(),
                )),
                Err(e) => attempt_for(e.kind()).map(|a| (a, Stderr::default())),
            };
            super::observe_attempt(id, call, &seen);
            let out = res?;
            let stderr = self.stderr_of(index);
            if out.status != 0 {
                super::failure::record(id, call.program, stderr);
            }
            Ok(out)
        }

        fn pause(&self, d: Duration, note: &str) {
            super::pause_on(self, d, note)
        }

        fn note(&self, line: &str) {
            super::Engine::note(self, line)
        }

        /// Recorded in [`FakeRunner::summaries`]; no file is written.
        fn step_summary(&self, markdown: &str) {
            self.summaries.borrow_mut().push(markdown.to_string());
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

#[path = "runner_create.rs"]
mod runner_create;

pub use runner_create::CreateOutcome;

#[cfg(test)]
#[path = "runner_observed_tests.rs"]
mod observed_tests;

#[cfg(test)]
mod tests {
    use super::fake::FakeRunner;
    use super::*;

    // ------------------------------------------------------------ HTTPS as a runner effect

    #[test]
    fn fake_runner_returns_a_scripted_https_reply() {
        let r = FakeRunner::default();
        r.push_https_reply(&crate::runner_https::HttpsReply {
            status: 200,
            content_type: Some("application/grpc-web+proto".into()),
            grpc_status: Some(0),
            grpc_message: None,
            body: zeroize::Zeroizing::new(vec![1, 2, 3]),
        });
        let req = crate::runner_https::HttpsRequest {
            method: "POST",
            uri: "central.zonetico.com/svc/Method".into(),
            headers: Vec::new(),
            body: zeroize::Zeroizing::new(Vec::new()),
        };
        let reply = r.https_read(&req).expect("a scripted reply");
        assert_eq!(reply.grpc_status, Some(0));
    }

    #[test]
    fn an_https_call_is_not_spawned_without_a_sim_world() {
        assert!(!fake_https_attempt(true, false));
    }

    #[test]
    fn a_release_build_never_spawns_an_https_call() {
        assert!(!fake_https_attempt(false, true));
    }

    // ------------------------------------------------------------ the matrix's call limit

    #[test]
    fn a_call_with_the_scope_words_in_order_is_in_the_test_limit_scope() {
        let args = ["--account", "A", "item", "get", "i1", "--format", "json"];
        assert!(in_test_limit_scope("op item get i1", "op", &args));
    }

    #[test]
    fn a_call_of_another_program_is_out_of_the_test_limit_scope() {
        assert!(!in_test_limit_scope("op whoami", "kubectl", &["whoami"]));
    }

    #[test]
    fn a_call_missing_a_scope_word_is_out_of_the_test_limit_scope() {
        let args = ["auth", "can-i", "get", "secrets"];
        assert!(!in_test_limit_scope(
            "kubectl auth can-i get deployments",
            "kubectl",
            &args
        ));
    }

    #[test]
    fn fly_is_flyctl_in_the_test_limit_scope() {
        assert!(in_test_limit_scope(
            "flyctl auth whoami",
            "fly",
            &["auth", "whoami"]
        ));
    }

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

    /// S2: `op` saying the item does not exist is refused at once, never retried.
    #[test]
    fn read_while_signed_out_of_op_is_not_retried() {
        let r = FakeRunner::default();
        (0..3).for_each(|_| {
            r.push_with_stderr(
                Output::failure(1),
                "[ERROR] 2026/10/11 03:47:46 You are not currently signed in. Please run `op signin --help` for instructions\n",
            )
        });
        let _ = read_fake(&r);
        assert_eq!(r.calls.borrow().len(), 1);
    }

    #[test]
    fn read_without_a_session_token_is_not_retried() {
        let r = FakeRunner::default();
        (0..3).for_each(|_| {
            r.push_with_stderr(
                Output::failure(1),
                "[ERROR] 2026/10/11 05:14:07 could not find session token for account mcproductlabs\n",
            )
        });
        let _ = read_fake(&r);
        assert_eq!(r.calls.borrow().len(), 1);
    }

    /// A session opv starts after an idle one expired reaches op, and only op.
    #[test]
    fn a_session_opv_started_is_passed_to_op_calls_only() {
        use_op_session(vec![(
            "OP_SESSION_ACCT".into(),
            crate::domain::SecretValue::new("tok".into()),
        )]);
        let has = |p: &str| {
            command_for(&Call::new(p, &[]))
                .get_envs()
                .any(|(k, _)| k == "OP_SESSION_ACCT")
        };
        let seen = (has("op"), has("flyctl"));
        use_op_session(Vec::new());
        assert_eq!(seen, (true, false));
    }

    /// FMECA M6: a captured call of another CLI carries no session, even one set on it.
    #[test]
    fn a_captured_call_of_another_cli_has_no_session() {
        let env = [("OP_SESSION_acct", "canary"), ("OP_SESSION", "canary")];
        let call = Call {
            env: &env,
            ..Call::new("flyctl", &[])
        };
        let removed: Vec<_> = command_for(&call)
            .get_envs()
            .filter(|(_, v)| v.is_none())
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        assert_eq!(removed, ["OP_SESSION", "OP_SESSION_acct"]);
    }

    /// `op` itself keeps the session it is given.
    #[test]
    fn a_captured_op_call_keeps_its_session() {
        let env = [("OP_SESSION_acct", "canary")];
        let call = Call {
            env: &env,
            ..Call::new("op", &[])
        };
        assert!(
            command_for(&call)
                .get_envs()
                .any(|(k, v)| k == "OP_SESSION_acct" && v.is_some())
        );
    }

    /// An inherited session (the shell's `opv login --shell`) is removed from another CLI.
    #[test]
    fn an_inherited_session_is_removed_from_another_cli() {
        let mut cmd = Command::new("gh");
        let inherited = ["OP_SESSION_acct", "PATH", "OP_SESSION_DELEGATION_ENABLED"];
        strip_session_vars(&mut cmd, "gh", inherited.iter().map(|s| s.to_string()));
        let removed: Vec<_> = cmd
            .get_envs()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        assert_eq!(removed, ["OP_SESSION_acct"]);
    }

    /// CI's service-account token is removed from another CLI, as a session is.
    #[test]
    fn an_inherited_service_account_token_is_removed_from_another_cli() {
        let mut cmd = Command::new("flyctl");
        let inherited = ["OP_SERVICE_ACCOUNT_TOKEN", "PATH"];
        strip_session_vars(&mut cmd, "flyctl", inherited.iter().map(|s| s.to_string()));
        let removed: Vec<_> = cmd
            .get_envs()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        assert_eq!(removed, ["OP_SERVICE_ACCOUNT_TOKEN"]);
    }

    /// `op` itself keeps the service-account token: it authenticates with it.
    #[test]
    fn an_op_call_keeps_the_service_account_token() {
        let mut cmd = Command::new("op");
        let inherited = ["OP_SERVICE_ACCOUNT_TOKEN"];
        strip_session_vars(&mut cmd, "op", inherited.iter().map(|s| s.to_string()));
        assert_eq!(cmd.get_envs().count(), 0);
    }

    /// The names of the variables an inherited child of `ProcessRunner` saw, by running
    /// `sh -c env` through `spawn` (names only; the canary value is compared, not printed).
    #[cfg(unix)]
    fn inherited_env_of(
        spawn: impl FnOnce(&ProcessRunner, &[&str], &[(&str, &str)]) -> io::Result<i32>,
    ) -> String {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("env");
        let out_s = out.to_str().unwrap().to_string();
        let script = "env > \"$0\"";
        let env = [
            ("OP_SESSION_canary", "S8CANARYsession"),
            ("OP_SESSION", "S8CANARYsession"),
            ("OP_SESSION_DELEGATION_ENABLED", "true"),
        ];
        let code = spawn(&ProcessRunner::default(), &["-c", script, &out_s], &env).unwrap();
        assert_eq!(code, 0);
        std::fs::read_to_string(out).unwrap()
    }

    /// FMECA M6: `run_inherited` (flyctl's deploy, `gh`) starts a CLI without a session.
    #[cfg(unix)]
    #[test]
    fn an_inherited_cli_child_gets_no_session() {
        let seen = inherited_env_of(|r, a, e| r.run_inherited("sh", a, e));
        assert!(
            !seen.contains("S8CANARYsession") && !seen.contains("OP_SESSION_canary="),
            "a session reached the child"
        );
        assert!(seen.contains("OP_SESSION_DELEGATION_ENABLED=true"));
    }

    /// FMECA M6: `run_inherited_clean` (the path `opv run` and fly use) likewise.
    #[cfg(unix)]
    #[test]
    fn a_clean_inherited_cli_child_gets_no_session() {
        let seen = inherited_env_of(|r, a, e| {
            r.run_inherited_clean("sh", a, e, &["SOME_DECLARED_KEY".to_string()])
        });
        assert!(
            !seen.contains("S8CANARYsession"),
            "a session reached the child"
        );
    }

    /// `opv login -- <cmd>` hands its session on: that is the command's purpose.
    #[cfg(unix)]
    #[test]
    fn the_login_child_keeps_its_session() {
        let seen = inherited_env_of(|r, a, e| r.run_signed_in_child("sh", a, e));
        assert!(seen.contains("OP_SESSION_canary=S8CANARYsession"));
    }

    #[test]
    fn read_with_an_expired_session_is_not_retried() {
        let r = FakeRunner::default();
        (0..3).for_each(|_| {
            r.push_with_stderr(
                Output::failure(1),
                "[ERROR] 2026/10/11 05:49:13 session expired, sign in to create a new session\n",
            )
        });
        let _ = read_fake(&r);
        assert_eq!(r.calls.borrow().len(), 1);
    }

    #[test]
    fn read_of_missing_op_item_is_not_retried() {
        let r = FakeRunner::default();
        (0..3).for_each(|_| {
            r.push_with_stderr(
                Output::failure(1),
                "[ERROR] \"i\" isn't an item in the \"v\" vault.\n",
            )
        });
        let _ = read_fake(&r);
        assert_eq!(r.calls.borrow().len(), 1);
    }

    /// S2: a missing Kubernetes object (`NotFound`) is refused at once, never retried.
    #[test]
    fn read_of_missing_kubernetes_object_is_not_retried() {
        let r = FakeRunner::default();
        (0..3).for_each(|_| {
            r.push_with_stderr(
                Output::failure(1),
                "Error from server (NotFound): deployments.apps \"api\" not found\n",
            )
        });
        let _ = r.read(&Call::new("kubectl", &["get", "deployment", "api"]), &[]);
        assert_eq!(r.calls.borrow().len(), 1);
    }

    /// S2: a missing Azure secret or resource is refused at once, never retried.
    #[test]
    fn read_of_missing_azure_resource_is_not_retried() {
        let r = FakeRunner::default();
        (0..3).for_each(|_| {
            r.push_with_stderr(Output::failure(1), "ERROR: (ResourceNotFound) gone\n")
        });
        let _ = r.read(&Call::new("az", &["containerapp", "show"]), &[]);
        assert_eq!(r.calls.borrow().len(), 1);
    }

    /// S2: unrecognised failure text keeps its retries (matching op's text is brittle).
    #[test]
    fn read_with_unrecognised_failure_text_is_retried() {
        let r = FakeRunner::default();
        (0..3).for_each(|_| r.push_with_stderr(Output::failure(1), "connection reset\n"));
        let _ = read_fake(&r);
        assert_eq!(r.calls.borrow().len(), 3);
    }

    /// S2: one program's not-found phrase does not stop another program's retries.
    #[test]
    fn not_found_phrase_of_another_program_is_retried() {
        let r = FakeRunner::default();
        (0..3).for_each(|_| r.push_with_stderr(Output::failure(1), "(NotFound)\n"));
        let _ = read_fake(&r);
        assert_eq!(r.calls.borrow().len(), 3);
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
                ROLLOUT_WRITE_TIMEOUT,
                DEFAULT_RUN_TIMEOUT
            ],
            [15, 60, 120, 900, 1800].map(Duration::from_secs)
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
            Some(Attempt::OverCap(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn signal_without_cap_is_killed() {
        use std::os::unix::process::ExitStatusExt;
        assert!(matches!(
            exited_early(ExitStatus::from_raw(9), false),
            Some(Attempt::Killed(9))
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
            limit: None,
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

    // Both tests below only ever set the flag (tests run in parallel).
    #[cfg(unix)]
    #[test]
    fn ctrl_c_is_left_to_a_child_that_owns_the_terminal() {
        signals::set_child_owns_terminal(true);
        assert!(signals::ignored(libc::SIGINT));
    }

    #[cfg(unix)]
    #[test]
    fn a_termination_stops_opv_even_while_a_child_owns_the_terminal() {
        signals::set_child_owns_terminal(true);
        assert!(!signals::ignored(libc::SIGTERM));
    }

    #[test]
    fn call_debug_hides_stdin_and_env_values() {
        let call = Call {
            program: "op",
            args: &["item", "edit"],
            stdin: Some(b"sk-live-123"),
            env: &[("OP_TOKEN", "tok-secret")],
            limit: None,
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
            limit: None,
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
            limit: None,
        };
        let o = ProcessRunner::default().read(&call, &[]).unwrap();
        assert!(matches!(o, Outcome::Done(o) if o.stdout.as_slice() == b"v1\n"));
    }

    /// A child that writes to stderr and fails: status propagated, stderr kept out of stdout.
    #[cfg(unix)]
    #[test]
    fn process_runner_reports_status_and_keeps_stderr_out_of_stdout() {
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

    // ------------------------------------------------------------ stderr (NR-31)

    fn failing_read_with_stderr(stderr: &str) -> FakeRunner {
        let r = FakeRunner::default();
        (0..READ_ATTEMPTS).for_each(|_| r.push_with_stderr(Output::failure(1), stderr));
        let _ = read_fake(&r);
        r
    }

    fn excerpt_lines() -> Vec<String> {
        take_failure_excerpt().map(|e| e.lines).unwrap_or_default()
    }

    #[test]
    fn failed_read_leaves_its_stderr_excerpt() {
        failing_read_with_stderr("ERROR: item not found\n");
        assert_eq!(excerpt_lines(), ["ERROR: item not found"]);
    }

    #[test]
    fn failed_read_excerpt_masks_a_registered_value() {
        crate::scrub::register("RnrMarker-91kq");
        failing_read_with_stderr("bad value RnrMarker-91kq\n");
        assert_eq!(excerpt_lines(), ["bad value ********"]);
    }

    #[test]
    fn read_succeeding_after_a_failure_leaves_no_excerpt() {
        let r = FakeRunner::default();
        r.push_with_stderr(Output::failure(1), "transient\n");
        r.push_with_stderr(Output::success("ok"), "");
        let _ = read_fake(&r);
        assert_eq!(take_failure_excerpt(), None);
    }

    #[test]
    fn failed_write_leaves_its_stderr_excerpt() {
        let r = FakeRunner::default();
        r.push_with_stderr(Output::failure(2), "Error: app not found\n");
        let _ = r.write(&Call::new("flyctl", &["secrets", "import"]));
        assert_eq!(
            take_failure_excerpt().map(|e| e.program),
            Some("flyctl".into())
        );
    }

    #[test]
    fn failed_probe_leaves_its_stderr_excerpt() {
        let r = FakeRunner::default();
        r.push_with_stderr(Output::failure(1), "[ERROR] not signed in\n");
        let _ = r.probe(&Call::new("op", &["whoami"]), PROBE_TIMEOUT);
        assert_eq!(excerpt_lines(), ["[ERROR] not signed in"]);
    }

    /// A diagnosis probe explains the failed read, so the read's excerpt stays.
    #[test]
    fn diagnosis_probe_keeps_the_failed_calls_excerpt() {
        let r = failing_read_with_stderr("denied\n");
        r.push_with_stderr(Output::success("{}"), "");
        diagnosing(|| r.probe(&Call::new("op", &["whoami"]), PROBE_TIMEOUT)).unwrap();
        assert_eq!(excerpt_lines(), ["denied"]);
    }

    #[test]
    fn failed_diagnosis_probe_does_not_replace_the_failed_calls_excerpt() {
        let r = failing_read_with_stderr("denied\n");
        r.push_with_stderr(Output::failure(1), "not signed in\n");
        diagnosing(|| r.probe(&Call::new("op", &["whoami"]), PROBE_TIMEOUT)).unwrap();
        assert_eq!(excerpt_lines(), ["denied"]);
    }

    #[test]
    fn probe_outside_a_diagnosis_drops_an_earlier_excerpt() {
        let r = failing_read_with_stderr("denied\n");
        r.push_with_stderr(Output::success("{}"), "");
        r.probe(&Call::new("az", &["version"]), PROBE_TIMEOUT)
            .unwrap();
        assert_eq!(take_failure_excerpt(), None);
    }

    #[test]
    fn excerpt_is_taken_once() {
        failing_read_with_stderr("x\n");
        let _ = take_failure_excerpt();
        assert_eq!(take_failure_excerpt(), None);
    }

    fn verbose_notes(stdout: &str, stderr: &str) -> Vec<String> {
        let r = FakeRunner::default();
        r.verbose.set(true);
        r.push_with_stderr(Output::success(stdout), stderr);
        let _ = r.read(&Call::new("az", &["keyvault", "secret", "list"]), &[]);
        r.notes.take()
    }

    #[test]
    fn verbose_shows_call_line_stderr_and_stdout_shape() {
        assert_eq!(
            verbose_notes(r#"{"b":"VbsContent-1","a":2}"#, "WARNING: preview\n"),
            [
                "az keyvault secret list (0.00 s): exit 0",
                "    stderr: WARNING: preview",
                "    stdout: 26 bytes, JSON object with keys: a, b",
            ]
        );
    }

    #[test]
    fn verbose_never_shows_stdout_content() {
        let notes = verbose_notes(r#"{"k":"VbsContent-2"}"#, "").join("\n");
        assert!(!notes.contains("VbsContent-2"), "{notes}");
    }

    #[test]
    fn verbose_stderr_is_scrubbed() {
        let notes = verbose_notes("", "Authorization: Bearer abc.def\n");
        assert_eq!(notes[1], "    stderr: Authorization: Bearer ********");
    }

    /// A 60-line reply whose first line is op's error and whose every line names `value`.
    fn long_reply(value: &str) -> String {
        let mut s = format!("[ERROR] 2026/10/16 10:00:00 refused {value}\n");
        for i in 1..60 {
            s.push_str(&format!("detail {i}: {value}\n"));
        }
        s
    }

    #[test]
    fn verbose_shows_every_line_of_a_long_reply() {
        let notes = verbose_notes("", &long_reply("plain"));
        assert_eq!(
            notes
                .iter()
                .filter(|n| n.starts_with("    stderr: "))
                .count(),
            60
        );
    }

    #[test]
    fn verbose_masks_a_value_in_every_line_of_a_long_reply() {
        crate::scrub::register("vbsLongValue-Q9");
        let notes = verbose_notes("", &long_reply("vbsLongValue-Q9")).join("\n");
        assert!(!notes.contains("vbsLongValue"), "{notes}");
    }

    /// I1: a value holding CR, BEL or ESC is masked in `--verbose` stderr too.
    fn verbose_with_value(value: &str) -> String {
        crate::scrub::register(value);
        verbose_notes("", &format!("error: bad value {value}\n")).join("\n")
    }

    #[test]
    fn verbose_masks_a_crlf_value() {
        let notes = verbose_with_value("Line1-vbsCrlfAAAA\r\nLine2-vbsCrlfBBBB");
        assert!(!notes.contains("vbsCrlf"), "{notes}");
    }

    #[test]
    fn verbose_masks_a_value_with_bel() {
        let notes = verbose_with_value("vbsBel-AAAA\x07vbsBel-BBBB");
        assert!(!notes.contains("vbsBel"), "{notes}");
    }

    #[test]
    fn verbose_masks_a_value_with_esc() {
        let notes = verbose_with_value("vbsEsc-AAAA\x1b[31mvbsEsc-BBBB");
        assert!(!notes.contains("vbsEsc"), "{notes}");
    }

    /// M3: every successful `op item get` registers its values, without `--verbose` and
    /// with op's global flags before the subcommand.
    #[test]
    fn item_read_registers_its_values_without_verbose() {
        let r = FakeRunner::new([Output::success(
            r#"{"fields":[{"label":"K","value":"m3ItemValueQ8z"}]}"#,
        )]);
        let _ = r.read(
            &Call::new(
                "op",
                &["--account", "acme", "item", "get", "i", "--vault", "v"],
            ),
            &[],
        );
        assert_eq!(crate::scrub::scrub("x m3ItemValueQ8z"), "x ********");
    }

    #[test]
    fn stdout_shape_of_an_array_is_its_length() {
        assert_eq!(stdout_shape(b"[1,2,3]"), "7 bytes, JSON array of 3");
    }

    #[test]
    fn stdout_shape_of_text_is_its_size() {
        assert_eq!(stdout_shape(b"secret text"), "11 bytes");
    }

    #[test]
    fn stderr_buffer_keeps_the_last_64_kib() {
        let mut s = Stderr::default();
        for i in 0..40u8 {
            s.push(&[i; 4096]);
        }
        let t = s.take();
        assert_eq!(
            (t.bytes.len(), t.truncated, t.bytes[t.bytes.len() - 1]),
            (STDERR_CAP, true, 39)
        );
    }

    #[test]
    fn stderr_debug_shows_length_only() {
        let mut s = Stderr::default();
        s.push(b"DbgMarker");
        assert_eq!(format!("{s:?}"), "Stderr { len: 9, truncated: false }");
    }

    /// A real child writes a registered marker to stderr and fails: the excerpt holds the
    /// line with the marker masked.
    #[cfg(unix)]
    #[test]
    fn process_runner_failure_excerpt_masks_a_registered_value() {
        crate::scrub::register("PrcMarker-77xq");
        let _ = ProcessRunner::default().read(
            &Call::new("sh", &["-c", "echo 'warn PrcMarker-77xq' >&2; exit 3"]),
            &[3],
        );
        assert_eq!(excerpt_lines(), ["warn ********"]);
    }

    /// More stderr than the cap neither blocks the child nor loses the last line.
    #[cfg(unix)]
    #[test]
    fn process_runner_keeps_the_tail_of_a_large_stderr() {
        let _ = ProcessRunner::default().read(
            &Call::new(
                "sh",
                &["-c", "i=0; while [ $i -lt 3000 ]; do echo 'noise line of some length here' >&2; i=$((i+1)); done; echo last >&2; exit 3"],
            ),
            &[3],
        );
        assert_eq!(excerpt_lines().last().map(String::as_str), Some("last"));
    }

    #[cfg(unix)]
    #[test]
    fn process_runner_successful_read_leaves_no_excerpt() {
        let _ = ProcessRunner::default().read(&Call::new("sh", &["-c", "echo note >&2"]), &[]);
        assert_eq!(take_failure_excerpt(), None);
    }

    /// Interactive calls are unchanged: the terminal passes through and nothing is
    /// captured for an excerpt.
    #[cfg(unix)]
    #[test]
    fn run_inherited_captures_no_stderr() {
        let code = ProcessRunner::default()
            .run_inherited("sh", &["-c", "exit 3"], &[])
            .unwrap();
        assert_eq!((code, take_failure_excerpt()), (3, None));
    }
}

#[cfg(test)]
mod account_arg_tests {
    use super::with_account;

    /// Found live: an account given only as `OP_ACCOUNT` never reached a Windows `op.exe`
    /// started from WSL, which then asked the 1Password app about the default account.
    #[test]
    fn an_op_call_with_an_account_in_its_env_carries_it_in_argv() {
        let args = with_account("op", &["item", "get", "i"], &[("OP_ACCOUNT", "AID")]);
        assert_eq!(args, ["item", "get", "i", "--account", "AID"]);
    }

    #[test]
    fn the_account_goes_before_the_child_command_of_op_run() {
        let args = with_account(
            "op",
            &["run", "--", "npm", "start"],
            &[("OP_ACCOUNT", "AID")],
        );
        assert_eq!(args, ["run", "--account", "AID", "--", "npm", "start"]);
    }

    /// Found live: `op --version --account X` fails, so doctor reported op as broken.
    #[test]
    fn op_version_carries_no_account() {
        assert_eq!(
            with_account("op", &["--version"], &[("OP_ACCOUNT", "AID")]),
            ["--version"]
        );
    }

    #[test]
    fn an_explicit_account_flag_is_kept_as_it_is() {
        let given = ["item", "list", "--account", "X"];
        assert_eq!(with_account("op", &given, &[("OP_ACCOUNT", "AID")]), given);
    }
}

#[cfg(test)]
mod signed_out_account_tests {
    use super::*;

    #[test]
    fn a_signed_out_call_names_its_own_account() {
        let call = Call::new("op", &["item", "get", "i", "--account", "ACCT"]);
        assert_eq!(call_account(&call).as_deref(), Some("ACCT"));
    }

    #[test]
    fn a_signed_out_call_names_its_op_account_variable() {
        let mut call = Call::new("op", &["item", "get", "i"]);
        let env = [("OP_ACCOUNT", "ENVACCT")];
        call.env = &env;
        assert_eq!(call_account(&call).as_deref(), Some("ENVACCT"));
    }
}
