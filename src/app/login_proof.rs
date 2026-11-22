//! Proof that an `OP_SESSION*` session is this terminal's own `opv login` sign-in (#353,
//! design `docs/design/own-login-proof.md`).
//!
//! On WSL with the Linux `op`, and on Linux without the 1Password app, every session is an
//! `OP_SESSION_<id>` variable. Production writes refuse such a variable (D6), because one
//! exported or handed in says nothing about who signed in. `opv login [-- <command>]`, when
//! it prompted the person itself, records a proof that it created the session:
//!
//! - a private directory `opv-login-<pid>-<random>` (0700) under the validated,
//!   RAM-backed `$XDG_RUNTIME_DIR`, holding `proof` (0600, created new, never followed);
//! - the record names the login's process ID, its start time, its executable, its
//!   controlling terminal, the SHA-256 of a 32-byte random nonce and the names of the
//!   session variables; nothing in it is derived from a session value (ADR-0001 R1: no
//!   digest of a secret in a file opv writes);
//! - the login's child, and only it, gets `OPV_LOGIN_PROOF=<pid>-<random>.<nonce>.<tag>`,
//!   where the tag is a SHA-256 keyed by the nonce over each session variable's name and
//!   value: it lives only in the environment that already holds the session itself;
//! - the directory is removed when the child exits (and on a signal); a killed login's is
//!   swept by the next login.
//!
//! [`verify`] accepts the environment's sessions only when every check passes, in this
//! order: no assistant marker, stdin and stdout a terminal, a well-formed
//! `OPV_LOGIN_PROOF`, a valid runtime directory, a private record, the nonce, the login
//! still running (process ID, start time and executable), the login an ancestor of this
//! process, the same controlling terminal, and the `OP_SESSION*` variables set here exactly
//! the ones the login created, with the tag over their values. `eval "$(opv login --shell)"` writes no proof: its session
//! outlives the login and is inherited by everything the shell starts later.
//!
//! Like agent mode, this is not a boundary against code running as the same user (it can
//! read `/proc/<pid>/environ` and write the record); it proves the session came from a
//! sign-in the person typed at this terminal, not from an exported or inherited variable.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::cause::SessionProof;
use crate::domain::SecretValue;

/// The variable the login's child gets: `<pid>-<random>.<nonce>`.
pub const PROOF_VAR: &str = "OPV_LOGIN_PROOF";

/// The proof directory's name prefix in `$XDG_RUNTIME_DIR` (swept when its login is gone).
pub const DIR_PREFIX: &str = "opv-login-";

/// The record's file name in the proof directory.
const RECORD: &str = "proof";

/// The record format.
const VERSION: u32 = 1;

/// A record larger than this was not written by opv.
const MAX_RECORD: u64 = 16 * 1024;

/// The longest ancestor chain walked (a loop or a deep tree ends the walk).
const MAX_HOPS: usize = 256;

/// The domain separator of the session digest.
const DOMAIN: &[u8] = b"opv-login-proof/1\0";

/// What `/proc/<pid>/stat` says about a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcStat {
    pub ppid: u32,
    /// Start time in clock ticks since boot (with the process ID, it names one process).
    pub start: u64,
    /// The controlling terminal's device number (0: none).
    pub tty: u64,
}

/// What the proof reads about processes: the testable seam.
pub trait Procs {
    /// This process's ID.
    fn this_pid(&self) -> u32;
    /// `pid`'s status, `None` when it does not exist.
    fn stat(&self, pid: u32) -> Option<ProcStat>;
    /// `pid`'s executable, `None` when unreadable.
    fn exe(&self, pid: u32) -> Option<PathBuf>;
    /// `pid`'s command name (`/proc/<pid>/comm`, at most 15 bytes), `None` when it does not
    /// exist. Readable even when `exe` is not: opv makes itself non-dumpable, and the kernel
    /// then hides its `exe` link from every other process of the same user.
    fn comm(&self, pid: u32) -> Option<String>;
}

/// The running system's processes, from `/proc` (Linux and WSL).
#[derive(Debug, Clone, Copy, Default)]
pub struct LinuxProcs;

impl Procs for LinuxProcs {
    fn this_pid(&self) -> u32 {
        std::process::id()
    }
    fn stat(&self, pid: u32) -> Option<ProcStat> {
        parse_stat(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
    }
    fn exe(&self, pid: u32) -> Option<PathBuf> {
        std::fs::read_link(format!("/proc/{pid}/exe")).ok()
    }
    fn comm(&self, pid: u32) -> Option<String> {
        let c = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
        Some(c.trim_end_matches('\n').to_string())
    }
}

/// `/proc/<pid>/stat`: the fields after the command name, which is in parentheses and may
/// itself hold spaces and parentheses (so the last `)` ends it).
pub fn parse_stat(line: &str) -> Option<ProcStat> {
    let rest = &line[line.rfind(')')? + 1..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    // state(0) ppid(1) pgrp(2) session(3) tty_nr(4) ... starttime(19)
    Some(ProcStat {
        ppid: f.get(1)?.parse().ok()?,
        tty: f.get(4)?.parse::<i64>().ok()? as u64,
        start: f.get(19)?.parse().ok()?,
    })
}

/// The record: names, numbers and digests only, never a value.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Record {
    v: u32,
    pid: u32,
    start: u64,
    tty: u64,
    exe: String,
    nonce_sha256: String,
    /// The session variables' names (never a value or a digest of one).
    sessions: BTreeSet<String>,
}

/// A proof issued for one login's child. Dropping it removes the record.
pub struct Issued {
    dir: crate::ramdir::PrivateDir,
    value: Zeroizing<String>,
}

impl Issued {
    /// `OPV_LOGIN_PROOF`'s value for the child.
    pub fn value(&self) -> &str {
        &self.value
    }
    /// The proof directory (tests).
    pub fn dir(&self) -> &Path {
        self.dir.path()
    }
}

/// Executable paths compare without the kernel's ` (deleted)` (an upgrade mid-login).
/// The kernel's command name for an executable path: its file name, cut to 15 bytes.
fn comm_of(exe: &str) -> String {
    let name = Path::new(exe)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    name.as_bytes()[..name.len().min(15)]
        .iter()
        .map(|&b| b as char)
        .collect()
}

fn exe_name(p: &Path) -> String {
    let s = p.to_string_lossy();
    s.strip_suffix(" (deleted)").unwrap_or(&s).to_string()
}

/// The tag over `sessions` (name and value each), keyed by the nonce, in name order.
fn tag<'a>(nonce: &[u8], sessions: impl Iterator<Item = (&'a str, &'a str)>) -> String {
    let mut sorted: Vec<(&str, &str)> = sessions.collect();
    sorted.sort_unstable();
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(nonce);
    for (name, value) in sorted {
        h.update([0]);
        h.update(name.as_bytes());
        h.update([0]);
        h.update(value.as_bytes());
    }
    hex::encode(h.finalize())
}

/// Record a proof for `sessions` (the variables this login's own sign-in produced) in
/// `runtime`. Refused, writing nothing, when there is no fresh session, no controlling
/// terminal, or the directory cannot be made private.
pub fn issue(
    sessions: &[(String, SecretValue)],
    runtime: Result<&Path, SessionProof>,
    procs: &dyn Procs,
) -> Result<Issued, SessionProof> {
    if sessions.is_empty() {
        return Err(SessionProof::NoProof);
    }
    let runtime = runtime?;
    let pid = procs.this_pid();
    let me = procs.stat(pid).ok_or(SessionProof::Unsupported)?;
    if me.tty == 0 {
        return Err(SessionProof::NoTerminal);
    }
    let exe = procs.exe(pid).ok_or(SessionProof::Unsupported)?;
    crate::ramdir::sweep(runtime, DIR_PREFIX);
    let dir = crate::ramdir::PrivateDir::create(runtime, DIR_PREFIX)
        .map_err(|_| SessionProof::RuntimeDir)?;
    let id = dir
        .path()
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_prefix(DIR_PREFIX))
        .ok_or(SessionProof::RuntimeDir)?
        .to_string();
    let mut nonce = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut nonce[..]).map_err(|_| SessionProof::Unsupported)?;
    let record = Record {
        v: VERSION,
        pid,
        start: me.start,
        tty: me.tty,
        exe: exe_name(&exe),
        nonce_sha256: hex::encode(Sha256::digest(&nonce[..])),
        sessions: sessions.iter().map(|(name, _)| name.clone()).collect(),
    };
    let body = serde_json::to_vec(&record).map_err(|_| SessionProof::Unsupported)?;
    write_new(&dir.path().join(RECORD), &body).map_err(|_| SessionProof::RuntimeDir)?;
    let tag = tag(
        &nonce[..],
        sessions.iter().map(|(n, v)| (n.as_str(), v.expose())),
    );
    let value = Zeroizing::new(format!("{id}.{}.{tag}", hex::encode(&nonce[..])));
    Ok(Issued { dir, value })
}

/// Create `path` new (never an existing file or a link), mode 0600, and write `body`.
fn write_new(path: &Path, body: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut f = opts.open(path)?;
    f.write_all(body)?;
    f.sync_all()
}

/// What [`verify`] judges: the environment of the process asking.
pub struct Claim<'a> {
    /// `OPV_LOGIN_PROOF`, if set.
    pub proof: Option<&'a str>,
    /// Every `OP_SESSION*` set and non-empty here, with its value (hashed, never kept).
    pub sessions: &'a [(String, Zeroizing<String>)],
    /// Stdin and stdout are a terminal.
    pub interactive: bool,
    /// An assistant's marker is set.
    pub agent: bool,
}

/// Whether `claim`'s sessions are this terminal's own `opv login` sign-in; the first check
/// that fails otherwise (module docs for the order).
pub fn verify(
    claim: &Claim<'_>,
    runtime: Result<&Path, SessionProof>,
    procs: &dyn Procs,
) -> Result<(), SessionProof> {
    if claim.agent {
        return Err(SessionProof::Agent);
    }
    if !claim.interactive {
        return Err(SessionProof::NoTerminal);
    }
    let proof = claim.proof.ok_or(SessionProof::NoProof)?;
    let (id, nonce, want) = parse_proof(proof).ok_or(SessionProof::Malformed)?;
    let runtime = runtime?;
    let dir = runtime.join(format!("{DIR_PREFIX}{id}"));
    let record = read_record(&dir)?;
    let nonce_ok: bool = hex::encode(Sha256::digest(&nonce[..]))
        .as_bytes()
        .ct_eq(record.nonce_sha256.as_bytes())
        .into();
    if record.v != VERSION || !nonce_ok {
        return Err(SessionProof::Forged);
    }
    let login = procs.stat(record.pid).ok_or(SessionProof::Stale)?;
    // The login is non-dumpable (opv clears PR_SET_DUMPABLE), so its `exe` link is hidden
    // from this process; then the command name stands in. The process ID with its start time
    // already names exactly one process, so a reused ID is still refused.
    let same_program = match procs.exe(record.pid) {
        Some(p) => exe_name(&p) == record.exe,
        None => procs
            .comm(record.pid)
            .is_some_and(|c| c == comm_of(&record.exe)),
    };
    if login.start != record.start || !same_program {
        return Err(SessionProof::Stale);
    }
    if !is_ancestor(record.pid, record.start, procs) {
        return Err(SessionProof::NotAncestor);
    }
    let me = procs
        .stat(procs.this_pid())
        .ok_or(SessionProof::Unsupported)?;
    if me.tty == 0 || me.tty != record.tty {
        return Err(SessionProof::OtherTerminal);
    }
    let names: BTreeSet<String> = claim.sessions.iter().map(|(n, _)| n.clone()).collect();
    if names.is_empty() || names != record.sessions {
        return Err(SessionProof::WrongSession);
    }
    let got = tag(
        &nonce[..],
        claim.sessions.iter().map(|(n, v)| (n.as_str(), v.as_str())),
    );
    if !bool::from(got.as_bytes().ct_eq(want.as_bytes())) {
        return Err(SessionProof::WrongSession);
    }
    Ok(())
}

/// `<pid>-<random>.<64 hex>.<64 hex>` → (`<pid>-<random>`, the nonce, the tag). The ID is
/// digits, one `-` and lowercase hex only, so it can never name another path.
fn parse_proof(v: &str) -> Option<(String, Zeroizing<Vec<u8>>, String)> {
    let mut parts = v.trim().split('.');
    let (id, nonce, tag) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || tag.len() != 64 || !tag.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let (pid, random) = id.split_once('-')?;
    let ok_pid = !pid.is_empty() && pid.len() <= 10 && pid.bytes().all(|b| b.is_ascii_digit());
    let ok_random = !random.is_empty()
        && random.len() <= 32
        && random
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !ok_pid || !ok_random || nonce.len() != 64 {
        return None;
    }
    let nonce = Zeroizing::new(hex::decode(nonce).ok()?);
    Some((id.to_string(), nonce, tag.to_ascii_lowercase()))
}

/// The record in `dir`, when `dir` is this user's private directory and `proof` a private
/// regular file of this user (never followed through a link).
fn read_record(dir: &Path) -> Result<Record, SessionProof> {
    match std::fs::symlink_metadata(dir) {
        Err(_) => return Err(SessionProof::Missing),
        Ok(_) if !crate::ramdir::private_dir(dir) => return Err(SessionProof::UnsafeRecord),
        Ok(_) => {}
    }
    let path = dir.join(RECORD);
    let meta = std::fs::symlink_metadata(&path).map_err(|_| SessionProof::Missing)?;
    if !meta.file_type().is_file() || meta.len() > MAX_RECORD || !private_file(&meta) {
        return Err(SessionProof::UnsafeRecord);
    }
    let body = std::fs::read(&path).map_err(|_| SessionProof::Missing)?;
    serde_json::from_slice(&body).map_err(|_| SessionProof::Malformed)
}

#[cfg(unix)]
fn private_file(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    meta.uid() == rustix::process::geteuid().as_raw() && meta.mode() & 0o077 == 0
}

#[cfg(not(unix))]
fn private_file(_meta: &std::fs::Metadata) -> bool {
    false
}

/// Whether the process `pid` that started at `start` is an ancestor of this process.
fn is_ancestor(pid: u32, start: u64, procs: &dyn Procs) -> bool {
    let mut at = procs.this_pid();
    for _ in 0..MAX_HOPS {
        let Some(s) = procs.stat(at) else {
            return false;
        };
        if s.ppid == 0 || s.ppid == at {
            return false;
        }
        at = s.ppid;
        if at == pid {
            return procs.stat(at).is_some_and(|p| p.start == start);
        }
    }
    false
}

/// The runtime directory a proof lives in (`$XDG_RUNTIME_DIR`, validated as local delivery
/// validates it), or [`SessionProof::RuntimeDir`]; [`SessionProof::Unsupported`] off Linux.
pub fn runtime_dir() -> Result<PathBuf, SessionProof> {
    if !cfg!(target_os = "linux") {
        return Err(SessionProof::Unsupported);
    }
    super::local_delivery::runtime_dir_support().map_err(|_| SessionProof::RuntimeDir)
}

/// [`issue`] for this process (the login).
pub fn issue_here(sessions: &[(String, SecretValue)]) -> Result<Issued, SessionProof> {
    if !cfg!(target_os = "linux") {
        return Err(SessionProof::Unsupported);
    }
    let runtime = runtime_dir();
    issue(sessions, runtime.as_deref().map_err(|e| *e), &LinuxProcs)
}

/// [`verify`] for this process, judged through `env` for the terminal and the markers.
pub fn verify_here(env: &dyn crate::host::HostEnv) -> Result<(), SessionProof> {
    if !cfg!(target_os = "linux") {
        return Err(SessionProof::Unsupported);
    }
    let sessions: Vec<(String, Zeroizing<String>)> = super::account::session_var_names()
        .into_iter()
        .filter_map(|n| {
            let v = Zeroizing::new(std::env::var(&n).ok()?);
            (!v.is_empty()).then_some((n, v))
        })
        .collect();
    let proof = std::env::var(PROOF_VAR).ok().map(Zeroizing::new);
    let claim = Claim {
        proof: proof.as_deref().map(String::as_str),
        sessions: &sessions,
        interactive: env.interactive(),
        agent: env.agent_mode().is_some(),
    };
    let runtime = runtime_dir();
    verify(&claim, runtime.as_deref().map_err(|e| *e), &LinuxProcs)
}

#[cfg(all(test, unix))]
#[path = "login_proof_tests.rs"]
mod tests;
