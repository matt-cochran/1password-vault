//! Remote development delivery (#139): `opv run <env> --product <p> --remote <profile>`
//! sends the product's selected keys to a reviewed, pinned remote host over SSH and runs the
//! pinned command there, with no plaintext environment file on either host.
//!
//! ```text
//! opv run dev --product journeeze --role serve --remote builder        (a person's terminal)
//!   └─ op run -- opv remote-send --plan <names, paths, pinned profile>  (values only in env)
//!        └─ ssh -F none … -o StrictHostKeyChecking=yes … host <opv> remote-receive
//!             └─ (remote) opv remote-receive: payload from stdin → RAM directory / env
//!                  └─ the pinned command in the pinned working directory
//! ```
//!
//! - `op run` stays the only thing that resolves references; `remote-send` reads the values
//!   from its own environment and writes them only into SSH's stdin, framed as one payload
//!   ([`encode`]). Arguments, SSH's environment and every message carry names only.
//! - SSH is fully pinned: `-F none` (no user or system configuration, so no `ProxyCommand`,
//!   `LocalCommand`, `SendEnv` or forwarding from there), the profile's host key as the only
//!   known host, strict checking, batch mode, no agent/X11/port forwarding, no multiplexing.
//!   Only `PATH`, `HOME`, the user and locale names and `SSH_AUTH_SOCK` reach SSH's
//!   environment: never an `OP_*` credential, never a key.
//! - The remote command line is fixed (`<opv> remote-receive`, a validated absolute path),
//!   so the remote shell sees no value and nothing from the run's arguments.
//! - The receiver reads the whole payload and checks it ([`decode`]) before it writes or
//!   starts anything: a short, malformed or oversized payload starts nothing and writes
//!   nothing (no partial delivery). File keys go to a fresh 0700 directory on the remote
//!   user's RAM-backed `$XDG_RUNTIME_DIR` (refused otherwise, never a disk fallback); the
//!   app's environment is the declared keys plus [`BASICS`](super::local_delivery::BASICS).
//! - Liveness: after the payload the sender writes a heartbeat byte every [`HEARTBEAT`].
//!   When stdin ends (Ctrl-C, the local opv or SSH ended, a dropped connection) or is
//!   silent for [`SILENCE_LIMIT`], or the receiver gets SIGHUP/SIGTERM/SIGINT, the receiver
//!   stops the app's whole process group (SIGTERM, then SIGKILL after [`STOP_GRACE`]) and
//!   removes the directory. A SIGKILL of the receiver itself leaves the directory in RAM
//!   until the next `remote-receive` sweeps it, or the remote session's runtime directory
//!   goes at logout or reboot.

use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::domain::model::Remote;
use crate::error::{Code, Error};

/// The payload's first line: the protocol and its version.
pub const MAGIC: &[u8] = b"OPV-REMOTE 1\n";
/// The payload's last line, after the last value: the commit marker.
pub const END: &[u8] = b"END\n";
/// How often the sender proves it is still there, after the payload.
pub const HEARTBEAT: Duration = Duration::from_secs(10);
/// How long the receiver tolerates silence on stdin before it stops the app.
pub const SILENCE_LIMIT: Duration = Duration::from_secs(45);
/// Time the app's process group gets after SIGTERM before SIGKILL.
pub const STOP_GRACE: Duration = Duration::from_secs(5);
/// The directory name prefix in the remote `$XDG_RUNTIME_DIR` (swept when its run is gone).
pub const DIR_PREFIX: &str = "opv-remote.";

const MAX_HEADER: usize = 64 * 1024;
const MAX_VALUE: usize = 1 << 20;
const MAX_KEYS: usize = 256;

/// What the receiver does: key names in payload order, file paths, the directory variable
/// and the pinned working directory and command. Never a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub keys: Vec<String>,
    pub files: Vec<(String, String)>,
    pub dir_env: Option<String>,
    pub workdir: String,
    pub command: Vec<String>,
}

/// What `remote-send` gets from `opv run --remote` (on its command line, as JSON): the
/// profile's pinned connection and the [`Header`]. Names, paths and a public key only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub profile: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub host_key: String,
    pub identity_file: Option<String>,
    pub opv: String,
    pub header: Header,
}

impl Plan {
    /// The plan for `profile` of a product: `selected` key names in order, `files` the
    /// `(key, path)` of each file key, `dir_env` the product's directory variable.
    pub fn new(
        profile: &str,
        remote: &Remote,
        keys: Vec<String>,
        files: Vec<(String, String)>,
        dir_env: Option<String>,
    ) -> Self {
        Plan {
            profile: profile.to_string(),
            host: remote.host.clone(),
            port: remote.port,
            user: remote.user.clone(),
            host_key: remote.host_key.clone(),
            identity_file: remote.identity_file.clone(),
            opv: remote.opv.clone(),
            header: Header {
                keys,
                files,
                dir_env,
                workdir: remote.workdir.clone(),
                command: remote.command.clone(),
            },
        }
    }
}

/// A checked payload: its header and each value, in header order.
pub type Decoded = (Header, Vec<Zeroizing<Vec<u8>>>);

/// Why a payload was refused. Names and sizes only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal(pub String);

fn refused(m: impl Into<String>) -> Refusal {
    Refusal(m.into())
}

/// The payload: [`MAGIC`], the header's length (u32, big-endian) and JSON, then per key in
/// header order its length and exact bytes, then [`END`].
pub fn encode(header: &Header, values: &[&[u8]]) -> Result<Zeroizing<Vec<u8>>, Refusal> {
    if values.len() != header.keys.len() {
        return Err(refused("one value per key"));
    }
    let head = serde_json::to_vec(header).map_err(|_| refused("the header cannot be rendered"))?;
    let mut out = Zeroizing::new(Vec::new());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(head.len() as u32).to_be_bytes());
    out.extend_from_slice(&head);
    for (key, v) in header.keys.iter().zip(values) {
        if v.len() > MAX_VALUE {
            return Err(refused(format!("{key} is larger than 1 MiB")));
        }
        out.extend_from_slice(&(v.len() as u32).to_be_bytes());
        out.extend_from_slice(v);
    }
    out.extend_from_slice(END);
    Ok(out)
}

fn read_len(r: &mut dyn Read, what: &str) -> Result<usize, Refusal> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)
        .map_err(|_| refused(format!("the payload ended before {what}")))?;
    Ok(u32::from_be_bytes(b) as usize)
}

/// Read and check a whole payload before anything is written or started: the magic, a
/// valid header ([`check_header`]), every value, and the commit marker. Any shortfall is a
/// [`Refusal`] and nothing is delivered.
pub fn decode(r: &mut dyn Read) -> Result<Decoded, Refusal> {
    let mut magic = [0u8; MAGIC.len()];
    r.read_exact(&mut magic)
        .map_err(|_| refused("the payload ended before its first line"))?;
    if magic != MAGIC {
        return Err(refused(
            "the payload is not opv remote protocol 1 (is the remote opv the same release?)",
        ));
    }
    let n = read_len(r, "the header")?;
    if n > MAX_HEADER {
        return Err(refused("the header is larger than 64 KiB"));
    }
    let mut head = vec![0u8; n];
    r.read_exact(&mut head)
        .map_err(|_| refused("the payload ended inside the header"))?;
    let header: Header =
        serde_json::from_slice(&head).map_err(|_| refused("the header is not valid"))?;
    check_header(&header)?;
    let mut values = Vec::with_capacity(header.keys.len());
    for key in &header.keys {
        let n = read_len(r, &format!("{key}'s value"))?;
        if n > MAX_VALUE {
            return Err(refused(format!("{key} is larger than 1 MiB")));
        }
        let mut v = Zeroizing::new(vec![0u8; n]);
        r.read_exact(&mut v)
            .map_err(|_| refused(format!("the payload ended inside {key}'s value")))?;
        values.push(v);
    }
    let mut end = [0u8; END.len()];
    r.read_exact(&mut end)
        .map_err(|_| refused("the payload ended before its commit marker"))?;
    if end != END {
        return Err(refused("the payload's commit marker is missing"));
    }
    Ok((header, values))
}

fn is_key_name(s: &str) -> bool {
    crate::config::is_env_name(s) && !s.starts_with("OP_")
}

fn is_file_path(p: &str) -> bool {
    let parts: Vec<&str> = p.split('/').collect();
    p.len() <= 128
        && parts.len() <= 4
        && parts.iter().all(|c| {
            c.split('-').all(|s| {
                !s.is_empty()
                    && s.chars()
                        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit())
            })
        })
}

/// A control character other than newline or tab (a multi-line `sh -c` script is fine).
pub(crate) fn has_control(s: &str) -> bool {
    s.chars().any(|c| c.is_control() && c != '\n' && c != '\t')
}

/// The receiver checks the header on its own, as the configuration did on the sending
/// side: the remote host does not trust the sender to have validated it.
pub fn check_header(h: &Header) -> Result<(), Refusal> {
    if h.keys.len() > MAX_KEYS {
        return Err(refused("more than 256 keys"));
    }
    let mut seen = BTreeSet::new();
    for k in &h.keys {
        if !is_key_name(k) || !seen.insert(k.as_str()) {
            return Err(refused("a key name is invalid, an OP_* name, or repeated"));
        }
    }
    let mut paths: Vec<&str> = Vec::new();
    for (k, p) in &h.files {
        if !seen.contains(k.as_str()) || !is_file_path(p) {
            return Err(refused(format!("{k}'s file path is not valid")));
        }
        if paths
            .iter()
            .any(|o| *o == p || p.starts_with(&format!("{o}/")) || o.starts_with(&format!("{p}/")))
        {
            return Err(refused(format!("{k}'s file path collides with another")));
        }
        paths.push(p);
    }
    match &h.dir_env {
        Some(v)
            if !is_key_name(v)
                || matches!(v.as_str(), "PATH" | "HOME")
                || seen.contains(v.as_str()) =>
        {
            return Err(refused("the directory variable is not valid"));
        }
        None if !h.files.is_empty() => {
            return Err(refused("file keys need a directory variable"));
        }
        _ => {}
    }
    if !crate::config::is_remote_path(&h.workdir) {
        return Err(refused(
            "the working directory is not a valid absolute path",
        ));
    }
    if h.command.is_empty() || h.command.iter().any(|a| has_control(a)) {
        return Err(refused(
            "the command is empty or has control characters other than newline and tab",
        ));
    }
    Ok(())
}

/// The `known_hosts` line for the pinned key, under an alias that names the profile, so no
/// other host entry can match and no port formatting is involved.
pub fn known_hosts_line(plan: &Plan) -> String {
    format!("{} {}\n", host_alias(plan), plan.host_key)
}

fn host_alias(plan: &Plan) -> String {
    format!("opv-remote-{}", plan.profile)
}

/// SSH's arguments: everything pinned, nothing from the user's SSH configuration, the
/// remote command fixed. `known_hosts` is the file holding [`known_hosts_line`].
pub fn ssh_args(plan: &Plan, known_hosts: &Path) -> Vec<String> {
    let mut a: Vec<String> = vec!["-F".into(), "none".into(), "-T".into()];
    let opts = [
        "BatchMode=yes".to_string(),
        "StrictHostKeyChecking=yes".to_string(),
        format!("UserKnownHostsFile={}", known_hosts.display()),
        "GlobalKnownHostsFile=/dev/null".to_string(),
        format!("HostKeyAlias={}", host_alias(plan)),
        "UpdateHostKeys=no".to_string(),
        "CheckHostIP=no".to_string(),
        "ForwardAgent=no".to_string(),
        "ForwardX11=no".to_string(),
        "ClearAllForwardings=yes".to_string(),
        "PermitLocalCommand=no".to_string(),
        "ControlMaster=no".to_string(),
        "ControlPath=none".to_string(),
        "ConnectTimeout=20".to_string(),
        "ServerAliveInterval=15".to_string(),
        "ServerAliveCountMax=3".to_string(),
    ];
    for o in opts {
        a.extend(["-o".to_string(), o]);
    }
    if let Some(id) = &plan.identity_file {
        a.extend([
            "-o".to_string(),
            "IdentitiesOnly=yes".to_string(),
            "-i".to_string(),
            expand_home(id),
        ]);
    }
    a.extend([
        "-p".to_string(),
        plan.port.to_string(),
        "-l".to_string(),
        plan.user.clone(),
        "--".to_string(),
        plan.host.clone(),
        format!("{} remote-receive", plan.opv),
    ]);
    a
}

fn expand_home(p: &str) -> String {
    match (p.strip_prefix("~/"), std::env::var("HOME")) {
        (Some(rest), Ok(home)) => format!("{home}/{rest}"),
        _ => p.to_string(),
    }
}

/// The only variables SSH gets: enough to find its binary, the user's home and the agent.
pub const SSH_ENV: &[&str] = &["PATH", "HOME", "USER", "LOGNAME", "LANG", "SSH_AUTH_SOCK"];

/// SSH's environment from `inherited`: [`SSH_ENV`] only, so neither an `OP_*` credential
/// nor a resolved key reaches SSH (or, through it, the remote host).
pub fn ssh_env(inherited: &[(String, String)]) -> Vec<(String, String)> {
    inherited
        .iter()
        .filter(|(k, _)| SSH_ENV.contains(&k.as_str()))
        .cloned()
        .collect()
}

/// `opv remote-send --plan <json>`: the step `op run` starts. Reads the selected values from
/// this process's environment, connects with the pinned SSH profile, sends the payload, then
/// a heartbeat until SSH ends. Returns SSH's exit code (the remote app's, or 255 when SSH
/// itself failed).
pub fn send(plan: &Plan) -> Result<i32, Error> {
    check_header(&plan.header).map_err(|r| {
        Error::Config(format!("remote profile {}: {}; nothing was sent", plan.profile, r.0).into())
    })?;
    let inherited: Zeroizing<Vec<(String, String)>> = Zeroizing::new(std::env::vars().collect());
    let mut values: Vec<&[u8]> = Vec::with_capacity(plan.header.keys.len());
    for key in &plan.header.keys {
        let Some((_, v)) = inherited.iter().find(|(k, _)| k == key) else {
            return Err(Error::Source(
                format!("{key} was not resolved by op run; nothing was sent").into(),
            ));
        };
        values.push(v.as_bytes());
    }
    let payload = encode(&plan.header, &values)
        .map_err(|r| Error::Config(format!("{}; nothing was sent", r.0).into()))?;
    drop(values);

    // The pinned host key, in a private directory removed when this step ends.
    let base =
        crate::app::local_delivery::runtime_dir_support().unwrap_or_else(|_| std::env::temp_dir());
    let dir = crate::ramdir::PrivateDir::create(&base, "opv-ssh.").map_err(|e| {
        Error::Dependency(
            format!("cannot create the pinned known_hosts file ({})", e.kind()).into(),
        )
    })?;
    let known = dir.path().join("known_hosts");
    std::fs::write(&known, known_hosts_line(plan)).map_err(|e| {
        Error::Dependency(format!("cannot write the pinned known_hosts file ({})", e.kind()).into())
    })?;

    // Ctrl-C reaches SSH too; this step outlives it to remove the directory above.
    let stop = Arc::new(AtomicBool::new(false));
    #[cfg(unix)]
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        let _ = signal_hook::flag::register(sig, Arc::clone(&stop));
    }

    let env = Zeroizing::new(ssh_env(&inherited));
    let mut child = std::process::Command::new("ssh")
        .args(ssh_args(plan, &known))
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => Error::Dependency(
                "ssh is not installed or not on PATH; remote delivery needs the OpenSSH client"
                    .into(),
            )
            .with_code(Code::DependencyMissing),
            k => Error::Dependency(format!("cannot start ssh ({k:?})").into()),
        })?;
    drop(inherited);
    let mut stdin = child.stdin.take().expect("piped");
    let sent = stdin.write_all(&payload).and_then(|()| stdin.flush());
    drop(payload);
    if sent.is_ok() {
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                std::thread::sleep(HEARTBEAT);
                if stdin.write_all(b"\n").and_then(|()| stdin.flush()).is_err() {
                    return;
                }
            }
        });
    } else {
        drop(stdin);
    }
    let status = child
        .wait()
        .map_err(|e| Error::Dependency(format!("cannot wait for ssh ({:?})", e.kind()).into()))?;
    drop(dir);
    let code = exit_code(status);
    if code == 255 {
        let _ = writeln!(
            io::stderr(),
            "opv: ssh to remote profile {} ({}@{}:{}) exited 255: the connection, \
             authentication or the pinned host key check failed (or the remote app itself \
             exited 255). Check with: opv run --remote {} --preview",
            plan.profile,
            plan.user,
            plan.host,
            plan.port,
            plan.profile
        );
    }
    Ok(code)
}

fn exit_code(status: std::process::ExitStatus) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return 128 + sig;
        }
    }
    status.code().unwrap_or(1)
}

/// Why the receiver stopped the app before it ended on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// stdin ended: the local side is gone.
    Disconnected,
    /// No heartbeat for [`SILENCE_LIMIT`].
    Silent,
    /// SIGHUP, SIGTERM or SIGINT reached the receiver.
    Signal,
}

impl Stop {
    fn reason(self) -> &'static str {
        match self {
            Stop::Disconnected => "the connection to the local opv ended",
            Stop::Silent => "the local opv sent no heartbeat for 45 seconds",
            Stop::Signal => "the receiver was signalled",
        }
    }
}

/// The app's environment on the remote host: [`BASICS`](super::local_delivery::BASICS) from
/// the receiver's own session (never an `OP_*` variable), each variable key's value, and the
/// directory variable. Always declared-only: nothing else of the remote session is passed.
pub fn remote_env(
    header: &Header,
    values: &[Zeroizing<Vec<u8>>],
    session: &[(String, String)],
    dir: Option<&str>,
) -> Result<Vec<(std::ffi::OsString, std::ffi::OsString)>, Refusal> {
    let mut out: Vec<(std::ffi::OsString, std::ffi::OsString)> = session
        .iter()
        .filter(|(k, _)| super::local_delivery::is_basic(k))
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
    for (key, v) in header.keys.iter().zip(values) {
        if header.files.iter().any(|(k, _)| k == key) {
            continue;
        }
        if v.contains(&0) {
            return Err(refused(format!(
                "{key} holds a NUL byte, which an environment variable cannot carry; deliver it \
                 as a file"
            )));
        }
        out.retain(|(k, _)| k != key.as_str());
        out.push((key.into(), os_from_bytes(v)));
    }
    if let (Some(var), Some(dir)) = (&header.dir_env, dir) {
        out.retain(|(k, _)| k != var.as_str());
        out.push((var.into(), dir.into()));
    }
    Ok(out)
}

#[cfg(unix)]
fn os_from_bytes(b: &[u8]) -> std::ffi::OsString {
    use std::os::unix::ffi::OsStringExt;
    std::ffi::OsString::from_vec(b.to_vec())
}

#[cfg(not(unix))]
fn os_from_bytes(b: &[u8]) -> std::ffi::OsString {
    String::from_utf8_lossy(b).into_owned().into()
}

fn receive_refused(r: Refusal) -> Error {
    Error::Policy(
        format!(
            "remote delivery refused: {}; nothing was written or started",
            r.0
        )
        .into(),
    )
    .with_code(Code::PolicyRefused)
}

/// `opv remote-receive` on the remote host: read the payload from `input` (SSH's stdin),
/// deliver it, run the pinned command, and stop it when the local side goes away.
#[cfg(unix)]
pub fn receive(mut input: Box<dyn Read + Send>) -> Result<i32, Error> {
    let (header, values) = decode(&mut *input).map_err(receive_refused)?;
    let session: Zeroizing<Vec<(String, String)>> = Zeroizing::new(std::env::vars().collect());
    let mut dir = None;
    if !header.files.is_empty() {
        use crate::ramdir::{PrivateDir, sweep};
        let runtime = super::local_delivery::runtime_dir_support()
            .map_err(|_| super::local_delivery::ram_dir_error())?;
        sweep(&runtime, DIR_PREFIX);
        let private = PrivateDir::create(&runtime, DIR_PREFIX)
            .map_err(|_| super::local_delivery::ram_dir_error())?;
        for (key, rel) in &header.files {
            let i = header.keys.iter().position(|k| k == key).expect("checked");
            super::local_delivery::write_file(private.path(), rel, &values[i]).map_err(|e| {
                Error::Policy(
                    format!(
                        "cannot write {key}'s file in the private directory ({})",
                        e.kind()
                    )
                    .into(),
                )
                .with_code(Code::PolicyRefused)
            })?;
        }
        dir = Some(private);
    }
    let env = remote_env(&header, &values, &session, dir.as_ref().map(|d| d.utf8()))
        .map_err(receive_refused)?;
    drop(values);

    let signalled = Arc::new(AtomicBool::new(false));
    for sig in [libc::SIGHUP, libc::SIGTERM, libc::SIGINT] {
        let _ = signal_hook::flag::register(sig, Arc::clone(&signalled));
    }
    use std::os::unix::process::CommandExt;
    let mut child = std::process::Command::new(&header.command[0])
        .args(&header.command[1..])
        .current_dir(&header.workdir)
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k, v)))
        .stdin(std::process::Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|e| {
            Error::Dependency(
                format!(
                    "cannot start {} in {} ({:?}); nothing else was started",
                    header.command[0],
                    header.workdir,
                    e.kind()
                )
                .into(),
            )
        });
    drop(env);
    let mut child = match child.as_mut() {
        Ok(_) => child.expect("checked"),
        Err(_) => {
            drop(dir);
            return Err(child.expect_err("checked"));
        }
    };

    // Heartbeats: any byte proves the sender is there; end of input means it is gone.
    let started = Instant::now();
    let last = Arc::new(AtomicU64::new(0));
    let ended = Arc::new(AtomicBool::new(false));
    {
        let (last, ended) = (Arc::clone(&last), Arc::clone(&ended));
        std::thread::spawn(move || {
            let mut buf = [0u8; 64];
            loop {
                match input.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => last.store(started.elapsed().as_millis() as u64, Ordering::SeqCst),
                }
            }
            ended.store(true, Ordering::SeqCst);
        });
    }
    let stop = loop {
        if let Some(status) = child.try_wait().map_err(|e| {
            Error::Dependency(format!("cannot wait for the app ({:?})", e.kind()).into())
        })? {
            drop(dir);
            return Ok(exit_code(status));
        }
        let silent = started.elapsed().as_millis() as u64 - last.load(Ordering::SeqCst)
            > SILENCE_LIMIT.as_millis() as u64;
        if ended.load(Ordering::SeqCst) {
            break Stop::Disconnected;
        }
        if signalled.load(Ordering::SeqCst) {
            break Stop::Signal;
        }
        if silent {
            break Stop::Silent;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let status = stop_group(&mut child);
    drop(dir);
    let _ = writeln!(
        io::stderr(),
        "opv: {}; stopped the app and removed its secrets directory",
        stop.reason()
    );
    Ok(status.map_or(1, exit_code))
}

#[cfg(not(unix))]
pub fn receive(_input: Box<dyn Read + Send>) -> Result<i32, Error> {
    Err(Error::Policy(
        "remote delivery receives on Linux only; nothing was written or started".into(),
    )
    .with_code(Code::PolicyRefused))
}

/// SIGTERM to the app's process group, SIGKILL after [`STOP_GRACE`]; the app's status.
#[cfg(unix)]
fn stop_group(child: &mut std::process::Child) -> Option<std::process::ExitStatus> {
    let group = -(child.id() as i32);
    // SAFETY: kill(2) on the child's own process group, created with process_group(0).
    unsafe { libc::kill(group, libc::SIGTERM) };
    let deadline = Instant::now() + STOP_GRACE;
    while Instant::now() < deadline {
        if let Ok(Some(s)) = child.try_wait() {
            // SAFETY: as above; ends anything the app left in its group.
            unsafe { libc::kill(group, libc::SIGKILL) };
            return Some(s);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // SAFETY: as above.
    unsafe { libc::kill(group, libc::SIGKILL) };
    child.wait().ok()
}

#[cfg(test)]
#[path = "remote_delivery_tests.rs"]
mod tests;
