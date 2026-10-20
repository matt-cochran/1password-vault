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
#[cfg(unix)]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::local_delivery::Outer;
use crate::cause::{Cause, DiagnoseContext, EnvName, ExitClass, Guard, IoKind, KeyName};
use crate::cause::{ProductName, ProfileName};
use crate::domain::model::Remote;
use crate::error::Error;

/// The payload's first line: the protocol and its version.
pub const MAGIC: &[u8] = b"OPV-REMOTE 1\n";
/// The protocol version [`MAGIC`] names.
pub const PROTOCOL: u32 = 1;
/// The receiver's first stderr line, before it reads the payload: it runs and speaks
/// protocol `<n>` (the handshake). The sender does not show it.
pub const READY_PREFIX: &str = "OPV-REMOTE READY ";
/// The receiver's stderr line once the payload is checked and delivered, just before the
/// app starts. The sender does not show it.
pub const DELIVERED: &str = "OPV-REMOTE DELIVERED";
/// The refusal of a payload that does not start with [`MAGIC`].
const OTHER_PROTOCOL: &str =
    "the payload is not opv remote protocol 1 (is the remote opv the same release?)";
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
    /// The person's `opv run` (names and flags only), so the receiver's messages name the
    /// run to fix and re-run, never the hidden receiver (design §6.1, X25).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outer: Option<Outer>,
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
    /// `(key, path)` of each file key, `dir_env` the product's directory variable, `outer`
    /// the person's run (dropped when it is not valid).
    pub fn new(
        profile: &str,
        remote: &Remote,
        keys: Vec<String>,
        files: Vec<(String, String)>,
        dir_env: Option<String>,
        outer: Option<Outer>,
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
                outer: outer.filter(Outer::is_valid),
            },
        }
    }

    /// The person's run this plan serves, when known.
    fn outer(&self) -> Option<&Outer> {
        self.header.outer.as_ref()
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
        return Err(refused(OTHER_PROTOCOL));
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
/// a heartbeat until SSH ends. Returns the remote app's exit code. When SSH itself failed
/// (255 before the receiver's handshake, a dropped session, a missing remote opv), the
/// failure goes to the ssh diagnosis ([`super::remote_diagnose`]) and its errors name the
/// person's `opv run`, never this hidden step (design §6.1, X25).
pub fn send(plan: &Plan) -> Result<i32, Error> {
    Outer::install(plan.outer());
    let bug = |site: &'static str| -> Error { Cause::Bug { site }.into() };
    check_header(&plan.header).map_err(|_| bug("remote-send: the plan opv run built"))?;
    let inherited: Zeroizing<Vec<(String, String)>> = Zeroizing::new(std::env::vars().collect());
    let mut values: Vec<&[u8]> = Vec::with_capacity(plan.header.keys.len());
    for key in &plan.header.keys {
        // `op run` resolves every reference `opv run` gave it, or starts nothing.
        let Some((_, v)) = inherited.iter().find(|(k, _)| k == key) else {
            return Err(bug("remote-send: a key op run did not resolve"));
        };
        if v.len() > MAX_VALUE {
            return Err(too_large(plan, key));
        }
        values.push(v.as_bytes());
    }
    let payload =
        encode(&plan.header, &values).map_err(|_| bug("remote-send: the payload encoding"))?;
    drop(values);

    // The pinned host key, in a private directory removed when this step ends.
    let base =
        crate::app::local_delivery::runtime_dir_support().unwrap_or_else(|_| std::env::temp_dir());
    let dir = crate::ramdir::PrivateDir::create(&base, "opv-ssh.")
        .map_err(|e| super::local_delivery::private_dir_failed(&base, &e))?;
    let known = dir.path().join("known_hosts");
    std::fs::write(&known, known_hosts_line(plan))
        .map_err(|e| super::local_delivery::private_dir_failed(dir.path(), &e))?;

    // Ctrl-C reaches SSH too; this step outlives it to remove the directory above.
    let stop = Arc::new(AtomicBool::new(false));
    #[cfg(unix)]
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        let _ = signal_hook::flag::register(sig, Arc::clone(&stop));
    }

    let env = Zeroizing::new(ssh_env(&inherited));
    let args = ssh_args(plan, &known);
    let mut child = std::process::Command::new("ssh")
        .args(&args)
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| ssh_spawn_failed(&e))?;
    drop(inherited);
    // SSH's own messages and the receiver's are shown as they come; the handshake lines
    // are kept for the diagnosis below.
    let relay = child
        .stderr
        .take()
        .map(|mut err| std::thread::spawn(move || relay_stderr(&mut err, &mut io::stderr())));
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
        .map_err(|_| bug("remote-send: waiting for ssh"))?;
    drop(dir);
    let seen = relay.and_then(|t| t.join().ok()).unwrap_or_default();
    ssh_outcome(plan, &args, exit_code(status), &seen)
}

/// A value over the payload's limit for one key, named by the run it belongs to.
fn too_large(plan: &Plan, key: &str) -> Error {
    let (env, product) = plan
        .outer()
        .map(|o| (o.env.as_str(), o.product.as_str()))
        .unwrap_or_default();
    Cause::Guard {
        guard: Guard::ValueTooLarge {
            product: ProductName::new(product),
            key: KeyName::new(key),
            env: EnvName::new(env),
            limit: MAX_VALUE as u64,
        },
    }
    .into()
}

/// `ssh` could not be started on this machine.
fn ssh_spawn_failed(e: &io::Error) -> Error {
    if e.kind() == io::ErrorKind::NotFound {
        let host = crate::host::Host::detect();
        Cause::ToolMissing {
            tool: "ssh".into(),
            platform: host.platform,
            shell: host.shell,
            ci: host.ci,
        }
        .into()
    } else {
        Cause::ToolUnusable {
            tool: "ssh".into(),
            why: crate::cause::Unusable::SpawnFailed {
                io: IoKind::from(e.kind()),
            },
        }
        .into()
    }
}

/// The run's result from SSH's exit `code` and what the receiver said on stderr (`seen`).
/// A receiver of another protocol is a version mismatch, whatever the code. A 255 before the
/// handshake, a 255 the session's end explains, or a 127 before the handshake (no remote
/// opv) is SSH's own failure, diagnosed from its recorded wording; any other code, and a
/// 255 after delivery that nothing explains, is the remote app's own exit (R77).
fn ssh_outcome(plan: &Plan, args: &[String], code: i32, seen: &Relayed) -> Result<i32, Error> {
    if let Some(p) = seen.protocol.filter(|p| *p != PROTOCOL) {
        return Err(Cause::RemoteVersionMismatch {
            profile: ProfileName::new(&plan.profile),
            remote_protocol: p,
        }
        .into());
    }
    let handshake = seen.protocol.is_some();
    if !(code == 255 || (code == 127 && !handshake)) {
        return Ok(code);
    }
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    crate::runner::record_streamed("ssh", &words, ExitClass::Code { code }, &seen.tail);
    let Some(failed) = crate::runner::take_failure() else {
        return Ok(code);
    };
    let known = pinned_check_file(plan);
    let conn = super::remote_diagnose::Connection {
        profile: &plan.profile,
        user: &plan.user,
        host: &plan.host,
        port: plan.port,
        known_hosts: &known,
        identity_file: plan.identity_file.as_deref().map(Path::new),
        remote_program: &plan.opv,
        handshake_done: handshake,
        payload_confirmed: seen.delivered,
    };
    let ctx = DiagnoseContext {
        env: plan.outer().map(|o| EnvName::new(&o.env)),
        ..DiagnoseContext::default()
    };
    match super::remote_diagnose::diagnose(failed.seen.clone(), failed.stderr(), &conn, &ctx) {
        Cause::Unrecognized { .. } if seen.delivered => Ok(code),
        cause => Err(cause.into()),
    }
}

/// A `known_hosts` file pinning the profile's host key under the host's own name, kept in
/// opv's state directory so the connection check a failure names can be run as shown (the
/// run's own pinned file is removed when the run ends). A public key only.
fn pinned_check_file(plan: &Plan) -> std::path::PathBuf {
    let state = std::env::var_os("XDG_STATE_HOME")
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| Path::new(&h).join(".local/state")))
        .unwrap_or_else(std::env::temp_dir);
    let name: String = plan
        .profile
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let dir = state.join("opv").join("known_hosts");
    let path = dir.join(name);
    let host = if plan.port == 22 {
        plan.host.clone()
    } else {
        format!("[{}]:{}", plan.host, plan.port)
    };
    let _ = std::fs::create_dir_all(&dir)
        .and_then(|()| std::fs::write(&path, format!("{host} {}\n", plan.host_key)));
    path
}

/// What the sender saw on SSH's stderr: the receiver's handshake (its protocol), whether
/// it confirmed the payload, and the last bytes (for the diagnosis; never shown again).
#[derive(Default)]
pub struct Relayed {
    pub protocol: Option<u32>,
    pub delivered: bool,
    pub tail: Zeroizing<Vec<u8>>,
}

/// The most of SSH's stderr kept for the diagnosis.
const TAIL: usize = 16 * 1024;

fn keep(tail: &mut Vec<u8>, bytes: &[u8]) {
    tail.extend_from_slice(bytes);
    if tail.len() > TAIL {
        let cut = tail.len() - TAIL;
        tail.drain(..cut);
    }
}

/// Copy SSH's stderr to `out` as it comes, leaving out the receiver's two handshake lines
/// ([`READY_PREFIX`], [`DELIVERED`]). Line by line until the payload is confirmed (SSH's
/// and the receiver's messages are whole lines), then the app's output unchanged.
pub fn relay_stderr(input: &mut dyn Read, out: &mut dyn Write) -> Relayed {
    use std::io::BufRead;
    let mut r = io::BufReader::new(input);
    let mut seen = Relayed::default();
    let mut line = Zeroizing::new(Vec::new());
    while !seen.delivered {
        line.clear();
        match r.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => return seen,
            Ok(_) => {}
        }
        let text = line.strip_suffix(b"\n").unwrap_or(&line);
        if let Some(n) = text.strip_prefix(READY_PREFIX.as_bytes()) {
            let n = std::str::from_utf8(n)
                .ok()
                .and_then(|n| n.trim().parse().ok());
            seen.protocol = Some(n.unwrap_or(0));
            continue;
        }
        if text == DELIVERED.as_bytes() {
            seen.delivered = true;
            continue;
        }
        let _ = out.write_all(&line).and_then(|()| out.flush());
        keep(&mut seen.tail, &line);
    }
    let mut buf = Zeroizing::new(vec![0u8; 4096]);
    loop {
        match r.read(&mut buf) {
            Ok(0) | Err(_) => return seen,
            Ok(n) => {
                let _ = out.write_all(&buf[..n]).and_then(|()| out.flush());
                keep(&mut seen.tail, &buf[..n]);
            }
        }
    }
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
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// stdin ended: the local side is gone.
    Disconnected,
    /// No heartbeat for [`SILENCE_LIMIT`].
    Silent,
    /// SIGHUP, SIGTERM or SIGINT reached the receiver.
    Signal,
}

#[cfg(unix)]
impl Stop {
    fn reason(self) -> &'static str {
        match self {
            Stop::Disconnected => "the connection to the local opv ended",
            Stop::Silent => "the local opv sent no heartbeat for 45 seconds",
            Stop::Signal => "the remote opv was stopped (SIGHUP, SIGTERM or SIGINT)",
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
                "{key} holds a NUL byte, which an environment variable cannot carry; give the \
                 key file = \"<path>\" in the configuration"
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

/// This host's name, for the label on the receiver's messages.
#[cfg(unix)]
fn host_name() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: gethostname writes at most `buf.len()` bytes into the buffer it is given.
    let ok = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } == 0;
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    match std::str::from_utf8(&buf[..end]) {
        Ok(name) if ok && !name.is_empty() && !name.chars().any(char::is_control) => {
            name.to_string()
        }
        _ => "the remote host".to_string(),
    }
}

/// The label on every message the receiver writes: its stderr reaches the person's
/// terminal through SSH, so each line says it comes from the remote host (07.18).
#[cfg(unix)]
fn remote_label() -> String {
    format!("opv on {} (remote)", host_name())
}

/// Print `e` labelled as the remote host's and return its exit code: the steps render
/// against the person's `opv run` ([`Outer::install`]), never `opv remote-receive`.
#[cfg(unix)]
fn report_remote(e: &Error) -> i32 {
    let text = crate::error::report(e);
    let text = match text.strip_prefix("opv: ") {
        Some(rest) => format!("{}: {rest}", remote_label()),
        None => text,
    };
    let _ = write!(crate::output::stderr(), "{text}");
    e.exit_code()
}

/// `opv remote-receive` on the remote host: read the payload from `input` (SSH's stdin),
/// deliver it, run the pinned command, and stop it when the local side goes away. Its first
/// stderr line is the handshake ([`READY_PREFIX`]); a refusal is printed here, labelled as
/// the remote host's, and its exit code returned.
#[cfg(unix)]
pub fn receive(input: Box<dyn Read + Send>) -> Result<i32, Error> {
    let _ = writeln!(io::stderr(), "{READY_PREFIX}{PROTOCOL}");
    match deliver(input) {
        Ok(code) => Ok(code),
        Err(e) => Ok(report_remote(&e)),
    }
}

/// The receiver's work after the handshake.
#[cfg(unix)]
fn deliver(mut input: Box<dyn Read + Send>) -> Result<i32, Error> {
    let bug = |site: &'static str| -> Error { Cause::Bug { site }.into() };
    let (header, values) = match decode(&mut *input) {
        Ok(d) => d,
        // The sender saw this receiver's protocol in the handshake and reports the
        // mismatch with the profile's name; nothing was written or started.
        Err(r) if r.0 == OTHER_PROTOCOL => return Ok(3),
        Err(_) => return Err(bug("remote-receive: the payload check")),
    };
    let outer = header.outer.clone().filter(Outer::is_valid);
    Outer::install(outer.as_ref());
    let session: Zeroizing<Vec<(String, String)>> = Zeroizing::new(std::env::vars().collect());
    let mut dir = None;
    if !header.files.is_empty() {
        use crate::ramdir::{PrivateDir, sweep};
        let runtime = super::local_delivery::runtime_dir_support()
            .map_err(|why| Outer::ram_dir_unavailable(outer.as_ref(), true, why))?;
        sweep(&runtime, DIR_PREFIX);
        let private = PrivateDir::create(&runtime, DIR_PREFIX)
            .map_err(|e| super::local_delivery::private_dir_failed(&runtime, &e))?;
        let open = super::local_delivery::OpenDir::open_private(private.path())
            .map_err(|e| super::local_delivery::private_dir_failed(private.path(), &e))?;
        for (key, rel) in &header.files {
            let i = header.keys.iter().position(|k| k == key).expect("checked");
            super::local_delivery::write_file(&open, rel, &values[i])
                .map_err(|e| super::local_delivery::private_dir_failed(private.path(), &e))?;
        }
        dir = Some(private);
    }
    // A NUL byte cannot reach `remote-send` through its environment, so only a faulty
    // sender sends one.
    let env = remote_env(&header, &values, &session, dir.as_ref().map(|d| d.utf8()))
        .map_err(|_| bug("remote-receive: a variable value holds a NUL byte"))?;
    drop(values);

    let signalled = Arc::new(AtomicBool::new(false));
    for sig in [libc::SIGHUP, libc::SIGTERM, libc::SIGINT] {
        let _ = signal_hook::flag::register(sig, Arc::clone(&signalled));
    }
    let _ = writeln!(io::stderr(), "{DELIVERED}");
    // As in the local step: inherited descriptors stop here (stdio still passes).
    crate::hardening::cloexec_inherited();
    use std::os::unix::process::CommandExt;
    let mut child = std::process::Command::new(&header.command[0])
        .args(&header.command[1..])
        .current_dir(&header.workdir)
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k, v)))
        .stdin(std::process::Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|e| -> Error {
            Cause::ChildStartFailed {
                program: header.command[0].clone(),
                workdir: Some(std::path::PathBuf::from(&header.workdir)),
                io: IoKind::from(e.kind()),
                remote: Some(ProfileName::new(
                    outer
                        .as_ref()
                        .and_then(|o| o.profile.clone())
                        .unwrap_or_default(),
                )),
            }
            .into()
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
        if let Some(status) = child
            .try_wait()
            .map_err(|_| bug("remote-receive: waiting for the app"))?
        {
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
        "{}: {}; stopped the app and removed its secrets directory",
        remote_label(),
        stop.reason()
    );
    Ok(status.map_or(1, exit_code))
}

#[cfg(not(unix))]
pub fn receive(_input: Box<dyn Read + Send>) -> Result<i32, Error> {
    // File keys need a RAM-backed folder, which only Linux and other Unix hosts give.
    Err(crate::cause::Cause::RamDirUnavailable {
        remote: None,
        why: crate::cause::RamDir::NoneOnPlatform {
            os: std::env::consts::OS,
        },
        purpose: crate::cause::RamPurpose::FileDelivery,
        env: None,
        product: None,
    }
    .into())
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
