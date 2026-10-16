//! The simulated `ssh`: the remote side runs here, as `tests/remote_delivery.rs` does, with
//! the host's environment and its command paths mapped to local ones. Failure replies come
//! from `tests/fixtures/ssh/failures/` (OpenSSH 9.6p1). A successful session prints nothing
//! of ssh's own (failures 11); its output is the remote side's. The host-key fingerprint in
//! the mismatch banner (failures 01, `<FINGERPRINT>`) is the host's `fingerprint`, else the
//! one recorded from a throwaway sshd in `tests/fixtures/ssh/success/02-keygen-fingerprint`
//! (the same `SHA256:…` the banner printed for that key). Nothing here is invented.
//!
//! ```json
//! "hosts": {"builder.example.internal": {
//!   "env": {"XDG_RUNTIME_DIR": "/tmp/…"},
//!   "commands": {"/usr/local/bin/opv": "/abs/path/to/opv"},
//!   "state": "ok"        // or connection_refused, host_key_mismatch, host_key_unknown,
//! }}                     // auth_refused: every connection fails that way
//! ```
//! A host missing from `hosts` does not resolve (06).

use std::process::{Command, Stdio};
use std::time::Duration;

use crate::args::flag;
use crate::faults::Kind;
use crate::recordings::{Reply, recorded};
use crate::world::World;

const DIR: &str = "ssh/failures";
/// ssh options that take a value.
const VALUED: &[&str] = &[
    "-F", "-o", "-i", "-p", "-l", "-E", "-c", "-m", "-b", "-J", "-L", "-R", "-D", "-W", "-S", "-O",
    "-Q", "-w", "-e", "-B", "-I",
];

/// A remote command to run here once the world is unlocked.
pub struct Remote {
    pub command: String,
    pub env: Vec<(String, String)>,
    /// `drop_mid_run`: stop the session after this long.
    pub drop_after: Option<Duration>,
    /// `applied_but_reply_lost`: run it, then lose the connection before its reply.
    pub lose_reply: bool,
    pub host: String,
}

pub enum Action {
    Reply(Reply),
    Remote(Remote),
}

/// The parsed call: options, the destination and the remote command.
struct Parsed {
    host: String,
    command: Vec<String>,
}

fn parse(args: &[String]) -> Parsed {
    let mut it = args.iter().peekable();
    let mut rest = Vec::new();
    while let Some(a) = it.next() {
        if a == "--" {
            rest.extend(it.by_ref().cloned());
            break;
        }
        if VALUED.contains(&a.as_str()) {
            it.next();
            continue;
        }
        if a.starts_with('-') {
            continue;
        }
        rest.push(a.clone());
        rest.extend(it.by_ref().cloned());
        break;
    }
    let mut rest = rest.into_iter();
    Parsed {
        host: rest.next().unwrap_or_default(),
        command: rest.collect(),
    }
}

/// The call's words: the destination, then the remote command's words.
pub fn call_words(args: &[String]) -> Vec<String> {
    let p = parse(args);
    std::iter::once(p.host)
        .chain(p.command.join(" ").split_whitespace().map(str::to_string))
        .collect()
}

/// The value of `-o <name>=<value>`.
fn option(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .filter(|w| w[0] == "-o")
        .find_map(|w| w[1].strip_prefix(&format!("{name}=")).map(str::to_string))
}

pub fn fault(kind: Kind, world: &World, args: &[String]) -> Action {
    let p = parse(args);
    let profile = option(args, "HostKeyAlias")
        .and_then(|a| a.strip_prefix("opv-remote-").map(str::to_string))
        .unwrap_or_default();
    let known = option(args, "UserKnownHostsFile").unwrap_or_default();
    let port = flag(args, "-p").unwrap_or("22").to_string();
    let user = flag(args, "-l").unwrap_or_default().to_string();
    let case =
        |c: &str, subs: &[(&str, String)]| Action::Reply(recorded(&format!("{DIR}/{c}"), subs));
    match kind {
        Kind::HostKeyMismatch => case(
            "01-host-key-mismatch",
            &[
                (
                    "<KNOWN_HOSTS_TRUNCATED_100>",
                    known.chars().take(100).collect(),
                ),
                ("<KNOWN_HOSTS>", known),
                (
                    "<FINGERPRINT>",
                    world.doc["hosts"][&p.host]["fingerprint"]
                        .as_str()
                        .map(str::to_string)
                        .unwrap_or_else(recorded_fingerprint),
                ),
                ("<PROFILE>", profile),
            ],
        ),
        Kind::HostKeyUnknown => case("02-host-key-unknown", &[("<PROFILE>", profile)]),
        Kind::Forbidden | Kind::CredentialRejected => {
            case("03-auth-refused", &[("<USER>", user), ("<HOST>", p.host)])
        }
        Kind::ConnectionRefused | Kind::Unreachable => case(
            "05-connection-refused",
            &[("<HOST>", p.host), ("<PORT>", port)],
        ),
        Kind::NotFound => case(
            "06-name-resolution-failed",
            &[("<UNRESOLVABLE_HOST>", p.host)],
        ),
        Kind::ConnectTimeout => case(
            "12-connect-timeout",
            &[
                ("<UNROUTABLE_HOST>", p.host),
                (" port 22:", format!(" port {port}:")),
            ],
        ),
        Kind::RemoteCommandMissing => case(
            "08-remote-command-not-on-path",
            &[(
                "opv-not-installed",
                p.command
                    .join(" ")
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_string(),
            )],
        ),
        Kind::ServerUnresponsive => case("10-drop-server-unresponsive", &[("<HOST>", p.host)]),
        Kind::DropMidRun | Kind::AppliedButReplyLost => match run(world, args) {
            Action::Remote(mut r) => {
                if kind == Kind::DropMidRun {
                    r.drop_after = Some(Duration::from_secs(1));
                } else {
                    r.lose_reply = true;
                }
                Action::Remote(r)
            }
            other => other,
        },
        _ => Action::Reply(Reply::no_recording(&format!("{} on ssh", kind.name()), DIR)),
    }
}

/// The `SHA256:…` field of `ssh-keygen -l -E sha256` on the throwaway host key (success 02).
fn recorded_fingerprint() -> String {
    let r = recorded("ssh/success/02-keygen-fingerprint", &[]);
    String::from_utf8_lossy(&r.stdout)
        .split_whitespace()
        .find(|w| w.starts_with("SHA256:"))
        .unwrap_or_default()
        .to_string()
}

pub fn run(world: &World, args: &[String]) -> Action {
    let p = parse(args);
    let Some(host) = world.doc["hosts"].get(&p.host).cloned() else {
        return fault(Kind::NotFound, world, args);
    };
    let state = match host["state"].as_str().unwrap_or("ok") {
        "connection_refused" => Some(Kind::ConnectionRefused),
        "host_key_mismatch" => Some(Kind::HostKeyMismatch),
        "host_key_unknown" => Some(Kind::HostKeyUnknown),
        "auth_refused" => Some(Kind::Forbidden),
        _ => None,
    };
    if let Some(kind) = state {
        return fault(kind, world, args);
    }
    let line = p.command.join(" ");
    let (first, rest) = line.split_once(' ').unwrap_or((line.as_str(), ""));
    let mapped = host["commands"][first]
        .as_str()
        .unwrap_or(first)
        .to_string();
    if mapped.starts_with('/') && !std::path::Path::new(&mapped).exists() {
        return Action::Reply(recorded(
            &format!("{DIR}/07-remote-command-missing-path"),
            &[("<TMP>/missing/opv", first.to_string())],
        ));
    }
    let env: Vec<(String, String)> = host["env"]
        .as_object()
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
                .collect()
        })
        .unwrap_or_default();
    // A bare command name the remote PATH does not hold: the remote bash's reply (08), not
    // whatever this machine's shell would print.
    let path = env
        .iter()
        .find(|(k, _)| k == "PATH")
        .map(|(_, v)| v.clone())
        .or_else(|| std::env::var("PATH").ok())
        .unwrap_or_default();
    let builtin = matches!(
        mapped.as_str(),
        "true" | "false" | "echo" | "cat" | "exec" | ""
    );
    if !mapped.contains('/')
        && !builtin
        && !path
            .split(':')
            .any(|d| std::path::Path::new(d).join(&mapped).is_file())
    {
        return fault(Kind::RemoteCommandMissing, world, args);
    }
    Action::Remote(Remote {
        command: if rest.is_empty() {
            mapped
        } else {
            format!("{mapped} {rest}")
        },
        env,
        drop_after: None,
        lose_reply: false,
        host: p.host,
    })
}

/// Run the remote side here: its stdin, stdout and stderr are ssh's own. Returns ssh's exit.
pub fn execute(r: Remote) -> Reply {
    let shell = if std::path::Path::new("/bin/bash").exists() {
        "/bin/bash"
    } else {
        "/bin/sh"
    };
    let mut cmd = Command::new(shell);
    cmd.arg("-c")
        .arg(&r.command)
        .envs(r.env.iter().map(|(k, v)| (k, v)));
    if r.lose_reply {
        cmd.stdout(Stdio::null());
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return Reply {
                stderr: format!("opv-sim: cannot run the remote side ({e})\n").into_bytes(),
                code: 255,
                ..Reply::default()
            };
        }
    };
    let dropped = || {
        recorded(
            &format!("{DIR}/09-drop-session-killed"),
            &[("<HOST>", r.host.clone())],
        )
    };
    if let Some(after) = r.drop_after {
        std::thread::sleep(after);
        let _ = child.kill();
        let _ = child.wait();
        return dropped();
    }
    let status = child.wait();
    if r.lose_reply {
        return dropped();
    }
    Reply {
        code: status.ok().and_then(|s| s.code()).unwrap_or(255),
        ..Reply::default()
    }
}
