//! #139: remote development delivery, run as the real binary. The receiver gets its payload
//! on stdin as SSH would give it; the sender runs against a stand-in `ssh` on PATH that
//! starts the receiver locally. Test markers only, never a real credential. The apps compare
//! values themselves and print only verdicts.
#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use opv::app::remote_delivery::{Header, Plan, encode};

const MARKER: &str = "test-marker-value-139";
const PEM: &str = "-----BEGIN PRIVATE KEY-----\nTESTMARKER139\n-----END PRIVATE KEY-----\n";
const HOST_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestMarkerHostKeyNotARealKey139";

/// The session's RAM-backed runtime directory, when this machine has one (else the
/// file-delivery scenarios are skipped, as in `tests/local_delivery.rs`).
fn runtime_dir() -> Option<PathBuf> {
    let uid = rustix::process::geteuid().as_raw();
    let p = PathBuf::from(format!("/run/user/{uid}"));
    let st = rustix::fs::statfs(&p).ok()?;
    #[allow(clippy::unnecessary_cast)]
    let magic = (st.f_type as u64) & 0xffff_ffff;
    (magic == 0x0102_1994).then_some(p)
}

fn header(workdir: &Path, script: &str) -> Header {
    Header {
        keys: vec!["SERVE_TOKEN".into(), "GITHUB_APP_PRIVATE_KEY".into()],
        files: vec![(
            "GITHUB_APP_PRIVATE_KEY".into(),
            "github-app/private-key".into(),
        )],
        dir_env: Some("JZ_VAULT_DIR".into()),
        workdir: workdir.to_str().unwrap().into(),
        command: vec!["sh".into(), "-c".into(), script.into()],
    }
}

/// The app script's verdicts: the variable and the file compared with the markers.
const VERDICTS: &str = r#"
expected_pem="$(printf '%s\n' '-----BEGIN PRIVATE KEY-----' 'TESTMARKER139' '-----END PRIVATE KEY-----')"
[ "$SERVE_TOKEN" = "test-marker-value-139" ] && echo token-ok
cmp -s "$JZ_VAULT_DIR/github-app/private-key" - <<EOF && echo pem-ok
$expected_pem
EOF
[ -z "$OP_SESSION_my" ] && echo no-op-session
"#;

fn receiver(runtime: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_opv"));
    c.arg("remote-receive")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("XDG_RUNTIME_DIR", runtime)
        .env("OP_SESSION_my", MARKER)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    c
}

/// Deliver `payload` and close stdin right after it; the app's stdout.
fn receive_once(runtime: &Path, payload: &[u8]) -> (Option<i32>, String) {
    let mut child = receiver(runtime).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(payload).unwrap();
    // Keep the connection open while the app runs: it is stopped when stdin ends.
    let out = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(2));
        drop(stdin);
    });
    let o = child.wait_with_output().unwrap();
    out.join().unwrap();
    (
        o.status.code(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        ),
    )
}

fn delivered(runtime: &Path) -> String {
    let work = tempfile::tempdir().unwrap();
    let h = header(work.path(), VERDICTS);
    let p = encode(&h, &[MARKER.as_bytes(), PEM.as_bytes()]).unwrap();
    receive_once(runtime, &p).1
}

#[test]
fn the_remote_app_reads_its_variable_key() {
    let Some(rt) = runtime_dir() else { return };
    let out = delivered(&rt);
    assert!(out.contains("token-ok"), "{out}");
}

#[test]
fn the_remote_app_reads_the_pem_byte_for_byte() {
    let Some(rt) = runtime_dir() else { return };
    assert!(delivered(&rt).contains("pem-ok"));
}

#[test]
fn the_remote_app_gets_no_op_session() {
    let Some(rt) = runtime_dir() else { return };
    assert!(delivered(&rt).contains("no-op-session"));
}

#[test]
fn a_cut_payload_starts_nothing() {
    let Some(rt) = runtime_dir() else { return };
    let work = tempfile::tempdir().unwrap();
    let flag = work.path().join("started");
    let h = header(work.path(), &format!("touch {}", flag.display()));
    let p = encode(&h, &[MARKER.as_bytes(), PEM.as_bytes()]).unwrap();
    receive_once(&rt, &p[..p.len() - 8]);
    assert!(!flag.exists());
}

#[test]
fn a_cut_payload_writes_no_directory() {
    let Some(rt) = runtime_dir() else { return };
    let before = remote_dirs(&rt);
    let work = tempfile::tempdir().unwrap();
    let h = header(work.path(), "true");
    let p = encode(&h, &[MARKER.as_bytes(), PEM.as_bytes()]).unwrap();
    receive_once(&rt, &p[..p.len() - 8]);
    assert_eq!(remote_dirs(&rt), before);
}

fn remote_dirs(rt: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(rt)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("opv-remote."))
        })
        .collect();
    v.sort();
    v
}

/// A long-running app that prints its directory; stdin is closed once it is up. Returns how
/// long the receiver took to stop it and the directory it had.
fn disconnect(rt: &Path) -> (Duration, PathBuf) {
    let work = tempfile::tempdir().unwrap();
    let h = header(work.path(), "echo \"$JZ_VAULT_DIR\"; exec sleep 60");
    let p = encode(&h, &[MARKER.as_bytes(), PEM.as_bytes()]).unwrap();
    let mut child = receiver(rt).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&p).unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let start = Instant::now();
    drop(stdin);
    child.wait().unwrap();
    (start.elapsed(), PathBuf::from(line.trim()))
}

#[test]
fn a_dropped_connection_stops_the_remote_app() {
    let Some(rt) = runtime_dir() else { return };
    assert!(disconnect(&rt).0 < Duration::from_secs(10));
}

#[test]
fn a_dropped_connection_removes_the_secrets_directory() {
    let Some(rt) = runtime_dir() else { return };
    let (_, dir) = disconnect(&rt);
    assert!(!dir.exists(), "{}", dir.display());
}

// --- the sender, end to end through a stand-in ssh -----------------------------------

/// A directory with an `ssh` that ignores its arguments and runs the receiver here, with
/// the runtime directory a remote session would have.
fn fake_ssh(rt: &Path) -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"{args}\"\nenv > \"{env}\"\nXDG_RUNTIME_DIR='{rt}' exec '{opv}' remote-receive\n",
        args = d.path().join("args").display(),
        env = d.path().join("env").display(),
        rt = rt.display(),
        opv = env!("CARGO_BIN_EXE_opv"),
    );
    let path = d.path().join("ssh");
    std::fs::write(&path, script).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    d
}

fn send(rt: &Path, ssh: &Path) -> String {
    let work = tempfile::tempdir().unwrap();
    let plan = Plan {
        profile: "builder".into(),
        host: "builder.example.internal".into(),
        port: 22,
        user: "dev".into(),
        host_key: HOST_KEY.into(),
        identity_file: None,
        opv: "/usr/local/bin/opv".into(),
        header: header(work.path(), VERDICTS),
    };
    let o = Command::new(env!("CARGO_BIN_EXE_opv"))
        .args([
            "remote-send",
            "--plan",
            &serde_json::to_string(&plan).unwrap(),
        ])
        .env_clear()
        .env("PATH", format!("{}:/usr/bin:/bin", ssh.display()))
        .env("HOME", "/tmp")
        .env("XDG_RUNTIME_DIR", rt)
        .env("SERVE_TOKEN", MARKER)
        .env("GITHUB_APP_PRIVATE_KEY", PEM)
        .env("OP_SESSION_my", MARKER)
        .output()
        .unwrap();
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn values_sent_through_ssh_arrive_exactly() {
    let Some(rt) = runtime_dir() else { return };
    let ssh = fake_ssh(&rt);
    let out = send(&rt, ssh.path());
    assert!(out.contains("token-ok") && out.contains("pem-ok"), "{out}");
}

#[test]
fn no_value_reaches_the_ssh_command_line() {
    let Some(rt) = runtime_dir() else { return };
    let ssh = fake_ssh(&rt);
    send(&rt, ssh.path());
    let args = std::fs::read_to_string(ssh.path().join("args")).unwrap();
    assert!(!args.contains(MARKER) && !args.contains("TESTMARKER139"));
}

#[test]
fn no_value_or_op_session_reaches_the_ssh_environment() {
    let Some(rt) = runtime_dir() else { return };
    let ssh = fake_ssh(&rt);
    send(&rt, ssh.path());
    let env = std::fs::read_to_string(ssh.path().join("env")).unwrap();
    assert!(
        !env.contains(MARKER) && !env.contains("OP_SESSION"),
        "{env}"
    );
}
