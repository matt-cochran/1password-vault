//! opv-sim scenarios for `opv set --from-file` (0.15.0, #217): a file key's bytes are
//! stored verbatim from the file.
//!
//! `opv set` runs only in a person's own terminal, and the scenario harness gives opv none
//! (`scenarios/set_needs_terminal.snap`): the terminal-requiring cases put stdin and stdout
//! on the slave side of a pseudo-terminal from [`libc::openpty`], so the real binary sees a
//! TTY while stderr stays piped and `--json` still reaches the snapshot.
//!
//! The world is the e2e app's (`tests/e2e/app/world.json`) with the dev web vault writable
//! and `web/TLS_CERTIFICATE` (declared with `file = "tls/certificate"`) and `web/API_KEY`
//! (no `file`) present. Each case is one behaviour with one assertion:
//!
//! - a multi-line, canary-looking PEM with a trailing newline written with `--from-file` is
//!   stored byte for byte (read back from the simulated item);
//! - a plain key with `--from-file` is refused `usage`;
//! - a symlink path is refused `input_invalid`;
//! - without a terminal the command is refused `terminal_required` (exit 6);
//! - under agent mode (`OPV_AGENT=1`) it is refused `person_only` (exit 6).

use serde_json::{Value, json};

use crate::coverage::{Run, Scenario, scenario_snapshots, updating};

/// The scenario snapshot this module writes (`tests/e2e/snapshots/scenarios/`).
pub(crate) const SNAPSHOTS: &[&str] = &["set_from_file"];

/// The dev account's user (`tests/e2e/app/world.json`).
const DEV_USER: &str = "UE2EDEVUSER000000000000001";
/// The dev web vault and its item (a writable boundary).
const WEB_DEV_VAULT: &str = "vE2EWEBDEV0000000000000001";
const WEB_DEV_ITEM: &str = "iE2EWEBDEV0000000000000001";
/// The file key (`file = "tls/certificate"`) and the plain key (no `file`) of the app.
const FILE_KEY: &str = "TLS_CERTIFICATE";
const PLAIN_KEY: &str = "API_KEY";

/// A canary-looking multi-line PEM, ending in a newline: the bytes a person keeps in a file.
/// Never a real key, and never printed: the snapshot only holds the value's state.
const PEM: &str = concat!(
    "-----BEGIN TEST-CANARY CERTIFICATE-----\n",
    "CANARYCANARYCANARYCANARYCANARYCANARYCANARYCANARY\n",
    "CANARYCANARYCANARYCANARYCANARYCANARYCANARYCANARY\n",
    "-----END TEST-CANARY CERTIFICATE-----\n",
);

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

/// `args` with `--json` appended.
fn json_args(a: &[&str]) -> Vec<String> {
    let mut v = args(a);
    v.push("--json".into());
    v
}

fn document(run: &Run) -> Value {
    serde_json::Deserializer::from_str(&run.stdout)
        .into_iter::<Value>()
        .next()
        .and_then(Result::ok)
        .unwrap_or_else(|| panic!("no document: {}{}", run.stdout, run.stderr))
}

/// The app with the dev web vault writable by the dev user, so `opv set` may write it.
fn writable_web_dev() -> Scenario {
    Scenario::new().world(|w| {
        for v in w["op"]["vaults"].as_array_mut().expect("vaults") {
            if v["id"] == WEB_DEV_VAULT {
                v["users"] = json!([{"id": DEV_USER, "name": "E2E Dev",
                                     "email": "dev@example.com"}]);
            }
        }
    })
}

/// The world with `pem/certificate.pem` on disk, owner-only, holding [`PEM`].
fn with_pem_file() -> Scenario {
    writable_web_dev()
        .file("pem/certificate.pem", PEM)
        .mode("pem/certificate.pem", 0o600)
}

/// [`with_pem_file`] with `pem/link.pem` a symbolic link to the real file.
#[cfg(unix)]
fn with_symlinked_pem() -> Scenario {
    let s = with_pem_file();
    std::os::unix::fs::symlink(s.path("pem/certificate.pem"), s.path("pem/link.pem"))
        .expect("symlink");
    s
}

/// The value the simulated 1Password item holds for `label` (the way `consistency.rs` reads
/// the world back), or the empty string when it is absent.
fn stored_value(s: &Scenario, label: &str) -> String {
    let w: Value =
        serde_json::from_str(&std::fs::read_to_string(s.path("world/world.json")).expect("world"))
            .expect("world");
    w["op"]["items"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|i| i["id"] == WEB_DEV_ITEM)
        .flat_map(|i| i["fields"].as_array().cloned().unwrap_or_default())
        .find(|f| f["label"] == label)
        .and_then(|f| f["value"].as_str().map(str::to_string))
        .unwrap_or_else(|| panic!("no stored {label}: {w}"))
}

/// `opv <args>` with stdin and stdout on the slave side of a pseudo-terminal, so the real
/// binary sees the person's terminal the harness does not give it. `stderr` stays piped.
/// Echo and the `\n` → `\r\n` translation are off (termios via `libc`), and any remaining
/// CRLF is normalised, so the snapshot is stable. The master is read to EOF (EIO on Linux)
/// once every slave descriptor is closed, then the child is reaped.
#[cfg(unix)]
fn opv_in_a_pty(s: &Scenario, args: &[String]) -> Run {
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
    use std::process::Stdio;

    let root = s
        .path("bin")
        .parent()
        .expect("scenario root")
        .display()
        .to_string();
    let args: Vec<String> = args.iter().map(|a| a.replace("{root}", &root)).collect();

    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    let made = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(made, 0, "openpty: {}", std::io::Error::last_os_error());
    let master = unsafe { OwnedFd::from_raw_fd(master) };
    let slave = unsafe { OwnedFd::from_raw_fd(slave) };

    // Echo and the \n → \r\n translation off: what the child writes is what the master reads.
    let mut term = unsafe { std::mem::zeroed::<libc::termios>() };
    let got = unsafe { libc::tcgetattr(slave.as_raw_fd(), &mut term) };
    assert_eq!(got, 0, "tcgetattr: {}", std::io::Error::last_os_error());
    term.c_lflag &= !(libc::ECHO | libc::ECHONL);
    term.c_oflag &= !libc::ONLCR;
    let set = unsafe { libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, &term) };
    assert_eq!(set, 0, "tcsetattr: {}", std::io::Error::last_os_error());

    let mut cmd = s.command();
    cmd.args(&args)
        .stdin(Stdio::from(slave.try_clone().expect("pty stdin")))
        .stdout(Stdio::from(slave.try_clone().expect("pty stdout")))
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn opv in a pty");
    // The parent must hold no slave descriptor open, or the master never reaches EOF.
    drop(cmd);
    drop(slave);

    let mut out = Vec::new();
    let mut reader = std::fs::File::from(master);
    match std::io::Read::read_to_end(&mut reader, &mut out) {
        Ok(_) => {}
        Err(e) if e.raw_os_error() == Some(libc::EIO) => {}
        Err(e) => panic!("read the pty: {e}"),
    }
    let status = child.wait().expect("wait opv");
    let mut err = Vec::new();
    if let Some(mut stderr) = child.stderr.take() {
        std::io::Read::read_to_end(&mut stderr, &mut err).expect("stderr");
    }
    Run {
        code: status.code(),
        stdout: s.normalize(&String::from_utf8_lossy(&out).replace("\r\n", "\n")),
        stderr: s.normalize(&String::from_utf8_lossy(&err)),
    }
}

// --- the behaviours, one assertion each -----------------------------------------------------

/// A multi-line PEM with a trailing newline is stored byte for byte.
#[cfg(unix)]
#[test]
fn a_multi_line_pem_from_file_is_stored_byte_for_byte() {
    let s = with_pem_file();
    let run = opv_in_a_pty(
        &s,
        &args(&[
            "set",
            &format!("web/{FILE_KEY}"),
            "--env",
            "dev",
            "--from-file",
            "{root}/pem/certificate.pem",
        ]),
    );
    assert_eq!(
        stored_value(&s, FILE_KEY).as_bytes(),
        PEM.as_bytes(),
        "{}{}",
        run.stdout,
        run.stderr
    );
}

/// A plain key (no `file = …`) refuses `--from-file` with `usage`.
#[cfg(unix)]
#[test]
fn a_plain_key_from_file_is_refused_as_usage() {
    let run = opv_in_a_pty(
        &with_pem_file(),
        &json_args(&[
            "set",
            &format!("web/{PLAIN_KEY}"),
            "--env",
            "dev",
            "--from-file",
            "{root}/pem/certificate.pem",
        ]),
    );
    assert_eq!(
        document(&run)["error"]["code"],
        "usage",
        "{}{}",
        run.stdout,
        run.stderr
    );
}

/// A symlink path is refused `input_invalid`; opv never reads what a link points to.
#[cfg(unix)]
#[test]
fn a_symlink_from_file_is_refused_as_input_invalid() {
    let run = opv_in_a_pty(
        &with_symlinked_pem(),
        &json_args(&[
            "set",
            &format!("web/{FILE_KEY}"),
            "--env",
            "dev",
            "--from-file",
            "{root}/pem/link.pem",
        ]),
    );
    assert_eq!(
        document(&run)["error"]["code"],
        "input_invalid",
        "{}{}",
        run.stdout,
        run.stderr
    );
}

/// Without a terminal the command is `terminal_required`, the catalog's exit 6.
#[test]
fn from_file_without_a_terminal_is_terminal_required() {
    let run = with_pem_file().opv(&json_args(&[
        "set",
        &format!("web/{FILE_KEY}"),
        "--env",
        "dev",
        "--from-file",
        "{root}/pem/certificate.pem",
    ]));
    assert_eq!(
        (document(&run)["error"]["code"].clone(), run.code),
        (json!("terminal_required"), Some(6)),
        "{}{}",
        run.stdout,
        run.stderr
    );
}

/// In agent mode (`OPV_AGENT=1`) it is `person_only`, the catalog's exit 6.
#[test]
fn from_file_in_agent_mode_is_person_only() {
    let run = with_pem_file().var("OPV_AGENT", "1").opv(&json_args(&[
        "set",
        &format!("web/{FILE_KEY}"),
        "--env",
        "dev",
        "--from-file",
        "{root}/pem/certificate.pem",
    ]));
    assert_eq!(
        (document(&run)["error"]["code"].clone(), run.code),
        (json!("person_only"), Some(6)),
        "{}{}",
        run.stdout,
        run.stderr
    );
}

// --- the snapshot ---------------------------------------------------------------------------

/// One run as snapshot sections. The headings end in `text`/`--json`, so the coverage gates
/// read the JSON runs' error documents (fixes_0141).
fn section(snap: &mut String, label: &str, run: &Run) {
    snap.push_str(&format!(
        "\n## {label} exit: {}\n## {label} stdout\n{}\n## {label} stderr\n{}",
        run.code.map_or("killed".into(), |c| c.to_string()),
        run.stdout,
        run.stderr,
    ));
}

/// Each behaviour's telling runs, text and `--json`, each case on a fresh world.
#[cfg(unix)]
fn transcript() -> String {
    let mut snap = String::from("# set_from_file: `opv set --from-file` through the real binary\n");
    let pem = [
        "set",
        &format!("web/{FILE_KEY}"),
        "--env",
        "dev",
        "--from-file",
        "{root}/pem/certificate.pem",
    ];
    let plain = [
        "set",
        &format!("web/{PLAIN_KEY}"),
        "--env",
        "dev",
        "--from-file",
        "{root}/pem/certificate.pem",
    ];
    let link = [
        "set",
        &format!("web/{FILE_KEY}"),
        "--env",
        "dev",
        "--from-file",
        "{root}/pem/link.pem",
    ];

    section(
        &mut snap,
        "pem text",
        &opv_in_a_pty(&with_pem_file(), &args(&pem)),
    );
    section(
        &mut snap,
        "pem --json",
        &opv_in_a_pty(&with_pem_file(), &json_args(&pem)),
    );
    section(
        &mut snap,
        "plain key text",
        &opv_in_a_pty(&with_pem_file(), &args(&plain)),
    );
    section(
        &mut snap,
        "plain key --json",
        &opv_in_a_pty(&with_pem_file(), &json_args(&plain)),
    );
    section(
        &mut snap,
        "symlink text",
        &opv_in_a_pty(&with_symlinked_pem(), &args(&link)),
    );
    section(
        &mut snap,
        "symlink --json",
        &opv_in_a_pty(&with_symlinked_pem(), &json_args(&link)),
    );
    section(
        &mut snap,
        "no terminal text",
        &with_pem_file().opv(&args(&pem)),
    );
    section(
        &mut snap,
        "no terminal --json",
        &with_pem_file().opv(&json_args(&pem)),
    );
    section(
        &mut snap,
        "agent mode text",
        &with_pem_file().var("OPV_AGENT", "1").opv(&args(&pem)),
    );
    section(
        &mut snap,
        "agent mode --json",
        &with_pem_file().var("OPV_AGENT", "1").opv(&json_args(&pem)),
    );
    snap
}

#[cfg(unix)]
#[test]
fn the_set_from_file_scenarios_match_their_snapshot() {
    let got = transcript();
    let path = scenario_snapshots().join(format!("{}.snap", SNAPSHOTS[0]));
    if updating() {
        std::fs::write(&path, &got).expect("write snapshot");
        return;
    }
    let want = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(
        got,
        want,
        "{} differs from its snapshot; review and rerun with UPDATE_SNAPSHOTS=1",
        path.display()
    );
}
