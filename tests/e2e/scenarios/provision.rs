//! `opv provision` end to end (#253, design `owner-value-ingestion.md` §10.6-§10.7): the
//! real binary, `opv-sim` as `op`, and `opv-e2e-producer` (`tests/sim/producer.rs`) as a
//! consent-shaped producer that speaks `opv.produce/1` from a script in the project.
//!
//! `opv provision` writes only at a person's terminal (§6), and the scenario harness gives
//! opv none: the terminal cases put stdin and stdout on the slave side of a pseudo-terminal
//! (as `set_from_file.rs` does), keep stderr piped, and answer the typed-back confirmation
//! only once its question has arrived on stderr, within a bounded deadline: no sleeps
//! (FMECA mitigation mit-pty-repeat).
//!
//! The app gains two `web` keys and one set, `grant`, in `dev` and `prod` (`confirm_env`):
//! `web/GRANT_TOKEN` made by the producer `consent` (its input `web/API_KEY`, its consent
//! page on `consent.example.test`) and `web/GRANT_SALT` generated. The producer's value is
//! [`CANARY`] and what it writes to stderr holds [`STDERR_CANARY`]; both carry the
//! `test-marker-e2e-` marker, so the general canary gate (`no_scenario_snapshot_holds_a_value`)
//! also covers this module's snapshot (test 66). Each behaviour below is one test with one
//! assertion:
//!
//! - 67: a person provisions the set in production; the vault holds the producer's value,
//!   the receipt names the revision, and the consent page went to the desktop's opener;
//! - 68: a wrong typed environment is `confirm_mismatch` and starts no producer;
//! - 69: without a terminal, `--dry-run --json` is the plan and a write is
//!   `terminal_required`;
//! - 70: `ready` blocks on a partial set, naming `opv provision`;
//! - 61-66: the producer's value never reaches an argv, the environment of anything opv
//!   starts, a file other than the vault, opv's output, the receipt or the snapshot; nor does
//!   the producer's stderr, even when it fails;
//! - `producer_failed` (an exit after a result, an `error` line) and `producer_changed` (an
//!   edited producer file) are reached here for the coverage gate.

use std::io::{Read as _, Write as _};
use std::path::Path;
use std::process::Stdio;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::coverage::{Run, Scenario, scenario_snapshots, updating};

/// The scenario snapshot this module writes (`tests/e2e/snapshots/scenarios/`).
pub(crate) const SNAPSHOTS: &[&str] = &["provision"];

/// The dev account's user (`tests/e2e/app/world.json`).
const DEV_USER: &str = "UE2EDEVUSER000000000000001";
/// The web boundary's vaults and items.
const WEB_DEV_VAULT: &str = "vE2EWEBDEV0000000000000001";
const WEB_PROD_VAULT: &str = "vE2EWEBPROD000000000000001";
const WEB_PROD_ITEM: &str = "iE2EWEBPROD000000000000001";

/// The producer's value: a marker no output, argv, file or snapshot may hold.
const CANARY: &str = "test-marker-e2e-grant-canary-7Q3V9K2M";
/// What the producer writes to its stderr: an unknown format a scrubber would not know.
const STDERR_CANARY: &str =
    "Traceback: token endpoint said {\"refresh\": \"test-marker-e2e-stderr-canary-X4P8\"}\n";
/// The consent page the producer names (a host in `open_url_hosts`).
const CONSENT_URL: &str = "https://consent.example.test/authorize?client=e2e&scope=grant";
/// The confirmation's question (§4.4), awaited on stderr before the answer is typed.
const QUESTION: &str = "Type the environment name to provision grant in it:";
/// How long one terminal run may take before the test fails (never a sleep: the bound of
/// the expect-style waits).
const DEADLINE: Duration = Duration::from_secs(90);

/// The producer's script (`project/producer/consent.json`) for a consent that succeeds.
fn consent_ok() -> Value {
    json!({
        "notices": [{"open_url": CONSENT_URL}, {"waiting": true}],
        "outputs": {"refresh_token": CANARY},
        "record": "producer/seen.json",
    })
}

/// A producer that prints a result, writes [`STDERR_CANARY`] and exits 1: the result is
/// discarded and its stderr never shown (tests 55, 61).
fn consent_exit_after_result() -> Value {
    json!({
        "notices": [{"waiting": true}],
        "outputs": {"refresh_token": CANARY},
        "stderr": STDERR_CANARY,
        "exit": 1,
        "record": "producer/seen.json",
    })
}

/// A producer that reports its own closed error code.
fn consent_denied() -> Value {
    json!({
        "notices": [{"open_url": CONSENT_URL}],
        "error": "consent_denied",
        "stderr": STDERR_CANARY,
        "record": "producer/seen.json",
    })
}

/// The contract's addition: two `web` keys, the producer pinned to its script, the set.
fn contract(sha256: &str) -> String {
    format!(
        r#"
# provision (#253): a consent grant made by a producer, with a generated companion.
[products.web.keys.GRANT_TOKEN]
kind = "secret"
environments = ["dev", "prod"]
guidance = "the consent grant a person makes"

[products.web.keys.GRANT_SALT]
kind = "secret"
environments = ["dev", "prod"]

[producers.consent]
command = ["opv-e2e-producer", "producer/consent.json"]
sha256 = "{sha256}"
outputs = ["refresh_token"]
inputs = {{ client_id = "web/API_KEY" }}
open_url_hosts = ["consent.example.test"]
timeout = "1m"

[sets.grant]
environments = ["dev", "prod"]

[sets.grant.members]
"web/GRANT_TOKEN" = {{ producer = "consent", output = "refresh_token" }}
"web/GRANT_SALT" = {{ generate = {{ hex_bytes = 32 }} }}
"#
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(bytes))
}

/// The app with the `grant` set, the producer's script pinned, the web vaults writable by
/// the dev user, a display and a stub opener for every platform's opener name (it records
/// the URL it was given in `world/opened.log`), so the consent page never reaches a real
/// browser and the run reads the same on every host.
fn grant(script: &Value) -> Scenario {
    let text = format!("{script:#}\n");
    let pin = sha256_hex(text.as_bytes());
    Scenario::new()
        .world(|w| {
            for v in w["op"]["vaults"].as_array_mut().expect("vaults") {
                if v["id"] == WEB_DEV_VAULT || v["id"] == WEB_PROD_VAULT {
                    v["users"] = json!([{"id": DEV_USER, "name": "E2E Dev",
                                         "email": "dev@example.com"}]);
                }
            }
        })
        .file("project/producer/consent.json", &text)
        .config(|c| c + &contract(&pin))
        .var("DISPLAY", ":e2e")
        .after_install(|s| {
            let log = s.path("world/opened.log");
            let stub = format!(
                "#!/bin/sh\nfor a in \"$@\"; do last=$a; done\nprintf '%s\\n' \"$last\" >> '{}'\n",
                log.display()
            );
            for name in ["xdg-open", "open", "rundll32.exe"] {
                let p = s.path(&format!("bin/{name}"));
                std::fs::write(&p, &stub).expect("opener stub");
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755))
                    .expect("chmod");
            }
        })
}

/// [`grant`] with the producer's script edited after the contract pinned it.
fn edited_producer() -> Scenario {
    grant(&consent_ok()).file(
        "project/producer/consent.json",
        &format!("{:#}\n", json!({"outputs": {"refresh_token": "edited"}})),
    )
}

/// [`grant`] with `web/GRANT_SALT` already held in prod and `web/GRANT_TOKEN` not: a
/// partial set.
fn partial() -> Scenario {
    grant(&consent_ok()).world(|w| {
        for item in w["op"]["items"].as_array_mut().expect("items") {
            if item["id"] == WEB_PROD_ITEM {
                item["fields"].as_array_mut().expect("fields").push(json!({
                    "id": "web_grant_salt", "section": {"id": "web", "label": "web"},
                    "label": "GRANT_SALT", "type": "CONCEALED",
                    "value": "test-marker-e2e-prod-web-grant-salt"}));
            }
        }
    })
}

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

/// `opv provision grant --env prod`, with `extra` appended.
fn provision(extra: &[&str]) -> Vec<String> {
    let mut v = args(&["provision", "grant", "--env", "prod"]);
    v.extend(extra.iter().map(|s| s.to_string()));
    v
}

fn document(run: &Run) -> Value {
    serde_json::Deserializer::from_str(&run.stdout)
        .into_iter::<Value>()
        .next()
        .and_then(Result::ok)
        .unwrap_or_else(|| panic!("no document: {}{}", run.stdout, run.stderr))
}

fn read(s: &Scenario, rel: &str) -> String {
    std::fs::read_to_string(s.path(rel)).unwrap_or_default()
}

/// The value the simulated prod web item holds for `label`, if any.
fn stored(s: &Scenario, label: &str) -> Option<String> {
    let w: Value = serde_json::from_str(&read(s, "world/world.json")).expect("world");
    w["op"]["items"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|i| i["id"] == WEB_PROD_ITEM)
        .flat_map(|i| i["fields"].as_array().cloned().unwrap_or_default())
        .find(|f| f["label"] == label)
        .and_then(|f| f["value"].as_str().map(str::to_string))
}

/// What a terminal run's snapshot must not depend on: the time left of the run budget.
fn steady(s: &str) -> String {
    let s = regex::Regex::new(r"of \S+ left")
        .expect("regex")
        .replace_all(s, "of <left> left");
    regex::Regex::new(r#""left_seconds":\d+"#)
        .expect("regex")
        .replace_all(&s, r#""left_seconds":"<left>""#)
        .into_owned()
}

// --- the person's terminal ------------------------------------------------------------------

/// `opv <args>` at a person's terminal: stdin and stdout on the slave side of a
/// pseudo-terminal (echo and `\n` → `\r\n` off, so stdout is what opv wrote), stderr piped.
/// When `answer` is given it is typed only after [`QUESTION`] has arrived on stderr. Every
/// wait is on output or the child, bounded by [`DEADLINE`]; past it the child is killed and
/// the test fails with what it printed.
fn at_a_terminal(s: &Scenario, args: &[String], answer: Option<&str>) -> Run {
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    // SAFETY: openpty writes two new descriptors; the null pointers ask for defaults.
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
    // SAFETY: both descriptors were just opened and are owned here only.
    let master = unsafe { OwnedFd::from_raw_fd(master) };
    let slave = unsafe { OwnedFd::from_raw_fd(slave) };
    // SAFETY: a zeroed termios is valid storage for tcgetattr to fill.
    let mut term = unsafe { std::mem::zeroed::<libc::termios>() };
    // SAFETY: `slave` is an open terminal descriptor; `term` is valid storage.
    assert_eq!(unsafe { libc::tcgetattr(slave.as_raw_fd(), &mut term) }, 0);
    term.c_lflag &= !(libc::ECHO | libc::ECHONL);
    term.c_oflag &= !libc::ONLCR;
    // SAFETY: as above.
    assert_eq!(
        unsafe { libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, &term) },
        0
    );

    let mut cmd = s.command();
    cmd.args(args)
        .stdin(Stdio::from(slave.try_clone().expect("pty stdin")))
        .stdout(Stdio::from(slave.try_clone().expect("pty stdout")))
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn opv at a terminal");
    // The parent holds no slave descriptor, so the master reaches EOF when opv is gone.
    drop(cmd);
    drop(slave);

    let mut keyboard = std::fs::File::from(master);
    let mut screen = keyboard.try_clone().expect("pty master");
    let shown = std::thread::spawn(move || {
        let mut out = Vec::new();
        match screen.read_to_end(&mut out) {
            Ok(_) => {}
            Err(e) if e.raw_os_error() == Some(libc::EIO) => {}
            Err(e) => panic!("read the pty: {e}"),
        }
        out
    });
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let mut stderr = child.stderr.take().expect("stderr");
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = stderr.read(&mut buf) {
            if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });

    let until = Instant::now() + DEADLINE;
    let mut err = Vec::new();
    let mut pending = answer;
    loop {
        let left = until.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(chunk) => err.extend(chunk),
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "opv at a terminal did not finish within {DEADLINE:?}; stderr so far:\n{}",
                    String::from_utf8_lossy(&err)
                );
            }
        }
        if let Some(a) = pending
            && String::from_utf8_lossy(&err).contains(QUESTION)
        {
            keyboard
                .write_all(format!("{a}\n").as_bytes())
                .expect("type the answer");
            pending = None;
        }
    }
    // stderr is closed: opv has exited or is exiting. Its exit is awaited on a thread, so
    // the wait stays bounded by the same deadline.
    let pid = child.id();
    let (done, exited) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = done.send(child.wait());
    });
    let status = match exited.recv_timeout(until.saturating_duration_since(Instant::now())) {
        Ok(st) => st.expect("wait opv"),
        Err(_) => {
            // SAFETY: sends a signal to the child this test started.
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
            panic!("opv closed stderr but did not exit within {DEADLINE:?}");
        }
    };
    drop(keyboard);
    let out = shown.join().expect("pty reader");
    assert!(
        pending.is_none(),
        "opv never asked {QUESTION:?}: {}",
        String::from_utf8_lossy(&err)
    );
    Run {
        code: status.code(),
        stdout: steady(&s.normalize(&String::from_utf8_lossy(&out).replace("\r\n", "\n"))),
        stderr: steady(&s.normalize(&String::from_utf8_lossy(&err))),
    }
}

/// Every regular file under the scenario root that holds `needle`, except the vault itself
/// (`world/world.json`, where the value belongs) and the producer's own script (the issuer
/// in this world: it held the value before opv did, design §9.2).
fn files_holding(s: &Scenario, needle: &str) -> Vec<String> {
    fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let t = e.file_type().expect("file type");
            if t.is_dir() {
                walk(&e.path(), out);
            } else if t.is_file() {
                out.push(e.path());
            }
        }
    }
    let root = s.path("world").parent().expect("root").to_path_buf();
    let mut files = Vec::new();
    walk(&root, &mut files);
    files
        .into_iter()
        .filter(|p| {
            *p != s.path("world/world.json") && *p != s.path("project/producer/consent.json")
        })
        .filter(|p| {
            std::fs::read(p)
                .map(|b| String::from_utf8_lossy(&b).contains(needle))
                .unwrap_or(false)
        })
        .map(|p| p.display().to_string())
        .collect()
}

// --- 67-70: the behaviours ------------------------------------------------------------------

/// 67: a person provisions the set in production: the vault holds the producer's value.
#[test]
fn a_person_provisions_the_grant_set_in_production() {
    let s = grant(&consent_ok());
    let run = at_a_terminal(&s, &provision(&[]), Some("prod"));
    assert_eq!(
        stored(&s, "GRANT_TOKEN").as_deref(),
        Some(CANARY),
        "{}{}",
        run.stdout,
        run.stderr
    );
}

/// 67: the receipt names the revision the write made and verified.
#[test]
fn the_receipt_names_the_verified_revision() {
    let s = grant(&consent_ok());
    let doc = document(&at_a_terminal(&s, &provision(&["--json"]), Some("prod")));
    assert_eq!(
        (
            doc["result"].clone(),
            doc["item"]["verified_at"] == doc["item"]["version_after"]
                && doc["item"]["version_after"].is_u64()
        ),
        (json!("written"), true),
        "{doc}"
    );
}

/// 67: the producer's consent page is opened by opv with the desktop's opener.
#[test]
fn the_consent_page_goes_to_the_opener() {
    let s = grant(&consent_ok());
    at_a_terminal(&s, &provision(&[]), Some("prod"));
    assert_eq!(read(&s, "world/opened.log"), format!("{CONSENT_URL}\n"));
}

/// 68: a wrong typed environment is `confirm_mismatch`, and no producer starts.
#[test]
fn a_wrong_typed_environment_starts_no_producer() {
    let s = grant(&consent_ok());
    let doc = document(&at_a_terminal(&s, &provision(&["--json"]), Some("dev")));
    assert_eq!(
        (
            doc["error"]["code"].clone(),
            s.path("project/producer/seen.json").exists()
        ),
        (json!("confirm_mismatch"), false),
        "{doc}"
    );
}

/// 69: without a terminal, `--dry-run --json` is the plan, and nothing is written.
#[test]
fn a_dry_run_without_a_terminal_is_the_plan() {
    let s = grant(&consent_ok());
    let doc = document(&s.opv(&provision(&["--dry-run", "--json"])));
    assert_eq!(
        (doc["result"].clone(), doc["plan"]["state"].clone()),
        (json!("dry_run"), json!("absent")),
        "{doc}"
    );
}

/// 69: without a terminal, the write is `terminal_required`.
#[test]
fn a_write_without_a_terminal_is_terminal_required() {
    let run = grant(&consent_ok()).opv(&provision(&["--json"]));
    assert_eq!(
        (document(&run)["error"]["code"].clone(), run.code),
        (json!("terminal_required"), Some(6)),
        "{}{}",
        run.stdout,
        run.stderr
    );
}

/// 70: `ready` blocks on a partial set and names the command that makes it.
#[test]
fn ready_names_provision_for_a_partial_set() {
    let run = partial().opv(&args(&["ready", "prod", "--json"]));
    assert!(
        run.stdout.contains("opv provision grant --env prod"),
        "{}{}",
        run.stdout,
        run.stderr
    );
}

/// An edited producer file is `producer_changed` before anything runs.
#[test]
fn an_edited_producer_is_producer_changed() {
    let run = edited_producer().opv(&provision(&["--dry-run", "--json"]));
    assert_eq!(
        document(&run)["error"]["code"],
        "producer_changed",
        "{}{}",
        run.stdout,
        run.stderr
    );
}

/// A producer exit after its result discards the result: nothing is written.
#[test]
fn an_exit_after_the_result_writes_nothing() {
    let s = grant(&consent_exit_after_result());
    let run = at_a_terminal(&s, &provision(&["--json"]), Some("prod"));
    assert_eq!(
        (
            document(&run)["error"]["code"].clone(),
            stored(&s, "GRANT_TOKEN")
        ),
        (json!("producer_failed"), None),
        "{}{}",
        run.stdout,
        run.stderr
    );
}

// --- 61-66: custody canaries ----------------------------------------------------------------

/// 61: a producer's stderr in an unknown format, then exit 1, reaches no output.
#[test]
fn producer_stderr_reaches_no_output_when_it_fails() {
    let s = grant(&consent_exit_after_result());
    let text = at_a_terminal(&s, &provision(&[]), Some("prod"));
    let json = at_a_terminal(
        &grant(&consent_exit_after_result()),
        &provision(&["--json"]),
        Some("prod"),
    );
    let all = format!(
        "{}{}{}{}",
        text.stdout, text.stderr, json.stdout, json.stderr
    );
    assert!(
        !all.contains("stderr-canary") && !all.contains(CANARY),
        "{all}"
    );
}

/// 62: the value is in no argv: not opv's calls (`calls.log`), not the producer's, not the
/// opener's; and in no environment opv gave the producer.
#[test]
fn the_value_is_in_no_argv_or_environment() {
    let s = grant(&consent_ok());
    at_a_terminal(&s, &provision(&[]), Some("prod"));
    let seen = read(&s, "project/producer/seen.json");
    let argv_and_env = format!(
        "{}{seen}{}",
        read(&s, "world/calls.log"),
        read(&s, "world/opened.log")
    );
    assert!(
        !seen.is_empty() && !argv_and_env.contains(CANARY),
        "{argv_and_env}"
    );
}

/// 63: on success, the value is on neither of opv's streams.
#[test]
fn the_value_is_not_on_stdout_or_stderr() {
    let run = at_a_terminal(&grant(&consent_ok()), &provision(&[]), Some("prod"));
    let all = format!("{}{}", run.stdout, run.stderr);
    assert!(
        all.contains("provisioned") && !all.contains(CANARY),
        "{all}"
    );
}

/// 64: the `--json` receipt holds no value.
#[test]
fn the_receipt_holds_no_value() {
    let run = at_a_terminal(&grant(&consent_ok()), &provision(&["--json"]), Some("prod"));
    let doc = document(&run).to_string();
    assert!(!doc.contains(CANARY), "{doc}");
}

/// 65: after the run, no file under the scratch `HOME`, the project or the simulator's
/// bookkeeping holds the value; only the vault does.
#[test]
fn no_file_but_the_vault_holds_the_value() {
    let s = grant(&consent_ok());
    let run = at_a_terminal(&s, &provision(&[]), Some("prod"));
    assert_eq!(
        (
            stored(&s, "GRANT_TOKEN").as_deref(),
            files_holding(&s, CANARY)
        ),
        (Some(CANARY), Vec::<String>::new()),
        "{}{}",
        run.stdout,
        run.stderr
    );
}

/// 66: the committed snapshot holds neither canary.
#[test]
fn the_snapshot_holds_no_value() {
    let snap = std::fs::read_to_string(scenario_snapshots().join("provision.snap"))
        .expect("provision snapshot");
    assert!(
        !snap.contains(CANARY) && !snap.contains("stderr-canary"),
        "provision.snap holds a canary"
    );
}

// --- the snapshot ---------------------------------------------------------------------------

/// One run as snapshot sections; headings end in `text`/`--json`, so the coverage gates read
/// the JSON runs' error documents.
fn section(snap: &mut String, label: &str, run: &Run) {
    snap.push_str(&format!(
        "\n## {label} exit: {}\n## {label} stdout\n{}\n## {label} stderr\n{}",
        run.code.map_or("killed".into(), |c| c.to_string()),
        steady(&run.stdout),
        steady(&run.stderr),
    ));
}

/// A terminal case: its label, the producer's script and the typed answer.
type TerminalCase = (&'static str, fn() -> Value, &'static str);
/// A case without a terminal: its label, its world and its arguments.
type PlainCase = (&'static str, fn() -> Scenario, Vec<String>);

/// Each case's telling runs, text and `--json`, each on a fresh world.
fn transcript() -> String {
    let mut snap = String::from("# provision: `opv provision` through the real binary\n");
    let terminal: [TerminalCase; 4] = [
        ("written", consent_ok, "prod"),
        ("wrong environment", consent_ok, "dev"),
        ("exit after result", consent_exit_after_result, "prod"),
        ("producer error", consent_denied, "prod"),
    ];
    for (label, script, answer) in terminal {
        section(
            &mut snap,
            &format!("{label} text"),
            &at_a_terminal(&grant(&script()), &provision(&[]), Some(answer)),
        );
        section(
            &mut snap,
            &format!("{label} --json"),
            &at_a_terminal(&grant(&script()), &provision(&["--json"]), Some(answer)),
        );
    }
    let plain: [PlainCase; 4] = [
        (
            "dry run",
            || grant(&consent_ok()),
            provision(&["--dry-run"]),
        ),
        ("no terminal", || grant(&consent_ok()), provision(&[])),
        (
            "edited producer",
            edited_producer,
            provision(&["--dry-run"]),
        ),
        ("partial ready", partial, args(&["ready", "prod"])),
    ];
    for (label, scenario, a) in plain {
        section(&mut snap, &format!("{label} text"), &scenario().opv(&a));
        let mut j = a.clone();
        j.push("--json".into());
        section(&mut snap, &format!("{label} --json"), &scenario().opv(&j));
    }
    snap
}

#[test]
fn the_provision_scenarios_match_their_snapshot() {
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
