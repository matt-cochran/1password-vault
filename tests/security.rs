//! Security and failure-mode tests (S7; SR-1..SR-4, FR-10, Review Focus 4).
//!
//! Every test runs the real `opv` binary against fake `op` and `flyctl` executables:
//! small `#!/bin/sh` scripts in a temp `bin` dir that is the ONLY entry on `PATH` (so the
//! real tools can never run; `cat` is symlinked in for the fakes). Each fake records its
//! argv (one arg per line), stdin and exported environment into a separate record dir,
//! always writes a stderr canary that must never reach opv's output, and prints
//! fixture JSON or fails as the scenario's env vars say. The item JSON has the real
//! `op item get` shape (D0) and carries obviously fake marker values that all contain
//! `S7MARKER`, so one substring check finds any of them anywhere.
//!
//! Unix only (ruling P8): the fakes are shell scripts.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use serde_json::{Value, json};
use tempfile::TempDir;

const CONFIG: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/secrets.toml");

/// Every marker contains this, so absence of `MARK` proves absence of every value.
const MARK: &str = "S7MARKER";
/// Written to stderr by every fake on every call (alongside a value marker).
const CHILD_STDERR: &str = "S7CHILDSTDERR";

const OPENAI: &str = "sk-proj-S7MARKERVALUEopenai0001";
/// 43 base64 chars + `=`: decodes to exactly 32 bytes (rule `base64_bytes = 32`).
const ENC: &str = "S7MARKERVALUEencS7MARKERVALUEencS7MARKERVAA=";
/// Prod has payments mode `off`, so this key is skipped: never staged, never shown.
const STRIPE: &str = "sk_live_S7MARKERVALUEstripe0003";
/// Undeclared typo field (`OPENAI_API_KEYS`): an extra, never staged.
const EXTRA: &str = "sk-proj-S7MARKERVALUEextra0004";
/// Value of the built-in notes field outside any section.
const NOTES: &str = "S7MARKERVALUEnotes0005";

const APP: &str = "mcproductlabs-portfolio-production";
const N_OPENAI: &str = "FLEET__ALLUMATA__OPENAI_API_KEY";
const N_ENC: &str = "FLEET__ALLUMATA__INTEGRATION_ENC_KEY";
const N_STRIPE: &str = "FLEET__ALLUMATA__STRIPE_SECRET_KEY";

const FAKE_OP: &str = r#"#!/bin/sh
n=0
[ -f "$FAKE_REC/.seq" ] && read n < "$FAKE_REC/.seq"
n=$((n + 1))
echo "$n" > "$FAKE_REC/.seq"
p="$FAKE_REC/$(printf '%04d' "$n")-op"
for a in "$@"; do printf '%s\n' "$a"; done > "$p.argv"
cat > "$p.stdin"
export -p > "$p.env"
if [ "$1" = "run" ]; then
  # `opv run` inherits stdio by design (FR-4): no canary, and do not exec.
  exit "${FAKE_OP_RUN_EXIT:-0}"
fi
printf '%s %s\n' "$FAKE_CHILD_STDERR" "$FAKE_STDERR_VALUE" >&2
case "$1" in
  --version) echo "2.30.0"; exit 0 ;;
  whoami)
    e="${FAKE_OP_WHOAMI_EXIT:-$FAKE_OP_EXIT}"
    [ -n "$e" ] && exit "$e"
    printf '{"email":"S7MARKERVALUEwho@example.invalid","user_type":"SERVICE_ACCOUNT"}\n'; exit 0 ;;
  account)
    if [ -n "$FAKE_OP_NO_ACCOUNTS" ]; then printf '[]\n'
    else printf '[{"url":"S7MARKERVALUE.example.invalid","email":"S7MARKERVALUE@example.invalid"}]\n'; fi
    exit 0 ;;
  item)
    e="${FAKE_OP_ITEM_EXIT:-$FAKE_OP_EXIT}"
    [ -n "$e" ] && exit "$e"
    cat "$FAKE_FIX/item.json"; exit 0 ;;
  vault)
    # NR-26 probe: its output names the vault and must never be echoed.
    [ -n "$FAKE_OP_VAULT_EXIT" ] && exit "$FAKE_OP_VAULT_EXIT"
    printf '{"id":"vprd","name":"S7MARKERVALUEvault"}\n'; exit 0 ;;
esac
exit 97
"#;

const FAKE_FLYCTL: &str = r#"#!/bin/sh
n=0
[ -f "$FAKE_REC/.seq" ] && read n < "$FAKE_REC/.seq"
n=$((n + 1))
echo "$n" > "$FAKE_REC/.seq"
p="$FAKE_REC/$(printf '%04d' "$n")-flyctl"
for a in "$@"; do printf '%s\n' "$a"; done > "$p.argv"
cat > "$p.stdin"
export -p > "$p.env"
printf '%s %s\n' "$FAKE_CHILD_STDERR" "$FAKE_STDERR_VALUE" >&2
case "$1 $2" in
  "version "*) echo "flyctl v0.4.112 linux/amd64 Commit: fake"; exit 0 ;;
  "auth whoami") echo "S7MARKERVALUEfly@example.invalid"; exit "${FAKE_FLY_AUTH_EXIT:-0}" ;;
  "secrets list")
    l=0
    [ -f "$FAKE_REC/.lists" ] && read l < "$FAKE_REC/.lists"
    l=$((l + 1))
    echo "$l" > "$FAKE_REC/.lists"
    # From list number FAKE_FLY_LIST_FAIL_AT on, every list fails (a read is retried).
    [ -n "$FAKE_FLY_LIST_FAIL_AT" ] && [ "$l" -ge "$FAKE_FLY_LIST_FAIL_AT" ] && exit 1
    if [ "$l" = 1 ]; then cat "$FAKE_FIX/list_a.json"; else cat "$FAKE_FIX/list_b.json"; fi
    exit 0 ;;
  # NR-24 preflight (shapes follow the recorded flyctl output in tests/fixtures/fly/).
  "status --app") printf '{"ID":"app","Status":"deployed","Machines":[{"id":"m1","state":"started"}]}\n'; exit 0 ;;
  "releases --app") printf '[{"Version":1,"Status":"complete","User":{"Email":"S7MARKERVALUE@example.invalid"}}]\n'; exit 0 ;;
  "secrets import")
    [ -n "$FAKE_FLY_IMPORT_SLEEP" ] && /bin/sleep "$FAKE_FLY_IMPORT_SLEEP"
    exit "${FAKE_FLY_IMPORT_EXIT:-0}" ;;
  "secrets unset") exit 0 ;;
  "secrets deploy") exit 0 ;;
esac
exit 97
"#;

// ------------------------------------------------------------------------- fixtures

fn field(section: Option<&str>, label: &str, ty: &str, value: Option<&str>) -> Value {
    let mut f = json!({
        "id": format!("{}_{}", section.unwrap_or("x"), label.to_lowercase()),
        "type": ty,
        "label": label,
        "reference": "op://<vault-id>/<item-id>/<field-ref>",
    });
    if let Some(s) = section {
        f["section"] = json!({"id": s, "label": s});
    }
    if let Some(v) = value {
        f["value"] = json!(v);
    }
    f
}

/// A fleet item in the real `op item get --format json` shape (D0 `op_item.json`).
fn item(fields: Vec<Value>) -> String {
    json!({
        "id": "iprd",
        "title": "fleet",
        "version": 7,
        "vault": {"id": "vprd", "name": "fleet-prod"},
        "category": "SECURE_NOTE",
        "last_edited_by": "<user-id>",
        "created_at": "2026-10-07T03:53:02Z",
        "updated_at": "2026-10-07T07:02:46Z",
        "sections": [{"id": "allumata", "label": "allumata"}],
        "fields": fields,
    })
    .to_string()
}

/// Every declared prod key present and rule-valid, plus a skipped Stripe key, an extra
/// typo field and a notes value: all secret values are markers.
fn good_fields(openai: &str) -> Vec<Value> {
    let a = Some("allumata");
    vec![
        field(None, "notesPlain", "STRING", Some(NOTES)),
        field(a, "OPENAI_API_KEY", "CONCEALED", Some(openai)),
        field(a, "INTEGRATION_ENC_KEY", "CONCEALED", Some(ENC)),
        field(a, "STRIPE_SECRET_KEY", "CONCEALED", Some(STRIPE)),
        field(a, "SIGNUP_POLICY", "STRING", Some("invite_only")),
        field(a, "OPENAI_API_KEYS", "CONCEALED", Some(EXTRA)),
    ]
}

fn good_item() -> String {
    item(good_fields(OPENAI))
}

/// List A: the skipped Stripe key is on Fly (a prune candidate) plus an unmanaged secret.
fn list_a() -> String {
    json!([
        {"name": N_STRIPE, "digest": "d-stripe", "status": "Deployed"},
        {"name": "UNMANAGED_OTHER", "digest": "d-other", "status": "Deployed"},
    ])
    .to_string()
}

/// List B (after import): both staged keys have new digests.
fn list_b() -> String {
    json!([
        {"name": N_STRIPE, "digest": "d-stripe", "status": "Deployed"},
        {"name": "UNMANAGED_OTHER", "digest": "d-other", "status": "Deployed"},
        {"name": N_OPENAI, "digest": "d-openai-new", "status": "Staged"},
        {"name": N_ENC, "digest": "d-enc-new", "status": "Staged"},
    ])
    .to_string()
}

// -------------------------------------------------------------------------- harness

struct Harness {
    _root: TempDir,
    bin: PathBuf,
    rec: PathBuf,
    fix: PathBuf,
    /// Empty dirs used as TMPDIR and CWD of every run (see `no_files_written`).
    tmp: PathBuf,
    cwd: PathBuf,
    env: Vec<(String, String)>,
    /// The `--config` every run passes; the shared fixture unless replaced.
    config: PathBuf,
}

#[derive(Debug)]
struct Call {
    prog: String,
    argv: Vec<String>,
    stdin: String,
    env: String,
}

struct Run {
    code: i32,
    stdout: String,
    /// stderr without the runner's retry notices (NR-3), which are in `retries`.
    stderr: String,
    retries: Vec<String>,
}

impl Run {
    fn all(&self) -> String {
        format!("{}\n{}", self.stdout, self.stderr)
    }
}

fn write_exe(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// The fake `op` and `flyctl`, written once per test binary and closed before any of its
/// tests spawns a process; harnesses only symlink them.
///
/// Writing an executable while another thread forks lets the child inherit the open write
/// fd, and an exec of that file then fails with ETXTBSY ("text file busy"), which opv
/// correctly reports as a dependency error (exit 3): a flaky test, not a bug. The fakes
/// read everything per-test from env vars (`FAKE_REC`, `FAKE_FIX`, ...), so one copy
/// serves every harness. [`Harness::build`], which every spawn goes through, forces this.
fn fakes() -> &'static Path {
    static FAKES: OnceLock<TempDir> = OnceLock::new();
    FAKES
        .get_or_init(|| {
            let dir = TempDir::new().unwrap();
            write_exe(&dir.path().join("op"), FAKE_OP);
            write_exe(&dir.path().join("flyctl"), FAKE_FLYCTL);
            dir
        })
        .path()
}

impl Harness {
    fn new(item_json: &str) -> Self {
        Self::build(item_json, true, true)
    }

    fn build(item_json: &str, with_op: bool, with_flyctl: bool) -> Self {
        let fakes = fakes();
        let root = TempDir::new().unwrap();
        let mk = |n: &str| {
            let p = root.path().join(n);
            fs::create_dir(&p).unwrap();
            p
        };
        let (bin, rec, fix, tmp, cwd) = (mk("bin"), mk("rec"), mk("fix"), mk("tmp"), mk("cwd"));
        let cat = ["/bin/cat", "/usr/bin/cat"]
            .into_iter()
            .find(|p| Path::new(p).exists())
            .expect("cat");
        std::os::unix::fs::symlink(cat, bin.join("cat")).unwrap();
        if with_op {
            std::os::unix::fs::symlink(fakes.join("op"), bin.join("op")).unwrap();
        }
        if with_flyctl {
            std::os::unix::fs::symlink(fakes.join("flyctl"), bin.join("flyctl")).unwrap();
        }
        fs::write(fix.join("item.json"), item_json).unwrap();
        fs::write(fix.join("list_a.json"), list_a()).unwrap();
        fs::write(fix.join("list_b.json"), list_b()).unwrap();
        let env = vec![
            // Ruling 3: with credentials present an op failure is a Source error.
            (
                "OP_SERVICE_ACCOUNT_TOKEN".into(),
                "dummy-not-a-token".into(),
            ),
            ("FAKE_CHILD_STDERR".into(), CHILD_STDERR.into()),
            ("FAKE_STDERR_VALUE".into(), OPENAI.into()),
        ];
        Harness {
            _root: root,
            bin,
            rec,
            fix,
            tmp,
            cwd,
            env,
            config: PathBuf::from(CONFIG),
        }
    }

    /// Run every later command against `toml` instead of the shared fixture.
    fn use_config(&mut self, toml: &str) -> &mut Self {
        let p = self.fix.join("secrets.toml");
        fs::write(&p, toml).unwrap();
        self.config = p;
        self
    }

    fn set(&mut self, k: &str, v: &str) -> &mut Self {
        self.env.retain(|(n, _)| n != k);
        self.env.push((k.into(), v.into()));
        self
    }

    fn unset(&mut self, k: &str) -> &mut Self {
        self.env.retain(|(n, _)| n != k);
        self
    }

    fn set_item(&self, json: &str) {
        fs::write(self.fix.join("item.json"), json).unwrap();
    }

    /// Forget recorded calls (and the fakes' counters) between runs.
    fn reset(&self) {
        for e in fs::read_dir(&self.rec).unwrap() {
            fs::remove_file(e.unwrap().path()).unwrap();
        }
    }

    fn run(&self, args: &[&str]) -> Run {
        self.run_config(&self.config, args)
    }

    fn run_config(&self, config: impl AsRef<std::ffi::OsStr>, args: &[&str]) -> Run {
        let out = Command::new(env!("CARGO_BIN_EXE_opv"))
            .env_remove("GITHUB_STEP_SUMMARY") // never the job summary of the run testing opv
            .arg("--config")
            .arg(config.as_ref())
            .args(args)
            .env_clear()
            .env("PATH", &self.bin)
            .env("TMPDIR", &self.tmp)
            // Test builds only: retries (NR-3) without waiting out the backoff.
            .env("OPV_TEST_BACKOFF_SCALE", "0")
            .env("FAKE_REC", &self.rec)
            .env("FAKE_FIX", &self.fix)
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .current_dir(&self.cwd)
            .output()
            .unwrap();
        let all_err = String::from_utf8(out.stderr).unwrap();
        let (retries, rest): (Vec<&str>, Vec<&str>) = all_err
            .split_inclusive('\n')
            .partition(|l| l.starts_with("retrying "));
        Run {
            code: out.status.code().expect("exited normally"),
            stdout: String::from_utf8(out.stdout).unwrap(),
            stderr: rest.concat(),
            retries: retries.iter().map(|l| l.trim_end().to_string()).collect(),
        }
    }

    fn calls(&self) -> Vec<Call> {
        let mut stems: Vec<String> = fs::read_dir(&self.rec)
            .unwrap()
            .filter_map(|e| {
                let name = e.unwrap().file_name().into_string().unwrap();
                name.strip_suffix(".argv").map(str::to_owned)
            })
            .collect();
        stems.sort();
        stems
            .into_iter()
            .map(|s| {
                let read = |ext: &str| fs::read_to_string(self.rec.join(format!("{s}.{ext}")));
                Call {
                    prog: s.split_once('-').unwrap().1.to_string(),
                    argv: read("argv").unwrap().lines().map(str::to_owned).collect(),
                    stdin: read("stdin").unwrap(),
                    env: read("env").unwrap(),
                }
            })
            .collect()
    }

    fn fly_calls(&self, sub: &str) -> usize {
        self.calls()
            .iter()
            .filter(|c| c.prog == "flyctl" && c.argv.get(1).map(String::as_str) == Some(sub))
            .count()
    }
}

/// Every command that talks to a fake, with a label. `run` is listed separately because
/// it inherits stdio by design (FR-4).
const COMMANDS: &[&[&str]] = &[
    &["doctor"],
    &["status", "prod"],
    &["plan", "prod"],
    &["sync", "prod"],
    &["sync", "prod", "--prune", "--deploy"],
    &["config", "export", "prod", "--json"],
    &["item", "skeleton", "prod"],
];

fn assert_no_marker(what: &str, text: &str) {
    for m in [MARK, CHILD_STDERR] {
        assert!(!text.contains(m), "{what} contains {m}:\n{text}");
    }
}

/// True for a line of a failed call's scrubbed stderr excerpt (NR-31).
fn is_excerpt_line(l: &str) -> bool {
    ["  op said: ", "  flyctl said: ", "  az said: "]
        .iter()
        .any(|p| l.starts_with(p))
}

/// No value anywhere. Child stderr (the canary) only on stderr, and only in the labelled,
/// scrubbed excerpt of a failed call (NR-31); stdout never carries child output.
fn assert_clean_output(cmd: &[&str], r: &Run) {
    assert_no_marker(&format!("{cmd:?} stdout"), &r.stdout);
    assert!(
        !r.stderr.contains(MARK),
        "{cmd:?} stderr contains {MARK}:\n{}",
        r.stderr
    );
    for l in r.stderr.lines().filter(|l| l.contains(CHILD_STDERR)) {
        assert!(
            is_excerpt_line(l),
            "{cmd:?} child stderr outside an excerpt: {l}"
        );
    }
}

fn assert_argv_and_env_clean(h: &Harness) {
    let calls = h.calls();
    assert!(!calls.is_empty());
    for c in &calls {
        for a in &c.argv {
            assert!(!a.contains(MARK), "value in argv of {c:?}");
        }
        // The harness's own FAKE_* control vars (one carries the stderr value) excluded.
        let env = c.env.lines().filter(|l| !l.contains(" FAKE_"));
        for l in env {
            assert!(
                !l.contains(MARK),
                "value in env of {} {:?}: {l}",
                c.prog,
                c.argv
            );
        }
    }
}

// ---------------------------------------------------------------------------- tests

/// SR-3: a full `fly sync --prune --deploy` (op read, list, import, list, unset, deploy)
/// puts no value in any child's argv (or environment).
#[test]
fn no_secret_in_any_argv() {
    let h = Harness::new(&good_item());
    let r = h.run(&["sync", "prod", "--prune", "--deploy"]);
    assert_eq!(r.code, 0, "{}", r.all());

    let calls = h.calls();
    let argv: Vec<(&str, Vec<&str>)> = calls
        .iter()
        .map(|c| (c.prog.as_str(), c.argv.iter().map(String::as_str).collect()))
        .collect();
    assert_eq!(
        argv,
        vec![
            (
                "op",
                vec!["item", "get", "iprd", "--vault", "vprd", "--format", "json"]
            ),
            ("flyctl", vec!["secrets", "list", "--app", APP, "--json"]),
            ("flyctl", vec!["status", "--app", APP, "--json"]),
            ("flyctl", vec!["releases", "--app", APP, "--json"]),
            ("flyctl", vec!["secrets", "import", "--app", APP, "--stage"]),
            ("flyctl", vec!["secrets", "list", "--app", APP, "--json"]),
            (
                "flyctl",
                vec!["secrets", "unset", N_STRIPE, "--app", APP, "--stage"]
            ),
            ("flyctl", vec!["secrets", "deploy", "--app", APP]),
        ],
        "{}",
        r.all()
    );
    assert_argv_and_env_clean(&h);

    // Same for every other command, and for `run` (env carries op:// refs, not values).
    for cmd in
        COMMANDS
            .iter()
            .copied()
            .chain([&["run", "prod", "--product", "allumata", "--", "true"][..]])
    {
        h.reset();
        h.run(cmd);
        assert_argv_and_env_clean(&h);
    }
    // `run` reads the item first (FR-43); the env is on the `op run` call.
    let calls = h.calls();
    let run_env = &calls
        .iter()
        .find(|c| c.argv.first().is_some_and(|a| a == "run"))
        .expect("op run")
        .env;
    assert!(
        run_env.contains("op://vprd/iprd/allumata/OPENAI_API_KEY"),
        "{run_env}"
    );
}

/// SR-3: the import stdin is the one channel that carries values; it carries exactly the
/// staged ones, and every argv file and opv's own output lack them.
#[test]
fn stdin_only_channel() {
    let h = Harness::new(&good_item());
    let r = h.run(&["sync", "prod"]);
    assert_eq!(r.code, 0, "{}", r.all());
    assert_clean_output(&["sync", "prod"], &r);

    let calls = h.calls();
    let import: Vec<&Call> = calls
        .iter()
        .filter(|c| c.argv.get(1).map(String::as_str) == Some("import"))
        .collect();
    assert_eq!(import.len(), 1, "{calls:?}");
    let mut lines: Vec<&str> = import[0].stdin.lines().collect();
    lines.sort_unstable();
    let enc = format!("{N_ENC}=\"\"\"{ENC}\"\"\"");
    let openai = format!("{N_OPENAI}=\"\"\"{OPENAI}\"\"\"");
    assert_eq!(
        lines,
        [enc.as_str(), openai.as_str()],
        "exactly the staged lines"
    );
    assert!(import[0].stdin.ends_with('\n'));
    for v in [OPENAI, ENC] {
        assert!(import[0].stdin.contains(v), "{v} not on import stdin");
    }
    for v in [STRIPE, EXTRA, NOTES] {
        assert!(!import[0].stdin.contains(v), "unstaged value on stdin");
    }
    // No other call received any value on stdin, argv or env.
    for c in &calls {
        if !std::ptr::eq(c, import[0]) {
            assert!(!c.stdin.contains(MARK), "value on stdin of {c:?}");
        }
    }
    assert_argv_and_env_clean(&h);
}

/// SR-1: no value reaches opv's stdout or stderr for any command, success or
/// failure (forced rule failures included).
#[test]
fn no_secret_in_stdout_or_stderr() {
    let h = Harness::new(&good_item());
    for cmd in COMMANDS {
        h.reset();
        let r = h.run(cmd);
        assert!(
            [0, 8].contains(&r.code),
            "{cmd:?} exit {}: {}",
            r.code,
            r.all()
        );
        assert_clean_output(cmd, &r);
    }
    // Forced rule failure: wrong prefix on a secret.
    h.set_item(&item(good_fields("pk-S7MARKERVALUEbadprefix0006")));
    for cmd in COMMANDS {
        h.reset();
        let r = h.run(cmd);
        assert_clean_output(cmd, &r);
    }
}

/// Carried from S1-M5, amended by NR-31: every fake writes a canary plus a value to stderr
/// on every call. A successful command shows none of it.
#[test]
fn successful_commands_drop_child_stderr() {
    let h = Harness::new(&good_item());
    for cmd in COMMANDS {
        h.reset();
        let r = h.run(cmd);
        assert!(!h.calls().is_empty(), "{cmd:?} spawned nothing");
        assert_no_marker(&format!("{cmd:?}"), &r.all());
    }
}

/// NR-31: failing children (op fails, then flyctl list fails) show their stderr only as
/// the labelled excerpt, with the value scrubbed.
#[test]
fn failing_commands_show_only_scrubbed_child_stderr() {
    let mut h = Harness::new(&good_item());
    h.set("FAKE_OP_EXIT", "1");
    for cmd in COMMANDS {
        h.reset();
        assert_clean_output(cmd, &h.run(cmd));
    }
    h.unset("FAKE_OP_EXIT").set("FAKE_FLY_LIST_FAIL_AT", "1");
    for cmd in COMMANDS {
        h.reset();
        assert_clean_output(cmd, &h.run(cmd));
    }
}

/// Brief: fake `op` prints a value to stderr and the item read exits 1 while signed in →
/// Source (4), value not echoed. FR-26: names the IDs and the identity type (never the
/// identity) and says to grant access; never "to see why".
#[test]
fn child_stderr_suppressed() {
    let mut h = Harness::new(&good_item());
    h.set("FAKE_OP_ITEM_EXIT", "1");
    for cmd in [
        &["status", "prod"][..],
        &["plan", "prod"],
        &["sync", "prod"],
        &["config", "export", "prod", "--json"],
        &["item", "skeleton", "prod"],
    ] {
        h.reset();
        let r = h.run(cmd);
        assert_eq!(r.code, 4, "{cmd:?}: {}", r.all());
        assert!(
            // P16: a retry note may come first (signed in, vault readable).
            r.stderr
                .lines()
                .any(|l| l.starts_with("opv: source error: op item get failed (exit 1)")),
            "{cmd:?}: {}",
            r.stderr
        );
        for want in [
            "signed in to 1Password as SERVICE_ACCOUNT",
            "item iprd not found in vault vprd",
            "op item get iprd --vault vprd",
        ] {
            assert!(r.stderr.contains(want), "{cmd:?}: {want}: {}", r.stderr);
        }
        assert!(!r.stderr.contains("to see why"), "{}", r.stderr);
        assert!(!r.stderr.contains("example.invalid"), "{}", r.stderr);
        assert_clean_output(cmd, &r);
        assert_eq!(h.fly_calls("import"), 0);
    }
}

/// Ruling 3 (S3's rule): with no OP_SERVICE_ACCOUNT_TOKEN / OP_SESSION_* an op failure is
/// an authentication error (7, its own code since the final fix wave), not a source error.
#[test]
fn op_failure_without_credentials_is_auth() {
    let mut h = Harness::new(&good_item());
    h.unset("OP_SERVICE_ACCOUNT_TOKEN").set("FAKE_OP_EXIT", "1");
    for cmd in [&["status", "prod"][..], &["sync", "prod"], &["doctor"]] {
        h.reset();
        let r = h.run(cmd);
        assert_eq!(r.code, 7, "{cmd:?}: {}", r.all());
        assert!(
            r.all().contains("authentication error"),
            "{cmd:?}: {}",
            r.all()
        );
        assert_clean_output(cmd, &r);
    }
}

/// SR-4: no file is written to TMPDIR or the working directory by any command, on success
/// or failure. (The fakes' record dir is separate and does not count.)
#[test]
fn no_files_written() {
    let mut h = Harness::new(&good_item());
    let empty = |p: &Path| fs::read_dir(p).unwrap().next().is_none();
    let check = |h: &Harness, cmd: &[&str]| {
        h.reset();
        h.run(cmd);
        assert!(empty(&h.tmp), "{cmd:?} wrote to TMPDIR");
        assert!(empty(&h.cwd), "{cmd:?} wrote to CWD");
    };
    for cmd in COMMANDS {
        check(&h, cmd);
    }
    check(&h, &["run", "prod", "--product", "allumata", "--", "true"]);
    // Item with missing fields: skeleton writes (to op stdin, never to disk).
    h.set_item(&item(vec![]));
    for cmd in COMMANDS {
        check(&h, cmd);
    }
    h.set_item(&good_item());
    h.set("FAKE_FLY_LIST_FAIL_AT", "2");
    check(&h, &["sync", "prod", "--prune", "--deploy"]);
    // Skeleton did reach `op item edit` with its template on stdin.
    h.unset("FAKE_FLY_LIST_FAIL_AT");
    h.set_item(&item(vec![]));
    h.reset();
    let r = h.run(&["item", "skeleton", "prod"]);
    assert_eq!(r.code, 0, "{}", r.all());
    assert!(h.calls().iter().any(|c| c.argv[..2] == ["item", "edit"]));
}

/// Review Focus 4: `flyctl secrets list` (A) fails → Target (5) before anything is staged.
#[test]
fn failure_after_partial_plan_stages_nothing() {
    let mut h = Harness::new(&good_item());
    h.set("FAKE_FLY_LIST_FAIL_AT", "1");
    let r = h.run(&["sync", "prod", "--prune", "--deploy"]);
    assert_eq!(r.code, 5, "{}", r.all());
    assert!(
        r.stderr
            .starts_with("opv: target error: fly secrets list failed (exit 1)"),
        "{}",
        r.stderr
    );
    // FR-26: logged in (auth whoami succeeds), so the app is named with the token check;
    // never "to see why" (child stderr is discarded).
    assert!(
        r.stderr.contains(&format!(
            "flyctl failed for app {APP}: check that the logged-in Fly account can access it"
        )),
        "{}",
        r.stderr
    );
    assert!(!r.stderr.contains("to see why"), "{}", r.stderr);
    for sub in ["import", "unset", "deploy"] {
        assert_eq!(h.fly_calls(sub), 0, "{sub} after a failed list");
    }
    assert_clean_output(&["sync"], &r);
}

/// NR-3: a read that keeps failing prints one notice per retry, naming the step only.
#[test]
fn failing_read_prints_retry_notices() {
    let mut h = Harness::new(&good_item());
    h.set("FAKE_FLY_LIST_FAIL_AT", "1");
    let r = h.run(&["status", "prod"]);
    assert_eq!(
        r.retries
            .iter()
            .map(|l| l.split(" in ").next().unwrap_or_default())
            .collect::<Vec<_>>(),
        [
            "retrying flyctl secrets list (2/3)",
            "retrying flyctl secrets list (3/3)"
        ]
    );
}

/// Review Focus 4: list B (after import) fails → Target (5); nothing further is mutated
/// (no unset, no deploy) even with --prune --deploy.
#[test]
fn list_b_failure_after_staging() {
    let mut h = Harness::new(&good_item());
    h.set("FAKE_FLY_LIST_FAIL_AT", "2");
    let r = h.run(&["sync", "prod", "--prune", "--deploy"]);
    assert_eq!(r.code, 5, "{}", r.all());
    assert!(
        r.stderr
            .starts_with("opv: target error: fly secrets list failed (exit 1)"),
        "{}",
        r.stderr
    );
    assert_eq!(h.fly_calls("import"), 1);
    assert_eq!(
        h.fly_calls("list"),
        4,
        "list A, then list B and its two retries"
    );
    assert_eq!(h.fly_calls("unset"), 0, "unset after a failed list B");
    assert_eq!(h.fly_calls("deploy"), 0, "deploy after a failed list B");
    assert_clean_output(&["sync"], &r);
}

/// Review Focus 4 (import itself fails): Target (5), no unset/deploy afterwards.
#[test]
fn import_failure_stops_the_run() {
    let mut h = Harness::new(&good_item());
    h.set("FAKE_FLY_IMPORT_EXIT", "1");
    let r = h.run(&["sync", "prod", "--prune", "--deploy"]);
    assert_eq!(r.code, 5, "{}", r.all());
    assert!(
        r.stderr.contains("fly secrets import failed (exit 1)"),
        "{}",
        r.stderr
    );
    assert_eq!(h.fly_calls("list"), 1);
    assert_eq!(h.fly_calls("unset"), 0);
    assert_eq!(h.fly_calls("deploy"), 0);
    assert_clean_output(&["sync"], &r);
}

/// FR-15 / Review Focus 1: a value failing a rule is named by key and rule, never by
/// value; `fly sync` refuses with Policy (6) and stages nothing; `status` and `fly plan`
/// report Findings (8).
#[test]
fn rule_failure_names_key_not_value() {
    let h = Harness::new(&good_item());
    // A trailing newline alone is normalized, not refused (FR-43): see
    // `trailing_newline_is_read_in_its_intended_form`.
    for (value, rule) in [
        (" sk-proj-S7MARKERVALUEspace0008", "no_surrounding_space"),
        ("pk-S7MARKERVALUEprefix0009", "prefix"),
        ("sk-or-S7MARKERVALUEopenrouter0010", "not_prefix"),
    ] {
        h.set_item(&item(good_fields(value)));
        let named = format!("allumata/OPENAI_API_KEY (failed {rule} (");

        h.reset();
        let r = h.run(&["sync", "prod", "--prune", "--deploy"]);
        assert_eq!(r.code, 6, "{rule}: {}", r.all());
        assert!(
            r.stderr
                .starts_with("opv: policy denied: sync refused, nothing staged"),
            "{rule}: {}",
            r.stderr
        );
        assert!(r.stderr.contains(&named), "{rule}: {}", r.stderr);
        for sub in ["import", "unset", "deploy"] {
            assert_eq!(h.fly_calls(sub), 0, "{rule}: {sub}");
        }
        assert_clean_output(&["sync"], &r);

        for cmd in [&["status", "prod"][..], &["plan", "prod"]] {
            h.reset();
            let r = h.run(cmd);
            assert_eq!(r.code, 8, "{rule} {cmd:?}: {}", r.all());
            assert!(r.stdout.contains("OPENAI_API_KEY"), "{}", r.stdout);
            assert!(
                r.stdout.contains(&format!("failed {rule} (")),
                "{}",
                r.stdout
            );
            assert_clean_output(cmd, &r);
        }
    }
}

/// FR-43: a value whose only problem is a trailing newline is read in its intended form,
/// so sync goes ahead, and opv's output still carries no value.
#[test]
fn trailing_newline_is_read_in_its_intended_form() {
    let h = Harness::new(&item(good_fields("sk-proj-S7MARKERVALUEnewline0007\n")));
    let r = h.run(&["sync", "prod", "--prune", "--deploy"]);
    assert_eq!(r.code, 0, "{}", r.all());
    assert_clean_output(&["sync"], &r);
}

/// Commands that read the item (every `op item get` failure path).
const READERS: &[&[&str]] = &[
    &["status", "prod"],
    &["plan", "prod"],
    &["sync", "prod"],
    &["config", "export", "prod", "--json"],
    &["item", "skeleton", "prod"],
];

/// `op` calls of the last run, as `argv[0] argv[1]`.
fn op_subcommands(h: &Harness) -> Vec<String> {
    h.calls()
        .iter()
        .filter(|c| c.prog == "op")
        .map(|c| c.argv.iter().take(2).cloned().collect::<Vec<_>>().join(" "))
        .collect()
}

/// FR-26 regression (§8 item 25): `OP_SESSION_*` is present but expired, so `op item get`
/// and `op whoami` both fail. Exit 7 with the sign-in command for the shell, never
/// "run op item get ... to see why" and never exit 4. One item read only (FR-13).
#[test]
fn expired_session_is_auth_with_signin_command() {
    let mut h = Harness::new(&good_item());
    h.unset("OP_SERVICE_ACCOUNT_TOKEN")
        .set("OP_SESSION_my_team", "expired-dummy-session")
        .set("SHELL", "/bin/bash")
        .set("FAKE_OP_EXIT", "1");
    for cmd in READERS {
        h.reset();
        let r = h.run(cmd);
        assert_eq!(r.code, 7, "{cmd:?}: {}", r.all());
        assert!(
            r.stderr
                .starts_with("opv: authentication error: not signed in to 1Password"),
            "{cmd:?}: {}",
            r.stderr
        );
        assert!(
            r.stderr.contains("\n  sign in: eval $(op signin)\n"),
            "{}",
            r.stderr
        );
        assert!(!r.stderr.contains("to see why"), "{}", r.stderr);
        assert!(!r.stderr.contains("expired-dummy-session"), "{}", r.stderr);
        assert_clean_output(cmd, &r);
        assert_eq!(
            op_subcommands(&h),
            vec!["item get", "whoami --format", "account list"],
            "{cmd:?}"
        );
        assert_eq!(h.fly_calls("import"), 0);
    }
    // fish users get fish syntax.
    h.set("SHELL", "/usr/bin/fish");
    h.reset();
    let r = h.run(&["status", "prod"]);
    assert_eq!(r.code, 7, "{}", r.all());
    assert!(
        r.stderr.contains("\n  sign in: eval (op signin)\n"),
        "{}",
        r.stderr
    );
    assert!(!r.stderr.contains("$("), "{}", r.stderr);
}

/// FR-26: no account on this machine → `op account add`, then sign in; exit 7.
#[test]
fn no_account_is_auth_with_account_add() {
    let mut h = Harness::new(&good_item());
    h.unset("OP_SERVICE_ACCOUNT_TOKEN")
        .set("SHELL", "/bin/zsh")
        .set("FAKE_OP_EXIT", "1")
        .set("FAKE_OP_NO_ACCOUNTS", "1");
    for cmd in [&["status", "prod"][..], &["doctor"]] {
        h.reset();
        let r = h.run(cmd);
        assert_eq!(r.code, 7, "{cmd:?}: {}", r.all());
        for want in [
            "no 1Password account is set up for op on this machine",
            "\n  add one: op account add --address <sign-in address> --email <email>\n",
            "\n  then sign in: eval $(op signin)\n",
            "type the Secret Key and password only at op's prompts",
        ] {
            assert!(r.all().contains(want), "{cmd:?}: {want}: {}", r.all());
        }
        assert_clean_output(cmd, &r);
    }
}

/// FR-26 under CI: advise OP_SERVICE_ACCOUNT_TOKEN, print no interactive command, and do
/// not run `op account list`.
#[test]
fn ci_not_signed_in_advises_service_account_token() {
    let mut h = Harness::new(&good_item());
    h.unset("OP_SERVICE_ACCOUNT_TOKEN")
        .set("CI", "true")
        .set("FAKE_OP_EXIT", "1");
    let r = h.run(&["sync", "prod"]);
    assert_eq!(r.code, 7, "{}", r.all());
    assert!(
        r.stderr.contains("set OP_SERVICE_ACCOUNT_TOKEN"),
        "{}",
        r.stderr
    );
    assert!(!r.stderr.contains("op signin"), "{}", r.stderr);
    assert!(!r.stderr.contains("to see why"), "{}", r.stderr);
    assert_eq!(op_subcommands(&h), vec!["item get", "whoami --format"]);
}

/// FR-26: a clean `status` ends with the summary line on stdout; exit 0.
#[test]
fn clean_status_prints_summary_line() {
    let h = Harness::new(&good_item());
    let r = h.run(&["status", "prod"]);
    assert_eq!(r.code, 0, "{}", r.all());
    let first = r.stdout.lines().next().unwrap();
    assert!(
        first.starts_with("prod: ") && first.ends_with(" · 0 findings · 2 not yet on Fly"),
        "{}",
        r.stdout
    );
    assert_clean_output(&["status", "prod"], &r);
}

/// FR-26: a failed flyctl call while logged out of Fly is authentication (7) with
/// `flyctl auth login`; under CI, "set FLY_API_TOKEN". The account named by
/// `flyctl auth whoami` never appears, and nothing says "to see why".
#[test]
fn fly_logged_out_is_auth_with_next_step() {
    let mut h = Harness::new(&good_item());
    h.set("FAKE_FLY_LIST_FAIL_AT", "1")
        .set("FAKE_FLY_AUTH_EXIT", "1");
    for cmd in [
        &["status", "prod"][..],
        &["plan", "prod"],
        &["sync", "prod"],
    ] {
        h.reset();
        let r = h.run(cmd);
        assert_eq!(r.code, 7, "{cmd:?}: {}", r.all());
        assert!(
            r.stderr
                .starts_with("opv: authentication error: not logged in to Fly"),
            "{cmd:?}: {}",
            r.stderr
        );
        assert!(
            r.stderr.contains("\n  log in: flyctl auth login\n"),
            "{}",
            r.stderr
        );
        assert!(!r.stderr.contains("to see why"), "{}", r.stderr);
        assert_clean_output(cmd, &r);
        assert_eq!(h.fly_calls("import"), 0);
    }
    h.set("CI", "true");
    h.reset();
    let r = h.run(&["sync", "prod"]);
    assert_eq!(r.code, 7, "{}", r.all());
    assert!(r.stderr.contains("set FLY_API_TOKEN"), "{}", r.stderr);
    assert!(!r.stderr.contains("auth login"), "{}", r.stderr);
    assert_clean_output(&["sync", "prod"], &r);
}

/// FR-26 / FR-10: with a non-interactive 1Password credential (service account or
/// Connect) set, a read and whoami that both fail are ambiguous: Source (4) naming the
/// variable, no interactive command, no `op account list`.
#[test]
fn rejected_credential_keeps_source_category() {
    for (set, var) in [
        (
            &[("OP_SERVICE_ACCOUNT_TOKEN", "dummy-not-a-token")][..],
            "OP_SERVICE_ACCOUNT_TOKEN",
        ),
        (
            &[
                ("OP_CONNECT_HOST", "http://connect.invalid"),
                ("OP_CONNECT_TOKEN", "dummy-not-a-token"),
            ][..],
            "OP_CONNECT_TOKEN",
        ),
    ] {
        let mut h = Harness::new(&good_item());
        h.unset("OP_SERVICE_ACCOUNT_TOKEN")
            .set("SHELL", "/bin/bash")
            .set("FAKE_OP_EXIT", "1");
        for (k, v) in set {
            h.set(k, v);
        }
        let r = h.run(&["status", "prod"]);
        assert_eq!(r.code, 4, "{var}: {}", r.all());
        assert!(
            r.stderr
                .contains(&format!("check the token in {var} and network access")),
            "{}",
            r.stderr
        );
        assert!(!r.stderr.contains("op signin"), "{}", r.stderr);
        assert!(!r.stderr.contains("dummy-not-a-token"), "{}", r.stderr);
        assert_eq!(op_subcommands(&h), vec!["item get", "whoami --format"]);
    }
}

/// FR-26: `CI=false` is not CI (interactive sign-in command shown).
#[test]
fn ci_false_is_not_ci() {
    let mut h = Harness::new(&good_item());
    h.unset("OP_SERVICE_ACCOUNT_TOKEN")
        .set("CI", "false")
        .set("SHELL", "/bin/bash")
        .set("FAKE_OP_EXIT", "1");
    let r = h.run(&["status", "prod"]);
    assert_eq!(r.code, 7, "{}", r.all());
    assert!(
        r.stderr.contains("sign in: eval $(op signin)"),
        "{}",
        r.stderr
    );
}

/// FR-26 / FR-10: with FLY_API_TOKEN set, a failed flyctl call is a target error (5) naming
/// the app and the variable; `flyctl auth whoami` is not run (deploy tokens fail it).
#[test]
fn fly_token_failure_is_target_without_whoami() {
    let mut h = Harness::new(&good_item());
    h.set("FAKE_FLY_LIST_FAIL_AT", "1")
        .set("FAKE_FLY_AUTH_EXIT", "1")
        .set("FLY_API_TOKEN", "dummy-fly-token");
    let r = h.run(&["sync", "prod"]);
    assert_eq!(r.code, 5, "{}", r.all());
    assert!(
        r.stderr.contains(&format!(
            "flyctl failed for app {APP}: check that the token in FLY_API_TOKEN can access it"
        )),
        "{}",
        r.stderr
    );
    assert!(!r.stderr.contains("dummy-fly-token") && !r.stderr.contains("to see why"));
    assert_eq!(h.fly_calls("whoami"), 0);
    assert_clean_output(&["sync", "prod"], &r);
}

/// FR-10: stable exit codes per category, observed from the real binary (src/error.rs).
#[test]
fn exit_codes() {
    // 0: everything fine.
    let h = Harness::new(&good_item());
    assert_eq!(h.run(&["sync", "prod"]).code, 0);
    assert_eq!(h.run(&["status", "prod"]).code, 0);
    assert_eq!(h.run(&["doctor"]).code, 0);

    // 2: configuration (bad file, unknown env, bad --rotate), before any subprocess.
    let bad = h.fix.join("bad.toml");
    fs::write(&bad, "[profile]\nkind = 42\n").unwrap();
    h.reset();
    let out = Command::new(env!("CARGO_BIN_EXE_opv"))
        .env_remove("GITHUB_STEP_SUMMARY") // never the job summary of the run testing opv
        .args(["--config", bad.to_str().unwrap(), "sync", "prod"])
        .env_clear()
        .env("PATH", &h.bin)
        .env("FAKE_REC", &h.rec)
        .env("FAKE_FIX", &h.fix)
        .current_dir(&h.cwd)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(h.calls().is_empty());
    for cmd in [
        &["sync", "qa"][..],
        &["sync", "prod", "--rotate", "allumata/OPENAI_API_KEY"],
    ] {
        h.reset();
        let r = h.run(cmd);
        assert_eq!(r.code, 2, "{cmd:?}: {}", r.all());
        assert!(h.calls().is_empty(), "{cmd:?} spawned a child");
    }

    // 3: `op` missing from PATH (dependency).
    let no_op = Harness::build(&good_item(), false, true);
    for cmd in [&["sync", "prod"][..], &["status", "prod"], &["doctor"]] {
        let r = no_op.run(cmd);
        assert_eq!(r.code, 3, "{cmd:?}: {}", r.all());
        assert!(r.stderr.contains("dependency error"), "{}", r.stderr);
    }
    // 3: `flyctl` missing from PATH (dependency); nothing staged.
    let no_fly = Harness::build(&good_item(), true, false);
    let r = no_fly.run(&["sync", "prod"]);
    assert_eq!(r.code, 3, "{}", r.all());
    assert!(
        r.stderr.contains("flyctl not found on PATH"),
        "{}",
        r.stderr
    );

    // 4: source (op fails with credentials present; malformed item JSON).
    let mut h4 = Harness::new(&good_item());
    h4.set("FAKE_OP_ITEM_EXIT", "1");
    assert_eq!(h4.run(&["sync", "prod"]).code, 4);
    let h4b = Harness::new("{\"fields\": [ not json");
    let r = h4b.run(&["sync", "prod"]);
    assert_eq!(r.code, 4, "{}", r.all());

    // 5: target (list fails).
    let mut h5 = Harness::new(&good_item());
    h5.set("FAKE_FLY_LIST_FAIL_AT", "1");
    assert_eq!(h5.run(&["status", "prod"]).code, 5);

    // 6: policy (sync with a missing key refuses, nothing staged).
    let missing = item(
        good_fields(OPENAI)
            .into_iter()
            .filter(|f| f["label"] != "INTEGRATION_ENC_KEY")
            .collect(),
    );
    let h6 = Harness::new(&missing);
    let r = h6.run(&["sync", "prod"]);
    assert_eq!(r.code, 6, "{}", r.all());
    assert!(
        r.stderr.contains("allumata/INTEGRATION_ENC_KEY (missing)"),
        "{}",
        r.stderr
    );
    assert_eq!(h6.fly_calls("import"), 0);

    // 7: authentication (op fails with no credentials in the environment).
    let mut h7 = Harness::new(&good_item());
    h7.unset("OP_SERVICE_ACCOUNT_TOKEN")
        .set("FAKE_OP_EXIT", "1");
    for cmd in [&["sync", "prod"][..], &["status", "prod"], &["doctor"]] {
        h7.reset();
        let r = h7.run(cmd);
        assert_eq!(r.code, 7, "{cmd:?}: {}", r.all());
        assert!(r.stderr.contains("authentication error"), "{}", r.stderr);
    }

    // 8: findings (status / plan with a missing key).
    h6.reset();
    assert_eq!(h6.run(&["status", "prod"]).code, 8);
    assert_eq!(h6.run(&["plan", "prod"]).code, 8);
}

/// I3: `--expect-no-change` is gone (usage error, exit 2, nothing spawned).
#[test]
fn expect_no_change_flag_is_removed() {
    let h = Harness::new(&good_item());
    let r = h.run(&["sync", "prod", "--expect-no-change"]);
    assert_eq!(r.code, 2, "{}", r.all());
    assert!(h.calls().is_empty());
}

/// I4: a closed stdout (`status | head`) stops output and the command still returns its
/// own result: 8 with a missing key, 0 when complete; never a dependency error (3).
#[test]
fn broken_stdout_returns_the_command_result() {
    let missing = item(
        good_fields(OPENAI)
            .into_iter()
            .filter(|f| f["label"] != "INTEGRATION_ENC_KEY")
            .collect(),
    );
    for (item_json, cmd, want) in [
        (missing.clone(), &["status", "prod"][..], 8),
        (missing, &["plan", "prod"], 8),
        (good_item(), &["status", "prod"], 0),
        (good_item(), &["sync", "prod"], 0),
    ] {
        let h = Harness::new(&item_json);
        let mut child = Command::new(env!("CARGO_BIN_EXE_opv"))
            .env_remove("GITHUB_STEP_SUMMARY") // never the job summary of the run testing opv
            .arg("--config")
            .arg(CONFIG)
            .args(cmd)
            .env_clear()
            .env("PATH", &h.bin)
            .env("TMPDIR", &h.tmp)
            .env("FAKE_REC", &h.rec)
            .env("FAKE_FIX", &h.fix)
            .envs(h.env.iter().map(|(k, v)| (k, v)))
            .current_dir(&h.cwd)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        // Close the read end before opv writes anything (the fakes take a while).
        drop(child.stdout.take());
        let out = child.wait_with_output().unwrap();
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert_eq!(out.status.code(), Some(want), "{cmd:?}: {stderr}");
        assert!(!stderr.contains("dependency error"), "{cmd:?}: {stderr}");
        assert_no_marker(&format!("{cmd:?} stderr"), &stderr);
    }
}

/// I2: a value that passes the rules but cannot travel on a Fly import line fails a rule
/// named after the import rule in `status` and `fly plan` (8), and `fly sync` refuses it
/// (6) naming product/KEY; nothing is staged.
#[test]
fn import_refusal_shows_in_status_and_plan_and_blocks_sync() {
    let h = Harness::new(&item(good_fields("sk-proj-S7MARKERVALUE\"#frag0011")));
    let rule = "import-hash-after-odd-quotes";
    for cmd in [&["status", "prod"][..], &["plan", "prod"]] {
        h.reset();
        let r = h.run(cmd);
        assert_eq!(r.code, 8, "{cmd:?}: {}", r.all());
        assert!(
            r.stdout
                .lines()
                .any(|l| l.contains("OPENAI_API_KEY") && l.contains(&format!("failed {rule} ("))),
            "{}",
            r.stdout
        );
        assert_clean_output(cmd, &r);
    }
    h.reset();
    let r = h.run(&["sync", "prod", "--prune", "--deploy"]);
    assert_eq!(r.code, 6, "{}", r.all());
    assert!(
        r.stderr
            .contains(&format!("allumata/OPENAI_API_KEY (failed {rule} (")),
        "{}",
        r.stderr
    );
    for sub in ["import", "unset", "deploy"] {
        assert_eq!(h.fly_calls(sub), 0, "{sub}");
    }
    assert_clean_output(&["sync"], &r);
}

// ----------------------------------------------------------------- FR-21 (--json)

/// An item missing one desired key (a blocking finding) for exit-code parity tests.
fn item_without_enc() -> String {
    item(
        good_fields(OPENAI)
            .into_iter()
            .filter(|f| f["label"] != "INTEGRATION_ENC_KEY")
            .collect(),
    )
}

/// FR-21: `status --json` prints one parseable JSON document and nothing else on stdout.
#[test]
fn status_json_stdout_is_one_json_document() {
    let h = Harness::new(&good_item());
    let r = h.run(&["status", "prod", "--json"]);
    assert!(
        serde_json::from_str::<Value>(&r.stdout).is_ok(),
        "not one JSON document: {}",
        r.all()
    );
}

/// FR-21: `fly plan --json` prints one parseable JSON document and nothing else on stdout.
#[test]
fn fly_plan_json_stdout_is_one_json_document() {
    let h = Harness::new(&good_item());
    let r = h.run(&["plan", "prod", "--json"]);
    assert!(
        serde_json::from_str::<Value>(&r.stdout).is_ok(),
        "not one JSON document: {}",
        r.all()
    );
}

/// FR-21: the document declares `schema_version: 1`.
#[test]
fn status_json_schema_version_is_one() {
    let h = Harness::new(&good_item());
    let r = h.run(&["status", "prod", "--json"]);
    let doc: Value = serde_json::from_str(&r.stdout).expect("one JSON document");
    assert_eq!(doc["schema_version"], json!(1), "{}", r.all());
}

/// FR-21: the document names the environment and carries names-only totals.
#[test]
fn status_json_totals_are_names_and_counts() {
    let h = Harness::new(&good_item());
    let r = h.run(&["status", "prod", "--json"]);
    let doc: Value = serde_json::from_str(&r.stdout).expect("one JSON document");
    assert_eq!(
        (&doc["environment"], &doc["totals"]),
        (
            &json!("prod"),
            &json!({
                "rows": 4,
                "findings": 0,
                "extras": 1,
                "to_stage": 2,
                "held": 0,
                "to_prune": 1,
            })
        ),
        "{}",
        r.all()
    );
}

/// FR-21: each row object carries product, key, kind, state, failing rule, Fly name and
/// target presence.
#[test]
fn status_json_row_carries_the_contract_fields() {
    let h = Harness::new(&good_item());
    let r = h.run(&["status", "prod", "--json"]);
    let doc: Value = serde_json::from_str(&r.stdout).expect("one JSON document");
    let row = doc["rows"]
        .as_array()
        .expect("rows array")
        .iter()
        .find(|x| x["key"] == "OPENAI_API_KEY")
        .expect("OPENAI_API_KEY row");
    assert_eq!(
        row,
        &json!({
            "product": "allumata",
            "key": "OPENAI_API_KEY",
            "kind": "secret",
            "state": "saved",
            "rule": null,
            "reason": null,
            "fly_name": N_OPENAI,
            "target_name": N_OPENAI,
            "target": "absent",
            "action": "would_stage",
        }),
        "{}",
        r.all()
    );
}

/// FR-21: a failing row names its rule in `rule` and carries no value.
#[test]
fn status_json_row_names_failing_rule() {
    let h = Harness::new(&item(good_fields("pk-S7MARKERVALUEbadprefix0012")));
    let r = h.run(&["status", "prod", "--json"]);
    let doc: Value = serde_json::from_str(&r.stdout).expect("one JSON document");
    let row = doc["rows"]
        .as_array()
        .expect("rows array")
        .iter()
        .find(|x| x["key"] == "OPENAI_API_KEY")
        .expect("OPENAI_API_KEY row");
    assert_eq!(
        (row["state"].clone(), row["rule"].clone()),
        (json!("failing_rule"), json!("prefix")),
        "{}",
        r.all()
    );
}

/// FR-22: a failing row carries its reason in a separate `reason` field next to `rule`,
/// built from the configuration (the expected prefix), never from the value.
#[test]
fn status_json_row_carries_failing_reason() {
    let h = Harness::new(&item(good_fields("pk-S7MARKERVALUEbadprefix0013")));
    let r = h.run(&["status", "prod", "--json"]);
    let doc: Value = serde_json::from_str(&r.stdout).expect("one JSON document");
    let row = doc["rows"]
        .as_array()
        .expect("rows array")
        .iter()
        .find(|x| x["key"] == "OPENAI_API_KEY")
        .expect("OPENAI_API_KEY row");
    assert_eq!(row["reason"], json!("expected prefix sk-"), "{}", r.all());
}

/// FR-22: the JSON document keeps schema_version 1 when `reason` is added.
#[test]
fn status_json_reason_keeps_schema_version_one() {
    let h = Harness::new(&item(good_fields("pk-S7MARKERVALUEbadprefix0014")));
    let r = h.run(&["status", "prod", "--json"]);
    let doc: Value = serde_json::from_str(&r.stdout).expect("one JSON document");
    assert_eq!(doc["schema_version"], json!(1), "{}", r.all());
}

/// FR-22: text output shows `failed <rule> (<reason>)`.
#[test]
fn status_text_shows_rule_and_reason() {
    let h = Harness::new(&item(good_fields("pk-S7MARKERVALUEbadprefix0015")));
    let r = h.run(&["status", "prod"]);
    assert!(
        r.stdout
            .lines()
            .any(|l| l.contains("OPENAI_API_KEY")
                && l.contains("failed prefix (expected prefix sk-)")),
        "{}",
        r.stdout
    );
    assert_clean_output(&["status"], &r);
}

/// FR-21 / SR-1: `status --json` contains no secret value marker (nor child stderr).
#[test]
fn status_json_omits_every_marker_value() {
    let h = Harness::new(&good_item());
    let r = h.run(&["status", "prod", "--json"]);
    serde_json::from_str::<Value>(&r.stdout).expect("one JSON document");
    assert_no_marker("status --json stdout", &r.stdout);
}

/// FR-21 / SR-1: `fly plan --json` contains no secret value marker (nor child stderr).
#[test]
fn fly_plan_json_omits_every_marker_value() {
    let h = Harness::new(&good_item());
    let r = h.run(&["plan", "prod", "--json"]);
    serde_json::from_str::<Value>(&r.stdout).expect("one JSON document");
    assert_no_marker("fly plan --json stdout", &r.stdout);
}

/// FR-21: the document carries no guidance text (guidance belongs in `explain`).
#[test]
fn status_json_omits_guidance_text() {
    let h = Harness::new(&good_item());
    let r = h.run(&["status", "prod", "--json"]);
    assert!(
        !r.stdout.contains("OpenAI platform / API keys"),
        "guidance leaked: {}",
        r.stdout
    );
}

/// FR-10 / FR-21: `status` exits 8 for blocking findings with and without `--json`.
#[test]
fn status_json_exit_code_matches_text_on_findings() {
    let h = Harness::new(&item_without_enc());
    let text = h.run(&["status", "prod"]).code;
    h.reset();
    let json = h.run(&["status", "prod", "--json"]).code;
    assert_eq!((text, json), (8, 8));
}

/// FR-10 / FR-21: `fly plan` exits 8 for blocking findings with and without `--json`.
#[test]
fn fly_plan_json_exit_code_matches_text_on_findings() {
    let h = Harness::new(&item_without_enc());
    let text = h.run(&["plan", "prod"]).code;
    h.reset();
    let json = h.run(&["plan", "prod", "--json"]).code;
    assert_eq!((text, json), (8, 8));
}

/// FR-10 / A1: an error before the document is produced still exits 4, and stdout is the
/// one failure document, not a partial one.
#[test]
fn status_json_error_prints_the_failure_document_on_stdout() {
    let mut h = Harness::new(&good_item());
    h.set("FAKE_OP_ITEM_EXIT", "1");
    let r = h.run(&["status", "prod", "--json"]);
    let doc: Value = serde_json::from_str(&r.stdout).expect("one JSON document");
    assert_eq!(
        (r.code, doc["ok"].clone(), doc["exit_code"].clone()),
        (4, json!(false), json!(4)),
        "{}",
        r.all()
    );
}

/// FR-10 / A1: `plan --json` likewise.
#[test]
fn plan_json_error_names_its_code() {
    let mut h = Harness::new(&good_item());
    h.set("FAKE_OP_ITEM_EXIT", "1");
    let r = h.run(&["plan", "prod", "--json"]);
    let doc: Value = serde_json::from_str(&r.stdout).expect("one JSON document");
    assert_eq!(doc["error"]["code"], "item_not_found", "{}", r.all());
}

/// SR-1 / A1: the failure document carries no value, though the failed call's stderr
/// (masked in the text) carried one.
#[test]
fn json_failure_document_carries_no_value() {
    let mut h = Harness::new(&good_item());
    h.set("FAKE_OP_ITEM_EXIT", "1");
    let r = h.run(&["status", "prod", "--json"]);
    assert!(!r.stdout.contains(MARK), "{}", r.stdout);
}

/// SR-1 / A6: no `--json` document carries a value or the child's stderr, whatever the
/// command.
#[test]
fn json_documents_carry_no_value() {
    let h = Harness::new(&good_item());
    let mut leaked = Vec::new();
    for args in [
        &["status", "prod", "--json"][..],
        &["plan", "prod", "--json"],
        &["check", "prod", "--product", "allumata", "--json"],
        &["sync", "prod", "--json"],
        &["doctor", "--env", "prod", "--json"],
        &[
            "explain",
            "allumata/OPENAI_API_KEY",
            "--env",
            "prod",
            "--json",
        ],
    ] {
        h.reset();
        let r = h.run(args);
        if r.stdout.contains(MARK) || r.stdout.contains(CHILD_STDERR) {
            leaked.push(format!("{args:?}: {}", r.stdout));
        }
    }
    assert!(leaked.is_empty(), "{leaked:?}");
}

// ------------------------------------------------------------ simple profile (FR-20)

const SIMPLE_CONFIG: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/simple.toml");
const S_DB: &str = "postgres://S7MARKERVALUEdb0006";

/// A simple-profile item: unsectioned fields, plus a notes value and a sectioned field
/// that the simple profile ignores. Every secret value is a marker.
fn simple_item() -> String {
    item(vec![
        field(None, "notesPlain", "STRING", Some(NOTES)),
        field(None, "DATABASE_URL", "CONCEALED", Some(S_DB)),
        field(None, "JWT_KEY", "CONCEALED", Some(ENC)),
        field(None, "LOG_LEVEL", "STRING", Some("info")),
        field(
            Some("allumata"),
            "OPENAI_API_KEY",
            "CONCEALED",
            Some(OPENAI),
        ),
    ])
}

/// A simple harness whose Fly app holds a declared key not desired in prod
/// (`STAGING_DEBUG_TOKEN`) and a name the file never declares (`UNMANAGED_OTHER`).
fn simple_harness() -> Harness {
    let h = Harness::new(&simple_item());
    let a = json!([
        {"name": "STAGING_DEBUG_TOKEN", "digest": "d-s", "status": "Deployed"},
        {"name": "UNMANAGED_OTHER", "digest": "d-other", "status": "Deployed"},
    ]);
    let b = json!([
        {"name": "STAGING_DEBUG_TOKEN", "digest": "d-s", "status": "Deployed"},
        {"name": "UNMANAGED_OTHER", "digest": "d-other", "status": "Deployed"},
        {"name": "DATABASE_URL", "digest": "d-db", "status": "Staged"},
        {"name": "JWT_KEY", "digest": "d-jwt", "status": "Staged"},
    ]);
    fs::write(h.fix.join("list_a.json"), a.to_string()).unwrap();
    fs::write(h.fix.join("list_b.json"), b.to_string()).unwrap();
    h
}

/// SR-1, SR-3: every command against a simple-profile file keeps values out of output,
/// argv and child environments.
#[test]
fn simple_profile_commands_never_leak_values() {
    let h = simple_harness();
    for cmd in COMMANDS {
        h.reset();
        let r = h.run_config(SIMPLE_CONFIG, cmd);
        assert_clean_output(cmd, &r);
        assert_argv_and_env_clean(&h);
    }
}

/// FR-13, §8 item 15: a simple `fly sync --prune --deploy` reads the item exactly once.
#[test]
fn simple_profile_sync_reads_one_item() {
    let h = simple_harness();
    let r = h.run_config(SIMPLE_CONFIG, &["sync", "prod", "--prune", "--deploy"]);
    assert_eq!(r.code, 0, "{}", r.all());
    let gets = h
        .calls()
        .iter()
        .filter(|c| c.prog == "op" && c.argv.first().map(String::as_str) == Some("item"))
        .count();
    assert_eq!(gets, 1);
}

/// FR-8, SR-6, §8 item 15: `--prune` under the simple profile unsets the declared key not
/// desired here and never the undeclared name.
#[test]
fn simple_profile_prune_touches_only_declared_keys() {
    let h = simple_harness();
    let r = h.run_config(SIMPLE_CONFIG, &["sync", "prod", "--prune"]);
    assert_eq!(r.code, 0, "{}", r.all());
    let unset: Vec<Vec<String>> = h
        .calls()
        .into_iter()
        .filter(|c| c.prog == "flyctl" && c.argv.get(1).map(String::as_str) == Some("unset"))
        .map(|c| c.argv)
        .collect();
    assert_eq!(
        unset,
        vec![vec![
            "secrets",
            "unset",
            "STAGING_DEBUG_TOKEN",
            "--app",
            "myapp-production",
            "--stage"
        ]]
    );
}

// ------------------------------------------------------------- FR-22 failure reasons

/// A hex marker (hex values cannot carry `S7MARKER`); must never appear either.
const HEX_MARK: &str = "f22dec0de5";

/// One key per rule failure path (FR-15, FR-22), every rule in its own key so each row
/// fails exactly one way. Config text holds no marker.
const REASONS_CONFIG: &str = r#"
[profile]
kind = "fleet"

[environments.staging]
vault_id = "vstg"
item_id = "istg"
fly.app = "reasons-staging"
fly.secret_name = "FLEET__{PRODUCT}__{KEY}"

[environments.prod]
vault_id = "vprd"
item_id = "iprd"
fly.app = "mcproductlabs-portfolio-production"
fly.secret_name = "FLEET__{PRODUCT}__{KEY}"
modes.allumata.payments = "test"
modes.allumata.region = "weird"

[products.allumata.keys.REFUSED]
kind = "secret"
environments = ["staging"]
rules = { refuse_in = ["prod"] }

[products.allumata.keys.EMPTY]
kind = "secret"
environments = ["prod"]

[products.allumata.keys.MULTILINE]
kind = "secret"
environments = ["prod"]

[products.allumata.keys.SPACED]
kind = "secret"
environments = ["prod"]

[products.allumata.keys.TOO_LONG]
kind = "secret"
environments = ["prod"]

[products.allumata.keys.PREFIX]
kind = "secret"
environments = ["prod"]
rules = { prefix = "sk-" }

[products.allumata.keys.NOT_PREFIX]
kind = "secret"
environments = ["prod"]
rules = { not_prefix = "zz-" }

[products.allumata.keys.MODE_WRONG]
kind = "secret"
environments = ["prod"]
rules = { prefix_by_mode = { mode = "payments", values = { test = "sk_test_" } } }

[products.allumata.keys.MODE_UNSET]
kind = "secret"
environments = ["prod"]
rules = { prefix_by_mode = { mode = "billing", values = { on = "b_" } } }

[products.allumata.keys.MODE_UNMAPPED]
kind = "secret"
environments = ["prod"]
rules = { prefix_by_mode = { mode = "region", values = { eu = "eu_" } } }

[products.allumata.keys.REGEX]
kind = "secret"
environments = ["prod"]
rules = { regex = "[a-z]+" }

[products.allumata.keys.ENUM]
kind = "secret"
environments = ["prod"]
rules = { enum = ["a", "b"] }

[products.allumata.keys.B64_NOT]
kind = "secret"
environments = ["prod"]
rules = { base64_bytes = 32 }

[products.allumata.keys.B64_COUNT]
kind = "secret"
environments = ["prod"]
rules = { base64_bytes = 32 }

[products.allumata.keys.HEX_NOT]
kind = "secret"
environments = ["prod"]
rules = { hex_bytes = 4 }

[products.allumata.keys.HEX_COUNT]
kind = "secret"
environments = ["prod"]
rules = { hex_bytes = 4 }

[products.allumata.keys.EMAILS]
kind = "secret"
environments = ["prod"]
rules = { email_list = true }

[products.allumata.keys.URL_SCHEME]
kind = "secret"
environments = ["prod"]
rules = { https_url = true }

[products.allumata.keys.URL_SPACE]
kind = "secret"
environments = ["prod"]
rules = { https_url = true }

[products.allumata.keys.ENSURE_EMPTY]
kind = "secret"
environments = ["prod"]
rules = { ensure_prefix = "pre_" }

[products.allumata.keys.PATTERN]
kind = "secret"
environments = ["prod"]
rules = { ensure_prefix = "pre_", pattern = "[a-z]+" }

[products.allumata.keys.UNKNOWN_TRANSFORM]
kind = "secret"
environments = ["prod"]
rules = { transform = "nope" }

[products.allumata.keys.FLY_IMPORT]
kind = "secret"
environments = ["prod"]

[products.allumata.keys.PEM_NO_MARKERS]
kind = "secret"
environments = ["prod"]
rules = { transform = "pem_private_key" }

[products.allumata.keys.PEM_LABELS]
kind = "secret"
environments = ["prod"]
rules = { transform = "pem_private_key" }

[products.allumata.keys.PEM_NOT_PRIVATE]
kind = "secret"
environments = ["prod"]
rules = { transform = "pem_private_key" }

[products.allumata.keys.PEM_ENCRYPTED]
kind = "secret"
environments = ["prod"]
rules = { transform = "pem_private_key" }

[products.allumata.keys.PEM_PROC_TYPE]
kind = "secret"
environments = ["prod"]
rules = { transform = "pem_private_key" }

[products.allumata.keys.PEM_TWO_BLOCKS]
kind = "secret"
environments = ["prod"]
rules = { transform = "pem_private_key" }

[products.allumata.keys.PEM_NOT_BASE64]
kind = "secret"
environments = ["prod"]
rules = { transform = "pem_private_key" }

[products.allumata.keys.PEM_NOT_KEY]
kind = "secret"
environments = ["prod"]
rules = { transform = "pem_private_key" }
"#;

/// (key, marker value, expected rule, expected reason). Every value but the three that
/// cannot hold one (empty, exactly the prefix) carries `S7MARKER` or [`HEX_MARK`].
fn reason_cases() -> Vec<(&'static str, String, &'static str, &'static str)> {
    let m = MARK;
    let one_pem =
        format!("-----BEGIN RSA PRIVATE KEY-----\n{m}AA\n-----END RSA PRIVATE KEY-----\n");
    let long = format!("{m}{}", "a".repeat(59_000));
    let too_long_reason = "longer than the 59000-byte limit";
    vec![
        (
            "REFUSED",
            format!("{m}refused"),
            "refuse_in",
            "must not be set in this environment",
        ),
        ("EMPTY", String::new(), "nonempty", "empty"),
        (
            "MULTILINE",
            format!("{m}\nline"),
            "single_line",
            "contains a line break or NUL",
        ),
        (
            "SPACED",
            format!(" {m}"),
            "no_surrounding_space",
            "leading or trailing whitespace",
        ),
        ("TOO_LONG", long, "max_len", too_long_reason),
        (
            "PREFIX",
            format!("{m}prefix"),
            "prefix",
            "expected prefix sk-",
        ),
        (
            "NOT_PREFIX",
            format!("zz-{m}"),
            "not_prefix",
            "starts with a refused prefix",
        ),
        (
            "MODE_WRONG",
            format!("{m}mode"),
            "prefix_by_mode",
            "wrong prefix for mode test",
        ),
        (
            "MODE_UNSET",
            format!("{m}mode"),
            "prefix_by_mode",
            "mode billing is not set in this environment",
        ),
        (
            "MODE_UNMAPPED",
            format!("{m}mode"),
            "prefix_by_mode",
            "no prefix is configured for mode weird",
        ),
        (
            "REGEX",
            format!("{m}regex"),
            "regex",
            "does not match the configured regex",
        ),
        ("ENUM", format!("{m}enum"), "enum", "expected one of: a, b"),
        (
            "B64_NOT",
            format!("{m}!!"),
            "base64_bytes",
            "not standard base64",
        ),
        (
            "B64_COUNT",
            format!("{m}AAAA"),
            "base64_bytes",
            "does not decode to 32 bytes",
        ),
        ("HEX_NOT", format!("{m}zz"), "hex_bytes", "not hex"),
        (
            "HEX_COUNT",
            HEX_MARK.to_string(),
            "hex_bytes",
            "does not decode to 4 bytes",
        ),
        (
            "EMAILS",
            format!("{m}@nowhere"),
            "email_list",
            "not a comma-separated list of email addresses",
        ),
        (
            "URL_SCHEME",
            format!("http://{m}"),
            "https_url",
            "not an https:// URL",
        ),
        (
            "URL_SPACE",
            format!("https://{m} x"),
            "https_url",
            "URL contains whitespace",
        ),
        (
            "ENSURE_EMPTY",
            "pre_".to_string(),
            "ensure_prefix",
            "nothing after the prefix",
        ),
        (
            "PATTERN",
            format!("pre_{m}"),
            "pattern",
            "text after the prefix does not match the pattern",
        ),
        (
            "UNKNOWN_TRANSFORM",
            format!("{m}t"),
            "transform",
            "unknown transform",
        ),
        (
            "FLY_IMPORT",
            format!("{m}\"#x"),
            "import-hash-after-odd-quotes",
            "a # follows an odd number of double quotes",
        ),
        (
            "PEM_NO_MARKERS",
            format!("{m} is no pem"),
            "transform",
            "no BEGIN/END markers",
        ),
        (
            "PEM_LABELS",
            format!("-----BEGIN RSA PRIVATE KEY-----\n{m}AA\n-----END {m} PRIVATE KEY-----\n"),
            "transform",
            "BEGIN/END labels differ",
        ),
        (
            "PEM_NOT_PRIVATE",
            format!("-----BEGIN {m} PUBLIC KEY-----\n{m}AA\n-----END {m} PUBLIC KEY-----\n"),
            "transform",
            "not a private key",
        ),
        (
            "PEM_ENCRYPTED",
            format!(
                "-----BEGIN ENCRYPTED PRIVATE KEY-----\n{m}AA\n-----END ENCRYPTED PRIVATE KEY-----\n"
            ),
            "transform",
            "encrypted key",
        ),
        (
            "PEM_PROC_TYPE",
            one_pem.replacen(
                "KEY-----\n",
                &format!("KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,{m}\n\n"),
                1,
            ),
            "transform",
            "encrypted key",
        ),
        (
            "PEM_TWO_BLOCKS",
            format!("{one_pem}{one_pem}"),
            "transform",
            "more than one PEM block",
        ),
        (
            "PEM_NOT_BASE64",
            format!("-----BEGIN PRIVATE KEY-----\n{m}%%\n-----END PRIVATE KEY-----\n"),
            "transform",
            "body is not base64",
        ),
        // `S7MARKER` decodes to bytes that do not start a DER SEQUENCE.
        (
            "PEM_NOT_KEY",
            format!("-----BEGIN PRIVATE KEY-----\n{m}\n-----END PRIVATE KEY-----\n"),
            "transform",
            "not a key structure",
        ),
    ]
}

fn reasons_harness() -> Harness {
    let fields = reason_cases()
        .into_iter()
        .map(|(key, value, _, _)| field(Some("allumata"), key, "CONCEALED", Some(&value)))
        .collect();
    let mut h = Harness::new(&item(fields));
    h.use_config(REASONS_CONFIG);
    h
}

fn assert_no_reason_marker(what: &str, text: &str) {
    for m in [MARK, HEX_MARK, CHILD_STDERR] {
        assert!(!text.contains(m), "{what} contains {m}:\n{text}");
    }
}

/// FR-22 / SR-1: marker values driven through every rule failure path (every rule, every
/// reason, all seven `pem_private_key` reasons, the FR-24 rules, the SigNoz alias and a
/// Fly import refusal) leave no marker byte sequence in text or JSON output.
#[test]
fn rule_failure_reasons_never_carry_a_marker() {
    let h = reasons_harness();
    for (cmd, want) in [
        (&["status", "prod"][..], 8),
        (&["status", "prod", "--json"], 8),
        (&["plan", "prod"], 8),
        (&["plan", "prod", "--json"], 8),
        (&["sync", "prod", "--prune", "--deploy"], 6),
    ] {
        h.reset();
        let r = h.run(cmd);
        assert_eq!(r.code, want, "{cmd:?}: {}", r.all());
        assert_no_reason_marker(&format!("{cmd:?} stdout"), &r.stdout);
        assert_no_reason_marker(&format!("{cmd:?} stderr"), &r.stderr);
    }
}

/// FR-22: every failure path in [`reason_cases`] is really reached, with its rule and
/// reason in the JSON row (so the marker test above covers each path).
#[test]
fn every_rule_failure_path_reports_its_rule_and_reason() {
    let h = reasons_harness();
    let r = h.run(&["status", "prod", "--json"]);
    let doc: Value = serde_json::from_str(&r.stdout).expect("one JSON document");
    let rows = doc["rows"].as_array().expect("rows array");
    for (key, _, rule, reason) in reason_cases() {
        let row = rows
            .iter()
            .find(|x| x["key"] == key)
            .unwrap_or_else(|| panic!("{key} row: {}", r.stdout));
        assert_eq!(
            (row["rule"].clone(), row["reason"].clone()),
            (json!(rule), json!(reason)),
            "{key}"
        );
    }
}

/// FR-22: `pem_private_key` reports each of its seven reasons.
#[test]
fn pem_private_key_reports_each_of_its_seven_reasons() {
    let h = reasons_harness();
    let r = h.run(&["status", "prod"]);
    for reason in [
        "no BEGIN/END markers",
        "BEGIN/END labels differ",
        "not a private key",
        "encrypted key",
        "more than one PEM block",
        "body is not base64",
        "not a key structure",
    ] {
        assert!(
            r.stdout.contains(&format!("failed transform ({reason})")),
            "{reason}: {}",
            r.stdout
        );
    }
}

/// FR-22 / FR-13: `explain` makes no 1Password or Fly call at all.
#[test]
fn explain_makes_no_op_or_flyctl_call() {
    let h = Harness::new(&good_item());
    let r = h.run(&["explain", "allumata/OPENAI_API_KEY", "--env", "prod"]);
    assert_eq!(r.code, 0, "{}", r.all());
    assert!(h.calls().is_empty(), "{:?}", h.calls());
}

/// FR-22, FR-20, SR-1: under the simple profile a failing row's reason carries no marker,
/// in text or JSON, and the JSON row keeps `product: null`.
#[test]
fn simple_profile_rule_failure_reason_carries_no_marker() {
    let h = Harness::new(&item(vec![
        field(
            None,
            "DATABASE_URL",
            "CONCEALED",
            Some("mysql://S7MARKERVALUEdb0016"),
        ),
        field(None, "JWT_KEY", "CONCEALED", Some(ENC)),
        field(None, "LOG_LEVEL", "STRING", Some("info")),
    ]));
    let text = h.run_config(SIMPLE_CONFIG, &["status", "prod"]);
    assert_eq!(text.code, 8, "{}", text.all());
    assert!(
        text.stdout
            .contains("failed prefix (expected prefix postgres://)"),
        "{}",
        text.stdout
    );
    assert_clean_output(&["status", "prod"], &text);
    let json = h.run_config(SIMPLE_CONFIG, &["status", "prod", "--json"]);
    assert_clean_output(&["status", "prod", "--json"], &json);
    let doc: Value = serde_json::from_str(&json.stdout).expect("one JSON document");
    let row = doc["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["key"] == "DATABASE_URL")
        .unwrap()
        .clone();
    assert_eq!(
        (row["product"].clone(), row["reason"].clone()),
        (Value::Null, json!("expected prefix postgres://"))
    );
}

// ------------------------------------------------- NR-31: scrubbed child stderr excerpts

/// An item value with every character class an encoding changes.
const JSONISH: &str = "S7MARKERVALUEjson\"q\\w/\u{e9}+?&=0007";

fn jsonish_item() -> String {
    let mut fields = good_fields(OPENAI);
    fields.push(field(
        Some("allumata"),
        "JSONISH_EXTRA",
        "CONCEALED",
        Some(JSONISH),
    ));
    item(fields)
}

/// `status prod` after a good item read, with every `flyctl secrets list` failing and
/// writing `value` to stderr.
fn list_failure_with_stderr(value: &str) -> Run {
    let mut h = Harness::new(&jsonish_item());
    h.set("FAKE_FLY_LIST_FAIL_AT", "1")
        .set("FAKE_STDERR_VALUE", value);
    h.run(&["status", "prod"])
}

const MASKED_EXCERPT: &str = "\n  flyctl said: S7CHILDSTDERR __SECRET__\n";

#[test]
fn excerpt_masks_a_raw_item_value() {
    assert!(
        list_failure_with_stderr(JSONISH)
            .stderr
            .contains(MASKED_EXCERPT)
    );
}

#[test]
fn excerpt_masks_a_json_escaped_item_value() {
    let escaped = serde_json::to_string(JSONISH).unwrap();
    let r = list_failure_with_stderr(&escaped[1..escaped.len() - 1]);
    assert!(r.stderr.contains(MASKED_EXCERPT), "{}", r.stderr);
}

#[test]
fn excerpt_masks_a_base64_item_value() {
    use base64::Engine as _;
    let enc = base64::engine::general_purpose::STANDARD.encode(JSONISH);
    assert!(
        list_failure_with_stderr(&enc)
            .stderr
            .contains(MASKED_EXCERPT)
    );
}

#[test]
fn excerpt_masks_a_base64url_item_value() {
    use base64::Engine as _;
    let enc = base64::engine::general_purpose::URL_SAFE.encode(JSONISH);
    assert!(
        list_failure_with_stderr(&enc)
            .stderr
            .contains(MASKED_EXCERPT)
    );
}

#[test]
fn excerpt_masks_an_unpadded_base64url_item_value() {
    use base64::Engine as _;
    let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(JSONISH);
    assert!(
        list_failure_with_stderr(&enc)
            .stderr
            .contains(MASKED_EXCERPT)
    );
}

#[test]
fn excerpt_masks_a_percent_encoded_item_value() {
    let enc: String = JSONISH
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    assert!(
        list_failure_with_stderr(&enc)
            .stderr
            .contains(MASKED_EXCERPT)
    );
}

/// A token opv never read is masked by its shape.
#[test]
fn excerpt_masks_a_jwt_opv_never_read() {
    let r = list_failure_with_stderr("eyJhbGciOiJIUzI1NiJ9.eyJTN01BUktFUiI6MX0.c2ln");
    assert!(r.stderr.contains(MASKED_EXCERPT), "{}", r.stderr);
}

/// A value of the notes field, outside every section, is registered too.
#[test]
fn excerpt_masks_an_unsectioned_item_value() {
    assert!(
        list_failure_with_stderr(NOTES)
            .stderr
            .contains(MASKED_EXCERPT)
    );
}

/// At most five lines, the last ones, each labelled with the program, right after the
/// error line.
#[test]
fn excerpt_shows_the_last_five_lines_labelled_with_the_program() {
    let r = list_failure_with_stderr("l2\nl3\nl4\nl5\nl6\nl7");
    let excerpt: Vec<&str> = r.stderr.lines().filter(|l| is_excerpt_line(l)).collect();
    assert_eq!(
        excerpt,
        [
            "  flyctl said: l3",
            "  flyctl said: l4",
            "  flyctl said: l5",
            "  flyctl said: l6",
            "  flyctl said: l7"
        ],
        "{}",
        r.stderr
    );
}

/// `--verbose` shows each call's stderr, scrubbed (the notes value only the registry
/// knows), under its call line.
#[test]
fn verbose_shows_scrubbed_child_stderr() {
    let mut h = Harness::new(&good_item());
    h.set("FAKE_STDERR_VALUE", NOTES);
    let r = h.run(&["--verbose", "status", "prod"]);
    assert!(
        r.stderr
            .contains("\n    stderr: S7CHILDSTDERR __SECRET__\n"),
        "{}",
        r.stderr
    );
}

/// `--verbose` shows the size and JSON shape of each call's stdout.
#[test]
fn verbose_shows_stdout_shape() {
    let h = Harness::new(&good_item());
    let r = h.run(&["--verbose", "status", "prod"]);
    assert!(
        r.stderr
            .lines()
            .any(|l| l.starts_with("    stdout: ") && l.contains("JSON object with keys: ")),
        "{}",
        r.stderr
    );
}

/// SR-1: no stdout content (the fakes print markers in item, whoami and account JSON)
/// reaches any output with `--verbose`, on success or failure.
#[test]
fn verbose_never_shows_stdout_content() {
    let mut h = Harness::new(&good_item());
    h.set("FAKE_STDERR_VALUE", "plain");
    let mut runs = Vec::new();
    for fail in [
        None,
        Some(("FAKE_OP_EXIT", "1")),
        Some(("FAKE_FLY_LIST_FAIL_AT", "1")),
    ] {
        if let Some((k, v)) = fail {
            h.set(k, v);
        }
        for cmd in COMMANDS {
            h.reset();
            let args: Vec<&str> = std::iter::once("--verbose")
                .chain(cmd.iter().copied())
                .collect();
            runs.push(h.run(&args).all());
        }
    }
    assert!(
        runs.iter().all(|t| !t.contains(MARK)),
        "{}",
        runs.join("\n----\n")
    );
}

// ------------------------------------------------------------- NR-19: the Next line

/// Every kind of non-zero exit the CLI has, as (label, run): a usage error, each error
/// category (exit 2 to 9), a failing `doctor` and a `confirm_env` refusal.
/// [`exit_paths_cover_every_category`] checks the exit codes.
fn exit_paths() -> Vec<(&'static str, Run)> {
    let mut v = Vec::new();
    let h = Harness::new(&good_item());
    v.push(("usage", h.run(&["sync"])));
    v.push(("config", h.run(&["status", "qa"])));
    let no_op = Harness::build(&good_item(), false, true);
    v.push(("dependency", no_op.run(&["status", "prod"])));
    v.push(("doctor", no_op.run(&["doctor"])));
    let mut h4 = Harness::new(&good_item());
    h4.set("FAKE_OP_ITEM_EXIT", "1");
    v.push(("source", h4.run(&["status", "prod"])));
    let mut h5 = Harness::new(&good_item());
    h5.set("FAKE_FLY_LIST_FAIL_AT", "1");
    v.push(("target", h5.run(&["status", "prod"])));
    let missing = item(
        good_fields(OPENAI)
            .into_iter()
            .filter(|f| f["label"] != "INTEGRATION_ENC_KEY")
            .collect(),
    );
    let h6 = Harness::new(&missing);
    v.push(("policy", h6.run(&["sync", "prod"])));
    v.push(("findings", h6.run(&["status", "prod"])));
    let mut h7 = Harness::new(&good_item());
    h7.set("FAKE_FLY_LIST_FAIL_AT", "1")
        .set("FAKE_FLY_AUTH_EXIT", "1");
    v.push(("auth", h7.run(&["status", "prod"])));
    // A write cut off by the run budget: its outcome is unknown (NR-2).
    let mut h9 = Harness::new(&good_item());
    h9.set("FAKE_FLY_IMPORT_SLEEP", "5");
    v.push(("unknown", h9.run(&["--timeout", "2", "sync", "prod"])));
    let mut guarded = Harness::new(&good_item());
    let text = fs::read_to_string(CONFIG).unwrap().replace(
        "modes.allumata.payments = \"off\"",
        "modes.allumata.payments = \"off\"\nconfirm_env = true",
    );
    guarded.use_config(&text);
    v.push(("confirm_env", guarded.run(&["sync", "prod", "--deploy"])));
    v
}

/// NR-19: every non-zero exit ends with exactly one `Next:` line, the last on stderr.
#[test]
fn every_error_exit_prints_one_next_line_last() {
    let bad: Vec<String> = exit_paths()
        .into_iter()
        .filter(|(_, r)| {
            let lines: Vec<&str> = r.stderr.lines().collect();
            let nexts = lines.iter().filter(|l| l.starts_with("Next: ")).count();
            r.code == 0 || nexts != 1 || !lines.last().is_some_and(|l| l.starts_with("Next: "))
        })
        .map(|(what, r)| format!("{what} (exit {}):\n{}", r.code, r.stderr))
        .collect();
    assert!(bad.is_empty(), "{}", bad.join("\n---\n"));
}

/// The exit paths above reach every error category's exit code (2 to 9).
#[test]
fn exit_paths_cover_every_category() {
    let mut codes: Vec<i32> = exit_paths().iter().map(|(_, r)| r.code).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes, vec![2, 3, 4, 5, 6, 7, 8, 9]);
}

/// NR-20: a guarded environment's refusal names the exact command to run.
#[test]
fn confirm_env_refusal_ends_with_the_exact_command() {
    let mut h = Harness::new(&good_item());
    let text = fs::read_to_string(CONFIG).unwrap().replace(
        "modes.allumata.payments = \"off\"",
        "modes.allumata.payments = \"off\"\nconfirm_env = true",
    );
    h.use_config(&text);
    let r = h.run(&["sync", "prod", "--deploy"]);
    assert_eq!(
        r.stderr.lines().last(),
        Some("Next: opv sync prod --deploy --confirm prod")
    );
}

/// P2: `sync --json` prints one document on stdout and nothing else.
#[test]
fn sync_json_stdout_is_one_document() {
    let h = Harness::new(&good_item());
    let r = h.run(&["sync", "prod", "--json"]);
    let doc: Value = serde_json::from_str(&r.stdout).expect("one JSON document");
    let pending: Vec<&Value> = doc["pending"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| &p["target_name"])
        .collect();
    assert_eq!(pending, [N_ENC, N_OPENAI], "{}", r.all());
}

/// P22: `status` without an environment prints one line per environment.
#[test]
fn status_without_env_prints_one_line_per_environment() {
    let h = Harness::new(&good_item());
    let r = h.run(&["status"]);
    let envs: Vec<&str> = r
        .stdout
        .lines()
        .map(|l| l.split(':').next().unwrap_or_default())
        .collect();
    assert_eq!(envs, ["prod", "staging"], "{}", r.all());
}

/// H8, SR-1: with `GITHUB_STEP_SUMMARY` set, status, plan and sync (missing keys and
/// complete ones) append a names-only summary: no value, no identity, no link.
#[test]
fn step_summary_never_carries_a_value() {
    let summary_dir = TempDir::new().unwrap();
    let path = summary_dir.path().join("summary.md");
    let mut h = Harness::new(&good_item());
    h.set("GITHUB_STEP_SUMMARY", path.to_str().unwrap());
    for item_json in [item(vec![]), good_item()] {
        h.set_item(&item_json);
        for cmd in [
            &["status", "prod"][..],
            &["plan", "prod"],
            &["sync", "prod"],
        ] {
            h.reset();
            h.run(cmd);
        }
    }
    let md = fs::read_to_string(&path).unwrap();
    assert!(
        md.contains("### opv plan prod") && !md.contains(MARK) && !md.contains("1password.com"),
        "{md}"
    );
}
