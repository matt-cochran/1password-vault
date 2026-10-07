//! Security and failure-mode tests (S7; SR-1..SR-4, FR-10, Review Focus 4).
//!
//! Every test runs the real `secretctl` binary against fake `op` and `flyctl` executables:
//! small `#!/bin/sh` scripts in a temp `bin` dir that is the ONLY entry on `PATH` (so the
//! real tools can never run; `cat` is symlinked in for the fakes). Each fake records its
//! argv (one arg per line), stdin and exported environment into a separate record dir,
//! always writes a stderr canary that must never reach secretctl's output, and prints
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
  # `secretctl run` inherits stdio by design (FR-4): no canary, and do not exec.
  exit "${FAKE_OP_RUN_EXIT:-0}"
fi
printf '%s %s\n' "$FAKE_CHILD_STDERR" "$FAKE_STDERR_VALUE" >&2
case "$1" in
  --version) echo "2.30.0"; exit 0 ;;
  whoami)
    [ -n "$FAKE_OP_EXIT" ] && exit "$FAKE_OP_EXIT"
    printf '{"user_type":"SERVICE_ACCOUNT"}\n'; exit 0 ;;
  item)
    [ -n "$FAKE_OP_EXIT" ] && exit "$FAKE_OP_EXIT"
    cat "$FAKE_FIX/item.json"; exit 0 ;;
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
  "auth whoami") echo "fake@example.invalid"; exit 0 ;;
  "secrets list")
    l=0
    [ -f "$FAKE_REC/.lists" ] && read l < "$FAKE_REC/.lists"
    l=$((l + 1))
    echo "$l" > "$FAKE_REC/.lists"
    [ "$l" = "$FAKE_FLY_LIST_FAIL_AT" ] && exit 1
    if [ "$l" = 1 ]; then cat "$FAKE_FIX/list_a.json"; else cat "$FAKE_FIX/list_b.json"; fi
    exit 0 ;;
  "secrets import") exit "${FAKE_FLY_IMPORT_EXIT:-0}" ;;
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
    stderr: String,
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

impl Harness {
    fn new(item_json: &str) -> Self {
        Self::build(item_json, true, true)
    }

    fn build(item_json: &str, with_op: bool, with_flyctl: bool) -> Self {
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
            write_exe(&bin.join("op"), FAKE_OP);
        }
        if with_flyctl {
            write_exe(&bin.join("flyctl"), FAKE_FLYCTL);
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
        }
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
        let out = Command::new(env!("CARGO_BIN_EXE_secretctl"))
            .arg("--config")
            .arg(CONFIG)
            .args(args)
            .env_clear()
            .env("PATH", &self.bin)
            .env("TMPDIR", &self.tmp)
            .env("FAKE_REC", &self.rec)
            .env("FAKE_FIX", &self.fix)
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .current_dir(&self.cwd)
            .output()
            .unwrap();
        Run {
            code: out.status.code().expect("exited normally"),
            stdout: String::from_utf8(out.stdout).unwrap(),
            stderr: String::from_utf8(out.stderr).unwrap(),
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
    &["fly", "plan", "prod"],
    &["fly", "sync", "prod"],
    &["fly", "sync", "prod", "--prune", "--deploy"],
    &["config", "export", "prod", "--json"],
    &["item", "skeleton", "prod"],
];

fn assert_no_marker(what: &str, text: &str) {
    for m in [MARK, CHILD_STDERR] {
        assert!(!text.contains(m), "{what} contains {m}:\n{text}");
    }
}

fn assert_clean_output(cmd: &[&str], r: &Run) {
    assert_no_marker(&format!("{cmd:?} stdout"), &r.stdout);
    assert_no_marker(&format!("{cmd:?} stderr"), &r.stderr);
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
    let r = h.run(&["fly", "sync", "prod", "--prune", "--deploy"]);
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
    let run_env = &h.calls()[0].env;
    assert!(
        run_env.contains("op://vprd/iprd/allumata/OPENAI_API_KEY"),
        "{run_env}"
    );
}

/// SR-3: the import stdin is the one channel that carries values; it carries exactly the
/// staged ones, and every argv file and secretctl's own output lack them.
#[test]
fn stdin_only_channel() {
    let h = Harness::new(&good_item());
    let r = h.run(&["fly", "sync", "prod"]);
    assert_eq!(r.code, 0, "{}", r.all());
    assert_clean_output(&["fly", "sync", "prod"], &r);

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

/// SR-1: no value reaches secretctl's stdout or stderr for any command, success or
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

/// Carried from S1-M5: every fake writes a canary plus a value to stderr on every call;
/// neither appears in secretctl's stdout or stderr for any command, including failures.
#[test]
fn drops_child_stderr() {
    let mut h = Harness::new(&good_item());
    for cmd in COMMANDS {
        h.reset();
        let r = h.run(cmd);
        assert!(!h.calls().is_empty(), "{cmd:?} spawned nothing");
        assert_clean_output(cmd, &r);
    }
    // Failing children too: op fails, then flyctl list fails.
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

/// Brief: fake `op` prints a value to stderr and exits 1 → Source (4), value not echoed.
#[test]
fn child_stderr_suppressed() {
    let mut h = Harness::new(&good_item());
    h.set("FAKE_OP_EXIT", "1");
    for cmd in [
        &["status", "prod"][..],
        &["fly", "plan", "prod"],
        &["fly", "sync", "prod"],
        &["config", "export", "prod", "--json"],
        &["item", "skeleton", "prod"],
    ] {
        h.reset();
        let r = h.run(cmd);
        assert_eq!(r.code, 4, "{cmd:?}: {}", r.all());
        assert!(
            r.stderr
                .starts_with("secretctl: source error: op item get failed (exit 1)"),
            "{cmd:?}: {}",
            r.stderr
        );
        assert_clean_output(cmd, &r);
        assert_eq!(h.fly_calls("import"), 0);
    }
}

/// Ruling 3 (S3's rule): with no OP_SERVICE_ACCOUNT_TOKEN / OP_SESSION_* an op failure is
/// an authentication error (3), not a source error.
#[test]
fn op_failure_without_credentials_is_auth() {
    let mut h = Harness::new(&good_item());
    h.unset("OP_SERVICE_ACCOUNT_TOKEN").set("FAKE_OP_EXIT", "1");
    for cmd in [
        &["status", "prod"][..],
        &["fly", "sync", "prod"],
        &["doctor"],
    ] {
        h.reset();
        let r = h.run(cmd);
        assert_eq!(r.code, 3, "{cmd:?}: {}", r.all());
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
    check(&h, &["fly", "sync", "prod", "--prune", "--deploy"]);
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
    let r = h.run(&["fly", "sync", "prod", "--prune", "--deploy"]);
    assert_eq!(r.code, 5, "{}", r.all());
    assert!(
        r.stderr
            .starts_with("secretctl: target error: fly secrets list failed (exit 1)"),
        "{}",
        r.stderr
    );
    for sub in ["import", "unset", "deploy"] {
        assert_eq!(h.fly_calls(sub), 0, "{sub} after a failed list");
    }
    assert_clean_output(&["fly", "sync"], &r);
}

/// Review Focus 4: list B (after import) fails → Target (5); nothing further is mutated
/// (no unset, no deploy) even with --prune --deploy.
#[test]
fn list_b_failure_after_staging() {
    let mut h = Harness::new(&good_item());
    h.set("FAKE_FLY_LIST_FAIL_AT", "2");
    let r = h.run(&["fly", "sync", "prod", "--prune", "--deploy"]);
    assert_eq!(r.code, 5, "{}", r.all());
    assert!(
        r.stderr
            .starts_with("secretctl: target error: fly secrets list failed (exit 1)"),
        "{}",
        r.stderr
    );
    assert_eq!(h.fly_calls("import"), 1);
    assert_eq!(h.fly_calls("list"), 2);
    assert_eq!(h.fly_calls("unset"), 0, "unset after a failed list B");
    assert_eq!(h.fly_calls("deploy"), 0, "deploy after a failed list B");
    assert_clean_output(&["fly", "sync"], &r);
}

/// Review Focus 4 (import itself fails): Target (5), no unset/deploy afterwards.
#[test]
fn import_failure_stops_the_run() {
    let mut h = Harness::new(&good_item());
    h.set("FAKE_FLY_IMPORT_EXIT", "1");
    let r = h.run(&["fly", "sync", "prod", "--prune", "--deploy"]);
    assert_eq!(r.code, 5, "{}", r.all());
    assert!(
        r.stderr.contains("fly secrets import failed (exit 1)"),
        "{}",
        r.stderr
    );
    assert_eq!(h.fly_calls("list"), 1);
    assert_eq!(h.fly_calls("unset"), 0);
    assert_eq!(h.fly_calls("deploy"), 0);
    assert_clean_output(&["fly", "sync"], &r);
}

/// FR-15 / Review Focus 1: a value failing a rule is named by key and rule, never by
/// value; `fly sync` refuses with Policy (6) and stages nothing; `status` and `fly plan`
/// report Findings (8).
#[test]
fn rule_failure_names_key_not_value() {
    let h = Harness::new(&good_item());
    for (value, rule) in [
        ("sk-proj-S7MARKERVALUEnewline0007\n", "single_line"),
        (" sk-proj-S7MARKERVALUEspace0008", "no_surrounding_space"),
        ("pk-S7MARKERVALUEprefix0009", "prefix"),
        ("sk-or-S7MARKERVALUEopenrouter0010", "not_prefix"),
    ] {
        h.set_item(&item(good_fields(value)));
        let named = format!("allumata/OPENAI_API_KEY (fails rule {rule})");

        h.reset();
        let r = h.run(&["fly", "sync", "prod", "--prune", "--deploy"]);
        assert_eq!(r.code, 6, "{rule}: {}", r.all());
        assert!(
            r.stderr
                .starts_with("secretctl: policy denied: fly sync refused, nothing staged"),
            "{rule}: {}",
            r.stderr
        );
        assert!(r.stderr.contains(&named), "{rule}: {}", r.stderr);
        for sub in ["import", "unset", "deploy"] {
            assert_eq!(h.fly_calls(sub), 0, "{rule}: {sub}");
        }
        assert_clean_output(&["fly", "sync"], &r);

        for cmd in [&["status", "prod"][..], &["fly", "plan", "prod"]] {
            h.reset();
            let r = h.run(cmd);
            assert_eq!(r.code, 8, "{rule} {cmd:?}: {}", r.all());
            assert!(r.stdout.contains("OPENAI_API_KEY"), "{}", r.stdout);
            assert!(
                r.stdout.contains(&format!("fails rule {rule}")),
                "{}",
                r.stdout
            );
            assert_clean_output(cmd, &r);
        }
    }
}

/// FR-10: stable exit codes per category, observed from the real binary (src/error.rs).
#[test]
fn exit_codes() {
    // 0: everything fine.
    let h = Harness::new(&good_item());
    assert_eq!(h.run(&["fly", "sync", "prod"]).code, 0);
    assert_eq!(h.run(&["status", "prod"]).code, 0);
    assert_eq!(h.run(&["doctor"]).code, 0);

    // 2: configuration (bad file, unknown env, bad --rotate), before any subprocess.
    let bad = h.fix.join("bad.toml");
    fs::write(&bad, "[profile]\nkind = 42\n").unwrap();
    h.reset();
    let out = Command::new(env!("CARGO_BIN_EXE_secretctl"))
        .args(["--config", bad.to_str().unwrap(), "fly", "sync", "prod"])
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
        &["fly", "sync", "qa"][..],
        &["fly", "sync", "prod", "--rotate", "allumata/OPENAI_API_KEY"],
    ] {
        h.reset();
        let r = h.run(cmd);
        assert_eq!(r.code, 2, "{cmd:?}: {}", r.all());
        assert!(h.calls().is_empty(), "{cmd:?} spawned a child");
    }

    // 3: `op` missing from PATH (dependency).
    let no_op = Harness::build(&good_item(), false, true);
    for cmd in [
        &["fly", "sync", "prod"][..],
        &["status", "prod"],
        &["doctor"],
    ] {
        let r = no_op.run(cmd);
        assert_eq!(r.code, 3, "{cmd:?}: {}", r.all());
        assert!(r.stderr.contains("dependency error"), "{}", r.stderr);
    }
    // 3: `flyctl` missing from PATH (dependency); nothing staged.
    let no_fly = Harness::build(&good_item(), true, false);
    let r = no_fly.run(&["fly", "sync", "prod"]);
    assert_eq!(r.code, 3, "{}", r.all());
    assert!(
        r.stderr.contains("flyctl not found on PATH"),
        "{}",
        r.stderr
    );

    // 4: source (op fails with credentials present; malformed item JSON).
    let mut h4 = Harness::new(&good_item());
    h4.set("FAKE_OP_EXIT", "1");
    assert_eq!(h4.run(&["fly", "sync", "prod"]).code, 4);
    let h4b = Harness::new("{\"fields\": [ not json");
    let r = h4b.run(&["fly", "sync", "prod"]);
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
    let r = h6.run(&["fly", "sync", "prod"]);
    assert_eq!(r.code, 6, "{}", r.all());
    assert!(
        r.stderr.contains("allumata/INTEGRATION_ENC_KEY (missing)"),
        "{}",
        r.stderr
    );
    assert_eq!(h6.fly_calls("import"), 0);

    // 8: findings (status / plan with a missing key; sync --expect-no-change that changed).
    h6.reset();
    assert_eq!(h6.run(&["status", "prod"]).code, 8);
    assert_eq!(h6.run(&["fly", "plan", "prod"]).code, 8);
    h.reset();
    let r = h.run(&["fly", "sync", "prod", "--expect-no-change"]);
    assert_eq!(r.code, 8, "{}", r.all());
    assert_clean_output(&["fly", "sync"], &r);
}
