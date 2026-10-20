//! The fault matrix (design §13.3, §13.4): every command in [`COMMANDS`] × every call it
//! makes against `tests/e2e/app` × every fault `opv-sim` has a recording for at that call.
//! Each cell runs the real `opv` twice (text and `--json`) with `OPV_NO_SKILL=1`, a scratch
//! `HOME`, a temp copy of the project and the simulator first on `PATH`, then checks the
//! catalog's rules on the result, one test per rule, named `<cell>::<rule>`.
//!
//! The cells are generated, not written by hand:
//!
//! ```text
//! # 1. discover the calls, run every candidate, write cells.rs, SKIPPED.md and COVERAGE.md
//! UPDATE_SNAPSHOTS=1 cargo nextest run --features fake --test e2e_matrix the_committed_cells
//! # 2. write each cell's snapshot (tests/e2e/snapshots/<cell>.snap)
//! UPDATE_SNAPSHOTS=1 cargo nextest run --features fake --test e2e_matrix
//! ```
//!
//! A candidate the simulator answers with exit 86 (no recording) or 87 (not modelled) is not
//! a cell: it is listed in `snapshots/SKIPPED.md`, so the gaps in the recordings stay
//! visible. A rule a not-yet-migrated path breaks is listed in `snapshots/KNOWN_LEGACY.txt`
//! (`<cell> <rule>`); since every path is migrated it is empty, and stays empty
//! ([`known_legacy_is_empty`]); an entry whose rule now holds fails until it is removed.
#![cfg(all(unix, feature = "fake"))]

#[path = "../sim/args.rs"]
#[allow(dead_code)]
mod sim_args;

use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime};

use serde_json::Value;

const ROOT: &str = env!("CARGO_MANIFEST_DIR");
const OPV: &str = env!("CARGO_BIN_EXE_opv");
const SIM: &str = env!("CARGO_BIN_EXE_opv-sim");
const ACCOUNT: &str = "AE2EDEVACCOUNT000000000001";

/// The commands of the matrix: a slug and the arguments after `opv` (text mode; the `--json`
/// run appends `--json`). Read-only commands and dry runs only.
const COMMANDS: &[(&str, &[&str])] = &[
    ("doctor_prod", &["doctor", "--env", "prod"]),
    ("status_prod", &["status", "prod"]),
    ("plan_prod", &["plan", "prod"]),
    ("doctor_dev", &["doctor", "--env", "dev"]),
    ("ready_dev", &["ready", "dev"]),
    ("access", &["access"]),
    ("explain_key", &["explain", "web/API_KEY", "--env", "prod"]),
    (
        "explain_target",
        &["explain", "--target", "fly", "--env", "prod"],
    ),
    (
        "run_preview",
        &[
            "run",
            "--preview",
            "dev",
            "--product",
            "web",
            "--role",
            "serve",
        ],
    ),
    (
        "vault_locate",
        &["vault", "locate", "vE2ESHAREDDEV00000000000001"],
    ),
    ("account_list", &["account", "list"]),
    ("contract", &["contract"]),
    // `sync` has no dry run: on a confirm_env environment without --confirm it reads, then
    // refuses before writing.
    ("sync_prod_unconfirmed", &["sync", "prod"]),
    ("propose_structure", &["propose", "structure"]),
];

/// The fault kinds `opv-sim` knows for every tool (tests/sim/faults.rs).
const KINDS: &[&str] = &[
    "signed_out",
    "other_account_session",
    "account_not_on_machine",
    "credential_rejected",
    "forbidden",
    "not_found",
    "unreachable",
    "rate_limited",
    "server_error",
    "timeout",
    "malformed_output",
    "applied_but_reply_lost",
    "tool_missing",
];

/// The ssh-only kinds.
const SSH_KINDS: &[&str] = &[
    "host_key_mismatch",
    "host_key_unknown",
    "connection_refused",
    "connect_timeout",
    "drop_mid_run",
    "server_unresponsive",
    "remote_command_missing",
];

/// The switches each simulated tool takes without a value (tests/sim/<tool>.rs `BOOLEAN`):
/// the call words are computed exactly as the simulator computes them.
fn boolean_flags(program: &str) -> &'static [&'static str] {
    match program {
        "op" => &["--reveal", "--raw", "--version", "--force"],
        "flyctl" | "fly" => &["--stage", "--json", "--detach"],
        "gh" => &["--silent", "-i", "--version", "--app"],
        "kubectl" => &[
            "--server-side",
            "--ignore-not-found",
            "--client",
            "--show-labels",
            "--all",
            "--overwrite",
        ],
        _ => &[],
    }
}

const NO_RECORDING: i32 = 86;
const UNSUPPORTED: i32 = 87;
const NO_OUTPUT: i32 = 88;

fn snapshots() -> PathBuf {
    Path::new(ROOT).join("tests/e2e/snapshots")
}

fn updating() -> bool {
    std::env::var("UPDATE_SNAPSHOTS").is_ok_and(|v| v == "1")
}

// --- one cell -------------------------------------------------------------------------------

/// One cell: a command, one of its calls, one fault on that call (every occurrence).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Cell {
    command: String,
    program: String,
    call: String,
    kind: String,
}

impl Cell {
    fn args(&self) -> &'static [&'static str] {
        COMMANDS
            .iter()
            .find(|(slug, _)| *slug == self.command)
            .map(|(_, a)| *a)
            .unwrap_or_else(|| panic!("unknown command {}", self.command))
    }

    fn name(&self) -> String {
        slug(&format!(
            "{}__{}_{}__{}",
            self.command, self.program, self.call, self.kind
        ))
    }

    fn faults(&self) -> String {
        let mut f = format!(
            "[[fault]]\nprogram = \"{}\"\ncall = \"{}\"\nkind = \"{}\"\n",
            self.program, self.call, self.kind
        );
        if self.kind == "timeout" {
            // Hangs past opv's own (capped) call limit: opv kills it, as it would a real hang.
            f.push_str("seconds = 60\n");
        }
        f
    }
}

/// The per-call limit a `timeout` cell runs opv with (`OPV_TEST_CALL_LIMIT`, `fake` builds
/// only), so the hang ends as opv's own timeout without waiting out the real limits. It holds
/// for the hanging call only (`OPV_TEST_CALL_LIMIT_CALL`): every other call keeps opv's real
/// limits, so a loaded machine cannot time out a call the fault does not target (#205). A run
/// that shows one anyway is disturbed ([`disturbance`]), run again and never cached.
const CALL_LIMIT_SECS: &str = "2";

/// How many times a disturbed cell is run before its disturbed outcome is reported.
const DISTURBED_ATTEMPTS: usize = 3;

/// The harness's own real-time limit on one opv run.
const RUN_LIMIT: Duration = Duration::from_secs(180);

fn slug(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        let c = c.to_ascii_lowercase();
        if c.is_ascii_alphanumeric() || c == '_' {
            out.push(c);
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    out
}

/// A scenario directory: the world (with `faults.toml`), a `bin` of wrappers around the
/// simulator that log each call's argv and exit, a scratch `HOME` and a project copy.
struct Scenario {
    root: tempfile::TempDir,
    /// The hanging call of a `timeout` cell (`<program> <words>`): `OPV_TEST_CALL_LIMIT`
    /// for that call only.
    call_limit: Option<String>,
}

impl Scenario {
    fn new(faults: &str) -> Self {
        let root = tempfile::tempdir().expect("temp dir");
        let p = root.path();
        let world = p.join("world");
        let project = p.join("project");
        for d in [&world, &project, &p.join("home"), &p.join("bin")] {
            std::fs::create_dir_all(d).expect("scenario dir");
        }
        let app = Path::new(ROOT).join("tests/e2e/app");
        std::fs::copy(app.join("world.json"), world.join("world.json")).expect("world");
        std::fs::write(world.join("faults.toml"), faults).expect("faults");
        std::fs::copy(app.join("secrets.toml"), project.join("secrets.toml")).expect("config");
        std::fs::copy(
            app.join("secrets.bindings.toml"),
            project.join("secrets.bindings.toml"),
        )
        .expect("bindings");
        // The project's own account, so no `.opv` above the temp directory is read.
        std::fs::write(project.join(".opv"), format!("account = \"{ACCOUNT}\"\n")).expect(".opv");
        let raw = p.join("sim-bin");
        let ok = Command::new(SIM)
            .arg("install")
            .arg(&raw)
            .env("OPV_SIM_WORLD", &world)
            .status()
            .expect("opv-sim install")
            .success();
        assert!(ok, "opv-sim install failed");
        for entry in std::fs::read_dir(&raw).expect("sim bin") {
            let name = entry.expect("entry").file_name();
            let name = name.to_string_lossy();
            // The child keeps its stderr (fd 3); bash's own job report of a killed child
            // ("line 4: <pid> Killed …", with a PID and the builder's path) goes nowhere.
            // `open/<id>` holds the call's argv while it runs: one left behind is a call opv
            // cut off ([`Scenario::cut_off`]).
            let script = format!(
                "#!/bin/bash\n\
                 printf '%s\\x1f' '{name}' \"$@\" >> \"$OPV_SIM_WORLD/argv.log\"\n\
                 printf '\\x1e' >> \"$OPV_SIM_WORLD/argv.log\"\n\
                 open=\"$OPV_SIM_WORLD/open/$$.$RANDOM$RANDOM\"\n\
                 mkdir -p \"$OPV_SIM_WORLD/open\"\n\
                 printf '%s\\x1f' '{name}' \"$@\" > \"$open\"\n\
                 exec 3>&2\n\
                 {{ ( exec -a '{name}' '{SIM}' \"$@\" 2>&3 ); }} 2>/dev/null\n\
                 rc=$?\n\
                 rm -f \"$open\"\n\
                 echo \"$rc\" >> \"$OPV_SIM_WORLD/exits.log\"\n\
                 if [ \"$rc\" -gt 128 ] && [ \"$rc\" -lt 160 ]; then kill -$((rc - 128)) $$; fi\n\
                 exit $rc\n"
            );
            let path = p.join("bin").join(&*name);
            std::fs::write(&path, script).expect("wrapper");
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }
        Self {
            root,
            call_limit: None,
        }
    }

    fn path(&self, sub: &str) -> PathBuf {
        self.root.path().join(sub)
    }

    /// Run `opv args` in the project; `None` exit when it had to be killed.
    fn opv(&self, args: &[String]) -> Run {
        let mut child = Command::new(OPV)
            .args(args)
            .current_dir(self.path("project"))
            .env_clear()
            .env(
                "PATH",
                format!("{}:{}", self.path("bin").display(), system_bin().display()),
            )
            .env("HOME", self.path("home"))
            .env("OPV_NO_SKILL", "1")
            .env("OPV_SIM_WORLD", self.path("world"))
            // Doctor's core-dump check reads this, not the host's `fs.suid_dumpable`: the
            // warning count in the summary line must not depend on the builder.
            .env("OPV_TEST_SUID_DUMPABLE", "0")
            // The 1Password app integration is off on every runner, so a sign-in message
            // never depends on the host.
            .env("OP_BIOMETRIC_UNLOCK_ENABLED", "false")
            .envs(self.call_limit.iter().flat_map(|scope| {
                [
                    ("OPV_TEST_CALL_LIMIT", CALL_LIMIT_SECS),
                    ("OPV_TEST_CALL_LIMIT_CALL", scope.as_str()),
                ]
            }))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run opv");
        let deadline = Instant::now() + RUN_LIMIT;
        let mut overran = false;
        loop {
            if child.try_wait().expect("wait").is_some() {
                break;
            }
            if Instant::now() > deadline {
                overran = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = child.kill();
        let out = child.wait_with_output().expect("output");
        Run {
            code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            overran,
        }
    }

    /// The simulated calls opv cut off (killed before they answered), as `(program, words)`.
    fn cut_off(&self) -> Vec<(String, Vec<String>)> {
        std::fs::read_dir(self.path("world/open"))
            .map(|d| {
                d.filter_map(Result::ok)
                    .filter_map(|e| std::fs::read_to_string(e.path()).ok())
                    .map(|r| call_record(&r))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Every simulated call so far, as `(program, words)`.
    fn calls(&self) -> Vec<(String, Vec<String>)> {
        let log = std::fs::read_to_string(self.path("world/argv.log")).unwrap_or_default();
        log.split('\x1e')
            .filter(|r| !r.is_empty())
            .map(call_record)
            .collect()
    }

    fn sim_exits(&self) -> Vec<i32> {
        std::fs::read_to_string(self.path("world/exits.log"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.trim().parse().ok())
            .collect()
    }

    fn normalize(&self, s: &str) -> String {
        // macOS resolves the temp directory through a symlink (/var → /private/var).
        let root = self.root.path().display().to_string();
        let real = std::fs::canonicalize(self.root.path())
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| root.clone());
        let s = s.replace(&real, "<SCENARIO>").replace(&root, "<SCENARIO>");
        let s = delay_re().replace_all(&s, "in <delay>");
        let s = receipt_re().replace_all(&s, "rcpt-<id>");
        // opv's own version changes every release; a snapshot must not.
        let s = s.replace(
            &format!(r#""opv_version":"{}""#, env!("CARGO_PKG_VERSION")),
            r#""opv_version":"<version>""#,
        );
        // The host's platform (WSL or plain Linux, read from the kernel) is not the
        // scenario's: a snapshot must match on every builder.
        let s = platform_re().replace_all(&s, r#""platform":"<platform>""#);
        let s = s.replace(" (op in WSL does not see the Windows app's accounts)", "");
        // Doctor's core-dump check reads the host's `fs.suid_dumpable`.
        let s = core_dump_text_re().replace_all(&s, "<host core-dump check>\n");
        // Doctor's app-integration row reads the host (WSL, a display; #203).
        let s = app_integration_text_re().replace_all(&s, "<host app-integration check>\n");
        let s = app_integration_json_re()
            .replace_all(&s, r#"{"name":"op app integration","host":true}"#);
        core_dump_json_re()
            .replace_all(&s, r#"{"name":"core dumps","host":true}"#)
            .into_owned()
    }
}

/// One logged call (`<name>\x1f<arg>\x1f…\x1f`) as `(program, words)`, the words computed as
/// the simulator computes them.
fn call_record(r: &str) -> (String, Vec<String>) {
    let mut parts: Vec<String> = r.split('\x1f').map(str::to_string).collect();
    parts.pop(); // after the last separator
    let name = parts.remove(0);
    let program = if name == "fly" { "flyctl".into() } else { name };
    let words = if program == "ssh" {
        parts
            .iter()
            .filter(|a| !a.starts_with('-'))
            .cloned()
            .collect()
    } else {
        sim_args::words(&parts, boolean_flags(&program))
    };
    (program, words)
}

/// The tools the simulator stands in for: never taken from the host.
const SIMULATED: &[&str] = &["op", "flyctl", "fly", "kubectl", "gh", "ssh", "az"];

/// `/usr/bin` and `/bin` without the simulated tools (one directory of links, made once per
/// build): a tool the scenario leaves out is then missing, as a `tool_missing` fault means,
/// never the host's own copy (a runner image ships `gh` and `ssh` in `/usr/bin`).
fn system_bin() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("e2e-system-bin");
        if dir.is_dir() {
            return dir;
        }
        // Built aside and renamed into place, so a test process never sees half of it.
        let tmp = dir.with_extension(std::process::id().to_string());
        std::fs::create_dir_all(&tmp).expect("system bin");
        for sys in ["/usr/bin", "/bin"] {
            let Ok(entries) = std::fs::read_dir(sys) else {
                continue;
            };
            for e in entries.flatten() {
                let name = e.file_name();
                if SIMULATED.iter().any(|t| name == *t) {
                    continue;
                }
                let link = tmp.join(&name);
                if std::fs::symlink_metadata(&link).is_err() {
                    let _ = std::os::unix::fs::symlink(e.path(), &link);
                }
            }
        }
        if std::fs::rename(&tmp, &dir).is_err() {
            let _ = std::fs::remove_dir_all(&tmp);
        }
        dir
    })
}

/// A retry's jittered delay.
fn delay_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"in \d+(\.\d+)? ?(ms|s)\b").expect("regex"))
}

/// Doctor's host core-dump check in text: its line and any `as root:` fix line.
fn core_dump_text_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"(?m)^(ok|warn|FAIL) +core dumps: [^\n]*\n(  [a-z ]+: [^\n]*\n)*")
            .expect("regex")
    })
}

/// Doctor's host core-dump check in a JSON document.
fn core_dump_json_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r#"\{"name":"core dumps"[^}]*\}"#).expect("regex"))
}

/// Doctor's `op app integration` row in text (#203): it depends on the host.
fn app_integration_text_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"(?m)^(ok|warn|skip) +op app integration: [^\n]*\n").expect("regex")
    })
}

/// Doctor's `op app integration` row in a JSON document.
fn app_integration_json_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r#"\{"name":"op app integration"[^}]*\}"#).expect("regex"))
}

/// The detected platform in a JSON document.
fn platform_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r#""platform":"(linux|wsl)""#).expect("regex"))
}

/// A readiness receipt's id (fresh each run).
fn receipt_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"rcpt-[0-9a-f]+").expect("regex"))
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
    /// The harness stopped opv at its own real-time limit ([`RUN_LIMIT`]).
    #[serde(skip)]
    overran: bool,
}

/// What one cell produced, normalized for the snapshot.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
struct Outcome {
    text: Run,
    json: Run,
    /// The simulator's exit codes, both runs.
    sim_exits: Vec<i32>,
    /// The `next` of the `--json` document, and the exit of `opv <next> --help`.
    next_help: Option<(String, Option<i32>)>,
    /// Why the run says nothing about opv: the machine, not the fault, decided it
    /// ([`disturbance`]). A disturbed outcome is never cached.
    #[serde(skip)]
    disturbed: Option<String>,
}

impl Cell {
    /// Whether the cell's fault hits a call: its program, and its words leading the call's.
    fn targets(&self, program: &str, words: &[String]) -> bool {
        let wanted: Vec<&str> = self.call.split_whitespace().collect();
        program == self.program
            && wanted.len() <= words.len()
            && wanted.iter().zip(words).all(|(w, a)| w == a)
    }
}

/// Why a cell's run was decided by the machine rather than the fault: the harness had to stop
/// opv at its own real-time limit, or opv cut off a call the fault does not target (only the
/// targeted call hangs; any other call ran into the short call limit because it was slow).
fn disturbance(cell: &Cell, overran: bool, cut_off: &[(String, Vec<String>)]) -> Option<String> {
    if overran {
        return Some(format!(
            "opv ran past the harness's {}s limit",
            RUN_LIMIT.as_secs()
        ));
    }
    cut_off
        .iter()
        .find(|(program, words)| !cell.targets(program, words))
        .map(|(program, words)| {
            format!(
                "`{program} {}` is not the faulted call but opv cut it off",
                words.join(" ")
            )
        })
}

/// The recordings directory of a simulated tool (tests/sim/<tool>.rs `DIR`).
fn recordings_dir(program: &str) -> &'static str {
    match program {
        "op" => "op",
        "flyctl" | "fly" => "fly",
        "gh" => "github",
        "kubectl" => "kubernetes",
        "ssh" => "ssh",
        _ => "<unknown>",
    }
}

/// Why a `tool_missing` candidate on a later call of its tool is no cell: a tool that is not
/// installed is missing for every call (opv-sim leaves it out of `PATH`), so opv fails at the
/// command's first call of it, and the run is the one of that first call's cell.
fn tool_missing_elsewhere(cell: &Cell) -> Option<String> {
    if cell.kind != "tool_missing" {
        return None;
    }
    let first = first_calls()
        .get(&(cell.command.clone(), cell.program.clone()))?
        .clone();
    (first != cell.call).then(|| {
        let same = Cell {
            call: first.clone(),
            ..cell.clone()
        };
        format!(
            "a missing `{}` is missing for every call: opv fails at its first one, `{} {first}`, \
             so this run is the one of `{}`",
            cell.program,
            cell.program,
            same.name()
        )
    })
}

/// The first call each command makes of each tool, from the committed cells and skips'
/// discovery order: `(command, program)` → call words.
fn first_calls() -> &'static BTreeMap<(String, String), String> {
    static FIRST: OnceLock<BTreeMap<(String, String), String>> = OnceLock::new();
    FIRST.get_or_init(|| {
        let mut first = BTreeMap::new();
        for (command, calls) in discover() {
            for (program, words) in calls {
                if !words.is_empty() {
                    first
                        .entry((command.to_string(), program))
                        .or_insert_with(|| words.join(" "));
                }
            }
        }
        first
    })
}

impl Outcome {
    /// Why the candidate is no cell (E4): the reply nobody recorded, or the call the
    /// simulator does not model. Recordings are never invented (CONTRIBUTING).
    fn skipped(&self, cell: &Cell) -> Option<String> {
        if self.sim_exits.contains(&NO_RECORDING) {
            Some(format!(
                "no `{}` reply recorded for `{} {}` under tests/fixtures/{}/failures (opv-sim exit 86)",
                cell.kind,
                cell.program,
                cell.call,
                recordings_dir(&cell.program)
            ))
        } else if self.sim_exits.contains(&NO_OUTPUT) {
            Some(format!(
                "`{} {}` fails or answers nothing without the fault, so it has no output for `{}` to damage (opv-sim exit 88)",
                cell.program, cell.call, cell.kind
            ))
        } else if self.sim_exits.contains(&UNSUPPORTED) {
            Some(format!(
                "`{} {}` is not modelled by opv-sim (exit 87)",
                cell.program, cell.call
            ))
        } else {
            None
        }
    }

    fn document(&self) -> Option<Value> {
        let mut docs = serde_json::Deserializer::from_str(&self.json.stdout).into_iter::<Value>();
        let first = docs.next()?.ok()?;
        docs.next().is_none().then_some(first)
    }

    fn snapshot(&self, cell: &Cell) -> String {
        let mut s = format!(
            "# {}: opv {} | fault {} on {} {}\n",
            cell.name(),
            cell.args().join(" "),
            cell.kind,
            cell.program,
            cell.call
        );
        for (mode, r) in [("text", &self.text), ("json", &self.json)] {
            s.push_str(&format!(
                "\n## {mode} exit: {}\n## {mode} stdout\n{}\n## {mode} stderr\n{}",
                r.code.map_or("killed".into(), |c| c.to_string()),
                r.stdout,
                r.stderr
            ));
        }
        s
    }
}

/// Run the cell until a run is not disturbed, at most [`DISTURBED_ATTEMPTS`] times.
fn run_cell(cell: &Cell) -> Outcome {
    let mut o = run_cell_once(cell);
    for _ in 1..DISTURBED_ATTEMPTS {
        let Some(why) = &o.disturbed else {
            break;
        };
        eprintln!("matrix: {} disturbed, running it again: {why}", cell.name());
        o = run_cell_once(cell);
    }
    o
}

fn run_cell_once(cell: &Cell) -> Outcome {
    let mut sc = Scenario::new(&cell.faults());
    sc.call_limit = (cell.kind == "timeout").then(|| format!("{} {}", cell.program, cell.call));
    let base: Vec<String> = cell.args().iter().map(|a| a.to_string()).collect();
    let text = sc.opv(&base);
    let mut json_args = base.clone();
    json_args.push("--json".into());
    let json = sc.opv(&json_args);
    let mut out = Outcome {
        text: Run {
            code: text.code,
            stdout: sc.normalize(&text.stdout),
            stderr: sc.normalize(&text.stderr),
            overran: text.overran,
        },
        json: Run {
            code: json.code,
            stdout: sc.normalize(&json.stdout),
            stderr: sc.normalize(&json.stderr),
            overran: json.overran,
        },
        sim_exits: sc.sim_exits(),
        next_help: None,
        disturbed: disturbance(cell, text.overran || json.overran, &sc.cut_off()),
    };
    if let Some(next) = out.document().as_ref().and_then(next_of) {
        let code = match shell_words(&next) {
            Some(mut w) if w.first().is_some_and(|p| p == "opv") => {
                w.remove(0);
                let at = w.iter().position(|a| a == "--").unwrap_or(w.len());
                w.insert(at, "--help".into());
                let help = sc.opv(&w);
                if help.overran && out.disturbed.is_none() {
                    out.disturbed = disturbance(cell, true, &[]);
                }
                help.code
            }
            // Another program's command (op, kubectl, …): clap has nothing to say.
            Some(_) => Some(0),
            None => Some(-1),
        };
        out.next_help = Some((next, code));
    }
    out
}

// --- the cache shared by the rule tests of one cell -----------------------------------------

/// The fingerprint of everything a cell's result depends on, the recordings the simulator
/// reads at run time included.
fn inputs_key() -> String {
    static KEY: OnceLock<String> = OnceLock::new();
    KEY.get_or_init(|| {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        let mut inputs = vec![
            PathBuf::from(OPV),
            PathBuf::from(SIM),
            Path::new(ROOT).join("tests/e2e/app/world.json"),
            Path::new(ROOT).join("tests/e2e/app/secrets.toml"),
            Path::new(ROOT).join("tests/e2e/app/secrets.bindings.toml"),
            Path::new(ROOT).join("tests/e2e/matrix.rs"),
        ];
        files_under(&Path::new(ROOT).join("tests/fixtures"), &mut inputs);
        for p in inputs {
            let m = std::fs::metadata(&p).expect("input");
            p.hash(&mut h);
            (m.len(), m.modified().unwrap_or(SystemTime::UNIX_EPOCH)).hash(&mut h);
        }
        format!("{:016x}", h.finish())
    })
    .clone()
}

/// Every file under `dir`, in a stable order.
fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    paths.sort();
    for p in paths {
        if p.is_dir() {
            files_under(&p, out);
        } else {
            out.push(p);
        }
    }
}

fn cache_dir() -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("e2e-matrix")
        .join(inputs_key());
    std::fs::create_dir_all(&dir).expect("cache dir");
    dir
}

fn cached(cell: &Cell) -> Option<Outcome> {
    let bytes = std::fs::read(cache_dir().join(format!("{}.json", cell.name()))).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Claim `cell` and compute it; `None` when another test holds it.
fn compute(cell: &Cell) -> Option<Outcome> {
    let dir = cache_dir();
    let lock = dir.join(format!("{}.lock", cell.name()));
    if std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock)
        .is_err()
    {
        let stale = std::fs::metadata(&lock)
            .and_then(|m| m.modified())
            .is_ok_and(|t| t.elapsed().unwrap_or_default() > Duration::from_secs(600));
        if stale {
            let _ = std::fs::remove_file(&lock);
        }
        return None;
    }
    let o = cached(cell).unwrap_or_else(|| run_cell(cell));
    store(&dir, cell, &o);
    let _ = std::fs::remove_file(&lock);
    Some(o)
}

/// Cache an outcome in `dir`, unless the machine decided it: a disturbed result would fail
/// every later run of the same build.
fn store(dir: &Path, cell: &Cell, o: &Outcome) {
    if o.disturbed.is_some() {
        return;
    }
    let tmp = dir.join(format!("{}.{}.tmp", cell.name(), std::process::id()));
    std::fs::write(&tmp, serde_json::to_vec(o).expect("encode")).expect("cache");
    std::fs::rename(&tmp, dir.join(format!("{}.json", cell.name()))).expect("cache");
}

/// Fail a test on a disturbed outcome with the reason, not with a misleading rule or diff.
fn assert_undisturbed(cell: &Cell, o: &Outcome) {
    if let Some(why) = &o.disturbed {
        panic!(
            "{}: no result after {DISTURBED_ATTEMPTS} runs: {why}",
            cell.name()
        );
    }
}

/// The cell's outcome, computed once per build of the inputs and shared between the rule
/// tests (each may run in its own process). A test waiting on a cell another test is
/// computing computes a cell nobody has claimed yet, so the waiters share the matrix's work.
fn outcome(cell: &Cell) -> Outcome {
    loop {
        if let Some(o) = cached(cell).or_else(|| compute(cell)) {
            return o;
        }
        let idle = committed_cells()
            .iter()
            .filter(|c| cached(c).is_none())
            .find_map(compute)
            .is_none();
        if idle {
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

// --- the rules ------------------------------------------------------------------------------

/// The `next` of a document: the error's, else the top level's.
fn next_of(doc: &Value) -> Option<String> {
    doc.pointer("/error/next")
        .or_else(|| doc.get("next"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// A command line split as a POSIX shell would (quotes only); `None` when unbalanced.
fn shell_words(s: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut has = false;
    let mut quote: Option<char> = None;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some('"'), '\\') => cur.extend(chars.next()),
            (Some(_), c) => cur.push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                has = true;
            }
            (None, '\\') => {
                cur.extend(chars.next());
                has = true;
            }
            (None, c) if c.is_whitespace() => {
                if has || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                    has = false;
                }
            }
            (None, c) => cur.push(c),
        }
    }
    if quote.is_some() {
        return None;
    }
    if has || !cur.is_empty() {
        out.push(cur);
    }
    Some(out)
}

/// Every code a [`Cause`] can report: the strings of `Cause::code` in `src/cause/mod.rs`.
fn catalog_codes() -> &'static BTreeSet<String> {
    static CODES: OnceLock<BTreeSet<String>> = OnceLock::new();
    CODES.get_or_init(|| {
        let src = std::fs::read_to_string(Path::new(ROOT).join("src/cause/mod.rs"))
            .expect("src/cause/mod.rs");
        let start = src.find("pub fn code(&self)").expect("Cause::code");
        let end = start
            + src[start..]
                .find("pub fn exit_code")
                .expect("Cause::exit_code");
        regex::Regex::new(r#""([a-z_]+)""#)
            .expect("regex")
            .captures_iter(&src[start..end])
            .map(|c| c[1].to_string())
            .collect()
    })
}

fn canaries() -> &'static Vec<String> {
    static C: OnceLock<Vec<String>> = OnceLock::new();
    C.get_or_init(|| {
        let world = std::fs::read_to_string(Path::new(ROOT).join("tests/e2e/app/world.json"))
            .expect("world.json");
        regex::Regex::new(r"(test-marker-e2e-[a-z0-9-]+|[A-Za-z0-9]+_e2e_marker_[a-z_]+)")
            .expect("regex")
            .find_iter(&world)
            .map(|m| m.as_str().to_string())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    })
}

/// Terminal control a message must never carry: ESC (CSI, OSC), C1 CSI/OSC, bidi controls.
fn control_char(c: char) -> bool {
    matches!(c, '\x1b' | '\u{9b}' | '\u{9d}' | '\u{7}')
        || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{200e}' | '\u{200f}')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rule {
    JsonIsOneDocument,
    CodeIsInTheCatalog,
    NextParses,
    NextDoesNotLoop,
    HumanRequiredMatchesTheStep,
    NoCanaryValue,
    NoEscapeSequence,
}

const RULES: &[Rule] = &[
    Rule::JsonIsOneDocument,
    Rule::CodeIsInTheCatalog,
    Rule::NextParses,
    Rule::NextDoesNotLoop,
    Rule::HumanRequiredMatchesTheStep,
    Rule::NoCanaryValue,
    Rule::NoEscapeSequence,
];

impl Rule {
    fn name(self) -> &'static str {
        match self {
            Rule::JsonIsOneDocument => "json_is_one_document",
            Rule::CodeIsInTheCatalog => "code_is_in_the_catalog",
            Rule::NextParses => "next_parses",
            Rule::NextDoesNotLoop => "next_does_not_loop",
            Rule::HumanRequiredMatchesTheStep => "human_required_matches_the_step",
            Rule::NoCanaryValue => "no_canary_value",
            Rule::NoEscapeSequence => "no_escape_sequence",
        }
    }

    /// `Err` with the reason when the rule is broken.
    fn check(self, cell: &Cell, o: &Outcome) -> Result<(), String> {
        let doc = o.document();
        let error = doc
            .as_ref()
            .and_then(|d| d.get("error"))
            .filter(|e| e.is_object());
        match self {
            Rule::JsonIsOneDocument => doc
                .map(|_| ())
                .ok_or_else(|| format!("--json stdout is not one document: {:?}", o.json.stdout)),
            Rule::CodeIsInTheCatalog => {
                let Some(e) = error else { return Ok(()) };
                let code = e.get("code").and_then(Value::as_str).unwrap_or("<none>");
                if catalog_codes().contains(code) {
                    Ok(())
                } else {
                    Err(format!("error.code {code:?} is not a catalog code"))
                }
            }
            Rule::NextParses => match &o.next_help {
                Some((_, Some(0))) | None => Ok(()),
                Some((next, code)) => Err(format!("`{next}` with --help exited {code:?}")),
            },
            Rule::NextDoesNotLoop => {
                let Some(e) = error else { return Ok(()) };
                let Some(next) = doc.as_ref().and_then(next_of) else {
                    return Ok(());
                };
                let strip = |w: Vec<String>| -> Vec<String> {
                    w.into_iter().filter(|a| a != "--json").collect()
                };
                let failing: Vec<String> = std::iter::once("opv".to_string())
                    .chain(cell.args().iter().map(|a| a.to_string()))
                    .collect();
                let same = shell_words(&next).map(strip) == Some(strip(failing));
                let safe = e.get("retry").and_then(Value::as_str) == Some("safe");
                // Design §11 `no_loop`: a person-only Do before the same command changes
                // what it meets (a sign-in), so that re-run is no loop.
                let has_do = e.get("do").is_some_and(|d| !d.is_null());
                let person_first =
                    e.get("human_required").and_then(Value::as_bool) == Some(true) && has_do;
                // Retry after_fix: the Do is the fix (installing a missing tool, R56, is the
                // agent's own), so the re-run after it meets something else, as the catalog's
                // `no_loop` holds for any cause whose re-run follows a Do.
                let fixed_first =
                    e.get("retry").and_then(Value::as_str) == Some("after_fix") && has_do;
                if same && !safe && !person_first && !fixed_first {
                    Err(format!(
                        "next {next:?} reruns the failing command without a safe retry"
                    ))
                } else {
                    Ok(())
                }
            }
            Rule::HumanRequiredMatchesTheStep => {
                let Some(e) = error else { return Ok(()) };
                let human = e.get("human_required").and_then(Value::as_bool) == Some(true);
                let handoff = e.get("next_kind").and_then(Value::as_str) == Some("handoff");
                let has_do = e.get("do").is_some_and(|d| !d.is_null());
                if handoff && !human {
                    Err("next_kind is handoff but human_required is false".into())
                } else if human && !handoff && !has_do {
                    Err("human_required with neither a handoff nor a person's Do".into())
                } else {
                    Ok(())
                }
            }
            Rule::NoCanaryValue => {
                let all = [
                    &o.text.stdout,
                    &o.text.stderr,
                    &o.json.stdout,
                    &o.json.stderr,
                ];
                match canaries()
                    .iter()
                    .find(|c| all.iter().any(|s| s.contains(c.as_str())))
                {
                    Some(c) => Err(format!("canary value {c} printed")),
                    None => Ok(()),
                }
            }
            Rule::NoEscapeSequence => {
                let all = [
                    &o.text.stdout,
                    &o.text.stderr,
                    &o.json.stdout,
                    &o.json.stderr,
                ];
                match all
                    .iter()
                    .flat_map(|s| s.chars())
                    .find(|c| control_char(*c))
                {
                    Some(c) => Err(format!("control character U+{:04X} printed", c as u32)),
                    None => Ok(()),
                }
            }
        }
    }
}

fn known_legacy() -> &'static BTreeSet<String> {
    static L: OnceLock<BTreeSet<String>> = OnceLock::new();
    L.get_or_init(|| {
        std::fs::read_to_string(snapshots().join("KNOWN_LEGACY.txt"))
            .unwrap_or_default()
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(str::to_string)
            .collect()
    })
}

/// The test of one rule on one cell: it holds, or it is a listed legacy failure that still
/// fails (an entry whose rule now holds must be removed).
fn rule_test(cell: &Cell, rule: Rule) {
    let o = outcome(cell);
    assert_undisturbed(cell, &o);
    let result = rule.check(cell, &o);
    let listed = known_legacy().contains(&format!("{} {}", cell.name(), rule.name()));
    assert_eq!(
        result.is_err(),
        listed,
        "{} {}: {}",
        cell.name(),
        rule.name(),
        match &result {
            Err(why) => format!("broken and not in KNOWN_LEGACY.txt: {why}"),
            Ok(()) => "holds now: remove it from KNOWN_LEGACY.txt".into(),
        }
    );
}

/// The committed snapshots are recorded on Linux. Other hosts word some messages for their
/// platform by design (the 1Password app holding the accounts on macOS, the core-dump
/// check), so they run the rules but skip the snapshot comparison.
fn snapshot_test(cell: &Cell) {
    if !cfg!(target_os = "linux") {
        return;
    }
    let o = outcome(cell);
    assert_undisturbed(cell, &o);
    let path = snapshots().join(format!("{}.snap", cell.name()));
    let got = o.snapshot(cell);
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

macro_rules! cells {
    ($($name:ident => $command:literal, $program:literal, $call:literal, $kind:literal;)*) => {
        /// Every committed cell.
        fn committed_cells() -> Vec<Cell> {
            vec![$(Cell {
                command: $command.into(),
                program: $program.into(),
                call: $call.into(),
                kind: $kind.into(),
            },)*]
        }
        $(
            #[allow(non_snake_case)]
            mod $name {
                use super::*;
                fn cell() -> Cell {
                    Cell {
                        command: $command.into(),
                        program: $program.into(),
                        call: $call.into(),
                        kind: $kind.into(),
                    }
                }
                #[test]
                fn json_is_one_document() {
                    rule_test(&cell(), Rule::JsonIsOneDocument);
                }
                #[test]
                fn code_is_in_the_catalog() {
                    rule_test(&cell(), Rule::CodeIsInTheCatalog);
                }
                #[test]
                fn next_parses() {
                    rule_test(&cell(), Rule::NextParses);
                }
                #[test]
                fn next_does_not_loop() {
                    rule_test(&cell(), Rule::NextDoesNotLoop);
                }
                #[test]
                fn human_required_matches_the_step() {
                    rule_test(&cell(), Rule::HumanRequiredMatchesTheStep);
                }
                #[test]
                fn no_canary_value() {
                    rule_test(&cell(), Rule::NoCanaryValue);
                }
                #[test]
                fn no_escape_sequence() {
                    rule_test(&cell(), Rule::NoEscapeSequence);
                }
                #[test]
                fn snapshot() {
                    snapshot_test(&cell());
                }
            }
        )*
    };
}

include!("snapshots/cells.rs");

// --- generation and the gates ---------------------------------------------------------------

/// The calls each command makes against the unfaulted world, as `(program, words)`, first
/// seen first.
/// Each command's calls, as `(program, words)`, first seen first.
type Discovered = BTreeMap<&'static str, Vec<(String, Vec<String>)>>;

fn discover() -> Discovered {
    static SEEN: OnceLock<Discovered> = OnceLock::new();
    SEEN.get_or_init(discover_now).clone()
}

fn discover_now() -> Discovered {
    COMMANDS
        .iter()
        .map(|(slug, args)| {
            let sc = Scenario::new("");
            let mut a: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            a.push("--json".into());
            sc.opv(&a);
            let mut seen = Vec::new();
            for c in sc.calls() {
                if !seen.contains(&c) {
                    seen.push(c);
                }
            }
            (*slug, seen)
        })
        .collect()
}

/// Every candidate cell, and the calls no fault can target (no subcommand words: a fault
/// without `call` would hit every call of the tool).
fn candidates() -> (Vec<Cell>, Vec<String>) {
    let mut cells = Vec::new();
    let mut untargetable = Vec::new();
    for (command, calls) in discover() {
        for (program, words) in calls {
            if words.is_empty() {
                untargetable.push(format!("{command}: {program} (no subcommand words)"));
                continue;
            }
            let kinds = KINDS
                .iter()
                .chain(if program == "ssh" { SSH_KINDS } else { &[] });
            for kind in kinds {
                cells.push(Cell {
                    command: command.to_string(),
                    program: program.clone(),
                    call: words.join(" "),
                    kind: kind.to_string(),
                });
            }
        }
    }
    cells.sort();
    cells.dedup();
    (cells, untargetable)
}

/// The skipped candidates committed in SKIPPED.md, by cell name.
fn committed_skips() -> BTreeSet<String> {
    std::fs::read_to_string(snapshots().join("SKIPPED.md"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.strip_prefix("| `"))
        .filter_map(|l| l.split('`').next())
        .map(str::to_string)
        .collect()
}

fn in_parallel<T: Send, R: Send>(items: Vec<T>, f: impl Fn(&T) -> R + Sync) -> Vec<(T, R)> {
    let n = std::thread::available_parallelism().map_or(4, |n| n.get());
    let queue = std::sync::Mutex::new(items.into_iter().collect::<Vec<_>>());
    let out = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|s| {
        for _ in 0..n {
            s.spawn(|| {
                loop {
                    let Some(item) = queue.lock().expect("queue").pop() else {
                        break;
                    };
                    let r = f(&item);
                    out.lock().expect("out").push((item, r));
                }
            });
        }
    });
    out.into_inner().expect("out")
}

/// §13.3: the committed cells and skips are exactly the candidates discovery finds today.
/// With `UPDATE_SNAPSHOTS=1` it runs every candidate and rewrites `cells.rs`, `SKIPPED.md`
/// and `COVERAGE.md` (and, with `MATRIX_SEED_LEGACY=1`, `KNOWN_LEGACY.txt`).
#[test]
fn the_committed_cells_are_the_discovered_candidates() {
    let (cands, untargetable) = candidates();
    if updating() {
        generate(cands, untargetable);
        return;
    }
    let want: BTreeSet<String> = cands.iter().map(Cell::name).collect();
    let have: BTreeSet<String> = committed_cells()
        .iter()
        .map(Cell::name)
        .chain(committed_skips())
        .collect();
    assert_eq!(
        want, have,
        "the calls changed: regenerate with UPDATE_SNAPSHOTS=1 (module docs)"
    );
}

/// Every path is migrated, so no rule may be excused again: `KNOWN_LEGACY.txt` stays empty.
#[test]
fn no_rule_is_excused_as_known_legacy() {
    assert!(known_legacy().is_empty(), "{:?}", known_legacy());
}

fn generate(cands: Vec<Cell>, untargetable: Vec<String>) {
    let (redundant, run): (Vec<Cell>, Vec<Cell>) = cands
        .into_iter()
        .partition(|c| tool_missing_elsewhere(c).is_some());
    let mut results = in_parallel(run, outcome);
    results.sort_by(|a, b| a.0.cmp(&b.0));
    let mut skip_rows: Vec<(String, String)> = Vec::new();
    let row = |cell: &Cell, why: &str| {
        (
            cell.name(),
            format!(
                "| `{}` | opv {} | {} {} | {} | {why} |\n",
                cell.name(),
                cell.args().join(" "),
                cell.program,
                cell.call,
                cell.kind
            ),
        )
    };
    for cell in &redundant {
        if let Some(why) = tool_missing_elsewhere(cell) {
            skip_rows.push(row(cell, &why));
        }
    }
    let mut cells_rs = String::from(
        "// @generated by `UPDATE_SNAPSHOTS=1 cargo nextest run --features fake --test e2e_matrix \
         the_committed_cells`: the live cells of the fault matrix (tests/e2e/matrix.rs).\n\
         cells! {\n",
    );
    let mut skipped = String::from(
        "# Fault matrix: skipped candidates\n\n\
         Generated by `tests/e2e/matrix.rs`. Each row is a command × call × fault the \
         simulator cannot answer yet: nobody has recorded that tool's reply to that call \
         under that fault in `tests/fixtures/<tool>/failures/` (opv-sim exit 86), or the \
         simulator does not model the call (exit 87), or the call fails or answers nothing without the fault, \
         so `malformed_output` has no output to damage (exit 88). A `tool_missing` row on a later call of a \
         tool is the run of that tool's first call: a tool that is not installed is missing for \
         every call. Most rows are `rate_limited`, \
         `server_error` and `forbidden` on op, flyctl and gh: those replies need a live \
         account that is throttled, failing or refused, and no such recording exists yet. \
         The replies are never invented (CONTRIBUTING: recordings, never invented output); \
         recording one turns its rows into live cells. The coverage gate \
         (tests/e2e/coverage.rs) checks every row states its reason.\n\n\
         | cell | command | call | fault | why |\n|---|---|---|---|---|\n",
    );
    let mut legacy = String::from(
        "# Rules a not-yet-migrated path breaks: `<cell> <rule>`. This list only shrinks\n\
         # (empty since every path is migrated); remove an entry once its rule holds.\n",
    );
    let mut legacy_n = 0;
    let mut codes: BTreeMap<String, usize> = BTreeMap::new();
    let mut live = 0;
    for (cell, o) in &results {
        if let Some(why) = o.skipped(cell) {
            skip_rows.push(row(cell, &why));
            continue;
        }
        live += 1;
        cells_rs.push_str(&format!(
            "    {} => {:?}, {:?}, {:?}, {:?};\n",
            cell.name(),
            cell.command,
            cell.program,
            cell.call,
            cell.kind
        ));
        if let Some(code) = o.document().and_then(|d| {
            d.pointer("/error/code")
                .and_then(Value::as_str)
                .map(str::to_string)
        }) {
            *codes.entry(code).or_default() += 1;
        }
        for rule in RULES {
            if rule.check(cell, o).is_err() {
                legacy_n += 1;
                legacy.push_str(&format!("{} {}\n", cell.name(), rule.name()));
            }
        }
    }
    cells_rs.push_str("}\n");
    skip_rows.sort();
    for (_, r) in &skip_rows {
        skipped.push_str(r);
    }
    if !untargetable.is_empty() {
        skipped.push_str("\n## Calls no fault can target\n\n");
        for u in &untargetable {
            skipped.push_str(&format!("- {u}\n"));
        }
    }
    let mut coverage = format!(
        "# Fault matrix: coverage (§13.4)\n\nGenerated by `tests/e2e/matrix.rs`. {live} live \
         cells; {} skipped.\n\n## Error codes reached\n\n| code | cells | catalog |\n|---|---|---|\n",
        skip_rows.len()
    );
    for (code, n) in &codes {
        let cat = if catalog_codes().contains(code) {
            "yes"
        } else {
            "legacy"
        };
        coverage.push_str(&format!("| `{code}` | {n} | {cat} |\n"));
    }
    coverage.push_str("\n## Catalog codes no cell reaches yet\n\n");
    for code in catalog_codes() {
        if !codes.contains_key(code) {
            coverage.push_str(&format!("- `{code}`\n"));
        }
    }
    let dir = snapshots();
    std::fs::create_dir_all(&dir).expect("snapshots dir");
    std::fs::write(dir.join("cells.rs"), cells_rs).expect("cells.rs");
    std::fs::write(dir.join("SKIPPED.md"), skipped).expect("SKIPPED.md");
    std::fs::write(dir.join("COVERAGE.md"), coverage).expect("COVERAGE.md");
    if std::env::var("MATRIX_SEED_LEGACY").is_ok_and(|v| v == "1") {
        std::fs::write(dir.join("KNOWN_LEGACY.txt"), legacy).expect("KNOWN_LEGACY.txt");
    }
    eprintln!("matrix: {live} live cells, {legacy_n} legacy rule failures");
}

/// Every path is migrated: no cell may break a rule as a known exception (J1).
#[test]
fn known_legacy_is_empty() {
    assert!(
        known_legacy().is_empty(),
        "KNOWN_LEGACY.txt lists {:?}; fix the rule instead",
        known_legacy()
    );
}

/// Every snapshot file belongs to a committed cell (a removed cell takes its snapshot).
#[test]
fn every_snapshot_belongs_to_a_cell() {
    let cells: BTreeSet<String> = committed_cells().iter().map(Cell::name).collect();
    let orphans: Vec<String> = std::fs::read_dir(snapshots())
        .map(|d| {
            d.filter_map(Result::ok)
                .filter_map(|e| e.file_name().to_str().map(str::to_string))
                .filter_map(|n| n.strip_suffix(".snap").map(str::to_string))
                .filter(|n| !cells.contains(n))
                .collect()
        })
        .unwrap_or_default();
    assert!(orphans.is_empty(), "snapshots without a cell: {orphans:?}");
}

// --- the harness's own logic ----------------------------------------------------------------

mod harness {
    use super::*;

    fn timeout_cell() -> Cell {
        Cell {
            command: "doctor_prod".into(),
            program: "kubectl".into(),
            call: "auth can-i".into(),
            kind: "timeout".into(),
        }
    }

    fn call(program: &str, words: &[&str]) -> (String, Vec<String>) {
        (
            program.into(),
            words.iter().map(|w| w.to_string()).collect(),
        )
    }

    fn disturbed() -> Outcome {
        Outcome {
            disturbed: Some("loaded".into()),
            ..Outcome::default()
        }
    }

    #[test]
    fn a_cut_off_call_the_fault_targets_is_no_disturbance() {
        let cut = [call("kubectl", &["auth", "can-i", "patch", "configmaps"])];
        assert_eq!(disturbance(&timeout_cell(), false, &cut), None);
    }

    #[test]
    fn a_cut_off_call_the_fault_does_not_target_disturbs_the_run() {
        let cut = [call("op", &["vault", "user", "list"])];
        assert!(disturbance(&timeout_cell(), false, &cut).is_some());
    }

    #[test]
    fn a_run_past_the_harness_limit_disturbs_it() {
        assert!(disturbance(&timeout_cell(), true, &[]).is_some());
    }

    #[test]
    fn a_disturbed_outcome_is_not_cached() {
        let dir = tempfile::tempdir().expect("temp dir");
        store(dir.path(), &timeout_cell(), &disturbed());
        let name = format!("{}.json", timeout_cell().name());
        assert!(!dir.path().join(name).exists());
    }

    #[test]
    fn an_undisturbed_outcome_is_cached() {
        let dir = tempfile::tempdir().expect("temp dir");
        store(dir.path(), &timeout_cell(), &Outcome::default());
        let name = format!("{}.json", timeout_cell().name());
        assert!(dir.path().join(name).exists());
    }

    /// Run the scenario's `kubectl auth can-i get deployments` wrapper, killing it after
    /// `after` as opv kills a call at its limit.
    fn kubectl_killed_after(sc: &Scenario, after: Duration) {
        let mut child = Command::new(sc.path("bin/kubectl"))
            .args(["auth", "can-i", "get", "deployments"])
            .env("OPV_SIM_WORLD", sc.path("world"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("run wrapper");
        let deadline = Instant::now() + after;
        while child.try_wait().expect("wait").is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn a_call_killed_before_it_answers_is_cut_off() {
        let sc = Scenario::new(&format!(
            "{}seconds = 5\n",
            timeout_cell().faults().replace("seconds = 60\n", "")
        ));
        kubectl_killed_after(&sc, Duration::from_millis(500));
        assert_eq!(
            sc.cut_off(),
            vec![call("kubectl", &["auth", "can-i", "get", "deployments"])]
        );
    }

    #[test]
    fn a_call_that_answers_is_not_cut_off() {
        let sc = Scenario::new("");
        kubectl_killed_after(&sc, Duration::from_secs(60));
        assert!(sc.cut_off().is_empty());
    }
}
