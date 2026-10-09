//! `doctor` use case (FR-3).
//!
//! Checks, one line each, always all of them: configuration valid; `op --version`;
//! the 1Password session via [`onepassword::diagnose`] (`op whoami`, and `op account list`
//! when it fails; free of rate-limit cost per D0), the same classification a failed item
//! read uses (FR-26); then, for each provider some environment uses, the provider's own
//! checks (`TargetConfig::doctor`, FR-37). Environments without a target are listed as
//! skipped. Returns the error of the first failing check.
//!
//! A tool version opv was not tested with (op older than 2.40.0, or a provider CLI outside
//! its tested range) is a `warn` line, never a failure.
//!
//! Tool output is never echoed: only a version string that matches a strict pattern, and
//! from `op whoami` only the account type (`SERVICE_ACCOUNT`, ...), never identity or
//! tokens; from `op account list` only the number of accounts. Unscoped, no item is read.
//!
//! With `--env` (P6) one more check, `item`, reads that environment's item once by vault
//! and item ID (FR-13; skipped when op is not signed in) and plans it against the declared
//! keys of the selected product(s) exactly as `check` does: `ok item: <vault>/<item>
//! readable (<n> field(s) in section <p>)`, or a failing line naming each key that is not
//! ready (names and states only, never a value) and the `opv check` command. So doctor is
//! never all clear when `check` would fail.
//!
//! `--json` (P18) prints one document instead of the lines: `{schema_version: 1, checks:
//! [{name, status: ok|warn|fail|skip, detail, next}], next}`; `detail` is the line's first
//! line, `next` its remediation (or null), the top-level `next` the first failure's.
//!
//! A failing check prints the next command for the detected platform and shell (FR-26):
//! the sign-in command, `op account add`, or the install command.
//!
//! The output ends with one `Next step` line (FR-22): the first failing check and the safe
//! command that addresses it (the first remediation line of that check), or `nothing
//! pending`. Text only, never a prompt (FR-9).

use std::collections::BTreeSet;
use std::io::{self, Write};

use super::write_err;
use crate::adapters::probe::{parse_version, spawn_tool, version_in};
use crate::adapters::{onepassword, registry};
use crate::domain::model::key_label;
use crate::domain::{Fleet, KeyState};
use crate::error::Error;
use crate::host::{Host, OP_CLI};
use crate::provider::{TargetConfig, Verdict as Check};
use crate::runner::CommandRunner;

/// Oldest `op` release opv is tested with.
pub const OP_TESTED_MIN: (u64, u64, u64) = (2, 40, 0);

/// Name of the configuration check (its message is parser output, see [`next_step`]).
const CONFIG_CHECK: &str = "config";

/// Name of the item check (`--env` only, P6).
const ITEM_CHECK: &str = "item";

/// The fixed step for an invalid configuration.
const CONFIG_FIX: &str = "fix secrets.toml (see the config line above) and re-run `opv doctor`";

/// The step when there is no configuration yet (P3).
const FIRST_RUN: &str =
    "opv init <env> --vault <vault title> --item <item title>   (new project: opv setup)";

/// The step for a failure without a remediation line of its own.
const RERUN: &str = "fix the failure reported above and re-run `opv doctor`";

pub fn run_scoped(
    config: Result<Fleet, Error>,
    env: Option<&str>,
    product: Option<&str>,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    run_scoped_as(config, env, product, false, r, out)
}

/// [`run_scoped`], printing one JSON document instead of the check lines when `json` (P18).
pub fn run_scoped_as(
    config: Result<Fleet, Error>,
    env: Option<&str>,
    product: Option<&str>,
    json: bool,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let config = match env {
        Some(e) => config.and_then(|f| super::local::select(&f, e, product, false)),
        None if product.is_some() => Err(Error::Config("--product requires --env".into())),
        None => config,
    };
    // Scoped to environments without a target: local runs are all they are for, so a
    // Windows op.exe is a failure there and only a warning elsewhere (#54).
    let local_only = env.is_some()
        && config
            .as_ref()
            .is_ok_and(|f| f.environments.values().all(|e| e.target().is_none()));
    let scope = Scope {
        env,
        product,
        local_only,
        json,
    };
    run_on(config, r, &Host::detect, scope, out)
}

pub fn run(
    config: Result<Fleet, Error>,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    run_on(config, r, &Host::detect, Scope::default(), out)
}

/// [`run`] on a given host (tests).
pub fn run_with(
    config: Result<Fleet, Error>,
    r: &dyn CommandRunner,
    host: &Host,
    out: &mut dyn Write,
) -> Result<(), Error> {
    run_on(config, r, &|| *host, Scope::default(), out)
}

/// What `doctor` was asked to check, and how to print it.
#[derive(Debug, Clone, Copy, Default)]
struct Scope<'a> {
    /// `--env`: the item check reads this environment's item (P6).
    env: Option<&'a str>,
    /// `--product` (with `--env`).
    product: Option<&'a str>,
    /// Every environment in scope has no target (#54).
    local_only: bool,
    /// `--json` (P18).
    json: bool,
}

/// The state of one check line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Ok,
    Warn,
    Fail,
    Skip,
}

impl State {
    /// The fixed-width word the text output starts with.
    fn word(self) -> &'static str {
        match self {
            State::Ok => "ok  ",
            State::Warn => "warn",
            State::Fail => "FAIL",
            State::Skip => "skip",
        }
    }

    /// The JSON `status` (P18).
    fn json(self) -> &'static str {
        match self {
            State::Ok => "ok",
            State::Warn => "warn",
            State::Fail => "fail",
            State::Skip => "skip",
        }
    }
}

/// One check: its name, state and text (names, versions and commands only, never a value
/// or tool output; the first line is the detail, indented lines are remediation).
struct Row {
    name: String,
    state: State,
    text: String,
}

impl Row {
    /// The remediation for this row: its first indented line (without a `next: ` lead),
    /// or the fixed configuration step. `None` for a row with nothing to do.
    fn next(&self) -> Option<String> {
        if self.state == State::Fail && self.name == CONFIG_CHECK {
            // No file yet is a first run, not a file to fix (P3).
            if self.text.contains(crate::config::NOT_FOUND) {
                return Some(FIRST_RUN.into());
            }
            return Some(CONFIG_FIX.into());
        }
        if matches!(self.state, State::Ok | State::Skip) {
            return None;
        }
        self.text
            .lines()
            .skip(1)
            .find_map(|l| l.strip_prefix("  "))
            .map(|l| l.strip_prefix("next: ").unwrap_or(l).trim().to_string())
            .filter(|h| !h.is_empty())
    }
}

/// The rows collected so far, and the first failure (returned as the run's error).
#[derive(Default)]
struct Report {
    rows: Vec<Row>,
    first: Option<(String, Error)>,
}

impl Report {
    fn push(&mut self, name: &str, res: Result<Check, Error>) {
        let (state, text) = match res {
            Ok(Check::Ok(t)) => (State::Ok, t),
            Ok(Check::Warn(t)) => (State::Warn, t),
            Err(e) => {
                let t = e.to_string();
                if self.first.is_none() {
                    self.first = Some((name.to_string(), e));
                }
                (State::Fail, t)
            }
        };
        self.rows.push(Row {
            name: name.to_string(),
            state,
            text,
        });
    }

    /// A failing check whose line text differs from its error (the item check, P6).
    fn fail(&mut self, name: &str, text: String, e: Error) {
        if self.first.is_none() {
            self.first = Some((name.to_string(), e));
        }
        self.rows.push(Row {
            name: name.to_string(),
            state: State::Fail,
            text,
        });
    }

    fn skip(&mut self, name: &str, text: String) {
        self.rows.push(Row {
            name: name.to_string(),
            state: State::Skip,
            text,
        });
    }

    fn passed(&self, name: &str) -> bool {
        self.rows
            .iter()
            .any(|r| r.name == name && matches!(r.state, State::Ok | State::Warn))
    }
}

/// The host is detected only when a check needs it (a failure or a credential decision).
fn run_on(
    config: Result<Fleet, Error>,
    r: &dyn CommandRunner,
    host: &dyn Fn() -> Host,
    scope: Scope<'_>,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let mut report = Report::default();
    let (fleet, config_line) = match config {
        Ok(f) => {
            let summary = config_summary(&f);
            (Some(f), Ok(Check::Ok(summary)))
        }
        Err(e) => (None, Err(e)),
    };
    // (one target per provider in use, environments without a target)
    let targets = fleet.as_ref().map(|f| {
        (
            providers_in_use(f),
            f.environments
                .iter()
                .filter(|(_, e)| e.target().is_none())
                .map(|(n, _)| n.clone())
                .collect::<Vec<_>>(),
        )
    });
    report.push(CONFIG_CHECK, config_line);
    let op_check = op_version(r, host);
    let op_present = op_check.is_ok();
    report.push("op", op_check);
    if op_present {
        report.push("op auth", op_auth(r, host, scope.env).map(Check::Ok));
    } else {
        // One failure per cause: the op line already says why (review #12).
        report.skip("op auth", "op not available (see the op line above)".into());
    }
    if let Some(env) = scope.env {
        match &fleet {
            Some(f) if report.passed("op auth") => {
                item_check(f, env, scope.product, r, &mut report)
            }
            Some(_) => report.skip(
                ITEM_CHECK,
                "not checked (see the op auth line above)".into(),
            ),
            None => report.skip(ITEM_CHECK, "not checked (configuration invalid)".into()),
        }
    }
    let default = registry::DEFAULT;
    match targets {
        Some((used, without)) if !used.is_empty() => {
            for t in &used {
                for c in t.doctor(r, host) {
                    report.push(&c.name, c.outcome);
                }
            }
            if !without.is_empty() {
                // One provider in use: its section name; several: "target".
                let section = match used.as_slice() {
                    [only] => only.provider().section(),
                    _ => "target",
                };
                report.skip(
                    section,
                    format!(
                        "no {section} section in environment(s) {} (run, config export and item skeleton only)",
                        without.join(", ")
                    ),
                );
            }
        }
        Some(_) => {
            for check in default.doctor_checks() {
                report.skip(
                    check,
                    format!("no environment has a {} section", default.section()),
                );
            }
        }
        None => {
            for check in default.doctor_checks() {
                report.skip(check, "not checked (configuration invalid)".into());
            }
        }
    }
    if cfg!(windows) {
    } else if op_present {
        report.push("op local run", local_run(r, scope.local_only));
    } else {
        report.skip(
            "op local run",
            "op not available (see the op line above)".into(),
        );
    }
    report.push("opv", opv_on_path(r));
    if scope.json {
        print_json(&report, out)?;
    } else {
        print_text(&report, out)?;
    }
    match report.first {
        // Every check line is printed above; the error repeats only the category and the
        // failing check, so a long message (a TOML snippet) is not printed twice (#12).
        Some((check, e)) => Err(summary_error(&check, e)),
        None => Ok(()),
    }
}

fn print_text(report: &Report, out: &mut dyn Write) -> Result<(), Error> {
    for row in &report.rows {
        writeln!(out, "{}  {}: {}", row.state.word(), row.name, row.text).map_err(write_err)?;
    }
    let next = match report.rows.iter().find(|r| r.state == State::Fail) {
        Some(row) => next_step(row),
        None => "Next step: nothing pending".into(),
    };
    writeln!(out, "{next}").map_err(write_err)
}

/// P18: `{schema_version: 1, checks: [{name, status, detail, next}], next}`. `detail` is
/// the first line of the check's text (names, versions and commands only), `next` its
/// remediation or null; the top-level `next` is the first failing check's, or null.
fn print_json(report: &Report, out: &mut dyn Write) -> Result<(), Error> {
    let checks: Vec<serde_json::Value> = report
        .rows
        .iter()
        .map(|row| {
            serde_json::json!({
                "name": row.name,
                "status": row.state.json(),
                "detail": row.text.lines().next().unwrap_or(""),
                "next": row.next(),
            })
        })
        .collect();
    let next = report
        .rows
        .iter()
        .find(|r| r.state == State::Fail)
        .map(|row| row.next().unwrap_or_else(|| RERUN.into()));
    let doc = serde_json::json!({"schema_version": 1, "checks": checks, "next": next});
    writeln!(out, "{doc}").map_err(write_err)
}

/// The error `doctor` returns: the first failing check's category (its exit code, FR-10)
/// with a short message, since its full text is already in the output.
fn summary_error(check: &str, e: Error) -> Error {
    let m = format!("the {check} check failed (see the doctor output above)");
    match e {
        Error::Config(_) => Error::Config(m),
        Error::Dependency(_) => Error::Dependency(m),
        Error::Auth(_) => Error::Auth(m),
        Error::Source(_) => Error::Source(m),
        Error::Target(_) => Error::Target(m),
        Error::Policy(_) => Error::Policy(m),
        Error::Unknown(_) => Error::Unknown(m),
        findings @ Error::Findings(_) => findings,
    }
}

/// P6: `doctor --env` reads the environment's item once, by IDs (FR-13), and plans it
/// against the declared keys exactly as `check` does, so doctor is never all clear when
/// `check` would fail. Reports names, counts and states only; never a value.
fn item_check(
    fleet: &Fleet,
    env_name: &str,
    product: Option<&str>,
    r: &dyn CommandRunner,
    report: &mut Report,
) {
    let Ok(env) = fleet.environment(env_name) else {
        return report.skip(ITEM_CHECK, "not checked (undefined environment)".into());
    };
    let sections: BTreeSet<String> = fleet.products.keys().cloned().collect();
    let item = if fleet.is_simple() {
        onepassword::read_item_as(r, env, fleet.profile)
    } else {
        onepassword::read_item_in_sections(r, env, fleet.profile, &sections)
    };
    let item = match item {
        Ok(i) => i,
        Err(e) => return report.push(ITEM_CHECK, Err(e)),
    };
    let where_ = if fleet.is_simple() {
        String::new()
    } else if sections.len() == 1 {
        format!(" in section {}", sections.iter().next().expect("one"))
    } else {
        format!(
            " in sections {}",
            sections.iter().cloned().collect::<Vec<_>>().join(", ")
        )
    };
    let readable = format!(
        "{}/{} readable ({} field(s){where_})",
        env.vault_id,
        env.item_id,
        item.fields.len()
    );
    let mut selected = fleet.clone();
    for e in selected.environments.values_mut() {
        e.target = None;
    }
    let none = BTreeSet::new();
    let plan = match super::plan_item(&selected, env_name, item.fields, None, &none, &none) {
        Ok((plan, _)) => plan,
        Err(e) => return report.push(ITEM_CHECK, Err(e)),
    };
    let blocking: Vec<String> = plan
        .rows
        .iter()
        .filter_map(|row| {
            let state = match &row.state {
                KeyState::Missing => "missing".to_string(),
                KeyState::WrongKind => "wrong kind".to_string(),
                KeyState::RuleFailed(rule, _) => format!("failed {rule}"),
                KeyState::Ready | KeyState::Skipped => return None,
            };
            Some(format!("{} ({state})", key_label(&row.product, &row.key)))
        })
        .collect();
    if blocking.is_empty() {
        return report.push(ITEM_CHECK, Ok(Check::Ok(readable)));
    }
    let check = match product {
        Some(p) => format!("opv check {env_name} --product {p}"),
        None if fleet.is_simple() => format!("opv check {env_name}"),
        None => {
            let first = plan
                .rows
                .iter()
                .find(|r| !matches!(r.state, KeyState::Ready | KeyState::Skipped))
                .map_or("<product>", |r| r.product.as_str());
            format!("opv check {env_name} --product {first}")
        }
    };
    report.fail(
        ITEM_CHECK,
        format!(
            "{readable}, but {} key(s) not ready: {}\n  next: fill them in 1Password, then {check}",
            blocking.len(),
            blocking.join(", ")
        ),
        Error::Findings(blocking.len()),
    );
}

/// One target per provider and named store some environment uses, in registry order
/// (FR-37, FR-39): a target that keeps its secrets in a named store also checks that store
/// and its binding.
fn providers_in_use(f: &Fleet) -> Vec<&dyn TargetConfig> {
    let mut used: Vec<&dyn TargetConfig> = Vec::new();
    let store_of = |t: &dyn TargetConfig| t.secrets_in().map(|s| s.name().to_string());
    for t in f.environments.values().filter_map(|e| e.target()) {
        if !used.iter().any(|u| {
            u.provider().section() == t.provider().section() && store_of(*u) == store_of(t)
        }) {
            used.push(t);
        }
    }
    used.sort_by_key(|t| {
        registry::PROVIDERS
            .iter()
            .position(|p| p.section() == t.provider().section())
    });
    used
}

/// `valid (N environment(s), M product(s))`, or under the simple profile, whose one
/// product is hidden (FR-20), `valid (N environment(s), M key(s))`.
fn config_summary(f: &Fleet) -> String {
    let envs = f.environments.len();
    if f.is_simple() {
        let keys: usize = f.products.values().map(|p| p.keys.len()).sum();
        format!("valid ({envs} environment(s), {keys} key(s))")
    } else {
        format!(
            "valid ({envs} environment(s), {} product(s))",
            f.products.len()
        )
    }
}

/// The `Next step` line for the first failing check (FR-22).
///
/// A configuration failure gets a fixed step: its message is parser output (a TOML error
/// carries a `  |` source gutter), not a layout opv controls. For doctor's own tool and auth
/// checks, whose messages opv writes, the step is that check's first remediation line (the
/// install, sign-in, `op account add` or log-in command the failure already prints, FR-26),
/// or the fix-and-re-run hint when it has none. Never tool output or a value (SR-1).
fn next_step(row: &Row) -> String {
    let check = &row.name;
    match row.next() {
        Some(h) => format!("Next step ({check}): {h}"),
        None => format!("Next step ({check}): {RERUN}"),
    }
}

fn op_version(r: &dyn CommandRunner, host: &dyn Fn() -> Host) -> Result<Check, Error> {
    let o = spawn_tool(r, OP_CLI, host, &["--version"])?;
    if o.status != 0 {
        return Err(Error::Dependency(format!(
            "op --version failed (exit {})",
            o.status
        )));
    }
    let (a, b, c) = OP_TESTED_MIN;
    Ok(match version_in(&o.stdout) {
        Some(v) if parse_version(&v).is_some_and(|n| n >= OP_TESTED_MIN) => {
            Check::Ok(format!("version {v}"))
        }
        // An older op is installed already: the step is an upgrade, not an install (#13).
        Some(v) => Check::Warn(format!(
            "version {v}; opv is tested with op {a}.{b}.{c} or newer\n  {}",
            op_upgrade_hint(&host())
        )),
        None => Check::Warn(format!(
            "present, version not recognised; opv is tested with op {a}.{b}.{c} or newer\n  {}",
            op_upgrade_hint(&host())
        )),
    })
}

/// How to upgrade an installed `op` on this platform.
fn op_upgrade_hint(h: &Host) -> &'static str {
    use crate::host::Platform;
    match (h.ci, h.platform) {
        (true, _) => {
            "upgrade op in the CI job (GitHub Actions: 1password/install-cli-action installs the latest)"
        }
        (false, Platform::MacOs) => "upgrade: brew upgrade 1password-cli",
        (false, Platform::Windows) => "upgrade: winget upgrade AgileBits.1Password.CLI",
        (false, _) => "upgrade: op update (or your package manager: apt, dnf)",
    }
}

/// The 1Password session, classified exactly as a failed item read is (FR-26).
fn op_auth(
    r: &dyn CommandRunner,
    host: &dyn Fn() -> Host,
    env: Option<&str>,
) -> Result<String, Error> {
    use onepassword::Session;
    match onepassword::diagnose(r, host)? {
        Session::SignedIn(t) => Ok(format!("signed in ({t})")),
        Session::Unknown => Err(Error::Dependency(
            "op whoami did not run to completion; the 1Password session could not be checked"
                .into(),
        )),
        s => Err(onepassword::session_error(s, &host(), None, env)
            .expect("every other session is an error")),
    }
}

/// Whether `opv run` can work here: the first `op` on PATH must be native, because a Windows
/// `op.exe` reached from WSL cannot start a Linux child (#54). Local-only scopes fail on it;
/// everything else warns, since deployment commands still work through `op.exe`.
fn local_run(r: &dyn CommandRunner, local_only: bool) -> Result<Check, Error> {
    // A URL, not a repository path: a binary install has no docs folder (#17).
    let windows_op = format!(
        "op is the Windows op.exe, which cannot start a Linux child, so `opv run` will fail \
         here\n  install the Linux 1Password CLI in WSL and sign in: see {}/local-development.md#wsl",
        crate::DOCS_URL
    );
    match r.local_run_supported() {
        Ok(()) => Ok(Check::Ok(
            "native op; opv run can start local commands".into(),
        )),
        Err(e) if e.kind() == io::ErrorKind::Unsupported && local_only => {
            Err(Error::Dependency(windows_op))
        }
        Err(e) if e.kind() == io::ErrorKind::Unsupported => Ok(Check::Warn(windows_op)),
        Err(e) if local_only => Err(Error::Dependency(format!(
            "cannot inspect op on PATH ({})",
            e.kind()
        ))),
        Err(e) => Ok(Check::Warn(format!(
            "cannot inspect op on PATH ({})",
            e.kind()
        ))),
    }
}

/// Task I: every `opv` on PATH, one check line. The npm `bin` wrapper runs the canonical
/// binary, so a wrapper beside the binary is the intended state and reads `ok`. A second
/// native copy, or a wrapper whose package version differs from the binary, is a warning
/// naming the command that fixes it. Never fails the run: a candidate that cannot be read
/// still leaves the others reported.
fn opv_on_path(r: &dyn CommandRunner) -> Result<Check, Error> {
    use crate::host::OpvCopy;
    let copies = crate::host::opv_copies_on_path();
    let mut binaries: Vec<(std::path::PathBuf, String)> = Vec::new();
    let mut wrappers: Vec<(std::path::PathBuf, Option<String>)> = Vec::new();
    for copy in copies {
        match copy {
            OpvCopy::Binary(p) => {
                let program = p.to_string_lossy().into_owned();
                let call = crate::runner::Call::new(program.as_str(), &["--version"]);
                let version = match r.probe(&call, crate::runner::PROBE_TIMEOUT) {
                    Ok(o) if o.status == 0 => version_in(o.stdout.as_slice())
                        .unwrap_or_else(|| "version not recognised".into()),
                    _ => "version not recognised".into(),
                };
                binaries.push((p, version));
            }
            OpvCopy::NpmWrapper { path, version } => wrappers.push((path, version)),
        }
    }
    let Some((first, first_version)) = binaries.first() else {
        return Ok(match wrappers.first() {
            None => Check::Ok("not found on PATH".into()),
            Some((p, v)) => Check::Ok(format!(
                "{} {} (npm wrapper running its bundled copy; run: npm rebuild -g @matthew-cochran/opv)",
                p.display(),
                v.as_deref().unwrap_or("version not recognised")
            )),
        });
    };
    let mut fixes: Vec<String> = binaries
        .iter()
        .skip(1)
        .map(|(p, _)| removal_command(p))
        .collect();
    let stale_wrapper = wrappers.iter().any(|(_, v)| {
        v.as_deref()
            .is_some_and(|v| v != first_version.trim_start_matches('v'))
    });
    if stale_wrapper || wrappers.len() > 1 {
        fixes.push("npm update -g @matthew-cochran/opv".into());
    }
    if fixes.is_empty() {
        let also = if wrappers.is_empty() {
            ""
        } else {
            " (also run by the npm wrapper)"
        };
        return Ok(Check::Ok(format!(
            "{} {first_version}{also}",
            first.display()
        )));
    }
    let mut listed: Vec<String> = binaries
        .iter()
        .map(|(p, v)| format!("{} {v}", p.display()))
        .collect();
    listed.extend(wrappers.iter().map(|(p, v)| {
        format!(
            "{} {} (npm wrapper)",
            p.display(),
            v.as_deref().unwrap_or("version not recognised")
        )
    }));
    Ok(Check::Warn(format!(
        "{}; make them one install: {}",
        listed.join(", "),
        fixes.join(", ")
    )))
}

/// The command that removes one opv copy on this platform.
fn removal_command(p: &std::path::Path) -> String {
    if cfg!(windows) {
        format!("del \"{}\"", p.display())
    } else {
        format!("rm {}", p.display())
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;
    use crate::app::testutil::*;
    use crate::runner::Output;
    use crate::runner::fake::FakeRunner;

    const WHOAMI: &str = r#"{"url":"https://my.1password.com","email":"ci-FIXTUREVALUE@example.com","user_uuid":"UFIXTUREVALUE","account_uuid":"AFIXTUREVALUE","user_type":"SERVICE_ACCOUNT"}"#;

    const FLY_WHOAMI: &str = "ops-FIXTUREVALUE@example.com\n";

    fn good() -> Vec<Output> {
        vec![
            Output::success(b"2.40.0\n".to_vec()),
            Output::success(WHOAMI.as_bytes().to_vec()),
            Output::success(
                b"flyctl v0.4.112 linux/amd64 Commit: ca63052e BuildDate: x\n".to_vec(),
            ),
            Output::success(FLY_WHOAMI.as_bytes().to_vec()),
        ]
    }

    fn linux() -> Host {
        Host::from_env(&crate::host::FakeEnv::new("linux").shell("/bin/bash"))
    }

    /// config, op, op auth, flyctl, fly auth, (off Windows) op local run, and opv.
    const CHECK_LINES: usize = if cfg!(windows) { 6 } else { 7 };

    /// Doctor scoped to environments without a target (`doctor --env dev`), on Linux.
    #[cfg(not(windows))]
    fn doctor_local_only(r: &FakeRunner) -> (Result<(), Error>, String) {
        let mut out = Vec::new();
        let scope = Scope {
            local_only: true,
            ..Scope::default()
        };
        let res = run_on(Ok(fleet()), r, &|| linux(), scope, &mut out);
        (res, text_of(&out))
    }

    #[cfg(not(windows))]
    fn windows_op(r: &FakeRunner) -> &FakeRunner {
        *r.local_run_error.borrow_mut() = Some(io::ErrorKind::Unsupported);
        r
    }

    fn doctor(config: Result<Fleet, Error>, r: &FakeRunner) -> (Result<(), Error>, String) {
        let mut out = Vec::new();
        let res = run_with(config, r, &linux(), &mut out);
        (res, text_of(&out))
    }

    /// The check lines only (remediation lines under a check are indented; the closing
    /// `Next step` line is not a check).
    fn checks(out: &str) -> Vec<&str> {
        out.lines()
            .filter(|l| !l.starts_with("  ") && !l.starts_with("Next step"))
            .collect()
    }

    fn next_line(out: &str) -> &str {
        out.lines().last().unwrap()
    }

    #[test]
    fn all_checks_pass_one_line_each() {
        let r = FakeRunner::new(good());
        let (res, out) = doctor(Ok(fleet()), &r);
        res.unwrap();
        let lines = checks(&out);
        assert_eq!(lines.len(), CHECK_LINES, "{out}");
        assert!(
            lines[0].starts_with("ok") && lines[0].contains("config"),
            "{out}"
        );
        assert!(
            lines[1].contains("op") && lines[1].contains("2.40.0"),
            "{out}"
        );
        assert!(lines[2].contains("SERVICE_ACCOUNT"), "{out}");
        assert!(
            lines[3].contains("flyctl") && lines[3].contains("v0.4.112"),
            "{out}"
        );
        assert!(
            lines[4].starts_with("ok") && lines[4].contains("fly auth"),
            "{out}"
        );
        assert_eq!(
            argvs(&r),
            vec![
                "op --version",
                "op whoami --format json",
                "flyctl version",
                "flyctl auth whoami"
            ]
        );
    }

    /// `op whoami` output names the account; only the account type is printed.
    #[test]
    fn whoami_identity_is_never_printed() {
        let r = FakeRunner::new(good());
        let (_, out) = doctor(Ok(fleet()), &r);
        assert_no_values(&out);
        assert!(!out.contains("example.com"), "{out}");
        assert!(!out.contains("1password.com"), "{out}");
    }

    /// Doctor never reads an item (that would cost a rate-limited request).
    #[test]
    fn doctor_never_reads_an_item() {
        let r = FakeRunner::new(good());
        doctor(Ok(fleet()), &r).0.unwrap();
        assert!(!r.argv_contains("item"));
    }

    #[test]
    fn op_missing_is_dependency_and_every_check_still_prints() {
        let r = FakeRunner::new([]);
        r.push_io_error(io::ErrorKind::NotFound);
        r.responses.borrow_mut().push_back(Ok(good().remove(2)));
        r.responses.borrow_mut().push_back(Ok(good().remove(3)));
        let (res, out) = doctor(Ok(fleet()), &r);
        let e = res.unwrap_err();
        assert!(matches!(e, Error::Dependency(_)), "{e}");
        let lines = checks(&out);
        assert_eq!(lines.len(), CHECK_LINES, "{out}");
        assert!(lines[3].starts_with("ok"), "{out}");
        assert!(lines[1].starts_with("FAIL"), "{out}");
        // #12: one failure per cause; op auth is skipped, not failed a second time.
        assert!(lines[2].starts_with("skip  op auth"), "{out}");
        // FR-26: the install command for the detected OS, under the failing check.
        assert!(
            out.contains("op not found on PATH\n  install op from https://developer.1password.com"),
            "{out}"
        );
    }

    #[test]
    fn op_not_signed_in_is_auth() {
        let mut g = good();
        g[1] = Output::failure(1);
        g.insert(2, Output::success(br#"[{"url":"x"}]"#.to_vec()));
        let r = FakeRunner::new(g);
        let (res, out) = doctor(Ok(fleet()), &r);
        let e = res.unwrap_err();
        assert!(matches!(e, Error::Auth(_)), "{e}");
        assert_eq!(e.exit_code(), 7);
        let lines = checks(&out);
        assert!(
            lines[2].starts_with("FAIL  op auth: authentication error: not signed in"),
            "{out}"
        );
        assert!(out.contains("\n  sign in: opv login\n"), "{out}");
        assert_eq!(lines.len(), CHECK_LINES, "{out}");
        // Doctor and the read path share one classification: whoami, then account list.
        assert_eq!(
            argvs(&r)[1..3],
            ["op whoami --format json", "op account list --format json"]
        );
    }

    #[test]
    fn flyctl_missing_is_dependency() {
        let r = FakeRunner::new(good().into_iter().take(2));
        r.push_io_error(io::ErrorKind::NotFound);
        r.push_io_error(io::ErrorKind::NotFound);
        let (res, out) = doctor(Ok(fleet()), &r);
        assert!(matches!(res, Err(Error::Dependency(_))), "{res:?}");
        assert!(out.lines().nth(3).unwrap().starts_with("FAIL"), "{out}");
    }

    /// Invalid config is reported first (the first failing category) but the tool checks
    /// still run and print.
    #[test]
    fn invalid_config_is_config_error_and_other_checks_still_print() {
        let r = FakeRunner::new(good());
        let (res, out) = doctor(Err(Error::Config("invalid secrets.toml: boom".into())), &r);
        let e = res.unwrap_err();
        assert!(matches!(e, Error::Config(_)), "{e}");
        let lines = checks(&out);
        assert_eq!(lines.len(), CHECK_LINES, "{out}");
        assert!(
            lines[0].starts_with("FAIL") && lines[0].contains("boom"),
            "{out}"
        );
        assert!(lines[1].starts_with("ok"), "{out}");
    }

    /// FR-3: Fly authentication by exit status; its stdout (an email) is never printed.
    #[test]
    fn fly_auth_passes_without_printing_identity() {
        let r = FakeRunner::new(good());
        let (res, out) = doctor(Ok(fleet()), &r);
        res.unwrap();
        assert!(checks(&out).contains(&"ok    fly auth: signed in"), "{out}");
        assert_no_values(&out);
        assert!(!out.contains("example.com"), "{out}");
    }

    #[test]
    fn fly_not_signed_in_is_auth_and_identity_not_printed() {
        let mut g = good();
        g[3] = Output {
            status: 1,
            stdout: zeroize::Zeroizing::new(FLY_WHOAMI.as_bytes().to_vec()),
        };
        let r = FakeRunner::new(g);
        let (res, out) = doctor(Ok(fleet()), &r);
        let e = res.unwrap_err();
        assert!(matches!(e, Error::Auth(_)), "{e}");
        assert!(
            out.lines().nth(4).unwrap().starts_with("FAIL  fly auth"),
            "{out}"
        );
        assert_no_values(&out);
        assert_no_values(&e.to_string());
    }

    /// FR-26: with a Fly token set, a failing `flyctl auth whoami` is a warning (app-scoped
    /// deploy tokens cannot run it), not an authentication failure.
    #[test]
    fn fly_auth_failure_with_fly_token_is_a_warning() {
        let mut g = good();
        g[3] = Output::failure(1);
        let r = FakeRunner::new(g);
        let h = Host::from_env(
            &crate::host::FakeEnv::new("linux")
                .shell("/bin/bash")
                .var("FLY_API_TOKEN"),
        );
        let mut out = Vec::new();
        run_with(Ok(fleet()), &r, &h, &mut out).unwrap();
        let out = text_of(&out);
        assert!(
            out.lines()
                .any(|l| l.starts_with("warn  fly auth:") && l.contains("FLY_API_TOKEN")),
            "{out}"
        );
        assert!(!out.contains("auth login"), "{out}");
    }

    /// I8: tested versions print no warning.
    #[test]
    fn tested_versions_do_not_warn() {
        let r = FakeRunner::new(good());
        let (res, out) = doctor(Ok(fleet()), &r);
        res.unwrap();
        assert!(!out.contains("warn"), "{out}");
    }

    /// I8: an older op, or a flyctl outside 0.4.x from 0.4.112, warns but does not fail.
    #[test]
    fn untested_versions_warn_but_pass() {
        for (op, fly, warn_op, warn_fly) in [
            ("2.39.9\n", "flyctl v0.4.112 linux/amd64\n", true, false),
            ("2.30.0\n", "flyctl v0.4.111 linux/amd64\n", true, true),
            ("2.41.0\n", "flyctl v0.3.0 linux/amd64\n", false, true),
            ("3.0.0\n", "flyctl v0.4.112\n", false, false),
        ] {
            let mut g = good();
            g[0] = Output::success(op.as_bytes().to_vec());
            g[2] = Output::success(fly.as_bytes().to_vec());
            let r = FakeRunner::new(g);
            let (res, out) = doctor(Ok(fleet()), &r);
            res.unwrap();
            let lines = checks(&out);
            assert_eq!(lines[1].starts_with("warn  op:"), warn_op, "{out}");
            assert_eq!(lines[3].starts_with("warn  flyctl:"), warn_fly, "{out}");
            if warn_op {
                assert!(lines[1].contains("2.40.0"), "{out}");
            }
            if warn_fly {
                assert!(lines[3].contains("0.4.112"), "{out}");
            }
        }
    }

    #[test]
    fn later_flyctl_patch_does_not_warn() {
        let mut g = good();
        g[2] = Output::success(b"flyctl v0.4.113 linux/amd64\n".to_vec());
        let r = FakeRunner::new(g);
        let (res, out) = doctor(Ok(fleet()), &r);
        res.unwrap();
        assert!(checks(&out)[3].starts_with("ok    flyctl:"), "{out}");
    }

    #[test]
    fn next_flyctl_minor_warns() {
        let mut g = good();
        g[2] = Output::success(b"flyctl v0.5.0 linux/amd64\n".to_vec());
        let r = FakeRunner::new(g);
        let (res, out) = doctor(Ok(fleet()), &r);
        res.unwrap();
        assert!(checks(&out)[3].starts_with("warn  flyctl:"), "{out}");
    }

    #[test]
    fn parse_version_cases() {
        assert_eq!(parse_version("2.40.0"), Some((2, 40, 0)));
        assert_eq!(parse_version("v0.4.112"), Some((0, 4, 112)));
        assert_eq!(parse_version("2.40"), Some((2, 40, 0)));
        assert_eq!(parse_version("1.2.3.4"), None);
        assert_eq!(parse_version("x"), None);
        assert!(parse_version("2.9.0") < Some(OP_TESTED_MIN));
    }

    /// I5: Fly checks are skipped when no environment has a fly section, and environments
    /// without one are named when others have it.
    #[test]
    fn fly_checks_follow_fly_sections() {
        let no_fly = crate::config::parse(
            "[profile]\nkind = \"fleet\"\n[environments.dev]\nvault_id = \"v\"\nitem_id = \"i\"\n",
        )
        .unwrap();
        let r = FakeRunner::new(good().into_iter().take(2));
        let (res, out) = doctor(Ok(no_fly), &r);
        res.unwrap();
        assert!(
            out.contains("skip  flyctl: no environment has a fly section"),
            "{out}"
        );
        assert_eq!(r.calls.borrow().len(), 2, "{:?}", argvs(&r));

        let mixed = fleet_with("[environments.dev]\nvault_id = \"vdev\"\nitem_id = \"idev\"\n");
        let r = FakeRunner::new(good());
        let (res, out) = doctor(Ok(mixed), &r);
        res.unwrap();
        assert!(out.contains("ok    fly auth"), "{out}");
        assert!(
            out.contains("skip  fly: no fly section in environment(s) dev"),
            "{out}"
        );
    }

    const AZURE: &str = "[profile]\nkind = \"simple\"\n\
        [environments.prod]\nvault_id = \"v\"\nitem_id = \"i\"\n\
        [environments.prod.azure]\nsubscription = \"00000000-0000-0000-0000-000000000000\"\n\
        key_vault = \"kv\"\nresource_group = \"rg\"\ncontainer_app = \"ca\"\nidentity = \"system\"\n";

    /// FR-37: az is only checked when an environment has an azure section.
    #[test]
    fn doctor_checks_az_only_with_azure_target() {
        let r = FakeRunner::new(good());
        let _ = doctor(Ok(fleet()), &r);
        assert!(!r.calls.borrow().iter().any(|c| c.program == "az"));
    }

    /// FR-26: signed out of Azure is a failing `az login` line naming the command.
    #[test]
    fn doctor_signed_out_of_azure_names_az_login() {
        let version = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/azure/az-version.json"
        ))
        .unwrap();
        let r = FakeRunner::new(
            good()
                .into_iter()
                .take(2)
                .chain([Output::success(version), Output::failure(1)]),
        );
        let (_, out) = doctor(crate::config::parse(AZURE), &r);
        assert!(
            out.contains("FAIL  az login: authentication error: not logged in to Azure"),
            "{out}"
        );
    }

    #[test]
    fn simple_profile_config_line_counts_keys_not_products() {
        let simple = crate::config::load("tests/fixtures/simple.toml").unwrap();
        let r = FakeRunner::new(good());
        let (_, out) = doctor(Ok(simple), &r);
        assert_eq!(
            checks(&out)[0],
            "ok    config: valid (2 environment(s), 5 key(s))",
            "{out}"
        );
    }

    #[test]
    fn fleet_config_line_still_counts_products() {
        let r = FakeRunner::new(good());
        let (_, out) = doctor(Ok(fleet()), &r);
        assert_eq!(
            checks(&out)[0],
            "ok    config: valid (2 environment(s), 1 product(s))",
            "{out}"
        );
    }

    #[test]
    fn next_step_is_the_last_line_when_all_checks_pass() {
        let r = FakeRunner::new(good());
        let (_, out) = doctor(Ok(fleet()), &r);
        assert_eq!(next_line(&out), "Next step: nothing pending", "{out}");
    }

    #[test]
    fn next_step_appears_exactly_once() {
        let r = FakeRunner::new([]);
        for _ in 0..4 {
            r.push_io_error(io::ErrorKind::NotFound);
        }
        let (_, out) = doctor(Ok(fleet()), &r);
        assert_eq!(
            out.lines().filter(|l| l.starts_with("Next step")).count(),
            1,
            "{out}"
        );
    }

    #[test]
    fn next_step_names_install_command_when_op_is_missing() {
        let r = FakeRunner::new([]);
        r.push_io_error(io::ErrorKind::NotFound);
        r.responses.borrow_mut().push_back(Ok(good().remove(2)));
        r.responses.borrow_mut().push_back(Ok(good().remove(3)));
        let (_, out) = doctor(Ok(fleet()), &r);
        assert_eq!(
            next_line(&out),
            "Next step (op): install op from https://developer.1password.com/docs/cli/get-started/ \
             (apt, dnf or the zip for this Linux distribution)",
            "{out}"
        );
    }

    #[test]
    fn next_step_names_signin_command_when_op_is_not_signed_in() {
        let mut g = good();
        g[1] = Output::failure(1);
        g.insert(2, Output::success(br#"[{"url":"x"}]"#.to_vec()));
        let r = FakeRunner::new(g);
        let (_, out) = doctor(Ok(fleet()), &r);
        assert_eq!(
            next_line(&out),
            "Next step (op auth): sign in: opv login",
            "{out}"
        );
    }

    #[test]
    fn next_step_names_account_add_when_no_account_exists() {
        let mut g = good();
        g[1] = Output::failure(1);
        g.insert(2, Output::success(b"[]".to_vec()));
        let r = FakeRunner::new(g);
        let (_, out) = doctor(Ok(fleet()), &r);
        assert!(
            next_line(&out).starts_with("Next step (op auth): add one: op account add"),
            "{out}"
        );
    }

    #[test]
    fn next_step_names_fly_login_when_fly_is_logged_out() {
        let mut g = good();
        g[3] = Output::failure(1);
        let r = FakeRunner::new(g);
        let (_, out) = doctor(Ok(fleet()), &r);
        assert_eq!(
            next_line(&out),
            "Next step (fly auth): log in: flyctl auth login",
            "{out}"
        );
    }

    #[test]
    fn next_step_names_the_first_failing_check() {
        let mut g = good();
        g[1] = Output::failure(1);
        g.insert(2, Output::success(br#"[{"url":"x"}]"#.to_vec()));
        g[4] = Output::failure(1); // fly auth fails too
        let r = FakeRunner::new(g);
        let (_, out) = doctor(Ok(fleet()), &r);
        assert!(next_line(&out).starts_with("Next step (op auth):"), "{out}");
    }

    const CONFIG_STEP: &str =
        "Next step (config): fix secrets.toml (see the config line above) and re-run `opv doctor`";

    #[test]
    fn next_step_for_invalid_config_is_fix_and_rerun() {
        let r = FakeRunner::new(good());
        let (_, out) = doctor(Err(Error::Config("invalid secrets.toml: boom".into())), &r);
        assert_eq!(next_line(&out), CONFIG_STEP, "{out}");
    }

    /// A real TOML syntax error carries a `  |` source gutter; it is never the step.
    #[test]
    fn next_step_for_toml_syntax_error_is_the_fixed_config_step() {
        let e = crate::config::parse("[profile\nkind = \"fleet\"\n").unwrap_err();
        assert!(e.to_string().contains("  |"), "{e}");
        let r = FakeRunner::new(good());
        let (_, out) = doctor(Err(e), &r);
        assert_eq!(next_line(&out), CONFIG_STEP, "{out}");
    }

    #[test]
    fn next_step_for_unknown_field_error_is_the_fixed_config_step() {
        let text = std::fs::read_to_string("tests/fixtures/secrets.toml").unwrap();
        let e = crate::config::parse(&text.replace(
            "guidance = \"OpenAI platform / API keys\"",
            "guidance = \"OpenAI platform / API keys\"\nbogus = 1",
        ))
        .unwrap_err();
        assert!(e.to_string().contains("bogus"), "{e}");
        let r = FakeRunner::new(good());
        let (_, out) = doctor(Err(e), &r);
        assert_eq!(next_line(&out), CONFIG_STEP, "{out}");
    }

    #[test]
    fn next_step_for_failing_version_check_is_fix_and_rerun() {
        let mut g = good();
        g[0] = Output::failure(2);
        let r = FakeRunner::new(g);
        let (_, out) = doctor(Ok(fleet()), &r);
        assert_eq!(
            next_line(&out),
            "Next step (op): fix the failure reported above and re-run `opv doctor`",
            "{out}"
        );
    }

    #[test]
    fn next_step_never_prompts() {
        let mut g = good();
        g[1] = Output::failure(1);
        g.insert(2, Output::success(br#"[{"url":"x"}]"#.to_vec()));
        let r = FakeRunner::new(g);
        let (_, out) = doctor(Ok(fleet()), &r);
        let next = next_line(&out);
        assert!(
            !next.contains('?') && !next.to_lowercase().contains("[y/n]"),
            "{next}"
        );
    }

    #[test]
    fn next_step_under_ci_names_service_account_token() {
        let mut g = good();
        g[1] = Output::failure(1);
        let r = FakeRunner::new(g);
        let h = Host::from_env(
            &crate::host::FakeEnv::new("linux")
                .shell("/bin/bash")
                .var("CI"),
        );
        let mut out = Vec::new();
        let _ = run_with(Ok(fleet()), &r, &h, &mut out);
        let out = text_of(&out);
        assert!(
            next_line(&out).starts_with("Next step (op auth): set OP_SERVICE_ACCOUNT_TOKEN"),
            "{out}"
        );
    }

    /// Unparseable tool output is not echoed (it could be anything).
    #[test]
    fn odd_version_output_is_not_echoed() {
        let mut g = good();
        g[0] = Output::success(b"weird FIXTUREVALUE output\n".to_vec());
        let r = FakeRunner::new(g);
        let (res, out) = doctor(Ok(fleet()), &r);
        res.unwrap();
        assert_no_values(&out);
    }

    #[test]
    fn scoped_development_doctor_never_queries_fly_in_mixed_file() {
        let mut f = fleet();
        let mut env = f.environments["staging"].clone();
        env.target = None;
        f.environments.insert("dev".into(), env);
        let r = FakeRunner::new(good().into_iter().take(2).chain([item(&complete_fields())]));
        let mut out = Vec::new();
        run_scoped(Ok(f), Some("dev"), Some("allumata"), &r, &mut out).unwrap();
        assert!(r.calls.borrow().iter().all(|c| c.program == "op"));
    }
    #[cfg(not(windows))]
    #[test]
    fn native_op_passes_the_local_run_check() {
        let (_, out) = doctor(Ok(fleet()), &FakeRunner::new(good()));
        assert!(out.contains("ok    op local run: native op"), "{out}");
    }

    #[cfg(not(windows))]
    #[test]
    fn windows_op_warns_when_deployment_environments_are_in_scope() {
        let r = FakeRunner::new(good());
        let (res, _) = doctor(Ok(fleet()), windows_op(&r));
        assert!(res.is_ok());
    }

    #[cfg(not(windows))]
    #[test]
    fn windows_op_fails_a_local_only_scope() {
        let r = FakeRunner::new(good());
        let (res, _) = doctor_local_only(windows_op(&r));
        assert!(matches!(res, Err(Error::Dependency(_))));
    }

    #[cfg(not(windows))]
    #[test]
    fn windows_op_failure_still_prints_every_check_and_a_next_step() {
        let r = FakeRunner::new(good());
        let (_, out) = doctor_local_only(windows_op(&r));
        assert!(
            out.ends_with(
                "Next step (op local run): install the Linux 1Password CLI in WSL and sign in: see https://github.com/matt-cochran/1password-vault/blob/main/docs/local-development.md#wsl\n"
            ),
            "{out}"
        );
    }

    fn binary(p: &str) -> crate::host::OpvCopy {
        crate::host::OpvCopy::Binary(std::path::PathBuf::from(p))
    }

    fn wrapper(p: &str, v: Option<&str>) -> crate::host::OpvCopy {
        crate::host::OpvCopy::NpmWrapper {
            path: std::path::PathBuf::from(p),
            version: v.map(str::to_owned),
        }
    }

    /// Doctor output with `copies` on PATH and `versions` answering each binary probe.
    fn doctor_with_opv_copies(copies: Vec<crate::host::OpvCopy>, versions: &[&str]) -> String {
        let r = FakeRunner::new(
            good().into_iter().chain(
                versions
                    .iter()
                    .map(|v| Output::success(format!("opv {v}\n").into_bytes())),
            ),
        );
        let mut out = Vec::new();
        let res =
            crate::host::with_test_path(copies, || run_with(Ok(fleet()), &r, &linux(), &mut out));
        res.unwrap();
        text_of(&out)
    }

    #[test]
    fn doctor_lists_one_opv_on_path_with_its_version() {
        let out = doctor_with_opv_copies(vec![binary("/opt/opv/bin/opv")], &["1.2.3"]);
        assert!(out.contains("ok    opv: /opt/opv/bin/opv 1.2.3"), "{out}");
    }

    #[test]
    fn doctor_accepts_the_npm_wrapper_beside_the_matching_binary() {
        let out = doctor_with_opv_copies(
            vec![
                binary("/home/x/.local/bin/opv"),
                wrapper("/usr/bin/opv", Some("1.2.3")),
            ],
            &["1.2.3"],
        );
        assert!(
            out.contains("ok    opv: /home/x/.local/bin/opv 1.2.3 (also run by the npm wrapper)"),
            "{out}"
        );
    }

    #[test]
    fn doctor_warns_on_two_opv_copies() {
        let out = doctor_with_opv_copies(
            vec![
                binary("/home/x/.local/bin/opv"),
                binary("/home/x/.cargo/bin/opv"),
            ],
            &["1.2.3", "1.1.0"],
        );
        let fix = if cfg!(windows) {
            "del \"/home/x/.cargo/bin/opv\""
        } else {
            "rm /home/x/.cargo/bin/opv"
        };
        assert!(
            out.lines()
                .any(|l| l.starts_with("warn  opv:") && l.contains(fix)),
            "{out}"
        );
    }

    #[test]
    fn doctor_warns_when_the_npm_wrapper_is_a_different_version() {
        let out = doctor_with_opv_copies(
            vec![
                binary("/home/x/.local/bin/opv"),
                wrapper("/usr/bin/opv", Some("1.1.0")),
            ],
            &["1.2.3"],
        );
        assert!(
            out.lines()
                .any(|l| l.starts_with("warn  opv:")
                    && l.contains("npm update -g @matthew-cochran/opv")),
            "{out}"
        );
    }

    #[test]
    fn doctor_does_not_run_the_npm_wrapper_to_read_its_version() {
        // One probe answer only: a second probe would exhaust the fake runner.
        let out = doctor_with_opv_copies(
            vec![
                binary("/home/x/.local/bin/opv"),
                wrapper("/usr/bin/opv", Some("1.2.3")),
            ],
            &["1.2.3"],
        );
        assert!(!out.contains("fail"), "{out}");
    }

    /// `doctor --env prod --product allumata` with `item` answering the one item read.
    fn doctor_scoped(item: Output, json: bool) -> (Result<(), Error>, String, FakeRunner) {
        let mut g = good();
        g.insert(2, item);
        let r = FakeRunner::new(g);
        let mut out = Vec::new();
        let res = run_scoped_as(
            Ok(fleet()),
            Some("prod"),
            Some("allumata"),
            json,
            &r,
            &mut out,
        );
        (res, text_of(&out), r)
    }

    /// P6: a readable item is one `ok item:` line naming the IDs and the field count.
    #[test]
    fn scoped_doctor_reports_the_item_readable() {
        let (_, out, _) = doctor_scoped(complete_item(), false);
        assert!(
            checks(&out)
                .contains(&"ok    item: vprd/iprd readable (3 field(s) in section allumata)"),
            "{out}"
        );
    }

    /// P6, FR-13: the scoped doctor reads the item exactly once.
    #[test]
    fn scoped_doctor_reads_the_item_once() {
        let (_, _, r) = doctor_scoped(complete_item(), false);
        assert_eq!(
            argvs(&r)
                .iter()
                .filter(|a| a.starts_with("op item"))
                .count(),
            1
        );
    }

    /// P6: doctor is never all clear when `check` would fail.
    #[test]
    fn scoped_doctor_fails_when_a_key_is_missing() {
        let (res, _, _) = doctor_scoped(item_without("allumata", "OPENAI_API_KEY"), false);
        assert!(matches!(res, Err(Error::Findings(1))), "{res:?}");
    }

    #[test]
    fn scoped_doctor_names_the_key_that_check_would_report() {
        let (_, out, _) = doctor_scoped(item_without("allumata", "OPENAI_API_KEY"), false);
        assert!(
            out.contains("but 1 key(s) not ready: allumata/OPENAI_API_KEY (missing)"),
            "{out}"
        );
    }

    #[test]
    fn scoped_doctor_next_step_is_the_check_command() {
        let (_, out, _) = doctor_scoped(item_without("allumata", "OPENAI_API_KEY"), false);
        assert_eq!(
            next_line(&out),
            "Next step (item): fill them in 1Password, then opv check prod --product allumata",
            "{out}"
        );
    }

    /// P6: an item this identity cannot read is a failing item line with the fix.
    #[test]
    fn scoped_doctor_fails_an_unreadable_item() {
        let mut g = good();
        g.splice(
            2..2,
            [
                Output::failure(1),
                Output::success(WHOAMI.as_bytes().to_vec()),
                Output::failure(1),
            ],
        );
        let r = FakeRunner::new(g);
        let mut out = Vec::new();
        let _ = run_scoped(Ok(fleet()), Some("prod"), None, &r, &mut out);
        let out = text_of(&out);
        assert!(
            checks(&out)
                .iter()
                .any(|l| l.starts_with("FAIL  item:") && l.contains("cannot access vault vprd")),
            "{out}"
        );
    }

    /// P6: no item read when op is not signed in (the op auth line already fails).
    #[test]
    fn scoped_doctor_skips_the_item_when_not_signed_in() {
        let mut g = good();
        g[1] = Output::failure(1);
        g.insert(2, Output::success(br#"[{"url":"x"}]"#.to_vec()));
        let r = FakeRunner::new(g);
        let mut out = Vec::new();
        let _ = run_scoped(Ok(fleet()), Some("prod"), None, &r, &mut out);
        assert!(!r.argv_contains("item"), "{:?}", argvs(&r));
    }

    fn json_doc(out: &str) -> serde_json::Value {
        serde_json::from_str(out).unwrap()
    }

    /// P18: one JSON document, schema 1, one entry per check.
    #[test]
    fn json_lists_every_check_with_its_status() {
        let (_, out, _) = doctor_scoped(complete_item(), true);
        let doc = json_doc(&out);
        let checks: Vec<(String, String)> = doc["checks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| {
                (
                    c["name"].as_str().unwrap().to_string(),
                    c["status"].as_str().unwrap().to_string(),
                )
            })
            .take(4)
            .collect();
        assert_eq!(
            (doc["schema_version"].as_u64(), checks),
            (
                Some(1),
                [
                    ("config", "ok"),
                    ("op", "ok"),
                    ("op auth", "ok"),
                    ("item", "ok")
                ]
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .to_vec()
            )
        );
    }

    #[test]
    fn json_next_is_null_when_nothing_is_pending() {
        let (_, out, _) = doctor_scoped(complete_item(), true);
        assert!(json_doc(&out)["next"].is_null(), "{out}");
    }

    #[test]
    fn json_next_is_the_first_failing_checks_step() {
        let (_, out, _) = doctor_scoped(item_without("allumata", "OPENAI_API_KEY"), true);
        assert_eq!(
            json_doc(&out)["next"],
            "fill them in 1Password, then opv check prod --product allumata",
            "{out}"
        );
    }

    #[test]
    fn json_detail_is_the_first_line_only() {
        let (_, out, _) = doctor_scoped(item_without("allumata", "OPENAI_API_KEY"), true);
        let doc = json_doc(&out);
        let item = doc["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "item")
            .unwrap()
            .clone();
        assert!(!item["detail"].as_str().unwrap().contains('\n'), "{item}");
    }

    #[test]
    fn json_output_carries_no_value() {
        let (_, out, _) = doctor_scoped(item_without("allumata", "OPENAI_API_KEY"), true);
        assert_no_values(&out);
    }

    /// P7, FR-40: on an interactive terminal the sign-in step is `opv login`.
    #[test]
    fn next_step_on_a_terminal_names_opv_login() {
        let mut g = good();
        g[1] = Output::failure(1);
        g.insert(2, Output::success(br#"[{"url":"x"}]"#.to_vec()));
        let r = FakeRunner::new(g);
        let h = Host::from_env(&crate::host::FakeEnv::new("linux").shell("/bin/bash").tty());
        let mut out = Vec::new();
        let _ = run_with(Ok(fleet()), &r, &h, &mut out);
        assert_eq!(
            next_line(&text_of(&out)),
            "Next step (op auth): sign in: opv login"
        );
    }

    /// #12: the returned error does not repeat a long check message printed above.
    #[test]
    fn returned_error_does_not_repeat_the_config_message() {
        let r = FakeRunner::new(good());
        let (res, _) = doctor(Err(Error::Config("invalid secrets.toml: boom".into())), &r);
        assert!(!res.unwrap_err().to_string().contains("boom"));
    }

    /// #13: an older op gets an upgrade step, not an install link.
    #[test]
    fn older_op_warning_names_an_upgrade() {
        let mut g = good();
        g[0] = Output::success(b"2.31.0\n".to_vec());
        let r = FakeRunner::new(g);
        let (_, out) = doctor(Ok(fleet()), &r);
        assert!(out.contains("\n  upgrade: op update"), "{out}");
    }

    /// P3: with no configuration at all, the step is the first-run router, not "fix it".
    #[test]
    fn next_step_without_any_configuration_offers_init_and_setup() {
        let r = FakeRunner::new(good());
        let missing = crate::config::not_found(std::path::Path::new("/nowhere"));
        let (_, out) = doctor(Err(missing), &r);
        assert_eq!(
            next_line(&out),
            "Next step (config): opv init <env> --vault <vault title> --item <item title>   (new project: opv setup)",
            "{out}"
        );
    }
}
