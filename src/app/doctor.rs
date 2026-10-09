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
//! keys of the selected products exactly as `check` does: `ok item: <vault>/<item>
//! readable (<n> fields in section <p>)`, or a failing line naming each key that is not
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
//! A failure ends the run with the first failing check as the error, whose `Next:` line
//! (NR-19) is the safe command that addresses it (the first remediation line of that check);
//! a clean run ends with `Next: nothing pending`. Text only, never a prompt (FR-9).

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

/// Name of the configuration check (its message is parser output, see [`Row::next`]).
const CONFIG_CHECK: &str = "config";

/// Name of the item check (`--env` only, P6).
const ITEM_CHECK: &str = "item";

/// The fixed step for an invalid configuration.
const CONFIG_FIX: &str = "fix secrets.toml (see the config line above), then run opv doctor";

/// The step when there is no configuration yet (P3); the config line lists the others.
const FIRST_RUN: &str = "opv init <env> --vault <vault title> --item <item title>";

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
    let request = Request {
        env,
        product,
        json,
        source: None,
        deploy_failure: None,
    };
    run_request(config, request, r, out)
}

/// What `opv doctor` was asked for, from the command line.
#[derive(Debug, Default)]
pub struct Request<'a> {
    /// `--env`.
    pub env: Option<&'a str>,
    /// `--product` (with `--env`).
    pub product: Option<&'a str>,
    /// `--json`.
    pub json: bool,
    /// Where the configuration came from, for the config line (`source: ./secrets.toml`,
    /// `source: manifest "opv · app" in vault V (matched …)`, FR-44).
    pub source: Option<&'a str>,
    /// The environment's deploy sign-in failed before doctor ran (FR-40). Doctor reports
    /// it as one failing check, runs the other checks and skips the target checks that
    /// need those credentials (owner ruling: doctor never aborts on it).
    pub deploy_failure: Option<super::signin::DeployFailure>,
}

/// [`run_scoped_as`] for a whole [`Request`].
pub fn run_request(
    config: Result<Fleet, Error>,
    request: Request<'_>,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    run_request_on(config, request, r, &Host::detect, out)
}

fn run_request_on(
    config: Result<Fleet, Error>,
    request: Request<'_>,
    r: &dyn CommandRunner,
    host: &dyn Fn() -> Host,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let Request {
        env,
        product,
        json,
        source,
        deploy_failure,
    } = request;
    let config =
        match env {
            Some(e) => config.and_then(|f| super::local::select(&f, e, product, false)),
            None if product.is_some() => Err(Error::Config("--product requires --env".into())
                .with_code(crate::error::Code::Usage)),
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
        source,
    };
    run_on_with(config, r, host, scope, deploy_failure, out)
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
    /// Where the configuration came from (FR-44).
    source: Option<&'a str>,
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
    /// The failure's own next step (NR-19), printed as `  fix: <step>` under the line.
    fix: Option<String>,
    /// A failed call's scrubbed stderr excerpt (`  az said: …`), printed under the line in
    /// text output only, never in `--json` (M2, NR-31).
    excerpt: Option<String>,
}

impl Row {
    /// The remediation for this row: the fixed configuration step, the failure's own next
    /// step, or its first indented line (the install, sign-in, `op account add` or log-in
    /// command the failure already prints, FR-26). `None` for a row with nothing to do.
    /// Never tool output or a value (SR-1).
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
        if let Some(f) = &self.fix {
            return Some(f.clone());
        }
        self.text
            .lines()
            .skip(1)
            .find_map(|l| l.strip_prefix("  "))
            .map(|l| l.strip_prefix("next: ").unwrap_or(l).trim().to_string())
            .filter(|h| !h.is_empty())
    }

    /// The `Next:` step for this row when it is the first failure (NR-19).
    fn step(&self) -> String {
        self.next().unwrap_or_else(|| rerun(&self.name))
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
        let (state, text, fix) = match res {
            Ok(Check::Ok(t)) => (State::Ok, t, None),
            Ok(Check::Warn(t)) => (State::Warn, t, None),
            Err(e) => {
                let t = e.to_string();
                let fix = e.next_step().map(str::to_string);
                if self.first.is_none() {
                    self.first = Some((name.to_string(), e));
                }
                (State::Fail, t, fix)
            }
        };
        self.rows.push(Row {
            name: name.to_string(),
            state,
            text,
            fix,
            excerpt: None,
        });
    }

    /// A failing check whose line text differs from its error (the item check, P6).
    fn fail(&mut self, name: &str, text: String, e: Error) {
        let fix = e.next_step().map(str::to_string);
        if self.first.is_none() {
            self.first = Some((name.to_string(), e));
        }
        self.rows.push(Row {
            name: name.to_string(),
            state: State::Fail,
            text,
            fix,
            excerpt: None,
        });
    }

    fn skip(&mut self, name: &str, text: String) {
        self.rows.push(Row {
            name: name.to_string(),
            state: State::Skip,
            text,
            fix: None,
            excerpt: None,
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
    run_on_with(config, r, host, scope, None, out)
}

/// The check that reports a failed deploy sign-in (FR-40).
const DEPLOY_CHECK: &str = "deploy credentials";

/// Why a target check was not run after a failed deploy sign-in.
const DEPLOY_SKIP: &str = "not checked (deploy credentials failed)";

/// [`run_on`], with the environment's failed deploy sign-in, if any.
fn run_on_with(
    config: Result<Fleet, Error>,
    r: &dyn CommandRunner,
    host: &dyn Fn() -> Host,
    scope: Scope<'_>,
    deploy_failure: Option<super::signin::DeployFailure>,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let mut report = Report::default();
    let (fleet, config_line) = match config {
        Ok(f) => {
            let mut summary = config_summary(&f);
            if let Some(src) = scope.source {
                summary.push_str(&format!("; source: {src}"));
            }
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
    // The checks that run the deploy identity's CLI, when its sign-in failed: every check
    // of that provider but the first (its tool version).
    let mut needs_deploy: Vec<&str> = Vec::new();
    if let Some(failure) = deploy_failure {
        report.push(DEPLOY_CHECK, Err(failure.error));
        // Text output only, under the FAIL line; never in `--json` (M2, NR-31).
        if let Some(row) = report.rows.last_mut() {
            row.excerpt = failure.excerpt.map(|x| x.render());
        }
        if let Some(f) = &fleet {
            for t in f.environments.values().filter_map(|e| e.target()) {
                let checks = crate::provider::deploy_provider(t).doctor_checks();
                needs_deploy.extend(checks.iter().skip(1));
            }
        }
    }
    let default = registry::DEFAULT;
    match targets {
        Some((used, without)) if !used.is_empty() => {
            for t in &used {
                for c in t.doctor(r, host) {
                    if needs_deploy.iter().any(|n| *n == c.name) {
                        report.skip(&c.name, DEPLOY_SKIP.into());
                    } else {
                        report.push(&c.name, c.outcome);
                    }
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
                        "no {section} section in {} {} (run, config export and item skeleton only)",
                        if without.len() == 1 {
                            "environment"
                        } else {
                            "environments"
                        },
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
        print_json(&report, &doctor_command(&scope), scope.source, out)?;
    } else {
        print_text(&report, out, &mut std::io::stderr())?;
    }
    // The first failure is the result: its FAIL line above has the detail, so the error
    // names the check only, and its next step is that check's remediation (NR-19). The
    // `Next:` line is printed once, last, by the error report on stderr.
    match report.first {
        Some((check, e)) => {
            let next = report
                .rows
                .iter()
                .find(|r| r.name == check && r.state == State::Fail)
                .map_or_else(|| rerun(&check), Row::step);
            Err(e
                .map_text(|_| format!("{check} check failed (see the FAIL line above)"))
                .with_next(next))
        }
        None => {
            if !scope.json {
                writeln!(out, "all clear: nothing pending").map_err(write_err)?;
            }
            Ok(())
        }
    }
}

/// One line per check, with `  fix: <step>` under a failure whose step is not already
/// in its text. The closing `Next:` line is `run_on`'s (all clear) or the error report's.
/// The report as text on `out`; a failed call's scrubbed excerpt goes to `err` (stderr)
/// right after its FAIL line, never to stdout or a JSON document (M2, NR-31).
fn print_text(report: &Report, out: &mut dyn Write, err: &mut dyn Write) -> Result<(), Error> {
    for row in &report.rows {
        writeln!(out, "{}  {}: {}", row.state.word(), row.name, row.text).map_err(write_err)?;
        if let Some(x) = &row.excerpt {
            out.flush().map_err(write_err)?;
            let _ = write!(err, "{x}");
        }
        if let (State::Fail, Some(fix)) = (row.state, &row.fix) {
            writeln!(out, "  fix: {fix}").map_err(write_err)?;
        }
    }
    Ok(())
}

/// `opv doctor` with the scope's flags, the command to run again once a fix is done.
fn doctor_command(scope: &Scope<'_>) -> String {
    let mut c = "opv doctor".to_string();
    if let Some(e) = scope.env {
        c.push_str(&format!(" --env {e}"));
    }
    if let Some(p) = scope.product {
        c.push_str(&format!(" --product {p}"));
    }
    c
}

/// P18, A3: `{schema_version: 1, config_source, checks: [{name, status, detail, next, do}],
/// next, do}`. `config_source` is where the configuration was found (FR-44), or null.
/// `detail` is the first line of the check's text (names, versions and commands only);
/// a check with something to do has `do` (the action only a person can take, or null)
/// and `next` (a command that runs as typed), both null otherwise; the top-level pair is
/// the first failing check's.
fn print_json(
    report: &Report,
    rerun: &str,
    source: Option<&str>,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let split = |row: &Row| row.next().map(|n| crate::error::split_step(&n, rerun));
    let checks: Vec<serde_json::Value> = report
        .rows
        .iter()
        .map(|row| {
            let step = split(row);
            serde_json::json!({
                "name": row.name,
                "status": row.state.json(),
                "detail": row.text.lines().next().unwrap_or(""),
                "next": step.as_ref().map(|s| s.next.clone()),
                "do": step.and_then(|s| s.action),
            })
        })
        .collect();
    let first = report
        .rows
        .iter()
        .find(|r| r.state == State::Fail)
        .map(|r| crate::error::split_step(&r.step(), rerun));
    let doc = serde_json::json!({
        "schema_version": crate::json::SCHEMA_VERSION,
        "config_source": source,
        "checks": checks,
        "next": first.as_ref().map(|s| s.next.clone()),
        "do": first.and_then(|s| s.action),
    });
    writeln!(out, "{doc}").map_err(write_err)
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
    // Tolerant, and tidied when a person runs doctor (FR-43).
    let item = match super::tidy::read(fleet, env_name, r) {
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
        "{}/{} readable ({}{where_})",
        env.vault_id,
        env.item_id,
        super::plural(item.fields.len(), "field", "fields")
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
                KeyState::Ready | KeyState::Skipped | KeyState::SourceBlocked => return None,
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
                .find(|r| super::is_blocking(r))
                .map_or("<product>", |r| r.product.as_str());
            format!("opv check {env_name} --product {first}")
        }
    };
    report.fail(
        ITEM_CHECK,
        format!(
            "{readable}, but {} not ready: {}",
            super::plural(blocking.len(), "key", "keys"),
            blocking.join(", ")
        ),
        Error::findings(
            blocking.len(),
            format!("fill them in 1Password, then {check}"),
        ),
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

/// `valid (N environments, M products)`, or under the simple profile, whose one product
/// is hidden (FR-20), `valid (N environments, M keys)`.
fn config_summary(f: &Fleet) -> String {
    let envs = super::plural(f.environments.len(), "environment", "environments");
    if f.is_simple() {
        let keys: usize = f.products.values().map(|p| p.keys.len()).sum();
        format!("valid ({envs}, {})", super::plural(keys, "key", "keys"))
    } else {
        format!(
            "valid ({envs}, {})",
            super::plural(f.products.len(), "product", "products")
        )
    }
}

/// The fix-and-re-run step for a failing check without a remediation of its own.
fn rerun(check: &str) -> String {
    format!("fix the {check} failure above, then run opv doctor")
}

fn op_version(r: &dyn CommandRunner, host: &dyn Fn() -> Host) -> Result<Check, Error> {
    let o = spawn_tool(r, OP_CLI, host, &["--version"])?;
    if o.status != 0 {
        return Err(Error::Dependency(
            format!("op --version failed (exit {})", o.status).into(),
        ));
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
            Err(Error::Dependency(windows_op.into()))
        }
        Err(e) if e.kind() == io::ErrorKind::Unsupported => Ok(Check::Warn(windows_op)),
        Err(e) if local_only => Err(Error::Dependency(
            format!("cannot inspect op on PATH ({})", e.kind()).into(),
        )),
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
        let t = terminal(&res, &out);
        (res, t)
    }

    /// What the terminal shows: stdout, then on failure the stderr report (NR-19).
    fn terminal(res: &Result<(), Error>, out: &[u8]) -> String {
        let mut t = text_of(out);
        if let Err(e) = res {
            t.push_str(&crate::error::report(e, "opv doctor", None));
        }
        t
    }

    #[cfg(not(windows))]
    fn windows_op(r: &FakeRunner) -> &FakeRunner {
        *r.local_run_error.borrow_mut() = Some(io::ErrorKind::Unsupported);
        r
    }

    fn doctor(config: Result<Fleet, Error>, r: &FakeRunner) -> (Result<(), Error>, String) {
        let mut out = Vec::new();
        let res = run_with(config, r, &linux(), &mut out);
        let t = terminal(&res, &out);
        (res, t)
    }

    /// The check lines only (remediation lines under a check are indented; the closing
    /// `Next:` line and the error report are not checks).
    fn checks(out: &str) -> Vec<&str> {
        out.lines()
            .filter(|l| {
                !l.starts_with("  ")
                    && !l.starts_with("Next: ")
                    && !l.starts_with("Do: ")
                    && !l.starts_with("opv: ")
                    && !l.starts_with("all clear")
            })
            .collect()
    }

    fn next_line(out: &str) -> &str {
        out.lines().last().unwrap()
    }

    /// The `Do:` line of the error report (A3), or "" without one.
    fn do_line(out: &str) -> &str {
        out.lines()
            .find(|l| l.starts_with("Do: "))
            .unwrap_or_default()
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
            out.contains("skip  fly: no fly section in environment dev"),
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
            "ok    config: valid (2 environments, 5 keys)",
            "{out}"
        );
    }

    #[test]
    fn fleet_config_line_still_counts_products() {
        let r = FakeRunner::new(good());
        let (_, out) = doctor(Ok(fleet()), &r);
        assert_eq!(
            checks(&out)[0],
            "ok    config: valid (2 environments, 1 product)",
            "{out}"
        );
    }

    #[test]
    fn next_step_is_the_last_line_when_all_checks_pass() {
        let r = FakeRunner::new(good());
        let (_, out) = doctor(Ok(fleet()), &r);
        assert_eq!(next_line(&out), "all clear: nothing pending", "{out}");
    }

    #[test]
    fn next_step_appears_exactly_once() {
        let r = FakeRunner::new([]);
        for _ in 0..4 {
            r.push_io_error(io::ErrorKind::NotFound);
        }
        let (_, out) = doctor(Ok(fleet()), &r);
        assert_eq!(
            out.lines().filter(|l| l.starts_with("Next")).count(),
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
            do_line(&out),
            "Do: install op from https://developer.1password.com/docs/cli/get-started/ \
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
        assert_eq!(do_line(&out), "Do: sign in: opv login", "{out}");
    }

    #[test]
    fn next_step_names_account_add_when_no_account_exists() {
        let mut g = good();
        g[1] = Output::failure(1);
        g.insert(2, Output::success(b"[]".to_vec()));
        let r = FakeRunner::new(g);
        let (_, out) = doctor(Ok(fleet()), &r);
        assert!(
            do_line(&out).starts_with("Do: add one: op account add"),
            "{out}"
        );
    }

    #[test]
    fn next_step_names_fly_login_when_fly_is_logged_out() {
        let mut g = good();
        g[3] = Output::failure(1);
        let r = FakeRunner::new(g);
        let (_, out) = doctor(Ok(fleet()), &r);
        assert_eq!(do_line(&out), "Do: log in: flyctl auth login", "{out}");
    }

    #[test]
    fn next_step_names_the_first_failing_check() {
        let mut g = good();
        g[1] = Output::failure(1);
        g.insert(2, Output::success(br#"[{"url":"x"}]"#.to_vec()));
        g[4] = Output::failure(1); // fly auth fails too
        let r = FakeRunner::new(g);
        let (_, out) = doctor(Ok(fleet()), &r);
        assert!(do_line(&out).starts_with("Do: sign in"), "{out}");
    }

    const CONFIG_STEP: &str = "Do: fix secrets.toml (see the config line above)";

    #[test]
    fn next_step_for_invalid_config_is_fix_and_rerun() {
        let r = FakeRunner::new(good());
        let (_, out) = doctor(Err(Error::Config("invalid secrets.toml: boom".into())), &r);
        assert_eq!(do_line(&out), CONFIG_STEP, "{out}");
    }

    /// A real TOML syntax error carries its position; it is never the step.
    #[test]
    fn next_step_for_toml_syntax_error_is_the_fixed_config_step() {
        let e = crate::config::parse("[profile\nkind = \"fleet\"\n").unwrap_err();
        let r = FakeRunner::new(good());
        let (_, out) = doctor(Err(e), &r);
        assert_eq!(do_line(&out), CONFIG_STEP, "{out}");
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
        assert_eq!(do_line(&out), CONFIG_STEP, "{out}");
    }

    #[test]
    fn next_step_for_failing_version_check_is_fix_and_rerun() {
        let mut g = good();
        g[0] = Output::failure(2);
        let r = FakeRunner::new(g);
        let (_, out) = doctor(Ok(fleet()), &r);
        assert_eq!(do_line(&out), "Do: fix the op failure above", "{out}");
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
        let res = run_with(Ok(fleet()), &r, &h, &mut out);
        let out = terminal(&res, &out);
        assert!(
            do_line(&out).starts_with("Do: set OP_SERVICE_ACCOUNT_TOKEN"),
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
                "Do: install the Linux 1Password CLI in WSL and sign in: see https://github.com/matt-cochran/1password-vault/blob/main/docs/local-development.md#wsl\nNext: opv doctor\n"
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

    /// `doctor --env prod` after the environment's deploy sign-in failed (FR-40).
    fn doctor_deploy_failed(json: bool) -> (Result<(), Error>, String) {
        let mut g = good();
        g.insert(2, complete_item());
        let r = FakeRunner::new(g);
        let mut out = Vec::new();
        let request = Request {
            env: Some("prod"),
            product: Some("allumata"),
            json,
            source: None,
            deploy_failure: Some(crate::app::signin::DeployFailure {
                error: Error::Auth(
                    "deploy credentials: az login failed\n  next: check the item".into(),
                ),
                excerpt: crate::scrub::Excerpt::from_stderr(
                    "az",
                    b"ERROR: AADSTS7000215 invalid client secret\n",
                    false,
                ),
            }),
        };
        let res = run_request_on(Ok(fleet()), request, &r, &|| linux(), &mut out);
        (res, text_of(&out))
    }

    /// Owner ruling: a failed deploy sign-in is one failing check line, not an abort.
    #[test]
    fn deploy_failure_is_one_fail_line() {
        let (_, out) = doctor_deploy_failed(false);
        assert!(
            checks(&out).contains(&"FAIL  deploy credentials: authentication error: deploy credentials: az login failed"),
            "{out}"
        );
    }

    /// Its remediation is the person's step (A3: `Do:`, then the re-check as `Next:`).
    #[test]
    fn deploy_failure_names_its_fix() {
        let (res, out) = doctor_deploy_failed(false);
        let t = terminal(&res, out.as_bytes());
        assert_eq!(do_line(&t), "Do: check the item", "{t}");
    }

    /// UX1: the failing line carries its fix under it, like every other check.
    #[test]
    fn deploy_failure_prints_its_fix_under_the_fail_line() {
        let (_, out) = doctor_deploy_failed(false);
        assert!(out.contains("\n  fix: check the item\n"), "{out}");
    }

    /// The target checks that use the deploy identity are skipped, saying why.
    #[test]
    fn deploy_failure_skips_the_target_sign_in_check() {
        let (_, out) = doctor_deploy_failed(false);
        assert!(
            checks(&out).contains(&"skip  fly auth: not checked (deploy credentials failed)"),
            "{out}"
        );
    }

    /// The tool check needs no credentials and still runs.
    #[test]
    fn deploy_failure_still_checks_the_target_tool() {
        let (_, out) = doctor_deploy_failed(false);
        assert!(
            checks(&out).contains(&"ok    flyctl: version v0.4.112"),
            "{out}"
        );
    }

    /// The non-target checks still run (the item is read).
    #[test]
    fn deploy_failure_still_checks_the_item() {
        let (_, out) = doctor_deploy_failed(false);
        assert!(
            checks(&out).contains(&"ok    item: vprd/iprd readable (3 fields in section allumata)"),
            "{out}"
        );
    }

    /// The run fails with the deploy failure's category (exit 7 for a sign-in).
    #[test]
    fn deploy_failure_exits_with_its_category() {
        let (res, _) = doctor_deploy_failed(false);
        assert!(matches!(res, Err(Error::Auth(_))), "{res:?}");
    }

    /// The JSON output carries the same check.
    #[test]
    fn deploy_failure_json_check_fails_with_its_fix() {
        let (_, out) = doctor_deploy_failed(true);
        let doc: serde_json::Value = serde_json::from_str(&out).unwrap();
        let check = doc["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "deploy credentials")
            .unwrap()
            .clone();
        assert_eq!(
            (check["status"].clone(), check["do"].clone()),
            ("fail".into(), "check the item".into()),
            "{out}"
        );
    }

    /// M2: the failed call's excerpt goes to stderr, after its FAIL line.
    #[test]
    fn excerpt_row_prints_the_excerpt_on_stderr() {
        let mut report = Report::default();
        report.push(DEPLOY_CHECK, Err(Error::Auth("az login failed".into())));
        report.rows[0].excerpt = Some("  az said: ERROR: bad\n".into());
        let mut err = Vec::new();
        print_text(&report, &mut Vec::new(), &mut err).unwrap();
        assert_eq!(String::from_utf8(err).unwrap(), "  az said: ERROR: bad\n");
    }

    /// M2: stdout never carries the excerpt, text or JSON.
    #[test]
    fn deploy_failure_text_stdout_has_no_excerpt() {
        let (_, out) = doctor_deploy_failed(false);
        assert!(!out.contains("said:"), "{out}");
    }

    /// M2: no `said:` excerpt in the JSON document; it stays on stderr-style text only.
    #[test]
    fn deploy_failure_json_has_no_excerpt() {
        let (_, out) = doctor_deploy_failed(true);
        assert!(!out.contains("said:"), "{out}");
    }

    /// The JSON output marks the skipped target check.
    #[test]
    fn deploy_failure_json_skips_the_target_sign_in_check() {
        let (_, out) = doctor_deploy_failed(true);
        let doc: serde_json::Value = serde_json::from_str(&out).unwrap();
        let check = doc["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "fly auth")
            .unwrap()
            .clone();
        assert_eq!(check["status"], "skip", "{out}");
    }

    /// P6: a readable item is one `ok item:` line naming the IDs and the field count.
    #[test]
    fn scoped_doctor_reports_the_item_readable() {
        let (_, out, _) = doctor_scoped(complete_item(), false);
        assert!(
            checks(&out).contains(&"ok    item: vprd/iprd readable (3 fields in section allumata)"),
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
        assert!(matches!(res, Err(Error::Findings(1, _))), "{res:?}");
    }

    #[test]
    fn scoped_doctor_names_the_key_that_check_would_report() {
        let (_, out, _) = doctor_scoped(item_without("allumata", "OPENAI_API_KEY"), false);
        assert!(
            out.contains("but 1 key not ready: allumata/OPENAI_API_KEY (missing)"),
            "{out}"
        );
    }

    #[test]
    fn scoped_doctor_next_step_is_the_check_command() {
        let (res, out, _) = doctor_scoped(item_without("allumata", "OPENAI_API_KEY"), false);
        assert_eq!(
            res.unwrap_err().next_step(),
            Some("fill them in 1Password, then opv check prod --product allumata"),
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
            "opv check prod --product allumata",
            "{out}"
        );
    }

    #[test]
    fn json_do_is_the_first_failing_checks_action() {
        let (_, out, _) = doctor_scoped(item_without("allumata", "OPENAI_API_KEY"), true);
        assert_eq!(json_doc(&out)["do"], "fill them in 1Password", "{out}");
    }

    #[test]
    fn json_success_golden() {
        let (res, out, _) = doctor_scoped(complete_item(), true);
        crate::app::json_tests::golden(
            "doctor_success",
            &crate::app::json_tests::without_check(
                &crate::app::json_tests::framed(
                    out.as_bytes(),
                    &res,
                    "opv doctor --env prod --json",
                ),
                "op local run",
            ),
        );
    }

    #[test]
    fn json_failure_golden() {
        let (res, out, _) = doctor_scoped(item_without("allumata", "OPENAI_API_KEY"), true);
        crate::app::json_tests::golden(
            "doctor_failure",
            &crate::app::json_tests::without_check(
                &crate::app::json_tests::framed(
                    out.as_bytes(),
                    &res,
                    "opv doctor --env prod --json",
                ),
                "op local run",
            ),
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
        let res = run_with(Ok(fleet()), &r, &h, &mut out);
        assert_eq!(do_line(&terminal(&res, &out)), "Do: sign in: opv login");
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
            do_line(&out),
            "Do: fill in and run: opv init <env> --vault <vault title> --item <item title>",
            "{out}"
        );
    }
}
