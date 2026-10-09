//! Fly.io adapter wrapping `flyctl` (S4; FR-6, FR-7, FR-8, SR-1, SR-3, SR-4, §6.4).
//!
//! Five operations, each one `flyctl` call (none when there is nothing to do), except
//! [`preflight`], which makes two:
//!
//! | fn | argv |
//! |---|---|
//! | [`preflight`] | `status --app <app> --json`, `releases --app <app> --json` (NR-24) |
//! | [`list`] | `secrets list --app <app> --json` |
//! | [`stage`] | `secrets import --app <app> --stage` (values on stdin) |
//! | [`unset_staged`] | `secrets unset <names...> --app <app> --stage` |
//! | [`deploy`] | `secrets deploy --app <app>` |
//!
//! Fly digests are not computable locally (D0, `docs/design/spike-d0-findings.md` Q4), so change
//! detection is stage-and-compare (P1, §6.4): S6 calls `list` (A), `stage`, `list` (B) and
//! compares digests by name. `status` is passed through but never used for change
//! detection; S6 uses it only as an extra deploy trigger (pending `Staged`/`Partial`).
//!
//! # Stdin encoding (SR-3, SR-4)
//!
//! Values travel only on stdin, never in argv, env or files. Each value is one line
//! `NAME="""VALUE"""\n`. Per flyctl v0.4.112 `parser.go` (findings "Follow-up 2a") the
//! triple-quoted form stores VALUE byte-for-byte when VALUE has no newline and, if it
//! contains `#`, an even number of `"` before its first `#`. Everything else that could be
//! mangled is refused up front, for the whole batch, before any call ([`validate_import`]).
//! The test module carries a Rust port of that parser and proves the round trip.
//!
//! # Errors (FR-10, SR-1)
//!
//! - `flyctl` missing from PATH: [`Error::Dependency`].
//! - A non-zero exit is diagnosed (FR-26) with `flyctl auth whoami`, exit status only (its
//!   stdout names the account and is dropped unread, SR-1): failing → [`Error::Auth`]
//!   "not logged in to Fly" with `flyctl auth login` (or "set FLY_API_TOKEN" under CI);
//!   succeeding → [`Error::Target`] naming the app (access, existence, machines for a
//!   deploy). With `FLY_API_TOKEN` / `FLY_ACCESS_TOKEN` set, `auth whoami` is not consulted
//!   (app-scoped deploy tokens fail it): [`Error::Target`] naming the app and the
//!   variable. Only when `auth whoami` itself cannot run does the error keep the
//!   last-resort hint `"...; run `flyctl ...` to see why"` (program, subcommand, names and
//!   the app only, never values or stdin).
//! - Any other spawn failure or unparseable list JSON: [`Error::Target`].
//! - A captured call that exceeds the runner's timeout: [`Error::Target`] naming `flyctl`.
//! - A refused value or name: [`Error::Policy`] naming the key and the rule, never the value.
//!
//! Child stderr is never captured or echoed (the runner discards it). flyctl exits 1 for
//! every error, auth included, so authentication is told apart by the separate, read-only
//! `flyctl auth whoami` call ([`auth_whoami`], shared with `doctor`), never by guessing.

pub mod config;

pub use config::{FLYCTL_TESTED, FlyTarget, PROVIDER};

use std::collections::BTreeSet;
use std::io;

use serde::Deserialize;
use zeroize::Zeroizing;

use crate::domain::SecretValue;
use crate::domain::plan::StoreEntry;
use crate::error::Error;
use crate::host::{Host, Tool};
use crate::ports::{StagedRuntime, StagedStore, Store};
use crate::provider::{Check, Verdict};
use crate::runner::{
    Call, CommandRunner, Outcome, Output, PROBE_TIMEOUT, status_text, unknown_text,
};

/// The Fly CLI binary.
pub const PROGRAM: &str = "flyctl";

/// The Fly CLI and how to install it.
pub const FLYCTL: Tool = Tool {
    program: PROGRAM,
    ci: "install flyctl in the CI job (GitHub Actions: \
         uses: superfly/flyctl-actions/setup-flyctl@master)",
    macos: "install: brew install flyctl",
    windows: "install: iwr https://fly.io/install.ps1 -useb | iex",
    linux: "install: curl -L https://fly.io/install.sh | sh",
    vendor: "Fly",
    status_page: "https://status.flyio.net",
};

/// A Fly token in the environment, in the order they are tried (by name only).
pub const CREDENTIAL_VARS: &[&str] = &["FLY_API_TOKEN", "FLY_ACCESS_TOKEN"];

/// Longest encoded stdin line (`NAME="""VALUE"""`, excluding the newline) we will send.
///
/// flyctl's `bufio.Scanner` silently drops everything from a line of 64 KiB onwards and
/// still reports success, which digests could not reveal; 60 000 leaves a safe margin.
pub const MAX_IMPORT_LINE: usize = 60_000;

const TRIPLE_QUOTE: &[u8] = b"\"\"\"";

/// One `secrets list --json` entry. Unknown fields (future ones) are ignored.
#[derive(Deserialize)]
struct ListEntry {
    name: String,
    #[serde(default)]
    digest: Option<String>,
    #[serde(default)]
    status: Option<String>,
}

/// Fly as both target ports (FR-28): a Fly secret is the store entry and the env var at
/// once. Each method is the free function of the same operation, unchanged.
pub struct Fly<'a> {
    pub runner: &'a dyn CommandRunner,
    pub app: &'a str,
}

impl Store for Fly<'_> {
    fn list(&self) -> Result<Vec<StoreEntry>, Error> {
        list(self.runner, self.app)
    }
    fn refusal(&self, name: &str, value: &SecretValue) -> Option<(&'static str, &'static str)> {
        entry_refusal_reason(name, value)
    }
}

impl StagedStore for Fly<'_> {
    fn validate(&self, batch: &[(String, &SecretValue)]) -> Result<(), Error> {
        validate_import(batch)
    }
    fn write(&self, batch: &[(String, &SecretValue)]) -> Result<(), Error> {
        stage(self.runner, self.app, batch)
    }
    fn remove(&self, names: &[String]) -> Result<(), Error> {
        unset_staged(self.runner, self.app, names)
    }
}

impl StagedRuntime for Fly<'_> {
    fn deploy(&self) -> Result<(), Error> {
        deploy(self.runner, self.app)
    }
}

/// Every secret on `app` with its version and pending flag: one
/// `flyctl secrets list --app <app> --json` call.
pub fn list(r: &dyn CommandRunner, app: &str) -> Result<Vec<StoreEntry>, Error> {
    const WHAT: &str = "fly secrets list";
    let entries: Vec<ListEntry> =
        read_json(r, WHAT, app, &["secrets", "list", "--app", app, "--json"])?;
    Ok(entries
        .into_iter()
        .map(|e| StoreEntry {
            name: e.name,
            version: e.digest,
            pending: matches!(e.status.as_deref(), Some("Staged" | "Partial")),
        })
        .collect())
}

/// Stage every `(fly name, value)` with one `flyctl secrets import --app <app> --stage`
/// call, values on stdin only. The whole batch is validated first; on any refusal nothing
/// is staged. An empty batch makes no call.
pub fn stage(
    r: &dyn CommandRunner,
    app: &str,
    values: &[(String, &SecretValue)],
) -> Result<(), Error> {
    if values.is_empty() {
        return Ok(());
    }
    let input = encode_import(values)?;
    // The import itself cannot be re-run by hand without the values; listing the app shows
    // whether access and authentication work.
    run(
        r,
        Effect::Write,
        "fly secrets import",
        app,
        &["secrets", "import", "--app", app, "--stage"],
        Some(&input),
        &["secrets", "list", "--app", app],
    )?;
    Ok(())
}

/// Remove `names` from `app` as a staged change: one
/// `flyctl secrets unset <names...> --app <app> --stage` call. Names are not secret, so
/// they go in argv; each must be a valid Fly name (so none can be read as a flag). An
/// empty list makes no call. Callers decide what may be pruned (FR-8).
pub fn unset_staged(r: &dyn CommandRunner, app: &str, names: &[String]) -> Result<(), Error> {
    if names.is_empty() {
        return Ok(());
    }
    if let Some(bad) = names.iter().find(|n| !valid_name(n)) {
        return Err(refused(bad, "fly-name-invalid", "unset"));
    }
    let mut args = vec!["secrets", "unset"];
    args.extend(names.iter().map(String::as_str));
    args.extend(["--app", app, "--stage"]);
    run(
        r,
        Effect::Write,
        "fly secrets unset",
        app,
        &args,
        None,
        &args,
    )?;
    Ok(())
}

/// Deploy staged secrets: one `flyctl secrets deploy --app <app>` call (FR-7; S6 calls it
/// only with `--deploy`). On an app with no machines flyctl exits 1 (D0), which maps to
/// `Error::Target("fly secrets deploy failed (exit 1)")`.
pub fn deploy(r: &dyn CommandRunner, app: &str) -> Result<(), Error> {
    run(
        r,
        Effect::Write,
        "fly secrets deploy",
        app,
        &["secrets", "deploy", "--app", app],
        None,
        &["secrets", "deploy", "--app", app],
    )?;
    Ok(())
}

/// `flyctl status --app <app> --json`: only the app `Status` and each machine's `state`
/// are read; every other field (organization, hostnames) is skipped unread. flyctl renders
/// its Go structs as-is, so keys are `Status` / `Machines`; lower case is accepted too.
#[derive(Deserialize)]
struct AppStatus {
    #[serde(rename = "Status", alias = "status", default)]
    status: Option<String>,
    #[serde(rename = "Machines", alias = "machines", default)]
    machines: Option<Vec<MachineState>>,
}

#[derive(Deserialize)]
struct MachineState {
    #[serde(default)]
    state: Option<String>,
}

/// One `flyctl releases --app <app> --json` entry: version and status only (the `User`
/// field names an account and is skipped unread, SR-1).
#[derive(Deserialize)]
struct Release {
    #[serde(rename = "Version", alias = "version", default)]
    version: Option<i64>,
    #[serde(rename = "Status", alias = "status", default)]
    status: Option<String>,
    #[serde(rename = "InProgress", alias = "inProgress", default)]
    in_progress: Option<bool>,
}

/// Fly state before the first write (NR-24): two reads, `flyctl status --app <app> --json`
/// and `flyctl releases --app <app> --json`.
///
/// - App `suspended` or `dead`: refused (`Target`) with `flyctl apps resume <app>`.
/// - No machines, or none started: a warning; secrets still stage, and a deploy updates
///   stopped machines on their next start (a deploy with no machine at all fails, D0).
/// - Latest release `pending` / `running` (or `InProgress`): refused, a deploy is running.
///
/// A missing or unreachable app fails the read and is diagnosed like any flyctl call
/// (FR-26); an unanswered read is the outage error (NR-28).
pub fn preflight(r: &dyn CommandRunner, app: &str) -> Result<Vec<Check>, Error> {
    let status: AppStatus = read_json(r, "fly status", app, &["status", "--app", app, "--json"])?;
    let state = status.status.unwrap_or_default().to_ascii_lowercase();
    if matches!(state.as_str(), "suspended" | "dead") {
        return Err(Error::Target(format!(
            "Fly app {app} is {state}; nothing was changed\n  Next: {PROGRAM} apps resume {app}, \
             then re-run"
        )));
    }
    let machines = status.machines.unwrap_or_default();
    let started = machines
        .iter()
        .filter(|m| matches!(m.state.as_deref(), Some("started" | "starting")))
        .count();
    let mut checks = Vec::new();
    let warn = |detail: String| Check {
        name: "fly app",
        outcome: Ok(Verdict::Warn(detail)),
    };
    if machines.is_empty() {
        checks.push(warn(format!(
            "{app} has no machines: secrets still stage; a deploy needs a machine \
             ({PROGRAM} deploy --app {app})"
        )));
    } else if started == 0 {
        checks.push(warn(
            "machines stopped: secrets still stage; deploy updates them on next start".into(),
        ));
    }
    let releases: Vec<Release> = read_json(
        r,
        "fly releases",
        app,
        &["releases", "--app", app, "--json"],
    )?;
    let latest = releases
        .iter()
        .max_by_key(|r| r.version.unwrap_or(i64::MIN));
    if let Some(rel) = latest.filter(|r| release_running(r)) {
        let v = rel
            .version
            .map(|v| format!(" (release v{v})"))
            .unwrap_or_default();
        return Err(Error::Target(format!(
            "a deploy is already running on Fly app {app}{v}; nothing was changed\n  Next: \
             wait, then re-run"
        )));
    }
    Ok(checks)
}

fn release_running(r: &Release) -> bool {
    r.in_progress == Some(true)
        || r.status
            .as_deref()
            .is_some_and(|s| matches!(s.to_ascii_lowercase().as_str(), "pending" | "running"))
}

/// One flyctl read whose stdout is JSON of type `T`. serde_json messages can quote input,
/// so a parse error reports only the position.
fn read_json<T: serde::de::DeserializeOwned>(
    r: &dyn CommandRunner,
    what: &str,
    app: &str,
    args: &[&str],
) -> Result<T, Error> {
    let hint = args.strip_suffix(&["--json"]).unwrap_or(args);
    let out = run(r, Effect::Read, what, app, args, None, hint)?;
    serde_json::from_slice(&out.stdout).map_err(|e| {
        Error::Target(format!(
            "{what} returned unexpected JSON (line {}, column {})",
            e.line(),
            e.column()
        ))
    })
}

/// Check a batch against every import rule without running anything; S6 may call this
/// before reading Fly so a bad value fails fast. Rules, checked per entry in order:
///
/// - `fly-name-invalid`: the name does not match `^[A-Z][A-Z0-9_]*$`;
/// - `import-duplicate-name`: the name occurs twice in the batch;
/// - `import-invalid-utf8`, `import-newline`, `import-hash-after-odd-quotes`: see
///   [`import_refusal`];
/// - `import-line-too-long`: the encoded line exceeds [`MAX_IMPORT_LINE`] bytes.
pub fn validate_import(values: &[(String, &SecretValue)]) -> Result<(), Error> {
    let mut seen = BTreeSet::new();
    for (name, value) in values {
        if !valid_name(name) {
            return Err(refused(name, "fly-name-invalid", "import"));
        }
        if !seen.insert(name.as_str()) {
            return Err(refused(name, "import-duplicate-name", "import"));
        }
        if let Some(rule) = entry_refusal(name, value) {
            return Err(refused(name, rule, "import"));
        }
    }
    Ok(())
}

/// The first per-entry import rule `(name, value)` breaks, or `None`: `fly-name-invalid`,
/// the [`import_refusal`] value rules, then `import-line-too-long`. Everything
/// [`validate_import`] checks except duplicates across a batch. `status` and `fly plan` run
/// it on every ready secret so they cannot show green for a value `fly sync` would refuse.
pub fn entry_refusal(name: &str, value: &SecretValue) -> Option<&'static str> {
    if !valid_name(name) {
        return Some("fly-name-invalid");
    }
    let v = value.expose().as_bytes();
    if let Some(rule) = import_refusal(v) {
        return Some(rule);
    }
    if encoded_len(name, v) > MAX_IMPORT_LINE {
        return Some("import-line-too-long");
    }
    None
}

/// [`entry_refusal`] with the rule's fixed reason (FR-22), for the planner's target check.
pub fn entry_refusal_reason(
    name: &str,
    value: &SecretValue,
) -> Option<(&'static str, &'static str)> {
    entry_refusal(name, value).map(|rule| (rule, import_reason(rule)))
}

/// The first value rule `value` breaks, or `None` if flyctl stores it unchanged in the
/// `NAME="""VALUE"""` form:
///
/// - `import-invalid-utf8`: flyctl sends values as JSON and Go replaces invalid bytes with
///   U+FFFD. (A [`SecretValue`] is always UTF-8; the rule exists for byte callers.)
/// - `import-newline`: contains `\n` or `\r`. Multiline values are out of scope (v0.1).
/// - `import-hash-after-odd-quotes`: contains `#` with an odd number of `"` before the
///   first one; flyctl would cut the value there (parser.go L37-40, where our leading `"""`
///   makes the count even).
pub fn import_refusal(value: &[u8]) -> Option<&'static str> {
    if std::str::from_utf8(value).is_err() {
        return Some("import-invalid-utf8");
    }
    if value.iter().any(|&b| b == b'\n' || b == b'\r') {
        return Some("import-newline");
    }
    if let Some(i) = value.iter().position(|&b| b == b'#')
        && value[..i].iter().filter(|&&b| b == b'"').count() % 2 == 1
    {
        return Some("import-hash-after-odd-quotes");
    }
    None
}

/// Validate (see [`validate_import`]) and encode the batch as flyctl import stdin, one
/// `NAME="""VALUE"""\n` line per entry. The buffer is zeroized on drop and allocated once
/// at its final size, so no reallocation leaves an unzeroized copy behind (SR-8).
pub fn encode_import(values: &[(String, &SecretValue)]) -> Result<Zeroizing<Vec<u8>>, Error> {
    validate_import(values)?;
    let total: usize = values
        .iter()
        .map(|(n, v)| encoded_len(n, v.expose().as_bytes()) + 1)
        .sum();
    let mut buf = Zeroizing::new(Vec::with_capacity(total));
    for (name, value) in values {
        buf.extend_from_slice(name.as_bytes());
        buf.push(b'=');
        buf.extend_from_slice(TRIPLE_QUOTE);
        buf.extend_from_slice(value.expose().as_bytes());
        buf.extend_from_slice(TRIPLE_QUOTE);
        buf.push(b'\n');
    }
    debug_assert_eq!(buf.len(), total);
    Ok(buf)
}

/// Length of `NAME="""VALUE"""` without the newline.
fn encoded_len(name: &str, value: &[u8]) -> usize {
    name.len() + 1 + 2 * TRIPLE_QUOTE.len() + value.len()
}

/// `^[A-Z][A-Z0-9_]*$`, the Fly names opv renders (S1 validates the template).
fn valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z'))
        && bytes.all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

/// A refusal names the key, the rule and its fixed reason, never the value (FR-15, FR-22,
/// SR-1).
fn refused(name: &str, rule: &str, op: &str) -> Error {
    Error::Policy(format!(
        "fly {op} refused for {name:?}: rule {rule} ({}); nothing was sent to Fly",
        import_reason(rule)
    ))
}

/// The fixed reason for a Fly import or name rule (FR-22): a constant per rule, never
/// anything read from the value.
pub fn import_reason(rule: &str) -> &'static str {
    match rule {
        "fly-name-invalid" => "not a valid Fly secret name",
        "import-duplicate-name" => "name occurs twice in one import",
        "import-invalid-utf8" => "not valid UTF-8",
        "import-newline" => "contains a line break",
        "import-hash-after-odd-quotes" => "a # follows an odd number of double quotes",
        "import-line-too-long" => "too long for one Fly import line",
        _ => "refused by the Fly import rules",
    }
}

/// `flyctl auth whoami`, exit status only: `Ok(true)` logged in, `Ok(false)` not. A
/// diagnosis probe with its own short limit ([`PROBE_TIMEOUT`]). Its stdout names the
/// account (an email), so it is dropped unread (zeroized with the `Output`, SR-1). Shared
/// by `doctor` and the failure diagnosis (FR-26).
pub fn auth_whoami(r: &dyn CommandRunner) -> io::Result<bool> {
    r.probe(&Call::new(PROGRAM, &["auth", "whoami"]), PROBE_TIMEOUT)
        .map(|o| o.status == 0)
}

/// "not logged in to Fly" with the next step for `host` (FR-26): `flyctl auth login`
/// interactively, or set FLY_API_TOKEN under CI. `failed` names what failed first, if
/// anything before `flyctl auth whoami`. Text only, never a prompt (FR-9).
pub fn not_logged_in(host: &Host, failed: Option<&str>) -> Error {
    let ctx = match failed {
        Some(f) => format!("{f}; {PROGRAM} auth whoami failed"),
        None => format!("{PROGRAM} auth whoami failed"),
    };
    let next = if host.ci {
        "next: set FLY_API_TOKEN to a Fly token that can access the app (as a CI secret, \
         never in the repository)"
            .to_string()
    } else {
        format!("log in: {PROGRAM} auth login")
    };
    Error::Auth(format!(
        "not logged in to Fly ({ctx})\n  {next}\n  then run opv again"
    ))
}

/// The value-free next step for a failed call on `app` whose cause opv cannot tell apart:
/// access, a missing app, or (for a deploy) an app with no machines (D0).
fn check_app(app: &str, who: &str) -> String {
    format!(
        "{PROGRAM} failed for app {app}: check that {who} can access it, that the app \
         exists, and, for a deploy, that it has at least one machine"
    )
}

/// The error for a flyctl call that exited `status` (FR-26, FR-10). Host detection happens
/// here, on the failure path only.
///
/// - A Fly token in the environment (`FLY_API_TOKEN` / `FLY_ACCESS_TOKEN`): `Target`
///   (exit 5) naming the app and the variable. `auth whoami` is not consulted, because
///   app-scoped deploy tokens fail it.
/// - Otherwise [`auth_whoami`]: failing → `Auth` (exit 7, [`not_logged_in`]); succeeding →
///   `Target` (exit 5) naming the app; unable to run (spawn error, timeout) → `Target` with
///   the last-resort re-run `hint` (names and the app only).
fn failure(
    r: &dyn CommandRunner,
    host: &dyn Fn() -> Host,
    effect: Effect,
    what: &str,
    app: &str,
    status: i32,
    hint: &[&str],
) -> Error {
    let failed = format!("{what} failed ({})", status_text(status));
    let h = host();
    if let Some(var) = h.token(CREDENTIAL_VARS) {
        return Error::Target(format!(
            "{failed}\n  {}",
            check_app(app, &format!("the token in {var}"))
        ));
    }
    match auth_whoami(r) {
        Ok(false) => not_logged_in(&h, Some(&failed)),
        Ok(true) => Error::Target(format!(
            "{failed}: logged in to Fly\n  {}",
            check_app(app, "the logged-in Fly account")
        )),
        Err(_) if effect == Effect::Write => Error::Unknown(format!(
            "{failed}; the change may or may not have been applied\n  next: run \
             `{PROGRAM} {}` to see why, then re-run the same command",
            hint.join(" ")
        )),
        Err(_) => Error::Target(format!(
            "{failed}; run `{PROGRAM} {}` to see why",
            hint.join(" ")
        )),
    }
}

/// Whether a flyctl call changes the app (NR-2): reads are retried by the runner, writes
/// never are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Effect {
    Read,
    Write,
}

/// Run one flyctl subcommand and map failures to typed, value-free errors. A non-zero exit
/// is diagnosed by [`failure`] (child stderr is discarded, SR-1). The host is detected
/// only on failure.
///
/// Mapping (NR-2): a read still failing after its retries, or a write that exited non-zero,
/// is diagnosed as before (`auth whoami` is a definite read-back for sign-in); a write
/// whose diagnosis cannot run, or that timed out, was killed or was lost, is
/// `Error::Unknown` (exit 9, safe to re-run). A read that never finished after its retries
/// is the outage error naming the step and Fly's status page (NR-28, exit 9).
fn run(
    r: &dyn CommandRunner,
    effect: Effect,
    what: &str,
    app: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
    hint: &[&str],
) -> Result<Output, Error> {
    run_on(r, &Host::detect, effect, what, app, args, stdin, hint)
}

#[allow(clippy::too_many_arguments)]
fn run_on(
    r: &dyn CommandRunner,
    host: &dyn Fn() -> Host,
    effect: Effect,
    what: &str,
    app: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
    hint: &[&str],
) -> Result<Output, Error> {
    let call = Call::new(PROGRAM, args).with_stdin(stdin);
    let outcome = match effect {
        Effect::Read => r.read(&call, &[]),
        Effect::Write => r.write(&call),
    }
    .map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => Error::Dependency(format!(
            "{PROGRAM} not found on PATH\n  {}",
            host().install_hint(FLYCTL)
        )),
        // The runner's own message names the program (no child output).
        io::ErrorKind::TimedOut => Error::Target(format!("{what}: {e}")),
        kind => Error::Target(format!("{what} could not start {PROGRAM} ({kind})")),
    })?;
    match outcome {
        Outcome::Done(out) => Ok(out),
        Outcome::Refused(out) => Err(failure(r, host, effect, what, app, out.status, hint)),
        Outcome::Unknown {
            status: Some(status),
            ..
        } => Err(failure(r, host, effect, what, app, status, hint)),
        Outcome::Unknown { reason, .. } if effect == Effect::Write => Err(Error::Unknown(format!(
            "{what}: {}; the change may or may not have been applied\n  next: re-run \
                 the same command",
            unknown_text(PROGRAM, reason)
        ))),
        // A read unanswered after its last attempt: Fly is unreachable (NR-28).
        Outcome::Unknown { .. } => Err(FLYCTL.outage(what)),
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;
    use crate::runner::Output;
    use crate::runner::fake::{FakeRunner, failed_read};

    const MARK: &str = "sk-proj-LEAKCANARY";

    fn sv(v: &str) -> SecretValue {
        SecretValue::new(v.to_string())
    }

    fn args(r: &FakeRunner, i: usize) -> Vec<String> {
        r.calls.borrow()[i].args.clone()
    }

    fn stdin(r: &FakeRunner, i: usize) -> Vec<u8> {
        r.calls.borrow()[i].stdin.clone().expect("stdin was sent")
    }

    fn err_text(e: &Error) -> String {
        format!("{e} {e:?} {e:#?}")
    }

    // ---------------------------------------------------------------- stage

    #[test]
    fn stage_sends_values_only_on_stdin() {
        let r = FakeRunner::new([Output::success("")]);
        let v = sv("sk-proj-XYZ");
        stage(&r, "app", &[("FLEET__ALLUMATA__OPENAI_API_KEY".into(), &v)]).unwrap();
        let calls = r.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].program, "flyctl");
        assert_eq!(
            calls[0].args,
            ["secrets", "import", "--app", "app", "--stage"]
        );
        assert!(calls[0].env.is_empty());
        assert_eq!(
            calls[0].stdin.as_deref(),
            Some(&b"FLEET__ALLUMATA__OPENAI_API_KEY=\"\"\"sk-proj-XYZ\"\"\"\n"[..])
        );
        drop(calls);
        assert!(!r.argv_contains("sk-proj"));
    }

    #[test]
    fn stage_batches_every_value_into_one_import_call() {
        let r = FakeRunner::new([Output::success("")]);
        let (a, b, c) = (sv("alpha"), sv(" spaced "), sv("x=y#\"\"z"));
        stage(
            &r,
            "fleet-prod",
            &[("A".into(), &a), ("B_2".into(), &b), ("C".into(), &c)],
        )
        .unwrap();
        assert_eq!(r.calls.borrow().len(), 1);
        assert_eq!(
            args(&r, 0),
            ["secrets", "import", "--app", "fleet-prod", "--stage"]
        );
        assert_eq!(
            stdin(&r, 0),
            b"A=\"\"\"alpha\"\"\"\nB_2=\"\"\" spaced \"\"\"\nC=\"\"\"x=y#\"\"z\"\"\"\n".to_vec()
        );
        for v in ["alpha", "spaced", "x=y"] {
            assert!(!r.argv_contains(v), "{v} reached argv");
        }
    }

    #[test]
    fn empty_stage_makes_no_call() {
        let r = FakeRunner::default();
        stage(&r, "app", &[]).unwrap();
        assert!(r.calls.borrow().is_empty());
    }

    #[test]
    fn stage_refuses_whole_batch_naming_key_and_rule_never_value() {
        let long = format!("{MARK}{}", "x".repeat(MAX_IMPORT_LINE));
        let cases: Vec<(String, &str)> = vec![
            (format!("{MARK}\nsecond"), "import-newline"),
            (format!("{MARK}\r"), "import-newline"),
            (format!("{MARK}\rmid"), "import-newline"),
            (format!("{MARK}\"#frag"), "import-hash-after-odd-quotes"),
            (format!("\"\"\"{MARK}#"), "import-hash-after-odd-quotes"),
            (long, "import-line-too-long"),
        ];
        for (bad, rule) in cases {
            let r = FakeRunner::default(); // no response queued: any call would panic
            let good = sv("fine");
            let bad = sv(&bad);
            let e = stage(
                &r,
                "app",
                &[("GOOD".into(), &good), ("FLEET__P__BAD_KEY".into(), &bad)],
            )
            .unwrap_err();
            assert!(matches!(e, Error::Policy(_)), "{rule}: {e:?}");
            let t = err_text(&e);
            assert!(t.contains("FLEET__P__BAD_KEY"), "{t}");
            assert!(t.contains(rule), "{rule}: {t}");
            assert!(!t.contains(MARK), "value leaked: {t}");
            assert!(!t.contains("GOOD"), "names the wrong key: {t}");
            assert!(r.calls.borrow().is_empty(), "{rule}: staged something");
        }
    }

    #[test]
    fn stage_refuses_invalid_and_duplicate_names_before_any_call() {
        let v = sv(MARK);
        for name in [
            "",
            "lower",
            "1LEADING_DIGIT",
            "_LEAD",
            "HAS-DASH",
            "HAS SPACE",
            "EQ=X",
            "--app",
            "É",
        ] {
            let r = FakeRunner::default();
            let e = stage(&r, "app", &[(name.into(), &v)]).unwrap_err();
            assert!(matches!(e, Error::Policy(_)), "{name}: {e:?}");
            assert!(err_text(&e).contains("fly-name-invalid"), "{name}");
            assert!(!err_text(&e).contains(MARK));
            assert!(r.calls.borrow().is_empty());
        }
        let r = FakeRunner::default();
        let e = stage(&r, "app", &[("DUP".into(), &v), ("DUP".into(), &v)]).unwrap_err();
        let t = err_text(&e);
        assert!(
            t.contains("DUP") && t.contains("import-duplicate-name"),
            "{t}"
        );
        assert!(!t.contains(MARK));
        assert!(r.calls.borrow().is_empty());
    }

    #[test]
    fn line_length_limit_is_on_the_encoded_line() {
        let name = "FLEET__P__K";
        let overhead = name.len() + "=\"\"\"".len() + "\"\"\"".len();
        let at = sv(&"v".repeat(MAX_IMPORT_LINE - overhead));
        assert!(validate_import(&[(name.into(), &at)]).is_ok());
        let over = sv(&"v".repeat(MAX_IMPORT_LINE - overhead + 1));
        let e = validate_import(&[(name.into(), &over)]).unwrap_err();
        assert!(err_text(&e).contains("import-line-too-long"));
        // Multi-byte characters count as bytes, not chars.
        let euro = sv(&"€".repeat((MAX_IMPORT_LINE - overhead) / 3 + 1));
        assert!(validate_import(&[(name.into(), &euro)]).is_err());
    }

    #[test]
    fn import_refusal_byte_rules() {
        assert_eq!(import_refusal(b"plain"), None);
        assert_eq!(import_refusal(b""), None);
        assert_eq!(import_refusal(b"a\nb"), Some("import-newline"));
        assert_eq!(import_refusal(b"a\rb"), Some("import-newline"));
        assert_eq!(
            import_refusal(b"a\"#b"),
            Some("import-hash-after-odd-quotes")
        );
        assert_eq!(import_refusal(b"a\"\"#b"), None);
        assert_eq!(import_refusal(b"#lead"), None);
        assert_eq!(
            import_refusal(b"a#b\"c"),
            None,
            "quotes after the # don't count"
        );
        assert_eq!(import_refusal(b"\xff\xfe"), Some("import-invalid-utf8"));
        assert_eq!(import_refusal(b"ok\xc3"), Some("import-invalid-utf8"));
        assert_eq!(import_refusal("é€😀".as_bytes()), None);
    }

    #[test]
    fn stdin_buffer_is_zeroizing() {
        let v = sv("abc");
        let buf: Zeroizing<Vec<u8>> = encode_import(&[("K".into(), &v)]).unwrap();
        assert_eq!(buf.as_slice(), b"K=\"\"\"abc\"\"\"\n");
    }

    #[test]
    fn stage_failure_is_target_error_without_value_or_stderr() {
        let r = FakeRunner::new([Output::failure(1), logged_in()]);
        let v = sv(MARK);
        let e = stage(&r, "app", &[("K".into(), &v)]).unwrap_err();
        match &e {
            Error::Target(m) => assert_eq!(m, &logged_in_msg("fly secrets import", 1)),
            other => panic!("{other:?}"),
        }
        assert!(!err_text(&e).contains(MARK));
    }

    // ---------------------------------------------------------------- list

    #[test]
    fn list_parses_names_and_digests() {
        let r = FakeRunner::new([Output::success(
            &include_bytes!("../../../tests/fixtures/fly_list.json")[..],
        )]);
        let s = list(&r, "app").unwrap();
        assert_eq!(
            s,
            vec![
                StoreEntry {
                    name: "A".into(),
                    version: Some("<digest-a>".into()),
                    pending: true,
                },
                StoreEntry {
                    name: "B".into(),
                    version: Some("<digest-b>".into()),
                    pending: true,
                },
            ]
        );
        assert_eq!(r.calls.borrow().len(), 1);
        assert_eq!(r.calls.borrow()[0].program, "flyctl");
        assert_eq!(args(&r, 0), ["secrets", "list", "--app", "app", "--json"]);
        assert!(r.calls.borrow()[0].stdin.is_none());
    }

    #[test]
    fn list_real_shape_keeps_status_and_tolerates_missing_digest() {
        let json = br#"[
          {"name":"FLEET__ALLUMATA__OPENAI_API_KEY","digest":"abbf42e97d95a292","status":"Deployed"},
          {"name":"FLEET__ALLUMATA__STRIPE_SECRET_KEY","digest":"abd0c8276c1dd3e9","status":"Staged"},
          {"name":"OTHER_TOOL","digest":"0123456789abcdef","status":"Partial","extra":1},
          {"name":"NULL_DIGEST","digest":null,"status":"Unknown"},
          {"name":"NO_DIGEST"}
        ]"#;
        let r = FakeRunner::new([Output::success(&json[..])]);
        let s = list(&r, "fleet-prod").unwrap();
        let got: Vec<(&str, Option<&str>)> = s
            .iter()
            .map(|f| (f.name.as_str(), f.version.as_deref()))
            .collect();
        assert_eq!(
            got,
            [
                ("FLEET__ALLUMATA__OPENAI_API_KEY", Some("abbf42e97d95a292")),
                (
                    "FLEET__ALLUMATA__STRIPE_SECRET_KEY",
                    Some("abd0c8276c1dd3e9")
                ),
                ("OTHER_TOOL", Some("0123456789abcdef")),
                ("NULL_DIGEST", None),
                ("NO_DIGEST", None),
            ]
        );
        let pending: Vec<bool> = s.iter().map(|f| f.pending).collect();
        assert_eq!(pending, [false, true, true, false, false]);
    }

    #[test]
    fn list_of_empty_app_is_empty() {
        let r = FakeRunner::new([Output::success("[]\n")]);
        assert!(list(&r, "app").unwrap().is_empty());
    }

    #[test]
    fn list_malformed_json_is_target_error_without_echoing_output() {
        for body in [
            &b"not json sk-proj-LEAKCANARY"[..],
            b"{\"name\":\"A\"}",
            b"",
        ] {
            let r = FakeRunner::new([Output::success(body)]);
            let e = list(&r, "app").unwrap_err();
            assert!(matches!(e, Error::Target(_)), "{e:?}");
            assert!(!err_text(&e).contains(MARK));
        }
    }

    #[test]
    fn failure_is_target_error() {
        let r = FakeRunner::new(failed_read(1).chain([logged_in()]));
        match list(&r, "app") {
            Err(Error::Target(m)) => assert_eq!(m, logged_in_msg("fly secrets list", 1)),
            other => panic!("{other:?}"),
        }
        assert_eq!(r.calls.borrow()[3].args, vec!["auth", "whoami"]);
    }

    // ---------------------------------------------------------------- unset / deploy

    #[test]
    fn unset_staged_passes_names_and_stage_flag() {
        let r = FakeRunner::new([Output::success("")]);
        unset_staged(&r, "app", &["FLEET__A__X".into(), "FLEET__B__Y".into()]).unwrap();
        assert_eq!(
            args(&r, 0),
            [
                "secrets",
                "unset",
                "FLEET__A__X",
                "FLEET__B__Y",
                "--app",
                "app",
                "--stage"
            ]
        );
        assert!(r.calls.borrow()[0].stdin.is_none());
    }

    #[test]
    fn empty_unset_makes_no_call() {
        let r = FakeRunner::default();
        unset_staged(&r, "app", &[]).unwrap();
        assert!(r.calls.borrow().is_empty());
    }

    #[test]
    fn unset_refuses_invalid_names_before_any_call() {
        let r = FakeRunner::default();
        let e = unset_staged(&r, "app", &["OK".into(), "--app".into()]).unwrap_err();
        assert!(err_text(&e).contains("fly-name-invalid"));
        assert!(r.calls.borrow().is_empty());
    }

    #[test]
    fn unset_failure_is_target_error() {
        let r = FakeRunner::new([Output::failure(2), logged_in()]);
        match unset_staged(&r, "app", &["X".into()]) {
            Err(Error::Target(m)) => assert_eq!(m, logged_in_msg("fly secrets unset", 2)),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn deploy_runs_secrets_deploy() {
        let r = FakeRunner::new([Output::success("")]);
        deploy(&r, "app").unwrap();
        assert_eq!(r.calls.borrow()[0].program, "flyctl");
        assert_eq!(args(&r, 0), ["secrets", "deploy", "--app", "app"]);
    }

    #[test]
    fn deploy_without_machines_is_target_error() {
        // D0: `fly secrets deploy` on an app with no machines exits 1.
        let r = FakeRunner::new([Output::failure(1), logged_in()]);
        match deploy(&r, "app") {
            Err(Error::Target(m)) => assert_eq!(m, logged_in_msg("fly secrets deploy", 1)),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn non_zero_exit_while_logged_in_is_never_auth() {
        // flyctl has no distinct auth exit code and stderr is discarded (SR-1): no exit
        // status is guessed into Auth; only a failing `auth whoami` is.
        for code in [1, 2, 3, 4, 5, 77, 126, 127, 255, -1] {
            let r = FakeRunner::new(failed_read(code).chain([logged_in()]));
            assert!(matches!(list(&r, "app"), Err(Error::Target(_))), "{code}");
        }
    }

    #[test]
    fn missing_flyctl_is_dependency_error_other_spawn_errors_are_target() {
        let r = FakeRunner::default();
        r.push_io_error(io::ErrorKind::NotFound);
        assert!(matches!(list(&r, "app"), Err(Error::Dependency(_))));
        let r = FakeRunner::default();
        r.push_io_error(io::ErrorKind::PermissionDenied);
        let v = sv(MARK);
        let e = stage(&r, "app", &[("K".into(), &v)]).unwrap_err();
        assert!(matches!(e, Error::Target(_)), "{e:?}");
        assert!(!err_text(&e).contains(MARK));
        let r = FakeRunner::default();
        r.push_io_error(io::ErrorKind::NotFound);
        assert!(matches!(deploy(&r, "app"), Err(Error::Dependency(_))));
    }

    /// I6: the re-run hint is built from program, subcommand, names and IDs only.
    /// The last-resort re-run hint (only when `auth whoami` cannot run) holds names and IDs
    /// only.
    #[test]
    fn failure_hint_never_contains_a_value_or_stdin() {
        for (attempts, call) in four_calls() {
            let r = FakeRunner::new((0..attempts).map(|_| Output {
                status: 1,
                stdout: zeroize::Zeroizing::new(MARK.as_bytes().to_vec()),
            }));
            r.push_io_error(io::ErrorKind::PermissionDenied);
            let e = call(&r).unwrap_err();
            let t = err_text(&e);
            assert!(matches!(e, Error::Target(_) | Error::Unknown(_)), "{t}");
            assert!(t.contains("run `flyctl secrets "), "{t}");
            assert!(t.contains("--app fleet-prod"), "{t}");
            assert!(t.contains("to see why"), "{t}");
            assert!(!t.contains(MARK), "value in hint: {t}");
            assert!(!t.contains("--json"), "{t}");
        }
    }

    // ---- FR-26: diagnosis of a failed flyctl call ------------------------------------

    const WHO: &str = "ops-FLYIDENTITY@example.com\n";

    fn logged_in() -> Output {
        Output::success(WHO)
    }

    fn logged_out() -> Output {
        Output {
            status: 1,
            stdout: zeroize::Zeroizing::new(WHO.as_bytes().to_vec()),
        }
    }

    fn logged_in_msg(what: &str, code: i32) -> String {
        format!(
            "{what} failed (exit {code}): logged in to Fly\n  flyctl failed for app app: \
             check that the logged-in Fly account can access it, that the app exists, and, \
             for a deploy, that it has at least one machine"
        )
    }

    type FlyCall = Box<dyn Fn(&FakeRunner) -> Result<(), Error>>;

    /// The four public calls, each with the number of attempts a failure takes (a read is
    /// retried, a write never is).
    fn four_calls() -> [(usize, FlyCall); 4] {
        let reads = crate::runner::READ_ATTEMPTS as usize;
        [
            (reads, Box::new(|r| list(r, "fleet-prod").map(|_| ()))),
            (
                1,
                Box::new(|r| {
                    let v = sv(MARK);
                    stage(r, "fleet-prod", &[("FLEET__P__K".into(), &v)])
                }),
            ),
            (
                1,
                Box::new(|r| unset_staged(r, "fleet-prod", &["FLEET__P__OLD".into()])),
            ),
            (1, Box::new(|r| deploy(r, "fleet-prod"))),
        ]
    }

    fn host(env: crate::host::FakeEnv) -> Host {
        Host::from_env(&env)
    }

    fn bash() -> Host {
        host(crate::host::FakeEnv::new("linux").shell("/bin/bash"))
    }

    #[test]
    fn flyctl_install_hint_per_platform() {
        let hints: Vec<String> = ["macos", "windows", "linux"]
            .map(|os| host(crate::host::FakeEnv::new(os)).install_hint(FLYCTL))
            .into();
        assert_eq!(
            hints,
            [
                "install: brew install flyctl",
                "install: iwr https://fly.io/install.ps1 -useb | iex",
                "install: curl -L https://fly.io/install.sh | sh",
            ]
        );
    }

    #[test]
    fn flyctl_install_hint_under_ci_is_the_setup_action() {
        let ci = host(crate::host::FakeEnv::new("linux").var("CI"));
        assert!(ci.install_hint(FLYCTL).contains("setup-flyctl"));
    }

    #[test]
    fn fly_api_token_wins_over_fly_access_token() {
        let h = host(
            crate::host::FakeEnv::new("linux")
                .var("FLY_ACCESS_TOKEN")
                .var("FLY_API_TOKEN"),
        );
        assert_eq!(h.token(CREDENTIAL_VARS), Some("FLY_API_TOKEN"));
    }

    /// `run_on` for a failing `secrets <sub>` on `app` with `host`.
    fn fail_on(h: Host, sub: &str, app: &str, whoami: Option<Output>) -> (Error, FakeRunner) {
        let effect = if sub == "list" {
            Effect::Read
        } else {
            Effect::Write
        };
        let r = match effect {
            Effect::Read => FakeRunner::new(failed_read(1)),
            Effect::Write => FakeRunner::new([Output::failure(1)]),
        };
        if let Some(w) = whoami {
            r.responses.borrow_mut().push_back(Ok(w));
        }
        let what = format!("fly secrets {sub}");
        let e = run_on(&r, &|| h, effect, &what, app, &["secrets", sub], None, &[]).unwrap_err();
        (e, r)
    }

    /// Logged out (no Fly token set): Auth (exit 7), "not logged in to Fly",
    /// `flyctl auth login`.
    #[test]
    fn logged_out_is_auth_exit_7_with_login_command() {
        let (e, _) = fail_on(bash(), "list", "app", Some(logged_out()));
        assert_eq!(e.exit_code(), 7, "{e}");
        let t = e.to_string();
        assert!(
            t.starts_with(
                "authentication error: not logged in to Fly (fly secrets list failed (exit 1); \
                 flyctl auth whoami failed)"
            ),
            "{t}"
        );
        assert!(t.contains("\n  log in: flyctl auth login\n"), "{t}");
        assert!(
            !t.contains("to see why") && !t.contains("FLYIDENTITY"),
            "{t}"
        );
    }

    /// Logged out on Windows, macOS, WSL, fish: the same `flyctl auth login` (one syntax).
    #[test]
    fn logged_out_login_command_is_the_same_on_every_interactive_platform() {
        for env in [
            crate::host::FakeEnv::new("windows"),
            crate::host::FakeEnv::new("macos").shell("/bin/zsh"),
            crate::host::FakeEnv::new("linux").var("WSL_DISTRO_NAME"),
            crate::host::FakeEnv::new("linux").shell("/usr/bin/fish"),
        ] {
            let t = not_logged_in(&host(env.clone()), None).to_string();
            assert!(
                t.contains("\n  log in: flyctl auth login\n"),
                "{env:?}: {t}"
            );
            assert!(!t.contains("FLY_API_TOKEN to a Fly token"), "{t}");
        }
    }

    /// CI without a Fly token: set FLY_API_TOKEN, no interactive command; exit 7.
    #[test]
    fn logged_out_under_ci_advises_fly_api_token() {
        let h = host(crate::host::FakeEnv::new("linux").var("GITHUB_ACTIONS"));
        let (e, _) = fail_on(h, "deploy", "app", Some(logged_out()));
        assert_eq!(e.exit_code(), 7, "{e}");
        let t = e.to_string();
        assert!(t.contains("not logged in to Fly"), "{t}");
        assert!(t.contains("\n  next: set FLY_API_TOKEN"), "{t}");
        assert!(
            !t.contains("auth login"),
            "no interactive command under CI: {t}"
        );
    }

    /// Logged in but the call failed: Target (exit 5) naming the app, access, existence
    /// and (for a deploy) machines, so a deploy on an app without machines is not
    /// misdirected.
    #[test]
    fn logged_in_but_failed_is_target_exit_5_naming_the_app() {
        let (e, _) = fail_on(bash(), "deploy", "fleet-prod", Some(logged_in()));
        assert_eq!(e.exit_code(), 5, "{e}");
        let t = e.to_string();
        assert!(
            t.contains(
                "flyctl failed for app fleet-prod: check that the logged-in Fly account can \
                 access it, that the app exists, and, for a deploy, that it has at least one \
                 machine"
            ),
            "{t}"
        );
        assert!(
            !t.contains("to see why") && !t.contains("FLYIDENTITY"),
            "{t}"
        );
    }

    /// FR-26 / FR-10: with FLY_API_TOKEN or FLY_ACCESS_TOKEN set, `auth whoami` is not
    /// consulted (app-scoped deploy tokens fail it): Target (exit 5) naming the app and
    /// the variable, logged-in check skipped, CI or not.
    #[test]
    fn fly_token_set_is_target_exit_5_without_whoami() {
        for (env, var) in [
            (
                crate::host::FakeEnv::new("linux")
                    .shell("/bin/bash")
                    .var("FLY_API_TOKEN"),
                "FLY_API_TOKEN",
            ),
            (
                crate::host::FakeEnv::new("linux")
                    .var("CI")
                    .var("FLY_ACCESS_TOKEN"),
                "FLY_ACCESS_TOKEN",
            ),
        ] {
            let (e, r) = fail_on(host(env), "deploy", "fleet-prod", None);
            assert_eq!(e.exit_code(), 5, "{e}");
            let t = e.to_string();
            assert!(
                t.contains(&format!(
                    "flyctl failed for app fleet-prod: check that the token in {var} can \
                     access it, that the app exists, and, for a deploy, that it has at least \
                     one machine"
                )),
                "{t}"
            );
            assert!(
                !t.contains("auth login") && !t.contains("to see why"),
                "{t}"
            );
            assert_eq!(r.calls.borrow().len(), 1, "no auth whoami with a Fly token");
        }
    }

    /// The public calls detect the host on failure: with a Fly token, no `auth whoami`.
    #[test]
    fn public_calls_with_fly_token_skip_whoami() {
        let h = host(crate::host::FakeEnv::new("linux").var("FLY_API_TOKEN"));
        for (attempts, call) in four_calls() {
            let r = FakeRunner::new((0..attempts).map(|_| Output::failure(1)));
            let e = crate::host::with_test_host(h, || call(&r)).unwrap_err();
            assert_eq!(e.exit_code(), 5, "{e}");
            assert!(
                err_text(&e).contains("flyctl failed for app fleet-prod"),
                "{e}"
            );
            assert_eq!(r.calls.borrow().len(), attempts);
        }
    }

    /// FR-26: a diagnosis probe that times out is Unknown → the last-resort re-run hint.
    #[test]
    fn whoami_timeout_falls_back_to_rerun_hint() {
        let r = FakeRunner::new(failed_read(1));
        r.push_io_error(io::ErrorKind::TimedOut);
        let h = bash();
        let e = run_on(
            &r,
            &|| h,
            Effect::Read,
            "fly secrets list",
            "app",
            &["secrets", "list"],
            None,
            &["secrets", "list", "--app", "app"],
        )
        .unwrap_err();
        assert!(
            matches!(&e, Error::Target(m) if m == "fly secrets list failed (exit 1); run `flyctl secrets list --app app` to see why"),
            "{e:?}"
        );
    }

    /// Regression (FR-26): when `auth whoami` runs, no flyctl failure path says "to see
    /// why", logged in or not, and the account identity never appears.
    #[test]
    fn no_failure_path_says_to_see_why_when_whoami_runs() {
        for who in [logged_in, logged_out] {
            for (attempts, call) in four_calls() {
                let r = FakeRunner::new((0..attempts).map(|_| Output::failure(1)).chain([who()]));
                let e = call(&r).unwrap_err();
                let t = err_text(&e);
                assert!(!t.contains("to see why"), "{t}");
                assert!(!t.contains("FLYIDENTITY") && !t.contains(MARK), "{t}");
                assert!(matches!(e, Error::Target(_) | Error::Auth(_)), "{t}");
                let calls = r.calls.borrow();
                assert_eq!(calls.len(), attempts + 1);
                assert_eq!(calls[attempts].args, vec!["auth", "whoami"]);
            }
        }
    }

    /// NR-2: a write that timed out may or may not have happened: exit 9, safe to re-run.
    fn timed_out_write(call: impl Fn(&FakeRunner) -> Result<(), Error>) -> i32 {
        let r = FakeRunner::default();
        r.push_unknown("timeout");
        call(&r).unwrap_err().exit_code()
    }

    #[test]
    fn import_timeout_is_unknown_exit_9() {
        let v = sv(MARK);
        assert_eq!(
            timed_out_write(|r| stage(r, "fleet-prod", &[("FLEET__P__K".into(), &v)])),
            9
        );
    }

    #[test]
    fn unset_timeout_is_unknown_exit_9() {
        assert_eq!(
            timed_out_write(|r| unset_staged(r, "fleet-prod", &["FLEET__P__OLD".into()])),
            9
        );
    }

    #[test]
    fn deploy_timeout_is_unknown_exit_9() {
        assert_eq!(timed_out_write(|r| deploy(r, "fleet-prod")), 9);
    }

    /// NR-2: a failed write whose `auth whoami` cannot run is an unknown outcome (exit 9).
    #[test]
    fn failed_write_without_diagnosis_is_unknown_exit_9() {
        let r = FakeRunner::new([Output::failure(1)]);
        r.push_io_error(io::ErrorKind::TimedOut);
        let e = crate::host::with_test_host(bash(), || deploy(&r, "fleet-prod")).unwrap_err();
        assert_eq!(e.exit_code(), 9, "{e}");
    }

    /// NR-28: a read that timed out on every attempt is an outage: exit 9, nothing changed.
    #[test]
    fn read_timeout_is_an_outage_exit_9() {
        let r = FakeRunner::default();
        r.push_unknowns("timeout", crate::runner::READ_ATTEMPTS);
        assert_eq!(list(&r, "app").unwrap_err().exit_code(), 9);
    }

    /// NR-24: preflight reads the app status, then its releases; nothing else.
    #[test]
    fn preflight_reads_status_then_releases() {
        let r = FakeRunner::new([
            Output::success(r#"{"Status":"deployed","Machines":[{"state":"started"}]}"#),
            Output::success(r#"[{"Version":1,"Status":"complete"}]"#),
        ]);
        preflight(&r, "app").unwrap();
        let argv: Vec<String> = r.calls.borrow().iter().map(|c| c.args.join(" ")).collect();
        assert_eq!(
            argv,
            ["status --app app --json", "releases --app app --json"]
        );
    }

    /// NR-24: `InProgress` on the latest release (by version) refuses, whatever its status.
    #[test]
    fn latest_release_in_progress_refuses() {
        let r = FakeRunner::new([
            Output::success(r#"{"status":"deployed","machines":[{"state":"started"}]}"#),
            Output::success(
                r#"[{"Version":7,"InProgress":true,"Status":""},{"Version":6,"Status":"complete"}]"#,
            ),
        ]);
        assert!(
            preflight(&r, "app")
                .unwrap_err()
                .to_string()
                .contains("a deploy is already running on Fly app app (release v7)")
        );
    }

    /// NR-6, SR-1: an unexpected status document is a target error that never echoes it.
    #[test]
    fn unexpected_status_json_never_echoes_output() {
        let r = FakeRunner::new([Output::success(r#"{"Machines":"LEAKCANARY"}"#)]);
        let e = preflight(&r, "app").unwrap_err();
        assert!(!format!("{e} {e:?}").contains("LEAKCANARY"), "{e}");
    }

    /// FR-26: host detection happens only on the failure path.
    #[test]
    fn successful_call_never_detects_the_host() {
        let r = FakeRunner::new([Output::success("[]")]);
        let called = std::cell::Cell::new(false);
        let host = || {
            called.set(true);
            bash()
        };
        run_on(
            &r,
            &host,
            Effect::Read,
            "fly secrets list",
            "app",
            &["secrets", "list"],
            None,
            &[],
        )
        .unwrap();
        assert!(!called.get());
    }

    #[test]
    fn read_outage_names_the_step_and_status_page() {
        let r = FakeRunner::default();
        r.push_unknowns("lost", crate::runner::READ_ATTEMPTS);
        assert_eq!(
            list(&r, "app").unwrap_err().to_string(),
            "outcome unknown: Fly did not respond after 3 attempts (fly secrets list); nothing \
             was changed. Check https://status.flyio.net, then re-run"
        );
    }

    /// FR-22: an import refusal names the rule and its fixed reason, never the value.
    #[test]
    fn import_refusal_error_names_rule_and_reason() {
        let v = sv("a\"#ZQXMARK");
        let e = validate_import(&[("FLEET__P__K".to_string(), &v)]).unwrap_err();
        let t = e.to_string();
        assert!(
            t.contains(
                "rule import-hash-after-odd-quotes (a # follows an odd number of double quotes)"
            ),
            "{t}"
        );
        assert!(!t.contains("ZQXMARK"), "{t}");
    }

    #[test]
    fn entry_refusal_reason_pairs_rule_with_its_reason() {
        assert_eq!(
            entry_refusal_reason("FLEET__P__K", &sv("a\nb")),
            Some(("import-newline", "contains a line break"))
        );
    }

    #[test]
    fn entry_refusal_matches_validate_import_per_entry() {
        let name = "FLEET__P__K";
        let overhead = name.len() + 7;
        assert_eq!(entry_refusal(name, &sv("fine")), None);
        assert_eq!(
            entry_refusal("bad-name", &sv("fine")),
            Some("fly-name-invalid")
        );
        assert_eq!(
            entry_refusal(name, &sv("a\"#b")),
            Some("import-hash-after-odd-quotes")
        );
        assert_eq!(entry_refusal(name, &sv("a\nb")), Some("import-newline"));
        let at = sv(&"v".repeat(MAX_IMPORT_LINE - overhead));
        assert_eq!(entry_refusal(name, &at), None);
        let over = sv(&"v".repeat(MAX_IMPORT_LINE - overhead + 1));
        assert_eq!(entry_refusal(name, &over), Some("import-line-too-long"));
        // The rules' MAX_LEN fits on an import line for any realistic Fly name (< 900 bytes).
        let max = sv(&"v".repeat(crate::domain::rules::MAX_LEN));
        assert_eq!(entry_refusal(&"N".repeat(900), &max), None);
    }

    #[test]
    fn no_value_reaches_argv_across_a_full_sequence() {
        // list A -> stage -> list B -> unset -> deploy: values only ever on stdin (SR-3).
        let r = FakeRunner::new([
            Output::success("[]"),
            Output::success(""),
            Output::success("[]"),
            Output::success(""),
            Output::success(""),
        ]);
        let (a, b) = (sv(MARK), sv(&format!("{MARK}-two \"q\" $x \\n")));
        list(&r, "app").unwrap();
        stage(&r, "app", &[("A".into(), &a), ("B".into(), &b)]).unwrap();
        list(&r, "app").unwrap();
        unset_staged(&r, "app", &["OLD".into()]).unwrap();
        deploy(&r, "app").unwrap();
        assert_eq!(r.calls.borrow().len(), 5);
        assert!(!r.argv_contains(MARK));
        assert!(r.calls.borrow().iter().all(|c| c.env.is_empty()));
        let only_stdin: Vec<bool> = r.calls.borrow().iter().map(|c| c.stdin.is_some()).collect();
        assert_eq!(only_stdin, [false, true, false, false, false]);
    }

    // ------------------------------------------------- flyctl import parser port
    //
    // A Rust port of `parseSecrets` in flyctl v0.4.112 `internal/command/secrets/parser.go`
    // (commit ca63052e), as documented line by line in docs/design/spike-d0-findings.md
    // ("Follow-up 2a"). Go strings are bytes; every byte the parser inspects (`\n`, `\r`,
    // `#`, `"`, `'`, `=`, ` `) is ASCII, and UTF-8 continuation bytes are never ASCII, so
    // char-level operations on `&str` are equivalent here.

    const TQ: &str = "\"\"\"";

    /// Returns the parsed (key, value) pairs, or `None` where flyctl would misbehave in a
    /// way we can't model faithfully (unterminated multiline at EOF, the `"` panic, a line
    /// with no `=`). Those outcomes are never a faithful round trip either way.
    fn go_parse(input: &str) -> Option<Vec<(String, String)>> {
        let mut out = Vec::new();
        let mut multi: Option<(String, Vec<String>)> = None;
        // L17: bufio.Scanner splits on '\n' and strips one trailing '\r' per line. A final
        // empty token after a trailing '\n' is not emitted; it would be skipped as blank.
        for line in input.split('\n') {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.len() >= 64 * 1024 {
                // L17/L77: the scanner stops silently, dropping the rest.
                return Some(out);
            }
            // L62-72: multiline continuation until a line ends with `"""`.
            if let Some((key, parts)) = multi.as_mut() {
                if let Some(last) = line.strip_suffix(TQ) {
                    parts.push(last.to_string());
                    out.push((std::mem::take(key), parts.join("\n")));
                    multi = None;
                } else {
                    parts.push(line.to_string());
                }
                continue;
            }
            // L27: blank / whitespace-only / leading '#' lines are skipped.
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            // L31: split at the first '='.
            let (k, v) = line.split_once('=')?;
            // L35: key TrimSpace; L36: strip leading U+0020 from the value only.
            let key = k.trim().to_string();
            let mut v = v.trim_start_matches(' ');
            // L37-40: cut at the first '#' when an even number of '"' precede it.
            if let Some(i) = v.find('#')
                && v[..i].matches('"').count() % 2 == 0
            {
                v = v[..i].trim_end_matches(' ');
            }
            if v.len() >= 6 && v.starts_with(TQ) && v.ends_with(TQ) {
                // L42-45: triple-quoted, inner text verbatim.
                v = &v[3..v.len() - 3];
            } else if let Some(rest) = v.strip_prefix(TQ) {
                // L46-51: start of a multiline value.
                multi = Some((key, vec![rest.to_string()]));
                continue;
            } else if v == "\"" {
                // L53-59: `value[1:0]` panics in flyctl.
                return None;
            } else if v.len() >= 2
                && ((v.starts_with('"') && v.ends_with('"'))
                    || (v.starts_with('\'') && v.ends_with('\'')))
            {
                v = &v[1..v.len() - 1];
            }
            out.push((key, v.to_string()));
        }
        if multi.is_some() {
            return None;
        }
        Some(out)
    }

    /// What flyctl would store for `value` sent in our encoding, ignoring our refusals.
    fn stored_unchecked(value: &str) -> Option<String> {
        let line = format!("K={TQ}{value}{TQ}\n");
        match go_parse(&line)?.as_slice() {
            [(k, v)] if k == "K" => Some(v.clone()),
            _ => None,
        }
    }

    #[test]
    fn parser_port_matches_documented_examples() {
        // Plain form pitfalls the triple-quoted form avoids (findings 2a).
        let p = |l: &str| go_parse(l).unwrap()[0].1.clone();
        assert_eq!(p("K=pa#ss"), "pa");
        assert_eq!(p("K=  lead"), "lead");
        assert_eq!(p("K=\"wrapped\""), "wrapped");
        assert_eq!(p("K='single'"), "single");
        assert_eq!(p("K=a=b=c"), "a=b=c");
        assert_eq!(p("K= probe-dq\"h#x$y\\z=w"), "probe-dq\"h#x$y\\z=w");
        assert_eq!(p("K=v  # comment"), "v");
        assert_eq!(p(" K =v"), "v");
        assert_eq!(go_parse(" K =v").unwrap()[0].0, "K");
        // Triple-quoted keeps spaces, quotes, `\`, `$`, `=`.
        assert_eq!(
            p("K=\"\"\"  a \"b\" 'c' \\n $X = \"\"\""),
            "  a \"b\" 'c' \\n $X = "
        );
        // A value of exactly `"` panics flyctl.
        assert!(go_parse("K=\"").is_none());
        // Comment and blank lines skipped; CRLF stripped.
        assert_eq!(
            go_parse("# c\n\n   \nA=1\r\nB=2\n").unwrap(),
            vec![("A".into(), "1".into()), ("B".into(), "2".into())]
        );
        // Odd quotes before '#' in our encoding: the cut fires and the value is mangled.
        assert_ne!(stored_unchecked("a\"#b").as_deref(), Some("a\"#b"));
    }

    fn tricky_corpus() -> Vec<String> {
        let mut v: Vec<String> = [
            "",
            " ",
            "  lead",
            "trail  ",
            " both ",
            "\t",
            "\ttab",
            "#",
            "##",
            "#lead",
            "trail#",
            "pa#ss",
            "a #b",
            "postgres://u:p@h/db#frag",
            "\"",
            "\"\"",
            "\"\"\"",
            "\"\"\"\"\"\"",
            "\"wrapped\"",
            "'single'",
            "'",
            "\"\"#even",
            "\"a\"\"b\"#c",
            "\"#odd",
            "a\"#b",
            "\"\"\"#",
            "x\"\"\"y",
            "ends\"\"\"",
            "\"\"\"starts",
            "$HOME",
            "${VAR}",
            "\\",
            "\\n",
            "back\\slash\\",
            "=",
            "==",
            "a=b=c",
            "=lead",
            "é",
            "€uro",
            "😀 emoji 😀",
            "日本語#テスト",
            "mixed \"q\" 'q' $ \\ = # end",
            "sk-proj-abc123_XYZ-789",
            "whsec_0123456789abcdef",
            "base64+/==",
            "\r",
            "a\rb",
            "\n",
            "a\nb",
            "trailing-cr\r",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        // Deterministic pseudo-random values over a tricky alphabet (xorshift64*).
        let alphabet = [
            "\"", "'", "#", "$", "\\", "=", " ", "\t", "a", "Z", "0", "é", "€", "😀", "\"\"\"",
            "\r", "\n", "{", "}", "%", "`", ";", "!", "\u{0}",
        ];
        let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            s.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        for _ in 0..20_000 {
            let len = (next() % 14) as usize;
            let val: String = (0..len)
                .map(|_| alphabet[(next() % alphabet.len() as u64) as usize])
                .collect();
            v.push(val);
        }
        v
    }

    #[test]
    fn every_accepted_value_round_trips_through_the_parser() {
        let mut accepted = 0;
        for value in tricky_corpus() {
            let v = sv(&value);
            let batch = [("K".to_string(), &v)];
            if validate_import(&batch).is_ok() {
                accepted += 1;
                let buf = encode_import(&batch).unwrap();
                let text = std::str::from_utf8(&buf).unwrap();
                assert_eq!(
                    go_parse(text),
                    Some(vec![("K".to_string(), value.clone())]),
                    "accepted value did not round-trip: {value:?}"
                );
            }
        }
        assert!(accepted > 5_000, "corpus too weak: {accepted} accepted");
    }

    #[test]
    fn refusal_rules_are_exact_for_single_line_values() {
        // For values without newline/CR (which we refuse by policy), the hash rule rejects
        // exactly the values flyctl would mangle: no false refusals, no misses.
        for value in tricky_corpus() {
            if value.contains('\n') || value.contains('\r') {
                continue;
            }
            let refused = import_refusal(value.as_bytes()).is_some();
            let faithful = stored_unchecked(&value).as_deref() == Some(value.as_str());
            assert_eq!(refused, !faithful, "rule mismatch for {value:?}");
        }
    }

    #[test]
    fn multi_value_batch_round_trips_in_order() {
        let corpus = tricky_corpus();
        let accepted: Vec<SecretValue> = corpus
            .iter()
            .filter(|v| import_refusal(v.as_bytes()).is_none())
            .take(500)
            .map(|v| sv(v))
            .collect();
        let batch: Vec<(String, &SecretValue)> = accepted
            .iter()
            .enumerate()
            .map(|(i, v)| (format!("K_{i}"), v))
            .collect();
        let buf = encode_import(&batch).unwrap();
        let parsed = go_parse(std::str::from_utf8(&buf).unwrap()).unwrap();
        let want: Vec<(String, String)> = batch
            .iter()
            .map(|(k, v)| (k.clone(), v.expose().to_string()))
            .collect();
        assert_eq!(parsed, want);
    }

    #[test]
    fn fly_store_write_is_one_staged_import() {
        let r = FakeRunner::new([Output::success(Vec::new())]);
        let v = sv(MARK);
        Fly {
            runner: &r,
            app: "app",
        }
        .write(&[("A".into(), &v)])
        .unwrap();
        let argv: Vec<String> = r.calls.borrow().iter().map(|c| c.args.join(" ")).collect();
        assert_eq!(argv, ["secrets import --app app --stage"]);
    }
}
