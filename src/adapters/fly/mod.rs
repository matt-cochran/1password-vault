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
//! # Errors (FR-10, SR-1; design `docs/design/error-catalog.md` §5)
//!
//! - `flyctl` missing from PATH: `Cause::ToolMissing`.
//! - A failed call (a non-zero exit, a timeout, a signal) is never classified here: what the
//!   runner observed and the call's reply go to [`diagnose::diagnose`] ([`failed_call`]),
//!   which reads the principal in effect (the person, a shell token, deploy credentials) and
//!   the recorded flyctl phrases. Only a phrase flyctl printed makes "signed out" (06.11);
//!   an unknown reply is `Unrecognized`, shown with the reply.
//! - A missing app and a signed-out CLI are not retried ([`FLYCTL`]'s phrases, 09.13).
//! - A refused value or name: [`Error::Policy`] naming the key and the rule, never the value.
//!
//! Child stderr is never echoed except through the scrubbed evidence box.

pub mod config;
pub mod diagnose;
pub mod login;

pub use config::{FLYCTL_TESTED, FlyTarget, PROVIDER};

use std::collections::BTreeSet;
use std::io;
use std::time::Duration;

use serde::Deserialize;
use zeroize::Zeroizing;

use crate::cause::{
    Cause, DiagnoseContext, DottedPath, ExitClass, Location, NamedBy, Observed, OutputProblem,
    Refusal, ResourceKind, ResourceName, ResourceRef, System, Unusable, Upstream,
};
use crate::domain::SecretValue;
use crate::domain::plan::StoreEntry;
use crate::error::Error;
use crate::host::{Host, Tool};
use crate::ports::{StagedRuntime, StagedStore, Store};
use crate::provider::{Check, Preflight, Verdict};
use crate::runner::{Call, CommandRunner, Outcome, Output, PROBE_TIMEOUT, Wait};

/// The Fly CLI binary.
pub const PROGRAM: &str = "flyctl";

/// The Fly CLI and how to install it.
pub const FLYCTL: Tool = Tool {
    program: PROGRAM,
    ci: "install flyctl in the CI job (GitHub Actions: \
         uses: superfly/flyctl-actions/setup-flyctl@1.6)",
    macos: "install: brew install flyctl",
    windows: "install: iwr https://fly.io/install.ps1 -useb | iex",
    linux: "install: curl -L https://fly.io/install.sh | sh",
    vendor: "Fly",
    status_page: "https://status.flyio.net",
    pinned_env: &[("FLY_NO_UPDATE_CHECK", "1"), ("NO_COLOR", "1")],
    // Recorded flyctl replies (tests/fixtures/fly/failures): a missing app and a signed-out
    // CLI are not transient, so a read reports them at once instead of retrying (09.13).
    not_found: &["app not found"],
    signed_out: &["no access token available"],
    aliases: &["fly"],
    version_args: &["version"],
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
            stamp: None,
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
    run(
        r,
        Effect::Write,
        "fly secrets import",
        app,
        &["secrets", "import", "--app", app, "--stage"],
        Some(&input),
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
    run(r, Effect::Write, "fly secrets unset", app, &args, None)?;
    Ok(())
}

/// Deploy staged secrets: one `flyctl secrets deploy --app <app>` call (FR-7; S6 calls it
/// only with `--deploy`). On an app with no machines flyctl exits 1 (D0), which maps to
/// `Error::Target("fly secrets deploy failed (exit 1)".into())`.
pub fn deploy(r: &dyn CommandRunner, app: &str) -> Result<(), Error> {
    run(
        r,
        Effect::Write,
        "fly secrets deploy",
        app,
        &["secrets", "deploy", "--app", app],
        None,
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
/// and `flyctl releases --app <app> --json` (shapes recorded from real flyctl output in
/// `tests/fixtures/fly/`).
///
/// - App `dead`: refused (`Target`); it cannot hold secrets.
/// - No machines (`suspended` and `pending` apps on the Machines platform have none): a
///   warning; secrets are app-level so they still stage, and `skip_deploy` is set because
///   there is nothing to restart.
/// - Machines present but none started: a warning; secrets still stage.
/// - Latest release `InProgress`, `pending` or `running`: a deploy is running; `sync` waits
///   for it, polling the releases every [`DEPLOY_POLL`] with a progress line at least every
///   [`DEPLOY_PROGRESS`], inside the run budget (NR-4) and at most [`DEPLOY_WAIT_MAX`];
///   still running then is refused with nothing changed.
///
/// A missing or unreachable app fails the read and is diagnosed like any flyctl call
/// (FR-26); an unanswered read is the outage error (NR-28).
pub fn preflight(r: &dyn CommandRunner, app: &str) -> Result<Preflight, Error> {
    let status: AppStatus = read_json(r, "fly status", app, &["status", "--app", app, "--json"])?;
    let state = status.status.unwrap_or_default().to_ascii_lowercase();
    if state == "dead" {
        // flyctl's own status read says the app cannot hold secrets; nothing was changed.
        return Err(unusable(&["status", "--app", app, "--json"], |seen| {
            Cause::TargetRefused {
                system: System::Fly,
                subject: app_ref(app),
                why: Refusal::NotRunning,
                env: None,
                target: None,
                seen,
            }
        }));
    }
    let machines = status.machines.unwrap_or_default();
    let started = machines
        .iter()
        .filter(|m| matches!(m.state.as_deref(), Some("started" | "starting")))
        .count();
    let mut pre = Preflight::default();
    let warn = |detail: String| Check {
        name: format!("fly app {app}").into(),
        outcome: Ok(Verdict::Warn(detail)),
    };
    if machines.is_empty() || matches!(state.as_str(), "suspended" | "pending") {
        pre.checks.push(warn(format!(
            "no machines; secrets are staged and apply when machines start (fly scale \
             count 1 --app {app})"
        )));
        pre.skip_deploy = Some(format!(
            "deploy skipped: {app} has no machines; staged secrets apply when machines start"
        ));
    } else if started == 0 {
        pre.checks.push(warn(
            "machines stopped; secrets are staged and apply when machines start".into(),
        ));
    }
    wait_for_running_deploy(r, app)?;
    Ok(pre)
}

/// How often `sync` re-reads the releases while a Fly deploy runs.
pub const DEPLOY_POLL: Duration = Duration::from_secs(5);
/// A progress line at least this often while waiting (NR-4).
pub const DEPLOY_PROGRESS: Duration = Duration::from_secs(15);
/// The longest `sync` waits for someone else's Fly deploy, whatever the run budget.
pub const DEPLOY_WAIT_MAX: Duration = Duration::from_secs(600);

/// Waits until the latest release is no longer running (see [`preflight`]).
fn wait_for_running_deploy(r: &dyn CommandRunner, app: &str) -> Result<(), Error> {
    let wait = Wait::new(r, DEPLOY_WAIT_MAX);
    let mut reported: Option<Duration> = None;
    loop {
        let releases: Vec<Release> = read_json(
            r,
            "fly releases",
            app,
            &["releases", "--app", app, "--json"],
        )?;
        let Some(latest) = releases
            .iter()
            .max_by_key(|r| r.version.unwrap_or(i64::MIN))
            .filter(|l| release_running(l))
        else {
            return Ok(());
        };
        let waited = wait.elapsed(r);
        if wait.over(r, DEPLOY_POLL) {
            return Err(deploy_still_running(app));
        }
        let note = if reported.is_none_or(|at| waited.saturating_sub(at) >= DEPLOY_PROGRESS) {
            reported = Some(waited);
            let release = latest
                .version
                .map(|v| format!(" (release v{v})"))
                .unwrap_or_default();
            format!(
                "waiting for the running Fly deploy of {app}{release} to finish, {} s",
                waited.as_secs()
            )
        } else {
            String::new()
        };
        wait.pause(r, DEPLOY_POLL, &note);
    }
}

/// A Fly deploy still running when the wait stopped (06.32), as flyctl's own releases read
/// shows it: nothing was changed, and the step is to wait for it (design §4.5).
fn deploy_still_running(app: &str) -> Error {
    unusable(&["releases", "--app", app, "--json"], |seen| {
        Cause::TargetRefused {
            system: System::Fly,
            subject: app_ref(app),
            why: Refusal::InProgress,
            env: None,
            target: None,
            seen,
        }
    })
}

/// The cause of the latest flyctl call `args`, which answered with a reply opv cannot use,
/// built on the runner's own observation of it (design §4.6, A1).
fn unusable(args: &[&str], cause: impl FnOnce(Observed) -> Cause) -> Error {
    match crate::runner::take_unusable_reply(&Call::new(PROGRAM, args)) {
        Some(seen) => cause(seen).into(),
        None => Cause::Bug {
            site: "fly: a flyctl reply the runner did not observe",
        }
        .into(),
    }
}

/// The Fly app `app`, as a catalog subject.
fn app_ref(app: &str) -> ResourceRef {
    ResourceRef {
        kind: ResourceKind::FlyApp,
        name: ResourceName::new(app),
        scope: None,
    }
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
    let out = run(r, Effect::Read, what, app, args, None)?;
    serde_json::from_slice(&out.stdout).map_err(|e| {
        let at = Location {
            line: u32::try_from(e.line()).unwrap_or(u32::MAX),
            col: u32::try_from(e.column()).unwrap_or(u32::MAX),
        };
        unusable(args, |seen| Cause::UnexpectedOutput {
            system: System::Fly,
            at: Some(at),
            problem: OutputProblem::Unparseable,
            during: crate::cause::During::Read,
            seen,
        })
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

/// A batch that breaks an import rule reached the write. `sync` refuses every value with an
/// [`entry_refusal`] as a blocking row of its plan (`KeysBlocking`) and the loader refuses
/// two keys rendering one name, so this is an internal error; nothing was sent to Fly.
fn refused(_name: &str, _rule: &str, _op: &str) -> Error {
    Cause::Bug {
        site: "fly: a name or value the plan passed breaks a Fly import rule",
    }
    .into()
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

/// The resource a call on `app` is about, and where its name came from (a target's
/// `fly.app` field), for the diagnosis of a failed call (design §5).
pub(crate) fn app_context(app: &str) -> DiagnoseContext {
    DiagnoseContext {
        resource: Some(ResourceRef {
            kind: ResourceKind::FlyApp,
            name: ResourceName::new(app),
            scope: None,
        }),
        named_by: Some(NamedBy::ConfigField {
            path: DottedPath(vec!["fly".to_string(), "app".to_string()]),
        }),
        ..DiagnoseContext::default()
    }
}

/// The cause of the flyctl call that just failed (a non-zero exit, a timeout, a signal):
/// what the runner observed and the call's reply, classified by [`diagnose::diagnose`]
/// (design §5), with the reply shown as evidence. Never a cause chosen here.
pub(crate) fn failed_call(ctx: &DiagnoseContext) -> Error {
    let Some(failed) = crate::runner::take_failure() else {
        return Cause::Bug {
            site: "fly: a failed flyctl call left no observation",
        }
        .into();
    };
    let exit = failed.seen.exit();
    let cause = diagnose::diagnose(failed.seen.clone(), failed.stderr(), ctx);
    let said = failed.excerpt.map(|e| e.lines).unwrap_or_default();
    if said.is_empty() {
        return cause.into();
    }
    Error::with_evidence(
        cause,
        Upstream {
            source: System::Fly,
            tool: "Fly API via flyctl".to_string(),
            version: None,
            exit,
            said,
            removed_advice: false,
            untrusted: true,
        },
    )
}

/// A flyctl call that returned an error instead of an outcome: flyctl is not installed
/// (or cannot be started), a probe that did not answer in time (diagnosed like any failed
/// call, design §5), or a run budget that let the call never start (NR-4).
pub(crate) fn call_error(
    r: &dyn CommandRunner,
    host: &dyn Fn() -> Host,
    e: &io::Error,
    ctx: &DiagnoseContext,
) -> Error {
    if e.kind() == io::ErrorKind::NotFound {
        let host = host();
        return Cause::ToolMissing {
            tool: PROGRAM.to_string(),
            platform: host.platform,
            shell: host.shell,
            ci: host.ci,
        }
        .into();
    }
    let started = crate::runner::take_observed()
        .filter(|seen| !matches!(seen.exit(), ExitClass::SpawnFailed));
    match started {
        Some(seen) => {
            let _ = crate::runner::take_failure_excerpt();
            diagnose::diagnose(seen, "", ctx).into()
        }
        // The spent run budget never let the call start.
        None if e.kind() == io::ErrorKind::TimedOut => FLYCTL.budget_spent(r, e),
        None => Cause::ToolUnusable {
            tool: PROGRAM.to_string(),
            why: Unusable::SpawnFailed {
                io: e.kind().into(),
            },
        }
        .into(),
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
) -> Result<Output, Error> {
    let ctx = DiagnoseContext {
        write: effect == Effect::Write,
        ..app_context(app)
    };
    let call = Call::new(PROGRAM, args).with_stdin(stdin);
    // `secrets deploy` restarts the machines one by one and waits for their health checks:
    // minutes on a multi-machine app (NR-4).
    let call = if args.starts_with(&["secrets", "deploy"]) {
        call.rollout()
    } else {
        call
    };
    let outcome = match effect {
        Effect::Read => r.read(&call, &[]),
        Effect::Write => r.write(&call),
    }
    .map_err(|e| match e.kind() {
        // A spent run budget; the runner's own message names the program (no child output).
        io::ErrorKind::TimedOut => FLYCTL.budget_spent(r, &e),
        _ => call_error(r, &Host::detect, &e, &ctx),
    })?;
    match outcome {
        Outcome::Done(out) => Ok(out),
        Outcome::Refused(_)
        | Outcome::Unknown {
            status: Some(_), ..
        } => Err(failed_call(&ctx)),
        // A write that timed out or was killed: diagnosed by what it was doing (an unknown
        // write, design §4.6).
        Outcome::Unknown { reason, .. } if effect == Effect::Write => {
            match crate::runner::take_observed() {
                Some(seen) => Err(diagnose::diagnose(seen, "", &ctx).into()),
                // A runner that reported it unanswered without observing it (an in-memory
                // double) has it recorded as lost: its outcome is only unknown (NR-2).
                None => {
                    let _ = reason;
                    match crate::host::lost_call(PROGRAM) {
                        Some(failed) => Err(diagnose::diagnose(failed.seen, "", &ctx).into()),
                        None => Err(Cause::Bug {
                            site: "fly: an unfinished flyctl write left no observation",
                        }
                        .into()),
                    }
                }
            }
        }
        // A read unanswered after its last attempt: Fly is unreachable (NR-28), or, after
        // this run's first write, the run stopped half way (NR-2).
        Outcome::Unknown { .. } => Err(FLYCTL.unanswered(r, what)),
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;
    use crate::runner::Output;
    use crate::runner::fake::FakeRunner;

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
            assert_eq!(e.code_str(), "internal_error", "{rule}: {e:?}");
            let t = err_text(&e);
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
            assert_eq!(e.code_str(), "internal_error", "{name}: {e:?}");
            assert!(!err_text(&e).contains(MARK));
            assert!(r.calls.borrow().is_empty());
        }
        let r = FakeRunner::default();
        let e = stage(&r, "app", &[("DUP".into(), &v), ("DUP".into(), &v)]).unwrap_err();
        let t = err_text(&e);
        assert_eq!(e.code_str(), "internal_error", "{t}");
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
        assert_eq!(entry_refusal(name, &over), Some("import-line-too-long"));
        assert!(validate_import(&[(name.into(), &over)]).is_err());
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
    fn a_failed_import_never_shows_the_value() {
        let r = FakeRunner::new([Output::failure(1)]);
        let v = sv(MARK);
        let e = stage(&r, "app", &[("K".into(), &v)]).unwrap_err();
        assert!(!err_text(&e).contains(MARK), "{e:?}");
    }

    /// A runner signed in with an environment's deploy credentials (FR-40).
    pub(super) struct UnderDeployCredentials<'a>(pub(super) &'a FakeRunner);

    impl CommandRunner for UnderDeployCredentials<'_> {
        fn read(&self, call: &Call, refused: &[i32]) -> io::Result<Outcome> {
            self.0.read(call, refused)
        }
        fn write(&self, call: &Call) -> io::Result<Outcome> {
            self.0.write(call)
        }
        fn probe(&self, call: &Call, limit: std::time::Duration) -> io::Result<Output> {
            self.0.probe(call, limit)
        }
        fn pause(&self, d: std::time::Duration, note: &str) {
            self.0.pause(d, note)
        }
        fn note(&self, line: &str) {
            self.0.note(line)
        }
        fn run_inherited(&self, p: &str, a: &[&str], e: &[(&str, &str)]) -> io::Result<i32> {
            self.0.run_inherited(p, a, e)
        }
        fn deploy_signed_in(&self) -> bool {
            true
        }
    }

    fn the_cause(e: &Error) -> &Cause {
        e.cause().map(|(c, _)| c).expect("a catalog error")
    }

    fn bash_host<T>(f: impl FnOnce() -> T) -> T {
        crate::host::with_test_host(bash(), f)
    }

    /// A Fly token rejected under an environment's deploy credentials names that item,
    /// never the person's sign-in (design §5, "The principal is known").
    #[test]
    fn a_rejected_deploy_token_is_the_deploy_credentials_never_a_sign_in() {
        let r = FakeRunner::default();
        r.push_with_stderr(
            Output::failure(1),
            "Error: You must be authenticated to view this.",
        );
        let principal = crate::cause::Principal::DeployCredentials {
            vault: crate::cause::VaultId::new("vlt-deploy"),
            item: crate::cause::ItemId::new("itm-deploy"),
            env: crate::cause::EnvName::new("prod"),
            target: crate::cause::TargetName::new("web"),
        };
        let e = crate::runner::under_deploy(principal, || deploy(&r, "app")).unwrap_err();
        assert_eq!(e.code_str(), "deploy_credentials_failed", "{e:?}");
    }

    #[test]
    fn a_timed_out_whoami_is_provider_unavailable() {
        let r = FakeRunner::default();
        r.push_unknown("timeout");
        let e = bash_host(|| login::mint_preflight(&r)).unwrap_err();
        assert_eq!(e.code_str(), "provider_unavailable", "{e:?}");
    }

    /// 06.11: offline, `flyctl auth whoami` exits 1; Fly not answering is never "signed out".
    #[test]
    fn a_whoami_that_cannot_reach_fly_is_provider_unavailable() {
        let r = FakeRunner::default();
        r.push_with_stderr(
            Output::failure(1),
            include_str!(
                "../../../tests/fixtures/fly/failures/09-network-unreachable-whoami.stderr"
            ),
        );
        let e = bash_host(|| login::mint_preflight(&r)).unwrap_err();
        assert_eq!(e.code_str(), "provider_unavailable", "{e:?}");
    }

    /// 06.11: "signed out" only when flyctl said so.
    #[test]
    fn a_whoami_that_says_no_token_is_not_signed_in() {
        let r = FakeRunner::default();
        r.push_with_stderr(
            Output::failure(1),
            include_str!("../../../tests/fixtures/fly/failures/01-signed-out-whoami.stderr"),
        );
        let e = bash_host(|| login::mint_preflight(&r)).unwrap_err();
        assert!(matches!(the_cause(&e), Cause::NotSignedIn { .. }), "{e:?}");
    }

    /// 06.11: a whoami reply opv does not recognise is reported as such, never as signed out.
    #[test]
    fn an_unrecognised_whoami_failure_is_never_signed_out() {
        let r = FakeRunner::new([Output::failure(1)]);
        let e = bash_host(|| login::mint_preflight(&r)).unwrap_err();
        assert_eq!(e.code_str(), "unrecognized_failure", "{e:?}");
    }

    fn token_host() -> Host {
        host(crate::host::FakeEnv::new("linux").var("FLY_API_TOKEN"))
    }

    /// 06.05: a Fly token in the shell overrides the login, so the mint asks for the
    /// person's own session before any call (never "flyctl auth login", which cannot help).
    #[test]
    fn a_shell_token_refuses_the_mint_as_needing_your_own_session() {
        let r = FakeRunner::default();
        let e =
            crate::host::with_test_host(token_host(), || login::mint_preflight(&r)).unwrap_err();
        assert_eq!(e.code_str(), "own_session_required", "{e:?}");
    }

    #[test]
    fn a_shell_token_refusal_makes_no_call() {
        let r = FakeRunner::default();
        let _ = crate::host::with_test_host(token_host(), || login::mint_preflight(&r));
        assert!(r.calls.borrow().is_empty());
    }

    #[test]
    fn a_shell_token_refusal_says_to_run_without_the_variable() {
        let r = FakeRunner::default();
        let e =
            crate::host::with_test_host(token_host(), || login::mint_preflight(&r)).unwrap_err();
        let todo = the_cause(&e).do_text(&crate::cause::Invocation::default());
        assert!(
            todo.is_some_and(|t| t.contains("without FLY_API_TOKEN")),
            "{e:?}"
        );
    }

    #[test]
    fn a_refused_token_mint_for_a_missing_app_is_not_found() {
        let r = FakeRunner::default();
        r.push_with_stderr(
            Output::failure(1),
            include_str!(
                "../../../tests/fixtures/fly/failures/06-app-not-found-secrets-list.stderr"
            ),
        );
        let e = login::mint_deploy_credential(&r, "my-app", "opv-x").unwrap_err();
        assert!(matches!(the_cause(&e), Cause::NotFound { .. }), "{e:?}");
    }

    fn unknown_mint() -> Error {
        let r = FakeRunner::default();
        r.push_unknown("timeout");
        login::mint_deploy_credential(&r, "my-app", "opv-x").unwrap_err()
    }

    /// 06.10: a token mint whose outcome is unknown is check-first, never "re-run".
    #[test]
    fn an_unknown_token_mint_is_check_first() {
        assert_eq!(
            the_cause(&unknown_mint()).retry(),
            crate::cause::RetryClass::CheckFirst
        );
    }

    /// 06.10: Next lists the app's tokens; it never mints a second one.
    #[test]
    fn an_unknown_token_mint_checks_the_token_list() {
        let next = the_cause(&unknown_mint())
            .step(&crate::cause::Invocation::default())
            .1;
        assert_eq!(
            next,
            crate::cause::Next::Vendor(crate::cause::VendorCmd {
                program: "flyctl".into(),
                args: ["tokens", "list", "--app", "my-app"]
                    .map(String::from)
                    .to_vec(),
            })
        );
    }

    /// 06.10: the orphan's secret was never stored, so the person revokes it.
    #[test]
    fn an_unknown_token_mint_says_to_revoke_the_orphan() {
        let todo = the_cause(&unknown_mint()).do_text(&crate::cause::Invocation::default());
        assert!(todo.is_some_and(|t| t.contains("lists opv-x, revoke it")));
    }

    #[test]
    fn a_deploy_item_without_a_token_is_deploy_credentials_failed() {
        use crate::provider::DeployLogin;
        let mut l = login::FlyLogin::default();
        let e = l
            .sign_in(std::collections::BTreeMap::new(), &FakeRunner::default())
            .unwrap_err();
        // The item is read with every declared field, so a missing one is opv's bug.
        assert_eq!(e.code_str(), "internal_error");
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
                    stamp: None,
                },
                StoreEntry {
                    name: "B".into(),
                    version: Some("<digest-b>".into()),
                    pending: true,
                    stamp: None,
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
            assert_eq!(e.code_str(), "unexpected_output", "{e:?}");
            assert!(!err_text(&e).contains(MARK));
        }
    }

    /// A failed call shows flyctl's reply as evidence (design §7.3).
    #[test]
    fn a_failed_list_shows_the_reply() {
        let r = FakeRunner::default();
        for _ in 0..crate::runner::READ_ATTEMPTS {
            r.push_with_stderr(Output::failure(1), "Error: something new from Fly");
        }
        let e = list(&r, "app").unwrap_err();
        assert!(e.cause().is_some_and(|(_, up)| up.is_some()), "{e:?}");
    }

    /// 09.13: a missing app is reported at once, never retried as if transient.
    #[test]
    fn a_missing_app_is_not_retried() {
        let r = FakeRunner::default();
        r.push_with_stderr(
            Output::failure(1),
            include_str!(
                "../../../tests/fixtures/fly/failures/06-app-not-found-secrets-list.stderr"
            ),
        );
        let _ = list(&r, "fleet-prod");
        assert_eq!(r.calls.borrow().len(), 1);
    }

    /// 09.13: a missing app names the app and the field that names it, never "logged in".
    #[test]
    fn a_missing_app_is_not_found_naming_the_app() {
        let r = FakeRunner::default();
        r.push_with_stderr(
            Output::failure(1),
            include_str!(
                "../../../tests/fixtures/fly/failures/06-app-not-found-secrets-list.stderr"
            ),
        );
        let e = list(&r, "fleet-prod").unwrap_err();
        assert!(e.to_string().contains("fleet-prod"), "{e}");
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
        assert_eq!(e.code_str(), "internal_error", "{e:?}");
        assert!(r.calls.borrow().is_empty());
    }

    #[test]
    fn deploy_runs_secrets_deploy() {
        let r = FakeRunner::new([Output::success("")]);
        deploy(&r, "app").unwrap();
        assert_eq!(r.calls.borrow()[0].program, "flyctl");
        assert_eq!(args(&r, 0), ["secrets", "deploy", "--app", "app"]);
    }

    /// A failed write whose reply opv does not recognise is reported as unrecognised with
    /// what opv established, never a guessed cause.
    #[test]
    fn an_unrecognised_failed_deploy_is_unrecognized() {
        let r = FakeRunner::new([Output::failure(1)]);
        let e = deploy(&r, "app").unwrap_err();
        assert_eq!(e.code_str(), "unrecognized_failure", "{e:?}");
    }

    #[test]
    fn missing_flyctl_is_dependency_missing() {
        let r = FakeRunner::default();
        r.push_io_error(io::ErrorKind::NotFound);
        assert_eq!(
            list(&r, "app").unwrap_err().code_str(),
            "dependency_missing"
        );
    }

    #[test]
    fn a_flyctl_that_cannot_start_is_tool_unusable() {
        let r = FakeRunner::default();
        r.push_io_error(io::ErrorKind::PermissionDenied);
        let v = sv(MARK);
        let e = stage(&r, "app", &[("K".into(), &v)]).unwrap_err();
        assert_eq!(e.code_str(), "tool_unusable", "{e:?}");
    }

    /// No failure path makes a diagnosis call of its own: the reply is diagnosed (§5).
    #[test]
    fn a_failed_call_makes_no_other_call() {
        for (attempts, call) in four_calls() {
            let r = FakeRunner::new((0..attempts).map(|_| Output::failure(1)));
            let _ = call(&r);
            assert_eq!(r.calls.borrow().len(), attempts);
        }
    }

    /// SR-1: no failure path shows a value or flyctl's stdout.
    #[test]
    fn no_failure_shows_a_value_or_stdout() {
        for (attempts, call) in four_calls() {
            let r = FakeRunner::new((0..attempts).map(|_| Output {
                status: 1,
                stdout: zeroize::Zeroizing::new(MARK.as_bytes().to_vec()),
            }));
            let e = call(&r).unwrap_err();
            assert!(!err_text(&e).contains(MARK), "{e:?}");
        }
    }

    // ---- FR-26: diagnosis of a failed flyctl call ------------------------------------

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

    /// NR-28: a read that timed out on every attempt is an outage: exit 9, nothing changed.
    #[test]
    fn read_timeout_is_an_outage_exit_9() {
        let r = FakeRunner::default();
        r.push_unknowns("timeout", crate::runner::READ_ATTEMPTS);
        assert_eq!(list(&r, "app").unwrap_err().exit_code(), 9);
    }

    /// A Fly target as configured (target `web`, app `app`).
    fn fly_target() -> crate::domain::Fleet {
        crate::config::parse(
            "[environments.prod]\nboundaries.web = { vault_id = \"v\", item_id = \"i\" }\n\
             [environments.prod.targets.web]\nfly.app = \"app\"\nfly.secret_name = \"{KEY}\"\n\
             state_vault_id = \"s\"\n[products.web.keys.K]\n\
             kind = \"secret\"\nenvironments = [\"prod\"]\n",
        )
        .unwrap()
    }

    /// Read commands make no preflight call on Fly: the app's state matters only to writes.
    #[test]
    fn read_mode_preflight_makes_no_call() {
        let fleet = fly_target();
        let r = FakeRunner::new(Vec::<Output>::new());
        let t = fleet.environments["prod"].targets["web"].config.as_ref();
        t.preflight(&r, crate::provider::PreflightMode::Read)
            .unwrap();
        assert!(r.calls.borrow().is_empty());
    }

    const STARTED: &str = r#"{"Status":"deployed","Machines":[{"state":"started"}]}"#;
    const RUNNING: &str = r#"[{"Version":2,"Status":"running"}]"#;
    const COMPLETE: &str = r#"[{"Version":2,"Status":"complete"}]"#;

    /// `sync` (mutate mode) waits for a running deploy, then goes on (UX1).
    #[test]
    fn mutate_mode_preflight_waits_for_a_running_deploy() {
        let fleet = fly_target();
        let r = FakeRunner::new([
            Output::success(STARTED),
            Output::success(RUNNING),
            Output::success(COMPLETE),
        ]);
        let t = fleet.environments["prod"].targets["web"].config.as_ref();
        assert!(
            t.preflight(&r, crate::provider::PreflightMode::Mutate)
                .is_ok()
        );
    }

    #[test]
    fn waiting_for_a_running_deploy_prints_progress() {
        let r = FakeRunner::new([
            Output::success(STARTED),
            Output::success(RUNNING),
            Output::success(COMPLETE),
        ]);
        preflight(&r, "app").unwrap();
        assert_eq!(
            *r.notes.borrow(),
            ["waiting for the running Fly deploy of app (release v2) to finish, 0 s"]
        );
    }

    /// The progress line repeats at most every 15 s while the deploy keeps running.
    #[test]
    fn progress_while_waiting_is_at_most_every_15_seconds() {
        let mut responses = vec![Output::success(STARTED)];
        responses.extend((0..5).map(|_| Output::success(RUNNING)));
        responses.push(Output::success(COMPLETE));
        let r = FakeRunner::new(responses);
        preflight(&r, "app").unwrap();
        assert_eq!(r.notes.borrow().len(), 2, "{:?}", r.notes.borrow());
    }

    /// A deploy still running when the run budget is nearly spent refuses, nothing changed.
    #[test]
    fn deploy_still_running_at_the_end_of_the_budget_refuses() {
        let r = FakeRunner::new([
            Output::success(STARTED),
            Output::success(RUNNING),
            Output::success(RUNNING),
            Output::success(RUNNING),
        ]);
        // Room for two polls, each with one read's limit to spare (NR-4).
        r.budget.set(crate::runner::READ_TIMEOUT + DEPLOY_POLL * 2);
        assert!(matches!(
            preflight(&r, "app").map_err(|e| e.cause().map(|(c, _)| c.clone())),
            Err(Some(Cause::TargetRefused {
                why: Refusal::InProgress,
                ..
            }))
        ));
    }

    /// 06.32: a deploy still running is the provider's change in progress, never a
    /// re-run with a larger --timeout (the wait's own cap may have ended it).
    #[test]
    fn a_deploy_still_running_never_offers_a_larger_timeout() {
        let r = FakeRunner::new([Output::success("[]")]);
        let _ = r.read(&Call::new(PROGRAM, &["releases"]), &[]);
        let e = deploy_still_running("app");
        assert!(!crate::error::report(&e).contains("--timeout"), "{e:?}");
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

    /// NR-24: `InProgress` on the latest release (by version) is a running deploy, whatever
    /// its status: preflight reads the releases again.
    #[test]
    fn latest_release_in_progress_is_waited_for() {
        let r = FakeRunner::new([
            Output::success(r#"{"status":"deployed","machines":[{"state":"started"}]}"#),
            Output::success(
                r#"[{"Version":7,"InProgress":true,"Status":""},{"Version":6,"Status":"complete"}]"#,
            ),
            Output::success(r#"[{"Version":7,"Status":"complete"}]"#),
        ]);
        preflight(&r, "app").unwrap();
        assert_eq!(r.calls.borrow().len(), 3);
    }

    /// NR-6, SR-1: an unexpected status document is a target error that never echoes it.
    #[test]
    fn unexpected_status_json_never_echoes_output() {
        let r = FakeRunner::new([Output::success(r#"{"Machines":"LEAKCANARY"}"#)]);
        let e = preflight(&r, "app").unwrap_err();
        assert!(!format!("{e} {e:?}").contains("LEAKCANARY"), "{e}");
    }

    #[test]
    /// A lost reply is an observed failure now (B1), so it is diagnosed like any unanswered
    /// read instead of the legacy outage text.
    fn read_outage_is_provider_unavailable() {
        let r = FakeRunner::default();
        r.push_unknowns("lost", crate::runner::READ_ATTEMPTS);
        assert_eq!(
            list(&r, "app").unwrap_err().code_str(),
            "provider_unavailable"
        );
    }

    /// FR-22: an import refusal names the rule and its fixed reason, never the value; the
    /// plan's row carries it (`entry_refusal_reason`), as sync refuses before staging.
    #[test]
    fn import_refusal_names_rule_and_reason() {
        let v = sv("a\"#ZQXMARK");
        assert_eq!(
            entry_refusal_reason("FLEET__P__K", &v),
            Some((
                "import-hash-after-odd-quotes",
                "a # follows an odd number of double quotes"
            ))
        );
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
            // Each case tests encoding/parser fidelity independently. Retaining all
            // 20,000 prior marker values only exercises registry growth, not this
            // assertion; keep the real SecretValue registration for the current case.
            crate::scrub::reset_test_registry();
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
