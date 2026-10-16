//! The documents `opv ui` reads from this opv binary, typed (07.01–07.04): the CLI's own
//! document types where they deserialize (the readiness receipt's parts, the account
//! report, the access report), and the shape the CLI writes everywhere else. A
//! `{ok: false, error}` reply is an error carrying the catalog's text and steps, never data
//! (07.02); findings (exit 8) still carry their rows. Names, states and commands only: no
//! document holds a value.

use std::fmt;

use serde::Deserialize;
use serde::de::DeserializeOwned;

pub use crate::app::account::Report as AccountsDoc;
pub use crate::domain::access_plan::AccessReport;

/// Where the documents come from: the opv binary itself, or fixtures in tests.
pub trait Source {
    /// The stdout of `opv <args>` (with `--json` in `args`), whatever the exit code; `Err`
    /// with a short reason when the command could not be run.
    fn stdout(&self, args: &[&str]) -> Result<Vec<u8>, String>;
}

/// The `error` of a failure document: the catalog's message and its steps (A1).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct ErrorDoc {
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub message: String,
    /// What a person does first, when anything.
    #[serde(rename = "do", default)]
    pub act: Option<String>,
    /// The one command that runs next, when any.
    #[serde(default)]
    pub next: Option<String>,
}

impl ErrorDoc {
    /// The lines the CLI prints for it: the message, `Do:` and `Next:`.
    pub fn lines(&self) -> Vec<String> {
        let mut out = vec![self.message.clone()];
        if let Some(a) = &self.act {
            out.push(format!("Do: {a}"));
        }
        if let Some(n) = &self.next {
            out.push(format!("Next: {n}"));
        }
        out
    }
}

/// Why a document could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The command failed: its catalog error, with its steps.
    Error(ErrorDoc),
    /// No document of the expected shape: opv could not be run, or printed something else.
    NoDocument(String),
}

impl Failure {
    /// The lines to show: the error's message and steps, or the one reason.
    pub fn lines(&self) -> Vec<String> {
        match self {
            Failure::Error(e) => e.lines(),
            Failure::NoDocument(why) => vec![why.clone()],
        }
    }
}

impl fmt::Display for Failure {
    /// One line, for the status line: the lines joined with ` · `.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.lines().join(" · "))
    }
}

/// The frame every `--json` document has (A1).
#[derive(Deserialize)]
struct Frame {
    #[serde(default = "success")]
    ok: bool,
    #[serde(default)]
    exit_code: Option<i32>,
    #[serde(default)]
    error: Option<ErrorDoc>,
}

fn success() -> bool {
    true
}

/// The exit code of findings: the command failed, and its document still carries the rows.
const FINDINGS_EXIT: i32 = 8;

/// `stdout` as a `T`. A failure document is [`Failure::Error`], unless it is findings and
/// still reads as a `T`.
pub fn parse<T: DeserializeOwned>(stdout: &[u8]) -> Result<T, Failure> {
    let frame: Frame = serde_json::from_slice(stdout)
        .map_err(|_| Failure::NoDocument("opv printed no JSON document".into()))?;
    let body = serde_json::from_slice::<T>(stdout);
    match (frame.ok, body) {
        (true, Ok(t)) => Ok(t),
        (false, Ok(t)) if frame.exit_code == Some(FINDINGS_EXIT) => Ok(t),
        (false, _) => Err(Failure::Error(frame.error.unwrap_or_default())),
        (true, Err(_)) => Err(Failure::NoDocument(
            "opv printed a document of another shape (is this opv ui from another version?)".into(),
        )),
    }
}

/// `opv <args>` read as a `T`.
pub fn fetch<T: DeserializeOwned>(source: &dyn Source, args: &[&str]) -> Result<T, Failure> {
    let stdout = source.stdout(args).map_err(Failure::NoDocument)?;
    parse(&stdout)
}

/// `opv config export --json`: the configuration as stored, read by opv's own parser, so
/// the 0.7+ shape (targets under `environments.<env>.targets`) is read as the CLI reads it
/// (07.01).
pub fn fetch_config(source: &dyn Source) -> Result<crate::domain::Fleet, Failure> {
    let stdout = source
        .stdout(&["config", "export", "--json"])
        .map_err(Failure::NoDocument)?;
    parse_config(&stdout)
}

/// [`fetch_config`]'s parse of the document.
pub fn parse_config(stdout: &[u8]) -> Result<crate::domain::Fleet, Failure> {
    let frame: Frame = serde_json::from_slice(stdout)
        .map_err(|_| Failure::NoDocument("opv printed no JSON document".into()))?;
    if !frame.ok {
        return Err(Failure::Error(frame.error.unwrap_or_default()));
    }
    let shape = || Failure::NoDocument("the configuration document did not read back".into());
    let value: toml::Value = serde_json::from_slice(stdout).map_err(|_| shape())?;
    let text = toml::to_string(&value).map_err(|_| shape())?;
    crate::config::parse(&text).map_err(|e| Failure::NoDocument(e.to_string()))
}

/// `opv ready --json` (FR-51), with the receipt's own types.
#[derive(Debug, Clone, Deserialize)]
pub struct ReadyDoc {
    pub receipt_id: String,
    pub config: crate::app::ready::ConfigRef,
    pub account: Option<crate::app::ready::AccountRef>,
    pub matrix: Vec<crate::app::ready::MatrixEntry>,
    pub findings: Vec<crate::app::ready::Finding>,
    pub next: Option<crate::app::ready::Next>,
}

/// `opv status|check|plan <env> --json` (A6): the rows, and for `plan` what it would write.
#[derive(Debug, Clone, Deserialize)]
pub struct RowsDoc {
    pub rows: Vec<RowDoc>,
    /// `plan`: the plan id `sync --expect-plan` checks; absent with findings.
    #[serde(default)]
    pub plan_id: Option<String>,
    #[serde(default)]
    pub stage: Vec<String>,
    #[serde(default)]
    pub prune: Vec<String>,
    pub totals: Totals,
}

/// The counts of a rows document.
#[derive(Debug, Clone, Deserialize)]
pub struct Totals {
    pub findings: usize,
}

/// One row (A6).
#[derive(Debug, Clone, Deserialize)]
pub struct RowDoc {
    /// The row's target name (FR-56); `null` where no target is read (`check`).
    pub target: Option<String>,
    pub product: Option<String>,
    pub key: String,
    pub state: String,
    pub rule: Option<String>,
    /// `present`, `absent`, `would_change`, `not_delivered`, or `null`.
    pub target_state: Option<String>,
}

/// `opv history <env> --json` (#95): one target's rows, or one block per target when the
/// environment has several (FR-56).
#[derive(Debug, Clone, Deserialize)]
pub struct HistoryDoc {
    /// One target: its name; `null` for a run-only environment.
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub latest: Option<Latest>,
    #[serde(default)]
    pub rows: Vec<HistoryRow>,
    /// Several targets: one block each.
    #[serde(default)]
    pub targets: Vec<TargetHistory>,
}

impl HistoryDoc {
    /// One block per target, whichever form the document has.
    pub fn parts(&self) -> Vec<TargetHistory> {
        if !self.targets.is_empty() {
            return self.targets.clone();
        }
        match &self.name {
            Some(name) => vec![TargetHistory {
                name: name.clone(),
                latest: self.latest.clone(),
                rows: self.rows.clone(),
            }],
            None => Vec::new(),
        }
    }
}

/// One target's history.
#[derive(Debug, Clone, Deserialize)]
pub struct TargetHistory {
    pub name: String,
    #[serde(default)]
    pub latest: Option<Latest>,
    #[serde(default)]
    pub rows: Vec<HistoryRow>,
}

/// The latest write stamp found on a target (FR-42).
#[derive(Debug, Clone, Deserialize)]
pub struct Latest {
    pub written: Option<String>,
    pub plan: Option<String>,
    pub opv_version: Option<String>,
}

/// One history row (`domain::history::HistoryRow`).
#[derive(Debug, Clone, Deserialize)]
pub struct HistoryRow {
    pub product: String,
    pub key: String,
    pub version: Option<String>,
    pub written: Option<String>,
    pub state: String,
}

/// `opv access --json` (FR-59): per environment, the access report, the owner's commands
/// and the findings.
#[derive(Debug, Clone, Deserialize)]
pub struct AccessDoc {
    pub environments: Vec<AccessEnv>,
}

/// One environment of the access document.
#[derive(Debug, Clone, Deserialize)]
pub struct AccessEnv {
    pub environment: String,
    pub report: AccessReport,
    #[serde(default)]
    pub commands: Vec<String>,
    #[serde(default)]
    pub findings: Vec<AccessFinding>,
}

/// One finding of the access document.
#[derive(Debug, Clone, Deserialize)]
pub struct AccessFinding {
    pub code: String,
    pub message: String,
    pub next: Option<String>,
}

/// `opv adopt <env> --from <file> --json` (#94).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AdoptDoc {
    #[serde(default)]
    pub rows: Vec<AdoptRow>,
}

/// One found name and what adopting it would do.
#[derive(Debug, Clone, Deserialize)]
pub struct AdoptRow {
    #[serde(default)]
    pub found: Vec<String>,
    pub product: Option<String>,
    pub key: Option<String>,
    pub action: String,
}

#[cfg(test)]
#[path = "docs_tests.rs"]
mod tests;
