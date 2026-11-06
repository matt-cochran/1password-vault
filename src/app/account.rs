//! `opv account list` and `opv account use` (FR-49): which 1Password accounts this
//! machine's `op` knows, which one this project uses, and the findings that tell a person
//! or agent what to do next. Read-only for `list`; `use` records one account in `.opv`.
//!
//! Nothing here calls `op`: [`report`] takes the already-probed [`Discovery`] and a
//! [`signed_in`](Inputs::signed_in) closure, so it is pure and testable. The CLI wiring
//! that runs `op`, reads `.opv`/`OP_ACCOUNT` and prints the document is a later deliverable.

use std::io::Write;

use crate::adapters::onepassword_manifest::{Account, Discovery};
use crate::cause::{
    AccountChoice, AccountId, AccountRef, AccountSource, Cause, Cmd, Invocation, Next, VarName,
};
use crate::error::Error;
use crate::host::Platform;

/// Whether the 1Password app holds the accounts `op` sees: on macOS and Windows, and for the
/// Windows `op.exe` reached from WSL. There an account is added in the app, never with
/// `opv login --add` (audit 04.07, design §6.4 `RefusedBecause::Platform`).
pub fn app_holds_accounts(platform: Platform, op_windows_exe: bool) -> bool {
    matches!(platform, Platform::MacOs | Platform::Windows) || op_windows_exe
}

/// [`app_holds_accounts`] for this machine.
pub fn app_holds_accounts_here() -> bool {
    let host = crate::host::Host::detect();
    app_holds_accounts(host.platform, host.op_is_windows_exe())
}

/// How a person named an account: an email, an account ID, or anything else op matches
/// (a shorthand, a user ID or a sign-in address). Only an email may follow
/// `opv login --add --account` (audit 04.02).
pub fn account_ref(value: &str) -> AccountRef {
    if value.contains('@') {
        AccountRef::Email(value.to_string())
    } else if value.len() == 26
        && value
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        AccountRef::Id(AccountId::new(value))
    } else {
        AccountRef::Shorthand(value.to_string())
    }
}

/// Where `account` was chosen for a sign-in, as far as opv can tell afterwards: `OP_ACCOUNT`,
/// else the nearest `.opv` (by its path), else `--account`.
pub fn source_of(account: &str) -> AccountSource {
    if crate::config_store::account_env().is_some_and(|a| a == account) {
        return AccountSource::EnvVar {
            var: VarName::new("OP_ACCOUNT"),
        };
    }
    let here = std::env::current_dir().unwrap_or_default();
    if let Some(path) = crate::config_store::walk_up(&here, ".opv")
        && crate::config_store::pointer_account(&here).is_some_and(|a| a == account)
    {
        return AccountSource::DotOpv { path };
    }
    AccountSource::Flag
}

/// The error for an `op account list` that failed or printed something opv does not
/// understand (#157). One that did not finish is 1Password not answering (the 1Password
/// diagnosis of the call); otherwise op's reply was not kept (`manifest::discover` drops
/// it), so nothing opv could diagnose is known and the step is `opv doctor`.
pub(crate) fn account_list_failed() -> Error {
    // E1: every failed list is diagnosed from op's own reply; one that answered with
    // output opv cannot read is `UnexpectedOutput`.
    if let Some(f) = crate::runner::take_failure() {
        return crate::adapters::onepassword_diagnose::diagnose(
            f.seen.clone(),
            f.stderr(),
            &crate::cause::DiagnoseContext::default(),
        )
        .into();
    }
    let list = crate::runner::Call::new(
        crate::adapters::onepassword::OP,
        &["account", "list", "--format", "json"],
    );
    match crate::runner::take_unusable_reply(&list) {
        Some(seen) => crate::cause::Cause::UnexpectedOutput {
            system: crate::cause::System::OnePassword,
            at: None,
            problem: crate::cause::OutputProblem::Unparseable,
            during: crate::cause::During::Read,
            seen,
        }
        .into(),
        // No failure was observed, and every answered op call is: the list was not run.
        None => crate::cause::Cause::Bug {
            site: "account: an op account list the runner did not observe",
        }
        .into(),
    }
}

/// Everything [`report`] needs, already gathered by the caller: the `op account list`
/// result, a probe for each account's session, the selection values (in precedence order)
/// and the host platform.
pub struct Inputs<'a> {
    pub discovery: Discovery,
    /// Whether `op` is signed in to the account with this ID; `None` when the probe could
    /// not run. Called once per listed account, never for one that is not listed.
    pub signed_in: &'a dyn Fn(&str) -> Option<bool>,
    /// `--account`.
    pub flag: Option<&'a str>,
    /// `OP_ACCOUNT`.
    pub env: Option<&'a str>,
    /// The nearest `.opv` account and its path.
    pub pointer: Option<(&'a str, &'a std::path::Path)>,
    /// The project's recorded account (the manifest); `None` when there is none.
    pub manifest: Option<&'a str>,
    pub platform: Platform,
    /// The names of the `OP_SESSION_*` variables in this environment (names only, never a
    /// value; #142).
    pub session_vars: Vec<String>,
    /// How far this process reaches a 1Password session ([`super::signin::reach`]): it
    /// decides the sign-in and verify steps of an `account_required` choice (FR-65).
    pub reach: crate::json::Reach,
}

/// The names of the `OP_SESSION_*` variables set in this process's environment (#142),
/// sorted. Only names that [`is_session_var`] accepts.
pub fn session_var_names() -> Vec<String> {
    let mut names: Vec<String> = std::env::vars_os()
        .filter_map(|(k, _)| k.into_string().ok())
        .filter(|k| is_session_var(k))
        .collect();
    names.sort();
    names
}

/// op's own variables that share the `OP_SESSION_` prefix but hold no session (FMECA L6:
/// `OP_SESSION_DELEGATION_ENABLED` is in op 2.40's strings).
const NOT_SESSION_VARS: &[&str] = &["OP_SESSION_DELEGATION_ENABLED"];

/// True when `name` is a variable op reads a CLI session from: the bare `OP_SESSION` or
/// `OP_SESSION_<shorthand or user ID>` (#203, FMECA M3, L6). By name only.
pub fn is_session_var(name: &str) -> bool {
    match name.strip_prefix("OP_SESSION") {
        Some("") => true,
        Some(rest) => rest.len() > 1 && rest.starts_with('_') && !NOT_SESSION_VARS.contains(&name),
        None => false,
    }
}

/// The listed account `var` holds a session for: op suffixes the variable with the account's
/// shorthand or user ID (matched ignoring case, as op lists them). `None` for the bare
/// `OP_SESSION`, which names no account, and for a suffix no listed account has (#142,
/// FMECA M3). By name only; a value is never read.
pub fn session_var_owner<'a>(var: &str, listed: &'a [Account]) -> Option<&'a Account> {
    let name = var.strip_prefix("OP_SESSION_")?;
    if name.is_empty() {
        return None;
    }
    listed.iter().find(|a| {
        [&a.shorthand, &a.user_uuid, &a.account_uuid]
            .iter()
            .any(|f| !f.is_empty() && f.eq_ignore_ascii_case(name))
    })
}

/// The `OP_SESSION_<id>` variable op names for `account`: its shorthand, else its user ID,
/// the names [`session_var_owner`] maps back to it (FMECA M4). `None` when it has neither.
pub fn session_var_name(account: &Account) -> Option<String> {
    [&account.shorthand, &account.user_uuid]
        .into_iter()
        .find(|f| !f.is_empty())
        .map(|f| format!("OP_SESSION_{f}"))
}

/// The selected account: its ID, how it was chosen and where that choice came from.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Selected {
    pub account_id: String,
    /// `flag`, `env`, `pointer`, `manifest` or `only`.
    pub by: String,
    /// `--account`, `OP_ACCOUNT`, the pointer's path, `manifest`, or `only`.
    pub source: String,
}

/// One account this CLI knows, as the document lists it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccountRow {
    pub account_id: String,
    pub user_id: String,
    pub email: String,
    pub address: String,
    pub shorthand: String,
    pub source: String,
    pub signed_in: Option<bool>,
    pub selected: bool,
}

/// One state a person or agent must act on, with one runnable next step.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    pub code: String,
    pub human_required: bool,
    pub message: String,
    /// The step as a person reads it; `None` when it is no single command (a `choose`).
    pub next: Option<String>,
    /// The typed step (FR-65): the report's `next`, and `ready`'s, are built from it, never
    /// from [`Finding::next`]'s text. `None` for an advisory finding; never serialized.
    #[serde(skip)]
    pub step: Option<Next>,
}

/// The FR-49 document (`opv account list --json`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Report {
    pub discovery: String,
    pub platform: String,
    pub cli_accounts_only: bool,
    pub selected: Option<Selected>,
    pub accounts: Vec<AccountRow>,
    pub findings: Vec<Finding>,
    /// The typed `next` of the first finding with a step (schema 4, FR-65): `kind`, `actor`,
    /// `command` and `argv`, and for `account_required` the `choose` with its `reach` and
    /// `choices`. The same builder serves `opv ready` ([`typed_step`]).
    #[serde(default, deserialize_with = "step_or_none")]
    pub next: Option<serde_json::Value>,
}

/// A framed `next` read back: `None` for the frame's `kind: none` (a report with no step),
/// else the typed object as written.
fn step_or_none<'de, D>(d: D) -> Result<Option<serde_json::Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v: serde_json::Value = serde::Deserialize::deserialize(d)?;
    Ok((!v.is_null() && v["kind"] != "none").then_some(v))
}

impl Report {
    /// The `Next:` line of the text output: the first finding's step as a person reads it,
    /// or each choice's first step for a `choose`.
    pub fn next_line(&self) -> Option<String> {
        self.findings
            .iter()
            .find(|f| f.step.is_some())
            .and_then(Finding::step_text)
    }

    /// The report without the findings whose code is `code`, its `next` taken again from
    /// what remains (`opv ready` drops `account_required` when every environment names its
    /// own account, so none is chosen for the project).
    pub fn without(mut self, code: &str) -> Self {
        self.findings.retain(|f| f.code != code);
        self.next = report_next(&self.findings);
        self
    }
}

impl Finding {
    /// The step as a person reads it: [`Finding::next`], or for a `choose` each choice's
    /// first step (`pick one: opv account use <ID>; …`). `None` for an advisory finding.
    pub fn step_text(&self) -> Option<String> {
        self.next
            .clone()
            .or_else(|| self.step.as_ref().and_then(choose_line))
    }
}

/// The typed `next` of a finding's step, as `account list` and `ready` render it (schema 4):
/// against `opv account list`, with `argv` built only from the typed command (FR-65).
pub fn typed_step(step: &Next) -> serde_json::Value {
    crate::cause::render::typed_next_value(step, &list_invocation())
}

/// A `choose` as one line: each choice's first step, for the person to pick from.
fn choose_line(step: &Next) -> Option<String> {
    let Next::Choose(c) = step else {
        return None;
    };
    let firsts: Vec<String> = c
        .choices
        .iter()
        .filter_map(|choice| {
            choice
                .steps
                .first()?
                .run
                .as_ref()
                .map(crate::cause::render::cmd_text)
        })
        .collect();
    Some(format!("pick one: {}", firsts.join("; ")))
}

/// The report's `next`: the typed step of the first finding that has one.
fn report_next(findings: &[Finding]) -> Option<serde_json::Value> {
    findings
        .iter()
        .find_map(|f| f.step.as_ref())
        .map(typed_step)
}

/// What `opv account use` recorded: the account ID and the `.opv` file written.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct UseOutcome {
    pub account_id: String,
    pub path: std::path::PathBuf,
}

/// The address as the document lists it: the sign-in URL without `https://` and a
/// trailing `/`.
fn address(url: &str) -> String {
    url.trim_start_matches("https://")
        .trim_end_matches('/')
        .to_string()
}

fn platform_str(platform: Platform) -> &'static str {
    match platform {
        Platform::Linux => "linux",
        Platform::Wsl => "wsl",
        Platform::MacOs => "macos",
        Platform::Windows => "windows",
        Platform::Other => "other",
    }
}

fn discovery_str(discovery: &Discovery) -> &'static str {
    match discovery {
        Discovery::Listed(_) => "ok",
        Discovery::Unavailable => "unavailable",
        Discovery::OpMissing => "op_missing",
    }
}

/// The accounts `who` names, with [`onepassword_manifest::resolve`]'s semantics: an account
/// ID, user ID, email, shorthand or sign-in address, matched ignoring case. Empty when
/// nothing matches; several entries when the value is shared (a sign-in address is).
fn matching<'a>(accounts: &'a [Account], who: &str) -> Vec<&'a Account> {
    let w = who.trim().to_ascii_lowercase();
    let host = |u: &str| {
        u.trim_start_matches("https://")
            .trim_end_matches('/')
            .to_ascii_lowercase()
    };
    accounts
        .iter()
        .filter(|a| {
            [&a.account_uuid, &a.user_uuid, &a.email, &a.shorthand]
                .iter()
                .any(|f| !f.is_empty() && f.to_ascii_lowercase() == w)
                || host(&a.url) == host(&w)
        })
        .collect()
}

/// The first selection value in precedence order: `--account`, `OP_ACCOUNT`, `.opv`, the
/// project's manifest; its `by` and its `source`.
fn first_present<'a>(inputs: &Inputs<'a>) -> Option<(&'a str, &'static str, String)> {
    if let Some(value) = inputs.flag {
        return Some((value, "flag", "--account".to_string()));
    }
    if let Some(value) = inputs.env {
        return Some((value, "env", "OP_ACCOUNT".to_string()));
    }
    if let Some((value, path)) = inputs.pointer {
        return Some((value, "pointer", path.display().to_string()));
    }
    if let Some(value) = inputs.manifest {
        return Some((value, "manifest", "manifest".to_string()));
    }
    None
}

/// `opv account list` itself: a finding's step is rendered against it and is never this
/// same command (X7, audit 04.03).
fn list_invocation() -> Invocation {
    Invocation {
        command: vec!["account".into(), "list".into()],
        ..Invocation::default()
    }
}

/// A finding with a cataloged cause's words and step: the cause, then its Do, and its Next
/// unless that is `opv account list` itself.
fn finding_from(code: &str, cause: &Cause) -> Finding {
    let inv = list_invocation();
    let (_, next) = cause.step(&inv);
    let mut message = cause.message();
    if let Some(action) = cause.do_text(&inv) {
        message = format!("{message}; {action}");
    }
    let listing = crate::cause::render::cmd_text(&cmd(&["account", "list"], &[]));
    let text = crate::cause::render::next_text(&next, &inv).filter(|n| *n != listing);
    Finding {
        code: code.into(),
        human_required: cause.human_required(&inv),
        message,
        step: text.is_some().then_some(next),
        next: text,
    }
}

fn cmd(command: &[&str], args: &[&str]) -> Cmd {
    Cmd {
        command: command.iter().map(|w| w.to_string()).collect(),
        args: args.iter().map(|w| w.to_string()).collect(),
    }
}

/// Where a selection value came from, from [`first_present`]'s `by` and `source`.
fn selected_by(by: &str, source: &str) -> AccountSource {
    match by {
        "flag" => AccountSource::Flag,
        "env" => AccountSource::EnvVar {
            var: VarName::new("OP_ACCOUNT"),
        },
        "pointer" => AccountSource::DotOpv {
            path: std::path::PathBuf::from(source),
        },
        _ => AccountSource::OpDefault,
    }
}

/// The finding for a selection value that names no listed account (audit 04.03, 04.07,
/// 09.01): add the account that holds it (at op's prompt, or in the 1Password app where the
/// app holds the accounts), never `opv account list` again.
fn absent_finding(value: &str, by: &str, source: &str, in_app: bool) -> Finding {
    finding_from(
        "selected_account_absent",
        &Cause::AccountNotOnMachine {
            account: account_ref(value),
            selected_by: selected_by(by, source),
            in_app,
        },
    )
}

/// One candidate as a person tells it apart: `ID (email, shorthand)`.
fn candidate(a: &Account) -> String {
    let email = if a.email.is_empty() { "-" } else { &a.email };
    let short = if a.shorthand.is_empty() {
        "-"
    } else {
        &a.shorthand
    };
    format!("{} ({email}, {short})", a.account_uuid)
}

/// The finding for a selection value several listed accounts match (a sign-in address is
/// shared by every account on it): each candidate by ID, email and shorthand, and no
/// runnable step, since only the person knows which one they mean (audit 04.05, X2).
fn ambiguous_finding(value: &str, source: &str, many: &[&Account]) -> Finding {
    let named: Vec<String> = many.iter().map(|a| candidate(a)).collect();
    Finding {
        code: "account_ambiguous".into(),
        human_required: true,
        message: format!(
            "{value:?} (from {source}) matches {} accounts: {}; pick the account by its \
             email, then run opv account use <that account ID>",
            many.len(),
            named.join(", ")
        ),
        next: None,
        step: None,
    }
}

/// The finding for a selected account whose session probe failed. `op whoami --account`
/// never asks the 1Password app, so with the app integration a person who is signed in may
/// show here until a command is approved (audit 04.08): the message says both.
fn signed_out_finding(account_id: &str) -> Finding {
    // The person's own sign-in (`authorize`), named by account ID (FR-50).
    let login = cmd(&["login"], &["--account", account_id]);
    Finding {
        code: "selected_signed_out".into(),
        human_required: true,
        message: format!(
            "op has no session for the selected 1Password account {account_id} here; if you \
             use the 1Password app, unlock it and approve its prompt, else sign in"
        ),
        next: Some(crate::cause::render::cmd_text(&login)),
        step: Some(Next::Handoff(login)),
    }
}

/// #257, FR-65: several listed accounts and none selected for the project. opv never picks
/// one: the person chooses, and each choice's steps record it (`opv account use <ID>`),
/// sign in by `reach` unless that account is signed in, and check with `opv ready --json`.
/// Blocking, and the same `choose` `opv ready` and the catalog's `account_required` give
/// ([`crate::cause::step::account_choices`]).
fn required_finding(rows: &[AccountRow], reach: crate::json::Reach) -> Finding {
    let accounts = choices_of(rows);
    let cause = Cause::AccountRequired {
        accounts: accounts.clone(),
        reach,
    };
    let inv = list_invocation();
    let mut message = cause.message();
    if let Some(action) = cause.do_text(&inv) {
        message = format!("{message}; {action}");
    }
    let step = crate::cause::step::account_choices(&accounts, reach, &cmd(&["ready"], &["--json"]));
    Finding {
        code: "account_required".into(),
        human_required: true,
        message,
        next: None,
        step: Some(step),
    }
}

/// The listed accounts as the choices of a `choose`, in `op account list`'s order (never
/// ranked): ID, email, sign-in address, shorthand and the session probe's answer.
fn choices_of(rows: &[AccountRow]) -> Vec<AccountChoice> {
    rows.iter()
        .map(|r| AccountChoice {
            email: r.email.clone(),
            address: r.address.clone(),
            id: AccountId::new(r.account_id.clone()),
            shorthand: (!r.shorthand.is_empty()).then(|| r.shorthand.clone()),
            signed_in: r.signed_in,
        })
        .collect()
}

/// #142: several accounts on one sign-in address (`my.1password.com` for every individual
/// and family account): naming the address picks one of them, often not the intended
/// one. Each is named by shorthand and email so the person can name the right one.
fn shared_address_findings(listed: &[Account]) -> Vec<Finding> {
    let mut by_host: std::collections::BTreeMap<String, Vec<&Account>> = Default::default();
    for a in listed {
        by_host
            .entry(address(&a.url).to_ascii_lowercase())
            .or_default()
            .push(a);
    }
    by_host
        .into_iter()
        .filter(|(_, accounts)| accounts.len() > 1)
        .map(|(host, accounts)| {
            let named: Vec<String> = accounts
                .iter()
                .map(|a| {
                    let short = if a.shorthand.is_empty() {
                        "-"
                    } else {
                        &a.shorthand
                    };
                    let email = if a.email.is_empty() { "-" } else { &a.email };
                    format!("{short} = {email} ({})", a.account_uuid)
                })
                .collect();
            Finding {
                step: None,
                code: "shared_sign_in_address".into(),
                human_required: false,
                message: format!(
                    "{} accounts share the sign-in address {host}: {}. Naming {host} picks one \
                     of them; name an account by its account ID with opv, or by its shorthand \
                     with op (op signin --account <shorthand>)",
                    accounts.len(),
                    named.join("; ")
                ),
                next: None,
            }
        })
        .collect()
}

/// #142: an `OP_SESSION_<name>` variable in this shell that belongs to another listed
/// account than the selected one, or to no listed account. op picks sessions by these
/// variables, so a stale or foreign one can make a sign-in or a call use the wrong account
/// or fail as "not signed in". Names only; a value is never read.
fn session_var_findings(
    vars: &[String],
    listed: &[Account],
    selected: Option<&str>,
) -> Vec<Finding> {
    // A sign-in leaves the variable in place, so these carry no step: the message says
    // `unset <var>` (#157).
    vars.iter()
        .filter_map(|var| {
            // The bare `OP_SESSION` (an `op signin` without an account) names no account:
            // stale here, since opv names accounts.
            match session_var_owner(var, listed) {
                Some(a) if Some(a.account_uuid.as_str()) == selected => None,
                Some(a) => Some(Finding {
                    code: "session_for_other_account".into(),
                    human_required: true,
                    message: format!(
                        "{var} in this shell is a session for another account ({}, {}); opv \
                         ignores it when it signs in, but op and other tools may use it. Remove \
                         it from this shell (unset {var}) unless you meant that account",
                        if a.email.is_empty() { "-" } else { &a.email },
                        a.account_uuid
                    ),
                    next: None,
                    step: None,
                }),
                None => Some(Finding {
                    code: "stale_session_variable".into(),
                    human_required: true,
                    message: format!(
                        "{var} in this shell names no account this 1Password CLI knows (an old \
                         eval of op signin?); remove it from this shell (unset {var})"
                    ),
                    next: None,
                    step: None,
                }),
            }
        })
        .collect()
}

/// Build the FR-49 report. Pure: no `op` call, no filesystem, no prompt.
pub fn report(inputs: &Inputs<'_>) -> Report {
    report_with(inputs, false)
}

/// [`report`], for an `op` that is the Windows `op.exe` reached from WSL (`op_windows_exe`):
/// its accounts come from the Windows 1Password app.
pub fn report_with(inputs: &Inputs<'_>, op_windows_exe: bool) -> Report {
    let in_app = app_holds_accounts(inputs.platform, op_windows_exe);
    let listed: &[Account] = match &inputs.discovery {
        Discovery::Listed(accounts) => accounts,
        _ => &[],
    };
    let mut findings: Vec<Finding> = Vec::new();
    match &inputs.discovery {
        Discovery::Listed(_) => {}
        Discovery::Unavailable => findings.push(Finding {
            code: "discovery_unavailable".into(),
            human_required: false,
            message: "op account list failed or printed something opv does not understand".into(),
            next: Some("opv doctor".into()),
            step: Some(Next::Check(cmd(&["doctor"], &[]))),
        }),
        Discovery::OpMissing => findings.push(Finding {
            code: "op_missing".into(),
            human_required: true,
            message: "the 1Password CLI (op) is not installed".into(),
            next: Some("opv doctor".into()),
            step: Some(Next::Check(cmd(&["doctor"], &[]))),
        }),
    }
    // The probe runs once per listed account and only for a listed account.
    let mut rows: Vec<AccountRow> = listed
        .iter()
        .map(|a| AccountRow {
            account_id: a.account_uuid.clone(),
            user_id: a.user_uuid.clone(),
            email: a.email.clone(),
            address: address(&a.url),
            shorthand: a.shorthand.clone(),
            source: "cli".into(),
            signed_in: (inputs.signed_in)(&a.account_uuid),
            selected: false,
        })
        .collect();

    let mut selected: Option<Selected> = None;
    let mut selected_at: Option<usize> = None;
    if matches!(inputs.discovery, Discovery::Listed(_)) {
        if listed.is_empty() {
            findings.push(finding_from(
                "no_accounts",
                &Cause::AccountNotOnMachine {
                    account: AccountRef::Unnamed,
                    selected_by: AccountSource::OpDefault,
                    in_app,
                },
            ));
        } else if let Some((value, by, source)) = first_present(inputs) {
            match matching(listed, value).as_slice() {
                [one] => {
                    let account_id = one.account_uuid.clone();
                    selected_at = rows.iter().position(|r| r.account_id == account_id);
                    selected = Some(Selected {
                        account_id,
                        by: by.into(),
                        source,
                    });
                }
                [] => findings.push(absent_finding(value, by, &source, in_app)),
                many => findings.push(ambiguous_finding(value, &source, many)),
            }
        } else if listed.len() == 1 {
            selected_at = Some(0);
            selected = Some(Selected {
                account_id: rows[0].account_id.clone(),
                by: "only".into(),
                source: "only".into(),
            });
        } else {
            // #257: several accounts and nothing names one. Never a guess (X2).
            findings.push(required_finding(&rows, inputs.reach));
        }
    }
    if let Some(at) = selected_at {
        rows[at].selected = true;
        if rows[at].signed_in == Some(false) {
            findings.push(signed_out_finding(&rows[at].account_id));
        }
    }

    let chosen = selected.as_ref().map(|s| s.account_id.as_str());
    findings.extend(session_var_findings(&inputs.session_vars, listed, chosen));
    findings.extend(shared_address_findings(listed));
    let next = report_next(&findings);
    Report {
        discovery: discovery_str(&inputs.discovery).into(),
        platform: platform_str(inputs.platform).into(),
        cli_accounts_only: !in_app,
        selected,
        accounts: rows,
        findings,
        next,
    }
}

/// The account column: `email (account id)`, or the ID alone when no email is known.
fn account_label(a: &AccountRow) -> String {
    if a.email.is_empty() {
        a.account_id.clone()
    } else {
        format!("{} ({})", a.email, a.account_id)
    }
}

fn signed_word(signed_in: Option<bool>) -> &'static str {
    match signed_in {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    }
}

/// One padded table row, columns two spaces apart and no trailing spaces.
fn write_row(out: &mut dyn Write, cells: &[String; 5], widths: &[usize; 5]) -> Result<(), Error> {
    let mut line = String::new();
    for (i, cell) in cells.iter().enumerate() {
        if i > 0 {
            line.push_str("  ");
        }
        line.push_str(cell);
        for _ in 0..widths[i].saturating_sub(cell.chars().count()) {
            line.push(' ');
        }
    }
    writeln!(out, "{}", line.trim_end()).map_err(super::write_err)
}

/// Render the report as the `opv account list` table, its selection line, the CLI-only note
/// where it applies, and each finding as `<code>: <message>`. Only metadata; never a value.
pub fn render_text(report: &Report, out: &mut dyn Write) -> Result<(), Error> {
    let headers = ["SELECTED", "ACCOUNT", "ADDRESS", "SOURCE", "SIGNED IN"];
    let rows: Vec<[String; 5]> = report
        .accounts
        .iter()
        .map(|a| {
            [
                if a.selected { "*" } else { "" }.to_string(),
                account_label(a),
                a.address.clone(),
                a.source.clone(),
                signed_word(a.signed_in).to_string(),
            ]
        })
        .collect();
    let mut widths = headers.map(str::len);
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    write_row(out, &headers.map(str::to_string), &widths)?;
    for row in &rows {
        write_row(out, row, &widths)?;
    }
    if report.discovery == "credential" {
        return writeln!(
            out,
            "a 1Password service account or Connect credential is set: it decides the account, \
             so there is nothing to list or choose"
        )
        .map_err(super::write_err);
    }
    let selected = match &report.selected {
        Some(s) if s.by == "only" => format!(
            "selected: the only account this CLI knows; not recorded for this project yet \
             (opv account use {} records it)",
            s.account_id
        ),
        Some(s) => format!("selected by {}", s.source),
        None => "no account selected for this project".to_string(),
    };
    writeln!(out, "{selected}").map_err(super::write_err)?;
    if report.cli_accounts_only {
        let mut line = String::from(
            "Only accounts added to this 1Password CLI are listed; an account that is only in \
             the 1Password app appears after opv login --add.",
        );
        if report.platform == "wsl" {
            line.push_str(" (op in WSL does not see the Windows app's accounts)");
        }
        writeln!(out, "{line}").map_err(super::write_err)?;
    } else if report.platform == "wsl" {
        // The Windows `op.exe`: its accounts are the Windows app's (audit 04.17).
        writeln!(
            out,
            "Accounts come from the Windows 1Password app; add one there."
        )
        .map_err(super::write_err)?;
    }
    for finding in &report.findings {
        writeln!(out, "{}: {}", finding.code, finding.message).map_err(super::write_err)?;
    }
    Ok(())
}

/// Resolve `who` to one listed account and record it in the nearest `.opv`. Several
/// matches record nothing and name the candidates for the person to pick (never the first,
/// X2); no match is an account not added here, added at op's prompt or, where the app holds
/// the accounts (`in_app`), in the 1Password app.
pub fn use_account(
    accounts: &[Account],
    who: &str,
    start: &std::path::Path,
    in_app: bool,
) -> Result<UseOutcome, Error> {
    match matching(accounts, who).as_slice() {
        [one] => {
            let account_id = one.account_uuid.clone();
            let recorded = crate::config_store::record_account(start, &account_id)?;
            Ok(UseOutcome {
                account_id,
                path: recorded.path,
            })
        }
        [] => Err(Cause::AccountNotOnMachine {
            account: account_ref(who),
            selected_by: AccountSource::Argument,
            in_app,
        }
        .into()),
        many => Err(Cause::AccountAmbiguous {
            given: who.to_string(),
            candidates: many
                .iter()
                .map(|a| AccountId::new(a.account_uuid.clone()))
                .collect(),
        }
        .into()),
    }
}

/// The FR-49 report for this machine and checkout: one `op account list` probe, one
/// `op whoami --account <id>` probe per listed account, `.opv` and `OP_ACCOUNT`.
pub fn gather(r: &dyn crate::runner::CommandRunner, flag: Option<&str>) -> Report {
    gather_with(r, flag, None)
}

/// [`gather`] with the account the project's configuration names (`project`: the one every
/// environment's `account` agrees on), which selects as the manifest does.
pub fn gather_with(
    r: &dyn crate::runner::CommandRunner,
    flag: Option<&str>,
    project: Option<&str>,
) -> Report {
    use crate::adapters::onepassword_manifest as manifest;
    let host = crate::host::Host::detect();
    // A service account or Connect decides the account itself: nothing to list or choose.
    if host.op_credential.is_some() {
        return credential_report(host.platform);
    }
    let here = std::env::current_dir().unwrap_or_default();
    let pointer = crate::config_store::pointer_account(&here);
    // The `.opv` file by its full path, so a person can find it (audit 09.01).
    let pointer_path = crate::config_store::walk_up(&here, ".opv")
        .unwrap_or_else(|| std::path::PathBuf::from(".opv"));
    let env = crate::config_store::account_env();
    let probe = |id: &str| manifest::signed_in(r, id);
    let discovery = manifest::discover(r);
    let session_vars = session_var_names();
    let listed: &[Account] = match &discovery {
        Discovery::Listed(accounts) => accounts,
        _ => &[],
    };
    // No account is selected when a choice is offered, so only the app can reach one.
    let reach = super::signin::reach(None, &session_vars, listed, &host);
    report_with(
        &Inputs {
            discovery,
            signed_in: &probe,
            flag,
            env: env.as_deref(),
            pointer: pointer.as_deref().map(|a| (a, pointer_path.as_path())),
            manifest: project,
            platform: host.platform,
            session_vars,
            reach,
        },
        host.op_is_windows_exe(),
    )
}

/// The report when a non-interactive credential (service account, Connect) is set: it
/// decides the account, so there is no list, selection or finding (`discovery: credential`).
pub fn credential_report(platform: Platform) -> Report {
    Report {
        discovery: "credential".into(),
        platform: platform_str(platform).into(),
        cli_accounts_only: false,
        selected: None,
        accounts: Vec::new(),
        findings: Vec::new(),
        next: None,
    }
}

/// `opv account list [--account <who>] [--json]` (FR-49): one `op account list` probe and
/// one `op whoami --account <id>` probe per listed account; reads `.opv` and `OP_ACCOUNT`.
/// Nothing prompts, signs in, adds an account or writes. Findings never fail the command:
/// the document (or the text) reports them, and an agent acts on `next`.
pub fn list(
    r: &dyn crate::runner::CommandRunner,
    flag: Option<&str>,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let doc = gather(r, flag);
    // Design §5: op that is not installed is the command's failure (exit 3, with its install
    // line), as for `opv account use`; there is no list to report.
    if doc.discovery == discovery_str(&Discovery::OpMissing) {
        return Err(crate::adapters::onepassword::op_missing(
            &crate::host::Host::detect(),
        ));
    }
    if json {
        let v = document(&doc)?;
        return writeln!(out, "{v}").map_err(super::write_err);
    }
    render_text(&doc, out)?;
    if let Some(next) = doc.next_line() {
        writeln!(out, "Next: {next}").map_err(super::write_err)?;
    }
    Ok(())
}

/// The `opv account list --json` body of `report` (FR-49, schema 4), before the frame: its
/// `next` is the typed step, a `choose` for `account_required` (FR-65). The one builder
/// for `account list`, `ready` and MCP's `accounts` section ([`gather`] then this).
pub fn document(report: &Report) -> Result<serde_json::Value, Error> {
    let mut v = serde_json::to_value(report).map_err(|_| {
        Error::from(Cause::Bug {
            site: "account list serialization",
        })
    })?;
    v["schema_version"] = serde_json::json!(crate::json::SCHEMA_VERSION);
    Ok(v)
}

/// `opv account use <who> [--json]` (FR-49): records the account in `.opv`, without a prompt
/// or a sign-in.
pub fn use_command(
    r: &dyn crate::runner::CommandRunner,
    who: &str,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), Error> {
    use crate::adapters::onepassword_manifest as manifest;
    let accounts = match manifest::discover(r) {
        manifest::Discovery::Listed(found) => found,
        manifest::Discovery::OpMissing => {
            return Err(crate::adapters::onepassword::op_missing(
                &crate::host::Host::detect(),
            ));
        }
        manifest::Discovery::Unavailable => return Err(account_list_failed()),
    };
    let here = std::env::current_dir().unwrap_or_default();
    let done = use_account(&accounts, who, &here, app_holds_accounts_here())?;
    if json {
        let v = serde_json::json!({
            "schema_version": crate::json::SCHEMA_VERSION,
            "account_id": done.account_id,
            "path": done.path,
        });
        return writeln!(out, "{v}").map_err(super::write_err);
    }
    writeln!(
        out,
        "This project uses 1Password account {}; recorded in {} (commit it).",
        done.account_id,
        done.path.display()
    )
    .map_err(super::write_err)
}

#[cfg(test)]
#[path = "account_tests.rs"]
mod tests;

#[cfg(test)]
mod credential_tests {
    use super::*;

    #[test]
    fn a_credential_report_has_no_findings() {
        assert!(credential_report(Platform::Linux).findings.is_empty());
    }

    #[test]
    fn a_credential_report_says_the_credential_decides() {
        let mut out = Vec::new();
        render_text(&credential_report(Platform::Linux), &mut out).unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("it decides the account")
        );
    }
}
