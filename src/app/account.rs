//! `opv account list` and `opv account use` (FR-49): which 1Password accounts this
//! machine's `op` knows, which one this project uses, and the findings that tell a person
//! or agent what to do next. Read-only for `list`; `use` records one account in `.opv`.
//!
//! Nothing here calls `op`: [`report`] takes the already-probed [`Discovery`] and a
//! [`signed_in`](Inputs::signed_in) closure, so it is pure and testable. The CLI wiring
//! that runs `op`, reads `.opv`/`OP_ACCOUNT` and prints the document is a later deliverable.

use std::io::Write;

use crate::adapters::onepassword_manifest::{Account, Discovery};
use crate::error::{Code, Error};
use crate::host::Platform;

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
}

/// The names of the `OP_SESSION_*` variables set in this process's environment (#142).
pub fn session_var_names() -> Vec<String> {
    let mut names: Vec<String> = std::env::vars_os()
        .filter_map(|(k, _)| k.into_string().ok())
        .filter(|k| k.starts_with("OP_SESSION_"))
        .collect();
    names.sort();
    names
}

/// The selected account: its ID, how it was chosen and where that choice came from.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Selected {
    pub account_id: String,
    /// `flag`, `env`, `pointer`, `manifest` or `only`.
    pub by: String,
    /// `--account`, `OP_ACCOUNT`, the pointer's path, `manifest`, or `only`.
    pub source: String,
}

/// One account this CLI knows, as the document lists it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Finding {
    pub code: String,
    pub human_required: bool,
    pub message: String,
    pub next: Option<String>,
}

/// The FR-49 document (`opv account list --json`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Report {
    pub discovery: String,
    pub platform: String,
    pub cli_accounts_only: bool,
    pub selected: Option<Selected>,
    pub accounts: Vec<AccountRow>,
    pub findings: Vec<Finding>,
    pub next: Option<String>,
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

/// The next step for a value that names no listed account: one add-account step for an
/// email, else the command that lists the accounts.
fn absent_next(value: &str) -> String {
    if value.contains('@') {
        format!("opv login --add --account {value}")
    } else {
        "opv account list".to_string()
    }
}

/// The finding for a selection value that names no listed account: one add-account step
/// for an email, else the command that lists the accounts.
fn absent_finding(value: &str, source: &str) -> Finding {
    Finding {
        code: "selected_account_absent".into(),
        human_required: true,
        message: format!(
            "no 1Password account listed by this CLI matches {value:?} (from {source})"
        ),
        next: Some(absent_next(value)),
    }
}

/// The finding for a selection value several listed accounts match (a sign-in address is
/// shared by every account on it): the candidates' IDs and addresses only.
fn ambiguous_finding(value: &str, source: &str, many: &[&Account]) -> Finding {
    let ids: Vec<String> = many
        .iter()
        .map(|a| format!("{} ({})", a.account_uuid, address(&a.url)))
        .collect();
    Finding {
        code: "account_ambiguous".into(),
        human_required: true,
        message: format!(
            "{value:?} (from {source}) matches {} accounts: {}; name one by its account ID",
            many.len(),
            ids.join(", ")
        ),
        next: Some(format!("opv account use {}", many[0].account_uuid)),
    }
}

/// The finding for a selected account whose session probe says it is signed out.
fn signed_out_finding(account_id: &str) -> Finding {
    Finding {
        code: "selected_signed_out".into(),
        human_required: true,
        message: format!("the selected 1Password account {account_id} is not signed in"),
        next: Some(format!("opv login --account {account_id}")),
    }
}

/// #142: several accounts on one sign-in address (`my.1password.com` for every individual
/// and family account): naming the address picks one of them, often not the intended
/// one. Each is named by shorthand and email so the person can name the right one.
fn shared_address_findings(listed: &[Account], selected: Option<&str>) -> Vec<Finding> {
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
                code: "shared_sign_in_address".into(),
                human_required: false,
                message: format!(
                    "{} accounts share the sign-in address {host}: {}. Naming {host} picks one \
                     of them; name an account by its account ID with opv, or by its shorthand \
                     with op (op signin --account <shorthand>)",
                    accounts.len(),
                    named.join("; ")
                ),
                next: selected.map(|id| format!("opv login --account {id}")),
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
    let next = selected.map(|id| format!("opv login --account {id}"));
    vars.iter()
        .filter_map(|var| {
            let name = var.strip_prefix("OP_SESSION_")?;
            let owner = listed.iter().find(|a| {
                [&a.shorthand, &a.user_uuid, &a.account_uuid]
                    .iter()
                    .any(|f| !f.is_empty() && f.eq_ignore_ascii_case(name))
            });
            match owner {
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
                    next: next.clone(),
                }),
                None => Some(Finding {
                    code: "stale_session_variable".into(),
                    human_required: true,
                    message: format!(
                        "{var} in this shell names no account this 1Password CLI knows (an old \
                         eval of op signin?); remove it from this shell (unset {var})"
                    ),
                    next: next.clone(),
                }),
            }
        })
        .collect()
}

/// Build the FR-49 report. Pure: no `op` call, no filesystem, no prompt.
pub fn report(inputs: &Inputs<'_>) -> Report {
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
        }),
        Discovery::OpMissing => findings.push(Finding {
            code: "op_missing".into(),
            human_required: true,
            message: "the 1Password CLI (op) is not installed".into(),
            next: Some("opv doctor".into()),
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
            findings.push(Finding {
                code: "no_accounts".into(),
                human_required: true,
                message: "this 1Password CLI knows no accounts; add one".into(),
                next: Some("opv login --add".into()),
            });
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
                [] => findings.push(absent_finding(value, &source)),
                many => findings.push(ambiguous_finding(value, &source, many)),
            }
        } else if listed.len() == 1 {
            selected_at = Some(0);
            selected = Some(Selected {
                account_id: rows[0].account_id.clone(),
                by: "only".into(),
                source: "only".into(),
            });
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
    findings.extend(shared_address_findings(listed, chosen));
    let next = findings.first().and_then(|f| f.next.clone());
    Report {
        discovery: discovery_str(&inputs.discovery).into(),
        platform: platform_str(inputs.platform).into(),
        cli_accounts_only: matches!(
            inputs.platform,
            Platform::Linux | Platform::Wsl | Platform::Other
        ),
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
    }
    for finding in &report.findings {
        writeln!(out, "{}: {}", finding.code, finding.message).map_err(super::write_err)?;
    }
    Ok(())
}

/// Resolve `who` to one listed account and record it in the nearest `.opv`. Several
/// matches name the candidates' IDs and addresses only and pick the first; no match names
/// `who` and points at the add-account (or list) step.
pub fn use_account(
    accounts: &[Account],
    who: &str,
    start: &std::path::Path,
) -> Result<UseOutcome, Error> {
    match matching(accounts, who).as_slice() {
        [one] => {
            let account_id = one.account_uuid.clone();
            let path = crate::config_store::record_account(start, &account_id)?;
            Ok(UseOutcome { account_id, path })
        }
        [] => Err(Error::Config(
            format!("no 1Password account listed by this CLI matches {who:?}").into(),
        )
        .with_code(Code::AccountNotRegistered)
        .with_next(absent_next(who))),
        many => {
            let listing = many
                .iter()
                .map(|a| format!("  {}  {}", a.account_uuid, address(&a.url)))
                .collect::<Vec<_>>()
                .join("\n");
            Err(Error::Config(
                format!(
                    "{} 1Password accounts match; pick one by its account ID:\n{listing}",
                    many.len()
                )
                .into(),
            )
            .with_code(Code::AccountAmbiguous)
            .with_next(format!("opv account use {}", many[0].account_uuid)))
        }
    }
}

/// The FR-49 report for this machine and checkout: one `op account list` probe, one
/// `op whoami --account <id>` probe per listed account, `.opv` and `OP_ACCOUNT`.
pub fn gather(r: &dyn crate::runner::CommandRunner, flag: Option<&str>) -> Report {
    use crate::adapters::onepassword_manifest as manifest;
    let host = crate::host::Host::detect();
    // A service account or Connect decides the account itself: nothing to list or choose.
    if host.op_credential.is_some() {
        return credential_report(host.platform);
    }
    let here = std::env::current_dir().unwrap_or_default();
    let pointer = crate::config_store::pointer_account(&here);
    let env = crate::config_store::account_env();
    let probe = |id: &str| manifest::signed_in(r, id);
    report(&Inputs {
        discovery: manifest::discover(r),
        signed_in: &probe,
        flag,
        env: env.as_deref(),
        pointer: pointer
            .as_deref()
            .map(|a| (a, std::path::Path::new(".opv"))),
        manifest: None,
        platform: crate::host::Host::detect().platform,
        session_vars: session_var_names(),
    })
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
    if json {
        let mut v = serde_json::to_value(&doc)
            .map_err(|_| Error::Config("cannot serialize the account list".into()))?;
        v["schema_version"] = serde_json::json!(crate::json::SCHEMA_VERSION);
        return writeln!(out, "{v}").map_err(super::write_err);
    }
    render_text(&doc, out)?;
    if let Some(next) = &doc.next {
        writeln!(out, "Next: {next}").map_err(super::write_err)?;
    }
    Ok(())
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
        manifest::Discovery::Unavailable => {
            return Err(Error::Source(
                "op account list failed, so opv cannot check the account; nothing was recorded"
                    .into(),
            )
            .with_next("opv doctor"));
        }
    };
    let here = std::env::current_dir().unwrap_or_default();
    let done = use_account(&accounts, who, &here)?;
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
