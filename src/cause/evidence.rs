//! Evidence of a failure (design §7.1, §7.3, §9.4): opv's own `checked:` line, rendered from
//! the typed [`Observed`] call, and the attributed box holding the upstream tool's reply.
//!
//! The box is the only place third-party text appears. It is already scrubbed when it reaches
//! [`Upstream`]; here control characters, escape sequences and bidirectional overrides are
//! stripped once more (display, never interpretation), lines are cut at
//! [`LINE_CHARS`] characters and at most [`BOX_LINES`] lines are shown unless verbose.

use super::{AccountId, ExitClass, Observed, Principal, Upstream};

/// Lines the box shows without `--verbose`.
pub const BOX_LINES: usize = 5;
/// Characters per line the box shows without `--verbose`.
pub const LINE_CHARS: usize = 240;

/// How a failed call ended, in plain words (`exit 1`, `timed out`).
pub fn exit_words(exit: ExitClass) -> String {
    match exit {
        ExitClass::Code { code } => format!("exit {code}"),
        ExitClass::Signal { signal } => format!("stopped by signal {signal}"),
        ExitClass::TimedOut => "timed out".to_string(),
        ExitClass::SpawnFailed => "did not start".to_string(),
    }
}

/// The call opv made, names and IDs only: `op vault get v1`.
pub fn call_words(seen: &Observed) -> String {
    let call = seen.call();
    std::iter::once(call.program.as_str())
        .chain(call.words.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The account the call ran in: the cause's own account when it names one (the selected
/// account of `InOtherAccount`), else the acting person's. Always an ID, never an email.
pub fn checked_account<'a>(
    seen: &'a Observed,
    cause_account: Option<&'a AccountId>,
) -> Option<&'a AccountId> {
    cause_account.or(match seen.principal() {
        Principal::Person { account } => account.as_ref(),
        Principal::ServiceAccount { .. }
        | Principal::ServicePrincipal { .. }
        | Principal::AppIdentity { .. }
        | Principal::StoreIdentity { .. }
        | Principal::DeployCredentials { .. }
        | Principal::ShellToken { .. } => None,
    })
}

/// Who acted, for the `checked:` line; `None` for the signed-in person (the account says it).
fn acting_as(p: &Principal) -> Option<String> {
    match p {
        Principal::Person { .. } => None,
        Principal::ServiceAccount { name } => Some(format!("service account {name}")),
        Principal::ServicePrincipal { client_id } => Some(format!("service principal {client_id}")),
        Principal::AppIdentity { name } => Some(format!("app identity {name}")),
        Principal::StoreIdentity { name } => Some(format!("store identity {name}")),
        Principal::DeployCredentials { item, env, target } => Some(format!(
            "deploy credentials {item} of target {target} in environment {env}"
        )),
        Principal::ShellToken { var } => Some(format!("the token in {var}")),
    }
}

/// `checked: op vault get v1 in account A1 (exit 1)`, without indentation.
pub fn checked_line(seen: &Observed, cause_account: Option<&AccountId>) -> String {
    let mut s = format!("checked: {}", call_words(seen));
    if let Some(a) = checked_account(seen, cause_account) {
        s.push_str(&format!(" in account {a}"));
    }
    if let Some(who) = acting_as(seen.principal()) {
        s.push_str(&format!(" as {who}"));
    }
    s.push_str(&format!(" ({})", exit_words(seen.exit())));
    s
}

/// Remove what a terminal could interpret (§9.4): C0/C1 controls other than tab, ANSI/OSC
/// escape sequences, and bidirectional overrides.
pub fn strip_display(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            match chars.peek() {
                // CSI: parameters and intermediates, ended by a final byte 0x40..=0x7e.
                Some('[') => {
                    chars.next();
                    for d in chars.by_ref() {
                        if ('\u{40}'..='\u{7e}').contains(&d) {
                            break;
                        }
                    }
                }
                // OSC/DCS/PM/APC: ended by BEL or ESC \.
                Some(']' | 'P' | '^' | '_') => {
                    chars.next();
                    while let Some(d) = chars.next() {
                        if d == '\u{7}' {
                            break;
                        }
                        if d == '\u{1b}' {
                            if chars.peek() == Some(&'\\') {
                                chars.next();
                            }
                            break;
                        }
                    }
                }
                Some(_) => {
                    chars.next();
                }
                None => {}
            }
            continue;
        }
        let bidi = matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
        if (c.is_control() && c != '\t') || bidi {
            continue;
        }
        out.push(c);
    }
    out
}

/// The lines the box shows: stripped, cut at [`LINE_CHARS`] and limited to [`BOX_LINES`]
/// unless verbose. Also returns how many lines were left out.
pub fn shown_lines(up: &Upstream, verbose: bool) -> (Vec<String>, usize) {
    let take = if verbose { up.said.len() } else { BOX_LINES };
    let lines = up
        .said
        .iter()
        .take(take)
        .map(|l| {
            let l = strip_display(l);
            if verbose || l.chars().count() <= LINE_CHARS {
                l
            } else {
                let cut: String = l.chars().take(LINE_CHARS).collect();
                format!("{cut}…")
            }
        })
        .collect::<Vec<_>>();
    let left_out = up.said.len().saturating_sub(lines.len());
    (lines, left_out)
}

/// The attributed box (§7.3); `utf8: false` falls back to ASCII. Ends with a newline.
pub fn upstream_box(up: &Upstream, verbose: bool, utf8: bool) -> String {
    let (lines, left_out) = shown_lines(up, verbose);
    let head = match &up.version {
        Some(v) => format!("{} ({v}) replied, {}", up.tool, exit_words(up.exit)),
        None => format!("{} replied, {}", up.tool, exit_words(up.exit)),
    };
    let mut notes = vec!["scrubbed".to_string()];
    if up.removed_advice {
        notes.push(format!("{}'s own advice removed", up.tool));
    }
    if left_out > 0 {
        notes.push(format!("{left_out} more lines with --verbose"));
    }
    let foot = format!("({})", notes.join("; "));
    let (top, bar, bottom) = if utf8 {
        (format!("╭─ {head}"), "│ ", format!("╰─ {foot}"))
    } else {
        (format!("--- {head} ---"), "| ", format!("--- {foot} ---"))
    };
    let mut s = top;
    s.push('\n');
    for l in lines {
        s.push_str(bar);
        s.push_str(&l);
        s.push('\n');
    }
    s.push_str(&bottom);
    s.push('\n');
    s
}

/// The document's `evidence.upstream`: the same lines the box shows, marked untrusted.
pub fn upstream_value(up: &Upstream, verbose: bool) -> serde_json::Value {
    let (lines, _) = shown_lines(up, verbose);
    let mut v = serde_json::to_value(up).unwrap_or(serde_json::Value::Null);
    if let Some(o) = v.as_object_mut() {
        o.insert("said".into(), serde_json::json!(lines));
        o.insert("untrusted".into(), serde_json::Value::Bool(true));
    }
    v
}
