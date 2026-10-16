//! The detail screens of `opv ui` (#82): one key, the shared values and their consumers, and
//! the 1Password accounts. Names, states and commands only.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use super::app::App;
use super::render::cell_word;

const DIM: Style = Style::new().fg(Color::DarkGray);
const BOLD: Style = Style::new().add_modifier(Modifier::BOLD);

/// One key: its declaration, where it lands per environment, who reads it, and its actions
/// with the commands they run.
pub fn key_detail(f: &mut Frame, area: Rect, app: &App, product: &str, key: &str) {
    let s = &app.snap;
    let spec = s
        .products
        .iter()
        .find(|p| p.name == product)
        .and_then(|p| p.keys.iter().find(|k| k.name == key));
    let label = app.label(product, key);
    let mut lines = vec![Line::styled(label.clone(), BOLD)];
    if let Some(k) = spec {
        let mut kind = k.kind.clone();
        if k.personal {
            kind.push_str(" · personal (your own value)");
        }
        if k.immutable {
            kind.push_str(" · immutable");
        }
        lines.push(Line::raw(format!("kind      {kind}")));
        if let Some(from) = &k.from {
            lines.push(Line::raw(format!("shared    reads {from}")));
        }
        if !k.guidance.is_empty() {
            lines.push(Line::raw(format!("guidance  {}", k.guidance)));
        }
        lines.push(Line::raw(""));
        for e in &s.envs {
            if !k.environments.contains(&e.key) {
                continue;
            }
            let delivered = s
                .summary
                .get(&(e.key.clone(), product.to_string()))
                .is_none_or(|m| m.delivered);
            let (word, style) = cell_word(
                s.cells
                    .get(&(e.key.clone(), product.to_string(), key.to_string())),
                &k.kind,
                delivered,
            );
            lines.push(Line::from(vec![
                Span::raw(format!("{:<24}", e.title)),
                Span::styled(format!("{word:<18}"), style),
                Span::styled(e.place(), DIM),
            ]));
        }
    }
    let found = s.findings_for(product, key);
    if !found.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::styled("Needs attention", BOLD));
        for fnd in found {
            let mark = if fnd.blocking { "✗" } else { "!" };
            let env = fnd.environment.as_deref().unwrap_or("-");
            lines.push(Line::raw(format!("{mark} {} ({env})", fnd.code)));
            if let Some(m) = &fnd.message {
                lines.push(Line::raw(format!("  {m}")));
            }
            lines.push(Line::styled(format!("  → {}", fnd.prerequisite), DIM));
        }
    }
    let readers = s.consumers(product, key);
    if !readers.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::raw(format!(
            "read by   {}",
            readers
                .iter()
                .map(|(p, k)| app.label(p, k))
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        "o  open it in 1Password to type or fix the value",
        DIM,
    ));
    lines.push(Line::styled(
        format!(
            "   = {}   ·   opv explain {label}",
            super::app::command_line(&app.open_command(product, key))
        ),
        DIM,
    ));
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title(" Key ")),
        area,
    );
}

/// The shared values (source-only products) and every key that reads each.
pub fn shared(f: &mut Frame, area: Rect, app: &App) {
    let s = &app.snap;
    let mut lines = Vec::new();
    let rows = app.main_rows();
    if rows.is_empty() {
        lines.push(Line::raw(
            "No shared values: a source-only product (source_only = true) holds values other \
             keys point at with from.",
        ));
    }
    for (i, (p, k)) in rows.iter().enumerate() {
        let readers = s.consumers(p, k);
        let text = format!(
            "{:<32} used by {} key(s){}",
            app.label(p, k),
            readers.len(),
            if readers.is_empty() {
                "  ! nothing reads it"
            } else {
                ""
            }
        );
        let style = if i == app.row && !app.in_nav {
            Style::new().add_modifier(Modifier::REVERSED)
        } else {
            Style::new()
        };
        lines.push(Line::styled(text, style));
        for (rp, rk) in readers {
            lines.push(Line::styled(format!("    ↳ {}", app.label(&rp, &rk)), DIM));
        }
    }
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Shared values "),
        ),
        area,
    );
}

/// The accounts this CLI knows (`opv account list --json`).
pub fn accounts(f: &mut Frame, area: Rect, app: &App) {
    let mut lines = Vec::new();
    match &app.accounts {
        None => lines.push(Line::raw("reading accounts…")),
        Some(Err(failure)) => failed(&mut lines, "could not list the accounts", failure),
        Some(Ok(doc)) => {
            for a in &doc.accounts {
                let mark = if a.selected { "*" } else { " " };
                let signed = match a.signed_in {
                    Some(true) => "signed in",
                    Some(false) => "signed out",
                    None => "unknown",
                };
                lines.push(Line::raw(format!(
                    "{mark} {} ({})  {}  {signed}",
                    a.email, a.account_id, a.address,
                )));
            }
            if doc.accounts.is_empty() {
                lines.push(Line::raw(
                    "No 1Password account is listed: opv signs in with the credential it finds.",
                ));
            }
            if doc.cli_accounts_only {
                lines.push(Line::styled(
                    "Only accounts added to this 1Password CLI are listed; add one with opv \
                     login --add (at 1Password's own prompt).",
                    DIM,
                ));
            }
            for fnd in &doc.findings {
                let next = fnd
                    .next
                    .as_deref()
                    .map_or(String::new(), |n| format!("  → {n}"));
                lines.push(Line::raw(format!("{}: {}{next}", fnd.code, fnd.message)));
            }
        }
    }
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" 1Password accounts "),
        ),
        area,
    );
}

/// The adoption review (#94): each found key with what would happen and the person's
/// decision, the count it would write and the keys. Names and actions only, never a value.
pub fn adopt(f: &mut Frame, area: Rect, app: &App, env: &str, from: &str) {
    use super::adopt_review::{Decision, writes};
    let mut lines = vec![
        Line::raw(format!(
            "From {from} into {env}: nothing is written until you confirm"
        )),
        Line::raw(""),
    ];
    for (i, r) in app.adopt.iter().enumerate() {
        let decision = match r.decision {
            Some(Decision::Take) if r.action == "differs" => "replace (take the found value)",
            Some(Decision::Take) => "import",
            Some(Decision::Keep) => "keep 1Password",
            Some(Decision::Skip) => "skip",
            None => "",
        };
        let what = match r.action.as_str() {
            "import" => "new in 1Password".to_string(),
            "differs" => "differs from 1Password".to_string(),
            "match" | "format_only" => "same value".to_string(),
            "fails_rule" => "fails a rule: not imported".to_string(),
            "conflict" => "found copies differ: decide in 1Password".to_string(),
            "ambiguous" => "matches several keys: not imported".to_string(),
            "not_declared" => "not declared: ignored".to_string(),
            "not_applicable" => "not in this environment".to_string(),
            other => other.replace('_', " "),
        };
        let lock = if r.immutable { " (immutable)" } else { "" };
        let text = format!("{:<32} {what:<28} {decision}{lock}", r.label);
        let style = if i == app.row && !app.in_nav {
            Style::new().add_modifier(Modifier::REVERSED)
        } else if r.decision.is_none() {
            DIM
        } else {
            Style::new()
        };
        lines.push(Line::styled(text, style));
    }
    if app.adopt.is_empty() {
        lines.push(Line::raw("Nothing found in the source."));
    }
    lines.push(Line::raw(""));
    lines.push(Line::raw(format!(
        "{} to write · enter: change the selected key · y: review and apply · esc: back",
        writes(&app.adopt)
    )));
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title(" Adopt ")),
        area,
    );
}

/// What opv last wrote to `env`'s target (#95), from `opv history <env> --json`: the
/// latest write, then each key with its state. Names, versions, times and plan ids only.
pub fn history(f: &mut Frame, area: Rect, app: &App, env: &str) {
    let mut lines = Vec::new();
    match &app.history {
        None => lines.push(Line::raw("reading history…")),
        Some(Err(failure)) => failed(&mut lines, "could not read the history", failure),
        Some(Ok(doc)) => {
            let parts = doc.parts();
            let several = parts.len() > 1;
            for part in &parts {
                if several {
                    lines.push(Line::styled(format!("target {}", part.name), BOLD));
                }
                match &part.latest {
                    Some(l) => lines.push(Line::styled(
                        format!(
                            "last write {} by plan {} (opv {})",
                            l.written.as_deref().unwrap_or("-"),
                            l.plan.as_deref().unwrap_or("-"),
                            l.opv_version.as_deref().unwrap_or("-"),
                        ),
                        BOLD,
                    )),
                    None => lines.push(Line::raw(
                        "no opv write stamp found here; versions are compared with what opv's own syncs recorded",
                    )),
                }
                lines.push(Line::raw(""));
                for r in &part.rows {
                    let label = app.label(&r.product, &r.key);
                    let state = match r.state.as_str() {
                        "stamped" => "written by opv",
                        "recorded" => "as opv left it",
                        "changed_outside_opv" => "changed outside opv",
                        "not_recorded" => "no record of opv writing it",
                        "absent" => "not on the target",
                        other => other,
                    };
                    lines.push(Line::raw(format!(
                        "{label:<30} {:<10} {state:<28} {}",
                        r.version.as_deref().unwrap_or("-"),
                        r.written.as_deref().unwrap_or(""),
                    )));
                }
                if part.rows.is_empty() {
                    lines.push(Line::raw("no secret this target delivers is declared"));
                }
                if several {
                    lines.push(Line::raw(""));
                }
            }
            if parts.is_empty() {
                lines.push(Line::raw(
                    "no target: opv writes nothing outside 1Password for this environment",
                ));
            }
        }
    }
    let title = format!(
        " History · {} ",
        app.snap.env(env).map_or(env, |e| e.title.as_str())
    );
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title(title)),
        area,
    );
}

/// Who needs which vault and whether they have it (#96, FR-59), from `opv access --json`:
/// per environment each principal's grants and their state, extra readers, the findings,
/// and the owner's commands (shown, never run: 1Password shows a new token once). Never
/// "clean": what was checked and what could not be classified are counted.
pub fn access(f: &mut Frame, area: Rect, app: &App) {
    use crate::domain::access_plan::{GrantState, Permission, Principal};
    let mut lines = Vec::new();
    match &app.access {
        None => lines.push(Line::raw("reading who can use each vault…")),
        Some(Err(failure)) => failed(&mut lines, "could not read the vault access", failure),
        Some(Ok(doc)) => {
            for e in &doc.environments {
                let name = e.environment.as_str();
                let title = app.snap.env(name).map_or(name, |x| x.title.as_str());
                lines.push(Line::styled(title.to_string(), BOLD));
                for check in &e.report.checks {
                    let who = match &check.grant.principal {
                        Principal::Deploy { target, .. } => format!("deploy identity of {target}"),
                        Principal::CiReader { .. } => "CI reader".to_string(),
                    };
                    let needs = match check.grant.permission {
                        Permission::Read => "read",
                        Permission::ReadWrite => "read and write",
                    };
                    let state = match check.state {
                        GrantState::Present => "granted",
                        GrantState::Missing => "missing",
                        GrantState::ReadOnlyNeeded => "can write, should only read",
                        GrantState::NotVisible => "not visible to you",
                        GrantState::NotInAccount => "vault not in this account",
                    };
                    lines.push(Line::raw(format!(
                        "  {who} ({}): {needs} on vault {}: {state}",
                        check.grant.service_account, check.grant.vault_id
                    )));
                }
                for extra in &e.report.extra {
                    lines.push(Line::raw(format!(
                        "  extra reader {} on vault {}",
                        extra.service_account, extra.vault_id
                    )));
                }
                for fnd in &e.findings {
                    lines.push(Line::raw(format!("  ! {}: {}", fnd.code, fnd.message)));
                    if let Some(n) = &fnd.next {
                        lines.push(Line::styled(format!("    next: {n}"), DIM));
                    }
                }
                for c in &e.commands {
                    lines.push(Line::styled(format!("  Owner runs: {c}"), DIM));
                }
                if !e.commands.is_empty() {
                    lines.push(Line::styled(
                        format!(
                            "  1Password shows a new token once: store it as the CI secret \
                             OP_SERVICE_ACCOUNT_TOKEN, or run opv access {name} --create \
                             --github <owner/repo>"
                        ),
                        DIM,
                    ));
                }
                lines.push(Line::styled(
                    format!(
                        "  checked: {}, could not classify: {}",
                        e.report.checked, e.report.unclassified
                    ),
                    DIM,
                ));
            }
            if doc.environments.is_empty() {
                lines.push(Line::raw("no environment needs vault access"));
            }
        }
    }
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title(" CI access ")),
        area,
    );
}

/// The lines of a document that could not be read: what, the error, and its steps.
fn failed(lines: &mut Vec<Line<'static>>, what: &str, failure: &super::docs::Failure) {
    let mut text = failure.lines().into_iter();
    lines.push(Line::raw(format!(
        "{what}: {}",
        text.next().unwrap_or_default()
    )));
    for l in text {
        lines.push(Line::styled(l, DIM));
    }
}
