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
            let place = e.target.as_deref().unwrap_or("local");
            lines.push(Line::from(vec![
                Span::raw(format!("{:<24}", e.title)),
                Span::styled(format!("{word:<18}"), style),
                Span::styled(place.to_string(), DIM),
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
        format!("   = opv open {label}   ·   opv explain {label}"),
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
        Some(doc) => {
            for a in doc["accounts"].as_array().into_iter().flatten() {
                let mark = if a["selected"].as_bool() == Some(true) {
                    "*"
                } else {
                    " "
                };
                let signed = match a["signed_in"].as_bool() {
                    Some(true) => "signed in",
                    Some(false) => "signed out",
                    None => "unknown",
                };
                lines.push(Line::raw(format!(
                    "{mark} {} ({})  {}  {signed}",
                    a["email"].as_str().unwrap_or("-"),
                    a["account_id"].as_str().unwrap_or("-"),
                    a["address"].as_str().unwrap_or("-"),
                )));
            }
            if doc["cli_accounts_only"].as_bool() == Some(true) {
                lines.push(Line::styled(
                    "Only accounts added to this 1Password CLI are listed; add one with opv \
                     login --add (at 1Password's own prompt).",
                    DIM,
                ));
            }
            for fnd in doc["findings"].as_array().into_iter().flatten() {
                lines.push(Line::raw(format!(
                    "{}: {}  → {}",
                    fnd["code"].as_str().unwrap_or(""),
                    fnd["message"].as_str().unwrap_or(""),
                    fnd["next"].as_str().unwrap_or("")
                )));
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
