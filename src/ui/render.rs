//! Drawing `opv ui` (#82) with ratatui: the header, the sidebar of environments and
//! products (from the configuration), the main pane of the current screen, a confirmation
//! or input over it, and the key bar. Secret values are never drawn: a secret shows as
//! `••••` with its state word; config values are not secret and are not fetched either.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell as TCell, Clear, Paragraph, Row, Table, Wrap};

use super::app::{App, Modal, Nav, Screen};
use super::model::{Cell, Snapshot};

const DIM: Style = Style::new().fg(Color::DarkGray);
const OK: Style = Style::new().fg(Color::Green);
const WARN: Style = Style::new().fg(Color::Yellow);
const BAD: Style = Style::new().fg(Color::Red);
const BOLD: Style = Style::new().add_modifier(Modifier::BOLD);
const SELECTED: Style = Style::new()
    .add_modifier(Modifier::REVERSED)
    .add_modifier(Modifier::BOLD);

/// Draw the whole UI.
pub fn draw(f: &mut Frame, app: &App) {
    let keys = keybar_lines(f.area().width);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(5),
            Constraint::Length(1 + keys.len() as u16),
        ])
        .split(f.area());
    header(f, rows[0], app);
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(28), Constraint::Min(30)])
        .split(rows[1]);
    sidebar(f, cols[0], app);
    match &app.screen {
        Screen::Overview => overview(f, cols[1], app),
        Screen::Env(e) => env_screen(f, cols[1], app, e),
        Screen::Product(p) => product(f, cols[1], app, p),
        Screen::Key { product, key } => super::screens::key_detail(f, cols[1], app, product, key),
        Screen::Shared => super::screens::shared(f, cols[1], app),
        Screen::Accounts => super::screens::accounts(f, cols[1], app),
        Screen::Adopt { env, from } => super::screens::adopt(f, cols[1], app, env, from),
    }
    keybar(f, rows[2], app, keys);
    if let Some(m) = &app.modal {
        modal(f, f.area(), m);
    }
}

fn header(f: &mut Frame, area: Rect, app: &App) {
    let s = &app.snap;
    let mut spans = vec![Span::styled(" opv ui ", BOLD)];
    if let Some(src) = &s.config_source {
        spans.push(Span::styled(format!("· {src} "), DIM));
    }
    spans.push(Span::raw(match &s.account {
        Some(a) => format!("· account {a}"),
        None => "· account: decided by the credential, or none selected".into(),
    }));
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn sidebar(f: &mut Frame, area: Rect, app: &App) {
    let mut lines = Vec::new();
    let mut section = "";
    for (i, n) in app.nav.iter().enumerate() {
        let (group, text) = match n {
            Nav::Overview => ("", "Overview".to_string()),
            Nav::Shared => ("", "Shared values".to_string()),
            Nav::Env(e) => {
                let env = app.snap.env(e);
                let title = env.map_or(e.as_str(), |x| x.title.as_str());
                let kind = match env.and_then(|x| x.target.as_deref()) {
                    Some(t) => t.to_string(),
                    None => "local".into(),
                };
                ("ENVIRONMENTS", format!("{title} · {kind}"))
            }
            Nav::Product(p) => {
                let n = app
                    .snap
                    .products
                    .iter()
                    .find(|x| &x.name == p)
                    .map_or(0, |x| x.keys.len());
                ("PRODUCTS", format!("{p} · {n} keys"))
            }
        };
        if group != section && !group.is_empty() {
            lines.push(Line::styled(group, DIM));
            section = group;
        }
        let style = if i == app.nav_at && app.in_nav {
            SELECTED
        } else if i == app.nav_at {
            BOLD
        } else {
            Style::new()
        };
        lines.push(Line::styled(format!(" {text}"), style));
    }
    f.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::RIGHT)),
        area,
    );
}

/// The state word of one cell, as `status` would say it (never a value).
pub fn cell_word(cell: Option<&Cell>, kind: &str, delivered: bool) -> (String, Style) {
    let Some(c) = cell else {
        return ("—".into(), DIM);
    };
    if !delivered {
        return ("not here".into(), DIM);
    }
    let mask = if kind == "secret" {
        "•••• "
    } else {
        ""
    };
    if c.target.as_deref() == Some("not_delivered") {
        return ("not here".into(), DIM);
    }
    match c.state.as_str() {
        "missing" => ("missing".into(), WARN),
        "failing_rule" => (format!("✗ {}", c.rule.as_deref().unwrap_or("rule")), BAD),
        "wrong_kind" => ("✗ wrong kind".into(), BAD),
        "source_blocked" => ("blocked by source".into(), WARN),
        "skipped" => ("skipped".into(), DIM),
        "saved" => match c.target.as_deref() {
            Some("absent") => (format!("{mask}new"), WARN),
            Some("would_change") => (format!("{mask}changed"), WARN),
            Some("present") => (format!("{mask}same"), OK),
            _ => (format!("{mask}saved"), OK),
        },
        other => (other.to_string(), Style::new()),
    }
}

fn summary_cell(s: &Snapshot, env: &str, product: &str) -> (String, Style) {
    match s.summary.get(&(env.to_string(), product.to_string())) {
        None => ("—".into(), DIM),
        Some(m) if !m.delivered => ("not here".into(), DIM),
        Some(m) if m.findings > 0 => (
            format!("{}/{} · {} finding(s)", m.saved, m.keys, m.findings),
            WARN,
        ),
        Some(m) => (format!("✓ {}/{}", m.saved, m.keys), OK),
    }
}

fn overview(f: &mut Frame, area: Rect, app: &App) {
    let s = &app.snap;
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(4), Constraint::Length(9)])
        .split(area);
    let mut header = vec![TCell::from("PRODUCT")];
    header.extend(s.envs.iter().map(|e| TCell::from(e.title.clone())));
    let rows: Vec<Row> = s
        .product_names()
        .into_iter()
        .map(|p| {
            let mut cells = vec![TCell::from(p.to_string())];
            cells.extend(s.envs.iter().map(|e| {
                let (t, st) = summary_cell(s, &e.key, p);
                TCell::from(Span::styled(t, st))
            }));
            Row::new(cells)
        })
        .collect();
    let widths: Vec<Constraint> = std::iter::once(Constraint::Length(14))
        .chain(s.envs.iter().map(|_| Constraint::Min(14)))
        .collect();
    let title = match &s.receipt_id {
        Some(id) => format!(" Readiness: environments × products · receipt {id} "),
        None => " Readiness: environments × products ".into(),
    };
    f.render_widget(
        Table::new(rows, widths)
            .header(Row::new(header).style(DIM))
            .block(Block::default().borders(Borders::ALL).title(title)),
        parts[0],
    );
    let mut lines: Vec<Line> = Vec::new();
    if s.findings.is_empty() {
        lines.push(Line::styled(
            "Nothing needs attention: every declared key is saved.",
            OK,
        ));
    }
    for fnd in s.findings.iter().take(5) {
        let scope = [&fnd.environment, &fnd.product, &fnd.key]
            .iter()
            .filter_map(|x| x.as_deref())
            .collect::<Vec<_>>()
            .join(" · ");
        let style = if fnd.blocking { BAD } else { DIM };
        lines.push(Line::from(vec![
            Span::styled(format!("{} ", if fnd.blocking { "✗" } else { "·" }), style),
            Span::styled(format!("{} ", fnd.code), style),
            Span::raw(format!("{scope}  [{}]", fnd.actor)),
        ]));
        if let Some(m) = &fnd.message {
            lines.push(Line::raw(format!("    {m}")));
        }
        lines.push(Line::styled(format!("    → {}", fnd.prerequisite), DIM));
    }
    if let Some((actor, cmd)) = &s.next {
        lines.push(Line::from(vec![
            Span::styled("Next ", BOLD),
            Span::raw(format!("({actor}): {cmd}   ")),
            Span::styled("n runs it after you confirm", DIM),
        ]));
    }
    for p in &s.problems {
        lines.push(Line::styled(format!("could not read: {p}"), WARN));
    }
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Needs attention "),
        ),
        parts[1],
    );
}

/// A keys table: rows of (product, key), one column per environment in `envs`.
fn keys_table<'a>(
    app: &'a App,
    rows: &[(String, String)],
    envs: &[&str],
    title: String,
) -> Table<'a> {
    let s = &app.snap;
    let mut header = vec![TCell::from("KEY"), TCell::from("KIND")];
    header.extend(
        envs.iter()
            .map(|e| TCell::from(s.env(e).map_or(e.to_string(), |x| x.title.clone()))),
    );
    let body: Vec<Row> = rows
        .iter()
        .enumerate()
        .map(|(i, (p, k))| {
            let spec = s
                .products
                .iter()
                .find(|x| &x.name == p)
                .and_then(|x| x.keys.iter().find(|y| &y.name == k));
            let kind = spec.map_or("secret", |x| x.kind.as_str());
            let mut label = app.label(p, k);
            if spec.is_some_and(|x| x.personal) {
                label.push_str("  (yours)");
            }
            if spec.and_then(|x| x.from.as_ref()).is_some() {
                label.push_str("  ↗ shared");
            }
            let mut cells = vec![TCell::from(label), TCell::from(kind.to_string())];
            cells.extend(envs.iter().map(|e| {
                let delivered = s
                    .summary
                    .get(&(e.to_string(), p.clone()))
                    .is_none_or(|m| m.delivered);
                let (t, st) = cell_word(
                    s.cells.get(&(e.to_string(), p.clone(), k.clone())),
                    kind,
                    delivered,
                );
                TCell::from(Span::styled(t, st))
            }));
            let row = Row::new(cells);
            if i == app.row && !app.in_nav {
                row.style(SELECTED)
            } else {
                row
            }
        })
        .collect();
    let widths: Vec<Constraint> = [Constraint::Min(26), Constraint::Length(7)]
        .into_iter()
        .chain(envs.iter().map(|_| Constraint::Min(12)))
        .collect();
    Table::new(body, widths)
        .header(Row::new(header).style(DIM))
        .block(Block::default().borders(Borders::ALL).title(title))
}

fn product(f: &mut Frame, area: Rect, app: &App, p: &str) {
    let envs: Vec<&str> = app.snap.envs.iter().map(|e| e.key.as_str()).collect();
    let rows = app.main_rows();
    let title = format!(" {p} · {} keys × {} environments ", rows.len(), envs.len());
    f.render_widget(keys_table(app, &rows, &envs, title), area);
}

fn env_screen(f: &mut Frame, area: Rect, app: &App, e: &str) {
    let rows = app.main_rows();
    let env = app.snap.env(e);
    let mut title = format!(" {} ", env.map_or(e, |x| x.title.as_str()));
    if let Some(a) = env.and_then(|x| x.audience.as_deref()) {
        title.push_str(&format!("· for {a} "));
    }
    if env.is_some_and(|x| x.guarded) {
        title.push_str("· guarded ");
    }
    f.render_widget(keys_table(app, &rows, &[e], title), area);
}

/// Every key the bar lists, most needed first.
const KEYS: [&str; 14] = [
    "q quit",
    "↑↓ move",
    "tab sidebar/main",
    "enter open",
    "esc back",
    "s sync…",
    "i adopt…",
    "o open in 1Password",
    "+ key…",
    "E environment…",
    "e edit config",
    "n next step",
    "a accounts",
    "r refresh",
];

/// The key bar wrapped to `width` (whole entries per line), at most three lines.
pub fn keybar_lines(width: u16) -> Vec<String> {
    let width = usize::from(width.max(1));
    let mut lines: Vec<String> = Vec::new();
    for k in KEYS {
        match lines.last_mut() {
            Some(l) if l.chars().count() + 3 + k.chars().count() <= width => {
                l.push_str(" · ");
                l.push_str(k);
            }
            _ => lines.push(k.to_string()),
        }
    }
    lines.truncate(3);
    lines
}

fn keybar(f: &mut Frame, area: Rect, app: &App, keys: Vec<String>) {
    let mut lines = vec![Line::styled(app.status.clone(), WARN)];
    lines.extend(keys.into_iter().map(|k| Line::styled(k, DIM)));
    f.render_widget(Paragraph::new(lines), area);
}

/// Drop every colour from a drawn frame, for a terminal where colour is off (`NO_COLOR`):
/// what was dimmed by colour keeps the dim attribute, and reverse and bold (the selection)
/// stay as they are.
pub fn monochrome(buf: &mut ratatui::buffer::Buffer) {
    for cell in &mut buf.content {
        if cell.fg == Color::DarkGray {
            cell.modifier |= Modifier::DIM;
        }
        cell.fg = Color::Reset;
        cell.bg = Color::Reset;
    }
}

fn modal(f: &mut Frame, area: Rect, m: &Modal) {
    let w = area.width.saturating_sub(10).min(90);
    let h = match m {
        Modal::Form(form) => (form.rows().len() as u16 + 5).min(area.height),
        _ => 12.min(area.height),
    };
    let r = Rect::new(
        area.x + (area.width.saturating_sub(w)) / 2,
        area.y + (area.height.saturating_sub(h)) / 2,
        w,
        h,
    );
    f.render_widget(Clear, r);
    let (title, mut lines) = match m {
        Modal::Confirm {
            title,
            lines,
            command,
            guard,
            typed,
        } => {
            let mut out: Vec<Line> = lines.iter().map(|l| Line::raw(l.clone())).collect();
            out.push(Line::raw(""));
            match (command.is_empty(), guard) {
                (true, _) => out.push(Line::styled("enter or esc: close", DIM)),
                (false, Some(g)) => {
                    out.push(Line::raw(format!("type {g} to confirm: {typed}▏")));
                    out.push(Line::styled(
                        "enter: run · esc: cancel (nothing written)",
                        DIM,
                    ));
                }
                (false, None) => out.push(Line::styled(
                    "enter: run · esc: cancel (nothing written)",
                    DIM,
                )),
            }
            (title.clone(), out)
        }
        Modal::Form(form) => {
            let mut out: Vec<Line> = form
                .lines()
                .into_iter()
                .map(|(label, text, on)| {
                    let line = format!("{label:<14} {text}{}", if on { "▏" } else { "" });
                    if on {
                        Line::styled(line, SELECTED)
                    } else {
                        Line::raw(line)
                    }
                })
                .collect();
            if let Some(e) = &form.error {
                out.push(Line::styled(e.clone(), BAD));
            }
            out.push(Line::styled(
                "↑↓ move · type · space choose · enter: review the command · esc: cancel",
                DIM,
            ));
            (form.title().to_string(), out)
        }
        Modal::Input { prompt, value, .. } => (
            "Adopt".to_string(),
            vec![
                Line::raw(prompt.clone()),
                Line::raw(format!("{value}▏")),
                Line::styled("enter: continue · esc: cancel", DIM),
            ],
        ),
    };
    lines.truncate(h as usize);
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {title} ")),
        ),
        r,
    );
}

#[cfg(test)]
#[path = "render_tests.rs"]
mod tests;
