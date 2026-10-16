//! The terminal loop of `opv ui` (#82): reads the documents from this opv binary, draws, and
//! handles keys. An action leaves the full-screen view, runs the `opv` command in the
//! person's terminal (so 1Password's prompts and opv's output appear exactly as on the CLI),
//! waits for Enter, and comes back refreshed.

use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use super::app::{App, Effect, Key};
use super::docs::{AccessDoc, AccountsDoc, AdoptDoc, HistoryDoc, RowsDoc, Source, fetch};
use super::model::Snapshot;
use crate::cause::{Cause, NoTerminal};
use crate::error::Error;
use crate::runner::signals;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

/// This opv binary, run as a child with `--json` documents on stdout.
pub struct Exe {
    pub exe: PathBuf,
    /// `--config` given to `opv ui`, passed on to every child.
    pub config: Option<PathBuf>,
}

impl Exe {
    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(&self.exe);
        if let Some(cfg) = &self.config {
            c.arg("--config").arg(cfg);
        }
        c.args(args);
        c
    }
}

impl Source for Exe {
    fn stdout(&self, args: &[&str]) -> Result<Vec<u8>, String> {
        let out = self
            .command(args)
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map_err(|e| format!("could not run opv ({})", e.kind()))?;
        Ok(out.stdout)
    }
}

/// The UI's key for a terminal key event. Ctrl-C (raw mode turns it into a key, not a
/// signal) is [`Key::Interrupt`]; any other Ctrl or Alt chord means nothing, so Ctrl-S is
/// never `s` (sync).
pub(crate) fn key_of(k: KeyEvent) -> Option<Key> {
    if k.modifiers.contains(KeyModifiers::CONTROL) {
        return matches!(k.code, KeyCode::Char('c' | 'C')).then_some(Key::Interrupt);
    }
    if k.modifiers
        .intersects(KeyModifiers::ALT | KeyModifiers::SUPER | KeyModifiers::META)
    {
        return None;
    }
    Some(match k.code {
        KeyCode::Up => Key::Up,
        KeyCode::Down => Key::Down,
        KeyCode::Left => Key::Left,
        KeyCode::Right => Key::Right,
        KeyCode::Enter => Key::Enter,
        KeyCode::Esc => Key::Esc,
        KeyCode::Tab => Key::Tab,
        KeyCode::Backspace => Key::Backspace,
        KeyCode::Char(c) => Key::Char(c),
        _ => return None,
    })
}

/// A terminal opv can draw on: a TTY on both ends, not `TERM=dumb`, not asked for text.
pub fn capable() -> bool {
    io::stdin().is_terminal()
        && io::stdout().is_terminal()
        && std::env::var("TERM").map_or(true, |t| t != "dumb")
        && std::env::var_os("OPV_UI_TEXT").is_none()
}

/// `opv ui`: the full-screen view, or (without a capable terminal) the same information as
/// lines, from `opv ready`. Returns the exit code (`ready`'s when the text form ran), so the
/// caller exits and every guard and drop runs (D7).
pub fn run(source: Exe, out: &mut dyn Write) -> Result<i32, Error> {
    if !capable() {
        let why = if std::env::var_os("OPV_UI_TEXT").is_some() {
            "OPV_UI_TEXT is set"
        } else {
            "opv ui draws only in an interactive terminal, and this is not one"
        };
        writeln!(
            out,
            "{why}; here is the same information as text (opv ready):"
        )
        .map_err(crate::app::write_err)?;
        let status = source
            .command(&["ready"])
            .status()
            .map_err(|e| start_failed(e.kind()))?;
        // ready printed its own error and steps; they stay the last word, with its exit
        // code (07.05), returned to main instead of exiting here (D7).
        out.flush().map_err(crate::app::write_err)?;
        return Ok(exit_code(status));
    }
    eprintln!("opv ui: reading the configuration and readiness…");
    let mut app = App::new(Snapshot::gather(&source));
    let mut term = enter()?;
    let result = (|| -> Result<(), Error> {
        loop {
            paint(&mut term, &app)?;
            if !event::poll(Duration::from_millis(250)).map_err(|e| io_err(&e))? {
                continue;
            }
            let Event::Key(k) = event::read().map_err(|e| io_err(&e))? else {
                continue;
            };
            if k.kind != KeyEventKind::Press {
                continue;
            }
            let Some(key) = key_of(k) else { continue };
            match app.handle(key) {
                Effect::None => {}
                Effect::Quit => return Ok(()),
                Effect::Refresh => {
                    busy(&mut term, &mut app, "refreshing…")?;
                    app.refreshed(Snapshot::gather(&source));
                    app.status = "refreshed".into();
                }
                Effect::AdoptPlan { env, from } => {
                    busy(&mut term, &mut app, &format!("reading {from}…"))?;
                    app.status.clear();
                    match fetch::<AdoptDoc>(&source, &["adopt", &env, "--from", &from, "--json"]) {
                        Ok(doc) => app.open_adopt(&env, &from, &doc),
                        Err(failure) => {
                            app.status = format!("opv adopt {env} --from {from}: {failure}")
                        }
                    }
                }
                Effect::LoadHistory(env) => {
                    app.history = Some(fetch::<HistoryDoc>(&source, &["history", &env, "--json"]));
                }
                Effect::LoadAccess => {
                    app.access = Some(fetch::<AccessDoc>(&source, &["access", "--json"]));
                }
                Effect::LoadAccounts => {
                    busy(&mut term, &mut app, "reading accounts…")?;
                    app.status.clear();
                    app.accounts = Some(fetch::<AccountsDoc>(
                        &source,
                        &["account", "list", "--json"],
                    ));
                }
                Effect::Plan { env } => {
                    busy(&mut term, &mut app, &format!("planning a sync of {env}…"))?;
                    app.status.clear();
                    match fetch::<RowsDoc>(&source, &["plan", &env, "--json"]) {
                        Ok(plan) => app.confirm_sync(&env, &plan),
                        Err(failure) => app.status = format!("opv plan {env}: {failure}"),
                    }
                }
                Effect::Run(args) => {
                    leave(&mut term)?;
                    let line = super::app::command_line(&args);
                    println!("\n$ {line}");
                    let words: Vec<&str> = args.iter().map(String::as_str).collect();
                    // The command owns the terminal now: Ctrl-C stops it, not opv ui.
                    signals::set_child_owns_terminal(true);
                    let status = source.command(&words).status();
                    println!("\nPress Enter to return to opv ui.");
                    let _ = io::stdin().read_line(&mut String::new());
                    signals::set_child_owns_terminal(false);
                    term = enter()?;
                    app.status = match status {
                        Ok(s) if s.success() => format!("ran: {line}"),
                        Ok(s) => match s.code() {
                            Some(code) => format!("{line}: exit {code}"),
                            None => format!("{line}: interrupted"),
                        },
                        Err(e) => format!("{line}: could not run ({})", e.kind()),
                    };
                    let done = std::mem::take(&mut app.status);
                    busy(&mut term, &mut app, &format!("{done} · refreshing…"))?;
                    app.refreshed(Snapshot::gather(&source));
                    app.status = done;
                }
            }
        }
    })();
    leave(&mut term)?;
    result.map(|()| 0)
}

type Term = Terminal<CrosstermBackend<io::Stdout>>;

/// Draw the UI. Under `NO_COLOR` crossterm writes each colour change as an SGR reset,
/// which drops the reverse and bold of a selection on the way: draw without colour then.
fn paint(term: &mut Term, app: &App) -> Result<(), Error> {
    let mono = crossterm::style::Colored::ansi_color_disabled_memoized();
    term.draw(|f| {
        super::render::draw(f, app);
        if mono {
            super::render::monochrome(f.buffer_mut());
        }
    })
    .map(|_| ())
    .map_err(|e| io_err(&e))
}

/// Show `what` in the status line and draw now, before something slow (opv reading
/// 1Password), so the screen is never blank or stale while it runs.
fn busy(term: &mut Term, app: &mut App, what: &str) -> Result<(), Error> {
    app.status = what.to_string();
    paint(term, app)
}

/// The terminal stopped working under opv ui (raw mode, drawing or reading a key failed):
/// there is no terminal to draw on.
fn io_err(_: &dyn std::fmt::Display) -> Error {
    Cause::NeedsTerminal {
        why: NoTerminal::NoTty,
    }
    .into()
}

/// This opv binary could not be started as a child (C11).
fn start_failed(io: io::ErrorKind) -> Error {
    Cause::ChildStartFailed {
        program: "opv".into(),
        workdir: None,
        io: io.into(),
        remote: None,
    }
    .into()
}

/// The exit code a child ended with, passed on unchanged; a signal as `128 + signal`.
pub(crate) fn exit_code(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return 128 + sig;
        }
    }
    1
}

/// Put the terminal back as the shell expects it (best effort) when opv ends on a signal or
/// a panic. It writes to the terminal device, not to stdout: `main` holds stdout's lock for
/// the whole command, so the signal thread would wait for it forever.
fn restore() {
    let _ = terminal::disable_raw_mode();
    #[cfg(windows)]
    const TERMINAL: &str = "CONOUT$";
    #[cfg(not(windows))]
    const TERMINAL: &str = "/dev/tty";
    if let Ok(mut tty) = std::fs::OpenOptions::new().write(true).open(TERMINAL) {
        let _ = crossterm::execute!(tty, terminal::LeaveAlternateScreen, crossterm::cursor::Show);
    }
}

fn enter() -> Result<Term, Error> {
    static HOOK: std::sync::Once = std::sync::Once::new();
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore();
            previous(info);
        }));
    });
    signals::set_on_exit(Some(restore));
    terminal::enable_raw_mode().map_err(|e| io_err(&e))?;
    crossterm::execute!(io::stdout(), terminal::EnterAlternateScreen).map_err(|e| io_err(&e))?;
    Terminal::new(CrosstermBackend::new(io::stdout())).map_err(|e| io_err(&e))
}

fn leave(term: &mut Term) -> Result<(), Error> {
    signals::set_on_exit(None);
    terminal::disable_raw_mode().map_err(|e| io_err(&e))?;
    crossterm::execute!(term.backend_mut(), terminal::LeaveAlternateScreen)
        .map_err(|e| io_err(&e))?;
    term.show_cursor().map_err(|e| io_err(&e))
}

#[cfg(test)]
#[path = "run_tests.rs"]
mod tests;
