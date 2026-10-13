//! The terminal loop of `opv ui` (#82): reads the documents from this opv binary, draws, and
//! handles keys. An action leaves the full-screen view, runs the `opv` command in the
//! person's terminal (so 1Password's prompts and opv's output appear exactly as on the CLI),
//! waits for Enter, and comes back refreshed.

use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use serde_json::Value;

use super::app::{App, Effect, Key};
use super::model::{Snapshot, Source};
use crate::error::Error;

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
    fn json(&self, args: &[&str]) -> Result<Value, String> {
        let out = self
            .command(args)
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map_err(|e| e.kind().to_string())?;
        serde_json::from_slice(&out.stdout).map_err(|_| "no JSON document".to_string())
    }
}

fn key_of(code: KeyCode) -> Option<Key> {
    Some(match code {
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
/// lines, from `opv ready`.
pub fn run(source: Exe, out: &mut dyn Write) -> Result<(), Error> {
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
        let status = source.command(&["ready"]).status().map_err(|e| {
            Error::Dependency(format!("cannot run opv ready ({})", e.kind()).into())
        })?;
        return if status.success() {
            Ok(())
        } else {
            Err(Error::findings(1, "opv ready"))
        };
    }
    let mut app = App::new(Snapshot::gather(&source));
    let mut term = enter()?;
    let result = (|| -> Result<(), Error> {
        loop {
            term.draw(|f| super::render::draw(f, &app))
                .map_err(|e| io_err(&e))?;
            if !event::poll(Duration::from_millis(250)).map_err(|e| io_err(&e))? {
                continue;
            }
            let Event::Key(k) = event::read().map_err(|e| io_err(&e))? else {
                continue;
            };
            if k.kind != KeyEventKind::Press {
                continue;
            }
            let Some(key) = key_of(k.code) else { continue };
            match app.handle(key) {
                Effect::None => {}
                Effect::Quit => return Ok(()),
                Effect::Refresh => {
                    app.status = "refreshing…".into();
                    term.draw(|f| super::render::draw(f, &app))
                        .map_err(|e| io_err(&e))?;
                    app.refreshed(Snapshot::gather(&source));
                    app.status = "refreshed".into();
                }
                Effect::LoadAccounts => {
                    app.accounts = source.json(&["account", "list", "--json"]).ok();
                }
                Effect::Plan { env } => match source.json(&["plan", &env, "--json"]) {
                    Ok(plan) => app.confirm_sync(&env, &plan),
                    Err(why) => app.status = format!("opv plan {env}: {why}"),
                },
                Effect::Run(args) => {
                    leave(&mut term)?;
                    let line = format!("opv {}", args.join(" "));
                    println!("\n$ {line}");
                    let words: Vec<&str> = args.iter().map(String::as_str).collect();
                    let status = source.command(&words).status();
                    println!("\nPress Enter to return to opv ui.");
                    let _ = io::stdin().read_line(&mut String::new());
                    term = enter()?;
                    app.status = match status {
                        Ok(s) if s.success() => format!("ran: {line}"),
                        Ok(s) => format!("{line}: exit {}", s.code().unwrap_or(1)),
                        Err(e) => format!("{line}: could not run ({})", e.kind()),
                    };
                    app.refreshed(Snapshot::gather(&source));
                }
            }
        }
    })();
    leave(&mut term)?;
    result
}

type Term = Terminal<CrosstermBackend<io::Stdout>>;

fn io_err(e: &dyn std::fmt::Display) -> Error {
    Error::Dependency(format!("terminal: {e}").into())
}

fn enter() -> Result<Term, Error> {
    terminal::enable_raw_mode().map_err(|e| io_err(&e))?;
    crossterm::execute!(io::stdout(), terminal::EnterAlternateScreen).map_err(|e| io_err(&e))?;
    Terminal::new(CrosstermBackend::new(io::stdout())).map_err(|e| io_err(&e))
}

fn leave(term: &mut Term) -> Result<(), Error> {
    terminal::disable_raw_mode().map_err(|e| io_err(&e))?;
    crossterm::execute!(term.backend_mut(), terminal::LeaveAlternateScreen)
        .map_err(|e| io_err(&e))?;
    term.show_cursor().map_err(|e| io_err(&e))
}
