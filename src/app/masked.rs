//! Masked secret entry (0.9.0): the one place a person types or pastes a secret into opv
//! (`opv setup`). A fully hidden prompt gives no sign that a paste landed, so the prompt
//! shows [`MASK`] as soon as anything is entered and nothing while the field is empty. The
//! mask has a fixed width: it never grows with the input, so neither the screen nor a
//! screen recording reveals the secret's length.
//!
//! [`Masked`] is the editing state machine (tested without a terminal); [`prompt`] drives it
//! from the terminal in raw mode with bracketed paste. The value lives only in a
//! [`Zeroizing`] buffer and is handed back as a [`SecretValue`]; it is never echoed,
//! logged or put in an error.

use zeroize::Zeroizing;

use crate::domain::SecretValue;
use crate::error::Error;

/// What the prompt shows once anything is entered: fixed, whatever the length.
pub const MASK: &str = "********";

/// One edit from the terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Key {
    Char(char),
    /// A bracketed paste: the whole pasted text at once.
    Paste(String),
    Backspace,
    /// Ctrl-U: clear the field.
    Clear,
    Enter,
    /// Ctrl-C or Ctrl-D on an empty field: stop.
    Cancel,
}

/// Where the edit leaves the prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Editing,
    Done,
    Cancelled,
}

/// The value being entered.
#[derive(Default)]
pub struct Masked {
    value: Zeroizing<String>,
}

impl Masked {
    /// Apply one edit. A pasted trailing newline ends nothing and is not kept (terminals add
    /// one to a pasted line).
    pub fn apply(&mut self, key: Key) -> Step {
        match key {
            Key::Char(c) if !c.is_control() => self.value.push(c),
            Key::Char(_) => {}
            Key::Paste(text) => {
                let text = Zeroizing::new(text);
                self.value
                    .extend(text.chars().filter(|c| !matches!(c, '\r' | '\n')));
            }
            Key::Backspace => {
                self.value.pop();
            }
            Key::Clear => self.value.clear(),
            Key::Enter => return Step::Done,
            Key::Cancel => return Step::Cancelled,
        }
        Step::Editing
    }

    /// What the field shows: [`MASK`] when anything is entered, else nothing.
    pub fn display(&self) -> &'static str {
        if self.value.is_empty() { "" } else { MASK }
    }

    /// The entered value.
    pub fn into_secret(self) -> SecretValue {
        SecretValue::new(self.value.as_str().to_string())
    }
}

/// Ask for a secret at `label` in the person's terminal, masked. `Ok(None)` when they stop
/// (Ctrl-C); an empty value means "skip". Falls back to a fully hidden prompt where the
/// terminal cannot be driven (a build without the terminal UI).
pub fn prompt(label: &str) -> Result<Option<SecretValue>, Error> {
    #[cfg(feature = "ui")]
    {
        terminal::run(label)
    }
    #[cfg(not(feature = "ui"))]
    {
        let value =
            rpassword::prompt_password(format!("{label} (hidden): ")).map_err(|_| no_terminal())?;
        Ok(Some(SecretValue::new(value)))
    }
}

/// The prompt could not drive or read the terminal (R60): the value needs a person at their
/// own interactive terminal (or filled privately in 1Password).
fn no_terminal() -> Error {
    crate::cause::Cause::NeedsTerminal {
        why: crate::cause::NoTerminal::NoTty,
    }
    .into()
}

#[cfg(feature = "ui")]
mod terminal {
    use std::io::Write;

    use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
    use crossterm::{cursor, execute, terminal};

    use super::{Key, Masked, Step};
    use crate::domain::SecretValue;
    use crate::error::Error;

    fn io_err(_: std::io::Error) -> Error {
        super::no_terminal()
    }

    /// Raw mode and bracketed paste for the prompt's lifetime, restored on every exit.
    struct Raw;

    impl Raw {
        fn on() -> Result<Self, Error> {
            terminal::enable_raw_mode().map_err(io_err)?;
            let _ = execute!(std::io::stderr(), event::EnableBracketedPaste);
            Ok(Raw)
        }
    }

    impl Drop for Raw {
        fn drop(&mut self) {
            let _ = execute!(std::io::stderr(), event::DisableBracketedPaste);
            let _ = terminal::disable_raw_mode();
        }
    }

    fn key_of(ev: Event) -> Option<Key> {
        match ev {
            Event::Paste(text) => Some(Key::Paste(text)),
            Event::Key(KeyEvent {
                code,
                modifiers,
                kind: KeyEventKind::Press | KeyEventKind::Repeat,
                ..
            }) => {
                let ctrl = modifiers.contains(KeyModifiers::CONTROL);
                match code {
                    KeyCode::Enter => Some(Key::Enter),
                    KeyCode::Backspace => Some(Key::Backspace),
                    KeyCode::Char('c') | KeyCode::Char('d') if ctrl => Some(Key::Cancel),
                    KeyCode::Char('u') if ctrl => Some(Key::Clear),
                    KeyCode::Char(c) if !ctrl => Some(Key::Char(c)),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    pub(super) fn run(label: &str) -> Result<Option<SecretValue>, Error> {
        let prompt = format!("{label} (masked; Enter to skip): ");
        let mut err = std::io::stderr();
        let mut field = Masked::default();
        let raw = Raw::on()?;
        let draw = |err: &mut std::io::Stderr, shown: &str| {
            let _ = execute!(
                err,
                cursor::MoveToColumn(0),
                terminal::Clear(terminal::ClearType::CurrentLine)
            );
            let _ = write!(err, "{prompt}{shown}");
            let _ = err.flush();
        };
        draw(&mut err, "");
        let step = loop {
            let Some(key) = key_of(event::read().map_err(io_err)?) else {
                continue;
            };
            // Ctrl-D on an empty field stops; with input it is ignored.
            let step = field.apply(key);
            if step != Step::Editing {
                break step;
            }
            draw(&mut err, field.display());
        };
        drop(raw);
        let _ = writeln!(err);
        Ok(match step {
            Step::Cancelled => None,
            _ => Some(field.into_secret()),
        })
    }
}

#[cfg(test)]
#[path = "masked_tests.rs"]
mod tests;
