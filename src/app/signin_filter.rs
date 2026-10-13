//! `op signin` and `op account add` keep 1Password's own prompts on the terminal, but their
//! error lines are opv's to explain (FR-50, #79).
//!
//! [`Filter`] sits between the child's stderr and the terminal. Bytes pass through as they
//! arrive, so a prompt without a newline (`Enter the password for … at …: `) shows at once.
//! Only a possible start of `[ERROR] ` is held back (at most 8 bytes), and an error line,
//! which op prints after its prompt on the same line, is captured instead of printed: it
//! carries op's own directions (`Please run 'op signin --help'`), which are not opv's.
//! [`classify`] turns the captured message into a [`Failure`] with one recovery step.

use std::io::{self, Read, Write};

use crate::error::{Code, Error};

/// op's error prefix: `[ERROR] YYYY/MM/DD HH:MM:SS <message>`.
const ERROR_TAG: &[u8] = b"[ERROR] ";
/// Longest error message kept, in bytes; the rest is dropped.
const MAX_MESSAGE: usize = 4096;

/// A streaming filter of op's stderr: forwards everything except error lines, which it
/// keeps for [`classify`].
#[derive(Default)]
pub struct Filter {
    /// Bytes that may be the start of [`ERROR_TAG`], not yet forwarded.
    pending: Vec<u8>,
    /// Inside an error line: its bytes so far.
    error: Option<Vec<u8>>,
    /// Every completed error message, timestamp removed, oldest first.
    messages: Vec<String>,
}

impl Filter {
    /// Feed `chunk`; forward what is safe to `out` and flush it, so a prompt shows at once.
    pub fn feed(&mut self, chunk: &[u8], out: &mut dyn Write) -> io::Result<()> {
        let mut forward = Vec::with_capacity(chunk.len());
        for &b in chunk {
            if let Some(err) = &mut self.error {
                if b == b'\n' {
                    let done = self.error.take().unwrap_or_default();
                    self.messages.push(message_of(&done));
                } else if err.len() < MAX_MESSAGE {
                    err.push(b);
                }
                continue;
            }
            self.pending.push(b);
            if ERROR_TAG.starts_with(&self.pending) {
                if self.pending.len() == ERROR_TAG.len() {
                    self.pending.clear();
                    self.error = Some(Vec::new());
                }
                continue;
            }
            // Not the tag: release what was held, but a `[` may start it again.
            let last = self.pending.pop().unwrap_or_default();
            forward.append(&mut self.pending);
            if last == ERROR_TAG[0] {
                self.pending.push(last);
            } else {
                forward.push(last);
            }
        }
        out.write_all(&forward)?;
        out.flush()
    }

    /// End of stream: forward any held bytes and keep an unfinished error line.
    pub fn finish(mut self, out: &mut dyn Write) -> io::Result<Vec<String>> {
        if let Some(err) = self.error.take() {
            self.messages.push(message_of(&err));
        }
        out.write_all(&self.pending)?;
        out.flush()?;
        Ok(self.messages)
    }

    /// Copy `from` (a child's stderr) through the filter to `out` until it closes.
    pub fn pump(from: &mut dyn Read, out: &mut dyn Write) -> io::Result<Vec<String>> {
        let mut filter = Filter::default();
        let mut buf = [0u8; 1024];
        loop {
            match from.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => filter.feed(&buf[..n], out)?,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        filter.finish(out)
    }
}

/// The message of one error line: its text after op's `YYYY/MM/DD HH:MM:SS ` timestamp.
fn message_of(line: &[u8]) -> String {
    let text = String::from_utf8_lossy(line);
    let text = text.trim_end_matches('\r').trim();
    let mut parts = text.splitn(3, ' ');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(d), Some(t), Some(rest)) if is_stamp(d, '/') && is_stamp(t, ':') => rest.to_string(),
        _ => text.to_string(),
    }
}

/// `2026/10/13` or `03:21:24`: three groups of digits joined by `sep`.
fn is_stamp(s: &str, sep: char) -> bool {
    let groups: Vec<&str> = s.split(sep).collect();
    groups.len() == 3
        && groups
            .iter()
            .all(|g| !g.is_empty() && g.bytes().all(|b| b.is_ascii_digit()))
}

/// Why a sign-in or account add failed, in opv's words (FR-50).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The account is not added to this CLI.
    AccountNotRegistered,
    /// No session, or it ended.
    NotSignedIn,
    /// The 1Password app is locked, closed, or its CLI integration is off.
    DesktopAppUnavailable,
    /// 1Password refused what was typed.
    CredentialRejected,
    /// The prompt was cancelled (Ctrl-C, end of input) or a second factor failed.
    Cancelled,
    /// 1Password could not be reached.
    ProviderUnavailable,
    /// There is no terminal for op's prompt.
    NoTerminal,
    /// Anything else: never guessed to be a wrong password.
    Unexpected,
}

/// Classify op's error messages and exit status. Only clear signals are mapped; everything
/// else is [`Failure::Unexpected`].
pub fn classify(messages: &[String], status: Option<i32>) -> Failure {
    let all = messages.join("\n").to_ascii_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| all.contains(n));
    if matches!(status, Some(130 | 143)) || has(&["canceled", "cancelled", "interrupt"]) {
        Failure::Cancelled
    } else if has(&[
        "inappropriate ioctl",
        "not a terminal",
        "missing op_secret_key",
    ]) {
        Failure::NoTerminal
    } else if has(&[
        "no accounts found matching",
        "no account found for",
        "account not found",
    ]) {
        Failure::AccountNotRegistered
    } else if has(&["desktop app", "1password app", "app integration", "locked"]) {
        Failure::DesktopAppUnavailable
    } else if has(&["(401)", "unauthorized", "invalid credentials", "incorrect"]) {
        Failure::CredentialRejected
    } else if has(&[
        "dial tcp",
        "no such host",
        "connection refused",
        "connection reset",
        "timeout",
        "(502)",
        "(503)",
        "(504)",
    ]) {
        Failure::ProviderUnavailable
    } else if has(&[
        "no active session",
        "not currently signed in",
        "session expired",
    ]) {
        Failure::NotSignedIn
    } else {
        Failure::Unexpected
    }
}

impl Failure {
    /// The stable error code (FR-50).
    pub fn code(self) -> Code {
        match self {
            Failure::AccountNotRegistered => Code::AccountNotRegistered,
            Failure::NotSignedIn => Code::OpNotSignedIn,
            Failure::DesktopAppUnavailable => Code::DesktopAppUnavailable,
            Failure::CredentialRejected => Code::CredentialRejected,
            Failure::Cancelled => Code::SignInCancelled,
            Failure::ProviderUnavailable => Code::ProviderUnavailable,
            Failure::NoTerminal => Code::TerminalRequired,
            Failure::Unexpected => Code::OpUnexpected,
        }
    }

    /// The error for `what` (`signing in`, `adding the account`) to `account` (as the person
    /// named it, or `None`) during `opv <command>`; one recovery step, naming the account
    /// whenever it is known.
    pub fn error(self, what: &str, account: Option<&str>, command: &str) -> Error {
        let who = account.map_or(String::new(), |a| format!(" to {a}"));
        let again = match account {
            Some(a) => format!("opv login --account {a}"),
            None => "opv login".to_string(),
        };
        let (text, step, next) = match self {
            Failure::AccountNotRegistered => (
                format!(
                    "1Password could not find the account{who}: it is not added to this 1Password CLI"
                ),
                "add it here; you type the sign-in address, Secret Key and password only at 1Password's prompt",
                match account {
                    Some(a) => format!("opv login --add --account {a}"),
                    None => "opv login --add".to_string(),
                },
            ),
            Failure::NotSignedIn => (
                format!("1Password did not start a session{who}"),
                "sign in again at 1Password's prompt",
                again,
            ),
            Failure::DesktopAppUnavailable => (
                format!("the 1Password app did not answer while {what}{who}"),
                "unlock the 1Password app and turn on Settings > Developer > Integrate with 1Password CLI, then try again",
                again,
            ),
            Failure::CredentialRejected => (
                format!("1Password did not accept what was typed while {what}{who}"),
                "type the password (and Secret Key when asked) again at 1Password's prompt",
                again,
            ),
            Failure::Cancelled => (
                format!("{what}{who} was cancelled"),
                "start again when ready",
                again,
            ),
            Failure::ProviderUnavailable => (
                format!("1Password could not be reached while {what}{who}"),
                "check the network or https://status.1password.com, then try again; nothing was changed",
                again,
            ),
            Failure::NoTerminal => (
                format!("1Password needs your own terminal for its prompt while {what}{who}"),
                "run this in your own interactive terminal",
                again,
            ),
            Failure::Unexpected => (
                format!("{what}{who} did not complete; 1Password gave no reason opv recognises"),
                "check the CLI with opv doctor, then try again",
                "opv doctor".to_string(),
            ),
        };
        let text = format!("{text} (during opv {command}). Nothing was printed from the session.");
        let e = match self {
            Failure::ProviderUnavailable => Error::Unknown(text.into()),
            Failure::NoTerminal => Error::Policy(text.into()),
            _ => Error::Auth(text.into()),
        };
        e.with_code(self.code()).with_do(step).with_next(next)
    }
}

#[cfg(test)]
#[path = "signin_filter_tests.rs"]
mod tests;
