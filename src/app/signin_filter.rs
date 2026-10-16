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

use crate::cause::{
    AccountId, AccountRef, Cause, DiagnoseContext, ExitClass, NoTerminal, SessionState, System,
    Upstream,
};
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
        // macOS or Windows with the app integration off: op sees no account (audit 04.15).
        "no accounts configured",
    ]) {
        Failure::AccountNotRegistered
    } else if has(&[
        "desktop app",
        "1password app",
        "app integration",
        "locked",
        // The app's approval prompt left unanswered, before any network reading (04.18).
        "authorization timeout",
        "authorization prompt",
        "approval",
    ]) {
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

    /// The cataloged cause of this failure for `account` (as the person named it, or
    /// `None`). `None` for a failure the catalog cannot name without the failed call's
    /// observation (`op signin` runs on the terminal, outside the runner): 1Password not
    /// reached, and a reason opv does not recognise.
    pub fn cause(self, account: Option<&str>) -> Option<Cause> {
        let signed_out = |state| Cause::NotSignedIn {
            system: System::OnePassword,
            account: account.map(AccountId::new),
            state,
        };
        Some(match self {
            // Audit 04.02: only an email follows `opv login --add --account`; an account ID
            // is added at op's prompt (or in the app where the app holds the accounts).
            Failure::AccountNotRegistered => Cause::AccountNotOnMachine {
                account: account.map_or(AccountRef::Unnamed, super::account::account_ref),
                selected_by: account.map_or(
                    crate::cause::AccountSource::OpDefault,
                    super::account::source_of,
                ),
                in_app: super::account::app_holds_accounts_here(),
            },
            Failure::DesktopAppUnavailable => signed_out(SessionState::AppLocked),
            // A rejected password, a cancelled prompt or no session: not signed in, and
            // signing in again is the step; op's own words are the evidence.
            Failure::NotSignedIn | Failure::CredentialRejected | Failure::Cancelled => {
                signed_out(SessionState::SignedOut)
            }
            Failure::NoTerminal => Cause::NeedsTerminal {
                why: if crate::host::Host::detect().ci {
                    NoTerminal::Ci
                } else {
                    NoTerminal::NoTty
                },
            },
            Failure::ProviderUnavailable | Failure::Unexpected => return None,
        })
    }

    /// The error for `what` (`signing in`, `adding the account`) to `account` (as the person
    /// named it, or `None`) during `opv <command>`, when op's own lines were not kept: the
    /// same as [`Failure::error_said`] with none.
    pub fn error(self, what: &str, account: Option<&str>, command: &str) -> Error {
        self.error_said(what, account, command, &[], None)
    }

    /// The error for this failure with op's own error lines (`messages`, from [`Filter`])
    /// and exit `status` (128 + n for signal n) as the scrubbed evidence (#142: opv's words
    /// alone can hide the cause). A failure the classifier cannot name (1Password not
    /// reached, a reason opv does not recognise) is recorded as the streamed `op` call it
    /// was and diagnosed from op's own reply, like every failed `op` call (C9, 04.02).
    pub fn error_said(
        self,
        what: &str,
        account: Option<&str>,
        command: &str,
        messages: &[String],
        status: Option<i32>,
    ) -> Error {
        let _ = command;
        let said: Vec<String> = messages
            .iter()
            .filter(|m| !m.trim().is_empty())
            .map(|m| crate::scrub::scrub(m.lines().next().unwrap_or_default()))
            .collect();
        match self.cause(account) {
            Some(cause) if !said.is_empty() => Error::with_evidence(
                cause,
                Upstream {
                    source: System::OnePassword,
                    tool: "1Password CLI".into(),
                    version: None,
                    exit: match status {
                        Some(code) => ExitClass::Code { code },
                        None => ExitClass::Signal { signal: 0 },
                    },
                    said,
                    removed_advice: false,
                    untrusted: true,
                },
            ),
            Some(cause) => cause.into(),
            None => diagnosed(what, account, messages, status),
        }
    }
}

/// The prompted `op` call (`op signin`, `op account add`) that ended as `status` after
/// printing `messages`, recorded with the runner (it ran on the terminal, outside it) and
/// diagnosed by the 1Password strategy from op's own reply, with that reply as evidence.
fn diagnosed(what: &str, account: Option<&str>, messages: &[String], status: Option<i32>) -> Error {
    let args: &[&str] = if what.contains("account") {
        &["account", "add"]
    } else {
        &["signin"]
    };
    let exit = match status {
        Some(code) if code > 128 => ExitClass::Signal { signal: code - 128 },
        Some(code) => ExitClass::Code { code },
        None => ExitClass::Signal { signal: 0 },
    };
    crate::runner::record_streamed(
        crate::adapters::onepassword::OP,
        args,
        exit,
        messages.join("\n").as_bytes(),
    );
    let Some(failure) = crate::runner::take_failure() else {
        return Cause::Bug {
            site: "signin_filter: a recorded op prompt left no failure",
        }
        .into();
    };
    let ctx = DiagnoseContext {
        account: account
            .filter(|a| crate::config::is_id(a))
            .map(AccountId::new),
        ..DiagnoseContext::default()
    };
    let cause = crate::adapters::onepassword_diagnose::diagnose(
        failure.seen.clone(),
        failure.stderr(),
        &ctx,
    );
    let said = failure.excerpt.map(|x| x.lines).unwrap_or_default();
    if said.is_empty() {
        return cause.into();
    }
    Error::with_evidence(
        cause,
        Upstream {
            source: System::OnePassword,
            tool: "1Password CLI".into(),
            version: None,
            exit,
            said,
            removed_advice: false,
            untrusted: true,
        },
    )
}

#[cfg(test)]
#[path = "signin_filter_tests.rs"]
mod tests;
