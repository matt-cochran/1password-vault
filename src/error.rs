//! Typed errors with stable exit codes (FR-10, §6.6), each carrying an optional next step
//! (NR-19).
//!
//! Messages may name keys, references and rules but never secret values (SR-1, FR-15).
//! Variants therefore carry a [`Msg`] built by callers from plain strings, never a
//! `SecretValue`.
//!
//! Every non-zero exit ends with exactly one `Next: <step>` line, the last line on stderr
//! ([`report`]). The step is the error's own ([`Error::next_step`]) or, when the error has
//! none, the category's default chosen by `main` ([`Error::default_next`]).

use std::fmt;

/// Exit code for success, for completeness alongside [`Error::exit_code`].
pub const EXIT_OK: i32 = 0;

/// An error message and the runnable step that fixes it (NR-19). Names only, never a value.
///
/// Built from a `String` or `&str`. By convention a message may end with a line
/// `  next: <step>` (any case); that line becomes the step and is not part of the text, so
/// the step is printed once, last, by [`report`].
#[derive(Clone, PartialEq, Eq)]
pub struct Msg {
    text: String,
    next: Option<String>,
}

impl Msg {
    /// The message without its next step.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The next step, when the message names one.
    pub fn next(&self) -> Option<&str> {
        self.next.as_deref()
    }

    /// True when the text or the next step contains `pat`.
    pub fn mentions(&self, pat: &str) -> bool {
        self.text.contains(pat) || self.next.as_deref().is_some_and(|n| n.contains(pat))
    }

    /// The same message with `f` applied to its text; the next step is kept.
    pub fn map_text(self, f: impl FnOnce(String) -> String) -> Msg {
        Msg {
            text: f(self.text),
            next: self.next,
        }
    }
}

/// The marker of a trailing next-step line inside a message string.
const NEXT_MARK: &str = "\n  next: ";

impl From<String> for Msg {
    fn from(s: String) -> Self {
        let lower = s.to_ascii_lowercase();
        match lower.rfind(NEXT_MARK) {
            Some(at) => {
                let step = s[at + NEXT_MARK.len()..]
                    .lines()
                    .map(str::trim)
                    .collect::<Vec<_>>()
                    .join(" ");
                Msg {
                    text: s[..at].to_string(),
                    next: (!step.is_empty()).then_some(step),
                }
            }
            None => Msg {
                text: s,
                next: None,
            },
        }
    }
}

impl From<&str> for Msg {
    fn from(s: &str) -> Self {
        Msg::from(s.to_string())
    }
}

impl std::ops::Deref for Msg {
    type Target = str;
    fn deref(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for Msg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl fmt::Debug for Msg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.next {
            Some(n) => write!(f, "{:?} next {:?}", self.text, n),
            None => write!(f, "{:?}", self.text),
        }
    }
}

impl PartialEq<str> for Msg {
    fn eq(&self, other: &str) -> bool {
        self.text == other
    }
}

impl PartialEq<&str> for Msg {
    fn eq(&self, other: &&str) -> bool {
        self.text == *other
    }
}

impl PartialEq<String> for Msg {
    fn eq(&self, other: &String) -> bool {
        &self.text == other
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(Msg),
    #[error("dependency error: {0}")]
    Dependency(Msg),
    #[error("authentication error: {0}")]
    Auth(Msg),
    #[error("source error: {0}")]
    Source(Msg),
    #[error("target error: {0}")]
    Target(Msg),
    #[error("policy denied: {0}")]
    Policy(Msg),
    /// `status` / `plan` / `check` found `n` blocking keys; the message is the count
    /// (`1 finding`, `2 findings`) and its next step the command that shows the fix.
    #[error("{1}")]
    Findings(usize, Msg),
    /// An external change may or may not have been applied; nothing is known to be broken;
    /// re-running the same command is safe (NR-2).
    #[error("outcome unknown: {0}")]
    Unknown(Msg),
}

/// Every category, in exit-code order (for tests that cover each one).
pub const CATEGORIES: [&str; 8] = [
    "config",
    "dependency",
    "source",
    "target",
    "policy",
    "auth",
    "findings",
    "unknown",
];

impl Error {
    /// Stable process exit code per category. A public contract from v0.1.0 on.
    ///
    /// | code | category |
    /// |---|---|
    /// | 0 | success |
    /// | 2 | configuration, and command-line usage (clap's own code) |
    /// | 3 | dependency (`op` or the target CLI missing or unusable) |
    /// | 4 | source (1Password) |
    /// | 5 | target (Fly, Azure, Kubernetes) |
    /// | 6 | policy (refused: blocking keys, refused values, denied destructive operation) |
    /// | 7 | authentication (1Password or the target) |
    /// | 8 | findings (`status` / `plan` / `check` found blocking keys) |
    /// | 9 | outcome unknown (a change may or may not have been applied; safe to re-run) |
    ///
    /// 130 / 143: interrupted by SIGINT / SIGTERM (Unix).
    ///
    /// `run` exits with the child's own code instead (FR-4); see its help.
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::Config(_) => 2,
            Error::Dependency(_) => 3,
            Error::Source(_) => 4,
            Error::Target(_) => 5,
            Error::Policy(_) => 6,
            Error::Auth(_) => 7,
            Error::Findings(..) => 8,
            Error::Unknown(_) => 9,
        }
    }

    /// `n` blocking keys found; `next` is the command that shows or fixes them.
    pub fn findings(n: usize, next: impl Into<String>) -> Error {
        let text = if n == 1 {
            "1 finding".to_string()
        } else {
            format!("{n} findings")
        };
        Error::Findings(
            n,
            Msg {
                text,
                next: Some(next.into()),
            },
        )
    }

    fn msg(&self) -> &Msg {
        match self {
            Error::Config(m)
            | Error::Dependency(m)
            | Error::Auth(m)
            | Error::Source(m)
            | Error::Target(m)
            | Error::Policy(m)
            | Error::Findings(_, m)
            | Error::Unknown(m) => m,
        }
    }

    fn msg_mut(&mut self) -> &mut Msg {
        match self {
            Error::Config(m)
            | Error::Dependency(m)
            | Error::Auth(m)
            | Error::Source(m)
            | Error::Target(m)
            | Error::Policy(m)
            | Error::Findings(_, m)
            | Error::Unknown(m) => m,
        }
    }

    /// The runnable step that fixes this error, when it names one (NR-19).
    pub fn next_step(&self) -> Option<&str> {
        self.msg().next()
    }

    /// True when the message or its next step contains `pat`.
    pub fn mentions(&self, pat: &str) -> bool {
        self.msg().mentions(pat)
    }

    /// The message without category prefix or next step.
    pub fn text(&self) -> &str {
        self.msg().text()
    }

    /// This error with `next` as its step (replacing any it had).
    pub fn with_next(mut self, next: impl Into<String>) -> Error {
        self.msg_mut().next = Some(next.into());
        self
    }

    /// This error with `next` as its step only when it has none yet.
    pub fn or_next(self, next: impl FnOnce() -> String) -> Error {
        if self.next_step().is_some() {
            self
        } else {
            self.with_next(next())
        }
    }

    /// The same category and next step with `f` applied to the text.
    pub fn map_text(mut self, f: impl FnOnce(String) -> String) -> Error {
        let m = std::mem::replace(self.msg_mut(), Msg::from(String::new()));
        *self.msg_mut() = m.map_text(f);
        self
    }

    /// The category's step for an error that names none. `rerun` is the command that was
    /// run, for the categories where running it again is the fix (outcome unknown). A
    /// dependency or sign-in error already prints its install or sign-in command on its
    /// first indented line (FR-26); that line is the step.
    pub fn default_next(&self, rerun: &str) -> String {
        match self {
            Error::Unknown(_) => format!("{rerun} (safe to re-run)"),
            Error::Findings(..) | Error::Policy(_) => format!("fix the keys above, then {rerun}"),
            Error::Dependency(m) | Error::Auth(m) => m
                .text()
                .lines()
                .skip(1)
                .find_map(|l| l.strip_prefix("  "))
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map_or_else(|| "opv doctor".to_string(), str::to_string),
            _ => "opv doctor".to_string(),
        }
    }

    /// The category name, as in [`CATEGORIES`].
    pub fn category(&self) -> &'static str {
        match self {
            Error::Config(_) => "config",
            Error::Dependency(_) => "dependency",
            Error::Source(_) => "source",
            Error::Target(_) => "target",
            Error::Policy(_) => "policy",
            Error::Auth(_) => "auth",
            Error::Findings(..) => "findings",
            Error::Unknown(_) => "unknown",
        }
    }
}

/// What opv prints on stderr for `e` (NR-19, SR-1): `opv: <error>`, then exactly one
/// `Next: <step>` line, always last. The step is the error's own or `fallback`. Any later
/// addition (a scrubbed child-stderr excerpt) goes between the two, never after `Next:`.
pub fn report(e: &Error, fallback: &str) -> String {
    let mut out = format!("opv: {e}\n");
    out.push_str(&next_line(e.next_step().unwrap_or(fallback)));
    out
}

/// The one `Next:` line, newline-terminated; a multi-line step is joined onto one line.
pub fn next_line(step: &str) -> String {
    let step = step.lines().map(str::trim).collect::<Vec<_>>().join(" ");
    format!("Next: {step}\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn every_category() -> Vec<Error> {
        let s = || Msg::from("x");
        vec![
            Error::Config(s()),
            Error::Dependency(s()),
            Error::Source(s()),
            Error::Target(s()),
            Error::Policy(s()),
            Error::Auth(s()),
            Error::findings(3, "opv status prod"),
            Error::Unknown(s()),
        ]
    }

    #[test]
    fn exit_codes_are_stable() {
        let codes: Vec<i32> = every_category().iter().map(Error::exit_code).collect();
        assert_eq!(codes, vec![2, 3, 4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn every_category_is_listed() {
        let names: Vec<&str> = every_category().iter().map(Error::category).collect();
        assert_eq!(names, CATEGORIES.to_vec());
    }

    /// NR-19: every category, with or without its own step, reports exactly one `Next:`
    /// line, and it is the last line.
    #[test]
    fn every_category_reports_one_next_line_last() {
        let mut bad = Vec::new();
        for e in every_category().into_iter().chain(
            every_category()
                .into_iter()
                .map(|e| e.with_next("opv doctor")),
        ) {
            let text = report(&e, &e.default_next("opv status prod"));
            let lines: Vec<&str> = text.lines().collect();
            let nexts = lines.iter().filter(|l| l.starts_with("Next: ")).count();
            if nexts != 1 || !lines.last().is_some_and(|l| l.starts_with("Next: ")) {
                bad.push(text);
            }
        }
        assert!(bad.is_empty(), "{bad:?}");
    }

    #[test]
    fn a_trailing_next_line_becomes_the_step() {
        let m = Msg::from("refused\n  next: opv explain api/KEY --env prod");
        assert_eq!(m.next(), Some("opv explain api/KEY --env prod"));
    }

    #[test]
    fn a_trailing_next_line_leaves_the_text() {
        let m = Msg::from("refused\n  Next: opv doctor");
        assert_eq!(m.text(), "refused");
    }

    #[test]
    fn report_never_repeats_an_embedded_next_line() {
        let e = Error::Target("failed\n  next: az login".into());
        assert_eq!(
            report(&e, "opv doctor"),
            "opv: target error: failed\nNext: az login\n"
        );
    }

    #[test]
    fn report_uses_the_fallback_without_a_step() {
        let e = Error::Source("x".into());
        assert_eq!(
            report(&e, "opv doctor"),
            "opv: source error: x\nNext: opv doctor\n"
        );
    }

    #[test]
    fn map_text_keeps_the_step() {
        let e = Error::Auth("signed out\n  next: op signin".into()).map_text(|t| t + "\n  more");
        assert_eq!(e.next_step(), Some("op signin"));
    }

    #[test]
    fn findings_name_their_count() {
        assert_eq!(Error::findings(1, "x").to_string(), "1 finding");
    }

    #[test]
    fn unknown_error_exits_9() {
        assert_eq!(Error::Unknown("fly secrets deploy".into()).exit_code(), 9);
    }

    #[test]
    fn unknown_error_says_outcome_unknown() {
        let e = Error::Unknown("deploy: the CLI was killed".into());
        assert_eq!(e.to_string(), "outcome unknown: deploy: the CLI was killed");
    }

    #[test]
    fn dependency_error_defaults_to_its_install_line() {
        let e = Error::Dependency("op not found on PATH\n  install: brew install op".into());
        assert_eq!(
            e.default_next("opv status prod"),
            "install: brew install op"
        );
    }

    #[test]
    fn unknown_error_defaults_to_running_the_command_again() {
        let e = Error::Unknown("x".into());
        assert_eq!(
            e.default_next("opv sync prod --deploy"),
            "opv sync prod --deploy (safe to re-run)"
        );
    }
}
