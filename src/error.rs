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
    /// The stable machine-readable cause (A2); the category's default when `None`.
    code: Option<Code>,
    /// The human-only action that comes before `next` (A3), when the error names one.
    action: Option<String>,
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

    /// The human-only action set with [`Error::with_do`], when any.
    pub fn action(&self) -> Option<&str> {
        self.action.as_deref()
    }

    /// True when the text or the next step contains `pat`.
    pub fn mentions(&self, pat: &str) -> bool {
        self.text.contains(pat) || self.next.as_deref().is_some_and(|n| n.contains(pat))
    }

    /// The same message with `f` applied to its text; the next step is kept.
    pub fn map_text(self, f: impl FnOnce(String) -> String) -> Msg {
        Msg {
            text: f(self.text),
            ..self
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
                    code: None,
                    action: None,
                }
            }
            None => Msg {
                text: s,
                next: None,
                code: None,
                action: None,
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
                code: None,
                action: None,
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

    /// The category's step for an error that names none, before it is split into `Do:`
    /// and `Next:` ([`Error::step`]). `rerun` is the command that was run; `help` the
    /// command's `--help`, for a cause the same command can never get past (a misspelt
    /// environment or product). A dependency or sign-in error already prints its install
    /// or sign-in command on its first indented line (FR-26); that line is the step.
    pub fn default_next(&self, rerun: &str) -> String {
        self.default_step(rerun, rerun)
    }

    fn default_step(&self, rerun: &str, help: &str) -> String {
        match self {
            Error::Unknown(_) => rerun.to_string(),
            Error::Findings(..) => format!("fix the keys above in 1Password, then {rerun}"),
            Error::Policy(_) => format!("fix the cause above, then {rerun}"),
            Error::Dependency(m) | Error::Auth(m) => m
                .text()
                .lines()
                .skip(1)
                .find_map(|l| l.strip_prefix("  "))
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map_or_else(|| rerun.to_string(), |l| format!("{l}, then {rerun}")),
            _ if self.code().retry() == Retry::Never => help.to_string(),
            Error::Config(_) => format!("fix the cause above, then {rerun}"),
            _ => rerun.to_string(),
        }
    }

    /// This error with a stable machine-readable cause (A2).
    pub fn with_code(mut self, code: Code) -> Error {
        self.msg_mut().code = Some(code);
        self
    }

    /// The stable cause: the one set with [`Error::with_code`], else the category's.
    pub fn code(&self) -> Code {
        self.msg().code.unwrap_or(match self {
            Error::Config(_) => Code::ConfigInvalid,
            Error::Dependency(_) => Code::DependencyMissing,
            Error::Source(_) => Code::SourceError,
            Error::Target(_) => Code::TargetError,
            Error::Policy(_) => Code::PolicyRefused,
            Error::Auth(_) => Code::AuthRequired,
            Error::Findings(..) => Code::Findings,
            Error::Unknown(_) => Code::OutcomeUnknown,
        })
    }

    /// The human-only action set with [`Error::with_do`], when any.
    pub fn action(&self) -> Option<&str> {
        self.msg().action()
    }

    /// This error with a human-only action printed as `Do: <action>` before `Next:` (A3).
    pub fn with_do(mut self, action: impl Into<String>) -> Error {
        self.msg_mut().action = Some(action.into());
        self
    }

    /// What to do next (A3): an optional human action and a command that runs as typed.
    /// `rerun` is the command that was run, `help` its `--help` command.
    pub fn step(&self, rerun: &str, help: &str) -> Step {
        let raw = match self.next_step() {
            Some(n) => n.to_string(),
            None => self.default_step(rerun, help),
        };
        let mut step = split_step(&raw, rerun);
        if let Some(a) = &self.msg().action {
            step.action = Some(a.clone());
        }
        step
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

    /// True for the categories an external call can cause; only these show the failed
    /// call's stderr excerpt (NR-31). Configuration, policy and findings never do.
    pub fn from_external_call(&self) -> bool {
        matches!(
            self,
            Error::Dependency(_)
                | Error::Auth(_)
                | Error::Source(_)
                | Error::Target(_)
                | Error::Unknown(_)
        )
    }
}

/// Whether re-running the same command can help (A1): `safe` now (nothing is known to be
/// broken), `after_fix` once the `Do:` step or the cause above is fixed, `never` (the
/// command itself must change; run `next` instead).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retry {
    Safe,
    AfterFix,
    Never,
}

impl Retry {
    pub fn as_str(self) -> &'static str {
        match self {
            Retry::Safe => "safe",
            Retry::AfterFix => "after_fix",
            Retry::Never => "never",
        }
    }
}

macro_rules! codes {
    ($($variant:ident => $slug:literal, $exit:literal, $retry:ident, $human:literal, $meaning:literal;)*) => {
        /// The stable error causes (A2): a closed list, part of the JSON contract. Text
        /// output is unchanged; `--json` carries the slug as `error.code`, and `opv schema`
        /// lists every one.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Code {
            $($variant,)*
        }

        impl Code {
            /// Every code, in exit-code order.
            pub const ALL: &'static [Code] = &[$(Code::$variant,)*];

            /// The slug, `snake_case`.
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Code::$variant => $slug,)*
                }
            }

            /// The process exit code this cause exits with.
            pub fn exit_code(self) -> i32 {
                match self {
                    $(Code::$variant => $exit,)*
                }
            }

            /// Whether re-running the same command can help.
            pub fn retry(self) -> Retry {
                match self {
                    $(Code::$variant => Retry::$retry,)*
                }
            }

            /// True when only a person can take the next step (A9): sign in, fill a value
            /// in 1Password, grant access or type at a terminal prompt. An agent hands the
            /// `do` and `next` fields to the user instead of acting.
            pub fn human_required(self) -> bool {
                match self {
                    $(Code::$variant => $human,)*
                }
            }

            /// One line on what the code means.
            pub fn meaning(self) -> &'static str {
                match self {
                    $(Code::$variant => $meaning,)*
                }
            }
        }
    };
}

codes! {
    Usage => "usage", 2, Never, false, "the command line is not valid (unknown flag, missing argument)";
    ConfigNotFound => "config_not_found", 2, AfterFix, false, "no secrets.toml in this directory or a parent, and no 1Password manifest for this checkout";
    ManifestNotFound => "manifest_not_found", 2, AfterFix, false, "no 1Password manifest has the project's title (OPV_PROJECT or .opv)";
    ManifestAmbiguous => "manifest_ambiguous", 2, AfterFix, true, "several 1Password manifests match; a person keeps one and archives the others";
    ManifestExists => "manifest_exists", 2, Never, false, "a manifest for this project already exists; change it with opv config edit";
    ConfigChanged => "config_changed", 2, Safe, false, "the configuration changed while opv was editing it; nothing was written; re-running is safe";
    ConfigInvalid => "config_invalid", 2, AfterFix, false, "secrets.toml or a flag value is not valid";
    UnknownEnv => "unknown_env", 2, Never, false, "the environment is not defined in secrets.toml";
    UnknownProduct => "unknown_product", 2, Never, false, "the product is not declared, or the simple profile takes none";
    UndeclaredKey => "undeclared_key", 2, Never, false, "the key is not declared (for this environment)";
    NoTarget => "no_target", 2, Never, false, "the environment has no deployment target (run-only)";
    DependencyMissing => "dependency_missing", 3, AfterFix, false, "op or the target CLI is missing or unusable";
    SourceError => "source_error", 4, AfterFix, false, "1Password could not be read";
    ItemNotFound => "item_not_found", 4, AfterFix, false, "the item is not in the vault (moved, archived, deleted, or a wrong item_id)";
    VaultNoAccess => "vault_no_access", 4, AfterFix, true, "the signed-in identity cannot access the vault";
    TargetError => "target_error", 5, AfterFix, false, "the target (Fly, Azure, Kubernetes) refused or failed";
    TargetUnhealthy => "target_unhealthy", 5, AfterFix, false, "the new revision did not become healthy; the previous one keeps serving";
    PolicyRefused => "policy_refused", 6, AfterFix, false, "opv refused the operation";
    KeysBlocking => "keys_blocking", 6, AfterFix, true, "sync refused: keys are missing or failing a rule; nothing was written";
    ConfirmRequired => "confirm_required", 6, Never, true, "the environment sets confirm_env; pass --confirm <env>";
    ConfirmMismatch => "confirm_mismatch", 6, Never, false, "--confirm names another environment";
    StalePlan => "stale_plan", 6, Never, false, "sync --expect-plan: the plan changed since it was reviewed (the item, the target or the configuration); nothing was changed; review the new plan";
    RamDirUnavailable => "ram_dir_unavailable", 6, AfterFix, false, "deploy credentials for Azure need a private RAM-backed directory (XDG_RUNTIME_DIR on Linux, %LOCALAPPDATA%\\Temp on Windows) and none is usable; nothing was read or changed";
    TerminalRequired => "terminal_required", 6, Never, true, "the command needs the user's own interactive terminal";
    AuthRequired => "auth_required", 7, AfterFix, true, "not signed in to 1Password or the target CLI";
    OpNotSignedIn => "op_not_signed_in", 7, AfterFix, true, "not signed in to 1Password";
    DeployCredentialsFailed => "deploy_credentials_failed", 7, AfterFix, true, "the environment's deploy credentials in 1Password were rejected or are incomplete; nothing was changed";
    Findings => "findings", 8, AfterFix, true, "keys are missing or failing a rule (values are filled in 1Password by a person)";
    OutcomeUnknown => "outcome_unknown", 9, Safe, false, "a change may or may not have been applied; re-running is safe";
    ProviderUnavailable => "provider_unavailable", 9, Safe, false, "a provider did not answer after its retries; nothing was changed";
    Interrupted => "interrupted", 130, Safe, false, "interrupted by SIGINT (130) or SIGTERM (143); re-running is safe";
    TidyConflict => "tidy_conflict", 4, Safe, false, "the 1Password item changed twice while opv was tidying it, so nothing was written; never a failure: reported in a document's tidy_error while the command reads the item as it is";
}

/// The end of a failure (A3): an optional human-only action (`Do:`) and one command that
/// runs as typed (`Next:`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub action: Option<String>,
    pub next: String,
}

/// Programs a `Next:` command may start with.
const PROGRAMS: [&str; 15] = [
    "opv", "op", "az", "kubectl", "flyctl", "fly", "helm", "brew", "winget", "scoop", "npm",
    "cargo", "gh", "curl", "env",
];

/// Words that only prose has; a step containing one is an instruction, not a command.
const PROSE: [&str; 33] = [
    "the", "a", "an", "to", "and", "or", "then", "if", "it", "its", "lists", "shows", "with",
    "for", "your", "is", "are", "see", "again", "that", "this", "from", "when", "until", "after",
    "before", "once", "which", "so", "not", "ask", "wait", "re-run",
];

/// True when `step` is one command that runs as typed: a known program, then words that
/// are neither placeholders (`<env>`), shell syntax (`$(...)`, `;`, backticks) nor prose.
pub fn is_runnable(step: &str) -> bool {
    let mut words = step.split_whitespace();
    words.next().is_some_and(|p| PROGRAMS.contains(&p))
        && !step.contains(['<', '>', '`', ';', '(', ')', '$', '|', '&'])
        && words.all(|w| !PROSE.contains(&w) && !w.ends_with([',', ':', '.']))
}

/// `a` as one word of a `Next:` command, quoted only when the shell would split or expand
/// it, so the command still runs as typed. Unix shells: single quotes. Windows: `\` and
/// `~` need no quoting (neither cmd.exe nor PowerShell treats them specially inside a
/// word), and a word that does is double-quoted, which cmd.exe and PowerShell both read
/// (a path cannot contain `"`); a word holding `$` or a backtick, which PowerShell would
/// expand inside double quotes, is single-quoted instead.
pub fn shell_word(a: &str) -> String {
    shell_word_for(a, cfg!(windows))
}

/// [`shell_word`] for Windows (`windows`, quoted for PowerShell) or Unix quoting. On
/// Windows a word with `,` (an array in PowerShell), `%` or a leading `@` (splatting) is
/// quoted too (M12). cmd.exe still expands `%NAME%` inside quotes; usage.md notes it.
pub fn shell_word_for(a: &str, windows: bool) -> String {
    let safe = |c: char| {
        c.is_ascii_alphanumeric()
            || "-_./=:@+".contains(c)
            || (!windows && ",%".contains(c))
            || (windows && "\\~".contains(c))
    };
    if !a.is_empty() && a.chars().all(safe) && !(windows && a.starts_with('@')) {
        return a.to_string();
    }
    if windows && !a.contains(['$', '`', '"']) {
        return format!("\"{a}\"");
    }
    if windows {
        return format!("'{}'", a.replace('\'', "''"));
    }
    format!("'{}'", a.replace('\'', "'\\''"))
}

/// Split a free-form step into `Do:` and `Next:` (A3). A runnable step is the `Next:`
/// alone. `<action>, then [run] <command>` splits at `then`. Anything else is the action,
/// and `rerun` (the command that was run) is what to run once it is done.
pub fn split_step(raw: &str, rerun: &str) -> Step {
    let step = raw.lines().map(str::trim).collect::<Vec<_>>().join(" ");
    let step = step
        .trim()
        .trim_end_matches(" (safe to re-run)")
        .to_string();
    if is_runnable(&step) {
        return Step {
            action: None,
            next: step,
        };
    }
    // `run <command> again; <why>`: the command, without the explanation.
    let lead = step.split("; ").next().unwrap_or_default();
    let lead = lead.strip_prefix("run ").unwrap_or(lead);
    let lead = lead
        .strip_suffix(" again")
        .unwrap_or(lead)
        .trim_matches('`');
    if is_runnable(lead) {
        return Step {
            action: None,
            next: lead.to_string(),
        };
    }
    let split = step
        .rsplit_once(", then ")
        .or_else(|| step.rsplit_once(" then "));
    if let Some((head, tail)) = split {
        let tail = tail.trim().trim_end_matches('.');
        let tail = tail.strip_prefix("run ").unwrap_or(tail);
        let tail = tail.strip_suffix(" again").unwrap_or(tail);
        let tail = tail.trim_matches('`');
        if is_runnable(tail) {
            return Step {
                action: Some(head.to_string()),
                next: tail.to_string(),
            };
        }
        if is_rerun_phrase(tail) {
            return Step {
                action: Some(head.to_string()),
                next: rerun.to_string(),
            };
        }
    }
    if is_rerun_phrase(&step) {
        return Step {
            action: None,
            next: rerun.to_string(),
        };
    }
    let action = match step.split_whitespace().next() {
        // A command with placeholders: the person fills them in.
        Some(p) if PROGRAMS.contains(&p) => format!("fill in and run: {step}"),
        _ => step,
    };
    Step {
        action: Some(action),
        next: rerun.to_string(),
    }
}

/// "re-run the same command", "run opv again" and similar.
fn is_rerun_phrase(s: &str) -> bool {
    let s = s.trim().trim_end_matches('.').to_ascii_lowercase();
    matches!(
        s.as_str(),
        "re-run" | "rerun" | "re-run it" | "run opv again" | "run it again" | "re-run opv"
    ) || s.ends_with("the same command")
        || s.ends_with("the same command again")
}

/// What opv prints on stderr for `e` (NR-19, NR-31, SR-1, A3), in this order: `opv:
/// <error>`'s first line; the failed call's scrubbed stderr `excerpt` (`  az said: …`, at
/// most 5 lines, only for [`Error::from_external_call`] categories); the rest of the
/// error's text; `Do: <action>` when a person must act first; then exactly one `Next:
/// <command>` line, always last, that runs as typed. `rerun` is the command that was run;
/// it is the `Next:` command when the error names none (see [`Error::step`]). The error's
/// `Display` is unchanged.
pub fn report(e: &Error, rerun: &str, excerpt: Option<&crate::scrub::Excerpt>) -> String {
    report_with(e, &e.step(rerun, rerun), excerpt)
}

/// [`report`] with the step already worked out.
pub fn report_with(e: &Error, step: &Step, excerpt: Option<&crate::scrub::Excerpt>) -> String {
    let msg = format!("opv: {e}");
    let (head, rest) = match msg.split_once('\n') {
        Some((h, r)) => (h, Some(r)),
        None => (msg.as_str(), None),
    };
    let mut out = format!("{head}\n");
    if let Some(x) = excerpt.filter(|_| e.from_external_call()) {
        out.push_str(&x.render());
    }
    if let Some(r) = rest {
        out.push_str(r);
        out.push('\n');
    }
    out.push_str(&step_lines(step));
    out
}

/// `Do: <action>` (when any) and the one `Next:` line, newline-terminated.
pub fn step_lines(step: &Step) -> String {
    let mut out = String::new();
    if let Some(a) = &step.action {
        let a = a.lines().map(str::trim).collect::<Vec<_>>().join(" ");
        out.push_str(&format!("Do: {a}\n"));
    }
    out.push_str(&next_line(&step.next));
    out
}

/// The one `Next:` line, newline-terminated; a multi-line step is joined onto one line.
pub fn next_line(step: &str) -> String {
    let step = step.lines().map(str::trim).collect::<Vec<_>>().join(" ");
    format!("Next: {step}\n")
}

/// The `--json` failure document (A1): `{schema_version, ok: false, exit_code, error:
/// {code, category, message, detail, retry, human_required, do, next}}`. Names only, like
/// the text (SR-1); the failed call's stderr excerpt is never included.
pub fn envelope(e: &Error, step: &Step) -> serde_json::Value {
    let text = e.text();
    let mut lines = text.lines();
    let message = lines.next().unwrap_or_default().trim().to_string();
    let detail: Vec<String> = lines
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    let code = e.code();
    serde_json::json!({
        "schema_version": crate::json::SCHEMA_VERSION,
        "ok": false,
        "exit_code": e.exit_code(),
        "error": error_object(
            code.as_str(),
            e.category(),
            &message,
            detail,
            code.retry(),
            code.human_required(),
            step,
        ),
    })
}

/// The `error` object of a failure document (A1, A9).
pub fn error_object(
    code: &str,
    category: &str,
    message: &str,
    detail: Vec<String>,
    retry: Retry,
    human_required: bool,
    step: &Step,
) -> serde_json::Value {
    serde_json::json!({
        "code": code,
        "category": category,
        "message": message,
        "detail": detail,
        "retry": retry.as_str(),
        "human_required": human_required,
        "do": step.action,
        "next": step.next,
    })
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
            let text = report(&e, &e.default_next("opv status prod"), Some(&excerpt()));
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
            report(&e, "opv doctor", None),
            "opv: target error: failed\nNext: az login\n"
        );
    }

    #[test]
    fn report_uses_the_fallback_without_a_step() {
        let e = Error::Source("x".into());
        assert_eq!(
            report(&e, "opv doctor", None),
            "opv: source error: x\nNext: opv doctor\n"
        );
    }

    #[test]
    fn map_text_keeps_the_step() {
        let e =
            Error::Auth("signed out\n  next: opv login dev".into()).map_text(|t| t + "\n  more");
        assert_eq!(e.next_step(), Some("opv login dev"));
    }

    #[test]
    fn findings_name_their_count() {
        assert_eq!(Error::findings(1, "x").to_string(), "1 finding");
    }

    fn excerpt() -> crate::scrub::Excerpt {
        crate::scrub::Excerpt {
            program: "az".into(),
            lines: vec!["ERROR: (Forbidden) caller lacks get permission".into()],
        }
    }

    #[test]
    fn report_orders_error_line_then_excerpt_then_next() {
        let e = Error::Target(
            "az keyvault secret list failed (exit 1)\n  vault: kv-prod\n  next: az login".into(),
        );
        assert_eq!(
            report(&e, "opv doctor", Some(&excerpt())),
            "opv: target error: az keyvault secret list failed (exit 1)\n  az said: ERROR: (Forbidden) caller lacks get permission\n  vault: kv-prod\nNext: az login\n"
        );
    }

    #[test]
    fn report_without_excerpt_is_the_error_line_then_next() {
        assert_eq!(
            report(&Error::Source("x".into()), "opv doctor", None),
            "opv: source error: x\nNext: opv doctor\n"
        );
    }

    #[test]
    fn report_never_attaches_an_excerpt_to_a_policy_error() {
        assert_eq!(
            report(
                &Error::Policy("x".into()).with_next("opv doctor"),
                "opv doctor",
                Some(&excerpt())
            ),
            "opv: policy denied: x\nNext: opv doctor\n"
        );
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
            e.step("opv status prod", "opv status --help")
                .action
                .as_deref(),
            Some("install: brew install op")
        );
    }

    #[test]
    fn unknown_error_defaults_to_running_the_command_again() {
        let e = Error::Unknown("x".into());
        assert_eq!(
            e.step("opv sync prod --deploy", "opv sync --help").next,
            "opv sync prod --deploy"
        );
    }

    // --- A3: `Do:` for a person, `Next:` that runs as typed ---

    fn split(raw: &str) -> Step {
        split_step(raw, "opv status prod")
    }

    #[test]
    fn a_runnable_step_is_the_next_command_alone() {
        assert_eq!(
            split("opv explain api/KEY --env prod"),
            Step {
                action: None,
                next: "opv explain api/KEY --env prod".into()
            }
        );
    }

    #[test]
    fn fix_then_run_splits_into_do_and_next() {
        assert_eq!(
            split("fix the keys above in 1Password, then run opv status prod"),
            Step {
                action: Some("fix the keys above in 1Password".into()),
                next: "opv status prod".into()
            }
        );
    }

    #[test]
    fn a_rerun_phrase_becomes_the_command_that_was_run() {
        assert_eq!(
            split_step(
                "check the vault, then re-run the same command",
                "opv sync prod"
            )
            .next,
            "opv sync prod"
        );
    }

    #[test]
    fn prose_becomes_the_action() {
        assert_eq!(
            split("sign in: eval $(op signin)").action.as_deref(),
            Some("sign in: eval $(op signin)")
        );
    }

    #[test]
    fn a_command_with_placeholders_is_an_action_for_a_person() {
        assert_eq!(
            split("opv init <env> --vault <vault title> --item <item title>").next,
            "opv status prod"
        );
    }

    #[test]
    fn the_safe_to_rerun_note_never_reaches_next() {
        assert_eq!(
            split("opv sync prod (safe to re-run)").next,
            "opv sync prod"
        );
    }

    #[test]
    fn prose_after_a_command_is_not_runnable() {
        assert!(!is_runnable(
            "kubectl config get-contexts -o name lists the contexts"
        ));
    }

    /// A3: every category's `Next:` is runnable, with and without its own step.
    #[test]
    fn every_category_reports_a_runnable_next() {
        let bad: Vec<String> = every_category()
            .into_iter()
            .map(|e| e.step("opv status prod", "opv status --help").next)
            .filter(|n| !is_runnable(n))
            .collect();
        assert!(bad.is_empty(), "{bad:?}");
    }

    #[test]
    fn report_prints_do_right_before_next() {
        let e = Error::findings(
            1,
            "fix the keys above in 1Password, then run opv status prod",
        );
        assert_eq!(
            report(&e, "opv status prod", None),
            "opv: 1 finding\nDo: fix the keys above in 1Password\nNext: opv status prod\n"
        );
    }

    #[test]
    fn a_unix_word_with_a_space_is_single_quoted() {
        assert_eq!(
            shell_word_for("/tmp/my dir/secrets.toml", false),
            "'/tmp/my dir/secrets.toml'"
        );
    }

    #[test]
    fn a_windows_temp_path_needs_no_quotes() {
        let p = r"C:\Users\RUNNER~1\AppData\Local\Temp\.tmpX\secrets.toml";
        assert_eq!(shell_word_for(p, true), p);
    }

    /// M12: PowerShell splits `dev,prod` into an array; quoted, it stays one argument.
    #[test]
    fn a_windows_word_with_a_comma_is_quoted() {
        assert_eq!(shell_word_for("dev,prod", true), r#""dev,prod""#);
    }

    #[test]
    fn a_windows_word_with_a_percent_is_quoted() {
        assert_eq!(shell_word_for("50%", true), r#""50%""#);
    }

    #[test]
    fn a_unix_word_with_a_comma_needs_no_quotes() {
        assert_eq!(shell_word_for("dev,prod", false), "dev,prod");
    }

    #[test]
    fn a_windows_word_with_a_space_is_double_quoted() {
        assert_eq!(
            shell_word_for(r"C:\Users\John Smith\secrets.toml", true),
            r#""C:\Users\John Smith\secrets.toml""#
        );
    }

    #[test]
    fn an_explicit_action_wins() {
        let e = Error::Policy("needs a terminal".into())
            .with_do("ask the user to run this in their own terminal")
            .with_next("opv login");
        assert_eq!(
            e.step("x", "y").action.as_deref(),
            Some("ask the user to run this in their own terminal")
        );
    }

    #[test]
    fn a_misspelt_environment_points_to_help() {
        let e = Error::Config("undefined environment".into()).with_code(Code::UnknownEnv);
        assert_eq!(
            e.step("opv status qa", "opv status --help").next,
            "opv status --help"
        );
    }

    // --- A2: codes ---

    #[test]
    fn a_category_without_a_code_reports_its_default() {
        assert_eq!(Error::Unknown("x".into()).code(), Code::OutcomeUnknown);
    }

    #[test]
    fn every_category_default_code_exits_with_the_category() {
        let bad: Vec<&str> = every_category()
            .iter()
            .filter(|e| e.code().exit_code() != e.exit_code())
            .map(Error::category)
            .collect();
        assert!(bad.is_empty(), "{bad:?}");
    }

    #[test]
    fn a_code_survives_map_text() {
        let e = Error::Policy("x".into())
            .with_code(Code::KeysBlocking)
            .map_text(|t| t + " more");
        assert_eq!(e.code(), Code::KeysBlocking);
    }

    #[test]
    fn outcome_unknown_is_safe_to_retry() {
        assert_eq!(Code::OutcomeUnknown.retry(), Retry::Safe);
    }

    #[test]
    fn a_terminal_refusal_needs_a_human() {
        assert!(Code::TerminalRequired.human_required());
    }

    // --- A1: the envelope ---

    #[test]
    fn envelope_carries_code_retry_do_and_next() {
        let e = Error::Policy("sync refused".into())
            .with_code(Code::KeysBlocking)
            .with_do("fix api/KEY in 1Password")
            .with_next("opv explain api/KEY --env prod");
        let v = envelope(&e, &e.step("opv sync prod", "opv sync --help"));
        assert_eq!(
            v,
            serde_json::json!({
                "schema_version": 1,
                "ok": false,
                "exit_code": 6,
                "error": {
                    "code": "keys_blocking",
                    "category": "policy",
                    "message": "sync refused",
                    "detail": [],
                    "retry": "after_fix",
                    "human_required": true,
                    "do": "fix api/KEY in 1Password",
                    "next": "opv explain api/KEY --env prod",
                }
            })
        );
    }

    #[test]
    fn envelope_message_is_the_first_line_and_detail_the_rest() {
        let e = Error::Source("item not found\n  vault: vprd".into());
        let v = envelope(&e, &e.step("opv status prod", "h"));
        assert_eq!(v["error"]["detail"], serde_json::json!(["vault: vprd"]));
    }
}
