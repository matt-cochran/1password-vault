//! Typed errors with stable exit codes (FR-10, §6.6).
//!
//! Every failure is a cataloged cause ([`crate::cause::Cause`], design
//! `docs/design/error-catalog.md`), rendered once by [`crate::cause::render`]: its text on
//! stderr ([`render_text`]), its `--json` and MCP `error` object ([`document`]). Its code,
//! exit code, retry class, `Do:` and `Next:` come from the cause alone; there is no free-text
//! error and no step override (design §6.1, §10). The public codes are the catalog's
//! ([`crate::cause::codes::table`]).
//!
//! Messages may name keys, references and rules but never secret values (SR-1, FR-15).

use crate::cause::{Cause, Invocation, Upstream};

/// Exit code for success, for completeness alongside [`Error::exit_code`].
pub const EXIT_OK: i32 = 0;

/// A cataloged cause and the upstream tool's reply, when any (design §3). Exit code, code,
/// retry and `human_required` come from the cause; text and documents from
/// [`crate::cause::render`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{}", .0.message())]
    Catalog(Box<Cause>, Option<Box<Upstream>>),
}

impl From<Cause> for Error {
    fn from(cause: Cause) -> Error {
        Error::Catalog(Box::new(cause), None)
    }
}

/// The invocation an error renders its steps against: the process's own command line (one
/// place, until every entry point passes its own).
pub fn invocation() -> Invocation {
    if let Some(outer) = OUTER_INVOCATION.get() {
        return outer.clone();
    }
    Invocation::from_cli(&std::env::args().collect::<Vec<_>>())
}

/// The person's `opv run` an internal step (`local-delivery`, `remote-send`,
/// `remote-receive`) serves, set once by that step (design §6.1, X25): its errors render
/// their steps against it, never against the hidden command itself.
static OUTER_INVOCATION: std::sync::OnceLock<Invocation> = std::sync::OnceLock::new();

/// Set the invocation an internal step's errors render against (see [`invocation`]).
pub fn set_outer_invocation(inv: Invocation) {
    let _ = OUTER_INVOCATION.set(inv);
}

impl Error {
    /// Stable process exit code: the cause's (design §4.11). A public contract from v0.1.0
    /// on: 2 configuration and usage, 3 dependency, 4 1Password, 5 target, 6 policy, 7
    /// authentication, 8 findings, 9 outcome unknown, 70 internal, 128 + the signal when
    /// interrupted. `run` exits with the child's own code instead (FR-4); see its help.
    pub fn exit_code(&self) -> i32 {
        self.parts().0.exit_code()
    }

    /// A cataloged cause with the upstream tool's reply as its evidence.
    pub fn with_evidence(cause: Cause, upstream: Upstream) -> Error {
        Error::Catalog(Box::new(cause), Some(Box::new(upstream)))
    }

    /// The cause and its evidence.
    pub fn parts(&self) -> (&Cause, Option<&Upstream>) {
        let Error::Catalog(c, up) = self;
        (c, up.as_deref())
    }

    /// The cause and its evidence, as an `Option` for the callers that match on it (every
    /// error has a cause: this is always `Some`).
    pub fn cause(&self) -> Option<(&Cause, Option<&Upstream>)> {
        Some(self.parts())
    }

    /// The stable code: the cause's own ([`Cause::code`]). Documents and MCP answers use it.
    pub fn code_str(&self) -> &'static str {
        self.parts().0.code()
    }

    /// True when only a person can take the next step (A9), derived from the cause.
    pub fn human_required(&self) -> bool {
        self.parts().0.human_required(&invocation())
    }

    /// The message (the cause's first line), as [`std::fmt::Display`] prints it.
    pub fn text(&self) -> String {
        self.to_string()
    }

    /// True when the rendered text (message, evidence, `Do:` and `Next:`) contains `pat`.
    pub fn mentions(&self, pat: &str) -> bool {
        report(self).contains(pat)
    }

    /// The category name, by exit code.
    pub fn category(&self) -> &'static str {
        crate::cause::render::category(self.exit_code())
    }

    /// Its `Do:` in words, rendered from the cause against [`invocation`] (the document's
    /// `do`); `None` when a person has nothing to do first.
    pub fn do_text(&self) -> Option<String> {
        self.parts().0.do_text(&invocation())
    }

    /// Its `Next:` command line, rendered from the cause against [`invocation`] (the
    /// document's `next`); `None` when there is no command to run.
    pub fn next_text(&self) -> Option<String> {
        let inv = invocation();
        crate::cause::render::next_text(&self.parts().0.step(&inv).1, &inv)
    }
}

/// What opv prints on stderr for `e` (§7.1), rendered against [`invocation`]: `opv:
/// <message>`, the `checked:` line, the upstream box, `Do:`, and `Next:` last.
pub fn report(e: &Error) -> String {
    render_text(e, &invocation(), false, false, false)
}

/// [`report`] against `inv`, with `--verbose` (the whole scrubbed upstream reply), UTF-8
/// box drawing and colour as the caller decides (§7.1, §7.3).
pub fn render_text(e: &Error, inv: &Invocation, verbose: bool, utf8: bool, colour: bool) -> String {
    let (cause, upstream) = e.parts();
    crate::cause::render::render_text(cause, upstream, inv, verbose, utf8, colour)
}

/// The `error` object of the `--json` document and of an MCP answer (§7.2), rendered
/// against `inv`. Names only, like the text (SR-1).
pub fn document(e: &Error, inv: &Invocation, verbose: bool) -> serde_json::Value {
    let (cause, upstream) = e.parts();
    crate::cause::render::document(cause, upstream, inv, verbose)
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

#[cfg(test)]
mod tests {
    use super::*;

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

    // --- the one renderer (design §3, §7) -----------------------------------------------

    fn own_session() -> Cause {
        Cause::NeedsOwnSession {
            command: crate::cause::CommandId("approve".into()),
            identity: crate::cause::Principal::ServiceAccount {
                name: "sa-ci".into(),
            },
        }
    }

    #[test]
    fn a_catalog_error_exits_with_its_causes_code() {
        assert_eq!(
            Error::from(own_session()).exit_code(),
            own_session().exit_code()
        );
    }

    #[test]
    fn a_catalog_error_reports_the_catalog_text() {
        let want = crate::cause::render::render_text(
            &own_session(),
            None,
            &invocation(),
            false,
            false,
            false,
        );
        assert_eq!(report(&Error::from(own_session())), want);
    }

    #[test]
    fn a_catalog_errors_document_is_the_catalog_document() {
        let want = crate::cause::render::document(&own_session(), None, &invocation(), false);
        assert_eq!(
            document(&Error::from(own_session()), &invocation(), false),
            want
        );
    }

    #[test]
    fn a_catalog_errors_code_string_is_its_causes() {
        assert_eq!(
            Error::from(own_session()).code_str(),
            "own_session_required"
        );
    }

    #[test]
    fn a_catalog_errors_category_follows_its_exit_code() {
        assert_eq!(Error::from(own_session()).category(), "auth");
    }
}
