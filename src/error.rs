//! Typed errors with stable exit codes (FR-10, §6.6).
//!
//! Every failure is a cataloged cause ([`crate::cause::Cause`], design
//! `docs/design/error-catalog.md`), rendered once by [`crate::cause::render`]: its text on
//! stderr ([`render_text`]), its `--json` and MCP `error` object ([`document`]). Its `Do:`
//! and `Next:` come from the cause alone; there is no step override (design §6.1).
//!
//! Messages may name keys, references and rules but never secret values (SR-1, FR-15).

use std::borrow::Cow;
use std::fmt;

use crate::cause::{Cause, Invocation, Upstream};

/// Exit code for success, for completeness alongside [`Error::exit_code`].
pub const EXIT_OK: i32 = 0;

/// The text of a Legacy error. Names only, never a value.
#[derive(Clone, PartialEq, Eq)]
pub struct Msg {
    text: String,
}

impl Msg {
    /// The message.
    pub fn text(&self) -> &str {
        &self.text
    }
}

impl From<String> for Msg {
    fn from(text: String) -> Self {
        Msg { text }
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
        write!(f, "{:?}", self.text)
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
    #[error("{1}")]
    Findings(usize, Msg),
    #[error("outcome unknown: {0}")]
    Unknown(Msg),
    /// A cataloged cause and the upstream tool's reply, when any (design
    /// `docs/design/error-catalog.md` §3). Exit code, code, retry and `human_required` come
    /// from the cause; text and documents from [`crate::cause::render`]. The variants above
    /// are the Legacy arm: production code builds none (the ratchet), and they are removed
    /// next (§10).
    #[error("{}", .0.message())]
    Catalog(Box<Cause>, Option<Box<Upstream>>),
}

impl From<Cause> for Error {
    fn from(cause: Cause) -> Error {
        Error::Catalog(Box::new(cause), None)
    }
}

/// The invocation a Catalog error renders its steps against: the process's own command
/// line (one place, until every entry point passes its own).
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

/// The site a Legacy error renders as: opv's own fault, since production builds none.
const LEGACY_SITE: &str = "an error without a cataloged cause";

impl Error {
    /// Stable process exit code: the cause's (design §4.11). A public contract from v0.1.0
    /// on: 2 configuration and usage, 3 dependency, 4 1Password, 5 target, 6 policy, 7
    /// authentication, 8 findings, 9 outcome unknown, 70 internal, 130/143 interrupted.
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
            Error::Catalog(c, _) => c.exit_code(),
        }
    }

    /// A cataloged cause with the upstream tool's reply as its evidence.
    pub fn with_evidence(cause: Cause, upstream: Upstream) -> Error {
        Error::Catalog(Box::new(cause), Some(Box::new(upstream)))
    }

    /// The cataloged cause and its evidence, for a Catalog error.
    pub fn cause(&self) -> Option<(&Cause, Option<&Upstream>)> {
        match self {
            Error::Catalog(c, up) => Some((c, up.as_deref())),
            _ => None,
        }
    }

    /// The cause the one renderer renders, and its evidence: a Legacy error renders as
    /// opv's internal error.
    fn rendered(&self) -> (Cow<'_, Cause>, Option<&Upstream>) {
        match self {
            Error::Catalog(c, up) => (Cow::Borrowed(c), up.as_deref()),
            _ => (Cow::Owned(Cause::Bug { site: LEGACY_SITE }), None),
        }
    }

    /// The stable code as a string: the cause's own. Documents and MCP answers use this.
    pub fn code_str(&self) -> &'static str {
        self.rendered().0.code()
    }

    /// True when only a person can take the next step (A9), derived from the cause.
    pub fn human_required(&self) -> bool {
        self.rendered().0.human_required(&invocation())
    }

    fn msg(&self) -> Option<&Msg> {
        match self {
            Error::Config(m)
            | Error::Dependency(m)
            | Error::Auth(m)
            | Error::Source(m)
            | Error::Target(m)
            | Error::Policy(m)
            | Error::Findings(_, m)
            | Error::Unknown(m) => Some(m),
            Error::Catalog(..) => None,
        }
    }

    /// True when the message contains `pat`.
    pub fn mentions(&self, pat: &str) -> bool {
        self.text().contains(pat)
    }

    /// The message without category prefix: a Legacy error's text, else empty.
    pub fn text(&self) -> &str {
        self.msg().map_or("", Msg::text)
    }

    /// The stable cause as a [`Code`]: the cause's own when the closed list has it, else
    /// its category's.
    pub fn code(&self) -> Code {
        catalog_code(&self.rendered().0)
    }

    /// The category name, by exit code.
    pub fn category(&self) -> &'static str {
        crate::cause::render::category(self.exit_code())
    }

    /// Its `Do:` in words, rendered from the cause against [`invocation`] (the document's
    /// `do`); `None` when a person has nothing to do first.
    pub fn do_text(&self) -> Option<String> {
        let (cause, _) = self.rendered();
        cause.do_text(&invocation())
    }

    /// Its `Next:` command line, rendered from the cause against [`invocation`] (the
    /// document's `next`); `None` when there is no command to run.
    pub fn next_text(&self) -> Option<String> {
        let (cause, _) = self.rendered();
        let inv = invocation();
        crate::cause::render::next_text(&cause.step(&inv).1, &inv)
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
    let (cause, upstream) = e.rendered();
    crate::cause::render::render_text(&cause, upstream, inv, verbose, utf8, colour)
}

/// The `error` object of the `--json` document and of an MCP answer (§7.2), rendered
/// against `inv`. Names only, like the text (SR-1).
pub fn document(e: &Error, inv: &Invocation, verbose: bool) -> serde_json::Value {
    let (cause, upstream) = e.rendered();
    crate::cause::render::document(&cause, upstream, inv, verbose)
}

/// The [`Code`] of a cause: its own when the closed list has it, else its category's.
fn catalog_code(c: &Cause) -> Code {
    if let Some(code) = Code::ALL.iter().find(|k| k.as_str() == c.code()) {
        return *code;
    }
    match c.exit_code() {
        2 => Code::ConfigInvalid,
        3 => Code::DependencyMissing,
        4 => Code::SourceError,
        5 => Code::TargetError,
        6 => Code::PolicyRefused,
        7 => Code::AuthRequired,
        8 => Code::Findings,
        n if n > 128 => Code::Interrupted,
        _ => Code::OutcomeUnknown,
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
    AccountRequired => "account_required", 2, AfterFix, true, "several 1Password accounts are on this machine and none is chosen for this project; a person picks one with opv login --account";
    AccountAmbiguous => "account_ambiguous", 2, AfterFix, true, "an email or sign-in address names several 1Password accounts; a person picks one by its account ID";
    ManifestNotFound => "manifest_not_found", 2, AfterFix, false, "no 1Password manifest has the project's title (OPV_PROJECT or .opv)";
    ManifestAmbiguous => "manifest_ambiguous", 2, AfterFix, true, "several 1Password manifests match; a person keeps one and archives the others";
    ManifestExists => "manifest_exists", 2, Never, false, "a manifest for this project already exists; change it with opv config edit";
    ConfigChanged => "config_changed", 2, Safe, false, "the configuration changed while opv was editing it: nothing was written and re-running is safe, or (when the error says so) another edit landed with opv's and a person checks the manifest's history";
    ConfigInvalid => "config_invalid", 2, AfterFix, false, "secrets.toml or a flag value is not valid";
    BoundaryMissing => "boundary_missing", 2, AfterFix, false, "a product has a key desired in an environment whose boundary (vault and item) is not recorded";
    StateVaultMissing => "state_vault_missing", 2, AfterFix, false, "a target has no state vault recorded for its delivery evidence";
    StateVaultWiderThanValues => "state_vault_wider_than_values", 2, AfterFix, true, "a state vault shared by targets could be readable more widely than the values its evidence describes; a person gives one target its own";
    DuplicateScope => "duplicate_scope", 2, Never, false, "a receipt file holds more than one entry for the same environment, product and target";
    UnknownEnv => "unknown_env", 2, Never, false, "the environment is not defined in secrets.toml";
    UnknownProduct => "unknown_product", 2, Never, false, "the product is not declared";
    UndeclaredKey => "undeclared_key", 2, Never, false, "the key is not declared (for this environment)";
    NoTarget => "no_target", 2, Never, false, "the environment has no deployment target (run-only)";
    DependencyMissing => "dependency_missing", 3, AfterFix, false, "op or the target CLI is missing or unusable";
    SourceError => "source_error", 4, AfterFix, false, "1Password could not be read";
    ItemNotFound => "item_not_found", 4, AfterFix, false, "the item is not in the vault (moved, archived, deleted, or a wrong item_id)";
    VaultNoAccess => "vault_no_access", 4, AfterFix, true, "the signed-in identity cannot access the vault";
    ItemChanged => "item_changed", 4, AfterFix, true, "opv setup: the 1Password item changed while setup was saving it: again after setup re-read it (nothing was written; run opv setup again), or another edit landed with setup's or a field setup wrote is missing (a person checks the item's history)";
    InventoryIncomplete => "inventory_incomplete", 4, AfterFix, true, "one or more 1Password accounts could not be listed, so the project inventory is incomplete; a project missing from it is not evidence that it does not exist";
    TargetError => "target_error", 5, AfterFix, false, "the target (Fly, Azure, Kubernetes) refused or failed";
    PermissionDenied => "permission_denied", 5, AfterFix, true, "signed in to the target, but this identity lacks a role or right there (or a network rule keeps it out); a person with access grants it";
    OwnerSetupRequired => "owner_setup_required", 5, AfterFix, true, "the target lacks something only its owner sets up (a GitHub environment and its protection rules); a person creates it";
    TargetUnhealthy => "target_unhealthy", 5, AfterFix, false, "the new revision did not become healthy; the previous one keeps serving";
    UpdateRefused => "update_refused", 5, AfterFix, false, "the target refused the update and applied nothing; the previous revision keeps serving; re-running repeats the refusal";
    PolicyRefused => "policy_refused", 6, AfterFix, false, "opv refused the operation";
    ApprovalRequired => "approval_required", 6, AfterFix, true, "the structural plan has no unused, unexpired approval for this project and account; a person runs opv approve <plan_id> in their own terminal";
    KeysBlocking => "keys_blocking", 6, AfterFix, true, "sync refused: keys are missing or failing a rule; nothing was written";
    ConfirmRequired => "confirm_required", 6, Never, true, "the environment sets confirm_env; pass --confirm <env>";
    ConfirmMismatch => "confirm_mismatch", 6, Never, false, "--confirm names another environment";
    StalePlan => "stale_plan", 6, Never, false, "sync --expect-plan: the plan changed since it was reviewed (the item, the target or the configuration); nothing was changed; review the new plan";
    RamDirUnavailable => "ram_dir_unavailable", 6, AfterFix, false, "Azure deploy credentials, or a file opv run delivers locally, need a private RAM-backed directory (XDG_RUNTIME_DIR on Linux, %LOCALAPPDATA%\\Temp on Windows) and none is usable; nothing was read or changed";
    TerminalRequired => "terminal_required", 6, Never, true, "the command needs the user's own interactive terminal";
    AuthRequired => "auth_required", 7, AfterFix, true, "not signed in to 1Password or the target CLI";
    OpNotSignedIn => "op_not_signed_in", 7, AfterFix, true, "not signed in to 1Password";
    IdsNotInAccount => "ids_not_in_account", 2, AfterFix, true, "an environment's recorded vault is not in the selected 1Password account; a person selects the owning account or rebinds the environment (opv bootstrap --rebind)";
    AccountNotRegistered => "account_not_registered", 7, AfterFix, true, "the 1Password account is not added to this 1Password CLI; a person adds it at 1Password's prompt with opv login --add";
    DesktopAppUnavailable => "desktop_app_unavailable", 7, AfterFix, true, "the 1Password app is locked, closed, or its CLI integration is off";
    CredentialRejected => "credential_rejected", 7, AfterFix, true, "1Password did not accept what was typed at its prompt";
    SignInCancelled => "sign_in_cancelled", 7, AfterFix, true, "the 1Password sign-in prompt was cancelled";
    OpUnexpected => "op_unexpected", 7, AfterFix, true, "1Password's CLI failed for a reason opv does not recognise; opv doctor checks it";
    DeployCredentialsFailed => "deploy_credentials_failed", 7, AfterFix, true, "the environment's deploy credentials in 1Password were rejected or are incomplete; nothing was changed";
    Findings => "findings", 8, AfterFix, true, "keys are missing or failing a rule (values are filled in 1Password by a person)";
    OutcomeUnknown => "outcome_unknown", 9, Safe, false, "a change may or may not have been applied; re-running is safe";
    ProviderUnavailable => "provider_unavailable", 9, Safe, false, "a provider did not answer after its retries; nothing was changed";
    Interrupted => "interrupted", 130, Safe, false, "interrupted by SIGINT (130) or SIGTERM (143); re-running is safe";
    TidyConflict => "tidy_conflict", 4, Safe, false, "the 1Password item changed while opv was tidying it: twice before the write (nothing was written), or another edit landed with opv's (check the item's history; opv never retries); a read reports it in its document's tidy_error and goes on with the item as it is, and opv tidy fails with it";
    TidyUnverified => "tidy_unverified", 4, AfterFix, true, "opv tidied the 1Password item but the item read back lacks a field opv wrote or kept; a person restores it from the item's history; a read reports it in its document's tidy_error and goes on, and opv tidy fails with it";
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
