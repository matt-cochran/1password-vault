//! Typed errors with stable exit codes (FR-10, §6.6).
//!
//! Messages may name keys, references and rules but never secret values (SR-1, FR-15).
//! Variants therefore carry plain `String`s built by callers, never a `SecretValue`.

/// Exit code for success, for completeness alongside [`Error::exit_code`].
pub const EXIT_OK: i32 = 0;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("dependency error: {0}")]
    Dependency(String),
    #[error("authentication error: {0}")]
    Auth(String),
    #[error("source error: {0}")]
    Source(String),
    #[error("target error: {0}")]
    Target(String),
    #[error("policy denied: {0}")]
    Policy(String),
    #[error("status findings: {0}")]
    Findings(usize),
    /// An external change may or may not have been applied; nothing is known to be broken;
    /// re-running the same command is safe (NR-2).
    #[error("outcome unknown: {0}")]
    Unknown(String),
}

impl Error {
    /// Stable process exit code per category. A public contract from v0.1.0 on.
    ///
    /// | code | category |
    /// |---|---|
    /// | 0 | success |
    /// | 2 | configuration, and command-line usage (clap's own code) |
    /// | 3 | dependency (`op` / `flyctl` missing or unusable) |
    /// | 4 | source (1Password) |
    /// | 5 | target (Fly) |
    /// | 6 | policy (refused: blocking keys, refused values, denied destructive operation) |
    /// | 7 | authentication (1Password or Fly) |
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
            Error::Findings(_) => 8,
            Error::Unknown(_) => 9,
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

/// What opv prints on stderr for `e` (NR-31, SR-1): `opv: <error>`, with the failed call's
/// scrubbed stderr `excerpt` (`  az said: …`, at most 5 lines) right after the error's
/// first line, so the error's own `next:` step stays last. The error's `Display` is
/// unchanged; the excerpt is shown only for [`Error::from_external_call`] categories.
pub fn report(e: &Error, excerpt: Option<&crate::scrub::Excerpt>) -> String {
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
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_stable() {
        let s = || String::from("x");
        assert_eq!(Error::Config(s()).exit_code(), 2);
        assert_eq!(Error::Dependency(s()).exit_code(), 3);
        assert_eq!(Error::Auth(s()).exit_code(), 7);
        assert_eq!(Error::Source(s()).exit_code(), 4);
        assert_eq!(Error::Target(s()).exit_code(), 5);
        assert_eq!(Error::Policy(s()).exit_code(), 6);
        assert_eq!(Error::Findings(3).exit_code(), 8);
    }

    fn excerpt() -> crate::scrub::Excerpt {
        crate::scrub::Excerpt {
            program: "az".into(),
            lines: vec!["ERROR: (Forbidden) caller lacks get permission".into()],
        }
    }

    #[test]
    fn report_puts_the_excerpt_after_the_first_error_line() {
        let e = Error::Target("az keyvault secret list failed (exit 1)\n  next: az login".into());
        assert_eq!(
            report(&e, Some(&excerpt())),
            "opv: target error: az keyvault secret list failed (exit 1)\n  az said: ERROR: (Forbidden) caller lacks get permission\n  next: az login\n"
        );
    }

    #[test]
    fn report_without_excerpt_is_the_error_line() {
        assert_eq!(
            report(&Error::Source("x".into()), None),
            "opv: source error: x\n"
        );
    }

    #[test]
    fn report_never_attaches_an_excerpt_to_a_policy_error() {
        assert_eq!(
            report(&Error::Policy("x".into()), Some(&excerpt())),
            "opv: policy denied: x\n"
        );
    }

    #[test]
    fn unknown_error_exits_9() {
        assert_eq!(Error::Unknown("fly secrets deploy".into()).exit_code(), 9);
    }

    #[test]
    fn unknown_error_says_outcome_unknown() {
        let e = Error::Unknown("fly secrets deploy: flyctl was killed".into());
        assert_eq!(
            e.to_string(),
            "outcome unknown: fly secrets deploy: flyctl was killed"
        );
    }
}
