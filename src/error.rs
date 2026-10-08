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
        }
    }
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
}
