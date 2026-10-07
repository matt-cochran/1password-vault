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
    #[error("child process failed with {0}")]
    Child(i32),
    #[error("status findings: {0}")]
    Findings(usize),
}

impl Error {
    /// Stable process exit code per category.
    ///
    /// | code | category |
    /// |---|---|
    /// | 2 | configuration |
    /// | 3 | dependency / authentication |
    /// | 4 | source (1Password) |
    /// | 5 | target (Fly) |
    /// | 6 | policy (denied destructive operation) |
    /// | n | child exit code, propagated by `run` (FR-4) |
    /// | 8 | `status` found problems |
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::Config(_) => 2,
            Error::Dependency(_) | Error::Auth(_) => 3,
            Error::Source(_) => 4,
            Error::Target(_) => 5,
            Error::Policy(_) => 6,
            Error::Child(c) => *c,
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
        assert_eq!(Error::Auth(s()).exit_code(), 3);
        assert_eq!(Error::Source(s()).exit_code(), 4);
        assert_eq!(Error::Target(s()).exit_code(), 5);
        assert_eq!(Error::Policy(s()).exit_code(), 6);
        assert_eq!(Error::Child(42).exit_code(), 42);
        assert_eq!(Error::Findings(3).exit_code(), 8);
    }
}
