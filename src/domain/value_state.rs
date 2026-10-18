//! Value states (design Part V, row `value-state`): the only thing an assistant learns
//! about a value. A state is computed in memory from a read result and the key's contract,
//! and carries no number, length, digest or part of the value.
//!
//! The read error type, [`ReadError`], deliberately has no conversion to
//! [`ValueState::Absent`] or to an `Option`: a value opv could not read is reported as
//! `unreadable`, never as absent or empty (the compile-fail doctests below prove it).

use super::health;
use super::presence::Presence;
use super::secret::SecretValue;

/// Why opv could not read a value (a closed set; never a value or a part of one).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnreadableCause {
    /// No signed-in 1Password session.
    NotSignedIn,
    /// The session has no access to the item or vault.
    NoAccess,
    /// The item or field does not exist.
    ItemMissing,
    /// The `op` command failed for another reason.
    OpFailed,
}

/// A read failure. There is no `From<ReadError>` for [`ValueState`] or `Option`, so a read
/// that failed can never be classified as absent.
///
/// ```
/// use opv::domain::value_state::{ReadError, UnreadableCause};
/// let e = ReadError::new(UnreadableCause::NoAccess);
/// assert_eq!(e.cause(), &UnreadableCause::NoAccess);
/// ```
///
/// ```compile_fail
/// use opv::domain::value_state::{ReadError, UnreadableCause, ValueState};
/// let e = ReadError::new(UnreadableCause::NoAccess);
/// let _s: ValueState = e.into();
/// ```
///
/// ```compile_fail
/// use opv::domain::value_state::{ReadError, UnreadableCause};
/// let e = ReadError::new(UnreadableCause::NoAccess);
/// let _o: Option<String> = e.into();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadError {
    cause: UnreadableCause,
}

impl ReadError {
    /// A read failure with its cause.
    pub fn new(cause: UnreadableCause) -> Self {
        Self { cause }
    }

    /// The cause of the failure.
    pub fn cause(&self) -> &UnreadableCause {
        &self.cause
    }
}

/// The state of one value in one environment. No variant carries a number, a length or any
/// part of the value.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ValueState {
    /// No field.
    Absent,
    /// The field exists and is empty (or whitespace only).
    Empty,
    /// A known placeholder ([`health::is_placeholder`]).
    Placeholder,
    /// Fails a rule committed on the default branch; only the rule's name is reported.
    Malformed {
        /// The failing rule's stable name, never any part of the value.
        rule: String,
    },
    /// Present and passes everything.
    Set,
    /// opv could not read it; the cause is reported, never absent or empty.
    Unreadable {
        /// Why the read failed.
        cause: UnreadableCause,
    },
    /// The key's presence excludes this environment.
    NotWanted {
        /// The declared reason the key is not wanted here.
        reason: String,
    },
}

/// Classify one value.
///
/// `presence` is checked first: a key excluded from the environment is `not_wanted`
/// whatever the read did. A read error is then `unreadable`. `rules_committed` gates the
/// rule check (only rules committed on the default branch count): when it is false,
/// `check` is never called and a failing rule can never yield `malformed`.
pub fn classify(
    read: Result<Option<&SecretValue>, ReadError>,
    presence: Presence,
    rules_committed: bool,
    check: impl FnOnce(&SecretValue) -> Result<(), &'static str>,
) -> ValueState {
    if let Presence::NotWanted { reason } = presence {
        return ValueState::NotWanted { reason };
    }
    match read {
        Err(e) => ValueState::Unreadable { cause: e.cause },
        Ok(None) => ValueState::Absent,
        Ok(Some(value)) => {
            let v = value.expose();
            if v.trim().is_empty() {
                return ValueState::Empty;
            }
            if health::is_placeholder(v) {
                return ValueState::Placeholder;
            }
            if rules_committed && let Err(rule) = check(value) {
                return ValueState::Malformed {
                    rule: rule.to_string(),
                };
            }
            ValueState::Set
        }
    }
}

#[cfg(test)]
#[path = "value_state_tests.rs"]
mod tests;
