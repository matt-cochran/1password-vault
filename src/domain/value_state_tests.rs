//! Value states (design Part V, row `value-state`): one atomic test per state, through the
//! public `classify` seam. No test asserts on private implementation or call sequence.

use crate::domain::presence::Presence;
use crate::domain::secret::SecretValue;
use crate::domain::value_state::{ReadError, UnreadableCause, ValueState, classify};

/// A value wrapped for classification.
fn value(v: &str) -> SecretValue {
    SecretValue::new(v.to_string())
}

#[test]
fn not_wanted_is_reported_before_any_read_error() {
    let state = classify(
        Err(ReadError::new(UnreadableCause::NoAccess)),
        Presence::NotWanted {
            reason: "not deployed here".into(),
        },
        true,
        |_| Ok(()),
    );
    assert_eq!(
        state,
        ValueState::NotWanted {
            reason: "not deployed here".into()
        }
    );
}

#[test]
fn read_error_is_unreadable_with_its_cause() {
    let state = classify(
        Err(ReadError::new(UnreadableCause::NoAccess)),
        Presence::Present,
        true,
        |_| Ok(()),
    );
    assert_eq!(
        state,
        ValueState::Unreadable {
            cause: UnreadableCause::NoAccess
        }
    );
}

#[test]
fn missing_field_is_absent() {
    let state = classify(Ok(None), Presence::Present, true, |_| Ok(()));
    assert_eq!(state, ValueState::Absent);
}

#[test]
fn whitespace_only_field_is_empty() {
    let v = value("   ");
    let state = classify(Ok(Some(&v)), Presence::Present, true, |_| Ok(()));
    assert_eq!(state, ValueState::Empty);
}

#[test]
fn known_placeholder_is_placeholder() {
    let v = value("changeme");
    let state = classify(Ok(Some(&v)), Presence::Present, true, |_| Ok(()));
    assert_eq!(state, ValueState::Placeholder);
}

#[test]
fn failing_committed_rule_is_malformed_with_the_rule_name_only() {
    let v = value("not-a-url");
    let state = classify(Ok(Some(&v)), Presence::Present, true, |_| Err("https_url"));
    assert_eq!(
        state,
        ValueState::Malformed {
            rule: "https_url".into()
        }
    );
}

#[test]
fn value_passing_committed_rules_is_set() {
    let v = value("sk-live-abc");
    let state = classify(Ok(Some(&v)), Presence::Present, true, |_| Ok(()));
    assert_eq!(state, ValueState::Set);
}

#[test]
fn a_pending_review_rule_is_never_evaluated() {
    let v = value("not-a-url");
    let state = classify(Ok(Some(&v)), Presence::Present, false, |_| {
        panic!("a pending-review rule must not be evaluated")
    });
    assert_eq!(state, ValueState::Set);
}

#[test]
fn debug_of_every_state_is_value_free() {
    let marker = "S7MARKER-DO-NOT-LEAK";
    let v = value(marker);
    let states = [
        ValueState::Absent,
        ValueState::Empty,
        ValueState::Placeholder,
        ValueState::Malformed {
            rule: "https_url".into(),
        },
        ValueState::Set,
        ValueState::Unreadable {
            cause: UnreadableCause::OpFailed,
        },
        ValueState::NotWanted {
            reason: "not deployed here".into(),
        },
        classify(Ok(Some(&v)), Presence::Present, true, |_| Ok(())),
    ];
    let rendered: String = states.iter().map(|s| format!("{s:?}")).collect();
    assert!(!rendered.contains(marker));
}
