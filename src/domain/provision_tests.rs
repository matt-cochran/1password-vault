//! The set-state classifier (design §4.5): one behavioural assertion per test, through the
//! public `classify` seam.

use crate::domain::provision::{KeyRef, SetState, Unclassifiable, classify};
use crate::domain::value_state::{UnreadableCause, ValueState};

fn malformed() -> ValueState {
    ValueState::Malformed {
        rule: "hex_bytes".into(),
    }
}

#[test]
fn no_member_holding_a_value_is_absent() {
    let states = [ValueState::Absent, ValueState::Empty];
    assert_eq!(classify(&states), Ok(SetState::Absent));
}

#[test]
fn a_placeholder_holds_no_value() {
    let states = [ValueState::Placeholder, ValueState::Absent];
    assert_eq!(classify(&states), Ok(SetState::Absent));
}

#[test]
fn every_member_set_is_complete() {
    let states = [ValueState::Set, ValueState::Set];
    assert_eq!(classify(&states), Ok(SetState::Complete));
}

#[test]
fn some_members_set_is_partial() {
    let states = [ValueState::Set, ValueState::Absent];
    assert_eq!(classify(&states), Ok(SetState::Partial));
}

#[test]
fn a_malformed_member_beside_a_missing_one_is_partial() {
    let states = [malformed(), ValueState::Absent];
    assert_eq!(classify(&states), Ok(SetState::Partial));
}

#[test]
fn every_member_held_with_one_failing_its_rules_is_inconsistent() {
    let states = [ValueState::Set, malformed()];
    assert_eq!(classify(&states), Ok(SetState::Inconsistent));
}

#[test]
fn an_unreadable_member_is_never_absent() {
    let states = [
        ValueState::Absent,
        ValueState::Unreadable {
            cause: UnreadableCause::NoAccess,
        },
    ];
    assert_eq!(
        classify(&states),
        Err(Unclassifiable::Unreadable {
            cause: UnreadableCause::NoAccess
        })
    );
}

#[test]
fn a_supplied_member_is_not_stored() {
    let states = [ValueState::Set, ValueState::Supplied];
    assert_eq!(classify(&states), Err(Unclassifiable::NotStored));
}

#[test]
fn a_set_without_members_is_absent() {
    assert_eq!(classify(std::iter::empty()), Ok(SetState::Absent));
}

#[test]
fn a_key_ref_splits_at_the_first_slash() {
    assert_eq!(
        KeyRef::parse("app/KEY").map(|k| k.to_string()).as_deref(),
        Some("app/KEY")
    );
}

#[test]
fn a_key_ref_without_a_product_is_refused() {
    assert_eq!(KeyRef::parse("/KEY"), None);
}
