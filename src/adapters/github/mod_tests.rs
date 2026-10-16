use super::gh::missing_environment_error;
use crate::cause::{Cause, Invocation};

fn cause() -> Cause {
    missing_environment_error("org/r", "staging")
        .cause()
        .expect("a catalog cause")
        .0
        .clone()
}

fn sync() -> Invocation {
    Invocation::from_cli(&["opv".into(), "sync".into(), "prod".into()])
}

#[test]
fn missing_environment_error_names_repository_and_environment() {
    let m = cause().message();
    assert!(m.contains("org/r") && m.contains("staging"), "{m}");
}

#[test]
fn missing_environment_error_is_owner_setup_required() {
    assert_eq!(cause().code(), "owner_setup_required");
}

#[test]
fn missing_environment_error_needs_a_human() {
    assert!(cause().human_required(&sync()));
}

// 06.46: the message no longer claims "opv never creates GitHub environments", which
// `opv access --create --github-env` contradicts.
#[test]
fn missing_environment_error_does_not_claim_opv_never_creates_environments() {
    assert!(!cause().message().contains("never creates"));
}
