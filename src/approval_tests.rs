//! Behaviour tests for [`crate::approval`]. Each test states one observable outcome and
//! drives the public API only; the filesystem is a temp directory, never the user's state
//! directory, and no process-wide environment variable is set.

use super::*;
use crate::error::Code;

const PLAN: &str = "sp-0123456789abcdef";
const OTHER_PLAN: &str = "sp-fedcba9876543210";
const OTHER_PLAN_APPROVE: &str = "opv approve sp-fedcba9876543210";
const NOW: u64 = 1_000_000;

fn tempdir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

/// The directory callers pass to `record_in`/`consume_in`: a child of a temp directory, so
/// the tests never touch the real state directory.
fn approvals(root: &tempfile::TempDir) -> std::path::PathBuf {
    root.path().join("approvals")
}

#[test]
fn ttl_is_fifteen_minutes() {
    assert_eq!(TTL, std::time::Duration::from_secs(15 * 60));
}

#[test]
fn record_then_consume_with_the_same_scope_succeeds() {
    let t = tempdir();
    let dir = approvals(&t);
    record_in(&dir, PLAN, "proj", "acct", NOW).unwrap();
    assert!(consume_in(&dir, PLAN, "proj", "acct", NOW + 1).is_ok());
}

#[test]
fn a_second_consume_of_the_same_approval_is_refused() {
    let t = tempdir();
    let dir = approvals(&t);
    record_in(&dir, PLAN, "proj", "acct", NOW).unwrap();
    consume_in(&dir, PLAN, "proj", "acct", NOW + 1).unwrap();
    let refused = consume_in(&dir, PLAN, "proj", "acct", NOW + 2).unwrap_err();
    assert_eq!(refused.code(), Code::ApprovalRequired);
}

#[test]
fn consume_at_exactly_the_expiry_instant_is_refused() {
    let t = tempdir();
    let dir = approvals(&t);
    record_in(&dir, PLAN, "proj", "acct", NOW).unwrap();
    let refused = consume_in(&dir, PLAN, "proj", "acct", NOW + TTL.as_secs()).unwrap_err();
    assert_eq!(refused.code(), Code::ApprovalRequired);
}

#[test]
fn consume_with_another_project_is_refused() {
    let t = tempdir();
    let dir = approvals(&t);
    record_in(&dir, PLAN, "proj", "acct", NOW).unwrap();
    let refused = consume_in(&dir, PLAN, "other", "acct", NOW + 1).unwrap_err();
    assert_eq!(refused.code(), Code::ApprovalRequired);
}

#[test]
fn consume_with_another_account_is_refused() {
    let t = tempdir();
    let dir = approvals(&t);
    record_in(&dir, PLAN, "proj", "acct", NOW).unwrap();
    let refused = consume_in(&dir, PLAN, "proj", "other", NOW + 1).unwrap_err();
    assert_eq!(refused.code(), Code::ApprovalRequired);
}

#[test]
fn consume_for_another_plan_id_is_refused() {
    let t = tempdir();
    let dir = approvals(&t);
    record_in(&dir, PLAN, "proj", "acct", NOW).unwrap();
    let refused = consume_in(&dir, OTHER_PLAN, "proj", "acct", NOW + 1).unwrap_err();
    assert_eq!(refused.code(), Code::ApprovalRequired);
}

#[test]
fn consume_with_no_record_is_refused() {
    let t = tempdir();
    let dir = approvals(&t);
    let refused = consume_in(&dir, PLAN, "proj", "acct", NOW).unwrap_err();
    assert_eq!(refused.code(), Code::ApprovalRequired);
}

#[test]
fn a_refusals_next_step_names_the_approve_command() {
    let t = tempdir();
    let dir = approvals(&t);
    let refused = consume_in(&dir, OTHER_PLAN, "proj", "acct", NOW).unwrap_err();
    assert_eq!(refused.next_step(), Some(OTHER_PLAN_APPROVE));
}

#[test]
fn a_malformed_plan_id_is_refused_with_usage() {
    let t = tempdir();
    let dir = approvals(&t);
    let refused = record_in(&dir, "not-a-plan", "proj", "acct", NOW).unwrap_err();
    assert_eq!(refused.code(), Code::Usage);
}

#[test]
fn a_malformed_plan_id_is_refused_before_the_directory_is_created() {
    let t = tempdir();
    let dir = approvals(&t);
    let _ = record_in(&dir, "not-a-plan", "proj", "acct", NOW);
    assert!(!dir.exists());
}

#[test]
fn a_new_record_replaces_an_earlier_unused_approval_for_the_same_plan() {
    let t = tempdir();
    let dir = approvals(&t);
    record_in(&dir, PLAN, "first", "acct", NOW).unwrap();
    record_in(&dir, PLAN, "second", "acct", NOW).unwrap();
    assert!(consume_in(&dir, PLAN, "second", "acct", NOW + 1).is_ok());
}

#[test]
fn a_malformed_record_is_refused() {
    let t = tempdir();
    let dir = approvals(&t);
    record_in(&dir, PLAN, "proj", "acct", NOW).unwrap();
    std::fs::write(dir.join(format!("{PLAN}.json")), b"not json").unwrap();
    let refused = consume_in(&dir, PLAN, "proj", "acct", NOW + 1).unwrap_err();
    assert_eq!(refused.code(), Code::ApprovalRequired);
}

#[test]
fn an_expired_claim_leaves_no_reusable_approval() {
    let t = tempdir();
    let dir = approvals(&t);
    record_in(&dir, PLAN, "proj", "acct", NOW).unwrap();
    let _ = consume_in(&dir, PLAN, "proj", "acct", NOW + TTL.as_secs());
    assert!(consume_in(&dir, PLAN, "proj", "acct", NOW + 1).is_err());
}

#[test]
fn a_project_mismatch_claim_leaves_no_reusable_approval() {
    let t = tempdir();
    let dir = approvals(&t);
    record_in(&dir, PLAN, "proj", "acct", NOW).unwrap();
    let _ = consume_in(&dir, PLAN, "other", "acct", NOW + 1);
    assert!(consume_in(&dir, PLAN, "proj", "acct", NOW + 1).is_err());
}

#[test]
fn two_concurrent_consumers_of_one_approval_yield_exactly_one_success() {
    let t = tempdir();
    let dir = approvals(&t);
    record_in(&dir, PLAN, "proj", "acct", NOW).unwrap();
    let (first, second) = std::thread::scope(|scope| {
        let a = scope.spawn(|| consume_in(&dir, PLAN, "proj", "acct", NOW + 1).is_ok());
        let b = scope.spawn(|| consume_in(&dir, PLAN, "proj", "acct", NOW + 1).is_ok());
        (a.join().unwrap(), b.join().unwrap())
    });
    assert!(first ^ second);
}

#[cfg(unix)]
#[test]
fn the_recorded_file_has_mode_0600() {
    use std::os::unix::fs::PermissionsExt as _;
    let t = tempdir();
    let dir = approvals(&t);
    record_in(&dir, PLAN, "proj", "acct", NOW).unwrap();
    let mode = std::fs::metadata(dir.join(format!("{PLAN}.json")))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}

#[cfg(unix)]
#[test]
fn the_created_directory_has_mode_0700() {
    use std::os::unix::fs::PermissionsExt as _;
    let t = tempdir();
    let dir = approvals(&t);
    record_in(&dir, PLAN, "proj", "acct", NOW).unwrap();
    let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
}

#[cfg(unix)]
#[test]
fn a_symlinked_approvals_directory_is_refused() {
    let t = tempdir();
    let real = t.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = approvals(&t);
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let refused = record_in(&link, PLAN, "proj", "acct", NOW).unwrap_err();
    assert_eq!(refused.code(), Code::PolicyRefused);
}

#[cfg(unix)]
#[test]
fn a_group_or_other_accessible_approvals_directory_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;
    let t = tempdir();
    let dir = approvals(&t);
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let refused = record_in(&dir, PLAN, "proj", "acct", NOW).unwrap_err();
    assert_eq!(refused.code(), Code::PolicyRefused);
}
