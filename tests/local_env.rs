//! Real child-process isolation tests: synthetic values only.
use opv::runner::{CommandRunner, ProcessRunner};
use std::process::Command;
#[test]
fn clean_run_removes_parent_managed_values_and_adds_selected_reference() {
    let result = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "clean_parent", "--nocapture"])
        .env("OPV_TEST_STAGE", "parent")
        .env("STALE_KEY", "SYNTHETIC_STALE")
        .env("SELECTED_KEY", "SYNTHETIC_OLD")
        .output()
        .unwrap();
    assert!(result.status.success(), "synthetic child failed");
}
#[test]
fn clean_parent() {
    if std::env::var("OPV_TEST_STAGE").as_deref() != Ok("parent") {
        return;
    }
    let exe = std::env::current_exe().unwrap();
    let code = ProcessRunner::default()
        .run_inherited_clean(
            exe.to_str().unwrap(),
            &["--exact", "clean_child", "--nocapture"],
            &[
                ("OPV_TEST_STAGE", "child"),
                ("SELECTED_KEY", "op://v/i/api/SELECTED_KEY"),
            ],
            &["STALE_KEY".to_string(), "SELECTED_KEY".to_string()],
        )
        .unwrap();
    assert_eq!(code, 0);
}
#[test]
fn clean_child() {
    if std::env::var("OPV_TEST_STAGE").as_deref() != Ok("child") {
        return;
    }
    assert!(
        std::env::var_os("STALE_KEY").is_none(),
        "stale managed key retained"
    );
    assert!(
        std::env::var("SELECTED_KEY").as_deref() == Ok("op://v/i/api/SELECTED_KEY"),
        "selected reference not applied"
    );
    assert!(std::env::var_os("PATH").is_some(), "tool context cleared");
}
