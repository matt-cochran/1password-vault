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

/// Re-runs this test binary as a child stage; the stage decides what to assert or exit with.
fn spawn_stage(stage: &str, env: &[(&str, &str)], remove: &[&str]) -> i32 {
    let exe = std::env::current_exe().unwrap();
    let mut pairs = vec![("OPV_TEST_STAGE", stage)];
    pairs.extend_from_slice(env);
    let remove: Vec<String> = remove.iter().map(|s| s.to_string()).collect();
    ProcessRunner::default()
        .run_inherited_clean(
            exe.to_str().unwrap(),
            &["--exact", "stage_dispatch", "--nocapture"],
            &pairs,
            &remove,
        )
        .unwrap()
}

#[test]
fn clean_run_passes_the_child_exit_status_through() {
    assert_eq!(spawn_stage("exit5", &[], &["STALE_KEY"]), 5);
}

#[test]
fn nested_product_runs_do_not_inherit_the_outer_products_reference() {
    let code = spawn_stage(
        "outer",
        &[("A_KEY", "op://v/i/a/A_KEY")],
        &["A_KEY", "B_KEY"],
    );
    assert_eq!(code, 0, "inner product run saw the outer product's key");
}

#[test]
fn stage_dispatch() {
    match std::env::var("OPV_TEST_STAGE").as_deref() {
        Ok("exit5") => std::process::exit(5),
        // The outer product's run starts the inner product's run, as a nested `opv run` would.
        Ok("outer") => std::process::exit(spawn_stage(
            "inner",
            &[("B_KEY", "op://v/i/b/B_KEY")],
            &["A_KEY", "B_KEY"],
        )),
        Ok("inner") => {
            let clean = std::env::var_os("A_KEY").is_none()
                && std::env::var("B_KEY").as_deref() == Ok("op://v/i/b/B_KEY");
            std::process::exit(if clean { 0 } else { 1 })
        }
        _ => {}
    }
}
