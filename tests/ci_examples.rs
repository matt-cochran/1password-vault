//! The workflows in `examples/ci-change-detection/` are exactly what
//! `opv ci workflow --on-change` / `--drift` print for that example configuration, so a
//! copied workflow never drifts from the generator (deliverable C6).

use std::path::{Path, PathBuf};
use std::process::Command;

fn example(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples/ci-change-detection")
        .join(name)
}

/// Run the built binary for the example configuration and return its stdout.
fn render(flag: &str) -> String {
    let config = example("secrets.toml");
    let out = Command::new(env!("CARGO_BIN_EXE_opv"))
        .arg("--config")
        .arg(&config)
        .args(["ci", "workflow", flag])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("run opv");
    assert!(
        out.status.success(),
        "opv ci workflow {flag} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf-8 stdout")
}

#[test]
fn on_change_workflow_file_matches_cli_output() {
    let file = std::fs::read_to_string(example(".github/workflows/opv-sync-on-change.yml"))
        .expect("the on-change workflow file exists");
    assert_eq!(file, render("--on-change"));
}

#[test]
fn drift_workflow_file_matches_cli_output() {
    let file = std::fs::read_to_string(example(".github/workflows/opv-drift.yml"))
        .expect("the drift workflow file exists");
    assert_eq!(file, render("--drift"));
}
