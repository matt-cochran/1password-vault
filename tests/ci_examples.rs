//! The workflows in `examples/ci-change-detection/` are exactly what
//! `opv ci workflow --on-change` / `--drift` print for that example configuration, so a
//! copied workflow never drifts from the generator (deliverable C6). The promotion-chain
//! recipe is hand-written, so it is read and checked for its shape instead.

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

/// The hand-written promotion-chain recipe under test.
fn promotion() -> String {
    std::fs::read_to_string(example(".github/workflows/opv-promotion.yml"))
        .expect("the promotion-chain workflow file exists")
}

/// Each `jobs:` entry as its name and the job it `needs:`, in the order the file lists them.
fn promotion_jobs(text: &str) -> Vec<(String, Option<String>)> {
    let mut jobs: Vec<(String, Option<String>)> = Vec::new();
    let mut in_jobs = false;
    for line in text.lines() {
        if line == "jobs:" {
            in_jobs = true;
            continue;
        }
        if !in_jobs {
            continue;
        }
        if let Some(name) = line.strip_prefix("  ").and_then(|l| l.strip_suffix(':')) {
            if !name.is_empty() && !name.contains(char::is_whitespace) {
                jobs.push((name.to_string(), None));
            }
        } else if let Some(rest) = line.strip_prefix("    needs:")
            && let Some((_, need)) = jobs.last_mut()
        {
            *need = Some(rest.trim().to_string());
        }
    }
    jobs
}

/// The environments whose gate a promotion job runs, in file order.
fn gated_environments(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("run: opv ready ")?;
            Some(rest.strip_suffix(" --gate")?.to_string())
        })
        .collect()
}

#[test]
fn promotion_chain_runs_dev_then_staging_then_prod() {
    let chain = promotion_jobs(&promotion());
    assert_eq!(
        chain,
        vec![
            ("dev".to_string(), None),
            ("staging".to_string(), Some("dev".to_string())),
            ("prod".to_string(), Some("staging".to_string())),
        ]
    );
}

#[test]
fn every_promotion_job_gates_on_its_environment() {
    assert_eq!(gated_environments(&promotion()), ["dev", "staging", "prod"]);
}

#[test]
fn promotion_chain_never_runs_opv_apply() {
    let runs_apply = promotion()
        .lines()
        .any(|line| line.trim_start().starts_with("run:") && line.contains("opv apply"));
    assert!(!runs_apply);
}

/// Each tier is gated after its own sync: `ready --gate` fails on a value that is set but not yet
/// delivered, so a gate before the sync would never let a new value through.
#[test]
fn every_promotion_job_gates_after_its_sync() {
    let text = promotion();
    assert!(["dev", "staging", "prod"].iter().all(|env| {
        let sync = text
            .find(&format!("opv sync {env} "))
            .expect("the job syncs");
        let gate = text
            .find(&format!("opv ready {env} --gate"))
            .expect("the job gates");
        sync < gate
    }));
}
