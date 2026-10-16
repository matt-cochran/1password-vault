//! #131: `opv version` reports opv and every CLI it runs, credential-free.

use std::io;

use super::*;
use crate::runner::Output;
use crate::runner::fake::FakeRunner;

const FLY: &str = "[environments.prod]\n\n[environments.prod.targets.web]\nfly.app = \"a\"\n";

/// A runner answering each CLI's version probe in registry order (op, flyctl, az,
/// kubectl, gh).
fn answering(op: Output) -> FakeRunner {
    let r = FakeRunner::new([op]);
    for _ in 0..4 {
        r.push_io_error(io::ErrorKind::NotFound);
    }
    r
}

fn doc(r: &FakeRunner, config: Option<&Path>) -> serde_json::Value {
    let dir = tempfile::tempdir().unwrap();
    let mut out = Vec::new();
    run(r, config, dir.path(), true, &mut out).unwrap();
    serde_json::from_slice(&out).unwrap()
}

fn op_report(r: &FakeRunner) -> serde_json::Value {
    doc(r, None)["tools"][0].clone()
}

#[test]
fn the_1password_cli_version_is_reported() {
    let r = answering(Output::success("2.40.0\n"));
    assert_eq!(op_report(&r)["version"], "2.40.0");
}

#[test]
fn a_missing_cli_is_reported_missing() {
    let r = answering(Output::success("2.40.0\n"));
    assert_eq!(doc(&r, None)["tools"][1]["status"], "missing");
}

#[test]
fn a_failing_probe_is_unknown() {
    let r = answering(Output::failure(1));
    assert_eq!(op_report(&r)["reason"], "probe failed");
}

#[test]
fn a_timed_out_probe_is_unknown() {
    let r = FakeRunner::default();
    r.push_io_error(io::ErrorKind::TimedOut);
    for _ in 0..4 {
        r.push_io_error(io::ErrorKind::NotFound);
    }
    assert_eq!(op_report(&r)["reason"], "timed out");
}

#[test]
fn opv_s_own_version_is_reported_when_every_cli_is_missing() {
    let r = FakeRunner::default();
    for _ in 0..5 {
        r.push_io_error(io::ErrorKind::NotFound);
    }
    assert_eq!(doc(&r, None)["opv"]["version"], env!("CARGO_PKG_VERSION"));
}

#[test]
fn the_text_output_starts_with_the_version_line() {
    let r = answering(Output::success("2.40.0\n"));
    let dir = tempfile::tempdir().unwrap();
    let mut out = Vec::new();
    run(&r, None, dir.path(), false, &mut out).unwrap();
    let text = String::from_utf8(out).unwrap();
    assert_eq!(
        text.lines().next(),
        Some(format!("opv {}", env!("CARGO_PKG_VERSION")).as_str())
    );
}

#[test]
fn only_the_version_token_of_a_probe_is_kept() {
    let r = answering(Output::success("OP_SESSION_my=SECRETMARKER131 2.40.0\n"));
    assert!(!doc(&r, None).to_string().contains("SECRETMARKER131"));
}

#[test]
fn every_call_is_a_version_probe() {
    let r = answering(Output::success("2.40.0\n"));
    let _ = doc(&r, None);
    let calls = r.calls.borrow();
    let probes: Vec<String> = calls
        .iter()
        .map(|c| format!("{} {}", c.program, c.args.join(" ")))
        .collect();
    assert_eq!(
        probes,
        [
            "op --version",
            "flyctl version",
            "az version --output tsv",
            "kubectl version --client",
            "gh --version"
        ]
    );
}

#[test]
fn outside_a_project_no_provider_is_configured() {
    let r = answering(Output::success("2.40.0\n"));
    assert!(
        doc(&r, None)["providers"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p["configured"].is_null())
    );
}

#[test]
fn outside_a_project_there_is_no_configuration() {
    let r = answering(Output::success("2.40.0\n"));
    assert_eq!(doc(&r, None)["config"]["source"], "none");
}

#[test]
fn a_fly_target_makes_flyctl_configured() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.toml");
    std::fs::write(&path, FLY).unwrap();
    let r = answering(Output::success("2.40.0\n"));
    assert_eq!(doc(&r, Some(&path))["tools"][1]["configured"], true);
}

#[test]
fn an_unused_provider_cli_is_not_configured() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.toml");
    std::fs::write(&path, FLY).unwrap();
    let r = answering(Output::success("2.40.0\n"));
    assert_eq!(doc(&r, Some(&path))["tools"][2]["configured"], false);
}

#[test]
fn a_dot_opv_above_the_repository_root_is_no_configuration() {
    // C7 (09.08): `.opv` is found by the repository-root rule, never above the root.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".opv"), "account = \"AX\"\n").unwrap();
    let repo = dir.path().join("repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    let (report, _) = super::local_config(None, &repo);
    assert_eq!(report.source, "none");
}
