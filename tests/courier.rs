//! Courier invariant over every transport (design `assistant-guided-setup.md` §"CI runs
//! opv", row `courier-test`): a value goes from opv to its tool on stdin only, never argv,
//! the child environment, a file opv wrote or the rendered output.
//!
//! Each transport drives its public write path with a value `S7MARKER-courier-<transport>`
//! through `opv::runner::fake::FakeRunner`, so every platform call and its stdin, argv and
//! environment are recorded. Reads are answered from the recorded fixtures under
//! `tests/fixtures/`. The marker scan looks at the recorded argv, the recorded child
//! environment, every file under a fresh temp directory and the write path's rendered
//! output; a separate test asserts the marker is on the recorded stdin.
//!
//! Local delivery is in-process and has no platform tool: its channel is the developer
//! app's environment or a private tmpfs file (`docs/design/delivery-transports.md` §5,
//! #136/#137), so its courier tests pin that the marker reaches the child through its
//! declared channel only, never a file key's variable.
#![cfg(feature = "fake")]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use opv::adapters::azure::keyvault::KeyVault;
use opv::adapters::fly;
use opv::adapters::github::Scope;
use opv::adapters::github::gh;
use opv::adapters::kubernetes::KubeSecrets;
use opv::adapters::kubernetes::KubeTarget;
use opv::app::local_delivery::{Delivery, child_env};
use opv::domain::{SecretValue, Stamp};
use opv::ports::PinnedStore;
use opv::runner::Output;
use opv::runner::fake::FakeRunner;

/// The recorded Deployment `store.rs` reads before a write (K1 fixture).
const DEPLOYMENT: &str = include_str!("fixtures/kubernetes/deployment-get.json");

/// Fixed hex version the Key Vault `set` answer and its confirm read carry.
const KV_VERSION: &str = "46687ce78b76487cb0c1da470360b638";

fn stamp() -> Stamp {
    Stamp::now("dev", "7f3c9a1e")
}

/// Every file under `dir`, recursively.
fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            files_under(&path, out);
        } else {
            out.push(path);
        }
    }
}

/// The side channels `marker` reached during a write: the recorded argv, the recorded
/// child environment, the rendered output and any file under `temp`. Empty is the courier
/// invariant holding.
fn exposures(runner: &FakeRunner, temp: &Path, output: &str, marker: &str) -> Vec<&'static str> {
    let mut found = Vec::new();
    let calls = runner.calls.borrow();
    if calls
        .iter()
        .any(|c| c.program.contains(marker) || c.args.iter().any(|a| a.contains(marker)))
    {
        found.push("argv");
    }
    if calls.iter().any(|c| {
        c.env
            .iter()
            .any(|(k, v)| k.contains(marker) || v.contains(marker))
    }) {
        found.push("the child environment");
    }
    drop(calls);
    if output.contains(marker) {
        found.push("output");
    }
    let mut files = Vec::new();
    files_under(temp, &mut files);
    let needle = marker.as_bytes();
    if files
        .iter()
        .any(|p| std::fs::read(p).is_ok_and(|b| b.windows(needle.len()).any(|w| w == needle)))
    {
        found.push("a file");
    }
    found
}

/// The single courier assertion: the marker reached no side channel.
fn assert_unexposed(runner: &FakeRunner, temp: &Path, output: &str, marker: &str) {
    let leaked = exposures(runner, temp, output, marker);
    assert!(
        leaked.is_empty(),
        "the marker reached {}",
        leaked.join(", ")
    );
}

/// Every byte every recorded call sent on stdin.
fn stdin_bytes(runner: &FakeRunner) -> Vec<u8> {
    runner
        .calls
        .borrow()
        .iter()
        .flat_map(|c| c.stdin.clone().unwrap_or_default())
        .collect()
}

fn kube_target() -> KubeTarget {
    KubeTarget {
        context: "kind-opv".into(),
        namespace: "opv-spike".into(),
        deployment: "api".into(),
        container: None,
        env: "dev".into(),
    }
}

fn kv_id() -> String {
    format!("https://courier-kv.vault.azure.net/secrets/courier-kv/{KV_VERSION}")
}

fn key_vault(r: &FakeRunner) -> KeyVault<'_> {
    KeyVault {
        runner: r,
        vault: "courier-kv",
        subscription: "00000000-0000-0000-0000-000000000000",
        env: "dev",
        managed: BTreeSet::new(),
    }
}

fn one_repo() -> Vec<String> {
    vec!["example-org/example-repo".to_string()]
}

// ---------------------------------------------------------------- Fly

#[test]
fn the_fly_courier_keeps_the_marker_out_of_every_side_channel() {
    let marker = "S7MARKER-courier-fly";
    let temp = tempfile::tempdir().unwrap();
    let r = FakeRunner::new([Output::success("")]);
    let value = SecretValue::new(marker.to_string());
    fly::stage(&r, "courier-app", &[("COURIER_FLY".into(), &value)]).unwrap();
    assert_unexposed(&r, temp.path(), "", marker);
}

#[test]
fn the_fly_courier_sends_the_marker_on_stdin() {
    let marker = "S7MARKER-courier-fly";
    let r = FakeRunner::new([Output::success("")]);
    let value = SecretValue::new(marker.to_string());
    fly::stage(&r, "courier-app", &[("COURIER_FLY".into(), &value)]).unwrap();
    assert!(String::from_utf8_lossy(&stdin_bytes(&r)).contains(marker));
}

// ---------------------------------------------------------------- Kubernetes

#[test]
fn the_kubernetes_courier_keeps_the_marker_out_of_every_side_channel() {
    let marker = "S7MARKER-courier-kubernetes";
    let temp = tempfile::tempdir().unwrap();
    let r = FakeRunner::new([Output::success(DEPLOYMENT), Output::success("")]);
    let target = kube_target();
    let store = KubeSecrets::new(&r, &target, BTreeSet::new());
    let value = SecretValue::new(marker.to_string());
    // The apply's answer cannot name the random version, so the write errors after it sent
    // its manifest; the recorded call and its stdin are what the courier test reads.
    let output = store
        .write_one("COURIER_K8S", &value, &stamp())
        .err()
        .map(|e| format!("{e} {e:?}"))
        .unwrap_or_default();
    assert_unexposed(&r, temp.path(), &output, marker);
}

#[test]
fn the_kubernetes_courier_sends_the_marker_on_stdin() {
    use base64::Engine as _;
    let marker = "S7MARKER-courier-kubernetes";
    let encoded = base64::engine::general_purpose::STANDARD.encode(marker);
    let r = FakeRunner::new([Output::success(DEPLOYMENT), Output::success("")]);
    let target = kube_target();
    let store = KubeSecrets::new(&r, &target, BTreeSet::new());
    let value = SecretValue::new(marker.to_string());
    let _ = store.write_one("COURIER_K8S", &value, &stamp());
    assert!(String::from_utf8_lossy(&stdin_bytes(&r)).contains(encoded.as_str()));
}

// ---------------------------------------------------------------- Azure Key Vault

#[test]
fn the_key_vault_courier_keeps_the_marker_out_of_every_side_channel() {
    let marker = "S7MARKER-courier-keyvault";
    let temp = tempfile::tempdir().unwrap();
    let r = FakeRunner::new([Output::success(kv_id()), Output::success(kv_id())]);
    let value = SecretValue::new(marker.to_string());
    key_vault(&r)
        .write_one("COURIER_KV", &value, &stamp())
        .unwrap();
    assert_unexposed(&r, temp.path(), "", marker);
}

#[test]
fn the_key_vault_courier_sends_the_marker_on_stdin() {
    let marker = "S7MARKER-courier-keyvault";
    let r = FakeRunner::new([Output::success(kv_id()), Output::success(kv_id())]);
    let value = SecretValue::new(marker.to_string());
    key_vault(&r)
        .write_one("COURIER_KV", &value, &stamp())
        .unwrap();
    assert_eq!(stdin_bytes(&r), marker.as_bytes());
}

// ---------------------------------------------------------------- GitHub secrets

#[test]
fn the_github_secret_courier_keeps_the_marker_out_of_every_side_channel() {
    let marker = "S7MARKER-courier-github-secret";
    let temp = tempfile::tempdir().unwrap();
    let r = FakeRunner::new([Output::success("")]);
    let repos = one_repo();
    let value = SecretValue::new(marker.to_string());
    gh::set_secrets(
        &r,
        Scope {
            repos: &repos,
            environment: None,
        },
        &[("COURIER_GH_SECRET".into(), &value)],
    )
    .unwrap();
    assert_unexposed(&r, temp.path(), "", marker);
}

#[test]
fn the_github_secret_courier_sends_the_marker_on_stdin() {
    let marker = "S7MARKER-courier-github-secret";
    let r = FakeRunner::new([Output::success("")]);
    let repos = one_repo();
    let value = SecretValue::new(marker.to_string());
    gh::set_secrets(
        &r,
        Scope {
            repos: &repos,
            environment: None,
        },
        &[("COURIER_GH_SECRET".into(), &value)],
    )
    .unwrap();
    assert_eq!(stdin_bytes(&r), marker.as_bytes());
}

// ---------------------------------------------------------------- GitHub variables

#[test]
fn the_github_variable_courier_keeps_the_marker_out_of_every_side_channel() {
    let marker = "S7MARKER-courier-github-variable";
    let temp = tempfile::tempdir().unwrap();
    let r = FakeRunner::new([Output::success("")]);
    let repos = one_repo();
    gh::set_variables(
        &r,
        Scope {
            repos: &repos,
            environment: None,
        },
        &[("COURIER_GH_VARIABLE".into(), marker)],
    )
    .unwrap();
    assert_unexposed(&r, temp.path(), "", marker);
}

#[test]
fn the_github_variable_courier_sends_the_marker_on_stdin() {
    let marker = "S7MARKER-courier-github-variable";
    let r = FakeRunner::new([Output::success("")]);
    let repos = one_repo();
    gh::set_variables(
        &r,
        Scope {
            repos: &repos,
            environment: None,
        },
        &[("COURIER_GH_VARIABLE".into(), marker)],
    )
    .unwrap();
    assert_eq!(stdin_bytes(&r), marker.as_bytes());
}

// ---------------------------------------------------------------- local delivery

fn worker() -> Delivery {
    Delivery {
        keys: vec!["COURIER_LOCAL".into()],
        declared_only: true,
        files: Vec::new(),
        dir_env: None,
        command: Vec::new(),
    }
}

#[test]
fn the_local_courier_hands_the_marker_to_the_app_through_its_declared_variable() {
    let marker = "S7MARKER-courier-local";
    let inherited = vec![("COURIER_LOCAL".to_string(), marker.to_string())];
    let env = child_env(&worker(), &inherited, None);
    assert!(env.iter().any(|(k, v)| k == "COURIER_LOCAL" && v == marker));
}

#[test]
fn the_local_courier_hands_a_file_keys_marker_to_its_file_not_the_environment() {
    let marker = "S7MARKER-courier-local-file";
    let d = Delivery {
        keys: vec!["COURIER_LOCAL_FILE".into()],
        declared_only: true,
        files: vec![("COURIER_LOCAL_FILE".into(), "courier/secret".into())],
        dir_env: Some("COURIER_DIR".into()),
        command: Vec::new(),
    };
    let inherited = vec![("COURIER_LOCAL_FILE".to_string(), marker.to_string())];
    let env = child_env(&d, &inherited, Some("/run/user/1/opv-run.x"));
    assert!(!env.iter().any(|(_, v)| v == marker));
}
