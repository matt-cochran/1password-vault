//! #263, #264: `opv run <env> --product input` run as the real binary, against one boundary
//! item shared with an `output` product whose keys are empty or supplied at sync. Design:
//! `docs/design/product-scoped-run.md` §6 (B1-B5).
//!
//! The fake `op` on PATH serves the item JSON for `item get` and, for `run --`, only execs
//! the child with the environment it was given, as `tests/local_delivery.rs` does. It
//! resolves no reference. Values are test markers; the child prints names only.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Output};

/// Like `op`: `item get` prints `item.json` from the working directory, the identity is a
/// service account, and `run` execs the command after `--`.
const FAKE_OP: &str = "#!/bin/sh\ncase \"$1\" in\n  item) cat item.json; exit 0 ;;\n  whoami) echo '{\"user_type\":\"SERVICE_ACCOUNT\"}'; exit 0 ;;\n  account) echo '[]'; exit 0 ;;\nesac\nwhile [ \"$1\" != -- ]; do shift; done\nshift\nexec \"$@\"\n";

/// One boundary `acceptance` holding `input` (A, B: filled) and `output` (X, Y: empty; Z:
/// supplied at sync). The load requires a target and a shape rule for Z; `run` never reads
/// the target.
const CONFIG: &str = r#"
[environments.prod]
boundaries.acceptance = { vault_id = "vdev", item_id = "idev" }

[environments.prod.targets.web]
fly.app = "web-prod"
fly.secret_name = "{KEY}"
products = ["output"]
state_vault_id = "sprod"

[products.input]
boundary = "acceptance"

[products.input.keys.A]
kind = "secret"
environments = ["prod"]

[products.input.keys.B]
kind = "secret"
environments = ["prod"]

[products.output]
boundary = "acceptance"

[products.output.keys.X]
kind = "secret"
environments = ["prod"]

[products.output.keys.Y]
kind = "secret"
environments = ["prod"]

[products.output.keys.Z]
kind = "secret"
source = "infrastructure"
environments = ["prod"]
rules = { regex = "z-.+" }
"#;

/// A marker standing in for an infrastructure value the parent environment carries.
const Z_MARKER: &str = "z-test-marker-264";

/// The fake `op`'s directory, written once per test binary before any test spawns it (a
/// write racing another thread's fork can make its exec fail with ETXTBSY).
fn fake_bin() -> &'static Path {
    static BIN: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    BIN.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let op = dir.path().join("op");
        std::fs::write(&op, FAKE_OP).unwrap();
        std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o755)).unwrap();
        dir
    })
    .path()
}

/// The boundary item: A and B filled unless named in `empty`, X and Y empty, Z absent,
/// every field in its product's section.
fn item_json(empty: &[&str]) -> String {
    let field = |i: usize, section: &str, label: &str, value: &str| {
        let value = if value.is_empty() {
            String::new()
        } else {
            format!(r#","value":"{value}""#)
        };
        format!(
            r#"{{"id":"f{i}","type":"CONCEALED","label":"{label}","section":{{"id":"s_{section}","label":"{section}"}}{value}}}"#
        )
    };
    let filled = |k: &str, v: &'static str| if empty.contains(&k) { "" } else { v };
    let fields = [
        r#"{"id":"notesPlain","type":"STRING","purpose":"NOTES","label":"notesPlain"}"#
            .to_string(),
        field(0, "input", "A", filled("A", "a-test-marker")),
        field(1, "input", "B", filled("B", "b-test-marker")),
        field(2, "output", "X", ""),
        field(3, "output", "Y", ""),
        r#"{"id":"f4","type":"STRING","label":"convention","section":{"id":"s_opv","label":"opv"},"value":"1"}"#
            .to_string(),
    ];
    format!(
        r#"{{"id":"idev","title":"prod","version":1,"vault":{{"id":"vdev","name":"prod"}},"category":"SECURE_NOTE","updated_at":"2026-10-08T00:00:00Z","sections":[{{"id":"s_input","label":"input"}},{{"id":"s_output","label":"output"}},{{"id":"s_opv","label":"opv"}}],"fields":[{}]}}"#,
        fields.join(",")
    )
}

/// `opv run prod --product input <args>` with `parent` added to a clean environment, the
/// item's `empty` keys emptied.
fn opv_run(args: &[&str], empty: &[&str], parent: &[(&str, &str)]) -> Output {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("secrets.toml");
    // The 1Password ids go to `secrets.bindings.toml`, as the loader requires.
    opv::config::bindings::write_split(&config, CONFIG).unwrap();
    std::fs::write(root.path().join("item.json"), item_json(empty)).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_opv"));
    cmd.args(["--config", config.to_str().unwrap()])
        .args(["run", "prod", "--product", "input"])
        .args(args)
        .env_clear()
        .env("PATH", format!("{}:/usr/bin:/bin", fake_bin().display()))
        .env("HOME", root.path())
        .current_dir(root.path());
    for (k, v) in parent {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

/// `opv run prod --product input --confirm prod -- sh -c <script>`.
fn run_child(script: &str, empty: &[&str], parent: &[(&str, &str)]) -> Output {
    opv_run(
        &["--confirm", "prod", "--", "sh", "-c", script],
        empty,
        parent,
    )
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The variable names the child sees (names only, never a value).
fn child_names(parent: &[(&str, &str)]) -> Vec<String> {
    let out = run_child("env | cut -d= -f1", &[], parent);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect()
}

#[test]
fn run_input_exits_with_the_childs_code() {
    let out = run_child("exit 0", &[], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
}

#[test]
fn run_input_stderr_names_no_output_product() {
    let out = run_child("exit 0", &["A"], &[]);
    assert!(!stderr(&out).contains("output/"), "{}", stderr(&out));
}

#[test]
fn run_input_stderr_names_its_own_empty_key() {
    let out = run_child("exit 0", &["A"], &[]);
    assert!(stderr(&out).contains("input/A"), "{}", stderr(&out));
}

#[test]
fn run_input_child_sees_no_stored_output_name() {
    let names = child_names(&[("X", "x-test-marker-263")]);
    assert!(!names.iter().any(|n| n == "X"), "{names:?}");
}

#[test]
fn run_input_preview_json_lists_only_input_keys() {
    let out = opv_run(&["--preview", "--json"], &[], &[]);
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
    let products: Vec<&str> = doc["keys"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|k| k["product"].as_str())
        .collect();
    assert!(
        out.status.success() && !products.is_empty() && products.iter().all(|p| *p == "input"),
        "{products:?} {}",
        stderr(&out)
    );
}

#[test]
fn run_input_child_keeps_an_inherited_infrastructure_name() {
    let names = child_names(&[("Z", Z_MARKER)]);
    assert!(names.iter().any(|n| n == "Z"), "{names:?}");
}
