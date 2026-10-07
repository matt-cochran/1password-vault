//! CLI wiring: exit codes and error format for paths that never spawn `op` or `flyctl`.

use std::process::Command;

fn secretctl(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_secretctl"))
        .args(args)
        .env_remove("OP_SERVICE_ACCOUNT_TOKEN")
        // An empty PATH guarantees no real `op` or `flyctl` can run from these tests.
        .env("PATH", "")
        .output()
        .unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

const CFG: &str = "tests/fixtures/secrets.toml";

#[test]
fn unknown_environment_exits_2_before_any_subprocess() {
    for cmd in [
        vec!["status", "qa"],
        vec!["fly", "plan", "qa"],
        vec!["fly", "sync", "qa"],
        vec!["config", "export", "qa", "--json"],
        vec!["item", "skeleton", "qa"],
    ] {
        let mut args = vec!["--config", CFG];
        args.extend(&cmd);
        let (code, _, err) = secretctl(&args);
        assert_eq!(code, 2, "{cmd:?}: {err}");
        assert!(
            err.starts_with("secretctl: configuration error: undefined environment \"qa\""),
            "{cmd:?}: {err}"
        );
    }
}

#[test]
fn missing_config_file_exits_2() {
    let (code, _, err) = secretctl(&["--config", "does-not-exist.toml", "status", "prod"]);
    assert_eq!(code, 2, "{err}");
    assert!(err.starts_with("secretctl: configuration error"), "{err}");
}

#[test]
fn usage_errors_exit_2() {
    for args in [
        vec!["--config", CFG, "config", "export", "prod"], // --json is required
        vec!["--config", CFG, "fly", "sync"],
        vec!["nonsense"],
    ] {
        let (code, _, err) = secretctl(&args);
        assert_eq!(code, 2, "{args:?}: {err}");
    }
}

#[test]
fn invalid_rotate_entry_exits_2() {
    let (code, _, err) = secretctl(&[
        "--config",
        CFG,
        "fly",
        "sync",
        "prod",
        "--rotate",
        "allumata/OPENAI_API_KEY",
    ]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("allumata/OPENAI_API_KEY"), "{err}");
}

/// With no `op` on PATH the read fails cleanly as a dependency error (exit 3).
#[test]
fn missing_op_exits_3() {
    let (code, out, err) = secretctl(&["--config", CFG, "fly", "plan", "prod"]);
    assert_eq!(code, 3, "{err}");
    assert!(out.is_empty());
    assert!(err.starts_with("secretctl: dependency error"), "{err}");
}

#[test]
fn invalid_prune_immutable_entry_exits_2() {
    for extra in [
        &["--prune", "--prune-immutable", "allumata/OPENAI_API_KEY"][..], // not immutable
        &["--prune-immutable", "allumata/INTEGRATION_ENC_KEY"],           // without --prune
    ] {
        let mut args = vec!["--config", CFG, "fly", "sync", "prod"];
        args.extend(extra);
        let (code, _, err) = secretctl(&args);
        assert_eq!(code, 2, "{extra:?}: {err}");
        assert!(err.contains("--prune-immutable"), "{err}");
    }
}

#[test]
fn expect_no_change_is_not_a_flag() {
    let (code, _, err) = secretctl(&["--config", CFG, "fly", "sync", "prod", "--expect-no-change"]);
    assert_eq!(code, 2, "{err}");
}

/// I5: an environment without a `fly` section works for run-only use; the Fly commands and
/// status exit 2 naming it, before any subprocess (PATH is empty).
#[test]
fn env_without_fly_section_exits_2_for_fly_commands() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("secrets.toml");
    let text = std::fs::read_to_string(CFG).unwrap();
    std::fs::write(
        &cfg,
        format!("{text}\n[environments.dev]\nvault_id = \"vdev\"\nitem_id = \"idev\"\n"),
    )
    .unwrap();
    let cfg = cfg.to_str().unwrap();
    for cmd in [
        vec!["status", "dev"],
        vec!["fly", "plan", "dev"],
        vec!["fly", "sync", "dev"],
    ] {
        let mut args = vec!["--config", cfg];
        args.extend(&cmd);
        let (code, _, err) = secretctl(&args);
        assert_eq!(code, 2, "{cmd:?}: {err}");
        assert!(
            err.contains("environment \"dev\" has no fly section"),
            "{cmd:?}: {err}"
        );
    }
    // config export and item skeleton get past config to the 1Password read (op missing: 3).
    for cmd in [
        vec!["config", "export", "dev", "--json"],
        vec!["item", "skeleton", "dev"],
    ] {
        let mut args = vec!["--config", cfg];
        args.extend(&cmd);
        let (code, _, err) = secretctl(&args);
        assert_eq!(code, 3, "{cmd:?}: {err}");
    }
}

/// I7: top-level help has examples and the exit codes; no requirement IDs anywhere.
#[test]
fn help_has_examples_and_no_requirement_ids() {
    let (code, out, err) = secretctl(&["--help"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("Examples:"), "{out}");
    assert!(out.contains("secretctl item skeleton staging"), "{out}");
    assert!(out.contains("7 authentication"), "{out}");
    assert!(
        out.contains("<ENV>") || out.contains("environment defined"),
        "{out}"
    );
    for args in [
        vec!["--help"],
        vec!["status", "--help"],
        vec!["fly", "sync", "--help"],
        vec!["fly", "plan", "--help"],
        vec!["run", "--help"],
        vec!["doctor", "--help"],
        vec!["item", "skeleton", "--help"],
        vec!["config", "export", "--help"],
    ] {
        let (_, out, _) = secretctl(&args);
        assert!(
            !out.contains("(FR-") && !out.contains("FR-1"),
            "{args:?}: {out}"
        );
        assert!(!out.contains("expect-no-change"), "{args:?}: {out}");
    }
    let (_, out, _) = secretctl(&["status", "--help"]);
    assert!(out.contains("Environment name"), "{out}");
}

#[test]
fn run_help_shows_usage() {
    let (code, out, err) = secretctl(&["run", "--help"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("Usage: secretctl run"), "{out}");
    assert!(out.contains("--product"), "{out}");
}

#[test]
fn run_requires_product_and_command() {
    for args in [
        vec!["--config", CFG, "run", "staging", "--", "true"],
        vec!["--config", CFG, "run", "staging", "--product", "allumata"],
    ] {
        let (code, _, err) = secretctl(&args);
        assert_eq!(code, 2, "{args:?}: {err}");
    }
}

#[cfg(unix)]
mod run_with_fake_op {
    use super::CFG;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::process::Command;

    /// Install a fake `op` that logs each invocation, then execs the args after `--`.
    fn fake_op_dir(name: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("secretctl-cli-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("calls.log");
        let script = format!(
            "#!/bin/sh\necho called >> '{}'\nwhile [ \"$1\" != -- ]; do shift; done\nshift\nexec \"$@\"\n",
            log.display()
        );
        let op = dir.join("op");
        std::fs::write(&op, script).unwrap();
        std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o755)).unwrap();
        (dir, log)
    }

    fn run(path: &std::path::Path, args: &[&str]) -> (i32, String, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_secretctl"))
            .args(["--config", CFG])
            .args(args)
            .env_remove("OP_SERVICE_ACCOUNT_TOKEN")
            .env("PATH", format!("{}:/usr/bin:/bin", path.display()))
            .output()
            .unwrap();
        (
            out.status.code().unwrap(),
            String::from_utf8(out.stdout).unwrap(),
            String::from_utf8(out.stderr).unwrap(),
        )
    }

    #[test]
    fn unknown_env_exits_2_without_calling_op() {
        let (dir, log) = fake_op_dir("unknown");
        let (code, _, err) = run(&dir, &["run", "qa", "--product", "allumata", "--", "true"]);
        assert_eq!(code, 2, "{err}");
        assert!(
            err.starts_with("secretctl: configuration error: undefined environment \"qa\""),
            "{err}"
        );
        assert!(!log.exists(), "op must not be invoked");
    }

    #[test]
    fn child_exit_code_is_propagated_exactly() {
        let (dir, log) = fake_op_dir("exit7");
        let (code, _, err) = run(
            &dir,
            &[
                "run",
                "staging",
                "--product",
                "allumata",
                "--",
                "sh",
                "-c",
                "exit 7",
            ],
        );
        assert_eq!(code, 7, "{err}");
        assert!(
            err.is_empty(),
            "no secretctl message for a child exit: {err}"
        );
        assert_eq!(std::fs::read_to_string(log).unwrap().lines().count(), 1);
    }

    #[test]
    fn child_sees_op_references_not_values() {
        let (dir, _) = fake_op_dir("env");
        let (code, out, err) = run(
            &dir,
            &[
                "run",
                "staging",
                "--product",
                "allumata",
                "--",
                "sh",
                "-c",
                "printf %s \"$INTEGRATION_ENC_KEY\"",
            ],
        );
        assert_eq!(code, 0, "{err}");
        assert_eq!(out, "op://vstg/istg/allumata/INTEGRATION_ENC_KEY");
    }

    #[test]
    fn missing_op_exits_3() {
        let out = Command::new(env!("CARGO_BIN_EXE_secretctl"))
            .args([
                "--config",
                CFG,
                "run",
                "staging",
                "--product",
                "allumata",
                "--",
                "true",
            ])
            .env("PATH", "")
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(3));
    }
}
