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
