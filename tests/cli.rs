//! CLI wiring: exit codes and error format for paths that never spawn `op` or `flyctl`.

use std::process::Command;

fn opv(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_opv"))
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
        let (code, _, err) = opv(&args);
        assert_eq!(code, 2, "{cmd:?}: {err}");
        assert!(
            err.starts_with("opv: configuration error: undefined environment \"qa\""),
            "{cmd:?}: {err}"
        );
    }
}

#[test]
fn missing_config_file_exits_2() {
    let (code, _, err) = opv(&["--config", "does-not-exist.toml", "status", "prod"]);
    assert_eq!(code, 2, "{err}");
    assert!(err.starts_with("opv: configuration error"), "{err}");
}

/// Run opv with `dir` as the working directory and no `op` or `flyctl` on PATH.
fn opv_in(dir: &std::path::Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_opv"))
        .args(args)
        .current_dir(dir)
        .env_remove("OP_SERVICE_ACCOUNT_TOKEN")
        .env("PATH", "")
        .output()
        .unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

/// A temp dir with a valid `secrets.toml` at its root and a `nested` child to run from.
fn dir_with_ancestor_config() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("secrets.toml"),
        std::fs::read_to_string(CFG).unwrap(),
    )
    .unwrap();
    let nested = dir.path().join("nested");
    std::fs::create_dir_all(&nested).unwrap();
    (dir, nested)
}

#[test]
fn discovered_config_is_announced_once_on_stderr() {
    let (_dir, nested) = dir_with_ancestor_config();
    let (_, _, err) = opv_in(&nested, &["status", "qa"]);
    let announced: Vec<&str> = err
        .lines()
        .filter_map(|l| l.strip_prefix("using "))
        .collect();
    let expected = nested.parent().unwrap().join("secrets.toml");
    assert!(
        announced.len() == 1 && same_file(announced[0], &expected),
        "{err}"
    );
}

/// Paths compared as filesystem locations: on Windows the same directory can appear in
/// short (8.3) and long form, and `canonicalize` adds a `\\?\` prefix.
fn same_file(printed: &str, expected: &std::path::Path) -> bool {
    match (
        std::fs::canonicalize(printed),
        std::fs::canonicalize(expected),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

#[test]
fn discovery_loads_the_ancestor_config_for_the_command() {
    let (_dir, nested) = dir_with_ancestor_config();
    let (_, _, err) = opv_in(&nested, &["status", "qa"]);
    assert!(err.contains("undefined environment \"qa\""), "{err}");
}

#[test]
fn doctor_without_any_config_still_runs_its_other_checks() {
    let dir = tempfile::tempdir().unwrap();
    let (_, stdout, _) = opv_in(dir.path(), &["doctor"]);
    assert!(stdout.contains("op auth"), "{stdout}");
}

#[test]
fn missing_discovered_config_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("nested");
    std::fs::create_dir_all(&nested).unwrap();
    let (code, _, _) = opv_in(&nested, &["status", "prod"]);
    assert_eq!(code, 2);
}

#[test]
fn missing_discovered_config_names_starting_directory() {
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("nested");
    std::fs::create_dir_all(&nested).unwrap();
    let (_, _, err) = opv_in(&nested, &["status", "prod"]);
    let named = err
        .split("no secrets.toml found in ")
        .nth(1)
        .and_then(|rest| rest.split(" or any parent directory").next())
        .unwrap_or("");
    assert!(same_file(named, &nested), "{err}");
}

#[test]
fn missing_discovered_config_suggests_config_flag() {
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("nested");
    std::fs::create_dir_all(&nested).unwrap();
    let (_, _, err) = opv_in(&nested, &["status", "prod"]);
    assert!(err.contains("--config"), "{err}");
}

#[test]
fn explicit_config_suppresses_using_line() {
    let (_, _, err) = opv(&["--config", CFG, "status", "qa"]);
    assert!(!err.contains("using "), "{err}");
}

#[test]
fn top_level_help_describes_config_discovery() {
    let (_, out, _) = opv(&["--help"]);
    assert!(out.contains("parent"), "{out}");
}

#[test]
fn usage_errors_exit_2() {
    for args in [
        vec!["--config", CFG, "config", "export", "prod"], // --json is required
        vec!["--config", CFG, "fly", "sync"],
        vec!["nonsense"],
    ] {
        let (code, _, err) = opv(&args);
        assert_eq!(code, 2, "{args:?}: {err}");
    }
}

#[test]
fn invalid_rotate_entry_exits_2() {
    let (code, _, err) = opv(&[
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
    let (code, out, err) = opv(&["--config", CFG, "fly", "plan", "prod"]);
    assert_eq!(code, 3, "{err}");
    assert!(out.is_empty());
    assert!(err.starts_with("opv: dependency error"), "{err}");
}

#[test]
fn invalid_prune_immutable_entry_exits_2() {
    for extra in [
        &["--prune", "--prune-immutable", "allumata/OPENAI_API_KEY"][..], // not immutable
        &["--prune-immutable", "allumata/INTEGRATION_ENC_KEY"],           // without --prune
    ] {
        let mut args = vec!["--config", CFG, "fly", "sync", "prod"];
        args.extend(extra);
        let (code, _, err) = opv(&args);
        assert_eq!(code, 2, "{extra:?}: {err}");
        assert!(err.contains("--prune-immutable"), "{err}");
    }
}

#[test]
fn expect_no_change_is_not_a_flag() {
    let (code, _, err) = opv(&["--config", CFG, "fly", "sync", "prod", "--expect-no-change"]);
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
        let (code, _, err) = opv(&args);
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
        let (code, _, err) = opv(&args);
        assert_eq!(code, 3, "{cmd:?}: {err}");
    }
}

/// I7: top-level help has examples and the exit codes; no requirement IDs anywhere.
#[test]
fn help_has_examples_and_no_requirement_ids() {
    let (code, out, err) = opv(&["--help"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("Examples:"), "{out}");
    assert!(out.contains("opv item skeleton staging"), "{out}");
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
        let (_, out, _) = opv(&args);
        assert!(
            !out.contains("(FR-") && !out.contains("FR-1"),
            "{args:?}: {out}"
        );
        assert!(!out.contains("expect-no-change"), "{args:?}: {out}");
    }
    let (_, out, _) = opv(&["status", "--help"]);
    assert!(out.contains("Environment name"), "{out}");
}

#[test]
fn run_help_shows_usage() {
    let (code, out, err) = opv(&["run", "--help"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("Usage: opv run"), "{out}");
    assert!(out.contains("--product"), "{out}");
}

#[test]
fn run_requires_product_and_command() {
    for args in [
        vec!["--config", CFG, "run", "staging", "--", "true"],
        vec!["--config", CFG, "run", "staging", "--product", "allumata"],
    ] {
        let (code, _, err) = opv(&args);
        assert_eq!(code, 2, "{args:?}: {err}");
    }
}

#[test]
fn deprecated_signoz_transform_prints_a_warning_on_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("secrets.toml");
    let text = std::fs::read_to_string(CFG).unwrap();
    std::fs::write(
        &cfg,
        format!(
            "{text}\n[products.p.keys.TRACE]\nkind = \"secret\"\nenvironments = [\"prod\"]\nrules = {{ transform = \"signoz_ingestion_header\" }}\n"
        ),
    )
    .unwrap();
    let (_, _, err) = opv(&["--config", cfg.to_str().unwrap(), "status", "prod"]);
    assert!(
        err.contains("warning: p/TRACE: transform = \"signoz_ingestion_header\" is deprecated"),
        "{err}"
    );
}

const SIMPLE: &str = "tests/fixtures/simple.toml";

/// FR-20: doctor accepts a simple-profile file.
#[test]
fn doctor_reports_a_simple_profile_file_as_valid() {
    let (_, out, err) = opv(&["--config", SIMPLE, "doctor"]);
    assert!(
        out.contains("ok    config: valid (2 environment(s), 5 key(s))"),
        "{out}{err}"
    );
}

/// FR-20: `run` takes no --product under the simple profile.
#[test]
fn run_with_product_under_simple_exits_2() {
    let (code, _, err) = opv(&[
        "--config",
        SIMPLE,
        "run",
        "prod",
        "--product",
        "api",
        "--",
        "true",
    ]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("--product"), "{err}");
}

/// FR-20: a simple file with an unknown environment is still exit 2 before any call.
#[test]
fn simple_unknown_environment_exits_2_before_any_subprocess() {
    for cmd in [
        vec!["status", "qa"],
        vec!["fly", "plan", "qa"],
        vec!["fly", "sync", "qa"],
        vec!["config", "export", "qa", "--json"],
        vec!["item", "skeleton", "qa"],
    ] {
        let mut args = vec!["--config", SIMPLE];
        args.extend(&cmd);
        let (code, _, err) = opv(&args);
        assert_eq!(code, 2, "{cmd:?}: {err}");
    }
}

#[cfg(unix)]
mod run_with_fake_op {
    use super::CFG;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::OnceLock;

    /// The fake `op`, written once per test binary and closed before any test here spawns
    /// it. Writing an executable while another thread forks lets the child inherit the
    /// write fd, and a later exec of it fails with ETXTBSY (exit 3, a flaky test). The fake
    /// logs to `$FAKE_OP_LOG`, so one copy serves every test; each test gets a symlink.
    fn shared_fake_op() -> &'static Path {
        static FAKE: OnceLock<PathBuf> = OnceLock::new();
        FAKE.get_or_init(|| {
            let dir = std::env::temp_dir().join(format!("opv-cli-fake-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let op = dir.join("op");
            std::fs::write(
                &op,
                "#!/bin/sh\necho called >> \"$FAKE_OP_LOG\"\nwhile [ \"$1\" != -- ]; do shift; done\nshift\nexec \"$@\"\n",
            )
            .unwrap();
            std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o755)).unwrap();
            op
        })
    }

    /// A per-test PATH dir holding a symlink to the shared fake `op`, and its call log.
    fn fake_op_dir(name: &str) -> (PathBuf, PathBuf) {
        let op = shared_fake_op();
        let dir = std::env::temp_dir().join(format!("opv-cli-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink(op, dir.join("op")).unwrap();
        let log = dir.join("calls.log");
        (dir, log)
    }

    fn run(path: &std::path::Path, args: &[&str]) -> (i32, String, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_opv"))
            .args(["--config", CFG])
            .args(args)
            .env_remove("OP_SERVICE_ACCOUNT_TOKEN")
            .env("FAKE_OP_LOG", path.join("calls.log"))
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
            err.starts_with("opv: configuration error: undefined environment \"qa\""),
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
        assert!(err.is_empty(), "no opv message for a child exit: {err}");
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

    /// FR-20: under the simple profile the child sees unsectioned field references.
    #[test]
    fn simple_child_sees_unsectioned_op_references() {
        let (dir, _) = fake_op_dir("simple-env");
        let out = Command::new(env!("CARGO_BIN_EXE_opv"))
            .args(["--config", super::SIMPLE, "run", "prod", "--"])
            .args(["sh", "-c", "printf %s \"$JWT_KEY\""])
            .env_remove("OP_SERVICE_ACCOUNT_TOKEN")
            .env("PATH", format!("{}:/usr/bin:/bin", dir.display()))
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0));
        assert_eq!(
            String::from_utf8(out.stdout).unwrap(),
            "op://vprd/iprd/JWT_KEY"
        );
    }

    #[test]
    fn missing_op_exits_3() {
        let out = Command::new(env!("CARGO_BIN_EXE_opv"))
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

/// FR-22: `explain` reads only the configuration, so it succeeds with no `op` or `flyctl`.
#[test]
fn explain_runs_without_op_or_flyctl() {
    let (code, out, err) = opv(&[
        "--config",
        CFG,
        "explain",
        "allumata/OPENAI_API_KEY",
        "--env",
        "prod",
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("op item get iprd --vault vprd"), "{out}");
}

/// FR-22: the printed `op` command never contains `--reveal`.
#[test]
fn explain_never_prints_reveal() {
    let (_, out, err) = opv(&[
        "--config",
        CFG,
        "explain",
        "allumata/OPENAI_API_KEY",
        "--env",
        "prod",
    ]);
    assert!(
        !out.contains("--reveal") && !err.contains("--reveal"),
        "{out}{err}"
    );
}

/// FR-22: an undeclared key is a configuration error (exit 2).
#[test]
fn explain_undeclared_key_exits_2() {
    let (code, _, err) = opv(&["--config", CFG, "explain", "allumata/NOPE", "--env", "prod"]);
    assert_eq!(code, 2, "{err}");
    assert!(err.starts_with("opv: configuration error"), "{err}");
}

/// FR-22, FR-20: under the simple profile `explain` takes the bare key.
#[test]
fn explain_simple_form_takes_the_bare_key() {
    let (code, out, err) = opv(&[
        "--config",
        SIMPLE,
        "explain",
        "DATABASE_URL",
        "--env",
        "prod",
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(out.starts_with("DATABASE_URL in prod\n"), "{out}");
}

/// FR-22, FR-20: `<product>/<key>` under the simple profile is a configuration error.
#[test]
fn explain_product_form_under_simple_exits_2() {
    let (code, _, err) = opv(&[
        "--config",
        SIMPLE,
        "explain",
        "app/DATABASE_URL",
        "--env",
        "prod",
    ]);
    assert_eq!(code, 2, "{err}");
}

/// FR-22, FR-20: a bare key under the fleet profile is a configuration error.
#[test]
fn explain_bare_key_under_fleet_exits_2() {
    let (code, _, err) = opv(&[
        "--config",
        CFG,
        "explain",
        "OPENAI_API_KEY",
        "--env",
        "prod",
    ]);
    assert_eq!(code, 2, "{err}");
}
