//! Help, completions, environment defaults and colour (P5, P13, P14, P15, P17). None of
//! these paths spawns `op` or a target CLI.

use std::process::Command;

const CFG: &str = "tests/fixtures/secrets.toml";
const SIMPLE: &str = "tests/fixtures/simple.toml";

/// Run opv with `envs` set, no `op` or target CLI on PATH, and none of opv's own variables
/// inherited from the developer's shell.
fn opv_with(envs: &[(&str, &str)], args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_opv"));
    cmd.env_remove("GITHUB_STEP_SUMMARY"); // never the job summary of the run testing opv
    cmd.args(args)
        .env_remove("OP_SERVICE_ACCOUNT_TOKEN")
        .env_remove("OPV_CONFIG")
        .env_remove("OPV_PRODUCT")
        .env_remove("NO_COLOR")
        .env("PATH", "");
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

const COMMANDS: [&str; 8] = [
    "sync", "run", "check", "init", "explain", "doctor", "status", "plan",
];

#[test]
fn every_command_help_groups_global_options() {
    for c in COMMANDS {
        let (_, out, _) = opv_with(&[], &[c, "--help"]);
        assert!(out.contains("\nGlobal options: --config"), "{c}: {out}");
    }
}

#[test]
fn every_command_help_has_examples() {
    for c in COMMANDS {
        let (_, out, _) = opv_with(&[], &[c, "--help"]);
        assert!(out.contains("Examples:\n  opv "), "{c}: {out}");
    }
}

#[test]
fn command_options_come_before_global_options_in_sync_help() {
    let (_, out, _) = opv_with(&[], &["sync", "--help"]);
    assert!(
        out.find("--prune-immutable") < out.find("Global options:"),
        "{out}"
    );
}

#[test]
fn login_help_documents_environment_and_command() {
    let (_, out, _) = opv_with(&[], &["login", "--help"]);
    assert!(
        out.contains("account the environment uses") && out.contains("Command and arguments"),
        "{out}"
    );
}

#[test]
fn root_example_comments_are_aligned() {
    let (_, out, _) = opv_with(&[], &["--help"]);
    let cols: std::collections::BTreeSet<usize> = out
        .lines()
        .skip_while(|l| *l != "Examples:")
        .take_while(|l| !l.is_empty())
        .filter(|l| !l.contains(" -- ")) // the long run line overflows on purpose
        .filter_map(|l| l.find(" # "))
        .collect();
    assert_eq!(cols.len(), 1, "{out}");
}

#[test]
fn short_help_about_is_provider_neutral() {
    let (_, out, _) = opv_with(&[], &["-h"]);
    assert!(
        out.starts_with("Use 1Password settings in local apps and deployment targets"),
        "{out}"
    );
}

#[test]
fn exit_code_help_names_every_target_cli() {
    let (_, out, _) = opv_with(&[], &["--help"]);
    assert!(
        out.contains("3 dependency (op or the target CLI (flyctl, az,\n  kubectl) missing)")
            && out.contains("5 target (Fly, Azure, Kubernetes)"),
        "{out}"
    );
}

#[test]
fn config_export_no_longer_requires_json_flag() {
    let (_, _, err) = opv_with(&[], &["--config", CFG, "config", "export", "qa"]);
    assert!(err.contains("undefined environment \"qa\""), "{err}");
}

// --- completions (P13) ---

#[test]
fn completions_write_a_script_per_shell() {
    for shell in ["bash", "zsh", "fish", "powershell"] {
        let (code, out, err) = opv_with(&[], &["completions", shell]);
        assert!(code == 0 && out.contains("sync"), "{shell}: {code} {err}");
    }
}

#[test]
fn completions_help_has_install_lines() {
    let (_, out, _) = opv_with(&[], &["completions", "--help"]);
    assert!(
        ["bash", "zsh", "fish", "powershell"]
            .iter()
            .all(|s| out.contains(&format!("opv completions {s} "))),
        "{out}"
    );
}

#[test]
fn completions_for_an_unknown_shell_exit_2() {
    let (code, _, _) = opv_with(&[], &["completions", "tcsh"]);
    assert_eq!(code, 2);
}

// --- OPV_CONFIG (P14) ---

#[test]
fn opv_config_selects_the_configuration() {
    let (_, _, err) = opv_with(&[("OPV_CONFIG", CFG)], &["status", "qa"]);
    assert!(err.contains("undefined environment \"qa\""), "{err}");
}

#[test]
fn opv_config_is_announced_on_stderr() {
    let (_, _, err) = opv_with(&[("OPV_CONFIG", CFG)], &["status", "qa"]);
    assert!(
        err.starts_with(&format!("using {CFG} (from OPV_CONFIG)\n")),
        "{err}"
    );
}

#[test]
fn config_flag_overrides_opv_config() {
    let (_, _, err) = opv_with(
        &[("OPV_CONFIG", "does-not-exist.toml")],
        &["--config", CFG, "status", "qa"],
    );
    assert!(err.contains("undefined environment \"qa\""), "{err}");
}

#[test]
fn config_help_shows_opv_config() {
    let (_, out, _) = opv_with(&[], &["--help"]);
    assert!(out.contains("[env: OPV_CONFIG"), "{out}");
}

#[test]
fn init_refuses_opv_config() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_opv"))
        .env_remove("GITHUB_STEP_SUMMARY") // never the job summary of the run testing opv
        .args(["init", "dev", "--vault", "v", "--item", "i"])
        .current_dir(dir.path())
        .env("OPV_CONFIG", "elsewhere.toml")
        .env("PATH", "")
        .output()
        .unwrap();
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(
        err.contains("OPV_CONFIG is set; unset it for init"),
        "{err}"
    );
}

// --- OPV_PRODUCT (P15) ---

const EXPLAIN_BARE: [&str; 6] = [
    "--config",
    CFG,
    "explain",
    "OPENAI_API_KEY",
    "--env",
    "prod",
];

#[test]
fn opv_product_completes_a_bare_explain_key() {
    let (code, _, err) = opv_with(&[("OPV_PRODUCT", "allumata")], &EXPLAIN_BARE);
    assert_eq!(code, 0, "{err}");
}

#[test]
fn opv_product_is_reported_on_stderr() {
    let (_, _, err) = opv_with(&[("OPV_PRODUCT", "allumata")], &EXPLAIN_BARE);
    assert!(
        err.contains("product allumata (from OPV_PRODUCT)\n"),
        "{err}"
    );
}

#[test]
fn product_flag_is_not_reported_as_from_opv_product() {
    let (_, _, err) = opv_with(
        &[("OPV_PRODUCT", "allumata")],
        &["--config", CFG, "check", "qa", "--product", "allumata"],
    );
    assert!(!err.contains("OPV_PRODUCT"), "{err}");
}

#[test]
fn opv_product_is_ignored_under_the_simple_profile() {
    let (code, _, err) = opv_with(
        &[("OPV_PRODUCT", "app")],
        &[
            "--config",
            SIMPLE,
            "explain",
            "DATABASE_URL",
            "--env",
            "prod",
        ],
    );
    assert_eq!(code, 0, "{err}");
}

#[test]
fn opv_product_does_not_satisfy_doctor_without_env() {
    let (_, _, err) = opv_with(&[("OPV_PRODUCT", "allumata")], &["--config", CFG, "doctor"]);
    assert!(!err.contains("OPV_PRODUCT"), "{err}");
}

// --- colour (P17) ---

fn has_escape(s: &str) -> bool {
    s.contains('\x1b')
}

#[test]
fn piped_output_has_no_escape_codes() {
    let (_, out, _) = opv_with(&[], &["--config", CFG, "doctor"]);
    assert!(!has_escape(&out), "{out:?}");
}

#[test]
fn no_color_gives_no_escape_codes() {
    let (_, out, _) = opv_with(&[("NO_COLOR", "1")], &["--config", CFG, "doctor"]);
    assert!(!has_escape(&out), "{out:?}");
}

#[test]
fn color_always_colours_doctor_state_words() {
    let (_, out, _) = opv_with(&[], &["--color", "always", "--config", CFG, "doctor"]);
    assert!(out.contains("\x1b[31mFAIL\x1b[0m  op"), "{out:?}");
}

#[test]
fn color_always_leaves_text_otherwise_identical() {
    let (_, plain, _) = opv_with(&[], &["--config", CFG, "doctor"]);
    let (_, coloured, _) = opv_with(&[], &["--color", "always", "--config", CFG, "doctor"]);
    let stripped = regex::Regex::new("\x1b\\[[0-9;]*m")
        .unwrap()
        .replace_all(&coloured, "")
        .into_owned();
    assert_eq!(stripped, plain);
}

#[test]
fn color_always_never_colours_explain() {
    let (_, out, _) = opv_with(
        &[],
        &[
            "--color",
            "always",
            "--config",
            CFG,
            "explain",
            "allumata/OPENAI_API_KEY",
            "--env",
            "prod",
        ],
    );
    assert!(!has_escape(&out), "{out:?}");
}

/// P12: OPV_PRODUCT is the default for --product on status (checked before any call).
#[test]
fn opv_product_applies_to_status() {
    let (_, _, err) = opv_with(
        &[("OPV_PRODUCT", "nope")],
        &["--config", CFG, "status", "prod"],
    );
    assert!(
        err.starts_with("product nope (from OPV_PRODUCT)\n"),
        "{err}"
    );
}

#[test]
fn opv_product_applies_to_plan() {
    let (code, _, _) = opv_with(
        &[("OPV_PRODUCT", "nope")],
        &["--config", CFG, "plan", "prod"],
    );
    assert_eq!(code, 2);
}

/// P20: sync never takes its product from the environment.
#[test]
fn opv_product_is_never_used_by_sync() {
    let (_, _, err) = opv_with(
        &[("OPV_PRODUCT", "nope")],
        &["--config", CFG, "sync", "prod"],
    );
    assert!(!err.contains("OPV_PRODUCT"), "{err}");
}

/// NR-19: a usage error ends with the help command for the subcommand.
#[test]
fn usage_error_ends_with_the_help_command() {
    let (_, _, err) = opv_with(&[], &["sync"]);
    assert_eq!(err.lines().last(), Some("Next: opv sync --help"), "{err}");
}

/// Every subcommand points at `opv --help` for the global options (H9).
#[test]
fn subcommand_help_points_at_root_help_for_global_options() {
    let (_, out, _) = opv_with(&[], &["status", "--help"]);
    assert!(out.contains("(details: opv --help)"), "{out}");
}

/// A10: `opv guide agent` prints the agent setup guide.
#[test]
fn guide_agent_prints_the_agent_setup_guide() {
    let (code, out, _) = opv_with(&[], &["guide", "agent"]);
    assert!(
        code == 0 && out.starts_with("# Setting up opv for a user"),
        "{code} {out}"
    );
}

/// H10: a broken secrets.toml after `sync` names a read-only re-check, never the write.
#[test]
fn config_error_next_after_sync_is_plan() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.toml");
    let text = std::fs::read_to_string(CFG).unwrap();
    std::fs::write(
        &path,
        text.replacen("kind = \"secret\"", "kind = \"secert\"", 1),
    )
    .unwrap();
    let p = path.to_str().unwrap();
    let (_, _, err) = opv_with(&[], &["--config", p, "sync", "prod", "--deploy"]);
    assert_eq!(
        err.lines().last(),
        Some(format!("Next: opv --config {p} plan prod").as_str()),
        "{err}"
    );
}

/// P10: --confirm is documented on sync.
#[test]
fn sync_help_documents_confirm() {
    let (_, out, _) = opv_with(&[], &["sync", "--help"]);
    assert!(out.contains("--confirm <ENV>"), "{out}");
}

/// NR-19: `opv` with no command shows the help, exits 2 and ends with a `Next:` line.
#[test]
fn missing_command_ends_with_the_help_command() {
    let (_, _, err) = opv_with(&[], &[]);
    assert_eq!(err.lines().last(), Some("Next: opv --help"), "{err}");
}
