//! Behaviour of the typed steps (design §6.1): one assert per test.
//!
//! The real clap tree lives in the binary crate, so a library test cannot name it
//! directly. `cli_command` below rebuilds the tree from `opv::schema::EFFECTS`, the
//! registry of every runnable opv command, and each leaf accepts the arguments the row
//! gives. The rows cover every command path in that registry.

use std::collections::BTreeMap;

use crate::cause::{Cmd, Invocation, Origin};

fn words(line: &str) -> Vec<String> {
    line.split_whitespace().map(str::to_string).collect()
}

/// The command tree as `opv::schema` lists it; each leaf accepts any trailing arguments.
fn cli_command() -> clap::Command {
    let paths: Vec<Vec<String>> = crate::schema::EFFECTS
        .iter()
        .map(|effect| {
            effect
                .command
                .split_whitespace()
                .filter(|w| !w.starts_with('-'))
                .map(str::to_string)
                .collect()
        })
        .collect();
    let mut grouped: BTreeMap<String, Vec<Vec<String>>> = BTreeMap::new();
    for path in paths {
        if let Some((head, tail)) = path.split_first() {
            grouped.entry(head.clone()).or_default().push(tail.to_vec());
        }
    }
    let mut root = clap::Command::new("opv").disable_help_subcommand(true);
    for (name, tails) in grouped {
        root = root.subcommand(subtree(&name, &tails));
    }
    root
}

/// One command node: a leaf accepts arguments, a parent holds its children.
fn subtree(name: &str, tails: &[Vec<String>]) -> clap::Command {
    let children: Vec<&Vec<String>> = tails.iter().filter(|t| !t.is_empty()).collect();
    if children.is_empty() {
        return clap::Command::new(name.to_string()).arg(
            clap::Arg::new("arguments")
                .num_args(0..)
                .allow_hyphen_values(true),
        );
    }
    let mut grouped: BTreeMap<String, Vec<Vec<String>>> = BTreeMap::new();
    for tail in children {
        let (head, rest) = tail.split_first().expect("non-empty");
        grouped.entry(head.clone()).or_default().push(rest.to_vec());
    }
    let mut command = clap::Command::new(name.to_string());
    for (child, rest) in grouped {
        command = command.subcommand(subtree(&child, &rest));
    }
    command
}

/// One test per command path in the registry: `Cmd::to_argv()` is accepted by clap.
macro_rules! parses {
    ($name:ident: $($word:literal),+ $(,)?) => {
        #[test]
        fn $name() {
            let command = Cmd {
                command: vec![$($word.to_string()),+],
                args: Vec::new(),
            };
            assert!(
                cli_command().try_get_matches_from(command.to_argv()).is_ok(),
                "{}",
                command.to_argv().join(" ")
            );
        }
    };
}

parses!(every_next_parses_setup: "setup");
parses!(every_next_parses_login: "login");
parses!(every_next_parses_doctor: "doctor");
parses!(every_next_parses_check: "check");
parses!(every_next_parses_status: "status");
parses!(every_next_parses_projects: "projects");
parses!(every_next_parses_adopt: "adopt");
parses!(every_next_parses_ui: "ui");
parses!(every_next_parses_history: "history");
parses!(every_next_parses_tidy: "tidy");
parses!(every_next_parses_delivery_verify: "delivery", "verify");
parses!(every_next_parses_ci_workflow: "ci", "workflow");
parses!(every_next_parses_access: "access");
parses!(every_next_parses_ready: "ready");
parses!(every_next_parses_generate: "generate");
parses!(every_next_parses_vault_locate: "vault", "locate");
parses!(every_next_parses_mcp_serve: "mcp", "serve");
parses!(every_next_parses_mcp_install: "mcp", "install");
parses!(every_next_parses_version: "version");
parses!(every_next_parses_approve: "approve");
parses!(every_next_parses_bootstrap: "bootstrap");
parses!(every_next_parses_account_list: "account", "list");
parses!(every_next_parses_account_use: "account", "use");
parses!(every_next_parses_run: "run");
parses!(every_next_parses_plan: "plan");
parses!(every_next_parses_sync: "sync");
parses!(every_next_parses_config_export: "config", "export");
parses!(every_next_parses_config_import: "config", "import");
parses!(every_next_parses_config_edit: "config", "edit");
parses!(every_next_parses_config_check: "config", "check");
parses!(every_next_parses_item_skeleton: "item", "skeleton");
parses!(every_next_parses_explain: "explain");
parses!(every_next_parses_open: "open");
parses!(every_next_parses_help: "help");
parses!(every_next_parses_init: "init");
parses!(every_next_parses_add: "add");
parses!(every_next_parses_completions: "completions");
parses!(every_next_parses_schema: "schema");
parses!(every_next_parses_guide: "guide");
parses!(every_next_parses_skill_install: "skill", "install");
parses!(every_next_parses_skill_status: "skill", "status");
parses!(every_next_parses_target_add: "target", "add");
parses!(every_next_parses_target_list: "target", "list");
parses!(every_next_parses_target_credentials: "target", "credentials");
parses!(every_next_parses_env_add: "env", "add");
parses!(every_next_parses_structure_plan: "structure", "plan");
parses!(every_next_parses_structure_apply: "structure", "apply");
parses!(every_next_parses_config_describe: "config", "describe");

#[test]
fn rerun_keeps_every_flag() {
    let invocation = Invocation::from_cli(&words(
        "run dev --config cfg --json --timeout 60 --verbose --target t --product p \
         --role r --remote h --confirm --rotate --skip --project . --account a",
    ));
    let flags: Vec<String> = invocation
        .rerun_argv()
        .into_iter()
        .filter(|w| w.starts_with("--"))
        .collect();
    assert_eq!(
        flags,
        words(
            "--config --json --timeout --verbose --target --product --role --remote \
             --confirm --rotate --skip --project --account"
        )
    );
}

#[test]
fn a_child_command_is_never_rendered() {
    let invocation = Invocation::from_cli(&words("run dev --product api -- npm run secret-arg"));
    assert_eq!(invocation.rerun_argv(), words("opv run dev --product api"));
}

#[test]
fn a_run_with_a_child_command_has_child() {
    let invocation = Invocation::from_cli(&words("run dev --product api -- npm run secret-arg"));
    assert!(invocation.has_child);
}

#[test]
fn with_arg_changes_only_that_word() {
    let invocation = Invocation::from_cli(&words("run dev --product api"));
    assert_eq!(
        invocation.with_arg("dev", "prod").rerun_argv(),
        words("opv run prod --product api")
    );
}

#[test]
fn an_mcp_invocation_remembers_the_tool() {
    let invocation = Invocation::from_mcp("opv_sync", words("prod"));
    assert_eq!(
        invocation.origin,
        Origin::Mcp {
            tool: "opv_sync".into()
        }
    );
}

#[test]
fn cmd_to_argv_is_opv_then_path_then_args() {
    let command = Cmd {
        command: words("target add"),
        args: words("prod"),
    };
    assert_eq!(command.to_argv(), words("opv target add prod"));
}

#[test]
fn a_rebuilt_step_leaves_out_the_colour_flag() {
    let inv = Invocation::from_cli(&[
        "opv".to_string(),
        "doctor".to_string(),
        "--color".to_string(),
        "always".to_string(),
        "--config".to_string(),
        "x.toml".to_string(),
    ]);
    assert_eq!(inv.args, vec!["--config".to_string(), "x.toml".to_string()]);
}
