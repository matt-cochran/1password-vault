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
parses!(every_next_parses_status: "status");
parses!(every_next_parses_projects: "projects");
parses!(every_next_parses_ui: "ui");
parses!(every_next_parses_history: "history");
parses!(every_next_parses_delivery_verify: "delivery", "verify");
parses!(every_next_parses_ci_workflow: "ci", "workflow");
parses!(every_next_parses_access: "access");
parses!(every_next_parses_ready: "ready");
parses!(every_next_parses_vault_locate: "vault", "locate");
parses!(every_next_parses_mcp_serve: "mcp", "serve");
parses!(every_next_parses_mcp_install: "mcp", "install");
parses!(every_next_parses_version: "version");
parses!(every_next_parses_account_list: "account", "list");
parses!(every_next_parses_account_use: "account", "use");
parses!(every_next_parses_run: "run");
parses!(every_next_parses_plan: "plan");
parses!(every_next_parses_sync: "sync");
parses!(every_next_parses_config_export: "config", "export");
parses!(every_next_parses_config_import: "config", "import");
parses!(every_next_parses_config_edit: "config", "edit");
parses!(every_next_parses_config_check: "config", "check");
parses!(every_next_parses_explain: "explain");
parses!(every_next_parses_open: "open");
parses!(every_next_parses_help: "help");
parses!(every_next_parses_completions: "completions");
parses!(every_next_parses_schema: "schema");
parses!(every_next_parses_guide: "guide");
parses!(every_next_parses_skill_install: "skill", "install");
parses!(every_next_parses_skill_status: "skill", "status");
parses!(every_next_parses_target_list: "target", "list");
parses!(every_next_parses_needs: "needs");
parses!(every_next_parses_contract: "contract");
parses!(every_next_parses_propose: "propose");
parses!(every_next_parses_propose_key: "propose", "key");
parses!(every_next_parses_propose_env: "propose", "env");
parses!(every_next_parses_propose_target: "propose", "target");
parses!(every_next_parses_propose_retire: "propose", "retire");
parses!(every_next_parses_propose_setup: "propose", "setup");
parses!(every_next_parses_propose_structure: "propose", "structure");
parses!(every_next_parses_propose_generate: "propose", "generate");
parses!(every_next_parses_apply: "apply");
parses!(every_next_parses_set: "set");
parses!(every_next_parses_import: "import");
parses!(every_next_parses_target_credentials: "target", "credentials");
parses!(every_next_parses_target_op: "target", "op");

/// The command path of `next`'s rendered command (`opv propose structure` →
/// `["propose", "structure"]`), walked down the registry's tree; `None` when it names a
/// command the registry does not have.
fn registered_path(text: &str) -> Option<Vec<String>> {
    let root = cli_command();
    let mut node = &root;
    let mut path = Vec::new();
    for word in text.split_whitespace().skip(1) {
        match node.find_subcommand(word) {
            Some(sub) => {
                path.push(word.to_string());
                node = sub;
            }
            None => break,
        }
    }
    (!path.is_empty() && !node.has_subcommands() || path == ["propose"]).then_some(path)
}

/// Design §25.3: every catalog cause's `next` names a command this opv has (none of the
/// removed 0.11.0 commands).
#[test]
fn every_catalog_next_names_a_command_that_exists() {
    let inv = Invocation::from_cli(&words("opv status prod"));
    let missing: Vec<String> = crate::cause::codes::one_of_each()
        .iter()
        .filter_map(|cause| {
            let doc = crate::cause::render::document(cause, None, &inv, false);
            let command = doc["next"]["command"].as_str()?.to_string();
            command.starts_with("opv ").then_some(command)
        })
        .filter(|command| registered_path(command).is_none())
        .collect();
    assert!(missing.is_empty(), "{missing:?}");
}

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
    let invocation = Invocation::from_mcp("opv_generate", words("prod"));
    assert_eq!(
        invocation.origin,
        Origin::Mcp {
            tool: "opv_generate".into()
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

// --- FR-65: typed choices and argv (design agent-signin-readiness §2.3) --------------------

use crate::cause::{AccountChoice, AccountId, Next, Step};
use crate::json::{NextActor, Reach, StepEffect};

fn candidate(id: &str, signed_in: Option<bool>) -> AccountChoice {
    AccountChoice {
        email: format!("{id}@example.com"),
        address: "my.1password.com".into(),
        id: AccountId::new(id),
        shorthand: Some("my".into()),
        signed_in,
    }
}

fn ready_json() -> Cmd {
    Cmd {
        command: words("ready"),
        args: words("--json"),
    }
}

fn two_candidates() -> Vec<AccountChoice> {
    vec![
        candidate("TTDZ56BH", Some(false)),
        candidate("6AINMAIK", Some(true)),
    ]
}

/// The steps of choice `at` for `reach`.
fn steps_of(reach: Reach, at: usize) -> Vec<Step> {
    match crate::cause::step::account_choices(&two_candidates(), reach, &ready_json()) {
        Next::Choose(c) => c.choices[at].steps.clone(),
        other => panic!("not a choose: {other:?}"),
    }
}

fn texts(steps: &[Step]) -> Vec<Option<String>> {
    steps
        .iter()
        .map(|s| s.run.as_ref().map(|c| c.to_argv().join(" ")))
        .collect()
}

#[test]
fn two_candidates_are_a_choose() {
    let next = crate::cause::step::account_choices(&two_candidates(), Reach::None, &ready_json());
    assert!(matches!(next, Next::Choose(_)));
}

#[test]
fn choose_needs_two_candidates() {
    let one = [candidate("TTDZ56BH", None)];
    let next = crate::cause::step::account_choices(&one, Reach::None, &ready_json());
    assert!(!matches!(next, Next::Choose(_)));
}

#[test]
fn no_candidate_is_the_persons_add() {
    let next = crate::cause::step::account_choices(&[], Reach::None, &ready_json());
    assert_eq!(
        next,
        Next::Handoff(Cmd {
            command: words("login"),
            args: words("--add"),
        })
    );
}

#[test]
fn choices_keep_the_given_order() {
    let ids: Vec<String> =
        match crate::cause::step::account_choices(&two_candidates(), Reach::None, &ready_json()) {
            Next::Choose(c) => c.choices.iter().map(|c| c.account.id.to_string()).collect(),
            _ => Vec::new(),
        };
    assert_eq!(ids, ["TTDZ56BH", "6AINMAIK"]);
}

#[test]
fn a_choice_starts_with_account_use_by_id() {
    assert_eq!(
        texts(&steps_of(Reach::None, 0))[0].as_deref(),
        Some("opv account use TTDZ56BH")
    );
}

#[test]
fn account_use_is_the_assistants_config_write() {
    let first = &steps_of(Reach::None, 0)[0];
    assert_eq!(
        (first.actor, first.effect),
        (NextActor::Assistant, StepEffect::WritesConfig)
    );
}

#[test]
fn signed_out_without_reach_signs_in_in_the_persons_terminal() {
    assert_eq!(
        texts(&steps_of(Reach::None, 0)),
        [
            Some("opv account use TTDZ56BH".to_string()),
            Some("opv login -- opv ready --json".to_string()),
        ]
    );
}

#[test]
fn signed_out_with_the_app_unlocks_it_then_verifies() {
    assert_eq!(
        texts(&steps_of(Reach::App, 0)),
        [
            Some("opv account use TTDZ56BH".to_string()),
            None,
            Some("opv ready --json".to_string()),
        ]
    );
}

#[test]
fn the_app_sign_in_says_what_to_do() {
    assert_eq!(
        steps_of(Reach::App, 0)[1].does,
        Some("unlock the 1Password app and approve its prompt")
    );
}

#[test]
fn a_shell_reach_signs_in_with_the_refresh_line() {
    let sign_in = &steps_of(Reach::Shell, 0)[1];
    assert!(
        sign_in
            .run
            .as_ref()
            .is_some_and(|c| c.as_login_shell().is_some())
    );
}

#[test]
fn signed_in_choice_has_no_signin_step() {
    let effects: Vec<StepEffect> = steps_of(Reach::None, 1).iter().map(|s| s.effect).collect();
    assert!(!effects.contains(&StepEffect::SignsIn), "{effects:?}");
}

#[test]
fn every_sign_in_step_is_the_persons() {
    let actors: Vec<NextActor> = [Reach::App, Reach::Shell, Reach::None]
        .into_iter()
        .flat_map(|r| steps_of(r, 0))
        .filter(|s| s.effect == StepEffect::SignsIn)
        .map(|s| s.actor)
        .collect();
    assert!(actors.iter().all(|a| *a == NextActor::Person), "{actors:?}");
}

#[test]
fn a_rerun_with_a_child_signs_in_with_a_placeholder() {
    let rerun = Cmd {
        command: words("run"),
        args: words("dev --"),
    };
    let next = crate::cause::step::account_choices(&two_candidates(), Reach::None, &rerun);
    let Next::Choose(c) = next else {
        panic!("not a choose")
    };
    assert_eq!(
        c.choices[0].steps[1].run.as_ref().and_then(Cmd::exec_argv),
        None
    );
}

#[test]
fn exec_argv_of_a_placeholder_is_none() {
    let c = Cmd {
        command: words("login"),
        args: words("-- opv run dev --"),
    };
    assert_eq!(c.exec_argv(), None);
}

#[test]
fn exec_argv_of_a_refresh_line_is_none() {
    let c = Cmd::login_shell(crate::host::Shell::Posix, None);
    assert_eq!(c.exec_argv(), None);
}

#[test]
fn exec_argv_of_a_plain_command_is_its_argv() {
    assert_eq!(ready_json().exec_argv(), Some(words("opv ready --json")));
}

/// Every `argv` the catalog's typed producers and the choices emit, under a few invocations.
fn every_emitted_argv() -> Vec<Vec<String>> {
    let invocations = [
        Invocation::from_cli(&words("opv ready dev --json")),
        Invocation::from_cli(&words("opv run dev -- sh -c true")),
        Invocation::from_cli(&words("opv sync prod --target web")),
        Invocation::from_mcp("opv_state", Vec::new()),
    ];
    let mut out = Vec::new();
    for inv in &invocations {
        for c in crate::cause::codes::examples() {
            let doc = crate::cause::render::document(&c, None, inv, false);
            if let Some(argv) = doc["next"]["argv"].as_array() {
                out.push(
                    argv.iter()
                        .filter_map(|w| w.as_str().map(String::from))
                        .collect(),
                );
            }
        }
    }
    for reach in [Reach::App, Reach::Shell, Reach::None] {
        for at in 0..2 {
            out.extend(
                steps_of(reach, at)
                    .iter()
                    .filter_map(|s| s.run.as_ref()?.exec_argv()),
            );
        }
    }
    out
}

#[test]
fn argv_round_trips_clap() {
    let refused: Vec<String> = every_emitted_argv()
        .into_iter()
        .filter(|argv| cli_command().try_get_matches_from(argv).is_err())
        .map(|argv| argv.join(" "))
        .collect();
    assert_eq!(refused, Vec::<String>::new());
}

#[test]
fn the_typed_producers_emit_argv() {
    assert!(!every_emitted_argv().is_empty());
}
