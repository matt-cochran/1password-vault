//! `opv ci workflow` (j7): print a ready-to-commit GitHub Actions workflow for one target.
//!
//! The printed workflow is read-only output: it names the target's provider only through
//! `TargetConfig`, references no secret besides the 1Password service-account token, and
//! refuses an unknown environment or target before printing anything.

use super::*;
use crate::app::testutil::text_of;
use crate::config;

/// One environment with a Fly target and one product: enough to print a workflow.
const FLY_FLEET: &str = "\
[environments.prod]
boundaries.api = { vault_id = \"v1\", item_id = \"i1\" }

[environments.prod.targets.portfolio]
fly.app = \"portfolio-prod\"
fly.secret_name = \"FLEET__{PRODUCT}__{KEY}\"
state_vault_id = \"s1\"

[products.api.keys.TOKEN]
kind = \"secret\"
environments = [\"prod\"]
";

/// The same environment with a GitHub target (no provider CI setup step in the docs).
const GITHUB_FLEET: &str = "\
[environments.prod]
boundaries.api = { vault_id = \"v1\", item_id = \"i1\" }

[environments.prod.targets.portfolio]
github.repo = \"owner/name\"
state_vault_id = \"s1\"

[products.api.keys.TOKEN]
kind = \"secret\"
environments = [\"prod\"]
";

/// The printed workflow for the Fly fixture, as text.
fn fly_workflow(github_env: Option<&str>, deploy: bool) -> String {
    let fleet = config::parse(FLY_FLEET).unwrap();
    let mut out = Vec::new();
    run(&fleet, "prod", "portfolio", github_env, deploy, &mut out).unwrap();
    text_of(&out)
}

fn refused(env: &str, target: &str) -> (Error, String) {
    let fleet = config::parse(FLY_FLEET).unwrap();
    let mut out = Vec::new();
    let err = run(&fleet, env, target, None, false, &mut out).unwrap_err();
    (err, text_of(&out))
}

// --- what the printed workflow contains ------------------------------------------------

#[test]
fn fly_target_includes_the_flyctl_setup_step() {
    assert!(
        fly_workflow(None, false).contains("uses: superfly/flyctl-actions/setup-flyctl@1.6"),
        "{}",
        fly_workflow(None, false)
    );
}

#[test]
fn fly_target_includes_the_sync_receipt_command() {
    assert!(
        fly_workflow(None, false)
            .contains("opv sync prod --target portfolio --receipt portfolio.receipt.json"),
        "{}",
        fly_workflow(None, false)
    );
}

#[test]
fn fly_target_includes_the_receipt_upload_step() {
    assert!(
        fly_workflow(None, false).contains("actions/upload-artifact@v4"),
        "{}",
        fly_workflow(None, false)
    );
}

#[test]
fn fly_target_includes_the_delivery_verify_command() {
    assert!(
        fly_workflow(None, false).contains(
            "opv delivery verify prod --target portfolio --receipt portfolio.receipt.json"
        ),
        "{}",
        fly_workflow(None, false)
    );
}

#[test]
fn fly_target_names_no_deploy_token() {
    assert!(!fly_workflow(None, false).contains("FLY_API_TOKEN"));
}

#[test]
fn fly_target_references_only_the_service_account_secret() {
    let yaml = fly_workflow(None, false);
    assert_eq!(
        yaml.matches("${{ secrets.").count(),
        yaml.matches("${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}")
            .count()
    );
}

#[test]
fn workflow_pins_the_running_crate_version() {
    assert!(
        fly_workflow(None, false).contains(&format!("OPV_VERSION: v{}", env!("CARGO_PKG_VERSION"))),
        "{}",
        fly_workflow(None, false)
    );
}

#[test]
fn workflow_uses_manual_dispatch() {
    assert!(fly_workflow(None, false).contains("workflow_dispatch:"));
}

#[test]
fn workflow_declares_no_push_trigger() {
    assert!(!fly_workflow(None, false).contains("push:"));
}

#[test]
fn workflow_grants_contents_read() {
    assert!(fly_workflow(None, false).contains("\npermissions:\n  contents: read\n"));
}

#[test]
fn job_id_names_the_environment_and_target() {
    assert!(fly_workflow(None, false).contains("  sync-prod-portfolio:"));
}

#[test]
fn identity_header_names_the_access_command() {
    assert!(
        fly_workflow(None, false)
            .contains("#   opv access prod --target portfolio --create --github <owner/repo>"),
        "{}",
        fly_workflow(None, false)
    );
}

#[test]
fn a_provider_without_a_setup_step_omits_the_setup_step() {
    let fleet = config::parse(GITHUB_FLEET).unwrap();
    let mut out = Vec::new();
    run(&fleet, "prod", "portfolio", None, false, &mut out).unwrap();
    assert!(!text_of(&out).contains("setup-flyctl"));
}

// --- flags -----------------------------------------------------------------------------

#[test]
fn deploy_appends_to_the_sync_command() {
    assert!(
        fly_workflow(None, true)
            .contains("opv sync prod --target portfolio --receipt portfolio.receipt.json --deploy"),
        "{}",
        fly_workflow(None, true)
    );
}

#[test]
fn deploy_is_named_once() {
    assert_eq!(fly_workflow(None, true).matches("--deploy").count(), 1);
}

#[test]
fn github_env_sets_the_job_environment() {
    assert!(fly_workflow(Some("production"), false).contains("    environment: production\n"));
}

#[test]
fn no_github_env_omits_the_job_environment() {
    assert!(!fly_workflow(None, false).contains("environment:"));
}

// --- refusals --------------------------------------------------------------------------

#[test]
fn unknown_target_is_an_unknown_target() {
    let (err, _) = refused("prod", "missing");
    assert_eq!(err.code_str(), "unknown_target");
}

#[test]
fn unknown_target_prints_nothing() {
    let (_, out) = refused("prod", "missing");
    assert_eq!(out, "");
}

#[test]
fn unknown_environment_is_a_usage_error() {
    // Exit 2 either way; the catalog names it unknown_env (audit 03.02).
    let (err, _) = refused("missing", "portfolio");
    assert_eq!(err.exit_code(), 2);
}

#[test]
fn unknown_environment_prints_nothing() {
    let (_, out) = refused("missing", "portfolio");
    assert_eq!(out, "");
}

#[test]
fn identity_header_carries_the_github_environment() {
    assert!(
        fly_workflow(Some("production"), false)
            .contains("--github <owner/repo> --github-env production")
    );
}

#[test]
fn an_environment_that_needs_confirmation_is_confirmed_in_the_sync() {
    let fleet = config::parse(&FLY_FLEET.replace(
        "[environments.prod]\n",
        "[environments.prod]\nconfirm_env = true\n",
    ))
    .unwrap();
    let mut out = Vec::new();
    run(&fleet, "prod", "portfolio", None, false, &mut out).unwrap();
    assert!(
        text_of(&out).contains("run: opv sync prod --target portfolio --confirm prod --receipt")
    );
}

// --- whether the printed job can sign in to the target (06.24, 06.48) -----------------

/// The printed workflow for `fleet`'s `prod`/`portfolio`.
fn workflow_of(fleet: &str) -> String {
    let fleet = config::parse(fleet).unwrap();
    let mut out = Vec::new();
    run(&fleet, "prod", "portfolio", None, false, &mut out).unwrap();
    text_of(&out)
}

/// `fleet` with the target's deploy credentials recorded.
fn with_deploy_credentials(fleet: &str) -> String {
    fleet.replacen(
        "state_vault_id = \"s1\"\n",
        "state_vault_id = \"s1\"\ndeploy_credentials = \"op://deploy/portfolio\"\n",
        1,
    )
}

#[test]
fn identity_header_says_which_token_it_means() {
    assert!(fly_workflow(None, false).contains(
        "# secrets.OP_SERVICE_ACCOUNT_TOKEN is created once, by a person in their own \
         terminal, with:\n"
    ));
}

#[test]
fn a_fly_target_without_deploy_credentials_names_the_mint_command() {
    assert!(
        workflow_of(FLY_FLEET)
            .contains("#   opv target credentials prod --target portfolio --create\n"),
        "{}",
        workflow_of(FLY_FLEET)
    );
}

#[test]
fn a_github_target_without_deploy_credentials_names_config_edit() {
    assert!(
        workflow_of(GITHUB_FLEET).contains("a person adds them first with:\n#   opv config edit\n"),
        "{}",
        workflow_of(GITHUB_FLEET)
    );
}

#[test]
fn a_target_with_deploy_credentials_gets_no_sign_in_note() {
    assert!(!workflow_of(&with_deploy_credentials(FLY_FLEET)).contains("not recorded yet"));
}

// --- the two §2.5 recipes (C5) ---------------------------------------------------------

/// The fixtures' configuration: staging and prod, each with one Fly target and no
/// `confirm_env`, so both sync directly.
fn fixture_fleet() -> Fleet {
    config::load("tests/fixtures/secrets.toml").unwrap()
}

/// The change workflow for `fleet`, as text.
fn change_of(fleet: &Fleet, every: u8) -> String {
    let mut out = Vec::new();
    run_on_change(fleet, every, &mut out).unwrap();
    text_of(&out)
}

/// The change workflow of `FLY_FLEET`, with `confirm_env` added when `confirm`.
fn fly_change(confirm: bool, every: u8) -> String {
    let text = if confirm {
        FLY_FLEET.replace(
            "[environments.prod]\n",
            "[environments.prod]\nconfirm_env = true\n",
        )
    } else {
        FLY_FLEET.to_string()
    };
    change_of(&config::parse(&text).unwrap(), every)
}

#[test]
fn on_change_workflow_matches_the_fixture_golden() {
    assert_eq!(
        change_of(&fixture_fleet(), 15),
        std::fs::read_to_string("tests/fixtures/ci/on-change.yml").unwrap()
    );
}

#[test]
fn drift_workflow_matches_the_fixture_golden() {
    let mut out = Vec::new();
    run_drift(&fixture_fleet(), &mut out).unwrap();
    assert_eq!(
        text_of(&out),
        std::fs::read_to_string("tests/fixtures/ci/drift.yml").unwrap()
    );
}

#[test]
fn a_confirm_env_environment_gets_a_plan_job() {
    assert!(fly_change(true, 15).contains("  plan-prod:\n"));
}

#[test]
fn a_confirm_env_sync_is_gated_on_the_plans_id() {
    assert!(fly_change(true, 15).contains(
        "run: opv sync prod --deploy --expect-plan ${{ needs.plan-prod.outputs.plan_id }}"
    ));
}

#[test]
fn a_non_confirm_environment_syncs_directly() {
    assert!(fly_change(false, 15).contains("        run: opv sync prod --deploy\n"));
}

#[test]
fn every_thirty_sets_a_thirty_minute_cron() {
    assert!(fly_change(false, 30).contains("cron: \"*/30 * * * *\""));
}

#[test]
fn the_detect_step_branches_on_changed() {
    assert!(fly_change(false, 15).contains("  10) echo \"$ENV=yes\" >> \"$GITHUB_OUTPUT\" ;;"));
}

#[test]
fn the_change_workflow_puts_every_sync_in_one_concurrency_group() {
    assert!(
        fly_change(false, 15).contains("concurrency: {group: opv-sync, cancel-in-progress: false}")
    );
}

// --- the pull-request checks and the relaxations job (Part V, row `ci-workflow`) ---------

/// The single-target workflow for the fixture configuration's `prod`/`portfolio`.
fn fixture_run(env: &str, target: &str) -> String {
    let fleet = fixture_fleet();
    let mut out = Vec::new();
    run(&fleet, env, target, None, false, &mut out).unwrap();
    text_of(&out)
}

#[test]
fn pr_workflow_triggers_on_pull_request() {
    assert!(fly_workflow(None, false).contains("  pull_request:\n"));
}

#[test]
fn sync_job_runs_only_on_dispatch() {
    assert!(
        fly_workflow(None, false).contains("    if: github.event_name == 'workflow_dispatch'\n")
    );
}

#[test]
fn pr_checks_run_the_needs_gate() {
    assert!(fly_workflow(None, false).contains("        run: opv needs --gate\n"));
}

#[test]
fn pr_checks_run_the_contract_check() {
    assert!(
        fly_workflow(None, false).contains("        run: opv contract --check contract.json\n")
    );
}

#[test]
fn pr_checks_run_the_ready_gate() {
    assert!(fly_workflow(None, false).contains("        run: opv ready prod --gate\n"));
}

#[test]
fn the_relaxations_status_is_named_opv_relaxations() {
    assert!(fly_workflow(None, false).contains("    name: opv/relaxations\n"));
}

#[test]
fn relaxations_are_listed_against_the_default_branch() {
    assert!(
        fly_workflow(None, false).contains(
            "          relaxations=$(opv contract --relaxations --base \"$BASE\" --json)\n"
        )
    );
}

#[test]
fn the_default_branch_is_the_repositorys_default_branch() {
    assert!(
        fly_workflow(None, false)
            .contains("          BASE: origin/${{ github.event.repository.default_branch }}\n")
    );
}

#[test]
fn the_relaxations_job_uses_the_workflow_token() {
    assert!(fly_workflow(None, false).contains("      GH_TOKEN: ${{ github.token }}\n"));
}

#[test]
fn the_relaxations_job_requires_approval_at_the_head() {
    assert!(
        fly_workflow(None, false)
            .contains("select(.state == \"APPROVED\" and .commit_id == $head)")
    );
}

#[test]
fn run_workflow_matches_the_fixture_golden() {
    assert_eq!(
        fixture_run("prod", "portfolio"),
        std::fs::read_to_string("tests/fixtures/ci/pr.yml").unwrap()
    );
}

#[test]
fn the_example_pr_workflow_equals_the_output() {
    let fleet = config::load("examples/ci-change-detection/secrets.toml").unwrap();
    let mut out = Vec::new();
    run(&fleet, "prod", "app", None, false, &mut out).unwrap();
    assert_eq!(
        text_of(&out),
        std::fs::read_to_string("examples/ci-change-detection/.github/workflows/opv-pr.yml")
            .unwrap()
    );
}

// --- #206: --supply and --supply-check (T16) ------------------------------------------------

/// prod with a Fly target `web` delivering api's two infrastructure keys and a stored one.
const SUPPLY_FLEET: &str = "\
[environments.prod]
boundaries.api = { vault_id = \"v1\", item_id = \"i1\" }
confirm_env = true

[environments.prod.targets.web]
fly.app = \"web-prod\"
fly.secret_name = \"APP_{KEY}\"
state_vault_id = \"s1\"

[products.api.keys.DATABASE_URL]
kind = \"secret\"
source = \"infrastructure\"
environments = [\"prod\"]
rules = { regex = \"postgres(ql)?://.+\" }

[products.api.keys.STRIPE_WEBHOOK_SECRET]
kind = \"secret\"
source = \"infrastructure\"
environments = [\"prod\"]
immutable = true
rules = { ensure_prefix = \"whsec_\" }

[products.api.keys.TOKEN]
kind = \"secret\"
environments = [\"prod\"]
";

/// `opv ci workflow prod --target web --supply [--deploy]`, as text.
fn supply_step_text(deploy: bool) -> String {
    let fleet = config::parse(SUPPLY_FLEET).unwrap();
    let mut out = Vec::new();
    run_supply(&fleet, "prod", "web", deploy, &mut out).unwrap();
    text_of(&out)
}

/// `opv ci workflow --supply-check` of `yaml`.
fn check(yaml: &str) -> Result<(), Error> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("apply.yml");
    std::fs::write(&path, yaml).unwrap();
    run_supply_check(&path, &mut Vec::new())
}

#[test]
fn supply_step_maps_each_key_with_a_fixed_jq_error() {
    assert!(supply_step_text(false).contains(
        "\"api/DATABASE_URL\": (.database_url.value | strings // error(\"database_url missing\"))"
    ));
}

#[test]
fn supply_step_maps_the_second_key_too() {
    assert!(supply_step_text(false).contains("error(\"stripe_webhook_secret missing\")"));
}

#[test]
fn supply_step_leaves_the_stored_key_out() {
    assert!(!supply_step_text(false).contains("api/TOKEN"));
}

#[test]
fn supply_step_never_rotates() {
    assert!(!supply_step_text(true).contains("--rotate"));
}

#[test]
fn supply_step_fails_on_a_failed_producer() {
    assert!(supply_step_text(false).contains("set -euo pipefail"));
}

#[test]
fn supply_step_ends_the_jq_program_with_the_pipe_into_the_supplying_sync() {
    assert!(supply_step_text(true).contains(
        "missing\"))}}' |\n            opv sync prod --target web --supply-stdin --deploy --receipt web.receipt.json --confirm prod\n"
    ));
}

#[test]
fn supply_step_has_no_line_that_starts_with_a_pipe() {
    assert!(
        !supply_step_text(true)
            .lines()
            .any(|l| l.trim_start().starts_with('|'))
    );
}

#[test]
fn supply_step_passes_the_targets_token_through_its_env() {
    assert!(
        supply_step_text(false).contains("          FLY_API_TOKEN: ${{ secrets.FLY_API_TOKEN }}\n")
    );
}

#[test]
fn supply_step_keeps_the_service_account_token_in_its_env() {
    assert!(
        supply_step_text(false).contains(
            "          OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}\n"
        )
    );
}

#[test]
fn supply_check_job_pins_the_running_crate_version() {
    assert!(
        supply_step_text(false)
            .contains(&format!("OPV_VERSION: v{}   #", env!("CARGO_PKG_VERSION")))
    );
}

#[test]
fn supply_step_for_a_provider_without_a_token_variable_passes_none() {
    let keys = [("api/DATABASE_URL".to_string(), "DATABASE_URL".to_string())];
    let text = supply_step(&SupplyStep {
        env: "prod",
        target: "web",
        keys: &keys,
        deploy: false,
        confirm: false,
        credential: None,
    });
    // Only the service-account token: no provider token line.
    assert_eq!(text.matches(": ${{ secrets.").count(), 1);
}

/// The fenced block of `docs/infra-generated-values.md` that follows `after`.
fn guide_block(after: &str, fence: &str) -> String {
    let guide = std::fs::read_to_string("docs/infra-generated-values.md").unwrap();
    let rest = &guide[guide.find(after).unwrap()..];
    let open = format!("```{fence}\n");
    let body = &rest[rest.find(&open).unwrap() + open.len()..];
    body[..body.find("```").unwrap()].to_string()
}

#[test]
fn the_guides_supply_step_equals_the_generated_step() {
    let text = supply_step_text(true);
    let step = &text[..text.find("\n# And this job").unwrap()];
    assert_eq!(guide_block("For the configuration above:", "yaml"), step);
}

#[test]
fn the_guides_supply_check_job_equals_the_generated_job() {
    let text = supply_step_text(true);
    let job = &text[text.find("  opv-supply-check:").unwrap()..];
    assert_eq!(
        guide_block("point it at the file that holds the step:", "yaml")
            .replace("v0.13.0", &format!("v{}", env!("CARGO_PKG_VERSION"))),
        job
    );
}

// --- every generated script is valid bash, and the supply step logs no value -------------

/// The body of every `run:` script in `yaml`, as bash runs it: a block scalar dedented, an
/// inline command after `run:`, each `${{ … }}` replaced by a word as GitHub would.
/// Only the unix tests use it: they hand the scripts to bash.
#[cfg(unix)]
fn run_scripts(yaml: &str) -> Vec<String> {
    scripts(yaml)
        .into_iter()
        .map(|sc| {
            let body: Vec<&str> = if sc.lines.len() == 1 && sc.lines[0].1.contains("run:") {
                let l = &sc.lines[0].1;
                vec![&l[l.find("run:").unwrap() + 4..]]
            } else {
                sc.lines.iter().map(|(_, l)| l.as_str()).collect()
            };
            let pad = body
                .iter()
                .filter(|l| !l.trim().is_empty())
                .map(|l| l.len() - l.trim_start().len())
                .min()
                .unwrap_or(0);
            let mut text: String = body
                .iter()
                .map(|l| format!("{}\n", l.get(pad..).unwrap_or("")))
                .collect();
            while let Some(at) = text.find("${{") {
                let end = text[at..].find("}}").map_or(text.len(), |e| at + e + 2);
                text.replace_range(at..end, "EXPR");
            }
            text
        })
        .collect()
}

/// Whether every `run:` script of `yaml` passes `bash -n`, and there is at least one.
#[cfg(unix)]
fn every_script_parses(yaml: &str) -> bool {
    let all = run_scripts(yaml);
    !all.is_empty()
        && all.iter().all(|script| {
            std::process::Command::new("bash")
                .args(["-n", "-c", script])
                .output()
                .is_ok_and(|o| o.status.success())
        })
}

#[cfg(unix)]
#[test]
fn the_supply_step_and_its_check_job_pass_bash_n() {
    assert!(every_script_parses(&supply_step_text(true)));
}

#[cfg(unix)]
#[test]
fn the_supply_step_without_deploy_passes_bash_n() {
    assert!(every_script_parses(&supply_step_text(false)));
}

#[cfg(unix)]
#[test]
fn the_sync_workflow_passes_bash_n() {
    assert!(every_script_parses(&fly_workflow(Some("production"), true)));
}

#[cfg(unix)]
#[test]
fn the_pr_workflow_passes_bash_n() {
    assert!(every_script_parses(&fixture_run("prod", "portfolio")));
}

#[cfg(unix)]
#[test]
fn the_change_workflow_passes_bash_n() {
    assert!(every_script_parses(&fly_change(true, 15)));
}

#[cfg(unix)]
#[test]
fn the_drift_workflow_passes_bash_n() {
    let mut out = Vec::new();
    run_drift(&fixture_fleet(), &mut out).unwrap();
    assert!(every_script_parses(&text_of(&out)));
}

/// The canary the stub producer puts in every value; it must never reach the step's log.
#[cfg(unix)]
const CANARY: &str = "S7MARKER";

/// What running the generated supply step printed, and what the stub `opv sync` read.
#[cfg(unix)]
struct SupplyRun {
    status: std::process::ExitStatus,
    log: String,
    piped: String,
}

/// Run the generated supply step (without the check job) under bash with a stub
/// `terraform` whose outputs hold [`CANARY`], the real `jq`, and a stub `opv` that reads
/// its stdin into a file. `None` when `jq` is not installed.
#[cfg(unix)]
fn run_supply_step() -> Option<SupplyRun> {
    use std::os::unix::fs::PermissionsExt;
    if std::process::Command::new("jq")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("skipped: jq is not installed");
        return None;
    }
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let piped = dir.path().join("piped");
    let stub = |name: &str, body: &str| {
        let path = bin.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    stub(
        "terraform",
        &format!(
            "case \"$1\" in\n  state) echo '{{\"serial\": 7}}' ;;\n  output) echo '{{\"database_url\": \
             {{\"value\": \"postgres://u:{CANARY}@db/x\"}}, \"stripe_webhook_secret\": \
             {{\"value\": \"whsec_{CANARY}\"}}}}' ;;\nesac\n"
        ),
    );
    stub(
        "opv",
        &format!(
            "if [ \"$1\" = sync ]; then cat > '{}'; fi\nexit 0\n",
            piped.display()
        ),
    );
    let text = supply_step_text(true);
    let step = text.split("\n  opv-supply-check:").next().unwrap();
    let script = run_scripts(step).into_iter().next().unwrap();
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let out = std::process::Command::new("bash")
        .args(["-c", &script])
        .env("PATH", path)
        .output()
        .unwrap();
    Some(SupplyRun {
        status: out.status,
        log: format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
        piped: std::fs::read_to_string(&piped).unwrap_or_default(),
    })
}

#[cfg(unix)]
#[test]
fn the_supply_step_runs_to_success() {
    if let Some(run) = run_supply_step() {
        assert!(run.status.success(), "{}", run.log);
    }
}

#[cfg(unix)]
#[test]
fn the_supply_step_logs_no_value() {
    if let Some(run) = run_supply_step() {
        assert!(!run.log.contains(CANARY));
    }
}

#[cfg(unix)]
#[test]
fn the_supply_step_pipes_the_values_into_opv_sync() {
    if let Some(run) = run_supply_step() {
        assert!(run.piped.contains(&format!("whsec_{CANARY}")));
    }
}

#[test]
fn supply_step_is_a_step_with_no_concurrency_group() {
    assert!(!supply_step_text(false).contains("concurrency:"));
}

#[test]
fn supply_step_forbids_expressions_in_its_script() {
    assert!(supply_step_text(false).contains("Never put ${{ ... }} in the script"));
}

#[test]
fn supply_step_passes_its_own_check() {
    assert!(
        check(&format!(
            "jobs:\n  apply:\n    steps:\n{}",
            supply_step_text(true)
        ))
        .is_ok()
    );
}

#[test]
fn supply_for_a_target_without_infrastructure_keys_is_refused() {
    let fleet = config::parse(FLY_FLEET).unwrap();
    assert!(run_supply(&fleet, "prod", "portfolio", false, &mut Vec::new()).is_err());
}

/// A step that pipes into `--supply-stdin`, with `line` in its script.
fn supplying_step(line: &str) -> String {
    format!(
        "jobs:\n  apply:\n    steps:\n      - name: deliver\n        env:\n          \
         OP_SERVICE_ACCOUNT_TOKEN: ${{{{ secrets.OPV }}}}\n        run: |\n          \
         set -euo pipefail\n          {line}\n          \
         printf '%s' \"$DOC\" | opv sync prod --supply-stdin\n"
    )
}

#[test]
fn supply_check_refuses_a_step_output_in_the_script() {
    let e = check(&supplying_step("echo ${{ steps.x.outputs.v }}")).unwrap_err();
    assert!(matches!(
        e.cause().map(|c| c.0),
        Some(Cause::InputInvalid {
            rule: crate::cause::FieldRule::Supply {
                supply: crate::cause::SupplyRule::ExpressionInSupplyStep { line: 9 }
            },
            ..
        })
    ));
}

#[test]
fn supply_check_accepts_a_github_expression() {
    assert!(check(&supplying_step("echo ${{ github.sha }}")).is_ok());
}

#[test]
fn supply_check_accepts_a_secret_in_the_steps_env() {
    assert!(check(&supplying_step("echo plain")).is_ok());
}

#[test]
fn supply_check_ignores_a_step_that_does_not_supply() {
    let yaml = "jobs:\n  a:\n    steps:\n      - run: echo ${{ steps.x.outputs.v }}\n";
    assert!(check(yaml).is_ok());
}

#[test]
fn supply_check_refuses_an_inline_supplying_run() {
    let yaml =
        "jobs:\n  a:\n    steps:\n      - run: echo ${{ env.V }} | opv sync prod --supply-stdin\n";
    assert!(check(yaml).is_err());
}

#[test]
fn supply_check_of_an_unreadable_file_is_input_unreadable() {
    let e = run_supply_check(
        std::path::Path::new("/nonexistent/apply.yml"),
        &mut Vec::new(),
    )
    .unwrap_err();
    assert!(matches!(
        e.cause().map(|c| c.0),
        Some(Cause::InputUnreadable { .. })
    ));
}
