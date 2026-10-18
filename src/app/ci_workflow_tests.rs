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
