//! `opv ci workflow` (j7): print a ready-to-commit GitHub Actions workflow for one target.
//!
//! The printed workflow is read-only output: it names the target's provider only through
//! `TargetConfig`, references no secret besides the 1Password service-account token, and
//! refuses an unknown environment or target before printing anything.

use super::*;
use crate::app::testutil::text_of;
use crate::config;
use crate::error::Code;

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
    assert_eq!(fly_workflow(None, false).matches("${{ secrets.").count(), 1);
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
    let (err, _) = refused("missing", "portfolio");
    assert_eq!(err.code(), Code::Usage);
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
