//! R9 acceptance: `opv doctor` reports production-tier vault reads and production
//! platform logins. Every row is a warning; none of them may fail the run.
//!
//! The vault reach uses the same probes `access` observes, with the recorded
//! `op/success/s20-whoami` (`user_uuid` `<USER_A>`) and `s23-writer-vault-user-list`
//! (`<USER_A>` may edit) fixtures. The Kubernetes context name is the recorded
//! `kubernetes/failures/04-context-present-probe.stdout` (`kind-opv-rec`). Fly, Azure and
//! GitHub decide from the provider's own sign-in check, expressed here as opv's own
//! [`ProviderCheck`], never as invented tool output.

use super::*;
use crate::app::testutil::{complete_item, fleet, fleet_with, text_of};
use crate::host::Host;
use crate::provider::Check as ProviderCheck;
use crate::runner::Output;
use crate::runner::fake::FakeRunner;

const S20_WHOAMI: &str = include_str!("../../tests/fixtures/op/success/s20-whoami.stdout");
const S23_WRITER: &str =
    include_str!("../../tests/fixtures/op/success/s23-writer-vault-user-list.stdout");
const KUBE_VERSION: &str =
    include_str!("../../tests/fixtures/kubernetes/failures/07-version-client.stdout");
const KUBE_CONTEXT: &str =
    include_str!("../../tests/fixtures/kubernetes/failures/04-context-present-probe.stdout");

fn host() -> Host {
    Host::from_env(&crate::host::FakeEnv::new("linux").shell("/bin/bash"))
}

/// A production-readable vault warns, naming the environment and the vault.
#[test]
fn reads_of_a_production_vault_warn() {
    let r = FakeRunner::new([
        Output::success(S20_WHOAMI.as_bytes().to_vec()),
        Output::success(S23_WRITER.as_bytes().to_vec()),
    ]);
    let mut report = Report::default();
    reads_production_vault(&fleet(), "prod", &r, &|| host(), &mut report);
    assert!(
        report
            .rows
            .iter()
            .any(|row| row.name == READS_PRODUCTION_CHECK
                && matches!(row.state, State::Warn)
                && row.text.contains("vprd"))
    );
}

/// A shared-tier vault this session can read does not warn (staging is `Shared`).
#[test]
fn a_shared_tier_vault_does_not_warn() {
    let r = FakeRunner::new([
        Output::success(S20_WHOAMI.as_bytes().to_vec()),
        Output::success(S23_WRITER.as_bytes().to_vec()),
    ]);
    let mut report = Report::default();
    reads_production_vault(&fleet(), "staging", &r, &|| host(), &mut report);
    assert!(report.rows.is_empty());
}

/// Kubernetes: the target's context being present in the kubeconfig (the provider's own
/// sign-in check) counts as a live login, and warns. Recorded replies: `kubectl version
/// --client`, then `kubectl config get-contexts kind-opv-rec -o name` (present), then a
/// failed cluster probe so the later checks are skipped.
#[test]
fn a_live_kube_production_login_warns() {
    let f = fleet_with(KUBE);
    let target = f.environments["prod"].targets["kube"].config.as_ref();
    let r = FakeRunner::new([
        Output::success(KUBE_VERSION.as_bytes().to_vec()),
        Output::success(KUBE_CONTEXT.as_bytes().to_vec()),
        Output::failure(1),
    ]);
    let checks = target.doctor(&r, &|| host());
    let mut report = Report::default();
    if production_session_live(target, &checks) {
        production_login_warn(target, "kube", "prod", &mut report);
    }
    assert!(
        report
            .rows
            .iter()
            .any(|row| row.name == PRODUCTION_LOGIN_CHECK && matches!(row.state, State::Warn))
    );
}

/// Kubernetes: the target's context is absent from the kubeconfig, so this shell is not
/// signed in to that target. Recorded replies: `kubectl version --client`, then the
/// failed `kubectl config get-contexts opv-nonexistent -o name` probe.
#[test]
fn a_different_kube_context_does_not_warn() {
    let f = fleet_with(KUBE_MISSING);
    let target = f.environments["prod"].targets["kube"].config.as_ref();
    let r = FakeRunner::new([
        Output::success(KUBE_VERSION.as_bytes().to_vec()),
        Output::failure(1),
    ]);
    let checks = target.doctor(&r, &|| host());
    let mut report = Report::default();
    if production_session_live(target, &checks) {
        production_login_warn(target, "kube", "prod", &mut report);
    }
    assert!(report.rows.is_empty());
}

/// Fly: a live `fly auth` check for a production target warns.
#[test]
fn a_live_fly_production_login_warns() {
    let f = fleet();
    let target = f.environments["prod"].targets["portfolio"].config.as_ref();
    let checks = [live(target)];
    let mut report = Report::default();
    if production_session_live(target, &checks) {
        production_login_warn(target, "portfolio", "prod", &mut report);
    }
    assert!(
        report
            .rows
            .iter()
            .any(|row| row.name == PRODUCTION_LOGIN_CHECK && matches!(row.state, State::Warn))
    );
}

/// Azure: a live `az login` check for a production target warns.
#[test]
fn a_live_azure_production_login_warns() {
    let f = fleet_with(AZURE);
    let target = f.environments["prod"].targets["app"].config.as_ref();
    let checks = [live(target)];
    let mut report = Report::default();
    if production_session_live(target, &checks) {
        production_login_warn(target, "app", "prod", &mut report);
    }
    assert!(
        report
            .rows
            .iter()
            .any(|row| row.name == PRODUCTION_LOGIN_CHECK && matches!(row.state, State::Warn))
    );
}

/// GitHub: a live `gh auth` check for a production target warns.
#[test]
fn a_live_github_production_login_warns() {
    let f = fleet_with(GITHUB);
    let target = f.environments["prod"].targets["gh"].config.as_ref();
    let checks = [live(target)];
    let mut report = Report::default();
    if production_session_live(target, &checks) {
        production_login_warn(target, "gh", "prod", &mut report);
    }
    assert!(
        report
            .rows
            .iter()
            .any(|row| row.name == PRODUCTION_LOGIN_CHECK && matches!(row.state, State::Warn))
    );
}

/// Neither R9 warning can make `opv doctor` fail: with the item readable and both rows
/// firing, the run still succeeds.
#[test]
fn an_r9_warning_does_not_fail_doctor() {
    let r = FakeRunner::new([
        Output::success(b"2.40.0\n".to_vec()),
        Output::success(S20_WHOAMI.as_bytes().to_vec()),
        complete_item(),
        Output::success(S20_WHOAMI.as_bytes().to_vec()),
        Output::success(S23_WRITER.as_bytes().to_vec()),
        Output::success(b"flyctl v0.4.112 linux/amd64 Commit: ca63052e BuildDate: x\n".to_vec()),
        Output::success(b"ops-FIXTUREVALUE@example.com\n".to_vec()),
        Output::success(Vec::new()),
    ]);
    let mut out = Vec::new();
    let res = run_scoped_as(
        Ok(fleet()),
        Some("prod"),
        Some("allumata"),
        false,
        &r,
        &mut out,
    );
    assert!(res.is_ok(), "{:?} {}", res.err(), text_of(&out));
}

/// The provider's own sign-in check (the second it prints), as a passing outcome.
fn live(target: &dyn TargetConfig) -> ProviderCheck {
    let name = target.provider().doctor_checks()[1];
    ProviderCheck {
        name: name.into(),
        outcome: Ok(crate::provider::Verdict::Ok("signed in".into())),
    }
}

/// One Azure target in `prod`, whose `az login` is the provider's second check.
const AZURE: &str = "[environments.prod.targets.app]\nstate_vault_id = \"sprod\"\n\
    [environments.prod.targets.app.azure]\nsubscription = \"00000000-0000-0000-0000-000000000000\"\n\
    key_vault = \"kv\"\nresource_group = \"rg\"\ncontainer_app = \"ca\"\nidentity = \"system\"\n\
    env_name = \"{KEY}\"\n";

/// One GitHub target in `prod`, whose `gh auth` is the provider's second check.
const GITHUB: &str = "[environments.prod.targets.gh]\nstate_vault_id = \"sgh\"\n\
    [environments.prod.targets.gh.github]\nrepo = \"org/r\"\n";

/// One Kubernetes target in `prod`, context `kind-opv-rec` (the recorded context name).
const KUBE: &str = "[environments.prod.targets.kube]\nstate_vault_id = \"skube\"\n\
    kubernetes.context = \"kind-opv-rec\"\nkubernetes.namespace = \"opv-rec\"\n\
    kubernetes.deployment = \"api\"\nkubernetes.env_name = \"{KEY}\"\n";

/// A Kubernetes target whose context is not in the kubeconfig.
const KUBE_MISSING: &str = "[environments.prod.targets.kube]\nstate_vault_id = \"skube\"\n\
    kubernetes.context = \"opv-nonexistent\"\nkubernetes.namespace = \"opv-rec\"\n\
    kubernetes.deployment = \"api\"\nkubernetes.env_name = \"{KEY}\"\n";
