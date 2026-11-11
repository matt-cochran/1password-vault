//! #296: reporting recorded CI credential expiry in `ready`, `doctor` and `status`. One
//! behavioural scenario per test, each through a public interface, value-free.

use super::*;
use crate::config::Source;
use crate::config::bindings::Bindings;
use crate::domain::Fleet;
use crate::domain::credential::{CredentialKind, ExpiryState};

/// A minimal deployable fleet: one run-only-boundary product and one Fly target, so both
/// the environment's CI reader and a target's credentials can be recorded.
const CONFIG: &str = "\
[environments.staging]
boundaries.web = { vault_id = \"vweb\", item_id = \"iweb\" }

[environments.staging.targets.web]
fly.app = \"shop-staging\"
fly.secret_name = \"{KEY}\"
state_vault_id = \"vstate\"

[products.web.keys.WEB_KEY]
kind = \"secret\"
environments = [\"staging\"]
";

fn today() -> String {
    crate::app::retire::today()
}

/// Write `CONFIG` and `bindings` as a project beside a temp contract, and load the fleet
/// from that file so its `read_from` names the sibling bindings.
fn located(
    text: &str,
    bindings: &[(&str, &str)],
) -> (tempfile::TempDir, std::path::PathBuf, Fleet) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.toml");
    std::fs::write(&path, text).unwrap();
    let mut b = Bindings::default();
    for (key, value) in bindings {
        b.insert(*key, *value);
    }
    crate::config::bindings::write_sibling(&path, &b).unwrap();
    let fleet = crate::config::parse_at(text, Source::File(&path)).unwrap();
    (dir, path, fleet)
}

/// One environment input for `credential_health`, with no rows to read.
fn env(name: &str) -> EnvInput {
    EnvInput {
        name: name.into(),
        target: None,
        rows: Ok(Vec::new()),
        title: None,
        audience: None,
        personal_item: Default::default(),
    }
}

/// An account report with no account selected and no findings.
fn no_accounts() -> crate::app::account::Report {
    crate::app::account::Report {
        discovery: "unavailable".into(),
        platform: "linux".into(),
        cli_accounts_only: false,
        selected: None,
        accounts: Vec::new(),
        findings: Vec::new(),
        next: None,
    }
}

/// The ready findings for `fleet` and `envs`, with credential health as `ready` builds it.
fn ready_findings(fleet: &Fleet, envs: Vec<EnvInput>) -> Vec<Finding> {
    let account = no_accounts();
    let health = credential_health(fleet, &envs, &today());
    let inputs = Inputs {
        config_source: Some("secrets.toml".into()),
        account: &account,
        envs,
        personal: Default::default(),
        health,
        retirement: Vec::new(),
    };
    receipt(&inputs, "test").findings
}

fn ci_reader_path() -> String {
    crate::domain::credential::ci_reader_expires_path("staging")
}

fn ci_identity_path() -> String {
    crate::domain::credential::ci_identity_expires_path("staging", "web")
}

fn deploy_path() -> String {
    crate::domain::credential::deploy_expires_path("staging", "web")
}

#[test]
fn a_credential_fourteen_days_out_is_expiring() {
    let today = today();
    let expires = crate::domain::credential::add_days(&today, 14).unwrap();
    let (_d, _p, fleet) = located(CONFIG, &[(&ci_reader_path(), &expires)]);
    let record = credential_records(&fleet, "staging");
    assert_eq!(
        credential_state(&record[0], &today),
        ExpiryState::Expiring { days_left: 14 }
    );
}

#[test]
fn a_credential_fifteen_days_out_is_ok() {
    let today = today();
    let expires = crate::domain::credential::add_days(&today, 15).unwrap();
    let (_d, _p, fleet) = located(CONFIG, &[(&ci_reader_path(), &expires)]);
    let record = credential_records(&fleet, "staging");
    assert_eq!(
        credential_state(&record[0], &today),
        ExpiryState::Ok { days_left: 15 }
    );
}

#[test]
fn a_credential_at_its_date_is_expired() {
    let today = today();
    let (_d, _p, fleet) = located(CONFIG, &[(&ci_reader_path(), &today)]);
    let record = credential_records(&fleet, "staging");
    assert_eq!(credential_state(&record[0], &today), ExpiryState::Expired);
}

#[test]
fn a_manifest_project_reports_no_credential() {
    let fleet = crate::config::parse_at(CONFIG, Source::Manifest("opv · app")).unwrap();
    assert!(credential_records(&fleet, "staging").is_empty());
}

#[test]
fn ready_reports_an_expiring_credential_as_a_health_finding() {
    let today = today();
    let expires = crate::domain::credential::add_days(&today, 14).unwrap();
    let (_d, _p, fleet) = located(CONFIG, &[(&ci_reader_path(), &expires)]);
    let findings = credential_health(&fleet, &[env("staging")], &today);
    assert_eq!(findings[0].code, CREDENTIAL_EXPIRING);
}

#[test]
fn ready_names_a_target_credential_by_its_target() {
    let today = today();
    let expires = crate::domain::credential::add_days(&today, 14).unwrap();
    let (_d, _p, fleet) = located(CONFIG, &[(&deploy_path(), &expires)]);
    let findings = credential_health(&fleet, &[env("staging")], &today);
    assert_eq!(findings[0].key, "web");
}

#[test]
fn a_ci_reader_finding_next_rotates_access_without_a_target() {
    let today = today();
    let expires = crate::domain::credential::add_days(&today, 14).unwrap();
    let (_d, _p, fleet) = located(CONFIG, &[(&ci_reader_path(), &expires)]);
    let findings = ready_findings(&fleet, vec![env("staging")]);
    assert_eq!(
        findings[0].prerequisite,
        "opv access staging --rotate --github <owner/repo>"
    );
}

#[test]
fn a_target_service_account_finding_next_rotates_access_with_its_target() {
    let today = today();
    let expires = crate::domain::credential::add_days(&today, 14).unwrap();
    let (_d, _p, fleet) = located(CONFIG, &[(&ci_identity_path(), &expires)]);
    let findings = ready_findings(&fleet, vec![env("staging")]);
    assert_eq!(
        findings[0].prerequisite,
        "opv access staging --target web --rotate --github <owner/repo>"
    );
}

#[test]
fn a_deploy_credential_finding_next_rotates_target_credentials() {
    let today = today();
    let expires = crate::domain::credential::add_days(&today, 14).unwrap();
    let (_d, _p, fleet) = located(CONFIG, &[(&deploy_path(), &expires)]);
    let findings = ready_findings(&fleet, vec![env("staging")]);
    assert_eq!(
        findings[0].prerequisite,
        "opv target credentials staging --target web --rotate"
    );
}

#[test]
fn doctor_fails_an_expired_credential_check_in_its_json() {
    let today = today();
    let (_d, _p, fleet) = located(CONFIG, &[(&ci_reader_path(), &today)]);
    let runner = crate::adapters::fake_op::FakeOp::default();
    let mut out = Vec::new();
    let _ = crate::app::doctor::run_scoped_as(
        Ok(fleet),
        Some("staging"),
        None,
        true,
        &runner,
        &mut out,
    );
    let doc: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let check = doc["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "ci reader credential")
        .cloned()
        .unwrap();
    assert_eq!(check["status"], "fail");
}

#[test]
fn doctor_warns_an_expiring_credential_check_in_its_json() {
    let today = today();
    let expires = crate::domain::credential::add_days(&today, 14).unwrap();
    let (_d, _p, fleet) = located(CONFIG, &[(&ci_reader_path(), &expires)]);
    let runner = crate::adapters::fake_op::FakeOp::default();
    let mut out = Vec::new();
    let _ = crate::app::doctor::run_scoped_as(
        Ok(fleet),
        Some("staging"),
        None,
        true,
        &runner,
        &mut out,
    );
    let doc: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let check = doc["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "ci reader credential")
        .cloned()
        .unwrap();
    assert_eq!(check["status"], "warn");
}

#[test]
fn status_prints_an_expiring_credential_line() {
    let today = today();
    let expires = crate::domain::credential::add_days(&today, 14).unwrap();
    let (_d, _p, fleet) = located(CONFIG, &[(&ci_reader_path(), &expires)]);
    let mut out = Vec::new();
    crate::app::status::print_credentials(&mut out, &fleet, "staging").unwrap();
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains("staging: credential ci reader: expiring in 14 days"),
        "{text}"
    );
}

#[test]
fn credential_next_for_a_deploy_credential_rotates_the_target() {
    assert_eq!(
        credential_next(CredentialKind::Deploy, "staging", Some("web")),
        "opv target credentials staging --target web --rotate"
    );
}
