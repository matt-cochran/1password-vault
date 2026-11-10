//! The credential lifecycle contract (#296, #297): one behavior per test. Every record
//! here is value-free: an identity name and a date, never a token.

use super::credential::{
    CredentialKind, DEFAULT_EXPIRY_WINDOW_DAYS, ExpiryState, ci_identity_expires_path,
    ci_reader_expires_path, deploy_expires_path, expiry_state, records,
};
use crate::config::bindings::Bindings;

#[test]
fn a_missing_expiry_date_is_unknown() {
    assert_eq!(
        expiry_state(None, "2026-11-10", DEFAULT_EXPIRY_WINDOW_DAYS),
        ExpiryState::Unknown
    );
}

#[test]
fn an_unparsable_expiry_date_is_unknown() {
    assert_eq!(
        expiry_state(Some("not-a-date"), "2026-11-10", DEFAULT_EXPIRY_WINDOW_DAYS),
        ExpiryState::Unknown
    );
}

#[test]
fn an_expiry_today_is_expired_at_zero_days() {
    assert_eq!(
        expiry_state(Some("2026-11-10"), "2026-11-10", DEFAULT_EXPIRY_WINDOW_DAYS),
        ExpiryState::Expired
    );
}

#[test]
fn an_expiry_in_fourteen_days_is_expiring() {
    assert_eq!(
        expiry_state(Some("2026-11-24"), "2026-11-10", DEFAULT_EXPIRY_WINDOW_DAYS),
        ExpiryState::Expiring { days_left: 14 }
    );
}

#[test]
fn an_expiry_in_fifteen_days_is_ok() {
    assert_eq!(
        expiry_state(Some("2026-11-25"), "2026-11-10", DEFAULT_EXPIRY_WINDOW_DAYS),
        ExpiryState::Ok { days_left: 15 }
    );
}

#[test]
fn the_ci_reader_expiry_path_is_the_dotted_bindings_key() {
    assert_eq!(
        ci_reader_expires_path("prod"),
        "environments.prod.ci_reader.expires_on"
    );
}

#[test]
fn the_deploy_expiry_path_is_the_dotted_bindings_key() {
    assert_eq!(
        deploy_expires_path("prod", "web"),
        "environments.prod.targets.web.deploy_credentials_expires_on"
    );
}

#[test]
fn the_ci_identity_expiry_path_is_the_dotted_bindings_key() {
    assert_eq!(
        ci_identity_expires_path("prod", "web"),
        "environments.prod.targets.web.ci_identity.expires_on"
    );
}

#[test]
fn bindings_accept_every_expiry_record_key() {
    let text = "\
environments.prod.ci_reader.expires_on = \"2026-11-24\"
environments.prod.targets.web.deploy_credentials_expires_on = \"2026-11-25\"
environments.prod.targets.web.ci_identity.expires_on = \"2026-12-01\"
";
    assert_eq!(
        Bindings::parse(text)
            .map(|b| vec![
                b.get("environments.prod.ci_reader.expires_on")
                    .map(str::to_owned),
                b.get("environments.prod.targets.web.deploy_credentials_expires_on")
                    .map(str::to_owned),
                b.get("environments.prod.targets.web.ci_identity.expires_on")
                    .map(str::to_owned),
            ])
            .ok(),
        Some(vec![
            Some("2026-11-24".to_string()),
            Some("2026-11-25".to_string()),
            Some("2026-12-01".to_string()),
        ])
    );
}

#[test]
fn records_reads_the_ci_reader_expiry_as_a_service_account() {
    let bindings =
        Bindings::parse("environments.prod.ci_reader.expires_on = \"2026-11-24\"\n").unwrap();
    let out = records(&bindings, "prod", &[]);
    assert_eq!(
        (
            out[0].kind,
            out[0].target.as_deref(),
            out[0].expires_on.as_deref()
        ),
        (CredentialKind::ServiceAccount, None, Some("2026-11-24"))
    );
}

#[test]
fn records_reads_each_targets_deploy_expiry() {
    let bindings = Bindings::parse(
        "environments.prod.targets.web.deploy_credentials_expires_on = \"2026-11-25\"\n",
    )
    .unwrap();
    let out = records(&bindings, "prod", &["web".to_string()]);
    assert_eq!(
        (
            out[0].kind,
            out[0].target.as_deref(),
            out[0].expires_on.as_deref()
        ),
        (CredentialKind::Deploy, Some("web"), Some("2026-11-25"))
    );
}

#[test]
fn records_reads_each_targets_ci_service_account_expiry() {
    let bindings =
        Bindings::parse("environments.prod.targets.web.ci_identity.expires_on = \"2026-12-01\"\n")
            .unwrap();
    let out = records(&bindings, "prod", &["web".to_string()]);
    assert_eq!(
        (
            out[0].kind,
            out[0].target.as_deref(),
            out[0].expires_on.as_deref()
        ),
        (
            CredentialKind::ServiceAccount,
            Some("web"),
            Some("2026-12-01")
        )
    );
}

#[test]
fn ninety_days_after_a_date_crosses_the_year_end() {
    assert_eq!(
        crate::domain::credential::add_days("2026-11-10", 90).as_deref(),
        Some("2027-02-08")
    );
}
