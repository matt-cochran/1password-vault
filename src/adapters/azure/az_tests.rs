//! The `az` failure plumbing: opv's own facts choose the cause, `az`'s reply is evidence
//! (owner decision 2026-10-16, error-catalog §12.4).

use super::*;
use crate::runner::fake::FakeRunner;

const FORBIDDEN: &str =
    "ERROR: (Forbidden) The user does not have secrets set permission on kv-prod\n";
/// What an expired refresh token looks like to a person (audit 06.02); no recording backs
/// it, so opv must not classify it from this text.
const EXPIRED: &str = "ERROR: AADSTS700082: The refresh token has expired due to inactivity. \
                       Please run 'az login' to setup account.\n";

fn ctx() -> DiagnoseContext {
    about(
        ResourceKind::KeyVault,
        "kv-prod",
        "subscription sub-1".into(),
        Some("prod"),
    )
}

/// A `keyvault secret set` that exits 1 with `stderr`, then `az account show` exiting
/// `probe` (when given).
fn failed_set(stderr: &str, probe: Option<Output>) -> Error {
    let r = FakeRunner::default();
    r.push_with_stderr(Output::failure(1), stderr);
    if let Some(p) = probe {
        r.push_with_stderr(p, "");
    }
    let outcome = invoke(
        &r,
        Effect::Write,
        "keyvault secret set",
        &["keyvault", "secret", "set"],
        None,
        &[],
    )
    .unwrap();
    write_output(&r, ctx(), outcome).unwrap_err()
}

/// NR-31: a refused `az` call keeps its own scrubbed reply, as the error's evidence.
#[test]
fn failed_call_shows_the_az_reply_as_evidence() {
    let e = failed_set(FORBIDDEN, Some(Output::success("")));
    assert_eq!(
        e.cause().and_then(|(_, up)| up).map(|u| u.said.clone()),
        Some(vec![FORBIDDEN.trim_end().to_string()])
    );
}

/// 06.02: signed in per `az account show`, the failure is not blamed on a role or a
/// missing resource; with no recording of az's wording it is unrecognised.
#[test]
fn expired_session_while_profile_signed_in_is_unrecognized_not_a_role() {
    let e = failed_set(EXPIRED, Some(Output::success("")));
    assert_eq!(e.code_str(), "unrecognized_failure");
}

#[test]
fn failed_account_show_is_the_azure_sign_in() {
    let e = failed_set(FORBIDDEN, Some(Output::failure(1)));
    assert_eq!(e.code_str(), "target_not_signed_in");
}

#[test]
fn sign_in_probe_that_cannot_run_does_not_claim_signed_out() {
    let r = FakeRunner::default();
    r.push_with_stderr(Output::failure(1), FORBIDDEN);
    r.push_unknown("timeout");
    let outcome = invoke(
        &r,
        Effect::Write,
        "keyvault secret set",
        &["keyvault", "secret", "set"],
        None,
        &[],
    )
    .unwrap();
    let e = write_output(&r, ctx(), outcome).unwrap_err();
    assert_eq!(e.code_str(), "unrecognized_failure");
}

#[test]
fn write_that_never_answered_is_an_unknown_outcome() {
    let r = FakeRunner::default();
    r.push_unknown("timeout");
    let outcome = invoke(
        &r,
        Effect::Write,
        "keyvault secret set",
        &["keyvault", "secret", "set"],
        None,
        &[],
    )
    .unwrap();
    let e = write_output(&r, ctx(), outcome).unwrap_err();
    assert_eq!(e.code_str(), "outcome_unknown");
}

#[test]
fn missing_az_is_a_missing_tool() {
    let r = FakeRunner::default();
    r.push_io_error(io::ErrorKind::NotFound);
    let e = invoke(
        &r,
        Effect::Read,
        "keyvault secret list",
        &["keyvault"],
        None,
        &[],
    )
    .unwrap_err();
    assert_eq!(e.code_str(), "dependency_missing");
}

#[test]
fn sign_in_probe_that_never_answered_is_not_a_sign_out() {
    let r = FakeRunner::default();
    r.push_unknown("timeout");
    let e = signed_in(&r).unwrap_err();
    assert_eq!(e.code_str(), "provider_unavailable");
}
