//! Recorded gh failures mapped to a cause (design §4, §5). One assertion per test.
//!
//! Every fixture is a real recording (`tests/fixtures/github/failures`): the `.stderr` is
//! the raw reply and the `.exit` is what the runner observed. Test code builds the sealed
//! [`Observed`] the runner would hand to the strategy.

use super::diagnose;
use crate::cause::{
    CallId, Cause, CreateKind, CredentialProblem, CredentialRef, DiagnoseContext, EnvName,
    ExitClass, ItemId, Observed, Principal, Refind, SessionState, System, TargetName, VarName,
};

/// The recorded raw stderr and observed exit class for `case`.
fn recorded(case: &str) -> (String, ExitClass) {
    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/github/failures"
    );
    let stderr = std::fs::read_to_string(format!("{dir}/{case}.stderr")).expect("stderr recording");
    let raw = std::fs::read_to_string(format!("{dir}/{case}.exit")).expect("exit recording");
    let code = raw
        .trim()
        .parse::<i32>()
        .expect("recorded exit is a number");
    (stderr, ExitClass::Code { code })
}

fn call() -> CallId {
    CallId {
        system: System::GitHub,
        program: "gh".to_string(),
        words: vec![
            "secret".to_string(),
            "list".to_string(),
            "-R".to_string(),
            "acme/api".to_string(),
        ],
    }
}

fn observed(exit: ExitClass, principal: Principal) -> Observed {
    Observed::from_failed_call(call(), exit, principal)
}

fn person() -> Principal {
    Principal::Person { account: None }
}

fn shell_token(var: &str) -> Principal {
    Principal::ShellToken {
        var: VarName::new(var),
    }
}

fn deploy_credentials() -> Principal {
    Principal::DeployCredentials {
        item: ItemId::new("itm-deploy"),
        env: EnvName::new("prod"),
        target: TargetName::new("ci"),
    }
}

fn diagnosed(case: &str, principal: Principal) -> Cause {
    let (stderr, exit) = recorded(case);
    diagnose(
        observed(exit, principal),
        &stderr,
        &DiagnoseContext::default(),
    )
}

fn timed_out(ctx: &DiagnoseContext) -> Cause {
    diagnose(observed(ExitClass::TimedOut, person()), "", ctx)
}

#[test]
fn recording_01_not_signed_in_is_signed_out() {
    assert!(matches!(
        diagnosed("01-not-signed-in", person()),
        Cause::NotSignedIn {
            system: System::GitHub,
            state: SessionState::SignedOut,
            ..
        }
    ));
}

#[test]
fn recording_02_invalid_token_names_the_shell_token() {
    assert!(matches!(
        diagnosed("02-invalid-token", shell_token("GH_TOKEN")),
        Cause::CredentialRejected {
            system: System::GitHub,
            credential: CredentialRef::ShellToken { var },
            problem: CredentialProblem::Rejected { .. },
            ..
        } if var == VarName::new("GH_TOKEN")
    ));
}

#[test]
fn recording_03_login_with_token_refused_is_overridden_by_gh_token() {
    assert!(matches!(
        diagnosed("03-login-with-token-refused", shell_token("GH_TOKEN")),
        Cause::CredentialRejected {
            problem: CredentialProblem::OverriddenByEnvironment { var },
            ..
        } if var == VarName::new("GH_TOKEN")
    ));
}

#[test]
fn recording_03_names_gh_token_from_the_reply_when_no_principal_did() {
    assert!(matches!(
        diagnosed("03-login-with-token-refused", person()),
        Cause::CredentialRejected {
            problem: CredentialProblem::OverriddenByEnvironment { var },
            ..
        } if var == VarName::new("GH_TOKEN")
    ));
}

#[test]
fn recording_04_repo_lookup_with_invalid_token_is_the_rejected_token() {
    assert!(matches!(
        diagnosed("04-repo-not-found", shell_token("GH_TOKEN")),
        Cause::CredentialRejected {
            credential: CredentialRef::ShellToken { var },
            ..
        } if var == VarName::new("GH_TOKEN")
    ));
}

#[test]
fn recording_05_secret_list_not_signed_in_is_signed_out() {
    assert!(matches!(
        diagnosed("05-secret-list-not-signed-in", person()),
        Cause::NotSignedIn {
            system: System::GitHub,
            state: SessionState::SignedOut,
            ..
        }
    ));
}

#[test]
fn a_rejected_github_token_names_that_variable() {
    assert!(matches!(
        diagnosed("02-invalid-token", shell_token("GITHUB_TOKEN")),
        Cause::CredentialRejected {
            credential: CredentialRef::ShellToken { var },
            ..
        } if var == VarName::new("GITHUB_TOKEN")
    ));
}

#[test]
fn a_rejected_deploy_credential_names_the_deploy_credential() {
    assert_eq!(
        diagnosed("02-invalid-token", deploy_credentials()).code(),
        "deploy_credentials_failed"
    );
}

#[test]
fn bad_credentials_without_a_token_is_an_expired_login() {
    assert!(matches!(
        diagnosed("02-invalid-token", person()),
        Cause::NotSignedIn {
            system: System::GitHub,
            state: SessionState::Expired,
            ..
        }
    ));
}

#[test]
fn a_timed_out_create_has_an_unknown_outcome() {
    let ctx = DiagnoseContext {
        create: Some((
            CreateKind::GitHubEnvironment,
            "prod".to_string(),
            Refind::ByTitle,
        )),
        ..DiagnoseContext::default()
    };
    assert_eq!(timed_out(&ctx).code(), "create_outcome_unknown");
}

#[test]
fn a_timed_out_write_has_an_unknown_outcome() {
    let ctx = DiagnoseContext {
        write: true,
        ..DiagnoseContext::default()
    };
    assert_eq!(timed_out(&ctx).code(), "outcome_unknown");
}

#[test]
fn a_timed_out_read_is_unavailable() {
    assert_eq!(
        timed_out(&DiagnoseContext::default()).code(),
        "provider_unavailable"
    );
}

#[test]
fn a_signalled_write_has_an_unknown_outcome() {
    let ctx = DiagnoseContext {
        write: true,
        ..DiagnoseContext::default()
    };
    let cause = diagnose(
        observed(ExitClass::Signal { signal: 15 }, person()),
        "",
        &ctx,
    );
    assert_eq!(cause.code(), "outcome_unknown");
}

#[test]
fn an_unrecorded_gh_reply_is_unrecognized() {
    let cause = diagnose(
        observed(ExitClass::Code { code: 1 }, person()),
        "gh: something nobody recorded (HTTP 418)",
        &DiagnoseContext::default(),
    );
    assert!(matches!(
        cause,
        Cause::Unrecognized {
            system: System::GitHub,
            ..
        }
    ));
}

#[test]
fn spike_q9_secret_list_with_a_rejected_deploy_token_is_deploy_credentials_failed() {
    let stderr = include_str!("../../../tests/fixtures/github/stderr-bad_token.txt");
    let cause = diagnose(
        observed(ExitClass::Code { code: 1 }, deploy_credentials()),
        stderr,
        &DiagnoseContext::default(),
    );
    assert_eq!(cause.code(), "deploy_credentials_failed");
}
