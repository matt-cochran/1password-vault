//! Recorded flyctl failures mapped to a cause (design §4, §5). One assertion per test.
//!
//! Every fixture is a real recording (`tests/fixtures/fly/failures`): the `.stderr` is the
//! raw reply and the `.exit` is what the runner observed. Test code builds the sealed
//! [`Observed`] the runner would hand to the strategy.

use super::diagnose;
use crate::cause::{
    CallId, Cause, CreateKind, CredentialRef, DiagnoseContext, EnvName, ExitClass, ItemId,
    Observed, Principal, Refind, System, TargetName, VarName,
};

/// The recorded raw stderr and observed exit class for `case`.
fn recorded(case: &str) -> (String, ExitClass) {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/fly/failures");
    let stderr = std::fs::read_to_string(format!("{dir}/{case}.stderr")).expect("stderr recording");
    let raw = std::fs::read_to_string(format!("{dir}/{case}.exit")).expect("exit recording");
    (stderr, exit_class(raw.trim()))
}

/// `timeout(1)` reports 124 for a call it ended; opv's runner reports that as `TimedOut`.
fn exit_class(raw: &str) -> ExitClass {
    match raw.parse::<i32>() {
        Ok(124) => ExitClass::TimedOut,
        Ok(code) => ExitClass::Code { code },
        Err(_) => panic!("recorded exit {raw:?} is not a number"),
    }
}

fn call() -> CallId {
    CallId {
        system: System::Fly,
        program: "flyctl".to_string(),
        words: vec!["auth".to_string(), "whoami".to_string()],
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

fn diagnosed(case: &str, principal: Principal) -> Cause {
    let (stderr, exit) = recorded(case);
    diagnose(
        observed(exit, principal),
        &stderr,
        &DiagnoseContext::default(),
    )
}

#[test]
fn recording_01_signed_out_whoami_is_not_signed_in() {
    assert_eq!(
        diagnosed("01-signed-out-whoami", person()).code(),
        "target_not_signed_in"
    );
}

#[test]
fn recording_02_signed_out_secrets_list_is_not_signed_in() {
    assert_eq!(
        diagnosed("02-signed-out-secrets-list", person()).code(),
        "target_not_signed_in"
    );
}

#[test]
fn recording_03_invalid_token_whoami_is_credential_rejected() {
    assert_eq!(
        diagnosed("03-invalid-token-whoami", shell_token("FLY_API_TOKEN")).code(),
        "credential_rejected"
    );
}

#[test]
fn recording_04_invalid_token_secrets_list_is_credential_rejected() {
    assert_eq!(
        diagnosed(
            "04-invalid-token-secrets-list",
            shell_token("FLY_API_TOKEN")
        )
        .code(),
        "credential_rejected"
    );
}

#[test]
fn recording_05_shell_token_overrides_login_is_credential_rejected() {
    assert_eq!(
        diagnosed(
            "05-shell-token-overrides-login-whoami",
            shell_token("FLY_API_TOKEN")
        )
        .code(),
        "credential_rejected"
    );
}

#[test]
fn recording_06_app_not_found_is_resource_not_found() {
    assert_eq!(
        diagnosed("06-app-not-found-secrets-list", person()).code(),
        "resource_not_found"
    );
}

#[test]
fn recording_08_network_down_signed_out_is_not_signed_in() {
    assert_eq!(
        diagnosed("08-network-unreachable-signed-out-whoami", person()).code(),
        "target_not_signed_in"
    );
}

#[test]
fn recording_09_network_unreachable_whoami_is_provider_unavailable() {
    assert_eq!(
        diagnosed(
            "09-network-unreachable-whoami",
            shell_token("FLY_API_TOKEN")
        )
        .code(),
        "provider_unavailable"
    );
}

#[test]
fn recording_10_network_unreachable_secrets_list_is_provider_unavailable() {
    assert_eq!(
        diagnosed(
            "10-network-unreachable-secrets-list",
            shell_token("FLY_API_TOKEN")
        )
        .code(),
        "provider_unavailable"
    );
}

#[test]
fn recording_11_timeout_is_provider_unavailable() {
    assert_eq!(
        diagnosed(
            "11-timeout-silent-proxy-whoami",
            shell_token("FLY_API_TOKEN")
        )
        .code(),
        "provider_unavailable"
    );
}

#[test]
fn an_unrecorded_flyctl_reply_is_unrecognized() {
    let cause = diagnose(
        observed(ExitClass::Code { code: 1 }, person()),
        "Error: the app is having a bad day",
        &DiagnoseContext::default(),
    );
    assert!(matches!(
        cause,
        Cause::Unrecognized {
            system: System::Fly,
            ..
        }
    ));
}

#[test]
fn a_timed_out_create_has_an_unknown_outcome() {
    let ctx = DiagnoseContext {
        create: Some((CreateKind::DeployToken, "web".to_string(), Refind::ByTitle)),
        ..DiagnoseContext::default()
    };
    let cause = diagnose(observed(ExitClass::TimedOut, person()), "", &ctx);
    assert_eq!(cause.code(), "create_outcome_unknown");
}

#[test]
fn a_timed_out_write_has_an_unknown_outcome() {
    let ctx = DiagnoseContext {
        write: true,
        ..DiagnoseContext::default()
    };
    let cause = diagnose(observed(ExitClass::TimedOut, person()), "", &ctx);
    assert_eq!(cause.code(), "outcome_unknown");
}

#[test]
fn a_signalled_create_has_an_unknown_outcome() {
    let ctx = DiagnoseContext {
        create: Some((CreateKind::DeployToken, "web".to_string(), Refind::ByTitle)),
        ..DiagnoseContext::default()
    };
    let cause = diagnose(
        observed(ExitClass::Signal { signal: 15 }, person()),
        "",
        &ctx,
    );
    assert_eq!(cause.code(), "create_outcome_unknown");
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
fn a_rejected_shell_token_names_the_variable() {
    let cause = diagnosed("03-invalid-token-whoami", shell_token("FLY_API_TOKEN"));
    assert!(matches!(
        cause,
        Cause::CredentialRejected {
            credential: CredentialRef::ShellToken { var },
            ..
        } if var == VarName::new("FLY_API_TOKEN")
    ));
}

#[test]
fn a_rejected_deploy_credential_names_the_deploy_credential() {
    let principal = Principal::DeployCredentials {
        vault: crate::cause::VaultId::new("vlt-deploy"),
        item: ItemId::new("itm-deploy"),
        env: EnvName::new("prod"),
        target: TargetName::new("web"),
    };
    let cause = diagnosed("03-invalid-token-whoami", principal);
    assert!(matches!(
        cause,
        Cause::CredentialRejected {
            credential: CredentialRef::DeployCredentials { .. },
            ..
        }
    ));
}

/// D5/B3: a rejected deploy credential names the vault that holds its item, never "(vault )".
#[test]
fn a_rejected_deploy_credential_names_its_vault() {
    let principal = Principal::DeployCredentials {
        vault: crate::cause::VaultId::new("vlt-deploy"),
        item: ItemId::new("itm-deploy"),
        env: EnvName::new("prod"),
        target: TargetName::new("web"),
    };
    assert!(
        diagnosed("03-invalid-token-whoami", principal)
            .message()
            .contains("(vault vlt-deploy)")
    );
}
