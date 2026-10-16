//! The ssh diagnosis strategy against the recorded OpenSSH failures (design §5, #139): one
//! behavioral assertion per scenario.

use std::path::Path;

use super::*;
use crate::cause::{
    CallId, Cause, CreateKind, CredentialRef, DiagnoseContext, EnvName, ExitClass, ItemId,
    Observed, Principal, Refind, System, TargetName, VarName,
};

fn observed(exit: ExitClass, principal: Principal) -> Observed {
    Observed::from_failed_call(
        CallId {
            system: System::Ssh,
            program: "ssh".into(),
            words: vec!["-F".into(), "none".into(), "--".into(), "host".into()],
        },
        exit,
        principal,
    )
}

fn person() -> Principal {
    Principal::Person { account: None }
}

fn conn_before() -> Connection<'static> {
    Connection {
        profile: "lab",
        user: "deploy",
        host: "127.0.0.1",
        port: 42222,
        known_hosts: Path::new("/tmp/known_hosts"),
        identity_file: Some(Path::new("/tmp/id_ed25519")),
        remote_program: "/opt/opv",
        handshake_done: false,
        payload_confirmed: false,
    }
}

fn conn_after() -> Connection<'static> {
    Connection {
        handshake_done: true,
        ..conn_before()
    }
}

fn exit_code(raw: &str) -> i32 {
    raw.trim()
        .parse()
        .expect("the .exit fixture holds an integer")
}

fn diagnosed(stderr: &str, exit: &str, conn: &Connection<'_>) -> Cause {
    diagnose(
        observed(
            ExitClass::Code {
                code: exit_code(exit),
            },
            person(),
        ),
        stderr,
        conn,
        &DiagnoseContext::default(),
    )
}

// --- one recorded fixture case each --------------------------------------------------------

#[test]
fn case_01_host_key_mismatch_is_remote_unreachable() {
    let cause = diagnosed(
        include_str!("../../tests/fixtures/ssh/failures/01-host-key-mismatch.stderr"),
        include_str!("../../tests/fixtures/ssh/failures/01-host-key-mismatch.exit"),
        &conn_before(),
    );
    assert_eq!(cause.code(), "remote_unreachable");
}

#[test]
fn case_02_host_key_unknown_is_remote_unreachable() {
    let cause = diagnosed(
        include_str!("../../tests/fixtures/ssh/failures/02-host-key-unknown.stderr"),
        include_str!("../../tests/fixtures/ssh/failures/02-host-key-unknown.exit"),
        &conn_before(),
    );
    assert_eq!(cause.code(), "remote_unreachable");
}

#[test]
fn case_03_auth_refused_is_credential_rejected() {
    let cause = diagnosed(
        include_str!("../../tests/fixtures/ssh/failures/03-auth-refused.stderr"),
        include_str!("../../tests/fixtures/ssh/failures/03-auth-refused.exit"),
        &conn_before(),
    );
    assert_eq!(cause.code(), "credential_rejected");
}

#[test]
fn case_04_auth_identity_missing_is_credential_rejected() {
    let cause = diagnosed(
        include_str!("../../tests/fixtures/ssh/failures/04-auth-identity-missing.stderr"),
        include_str!("../../tests/fixtures/ssh/failures/04-auth-identity-missing.exit"),
        &conn_before(),
    );
    assert_eq!(cause.code(), "credential_rejected");
}

#[test]
fn case_05_connection_refused_is_remote_unreachable() {
    let cause = diagnosed(
        include_str!("../../tests/fixtures/ssh/failures/05-connection-refused.stderr"),
        include_str!("../../tests/fixtures/ssh/failures/05-connection-refused.exit"),
        &conn_before(),
    );
    assert_eq!(cause.code(), "remote_unreachable");
}

#[test]
fn case_06_name_resolution_failure_is_remote_unreachable() {
    let cause = diagnosed(
        include_str!("../../tests/fixtures/ssh/failures/06-name-resolution-failed.stderr"),
        include_str!("../../tests/fixtures/ssh/failures/06-name-resolution-failed.exit"),
        &conn_before(),
    );
    assert_eq!(cause.code(), "remote_unreachable");
}

#[test]
fn case_07_remote_command_missing_path_is_child_start_failed() {
    let cause = diagnosed(
        include_str!("../../tests/fixtures/ssh/failures/07-remote-command-missing-path.stderr"),
        include_str!("../../tests/fixtures/ssh/failures/07-remote-command-missing-path.exit"),
        &conn_after(),
    );
    assert_eq!(cause.code(), "child_start_failed");
}

#[test]
fn case_08_remote_command_not_on_path_is_child_start_failed() {
    let cause = diagnosed(
        include_str!("../../tests/fixtures/ssh/failures/08-remote-command-not-on-path.stderr"),
        include_str!("../../tests/fixtures/ssh/failures/08-remote-command-not-on-path.exit"),
        &conn_after(),
    );
    assert_eq!(cause.code(), "child_start_failed");
}

#[test]
fn case_09_session_killed_mid_delivery_is_remote_disconnected() {
    let cause = diagnosed(
        include_str!("../../tests/fixtures/ssh/failures/09-drop-session-killed.stderr"),
        include_str!("../../tests/fixtures/ssh/failures/09-drop-session-killed.exit"),
        &conn_after(),
    );
    assert_eq!(cause.code(), "remote_disconnected");
}

#[test]
fn case_10_server_unresponsive_is_remote_disconnected() {
    let cause = diagnosed(
        include_str!("../../tests/fixtures/ssh/failures/10-drop-server-unresponsive.stderr"),
        include_str!("../../tests/fixtures/ssh/failures/10-drop-server-unresponsive.exit"),
        &conn_after(),
    );
    assert_eq!(cause.code(), "remote_disconnected");
}

#[test]
fn case_11_success_is_left_unrecognized_by_the_failure_strategy() {
    let cause = diagnosed(
        include_str!("../../tests/fixtures/ssh/failures/11-success.stderr"),
        include_str!("../../tests/fixtures/ssh/failures/11-success.exit"),
        &conn_after(),
    );
    assert_eq!(cause.code(), "unrecognized_failure");
}

#[test]
fn case_12_connect_timeout_is_remote_unreachable() {
    let cause = diagnosed(
        include_str!("../../tests/fixtures/ssh/failures/12-connect-timeout.stderr"),
        include_str!("../../tests/fixtures/ssh/failures/12-connect-timeout.exit"),
        &conn_before(),
    );
    assert_eq!(cause.code(), "remote_unreachable");
}

// --- the rules the fixtures cannot show -----------------------------------------------------

#[test]
fn unrecognized_ssh_stderr_is_unrecognized() {
    let cause = diagnosed("ssh: something nobody recorded", "255", &conn_before());
    assert_eq!(cause.code(), "unrecognized_failure");
}

#[test]
fn a_timed_out_create_has_an_unknown_outcome() {
    let ctx = DiagnoseContext {
        create: Some((CreateKind::Item, "db-url".into(), Refind::ByTitle)),
        ..DiagnoseContext::default()
    };
    let cause = diagnose(
        observed(ExitClass::TimedOut, person()),
        "",
        &conn_after(),
        &ctx,
    );
    assert_eq!(cause.code(), "create_outcome_unknown");
}

#[test]
fn a_timed_out_write_has_an_unknown_outcome() {
    let ctx = DiagnoseContext {
        write: true,
        ..DiagnoseContext::default()
    };
    let cause = diagnose(
        observed(ExitClass::TimedOut, person()),
        "",
        &conn_after(),
        &ctx,
    );
    assert_eq!(cause.code(), "outcome_unknown");
}

#[test]
fn a_rejected_shell_token_names_the_token() {
    let principal = Principal::ShellToken {
        var: VarName::new("DEPLOY_TOKEN"),
    };
    let cause = diagnose(
        observed(ExitClass::Code { code: 255 }, principal),
        "deploy@127.0.0.1: Permission denied (publickey).",
        &conn_before(),
        &DiagnoseContext::default(),
    );
    assert!(matches!(
        cause,
        Cause::CredentialRejected {
            credential: CredentialRef::ShellToken { var },
            ..
        } if var.as_str() == "DEPLOY_TOKEN"
    ));
}

#[test]
fn a_rejected_deploy_credential_names_the_credential() {
    let principal = Principal::DeployCredentials {
        item: ItemId::new("item-deploy"),
        env: EnvName::new("prod"),
        target: TargetName::new("web"),
    };
    let cause = diagnose(
        observed(ExitClass::Code { code: 255 }, principal),
        "deploy@127.0.0.1: Permission denied (publickey).",
        &conn_before(),
        &DiagnoseContext::default(),
    );
    assert!(matches!(
        cause,
        Cause::CredentialRejected {
            credential: CredentialRef::DeployCredentials { item, .. },
            ..
        } if item.as_str() == "item-deploy"
    ));
}
