//! Azure diagnosis: the runner-level facts only, no Azure wording (owner decision
//! 2026-10-16, error-catalog §12.4). There is no recorded Azure failure fixture, so every
//! `az` phrase is `Unrecognized` for now.

use super::diagnose;
use crate::cause::{
    CallId, Cause, CreateKind, DiagnoseContext, ExitClass, Observed, Principal, Refind,
    ResourceKind, ResourceName, ResourceRef, System,
};

fn seen(exit: ExitClass) -> Observed {
    Observed::from_failed_call(
        CallId {
            system: System::Azure,
            program: "az".to_string(),
            words: vec!["keyvault".to_string(), "show".to_string()],
        },
        exit,
        Principal::Person { account: None },
    )
}

fn create_ctx() -> DiagnoseContext {
    DiagnoseContext {
        create: Some((
            CreateKind::GitHubEnvironment,
            "env-prod".to_string(),
            Refind::ByTitle,
        )),
        ..DiagnoseContext::default()
    }
}

fn write_ctx() -> DiagnoseContext {
    DiagnoseContext {
        write: true,
        resource: Some(ResourceRef {
            kind: ResourceKind::KeyVault,
            name: ResourceName::new("kv-demo"),
            scope: None,
        }),
        ..DiagnoseContext::default()
    }
}

#[test]
fn a_timed_out_create_is_a_create_outcome_unknown() {
    let cause = diagnose(seen(ExitClass::TimedOut), "", &create_ctx());
    assert_eq!(cause.code(), "create_outcome_unknown");
}

#[test]
fn a_timed_out_write_is_an_outcome_unknown() {
    let cause = diagnose(seen(ExitClass::TimedOut), "", &write_ctx());
    assert_eq!(cause.code(), "outcome_unknown");
}

#[test]
fn a_timed_out_read_is_a_provider_unavailable() {
    let cause = diagnose(seen(ExitClass::TimedOut), "", &DiagnoseContext::default());
    assert_eq!(cause.code(), "provider_unavailable");
}

#[test]
fn a_spawn_failure_is_a_dependency_missing() {
    let cause = diagnose(
        seen(ExitClass::SpawnFailed),
        "",
        &DiagnoseContext::default(),
    );
    assert_eq!(cause.code(), "dependency_missing");
}

#[test]
fn a_signal_interrupting_a_read_is_a_provider_unavailable() {
    let cause = diagnose(
        seen(ExitClass::Signal { signal: 9 }),
        "",
        &DiagnoseContext::default(),
    );
    assert_eq!(cause.code(), "provider_unavailable");
}

#[test]
fn an_unrecorded_azure_error_is_unrecognized() {
    let cause = diagnose(
        seen(ExitClass::Code { code: 1 }),
        "ERROR: something az said that opv has no recording for",
        &DiagnoseContext::default(),
    );
    assert!(matches!(
        cause,
        Cause::Unrecognized {
            system: System::Azure,
            ..
        }
    ));
}
