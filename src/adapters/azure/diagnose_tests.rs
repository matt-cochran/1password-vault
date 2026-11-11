//! Azure diagnosis: the runner-level facts only, no Azure wording (owner decision
//! 2026-10-16, error-catalog §12.4). There is no recorded Azure failure fixture, so every
//! `az` phrase is `Unrecognized` for now.

use super::{GithubContext, diagnose, federated_checks, with_github_context};
use crate::cause::{
    CallId, Cause, CreateKind, DiagnoseContext, ExitClass, Observed, Principal, Refind,
    ResourceKind, ResourceName, ResourceRef, System,
};
use crate::domain::FederatedIdentity;
use crate::provider::{Check, Verdict};
use crate::runner::Output;
use crate::runner::fake::FakeRunner;
use serde_json::json;

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

// ---- federated deploy identity in doctor (#297) ----

/// The federated target of the OIDC spike's fakes (tests/fixtures/azure/oidc/README.md).
fn federated_target() -> crate::adapters::azure::AzureTarget {
    crate::adapters::azure::AzureTarget {
        subscription: "33333333-3333-3333-3333-333333333333".into(),
        key_vault: "kv-opv-fixture".into(),
        resource_group: "opv-fixture-rg".into(),
        container_app: "opv-fixture-app".into(),
        container: None,
        identity: "system".into(),
        env_name_template: "FLEET__{PRODUCT}__{KEY}".into(),
        config: crate::adapters::azure::ConfigRoute::Env,
        companion_jobs: Vec::new(),
        federated: Some(FederatedIdentity {
            tenant_id: "11111111-1111-1111-1111-111111111111".into(),
            client_id: "22222222-2222-2222-2222-222222222222".into(),
            subscription_id: "33333333-3333-3333-3333-333333333333".into(),
        }),
        vault_uri: Default::default(),
    }
}

/// The ambient context of a job with a GitHub environment.
fn in_actions(repo: &str, environment: &str) -> GithubContext {
    GithubContext {
        actions: true,
        repository: Some(repo.into()),
        environment: Some(environment.into()),
        self_hosted: false,
    }
}

fn check<'a>(checks: &'a [Check], name: &str) -> &'a Check {
    checks
        .iter()
        .find(|c| c.name == name)
        .expect("missing check")
}

/// R1: a federated Azure target's doctor names the mode with its three non-secret ids.
#[test]
fn federated_doctor_shows_the_deploy_identity_mode() {
    let r = FakeRunner::default();
    let checks = with_github_context(in_actions("example-org/example-repo", "prod"), || {
        federated_checks(&federated_target(), &r, false)
    });
    assert!(matches!(
        check(&checks, "deploy identity").outcome,
        Ok(Verdict::Ok(ref m)) if m == "federated (tenant 11111111-1111-1111-1111-111111111111, \
            client 22222222-2222-2222-2222-222222222222, subscription 33333333-3333-3333-3333-333333333333)"
    ));
}

/// R2: inside GitHub Actions a subject the app does not trust is reported with one Next.
#[test]
fn federated_doctor_reports_a_subject_mismatch_with_a_next() {
    let r = FakeRunner::new(vec![Output::success(
        serde_json::to_vec(&json!([{ "subject": "repo:other/repo:environment:prod" }])).unwrap(),
    )]);
    let checks = with_github_context(in_actions("example-org/example-repo", "prod"), || {
        federated_checks(&federated_target(), &r, true)
    });
    assert!(matches!(
        check(&checks, "federated credential").outcome,
        Ok(Verdict::Warn(ref m))
            if m.contains("repo:example-org/example-repo:environment:prod")
                && m.lines().filter(|l| l.starts_with("  ")).count() == 1
                && m.contains("az ad app federated-credential create")
    ));
}

/// R3: a self-hosted runner warns that the session may stay on disk.
#[test]
fn federated_doctor_warns_on_a_self_hosted_runner() {
    let r = FakeRunner::default();
    let ctx = GithubContext {
        self_hosted: true,
        ..in_actions("example-org/example-repo", "prod")
    };
    let checks = with_github_context(ctx, || federated_checks(&federated_target(), &r, false));
    assert!(matches!(
        check(&checks, "runner").outcome,
        Ok(Verdict::Warn(ref m)) if m.contains("self-hosted") && m.contains("az logout")
    ));
}

/// R4: outside GitHub Actions the federated mode is `CI only`, an info line, not a failure.
#[test]
fn federated_doctor_outside_github_actions_is_ci_only() {
    let r = FakeRunner::default();
    let checks = with_github_context(GithubContext::default(), || {
        federated_checks(&federated_target(), &r, true)
    });
    assert!(matches!(
        check(&checks, "deploy identity").outcome,
        Ok(Verdict::Ok(ref m)) if m.contains("CI only")
    ));
}
