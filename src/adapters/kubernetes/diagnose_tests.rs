//! The kubectl strategy against the recorded failures (design §4/§5). One atomic test per
//! fixture, each asserting one cause code from the public strategy.

use super::diagnose;
use crate::cause::{
    CallId, CreateKind, DiagnoseContext, EnvName, ExitClass, ItemId, Observed, Principal, Refind,
    System, TargetName, VarName,
};

fn seen_as(exit: ExitClass, words: &[&str], principal: Principal) -> Observed {
    Observed::from_failed_call(
        CallId {
            system: System::Kubernetes,
            program: "kubectl".to_string(),
            words: words.iter().map(|w| (*w).to_string()).collect(),
        },
        exit,
        principal,
    )
}

fn seen(exit: i32, words: &[&str]) -> Observed {
    seen_as(
        ExitClass::Code { code: exit },
        words,
        Principal::Person { account: None },
    )
}

/// Load a recorded `<name>.stderr` and `<name>.exit` and return the classified code.
macro_rules! fixture_code {
    ($name:literal, $words:expr) => {{
        let stderr = include_str!(concat!(
            "../../../tests/fixtures/kubernetes/failures/",
            $name,
            ".stderr"
        ));
        let exit: i32 = include_str!(concat!(
            "../../../tests/fixtures/kubernetes/failures/",
            $name,
            ".exit"
        ))
        .trim()
        .parse()
        .unwrap();
        diagnose(seen(exit, $words), stderr, &DiagnoseContext::default()).code()
    }};
}

#[test]
fn an_unauthorized_resource_read_is_a_target_sign_in() {
    assert_eq!(
        fixture_code!("01-unauthorized-get-secret-list", &["get", "secret"]),
        "target_not_signed_in"
    );
}

#[test]
fn an_unauthorized_version_probe_is_a_target_sign_in() {
    assert_eq!(
        fixture_code!("01-unauthorized-version-probe", &["version"]),
        "target_not_signed_in"
    );
}

#[test]
fn an_unauthorized_can_i_is_a_target_sign_in() {
    assert_eq!(
        fixture_code!(
            "01-unauthorized-auth-can-i",
            &["auth", "can-i", "create", "secrets"]
        ),
        "target_not_signed_in"
    );
}

#[test]
fn a_forbidden_get_secret_names_the_missing_right() {
    assert_eq!(
        fixture_code!("02-forbidden-get-secret", &["get", "secret"]),
        "permission_denied"
    );
}

#[test]
fn a_forbidden_list_secrets_names_the_missing_right() {
    assert_eq!(
        fixture_code!("02-forbidden-list-secrets", &["get", "secret"]),
        "permission_denied"
    );
}

#[test]
fn a_forbidden_server_side_apply_names_the_patch_verb() {
    assert_eq!(
        fixture_code!(
            "02-forbidden-create-secret",
            &["apply", "--server-side", "-f", "-"]
        ),
        "permission_denied"
    );
}

#[test]
fn a_forbidden_client_side_create_names_the_create_verb() {
    assert_eq!(
        fixture_code!(
            "02-forbidden-create-secret-clientside",
            &["create", "-f", "-"]
        ),
        "permission_denied"
    );
}

#[test]
fn a_forbidden_patch_deployment_names_the_get_verb() {
    assert_eq!(
        fixture_code!(
            "02-forbidden-patch-deployment",
            &["patch", "deployment", "api"]
        ),
        "permission_denied"
    );
}

#[test]
fn a_forbidden_replace_deployment_names_the_update_verb() {
    assert_eq!(
        fixture_code!("02-forbidden-replace-deployment", &["replace", "-f", "-"]),
        "permission_denied"
    );
}

#[test]
fn a_forbidden_get_deployment_names_the_missing_right() {
    assert_eq!(
        fixture_code!("02-forbidden-get-deployment", &["get", "deployment", "api"]),
        "permission_denied"
    );
}

#[test]
fn a_can_i_no_is_a_missing_right_not_a_failure() {
    assert_eq!(
        fixture_code!(
            "02-can-i-create-secrets-no",
            &["auth", "can-i", "create", "secrets"]
        ),
        "permission_denied"
    );
}

#[test]
fn a_missing_secret_is_not_found() {
    assert_eq!(
        fixture_code!("03-notfound-secret", &["get", "secret", "opv-missing"]),
        "resource_not_found"
    );
}

#[test]
fn a_missing_deployment_is_not_found() {
    assert_eq!(
        fixture_code!(
            "03-notfound-deployment",
            &["get", "deployment", "opv-missing"]
        ),
        "resource_not_found"
    );
}

#[test]
fn a_missing_namespace_on_a_deployment_read_is_not_found() {
    assert_eq!(
        fixture_code!(
            "03-notfound-namespace-get-deployment",
            &["get", "deployment", "api"]
        ),
        "resource_not_found"
    );
}

#[test]
fn a_missing_namespace_on_a_secret_create_is_not_found() {
    assert_eq!(
        fixture_code!(
            "03-notfound-namespace-create-secret",
            &["apply", "--server-side", "-f", "-"]
        ),
        "resource_not_found"
    );
}

#[test]
fn a_missing_namespace_read_is_not_found() {
    assert_eq!(
        fixture_code!("03-notfound-namespace-get", &["get", "namespace"]),
        "resource_not_found"
    );
}

#[test]
fn a_context_missing_on_a_resource_call_is_not_found() {
    assert_eq!(
        fixture_code!(
            "04-context-missing-get-deployment",
            &["get", "deployment", "api"]
        ),
        "resource_not_found"
    );
}

#[test]
fn a_context_missing_on_the_probe_is_not_found() {
    assert_eq!(
        fixture_code!(
            "04-context-missing-probe",
            &["config", "get-contexts", "opv-nonexistent"]
        ),
        "resource_not_found"
    );
}

#[test]
fn an_unreachable_deployment_read_is_provider_unavailable() {
    assert_eq!(
        fixture_code!(
            "05-unreachable-get-deployment",
            &["get", "deployment", "api"]
        ),
        "provider_unavailable"
    );
}

#[test]
fn an_unreachable_version_probe_is_provider_unavailable() {
    assert_eq!(
        fixture_code!("05-unreachable-version-probe", &["version"]),
        "provider_unavailable"
    );
}

#[test]
fn an_unreachable_can_i_is_provider_unavailable_not_a_resource_warning() {
    assert_eq!(
        fixture_code!(
            "05-unreachable-auth-can-i",
            &["auth", "can-i", "create", "secrets"]
        ),
        "provider_unavailable"
    );
}

#[test]
fn a_missing_external_secrets_operator_on_a_list_is_owner_setup_required() {
    assert_eq!(
        fixture_code!(
            "06-eso-get-clustersecretstores",
            &["get", "clustersecretstores"]
        ),
        "owner_setup_required"
    );
}

#[test]
fn a_missing_external_secrets_operator_on_a_named_read_is_owner_setup_required() {
    assert_eq!(
        fixture_code!(
            "06-eso-get-clustersecretstore-named",
            &[
                "get",
                "clustersecretstores.external-secrets.io",
                "opv-store"
            ]
        ),
        "owner_setup_required"
    );
}

#[test]
fn an_empty_external_secrets_api_resources_reply_is_owner_setup_required() {
    assert_eq!(
        fixture_code!(
            "06-eso-api-resources",
            &["api-resources", "--api-group=external-secrets.io"]
        ),
        "owner_setup_required"
    );
}

#[test]
fn a_missing_external_secrets_raw_v1_is_owner_setup_required() {
    assert_eq!(
        fixture_code!(
            "06-eso-raw-v1",
            &["get", "--raw", "/apis/external-secrets.io/v1"]
        ),
        "owner_setup_required"
    );
}

#[test]
fn a_missing_external_secrets_raw_group_is_owner_setup_required() {
    assert_eq!(
        fixture_code!(
            "06-eso-raw-group",
            &["get", "--raw", "/apis/external-secrets.io"]
        ),
        "owner_setup_required"
    );
}

#[test]
fn a_successful_forbidden_identity_version_probe_is_unrecognised() {
    assert_eq!(
        fixture_code!("02-forbidden-version-probe", &["version"]),
        "unrecognized_failure"
    );
}

#[test]
fn a_successful_ignore_not_found_secret_read_is_unrecognised() {
    assert_eq!(
        fixture_code!(
            "03-notfound-secret-ignore",
            &["get", "secret", "opv-missing", "--ignore-not-found"]
        ),
        "unrecognized_failure"
    );
}

#[test]
fn a_successful_context_probe_is_unrecognised() {
    assert_eq!(
        fixture_code!(
            "04-context-present-probe",
            &["config", "get-contexts", "kind-opv-rec"]
        ),
        "unrecognized_failure"
    );
}

#[test]
fn a_successful_client_version_read_is_unrecognised() {
    assert_eq!(
        fixture_code!("07-version-client", &["version", "--client"]),
        "unrecognized_failure"
    );
}

#[test]
fn a_successful_server_version_read_is_unrecognised() {
    assert_eq!(
        fixture_code!("07-version-server", &["version"]),
        "unrecognized_failure"
    );
}

#[test]
fn an_unrecognised_stderr_is_unrecognized_for_kubernetes() {
    assert_eq!(
        diagnose(
            seen(1, &["get", "pods"]),
            "some inexplicable kubectl noise",
            &DiagnoseContext::default()
        )
        .code(),
        "unrecognized_failure"
    );
}

#[test]
fn a_timed_out_create_is_a_create_outcome_unknown() {
    let ctx = DiagnoseContext {
        create: Some((
            CreateKind::ItemWithSecrets,
            "opv-api".into(),
            Refind::ByTitle,
        )),
        ..DiagnoseContext::default()
    };
    assert_eq!(
        diagnose(
            seen_as(
                ExitClass::TimedOut,
                &["apply", "-f", "-"],
                Principal::Person { account: None }
            ),
            "",
            &ctx
        )
        .code(),
        "create_outcome_unknown"
    );
}

#[test]
fn a_timed_out_write_is_a_write_outcome_unknown() {
    let ctx = DiagnoseContext {
        write: true,
        ..DiagnoseContext::default()
    };
    assert_eq!(
        diagnose(
            seen_as(
                ExitClass::TimedOut,
                &["replace", "-f", "-"],
                Principal::Person { account: None }
            ),
            "",
            &ctx
        )
        .code(),
        "outcome_unknown"
    );
}

#[test]
fn a_timed_out_read_is_provider_unavailable() {
    assert_eq!(
        diagnose(
            seen_as(
                ExitClass::TimedOut,
                &["get", "deployment", "api"],
                Principal::Person { account: None }
            ),
            "",
            &DiagnoseContext::default()
        )
        .code(),
        "provider_unavailable"
    );
}

#[test]
fn a_rejected_shell_token_names_the_token() {
    assert_eq!(
        diagnose(
            seen_as(
                ExitClass::Code { code: 1 },
                &["get", "secret"],
                Principal::ShellToken {
                    var: VarName::new("KUBECONFIG_TOKEN")
                }
            ),
            "error: You must be logged in to the server (Unauthorized)",
            &DiagnoseContext::default()
        )
        .code(),
        "credential_rejected"
    );
}

#[test]
fn a_rejected_deploy_credential_names_the_credential() {
    assert_eq!(
        diagnose(
            seen_as(
                ExitClass::Code { code: 1 },
                &["get", "secret"],
                Principal::DeployCredentials {
                    vault: crate::cause::VaultId::new("vlt-deploy"),
                    item: ItemId::new("itm-deploy"),
                    env: EnvName::new("env-prod"),
                    target: TargetName::new("tgt-web"),
                }
            ),
            "error: You must be logged in to the server (Unauthorized)",
            &DiagnoseContext::default()
        )
        .code(),
        "deploy_credentials_failed"
    );
}
