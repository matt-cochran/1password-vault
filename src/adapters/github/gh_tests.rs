use super::*;
use crate::cause::Cause;
use crate::runner::Output;
use crate::runner::fake::FakeRunner;

const MARKER: &str = "MARKER_GH_SECRET_VALUE_7c1f";
const REPOS: &[&str] = &["example-org/example-repo"];

fn repos() -> Vec<String> {
    REPOS.iter().map(|r| r.to_string()).collect()
}

fn scope(repos: &[String]) -> Scope<'_> {
    Scope {
        repos,
        environment: None,
    }
}

#[test]
fn secret_values_never_reach_argv() {
    let r = FakeRunner::new([Output::success("")]);
    let v = SecretValue::new(MARKER.into());
    let repos = repos();
    set_secrets(&r, scope(&repos), &[("API_TOKEN".into(), &v)]).unwrap();
    assert!(!r.argv_contains(MARKER));
}

#[test]
fn variable_values_never_reach_argv() {
    let r = FakeRunner::new([Output::success("")]);
    let repos = repos();
    set_variables(&r, scope(&repos), &[("APP_NAME".into(), MARKER)]).unwrap();
    assert!(!r.argv_contains(MARKER));
}

// ---------------------------------------------------------------- recorded fixtures

const SECRET_LIST: &str = include_str!("../../../tests/fixtures/github/secret-list.json");
const SECRET_LIST_EMPTY: &str =
    include_str!("../../../tests/fixtures/github/secret-list-empty.json");
const SECRET_LIST_ENV: &str = include_str!("../../../tests/fixtures/github/secret-list-env.json");

fn two_repos() -> Vec<String> {
    vec![
        "example-org/repo-a".to_string(),
        "example-org/repo-b".to_string(),
    ]
}

// ------------------------------------------------------------------------- list_secrets

#[test]
fn list_secrets_reads_the_recorded_secret() {
    let r = FakeRunner::new([Output::success(SECRET_LIST)]);
    let repos = repos();
    assert_eq!(
        list_secrets(&r, scope(&repos)).unwrap(),
        vec![StoreEntry {
            name: "OPV_SPIKE_TOKEN".to_string(),
            version: Some("2026-10-13T06:03:09Z".to_string()),
            pending: false,
            stamp: None,
        }]
    );
}

#[test]
fn list_secrets_of_an_empty_store_is_empty() {
    let r = FakeRunner::new([Output::success(SECRET_LIST_EMPTY)]);
    let repos = repos();
    assert!(list_secrets(&r, scope(&repos)).unwrap().is_empty());
}

#[test]
fn list_secrets_keeps_a_name_that_every_repo_has() {
    let r = FakeRunner::new([Output::success(SECRET_LIST), Output::success(SECRET_LIST)]);
    let repos = two_repos();
    assert_eq!(
        list_secrets(&r, scope(&repos))
            .unwrap()
            .iter()
            .map(|e| e.name.as_str())
            .collect::<Vec<_>>(),
        ["OPV_SPIKE_TOKEN"]
    );
}

#[test]
fn list_secrets_drops_a_name_that_another_repo_lacks() {
    let r = FakeRunner::new([
        Output::success(SECRET_LIST),
        Output::success(SECRET_LIST_ENV),
    ]);
    let repos = two_repos();
    assert!(list_secrets(&r, scope(&repos)).unwrap().is_empty());
}

#[test]
fn list_secrets_passes_the_exact_read_argv() {
    let r = FakeRunner::new([Output::success(SECRET_LIST)]);
    let repos = repos();
    list_secrets(&r, scope(&repos)).unwrap();
    let args = r.calls.borrow()[0].args.clone();
    assert_eq!(
        args,
        [
            "secret",
            "list",
            "-R",
            "example-org/example-repo",
            "--json",
            "name,updatedAt"
        ]
    );
}

const VARIABLE_LIST: &str = include_str!("../../../tests/fixtures/github/variable-list.json");
const VARIABLE_LIST_ENV: &str =
    include_str!("../../../tests/fixtures/github/variable-list-env.json");

fn scope_env<'a>(repos: &'a [String], environment: &'a str) -> Scope<'a> {
    Scope {
        repos,
        environment: Some(environment),
    }
}

#[test]
fn list_secrets_puts_the_environment_flag_right_after_the_repo() {
    let r = FakeRunner::new([Output::success(SECRET_LIST_ENV)]);
    let repos = repos();
    list_secrets(&r, scope_env(&repos, "staging")).unwrap();
    let args = r.calls.borrow()[0].args.clone();
    assert_eq!(
        args,
        [
            "secret",
            "list",
            "-R",
            "example-org/example-repo",
            "-e",
            "staging",
            "--json",
            "name,updatedAt"
        ]
    );
}

// ---------------------------------------------------------------------- list_variables

#[test]
fn list_variables_reads_the_recorded_variable() {
    let r = FakeRunner::new([Output::success(VARIABLE_LIST)]);
    let repos = repos();
    let got = list_variables(&r, scope(&repos)).unwrap();
    assert_eq!(
        got.get("OPV_SPIKE_APP").map(String::as_str),
        Some("marker-config-2")
    );
}

#[test]
fn list_variables_keeps_only_names_shared_by_every_repo() {
    let r = FakeRunner::new([
        Output::success(VARIABLE_LIST),
        Output::success(VARIABLE_LIST_ENV),
    ]);
    let repos = two_repos();
    assert!(list_variables(&r, scope(&repos)).unwrap().is_empty());
}

// ------------------------------------------------------------------------- set_secrets

#[test]
fn set_secrets_writes_each_name_to_each_repo_in_order() {
    let r = FakeRunner::new((0..4).map(|_| Output::success("")));
    let repos = two_repos();
    let va = SecretValue::new("a-value".into());
    let vb = SecretValue::new("b-value".into());
    let batch = vec![("B".to_string(), &vb), ("A".to_string(), &va)];
    set_secrets(&r, scope(&repos), &batch).unwrap();
    let got: Vec<Vec<String>> = r.calls.borrow().iter().map(|c| c.args.clone()).collect();
    assert_eq!(
        got,
        vec![
            vec!["secret", "set", "A", "-R", "example-org/repo-a"],
            vec!["secret", "set", "A", "-R", "example-org/repo-b"],
            vec!["secret", "set", "B", "-R", "example-org/repo-a"],
            vec!["secret", "set", "B", "-R", "example-org/repo-b"],
        ]
    );
}

#[test]
fn set_secrets_sends_the_value_as_stdin() {
    let r = FakeRunner::new([Output::success("")]);
    let repos = repos();
    let v = SecretValue::new("s3cret-value".into());
    set_secrets(&r, scope(&repos), &[("API_TOKEN".into(), &v)]).unwrap();
    assert_eq!(
        r.calls.borrow()[0].stdin.as_deref(),
        Some(b"s3cret-value".as_slice())
    );
}

#[test]
fn set_secrets_with_an_empty_batch_makes_no_call() {
    let r = FakeRunner::default();
    let repos = repos();
    set_secrets(&r, scope(&repos), &[]).unwrap();
    assert!(r.calls.borrow().is_empty());
}

// ----------------------------------------------------------------------- set_variables

#[test]
fn set_variables_writes_each_name_to_each_repo_in_order() {
    let r = FakeRunner::new((0..4).map(|_| Output::success("")));
    let repos = two_repos();
    let batch = vec![("B".to_string(), "b-value"), ("A".to_string(), "a-value")];
    set_variables(&r, scope(&repos), &batch).unwrap();
    let got: Vec<Vec<String>> = r.calls.borrow().iter().map(|c| c.args.clone()).collect();
    assert_eq!(
        got,
        vec![
            vec!["variable", "set", "A", "-R", "example-org/repo-a"],
            vec!["variable", "set", "A", "-R", "example-org/repo-b"],
            vec!["variable", "set", "B", "-R", "example-org/repo-a"],
            vec!["variable", "set", "B", "-R", "example-org/repo-b"],
        ]
    );
}

#[test]
fn set_variables_sends_the_value_as_stdin() {
    let r = FakeRunner::new([Output::success("")]);
    let repos = repos();
    set_variables(&r, scope(&repos), &[("APP_NAME".into(), "config-value")]).unwrap();
    assert_eq!(
        r.calls.borrow()[0].stdin.as_deref(),
        Some(b"config-value".as_slice())
    );
}

#[test]
fn set_variables_with_an_empty_batch_makes_no_call() {
    let r = FakeRunner::default();
    let repos = repos();
    set_variables(&r, scope(&repos), &[]).unwrap();
    assert!(r.calls.borrow().is_empty());
}

/// The whole terminal report of `e`, as a person reads it.
fn rendered(e: &Error) -> String {
    crate::error::report(e, "opv sync prod", None)
}

#[test]
fn set_secrets_failure_names_what_was_already_written() {
    let r = FakeRunner::new([Output::success(""), Output::failure(1), Output::success("")]);
    let repos = two_repos();
    let v = SecretValue::new("second-repo-value".into());
    let err = set_secrets(&r, scope(&repos), &[("API_TOKEN".into(), &v)]).unwrap_err();
    assert!(
        matches!(err.cause(), Some((Cause::Partial { done, .. }, _)) if done.iter().any(|d| d.contains("API_TOKEN"))),
        "{err:?}"
    );
}

const STDERR_BAD_TOKEN: &str = include_str!("../../../tests/fixtures/github/stderr-bad_token.txt");
const STDERR_ENV_MISSING_SET: &str =
    include_str!("../../../tests/fixtures/github/stderr-env_missing_set.txt");

#[test]
fn set_secrets_failure_never_contains_the_value() {
    let r = FakeRunner::new([Output::success(""), Output::failure(1), Output::success("")]);
    let repos = two_repos();
    let v = SecretValue::new("SECOND_REPO_VALUE_9f3a".into());
    let err = set_secrets(&r, scope(&repos), &[("API_TOKEN".into(), &v)]).unwrap_err();
    assert!(!rendered(&err).contains("SECOND_REPO_VALUE_9f3a"));
}

#[test]
fn set_variables_failure_names_what_was_already_written() {
    let r = FakeRunner::new([Output::success(""), Output::failure(1), Output::success("")]);
    let repos = two_repos();
    let err = set_variables(&r, scope(&repos), &[("APP_NAME".into(), "config-value")]).unwrap_err();
    assert!(
        matches!(err.cause(), Some((Cause::Partial { done, .. }, _)) if done.iter().any(|d| d.contains("APP_NAME"))),
        "{err:?}"
    );
}

/// `gh secret set` refused with the spike's rejected-token reply, under deploy credentials.
fn set_with_rejected_deploy_token(environment: Option<&str>) -> Error {
    let r = FakeRunner::default();
    r.push_with_stderr(Output::failure(1), STDERR_BAD_TOKEN);
    let repos = repos();
    let v = SecretValue::new("token-value".into());
    let principal = crate::cause::Principal::DeployCredentials {
        vault: crate::cause::VaultId::new("vlt-deploy"),
        item: crate::cause::ItemId::new("gh-deploy"),
        env: crate::cause::EnvName::new("prod"),
        target: crate::cause::TargetName::new("ci"),
    };
    crate::runner::under_deploy(principal, || {
        set_secrets(
            &r,
            Scope {
                repos: &repos,
                environment,
            },
            &[("API_TOKEN".into(), &v)],
        )
    })
    .unwrap_err()
}

#[test]
fn a_rejected_deploy_token_is_deploy_credentials_failed() {
    assert_eq!(
        set_with_rejected_deploy_token(None).code_str(),
        "deploy_credentials_failed"
    );
}

#[test]
fn a_rejected_deploy_token_never_offers_gh_auth_login() {
    assert!(!rendered(&set_with_rejected_deploy_token(None)).contains("gh auth login"));
}

#[test]
fn a_rejected_token_for_a_github_environment_needs_the_environments_permission() {
    assert!(
        rendered(&set_with_rejected_deploy_token(Some("staging")))
            .contains("Environments read and write"),
        "{}",
        rendered(&set_with_rejected_deploy_token(Some("staging")))
    );
}

#[test]
fn a_rejected_token_for_repository_values_needs_no_environments_permission() {
    assert!(!rendered(&set_with_rejected_deploy_token(None)).contains("Environments"));
}

#[test]
fn set_secrets_with_an_unrecorded_reply_is_unrecognized() {
    let r = FakeRunner::default();
    r.push_with_stderr(Output::failure(1), STDERR_ENV_MISSING_SET);
    let repos = repos();
    let v = SecretValue::new("token-value".into());
    let err = set_secrets(&r, scope(&repos), &[("API_TOKEN".into(), &v)]).unwrap_err();
    assert_eq!(err.code_str(), "unrecognized_failure");
}

#[test]
fn set_secrets_with_an_unrecorded_reply_shows_ghs_reply() {
    let r = FakeRunner::default();
    r.push_with_stderr(Output::failure(1), STDERR_ENV_MISSING_SET);
    let repos = repos();
    let v = SecretValue::new("token-value".into());
    let err = set_secrets(&r, scope(&repos), &[("API_TOKEN".into(), &v)]).unwrap_err();
    assert!(rendered(&err).contains("HTTP 404"), "{}", rendered(&err));
}

#[test]
fn set_secrets_with_an_unknown_outcome_is_outcome_unknown() {
    let r = FakeRunner::default();
    r.push_unknown("timeout");
    let repos = repos();
    let v = SecretValue::new("token-value".into());
    let err = set_secrets(&r, scope(&repos), &[("API_TOKEN".into(), &v)]).unwrap_err();
    assert_eq!(err.code_str(), "outcome_unknown");
}

#[test]
fn a_missing_gh_is_dependency_missing() {
    let r = FakeRunner::default();
    r.push_io_error(std::io::ErrorKind::NotFound);
    let repos = repos();
    assert_eq!(
        list_secrets(&r, scope(&repos)).unwrap_err().code_str(),
        "dependency_missing"
    );
}

// ---------------------------------------------------------------------------- deletes

const STDERR_DEL_MISSING: &str =
    include_str!("../../../tests/fixtures/github/stderr-del_missing.txt");

#[test]
fn delete_secrets_treats_a_missing_secret_as_gone() {
    let r = FakeRunner::default();
    r.push_with_stderr(Output::failure(1), STDERR_DEL_MISSING);
    let repos = repos();
    let res = delete_secrets(&r, scope(&repos), &["OPV_NOPE".to_string()]);
    assert!(res.is_ok());
}

#[test]
fn delete_variables_treats_a_missing_variable_as_gone() {
    let r = FakeRunner::default();
    r.push_with_stderr(Output::failure(1), STDERR_DEL_MISSING);
    let repos = repos();
    let res = delete_variables(&r, scope(&repos), &["OPV_NOPE".to_string()]);
    assert!(res.is_ok());
}

// -------------------------------------------------------------------------- refusals

#[test]
fn secret_refusal_rejects_a_bad_name() {
    let v = SecretValue::new("value".into());
    assert_eq!(
        secret_refusal("BAD-NAME", &v).map(|(rule, _)| rule),
        Some(NAME_RULE)
    );
}

#[test]
fn secret_refusal_rejects_the_github_prefix() {
    let v = SecretValue::new("value".into());
    assert_eq!(
        secret_refusal("GITHUB_FOO", &v).map(|(rule, _)| rule),
        Some(NAME_RULE)
    );
}

#[test]
fn secret_refusal_rejects_a_secret_over_the_limit() {
    let v = SecretValue::new("x".repeat(47_953));
    assert_eq!(
        secret_refusal("OPV_BIG", &v).map(|(rule, _)| rule),
        Some(SECRET_TOO_LARGE_RULE)
    );
}

#[test]
fn secret_refusal_accepts_a_secret_at_the_limit() {
    let v = SecretValue::new("x".repeat(47_952));
    assert!(secret_refusal("OPV_BIG", &v).is_none());
}

#[test]
fn variable_refusal_rejects_an_empty_value() {
    assert_eq!(
        variable_refusal("OPV_EMPTYVAR", "").map(|(rule, _)| rule),
        Some(VARIABLE_EMPTY_RULE)
    );
}

#[test]
fn variable_refusal_rejects_a_variable_over_the_limit() {
    let value = "x".repeat(48_001);
    assert_eq!(
        variable_refusal("OPV_BIGV", &value).map(|(rule, _)| rule),
        Some(VARIABLE_TOO_LARGE_RULE)
    );
}

#[test]
fn variable_refusal_accepts_a_variable_at_the_limit() {
    let value = "x".repeat(48_000);
    assert!(variable_refusal("OPV_BIGV", &value).is_none());
}

// --------------------------------------------------------------------- validate_secrets

#[test]
fn validate_secrets_rejects_a_bad_name() {
    let v = SecretValue::new("value".into());
    let batch = vec![("BAD-NAME".to_string(), &v)];
    assert!(validate_secrets(&batch).unwrap_err().code_str() == "internal_error");
}

#[test]
fn validate_secrets_rejects_the_github_prefix() {
    let v = SecretValue::new("value".into());
    let batch = vec![("GITHUB_FOO".to_string(), &v)];
    assert!(validate_secrets(&batch).unwrap_err().code_str() == "internal_error");
}

#[test]
fn validate_secrets_error_never_contains_the_value() {
    let v = SecretValue::new(format!("{MARKER}{}", "x".repeat(47_953)));
    let batch = vec![("OPV_BIG".to_string(), &v)];
    let err = validate_secrets(&batch).unwrap_err();
    assert!(!err.to_string().contains(MARKER));
}

// ------------------------------------------------------------------------- environments

const ENVIRONMENTS: &str = include_str!("../../../tests/fixtures/github/environments.json");

#[test]
fn environments_reads_the_recorded_names() {
    let r = FakeRunner::new([Output::success(ENVIRONMENTS)]);
    assert_eq!(
        environments(&r, "example-org/example-repo").unwrap(),
        ["staging"]
    );
}

// -------------------------------------------------------------------------- auth_status

#[test]
fn auth_status_is_true_for_exit_zero() {
    let r = FakeRunner::new([Output::success("")]);
    assert!(auth_status(&r).unwrap());
}

#[test]
fn auth_status_is_false_for_exit_one() {
    let r = FakeRunner::new([Output::failure(1)]);
    assert!(!auth_status(&r).unwrap());
}

// A GitHub environment missing from the repository (found in the live smoke) -------------

const ENV_404: &str = include_str!("../../../tests/fixtures/github/stderr-env_missing_list.txt");

/// The listing fails with gh's bare 404; the environments read shows only `staging`.
fn listing_in_missing_environment() -> Result<Vec<StoreEntry>, Error> {
    let r = FakeRunner::default();
    r.push_with_stderr(Output::failure(1), ENV_404);
    r.responses
        .borrow_mut()
        .push_back(Ok(Output::success(ENVIRONMENTS)));
    let repos = repos();
    list_secrets(
        &r,
        Scope {
            repos: &repos,
            environment: Some("nope"),
        },
    )
}

#[test]
fn listing_in_a_missing_environment_is_owner_setup_required() {
    let e = listing_in_missing_environment().unwrap_err();
    assert_eq!(e.code_str(), "owner_setup_required");
}

#[test]
fn listing_in_a_missing_environment_names_it() {
    let e = listing_in_missing_environment().unwrap_err();
    assert!(
        rendered(&e).contains("GitHub environment nope in example-org/example-repo"),
        "{}",
        rendered(&e)
    );
}

#[test]
fn listing_in_a_missing_environment_leaves_the_setup_to_a_person() {
    let e = listing_in_missing_environment().unwrap_err();
    assert!(e.human_required());
}
