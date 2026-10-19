//! Tests for [`super`] (design row `scan-manifests`): one test per manifest kind, through
//! the public [`Pattern`] interface over recorded fixtures, plus the value-boundary test.
//! Each test makes exactly one behavioural assertion.

use super::*;

/// The observed names for `text`, sorted, through the public [`Pattern::scan`].
fn names(pattern: &dyn Pattern, path: &str, text: &str) -> Vec<String> {
    let mut names: Vec<String> = pattern
        .scan(path, text)
        .into_iter()
        .filter_map(|o| o.name)
        .collect();
    names.sort();
    names
}

#[test]
fn dotenv_example_names_are_observed() {
    let observed = names(
        &DotEnv,
        ".env.example",
        include_str!("../../tests/fixtures/scan/manifests/.env.example"),
    );
    assert_eq!(
        observed,
        vec!["API_KEY", "DATABASE_URL", "EMPTY_NAME", "LOG_LEVEL"]
    );
}

#[test]
fn compose_environment_names_are_observed() {
    let observed = names(
        &Compose,
        "docker-compose.yml",
        include_str!("../../tests/fixtures/scan/manifests/docker-compose.yml"),
    );
    assert_eq!(
        observed,
        vec![
            "API_TOKEN",
            "DATABASE_URL",
            "EXTERNAL_TOKEN",
            "FEATURE_DEBUG",
            "LOG_LEVEL",
            "QUEUE_TOKEN",
            "REDIS_URL",
        ]
    );
}

#[test]
fn kubernetes_env_names_are_observed() {
    let observed = names(
        &K8sManifest,
        "kubernetes.yaml",
        include_str!("../../tests/fixtures/scan/manifests/kubernetes.yaml"),
    );
    assert_eq!(
        observed,
        vec![
            "CONFIG_KEY",
            "CONFIG_VALUE",
            "DATABASE_URL",
            "DB_PASSWORD",
            "LOG_LEVEL",
        ]
    );
}

#[test]
fn fly_env_names_are_observed() {
    let observed = names(
        &FlyToml,
        "fly.toml",
        include_str!("../../tests/fixtures/scan/manifests/fly.toml"),
    );
    assert_eq!(observed, vec!["API_TOKEN", "DATABASE_URL", "LOG_LEVEL"]);
}

#[test]
fn github_workflow_names_are_observed() {
    let observed = names(
        &GithubActions,
        ".github/workflows/deploy.yml",
        include_str!("../../tests/fixtures/scan/manifests/.github/workflows/deploy.yml"),
    );
    assert_eq!(
        observed,
        vec![
            "API_TOKEN",
            "BASE_URL",
            "BUILD_PROFILE",
            "CARGO_TERM_COLOR",
            "CI_API_TOKEN",
            "DEPLOY_TOKEN",
            "IMAGE_NAME",
            "REGISTRY",
            "SITE_URL",
        ]
    );
}

#[test]
fn dotenv_observation_debug_never_contains_the_right_hand_side() {
    let observations = DotEnv.scan(".env.example", "API_KEY=changeme\n");
    assert!(!format!("{:?}", observations[0]).contains("changeme"));
}
