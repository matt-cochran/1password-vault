use super::*;
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
