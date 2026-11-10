//! Credential-free integration harness; never built into a release asset.
use opv::adapters::github::{Scope, gh};
use opv::domain::SecretValue;
use opv::runner::ProcessRunner;
use std::io::{self, Read};
fn main() {
    let mut payload = String::new();
    io::stdin()
        .take(48_000)
        .read_to_string(&mut payload)
        .expect("fixture input");
    let value = SecretValue::new(payload);
    let repos = vec!["example/app".to_string()];
    let result = gh::set_secrets(
        &ProcessRunner::default(),
        Scope {
            repos: &repos,
            environment: Some("fixture"),
        },
        &[("FIXTURE_APP_KEY".into(), &value)],
    );
    if let Err(error) = result {
        // A transport's raw stderr or supplied payload must never appear in this harness.
        eprintln!("fixture secret API write refused: {}", error.code_str());
        std::process::exit(1);
    }
}
