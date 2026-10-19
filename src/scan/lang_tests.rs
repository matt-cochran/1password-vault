//! Behaviour tests for [`super`] (design row `scan-lang`): each language pattern over its
//! recorded fixture. Each test makes exactly one behavioural assertion on the public
//! [`Observation`] outcome: the reads a language resolves, or the computed names it cannot.

use super::*;

/// A statically read observation at `file:line`.
fn observed(name: &str, file: &str, line: usize) -> Observation {
    Observation {
        name: Some(name.to_string()),
        file: file.to_string(),
        line,
        kind: Kind::Observed,
    }
}

/// A computed, unresolvable observation at `file:line`.
fn ambiguous(file: &str, line: usize) -> Observation {
    Observation {
        name: None,
        file: file.to_string(),
        line,
        kind: Kind::Ambiguous,
    }
}

// --- Rust ----------------------------------------------------------------------------------

#[test]
fn rust_static_env_reads_are_observed_with_file_and_line() {
    let file = "tests/fixtures/scan/rust/observed.rs.txt";
    let got = Rust.scan(
        file,
        include_str!("../../tests/fixtures/scan/rust/observed.rs.txt"),
    );
    assert_eq!(
        got,
        vec![
            observed("DATABASE_URL", file, 4),
            observed("CACHE_DIR", file, 5),
            observed("BUILD_ID", file, 6),
            observed("RELEASE_CHANNEL", file, 7),
            observed("DOTENV_TOKEN", file, 8),
        ]
    );
}

#[test]
fn rust_computed_env_names_are_ambiguous() {
    let file = "tests/fixtures/scan/rust/computed.rs.txt";
    let got = Rust.scan(
        file,
        include_str!("../../tests/fixtures/scan/rust/computed.rs.txt"),
    );
    assert_eq!(
        got,
        vec![ambiguous(file, 5), ambiguous(file, 6), ambiguous(file, 7),]
    );
}

// --- TypeScript/JavaScript -----------------------------------------------------------------

#[test]
fn typescript_static_env_reads_are_observed_with_file_and_line() {
    let file = "tests/fixtures/scan/typescript/observed.ts.txt";
    let got = TypeScript.scan(
        file,
        include_str!("../../tests/fixtures/scan/typescript/observed.ts.txt"),
    );
    assert_eq!(
        got,
        vec![
            observed("API_KEY", file, 1),
            observed("DB_URL", file, 2),
            observed("PUBLIC_URL", file, 3),
            observed("DENO_TOKEN", file, 4),
        ]
    );
}

#[test]
fn typescript_computed_env_names_are_ambiguous() {
    let file = "tests/fixtures/scan/typescript/computed.ts.txt";
    let got = TypeScript.scan(
        file,
        include_str!("../../tests/fixtures/scan/typescript/computed.ts.txt"),
    );
    assert_eq!(
        got,
        vec![
            ambiguous(file, 2),
            ambiguous(file, 3),
            ambiguous(file, 4),
            ambiguous(file, 5),
        ]
    );
}

// --- Python --------------------------------------------------------------------------------

#[test]
fn python_static_env_reads_are_observed_with_file_and_line() {
    let file = "tests/fixtures/scan/python/observed.py.txt";
    let got = Python.scan(
        file,
        include_str!("../../tests/fixtures/scan/python/observed.py.txt"),
    );
    assert_eq!(
        got,
        vec![
            observed("DATABASE_URL", file, 3),
            observed("CACHE_DIR", file, 4),
            observed("API_KEY", file, 5),
            observed("DEBUG", file, 6),
        ]
    );
}

#[test]
fn python_computed_env_names_are_ambiguous() {
    let file = "tests/fixtures/scan/python/computed.py.txt";
    let got = Python.scan(
        file,
        include_str!("../../tests/fixtures/scan/python/computed.py.txt"),
    );
    assert_eq!(
        got,
        vec![
            ambiguous(file, 4),
            ambiguous(file, 5),
            ambiguous(file, 6),
            ambiguous(file, 7),
        ]
    );
}

// --- Go ------------------------------------------------------------------------------------

#[test]
fn go_static_env_reads_are_observed_with_file_and_line() {
    let file = "tests/fixtures/scan/go/observed.go.txt";
    let got = Go.scan(
        file,
        include_str!("../../tests/fixtures/scan/go/observed.go.txt"),
    );
    assert_eq!(
        got,
        vec![
            observed("API_KEY", file, 6),
            observed("DATABASE_URL", file, 7),
        ]
    );
}

#[test]
fn go_computed_env_names_are_ambiguous() {
    let file = "tests/fixtures/scan/go/computed.go.txt";
    let got = Go.scan(
        file,
        include_str!("../../tests/fixtures/scan/go/computed.go.txt"),
    );
    assert_eq!(got, vec![ambiguous(file, 7), ambiguous(file, 8)]);
}
