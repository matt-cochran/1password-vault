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

// --- Ruby ----------------------------------------------------------------------------------

/// Ruby reads: `ENV['X']`, `ENV["X"]` and `ENV.fetch('X'[, default])`, one per line.
const RUBY_OBSERVED: &str = concat!(
    "# frozen_string_literal: true\n",
    "\n",
    "database_url = ENV[\"DATABASE_URL\"]\n",
    "cache_dir = ENV['CACHE_DIR']\n",
    "api_key = ENV.fetch(\"API_KEY\")\n",
    "debug = ENV.fetch('DEBUG', \"false\")\n",
);

/// Ruby computed names: a variable or call where a literal name would be.
const RUBY_COMPUTED: &str = concat!(
    "# frozen_string_literal: true\n",
    "\n",
    "key = \"DATABASE_URL\"\n",
    "a = ENV[key]\n",
    "b = ENV.fetch(name)\n",
    "c = ENV.fetch(build_name, \"default\")\n",
);

#[test]
fn ruby_static_env_reads_are_observed_with_file_and_line() {
    let file = "app.rb";
    let got = Ruby.scan(file, RUBY_OBSERVED);
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
fn ruby_computed_env_names_are_ambiguous() {
    let file = "app.rb";
    let got = Ruby.scan(file, RUBY_COMPUTED);
    assert_eq!(
        got,
        vec![ambiguous(file, 4), ambiguous(file, 5), ambiguous(file, 6)]
    );
}

// --- C/C++ ---------------------------------------------------------------------------------

/// C reads: `getenv("X")` and `secure_getenv("X")`, one per line.
const C_OBSERVED: &str = concat!(
    "#include <stdlib.h>\n",
    "\n",
    "int main(void) {\n",
    "    const char *a = getenv(\"DATABASE_URL\");\n",
    "    const char *b = secure_getenv(\"CACHE_DIR\");\n",
    "    return a == 0 || b == 0;\n",
    "}\n",
);

/// C computed names: a variable or call where a literal name would be.
const C_COMPUTED: &str = concat!(
    "#include <stdlib.h>\n",
    "\n",
    "int main(void) {\n",
    "    const char *key = \"DATABASE_URL\";\n",
    "    const char *a = getenv(key);\n",
    "    const char *b = getenv(build_name());\n",
    "    return a == 0 || b == 0;\n",
    "}\n",
);

/// C++ reads: the qualified `std::getenv` and `secure_getenv`.
const CPP_OBSERVED: &str = concat!(
    "#include <cstdlib>\n",
    "\n",
    "int main() {\n",
    "    const char *a = std::getenv(\"DATABASE_URL\");\n",
    "    const char *b = secure_getenv(\"CACHE_DIR\");\n",
    "    return a == nullptr || b == nullptr;\n",
    "}\n",
);

#[test]
fn c_static_getenv_reads_are_observed_with_file_and_line() {
    let file = "app.c";
    let got = C.scan(file, C_OBSERVED);
    assert_eq!(
        got,
        vec![
            observed("DATABASE_URL", file, 4),
            observed("CACHE_DIR", file, 5)
        ]
    );
}

#[test]
fn c_computed_getenv_names_are_ambiguous() {
    let file = "app.c";
    let got = C.scan(file, C_COMPUTED);
    assert_eq!(got, vec![ambiguous(file, 5), ambiguous(file, 6)]);
}

#[test]
fn cpp_static_getenv_reads_are_observed_with_file_and_line() {
    let file = "app.cpp";
    let got = C.scan(file, CPP_OBSERVED);
    assert_eq!(
        got,
        vec![
            observed("DATABASE_URL", file, 4),
            observed("CACHE_DIR", file, 5)
        ]
    );
}

// --- secrets directory ---------------------------------------------------------------------

/// A Rust app reading the file a `local.secrets_dir_env` key is delivered as (#136): the
/// directory variable is `APP_SECRETS_DIR` and the key `MIGRATE_PEM` is the file
/// `db/migrate-pem`, never a variable.
const SECRETS_DIR_RUST: &str = concat!(
    "use std::path::Path;\n",
    "\n",
    "fn pem() -> std::io::Result<String> {\n",
    "    let dir = std::env::var(\"APP_SECRETS_DIR\").expect(\"APP_SECRETS_DIR\");\n",
    "    std::fs::read_to_string(Path::new(&dir).join(\"db/migrate-pem\"))\n",
    "}\n",
);

#[test]
fn the_needs_scanner_reports_a_file_under_the_secrets_directory_with_its_key_name() {
    let file = "src/db.rs";
    let pattern = SecretsDir::new("APP_SECRETS_DIR", [("db/migrate-pem", "MIGRATE_PEM")]);
    assert_eq!(
        pattern.scan(file, SECRETS_DIR_RUST),
        vec![observed("MIGRATE_PEM", file, 5)]
    );
}

#[test]
fn the_needs_scanner_ignores_a_read_that_is_not_a_declared_file() {
    let file = "src/db.rs";
    let pattern = SecretsDir::new("APP_SECRETS_DIR", [("db/other", "OTHER_KEY")]);
    assert_eq!(pattern.scan(file, SECRETS_DIR_RUST), Vec::new());
}

// --- coverage ------------------------------------------------------------------------------

/// A fixed in-test tree: the files and text a scan reads, with no git and no disk.
struct FixedTree(&'static [(&'static str, &'static str)]);

impl crate::scan::Tree for FixedTree {
    fn files(
        &self,
        _runner: &dyn crate::runner::CommandRunner,
        _repo: &std::path::Path,
    ) -> Vec<String> {
        self.0.iter().map(|(path, _)| (*path).to_string()).collect()
    }

    fn read(
        &self,
        _runner: &dyn crate::runner::CommandRunner,
        _repo: &std::path::Path,
        path: &str,
    ) -> Option<String> {
        self.0
            .iter()
            .find(|(candidate, _)| *candidate == path)
            .map(|(_, text)| (*text).to_string())
    }
}

#[test]
fn coverage_names_ruby_and_c_when_both_are_scanned() {
    let tree = FixedTree(&[
        ("app.rb", "x = ENV[\"DATABASE_URL\"]\n"),
        ("app.c", "char *x = getenv(\"CACHE_DIR\");\n"),
    ]);
    let runner = crate::runner::ProcessRunner::default();
    let patterns: Vec<&dyn Pattern> = vec![&Ruby, &C];
    let scan = crate::scan::Scan::collect(&runner, std::path::Path::new("."), &tree, &patterns);
    assert_eq!(
        scan.coverage.languages,
        vec!["c".to_string(), "ruby".to_string()]
    );
}
