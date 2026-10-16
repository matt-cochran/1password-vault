//! The Legacy ratchet at zero (design `docs/design/error-catalog.md` §10, step 5): the
//! free-text `Error` category constructors and `Cause::Legacy` are gone, so every failure is
//! a cataloged cause. This test fails if any of them comes back, in production code or in a
//! test.

use std::path::Path;

/// The free-text constructors the catalog replaced. None may appear anywhere.
const LEGACY: [&str; 10] = [
    "Error::Config(",
    "Error::Source(",
    "Error::Target(",
    "Error::Dependency(",
    "Error::Auth(",
    "Error::Policy(",
    "Error::Unknown(",
    "Error::Findings(",
    "Error::findings(",
    "Cause::Legacy",
];

/// `file:line` of every legacy constructor under `dir`, comments included (a doc example
/// would be copied).
fn uses_in(dir: &Path, out: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).expect("a readable directory") {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            uses_in(&path, out);
            continue;
        }
        if path.extension().is_none_or(|e| e != "rs") || path.ends_with("legacy_ratchet.rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("a source file");
        for (n, line) in text.lines().enumerate() {
            if LEGACY.iter().any(|c| line.contains(c)) {
                out.push(format!("{}:{}", path.display(), n + 1));
            }
        }
    }
}

#[test]
fn no_legacy_error_constructor_exists() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut found = Vec::new();
    uses_in(&root.join("src"), &mut found);
    uses_in(&root.join("tests"), &mut found);
    assert!(
        found.is_empty(),
        "a free-text error is back (report it as a Cause in src/cause; design §10): {found:?}"
    );
}
