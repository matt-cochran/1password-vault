//! FR-60 (one way only): no removed form of opv's own survives in production code. Each
//! identifier below belonged to a form 0.7.0 removed: the simple profile, the values item's
//! ledger section, the deprecated `fly_name` field, the single-target helper, the
//! environment-level item and `opv init`'s target options. A removed form is refused with
//! its replacement at load (src/config.rs) or on the command line (src/main.rs) and never
//! read; this test keeps the code paths from coming back.
use std::path::{Path, PathBuf};

/// Identifiers that only a removed form needed.
const REMOVED: &[&str] = &[
    "SIMPLE_PRODUCT",
    "SIMPLE_TEMPLATE",
    "Profile::Simple",
    "is_simple(",
    "fly_name",
    "sole_target",
    "STATE_SECTION",
    "from_layout",
    "record_ledger",
    "json_product",
    "RawSimpleConfig",
    "validate_simple",
    "TargetNameRequired",
    "TargetChoice",
    "choose_target",
];

/// Every `.rs` file under `dir`.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("readable source dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The production part of a source file: everything before its test module (a
/// `#[cfg(test)]` followed by `mod` or `#[path`), and nothing from a `*_tests.rs` file. A
/// `#[cfg(test)]` on a single helper item does not end the production part.
fn production(path: &Path, text: &str) -> String {
    if path.to_string_lossy().ends_with("_tests.rs") {
        return String::new();
    }
    let mut end = text.len();
    let mut from = 0;
    while let Some(i) = text[from..].find("#[cfg(test)]") {
        let at = from + i;
        let rest = text[at + "#[cfg(test)]".len()..].trim_start();
        if rest.starts_with("mod ") || rest.starts_with("#[path") {
            end = at;
            break;
        }
        from = at + 1;
    }
    text[..end].to_string()
}

#[test]
fn no_removed_form_survives_in_production_code() {
    let mut files = Vec::new();
    rust_files(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    let mut found = Vec::new();
    for path in files {
        let text = std::fs::read_to_string(&path).expect("readable source");
        let code = production(&path, &text);
        for (n, line) in code.lines().enumerate() {
            for name in REMOVED {
                if line.contains(name) {
                    found.push(format!("{}:{}: {name}", path.display(), n + 1));
                }
            }
        }
    }
    assert!(
        found.is_empty(),
        "removed forms in production code:\n{}",
        found.join("\n")
    );
}
