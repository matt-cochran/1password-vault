//! Design §5 "Sealing": `Observed::from_failed_call` is called in production code only by
//! the runner, for a call it actually made and that failed. Test modules are excluded: a
//! `*_tests.rs` file, a `tests.rs` file, and everything from a file's `#[cfg(test)]` on.

use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("src is readable") {
        let path = entry.expect("entry is readable").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn is_test_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    name == "tests.rs" || name.ends_with("_tests.rs")
}

/// The production part of `text`: up to its first `#[cfg(test)]`.
fn production(text: &str) -> &str {
    text.split("#[cfg(test)]").next().unwrap_or(text)
}

fn calls_from_failed_call(text: &str) -> bool {
    production(text).lines().any(|line| {
        let code = line.trim_start();
        !code.starts_with("//")
            && !code.contains("fn from_failed_call(")
            && code.contains("from_failed_call(")
    })
}

#[test]
fn only_the_runner_builds_an_observed() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    let mut callers: Vec<String> = files
        .iter()
        .filter(|p| !is_test_file(p))
        .filter(|p| calls_from_failed_call(&std::fs::read_to_string(p).expect("source is UTF-8")))
        .map(|p| {
            p.strip_prefix(root)
                .expect("under the crate")
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    callers.sort();
    assert_eq!(callers, vec!["src/runner.rs".to_string()]);
}
