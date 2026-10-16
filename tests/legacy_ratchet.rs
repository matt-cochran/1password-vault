//! The Legacy ratchet (design `docs/design/error-catalog.md` §10, phase 1): the free-text
//! `Error` category constructors may only be used less over time. Promotion from `dev` to
//! `staging` is gated on this count reaching zero.

use std::path::Path;

/// Legacy constructions in production code when the Catalog arm landed. Lower it when a
/// change converts call sites to causes; never raise it.
const LEGACY_CEILING: usize = 495;

const CONSTRUCTORS: [&str; 8] = [
    "Error::Config(",
    "Error::Source(",
    "Error::Target(",
    "Error::Dependency(",
    "Error::Auth(",
    "Error::Policy(",
    "Error::Unknown(",
    "Error::Findings(",
];

/// Constructions in one file's production code: everything before its first `#[cfg(test)]`
/// line, skipping comments and match patterns that bind nothing (`(_)`, `(..)`).
fn count_in(text: &str) -> usize {
    text.lines()
        .take_while(|l| l.trim_start() != "#[cfg(test)]")
        .filter(|l| !l.trim_start().starts_with("//"))
        .map(|l| {
            CONSTRUCTORS
                .iter()
                .map(|c| {
                    l.match_indices(c)
                        .filter(|(i, _)| {
                            let rest = &l[i + c.len()..];
                            !(rest.starts_with('_') || rest.starts_with(".."))
                        })
                        .count()
                })
                .sum::<usize>()
        })
        .sum()
}

fn count_dir(dir: &Path) -> usize {
    let mut n = 0;
    for entry in std::fs::read_dir(dir).expect("src/ is readable") {
        let path = entry.expect("a directory entry").path();
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if path.is_dir() {
            n += count_dir(&path);
        } else if name.ends_with(".rs") && !name.ends_with("_tests.rs") {
            n += count_in(&std::fs::read_to_string(&path).expect("a source file"));
        }
    }
    n
}

#[test]
fn legacy_error_constructions_only_go_down() {
    let n = count_dir(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"));
    assert!(
        n <= LEGACY_CEILING,
        "{n} Legacy Error constructions in src/ (ceiling {LEGACY_CEILING}): the count may only go \
         down. Report the failure as a Cause (src/cause) instead; see \
         docs/design/error-catalog.md §10."
    );
}
