//! Scanner core (design Part V, row `scan-core`): the walker, the name grammar, the
//! built-in ignore list, the coverage, and the [`Pattern`] trait the language and manifest
//! rows implement.
//!
//! A scan reads source text and returns names only. It never reads a value: patterns see
//! the text of a file, never the environment, and an observation carries a name, a
//! `file:line` and a kind, never a value, a length or a digest. A candidate that does not
//! match the name grammar (or is a built-in runtime name) is dropped and counted, so a
//! value a pattern mistakes for a name cannot reach a document.

use std::collections::BTreeSet;
use std::path::Path;

use crate::runner::{Call, CommandRunner, PROBE_TIMEOUT};

/// The largest file the scanner reads. A bigger file is skipped (binary assets, lock files,
/// generated bundles).
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// Vendored and build directories the walker always skips, even when they are tracked or not
/// gitignored.
pub const SKIP_DIRS: &[&str] = &[
    "node_modules",
    "vendor",
    "target",
    "dist",
    "build",
    ".venv",
    "__pycache__",
    ".git",
];

/// The built-in runtime names a scan drops: they are set by the OS, the shell, the
/// toolchain or the platform, never by the application's contract. One const list.
pub const RUNTIME_NAMES: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "PWD",
    "OLDPWD",
    "TERM",
    "COLORTERM",
    "NO_COLOR",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "TMPDIR",
    "TEMP",
    "TMP",
    "NODE_ENV",
    "CI",
    "PORT",
    "HOSTNAME",
    "RUST_LOG",
    "RUST_BACKTRACE",
    "RUSTUP_HOME",
    "CARGO_HOME",
    "PYTHONPATH",
    "PYTHONHOME",
    "VIRTUAL_ENV",
    "GOPATH",
    "GOROOT",
    "GOFLAGS",
    "EDITOR",
    "VISUAL",
    "PAGER",
];

/// Whether `name` matches the scanner's name grammar `^[A-Z][A-Z0-9_]*$`.
pub fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_uppercase())
        && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Whether `name` is one of the built-in runtime names ([`RUNTIME_NAMES`]).
pub fn runtime_name(name: &str) -> bool {
    RUNTIME_NAMES.contains(&name)
}

/// What an [`Observation`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A statically read name: `name` is `Some`.
    Observed,
    /// A computed or dynamic name the scanner cannot resolve: `name` is `None`.
    Ambiguous,
}

/// One place the scanner saw a name, or saw that it could not resolve one. Carries a
/// `file`, a `line` and a [`Kind`], never a value.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Observation {
    /// The observed name, or `None` for an [`Kind::Ambiguous`] observation.
    pub name: Option<String>,
    /// The path of the file, relative to the scanned root.
    pub file: String,
    /// The 1-based line number.
    pub line: usize,
    /// Whether the name was read statically or is computed.
    pub kind: Kind,
}

/// What the scan covered: how many files and languages it read, and how many candidate
/// patterns it dropped (invalid names and runtime names). A count, never a dropped name:
/// a value mistaken for a name is dropped, not reported.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Coverage {
    /// The files read by at least one pattern.
    pub files: usize,
    /// The languages of the patterns that read at least one file, sorted.
    pub languages: Vec<String>,
    /// The candidate names dropped by the grammar or the runtime list.
    pub skipped_patterns: usize,
}

/// The result of a scan: the observations and the coverage.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Scan {
    /// Every name the patterns observed or could not resolve, in walk order.
    pub observations: Vec<Observation>,
    /// What the scan read and what it dropped.
    pub coverage: Coverage,
}

/// A language or manifest scanner. The core owns the walker, the grammar and the ignore
/// list; a pattern owns only how one file's text is read. A pattern returns
/// [`Observation`]s and never a value.
pub trait Pattern {
    /// The language or manifest kind this pattern reads, e.g. `rust`, `dotenv`.
    fn language(&self) -> &'static str;
    /// Whether this pattern reads `path`.
    fn applies(&self, path: &str) -> bool;
    /// The observations in `text` at `path`.
    fn scan(&self, path: &str, text: &str) -> Vec<Observation>;
}

/// Where a scan's files and their text come from: the working tree or a committed revision.
pub trait Tree {
    /// The candidate paths, relative to the repository root.
    fn files(&self, runner: &dyn CommandRunner, repo: &Path) -> Vec<String>;
    /// The text of `path`, or `None` when it is missing, binary or over [`MAX_FILE_BYTES`].
    fn read(&self, runner: &dyn CommandRunner, repo: &Path, path: &str) -> Option<String>;
}

/// The working tree: `git ls-files --cached --others --exclude-standard -z`, so
/// `.gitignore` is respected; the text is read from disk.
pub struct WorkTree;

impl Tree for WorkTree {
    fn files(&self, runner: &dyn CommandRunner, repo: &Path) -> Vec<String> {
        git_paths(
            runner,
            repo,
            &[
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
            ],
        )
    }

    fn read(&self, _runner: &dyn CommandRunner, repo: &Path, path: &str) -> Option<String> {
        let full = repo.join(path);
        let meta = std::fs::metadata(&full).ok()?;
        if meta.len() > MAX_FILE_BYTES {
            return None;
        }
        let bytes = std::fs::read(&full).ok()?;
        text_of(bytes)
    }
}

/// A committed revision: `git ls-tree -r -z --name-only <rev>` and `git show <rev>:<path>`,
/// so a scan can read the deployed revision rather than the working tree.
pub struct Revision<'a>(pub &'a str);

impl Tree for Revision<'_> {
    fn files(&self, runner: &dyn CommandRunner, repo: &Path) -> Vec<String> {
        git_paths(
            runner,
            repo,
            &["ls-tree", "-r", "-z", "--name-only", self.0],
        )
    }

    fn read(&self, runner: &dyn CommandRunner, repo: &Path, path: &str) -> Option<String> {
        let dir = repo.to_str().unwrap_or(".");
        let spec = format!("{}:{path}", self.0);
        match runner.probe(
            &Call::new("git", &["-C", dir, "show", spec.as_str()]),
            PROBE_TIMEOUT,
        ) {
            Ok(o) if o.status == 0 => {
                if o.stdout.len() as u64 > MAX_FILE_BYTES {
                    return None;
                }
                text_of(o.stdout.to_vec())
            }
            _ => None,
        }
    }
}

impl Scan {
    /// Walk `tree` over `repo` with `patterns`: skip vendored and build directories, read
    /// each applicable file, drop and count names that fail the grammar or the runtime list,
    /// and report the coverage.
    pub fn collect(
        runner: &dyn CommandRunner,
        repo: &Path,
        tree: &dyn Tree,
        patterns: &[&dyn Pattern],
    ) -> Scan {
        let mut scan = Scan::default();
        let mut languages: BTreeSet<&'static str> = BTreeSet::new();
        for path in tree.files(runner, repo) {
            if skipped_dir(&path) {
                continue;
            }
            let applicable: Vec<&dyn Pattern> = patterns
                .iter()
                .copied()
                .filter(|p| p.applies(&path))
                .collect();
            if applicable.is_empty() {
                continue;
            }
            let Some(text) = tree.read(runner, repo, &path) else {
                continue;
            };
            scan.coverage.files += 1;
            for pattern in applicable {
                languages.insert(pattern.language());
                for observation in pattern.scan(&path, &text) {
                    if kept(&observation) {
                        scan.observations.push(observation);
                    } else {
                        scan.coverage.skipped_patterns += 1;
                    }
                }
            }
        }
        scan.coverage.languages = languages.into_iter().map(str::to_string).collect();
        scan
    }
}

/// Whether `path` passes through a vendored or build directory ([`SKIP_DIRS`]).
fn skipped_dir(path: &str) -> bool {
    path.split('/')
        .any(|component| SKIP_DIRS.contains(&component))
}

/// Whether an observation survives the name grammar and the runtime list. An
/// [`Kind::Ambiguous`] observation carries no name and always survives; an
/// [`Kind::Observed`] one must carry a valid, non-runtime name.
fn kept(observation: &Observation) -> bool {
    match observation.kind {
        Kind::Ambiguous => true,
        Kind::Observed => observation
            .name
            .as_deref()
            .is_some_and(|name| valid_name(name) && !runtime_name(name)),
    }
}

/// The NUL-separated paths one `git` listing call printed; an empty list on any failure.
fn git_paths(runner: &dyn CommandRunner, repo: &Path, args: &[&str]) -> Vec<String> {
    let dir = repo.to_str().unwrap_or(".");
    let mut argv = vec!["-C", dir];
    argv.extend_from_slice(args);
    match runner.probe(&Call::new("git", &argv), PROBE_TIMEOUT) {
        Ok(o) if o.status == 0 => o
            .stdout
            .split(|b| *b == 0)
            .filter(|part| !part.is_empty())
            .filter_map(|part| String::from_utf8(part.to_vec()).ok())
            .collect(),
        _ => Vec::new(),
    }
}

/// A file's bytes as text, or `None` for a binary file (a NUL byte) or invalid UTF-8.
fn text_of(bytes: Vec<u8>) -> Option<String> {
    if bytes.contains(&0) {
        return None;
    }
    String::from_utf8(bytes).ok()
}

pub mod lang;
pub mod manifests;

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
