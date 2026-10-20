//! Language scanner patterns (design Part V, row `scan-lang`): Rust, TypeScript/JavaScript,
//! Python, Go, Ruby and C/C++. Each pattern reads one language's source text and returns names
//! only.
//!
//! A statically read literal name is [`Kind::Observed`] with its `file:line`; the same call
//! with a computed argument (a variable, concatenation, template or f-string) is
//! [`Kind::Ambiguous`] with no name. A pattern never reads a value: it sees text, never the
//! environment, and an [`Observation`] carries a name, a file and a line, never a value.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use regex::Regex;

use super::{Kind, Observation, Pattern};

/// One call form a language reads: its compiled [`Regex`] (the argument in capture group 1)
/// and whether group 1 is itself the name (`process.env.X`) rather than an argument to
/// classify (`process.env["X"]`).
struct Call {
    re: Regex,
    bare: bool,
}

/// Compile one call form. The pattern is a static literal, so a failure is a bug.
fn call(pattern: &str, bare: bool) -> Call {
    Call {
        re: Regex::new(pattern).expect("static language regex"),
        bare,
    }
}

/// Every observation one language's `calls` make in `text`, in text order. A literal
/// argument is observed with its name; a computed one is ambiguous with no name.
fn scan_with(path: &str, text: &str, calls: &[Call]) -> Vec<Observation> {
    let mut found: Vec<(usize, Observation)> = Vec::new();
    for form in calls {
        for caps in form.re.captures_iter(text) {
            let arg = caps.get(1).expect("one capture group").as_str();
            let start = caps.get(0).expect("whole match").start();
            let (name, kind) = if form.bare {
                (Some(arg.to_string()), Kind::Observed)
            } else {
                match literal(arg) {
                    Some(name) => (Some(name), Kind::Observed),
                    None => (None, Kind::Ambiguous),
                }
            };
            found.push((
                start,
                Observation {
                    name,
                    file: path.to_string(),
                    line: line_of(text, start),
                    kind,
                },
            ));
        }
    }
    found.sort_by_key(|(offset, _)| *offset);
    found
        .into_iter()
        .map(|(_, observation)| observation)
        .collect()
}

/// The 1-based line of the byte `offset` in `text`.
fn line_of(text: &str, offset: usize) -> usize {
    text[..offset].bytes().filter(|b| *b == b'\n').count() + 1
}

/// The name inside a plain quoted literal, or `None` for a computed argument. A template,
/// f-string, concatenation or variable is computed; only `"X"` and `'X'` are literal.
fn literal(arg: &str) -> Option<String> {
    let arg = arg.trim();
    let bytes = arg.as_bytes();
    if bytes.len() >= 2 {
        let (first, last) = (bytes[0], bytes[bytes.len() - 1]);
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return Some(arg[1..arg.len() - 1].to_string());
        }
    }
    None
}

/// Rust: `std::env::var`, `env::var_os`, `env!`, `option_env!`, `dotenvy::var`.
pub struct Rust;

impl Pattern for Rust {
    fn language(&self) -> &'static str {
        "rust"
    }

    fn applies(&self, path: &str) -> bool {
        path.ends_with(".rs")
    }

    fn scan(&self, path: &str, text: &str) -> Vec<Observation> {
        scan_with(path, text, rust_calls())
    }
}

fn rust_calls() -> &'static [Call] {
    static CALLS: OnceLock<Vec<Call>> = OnceLock::new();
    CALLS.get_or_init(|| {
        vec![
            call(r#"(?:std::)?env::var(?:_os)?\s*\(\s*([^)]*)\)"#, false),
            call(r#"\bdotenvy::var\s*\(\s*([^)]*)\)"#, false),
            call(r#"\b(?:option_)?env!\s*\(\s*([^)]*)\)"#, false),
        ]
    })
}

/// TypeScript/JavaScript: `process.env.X`, `process.env["X"]`, `import.meta.env.X`,
/// `Deno.env.get("X")`.
pub struct TypeScript;

impl Pattern for TypeScript {
    fn language(&self) -> &'static str {
        "typescript"
    }

    fn applies(&self, path: &str) -> bool {
        [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]
            .iter()
            .any(|ext| path.ends_with(ext))
    }

    fn scan(&self, path: &str, text: &str) -> Vec<Observation> {
        scan_with(path, text, typescript_calls())
    }
}

fn typescript_calls() -> &'static [Call] {
    static CALLS: OnceLock<Vec<Call>> = OnceLock::new();
    CALLS.get_or_init(|| {
        vec![
            call(r#"\bprocess\.env\.([A-Za-z_$][A-Za-z0-9_$]*)"#, true),
            call(r#"\bprocess\.env\s*\[\s*([^\]]*)\]"#, false),
            call(r#"\bimport\.meta\.env\.([A-Za-z_$][A-Za-z0-9_$]*)"#, true),
            call(r#"\bDeno\.env\.get\s*\(\s*([^)]*)\)"#, false),
        ]
    })
}

/// Python: `os.environ["X"]`, `os.environ.get("X")`, `os.getenv("X")`, `environ.get("X")`.
pub struct Python;

impl Pattern for Python {
    fn language(&self) -> &'static str {
        "python"
    }

    fn applies(&self, path: &str) -> bool {
        path.ends_with(".py")
    }

    fn scan(&self, path: &str, text: &str) -> Vec<Observation> {
        scan_with(path, text, python_calls())
    }
}

fn python_calls() -> &'static [Call] {
    static CALLS: OnceLock<Vec<Call>> = OnceLock::new();
    CALLS.get_or_init(|| {
        vec![
            call(r#"\bos\.environ\s*\[\s*([^\]]*)\]"#, false),
            call(r#"\bos\.environ\.get\s*\(\s*([^)]*)\)"#, false),
            call(r#"\bos\.getenv\s*\(\s*([^)]*)\)"#, false),
            call(r#"(?:^|[^.\w])environ\.get\s*\(\s*([^)]*)\)"#, false),
        ]
    })
}

/// Go: `os.Getenv("X")`, `os.LookupEnv("X")`. `viper.GetString("X")` is not an env read.
pub struct Go;

impl Pattern for Go {
    fn language(&self) -> &'static str {
        "go"
    }

    fn applies(&self, path: &str) -> bool {
        path.ends_with(".go")
    }

    fn scan(&self, path: &str, text: &str) -> Vec<Observation> {
        scan_with(path, text, go_calls())
    }
}

fn go_calls() -> &'static [Call] {
    static CALLS: OnceLock<Vec<Call>> = OnceLock::new();
    CALLS.get_or_init(|| {
        vec![call(
            r#"\bos\.(?:Getenv|LookupEnv)\s*\(\s*([^)]*)\)"#,
            false,
        )]
    })
}

/// Ruby: `ENV['X']`, `ENV["X"]`, `ENV.fetch('X'[, default])`, in a `.rb` file or a
/// `Rakefile`/`Gemfile`.
pub struct Ruby;

impl Pattern for Ruby {
    fn language(&self) -> &'static str {
        "ruby"
    }

    fn applies(&self, path: &str) -> bool {
        path.ends_with(".rb") || matches!(file_name(path), "Rakefile" | "Gemfile")
    }

    fn scan(&self, path: &str, text: &str) -> Vec<Observation> {
        scan_with(path, text, ruby_calls())
    }
}

/// The final path component: `a/b/Rakefile` is `Rakefile`.
fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn ruby_calls() -> &'static [Call] {
    static CALLS: OnceLock<Vec<Call>> = OnceLock::new();
    CALLS.get_or_init(|| {
        vec![
            call(r#"\bENV\s*\[\s*([^\]]*)\]"#, false),
            call(r#"\bENV\.fetch\s*\(\s*([^,)]*)"#, false),
        ]
    })
}

/// C/C++: `getenv("X")`, `secure_getenv("X")`, including the qualified `std::getenv`.
pub struct C;

impl Pattern for C {
    fn language(&self) -> &'static str {
        "c"
    }

    fn applies(&self, path: &str) -> bool {
        [".c", ".h", ".cc", ".cpp", ".hpp"]
            .iter()
            .any(|ext| path.ends_with(ext))
    }

    fn scan(&self, path: &str, text: &str) -> Vec<Observation> {
        scan_with(path, text, c_calls())
    }
}

fn c_calls() -> &'static [Call] {
    static CALLS: OnceLock<Vec<Call>> = OnceLock::new();
    CALLS.get_or_init(|| vec![call(r#"\b(?:secure_)?getenv\s*\(\s*([^)]*)\)"#, false)])
}

/// Reads of files under a product's declared secrets directory (#136, #175): the app is
/// handed the directory in `local.secrets_dir_env` (say `APP_SECRETS_DIR`), and a key with
/// `file = "db/migrate-pem"` is delivered there as a file, never as a variable. A read of
/// `<secrets_dir_env>/<file>` is therefore an observation of the key that file delivers, by
/// name; nothing here reads a value.
///
/// The contract builds it ([`SecretsDir::new`]): the variable naming the directory, and each
/// declared `file` path mapped to the key it delivers.
pub struct SecretsDir {
    /// One `(variable, file path -> key)` group per product that declares
    /// `local.secrets_dir_env`.
    groups: Vec<(String, BTreeMap<String, String>)>,
}

impl SecretsDir {
    /// The reads of files under `dir_env`: `files` maps each declared `file` path to the key
    /// delivered there.
    pub fn new<S, K>(dir_env: impl Into<String>, files: impl IntoIterator<Item = (S, K)>) -> Self
    where
        S: Into<String>,
        K: Into<String>,
    {
        let files = files
            .into_iter()
            .map(|(path, key)| (path.into(), key.into()))
            .collect();
        Self {
            groups: vec![(dir_env.into(), files)],
        }
    }

    /// The reads of files under several directories at once: one `(variable, file path ->
    /// key)` group per product that declares `local.secrets_dir_env`.
    pub fn from_groups(
        groups: impl IntoIterator<Item = (String, BTreeMap<String, String>)>,
    ) -> Self {
        Self {
            groups: groups.into_iter().collect(),
        }
    }

    /// Whether no product declares a secrets directory with a `file` key.
    pub fn is_empty(&self) -> bool {
        self.groups.iter().all(|(_, files)| files.is_empty())
    }
}

impl Pattern for SecretsDir {
    fn language(&self) -> &'static str {
        "secrets_dir"
    }

    fn applies(&self, path: &str) -> bool {
        code_file(path)
    }

    fn scan(&self, path: &str, text: &str) -> Vec<Observation> {
        let mut found: Vec<(usize, Observation)> = Vec::new();
        for (dir_env, files) in &self.groups {
            // The app reads these files where it has the directory variable; without it the
            // same path literal names some other file.
            if !text.contains(dir_env.as_str()) {
                continue;
            }
            for (file, key) in files {
                for offset in quoted(text, file) {
                    found.push((
                        offset,
                        Observation {
                            name: Some(key.clone()),
                            file: path.to_string(),
                            line: line_of(text, offset),
                            kind: Kind::Observed,
                        },
                    ));
                }
            }
        }
        found.sort_by_key(|(offset, _)| *offset);
        found.dedup_by(|a, b| a.1 == b.1);
        found
            .into_iter()
            .map(|(_, observation)| observation)
            .collect()
    }
}

/// The byte offsets where `needle` sits inside a plain quoted literal (`"..."` or `'...'`).
fn quoted(text: &str, needle: &str) -> Vec<usize> {
    let mut at = Vec::new();
    for quote in ['"', '\''] {
        let wrapped = format!("{quote}{needle}{quote}");
        at.extend(text.match_indices(&wrapped).map(|(offset, _)| offset + 1));
    }
    at
}

/// Whether a secrets-directory read can be in `path`: the languages the scanner reads, plus
/// shell and the extensionless Ruby scripts.
fn code_file(path: &str) -> bool {
    const EXT: &[&str] = &[
        ".rs", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".go", ".rb", ".c", ".h",
        ".cc", ".cpp", ".hpp", ".sh", ".bash",
    ];
    EXT.iter().any(|ext| path.ends_with(ext)) || matches!(file_name(path), "Rakefile" | "Gemfile")
}

#[cfg(test)]
#[path = "lang_tests.rs"]
mod tests;
