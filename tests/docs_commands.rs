//! Docs drift guard: every `opv ...` command line shown in the user docs must
//! be accepted by the real clap parser, so a renamed flag or command fails CI
//! instead of leaving the docs stale.

use std::path::{Path, PathBuf};
use std::process::Command;

const SHELL_LANGS: [&str; 5] = ["", "sh", "bash", "shell", "console"];
const CLAP_MARKERS: [&str; 4] = [
    "error: unexpected argument",
    "error: unrecognized subcommand",
    "error: invalid value",
    "error: the following required arguments were not provided",
];

#[derive(Debug, PartialEq)]
struct DocCommand {
    file: String,
    line: usize,
    args: Vec<String>,
}

#[derive(Debug, Default, PartialEq)]
struct Extracted {
    commands: Vec<DocCommand>,
    skipped: Vec<String>,
}

fn substitute_placeholders(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find('<') {
        let after = &rest[start + 1..];
        match after.find('>') {
            Some(end)
                if !after[..end].is_empty() && !after[..end].contains(char::is_whitespace) =>
            {
                out.push_str(&rest[..start]);
                out.push_str(match &after[..end] {
                    "env" => "dev",
                    "product" => "api",
                    "KEY" => "KEY",
                    _ => "x",
                });
                rest = &after[end + 1..];
            }
            _ => {
                out.push_str(&rest[..=start]);
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Strip a trailing ` # comment` that is outside quotes.
fn strip_comment(line: &str) -> &str {
    let mut quote: Option<char> = None;
    let mut prev = ' ';
    for (i, c) in line.char_indices() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if c == '"' || c == '\'' => quote = Some(c),
            None if c == '#' && prev.is_whitespace() => return line[..i].trim_end(),
            None => {}
        }
        prev = c;
    }
    line.trim_end()
}

/// Minimal shell word splitting: whitespace, single and double quotes.
fn split_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut quote: Option<char> = None;
    for c in line.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => cur.push(c),
            None if c == '"' || c == '\'' => {
                quote = Some(c);
                in_word = true;
            }
            None if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            None => {
                cur.push(c);
                in_word = true;
            }
        }
    }
    if in_word {
        words.push(cur);
    }
    words
}

fn extract(file: &str, text: &str) -> Extracted {
    let mut result = Extracted::default();
    let mut in_fence = false;
    let mut shell_fence = false;
    let mut pending: Option<(usize, String)> = None;

    let finish = |result: &mut Extracted, start: usize, joined: String| {
        let cleaned = strip_comment(&joined).to_string();
        let cleaned = cleaned.trim();
        let cmd = cleaned.strip_prefix("$ ").unwrap_or(cleaned).trim();
        if !cmd.starts_with("opv ") && cmd != "opv" {
            return;
        }
        let synopsis = cmd.split_whitespace().any(|w| w.starts_with('['));
        if cmd.contains('|') || cmd.contains("$(") || cmd.contains("&&") || synopsis {
            result.skipped.push(format!("{file}:{start}: {cmd}"));
            return;
        }
        let mut words = split_words(&substitute_placeholders(cmd));
        // Output redirection is not part of the CLI surface; drop it.
        if let Some(i) = words.iter().position(|w| w == ">" || w == ">>") {
            words.truncate(i);
        }
        result.commands.push(DocCommand {
            file: file.to_string(),
            line: start,
            args: words[1..].to_vec(),
        });
    };

    for (idx, raw) in text.lines().enumerate() {
        let n = idx + 1;
        let trimmed = raw.trim();
        if let Some(info) = trimmed.strip_prefix("```") {
            if in_fence {
                if let Some((start, joined)) = pending.take() {
                    finish(&mut result, start, joined);
                }
                in_fence = false;
            } else {
                in_fence = true;
                let lang = info.trim().to_ascii_lowercase();
                shell_fence = SHELL_LANGS.contains(&lang.as_str());
            }
            continue;
        }
        if !in_fence || !shell_fence {
            continue;
        }
        let (start, mut joined) = match pending.take() {
            Some((s, mut j)) => {
                j.push(' ');
                j.push_str(trimmed);
                (s, j)
            }
            None => (n, trimmed.to_string()),
        };
        if joined.ends_with('\\') {
            joined.pop();
            let joined = joined.trim_end().to_string();
            pending = Some((start, joined));
        } else {
            finish(&mut result, start, std::mem::take(&mut joined));
        }
    }
    if let Some((start, joined)) = pending.take() {
        finish(&mut result, start, joined);
    }
    result
}

fn doc_files(root: &Path) -> Vec<PathBuf> {
    let mut files = vec![
        root.join("README.md"),
        root.join("llms.txt"),
        root.join("CONTRIBUTING.md"),
    ];
    let mut docs: Vec<PathBuf> = std::fs::read_dir(root.join("docs"))
        .expect("docs dir")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.extension().is_some_and(|e| e == "md"))
        .collect();
    docs.sort();
    files.extend(docs);
    files.retain(|p| p.exists());
    files
}

fn is_clap_usage_error(code: Option<i32>, stderr: &str) -> bool {
    if code != Some(2) {
        return false;
    }
    CLAP_MARKERS.iter().any(|m| stderr.contains(m))
        || stderr
            .find("error:")
            .is_some_and(|i| stderr[i..].contains("Usage:"))
}

#[test]
fn every_documented_opv_command_parses() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let sandbox = tempfile::tempdir().expect("tempdir");
    let mut failures = Vec::new();
    let mut skipped = Vec::new();
    let mut checked = 0;

    for path in doc_files(&root) {
        let rel = path.strip_prefix(&root).unwrap().display().to_string();
        let text = std::fs::read_to_string(&path).expect("read doc");
        let found = extract(&rel, &text);
        skipped.extend(found.skipped);
        for cmd in found.commands {
            if matches!(
                cmd.args.first().map(String::as_str),
                Some("setup" | "login")
            ) {
                skipped.push(format!("{}:{}: needs a TTY", cmd.file, cmd.line));
                continue;
            }
            checked += 1;
            let out = Command::new(env!("CARGO_BIN_EXE_opv"))
                .args(&cmd.args)
                .current_dir(sandbox.path())
                .env_clear()
                .env("PATH", "")
                .env("HOME", sandbox.path())
                .env_remove("OPV_CONFIG")
                .env_remove("OPV_PRODUCT")
                .stdin(std::process::Stdio::null())
                .output()
                .expect("run opv");
            let stderr = String::from_utf8_lossy(&out.stderr);
            if is_clap_usage_error(out.status.code(), &stderr) {
                failures.push(format!(
                    "{}:{}: opv {}\n    {}",
                    cmd.file,
                    cmd.line,
                    cmd.args.join(" "),
                    stderr.lines().next().unwrap_or("")
                ));
            }
        }
    }

    eprintln!(
        "checked {checked} documented commands; skipped {}:",
        skipped.len()
    );
    for s in &skipped {
        eprintln!("  skipped {s}");
    }
    assert!(
        failures.is_empty(),
        "documented commands rejected by the CLI parser:\n{}",
        failures.join("\n")
    );
}

#[test]
fn extractor_joins_continuations() {
    let got = extract(
        "f.md",
        "```sh\nopv sync dev \\\n  --deploy \\\n  --prune\n```\n",
    );
    assert_eq!(got.commands[0].args, ["sync", "dev", "--deploy", "--prune"]);
}

#[test]
fn extractor_reports_start_line_of_continued_command() {
    let got = extract("f.md", "text\n```sh\nopv sync dev \\\n  --deploy\n```\n");
    assert_eq!(got.commands[0].line, 3);
}

#[test]
fn extractor_strips_trailing_comments() {
    let got = extract("f.md", "```sh\nopv plan dev   # preview\n```\n");
    assert_eq!(got.commands[0].args, ["plan", "dev"]);
}

#[test]
fn extractor_keeps_hash_inside_quotes() {
    let got = extract("f.md", "```sh\nopv run dev -- echo \"a #b\"\n```\n");
    assert_eq!(got.commands[0].args.last().unwrap(), "a #b");
}

#[test]
fn extractor_substitutes_known_placeholders() {
    let got = extract("f.md", "```\nopv check <env> --product <product>\n```\n");
    assert_eq!(got.commands[0].args, ["check", "dev", "--product", "api"]);
}

#[test]
fn extractor_substitutes_key_placeholder() {
    let got = extract("f.md", "```\nopv explain <KEY>\n```\n");
    assert_eq!(got.commands[0].args, ["explain", "KEY"]);
}

#[test]
fn extractor_substitutes_unknown_placeholders_with_x() {
    let got = extract("f.md", "```\nopv init <env> --vault <vault-id>\n```\n");
    assert_eq!(got.commands[0].args, ["init", "dev", "--vault", "x"]);
}

#[test]
fn extractor_accepts_dollar_prompt() {
    let got = extract("f.md", "```console\n$ opv doctor\n```\n");
    assert_eq!(got.commands[0].args, ["doctor"]);
}

#[test]
fn extractor_skips_pipes() {
    let got = extract("f.md", "```sh\nopv plan dev --json | jq .\n```\n");
    assert_eq!((got.commands.len(), got.skipped.len()), (0, 1));
}

#[test]
fn extractor_skips_command_substitution_and_and_chains() {
    let got = extract("f.md", "```sh\nopv run $(x)\nopv a && opv b\n```\n");
    assert_eq!((got.commands.len(), got.skipped.len()), (0, 2));
}

#[test]
fn extractor_skips_synopsis_lines() {
    let got = extract("f.md", "```sh\nopv sync dev [--deploy]\n```\n");
    assert_eq!((got.commands.len(), got.skipped.len()), (0, 1));
}

#[test]
fn extractor_drops_output_redirection() {
    let got = extract("f.md", "```sh\nopv completions zsh > _opv\n```\n");
    assert_eq!(got.commands[0].args, ["completions", "zsh"]);
}

#[test]
fn extractor_ignores_other_languages_and_prose() {
    let got = extract(
        "f.md",
        "opv plan dev\n```toml\nopv = 1\n```\n```json\nopv plan dev\n```\n",
    );
    assert_eq!(got.commands.len(), 0);
}

/// The GitHub Actions example pins the release this source builds, so a version bump
/// cannot leave it installing an old opv.
#[test]
fn github_actions_example_pins_this_version() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let usage = std::fs::read_to_string(root.join("docs/usage.md")).expect("usage.md");
    let want = format!("OPV_VERSION: v{}", env!("CARGO_PKG_VERSION"));
    assert!(usage.contains(&want), "docs/usage.md must pin {want}");
}
