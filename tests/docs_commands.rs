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
    // Each example's README is a page people copy commands from, too.
    let mut examples: Vec<PathBuf> = std::fs::read_dir(root.join("examples"))
        .expect("examples dir")
        .map(|e| e.expect("entry").path().join("README.md"))
        .collect();
    examples.sort();
    files.extend(examples);
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
                .env_remove("GITHUB_STEP_SUMMARY") // never the job summary of the run testing opv
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

/// Every target a shell block in the fleet-fly example names with `--target` is declared as
/// `[environments.<env>.targets.<name>]` in that example's `secrets.toml`.
#[test]
fn fleet_fly_readme_targets_are_declared_in_its_secrets() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let readme =
        std::fs::read_to_string(root.join("examples/fleet-fly/README.md")).expect("read README");
    let secrets = std::fs::read_to_string(root.join("examples/fleet-fly/secrets.toml"))
        .expect("read secrets.toml");

    let declared: std::collections::BTreeSet<String> = secrets
        .lines()
        .filter_map(|l| l.trim().strip_prefix("[environments."))
        .filter_map(|rest| rest.split_once(".targets."))
        .filter_map(|(_, name)| name.strip_suffix(']'))
        .map(str::trim)
        .map(str::to_string)
        .collect();
    let used: std::collections::BTreeSet<String> = extract("examples/fleet-fly/README.md", &readme)
        .commands
        .iter()
        .flat_map(|cmd| {
            cmd.args
                .iter()
                .enumerate()
                .filter(|(_, a)| a.as_str() == "--target")
                .filter_map(|(i, _)| cmd.args.get(i + 1).cloned())
        })
        .collect();

    let undeclared: Vec<&String> = used.difference(&declared).collect();
    assert!(
        undeclared.is_empty(),
        "examples/fleet-fly/README.md names targets missing from secrets.toml: {undeclared:?}"
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

const CODES_BEGIN: &str = "<!-- error-codes:begin";
const CODES_END: &str = "<!-- error-codes:end -->";

/// The usage.md error-code table, generated from the catalog's `Cause` enum (I8, design
/// §10 step 5): each code's exit codes, retry classes and `human_required`, from an example
/// of every cause ([`opv::cause::codes::table`]).
fn codes_table() -> String {
    let mut t =
        String::from("| `code` | Exit | `retry` | Human | Meaning |\n|---|---|---|---|---|\n");
    for r in opv::cause::codes::table() {
        let exit: Vec<String> = r.exits.iter().map(i32::to_string).collect();
        let retry: Vec<&str> = r.retry.iter().map(|c| c.as_str()).collect();
        let human: Vec<&str> = r
            .human_required
            .iter()
            .map(|h| if *h { "yes" } else { "no" })
            .collect();
        t.push_str(&format!(
            "| `{}` | {} | {} | {} | {} |\n",
            r.code,
            exit.join("/"),
            retry.join("/"),
            human.join("/"),
            r.meaning.replace('|', "\\|")
        ));
    }
    t
}

/// I8, `docs_table_is_generated` (design §11): the error-code table in usage.md is exactly
/// the one generated from the `Cause` enum. Regenerate it with `UPDATE_DOCS=1 cargo
/// nextest run --features fake --test docs_commands`.
#[test]
fn usage_error_code_table_matches_the_code() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/usage.md");
    let doc = std::fs::read_to_string(&path).unwrap();
    let begin = doc
        .find(CODES_BEGIN)
        .expect("usage.md has the error-codes:begin marker");
    let body = begin + doc[begin..].find("-->").unwrap() + "-->\n".len();
    let end = doc
        .find(CODES_END)
        .expect("usage.md has the error-codes:end marker");
    let want = codes_table();
    if std::env::var_os("UPDATE_DOCS").is_some() {
        std::fs::write(&path, format!("{}{want}{}", &doc[..body], &doc[end..])).unwrap();
        return;
    }
    assert_eq!(
        &doc[body..end],
        want,
        "run UPDATE_DOCS=1 cargo test --features fake --test docs_commands"
    );
}

/// One of the four id fields (`vault_id`, `item_id`, `state_vault_id`, `delivery_items`) written
/// as a bare or inline-table assignment in a `secrets.toml` example. A dotted path
/// (`environments.prod.boundaries.api.vault_id = …`) is the bindings-file form, not inline.
fn inline_id_field(line: &str) -> Option<&'static str> {
    const NAMES: [&str; 4] = ["vault_id", "item_id", "state_vault_id", "delivery_items"];
    let code = strip_comment(line);
    for name in NAMES {
        let mut from = 0;
        while let Some(pos) = code[from..].find(name) {
            let i = from + pos;
            let before = code[..i].chars().rev().find(|c| !c.is_whitespace());
            let after = code[i + name.len()..].trim_start();
            if before != Some('.') && after.starts_with('=') {
                return Some(name);
            }
            from = i + name.len();
        }
    }
    None
}

/// Every `secrets.toml` example in configuration.md keeps 1Password ids out of the contract:
/// the only id assignments are in the `secrets.bindings.toml` block.
#[test]
fn configuration_secrets_examples_have_no_inline_ids() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let text =
        std::fs::read_to_string(root.join("docs/configuration.md")).expect("read configuration.md");
    let mut in_toml = false;
    let mut bindings = false;
    let mut offenders = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let trimmed = raw.trim();
        if let Some(info) = trimmed.strip_prefix("```") {
            if in_toml {
                in_toml = false;
                bindings = false;
            } else if info.trim().eq_ignore_ascii_case("toml") {
                in_toml = true;
                bindings = false;
            }
            continue;
        }
        if !in_toml {
            continue;
        }
        if raw.contains("secrets.bindings.toml") {
            bindings = true;
        }
        if bindings {
            continue;
        }
        if let Some(name) = inline_id_field(raw) {
            offenders.push(format!("docs/configuration.md:{}: {name} = …", idx + 1));
        }
    }
    assert!(
        offenders.is_empty(),
        "secrets.toml examples must keep 1Password ids in secrets.bindings.toml:\n{}",
        offenders.join("\n")
    );
}

/// The contents of every inline Markdown link target on `line`.
fn links(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(i) = rest.find("](") {
        let after = &rest[i + 2..];
        match after.find(')') {
            Some(end) => {
                out.push(after[..end].to_string());
                rest = &after[end + 1..];
            }
            None => break,
        }
    }
    out
}

/// Drop inline code spans (`` `…` ``) so a `](...)` inside code is not read as a link.
fn strip_code_spans(line: &str) -> String {
    let mut out = String::new();
    let mut in_code = false;
    for c in line.chars() {
        if c == '`' {
            in_code = !in_code;
        } else if !in_code {
            out.push(c);
        }
    }
    out
}

/// GitHub's heading anchor: lower-case, spaces to hyphens, other punctuation dropped.
fn heading_anchor(heading: &str) -> String {
    let mut out = String::new();
    for c in heading.chars() {
        if c.is_alphanumeric() || c == '-' || c == '_' {
            out.extend(c.to_lowercase());
        } else if c == ' ' {
            out.push('-');
        }
    }
    out
}

/// The anchors of every ATX heading in a Markdown file, fences excluded.
fn heading_anchors(path: &Path) -> std::collections::HashSet<String> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let mut anchors = std::collections::HashSet::new();
    let mut in_fence = false;
    for raw in text.lines() {
        let trimmed = raw.trim_start();
        if trimmed.starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        if let Some(h) = trimmed.strip_prefix('#') {
            let h = h.trim_start_matches('#').trim();
            if !h.is_empty() {
                anchors.insert(heading_anchor(h));
            }
        }
    }
    anchors
}

/// Every relative link in a doc resolves: its file exists and, with a `#fragment`, the
/// target file has a matching heading.
fn relative_links_resolve(rel: &str) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = root.join(rel);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {rel}: {e}"));
    let mut failures = Vec::new();
    let mut in_fence = false;
    for (idx, raw) in text.lines().enumerate() {
        if raw.trim_start().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        for target in links(&strip_code_spans(raw)) {
            if target.starts_with("http://")
                || target.starts_with("https://")
                || target.starts_with("mailto:")
            {
                continue;
            }
            let (file, fragment) = match target.split_once('#') {
                Some((file, fragment)) => (file, Some(fragment)),
                None => (target.as_str(), None),
            };
            let resolved = if file.is_empty() {
                path.clone()
            } else {
                path.parent().expect("docs dir").join(file)
            };
            if !resolved.exists() {
                failures.push(format!("{rel}:{}: missing {}", idx + 1, resolved.display()));
                continue;
            }
            let is_markdown = resolved
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e == "md" || e == "txt");
            if let Some(fragment) = fragment
                && is_markdown
                && !heading_anchors(&resolved).contains(fragment)
            {
                failures.push(format!(
                    "{rel}:{}: {} has no heading #{fragment}",
                    idx + 1,
                    resolved.display()
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{rel} has unresolved relative links:\n{}",
        failures.join("\n")
    );
}

/// Every relative link in configuration.md resolves.
#[test]
fn configuration_relative_links_resolve() {
    relative_links_resolve("docs/configuration.md");
}

/// Every relative link in security.md resolves.
#[test]
fn security_relative_links_resolve() {
    relative_links_resolve("docs/security.md");
}

/// `opv` rewrites clap's `unrecognized subcommand` error as its own exit-2 line,
/// `opv: unrecognized subcommand '<word>'`, which [`is_clap_usage_error`] does not match.
/// A command §25.3 removed renders exactly that line, so this is how the docs guard
/// recognises a removed command.
fn is_removed_command_error(code: Option<i32>, stderr: &str) -> bool {
    code == Some(2) && stderr.contains("unrecognized subcommand")
}

/// A doc block naming a §25.3 removed command is reported: the extracted `opv bootstrap`
/// runs and produces the removed-command line.
#[test]
fn reports_a_removed_command_named_in_a_doc() {
    let found = extract("fixture.md", "```sh\nopv bootstrap\n```\n");
    let args = &found.commands[0].args;
    let sandbox = tempfile::tempdir().expect("tempdir");
    let out = Command::new(env!("CARGO_BIN_EXE_opv"))
        .args(args)
        .current_dir(sandbox.path())
        .env_clear()
        .env("PATH", "")
        .env("HOME", sandbox.path())
        .stdin(std::process::Stdio::null())
        .output()
        .expect("run opv");
    assert!(is_removed_command_error(
        out.status.code(),
        &String::from_utf8_lossy(&out.stderr)
    ));
}
