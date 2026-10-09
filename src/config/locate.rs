//! Configuration errors that point at the file (H10, FR-2): `<file>:<line>: <field>:
//! <problem>`, the offending line, and the exact fix where one can be derived from the
//! message. Names and positions only: `secrets.toml` holds no values.
//!
//! `parse` reports errors against the name `secrets.toml` (it never sees a path), in the
//! TOML parser's layout or as a bare message that starts with its owner (`environment
//! prod: …`, `api/KEY: …`). [`relocate`] rewrites either form for the file that was read.

use std::path::Path;

use toml::de::DeTable;

use crate::app::suggest;
use crate::error::Error;

/// How [`super::parse`] prefixes an error that carries a position.
const INVALID: &str = "invalid secrets.toml: ";
/// How the TOML parser's own layout starts.
const AT_LINE: &str = "TOML parse error at line ";

/// `e`, when it is a configuration error from parsing `text`, rewritten to name `file`,
/// the line and the field, with a `fix:` line when the message names what is allowed. Its
/// next step, if any, is kept. Any other error is returned unchanged.
pub(super) fn relocate(e: Error, text: &str, file: &Path) -> Error {
    relocate_at(e, text, super::Source::File(file))
}

/// [`relocate`] for any [`super::Source`]: a file is named with the line
/// (`<file>:<line>: <field>`); a manifest has no file, so it is named by its title
/// (`manifest "opv · app": <field>`, FR-44), still with the offending line shown.
pub(super) fn relocate_at(e: Error, text: &str, source: super::Source<'_>) -> Error {
    let Error::Config(m) = &e else { return e };
    let next = m.next().map(str::to_string);
    let body = m.text().strip_prefix(INVALID).unwrap_or(m.text());
    let (file, numbered) = match source {
        super::Source::File(f) => (f.display().to_string(), true),
        super::Source::Manifest(title) => (format!("manifest {title:?}"), false),
    };
    let rewritten = match placed(body) {
        Some(p) => {
            let field = field_on_line(text, p.line);
            let line = numbered.then_some(p.line);
            render(&file, line, &field, Some(p.snippet), &p.msg, text)
        }
        None => {
            let (field, line, snippet) = match owner_path(body) {
                Some(path) => locate_path(text, &path),
                None => (String::new(), None, None),
            };
            let line = line.filter(|_| numbered);
            render(&file, line, &field, snippet, body, text)
        }
    };
    let out = Error::Config(rewritten.into());
    match next {
        Some(n) => out.with_next(n),
        None => out,
    }
}

/// An error in the TOML parser's layout: the 0-based line, the three snippet lines and the
/// message after them.
struct Placed {
    line: usize,
    snippet: String,
    msg: String,
}

fn placed(body: &str) -> Option<Placed> {
    let rest = body.strip_prefix(AT_LINE)?;
    let (head, rest) = rest.split_once('\n')?;
    let num: usize = head.split(',').next()?.trim().parse().ok()?;
    let mut lines = rest.splitn(4, '\n');
    let snippet = [lines.next()?, lines.next()?, lines.next()?].join("\n");
    let msg = lines.next().unwrap_or("").trim_end().to_string();
    Some(Placed {
        line: num.checked_sub(1)?,
        snippet,
        msg,
    })
}

/// `file:line: field: msg`, the snippet, the rest of the message and the fix.
fn render(
    file: &str,
    line: Option<usize>,
    field: &str,
    snippet: Option<String>,
    msg: &str,
    text: &str,
) -> String {
    let (first, rest) = msg.split_once('\n').unwrap_or((msg, ""));
    let first = if field.is_empty() {
        first
    } else {
        without_owner(first)
    };
    let mut out = match line {
        Some(l) => format!("{file}:{}: ", l + 1),
        None => format!("{file}: "),
    };
    if !field.is_empty() {
        out.push_str(field);
        out.push_str(": ");
    }
    out.push_str(first);
    if let Some(s) = snippet {
        out.push('\n');
        out.push_str(&s);
    }
    if !rest.trim().is_empty() {
        out.push('\n');
        out.push_str(rest.trim_end());
    }
    // U4: Do: the fix line becomes the `Do:` step once error.rs has one.
    if let Some(fix) = fix_for(msg, field, text) {
        out.push_str("\n  fix: ");
        out.push_str(&fix);
    }
    out
}

/// `msg` without a leading owner (`environment prod: `, `api/KEY: `, `KEY: `, `store s: `,
/// `product "p": `), which the field already names.
fn without_owner(msg: &str) -> &str {
    let Some((owner, rest)) = msg.split_once(": ") else {
        return msg;
    };
    let words: Vec<&str> = owner.split(' ').collect();
    let is_key = |w: &str| {
        w.chars().next().is_some_and(|c| c.is_ascii_uppercase())
            && w.chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    };
    let owned = match words.as_slice() {
        ["environment" | "store" | "product", _] => true,
        [one] => one.contains('/') || is_key(one),
        _ => false,
    };
    if owned { rest } else { msg }
}

/// The dotted field a 0-based `line` declares: the nearest `[table]` header above it (or
/// on it) and the key assigned on the line.
pub(super) fn field_on_line(text: &str, line: usize) -> String {
    let lines: Vec<&str> = text.split('\n').collect();
    let Some(current) = lines.get(line) else {
        return String::new();
    };
    if let Some(h) = header_of(current) {
        return h;
    }
    let header = lines[..line].iter().rev().find_map(|l| header_of(l));
    match (header, key_of(current)) {
        (Some(h), Some(k)) => format!("{h}.{k}"),
        (Some(h), None) => h,
        (None, Some(k)) => k,
        (None, None) => String::new(),
    }
}

/// `a.b` for a `[a.b]` or `[[a.b]]` header line.
fn header_of(line: &str) -> Option<String> {
    let t = line.trim_start();
    let inner = t.strip_prefix('[')?;
    let inner = inner.strip_prefix('[').unwrap_or(inner);
    let end = inner.find(']')?;
    Some(normalise(&inner[..end]))
}

/// `k` for a `k = v` line (dotted keys kept), `None` for anything else.
fn key_of(line: &str) -> Option<String> {
    let t = line.trim_start();
    if t.starts_with('#') || t.starts_with('[') {
        return None;
    }
    let (k, _) = t.split_once('=')?;
    let k = normalise(k);
    (!k.is_empty()).then_some(k)
}

fn normalise(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace() && *c != '"' && *c != '\'')
        .collect()
}

/// The table path a bare message names by its owner prefix.
fn owner_path(msg: &str) -> Option<Vec<String>> {
    let words: Vec<&str> = msg.split_whitespace().collect();
    let own = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let unquote = |s: &str| s.trim_matches(|c| c == '"' || c == ':').to_string();
    match words.as_slice() {
        ["environment", env, field, ..] if env.ends_with(':') => {
            let env = unquote(env);
            let mut path = vec!["environments".to_string(), env];
            let field = field.trim_end_matches(':');
            if field
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '_' || c == '.')
            {
                path.extend(field.split('.').map(str::to_string));
            }
            Some(path)
        }
        ["environments", _, "and", b, ..] => Some(vec!["environments".into(), unquote(b)]),
        ["product", p, ..] => Some(vec!["products".into(), unquote(p)]),
        ["store", s, ..] => Some(vec!["stores".into(), unquote(s)]),
        ["profile.kind", ..] => Some(own(&["profile", "kind"])),
        ["simple", "profile:", ..] => Some(own(&["products"])),
        ["no", "environments", ..] => Some(own(&["environments"])),
        [owner, ..] if owner.ends_with(':') => {
            let owner = owner.trim_end_matches(':');
            let mut path = match owner.split_once('/') {
                Some((p, k)) => own(&["products", p, "keys", k]),
                None if owner.chars().next().is_some_and(|c| c.is_ascii_uppercase()) => {
                    own(&["keys", owner])
                }
                None => return None,
            };
            if msg.contains("undefined environment") && !msg.contains("refuse_in") {
                path.push("environments".into());
            } else if msg.contains(" rule ") || msg.contains("transform") {
                path.push("rules".into());
            }
            Some(path)
        }
        _ => None,
    }
}

/// The deepest declared part of `path`: its dotted name, 0-based line and snippet.
fn locate_path(text: &str, path: &[String]) -> (String, Option<usize>, Option<String>) {
    let Ok(root) = DeTable::parse(text) else {
        return (path.join("."), None, None);
    };
    let mut table = Some(root.get_ref());
    let mut found: Option<std::ops::Range<usize>> = None;
    let mut depth = 0;
    for part in path {
        let Some((n, v)) = table.and_then(|t| t.iter().find(|(n, _)| n.get_ref().as_ref() == part))
        else {
            break;
        };
        found = Some(n.span());
        depth += 1;
        table = v.get_ref().as_table();
    }
    match found {
        Some(span) => {
            let line = text[..span.start].matches('\n').count();
            (
                path[..depth].join("."),
                Some(line),
                Some(snippet(text, span)),
            )
        }
        None => (path.join("."), None, None),
    }
}

/// The three snippet lines of the TOML parser's layout for `span`.
fn snippet(text: &str, span: std::ops::Range<usize>) -> String {
    let before = &text[..span.start];
    let line = before.matches('\n').count();
    let column = before.len() - before.rfind('\n').map_or(0, |i| i + 1);
    let content = text.split('\n').nth(line).unwrap_or("");
    let num = (line + 1).to_string();
    let pad = " ".repeat(num.len() + 1);
    let width = span.len().min(content.len().saturating_sub(column)).max(1);
    format!(
        "{pad}|\n{num} | {content}\n{pad}|{}{}",
        " ".repeat(column + 1),
        "^".repeat(width)
    )
}

/// The edit that fixes `msg` at `field`, when the message names what is allowed.
fn fix_for(msg: &str, field: &str, text: &str) -> Option<String> {
    let first = msg.lines().next().unwrap_or(msg);
    if let Some(bad) = quoted_after(first, "unknown field ") {
        let allowed = allowed_after(first);
        return Some(
            match suggest::close(&bad, allowed.iter().map(String::as_str)).first() {
                Some(good) => format!("rename {bad} to {good}"),
                None if allowed.is_empty() => format!("remove {bad}"),
                None => format!("remove {bad}; allowed here: {}", allowed.join(", ")),
            },
        );
    }
    if let Some(bad) = quoted_after(first, "unknown target section ") {
        let allowed = allowed_after(first);
        return Some(
            match suggest::close(&bad, allowed.iter().map(String::as_str)).first() {
                Some(good) => format!("rename [{field}] to use {good}"),
                None => format!("use one of: {}", allowed.join(", ")),
            },
        );
    }
    if let Some(bad) = quoted_after(first, "unknown variant ") {
        let allowed = allowed_after(first);
        let leaf = field.rsplit('.').next().unwrap_or(field);
        return Some(
            match suggest::close(&bad, allowed.iter().map(String::as_str)).first() {
                Some(good) => format!("set {leaf} = \"{good}\""),
                None => format!("set {leaf} to one of: {}", allowed.join(", ")),
            },
        );
    }
    if let Some(missing) = quoted_after(first, "missing field ") {
        return Some(format!("add {missing} = ... under [{field}]"));
    }
    if let Some(env) = quoted_after(first, "undefined environment ") {
        let defined = environments(text);
        return Some(
            match suggest::close(&env, defined.iter().map(String::as_str)).first() {
                Some(good) => format!("change \"{env}\" to \"{good}\""),
                None => format!(
                    "declare [environments.{env}] or use one of: {}",
                    defined.join(", ")
                ),
            },
        );
    }
    if let Some((_, pattern)) = first.split_once("must match ") {
        let pattern = pattern.split_whitespace().next().unwrap_or(pattern);
        return Some(format!("change {field} so it matches {pattern}"));
    }
    if first.ends_with(" is empty") {
        return Some(format!("set {field} to a non-empty value"));
    }
    None
}

/// The name after `marker`, in backticks or double quotes.
fn quoted_after(s: &str, marker: &str) -> Option<String> {
    let rest = &s[s.find(marker)? + marker.len()..];
    let q = rest.chars().next().filter(|c| *c == '`' || *c == '"')?;
    let inner = &rest[1..];
    Some(inner[..inner.find(q)?].to_string())
}

/// The names after `expected` (or `known:`): backticked names when there are any,
/// otherwise the comma- or `or`-separated words.
fn allowed_after(s: &str) -> Vec<String> {
    let Some(at) = s.find("expected ").or_else(|| s.find("known: ")) else {
        return Vec::new();
    };
    let tail = &s[at..];
    let ticked: Vec<String> = tail
        .split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect();
    if !ticked.is_empty() {
        return ticked;
    }
    let tail = tail
        .trim_start_matches("expected ")
        .trim_start_matches("known: ");
    tail.split([',', '(', ')'])
        .flat_map(|p| p.split(" or "))
        .filter_map(|p| p.split_whitespace().next())
        .filter(|w| {
            w.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                && !matches!(*w, "a" | "or" | "one" | "of")
        })
        .map(str::to_string)
        .collect()
}

/// The environment names `text` declares, for an undefined-environment fix.
fn environments(text: &str) -> Vec<String> {
    let Ok(t) = text.parse::<toml::Table>() else {
        return Vec::new();
    };
    t.get("environments")
        .and_then(toml::Value::as_table)
        .map(|e| e.keys().cloned().collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use crate::error::Error;

    /// The fixture with `from` replaced by `to`, loaded from a file; the error's text and
    /// the file's path.
    fn load_err(from: &str, to: &str) -> (Error, String) {
        let text = std::fs::read_to_string("tests/fixtures/secrets.toml").unwrap();
        assert!(text.contains(from), "{from}");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.toml");
        std::fs::write(&path, text.replacen(from, to, 1)).unwrap();
        let e = crate::config::load(&path).unwrap_err();
        (e, path.display().to_string())
    }

    #[test]
    fn unknown_field_names_file_line_and_field() {
        let (e, file) = load_err(
            "item_id = \"iprd\"",
            "item_id = \"iprd\"\nconfrm_env = true",
        );
        let want = format!("{file}:14: environments.prod.confrm_env: unknown field");
        assert!(e.text().starts_with(&want), "{e}");
    }

    #[test]
    fn unknown_field_fix_names_the_closest_field() {
        let (e, _) = load_err(
            "item_id = \"iprd\"",
            "item_id = \"iprd\"\nconfrm_env = true",
        );
        assert!(
            e.text()
                .ends_with("  fix: rename confrm_env to confirm_env"),
            "{e}"
        );
    }

    #[test]
    fn unknown_variant_fix_names_the_closest_value() {
        let (e, _) = load_err("kind = \"secret\"", "kind = \"secert\"");
        assert!(e.text().ends_with("  fix: set kind = \"secret\""), "{e}");
    }

    #[test]
    fn undefined_environment_is_located_at_the_key() {
        let (e, file) = load_err("environments = [\"prod\"]", "environments = [\"prd\"]");
        let want = format!(
            "{file}:20: products.allumata.keys.OPENAI_API_KEY.environments: undefined environment"
        );
        assert!(e.text().starts_with(&want), "{e}");
    }

    #[test]
    fn undefined_environment_fix_names_the_closest_environment() {
        let (e, _) = load_err("environments = [\"prod\"]", "environments = [\"prd\"]");
        assert!(
            e.text().ends_with("  fix: change \"prd\" to \"prod\""),
            "{e}"
        );
    }

    #[test]
    fn missing_field_fix_names_the_table() {
        let (e, _) = load_err("vault_id = \"vprd\"", "");
        assert!(
            e.text()
                .ends_with("  fix: add vault_id = ... under [environments.prod]"),
            "{e}"
        );
    }

    #[test]
    fn bad_key_name_names_its_line() {
        let (e, file) = load_err(
            "[products.allumata.keys.OPENAI_API_KEY]",
            "[products.allumata.keys.openai]",
        );
        assert!(
            e.text().starts_with(&format!(
                "{file}:18: products.allumata.keys.openai: key name"
            )),
            "{e}"
        );
    }

    #[test]
    fn located_error_keeps_the_offending_line() {
        let (e, _) = load_err("kind = \"secret\"", "kind = \"secert\"");
        assert!(e.text().contains("19 | kind = \"secert\""), "{e}");
    }
}
