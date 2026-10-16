//! Configuration errors that point at the source (H10, FR-2). Names and positions only,
//! never the offending line (C1, SR-1): a file given by mistake (a `.env`) may hold values,
//! so no error quotes the text it came from.
//!
//! `parse` reports a catalog cause ([`Cause::ConfigInvalid`] and the other §4.1 variants)
//! whose field and rule come from the validator, against a stand-in source (it never sees a
//! path). [`relocate_at`] names the real source: the cause's fields are kept as they are,
//! never re-derived from a message or a line (audit 03.01).
//!
//! A provider's section parser still reports free text (`invalid secrets.toml: TOML parse
//! error at line …`, or a bare `environment prod: …`); that text is rewritten to name the
//! source, with the fix only where the parser's message names what is allowed.

use toml::de::DeTable;

use crate::app::suggest;
use crate::cause::{Cause, ConfigSource};
use crate::error::Error;

/// How [`super::parse`] prefixes an error that carries a position.
const INVALID: &str = "invalid secrets.toml: ";
/// How the TOML parser's own layout starts.
const AT_LINE: &str = "TOML parse error at line ";

/// `e`, when it is a configuration error from parsing `text`, naming `source`. A catalog
/// cause gets `source` in place of the stand-in (a manifest has no file, so no line); a
/// provider's free text is rewritten to `<file>:<line>: <field>: <problem>`. Any other error
/// is returned unchanged.
pub(super) fn relocate_at(e: Error, text: &str, source: ConfigSource) -> Error {
    if let Some((cause, _)) = e.cause() {
        return with_source(cause.clone(), source).into();
    }
    legacy(e, text, &source)
}

/// `cause` naming `source`; a manifest has no lines, so its location is dropped (FR-44).
fn with_source(mut cause: Cause, real: ConfigSource) -> Cause {
    let manifest = matches!(real, ConfigSource::Manifest { .. });
    match &mut cause {
        Cause::ConfigInvalid { source, at, .. } | Cause::StateVaultTooWide { source, at, .. } => {
            *source = real;
            if manifest {
                *at = None;
            }
        }
        Cause::BoundaryMissing { source, .. } | Cause::StateVaultMissing { source, .. } => {
            *source = real;
        }
        _ => {}
    }
    cause
}

/// A provider's free-text configuration error, named against `source`.
fn legacy(e: Error, text: &str, source: &ConfigSource) -> Error {
    let code = e.code();
    let Error::Config(m) = &e else { return e };
    let next = m.next().map(str::to_string);
    let body = m.text().strip_prefix(INVALID).unwrap_or(m.text());
    let (file, numbered) = match source {
        ConfigSource::File { path, .. } => (path.display().to_string(), true),
        ConfigSource::Manifest { title, .. } => (format!("manifest {title:?}"), false),
    };
    let rewritten = match placed(body) {
        Some(p) => {
            let field = field_on_line(text, p.line);
            let line = numbered.then_some(p.line);
            (render(&file, line, &field, &p.msg), fix_for(&p.msg, &field))
        }
        None => {
            let (field, line) = match owner_path(body) {
                Some(path) => locate_path(text, &path),
                None => (String::new(), None),
            };
            let line = line.filter(|_| numbered);
            (render(&file, line, &field, body), fix_for(body, &field))
        }
    };
    let (rewritten, fix) = rewritten;
    let mut out = Error::Config(rewritten.into()).with_code(code);
    if let Some(fix) = fix {
        out = out.with_do(fix);
    }
    match next {
        Some(n) => out.with_next(n),
        None => out,
    }
}
/// An error in [`super::toml_error`]'s layout: the 0-based line and the message after it.
struct Placed {
    line: usize,
    msg: String,
}

fn placed(body: &str) -> Option<Placed> {
    let rest = body.strip_prefix(AT_LINE)?;
    let (head, rest) = rest.split_once('\n').unwrap_or((rest, ""));
    let num: usize = head.split(',').next()?.trim().parse().ok()?;
    Some(Placed {
        line: num.checked_sub(1)?,
        msg: rest.trim_end().to_string(),
    })
}

/// `file:line: field: msg` and the rest of the message. Never a source line (C1).
fn render(file: &str, line: Option<usize>, field: &str, msg: &str) -> String {
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
    if !rest.trim().is_empty() {
        out.push('\n');
        out.push_str(rest.trim_end());
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
        ["product", p, ..] => Some(vec!["products".into(), unquote(p)]),
        ["store", s, ..] => Some(vec!["stores".into(), unquote(s)]),
        _ => None,
    }
}

/// The deepest declared part of `path`: its dotted name and 0-based line.
fn locate_path(text: &str, path: &[String]) -> (String, Option<usize>) {
    let Ok(root) = DeTable::parse(text) else {
        return (path.join("."), None);
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
            (path[..depth].join("."), Some(line))
        }
        None => (path.join("."), None),
    }
}

/// The edit that fixes `msg` at `field`, when the message names what is allowed.
fn fix_for(msg: &str, field: &str) -> Option<String> {
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
    // A table is named only when the line gave one (never `under []`, audit 03.04). A
    // "must match" or "is empty" message gives no fix: the field it is about is the
    // parser's to name, and guessing it from the line named the wrong one (audit 03.01).
    if let Some(missing) = quoted_after(first, "missing field ")
        && !field.is_empty()
    {
        return Some(format!("add {missing} = ... under [{field}]"));
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

#[cfg(test)]
mod tests {
    use crate::cause::{Cause, ConfigSource, Invocation};
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

    /// The Do of `e`, a catalog cause, as rendered.
    fn do_of(e: &Error) -> Option<String> {
        e.cause()
            .and_then(|(c, _)| c.do_text(&Invocation::default()))
    }

    #[test]
    fn unknown_field_names_file_line_and_field() {
        let (e, file) = load_err(
            "modes.allumata.payments = \"off\"",
            "modes.allumata.payments = \"off\"\nconfrm_env = true",
        );
        let want = format!("{file} at line 13, column 1: environments.prod.confrm_env ");
        assert!(e.to_string().starts_with(&want), "{e}");
    }

    #[test]
    fn unknown_field_fix_names_the_closest_field() {
        let (e, file) = load_err(
            "modes.allumata.payments = \"off\"",
            "modes.allumata.payments = \"off\"\nconfrm_env = true",
        );
        assert_eq!(
            do_of(&e),
            Some(format!(
                "rename environments.prod.confrm_env to confirm_env in {file} at line 13, column 1"
            ))
        );
    }

    #[test]
    fn unknown_variant_fix_names_the_closest_value() {
        let (e, _) = load_err("kind = \"secret\"", "kind = \"secert\"");
        assert!(
            do_of(&e).is_some_and(|d| d.starts_with("set kind = \"secret\" in ")),
            "{:?}",
            do_of(&e)
        );
    }

    #[test]
    fn undefined_environment_is_located_at_the_key() {
        let (e, file) = load_err("environments = [\"prod\"]", "environments = [\"prd\"]");
        let want = format!(
            "{file} at line 21, column 1: products.allumata.keys.OPENAI_API_KEY.environments \
             names environment prd"
        );
        assert!(e.to_string().starts_with(&want), "{e}");
    }

    #[test]
    fn undefined_environment_fix_names_the_closest_environment() {
        let (e, _) = load_err("environments = [\"prod\"]", "environments = [\"prd\"]");
        assert!(
            do_of(&e).is_some_and(|d| d.starts_with(
                "change prd to prod in products.allumata.keys.OPENAI_API_KEY.environments"
            )),
            "{:?}",
            do_of(&e)
        );
    }

    #[test]
    fn missing_field_fix_names_the_field() {
        let (e, _) = load_err("kind = \"secret\"\n", "");
        assert!(
            do_of(&e)
                .is_some_and(|d| d.starts_with("add products.allumata.keys.OPENAI_API_KEY.kind")),
            "{:?}",
            do_of(&e)
        );
    }

    #[test]
    fn bad_key_name_names_its_line() {
        let (e, file) = load_err(
            "[products.allumata.keys.OPENAI_API_KEY]",
            "[products.allumata.keys.openai]",
        );
        assert!(
            e.to_string().starts_with(&format!(
                "{file} at line 19, column 25: products.allumata.keys.openai must be"
            )),
            "{e}"
        );
    }

    #[test]
    fn located_error_never_shows_the_offending_line() {
        let (e, _) = load_err("kind = \"secret\"", "kind = \"secert\"");
        assert!(!e.to_string().contains("secert"), "{e}");
    }

    /// 03.01: a manifest's refusal names the manifest, and no file line.
    #[test]
    fn a_manifest_refusal_names_the_manifest() {
        let text = std::fs::read_to_string("tests/fixtures/secrets.toml")
            .unwrap()
            .replacen("kind = \"secret\"", "kind = \"secert\"", 1);
        let e = crate::config::parse_at(
            &text,
            crate::config::Source::ManifestIn {
                title: "opv · app",
                vault: "vlt",
            },
        )
        .unwrap_err();
        assert!(matches!(
            e.cause(),
            Some((Cause::ConfigInvalid { source: ConfigSource::Manifest { title, .. }, at: None, .. }, _))
                if title == "opv · app"
        ));
    }

    /// C1 (SR-1): a `.env` given as the configuration, with its value quoted or bare.
    const MARKER: &str = "sk-live-C1MARKERVALUE";

    fn env_file_error(text: &str) -> Error {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        std::fs::write(&path, text).unwrap();
        crate::config::load(&path).unwrap_err()
    }

    /// Everything a refusal shows: its message and its Do.
    fn shown(e: &Error) -> String {
        format!("{e} {:?}", do_of(e))
    }

    #[test]
    fn quoted_env_file_error_never_shows_the_value() {
        let e = env_file_error(&format!("OPENAI_API_KEY=\"{MARKER}\"\n"));
        assert!(!shown(&e).contains("C1MARKER"), "{}", shown(&e));
    }

    #[test]
    fn bare_env_file_error_never_shows_the_value() {
        let e = env_file_error(&format!("OPENAI_API_KEY={MARKER}\n"));
        assert!(!shown(&e).contains("C1MARKER"), "{}", shown(&e));
    }

    #[test]
    fn env_file_error_still_names_line_and_column() {
        let e = env_file_error(&format!("# comment\nOPENAI_API_KEY={MARKER}\n"));
        assert!(e.to_string().contains(" at line 2, column "), "{e}");
    }

    #[test]
    fn manifest_error_never_shows_the_value() {
        let text = format!("OPENAI_API_KEY=\"{MARKER}\"\n");
        let e = crate::config::parse_at(&text, crate::config::Source::Manifest("opv · app"))
            .unwrap_err();
        assert!(!shown(&e).contains("C1MARKER"), "{}", shown(&e));
    }

    #[test]
    fn mistyped_string_error_never_shows_the_value() {
        let text = std::fs::read_to_string("tests/fixtures/secrets.toml").unwrap();
        let bad = text.replacen(
            "[environments.staging]",
            &format!("stores = \"{MARKER}\"\n[environments.staging]"),
            1,
        );
        let e = crate::config::parse(&bad).unwrap_err();
        assert!(!shown(&e).contains("C1MARKER"), "{}", shown(&e));
    }

    #[test]
    fn env_file_error_json_envelope_never_shows_the_value() {
        let e = env_file_error(&format!("OPENAI_API_KEY=\"{MARKER}\"\n"));
        let v = crate::error::envelope(&e, &e.step("opv status prod", "opv status --help"));
        assert!(!v.to_string().contains("C1MARKER"), "{v}");
    }
}
