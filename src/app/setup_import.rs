//! Owner-opted-in literal settings import. Never executes or expands shell code.
use crate::domain::SecretValue;
use crate::error::Error;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// The refusal with where it happened: the 1-based line and, once read, the key's name,
/// and what to change. Names and line numbers only, never a value (SR-1).
fn refused_at(input: &str, rest: &str, key: Option<&str>, why: &str) -> Error {
    let offset = input.len() - rest.len();
    let line = input[..offset].matches('\n').count() + 1;
    let place = match key {
        Some(k) => format!("line {line} ({k})"),
        None => format!("line {line}"),
    };
    Error::Config(
        format!(
            "This settings file is not a supported literal .env file: {place}: {why}. Nothing \
             was imported. opv never executes shell commands or expands variables; a value you \
             cannot write literally can be typed in 1Password instead."
        )
        .into(),
    )
}

/// What to do about an unquoted value opv will not take as a literal.
const QUOTE_IT: &str = "the value has a space or one of ' $ ` \\ ( ) < > ; & | \" outside quotes; \
     put it in single quotes (KEY='value') so it is taken literally";

/// The literal assignments of a dotenv file. A line opv cannot take literally refuses the
/// whole file, naming the line and key (never the value) and what to change.
pub fn parse(input: &str) -> Result<BTreeMap<String, SecretValue>, Error> {
    let at = |rest: &str, key: Option<&str>, why: &str| refused_at(input, rest, key, why);
    let mut rest = input;
    let mut values = BTreeMap::new();
    while !rest.is_empty() {
        rest = rest.trim_start_matches([' ', '\t', '\r', '\n']);
        if rest.is_empty() {
            break;
        }
        if rest.starts_with('#') {
            rest = rest.split_once('\n').map_or("", |(_, tail)| tail);
            continue;
        }
        if let Some(tail) = rest.strip_prefix("export ") {
            rest = tail.trim_start_matches([' ', '\t']);
        }
        let Some((key, tail)) = rest.split_once('=') else {
            return Err(at(rest, None, "a line that is not KEY=value"));
        };
        let key = key.trim();
        if key.is_empty()
            || key.contains('\n')
            || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            || key.chars().next().is_some_and(|c| c.is_ascii_digit())
        {
            let what = if key.contains('\n') {
                "a line that is not KEY=value"
            } else {
                "not a variable name (letters, digits and _, not starting with a digit)"
            };
            return Err(at(rest, None, what));
        }
        let line_start = rest;
        rest = tail.trim_start_matches([' ', '\t']);
        let mut value = Zeroizing::new(String::with_capacity(rest.len()));
        if let Some(quote) = rest.chars().next().filter(|c| *c == '\'' || *c == '"') {
            rest = &rest[1..];
            let mut closed = false;
            while let Some(c) = rest.chars().next() {
                rest = &rest[c.len_utf8()..];
                if c == quote {
                    closed = true;
                    break;
                }
                if quote == '"' && (c == '$' || c == '`') {
                    return Err(at(
                        line_start,
                        Some(key),
                        "$ or ` inside double quotes would expand in a shell; use single quotes \
                         (KEY='value') for a literal value, or escape it as \\$",
                    ));
                }
                if quote == '"' && c == '\\' {
                    let Some(next) = rest.chars().next() else {
                        return Err(at(line_start, Some(key), "the closing quote is missing"));
                    };
                    if matches!(next, '\\' | '"' | '$' | '`' | '\n') {
                        rest = &rest[next.len_utf8()..];
                        if next != '\n' {
                            value.push(next);
                        }
                    } else {
                        value.push(c);
                    }
                } else {
                    value.push(c);
                }
            }
            if !closed {
                return Err(at(line_start, Some(key), "the closing quote is missing"));
            }
            rest = rest.trim_start_matches([' ', '\t', '\r']);
            if rest.starts_with(';') {
                rest = &rest[1..];
                rest = rest.trim_start_matches([' ', '\t', '\r']);
            }
            if rest.starts_with('#') {
                rest = rest.split_once('\n').map_or("", |(_, tail)| tail);
            } else if rest.starts_with('\n') {
                rest = &rest[1..];
            } else if !rest.is_empty() {
                return Err(at(
                    line_start,
                    Some(key),
                    "something follows the closing quote; only a # comment may",
                ));
            }
        } else {
            let (line, tail) = rest.split_once('\n').unwrap_or((rest, ""));
            rest = tail;
            let literal = line.trim_end_matches('\r');
            let literal = literal
                .split_once(" #")
                .map_or(literal, |(v, _)| v)
                .trim()
                .trim_end_matches(';');
            if literal
                .chars()
                .any(|c| c.is_whitespace() || "'$`\\()<>;&|\"".contains(c))
            {
                return Err(at(line_start, Some(key), QUOTE_IT));
            }
            value.push_str(literal);
        }
        if values
            .insert(
                key.to_string(),
                SecretValue::new(std::mem::take(&mut *value)),
            )
            .is_some()
        {
            return Err(at(
                line_start,
                Some(key),
                "the key is set twice; keep one line",
            ));
        }
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_literal_multiline_encryption_and_special_characters() {
        let text = "export TF_ENCRYPTION='key_provider \"pbkdf2\" \"state\" {\n  passphrase = \"$literal;value\"\n}'\nAWS_ACCESS_KEY_ID=synthetic-id\n";
        let values = parse(text).unwrap();
        assert_eq!(
            values["TF_ENCRYPTION"].expose(),
            "key_provider \"pbkdf2\" \"state\" {\n  passphrase = \"$literal;value\"\n}"
        );
        assert_eq!(values["AWS_ACCESS_KEY_ID"].expose(), "synthetic-id");
    }
    #[test]
    fn shell_expressions_and_duplicates_are_refused_without_quoting_values() {
        for text in [
            "TOKEN=$(echo synthetic-private)",
            "TOKEN=\"$synthetic_private\"",
            "TOKEN=`echo synthetic-private`",
            "TOKEN=x\nTOKEN=synthetic-private",
            "TOKEN='synthetic-private' another-command",
        ] {
            let error = parse(text).err().unwrap();
            assert!(!error.to_string().contains("synthetic-private"));
        }
    }
    #[test]
    fn a_refusal_names_the_line_and_key() {
        let error =
            parse("A=1\nDATABASE_URL=postgres://h/db?a=1&b=synthetic-private\n").unwrap_err();
        assert!(
            error.to_string().contains("line 2 (DATABASE_URL)"),
            "{error}"
        );
    }
    #[test]
    fn a_refusal_never_holds_the_value() {
        let error =
            parse("A=1\nDATABASE_URL=postgres://h/db?a=1&b=synthetic-private\n").unwrap_err();
        assert!(!error.to_string().contains("synthetic-private"));
    }
    #[test]
    fn an_unquoted_special_value_is_told_to_use_single_quotes() {
        let error = parse("URL=a&b\n").unwrap_err();
        assert!(error.to_string().contains("single quotes"), "{error}");
    }
    #[test]
    fn an_invalid_name_names_its_line() {
        let error = parse("A=1\n\nbad-name=1\n").unwrap_err();
        assert!(error.to_string().contains("line 3"), "{error}");
    }
    #[test]
    fn a_repeated_key_is_named() {
        let error = parse("A=1\nA=2\n").unwrap_err();
        assert!(error.to_string().contains("line 2 (A)"), "{error}");
    }
    #[test]
    fn single_quotes_keep_an_ampersand_literally() {
        let values = parse("URL='postgres://h/db?a=1&b=2'\n").unwrap();
        assert_eq!(values["URL"].expose(), "postgres://h/db?a=1&b=2");
    }
    #[test]
    fn supports_comments_crlf_and_escaped_double_quotes() {
        let values = parse("# comment\r\nexport TOKEN=\"a\\\"b\\$c\" # note\r\n").unwrap();
        assert_eq!(values["TOKEN"].expose(), "a\"b$c");
    }
}
