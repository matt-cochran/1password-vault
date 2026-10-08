//! Owner-opted-in literal settings import. Never executes or expands shell code.
use crate::domain::SecretValue;
use crate::error::Error;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

fn refused() -> Error {
    Error::Config("[SETUP-IMPORT] This settings file is not a supported literal .env file. Nothing was imported. opv never executes shell commands or expands variables; use quoted literal assignments or fill the missing setting privately in 1Password.".into())
}

pub fn parse(input: &str) -> Result<BTreeMap<String, SecretValue>, Error> {
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
        let (key, tail) = rest.split_once('=').ok_or_else(refused)?;
        let key = key.trim();
        if key.is_empty()
            || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            || key.chars().next().is_some_and(|c| c.is_ascii_digit())
        {
            return Err(refused());
        }
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
                    return Err(refused());
                }
                if quote == '"' && c == '\\' {
                    let next = rest.chars().next().ok_or_else(refused)?;
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
                return Err(refused());
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
                return Err(refused());
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
                return Err(refused());
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
            return Err(refused());
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
    fn supports_comments_crlf_and_escaped_double_quotes() {
        let values = parse("# comment\r\nexport TOKEN=\"a\\\"b\\$c\" # note\r\n").unwrap();
        assert_eq!(values["TOKEN"].expose(), "a\"b$c");
    }
}
