//! The `--json` contract (A1, A6): one document on stdout for every outcome.
//!
//! Every command writes its own document (rows, checks, the run report); [`finish`] gives
//! each the same frame, in this key order: `schema_version`, `ok`, `exit_code` (failures
//! only), the command's own fields, `next`, `do`, and on failure `error` (the catalog's
//! document, [`crate::error::document`]). A failure before the command wrote anything is
//! the bare envelope; a failure after it (findings, exit 8) keeps the rows and adds `error`. The
//! human text still goes to stderr, so a terminal user loses nothing.
//!
//! `schema_version` stays 1 while fields are only added; it changes only when a field
//! changes meaning. Names only, never a value (SR-1).

use serde_json::{Map, Value};

use crate::error::Error;

/// The version of every `--json` document's shape.
pub const SCHEMA_VERSION: u32 = 1;

/// The final stdout of a `--json` command: `body` is what the command wrote (one JSON
/// object, or nothing), `res` its result; a failure's `error` is rendered against the
/// process's invocation ([`finish_with`] names another). `raw` keeps a successful body
/// byte for byte (`config export`, whose document is the config values map itself, has no
/// frame).
pub fn finish(body: &[u8], res: Result<(), &Error>, raw: bool) -> Vec<u8> {
    finish_with(body, res, raw, &crate::error::invocation(), false)
}

/// [`finish`] with a failure's `error` rendered against `inv`, with the whole upstream
/// reply when `verbose` (§7.3).
pub fn finish_with(
    body: &[u8],
    res: Result<(), &Error>,
    raw: bool,
    inv: &crate::cause::Invocation,
    verbose: bool,
) -> Vec<u8> {
    let doc = serde_json::from_slice::<Value>(body).ok();
    let out = match (res, doc) {
        (Ok(()), _) if raw => return body.to_vec(),
        (Ok(()), Some(Value::Object(fields))) => frame(fields, None),
        // Not a JSON object: nothing to frame.
        (Ok(()), _) => return body.to_vec(),
        (Err(e), doc) => {
            let fields = match doc {
                Some(Value::Object(m)) if !raw => m,
                _ => Map::new(),
            };
            let error = crate::error::document(e, inv, verbose);
            frame(fields, Some((e.exit_code(), error)))
        }
    };
    let mut text = Value::Object(out).to_string();
    text.push('\n');
    text.into_bytes()
}

/// The frame around `fields` (see the module docs), with `failure` the exit code and the
/// `error` object.
fn frame(mut fields: Map<String, Value>, failure: Option<(i32, Value)>) -> Map<String, Value> {
    let mut out = Map::new();
    let version = fields
        .shift_remove("schema_version")
        .unwrap_or(Value::from(SCHEMA_VERSION));
    out.insert("schema_version".into(), version);
    fields.shift_remove("ok");
    out.insert("ok".into(), Value::Bool(failure.is_none()));
    let mut next = fields.shift_remove("next").unwrap_or(Value::Null);
    let mut action = fields.shift_remove("do").unwrap_or(Value::Null);
    let mut error = Value::Null;
    if let Some((exit_code, e)) = failure {
        out.insert("exit_code".into(), Value::from(exit_code));
        next = e["next"].clone();
        action = e["do"].clone();
        error = e;
    }
    fields.shift_remove("exit_code");
    fields.shift_remove("error");
    out.extend(fields);
    out.insert("next".into(), next);
    out.insert("do".into(), action);
    if !error.is_null() {
        out.insert("error".into(), error);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused() -> Error {
        crate::cause::Cause::NeedsConfirm {
            env: crate::cause::EnvName::new("prod"),
        }
        .into()
    }

    fn parse(b: &[u8]) -> Value {
        serde_json::from_slice(b).unwrap()
    }

    fn keys(v: &Value) -> Vec<String> {
        v.as_object().unwrap().keys().cloned().collect()
    }

    #[test]
    fn success_gains_ok_true_after_schema_version() {
        let out = finish(br#"{"schema_version":1,"rows":[]}"#, Ok(()), false);
        assert_eq!(
            keys(&parse(&out)),
            ["schema_version", "ok", "rows", "next", "do"]
        );
    }

    #[test]
    fn success_keeps_the_commands_own_next() {
        let out = finish(
            br#"{"schema_version":1,"next":"opv sync prod"}"#,
            Ok(()),
            false,
        );
        assert_eq!(parse(&out)["next"], "opv sync prod");
    }

    #[test]
    fn failure_without_a_document_is_the_bare_envelope() {
        let out = finish(b"", Err(&refused()), false);
        assert_eq!(
            keys(&parse(&out)),
            ["schema_version", "ok", "exit_code", "next", "do", "error"]
        );
    }

    #[test]
    fn failure_after_a_document_keeps_its_rows() {
        let out = finish(
            br#"{"schema_version":1,"rows":[1]}"#,
            Err(&refused()),
            false,
        );
        assert_eq!(parse(&out)["rows"], serde_json::json!([1]));
    }

    #[test]
    fn failure_next_is_the_errors_step() {
        let e = refused();
        let out = finish(br#"{"schema_version":1,"next":null}"#, Err(&e), false);
        let want = crate::error::document(&e, &crate::error::invocation(), false);
        assert_eq!(parse(&out)["next"], want["next"]);
    }

    #[test]
    fn raw_success_is_unchanged() {
        let body = b"{\n  \"LOG_LEVEL\": \"info\"\n}\n";
        assert_eq!(finish(body, Ok(()), true), body.to_vec());
    }

    #[test]
    fn raw_failure_is_the_envelope_only() {
        let out = finish(br#"{"LOG_LEVEL":"info"}"#, Err(&refused()), true);
        assert!(parse(&out).get("LOG_LEVEL").is_none());
    }
}
