//! The `--json` contract (A1, A6): one document on stdout for every outcome.
//!
//! Every command writes its own document (rows, checks, the run report); [`finish`] gives
//! each the same frame, in this key order: `schema_version`, `ok`, `exit_code` (failures
//! only), the command's own fields, `next`, `do`, and on failure `error` (the catalog's
//! document, [`crate::error::document`]). A failure before the command wrote anything is
//! the bare envelope; a failure after it (findings, exit 8) keeps the rows and adds `error`. The
//! human text still goes to stderr, so a terminal user loses nothing.
//!
//! `schema_version` is 3 since 0.12.0: `next` is the typed object `{kind, actor,
//! command}` (a closed kind: `run`, `apply`, `enter_value`, `authorize`, `wait_ci`, `none`;
//! a closed actor: `assistant`, `person`, `ci`), so no client reads a free-text field to
//! decide an action. It changes only when a field changes meaning. Names only, never a
//! value (SR-1).

use serde_json::{Map, Value};

use crate::error::Error;

/// The version of every `--json` document's shape.
pub const SCHEMA_VERSION: u32 = 3;

/// The action a `next` names (schema 3): the closed set a client branches on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NextKind {
    Run,
    Apply,
    EnterValue,
    Authorize,
    WaitCi,
    None,
}

/// Who performs a `next` (schema 3): the closed set of actors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NextActor {
    Assistant,
    Person,
    Ci,
}

impl NextKind {
    /// The kind named by a serialised `next.kind`; `None` when it is not in the closed set.
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "run" => Some(Self::Run),
            "apply" => Some(Self::Apply),
            "enter_value" => Some(Self::EnterValue),
            "authorize" => Some(Self::Authorize),
            "wait_ci" => Some(Self::WaitCi),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

impl NextActor {
    /// The actor named by a serialised `next.actor` (or a finding's `owner`/`agent`);
    /// `None` when the caller must fall back to the person.
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "assistant" | "agent" => Some(Self::Assistant),
            "person" | "owner" => Some(Self::Person),
            "ci" => Some(Self::Ci),
            _ => None,
        }
    }
}

/// A `next` field as the typed object of schema 3. A command's own string `next` is a `run`
/// for the assistant; an object that already names a `kind` keeps it (the error document,
/// `ready`); an object that only names an `actor` takes the kind that actor runs; anything
/// else is `none` for the person, with no command.
fn typed_next(next: Value) -> Value {
    match next {
        Value::String(command) => typed(NextKind::Run, NextActor::Assistant, Some(command)),
        Value::Object(fields) => {
            let actor = fields
                .get("actor")
                .and_then(Value::as_str)
                .and_then(NextActor::from_name)
                .unwrap_or(NextActor::Person);
            let kind = fields
                .get("kind")
                .and_then(Value::as_str)
                .and_then(NextKind::from_name)
                .unwrap_or_else(|| kind_for(actor));
            let command = fields
                .get("command")
                .and_then(Value::as_str)
                .map(str::to_string);
            typed(kind, actor, command)
        }
        _ => typed(NextKind::None, NextActor::Person, None),
    }
}

/// The kind an actor runs when its `next` does not name one (the `ready` document): the
/// assistant runs the command, the person applies the change, CI runs it.
fn kind_for(actor: NextActor) -> NextKind {
    match actor {
        NextActor::Assistant | NextActor::Ci => NextKind::Run,
        NextActor::Person => NextKind::Apply,
    }
}

fn typed(kind: NextKind, actor: NextActor, command: Option<String>) -> Value {
    serde_json::json!({"kind": kind, "actor": actor, "command": command})
}

/// The command a `next` value names: the schema-3 object's `command`, or a bare string
/// (a command's own body before [`finish`] framed it).
pub fn command_of(next: &Value) -> Option<&str> {
    match next {
        Value::String(s) => Some(s.as_str()),
        Value::Object(m) => m.get("command").and_then(Value::as_str),
        _ => None,
    }
}

/// A `next` read back as the command it names, whether it is the schema-3 object or a bare
/// string (a command's own body before [`finish`] framed it). For clients that only show it.
pub fn next_command<'de, D>(d: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value: Value = serde::Deserialize::deserialize(d)?;
    Ok(command_of(&value).map(str::to_string))
}

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
    let mut next = typed_next(fields.shift_remove("next").unwrap_or(Value::Null));
    let mut action = fields.shift_remove("do").unwrap_or(Value::Null);
    let mut error = Value::Null;
    if let Some((exit_code, e)) = failure {
        out.insert("exit_code".into(), Value::from(exit_code));
        next = typed_next(e["next"].clone());
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
        let out = finish(br#"{"schema_version":2,"rows":[]}"#, Ok(()), false);
        assert_eq!(
            keys(&parse(&out)),
            ["schema_version", "ok", "rows", "next", "do"]
        );
    }

    #[test]
    fn success_keeps_the_commands_own_next() {
        let out = finish(
            br#"{"schema_version":3,"next":"opv sync prod"}"#,
            Ok(()),
            false,
        );
        assert_eq!(
            parse(&out)["next"],
            serde_json::json!({
                "kind": "run",
                "actor": "assistant",
                "command": "opv sync prod"
            })
        );
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
            br#"{"schema_version":2,"rows":[1]}"#,
            Err(&refused()),
            false,
        );
        assert_eq!(parse(&out)["rows"], serde_json::json!([1]));
    }

    #[test]
    fn failure_next_is_the_errors_step() {
        let e = refused();
        let out = finish(br#"{"schema_version":2,"next":null}"#, Err(&e), false);
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

    fn inv() -> crate::cause::Invocation {
        crate::cause::Invocation {
            origin: crate::cause::Origin::Cli,
            command: vec!["sync".into()],
            args: vec!["prod".into()],
            has_child: false,
        }
    }

    #[test]
    fn a_successful_documents_next_is_a_typed_run_for_the_assistant() {
        let out = finish(
            br#"{"schema_version":3,"next":"opv sync prod"}"#,
            Ok(()),
            false,
        );
        assert_eq!(
            parse(&out),
            serde_json::json!({
                "schema_version": 3,
                "ok": true,
                "next": {"kind": "run", "actor": "assistant", "command": "opv sync prod"},
                "do": null,
            })
        );
    }

    #[test]
    fn a_failing_documents_next_is_a_typed_person_handoff() {
        let e = refused();
        let inv = inv();
        let out = finish_with(br#"{"schema_version":3}"#, Err(&e), false, &inv, false);
        let error = crate::error::document(&e, &inv, false);
        assert_eq!(
            parse(&out),
            serde_json::json!({
                "schema_version": 3,
                "ok": false,
                "exit_code": e.exit_code(),
                "next": {
                    "kind": "apply",
                    "actor": "person",
                    "command": "opv sync prod --confirm prod",
                },
                "do": error["do"].clone(),
                "error": error,
            })
        );
    }

    #[test]
    fn a_document_without_a_next_is_a_typed_none_for_the_person() {
        let out = finish(br#"{"schema_version":3,"rows":[]}"#, Ok(()), false);
        assert_eq!(
            parse(&out),
            serde_json::json!({
                "schema_version": 3,
                "ok": true,
                "rows": [],
                "next": {"kind": "none", "actor": "person", "command": null},
                "do": null,
            })
        );
    }
}
