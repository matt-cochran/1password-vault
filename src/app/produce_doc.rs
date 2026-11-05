//! The `opv.produce/1` admission parser (#253, `docs/design/owner-value-ingestion.md` §5.2).
//!
//! A producer writes one JSON object per line to stdout: notices while it works, then exactly
//! one terminal line, a `result` or an `error`. This module turns those lines into typed
//! [`Notice`]s and one [`Terminal`]; it never sees a process, only the bytes of a line. Every
//! refusal is `InputInvalid { kind: Produce, rule }` with a line number or an output position,
//! never serde's error text and never a producer's own string.
//!
//! Output values are [`SecretValue`]s registered with the scrubber as they are parsed, so the
//! output guard masks them even when the run's env says it holds no secret.
//!
//! The caller feeds complete lines (a trailing newline already removed) in order:
//!
//! ```ignore
//! let mut parser = Parser::new(context);
//! while let Some(line) = reader.next_line()? {
//!     if let Some(notice) = parser.feed(line.as_bytes())? {
//!         show(notice);
//!     }
//! }
//! let terminal = parser.finish()?;
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::PathBuf;

use serde::de::{self, DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use zeroize::Zeroizing;

use crate::cause::{Cause, FieldRule, InputKind, OpenUrlProblem, ProduceRule};
use crate::domain::SecretValue;
use crate::error::Error;

/// The only producer schema this opv admits.
pub const SCHEMA: &str = "opv.produce/1";
/// The most bytes a producer may print in all (§5.2).
pub const TOTAL_LIMIT: usize = 1 << 20;
/// The most bytes one stdout line may hold (§5.2).
pub const LINE_LIMIT: usize = 64 << 10;
/// The most bytes an `open_url` notice may hold (§5.2).
pub const URL_LIMIT: usize = 2048;
/// The most bytes one output value may hold (§5.2).
pub const VALUE_LIMIT: usize = 64 << 10;

/// What the caller knows before a producer runs: the run's `--env`, this run's nonce, the
/// declared outputs the set uses (in request order), and the producer's allowed `open_url`
/// hosts.
#[derive(Debug, Clone, Copy)]
pub struct Context<'a> {
    /// The environment a `result` must name.
    pub env: &'a str,
    /// The nonce a `result` must echo.
    pub nonce: &'a str,
    /// The declared outputs, each expected exactly once in the result.
    pub outputs: &'a [String],
    /// Hosts an `open_url` notice may name.
    pub open_url_hosts: &'a [String],
}

/// A notice from a line before the terminal one, already admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    /// The consent page to open: `https`, an allowed host, at most [`URL_LIMIT`] bytes, no
    /// userinfo. Without an opener the caller prints it.
    OpenUrl(String),
    /// The producer is waiting for something (for example, consent).
    Waiting,
}

/// The one terminal line.
#[derive(Debug)]
pub enum Terminal {
    /// A result whose outputs are exactly the declared ones, each once.
    Result(BTreeMap<String, SecretValue>),
    /// The producer reported this code (1 to 40 of `[a-z_]`); opv shows only it.
    Error(String),
}

/// An admitted producer exchange: its notices in order, and its one terminal line.
#[derive(Debug)]
pub struct Produced {
    notices: Vec<Notice>,
    terminal: Terminal,
}

impl Produced {
    /// The notices seen before the terminal line, in order.
    pub fn notices(&self) -> &[Notice] {
        &self.notices
    }

    /// The one terminal line.
    pub fn terminal(&self) -> &Terminal {
        &self.terminal
    }

    /// Split into notices and terminal line.
    pub fn into_parts(self) -> (Vec<Notice>, Terminal) {
        (self.notices, self.terminal)
    }
}

/// The incremental `opv.produce/1` parser: feed each complete stdout line and a notice comes
/// back as soon as its line is admitted, before the producer exits. [`finish`](Parser::finish)
/// gives the one terminal line.
pub struct Parser<'a> {
    context: Context<'a>,
    line: u32,
    total: usize,
    terminal: Option<Terminal>,
}

impl<'a> Parser<'a> {
    /// A parser for one producer run.
    pub fn new(context: Context<'a>) -> Self {
        Parser {
            context,
            line: 0,
            total: 0,
            terminal: None,
        }
    }

    /// Admit `line` (without its newline). Returns the notice it carried, if any.
    pub fn feed(&mut self, line: &[u8]) -> Result<Option<Notice>, Error> {
        let at = self.line.saturating_add(1);
        self.line = at;
        if self.terminal.is_some() {
            return Err(refuse(ProduceRule::ResultNotLast { line: at }));
        }
        if line.len() > LINE_LIMIT {
            return Err(refuse(ProduceRule::LineTooLong {
                line: at,
                limit: LINE_LIMIT as u64,
            }));
        }
        self.total = self.total.saturating_add(line.len().saturating_add(1));
        if self.total > TOTAL_LIMIT {
            return Err(refuse(ProduceRule::TooMuchOutput {
                limit: TOTAL_LIMIT as u64,
            }));
        }
        match classify(line, at, &self.context)? {
            Line::Notice(notice) => Ok(Some(notice)),
            Line::Terminal(terminal) => {
                self.terminal = Some(terminal);
                Ok(None)
            }
        }
    }

    /// The one terminal line, or `NoResult` when the producer printed none.
    pub fn finish(self) -> Result<Terminal, Error> {
        self.terminal.ok_or_else(|| refuse(ProduceRule::NoResult))
    }
}

/// Admit every line of `lines`, then the terminal line.
pub fn parse<'a, I, L>(lines: I, context: Context<'a>) -> Result<Produced, Error>
where
    I: IntoIterator<Item = L>,
    L: AsRef<[u8]>,
{
    let mut parser = Parser::new(context);
    let mut notices = Vec::new();
    for line in lines {
        if let Some(notice) = parser.feed(line.as_ref())? {
            notices.push(notice);
        }
    }
    let terminal = parser.finish()?;
    Ok(Produced { notices, terminal })
}

/// Admit every line of `buf`. One trailing newline ends the last line and is not a line of
/// its own; a further blank line is.
pub fn parse_bytes(buf: &[u8], context: Context<'_>) -> Result<Produced, Error> {
    let mut lines: Vec<&[u8]> = buf.split(|&b| b == b'\n').collect();
    if lines.last().is_some_and(|line| line.is_empty()) {
        lines.pop();
    }
    parse(lines, context)
}

/// One line's meaning once admitted.
enum Line {
    Notice(Notice),
    Terminal(Terminal),
}

/// An `InputInvalid { kind: Produce }` cause carrying no path, field or secret.
fn refuse(rule: ProduceRule) -> Error {
    Cause::InputInvalid {
        path: PathBuf::new(),
        kind: InputKind::Produce,
        at: None,
        field: "standard output".to_string(),
        rule: FieldRule::Produce { produce: rule },
    }
    .into()
}

/// One `open_url` notice's refusal reason, in precedence order: scheme, userinfo, host, then
/// the byte limit.
fn open_url_problem(url: &str, hosts: &[String]) -> Option<OpenUrlProblem> {
    let Some(after_scheme) = url.strip_prefix("https://") else {
        return Some(OpenUrlProblem::NotHttps);
    };
    let end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..end];
    if authority.contains('@') {
        return Some(OpenUrlProblem::Userinfo);
    }
    let host = match authority.strip_prefix('[') {
        Some(rest) => match rest.find(']') {
            Some(end) => &rest[..end],
            None => return Some(OpenUrlProblem::HostNotListed),
        },
        None => authority.split(':').next().unwrap_or(""),
    };
    if !hosts
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(host))
    {
        return Some(OpenUrlProblem::HostNotListed);
    }
    if url.len() > URL_LIMIT {
        return Some(OpenUrlProblem::TooLong {
            limit: URL_LIMIT as u64,
        });
    }
    None
}

/// `code` is 1 to 40 bytes of `[a-z_]` (the vocabulary the `error` line may report).
fn valid_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= 40
        && code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
}

fn classify(line: &[u8], at: u32, context: &Context<'_>) -> Result<Line, Error> {
    let raw: Raw =
        serde_json::from_slice(line).map_err(|_| refuse(ProduceRule::NotJson { line: at }))?;
    if raw.unknown {
        return Err(refuse(ProduceRule::UnknownField { line: at }));
    }
    if raw.schema != Some(true) {
        return Err(refuse(ProduceRule::WrongSchema { line: at }));
    }
    match text(&raw.kind) {
        Some("notice") => notice(raw, at, context),
        Some("result") => result(raw, at, context),
        Some("error") => error(raw, at),
        _ => Err(refuse(ProduceRule::WrongSchema { line: at })),
    }
}

fn notice(raw: Raw, at: u32, context: &Context<'_>) -> Result<Line, Error> {
    if raw.env.is_some() || raw.nonce.is_some() || raw.outputs_seen || raw.code.is_some() {
        return Err(refuse(ProduceRule::UnknownField { line: at }));
    }
    match (&raw.open_url, raw.waiting) {
        (Some(_), None) => {
            let url = text(&raw.open_url).unwrap_or("");
            match open_url_problem(url, context.open_url_hosts) {
                Some(why) => Err(refuse(ProduceRule::OpenUrlRefused { line: at, why })),
                None => Ok(Line::Notice(Notice::OpenUrl(url.to_string()))),
            }
        }
        (None, Some(true)) => Ok(Line::Notice(Notice::Waiting)),
        _ => Err(refuse(ProduceRule::WrongSchema { line: at })),
    }
}

fn result(raw: Raw, at: u32, context: &Context<'_>) -> Result<Line, Error> {
    if raw.open_url.is_some() || raw.waiting.is_some() || raw.code.is_some() {
        return Err(refuse(ProduceRule::UnknownField { line: at }));
    }
    if text(&raw.env) != Some(context.env) {
        return Err(refuse(ProduceRule::WrongEnvironment { line: at }));
    }
    if text(&raw.nonce) != Some(context.nonce) {
        return Err(refuse(ProduceRule::NonceMismatch { line: at }));
    }
    let outputs = raw.outputs.unwrap_or_default();
    let mut admitted: BTreeMap<String, SecretValue> = BTreeMap::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (i, RawOutput { name, value }) in outputs.into_iter().enumerate() {
        let position = u32::try_from(i + 1).unwrap_or(u32::MAX);
        let name = name.as_str();
        if !context.outputs.iter().any(|declared| declared == name) {
            return Err(refuse(ProduceRule::Undeclared { position }));
        }
        if !seen.insert(name.to_string()) {
            return Err(refuse(ProduceRule::Duplicate { position }));
        }
        match value {
            RawValue::Other => {
                return Err(refuse(ProduceRule::NotAString {
                    output: name.to_string(),
                }));
            }
            RawValue::Text(value) => {
                if value.expose().contains('\0') {
                    return Err(refuse(ProduceRule::NotAString {
                        output: name.to_string(),
                    }));
                }
                if value.expose().is_empty() {
                    return Err(refuse(ProduceRule::Empty {
                        output: name.to_string(),
                    }));
                }
                if value.expose().len() > VALUE_LIMIT {
                    return Err(refuse(ProduceRule::TooLarge {
                        output: name.to_string(),
                        limit: VALUE_LIMIT as u64,
                    }));
                }
                admitted.insert(name.to_string(), value);
            }
        }
    }
    let missing: Vec<String> = context
        .outputs
        .iter()
        .filter(|declared| !seen.contains(declared.as_str()))
        .cloned()
        .collect();
    if !missing.is_empty() {
        return Err(refuse(ProduceRule::Missing { names: missing }));
    }
    Ok(Line::Terminal(Terminal::Result(admitted)))
}

fn error(raw: Raw, at: u32) -> Result<Line, Error> {
    if raw.open_url.is_some()
        || raw.waiting.is_some()
        || raw.env.is_some()
        || raw.nonce.is_some()
        || raw.outputs_seen
    {
        return Err(refuse(ProduceRule::UnknownField { line: at }));
    }
    match text(&raw.code) {
        Some(code) if valid_code(code) => Ok(Line::Terminal(Terminal::Error(code.to_string()))),
        _ => Err(refuse(ProduceRule::ErrorCode { line: at })),
    }
}

fn text(field: &Option<RawText>) -> Option<&str> {
    field.as_ref().and_then(RawText::as_str)
}

fn text_of(scalar: Scalar) -> RawText {
    match scalar {
        Scalar::Str(value) => RawText::Text(value),
        Scalar::Bool(_) | Scalar::Other => RawText::Other,
    }
}

/// One parsed line, before admission. A field that is absent is `None`; a field that is
/// present but not the shape the schema wants is `Some(RawText::Other)`, so a repeat is still
/// caught as an unknown field.
#[derive(Default)]
struct Raw {
    schema: Option<bool>,
    kind: Option<RawText>,
    open_url: Option<RawText>,
    waiting: Option<bool>,
    env: Option<RawText>,
    nonce: Option<RawText>,
    outputs: Option<Vec<RawOutput>>,
    outputs_seen: bool,
    code: Option<RawText>,
    unknown: bool,
}

struct RawOutput {
    name: Zeroizing<String>,
    value: RawValue,
}

enum RawText {
    Text(Zeroizing<String>),
    Other,
}

impl RawText {
    fn as_str(&self) -> Option<&str> {
        match self {
            RawText::Text(value) => Some(value.as_str()),
            RawText::Other => None,
        }
    }
}

enum RawValue {
    Text(SecretValue),
    Other,
}

impl<'de> de::Deserialize<'de> for Raw {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(RawVisitor)
    }
}

struct RawVisitor;

impl<'de> Visitor<'de> for RawVisitor {
    type Value = Raw;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an opv.produce/1 line")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Raw, A::Error> {
        let mut raw = Raw::default();
        while let Some(Name(field)) = map.next_key::<Name>()? {
            match field.as_str() {
                "schema" if raw.schema.is_none() => {
                    let scalar = map.next_value::<Scalar>()?;
                    raw.schema = Some(matches!(&scalar, Scalar::Str(v) if v.as_str() == SCHEMA));
                }
                "kind" if raw.kind.is_none() => {
                    raw.kind = Some(text_of(map.next_value::<Scalar>()?));
                }
                "open_url" if raw.open_url.is_none() => {
                    raw.open_url = Some(text_of(map.next_value::<Scalar>()?));
                }
                "waiting" if raw.waiting.is_none() => {
                    raw.waiting = Some(matches!(map.next_value::<Scalar>()?, Scalar::Bool(true)));
                }
                "env" if raw.env.is_none() => {
                    raw.env = Some(text_of(map.next_value::<Scalar>()?));
                }
                "nonce" if raw.nonce.is_none() => {
                    raw.nonce = Some(text_of(map.next_value::<Scalar>()?));
                }
                "outputs" if !raw.outputs_seen => {
                    raw.outputs_seen = true;
                    raw.outputs = map.next_value::<Outputs>()?.0;
                }
                "code" if raw.code.is_none() => {
                    raw.code = Some(text_of(map.next_value::<Scalar>()?));
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                    raw.unknown = true;
                }
            }
        }
        Ok(raw)
    }
}

/// A JSON string member name, held zeroized.
struct Name(Zeroizing<String>);

impl<'de> de::Deserialize<'de> for Name {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct NameVisitor;

        impl Visitor<'_> for NameVisitor {
            type Value = Name;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a member name")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Name, E> {
                Ok(Name(Zeroizing::new(value.to_string())))
            }
        }

        deserializer.deserialize_str(NameVisitor)
    }
}

/// Any JSON value, remembered only as a string, a boolean, or "other".
enum Scalar {
    Str(Zeroizing<String>),
    Bool(bool),
    Other,
}

impl<'de> de::Deserialize<'de> for Scalar {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ScalarVisitor)
    }
}

struct ScalarVisitor;

impl<'de> Visitor<'de> for ScalarVisitor {
    type Value = Scalar;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Scalar, E> {
        Ok(Scalar::Str(Zeroizing::new(value.to_string())))
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Scalar, E> {
        Ok(Scalar::Bool(value))
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Scalar, E> {
        Ok(Scalar::Other)
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Scalar, E> {
        Ok(Scalar::Other)
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Scalar, E> {
        Ok(Scalar::Other)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Scalar, E> {
        Ok(Scalar::Other)
    }

    fn visit_none<E: de::Error>(self) -> Result<Scalar, E> {
        Ok(Scalar::Other)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Scalar, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(Scalar::Other)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Scalar, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(Scalar::Other)
    }
}

/// The `outputs` member: a `Vec` of pairs in document order, or `None` when it is not an
/// object.
struct Outputs(Option<Vec<RawOutput>>);

impl<'de> de::Deserialize<'de> for Outputs {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(OutputsVisitor)
    }
}

struct OutputsVisitor;

impl<'de> Visitor<'de> for OutputsVisitor {
    type Value = Outputs;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an object of outputs")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Outputs, A::Error> {
        let mut outputs = Vec::new();
        while let Some(Name(name)) = map.next_key::<Name>()? {
            let value = map.next_value_seed(ValueSeed)?;
            outputs.push(RawOutput { name, value });
        }
        Ok(Outputs(Some(outputs)))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Outputs, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(Outputs(None))
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<Outputs, E> {
        Ok(Outputs(None))
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Outputs, E> {
        Ok(Outputs(None))
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Outputs, E> {
        Ok(Outputs(None))
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Outputs, E> {
        Ok(Outputs(None))
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Outputs, E> {
        Ok(Outputs(None))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Outputs, E> {
        Ok(Outputs(None))
    }

    fn visit_none<E: de::Error>(self) -> Result<Outputs, E> {
        Ok(Outputs(None))
    }
}

/// One output value: a string, registered with the scrubber, or "other".
struct ValueSeed;

impl<'de> DeserializeSeed<'de> for ValueSeed {
    type Value = RawValue;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<RawValue, D::Error> {
        deserializer.deserialize_any(ValueVisitor)
    }
}

struct ValueVisitor;

impl<'de> Visitor<'de> for ValueVisitor {
    type Value = RawValue;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an output value")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<RawValue, E> {
        crate::scrub::register_secret(value);
        Ok(RawValue::Text(SecretValue::new(value.to_string())))
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<RawValue, E> {
        Ok(RawValue::Other)
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<RawValue, E> {
        Ok(RawValue::Other)
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<RawValue, E> {
        Ok(RawValue::Other)
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<RawValue, E> {
        Ok(RawValue::Other)
    }

    fn visit_unit<E: de::Error>(self) -> Result<RawValue, E> {
        Ok(RawValue::Other)
    }

    fn visit_none<E: de::Error>(self) -> Result<RawValue, E> {
        Ok(RawValue::Other)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<RawValue, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(RawValue::Other)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<RawValue, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(RawValue::Other)
    }
}

#[cfg(test)]
#[path = "produce_doc_tests.rs"]
mod tests;
