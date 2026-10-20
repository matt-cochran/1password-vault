//! Deliver-only infrastructure values (#206, `docs/design/deliver-only.md`): the core of a
//! value that infrastructure produces and the deploy job that produced it pipes to
//! `opv sync <env> --supply-stdin`. opv never writes such a value to 1Password.
//!
//! This module holds everything pure about a supply, in the order a supplying sync uses it:
//!
//! 1. [`read`]: the bounded stdin intake and the `opv.supply/1` parse (§3). Every value is a
//!    [`SecretValue`] registered with the scrubber as a secret the moment it is parsed; the
//!    raw buffer is wiped; serde's text, which quotes input, is never shown.
//! 2. [`admit`]: names, scope, opt-in, completeness and value shape (§2.3, §4.1), before
//!    the first 1Password read.
//! 3. [`refuse_stored`]: an infrastructure key with a 1Password field (§4.4).
//! 4. [`item_fields`]: the supplied values as synthetic item fields, so the key's rules
//!    run through the planner like any stored value (§4.2, §6.1).
//! 5. [`refusal`]: a failing rule, the target state (§4.3) and the producer's serial
//!    (§5.1), before the first target write.
//!
//! The sync wiring, the evidence lines and the receipts live in `sync.rs` and
//! `delivery.rs`. Nothing here writes 1Password or a target, and no error, `Debug` output
//! or refusal carries a supplied value or an input name that is not a declared key.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Read;
use std::path::PathBuf;
use std::time::Instant;

use serde::de::{self, DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use zeroize::Zeroizing;

use crate::cause::{
    Cause, EnvName, FieldRule, Guard, InputKind, KeyName, Location, ProductName, SupplyEntry,
    SupplyRefusal, SupplyRule, TargetName,
};
use crate::domain::ledger::Ledger;
use crate::domain::plan::{ItemField, KeyState, SyncPlan, TargetState};
use crate::domain::{Fleet, KeySpec, Kind, SecretValue, ValueSource, key_label, rules};
use crate::error::Error;

/// The schema id of a supply document.
pub const SCHEMA: &str = "opv.supply/1";
/// The most bytes a supply may hold (§3): opv reads one more, then refuses.
pub const TOTAL_LIMIT: usize = 1 << 20;
/// The most values a supply may name (§3).
pub const NAMES_LIMIT: usize = 256;
/// The fewest bytes a supplied value may have: the output guard masks secrets this long
/// (`crate::scrub::SECRET_MIN`), so every supplied value can be masked (S3).
pub const VALUE_MIN: usize = crate::scrub::SECRET_MIN;
/// The `path` of a supply problem: standard input, never a file.
const STDIN: &str = "<stdin>";

/// Whether `spec` declares `source = "infrastructure"` (§2.1): its value is supplied at
/// sync and never stored.
pub fn is_infrastructure(spec: &KeySpec) -> bool {
    spec.value_source == Some(ValueSource::Infrastructure)
}

/// One admitted supplied value. `Debug` prints the name only.
pub struct Supplied {
    pub product: String,
    pub key: String,
    pub value: SecretValue,
    /// The producer's serial of the document that supplied it (§5.1).
    pub serial: u64,
}

impl fmt::Debug for Supplied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Supplied")
            .field("product", &self.product)
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

/// An admitted supply (§4.1): every name a declared infrastructure key present in the
/// environment and in the run's scope, each once, and every infrastructure key in scope
/// supplied. `Debug` prints the environment and names only.
pub struct Supply {
    env: String,
    entries: BTreeMap<(String, String), Supplied>,
}

impl Supply {
    /// The environment the supply was admitted for.
    pub fn env(&self) -> &str {
        &self.env
    }

    /// The supplied value of `product/key`, if this run supplies it.
    pub fn get(&self, product: &str, key: &str) -> Option<&Supplied> {
        self.entries.get(&(product.to_string(), key.to_string()))
    }

    /// Every supplied `(product, key)`, sorted.
    pub fn names(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.keys().map(|(p, k)| (p.as_str(), k.as_str()))
    }

    /// How many values this run supplies.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the supply holds no value (never true for an admitted supply).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl fmt::Debug for Supply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<String> = self.names().map(|(p, k)| key_label(p, k)).collect();
        f.debug_struct("Supply")
            .field("env", &self.env)
            .field("names", &names)
            .finish()
    }
}

/// The bounds of one read (§3): bytes in total, names in total, and the run budget's end.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub total: usize,
    pub names: usize,
    pub deadline: Instant,
}

impl Limits {
    /// The design's limits (1 MiB, 256 names), ending at `deadline`.
    pub fn new(deadline: Instant) -> Self {
        Limits {
            total: TOTAL_LIMIT,
            names: NAMES_LIMIT,
            deadline,
        }
    }
}

/// The parsed, not yet admitted documents of a supply. Every string value is already a
/// [`SecretValue`] registered with the scrubber as a secret. `Debug` prints counts only:
/// a name here may be a value a mapping bug put where a name belongs.
pub struct RawSupply {
    documents: Vec<RawDocument>,
}

impl fmt::Debug for RawSupply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawSupply")
            .field("documents", &self.documents.len())
            .field(
                "entries",
                &self
                    .documents
                    .iter()
                    .map(|d| d.entries.len())
                    .sum::<usize>(),
            )
            .finish()
    }
}

/// One `opv.supply/1` document as parsed: its `env` (as given, possibly absent) and its
/// entries in order, duplicates kept.
struct RawDocument {
    env: Option<Zeroizing<String>>,
    serial: u64,
    entries: Vec<RawEntry>,
}

struct RawEntry {
    name: Zeroizing<String>,
    value: RawValue,
}

enum RawValue {
    Text(SecretValue),
    /// `null`, a number, a boolean, an object or an array.
    NotAString,
}

// --- intake (§3) ---------------------------------------------------------------------------

/// A supply stream problem (`input_invalid`) at `field` (`standard input`, `document 2`).
fn stream(field: impl Into<String>, at: Option<Location>, rule: SupplyRule) -> Error {
    Cause::InputInvalid {
        path: PathBuf::from(STDIN),
        kind: InputKind::Supply,
        at,
        field: field.into(),
        rule: FieldRule::Supply { supply: rule },
    }
    .into()
}

fn document(n: usize) -> String {
    format!("document {n}")
}

/// Read and parse a supply from `input` (§3): refused before a byte is read when
/// `stdin_is_terminal`; at most `limits.total` bytes (one more is read to tell), ending
/// within `limits.deadline`; one or more `opv.supply/1` documents back to back, at most
/// `limits.names` values in all. Each string value is registered with the scrubber as a
/// secret as it is parsed. Problems are `input_invalid` with positions only.
pub fn read(
    input: &mut dyn Read,
    stdin_is_terminal: bool,
    limits: &Limits,
) -> Result<RawSupply, Error> {
    if stdin_is_terminal {
        return Err(stream("standard input", None, SupplyRule::StdinIsTerminal));
    }
    let buf = read_bounded(input, limits)?;
    parse(&buf, limits)
}

/// The whole stream, wiped on drop, or the problem: over `limits.total` bytes, past the
/// deadline, or unreadable.
fn read_bounded(input: &mut dyn Read, limits: &Limits) -> Result<Zeroizing<Vec<u8>>, Error> {
    let too_large = || {
        stream(
            "standard input",
            None,
            SupplyRule::TooLarge {
                limit: limits.total as u64,
            },
        )
    };
    let timeout = || stream("standard input", None, SupplyRule::Timeout);
    // Allocated once, so growing it never leaves an unwiped copy behind.
    let mut buf = Zeroizing::new(Vec::with_capacity(limits.total + 1));
    let mut chunk = Zeroizing::new([0u8; 8192]);
    loop {
        if Instant::now() >= limits.deadline {
            return Err(timeout());
        }
        let room = limits.total + 1 - buf.len();
        let want = room.min(chunk.len());
        match input.read(&mut chunk[..want]) {
            Ok(0) => return Ok(buf),
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > limits.total {
                    return Err(too_large());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(timeout());
            }
            Err(e) => {
                return Err(Cause::InputUnreadable {
                    path: PathBuf::from(STDIN),
                    kind: InputKind::Supply,
                    io: e.kind().into(),
                }
                .into());
            }
        }
    }
}

/// A reader of opv's standard input that gives up at `deadline` (S12): a producer that
/// never closes its output ends the read with `TimedOut`, which [`read`] reports as
/// `Timeout`, instead of blocking until the job's own timeout. A background thread does
/// the blocking reads; every chunk it hands over is wiped on drop.
pub fn stdin_until(deadline: Instant) -> impl Read {
    until(std::io::stdin(), deadline)
}

/// [`stdin_until`] over any reader (tests use a reader that never ends).
pub fn until<R: Read + Send + 'static>(inner: R, deadline: Instant) -> DeadlineReader {
    let (tx, rx) = std::sync::mpsc::sync_channel::<std::io::Result<Zeroizing<Vec<u8>>>>(4);
    std::thread::spawn(move || {
        let mut inner = inner;
        loop {
            let mut chunk = Zeroizing::new(vec![0u8; 8192]);
            let sent = match inner.read(&mut chunk) {
                Ok(0) => tx.send(Ok(Zeroizing::new(Vec::new()))).map(|_| true),
                Ok(n) => {
                    chunk.truncate(n);
                    tx.send(Ok(chunk)).map(|_| false)
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => tx.send(Err(e)).map(|_| true),
            };
            if !matches!(sent, Ok(false)) {
                return;
            }
        }
    });
    DeadlineReader {
        rx,
        deadline,
        pending: Zeroizing::new(Vec::new()),
        at: 0,
        done: false,
    }
}

/// See [`until`]. `Debug` prints nothing of what passed through.
pub struct DeadlineReader {
    rx: std::sync::mpsc::Receiver<std::io::Result<Zeroizing<Vec<u8>>>>,
    deadline: Instant,
    pending: Zeroizing<Vec<u8>>,
    at: usize,
    done: bool,
}

impl fmt::Debug for DeadlineReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeadlineReader").finish_non_exhaustive()
    }
}

impl Read for DeadlineReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.at == self.pending.len() {
            if self.done {
                return Ok(0);
            }
            let left = self.deadline.saturating_duration_since(Instant::now());
            match self.rx.recv_timeout(left) {
                Ok(Ok(chunk)) if chunk.is_empty() => {
                    self.done = true;
                    return Ok(0);
                }
                Ok(Ok(chunk)) => {
                    self.pending = chunk;
                    self.at = 0;
                }
                Ok(Err(e)) => return Err(e),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    return Err(std::io::ErrorKind::TimedOut.into());
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    self.done = true;
                    return Ok(0);
                }
            }
        }
        let n = out.len().min(self.pending.len() - self.at);
        out[..n].copy_from_slice(&self.pending[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

/// The documents of `buf`, back to back. serde's error text quotes input, so only its
/// position and category are used.
fn parse(buf: &[u8], limits: &Limits) -> Result<RawSupply, Error> {
    let mut documents: Vec<RawDocument> = Vec::new();
    let mut names = 0usize;
    let mut de = serde_json::Deserializer::from_slice(buf).into_iter::<Parsed>();
    for item in &mut de {
        let n = documents.len() + 1;
        let parsed = item.map_err(|e| {
            let at = Location {
                line: u32::try_from(e.line()).unwrap_or(u32::MAX),
                col: u32::try_from(e.column()).unwrap_or(u32::MAX),
            };
            match e.classify() {
                // Valid JSON, but not an object: not a supply document.
                serde_json::error::Category::Data => {
                    stream(document(n), Some(at), SupplyRule::WrongSchema)
                }
                _ => stream(
                    document(n),
                    Some(at),
                    SupplyRule::NotJson {
                        line: at.line,
                        col: at.col,
                    },
                ),
            }
        })?;
        let doc = parsed
            .into_document()
            .map_err(|rule| stream(document(n), None, rule))?;
        names += doc.entries.len();
        if names > limits.names {
            return Err(stream(
                "standard input",
                None,
                SupplyRule::TooManyNames {
                    limit: limits.names as u64,
                },
            ));
        }
        documents.push(doc);
    }
    if documents.is_empty() {
        return Err(stream("standard input", None, SupplyRule::NoDocuments));
    }
    Ok(RawSupply { documents })
}

/// One document as the visitor saw it: every field it found, and the first problem (in
/// field order) that makes it no `opv.supply/1` document. The visitor never fails on a
/// value's type, so serde never builds a message quoting one.
#[derive(Default)]
struct Parsed {
    schema: Option<bool>,
    env: Option<Zeroizing<String>>,
    serial: Option<Option<u64>>,
    values: Option<Option<Vec<RawEntry>>>,
    unknown: bool,
}

impl Parsed {
    fn into_document(self) -> Result<RawDocument, SupplyRule> {
        if self.unknown {
            return Err(SupplyRule::UnknownField);
        }
        if self.schema != Some(true) {
            return Err(SupplyRule::WrongSchema);
        }
        let Some(Some(serial)) = self.serial else {
            return Err(SupplyRule::MissingSerial);
        };
        let entries = match self.values {
            Some(Some(entries)) if !entries.is_empty() => entries,
            _ => return Err(SupplyRule::NoValues),
        };
        Ok(RawDocument {
            env: self.env,
            serial,
            entries,
        })
    }
}

impl<'de> de::Deserialize<'de> for Parsed {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_map(DocVisitor)
    }
}

struct DocVisitor;

impl<'de> Visitor<'de> for DocVisitor {
    type Value = Parsed;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an opv.supply/1 document")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Parsed, A::Error> {
        let mut p = Parsed::default();
        while let Some(Name(field)) = map.next_key::<Name>()? {
            match field.as_str() {
                "schema" if p.schema.is_none() => {
                    let s = map.next_value::<Scalar>()?;
                    p.schema = Some(matches!(&s, Scalar::Str(v) if v.as_str() == SCHEMA));
                }
                "env" if p.env.is_none() => {
                    p.env = match map.next_value::<Scalar>()? {
                        Scalar::Str(v) => Some(v),
                        _ => Some(Zeroizing::new(String::new())),
                    };
                }
                "serial" if p.serial.is_none() => {
                    p.serial = Some(match map.next_value::<Scalar>()? {
                        Scalar::U64(n) => Some(n),
                        _ => None,
                    });
                }
                "values" if p.values.is_none() => {
                    p.values = Some(map.next_value::<Values>()?.0);
                }
                // An unknown field, or a known one twice (serde would keep the last).
                _ => {
                    map.next_value::<IgnoredAny>()?;
                    p.unknown = true;
                }
            }
        }
        Ok(p)
    }
}

/// An object key, wiped on drop: a mapping bug can put a value where a name belongs.
struct Name(Zeroizing<String>);

impl<'de> de::Deserialize<'de> for Name {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = Name;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a name")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Name, E> {
                Ok(Name(Zeroizing::new(v.to_owned())))
            }
        }
        d.deserialize_str(V)
    }
}

/// A JSON value seen only for its shape: a string (wiped on drop), a non-negative whole
/// number, or anything else (consumed, never kept).
enum Scalar {
    Str(Zeroizing<String>),
    U64(u64),
    Other,
}

impl<'de> de::Deserialize<'de> for Scalar {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(ScalarVisitor)
    }
}

struct ScalarVisitor;

impl<'de> Visitor<'de> for ScalarVisitor {
    type Value = Scalar;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Scalar, E> {
        Ok(Scalar::Str(Zeroizing::new(v.to_owned())))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Scalar, E> {
        Ok(Scalar::U64(v))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Scalar, E> {
        Ok(u64::try_from(v).map_or(Scalar::Other, Scalar::U64))
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Scalar, E> {
        Ok(Scalar::Other)
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Scalar, E> {
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

/// `values`: an object read entry by entry, so a name given twice is kept twice (serde's
/// own map keeps the last silently). `None` when `values` is not an object.
struct Values(Option<Vec<RawEntry>>);

impl<'de> de::Deserialize<'de> for Values {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(ValuesVisitor)
    }
}

struct ValuesVisitor;

impl<'de> Visitor<'de> for ValuesVisitor {
    type Value = Values;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an object of supplied values")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Values, A::Error> {
        let mut entries = Vec::new();
        while let Some(Name(name)) = map.next_key::<Name>()? {
            let value = map.next_value_seed(ValueSeed)?;
            entries.push(RawEntry { name, value });
        }
        Ok(Values(Some(entries)))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Values, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(Values(None))
    }
    fn visit_str<E: de::Error>(self, _: &str) -> Result<Values, E> {
        Ok(Values(None))
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Values, E> {
        Ok(Values(None))
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Values, E> {
        Ok(Values(None))
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Values, E> {
        Ok(Values(None))
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Values, E> {
        Ok(Values(None))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Values, E> {
        Ok(Values(None))
    }
}

/// One supplied value: a string becomes a [`SecretValue`] and is registered with the
/// scrubber as a secret right here, before anything else can fail; any other JSON value is
/// consumed and reported as [`RawValue::NotAString`].
struct ValueSeed;

impl<'de> DeserializeSeed<'de> for ValueSeed {
    type Value = RawValue;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<RawValue, D::Error> {
        d.deserialize_any(ValueVisitor)
    }
}

struct ValueVisitor;

impl<'de> Visitor<'de> for ValueVisitor {
    type Value = RawValue;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a supplied value")
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<RawValue, E> {
        crate::scrub::register_secret(v);
        Ok(RawValue::Text(SecretValue::new(v.to_owned())))
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<RawValue, E> {
        Ok(RawValue::NotAString)
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<RawValue, E> {
        Ok(RawValue::NotAString)
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<RawValue, E> {
        Ok(RawValue::NotAString)
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<RawValue, E> {
        Ok(RawValue::NotAString)
    }
    fn visit_unit<E: de::Error>(self) -> Result<RawValue, E> {
        Ok(RawValue::NotAString)
    }
    fn visit_none<E: de::Error>(self) -> Result<RawValue, E> {
        Ok(RawValue::NotAString)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<RawValue, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(RawValue::NotAString)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<RawValue, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(RawValue::NotAString)
    }
}

// --- admission (§2.3, §4.1) ------------------------------------------------------------------

/// What a supplying run covers (§2.3): its environment, the targets it selected (resolved
/// by the caller: `--target`, or every target of the environment), its `--product`, and
/// the keys its `--rotate` names.
#[derive(Debug, Clone, Copy)]
pub struct Scope<'a> {
    pub env: &'a str,
    pub targets: &'a [String],
    pub product: Option<&'a str>,
    pub rotate: &'a BTreeSet<(String, String)>,
}

/// A refusal of the supply for `env` (`policy_refused`, guard `supply_refused`).
fn refused(env: &str, entry: SupplyEntry, reason: SupplyRefusal) -> Error {
    Cause::Guard {
        guard: Guard::SupplyRefused {
            env: EnvName::new(env),
            entry,
            reason,
        },
    }
    .into()
}

fn named(product: &str, key: &str) -> SupplyEntry {
    SupplyEntry::Named {
        product: ProductName::new(product),
        key: KeyName::new(key),
    }
}

fn position(document: usize, index: usize) -> SupplyEntry {
    SupplyEntry::Position {
        document: u32::try_from(document).unwrap_or(u32::MAX),
        index: u32::try_from(index).unwrap_or(u32::MAX),
    }
}

/// Whether `spec` of `product` is present in `env_name` (§2.3): listed, not `except`ed,
/// not skipped by a mode, not refused by `refuse_in`.
fn present(fleet: &Fleet, env_name: &str, product: &str, spec: &KeySpec) -> bool {
    fleet.environments.get(env_name).is_some_and(|env| {
        rules::applies(spec, env_name, env, product) && !rules::refused_in(spec, env_name)
    })
}

/// Whether target `target` of `env_name` binds `product/key` (§2.3): it delivers the
/// product and its roles do not leave the key out (as `delivery::bindings` decides).
fn binds(fleet: &Fleet, env_name: &str, target: &str, product: &str, spec: &KeySpec) -> bool {
    if !fleet.delivers(env_name, target, product) {
        return false;
    }
    let served = fleet
        .environments
        .get(env_name)
        .and_then(|e| e.targets.get(target))
        .and_then(|t| t.roles.as_deref());
    match (&spec.roles, served) {
        (Some(roles), Some(served)) => roles.iter().any(|r| served.contains(r)),
        _ => true,
    }
}

/// Whether `product/key` is in the run's scope (§2.3): present, of the selected product,
/// and bound by at least one selected target.
fn in_scope(fleet: &Fleet, scope: &Scope<'_>, product: &str, spec: &KeySpec) -> bool {
    present(fleet, scope.env, product, spec)
        && scope.product.is_none_or(|p| p == product)
        && scope
            .targets
            .iter()
            .any(|t| binds(fleet, scope.env, t, product, spec))
}

/// Every declared infrastructure key, as `(product, key, spec)`, sorted.
fn infrastructure_keys(fleet: &Fleet) -> Vec<(&str, &str, &KeySpec)> {
    fleet
        .products
        .iter()
        .flat_map(|(p, prod)| {
            prod.keys
                .iter()
                .filter(|(_, s)| is_infrastructure(s))
                .map(move |(k, s)| (p.as_str(), k.as_str(), s))
        })
        .collect()
}

/// The declared key a supplied name names in canonical `<product>/<KEY>` form, if any.
fn declared<'f>(fleet: &'f Fleet, name: &str) -> Option<(&'f str, &'f str, &'f KeySpec)> {
    let (p, k) = name.split_once('/')?;
    let (product, prod) = fleet.products.get_key_value(p)?;
    let (key, spec) = prod.keys.get_key_value(k)?;
    Some((product.as_str(), key.as_str(), spec))
}

/// The infrastructure key a mis-written name most likely meant (§3, S11): the one whose
/// bare `KEY` or rendered target name it is, else the closest label by edit distance.
/// Only a declared label is ever returned; the name itself is never echoed.
fn closest(fleet: &Fleet, env_name: &str, name: &str) -> Option<String> {
    let keys = infrastructure_keys(fleet);
    let targets: Vec<&crate::domain::Target> = fleet
        .environments
        .get(env_name)
        .map(|e| e.targets.values().collect())
        .unwrap_or_default();
    let by_form: Vec<String> = keys
        .iter()
        .filter(|(p, k, _)| *k == name || targets.iter().any(|t| t.config.env_name(p, k) == name))
        .map(|(p, k, _)| key_label(p, k))
        .collect();
    if let [one] = by_form.as_slice() {
        return Some(one.clone());
    }
    let labels: Vec<String> = keys.iter().map(|(p, k, _)| key_label(p, k)).collect();
    crate::app::suggest::closest(name, labels.iter().map(String::as_str)).map(str::to_string)
}

/// Why a supplied string is no usable value (§3), checked in place without a copy.
fn unusable(value: &SecretValue) -> Option<SupplyRefusal> {
    let v = value.expose();
    if v.is_empty() {
        Some(SupplyRefusal::Empty)
    } else if v.contains('\0') {
        Some(SupplyRefusal::NotAString)
    } else if crate::domain::health::is_placeholder(v) {
        Some(SupplyRefusal::Placeholder)
    } else if v.len() < VALUE_MIN {
        Some(SupplyRefusal::TooShort)
    } else {
        None
    }
}

/// Admit `raw` for `scope` (§2.3, §4.1): pure, before any 1Password read. The first problem
/// wins, in document then entry order: a document produced for another environment; per
/// entry, a name that is not a declared key (by position, offering the closest
/// infrastructure key), a key that is not an infrastructure key, not present in the
/// environment, outside the scope, supplied twice, or whose value is unusable. Then a
/// `--rotate` of an infrastructure key this run does not supply, then every infrastructure
/// key in scope left unsupplied (S2).
pub fn admit(fleet: &Fleet, scope: &Scope<'_>, raw: RawSupply) -> Result<Supply, Error> {
    fleet.environment(scope.env)?;
    let env = scope.env;
    let mut entries: BTreeMap<(String, String), Supplied> = BTreeMap::new();
    for (d, doc) in raw.documents.into_iter().enumerate() {
        let d = d + 1;
        if doc.env.as_ref().map(|e| e.as_str()) != Some(env) {
            let document_env = doc
                .env
                .as_ref()
                .filter(|e| fleet.environments.contains_key(e.as_str()))
                .map(|e| EnvName::new(e.as_str()));
            // Entries count from 1, as everywhere else: the document's first.
            return Err(refused(
                env,
                position(d, 1),
                SupplyRefusal::WrongEnvironment { document_env },
            ));
        }
        for (i, entry) in doc.entries.into_iter().enumerate() {
            let Some((product, key, spec)) = declared(fleet, &entry.name) else {
                return Err(refused(
                    env,
                    position(d, i + 1),
                    SupplyRefusal::Undeclared {
                        closest: closest(fleet, env, &entry.name),
                    },
                ));
            };
            let at = || named(product, key);
            if !is_infrastructure(spec) {
                return Err(refused(env, at(), SupplyRefusal::NotOptedIn));
            }
            if !present(fleet, env, product, spec) {
                return Err(refused(env, at(), SupplyRefusal::NotInEnvironment));
            }
            if !in_scope(fleet, scope, product, spec) {
                return Err(refused(
                    env,
                    at(),
                    SupplyRefusal::OutOfScope {
                        targets: scope.targets.iter().map(TargetName::new).collect(),
                        product: scope.product.map(ProductName::new),
                    },
                ));
            }
            let pair = (product.to_string(), key.to_string());
            if entries.contains_key(&pair) {
                return Err(refused(env, at(), SupplyRefusal::Duplicate));
            }
            let value = match entry.value {
                RawValue::NotAString => {
                    return Err(refused(env, at(), SupplyRefusal::NotAString));
                }
                RawValue::Text(v) => v,
            };
            if let Some(reason) = unusable(&value) {
                return Err(refused(env, at(), reason));
            }
            entries.insert(
                pair,
                Supplied {
                    product: product.to_string(),
                    key: key.to_string(),
                    value,
                    serial: doc.serial,
                },
            );
        }
    }
    let keys = infrastructure_keys(fleet);
    for (p, k) in scope.rotate {
        let infra = keys.iter().any(|(kp, kk, _)| kp == p && kk == k);
        if infra && !entries.contains_key(&(p.clone(), k.clone())) {
            return Err(refused(env, named(p, k), SupplyRefusal::RotateWithoutValue));
        }
    }
    let missing: Vec<(&str, &str)> = keys
        .iter()
        .filter(|(p, _, spec)| in_scope(fleet, scope, p, spec))
        .filter(|(p, k, _)| !entries.contains_key(&(p.to_string(), k.to_string())))
        .map(|(p, k, _)| (*p, *k))
        .collect();
    if let Some((p, k)) = missing.first() {
        return Err(refused(
            env,
            named(p, k),
            SupplyRefusal::NotSupplied {
                keys: missing.iter().map(|(p, k)| key_label(p, k)).collect(),
            },
        ));
    }
    Ok(Supply {
        env: env.to_string(),
        entries,
    })
}

// --- 1Password and the planner (§4.4, §6.1) --------------------------------------------------

/// Refuse a 1Password field of an infrastructure key in `env`'s read (§4.4), supplied or
/// not: two sources of truth would let a person edit 1Password and wrongly believe the
/// target changed. `read` is the environment's item fields (`tidy::read`).
pub fn refuse_stored(fleet: &Fleet, env: &str, read: &[ItemField]) -> Result<(), Error> {
    for field in read {
        let Some(spec) = fleet
            .products
            .get(&field.section)
            .and_then(|p| p.keys.get(&field.label))
        else {
            continue;
        };
        if is_infrastructure(spec) {
            return Err(refused(
                env,
                named(&field.section, &field.label),
                SupplyRefusal::Stored {
                    boundary: fleet.boundary_of(&field.section).to_string(),
                },
            ));
        }
    }
    Ok(())
}

/// The supplied values as item fields (§6.1), appended to the environment's read so the
/// planner runs each key's rules (`transform`, `ensure_prefix`, the target's own check)
/// exactly as for a stored value. Each is a concealed field of the key's kind.
pub fn item_fields(fleet: &Fleet, supply: &Supply) -> Vec<ItemField> {
    supply
        .entries
        .values()
        .filter_map(|s| {
            let spec = fleet.products.get(&s.product)?.keys.get(&s.key)?;
            Some(ItemField {
                section: s.product.clone(),
                label: s.key.clone(),
                kind: spec.kind,
                value: SecretValue::new(s.value.expose().to_owned()),
                concealed: spec.kind == Kind::Secret,
            })
        })
        .collect()
}

/// The refusal of a planned supplying sync on one target, or `None` (§4.2, §4.3, §5.1),
/// before the first target write. `plan` was built with [`item_fields`] appended,
/// `ledgers` are the target's placement ledgers, `rotate` the run's `--rotate` keys, and
/// `name_of(product, key)` the target's store name of a key (the ledger's index).
///
/// First a supplied value failing its rule (`RuleFailed`). Then, per supplied name the
/// target delivers, in name order: when the ledger records a supplied serial, a lower
/// serial is `Stale` and an equal one with another value `SerialReused` (an equal one with
/// the same value at the recorded version is idempotent); then the target state: a name
/// the target lists without a supplied line is `Unproven`, an immutable one holding
/// another value `ImmutableDiffers`, and an immutable one at another version `Unproven`.
/// `--rotate` overrides every target-state and serial refusal.
pub fn refusal(
    plan: &SyncPlan,
    supply: &Supply,
    ledgers: &[Ledger],
    rotate: &BTreeSet<(String, String)>,
    name_of: &dyn Fn(&str, &str) -> String,
) -> Option<Error> {
    let env = supply.env();
    let supplied_rows = || {
        plan.rows
            .iter()
            .filter(|r| supply.get(&r.product, &r.key).is_some())
    };
    for row in supplied_rows() {
        if let KeyState::RuleFailed(rule, _) = &row.state {
            return Some(refused(
                env,
                named(&row.product, &row.key),
                SupplyRefusal::RuleFailed {
                    rule: rule.to_string(),
                },
            ));
        }
    }
    for row in supplied_rows() {
        let (p, k) = (row.product.as_str(), row.key.as_str());
        let Some(s) = supply.get(p, k) else {
            continue;
        };
        if row.target == TargetState::NotDelivered {
            continue;
        }
        let pair = (p.to_string(), k.to_string());
        let rotated = rotate.contains(&pair);
        let refuse = |reason| Some(refused(env, named(p, k), reason));
        if rotated {
            continue;
        }
        let name = name_of(p, k);
        let recorded = ledgers.iter().find_map(|l| l.supplied(&name));
        // §5.1: the producer's serial against the one recorded with the target's value.
        if let Some((_, serial)) = recorded {
            if s.serial < serial {
                return refuse(SupplyRefusal::Stale {
                    recorded: serial,
                    supplied: s.serial,
                });
            }
            if s.serial == serial {
                match row.target {
                    TargetState::Present => continue,
                    TargetState::WouldChange => {
                        return refuse(SupplyRefusal::SerialReused { serial });
                    }
                    _ => {}
                }
            }
        }
        // §4.3: one rule for every infrastructure key (S7). The planner holds an immutable
        // key the target lists and the run does not rotate.
        let immutable = plan.held_immutable.contains(&pair);
        match (row.target, recorded) {
            (TargetState::Absent | TargetState::NotDelivered, _) => {}
            (_, None) => return refuse(SupplyRefusal::Unproven),
            (TargetState::Present, Some(_)) => {}
            (TargetState::WouldChange, Some(_)) if immutable => {
                return refuse(SupplyRefusal::ImmutableDiffers);
            }
            (TargetState::Unknown, Some(_)) if immutable => {
                return refuse(SupplyRefusal::Unproven);
            }
            (TargetState::WouldChange | TargetState::Unknown, Some(_)) => {}
            // Only a row without a supplied value has these states; a supplied row never.
            (TargetState::AsSupplied | TargetState::Unrecorded, Some(_)) => {}
        }
    }
    None
}

#[cfg(test)]
#[path = "deliver_only_tests.rs"]
mod tests;
