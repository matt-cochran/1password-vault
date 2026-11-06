//! Provision templates (#262, `docs/design/owner-value-ingestion.md` §3.2, §4.5, §4.7, §5.3):
//! a set member whose value is a JSON document rendered from other members of its set and
//! from producer outputs held for the run only (intermediates, never stored).
//!
//! The contract tree is value-free: literals and references. A reference is a whole string
//! leaf, `"${product/KEY}"` (a member) or `"${producer.output}"` (an output); a literal never
//! contains `${`, so nothing is ever spliced into a string. The writer renders into a
//! [`Zeroizing`] buffer sized exactly once (no reallocation leaves a copy behind), escaping
//! each leaf straight from its [`SecretValue`]; no `serde_json::Value` ever holds a secret.
//! The output is compact JSON in declared order, the bytes of Python's
//! `json.dumps(doc, separators=(',', ':'), ensure_ascii=False)`.
//!
//! Reading a stored document back ([`extract`], [`fit`]) uses a small strict parser whose
//! strings are zeroized; it checks the document has the template's shape and yields each
//! reference leaf as a [`SecretValue`].

use std::collections::BTreeMap;

use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize as _, Zeroizing};

use super::provision::{KeyRef, MemberSource, ProvisionSet};
use super::secret::SecretValue;

/// The longest an intermediate (producer output) leaf may be in a stored document, in
/// bytes (§4.5: shape, not equality).
pub const MAX_INTERMEDIATE_BYTES: usize = 256;

/// The deepest nesting a stored document may have; deeper is not a template's shape.
const MAX_DEPTH: usize = 64;

/// A template member's contract tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    root: Node,
}

/// One node of a template tree. Tables keep their declared order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    /// A literal string; never contains `${`.
    String(String),
    Integer(i64),
    Bool(bool),
    /// A whole-leaf reference, rendered as a JSON string.
    Ref(Ref),
    Array(Vec<Node>),
    /// Entries in declared order.
    Table(Vec<(String, Node)>),
}

/// What a reference leaf names.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Ref {
    /// `${product/KEY}`: a member of the same set.
    Member(KeyRef),
    /// `${producer.output}`: an output of a producer, held for the run only.
    Output { producer: String, output: String },
}

impl std::fmt::Display for Ref {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ref::Member(k) => write!(f, "${{{k}}}"),
            Ref::Output { producer, output } => write!(f, "${{{producer}.{output}}}"),
        }
    }
}

/// Why a string leaf is neither a literal nor a whole reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafError {
    /// `${` inside a longer string (`"x${A}"`) or more than one reference: no interpolation.
    Interpolated,
    /// `"${…}"` naming neither `product/KEY` nor `producer.output`.
    Malformed,
}

/// A string leaf as written: a literal without `${`, or exactly one whole reference.
pub fn leaf(s: &str) -> Result<Node, LeafError> {
    if !s.contains("${") {
        return Ok(Node::String(s.to_string()));
    }
    let inner = s
        .strip_prefix("${")
        .and_then(|r| r.strip_suffix('}'))
        .filter(|i| !i.contains("${") && !i.contains('}'))
        .ok_or(LeafError::Interpolated)?;
    if inner.contains('/') {
        return KeyRef::parse(inner)
            .filter(|k| !k.key.contains('/') && !k.key.contains('.'))
            .map(|k| Node::Ref(Ref::Member(k)))
            .ok_or(LeafError::Malformed);
    }
    match inner.split_once('.') {
        Some((p, o)) if !p.is_empty() && !o.is_empty() && !o.contains('.') => {
            Ok(Node::Ref(Ref::Output {
                producer: p.to_string(),
                output: o.to_string(),
            }))
        }
        _ => Err(LeafError::Malformed),
    }
}

impl Template {
    pub fn new(root: Node) -> Self {
        Self { root }
    }

    pub fn root(&self) -> &Node {
        &self.root
    }

    /// Every reference leaf in declared order, repeats included.
    pub fn references(&self) -> Vec<&Ref> {
        fn walk<'a>(n: &'a Node, out: &mut Vec<&'a Ref>) {
            match n {
                Node::Ref(r) => out.push(r),
                Node::Array(items) => items.iter().for_each(|i| walk(i, out)),
                Node::Table(entries) => entries.iter().for_each(|(_, v)| walk(v, out)),
                Node::String(_) | Node::Integer(_) | Node::Bool(_) => {}
            }
        }
        let mut out = Vec::new();
        walk(&self.root, &mut out);
        out
    }

    /// Whether a leaf names `producer`'s `output`.
    pub fn uses_output(&self, producer: &str, output: &str) -> bool {
        self.references().into_iter().any(
            |r| matches!(r, Ref::Output { producer: p, output: o } if p == producer && o == output),
        )
    }

    /// Whether a leaf names an output of `producer`.
    pub fn uses_producer(&self, producer: &str) -> bool {
        self.references()
            .into_iter()
            .any(|r| matches!(r, Ref::Output { producer: p, .. } if p == producer))
    }
}

// ---- order ---------------------------------------------------------------------------

/// A template member that references itself, directly or through other templates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cycle {
    pub member: KeyRef,
}

/// The set's template members in an order where each comes after every template member it
/// references (render them in this order); [`Cycle`] when one references itself.
pub fn render_order(set: &ProvisionSet) -> Result<Vec<KeyRef>, Cycle> {
    let templates: BTreeMap<&KeyRef, &Template> = set
        .members
        .iter()
        .filter_map(|(k, s)| match s {
            MemberSource::Template(t) => Some((k, t)),
            _ => None,
        })
        .collect();
    #[derive(Clone, Copy, PartialEq)]
    enum Mark {
        Visiting,
        Done,
    }
    fn visit<'a>(
        k: &'a KeyRef,
        templates: &BTreeMap<&'a KeyRef, &'a Template>,
        marks: &mut BTreeMap<&'a KeyRef, Mark>,
        out: &mut Vec<KeyRef>,
    ) -> Result<(), Cycle> {
        match marks.get(k) {
            Some(Mark::Done) => return Ok(()),
            Some(Mark::Visiting) => return Err(Cycle { member: k.clone() }),
            None => {}
        }
        marks.insert(k, Mark::Visiting);
        for r in templates[k].references() {
            if let Ref::Member(m) = r
                && let Some((m, _)) = templates.get_key_value(m)
            {
                visit(m, templates, marks, out)?;
            }
        }
        marks.insert(k, Mark::Done);
        out.push(k.clone());
        Ok(())
    }
    let mut marks = BTreeMap::new();
    let mut out = Vec::new();
    for k in templates.keys() {
        visit(k, &templates, &mut marks, &mut out)?;
    }
    Ok(out)
}

// ---- writer --------------------------------------------------------------------------

/// Why a template did not render.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderError {
    /// No value for this reference in the run.
    Missing { reference: Ref },
    /// The rendered document did not read back to its sources (§5.3).
    RoundTrip(Mismatch),
}

trait Sink {
    fn put(&mut self, b: &[u8]);
}

struct Count(usize);

impl Sink for Count {
    fn put(&mut self, b: &[u8]) {
        self.0 += b.len();
    }
}

impl Sink for Vec<u8> {
    fn put(&mut self, b: &[u8]) {
        self.extend_from_slice(b);
    }
}

/// A JSON string as Python's `json.dumps(…, ensure_ascii=False)` writes it: `"` and `\`
/// escaped, `\b \f \n \r \t` short, other bytes below 0x20 as `\u00xx`, everything else raw.
fn write_str(s: &str, out: &mut impl Sink) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.put(b"\"");
    let b = s.as_bytes();
    let mut start = 0;
    for (i, &c) in b.iter().enumerate() {
        let short: &[u8] = match c {
            b'"' => b"\\\"",
            b'\\' => b"\\\\",
            b'\n' => b"\\n",
            b'\r' => b"\\r",
            b'\t' => b"\\t",
            0x08 => b"\\b",
            0x0c => b"\\f",
            0..=0x1f => b"",
            _ => continue,
        };
        out.put(&b[start..i]);
        if short.is_empty() {
            out.put(&[
                b'\\',
                b'u',
                b'0',
                b'0',
                HEX[usize::from(c >> 4)],
                HEX[usize::from(c & 0xf)],
            ]);
        } else {
            out.put(short);
        }
        start = i + 1;
    }
    out.put(&b[start..]);
    out.put(b"\"");
}

fn write_node<'v>(
    n: &Node,
    value: &impl Fn(&Ref) -> Option<&'v SecretValue>,
    out: &mut impl Sink,
) -> Result<(), RenderError> {
    match n {
        Node::String(s) => write_str(s, out),
        Node::Integer(i) => out.put(i.to_string().as_bytes()),
        Node::Bool(b) => out.put(if *b { b"true" } else { b"false" }),
        Node::Ref(r) => {
            let v = value(r).ok_or_else(|| RenderError::Missing {
                reference: r.clone(),
            })?;
            write_str(v.expose(), out);
        }
        Node::Array(items) => {
            out.put(b"[");
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.put(b",");
                }
                write_node(item, value, out)?;
            }
            out.put(b"]");
        }
        Node::Table(entries) => {
            out.put(b"{");
            for (i, (k, v)) in entries.iter().enumerate() {
                if i > 0 {
                    out.put(b",");
                }
                write_str(k, out);
                out.put(b":");
                write_node(v, value, out)?;
            }
            out.put(b"}");
        }
    }
    Ok(())
}

/// The template rendered as compact JSON in declared order, each reference leaf taken from
/// `value` (members and intermediates of this run), without the round-trip check.
pub fn write<'v>(
    t: &Template,
    value: impl Fn(&Ref) -> Option<&'v SecretValue>,
) -> Result<Zeroizing<Vec<u8>>, RenderError> {
    let mut count = Count(0);
    write_node(&t.root, &value, &mut count)?;
    let mut out = Zeroizing::new(Vec::with_capacity(count.0));
    write_node(&t.root, &value, &mut *out)?;
    debug_assert_eq!(out.len(), count.0, "sized exactly: no reallocation copy");
    Ok(out)
}

/// The template rendered ([`write`]) and read back: each reference leaf must equal its
/// source, and each intermediate must have a stored leaf's bounds (§5.3).
pub fn render<'v>(
    t: &Template,
    value: impl Fn(&Ref) -> Option<&'v SecretValue>,
) -> Result<Zeroizing<Vec<u8>>, RenderError> {
    let out = write(t, &value)?;
    round_trip(t, &out, &value).map_err(RenderError::RoundTrip)?;
    Ok(out)
}

/// `rendered` reads back as the template's shape with every reference leaf equal to its
/// source in `value`.
pub fn round_trip<'v>(
    t: &Template,
    rendered: &[u8],
    value: impl Fn(&Ref) -> Option<&'v SecretValue>,
) -> Result<(), Mismatch> {
    let leaves = extract(t, rendered)?;
    for r in t.references() {
        let same = match (value(r), leaves.get(r)) {
            (Some(a), Some(b)) => equal(a, b),
            _ => false,
        };
        if !same {
            return Err(Mismatch::LeafDiffers {
                reference: r.clone(),
            });
        }
    }
    Ok(())
}

fn equal(a: &SecretValue, b: &SecretValue) -> bool {
    a.expose().as_bytes().ct_eq(b.expose().as_bytes()).into()
}

// ---- reading a stored document -------------------------------------------------------

/// Why a stored document is not the template's (value-free: names a reference at most).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mismatch {
    /// Not one strict JSON document.
    NotJson,
    /// JSON, but not the template's tree: a missing or extra entry, another length, a
    /// literal that differs, a reference leaf that is not a string.
    NotItsShape,
    /// One reference appears more than once with different values.
    RepeatDisagrees { reference: Ref },
    /// An intermediate leaf is empty or longer than [`MAX_INTERMEDIATE_BYTES`].
    IntermediateBounds { reference: Ref },
    /// A member leaf differs from the stored member (or, for a rendering, a leaf from its
    /// source).
    LeafDiffers { reference: Ref },
}

/// The reference leaves of a stored document of a template's shape, one value per
/// reference.
#[derive(Debug, Default)]
pub struct Leaves(BTreeMap<Ref, SecretValue>);

impl Leaves {
    pub fn get(&self, r: &Ref) -> Option<&SecretValue> {
        self.0.get(r)
    }

    /// The leaf of member `k` (§4.7: a missing member is filled from it).
    pub fn member(&self, k: &KeyRef) -> Option<&SecretValue> {
        self.0.get(&Ref::Member(k.clone()))
    }

    /// The leaf of `producer`'s `output` (§4.7: a rerun's intermediate must equal it).
    pub fn output(&self, producer: &str, output: &str) -> Option<&SecretValue> {
        self.0.get(&Ref::Output {
            producer: producer.to_string(),
            output: output.to_string(),
        })
    }
}

/// The leaves of `stored` when it is a document of the template's shape: its literals equal
/// the template's, every reference leaf is a string, a repeated reference holds one value,
/// and every intermediate is non-empty and at most [`MAX_INTERMEDIATE_BYTES`]. Tables match
/// by key, in any order.
pub fn extract(t: &Template, stored: &[u8]) -> Result<Leaves, Mismatch> {
    let doc = Parser::document(stored)?;
    let mut leaves = Leaves::default();
    collect(&t.root, doc, &mut leaves)?;
    Ok(leaves)
}

/// [`extract`], and each member leaf equals the stored member `member` gives; a member it
/// gives no value for is not compared (it is missing, and filled from its leaf, §4.7).
/// `Ok` is the template's part of `complete` (§4.5).
pub fn fit<'v>(
    t: &Template,
    stored: &[u8],
    member: impl Fn(&KeyRef) -> Option<&'v SecretValue>,
) -> Result<Leaves, Mismatch> {
    let leaves = extract(t, stored)?;
    for (r, v) in &leaves.0 {
        if let Ref::Member(k) = r
            && let Some(m) = member(k)
            && !equal(m, v)
        {
            return Err(Mismatch::LeafDiffers {
                reference: r.clone(),
            });
        }
    }
    Ok(leaves)
}

/// A parsed JSON value; strings are zeroized on drop.
enum Json {
    Str(Zeroizing<String>),
    Int(i64),
    Bool(bool),
    Null,
    Arr(Vec<Json>),
    Obj(Vec<(Zeroizing<String>, Json)>),
}

fn collect(n: &Node, j: Json, leaves: &mut Leaves) -> Result<(), Mismatch> {
    match (n, j) {
        (Node::String(lit), Json::Str(s)) if *lit == *s => Ok(()),
        (Node::Integer(a), Json::Int(b)) if *a == b => Ok(()),
        (Node::Bool(a), Json::Bool(b)) if *a == b => Ok(()),
        (Node::Ref(r), Json::Str(mut s)) => {
            if let Ref::Output { .. } = r
                && (s.is_empty() || s.len() > MAX_INTERMEDIATE_BYTES)
            {
                return Err(Mismatch::IntermediateBounds {
                    reference: r.clone(),
                });
            }
            let v = SecretValue::new(std::mem::take(&mut *s));
            match leaves.0.get(r) {
                Some(seen) if !equal(seen, &v) => Err(Mismatch::RepeatDisagrees {
                    reference: r.clone(),
                }),
                Some(_) => Ok(()),
                None => {
                    leaves.0.insert(r.clone(), v);
                    Ok(())
                }
            }
        }
        (Node::Array(items), Json::Arr(js)) if items.len() == js.len() => items
            .iter()
            .zip(js)
            .try_for_each(|(n, j)| collect(n, j, leaves)),
        (Node::Table(entries), Json::Obj(mut js)) if entries.len() == js.len() => {
            for (k, n) in entries {
                let Some(i) = js.iter().position(|(jk, _)| jk.as_str() == k) else {
                    return Err(Mismatch::NotItsShape);
                };
                let (_, j) = js.swap_remove(i);
                collect(n, j, leaves)?;
            }
            Ok(())
        }
        _ => Err(Mismatch::NotItsShape),
    }
}

/// A strict RFC 8259 parser for one document: integers only (a fraction or exponent is not
/// a template's shape), duplicate keys refused, depth bounded.
struct Parser<'b> {
    b: &'b [u8],
    i: usize,
}

impl<'b> Parser<'b> {
    fn document(b: &'b [u8]) -> Result<Json, Mismatch> {
        let mut p = Parser { b, i: 0 };
        let v = p.value(0)?;
        p.ws();
        if p.i != b.len() {
            return Err(Mismatch::NotJson);
        }
        Ok(v)
    }

    fn ws(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.b.get(self.i) {
            self.i += 1;
        }
    }

    fn eat(&mut self, lit: &[u8]) -> bool {
        if self.b[self.i..].starts_with(lit) {
            self.i += lit.len();
            true
        } else {
            false
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, Mismatch> {
        if depth > MAX_DEPTH {
            return Err(Mismatch::NotItsShape);
        }
        self.ws();
        match self.b.get(self.i) {
            Some(b'{') => {
                self.i += 1;
                let mut entries: Vec<(Zeroizing<String>, Json)> = Vec::new();
                self.ws();
                if self.eat(b"}") {
                    return Ok(Json::Obj(entries));
                }
                loop {
                    self.ws();
                    let k = self.string()?;
                    if entries.iter().any(|(e, _)| e.as_str() == k.as_str()) {
                        return Err(Mismatch::NotItsShape);
                    }
                    self.ws();
                    if !self.eat(b":") {
                        return Err(Mismatch::NotJson);
                    }
                    let v = self.value(depth + 1)?;
                    entries.push((k, v));
                    self.ws();
                    if self.eat(b",") {
                        continue;
                    }
                    if self.eat(b"}") {
                        return Ok(Json::Obj(entries));
                    }
                    return Err(Mismatch::NotJson);
                }
            }
            Some(b'[') => {
                self.i += 1;
                let mut items = Vec::new();
                self.ws();
                if self.eat(b"]") {
                    return Ok(Json::Arr(items));
                }
                loop {
                    items.push(self.value(depth + 1)?);
                    self.ws();
                    if self.eat(b",") {
                        continue;
                    }
                    if self.eat(b"]") {
                        return Ok(Json::Arr(items));
                    }
                    return Err(Mismatch::NotJson);
                }
            }
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b't') if self.eat(b"true") => Ok(Json::Bool(true)),
            Some(b'f') if self.eat(b"false") => Ok(Json::Bool(false)),
            Some(b'n') if self.eat(b"null") => Ok(Json::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(Mismatch::NotJson),
        }
    }

    fn number(&mut self) -> Result<Json, Mismatch> {
        let start = self.i;
        self.eat(b"-");
        let digits = self.i;
        while let Some(b'0'..=b'9') = self.b.get(self.i) {
            self.i += 1;
        }
        let int = &self.b[digits..self.i];
        if int.is_empty() || (int.len() > 1 && int[0] == b'0') {
            return Err(Mismatch::NotJson);
        }
        if let Some(b'.' | b'e' | b'E') = self.b.get(self.i) {
            return Err(Mismatch::NotItsShape);
        }
        std::str::from_utf8(&self.b[start..self.i])
            .ok()
            .and_then(|s| s.parse().ok())
            .map(Json::Int)
            .ok_or(Mismatch::NotItsShape)
    }

    fn hex4(&mut self) -> Result<u32, Mismatch> {
        let h = self.b.get(self.i..self.i + 4).ok_or(Mismatch::NotJson)?;
        let v = std::str::from_utf8(h)
            .ok()
            .filter(|s| s.bytes().all(|c| c.is_ascii_hexdigit()))
            .and_then(|s| u32::from_str_radix(s, 16).ok())
            .ok_or(Mismatch::NotJson)?;
        self.i += 4;
        Ok(v)
    }

    /// A string at `self.i` (its opening quote), decoded into a buffer sized once.
    fn string(&mut self) -> Result<Zeroizing<String>, Mismatch> {
        if !self.eat(b"\"") {
            return Err(Mismatch::NotJson);
        }
        // The decoded string is never longer than its encoded form.
        let mut end = self.i;
        while end < self.b.len() && self.b[end] != b'"' {
            end += if self.b[end] == b'\\' { 2 } else { 1 };
        }
        let mut out = Zeroizing::new(Vec::with_capacity(end.saturating_sub(self.i)));
        loop {
            let Some(&c) = self.b.get(self.i) else {
                return Err(Mismatch::NotJson);
            };
            self.i += 1;
            match c {
                b'"' => break,
                0..=0x1f => return Err(Mismatch::NotJson),
                b'\\' => {
                    let Some(&e) = self.b.get(self.i) else {
                        return Err(Mismatch::NotJson);
                    };
                    self.i += 1;
                    let short = match e {
                        b'"' => b'"',
                        b'\\' => b'\\',
                        b'/' => b'/',
                        b'b' => 0x08,
                        b'f' => 0x0c,
                        b'n' => b'\n',
                        b'r' => b'\r',
                        b't' => b'\t',
                        b'u' => {
                            let mut cp = self.hex4()?;
                            if (0xd800..0xdc00).contains(&cp) {
                                if !self.eat(b"\\u") {
                                    return Err(Mismatch::NotJson);
                                }
                                let lo = self.hex4()?;
                                if !(0xdc00..0xe000).contains(&lo) {
                                    return Err(Mismatch::NotJson);
                                }
                                cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                            }
                            let ch = char::from_u32(cp).ok_or(Mismatch::NotJson)?;
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                            continue;
                        }
                        _ => return Err(Mismatch::NotJson),
                    };
                    out.push(short);
                }
                _ => out.push(c),
            }
        }
        match String::from_utf8(std::mem::take(&mut *out)) {
            Ok(s) => Ok(Zeroizing::new(s)),
            Err(e) => {
                e.into_bytes().zeroize();
                Err(Mismatch::NotJson)
            }
        }
    }
}

#[cfg(test)]
#[path = "provision_template_tests.rs"]
mod tests;
