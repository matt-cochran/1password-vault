//! The parsed HTTP target configuration (design `http-target` §3.1).
//!
//! Plain types only: the load rules that check them against the pinned descriptor (§3.2)
//! live in the provider lane. Every field is documented with the configuration key it comes
//! from; `request` is the literal request template (a `toml` value decoded against the
//! request message), and the value field is described by [`ValueField`].

use std::collections::BTreeMap;

/// One environment target's `http` section (§3.1).
#[derive(Debug, Clone, PartialEq)]
pub struct HttpTarget {
    /// `http.host`: the lowercase ASCII hostname the item's `base_url` must agree with.
    pub host: String,
    /// `http.descriptor`: the path of the pinned `FileDescriptorSet`.
    pub descriptor: String,
    /// `http.descriptor_sha256`: the hash the descriptor file must have.
    pub descriptor_sha256: String,
    /// `http.names`: delivered env name → remote name. Every name is mapped exactly once.
    pub names: BTreeMap<String, String>,
    /// `http.list`: how a list call is made and its reply read.
    pub list: ListCall,
    /// `http.put`: how a put call is made and its reply read.
    pub put: PutCall,
}

/// `http.list` (§3.1): the list RPC, its literal request template and the reply's role
/// field paths.
#[derive(Debug, Clone, PartialEq)]
pub struct ListCall {
    /// `list.call`: `"pkg.Service/Method"`.
    pub call: String,
    /// `list.request`: the literal request object, decoded against the request message with
    /// unknown fields refused. A string leaf may be `{name}` or `{version}` only.
    pub request: toml::Value,
    /// `list.items`: the field path to the repeated entry message.
    pub items: String,
    /// `list.name`: the entry field path holding the remote name.
    pub name: String,
    /// `list.version`: the entry field path holding the version integer.
    pub version: String,
    /// `list.status`: the entry field path holding the status enum.
    pub status: String,
    /// `list.absent`: status values that mean the name is not present.
    pub absent: Vec<String>,
    /// `list.rejected`: status values that mean the name is present but unhealthy.
    pub rejected: Vec<String>,
}

/// `http.put` (§3.1): the put RPC, its request template, the one value field and the reply's
/// role fields (the list's roles apply).
#[derive(Debug, Clone, PartialEq)]
pub struct PutCall {
    /// `put.call`: `"pkg.Service/Method"`.
    pub call: String,
    /// `put.request`: the literal request object; the value field may not appear in it.
    pub request: toml::Value,
    /// `put.value`: the one singular field the secret value is written to.
    pub value: ValueField,
    /// `put.reply`: the field path to the written entry message.
    pub reply: String,
    /// `put.conflict`: gRPC status names that mean "changed since opv listed".
    pub conflict: Vec<String>,
}

/// `put.value` (§3.1, §3.2 rule 2): the field of the request message that receives the value,
/// with the field number and wire kind the descriptor must agree on.
#[derive(Debug, Clone, PartialEq)]
pub struct ValueField {
    /// `put.value.field`: the singular field's name.
    pub field: String,
    /// `put.value.number`: the field's number; a renumbered field is a load error.
    pub number: u32,
    /// `put.value.type`: the field's kind, `string` or `bytes`.
    pub kind: ValueKind,
}

/// The wire kind of the value field (§3.1): `put.value.type` is `"string"` or `"bytes"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueKind {
    String,
    Bytes,
}
