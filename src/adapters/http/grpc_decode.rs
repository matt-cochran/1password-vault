//! gRPC-Web reply decoding for the HTTP target (design `http-target` §5.1).
//!
//! The decoder requires the binary gRPC-Web content types, refuses text and compressed
//! frames, reads the gRPC status and message from trailers-only headers *or* from a `0x80`
//! body trailer frame, and decodes `0x00` message frames through the pinned descriptor.
//! Reply fields are read afterwards by dotted path ([`read_role`]); nothing is converted to
//! JSON and no field outside the requested path is read.

use prost_reflect::{
    DescriptorPool, DynamicMessage, FieldDescriptor, Kind, ReflectMessage, Value,
};

use crate::adapters::http::descriptor;
use crate::runner_https::HttpsReply;

/// The required binary gRPC-Web content types (§5.1). Any other type, including
/// `application/grpc-web-text`, is refused.
const CONTENT_TYPE_WEB: &str = "application/grpc-web";
const CONTENT_TYPE_PROTO: &str = "application/grpc-web+proto";

/// The frame flags of the gRPC-Web wire format (§5.1): a length-prefixed message, a body
/// trailer, and the compression bit that this decoder refuses.
const FRAME_MESSAGE: u8 = 0x00;
const FRAME_TRAILER: u8 = 0x80;
const FRAME_COMPRESSED: u8 = 0x01;

/// A reply that could not be decoded: the content type, a frame or trailer, the method's
/// descriptor or a message did not match §5.1. The message names the rule and never a
/// reply byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyError {
    /// Why the reply was refused, without any reply value.
    pub message: String,
}

impl ReplyError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ReplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ReplyError {}

/// A decoded gRPC-Web reply (§5.1): the gRPC status code, the decoded output message only
/// when that status is zero, and the percent-decoded `grpc-message`.
#[derive(Clone)]
pub struct DecodedReply {
    /// The gRPC status code: the body trailer's when present, otherwise the header's.
    pub status: i32,
    /// The method's decoded output message; `None` for a non-zero status or an empty reply.
    pub message: Option<DynamicMessage>,
    /// The percent-decoded `grpc-message`, if the server sent one.
    pub grpc_message: Option<String>,
}

impl std::fmt::Debug for DecodedReply {
    /// The status and the presence of a message; never a decoded field, which may hold a
    /// value.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecodedReply")
            .field("status", &self.status)
            .field("has_message", &self.message.is_some())
            .field("grpc_message", &self.grpc_message)
            .finish()
    }
}

impl DecodedReply {
    /// The gRPC status code, named for callers thinking in gRPC terms.
    pub fn grpc_status(&self) -> i32 {
        self.status
    }

    /// The decoded output message, if this is a successful reply.
    pub fn decoded_message(&self) -> Option<&DynamicMessage> {
        self.message.as_ref()
    }
}

/// The kind of value a role field holds (§5.1, §3.1). `Message` is a singular entry and
/// `Messages` a repeated one; the list's `items` and the put reply's entry use these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleKind {
    String,
    Int,
    Enum,
    Message,
    Messages,
}

/// A value read from a role field (§5.1). `Int` covers every protobuf integer kind and is
/// reported as an `i64`; `Enum` is the enum value's name, not its number.
#[derive(Debug, Clone, PartialEq)]
pub enum RoleValue {
    String(String),
    Int(i64),
    Enum(String),
    Message(DynamicMessage),
    Messages(Vec<DynamicMessage>),
}

impl RoleValue {
    /// The string, when this is a [`RoleKind::String`] value.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    /// The integer, when this is a [`RoleKind::Int`] value.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(value) => Some(*value),
            _ => None,
        }
    }

    /// The enum value name, when this is a [`RoleKind::Enum`] value.
    pub fn as_enum(&self) -> Option<&str> {
        match self {
            Self::Enum(value) => Some(value),
            _ => None,
        }
    }

    /// The singular message, when this is a [`RoleKind::Message`] value.
    pub fn as_message(&self) -> Option<&DynamicMessage> {
        match self {
            Self::Message(value) => Some(value),
            _ => None,
        }
    }

    /// The repeated messages, when this is a [`RoleKind::Messages`] value.
    pub fn as_messages(&self) -> Option<&[DynamicMessage]> {
        match self {
            Self::Messages(value) => Some(value),
            _ => None,
        }
    }
}

/// Decode `reply` for `method` through `pool` (design `http-target` §5.1).
///
/// The content type must be `application/grpc-web` or `application/grpc-web+proto`.
/// `grpc-status` and `grpc-message` come from the `0x80` body trailer when present and
/// from the reply's headers otherwise (a trailers-only reply). `grpc-message` is
/// percent-decoded. A `0x00` message frame is decoded as the method's output message,
/// which is kept only when the status is zero.
pub fn decode_reply(
    pool: &DescriptorPool,
    method: &str,
    reply: &HttpsReply,
) -> Result<DecodedReply, ReplyError> {
    require_binary_content_type(reply.content_type.as_deref())?;

    let method = descriptor::method(pool, method)
        .ok_or_else(|| ReplyError::new("the method is not in the pinned descriptor"))?;
    let frames = decode_frames(reply.body.as_slice(), &method.output())?;

    let header_message = match reply.grpc_message.as_deref() {
        Some(message) => Some(percent_decode(message)?),
        None => None,
    };
    let status = frames
        .trailer
        .status
        .or(reply.grpc_status)
        .ok_or_else(|| ReplyError::new("the reply carries no grpc-status"))?;
    let grpc_message = frames.trailer.message.or(header_message);

    // The output message is kept only for a successful status; an error reply's body is
    // not exposed as a message.
    let message = if status == 0 { frames.message } else { None };
    Ok(DecodedReply {
        status,
        message,
        grpc_message,
    })
}

/// Require one of the two binary gRPC-Web content types; parameters such as a charset are
/// accepted, the text variant is named in the refusal (§5.1).
fn require_binary_content_type(content_type: Option<&str>) -> Result<(), ReplyError> {
    let essence = content_type
        .ok_or_else(|| ReplyError::new("the reply has no content type"))?
        .split(';')
        .next()
        .unwrap_or_default()
        .trim();
    if essence.eq_ignore_ascii_case(CONTENT_TYPE_WEB)
        || essence.eq_ignore_ascii_case(CONTENT_TYPE_PROTO)
    {
        return Ok(());
    }
    if essence.to_ascii_lowercase().starts_with("application/grpc-web-text") {
        return Err(ReplyError::new(
            "application/grpc-web-text is refused; only binary gRPC-Web is decoded",
        ));
    }
    Err(ReplyError::new(
        "the content type is not application/grpc-web or application/grpc-web+proto",
    ))
}

/// The frames of one reply: at most one message and the trailer's status and message.
struct Frames {
    message: Option<DynamicMessage>,
    trailer: Trailer,
}

#[derive(Default)]
struct Trailer {
    status: Option<i32>,
    message: Option<String>,
}

/// Walk the `0x00`/`0x80` frames of a gRPC-Web body (§5.1). A compressed frame (`0x01`)
/// is refused; a truncated frame, an unknown flag or a second message frame is malformed.
fn decode_frames(
    body: &[u8],
    output: &prost_reflect::MessageDescriptor,
) -> Result<Frames, ReplyError> {
    let mut at = 0usize;
    let mut message = None;
    let mut trailer = Trailer::default();

    while at < body.len() {
        let header = body
            .get(at..at + 5)
            .ok_or_else(|| ReplyError::new("a gRPC-Web frame header is truncated"))?;
        let flag = header[0];
        let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        at += 5;
        let payload = body
            .get(at..at + len)
            .ok_or_else(|| ReplyError::new("a gRPC-Web frame is truncated"))?;
        at += len;

        if flag & FRAME_COMPRESSED != 0 {
            return Err(ReplyError::new("a compressed gRPC-Web frame is refused"));
        }
        match flag {
            FRAME_MESSAGE => {
                if message.is_some() {
                    return Err(ReplyError::new(
                        "the reply has more than one gRPC-Web message frame",
                    ));
                }
                message = Some(
                    DynamicMessage::decode(output.clone(), payload)
                        .map_err(|_| ReplyError::new("a gRPC-Web message frame did not decode"))?,
                );
            }
            FRAME_TRAILER => trailer = decode_trailer(payload)?,
            _ => {
                return Err(ReplyError::new(format!(
                    "unknown gRPC-Web frame flag 0x{flag:02x}"
                )));
            }
        }
    }

    Ok(Frames { message, trailer })
}

/// Decode a `0x80` body trailer: `name:value\r\n` lines with no space after the colon
/// (§5.1). Only `grpc-status` and `grpc-message` are read; `grpc-message` is
/// percent-decoded.
fn decode_trailer(payload: &[u8]) -> Result<Trailer, ReplyError> {
    let text = std::str::from_utf8(payload)
        .map_err(|_| ReplyError::new("a gRPC-Web trailer is not UTF-8"))?;
    let mut trailer = Trailer::default();
    for line in text.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| ReplyError::new("a gRPC-Web trailer line has no colon"))?;
        if name.eq_ignore_ascii_case("grpc-status") {
            trailer.status = Some(
                value
                    .parse::<i32>()
                    .map_err(|_| ReplyError::new("the trailer grpc-status is not an integer"))?,
            );
        } else if name.eq_ignore_ascii_case("grpc-message") {
            trailer.message = Some(percent_decode(value)?);
        }
    }
    Ok(trailer)
}

/// Percent-decode a `grpc-message` value (§5.1). `+` is a literal plus, not a space, and an
/// invalid escape or UTF-8 is refused without echoing the message.
fn percent_decode(value: &str) -> Result<String, ReplyError> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0usize;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            let high = bytes
                .get(at + 1)
                .and_then(|byte| hex_digit(*byte))
                .ok_or_else(|| ReplyError::new("grpc-message has a truncated percent escape"))?;
            let low = bytes
                .get(at + 2)
                .and_then(|byte| hex_digit(*byte))
                .ok_or_else(|| ReplyError::new("grpc-message has a truncated percent escape"))?;
            out.push(high * 16 + low);
            at += 3;
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    String::from_utf8(out).map_err(|_| ReplyError::new("grpc-message is not valid UTF-8"))
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Read the field at dotted `path` from `msg` as `kind` (design `http-target` §5.1).
///
/// Every path segment must exist; the terminal field must have the requested type. An
/// absent integer or enum reads its proto3 default (`0` / the zero value's name), an absent
/// repeated message reads as empty. A wrong type is an error naming the path. No other
/// field of `msg` is read or copied.
pub fn read_role(
    msg: &DynamicMessage,
    path: &str,
    kind: RoleKind,
) -> Result<RoleValue, String> {
    let segments: Vec<&str> = path.split('.').collect();
    read_role_at(msg, &segments, path, kind)
}

fn read_role_at(
    msg: &DynamicMessage,
    segments: &[&str],
    path: &str,
    kind: RoleKind,
) -> Result<RoleValue, String> {
    let (head, rest) = segments
        .split_first()
        .ok_or_else(|| format!("{path}: the path is empty"))?;
    let field = msg
        .descriptor()
        .get_field_by_name(head)
        .ok_or_else(|| format!("{path}: `{head}` is not a field"))?;
    let value = msg.get_field(&field);

    if !rest.is_empty() {
        if field.is_list() || !matches!(field.kind(), Kind::Message(_)) {
            return Err(format!("{path}: `{head}` is not a singular message"));
        }
        return match value.as_ref() {
            Value::Message(inner) => read_role_at(inner, rest, path, kind),
            _ => Err(format!("{path}: `{head}` is not a message")),
        };
    }

    read_terminal(&field, value.as_ref(), path, kind)
}

fn read_terminal(
    field: &FieldDescriptor,
    value: &Value,
    path: &str,
    kind: RoleKind,
) -> Result<RoleValue, String> {
    match kind {
        RoleKind::String => {
            require_singular(field, path)?;
            match (field.kind(), value) {
                (Kind::String, Value::String(text)) => Ok(RoleValue::String(text.clone())),
                _ => Err(wrong_type(path, "a string")),
            }
        }
        RoleKind::Int => {
            require_singular(field, path)?;
            if !is_integer(field.kind()) {
                return Err(wrong_type(path, "an integer"));
            }
            match value {
                Value::I32(number) => Ok(RoleValue::Int(i64::from(*number))),
                Value::I64(number) => Ok(RoleValue::Int(*number)),
                Value::U32(number) => Ok(RoleValue::Int(i64::from(*number))),
                Value::U64(number) => i64::try_from(*number)
                    .map(RoleValue::Int)
                    .map_err(|_| format!("{path}: the integer does not fit in i64")),
                _ => Err(wrong_type(path, "an integer")),
            }
        }
        RoleKind::Enum => {
            require_singular(field, path)?;
            let Kind::Enum(enumeration) = field.kind() else {
                return Err(wrong_type(path, "an enum"));
            };
            match value {
                Value::EnumNumber(number) => enumeration
                    .get_value(*number)
                    .map(|value| RoleValue::Enum(value.name().to_string()))
                    .ok_or_else(|| format!("{path}: the enum number is not defined")),
                _ => Err(wrong_type(path, "an enum")),
            }
        }
        RoleKind::Message => {
            require_singular(field, path)?;
            if !matches!(field.kind(), Kind::Message(_)) {
                return Err(wrong_type(path, "a message"));
            }
            match value {
                Value::Message(message) => Ok(RoleValue::Message(message.clone())),
                _ => Err(wrong_type(path, "a message")),
            }
        }
        RoleKind::Messages => {
            if !field.is_list() || !matches!(field.kind(), Kind::Message(_)) {
                return Err(wrong_type(path, "a repeated message"));
            }
            match value {
                Value::List(values) => {
                    let mut messages = Vec::with_capacity(values.len());
                    for value in values {
                        match value {
                            Value::Message(message) => messages.push(message.clone()),
                            _ => return Err(wrong_type(path, "a repeated message")),
                        }
                    }
                    Ok(RoleValue::Messages(messages))
                }
                _ => Err(wrong_type(path, "a repeated message")),
            }
        }
    }
}

fn require_singular(field: &FieldDescriptor, path: &str) -> Result<(), String> {
    if field.is_list() || field.is_map() {
        Err(format!("{path}: the field is repeated, not singular"))
    } else {
        Ok(())
    }
}

fn is_integer(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::Int32
            | Kind::Int64
            | Kind::Uint32
            | Kind::Uint64
            | Kind::Sint32
            | Kind::Sint64
            | Kind::Fixed32
            | Kind::Fixed64
            | Kind::Sfixed32
            | Kind::Sfixed64
    )
}

fn wrong_type(path: &str, expected: &str) -> String {
    format!("{path}: the field is not {expected}")
}

#[cfg(test)]
#[path = "grpc_decode_tests.rs"]
mod grpc_decode_tests;
