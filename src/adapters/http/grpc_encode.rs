//! The gRPC-Web request codec (design `http-target` §5.1, §3.2).
//!
//! [`encode_request`] turns one `put` call's request template and its secret value into the
//! framed gRPC-Web request body. The template is decoded against the pinned request message
//! with unknown fields refused (§3.2 rule 3), encoded, and the value field is then written
//! directly from the [`SecretValue`]: its tag, its length and its bytes. The value never
//! enters a `toml::Value`, JSON, a `String` or a non-zeroizing buffer (T9), and a refusal
//! names the field, never the value.
//!
//! The wire order matters: prost encodes a message's set fields in ascending field-number
//! order, so the value field is written at its own number rather than after the whole
//! template. That reproduces the field order a normal client sends (the recorded
//! `tests/fixtures/https/zonetico/request-save.bin`); it does not send the value through any
//! intermediate message.

use prost::Message;
use prost_reflect::{
    DescriptorPool, DynamicMessage, FieldDescriptor, Kind, MessageDescriptor, MethodDescriptor,
    Value,
};
use zeroize::Zeroizing;

use super::model::{ValueField, ValueKind};
use crate::domain::secret::SecretValue;

/// Encode one `put` request (design `http-target` §5.1):
///
/// 1. resolve `method` in the pinned `pool`;
/// 2. check `value_field` against the request descriptor (number and kind, §3.2 rule 2);
/// 3. substitute the whole-leaf `{name}`/`{version}` placeholders of `template`, decode it
///    into a `DynamicMessage` with unknown fields (and the value field) refused;
/// 4. encode the message and the value field (tag, varint length, `value` bytes) into a
///    `Zeroizing` buffer, in field-number order;
/// 5. frame it as `0x00` plus the 4-byte big-endian message length.
///
/// The error names the file's field or rule, never a value.
pub fn encode_request(
    pool: &DescriptorPool,
    method: &MethodDescriptor,
    template: &toml::Value,
    name: &str,
    version: i64,
    value_field: &ValueField,
    value: &SecretValue,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let method = resolve_method(pool, method)?;
    let request = method.input();
    let value_desc = check_value_field(&request, value_field)?;
    let table = match template {
        toml::Value::Table(table) => table,
        _ => return Err(String::from("the request template must be an object")),
    };
    let message = decode_template(&request, table, value_field, name, version)?;
    let body = encode_body(&request, &message, &value_desc, value)?;
    Ok(frame(body))
}

/// The pinned pool's own descriptor for `method`, so a method that is not in the pinned
/// descriptor is refused before its fields are read.
fn resolve_method(
    pool: &DescriptorPool,
    method: &MethodDescriptor,
) -> Result<MethodDescriptor, String> {
    let full = format!("{}/{}", method.parent_service().full_name(), method.name());
    super::descriptor::method(pool, &full)
        .ok_or_else(|| format!("the method `{full}` is not in the pinned descriptor"))
}

/// The request message's field `value_field.field`, refusing a field that is absent,
/// repeated, renumbered or of a different kind (§3.2 rule 2).
fn check_value_field(
    request: &MessageDescriptor,
    value_field: &ValueField,
) -> Result<FieldDescriptor, String> {
    let field = request
        .get_field_by_name(&value_field.field)
        .ok_or_else(|| {
            format!(
                "the value field `{}` is not in the request message",
                value_field.field
            )
        })?;
    if field.is_list() || field.is_map() {
        return Err(format!(
            "the value field `{}` must be singular",
            value_field.field
        ));
    }
    if field.number() != value_field.number {
        return Err(format!(
            "the value field `{}` has number {} in the descriptor",
            value_field.field,
            field.number()
        ));
    }
    let configured = match value_field.kind {
        ValueKind::String => Kind::String,
        ValueKind::Bytes => Kind::Bytes,
    };
    if field.kind() != configured {
        return Err(format!(
            "the value field `{}` is not the configured string or bytes field",
            value_field.field
        ));
    }
    Ok(field)
}

/// Decode the literal `table` against `request`, substituting `{name}`/`{version}`. Every
/// key must name a known field and none may name the value field (§3.2 rule 3).
fn decode_template(
    request: &MessageDescriptor,
    table: &toml::Table,
    value_field: &ValueField,
    name: &str,
    version: i64,
) -> Result<DynamicMessage, String> {
    let mut message = DynamicMessage::new(request.clone());
    for (key, leaf) in table {
        let field = request
            .get_field_by_name(key)
            .ok_or_else(|| format!("the request template sets unknown field `{key}`"))?;
        if field.name() == value_field.field || field.number() == value_field.number {
            return Err(format!(
                "the request template may not set the value field `{}`",
                field.name()
            ));
        }
        let value = decode_leaf(&field, leaf, value_field, name, version)?;
        message.set_field(&field, value);
    }
    Ok(message)
}

/// Decode one leaf, an array for a repeated field and a single value otherwise.
fn decode_leaf(
    field: &FieldDescriptor,
    leaf: &toml::Value,
    value_field: &ValueField,
    name: &str,
    version: i64,
) -> Result<Value, String> {
    if field.is_list() {
        let items = match leaf {
            toml::Value::Array(items) => items,
            _ => return Err(wrong_type(field)),
        };
        let mut values = Vec::with_capacity(items.len());
        for item in items {
            values.push(decode_scalar(field, item, value_field, name, version)?);
        }
        return Ok(Value::List(values));
    }
    if field.is_map() {
        return Err(wrong_type(field));
    }
    decode_scalar(field, leaf, value_field, name, version)
}

/// Decode one scalar leaf: a placeholder or a literal of the field's own kind. A nested
/// message recurses into [`decode_template`].
fn decode_scalar(
    field: &FieldDescriptor,
    leaf: &toml::Value,
    value_field: &ValueField,
    name: &str,
    version: i64,
) -> Result<Value, String> {
    if let toml::Value::String(text) = leaf {
        if text == "{name}" {
            return match field.kind() {
                Kind::String => Ok(Value::String(name.to_owned())),
                Kind::Bytes => Ok(Value::Bytes(prost::bytes::Bytes::copy_from_slice(
                    name.as_bytes(),
                ))),
                _ => Err(placeholder_wrong_field(field, "{name}")),
            };
        }
        if text == "{version}" {
            return match field.kind() {
                Kind::Int32 | Kind::Sint32 | Kind::Sfixed32 => Ok(Value::I32(version as i32)),
                Kind::Int64 | Kind::Sint64 | Kind::Sfixed64 => Ok(Value::I64(version)),
                Kind::Uint32 | Kind::Fixed32 => Ok(Value::U32(version as u32)),
                Kind::Uint64 | Kind::Fixed64 => Ok(Value::U64(version as u64)),
                _ => Err(placeholder_wrong_field(field, "{version}")),
            };
        }
    }
    match (field.kind(), leaf) {
        (Kind::String, toml::Value::String(text)) => Ok(Value::String(text.clone())),
        (Kind::Bool, toml::Value::Boolean(flag)) => Ok(Value::Bool(*flag)),
        (Kind::Int32 | Kind::Sint32 | Kind::Sfixed32, toml::Value::Integer(i)) => {
            Ok(Value::I32(*i as i32))
        }
        (Kind::Int64 | Kind::Sint64 | Kind::Sfixed64, toml::Value::Integer(i)) => {
            Ok(Value::I64(*i))
        }
        (Kind::Uint32 | Kind::Fixed32, toml::Value::Integer(i)) => Ok(Value::U32(*i as u32)),
        (Kind::Uint64 | Kind::Fixed64, toml::Value::Integer(i)) => Ok(Value::U64(*i as u64)),
        (Kind::Float, toml::Value::Float(f)) => Ok(Value::F32(*f as f32)),
        (Kind::Double, toml::Value::Float(f)) => Ok(Value::F64(*f)),
        (Kind::Bytes, toml::Value::String(text)) => Ok(Value::Bytes(
            prost::bytes::Bytes::copy_from_slice(text.as_bytes()),
        )),
        (Kind::Message(nested), toml::Value::Table(table)) => Ok(Value::Message(decode_template(
            &nested,
            table,
            value_field,
            name,
            version,
        )?)),
        (Kind::Enum(values), toml::Value::String(text)) => {
            let value = values.get_value_by_name(text).ok_or_else(|| {
                format!(
                    "the request template sets `{}` to an unknown enum value",
                    field.name()
                )
            })?;
            Ok(Value::EnumNumber(value.number()))
        }
        _ => Err(wrong_type(field)),
    }
}

/// A type error that names the field and never a value.
fn wrong_type(field: &FieldDescriptor) -> String {
    format!(
        "the request template field `{}` has the wrong type",
        field.name()
    )
}

/// A placeholder that cannot fill the field, naming both but never a value.
fn placeholder_wrong_field(field: &FieldDescriptor, placeholder: &str) -> String {
    format!(
        "the `{placeholder}` placeholder cannot fill the `{}` field",
        field.name()
    )
}

/// Encode `template` and the value field into one zeroizing body, preserving field-number
/// order around the value's own number. `value`'s bytes are copied straight from the
/// [`SecretValue`] into the zeroizing buffer.
fn encode_body(
    request: &MessageDescriptor,
    template: &DynamicMessage,
    value_desc: &FieldDescriptor,
    value: &SecretValue,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut before = DynamicMessage::new(request.clone());
    let mut after = DynamicMessage::new(request.clone());
    for (field, leaf) in template.fields() {
        if field.number() < value_desc.number() {
            before.set_field(&field, leaf.clone());
        } else if field.number() > value_desc.number() {
            after.set_field(&field, leaf.clone());
        }
    }
    // One allocation of the exact size: a growing Vec would reallocate after the value is
    // in it and leave an unwiped copy behind (only the final buffer is zeroized on drop).
    let value_len = value.expose().len();
    let capacity = before.encoded_len()
        + varint_len(u64::from(value_desc.number()) << 3 | 2)
        + varint_len(value_len as u64)
        + value_len
        + after.encoded_len();
    let mut body = Zeroizing::new(Vec::with_capacity(capacity));
    before
        .encode(&mut *body)
        .map_err(|_| String::from("the request message could not be encoded"))?;
    append_value(&mut body, value_desc.number(), value);
    after
        .encode(&mut *body)
        .map_err(|_| String::from("the request message could not be encoded"))?;
    debug_assert_eq!(body.len(), capacity, "the request buffer never reallocates");
    Ok(body)
}

/// Write the value field directly: its protobuf tag (field number, wire type 2), the varint
/// length and then the value's bytes. Nothing but the raw bytes leaves the [`SecretValue`].
fn append_value(body: &mut Vec<u8>, number: u32, value: &SecretValue) {
    let bytes = value.expose().as_bytes();
    put_varint(body, u64::from(number) << 3 | 2);
    put_varint(body, bytes.len() as u64);
    body.extend_from_slice(bytes);
}

/// The number of bytes [`put_varint`] writes for `n`.
fn varint_len(mut n: u64) -> usize {
    let mut len = 1;
    while n >= 0x80 {
        n >>= 7;
        len += 1;
    }
    len
}

/// A protobuf base-128 varint.
fn put_varint(body: &mut Vec<u8>, mut n: u64) {
    while n >= 0x80 {
        body.push((n as u8) | 0x80);
        n >>= 7;
    }
    body.push(n as u8);
}

/// The gRPC-Web frame: `0x00` (uncompressed) plus the 4-byte big-endian message length.
fn frame(body: Zeroizing<Vec<u8>>) -> Zeroizing<Vec<u8>> {
    let mut framed = Zeroizing::new(Vec::with_capacity(body.len() + 5));
    framed.push(0x00);
    framed.extend_from_slice(&(body.len() as u32).to_be_bytes());
    framed.extend_from_slice(&body);
    framed
}

#[cfg(test)]
#[path = "grpc_encode_tests.rs"]
mod tests;
