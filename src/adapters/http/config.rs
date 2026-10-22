//! Parsing and load-time validation of a target's `http` section (design `http-target` §3.1,
//! §3.2).
//!
//! [`parse`] turns the raw TOML section into [`HttpTarget`], checking every load rule against
//! the pinned descriptor before any call is made. Every violation is returned as a
//! `(field path, rule)` pair and never a value: the rule names the form a value must take (a
//! hostname, a placeholder, a field number), so a refusal cannot leak a secret. The descriptor
//! is read through the caller's closure, so the parser never touches the file system.

use std::collections::BTreeMap;

use prost_reflect::{EnumDescriptor, FieldDescriptor, Kind, MessageDescriptor};

use super::descriptor;
use super::model::{HttpTarget, ListCall, PutCall, ValueField, ValueKind};

#[cfg(test)]
#[path = "config_tests.rs"]
mod config_tests;

/// The gRPC status names `put.conflict` may list (§3.2 rule 7).
const GRPC_STATUS_NAMES: [&str; 17] = [
    "OK",
    "CANCELLED",
    "UNKNOWN",
    "INVALID_ARGUMENT",
    "DEADLINE_EXCEEDED",
    "NOT_FOUND",
    "ALREADY_EXISTS",
    "PERMISSION_DENIED",
    "RESOURCE_EXHAUSTED",
    "FAILED_PRECONDITION",
    "ABORTED",
    "OUT_OF_RANGE",
    "UNIMPLEMENTED",
    "INTERNAL",
    "UNAVAILABLE",
    "DATA_LOSS",
    "UNAUTHENTICATED",
];

/// The whole-leaf placeholders a string leaf of a request template may be (§3.2 rule 3).
const PLACEHOLDERS: [&str; 2] = ["{name}", "{version}"];

/// Parse one target's `http` section (§3.1) and validate it against the descriptor returned by
/// `descriptor_bytes` (§3.2).
///
/// The closure receives `http.descriptor` and returns the pinned `FileDescriptorSet`, which
/// [`descriptor::load`] then checks against `http.descriptor_sha256`. On success every rule of
/// §3.2 holds and the model is returned; otherwise every violation is a `(field path, rule)`
/// pair, in the order it was found, and no value from the section ever appears in one.
pub fn parse(
    section: &toml::Table,
    descriptor_bytes: impl FnOnce(&str) -> Result<Vec<u8>, String>,
) -> Result<HttpTarget, Vec<(String, String)>> {
    let mut errors: Vec<(String, String)> = Vec::new();

    // §3.1 scalars. The host is checked once it is known; the descriptor is loaded once both
    // the path and the pin are known.
    let host = required_str(Some(section), "host", "http.host", &mut errors);
    let descriptor_path = required_str(Some(section), "descriptor", "http.descriptor", &mut errors);
    let descriptor_sha256 = required_str(
        Some(section),
        "descriptor_sha256",
        "http.descriptor_sha256",
        &mut errors,
    );

    if let Some(host) = host.as_deref()
        && let Err(rule) = check_host(host)
    {
        errors.push(("http.host".to_string(), rule.to_string()));
    }

    let names = parse_names(section, &mut errors);

    // §3.1 list and put. A missing table is one violation; its fields are reported separately.
    let list = section.get("list").and_then(toml::Value::as_table);
    let put = section.get("put").and_then(toml::Value::as_table);
    if list.is_none() {
        errors.push((
            "http.list".to_string(),
            "missing or not a table".to_string(),
        ));
    }
    if put.is_none() {
        errors.push(("http.put".to_string(), "missing or not a table".to_string()));
    }

    let list_call = required_str(list, "call", "http.list.call", &mut errors);
    let list_request = required_value(list, "request", "http.list.request", &mut errors);
    let list_items = required_str(list, "items", "http.list.items", &mut errors);
    let list_name = required_str(list, "name", "http.list.name", &mut errors);
    let list_version = required_str(list, "version", "http.list.version", &mut errors);
    let list_status = required_str(list, "status", "http.list.status", &mut errors);
    let list_absent = required_str_array(list, "absent", "http.list.absent", &mut errors);
    let list_rejected = required_str_array(list, "rejected", "http.list.rejected", &mut errors);

    let put_call = required_str(put, "call", "http.put.call", &mut errors);
    let put_request = required_value(put, "request", "http.put.request", &mut errors);
    let put_reply = required_str(put, "reply", "http.put.reply", &mut errors);
    let put_conflict = required_str_array(put, "conflict", "http.put.conflict", &mut errors);

    let value = put
        .and_then(|t| t.get("value"))
        .and_then(toml::Value::as_table);
    if put.is_some() && value.is_none() {
        errors.push((
            "http.put.value".to_string(),
            "missing or not a table".to_string(),
        ));
    }
    let value_field = required_str(value, "field", "http.put.value.field", &mut errors);
    let value_number = required_int(value, "number", "http.put.value.number", &mut errors);
    let value_type = required_str(value, "type", "http.put.value.type", &mut errors);

    // §3.2 rule 7: every conflict entry is a gRPC status name.
    if let Some(conflict) = put_conflict.as_deref() {
        for (i, code) in conflict.iter().enumerate() {
            if !GRPC_STATUS_NAMES.contains(&code.as_str()) {
                errors.push((
                    format!("http.put.conflict[{i}]"),
                    "not a gRPC status name".to_string(),
                ));
            }
        }
    }

    // §3.2 rule 2: the declared `put.value.type` is `"string"` or `"bytes"` even before the
    // descriptor is consulted.
    let declared_kind = value_type.as_deref().and_then(parse_value_kind);
    if let (Some(_), None) = (value_type.as_deref(), declared_kind) {
        errors.push((
            "http.put.value.type".to_string(),
            "type must be string or bytes".to_string(),
        ));
    }

    // §3.2 rule 1: pin and load the descriptor once, through the caller's closure.
    let pool = match (descriptor_path.as_deref(), descriptor_sha256.as_deref()) {
        (Some(path), Some(sha256)) => match descriptor_bytes(path) {
            Ok(bytes) => match descriptor::load(&bytes, sha256) {
                Ok(pool) => Some(pool),
                Err(rule) => {
                    errors.push(("http.descriptor".to_string(), rule));
                    None
                }
            },
            Err(rule) => {
                errors.push(("http.descriptor".to_string(), rule));
                None
            }
        },
        _ => None,
    };

    let mut list_entry: Option<MessageDescriptor> = None;

    if let Some(pool) = pool.as_ref() {
        // §3.2 rule 1: every named method exists in the pinned descriptor.
        let list_method = list_call
            .as_deref()
            .and_then(|call| descriptor::method(pool, call));
        let list_input = list_method.as_ref().map(|m| m.input());
        let list_output = list_method.as_ref().map(|m| m.output());
        if list_call.is_some() && list_method.is_none() {
            errors.push((
                "http.list.call".to_string(),
                "method not found in descriptor".to_string(),
            ));
        }

        let put_method = put_call
            .as_deref()
            .and_then(|call| descriptor::method(pool, call));
        let put_input = put_method.as_ref().map(|m| m.input());
        let put_output = put_method.as_ref().map(|m| m.output());
        if put_call.is_some() && put_method.is_none() {
            errors.push((
                "http.put.call".to_string(),
                "method not found in descriptor".to_string(),
            ));
        }

        // §3.2 rule 2: `put.value` names one singular `string`/`bytes` field of the request
        // message, and its number and type agree with the descriptor.
        let mut value_field_number: Option<u32> = None;
        if let Some(input) = put_input.as_ref()
            && let Some(field_name) = value_field.as_deref()
        {
            match field(input, field_name) {
                Some(descriptor_field) => {
                    let singular = !descriptor_field.is_list() && !descriptor_field.is_map();
                    match (singular, value_kind(&descriptor_field.kind())) {
                        (true, Some(kind)) => {
                            if let (Some(number), Some(declared)) = (value_number, declared_kind) {
                                if number != descriptor_field.number() {
                                    errors.push((
                                        "http.put.value.number".to_string(),
                                        "value field number does not match the descriptor"
                                            .to_string(),
                                    ));
                                }
                                if declared != kind {
                                    errors.push((
                                        "http.put.value.type".to_string(),
                                        "value field type does not match the descriptor"
                                            .to_string(),
                                    ));
                                }
                            }
                            value_field_number = Some(descriptor_field.number());
                        }
                        _ => errors.push((
                            "http.put.value.field".to_string(),
                            "value field must be a singular string or bytes field".to_string(),
                        )),
                    }
                }
                None => errors.push((
                    "http.put.value.field".to_string(),
                    "value field not found in the request message".to_string(),
                )),
            }
        }

        // §3.2 rule 3: each request template decodes against its request message, with the
        // value field the one member a put template may not set.
        if let (Some(input), Some(request)) = (list_input.as_ref(), list_request.as_ref()) {
            validate_template("http.list.request", request, input, None, &mut errors);
        }
        if let (Some(input), Some(request)) = (put_input.as_ref(), put_request.as_ref()) {
            validate_template(
                "http.put.request",
                request,
                input,
                value_field_number,
                &mut errors,
            );
        }

        // §3.2 rule 4: `items` is a repeated message field of the list reply; the roles are
        // typed field paths within one entry.
        if let Some(output) = list_output.as_ref()
            && let Some(items_path) = list_items.as_deref()
        {
            match resolve_field_path(output, items_path) {
                Some(items) => match items.kind() {
                    Kind::Message(entry) if items.is_list() => list_entry = Some(entry),
                    _ => errors.push((
                        "http.list.items".to_string(),
                        "items must be a repeated message field".to_string(),
                    )),
                },
                None => errors.push((
                    "http.list.items".to_string(),
                    "items path not found in the reply message".to_string(),
                )),
            }
        }
        if let Some(entry) = list_entry.as_ref() {
            check_role(
                entry,
                list_name.as_deref(),
                "http.list.name",
                RoleKind::String,
                &mut errors,
            );
            check_role(
                entry,
                list_version.as_deref(),
                "http.list.version",
                RoleKind::Integer,
                &mut errors,
            );
            let status = check_role(
                entry,
                list_status.as_deref(),
                "http.list.status",
                RoleKind::Enum,
                &mut errors,
            );
            if let Some(Kind::Enum(values)) = status.as_ref().map(|f| f.kind()) {
                check_enum_values(
                    &values,
                    list_absent.as_deref(),
                    "http.list.absent",
                    &mut errors,
                );
                check_enum_values(
                    &values,
                    list_rejected.as_deref(),
                    "http.list.rejected",
                    &mut errors,
                );
            }
        }

        // §3.2 rule 4: `put.reply` is the written entry message (the list's roles apply to it).
        if let Some(output) = put_output.as_ref()
            && let Some(reply_path) = put_reply.as_deref()
        {
            match resolve_field_path(output, reply_path) {
                Some(reply)
                    if !reply.is_list()
                        && !reply.is_map()
                        && matches!(reply.kind(), Kind::Message(_)) => {}
                Some(_) => errors.push((
                    "http.put.reply".to_string(),
                    "reply must be a message field".to_string(),
                )),
                None => errors.push((
                    "http.put.reply".to_string(),
                    "reply path not found in the reply message".to_string(),
                )),
            }
        }
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    let list = ListCall {
        call: list_call.expect("checked"),
        request: list_request.expect("checked"),
        items: list_items.expect("checked"),
        name: list_name.expect("checked"),
        version: list_version.expect("checked"),
        status: list_status.expect("checked"),
        absent: list_absent.expect("checked"),
        rejected: list_rejected.expect("checked"),
    };
    let put = PutCall {
        call: put_call.expect("checked"),
        request: put_request.expect("checked"),
        value: ValueField {
            field: value_field.expect("checked"),
            number: value_number.expect("checked"),
            kind: declared_kind.expect("checked"),
        },
        reply: put_reply.expect("checked"),
        conflict: put_conflict.expect("checked"),
    };
    Ok(HttpTarget {
        host: host.expect("checked"),
        descriptor: descriptor_path.expect("checked"),
        descriptor_sha256: descriptor_sha256.expect("checked"),
        names: names.expect("checked"),
        list,
        put,
    })
}

/// A required string at `path`; a missing key or a non-string is one violation.
fn required_str(
    table: Option<&toml::Table>,
    key: &str,
    path: &str,
    errors: &mut Vec<(String, String)>,
) -> Option<String> {
    match table.and_then(|t| t.get(key)) {
        Some(toml::Value::String(value)) => Some(value.clone()),
        Some(_) => {
            errors.push((path.to_string(), "must be a string".to_string()));
            None
        }
        None => {
            errors.push((path.to_string(), "missing".to_string()));
            None
        }
    }
}

/// A required non-negative integer field number at `path`.
fn required_int(
    table: Option<&toml::Table>,
    key: &str,
    path: &str,
    errors: &mut Vec<(String, String)>,
) -> Option<u32> {
    match table.and_then(|t| t.get(key)) {
        Some(toml::Value::Integer(number)) if (0..=u32::MAX as i64).contains(number) => {
            Some(*number as u32)
        }
        Some(toml::Value::Integer(_)) => {
            errors.push((
                path.to_string(),
                "must be a non-negative field number".to_string(),
            ));
            None
        }
        Some(_) => {
            errors.push((path.to_string(), "must be an integer".to_string()));
            None
        }
        None => {
            errors.push((path.to_string(), "missing".to_string()));
            None
        }
    }
}

/// A required array of strings at `path`.
fn required_str_array(
    table: Option<&toml::Table>,
    key: &str,
    path: &str,
    errors: &mut Vec<(String, String)>,
) -> Option<Vec<String>> {
    match table.and_then(|t| t.get(key)) {
        Some(toml::Value::Array(items)) => {
            let mut values = Vec::with_capacity(items.len());
            for (i, item) in items.iter().enumerate() {
                match item.as_str() {
                    Some(value) => values.push(value.to_string()),
                    None => errors.push((format!("{path}[{i}]"), "must be a string".to_string())),
                }
            }
            Some(values)
        }
        Some(_) => {
            errors.push((path.to_string(), "must be an array of strings".to_string()));
            None
        }
        None => {
            errors.push((path.to_string(), "missing".to_string()));
            None
        }
    }
}

/// A required TOML value at `path`, copied so the model owns its literal request template.
fn required_value(
    table: Option<&toml::Table>,
    key: &str,
    path: &str,
    errors: &mut Vec<(String, String)>,
) -> Option<toml::Value> {
    match table.and_then(|t| t.get(key)) {
        Some(value) => Some(value.clone()),
        None => {
            errors.push((path.to_string(), "missing".to_string()));
            None
        }
    }
}

/// Parse `http.names` (§3.2 rule 5): non-empty, every value a non-empty string, and no two env
/// names mapping to one remote name. Completeness is checked by the store.
fn parse_names(
    section: &toml::Table,
    errors: &mut Vec<(String, String)>,
) -> Option<BTreeMap<String, String>> {
    let Some(value) = section.get("names") else {
        errors.push(("http.names".to_string(), "missing".to_string()));
        return None;
    };
    let Some(table) = value.as_table() else {
        errors.push(("http.names".to_string(), "must be a table".to_string()));
        return None;
    };
    if table.is_empty() {
        errors.push((
            "http.names".to_string(),
            "must map at least one name".to_string(),
        ));
        return None;
    }

    let mut names = BTreeMap::new();
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for (env, remote) in table {
        match remote.as_str() {
            Some(remote) if !remote.is_empty() => {
                if let Some(first) = seen.get(remote) {
                    errors.push((
                        "http.names".to_string(),
                        format!("two env names map to one remote name ({first} and {env})"),
                    ));
                } else {
                    seen.insert(remote.to_string(), env.clone());
                }
                names.insert(env.clone(), remote.to_string());
            }
            Some(_) => errors.push((
                format!("http.names.{env}"),
                "remote name must not be empty".to_string(),
            )),
            None => errors.push((
                format!("http.names.{env}"),
                "remote name must be a string".to_string(),
            )),
        }
    }
    Some(names)
}

/// §3.2 rule 6: a lowercase ASCII hostname, not a URL, an IP literal, a port or a trailing dot.
fn check_host(host: &str) -> Result<(), &'static str> {
    const RULE: &str =
        "must be a lowercase ASCII hostname, not a URL, IP literal, port or trailing dot";
    if host.is_empty()
        || !host.is_ascii()
        || host != host.to_ascii_lowercase()
        || host.ends_with('.')
        || host.len() > 253
        || host
            .chars()
            .any(|c| !matches!(c, 'a'..='z' | '0'..='9' | '-' | '.'))
    {
        return Err(RULE);
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Err(RULE);
    }
    for label in host.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
            return Err(RULE);
        }
    }
    Ok(())
}

/// The field named `name` (or its JSON spelling) in `message`.
fn field(message: &MessageDescriptor, name: &str) -> Option<FieldDescriptor> {
    message
        .get_field_by_name(name)
        .or_else(|| message.get_field_by_json_name(name))
}

/// Resolve a dotted field path from `message`, refusing an empty segment and a non-message in
/// the middle.
fn resolve_field_path(message: &MessageDescriptor, path: &str) -> Option<FieldDescriptor> {
    let mut current = message.clone();
    let mut segments = path.split('.').peekable();
    let mut result = None;
    while let Some(segment) = segments.next() {
        if segment.is_empty() {
            return None;
        }
        let descriptor = field(&current, segment)?;
        if segments.peek().is_some() {
            match descriptor.kind() {
                Kind::Message(next) if !descriptor.is_list() && !descriptor.is_map() => {
                    current = next;
                }
                _ => return None,
            }
        } else {
            result = Some(descriptor);
        }
    }
    result
}

/// §3.2 rule 3: decode a literal request template against `message`, refusing unknown fields,
/// wrong scalar types, the value field and any string leaf that is not a literal or exactly
/// `{name}`/`{version}`.
fn validate_template(
    path: &str,
    value: &toml::Value,
    message: &MessageDescriptor,
    value_field_number: Option<u32>,
    errors: &mut Vec<(String, String)>,
) {
    let Some(table) = value.as_table() else {
        errors.push((
            path.to_string(),
            "request template must be a table".to_string(),
        ));
        return;
    };
    for (key, leaf) in table {
        let Some(descriptor) = field(message, key) else {
            errors.push((
                format!("{path}.{key}"),
                "unknown field in request template".to_string(),
            ));
            continue;
        };
        if Some(descriptor.number()) == value_field_number {
            errors.push((
                format!("{path}.{key}"),
                "request template may not set the value field".to_string(),
            ));
            continue;
        }
        validate_template_field(&format!("{path}.{key}"), leaf, &descriptor, errors);
    }
}

/// Validate one template member against its descriptor field.
fn validate_template_field(
    path: &str,
    value: &toml::Value,
    descriptor: &FieldDescriptor,
    errors: &mut Vec<(String, String)>,
) {
    if descriptor.is_map() {
        match (value, descriptor.kind()) {
            (toml::Value::Table(entries), Kind::Message(entry)) => {
                let value_field = entry.map_entry_value_field();
                for leaf in entries.values() {
                    validate_template_kind(path, leaf, &value_field.kind(), errors);
                }
            }
            _ => errors.push((path.to_string(), "must be a table".to_string())),
        }
        return;
    }
    let kind = descriptor.kind();
    if descriptor.is_list() {
        match value {
            toml::Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    validate_template_kind(&format!("{path}[{i}]"), item, &kind, errors);
                }
            }
            _ => errors.push((path.to_string(), "must be an array".to_string())),
        }
        return;
    }
    validate_template_kind(path, value, &kind, errors);
}

/// Validate one template leaf against a declared kind. A whole-leaf `{name}`/`{version}` is
/// accepted wherever a string or integer is expected; any other brace use is refused.
fn validate_template_kind(
    path: &str,
    value: &toml::Value,
    kind: &Kind,
    errors: &mut Vec<(String, String)>,
) {
    match kind {
        Kind::Message(message) => validate_template(path, value, message, None, errors),
        Kind::Enum(values) => {
            let ok = match value {
                toml::Value::String(name) => values.get_value_by_name(name).is_some(),
                toml::Value::Integer(_) => true,
                _ => false,
            };
            if !ok {
                errors.push((path.to_string(), "must be a value of the enum".to_string()));
            }
        }
        Kind::String | Kind::Bytes => match value {
            toml::Value::String(leaf) => check_placeholder(path, leaf, errors),
            _ => errors.push((path.to_string(), "must be a string".to_string())),
        },
        Kind::Bool => {
            if !matches!(value, toml::Value::Boolean(_)) {
                errors.push((path.to_string(), "must be a boolean".to_string()));
            }
        }
        Kind::Float | Kind::Double => {
            if !matches!(value, toml::Value::Integer(_) | toml::Value::Float(_)) {
                errors.push((path.to_string(), "must be a number".to_string()));
            }
        }
        _ => {
            if let toml::Value::String(leaf) = value
                && PLACEHOLDERS.contains(&leaf.as_str())
            {
                return;
            }
            if !matches!(value, toml::Value::Integer(_)) {
                errors.push((path.to_string(), "must be an integer".to_string()));
            }
        }
    }
}

/// A string leaf is a literal unless it uses braces, in which case it must be exactly one of
/// the two whole-leaf placeholders.
fn check_placeholder(path: &str, leaf: &str, errors: &mut Vec<(String, String)>) {
    if (leaf.contains('{') || leaf.contains('}')) && !PLACEHOLDERS.contains(&leaf) {
        errors.push((
            path.to_string(),
            "a string leaf must be a literal or exactly {name} or {version}".to_string(),
        ));
    }
}

/// The role kinds `http.list` names (§3.2 rule 4).
enum RoleKind {
    String,
    Integer,
    Enum,
}

impl RoleKind {
    fn matches(&self, kind: &Kind) -> bool {
        match self {
            RoleKind::String => matches!(kind, Kind::String),
            RoleKind::Integer => matches!(
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
            ),
            RoleKind::Enum => matches!(kind, Kind::Enum(_)),
        }
    }

    fn rule(&self) -> &'static str {
        match self {
            RoleKind::String => "name must be a string field",
            RoleKind::Integer => "version must be an integer field",
            RoleKind::Enum => "status must be an enum field",
        }
    }
}

/// Resolve one role path in the entry message and check its kind; a missing path or the wrong
/// kind is one violation. Returns the field so the status enum can validate `absent`/`rejected`.
fn check_role(
    entry: &MessageDescriptor,
    path: Option<&str>,
    field_path: &str,
    expected: RoleKind,
    errors: &mut Vec<(String, String)>,
) -> Option<FieldDescriptor> {
    let path = path?;
    match resolve_field_path(entry, path) {
        Some(descriptor) => {
            if descriptor.is_list() || descriptor.is_map() || !expected.matches(&descriptor.kind())
            {
                errors.push((field_path.to_string(), expected.rule().to_string()));
            }
            Some(descriptor)
        }
        None => {
            errors.push((
                field_path.to_string(),
                "path not found in the entry message".to_string(),
            ));
            None
        }
    }
}

/// Every name in `values` is a value of the status enum.
fn check_enum_values(
    values: &EnumDescriptor,
    names: Option<&[String]>,
    field_path: &str,
    errors: &mut Vec<(String, String)>,
) {
    let Some(names) = names else {
        return;
    };
    for (i, name) in names.iter().enumerate() {
        if values.get_value_by_name(name).is_none() {
            errors.push((
                format!("{field_path}[{i}]"),
                "status value is not a value of the status enum".to_string(),
            ));
        }
    }
}

/// The `put.value.type` spelling.
fn parse_value_kind(name: &str) -> Option<ValueKind> {
    match name {
        "string" => Some(ValueKind::String),
        "bytes" => Some(ValueKind::Bytes),
        _ => None,
    }
}

/// The descriptor kind of a value field, if it may receive the value.
fn value_kind(kind: &Kind) -> Option<ValueKind> {
    match kind {
        Kind::String => Some(ValueKind::String),
        Kind::Bytes => Some(ValueKind::Bytes),
        _ => None,
    }
}
