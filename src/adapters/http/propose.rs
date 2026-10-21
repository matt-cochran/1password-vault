//! The `http` section generated from an application's descriptor set (design `http-target`
//! §7): `opv propose target <env> <name> --provider http --http-descriptor <file>
//! --http-service <full.name>`. Deterministic: the same descriptor always yields
//! byte-identical text. No network call; the result passes the same load rules as
//! hand-written configuration.
//!
//! The generator only reads names, numbers and types out of the descriptor. It never reads a
//! value (a descriptor holds none) and it never guesses a host: `http.host` is a `<HOST>`
//! placeholder a person confirms. Every guessed line ends in `# suggested: confirm`; a
//! decision with no candidate is a `# choose:` comment instead.

use prost_reflect::{
    DescriptorPool, EnumDescriptor, FieldDescriptor, Kind, MessageDescriptor, MethodDescriptor,
    ServiceDescriptor,
};
use sha2::{Digest, Sha256};

#[cfg(test)]
#[path = "propose_tests.rs"]
mod propose_tests;

/// How deep the generated RPC comment block walks nested request/reply messages.
const COMMENT_DEPTH: usize = 3;

/// The TOML lines of an `http` target section for `service` in the descriptor set
/// `descriptor` (read from `descriptor_path`, which the section names), or why not. Never a
/// value: a descriptor holds names, numbers and types only.
pub fn section(descriptor: &[u8], descriptor_path: &str, service: &str) -> Result<String, String> {
    let pool =
        DescriptorPool::decode(descriptor).map_err(|e| format!("descriptor could not be read: {e}"))?;
    let service = pool
        .get_service_by_name(service)
        .ok_or_else(|| format!("service `{service}` is not in the descriptor"))?;

    let sha256 = hex::encode(Sha256::digest(descriptor));
    let mut out = String::new();
    out.push_str("http.host = \"<HOST>\"\n");
    out.push_str(&format!("http.descriptor = {}\n", toml_str(descriptor_path)));
    out.push_str(&format!(
        "http.descriptor_sha256 = {}\n",
        toml_str(&sha256)
    ));
    out.push('\n');

    append_rpc_comments(&mut out, &service);
    out.push('\n');
    append_list_section(&mut out, &service);
    out.push('\n');
    append_put_section(&mut out, &service);
    Ok(out)
}

/// A TOML basic string, so a path or name with a quote or backslash cannot break the output.
fn toml_str(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The comment block of §7: every RPC of the service with its request and reply field paths,
/// numbers and types, sorted by method name.
fn append_rpc_comments(out: &mut String, service: &ServiceDescriptor) {
    out.push_str(&format!(
        "# RPCs of {} (sorted by name)\n",
        service.full_name()
    ));
    let mut methods: Vec<MethodDescriptor> = service.methods().collect();
    methods.sort_by(|a, b| a.name().cmp(b.name()));
    for method in methods {
        out.push_str(&format!("# {}\n", method.name()));
        out.push_str(&format!("#   request {}\n", method.input().full_name()));
        let mut chain = vec![method.input().full_name().to_string()];
        append_field_comments(out, "#     ", "", &method.input(), 0, &mut chain);
        out.push_str(&format!("#   reply {}\n", method.output().full_name()));
        let mut chain = vec![method.output().full_name().to_string()];
        append_field_comments(out, "#     ", "", &method.output(), 0, &mut chain);
    }
}

/// The dotted field paths of `message`, sorted by field number then name, recursing into
/// message fields up to [`COMMENT_DEPTH`] and never into a message already on the path.
fn append_field_comments(
    out: &mut String,
    indent: &str,
    path: &str,
    message: &MessageDescriptor,
    depth: usize,
    chain: &mut Vec<String>,
) {
    if depth >= COMMENT_DEPTH {
        return;
    }
    let mut fields: Vec<FieldDescriptor> = message.fields().collect();
    fields.sort_by(|a, b| {
        a.number()
            .cmp(&b.number())
            .then_with(|| a.name().cmp(b.name()))
    });
    for field in fields {
        let field_path = format!("{path}{}", field.name());
        out.push_str(&format!(
            "{indent}{field_path}: {} {}\n",
            field.number(),
            field_type_label(&field)
        ));
        if let Kind::Message(inner) = field.kind()
            && !field.is_map()
        {
            let name = inner.full_name().to_string();
            if !chain.contains(&name) {
                chain.push(name);
                append_field_comments(
                    out,
                    indent,
                    &format!("{field_path}."),
                    &inner,
                    depth + 1,
                    chain,
                );
                chain.pop();
            }
        }
    }
}

/// The type of `field` for the comment block: a repeated field is prefixed and a map is
/// spelled `map<value>`, never a value.
fn field_type_label(field: &FieldDescriptor) -> String {
    let base = match field.kind() {
        Kind::Message(message) => message.full_name().to_string(),
        Kind::Enum(enumeration) => enumeration.full_name().to_string(),
        other => scalar_type_name(&other).to_string(),
    };
    if field.is_map() {
        format!("map<{base}>")
    } else if field.is_list() {
        format!("repeated {base}")
    } else {
        base
    }
}

/// The descriptor type name of a scalar `Kind`.
fn scalar_type_name(kind: &Kind) -> &'static str {
    match kind {
        Kind::Double => "double",
        Kind::Float => "float",
        Kind::Int32 => "int32",
        Kind::Int64 => "int64",
        Kind::Uint32 => "uint32",
        Kind::Uint64 => "uint64",
        Kind::Sint32 => "sint32",
        Kind::Sint64 => "sint64",
        Kind::Fixed32 => "fixed32",
        Kind::Fixed64 => "fixed64",
        Kind::Sfixed32 => "sfixed32",
        Kind::Sfixed64 => "sfixed64",
        Kind::Bool => "bool",
        Kind::String => "string",
        Kind::Bytes => "bytes",
        Kind::Message(_) => "message",
        Kind::Enum(_) => "enum",
    }
}

/// The roles §7 suggests inside the list reply's entry message.
struct Roles {
    /// `items`: the entry field path and its message.
    items: Option<(String, MessageDescriptor)>,
    /// `name`: the entry's remote name field.
    name: Option<FieldDescriptor>,
    /// `version`: the entry's version field.
    version: Option<FieldDescriptor>,
    /// `status`: the entry's status enum field and its values.
    status: Option<(FieldDescriptor, EnumDescriptor)>,
}

impl Roles {
    /// A quality score for the four roles: presence of an entry, plus how conventional each
    /// role field's name is (an exact `name`/`provider`/`version`/`status` scores highest).
    /// The list suggestion with the highest score is chosen when several RPCs start with
    /// `List`.
    fn score(&self) -> usize {
        let quality = |field: &Option<FieldDescriptor>, kind: RolePick| match field {
            Some(field) => 2 - usize::from(role_rank(kind, field)),
            None => 0,
        };
        let status = self.status.as_ref().map(|(field, _)| field);
        usize::from(self.items.is_some()) * 2
            + quality(&self.name, RolePick::String)
            + quality(&self.version, RolePick::Integer)
            + quality(&status.cloned(), RolePick::Enum)
    }
}

/// Find the item/name/version/status roles a list reply offers: the first repeated message
/// field, then the best string, integer and enum fields inside it.
fn detect_roles(reply: &MessageDescriptor) -> Roles {
    let mut repeated: Vec<FieldDescriptor> = reply
        .fields()
        .filter(|f| f.is_list() && matches!(f.kind(), Kind::Message(_)))
        .collect();
    repeated.sort_by(|a, b| {
        a.number()
            .cmp(&b.number())
            .then_with(|| a.name().cmp(b.name()))
    });
    let items = repeated.into_iter().next().and_then(|field| {
        if let Kind::Message(entry) = field.kind() {
            Some((field.name().to_string(), entry))
        } else {
            None
        }
    });
    let mut roles = Roles {
        items: None,
        name: None,
        version: None,
        status: None,
    };
    if let Some((path, entry)) = &items {
        roles.name = pick_field(entry, RolePick::String);
        roles.version = pick_field(entry, RolePick::Integer);
        if let Some(field) = pick_field(entry, RolePick::Enum)
            && let Kind::Enum(enumeration) = field.kind()
        {
            roles.status = Some((field, enumeration));
        }
        roles.items = Some((path.clone(), entry.clone()));
    }
    roles
}

/// The role kind [`pick_field`] ranks.
#[derive(Clone, Copy)]
enum RolePick {
    String,
    Integer,
    Enum,
}

/// Rank of a candidate field for a role: an exact conventional name first, then a name
/// containing it, then any field of the right kind.
fn role_rank(kind: RolePick, field: &FieldDescriptor) -> u8 {
    let name = field.name();
    let conventional = match kind {
        RolePick::String => name == "name" || name == "provider",
        RolePick::Integer => name == "version",
        RolePick::Enum => name == "status",
    };
    let related = match kind {
        RolePick::String => name.contains("name") || name.contains("provider"),
        RolePick::Integer => name.contains("version"),
        RolePick::Enum => name.contains("status"),
    };
    if conventional {
        0
    } else if related {
        1
    } else {
        2
    }
}

/// The best singular field of `entry` for `kind`, or none when the entry has no such field.
fn pick_field(entry: &MessageDescriptor, kind: RolePick) -> Option<FieldDescriptor> {
    let mut candidates: Vec<FieldDescriptor> = entry
        .fields()
        .filter(|f| !f.is_list() && !f.is_map())
        .filter(|f| match kind {
            RolePick::String => matches!(f.kind(), Kind::String),
            RolePick::Integer => is_integer_kind(&f.kind()),
            RolePick::Enum => matches!(f.kind(), Kind::Enum(_)),
        })
        .collect();
    candidates.sort_by(|a, b| {
        role_rank(kind, a)
            .cmp(&role_rank(kind, b))
            .then_with(|| a.number().cmp(&b.number()))
            .then_with(|| a.name().cmp(b.name()))
    });
    candidates.into_iter().next()
}

/// Whether `kind` is one of the protobuf integer kinds §3.2 counts as a version.
fn is_integer_kind(kind: &Kind) -> bool {
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

/// The enum value names of `enumeration` containing any of `needles`, sorted.
fn enum_values_containing(enumeration: &EnumDescriptor, needles: &[&str]) -> Vec<String> {
    let mut values: Vec<String> = enumeration
        .values()
        .filter(|value| needles.iter().any(|needle| value.name().contains(needle)))
        .map(|value| value.name().to_string())
        .collect();
    values.sort();
    values
}

/// Append the suggested `[http.list]` table: a `List*` RPC and its reply roles, each guessed
/// line marked `# suggested: confirm`.
fn append_list_section(out: &mut String, service: &ServiceDescriptor) {
    let Some(method) = choose_list(service) else {
        out.push_str("# choose: no List* RPC in the service\n");
        return;
    };
    let roles = detect_roles(&method.output());
    out.push_str("[http.list]\n");
    out.push_str(&format!(
        "call = {}  # suggested: confirm\n",
        toml_str(&method_full_name(&method))
    ));
    out.push_str(&format!(
        "request = {}  # suggested: confirm\n",
        request_template(&method.input(), None)
    ));
    if let Some((items, _)) = roles.items.as_ref() {
        out.push_str(&format!(
            "items = {}  # suggested: confirm\n",
            toml_str(items)
        ));
    }
    if let Some(name) = roles.name.as_ref() {
        out.push_str(&format!(
            "name = {}  # suggested: confirm\n",
            toml_str(name.name())
        ));
    }
    if let Some(version) = roles.version.as_ref() {
        out.push_str(&format!(
            "version = {}  # suggested: confirm\n",
            toml_str(version.name())
        ));
    }
    if let Some((status, enumeration)) = roles.status.as_ref() {
        out.push_str(&format!(
            "status = {}  # suggested: confirm\n",
            toml_str(status.name())
        ));
        let absent = enum_values_containing(enumeration, &["NOT_CONFIGURED", "REVOKED"]);
        let rejected = enum_values_containing(enumeration, &["REJECTED"]);
        out.push_str(&format!(
            "absent = {}  # suggested: confirm\n",
            string_array(&absent)
        ));
        out.push_str(&format!(
            "rejected = {}  # suggested: confirm\n",
            string_array(&rejected)
        ));
    }
}

/// Append the suggested `[http.put]` table: a `Save`/`Put`/`Set`/`Update` RPC, the request
/// template without the value field, the value field, the reply entry and the conflict code.
fn append_put_section(out: &mut String, service: &ServiceDescriptor) {
    let Some(method) = choose_put(service) else {
        out.push_str("# choose: no Save/Put/Set/Update RPC in the service\n");
        return;
    };
    let value = find_value_field(&method.input());
    out.push_str("[http.put]\n");
    out.push_str(&format!(
        "call = {}  # suggested: confirm\n",
        toml_str(&method_full_name(&method))
    ));
    out.push_str(&format!(
        "request = {}  # suggested: confirm\n",
        request_template(&method.input(), value.as_ref().map(FieldDescriptor::number))
    ));
    if let Some(field) = value.as_ref() {
        out.push_str(&format!(
            "value = {{ field = {}, number = {}, type = {} }}  # suggested: confirm\n",
            toml_str(field.name()),
            field.number(),
            toml_str(value_kind_name(&field.kind()))
        ));
    } else {
        for candidate in value_candidates(&method.input(), false) {
            out.push_str(&format!(
                "# choose: value = {{ field = {}, number = {}, type = {} }}\n",
                toml_str(candidate.name()),
                candidate.number(),
                toml_str(value_kind_name(&candidate.kind()))
            ));
        }
    }
    if let Some(reply) = pick_reply(&method.output()) {
        out.push_str(&format!(
            "reply = {}  # suggested: confirm\n",
            toml_str(&reply)
        ));
    }
    out.push_str("conflict = [\"ALREADY_EXISTS\"]  # suggested: confirm\n");
}

/// The `List*` RPC whose reply supplies the most roles; the smallest name breaks a tie.
fn choose_list(service: &ServiceDescriptor) -> Option<MethodDescriptor> {
    let mut best: Option<(usize, MethodDescriptor)> = None;
    for method in service.methods() {
        if !method.name().starts_with("List") {
            continue;
        }
        let score = detect_roles(&method.output()).score();
        let take = match &best {
            None => true,
            Some((best_score, best_method)) => {
                score > *best_score
                    || (score == *best_score && method.name() < best_method.name())
            }
        };
        if take {
            best = Some((score, method));
        }
    }
    best.map(|(_, method)| method)
}

/// The `Save`/`Put`/`Set`/`Update` RPC whose request names a value field, smallest name
/// breaking a tie.
fn choose_put(service: &ServiceDescriptor) -> Option<MethodDescriptor> {
    let mut best: Option<(usize, MethodDescriptor)> = None;
    for method in service.methods() {
        let name = method.name();
        let candidate = name.starts_with("Save")
            || name.starts_with("Put")
            || name.starts_with("Set")
            || name.starts_with("Update");
        if !candidate {
            continue;
        }
        let score = find_value_field(&method.input()).is_some() as usize;
        let take = match &best {
            None => true,
            Some((best_score, best_method)) => {
                score > *best_score
                    || (score == *best_score && method.name() < best_method.name())
            }
        };
        if take {
            best = Some((score, method));
        }
    }
    best.map(|(_, method)| method)
}

/// The singular `string`/`bytes` request field whose name contains `secret`, `value` or
/// `key`; the field a person confirms as the one that receives the value (§7).
fn find_value_field(request: &MessageDescriptor) -> Option<FieldDescriptor> {
    value_candidates(request, true).into_iter().next()
}

/// The singular `string`/`bytes` request fields, sorted by number then name. With `matching`
/// they are further filtered to the value-like names.
fn value_candidates(request: &MessageDescriptor, matching: bool) -> Vec<FieldDescriptor> {
    let mut candidates: Vec<FieldDescriptor> = request
        .fields()
        .filter(|f| !f.is_list() && !f.is_map())
        .filter(|f| matches!(f.kind(), Kind::String | Kind::Bytes))
        .filter(|f| {
            if !matching {
                return true;
            }
            let name = f.name().to_ascii_lowercase();
            name.contains("secret") || name.contains("value") || name.contains("key")
        })
        .collect();
    candidates.sort_by(|a, b| {
        a.number()
            .cmp(&b.number())
            .then_with(|| a.name().cmp(b.name()))
    });
    candidates
}

/// The `put.value.type` spelling of a value field's kind: `string` or `bytes`.
fn value_kind_name(kind: &Kind) -> &'static str {
    match kind {
        Kind::Bytes => "bytes",
        _ => "string",
    }
}

/// The first singular message field of the put reply, the entry whose roles the list's apply
/// (§3.2 rule 4); sorted by number then name.
fn pick_reply(output: &MessageDescriptor) -> Option<String> {
    let mut candidates: Vec<FieldDescriptor> = output
        .fields()
        .filter(|f| !f.is_list() && !f.is_map() && matches!(f.kind(), Kind::Message(_)))
        .collect();
    candidates.sort_by(|a, b| {
        a.number()
            .cmp(&b.number())
            .then_with(|| a.name().cmp(b.name()))
    });
    candidates
        .into_iter()
        .next()
        .map(|field| field.name().to_string())
}

/// The request template of §7: every string field and every version-like integer field,
/// except the value field. `provider`/`name` becomes `{name}` and a version field
/// `{version}`; another string is a `<FIELD>` placeholder and everything else is left out,
/// because opv cannot guess it.
fn request_template(request: &MessageDescriptor, value_number: Option<u32>) -> String {
    let mut fields: Vec<FieldDescriptor> = request.fields().collect();
    fields.sort_by(|a, b| {
        a.number()
            .cmp(&b.number())
            .then_with(|| a.name().cmp(b.name()))
    });
    let mut entries: Vec<String> = Vec::new();
    for field in fields {
        if Some(field.number()) == value_number || field.is_list() || field.is_map() {
            continue;
        }
        let name = field.name();
        let lower = name.to_ascii_lowercase();
        let rendered = match field.kind() {
            Kind::String if lower == "provider" || lower == "name" => "{name}".to_string(),
            Kind::String => format!("<{}>", name.to_ascii_uppercase()),
            kind if is_integer_kind(&kind) && lower.contains("version") => "{version}".to_string(),
            _ => continue,
        };
        entries.push(format!("{name} = {}", toml_str(&rendered)));
    }
    format!("{{ {} }}", entries.join(", "))
}

/// A TOML array of strings for `absent`/`rejected`.
fn string_array(values: &[String]) -> String {
    let items: Vec<String> = values.iter().map(|value| toml_str(value)).collect();
    format!("[{}]", items.join(", "))
}

/// The `"pkg.Service/Method"` call spelling of `method`.
fn method_full_name(method: &MethodDescriptor) -> String {
    format!("{}/{}", method.parent_service().full_name(), method.name())
}