//! `[sets]` and `[producers]` (#253, #262; `docs/design/owner-value-ingestion.md` §3): parsed
//! and checked at load (§3.2), then kept on [`Fleet`] as
//! [`crate::domain::provision`] types. Every refusal is `config_invalid` naming the field.
//!
//! The rules: a set's members are declared team keys stored in 1Password, wanted in each of
//! the set's environments, all in one boundary (D1); a key is in at most one set; a producer
//! is argv without `op`/`opv` as `command[0]` and without anything secret-shaped, pinned by
//! the SHA-256 of the project file it runs, capped at 15 minutes, and reads only keys of the
//! boundary and environments of the sets it serves (D5-B).

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;

use super::{Doc, check, is_product_name, undeclared};
use crate::cause::{Cause, ConfigCheck, Declared, FieldRule, PatternId};
use crate::domain::provision::{
    Generator, KeyRef, MAX_PRODUCER_TIMEOUT, MemberSource, Producer, ProvisionSet,
};
use crate::domain::provision_template::{self as template, LeafError, Node, Ref, Template};
use crate::domain::{Fleet, KeySpec, Kind, ValueSource};
use crate::error::Error;

/// `[sets.<name>]` as written.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawSet {
    environments: Vec<String>,
    members: BTreeMap<String, RawMember>,
}

/// One `members` entry as written: a producer output, a generator or a template. A
/// template's tree is read from the document itself ([`template_tree`]), which keeps the
/// declared order; this field only marks that one is written.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMember {
    #[serde(default)]
    producer: Option<String>,
    #[serde(default)]
    output: Option<String>,
    #[serde(default)]
    generate: Option<toml::Value>,
    #[serde(default)]
    template: Option<toml::Value>,
}

/// `[producers.<name>]` as written.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawProducer {
    command: Vec<String>,
    #[serde(default)]
    sha256: Option<String>,
    outputs: Vec<String>,
    #[serde(default)]
    inputs: BTreeMap<String, String>,
    #[serde(default)]
    open_url_hosts: Vec<String>,
    timeout: String,
}

/// The names `command[0]` may not have: opv never runs itself or `op` as a producer, so a
/// producer never gets `op`'s environment exemption (SR-7, vet F6).
const RESERVED_COMMANDS: [&str; 4] = ["op", "op.exe", "opv", "opv.exe"];

/// Check `sets` and `producers` against the validated `fleet` and record them on it.
pub(super) fn check_into(
    fleet: &mut Fleet,
    sets: BTreeMap<String, RawSet>,
    producers: BTreeMap<String, RawProducer>,
    doc: &Doc<'_>,
) -> Result<(), Error> {
    let mut checked_producers = BTreeMap::new();
    for (name, raw) in producers {
        let p = producer(&name, raw, fleet, doc)?;
        checked_producers.insert(name, p);
    }
    let mut checked_sets = BTreeMap::new();
    // Each member key, with the set that first named it.
    let mut owner: BTreeMap<KeyRef, String> = BTreeMap::new();
    for (name, raw) in sets {
        let s = set(&name, raw, fleet, &checked_producers, doc)?;
        for m in s.members.keys() {
            if let Some(other) = owner.get(m) {
                let label = m.to_string();
                return Err(doc.invalid(
                    &["sets", &name, "members", &label],
                    check(ConfigCheck::MemberOfTwoSets {
                        sets: vec![other.clone(), name.clone()],
                        member: label.clone(),
                    }),
                ));
            }
            owner.insert(m.clone(), name.clone());
        }
        checked_sets.insert(name, s);
    }
    check_outputs_used(&checked_producers, &checked_sets, doc)?;
    check_inputs(&checked_producers, &checked_sets, fleet, doc)?;
    fleet.producers = checked_producers;
    fleet.sets = checked_sets;
    Ok(())
}

/// The declared key `s` names (`"<product>/<KEY>"`), refused at `path` when it is not one.
fn declared_key<'f>(
    s: &str,
    fleet: &'f Fleet,
    doc: &Doc<'_>,
    path: &[&str],
) -> Result<(KeyRef, &'f KeySpec), Error> {
    let Some(k) = KeyRef::parse(s) else {
        return Err(doc.invalid(
            path,
            FieldRule::Type {
                expected: "a key named \"<product>/<KEY>\"",
            },
        ));
    };
    let Some(product) = fleet.products.get(&k.product) else {
        return Err(doc.invalid(
            path,
            undeclared(
                Declared::Product,
                &k.product,
                fleet.products.keys().map(String::as_str),
            ),
        ));
    };
    let Some(spec) = product.keys.get(&k.key) else {
        return Err(doc.invalid(
            path,
            undeclared(
                Declared::Key,
                &k.key,
                product.keys.keys().map(String::as_str),
            ),
        ));
    };
    Ok((k, spec))
}

/// Why `spec` is not a team key with its own field in its boundary item (personal, shared
/// with `from`, supplied by infrastructure); `None` when it is one.
fn not_stored(spec: &KeySpec) -> Option<&'static str> {
    if spec.personal {
        Some("personal")
    } else if spec.from.is_some() {
        Some("shared with from")
    } else if spec.value_source == Some(ValueSource::Infrastructure) {
        Some("supplied by infrastructure")
    } else {
        None
    }
}

fn set(
    name: &str,
    raw: RawSet,
    fleet: &Fleet,
    producers: &BTreeMap<String, Producer>,
    doc: &Doc<'_>,
) -> Result<ProvisionSet, Error> {
    if !is_product_name(name) {
        return Err(doc.invalid(
            &["sets", name],
            FieldRule::Pattern {
                id: PatternId::ProductName,
            },
        ));
    }
    if raw.environments.is_empty() {
        return Err(doc.invalid(&["sets", name, "environments"], FieldRule::Empty));
    }
    for env in &raw.environments {
        if !fleet.environments.contains_key(env) {
            return Err(doc.invalid(
                &["sets", name, "environments"],
                undeclared(
                    Declared::Environment,
                    env,
                    fleet.environments.keys().map(String::as_str),
                ),
            ));
        }
    }
    if raw.members.is_empty() {
        return Err(doc.invalid(&["sets", name, "members"], FieldRule::Empty));
    }
    let mut boundary: Option<String> = None;
    let mut members = BTreeMap::new();
    for (label, m) in &raw.members {
        let path = ["sets", name, "members", label.as_str()];
        let (key, spec) = declared_key(label, fleet, doc, &path)?;
        if let Some(why) = not_stored(spec) {
            return Err(doc.invalid(
                &path,
                check(ConfigCheck::SetMemberNotStored {
                    member: label.clone(),
                    why,
                }),
            ));
        }
        if let Some(env) = raw.environments.iter().find(|e| !spec.is_desired_in(e)) {
            return Err(doc.invalid(
                &path,
                check(ConfigCheck::SetMemberNotWanted {
                    member: label.clone(),
                    env: env.clone(),
                }),
            ));
        }
        let b = fleet.boundary_of(&key.product).to_string();
        match &boundary {
            None => boundary = Some(b),
            // A boundary is a product's in every environment, so the first set environment
            // names where the set would span items.
            Some(first) if *first != b => {
                return Err(doc.invalid(
                    &path,
                    check(ConfigCheck::SetSpansBoundaries {
                        env: raw.environments[0].clone(),
                        boundaries: vec![first.clone(), b],
                    }),
                ));
            }
            Some(_) => {}
        }
        let source = member_source(m, &key, spec, producers, doc, &path)?;
        members.insert(key, source);
    }
    let set = ProvisionSet {
        environments: raw.environments,
        boundary: boundary.unwrap_or_default(),
        members,
    };
    check_templates(name, &set, producers, doc)?;
    Ok(set)
}

fn member_source(
    m: &RawMember,
    key: &KeyRef,
    spec: &KeySpec,
    producers: &BTreeMap<String, Producer>,
    doc: &Doc<'_>,
    path: &[&str],
) -> Result<MemberSource, Error> {
    let at = |field: &'static str| -> Vec<&str> {
        let mut p = path.to_vec();
        p.push(field);
        p
    };
    if m.template.is_some() {
        let other = [
            ("producer", m.producer.is_some()),
            ("output", m.output.is_some()),
            ("generate", m.generate.is_some()),
        ];
        if let Some((field, _)) = other.iter().find(|(_, written)| *written) {
            return Err(doc.invalid(
                &at("template"),
                FieldRule::ConflictsWith {
                    field: super::dotted(&at(field)),
                },
            ));
        }
        if spec.kind != Kind::Secret {
            return Err(doc.invalid(
                &at("template"),
                FieldRule::Type {
                    expected: TEMPLATE_KIND,
                },
            ));
        }
        return Ok(MemberSource::Template(template_tree(doc, &at("template"))?));
    }
    match (&m.producer, &m.output, &m.generate) {
        (Some(_), _, Some(_)) => Err(doc.invalid(
            &at("generate"),
            FieldRule::ConflictsWith {
                field: super::dotted(&at("producer")),
            },
        )),
        (None, Some(_), Some(_)) => Err(doc.invalid(
            &at("output"),
            FieldRule::ConflictsWith {
                field: super::dotted(&at("generate")),
            },
        )),
        (None, None, None) => Err(doc.invalid(&at("generate"), FieldRule::Missing)),
        (None, Some(_), None) => Err(doc.invalid(&at("producer"), FieldRule::Missing)),
        (Some(_), None, None) => Err(doc.invalid(&at("output"), FieldRule::Missing)),
        (Some(producer), Some(output), None) => {
            let Some(p) = producers.get(producer) else {
                return Err(doc.invalid(
                    &at("producer"),
                    undeclared(
                        Declared::Producer,
                        producer,
                        producers.keys().map(String::as_str),
                    ),
                ));
            };
            if !p.outputs.contains(output) {
                return Err(doc.invalid(
                    &at("output"),
                    check(ConfigCheck::ProducerOutputUndeclared {
                        producer: producer.clone(),
                        output: output.clone(),
                        outputs: p.outputs.clone(),
                    }),
                ));
            }
            Ok(MemberSource::Producer {
                producer: producer.clone(),
                output: output.clone(),
            })
        }
        (None, None, Some(g)) => Ok(MemberSource::Generate(generator(
            g,
            key,
            spec,
            doc,
            &at("generate"),
        )?)),
    }
}

/// What a template string leaf may be (§3.2).
const TEMPLATE_LEAF: &str = "a literal without \"${\", or exactly \"${product/KEY}\" (a member of this set) or \"${producer.output}\"";
/// What a template node may be: TOML floats and datetimes have no exact JSON form here.
const TEMPLATE_NODE: &str = "a string, integer, boolean, array or table";
/// A template renders secrets, so its member is one.
const TEMPLATE_KIND: &str = "a key of kind \"secret\" (a template renders secrets)";
/// A template whose references come back to itself.
const TEMPLATE_CYCLE: &str =
    "a template that does not reference itself, directly or through another template";

/// The member's `template` at `path`, read from the document so tables keep their declared
/// order (the parsed table is sorted): each table's entries ordered by where their keys are
/// written. String leaves are literals or whole references ([`template::leaf`]); a table key
/// holding `${` is refused like a leaf.
fn template_tree(doc: &Doc<'_>, path: &[&str]) -> Result<Template, Error> {
    let mut table = Some(doc.root.get_ref());
    let mut found = None;
    for part in path {
        let Some((_, v)) =
            table.and_then(|t| t.iter().find(|(n, _)| n.get_ref().as_ref() == *part))
        else {
            return Err(doc.invalid(path, FieldRule::Missing));
        };
        table = v.get_ref().as_table();
        found = Some(v);
    }
    let Some(v) = found else {
        return Err(doc.invalid(path, FieldRule::Missing));
    };
    let mut at: Vec<String> = path.iter().map(|p| p.to_string()).collect();
    Ok(Template::new(node(v.get_ref(), doc, &mut at)?))
}

fn node(v: &toml::de::DeValue<'_>, doc: &Doc<'_>, at: &mut Vec<String>) -> Result<Node, Error> {
    use toml::de::DeValue;
    let refuse = |at: &[String], rule: FieldRule| {
        let p: Vec<&str> = at.iter().map(String::as_str).collect();
        doc.invalid(&p, rule)
    };
    let leaf_rule = |e: LeafError| match e {
        LeafError::Interpolated | LeafError::Malformed => FieldRule::Type {
            expected: TEMPLATE_LEAF,
        },
    };
    Ok(match v {
        DeValue::String(s) => template::leaf(s).map_err(|e| refuse(at, leaf_rule(e)))?,
        DeValue::Boolean(b) => Node::Bool(*b),
        DeValue::Integer(i) => {
            Node::Integer(i64::from_str_radix(i.as_str(), i.radix()).map_err(|_| {
                refuse(
                    at,
                    FieldRule::Type {
                        expected: TEMPLATE_NODE,
                    },
                )
            })?)
        }
        DeValue::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for (i, item) in items.iter().enumerate() {
                at.push(i.to_string());
                out.push(node(item.get_ref(), doc, at)?);
                at.pop();
            }
            Node::Array(out)
        }
        DeValue::Table(t) => {
            let mut entries: Vec<_> = t.iter().collect();
            entries.sort_by_key(|(k, _)| k.span().start);
            let mut out = Vec::with_capacity(entries.len());
            for (k, item) in entries {
                let k = k.get_ref().to_string();
                at.push(k.clone());
                if k.contains("${") {
                    return Err(refuse(at, leaf_rule(LeafError::Interpolated)));
                }
                out.push((k, node(item.get_ref(), doc, at)?));
                at.pop();
            }
            Node::Table(out)
        }
        DeValue::Float(_) | DeValue::Datetime(_) => {
            return Err(refuse(
                at,
                FieldRule::Type {
                    expected: TEMPLATE_NODE,
                },
            ));
        }
    })
}

/// A set's templates (§3.2): each `${product/KEY}` names a member of the set, each
/// `${producer.output}` a declared output of a declared producer, and no template
/// references itself, directly or through another template.
fn check_templates(
    name: &str,
    set: &ProvisionSet,
    producers: &BTreeMap<String, Producer>,
    doc: &Doc<'_>,
) -> Result<(), Error> {
    for (key, source) in &set.members {
        let MemberSource::Template(t) = source else {
            continue;
        };
        let label = key.to_string();
        let path = ["sets", name, "members", label.as_str(), "template"];
        for r in t.references() {
            match r {
                Ref::Member(m) if !set.members.contains_key(m) => {
                    let declared: Vec<String> = set.members.keys().map(|k| k.to_string()).collect();
                    return Err(doc.invalid(
                        &path,
                        undeclared(
                            Declared::Key,
                            &m.to_string(),
                            declared.iter().map(String::as_str),
                        ),
                    ));
                }
                Ref::Member(_) => {}
                Ref::Output { producer, output } => {
                    let Some(p) = producers.get(producer) else {
                        return Err(doc.invalid(
                            &path,
                            undeclared(
                                Declared::Producer,
                                producer,
                                producers.keys().map(String::as_str),
                            ),
                        ));
                    };
                    if !p.outputs.contains(output) {
                        return Err(doc.invalid(
                            &path,
                            check(ConfigCheck::ProducerOutputUndeclared {
                                producer: producer.clone(),
                                output: output.clone(),
                                outputs: p.outputs.clone(),
                            }),
                        ));
                    }
                }
            }
        }
    }
    if let Err(template::Cycle { member }) = template::render_order(set) {
        let label = member.to_string();
        return Err(doc.invalid(
            &["sets", name, "members", label.as_str(), "template"],
            FieldRule::Type {
                expected: TEMPLATE_CYCLE,
            },
        ));
    }
    Ok(())
}

/// `generate = "rules"` (on a key whose rules give a recipe), or exactly one of
/// `{ hex_bytes = N }` / `{ base64_bytes = N }` with N in 16..=1024.
fn generator(
    g: &toml::Value,
    key: &KeyRef,
    spec: &KeySpec,
    doc: &Doc<'_>,
    path: &[&str],
) -> Result<Generator, Error> {
    const SHAPE: FieldRule = FieldRule::Type {
        expected: "\"rules\", { hex_bytes = N } or { base64_bytes = N } with N from 16 to 1024",
    };
    match g {
        toml::Value::String(s) if s == "rules" => {
            if spec.has_generate_recipe() {
                Ok(Generator::Rules)
            } else {
                Err(doc.invalid(
                    path,
                    check(ConfigCheck::GenerateNoRecipe {
                        member: key.to_string(),
                    }),
                ))
            }
        }
        toml::Value::Table(t) if t.len() == 1 => {
            let (kind, n) = t.iter().next().expect("one entry");
            let (Some(n), "hex_bytes" | "base64_bytes") = (n.as_integer(), kind.as_str()) else {
                return Err(doc.invalid(path, SHAPE));
            };
            let Some(n) = u16::try_from(n).ok().filter(|n| (16..=1024).contains(n)) else {
                return Err(doc.invalid(
                    path,
                    check(ConfigCheck::GenerateBytes {
                        bytes: u64::try_from(n).unwrap_or(0),
                    }),
                ));
            };
            Ok(if kind == "hex_bytes" {
                Generator::HexBytes(n)
            } else {
                Generator::Base64Bytes(n)
            })
        }
        _ => Err(doc.invalid(path, SHAPE)),
    }
}

fn producer(name: &str, raw: RawProducer, fleet: &Fleet, doc: &Doc<'_>) -> Result<Producer, Error> {
    let at = |field: &'static str| ["producers", name, field];
    if !is_product_name(name) {
        return Err(doc.invalid(
            &["producers", name],
            FieldRule::Pattern {
                id: PatternId::ProductName,
            },
        ));
    }
    command(&raw.command, doc, &at("command"))?;
    if raw.outputs.is_empty() {
        return Err(doc.invalid(&at("outputs"), FieldRule::Empty));
    }
    for (i, o) in raw.outputs.iter().enumerate() {
        if !is_product_name(o) {
            return Err(doc.invalid(
                &at("outputs"),
                FieldRule::Pattern {
                    id: PatternId::ProductName,
                },
            ));
        }
        if raw.outputs[..i].contains(o) {
            return Err(doc.invalid(&at("outputs"), FieldRule::DuplicateKey));
        }
    }
    let mut inputs = BTreeMap::new();
    for (input, key) in &raw.inputs {
        let path = ["producers", name, "inputs", input.as_str()];
        if !is_product_name(input) {
            return Err(doc.invalid(
                &path,
                FieldRule::Pattern {
                    id: PatternId::ProductName,
                },
            ));
        }
        let (k, spec) = declared_key(key, fleet, doc, &path)?;
        if not_stored(spec).is_some() {
            return Err(doc.invalid(
                &path,
                check(ConfigCheck::ProducerInputOutside {
                    input: input.clone(),
                    key: key.clone(),
                }),
            ));
        }
        inputs.insert(input.clone(), k);
    }
    for host in &raw.open_url_hosts {
        if !is_host_name(host) {
            return Err(doc.invalid(
                &at("open_url_hosts"),
                check(ConfigCheck::OpenUrlHost { host: host.clone() }),
            ));
        }
    }
    let timeout = parse_timeout(&raw.timeout)
        .filter(|t| !t.is_zero())
        .ok_or_else(|| {
            doc.invalid(
                &at("timeout"),
                FieldRule::Type {
                    expected: "a duration such as \"10m\" or \"90s\"",
                },
            )
        })?;
    if timeout > MAX_PRODUCER_TIMEOUT {
        return Err(doc.invalid(
            &at("timeout"),
            check(ConfigCheck::ProducerTimeoutCap { max: "15m" }),
        ));
    }
    let sha256 = pin(name, &raw.command, raw.sha256, doc.dir, doc, &at("sha256"))?;
    Ok(Producer {
        command: raw.command,
        sha256,
        outputs: raw.outputs,
        inputs,
        open_url_hosts: raw.open_url_hosts,
        timeout,
    })
}

/// `command`: non-empty argv of non-empty strings; `command[0]`'s base name is not `op` or
/// `opv`; no element looks like a secret (a token pasted into argv).
fn command(command: &[String], doc: &Doc<'_>, path: &[&str]) -> Result<(), Error> {
    let Some(first) = command.first() else {
        return Err(doc.invalid(path, FieldRule::Empty));
    };
    if command.iter().any(|a| a.is_empty()) {
        return Err(doc.invalid(path, FieldRule::Empty));
    }
    let base = first.rsplit(['/', '\\']).next().unwrap_or(first);
    if RESERVED_COMMANDS.contains(&base.to_ascii_lowercase().as_str()) {
        return Err(doc.invalid(
            path,
            check(ConfigCheck::ProducerIsOp {
                program: base.to_string(),
            }),
        ));
    }
    if let Some(index) = command
        .iter()
        .position(|a| crate::scrub::scrub_patterns(a) != *a)
    {
        return Err(doc.invalid(path, check(ConfigCheck::ProducerArgumentSecret { index })));
    }
    Ok(())
}

/// `"<n>s"` or `"<n>m"`.
fn parse_timeout(s: &str) -> Option<Duration> {
    let (n, unit) = s.split_at(s.len().checked_sub(1)?);
    if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u64 = n.parse().ok()?;
    match unit {
        "s" => Some(Duration::from_secs(n)),
        "m" => Some(Duration::from_secs(n.checked_mul(60)?)),
        _ => None,
    }
}

/// A lowercase DNS host name: dot-separated labels of letters, digits and inner `-`.
fn is_host_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// The producer's pin (vet F17): `sha256` is 64 hex digits; when the contract was read from
/// a file (`dir`, the project directory), a `command` element naming a file inside it
/// requires `sha256`, which must equal that file's SHA-256 now. At most one such file.
fn pin(
    producer: &str,
    command: &[String],
    sha256: Option<String>,
    dir: Option<&Path>,
    doc: &Doc<'_>,
    path: &[&str],
) -> Result<Option<String>, Error> {
    if let Some(s) = &sha256
        && !(s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(doc.invalid(
            path,
            FieldRule::Type {
                expected: "64 hexadecimal digits",
            },
        ));
    }
    let sha256 = sha256.map(|s| s.to_ascii_lowercase());
    let Some(dir) = dir else {
        return Ok(sha256);
    };
    let files: Vec<(&String, std::path::PathBuf)> = command
        .iter()
        .filter_map(|a| project_file(dir, a).map(|f| (a, f)))
        .collect();
    let (arg, file) = match files.as_slice() {
        [] => return Ok(sha256),
        [(arg, file)] => (*arg, file),
        _ => {
            let mut command_path = path.to_vec();
            command_path.pop();
            command_path.push("command");
            return Err(doc.invalid(
                &command_path,
                FieldRule::Type {
                    expected: "an argument list naming at most one project file",
                },
            ));
        }
    };
    let Some(pinned) = sha256 else {
        return Err(doc.invalid(
            path,
            check(ConfigCheck::ProducerShaMissing { file: arg.clone() }),
        ));
    };
    if file_sha256(file).as_deref() != Some(pinned.as_str()) {
        return Err(Cause::ProducerChanged {
            producer: producer.to_string(),
            file: std::path::PathBuf::from(arg),
        }
        .into());
    }
    Ok(Some(pinned))
}

/// The lowercase hex SHA-256 of `file`, if it can be read.
fn file_sha256(file: &Path) -> Option<String> {
    use sha2::Digest as _;
    std::fs::read(file)
        .map(|bytes| hex::encode(sha2::Sha256::digest(&bytes)))
        .ok()
}

/// The producer's pin checked again right before it is spawned (security review 0.18.0
/// S9): the load-time check leaves the confirmation prompt as a window to edit the file.
/// The project file `command` names must still be one, hash to `sha256`, and need a pin;
/// with a pin and no project file, an argument that now names some other path (a symlink
/// out of the project, say) is refused too. Refuses with `ProducerChanged`.
pub(crate) fn recheck_pin(producer: &str, p: &Producer, dir: &Path) -> Result<(), Error> {
    let changed = |arg: &str| -> Error {
        Cause::ProducerChanged {
            producer: producer.to_string(),
            file: std::path::PathBuf::from(arg),
        }
        .into()
    };
    let files: Vec<(&String, std::path::PathBuf)> = p
        .command
        .iter()
        .filter_map(|a| project_file(dir, a).map(|f| (a, f)))
        .collect();
    match (files.as_slice(), p.sha256.as_deref()) {
        ([], None) => Ok(()),
        ([], Some(_)) => match p
            .command
            .iter()
            .skip(1)
            .find(|a| !a.starts_with('-') && dir.join(a).symlink_metadata().is_ok())
        {
            Some(arg) => Err(changed(arg)),
            None => Ok(()),
        },
        ([(arg, file)], Some(pinned)) if file_sha256(file).as_deref() == Some(pinned) => Ok(()),
        ([(arg, _), ..], _) => Err(changed(arg)),
    }
}

/// The file `arg` names inside the project directory `dir`, if it is one: an argument that
/// is not an option and resolves to a regular file under `dir`.
fn project_file(dir: &Path, arg: &str) -> Option<std::path::PathBuf> {
    if arg.starts_with('-') {
        return None;
    }
    let root = dir.canonicalize().ok()?;
    let file = root.join(arg).canonicalize().ok()?;
    (file.starts_with(&root) && file.is_file()).then_some(file)
}

/// Each producer output is used by a member or a template of some set.
fn check_outputs_used(
    producers: &BTreeMap<String, Producer>,
    sets: &BTreeMap<String, ProvisionSet>,
    doc: &Doc<'_>,
) -> Result<(), Error> {
    for (name, p) in producers {
        let used = |o: &String| {
            sets.values()
                .flat_map(|s| s.members.values())
                .any(|m| match m {
                    MemberSource::Producer { producer, output } => producer == name && output == o,
                    MemberSource::Template(t) => t.uses_output(name, o),
                    MemberSource::Generate(_) => false,
                })
        };
        if let Some(unused) = p.outputs.iter().find(|o| !used(o)) {
            return Err(doc.invalid(
                &["producers", name, "outputs"],
                check(ConfigCheck::ProducerOutputUnused {
                    producer: name.clone(),
                    output: unused.clone(),
                }),
            ));
        }
    }
    Ok(())
}

/// D5-B: a producer's inputs are keys of the boundary of every set it serves, wanted in
/// each of that set's environments (no cross-boundary or cross-environment read).
fn check_inputs(
    producers: &BTreeMap<String, Producer>,
    sets: &BTreeMap<String, ProvisionSet>,
    fleet: &Fleet,
    doc: &Doc<'_>,
) -> Result<(), Error> {
    for (name, p) in producers {
        let served = sets.values().filter(|s| {
            s.members.values().any(|m| match m {
                MemberSource::Producer { producer, .. } => producer == name,
                MemberSource::Template(t) => t.uses_producer(name),
                MemberSource::Generate(_) => false,
            })
        });
        for s in served {
            for (input, k) in &p.inputs {
                let spec = &fleet.products[&k.product].keys[&k.key];
                let inside = fleet.boundary_of(&k.product) == s.boundary
                    && s.environments.iter().all(|e| spec.is_desired_in(e));
                if !inside {
                    return Err(doc.invalid(
                        &["producers", name, "inputs", input],
                        check(ConfigCheck::ProducerInputOutside {
                            input: input.clone(),
                            key: k.to_string(),
                        }),
                    ));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "sets_tests.rs"]
mod tests;
