//! The 1Password side of self-healing conventions (FR-43): the tolerant parse of the whole
//! item, and the tidy write.
//!
//! - [`parse`] turns `op item get --format json` output into a
//!   [`Layout`](crate::domain::convention::Layout) without refusing anything: any field
//!   type, a missing label, a non-string value (kept as its text), duplicates. Values go
//!   straight into [`SecretValue`]s, which register them with the stderr scrubber (NR-31).
//! - [`apply`] applies a [`TidyPlan`] to the item JSON in memory. It never removes a field
//!   or a section; it relabels, moves, retypes and appends.
//! - [`write`] sends the whole tidied item to `op item edit <item_id> --vault <vault_id>
//!   --format json` on stdin: one atomic edit (the `item skeleton` invocation, D0), so an
//!   interrupted write leaves the item either untouched or fully tidied. Never retried
//!   (NR-2). Values only ever travel on stdin (SR-3); the JSON lives in `Zeroizing` buffers
//!   and a [`WipeOnDrop`] tree (SR-8).

use std::collections::BTreeSet;
use std::fmt;

use serde::Deserialize;
use serde::de::{self, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::{Value, json};
use zeroize::{Zeroize, Zeroizing};

use super::onepassword::{
    OP, WipeOnDrop, failed_op_error_as, json_error, op_spawn_error, serialize_exact,
};
use crate::domain::convention::{
    Found, KEPT_SECTION, Layout, MARKER_SECTION, Op, Section, TidyPlan,
};
use crate::domain::model::Environment;
use crate::domain::secret::SecretValue;
use crate::error::Error;
use crate::host::Host;
use crate::runner::{Call, CommandRunner, Outcome, status_text, unknown_text};

/// The item's edit stamp: `version` and `updated_at`. Two reads with the same stamp saw
/// the same item; a different stamp means someone edited it in between.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stamp(Option<u64>, Option<String>);

#[derive(Deserialize)]
struct RawItem {
    #[serde(default)]
    version: Option<u64>,
    #[serde(default)]
    updated_at: Option<String>,
    #[serde(default)]
    sections: Vec<RawSection>,
    #[serde(default)]
    fields: Vec<RawField>,
}

#[derive(Deserialize)]
struct RawSection {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    label: Option<String>,
}

#[derive(Deserialize)]
struct RawField {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    section: Option<RawSection>,
    #[serde(rename = "type", default)]
    ty: String,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    purpose: Option<String>,
    #[serde(default)]
    value: Option<Loose>,
}

/// Any JSON value as a [`SecretValue`]: a string as is, a number or boolean as its text,
/// anything else as empty. Never refuses, so no field can fail the read.
struct Loose(SecretValue);

impl<'de> Deserialize<'de> for Loose {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Loose;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("any value")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Loose, E> {
                Ok(Loose(SecretValue::new(v.to_owned())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Loose, E> {
                Ok(Loose(SecretValue::new(v)))
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Loose, E> {
                Ok(Loose(SecretValue::new(v.to_string())))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Loose, E> {
                Ok(Loose(SecretValue::new(v.to_string())))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Loose, E> {
                Ok(Loose(SecretValue::new(v.to_string())))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Loose, E> {
                Ok(Loose(SecretValue::new(v.to_string())))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Loose, E> {
                Ok(Loose(SecretValue::new(String::new())))
            }
            fn visit_none<E: de::Error>(self) -> Result<Loose, E> {
                self.visit_unit()
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Loose, A::Error> {
                while a.next_element::<IgnoredAny>()?.is_some() {}
                self.visit_unit()
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Loose, A::Error> {
                while a.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                self.visit_unit()
            }
        }
        d.deserialize_any(V)
    }
}

/// The tolerant parse of one `op item get --format json` output (see the module docs).
/// Fails only on JSON that is not an item at all (value-free message).
pub fn parse(json: &[u8]) -> Result<(Layout, Stamp), Error> {
    let raw: RawItem = serde_json::from_slice(json).map_err(|e| json_error(&e))?;
    let section = |s: RawSection| Section {
        id: s.id.unwrap_or_default(),
        label: s.label.unwrap_or_default(),
    };
    let layout = Layout {
        sections: raw.sections.into_iter().map(section).collect(),
        fields: raw
            .fields
            .into_iter()
            .map(|f| Found {
                id: f.id.unwrap_or_default(),
                section: f.section.map(section),
                ty: f.ty,
                label: f.label.unwrap_or_default(),
                builtin: f.purpose.is_some(),
                value: f
                    .value
                    .map_or_else(|| SecretValue::new(String::new()), |v| v.0),
            })
            .collect(),
    };
    Ok((layout, Stamp(raw.version, raw.updated_at)))
}

fn source(what: &str) -> Error {
    Error::Source(format!("op item JSON: {what}; nothing written").into())
}

/// `base`, or `base_2`, `base_3`, ... until it is not in `taken`; then taken.
fn claim(taken: &mut BTreeSet<String>, base: String) -> String {
    let mut candidate = base.clone();
    let mut n = 2;
    while taken.contains(&candidate) {
        candidate = format!("{base}_{n}");
        n += 1;
    }
    taken.insert(candidate.clone());
    candidate
}

/// An id made from a label: lower-case ASCII letters and digits, `_` for anything else.
fn id_from(label: &str) -> String {
    let s: String = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    let s = s.trim_matches('_').to_string();
    if s.is_empty() { "field".into() } else { s }
}

/// Apply `plan` to the item JSON `raw` it was made from, returning the whole tidied item,
/// ready for `op item edit` stdin. Pure; fails (value-free) only on JSON that is not an item.
pub fn apply(raw: &[u8], plan: &TidyPlan) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut doc = WipeOnDrop(serde_json::from_slice(raw).map_err(|e| json_error(&e))?);
    let obj = doc
        .0
        .as_object_mut()
        .ok_or_else(|| source("not an object"))?;
    for key in ["sections", "fields"] {
        let v = obj.entry(key).or_insert_with(|| Value::Array(Vec::new()));
        if !v.is_array() {
            return Err(source(&format!("`{key}` is not an array")));
        }
    }
    let str_at = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);

    // Section renames first: later edits look sections up by their new label.
    for op in &plan.ops {
        if let Op::RenameSection { id, to } = op {
            for s in obj["sections"].as_array_mut().expect("array") {
                if str_at(s, "id").as_deref() == Some(id) {
                    s["label"] = json!(to);
                }
            }
            for f in obj["fields"].as_array_mut().expect("array") {
                if let Some(sec) = f.get_mut("section")
                    && str_at(sec, "id").as_deref() == Some(id)
                {
                    sec["label"] = json!(to);
                }
            }
        }
    }

    let mut sections: Vec<(String, String)> = obj["sections"]
        .as_array()
        .expect("array")
        .iter()
        .filter_map(|s| Some((str_at(s, "id")?, str_at(s, "label").unwrap_or_default())))
        .collect();
    let mut section_ids: BTreeSet<String> = sections.iter().map(|(i, _)| i.clone()).collect();
    let mut field_ids: BTreeSet<String> = obj["fields"]
        .as_array()
        .expect("array")
        .iter()
        .filter_map(|f| str_at(f, "id"))
        .collect();
    let mut new_sections: Vec<Value> = Vec::new();
    // The section ref (`{"id", "label"}`) for `label`, created when absent.
    let mut section_ref = |label: &str| -> Value {
        let id = match sections.iter().find(|(_, l)| l == label) {
            Some((id, _)) => id.clone(),
            None => {
                let base = match label {
                    KEPT_SECTION => "opv_kept".to_string(),
                    MARKER_SECTION => "opv".to_string(),
                    other => id_from(other),
                };
                let id = claim(&mut section_ids, base);
                sections.push((id.clone(), label.to_string()));
                new_sections.push(json!({"id": id, "label": label}));
                id
            }
        };
        json!({"id": id, "label": label})
    };

    let mut new_fields: Vec<Value> = Vec::new();
    let count = obj["fields"].as_array().expect("array").len();
    for op in &plan.ops {
        match op {
            Op::RenameSection { .. } => {}
            Op::Place {
                index,
                section,
                label,
                conceal,
            } => {
                if *index >= count {
                    return Err(source("the item changed shape"));
                }
                let sec = section.as_deref().map(&mut section_ref);
                let f = obj["fields"]
                    .as_array_mut()
                    .expect("array")
                    .get_mut(*index)
                    .and_then(Value::as_object_mut)
                    .ok_or_else(|| source("a field is not an object"))?;
                f.insert("label".into(), json!(label));
                if *conceal {
                    f.insert("type".into(), json!("CONCEALED"));
                }
                match sec {
                    Some(s) => {
                        f.insert("section".into(), s);
                    }
                    None => {
                        f.remove("section");
                    }
                }
                // Derived from the old place; `op` recomputes it.
                f.remove("reference");
            }
            Op::SetValue { index, value } => {
                let f = obj["fields"]
                    .as_array_mut()
                    .expect("array")
                    .get_mut(*index)
                    .and_then(Value::as_object_mut)
                    .ok_or_else(|| source("a field is not an object"))?;
                let old = f.insert("value".into(), Value::String(value.expose().to_string()));
                if let Some(Value::String(mut s)) = old {
                    s.zeroize();
                }
            }
            Op::Add {
                section,
                label,
                concealed,
                value,
            } => {
                let sec = section.as_deref().map(&mut section_ref);
                let base = match &sec {
                    Some(s) => format!(
                        "{}_{}",
                        s["id"].as_str().unwrap_or("section"),
                        id_from(label)
                    ),
                    None => id_from(label),
                };
                let id = claim(&mut field_ids, base);
                let ty = if *concealed { "CONCEALED" } else { "STRING" };
                let v = value.as_ref().map_or("", SecretValue::expose);
                let mut f = json!({"id": id, "type": ty, "label": label, "value": v});
                if let Some(s) = sec {
                    f["section"] = s;
                }
                new_fields.push(f);
            }
        }
    }
    obj["sections"]
        .as_array_mut()
        .expect("array")
        .extend(new_sections);
    obj["fields"]
        .as_array_mut()
        .expect("array")
        .extend(new_fields);
    serialize_exact(&doc.0)
}

/// Write the whole tidied item: one `op item edit` with `template` on stdin (see the
/// module docs). A refused edit is diagnosed like any failed `op` call (FR-26); an edit
/// whose outcome is unknown says the item is either untouched or fully tidied.
/// Returns what the edit printed: the item as written (with values, in a zeroizing buffer;
/// the caller reads only its version and layout, I5), empty when `op` printed nothing.
pub fn write(
    r: &dyn CommandRunner,
    env: &Environment,
    template: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let host = &Host::detect;
    let args = [
        "item",
        "edit",
        env.item_id.as_str(),
        "--vault",
        env.vault_id.as_str(),
        "--format",
        "json",
    ];
    let call = Call::new(OP, &args).with_stdin(Some(template));
    let status = match r.write(&call).map_err(|e| op_spawn_error(&e, host))? {
        // The edited item comes back on stdout (with values): registered with the stderr
        // scrubber (NR-31) and handed back in its zeroizing buffer.
        Outcome::Done(o) => {
            crate::scrub::register_item_values(&o.stdout);
            return Ok(o.stdout);
        }
        Outcome::Refused(o) => o.status,
        Outcome::Unknown {
            status: Some(s), ..
        } => s,
        Outcome::Unknown { reason, .. } => {
            return Err(Error::Unknown(
                format!(
                    "{}: {}; the item is either unchanged or fully tidied (one edit)",
                    call.step(),
                    unknown_text(OP, reason)
                )
                .into(),
            ));
        }
    };
    Err(failed_op_error_as(
        r,
        env,
        host,
        &format!("op item edit failed ({})", status_text(status)),
        "grant this identity write access to the vault",
        true,
    ))
}

/// Field types a whole-item edit is known to keep exactly: plain string values (the
/// convention's own types). Anything else (OTP, SSH key, date, menu, address, credit card,
/// passkey, a type added later) is not proven to round-trip through `op item edit`.
const ROUND_TRIP_TYPES: [&str; 5] = ["CONCEALED", "STRING", "URL", "EMAIL", "PHONE"];

/// What in the item `op item edit` with the whole JSON is not proven to keep (I4), named
/// for a note (never a value): an attachment, a website list, or a field of a type outside
/// [`ROUND_TRIP_TYPES`]. `None`: every part of the item round-trips. JSON that cannot be
/// read is never rewritten either.
pub fn unprovable(raw: &[u8]) -> Option<&'static str> {
    #[derive(Deserialize)]
    struct Shape {
        #[serde(default)]
        files: Option<Vec<IgnoredAny>>,
        #[serde(default)]
        urls: Option<Vec<IgnoredAny>>,
        #[serde(default)]
        fields: Option<Vec<FieldShape>>,
    }
    #[derive(Deserialize)]
    struct FieldShape {
        #[serde(rename = "type", default)]
        ty: Option<String>,
    }
    let Ok(shape) = serde_json::from_slice::<Shape>(raw) else {
        return Some("content opv cannot read");
    };
    if shape.files.is_some_and(|f| !f.is_empty()) {
        return Some("an attachment");
    }
    if shape.urls.is_some_and(|u| !u.is_empty()) {
        return Some("a website list");
    }
    let odd = shape
        .fields
        .unwrap_or_default()
        .into_iter()
        .map(|f| f.ty.unwrap_or_default())
        .find(|t| !ROUND_TRIP_TYPES.contains(&t.as_str()))?;
    Some(match odd.as_str() {
        "OTP" => "a one-time password field",
        "SSHKEY" => "an SSH key field",
        "PASSKEY" => "a passkey",
        "DATE" => "a date field",
        "MONTH_YEAR" => "a month-year field",
        "ADDRESS" => "an address field",
        "REFERENCE" => "a reference to another item",
        _ => "a field of a type opv does not rewrite",
    })
}

/// How many fields of the tidy are missing from the item read back after the write (I4,
/// I5): each field of `intended` (the template written: every original field, moved,
/// relabelled or kept, plus the new ones) must be in `after` with the same section label,
/// label and value; each field of `original` must still be there by id with its value, or
/// its original value must be kept in another field. Values are compared in constant time
/// and never printed.
pub fn lost(original: &[u8], intended: &[u8], after: &[u8]) -> Result<usize, Error> {
    use subtle::ConstantTimeEq;
    let (original, _) = parse(original)?;
    let (intended, _) = parse(intended)?;
    let (after, _) = parse(after)?;
    let same = |a: &SecretValue, b: &SecretValue| -> bool {
        a.expose().as_bytes().ct_eq(b.expose().as_bytes()).into()
    };
    let mut used = vec![false; after.fields.len()];
    let mut missing = 0;
    for f in &intended.fields {
        let hit = after.fields.iter().enumerate().position(|(i, g)| {
            !used[i]
                && g.section_label() == f.section_label()
                && g.label == f.label
                && same(&g.value, &f.value)
        });
        match hit {
            Some(i) => used[i] = true,
            None => missing += 1,
        }
    }
    for f in &original.fields {
        let in_place = after.fields.iter().any(|g| g.id == f.id);
        let value_kept =
            f.value.expose().is_empty() || after.fields.iter().any(|g| same(&g.value, &f.value));
        if !(in_place && value_kept) {
            missing += 1;
        }
    }
    Ok(missing)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::convention::Change;

    fn layout_of(v: Value) -> Layout {
        parse(&serde_json::to_vec(&v).unwrap()).unwrap().0
    }

    /// Found live: a date field was named only as "a field of a type opv does not rewrite".
    #[test]
    fn unprovable_names_a_date_field() {
        let raw = json!({"fields": [{"id": "d", "type": "DATE", "label": "renewal"}]});
        assert_eq!(
            unprovable(&serde_json::to_vec(&raw).unwrap()),
            Some("a date field")
        );
    }

    #[test]
    fn parse_never_refuses_odd_fields() {
        let l = layout_of(json!({"fields": [
            {"id": "a", "type": "DATE", "label": "D", "value": 1700000000},
            {"id": "b", "type": "CONCEALED", "label": "K", "section": {"id": "s"}},
            {"id": "c", "type": "STRING", "value": {"nested": true}},
        ]}));
        assert_eq!(l.fields.len(), 3);
    }

    #[test]
    fn parse_reads_a_number_value_as_its_text() {
        let l =
            layout_of(json!({"fields": [{"id": "a", "type": "DATE", "label": "D", "value": 17}]}));
        assert_eq!(l.fields[0].value.expose(), "17");
    }

    #[test]
    fn stamp_changes_with_the_version() {
        let a = parse(br#"{"version": 1}"#).unwrap().1;
        let b = parse(br#"{"version": 2}"#).unwrap().1;
        assert_ne!(a, b);
    }

    #[test]
    fn apply_never_drops_a_field() {
        let raw = serde_json::to_vec(&json!({"fields": [
            {"id": "a", "type": "STRING", "label": "x", "value": "1"},
            {"id": "b", "type": "STRING", "label": "y", "value": "2"},
        ]}))
        .unwrap();
        let plan = TidyPlan {
            ops: vec![Op::Place {
                index: 0,
                section: Some(KEPT_SECTION.into()),
                label: "x (from top level, 2026-10-08)".into(),
                conceal: true,
            }],
            changes: vec![Change::KeptDuplicate("X".into())],
            kept: true,
        };
        let out: Value = serde_json::from_slice(&apply(&raw, &plan).unwrap()).unwrap();
        assert_eq!(out["fields"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn apply_creates_a_missing_section_once() {
        let raw = br#"{"fields": []}"#;
        let add = |label: &str| Op::Add {
            section: Some("api".into()),
            label: label.into(),
            concealed: true,
            value: None,
        };
        let plan = TidyPlan {
            ops: vec![add("A"), add("B")],
            changes: vec![],
            kept: false,
        };
        let out: Value = serde_json::from_slice(&apply(raw, &plan).unwrap()).unwrap();
        assert_eq!(out["sections"], json!([{"id": "api", "label": "api"}]));
    }
}
