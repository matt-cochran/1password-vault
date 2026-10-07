//! 1Password adapter wrapping the official `op` CLI (S3; FR-11, FR-13, FR-14, FR-19).
//!
//! - [`read_item`] makes exactly one `op item get <item_id> --vault <vault_id> --format json`
//!   call per environment, by ID only (FR-13). It returns the fields that live inside a
//!   section, typed by field type (FR-14: CONCEALED = secret, STRING = config), plus the raw
//!   item JSON so that [`write_skeleton`] needs no second read.
//! - [`write_skeleton`] (FR-19, the only write) pipes the full current item, with the missing
//!   sections and empty fields appended, to `op item edit <item_id> --vault <vault_id>
//!   --format json` on stdin. This is the invocation the D0 spike proved (attempt 1). A
//!   template replaces the item's fields, so it is always the whole item, never a partial one.
//!
//! Secrecy (SR-1, SR-3, SR-4, SR-8):
//! - Nothing but IDs and fixed words goes in argv; the template goes on stdin; no files.
//! - Child stderr is never read (`ProcessRunner` sends it to `Stdio::null()`), and no error
//!   built here includes child output or serde_json's own messages (they can quote values).
//! - Values are deserialized straight into [`SecretValue`] (zeroized on drop). The raw JSON
//!   is kept in a `Zeroizing` buffer and never printed (`Item`'s `Debug` shows its length).
//!
//! Unavoidable transient copies, documented per ruling 7:
//! - serde_json decodes a string containing escape sequences into an internal scratch
//!   buffer that is not zeroized. Unescaped strings are borrowed from the input and copied
//!   once, at exact capacity, into the `SecretValue`.
//! - `write_skeleton` parses the raw JSON into a `serde_json::Value`, whose `String`s hold
//!   values. Every string in that tree is zeroized before it is dropped (also on error paths),
//!   and the template is serialized into a `Zeroizing` buffer pre-sized to the exact length,
//!   so it never reallocates.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fmt;
use std::io::{self, Write};

use serde::Deserialize;
use serde::de::{self, Deserializer, Visitor};
use serde_json::{Value, json};
use zeroize::{Zeroize, Zeroizing};

use crate::domain::model::{Environment, Kind};
use crate::domain::plan::ItemField;
use crate::domain::secret::SecretValue;
use crate::error::Error;
use crate::runner::{CommandRunner, Output};

const OP: &str = "op";

/// The result of one whole-item read.
///
/// `fields` may be moved out (`std::mem::take(&mut item.fields)`) to build a plan;
/// [`write_skeleton`] uses only the raw JSON kept inside.
pub struct Item {
    pub fields: Vec<ItemField>,
    raw: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for Item {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Item")
            .field("fields", &self.fields)
            .field("raw_len", &self.raw.len())
            .finish()
    }
}

/// Whether the environment carries an explicit 1Password credential. Used only to classify
/// a failed `op item get` as [`Error::Auth`] instead of [`Error::Source`].
///
/// Rule (deterministic, value-free): `Present` if any of `OP_SERVICE_ACCOUNT_TOKEN`,
/// `OP_CONNECT_TOKEN` or a variable starting with `OP_SESSION_` is set and non-empty;
/// otherwise `Absent`. Only names and emptiness are inspected; values are never copied.
/// The desktop-app integration leaves no environment signal, so a desktop user whose read
/// fails for another reason is reported as `Auth`; the message says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Credentials {
    Present,
    Absent,
}

impl Credentials {
    pub fn from_env() -> Self {
        Self::from_vars(std::env::vars_os())
    }

    pub fn from_vars<K: AsRef<OsStr>, V: AsRef<OsStr>>(
        vars: impl IntoIterator<Item = (K, V)>,
    ) -> Self {
        let present = vars.into_iter().any(|(k, v)| {
            let named = k.as_ref().to_str().is_some_and(|k| {
                k == "OP_SERVICE_ACCOUNT_TOKEN"
                    || k == "OP_CONNECT_TOKEN"
                    || k.starts_with("OP_SESSION_")
            });
            named && !v.as_ref().is_empty()
        });
        if present {
            Credentials::Present
        } else {
            Credentials::Absent
        }
    }
}

/// Read the environment's item once, by vault ID and item ID (FR-13). See the module docs.
pub fn read_item(r: &dyn CommandRunner, env: &Environment) -> Result<Item, Error> {
    read_item_with(r, env, Credentials::from_env())
}

/// [`read_item`] with the credential signal supplied by the caller (tests, or S6 if it
/// already knows). A non-zero exit is `Source("op item get failed (exit N)")` unless `creds`
/// is `Absent`, in which case it is `Auth` with the same prefix.
pub fn read_item_with(
    r: &dyn CommandRunner,
    env: &Environment,
    creds: Credentials,
) -> Result<Item, Error> {
    let args = [
        "item",
        "get",
        env.item_id.as_str(),
        "--vault",
        env.vault_id.as_str(),
        "--format",
        "json",
    ];
    let Output { status, stdout } = run_op(r, &args, None)?;
    if status != 0 {
        let m = format!("op item get failed (exit {status})");
        return Err(match creds {
            Credentials::Present => Error::Source(m),
            Credentials::Absent => Error::Auth(format!(
                "{m}; no 1Password credentials in the environment (set \
                 OP_SERVICE_ACCOUNT_TOKEN or run `op signin`; if you use the desktop app \
                 integration, check that it is unlocked)"
            )),
        });
    }
    let fields = parse_fields(&stdout)?;
    Ok(Item {
        fields,
        raw: stdout,
    })
}

/// Add the `missing` (section label, field label, kind) entries to the item as empty fields
/// (FR-19). Sections are matched by label and created (id = label) when absent; every
/// existing section and field is sent back unchanged. Exactly one `op item edit` call, or
/// none when `missing` is empty. An entry that already exists in the item, or is listed
/// twice, is a `Source` error and nothing is written: skeleton never modifies a field.
pub fn write_skeleton(
    r: &dyn CommandRunner,
    env: &Environment,
    item: &Item,
    missing: &[(String, String, Kind)],
) -> Result<(), Error> {
    if missing.is_empty() {
        return Ok(());
    }
    let mut doc = WipeOnDrop(serde_json::from_slice(&item.raw).map_err(|e| json_error(&e))?);
    add_missing(&mut doc.0, missing)?;
    let template = serialize_exact(&doc.0)?;
    drop(doc);

    let args = [
        "item",
        "edit",
        env.item_id.as_str(),
        "--vault",
        env.vault_id.as_str(),
        "--format",
        "json",
    ];
    // The edited item comes back on stdout (with values); it is dropped, zeroized, unread.
    let out = run_op(r, &args, Some(&template))?;
    if out.status != 0 {
        return Err(Error::Source(format!(
            "op item edit failed (exit {})",
            out.status
        )));
    }
    Ok(())
}

fn run_op(r: &dyn CommandRunner, args: &[&str], stdin: Option<&[u8]>) -> Result<Output, Error> {
    r.run(OP, args, stdin, &[]).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => Error::Dependency("op CLI not found on PATH".into()),
        kind => Error::Dependency(format!("failed to run op: {kind}")),
    })
}

/// serde_json's Display can quote input (values), so report only position and category.
fn json_error(e: &serde_json::Error) -> Error {
    Error::Source(format!(
        "op returned malformed item JSON ({:?} error at line {}, column {})",
        e.classify(),
        e.line(),
        e.column()
    ))
}

#[derive(Deserialize)]
struct RawItem {
    #[serde(default)]
    fields: Vec<RawField>,
}

#[derive(Deserialize)]
struct RawField {
    #[serde(default)]
    section: Option<RawSection>,
    #[serde(rename = "type", default)]
    ty: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    value: Option<Concealed>,
}

#[derive(Deserialize)]
struct RawSection {
    #[serde(default)]
    label: Option<String>,
}

/// A JSON string deserialized directly into a [`SecretValue`].
struct Concealed(SecretValue);

impl<'de> Deserialize<'de> for Concealed {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = Concealed;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Concealed, E> {
                Ok(Concealed(SecretValue::new(v.to_owned())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Concealed, E> {
                Ok(Concealed(SecretValue::new(v)))
            }
        }
        d.deserialize_string(V)
    }
}

fn parse_fields(json: &[u8]) -> Result<Vec<ItemField>, Error> {
    let raw: RawItem = serde_json::from_slice(json).map_err(|e| json_error(&e))?;
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for f in raw.fields {
        // Fields outside sections (built-in notesPlain etc.) are not fleet keys (D0 Q1).
        let Some(section) = f.section else { continue };
        let section = match section.label {
            Some(l) if !l.is_empty() => l,
            _ => {
                return Err(Error::Source(format!(
                    "field {} is in a section without a label",
                    f.label
                )));
            }
        };
        if f.label.is_empty() {
            return Err(Error::Source(format!(
                "field without a label in section {section}"
            )));
        }
        let kind = match f.ty.as_str() {
            "CONCEALED" => Kind::Secret,
            "STRING" => Kind::Config,
            _ => {
                return Err(Error::Source(format!(
                    "unsupported field type on {section}/{}",
                    f.label
                )));
            }
        };
        if !seen.insert((section.clone(), f.label.clone())) {
            return Err(Error::Source(format!(
                "duplicate field {section}/{} in item",
                f.label
            )));
        }
        out.push(ItemField {
            section,
            label: f.label,
            kind,
            // D0: an empty field has no `value` key at all.
            value: f
                .value
                .map_or_else(|| SecretValue::new(String::new()), |c| c.0),
        });
    }
    Ok(out)
}

/// A JSON tree whose strings are zeroized when it is dropped.
struct WipeOnDrop(Value);

impl Drop for WipeOnDrop {
    fn drop(&mut self) {
        fn wipe(v: &mut Value) {
            match v {
                Value::String(s) => s.zeroize(),
                Value::Array(a) => a.iter_mut().for_each(wipe),
                Value::Object(m) => m.values_mut().for_each(wipe),
                _ => {}
            }
        }
        wipe(&mut self.0);
    }
}

fn add_missing(doc: &mut Value, missing: &[(String, String, Kind)]) -> Result<(), Error> {
    let obj = doc
        .as_object_mut()
        .ok_or_else(|| Error::Source("op item JSON is not an object".into()))?;

    let str_at = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
    let mut sections: Vec<(String, String)> = Vec::new(); // (id, label)
    if let Some(a) = obj.get("sections").and_then(Value::as_array) {
        for s in a {
            if let (Some(id), Some(label)) = (str_at(s, "id"), str_at(s, "label")) {
                sections.push((id, label));
            }
        }
    }
    let mut field_ids = BTreeSet::new();
    let mut existing = BTreeSet::new();
    if let Some(a) = obj.get("fields").and_then(Value::as_array) {
        for f in a {
            if let Some(id) = str_at(f, "id") {
                field_ids.insert(id);
            }
            if let (Some(s), Some(l)) = (
                f.get("section").and_then(|s| str_at(s, "label")),
                str_at(f, "label"),
            ) {
                existing.insert((s, l));
            }
        }
    }

    let mut listed = BTreeSet::new();
    for (s, l, _) in missing {
        if existing.contains(&(s.clone(), l.clone())) {
            return Err(Error::Source(format!(
                "skeleton: {s}/{l} already exists in the item; not modified"
            )));
        }
        if !listed.insert((s, l)) {
            return Err(Error::Source(format!("skeleton: {s}/{l} listed twice")));
        }
    }

    let mut new_sections = Vec::new();
    let mut new_fields = Vec::new();
    for (section, label, kind) in missing {
        let section_id = match sections.iter().find(|(_, l)| l == section) {
            Some((id, _)) => id.clone(),
            None => {
                let id = unique(section.clone(), |c| sections.iter().any(|(i, _)| i == c));
                sections.push((id.clone(), section.clone()));
                new_sections.push(json!({"id": id, "label": section}));
                id
            }
        };
        let id = unique(format!("{section}_{}", label.to_lowercase()), |c| {
            field_ids.contains(c)
        });
        field_ids.insert(id.clone());
        let ty = match kind {
            Kind::Secret => "CONCEALED",
            Kind::Config => "STRING",
        };
        new_fields.push(json!({
            "id": id,
            "section": {"id": section_id, "label": section},
            "type": ty,
            "label": label,
            "value": "",
        }));
    }

    for (key, add) in [("sections", new_sections), ("fields", new_fields)] {
        let arr = obj
            .entry(key)
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .ok_or_else(|| Error::Source(format!("op item JSON: `{key}` is not an array")))?;
        arr.extend(add);
    }
    Ok(())
}

/// `base`, or `base_2`, `base_3`, ... until `taken` is false.
fn unique(base: String, taken: impl Fn(&str) -> bool) -> String {
    if !taken(&base) {
        return base;
    }
    (2..)
        .map(|n| format!("{base}_{n}"))
        .find(|c| !taken(c))
        .expect("unbounded")
}

/// Serialize into a `Zeroizing` buffer allocated at the exact final size, so the buffer is
/// never reallocated (a realloc would leave an unzeroized copy of the values behind).
fn serialize_exact(v: &Value) -> Result<Zeroizing<Vec<u8>>, Error> {
    struct Count(usize);
    impl Write for Count {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0 += b.len();
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let fail = |_| Error::Source("could not serialize the item template".into());
    let mut n = Count(0);
    serde_json::to_writer(&mut n, v).map_err(fail)?;
    let mut buf = Zeroizing::new(Vec::with_capacity(n.0));
    serde_json::to_writer(&mut *buf, v).map_err(fail)?;
    debug_assert_eq!(buf.len(), n.0);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io;

    use serde_json::{Value, json};

    use super::*;
    use crate::runner::Output;
    use crate::runner::fake::FakeRunner;

    const GET_ARGS: [&str; 7] = ["item", "get", "istg", "--vault", "vstg", "--format", "json"];
    const EDIT_ARGS: [&str; 7] = [
        "item", "edit", "istg", "--vault", "vstg", "--format", "json",
    ];

    fn test_env() -> Environment {
        Environment {
            vault_id: "vstg".into(),
            item_id: "istg".into(),
            fly_app: "fleet-staging".into(),
            secret_name_template: "FLEET__{PRODUCT}__{KEY}".into(),
            modes: BTreeMap::new(),
        }
    }

    /// A field inside a section, in the shape of tests/fixtures/op_item.json.
    fn sf(id: &str, sec_id: &str, sec_label: &str, ty: &str, label: &str, value: &str) -> Value {
        json!({
            "id": id,
            "section": {"id": sec_id, "label": sec_label},
            "type": ty,
            "label": label,
            "value": value,
            "reference": format!("op://vstg/istg/{sec_label}/{label}"),
        })
    }

    fn notes() -> Value {
        json!({
            "id": "notesPlain", "type": "STRING", "purpose": "NOTES", "label": "notesPlain",
            "reference": "op://vstg/istg/notesPlain"
        })
    }

    fn item_json(sections: Value, fields: Vec<Value>) -> Vec<u8> {
        serde_json::to_vec_pretty(&json!({
            "id": "istg",
            "title": "fleet",
            "version": 7,
            "vault": {"id": "vstg", "name": "fleet-staging"},
            "category": "SECURE_NOTE",
            "last_edited_by": "U123",
            "created_at": "2026-10-07T03:53:02Z",
            "updated_at": "2026-10-07T07:02:46Z",
            "sections": sections,
            "fields": fields,
        }))
        .unwrap()
    }

    fn allumata_item() -> Vec<u8> {
        item_json(
            json!([{"id": "allumata", "label": "allumata"}]),
            vec![
                notes(),
                sf(
                    "a1",
                    "allumata",
                    "allumata",
                    "CONCEALED",
                    "OPENAI_API_KEY",
                    "sk-FIXTURE-openai",
                ),
                sf(
                    "a2",
                    "allumata",
                    "allumata",
                    "STRING",
                    "SIGNUP_POLICY",
                    "invite_only",
                ),
            ],
        )
    }

    fn read(bytes: Vec<u8>) -> Item {
        let r = FakeRunner::new([Output::success(bytes)]);
        read_item_with(&r, &test_env(), Credentials::Present).unwrap()
    }

    fn read_err(bytes: Vec<u8>) -> Error {
        let r = FakeRunner::new([Output::success(bytes)]);
        read_item_with(&r, &test_env(), Credentials::Present).unwrap_err()
    }

    fn find<'a>(fields: &'a [ItemField], section: &str, label: &str) -> &'a ItemField {
        fields
            .iter()
            .find(|f| f.section == section && f.label == label)
            .unwrap_or_else(|| panic!("no field {section}/{label}"))
    }

    // ---------- read_item ----------

    #[test]
    fn reads_whole_item_once_by_id() {
        let r = FakeRunner::new([Output::success(allumata_item())]);
        let item = read_item_with(&r, &test_env(), Credentials::Present).unwrap();
        let calls = r.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].program, "op");
        assert_eq!(calls[0].args, GET_ARGS);
        assert!(calls[0].stdin.is_none());
        let cfg = find(&item.fields, "allumata", "SIGNUP_POLICY");
        assert_eq!(
            (cfg.kind, cfg.value.expose()),
            (Kind::Config, "invite_only")
        );
        let sec = find(&item.fields, "allumata", "OPENAI_API_KEY");
        assert_eq!(
            (sec.kind, sec.value.expose()),
            (Kind::Secret, "sk-FIXTURE-openai")
        );
        assert_eq!(item.fields.len(), 2);
    }

    #[test]
    fn parses_real_d0_fixture_shape() {
        let item = read(include_bytes!("../../tests/fixtures/op_item.json").to_vec());
        assert_eq!(
            item.fields.len(),
            4,
            "notesPlain dropped, 4 sectioned fields"
        );
        for s in ["probe_a", "probe_b"] {
            let k = find(&item.fields, s, "API_KEY");
            assert_eq!((k.kind, k.value.expose()), (Kind::Secret, "<v>"));
            assert_eq!(find(&item.fields, s, "BASE_URL").kind, Kind::Config);
        }
    }

    #[test]
    fn fields_outside_sections_are_ignored() {
        let mut n = notes();
        n["value"] = json!("NOTE-MARKER-not-a-key");
        let item = read(item_json(
            json!([{"id": "allumata", "label": "allumata"}]),
            vec![
                n,
                // No section and a type we would otherwise reject: still ignored, not an error.
                json!({"id": "otp", "type": "OTP", "label": "one_time", "value": "otpauth://x"}),
                json!({"id": "pw", "type": "CONCEALED", "purpose": "PASSWORD", "label": "password", "value": "pw-FIXTURE"}),
                sf(
                    "a1",
                    "allumata",
                    "allumata",
                    "CONCEALED",
                    "OPENAI_API_KEY",
                    "sk-FIXTURE-openai",
                ),
            ],
        ));
        let labels: Vec<(&str, &str)> = item
            .fields
            .iter()
            .map(|f| (f.section.as_str(), f.label.as_str()))
            .collect();
        assert_eq!(labels, [("allumata", "OPENAI_API_KEY")]);
    }

    #[test]
    fn missing_value_is_empty_not_an_error() {
        let mut f = sf(
            "a1",
            "allumata",
            "allumata",
            "CONCEALED",
            "OPENAI_API_KEY",
            "",
        );
        f.as_object_mut().unwrap().remove("value");
        let item = read(item_json(
            json!([{"id": "allumata", "label": "allumata"}]),
            vec![f],
        ));
        assert_eq!(item.fields[0].value.expose(), "");
    }

    #[test]
    fn matches_section_by_label_not_id() {
        let item = read(item_json(
            json!([{"id": "x7f3kq", "label": "allumata"}]),
            vec![sf(
                "rnd1",
                "x7f3kq",
                "allumata",
                "STRING",
                "SIGNUP_POLICY",
                "open",
            )],
        ));
        find(&item.fields, "allumata", "SIGNUP_POLICY");
    }

    #[test]
    fn unsupported_type_in_section_is_source_error_naming_field() {
        let e = read_err(item_json(
            json!([{"id": "allumata", "label": "allumata"}]),
            vec![sf(
                "a1",
                "allumata",
                "allumata",
                "URL",
                "BASE_URL",
                "https://VALUE-MARKER",
            )],
        ));
        match e {
            Error::Source(m) => {
                assert_eq!(m, "unsupported field type on allumata/BASE_URL");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn duplicate_section_and_label_is_source_error() {
        let e = read_err(item_json(
            json!([{"id": "s1", "label": "allumata"}, {"id": "s2", "label": "allumata"}]),
            vec![
                sf(
                    "a1",
                    "s1",
                    "allumata",
                    "CONCEALED",
                    "OPENAI_API_KEY",
                    "sk-FIXTURE-old",
                ),
                sf(
                    "a2",
                    "s2",
                    "allumata",
                    "CONCEALED",
                    "OPENAI_API_KEY",
                    "sk-FIXTURE-new",
                ),
            ],
        ));
        match e {
            Error::Source(m) => {
                assert_eq!(m, "duplicate field allumata/OPENAI_API_KEY in item");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn non_zero_exit_maps_to_source_error_without_stderr() {
        let r = FakeRunner::new([Output::failure(1)]);
        let e = read_item_with(&r, &test_env(), Credentials::Present).unwrap_err();
        assert!(
            matches!(&e, Error::Source(m) if m == "op item get failed (exit 1)"),
            "{e:?}"
        );
    }

    #[test]
    fn non_zero_exit_without_any_credentials_is_auth() {
        let r = FakeRunner::new([Output::failure(1)]);
        let e = read_item_with(&r, &test_env(), Credentials::Absent).unwrap_err();
        match e {
            Error::Auth(m) => assert!(m.starts_with("op item get failed (exit 1)"), "{m}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn credentials_rule_is_explicit_and_value_free() {
        let none: [(&str, &str); 0] = [];
        assert_eq!(Credentials::from_vars(none), Credentials::Absent);
        assert_eq!(
            Credentials::from_vars([("PATH", "/bin"), ("OP_SERVICE_ACCOUNT_TOKEN", "")]),
            Credentials::Absent,
            "empty token is no token"
        );
        for name in [
            "OP_SERVICE_ACCOUNT_TOKEN",
            "OP_CONNECT_TOKEN",
            "OP_SESSION_my_team",
        ] {
            assert_eq!(
                Credentials::from_vars([(name, "tok")]),
                Credentials::Present,
                "{name}"
            );
        }
    }

    #[test]
    fn missing_op_binary_is_dependency_error() {
        let r = FakeRunner::default();
        r.push_io_error(io::ErrorKind::NotFound);
        let e = read_item_with(&r, &test_env(), Credentials::Present).unwrap_err();
        assert!(
            matches!(&e, Error::Dependency(m) if m.contains("op")),
            "{e:?}"
        );
    }

    #[test]
    fn malformed_json_error_never_echoes_content() {
        // A non-string value makes serde_json's own message quote it; ours must not.
        let mut f = sf("a1", "allumata", "allumata", "CONCEALED", "K", "");
        f["value"] = json!(987654321123u64);
        for bytes in [
            item_json(json!([{"id": "allumata", "label": "allumata"}]), vec![f]),
            b"{\"fields\": [ sk-FIXTURE-garbage".to_vec(),
        ] {
            let e = read_err(bytes);
            let s = format!("{e} {e:?}");
            assert!(matches!(e, Error::Source(_)), "{s}");
            assert!(
                !s.contains("987654321123") && !s.contains("sk-FIXTURE"),
                "{s}"
            );
        }
    }

    #[test]
    fn debug_never_prints_values_or_raw_json() {
        let item = read(allumata_item());
        let d = format!("{item:?} {item:#?}");
        assert!(
            !d.contains("sk-FIXTURE") && !d.contains("invite_only"),
            "{d}"
        );
        assert!(!d.contains("op://"), "raw JSON leaked: {d}");
        assert!(d.contains("OPENAI_API_KEY"), "names are fine: {d}");
    }

    // ---------- write_skeleton ----------

    fn edit_stdin(r: &FakeRunner) -> Value {
        let calls = r.calls.borrow();
        assert_eq!(calls.len(), 1, "skeleton write is exactly one call");
        assert_eq!(calls[0].program, "op");
        assert_eq!(calls[0].args, EDIT_ARGS);
        serde_json::from_slice(calls[0].stdin.as_ref().expect("template on stdin")).unwrap()
    }

    fn tpl_field<'a>(tpl: &'a Value, section: &str, label: &str) -> &'a Value {
        tpl["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["label"] == label && f["section"]["label"] == section)
            .unwrap_or_else(|| panic!("no template field {section}/{label}"))
    }

    #[test]
    fn skeleton_sends_full_item_on_stdin_with_empty_values() {
        let original: Value = serde_json::from_slice(&allumata_item()).unwrap();
        let item = read(allumata_item());
        let r = FakeRunner::new([Output::success(allumata_item())]);
        write_skeleton(
            &r,
            &test_env(),
            &item,
            &[
                ("allumata".into(), "STRIPE_SECRET_KEY".into(), Kind::Secret),
                ("signoz".into(), "OTEL_ENDPOINT".into(), Kind::Config),
            ],
        )
        .unwrap();
        assert!(!r.argv_contains("sk-FIXTURE") && !r.argv_contains("invite_only"));
        let tpl = edit_stdin(&r);

        // Every existing top-level key and every existing field survives unchanged.
        for (k, v) in original.as_object().unwrap() {
            if k != "fields" && k != "sections" {
                assert_eq!(&tpl[k], v, "top-level {k} changed");
            }
        }
        let fields = tpl["fields"].as_array().unwrap();
        for f in original["fields"].as_array().unwrap() {
            assert!(
                fields.contains(f),
                "existing field changed or dropped: {}",
                f["id"]
            );
        }
        assert_eq!(
            tpl_field(&tpl, "allumata", "OPENAI_API_KEY")["value"],
            "sk-FIXTURE-openai"
        );
        assert_eq!(fields.len(), 5);

        let s = tpl_field(&tpl, "allumata", "STRIPE_SECRET_KEY");
        assert_eq!((&s["type"], &s["value"]), (&json!("CONCEALED"), &json!("")));
        assert_eq!(s["section"]["id"], "allumata");
        let c = tpl_field(&tpl, "signoz", "OTEL_ENDPOINT");
        assert_eq!((&c["type"], &c["value"]), (&json!("STRING"), &json!("")));

        // The new section is created by label; the existing one is kept, not duplicated.
        let sections = tpl["sections"].as_array().unwrap();
        assert_eq!(
            sections
                .iter()
                .map(|s| s["label"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["allumata", "signoz"]
        );
        let sz = sections.iter().find(|s| s["label"] == "signoz").unwrap();
        assert_eq!(c["section"]["id"], sz["id"]);

        // Field ids are unique.
        let mut ids: Vec<&str> = fields.iter().map(|f| f["id"].as_str().unwrap()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), fields.len());
    }

    #[test]
    fn skeleton_reuses_existing_section_id_from_the_ui() {
        let bytes = item_json(
            json!([{"id": "x7f3kq", "label": "allumata"}]),
            vec![sf(
                "rnd1",
                "x7f3kq",
                "allumata",
                "STRING",
                "SIGNUP_POLICY",
                "open",
            )],
        );
        let item = read(bytes);
        let r = FakeRunner::new([Output::success("{}")]);
        let missing = [(
            "allumata".to_string(),
            "OPENAI_API_KEY".to_string(),
            Kind::Secret,
        )];
        write_skeleton(&r, &test_env(), &item, &missing).unwrap();
        let tpl = edit_stdin(&r);
        assert_eq!(tpl["sections"].as_array().unwrap().len(), 1);
        assert_eq!(
            tpl_field(&tpl, "allumata", "OPENAI_API_KEY")["section"]["id"],
            "x7f3kq"
        );
    }

    #[test]
    fn skeleton_field_ids_avoid_existing_ids() {
        let bytes = item_json(
            json!([{"id": "allumata", "label": "allumata"}]),
            vec![sf(
                "allumata_openai_api_key",
                "allumata",
                "allumata",
                "STRING",
                "OTHER",
                "x",
            )],
        );
        let item = read(bytes);
        let r = FakeRunner::new([Output::success("{}")]);
        let missing = [(
            "allumata".to_string(),
            "OPENAI_API_KEY".to_string(),
            Kind::Secret,
        )];
        write_skeleton(&r, &test_env(), &item, &missing).unwrap();
        let tpl = edit_stdin(&r);
        let id = tpl_field(&tpl, "allumata", "OPENAI_API_KEY")["id"]
            .as_str()
            .unwrap()
            .to_string();
        assert_ne!(id, "allumata_openai_api_key");
    }

    #[test]
    fn skeleton_with_nothing_missing_makes_no_call() {
        let item = read(allumata_item());
        let r = FakeRunner::default();
        write_skeleton(&r, &test_env(), &item, &[]).unwrap();
        assert!(r.calls.borrow().is_empty());
    }

    #[test]
    fn skeleton_refuses_to_touch_an_existing_field() {
        let item = read(allumata_item());
        let r = FakeRunner::default();
        let missing = [(
            "allumata".to_string(),
            "SIGNUP_POLICY".to_string(),
            Kind::Secret,
        )];
        let e = write_skeleton(&r, &test_env(), &item, &missing).unwrap_err();
        assert!(
            matches!(&e, Error::Source(m) if m.contains("allumata/SIGNUP_POLICY")),
            "{e:?}"
        );
        assert!(r.calls.borrow().is_empty());
    }

    #[test]
    fn skeleton_uses_raw_json_so_fields_can_be_moved_out_first() {
        let mut item = read(allumata_item());
        let fields = std::mem::take(&mut item.fields);
        assert_eq!(fields.len(), 2);
        let r = FakeRunner::new([Output::success("{}")]);
        let missing = [("allumata".to_string(), "NEW_KEY".to_string(), Kind::Config)];
        write_skeleton(&r, &test_env(), &item, &missing).unwrap();
        let tpl = edit_stdin(&r);
        assert_eq!(
            tpl_field(&tpl, "allumata", "OPENAI_API_KEY")["value"],
            "sk-FIXTURE-openai"
        );
    }

    #[test]
    fn skeleton_edit_failure_is_source_error() {
        let item = read(allumata_item());
        let r = FakeRunner::new([Output::failure(2)]);
        let missing = [("allumata".to_string(), "NEW_KEY".to_string(), Kind::Config)];
        let e = write_skeleton(&r, &test_env(), &item, &missing).unwrap_err();
        assert!(
            matches!(&e, Error::Source(m) if m == "op item edit failed (exit 2)"),
            "{e:?}"
        );
    }
}
