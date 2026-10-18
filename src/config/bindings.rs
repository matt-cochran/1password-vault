//! `secrets.bindings.toml` and the apply record (D-G): the 1Password ids live beside the
//! contract, not in it.
//!
//! The bindings file sits next to `secrets.toml` and holds one sorted line per id, written
//! as a dotted key (`environments.prod.boundaries.web.vault_id = "…"`), so two branches that
//! add different ids merge by union. [`load`](super::load) refuses an id still written inline
//! and names the one-way move (`opv propose structure`, then `opv apply`);
//! [`load_for_move`](super::load_for_move) is the only reader that accepts inline ids.
//!
//! A file of names and ids, never secret values: no error or message carries a value.

use std::collections::BTreeMap;
use std::path::Path;

use sha2::{Digest, Sha256};
use toml::de::{DeTable, DeValue};
use toml_edit::{DocumentMut, Item, Table, TableLike, Value};

use crate::cause::{Cause, ConfigSource, FieldRule, GivenBy, PatternId};
use crate::error::Error;

use super::{Doc, is_id, toml_invalid};

/// The bindings file's name, beside `secrets.toml`.
pub const FILE: &str = "secrets.bindings.toml";

/// The apply record's path under the project: the plan last applied and the digests of the
/// two files it wrote.
pub const APPLIED: &str = ".opv/applied.json";

/// The ids in `secrets.bindings.toml`, keyed by the dotted path of the field they fill in
/// `secrets.toml`. A `BTreeMap`, so the writer's order is the canonical sorted order and a
/// reader never depends on file order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bindings {
    ids: BTreeMap<String, String>,
}

impl Bindings {
    /// True when no id is recorded.
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// The id at `path` (a dotted key), when it is recorded.
    pub fn get(&self, path: &str) -> Option<&str> {
        self.ids.get(path).map(String::as_str)
    }

    /// Record `id` at `path`, replacing any earlier id there.
    pub fn insert(&mut self, path: impl Into<String>, id: impl Into<String>) -> Option<String> {
        self.ids.insert(path.into(), id.into())
    }

    /// The union of two bindings: every id of either; `other` wins where both record a path
    /// (so a later file may correct an earlier one).
    pub fn union(mut self, other: Bindings) -> Bindings {
        self.ids.extend(other.ids);
        self
    }

    /// The canonical text: one sorted line per id, a dotted key and a quoted id.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for (path, id) in &self.ids {
            out.push_str(path);
            out.push_str(" = ");
            out.push_str(&Value::from(id.as_str()).to_string());
            out.push('\n');
        }
        out
    }

    /// Parse the bindings file's text. An unknown key or a value that is not an id is a
    /// [`Cause::ConfigInvalid`] naming that key: nothing here decides what an id *means*.
    pub fn parse(text: &str) -> Result<Bindings, Error> {
        let doc = Doc::parse(text).map_err(|e| toml_invalid(text, &e))?;
        let mut ids = BTreeMap::new();
        let mut prefix = Vec::new();
        flatten(&doc, doc.root.get_ref(), &mut prefix, &mut ids)?;
        Ok(Bindings { ids })
    }
}

/// The inline ids in `text`, whatever their value: the fields a move takes out of the
/// contract. `parse` still validates the values.
pub fn inline_ids(text: &str) -> Result<Bindings, Error> {
    let doc = Doc::parse(text).map_err(|e| toml_invalid(text, &e))?;
    let ids = inline_values(doc.root.get_ref())
        .into_iter()
        .filter(|(path, _)| recognized_path(path))
        .map(|(path, id)| (path.join("."), id))
        .collect();
    Ok(Bindings { ids })
}

/// `Err` naming an inline id when `text` still writes one: ids are one-way out of the
/// contract, and the fix names the move that puts them in the sibling file.
pub fn refuse_inline(text: &str) -> Result<(), Error> {
    let doc = Doc::parse(text).map_err(|e| toml_invalid(text, &e))?;
    let Some((path, _)) = inline_values(doc.root.get_ref())
        .into_iter()
        .find(|(path, _)| recognized_path(path))
    else {
        return Ok(());
    };
    let refs: Vec<&str> = path.iter().map(String::as_str).collect();
    Err(doc.invalid(
        &refs,
        FieldRule::RemovedForm {
            form: "an inline 1Password id",
            replacement: "secrets.bindings.toml (run opv propose structure, then opv apply)"
                .to_string(),
        },
    ))
}

/// Read the bindings file at `path`. An absent file records no ids.
pub fn read(path: &Path) -> Result<Bindings, Error> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Bindings::default()),
        Err(e) => return Err(unreadable(path, &e)),
    };
    Bindings::parse(&text).map_err(|e| relocate(e, &text, path))
}

/// Read the bindings sibling of the contract at `config_path`
/// (`<dir>/secrets.bindings.toml`); an absent file records no ids.
pub fn read_sibling(config_path: &Path) -> Result<Bindings, Error> {
    let dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    read(&dir.join(FILE))
}

/// `text` with every id of `bindings` filled into it, keeping the contract's own formatting
/// and comments. A text that does not parse is returned unchanged, so `parse` reports its
/// syntax error rather than a merge failure.
pub fn merge(text: &str, bindings: &Bindings) -> String {
    if bindings.is_empty() {
        return text.to_string();
    }
    let Ok(mut doc) = text.parse::<DocumentMut>() else {
        return text.to_string();
    };
    // A boundary's vault before its item, as people write them; otherwise sorted.
    let mut ids: Vec<(&String, &String)> = bindings.ids.iter().collect();
    ids.sort_by_key(|(path, _)| {
        let (parent, last) = path.rsplit_once('.').unwrap_or(("", path.as_str()));
        (parent.to_string(), last != "vault_id", last.to_string())
    });
    for (path, id) in ids {
        let parts: Vec<&str> = path.split('.').collect();
        let Some((last, prefix)) = parts.split_last() else {
            continue;
        };
        if let Some(table) = table_at_mut(&mut doc, prefix) {
            table.insert(last, Item::Value(Value::from(id.as_str())));
        }
    }
    doc.to_string()
}

/// `text` with every inline id taken out, and those ids: the contract and the bindings a
/// writer saves (D-G). The tables that held the ids stay (`boundaries.web = {}`), so the
/// contract still declares them and a later [`merge`] fills them in place. A text that does
/// not parse is returned unchanged with no ids, so `parse` reports its syntax error.
pub fn split(text: &str) -> (String, Bindings) {
    let Ok(mut doc) = text.parse::<DocumentMut>() else {
        return (text.to_string(), Bindings::default());
    };
    let mut ids = BTreeMap::new();
    let mut prefix = Vec::new();
    if !take_ids(doc.as_table_mut(), &mut prefix, &mut ids) {
        return (text.to_string(), Bindings::default());
    }
    (doc.to_string(), Bindings { ids })
}

/// Write `bindings` as the sibling of the contract at `config_path`, in the canonical sorted
/// form, replacing the file. No file is created for no ids; an existing file is emptied, so
/// it never holds an id the contract no longer has.
pub fn write_sibling(config_path: &Path, bindings: &Bindings) -> Result<(), Error> {
    let dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    let path = dir.join(FILE);
    let text = bindings.render();
    match std::fs::read_to_string(&path) {
        Ok(now) if now == text => return Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && bindings.is_empty() => {
            return Ok(());
        }
        _ => {}
    }
    crate::config_edit::write_atomic(&path, &text, || Ok(()))
}

/// Write `text` as the contract at `path`, its inline ids moved to the sibling bindings file
/// (D-G): the two files a project keeps. Replaces both.
pub fn write_split(path: &Path, text: &str) -> Result<(), Error> {
    let (contract, ids) = split(text);
    crate::config_edit::write_atomic(path, &contract, || Ok(()))?;
    write_sibling(path, &ids)
}

/// For each line of `merged` (the contract with ids filled in by [`merge`]), the line of
/// `original` it came from: `None` for a line `merge` inserted. `merge` only inserts whole
/// lines (a key at the end of a table) or extends a line in place (an inline table, whose
/// key stays the same), so the two texts align line by line.
pub fn original_lines(original: &str, merged: &str) -> Vec<Option<usize>> {
    let a: Vec<&str> = original.lines().collect();
    let b: Vec<&str> = merged.lines().collect();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    for line in b {
        let extended = a.get(i).is_some_and(|was| {
            *was != line
                && was.contains('{')
                && was.split_once('=').map(|(k, _)| k) == line.split_once('=').map(|(k, _)| k)
        });
        if a.get(i) == Some(&line) || extended {
            out.push(Some(i));
            i += 1;
        } else {
            out.push(None);
        }
    }
    out
}

/// The apply record: the plan last applied, and the sha256 of the contract and bindings
/// files it wrote, so a later run can tell whether either changed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyRecord {
    pub plan_id: String,
    pub contract_digest: String,
    pub bindings_digest: String,
}

/// The lowercase hex sha256 of `bytes`, the form both record digests take.
pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Read the apply record at `path`; `None` when it has not been written.
pub fn read_record(path: &Path) -> Result<Option<ApplyRecord>, Error> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(unreadable(path, &e)),
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| bug("config::bindings::read_record"))
}

/// Write the apply record to `path`, creating its folder. Replaces any earlier record.
pub fn write_record(path: &Path, record: &ApplyRecord) -> Result<(), Error> {
    let text =
        serde_json::to_string_pretty(record).map_err(|_| bug("config::bindings::write_record"))?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| unreadable(path, &e))?;
    }
    std::fs::write(path, text).map_err(|e| unreadable(path, &e))
}

/// The four id families of the contract (D-G): a boundary's vault/item, a target's state
/// vault, and a target's per-product delivery item. Anything else is not a binding.
fn recognized(path: &[&str]) -> bool {
    matches!(
        path,
        ["environments", _, "boundaries", _, "vault_id" | "item_id"]
            | ["environments", _, "targets", _, "state_vault_id"]
            | ["environments", _, "targets", _, "delivery_items", _]
    )
}

fn recognized_path(path: &[String]) -> bool {
    let refs: Vec<&str> = path.iter().map(String::as_str).collect();
    recognized(&refs)
}

/// Walk the parsed document, collecting every leaf under the `recognized` families as
/// `(dotted path, raw value)` in file order.
fn inline_values(table: &DeTable<'_>) -> Vec<(Vec<String>, String)> {
    let mut out = Vec::new();
    let mut prefix = Vec::new();
    collect(table, &mut prefix, &mut out);
    out
}

fn collect(table: &DeTable<'_>, prefix: &mut Vec<String>, out: &mut Vec<(Vec<String>, String)>) {
    for (name, value) in table.iter() {
        prefix.push(name.get_ref().to_string());
        match value.get_ref() {
            DeValue::Table(inner) => collect(inner, prefix, out),
            other => out.push((
                prefix.clone(),
                other.as_str().unwrap_or_default().to_string(),
            )),
        }
        prefix.pop();
    }
}

/// Remove every recognized id leaf under `table` into `ids`, recursing into tables and
/// inline tables; true when one was removed.
fn take_ids(
    table: &mut dyn TableLike,
    prefix: &mut Vec<String>,
    ids: &mut BTreeMap<String, String>,
) -> bool {
    let mut removed = false;
    let keys: Vec<String> = table.iter().map(|(k, _)| k.to_string()).collect();
    for key in keys {
        prefix.push(key.clone());
        let refs: Vec<&str> = prefix.iter().map(String::as_str).collect();
        let Some(item) = table.get_mut(&key) else {
            prefix.pop();
            continue;
        };
        if let Some(inner) = item.as_table_like_mut() {
            removed |= take_ids(inner, prefix, ids);
        } else if recognized(&refs)
            && let Some(id) = item.as_str()
        {
            // An empty id is one not recorded yet: nothing to bind.
            if !id.is_empty() {
                ids.insert(prefix.join("."), id.to_string());
            }
            table.remove(&key);
            removed = true;
        }
        prefix.pop();
    }
    removed
}

/// Validate the bindings file: every leaf must be a recognized id field holding an id.
fn flatten(
    doc: &Doc<'_>,
    table: &DeTable<'_>,
    prefix: &mut Vec<String>,
    ids: &mut BTreeMap<String, String>,
) -> Result<(), Error> {
    for (name, value) in table.iter() {
        prefix.push(name.get_ref().to_string());
        let refs: Vec<&str> = prefix.iter().map(String::as_str).collect();
        match value.get_ref() {
            DeValue::Table(inner) => flatten(doc, inner, prefix, ids)?,
            other => match other.as_str() {
                Some(_) if !recognized(&refs) => {
                    return Err(doc.invalid(&refs, FieldRule::Unknown { suggestion: None }));
                }
                Some(id) if !is_id(id) => {
                    return Err(doc.invalid(&refs, FieldRule::Pattern { id: PatternId::Id }));
                }
                Some(id) => {
                    ids.insert(prefix.join("."), id.to_string());
                }
                None => {
                    return Err(doc.invalid(
                        &refs,
                        FieldRule::Type {
                            expected: "a 1Password id",
                        },
                    ));
                }
            },
        }
        prefix.pop();
    }
    Ok(())
}

/// A table at `path` in `doc`, creating missing intermediate tables as implicit ones (`ad
/// hoc` access to a nested key, as `config_edit` does). `None` when a path segment holds a
/// non-table value; `parse` then reports that in the contract.
fn table_at_mut<'a>(doc: &'a mut DocumentMut, path: &[&str]) -> Option<&'a mut dyn TableLike> {
    let mut t: &mut dyn TableLike = doc.as_table_mut();
    for seg in path {
        if t.get(seg).is_none() {
            let mut implicit = Table::new();
            implicit.set_implicit(true);
            t.insert(seg, Item::Table(implicit));
        }
        t = t.get_mut(seg)?.as_table_like_mut()?;
    }
    Some(t)
}

fn relocate(e: Error, text: &str, path: &Path) -> Error {
    super::locate::relocate_at(
        e,
        text,
        ConfigSource::File {
            path: path.to_path_buf(),
            given_by: GivenBy::Discovered,
        },
    )
}

fn unreadable(path: &Path, e: &std::io::Error) -> Error {
    Cause::ConfigUnreadable {
        path: path.to_path_buf(),
        io: e.kind().into(),
        given_by: GivenBy::Discovered,
    }
    .into()
}

fn bug(site: &'static str) -> Error {
    Cause::Bug { site }.into()
}

#[cfg(test)]
#[path = "bindings_tests.rs"]
mod tests;
