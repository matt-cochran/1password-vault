//! Editing an existing `secrets.toml` in place (H2): `opv add` and `opv init --add-env`.
//!
//! Edits go through `toml_edit`, so the file's comments, blank lines and order are kept and
//! only the added lines appear in a diff. Callers validate the edited text with the same
//! loader as a hand-written file ([`crate::config::parse`]) before writing it with
//! [`replace`]. The file holds IDs, names, kinds and rules, never a value, so it is not a
//! secret file; it is still written atomically so it is never seen half-written.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use toml_edit::{Array, DocumentMut, InlineTable, Item, Table, TableLike, Value};

use crate::cause::{Cause, ConfigSource, DottedPath, FieldRule, GivenBy, NameKind, NotEditable};
use crate::error::Error;

/// A new key's table: `kind`, `environments`, then the optional fields.
#[derive(Debug, Clone, Copy)]
pub struct NewKey<'a> {
    /// `secret` or `config`.
    pub kind: &'a str,
    pub environments: &'a [String],
    /// `rules = { … }` entries, in the order given.
    pub rules: &'a [(String, Value)],
    pub guidance: Option<&'a str>,
    pub immutable: bool,
    /// `from = "<product>/<KEY>"`: a shared key (FR-45).
    pub from: Option<&'a str>,
    /// `personal = true` (FR-55).
    pub personal: bool,
    /// `allow_same_value = true` (#92).
    pub allow_same_value: bool,
    /// `except = { <env> = "<reason>" }`: environments the key is present in but needs no
    /// value in (Part V, `presence`), in the order given.
    pub except: &'a [(String, String)],
    /// `source = "person" | "generated" | "derived"`.
    pub source: Option<&'a str>,
    /// A catalog shape name: its `Rules` are written as `rules = { … }`.
    pub shape: Option<&'a str>,
    /// `expires = "<date>"`.
    pub expires: Option<&'a str>,
    /// `lifecycle = "active" | "retiring" | "retired"`.
    pub lifecycle: Option<&'a str>,
}

/// A parsed `secrets.toml` that keeps its formatting.
#[derive(Debug, Clone)]
pub struct ConfigDoc {
    doc: DocumentMut,
    /// Where the text came from, for the catalog's source-aware wording (X16, 03.18);
    /// `secrets.toml` until the caller says otherwise ([`ConfigDoc::parse_in`]).
    source: Option<ConfigSource>,
}

/// `products.<product>.keys`.
fn keys_path(product: &str) -> Vec<&str> {
    vec!["products", product, "keys"]
}

impl ConfigDoc {
    pub fn parse(text: &str) -> Result<Self, Error> {
        Self::parse_text(text, None)
    }

    /// [`ConfigDoc::parse`] of the text of `source` (a file or a manifest): its errors name
    /// that source and its route (`opv config edit` for a manifest), never "secrets.toml".
    pub fn parse_in(text: &str, source: ConfigSource) -> Result<Self, Error> {
        Self::parse_text(text, Some(source))
    }

    fn parse_text(text: &str, source: Option<ConfigSource>) -> Result<Self, Error> {
        match text.parse::<DocumentMut>() {
            Ok(doc) => Ok(Self { doc, source }),
            Err(e) => Err(Cause::ConfigInvalid {
                source: source.unwrap_or_else(default_source),
                at: crate::config_store::location(text, e.span()),
                field: DottedPath(vec!["the TOML".into()]),
                rule: FieldRule::Syntax,
            }
            .into()),
        }
    }

    /// Where the text came from.
    fn source(&self) -> ConfigSource {
        self.source.clone().unwrap_or_else(default_source)
    }

    /// Environment names, in file order.
    pub fn environments(&self) -> Vec<String> {
        self.doc
            .get("environments")
            .and_then(Item::as_table_like)
            .map(|t| t.iter().map(|(k, _)| k.to_string()).collect())
            .unwrap_or_default()
    }

    fn table_at(&self, path: &[&str]) -> Option<&dyn TableLike> {
        let mut t: &dyn TableLike = self.doc.as_table();
        for seg in path {
            t = t.get(seg)?.as_table_like()?;
        }
        Some(t)
    }

    fn table_at_mut(&mut self, path: &[&str]) -> Option<&mut dyn TableLike> {
        let mut t: &mut dyn TableLike = self.doc.as_table_mut();
        for seg in path {
            t = t.get_mut(seg)?.as_table_like_mut()?;
        }
        Some(t)
    }

    fn key(&self, product: &str, key: &str) -> Option<&dyn TableLike> {
        self.table_at(&keys_path(product))?
            .get(key)?
            .as_table_like()
    }

    /// True when `product/key` is declared.
    pub fn has_key(&self, product: &str, key: &str) -> bool {
        self.key(product, key).is_some()
    }

    /// Declare `product/key`, after the product's last key (a new product goes last).
    /// Keys written as inline tables (`K = { kind = … }`) get one more inline table.
    pub fn add_key(&mut self, product: &str, key: &str, k: &NewKey<'_>) -> Result<(), Error> {
        let path = keys_path(product);
        let source = self.source();
        let mut t: &mut dyn TableLike = self.doc.as_table_mut();
        for seg in &path {
            if t.get(seg).is_none() {
                let mut implicit = Table::new();
                implicit.set_implicit(true);
                t.insert(seg, Item::Table(implicit));
            }
            t = t
                .get_mut(seg)
                .and_then(Item::as_table_like_mut)
                .ok_or_else(|| layout_error(source.clone(), &path.join(".")))?;
        }
        let inline = t.iter().any(|(_, v)| v.is_inline_table());
        let mut fields: Vec<(&str, Value)> = vec![("kind", Value::from(k.kind))];
        // An empty list means every environment: write no `environments` line at all.
        if !k.environments.is_empty() {
            fields.push(("environments", env_array(k.environments)));
        }
        if !k.except.is_empty() {
            let mut except: InlineTable = k
                .except
                .iter()
                .map(|(env, reason)| (env.as_str(), reason.as_str()))
                .collect();
            except.fmt();
            fields.push(("except", Value::InlineTable(except)));
        }
        // A shape's catalog rules, then any explicit `--rule` (which wins on a clash).
        let mut rules: Vec<(String, Value)> = k.shape.map(shape_rules).unwrap_or_default();
        rules.extend(k.rules.iter().cloned());
        if !rules.is_empty() {
            let mut table: InlineTable =
                rules.iter().map(|(n, v)| (n.as_str(), v.clone())).collect();
            table.fmt();
            fields.push(("rules", Value::InlineTable(table)));
        }
        if let Some(source) = k.source {
            fields.push(("source", Value::from(source)));
        }
        if let Some(expires) = k.expires {
            fields.push(("expires", Value::from(expires)));
        }
        if let Some(lifecycle) = k.lifecycle {
            fields.push(("lifecycle", Value::from(lifecycle)));
        }
        if k.immutable {
            fields.push(("immutable", Value::from(true)));
        }
        if let Some(g) = k.guidance {
            fields.push(("guidance", Value::from(g)));
        }
        if let Some(f) = k.from {
            fields.push(("from", Value::from(f)));
        }
        if k.personal {
            fields.push(("personal", Value::from(true)));
        }
        if k.allow_same_value {
            fields.push(("allow_same_value", Value::from(true)));
        }
        let item = if inline {
            let mut it: InlineTable = fields.into_iter().collect();
            it.fmt();
            Item::Value(Value::InlineTable(it))
        } else {
            let mut table = Table::new();
            for (name, v) in fields {
                table.insert(name, Item::Value(v));
            }
            Item::Table(table)
        };
        t.insert(key, item);
        if self.has_key(product, key) {
            Ok(())
        } else {
            Err(layout_error(source, &path.join(".")))
        }
    }

    /// Set `lifecycle` on the declared key (the retirement proposal's only edit).
    pub fn set_key_lifecycle(
        &mut self,
        product: &str,
        key: &str,
        lifecycle: &str,
    ) -> Result<(), Error> {
        let source = self.source();
        let mut path = keys_path(product);
        path.push(key);
        let t = self
            .table_at_mut(&path)
            .ok_or_else(|| layout_error(source, &path.join(".")))?;
        t.insert("lifecycle", Item::Value(Value::from(lifecycle)));
        Ok(())
    }

    /// Bulk extend (#179 B4): add `env` to the `environments` list of every key that declares
    /// one, in `product` (or in every product when `product` is `None`). A key with no list
    /// is already present in every environment and is left untouched; a key that already
    /// lists `env` is unchanged. Returns the products at least one of whose keys changed, so
    /// the caller can declare their boundary in `env`.
    pub fn extend_environment(&mut self, product: Option<&str>, env: &str) -> Vec<String> {
        let products: Vec<String> = match product {
            Some(p) => vec![p.to_string()],
            None => self
                .doc
                .get("products")
                .and_then(Item::as_table_like)
                .map(|t| t.iter().map(|(k, _)| k.to_string()).collect())
                .unwrap_or_default(),
        };
        let mut changed: Vec<String> = Vec::new();
        for product in products {
            let keys = keys_path(&product);
            let names: Vec<String> = match self.table_at(&keys) {
                Some(t) => t.iter().map(|(k, _)| k.to_string()).collect(),
                None => continue,
            };
            for key in names {
                let mut path = keys_path(&product);
                path.push(&key);
                let Some(item) = self
                    .table_at_mut(&path)
                    .and_then(|t| t.get_mut("environments"))
                else {
                    continue;
                };
                let Some(array) = item.as_array_mut() else {
                    continue;
                };
                if array.iter().any(|v| v.as_str() == Some(env)) {
                    continue;
                }
                array.push(env);
                if !changed.contains(&product) {
                    changed.push(product.clone());
                }
            }
        }
        changed
    }

    /// Declare `boundaries.<boundary> = {}` (no ids yet: an apply records them) in the
    /// declared environment `env`, unless it already declares that boundary. True when the
    /// text changed.
    pub fn declare_boundary(&mut self, env: &str, boundary: &str) -> Result<bool, Error> {
        let source = self.source();
        let env_table = self
            .table_at_mut(&["environments", env])
            .ok_or_else(|| layout_error(source.clone(), &format!("environments.{env}")))?;
        if env_table.get("boundaries").is_none() {
            let mut dotted = Table::new();
            dotted.set_dotted(true);
            env_table.insert("boundaries", Item::Table(dotted));
        }
        let boundaries = env_table
            .get_mut("boundaries")
            .and_then(Item::as_table_like_mut)
            .ok_or_else(|| layout_error(source, &format!("environments.{env}.boundaries")))?;
        if boundaries.get(boundary).is_some() {
            return Ok(false);
        }
        boundaries.insert(
            boundary,
            Item::Value(Value::InlineTable(InlineTable::new())),
        );
        Ok(true)
    }

    /// Add `[environments.<env>]` from `table_text` (a TOML fragment holding exactly that
    /// table), after the last environment.
    pub fn add_environment(&mut self, env: &str, table_text: &str) -> Result<(), Error> {
        // The fragment is opv's own text: a failure here is opv's bug, never the person's.
        let bug = || -> Error {
            Cause::Bug {
                site: "config_edit::add_environment",
            }
            .into()
        };
        let frag = table_text.parse::<DocumentMut>().map_err(|_| bug())?;
        let mut table = frag
            .get("environments")
            .and_then(|e| e.get(env))
            .and_then(Item::as_table)
            .cloned()
            .ok_or_else(bug)?;
        let source = self.source();
        clear_positions(&mut table);
        table.decor_mut().set_prefix("\n");
        let envs = self
            .doc
            .get_mut("environments")
            .and_then(Item::as_table_like_mut)
            .ok_or_else(|| layout_error(source, "environments"))?;
        if envs.get(env).is_some() {
            return Err(Cause::AlreadyDeclared {
                kind: NameKind::Environment,
                name: env.to_string(),
            }
            .into());
        }
        envs.insert(env, Item::Table(table));
        Ok(())
    }
}

impl std::fmt::Display for ConfigDoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.doc.fmt(f)
    }
}

/// The source a [`ConfigDoc`] names when its caller gave none.
fn default_source() -> ConfigSource {
    ConfigSource::File {
        path: PathBuf::from(crate::config_store::FILE_NAME),
        given_by: GivenBy::Discovered,
    }
}

/// `section` is written in a shape opv does not edit (an inline table or a value): the
/// person edits it by hand, through `opv config edit` for a file or a manifest (03.18).
fn layout_error(source: ConfigSource, section: &str) -> Error {
    Cause::ConfigNotEditable {
        source,
        reason: NotEditable::UnsupportedLayout {
            section: section.to_string(),
        },
    }
    .into()
}

/// `["a", "b"]`.
fn env_array(envs: &[String]) -> Value {
    let mut a: Array = envs.iter().map(String::as_str).collect();
    a.fmt();
    Value::Array(a)
}

/// The `rules` entries a catalog shape names: its [`crate::domain::Rules`] with the fields
/// left at their default omitted. An unknown shape has no rules (the caller reports it).
fn shape_rules(name: &str) -> Vec<(String, Value)> {
    let Some(shape) = crate::domain::catalog::lookup(name) else {
        return Vec::new();
    };
    let Ok(default) = toml::Value::try_from(crate::domain::Rules::default()) else {
        return Vec::new();
    };
    let Ok(value) = toml::Value::try_from(&shape.rules) else {
        return Vec::new();
    };
    let (toml::Value::Table(default), toml::Value::Table(mut value)) = (default, value) else {
        return Vec::new();
    };
    value.retain(|k, v| default.get(k) != Some(v));
    let Ok(text) = toml::to_string(&toml::Value::Table(value)) else {
        return Vec::new();
    };
    let Ok(frag) = text.parse::<DocumentMut>() else {
        return Vec::new();
    };
    frag.as_table()
        .iter()
        .filter_map(|(k, v)| v.clone().into_value().ok().map(|v| (k.to_string(), v)))
        .collect()
}

/// A table moved from another document takes its place from where it is inserted.
fn clear_positions(t: &mut Table) {
    t.set_position(None);
    for (_, v) in t.iter_mut() {
        if let Item::Table(sub) = v {
            clear_positions(sub);
        }
    }
}

/// Replace `path` (whose text was `original` when read) with `text`, atomically: a
/// temporary file in the same directory, then a rename. A symlink is followed, so the file
/// it points at is replaced. When the file changed since it was read, nothing is written.
pub fn replace(path: &Path, original: &str, text: &str) -> Result<(), Error> {
    let unreadable = |e: io::Error| crate::config_store::unreadable(path, &e, GivenBy::Discovered);
    let real = fs::canonicalize(path).map_err(unreadable)?;
    write_atomic(&real, text, || match fs::read_to_string(&real) {
        Ok(now) if now == original => Ok(()),
        Ok(_) => Err(Cause::ChangedBeforeWrite {
            object: crate::cause::StoreObject::File {
                path: path.to_path_buf(),
            },
        }
        .into()),
        Err(e) => Err(unreadable(e)),
    })
}

/// Write `text` to `target` through a temporary file in the same directory and a rename,
/// so the target is never partly written. `before_rename` runs last and can still refuse
/// (the file may have appeared or changed meanwhile). An existing target's permissions are
/// kept.
pub(crate) fn write_atomic(
    target: &Path,
    text: &str,
    before_rename: impl FnOnce() -> Result<(), Error>,
) -> Result<(), Error> {
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    let name = target
        .file_name()
        .map_or_else(|| "secrets.toml".into(), |n| n.to_string_lossy());
    let tmp: PathBuf = dir.join(format!(".{name}.opv.{}.tmp", std::process::id()));
    // A3: opv's own write failed: `LocalIo`, naming the destination path (never the content).
    let fail = |e: io::Error| -> Error {
        crate::cause::Cause::LocalIo {
            op: crate::cause::LocalOp::Write,
            path: target.to_path_buf(),
            io: crate::cause::IoKind::from(e.kind()),
        }
        .into()
    };
    let res = (|| {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(fail)?;
        f.write_all(text.as_bytes())
            .and_then(|()| f.sync_all())
            .map_err(fail)?;
        drop(f);
        if let Ok(meta) = fs::metadata(target) {
            fs::set_permissions(&tmp, meta.permissions()).map_err(fail)?;
        }
        before_rename()?;
        fs::rename(&tmp, target).map_err(fail)
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_write_into_a_missing_folder_is_opvs_own_local_io() {
        // A3: opv's own write failure is `LocalIo`, never a configuration error.
        let dir = tempfile::tempdir().unwrap();
        let e = write_atomic(&dir.path().join("no/such/secrets.toml"), "", || Ok(())).unwrap_err();
        assert_eq!(e.code_str(), "local_io_failed");
    }

    #[test]
    fn a_write_failure_names_the_destination_not_opvs_temp_file() {
        // A3: the LocalIo path is the file the person asked for, not opv's temporary file.
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("no/such/secrets.toml");
        let e = write_atomic(&dest, "", || Ok(())).unwrap_err();
        let Some((Cause::LocalIo { path, .. }, _)) = e.cause() else {
            panic!("expected LocalIo, got {e:?}");
        };
        assert_eq!(path, &dest);
    }

    const FILE: &str = "# top comment\n[environments.prod]  # the live one\nvault_id = \"v\"\nitem_id = \"i\"\n\n# api keys\n[products.api.keys.A]\nkind = \"secret\"\nenvironments = [\"prod\"]  # only prod\n";

    fn key<'a>(envs: &'a [String]) -> NewKey<'a> {
        NewKey {
            kind: "config",
            environments: envs,
            rules: &[],
            guidance: None,
            immutable: false,
            from: None,
            personal: false,
            allow_same_value: false,
            except: &[],
            source: None,
            shape: None,
            expires: None,
            lifecycle: None,
        }
    }

    #[test]
    fn add_key_keeps_every_existing_line_and_comment() {
        let mut d = ConfigDoc::parse(FILE).unwrap();
        let envs = ["prod".to_string()];
        d.add_key("api", "B", &key(&envs)).unwrap();
        assert!(d.to_string().starts_with(FILE));
    }

    #[test]
    fn add_key_in_a_new_product_writes_only_the_key_header() {
        let mut d = ConfigDoc::parse(FILE).unwrap();
        let envs = ["prod".to_string()];
        d.add_key("web", "C", &key(&envs)).unwrap();
        assert_eq!(
            &d.to_string()[FILE.len()..],
            "\n[products.web.keys.C]\nkind = \"config\"\nenvironments = [\"prod\"]\n"
        );
    }

    #[test]
    fn add_environment_goes_after_the_last_environment() {
        let mut d = ConfigDoc::parse(FILE).unwrap();
        d.add_environment(
            "dev",
            "[environments.dev]\nvault_id = \"vd\"\nitem_id = \"id\"\n",
        )
        .unwrap();
        assert!(d.to_string().contains(
            "item_id = \"i\"\n\n[environments.dev]\nvault_id = \"vd\"\nitem_id = \"id\"\n\n# api keys\n"
        ));
    }

    fn manifest_source() -> ConfigSource {
        ConfigSource::Manifest {
            title: "opv · app".into(),
            vault: crate::cause::VaultId::new("v"),
            project: "app".into(),
        }
    }

    /// 03.18: a layout opv does not edit, in a manifest, names the manifest (whose route is
    /// `opv config edit`), never "edit secrets.toml by hand".
    #[test]
    fn a_layout_opv_does_not_edit_names_the_manifest() {
        let text =
            "[environments.prod]\nvault_id = \"v\"\nitem_id = \"i\"\n\n[products]\napi = 1\n";
        let mut d = ConfigDoc::parse_in(text, manifest_source()).unwrap();
        let envs = ["prod".to_string()];
        let e = d.add_key("api", "B", &key(&envs)).unwrap_err();
        assert!(
            matches!(
                e.cause(),
                Some((
                    Cause::ConfigNotEditable {
                        source: ConfigSource::Manifest { .. },
                        ..
                    },
                    _
                ))
            ),
            "{e:?}"
        );
    }

    /// 03.18: an existing environment is already declared, not a file to edit by hand.
    #[test]
    fn adding_an_existing_environment_is_already_declared() {
        let mut d = ConfigDoc::parse(FILE).unwrap();
        let e = d
            .add_environment(
                "prod",
                "[environments.prod]\nvault_id = \"v\"\nitem_id = \"i\"\n",
            )
            .unwrap_err();
        assert_eq!(e.code_str(), "already_declared");
    }

    #[test]
    fn replace_refuses_a_file_changed_since_it_was_read() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("secrets.toml");
        fs::write(&p, "b").unwrap();
        assert!(replace(&p, "a", "c").is_err());
    }

    #[test]
    fn replace_leaves_no_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("secrets.toml");
        fs::write(&p, "a").unwrap();
        replace(&p, "a", "c").unwrap();
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("secrets.toml")]);
    }
}
