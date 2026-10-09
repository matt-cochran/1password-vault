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

use crate::error::Error;

fn cfg(msg: String) -> Error {
    Error::Config(msg.into())
}

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
}

/// A parsed `secrets.toml` that keeps its formatting.
#[derive(Debug, Clone)]
pub struct ConfigDoc {
    doc: DocumentMut,
}

/// `products.<product>.keys` (fleet) or `keys` (simple, `product` is `None`).
fn keys_path(product: Option<&str>) -> Vec<&str> {
    match product {
        Some(p) => vec!["products", p, "keys"],
        None => vec!["keys"],
    }
}

impl ConfigDoc {
    pub fn parse(text: &str) -> Result<Self, Error> {
        text.parse::<DocumentMut>()
            .map(|doc| Self { doc })
            .map_err(|e| cfg(format!("invalid secrets.toml: {e}")))
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

    fn key(&self, product: Option<&str>, key: &str) -> Option<&dyn TableLike> {
        self.table_at(&keys_path(product))?
            .get(key)?
            .as_table_like()
    }

    /// True when `[product/]key` is declared.
    pub fn has_key(&self, product: Option<&str>, key: &str) -> bool {
        self.key(product, key).is_some()
    }

    /// The declared key's `environments`, in file order.
    pub fn key_environments(&self, product: Option<&str>, key: &str) -> Vec<String> {
        self.key(product, key)
            .and_then(|t| t.get("environments"))
            .and_then(Item::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Every declared key as (product, key), in file order; product `None` under the simple
    /// profile.
    pub fn keys(&self, fleet_profile: bool) -> Vec<(Option<String>, String)> {
        let names = |t: &dyn TableLike| -> Vec<String> {
            t.iter()
                .filter(|(_, v)| v.is_table_like())
                .map(|(k, _)| k.to_string())
                .collect()
        };
        if !fleet_profile {
            return self
                .table_at(&["keys"])
                .map(|t| names(t).into_iter().map(|k| (None, k)).collect())
                .unwrap_or_default();
        }
        let Some(products) = self.table_at(&["products"]) else {
            return Vec::new();
        };
        products
            .iter()
            .flat_map(|(p, v)| {
                let keys = v
                    .as_table_like()
                    .and_then(|t| t.get("keys"))
                    .and_then(Item::as_table_like)
                    .map(names)
                    .unwrap_or_default();
                keys.into_iter().map(move |k| (Some(p.to_string()), k))
            })
            .collect()
    }

    /// Declare `[product/]key`, after the product's last key (a new product goes last).
    /// Keys written as inline tables (`K = { kind = … }`) get one more inline table.
    pub fn add_key(
        &mut self,
        product: Option<&str>,
        key: &str,
        k: &NewKey<'_>,
    ) -> Result<(), Error> {
        let path = keys_path(product);
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
                .ok_or_else(|| layout_error(&path.join(".")))?;
        }
        let inline = t.iter().any(|(_, v)| v.is_inline_table());
        let mut fields: Vec<(&str, Value)> = vec![
            ("kind", Value::from(k.kind)),
            ("environments", env_array(k.environments)),
        ];
        if !k.rules.is_empty() {
            let mut rules: InlineTable = k
                .rules
                .iter()
                .map(|(n, v)| (n.as_str(), v.clone()))
                .collect();
            rules.fmt();
            fields.push(("rules", Value::InlineTable(rules)));
        }
        if k.immutable {
            fields.push(("immutable", Value::from(true)));
        }
        if let Some(g) = k.guidance {
            fields.push(("guidance", Value::from(g)));
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
            Err(layout_error(&path.join(".")))
        }
    }

    /// Append `env` to the declared key's `environments`, keeping the array's style.
    pub fn add_key_env(
        &mut self,
        product: Option<&str>,
        key: &str,
        env: &str,
    ) -> Result<(), Error> {
        let name = match product {
            Some(p) => format!("{p}/{key}"),
            None => key.to_string(),
        };
        let mut path = keys_path(product);
        path.push(key);
        let arr = self
            .table_at_mut(&path)
            .and_then(|t| t.get_mut("environments"))
            .and_then(Item::as_array_mut)
            .ok_or_else(|| {
                cfg(format!(
                    "{name}: environments is not a list; edit secrets.toml by hand"
                ))
            })?;
        arr.push(env);
        Ok(())
    }

    /// Add `[environments.<env>]` from `table_text` (a TOML fragment holding exactly that
    /// table), after the last environment.
    pub fn add_environment(&mut self, env: &str, table_text: &str) -> Result<(), Error> {
        let frag = table_text
            .parse::<DocumentMut>()
            .map_err(|e| cfg(format!("invalid environment table: {e}")))?;
        let mut table = frag
            .get("environments")
            .and_then(|e| e.get(env))
            .and_then(Item::as_table)
            .cloned()
            .ok_or_else(|| cfg(format!("invalid environment table for {env}")))?;
        clear_positions(&mut table);
        table.decor_mut().set_prefix("\n");
        let envs = self
            .doc
            .get_mut("environments")
            .and_then(Item::as_table_like_mut)
            .ok_or_else(|| layout_error("environments"))?;
        if envs.get(env).is_some() {
            return Err(cfg(format!("environment {env} already exists")));
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

fn layout_error(path: &str) -> Error {
    cfg(format!(
        "cannot add under {path}: the file writes it in a shape opv does not edit (an inline \
         table or a value); edit secrets.toml by hand"
    ))
}

/// `["a", "b"]`.
fn env_array(envs: &[String]) -> Value {
    let mut a: Array = envs.iter().map(String::as_str).collect();
    a.fmt();
    Value::Array(a)
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
    let real =
        fs::canonicalize(path).map_err(|e| cfg(format!("cannot read {}: {e}", path.display())))?;
    write_atomic(&real, text, || match fs::read_to_string(&real) {
        Ok(now) if now == original => Ok(()),
        Ok(_) => Err(cfg(format!(
            "{} changed while opv was editing it; nothing written: run the command again",
            path.display()
        ))),
        Err(e) => Err(cfg(format!("cannot read {}: {e}", path.display()))),
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
    let fail = |what: &str, p: &Path, e: io::Error| {
        Error::Config(format!("cannot {what} {}: {e}", p.display()).into())
    };
    let res = (|| {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| fail("create", &tmp, e))?;
        f.write_all(text.as_bytes())
            .and_then(|()| f.sync_all())
            .map_err(|e| fail("write", &tmp, e))?;
        drop(f);
        if let Ok(meta) = fs::metadata(target) {
            fs::set_permissions(&tmp, meta.permissions()).map_err(|e| fail("write", &tmp, e))?;
        }
        before_rename()?;
        fs::rename(&tmp, target).map_err(|e| fail("write", target, e))
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "# top comment\n[profile]\nkind = \"fleet\"\n\n[environments.prod]  # the live one\nvault_id = \"v\"\nitem_id = \"i\"\n\n# api keys\n[products.api.keys.A]\nkind = \"secret\"\nenvironments = [\"prod\"]  # only prod\n";

    fn key<'a>(envs: &'a [String]) -> NewKey<'a> {
        NewKey {
            kind: "config",
            environments: envs,
            rules: &[],
            guidance: None,
            immutable: false,
        }
    }

    #[test]
    fn add_key_keeps_every_existing_line_and_comment() {
        let mut d = ConfigDoc::parse(FILE).unwrap();
        let envs = ["prod".to_string()];
        d.add_key(Some("api"), "B", &key(&envs)).unwrap();
        assert!(d.to_string().starts_with(FILE));
    }

    #[test]
    fn add_key_in_a_new_product_writes_only_the_key_header() {
        let mut d = ConfigDoc::parse(FILE).unwrap();
        let envs = ["prod".to_string()];
        d.add_key(Some("web"), "C", &key(&envs)).unwrap();
        assert_eq!(
            &d.to_string()[FILE.len()..],
            "\n[products.web.keys.C]\nkind = \"config\"\nenvironments = [\"prod\"]\n"
        );
    }

    #[test]
    fn add_key_env_appends_inside_the_existing_array() {
        let mut d = ConfigDoc::parse(FILE).unwrap();
        d.add_key_env(Some("api"), "A", "dev").unwrap();
        assert!(
            d.to_string()
                .contains("environments = [\"prod\", \"dev\"]  # only prod\n")
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
