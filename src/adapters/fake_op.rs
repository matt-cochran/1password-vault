//! A stateful fake `op` (and `git remote get-url origin`) for manifest tests: it stores
//! items with their tags, fields and versions, answers `vault list`, `item list --tags`,
//! `item list --vault`, `item get`,
//! `item create -` and `item edit` from that state, and records every call with its stdin.
//!
//! It models `op`'s local cache (op 2.x on UNIX): an `item get` without `--cache=false`
//! answers from the copy cached by the last read or write of that item, so an edit made
//! elsewhere ([`FakeOp::bump`], [`FakeOp::edit_elsewhere`]) stays invisible to it until a
//! `--cache=false` read refreshes the cache.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::io;
use std::time::Duration;

use serde_json::{Value, json};

use crate::runner::{Call, CommandRunner, Outcome, Output};

/// One recorded call.
#[derive(Debug, Clone)]
pub struct Recorded {
    pub program: String,
    pub args: Vec<String>,
    pub stdin: Option<Vec<u8>>,
}

/// The fake. `signed_in` false makes every op call fail as op does without a session.
pub struct FakeOp {
    pub items: RefCell<Vec<Value>>,
    pub vaults: Vec<(String, String)>,
    pub remote: RefCell<Option<String>>,
    /// `git rev-parse --show-toplevel`.
    pub toplevel: RefCell<Option<String>>,
    pub signed_in: Cell<bool>,
    pub calls: RefCell<Vec<Recorded>>,
    /// `op`'s local cache: the item as this machine last read or wrote it, by item ID.
    pub cache: RefCell<BTreeMap<String, Value>>,
    /// Someone else's edit, applied right after the n-th `item edit` reaches op (1-based),
    /// before op answers: an edit landing together with opv's (I5).
    pub racing_edit: Cell<Option<usize>>,
    edits: Cell<usize>,
    next_id: Cell<u32>,
}

impl Default for FakeOp {
    fn default() -> Self {
        Self {
            items: RefCell::default(),
            vaults: vec![
                ("vdev0000000000000000000001".into(), "myapp-dev".into()),
                ("vshr0000000000000000000002".into(), "shared".into()),
            ],
            remote: RefCell::new(None),
            toplevel: RefCell::new(None),
            signed_in: Cell::new(true),
            calls: RefCell::default(),
            cache: RefCell::default(),
            racing_edit: Cell::new(None),
            edits: Cell::new(0),
            next_id: Cell::new(1),
        }
    }
}

impl FakeOp {
    /// A fake whose `git remote get-url origin` prints `url`.
    pub fn with_remote(url: &str) -> Self {
        let f = Self::default();
        *f.remote.borrow_mut() = Some(url.to_string());
        f
    }

    /// Store an item directly (as if made in the 1Password app); returns its ID.
    pub fn insert(&self, vault: &str, mut item: Value) -> String {
        let (vid, vname) = self.vault(vault).expect("known vault");
        let id = self.new_id();
        item["id"] = json!(id);
        item["vault"] = json!({"id": vid, "name": vname});
        if item.get("version").is_none() {
            item["version"] = json!(1);
        }
        self.items.borrow_mut().push(item);
        id
    }

    /// Someone else edits the item: its version moves on.
    pub fn bump(&self, id: &str) {
        for i in self.items.borrow_mut().iter_mut() {
            if i["id"] == id {
                i["version"] = json!(i["version"].as_u64().unwrap_or(0) + 1);
            }
        }
    }

    /// Someone else edits the item's notes in the 1Password app: its version moves on and
    /// this machine's cache keeps the old copy.
    pub fn edit_elsewhere(&self, id: &str, notes: &str) {
        for i in self.items.borrow_mut().iter_mut() {
            if i["id"] == id {
                for f in i["fields"].as_array_mut().into_iter().flatten() {
                    if f["id"] == "notesPlain" {
                        f["value"] = json!(notes);
                    }
                }
                i["version"] = json!(i["version"].as_u64().unwrap_or(0) + 1);
            }
        }
    }

    /// The item with `id`.
    pub fn item(&self, id: &str) -> Value {
        self.items
            .borrow()
            .iter()
            .find(|i| i["id"] == id)
            .cloned()
            .expect("known item")
    }

    /// How many recorded calls start with `prefix` (program then args).
    pub fn count(&self, prefix: &[&str]) -> usize {
        self.calls
            .borrow()
            .iter()
            .filter(|c| {
                let all: Vec<&str> = std::iter::once(c.program.as_str())
                    .chain(c.args.iter().map(String::as_str))
                    .collect();
                all.starts_with(prefix)
            })
            .count()
    }

    /// True when `needle` occurs in any argv or stdin.
    pub fn saw(&self, needle: &str) -> bool {
        self.calls.borrow().iter().any(|c| {
            c.args.iter().any(|a| a.contains(needle))
                || c.stdin
                    .as_ref()
                    .is_some_and(|s| String::from_utf8_lossy(s).contains(needle))
        })
    }

    fn new_id(&self) -> String {
        let n = self.next_id.get();
        self.next_id.set(n + 1);
        format!("item{n:022}")
    }

    fn vault(&self, v: &str) -> Option<(String, String)> {
        self.vaults
            .iter()
            .find(|(id, name)| id == v || name == v)
            .cloned()
    }

    fn record(&self, call: &Call) {
        self.calls.borrow_mut().push(Recorded {
            program: call.program.to_string(),
            args: call.args.iter().map(|a| a.to_string()).collect(),
            stdin: call.stdin.map(<[u8]>::to_vec),
        });
    }

    fn answer(&self, call: &Call) -> Output {
        let args: Vec<&str> = call.args.to_vec();
        if call.program == "git" {
            return match (
                args.as_slice(),
                &*self.remote.borrow(),
                &*self.toplevel.borrow(),
            ) {
                (["remote", "get-url", "origin"], Some(url), _) => {
                    Output::success(format!("{url}\n"))
                }
                (["rev-parse", "--show-toplevel"], _, Some(top)) => {
                    Output::success(format!("{top}\n"))
                }
                _ => Output::failure(2),
            };
        }
        match args.as_slice() {
            ["whoami", ..] if self.signed_in.get() => Output::success(r#"{"user_type":"HUMAN"}"#),
            ["whoami", ..] => Output::failure(1),
            ["account", "list", ..] => Output::success(r#"[{"url":"my.1password.com"}]"#),
            _ if !self.signed_in.get() => Output::failure(1),
            ["vault", "list", ..] => {
                let rows: Vec<Value> = self
                    .vaults
                    .iter()
                    .map(|(id, name)| json!({"id": id, "name": name}))
                    .collect();
                Output::success(serde_json::to_vec(&rows).unwrap())
            }
            ["item", "list", "--vault", vault, ..] => {
                let rows: Vec<Value> = self
                    .items
                    .borrow()
                    .iter()
                    .filter(|i| i["vault"]["id"] == *vault)
                    .map(|i| json!({"id": i["id"], "title": i["title"], "version": i["version"]}))
                    .collect();
                Output::success(serde_json::to_vec(&rows).unwrap())
            }
            ["item", "list", "--tags", tag, ..] => {
                let rows: Vec<Value> = self
                    .items
                    .borrow()
                    .iter()
                    .filter(|i| {
                        i["tags"].as_array().is_some_and(|t| {
                            t.iter().any(|x| {
                                x.as_str()
                                    .is_some_and(|x| x == *tag || x.starts_with(&format!("{tag}/")))
                            })
                        })
                    })
                    .map(|i| {
                        json!({"id": i["id"], "title": i["title"], "tags": i["tags"],
                               "version": i["version"], "vault": i["vault"],
                               "category": i["category"]})
                    })
                    .collect();
                Output::success(serde_json::to_vec(&rows).unwrap())
            }
            ["item", "get", id, "--vault", vault, rest @ ..] => {
                let fresh = rest.contains(&crate::adapters::onepassword::NO_CACHE);
                let current = self
                    .items
                    .borrow()
                    .iter()
                    .find(|i| i["id"] == *id && i["vault"]["id"] == *vault)
                    .cloned();
                let Some(current) = current else {
                    return Output::failure(1);
                };
                let mut cache = self.cache.borrow_mut();
                let answer = match cache.get(*id) {
                    Some(cached) if !fresh => cached.clone(),
                    _ => current,
                };
                cache.insert((*id).to_string(), answer.clone());
                Output::success(serde_json::to_vec(&answer).unwrap())
            }
            ["item", "create", "--vault", vault, ..] => {
                let Some(mut item) = call
                    .stdin
                    .and_then(|s| serde_json::from_slice::<Value>(s).ok())
                else {
                    return Output::failure(1);
                };
                if self.vault(vault).is_none() {
                    return Output::failure(1);
                }
                item["version"] = json!(1);
                let id = self.insert(vault, item);
                let created = self.item(&id);
                self.cache.borrow_mut().insert(id, created.clone());
                Output::success(serde_json::to_vec(&created).unwrap())
            }
            ["item", "edit", id, "--vault", _, ..] => {
                let Some(new) = call
                    .stdin
                    .and_then(|s| serde_json::from_slice::<Value>(s).ok())
                else {
                    return Output::failure(1);
                };
                let n = self.edits.get() + 1;
                self.edits.set(n);
                if self.racing_edit.get() == Some(n) {
                    self.edit_elsewhere(id, "edited = \"elsewhere\"\n");
                }
                let mut items = self.items.borrow_mut();
                let Some(i) = items.iter_mut().find(|i| i["id"] == *id) else {
                    return Output::failure(1);
                };
                let version = i["version"].as_u64().unwrap_or(0) + 1;
                i["fields"] = new["fields"].clone();
                if new.get("sections").is_some() {
                    i["sections"] = new["sections"].clone();
                }
                i["tags"] = new["tags"].clone();
                i["title"] = new["title"].clone();
                i["version"] = json!(version);
                let written = i.clone();
                drop(items);
                self.cache
                    .borrow_mut()
                    .insert((*id).to_string(), written.clone());
                Output::success(serde_json::to_vec(&written).unwrap())
            }
            _ => Output::failure(1),
        }
    }
}

impl CommandRunner for FakeOp {
    fn read(&self, call: &Call, _refused: &[i32]) -> io::Result<Outcome> {
        self.record(call);
        let o = self.answer(call);
        Ok(if o.status == 0 {
            Outcome::Done(o)
        } else {
            Outcome::Refused(o)
        })
    }

    fn write(&self, call: &Call) -> io::Result<Outcome> {
        self.record(call);
        let o = self.answer(call);
        Ok(if o.status == 0 {
            Outcome::Done(o)
        } else {
            Outcome::Unknown {
                reason: "failed-write",
                status: Some(o.status),
            }
        })
    }

    fn probe(&self, call: &Call, _limit: Duration) -> io::Result<Output> {
        self.record(call);
        Ok(self.answer(call))
    }

    fn pause(&self, _d: Duration, _note: &str) {}

    fn note(&self, _line: &str) {}

    fn run_inherited(&self, _: &str, _: &[&str], _: &[(&str, &str)]) -> io::Result<i32> {
        Err(io::ErrorKind::Unsupported.into())
    }
}
