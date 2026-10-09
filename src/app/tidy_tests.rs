//! Self-healing conventions end to end (FR-43), against a stateful fake `op` that stores
//! the item, applies `op item edit` stdin to it and bumps its version. It models `op`'s
//! local cache: an `item get` without `--cache=false` answers with the copy cached by the
//! last read or write, so someone else's edit is invisible to it until a fresh read.

use std::cell::{Cell, RefCell};
use std::io;
use std::time::Duration;

use serde_json::{Value, json};

use super::*;
use crate::domain::convention::KEPT_SECTION;
use crate::host::FakeEnv;
use crate::runner::{Call, Outcome, Output};

const MARKER: &str = "TIDYMARKER";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Edit {
    Apply,
    /// Exits non-zero: no write access.
    Refuse,
    /// Killed before `op` applied it.
    KilledBefore,
    /// Applied, then the result was lost.
    KilledAfter,
    /// Applied, but op dropped the item's last field (a field it cannot round-trip).
    Lossy,
}

type Editor = fn(&mut Value);

struct FakeOp {
    item: RefCell<Value>,
    user_type: &'static str,
    edit: Cell<Edit>,
    /// Someone else editing the item: on the n-th `item get` (1-based), before it answers.
    editors: RefCell<Vec<(usize, Editor)>>,
    gets: Cell<usize>,
    /// `op`'s local cache of the item (the last read or written copy).
    cache: RefCell<Option<Value>>,
    /// Someone else's edit applied right after `op item edit` reaches op, before it applies
    /// opv's (I5).
    racing: Cell<Option<Editor>>,
    /// What `op item edit` echoes: the item as written (op's behaviour) or nothing.
    echo: Cell<bool>,
    calls: RefCell<Vec<(Vec<String>, Vec<u8>)>>,
    notes: RefCell<Vec<String>>,
    child_env: RefCell<Vec<(String, String)>>,
}

impl FakeOp {
    fn new(item: Value, user_type: &'static str) -> Self {
        Self {
            item: RefCell::new(item),
            user_type,
            edit: Cell::new(Edit::Apply),
            editors: RefCell::new(Vec::new()),
            gets: Cell::new(0),
            cache: RefCell::new(None),
            racing: Cell::new(None),
            echo: Cell::new(true),
            calls: RefCell::default(),
            notes: RefCell::default(),
            child_env: RefCell::default(),
        }
    }

    fn person(item: Value) -> Self {
        Self::new(item, "USER")
    }

    fn record(&self, call: &Call) {
        self.calls.borrow_mut().push((
            call.args.iter().map(|a| a.to_string()).collect(),
            call.stdin.map(<[u8]>::to_vec).unwrap_or_default(),
        ));
    }

    fn count(&self, prefix: &[&str]) -> usize {
        self.calls
            .borrow()
            .iter()
            .filter(|(a, _)| a.len() >= prefix.len() && a.iter().zip(prefix).all(|(x, p)| x == p))
            .count()
    }

    fn edits(&self) -> usize {
        self.count(&["item", "edit"])
    }

    fn notes(&self) -> String {
        self.notes.borrow().join("\n")
    }

    fn fields(&self) -> Vec<Value> {
        self.item.borrow()["fields"].as_array().unwrap().clone()
    }

    fn field(&self, section: Option<&str>, label: &str) -> Option<Value> {
        self.fields()
            .into_iter()
            .find(|f| f["label"] == label && f["section"]["label"].as_str() == section)
    }
}

fn bump(v: &mut Value) {
    v["version"] = json!(v["version"].as_u64().unwrap_or(0) + 1);
}

impl CommandRunner for FakeOp {
    fn read(&self, call: &Call, _refused: &[i32]) -> io::Result<Outcome> {
        self.record(call);
        if call.args.starts_with(&["item", "get"]) {
            let n = self.gets.get() + 1;
            self.gets.set(n);
            for (at, editor) in self.editors.borrow().iter() {
                if *at == n {
                    let mut item = self.item.borrow_mut();
                    editor(&mut item);
                    bump(&mut item);
                }
            }
            let fresh = call.args.contains(&crate::adapters::onepassword::NO_CACHE);
            let mut cache = self.cache.borrow_mut();
            let answer = match &*cache {
                Some(cached) if !fresh => cached.clone(),
                _ => self.item.borrow().clone(),
            };
            *cache = Some(answer.clone());
            return Ok(Outcome::Done(Output::success(
                serde_json::to_vec(&answer).unwrap(),
            )));
        }
        if call.args.starts_with(&["vault", "list"]) {
            return Ok(Outcome::Done(Output::success(
                br#"[{"id":"vdev","name":"dev"}]"#.to_vec(),
            )));
        }
        Ok(Outcome::Done(Output::success(b"[]".to_vec())))
    }

    fn write(&self, call: &Call) -> io::Result<Outcome> {
        self.record(call);
        if call.args.starts_with(&["item", "create"]) {
            let mut new: Value = serde_json::from_slice(call.stdin.unwrap()).unwrap();
            new["id"] = json!("inew");
            new["version"] = json!(1);
            *self.item.borrow_mut() = new;
            return Ok(Outcome::Done(Output::success(br#"{"id":"inew"}"#.to_vec())));
        }
        if !call.args.starts_with(&["item", "edit"]) {
            return Ok(Outcome::Done(Output::success(b"{}".to_vec())));
        }
        let mode = self.edit.get();
        if matches!(mode, Edit::Apply | Edit::KilledAfter | Edit::Lossy) {
            if let Some(editor) = self.racing.take() {
                let mut item = self.item.borrow_mut();
                editor(&mut item);
                bump(&mut item);
            }
            let mut new: Value = serde_json::from_slice(call.stdin.unwrap()).unwrap();
            new["version"] = self.item.borrow()["version"].clone();
            bump(&mut new);
            if mode == Edit::Lossy {
                new["fields"].as_array_mut().unwrap().pop();
            }
            *self.item.borrow_mut() = new.clone();
            *self.cache.borrow_mut() = Some(new);
        }
        let echoed = if self.echo.get() {
            serde_json::to_vec(&*self.item.borrow()).unwrap()
        } else {
            b"{}".to_vec()
        };
        Ok(match mode {
            Edit::Apply | Edit::Lossy => Outcome::Done(Output::success(echoed)),
            Edit::Refuse => Outcome::Unknown {
                reason: "failed-write",
                status: Some(1),
            },
            Edit::KilledBefore | Edit::KilledAfter => Outcome::Unknown {
                reason: "killed",
                status: None,
            },
        })
    }

    fn probe(&self, call: &Call, _limit: Duration) -> io::Result<Output> {
        self.record(call);
        if call.args.first() == Some(&"whoami") {
            return Ok(Output::success(
                json!({"user_type": self.user_type}).to_string(),
            ));
        }
        Ok(Output::success(b"[]".to_vec()))
    }

    fn pause(&self, _d: Duration, _note: &str) {}

    fn note(&self, line: &str) {
        self.notes.borrow_mut().push(line.to_string());
    }

    fn run_inherited(
        &self,
        _program: &str,
        args: &[&str],
        env: &[(&str, &str)],
    ) -> io::Result<i32> {
        self.calls
            .borrow_mut()
            .push((args.iter().map(|a| a.to_string()).collect(), Vec::new()));
        self.child_env
            .borrow_mut()
            .extend(env.iter().map(|(k, v)| (k.to_string(), v.to_string())));
        Ok(0)
    }

    fn run_inherited_clean(
        &self,
        program: &str,
        args: &[&str],
        env: &[(&str, &str)],
        _remove: &[String],
    ) -> io::Result<i32> {
        self.run_inherited(program, args, env)
    }
}

fn fleet() -> Fleet {
    config::parse(
        r#"
[profile]
kind = "fleet"

[environments.dev]
vault_id = "vdev"
item_id = "idev"

[products.api.keys.OPENAI_API_KEY]
kind = "secret"
environments = ["dev"]
rules = { prefix = "sk-" }

[products.api.keys.LOG_LEVEL]
kind = "config"
environments = ["dev"]

[products.web.keys.SESSION_KEY]
kind = "secret"
environments = ["dev"]
"#,
    )
    .unwrap()
}

/// (section label or "" for top level, label, type, value).
type F<'a> = (&'a str, &'a str, &'a str, &'a str);

/// `op item get --format json` output for `fields` (D0 shape).
fn item(fields: &[F<'_>]) -> Value {
    let mut sections: Vec<Value> = Vec::new();
    let mut fs = vec![
        json!({"id": "notesPlain", "type": "STRING", "purpose": "NOTES", "label": "notesPlain"}),
    ];
    for (i, (s, l, ty, v)) in fields.iter().enumerate() {
        let mut f = json!({"id": format!("f{i}"), "type": ty, "label": l});
        if !s.is_empty() {
            let id = format!("s_{}", s.replace(' ', "_"));
            if !sections.iter().any(|x| x["id"] == id.as_str()) {
                sections.push(json!({"id": id, "label": s}));
            }
            f["section"] = json!({"id": id, "label": s});
        }
        if !v.is_empty() {
            f["value"] = json!(v);
        }
        fs.push(f);
    }
    json!({
        "id": "idev", "title": "dev", "version": 1,
        "vault": {"id": "vdev", "name": "dev"},
        "category": "SECURE_NOTE",
        "updated_at": "2026-10-08T00:00:00Z",
        "sections": sections,
        "fields": fs,
    })
}

/// Every declared key, laid out by the convention.
fn tidy_item() -> Value {
    item(&[
        ("api", "OPENAI_API_KEY", "CONCEALED", "sk-TIDYMARKER"),
        ("api", "LOG_LEVEL", "STRING", "info"),
        ("web", "SESSION_KEY", "CONCEALED", "s-TIDYMARKER"),
        ("opv", "convention", "STRING", "1"),
    ])
}

/// One of every layout problem the tidy fixes.
fn messy_item() -> Value {
    item(&[
        (
            "Secrets",
            "OPENAI_API_KEY",
            "CONCEALED",
            "sk-TIDYMARKER-old",
        ),
        ("", "openai api key", "STRING", "sk-TIDYMARKER-new\n"),
        ("Misc", "log-level", "STRING", "debug"),
        ("web", "SESSION_KEY", "STRING", "s-TIDYMARKER"),
        ("web", "SESSION_KEY", "STRING", ""),
    ])
}

fn tidied(op: &FakeOp) -> Read {
    let _on = activate();
    read(&fleet(), "dev", op).unwrap()
}

fn with_host<T>(env: FakeEnv, f: impl FnOnce() -> T) -> T {
    crate::host::with_test_host(Host::from_env(&env.shell("/bin/bash")), f)
}

#[test]
fn civil_date_is_utc_gregorian() {
    assert_eq!(civil(20_734), "2026-10-08");
}

#[test]
fn a_secret_stored_as_text_is_made_concealed() {
    let op = FakeOp::person(item(&[(
        "api",
        "OPENAI_API_KEY",
        "STRING",
        "sk-TIDYMARKER",
    )]));
    tidied(&op);
    assert_eq!(
        op.field(Some("api"), "OPENAI_API_KEY").unwrap()["type"],
        "CONCEALED"
    );
}

#[test]
fn a_missing_field_is_created_empty_in_its_section() {
    let op = FakeOp::person(item(&[]));
    tidied(&op);
    assert!(op.field(Some("api"), "LOG_LEVEL").is_some());
}

#[test]
fn a_misplaced_field_is_moved_home_and_renamed() {
    let op = FakeOp::person(item(&[("Misc", "log-level", "STRING", "debug")]));
    tidied(&op);
    assert_eq!(
        op.field(Some("api"), "LOG_LEVEL").unwrap()["value"],
        "debug"
    );
}

#[test]
fn a_duplicate_is_kept_with_its_value() {
    let op = FakeOp::person(messy_item());
    tidied(&op);
    assert!(
        op.fields()
            .iter()
            .any(|f| f["section"]["label"] == KEPT_SECTION && f["value"] == "sk-TIDYMARKER-old")
    );
}

#[test]
fn a_normalized_value_is_written_trimmed() {
    let op = FakeOp::person(item(&[(
        "api",
        "OPENAI_API_KEY",
        "CONCEALED",
        "sk-TIDYMARKER\n",
    )]));
    tidied(&op);
    assert_eq!(
        op.field(Some("api"), "OPENAI_API_KEY").unwrap()["value"],
        "sk-TIDYMARKER"
    );
}

#[test]
fn a_normalized_original_is_kept_concealed() {
    let op = FakeOp::person(item(&[(
        "api",
        "OPENAI_API_KEY",
        "CONCEALED",
        "sk-TIDYMARKER\n",
    )]));
    tidied(&op);
    assert!(
        op.fields()
            .iter()
            .any(|f| f["section"]["label"] == KEPT_SECTION
                && f["type"] == "CONCEALED"
                && f["value"] == "sk-TIDYMARKER\n")
    );
}

#[test]
fn nothing_is_ever_deleted() {
    let before: Vec<Value> = messy_item()["fields"].as_array().unwrap().clone();
    let op = FakeOp::person(messy_item());
    tidied(&op);
    let after = op.fields();
    let value_kept = |v: &Value| v.is_null() || after.iter().any(|f| f["value"] == *v);
    let label_kept = |l: &str| {
        after.iter().any(|f| {
            f["label"]
                .as_str()
                .is_some_and(|x| x == l || x.starts_with(&format!("{l} (")))
        })
    };
    assert!(
        before
            .iter()
            .all(|f| value_kept(&f["value"]) && label_kept(f["label"].as_str().unwrap())),
        "{after:#?}"
    );
}

#[test]
fn the_tidy_writes_one_whole_item_edit() {
    let op = FakeOp::person(messy_item());
    tidied(&op);
    assert_eq!(op.edits(), 1);
}

#[test]
fn a_tidy_prints_one_line_naming_what_changed() {
    let op = FakeOp::person(item(&[(
        "api",
        "OPENAI_API_KEY",
        "STRING",
        "sk-TIDYMARKER",
    )]));
    tidied(&op);
    assert!(
        op.notes()
            .lines()
            .any(|l| l.starts_with("tidied 1Password (dev): ")
                && l.contains("made api/OPENAI_API_KEY concealed")),
        "{}",
        op.notes()
    );
}

#[test]
fn a_tidy_names_the_values_a_person_still_has_to_fill() {
    let op = FakeOp::person(tidy_item_without("LOG_LEVEL"));
    tidied(&op);
    assert!(
        op.notes()
            .contains("still needs a value in 1Password (dev): api/LOG_LEVEL"),
        "{}",
        op.notes()
    );
}

fn tidy_item_without(label: &str) -> Value {
    let mut v = tidy_item();
    v["fields"]
        .as_array_mut()
        .unwrap()
        .retain(|f| f["label"] != label);
    v
}

#[test]
fn the_read_returns_what_was_tidied() {
    let op = FakeOp::person(item(&[(
        "api",
        "OPENAI_API_KEY",
        "STRING",
        "sk-TIDYMARKER",
    )]));
    let r = tidied(&op);
    assert!(
        r.changes
            .contains(&Change::MadeConcealed("api/OPENAI_API_KEY".into()))
    );
}

#[test]
fn a_second_run_writes_nothing() {
    let op = FakeOp::person(messy_item());
    tidied(&op);
    tidied(&op);
    assert_eq!(op.edits(), 1);
}

#[test]
fn a_conventional_item_is_read_once_and_never_written() {
    let op = FakeOp::person(tidy_item());
    tidied(&op);
    assert_eq!(op.calls.borrow().len(), 1);
}

#[test]
fn a_service_account_never_writes() {
    let op = FakeOp::new(messy_item(), "SERVICE_ACCOUNT");
    tidied(&op);
    assert_eq!(op.edits(), 0);
}

/// A person's own `op` session, but this run signed in to the target with deploy
/// credentials (FR-40): the runner says so.
struct UnderDeployCredentials<'a>(&'a FakeOp);

impl CommandRunner for UnderDeployCredentials<'_> {
    fn read(&self, call: &Call, refused: &[i32]) -> io::Result<Outcome> {
        self.0.read(call, refused)
    }
    fn write(&self, call: &Call) -> io::Result<Outcome> {
        self.0.write(call)
    }
    fn probe(&self, call: &Call, limit: Duration) -> io::Result<Output> {
        self.0.probe(call, limit)
    }
    fn pause(&self, d: Duration, note: &str) {
        self.0.pause(d, note)
    }
    fn note(&self, line: &str) {
        self.0.note(line)
    }
    fn run_inherited(&self, p: &str, a: &[&str], e: &[(&str, &str)]) -> io::Result<i32> {
        self.0.run_inherited(p, a, e)
    }
    fn deploy_signed_in(&self) -> bool {
        true
    }
}

/// Owner ruling (0.5.0): tidy runs for a signed-in person only, never under deploy
/// credentials.
#[test]
fn a_run_under_deploy_credentials_never_writes() {
    let op = FakeOp::person(messy_item());
    let _on = activate();
    let _ = read(&fleet(), "dev", &UnderDeployCredentials(&op));
    assert_eq!(op.edits(), 0);
}

/// Ruling (0.5.0): the manifest's own fields are never touched by a tidy.
#[test]
fn the_manifest_item_is_never_tidied() {
    let mut item = messy_item();
    item["tags"] = json!([crate::adapters::onepassword_manifest::MANIFEST_TAG]);
    let op = FakeOp::person(item);
    tidied(&op);
    assert_eq!(op.edits(), 0);
}

#[test]
fn a_service_account_gets_one_note_that_a_person_will_tidy() {
    let op = FakeOp::new(messy_item(), "SERVICE_ACCOUNT");
    tidied(&op);
    assert_eq!(
        op.notes()
            .matches("The next opv run by a signed-in person tidies it.")
            .count(),
        1
    );
}

const READ_ONLY_NOTE: &str = "The next opv run by a signed-in person tidies it.";

#[test]
fn a_service_account_says_nothing_when_only_the_marker_is_missing() {
    let op = FakeOp::new(tidy_item_without("convention"), "SERVICE_ACCOUNT");
    tidied(&op);
    assert_eq!(op.notes(), "");
}

#[test]
fn a_person_never_writes_the_marker_alone() {
    let op = FakeOp::person(tidy_item_without("convention"));
    tidied(&op);
    assert_eq!(op.edits(), 0);
}

/// A missing value is reported as a missing key; a read-only run adds no layout note.
#[test]
fn a_service_account_says_nothing_when_only_fields_are_missing() {
    let op = FakeOp::new(tidy_item_without("LOG_LEVEL"), "SERVICE_ACCOUNT");
    tidied(&op);
    assert_eq!(op.notes(), "");
}

#[test]
fn ci_says_nothing_about_an_empty_item() {
    let op = FakeOp::person(item(&[]));
    with_host(FakeEnv::new("linux").var("CI"), || tidied(&op));
    assert_eq!(op.notes(), "");
}

#[test]
fn a_service_account_gets_the_note_once_however_often_the_item_is_read() {
    let op = FakeOp::new(messy_item(), "SERVICE_ACCOUNT");
    tidied(&op);
    tidied(&op);
    assert_eq!(op.notes().matches(READ_ONLY_NOTE).count(), 1);
}

#[test]
fn a_service_account_token_writes_nothing_and_needs_no_whoami() {
    let op = FakeOp::person(messy_item());
    with_host(
        FakeEnv::new("linux").var_val("OP_SERVICE_ACCOUNT_TOKEN", "dummy"),
        || tidied(&op),
    );
    assert_eq!(op.calls.borrow().len(), 1, "{:?}", op.calls.borrow());
}

#[test]
fn ci_never_writes() {
    let op = FakeOp::person(messy_item());
    with_host(FakeEnv::new("linux").var("CI"), || tidied(&op));
    assert_eq!(op.edits(), 0);
}

#[test]
fn ci_reads_a_misplaced_field_tolerantly() {
    let op = FakeOp::person(item(&[("Misc", "log-level", "STRING", "debug")]));
    let r = with_host(FakeEnv::new("linux").var("CI"), || tidied(&op));
    let f = r.fields.iter().find(|f| f.label == "LOG_LEVEL").unwrap();
    assert_eq!(f.value.expose(), "debug");
}

fn someone_edits_session(v: &mut Value) {
    for f in v["fields"].as_array_mut().unwrap() {
        if f["label"] == "SESSION_KEY" {
            f["value"] = json!("edited-by-someone");
        }
    }
}

#[test]
fn a_concurrent_edit_is_never_overwritten() {
    let op = FakeOp::person(item(&[
        ("api", "OPENAI_API_KEY", "STRING", "sk-TIDYMARKER"),
        ("web", "SESSION_KEY", "CONCEALED", "s-TIDYMARKER"),
    ]));
    // The second `item get` is the check right before the write.
    op.editors.borrow_mut().push((2, someone_edits_session));
    tidied(&op);
    assert_eq!(
        op.field(Some("web"), "SESSION_KEY").unwrap()["value"],
        "edited-by-someone"
    );
}

#[test]
fn a_concurrent_edit_is_replanned_and_tidied() {
    let op = FakeOp::person(item(&[
        ("api", "OPENAI_API_KEY", "STRING", "sk-TIDYMARKER"),
        ("web", "SESSION_KEY", "CONCEALED", "s-TIDYMARKER"),
    ]));
    op.editors.borrow_mut().push((2, someone_edits_session));
    tidied(&op);
    assert_eq!(
        op.field(Some("api"), "OPENAI_API_KEY").unwrap()["type"],
        "CONCEALED"
    );
}

#[test]
fn an_item_edited_twice_during_the_tidy_is_not_written() {
    let op = FakeOp::person(messy_item());
    op.editors.borrow_mut().push((2, someone_edits_session));
    op.editors.borrow_mut().push((3, someone_edits_session));
    tidied(&op);
    assert_eq!(op.edits(), 0);
}

#[test]
fn an_item_edited_twice_says_so() {
    let op = FakeOp::person(messy_item());
    op.editors.borrow_mut().push((2, someone_edits_session));
    op.editors.borrow_mut().push((3, someone_edits_session));
    tidied(&op);
    assert!(op.notes().contains("changed twice"), "{}", op.notes());
}

#[test]
fn an_interrupted_write_before_it_applied_leaves_the_item_untouched() {
    let op = FakeOp::person(messy_item());
    op.edit.set(Edit::KilledBefore);
    tidied(&op);
    assert_eq!(*op.item.borrow(), messy_item());
}

#[test]
fn an_interrupted_write_after_it_applied_leaves_the_item_fully_tidied() {
    let op = FakeOp::person(messy_item());
    op.edit.set(Edit::KilledAfter);
    tidied(&op);
    let raw = serde_json::to_vec(&*op.item.borrow()).unwrap();
    let (layout, _) = onepassword_tidy::parse(&raw).unwrap();
    assert!(convention::plan(&layout, &fleet(), "dev", &today()).is_empty());
}

#[test]
fn a_refused_write_never_fails_the_command() {
    let op = FakeOp::person(messy_item());
    op.edit.set(Edit::Refuse);
    let _on = activate();
    assert!(read(&fleet(), "dev", &op).is_ok());
}

#[test]
fn a_refused_write_says_the_item_was_read_as_it_is() {
    let op = FakeOp::person(messy_item());
    op.edit.set(Edit::Refuse);
    tidied(&op);
    assert!(
        op.notes().contains("could not tidy 1Password (dev)"),
        "{}",
        op.notes()
    );
}

#[test]
fn values_never_reach_argv() {
    let op = FakeOp::person(messy_item());
    tidied(&op);
    assert!(
        op.calls
            .borrow()
            .iter()
            .all(|(a, _)| a.iter().all(|x| !x.contains(MARKER)))
    );
}

#[test]
fn values_travel_on_stdin_only() {
    let op = FakeOp::person(messy_item());
    tidied(&op);
    let stdin = op
        .calls
        .borrow()
        .iter()
        .find(|(a, _)| a[..2] == ["item", "edit"])
        .unwrap()
        .1
        .clone();
    assert!(String::from_utf8(stdin).unwrap().contains(MARKER));
}

#[test]
fn values_never_reach_the_notes() {
    let op = FakeOp::person(messy_item());
    tidied(&op);
    assert!(!op.notes().contains(MARKER), "{}", op.notes());
}

fn check_json(op: &FakeOp) -> String {
    let _on = activate();
    let mut out = Vec::new();
    let _ = crate::app::local::check(&fleet(), "dev", Some("api"), op, &mut out, true);
    String::from_utf8(out).unwrap()
}

#[test]
fn json_carries_a_tidy_array() {
    let op = FakeOp::person(item(&[(
        "api",
        "OPENAI_API_KEY",
        "STRING",
        "sk-TIDYMARKER",
    )]));
    let doc: Value = serde_json::from_str(&check_json(&op)).unwrap();
    assert_eq!(
        doc["tidy"],
        json!([
            {"action": "created_field", "name": "api/LOG_LEVEL"},
            {"action": "made_concealed", "name": "api/OPENAI_API_KEY"},
            {"action": "created_section", "name": "web"},
            {"action": "created_field", "name": "web/SESSION_KEY"},
        ])
    );
}

#[test]
fn json_never_carries_a_value() {
    let op = FakeOp::person(messy_item());
    assert!(!check_json(&op).contains(MARKER));
}

#[test]
fn run_references_a_misplaced_field_by_id_when_read_only() {
    let op = FakeOp::new(
        item(&[("Misc", "openai-api-key", "CONCEALED", "sk-TIDYMARKER")]),
        "SERVICE_ACCOUNT",
    );
    let _on = activate();
    crate::app::run::run(&fleet(), "dev", "api", &["true".into()], &op).unwrap();
    assert!(
        op.child_env
            .borrow()
            .contains(&("OPENAI_API_KEY".into(), "op://vdev/idev/f0".into()))
    );
}

#[test]
fn run_after_a_persons_tidy_uses_the_convention_reference() {
    let op = FakeOp::person(item(&[(
        "Misc",
        "openai-api-key",
        "CONCEALED",
        "sk-TIDYMARKER",
    )]));
    let _on = activate();
    crate::app::run::run(&fleet(), "dev", "api", &["true".into()], &op).unwrap();
    assert!(op.child_env.borrow().contains(&(
        "OPENAI_API_KEY".into(),
        "op://vdev/idev/api/OPENAI_API_KEY".into()
    )));
}

#[test]
fn init_creates_a_missing_item_for_a_person() {
    let dir = tempfile::tempdir().unwrap();
    let op = FakeOp::person(json!({}));
    let args = crate::app::init::InitArgs {
        env: "dev".into(),
        vault: "dev".into(),
        item: "app".into(),
        target: None,
        fields: Default::default(),
        profile: Some(crate::domain::Profile::Simple),
        force: false,
    };
    let _on = activate();
    let mut out = Vec::new();
    let res = crate::app::init::run(&args, dir.path(), &op, &mut out);
    assert!(res.is_ok() && op.count(&["item", "create"]) == 1, "{res:?}");
}

#[test]
fn init_never_creates_an_item_for_a_service_account() {
    let dir = tempfile::tempdir().unwrap();
    let op = FakeOp::new(json!({}), "SERVICE_ACCOUNT");
    let args = crate::app::init::InitArgs {
        env: "dev".into(),
        vault: "dev".into(),
        item: "app".into(),
        target: None,
        fields: Default::default(),
        profile: Some(crate::domain::Profile::Simple),
        force: false,
    };
    let _on = activate();
    let mut out = Vec::new();
    let _ = crate::app::init::run(&args, dir.path(), &op, &mut out);
    assert_eq!(op.count(&["item", "create"]), 0);
}

// ---- Integration seams: shared keys (FR-45), links (H1), read-only consistency ----------

fn shared_fleet() -> Fleet {
    config::parse(
        r#"
[profile]
kind = "fleet"

[environments.dev]
vault_id = "vdev"
item_id = "idev"

[products.api.keys.OPENAI_API_KEY]
kind = "secret"
environments = ["dev"]

[products.worker.keys.OPENAI_API_KEY]
kind = "secret"
environments = ["dev"]
from = "api/OPENAI_API_KEY"
"#,
    )
    .unwrap()
}

#[test]
fn tidy_never_creates_a_field_for_a_shared_key() {
    let op = FakeOp::person(item(&[]));
    let _on = activate();
    read(&shared_fleet(), "dev", &op).unwrap();
    assert!(op.field(Some("worker"), "OPENAI_API_KEY").is_none());
}

#[test]
fn still_needs_a_value_names_the_source_not_the_shared_key() {
    let op = FakeOp::person(item(&[]));
    let _on = activate();
    read(&shared_fleet(), "dev", &op).unwrap();
    assert!(
        !op.notes().contains("worker/OPENAI_API_KEY"),
        "{}",
        op.notes()
    );
}

#[test]
fn still_needs_a_value_carries_the_item_link() {
    let op = FakeOp::person(item(&[]));
    tidied(&op);
    let line = op
        .notes()
        .lines()
        .find(|l| l.starts_with("still needs a value"))
        .unwrap()
        .to_string();
    assert!(line.contains(" · open: https://"), "{line}");
}

#[test]
fn an_item_edited_twice_reports_tidy_conflict() {
    let op = FakeOp::person(messy_item());
    op.editors.borrow_mut().push((2, someone_edits_session));
    op.editors.borrow_mut().push((3, someone_edits_session));
    assert_eq!(tidied(&op).tidy_error, Some(Code::TidyConflict));
}

fn prefixed_fleet() -> Fleet {
    config::parse(
        r#"
[profile]
kind = "simple"

[environments.dev]
vault_id = "vdev"
item_id = "idev"

[keys.API_TOKEN]
kind = "secret"
environments = ["dev"]
rules = { ensure_prefix = "tok_", pattern = "[A-Z]+" }
"#,
    )
    .unwrap()
}

/// A stored value a person's tidy rewrites: trailing newline, missing `ensure_prefix`.
fn unnormalized_item() -> Value {
    item(&[("", "API_TOKEN", "CONCEALED", "TIDYMARKER\n")])
}

fn token_value(op: &FakeOp) -> String {
    let _on = activate();
    let read = read(&prefixed_fleet(), "dev", op).unwrap();
    let f = read.fields.iter().find(|f| f.label == "API_TOKEN").unwrap();
    f.value.expose().to_string()
}

#[test]
fn a_read_only_identity_uses_the_value_a_persons_tidy_writes() {
    let person = FakeOp::person(unnormalized_item());
    let service = FakeOp::new(unnormalized_item(), "SERVICE_ACCOUNT");
    assert_eq!(token_value(&service), token_value(&person));
}

#[test]
fn a_persons_tidy_writes_the_normalized_value() {
    let person = FakeOp::person(unnormalized_item());
    token_value(&person);
    assert_eq!(
        person.field(None, "API_TOKEN").unwrap()["value"],
        "tok_TIDYMARKER"
    );
}

fn token_in_child_env(op: &FakeOp) -> String {
    let _on = activate();
    crate::app::run::run(
        &prefixed_fleet(),
        "dev",
        crate::domain::SIMPLE_PRODUCT,
        &["true".into()],
        op,
    )
    .unwrap();
    op.child_env
        .borrow()
        .iter()
        .find(|(k, _)| k == "API_TOKEN")
        .map(|(_, v)| v.clone())
        .unwrap()
}

/// Owner ruling (0.5.0): `run` keeps passing a reference under a read-only identity, so
/// `op run` keeps masking the value in the child's output.
#[test]
fn run_as_a_read_only_identity_gives_the_child_a_reference() {
    let service = FakeOp::new(unnormalized_item(), "SERVICE_ACCOUNT");
    assert_eq!(token_in_child_env(&service), "op://vdev/idev/API_TOKEN");
}

#[test]
fn run_as_a_read_only_identity_warns_once_per_fixable_key() {
    let service = FakeOp::new(unnormalized_item(), "SERVICE_ACCOUNT");
    token_in_child_env(&service);
    let warnings: Vec<String> = service
        .notes
        .borrow()
        .iter()
        .filter(|n| n.contains("fixable formatting problem"))
        .cloned()
        .collect();
    assert_eq!(
        warnings,
        [
            "API_TOKEN has a fixable formatting problem in 1Password; run as yourself (opv login \
          dev) and opv will tidy it"
        ]
    );
}

#[test]
fn run_after_a_persons_tidy_does_not_warn() {
    let person = FakeOp::person(unnormalized_item());
    token_in_child_env(&person);
    assert!(!person.notes().contains("fixable formatting problem"));
}

#[test]
fn run_after_a_persons_tidy_gives_the_child_a_reference() {
    let person = FakeOp::person(unnormalized_item());
    assert_eq!(token_in_child_env(&person), "op://vdev/idev/API_TOKEN");
}

#[test]
fn run_never_puts_a_value_in_argv_or_the_child_env() {
    let service = FakeOp::new(unnormalized_item(), "SERVICE_ACCOUNT");
    token_in_child_env(&service);
    let argv = service
        .calls
        .borrow()
        .iter()
        .all(|(args, _)| args.iter().all(|a| !a.contains(MARKER)));
    let env = service
        .child_env
        .borrow()
        .iter()
        .all(|(_, v)| !v.contains(MARKER));
    assert!(argv && env);
}

#[test]
fn item_skeleton_counts_a_misplaced_field_as_present() {
    let op = FakeOp::person(item(&[
        ("Misc", "log-level", "STRING", "debug"),
        ("api", "OPENAI_API_KEY", "CONCEALED", "sk-TIDYMARKER"),
        ("web", "SESSION_KEY", "CONCEALED", "s-TIDYMARKER"),
    ]));
    let mut out = Vec::new();
    crate::app::skeleton::run(&fleet(), "dev", &op, &mut out).unwrap();
    assert_eq!(op.edits(), 0, "{}", String::from_utf8_lossy(&out));
}

#[test]
fn item_skeleton_reads_an_item_the_strict_reader_refuses() {
    // Two fields with the same section and label: the strict reader's duplicate error.
    let op = FakeOp::person(item(&[
        ("api", "OPENAI_API_KEY", "CONCEALED", "sk-TIDYMARKER"),
        ("api", "OPENAI_API_KEY", "CONCEALED", ""),
    ]));
    let mut out = Vec::new();
    let res = crate::app::skeleton::run(&fleet(), "dev", &op, &mut out);
    assert!(res.is_ok(), "{res:?}");
}

#[test]
fn a_shared_key_reads_its_misplaced_source_tolerantly() {
    let op = FakeOp::person(item(&[(
        "Misc",
        "openai-api-key",
        "STRING",
        "sk-TIDYMARKER",
    )]));
    let out = with_host(FakeEnv::new("linux").var("CI"), || {
        let _on = activate();
        let mut out = Vec::new();
        let _ =
            crate::app::local::check(&shared_fleet(), "dev", Some("worker"), &op, &mut out, true);
        String::from_utf8(out).unwrap()
    });
    let doc: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(doc["findings"], 0, "{doc}");
}

#[test]
fn the_schema_lists_the_tidy_fields_of_a_check_document() {
    let op = FakeOp::person(item(&[(
        "api",
        "OPENAI_API_KEY",
        "STRING",
        "sk-TIDYMARKER",
    )]));
    let doc: Value = serde_json::from_str(&check_json(&op)).unwrap();
    assert!(
        crate::app::json_tests::undocumented(&doc, "check").is_empty(),
        "{doc}"
    );
}

#[test]
fn a_tidy_conflict_is_in_the_check_document() {
    let op = FakeOp::person(messy_item());
    op.editors.borrow_mut().push((2, someone_edits_session));
    op.editors.borrow_mut().push((3, someone_edits_session));
    let doc: Value = serde_json::from_str(&check_json(&op)).unwrap();
    assert_eq!(doc["tidy_error"], "tidy_conflict");
}

// ---- Final review: fresh reads (C1), version checks (I5), data-preserving tidy (I4),
// identity-specific notes (M3, M4), shared items (M1), item skeleton (M2) ----------------

/// A person's machine whose `op` cache still holds version 1 of the item while a teammate
/// rotated `web/SESSION_KEY` in the 1Password app (version 2).
fn stale_cache() -> FakeOp {
    let op = FakeOp::person(item(&[
        ("api", "OPENAI_API_KEY", "STRING", "sk-TIDYMARKER"),
        ("web", "SESSION_KEY", "CONCEALED", "s-TIDYMARKER"),
    ]));
    *op.cache.borrow_mut() = Some(op.item.borrow().clone());
    let mut current = op.item.borrow_mut();
    someone_edits_session(&mut current);
    bump(&mut current);
    drop(current);
    op
}

#[test]
fn a_tidy_never_writes_over_an_edit_ops_cache_hides() {
    let op = stale_cache();
    tidied(&op);
    assert_eq!(
        op.field(Some("web"), "SESSION_KEY").unwrap()["value"],
        "edited-by-someone"
    );
}

#[test]
fn a_tidy_still_tidies_past_a_stale_cache() {
    let op = stale_cache();
    tidied(&op);
    assert_eq!(
        op.field(Some("api"), "OPENAI_API_KEY").unwrap()["type"],
        "CONCEALED"
    );
}

#[test]
fn every_read_a_tidy_writes_from_bypasses_the_cache() {
    let op = FakeOp::person(messy_item());
    tidied(&op);
    let cached_after_first = op
        .calls
        .borrow()
        .iter()
        .filter(|(a, _)| a.starts_with(&["item".to_string(), "get".to_string()]))
        .skip(1)
        .any(|(a, _)| !a.iter().any(|x| x == "--cache=false"));
    assert!(!cached_after_first, "{:?}", op.calls.borrow());
}

#[test]
fn an_edit_landing_with_the_tidy_reports_tidy_conflict() {
    let op = FakeOp::person(messy_item());
    op.racing.set(Some(someone_edits_session));
    assert_eq!(tidied(&op).tidy_error, Some(Code::TidyConflict));
}

#[test]
fn an_edit_landing_with_the_tidy_is_never_retried() {
    let op = FakeOp::person(messy_item());
    op.racing.set(Some(someone_edits_session));
    tidied(&op);
    assert_eq!(op.edits(), 1);
}

#[test]
fn an_edit_landing_with_the_tidy_says_to_check_the_history() {
    let op = FakeOp::person(messy_item());
    op.racing.set(Some(someone_edits_session));
    tidied(&op);
    assert!(
        op.notes().contains("Check the item's history"),
        "{}",
        op.notes()
    );
}

#[test]
fn an_edit_landing_with_the_tidy_is_found_by_a_fresh_re_read_without_an_echo() {
    let op = FakeOp::person(messy_item());
    op.echo.set(false);
    op.racing.set(Some(someone_edits_session));
    assert_eq!(tidied(&op).tidy_error, Some(Code::TidyConflict));
}

#[test]
fn a_tidy_one_version_later_reports_no_error() {
    let op = FakeOp::person(messy_item());
    assert_eq!(tidied(&op).tidy_error, None);
}

#[test]
fn a_field_the_write_dropped_reports_tidy_unverified() {
    let op = FakeOp::person(messy_item());
    op.edit.set(Edit::Lossy);
    assert_eq!(tidied(&op).tidy_error, Some(Code::TidyUnverified));
}

#[test]
fn a_field_the_write_dropped_says_to_restore_it() {
    let op = FakeOp::person(messy_item());
    op.edit.set(Edit::Lossy);
    tidied(&op);
    assert!(
        op.notes().contains("restore them from the item's history"),
        "{}",
        op.notes()
    );
}

fn with_attachment() -> Value {
    let mut v = messy_item();
    v["files"] = json!([{"id": "f1", "name": "cert.pem", "size": 10}]);
    v
}

fn with_otp() -> Value {
    let mut v = messy_item();
    v["fields"].as_array_mut().unwrap().push(
        json!({"id": "otp", "type": "OTP", "label": "one-time password", "value": "otpauth://x"}),
    );
    v
}

#[test]
fn an_item_with_an_attachment_is_never_tidied() {
    let op = FakeOp::person(with_attachment());
    tidied(&op);
    assert_eq!(op.edits(), 0);
}

#[test]
fn an_item_with_an_otp_field_is_never_tidied() {
    let op = FakeOp::person(with_otp());
    tidied(&op);
    assert_eq!(op.edits(), 0);
}

#[test]
fn an_item_with_an_ssh_key_is_never_tidied() {
    let mut v = messy_item();
    v["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id": "k", "type": "SSHKEY", "label": "private key", "value": "x"}));
    let op = FakeOp::person(v);
    tidied(&op);
    assert_eq!(op.edits(), 0);
}

#[test]
fn an_item_never_tidied_gets_one_note() {
    let op = FakeOp::person(with_otp());
    tidied(&op);
    assert_eq!(
        op.notes().matches("opv never tidies such an item").count(),
        1,
        "{}",
        op.notes()
    );
}

#[test]
fn an_item_never_tidied_is_still_read_tolerantly() {
    let op = FakeOp::person(with_attachment());
    let r = tidied(&op);
    let f = r.fields.iter().find(|f| f.label == "LOG_LEVEL").unwrap();
    assert_eq!(f.value.expose(), "debug");
}

#[test]
fn an_attachment_added_before_the_write_stops_it() {
    fn attach(v: &mut Value) {
        v["files"] = json!([{"id": "f1", "name": "cert.pem"}]);
    }
    let op = FakeOp::person(messy_item());
    op.editors.borrow_mut().push((2, attach));
    tidied(&op);
    assert_eq!(op.edits(), 0);
}

#[test]
fn deploy_credentials_note_names_opv_check() {
    let op = FakeOp::person(messy_item());
    let _on = activate();
    let _ = read(&fleet(), "dev", &UnderDeployCredentials(&op));
    assert!(
        op.notes().contains("opv check dev tidies it"),
        "{}",
        op.notes()
    );
}

#[test]
fn deploy_credentials_note_never_promises_a_signed_in_person() {
    let op = FakeOp::person(messy_item());
    let _on = activate();
    let _ = read(&fleet(), "dev", &UnderDeployCredentials(&op));
    assert!(!op.notes().contains("signed-in person"), "{}", op.notes());
}

#[test]
fn run_after_a_persons_failed_tidy_never_says_run_as_yourself() {
    let person = FakeOp::person(unnormalized_item());
    person.edit.set(Edit::Refuse);
    token_in_child_env(&person);
    assert!(
        !person.notes().contains("run as yourself"),
        "{}",
        person.notes()
    );
}

#[test]
fn run_after_a_persons_failed_tidy_points_at_the_note() {
    let person = FakeOp::person(unnormalized_item());
    person.edit.set(Edit::Refuse);
    token_in_child_env(&person);
    assert!(
        person.notes().contains("opv could not tidy it in this run"),
        "{}",
        person.notes()
    );
}

fn simple_fleet() -> Fleet {
    config::parse(
        r#"
[profile]
kind = "simple"

[environments.dev]
vault_id = "vdev"
item_id = "idev"

[keys.LOG_LEVEL]
kind = "config"
environments = ["dev"]
"#,
    )
    .unwrap()
}

/// One item shared by a simple and a fleet configuration (M1).
fn shared_item() -> Value {
    item(&[
        ("", "LOG_LEVEL", "STRING", "info"),
        ("api", "OPENAI_API_KEY", "CONCEALED", "sk-TIDYMARKER"),
        ("api", "LOG_LEVEL", "STRING", "debug"),
        ("web", "SESSION_KEY", "CONCEALED", "s-TIDYMARKER"),
    ])
}

fn both(op: &FakeOp) {
    let _on = activate();
    read(&fleet(), "dev", op).unwrap();
    read(&simple_fleet(), "dev", op).unwrap();
}

#[test]
fn simple_and_fleet_configurations_sharing_an_item_settle() {
    let op = FakeOp::person(shared_item());
    both(&op);
    let settled = op.edits();
    both(&op);
    both(&op);
    assert_eq!(op.edits(), settled);
}

#[test]
fn a_fleet_tidy_never_moves_a_simple_configurations_top_level_key() {
    let op = FakeOp::person(shared_item());
    tidied(&op);
    assert_eq!(op.field(None, "LOG_LEVEL").unwrap()["value"], "info");
}

#[test]
fn a_simple_tidy_never_moves_a_fleet_configurations_field() {
    let op = FakeOp::person(item(&[("api", "LOG_LEVEL", "STRING", "debug")]));
    let _on = activate();
    read(&simple_fleet(), "dev", &op).unwrap();
    assert_eq!(
        op.field(Some("api"), "LOG_LEVEL").unwrap()["value"],
        "debug"
    );
}

#[test]
fn a_field_left_for_the_other_configuration_is_named_in_one_note() {
    let op = FakeOp::person(item(&[("api", "LOG_LEVEL", "STRING", "debug")]));
    let _on = activate();
    read(&simple_fleet(), "dev", &op).unwrap();
    assert_eq!(
        op.notes()
            .matches("where a fleet-profile configuration keeps it")
            .count(),
        1,
        "{}",
        op.notes()
    );
}

#[test]
fn item_skeleton_refuses_the_manifest_item() {
    let mut v = item(&[]);
    v["tags"] = json!([crate::adapters::onepassword_manifest::MANIFEST_TAG]);
    let op = FakeOp::person(v);
    let res = crate::app::skeleton::run(&fleet(), "dev", &op, &mut Vec::new());
    assert!(res.is_err());
}

#[test]
fn item_skeleton_never_writes_the_manifest_item() {
    let mut v = item(&[]);
    v["tags"] = json!([crate::adapters::onepassword_manifest::MANIFEST_TAG]);
    let op = FakeOp::person(v);
    let _ = crate::app::skeleton::run(&fleet(), "dev", &op, &mut Vec::new());
    assert_eq!(op.edits(), 0);
}

#[test]
fn item_skeleton_never_writes_over_an_edit_ops_cache_hides() {
    let op = FakeOp::person(item(&[("web", "SESSION_KEY", "CONCEALED", "s-TIDYMARKER")]));
    *op.cache.borrow_mut() = Some(op.item.borrow().clone());
    {
        let mut current = op.item.borrow_mut();
        someone_edits_session(&mut current);
        bump(&mut current);
    }
    crate::app::skeleton::run(&fleet(), "dev", &op, &mut Vec::new()).unwrap();
    assert_eq!(
        op.field(Some("web"), "SESSION_KEY").unwrap()["value"],
        "edited-by-someone"
    );
}

#[test]
fn item_skeleton_reports_an_edit_landing_with_it() {
    let op = FakeOp::person(item(&[]));
    op.racing.set(Some(someone_edits_session));
    crate::app::skeleton::run(&fleet(), "dev", &op, &mut Vec::new()).unwrap();
    assert!(op.notes().contains("another edit landed"), "{}", op.notes());
}
