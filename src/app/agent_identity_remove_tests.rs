//! `opv access [<env>] --remove --agent` (#338, S18): one scenario and one behavioural
//! assertion per test, over a fake store and a fake `op` session.

use std::cell::RefCell;
use std::io;
use std::time::Duration;

use super::*;
use crate::adapters::credential_store::{FakeCredentialSource, SourceDescription};
use crate::adapters::fake_op::FakeOp;
use crate::app::agent_identity::INDEX_FILE;
use crate::cause::{AgentStore, CreateKind, Invocation};
use crate::domain::SecretValue;
use crate::domain::agent_identity::AgentRecord;
use crate::runner::{Call, CreateOutcome, Outcome, Output};

/// Every seeded token starts with this, so a canary can look for it.
const MARKER: &str = "ops_FAKETOKENMARKER";
const ACCOUNT: &str = "AFAKEOP0000000000000000001";

/// The person's own `op` session, or with `service_account` a token's.
#[derive(Default)]
struct Session {
    op: FakeOp,
    service_account: bool,
}

impl Session {
    fn whoami(&self, call: &Call) -> Option<Output> {
        (self.service_account && call.args.first() == Some(&"whoami")).then(|| {
            Output::success(format!(
                r#"{{"user_type":"SERVICE_ACCOUNT","account_uuid":"{ACCOUNT}"}}"#
            ))
        })
    }
}

impl CommandRunner for Session {
    fn read(&self, call: &Call, refused: &[i32]) -> io::Result<Outcome> {
        match self.whoami(call) {
            Some(o) => Ok(Outcome::Done(o)),
            None => self.op.read(call, refused),
        }
    }
    fn probe(&self, call: &Call, limit: Duration) -> io::Result<Output> {
        match self.whoami(call) {
            Some(o) => Ok(o),
            None => self.op.probe(call, limit),
        }
    }
    fn create(&self, call: &Call, kind: CreateKind) -> io::Result<CreateOutcome> {
        self.op.create(call, kind)
    }
    fn write(&self, call: &Call) -> io::Result<Outcome> {
        self.op.write(call)
    }
    fn pause(&self, _: Duration, _: &str) {}
    fn note(&self, _: &str) {}
    fn run_inherited(&self, _: &str, _: &[&str], _: &[(&str, &str)]) -> io::Result<i32> {
        Err(io::ErrorKind::PermissionDenied.into())
    }
}

/// The fake store, whose delete fails (`agent_store_locked`) for `fail_env`.
struct Store {
    inner: FakeCredentialSource,
    fail_env: Option<&'static str>,
}

impl AgentCredentialSource for Store {
    fn describe(&self) -> SourceDescription {
        self.inner.describe()
    }
    fn preflight(&self) -> Result<SourceDescription, Error> {
        self.inner.preflight()
    }
    fn resolve(&self, key: &AgentKey) -> Result<Option<SecretValue>, Error> {
        self.inner.resolve(key)
    }
    fn store(&self, key: &AgentKey, value: &SecretValue) -> Result<(), Error> {
        self.inner.store(key, value)
    }
    fn delete(&self, key: &AgentKey) -> Result<bool, Error> {
        if self.fail_env == Some(key.env().as_str()) {
            return Err(Cause::AgentStoreLocked {
                store: AgentStore::MacosKeychain,
            }
            .into());
        }
        self.inner.delete(key)
    }
}

struct Answer(bool, RefCell<Vec<String>>);

impl Interaction for Answer {
    fn show(&mut self, message: &str) -> Result<(), Error> {
        self.1.borrow_mut().push(message.to_string());
        Ok(())
    }
    fn confirm(&mut self, _: &str) -> Result<bool, Error> {
        Ok(self.0)
    }
    fn secret(&mut self, _: &str) -> Result<SecretValue, Error> {
        unreachable!("never asks for a secret")
    }
}

fn key(env: &str) -> AgentKey {
    AgentKey::new(AccountId::new(ACCOUNT), "shop", EnvName::new(env)).unwrap()
}

fn name(env: &str) -> String {
    format!("shop-{env}-agent-laptop")
}

/// One identity per environment in the index, each with its token in the store.
struct Machine {
    _dir: tempfile::TempDir,
    index: std::path::PathBuf,
    store: Store,
}

fn machine(envs: &[&str]) -> Machine {
    let dir = tempfile::tempdir().unwrap();
    let index = dir.path().join("opv").join(INDEX_FILE);
    let store = Store {
        inner: FakeCredentialSource::new(AgentStore::MacosKeychain),
        fail_env: None,
    };
    for env in envs {
        agent_identity::record(
            &index,
            IndexEntry {
                project: "shop".into(),
                account_id: ACCOUNT.into(),
                record: AgentRecord {
                    account_name: name(env),
                    environment: env.to_string(),
                    machine: "laptop".into(),
                    store: "macos_keychain".into(),
                    created_on: "2026-08-19".into(),
                    expires_on: "2026-11-17".into(),
                    rotation_successor: None,
                },
            },
        )
        .unwrap();
        store
            .store(&key(env), &SecretValue::new(format!("{MARKER}{env}")))
            .unwrap();
    }
    Machine {
        _dir: dir,
        index,
        store,
    }
}

fn indexed(m: &Machine) -> Vec<String> {
    agent_identity::load(&m.index)
        .unwrap()
        .identities
        .into_iter()
        .map(|e| e.record.environment)
        .collect()
}

fn kept(m: &Machine, env: &str) -> bool {
    m.store.resolve(&key(env)).unwrap().is_some()
}

#[derive(Default)]
struct Opts<'a> {
    env: Option<&'a str>,
    json: bool,
    decline: bool,
}

struct Run {
    res: Result<(), Error>,
    out: String,
    shown: Vec<String>,
}

fn remove(s: &Session, m: &Machine, o: Opts<'_>) -> Run {
    let mut ui = Answer(!o.decline, RefCell::new(Vec::new()));
    let mut out = Vec::new();
    let req = Request {
        env: o.env,
        project: "shop",
        store: &m.store,
        index: &m.index,
        json: o.json,
    };
    let res = run(&req, s, &mut ui, &mut out);
    let shown = ui.1.borrow().clone();
    Run {
        res,
        out: String::from_utf8(out).unwrap(),
        shown,
    }
}

fn dev() -> Opts<'static> {
    Opts {
        env: Some("dev"),
        ..Opts::default()
    }
}

fn code_of(e: &Error) -> Option<&'static str> {
    e.cause().map(|(c, _)| c.code())
}

// --- one environment ------------------------------------------------------------------

#[test]
fn one_environment_removes_only_its_index_entry() {
    let m = machine(&["dev", "staging"]);
    let _ = remove(&Session::default(), &m, dev());
    assert_eq!(indexed(&m), vec!["staging".to_string()]);
}

#[test]
fn one_environment_deletes_its_token_from_the_store() {
    let m = machine(&["dev", "staging"]);
    let _ = remove(&Session::default(), &m, dev());
    assert!(!kept(&m, "dev"));
}

#[test]
fn one_environment_keeps_the_other_token() {
    let m = machine(&["dev", "staging"]);
    let _ = remove(&Session::default(), &m, dev());
    assert!(kept(&m, "staging"));
}

#[test]
fn an_environment_with_no_identity_here_is_agent_identity_not_installed() {
    let m = machine(&["staging"]);
    let run = remove(&Session::default(), &m, dev());
    assert_eq!(
        code_of(&run.res.unwrap_err()),
        Some("agent_identity_not_installed")
    );
}

#[test]
fn declining_removes_nothing() {
    let m = machine(&["dev"]);
    let _ = remove(
        &Session::default(),
        &m,
        Opts {
            decline: true,
            ..dev()
        },
    );
    assert!(kept(&m, "dev"));
}

#[test]
fn one_environment_ends_with_its_doctor() {
    let m = machine(&["dev"]);
    let run = remove(&Session::default(), &m, dev());
    assert_eq!(run.out.lines().last(), Some("Next: opv doctor --env dev"));
}

// --- every identity on the machine ----------------------------------------------------

#[test]
fn no_environment_removes_every_index_entry_of_the_project() {
    let m = machine(&["dev", "staging"]);
    let _ = remove(&Session::default(), &m, Opts::default());
    assert!(indexed(&m).is_empty());
}

#[test]
fn no_environment_deletes_every_token() {
    let m = machine(&["dev", "staging"]);
    let _ = remove(&Session::default(), &m, Opts::default());
    assert!(!kept(&m, "dev") && !kept(&m, "staging"));
}

#[test]
fn the_one_question_lists_every_identity() {
    let m = machine(&["dev", "staging"]);
    let run = remove(&Session::default(), &m, Opts::default());
    assert_eq!(
        run.shown,
        vec![
            "Remove 2 agent identities from this machine: their tokens in macOS Keychain and \
             their entries:"
                .to_string(),
            format!("  {}      (dev)", name("dev")),
            format!("  {}  (staging)", name("staging")),
        ]
    );
}

#[test]
fn no_identity_of_the_project_names_create() {
    let m = machine(&[]);
    let run = remove(&Session::default(), &m, Opts::default());
    assert_eq!(code_of(&run.res.unwrap_err()), Some("usage"));
}

#[test]
fn no_environment_ends_with_doctor() {
    let m = machine(&["dev", "staging"]);
    let run = remove(&Session::default(), &m, Opts::default());
    assert_eq!(run.out.lines().last(), Some("Next: opv doctor"));
}

// --- a store delete that fails, and a missing store entry ----------------------------

fn failing_dev(envs: &[&str]) -> Machine {
    let mut m = machine(envs);
    m.store.fail_env = Some("dev");
    m
}

#[test]
fn a_failed_store_delete_keeps_the_index_entry() {
    let m = failing_dev(&["dev", "staging"]);
    let _ = remove(&Session::default(), &m, Opts::default());
    assert_eq!(indexed(&m), vec!["dev".to_string()]);
}

#[test]
fn a_failed_store_delete_is_the_runs_result() {
    let m = failing_dev(&["dev", "staging"]);
    let run = remove(&Session::default(), &m, Opts::default());
    assert_eq!(code_of(&run.res.unwrap_err()), Some("agent_store_locked"));
}

#[test]
fn a_failed_store_delete_says_the_entry_is_kept() {
    let m = failing_dev(&["dev"]);
    let run = remove(&Session::default(), &m, dev());
    assert_eq!(
        run.out.trim_end(),
        format!(
            "not removed {:?} (dev): agent_store_locked; its token could not be deleted from \
             macOS Keychain, so its entry is kept",
            name("dev")
        )
    );
}

#[test]
fn a_missing_store_entry_still_removes_the_index_entry() {
    let m = machine(&["dev"]);
    m.store.delete(&key("dev")).unwrap();
    let _ = remove(&Session::default(), &m, dev());
    assert!(indexed(&m).is_empty());
}

#[test]
fn a_missing_store_entry_is_noted() {
    let m = machine(&["dev"]);
    m.store.delete(&key("dev")).unwrap();
    let run = remove(&Session::default(), &m, dev());
    assert_eq!(
        run.out.lines().next().map(str::to_string),
        Some(format!(
            "removed {:?} (dev): macOS Keychain held no token for it, so only its entry was \
             removed",
            name("dev")
        ))
    );
}

// --- the Do line ----------------------------------------------------------------------

fn do_line(run: &Run) -> Option<String> {
    run.out
        .lines()
        .find(|l| l.starts_with("Do: "))
        .map(str::to_string)
}

#[test]
fn the_do_line_names_every_removed_account() {
    let m = machine(&["dev", "staging"]);
    let run = remove(&Session::default(), &m, Opts::default());
    assert_eq!(
        do_line(&run),
        Some(format!(
            "Do: delete these in the 1Password web app (Developer > Service accounts); opv \
             cannot: {}, {}",
            name("dev"),
            name("staging")
        ))
    );
}

#[test]
fn the_do_line_names_an_interrupted_rotations_successor() {
    let m = machine(&["dev"]);
    let mut entry = agent_identity::load(&m.index).unwrap().identities[0].clone();
    entry.record.rotation_successor = Some("shop-dev-agent-laptop-20261117-0900".into());
    agent_identity::record(&m.index, entry).unwrap();
    let run = remove(&Session::default(), &m, dev());
    assert!(do_line(&run).is_some_and(|l| l.ends_with(&format!(
        "{}, shop-dev-agent-laptop-20261117-0900",
        name("dev")
    ))));
}

#[test]
fn the_do_line_leaves_out_an_identity_that_was_not_removed() {
    let m = failing_dev(&["dev", "staging"]);
    let run = remove(&Session::default(), &m, Opts::default());
    assert!(do_line(&run).is_some_and(|l| l.ends_with(&format!("cannot: {}", name("staging")))));
}

// --- refused under the agent ----------------------------------------------------------

#[test]
fn a_service_account_session_is_refused() {
    let s = Session {
        service_account: true,
        ..Session::default()
    };
    let m = machine(&["dev"]);
    let run = remove(&s, &m, dev());
    assert_eq!(code_of(&run.res.unwrap_err()), Some("own_session_required"));
}

#[test]
fn a_refused_run_keeps_the_token() {
    let s = Session {
        service_account: true,
        ..Session::default()
    };
    let m = machine(&["dev"]);
    let _ = remove(&s, &m, dev());
    assert!(kept(&m, "dev"));
}

// --- JSON and the no-token canary -----------------------------------------------------

#[test]
fn the_json_document_lists_every_account_to_delete() {
    let m = machine(&["dev", "staging"]);
    let run = remove(
        &Session::default(),
        &m,
        Opts {
            json: true,
            ..Opts::default()
        },
    );
    let doc: serde_json::Value = serde_json::from_str(&run.out).unwrap();
    assert_eq!(
        doc["delete"],
        serde_json::json!([name("dev"), name("staging")])
    );
}

#[test]
fn the_json_document_marks_a_kept_index_entry() {
    let m = failing_dev(&["dev"]);
    let run = remove(
        &Session::default(),
        &m,
        Opts {
            json: true,
            ..dev()
        },
    );
    let doc: serde_json::Value = serde_json::from_str(&run.out).unwrap();
    assert_eq!(doc["not_removed"][0]["index_entry_kept"], true);
}

#[test]
fn no_channel_carries_a_token() {
    let text_machine = machine(&["dev", "staging"]);
    let text = remove(&Session::default(), &text_machine, Opts::default());
    let json_machine = machine(&["dev", "staging"]);
    let json = remove(
        &Session::default(),
        &json_machine,
        Opts {
            json: true,
            ..Opts::default()
        },
    );
    let failed_machine = failing_dev(&["dev", "staging"]);
    let failed = remove(&Session::default(), &failed_machine, Opts::default());
    let err = failed.res.as_ref().unwrap_err();
    let inv = Invocation::default();
    let index = |m: &Machine| std::fs::read_to_string(&m.index).unwrap_or_default();
    let all = [&text, &json, &failed]
        .iter()
        .map(|r| format!("{}{}", r.out, r.shown.join("\n")))
        .chain([
            index(&text_machine),
            index(&json_machine),
            index(&failed_machine),
            format!("{err:?}{err}"),
            crate::error::document(err, &inv, true).to_string(),
        ])
        .collect::<String>();
    assert!(!all.contains("FAKETOKENMARKER"), "{all}");
}
