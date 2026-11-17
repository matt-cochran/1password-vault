//! `opv access [<env>] --rotate --agent` (#338, design `agent-identity.md` §7.3): one
//! scenario and one behavioural assertion per test, over a fake `op` whose every new token
//! reads exactly the vaults it was created with.

use std::cell::RefCell;
use std::io;
use std::time::Duration;

use serde_json::json;

use super::*;
use crate::adapters::credential_store::FakeCredentialSource;
use crate::adapters::fake_op::FakeOp;
use crate::app::agent_identity::INDEX_FILE;
use crate::cause::{AgentStore, Invocation};
use crate::domain::agent_identity::AgentRecord;
use crate::runner::{CreateOutcome, Outcome, Output};

/// Every token this world mints or seeds starts with this, so a canary can look for it.
const MARKER: &str = "ops_FAKETOKENMARKER";
const ACCOUNT: &str = "AFAKEOP0000000000000000001";
const VAULT_DEV: &str = "dddddddddddddddddddddddddd";
const VAULT_STAGING: &str = "ssssssssssssssssssssssssss";
const VAULT_PROD: &str = "pppppppppppppppppppppppppp";

fn fleet() -> Fleet {
    crate::config::parse(&format!(
        r#"[environments.dev]
boundaries.web = {{ vault_id = "{VAULT_DEV}", item_id = "idev" }}

[environments.staging]
boundaries.web = {{ vault_id = "{VAULT_STAGING}", item_id = "istaging" }}

[environments.prod]
tier = "production"
boundaries.web = {{ vault_id = "{VAULT_PROD}", item_id = "iprod" }}

[products.web.keys.WEB_KEY]
kind = "secret"
environments = ["dev", "staging", "prod"]
"#
    ))
    .unwrap()
}

/// The fake `op`: the person's session over the three vaults, and service-account creates
/// that mint a fresh token reading exactly the `--vault`s it was given.
struct World {
    op: FakeOp,
    /// Every token-scoped `op vault list` answers no vault: the binding check fails.
    bind_fails: bool,
    /// `op service-account create` is refused.
    create_refused: bool,
    /// The person's own session is a service account (not a person).
    session_is_service_account: bool,
    /// The successor names asked of `op service-account create`, in order.
    created: RefCell<Vec<String>>,
    /// Each minted token and the vaults it reads.
    tokens: RefCell<Vec<(String, Vec<String>)>>,
}

impl World {
    fn new() -> Self {
        let op = FakeOp::default();
        for v in [VAULT_DEV, VAULT_STAGING, VAULT_PROD] {
            op.vaults.borrow_mut().push((v.into(), v.into()));
            op.vault_users.borrow_mut().insert(v.into(), json!([]));
        }
        World {
            op,
            bind_fails: false,
            create_refused: false,
            session_is_service_account: false,
            created: RefCell::new(Vec::new()),
            tokens: RefCell::new(Vec::new()),
        }
    }
}

impl CommandRunner for World {
    fn read(&self, call: &Call, refused: &[i32]) -> io::Result<Outcome> {
        let token = call
            .env
            .iter()
            .find(|(name, _)| *name == "OP_SERVICE_ACCOUNT_TOKEN")
            .map(|(_, v)| v.to_string());
        if call.program == "op"
            && let Some(token) = token
        {
            if call.args.first() == Some(&"whoami") {
                return Ok(Outcome::Done(Output::success(format!(
                    r#"{{"user_type":"SERVICE_ACCOUNT","account_uuid":"{ACCOUNT}","user_uuid":"bbbbbbbbbbbbbbbbbbbbbbbbbb"}}"#
                ))));
            }
            if call.args.starts_with(&["vault", "list"]) {
                let vaults: Vec<serde_json::Value> = if self.bind_fails {
                    Vec::new()
                } else {
                    self.tokens
                        .borrow()
                        .iter()
                        .find(|(t, _)| *t == token)
                        .map(|(_, v)| v.iter().map(|id| json!({ "id": id })).collect())
                        .unwrap_or_default()
                };
                return Ok(Outcome::Done(Output::success(
                    serde_json::to_string(&vaults).unwrap(),
                )));
            }
        }
        if self.session_is_service_account && call.args.first() == Some(&"whoami") {
            return Ok(Outcome::Done(Output::success(format!(
                r#"{{"user_type":"SERVICE_ACCOUNT","account_uuid":"{ACCOUNT}"}}"#
            ))));
        }
        self.op.read(call, refused)
    }
    fn probe(&self, call: &Call, limit: Duration) -> io::Result<Output> {
        if self.session_is_service_account && call.args.first() == Some(&"whoami") {
            return Ok(Output::success(format!(
                r#"{{"user_type":"SERVICE_ACCOUNT","account_uuid":"{ACCOUNT}"}}"#
            )));
        }
        self.op.probe(call, limit)
    }
    fn create(&self, call: &Call, _: CreateKind) -> io::Result<CreateOutcome> {
        let name = call.args.get(2).map(|s| s.to_string()).unwrap_or_default();
        self.created.borrow_mut().push(name);
        if self.create_refused {
            return Ok(CreateOutcome::Refused(Output::failure(1)));
        }
        let vaults: Vec<String> = call
            .args
            .windows(2)
            .filter(|w| w[0] == "--vault")
            .filter_map(|w| w[1].split(':').next().map(str::to_string))
            .collect();
        let token = format!("{MARKER}{}", self.tokens.borrow().len());
        self.tokens.borrow_mut().push((token.clone(), vaults));
        Ok(CreateOutcome::Done(Output::success(format!("{token}\n"))))
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

fn old_token(env: &str) -> String {
    format!("{MARKER}OLD{env}")
}

fn old_name(env: &str) -> String {
    format!("shop-{env}-agent-laptop")
}

fn successor(env: &str) -> String {
    format!(
        "{}-{}",
        old_name(env),
        crate::app::credentials_rotate::date_suffix()
    )
}

/// One identity per environment in the index, each with its old token in the store.
struct Machine {
    _dir: tempfile::TempDir,
    index: std::path::PathBuf,
    store: FakeCredentialSource,
}

fn machine(envs: &[&str]) -> Machine {
    let dir = tempfile::tempdir().unwrap();
    let index = dir.path().join("opv").join(INDEX_FILE);
    let store = FakeCredentialSource::new(AgentStore::MacosKeychain);
    for env in envs {
        agent_identity::record(
            &index,
            IndexEntry {
                project: "shop".into(),
                account_id: ACCOUNT.into(),
                record: AgentRecord {
                    account_name: old_name(env),
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
            .store(&key(env), &SecretValue::new(old_token(env)))
            .unwrap();
    }
    Machine {
        _dir: dir,
        index,
        store,
    }
}

/// Leave the marker of an interrupted rotation on `env`'s entry.
fn interrupt(m: &Machine, env: &str, pending: &str) {
    let mut entry = loaded(m, env);
    entry.record.rotation_successor = Some(pending.into());
    agent_identity::record(&m.index, entry).unwrap();
}

fn loaded(m: &Machine, env: &str) -> IndexEntry {
    agent_identity::load(&m.index)
        .unwrap()
        .find(ACCOUNT, "shop", env)
        .cloned()
        .unwrap()
}

fn kept(m: &Machine, env: &str) -> Option<String> {
    m.store
        .resolve(&key(env))
        .unwrap()
        .map(|t| t.expose().to_string())
}

#[derive(Default)]
struct Opts<'a> {
    env: Option<&'a str>,
    revoked: Option<&'a str>,
    confirm: Option<&'a str>,
    json: bool,
    decline: bool,
}

struct Run {
    res: Result<(), Error>,
    out: String,
    shown: Vec<String>,
}

fn rotate(w: &World, m: &Machine, o: Opts<'_>) -> Run {
    let mut ui = Answer(!o.decline, RefCell::new(Vec::new()));
    let mut out = Vec::new();
    let req = Request {
        env: o.env,
        project: "shop",
        revoked: o.revoked,
        confirm: o.confirm,
        store: &m.store,
        index: &m.index,
        json: o.json,
    };
    let res = run(&fleet(), &req, w, &mut ui, &mut out);
    let shown = ui.1.borrow().clone();
    Run {
        res,
        out: String::from_utf8(out).unwrap(),
        shown,
    }
}

fn code_of(e: &Error) -> Option<&'static str> {
    e.cause().map(|(c, _)| c.code())
}

fn created(w: &World) -> Vec<String> {
    w.created.borrow().clone()
}

// --- one environment ------------------------------------------------------------------

/// #338: rotating the same identity twice in one minute names two service accounts.
#[test]
fn a_second_rotation_the_same_minute_names_a_new_successor() {
    let w = World::new();
    let m = machine(&["dev"]);
    for _ in 0..2 {
        let _ = rotate(
            &w,
            &m,
            Opts {
                env: Some("dev"),
                ..Opts::default()
            },
        );
    }
    assert_eq!(
        created(&w),
        vec![successor("dev"), format!("{}-2", successor("dev"))]
    );
}

#[test]
fn one_environment_rotates_only_its_identity() {
    let w = World::new();
    let m = machine(&["dev", "staging"]);
    let _ = rotate(
        &w,
        &m,
        Opts {
            env: Some("dev"),
            ..Opts::default()
        },
    );
    assert_eq!(created(&w), vec![successor("dev")]);
}

#[test]
fn the_successor_gets_the_same_read_only_vaults_for_90_days() {
    let w = World::new();
    let m = machine(&["dev"]);
    let _ = rotate(
        &w,
        &m,
        Opts {
            env: Some("dev"),
            ..Opts::default()
        },
    );
    let created = w.tokens.borrow()[0].1.clone();
    assert_eq!(created, vec![VAULT_DEV.to_string()]);
}

#[test]
fn the_successors_token_replaces_the_old_one_in_the_store() {
    let w = World::new();
    let m = machine(&["dev"]);
    let _ = rotate(
        &w,
        &m,
        Opts {
            env: Some("dev"),
            ..Opts::default()
        },
    );
    assert_eq!(kept(&m, "dev"), Some(format!("{MARKER}0")));
}

#[test]
fn a_rotated_identity_is_indexed_under_its_successor_without_a_marker() {
    let w = World::new();
    let m = machine(&["dev"]);
    let _ = rotate(
        &w,
        &m,
        Opts {
            env: Some("dev"),
            ..Opts::default()
        },
    );
    let record = loaded(&m, "dev").record;
    assert_eq!(
        (record.account_name, record.rotation_successor),
        (successor("dev"), None)
    );
}

#[test]
fn a_rotated_identity_expires_in_90_days() {
    let w = World::new();
    let m = machine(&["dev"]);
    let _ = rotate(
        &w,
        &m,
        Opts {
            env: Some("dev"),
            ..Opts::default()
        },
    );
    let expected = crate::domain::credential::add_days(&crate::app::retire::today(), 90).unwrap();
    assert_eq!(loaded(&m, "dev").record.expires_on, expected);
}

#[test]
fn an_environment_with_no_identity_here_is_agent_identity_not_installed() {
    let w = World::new();
    let m = machine(&["staging"]);
    let run = rotate(
        &w,
        &m,
        Opts {
            env: Some("dev"),
            ..Opts::default()
        },
    );
    assert_eq!(
        code_of(&run.res.unwrap_err()),
        Some("agent_identity_not_installed")
    );
}

#[test]
fn declining_rotates_nothing() {
    let w = World::new();
    let m = machine(&["dev"]);
    let _ = rotate(
        &w,
        &m,
        Opts {
            env: Some("dev"),
            decline: true,
            ..Opts::default()
        },
    );
    assert!(created(&w).is_empty());
}

#[test]
fn a_service_account_session_is_refused() {
    let mut w = World::new();
    w.session_is_service_account = true;
    let m = machine(&["dev"]);
    let run = rotate(
        &w,
        &m,
        Opts {
            env: Some("dev"),
            ..Opts::default()
        },
    );
    assert_eq!(code_of(&run.res.unwrap_err()), Some("own_session_required"));
}

// --- every identity on the machine ----------------------------------------------------

#[test]
fn no_environment_rotates_every_identity_on_the_machine() {
    let w = World::new();
    let m = machine(&["dev", "staging"]);
    let _ = rotate(&w, &m, Opts::default());
    assert_eq!(created(&w), vec![successor("dev"), successor("staging")]);
}

#[test]
fn the_question_lists_every_identity_and_its_successor() {
    let w = World::new();
    let m = machine(&["dev", "staging"]);
    let run = rotate(&w, &m, Opts::default());
    let expected = vec![
        "Replace 2 agent identities on this machine, each with a fresh one valid 90 days and \
         the same read-only vaults:"
            .to_string(),
        format!(
            "  {}      -> {}  (dev, 1 vault)",
            old_name("dev"),
            successor("dev")
        ),
        format!(
            "  {}  -> {}  (staging, 1 vault)",
            old_name("staging"),
            successor("staging")
        ),
    ];
    assert_eq!(run.shown, expected);
}

#[test]
fn the_do_line_names_every_old_account() {
    let w = World::new();
    let m = machine(&["dev", "staging"]);
    let run = rotate(&w, &m, Opts::default());
    let expected = format!(
        "created and checked 2 successors; replaced both tokens in macOS Keychain; nothing was printed\n\
         Do: revoke these in 1Password (Developer > Service accounts); opv cannot: {}, {}\n\
         Next: opv doctor\n",
        old_name("dev"),
        old_name("staging")
    );
    assert_eq!(run.out, expected);
}

// --- the binding check ----------------------------------------------------------------

#[test]
fn a_failed_binding_check_keeps_the_old_token() {
    let mut w = World::new();
    w.bind_fails = true;
    let m = machine(&["dev"]);
    let _ = rotate(
        &w,
        &m,
        Opts {
            env: Some("dev"),
            ..Opts::default()
        },
    );
    assert_eq!(kept(&m, "dev"), Some(old_token("dev")));
}

#[test]
fn a_failed_binding_check_names_the_successor_to_remove() {
    let mut w = World::new();
    w.bind_fails = true;
    let m = machine(&["dev"]);
    let run = rotate(
        &w,
        &m,
        Opts {
            env: Some("dev"),
            ..Opts::default()
        },
    );
    let wanted = format!("remove {:?} in 1Password", successor("dev"));
    assert!(
        run.shown.iter().any(|l| l.contains(&wanted)),
        "{:?}",
        run.shown
    );
}

#[test]
fn a_failed_binding_check_is_the_runs_result() {
    let mut w = World::new();
    w.bind_fails = true;
    let m = machine(&["dev"]);
    let run = rotate(
        &w,
        &m,
        Opts {
            env: Some("dev"),
            ..Opts::default()
        },
    );
    assert_eq!(
        code_of(&run.res.unwrap_err()),
        Some("reader_grants_unverified")
    );
}

#[test]
fn a_failed_create_leaves_the_marker_naming_the_successor() {
    let mut w = World::new();
    w.create_refused = true;
    let m = machine(&["dev"]);
    let _ = rotate(
        &w,
        &m,
        Opts {
            env: Some("dev"),
            ..Opts::default()
        },
    );
    assert_eq!(
        loaded(&m, "dev").record.rotation_successor,
        Some(successor("dev"))
    );
}

// --- an interrupted rotation (#324) ---------------------------------------------------

#[test]
fn an_interrupted_rotation_is_secret_not_stored() {
    let w = World::new();
    let m = machine(&["dev", "staging"]);
    interrupt(&m, "dev", "shop-dev-agent-laptop-20261110");
    let run = rotate(&w, &m, Opts::default());
    assert_eq!(code_of(&run.res.unwrap_err()), Some("secret_not_stored"));
}

#[test]
fn an_interrupted_rotation_lets_the_others_go_on() {
    let w = World::new();
    let m = machine(&["dev", "staging"]);
    interrupt(&m, "dev", "shop-dev-agent-laptop-20261110");
    let _ = rotate(&w, &m, Opts::default());
    assert_eq!(created(&w), vec![successor("staging")]);
}

#[test]
fn an_interrupted_rotation_offers_revoked() {
    let w = World::new();
    let m = machine(&["dev"]);
    interrupt(&m, "dev", "shop-dev-agent-laptop-20261110");
    let run = rotate(&w, &m, Opts::default());
    assert!(
        run.shown.iter().any(|l| l
            .contains("opv access dev --rotate --agent --revoked shop-dev-agent-laptop-20261110")),
        "{:?}",
        run.shown
    );
}

#[test]
fn revoked_lets_an_interrupted_rotation_go_ahead() {
    let w = World::new();
    let m = machine(&["dev"]);
    interrupt(&m, "dev", "shop-dev-agent-laptop-20261110");
    let _ = rotate(
        &w,
        &m,
        Opts {
            revoked: Some("shop-dev-agent-laptop-20261110"),
            ..Opts::default()
        },
    );
    assert_eq!(created(&w), vec![successor("dev")]);
}

// --- production -----------------------------------------------------------------------

#[test]
fn production_without_confirm_is_skipped_while_the_others_go_on() {
    let w = World::new();
    let m = machine(&["dev", "prod"]);
    let _ = rotate(&w, &m, Opts::default());
    assert_eq!(created(&w), vec![successor("dev")]);
}

#[test]
fn a_skipped_production_identity_is_a_note_not_a_failure() {
    let w = World::new();
    let m = machine(&["dev", "prod"]);
    let run = rotate(&w, &m, Opts::default());
    assert!(run.res.is_ok(), "{:?}", run.res);
}

#[test]
fn the_skip_note_gives_the_confirmed_command() {
    let w = World::new();
    let m = machine(&["dev", "prod"]);
    let run = rotate(&w, &m, Opts::default());
    assert!(
        run.shown.iter().any(|l| l.starts_with("Note: skipped")
            && l.contains("opv access prod --rotate --agent --confirm prod")),
        "{:?}",
        run.shown
    );
}

#[test]
fn production_alone_without_confirm_is_confirm_required() {
    let w = World::new();
    let m = machine(&["prod"]);
    let run = rotate(
        &w,
        &m,
        Opts {
            env: Some("prod"),
            ..Opts::default()
        },
    );
    assert_eq!(code_of(&run.res.unwrap_err()), Some("confirm_required"));
}

#[test]
fn production_with_confirm_is_rotated() {
    let w = World::new();
    let m = machine(&["prod"]);
    let _ = rotate(
        &w,
        &m,
        Opts {
            env: Some("prod"),
            confirm: Some("prod"),
            ..Opts::default()
        },
    );
    assert_eq!(created(&w), vec![successor("prod")]);
}

// --- JSON and the no-token canary -----------------------------------------------------

#[test]
fn the_json_document_lists_every_old_account_to_revoke() {
    let w = World::new();
    let m = machine(&["dev", "staging"]);
    let run = rotate(
        &w,
        &m,
        Opts {
            json: true,
            ..Opts::default()
        },
    );
    let doc: serde_json::Value = serde_json::from_str(&run.out).unwrap();
    assert_eq!(doc["revoke"], json!([old_name("dev"), old_name("staging")]));
}

#[test]
fn no_channel_carries_a_token() {
    let text_world = World::new();
    let text_machine = machine(&["dev", "staging"]);
    let text = rotate(&text_world, &text_machine, Opts::default());
    let json_world = World::new();
    let json_machine = machine(&["dev", "staging"]);
    let json = rotate(
        &json_world,
        &json_machine,
        Opts {
            json: true,
            ..Opts::default()
        },
    );
    let mut failed_world = World::new();
    failed_world.bind_fails = true;
    let failed_machine = machine(&["dev", "staging"]);
    let failed = rotate(&failed_world, &failed_machine, Opts::default());
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
