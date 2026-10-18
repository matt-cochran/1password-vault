//! Acceptance walkthrough for milestone `core-accepted` (0.12.0): the core documents render
//! in one in-process sim run against one world. The CLI wiring of `inventory` and `next`
//! comes later (`cli-sweep-b`), so each document is rendered through its library entry
//! point. One behavioural assertion per test; the run itself is shared through [`run`].
//!
//! The world: a contract with a `shared`-tier environment (`staging`) and a
//! `production`-tier one (`prod`), each binding boundary `core` through
//! `secrets.bindings.toml` in a temp dir, and three keys of product `api` wanted everywhere.
//! The fake 1Password holds one item per environment where `API_TOKEN` is set, `LOG_LEVEL`
//! is a placeholder and `DATABASE_URL` is absent. Every `op` reply is the fake's
//! (`FakeOp`), except the permission replies, which are the owner's recordings: `op whoami`
//! is `s20-whoami` (`<USER_A>`) and each vault's `op vault user list` is
//! `s23-writer-vault-user-list` (`<USER_A>` is the only writer).

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use serde_json::{Value, json};

use crate::adapters::fake_op::FakeOp;
use crate::app::explain::Asked;
use crate::app::next::{NextDoc, Signals};
use crate::domain::Fleet;
use crate::error::Error;
use crate::json::{NextActor, NextKind};
use crate::runner::{Call, CommandRunner, Outcome, Output};

const S20_WHOAMI: &str = include_str!("../../tests/fixtures/op/success/s20-whoami.stdout");
const S23_WRITER: &str =
    include_str!("../../tests/fixtures/op/success/s23-writer-vault-user-list.stdout");

/// The value placed in the set field; no rendered output may hold it.
const MARKER: &str = "S7MARKER-core";
const PROJECT: &str = "myapp";
/// The `shared`-tier environment's vault (one of the fake's own vaults).
const SHARED_VAULT: &str = "vshr0000000000000000000002";
/// The `production`-tier environment's vault, added to the fake.
const PROD_VAULT: &str = "vprd0000000000000000000003";

/// The contract: ids live in the bindings file beside it, never inline (D-G).
const CONTRACT: &str = r#"[environments.staging]
tier = "shared"
boundaries.core = {}

[environments.prod]
tier = "production"
boundaries.core = {}

[products.api]
boundary = "core"

[products.api.keys.API_TOKEN]
kind = "secret"

[products.api.keys.DATABASE_URL]
kind = "secret"

[products.api.keys.LOG_LEVEL]
kind = "config"
"#;

/// The fake, answering `op whoami` with the owner's recording (the fake's own reply names no
/// user); every other call is the fake's.
struct Session {
    op: FakeOp,
}

impl Session {
    fn whoami(call: &Call) -> bool {
        call.program == "op" && call.args.first() == Some(&"whoami")
    }
}

impl CommandRunner for Session {
    fn read(&self, call: &Call, refused: &[i32]) -> io::Result<Outcome> {
        if Self::whoami(call) {
            return Ok(Outcome::Done(Output::success(S20_WHOAMI)));
        }
        self.op.read(call, refused)
    }

    fn write(&self, call: &Call) -> io::Result<Outcome> {
        self.op.write(call)
    }

    fn probe(&self, call: &Call, limit: Duration) -> io::Result<Output> {
        if Self::whoami(call) {
            return Ok(Output::success(S20_WHOAMI));
        }
        self.op.probe(call, limit)
    }

    fn pause(&self, d: Duration, note: &str) {
        self.op.pause(d, note);
    }

    fn note(&self, line: &str) {
        self.op.note(line);
    }

    fn run_inherited(&self, program: &str, args: &[&str], env: &[(&str, &str)]) -> io::Result<i32> {
        self.op.run_inherited(program, args, env)
    }
}

/// The world: the temp checkout (kept alive), the loaded contract and the session.
struct World {
    _dir: tempfile::TempDir,
    fleet: Fleet,
    r: Session,
}

/// One environment's boundary item: `API_TOKEN` set, `LOG_LEVEL` a placeholder,
/// `DATABASE_URL` absent.
fn item(env: &str) -> Value {
    let field = |label: &str, kind: &str, value: &str| {
        json!({
            "id": format!("f-{label}"),
            "section": {"id": "s-api", "label": "api"},
            "label": label,
            "type": kind,
            "value": value
        })
    };
    json!({
        "title": format!("myapp {env}"),
        "category": "LOGIN",
        "fields": [
            field("API_TOKEN", "CONCEALED", MARKER),
            field("LOG_LEVEL", "STRING", "changeme"),
        ]
    })
}

fn world() -> World {
    let op = FakeOp::default();
    op.vaults
        .borrow_mut()
        .push((PROD_VAULT.into(), "myapp-prod".into()));
    let staging = op.insert(SHARED_VAULT, item("staging"));
    let prod = op.insert(PROD_VAULT, item("prod"));
    let writer: Value = serde_json::from_str(S23_WRITER).unwrap();
    for vault in [SHARED_VAULT, PROD_VAULT] {
        op.vault_users
            .borrow_mut()
            .insert(vault.into(), writer.clone());
    }
    let dir = tempfile::tempdir().unwrap();
    let contract: PathBuf = dir.path().join("secrets.toml");
    std::fs::write(&contract, CONTRACT).unwrap();
    let bindings = format!(
        "environments.prod.boundaries.core.item_id = \"{prod}\"\n\
         environments.prod.boundaries.core.vault_id = \"{PROD_VAULT}\"\n\
         environments.staging.boundaries.core.item_id = \"{staging}\"\n\
         environments.staging.boundaries.core.vault_id = \"{SHARED_VAULT}\"\n"
    );
    std::fs::write(dir.path().join(crate::config::bindings::FILE), bindings).unwrap();
    let fleet = crate::config::load(&contract).unwrap();
    World {
        _dir: dir,
        fleet,
        r: Session { op },
    }
}

/// Every core document of one run, each as rendered, plus the gate's error.
struct Run {
    inventory_text: String,
    inventory_json: Value,
    next: NextDoc,
    ready_gate: Result<(), Error>,
    doctor_r9: String,
    access_json: Value,
    explain_text: String,
    /// Every byte rendered in the run, in order (the documents and the gate's error text).
    all: Vec<u8>,
}

/// The writers each vault's user list reports, for `next`'s `single_writer` judgement.
fn writers(w: &World) -> Signals {
    let mut signals = Signals::default();
    for (vault, users) in w.r.op.vault_users.borrow().iter() {
        let access = crate::domain::access::analyse("", vault, true, Some(users));
        signals.writers.insert(vault.clone(), access.writers.len());
    }
    signals
}

/// The one sim run: every core document rendered against the same world.
fn run() -> Run {
    let w = world();
    let mut all = Vec::new();
    let mut render = |f: &mut dyn FnMut(&mut Vec<u8>)| {
        let mut out = Vec::new();
        f(&mut out);
        all.extend_from_slice(&out);
        String::from_utf8(out).unwrap()
    };

    let inventory_text = render(&mut |out| {
        crate::app::inventory::run(&w.fleet, None, None, &w.r, None, false, out).unwrap();
    });
    let inventory_json = render(&mut |out| {
        crate::app::inventory::run(&w.fleet, None, None, &w.r, None, true, out).unwrap();
    });

    let built = crate::app::inventory::gather(&w.fleet, None, None, &w.r, None).unwrap();
    let next = crate::app::next::next(&built, &writers(&w));
    render(&mut |out| {
        out.extend_from_slice(crate::app::next::render_text(&next).as_bytes());
        out.extend_from_slice(next.document().to_string().as_bytes());
    });

    let mut ready_gate = Ok(());
    render(&mut |out| {
        ready_gate = crate::app::ready::run_at(
            &w.fleet,
            None,
            None,
            &w.r,
            false,
            None,
            true,
            "2026-10-18T00:00:00Z",
            out,
        );
        if let Err(e) = &ready_gate {
            out.extend_from_slice(e.to_string().as_bytes());
        }
    });

    let doctor_r9 = render(&mut |out| {
        crate::app::doctor::production_vault_rows(&w.fleet, "prod", &w.r, out).unwrap();
    });

    let access_json = render(&mut |out| {
        crate::app::access::run(&w.fleet, None, None, Some(PROJECT), &w.r, true, out).unwrap();
    });
    render(&mut |out| {
        crate::app::access::run(&w.fleet, None, None, Some(PROJECT), &w.r, false, out).unwrap();
    });

    let asked = Asked::Key("api/API_TOKEN");
    let explain_text = render(&mut |out| {
        crate::app::explain::run_request_with(
            &w.r,
            &w.fleet,
            &asked,
            Some("staging"),
            PROJECT,
            out,
            false,
        )
        .unwrap();
    });
    render(&mut |out| {
        crate::app::explain::run_request_with(
            &w.r,
            &w.fleet,
            &asked,
            Some("staging"),
            PROJECT,
            out,
            true,
        )
        .unwrap();
    });

    Run {
        inventory_text,
        inventory_json: serde_json::from_str(&inventory_json).unwrap(),
        next,
        ready_gate,
        doctor_r9,
        access_json: serde_json::from_str(&access_json).unwrap(),
        explain_text,
        all,
    }
}

/// The cell of `key` in environment `env`, from the inventory's JSON document.
fn cell<'a>(doc: &'a Value, key: &str, env: &str) -> &'a Value {
    doc["cells"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["key"] == key && c["env"] == env)
        .unwrap()
}

// The walkthrough ---------------------------------------------------------------------------

#[test]
fn the_inventory_cell_of_the_set_key_is_set() {
    let run = run();
    assert_eq!(
        cell(&run.inventory_json, "API_TOKEN", "staging")["state"]["state"],
        "set"
    );
}

#[test]
fn the_inventory_cell_of_the_absent_key_is_absent() {
    let run = run();
    assert_eq!(
        cell(&run.inventory_json, "DATABASE_URL", "staging")["state"]["state"],
        "absent"
    );
}

#[test]
fn the_inventory_text_shows_the_placeholder_key_as_placeholder() {
    let run = run();
    assert!(
        run.inventory_text
            .lines()
            .any(|l| l.starts_with("api/LOG_LEVEL") && l.contains("placeholder/W")),
        "{}",
        run.inventory_text
    );
}

#[test]
fn next_is_the_persons_set_of_the_absent_key() {
    let run = run();
    let action = run
        .next
        .next
        .as_ref()
        .map(|a| (a.kind, a.actor, a.key.clone()));
    assert_eq!(
        action,
        Some((
            NextKind::EnterValue,
            NextActor::Person,
            Some("DATABASE_URL".to_string())
        ))
    );
}

#[test]
fn ready_gate_fails_gate_failed() {
    let run = run();
    assert_eq!(
        run.ready_gate.as_ref().err().map(Error::code_str),
        Some("gate_failed")
    );
}

#[test]
fn doctor_warns_that_the_recorded_writer_reads_the_production_vault() {
    let run = run();
    assert!(
        run.doctor_r9.lines().any(|l| l.starts_with("warn")
            && l.contains("production vault")
            && l.contains(PROD_VAULT)),
        "{}",
        run.doctor_r9
    );
}

#[test]
fn access_raises_single_writer_for_the_production_vault() {
    let run = run();
    let raised = run.access_json["environments"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|e| e["findings"].as_array().unwrap())
        .any(|f| {
            f["code"] == "single_writer" && f["message"].as_str().unwrap().contains(PROD_VAULT)
        });
    assert!(raised, "{}", run.access_json);
}

#[test]
fn explain_lists_the_keys_environments() {
    let run = run();
    let listed = run
        .explain_text
        .lines()
        .find_map(|l| l.trim().strip_prefix("held in:"))
        .map(str::trim);
    assert_eq!(listed, Some("prod, staging"), "{}", run.explain_text);
}

#[test]
fn no_output_of_the_run_holds_the_set_value() {
    let run = run();
    assert!(!String::from_utf8_lossy(&run.all).contains(MARKER));
}
