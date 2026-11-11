//! #296: recording credential expiry dates, value-free, beside the contract. One
//! behavioural scenario per test, each through the command's public `run`.

use std::cell::RefCell;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::json;

use super::*;
use crate::adapters::fake_op::FakeOp;
use crate::domain::Fleet;
use crate::runner::{Call, Outcome, Output};

/// The day the recorded expiry is measured from.
fn today() -> String {
    crate::app::retire::today()
}

/// The value-free expiry recorded at `key` is exactly `days_left` days after today.
fn assert_recorded_expiry_is_days_ahead(path: &Path, key: &str, days_left: i64) {
    let bindings = crate::config::bindings::read_sibling(path).unwrap();
    let recorded = bindings.get(key).map(str::to_string);
    assert_eq!(
        crate::domain::credential::expiry_state(recorded.as_deref(), &today(), days_left),
        crate::domain::credential::ExpiryState::Expiring { days_left }
    );
}

/// The value-free expiry recorded at `key` is absent.
fn assert_no_expiry_recorded(path: &Path, key: &str) {
    let bindings = crate::config::bindings::read_sibling(path).unwrap();
    assert!(bindings.get(key).is_none());
}

fn write_file(text: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.toml");
    crate::config::bindings::write_split(&path, text).unwrap();
    (dir, path)
}

// ── target credentials --create (R2) ────────────────────────────────────────────

const DEPLOY_TOKEN: &str = "fo1_FAKEDEPLOYTOKENMARKER0123456789";

fn deploy_fleet_text() -> String {
    "[environments.staging]\n\
     boundaries.web = { vault_id = \"vweb\", item_id = \"iweb\" }\n\
     \n\
     [environments.staging.targets.web]\n\
     fly.app = \"shop-staging\"\n\
     fly.secret_name = \"{KEY}\"\n\
     state_vault_id = \"vstate\"\n\
     \n\
     [products.web.keys.WEB_KEY]\n\
     kind = \"secret\"\n\
     environments = [\"staging\"]\n"
        .to_string()
}

fn deploy_fleet() -> Fleet {
    crate::config::parse(&deploy_fleet_text()).unwrap()
}

/// A fake `op` (state vault present, readable) and a `flyctl` that mints a deploy token.
struct DeployWorld {
    op: FakeOp,
    minted: Option<String>,
}

impl DeployWorld {
    fn new() -> Self {
        let op = FakeOp::default();
        op.vaults.borrow_mut().push(("vweb".into(), "web".into()));
        op.vaults
            .borrow_mut()
            .push(("vstate".into(), "state".into()));
        Self {
            op,
            minted: Some(DEPLOY_TOKEN.to_string()),
        }
    }
}

impl CommandRunner for DeployWorld {
    fn read(&self, call: &Call, refused: &[i32]) -> io::Result<Outcome> {
        self.op.read(call, refused)
    }
    fn probe(&self, call: &Call, limit: Duration) -> io::Result<Output> {
        if call.program == "flyctl" && call.args == ["auth", "whoami"] {
            return Ok(Output::success("me@example.com\n"));
        }
        self.op.probe(call, limit)
    }
    fn write(&self, call: &Call) -> io::Result<Outcome> {
        if call.program == "flyctl" && call.args.first().copied() == Some("tokens") {
            return Ok(match &self.minted {
                Some(t) => Outcome::Done(Output::success(format!("{t}\n"))),
                None => Outcome::Refused(Output::failure(1)),
            });
        }
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

fn create_deploy(w: &DeployWorld, fleet: &Fleet, path: &Path) -> Result<(), Error> {
    let mut ui = Answer(true, RefCell::new(Vec::new()));
    let mut out = Vec::new();
    crate::app::target_credentials::run(fleet, path, "staging", "web", "shop", w, &mut ui, &mut out)
}

#[test]
fn target_credentials_records_the_deploy_expiry_ninety_days_ahead() {
    let w = DeployWorld::new();
    let (_d, path) = write_file(&deploy_fleet_text());
    let _ = create_deploy(&w, &deploy_fleet(), &path);
    assert_recorded_expiry_is_days_ahead(
        &path,
        &crate::domain::credential::deploy_expires_path("staging", "web"),
        90,
    );
}

#[test]
fn a_failed_store_records_no_deploy_expiry() {
    let w = DeployWorld::new();
    // The state vault is gone: `op item create` fails, so nothing is minted-and-stored.
    w.op.vaults.borrow_mut().retain(|(id, _)| id != "vstate");
    let (_d, path) = write_file(&deploy_fleet_text());
    let _ = create_deploy(&w, &deploy_fleet(), &path);
    assert_no_expiry_recorded(
        &path,
        &crate::domain::credential::deploy_expires_path("staging", "web"),
    );
}

// ── access --create (R3) ────────────────────────────────────────────────────────

fn access_fleet_text() -> String {
    "[environments.staging]\n\
     boundaries.web = { vault_id = \"vweb\", item_id = \"iweb\" }\n\
     \n\
     [environments.staging.targets.fleet]\n\
     fly.app = \"shop-staging\"\n\
     fly.secret_name = \"{KEY}\"\n\
     state_vault_id = \"vstate\"\n\
     \n\
     [products.web.keys.WEB_KEY]\n\
     kind = \"secret\"\n\
     environments = [\"staging\"]\n"
        .to_string()
}

fn access_fleet() -> Fleet {
    crate::config::parse(&access_fleet_text()).unwrap()
}

/// The fleet as it loads from the contract at `path`, so its bindings sibling is there.
fn located_at(fleet: &Fleet, path: &Path) -> Fleet {
    let mut fleet = fleet.clone();
    fleet.read_from = crate::domain::model::ReadFrom(crate::cause::ConfigSource::File {
        path: path.to_path_buf(),
        given_by: crate::cause::GivenBy::Discovered,
    });
    fleet
}

const TOKEN: &str = "ops_FAKETOKENMARKER0123456789";

/// A fake `op` (both vaults in the account, readable) and a scripted `gh`.
struct AccessWorld {
    op: FakeOp,
    gh_signed_in: bool,
    gh_set_fails: bool,
    created: String,
}

impl AccessWorld {
    fn new() -> Self {
        let op = FakeOp::default();
        op.vaults.borrow_mut().push(("vweb".into(), "web".into()));
        op.vaults
            .borrow_mut()
            .push(("vstate".into(), "state".into()));
        op.vault_users.borrow_mut().insert("vweb".into(), json!([]));
        op.vault_users
            .borrow_mut()
            .insert("vstate".into(), json!([]));
        Self {
            op,
            gh_signed_in: true,
            gh_set_fails: false,
            created: format!("{TOKEN}\n"),
        }
    }
}

impl CommandRunner for AccessWorld {
    fn read(&self, call: &Call, refused: &[i32]) -> io::Result<Outcome> {
        if call.program == "gh" {
            return Ok(Outcome::Done(Output::success(
                json!({"environments": [{"name": "staging-deploy"}]}).to_string(),
            )));
        }
        self.op.read(call, refused)
    }
    fn probe(&self, call: &Call, limit: Duration) -> io::Result<Output> {
        if call.program == "gh" {
            return Ok(if self.gh_signed_in {
                Output::success("")
            } else {
                Output::failure(1)
            });
        }
        self.op.probe(call, limit)
    }
    fn write(&self, call: &Call) -> io::Result<Outcome> {
        match (call.program, call.args.first().copied()) {
            ("op", Some("service-account")) => {
                Ok(Outcome::Done(Output::success(self.created.clone())))
            }
            ("gh", Some("secret")) if self.gh_set_fails => Ok(Outcome::Refused(Output::failure(1))),
            ("gh", Some("secret")) => Ok(Outcome::Done(Output::success(""))),
            _ => self.op.write(call),
        }
    }
    fn pause(&self, _: Duration, _: &str) {}
    fn note(&self, _: &str) {}
    fn run_inherited(&self, _: &str, _: &[&str], _: &[(&str, &str)]) -> io::Result<i32> {
        Err(io::ErrorKind::PermissionDenied.into())
    }
}

fn create_access(w: &AccessWorld, fleet: &Fleet, target: Option<&str>) -> Result<(), Error> {
    let mut ui = Answer(true, RefCell::new(Vec::new()));
    let mut out = Vec::new();
    let req = Request {
        env: "staging",
        target,
        project: "shop",
        github: GitHub {
            repo: "acme/infra".into(),
            environment: Some("staging-deploy".into()),
            secret: SECRET.into(),
        },
    };
    run(fleet, &req, w, &mut ui, &mut out)
}

#[test]
fn access_create_with_a_target_records_the_ci_identity_expiry_ninety_days_ahead() {
    let w = AccessWorld::new();
    let (_d, path) = write_file(&access_fleet_text());
    let fleet = located_at(&access_fleet(), &path);
    let _ = create_access(&w, &fleet, Some("fleet"));
    assert_recorded_expiry_is_days_ahead(
        &path,
        &crate::domain::credential::ci_identity_expires_path("staging", "fleet"),
        90,
    );
}

#[test]
fn access_create_without_a_target_records_the_ci_reader_expiry_ninety_days_ahead() {
    let w = AccessWorld::new();
    let (_d, path) = write_file(&access_fleet_text());
    let fleet = located_at(&access_fleet(), &path);
    let _ = create_access(&w, &fleet, None);
    assert_recorded_expiry_is_days_ahead(
        &path,
        &crate::domain::credential::ci_reader_expires_path("staging"),
        90,
    );
}

#[test]
fn access_create_records_no_expiry_when_storing_the_secret_failed() {
    let mut w = AccessWorld::new();
    w.gh_set_fails = true;
    let (_d, path) = write_file(&access_fleet_text());
    let fleet = located_at(&access_fleet(), &path);
    let _ = create_access(&w, &fleet, None);
    assert_no_expiry_recorded(
        &path,
        &crate::domain::credential::ci_reader_expires_path("staging"),
    );
}
