//! #304, FR-70: `opv access --create` and `--rotate` record the issued CI identity's grant
//! receipt beside its expiry, from `op whoami` under the new token. One behavioural
//! scenario per test, each through the command's public `run`.

use std::cell::{Cell, RefCell};
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::json;

use super::*;
use crate::adapters::fake_op::FakeOp;
use crate::domain::Fleet;
use crate::domain::grant_receipt::{GrantReceipt, IssuedBy, ReceiptVault, contract_grants};
use crate::runner::{Call, Outcome, Output};

const TOKEN: &str = "ops_FAKERECEIPTTOKENMARKER0123456789";

/// What `op whoami` answers under the new token.
const SERVICE_ACCOUNT_WHOAMI: &str =
    include_str!("../../tests/fixtures/op/success/s30-whoami-service-account.stdout");
const HUMAN_WHOAMI: &str = r#"{"user_uuid":"UHUMAN","account_uuid":"AHUMAN","user_type":"HUMAN"}"#;
const INCOMPLETE_WHOAMI: &str = r#"{"user_type":"SERVICE_ACCOUNT"}"#;

fn fleet_text() -> String {
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

fn write_file() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.toml");
    crate::config::bindings::write_split(&path, &fleet_text()).unwrap();
    (dir, path)
}

/// The fleet as it loads from the contract at `path`, so its bindings sibling is there.
fn located_at(path: &Path) -> Fleet {
    let mut fleet = crate::config::parse(&fleet_text()).unwrap();
    fleet.read_from = crate::domain::model::ReadFrom(crate::cause::ConfigSource::File {
        path: path.to_path_buf(),
        given_by: crate::cause::GivenBy::Discovered,
    });
    fleet
}

/// The fleet as a manifest-configured project loads it: no bindings sibling.
fn from_manifest() -> Fleet {
    let mut fleet = crate::config::parse(&fleet_text()).unwrap();
    fleet.read_from = crate::domain::model::ReadFrom(crate::cause::ConfigSource::Manifest {
        title: "shop · opv".into(),
        vault: crate::cause::VaultId::new("vmanifest"),
        project: "shop".into(),
    });
    fleet
}

/// One recorded call: program, arguments, env names and values.
type Recorded = (String, Vec<String>, Vec<(String, String)>);

/// A fake `op` (both vaults in the account, readable, no service account listed) and a
/// scripted `gh` whose secret already exists, recording every call with its env.
struct World {
    op: FakeOp,
    /// `op whoami`'s answer under the new token.
    whoami: &'static str,
    whoami_ran_with_token: Cell<bool>,
    calls: RefCell<Vec<Recorded>>,
}

impl World {
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
        World {
            op,
            whoami: SERVICE_ACCOUNT_WHOAMI,
            whoami_ran_with_token: Cell::new(false),
            calls: RefCell::new(Vec::new()),
        }
    }

    fn record(&self, call: &Call) {
        self.calls.borrow_mut().push((
            call.program.to_string(),
            call.args.iter().map(|a| a.to_string()).collect(),
            call.env
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        ));
    }

    fn argv_contains(&self, needle: &str) -> bool {
        self.calls
            .borrow()
            .iter()
            .any(|(_, args, _)| args.iter().any(|a| a.contains(needle)))
    }
}

impl CommandRunner for World {
    fn read(&self, call: &Call, refused: &[i32]) -> io::Result<Outcome> {
        self.record(call);
        let under_token = call
            .env
            .iter()
            .any(|(k, v)| *k == "OP_SERVICE_ACCOUNT_TOKEN" && *v == TOKEN);
        if call.program == "op" && call.args.first().copied() == Some("whoami") && under_token {
            self.whoami_ran_with_token.set(true);
            return Ok(Outcome::Done(Output::success(self.whoami)));
        }
        if call.program == "gh" {
            let out = match call.args {
                ["secret", "list", ..] => Output::success(
                    json!([{"name": "OP_SERVICE_ACCOUNT_TOKEN", "updatedAt": "2026-11-10T00:00:00Z"}])
                        .to_string(),
                ),
                _ => Output::success(
                    json!({"environments": [{"name": "staging-deploy"}]}).to_string(),
                ),
            };
            return Ok(Outcome::Done(out));
        }
        self.op.read(call, refused)
    }
    fn probe(&self, call: &Call, limit: Duration) -> io::Result<Output> {
        self.record(call);
        match call.program {
            "op" if call.args.first().copied() == Some("whoami") => {
                Ok(Output::success(r#"{"user_type":"HUMAN"}"#))
            }
            "gh" => Ok(Output::success("")),
            _ => self.op.probe(call, limit),
        }
    }
    fn write(&self, call: &Call) -> io::Result<Outcome> {
        self.record(call);
        match (call.program, call.args.first().copied()) {
            ("op", Some("service-account")) => {
                Ok(Outcome::Done(Output::success(format!("{TOKEN}\n"))))
            }
            ("gh", _) => Ok(Outcome::Done(Output::success(""))),
            _ => self.op.write(call),
        }
    }
    fn pause(&self, _: Duration, _: &str) {}
    fn note(&self, _: &str) {}
    fn run_inherited(&self, _: &str, _: &[&str], _: &[(&str, &str)]) -> io::Result<i32> {
        Err(io::ErrorKind::PermissionDenied.into())
    }
}

struct Yes;

impl Interaction for Yes {
    fn show(&mut self, _: &str) -> Result<(), Error> {
        Ok(())
    }
    fn confirm(&mut self, _: &str) -> Result<bool, Error> {
        Ok(true)
    }
    fn secret(&mut self, _: &str) -> Result<SecretValue, Error> {
        unreachable!("never asks for a secret")
    }
}

fn request(target: Option<&str>) -> Request<'_> {
    Request {
        env: "staging",
        target,
        project: "shop",
        github: GitHub {
            repo: "acme/infra".into(),
            environment: Some("staging-deploy".into()),
            secret: SECRET.into(),
        },
    }
}

/// `opv access staging [--target t] --create`: its stdout.
fn create(w: &World, fleet: &Fleet, target: Option<&str>) -> String {
    let mut out = Vec::new();
    let _ = run(fleet, &request(target), w, &mut Yes, &mut out);
    String::from_utf8(out).unwrap()
}

/// `opv access staging [--target t] --rotate`: its stdout.
fn rotate(w: &World, fleet: &Fleet, target: Option<&str>) -> String {
    let mut out = Vec::new();
    let _ =
        crate::app::credentials_rotate::run_access(fleet, &request(target), w, &mut Yes, &mut out);
    String::from_utf8(out).unwrap()
}

/// The CI reader's receipt as recorded beside the contract at `path`.
fn reader_receipt(
    path: &Path,
) -> Option<Result<GrantReceipt, crate::domain::grant_receipt::Reason>> {
    crate::config::bindings::read_sibling(path)
        .unwrap()
        .receipt(&crate::domain::credential::ci_reader_receipt_path(
            "staging",
        ))
}

fn recorded_reader_receipt(path: &Path) -> GrantReceipt {
    reader_receipt(path)
        .expect("a receipt")
        .expect("a valid receipt")
}

#[test]
fn access_create_records_the_service_accounts_ids_in_the_receipt() {
    let w = World::new();
    let (_d, path) = write_file();
    create(&w, &located_at(&path), None);
    let receipt = recorded_reader_receipt(&path);
    assert_eq!(
        (
            receipt.account_id.as_str(),
            receipt.service_account_user_id.as_str()
        ),
        ("<ACCOUNT_1>", "<SERVICE_ACCOUNT_USER>")
    );
}

#[test]
fn the_receipts_digest_is_the_contract_grants_of_the_requested_grants() {
    let (_d, path) = write_file();
    let fleet = located_at(&path);
    let requested = crate::app::access::identity(&fleet, "staging", None, "shop", &World::new())
        .unwrap()
        .grants;
    create(&World::new(), &fleet, None);
    assert_eq!(
        recorded_reader_receipt(&path).contract_grants,
        contract_grants(&requested)
    );
}

#[test]
fn the_receipt_lists_each_vault_with_the_permissions_requested() {
    let w = World::new();
    let (_d, path) = write_file();
    create(&w, &located_at(&path), Some("fleet"));
    let receipt = crate::config::bindings::read_sibling(&path)
        .unwrap()
        .receipt(&crate::domain::credential::ci_identity_receipt_path(
            "staging", "fleet",
        ))
        .unwrap()
        .unwrap();
    assert_eq!(
        receipt.vaults,
        [
            ReceiptVault {
                id: "vstate".into(),
                permissions: vec!["read_items".into(), "write_items".into()],
            },
            ReceiptVault {
                id: "vweb".into(),
                permissions: vec!["read_items".into()],
            },
        ]
    );
}

#[test]
fn the_receipt_expires_on_the_recorded_expiry_date() {
    let w = World::new();
    let (_d, path) = write_file();
    create(&w, &located_at(&path), None);
    let expiry = crate::config::bindings::read_sibling(&path)
        .unwrap()
        .get(&crate::domain::credential::ci_reader_expires_path(
            "staging",
        ))
        .map(str::to_string);
    assert_eq!(Some(recorded_reader_receipt(&path).expires_on), expiry);
}

#[test]
fn access_create_records_issued_by_create() {
    let w = World::new();
    let (_d, path) = write_file();
    create(&w, &located_at(&path), None);
    assert_eq!(recorded_reader_receipt(&path).issued_by, IssuedBy::Create);
}

#[test]
fn access_rotation_records_issued_by_rotate() {
    let w = World::new();
    let (_d, path) = write_file();
    rotate(&w, &located_at(&path), None);
    assert_eq!(recorded_reader_receipt(&path).issued_by, IssuedBy::Rotate);
}

#[test]
fn access_rotation_records_the_successors_name() {
    let w = World::new();
    let (_d, path) = write_file();
    rotate(&w, &located_at(&path), None);
    let suffix = crate::app::retire::today().replace('-', "");
    assert_eq!(
        recorded_reader_receipt(&path).service_account_name,
        format!("shop-staging-ci-{suffix}")
    );
}

#[test]
fn access_create_runs_whoami_with_the_token_in_the_childs_environment() {
    let w = World::new();
    let (_d, path) = write_file();
    create(&w, &located_at(&path), None);
    assert!(w.whoami_ran_with_token.get());
}

#[test]
fn access_create_never_puts_the_token_in_argv() {
    let w = World::new();
    let (_d, path) = write_file();
    create(&w, &located_at(&path), None);
    assert!(!w.argv_contains("FAKERECEIPTTOKENMARKER"));
}

#[test]
fn access_rotation_never_puts_the_token_in_argv() {
    let w = World::new();
    let (_d, path) = write_file();
    rotate(&w, &located_at(&path), None);
    assert!(!w.argv_contains("FAKERECEIPTTOKENMARKER"));
}

#[test]
fn the_receipt_never_holds_the_token() {
    let w = World::new();
    let (dir, path) = write_file();
    create(&w, &located_at(&path), None);
    let text = std::fs::read_to_string(dir.path().join(crate::config::bindings::FILE)).unwrap();
    assert!(!text.contains("FAKERECEIPTTOKENMARKER"));
}

#[test]
fn a_whoami_that_is_not_a_service_account_writes_no_receipt() {
    let mut w = World::new();
    w.whoami = HUMAN_WHOAMI;
    let (_d, path) = write_file();
    create(&w, &located_at(&path), None);
    assert!(reader_receipt(&path).is_none());
}

#[test]
fn a_whoami_that_is_not_a_service_account_says_why() {
    let mut w = World::new();
    w.whoami = HUMAN_WHOAMI;
    let (_d, path) = write_file();
    let out = create(&w, &located_at(&path), None);
    assert!(out.contains("does not report a service account"), "{out}");
}

#[test]
fn an_incomplete_whoami_writes_no_receipt() {
    let mut w = World::new();
    w.whoami = INCOMPLETE_WHOAMI;
    let (_d, path) = write_file();
    create(&w, &located_at(&path), None);
    assert!(reader_receipt(&path).is_none());
}

#[test]
fn a_whoami_without_a_receipt_still_stores_the_token() {
    let mut w = World::new();
    w.whoami = HUMAN_WHOAMI;
    let (_d, path) = write_file();
    let mut out = Vec::new();
    let res = run(&located_at(&path), &request(None), &w, &mut Yes, &mut out);
    assert!(res.is_ok(), "{res:?}");
}

#[test]
fn a_manifest_project_writes_no_receipt() {
    let w = World::new();
    let (_d, path) = write_file();
    create(&w, &from_manifest(), None);
    assert!(reader_receipt(&path).is_none());
}

#[test]
fn a_manifest_project_says_no_receipt_is_recorded() {
    let w = World::new();
    let out = create(&w, &from_manifest(), None);
    assert!(out.contains("1Password manifest"), "{out}");
}

#[test]
fn recording_an_expiry_keeps_an_existing_receipt() {
    let w = World::new();
    let (_d, path) = write_file();
    create(&w, &located_at(&path), None);
    crate::app::target_credentials::record_expiry(
        &path,
        &crate::domain::credential::deploy_expires_path("staging", "fleet"),
        "2027-02-09",
    )
    .unwrap();
    assert!(matches!(reader_receipt(&path), Some(Ok(_))));
}

#[test]
fn recording_a_receipt_keeps_the_other_identitys_receipt() {
    let (_d, path) = write_file();
    create(&World::new(), &located_at(&path), None);
    create(&World::new(), &located_at(&path), Some("fleet"));
    assert!(matches!(reader_receipt(&path), Some(Ok(_))));
}
