//! `opv access --rotate` and `opv target credentials --rotate` (#296): one person-run step
//! that mints a fresh credential, stores it in place (never shown, never in argv), and
//! prints how to revoke the old one. One behavioural scenario per test.

use std::cell::RefCell;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::json;

use super::*;
use crate::adapters::fake_op::FakeOp;
use crate::runner::fake::FakeRunner;
use crate::runner::{Call, Outcome, Output};

const TOKEN: &str = "ops_FAKEROTATETOKENMARKER0123456789";
const DEPLOY_TOKEN: &str = "fo1_FAKEROTATEDEPLOYTOKENMARKER0123456789";

/// A staging environment with one Fly target and its state vault; `deploy` adds the
/// `deploy_credentials` line an earlier create would have recorded.
fn fleet_text(deploy: Option<&str>) -> String {
    let line = deploy
        .map(|r| format!("deploy_credentials = {r:?}\n"))
        .unwrap_or_default();
    format!(
        "[environments.staging]\n\
         boundaries.web = {{ vault_id = \"vweb\", item_id = \"iweb\" }}\n\
         \n\
         [environments.staging.targets.web]\n\
         fly.app = \"shop-staging\"\n\
         fly.secret_name = \"{{KEY}}\"\n\
         {line}state_vault_id = \"vstate\"\n\
         \n\
         [products.web.keys.WEB_KEY]\n\
         kind = \"secret\"\n\
         environments = [\"staging\"]\n"
    )
}

fn fleet(deploy: Option<&str>) -> Fleet {
    crate::config::parse(&fleet_text(deploy)).unwrap()
}

/// One recorded call: program, arguments, stdin, env values.
type Recorded = (String, Vec<String>, Option<Vec<u8>>, Vec<(String, String)>);

/// The fake `op` (vaults and item state) plus a scripted `gh` and `flyctl`, recording every
/// call with its stdin and env.
struct World {
    op: FakeOp,
    gh_signed_in: bool,
    gh_env_exists: bool,
    /// `None`: the secret is absent; `Some`: it is listed.
    gh_secret_listed: bool,
    /// A failed `gh secret set` goes through `observed` as an unknown outcome.
    gh_set_unknown: bool,
    /// `op whoami` answers a service account.
    service_account: bool,
    observed: FakeRunner,
    created: String,
    minted: Option<String>,
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
        // The item an earlier `target credentials --create` would have made.
        op.insert(
            "vstate",
            json!({
                "category": "SECURE_NOTE",
                "title": "shop · web · staging deploy credentials",
                "fields": [
                    {"id": "FLY_API_TOKEN", "label": "FLY_API_TOKEN", "type": "CONCEALED", "value": "old"}
                ],
                "tags": []
            }),
        );
        World {
            op,
            gh_signed_in: true,
            gh_env_exists: true,
            gh_secret_listed: true,
            gh_set_unknown: false,
            service_account: false,
            observed: FakeRunner::default(),
            created: format!("{TOKEN}\n"),
            minted: Some(DEPLOY_TOKEN.to_string()),
            calls: RefCell::new(Vec::new()),
        }
    }

    fn record(&self, call: &Call) {
        self.calls.borrow_mut().push((
            call.program.to_string(),
            call.args.iter().map(|a| a.to_string()).collect(),
            call.stdin.map(<[u8]>::to_vec),
            call.env
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        ));
    }

    fn count(&self, program: &str, first: &[&str]) -> usize {
        self.calls
            .borrow()
            .iter()
            .filter(|(p, a, _, _)| {
                p == program
                    && a.iter()
                        .map(String::as_str)
                        .take(first.len())
                        .eq(first.iter().copied())
            })
            .count()
    }

    fn ran(&self, program: &str, first: &[&str]) -> bool {
        self.count(program, first) > 0
    }

    fn argv_contains(&self, needle: &str) -> bool {
        self.calls
            .borrow()
            .iter()
            .any(|(_, a, _, _)| a.iter().any(|x| x.contains(needle)))
    }

    fn env_value(&self, program: &str, key: &str) -> Option<String> {
        self.calls
            .borrow()
            .iter()
            .filter(|(p, _, _, _)| p == program)
            .flat_map(|(_, _, _, e)| e.iter())
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
    }
}

impl CommandRunner for World {
    fn read(&self, call: &Call, refused: &[i32]) -> io::Result<Outcome> {
        self.record(call);
        if call.program == "gh" {
            let out = match call.args {
                ["secret", "list", ..] => {
                    let rows = if self.gh_secret_listed {
                        json!([{"name": "OP_SERVICE_ACCOUNT_TOKEN", "updatedAt": "2026-11-10T00:00:00Z"}])
                    } else {
                        json!([])
                    };
                    Output::success(rows.to_string())
                }
                ["api", ..] => {
                    let envs = if self.gh_env_exists {
                        json!({"environments": [{"name": "staging-deploy"}]})
                    } else {
                        json!({"environments": []})
                    };
                    Output::success(envs.to_string())
                }
                _ => Output::success(""),
            };
            return Ok(Outcome::Done(out));
        }
        self.op.read(call, refused)
    }

    fn probe(&self, call: &Call, limit: Duration) -> io::Result<Output> {
        self.record(call);
        match call.program {
            "op" if call.args.first().copied() == Some("whoami") => {
                Ok(Output::success(if self.service_account {
                    r#"{"user_type":"SERVICE_ACCOUNT"}"#
                } else {
                    r#"{"user_type":"HUMAN"}"#
                }))
            }
            "gh" => Ok(if self.gh_signed_in {
                Output::success("")
            } else {
                Output::failure(1)
            }),
            "flyctl" => Ok(Output::success("me@example.com\n")),
            _ => self.op.probe(call, limit),
        }
    }

    fn write(&self, call: &Call) -> io::Result<Outcome> {
        self.record(call);
        match (call.program, call.args) {
            ("op", ["service-account", "create", ..]) => {
                Ok(Outcome::Done(Output::success(self.created.clone())))
            }
            ("gh", ["secret", "set", ..]) if self.gh_set_unknown => {
                self.observed.push_unknown("lost");
                self.observed.write(call)
            }
            ("gh", _) => Ok(Outcome::Done(Output::success(""))),
            ("flyctl", ["tokens", ..]) => Ok(match &self.minted {
                Some(t) => Outcome::Done(Output::success(format!("{t}\n"))),
                None => Outcome::Refused(Output::failure(1)),
            }),
            _ => self.op.write(call),
        }
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

fn file(text: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.toml");
    crate::config::bindings::write_split(&path, text).unwrap();
    (dir, path)
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

fn access_request(target: Option<&str>) -> crate::app::access_create::Request<'_> {
    crate::app::access_create::Request {
        env: "staging",
        target,
        project: "shop",
        github: crate::app::access_create::GitHub {
            repo: "acme/infra".into(),
            environment: Some("staging-deploy".into()),
            secret: crate::app::access_create::SECRET.into(),
        },
    }
}

fn rotate_access(w: &World, fleet: &Fleet, target: Option<&str>) -> (Result<(), Error>, String) {
    let mut ui = Answer(true, RefCell::new(Vec::new()));
    let mut out = Vec::new();
    let res = run_access(fleet, &access_request(target), w, &mut ui, &mut out);
    (res, String::from_utf8(out).unwrap())
}

fn rotate_target(w: &World, fleet: &Fleet, path: &Path) -> (Result<(), Error>, String) {
    let mut ui = Answer(true, RefCell::new(Vec::new()));
    let mut out = Vec::new();
    let res = run_target(fleet, path, "staging", "web", "shop", w, &mut ui, &mut out);
    (res, String::from_utf8(out).unwrap())
}

// ── R1: a person's own session ─────────────────────────────────────────────────

#[test]
fn access_rotation_refuses_a_service_account_session() {
    let mut w = World::new();
    w.service_account = true;
    let (_d, path) = file(&fleet_text(None));
    let (res, _) = rotate_access(&w, &located_at(&fleet(None), &path), Some("web"));
    assert_eq!(res.unwrap_err().code_str(), "own_session_required");
}

#[test]
fn target_rotation_refuses_a_service_account_session() {
    let mut w = World::new();
    w.service_account = true;
    let deploy = Some("op://vstate/item0000000000000000000001");
    let (_d, path) = file(&fleet_text(deploy));
    let (res, _) = rotate_target(&w, &fleet(deploy), &path);
    assert_eq!(res.unwrap_err().code_str(), "own_session_required");
}

// ── R2: the GitHub secret must already exist ───────────────────────────────────

#[test]
fn access_rotation_refuses_when_the_github_secret_is_missing() {
    let mut w = World::new();
    w.gh_secret_listed = false;
    let (_d, path) = file(&fleet_text(None));
    let (res, _) = rotate_access(&w, &located_at(&fleet(None), &path), Some("web"));
    assert_eq!(
        res.unwrap_err().next_text().unwrap_or_default(),
        "opv access staging --target web --create"
    );
}

#[test]
fn access_rotation_creates_the_successor_with_the_identitys_grants() {
    let w = World::new();
    let (_d, path) = file(&fleet_text(None));
    let _ = rotate_access(&w, &located_at(&fleet(None), &path), Some("web"));
    let args = w
        .calls
        .borrow()
        .iter()
        .find(|(p, a, _, _)| p == "op" && a.first().map(String::as_str) == Some("service-account"))
        .map(|(_, a, _, _)| a.join(" "))
        .unwrap_or_default();
    assert_eq!(
        args,
        format!(
            "service-account create shop-staging-web-deploy-{} --vault vstate:read_items,write_items --vault vweb:read_items --expires-in 90d --raw",
            crate::app::retire::today().replace('-', "")
        )
    );
}

#[test]
fn access_rotation_verifies_the_token_in_the_childs_environment() {
    let w = World::new();
    let (_d, path) = file(&fleet_text(None));
    let _ = rotate_access(&w, &located_at(&fleet(None), &path), Some("web"));
    assert_eq!(
        w.env_value("op", "OP_SERVICE_ACCOUNT_TOKEN").as_deref(),
        Some(TOKEN)
    );
}

#[test]
fn access_rotation_never_puts_the_token_in_argv() {
    let w = World::new();
    let (_d, path) = file(&fleet_text(None));
    let _ = rotate_access(&w, &located_at(&fleet(None), &path), Some("web"));
    assert!(!w.argv_contains("FAKEROTATETOKENMARKER"));
}

#[test]
fn access_rotation_replaces_the_github_secret_on_stdin() {
    let w = World::new();
    let (_d, path) = file(&fleet_text(None));
    let _ = rotate_access(&w, &located_at(&fleet(None), &path), Some("web"));
    let stdin = w
        .calls
        .borrow()
        .iter()
        .find(|(p, a, _, _)| {
            p == "gh"
                && a.first().map(String::as_str) == Some("secret")
                && a.get(1).map(String::as_str) == Some("set")
        })
        .and_then(|(_, _, s, _)| s.clone());
    assert_eq!(stdin.as_deref(), Some(TOKEN.as_bytes()));
}

#[test]
fn access_rotation_names_the_successor() {
    let w = World::new();
    let (_d, path) = file(&fleet_text(None));
    let (_, out) = rotate_access(&w, &located_at(&fleet(None), &path), Some("web"));
    let successor = format!(
        "shop-staging-web-deploy-{}",
        crate::app::retire::today().replace('-', "")
    );
    assert!(out.contains(&successor), "{out}");
}

#[test]
fn access_rotation_prints_a_revoke_step() {
    let w = World::new();
    let (_d, path) = file(&fleet_text(None));
    let (_, out) = rotate_access(&w, &located_at(&fleet(None), &path), Some("web"));
    assert!(out.contains("Do: revoke"), "{out}");
}

#[test]
fn access_rotation_records_the_new_expiry() {
    let w = World::new();
    let (_d, path) = file(&fleet_text(None));
    let _ = rotate_access(&w, &located_at(&fleet(None), &path), Some("web"));
    let bindings = crate::config::bindings::read_sibling(&path).unwrap();
    assert!(
        bindings
            .get(&crate::domain::credential::ci_identity_expires_path(
                "staging", "web"
            ))
            .is_some()
    );
}

// ── R3: a failed secret write is an unknown outcome, never retried ─────────────

#[test]
fn access_rotation_reports_a_failed_secret_write_as_unknown() {
    let mut w = World::new();
    w.gh_set_unknown = true;
    let (_d, path) = file(&fleet_text(None));
    let (res, _) = rotate_access(&w, &located_at(&fleet(None), &path), Some("web"));
    assert_eq!(res.unwrap_err().code_str(), "outcome_unknown");
}

#[test]
fn access_rotation_never_retries_a_failed_secret_write() {
    let mut w = World::new();
    w.gh_set_unknown = true;
    let (_d, path) = file(&fleet_text(None));
    let _ = rotate_access(&w, &located_at(&fleet(None), &path), Some("web"));
    assert_eq!(w.count("gh", &["secret", "set"]), 1);
}

#[test]
fn access_rotation_reads_the_secret_back_after_a_failed_write() {
    let mut w = World::new();
    w.gh_set_unknown = true;
    let (_d, path) = file(&fleet_text(None));
    let _ = rotate_access(&w, &located_at(&fleet(None), &path), Some("web"));
    assert!(w.count("gh", &["secret", "list"]) >= 2);
}

// ── R4: target rotation ────────────────────────────────────────────────────────

#[test]
fn target_rotation_refuses_a_target_without_deploy_credentials() {
    let w = World::new();
    let (_d, path) = file(&fleet_text(None));
    let (res, _) = rotate_target(&w, &fleet(None), &path);
    assert!(
        res.unwrap_err()
            .next_text()
            .unwrap_or_default()
            .contains("--create")
    );
}

#[test]
fn target_rotation_mints_a_fresh_credential() {
    let w = World::new();
    let deploy = Some("op://vstate/item0000000000000000000001");
    let (_d, path) = file(&fleet_text(deploy));
    let _ = rotate_target(&w, &fleet(deploy), &path);
    assert!(w.ran("flyctl", &["tokens"]));
}

#[test]
fn target_rotation_never_puts_the_token_in_argv() {
    let w = World::new();
    let deploy = Some("op://vstate/item0000000000000000000001");
    let (_d, path) = file(&fleet_text(deploy));
    let _ = rotate_target(&w, &fleet(deploy), &path);
    assert!(!w.argv_contains("FAKEROTATEDEPLOYTOKENMARKER"));
}

#[test]
fn target_rotation_records_the_new_expiry() {
    let w = World::new();
    let deploy = Some("op://vstate/item0000000000000000000001");
    let (_d, path) = file(&fleet_text(deploy));
    let _ = rotate_target(&w, &fleet(deploy), &path);
    let bindings = crate::config::bindings::read_sibling(&path).unwrap();
    assert!(
        bindings
            .get(&crate::domain::credential::deploy_expires_path(
                "staging", "web"
            ))
            .is_some()
    );
}

#[test]
fn target_rotation_prints_the_providers_cleanup_hint() {
    let w = World::new();
    let deploy = Some("op://vstate/item0000000000000000000001");
    let (_d, path) = file(&fleet_text(deploy));
    let (_, out) = rotate_target(&w, &fleet(deploy), &path);
    assert!(out.contains("flyctl tokens revoke"), "{out}");
}

// ── R5: re-running converges ───────────────────────────────────────────────────

#[test]
fn access_rotation_refuses_to_make_a_second_successor() {
    let w = World::new();
    let successor = format!(
        "shop-staging-web-deploy-{}",
        crate::app::retire::today().replace('-', "")
    );
    let reader = json!([{
        "type": "SERVICE_ACCOUNT",
        "state": "ACTIVE",
        "name": successor,
        "permissions": ["allow_reading"]
    }]);
    w.op.vault_users
        .borrow_mut()
        .insert("vweb".into(), reader.clone());
    w.op.vault_users
        .borrow_mut()
        .insert("vstate".into(), reader);
    let (_d, path) = file(&fleet_text(None));
    let (res, _) = rotate_access(&w, &located_at(&fleet(None), &path), Some("web"));
    assert!(!w.ran("op", &["service-account"]));
    let _ = res;
}
