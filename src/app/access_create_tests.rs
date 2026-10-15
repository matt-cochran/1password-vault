//! `opv access --create`: one confirmation, the token only ever on gh's stdin.

use std::cell::RefCell;
use std::io;
use std::time::Duration;

use serde_json::json;

use super::*;
use crate::adapters::fake_op::FakeOp;
use crate::runner::Output;

const TOKEN: &str = "ops_FAKETOKENMARKER0123456789";

fn fleet() -> crate::domain::Fleet {
    crate::config::parse(
        r#"[environments.staging]
boundaries.web = { vault_id = "vweb", item_id = "iweb" }

[environments.staging.targets.fleet]
fly.app = "shop-staging"
fly.secret_name = "{KEY}"
state_vault_id = "vstate"

[products.web.keys.WEB_KEY]
kind = "secret"
environments = ["staging"]
"#,
    )
    .unwrap()
}

/// One recorded call: program, arguments, stdin.
type Recorded = (String, Vec<String>, Option<Vec<u8>>);

/// The fake `op` (both vaults in the account, readable, no service account yet) plus a
/// scripted `gh`, recording every call with its stdin.
struct World {
    op: FakeOp,
    gh_signed_in: bool,
    gh_env_exists: bool,
    gh_set_fails: bool,
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
            gh_signed_in: true,
            gh_env_exists: true,
            gh_set_fails: false,
            calls: RefCell::new(Vec::new()),
        }
    }
    fn record(&self, call: &Call) {
        self.calls.borrow_mut().push((
            call.program.to_string(),
            call.args.iter().map(|a| a.to_string()).collect(),
            call.stdin.map(<[u8]>::to_vec),
        ));
    }
    fn ran(&self, program: &str, first: &[&str]) -> bool {
        self.calls.borrow().iter().any(|(p, a, _)| {
            p == program
                && a.iter()
                    .map(String::as_str)
                    .take(first.len())
                    .eq(first.iter().copied())
        })
    }
}

impl CommandRunner for World {
    fn read(&self, call: &Call, refused: &[i32]) -> io::Result<Outcome> {
        self.record(call);
        if call.program == "gh" {
            // `gh api repos/<r>/environments`: the repository's environments.
            let envs = if self.gh_env_exists {
                json!({"environments": [{"name": "staging-deploy"}]})
            } else {
                json!({"environments": []})
            };
            return Ok(Outcome::Done(Output::success(envs.to_string())));
        }
        self.op.read(call, refused)
    }
    fn probe(&self, call: &Call, limit: Duration) -> io::Result<Output> {
        self.record(call);
        if call.program == "gh" {
            let ok = match call.args {
                ["auth", ..] => self.gh_signed_in,
                ["api", path, ..] if path.contains("/environments/") => self.gh_env_exists,
                _ => true,
            };
            return Ok(if ok {
                Output::success("")
            } else {
                Output::failure(1)
            });
        }
        self.op.probe(call, limit)
    }
    fn write(&self, call: &Call) -> io::Result<Outcome> {
        self.record(call);
        match (call.program, call.args) {
            ("op", ["service-account", "create", ..]) => {
                Ok(Outcome::Done(Output::success(format!("{TOKEN}\n"))))
            }
            ("gh", ["secret", "set", ..]) if self.gh_set_fails => {
                Ok(Outcome::Refused(Output::failure(1)))
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

fn gh(env: Option<&str>) -> GitHub {
    GitHub {
        repo: "acme/infra".into(),
        environment: env.map(str::to_string),
        secret: SECRET.into(),
    }
}

fn create(w: &World, target: Option<&str>, yes: bool) -> (Result<(), Error>, String, Vec<String>) {
    let mut ui = Answer(yes, RefCell::new(Vec::new()));
    let mut out = Vec::new();
    let req = Request {
        env: "staging",
        target,
        project: "shop",
        github: gh(Some("staging-deploy")),
    };
    let res = run(&fleet(), &req, w, &mut ui, &mut out);
    let shown = ui.1.borrow().clone();
    (res, String::from_utf8(out).unwrap(), shown)
}

#[test]
fn the_token_reaches_github_on_stdin() {
    let w = World::new();
    let _ = create(&w, Some("fleet"), true);
    let stdin = w
        .calls
        .borrow()
        .iter()
        .find(|(p, a, _)| p == "gh" && a.first().map(String::as_str) == Some("secret"))
        .and_then(|(_, _, s)| s.clone());
    assert_eq!(stdin.as_deref(), Some(TOKEN.as_bytes()));
}

#[test]
fn the_token_is_never_an_argument() {
    let w = World::new();
    let _ = create(&w, Some("fleet"), true);
    assert!(
        !w.calls
            .borrow()
            .iter()
            .any(|(_, a, _)| a.iter().any(|x| x.contains("FAKETOKENMARKER")))
    );
}

#[test]
fn the_token_is_never_shown() {
    let w = World::new();
    let (res, out, shown) = create(&w, Some("fleet"), true);
    let all = format!("{res:?}{out}{}", shown.join("\n"));
    assert!(!all.contains("FAKETOKENMARKER"), "{all}");
}

#[test]
fn the_deploy_identity_reads_the_boundary_and_writes_its_state_vault() {
    let w = World::new();
    let _ = create(&w, Some("fleet"), true);
    let args = w
        .calls
        .borrow()
        .iter()
        .find(|(p, a, _)| p == "op" && a.first().map(String::as_str) == Some("service-account"))
        .map(|(_, a, _)| a.join(" "))
        .unwrap_or_default();
    assert_eq!(
        args,
        "service-account create shop-staging-fleet-deploy --vault vstate:read_items,write_items --vault vweb:read_items --expires-in 90d --raw"
    );
}

#[test]
fn the_ci_reader_only_reads() {
    let w = World::new();
    let _ = create(&w, None, true);
    let args = w
        .calls
        .borrow()
        .iter()
        .find(|(p, a, _)| p == "op" && a.first().map(String::as_str) == Some("service-account"))
        .map(|(_, a, _)| a.join(" "))
        .unwrap_or_default();
    assert!(
        args.contains("--vault vweb:read_items") && !args.contains("write_items"),
        "{args}"
    );
}

#[test]
fn a_secret_set_names_the_repository_and_environment() {
    let w = World::new();
    let _ = create(&w, Some("fleet"), true);
    assert!(w.ran(
        "gh",
        &[
            "secret",
            "set",
            SECRET,
            "-R",
            "acme/infra",
            "-e",
            "staging-deploy"
        ]
    ));
}

#[test]
fn declining_creates_nothing() {
    let w = World::new();
    let _ = create(&w, Some("fleet"), false);
    assert!(!w.ran("op", &["service-account"]));
}

#[test]
fn a_signed_out_gh_creates_nothing() {
    let mut w = World::new();
    w.gh_signed_in = false;
    let _ = create(&w, Some("fleet"), true);
    assert!(!w.ran("op", &["service-account"]));
}

#[test]
fn a_vault_outside_the_account_creates_nothing() {
    let w = World::new();
    w.op.vault_users.borrow_mut().remove("vweb");
    w.op.vaults.borrow_mut().retain(|(id, _)| id != "vweb");
    let (res, _, _) = create(&w, Some("fleet"), true);
    assert_eq!(res.unwrap_err().next_step(), Some("opv vault locate vweb"));
}

#[test]
fn a_missing_github_environment_is_created_before_the_account() {
    let mut w = World::new();
    w.gh_env_exists = false;
    let _ = create(&w, Some("fleet"), true);
    let order: Vec<String> = w
        .calls
        .borrow()
        .iter()
        .filter(|(p, a, _)| {
            (p == "gh" && a.get(1).map(String::as_str) == Some("-X"))
                || (p == "op" && a.first().map(String::as_str) == Some("service-account"))
        })
        .map(|(p, _, _)| p.clone())
        .collect();
    assert_eq!(order, ["gh", "op"]);
}

#[test]
fn a_failed_secret_store_says_to_remove_the_new_account() {
    let mut w = World::new();
    w.gh_set_fails = true;
    let (res, _, _) = create(&w, Some("fleet"), true);
    assert!(
        res.unwrap_err()
            .text()
            .contains("remove that account in 1Password")
    );
}

#[test]
fn a_repository_that_is_not_owner_slash_name_is_refused() {
    let mut g = gh(None);
    g.repo = "acme".into();
    assert_eq!(check(&g).unwrap_err().code().as_str(), "usage");
}
