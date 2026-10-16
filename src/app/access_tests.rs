//! `opv access` (FR-52, FR-59): who needs which vault, per boundary and per target, end to
//! end on the stateful fake `op`. People are counted, never named.

use std::io;
use std::time::Duration;

use super::*;
use crate::adapters::fake_op::FakeOp;
use crate::runner::fake::FakeRunner;
use crate::runner::{Call, Outcome, Output};
use serde_json::{Value, json};

const VSHARED: &str = "vshared";
const VWEB: &str = "vweb";
const VWORKER: &str = "vworker";
const VWEB_STATE: &str = "vwebstate";
const VWORKER_STATE: &str = "vworkerstate";

/// One environment `prod` with two targets: `web` (delivering `web`, whose `SHARED_COPY`
/// key reads `api/SHARED` from the `shared` boundary) and `worker` (delivering `worker`).
fn fleet() -> crate::domain::Fleet {
    crate::config::parse(
        r#"[environments.prod]
boundaries.shared = { vault_id = "vshared", item_id = "ishared" }
boundaries.web = { vault_id = "vweb", item_id = "iweb" }
boundaries.worker = { vault_id = "vworker", item_id = "iworker" }

[environments.prod.targets.web]
fly.app = "shop-prod-web"
fly.secret_name = "{KEY}"
products = ["web"]
state_vault_id = "vwebstate"

[environments.prod.targets.worker]
fly.app = "shop-prod-worker"
fly.secret_name = "WORKER__{KEY}"
products = ["worker"]
state_vault_id = "vworkerstate"

[products.api]
boundary = "shared"
[products.api.keys.SHARED]
kind = "secret"
environments = ["prod"]

[products.web.keys.WEB_KEY]
kind = "secret"
environments = ["prod"]

[products.web.keys.SHARED_COPY]
kind = "secret"
environments = ["prod"]
from = "api/SHARED"

[products.worker.keys.WORKER_KEY]
kind = "secret"
environments = ["prod"]
"#,
    )
    .unwrap()
}

fn member() -> Value {
    json!({"type": "MEMBER", "state": "ACTIVE", "name": "Alice Example",
           "email": "alice@example.com",
           "permissions": ["allow_viewing", "allow_editing", "allow_managing"]})
}

fn account(name: &str, permissions: &[&str]) -> Value {
    json!({"type": "SERVICE_ACCOUNT", "state": "ACTIVE", "name": name,
           "permissions": permissions})
}

/// A fake where every vault is readable and every required grant is present: the deploy
/// identities and the CI reader are read-only on the boundaries, the deploy identities
/// read-write on their own state vaults.
fn visible() -> FakeOp {
    let op = FakeOp::default();
    {
        let mut users = op.vault_users.borrow_mut();
        users.insert(
            VSHARED.into(),
            json!([
                member(),
                account("shop-prod-web-deploy", &["allow_viewing"]),
                account("shop-prod-ci", &["allow_viewing"]),
            ]),
        );
        users.insert(
            VWEB.into(),
            json!([
                member(),
                account("shop-prod-web-deploy", &["allow_viewing"]),
                account("shop-prod-ci", &["allow_viewing"]),
            ]),
        );
        users.insert(
            VWORKER.into(),
            json!([
                member(),
                account("shop-prod-worker-deploy", &["allow_viewing"]),
                account("shop-prod-ci", &["allow_viewing"]),
            ]),
        );
        users.insert(
            VWEB_STATE.into(),
            json!([account(
                "shop-prod-web-deploy",
                &["allow_viewing", "allow_editing"]
            )]),
        );
        users.insert(
            VWORKER_STATE.into(),
            json!([account(
                "shop-prod-worker-deploy",
                &["allow_viewing", "allow_editing"]
            )]),
        );
    }
    op
}

/// A fake where every vault is readable but names no service account: every required grant
/// is missing.
fn members_only() -> FakeOp {
    let op = FakeOp::default();
    {
        let mut users = op.vault_users.borrow_mut();
        for vault in [VSHARED, VWEB, VWORKER, VWEB_STATE, VWORKER_STATE] {
            users.insert(vault.into(), json!([member()]));
        }
    }
    op
}

fn run_json(op: &dyn CommandRunner, env: Option<&str>, target: Option<&str>) -> Value {
    let mut out = Vec::new();
    run(&fleet(), env, target, Some("shop"), op, true, &mut out).unwrap();
    serde_json::from_slice(&out).unwrap()
}

fn run_text(op: &dyn CommandRunner, env: Option<&str>, target: Option<&str>) -> String {
    let mut out = Vec::new();
    run(&fleet(), env, target, Some("shop"), op, false, &mut out).unwrap();
    String::from_utf8(out).unwrap()
}

/// op 2.40.0's recorded reply to `op vault get <vault>` for a vault the account does not
/// hold (tests/fixtures/op/failures, case 14).
const NOT_A_VAULT_HERE: &str =
    include_str!("../../tests/fixtures/op/failures/14-vault-in-other-account.stderr");

/// The fake `op`, whose failed `op vault get` probes go through the observing fake runner
/// with op's recorded reply, as the real runner observes them (#157).
struct Probed {
    op: FakeOp,
    get: FakeRunner,
}

impl Probed {
    fn new(op: FakeOp) -> Self {
        Probed {
            op,
            get: FakeRunner::default(),
        }
    }
}

impl CommandRunner for Probed {
    fn read(&self, call: &Call, refused: &[i32]) -> io::Result<Outcome> {
        self.op.read(call, refused)
    }
    fn write(&self, call: &Call) -> io::Result<Outcome> {
        self.op.write(call)
    }
    fn probe(&self, call: &Call, limit: Duration) -> io::Result<Output> {
        let answer = self.op.probe(call, limit)?;
        match call.args {
            ["vault", "get", vault, ..] if call.program == "op" && answer.status != 0 => {
                self.get.push_with_stderr(
                    Output::failure(1),
                    &NOT_A_VAULT_HERE.replace("<VAULT_B>", vault),
                );
                self.get.probe(call, limit)
            }
            _ => Ok(answer),
        }
    }
    fn pause(&self, _: Duration, _: &str) {}
    fn note(&self, _: &str) {}
    fn run_inherited(&self, _: &str, _: &[&str], _: &[(&str, &str)]) -> io::Result<i32> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// The `(vault, permission)` of every check for one principal, in report order.
fn grants(doc: &Value, kind: &str, target: Option<&str>) -> Vec<(String, String)> {
    doc["environments"][0]["report"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["grant"]["principal"]["kind"] == kind)
        .filter(|c| target.is_none_or(|t| c["grant"]["principal"]["target"] == t))
        .map(|c| {
            (
                c["grant"]["vault_id"].as_str().unwrap().to_string(),
                c["grant"]["permission"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

/// The state of the one check on `vault`.
fn state_of(doc: &Value, vault: &str) -> String {
    doc["environments"][0]["report"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["grant"]["vault_id"] == vault)
        .unwrap()["state"]
        .as_str()
        .unwrap()
        .to_string()
}

fn commands(doc: &Value) -> Vec<String> {
    doc["environments"][0]["commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect()
}

// --- required access per principal -------------------------------------------------

#[test]
fn a_target_deploy_identity_reads_its_boundaries_and_writes_its_state_vault() {
    let doc = run_json(&visible(), Some("prod"), None);
    assert_eq!(
        grants(&doc, "deploy", Some("web")),
        [
            ("vshared".to_string(), "read".to_string()),
            ("vweb".to_string(), "read".to_string()),
            ("vwebstate".to_string(), "read_write".to_string()),
        ]
    );
}

#[test]
fn a_second_target_gets_its_own_deploy_grants() {
    let doc = run_json(&visible(), Some("prod"), None);
    assert_eq!(
        grants(&doc, "deploy", Some("worker")),
        [
            ("vworker".to_string(), "read".to_string()),
            ("vworkerstate".to_string(), "read_write".to_string()),
        ]
    );
}

#[test]
fn the_ci_reader_reads_every_boundary_vault() {
    let doc = run_json(&visible(), Some("prod"), None);
    assert_eq!(
        grants(&doc, "ci_reader", None),
        [
            ("vshared".to_string(), "read".to_string()),
            ("vweb".to_string(), "read".to_string()),
            ("vworker".to_string(), "read".to_string()),
        ]
    );
}

#[test]
fn a_present_grant_is_reported_present() {
    let doc = run_json(&visible(), Some("prod"), None);
    assert!(
        doc["environments"][0]["report"]["checks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["state"] == "present")
    );
}

// --- owner commands -----------------------------------------------------------------

#[test]
fn each_principal_with_a_missing_grant_gets_exactly_one_owner_command() {
    assert_eq!(
        commands(&run_json(&members_only(), Some("prod"), None)).len(),
        3
    );
}

#[test]
fn one_owner_command_covers_every_vault_of_its_principal() {
    let command = commands(&run_json(&members_only(), Some("prod"), None))
        .into_iter()
        .find(|c| c.contains("shop-prod-web-deploy"))
        .unwrap();
    assert_eq!(
        command,
        "op service-account create \"shop-prod-web-deploy\" --vault vshared:read_items \
         --vault vweb:read_items --vault vwebstate:read_items,write_items --expires-in 90d"
    );
}

/// A reader that can write where it should only read is fixed by recreating its service
/// account (its vaults and permissions are fixed at creation), so it gets an owner command.
#[test]
fn a_reader_that_can_write_a_boundary_gets_an_owner_command() {
    let op = visible();
    op.vault_users.borrow_mut().insert(
        VWEB.into(),
        json!([
            member(),
            account("shop-prod-web-deploy", &["allow_viewing", "allow_editing"]),
            account("shop-prod-ci", &["allow_viewing"]),
        ]),
    );
    let commands = commands(&run_json(&op, Some("prod"), None));
    assert_eq!(
        commands
            .iter()
            .filter(|c| c.contains("shop-prod-web-deploy"))
            .count(),
        1,
        "{commands:?}"
    );
}

#[test]
fn the_text_prefixes_each_owner_command() {
    assert!(
        run_text(&members_only(), Some("prod"), None)
            .contains("Owner runs: op service-account create")
    );
}

// --- narrowing ----------------------------------------------------------------------

#[test]
fn target_narrowing_keeps_only_that_deploy_principal() {
    let doc = run_json(&visible(), Some("prod"), Some("web"));
    let principals: Vec<&str> = doc["environments"][0]["report"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["grant"]["principal"]["kind"].as_str().unwrap())
        .collect();
    assert_eq!(principals, ["deploy", "deploy", "deploy"]);
}

#[test]
fn target_narrowing_omits_the_ci_reader() {
    let doc = run_json(&visible(), Some("prod"), Some("web"));
    assert!(grants(&doc, "ci_reader", None).is_empty());
}

// --- unreadable vaults --------------------------------------------------------------

/// Every needed vault is in the account (`op vault get` finds it), but no access list can
/// be read: the person cannot manage these vaults.
fn unreadable() -> FakeOp {
    let op = FakeOp::default();
    for v in [VSHARED, VWEB, VWORKER, VWEB_STATE, VWORKER_STATE] {
        op.vaults.borrow_mut().push((v.into(), v.into()));
    }
    op
}

#[test]
fn an_unreadable_vault_is_reported_not_visible() {
    let doc = run_json(&unreadable(), Some("prod"), None);
    assert_eq!(state_of(&doc, VWEB_STATE), "not_visible");
}

#[test]
fn an_unreadable_vault_is_counted_unclassified() {
    let doc = run_json(&unreadable(), Some("prod"), None);
    assert_eq!(doc["environments"][0]["report"]["unclassified"], 8);
}

#[test]
fn the_text_reports_an_unreadable_vault_as_not_visible() {
    assert!(run_text(&unreadable(), Some("prod"), None).contains("not visible"));
}

#[test]
fn the_output_never_says_clean() {
    assert!(
        !run_text(&unreadable(), Some("prod"), None)
            .to_lowercase()
            .contains("clean")
    );
}

#[test]
fn an_unreadable_vault_keeps_its_finding() {
    assert!(run_text(&unreadable(), Some("prod"), None).contains("access_not_visible"));
}

#[test]
fn a_finding_names_the_vault_it_is_about() {
    assert!(
        run_text(&unreadable(), Some("prod"), None).contains("vault vwebstate (environment prod)")
    );
}

// --- readers and privacy ------------------------------------------------------------

#[test]
fn a_writable_boundary_reader_is_flagged() {
    let op = visible();
    op.vault_users.borrow_mut().insert(
        VWEB.into(),
        json!([account("stranger", &["allow_viewing", "allow_editing"])]),
    );
    assert!(run_text(&op, Some("prod"), None).contains("ci_reader_can_write"));
}

#[test]
fn no_person_is_ever_named() {
    let text = run_text(&visible(), Some("prod"), None);
    assert!(!text.contains("Alice") && !text.contains("alice@example.com"));
}

// --- observation and read-only ------------------------------------------------------

#[test]
fn each_needed_vault_is_listed_once() {
    let op = visible();
    let _ = run_json(&op, Some("prod"), None);
    let calls = op
        .calls
        .borrow()
        .iter()
        .filter(|c| {
            c.args.starts_with(&[
                "vault".to_string(),
                "user".to_string(),
                "list".to_string(),
                VSHARED.to_string(),
            ])
        })
        .count();
    assert_eq!(calls, 1);
}

#[test]
fn access_never_runs_a_create_command() {
    let op = FakeOp::default();
    let _ = run_json(&op, Some("prod"), None);
    assert!(!op.calls.borrow().iter().any(|c| {
        c.args
            .starts_with(&["service-account".to_string(), "create".to_string()])
    }));
}

// --- project and json document ------------------------------------------------------

#[test]
fn the_project_option_names_the_service_accounts() {
    let mut out = Vec::new();
    run(
        &fleet(),
        Some("prod"),
        None,
        Some("acme"),
        &members_only(),
        true,
        &mut out,
    )
    .unwrap();
    let doc: Value = serde_json::from_slice(&out).unwrap();
    assert!(
        commands(&doc)
            .iter()
            .any(|c| c.contains("acme-prod-web-deploy"))
    );
}

#[test]
fn the_json_document_wraps_each_environment() {
    let doc = run_json(&visible(), Some("prod"), None);
    assert_eq!(doc["environments"][0]["environment"], "prod");
}

#[test]
fn the_json_document_carries_the_report() {
    let doc = run_json(&visible(), Some("prod"), None);
    assert!(doc["environments"][0]["report"].is_object());
}

#[test]
fn the_json_document_carries_the_commands() {
    let doc = run_json(&visible(), Some("prod"), None);
    assert!(doc["environments"][0]["commands"].is_array());
}

// --- #153: a vault not in the selected account is not "not visible" ---

/// Every grant missing, and the `web` boundary vault unreadable: in the account (`op vault
/// get` finds it) when `in_account`, else not.
fn web_vault_unreadable(in_account: bool) -> Probed {
    let op = members_only();
    op.vault_users.borrow_mut().remove(VWEB);
    if in_account {
        op.vaults
            .borrow_mut()
            .push((VWEB.into(), "shop-web-prod".into()));
    }
    Probed::new(op)
}

fn web_check_state(op: &dyn CommandRunner) -> Value {
    let doc = run_json(op, Some("prod"), Some("web"));
    doc["environments"][0]["report"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["grant"]["vault_id"] == VWEB)
        .unwrap()["state"]
        .clone()
}

#[test]
fn a_vault_missing_from_the_account_is_not_in_account() {
    assert_eq!(
        web_check_state(&web_vault_unreadable(false)),
        "not_in_account"
    );
}

#[test]
fn a_vault_in_the_account_with_an_unreadable_list_stays_not_visible() {
    assert_eq!(web_check_state(&web_vault_unreadable(true)), "not_visible");
}

#[test]
fn no_owner_command_is_printed_for_an_identity_needing_a_missing_vault() {
    let doc = run_json(&web_vault_unreadable(false), Some("prod"), Some("web"));
    assert!(
        doc["environments"][0]["commands"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_missing_vault_points_at_vault_locate() {
    let text = run_text(&web_vault_unreadable(false), Some("prod"), Some("web"));
    assert!(
        text.contains("vault_not_in_account") && text.contains("opv vault locate vweb"),
        "{text}"
    );
}

#[test]
fn an_identity_whose_vaults_all_exist_still_gets_its_owner_command() {
    let doc = run_json(&web_vault_unreadable(true), Some("prod"), Some("web"));
    assert!(
        !doc["environments"][0]["commands"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

/// #157: nobody signed in.
fn signed_out() -> FakeOp {
    let op = visible();
    op.signed_in.set(false);
    op
}

#[test]
fn access_without_a_session_is_op_not_signed_in() {
    let mut out = Vec::new();
    let e = run(
        &fleet(),
        None,
        None,
        Some("shop"),
        &signed_out(),
        true,
        &mut out,
    )
    .unwrap_err();
    assert_eq!(e.code_str(), "op_not_signed_in");
}

#[test]
fn access_without_a_session_classifies_no_vault() {
    let mut out = Vec::new();
    let _ = run(
        &fleet(),
        None,
        None,
        Some("shop"),
        &signed_out(),
        true,
        &mut out,
    );
    assert!(out.is_empty(), "{}", String::from_utf8_lossy(&out));
}

#[test]
fn one_vault_outside_the_account_leaves_the_others_classified() {
    assert_eq!(
        state_of(
            &run_json(&web_vault_unreadable(false), Some("prod"), Some("web")),
            VSHARED
        ),
        "missing"
    );
}

#[test]
fn a_missing_vault_finding_never_says_setup_vault() {
    let text = run_text(&web_vault_unreadable(false), Some("prod"), Some("web"));
    assert!(!text.contains("setup vault"), "{text}");
}

/// The configuration with `prod` in account `ACCTPROD` (#157).
fn fleet_in_account() -> crate::domain::Fleet {
    let mut fleet = fleet();
    fleet
        .environments
        .get_mut("prod")
        .expect("prod is declared")
        .account = Some("ACCTPROD".into());
    fleet
}

fn findings_in_account(op: &dyn CommandRunner) -> Value {
    let mut out = Vec::new();
    run(
        &fleet_in_account(),
        Some("prod"),
        Some("web"),
        Some("shop"),
        op,
        true,
        &mut out,
    )
    .unwrap();
    let doc: Value = serde_json::from_slice(&out).unwrap();
    doc["environments"][0]["findings"].clone()
}

#[test]
fn a_missing_vault_finding_names_the_account_it_checked() {
    let found = findings_in_account(&web_vault_unreadable(false));
    assert!(
        found[0]["message"]
            .as_str()
            .unwrap()
            .contains("not in 1Password account ACCTPROD"),
        "{found}"
    );
}

/// #153a: op lists the machine's accounts and none holds the vault, so `vault locate` would
/// only repeat the search: the step is the selected account's vault list.
#[test]
fn a_vault_no_account_on_the_machine_holds_steps_to_the_selected_accounts_vaults() {
    let found = findings_in_account(&web_vault_unreadable(false));
    assert_eq!(found[0]["next"], "op vault list --account ACCTPROD");
}

#[test]
fn a_vault_in_another_account_keeps_the_documented_finding_code() {
    let found = findings_in_account(&web_vault_unreadable(false));
    assert_eq!(found[0]["code"], "vault_not_in_account");
}

#[test]
fn a_vault_get_failure_the_runner_did_not_observe_is_never_guessed_elsewhere() {
    let op = members_only();
    op.vault_users.borrow_mut().remove(VWEB);
    assert_eq!(web_check_state(&op), "not_visible");
}

// --- 07.10, 07.34: findings name the environment and label their step ---

/// Two service accounts named like the web deploy identity read the shared vault, as after
/// `opv access --create` made a replacement.
fn replaced_reader() -> FakeOp {
    let op = visible();
    op.vault_users.borrow_mut().insert(
        VSHARED.into(),
        json!([
            account("shop-prod-web-deploy", &["allow_viewing"]),
            account("shop-prod-web-deploy", &["allow_viewing"]),
            account("shop-prod-ci", &["allow_viewing"]),
        ]),
    );
    op
}

#[test]
fn pending_revoke_steps_to_the_environment_not_the_vault() {
    let text = run_text(&replaced_reader(), Some("prod"), None);
    assert!(
        text.contains("    next: opv delivery verify prod\n"),
        "{text}"
    );
}

#[test]
fn pending_revoke_names_the_vault_and_its_environment() {
    let text = run_text(&replaced_reader(), Some("prod"), None);
    assert!(text.contains("vault vshared (environment prod)"), "{text}");
}

#[test]
fn an_undeclared_target_is_unknown_target() {
    let mut out = Vec::new();
    let e = run(
        &fleet(),
        Some("prod"),
        Some("nope"),
        Some("shop"),
        &visible(),
        true,
        &mut out,
    )
    .unwrap_err();
    assert_eq!(e.cause().map(|(c, _)| c.code()), Some("unknown_target"));
}
