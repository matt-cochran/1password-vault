//! `opv provision` (design `owner-value-ingestion.md` §10.3 tests 18-28, §10.4 tests
//! 31-38, and the steps of §4.2): one behavioural assertion per test, through the public
//! `provision` seam with the stateful fake `op` and scripted producers.

use std::cell::{Cell, RefCell};
use std::io;
use std::time::Duration;

use super::*;
use crate::adapters::fake_op::FakeOp;
use crate::cause::{Cause, Guard, NoTerminal, Principal, ProvisionRefusal, UnsupportedFeature};
use crate::host::FakeEnv;
use crate::runner::fake::{ScriptedEnd, ScriptedProducer};
use crate::runner::{Call, Output};

const VAULT: &str = "vdev0000000000000000000001";
/// A marker standing in for a held token; it must never reach the plan.
const HELD: &str = "held-REFRESHMARKER-0123456789";

/// The item of `app` in one environment: a client id and the refresh token `token`.
fn item(op: &FakeOp, env: &str, token: &str) -> String {
    op.insert(
        VAULT,
        serde_json::json!({
            "title": format!("app · {env} values"), "category": "SECURE_NOTE",
            "sections": [{"id": "app", "label": "app"}],
            "fields": [
                {"id": "f1", "section": {"id": "app", "label": "app"}, "type": "CONCEALED",
                 "label": "CLIENT_ID", "value": "client-id-value"},
                {"id": "f2", "section": {"id": "app", "label": "app"}, "type": "CONCEALED",
                 "label": "REFRESH_TOKEN", "value": token},
                {"id": "f3", "section": {"id": "app", "label": "app"}, "type": "CONCEALED",
                 "label": "SESSION_KEY", "value": ""}
            ]
        }),
    )
}

/// `prod` (production tier) and `staging`; the set `grant` holds the refresh token made by
/// the producer `consent` (10 min) in both. Its prod value is `prod_token`.
fn world_with(prod_token: &str) -> (FakeOp, Fleet) {
    let op = FakeOp::default();
    let prod = item(&op, "prod", prod_token);
    let staging = item(&op, "staging", "");
    let fleet = crate::config::parse(&format!(
        r#"[environments.prod]
tier = "production"
boundaries.app = {{ vault_id = "{VAULT}", item_id = "{prod}" }}

[environments.staging]
tier = "shared"
boundaries.app = {{ vault_id = "{VAULT}", item_id = "{staging}" }}

[products.app.keys.CLIENT_ID]
kind = "secret"

[products.app.keys.REFRESH_TOKEN]
kind = "secret"

[products.app.keys.SESSION_KEY]
kind = "secret"
rules = {{ hex_bytes = 32 }}

[products.app.keys.SIGNING_KEY]
kind = "secret"
rules = {{ hex_bytes = 32 }}

[products.app.keys.ID_TOKEN]
kind = "secret"
rules = {{ prefix = "id_" }}

[products.app.keys.ACCESS_TOKEN]
kind = "secret"
rules = {{ prefix = "at_" }}

[producers.consent]
command = ["python3", "-c", "pass"]
outputs = ["refresh_token"]
inputs = {{ client_id = "app/CLIENT_ID" }}
open_url_hosts = ["accounts.example.com"]
timeout = "10m"

[producers.pair]
command = ["python3", "-c", "pass"]
outputs = ["id", "access"]
timeout = "1m"

[sets.signing]
environments = ["prod", "staging"]
members = {{ "app/SIGNING_KEY" = {{ generate = "rules" }} }}

[sets.tokens]
environments = ["prod"]
members = {{ "app/ID_TOKEN" = {{ producer = "pair", output = "id" }}, "app/ACCESS_TOKEN" = {{ producer = "pair", output = "access" }} }}

[sets.grant]
environments = ["prod", "staging"]
members = {{ "app/REFRESH_TOKEN" = {{ producer = "consent", output = "refresh_token" }} }}

[sets.keys]
environments = ["prod"]
members = {{ "app/SESSION_KEY" = {{ generate = {{ hex_bytes = 32 }} }}, "app/CLIENT_ID" = {{ generate = {{ hex_bytes = 16 }} }} }}
"#
    ))
    .unwrap();
    (op, fleet)
}

/// The set `grant` absent in both environments.
fn world() -> (FakeOp, Fleet) {
    world_with("")
}

/// The item ID of `app` in `env`.
fn item_id(fleet: &Fleet, env: &str) -> String {
    fleet.environments[env].boundaries["app"]
        .as_ref()
        .unwrap()
        .item_id
        .clone()
}

/// The value of field `label` in item `id` outside the kept section, if any.
fn field(op: &FakeOp, id: &str, label: &str) -> Option<String> {
    held_in(op, id, |f| {
        f["label"] == label && f["section"]["label"] != crate::domain::convention::KEPT_SECTION
    })
}

/// The value of the first field of item `id` that `pick` chooses.
fn held_in(op: &FakeOp, id: &str, pick: impl Fn(&serde_json::Value) -> bool) -> Option<String> {
    op.item(id)["fields"]
        .as_array()?
        .iter()
        .find(|f| pick(f))
        .and_then(|f| f["value"].as_str().map(str::to_string))
}

/// Set field `label` of item `id` to `value`.
fn put(op: &FakeOp, id: &str, label: &str, value: &str) {
    for i in op.items.borrow_mut().iter_mut() {
        if i["id"] == id {
            for f in i["fields"].as_array_mut().into_iter().flatten() {
                if f["label"] == label {
                    f["value"] = serde_json::json!(value);
                }
            }
        }
    }
}

/// A made refresh token the scripted producer returns.
const MADE: &str = "made-REFRESHTOKEN-9876543210";

/// A producer's result line for `env` with `outputs`; `{nonce}` is this run's nonce.
fn result_line(env: &str, outputs: &[(&str, &str)]) -> String {
    let outputs: serde_json::Map<String, serde_json::Value> = outputs
        .iter()
        .map(|(k, v)| (k.to_string(), serde_json::json!(v)))
        .collect();
    serde_json::json!({
        "schema": "opv.produce/1", "kind": "result", "env": env, "nonce": "{nonce}",
        "outputs": outputs
    })
    .to_string()
}

/// Queue a producer that prints `lines` and exits 0.
fn producing(op: &FakeOp, lines: Vec<String>) {
    op.producers
        .borrow_mut()
        .push_back(ScriptedProducer::new(lines, ScriptedEnd::Exit(0)));
}

/// Queue the `consent` producer returning `token` for `env`.
fn consent(op: &FakeOp, env: &str, token: &str) {
    producing(op, vec![result_line(env, &[("refresh_token", token)])]);
}

/// A console that answers the typed-back question with `answer`, counts the questions, and
/// records what it showed and the URLs it was asked to open.
struct Scripted {
    answer: Option<&'static str>,
    asked: Cell<usize>,
    shown: Vec<String>,
    opened: RefCell<Vec<String>>,
}

impl Scripted {
    fn answering(answer: Option<&'static str>) -> Self {
        Self {
            answer,
            asked: Cell::new(0),
            shown: Vec::new(),
            opened: RefCell::default(),
        }
    }
}

impl ProvisionConsole for Scripted {
    fn show(&mut self, text: &str) -> Result<(), Error> {
        self.shown.push(text.to_string());
        Ok(())
    }
    fn type_back(&mut self, _question: &str) -> Result<Option<String>, Error> {
        self.asked.set(self.asked.get() + 1);
        Ok(self.answer.map(str::to_string))
    }
    fn open_url(&mut self, url: &str) -> bool {
        self.opened.borrow_mut().push(url.to_string());
        true
    }
}

/// A person at a Linux terminal.
fn person() -> FakeEnv {
    FakeEnv::new("linux").shell("/bin/bash").tty()
}

fn request<'a>(set: &'a str, env: &'a str) -> Request<'a> {
    Request {
        set,
        env,
        dry_run: false,
        replace: false,
        project: Path::new("."),
    }
}

fn run(
    op: &FakeOp,
    fleet: &Fleet,
    host: &FakeEnv,
    req: Request<'_>,
    console: &mut Scripted,
) -> Result<Outcome, Error> {
    provision(fleet, host, &req, &Wrapped::new(op), console)
}

fn run_on(
    r: &Wrapped<'_>,
    fleet: &Fleet,
    req: Request<'_>,
    console: &mut Scripted,
) -> Result<Outcome, Error> {
    provision(fleet, &person(), &req, r, console)
}

/// The refusal's cause; panics on success.
fn cause_of(r: Result<Outcome, Error>) -> Cause {
    r.unwrap_err().cause().unwrap().0.clone()
}

fn refusal_of(r: Result<Outcome, Error>) -> Option<ProvisionRefusal> {
    match cause_of(r) {
        Cause::Guard {
            guard: Guard::ProvisionRefused { reason, .. },
        } => Some(reason),
        _ => None,
    }
}

/// The fake `op`, with an optional run budget of `left`, an `item edit` that can fail, and
/// scripted producers whose `{nonce}` becomes the run's own.
struct Wrapped<'a> {
    op: &'a FakeOp,
    left: Option<Duration>,
    fail_edit: bool,
}

impl<'a> Wrapped<'a> {
    fn new(op: &'a FakeOp) -> Self {
        Self {
            op,
            left: None,
            fail_edit: false,
        }
    }
}

/// The fake `op` with a run budget of `left`.
fn budgeted(op: &FakeOp, left: Duration) -> Wrapped<'_> {
    Wrapped {
        left: Some(left),
        ..Wrapped::new(op)
    }
}

impl CommandRunner for Wrapped<'_> {
    fn read(&self, call: &Call, refused: &[i32]) -> io::Result<crate::runner::Outcome> {
        self.op.read(call, refused)
    }
    fn write(&self, call: &Call) -> io::Result<crate::runner::Outcome> {
        if self.fail_edit && call.args.starts_with(&["item", "edit"]) {
            return Ok(crate::runner::Outcome::Unknown {
                reason: "failed-write",
                status: Some(1),
            });
        }
        self.op.write(call)
    }
    fn probe(&self, call: &Call, limit: Duration) -> io::Result<Output> {
        self.op.probe(call, limit)
    }
    fn pause(&self, d: Duration, note: &str) {
        self.op.pause(d, note)
    }
    fn note(&self, line: &str) {
        self.op.note(line)
    }
    fn run_inherited(&self, p: &str, a: &[&str], e: &[(&str, &str)]) -> io::Result<i32> {
        self.op.run_inherited(p, a, e)
    }
    fn remaining(&self) -> Option<Duration> {
        self.left
    }
    fn produce(
        &self,
        call: &crate::runner::ProduceCall,
        on_line: &mut dyn FnMut(crate::runner::ProducedLine<'_>) -> crate::runner::LineVerdict,
    ) -> Result<crate::runner::Produced, Error> {
        let request: serde_json::Value = serde_json::from_slice(call.request).unwrap();
        let nonce = request["nonce"].as_str().unwrap().to_string();
        if let Some(script) = self.op.producers.borrow_mut().front_mut() {
            for line in &mut script.lines {
                *line = line.replace("{nonce}", &nonce);
            }
        }
        self.op.produce(call, on_line)
    }
}

// ---- §10.3 test 28: budget ------------------------------------------------------

#[test]
fn a_budget_smaller_than_the_producer_timeout_and_reserve_is_refused() {
    let (op, fleet) = world();
    let short = budgeted(&op, Duration::from_secs(5 * 60));
    let r = run_on(
        &short,
        &fleet,
        request("grant", "prod"),
        &mut Scripted::answering(Some("prod")),
    );
    assert_eq!(
        refusal_of(r),
        Some(ProvisionRefusal::BudgetTooSmall {
            needed_seconds: 10 * 60 + 240,
            left_seconds: 5 * 60,
        })
    );
}

#[test]
fn a_budget_refusal_comes_before_the_confirmation() {
    let (op, fleet) = world();
    let short = budgeted(&op, Duration::from_secs(5 * 60));
    let mut console = Scripted::answering(Some("prod"));
    let _ = run_on(&short, &fleet, request("grant", "prod"), &mut console);
    assert_eq!(console.asked.get(), 0);
}

#[test]
fn a_budget_with_room_for_the_producer_and_reserve_is_written() {
    let (op, fleet) = world();
    consent(&op, "prod", MADE);
    let room = budgeted(&op, Duration::from_secs(30 * 60));
    let r = run_on(
        &room,
        &fleet,
        request("grant", "prod"),
        &mut Scripted::answering(Some("prod")),
    );
    assert!(matches!(r, Ok(Outcome::Written(_))));
}

// ---- §10.4 tests 31-38: refusals --------------------------------------------------

#[test]
fn an_agent_marker_is_refused_as_person_only() {
    let (op, fleet) = world();
    let r = run(
        &op,
        &fleet,
        &person().var("CLAUDECODE"),
        request("grant", "prod"),
        &mut Scripted::answering(Some("prod")),
    );
    assert_eq!(r.unwrap_err().code_str(), "person_only");
}

#[test]
fn an_agent_marker_refusal_makes_no_op_call() {
    let (op, fleet) = world();
    let _ = run(
        &op,
        &fleet,
        &person().var("CLAUDECODE"),
        request("grant", "prod"),
        &mut Scripted::answering(Some("prod")),
    );
    assert!(op.calls.borrow().is_empty());
}

#[test]
fn ci_is_refused_as_needing_a_terminal() {
    let (op, fleet) = world();
    let r = run(
        &op,
        &fleet,
        &person().var_val("CI", "true"),
        request("grant", "prod"),
        &mut Scripted::answering(Some("prod")),
    );
    assert_eq!(
        cause_of(r),
        Cause::NeedsTerminal {
            why: NoTerminal::Ci
        }
    );
}

#[test]
fn a_ci_refusal_makes_no_op_call() {
    let (op, fleet) = world();
    let _ = run(
        &op,
        &fleet,
        &person().var_val("CI", "true"),
        request("grant", "prod"),
        &mut Scripted::answering(Some("prod")),
    );
    assert!(op.calls.borrow().is_empty());
}

#[test]
fn a_process_without_a_terminal_is_refused_as_needing_one() {
    let (op, fleet) = world();
    let r = run(
        &op,
        &fleet,
        &FakeEnv::new("linux").shell("/bin/bash"),
        request("grant", "prod"),
        &mut Scripted::answering(Some("prod")),
    );
    assert_eq!(
        cause_of(r),
        Cause::NeedsTerminal {
            why: NoTerminal::NoTty
        }
    );
}

#[test]
fn a_process_without_a_terminal_is_never_asked_to_confirm() {
    let (op, fleet) = world();
    let mut console = Scripted::answering(Some("prod"));
    let _ = run(
        &op,
        &fleet,
        &FakeEnv::new("linux").shell("/bin/bash"),
        request("grant", "prod"),
        &mut console,
    );
    assert_eq!(console.asked.get(), 0);
}

#[test]
fn a_service_account_identity_needs_the_persons_own_session() {
    let (op, fleet) = world();
    let r = run(
        &op,
        &fleet,
        &person().var("OP_SERVICE_ACCOUNT_TOKEN"),
        request("grant", "staging"),
        &mut Scripted::answering(Some("staging")),
    );
    assert_eq!(r.unwrap_err().code_str(), "own_session_required");
}

#[test]
fn a_session_variable_in_production_needs_the_persons_own_session() {
    let (op, fleet) = world();
    let r = run(
        &op,
        &fleet,
        &person().var("OP_SESSION_abcdef"),
        request("grant", "prod"),
        &mut Scripted::answering(Some("prod")),
    );
    assert!(matches!(
        cause_of(r),
        Cause::NeedsOwnSession {
            identity: Principal::ShellToken { var },
            ..
        } if var.as_str() == "OP_SESSION_abcdef"
    ));
}

#[test]
fn a_session_variable_outside_production_is_not_refused() {
    let (op, fleet) = world();
    consent(&op, "staging", MADE);
    let r = run(
        &op,
        &fleet,
        &person().var("OP_SESSION_abcdef"),
        request("grant", "staging"),
        &mut Scripted::answering(Some("staging")),
    );
    assert!(matches!(r, Ok(Outcome::Written(_))));
}

#[test]
fn a_wrong_typed_environment_is_a_confirm_mismatch() {
    let (op, fleet) = world();
    let r = run(
        &op,
        &fleet,
        &person(),
        request("grant", "prod"),
        &mut Scripted::answering(Some("staging")),
    );
    assert_eq!(r.unwrap_err().code_str(), "confirm_mismatch");
}

#[test]
fn a_wrong_typed_environment_writes_nothing() {
    let (op, fleet) = world();
    let _ = run(
        &op,
        &fleet,
        &person(),
        request("grant", "prod"),
        &mut Scripted::answering(Some("staging")),
    );
    assert_eq!(op.count(&["op", "item", "edit"]), 0);
}

#[test]
fn a_dry_run_under_an_agent_marker_returns_the_plan() {
    let (op, fleet) = world();
    let r = run(
        &op,
        &fleet,
        &FakeEnv::new("linux").var("CLAUDECODE"),
        Request {
            dry_run: true,
            ..request("grant", "prod")
        },
        &mut Scripted::answering(None),
    );
    assert!(matches!(r, Ok(Outcome::DryRun(_))));
}

#[test]
fn a_dry_run_under_an_agent_marker_writes_nothing() {
    let (op, fleet) = world();
    let _ = run(
        &op,
        &fleet,
        &FakeEnv::new("linux").var("CLAUDECODE"),
        Request {
            dry_run: true,
            ..request("grant", "prod")
        },
        &mut Scripted::answering(None),
    );
    assert_eq!(op.count(&["op", "item", "edit"]), 0);
}

#[test]
fn a_producer_member_on_native_windows_is_unsupported() {
    let (op, fleet) = world();
    let r = run(
        &op,
        &fleet,
        &FakeEnv::new("windows").tty(),
        request("grant", "prod"),
        &mut Scripted::answering(Some("prod")),
    );
    assert_eq!(
        cause_of(r),
        Cause::Unsupported {
            feature: UnsupportedFeature::ProducerOnWindows {
                set: "grant".into(),
                producer: "consent".into(),
            }
        }
    );
}

#[test]
fn a_generated_set_on_native_windows_is_not_refused_for_the_platform() {
    let (op, fleet) = world();
    let r = run(
        &op,
        &fleet,
        &FakeEnv::new("windows").tty(),
        request("keys", "prod"),
        &mut Scripted::answering(Some("prod")),
    );
    assert!(!matches!(
        r.as_ref().err().and_then(|e| e.cause()).map(|c| c.0),
        Some(Cause::Unsupported { .. })
    ));
}

// ---- §4.2 steps 2, 6 and 7: resolve, classify, plan, confirm ----------------------

#[test]
fn an_undeclared_set_is_a_usage_error() {
    let (op, fleet) = world();
    let r = run(
        &op,
        &fleet,
        &person(),
        request("nope", "prod"),
        &mut Scripted::answering(Some("prod")),
    );
    assert_eq!(r.unwrap_err().code_str(), "usage");
}

#[test]
fn an_environment_outside_the_set_is_a_usage_error() {
    let (op, fleet) = world();
    let r = run(
        &op,
        &fleet,
        &person(),
        request("keys", "staging"),
        &mut Scripted::answering(Some("staging")),
    );
    assert_eq!(r.unwrap_err().code_str(), "usage");
}

#[test]
fn a_complete_set_is_unchanged() {
    let (op, fleet) = world_with(HELD);
    let r = run(
        &op,
        &fleet,
        &person(),
        request("grant", "prod"),
        &mut Scripted::answering(Some("prod")),
    );
    assert!(matches!(r, Ok(Outcome::Unchanged(_))));
}

#[test]
fn a_complete_set_is_never_asked_to_confirm() {
    let (op, fleet) = world_with(HELD);
    let mut console = Scripted::answering(Some("prod"));
    let _ = run(
        &op,
        &fleet,
        &person(),
        request("grant", "prod"),
        &mut console,
    );
    assert_eq!(console.asked.get(), 0);
}

#[test]
fn a_partial_set_is_refused_naming_the_missing_member() {
    // `keys` holds CLIENT_ID and not SESSION_KEY.
    let (op, fleet) = world();
    let r = run(
        &op,
        &fleet,
        &person(),
        request("keys", "prod"),
        &mut Scripted::answering(Some("prod")),
    );
    assert_eq!(
        refusal_of(r),
        Some(ProvisionRefusal::Partial {
            missing: vec!["app/SESSION_KEY".into()]
        })
    );
}

#[test]
fn a_partial_set_with_replace_is_still_refused() {
    let (op, fleet) = world();
    let r = run(
        &op,
        &fleet,
        &person(),
        Request {
            replace: true,
            ..request("keys", "prod")
        },
        &mut Scripted::answering(Some("prod")),
    );
    assert!(matches!(
        refusal_of(r),
        Some(ProvisionRefusal::Partial { .. })
    ));
}

#[test]
fn an_inconsistent_set_is_refused_naming_the_failing_member() {
    // SESSION_KEY holds a value that is not 32 hex bytes: every member is held, one fails.
    let (op, fleet) = world();
    let id = fleet.environments["prod"].boundaries["app"]
        .as_ref()
        .unwrap()
        .item_id
        .clone();
    for i in op.items.borrow_mut().iter_mut() {
        if i["id"] == id.as_str() {
            i["fields"][2]["value"] = serde_json::json!("not-hex-at-all");
        }
    }
    let r = run(
        &op,
        &fleet,
        &person(),
        request("keys", "prod"),
        &mut Scripted::answering(Some("prod")),
    );
    assert_eq!(
        refusal_of(r),
        Some(ProvisionRefusal::Inconsistent {
            members: vec!["app/SESSION_KEY".into()]
        })
    );
}

#[test]
fn an_absent_set_typed_back_is_written() {
    let (op, fleet) = world();
    consent(&op, "prod", MADE);
    let r = run(
        &op,
        &fleet,
        &person(),
        request("grant", "prod"),
        &mut Scripted::answering(Some("prod")),
    );
    assert!(matches!(r, Ok(Outcome::Written(_))));
}

#[test]
fn no_typed_answer_declines() {
    let (op, fleet) = world();
    let r = run(
        &op,
        &fleet,
        &person(),
        request("grant", "prod"),
        &mut Scripted::answering(None),
    );
    assert!(matches!(r, Ok(Outcome::Declined(_))));
}

#[test]
fn the_written_plan_carries_the_version_read() {
    let (op, fleet) = world();
    consent(&op, "prod", MADE);
    let r = run(
        &op,
        &fleet,
        &person(),
        request("grant", "prod"),
        &mut Scripted::answering(Some("prod")),
    );
    assert_eq!(r.unwrap().plan().item.version, Some(1));
}

#[test]
fn the_plan_is_shown_before_the_confirmation() {
    let (op, fleet) = world();
    consent(&op, "prod", MADE);
    let mut console = Scripted::answering(Some("prod"));
    let _ = run(
        &op,
        &fleet,
        &person(),
        request("grant", "prod"),
        &mut console,
    );
    assert!(
        console.shown[0].contains("producer consent: python3 -c pass"),
        "{:?}",
        console.shown
    );
}

#[test]
fn the_plan_shows_the_budget_with_the_commit_reserve() {
    let (op, fleet) = world();
    consent(&op, "prod", MADE);
    let room = budgeted(&op, Duration::from_secs(30 * 60));
    let mut console = Scripted::answering(Some("prod"));
    let _ = run_on(&room, &fleet, request("grant", "prod"), &mut console);
    assert!(
        console.shown[0].contains("budget  10m producer + 4m commit of 30m left"),
        "{:?}",
        console.shown
    );
}

#[test]
fn the_plan_compares_producer_members_with_the_other_environment() {
    let (op, fleet) = world();
    let r = run(
        &op,
        &fleet,
        &person(),
        Request {
            dry_run: true,
            ..request("grant", "prod")
        },
        &mut Scripted::answering(None),
    );
    assert_eq!(r.unwrap().plan().compare, vec!["staging".to_string()]);
}

#[test]
fn the_plan_holds_no_member_value() {
    let (op, fleet) = world_with(HELD);
    let r = run(
        &op,
        &fleet,
        &person(),
        Request {
            dry_run: true,
            ..request("grant", "prod")
        },
        &mut Scripted::answering(None),
    );
    let plan = r.unwrap().plan().clone();
    let text = format!(
        "{}{}{plan:?}",
        render_plan(&plan),
        serde_json::to_string(&plan).unwrap()
    );
    assert!(!text.contains(HELD) && !text.contains("client-id-value"));
}

#[test]
fn replace_with_an_immutable_member_is_refused_before_the_confirmation() {
    let (op, fleet) = world_with(HELD);
    let mut fleet = fleet;
    fleet
        .products
        .get_mut("app")
        .unwrap()
        .keys
        .get_mut("REFRESH_TOKEN")
        .unwrap()
        .immutable = true;
    let r = run(
        &op,
        &fleet,
        &person(),
        Request {
            replace: true,
            ..request("grant", "prod")
        },
        &mut Scripted::answering(Some("prod")),
    );
    assert_eq!(
        refusal_of(r),
        Some(ProvisionRefusal::ImmutableMember {
            member: "app/REFRESH_TOKEN".into()
        })
    );
}

#[test]
fn a_session_variable_is_found_through_the_host_seam() {
    let found = crate::host::credential_on(&FakeEnv::new("linux").var("OP_SESSION_abcdef"));
    assert_eq!(found.as_deref(), Some("OP_SESSION_abcdef"));
}

// ---- §10.3 tests 18-27: produce, generate, validate, commit -----------------------

#[test]
fn an_absent_producer_set_holds_the_producers_value_after_the_write() {
    let (op, fleet) = world();
    consent(&op, "prod", MADE);
    let _ = run(
        &op,
        &fleet,
        &person(),
        request("grant", "prod"),
        &mut Scripted::answering(Some("prod")),
    );
    assert_eq!(
        field(&op, &item_id(&fleet, "prod"), "REFRESH_TOKEN").as_deref(),
        Some(MADE)
    );
}

#[test]
fn a_complete_set_makes_no_item_edit() {
    let (op, fleet) = world_with(HELD);
    let _ = run(
        &op,
        &fleet,
        &person(),
        request("grant", "prod"),
        &mut Scripted::answering(Some("prod")),
    );
    assert_eq!(op.count(&["op", "item", "edit"]), 0);
}

#[test]
fn a_complete_set_never_starts_the_producer() {
    let (op, fleet) = world_with(HELD);
    consent(&op, "prod", MADE);
    let _ = run(
        &op,
        &fleet,
        &person(),
        request("grant", "prod"),
        &mut Scripted::answering(Some("prod")),
    );
    assert_eq!(op.producers.borrow().len(), 1);
}

#[test]
fn a_partial_set_makes_no_item_edit() {
    let (op, fleet) = world();
    let _ = run(
        &op,
        &fleet,
        &person(),
        request("keys", "prod"),
        &mut Scripted::answering(Some("prod")),
    );
    assert_eq!(op.count(&["op", "item", "edit"]), 0);
}

#[test]
fn a_failed_item_edit_leaves_the_item_at_its_prior_version() {
    let (op, fleet) = world();
    consent(&op, "prod", MADE);
    let failing = Wrapped {
        fail_edit: true,
        ..Wrapped::new(&op)
    };
    let _ = run_on(
        &failing,
        &fleet,
        request("grant", "prod"),
        &mut Scripted::answering(Some("prod")),
    );
    assert_eq!(op.item(&item_id(&fleet, "prod"))["version"], 1);
}

#[test]
fn replace_keeps_the_old_value_in_the_kept_section() {
    let (op, fleet) = world_with(HELD);
    consent(&op, "prod", MADE);
    let _ = run(
        &op,
        &fleet,
        &person(),
        Request {
            replace: true,
            ..request("grant", "prod")
        },
        &mut Scripted::answering(Some("prod")),
    );
    let kept = held_in(&op, &item_id(&fleet, "prod"), |f| {
        f["section"]["label"] == crate::domain::convention::KEPT_SECTION
    });
    assert_eq!(kept.as_deref(), Some(HELD));
}

#[test]
fn replace_with_an_immutable_member_never_starts_the_producer() {
    let (op, mut fleet) = world_with(HELD);
    consent(&op, "prod", MADE);
    fleet
        .products
        .get_mut("app")
        .unwrap()
        .keys
        .get_mut("REFRESH_TOKEN")
        .unwrap()
        .immutable = true;
    let _ = run(
        &op,
        &fleet,
        &person(),
        Request {
            replace: true,
            ..request("grant", "prod")
        },
        &mut Scripted::answering(Some("prod")),
    );
    assert_eq!(op.producers.borrow().len(), 1);
}

#[test]
fn a_producer_value_another_environment_holds_is_refused_as_the_same_across_environments() {
    let (op, fleet) = world();
    put(&op, &item_id(&fleet, "staging"), "REFRESH_TOKEN", MADE);
    consent(&op, "prod", MADE);
    let r = run(
        &op,
        &fleet,
        &person(),
        request("grant", "prod"),
        &mut Scripted::answering(Some("prod")),
    );
    assert_eq!(
        refusal_of(r),
        Some(ProvisionRefusal::SameAcrossEnvironments {
            member: "app/REFRESH_TOKEN".into(),
            other: EnvName::new("staging"),
        })
    );
}

#[test]
fn a_generated_set_reads_no_other_environment() {
    let (op, fleet) = world();
    let staging = item_id(&fleet, "staging");
    let _ = run(
        &op,
        &fleet,
        &person(),
        request("signing", "prod"),
        &mut Scripted::answering(Some("prod")),
    );
    assert!(!op.calls.borrow().iter().any(|c| c.args.contains(&staging)));
}

#[test]
fn made_values_failing_their_rules_name_every_failing_member() {
    let (op, fleet) = world();
    producing(
        &op,
        vec![result_line(
            "prod",
            &[
                ("id", "no-prefix-id-value"),
                ("access", "no-prefix-access-value"),
            ],
        )],
    );
    let r = run(
        &op,
        &fleet,
        &person(),
        request("tokens", "prod"),
        &mut Scripted::answering(Some("prod")),
    );
    let named: Vec<String> = match cause_of(r) {
        Cause::KeysBlocking { rows, .. } => rows
            .iter()
            .map(|row| format!("{}/{}", row.product, row.key))
            .collect(),
        other => panic!("{other:?}"),
    };
    assert_eq!(named, ["app/ACCESS_TOKEN", "app/ID_TOKEN"]);
}

#[test]
fn made_values_failing_their_rules_make_no_item_edit() {
    let (op, fleet) = world();
    producing(
        &op,
        vec![result_line(
            "prod",
            &[
                ("id", "no-prefix-id-value"),
                ("access", "no-prefix-access-value"),
            ],
        )],
    );
    let _ = run(
        &op,
        &fleet,
        &person(),
        request("tokens", "prod"),
        &mut Scripted::answering(Some("prod")),
    );
    assert_eq!(op.count(&["op", "item", "edit"]), 0);
}

// ---- §5.2 through the use case: the producer's lines --------------------------------

#[test]
fn a_producer_error_line_is_reported_by_its_code() {
    let (op, fleet) = world();
    producing(
        &op,
        vec![r#"{"schema":"opv.produce/1","kind":"error","code":"access_denied"}"#.into()],
    );
    let r = run(
        &op,
        &fleet,
        &person(),
        request("grant", "prod"),
        &mut Scripted::answering(Some("prod")),
    );
    assert_eq!(
        cause_of(r),
        Cause::ProducerFailed {
            producer: "consent".into(),
            why: ProducerFailure::Reported {
                code: "access_denied".into()
            },
        }
    );
}

#[test]
fn a_producer_error_line_makes_no_item_edit() {
    let (op, fleet) = world();
    producing(
        &op,
        vec![r#"{"schema":"opv.produce/1","kind":"error","code":"access_denied"}"#.into()],
    );
    let _ = run(
        &op,
        &fleet,
        &person(),
        request("grant", "prod"),
        &mut Scripted::answering(Some("prod")),
    );
    assert_eq!(op.count(&["op", "item", "edit"]), 0);
}

const CONSENT_URL: &str = "https://accounts.example.com/o/oauth2/auth?client_id=public";

fn consent_with_url(op: &FakeOp, url: &str) {
    producing(
        op,
        vec![
            serde_json::json!({"schema": "opv.produce/1", "kind": "notice", "open_url": url})
                .to_string(),
            result_line("prod", &[("refresh_token", MADE)]),
        ],
    );
}

#[test]
fn an_allowed_consent_url_is_handed_to_the_opener() {
    let (op, fleet) = world();
    consent_with_url(&op, CONSENT_URL);
    let console = &mut Scripted::answering(Some("prod"));
    let _ = run(&op, &fleet, &person(), request("grant", "prod"), console);
    assert_eq!(*console.opened.borrow(), [CONSENT_URL]);
}

#[test]
fn a_consent_url_on_another_host_is_never_opened() {
    let (op, fleet) = world();
    consent_with_url(&op, "https://evil.example.net/consent");
    let console = &mut Scripted::answering(Some("prod"));
    let _ = run(&op, &fleet, &person(), request("grant", "prod"), console);
    assert!(console.opened.borrow().is_empty());
}

#[test]
fn the_producer_gets_the_input_value_on_its_stdin() {
    let (op, fleet) = world();
    consent(&op, "prod", MADE);
    let _ = run(
        &op,
        &fleet,
        &person(),
        request("grant", "prod"),
        &mut Scripted::answering(Some("prod")),
    );
    let stdin = op
        .calls
        .borrow()
        .iter()
        .find(|c| c.program == "python3")
        .and_then(|c| c.stdin.clone())
        .unwrap_or_default();
    let request: serde_json::Value = serde_json::from_slice(&stdin).unwrap();
    assert_eq!(request["inputs"]["client_id"], "client-id-value");
}

#[test]
fn a_missing_input_is_refused_before_the_confirmation() {
    let (op, fleet) = world();
    put(&op, &item_id(&fleet, "prod"), "CLIENT_ID", "");
    let mut console = Scripted::answering(Some("prod"));
    let _ = run(
        &op,
        &fleet,
        &person(),
        request("grant", "prod"),
        &mut console,
    );
    assert_eq!(console.asked.get(), 0);
}

#[test]
fn a_generated_set_holds_its_value_after_the_write() {
    let (op, fleet) = world();
    let _ = run(
        &op,
        &fleet,
        &person(),
        request("signing", "prod"),
        &mut Scripted::answering(Some("prod")),
    );
    let v = field(&op, &item_id(&fleet, "prod"), "SIGNING_KEY").unwrap_or_default();
    assert!(v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()));
}

// ---- §4.2 step 5: an item the edit cannot keep -------------------------------------

#[test]
fn an_item_with_an_attachment_is_refused_as_not_rewritable() {
    let (op, fleet) = world();
    let id = item_id(&fleet, "prod");
    for i in op.items.borrow_mut().iter_mut() {
        if i["id"] == id.as_str() {
            i["files"] = serde_json::json!([{"id": "f", "name": "cert.pem"}]);
        }
    }
    let r = run(
        &op,
        &fleet,
        &person(),
        request("grant", "prod"),
        &mut Scripted::answering(Some("prod")),
    );
    assert_eq!(
        refusal_of(r),
        Some(ProvisionRefusal::ItemNotRewritable {
            holds: "an attachment".into()
        })
    );
}

// ---- §7: the receipt ----------------------------------------------------------------

fn written_receipt(op: &FakeOp, fleet: &Fleet) -> Receipt {
    run(
        op,
        fleet,
        &person(),
        request("grant", "prod"),
        &mut Scripted::answering(Some("prod")),
    )
    .unwrap()
    .receipt()
    .unwrap()
}

#[test]
fn the_receipt_names_the_versions_before_and_after() {
    let (op, fleet) = world();
    consent(&op, "prod", MADE);
    let item = written_receipt(&op, &fleet).item;
    assert_eq!(
        (item.version_before, item.version_after),
        (Some(1), Some(2))
    );
}

#[test]
fn the_receipt_lists_the_compared_environment() {
    let (op, fleet) = world();
    consent(&op, "prod", MADE);
    assert_eq!(
        written_receipt(&op, &fleet).compared_environments,
        ["staging"]
    );
}

#[test]
fn the_receipt_holds_no_value() {
    let (op, fleet) = world();
    consent(&op, "prod", MADE);
    let receipt = written_receipt(&op, &fleet);
    let text = format!("{}{receipt:?}", serde_json::to_string(&receipt).unwrap());
    assert!(!text.contains(MADE) && !text.contains("client-id-value"));
}

#[test]
fn nothing_the_producer_printed_is_shown() {
    let (op, fleet) = world();
    consent_with_url(&op, CONSENT_URL);
    let mut console = Scripted::answering(Some("prod"));
    let _ = run(
        &op,
        &fleet,
        &person(),
        request("grant", "prod"),
        &mut console,
    );
    assert!(
        !console
            .shown
            .iter()
            .any(|l| l.contains(MADE) || l.contains("opv.produce"))
    );
}
