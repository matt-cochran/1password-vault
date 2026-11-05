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
        fill_missing: false,
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

// ---- #262 Slice B: templates (§3.1, §5.3, §5.4) and --fill-missing (§4.7) -------------

/// The issuer's three site IDs: intermediates, rendered into the bundle and never stored.
const SITE_IDS: [&str; 3] = [
    "00000000-0000-4000-8000-000000000001",
    "00000000-0000-4000-8000-000000000002",
    "00000000-0000-4000-8000-000000000003",
];

/// A Journeeze-shaped world (§3.1, neutral names): in `staging`, the set `sites` holds five
/// generated secrets, three site keys from the producer `site-issuer`, and the bundle
/// `shop/SITE_SECRETS` rendered from three site IDs (intermediates) and four of the
/// secrets. `bundle_rules` is the bundle key's extra TOML (its rules).
fn sites_world_with(bundle_rules: &str) -> (FakeOp, Fleet) {
    let op = FakeOp::default();
    let id = op.insert(
        VAULT,
        serde_json::json!({
            "title": "shop · staging values", "category": "SECURE_NOTE",
            "sections": [{"id": "shop", "label": "shop"}],
            "fields": []
        }),
    );
    let secret = |k: &str| format!("[products.shop.keys.{k}]\nkind = \"secret\"\n");
    let keys: String = [
        "PLATFORM_IDENTITY_SECRET",
        "AGENCY_IDENTITY_SECRET",
        "OWNER_IDENTITY_SECRET",
        "SITES_GATEWAY_KEY",
        "USER_HASH_KEY",
        "PLATFORM_SITE_KEY",
        "AGENCY_SITE_KEY",
        "OWNER_SITE_KEY",
    ]
    .iter()
    .map(|k| secret(k))
    .collect();
    let fleet = crate::config::parse(&format!(
        r#"[environments.staging]
tier = "shared"
boundaries.shop = {{ vault_id = "{VAULT}", item_id = "{id}" }}

{keys}
[products.shop.keys.SITE_SECRETS]
kind = "secret"
{bundle_rules}

[producers.site-issuer]
command = ["python3", "-c", "pass"]
outputs = ["platform_site_id", "platform_site_key", "agency_site_id", "agency_site_key",
           "owner_site_id", "owner_site_key"]
timeout = "5m"

[sets.sites]
environments = ["staging"]

[sets.sites.members]
"shop/PLATFORM_IDENTITY_SECRET" = {{ generate = {{ hex_bytes = 32 }} }}
"shop/AGENCY_IDENTITY_SECRET"   = {{ generate = {{ hex_bytes = 32 }} }}
"shop/OWNER_IDENTITY_SECRET"    = {{ generate = {{ hex_bytes = 32 }} }}
"shop/SITES_GATEWAY_KEY"        = {{ generate = {{ hex_bytes = 32 }} }}
"shop/USER_HASH_KEY"            = {{ generate = {{ hex_bytes = 32 }} }}
"shop/PLATFORM_SITE_KEY" = {{ producer = "site-issuer", output = "platform_site_key" }}
"shop/AGENCY_SITE_KEY"   = {{ producer = "site-issuer", output = "agency_site_key" }}
"shop/OWNER_SITE_KEY"    = {{ producer = "site-issuer", output = "owner_site_key" }}

[sets.sites.members."shop/SITE_SECRETS".template]
version = 1
sites = [
  {{ siteId = "${{site-issuer.platform_site_id}}", identitySecret = "${{shop/PLATFORM_IDENTITY_SECRET}}", gatewaySecret = "${{shop/SITES_GATEWAY_KEY}}" }},
  {{ siteId = "${{site-issuer.agency_site_id}}",   identitySecret = "${{shop/AGENCY_IDENTITY_SECRET}}",   gatewaySecret = "${{shop/SITES_GATEWAY_KEY}}" }},
  {{ siteId = "${{site-issuer.owner_site_id}}",    identitySecret = "${{shop/OWNER_IDENTITY_SECRET}}",    gatewaySecret = "${{shop/SITES_GATEWAY_KEY}}" }},
]
"#
    ))
    .unwrap();
    (op, fleet)
}

fn sites_world() -> (FakeOp, Fleet) {
    sites_world_with("")
}

/// The set's item in `staging`.
fn sites_item(fleet: &Fleet) -> String {
    fleet.environments["staging"].boundaries["shop"]
        .as_ref()
        .unwrap()
        .item_id
        .clone()
}

/// Queue the site issuer returning `ids` and three site keys.
fn issuing(op: &FakeOp, ids: [&str; 3]) {
    producing(
        op,
        vec![result_line(
            "staging",
            &[
                ("platform_site_id", ids[0]),
                ("platform_site_key", "site-key-platform-0001"),
                ("agency_site_id", ids[1]),
                ("agency_site_key", "site-key-agency-0002"),
                ("owner_site_id", ids[2]),
                ("owner_site_key", "site-key-owner-0003"),
            ],
        )],
    );
}

fn sites_request(fill_missing: bool) -> Request<'static> {
    Request {
        fill_missing,
        ..request("sites", "staging")
    }
}

/// Provision `sites` in `staging` with the issuer giving `ids`.
fn provision_sites(op: &FakeOp, fleet: &Fleet, fill_missing: bool) -> Result<Outcome, Error> {
    run(
        op,
        fleet,
        &person(),
        sites_request(fill_missing),
        &mut Scripted::answering(Some("staging")),
    )
}

/// A complete `sites` set, made by one run.
fn provisioned_sites() -> (FakeOp, Fleet) {
    let (op, fleet) = sites_world();
    issuing(&op, SITE_IDS);
    provision_sites(&op, &fleet, false).unwrap();
    (op, fleet)
}

/// Field `label` of the set's item.
fn site_field(op: &FakeOp, fleet: &Fleet, label: &str) -> Option<String> {
    field(op, &sites_item(fleet), label)
}

/// The bundle as the owner script builds it from the stored members and `ids`.
fn expected_bundle(op: &FakeOp, fleet: &Fleet, ids: [&str; 3]) -> serde_json::Value {
    let f = |k: &str| site_field(op, fleet, k).unwrap();
    let gateway = f("SITES_GATEWAY_KEY");
    serde_json::json!({"version": 1, "sites": [
        {"siteId": ids[0], "identitySecret": f("PLATFORM_IDENTITY_SECRET"), "gatewaySecret": gateway},
        {"siteId": ids[1], "identitySecret": f("AGENCY_IDENTITY_SECRET"), "gatewaySecret": gateway},
        {"siteId": ids[2], "identitySecret": f("OWNER_IDENTITY_SECRET"), "gatewaySecret": gateway},
    ]})
}

fn stored_bundle(op: &FakeOp, fleet: &Fleet) -> serde_json::Value {
    serde_json::from_str(&site_field(op, fleet, "SITE_SECRETS").unwrap()).unwrap()
}

#[test]
fn a_template_set_is_written() {
    let (op, fleet) = sites_world();
    issuing(&op, SITE_IDS);
    assert!(matches!(
        provision_sites(&op, &fleet, false),
        Ok(Outcome::Written(_))
    ));
}

#[test]
fn a_journeeze_shaped_set_stores_the_bundle_of_its_members_and_site_ids() {
    let (op, fleet) = provisioned_sites();
    assert_eq!(
        stored_bundle(&op, &fleet),
        expected_bundle(&op, &fleet, SITE_IDS)
    );
}

#[test]
fn the_bundle_is_compact_json() {
    let (op, fleet) = provisioned_sites();
    assert!(
        site_field(&op, &fleet, "SITE_SECRETS")
            .unwrap()
            .starts_with(r#"{"version":1,"sites":[{"siteId":""#)
    );
}

#[test]
fn a_producer_member_holds_its_output_beside_the_bundle() {
    let (op, fleet) = provisioned_sites();
    assert_eq!(
        site_field(&op, &fleet, "AGENCY_SITE_KEY").as_deref(),
        Some("site-key-agency-0002")
    );
}

#[test]
fn an_intermediate_is_stored_only_inside_the_bundle() {
    let (op, fleet) = provisioned_sites();
    let id = sites_item(&fleet);
    assert_eq!(
        held_in(&op, &id, |f| f["value"]
            .as_str()
            .is_some_and(|v| v.contains(SITE_IDS[0]))),
        site_field(&op, &fleet, "SITE_SECRETS")
    );
}

#[test]
fn a_template_set_writes_in_one_item_edit() {
    let (op, _fleet) = provisioned_sites();
    assert_eq!(op.count(&["op", "item", "edit"]), 1);
}

#[test]
fn the_receipt_names_the_bundle_as_template_made() {
    let (op, fleet) = sites_world();
    issuing(&op, SITE_IDS);
    let receipt = provision_sites(&op, &fleet, false)
        .unwrap()
        .receipt()
        .unwrap();
    assert!(
        receipt
            .members
            .iter()
            .any(|m| m.key == "shop/SITE_SECRETS" && m.made_by == "template")
    );
}

#[test]
fn the_receipt_holds_no_site_id() {
    let (op, fleet) = sites_world();
    issuing(&op, SITE_IDS);
    let receipt = provision_sites(&op, &fleet, false)
        .unwrap()
        .receipt()
        .unwrap();
    let text = format!("{}{receipt:?}", serde_json::to_string(&receipt).unwrap());
    assert!(!text.contains(SITE_IDS[0]));
}

#[test]
fn the_plan_runs_a_producer_a_template_uses() {
    let (op, fleet) = sites_world();
    let r = run(
        &op,
        &fleet,
        &person(),
        Request {
            dry_run: true,
            ..sites_request(false)
        },
        &mut Scripted::answering(None),
    );
    let names: Vec<String> = r
        .unwrap()
        .plan()
        .producers
        .iter()
        .map(|p| p.name.clone())
        .collect();
    assert_eq!(names, ["site-issuer"]);
}

#[test]
fn a_rendered_bundle_failing_its_keys_rules_is_refused_naming_it() {
    let (op, fleet) = sites_world_with("rules = { prefix = \"bundle:\" }");
    issuing(&op, SITE_IDS);
    let named: Vec<String> = match cause_of(provision_sites(&op, &fleet, false)) {
        Cause::KeysBlocking { rows, .. } => rows
            .iter()
            .map(|row| format!("{}/{}", row.product, row.key))
            .collect(),
        other => panic!("{other:?}"),
    };
    assert_eq!(named, ["shop/SITE_SECRETS"]);
}

#[test]
fn a_rendered_bundle_failing_its_keys_rules_makes_no_item_edit() {
    let (op, fleet) = sites_world_with("rules = { prefix = \"bundle:\" }");
    issuing(&op, SITE_IDS);
    let _ = provision_sites(&op, &fleet, false);
    assert_eq!(op.count(&["op", "item", "edit"]), 0);
}

#[test]
fn a_complete_template_set_is_unchanged() {
    let (op, fleet) = provisioned_sites();
    assert!(matches!(
        provision_sites(&op, &fleet, false),
        Ok(Outcome::Unchanged(_))
    ));
}

#[test]
fn a_bundle_disagreeing_with_a_member_is_refused_as_inconsistent() {
    let (op, fleet) = provisioned_sites();
    put(
        &op,
        &sites_item(&fleet),
        "SITES_GATEWAY_KEY",
        &"e".repeat(64),
    );
    assert_eq!(
        refusal_of(provision_sites(&op, &fleet, false)),
        Some(ProvisionRefusal::Inconsistent {
            members: vec!["shop/SITE_SECRETS".into()]
        })
    );
}

#[test]
fn a_bundle_of_another_shape_is_refused_as_inconsistent() {
    let (op, fleet) = provisioned_sites();
    put(
        &op,
        &sites_item(&fleet),
        "SITE_SECRETS",
        r#"{"version":2,"sites":[]}"#,
    );
    assert_eq!(
        refusal_of(provision_sites(&op, &fleet, false)),
        Some(ProvisionRefusal::Inconsistent {
            members: vec!["shop/SITE_SECRETS".into()]
        })
    );
}

#[test]
fn replace_remakes_a_disagreeing_bundle_from_the_new_members() {
    let (op, fleet) = provisioned_sites();
    put(
        &op,
        &sites_item(&fleet),
        "SITES_GATEWAY_KEY",
        &"e".repeat(64),
    );
    issuing(&op, SITE_IDS);
    let _ = run(
        &op,
        &fleet,
        &person(),
        Request {
            replace: true,
            ..sites_request(false)
        },
        &mut Scripted::answering(Some("staging")),
    );
    assert_eq!(
        stored_bundle(&op, &fleet),
        expected_bundle(&op, &fleet, SITE_IDS)
    );
}

// ---- --fill-missing (§4.7, D7) --------------------------------------------------------

#[test]
fn fill_missing_with_replace_is_a_usage_error() {
    let (op, fleet) = provisioned_sites();
    let r = run(
        &op,
        &fleet,
        &person(),
        Request {
            replace: true,
            ..sites_request(true)
        },
        &mut Scripted::answering(Some("staging")),
    );
    assert_eq!(r.unwrap_err().code_str(), "usage");
}

#[test]
fn fill_missing_keeps_every_present_value() {
    let (op, fleet) = provisioned_sites();
    let before = site_field(&op, &fleet, "PLATFORM_IDENTITY_SECRET");
    put(&op, &sites_item(&fleet), "USER_HASH_KEY", "");
    provision_sites(&op, &fleet, true).unwrap();
    assert_eq!(site_field(&op, &fleet, "PLATFORM_IDENTITY_SECRET"), before);
}

#[test]
fn fill_missing_keeps_the_present_bundle() {
    let (op, fleet) = provisioned_sites();
    let before = site_field(&op, &fleet, "SITE_SECRETS");
    put(&op, &sites_item(&fleet), "USER_HASH_KEY", "");
    provision_sites(&op, &fleet, true).unwrap();
    assert_eq!(site_field(&op, &fleet, "SITE_SECRETS"), before);
}

#[test]
fn fill_missing_generates_a_missing_member_no_bundle_holds() {
    let (op, fleet) = provisioned_sites();
    put(&op, &sites_item(&fleet), "USER_HASH_KEY", "");
    provision_sites(&op, &fleet, true).unwrap();
    let v = site_field(&op, &fleet, "USER_HASH_KEY").unwrap_or_default();
    assert!(v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()));
}

#[test]
fn fill_missing_of_a_generated_member_starts_no_producer() {
    let (op, fleet) = provisioned_sites();
    put(&op, &sites_item(&fleet), "USER_HASH_KEY", "");
    issuing(&op, SITE_IDS);
    provision_sites(&op, &fleet, true).unwrap();
    assert_eq!(op.producers.borrow().len(), 1);
}

#[test]
fn fill_missing_recovers_a_member_from_the_bundles_leaf() {
    let (op, fleet) = provisioned_sites();
    let before = site_field(&op, &fleet, "AGENCY_IDENTITY_SECRET");
    put(&op, &sites_item(&fleet), "AGENCY_IDENTITY_SECRET", "");
    provision_sites(&op, &fleet, true).unwrap();
    assert_eq!(site_field(&op, &fleet, "AGENCY_IDENTITY_SECRET"), before);
}

#[test]
fn fill_missing_renders_a_missing_bundle_from_the_present_members() {
    let (op, fleet) = provisioned_sites();
    put(&op, &sites_item(&fleet), "SITE_SECRETS", "");
    issuing(&op, SITE_IDS);
    provision_sites(&op, &fleet, true).unwrap();
    assert_eq!(
        stored_bundle(&op, &fleet),
        expected_bundle(&op, &fleet, SITE_IDS)
    );
}

#[test]
fn fill_missing_keeps_a_site_key_the_rerun_producer_returns_again() {
    let (op, fleet) = provisioned_sites();
    put(&op, &sites_item(&fleet), "OWNER_SITE_KEY", "");
    put(
        &op,
        &sites_item(&fleet),
        "PLATFORM_SITE_KEY",
        "kept-platform-key-0001",
    );
    issuing(&op, SITE_IDS);
    provision_sites(&op, &fleet, true).unwrap();
    assert_eq!(
        site_field(&op, &fleet, "PLATFORM_SITE_KEY").as_deref(),
        Some("kept-platform-key-0001")
    );
}

#[test]
fn fill_missing_takes_a_missing_site_key_from_the_rerun_producer() {
    let (op, fleet) = provisioned_sites();
    put(&op, &sites_item(&fleet), "OWNER_SITE_KEY", "");
    issuing(&op, SITE_IDS);
    provision_sites(&op, &fleet, true).unwrap();
    assert_eq!(
        site_field(&op, &fleet, "OWNER_SITE_KEY").as_deref(),
        Some("site-key-owner-0003")
    );
}

#[test]
fn fill_missing_refuses_a_rerun_whose_site_id_differs_from_the_bundle() {
    let (op, fleet) = provisioned_sites();
    put(&op, &sites_item(&fleet), "OWNER_SITE_KEY", "");
    issuing(
        &op,
        [
            SITE_IDS[0],
            SITE_IDS[1],
            "00000000-0000-4000-8000-0000000000ff",
        ],
    );
    assert_eq!(
        refusal_of(provision_sites(&op, &fleet, true)),
        Some(ProvisionRefusal::Inconsistent {
            members: vec!["shop/SITE_SECRETS".into()]
        })
    );
}

#[test]
fn fill_missing_with_a_differing_site_id_makes_no_item_edit() {
    let (op, fleet) = provisioned_sites();
    put(&op, &sites_item(&fleet), "OWNER_SITE_KEY", "");
    issuing(
        &op,
        [
            SITE_IDS[0],
            SITE_IDS[1],
            "00000000-0000-4000-8000-0000000000ff",
        ],
    );
    let _ = provision_sites(&op, &fleet, true);
    assert_eq!(op.count(&["op", "item", "edit"]), 1);
}

#[test]
fn fill_missing_refuses_a_partial_set_whose_bundle_disagrees_with_a_member() {
    let (op, fleet) = provisioned_sites();
    put(&op, &sites_item(&fleet), "USER_HASH_KEY", "");
    put(
        &op,
        &sites_item(&fleet),
        "SITES_GATEWAY_KEY",
        &"e".repeat(64),
    );
    assert_eq!(
        refusal_of(provision_sites(&op, &fleet, true)),
        Some(ProvisionRefusal::Inconsistent {
            members: vec!["shop/SITE_SECRETS".into()]
        })
    );
}

#[test]
fn fill_missing_on_a_complete_set_is_unchanged() {
    let (op, fleet) = provisioned_sites();
    assert!(matches!(
        provision_sites(&op, &fleet, true),
        Ok(Outcome::Unchanged(_))
    ));
}

#[test]
fn fill_missing_on_a_partial_generated_set_fills_it() {
    // `keys` holds CLIENT_ID and not SESSION_KEY.
    let (op, fleet) = world();
    let _ = run(
        &op,
        &fleet,
        &person(),
        Request {
            fill_missing: true,
            ..request("keys", "prod")
        },
        &mut Scripted::answering(Some("prod")),
    );
    let v = field(&op, &item_id(&fleet, "prod"), "SESSION_KEY").unwrap_or_default();
    assert!(v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()));
}

#[test]
fn fill_missing_on_a_partial_generated_set_keeps_the_present_member() {
    let (op, fleet) = world();
    let _ = run(
        &op,
        &fleet,
        &person(),
        Request {
            fill_missing: true,
            ..request("keys", "prod")
        },
        &mut Scripted::answering(Some("prod")),
    );
    assert_eq!(
        field(&op, &item_id(&fleet, "prod"), "CLIENT_ID").as_deref(),
        Some("client-id-value")
    );
}

#[test]
fn the_fill_missing_plan_keeps_present_members() {
    let (op, fleet) = provisioned_sites();
    put(&op, &sites_item(&fleet), "USER_HASH_KEY", "");
    let mut console = Scripted::answering(None);
    let _ = run(&op, &fleet, &person(), sites_request(true), &mut console);
    assert!(console.shown[0].contains("  keep    shop/PLATFORM_IDENTITY_SECRET"));
}

// ---- security review 0.18.0 S9: the pin again, right before the spawn ------------

/// `world()` whose `consent` producer runs the project file `connect.py`, pinned to the
/// reviewed text, while the file in the project now holds `now`.
fn pinned_world(now: &str) -> (FakeOp, Fleet, tempfile::TempDir) {
    use sha2::Digest as _;
    let (op, mut fleet) = world();
    consent(&op, "prod", MADE);
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("connect.py"), now).unwrap();
    let producer = fleet.producers.get_mut("consent").unwrap();
    producer.command = vec!["python3".into(), "connect.py".into()];
    producer.sha256 = Some(hex::encode(sha2::Sha256::digest(b"print('reviewed')\n")));
    (op, fleet, dir)
}

fn run_in(op: &FakeOp, fleet: &Fleet, dir: &Path) -> Result<Outcome, Error> {
    let req = Request {
        project: dir,
        ..request("grant", "prod")
    };
    run(
        op,
        fleet,
        &person(),
        req,
        &mut Scripted::answering(Some("prod")),
    )
}

#[test]
fn a_producer_file_changed_after_load_is_refused_as_changed() {
    let (op, fleet, dir) = pinned_world("print('edited')\n");
    assert_eq!(
        cause_of(run_in(&op, &fleet, dir.path())),
        Cause::ProducerChanged {
            producer: "consent".into(),
            file: "connect.py".into(),
        }
    );
}

#[test]
fn a_producer_file_changed_after_load_is_never_spawned() {
    let (op, fleet, dir) = pinned_world("print('edited')\n");
    let _ = run_in(&op, &fleet, dir.path());
    assert_eq!(op.producers.borrow().len(), 1);
}

#[test]
fn a_producer_file_still_matching_its_pin_is_written() {
    let (op, fleet, dir) = pinned_world("print('reviewed')\n");
    assert!(matches!(
        run_in(&op, &fleet, dir.path()),
        Ok(Outcome::Written(_))
    ));
}
