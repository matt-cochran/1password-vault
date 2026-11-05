//! `opv provision` part 1 (design `owner-value-ingestion.md` §10.3 test 28, §10.4 tests
//! 31-38, and the classify and confirmation steps of §4.2): one behavioural assertion per
//! test, through the public `provision` seam with the stateful fake `op`.

use std::cell::Cell;
use std::io;
use std::time::Duration;

use super::*;
use crate::adapters::fake_op::FakeOp;
use crate::cause::{Cause, Guard, NoTerminal, Principal, ProvisionRefusal, UnsupportedFeature};
use crate::host::FakeEnv;
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

[producers.consent]
command = ["python3", "-c", "pass"]
outputs = ["refresh_token"]
inputs = {{ client_id = "app/CLIENT_ID" }}
timeout = "10m"

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

/// A console that answers the typed-back question with `answer` and counts the questions.
struct Scripted {
    answer: Option<&'static str>,
    asked: Cell<usize>,
    shown: Vec<String>,
}

impl Scripted {
    fn answering(answer: Option<&'static str>) -> Self {
        Self {
            answer,
            asked: Cell::new(0),
            shown: Vec::new(),
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
    }
}

fn run(
    op: &dyn CommandRunner,
    fleet: &Fleet,
    host: &FakeEnv,
    req: Request<'_>,
    console: &mut Scripted,
) -> Result<Outcome, Error> {
    provision(fleet, host, &req, op, console)
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

/// The fake `op` with a run budget of `left`.
struct Budgeted<'a> {
    op: &'a FakeOp,
    left: Duration,
}

impl CommandRunner for Budgeted<'_> {
    fn read(&self, call: &Call, refused: &[i32]) -> io::Result<crate::runner::Outcome> {
        self.op.read(call, refused)
    }
    fn write(&self, call: &Call) -> io::Result<crate::runner::Outcome> {
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
        Some(self.left)
    }
}

// ---- §10.3 test 28: budget ------------------------------------------------------

#[test]
fn a_budget_smaller_than_the_producer_timeout_and_reserve_is_refused() {
    let (op, fleet) = world();
    let short = Budgeted {
        op: &op,
        left: Duration::from_secs(5 * 60),
    };
    let r = run(
        &short,
        &fleet,
        &person(),
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
    let short = Budgeted {
        op: &op,
        left: Duration::from_secs(5 * 60),
    };
    let mut console = Scripted::answering(Some("prod"));
    let _ = run(
        &short,
        &fleet,
        &person(),
        request("grant", "prod"),
        &mut console,
    );
    assert_eq!(console.asked.get(), 0);
}

#[test]
fn a_budget_with_room_for_the_producer_and_reserve_is_confirmed() {
    let (op, fleet) = world();
    let room = Budgeted {
        op: &op,
        left: Duration::from_secs(30 * 60),
    };
    let r = run(
        &room,
        &fleet,
        &person(),
        request("grant", "prod"),
        &mut Scripted::answering(Some("prod")),
    );
    assert!(matches!(r, Ok(Outcome::Confirmed(_))));
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
    let r = run(
        &op,
        &fleet,
        &person().var("OP_SESSION_abcdef"),
        request("grant", "staging"),
        &mut Scripted::answering(Some("staging")),
    );
    assert!(matches!(r, Ok(Outcome::Confirmed(_))));
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
fn an_absent_set_typed_back_is_confirmed() {
    let (op, fleet) = world();
    let r = run(
        &op,
        &fleet,
        &person(),
        request("grant", "prod"),
        &mut Scripted::answering(Some("prod")),
    );
    assert!(matches!(r, Ok(Outcome::Confirmed(_))));
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
fn the_confirmed_plan_carries_the_version_read() {
    let (op, fleet) = world();
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
    let room = Budgeted {
        op: &op,
        left: Duration::from_secs(30 * 60),
    };
    let mut console = Scripted::answering(Some("prod"));
    let _ = run(
        &room,
        &fleet,
        &person(),
        request("grant", "prod"),
        &mut console,
    );
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
