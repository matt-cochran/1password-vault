//! `opv run` pre-flights the 1Password sign-in before `op run` (#266, FR-40 amended): a
//! session or account cause stops the run, typed, before the child can start, and a sign-in
//! replay never follows a child that has started. Design: `docs/design/agent-signin-readiness.md`
//! §2.2 and §7.1 (`run::*`, `main::no_replay_after_child_started`).
//!
//! Every test that expects the read holds `tidy::activate()`: without it a unit test skips
//! the read (and so the preflight), and "no `op run`" would pass vacuously.

use super::*;
use crate::app::tidy::activate;
use crate::runner::Output;
use crate::runner::fake::FakeRunner;

/// op's own words without a session (op 2.40.0), as the signed-out read sees them.
const SIGNED_OUT: &str = "[ERROR] 2026/11/04 10:00:00 You are not currently signed in. Please run `op signin --help` for instructions\n";

const FLEET: &str = r#"
[environments.dev]
boundaries.core = { vault_id = "vdev", item_id = "idev" }

[products.app]
boundary = "core"

[products.app.keys.TOKEN]
kind = "secret"
environments = ["dev"]
"#;

fn fleet() -> Fleet {
    crate::config::parse(FLEET).unwrap()
}

fn cmd() -> Vec<String> {
    vec!["app".to_string()]
}

/// A runner on which every `op` call answers as op does without a session (no CLI
/// session, no desktop-app integration: the headless agent shell of #266).
fn signed_out() -> FakeRunner {
    let r = FakeRunner::default();
    for _ in 0..16 {
        r.push_with_stderr(Output::failure(1), SIGNED_OUT);
    }
    r
}

/// The `op run` calls the runner saw.
fn op_runs(r: &FakeRunner) -> usize {
    r.calls
        .borrow()
        .iter()
        .filter(|c| c.program == "op" && c.args.first().is_some_and(|a| a == "run"))
        .count()
}

/// `opv run dev -- app` on `r`, with the read on.
fn run_on(r: &FakeRunner) -> Result<i32, Error> {
    let _on = activate();
    run(&fleet(), "dev", "app", &cmd(), r)
}

// ---- the preflight ----------------------------------------------------------------------

#[test]
fn signed_out_read_stops_before_op_run() {
    let r = signed_out();
    let _ = run_on(&r);
    assert_eq!(op_runs(&r), 0);
}

#[test]
fn signed_out_read_is_op_not_signed_in() {
    let e = run_on(&signed_out()).unwrap_err();
    assert_eq!(e.code_str(), "op_not_signed_in");
}

/// Headless (an agent shell, no daemon, no CLI session): the typed error, and only a person
/// can act on it.
#[test]
fn signed_out_run_needs_a_person() {
    let e = run_on(&signed_out()).unwrap_err();
    assert!(e.human_required());
}

/// The child never started, so the run may be replayed after a sign-in at a terminal.
#[test]
fn signed_out_run_may_be_replayed() {
    let res = run_on(&signed_out());
    assert!(may_replay(&res));
}

#[test]
fn signed_out_run_never_marks_the_child_started() {
    let _ = run_on(&signed_out());
    assert!(!child_started());
}

/// Positive partner: a read that answers lets the run reach `op run`.
#[test]
fn signed_in_run_calls_op_run_once() {
    let r = FakeRunner::default();
    r.push_with_stderr(Output::success(item_json()), "");
    r.push_with_stderr(Output::success(Vec::new()), "");
    let _ = run_on(&r);
    assert_eq!(op_runs(&r), 1);
}

/// A failure that is neither a session nor an account (here an item op cannot find) is
/// still left to `op run` to report, as before #266.
#[test]
fn other_read_failure_still_runs() {
    let r = FakeRunner::default();
    for _ in 0..8 {
        r.push_with_stderr(
            Output::failure(1),
            "[ERROR] 2026/11/04 10:00:00 \"idev\" isn't an item in the \"vdev\" vault. Specify the item with its UUID, name, or domain.\n",
        );
    }
    r.responses
        .borrow_mut()
        .push_back(Ok(Output::success(Vec::new())));
    let _ = run_on(&r);
    assert_eq!(op_runs(&r), 1);
}

/// The item the read gets: TOKEN filled, in its section, laid out by the convention.
fn item_json() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "id": "idev",
        "version": 1,
        "vault": {"id": "vdev"},
        "sections": [{"id": "app", "label": "app"}],
        "fields": [
            {"id": "f1", "label": "TOKEN", "type": "CONCEALED", "value": "t-MARKER266",
             "section": {"id": "app", "label": "app"}},
            {"id": "f2", "label": "convention", "type": "STRING", "value": "1",
             "section": {"id": "opv", "label": "opv"}}
        ]
    }))
    .unwrap()
}

// ---- op's default account is refused (FR-40) ---------------------------------------------

/// Two accounts on this machine (`op account list`), neither selected.
fn two_accounts() -> FakeRunner {
    FakeRunner::new([Output::success(
        r#"[{"url":"my.1password.com","email":"a@example.com","user_uuid":"UAAAAAAAAAAAAAAAAAAAAAAAAA","account_uuid":"AAAAAAAAAAAAAAAAAAAAAAAAAA"},
           {"url":"team.1password.com","email":"a@example.com","user_uuid":"UBBBBBBBBBBBBBBBBBBBBBBBBB","account_uuid":"BBBBBBBBBBBBBBBBBBBBBBBBBB"}]"#,
    )])
}

#[test]
fn op_default_account_is_refused() {
    let r = two_accounts();
    let _none = no_account_selected();
    let e = run_on(&r).unwrap_err();
    assert_eq!(e.code_str(), "account_required");
}

#[test]
fn op_default_account_refusal_stops_before_op_run() {
    let r = two_accounts();
    let _none = no_account_selected();
    let _ = run_on(&r);
    assert_eq!(op_runs(&r), 0);
}

// ---- the replay guard (D4, FMECA item 4) --------------------------------------------------

/// A signed-out failure, as `launch` could return one after `op run` if a later change
/// added a step after the child (a post-run read, a remote step).
fn signed_out_error() -> Error {
    crate::cause::Cause::NotSignedIn {
        system: crate::cause::System::OnePassword,
        account: None,
        state: crate::cause::SessionState::SignedOut,
        selected_by: None,
    }
    .into()
}

/// main's sign-in loop (main.rs, FR-40) with an in-place sign-in that always succeeds: the
/// attempt is repeated at most once, and only while [`may_replay`] allows it.
fn main_loop(mut attempt: impl FnMut() -> Result<i32, Error>) -> Result<i32, Error> {
    let mut signed_in = false;
    loop {
        let res = attempt();
        if may_replay(&res) && !signed_in {
            signed_in = true;
            continue;
        }
        break res;
    }
}

#[test]
fn no_replay_after_child_started() {
    let r = FakeRunner::default();
    let _ = main_loop(|| {
        r.responses
            .borrow_mut()
            .push_back(Ok(Output::success(Vec::new())));
        run(&fleet(), "dev", "app", &cmd(), &r)?;
        Err(signed_out_error())
    });
    assert_eq!(op_runs(&r), 1);
}

/// Positive partner: the same failure before any child is replayed once.
#[test]
fn a_signed_out_failure_before_the_child_is_replayed_once() {
    let mut attempts = 0;
    let _ = main_loop(|| {
        attempts += 1;
        Err(signed_out_error())
    });
    assert_eq!(attempts, 2);
}

#[test]
fn a_started_child_is_marked() {
    let r = FakeRunner::new([Output::success(Vec::new())]);
    let _ = run(&fleet(), "dev", "app", &cmd(), &r);
    assert!(child_started());
}

#[test]
fn a_failure_other_than_signed_out_is_never_replayed() {
    let e: Error = crate::cause::Cause::NeedsConfirm {
        env: crate::cause::EnvName::new("dev"),
    }
    .into();
    assert!(!may_replay(&Err(e)));
}
