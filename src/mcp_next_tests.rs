//! `opv_next` (design §25.2, row `mcp-propose`): the same document as `opv next [--env]
//! --json`. One behaviour per test, each with one assertion. The world is `opv_state`'s
//! (`FakeOp` replies only): a `local` dev and a `shared` prod environment whose items hold
//! marked values.
//!
//! Parity: the tool's answer, success or failure, equals what the CLI prints for the same
//! input: the library calls `src/main.rs` makes for `opv next`, framed as the CLI frames
//! them against its own invocation (`opv next [--env <env>] --json`).

use std::io::Write as _;

use super::state_tests::{Fake, MARKER, World};
use super::*;

/// `opv_next` for `args` in the world.
fn tool(w: &World, args: Value) -> Value {
    let scope: NextScope = serde_json::from_value(args).unwrap();
    next_doc(w.project(), &w.r, &scope)
}

/// What `opv next [--env <env>] --json` prints in the world: the calls `src/main.rs` makes.
fn cli(w: &World, env: Option<&str>) -> Value {
    let words: Vec<&str> = std::iter::once("next")
        .chain(env.map(|e| ["--env", e]).into_iter().flatten())
        .collect();
    w.cli(&words, |fleet: &crate::domain::Fleet, r: &Fake, out| {
        let (document, signals) =
            crate::app::inventory::gather_for_next(fleet, env, None, r, None)?;
        let doc = crate::app::next::next(&document, &signals);
        writeln!(out, "{}", doc.document()).map_err(|_| Error::from(UNREADABLE_REPORT))
    })
}

// Parity ---------------------------------------------------------------------------------------

#[test]
fn opv_next_is_opv_next_json() {
    let w = World::new();
    assert_eq!(tool(&w, json!({})), cli(&w, None));
}

#[test]
fn opv_next_with_env_is_opv_next_env_json() {
    let w = World::new();
    assert_eq!(tool(&w, json!({"env": "prod"})), cli(&w, Some("prod")));
}

#[test]
fn opv_next_of_an_undeclared_environment_is_the_clis_own_failure() {
    let w = World::new();
    assert_eq!(tool(&w, json!({"env": "prdo"})), cli(&w, Some("prdo")));
}

// Refusals -------------------------------------------------------------------------------------

#[test]
fn opv_next_with_an_env_that_is_not_a_name_is_usage() {
    let w = World::new();
    assert_eq!(tool(&w, json!({"env": "../etc"}))["error"]["code"], "usage");
}

#[test]
fn opv_next_with_an_env_that_is_not_a_name_reads_nothing() {
    let w = World::new();
    tool(&w, json!({"env": "Prod!"}));
    assert!(w.r.0.calls.borrow().is_empty());
}

#[test]
fn opv_next_takes_no_other_field() {
    let parsed = serde_json::from_value::<NextScope>(json!({"product": "app"}));
    assert!(parsed.is_err());
}

// The canary: no answer carries a value ---------------------------------------------------------

#[test]
fn opv_next_answers_no_value() {
    let w = World::new();
    assert!(!tool(&w, json!({})).to_string().contains(MARKER));
}

#[test]
fn opv_next_with_env_answers_no_value() {
    let w = World::new();
    assert!(!tool(&w, json!({"env": "dev"})).to_string().contains(MARKER));
}

// The surface ----------------------------------------------------------------------------------

#[test]
fn opv_next_advertises_the_golden_input_schema() {
    let golden: Value =
        serde_json::from_str(include_str!("../tests/e2e/expected/surface.json")).unwrap();
    let want = golden["mcp"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "opv_next")
        .map(|t| t["input_schema"].clone())
        .unwrap();
    let tool = Server::tool_router()
        .list_all()
        .into_iter()
        .find(|t| t.name == "opv_next")
        .unwrap();
    assert_eq!(Value::Object((*tool.input_schema).clone()), want);
}
