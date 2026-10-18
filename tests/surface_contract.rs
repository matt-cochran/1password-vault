//! The §25 surface golden (`tests/e2e/expected/surface.json`): the one interface the CLI
//! and the MCP server must equal. These tests read the golden as data and check the parts
//! the row fixes: it parses, the five MCP tool names, the single writer, the intent schema
//! `opv_propose` advertises, and the absence of the removed 0.11.0 commands.

use std::collections::BTreeSet;

use serde_json::Value;

const GOLDEN_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/e2e/expected/surface.json"
);

/// The golden, parsed. A malformed golden is a test failure, not a panic in a helper.
fn golden() -> Value {
    let text = std::fs::read_to_string(GOLDEN_PATH).expect("the surface golden is readable");
    serde_json::from_str(&text).expect("the surface golden is valid JSON")
}

/// Every command path the golden lists, as a set.
fn cli_names(golden: &Value) -> BTreeSet<String> {
    golden["cli"]
        .as_array()
        .expect("cli is an array")
        .iter()
        .map(|command| {
            command["name"]
                .as_str()
                .expect("a cli command has a name")
                .to_string()
        })
        .collect()
}

#[test]
fn surface_golden_parses_as_json() {
    let text = std::fs::read_to_string(GOLDEN_PATH).expect("the surface golden is readable");
    assert!(serde_json::from_str::<Value>(&text).is_ok());
}

#[test]
fn surface_golden_lists_exactly_the_five_mcp_tools() {
    let listed: BTreeSet<String> = golden()["mcp"]
        .as_array()
        .expect("mcp is an array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("a tool name").to_string())
        .collect();
    let expected: BTreeSet<String> = [
        "opv_state",
        "opv_next",
        "opv_propose",
        "opv_import_local",
        "opv_explain",
    ]
    .iter()
    .map(|name| name.to_string())
    .collect();
    assert_eq!(listed, expected);
}

#[test]
fn surface_golden_marks_only_opv_import_local_as_writing() {
    let golden = golden();
    let writers: Vec<&str> = golden["mcp"]
        .as_array()
        .expect("mcp is an array")
        .iter()
        .filter(|tool| tool["writes"] == Value::Bool(true))
        .map(|tool| tool["name"].as_str().expect("a tool name"))
        .collect();
    assert_eq!(writers, vec!["opv_import_local"]);
}

#[test]
fn surface_golden_opv_propose_schema_equals_the_intent_schema() {
    let golden = golden();
    let propose = golden["mcp"]
        .as_array()
        .expect("mcp is an array")
        .iter()
        .find(|tool| tool["name"] == "opv_propose")
        .expect("opv_propose is listed");
    assert_eq!(propose["input_schema"], opv::domain::intent::json_schema());
}

#[test]
fn surface_golden_lists_no_removed_zero_eleven_command() {
    let names = cli_names(&golden());
    let removed = [
        "approve",
        "add",
        "env add",
        "target add",
        "init",
        "bootstrap",
        "structure plan",
        "structure apply",
        "item skeleton",
        "generate",
        "tidy",
        "adopt",
        "check",
        "config describe",
    ];
    let offending: Vec<&str> = removed
        .iter()
        .copied()
        .filter(|command| names.contains(*command))
        .collect();
    assert!(
        offending.is_empty(),
        "removed commands listed: {offending:?}"
    );
}
