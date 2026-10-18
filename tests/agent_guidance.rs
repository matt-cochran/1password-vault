//! The agent guide (`opv guide agent`) and the agent skill name every command of the §25
//! surface contract, so a command added without guidance for assistants fails here (#76).

use std::collections::BTreeSet;
use std::process::Command;

use serde_json::Value;

const GOLDEN_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/e2e/expected/surface.json"
);

/// The §25 surface golden, parsed. A malformed golden is a test failure, not a panic in a
/// helper.
fn golden() -> Value {
    let text = std::fs::read_to_string(GOLDEN_PATH).expect("the surface golden is readable");
    serde_json::from_str(&text).expect("the surface golden is valid JSON")
}

/// Every command path the golden fixes, as a set.
fn golden_cli_names() -> BTreeSet<String> {
    golden()["cli"]
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

/// Every MCP tool name the golden fixes, as a set.
fn golden_mcp_names() -> BTreeSet<String> {
    golden()["mcp"]
        .as_array()
        .expect("mcp is an array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("a tool name").to_string())
        .collect()
}

/// The live schema, for the parts of the contract the installed binary already carries.
fn schema() -> serde_json::Value {
    let out = Command::new(env!("CARGO_BIN_EXE_opv"))
        .arg("schema")
        .output()
        .expect("opv schema runs");
    serde_json::from_slice(&out.stdout).expect("schema is JSON")
}

fn read(path: &str) -> String {
    std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .expect("doc exists")
}

/// Commands the guide may leave out: shell plumbing that an assistant never needs.
const NOT_FOR_ASSISTANTS: &[&str] = &["completions", "help"];

#[test]
fn the_agent_guide_names_every_contract_command() {
    let guide = read("docs/agent-setup.md");
    let missing: Vec<String> = golden_cli_names()
        .into_iter()
        .filter(|c| !NOT_FOR_ASSISTANTS.contains(&c.as_str()))
        .filter(|c| !guide.contains(&format!("opv {c}")) && !guide.contains(&format!("`{c}`")))
        .collect();
    assert!(
        missing.is_empty(),
        "docs/agent-setup.md does not mention: {missing:?}"
    );
}

#[test]
fn the_skill_sends_a_session_to_the_guide_schema_and_receipt_first() {
    let skill = read("docs/agent-skill.md");
    assert!(
        ["opv guide agent", "opv schema", "opv ready --json"]
            .iter()
            .all(|c| skill.contains(c))
    );
}

#[test]
fn the_skill_carries_its_version_placeholder() {
    assert!(read("docs/agent-skill.md").contains("version: {{OPV_VERSION}}"));
}

/// The skill teaches the one configuration form (FR-60): no profile, boundaries and named
/// targets; and the per-placement flows (FR-56, FR-58, FR-59).
#[test]
fn the_skill_describes_the_one_form_and_the_placement_flows() {
    let skill = read("docs/agent-skill.md");
    let needles = [
        "[products.",
        "opv propose target",
        "grants_missing",
        "state_vault_wider_than_values",
        "every placement",
        "opv propose structure",
    ];
    assert!(
        !skill.contains("profile")
            && !skill.contains("simple")
            && needles.iter().all(|needle| skill.contains(needle)),
        "docs/agent-skill.md does not describe the one form and the placement flows"
    );
}

/// `docs/mcp.md` documents exactly the five tools the §25 golden fixes (and no 0.11.0 one).
#[test]
fn the_mcp_doc_names_exactly_the_five_contract_tools() {
    let doc = read("docs/mcp.md");
    let named: BTreeSet<String> = doc
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|word| word.starts_with("opv_"))
        .map(str::to_string)
        .collect();
    assert_eq!(
        named,
        golden_mcp_names(),
        "docs/mcp.md names a different MCP tool set"
    );
}

/// `opv schema` states the new commands' effects, describes the named commands' JSON
/// documents and mentions no removed form (E6, FR-56 to FR-60).
#[test]
fn the_schema_is_current_for_named_targets_and_boundaries() {
    let v = schema();
    let command = |name: &str| {
        v["commands"]
            .as_array()
            .expect("commands")
            .iter()
            .find(|c| c["name"] == name)
            .unwrap_or_else(|| panic!("schema has no command {name}"))
            .clone()
    };
    assert_eq!(command("target add")["effect"], "writes_config");
    assert_eq!(command("target add")["ask_user_first"], true);
    assert_eq!(command("target list")["effect"], "reads");
    for name in ["access", "bootstrap", "delivery verify", "config export"] {
        assert!(
            v["documents"].get(name).is_some(),
            "schema documents must describe {name}"
        );
    }
    assert!(
        !serde_json::to_string(&v["documents"])
            .unwrap()
            .contains("simple"),
        "schema documents still mention the simple profile"
    );
    let slugs: Vec<&str> = v["error_codes"]
        .as_array()
        .expect("error_codes")
        .iter()
        .filter_map(|c| c["code"].as_str())
        .collect();
    for slug in [
        "boundary_missing",
        "state_vault_missing",
        "state_vault_wider_than_values",
    ] {
        assert!(slugs.contains(&slug), "error_codes is missing {slug}");
    }
}

/// Every command line in docs/rotation.md names a command the installed binary has, so the
/// documented rotation procedure cannot drift behind the CLI (`opv schema`).
#[test]
fn the_rotation_doc_names_only_commands_the_binary_has() {
    let doc = read("docs/rotation.md");
    let known = schema_commands();
    let unknown: Vec<&str> = doc
        .lines()
        .filter_map(|line| line.trim().strip_prefix("opv "))
        .filter(|rest| {
            !known.iter().any(|name| {
                let words: Vec<&str> = name.split_whitespace().collect();
                !words.is_empty() && rest.split_whitespace().take(words.len()).eq(words)
            })
        })
        .collect();
    assert!(
        unknown.is_empty(),
        "docs/rotation.md names commands the binary does not have: {unknown:?}"
    );
}
