//! The agent guide (`opv guide agent`) and the agent skill name every command the installed
//! binary has, so a command added without guidance for assistants fails here (#76).

use std::process::Command;

fn schema_commands() -> Vec<String> {
    let out = Command::new(env!("CARGO_BIN_EXE_opv"))
        .arg("schema")
        .output()
        .expect("opv schema runs");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("schema is JSON");
    v["commands"]
        .as_array()
        .expect("commands")
        .iter()
        .filter_map(|c| c["name"].as_str().map(str::to_string))
        .collect()
}

fn read(path: &str) -> String {
    std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .expect("doc exists")
}

/// Commands the guide may leave out: shell plumbing that an assistant never needs.
const NOT_FOR_ASSISTANTS: &[&str] = &["completions", "help"];

#[test]
fn the_agent_guide_names_every_command() {
    let guide = read("docs/agent-setup.md");
    let missing: Vec<String> = schema_commands()
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
