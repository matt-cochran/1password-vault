//! The agent guide (`opv guide agent`) and the agent skill name every command the installed
//! binary has, so a command added without guidance for assistants fails here (#76).

use std::process::Command;

fn schema() -> serde_json::Value {
    let out = Command::new(env!("CARGO_BIN_EXE_opv"))
        .arg("schema")
        .output()
        .expect("opv schema runs");
    serde_json::from_slice(&out.stdout).expect("schema is JSON")
}

fn schema_commands() -> Vec<String> {
    schema()["commands"]
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

/// The skill teaches the one configuration form (FR-60): no profile, boundaries and named
/// targets; and the per-placement flows (FR-56, FR-58, FR-59).
#[test]
fn the_skill_describes_the_one_form_and_the_placement_flows() {
    let skill = read("docs/agent-skill.md");
    assert!(
        !skill.contains("profile") && !skill.contains("simple"),
        "docs/agent-skill.md still describes a profile: {skill}"
    );
    for needle in [
        "[products.",
        "opv target add",
        "grants_missing",
        "state_vault_wider_than_values",
        "every placement",
        "opv bootstrap",
    ] {
        assert!(
            skill.contains(needle),
            "docs/agent-skill.md does not name {needle:?}"
        );
    }
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
        "duplicate_scope",
    ] {
        assert!(slugs.contains(&slug), "error_codes is missing {slug}");
    }
}
