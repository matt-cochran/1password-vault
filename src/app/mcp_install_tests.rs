//! `opv mcp install`: client configurations are merged, never replaced.

use super::*;

const OPV: &str = "/home/me/.local/bin/opv";

fn args() -> Vec<String> {
    server_args(Path::new("/work/app"))
}

fn claude(text: &str, force: bool) -> Result<(String, &'static str), Error> {
    merge_claude(text, Path::new(".mcp.json"), NAME, OPV, &args(), force)
}

fn codex(text: &str, force: bool) -> Result<(String, &'static str), Error> {
    merge_codex(text, Path::new("config.toml"), NAME, OPV, &args(), force)
}

#[test]
fn the_server_runs_opv_mcp_serve_for_the_project() {
    assert_eq!(args(), ["mcp", "serve", "--project", "/work/app"]);
}

#[test]
fn a_new_claude_file_gets_the_opv_server() {
    let (out, _) = claude("", false).unwrap();
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["mcpServers"]["opv"]["command"], OPV);
}

#[test]
fn claude_keeps_other_servers() {
    let (out, _) = claude(
        r#"{"mcpServers":{"other":{"command":"x"}},"keep":1}"#,
        false,
    )
    .unwrap();
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["mcpServers"]["other"]["command"], "x");
}

#[test]
fn claude_registering_again_changes_nothing() {
    let (first, _) = claude("", false).unwrap();
    assert_eq!(claude(&first, false).unwrap().1, "unchanged");
}

#[test]
fn claude_refuses_a_different_opv_entry() {
    let text = r#"{"mcpServers":{"opv":{"command":"/elsewhere/opv-mcp","args":[]}}}"#;
    // A name clash is the person's choice of --name or --force: a usage problem (05.17).
    assert_eq!(claude(text, false).unwrap_err().code_str(), "usage");
}

// 05.17: the conflict's Next is `opv mcp install --help` from the person's own command, so
// it never drops `--project` the way the old fixed `--name opv-project` command did.
#[test]
fn a_conflict_steps_to_the_install_help() {
    let text = r#"{"mcpServers":{"opv":{"command":"/elsewhere/opv-mcp","args":[]}}}"#;
    let e = claude(text, false).unwrap_err();
    let inv = crate::cause::Invocation::from_cli(&[
        "opv".into(),
        "mcp".into(),
        "install".into(),
        "--project".into(),
        "../svc".into(),
    ]);
    assert_eq!(
        e.cause().expect("a catalog cause").0.step(&inv).1,
        crate::cause::Next::Check(crate::cause::Cmd {
            command: vec!["mcp".into(), "install".into()],
            args: vec!["--help".into()],
        })
    );
}

#[test]
fn claude_replaces_a_different_opv_entry_with_force() {
    let text = r#"{"mcpServers":{"opv":{"command":"/elsewhere/opv-mcp","args":[]}}}"#;
    assert_eq!(claude(text, true).unwrap().1, "updated");
}

#[test]
fn claude_refuses_a_file_that_is_not_json() {
    assert_eq!(
        claude("{not json", false).unwrap_err().code_str(),
        "config_invalid"
    );
}

#[test]
fn a_new_codex_file_gets_the_opv_server() {
    let (out, _) = codex("", false).unwrap();
    let doc: toml_edit::DocumentMut = out.parse().unwrap();
    assert_eq!(doc["mcp_servers"]["opv"]["command"].as_str(), Some(OPV));
}

#[test]
fn codex_keeps_comments_and_other_settings() {
    let text = "# my settings\nmodel = \"o3\"\n\n[mcp_servers.other]\ncommand = \"x\"\n";
    let (out, _) = codex(text, false).unwrap();
    assert!(
        out.contains("# my settings")
            && out.contains("[mcp_servers.other]")
            && out.contains("model = \"o3\"")
    );
}

#[test]
fn codex_registering_again_changes_nothing() {
    let (first, _) = codex("", false).unwrap();
    assert_eq!(codex(&first, false).unwrap().1, "unchanged");
}

#[test]
fn codex_refuses_a_different_opv_entry() {
    let text = "[mcp_servers.opv]\ncommand = \"/elsewhere/opv-mcp\"\nargs = []\n";
    assert_eq!(codex(text, false).unwrap_err().code_str(), "usage");
}

#[test]
fn no_entry_carries_an_environment() {
    let (c, _) = claude("", false).unwrap();
    let (x, _) = codex("", false).unwrap();
    assert!(!c.contains("env") && !x.contains("env"));
}

#[test]
fn register_writes_a_new_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested").join(".mcp.json");
    let a = args();
    register("claude", &path, |t| {
        merge_claude(t, &path, NAME, OPV, &a, false)
    })
    .unwrap();
    assert!(std::fs::read_to_string(&path).unwrap().contains("\"mcp\""));
}
