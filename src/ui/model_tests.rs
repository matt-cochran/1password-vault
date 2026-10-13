use super::*;

/// The documents recorded from a real run (`tests/fixtures/ui/`), served by command.
pub(crate) struct Fixtures;

impl Source for Fixtures {
    fn json(&self, args: &[&str]) -> Result<Value, String> {
        let file = match args {
            ["config", "export", ..] => "config.json",
            ["ready", ..] => "ready.json",
            ["status", "ci", ..] => "status-ci.json",
            ["check", "local", "--product", "api", ..] => "check-local-api.json",
            other => return Err(format!("no fixture for {other:?}")),
        };
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/ui")
            .join(file);
        serde_json::from_slice(&std::fs::read(path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())
    }
}

fn snap() -> Snapshot {
    Snapshot::gather(&Fixtures)
}

#[test]
fn environments_come_from_the_configuration_in_their_order() {
    let keys: Vec<String> = snap().envs.into_iter().map(|e| e.key).collect();
    assert_eq!(keys, ["local", "ci"]);
}

#[test]
fn an_environment_shows_its_title() {
    assert_eq!(snap().env("ci").unwrap().title, "CI (GitHub)");
}

#[test]
fn a_run_only_environment_has_no_target() {
    assert_eq!(snap().env("local").unwrap().target, None);
}

#[test]
fn a_deployed_environment_names_its_provider() {
    assert_eq!(snap().env("ci").unwrap().target.as_deref(), Some("GitHub"));
}

#[test]
fn a_source_only_product_is_listed_last() {
    assert_eq!(snap().product_names(), ["api", "shared"]);
}

#[test]
fn a_personal_key_is_marked() {
    let s = snap();
    let api = s.products.iter().find(|p| p.name == "api").unwrap();
    assert!(
        api.keys
            .iter()
            .any(|k| k.name == "OPENAI_API_KEY" && k.personal)
    );
}

#[test]
fn a_shared_value_lists_its_consumers() {
    assert_eq!(
        snap().consumers("shared", "DEPLOY_TOKEN"),
        [("api".to_string(), "DEPLOY_TOKEN".to_string())]
    );
}

#[test]
fn cells_come_from_each_environments_rows() {
    let s = snap();
    assert!(
        s.cells
            .contains_key(&("ci".into(), "api".into(), "API_TOKEN".into()))
    );
}

#[test]
fn every_document_was_read() {
    assert!(snap().problems.is_empty(), "{:?}", snap().problems);
}

#[test]
fn the_receipt_findings_are_kept() {
    assert!(!snap().findings.is_empty());
}
