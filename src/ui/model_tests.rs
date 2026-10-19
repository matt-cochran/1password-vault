use super::*;

/// The documents of a real run's shape (`tests/fixtures/ui/`), served by command. The
/// configuration is `config.toml` as `config export --json` prints it.
pub(crate) struct Fixtures;

fn fixture(name: &str) -> Result<Vec<u8>, String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/ui")
        .join(name);
    std::fs::read(path).map_err(|e| e.to_string())
}

/// `config.toml` as `opv config export --json` prints it.
pub(crate) fn exported_config() -> Vec<u8> {
    let text = String::from_utf8(fixture("config.toml").unwrap()).unwrap();
    let value: toml::Value = toml::from_str(&text).unwrap();
    serde_json::to_vec_pretty(&value).unwrap()
}

impl Source for Fixtures {
    fn stdout(&self, args: &[&str]) -> Result<Vec<u8>, String> {
        match args {
            ["config", "export", ..] => Ok(exported_config()),
            ["ready", ..] => fixture("ready.json"),
            ["status", "ci", ..] => fixture("status-ci.json"),
            ["inventory", "--env", "local", "--json"] => fixture("inventory-local.json"),
            other => Err(format!("no fixture for {other:?}")),
        }
    }
}

/// [`Fixtures`], except that the command starting with `command` prints `stdout`.
pub(crate) struct Replacing {
    pub command: &'static str,
    pub stdout: &'static str,
}

impl Source for Replacing {
    fn stdout(&self, args: &[&str]) -> Result<Vec<u8>, String> {
        if args.first() == Some(&self.command) {
            return Ok(self.stdout.as_bytes().to_vec());
        }
        Fixtures.stdout(args)
    }
}

/// `opv ready --json` when op is signed out: the failure document, with its steps.
pub(crate) const READY_FAILED: &str = r#"{"schema_version":2,"ok":false,"exit_code":7,"next":"opv login","do":null,"error":{"code":"op_not_signed_in","category":"auth","message":"1Password CLI is not signed in","retry":"after_fix","human_required":true,"do":null,"next":"opv login"}}"#;

fn snap() -> Snapshot {
    Snapshot::gather(&Fixtures)
}

fn ready_failed() -> Snapshot {
    Snapshot::gather(&Replacing {
        command: "ready",
        stdout: READY_FAILED,
    })
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
    assert!(!snap().env("local").unwrap().deployed());
}

#[test]
fn a_deployed_environment_names_its_provider() {
    assert_eq!(snap().env("ci").unwrap().place(), "GitHub");
}

#[test]
fn a_target_under_environments_targets_is_read() {
    // 07.01: 0.7+ keeps a provider section under `environments.<env>.targets.<name>`.
    let names: Vec<String> = snap()
        .env("ci")
        .unwrap()
        .targets
        .iter()
        .map(|t| t.name.clone())
        .collect();
    assert_eq!(names, ["app"]);
}

#[test]
fn an_environment_with_several_targets_counts_them() {
    let env = EnvView {
        key: "prod".into(),
        title: "prod".into(),
        targets: vec![
            TargetView {
                name: "api".into(),
                provider: "Fly".into(),
            },
            TargetView {
                name: "ci".into(),
                provider: "GitHub".into(),
            },
        ],
        audience: None,
        guarded: false,
    };
    assert_eq!(env.place(), "2 targets");
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
fn a_cell_reads_the_rows_target_state() {
    let s = snap();
    assert_eq!(
        s.cells[&("ci".into(), "api".into(), "API_TOKEN".into())]
            .target
            .as_deref(),
        Some("absent")
    );
}

/// A run-only environment has no target to read: its cells come from `opv inventory`.
#[test]
fn a_run_only_environment_reads_its_cells_from_the_inventory() {
    let s = snap();
    assert_eq!(
        s.cells[&("local".into(), "api".into(), "OPENAI_API_KEY".into())].state,
        "missing"
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

#[test]
fn a_failed_ready_is_a_problem() {
    // 07.02: `{ok: false, error}` is an error, never an empty receipt.
    assert_eq!(ready_failed().problems.len(), 1);
}

#[test]
fn a_failed_ready_shows_its_next_step() {
    let lines = ready_failed().problems[0].lines();
    assert!(
        lines.contains(&"  Next: opv login".to_string()),
        "{lines:?}"
    );
}

#[test]
fn a_failed_ready_shows_its_message() {
    let lines = ready_failed().problems[0].lines();
    assert_eq!(
        lines[0],
        "could not read readiness (opv ready): 1Password CLI is not signed in"
    );
}

#[test]
fn a_failed_configuration_is_a_problem() {
    let s = Snapshot::gather(&Replacing {
        command: "config",
        stdout: READY_FAILED,
    });
    assert_eq!(s.problems[0].what, "the configuration");
}

#[test]
fn several_targets_show_the_most_notable_state() {
    let mut s = Snapshot::default();
    let doc = |state: &str| -> RowsDoc {
        serde_json::from_value(serde_json::json!({
            "rows": [{"target": "t", "product": "p", "key": "K", "state": "saved",
                      "rule": null, "target_state": state}],
            "totals": {"findings": 0}
        }))
        .unwrap()
    };
    s.read_rows("prod", doc("absent"));
    s.read_rows("prod", doc("present"));
    assert_eq!(
        s.cells[&("prod".into(), "p".into(), "K".into())]
            .target
            .as_deref(),
        Some("absent")
    );
}
