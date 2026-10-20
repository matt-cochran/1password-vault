//! `opv_state` (design §25.2, row `mcp-state`): one tool whose every section answers the
//! `--json` document of the CLI command of that name. One behaviour per test, each with one
//! assertion. Every `op` reply comes from the shared fake (`FakeOp`); no tool output is
//! invented.
//!
//! Parity: for each section, the tool's answer equals the document the CLI prints for the
//! same world: the library entry point `src/main.rs` calls, with `--json`, framed as the CLI
//! frames it against the CLI's own invocation (`opv <command> <args> --json`).

use std::path::Path;

use super::*;
use crate::adapters::fake_op::FakeOp;
use crate::config::bindings::write_split;

/// The project's 1Password account.
const ACCOUNT: &str = "ACCOUNTAAA000000000000AAAA";

/// Every value the world holds carries this marker; no answer may.
pub(super) const MARKER: &str = "S7MARKER";

/// The clock `ready` records, fixed for both sides.
const NOW: &str = "2026-10-18T12:00:00Z";

/// A `local` dev environment and a `shared` prod one with a Fly target, one product `app`
/// with a secret and a config key. `ITEM` and `PROD` are the item ids.
const CONTRACT: &str = r#"[environments.dev]
tier = "local"
boundaries.app = { vault_id = "vdev0000000000000000000001", item_id = "ITEM" }

[environments.prod]
tier = "shared"
boundaries.app = { vault_id = "vshr0000000000000000000002", item_id = "PROD" }

[environments.prod.targets.web]
fly.app = "myapp-prod"
fly.secret_name = "{KEY}"
products = ["app"]
state_vault_id = "vshr0000000000000000000002"

[products.app.keys.API_KEY]
kind = "secret"
environments = ["dev", "prod"]

[products.app.keys.LOG_LEVEL]
kind = "config"
environments = ["dev", "prod"]
"#;

/// An environment's `app` item, both fields set to marked values.
fn app_item(env: &str) -> Value {
    json!({
        "title": format!("myapp · {env} values"), "category": "SECURE_NOTE",
        "sections": [{"id": "app", "label": "app"}],
        "fields": [
            {"id": "f1", "section": {"id": "app", "label": "app"}, "type": "CONCEALED", "label": "API_KEY", "value": format!("{MARKER}-{env}-api-key")},
            {"id": "f2", "section": {"id": "app", "label": "app"}, "type": "STRING", "label": "LOG_LEVEL", "value": format!("{MARKER}-{env}-info")}
        ]
    })
}

/// `FakeOp` as the tool's runner (its account is the project's).
pub(super) struct Fake(pub(super) FakeOp);

impl CommandRunner for Fake {
    fn read(&self, call: &Call, refused: &[i32]) -> io::Result<Outcome> {
        self.0.read(call, refused)
    }
    fn write(&self, call: &Call) -> io::Result<Outcome> {
        self.0.write(call)
    }
    fn probe(&self, call: &Call, limit: Duration) -> io::Result<Output> {
        self.0.probe(call, limit)
    }
    fn pause(&self, d: Duration, note: &str) {
        self.0.pause(d, note);
    }
    fn note(&self, line: &str) {
        self.0.note(line);
    }
    fn run_inherited(&self, program: &str, args: &[&str], env: &[(&str, &str)]) -> io::Result<i32> {
        self.0.run_inherited(program, args, env)
    }
}

impl Accounted for Fake {
    fn select_account(&self, _: Option<String>) {}
}

/// A checkout holding [`CONTRACT`] (its ids in `secrets.bindings.toml`) and the fake's dev
/// and prod items, both holding marked values. The checkout is no git repository, so
/// `needs` scans the project.
pub(super) struct World {
    dir: tempfile::TempDir,
    pub(super) r: Fake,
}

impl World {
    pub(super) fn new() -> Self {
        let op = FakeOp::default();
        let item = op.insert("vdev0000000000000000000001", app_item("dev"));
        let prod = op.insert("vshr0000000000000000000002", app_item("prod"));
        // The directory names the project (a name may not start with a dot).
        let dir = tempfile::Builder::new().prefix("myapp-").tempdir().unwrap();
        write_split(
            &dir.path().join("secrets.toml"),
            &CONTRACT.replace("ITEM", &item).replace("PROD", &prod),
        )
        .unwrap();
        // The project's account, as a person's `.opv` pointer records it (in the temp
        // checkout only).
        std::fs::write(
            dir.path().join(".opv"),
            format!("account = \"{ACCOUNT}\"\n"),
        )
        .unwrap();
        Self { dir, r: Fake(op) }
    }

    pub(super) fn project(&self) -> &Path {
        self.dir.path()
    }

    /// `opv_state` for `args` (an object of section and scope).
    fn tool(&self, args: Value) -> Value {
        let scope: StateScope = serde_json::from_value(args).unwrap();
        state_doc(self.project(), &self.r, &scope, Some(NOW))
    }

    /// The fleet the project loads to.
    pub(super) fn fleet(&self) -> crate::domain::Fleet {
        load_fleet(self.project(), &self.r).unwrap()
    }

    /// What `opv <words> --json` prints: `run` writes the body (or fails), framed as the CLI
    /// frames it against its own invocation.
    pub(super) fn cli(
        &self,
        words: &[&str],
        run: impl FnOnce(&crate::domain::Fleet, &Fake, &mut Vec<u8>) -> Result<(), Error>,
    ) -> Value {
        let fleet = self.fleet();
        let mut body = Vec::new();
        let res = run(&fleet, &self.r, &mut body);
        let argv: Vec<String> = std::iter::once("opv")
            .chain(words.iter().copied())
            .chain(std::iter::once("--json"))
            .map(str::to_string)
            .collect();
        let inv = Invocation::from_cli(&argv);
        serde_json::from_slice(&crate::json::finish_with(
            &body,
            res.as_ref().map(|_| ()),
            false,
            &inv,
            false,
        ))
        .unwrap()
    }
}

// Parity: each section is the CLI's document -------------------------------------------------

#[test]
fn the_inventory_section_is_opv_inventory_json() {
    let w = World::new();
    let want = w.cli(&["inventory", "--env", "dev"], |f, r, out| {
        crate::app::inventory::run(f, Some("dev"), None, r, None, true, out)
    });
    assert_eq!(w.tool(json!({"section": "inventory", "env": "dev"})), want);
}

#[test]
fn the_needs_section_is_opv_needs_json() {
    let w = World::new();
    let repo = w.project().to_path_buf();
    let want = w.cli(&["needs"], |f, r, out| {
        crate::app::needs::run(r, &repo, f, &Default::default(), false, true, out)
    });
    assert_eq!(w.tool(json!({"section": "needs"})), want);
}

#[test]
fn the_contract_section_is_opv_contract_json() {
    let w = World::new();
    let want = w.cli(
        &["contract", "--env", "prod", "--component", "app"],
        |f, _, out| crate::app::contract::write_document(f, Some("prod"), Some("app"), true, out),
    );
    assert_eq!(
        w.tool(json!({"section": "contract", "env": "prod", "product": "app"})),
        want
    );
}

#[test]
fn the_ready_section_is_opv_ready_json() {
    let w = World::new();
    let want = w.cli(&["ready", "dev"], |f, r, out| {
        crate::app::ready::run_at(f, None, Some("dev"), r, true, None, false, NOW, out)
    });
    assert_eq!(w.tool(json!({"section": "ready", "env": "dev"})), want);
}

#[test]
fn the_plan_section_is_opv_plan_json() {
    let w = World::new();
    let targets = vec!["web".to_string()];
    let want = w.cli(&["plan", "prod", "--target", "web"], |f, r, out| {
        crate::app::sync::plan_rotating(f, "prod", &targets, None, &[], r, out, true)
            .map_err(|e| e.in_env("prod"))
    });
    assert_eq!(
        w.tool(json!({"section": "plan", "env": "prod", "target": "web"})),
        want
    );
}

#[test]
fn the_changed_section_is_opv_changed_json() {
    let w = World::new();
    let want = w.cli(&["changed", "prod", "--product", "app"], |f, r, out| {
        crate::app::changed::run(f, "prod", Some("app"), &[], r, true, out).map(|_| ())
    });
    assert_eq!(
        w.tool(json!({"section": "changed", "env": "prod", "product": "app"})),
        want
    );
}

#[test]
fn the_access_section_is_opv_access_json() {
    let w = World::new();
    let want = w.cli(&["access", "prod"], |f, r, out| {
        crate::app::access::run(f, Some("prod"), None, None, r, true, out)
    });
    assert_eq!(w.tool(json!({"section": "access", "env": "prod"})), want);
}

#[test]
fn the_delivery_preview_section_is_opv_run_preview_json() {
    let w = World::new();
    let fleet = w.fleet();
    let mut out = Vec::new();
    crate::app::delivery_preview::preview_for(
        &fleet, "dev", None, None, None, true, &w.r, &mut out,
    )
    .unwrap();
    // `opv run --preview --json` prints the builder's document as it is (no frame).
    let want: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(
        w.tool(json!({"section": "delivery_preview", "env": "dev"})),
        want
    );
}

#[test]
fn the_history_section_is_opv_history_json() {
    let w = World::new();
    let want = w.cli(&["history", "prod", "--target", "web"], |f, r, out| {
        crate::app::history::run(f, "prod", Some("web"), r, true, out)
    });
    assert_eq!(
        w.tool(json!({"section": "history", "env": "prod", "target": "web"})),
        want
    );
}

#[test]
fn the_status_section_is_opv_status_json() {
    let w = World::new();
    let want = w.cli(&["status", "dev"], |f, r, out| {
        crate::app::status::run_targeted(f, "dev", &[], None, r, out, true, false)
            .map_err(|e| e.in_env("dev"))
    });
    assert_eq!(w.tool(json!({"section": "status", "env": "dev"})), want);
}

#[test]
fn the_status_section_without_env_is_the_overview() {
    let w = World::new();
    let want = w.cli(&["status"], |f, r, out| {
        crate::app::status::overview(f, None, r, out, true)
    });
    assert_eq!(w.tool(json!({"section": "status"})), want);
}

#[test]
fn an_undeclared_environment_is_the_clis_own_error() {
    let w = World::new();
    let want = w.cli(&["plan", "prdo"], |f, r, out| {
        crate::app::sync::plan_rotating(f, "prdo", &[], None, &[], r, out, true)
            .map_err(|e| e.in_env("prdo"))
    });
    assert_eq!(w.tool(json!({"section": "plan", "env": "prdo"})), want);
}

#[test]
fn a_missing_configuration_is_the_clis_own_error() {
    let dir = tempfile::Builder::new().prefix("myapp-").tempdir().unwrap();
    let r = Fake(FakeOp::default());
    let err = load_fleet(dir.path(), &r).unwrap_err();
    let argv = ["opv", "contract", "--json"].map(str::to_string);
    let want: Value = serde_json::from_slice(&crate::json::finish_with(
        &[],
        Err(&err),
        false,
        &Invocation::from_cli(&argv),
        false,
    ))
    .unwrap();
    let scope: StateScope = serde_json::from_value(json!({"section": "contract"})).unwrap();
    assert_eq!(state_doc(dir.path(), &r, &scope, Some(NOW)), want);
}

// Refusals ------------------------------------------------------------------------------------

#[test]
fn an_unknown_section_is_refused_as_usage() {
    let w = World::new();
    assert_eq!(
        w.tool(json!({"section": "configuration"}))["error"]["code"],
        "usage"
    );
}

#[test]
fn an_unknown_section_reads_nothing() {
    let w = World::new();
    w.tool(json!({"section": "deployment_plan"}));
    assert!(w.r.0.calls.borrow().is_empty());
}

#[test]
fn a_section_that_needs_env_is_refused_without_it() {
    let w = World::new();
    assert_eq!(w.tool(json!({"section": "plan"}))["error"]["code"], "usage");
}

#[test]
fn a_scope_the_section_does_not_take_is_refused() {
    let w = World::new();
    assert_eq!(
        w.tool(json!({"section": "needs", "env": "dev"}))["error"]["code"],
        "usage"
    );
}

#[test]
fn a_scope_that_is_not_a_name_is_refused() {
    let w = World::new();
    assert_eq!(
        w.tool(json!({"section": "ready", "env": "../etc"}))["error"]["code"],
        "usage"
    );
}

#[test]
fn a_target_without_env_is_refused() {
    let w = World::new();
    assert_eq!(
        w.tool(json!({"section": "access", "target": "web"}))["error"]["code"],
        "usage"
    );
}

#[test]
fn an_unknown_field_is_not_an_input() {
    let parsed = serde_json::from_value::<StateScope>(json!({"section": "ready", "verbose": true}));
    assert!(parsed.is_err());
}

// The canary: no section answers a value ------------------------------------------------------

/// One canary test per section, with the widest scope the section takes in the world: the
/// answer holds no part of any value the fake's items carry.
macro_rules! canary {
    ($($name:ident: $args:tt,)*) => {$(
        #[test]
        fn $name() {
            let w = World::new();
            assert!(!w.tool(json!($args)).to_string().contains(MARKER));
        }
    )*};
}

canary! {
    the_inventory_section_answers_no_value: {"section": "inventory"},
    the_needs_section_answers_no_value: {"section": "needs"},
    the_contract_section_answers_no_value: {"section": "contract"},
    the_ready_section_answers_no_value: {"section": "ready"},
    the_plan_section_answers_no_value: {"section": "plan", "env": "prod"},
    the_changed_section_answers_no_value: {"section": "changed", "env": "prod"},
    the_access_section_answers_no_value: {"section": "access"},
    the_delivery_preview_section_answers_no_value: {"section": "delivery_preview", "env": "dev"},
    the_history_section_answers_no_value: {"section": "history", "env": "prod"},
    the_status_overview_answers_no_value: {"section": "status"},
    the_status_section_answers_no_value: {"section": "status", "env": "dev"},
}

// The surface ---------------------------------------------------------------------------------

/// The registered tool names.
fn tool_names() -> Vec<String> {
    Server::tool_router()
        .list_all()
        .into_iter()
        .map(|t| t.name.to_string())
        .collect()
}

#[test]
fn the_six_read_tools_and_the_structure_plan_are_gone() {
    let removed = [
        "opv_ready",
        "opv_configuration",
        "opv_deployment_plan",
        "opv_changed",
        "opv_access",
        "opv_delivery_preview",
        "opv_structure_plan",
    ];
    let names = tool_names();
    assert!(
        !removed.iter().any(|r| names.iter().any(|n| n == r)),
        "{names:?}"
    );
}

#[test]
fn opv_state_advertises_the_golden_input_schema() {
    let golden: Value =
        serde_json::from_str(include_str!("../tests/e2e/expected/surface.json")).unwrap();
    let want = golden["mcp"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "opv_state")
        .map(|t| t["input_schema"].clone())
        .unwrap();
    let tool = Server::tool_router()
        .list_all()
        .into_iter()
        .find(|t| t.name == "opv_state")
        .unwrap();
    assert_eq!(Value::Object((*tool.input_schema).clone()), want);
}
