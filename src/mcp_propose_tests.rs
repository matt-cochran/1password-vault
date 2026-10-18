//! The MCP tools of row `mcp-propose` (design §25.2): `opv_propose`, `opv_import_local`
//! and `opv_explain`, and the five tools `tools/list` advertises. One behaviour per test, each with one assertion. Every `op` reply comes
//! from the shared fake (`FakeOp`); no tool output is invented.
//!
//! Parity: each tool's answer, success or failure, equals the `--json` document the CLI
//! library produces for the same input, framed as `opv <command> --json` frames it.

use std::cell::Cell;
use std::path::{Path, PathBuf};

use super::*;
use crate::adapters::fake_op::FakeOp;
use crate::config::bindings::write_split;

/// The dev item's vault (one the fake knows).
const DEV_VAULT: &str = "vdev0000000000000000000001";

/// The prod item's vault (the fake's shared one).
const SHARED_VAULT: &str = "vshr0000000000000000000002";

/// The project's 1Password account.
const ACCOUNT: &str = "ACCOUNTAAA000000000000AAAA";

/// Every value the worlds hold carries this marker; no answer may.
const MARKER: &str = "S7MARKER";

/// A `local` dev environment and a `shared` prod one, one product `app` with a secret and a
/// config key, on the fake's dev vault. `ITEM` is the dev item id.
const CONTRACT: &str = r#"[environments.dev]
tier = "local"
boundaries.app = { vault_id = "vdev0000000000000000000001", item_id = "ITEM" }

[environments.prod]
tier = "shared"
boundaries.app = { vault_id = "vshr0000000000000000000002", item_id = "PROD" }

[products.app.keys.API_KEY]
kind = "secret"
environments = ["dev", "prod"]

[products.app.keys.LOG_LEVEL]
kind = "config"
environments = ["dev", "prod"]
"#;

/// An environment's `app` item, both fields empty.
fn app_item(env: &str) -> Value {
    json!({
        "title": format!("myapp · {env} values"), "category": "SECURE_NOTE",
        "sections": [{"id": "app", "label": "app"}],
        "fields": [
            {"id": "f1", "section": {"id": "app", "label": "app"}, "type": "CONCEALED", "label": "API_KEY", "value": ""},
            {"id": "f2", "section": {"id": "app", "label": "app"}, "type": "STRING", "label": "LOG_LEVEL", "value": ""}
        ]
    })
}

/// `FakeOp`, counting every write that reaches it (a create is a write).
struct Counting {
    op: FakeOp,
    writes: Cell<usize>,
}

impl CommandRunner for Counting {
    fn read(&self, call: &Call, refused: &[i32]) -> io::Result<Outcome> {
        self.op.read(call, refused)
    }
    fn write(&self, call: &Call) -> io::Result<Outcome> {
        self.writes.set(self.writes.get() + 1);
        self.op.write(call)
    }
    fn probe(&self, call: &Call, limit: Duration) -> io::Result<Output> {
        self.op.probe(call, limit)
    }
    fn pause(&self, d: Duration, note: &str) {
        self.op.pause(d, note);
    }
    fn note(&self, line: &str) {
        self.op.note(line);
    }
    fn run_inherited(&self, program: &str, args: &[&str], env: &[(&str, &str)]) -> io::Result<i32> {
        self.op.run_inherited(program, args, env)
    }
}

impl Accounted for Counting {
    fn select_account(&self, _: Option<String>) {}
}

/// A checkout holding [`CONTRACT`] (its ids in `secrets.bindings.toml`), a `.env` of marked
/// values, and the fake's dev and prod items with both fields empty.
struct World {
    dir: tempfile::TempDir,
    r: Counting,
    item: String,
}

impl World {
    fn new() -> Self {
        let op = FakeOp::default();
        let item = op.insert(DEV_VAULT, app_item("dev"));
        let prod = op.insert(SHARED_VAULT, app_item("prod"));
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
        let env_file = dir.path().join("dev.env");
        std::fs::write(
            &env_file,
            format!("API_KEY={MARKER}-api-key\nLOG_LEVEL={MARKER}-info\n"),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&env_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        Self {
            dir,
            r: Counting {
                op,
                writes: Cell::new(0),
            },
            item,
        }
    }

    fn project(&self) -> &Path {
        self.dir.path()
    }

    fn contract(&self) -> PathBuf {
        self.project().join("secrets.toml")
    }

    fn propose(&self, args: Value) -> Value {
        propose_doc(self.project(), &self.r, &object(args))
    }

    fn import(&self, env: &str) -> Value {
        let args = ImportLocalScope {
            env: env.into(),
            file: "dev.env".into(),
        };
        import_local_doc(self.project(), &self.r, &args, std::iter::empty())
    }

    fn explain(&self, key: &str, env: &str) -> Value {
        let args = ExplainScope {
            key: Some(key.into()),
            env: Some(env.into()),
            ..ExplainScope::default()
        };
        explain_doc(self.project(), &self.r, &args)
    }

    /// The fleet the project loads to.
    fn fleet(&self) -> crate::domain::Fleet {
        load_fleet(self.project(), &self.r).unwrap()
    }
}

fn object(v: Value) -> rmcp::model::JsonObject {
    match v {
        Value::Object(m) => m,
        _ => panic!("an object"),
    }
}

/// `body`, a library document, framed as the CLI frames a successful `--json` document.
fn cli_json(body: &[u8]) -> Value {
    serde_json::from_slice(&crate::json::finish(body, Ok(()), false)).unwrap()
}

/// What `opv <words> --json` prints when it fails with `e`: the whole frame.
fn cli_failure(words: &[&str], e: &Error) -> Value {
    let argv: Vec<String> = std::iter::once("opv")
        .chain(words.iter().copied())
        .chain(std::iter::once("--json"))
        .map(str::to_string)
        .collect();
    serde_json::from_slice(&crate::json::finish_with(
        &[],
        Err(e),
        false,
        &Invocation::from_cli(&argv),
        false,
    ))
    .unwrap()
}

/// `doc` with the person's `--write` step as its `next`.
fn with_write_next(doc: &[u8], command: &str) -> Vec<u8> {
    let mut v: Value = serde_json::from_slice(doc).unwrap();
    v["next"] = json!({"kind": "apply", "actor": "person", "command": command});
    serde_json::to_vec(&v).unwrap()
}

fn as_json<T: serde::Serialize>(doc: &T) -> Vec<u8> {
    serde_json::to_vec(doc).unwrap()
}

/// A contract or setup proposal as `opv propose --json` prints it without `--write`.
fn unwritten<T: serde::Serialize>(doc: &T) -> Vec<u8> {
    let mut v = serde_json::to_value(doc).unwrap();
    v["written"] = Value::Null;
    serde_json::to_vec(&v).unwrap()
}

const KEY_INTENT: &str = r#"{"kind":"key","key":"NEW_KEY","product":"app","field_kind":"secret"}"#;

// opv_propose ------------------------------------------------------------------------------

#[test]
fn opv_propose_key_equals_the_librarys_proposal() {
    let w = World::new();
    let intent = crate::domain::intent::parse(KEY_INTENT).unwrap();
    let text = std::fs::read_to_string(w.contract()).unwrap();
    let ids = crate::config::bindings::read_sibling(&w.contract()).unwrap();
    let want = crate::app::propose::key::propose(&text, &ids, None, &intent).unwrap();
    assert_eq!(
        w.propose(serde_json::from_str(KEY_INTENT).unwrap()),
        cli_json(&with_write_next(
            &unwritten(&want),
            "opv propose key app/NEW_KEY --kind secret --write"
        ))
    );
}

#[test]
fn opv_propose_structure_equals_the_librarys_proposal() {
    let w = World::new();
    let scope = crate::app::structure::scope_as(w.project(), &w.r, "propose structure").unwrap();
    let want = crate::app::propose::structure::propose_structure_at(
        &w.r,
        &scope.config,
        &scope.project,
        &scope.account,
        &[],
        &[],
    )
    .unwrap();
    let mut doc = serde_json::to_value(&want).unwrap();
    doc["next"] = json!({"kind": "apply", "actor": "person",
                         "command": format!("opv apply {}", want.plan_id)});
    assert_eq!(
        w.propose(json!({"kind": "structure"})),
        cli_json(&as_json(&doc))
    );
}

#[test]
fn opv_propose_setup_from_names_equals_the_librarys_proposal() {
    let w = World::new();
    let want = crate::app::propose::setup::from_names(
        &w.project().join("dev.env"),
        crate::app::propose::setup::NAMES_ENV,
        &[],
        &[],
    )
    .unwrap();
    assert_eq!(
        w.propose(json!({"kind": "setup", "names_from": "dev.env"})),
        cli_json(&with_write_next(
            &unwritten(&want),
            "opv propose setup --names-from dev.env --write"
        ))
    );
}

#[test]
fn opv_propose_retire_of_an_undeclared_key_is_the_clis_own_failure() {
    let w = World::new();
    let intent = json!({"kind": "retire", "key": "NOPE", "product": "app"});
    let parsed = crate::domain::intent::parse(&intent.to_string()).unwrap();
    let text = std::fs::read_to_string(w.contract()).unwrap();
    let ids = crate::config::bindings::read_sibling(&w.contract()).unwrap();
    let err = crate::app::propose::key::propose(&text, &ids, None, &parsed)
        .map_err(proposal_refused)
        .unwrap_err();
    assert_eq!(
        w.propose(intent),
        cli_failure(&["propose", "retire", "app/NOPE"], &err)
    );
}

// The person's step after a contract proposal -----------------------------------------------

#[test]
fn opv_propose_key_next_is_the_persons_write() {
    let w = World::new();
    let doc = w.propose(json!({"kind": "key", "key": "NEW_KEY", "product": "app",
        "field_kind": "config", "immutable": true,
        "except": {"prod": "not used there"}, "guidance": "from the team lead"}));
    assert_eq!(
        doc["next"],
        json!({"kind": "apply", "actor": "person", "command":
            "opv propose key app/NEW_KEY --kind config \
             --except 'prod=not used there' --guidance 'from the team lead' --immutable --write"}),
        "{doc}"
    );
}

#[test]
fn opv_propose_env_next_is_the_persons_write() {
    let w = World::new();
    let doc = w.propose(json!({"kind": "env", "env": "staging", "tier": "shared"}));
    assert_eq!(
        doc["next"],
        json!({"kind": "apply", "actor": "person",
               "command": "opv propose env staging --tier shared --write"})
    );
}

#[test]
fn opv_propose_target_next_is_the_persons_write() {
    let w = World::new();
    let doc = w.propose(json!({"kind": "target", "env": "prod", "name": "web",
        "provider": "fly", "options": {"fly-app": "myapp-prod"}}));
    assert_eq!(
        doc["next"],
        json!({"kind": "apply", "actor": "person", "command":
            "opv propose target prod web --provider fly --fly-app myapp-prod --write"})
    );
}

#[test]
fn opv_propose_retire_next_is_the_persons_write() {
    let w = World::new();
    let doc = w.propose(json!({"kind": "retire", "key": "LOG_LEVEL", "product": "app"}));
    assert_eq!(
        doc["next"],
        json!({"kind": "apply", "actor": "person",
               "command": "opv propose retire app/LOG_LEVEL --write"})
    );
}

#[test]
fn opv_propose_a_document_the_cli_cannot_say_is_written_from_the_intent() {
    let w = World::new();
    let doc = w.propose(
        json!({"kind": "retire", "key": "LOG_LEVEL", "product": "app",
                               "guidance": "replaced by RUST_LOG"}),
    );
    assert_eq!(
        doc["next"]["command"],
        "opv propose --intent <intent.json> --write"
    );
}

#[test]
fn opv_propose_key_records_no_op_write() {
    let w = World::new();
    let _ = w.propose(serde_json::from_str(KEY_INTENT).unwrap());
    assert_eq!(w.r.writes.get(), 0);
}

#[test]
fn opv_propose_structure_records_no_op_write() {
    let w = World::new();
    let _ = w.propose(json!({"kind": "structure"}));
    assert_eq!(w.r.writes.get(), 0);
}

#[test]
fn opv_propose_key_leaves_the_contract_file_as_it_was() {
    let w = World::new();
    let before = std::fs::read_to_string(w.contract()).unwrap();
    let _ = w.propose(serde_json::from_str(KEY_INTENT).unwrap());
    assert_eq!(std::fs::read_to_string(w.contract()).unwrap(), before);
}

#[test]
fn opv_propose_with_a_regex_is_refused_naming_the_field() {
    let w = World::new();
    let doc = w.propose(json!({"kind": "key", "key": "NEW_KEY", "regex": "^sk_"}));
    assert_eq!(doc["error"]["subject"]["field"], json!(["regex"]));
}

#[test]
fn opv_propose_tidy_is_a_usage_error_naming_that_it_is_not_available() {
    let w = World::new();
    let doc = w.propose(json!({"kind": "tidy", "env": "dev"}));
    assert!(
        doc["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("tidy is not available")),
        "{doc}"
    );
}

#[test]
fn opv_propose_answers_no_marked_value() {
    let w = World::new();
    let doc = w.propose(json!({"kind": "setup", "names_from": "dev.env"}));
    assert!(!doc.to_string().contains(MARKER), "{doc}");
}

// opv_import_local --------------------------------------------------------------------------

#[test]
fn opv_import_local_equals_the_librarys_import() {
    let mcp = World::new();
    let cli = World::new();
    let mut out = Vec::new();
    crate::app::import_local::import_local_json(
        &cli.fleet(),
        "dev",
        &cli.project().join("dev.env"),
        &cli.r,
        &mut out,
    )
    .unwrap();
    assert_eq!(mcp.import("dev"), cli_json(&out));
}

#[test]
fn opv_import_local_into_a_shared_environment_is_the_clis_own_failure() {
    let mcp = World::new();
    let cli = World::new();
    let err = crate::app::import_local::import_local_json(
        &cli.fleet(),
        "prod",
        &cli.project().join("dev.env"),
        &cli.r,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(
        mcp.import("prod"),
        cli_failure(&["import", "prod", "--from", "dev.env"], &err)
    );
}

#[test]
fn opv_import_local_writes_the_local_environments_empty_field() {
    let w = World::new();
    let _ = w.import("dev");
    let item = w.r.op.item(&w.item);
    let value = item["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["label"] == "API_KEY")
        .and_then(|f| f["value"].as_str())
        .map(str::to_string);
    assert_eq!(value.as_deref(), Some("S7MARKER-api-key"));
}

#[test]
fn opv_import_local_into_a_shared_environment_is_import_tier_refused() {
    let w = World::new();
    assert_eq!(w.import("prod")["error"]["code"], "import_tier_refused");
}

#[test]
fn opv_import_local_into_a_shared_environment_writes_nothing() {
    let w = World::new();
    let _ = w.import("prod");
    assert_eq!(w.r.writes.get(), 0);
}

#[test]
fn opv_import_local_answers_no_marked_value() {
    let w = World::new();
    let doc = w.import("dev");
    assert!(!doc.to_string().contains(MARKER), "{doc}");
}

// opv_explain -------------------------------------------------------------------------------

#[test]
fn opv_explain_equals_the_librarys_explanation() {
    let w = World::new();
    let mut out = Vec::new();
    crate::app::explain::run_request_with(
        &w.r,
        &w.fleet(),
        &crate::app::explain::Asked::Key("app/API_KEY"),
        Some("dev"),
        &crate::app::personal::project_name(&w.r, w.project()),
        &mut out,
        true,
    )
    .unwrap();
    assert_eq!(w.explain("app/API_KEY", "dev"), cli_json(&out));
}

#[test]
fn opv_explain_of_an_undeclared_key_is_the_clis_own_failure() {
    let w = World::new();
    let err = crate::app::explain::run_request_with(
        &w.r,
        &w.fleet(),
        &crate::app::explain::Asked::Key("app/NOPE"),
        Some("dev"),
        &crate::app::personal::project_name(&w.r, w.project()),
        &mut Vec::new(),
        true,
    )
    .unwrap_err();
    assert_eq!(
        w.explain("app/NOPE", "dev"),
        cli_failure(&["explain", "app/NOPE", "--env", "dev"], &err)
    );
}

#[test]
fn opv_explain_of_a_name_that_is_not_a_key_is_usage() {
    let w = World::new();
    assert_eq!(w.explain("api key", "dev")["error"]["code"], "usage");
}

#[test]
fn opv_explain_answers_no_marked_value() {
    let w = World::new();
    let _ = w.import("dev");
    let doc = w.explain("app/API_KEY", "dev");
    assert!(!doc.to_string().contains(MARKER), "{doc}");
}

// The tool list -----------------------------------------------------------------------------

#[test]
fn the_removed_write_tools_are_not_listed() {
    let listed: Vec<String> = Server::tool_router()
        .list_all()
        .into_iter()
        .map(|t| t.name.to_string())
        .filter(|n| {
            [
                "opv_declare_key",
                "opv_declare_environment",
                "opv_declare_target",
                "opv_generate",
            ]
            .contains(&n.as_str())
        })
        .collect();
    assert_eq!(listed, Vec::<String>::new());
}

#[test]
fn opv_propose_advertises_exactly_the_intent_schema() {
    let tool = Server::tool_router()
        .list_all()
        .into_iter()
        .find(|t| t.name == "opv_propose")
        .unwrap();
    assert_eq!(
        Value::Object(tool.input_schema.as_ref().clone()),
        crate::domain::intent::json_schema()
    );
}

/// The §25 surface golden's tools: name to input schema.
fn golden_tools() -> std::collections::BTreeMap<String, Value> {
    let golden: Value =
        serde_json::from_str(include_str!("../tests/e2e/expected/surface.json")).unwrap();
    golden["mcp"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| {
            (
                t["name"].as_str().unwrap().to_string(),
                t["input_schema"].clone(),
            )
        })
        .collect()
}

#[test]
fn tools_list_equals_the_golden_names_and_input_schemas() {
    let listed: std::collections::BTreeMap<String, Value> = Server::tool_router()
        .list_all()
        .into_iter()
        .map(|t| {
            (
                t.name.to_string(),
                Value::Object(t.input_schema.as_ref().clone()),
            )
        })
        .collect();
    assert_eq!(listed, golden_tools());
}

#[test]
fn only_opv_import_local_is_not_read_only() {
    let writers: Vec<String> = Server::tool_router()
        .list_all()
        .into_iter()
        .filter(|t| {
            t.annotations
                .as_ref()
                .and_then(|a| a.read_only_hint)
                .is_none_or(|ro| !ro)
        })
        .map(|t| t.name.to_string())
        .collect();
    assert_eq!(writers, vec!["opv_import_local".to_string()]);
}

#[test]
fn no_tool_is_destructive() {
    let destructive: Vec<String> = Server::tool_router()
        .list_all()
        .into_iter()
        .filter(|t| {
            t.annotations
                .as_ref()
                .and_then(|a| a.destructive_hint)
                .is_none_or(|d| d)
        })
        .map(|t| t.name.to_string())
        .collect();
    assert_eq!(destructive, Vec::<String>::new());
}
