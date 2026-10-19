//! MCP tools (design §25.2). Five tools: `opv_state` and `opv_next` read, `opv_propose` and
//! `opv_explain` prepare and explain, and `opv_import_local` writes the local vault only. The reading
//! tools run on a runner that refuses every write beneath the application code.
//!
//! Every answer is the `--json` document of the CLI command the call is (D-G: one
//! interface): `opv_state` with `section` `ready` answers exactly what `opv ready --json`
//! prints, and so on for each section ([`state_doc`]). A failure, for every tool, is that
//! document's whole frame (`schema_version`, `ok: false`, `exit_code`, `next`, `do`,
//! `error`), exactly as `opv <command> --json` prints it, where `error` is the catalog's error
//! object (design
//! `docs/design/error-catalog.md` §7.2): code, category, message, subject, evidence (the
//! upstream reply marked `untrusted: true`), retry, human_required, do, and the typed next
//! `{kind, actor, command}`, rendered against the tool's own invocation ([`ToolCall`]). The
//! server is agent mode ([`crate::host::mark_mcp`]), so each library filters as it does for
//! an assistant on the CLI.
use crate::{
    app::agent_view::identifier,
    cause::{Cause, Cmd, CommandId, Invocation, Origin, Principal, UsageProblem, VarName, render},
    config_store,
    error::Error,
    runner::{Budget, Call, CommandRunner, Outcome, Output, ProcessRunner},
};
use rmcp::{handler::server::wrapper::Parameters, tool, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    io,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

#[derive(Clone)]
pub struct Server {
    project: PathBuf,
    gate: Arc<tokio::sync::Mutex<()>>,
}

/// `opv_import_local`'s input (design §25.2): a `local`-tier environment and a file.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportLocalScope {
    /// A declared environment whose tier is `local`.
    env: String,
    /// The `.env` file to import, relative to the project (or absolute).
    file: String,
}

/// `opv_explain`'s input (design §25.2): a key or a run plan id, and the environment.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ExplainScope {
    /// `[product/]KEY`.
    #[serde(default)]
    key: Option<String>,
    /// The run plan id `opv plan` prints.
    #[serde(default)]
    plan_id: Option<String>,
    /// The environment, as the CLI's `--env`.
    #[serde(default)]
    env: Option<String>,
}

/// `opv_next`'s input (design §25.2): the environment to scope to, as `opv next --env`.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NextScope {
    /// A declared environment.
    #[serde(default)]
    env: Option<String>,
}

/// `opv_state`'s input (design §25.2): a section and its optional scope. `section` is read
/// as text so an unknown one is refused in the answer, naming the sections.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct StateScope {
    /// One of [`SECTIONS`].
    #[serde(default)]
    section: String,
    /// The environment, as the section's command takes it.
    #[serde(default)]
    env: Option<String>,
    /// The product (`--product`; `opv contract`'s `--component`).
    #[serde(default)]
    product: Option<String>,
    /// The target (`--target`).
    #[serde(default)]
    target: Option<String>,
}

/// The name grammar of an environment (the intent document's).
const ENV_PATTERN: &str = "^[a-z][a-z0-9-]*$";

/// The grammar of a key reference, `[product/]KEY`.
const KEY_REF_PATTERN: &str = "^([a-z][a-z0-9-]*/)?[A-Z][A-Z0-9_]*$";

/// A JSON Schema object for a tool's input.
fn schema_object(schema: Value) -> Arc<rmcp::model::JsonObject> {
    match schema {
        Value::Object(map) => Arc::new(map),
        _ => Arc::new(rmcp::model::JsonObject::new()),
    }
}

/// `opv_propose`'s input schema: exactly the intent document's (design §25.2).
fn propose_schema() -> Arc<rmcp::model::JsonObject> {
    schema_object(crate::domain::intent::json_schema())
}

/// `opv_import_local`'s input schema (the §25 surface golden).
fn import_local_schema() -> Arc<rmcp::model::JsonObject> {
    schema_object(json!({
        "type": "object",
        "properties": {
            "env": { "type": "string", "pattern": ENV_PATTERN },
            "file": { "type": "string" }
        },
        "required": ["env", "file"],
        "additionalProperties": false
    }))
}

/// `opv_explain`'s input schema (the §25 surface golden): a key or a plan id, and the
/// optional `env` the CLI's `--env` is (a key declared in several environments, and every
/// plan id, need it).
fn explain_schema() -> Arc<rmcp::model::JsonObject> {
    schema_object(json!({
        "type": "object",
        "properties": {
            "key": { "type": "string", "pattern": KEY_REF_PATTERN },
            "plan_id": { "type": "string" },
            "env": { "type": "string", "pattern": ENV_PATTERN }
        },
        "oneOf": [{ "required": ["key"] }, { "required": ["plan_id"] }],
        "additionalProperties": false
    }))
}

/// `opv_next`'s input schema (the §25 surface golden).
fn next_schema() -> Arc<rmcp::model::JsonObject> {
    schema_object(json!({
        "type": "object",
        "properties": {
            "env": { "type": "string", "pattern": ENV_PATTERN }
        },
        "required": [],
        "additionalProperties": false
    }))
}

/// `opv_state`'s input schema (the §25 surface golden).
fn state_schema() -> Arc<rmcp::model::JsonObject> {
    schema_object(json!({
        "type": "object",
        "properties": {
            "section": { "enum": SECTIONS.map(|(name, _)| name) },
            "env": { "type": "string", "pattern": ENV_PATTERN },
            "product": { "type": "string", "pattern": ENV_PATTERN },
            "target": { "type": "string", "pattern": ENV_PATTERN }
        },
        "required": ["section"],
        "additionalProperties": false
    }))
}

/// One tool call as the catalog renders its failures (design §2.4, §6.1): the CLI command
/// that does the same work with every checked name filled in, run with `--json`. MCP is the
/// `--json` document (owner decision): its `error` is the one `opv <command> <args> --json`
/// prints, steps and re-runs included.
pub(crate) struct ToolCall {
    inv: Invocation,
    verbose: bool,
}

impl ToolCall {
    /// `tool`'s call, rendered as `opv <command> <args> --json`. `args` hold checked names
    /// only. The tool's name stays out of the document: the CLI's has none either.
    fn new(_tool: &str, command: &[&str], mut args: Vec<String>, verbose: bool) -> Self {
        if verbose {
            args.push("--verbose".into());
        }
        args.push("--json".into());
        Self {
            inv: Invocation {
                origin: Origin::Cli,
                command: command.iter().map(|w| w.to_string()).collect(),
                args,
                has_child: false,
            },
            verbose,
        }
    }

    /// The failure answer for `e`: the whole `--json` frame the CLI prints for it
    /// (`schema_version`, `ok: false`, `exit_code`, `next`, `do`, `error`).
    fn failed(&self, e: &Error) -> Value {
        let framed = crate::json::finish_with(&[], Err(e), false, &self.inv, self.verbose);
        serde_json::from_slice(&framed).unwrap_or_else(
            |_| json!({"ok": false, "error": error_document(e, &self.inv, self.verbose)}),
        )
    }

    /// The failure answer for a cause the tool itself found.
    fn refused(&self, cause: Cause) -> Value {
        self.failed(&cause.into())
    }

    /// The `--json` document of the CLI command this call is, for a command that wrote
    /// `body` and ended with `res`: framed exactly as `opv <command> --json` frames it
    /// ([`crate::json::finish_with`]), so a tool's answer is the CLI's document.
    fn document(&self, body: &[u8], res: Result<(), Error>) -> Value {
        let framed = crate::json::finish_with(
            body,
            res.as_ref().map(|_| ()),
            false,
            &self.inv,
            self.verbose,
        );
        serde_json::from_slice(&framed).unwrap_or_else(|_| self.refused(UNREADABLE_REPORT))
    }
}

/// The `error` object for `e` against `inv`: the catalog document (design §7.2), the same
/// one `--json` prints, with no separate hint table.
fn error_document(e: &Error, inv: &Invocation, verbose: bool) -> Value {
    crate::error::document(e, inv, verbose)
}

/// What a name argument must be, in the refusal's message.
const NAME_FORMAT: &str = "a declared name: letters, digits, '.', '_', '/' and '-' (opv_state section inventory lists them)";

/// The refusal of a name argument that is not one ([`identifier`]). The given text is never
/// repeated: it may be anything.
fn not_a_name(field: &str) -> Cause {
    usage(field, NAME_FORMAT)
}

fn usage(field: &str, format: &'static str) -> Cause {
    Cause::Usage {
        problem: UsageProblem::ValueFormat {
            flag: field.to_string(),
            format,
        },
    }
}

/// A 1Password write refused because `var` (an op session, service-account or Connect
/// credential) is set in the server's environment: the person runs `command` themselves.
fn own_session(command: &str, var: String) -> Cause {
    Cause::NeedsOwnSession {
        command: CommandId(command.to_string()),
        identity: Principal::ShellToken {
            var: VarName::new(var),
        },
    }
}

impl Server {
    /// The server for `project`. The MCP server is agent mode (design §25): every tool
    /// answers as to an assistant.
    pub fn new(project: PathBuf) -> Self {
        crate::host::mark_mcp();
        Self {
            project,
            gate: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// Run `f` on the project, one tool call at a time, off the async runtime. The
    /// redaction registry lives for the call: cleared before it, the answer passed through
    /// the output guard while it holds the call's values, and cleared after it. `writes`
    /// says whether the tool can change anything, for the answer when `f` never returns.
    async fn serialized(
        &self,
        tool: &'static str,
        writes: bool,
        verbose: bool,
        f: impl FnOnce(&std::path::Path) -> Value + Send + 'static,
    ) -> String {
        let guard = self.gate.clone().lock_owned().await;
        let project = self.project.clone();
        tokio::task::spawn_blocking(move || {
            // Keep serialization until the blocking work ends, even if the client
            // cancels its request and drops the awaiting future.
            let _guard = guard;
            crate::scrub::clear_mcp_registry();
            let _redaction_scope = RedactionScope;
            crate::scrub::guard_scrub(&f(&project).to_string())
        })
        .await
        .unwrap_or_else(|_| stopped(tool, writes, verbose).to_string())
    }
}

/// The answer when a tool's work stopped before it answered (it panicked): opv's own
/// fault, and for a tool that writes, a write that may have started.
fn stopped(tool: &str, writes: bool, verbose: bool) -> Value {
    let site = if writes {
        "the MCP tool stopped before it answered, and its write may have started: check with opv_state section ready before calling it again"
    } else {
        "the MCP tool stopped before it answered"
    };
    ToolCall::new(tool, &[], Vec::new(), verbose).refused(Cause::Bug { site })
}

#[tool_router(server_handler)]
impl Server {
    #[tool(
        name = "opv_state",
        description = "Read one section of this project's state, as the same document the CLI command of that name prints with --json: inventory (opv inventory: every declared key's state per environment), needs (opv needs: the names the code reads against the contract), contract (opv contract: the contract as data), ready (opv ready: readiness findings and each one's next step), plan (opv plan <env>: what a sync would change, and its plan_id), changed (opv changed <env>: source items changed since the last sync), access (opv access: who needs which vault for CI and deploys), delivery_preview (opv run <env> --preview: what a local run would deliver), history (opv history <env>: what opv last wrote to the targets) or status (opv status: settings in 1Password and on the targets). env, product and target scope the section as the command's own arguments do; plan, changed, delivery_preview and history need env. Names, states, item ids and versions only, never a value. Changes nothing: a sync, deploy or apply is a person's or CI's.",
        input_schema = state_schema(),
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn state(&self, Parameters(args): Parameters<StateScope>) -> String {
        self.serialized("opv_state", false, false, move |project| {
            let r = read_only(state_budget(&args.section));
            let answer = state_doc(project, &r, &args, None);
            if r.refused.load(Ordering::Relaxed) {
                return state_call(&args).refused(write_refused());
            }
            answer
        })
        .await
    }

    #[tool(
        name = "opv_next",
        description = "The one action this session can take next, then the queue, then what waits on others, by vault: the same document as `opv next [--env <env>] --json`. env scopes it to one declared environment. Names, states and commands only, never a value. Changes nothing.",
        input_schema = next_schema(),
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn next(&self, Parameters(args): Parameters<NextScope>) -> String {
        self.serialized("opv_next", false, false, move |project| {
            let r = read_only(PROPOSE_BUDGET);
            let answer = next_doc(project, &r, &args);
            if r.refused.load(Ordering::Relaxed) {
                return next_call(&args).refused(write_refused());
            }
            answer
        })
        .await
    }

    #[tool(
        name = "opv_propose",
        description = "Propose a change to this project's contract from one intent document (kind key, env, target, retire, setup, structure or generate): names, enumerated attributes and catalog shape names only, never a rule parameter (regex, prefix, enum) or a value. Returns the same document as `opv propose <kind> --json`: the relaxations it makes (listed first), the contract diff or the structure steps, the questions it asks, and a plan_id that only a person's `opv apply <plan_id>` runs. Pure: writes neither the contract nor 1Password.",
        input_schema = propose_schema(),
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn propose(&self, Parameters(args): Parameters<rmcp::model::JsonObject>) -> String {
        self.serialized("opv_propose", false, false, move |project| {
            let r = read_only(PROPOSE_BUDGET);
            let answer = propose_doc(project, &r, &args);
            if r.refused.load(Ordering::Relaxed) {
                let parsed = crate::domain::intent::parse(&Value::Object(args.clone()).to_string());
                return propose_call(&args, parsed.is_ok()).refused(write_refused());
            }
            answer
        })
        .await
    }

    #[tool(
        name = "opv_import_local",
        description = "Import a .env file's values into a local-tier environment's 1Password items, for the person's own machine. Only an environment whose tier is local is accepted (any other is refused as import_tier_refused before the file is read). Write-only: fills missing keys, never replaces a set value; each written item is tagged assistant_imported. Returns per key whether it was imported or skipped (already set, empty), never a value; the same document as `opv import <env> --from <file> --json`.",
        input_schema = import_local_schema(),
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    async fn import_local(&self, Parameters(args): Parameters<ImportLocalScope>) -> String {
        self.serialized("opv_import_local", true, false, move |project| {
            let r = ProcessRunner::new(Budget::starting_now(IMPORT_BUDGET), false);
            import_local_doc(project, &r, &args, std::env::vars())
        })
        .await
    }

    #[tool(
        name = "opv_explain",
        description = "Explain a declared key (`[product/]KEY`) or a run plan id, with the environment when the key is declared in several (a plan id always needs it): the key's source, boundary, every target and delivery that holds it and who can read it, or each step of the plan. Names and IDs only, never a value; the same document as `opv explain <key|plan_id> [--env <env>] --json`. Changes nothing.",
        input_schema = explain_schema(),
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn explain(&self, Parameters(args): Parameters<ExplainScope>) -> String {
        self.serialized("opv_explain", false, false, move |project| {
            let r = read_only(INSPECT_BUDGET);
            let answer = explain_doc(project, &r, &args);
            if r.refused.load(Ordering::Relaxed) {
                return explain_call(&args).refused(write_refused());
            }
            answer
        })
        .await
    }
}

/// The enforcement boundary is beneath application orchestration, not tool hints.
struct ReadOnly<R> {
    inner: R,
    refused: AtomicBool,
}

impl<R: CommandRunner> CommandRunner for ReadOnly<R> {
    fn read(&self, call: &Call, refused: &[i32]) -> io::Result<Outcome> {
        self.inner.read(call, refused)
    }
    fn probe(&self, call: &Call, limit: Duration) -> io::Result<Output> {
        self.inner.probe(call, limit)
    }
    fn write(&self, _: &Call) -> io::Result<Outcome> {
        self.refused.store(true, Ordering::Relaxed);
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "MCP changes require human approval outside the server",
        ))
    }
    fn run_inherited(&self, _: &str, _: &[&str], _: &[(&str, &str)]) -> io::Result<i32> {
        self.refused.store(true, Ordering::Relaxed);
        Err(io::ErrorKind::PermissionDenied.into())
    }
    fn pause(&self, d: Duration, _: &str) {
        self.inner.pause(d, "");
    }
    fn note(&self, _: &str) {}
    fn remaining(&self) -> Option<Duration> {
        self.inner.remaining()
    }
    // step_summary intentionally retains the no-op default: no CI file writes.
}

/// An inspection needed a change the read-only runner refused (such as a layout repair):
/// a person runs the CLI command in their own terminal.
fn write_refused() -> Cause {
    Cause::NeedsTerminal {
        why: crate::cause::NoTerminal::NoTty,
    }
}

/// A CLI document the tool could not read: opv's own fault.
const UNREADABLE_REPORT: Cause = Cause::Bug {
    site: "the MCP tool could not read opv's own report",
};

struct RedactionScope;
impl Drop for RedactionScope {
    fn drop(&mut self) {
        crate::scrub::clear_mcp_registry();
    }
}

/// The read-only runner every inspection uses, with a `budget`.
fn read_only(budget: Duration) -> ReadOnly<ProcessRunner> {
    ReadOnly {
        inner: ProcessRunner::new(Budget::starting_now(budget), false),
        refused: AtomicBool::new(false),
    }
}

/// Inspection's runner budget.
const INSPECT_BUDGET: Duration = Duration::from_secs(20);

/// A runner whose `op` calls use the project's account ([`ProcessRunner::use_account`]).
trait Accounted: CommandRunner + Sized {
    fn select_account(&self, account: Option<String>);
}

impl Accounted for ProcessRunner {
    fn select_account(&self, account: Option<String>) {
        self.use_account(account);
    }
}

impl Accounted for ReadOnly<ProcessRunner> {
    fn select_account(&self, account: Option<String>) {
        self.inner.use_account(account);
    }
}

/// The project's configuration, loaded on `r`. First, as the CLI does (FR-40, NR-7): the
/// project's account (`OP_ACCOUNT`, else its `.opv`) resolved to an ID, so an account value
/// two accounts share is `account_ambiguous` here too, and op's default is never used.
fn load_fleet(
    project: &std::path::Path,
    r: &impl Accounted,
) -> Result<crate::domain::Fleet, Error> {
    r.select_account(config_store::selected_account_id(r, project)?);
    config_store::locate(&config_request(project), r).and_then(|found| found.load(r))
}

/// The configuration lookup from `project`, as the CLI makes it.
fn config_request(project: &std::path::Path) -> config_store::Request {
    config_store::Request {
        start: project.into(),
        config: None,
        // L7: the CLI's choice of project (`OPV_PROJECT`), so a tool reads what `opv` does.
        project: config_store::project_env(),
        manifest_only: false,
        account: config_store::account_env(),
    }
}

/// Credentials that would let this process write 1Password without the person's own
/// authorization in the 1Password app (#133): an `op` session token, a service account or
/// Connect. The first one set, by name.
fn credential_in_environment(vars: impl Iterator<Item = (String, String)>) -> Option<String> {
    vars.filter(|(_, v)| !v.is_empty())
        .map(|(k, _)| k)
        .find(|k| {
            k == "OP_SESSION"
                || k.starts_with("OP_SESSION_")
                || [
                    "OP_SERVICE_ACCOUNT_TOKEN",
                    "OP_CONNECT_HOST",
                    "OP_CONNECT_TOKEN",
                ]
                .contains(&k.as_str())
        })
}

/// The refusal of a 1Password write when this process runs under CI (`CI` or
/// `GITHUB_ACTIONS`): 1Password is read-only there (`require_person`), so it is refused
/// before any call, like [`credential_in_environment`].
fn ci_refusal() -> Option<Cause> {
    crate::host::Host::detect()
        .ci
        .then_some(Cause::NeedsTerminal {
            why: crate::cause::NoTerminal::Ci,
        })
}

/// `opv_state` section `access`'s runner budget: above the 1Password app's approval wait
/// ([`crate::adapters::onepassword::APPROVAL_TIMEOUT`]), so the session check that follows
/// a `wake` waiting on the app's prompt still has time to run.
const ACCESS_BUDGET: Duration = Duration::from_secs(120);

/// `opv_propose`'s runner budget: a structure proposal reads every boundary item.
const PROPOSE_BUDGET: Duration = Duration::from_secs(60);

/// `opv_import_local`'s runner budget: above the 1Password app's approval wait, with the
/// writes after it.
const IMPORT_BUDGET: Duration = Duration::from_secs(300);

/// The intent kinds `opv_propose` has a library proposal for.
const PROPOSE_KINDS: [&str; 7] = [
    "key",
    "env",
    "target",
    "retire",
    "setup",
    "structure",
    "generate",
];

/// How one intent field is written on `opv propose <kind>`'s command line.
#[derive(Clone, Copy)]
enum Word {
    /// `--flag <text>`.
    Text,
    /// `--flag <item>` once per item.
    List,
    /// `--flag <name>=<text>` once per entry (`--except ENV=REASON`).
    Pairs,
    /// `--flag` when true.
    Switch,
    /// `--<name> <text>` once per entry (a target's provider options).
    Options,
}

/// One kind's command line: its positional fields, then its flags by intent field.
type ProposeFlags = (
    &'static [&'static str],
    &'static [(&'static str, &'static str, Word)],
);

/// The positional words and the flags of `opv propose <kind>` (`src/main.rs` `ProposeCmd`),
/// by intent field. A field of the intent missing here has no CLI flag.
fn propose_flags(kind: &str) -> ProposeFlags {
    use Word::{List, Options, Pairs, Switch, Text};
    match kind {
        "key" => (
            &["key"],
            &[
                ("field_kind", "--kind", Text),
                ("environments", "--env", List),
                ("except", "--except", Pairs),
                ("source", "--source", Text),
                ("shape", "--shape", Text),
                ("personal", "--personal", Switch),
                ("from", "--from", Text),
                ("guidance", "--guidance", Text),
                ("allow_same_value", "--allow-same-value", Switch),
                ("immutable", "--immutable", Switch),
                ("expires", "--expires", Text),
            ],
        ),
        "env" => (&["env"], &[("tier", "--tier", Text)]),
        "target" => (
            &["env", "name"],
            &[
                ("provider", "--provider", Text),
                ("products", "--products", List),
                ("role", "--role", Text),
                ("deploy_credentials", "--deploy-credentials", Text),
                ("options", "", Options),
            ],
        ),
        "retire" => (&["key"], &[]),
        "setup" => (
            &[],
            &[
                ("from_item", "--from-item", Text),
                ("vault", "--vault", Text),
                ("item", "--item", Text),
                ("names_from", "--names-from", Text),
                ("config_key", "--config-key", List),
                ("secret_key", "--secret-key", List),
                ("file", "--file", Switch),
                ("project", "--project", Text),
                ("account", "--account", Text),
            ],
        ),
        "structure" => (&[], &[("rebind", "--rebind", List)]),
        "generate" => (&["env", "keys"], &[]),
        _ => (&[], &[]),
    }
}

/// The kind and the words after `opv propose <kind>` of the CLI command that takes the same
/// intent document (positionals, then flags in the command's order). `None` when the
/// document is not one the CLI can say: an unknown kind, a field with no flag (a key's
/// `lifecycle`, a `guidance` outside kind key), or a text that is not one line.
fn propose_words(args: &rmcp::model::JsonObject) -> Option<(&'static str, Vec<String>)> {
    let kind = args.get("kind").and_then(Value::as_str)?;
    let kind = *PROPOSE_KINDS.iter().find(|k| **k == kind)?;
    let (positional, flags) = propose_flags(kind);
    let known = |field: &str| {
        field == "kind"
            || positional.contains(&field)
            || (field == "product" && positional.contains(&"key"))
            || flags.iter().any(|(f, _, _)| *f == field)
    };
    if !args.keys().all(|field| known(field)) {
        return None;
    }
    let text = |v: &Value| v.as_str().filter(|s| one_line(s)).map(str::to_string);
    let texts = |v: &Value| -> Option<Vec<String>> { v.as_array()?.iter().map(text).collect() };
    let mut words = Vec::new();
    for field in positional {
        let Some(v) = args.get(*field) else { continue };
        match *field {
            "key" => {
                let key = text(v)?;
                words.push(match args.get("product") {
                    Some(p) => format!("{}/{key}", text(p)?),
                    None => key,
                });
            }
            "keys" => words.extend(texts(v)?),
            _ => words.push(text(v)?),
        }
    }
    for (field, flag, word) in flags {
        let Some(v) = args.get(*field) else { continue };
        match word {
            Word::Text => words.extend([flag.to_string(), text(v)?]),
            Word::List => {
                for item in texts(v)? {
                    words.extend([flag.to_string(), item]);
                }
            }
            Word::Pairs | Word::Options => {
                for (name, item) in v.as_object()? {
                    let item = text(item)?;
                    if !one_line(name) {
                        return None;
                    }
                    match word {
                        Word::Pairs => words.extend([flag.to_string(), format!("{name}={item}")]),
                        _ => words.extend([format!("--{name}"), item]),
                    }
                }
            }
            Word::Switch => {
                if v.as_bool()? {
                    words.push(flag.to_string());
                }
            }
        }
    }
    Some((kind, words))
}

/// `opv_propose`'s call: `opv propose <kind> <words> --json`, the CLI command that takes
/// the same intent (`parsed`: the document parsed); with the kind alone when it is not one
/// the CLI can say ([`propose_words`]).
fn propose_call(args: &rmcp::model::JsonObject, parsed: bool) -> ToolCall {
    if let Some((kind, words)) = propose_words(args).filter(|_| parsed) {
        return ToolCall::new("opv_propose", &["propose", kind], words, false);
    }
    let kind = args
        .get("kind")
        .and_then(Value::as_str)
        .filter(|k| PROPOSE_KINDS.contains(k));
    let command: Vec<&str> = std::iter::once("propose").chain(kind).collect();
    ToolCall::new("opv_propose", &command, Vec::new(), false)
}

/// `args` without each free-text field the intent refuses for carrying a value
/// ([`Cause::ValueInTextField`]), and whether what remains parses: the call to make again.
fn without_value_fields(args: &rmcp::model::JsonObject) -> (rmcp::model::JsonObject, bool) {
    let mut fixed = args.clone();
    // Each round removes one field, so the loop ends within the field count.
    for _ in 0..=args.len() {
        match crate::domain::intent::parse(&Value::Object(fixed.clone()).to_string()) {
            Ok(_) => return (fixed, true),
            Err(e) => match e.parts().0 {
                Cause::ValueInTextField { field, .. } => match field.0.first() {
                    Some(f) if fixed.remove(f).is_some() => {}
                    _ => break,
                },
                _ => break,
            },
        }
    }
    (fixed, false)
}

/// The person's step after a contract or setup proposal (kinds key, env, target, retire,
/// setup): the same `opv propose <kind> … --write`, which writes the contract diff into the
/// repository's contract file, reviewed and committed in a pull request. A tool never writes
/// the contract, so it is the person's, as an `apply`. When the CLI cannot say the document
/// ([`propose_words`]), the step is the intent document itself, `opv propose --intent`.
fn write_next(args: &rmcp::model::JsonObject) -> Option<Value> {
    let kind = args.get("kind").and_then(Value::as_str)?;
    if !["key", "env", "target", "retire", "setup"].contains(&kind) {
        return None;
    }
    let command = match propose_words(args) {
        Some((kind, mut words)) => {
            words.push("--write".into());
            render::cmd_text(&Cmd {
                command: vec!["propose".into(), kind.into()],
                args: words,
            })
        }
        None => "opv propose --intent <intent.json> --write".to_string(),
    };
    Some(json!({"kind": "apply", "actor": "person", "command": command}))
}

/// `opv_propose`: the intent document parsed (an unknown field, such as a rule parameter,
/// is refused naming itself), then the library proposal for its kind, as the `--json`
/// document `opv propose <kind>` prints. Pure: `r` only reads, and nothing is written.
fn propose_doc<R: Accounted>(
    project: &std::path::Path,
    r: &R,
    args: &rmcp::model::JsonObject,
) -> Value {
    let parsed = crate::domain::intent::parse(&Value::Object(args.clone()).to_string());
    let call = match &parsed {
        Ok(_) => propose_call(args, true),
        // A free-text field that carries a value: the step is the same call without that
        // field, as the complete command that takes it (never the text itself).
        Err(_) => {
            let (fixed, parses) = without_value_fields(args);
            propose_call(&fixed, parses)
        }
    };
    let res = parsed.and_then(|intent| proposal(project, r, &intent, &call.inv));
    match res {
        Ok(mut doc) => {
            // A generated configuration's proposal already names its generator route
            // (#184): never the `--write` that would be refused.
            if doc.get("generated").is_none()
                && let Some(next) = write_next(args)
            {
                doc["next"] = next;
            }
            call.document(doc.to_string().as_bytes(), Ok(()))
        }
        Err(e) => call.document(&[], Err(e)),
    }
}

/// A library document as JSON.
fn to_doc<T: serde::Serialize>(doc: &T) -> Result<Value, Error> {
    serde_json::to_value(doc).map_err(|_| Error::from(UNREADABLE_REPORT))
}

/// The proposal `intent` implies, by kind, from the library `opv propose` runs
/// ([`crate::app::propose`]), as the `opv propose <kind> --json` document: the library's
/// proposal, `written: null` (a tool never writes), and for a structural proposal the
/// person's `opv apply` as `next`. A contract or setup proposal's `next` is set by
/// [`propose_doc`] ([`write_next`]).
fn proposal<R: Accounted>(
    project: &std::path::Path,
    r: &R,
    intent: &crate::domain::intent::Intent,
    inv: &Invocation,
) -> Result<Value, Error> {
    use crate::app::propose::{key, setup, target};
    use crate::domain::intent::Intent;
    let unwritten = |mut doc: Value| {
        doc["written"] = Value::Null;
        doc
    };
    match intent {
        Intent::Key { .. } | Intent::Env { .. } | Intent::Retire { .. } | Intent::Target { .. } => {
            let (text, ids, rules, generated) = contract_for_proposal(project, r)?;
            let base = rules.as_ref().and_then(|s| s.contract());
            let proposal = if matches!(intent, Intent::Target { .. }) {
                target::propose(&text, &ids, base, intent)
            } else {
                key::propose(&text, &ids, base, intent)
            }
            .map_err(proposal_refused)?;
            let mut doc = to_doc(&proposal).map(unwritten)?;
            // FR-52 (#184): the diff goes into the generator, then the structure: the
            // same `next` `opv propose` prints on the command line.
            if let Some(source) = generated {
                doc["generated"] = json!(true);
                doc["next"] = crate::app::propose::generated_next(source, &proposal, inv);
            }
            Ok(doc)
        }
        Intent::Setup {
            from_item,
            vault,
            item,
            names_from,
            config_key,
            secret_key,
            project: named,
            account,
            ..
        } => {
            let proposed = match (from_item, names_from) {
                (Some(env), _) => {
                    // FR-40, NR-7: the item is read in one chosen account, never op's default.
                    let given = account
                        .clone()
                        .or_else(|| config_store::pointer_account(project))
                        .or_else(config_store::account_env);
                    r.select_account(config_store::pick_account(r, given)?);
                    let (vault, item) = match (vault, item) {
                        (Some(v), Some(i)) => (v.clone(), i.clone()),
                        (vault, item) => {
                            let repo = config_store::git_repo(r);
                            let name = config_store::default_project(
                                named.as_deref(),
                                repo.as_deref(),
                                project,
                            )?;
                            let b = crate::app::init::SHARED_BOUNDARY;
                            let env = env.as_str();
                            (
                                vault.clone().unwrap_or_else(|| {
                                    crate::domain::naming::boundary_vault(&name, b, env)
                                }),
                                item.clone().unwrap_or_else(|| {
                                    crate::domain::naming::boundary_item(&name, b, env)
                                }),
                            )
                        }
                    };
                    let contract = config_store::walk_up(project, "secrets.toml")
                        .unwrap_or_else(|| project.join("secrets.toml"));
                    setup::from_item(r, env.as_str(), Some(&vault), Some(&item), Some(&contract))?
                }
                (None, Some(file)) => setup::from_names(
                    &project.join(file),
                    setup::NAMES_ENV,
                    config_key,
                    secret_key,
                )?,
                (None, None) => {
                    return Err(Cause::Usage {
                        problem: UsageProblem::NeedsFlag {
                            flag: "opv propose setup".into(),
                            needs: "--from-item <env> or --names-from <.env>".into(),
                        },
                    }
                    .into());
                }
            };
            to_doc(&proposed).map(unwritten)
        }
        Intent::Structure { rebind, .. } => {
            let rebind: Vec<String> = rebind.iter().map(|e| e.to_string()).collect();
            structure_proposal(project, r, &rebind, &[])
        }
        Intent::Generate { env, keys, .. } => {
            let keys = keys.iter().map(|k| k.to_string()).collect();
            structure_proposal(project, r, &[], &[(env.to_string(), keys)])
        }
    }
}

/// A loader refusal of the proposed text is the proposal's (`config_proposal_invalid`),
/// as `opv propose` words it: that text was never written.
fn proposal_refused(e: Error) -> Error {
    let Error::Catalog(cause, upstream) = e;
    let cause = match *cause {
        Cause::ConfigInvalid {
            source,
            field,
            rule,
            ..
        } => Cause::ConfigProposalInvalid {
            source,
            field,
            rule,
            from_proposal: true,
        },
        other => other,
    };
    Error::Catalog(Box::new(cause), upstream)
}

/// `opv apply <plan_id>` with the `--rebind` and `--generate` a structural proposal needs
/// to be recomputed as it was proposed: the person's step.
fn apply_step(plan_id: &str, rebind: &[String], generate: &[(String, Vec<String>)]) -> String {
    let mut args = vec![plan_id.to_string()];
    for env in rebind {
        args.extend(["--rebind".to_string(), env.clone()]);
    }
    for (env, keys) in generate {
        for k in keys {
            args.extend(["--generate".to_string(), format!("{env}:{k}")]);
        }
    }
    render::cmd_text(&Cmd {
        command: vec!["apply".into()],
        args,
    })
}

/// `opv propose structure|generate`: the structure plan over the project's configuration
/// (a file or its manifest), with its project name and account as `opv propose` resolves
/// them, and the person's `opv apply` next. Reads only.
fn structure_proposal<R: Accounted>(
    project: &std::path::Path,
    r: &R,
    rebind: &[String],
    generate: &[(String, Vec<String>)],
) -> Result<Value, Error> {
    let scope = crate::app::structure::scope_as(project, r, "propose structure")?;
    r.select_account(Some(scope.account.clone()));
    let p = crate::app::propose::structure::propose_structure_at(
        r,
        &scope.config,
        &scope.project,
        &scope.account,
        rebind,
        generate,
    )?;
    let mut doc = to_doc(&p)?;
    doc["next"] = json!({
        "kind": "apply",
        "actor": "person",
        "command": apply_step(&p.plan_id, rebind, generate),
    });
    Ok(doc)
}

/// The contract and its bindings as `opv propose` reads them (the configuration's text with
/// its ids, split), and the committed default-branch contract whose relaxations a proposal
/// lists first (none readable: `None`).
/// The last part is the configuration's source when it is generated (FR-52).
#[allow(clippy::type_complexity)]
fn contract_for_proposal<R: Accounted>(
    project: &std::path::Path,
    r: &R,
) -> Result<
    (
        String,
        crate::config::bindings::Bindings,
        Option<crate::app::rule_source::RuleSource>,
        Option<crate::cause::ConfigSource>,
    ),
    Error,
> {
    r.select_account(config_store::selected_account_id(r, project)?);
    let found = config_store::locate(&config_request(project), r)?;
    let store = found.store();
    let snap = store.read(r)?;
    let working = store.parse(&snap.text)?;
    let (contract, ids) = crate::config::bindings::split(&snap.text);
    let repo = config_store::repo_root(project).unwrap_or(project);
    let rules = crate::app::rule_source::rule_source(r, repo, &working).ok();
    let generated = crate::app::bootstrap::is_generated(&snap.text).then(|| found.cause_source());
    Ok((contract, ids, rules, generated))
}

/// One line of printable text, short enough to repeat in a re-run.
fn one_line(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control)
}

/// `opv_import_local`'s call: `opv import <env> --from <file> --json`, with the names
/// when they are checked.
fn import_local_call(args: &ImportLocalScope) -> ToolCall {
    let words = if identifier(&args.env) && one_line(&args.file) {
        vec![args.env.clone(), "--from".into(), args.file.clone()]
    } else {
        Vec::new()
    };
    ToolCall::new("opv_import_local", &["import"], words, false)
}

/// `opv_import_local`: the assistant's import into a `local`-tier environment
/// ([`crate::app::import_local`]), as the `opv import --json` document. A credential in
/// the server's environment (`vars`) or CI needs the person; any other tier is refused
/// before the file is read. Never a value.
fn import_local_doc<R: Accounted>(
    project: &std::path::Path,
    r: &R,
    args: &ImportLocalScope,
    vars: impl Iterator<Item = (String, String)>,
) -> Value {
    let call = import_local_call(args);
    if !identifier(&args.env) {
        return call.refused(not_a_name("env"));
    }
    if !one_line(&args.file) {
        return call.refused(usage("file", "the path of a .env file, on one line"));
    }
    if let Some(var) = credential_in_environment(vars) {
        return call.refused(own_session("import", var));
    }
    if let Some(refused) = ci_refusal() {
        return call.refused(refused);
    }
    let fleet = match load_fleet(project, r) {
        Ok(fleet) => fleet,
        Err(e) => return call.failed(&e),
    };
    let mut out = Vec::new();
    let res = crate::app::import_local::import_local_json(
        &fleet,
        &args.env,
        &project.join(&args.file),
        r,
        &mut out,
    )
    .map_err(|e| as_given(e, &args.file));
    call.document(&out, res)
}

/// A tier refusal naming the file as the caller gave it (`file`), not the path the server
/// resolved against the project: the person's own `opv import` step repeats the caller's
/// words. Any other error is unchanged.
fn as_given(e: Error, file: &str) -> Error {
    match e.parts().0 {
        Cause::ImportTierRefused { env, tier, .. } => Cause::ImportTierRefused {
            env: env.clone(),
            tier,
            file: std::path::PathBuf::from(file),
        }
        .into(),
        _ => e,
    }
}

/// A key reference, `[product/]KEY` ([`KEY_REF_PATTERN`]).
fn key_ref(s: &str) -> bool {
    let (product, key) = match s.split_once('/') {
        Some((p, k)) => (Some(p), k),
        None => (None, s),
    };
    let lower = |p: &str| {
        p.starts_with(|c: char| c.is_ascii_lowercase())
            && p.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    };
    let upper = key.starts_with(|c: char| c.is_ascii_uppercase())
        && key
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    product.is_none_or(lower) && upper
}

/// A run plan id: the lowercase hex digits `opv plan` prints as `plan_id`.
fn run_plan_id(s: &str) -> bool {
    s.len() == crate::domain::provenance::PLAN_ID_LEN
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// What `opv_explain` was asked, when it is exactly one checked key or plan id; else the
/// field and the format its refusal names.
fn explain_asked(args: &ExplainScope) -> Result<&str, (&'static str, &'static str)> {
    match (&args.key, &args.plan_id) {
        (Some(k), None) if key_ref(k) => Ok(k),
        (Some(_), None) => Err((
            "key",
            "[product/]KEY, a declared key (opv_state section contract lists them)",
        )),
        (None, Some(p)) if run_plan_id(p) => Ok(p),
        (None, Some(_)) => Err(("plan_id", "the lowercase hex plan_id opv plan prints")),
        _ => Err(("key, plan_id", "exactly one of key or plan_id")),
    }
}

/// `opv_explain`'s call: `opv explain <key|plan_id> [--env <env>] --json`, with the names
/// when they are checked.
fn explain_call(args: &ExplainScope) -> ToolCall {
    let mut words: Vec<String> = explain_asked(args)
        .ok()
        .map(str::to_string)
        .into_iter()
        .collect();
    if let Some(env) = args.env.as_ref().filter(|e| identifier(e)) {
        words.extend(["--env".to_string(), env.clone()]);
    }
    ToolCall::new("opv_explain", &["explain"], words, false)
}

/// `opv_explain`: the key form or the plan form of `opv explain` ([`crate::app::explain`]),
/// as its `--json` document. Names and IDs only, never a value.
fn explain_doc<R: Accounted>(project: &std::path::Path, r: &R, args: &ExplainScope) -> Value {
    let call = explain_call(args);
    let asked = match explain_asked(args) {
        Ok(asked) => asked,
        Err((field, format)) => return call.refused(usage(field, format)),
    };
    if args.env.as_ref().is_some_and(|e| !identifier(e)) {
        return call.refused(not_a_name("env"));
    }
    let fleet = match load_fleet(project, r) {
        Ok(fleet) => fleet,
        Err(e) => return call.failed(&e),
    };
    let name = crate::app::personal::project_name(r, project);
    let mut out = Vec::new();
    let res = crate::app::explain::run_request_with(
        r,
        &fleet,
        &crate::app::explain::Asked::Key(asked),
        args.env.as_deref(),
        &name,
        &mut out,
        true,
    );
    call.document(&out, res)
}

/// `opv_next`'s call: `opv next [--env <env>] --json`, with the environment when it is a
/// name.
fn next_call(args: &NextScope) -> ToolCall {
    let words = match args.env.as_deref().filter(|e| scope_name(e)) {
        Some(env) => vec!["--env".to_string(), env.to_string()],
        None => Vec::new(),
    };
    ToolCall::new("opv_next", &["next"], words, false)
}

/// `opv_next`: `opv next [--env <env>] --json` from the same library calls on the read-only
/// runner `r`: the inventory and its signals ([`crate::app::inventory::gather_for_next`])
/// ranked into one action, the queue and what waits on others ([`crate::app::next::next`]).
fn next_doc<R: Accounted>(project: &std::path::Path, r: &R, args: &NextScope) -> Value {
    let call = next_call(args);
    if args.env.as_deref().is_some_and(|e| !scope_name(e)) {
        return call.refused(usage(
            "env",
            "a declared name: lowercase letters, digits and '-', starting with a letter",
        ));
    }
    let fleet = match load_fleet(project, r) {
        Ok(fleet) => fleet,
        Err(e) => return call.failed(&e),
    };
    let res = crate::app::inventory::gather_for_next(&fleet, args.env.as_deref(), None, r, None)
        .map(|(document, signals)| crate::app::next::next(&document, &signals).document());
    match res {
        Ok(doc) => call.document(doc.to_string().as_bytes(), Ok(())),
        Err(e) => call.failed(&e),
    }
}

/// The sections of `opv_state` (design §25.2), in the golden's order.
const SECTIONS: [(&str, Section); 10] = [
    ("inventory", Section::Inventory),
    ("needs", Section::Needs),
    ("contract", Section::Contract),
    ("ready", Section::Ready),
    ("plan", Section::Plan),
    ("changed", Section::Changed),
    ("access", Section::Access),
    ("delivery_preview", Section::DeliveryPreview),
    ("history", Section::History),
    ("status", Section::Status),
];

/// What an unknown section is refused with.
const SECTION_FORMAT: &str = "one of inventory, needs, contract, ready, plan, changed, access, delivery_preview, history or status";

/// One `opv_state` section: the CLI command whose `--json` document it answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Section {
    Inventory,
    Needs,
    Contract,
    Ready,
    Plan,
    Changed,
    Access,
    DeliveryPreview,
    History,
    Status,
}

/// Whether a section takes a scope field, and whether it needs it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Takes {
    No,
    Optional,
    Required,
}

impl Section {
    fn parse(s: &str) -> Option<Self> {
        SECTIONS.iter().find(|(n, _)| *n == s).map(|(_, x)| *x)
    }

    fn name(self) -> &'static str {
        SECTIONS
            .iter()
            .find(|(_, x)| *x == self)
            .map_or("", |(n, _)| n)
    }

    /// The CLI command path.
    fn command(self) -> &'static [&'static str] {
        match self {
            Self::Inventory => &["inventory"],
            Self::Needs => &["needs"],
            Self::Contract => &["contract"],
            Self::Ready => &["ready"],
            Self::Plan => &["plan"],
            Self::Changed => &["changed"],
            Self::Access => &["access"],
            Self::DeliveryPreview => &["run"],
            Self::History => &["history"],
            Self::Status => &["status"],
        }
    }

    /// What the section takes of `env`, `product` and `target`, as its command does.
    fn takes(self) -> [Takes; 3] {
        use Takes::{No, Optional, Required};
        match self {
            Self::Inventory | Self::Contract => [Optional, Optional, No],
            Self::Needs => [No, No, No],
            Self::Ready => [Optional, No, No],
            Self::Plan | Self::Changed => [Required, Optional, Optional],
            Self::Access => [Optional, No, Optional],
            Self::DeliveryPreview => [Required, Optional, No],
            Self::History => [Required, No, Optional],
            Self::Status => [Optional, Optional, Optional],
        }
    }
}

/// A scope name: the golden's grammar ([`ENV_PATTERN`]), at most 64 bytes.
fn scope_name(s: &str) -> bool {
    s.len() <= 64
        && s.starts_with(|c: char| c.is_ascii_lowercase())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The CLI words of a checked scope for `section`, after its command path.
fn state_words(
    section: Section,
    env: Option<&str>,
    product: Option<&str>,
    target: Option<&str>,
) -> Vec<String> {
    let flag = |f: &str, v: Option<&str>| -> Vec<String> {
        v.map(|v| vec![f.to_string(), v.to_string()])
            .unwrap_or_default()
    };
    match section {
        Section::Needs => Vec::new(),
        Section::Inventory => [flag("--env", env), flag("--product", product)].concat(),
        Section::Contract => [flag("--env", env), flag("--component", product)].concat(),
        _ => {
            let preview = (section == Section::DeliveryPreview).then(|| "--preview".to_string());
            let positional: Vec<String> =
                env.map(str::to_string).into_iter().chain(preview).collect();
            [
                positional,
                flag("--target", target),
                flag("--product", product),
            ]
            .concat()
        }
    }
}

/// `opv_state`'s call: the section's CLI command with its scope, the names that are
/// checked ones; with no command for an unknown section.
fn state_call(args: &StateScope) -> ToolCall {
    let Some(section) = Section::parse(&args.section) else {
        return ToolCall::new("opv_state", &[], Vec::new(), false);
    };
    fn ok(v: &Option<String>) -> Option<&str> {
        v.as_deref().filter(|v| scope_name(v))
    }
    let words = state_words(section, ok(&args.env), ok(&args.product), ok(&args.target));
    ToolCall::new("opv_state", section.command(), words, false)
}

/// Why `args` is refused before anything is read: an unknown section, a scope field that is
/// not a name, one the section does not take, or one it needs and lacks.
fn state_refusal(section: Option<Section>, args: &StateScope) -> Option<Cause> {
    let Some(section) = section else {
        return Some(usage("section", SECTION_FORMAT));
    };
    let fields = [
        ("env", args.env.as_deref()),
        ("product", args.product.as_deref()),
        ("target", args.target.as_deref()),
    ];
    for ((field, value), takes) in fields.into_iter().zip(section.takes()) {
        match (value, takes) {
            (Some(v), _) if !scope_name(v) => {
                return Some(usage(
                    field,
                    "a declared name: lowercase letters, digits and '-', starting with a letter",
                ));
            }
            (Some(_), Takes::No) => {
                return Some(Cause::Usage {
                    problem: UsageProblem::ConflictsWith {
                        a: format!("section {}", section.name()),
                        b: field.into(),
                    },
                });
            }
            (None, Takes::Required) => {
                return Some(Cause::Usage {
                    problem: UsageProblem::NeedsFlag {
                        flag: format!("section {}", section.name()),
                        needs: field.into(),
                    },
                });
            }
            _ => {}
        }
    }
    if args.target.is_some() && args.env.is_none() {
        return Some(Cause::Usage {
            problem: UsageProblem::NeedsFlag {
                flag: "target".into(),
                needs: "env".into(),
            },
        });
    }
    None
}

/// The runner budget of a section: `access` waits on the 1Password app's approval; the
/// inventory and the code scan read more than the rest.
fn state_budget(section: &str) -> Duration {
    match Section::parse(section) {
        Some(Section::Access) => ACCESS_BUDGET,
        Some(Section::Inventory | Section::Needs) => PROPOSE_BUDGET,
        _ => INSPECT_BUDGET,
    }
}

/// `opv_state`: the section's `--json` document, as the CLI command of that name prints it
/// in agent mode, from the same library entry point on the read-only runner `r`.
/// `generated_at` fixes the clock `ready` records (a test's); `None` is now.
fn state_doc<R: Accounted>(
    project: &std::path::Path,
    r: &R,
    args: &StateScope,
    generated_at: Option<&str>,
) -> Value {
    let call = state_call(args);
    let section = Section::parse(&args.section);
    // Every failure is framed as the CLI frames it, so a refusal and a load failure are
    // the same document `opv <command> --json` prints.
    if let Some(cause) = state_refusal(section, args) {
        return call.document(&[], Err(cause.into()));
    }
    let Some(section) = section else {
        return call.document(&[], Err(usage("section", SECTION_FORMAT).into()));
    };
    let fleet = match load_fleet(project, r) {
        Ok(fleet) => fleet,
        Err(e) => return call.document(&[], Err(e)),
    };
    let (env, product, target) = (
        args.env.as_deref(),
        args.product.as_deref(),
        args.target.as_deref(),
    );
    let targets: Vec<String> = target.map(str::to_string).into_iter().collect();
    let required = env.unwrap_or_default();
    let mut out = zeroize::Zeroizing::new(Vec::new());
    let res = match section {
        Section::Inventory => {
            crate::app::inventory::run(&fleet, env, product, r, None, true, &mut *out)
        }
        Section::Needs => {
            crate::app::needs::run(r, &needs_repo(r, project), &fleet, false, true, &mut *out)
        }
        Section::Contract => {
            crate::app::contract::write_document(&fleet, env, product, true, &mut *out)
        }
        Section::Ready => {
            let now = generated_at
                .map(str::to_string)
                .unwrap_or_else(crate::domain::provenance::utc_now);
            crate::app::ready::run_at(&fleet, None, env, r, true, None, false, &now, &mut *out)
        }
        Section::Plan => crate::app::sync::plan_rotating(
            &fleet,
            required,
            &targets,
            product,
            &[],
            r,
            &mut *out,
            true,
        )
        .map_err(|e| e.in_env(required)),
        Section::Changed => {
            crate::app::changed::run(&fleet, required, product, &targets, r, true, &mut *out)
                .map(|_exit| ())
        }
        Section::Access => crate::app::access::run(&fleet, env, target, None, r, true, &mut *out),
        Section::DeliveryPreview => {
            // `opv run --preview --json` prints the builder's document as it is (no frame).
            return match crate::app::delivery_preview::build_for(
                &fleet, required, product, None, None, r,
            ) {
                Ok(doc) => doc,
                Err(e) => call.document(&[], Err(e)),
            };
        }
        Section::History => crate::app::history::run(&fleet, required, target, r, true, &mut *out),
        Section::Status => match env {
            None => crate::app::status::overview(&fleet, product, r, &mut *out, true),
            Some(env) => crate::app::status::run_targeted(
                &fleet, env, &targets, product, r, &mut *out, true, false,
            )
            .map_err(|e| e.in_env(env)),
        },
    };
    call.document(&out, res)
}

/// The repository `opv needs` scans: the project's git top level, else the project. The
/// CLI asks git from its working directory; the server's is the project.
fn needs_repo(r: &dyn CommandRunner, project: &std::path::Path) -> PathBuf {
    let dir = project.to_string_lossy();
    let argv = ["-C", &dir, "rev-parse", "--show-toplevel"];
    let call = Call::new("git", &argv);
    match r.probe(&call, crate::runner::PROBE_TIMEOUT) {
        Ok(o) if o.status == 0 => {
            let top = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if top.is_empty() {
                project.to_path_buf()
            } else {
                PathBuf::from(top)
            }
        }
        _ => project.to_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::fake::FakeRunner;

    #[test]
    fn write_is_refused_before_reaching_the_vendor() {
        let r = ReadOnly {
            inner: FakeRunner::new([]),
            refused: AtomicBool::new(false),
        };
        assert!(r.write(&Call::new("op", &["item", "edit"])).is_err());
        assert!(r.inner.calls.borrow().is_empty());
    }
    fn vars(pairs: &[(&str, &str)]) -> impl Iterator<Item = (String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn an_op_session_token_refuses_the_structural_apply() {
        let found = credential_in_environment(vars(&[("OP_SESSION_my", "x")]));
        assert_eq!(found.as_deref(), Some("OP_SESSION_my"));
    }

    #[test]
    fn a_bare_op_session_refuses_the_structural_apply() {
        let found = credential_in_environment(vars(&[("OP_SESSION", "x")]));
        assert_eq!(found.as_deref(), Some("OP_SESSION"));
    }

    #[test]
    fn a_service_account_token_refuses_the_structural_apply() {
        let found = credential_in_environment(vars(&[("OP_SERVICE_ACCOUNT_TOKEN", "ops_x")]));
        assert_eq!(found.as_deref(), Some("OP_SERVICE_ACCOUNT_TOKEN"));
    }

    #[test]
    fn a_connect_credential_refuses_the_structural_apply() {
        let found = credential_in_environment(vars(&[("OP_CONNECT_TOKEN", "x")]));
        assert_eq!(found.as_deref(), Some("OP_CONNECT_TOKEN"));
    }

    #[test]
    fn an_environment_without_op_credentials_may_apply() {
        let found = credential_in_environment(vars(&[("OP_ACCOUNT", "A"), ("HOME", "/h")]));
        assert_eq!(found, None);
    }

    #[test]
    fn every_registered_tool_has_a_cli_parity_entry() {
        let mut registered: Vec<String> = Server::tool_router()
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();
        registered.sort();
        let mut mapped: Vec<String> = crate::schema::MCP_TOOLS
            .iter()
            .map(|(tool, _)| tool.to_string())
            .collect();
        mapped.sort();
        mapped.dedup();
        assert_eq!(registered, mapped);
    }

    #[test]
    fn access_has_more_budget_than_the_1password_app_approval_wait() {
        assert!(ACCESS_BUDGET > crate::adapters::onepassword::APPROVAL_TIMEOUT);
    }

    fn under_ci<T>(f: impl FnOnce() -> T) -> T {
        let env = crate::host::FakeEnv::new("linux")
            .var_val("CI", "true")
            .shell("/bin/bash");
        crate::host::with_test_host(crate::host::Host::from_env(&env), f)
    }

    #[test]
    fn a_write_tool_is_refused_under_ci() {
        assert!(under_ci(ci_refusal).is_some());
    }

    fn tool(command: &[&str], args: &[&str]) -> ToolCall {
        ToolCall::new(
            "opv_state",
            command,
            args.iter().map(|a| a.to_string()).collect(),
            false,
        )
    }

    fn own_session() -> crate::error::Error {
        crate::cause::Cause::NeedsOwnSession {
            command: crate::cause::CommandId("generate".into()),
            identity: crate::cause::Principal::ServiceAccount {
                name: "sa-ci".into(),
            },
        }
        .into()
    }

    #[test]
    fn a_catalog_failure_is_exactly_the_documents_error_object() {
        let call = tool(&["plan"], &["prod"]);
        let want = render::document(
            &crate::cause::Cause::NeedsOwnSession {
                command: crate::cause::CommandId("generate".into()),
                identity: crate::cause::Principal::ServiceAccount {
                    name: "sa-ci".into(),
                },
            },
            None,
            &call.inv,
            false,
        );
        assert_eq!(call.failed(&own_session())["error"], want);
    }

    #[test]
    fn a_catalog_failure_answers_not_ok() {
        assert_eq!(tool(&["sync"], &[]).failed(&own_session())["ok"], false);
    }

    fn upstream(lines: usize) -> crate::cause::Upstream {
        crate::cause::Upstream {
            source: crate::cause::System::OnePassword,
            tool: "1Password CLI".into(),
            version: None,
            exit: crate::cause::ExitClass::Code { code: 1 },
            said: (0..lines).map(|i| format!("line {i}")).collect(),
            removed_advice: false,
            truncated: false,
            untrusted: true,
        }
    }

    fn with_upstream(lines: usize) -> crate::error::Error {
        crate::error::Error::with_evidence(
            crate::cause::Cause::Bug { site: "test" },
            upstream(lines),
        )
    }

    #[test]
    fn an_upstream_reply_is_marked_untrusted() {
        let v = tool(&["sync"], &[]).failed(&with_upstream(1));
        assert_eq!(v["error"]["evidence"]["upstream"]["untrusted"], true);
    }

    #[test]
    fn verbose_returns_the_whole_upstream_reply() {
        let call = ToolCall::new("opv_state", &["plan"], Vec::new(), true);
        let v = call.failed(&with_upstream(12));
        assert_eq!(
            v["error"]["evidence"]["upstream"]["said"]
                .as_array()
                .map(Vec::len),
            Some(12)
        );
    }

    #[test]
    fn without_verbose_the_upstream_reply_is_cut() {
        let v = tool(&["sync"], &[]).failed(&with_upstream(12));
        assert!(
            v["error"]["evidence"]["upstream"]["said"]
                .as_array()
                .unwrap()
                .len()
                < 12
        );
    }

    /// MCP is the `--json` document: a re-run is the CLI command with `--json`.
    #[test]
    fn a_rerun_is_the_cli_commands_json_form() {
        let e: crate::error::Error = crate::cause::Cause::Interrupted {
            signal: 2,
            writes_started: false,
        }
        .into();
        assert_eq!(
            tool(&["sync"], &[]).failed(&e)["error"]["next"]["command"],
            "opv sync --json"
        );
    }

    // 08.02: a target CLI's sign-out gets its own sign-in step, not a 1Password hint.
    fn fly_signed_out() -> crate::error::Error {
        crate::cause::Cause::NotSignedIn {
            system: crate::cause::System::Fly,
            account: None,
            state: crate::cause::SessionState::SignedOut,
        }
        .into()
    }

    #[test]
    fn a_target_sign_out_answers_with_the_target_sign_in() {
        let v = tool(&["plan"], &["prod"]).failed(&fly_signed_out());
        assert!(v["error"].to_string().contains("flyctl auth login"), "{v}");
    }

    #[test]
    fn a_target_sign_out_never_blames_1password() {
        let v = tool(&["plan"], &["prod"]).failed(&fly_signed_out());
        assert!(!v.to_string().contains("1Password"));
    }

    // 08 (S2): a write tool that stopped says its write may have started.
    #[test]
    fn a_write_tool_that_stopped_says_its_write_may_have_started() {
        assert!(
            stopped("opv_import_local", true, false)["error"]["message"]
                .as_str()
                .unwrap()
                .contains("write may have started")
        );
    }
}

#[cfg(test)]
#[path = "mcp_propose_tests.rs"]
mod propose_tests;

#[cfg(test)]
#[path = "mcp_state_tests.rs"]
mod state_tests;

#[cfg(test)]
#[path = "mcp_next_tests.rs"]
mod next_tests;
