//! MCP tools. The inspection tools are read-only: no value-bearing operation or mutation is
//! exposed, and their runner refuses every write beneath the application code.
//!
//! The structural tool (#133) plans structure only (vaults, items, empty fields, delivery
//! items; never a value) on the same read-only runner. A person applies it with `opv apply`
//! in their own terminal; no tool applies structure or syncs (design §25.3).
//!
//! A success answer is one projection per tool, built field by field from checked
//! identifiers; never a value. A failure answer is `{ok: false, error}`, where `error` is
//! exactly the `--json` document's error object (design `docs/design/error-catalog.md`
//! §7.2): code, category, message, subject, evidence (the upstream reply marked
//! `untrusted: true`), retry, human_required, do, and the typed next `{kind, actor, command}`,
//! rendered from the
//! cause against the tool's own invocation ([`ToolCall`]). Every tool takes `verbose`, as
//! the CLI's `--verbose`: the upstream reply in full rather than its last lines.
use crate::{
    app::agent_view::{configuration_projection, identifier, plan_projection},
    cause::{
        Cause, Closest, Cmd, CommandId, Invocation, NameKind, Origin, Principal, UsageProblem,
        VarName, render,
    },
    config_store,
    error::Error,
    runner::{Budget, Call, CommandRunner, Outcome, Output, ProcessRunner},
};
use rmcp::{handler::server::wrapper::Parameters, schemars, tool, tool_router};
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

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AccessScope {
    /// A declared environment; omitted: every environment.
    #[serde(default)]
    environment: Option<String>,
    /// A declared target of that environment: only its deploy identity.
    #[serde(default)]
    target: Option<String>,
    /// As the CLI's --verbose: an error's upstream reply in full.
    #[serde(default)]
    verbose: bool,
}

/// The input of a tool that takes nothing else.
#[derive(Deserialize, schemars::JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct Verbose {
    /// As the CLI's --verbose: an error's upstream reply in full.
    #[serde(default)]
    verbose: bool,
}

#[derive(Clone)]
pub struct Server {
    project: PathBuf,
    gate: Arc<tokio::sync::Mutex<()>>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeploymentPlanScope {
    /// A declared environment name, not a path, command, credential, or value.
    environment: String,
    /// Only these named targets (empty: every target of the environment), as
    /// `opv plan --target` takes them.
    #[serde(default)]
    targets: Vec<String>,
    /// Only this declared product.
    #[serde(default)]
    product: Option<String>,
    /// `PRODUCT/KEY` immutable keys to plan as replaced even though present (`--rotate`).
    #[serde(default)]
    rotate: Vec<String>,
    /// As the CLI's --verbose: an error's upstream reply in full.
    #[serde(default)]
    verbose: bool,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangedScope {
    /// A declared environment name, not a path, command, credential, or value.
    environment: String,
    /// Only these named targets (empty: every target of the environment), as
    /// `opv changed --target` takes them.
    #[serde(default)]
    targets: Vec<String>,
    /// Only this declared product.
    #[serde(default)]
    product: Option<String>,
    /// As the CLI's --verbose: an error's upstream reply in full.
    #[serde(default)]
    verbose: bool,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeliveryPreviewScope {
    /// A declared environment name, not a path, command, credential, or value.
    environment: String,
    /// Only this declared product; omitted: the one product with keys desired here.
    #[serde(default)]
    product: Option<String>,
    /// Only keys that declare this process role (and keys without roles).
    #[serde(default)]
    role: Option<String>,
    /// A reviewed remote profile name of the product (`[products.<p>.remotes.<name>]`):
    /// preview `opv run --remote` instead of a local run. Never a host, path or command.
    #[serde(default)]
    remote: Option<String>,
    /// As the CLI's --verbose: an error's upstream reply in full.
    #[serde(default)]
    verbose: bool,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadyScope {
    /// A declared environment name; omitted: every declared environment.
    #[serde(default)]
    environment: Option<String>,
    /// As the CLI's --verbose: an error's upstream reply in full.
    #[serde(default)]
    verbose: bool,
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

/// `opv_explain`'s input schema: the §25 surface golden's, plus the optional `env` the
/// CLI's `--env` is (a key declared in several environments, and every plan id, need it).
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

    /// The failure answer for `e`: `{ok: false, error}`.
    fn failed(&self, e: &Error) -> Value {
        json!({"ok": false, "error": error_document(e, &self.inv, self.verbose)})
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
const NAME_FORMAT: &str =
    "a declared name: letters, digits, '.', '_', '/' and '-' (opv_configuration lists them)";

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

/// `given` is not one of `fleet`'s environments: the declared ones, and the unique close
/// match when there is one.
fn unknown_env(fleet: &crate::domain::Fleet, given: &str) -> Cause {
    let known: Vec<&str> = fleet.environments.keys().map(String::as_str).collect();
    let close = crate::app::suggest::close(given, known.iter().copied());
    Cause::NotDeclared {
        kind: NameKind::Environment,
        given: given.to_string(),
        candidates: known.iter().map(|s| s.to_string()).collect(),
        closest: Closest::unique(&close),
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

    async fn inspect(&self, operation: Operation, env: Option<String>, verbose: bool) -> String {
        let tool = match operation {
            Operation::Ready => "opv_ready",
            Operation::Configuration => "opv_configuration",
        };
        self.serialized(tool, false, verbose, move |project| {
            inspect(project, operation, env.as_deref(), verbose)
        })
        .await
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
        "the MCP tool stopped before it answered, and its write may have started: check with opv_ready before calling it again"
    } else {
        "the MCP tool stopped before it answered"
    };
    ToolCall::new(tool, &[], Vec::new(), verbose).refused(Cause::Bug { site })
}

#[tool_router(server_handler)]
impl Server {
    #[tool(
        name = "opv_ready",
        description = "Read readiness metadata for one declared environment, or for every environment when none is named: each finding's code, blocking flag, actor, effect and next step (an opv command or a 1Password item link), and each target's state. Never returns a value, message or verification text. Humans handle authentication and secret entry. No changes are authorized.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn ready(&self, Parameters(args): Parameters<ReadyScope>) -> String {
        self.inspect(Operation::Ready, args.environment, args.verbose)
            .await
    }

    #[tool(
        name = "opv_configuration",
        description = "Inspect declared environment, key and target metadata only: environment names, product/key names and kinds, each target's provider and delivered products, whether each environment requires confirmation, and whether each target's state vault and deploy credentials are recorded. No values, rules, vault identifiers, locators, credential references, or configuration export.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn configuration(&self, Parameters(args): Parameters<Verbose>) -> String {
        self.inspect(Operation::Configuration, None, args.verbose)
            .await
    }

    #[tool(
        name = "opv_deployment_plan",
        description = "Preview deployment actions without executing them, for the whole environment or only the given targets, product and immutable keys to rotate (`PRODUCT/KEY`): each row's target, product, key and action, the plan_id, and the sync_command (`opv sync <env> --expect-plan <plan_id>` with the same --target, --product and --rotate) a person runs in their own terminal, or CI runs. No tool syncs, deploys, prunes or rotates; secret entry and layout repair stay with the person.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn deployment_plan(&self, Parameters(args): Parameters<DeploymentPlanScope>) -> String {
        let verbose = args.verbose;
        self.serialized("opv_deployment_plan", false, verbose, move |project| {
            deployment_plan(project, &args)
        })
        .await
    }

    #[tool(
        name = "opv_changed",
        description = "Whether a source item in 1Password changed since the last sync, for one declared environment (or only the given targets and product): each placement's product, target and state (unchanged; changed; no_record when no sync recorded its source versions) and, for a changed one, each source item's id with its recorded and current version numbers, plus the next step. Returns item ids and version numbers only, never a value. Changes nothing: a sync is a person's (opv_deployment_plan, then the person's opv sync in their own terminal) or CI's.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn changed(&self, Parameters(args): Parameters<ChangedScope>) -> String {
        let verbose = args.verbose;
        self.serialized("opv_changed", false, verbose, move |project| {
            changed(project, &args)
        })
        .await
    }

    #[tool(
        name = "opv_access",
        description = "Who needs which 1Password vault for CI and deploys, and who can read it now: each identity (a target's deploy identity, an environment's CI reader) with its service-account name, vaults, permissions and state (present, missing, read-only needed, not visible, not in this account), findings with their next step, and for each identity missing a grant the exact owner command that creates it and stores its token as a GitHub secret without showing it (`opv access <env> [--target <t>] --create --github <owner/repo> --github-env <github environment>`; the person runs it, filling in the repository and GitHub environment the CI job uses). Never a token or value. Changes nothing.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn access(&self, Parameters(args): Parameters<AccessScope>) -> String {
        let verbose = args.verbose;
        self.serialized("opv_access", false, verbose, move |project| {
            access_projection(
                project,
                args.environment.as_deref(),
                args.target.as_deref(),
                verbose,
            )
        })
        .await
    }

    #[tool(
        name = "opv_delivery_preview",
        description = "Preview which keys a local `opv run` would deliver for one environment, without reading any value: each key's product, name, source, destination (variable name or relative file path) and declared process roles; the key names a role withholds; the environment mode, the secrets-directory variable, whether RAM-backed file delivery is supported here, and whether the op CLI is present and signed in (unknown when it cannot be determined). With remote (a profile name the product declares), previews `opv run --remote`: the profile's pinned host, user, port, host-key type, working directory and command, and whether ssh is on PATH. Changes nothing; only the person runs opv run (a remote run needs their own terminal; no tool runs it).",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn delivery_preview(&self, Parameters(args): Parameters<DeliveryPreviewScope>) -> String {
        let verbose = args.verbose;
        self.serialized("opv_delivery_preview", false, verbose, move |project| {
            delivery_preview_doc(
                project,
                &args.environment,
                args.product.as_deref(),
                args.role.as_deref(),
                args.remote.as_deref(),
                verbose,
            )
        })
        .await
    }

    #[tool(
        name = "opv_structure_plan",
        description = "Plan the 1Password structure this project's configuration declares: the vaults and items that hold each product's values, state vaults, delivery items and empty fields (names, kinds and public IDs only; never a value). Returns a plan_id. Changes nothing. A person reviews and applies it with `opv apply` in their own terminal.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn structure_plan(&self, Parameters(args): Parameters<Verbose>) -> String {
        let verbose = args.verbose;
        self.serialized("opv_structure_plan", false, verbose, move |project| {
            structure_plan(project, verbose)
        })
        .await
    }

    #[tool(
        name = "opv_propose",
        description = "Propose a change to this project's contract from one intent document (kind key, env, target, retire, setup, structure or generate; tidy is not available here): names, enumerated attributes and catalog shape names only, never a rule parameter (regex, prefix, enum) or a value. Returns the same document as `opv propose <kind> --json`: the relaxations it makes (listed first), the contract diff or the structure steps, the questions it asks, and a plan_id that only a person's `opv apply <plan_id>` runs. Pure: writes neither the contract nor 1Password.",
        input_schema = propose_schema(),
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn propose(&self, Parameters(args): Parameters<rmcp::model::JsonObject>) -> String {
        self.serialized("opv_propose", false, false, move |project| {
            let r = read_only(PROPOSE_BUDGET);
            let answer = propose_doc(project, &r, &args);
            if r.refused.load(Ordering::Relaxed) {
                return propose_call(&args).refused(write_refused());
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

/// Each `--rotate` entry is `PRODUCT/KEY`, both declared-name identifiers.
fn rotate_ok(rotate: &[String]) -> bool {
    rotate.iter().all(|r| {
        r.split_once('/')
            .is_some_and(|(p, k)| identifier(p) && identifier(k))
    })
}

/// Why a sync or plan scope's names are refused, when they are: a name that is not one, a
/// rotate entry that is not `PRODUCT/KEY`, or more than 20 targets or rotate entries.
fn scope_refusal(
    environment: &str,
    targets: &[String],
    product: Option<&String>,
    rotate: &[String],
) -> Option<Cause> {
    if !identifier(environment) {
        return Some(not_a_name("environment"));
    }
    if targets.iter().any(|t| !identifier(t)) {
        return Some(not_a_name("targets"));
    }
    if product.is_some_and(|p| !identifier(p)) {
        return Some(not_a_name("product"));
    }
    if !rotate_ok(rotate) {
        return Some(usage(
            "rotate",
            "PRODUCT/KEY entries of declared names (opv_configuration lists them)",
        ));
    }
    if targets.len() > 20 {
        return Some(usage("targets", "at most 20 names"));
    }
    if rotate.len() > 20 {
        return Some(usage("rotate", "at most 20 entries"));
    }
    None
}

/// `--target t… --product p --rotate P/K…` words.
fn scope_flags(targets: &[String], product: Option<&String>, rotate: &[String]) -> Vec<String> {
    let mut args = Vec::new();
    for t in targets {
        args.extend(["--target".to_string(), t.clone()]);
    }
    if let Some(p) = product {
        args.extend(["--product".to_string(), p.clone()]);
    }
    for k in rotate {
        args.extend(["--rotate".to_string(), k.clone()]);
    }
    args
}

#[derive(Clone, Copy)]
enum Operation {
    Ready,
    Configuration,
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

fn inspect(
    project: &std::path::Path,
    operation: Operation,
    env: Option<&str>,
    verbose: bool,
) -> Value {
    let (tool, command): (&str, &[&str]) = match operation {
        Operation::Ready => ("opv_ready", &["ready"]),
        Operation::Configuration => ("opv_configuration", &["contract"]),
    };
    if env.is_some_and(|e| !identifier(e)) {
        return ToolCall::new(tool, command, Vec::new(), verbose)
            .refused(not_a_name("environment"));
    }
    let call = ToolCall::new(
        tool,
        command,
        env.map(str::to_string).into_iter().collect(),
        verbose,
    );
    let r = read_only(INSPECT_BUDGET);
    let fleet = match load_fleet(project, &r) {
        Ok(fleet) => fleet,
        Err(e) => return call.failed(&e),
    };
    if let Some(env) = env
        && !fleet.environments.contains_key(env)
    {
        return call.refused(unknown_env(&fleet, env));
    }
    if matches!(operation, Operation::Configuration) {
        return configuration_projection(&fleet);
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    let result = crate::app::ready::run(&fleet, None, env, &r, true, None, false, &mut *bytes);
    receipt_answer(&call, &r, &bytes, result, ready_receipt)
}

/// The answer for a CLI document in `bytes` that `result` produced on `r`: a refused write
/// needs a person's terminal, an unreadable document is the error (or opv's own fault),
/// else `project` of it. When `result` failed, the projection is marked failed and carries
/// the error, and its success `human_action` is dropped: it no longer applies.
fn receipt_answer<R: CommandRunner>(
    call: &ToolCall,
    r: &ReadOnly<R>,
    bytes: &[u8],
    result: Result<(), Error>,
    project: impl FnOnce(&Value) -> Option<Value>,
) -> Value {
    if r.refused.load(Ordering::Relaxed) {
        return call.refused(write_refused());
    }
    let mut doc: Value = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(_) => {
            return match result {
                Err(e) => call.failed(&e),
                Ok(()) => call.refused(UNREADABLE_REPORT),
            };
        }
    };
    let projected = project(&doc);
    crate::scrub::wipe_json(&mut doc);
    let Some(mut response) = projected else {
        return call.refused(UNREADABLE_REPORT);
    };
    if let Err(error) = result {
        response["ok"] = json!(false);
        if let Some(o) = response.as_object_mut() {
            o.remove("human_action");
        }
        response["error"] = error_document(&error, &call.inv, call.verbose);
    }
    response
}

/// `opv_deployment_plan`: the plan `opv plan <env> [--target t]… [--product p] [--rotate
/// P/K]… --json` prints ([`crate::app::sync::plan_rotating`]), projected, with the
/// `sync_command` for exactly that scope.
fn deployment_plan(project: &std::path::Path, args: &DeploymentPlanScope) -> Value {
    if let Some(refused) = scope_refusal(
        &args.environment,
        &args.targets,
        args.product.as_ref(),
        &args.rotate,
    ) {
        return ToolCall::new("opv_deployment_plan", &["plan"], Vec::new(), args.verbose)
            .refused(refused);
    }
    let r = read_only(INSPECT_BUDGET);
    let fleet = match load_fleet(project, &r) {
        Ok(fleet) => fleet,
        Err(e) => return plan_call(args).failed(&e),
    };
    deployment_plan_from_fleet(&fleet, args, &r)
}

/// `opv_deployment_plan`'s call: `opv plan <env>` with its scope (names already checked).
fn plan_call(args: &DeploymentPlanScope) -> ToolCall {
    let mut words = vec![args.environment.clone()];
    words.extend(scope_flags(
        &args.targets,
        args.product.as_ref(),
        &args.rotate,
    ));
    ToolCall::new("opv_deployment_plan", &["plan"], words, args.verbose)
}

/// [`deployment_plan`] on an already-loaded fleet and the read-only runner `r`.
fn deployment_plan_from_fleet<R: CommandRunner>(
    fleet: &crate::domain::Fleet,
    args: &DeploymentPlanScope,
    r: &ReadOnly<R>,
) -> Value {
    let call = plan_call(args);
    if !fleet.environments.contains_key(&args.environment) {
        return call.refused(unknown_env(fleet, &args.environment));
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    let result = crate::app::sync::plan_rotating(
        fleet,
        &args.environment,
        &args.targets,
        args.product.as_deref(),
        &args.rotate,
        r,
        &mut *bytes,
        true,
    )
    .map_err(|e| e.in_env(&args.environment));
    receipt_answer(&call, r, &bytes, result, |doc| plan_receipt(doc, args))
}

/// `opv_changed`'s call: `opv changed <env>` with its targets and product (names already
/// checked).
fn changed_call(args: &ChangedScope) -> ToolCall {
    let mut words = vec![args.environment.clone()];
    words.extend(scope_flags(&args.targets, args.product.as_ref(), &[]));
    ToolCall::new("opv_changed", &["changed"], words, args.verbose)
}

/// `opv_changed`: the document `opv changed <env> [--target t]… [--product p] --json` prints
/// ([`crate::app::changed::run`]) on the read-only runner, projected. A changed source item
/// (the CLI's exit 10) is a successful answer; any other failure is the CLI's `error`.
fn changed(project: &std::path::Path, args: &ChangedScope) -> Value {
    if let Some(refused) =
        scope_refusal(&args.environment, &args.targets, args.product.as_ref(), &[])
    {
        return ToolCall::new("opv_changed", &["changed"], Vec::new(), args.verbose)
            .refused(refused);
    }
    let call = changed_call(args);
    let r = read_only(INSPECT_BUDGET);
    let fleet = match load_fleet(project, &r) {
        Ok(fleet) => fleet,
        Err(e) => return call.failed(&e),
    };
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    let result = crate::app::changed::run(
        &fleet,
        &args.environment,
        args.product.as_deref(),
        &args.targets,
        &r,
        true,
        &mut *bytes,
    )
    .map(|_exit| ());
    receipt_answer(&call, &r, &bytes, result, changed_receipt)
}

/// One placement of the `opv changed --json` document, field by field: checked names, one
/// of the three states, and each moved item's id and version numbers.
fn changed_placement(p: &Value) -> Option<Value> {
    let product = p["product"].as_str().filter(|s| identifier(s))?;
    let target = p["target"].as_str().filter(|s| identifier(s))?;
    let state = p["state"]
        .as_str()
        .filter(|s| ["unchanged", "changed", "no_record"].contains(s))?;
    let mut out = json!({"product": product, "target": target, "state": state});
    let items: Vec<Value> = p["items"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|i| {
            let id = i["item_id"]
                .as_str()
                .filter(|s| s.len() <= 64 && crate::config::is_id(s))?;
            let mut item = json!({"item_id": id, "recorded": i["recorded"].as_u64()?});
            if let Some(current) = i["current"].as_u64() {
                item["current"] = json!(current);
            }
            Some(item)
        })
        .collect();
    if !items.is_empty() {
        out["items"] = json!(items);
    }
    Some(out)
}

/// The `opv changed --json` document as the MCP answer: a new response built field by
/// field, never a value.
fn changed_receipt(doc: &Value) -> Option<Value> {
    if doc.get("schema_version").and_then(Value::as_u64)
        != Some(u64::from(crate::json::SCHEMA_VERSION))
    {
        return None;
    }
    let environment = doc["environment"].as_str().filter(|e| identifier(e))?;
    let changed = doc["changed"].as_bool()?;
    let placements: Vec<Value> = doc["placements"]
        .as_array()?
        .iter()
        .filter_map(changed_placement)
        .collect();
    // opv's own step, rendered from checked names: one line. The CLI frames `next` (§4.1)
    // as the schema-3 object, so read its command.
    let one_line = |s: &str| s.len() <= 300 && !s.chars().any(char::is_control);
    let step = |k: &str| doc[k].as_str().filter(|s| one_line(s));
    let next = crate::json::command_of(&doc["next"]).filter(|s| one_line(s));
    Some(json!({
        "ok": true,
        "environment": environment,
        "changed": changed,
        "placements": placements,
        "next": next,
        "do": step("do"),
        "human_action": "Item ids and version numbers only. A sync is a person's or CI's: call opv_deployment_plan, and the person runs its sync_command in their own terminal.",
    }))
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

/// `opv_delivery_preview`'s call: `opv run <env> --preview` with its product, role and
/// remote (names already checked).
fn preview_call(
    environment: &str,
    product: Option<&str>,
    role: Option<&str>,
    remote: Option<&str>,
    verbose: bool,
) -> ToolCall {
    let mut words = vec![environment.to_string(), "--preview".to_string()];
    for (flag, v) in [
        ("--product", product),
        ("--role", role),
        ("--remote", remote),
    ] {
        if let Some(v) = v {
            words.extend([flag.to_string(), v.to_string()]);
        }
    }
    ToolCall::new("opv_delivery_preview", &["run"], words, verbose)
}

/// `opv_delivery_preview`: validate the names with [`identifier`], load the project's
/// configuration on a read-only runner, then answer with the shared preview document.
fn delivery_preview_doc(
    project: &std::path::Path,
    environment: &str,
    product: Option<&str>,
    role: Option<&str>,
    remote: Option<&str>,
    verbose: bool,
) -> Value {
    let bad = [
        ("environment", Some(environment)),
        ("product", product),
        ("role", role),
        ("remote", remote),
    ]
    .into_iter()
    .find(|(_, v)| v.is_some_and(|v| !identifier(v)));
    if let Some((field, _)) = bad {
        return ToolCall::new("opv_delivery_preview", &["run"], Vec::new(), verbose)
            .refused(not_a_name(field));
    }
    let r = read_only(INSPECT_BUDGET);
    let fleet = match load_fleet(project, &r) {
        Ok(fleet) => fleet,
        Err(e) => {
            return preview_call(environment, product, role, remote, verbose).failed(&e);
        }
    };
    delivery_preview_from_fleet(&fleet, environment, product, role, remote, &r, verbose)
}

/// The MCP answer from an already-loaded fleet: the same document the CLI's
/// `opv run --preview --json` prints ([`crate::app::delivery_preview::build`]), or its
/// failure.
fn delivery_preview_from_fleet(
    fleet: &crate::domain::Fleet,
    environment: &str,
    product: Option<&str>,
    role: Option<&str>,
    remote: Option<&str>,
    runner: &dyn CommandRunner,
    verbose: bool,
) -> Value {
    let call = preview_call(environment, product, role, remote, verbose);
    if !fleet.environments.contains_key(environment) {
        return call.refused(unknown_env(fleet, environment));
    }
    match crate::app::delivery_preview::build_for(fleet, environment, product, role, remote, runner)
    {
        Ok(doc) => doc,
        Err(e) => call.failed(&e),
    }
}

/// `opv_access`'s runner budget: above the 1Password app's approval wait
/// ([`crate::adapters::onepassword::APPROVAL_TIMEOUT`]), so the session check that follows
/// a `wake` waiting on the app's prompt still has time to run.
const ACCESS_BUDGET: Duration = Duration::from_secs(120);

/// `opv access` as checked identifiers: what each CI or deploy identity needs, its state,
/// and the owner's `opv access … --create` command for each identity missing a grant.
fn access_projection(
    project: &std::path::Path,
    env: Option<&str>,
    target: Option<&str>,
    verbose: bool,
) -> Value {
    let bare = || ToolCall::new("opv_access", &["access"], Vec::new(), verbose);
    if env.is_some_and(|e| !identifier(e)) {
        return bare().refused(not_a_name("environment"));
    }
    if target.is_some_and(|t| !identifier(t)) {
        return bare().refused(not_a_name("target"));
    }
    if target.is_some() && env.is_none() {
        return bare().refused(Cause::Usage {
            problem: UsageProblem::NeedsFlag {
                flag: "target".into(),
                needs: "environment".into(),
            },
        });
    }
    let mut words: Vec<String> = env.map(str::to_string).into_iter().collect();
    if let Some(t) = target {
        words.extend(["--target".to_string(), t.to_string()]);
    }
    let call = ToolCall::new("opv_access", &["access"], words, verbose);
    let r = read_only(ACCESS_BUDGET);
    let fleet = match load_fleet(project, &r) {
        Ok(fleet) => fleet,
        Err(e) => return call.failed(&e),
    };
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    let result = crate::app::access::run(&fleet, env, target, None, &r, true, &mut *bytes);
    if r.refused.load(Ordering::Relaxed) {
        return call.refused(write_refused());
    }
    let Ok(doc) = serde_json::from_slice::<Value>(&bytes) else {
        return match result {
            Err(e) => call.failed(&e),
            Ok(()) => call.refused(UNREADABLE_REPORT),
        };
    };
    access_answer(&doc)
}

/// The `opv access --json` document as the MCP answer, field by field (pure).
fn access_answer(doc: &Value) -> Value {
    let id_ok = |s: &str| crate::config::is_id(s) && s.len() <= 64;
    let mut envs = Vec::new();
    let mut any_owner_command = false;
    for e in doc["environments"].as_array().into_iter().flatten() {
        let Some(env_name) = e["environment"].as_str().filter(|n| identifier(n)) else {
            continue;
        };
        let mut identities: Vec<Value> = Vec::new();
        for c in e["report"]["checks"].as_array().into_iter().flatten() {
            let g = &c["grant"];
            let (Some(account), Some(vault)) = (
                g["service_account"].as_str().filter(|n| identifier(n)),
                g["vault_id"].as_str().filter(|v| id_ok(v)),
            ) else {
                continue;
            };
            let kind = g["principal"]["kind"]
                .as_str()
                .filter(|k| ["deploy", "ci_reader"].contains(k));
            let tgt = g["principal"]["target"].as_str().filter(|t| identifier(t));
            let permission = g["permission"]
                .as_str()
                .filter(|p| ["read", "read_write"].contains(p));
            let state = c["state"].as_str().filter(|s| {
                [
                    "present",
                    "missing",
                    "read_only_needed",
                    "not_visible",
                    "not_in_account",
                ]
                .contains(s)
            });
            let grant = json!({"vault_id": vault, "permission": permission, "state": state});
            match identities
                .iter_mut()
                .find(|i| i["service_account"] == account)
            {
                Some(i) => i["grants"].as_array_mut().expect("array").push(grant),
                None => identities.push(json!({
                    "service_account": account, "kind": kind, "target": tgt, "grants": [grant],
                })),
            }
        }
        for i in &mut identities {
            let grants = i["grants"].as_array().cloned().unwrap_or_default();
            let blocked = grants.iter().any(|g| g["state"] == "not_in_account");
            let needs = grants
                .iter()
                .any(|g| g["state"] == "missing" || g["state"] == "read_only_needed");
            let target_flag = i["target"]
                .as_str()
                .map(|t| format!(" --target {t}"))
                .unwrap_or_default();
            i["owner_command"] = if needs && !blocked {
                any_owner_command = true;
                json!(format!(
                    "opv access {env_name}{target_flag} --create --github <owner/repo> --github-env <github environment>"
                ))
            } else {
                Value::Null
            };
        }
        let findings: Vec<Value> = e["findings"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|f| {
                let code = f["code"].as_str().filter(|c| identifier(c))?;
                let next = f["next"]
                    .as_str()
                    .filter(|n| n.starts_with("opv ") && n.len() <= 200 && !n.contains('\n'));
                Some(json!({"code": code, "next": next}))
            })
            .collect();
        // What was checked and what could not be classified, as the CLI prints them: an
        // answer whose every grant is not_visible checked nothing.
        let count = |field: &str| e["report"][field].as_u64();
        envs.push(json!({
            "environment": env_name,
            "identities": identities,
            "findings": findings,
            "checked": count("checked"),
            "unclassified": count("unclassified"),
        }));
    }
    let human_action = if any_owner_command {
        "Creating an identity is the person's: they run its owner_command in their own terminal, with the GitHub repository and GitHub environment their CI job uses. The token goes to GitHub without being shown; never ask for it."
    } else {
        "No identity needs a grant created here; act on findings by their next step. Never ask for a token."
    };
    json!({
        "ok": true,
        "environments": envs,
        "changes_available": false,
        "human_action": human_action,
    })
}

fn structure_plan(project: &std::path::Path, verbose: bool) -> Value {
    let call = ToolCall::new(
        "opv_structure_plan",
        &["propose", "structure"],
        Vec::new(),
        verbose,
    );
    let r = read_only(Duration::from_secs(60));
    let planned =
        crate::app::structure::scope_as(project, &r, "propose structure").and_then(|scope| {
            r.inner.use_account(Some(scope.account.clone()));
            let text = match &scope.config {
                crate::app::structure::ConfigAt::File(path) => std::fs::read_to_string(path)
                    .map_err(|e| -> Error {
                        Cause::ConfigUnreadable {
                            path: path.clone(),
                            io: e.kind().into(),
                            given_by: crate::cause::GivenBy::Discovered,
                        }
                        .into()
                    })?,
                manifest => manifest.read_merged(&r)?,
            };
            crate::app::structure::plan(&r, &text, &scope.project, &scope.account)
        });
    if r.refused.load(Ordering::Relaxed) {
        return call.refused(write_refused());
    }
    match planned {
        Ok(p) => plan_projection(&p),
        Err(e) => call.failed(&e),
    }
}

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

/// What `kind` must be: `tidy` has no proposal yet (its schema arm stays, as the intent
/// document's), so it is refused naming itself.
const PROPOSE_KIND_FORMAT: &str = "one of key, env, target, retire, setup, structure or generate (kind tidy is not available: it has no proposal yet; a person runs opv tidy <env>)";

/// `opv_propose`'s call: `opv propose <kind> --json`, with the kind when it is one.
fn propose_call(args: &rmcp::model::JsonObject) -> ToolCall {
    let kind = args
        .get("kind")
        .and_then(Value::as_str)
        .filter(|k| PROPOSE_KINDS.contains(k) || *k == "tidy");
    let command: Vec<&str> = std::iter::once("propose").chain(kind).collect();
    ToolCall::new("opv_propose", &command, Vec::new(), false)
}

/// `opv_propose`: the intent document parsed (an unknown field, such as a rule parameter,
/// is refused naming itself), then the library proposal for its kind, as the `--json`
/// document `opv propose <kind>` prints. Pure: `r` only reads, and nothing is written.
fn propose_doc<R: Accounted>(
    project: &std::path::Path,
    r: &R,
    args: &rmcp::model::JsonObject,
) -> Value {
    let call = propose_call(args);
    let res = crate::domain::intent::parse(&Value::Object(args.clone()).to_string())
        .and_then(|intent| proposal(project, r, &intent));
    match res {
        Ok(doc) => call.document(doc.to_string().as_bytes(), Ok(())),
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
/// person's `opv apply` as `next`. A contract proposal has no `next` here: the CLI's is its
/// own command line with `--write`, which a person runs.
fn proposal<R: Accounted>(
    project: &std::path::Path,
    r: &R,
    intent: &crate::domain::intent::Intent,
) -> Result<Value, Error> {
    use crate::app::propose::{key, setup, target};
    use crate::domain::intent::Intent;
    let unwritten = |mut doc: Value| {
        doc["written"] = Value::Null;
        doc
    };
    match intent {
        Intent::Key { .. } | Intent::Env { .. } | Intent::Retire { .. } | Intent::Target { .. } => {
            let (text, ids, rules) = contract_for_proposal(project, r)?;
            let base = rules.as_ref().and_then(|s| s.contract());
            let proposal = if matches!(intent, Intent::Target { .. }) {
                target::propose(&text, &ids, base, intent)
            } else {
                key::propose(&text, &ids, base, intent)
            }
            .map_err(proposal_refused)?;
            to_doc(&proposal).map(unwritten)
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
        Intent::Tidy { .. } => Err(usage("kind", PROPOSE_KIND_FORMAT).into()),
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
fn contract_for_proposal<R: Accounted>(
    project: &std::path::Path,
    r: &R,
) -> Result<
    (
        String,
        crate::config::bindings::Bindings,
        Option<crate::app::rule_source::RuleSource>,
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
    Ok((contract, ids, rules))
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
    );
    call.document(&out, res)
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
            "[product/]KEY, a declared key (opv_configuration lists them)",
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

/// The next step an assistant may repeat for a finding: an `opv` command, or a 1Password
/// item link, and nothing else. A raw `op` command, a value or any other text becomes null.
fn ready_step(prerequisite: &str) -> Option<String> {
    let opv = prerequisite.starts_with("opv ")
        && !prerequisite.contains('\n')
        && prerequisite.len() <= 200;
    let link = prerequisite.starts_with("https://start.1password.com/open/i?")
        && prerequisite
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/:?=&._-".contains(&b));
    (opv || link).then(|| prerequisite.to_string())
}

/// One receipt finding as the MCP answer: checked fields only, never its message or
/// verification text. Scope fields that are not identifiers are dropped.
fn ready_finding(f: &Value) -> Value {
    let mut finding = json!({"blocking": f["blocking"].as_bool().unwrap_or(false)});
    if let Some(code) = f["code"].as_str().filter(|c| identifier(c)) {
        finding["code"] = json!(code);
    }
    for field in ["environment", "target", "product", "key"] {
        if let Some(v) = f["scope"][field].as_str().filter(|v| identifier(v)) {
            finding[field] = json!(v);
        }
    }
    if let Some(actor) = f["actor"]
        .as_str()
        .filter(|a| ["owner", "agent", "ci"].contains(a))
    {
        finding["actor"] = json!(actor);
    }
    if let Some(effect) = f["effect"].as_str().filter(|e| {
        [
            "none",
            "signs_in",
            "writes_1password",
            "writes_target",
            "writes_config",
        ]
        .contains(e)
    }) {
        finding["effect"] = json!(effect);
    }
    finding["step"] = json!(f["prerequisite"].as_str().and_then(ready_step));
    finding
}

/// One receipt target as the MCP answer: its state, never its locator or reason.
fn ready_target(t: &Value) -> Option<Value> {
    let environment = t["environment"].as_str().filter(|v| identifier(v))?;
    let name = t["name"].as_str().filter(|v| identifier(v))?;
    let mut target = json!({"environment": environment, "name": name});
    if let Some(state) = t["state"]
        .as_str()
        .filter(|s| ["ready", "grants_missing"].contains(s))
    {
        target["state"] = json!(state);
    }
    if let Some(evidence) = t["evidence_write"]
        .as_str()
        .filter(|s| ["not_verified", "verified"].contains(s))
    {
        target["evidence_write"] = json!(evidence);
    }
    Some(target)
}

/// The `opv ready --json` receipt as the MCP answer: a new response, never recursively
/// forwarding arbitrary upstream fields.
fn ready_receipt(doc: &Value) -> Option<Value> {
    if doc.get("schema_version").and_then(Value::as_u64)
        != Some(u64::from(crate::json::SCHEMA_VERSION))
    {
        return None;
    }
    let findings = doc.get("findings").and_then(Value::as_array)?;
    if findings.iter().any(|f| !f["blocking"].is_boolean()) {
        return None;
    }
    let projected: Vec<Value> = findings.iter().map(ready_finding).collect();
    let targets: Vec<Value> = doc["targets"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(ready_target)
        .collect();
    Some(json!({
        "ok": true,
        "blocking_findings": findings.iter().filter(|f| f["blocking"] == true).count(),
        "other_findings": findings.iter().filter(|f| f["blocking"] == false).count(),
        "findings": projected,
        "targets": targets,
        "human_action": "Use opv ready in your terminal for details; humans authenticate and enter values in 1Password.",
        "snapshot_only": true,
    }))
}

/// The `opv sync <env> --expect-plan <plan_id>` command for exactly `scope` (design §25.3:
/// a person runs it in their own terminal, or CI syncs; no tool syncs).
fn sync_command(plan_id: &str, scope: &DeploymentPlanScope) -> String {
    let mut args = vec![
        scope.environment.clone(),
        "--expect-plan".into(),
        plan_id.to_string(),
    ];
    args.extend(scope_flags(
        &scope.targets,
        scope.product.as_ref(),
        &scope.rotate,
    ));
    render::cmd_text(&Cmd {
        command: vec!["sync".into()],
        args,
    })
}

/// The `opv plan --json` document as the MCP answer, field by field, with the
/// `sync_command` for exactly `scope` (its targets, product and rotate entries).
fn plan_receipt(doc: &Value, scope: &DeploymentPlanScope) -> Option<Value> {
    if doc.get("schema_version").and_then(Value::as_u64)
        != Some(u64::from(crate::json::SCHEMA_VERSION))
    {
        return None;
    }
    let rows = doc.get("rows").and_then(Value::as_array)?;
    let rows: Vec<_> = rows
        .iter()
        .filter_map(|row| {
            let product = row["product"].as_str();
            let key = row["key"].as_str()?;
            if product.is_some_and(|p| !identifier(p)) || !identifier(key) {
                return None;
            }
            // What sync would do with the row: the plan's own words, or none.
            let action = match row["action"].as_str() {
                Some("would_stage") => "write",
                Some("would_prune") => "unset",
                Some("held") => "hold",
                None => "none",
                Some(_) => "review",
            };
            let target = row["target"].as_str().filter(|t| identifier(t));
            Some(json!({"target": target, "product": product, "key": key, "action": action}))
        })
        .collect();
    let plan_id = doc["plan_id"]
        .as_str()
        .filter(|s| s.len() <= 64 && s.bytes().all(|b| b.is_ascii_hexdigit()));
    let names = |field: &str| -> Vec<&str> {
        doc[field]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter(|name| identifier(name))
            .collect()
    };
    let sync = plan_id.map(|id| sync_command(id, scope));
    Some(
        json!({"ok": true, "rows": rows, "stage": names("stage"), "prune": names("prune"), "plan_id": plan_id, "sync_command": sync, "human_action": "A person runs sync_command in their own terminal (adding --deploy or --prune there to allow those), or CI syncs; it runs exactly this plan and refuses one that changed. No tool syncs, deploys, prunes or rotates."}),
    )
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
    #[test]
    fn readiness_drops_value_bearing_and_untrusted_fields() {
        let doc = json!({"schema_version": 3, "findings": [{"blocking": true, "message": "SECRET_MARKER", "prerequisite": "SECRET_MARKER"}], "value": "SECRET_MARKER"});
        assert!(
            !ready_receipt(&doc)
                .unwrap_or_default()
                .to_string()
                .contains("SECRET_MARKER")
        );
    }
    #[test]
    fn plan_drops_values_even_when_the_source_contains_them() {
        let doc = json!({"schema_version": 3, "rows": [{"product": "api", "key": "API_KEY", "action": "stage", "value": "SECRET_MARKER", "reason": "SECRET_MARKER"}], "plan_id": "123abc"});
        assert!(
            !plan_receipt(&doc, &plan_scope(&[], None, &[]))
                .unwrap_or_default()
                .to_string()
                .contains("SECRET_MARKER")
        );
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

    fn access_doc(state: &str, value_in_message: &str) -> Value {
        json!({"environments": [{
            "environment": "staging",
            "report": {"checks": [
                {"grant": {"principal": {"kind": "deploy", "environment": "staging", "target": "fleet"},
                           "service_account": "shop-staging-fleet-deploy", "vault_id": "vweb", "permission": "read"},
                 "state": state},
                {"grant": {"principal": {"kind": "deploy", "environment": "staging", "target": "fleet"},
                           "service_account": "shop-staging-fleet-deploy", "vault_id": "vstate", "permission": "read_write"},
                 "state": "missing"}
            ], "checked": 2, "unclassified": 1},
            "commands": ["op service-account create x --vault v:read_items"],
            "findings": [{"code": "access_not_visible", "message": value_in_message, "next": "op something raw"}]
        }]})
    }

    #[test]
    fn access_groups_grants_by_identity() {
        let v = access_answer(&access_doc("missing", "m"));
        assert_eq!(
            v["environments"][0]["identities"][0]["grants"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn access_names_the_opv_owner_command_for_a_missing_grant() {
        let v = access_answer(&access_doc("missing", "m"));
        assert_eq!(
            v["environments"][0]["identities"][0]["owner_command"],
            "opv access staging --target fleet --create --github <owner/repo> --github-env <github environment>"
        );
    }

    #[test]
    fn access_offers_no_command_when_a_vault_is_not_in_the_account() {
        let v = access_answer(&access_doc("not_in_account", "m"));
        assert!(v["environments"][0]["identities"][0]["owner_command"].is_null());
    }

    #[test]
    fn access_never_forwards_messages_or_raw_op_commands() {
        let v = access_answer(&access_doc("missing", "SECRET_MARKER"));
        let text = v.to_string();
        assert!(
            !text.contains("SECRET_MARKER")
                && !text.contains("op service-account")
                && !text.contains("op something")
        );
    }

    #[test]
    fn successful_receipt_can_still_have_blocking_findings() {
        let doc = json!({"schema_version": 3, "findings": [{"blocking": true}]});
        assert_eq!(
            ready_receipt(&doc).unwrap_or_default()["blocking_findings"],
            1
        );
    }

    fn ready_doc(findings: Value, targets: Value) -> Value {
        json!({"schema_version": 3, "findings": findings, "targets": targets})
    }

    #[test]
    fn a_ready_scope_without_an_environment_covers_every_environment() {
        let scope: ReadyScope = serde_json::from_value(json!({})).expect("empty scope");
        assert_eq!(scope.environment, None);
    }

    #[test]
    fn a_ready_finding_never_repeats_its_message_or_verify_text() {
        let doc = ready_doc(
            json!([{
                "code": "settings_unhealthy", "scope": {}, "blocking": true,
                "actor": "owner", "effect": "none", "prerequisite": "opv ready",
                "verify": "opv settings show SECRET_MARKER", "message": "SECRET_MARKER"
            }]),
            json!([]),
        );
        assert!(
            !ready_receipt(&doc)
                .unwrap_or_default()
                .to_string()
                .contains("SECRET_MARKER")
        );
    }

    #[test]
    fn a_ready_step_keeps_an_opv_prerequisite() {
        let doc = ready_doc(
            json!([{"code": "grants_missing", "scope": {}, "blocking": true,
                    "prerequisite": "opv access prod --target fleet"}]),
            json!([]),
        );
        assert_eq!(
            ready_receipt(&doc).unwrap_or_default()["findings"][0]["step"],
            "opv access prod --target fleet"
        );
    }

    #[test]
    fn a_ready_step_keeps_a_1password_item_link() {
        let link = "https://start.1password.com/open/i?a=ABC&v=vault1&i=item1";
        let doc = ready_doc(
            json!([{"code": "missing_item", "scope": {}, "blocking": true,
                    "prerequisite": link}]),
            json!([]),
        );
        assert_eq!(
            ready_receipt(&doc).unwrap_or_default()["findings"][0]["step"],
            link
        );
    }

    #[test]
    fn a_ready_step_drops_a_raw_op_command() {
        let doc = ready_doc(
            json!([{"code": "missing_item", "scope": {}, "blocking": true,
                    "prerequisite": "op item edit api --vault core"}]),
            json!([]),
        );
        assert_eq!(
            ready_receipt(&doc).unwrap_or_default()["findings"][0]["step"],
            Value::Null
        );
    }

    #[test]
    fn a_ready_step_drops_other_text() {
        let doc = ready_doc(
            json!([{"code": "missing_item", "scope": {}, "blocking": true,
                    "prerequisite": "sign in with your account"}]),
            json!([]),
        );
        assert_eq!(
            ready_receipt(&doc).unwrap_or_default()["findings"][0]["step"],
            Value::Null
        );
    }

    #[test]
    fn a_ready_finding_drops_an_unknown_actor() {
        let doc = ready_doc(
            json!([{"code": "missing_item", "scope": {}, "blocking": true,
                    "actor": "robot"}]),
            json!([]),
        );
        assert!(
            ready_receipt(&doc).unwrap_or_default()["findings"][0]
                .get("actor")
                .is_none()
        );
    }

    #[test]
    fn a_ready_finding_drops_an_unknown_effect() {
        let doc = ready_doc(
            json!([{"code": "missing_item", "scope": {}, "blocking": true,
                    "effect": "deletes_everything"}]),
            json!([]),
        );
        assert!(
            ready_receipt(&doc).unwrap_or_default()["findings"][0]
                .get("effect")
                .is_none()
        );
    }

    #[test]
    fn a_ready_finding_drops_a_scope_field_that_is_not_an_identifier() {
        let doc = ready_doc(
            json!([{"code": "missing_item", "blocking": true,
                    "scope": {"key": "API KEY with spaces"}}]),
            json!([]),
        );
        assert!(
            ready_receipt(&doc).unwrap_or_default()["findings"][0]
                .get("key")
                .is_none()
        );
    }

    #[test]
    fn a_ready_receipt_without_an_environment_lists_every_environment() {
        let target = |environment: &str| {
            json!({"environment": environment, "name": "fleet", "provider": "fly",
                   "locator": "SECRET_MARKER", "state": "ready",
                   "reason": "SECRET_MARKER", "evidence_write": "not_verified"})
        };
        let doc = ready_doc(json!([]), json!([target("staging"), target("prod")]));
        assert_eq!(
            ready_receipt(&doc).unwrap_or_default()["targets"]
                .as_array()
                .expect("targets")
                .len(),
            2
        );
    }

    #[test]
    fn a_ready_target_carries_only_its_environment_name_state_and_evidence() {
        let doc = ready_doc(
            json!([]),
            json!([{"environment": "prod", "name": "fleet", "provider": "fly",
                    "locator": "SECRET_MARKER", "state": "grants_missing",
                    "reason": "SECRET_MARKER", "evidence_write": "not_verified"}]),
        );
        assert_eq!(
            ready_receipt(&doc).unwrap_or_default()["targets"][0]
                .as_object()
                .expect("object")
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            vec!["environment", "name", "state", "evidence_write"]
        );
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
        assert_eq!(registered, mapped);
    }

    /// #139: the role fleet with one reviewed remote profile for prod's serve role.
    fn remote_fleet() -> crate::domain::Fleet {
        crate::app::testutil::fleet_without_targets(&format!(
            "{}\n[products.allumata.remotes.builder]\nhost = \"builder.example.internal\"\n\
             user = \"dev\"\nhost_key = \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestMarkerHostKey\"\n\
             environments = [\"prod\"]\nopv = \"/usr/local/bin/opv\"\nworkdir = \"/srv/app\"\n\
             command = [\"app\"]\n",
            crate::app::testutil::ROLE_KEYS
        ))
    }

    fn remote_preview(profile: &str) -> Value {
        let r = FakeRunner::new([Output::success(b"{\"user_type\":\"USER\"}".to_vec())]);
        delivery_preview_from_fleet(
            &remote_fleet(),
            "prod",
            Some("allumata"),
            Some("serve"),
            Some(profile),
            &r,
            false,
        )
    }

    #[test]
    fn opv_delivery_preview_previews_a_remote_profile() {
        assert_eq!(remote_preview("builder")["transport"], "remote");
    }

    #[test]
    fn opv_delivery_preview_lists_the_profiles_for_an_unknown_one() {
        assert_eq!(
            remote_preview("elsewhere")["error"]["message"]
                .as_str()
                .map(|m| m.contains("builder")),
            Some(true)
        );
    }

    #[test]
    fn opv_delivery_preview_returns_the_shared_document() {
        let fleet = crate::app::testutil::role_fleet();
        let sign_in = || Output::success(b"{\"user_type\":\"USER\"}".to_vec());
        let r = FakeRunner::new([sign_in(), sign_in()]);
        let via_tool = delivery_preview_from_fleet(
            &fleet,
            "prod",
            Some("allumata"),
            Some("serve"),
            None,
            &r,
            false,
        );
        let via_builder = crate::app::delivery_preview::build(
            &fleet,
            "prod",
            Some("allumata"),
            Some("serve"),
            &r,
        )
        .unwrap();
        assert_eq!(via_tool, via_builder);
    }

    #[test]
    fn opv_delivery_preview_refuses_a_non_identifier_name() {
        let answer =
            delivery_preview_doc(std::path::Path::new("."), "prod!", None, None, None, false);
        assert_eq!(answer["error"]["code"], "usage");
    }

    #[test]
    fn access_reports_how_many_grants_it_checked() {
        let v = access_answer(&access_doc("missing", "m"));
        assert_eq!(v["environments"][0]["checked"], 2);
    }

    #[test]
    fn access_reports_how_many_readers_it_could_not_classify() {
        let v = access_answer(&access_doc("missing", "m"));
        assert_eq!(v["environments"][0]["unclassified"], 1);
    }

    #[test]
    fn an_access_target_that_is_not_a_name_is_a_usage_error() {
        let v = access_projection(
            std::path::Path::new("."),
            Some("prod"),
            Some("no pe"),
            false,
        );
        assert_eq!(v["error"]["code"], "usage");
    }

    #[test]
    fn an_access_target_without_its_environment_is_a_usage_error() {
        let v = access_projection(std::path::Path::new("."), None, Some("fleet"), false);
        assert_eq!(v["error"]["code"], "usage");
    }

    #[test]
    fn access_has_more_budget_than_the_1password_app_approval_wait() {
        assert!(ACCESS_BUDGET > crate::adapters::onepassword::APPROVAL_TIMEOUT);
    }

    #[test]
    fn a_preview_with_an_undeclared_role_lists_the_declared_roles() {
        let fleet = crate::app::testutil::role_fleet();
        let r = FakeRunner::new([]);
        let v = delivery_preview_from_fleet(
            &fleet,
            "prod",
            Some("allumata"),
            Some("nope"),
            None,
            &r,
            false,
        );
        assert!(
            v["error"]["message"]
                .as_str()
                .unwrap()
                .contains("migrate, serve")
        );
    }

    #[test]
    fn a_preview_of_an_undeclared_product_never_asks_for_a_role() {
        let fleet = crate::app::testutil::role_fleet();
        let r = FakeRunner::new([]);
        let v = delivery_preview_from_fleet(&fleet, "prod", Some("nope"), None, None, &r, false);
        assert!(!v["error"]["message"].as_str().unwrap().contains("role"));
    }

    #[test]
    fn a_preview_of_an_undeclared_product_lists_the_products() {
        let fleet = crate::app::testutil::role_fleet();
        let r = FakeRunner::new([]);
        let v = delivery_preview_from_fleet(&fleet, "prod", Some("nope"), None, None, &r, false);
        assert!(v["error"]["message"].as_str().unwrap().contains("allumata"));
    }

    fn plan_scope(targets: &[&str], product: Option<&str>, rotate: &[&str]) -> DeploymentPlanScope {
        DeploymentPlanScope {
            environment: "prod".into(),
            targets: targets.iter().map(|t| t.to_string()).collect(),
            product: product.map(str::to_string),
            rotate: rotate.iter().map(|r| r.to_string()).collect(),
            verbose: false,
        }
    }

    #[test]
    fn a_scoped_deployment_plan_syncs_the_same_targets_product_and_rotation() {
        let doc =
            json!({"schema_version": 3, "environment": "prod", "rows": [], "plan_id": "0123abcd"});
        let v = plan_receipt(&doc, &plan_scope(&["fleet"], Some("api"), &["api/KEY"])).unwrap();
        assert_eq!(
            v["sync_command"],
            "opv sync prod --expect-plan 0123abcd --target fleet --product api --rotate api/KEY"
        );
    }

    #[test]
    fn a_deployment_plan_refuses_a_rotate_entry_that_is_not_product_slash_key() {
        let args = DeploymentPlanScope {
            environment: "prod".into(),
            targets: vec![],
            product: None,
            rotate: vec!["KEY".into()],
            verbose: false,
        };
        assert_eq!(
            scope_refusal(&args.environment, &args.targets, None, &args.rotate).map(|c| c.code()),
            Some("usage")
        );
    }

    #[test]
    fn a_deployment_plan_for_an_undeclared_environment_is_unknown_env() {
        let fleet = crate::app::testutil::role_fleet();
        let r = ReadOnly {
            inner: FakeRunner::new([]),
            refused: AtomicBool::new(false),
        };
        let args = DeploymentPlanScope {
            environment: "nope".into(),
            targets: vec![],
            product: None,
            rotate: vec![],
            verbose: false,
        };
        assert_eq!(
            deployment_plan_from_fleet(&fleet, &args, &r)["error"]["code"],
            "unknown_env"
        );
    }

    #[test]
    fn the_deployment_plan_hands_its_sync_command_to_a_person() {
        let doc = json!({"schema_version": 3, "rows": [], "plan_id": "0123abcd"});
        let v = plan_receipt(&doc, &plan_scope(&[], None, &[])).unwrap();
        assert!(
            v["human_action"]
                .as_str()
                .unwrap()
                .contains("A person runs sync_command")
        );
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

    #[test]
    fn a_ready_finding_keeps_its_target() {
        let doc = ready_doc(
            json!([{"code": "grants_missing", "blocking": true,
                    "scope": {"environment": "prod", "target": "fleet"}}]),
            json!([]),
        );
        assert_eq!(
            ready_receipt(&doc).unwrap_or_default()["findings"][0]["target"],
            "fleet"
        );
    }

    fn tool(command: &[&str], args: &[&str]) -> ToolCall {
        ToolCall::new(
            "opv_deployment_plan",
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
        let call = ToolCall::new("opv_deployment_plan", &["plan"], Vec::new(), true);
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

    // 08 (S2): a plan with blocking keys drops the success hint to sync a plan.
    #[test]
    fn a_failed_plan_drops_the_sync_hint() {
        let r = ReadOnly {
            inner: FakeRunner::new([]),
            refused: AtomicBool::new(false),
        };
        let doc = json!({"schema_version": 3, "rows": [], "plan_id": null}).to_string();
        let v = receipt_answer(
            &tool(&["plan"], &["prod"]),
            &r,
            doc.as_bytes(),
            Err(crate::cause::Cause::ValuesNeeded {
                env: crate::cause::EnvName::new("prod"),
                rows: Vec::new(),
            }
            .into()),
            |d| plan_receipt(d, &plan_scope(&[], None, &[])),
        );
        assert!(v.get("human_action").is_none());
    }

    #[test]
    fn an_unknown_environment_names_the_declared_ones() {
        let fleet = crate::app::testutil::role_fleet();
        assert!(unknown_env(&fleet, "nope").message().contains("prod"));
    }

    fn changed_doc() -> Value {
        json!({"schema_version": 3, "ok": true, "environment": "prod", "changed": true,
            "placements": [{"product": "web", "target": "fly", "state": "changed",
                "items": [{"item_id": "iabc123", "recorded": 3, "current": 4, "value": "SECRET_MARKER"}]},
                {"product": "web", "target": "gh", "state": "no_record"}],
            "next": "opv plan prod", "do": "review the plan", "value": "SECRET_MARKER"})
    }

    #[test]
    fn a_changed_source_is_an_ok_answer() {
        assert_eq!(changed_receipt(&changed_doc()).unwrap()["ok"], true);
    }

    #[test]
    fn a_changed_answer_keeps_each_items_versions() {
        assert_eq!(
            changed_receipt(&changed_doc()).unwrap()["placements"][0]["items"],
            json!([{"item_id": "iabc123", "recorded": 3, "current": 4}])
        );
    }

    #[test]
    fn a_changed_answer_drops_values_even_when_the_source_contains_them() {
        assert!(
            !changed_receipt(&changed_doc())
                .unwrap_or_default()
                .to_string()
                .contains("SECRET_MARKER")
        );
    }

    #[test]
    fn a_changed_answer_drops_a_placement_with_an_unknown_state() {
        let mut doc = changed_doc();
        doc["placements"][1]["state"] = json!("SECRET_MARKER");
        assert_eq!(
            changed_receipt(&doc).unwrap()["placements"]
                .as_array()
                .map(Vec::len),
            Some(1)
        );
    }

    #[test]
    fn a_changed_scope_with_a_target_that_is_not_a_name_is_usage() {
        let args = ChangedScope {
            environment: "prod".into(),
            targets: vec!["not a name".into()],
            product: None,
            verbose: false,
        };
        assert_eq!(
            changed(std::path::Path::new("/nonexistent"), &args)["error"]["code"],
            "usage"
        );
    }
}

#[cfg(test)]
#[path = "mcp_propose_tests.rs"]
mod propose_tests;
