//! MCP tools. The inspection tools are read-only: no value-bearing operation or mutation is
//! exposed, and their runner refuses every write beneath the application code.
//!
//! The structural tools (#133) plan and apply structure only (vaults, items, empty fields,
//! delivery items; never a value). `opv_structure_plan` runs on the same read-only runner.
//! `opv_structure_apply` writes only a plan a person approved in their own terminal
//! (`opv approve <plan_id>`, single use, bound to the project and 1Password account), and
//! only through the 1Password app's own authorization: it refuses to run with a session
//! token, service account or Connect credential in its environment.
//!
//! A success answer is one projection per tool, built field by field from checked
//! identifiers; never a value. A failure answer is `{ok: false, error}`, where `error` is
//! exactly the `--json` document's error object (design `docs/design/error-catalog.md`
//! §7.2): code, category, message, subject, evidence (the upstream reply marked
//! `untrusted: true`), retry, human_required, do, next and next_kind, rendered from the
//! cause against the tool's own invocation ([`ToolCall`]). Every tool takes `verbose`, as
//! the CLI's `--verbose`: the upstream reply in full rather than its last lines.
use crate::{
    app::agent_view::{applied_projection, configuration_projection, identifier, plan_projection},
    cause::{
        Cause, Closest, Cmd, CommandId, EnvName, Guard, Invocation, NameKind, Origin, PlanId,
        PlanScope, Principal, ProductKey, ProductName, TargetName, UsageProblem, VarName, render,
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

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApplyArgs {
    /// The plan id opv_structure_plan returned and a person approved with opv approve.
    plan_id: String,
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

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeclareKey {
    /// Product name.
    product: String,
    /// Key name (the variable name the app reads), never its value.
    key: String,
    /// `secret` or `config`.
    kind: String,
    /// Environments that need the key; empty means every declared environment.
    #[serde(default)]
    environments: Vec<String>,
    /// Validation rules, as `opv add --rule` takes them (`prefix=sk_`, `https_url`).
    #[serde(default)]
    rules: Vec<String>,
    /// One line telling the person where to get the value (never the value).
    #[serde(default)]
    guidance: Option<String>,
    /// The value must never change once set (rotation needs a person's approval).
    #[serde(default)]
    immutable: bool,
    /// As the CLI's --verbose: an error's upstream reply in full.
    #[serde(default)]
    verbose: bool,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeclareEnvironment {
    /// New environment name (`^[a-z][a-z0-9-]*$`).
    environment: String,
    /// As the CLI's --verbose: an error's upstream reply in full.
    #[serde(default)]
    verbose: bool,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeclareTarget {
    /// Declared environment.
    environment: String,
    /// New target name (`^[a-z][a-z0-9-]*$`).
    target: String,
    /// `fly`, `azure`, `kubernetes` or `github`; inferred from the options when omitted.
    #[serde(default)]
    provider: Option<String>,
    /// Provider options by flag name, as `opv target add` takes them (`fly-app`): public
    /// names only. Deploy credentials are refused.
    #[serde(default)]
    options: std::collections::BTreeMap<String, String>,
    /// Products it delivers; empty means every product except source-only ones.
    #[serde(default)]
    products: Vec<String>,
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

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GenerateScope {
    /// A declared environment whose empty fields receive the generated values.
    environment: String,
    /// One to twenty `product/KEY` names (never a value), each declared for the environment
    /// with a `base64_bytes` or `hex_bytes` rule.
    keys: Vec<String>,
    /// As the CLI's --verbose: an error's upstream reply in full.
    #[serde(default)]
    verbose: bool,
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
    pub fn new(project: PathBuf) -> Self {
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
        description = "Preview deployment actions without executing them, for the whole environment or only the given targets, product and immutable keys to rotate (`PRODUCT/KEY`): each row's target, product, key and action, the plan_id, and the approve_command (with the same --target, --product and --rotate) a person runs in their own terminal. Sync, deploy, prune and rotation run only through an approved opv_sync (which never prunes an immutable key); secret entry and layout repair stay with the person.",
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
        description = "Plan the 1Password structure this project's configuration declares: the vaults and items that hold each product's values, state vaults, delivery items and empty fields (names, kinds and public IDs only; never a value). Returns a plan_id. Changes nothing. A person reviews and approves it with `opv approve <plan_id>` in their own terminal before opv_structure_apply can create it.",
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
        name = "opv_structure_apply",
        description = "Create exactly the structural plan plan_id, which a person approved with `opv approve <plan_id>` in their own terminal (single use, 15 minutes, this project and account only). Refuses a stale or unapproved plan. Creates vaults, items, delivery items and empty fields only: never reads, writes or returns a value, never deletes, grants access, syncs or deploys. The 1Password app asks the person to authorize the writes. Returns created public IDs and 1Password links where the person enters values.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    async fn structure_apply(&self, Parameters(args): Parameters<ApplyArgs>) -> String {
        let verbose = args.verbose;
        self.serialized("opv_structure_apply", true, verbose, move |project| {
            structure_apply(project, &args.plan_id, verbose)
        })
        .await
    }

    #[tool(
        name = "opv_declare_key",
        description = "Declare a key, or extend one, in this project's secrets.toml: name, kind, environments, validation rules, one line of guidance, immutable. Names and rules only; never a value, never a shared or personal key. Edits the local file only; the empty 1Password field comes from the next approved structural plan.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    async fn declare_key(&self, Parameters(args): Parameters<DeclareKey>) -> String {
        let verbose = args.verbose;
        self.serialized("opv_declare_key", true, verbose, move |project| {
            declare_key(project, args)
        })
        .await
    }

    #[tool(
        name = "opv_declare_environment",
        description = "Declare an environment in this project's secrets.toml. Edits the local file only; the vaults and items that hold its values come from the next approved structural plan.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    async fn declare_environment(
        &self,
        Parameters(args): Parameters<DeclareEnvironment>,
    ) -> String {
        let verbose = args.verbose;
        self.serialized("opv_declare_environment", true, verbose, move |project| {
            declare_environment(project, &args.environment, verbose)
        })
        .await
    }

    #[tool(
        name = "opv_declare_target",
        description = "Declare a new named deploy target in this project's secrets.toml (provider and public options such as the Fly app, the products it delivers). Never changes an existing target (refused as already_declared) and never takes deploy credentials. Edits the local file only; its state vault and delivery items come from the next approved structural plan. Syncing or deploying to it stays a separately approved step.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    async fn declare_target(&self, Parameters(args): Parameters<DeclareTarget>) -> String {
        let verbose = args.verbose;
        self.serialized("opv_declare_target", true, verbose, move |project| {
            declare_target(project, args)
        })
        .await
    }

    #[tool(
        name = "opv_generate",
        description = "Generate self-made secrets (keys whose rules give base64_bytes or hex_bytes) with the OS random source and write them straight into their empty 1Password fields. Writes only empty fields: never replaces an existing value, never deletes, and never returns a value. The 1Password app asks the person to authorize the writes, so the server refuses to run with an op session, service-account or Connect credential in its environment.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false
        )
    )]
    async fn generate(&self, Parameters(args): Parameters<GenerateScope>) -> String {
        let verbose = args.verbose;
        self.serialized("opv_generate", true, verbose, move |project| {
            let call = generate_call(&args.environment, &args.keys, verbose);
            let r = ProcessRunner::new(Budget::starting_now(Duration::from_secs(300)), false);
            let fleet = match load_fleet(project, &r) {
                Ok(fleet) => fleet,
                Err(e) => return call.failed(&e),
            };
            // Writes go to the project's own 1Password account, never op's default.
            match crate::app::structure::binding_as(project, &r, "generate") {
                Ok((_, account)) => r.use_account(Some(account)),
                Err(e) => return call.failed(&e),
            }
            generate(
                &fleet,
                &args.environment,
                &args.keys,
                &r,
                std::env::vars(),
                verbose,
            )
        })
        .await
    }

    #[tool(
        name = "opv_sync",
        description = "Run exactly the deployment (sync) plan plan_id once, after a person approved it in their own terminal with `opv approve <plan_id> --sync <env>` (the approve_command opv_deployment_plan returns, with the same --target, --product, --deploy, --prune and --rotate). Refuses a stale or unapproved plan, writing nothing; the approval is single use and lasts 15 minutes. Rotates only the immutable keys the person approved and never prunes an immutable key. Returns the names written, and the target, product, key and name of each one pruned, pending and held, and whether it deployed; never a value.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false
        )
    )]
    async fn sync(&self, Parameters(args): Parameters<SyncScopeArgs>) -> String {
        let verbose = args.verbose;
        self.serialized("opv_sync", true, verbose, move |project| {
            let r = ProcessRunner::new(Budget::starting_now(Duration::from_secs(900)), false);
            let call = sync_call(&args);
            let fleet = match load_fleet(project, &r) {
                Ok(fleet) => fleet,
                Err(e) => return call.failed(&e),
            };
            let (name, account) = match crate::app::structure::binding_as(project, &r, "sync") {
                Ok(b) => b,
                Err(e) => return call.failed(&e),
            };
            r.use_account(Some(account.clone()));
            sync_approved(
                &fleet,
                &args,
                &name,
                &account,
                &r,
                now(),
                std::env::vars(),
                &mut |p, key, project, account, now| {
                    crate::approval::consume_scoped(p, key, project, account, now)
                },
            )
        })
        .await
    }
}

/// `opv_sync`'s input: exactly the scope a person approved.
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SyncScopeArgs {
    /// The declared environment.
    pub(crate) environment: String,
    /// The plan id opv_deployment_plan returned and the person approved.
    pub(crate) plan_id: String,
    /// Only these named targets (empty: every target of the environment).
    #[serde(default)]
    pub(crate) targets: Vec<String>,
    /// Only this product.
    #[serde(default)]
    pub(crate) product: Option<String>,
    /// Deploy after writing; only when the person approved with --deploy.
    #[serde(default)]
    pub(crate) deploy: bool,
    /// Unset managed names no longer declared; only when approved with --prune.
    #[serde(default)]
    pub(crate) prune: bool,
    /// `PRODUCT/KEY` immutable keys to replace even though present; only the ones the
    /// person approved with --rotate.
    #[serde(default)]
    pub(crate) rotate: Vec<String>,
    /// As the CLI's --verbose: an error's upstream reply in full.
    #[serde(default)]
    pub(crate) verbose: bool,
}

/// A sync plan id: eight lowercase hex digits.
fn sync_plan_id(s: &str) -> bool {
    s.len() == crate::domain::provenance::PLAN_ID_LEN
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
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

/// `opv_sync`'s call: `opv sync <env> --approved <plan_id>` and its scope, when every name
/// is checked; else the bare command.
fn sync_call(args: &SyncScopeArgs) -> ToolCall {
    let checked = scope_refusal(
        &args.environment,
        &args.targets,
        args.product.as_ref(),
        &args.rotate,
    )
    .is_none()
        && sync_plan_id(&args.plan_id);
    if !checked {
        return ToolCall::new("opv_sync", &["sync"], Vec::new(), args.verbose);
    }
    let mut words = vec![
        args.environment.clone(),
        "--approved".to_string(),
        args.plan_id.clone(),
    ];
    words.extend(scope_flags(
        &args.targets,
        args.product.as_ref(),
        &args.rotate,
    ));
    if args.deploy {
        words.push("--deploy".into());
    }
    if args.prune {
        words.push("--prune".into());
    }
    ToolCall::new("opv_sync", &["sync"], words, args.verbose)
}

/// The scope `args` names, as the catalog's plan scope.
fn plan_scope(args: &SyncScopeArgs) -> PlanScope {
    PlanScope::Sync {
        env: EnvName::new(&args.environment),
        targets: args.targets.iter().map(TargetName::new).collect(),
        product: args.product.as_ref().map(ProductName::new),
        deploy: args.deploy,
        prune: args.prune,
        rotate: args
            .rotate
            .iter()
            .filter_map(|r| r.split_once('/'))
            .map(|(p, k)| ProductKey {
                product: ProductName::new(p),
                key: crate::cause::KeyName::new(k),
            })
            .collect(),
    }
}

/// The failure of a sync whose approval was already used up: what was tried may have
/// partly run, and the approval cannot be used again, so the next step reads what remains
/// in the same scope (design §6.2). A cataloged cause keeps its own message and evidence
/// inside `Partial`; one not yet cataloged is reported as the used approval.
fn after_used_approval(e: Error, args: &SyncScopeArgs) -> Error {
    let plan = PlanId::new(&args.plan_id);
    let Error::Catalog(cause, upstream) = e;
    match *cause {
        Cause::Partial { .. } | Cause::ApprovalUsed { .. } => Error::Catalog(cause, upstream),
        then => Error::Catalog(
            Box::new(Cause::Partial {
                done: Vec::new(),
                approval_used: Some(plan),
                approval_scope: Some(plan_scope(args)),
                then: Box::new(then),
            }),
            upstream,
        ),
    }
}

/// One pruned, pending or held name of the sync document (`KeyNames::json_ref`).
#[derive(Deserialize)]
struct NameRef {
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    product: Option<String>,
    #[serde(default)]
    key: Option<String>,
    target_name: String,
}

/// The parts of `opv sync --json` the tool returns.
#[derive(Deserialize, Default)]
struct RunDoc {
    #[serde(default)]
    written_names: Vec<String>,
    #[serde(default)]
    pruned: Vec<NameRef>,
    #[serde(default)]
    pending: Vec<NameRef>,
    #[serde(default)]
    held: Vec<NameRef>,
    #[serde(default)]
    deployed: bool,
}

/// A name a target holds (a variable, a secret key): a bounded run of name characters.
fn target_name_ok(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 256
        && n.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-./".contains(&b))
}

/// Each checked [`NameRef`] as `{target, product, key, name}`; a field that is not a name
/// is null, and a ref whose name is not one is dropped.
fn name_refs(refs: &[NameRef]) -> Vec<Value> {
    let ident = |v: &Option<String>| v.as_deref().filter(|s| identifier(s)).map(str::to_string);
    refs.iter()
        .filter(|r| target_name_ok(&r.target_name))
        .map(|r| {
            json!({
                "target": ident(&r.target),
                "product": ident(&r.product),
                "key": ident(&r.key),
                "name": r.target_name,
            })
        })
        .collect()
}

/// `opv_sync` as a value: run the approved sync plan, or its failure. `vars` are the
/// process environment variables checked for an op credential; `consume` uses up the
/// approval. Built field by field: names only, never a value.
#[allow(clippy::too_many_arguments)]
pub(crate) fn sync_approved(
    fleet: &crate::domain::Fleet,
    args: &SyncScopeArgs,
    project: &str,
    account: &str,
    r: &dyn CommandRunner,
    now: u64,
    vars: impl Iterator<Item = (String, String)>,
    consume: &mut crate::app::approve::Scoped<'_>,
) -> Value {
    let call = sync_call(args);
    if let Some(var) = credential_in_environment(vars) {
        return call.refused(own_session("sync", var));
    }
    if let Some(refused) = scope_refusal(
        &args.environment,
        &args.targets,
        args.product.as_ref(),
        &args.rotate,
    ) {
        return call.refused(refused);
    }
    if !sync_plan_id(&args.plan_id) {
        return call.refused(usage(
            "plan_id",
            "the eight-digit plan_id opv_deployment_plan returns",
        ));
    }
    if !fleet.environments.contains_key(&args.environment) {
        return call.refused(unknown_env(fleet, &args.environment));
    }
    let scope = crate::app::approve::SyncScope {
        env: args.environment.clone(),
        targets: args.targets.clone(),
        product: args.product.clone(),
        deploy: args.deploy,
        prune: args.prune,
        rotate: args.rotate.clone(),
    };
    let mut report = zeroize::Zeroizing::new(Vec::new());
    let mut used = false;
    let ran = {
        let mut tracked = |p: &str, key: &str, project: &str, account: &str, now: u64| {
            let consumed = consume(p, key, project, account, now);
            used |= consumed.is_ok();
            consumed
        };
        crate::app::approve::run_approved_sync(
            fleet,
            &scope,
            &args.plan_id,
            project,
            account,
            now,
            r,
            &mut *report,
            true,
            None,
            &mut tracked,
        )
    };
    if let Err(e) = ran {
        let e = if used {
            after_used_approval(e, args)
        } else {
            e
        };
        return call.failed(&e);
    }
    let doc: RunDoc = serde_json::from_slice(&report).unwrap_or_default();
    let check = render::cmd_text(&Cmd {
        command: vec!["delivery".into(), "verify".into()],
        args: vec![args.environment.clone()],
    });
    json!({
        "ok": true,
        "plan_id": args.plan_id,
        "written": doc
            .written_names
            .iter()
            .filter(|n| target_name_ok(n))
            .collect::<Vec<_>>(),
        "pruned": name_refs(&doc.pruned),
        "pending": name_refs(&doc.pending),
        "held": name_refs(&doc.held),
        "deployed": doc.deployed,
        "human_action": format!(
            "Done once; the approval is used up. pending: names written but not deployed (a later approved sync with --deploy delivers them); held: immutable keys left as they are. Check delivery with opv_ready or {check}."
        ),
    })
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
    let req = config_store::Request {
        start: project.into(),
        config: None,
        project: None,
        manifest_only: false,
        account: config_store::account_env(),
    };
    config_store::locate(&req, r).and_then(|found| found.load(r))
}

fn inspect(
    project: &std::path::Path,
    operation: Operation,
    env: Option<&str>,
    verbose: bool,
) -> Value {
    let (tool, command): (&str, &[&str]) = match operation {
        Operation::Ready => ("opv_ready", &["ready"]),
        Operation::Configuration => ("opv_configuration", &["config", "describe"]),
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
    let result = crate::app::ready::run(&fleet, None, env, &r, true, None, &mut *bytes);
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
/// `approve_command` for exactly that scope.
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
    let scope = plan_sync_scope(args);
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    let result = crate::app::sync::plan_rotating(
        fleet,
        &scope.env,
        &scope.targets,
        scope.product.as_deref(),
        &scope.rotate,
        r,
        &mut *bytes,
        true,
    );
    receipt_answer(&call, r, &bytes, result, |doc| plan_receipt(doc, &scope))
}

/// The sync scope a deployment plan's `approve_command` names: its targets, product and
/// rotate entries; `--deploy` and `--prune` are the person's to add.
fn plan_sync_scope(args: &DeploymentPlanScope) -> crate::app::approve::SyncScope {
    crate::app::approve::SyncScope {
        env: args.environment.clone(),
        targets: args.targets.clone(),
        product: args.product.clone(),
        deploy: false,
        prune: false,
        rotate: args.rotate.clone(),
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

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// Run a declaration on the project's `secrets.toml` on the read-only runner: its answer
/// is whether the file changed, never its text. Without a local `secrets.toml`, a
/// configuration kept in 1Password is declared with the CLI command instead; with neither,
/// the answer is why none was found.
fn declared(
    project: &std::path::Path,
    call: &ToolCall,
    f: impl FnOnce(&dyn CommandRunner, &std::path::Path) -> Result<bool, Error>,
) -> Value {
    let Some(path) = config_store::walk_up(project, "secrets.toml") else {
        let r = read_only(INSPECT_BUDGET);
        return match load_fleet(project, &r) {
            Ok(_) => call.refused(Cause::Usage {
                problem: UsageProblem::UseInstead {
                    command: Cmd {
                        command: call.inv.command.clone(),
                        args: call.inv.args.clone(),
                    },
                },
            }),
            Err(e) => call.failed(&e),
        };
    };
    let r = read_only(INSPECT_BUDGET);
    match f(&r, &path) {
        _ if r.refused.load(Ordering::Relaxed) => call.refused(write_refused()),
        Ok(changed) => json!({
            "ok": true,
            "changed": changed,
            "human_action": "Call opv_structure_plan to see what this needs in 1Password; a person approves it with opv approve.",
        }),
        Err(e) => call.failed(&e),
    }
}

/// `opv_declare_key`: `opv add <product>/<KEY>` with its kind, environments, rules and
/// immutability.
fn declare_key(project: &std::path::Path, args: DeclareKey) -> Value {
    let bad = [("product", &args.product), ("key", &args.key)]
        .into_iter()
        .chain(args.environments.iter().map(|e| ("environments", e)))
        .find(|(_, n)| !identifier(n));
    if let Some((field, _)) = bad {
        return ToolCall::new("opv_declare_key", &["add"], Vec::new(), args.verbose)
            .refused(not_a_name(field));
    }
    let mut words = vec![format!("{}/{}", args.product, args.key)];
    if ["secret", "config"].contains(&args.kind.as_str()) {
        words.extend(["--kind".to_string(), args.kind.clone()]);
    }
    for e in &args.environments {
        words.extend(["--env".to_string(), e.clone()]);
    }
    let one_line = |s: &String| s.len() <= 300 && !s.chars().any(char::is_control);
    for rule in args.rules.iter().filter(|r| one_line(r)) {
        words.extend(["--rule".to_string(), rule.clone()]);
    }
    if let Some(g) = args.guidance.as_ref().filter(|g| one_line(g)) {
        words.extend(["--guidance".to_string(), g.clone()]);
    }
    if args.immutable {
        words.push("--immutable".into());
    }
    let call = ToolCall::new("opv_declare_key", &["add"], words, args.verbose);
    let k = crate::app::declare::Key {
        product: args.product,
        key: args.key,
        kind: args.kind,
        environments: args.environments,
        rules: args.rules,
        guidance: args.guidance,
        immutable: args.immutable,
    };
    declared(project, &call, |r, path| {
        crate::app::declare::key(r, path, &k)
    })
}

/// `opv_declare_environment`: `opv env add <env>`.
fn declare_environment(project: &std::path::Path, environment: &str, verbose: bool) -> Value {
    if !identifier(environment) {
        return ToolCall::new(
            "opv_declare_environment",
            &["env", "add"],
            Vec::new(),
            verbose,
        )
        .refused(not_a_name("environment"));
    }
    let call = ToolCall::new(
        "opv_declare_environment",
        &["env", "add"],
        vec![environment.to_string()],
        verbose,
    );
    declared(project, &call, |r, path| {
        crate::app::declare::environment(r, path, environment)
    })
}

/// `opv_declare_target`: `opv target add <env> <name>`. Deploy credentials are refused
/// before anything is read, and an existing target is refused as already declared: this
/// tool never changes one.
fn declare_target(project: &std::path::Path, args: DeclareTarget) -> Value {
    let names = [("environment", &args.environment), ("target", &args.target)]
        .into_iter()
        .chain(args.products.iter().map(|p| ("products", p)))
        .chain(args.options.keys().map(|k| ("options", k)));
    let bad = names
        .into_iter()
        .find(|(_, n)| !identifier(n))
        .map(|(f, _)| f);
    let bad = bad.or_else(|| {
        args.options
            .values()
            .any(|v| v.len() > 256 || v.chars().any(char::is_control))
            .then_some("options")
    });
    if let Some(field) = bad {
        return ToolCall::new(
            "opv_declare_target",
            &["target", "add"],
            Vec::new(),
            args.verbose,
        )
        .refused(not_a_name(field));
    }
    let call = ToolCall::new(
        "opv_declare_target",
        &["target", "add"],
        vec![args.environment.clone(), args.target.clone()],
        args.verbose,
    );
    if let Some(option) = args.options.keys().find(|k| k.contains("credential")) {
        return call.refused(Cause::Guard {
            guard: Guard::CredentialAsOption {
                option: option.clone(),
            },
        });
    }
    if let Some(exists) = load_fleet(project, &read_only(INSPECT_BUDGET))
        .ok()
        .and_then(|fleet| existing_target(&fleet, &args.environment, &args.target))
    {
        return call.refused(exists);
    }
    let t = crate::app::declare::Target {
        environment: args.environment,
        name: args.target,
        provider: args.provider,
        fields: args.options,
        products: args.products,
    };
    declared(project, &call, |r, path| {
        crate::app::declare::target(r, path, &t)
    })
}

/// `target` of `env` when `fleet` already declares it: this tool never changes one.
fn existing_target(fleet: &crate::domain::Fleet, env: &str, target: &str) -> Option<Cause> {
    fleet
        .environments
        .get(env)
        .is_some_and(|e| e.targets.contains_key(target))
        .then(|| Cause::AlreadyDeclared {
            kind: NameKind::Target,
            // The CLI's words (`opv target add`): MCP answers what `--json` prints.
            name: format!("{target} in environment {env}"),
        })
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
        &["structure", "plan"],
        Vec::new(),
        verbose,
    );
    let r = read_only(Duration::from_secs(60));
    let planned = crate::app::structure::scope(project, &r).and_then(|scope| {
        r.inner.use_account(Some(scope.account.clone()));
        let text = std::fs::read_to_string(&scope.path).map_err(|e| -> Error {
            Cause::ConfigUnreadable {
                path: scope.path.clone(),
                io: e.kind().into(),
                given_by: crate::cause::GivenBy::Discovered,
            }
            .into()
        })?;
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

fn structure_apply(project: &std::path::Path, plan_id: &str, verbose: bool) -> Value {
    if !crate::app::structure::is_plan_id(plan_id) {
        return ToolCall::new(
            "opv_structure_apply",
            &["structure", "apply"],
            Vec::new(),
            verbose,
        )
        .refused(usage(
            "plan_id",
            "the plan_id opv_structure_plan returns (sp- and 16 hex digits)",
        ));
    }
    let call = ToolCall::new(
        "opv_structure_apply",
        &["structure", "apply"],
        vec![plan_id.to_string()],
        verbose,
    );
    if let Some(var) = credential_in_environment(std::env::vars()) {
        return call.refused(own_session("structure apply", var));
    }
    if let Some(refused) = ci_refusal() {
        return call.refused(refused);
    }
    let r = ProcessRunner::new(Budget::starting_now(Duration::from_secs(300)), false);
    let applied = crate::app::structure::scope(project, &r).and_then(|scope| {
        r.use_account(Some(scope.account.clone()));
        crate::app::structure::apply(
            &r,
            &scope.path,
            &scope.project,
            &scope.account,
            plan_id,
            &mut |p| crate::approval::consume(&p.plan_id, &scope.project, &scope.account, now()),
        )
        // C2 (09.mcp): an id never approved here is unknown, not changed since approval.
        .map_err(|e| {
            crate::app::structure::unknown_unless_approved(e, &crate::approval::ever_approved)
        })
    });
    match applied {
        Ok(a) => applied_projection(&a),
        Err(e) => call.failed(&e),
    }
}

/// `opv_generate`'s call: `opv generate <env> <product/KEY>…` when every name is checked.
fn generate_call(env_name: &str, keys: &[String], verbose: bool) -> ToolCall {
    let checked = identifier(env_name)
        && !keys.is_empty()
        && keys.len() <= 20
        && keys.iter().all(|k| {
            k.split_once('/')
                .is_some_and(|(product, key)| identifier(product) && identifier(key))
        });
    let words = if checked {
        std::iter::once(env_name.to_string())
            .chain(keys.iter().cloned())
            .collect()
    } else {
        Vec::new()
    };
    ToolCall::new("opv_generate", &["generate"], words, verbose)
}

/// `opv_generate` as a value: generate each `product/KEY` and write it into its empty
/// 1Password field, or its failure. `vars` are the process environment variables checked
/// for a write credential (injected so a test need not set the process environment). The
/// sink is discarded: no value and no length other than the recipe's byte count is returned.
fn generate(
    fleet: &crate::domain::Fleet,
    env_name: &str,
    keys: &[String],
    r: &dyn CommandRunner,
    vars: impl Iterator<Item = (String, String)>,
    verbose: bool,
) -> Value {
    let call = generate_call(env_name, keys, verbose);
    if let Some(var) = credential_in_environment(vars) {
        return call.refused(own_session("generate", var));
    }
    if let Some(refused) = ci_refusal() {
        return call.refused(refused);
    }
    if !identifier(env_name) {
        return call.refused(not_a_name("environment"));
    }
    if keys.is_empty() || keys.len() > 20 {
        return call.refused(usage("keys", "1 to 20 names, each <product>/<KEY>"));
    }
    if keys.iter().any(|k| {
        k.split_once('/')
            .is_none_or(|(product, key)| !identifier(product) || !identifier(key))
    }) {
        return call.refused(usage(
            "keys",
            "<product>/<KEY> names, declared (opv_configuration lists them)",
        ));
    }
    if !fleet.environments.contains_key(env_name) {
        return call.refused(unknown_env(fleet, env_name));
    }
    // Every name and declaration is checked before anything is written.
    let chosen = match crate::app::generate::plan(fleet, env_name, keys) {
        Ok(chosen) => chosen,
        Err(e) => return call.failed(&e),
    };
    let mut sink = Vec::new();
    if let Err(e) = crate::app::generate::run(fleet, env_name, keys, r, &mut sink) {
        return call.failed(&e);
    }
    let generated: Vec<Value> = chosen
        .iter()
        .map(|(product, key, recipe)| {
            let (encoding, bytes) = match recipe {
                crate::app::generate::Recipe::Base64(n) => ("base64", *n),
                crate::app::generate::Recipe::Hex(n) => ("hex", *n),
            };
            json!({"product": product, "key": key, "encoding": encoding, "bytes": bytes})
        })
        .collect();
    json!({
        "ok": true,
        "generated": generated,
        "human_action": "The values went straight into 1Password and were never shown.",
        "next": render::cmd_text(&Cmd {
            command: vec!["status".into()],
            args: vec![env_name.to_string()],
        }),
    })
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

/// The `opv approve <plan_id> --sync <env>` command for exactly `scope`.
fn approve_command(plan_id: &str, scope: &crate::app::approve::SyncScope) -> String {
    let mut args = vec![plan_id.to_string(), "--sync".into(), scope.env.clone()];
    if scope.deploy {
        args.push("--deploy".into());
    }
    if scope.prune {
        args.push("--prune".into());
    }
    args.extend(scope_flags(
        &scope.targets,
        scope.product.as_ref(),
        &scope.rotate,
    ));
    render::cmd_text(&Cmd {
        command: vec!["approve".into()],
        args,
    })
}

/// The `opv plan --json` document as the MCP answer, field by field, with the
/// `approve_command` for exactly `scope` (its targets, product and rotate entries), so the
/// approval a person records covers the `opv_sync` that names the same scope.
fn plan_receipt(doc: &Value, scope: &crate::app::approve::SyncScope) -> Option<Value> {
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
    let approve = plan_id.map(|id| approve_command(id, scope));
    Some(
        json!({"ok": true, "rows": rows, "stage": names("stage"), "prune": names("prune"), "plan_id": plan_id, "approve_command": approve, "human_action": "A person reviews and approves this plan with approve_command in their own terminal (adding --deploy or --prune there to allow those); opv_sync with the same plan_id, targets, product, rotate and flags then runs exactly it once. Sync, deploy, prune and rotation happen only through that approved opv_sync, which never prunes an immutable key."}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::fake_op::FakeOp;
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
        let doc = json!({"schema_version": 2, "findings": [{"blocking": true, "message": "SECRET_MARKER", "prerequisite": "SECRET_MARKER"}], "value": "SECRET_MARKER"});
        assert!(
            !ready_receipt(&doc)
                .unwrap_or_default()
                .to_string()
                .contains("SECRET_MARKER")
        );
    }
    #[test]
    fn plan_drops_values_even_when_the_source_contains_them() {
        let doc = json!({"schema_version": 2, "rows": [{"product": "api", "key": "API_KEY", "action": "stage", "value": "SECRET_MARKER", "reason": "SECRET_MARKER"}], "plan_id": "123abc"});
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

    fn hostile_applied() -> crate::app::structure::Applied {
        crate::app::structure::Applied {
            plan_id: "sp-0123456789abcdef".into(),
            created: vec![crate::app::structure::Created {
                kind: "boundary",
                environment: "prod".into(),
                name: "core".into(),
                vault_id: "vault0001".into(),
                item_id: Some("SECRET_MARKER value with spaces".into()),
                link: Some("https://evil.example/?SECRET_MARKER".into()),
            }],
            fields_added: vec![],
            config_written: true,
            generator_ids: vec!["x = \"SECRET_MARKER\" \n injected".into()],
            concurrent_edits: vec![],
        }
    }

    #[test]
    fn the_apply_answer_drops_an_item_id_that_is_not_an_id() {
        let v = applied_projection(&hostile_applied());
        assert!(v["created"][0]["item_id"].is_null());
    }

    #[test]
    fn the_apply_answer_drops_a_link_outside_1password() {
        let v = applied_projection(&hostile_applied());
        assert!(v["created"][0]["link"].is_null());
    }

    #[test]
    fn the_apply_answer_drops_a_generator_line_with_a_newline() {
        let v = applied_projection(&hostile_applied());
        assert!(!v.to_string().contains("injected"));
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
        let doc = json!({"schema_version": 2, "findings": [{"blocking": true}]});
        assert_eq!(
            ready_receipt(&doc).unwrap_or_default()["blocking_findings"],
            1
        );
    }

    fn ready_doc(findings: Value, targets: Value) -> Value {
        json!({"schema_version": 2, "findings": findings, "targets": targets})
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

    const GENERATE_FLEET: &str = r#"[environments.dev]
boundaries.api = { vault_id = "vdev0000000000000000000001", item_id = "ITEM" }

[products.api.keys.SESSION_KEY]
kind = "secret"
environments = ["dev"]
rules = { base64_bytes = 32 }

[products.api.keys.WEBHOOK_HEX]
kind = "secret"
environments = ["dev"]
rules = { hex_bytes = 32 }

[products.api.keys.STRIPE_KEY]
kind = "secret"
environments = ["dev"]
rules = { prefix = "sk_" }
"#;

    /// A fake `op` whose dev item already holds `api/WEBHOOK_HEX` = `already-set`.
    fn generate_world() -> (crate::domain::Fleet, FakeOp, String) {
        let op = FakeOp::default();
        op.signed_in.set(true);
        let id = op.insert(
            "vdev0000000000000000000001",
            json!({
                "title": "myapp · api · dev values", "category": "SECURE_NOTE",
                "sections": [{"id": "api", "label": "api"}],
                "fields": [{"id": "f1", "label": "WEBHOOK_HEX", "type": "CONCEALED",
                            "section": {"id": "api", "label": "api"}, "value": "already-set"}],
            }),
        );
        let fleet = crate::config::parse(&GENERATE_FLEET.replace("ITEM", &id)).unwrap();
        (fleet, op, id)
    }

    fn generated_field(op: &FakeOp, id: &str, label: &str) -> Option<String> {
        op.item(id)["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["label"] == label)
            .and_then(|f| f["value"].as_str().map(str::to_string))
    }

    fn no_vars() -> impl Iterator<Item = (String, String)> {
        std::iter::empty()
    }

    #[test]
    fn opv_generate_writes_a_base64_value_into_an_empty_field() {
        let (fleet, op, id) = generate_world();
        let _ = generate(
            &fleet,
            "dev",
            &["api/SESSION_KEY".into()],
            &op,
            no_vars(),
            false,
        );
        assert_eq!(
            generated_field(&op, &id, "SESSION_KEY").map(|v| v.len()),
            Some(44)
        );
    }

    #[test]
    fn opv_generate_never_returns_the_generated_value() {
        let (fleet, op, id) = generate_world();
        let answer = generate(
            &fleet,
            "dev",
            &["api/SESSION_KEY".into()],
            &op,
            no_vars(),
            false,
        );
        let value = generated_field(&op, &id, "SESSION_KEY").unwrap();
        assert!(!answer.to_string().contains(&value));
    }

    #[test]
    fn opv_generate_reports_the_base64_recipe() {
        let (fleet, op, _) = generate_world();
        let answer = generate(
            &fleet,
            "dev",
            &["api/SESSION_KEY".into()],
            &op,
            no_vars(),
            false,
        );
        assert_eq!(
            answer["generated"][0],
            json!({"product": "api", "key": "SESSION_KEY", "encoding": "base64", "bytes": 32})
        );
    }

    #[test]
    fn opv_generate_offers_the_status_command_next() {
        let (fleet, op, _) = generate_world();
        let answer = generate(
            &fleet,
            "dev",
            &["api/SESSION_KEY".into()],
            &op,
            no_vars(),
            false,
        );
        assert_eq!(answer["next"], "opv status dev");
    }

    #[test]
    fn opv_generate_refuses_a_prefix_rule_key_with_policy_refused() {
        let (fleet, op, _) = generate_world();
        let answer = generate(
            &fleet,
            "dev",
            &["api/STRIPE_KEY".into()],
            &op,
            no_vars(),
            false,
        );
        assert_eq!(answer["error"]["code"], "policy_refused");
    }

    #[test]
    fn opv_generate_writes_nothing_when_another_key_is_refused() {
        let (fleet, op, id) = generate_world();
        let _ = generate(
            &fleet,
            "dev",
            &["api/SESSION_KEY".into(), "api/STRIPE_KEY".into()],
            &op,
            no_vars(),
            false,
        );
        assert_eq!(generated_field(&op, &id, "SESSION_KEY"), None);
    }

    #[test]
    fn opv_generate_refuses_a_filled_field_with_policy_refused() {
        let (fleet, op, _) = generate_world();
        let answer = generate(
            &fleet,
            "dev",
            &["api/WEBHOOK_HEX".into()],
            &op,
            no_vars(),
            false,
        );
        assert_eq!(answer["error"]["code"], "policy_refused");
    }

    #[test]
    fn opv_generate_keeps_an_existing_value() {
        let (fleet, op, id) = generate_world();
        let _ = generate(
            &fleet,
            "dev",
            &["api/WEBHOOK_HEX".into()],
            &op,
            no_vars(),
            false,
        );
        assert_eq!(
            generated_field(&op, &id, "WEBHOOK_HEX").as_deref(),
            Some("already-set")
        );
    }

    #[test]
    fn opv_generate_refuses_a_bad_name_as_usage() {
        let (fleet, op, _) = generate_world();
        let answer = generate(&fleet, "dev", &["api/NO PE".into()], &op, no_vars(), false);
        assert_eq!(answer["error"]["code"], "usage");
    }

    #[test]
    fn opv_generate_touches_no_1password_for_an_invalid_name() {
        let (fleet, op, _) = generate_world();
        let _ = generate(&fleet, "dev", &["api/NO PE".into()], &op, no_vars(), false);
        assert!(op.calls.borrow().is_empty());
    }

    #[test]
    fn opv_generate_refuses_a_service_account_token_in_the_environment() {
        let (fleet, op, _) = generate_world();
        let answer = generate(
            &fleet,
            "dev",
            &["api/SESSION_KEY".into()],
            &op,
            vars(&[("OP_SERVICE_ACCOUNT_TOKEN", "ops_x")]),
            false,
        );
        assert_eq!(answer["error"]["code"], "own_session_required");
    }

    #[test]
    fn opv_generate_reports_when_nobody_is_signed_in() {
        let (fleet, op, _) = generate_world();
        op.signed_in.set(false);
        let answer = generate(
            &fleet,
            "dev",
            &["api/SESSION_KEY".into()],
            &op,
            no_vars(),
            false,
        );
        assert_eq!(answer["error"]["code"], "op_not_signed_in");
    }

    #[test]
    fn opv_generate_returns_unknown_env_for_an_undeclared_environment() {
        let (fleet, op, _) = generate_world();
        let answer = generate(
            &fleet,
            "prod",
            &["api/SESSION_KEY".into()],
            &op,
            no_vars(),
            false,
        );
        assert_eq!(answer["error"]["code"], "unknown_env");
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
        crate::app::testutil::fleet_with(&format!(
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

    fn plan_scope(
        targets: &[&str],
        product: Option<&str>,
        rotate: &[&str],
    ) -> crate::app::approve::SyncScope {
        plan_sync_scope(&DeploymentPlanScope {
            environment: "prod".into(),
            targets: targets.iter().map(|t| t.to_string()).collect(),
            product: product.map(str::to_string),
            rotate: rotate.iter().map(|r| r.to_string()).collect(),
            verbose: false,
        })
    }

    #[test]
    fn a_scoped_deployment_plan_approves_the_same_targets_product_and_rotation() {
        let doc =
            json!({"schema_version": 2, "environment": "prod", "rows": [], "plan_id": "0123abcd"});
        let v = plan_receipt(&doc, &plan_scope(&["fleet"], Some("api"), &["api/KEY"])).unwrap();
        assert_eq!(
            v["approve_command"],
            "opv approve 0123abcd --sync prod --target fleet --product api --rotate api/KEY"
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
    fn the_deployment_plan_never_says_sync_is_unavailable_through_mcp() {
        let doc = json!({"schema_version": 2, "rows": [], "plan_id": "0123abcd"});
        let v = plan_receipt(&doc, &plan_scope(&[], None, &[])).unwrap();
        assert!(
            v["human_action"]
                .as_str()
                .unwrap()
                .contains("only through that approved opv_sync")
        );
    }

    fn under_ci<T>(f: impl FnOnce() -> T) -> T {
        let env = crate::host::FakeEnv::new("linux")
            .var_val("CI", "true")
            .shell("/bin/bash");
        crate::host::with_test_host(crate::host::Host::from_env(&env), f)
    }

    #[test]
    fn opv_generate_under_ci_needs_a_person_at_a_terminal() {
        let (fleet, op, _) = generate_world();
        let answer = under_ci(|| {
            generate(
                &fleet,
                "dev",
                &["api/SESSION_KEY".into()],
                &op,
                no_vars(),
                false,
            )
        });
        assert_eq!(answer["error"]["code"], "terminal_required");
    }

    #[test]
    fn opv_generate_under_ci_calls_nothing() {
        let (fleet, op, _) = generate_world();
        let _ = under_ci(|| {
            generate(
                &fleet,
                "dev",
                &["api/SESSION_KEY".into()],
                &op,
                no_vars(),
                false,
            )
        });
        assert!(op.calls.borrow().is_empty());
    }

    #[test]
    fn the_structural_apply_is_refused_under_ci() {
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
            "opv_sync",
            command,
            args.iter().map(|a| a.to_string()).collect(),
            false,
        )
    }

    fn own_session() -> crate::error::Error {
        crate::cause::Cause::NeedsOwnSession {
            command: crate::cause::CommandId("approve".into()),
            identity: crate::cause::Principal::ServiceAccount {
                name: "sa-ci".into(),
            },
        }
        .into()
    }

    #[test]
    fn a_catalog_failure_is_exactly_the_documents_error_object() {
        let call = tool(&["sync"], &["prod", "--approved", "0123abcd"]);
        let want = render::document(
            &crate::cause::Cause::NeedsOwnSession {
                command: crate::cause::CommandId("approve".into()),
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
        let call = ToolCall::new("opv_sync", &["sync"], Vec::new(), true);
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
            tool(&["sync"], &[]).failed(&e)["error"]["next"],
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

    // 08.05: an unapproved plan's approve step is a person's handoff, every scope flag kept.
    fn stale(_next: &str) -> crate::error::Error {
        crate::cause::Cause::ApprovalMissing {
            plan: crate::cause::PlanId::new("0123abcd"),
            scope: crate::cause::PlanScope::Sync {
                env: crate::cause::EnvName::new("prod"),
                targets: Vec::new(),
                product: None,
                deploy: false,
                prune: false,
                rotate: vec![crate::cause::ProductKey {
                    product: crate::cause::ProductName::new("api"),
                    key: crate::cause::KeyName::new("ENC_KEY"),
                }],
            },
        }
        .into()
    }

    const ROTATING_APPROVE: &str = "opv approve 0123abcd --sync prod --rotate api/ENC_KEY";

    #[test]
    fn a_stale_plan_needs_a_person() {
        let v = tool(&["sync"], &[]).failed(&stale(ROTATING_APPROVE));
        assert_eq!(v["error"]["human_required"], true);
    }

    #[test]
    fn a_stale_plan_hands_off_its_approve_step() {
        let v = tool(&["sync"], &[]).failed(&stale(ROTATING_APPROVE));
        assert_eq!(v["error"]["next_kind"], "handoff");
    }

    #[test]
    fn a_rotating_approve_step_keeps_its_rotation() {
        let v = tool(&["sync"], &[]).failed(&stale(ROTATING_APPROVE));
        assert_eq!(v["error"]["next"], ROTATING_APPROVE);
    }

    fn sync_args() -> SyncScopeArgs {
        SyncScopeArgs {
            environment: "prod".into(),
            plan_id: "0123abcd".into(),
            targets: vec!["fleet".into()],
            product: None,
            deploy: true,
            prune: false,
            rotate: vec![],
            verbose: false,
        }
    }

    // 08.04: once the approval is used, the answer reads what remains, never "call again".
    fn interrupted() -> crate::error::Error {
        crate::cause::Cause::Interrupted {
            signal: 15,
            writes_started: true,
        }
        .into()
    }

    #[test]
    fn a_failure_after_the_approval_was_used_reads_what_remains() {
        let args = sync_args();
        let e = after_used_approval(interrupted(), &args);
        assert_eq!(
            sync_call(&args).failed(&e)["error"]["next"],
            "opv plan prod --target fleet"
        );
    }

    #[test]
    fn a_failure_after_the_approval_was_used_says_it_is_used_up() {
        let args = sync_args();
        let e = after_used_approval(interrupted(), &args);
        assert!(
            sync_call(&args).failed(&e)["error"]["message"]
                .as_str()
                .unwrap()
                .contains("approval 0123abcd is used up")
        );
    }

    // 08.01: pruned, pending and held are objects in the sync document, not strings.
    fn run_doc() -> RunDoc {
        serde_json::from_value(json!({
            "written_names": ["API_KEY"],
            "pending": [{"target": "fleet", "product": "api", "key": "API_KEY", "target_name": "API_KEY"}],
            "held": [{"target": "fleet", "product": "api", "key": "ENC_KEY", "target_name": "ENC_KEY"}],
            "pruned": [{"target": "fleet", "product": null, "key": "OLD", "target_name": "OLD"}],
            "deployed": false,
        }))
        .unwrap()
    }

    #[test]
    fn a_sync_answer_lists_its_pending_names() {
        assert_eq!(name_refs(&run_doc().pending)[0]["key"], "API_KEY");
    }

    #[test]
    fn a_sync_answer_lists_its_held_names() {
        assert_eq!(name_refs(&run_doc().held)[0]["name"], "ENC_KEY");
    }

    #[test]
    fn a_sync_answer_lists_its_pruned_names() {
        assert_eq!(name_refs(&run_doc().pruned)[0]["target"], "fleet");
    }

    #[test]
    fn a_sync_answer_drops_a_name_that_is_not_one() {
        let doc: RunDoc = serde_json::from_value(json!({
            "held": [{"target": "fleet", "target_name": "A B; rm"}],
        }))
        .unwrap();
        assert!(name_refs(&doc.held).is_empty());
    }

    // 08 (S1): a declaration refused for a credential option says so.
    #[test]
    fn a_declared_credential_option_is_refused_as_policy() {
        let args = DeclareTarget {
            environment: "prod".into(),
            target: "web".into(),
            provider: None,
            options: [("deploy-credentials".to_string(), "x".to_string())].into(),
            products: vec![],
            verbose: false,
        };
        assert_eq!(
            declare_target(std::path::Path::new("/nonexistent"), args)["error"]["code"],
            "policy_refused"
        );
    }

    // 08 (S2): declaring a target that exists is refused, not "ok, unchanged".
    #[test]
    fn an_existing_target_is_already_declared() {
        let fleet = crate::app::testutil::role_fleet();
        let env = fleet.environments.keys().next().unwrap().clone();
        let target = fleet.environments[&env].targets.keys().next().cloned();
        let found = target.and_then(|t| existing_target(&fleet, &env, &t));
        assert_eq!(found.map(|c| c.code()), Some("already_declared"));
    }

    // 08 (S2): CI and a credential in the server's environment need a person.
    #[test]
    fn opv_generate_under_ci_needs_a_person() {
        let (fleet, op, _) = generate_world();
        let answer = under_ci(|| {
            generate(
                &fleet,
                "dev",
                &["api/SESSION_KEY".into()],
                &op,
                no_vars(),
                false,
            )
        });
        assert_eq!(answer["error"]["human_required"], true);
    }

    #[test]
    fn a_credential_in_the_environment_hands_off_the_cli_command() {
        let call = ToolCall::new(
            "opv_structure_apply",
            &["structure", "apply"],
            vec!["sp-0123456789abcdef".into()],
            false,
        );
        let v = call.refused(super::own_session(
            "structure apply",
            "OP_SESSION_my".into(),
        ));
        assert_eq!(
            v["error"]["next"],
            "opv structure apply sp-0123456789abcdef --json"
        );
    }

    // 08 (S2): a write tool that stopped says its write may have started.
    #[test]
    fn a_write_tool_that_stopped_says_its_write_may_have_started() {
        assert!(
            stopped("opv_sync", true, false)["error"]["message"]
                .as_str()
                .unwrap()
                .contains("write may have started")
        );
    }

    // 08 (S2): a plan with blocking keys drops the success hint to approve a plan.
    #[test]
    fn a_failed_plan_drops_the_approve_hint() {
        let r = ReadOnly {
            inner: FakeRunner::new([]),
            refused: AtomicBool::new(false),
        };
        let doc = json!({"schema_version": 2, "rows": [], "plan_id": null}).to_string();
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
}
