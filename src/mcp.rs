//! MCP tools. The inspection tools are read-only: no value-bearing operation or mutation is
//! exposed, and their runner refuses every write beneath the application code.
//!
//! The structural tools (#133) plan and apply structure only (vaults, items, empty fields,
//! delivery items; never a value). `opv_structure_plan` runs on the same read-only runner.
//! `opv_structure_apply` writes only a plan a person approved in their own terminal
//! (`opv approve <plan_id>`, single use, bound to the project and 1Password account), and
//! only through the 1Password app's own authorization: it refuses to run with a session
//! token, service account or Connect credential in its environment. Its answer is built
//! field by field from checked identifiers; no upstream text reaches it.
use crate::{
    app::agent_view::{applied_projection, configuration_projection, identifier, plan_projection},
    config_store,
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
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlanId {
    /// The plan id opv_structure_plan returned and a person approved with opv approve.
    plan_id: String,
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
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeclareEnvironment {
    /// New environment name (`^[a-z][a-z0-9-]*$`).
    environment: String,
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
    /// Products it delivers; empty means every product.
    #[serde(default)]
    products: Vec<String>,
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
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadyScope {
    /// A declared environment name; omitted: every declared environment.
    #[serde(default)]
    environment: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GenerateScope {
    /// A declared environment whose empty fields receive the generated values.
    environment: String,
    /// One to twenty `product/KEY` names (never a value), each declared for the environment
    /// with a `base64_bytes` or `hex_bytes` rule.
    keys: Vec<String>,
}

impl Server {
    pub fn new(project: PathBuf) -> Self {
        Self {
            project,
            gate: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    async fn inspect(&self, operation: Operation, env: Option<String>) -> String {
        self.serialized(move |project| inspect(project, operation, env.as_deref()))
            .await
    }

    /// Run `f` on the project, one tool call at a time, off the async runtime.
    async fn serialized(
        &self,
        f: impl FnOnce(&std::path::Path) -> Value + Send + 'static,
    ) -> String {
        let guard = self.gate.clone().lock_owned().await;
        let project = self.project.clone();
        tokio::task::spawn_blocking(move || {
            // Keep serialization until the blocking work ends, even if the client
            // cancels its request and drops the awaiting future.
            let _guard = guard;
            f(&project)
        })
        .await
        .unwrap_or_else(|_| {
            failure(
                "inspection_unavailable",
                &code_hint("inspection_unavailable", "the same opv command"),
            )
        })
        .to_string()
    }
}

#[tool_router(server_handler)]
impl Server {
    #[tool(
        name = "opv_ready",
        description = "Read readiness metadata for one declared environment, or for every environment when none is named: each finding's code, blocking flag, actor, effect and next step (an opv command or a 1Password item link), and each target's state. Never returns a value, message or verification text. Humans handle authentication and secret entry. No changes are authorized.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn ready(&self, Parameters(args): Parameters<ReadyScope>) -> String {
        self.inspect(Operation::Ready, args.environment).await
    }

    #[tool(
        name = "opv_configuration",
        description = "Inspect declared environment, key and target metadata only: environment names, product/key names and kinds, and each target's provider and delivered products. No values, rules, vault identifiers, locators, credential references, or configuration export.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn configuration(&self) -> String {
        self.inspect(Operation::Configuration, None).await
    }

    #[tool(
        name = "opv_deployment_plan",
        description = "Preview deployment actions without executing them, for the whole environment or only the given targets, product and immutable keys to rotate (`PRODUCT/KEY`): each row's target, product, key and action, the plan_id, and the approve_command (with the same --target, --product and --rotate) a person runs in their own terminal. Sync, deploy, prune and rotation run only through an approved opv_sync (which never prunes an immutable key); secret entry and layout repair stay with the person.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn deployment_plan(&self, Parameters(args): Parameters<DeploymentPlanScope>) -> String {
        self.serialized(move |project| deployment_plan(project, &args))
            .await
    }

    #[tool(
        name = "opv_access",
        description = "Who needs which 1Password vault for CI and deploys, and who can read it now: each identity (a target's deploy identity, an environment's CI reader) with its service-account name, vaults, permissions and state (present, missing, read-only needed, not visible, not in this account), findings with their next step, and for each identity missing a grant the exact owner command that creates it and stores its token as a GitHub secret without showing it (`opv access <env> [--target <t>] --create --github <owner/repo> --github-env <env>`; the person runs it, filling in the repository and GitHub environment the CI job uses). Never a token or value. Changes nothing.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn access(&self, Parameters(args): Parameters<AccessScope>) -> String {
        self.serialized(move |project| {
            access_projection(project, args.environment.as_deref(), args.target.as_deref())
        })
        .await
    }

    #[tool(
        name = "opv_delivery_preview",
        description = "Preview which keys a local `opv run` would deliver for one environment, without reading any value: each key's product, name, source, destination (variable name or relative file path) and declared process roles; the key names a role withholds; the environment mode, the secrets-directory variable, whether RAM-backed file delivery is supported here, and whether the op CLI is present and signed in (unknown when it cannot be determined). With remote (a profile name the product declares), previews `opv run --remote`: the profile's pinned host, user, port, host-key type, working directory and command, and whether ssh is on PATH; remote_profiles lists the product's profiles. Changes nothing; only the person runs opv run (a remote run needs their own terminal; no tool runs it).",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn delivery_preview(&self, Parameters(args): Parameters<DeliveryPreviewScope>) -> String {
        self.serialized(move |project| {
            delivery_preview_doc(
                project,
                &args.environment,
                args.product.as_deref(),
                args.role.as_deref(),
                args.remote.as_deref(),
            )
        })
        .await
    }

    #[tool(
        name = "opv_structure_plan",
        description = "Plan the 1Password structure this project's configuration declares: boundary vaults and items, state vaults, delivery items and empty fields (names, kinds and public IDs only; never a value). Returns a plan_id. Changes nothing. A person reviews and approves it with `opv approve <plan_id>` in their own terminal before opv_structure_apply can create it.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn structure_plan(&self) -> String {
        self.serialized(structure_plan).await
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
    async fn structure_apply(&self, Parameters(args): Parameters<PlanId>) -> String {
        self.serialized(move |project| structure_apply(project, &args.plan_id))
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
        self.serialized(move |project| {
            let names = std::iter::once(&args.product)
                .chain(std::iter::once(&args.key))
                .chain(args.environments.iter());
            if names.into_iter().any(|n| !identifier(n)) {
                return failure("invalid_name", "Use declared names only.");
            }
            let k = crate::app::declare::Key {
                product: args.product,
                key: args.key,
                kind: args.kind,
                environments: args.environments,
                rules: args.rules,
                guidance: args.guidance,
                immutable: args.immutable,
            };
            declared(project, |r, path| crate::app::declare::key(r, path, &k))
        })
        .await
    }

    #[tool(
        name = "opv_declare_environment",
        description = "Declare an environment in this project's secrets.toml. Edits the local file only; its boundary vaults and items come from the next approved structural plan.",
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
        self.serialized(move |project| {
            declared(project, |r, path| {
                crate::app::declare::environment(r, path, &args.environment)
            })
        })
        .await
    }

    #[tool(
        name = "opv_declare_target",
        description = "Declare a new named deploy target in this project's secrets.toml (provider and public options such as the Fly app, the products it delivers). Never changes an existing target and never takes deploy credentials. Edits the local file only; its state vault and delivery items come from the next approved structural plan. Syncing or deploying to it stays a separately approved step.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    async fn declare_target(&self, Parameters(args): Parameters<DeclareTarget>) -> String {
        self.serialized(move |project| {
            let names = [&args.environment, &args.target]
                .into_iter()
                .chain(args.products.iter())
                .chain(args.options.keys());
            if names.into_iter().any(|n| !identifier(n))
                || args
                    .options
                    .values()
                    .any(|v| v.len() > 256 || v.chars().any(char::is_control))
            {
                return failure(
                    "invalid_name",
                    "Use declared names and public provider options only.",
                );
            }
            let t = crate::app::declare::Target {
                environment: args.environment,
                name: args.target,
                provider: args.provider,
                fields: args.options,
                products: args.products,
            };
            declared(project, |r, path| crate::app::declare::target(r, path, &t))
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
        self.serialized(move |project| {
            let r = ProcessRunner::new(Budget::starting_now(Duration::from_secs(300)), false);
            let req = config_store::Request {
                start: project.into(),
                config: None,
                project: None,
                manifest_only: false,
                account: config_store::account_env(),
            };
            let fleet = match config_store::locate(&req, &r).and_then(|found| found.load(&r)) {
                Ok(fleet) => fleet,
                Err(e) => return generate_failure(&e),
            };
            // Writes go to the project's own 1Password account, never op's default.
            match crate::app::structure::binding(project, &r) {
                Ok((_, account)) => r.use_account(Some(account)),
                Err(e) => return generate_failure(&e),
            }
            generate(&fleet, &args.environment, &args.keys, &r, std::env::vars())
        })
        .await
    }

    #[tool(
        name = "opv_sync",
        description = "Run exactly the deployment (sync) plan plan_id once, after a person approved it in their own terminal with `opv approve <plan_id> --sync <env>` (the approve_command opv_deployment_plan returns, with the same --target, --product, --deploy, --prune and --rotate). Refuses a stale or unapproved plan, writing nothing; the approval is single use and lasts 15 minutes. Rotates only the immutable keys the person approved and never prunes an immutable key. Returns the names written, pruned, pending and held, and whether it deployed; never a value.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false
        )
    )]
    async fn sync(&self, Parameters(args): Parameters<SyncScopeArgs>) -> String {
        self.serialized(move |project| {
            let r = ProcessRunner::new(Budget::starting_now(Duration::from_secs(900)), false);
            let req = config_store::Request {
                start: project.into(),
                config: None,
                project: None,
                manifest_only: false,
                account: config_store::account_env(),
            };
            let fleet = match config_store::locate(&req, &r).and_then(|found| found.load(&r)) {
                Ok(fleet) => fleet,
                Err(e) => return structure_failure(&e, SYNC_CLI),
            };
            let (name, account) = match crate::app::structure::binding(project, &r) {
                Ok(b) => b,
                Err(e) => return structure_failure(&e, SYNC_CLI),
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
}

/// A sync plan id: eight lowercase hex digits.
fn sync_plan_id(s: &str) -> bool {
    s.len() == crate::domain::provenance::PLAN_ID_LEN
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// An `opv approve … --sync …` command built by opv itself: safe to repeat.
fn approve_step(next: Option<&str>) -> Option<String> {
    next.filter(|n| {
        n.starts_with("opv approve ")
            && n.len() <= 300
            && n.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b" -_".contains(&b))
    })
    .map(str::to_string)
}

/// `opv_sync` as a value: run the approved sync plan, or a fixed error. `vars` are the
/// process environment variables checked for an op credential; `consume` uses up the
/// approval. Built field by field: names only, never a value or upstream text.
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
    if let Some(var) = credential_in_environment(vars) {
        let mut answer = failure(
            "credential_in_environment",
            "An approved sync runs with the person's own 1Password sign-in. Start the opv MCP server without op session tokens, service-account or Connect credentials in its environment, or let the person run opv sync in their own terminal.",
        );
        answer["variable"] = json!(var);
        return answer;
    }
    let names = std::iter::once(&args.environment)
        .chain(args.targets.iter())
        .chain(args.product.iter());
    // Each --rotate entry is PRODUCT/KEY, both declared-name identifiers.
    let rotate_ok = args.rotate.iter().all(|r| {
        r.split_once('/')
            .is_some_and(|(p, k)| identifier(p) && identifier(k))
    });
    if names.into_iter().any(|n| !identifier(n))
        || args.targets.len() > 20
        || !rotate_ok
        || args.rotate.len() > 20
    {
        return failure("invalid_name", "Use declared names only.");
    }
    if !sync_plan_id(&args.plan_id) {
        return failure("invalid_plan_id", "Call opv_deployment_plan for a plan_id.");
    }
    if !fleet.environments.contains_key(&args.environment) {
        return failure("unknown_env", &code_hint("unknown_env", SYNC_CLI));
    }
    crate::scrub::clear_mcp_registry();
    let _redaction_scope = RedactionScope;
    let scope = crate::app::approve::SyncScope {
        env: args.environment.clone(),
        targets: args.targets.clone(),
        product: args.product.clone(),
        deploy: args.deploy,
        prune: args.prune,
        rotate: args.rotate.clone(),
    };
    let mut report = zeroize::Zeroizing::new(Vec::new());
    let ran = crate::app::approve::run_approved_sync(
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
        consume,
    );
    if let Err(e) = ran {
        let code = e.code().as_str();
        let fallback = code_hint(code, SYNC_CLI);
        let human_action = match code {
            "stale_plan" => {
                "The plan changed since it was approved; nothing was written and the approval was not used. Show the person the new plan and ask them to run approve_command in their own terminal."
            }
            "approval_required" => {
                "No unused approval covers this exact plan and scope. Ask the person to run approve_command in their own terminal, then call opv_sync again."
            }
            "op_not_signed_in" | "auth_required" => {
                "The person signs in (1Password desktop app integration, or the target's CLI) in their own terminal, then call opv_sync again."
            }
            _ => fallback.as_str(),
        };
        let mut answer = error_failure(&e, human_action);
        answer["approve_command"] = json!(approve_step(e.next_step()));
        return answer;
    }
    let doc: Value = serde_json::from_slice(&report).unwrap_or(Value::Null);
    let names = |field: &str| -> Vec<String> {
        doc[field]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str().or_else(|| v["name"].as_str()))
            .filter(|n| {
                n.len() <= 256
                    && n.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-./".contains(&b))
            })
            .map(str::to_string)
            .collect()
    };
    json!({
        "ok": true,
        "plan_id": args.plan_id,
        "written": names("written_names"),
        "pruned": names("pruned"),
        "pending": names("pending"),
        "held": names("held"),
        "deployed": doc["deployed"].as_bool().unwrap_or(false),
        "human_action": "Done once; the approval is used up. Check delivery with opv_ready or opv delivery verify.",
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

/// The CLI command named in hints for `opv_sync` failures.
const SYNC_CLI: &str = "opv sync <env> --approved <plan_id>";

/// The hint for a `policy_refused` write: the CI, service-account, deploy-credential and
/// unknown-identity refusals (`require_person`) all mean a person must run it themselves.
const PERSON_WRITES: &str = "Writes to 1Password need a person signed in with their own session: the person runs it in their own terminal without CI, service-account, Connect or deploy credentials (signing in with opv login when asked).";

/// True when only a person can take the next step for `code`: the error table's
/// [`crate::error::Code::human_required`], and for the MCP-only codes, a credential in the
/// server's environment.
fn human_required(code: &str) -> bool {
    code == "credential_in_environment"
        || crate::error::Code::ALL
            .iter()
            .any(|c| c.as_str() == code && c.human_required())
}

/// A failure answer: `{ok: false, code, human_required, human_action}`. `human_action` is
/// fixed text chosen by code, never an error message.
fn failure(code: &str, human_action: &str) -> Value {
    json!({"ok": false, "code": code, "human_required": human_required(code), "human_action": human_action})
}

/// `step` when it is one `opv …` command that runs as typed ([`crate::error::is_runnable`]):
/// built by opv from names, so it carries no value. Anything else is dropped.
fn runnable_opv(step: Option<&str>) -> Option<&str> {
    step.filter(|s| {
        s.starts_with("opv ")
            && s.len() <= 200
            && s.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
            && crate::error::is_runnable(s)
    })
}

/// The answer for `e`: its code, whether a person must act, `human_action`, and its `next`
/// and `do` when each is a runnable `opv` command. Never its message, which can quote
/// upstream output.
fn error_failure(e: &crate::error::Error, human_action: &str) -> Value {
    let mut v = failure(e.code().as_str(), human_action);
    if let Some(next) = runnable_opv(e.next_step()) {
        v["next"] = json!(next);
    }
    if let Some(action) = runnable_opv(e.action()) {
        v["do"] = json!(action);
    }
    v
}

/// The fixed hint for `code`, never an error message. `cli` is the CLI command a person
/// runs in their own terminal for the full explanation.
fn code_hint(code: &str, cli: &str) -> String {
    let fixed = match code {
        "op_not_signed_in"
        | "auth_required"
        | "desktop_app_unavailable"
        | "sign_in_cancelled"
        | "credential_rejected" => {
            "The person signs in to 1Password (the desktop app, with its CLI integration on) in their own terminal, with the command in next when there is one, then call this tool again."
        }
        "account_not_registered" => {
            "The person adds the project's 1Password account with opv login --add in their own terminal, then call this tool again."
        }
        "account_required" | "account_ambiguous" => {
            "The person picks the project's 1Password account with opv login --account <email or account ID> in their own terminal, then call this tool again."
        }
        "unknown_env" => "Name a declared environment; opv_configuration lists them.",
        "unknown_product" => "Name a declared product; opv_configuration lists them.",
        "undeclared_key" => {
            "Declare the key with opv_declare_key, then create its empty 1Password field with opv_structure_plan and opv_structure_apply."
        }
        "no_target" => "The environment has no deploy target; declare one with opv_declare_target.",
        "config_not_found" => "There is no secrets.toml; a person creates it with opv init.",
        "invalid_name" => {
            "Use declared names only (letters, digits, '.', '_', '/' and '-'); opv_configuration lists them."
        }
        "usage" => "An argument is missing or not valid; check the tool's input.",
        "vault_no_access" | "ids_not_in_account" => {
            "The signed-in 1Password account cannot see a recorded vault: the person signs in to the account that owns it (opv login --account) or is granted access, then call this tool again."
        }
        "dependency_missing" => {
            "op or a target CLI is missing or unusable: the person installs it (opv doctor shows which), then call this tool again."
        }
        "findings" | "keys_blocking" => {
            "Keys are missing or failing a rule: the person fills them in 1Password (opv_ready lists them by name), then call this tool again."
        }
        "outcome_unknown" | "provider_unavailable" | "interrupted" | "config_changed" => {
            "Nothing is known to be broken; call this tool again."
        }
        "policy_refused" => {
            return format!(
                "opv refused this and changed nothing. {PERSON_WRITES} Otherwise the person runs {cli} in their own terminal to see why."
            );
        }
        "terminal_required" => {
            return format!(
                "This needs a change only a person makes (such as a layout repair): they run {cli} in their own terminal and follow it, then call this tool again."
            );
        }
        "invalid_receipt" | "unsupported_receipt" | "inspection_unavailable" => {
            return format!(
                "opv could not build its report here; the person runs {cli} in their own terminal for details."
            );
        }
        _ if human_required(code) => {
            return format!(
                "A person acts on this: they run {cli} in their own terminal, which explains it; secret values are entered only in 1Password."
            );
        }
        _ => {
            return format!(
                "Fix the cause, then call this tool again; the person runs {cli} in their own terminal for details."
            );
        }
    };
    fixed.to_string()
}

/// A failure answer for `code` with its [`code_hint`].
fn inspection_error(code: &str, cli: &str) -> Value {
    failure(code, &code_hint(code, cli))
}

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

/// The project's configuration, loaded on `r`.
fn load_fleet(
    project: &std::path::Path,
    r: &dyn CommandRunner,
) -> Result<crate::domain::Fleet, crate::error::Error> {
    let req = config_store::Request {
        start: project.into(),
        config: None,
        project: None,
        manifest_only: false,
        account: config_store::account_env(),
    };
    config_store::locate(&req, r).and_then(|found| found.load(r))
}

fn inspect(project: &std::path::Path, operation: Operation, env: Option<&str>) -> Value {
    let cli = match operation {
        Operation::Ready => "opv ready",
        Operation::Configuration => "opv config describe",
    };
    crate::scrub::clear_mcp_registry();
    let _redaction_scope = RedactionScope;
    if env.is_some_and(|e| !identifier(e)) {
        return inspection_error("invalid_name", cli);
    }
    let r = read_only(INSPECT_BUDGET);
    let fleet = match load_fleet(project, &r) {
        Ok(fleet) => fleet,
        Err(e) => return error_failure(&e, &code_hint(e.code().as_str(), cli)),
    };
    if let Some(env) = env
        && !fleet.environments.contains_key(env)
    {
        return inspection_error("unknown_env", cli);
    }
    if matches!(operation, Operation::Configuration) {
        return configuration_projection(&fleet);
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    let result = crate::app::ready::run(&fleet, None, env, &r, true, None, &mut *bytes);
    receipt_answer(&r, &bytes, result, cli, |doc| {
        project_receipt(doc, Operation::Ready)
    })
}

/// The answer for a CLI document in `bytes` that `result` produced on `r`: a refused write
/// is `terminal_required`, an unreadable document the error (or `invalid_receipt`), else
/// `project` of it, marked failed with the error's code and step when `result` failed.
fn receipt_answer<R: CommandRunner>(
    r: &ReadOnly<R>,
    bytes: &[u8],
    result: Result<(), crate::error::Error>,
    cli: &str,
    project: impl FnOnce(&Value) -> Value,
) -> Value {
    if r.refused.load(Ordering::Relaxed) {
        return inspection_error("terminal_required", cli);
    }
    let mut doc: Value = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(_) => {
            return match result {
                Err(e) => error_failure(&e, &code_hint(e.code().as_str(), cli)),
                Ok(()) => inspection_error("invalid_receipt", cli),
            };
        }
    };
    let mut response = project(&doc);
    if let Err(error) = result {
        let code = error.code().as_str();
        response["ok"] = json!(false);
        response["code"] = json!(code);
        response["human_required"] = json!(human_required(code));
        if let Some(next) = runnable_opv(error.next_step()) {
            response["next"] = json!(next);
        }
    }
    crate::scrub::wipe_json(&mut doc);
    response
}

/// The CLI command named in hints for `opv_deployment_plan` failures.
const PLAN_CLI: &str = "opv plan <env>";

/// `opv_deployment_plan`: the plan `opv plan <env> [--target t]… [--product p] [--rotate
/// P/K]… --json` prints ([`crate::app::sync::plan_rotating`]), projected, with the
/// `approve_command` for exactly that scope.
fn deployment_plan(project: &std::path::Path, args: &DeploymentPlanScope) -> Value {
    crate::scrub::clear_mcp_registry();
    let _redaction_scope = RedactionScope;
    if let Some(refused) = plan_scope_refusal(args) {
        return refused;
    }
    let r = read_only(INSPECT_BUDGET);
    let fleet = match load_fleet(project, &r) {
        Ok(fleet) => fleet,
        Err(e) => return error_failure(&e, &code_hint(e.code().as_str(), PLAN_CLI)),
    };
    deployment_plan_from_fleet(&fleet, args, &r)
}

/// `invalid_name` when a name in `args` is not an identifier, a rotate entry is not
/// `PRODUCT/KEY`, or there are more than 20 targets or rotate entries.
fn plan_scope_refusal(args: &DeploymentPlanScope) -> Option<Value> {
    let rotate_ok = args.rotate.iter().all(|r| {
        r.split_once('/')
            .is_some_and(|(p, k)| identifier(p) && identifier(k))
    });
    let bad = std::iter::once(&args.environment)
        .chain(args.targets.iter())
        .chain(args.product.iter())
        .any(|n| !identifier(n))
        || !rotate_ok
        || args.targets.len() > 20
        || args.rotate.len() > 20;
    bad.then(|| inspection_error("invalid_name", PLAN_CLI))
}

/// [`deployment_plan`] on an already-loaded fleet and the read-only runner `r`.
fn deployment_plan_from_fleet<R: CommandRunner>(
    fleet: &crate::domain::Fleet,
    args: &DeploymentPlanScope,
    r: &ReadOnly<R>,
) -> Value {
    if !fleet.environments.contains_key(&args.environment) {
        return inspection_error("unknown_env", PLAN_CLI);
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
    receipt_answer(r, &bytes, result, PLAN_CLI, |doc| plan_receipt(doc, &scope))
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
fn ci_refusal(what: &str) -> Option<Value> {
    crate::host::Host::detect().ci.then(|| {
        let mut answer = failure(
            "policy_refused",
            &format!("{what} writes to 1Password, which is read-only under CI. {PERSON_WRITES}"),
        );
        answer["variable"] = json!("CI");
        answer
    })
}

/// The CLI command named in hints for `opv_delivery_preview` failures.
const PREVIEW_CLI: &str = "opv run <env> --preview";

/// `opv_delivery_preview`: validate the names with [`identifier`], load the project's
/// configuration on a read-only runner, then answer with the shared preview document.
fn delivery_preview_doc(
    project: &std::path::Path,
    environment: &str,
    product: Option<&str>,
    role: Option<&str>,
    remote: Option<&str>,
) -> Value {
    if !identifier(environment)
        || product.is_some_and(|p| !identifier(p))
        || role.is_some_and(|r| !identifier(r))
        || remote.is_some_and(|r| !identifier(r))
    {
        return inspection_error("invalid_name", PREVIEW_CLI);
    }
    let r = read_only(INSPECT_BUDGET);
    let fleet = match load_fleet(project, &r) {
        Ok(fleet) => fleet,
        Err(e) => return error_failure(&e, &code_hint(e.code().as_str(), PREVIEW_CLI)),
    };
    delivery_preview_from_fleet(&fleet, environment, product, role, remote, &r)
}

/// The MCP answer from an already-loaded fleet: the same document the CLI's
/// `opv run --preview --json` prints ([`crate::app::delivery_preview::build`]).
fn delivery_preview_from_fleet(
    fleet: &crate::domain::Fleet,
    environment: &str,
    product: Option<&str>,
    role: Option<&str>,
    remote: Option<&str>,
    runner: &dyn CommandRunner,
) -> Value {
    if !fleet.environments.contains_key(environment) {
        return inspection_error("unknown_env", PREVIEW_CLI);
    }
    match crate::app::delivery_preview::build_for(fleet, environment, product, role, remote, runner)
    {
        Ok(doc) => doc,
        Err(e) => preview_failure(fleet, environment, product, remote, &e),
    }
}

/// A preview failure with a hint for its cause: an undeclared product, a product to pick
/// (with the products to pick from), a role to name (with the roles the product's keys
/// declare) or a source-only product. Names only.
fn preview_failure(
    fleet: &crate::domain::Fleet,
    environment: &str,
    product: Option<&str>,
    remote: Option<&str>,
    e: &crate::error::Error,
) -> Value {
    let code = e.code().as_str();
    let products: Vec<&str> = fleet
        .products
        .iter()
        .filter(|(n, p)| !p.source_only && identifier(n))
        .map(|(n, _)| n.as_str())
        .collect();
    let picked = crate::app::pick_product(fleet, environment, product, "run").ok();
    let prod = picked.as_deref().and_then(|p| fleet.products.get(p));
    let profiles: Vec<&str> = prod
        .map(|p| {
            p.remotes
                .keys()
                .map(String::as_str)
                .filter(|n| identifier(n))
                .collect()
        })
        .unwrap_or_default();
    let unknown_profile = remote.is_some_and(|r| prod.is_some_and(|p| !p.remotes.contains_key(r)));
    let (hint, list) = match code {
        "usage" if unknown_profile => (
            "The product declares no remote profile by that name: name one of remote_profiles. A person adds a reviewed profile under [products.<p>.remotes.<name>]; no tool can.".to_string(),
            Some(("remote_profiles", profiles)),
        ),
        "policy_refused" if remote.is_some() => (
            "This remote profile does not allow this environment or role: preview another environment or role, or a person changes the reviewed profile.".to_string(),
            None,
        ),
        "unknown_product" => (code_hint(code, PREVIEW_CLI), Some(("products", products))),
        "usage" if picked.is_none() => (
            "Several products (or none) have keys desired in this environment: name one with product; products lists them.".to_string(),
            Some(("products", products)),
        ),
        "usage" => (
            "This product's keys declare process roles: name one of roles with role (a role no key declares is refused).".to_string(),
            Some((
                "roles",
                prod.map(crate::app::delivery_preview::declared_roles)
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|r| identifier(r))
                    .collect(),
            )),
        ),
        "config_invalid" if prod.is_some_and(|p| p.source_only) => (
            "This product is source-only: it holds shared values for other products' keys and is never run on its own. Name a product that uses it; products lists them.".to_string(),
            Some(("products", products)),
        ),
        _ => (code_hint(code, PREVIEW_CLI), None),
    };
    let mut v = error_failure(e, &hint);
    if let Some((field, names)) = list {
        v[field] = json!(names);
    }
    v
}

/// The error answer for `e` on a structural or declaration tool: its code, whether a person
/// must act, a hint by code, its runnable `next`, and the new plan id when it is
/// `stale_plan`. Never its text, which can quote upstream output. `cli` is the command a
/// person runs for details.
fn structure_failure(e: &crate::error::Error, cli: &str) -> Value {
    let code = e.code().as_str();
    let hint = match code {
        "approval_required" => {
            "No unused approval covers this plan: the person runs opv approve <plan_id> in their own terminal, then call opv_structure_apply again.".to_string()
        }
        "policy_refused" => format!(
            "opv refused this and changed nothing. {PERSON_WRITES} Otherwise fix the cause (the person runs {cli} in their own terminal to see it), then plan again."
        ),
        _ => code_hint(code, cli),
    };
    let mut v = error_failure(e, &hint);
    if let Some(id) = e
        .next_step()
        .and_then(|n| n.strip_prefix("opv approve "))
        .filter(|id| crate::app::structure::is_plan_id(id))
    {
        v["plan_id"] = json!(id);
        v["human_action"] = json!(format!(
            "The plan changed. Review the new plan with opv_structure_plan; a person approves it with `opv approve {id}`."
        ));
    }
    v
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// Run a declaration on the project's `secrets.toml` on the read-only runner: its answer
/// is whether the file changed, never its text.
fn declared(
    project: &std::path::Path,
    f: impl FnOnce(&dyn CommandRunner, &std::path::Path) -> Result<bool, crate::error::Error>,
) -> Value {
    const CLI: &str = "opv add";
    let Some(path) = config_store::walk_up(project, "secrets.toml") else {
        return failure(
            "config_not_found",
            "Declarations edit secrets.toml; a person creates it with opv init.",
        );
    };
    let r = read_only(INSPECT_BUDGET);
    match f(&r, &path) {
        _ if r.refused.load(Ordering::Relaxed) => inspection_error("terminal_required", CLI),
        Ok(changed) => json!({
            "ok": true,
            "changed": changed,
            "human_action": "Call opv_structure_plan to see what this needs in 1Password; a person approves it with opv approve.",
        }),
        Err(e) => structure_failure(&e, CLI),
    }
}

/// The CLI command named in hints for `opv_access` failures.
const ACCESS_CLI: &str = "opv access <env>";

/// `opv_access`'s runner budget: above the 1Password app's approval wait
/// ([`crate::adapters::onepassword::APPROVAL_TIMEOUT`]), so the session check that follows
/// a `wake` waiting on the app's prompt still has time to run.
const ACCESS_BUDGET: Duration = Duration::from_secs(120);

/// `opv access` as checked identifiers: what each CI or deploy identity needs, its state,
/// and the owner's `opv access … --create` command for each identity missing a grant.
fn access_projection(project: &std::path::Path, env: Option<&str>, target: Option<&str>) -> Value {
    if env.is_some_and(|e| !identifier(e)) || target.is_some_and(|t| !identifier(t)) {
        return inspection_error("invalid_name", ACCESS_CLI);
    }
    if target.is_some() && env.is_none() {
        return failure("usage", "Name the environment of the target.");
    }
    crate::scrub::clear_mcp_registry();
    let _redaction_scope = RedactionScope;
    let r = read_only(ACCESS_BUDGET);
    let fleet = match load_fleet(project, &r) {
        Ok(fleet) => fleet,
        Err(e) => return access_failure(&e),
    };
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    let result = crate::app::access::run(&fleet, env, target, None, &r, true, &mut *bytes);
    if r.refused.load(Ordering::Relaxed) {
        return inspection_error("terminal_required", ACCESS_CLI);
    }
    let Ok(doc) = serde_json::from_slice::<Value>(&bytes) else {
        return match result {
            Err(e) => access_failure(&e),
            Ok(()) => inspection_error("invalid_receipt", ACCESS_CLI),
        };
    };
    access_answer(&doc)
}

/// An `opv_access` failure: its code, a hint by code (never "plan again": access plans
/// nothing), and its runnable `next` (such as the `opv login --account …` that signs the
/// person in to the project's account).
fn access_failure(e: &crate::error::Error) -> Value {
    let code = e.code().as_str();
    let hint = match code {
        "policy_refused" => format!(
            "opv refused this check and changed nothing; the person runs {ACCESS_CLI} in their own terminal to see why."
        ),
        _ => code_hint(code, ACCESS_CLI),
    };
    error_failure(e, &hint)
}

/// The `opv access --json` document as the MCP answer, field by field (pure).
fn access_answer(doc: &Value) -> Value {
    let id_ok = |s: &str| crate::config::is_id(s) && s.len() <= 64;
    let mut envs = Vec::new();
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
    json!({
        "ok": true,
        "environments": envs,
        "changes_available": false,
        "human_action": "Creating an identity is the person's: they run its owner_command in their own terminal, with the GitHub repository and environment their CI job uses. The token goes to GitHub without being shown; never ask for it.",
    })
}

fn structure_plan(project: &std::path::Path) -> Value {
    const CLI: &str = "opv structure plan";
    crate::scrub::clear_mcp_registry();
    let _redaction_scope = RedactionScope;
    let r = read_only(Duration::from_secs(60));
    let planned = crate::app::structure::scope(project, &r).and_then(|scope| {
        r.inner.use_account(Some(scope.account.clone()));
        let text = std::fs::read_to_string(&scope.path).map_err(|e| {
            crate::error::Error::Config(
                format!("cannot read the configuration ({})", e.kind()).into(),
            )
        })?;
        crate::app::structure::plan(&r, &text, &scope.project, &scope.account)
    });
    if r.refused.load(Ordering::Relaxed) {
        return inspection_error("terminal_required", CLI);
    }
    match planned {
        Ok(p) => plan_projection(&p),
        Err(e) => structure_failure(&e, CLI),
    }
}

fn structure_apply(project: &std::path::Path, plan_id: &str) -> Value {
    const CLI: &str = "opv structure apply <plan_id>";
    if !crate::app::structure::is_plan_id(plan_id) {
        return failure("invalid_plan_id", "Call opv_structure_plan for a plan_id.");
    }
    if let Some(var) = credential_in_environment(std::env::vars()) {
        let mut answer = failure(
            "credential_in_environment",
            "Structural writes go through the 1Password app, which asks the person to authorize them. Start the opv MCP server without op session tokens, service-account or Connect credentials in its environment, or run opv bootstrap in your own terminal instead.",
        );
        answer["variable"] = json!(var);
        return answer;
    }
    if let Some(refused) = ci_refusal("The structural apply") {
        return refused;
    }
    crate::scrub::clear_mcp_registry();
    let _redaction_scope = RedactionScope;
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
    });
    match applied {
        Ok(a) => applied_projection(&a),
        Err(e) => structure_failure(&e, CLI),
    }
}

/// `opv_generate` as a value: generate each `product/KEY` and write it into its empty
/// 1Password field, or a fixed error. `vars` are the process environment variables checked
/// for a write credential (injected so a test need not set the process environment). The
/// sink is discarded: no value and no length other than the recipe's byte count is returned.
fn generate(
    fleet: &crate::domain::Fleet,
    env_name: &str,
    keys: &[String],
    r: &dyn CommandRunner,
    vars: impl Iterator<Item = (String, String)>,
) -> Value {
    if let Some(var) = credential_in_environment(vars) {
        let mut answer = failure(
            "credential_in_environment",
            "Generating writes through the 1Password app, which asks the person to authorize them. Start the opv MCP server without op session tokens, service-account or Connect credentials in its environment, or run opv generate in your own terminal instead.",
        );
        answer["variable"] = json!(var);
        return answer;
    }
    if let Some(refused) = ci_refusal("Generating") {
        return refused;
    }
    if keys.is_empty() || keys.len() > 20 {
        return failure("invalid_name", &generate_action("invalid_name"));
    }
    if keys.iter().any(|k| {
        k.split_once('/')
            .is_none_or(|(product, key)| !identifier(product) || !identifier(key))
    }) {
        return failure("invalid_name", &generate_action("invalid_name"));
    }
    if !fleet.environments.contains_key(env_name) {
        return failure("unknown_env", &generate_action("unknown_env"));
    }
    crate::scrub::clear_mcp_registry();
    let _redaction_scope = RedactionScope;
    // Every name and declaration is checked before anything is written.
    let chosen = match crate::app::generate::plan(fleet, env_name, keys) {
        Ok(chosen) => chosen,
        Err(e) => return generate_failure(&e),
    };
    let mut sink = Vec::new();
    if let Err(e) = crate::app::generate::run(fleet, env_name, keys, r, &mut sink) {
        return generate_failure(&e);
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
        "next": format!("opv status {env_name}"),
    })
}

/// The fixed human action for an error code; never a message or a value from upstream.
fn generate_action(code: &str) -> String {
    match code {
        "policy_refused" => format!(
            "opv refused and wrote nothing. Either a key is not self-made (opv generates only keys with base64_bytes or hex_bytes rules, into empty fields, and never replaces a value; a provider-issued key is created by the person at the provider and typed in 1Password), or this run may not write to 1Password. {PERSON_WRITES}"
        ),
        "invalid_name" => {
            "Name 1 to 20 keys as <product>/<KEY>, using declared names only.".to_string()
        }
        _ => code_hint(code, "opv generate <env> <product/KEY>"),
    }
}

/// `e`'s code with its fixed human action and runnable `next`; never its text, which can
/// quote upstream output.
fn generate_failure(e: &crate::error::Error) -> Value {
    error_failure(e, &generate_action(e.code().as_str()))
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

/// Construct a new response, never recursively forwarding arbitrary upstream fields.
fn project_receipt(doc: &Value, operation: Operation) -> Value {
    const CLI: &str = "opv ready";
    if doc.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return inspection_error("unsupported_receipt", CLI);
    }
    match operation {
        Operation::Ready => {
            let Some(findings) = doc.get("findings").and_then(Value::as_array) else {
                return inspection_error("invalid_receipt", CLI);
            };
            if findings.iter().any(|f| !f["blocking"].is_boolean()) {
                return inspection_error("invalid_receipt", CLI);
            }
            let projected: Vec<Value> = findings.iter().map(ready_finding).collect();
            let targets: Vec<Value> = doc["targets"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(ready_target)
                .collect();
            json!({"ok": true, "blocking_findings": findings.iter().filter(|f| f["blocking"] == true).count(), "other_findings": findings.iter().filter(|f| f["blocking"] == false).count(), "findings": projected, "targets": targets, "human_action": "Use opv ready in your terminal for details; humans authenticate and enter values in 1Password.", "snapshot_only": true})
        }
        Operation::Configuration => unreachable!(),
    }
}

/// The `opv plan --json` document as the MCP answer, field by field, with the
/// `approve_command` for exactly `scope` (its targets, product and rotate entries), so the
/// approval a person records covers the `opv_sync` that names the same scope.
fn plan_receipt(doc: &Value, scope: &crate::app::approve::SyncScope) -> Value {
    if doc.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return inspection_error("unsupported_receipt", PLAN_CLI);
    }
    let Some(rows) = doc.get("rows").and_then(Value::as_array) else {
        return inspection_error("invalid_receipt", PLAN_CLI);
    };
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
    let approve = plan_id.map(|id| scope.approve_command(id));
    json!({"ok": true, "rows": rows, "stage": names("stage"), "prune": names("prune"), "plan_id": plan_id, "approve_command": approve, "human_action": "A person reviews and approves this plan with approve_command in their own terminal (adding --deploy or --prune there to allow those); opv_sync with the same plan_id, targets, product, rotate and flags then runs exactly it once. Sync, deploy, prune and rotation happen only through that approved opv_sync, which never prunes an immutable key."})
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
        let doc = json!({"schema_version": 1, "findings": [{"blocking": true, "message": "SECRET_MARKER", "prerequisite": "SECRET_MARKER"}], "value": "SECRET_MARKER"});
        assert!(
            !project_receipt(&doc, Operation::Ready)
                .to_string()
                .contains("SECRET_MARKER")
        );
    }
    #[test]
    fn plan_drops_values_even_when_the_source_contains_them() {
        let doc = json!({"schema_version": 1, "rows": [{"product": "api", "key": "API_KEY", "action": "stage", "value": "SECRET_MARKER", "reason": "SECRET_MARKER"}], "plan_id": "123abc"});
        assert!(
            !plan_receipt(&doc, &plan_scope(&[], None, &[]))
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

    #[test]
    fn a_failed_structural_call_never_returns_upstream_text() {
        let e = crate::error::Error::Source("op said OP_SESSION_my=SECRET_MARKER".into());
        assert!(
            !structure_failure(&e, "opv structure plan")
                .to_string()
                .contains("SECRET_MARKER")
        );
    }

    #[test]
    fn a_stale_structural_plan_returns_the_new_plan_id() {
        let e = crate::error::Error::Policy("stale".into())
            .with_code(crate::error::Code::StalePlan)
            .with_next("opv approve sp-0123456789abcdef");
        assert_eq!(
            structure_failure(&e, "opv structure plan")["plan_id"],
            "sp-0123456789abcdef"
        );
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
        let doc = json!({"schema_version": 1, "findings": [{"blocking": true}]});
        assert_eq!(
            project_receipt(&doc, Operation::Ready)["blocking_findings"],
            1
        );
    }

    fn ready_doc(findings: Value, targets: Value) -> Value {
        json!({"schema_version": 1, "findings": findings, "targets": targets})
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
            !project_receipt(&doc, Operation::Ready)
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
            project_receipt(&doc, Operation::Ready)["findings"][0]["step"],
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
            project_receipt(&doc, Operation::Ready)["findings"][0]["step"],
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
            project_receipt(&doc, Operation::Ready)["findings"][0]["step"],
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
            project_receipt(&doc, Operation::Ready)["findings"][0]["step"],
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
            project_receipt(&doc, Operation::Ready)["findings"][0]
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
            project_receipt(&doc, Operation::Ready)["findings"][0]
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
            project_receipt(&doc, Operation::Ready)["findings"][0]
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
            project_receipt(&doc, Operation::Ready)["targets"]
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
            project_receipt(&doc, Operation::Ready)["targets"][0]
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
        let _ = generate(&fleet, "dev", &["api/SESSION_KEY".into()], &op, no_vars());
        assert_eq!(
            generated_field(&op, &id, "SESSION_KEY").map(|v| v.len()),
            Some(44)
        );
    }

    #[test]
    fn opv_generate_never_returns_the_generated_value() {
        let (fleet, op, id) = generate_world();
        let answer = generate(&fleet, "dev", &["api/SESSION_KEY".into()], &op, no_vars());
        let value = generated_field(&op, &id, "SESSION_KEY").unwrap();
        assert!(!answer.to_string().contains(&value));
    }

    #[test]
    fn opv_generate_reports_the_base64_recipe() {
        let (fleet, op, _) = generate_world();
        let answer = generate(&fleet, "dev", &["api/SESSION_KEY".into()], &op, no_vars());
        assert_eq!(
            answer["generated"][0],
            json!({"product": "api", "key": "SESSION_KEY", "encoding": "base64", "bytes": 32})
        );
    }

    #[test]
    fn opv_generate_offers_the_status_command_next() {
        let (fleet, op, _) = generate_world();
        let answer = generate(&fleet, "dev", &["api/SESSION_KEY".into()], &op, no_vars());
        assert_eq!(answer["next"], "opv status dev");
    }

    #[test]
    fn opv_generate_refuses_a_prefix_rule_key_with_policy_refused() {
        let (fleet, op, _) = generate_world();
        let answer = generate(&fleet, "dev", &["api/STRIPE_KEY".into()], &op, no_vars());
        assert_eq!(answer["code"], "policy_refused");
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
        );
        assert_eq!(generated_field(&op, &id, "SESSION_KEY"), None);
    }

    #[test]
    fn opv_generate_refuses_a_filled_field_with_policy_refused() {
        let (fleet, op, _) = generate_world();
        let answer = generate(&fleet, "dev", &["api/WEBHOOK_HEX".into()], &op, no_vars());
        assert_eq!(answer["code"], "policy_refused");
    }

    #[test]
    fn opv_generate_keeps_an_existing_value() {
        let (fleet, op, id) = generate_world();
        let _ = generate(&fleet, "dev", &["api/WEBHOOK_HEX".into()], &op, no_vars());
        assert_eq!(
            generated_field(&op, &id, "WEBHOOK_HEX").as_deref(),
            Some("already-set")
        );
    }

    #[test]
    fn opv_generate_returns_invalid_name_for_a_bad_name() {
        let (fleet, op, _) = generate_world();
        let answer = generate(&fleet, "dev", &["api/NO PE".into()], &op, no_vars());
        assert_eq!(answer["code"], "invalid_name");
    }

    #[test]
    fn opv_generate_touches_no_1password_for_an_invalid_name() {
        let (fleet, op, _) = generate_world();
        let _ = generate(&fleet, "dev", &["api/NO PE".into()], &op, no_vars());
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
        );
        assert_eq!(answer["code"], "credential_in_environment");
    }

    #[test]
    fn opv_generate_reports_when_nobody_is_signed_in() {
        let (fleet, op, _) = generate_world();
        op.signed_in.set(false);
        let answer = generate(&fleet, "dev", &["api/SESSION_KEY".into()], &op, no_vars());
        assert_eq!(answer["code"], "op_not_signed_in");
    }

    #[test]
    fn opv_generate_returns_unknown_env_for_an_undeclared_environment() {
        let (fleet, op, _) = generate_world();
        let answer = generate(&fleet, "prod", &["api/SESSION_KEY".into()], &op, no_vars());
        assert_eq!(answer["code"], "unknown_env");
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
        )
    }

    #[test]
    fn opv_delivery_preview_previews_a_remote_profile() {
        assert_eq!(remote_preview("builder")["transport"], "remote");
    }

    #[test]
    fn opv_delivery_preview_lists_the_profiles_for_an_unknown_one() {
        assert_eq!(
            remote_preview("elsewhere")["remote_profiles"],
            json!(["builder"])
        );
    }

    #[test]
    fn opv_delivery_preview_returns_the_shared_document() {
        let fleet = crate::app::testutil::role_fleet();
        let sign_in = || Output::success(b"{\"user_type\":\"USER\"}".to_vec());
        let r = FakeRunner::new([sign_in(), sign_in()]);
        let via_tool =
            delivery_preview_from_fleet(&fleet, "prod", Some("allumata"), Some("serve"), None, &r);
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
        let answer = delivery_preview_doc(std::path::Path::new("."), "prod!", None, None, None);
        assert_eq!(answer["code"], "invalid_name");
    }

    fn not_signed_in(next: &str) -> crate::error::Error {
        crate::error::Error::Auth("not signed in; op said SECRET_MARKER".into())
            .with_code(crate::error::Code::OpNotSignedIn)
            .with_next(next)
    }

    #[test]
    fn an_error_answer_says_a_person_must_act_on_a_sign_in() {
        let v = error_failure(&not_signed_in("opv login --account ABCDEF"), "hint");
        assert_eq!(v["human_required"], true);
    }

    #[test]
    fn an_error_answer_says_no_person_is_needed_for_an_unknown_environment() {
        assert_eq!(
            inspection_error("unknown_env", "opv ready")["human_required"],
            false
        );
    }

    #[test]
    fn an_error_answer_passes_through_a_runnable_opv_next() {
        let v = error_failure(&not_signed_in("opv login --account ABCDEF"), "hint");
        assert_eq!(v["next"], "opv login --account ABCDEF");
    }

    #[test]
    fn an_error_answer_drops_a_next_that_is_not_an_opv_command() {
        let v = error_failure(&not_signed_in("op signin --raw SECRET_MARKER"), "hint");
        assert!(v.get("next").is_none());
    }

    #[test]
    fn an_error_answer_drops_a_next_with_a_placeholder() {
        let v = error_failure(&not_signed_in("opv login --account <ID>"), "hint");
        assert!(v.get("next").is_none());
    }

    #[test]
    fn an_error_answer_passes_through_a_runnable_opv_do() {
        let e = not_signed_in("opv ready").with_do("opv login --add");
        assert_eq!(error_failure(&e, "hint")["do"], "opv login --add");
    }

    #[test]
    fn an_error_answer_drops_a_do_that_is_prose() {
        let e = not_signed_in("opv ready").with_do("sign in at the prompt SECRET_MARKER");
        assert!(error_failure(&e, "hint").get("do").is_none());
    }

    #[test]
    fn an_error_answer_never_carries_the_error_message() {
        let v = error_failure(&not_signed_in("opv login --account ABCDEF"), "hint");
        assert!(!v.to_string().contains("SECRET_MARKER"));
    }

    #[test]
    fn a_sign_in_hint_tells_the_person_to_sign_in() {
        assert!(code_hint("op_not_signed_in", ACCESS_CLI).contains("signs in to 1Password"));
    }

    #[test]
    fn an_unreadable_ready_report_sends_the_person_not_the_agent_to_the_terminal() {
        assert!(code_hint("invalid_receipt", "opv ready").contains("the person runs opv ready"));
    }

    #[test]
    fn a_credential_in_the_environment_needs_a_person() {
        assert!(human_required("credential_in_environment"));
    }

    #[test]
    fn every_mcp_only_error_code_is_documented() {
        let doc = include_str!("../docs/mcp.md");
        assert!(
            [
                "invalid_name",
                "invalid_plan_id",
                "credential_in_environment",
                "invalid_receipt",
                "unsupported_receipt",
                "inspection_unavailable",
            ]
            .iter()
            .all(|c| doc.contains(&format!("`{c}`")))
        );
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
    fn an_access_target_that_is_not_a_name_is_invalid_name() {
        let v = access_projection(std::path::Path::new("."), Some("prod"), Some("no pe"));
        assert_eq!(v["code"], "invalid_name");
    }

    #[test]
    fn an_access_target_without_its_environment_is_a_usage_error() {
        let v = access_projection(std::path::Path::new("."), None, Some("fleet"));
        assert_eq!(v["code"], "usage");
    }

    #[test]
    fn an_access_refusal_never_says_to_plan_again() {
        let e = crate::error::Error::Policy("refused".into());
        assert!(
            !access_failure(&e)["human_action"]
                .as_str()
                .unwrap()
                .contains("plan again")
        );
    }

    #[test]
    fn access_has_more_budget_than_the_1password_app_approval_wait() {
        assert!(ACCESS_BUDGET > crate::adapters::onepassword::APPROVAL_TIMEOUT);
    }

    #[test]
    fn a_preview_with_an_undeclared_role_lists_the_declared_roles() {
        let fleet = crate::app::testutil::role_fleet();
        let r = FakeRunner::new([]);
        let v =
            delivery_preview_from_fleet(&fleet, "prod", Some("allumata"), Some("nope"), None, &r);
        assert_eq!(v["roles"], json!(["migrate", "serve"]));
    }

    #[test]
    fn a_preview_of_an_undeclared_product_never_asks_for_a_role() {
        let fleet = crate::app::testutil::role_fleet();
        let r = FakeRunner::new([]);
        let v = delivery_preview_from_fleet(&fleet, "prod", Some("nope"), None, None, &r);
        assert!(!v["human_action"].as_str().unwrap().contains("role"));
    }

    #[test]
    fn a_preview_of_an_undeclared_product_lists_the_products() {
        let fleet = crate::app::testutil::role_fleet();
        let r = FakeRunner::new([]);
        let v = delivery_preview_from_fleet(&fleet, "prod", Some("nope"), None, None, &r);
        assert_eq!(v["products"], json!(["allumata"]));
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
        })
    }

    #[test]
    fn a_scoped_deployment_plan_approves_the_same_targets_product_and_rotation() {
        let doc =
            json!({"schema_version": 1, "environment": "prod", "rows": [], "plan_id": "0123abcd"});
        let v = plan_receipt(&doc, &plan_scope(&["fleet"], Some("api"), &["api/KEY"]));
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
        };
        assert_eq!(plan_scope_refusal(&args).unwrap()["code"], "invalid_name");
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
        };
        assert_eq!(
            deployment_plan_from_fleet(&fleet, &args, &r)["code"],
            "unknown_env"
        );
    }

    #[test]
    fn the_deployment_plan_never_says_sync_is_unavailable_through_mcp() {
        let doc = json!({"schema_version": 1, "rows": [], "plan_id": "0123abcd"});
        let v = plan_receipt(&doc, &plan_scope(&[], None, &[]));
        assert!(
            v["human_action"]
                .as_str()
                .unwrap()
                .contains("only through that approved opv_sync")
        );
    }

    #[test]
    fn a_generate_policy_refusal_names_a_person_running_it_without_ci_credentials() {
        assert!(generate_action("policy_refused").contains("without CI"));
    }

    #[test]
    fn a_structural_policy_refusal_names_a_person_running_it_without_ci_credentials() {
        let e = crate::error::Error::Policy("refused".into());
        assert!(
            structure_failure(&e, "opv structure apply <plan_id>")["human_action"]
                .as_str()
                .unwrap()
                .contains("without CI")
        );
    }

    fn under_ci<T>(f: impl FnOnce() -> T) -> T {
        let env = crate::host::FakeEnv::new("linux")
            .var_val("CI", "true")
            .shell("/bin/bash");
        crate::host::with_test_host(crate::host::Host::from_env(&env), f)
    }

    #[test]
    fn opv_generate_under_ci_names_the_ci_variable() {
        let (fleet, op, _) = generate_world();
        let answer =
            under_ci(|| generate(&fleet, "dev", &["api/SESSION_KEY".into()], &op, no_vars()));
        assert_eq!(answer["variable"], "CI");
    }

    #[test]
    fn opv_generate_under_ci_calls_nothing() {
        let (fleet, op, _) = generate_world();
        let _ = under_ci(|| generate(&fleet, "dev", &["api/SESSION_KEY".into()], &op, no_vars()));
        assert!(op.calls.borrow().is_empty());
    }

    #[test]
    fn the_structural_apply_is_refused_under_ci() {
        assert!(under_ci(|| ci_refusal("The structural apply")).is_some());
    }

    #[test]
    fn a_ready_finding_keeps_its_target() {
        let doc = ready_doc(
            json!([{"code": "grants_missing", "blocking": true,
                    "scope": {"environment": "prod", "target": "fleet"}}]),
            json!([]),
        );
        assert_eq!(
            project_receipt(&doc, Operation::Ready)["findings"][0]["target"],
            "fleet"
        );
    }
}
