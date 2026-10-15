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
pub struct Environment {
    /// A declared environment name, not a path, command, credential, or value.
    environment: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadyScope {
    /// A declared environment name; omitted: every declared environment.
    #[serde(default)]
    environment: Option<String>,
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
        .unwrap_or_else(|_| json!({"ok": false, "code": "inspection_unavailable"}))
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
        description = "Preview deployment actions without executing them. Secret entry, layout repair, sync, deploy, prune, and rotation require explicit human approval and are not available through this server.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn deployment_plan(&self, Parameters(args): Parameters<Environment>) -> String {
        self.inspect(Operation::Plan, Some(args.environment)).await
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
                return structure_error("invalid_name", "Use declared names only.");
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
                return structure_error(
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
}

#[derive(Clone, Copy)]
enum Operation {
    Ready,
    Configuration,
    Plan,
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

fn inspection_error(code: &str) -> Value {
    json!({"ok": false, "code": code, "human_action": "Run opv ready in your own terminal. Enter secret values only in 1Password. Review and approve any changes outside MCP."})
}

struct RedactionScope;
impl Drop for RedactionScope {
    fn drop(&mut self) {
        crate::scrub::clear_mcp_registry();
    }
}

fn inspect(project: &std::path::Path, operation: Operation, env: Option<&str>) -> Value {
    crate::scrub::clear_mcp_registry();
    let _redaction_scope = RedactionScope;
    if env.is_some_and(|e| !identifier(e)) {
        return inspection_error("invalid_environment");
    }
    let r = ReadOnly {
        inner: ProcessRunner::new(Budget::starting_now(Duration::from_secs(20)), false),
        refused: AtomicBool::new(false),
    };
    let req = config_store::Request {
        start: project.into(),
        config: None,
        project: None,
        manifest_only: false,
        account: config_store::account_env(),
    };
    let fleet = match config_store::locate(&req, &r).and_then(|found| found.load(&r)) {
        Ok(fleet) => fleet,
        Err(e) => return inspection_error(e.code().as_str()),
    };
    if let Some(env) = env
        && !fleet.environments.contains_key(env)
    {
        return inspection_error("unknown_environment");
    }
    if matches!(operation, Operation::Configuration) {
        return configuration_projection(&fleet);
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    let result = match operation {
        Operation::Ready => crate::app::ready::run(&fleet, None, env, &r, true, None, &mut *bytes),
        Operation::Plan => crate::app::sync::plan_scoped(
            &fleet,
            env.expect("plan environment"),
            None,
            &r,
            &mut *bytes,
            true,
        ),
        Operation::Configuration => unreachable!(),
    };
    if r.refused.load(Ordering::Relaxed) {
        return inspection_error("human_approval_required");
    }
    let mut doc: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => {
            return inspection_error(
                result
                    .err()
                    .map_or("invalid_receipt", |e| e.code().as_str()),
            );
        }
    };
    let mut response = project_receipt(&doc, operation);
    if let Err(error) = result {
        response["ok"] = json!(false);
        response["code"] = json!(error.code().as_str());
    }
    crate::scrub::wipe_json(&mut doc);
    response
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

fn structure_error(code: &str, human_action: &str) -> Value {
    json!({"ok": false, "code": code, "human_action": human_action})
}

/// The error answer for `e`: its code, and the new plan id when it is `stale_plan`. Never
/// its text, which can quote upstream output.
fn structure_failure(e: &crate::error::Error) -> Value {
    let code = e.code().as_str();
    let mut v = structure_error(
        code,
        if e.code().human_required() {
            "A person acts on this in their own terminal (opv explains it there); secret values are entered only in 1Password."
        } else {
            "Fix the cause, then plan again."
        },
    );
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
    let Some(path) = config_store::walk_up(project, "secrets.toml") else {
        return structure_error(
            "config_not_found",
            "Declarations edit secrets.toml; a person creates it with opv init.",
        );
    };
    let r = ReadOnly {
        inner: ProcessRunner::new(Budget::starting_now(Duration::from_secs(20)), false),
        refused: AtomicBool::new(false),
    };
    match f(&r, &path) {
        _ if r.refused.load(Ordering::Relaxed) => inspection_error("human_approval_required"),
        Ok(changed) => json!({
            "ok": true,
            "changed": changed,
            "human_action": "Call opv_structure_plan to see what this needs in 1Password; a person approves it with opv approve.",
        }),
        Err(e) => structure_failure(&e),
    }
}

/// `opv access` as checked identifiers: what each CI or deploy identity needs, its state,
/// and the owner's `opv access … --create` command for each identity missing a grant.
fn access_projection(project: &std::path::Path, env: Option<&str>, target: Option<&str>) -> Value {
    if env.is_some_and(|e| !identifier(e)) || target.is_some_and(|t| !identifier(t)) {
        return inspection_error("invalid_environment");
    }
    if target.is_some() && env.is_none() {
        return structure_error(
            "environment_required",
            "Name the environment of the target.",
        );
    }
    crate::scrub::clear_mcp_registry();
    let _redaction_scope = RedactionScope;
    let r = ReadOnly {
        inner: ProcessRunner::new(Budget::starting_now(Duration::from_secs(60)), false),
        refused: AtomicBool::new(false),
    };
    let req = config_store::Request {
        start: project.into(),
        config: None,
        project: None,
        manifest_only: false,
        account: config_store::account_env(),
    };
    let fleet = match config_store::locate(&req, &r).and_then(|found| found.load(&r)) {
        Ok(fleet) => fleet,
        Err(e) => return inspection_error(e.code().as_str()),
    };
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    let result = crate::app::access::run(&fleet, env, target, None, &r, true, &mut *bytes);
    if r.refused.load(Ordering::Relaxed) {
        return inspection_error("human_approval_required");
    }
    let Ok(doc) = serde_json::from_slice::<Value>(&bytes) else {
        return structure_failure(
            &result
                .err()
                .unwrap_or_else(|| crate::error::Error::Config("no report".into())),
        );
    };
    access_answer(&doc)
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
        envs.push(json!({"environment": env_name, "identities": identities, "findings": findings}));
    }
    json!({
        "ok": true,
        "environments": envs,
        "changes_available": false,
        "human_action": "Creating an identity is the person's: they run its owner_command in their own terminal, with the GitHub repository and environment their CI job uses. The token goes to GitHub without being shown; never ask for it.",
    })
}

fn structure_plan(project: &std::path::Path) -> Value {
    crate::scrub::clear_mcp_registry();
    let _redaction_scope = RedactionScope;
    let r = ReadOnly {
        inner: ProcessRunner::new(Budget::starting_now(Duration::from_secs(60)), false),
        refused: AtomicBool::new(false),
    };
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
        return inspection_error("human_approval_required");
    }
    match planned {
        Ok(p) => plan_projection(&p),
        Err(e) => structure_failure(&e),
    }
}

fn structure_apply(project: &std::path::Path, plan_id: &str) -> Value {
    if !crate::app::structure::is_plan_id(plan_id) {
        return structure_error("invalid_plan_id", "Call opv_structure_plan for a plan_id.");
    }
    if let Some(var) = credential_in_environment(std::env::vars()) {
        return json!({
            "ok": false,
            "code": "credential_in_environment",
            "variable": var,
            "human_action": "Structural writes go through the 1Password app, which asks the person to authorize them. Start the opv MCP server without op session tokens, service-account or Connect credentials in its environment, or run opv bootstrap in your own terminal instead."
        });
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
        Err(e) => structure_failure(&e),
    }
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
    for field in ["environment", "product", "key"] {
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
    if doc.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return inspection_error("unsupported_receipt");
    }
    match operation {
        Operation::Ready => {
            let Some(findings) = doc.get("findings").and_then(Value::as_array) else {
                return inspection_error("invalid_receipt");
            };
            if findings.iter().any(|f| !f["blocking"].is_boolean()) {
                return inspection_error("invalid_receipt");
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
        Operation::Plan => {
            let Some(rows) = doc.get("rows").and_then(Value::as_array) else {
                return inspection_error("invalid_receipt");
            };
            let rows: Vec<_> = rows
                .iter()
                .filter_map(|row| {
                    let product = row["product"].as_str();
                    let key = row["key"].as_str()?;
                    if product.is_some_and(|p| !identifier(p)) || !identifier(key) {
                        return None;
                    }
                    let action = row["action"]
                        .as_str()
                        .filter(|s| {
                            [
                                "stage",
                                "hold",
                                "prune",
                                "skip",
                                "none",
                                "write",
                                "unchanged",
                            ]
                            .contains(s)
                        })
                        .unwrap_or("review");
                    Some(json!({"product": product, "key": key, "action": action}))
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
            json!({"ok": true, "rows": rows, "stage": names("stage"), "prune": names("prune"), "plan_id": plan_id, "changes_available": false, "human_action": "Review the plan with opv in your terminal. Explicitly approve changes before sync, deployment, rotation, or pruning."})
        }
        Operation::Configuration => unreachable!(),
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
            !project_receipt(&doc, Operation::Plan)
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
        assert!(!structure_failure(&e).to_string().contains("SECRET_MARKER"));
    }

    #[test]
    fn a_stale_structural_plan_returns_the_new_plan_id() {
        let e = crate::error::Error::Policy("stale".into())
            .with_code(crate::error::Code::StalePlan)
            .with_next("opv approve sp-0123456789abcdef");
        assert_eq!(structure_failure(&e)["plan_id"], "sp-0123456789abcdef");
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
            ]},
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
}
