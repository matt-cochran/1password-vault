//! Read-only MCP tools. No value-bearing operation or mutation is exposed.
use crate::{
    config_store,
    domain::Kind,
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

impl Server {
    pub fn new(project: PathBuf) -> Self {
        Self {
            project,
            gate: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    async fn inspect(&self, operation: Operation, env: Option<String>) -> String {
        let guard = self.gate.clone().lock_owned().await;
        let project = self.project.clone();
        tokio::task::spawn_blocking(move || {
            // Keep serialization until the blocking work ends, even if the client
            // cancels its request and drops the awaiting future.
            let _guard = guard;
            inspect(&project, operation, env.as_deref())
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
        description = "Read readiness metadata for one environment. Never returns values. Humans handle authentication and secret entry. No changes are authorized.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn ready(&self, Parameters(args): Parameters<Environment>) -> String {
        self.inspect(Operation::Ready, Some(args.environment)).await
    }

    #[tool(
        name = "opv_configuration",
        description = "Inspect declared environment and key metadata only. No values, rules, vault identifiers, or configuration export. Changes require human approval outside MCP.",
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

fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-/".contains(&b))
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
        let environments: Vec<_> = fleet
            .environments
            .iter()
            .filter(|(n, _)| identifier(n))
            .map(|(name, e)| json!({"name": name, "requires_confirmation": e.confirm_env}))
            .collect();
        let keys: Vec<_> = fleet.products.iter().filter(|(n, _)| identifier(n)).flat_map(|(product, p)| p.keys.iter().filter(|(n, _)| identifier(n)).map(move |(key, spec)| json!({"product": product, "key": key, "kind": match spec.kind { Kind::Secret => "secret", Kind::Config => "config" }}))).collect();
        return json!({"ok": true, "environments": environments, "keys": keys, "changes_available": false});
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
            json!({"ok": true, "blocking_findings": findings.iter().filter(|f| f["blocking"] == true).count(), "other_findings": findings.iter().filter(|f| f["blocking"] == false).count(), "human_action": "Use opv ready in your terminal for details; humans authenticate and enter values in 1Password.", "snapshot_only": true})
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
    #[test]
    fn successful_receipt_can_still_have_blocking_findings() {
        let doc = json!({"schema_version": 1, "findings": [{"blocking": true}]});
        assert_eq!(
            project_receipt(&doc, Operation::Ready)["blocking_findings"],
            1
        );
    }
}
