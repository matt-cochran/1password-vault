//! `opv target op <env> --target <name> <operation>` (#234,
//! `docs/design/provider-operations.md`): a fixed operation on a target whose provider offers them, run under that
//! target's own deploy credentials, never printing a value.
//!
//! The operations are a closed table compiled into opv (§2): their programs, argv words and
//! slots are fixed, and a caller supplies only the environment, the target and validated
//! slot values. A request runs in three steps:
//!
//! 1. [`admit`] (P1–P6): pure checks of the configuration and the slots.
//! 2. [`preflight`] (P7–P10): credential-free local checks (the program, the in-memory
//!    folder, the docker daemon and image).
//! 3. [`execute`] (§5): the one read of the deploy credentials item, then the calls.
//!
//! Every refusal before [`execute`] is made with no `op` call. `opv target op` runs the
//! three steps; `registry-push` still refuses in [`execute`] with
//! [`OperationRefusal::NotYetAvailable`] until its lane (L3b, §11) lands.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

use crate::adapters::probe::{probe_failure, spawn_tool};
use crate::cause::{
    Cause, EnvName, Guard, NameKind, OperationRefusal, RamDir, RamPurpose, TargetName, UsageProblem,
};
use crate::domain::{Fleet, ItemRef, Target};
use crate::error::Error;
use crate::host::{DOCKER, Host, Platform, Tool};
use crate::provider::{ListedMachine, OperationBinding};
use crate::ramdir::{owned_dir, ram_backed};
use crate::runner::{Call, CommandRunner, Outcome, Output, isolated_env};

/// An operation of the table (§2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// Read: list the app's Machines.
    Machines,
    /// Write: move one Machine of the app to another image.
    MachineUpdate,
    /// Write: push a local image to the app's repository in the target's registry.
    RegistryPush,
}

impl Operation {
    /// Its name on the command line and in messages.
    pub fn name(self) -> &'static str {
        match self {
            Operation::Machines => "machines",
            Operation::MachineUpdate => "machine-update",
            Operation::RegistryPush => "registry-push",
        }
    }

    /// Whether the operation changes the target (P5: only these need the confirmation).
    fn is_write(self) -> bool {
        matches!(self, Operation::MachineUpdate | Operation::RegistryPush)
    }

    /// The program the operation runs (P7): the target's own CLI, or docker for a push.
    fn program(self, target_tool: &'static Tool) -> &'static Tool {
        match self {
            Operation::Machines | Operation::MachineUpdate => target_tool,
            Operation::RegistryPush => &DOCKER,
        }
    }
}

/// What the caller asked for: names and unvalidated slot values only (§3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub env: String,
    pub target: String,
    pub op: Operation,
    /// `--image`: `<registry>/<app>:<tag>` or `…@sha256:<64 hex>`.
    pub image: Option<String>,
    /// `--machine`: a Machine id of the app.
    pub machine: Option<String>,
    /// `--confirm`: the environment's name, for a write where it sets `confirm_env`.
    pub confirm: Option<String>,
}

/// A request that passed admission, bound to one target's configuration (§3.3, §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admitted {
    pub env: String,
    pub target: String,
    /// The target's bound app ([`OperationBinding::app`]), never a caller input.
    pub app: String,
    /// The registry host the app's images live under.
    pub registry: &'static str,
    /// The target's CLI, which runs the operations other than a push.
    pub tool: &'static Tool,
    /// The target's `deploy_credentials` item.
    pub credentials: ItemRef,
    pub op: Operation,
    /// The validated `--image`, in the app's repository.
    pub image: Option<String>,
    /// The validated `--machine`.
    pub machine: Option<String>,
    /// The local daemon's `unix://` endpoint, resolved by [`preflight`] for a registry push.
    pub docker_endpoint: Option<String>,
}

/// What an operation did, value-free: the lines opv prints and appends to the job summary
/// (§3.1). Names, ids, image references and digests only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub op: Operation,
    pub env: String,
    pub target: String,
    pub lines: Vec<String>,
    /// `machines`: the app's machines, projected (O5).
    pub machines: Vec<ListedMachine>,
    /// `machine-update`: the machine moved, and the image it now runs.
    pub updated: Option<(String, String)>,
}

impl Report {
    /// The `--json` document: the same fields as the lines (§5.4).
    pub fn json(&self) -> serde_json::Value {
        let mut doc = serde_json::json!({
            "environment": self.env,
            "target": self.target,
            "operation": self.op.name(),
        });
        match self.op {
            Operation::Machines => doc["machines"] = serde_json::json!(self.machines),
            _ => {
                if let Some((machine, image)) = &self.updated {
                    doc["machine"] = serde_json::json!(machine);
                    doc["image"] = serde_json::json!(image);
                }
            }
        }
        doc
    }
}

/// P1–P6: the environment, the target, its provider and deploy credentials, the confirmation
/// and the slots. Pure: no call of any program.
pub fn admit(fleet: &Fleet, req: &Request, _host: &Host) -> Result<Admitted, Error> {
    // P1–P3: the environment, its target, and the binding the target's provider gives.
    let (target, binding) = bound(fleet, &req.env, &req.target, req.op)?;
    // P4: the target records the deploy credentials the operation runs under.
    let credentials = target.deploy_credentials.clone().ok_or_else(|| {
        refused(
            &req.env,
            &req.target,
            req.op,
            OperationRefusal::NoDeployCredentials,
        )
    })?;
    // P5: a write on an environment with `confirm_env` needs `--confirm <env>`.
    if req.op.is_write() {
        super::run::require_confirmation(fleet, &req.env, req.confirm.as_deref(), "")?;
    }
    // P6: each given slot matches its validator; the image is in the target's repository.
    let (image, machine) = match req.op {
        Operation::Machines => (None, None),
        Operation::MachineUpdate => (
            Some(checked_image(
                &req.env,
                &req.target,
                req.op,
                &binding.app,
                binding.registry,
                req.image.as_deref(),
            )?),
            Some(checked_machine(req.machine.as_deref())?),
        ),
        Operation::RegistryPush => (
            Some(checked_image(
                &req.env,
                &req.target,
                req.op,
                &binding.app,
                binding.registry,
                req.image.as_deref(),
            )?),
            None,
        ),
    };
    Ok(Admitted {
        env: req.env.clone(),
        target: req.target.clone(),
        app: binding.app.clone(),
        registry: binding.registry,
        tool: binding.tool,
        credentials,
        op: req.op,
        image,
        machine,
        docker_endpoint: None,
    })
}

/// P7–P10: credential-free local checks; a registry push records its docker endpoint.
pub fn preflight(a: &mut Admitted, r: &dyn CommandRunner) -> Result<(), Error> {
    // Isolated like the operation itself: even a credential-free probe of the target's CLI
    // or docker never sees opv's whole environment (§5.5).
    crate::runner::isolated_env(|| {
        preflight_in(
            Host::detect().platform,
            std::env::var_os("XDG_RUNTIME_DIR"),
            &ram_backed,
            a,
            r,
        )
    })
}

/// [`preflight`] with the platform, the runtime directory and RAM test given (tests).
fn preflight_in(
    platform: Platform,
    runtime: Option<OsString>,
    is_ram: &dyn Fn(&Path) -> io::Result<bool>,
    a: &mut Admitted,
    r: &dyn CommandRunner,
) -> Result<(), Error> {
    // P7: the operation's program is on PATH.
    let tool = a.op.program(a.tool);
    spawn_tool(r, *tool, &|| Host::detect(), tool.version_args)?;
    if a.op != Operation::RegistryPush {
        return Ok(());
    }
    // P8: a user-owned, RAM-backed runtime directory for docker's private config.
    registry_ram_in(platform, runtime, is_ram)?;
    // P9: the local docker daemon (or none), never a remote one.
    let endpoint = docker_endpoint(a, r)?;
    // P10: the image is in that daemon, under the name the push would read.
    let image = a.image.as_deref().ok_or_else(|| {
        usage(UsageProblem::ValueFormat {
            flag: "--image".to_string(),
            format: image_format(a.op),
        })
    })?;
    docker_image_local(a, r, &endpoint, image)?;
    a.docker_endpoint = Some(endpoint);
    Ok(())
}

/// §5: read the deploy credentials item once, then make the operation's calls. The whole
/// run, sign-in included, is under [`isolated_env`]: no child but `op` sees more than opv's
/// basics and its own variables (§5.5).
pub fn execute(fleet: &Fleet, a: &Admitted, r: &dyn CommandRunner) -> Result<Report, Error> {
    if a.op == Operation::RegistryPush {
        return Err(not_yet_available(&a.env, &a.target, a.op));
    }
    let calls = bound(fleet, &a.env, &a.target, a.op)?.1.calls;
    let report = isolated_env(|| -> Result<Report, Error> {
        let signed = super::signin::open_for_operation(fleet, &a.env, &a.target, a.op.name(), r)?;
        let mut report = Report {
            op: a.op,
            env: a.env.clone(),
            target: a.target.clone(),
            lines: Vec::new(),
            machines: Vec::new(),
            updated: None,
        };
        if a.op == Operation::Machines {
            report.machines = calls.machines(&signed, &a.app)?;
            report.lines = machine_lines(&a.app, &report.machines);
            return Ok(report);
        }
        // Admission validated both slots (P6); an `Admitted` built without them is refused.
        let machine = checked_machine(a.machine.as_deref())?;
        let image = a.image.clone().ok_or_else(|| {
            usage(UsageProblem::ValueFormat {
                flag: "--image".to_string(),
                format: image_format(a.op),
            })
        })?;
        calls.machine_update(&signed, &a.env, &a.target, &a.app, &machine, &image)?;
        report.lines = vec![format!("updated machine {machine} to {image}")];
        report.updated = Some((machine, image));
        Ok(report)
    })?;
    r.step_summary(&format!(
        "opv target op {} --target {} {}: {}\n",
        a.env,
        a.target,
        a.op.name(),
        match &report.updated {
            Some((m, i)) => format!("updated machine {m} to {i}"),
            None => format!("{} machine(s)", report.machines.len()),
        }
    ));
    Ok(report)
}

/// One line per machine: id, name, state, region and image, nothing else (O5).
fn machine_lines(app: &str, machines: &[ListedMachine]) -> Vec<String> {
    if machines.is_empty() {
        return vec![format!("no machines in app {app}")];
    }
    machines
        .iter()
        .map(|m| {
            format!(
                "{}  {}  {}  {}  {}",
                m.id, m.name, m.state, m.region, m.image
            )
        })
        .collect()
}

/// P1–P3: the environment exists (its Next is the command as typed), the target is one of
/// its targets, and the target's provider offers the operations
/// ([`TargetConfig::operations`](crate::provider::TargetConfig::operations)).
fn bound<'f>(
    fleet: &'f Fleet,
    env: &str,
    target: &str,
    op: Operation,
) -> Result<(&'f Target, OperationBinding), Error> {
    let e = super::environment(fleet, env)?;
    let t = e.targets.get(target).ok_or_else(|| {
        super::not_declared(
            NameKind::Target,
            target,
            e.targets.keys().map(String::as_str),
        )
    })?;
    let binding = t.config.operations().ok_or_else(|| {
        refused(
            env,
            target,
            op,
            OperationRefusal::WrongProvider {
                provider: t.config.provider().section().to_string(),
            },
        )
    })?;
    Ok((t, binding))
}

fn not_yet_available(env: &str, target: &str, op: Operation) -> Error {
    refused(env, target, op, OperationRefusal::NotYetAvailable)
}

/// A refusal of the operation, with the environment, target and operation named.
fn refused(env: &str, target: &str, op: Operation, reason: OperationRefusal) -> Error {
    Cause::Guard {
        guard: Guard::OperationRefused {
            env: EnvName::new(env),
            target: TargetName::new(target),
            operation: op.name(),
            reason,
        },
    }
    .into()
}

fn usage(problem: UsageProblem) -> Error {
    Cause::Usage { problem }.into()
}

/// The `--image` slot (P6): exactly `<registry>/<app>` plus a tag (both operations) or
/// a `sha256:` digest (machine-update only). A well-formed image outside the app is
/// `ImageOutsideApp`; a malformed slot is `Usage`.
fn checked_image(
    env: &str,
    target: &str,
    op: Operation,
    app: &str,
    registry: &str,
    given: Option<&str>,
) -> Result<String, Error> {
    let format = image_format(op);
    let Some(image) = given else {
        return Err(usage(UsageProblem::ValueFormat {
            flag: "--image".to_string(),
            format,
        }));
    };
    let outside = || {
        refused(
            env,
            target,
            op,
            OperationRefusal::ImageOutsideApp {
                app: app.to_string(),
            },
        )
    };
    // A registry push names the repository in Docker's own grammar, stricter than
    // `is_id`; a bound app that fails it can hold no image of this operation.
    if op == Operation::RegistryPush && !docker_repository(app) {
        return Err(outside());
    }
    let Some(rest) = image
        .strip_prefix(registry)
        .and_then(|r| r.strip_prefix('/'))
    else {
        return Err(outside());
    };
    let Some(suffix) = rest.strip_prefix(app) else {
        return Err(outside());
    };
    if suffix.is_empty() {
        return Err(usage(UsageProblem::ValueFormat {
            flag: "--image".to_string(),
            format,
        }));
    }
    let malformed = || {
        usage(UsageProblem::ValueFormat {
            flag: "--image".to_string(),
            format,
        })
    };
    if let Some(tag) = suffix.strip_prefix(':') {
        if valid_tag(tag) {
            Ok(image.to_string())
        } else {
            Err(malformed())
        }
    } else if let Some(digest) = suffix.strip_prefix('@') {
        if op == Operation::RegistryPush {
            // A push reads a local image by tag; a digest is not a push source.
            return Err(malformed());
        }
        if valid_digest(digest) {
            Ok(image.to_string())
        } else {
            Err(malformed())
        }
    } else {
        Err(outside())
    }
}

fn image_format(op: Operation) -> &'static str {
    match op {
        Operation::RegistryPush => "<the target's registry>/<app>:<tag>",
        _ => {
            "<the target's registry>/<app>:<tag> or \
             <the target's registry>/<app>@sha256:<64 lowercase hex>"
        }
    }
}

/// The `--machine` slot (P6): 14 lowercase hex characters (the assumed Machine id).
fn checked_machine(given: Option<&str>) -> Result<String, Error> {
    let bad = || {
        usage(UsageProblem::ValueFormat {
            flag: "--machine".to_string(),
            format: "a 14-character Machine id (lowercase hex)",
        })
    };
    match given {
        Some(id) if valid_machine(id) => Ok(id.to_string()),
        _ => Err(bad()),
    }
}

fn valid_tag(tag: &str) -> bool {
    let mut bytes = tag.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !(first.is_ascii_alphanumeric() || first == b'_') {
        return false;
    }
    tag.len() <= 128 && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

fn valid_digest(digest: &str) -> bool {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(lower_hex)
}

fn valid_machine(id: &str) -> bool {
    id.len() == 14 && id.bytes().all(lower_hex)
}

fn lower_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

/// Docker's repository path component: `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*`.
fn docker_repository(app: &str) -> bool {
    let b = app.as_bytes();
    let mut i = 0;
    while i < b.len() && lower_alnum(b[i]) {
        i += 1;
    }
    if i == 0 {
        return false;
    }
    while i < b.len() {
        match b[i] {
            b'-' => {
                while i < b.len() && b[i] == b'-' {
                    i += 1;
                }
            }
            b'_' => {
                if b.get(i + 1) == Some(&b'_') {
                    i += 2;
                } else {
                    i += 1;
                }
            }
            b'.' => i += 1,
            _ => return false,
        }
        let start = i;
        while i < b.len() && lower_alnum(b[i]) {
            i += 1;
        }
        if i == start {
            return false;
        }
    }
    true
}

fn lower_alnum(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit()
}

/// The P8 check with the platform, the runtime directory and RAM test given (tests).
fn registry_ram_in(
    platform: Platform,
    runtime: Option<OsString>,
    is_ram: &dyn Fn(&Path) -> io::Result<bool>,
) -> Result<(), Error> {
    if platform == Platform::MacOs {
        return Err(ram_unavailable(RamDir::NoneOnPlatform { os: "macOS" }));
    }
    if platform == Platform::Windows {
        return Err(ram_unavailable(RamDir::NoneOnPlatform { os: "Windows" }));
    }
    let runtime = runtime
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| ram_unavailable(RamDir::Unset))?;
    if !runtime.is_absolute() {
        return Err(ram_unavailable(RamDir::NotAbsolute));
    }
    if !owned_dir(&runtime) {
        return Err(ram_unavailable(RamDir::NotOwned));
    }
    if !is_ram(&runtime).unwrap_or(false) {
        return Err(ram_unavailable(RamDir::NotTmpfs));
    }
    Ok(())
}

fn ram_unavailable(why: RamDir) -> Error {
    Cause::RamDirUnavailable {
        remote: None,
        why,
        purpose: RamPurpose::RegistryPush,
        env: None,
        product: None,
    }
    .into()
}

/// P9: the local docker endpoint, from `docker context inspect`. `DOCKER_CONTEXT` choosing
/// another context is refused before any call.
fn docker_endpoint(a: &Admitted, r: &dyn CommandRunner) -> Result<String, Error> {
    docker_endpoint_in(std::env::var_os("DOCKER_CONTEXT"), a, r)
}

/// The P9 check with `DOCKER_CONTEXT` given (tests): a set, non-empty value names a daemon
/// other than the local one, whatever endpoint that context resolves to.
fn docker_endpoint_in(
    context: Option<OsString>,
    a: &Admitted,
    r: &dyn CommandRunner,
) -> Result<String, Error> {
    if context.is_some_and(|v| !v.is_empty()) {
        return Err(refused(
            &a.env,
            &a.target,
            a.op,
            OperationRefusal::RemoteDockerDaemon,
        ));
    }
    let args = [
        "context",
        "inspect",
        "--format",
        "{{.Endpoints.docker.Host}}",
    ];
    let out = docker_read(
        r,
        &Call::new(DOCKER.program, &args),
        "docker context inspect",
    )?;
    let endpoint = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !endpoint.starts_with("unix://") {
        return Err(refused(
            &a.env,
            &a.target,
            a.op,
            OperationRefusal::RemoteDockerDaemon,
        ));
    }
    Ok(endpoint)
}

/// P10: the image is in the local daemon (the endpoint P9 resolved), under its own name.
fn docker_image_local(
    a: &Admitted,
    r: &dyn CommandRunner,
    endpoint: &str,
    image: &str,
) -> Result<(), Error> {
    let args = ["image", "inspect", "--format", "{{.Id}}", image];
    let call = Call {
        env: &[("DOCKER_HOST", endpoint)],
        ..Call::new(DOCKER.program, &args)
    };
    match r.read(&call, &[1]) {
        Ok(Outcome::Done(_)) => Ok(()),
        Ok(Outcome::Refused(_)) => Err(refused(
            &a.env,
            &a.target,
            a.op,
            OperationRefusal::ImageNotLocal {
                image: image.to_string(),
            },
        )),
        Ok(Outcome::Unknown { .. }) => Err(DOCKER.unanswered(r, "docker image inspect")),
        Err(e) => Err(probe_failure(&DOCKER, &e, &|| Host::detect())),
    }
}

fn docker_read(r: &dyn CommandRunner, call: &Call, step: &str) -> Result<Output, Error> {
    match r.read(call, &[1]) {
        Ok(Outcome::Done(o)) => Ok(o),
        Ok(Outcome::Refused(_) | Outcome::Unknown { .. }) => Err(DOCKER.unanswered(r, step)),
        Err(e) => Err(probe_failure(&DOCKER, &e, &|| Host::detect())),
    }
}

#[cfg(test)]
#[path = "provider_op_tests.rs"]
mod tests;
