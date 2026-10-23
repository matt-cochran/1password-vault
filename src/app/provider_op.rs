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
//! Every refusal before [`execute`] is made with no `op` call. This is the interface of
//! Step 0 (§11): each step refuses with [`OperationRefusal::NotYetAvailable`] until its lane
//! lands, and no command reaches it yet.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

use crate::adapters::probe::{probe_failure, spawn_tool};
use crate::cause::{
    Cause, EnvName, Guard, NameKind, OperationRefusal, RamDir, RamPurpose, TargetName, UsageProblem,
};
use crate::domain::{Fleet, ItemRef};
use crate::error::Error;
use crate::host::{DOCKER, Host, Platform, Tool};
use crate::provider::OperationBinding;
use crate::ramdir::{owned_dir, ram_backed};
use crate::runner::{Call, CommandRunner, Outcome, Output};

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
    fn program(self, binding: &OperationBinding) -> &'static Tool {
        match self {
            Operation::Machines | Operation::MachineUpdate => binding.tool,
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
}

/// P1–P6: the environment, the target, its provider and deploy credentials, the confirmation
/// and the slots. Pure: no call of any program.
pub fn admit(fleet: &Fleet, req: &Request, _host: &Host) -> Result<Admitted, Error> {
    // P1: the environment exists (its Next is the command as typed).
    let env = super::environment(fleet, &req.env)?;
    // P2: the target is one of that environment's targets.
    let target = env.targets.get(&req.target).ok_or_else(|| {
        super::not_declared(
            NameKind::Target,
            &req.target,
            env.targets.keys().map(String::as_str),
        )
    })?;
    // P3: the target's provider offers the operations ([`TargetConfig::operations`]).
    let Some(binding) = target.config.operations() else {
        return Err(refused(
            &req.env,
            &req.target,
            req.op,
            OperationRefusal::WrongProvider {
                provider: target.config.provider().section().to_string(),
            },
        ));
    };
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
    preflight_in(
        Host::detect().platform,
        std::env::var_os("XDG_RUNTIME_DIR"),
        &ram_backed,
        a,
        r,
    )
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
    let tool = a.op.program(&OperationBinding {
        app: a.app.clone(),
        tool: a.tool,
        registry: a.registry,
    });
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

/// §5: read the deploy credentials item once, then make the operation's calls.
pub fn execute(a: &Admitted, _r: &dyn CommandRunner) -> Result<Report, Error> {
    Err(not_yet_available(&a.env, &a.target, a.op))
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
