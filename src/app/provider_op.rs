//! `opv target op <env> --target <name> <operation>` (#234,
//! `docs/design/provider-operations.md`): a fixed operation on a Fly target, run under that
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

use crate::cause::{Cause, EnvName, Guard, OperationRefusal, TargetName};
use crate::domain::{Fleet, ItemRef};
use crate::error::Error;
use crate::host::Host;
use crate::runner::CommandRunner;

/// An operation of the table (§2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// Read: list the app's Machines.
    Machines,
    /// Write: move one Machine of the app to another image.
    MachineUpdate,
    /// Write: push a local image to the app's repository in Fly's registry.
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
}

/// What the caller asked for: names and unvalidated slot values only (§3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub env: String,
    pub target: String,
    pub op: Operation,
    /// `--image`: `registry.fly.io/<app>:<tag>` or `…@sha256:<64 hex>`.
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
    /// The target's `fly.app`, never a caller input.
    pub app: String,
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
pub fn admit(_fleet: &Fleet, req: &Request, _host: &Host) -> Result<Admitted, Error> {
    Err(not_yet_available(&req.env, &req.target, req.op))
}

/// P7–P10: credential-free local checks; a registry push records its docker endpoint.
pub fn preflight(a: &mut Admitted, _r: &dyn CommandRunner) -> Result<(), Error> {
    Err(not_yet_available(&a.env, &a.target, a.op))
}

/// §5: read the deploy credentials item once, then make the operation's calls.
pub fn execute(a: &Admitted, _r: &dyn CommandRunner) -> Result<Report, Error> {
    Err(not_yet_available(&a.env, &a.target, a.op))
}

fn not_yet_available(env: &str, target: &str, op: Operation) -> Error {
    Cause::Guard {
        guard: Guard::OperationRefused {
            env: EnvName::new(env),
            target: TargetName::new(target),
            operation: op.name(),
            reason: OperationRefusal::NotYetAvailable,
        },
    }
    .into()
}

#[cfg(test)]
#[path = "provider_op_tests.rs"]
mod tests;
