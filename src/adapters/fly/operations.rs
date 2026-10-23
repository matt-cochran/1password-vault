//! Fly Machines operations for `opv target op` (#234, `docs/design/provider-operations.md`
//! §2, §5.2): the fixed flyctl argv for `machines` and `machine-update`, the typed
//! projection of `flyctl machine list --json`, and O4's listing check.
//!
//! The operation table is compiled in (§2, O6): the programs, every argv word and every
//! slot are fixed. `<app>` is always the target's `fly.app`, never a caller input; the
//! caller's `--machine` and `--image` were validated by admission (P6) and appear only in
//! their own slots. No other flag is ever passed, so `machine-update` changes only the
//! image (O3).
//!
//! The listing is parsed into [`Machine`], which names `id`, `name`, `state`, `region` and
//! `config.image` only (O5). `config.env`, metadata, services and every other key are
//! skipped by serde, never held as a string and never printed (S11). A reply that does not
//! carry a projected field is [`Cause::UnexpectedOutput`], never a panic.
//!
//! # Calls (§5.2)
//!
//! Token handling stays with the caller: `provider_op::execute` reads the item once and runs
//! these functions under the deploy principal, so flyctl's own environment carries the
//! token (`FlyLogin::env("flyctl")`). `machines` is a read (`Effect::Read`);
//! `machine-update` first re-lists the app and refuses an id that is not in it (O4), then is
//! a [`Call::rollout`] write, never retried.

use serde::Deserialize;

use super::{Effect, read_json};
use crate::cause::{Cause, EnvName, Guard, OperationRefusal, TargetName};
use crate::error::Error;
use crate::runner::CommandRunner;

/// `machines` argv: `flyctl machine list --app <app> --json` (§2).
///
/// `app` is the target's `fly.app`, never a caller input.
pub fn machines_args(app: &str) -> [&str; 5] {
    ["machine", "list", "--app", app, "--json"]
}

/// `machine-update` argv:
/// `flyctl machine update <id> --app <app> --image <image> --yes` (§2).
///
/// Only the validated id and image are carried (P6, O3); no other flag is passed.
pub fn machine_update_args<'a>(app: &'a str, machine: &'a str, image: &'a str) -> [&'a str; 8] {
    [
        "machine", "update", machine, "--app", app, "--image", image, "--yes",
    ]
}

/// One Machine of `flyctl machine list --app <app> --json` (§2, O5): the projected fields
/// only. `config.env`, metadata, services and every other field are skipped by serde, so
/// no value in them is read into memory (S11).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Machine {
    /// The Machine id (`^[0-9a-f]{14}$`, P6).
    pub id: String,
    /// The Machine's name.
    pub name: String,
    /// flyctl's state word, e.g. `started`.
    pub state: String,
    /// The Machine's region, e.g. `iad`.
    pub region: String,
    /// The `config` object, projected to its `image` ([`Machine::image`]).
    #[serde(rename = "config")]
    config: MachineConfig,
}

/// The `config` object of a Machine, projected to `image` only (O5). Every other key,
/// including `env`, is skipped unread.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct MachineConfig {
    /// The image reference flyctl reports, `registry.fly.io/<app>:<tag>` or a digest.
    image: String,
}

impl Machine {
    /// The Machine's image reference, `config.image` (O5).
    pub fn image(&self) -> &str {
        &self.config.image
    }
}

/// The app's Machines: one `flyctl machine list --app <app> --json` read (§2, §5.2).
pub fn machines(r: &dyn CommandRunner, app: &str) -> Result<Vec<Machine>, Error> {
    read_json(r, "fly machine list", app, &machines_args(app))
}

/// O4: whether `machine` is one of the listed Machines.
pub fn listed(machines: &[Machine], machine: &str) -> bool {
    machines.iter().any(|m| m.id == machine)
}

/// Move one Machine of `app` to `image`: `flyctl machine list --app <app> --json`, refuse an
/// id that is not in it (O4, a definite refusal before any write), then the `--image`-only
/// `flyctl machine update` (§2, §5.2).
///
/// `env` and `target` name the refusal ([`OperationRefusal::MachineNotInApp`]); `app` is the
/// target's bound `fly.app`, never a caller input.
pub fn machine_update(
    r: &dyn CommandRunner,
    env: &str,
    target: &str,
    app: &str,
    machine: &str,
    image: &str,
) -> Result<(), Error> {
    if !listed(&machines(r, app)?, machine) {
        return Err(Cause::Guard {
            guard: Guard::OperationRefused {
                env: EnvName::new(env),
                target: TargetName::new(target),
                operation: "machine-update",
                reason: OperationRefusal::MachineNotInApp {
                    machine: machine.to_string(),
                },
            },
        }
        .into());
    }
    super::run(
        r,
        Effect::Write,
        "fly machine update",
        app,
        &machine_update_args(app, machine, image),
        None,
    )
    .map(|_| ())
}

#[cfg(test)]
#[path = "operations_tests.rs"]
mod tests;
