//! Vendor adapters behind the `CommandRunner` seam (FR-12). Each wraps an official CLI.

pub mod fly;
pub mod onepassword;
/// Dev-time title lookup and value-free item read, for `opv init` only (FR-23).
pub(crate) mod onepassword_init;

use crate::domain::Target;
use crate::error::Error;
use crate::ports::{PinnedRuntime, PinnedStore, StagedRuntime, StagedStore, Store};
use crate::runner::CommandRunner;

/// A target's store and runtime adapters. The variant is the flow: staged (Fly) or
/// pinned (clouds).
pub enum Ports<'a> {
    Staged {
        store: Box<dyn StagedStore + 'a>,
        runtime: Box<dyn StagedRuntime + 'a>,
    },
    Pinned {
        store: Box<dyn PinnedStore + 'a>,
        runtime: Box<dyn PinnedRuntime + 'a>,
    },
}

impl<'a> Ports<'a> {
    /// The store as the operations every flow shares, for `status` and `plan`.
    pub fn store(&self) -> &dyn Store {
        match self {
            Ports::Staged { store, .. } => store.as_ref(),
            Ports::Pinned { store, .. } => store.as_ref(),
        }
    }
}

/// The store and runtime adapters for `target` (FR-28). The only place that maps a
/// configured target to its vendor adapter.
pub fn open<'a>(target: &'a Target, r: &'a dyn CommandRunner) -> Result<Ports<'a>, Error> {
    match target {
        Target::Fly(t) => Ok(Ports::Staged {
            store: Box::new(fly::Fly {
                runner: r,
                app: &t.app,
            }),
            runtime: Box::new(fly::Fly {
                runner: r,
                app: &t.app,
            }),
        }),
        // Placeholder until the Azure adapters land (FR-28).
        Target::Azure(_) => Err(Error::Config(
            "the Azure target is not supported yet".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::FlyTarget;
    use crate::runner::fake::FakeRunner;

    #[test]
    fn fly_target_opens_staged_ports() {
        let fly_target = Target::Fly(FlyTarget {
            app: "opv-test".into(),
            secret_name_template: "FLEET__{PRODUCT}__{KEY}".into(),
        });
        let r = FakeRunner::new([]);
        assert!(matches!(open(&fly_target, &r), Ok(Ports::Staged { .. })));
    }
}
