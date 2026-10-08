//! Vendor adapters behind the `CommandRunner` seam (FR-12). Each wraps an official CLI.

pub mod fly;
pub mod onepassword;
/// Dev-time title lookup and value-free item read, for `opv init` only (FR-23).
pub(crate) mod onepassword_init;

use crate::domain::Target;
use crate::error::Error;
use crate::ports::{Runtime, SecretStore};
use crate::runner::CommandRunner;

/// A target's store and runtime adapters.
pub type Adapters<'a> = (Box<dyn SecretStore + 'a>, Box<dyn Runtime + 'a>);

/// The store and runtime adapters for `target` (FR-28). The only place that maps a
/// configured target to its vendor adapter.
pub fn open<'a>(target: &'a Target, r: &'a dyn CommandRunner) -> Result<Adapters<'a>, Error> {
    match target {
        Target::Fly(t) => Ok((
            Box::new(fly::Fly {
                runner: r,
                app: &t.app,
            }),
            Box::new(fly::Fly {
                runner: r,
                app: &t.app,
            }),
        )),
        // Placeholder until the Azure adapters land (FR-28).
        Target::Azure(_) => Err(Error::Config(
            "the Azure target is not supported yet".into(),
        )),
    }
}
