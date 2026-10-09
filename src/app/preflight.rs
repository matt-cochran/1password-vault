//! Preflight before the first write (NR-23).
//!
//! A mutating command (`sync`) proves, read-only and in this order, everything its writes
//! depend on before it makes the first one; any failure stops the run with nothing
//! written:
//!
//! 1. **CLIs, 1Password sign-in and item reachability** (NR-10, NR-26, NR-27): the item
//!    read by IDs (FR-13). `op` missing is `Dependency` with the install command; not
//!    signed in is `Auth`; an unavailable item is diagnosed by IDs (vault access versus a
//!    moved, archived or deleted item, `op vault get <vault_id>`).
//! 2. **Provider CLI, sign-in and reachability**: the target's first list (the provider
//!    CLI missing is `Dependency`, signed out is `Auth`, an unknown app is `Target`).
//! 3. **Target state** ([`run`], `TargetConfig::preflight`, NR-24): e.g. a suspended Fly
//!    app or a deploy already running refuses; stopped machines are a warning line.
//!
//! Steps 1 and 2 are the reads the plan needs anyway, so preflight adds no second item
//! read and no extra sign-in probe. Only the CLIs the environment uses are ever called
//! (NR-27). A read still unanswered after its retries is an outage (NR-28): exit 9 naming
//! the provider, the step and its status page; nothing was changed.

use std::io::Write;

use super::write_err;
use crate::error::Error;
use crate::provider::TargetConfig;
use crate::runner::CommandRunner;

/// Step 3: the target's own state checks. A failed check refuses the run; every other
/// check returned prints one line in `doctor`'s format (`warn  fly app <app>: ...`); the result is the line to print instead of a deploy when the
/// runtime has nothing to restart.
pub(crate) fn run(
    t: &dyn TargetConfig,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<Option<String>, Error> {
    let pre = t.preflight(r)?;
    for c in pre.checks {
        let line = c.outcome?.line(&c.name);
        writeln!(out, "{line}").map_err(write_err)?;
    }
    Ok(pre.skip_deploy)
}
