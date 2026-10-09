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
//!
//! Read commands (`status`, `plan`) run step 3 too, as [`read`], before the target's first
//! read: the same diagnosis, but they never wait on the target. An update in progress is
//! one note line on stderr and they go on with the state as it is.

use std::io::Write;

use super::write_err;
use crate::error::Error;
use crate::provider::{PreflightMode, TargetConfig};
use crate::runner::CommandRunner;

/// Step 3 for a mutating command: the target's own state, waiting for an update in
/// progress. A failed check refuses the run; every other check returned prints one line in
/// `doctor`'s format (`warn  fly app <app>: ...`); the result is the line to print instead
/// of a deploy when the runtime has nothing to restart. With `notes`, the lines go to
/// stderr instead (`sync --json` keeps stdout one document).
pub(crate) fn run(
    t: &dyn TargetConfig,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
    notes: bool,
) -> Result<Option<String>, Error> {
    let pre = t.preflight(r, PreflightMode::Mutate)?;
    for c in pre.checks {
        let line = c.outcome?.line(&c.name);
        if notes {
            r.note(&line);
        } else {
            writeln!(out, "{line}").map_err(write_err)?;
        }
    }
    Ok(pre.skip_deploy)
}

/// Step 3 for a read command: never waits; each warning is one note on stderr, so
/// `--json` output stays a single document.
pub(crate) fn read(t: &dyn TargetConfig, r: &dyn CommandRunner) -> Result<(), Error> {
    for c in t.preflight(r, PreflightMode::Read)?.checks {
        r.note(&c.outcome?.line(&c.name));
    }
    Ok(())
}
