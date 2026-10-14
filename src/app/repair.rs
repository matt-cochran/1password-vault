//! `opv tidy <env> [--json]` (#113): the explicit layout repair. It runs the same guarded
//! tidy a signed-in person's read runs (FR-43, [`super::tidy`]): one whole-item
//! `op item edit`, verified, nothing deleted, displaced fields kept in `opv · kept`. Unlike
//! that implicit tidy it refuses outright unless a person signed in with their own session
//! runs it, so its `writes_1password` effect is the whole story. `opv doctor` never writes
//! and names this command when the layout needs it. Names and actions only, never a value.

use std::io::Write;

use super::write_err;
use crate::domain::Fleet;
use crate::error::Error;
use crate::runner::CommandRunner;

/// Run `opv tidy <env>`.
pub fn run(
    fleet: &Fleet,
    env_name: &str,
    r: &dyn CommandRunner,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), Error> {
    fleet.environment(env_name)?;
    super::tidy::require_person(r, &format!("opv tidy {env_name}"))?;
    let read = super::tidy::read(fleet, env_name, r)?;
    if let Some(code) = read.tidy_error {
        return Err(Error::Unknown(
            format!(
                "could not tidy 1Password ({env_name}); the item was read as it is and left \
                 as opv found it or as one verified edit left it"
            )
            .into(),
        )
        .with_code(code)
        .with_next(format!("opv doctor --env {env_name}")));
    }
    if json {
        let doc = serde_json::json!({
            "schema_version": crate::json::SCHEMA_VERSION,
            "environment": env_name,
            "tidied": !read.changes.is_empty(),
            "tidy": super::json_tidy(&read.changes),
            "needing_values": read.needing_values,
        });
        return writeln!(out, "{doc}").map_err(write_err);
    }
    if read.changes.is_empty() {
        return writeln!(
            out,
            "1Password ({env_name}) already follows opv's layout; nothing written"
        )
        .map_err(write_err);
    }
    // `tidy::read` already named every change in its one `tidied 1Password (<env>): …` line
    // on stderr.
    writeln!(
        out,
        "1Password ({env_name}) now follows opv's layout ({})",
        super::plural(read.changes.len(), "change", "changes")
    )
    .map_err(write_err)
}
