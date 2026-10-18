//! `opv_import_local <env> --from <file>` (design row `import-local`): an assistant's
//! import into the person's own local environment. It refuses, before reading anything, an
//! environment whose tier is not `local` ([`Cause::ImportTierRefused`]); otherwise it is
//! `opv import` with no `--replace` and no `--rotate` (a write-only import: missing values
//! only, never an overwrite), and every written item is tagged `assistant_imported` on the
//! same verified `op item edit` — a value-free mark the health check and the `ready --gate`
//! gate use to treat the values as not the person's own.

use std::io::Write;
use std::path::Path;

use super::import::{self, Opts, Source};
use crate::cause::{Cause, EnvName};
use crate::domain::{Fleet, Tier};
use crate::error::Error;
use crate::runner::CommandRunner;

/// The 1Password item tag every [`import_local`] write carries (design row `import-local`).
pub const ASSISTANT_IMPORTED: &str = "assistant_imported";

/// Import `file`'s values into `env`'s boundary items, for an assistant. Only a `local`
/// environment may take it; any other tier is refused at once, before the file is read.
/// The import is write-only: it fills missing keys and never replaces a set value.
pub fn import_local(
    fleet: &Fleet,
    env: &str,
    file: &Path,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    import_local_as(fleet, env, file, false, r, out)
}

/// [`import_local`] reporting as the `opv import --json` document: per key `imported` or
/// skipped, never a value. The MCP tool `opv_import_local` answers with it.
pub fn import_local_json(
    fleet: &Fleet,
    env: &str,
    file: &Path,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    import_local_as(fleet, env, file, true, r, out)
}

/// [`import_local`], its report as text or as the `--json` document (`json`).
fn import_local_as(
    fleet: &Fleet,
    env: &str,
    file: &Path,
    json: bool,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let tier = fleet.environment(env)?.tier;
    if tier != Tier::Local {
        return Err(Cause::ImportTierRefused {
            env: EnvName::new(env),
            tier: tier_name(tier),
        }
        .into());
    }
    let opts = Opts {
        source: Source::Dotenv(file.to_path_buf()),
        replace: Vec::new(),
        rotate: Vec::new(),
        skip: Vec::new(),
        dry_run: false,
        json,
    };
    import::run_tagged(fleet, env, &opts, Some(ASSISTANT_IMPORTED), r, out)
}

/// The tier's name for [`Cause::ImportTierRefused`] (never a value).
fn tier_name(tier: Tier) -> &'static str {
    match tier {
        Tier::Local => "local",
        Tier::Shared => "shared",
        Tier::Production => "production",
    }
}

#[cfg(test)]
#[path = "import_local_tests.rs"]
mod tests;
