//! `opv access [<env>] [--json]` (#96, FR-52): who can read each environment's vault, for a
//! least-privilege CI reader. One read-only `op vault user list <vault>` per environment:
//! people and guests are counted, never named; service accounts are named with whether they
//! can only read. A deployed environment without a read-only service account gets the
//! owner's exact `op service-account create … :read_items` command, which opv prints and
//! never runs (1Password shows the new token once, to the owner).

use std::io::Write;

use super::write_err;
use crate::adapters::onepassword_init;
use crate::domain::access::{AccessFinding, EnvAccess, analyse, findings};
use crate::error::Error;
use crate::host::Host;
use crate::runner::CommandRunner;

/// Run `opv access`.
pub fn run(
    fleet: &crate::domain::Fleet,
    only: Option<&str>,
    r: &dyn CommandRunner,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), Error> {
    if let Some(e) = only {
        fleet.environment(e)?;
    }
    let mut ordered: Vec<(&String, &crate::domain::Environment)> = fleet
        .environments
        .iter()
        .filter(|(name, _)| only.is_none_or(|o| o == name.as_str()))
        .collect();
    ordered.sort_by_key(|(name, env)| (env.order.unwrap_or(i64::MAX), (*name).clone()));
    let mut envs = Vec::new();
    for (name, env) in ordered {
        let users = onepassword_init::vault_users(r, &env.vault_id, &Host::detect)?;
        envs.push(analyse(
            name,
            &env.vault_id,
            env.target().is_some(),
            users.as_ref(),
        ));
    }
    let project = super::personal::project_name(r, &std::env::current_dir().unwrap_or_default());
    let found = findings(&project, &envs);
    report(out, &envs, &found, json)
}

/// Print the access view: one line per environment, then the findings with their commands.
fn report(
    out: &mut dyn Write,
    envs: &[EnvAccess],
    found: &[AccessFinding],
    json: bool,
) -> Result<(), Error> {
    if json {
        let doc = serde_json::json!({
            "schema_version": crate::json::SCHEMA_VERSION,
            "environments": envs,
            "findings": found,
        });
        return writeln!(out, "{doc}").map_err(write_err);
    }
    for e in envs {
        let line = if !e.visible {
            format!(
                "{}: vault {}: not visible to you",
                e.environment, e.vault_id
            )
        } else {
            let readers: Vec<String> = e
                .service_accounts
                .iter()
                .map(|s| {
                    let how = if s.read_only {
                        "read-only"
                    } else {
                        "can write"
                    };
                    format!("{} ({how})", s.name)
                })
                .collect();
            let ci = if readers.is_empty() {
                "no service account".to_string()
            } else {
                readers.join(", ")
            };
            format!(
                "{}: vault {}: {} {}, {} {}; {ci}",
                e.environment,
                e.vault_id,
                e.people,
                if e.people == 1 { "person" } else { "people" },
                e.guests,
                if e.guests == 1 { "guest" } else { "guests" }
            )
        };
        writeln!(out, "{line}").map_err(write_err)?;
    }
    for f in found {
        writeln!(out, "  {}: {}", f.code, f.message).map_err(write_err)?;
        if let Some(n) = &f.next {
            writeln!(
                out,
                "    owner runs (the token is shown once, by 1Password): {n}"
            )
            .map_err(write_err)?;
        }
    }
    if found.iter().any(|f| f.next.is_some()) {
        writeln!(
            out,
            "Then store the token as the CI secret OP_SERVICE_ACCOUNT_TOKEN yourself; opv never \
             sees it."
        )
        .map_err(write_err)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "access_tests.rs"]
mod tests;
