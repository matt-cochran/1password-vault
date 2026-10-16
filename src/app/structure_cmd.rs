//! CLI parity with the MCP tools (j8): `opv env add`, `opv structure plan`,
//! `opv structure apply` and `opv config describe`.
//!
//! Each command does the same work as its MCP tool and prints the same document with
//! `--json`, built by the shared builders in [`crate::app::agent_view`]: a person can run
//! what an assistant ran over MCP, with no extra write and no value in sight.

use std::io::Write;
use std::path::Path;

use serde_json::{Value, json};

use crate::app::agent_view;
use crate::app::structure::{self, Scope};
use crate::cause::render::cmd_text;
use crate::cause::{Cause, Cmd, EnvName, GivenBy};
use crate::domain::{Fleet, Kind};
use crate::error::Error;
use crate::runner::CommandRunner;

/// A `Next:` line naming one opv command, built from its typed parts (design §10.1).
fn next(out: &mut dyn Write, command: &[&str], args: &[&str]) -> Result<(), Error> {
    let c = Cmd {
        command: command.iter().map(|w| w.to_string()).collect(),
        args: args.iter().map(|a| a.to_string()).collect(),
    };
    line(out, &format!("Next: {}", cmd_text(&c)))
}

fn write_json(out: &mut dyn Write, doc: &Value) -> Result<(), Error> {
    let mut text = doc.to_string();
    text.push('\n');
    out.write_all(text.as_bytes())
        .map_err(crate::app::write_err)
}

fn line(out: &mut dyn Write, text: &str) -> Result<(), Error> {
    writeln!(out, "{text}").map_err(crate::app::write_err)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// `opv env add <ENV>`: declare an environment in the project's `secrets.toml`, like the
/// MCP `opv_declare_environment` tool. A generated configuration is refused; nothing else
/// is written.
pub fn env_add(
    r: &dyn CommandRunner,
    start: &Path,
    environment: &str,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), Error> {
    // 05.37: the environment is known, so the step names it.
    let path = crate::config_store::walk_up(start, "secrets.toml").ok_or_else(|| -> Error {
        Cause::ConfigNotFound {
            searched_from: start.to_path_buf(),
            env: Some(EnvName::new(environment)),
        }
        .into()
    })?;
    let changed = crate::app::declare::environment(r, &path, environment)?;
    if json {
        return write_json(
            out,
            &json!({
                "ok": true,
                "changed": changed,
                "human_action": "Call `opv structure plan` to see what this needs in 1Password; a person approves it with `opv approve`.",
            }),
        );
    }
    if changed {
        line(
            out,
            &format!("declared environment {environment} in {}", path.display()),
        )?;
    } else {
        line(
            out,
            &format!("environment {environment} is already declared; nothing changed"),
        )?;
    }
    next(out, &["structure", "plan"], &[])
}

/// `opv structure plan`: resolve the project's [`Scope`], plan it, and print. Read-only.
pub fn plan(
    r: &dyn CommandRunner,
    start: &Path,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let scope = structure::scope(start, r)?;
    plan_scoped(r, &scope, json, out)
}

/// [`plan`] for an already-resolved scope: the plan identical to `opv_structure_plan`.
pub(crate) fn plan_scoped(
    r: &dyn CommandRunner,
    scope: &Scope,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let text = std::fs::read_to_string(&scope.path)
        .map_err(|e| crate::config_store::unreadable(&scope.path, &e, GivenBy::Discovered))?;
    let p = structure::plan(r, &text, &scope.project, &scope.account)?;
    if json {
        return write_json(out, &agent_view::plan_projection(&p));
    }
    let lines = structure::describe(&p);
    // 05.13: a complete structure has nothing to approve.
    if lines.is_empty() {
        line(out, "Nothing to create.")?;
        return next(out, &["ready"], &[]);
    }
    for l in &lines {
        line(out, l)?;
    }
    next(out, &["approve"], &[&p.plan_id])?;
    line(
        out,
        &format!(
            "(in your own terminal; then {})",
            cmd_text(&Cmd {
                command: vec!["structure".into(), "apply".into()],
                args: vec![p.plan_id.clone()],
            })
        ),
    )
}

/// `opv structure apply <PLAN_ID>`: apply exactly the plan a person approved with
/// `opv approve`, consuming the single-use approval like the MCP `opv_structure_apply`
/// tool.
pub fn apply(
    r: &dyn CommandRunner,
    start: &Path,
    plan_id: &str,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let scope = structure::scope(start, r)?;
    let project = scope.project.clone();
    let account = scope.account.clone();
    apply_authorized(
        r,
        &scope,
        plan_id,
        &mut |p| crate::approval::consume(&p.plan_id, &project, &account, now()),
        json,
        out,
    )
}

/// [`apply`] with an injected authorization check (the real one is
/// [`crate::approval::consume`]; tests use a temp-dir [`crate::approval::consume_in`]).
pub(crate) fn apply_authorized(
    r: &dyn CommandRunner,
    scope: &Scope,
    plan_id: &str,
    authorize: &mut dyn FnMut(&structure::Plan) -> Result<(), Error>,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let applied = structure::apply(
        r,
        &scope.path,
        &scope.project,
        &scope.account,
        plan_id,
        authorize,
    )?;
    if json {
        return write_json(out, &agent_view::applied_projection(&applied));
    }
    for c in &applied.created {
        let ids = match &c.item_id {
            Some(item) => format!("vault {}, item {}", c.vault_id, item),
            None => format!("vault {}", c.vault_id),
        };
        line(
            out,
            &format!("created {} {} in {} ({ids})", c.kind, c.name, c.environment),
        )?;
        if let Some(link) = &c.link {
            line(out, link)?;
        }
    }
    for f in &applied.fields_added {
        line(
            out,
            &format!(
                "added empty {} field {}/{} to the {} item in {}",
                f.kind, f.product, f.key, f.boundary, f.environment
            ),
        )?;
    }
    // 05.12: what the JSON form carries, the text form says too.
    if applied.config_written {
        line(
            out,
            &format!("recorded the new IDs in {}", scope.path.display()),
        )?;
    }
    if !applied.generator_ids.is_empty() {
        line(
            out,
            &format!(
                "{} is generated, so opv did not change it; record these IDs in its generator's input:",
                scope.path.display()
            ),
        )?;
        for id in &applied.generator_ids {
            line(out, &format!("  {id}"))?;
        }
    }
    for item in &applied.concurrent_edits {
        line(
            out,
            &format!(
                "another edit landed on the {item} item while fields were added: check its history in 1Password"
            ),
        )?;
    }
    next(out, &["ready"], &[])
}

/// `opv config describe`: the same metadata document as the MCP `opv_configuration` tool.
/// Text form is one line per environment, one per key and one per target.
pub fn config_describe(fleet: &Fleet, json: bool, out: &mut dyn Write) -> Result<(), Error> {
    if json {
        return write_json(out, &agent_view::configuration_projection(fleet));
    }
    for (name, e) in &fleet.environments {
        let note = if e.confirm_env {
            " (requires confirmation)"
        } else {
            ""
        };
        line(out, &format!("environment {name}{note}"))?;
    }
    for (product, p) in &fleet.products {
        for (key, spec) in &p.keys {
            let kind = match spec.kind {
                Kind::Secret => "secret",
                Kind::Config => "config",
            };
            line(out, &format!("key {product}/{key} {kind}"))?;
        }
    }
    for (env, e) in &fleet.environments {
        for (name, t) in &e.targets {
            line(
                out,
                &format!("target {env}/{name} {}", t.config.provider().section()),
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "structure_cmd_tests.rs"]
mod tests;
