//! Metadata-only delivery preview for `opv run --preview` and the MCP tool
//! `opv_delivery_preview` (#136, items 1 and 2). It reads identifiers only: no value, no
//! `op run`, no `op read`, no `op item get`. The one optional `op` call is the cheap
//! read-only session probe (`op whoami`, with `op account list` as its own fallback); a
//! prerequisite that cannot be determined is reported as `unknown`, never as missing.
//!
//! [`select`] is the single key selection `opv run` uses for both the `op run` reference
//! set and the local delivery step: process roles (#136) are applied where the keys are
//! chosen, so a key withheld by role is neither resolved by `op` nor written to a file nor
//! put in the child environment. A product whose keys declare roles and a run that gives no
//! `--role`, or names a role no key declares, is `"usage"` before any 1Password read.
//!
//! `build` is the one shared builder the CLI (`opv run --preview`) and the MCP tool call,
//! so the document is identical wherever it is asked for.

use std::io::{self, Write};

use serde_json::{Value, json};

use crate::adapters::onepassword::{self, Session};
use crate::cause::{Cause, Closest, NameKind};
use crate::domain::{Environment, Fleet, KeySpec, Product, rules};
use crate::error::Error;
use crate::host::Host;
use crate::runner::CommandRunner;

/// The version of the preview document's shape.
pub const SCHEMA_VERSION: u32 = 1;

/// The role names any key of `product` declares, sorted and deduplicated. Product-wide, so
/// a run that omits `--role` is refused even when only one key is role-scoped.
pub fn declared_roles(prod: &Product) -> Vec<&str> {
    let mut out: Vec<&str> = prod
        .keys
        .values()
        .filter_map(|s| s.roles.as_deref())
        .flatten()
        .map(String::as_str)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// What one `opv run` delivers for an environment: the keys the run passes to `op run`
/// (and the local delivery step), and the keys its rules would deliver but the role
/// withholds.
pub struct Selection<'a> {
    pub delivered: Vec<(&'a String, &'a KeySpec)>,
    pub withheld: Vec<&'a String>,
}

/// The keys of `prod` desired in `env_name` after rules and role filtering (#136). A key
/// without `roles` is delivered to every role, `--role` or not; a key with `roles` only
/// when `role` names one of them. Fail closed: no `--role` for a product with role-scoped
/// keys ([`Cause::ChoiceRequired`]), or a `--role` no key declares ([`Cause::NotDeclared`]),
/// is refused before any 1Password read. Their steps are built from the person's own
/// invocation, so a preview stays a preview and a remote run stays remote (07.11).
pub fn select<'a>(
    env_name: &str,
    env: &Environment,
    product: &str,
    prod: &'a Product,
    role: Option<&str>,
) -> Result<Selection<'a>, Error> {
    let declared = declared_roles(prod);
    match role {
        None if !declared.is_empty() => {
            return Err(Cause::ChoiceRequired {
                flag: "--role".into(),
                candidates: declared.iter().map(|r| r.to_string()).collect(),
            }
            .into());
        }
        Some(r) if !declared.contains(&r) => {
            return Err(Cause::NotDeclared {
                kind: NameKind::Role,
                given: r.to_string(),
                candidates: declared.iter().map(|r| r.to_string()).collect(),
                closest: Closest::unique(&super::suggest::close(r, declared.iter().copied())),
            }
            .into());
        }
        _ => {}
    }
    let mut delivered = Vec::new();
    let mut withheld = Vec::new();
    for (key, spec) in &prod.keys {
        if !rules::applies(spec, env_name, env, product) {
            continue;
        }
        match (spec.roles.as_deref(), role) {
            (None, _) => delivered.push((key, spec)),
            (Some(roles), Some(r)) if roles.iter().any(|x| x == r) => delivered.push((key, spec)),
            (Some(_), _) => withheld.push(key),
        }
    }
    Ok(Selection {
        delivered,
        withheld,
    })
}

/// The preview document for `opv run --preview --json` and `opv_delivery_preview`: one JSON
/// object, `schema_version` 1, built field by field from identifiers. No value is read and
/// no `op run`/`op read`/`op item get` is made; the only `op` call is the session probe.
pub fn build(
    fleet: &Fleet,
    env_name: &str,
    product: Option<&str>,
    role: Option<&str>,
    runner: &dyn CommandRunner,
) -> Result<Value, Error> {
    build_for(fleet, env_name, product, role, None, runner)
}

/// [`build`] for a transport (#139): `remote` names a reviewed remote profile, whose pinned
/// connection and command are added under `remote` (identifiers and the public host key's
/// type only), after the same checks `opv run --remote` makes before any read. `transport`
/// is `local` or `remote`; `remote_profiles` lists the product's profile names either way.
pub fn build_for(
    fleet: &Fleet,
    env_name: &str,
    product: Option<&str>,
    role: Option<&str>,
    remote: Option<&str>,
    runner: &dyn CommandRunner,
) -> Result<Value, Error> {
    let product_name = match product {
        Some(p) => p.to_string(),
        None => super::pick_product(fleet, env_name, None)?,
    };
    let env = fleet.environment(env_name)?;
    let prod = fleet
        .products
        .get(&product_name)
        .ok_or_else(|| super::undefined_product(fleet, &product_name, Some(env_name)))?;
    if prod.source_only {
        // 07.38: the cause's step is the preview of a product that reads it, when one does.
        return Err(super::source_only(fleet, &product_name, Some(env_name)));
    }
    let selection = select(env_name, env, &product_name, prod, role)?;
    let remote_doc = match remote {
        Some(name) => {
            let r = super::run::remote_profile(fleet, env_name, &product_name, role, name)?;
            Some(json!({
                "profile": name,
                "host": r.host,
                "port": r.port,
                "user": r.user,
                "host_key_type": r.host_key.split(' ').next(),
                "host_key_pinned": true,
                "workdir": r.workdir,
                "command": r.command,
                "opv": r.opv,
                "environments": r.environments,
                "roles": r.roles,
                "ssh": ssh_present(),
                "file_delivery": "checked on the remote host: a user-owned $XDG_RUNTIME_DIR on tmpfs, else refused",
            }))
        }
        None => None,
    };
    let environment_mode = match prod.local.as_ref().map(|l| l.environment) {
        Some(crate::domain::model::LocalEnvironment::DeclaredOnly) => "declared_only",
        _ => "inherit",
    };
    let dir_env = prod
        .local
        .as_ref()
        .and_then(|l| l.secrets_dir_env.as_deref());
    let environment_mode = if remote.is_some() {
        "declared_only"
    } else {
        environment_mode
    };
    let file_delivery = match crate::app::local_delivery::runtime_dir_support() {
        Ok(_) => json!({"supported": true, "reason": Value::Null}),
        Err(why) => json!({
            "supported": false,
            "reason": crate::app::local_delivery::ram_dir_reason(&why),
        }),
    };
    let keys: Vec<Value> = selection
        .delivered
        .iter()
        .map(|(key, spec)| {
            let (source_product, source_key) = spec
                .source()
                .unwrap_or((product_name.as_str(), key.as_str()));
            let destination = match &spec.file {
                Some(path) => format!("file:{path}"),
                None => format!("env:{key}"),
            };
            json!({
                "product": product_name,
                "key": key,
                "source": format!("{source_product}/{source_key}"),
                "destination": destination,
                "roles": match &spec.roles {
                    Some(roles) => json!(roles),
                    None => Value::Null,
                },
            })
        })
        .collect();
    Ok(json!({
        "schema_version": SCHEMA_VERSION,
        "environment": env_name,
        "product": product_name,
        "role": role,
        "environment_mode": environment_mode,
        "secrets_dir_env": dir_env,
        "file_delivery": file_delivery,
        "prerequisites": prerequisites(runner),
        "keys": keys,
        "withheld_by_role": selection
            .withheld
            .iter()
            .map(|k| k.as_str())
            .collect::<Vec<_>>(),
        "transport": if remote.is_some() { "remote" } else { "local" },
        "remote": remote_doc,
        "remote_profiles": prod.remotes.keys().collect::<Vec<_>>(),
    }))
}

/// Whether the OpenSSH client is on PATH (`yes`/`no`), found by looking, never by running.
fn ssh_present() -> &'static str {
    let found = std::env::var_os("PATH").is_some_and(|p| {
        std::env::split_paths(&p).any(|d| d.join("ssh").is_file() || d.join("ssh.exe").is_file())
    });
    if found { "yes" } else { "no" }
}

/// The two prerequisites a person needs for a run: `op` present and signed in. Found with
/// the existing read-only session check (never an item read). A probe that cannot complete
/// is `unknown`, never `no`: a failed discovery is not a missing one.
fn prerequisites(runner: &dyn CommandRunner) -> Value {
    let (op, signed_in) = match onepassword::diagnose(runner, &Host::detect) {
        Ok(Session::SignedIn(_)) => ("yes", "yes"),
        Ok(Session::NotSignedIn | Session::NoAccount | Session::CredentialFailed(_)) => {
            ("yes", "no")
        }
        Ok(Session::Unknown) => ("unknown", "unknown"),
        Err(e) if e.code_str() == "dependency_missing" => ("no", "unknown"),
        Err(_) => ("unknown", "unknown"),
    };
    json!({"op": op, "signed_in": signed_in})
}

/// `opv run <env> [--product <p>] [--role <r>] --preview [--json]`: build the document and
/// print it. Reads no value, runs nothing, and returns 0.
#[allow(clippy::too_many_arguments)]
pub fn preview_for(
    fleet: &Fleet,
    env_name: &str,
    product: Option<&str>,
    role: Option<&str>,
    remote: Option<&str>,
    json_out: bool,
    runner: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let doc = build_for(fleet, env_name, product, role, remote, runner)?;
    if json_out {
        let text = serde_json::to_string(&doc).map_err(|_| -> Error {
            Cause::Bug {
                site: "run --preview: the document",
            }
            .into()
        })?;
        writeln!(out, "{text}").map_err(write_err)?;
    } else {
        write_text(&doc, out).map_err(write_err)?;
    }
    Ok(())
}

/// The preview could not be written to stdout (A3): `LocalIo{Stdout}`.
fn write_err(e: io::Error) -> Error {
    crate::cause::Cause::LocalIo {
        op: crate::cause::LocalOp::Stdout,
        path: std::path::PathBuf::new(),
        io: crate::cause::IoKind::from(e.kind()),
    }
    .into()
}

/// The text form: one line per delivered key plus the summary lines, names and identifiers
/// only.
fn write_text(doc: &Value, out: &mut dyn Write) -> io::Result<()> {
    for k in doc["keys"].as_array().into_iter().flatten() {
        let roles = match &k["roles"] {
            Value::Array(a) => a
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", "),
            _ => "all".to_string(),
        };
        writeln!(
            out,
            "{} -> {} (source {}; roles {})",
            k["key"].as_str().unwrap_or(""),
            k["destination"].as_str().unwrap_or(""),
            k["source"].as_str().unwrap_or(""),
            roles
        )?;
    }
    let withheld: Vec<&str> = doc["withheld_by_role"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if !withheld.is_empty() {
        writeln!(out, "withheld by role: {}", withheld.join(", "))?;
    }
    writeln!(
        out,
        "environment mode: {}",
        doc["environment_mode"].as_str().unwrap_or("inherit")
    )?;
    match doc["secrets_dir_env"].as_str() {
        Some(v) => writeln!(out, "secrets directory: {v}")?,
        None => writeln!(out, "secrets directory: none")?,
    }
    // 07.24: only when a key is a file, and for a remote run the remote host decides.
    let r = &doc["remote"];
    let fd = &doc["file_delivery"];
    let has_file = doc["keys"].as_array().into_iter().flatten().any(|k| {
        k["destination"]
            .as_str()
            .is_some_and(|d| d.starts_with("file:"))
    });
    if has_file {
        if r.is_object() {
            writeln!(out, "file delivery: checked on the remote host")?;
        } else if fd["supported"].as_bool().unwrap_or(false) {
            writeln!(out, "file delivery: supported")?;
        } else {
            writeln!(
                out,
                "file delivery: unsupported ({})",
                fd["reason"].as_str().unwrap_or("unknown")
            )?;
        }
    }
    if r.is_object() {
        writeln!(
            out,
            "transport: remote profile {} ({}@{}:{}, pinned {} host key; ssh on PATH: {})",
            r["profile"].as_str().unwrap_or(""),
            r["user"].as_str().unwrap_or(""),
            r["host"].as_str().unwrap_or(""),
            r["port"],
            r["host_key_type"].as_str().unwrap_or(""),
            r["ssh"].as_str().unwrap_or("unknown"),
        )?;
        let command: Vec<&str> = r["command"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        writeln!(
            out,
            "remote command: {} (in {})",
            command.join(" "),
            r["workdir"].as_str().unwrap_or("")
        )?;
    } else {
        writeln!(out, "transport: local")?;
    }
    writeln!(
        out,
        "op: {}; signed in: {}",
        doc["prerequisites"]["op"].as_str().unwrap_or("unknown"),
        doc["prerequisites"]["signed_in"]
            .as_str()
            .unwrap_or("unknown")
    )?;
    Ok(())
}

#[cfg(test)]
#[path = "delivery_preview_tests.rs"]
mod tests;
