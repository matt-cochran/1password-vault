//! `opv version [--json]` (#131): opv's own version and a local inventory of the CLIs it
//! runs, in one command. `opv --version` stays the single line it always was.
//!
//! Read-only, quick and credential-free: one bounded version probe per CLI opv runs (the
//! 1Password CLI, then each registered provider's), with arguments that print the version
//! locally (never a sign-in, an account or vault call, a service request or an update
//! check). Only the version token is kept from a probe's output. The configuration is read
//! from a local `secrets.toml` only, to tell which providers it uses; a configuration kept
//! in 1Password is reported as not read. Missing CLIs and failed probes are information:
//! the command exits 0 whenever it printed opv's version.

use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::json;

use super::write_err;
use crate::adapters::probe::version_in;
use crate::adapters::registry;
use crate::error::Error;
use crate::host::Tool;
use crate::runner::{Call, CommandRunner, PROBE_TIMEOUT};

/// One CLI opv runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ToolReport {
    pub program: &'static str,
    pub vendor: &'static str,
    /// `installed`, `missing` or `unknown`.
    pub status: &'static str,
    pub version: Option<String>,
    /// Why the version is unknown: `timed out`, `probe failed`, `version not recognised`.
    pub reason: Option<&'static str>,
    /// The provider sections that use it; empty for the 1Password CLI, which every
    /// project uses.
    pub providers: Vec<&'static str>,
    /// Whether the local configuration uses it; `None` when there is none to read.
    pub configured: Option<bool>,
}

/// One registered provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderReport {
    pub section: &'static str,
    pub configured: Option<bool>,
    pub tools: Vec<&'static str>,
}

/// Where the configuration is, as far as a local look can tell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfigReport {
    /// `file`, `manifest` or `none`.
    pub source: &'static str,
    pub path: Option<PathBuf>,
    /// True when the file was read for its provider sections.
    pub read: bool,
}

/// The local configuration: `config` (`--config`/`OPV_CONFIG`) or the nearest
/// `secrets.toml`, else a `.opv` pointer (a configuration in 1Password, not read here).
/// The provider sections its targets use, when it could be read.
pub fn local_config(config: Option<&Path>, start: &Path) -> (ConfigReport, Option<Vec<String>>) {
    use crate::config_store::{find_dot_opv, walk_up};
    let path = config
        .map(Path::to_path_buf)
        .or_else(|| walk_up(start, "secrets.toml"));
    let Some(path) = path else {
        let source = if find_dot_opv(start).is_some() {
            "manifest"
        } else {
            "none"
        };
        return (
            ConfigReport {
                source,
                path: None,
                read: false,
            },
            None,
        );
    };
    let sections = std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| t.parse::<toml_edit::DocumentMut>().ok())
        .map(|doc| target_sections(&doc));
    (
        ConfigReport {
            source: "file",
            read: sections.is_some(),
            path: Some(path),
        },
        sections,
    )
}

/// Every provider section a target of the document names.
fn target_sections(doc: &toml_edit::DocumentMut) -> Vec<String> {
    let mut out = Vec::new();
    let envs = doc.get("environments").and_then(|e| e.as_table_like());
    for (_, env) in envs.into_iter().flat_map(|t| t.iter()) {
        let targets = env.get("targets").and_then(|t| t.as_table_like());
        for (_, target) in targets.into_iter().flat_map(|t| t.iter()) {
            for p in registry::PROVIDERS {
                if target.get(p.section()).is_some() && !out.iter().any(|s| s == p.section()) {
                    out.push(p.section().to_string());
                }
            }
        }
    }
    out
}

/// One bounded probe of `tool`'s version.
fn probe(
    r: &dyn CommandRunner,
    tool: &Tool,
) -> (&'static str, Option<String>, Option<&'static str>) {
    match r.probe(&Call::new(tool.program, tool.version_args), PROBE_TIMEOUT) {
        Ok(o) if o.status == 0 => match version_in(o.stdout.as_slice()) {
            Some(v) => ("installed", Some(v), None),
            None => ("unknown", None, Some("version not recognised")),
        },
        Ok(_) => {
            // The probe's stderr must not attach to anything this command reports.
            let _ = crate::runner::take_failure_excerpt();
            ("unknown", None, Some("probe failed"))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => ("missing", None, None),
        Err(e) if e.kind() == ErrorKind::TimedOut => ("unknown", None, Some("timed out")),
        Err(_) => ("unknown", None, Some("probe failed")),
    }
}

/// The inventory: every CLI opv runs, and each provider, against `sections` (the local
/// configuration's provider sections, `None` when there is none to read).
pub fn inventory(
    r: &dyn CommandRunner,
    sections: Option<&[String]>,
) -> (Vec<ToolReport>, Vec<ProviderReport>) {
    let uses = |section: &str| sections.map(|s| s.iter().any(|x| x == section));
    let providers: Vec<ProviderReport> = registry::PROVIDERS
        .iter()
        .map(|p| ProviderReport {
            section: p.section(),
            configured: uses(p.section()),
            tools: p.tools().iter().map(|t| t.program).collect(),
        })
        .collect();
    let tools = crate::host::tools()
        .map(|tool| {
            let users: Vec<&'static str> = providers
                .iter()
                .filter(|p| p.tools.contains(&tool.program))
                .map(|p| p.section)
                .collect();
            let configured = if tool.program == crate::host::OP_CLI.program {
                sections.map(|_| true)
            } else {
                sections.map(|_| {
                    providers
                        .iter()
                        .any(|p| users.contains(&p.section) && p.configured == Some(true))
                })
            };
            let (status, version, reason) = probe(r, tool);
            ToolReport {
                program: tool.program,
                vendor: tool.vendor,
                status,
                version,
                reason,
                providers: users,
                configured,
            }
        })
        .collect();
    (tools, providers)
}

/// `opv version [--json]`.
pub fn run(
    r: &dyn CommandRunner,
    config: Option<&Path>,
    start: &Path,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let opv = env!("CARGO_PKG_VERSION");
    let (cfg, sections) = local_config(config, start);
    let (tools, providers) = inventory(r, sections.as_deref());
    if json {
        let doc = json!({
            "schema_version": crate::json::SCHEMA_VERSION,
            "opv": {"version": opv},
            "tools": tools,
            "providers": providers,
            "config": cfg,
        });
        return writeln!(out, "{doc}").map_err(write_err);
    }
    writeln!(out, "opv {opv}").map_err(write_err)?;
    for t in &tools {
        let state = match (t.status, &t.version, t.reason) {
            ("installed", Some(v), _) => v.clone(),
            // 05.40: what to do about it, not only the state.
            ("missing", _, _) => "missing (opv doctor shows how to install it)".into(),
            (_, _, reason) => format!("unknown ({})", reason.unwrap_or("probe failed")),
        };
        let used = if t.providers.is_empty() {
            "every project".to_string()
        } else {
            format!("targets: {}", t.providers.join(", "))
        };
        let configured = match t.configured {
            Some(true) => "; configured",
            // 05.40: "not configured" read as "not set up"; it means this project's
            // configuration has no target that needs the tool.
            Some(false) => "; not used by this configuration",
            None => "",
        };
        writeln!(
            out,
            "{} ({}): {state}; used by {used}{configured}",
            t.program, t.vendor
        )
        .map_err(write_err)?;
    }
    let config_line = match (cfg.source, &cfg.path, cfg.read) {
        ("file", Some(p), true) => format!("configuration: {}", p.display()),
        ("file", Some(p), false) => {
            format!("configuration: {} (not readable as TOML)", p.display())
        }
        ("manifest", _, _) => "configuration: in 1Password (not read; needs sign-in)".into(),
        _ => "configuration: none found here".into(),
    };
    writeln!(out, "{config_line}").map_err(write_err)
}

#[cfg(test)]
#[path = "version_tests.rs"]
mod tests;
