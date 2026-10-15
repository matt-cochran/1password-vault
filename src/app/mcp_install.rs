//! `opv mcp install` (#133 follow-up, 0.8.1): register opv's MCP server, `opv mcp serve
//! --project <dir>`, with an assistant, so the MCP tools need no separate binary or build.
//!
//! - Claude Code: the project's `.mcp.json` (`mcpServers.<name>`), shared with the team
//!   when committed.
//! - Codex: the user's `$CODEX_HOME/config.toml`, else `~/.codex/config.toml`
//!   (`[mcp_servers.<name>]`).
//!
//! Each file is merged, never replaced: other servers and settings stay as they are, and an
//! existing entry of the same name that runs something else is refused unless `--force`.
//! The entry holds the absolute path of this opv and the project directory; no value,
//! credential or environment variable is ever written (the server must start without
//! `op` session, service-account or Connect credentials, so none is put in its config).

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::error::{Code, Error};

/// The entry name opv registers by default.
pub const NAME: &str = "opv";

/// What registering did to one client's configuration.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Registered {
    /// `claude` or `codex`.
    pub client: &'static str,
    pub path: PathBuf,
    /// `added`, `updated` (with `--force`) or `unchanged`.
    pub action: &'static str,
}

/// The command and arguments of the server entry: `<opv> mcp serve --project <dir>`.
pub fn server_args(project: &Path) -> Vec<String> {
    vec![
        "mcp".into(),
        "serve".into(),
        "--project".into(),
        project.display().to_string(),
    ]
}

fn conflict(client: &str, path: &Path, name: &str) -> Error {
    Error::Policy(
        format!(
            "{} already has an MCP server named {name:?} that runs something else; opv left it \
             as it is",
            path.display()
        )
        .into(),
    )
    .with_code(Code::PolicyRefused)
    .with_do(format!(
        "keep it and register opv under another name (--name), or replace it with --force ({client})"
    ))
    .with_next(format!("opv mcp install --client {client} --name opv-project"))
}

fn invalid(path: &Path, what: &str) -> Error {
    Error::Config(
        format!(
            "{} is not valid {what}; opv did not change it",
            path.display()
        )
        .into(),
    )
    .with_code(Code::ConfigInvalid)
}

/// `text` (the current `.mcp.json`, empty when there is none) with `name` registered as
/// `command args`: the new text and what changed.
pub fn merge_claude(
    text: &str,
    path: &Path,
    name: &str,
    command: &str,
    args: &[String],
    force: bool,
) -> Result<(String, &'static str), Error> {
    let mut doc: Value = if text.trim().is_empty() {
        json!({})
    } else {
        serde_json::from_str(text).map_err(|_| invalid(path, "JSON"))?
    };
    let Some(root) = doc.as_object_mut() else {
        return Err(invalid(path, "an MCP configuration (a JSON object)"));
    };
    let servers = root
        .entry("mcpServers")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| invalid(path, "an MCP configuration (mcpServers is not an object)"))?;
    let entry = json!({"command": command, "args": args});
    let action = match servers.get(name) {
        Some(existing) if existing == &entry => return Ok((text.to_string(), "unchanged")),
        Some(_) if !force => return Err(conflict("claude", path, name)),
        Some(_) => "updated",
        None => "added",
    };
    servers.insert(name.to_string(), entry);
    let mut out =
        serde_json::to_string_pretty(&doc).map_err(|_| invalid(path, "JSON after the change"))?;
    out.push('\n');
    Ok((out, action))
}

/// `text` (the current Codex `config.toml`, empty when there is none) with `name`
/// registered under `[mcp_servers.<name>]`, comments and order kept.
pub fn merge_codex(
    text: &str,
    path: &Path,
    name: &str,
    command: &str,
    args: &[String],
    force: bool,
) -> Result<(String, &'static str), Error> {
    use toml_edit::{Array, DocumentMut, Item, Table, value};
    let mut doc: DocumentMut = text.parse().map_err(|_| invalid(path, "TOML"))?;
    if doc.get("mcp_servers").is_none() {
        let mut t = Table::new();
        t.set_implicit(true);
        doc.insert("mcp_servers", Item::Table(t));
    }
    let servers = doc["mcp_servers"]
        .as_table_mut()
        .ok_or_else(|| invalid(path, "a Codex configuration (mcp_servers is not a table)"))?;
    let same = |t: &dyn toml_edit::TableLike| {
        t.get("command").and_then(Item::as_str) == Some(command)
            && t.get("args").and_then(Item::as_array).is_some_and(|a| {
                a.iter().map(|v| v.as_str()).collect::<Vec<_>>()
                    == args.iter().map(|s| Some(s.as_str())).collect::<Vec<_>>()
            })
    };
    let action = match servers.get(name).and_then(Item::as_table_like) {
        Some(t) if same(t) => return Ok((text.to_string(), "unchanged")),
        Some(_) if !force => return Err(conflict("codex", path, name)),
        Some(_) => "updated",
        None => "added",
    };
    let mut entry = Table::new();
    entry.insert("command", value(command));
    let mut a = Array::new();
    for arg in args {
        a.push(arg.as_str());
    }
    entry.insert("args", value(a));
    servers.insert(name, Item::Table(entry));
    Ok((doc.to_string(), action))
}

/// The shared install npm's postinstall and install.sh keep current: `~/.local/bin/opv`,
/// `%LOCALAPPDATA%\Programs\opv\opv.exe` on Windows.
pub fn shared_install() -> Option<PathBuf> {
    if cfg!(windows) {
        let base = std::env::var_os("LOCALAPPDATA")?;
        return Some(
            PathBuf::from(base)
                .join("Programs")
                .join("opv")
                .join("opv.exe"),
        );
    }
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".local").join("bin").join("opv"))
}

/// The Codex configuration file: `$CODEX_HOME/config.toml`, else `~/.codex/config.toml`.
pub fn codex_config() -> Result<PathBuf, Error> {
    if let Some(home) = std::env::var_os("CODEX_HOME").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(home).join("config.toml"));
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or_else(|| Error::Config("cannot find the home directory (HOME)".into()))?;
    Ok(PathBuf::from(home).join(".codex").join("config.toml"))
}

/// Merge the entry into the file at `path` with `merge`, and write it atomically when it
/// changed (its directory created when missing).
pub fn register(
    client: &'static str,
    path: &Path,
    merge: impl FnOnce(&str) -> Result<(String, &'static str), Error>,
) -> Result<Registered, Error> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(Error::Config(
                format!("cannot read {} ({})", path.display(), e.kind()).into(),
            ));
        }
    };
    let (new, action) = merge(&text)?;
    if action != "unchanged" {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| {
                Error::Config(format!("cannot create {} ({})", dir.display(), e.kind()).into())
            })?;
        }
        crate::config_edit::write_atomic(path, &new, || Ok(()))?;
    }
    Ok(Registered {
        client,
        path: path.to_path_buf(),
        action,
    })
}

#[cfg(test)]
#[path = "mcp_install_tests.rs"]
mod tests;
