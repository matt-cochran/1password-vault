//! `opv skill install` / `opv skill status` (FR-52): the agent skill embedded in this
//! binary, installed where coding agents look for it, and a report of installed copies.
//!
//! The skill is versioned with the binary. [`render`] replaces every `{{OPV_VERSION}}` and
//! appends one marker line naming the version and the sha256 of everything before it, so
//! [`status`] and `opv doctor` can tell a current copy from an older or hand-edited one
//! without reading any value. An existing copy whose marker hash matches its content was
//! written by opv (any version) and is safe to overwrite; anything else is kept.
//!
//! Copies are written only on install: by `install.sh`, the npm postinstall and `opv skill
//! install` (design `docs/design/error-catalog.md` §12.4). No other command writes $HOME;
//! [`update_commands`] names the install that brings an outdated copy up to date.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::Error;

/// The agent skill, embedded so it matches this binary's version (A10).
const SKILL: &str = include_str!("../../docs/agent-skill.md");

/// Where a coding agent looks for the skill.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Target {
    /// Claude Code: `<root>/.claude/skills/opv/SKILL.md`.
    Claude,
    /// Codex and other `.agents` clients: `<root>/.agents/skills/opv/SKILL.md`.
    Codex,
}

/// Both targets, in `all` order.
pub const ALL: [Target; 2] = [Target::Claude, Target::Codex];

impl Target {
    /// `claude` / `codex`, as the CLI spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            Target::Claude => "claude",
            Target::Codex => "codex",
        }
    }

    /// The skill file under `root`.
    pub fn path(self, root: &Path) -> PathBuf {
        match self {
            Target::Claude => root.join(".claude/skills/opv/SKILL.md"),
            Target::Codex => root.join(".agents/skills/opv/SKILL.md"),
        }
    }
}

/// The user's home directory: `HOME`, else `USERPROFILE` (Windows).
pub fn user_root() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// The current directory's git top level (the first ancestor containing `.git`), else the
/// current directory.
pub fn project_root() -> PathBuf {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    cwd.ancestors()
        .find(|d| d.join(".git").exists())
        .map(Path::to_path_buf)
        .unwrap_or(cwd)
}

/// The roots `status` and `doctor` look at: the user's home (when it is known) and this
/// project.
pub fn roots() -> Vec<(&'static str, PathBuf)> {
    let mut roots = Vec::new();
    if let Some(home) = user_root() {
        roots.push(("user", home));
    }
    roots.push(("project", project_root()));
    roots
}

/// Render the embedded skill for `version`: every `{{OPV_VERSION}}` replaced, then one
/// final marker line naming the version and the sha256 of everything before it.
pub fn render(version: &str) -> String {
    let body = SKILL.replace("{{OPV_VERSION}}", version);
    let hash = sha256_hex(body.as_bytes());
    format!("{body}<!-- opv-skill {version} sha256:{hash} -->\n")
}

/// The version of an unedited copy (its marker hash matches the content before it), or
/// `None` when the file has no well-formed marker or was edited.
pub fn installed_version(text: &str) -> Option<String> {
    let (body, version, hash) = marker(text)?;
    (sha256_hex(body.as_bytes()) == hash).then(|| version.to_string())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// `(content before the marker, version, hash)` of the final marker line, when the text
/// ends with a well-formed one; `None` for a file opv never wrote or that was damaged.
fn marker(text: &str) -> Option<(&str, &str, &str)> {
    let without_trailing = text.strip_suffix('\n')?;
    let start = without_trailing.rfind('\n').map_or(0, |i| i + 1);
    let line = &without_trailing[start..];
    let inner = line.strip_prefix("<!-- opv-skill ")?.strip_suffix(" -->")?;
    let (version, hash) = inner.rsplit_once(" sha256:")?;
    (hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())).then_some((
        &text[..start],
        version,
        hash,
    ))
}

/// The version in the marker (when there is one) and whether the copy was edited by hand
/// (no marker, or a hash that does not match its content).
fn inspect(text: &str) -> (Option<String>, bool) {
    match marker(text) {
        Some((body, version, hash)) => (
            Some(version.to_string()),
            sha256_hex(body.as_bytes()) != hash,
        ),
        None => (None, true),
    }
}

/// A copy written (`written`) and a copy kept because it was edited by hand (`kept`).
#[derive(Debug, Default)]
pub struct Installed {
    pub written: Vec<(Target, PathBuf)>,
    pub kept: Vec<(Target, PathBuf)>,
}

impl serde::Serialize for Installed {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;
        let written: Vec<Entry<'_>> = self
            .written
            .iter()
            .map(|(target, path)| Entry {
                target: *target,
                path,
            })
            .collect();
        let kept: Vec<Kept<'_>> = self
            .kept
            .iter()
            .map(|(target, path)| Kept {
                target: *target,
                path,
                reason: "edited",
            })
            .collect();
        let mut st = s.serialize_struct("Installed", 2)?;
        st.serialize_field("written", &written)?;
        st.serialize_field("kept", &kept)?;
        st.end()
    }
}

#[derive(serde::Serialize)]
struct Entry<'a> {
    target: Target,
    path: &'a Path,
}

#[derive(serde::Serialize)]
struct Kept<'a> {
    target: Target,
    path: &'a Path,
    reason: &'static str,
}

/// Install `render(version)` for each target under `root`. A missing file is written; an
/// existing file whose marker hash matches its content (unedited, any version) is
/// overwritten; an edited file is kept unless `force`. Writes are atomic.
pub fn install(
    root: &Path,
    targets: &[Target],
    version: &str,
    force: bool,
) -> Result<Installed, Error> {
    let text = render(version);
    let mut installed = Installed::default();
    for &target in targets {
        let path = target.path(root);
        let edited = match fs::read_to_string(&path) {
            Ok(existing) => inspect(&existing).1,
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            // Unreadable: never overwrite what opv cannot verify.
            Err(_) => true,
        };
        if edited && !force {
            installed.kept.push((target, path));
            continue;
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| write_error("create", parent, e))?;
        }
        crate::config_edit::write_atomic(&path, &text, || Ok(()))?;
        installed.written.push((target, path));
    }
    Ok(installed)
}

/// One installed copy of the skill.
#[derive(Debug, serde::Serialize)]
pub struct Copy {
    /// `user` or `project`.
    pub scope: String,
    /// The root the copy was found under (the home, or the project's top level).
    #[serde(skip)]
    pub root: PathBuf,
    pub target: Target,
    pub path: PathBuf,
    /// The version in the marker, when the file has one.
    pub version: Option<String>,
    /// The file was edited by hand (its marker hash does not match) or has no marker.
    pub edited: bool,
    /// The copy is this binary's version and unedited.
    pub current: bool,
}

/// Every target file that exists under `roots`, one copy each.
pub fn status(roots: &[(&str, PathBuf)], version: &str) -> Vec<Copy> {
    let mut copies = Vec::new();
    for (scope, root) in roots {
        for target in ALL {
            let path = target.path(root);
            let Ok(text) = fs::read_to_string(&path) else {
                continue;
            };
            let (found, edited) = inspect(&text);
            copies.push(Copy {
                scope: (*scope).to_string(),
                root: root.clone(),
                target,
                path,
                current: !edited && found.as_deref() == Some(version),
                version: found,
                edited,
            });
        }
    }
    copies
}

impl Copy {
    /// Unedited and not this binary's version: `opv skill install` replaces it.
    pub fn outdated(&self) -> bool {
        !self.edited && !self.current
    }
}

/// The install that updates each scope holding an outdated copy, one per root in the order
/// found: `opv skill install --user` for the home, `opv skill install --project <root>` for
/// a project (never `--user` for a project copy), with `--target` when only one of the
/// root's copies is outdated. Empty when every copy is current or edited.
pub fn update_commands(copies: &[Copy]) -> Vec<String> {
    let mut roots: Vec<(&str, &Path, Vec<Target>)> = Vec::new();
    for c in copies.iter().filter(|c| c.outdated()) {
        match roots.iter_mut().find(|(_, r, _)| *r == c.root.as_path()) {
            Some((_, _, targets)) => targets.push(c.target),
            None => roots.push((&c.scope, &c.root, vec![c.target])),
        }
    }
    roots
        .into_iter()
        .map(|(scope, root, targets)| {
            let mut cmd = if scope == "user" {
                "opv skill install --user".to_string()
            } else {
                format!(
                    "opv skill install --project {}",
                    crate::error::shell_word(&root.display().to_string())
                )
            };
            if let [one] = targets.as_slice() {
                cmd.push_str(" --target ");
                cmd.push_str(one.as_str());
            }
            cmd
        })
        .collect()
}

/// The `opv skill install --json` document: `written` and `kept` (with `reason`), and the
/// next step. Names and paths only.
pub fn install_document(installed: &Installed) -> Result<String, Error> {
    let mut doc = serde_json::to_value(installed).map_err(json_error)?;
    doc["schema_version"] = serde_json::json!(crate::json::SCHEMA_VERSION);
    doc["next"] = serde_json::json!("opv guide agent");
    Ok(doc.to_string())
}

/// The `opv skill status --json` document: one entry per installed copy, the installs that
/// update outdated copies (`update`), and the next step: the first of those, `opv skill
/// install` when nothing is installed, else none.
pub fn status_document(copies: &[Copy]) -> Result<String, Error> {
    let update = update_commands(copies);
    let next = match update.first() {
        Some(first) => Some(first.clone()),
        None if copies.is_empty() => Some("opv skill install".to_string()),
        None => None,
    };
    let doc = serde_json::json!({
        "schema_version": crate::json::SCHEMA_VERSION,
        "copies": copies,
        "update": update,
        "next": next,
    });
    Ok(doc.to_string())
}

fn json_error(e: serde_json::Error) -> Error {
    Error::Dependency(format!("cannot serialize JSON ({e})").into())
}

fn write_error(what: &str, p: &Path, e: io::Error) -> Error {
    Error::Config(format!("cannot {what} {}: {e}", p.display()).into())
}
