//! Where the configuration lives (FR-1, FR-25, FR-44): a `secrets.toml` file or a project
//! manifest in 1Password holding the same TOML. Both implement [`ConfigStore`], so every
//! command (and `add`, `init` and tidy-ups) reads and writes either one the same way.
//!
//! Discovery ([`locate`]), first match wins:
//! 1. `--config <file>` (or `OPV_CONFIG`);
//! 2. `OPV_PROJECT=<name>`: the manifest titled `opv · <name>`;
//! 3. a `secrets.toml` in the current directory or a parent (unchanged since v0.2);
//! 4. a one-line `.opv` file (`project = "<name>"`, optionally `account = "…"`) in the
//!    current directory or a parent;
//! 5. the git remote `origin`, normalized to `host/owner/repo`, matched against the
//!    manifests' repo tags.
//!
//! Steps 2, 4 and 5 make one `op item list --tags opv-manifest` call (metadata only);
//! loading a manifest is one more `op item get` by IDs, before the environment's item read.
//! The manifest holds names, IDs and rules, never a value.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::adapters::onepassword_manifest::{self as manifest, MANIFEST_TAG, Row};
use crate::config;
use crate::domain::Fleet;
use crate::error::Error;
use crate::host::Host;
use crate::runner::{Call, CommandRunner, PROBE_TIMEOUT};

/// The file read by step 3 of discovery.
pub const FILE_NAME: &str = "secrets.toml";
/// The one-line project pointer read by step 4.
pub const DOT_FILE: &str = ".opv";
/// The tag prefix carrying a normalized repository (`/` replaced by `|`, see [`repo_tag`]).
pub const REPO_TAG_PREFIX: &str = "opv-repo:";

/// The manifest's title for `project`.
pub fn manifest_title(project: &str) -> String {
    format!("opv · {project}")
}

/// A project name: `^[A-Za-z0-9][A-Za-z0-9._-]*$`, at most 64 characters.
pub fn is_project_name(s: &str) -> bool {
    s.len() <= 64 && config::is_id(s)
}

/// The text of a configuration and the version it was read at (the manifest's item
/// version; `None` for a file, whose text itself is compared).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub text: String,
    pub version: Option<u64>,
}

/// What [`ConfigStore::replace`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Replaced {
    Saved,
    /// The configuration changed since `base` was read; nothing was written. Holds the
    /// current snapshot to start again from.
    Changed(Snapshot),
}

/// A home for the configuration text: the file or the manifest.
pub trait ConfigStore {
    /// One line naming it: `./secrets.toml`, `manifest "opv · app" in vault V (matched …)`.
    fn describe(&self) -> String;
    /// Read the current text.
    fn read(&self, r: &dyn CommandRunner) -> Result<Snapshot, Error>;
    /// Read the text an edit starts from (`add`, `init --add-env`, `config edit`): for the
    /// manifest, refused unless a person runs opv (I3) and read past `op`'s cache (C1).
    fn read_for_write(&self, r: &dyn CommandRunner) -> Result<Snapshot, Error> {
        self.read(r)
    }
    /// Replace the text with `text` if it is still at `base` (optimistic concurrency).
    fn replace(
        &self,
        r: &dyn CommandRunner,
        base: &Snapshot,
        text: &str,
    ) -> Result<Replaced, Error>;
    /// How errors in its text name it (`<path>:<line>: …` or `manifest "opv · app": …`).
    fn source(&self) -> config::Source<'_>;
    /// Validate `text` as this configuration, with errors naming it (H10, FR-44).
    fn parse(&self, text: &str) -> Result<Fleet, Error> {
        config::parse_at(text, self.source())
    }
}

/// Write `text` over `base` through `store`, refusing (nothing written) when someone
/// changed the configuration since it was read. For commands that edit once and stop
/// (`add`, `init --add-env`); `config edit` re-opens instead.
pub fn save(
    store: &dyn ConfigStore,
    r: &dyn CommandRunner,
    base: &Snapshot,
    text: &str,
) -> Result<(), Error> {
    match store.replace(r, base, text)? {
        Replaced::Saved => Ok(()),
        Replaced::Changed(_) => Err(Error::Config(
            format!(
                "{} changed while opv was editing it; nothing written: run the command again",
                store.describe()
            )
            .into(),
        )
        .with_code(crate::error::Code::ConfigChanged)),
    }
}

/// `secrets.toml` (or any `--config` path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileStore {
    pub path: PathBuf,
}

impl ConfigStore for FileStore {
    fn describe(&self) -> String {
        self.path.display().to_string()
    }

    fn read(&self, _: &dyn CommandRunner) -> Result<Snapshot, Error> {
        let text = fs::read_to_string(&self.path).map_err(|e| {
            Error::Config(format!("cannot read {}: {e}", self.path.display()).into())
        })?;
        Ok(Snapshot {
            text,
            version: None,
        })
    }

    fn replace(
        &self,
        r: &dyn CommandRunner,
        base: &Snapshot,
        text: &str,
    ) -> Result<Replaced, Error> {
        let now = self.read(r)?;
        if now.text != base.text {
            return Ok(Replaced::Changed(now));
        }
        // Atomic (temporary file, then rename), symlinks followed, permissions kept, and
        // compared once more right before the rename.
        match crate::config_edit::replace(&self.path, &base.text, text) {
            Ok(()) => Ok(Replaced::Saved),
            Err(e) => match self.read(r) {
                Ok(now) if now.text != base.text => Ok(Replaced::Changed(now)),
                _ => Err(e),
            },
        }
    }

    fn source(&self) -> config::Source<'_> {
        config::Source::File(&self.path)
    }
}

/// How a manifest was found, for the `using` line and `doctor`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Matched {
    /// `OPV_PROJECT`.
    ProjectEnv,
    /// A `.opv` file.
    DotFile(PathBuf),
    /// The git remote, normalized.
    Repo(String),
    /// Named on the command line (`config import`, `init`).
    Given,
}

/// The project manifest in 1Password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestStore {
    pub vault_id: String,
    pub vault_name: String,
    pub item_id: String,
    pub title: String,
    pub account: Option<String>,
    pub matched: Matched,
}

impl ManifestStore {
    /// The store for a listed manifest.
    pub fn from_row(row: &Row, account: Option<String>, matched: Matched) -> Self {
        Self {
            vault_id: row.vault.id.clone(),
            vault_name: row.vault.name.clone(),
            item_id: row.id.clone(),
            title: row.title.clone(),
            account,
            matched,
        }
    }

    fn read_item(&self, r: &dyn CommandRunner, fresh: bool) -> Result<manifest::Manifest, Error> {
        manifest::get(
            r,
            &self.vault_id,
            &self.item_id,
            self.account.as_deref(),
            fresh,
            &Host::detect,
        )
    }

    /// I5: after the edit, the manifest must be exactly one version past the read it was
    /// built from and hold `text`; otherwise another edit landed in between (one of the
    /// two was lost). Reported, never retried.
    fn confirm(
        &self,
        r: &dyn CommandRunner,
        built_on: u64,
        written: manifest::Written,
        text: &str,
    ) -> Result<(), Error> {
        let (version, now) = match written {
            manifest::Written {
                version: Some(v),
                text: Some(t),
            } => (v, t),
            _ => {
                let m = self.read_item(r, true)?;
                (m.version, m.text)
            }
        };
        let expected = built_on + 1;
        if version == expected && now == text {
            return Ok(());
        }
        Err(Error::Config(
            format!(
                "{}: another edit landed while opv wrote it (version {version}, expected \
                 {expected}); opv did not retry. Check the manifest's history in 1Password and \
                 keep the right version",
                self.describe()
            )
            .into(),
        )
        .with_code(crate::error::Code::ConfigChanged)
        .with_next("opv config export --toml"))
    }
}

impl ConfigStore for ManifestStore {
    fn describe(&self) -> String {
        let vault = if self.vault_name.is_empty() {
            &self.vault_id
        } else {
            &self.vault_name
        };
        let how = match &self.matched {
            Matched::ProjectEnv => " (from OPV_PROJECT)".to_string(),
            Matched::DotFile(p) => format!(" (from {})", p.display()),
            Matched::Repo(repo) => format!(" (matched {repo})"),
            Matched::Given => String::new(),
        };
        format!("manifest {:?} in vault {vault}{how}", self.title)
    }

    fn read(&self, r: &dyn CommandRunner) -> Result<Snapshot, Error> {
        let m = self.read_item(r, false)?;
        Ok(Snapshot {
            text: m.text,
            version: Some(m.version),
        })
    }

    fn read_for_write(&self, r: &dyn CommandRunner) -> Result<Snapshot, Error> {
        crate::app::tidy::require_person(r, "this command")?;
        let m = self.read_item(r, true)?;
        Ok(Snapshot {
            text: m.text,
            version: Some(m.version),
        })
    }

    /// Refused unless a person runs opv (I3). Re-reads the item past `op`'s cache (C1) and
    /// refuses when its version moved since `base`; otherwise sends the item just read back
    /// with the new notes, then checks that the edit is exactly one version later and holds
    /// `text` (I5: op has no conditional write, so a change in the moment between the
    /// re-read and the write is detected afterwards and reported, not prevented).
    fn replace(
        &self,
        r: &dyn CommandRunner,
        base: &Snapshot,
        text: &str,
    ) -> Result<Replaced, Error> {
        crate::app::tidy::require_person(r, "this command")?;
        let now = self.read_item(r, true)?;
        if Some(now.version) != base.version {
            return Ok(Replaced::Changed(Snapshot {
                text: now.text,
                version: Some(now.version),
            }));
        }
        let written = manifest::edit(
            r,
            &self.vault_id,
            &self.item_id,
            &now.raw,
            text,
            self.account.as_deref(),
            &Host::detect,
        )?;
        self.confirm(r, now.version, written, text)?;
        Ok(Replaced::Saved)
    }
    fn source(&self) -> config::Source<'_> {
        config::Source::Manifest(&self.title)
    }

    fn parse(&self, text: &str) -> Result<Fleet, Error> {
        let mut fleet = config::parse_at(text, self.source())?;
        fleet.origin = crate::domain::Origin::Manifest;
        Ok(fleet)
    }
}

/// How `--config` was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Given {
    Flag,
    Env,
}

/// Where the configuration was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Found {
    File {
        store: FileStore,
        /// `None` when found by the walk-up.
        given: Option<Given>,
    },
    Manifest(ManifestStore),
}

impl Found {
    pub fn store(&self) -> &dyn ConfigStore {
        match self {
            Found::File { store, .. } => store,
            Found::Manifest(m) => m,
        }
    }

    /// The `using …` line for stderr, or `None` for a path given with `--config`.
    pub fn announce(&self) -> Option<String> {
        match self {
            Found::File {
                given: Some(Given::Flag),
                ..
            } => None,
            Found::File {
                store,
                given: Some(Given::Env),
            } => Some(format!("using {} (from OPV_CONFIG)", store.describe())),
            Found::File { store, given: None } => Some(format!("using {}", store.describe())),
            Found::Manifest(m) => Some(format!("using {}", m.describe())),
        }
    }

    /// Read and validate the configuration. A manifest found in a given account (a `.opv`
    /// pointer, `OP_ACCOUNT` or the multi-account search) passes that account to every
    /// environment that names none of its own (I2), so the environments' item reads go to
    /// the account the manifest lives in.
    pub fn load(&self, r: &dyn CommandRunner) -> Result<Fleet, Error> {
        let snap = self.store().read(r)?;
        let mut fleet = parse_from(self, &snap.text)?;
        if let Found::Manifest(ManifestStore {
            account: Some(a), ..
        }) = self
        {
            for env in fleet.environments.values_mut() {
                env.account.get_or_insert_with(|| a.clone());
            }
        }
        Ok(fleet)
    }
}

/// [`config::parse`] with errors naming where the text came from: `<path>:<line>: <field>`
/// for a file, `manifest "opv · app": <field>` for a manifest (H10, FR-44).
pub fn parse_from(found: &Found, text: &str) -> Result<Fleet, Error> {
    found.store().parse(text)
}

/// What discovery starts from.
#[derive(Debug, Clone, Default)]
pub struct Request {
    /// The current directory.
    pub start: PathBuf,
    /// `--config` / `OPV_CONFIG`.
    pub config: Option<(PathBuf, Given)>,
    /// `OPV_PROJECT` (non-empty).
    pub project: Option<String>,
    /// Skip step 3 (`secrets.toml`): `config check` and `config import` compare a file with
    /// the manifest, so the file itself must not be the match.
    pub manifest_only: bool,
    /// The 1Password account to look in (`OP_ACCOUNT`, [`account_env`]); a `.opv`
    /// pointer's own `account` wins. Without one, op's default account is listed first and
    /// a repository match not found there is looked for in every other signed-in account.
    pub account: Option<String>,
}

/// `OP_ACCOUNT`, when set and non-empty and no service-account or Connect credential is
/// set (that credential decides the account, as for environments, FR-40).
pub fn account_env() -> Option<String> {
    if Host::detect().op_credential.is_some() {
        return None;
    }
    // Only a value `--account` can take as a value, never a flag (M5).
    std::env::var("OP_ACCOUNT")
        .ok()
        .filter(|a| config::is_account(a))
}

/// `OPV_PROJECT`, when set and non-empty.
pub fn project_env() -> Option<String> {
    std::env::var("OPV_PROJECT").ok().filter(|p| !p.is_empty())
}

/// The `.opv` pointer.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DotOpv {
    pub project: String,
    #[serde(default)]
    pub account: Option<String>,
}

/// Parse a `.opv` file's text.
pub fn parse_dot_opv(text: &str, path: &Path) -> Result<DotOpv, Error> {
    let d: DotOpv = toml::from_str(text).map_err(|e| {
        Error::Config(
            format!(
                "invalid {}: {}; expected one line: project = \"<name>\" (optionally account = \
                 \"<account>\")",
                path.display(),
                e.message()
            )
            .into(),
        )
    })?;
    if !is_project_name(&d.project) {
        return Err(Error::Config(
            format!(
                "invalid {}: project {:?} must match ^[A-Za-z0-9][A-Za-z0-9._-]*$",
                path.display(),
                d.project
            )
            .into(),
        ));
    }
    // M5: the account reaches `op` as `--account <account>`: a sign-in address, email or
    // account ID only, never something `op` could read as a flag.
    if let Some(a) = &d.account
        && !config::is_account(a)
    {
        return Err(Error::Config(
            format!(
                "invalid {}: account {a:?} must be a sign-in address, email or account ID \
                 (letters, digits, . - _ @ +, starting with a letter or digit)",
                path.display()
            )
            .into(),
        ));
    }
    Ok(d)
}

/// The account named by the nearest `.opv` pointer, if any (read without any `op` call,
/// for `opv login` before a manifest can be read).
pub fn pointer_account(start: &Path) -> Option<String> {
    let path = walk_up(start, DOT_FILE)?;
    let text = fs::read_to_string(&path).ok()?;
    parse_dot_opv(&text, &path).ok()?.account
}

/// The nearest file named `name` in `start` or a parent.
fn walk_up(start: &Path, name: &str) -> Option<PathBuf> {
    start
        .ancestors()
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

/// Find the configuration (see the module docs). The `op` and `git` calls go through `r`.
pub fn locate(req: &Request, r: &dyn CommandRunner) -> Result<Found, Error> {
    if let Some((path, given)) = &req.config {
        return Ok(Found::File {
            store: FileStore { path: path.clone() },
            given: Some(*given),
        });
    }
    if let Some(project) = &req.project {
        return by_project(r, project, req.account.clone(), Matched::ProjectEnv);
    }
    if !req.manifest_only
        && let Some(path) = config::discover(&req.start)
    {
        return Ok(Found::File {
            store: FileStore { path },
            given: None,
        });
    }
    if let Some(path) = walk_up(&req.start, DOT_FILE) {
        let text = fs::read_to_string(&path)
            .map_err(|e| Error::Config(format!("cannot read {}: {e}", path.display()).into()))?;
        let dot = parse_dot_opv(&text, &path)?;
        let account = dot.account.or_else(|| req.account.clone());
        return by_project(r, &dot.project, account, Matched::DotFile(path));
    }
    match git_repo(r) {
        Some(repo) => by_repo(r, &repo, &req.start, req.account.as_deref()),
        None => Err(not_found(&req.start, None)),
    }
}

/// The manifest titled `opv · <project>`.
fn by_project(
    r: &dyn CommandRunner,
    project: &str,
    account: Option<String>,
    matched: Matched,
) -> Result<Found, Error> {
    if !is_project_name(project) {
        return Err(Error::Config(
            format!("project {project:?} must match ^[A-Za-z0-9][A-Za-z0-9._-]*$").into(),
        ));
    }
    let rows = manifest::list(r, account.as_deref(), &Host::detect)?;
    let title = manifest_title(project);
    let hits: Vec<&Row> = rows.iter().filter(|r| r.title == title).collect();
    match hits.as_slice() {
        [one] => Ok(Found::Manifest(ManifestStore::from_row(
            one, account, matched,
        ))),
        [] => Err(Error::Config(
            format!("no 1Password manifest titled {title:?} (tag {MANIFEST_TAG}) is visible")
                .into(),
        )
        .with_code(crate::error::Code::ManifestNotFound)
        .with_next(format!(
            "opv config import --vault <vault> --project {project}"
        ))),
        many => Err(Error::Config(
            format!(
                "{} manifests are titled {title:?}: {}; keep one (archive the others in \
                 1Password)",
                many.len(),
                listing(many)
            )
            .into(),
        )
        .with_code(crate::error::Code::ManifestAmbiguous)),
    }
}

/// The manifests whose repo tag is `repo`; in a monorepo the one whose path tag is the
/// longest prefix of the current directory (relative to the repository root) wins, and a
/// manifest without paths covers the whole repository at the lowest priority.
fn by_repo(
    r: &dyn CommandRunner,
    repo: &str,
    start: &Path,
    account: Option<&str>,
) -> Result<Found, Error> {
    let tag = repo_tag(repo);
    let mut rows = manifest::list(r, account, &Host::detect)?;
    let mut account = account.map(str::to_string);
    // Not in the default account: look in each other signed-in account (FR-40: projects
    // may live in different accounts), and use the first one that has a match.
    if account.is_none() && !rows.iter().any(|r| r.tags.contains(&tag)) {
        let accounts = manifest::accounts(r);
        let several = accounts.len() > 1;
        for a in accounts.into_iter().filter(|_| several) {
            let Ok(more) = manifest::list(r, Some(&a.account_uuid), &Host::detect) else {
                continue;
            };
            if more.iter().any(|r| r.tags.contains(&tag)) {
                rows = more;
                account = Some(a.account_uuid);
                break;
            }
        }
    }
    let hits: Vec<&Row> = rows.iter().filter(|r| r.tags.contains(&tag)).collect();
    let found = |row: &Row| {
        Ok(Found::Manifest(ManifestStore::from_row(
            row,
            account.clone(),
            Matched::Repo(repo.to_string()),
        )))
    };
    if hits.is_empty() {
        return Err(not_found(start, Some(repo)));
    }
    let rel = git_toplevel(r).and_then(|top| relative(start, &top));
    let rel = rel.as_deref().unwrap_or("");
    // I1: even the only match is used only when it covers this directory: no path tags
    // (the whole repository) or a path tag that is a prefix of it.
    if let [one] = hits.as_slice() {
        if path_score(&row_paths(one), rel).is_some() {
            return found(one);
        }
        return Err(Error::Config(
            format!(
                "the only manifest matching {repo} does not cover {}: {}",
                if rel.is_empty() {
                    "the repository root"
                } else {
                    rel
                },
                listing_with_paths(&hits)
            )
            .into(),
        )
        .with_code(crate::error::Code::ManifestNotFound)
        .with_next(format!(
            "OPV_PROJECT={} opv <command>",
            project_of(one).unwrap_or("<project>")
        )));
    }
    let scored: Vec<(usize, &Row)> = hits
        .iter()
        .filter_map(|row| path_score(&row_paths(row), rel).map(|s| (s, *row)))
        .collect();
    let best = scored.iter().map(|(s, _)| *s).max();
    let top: Vec<&Row> = scored
        .iter()
        .filter(|(s, _)| Some(*s) == best)
        .map(|(_, r)| *r)
        .collect();
    match top.as_slice() {
        [one] => found(one),
        _ => Err(Error::Config(
            format!(
                "{} manifests match {repo}{}: {}",
                hits.len(),
                if rel.is_empty() {
                    String::new()
                } else {
                    format!(" and none covers {rel} alone")
                },
                listing_with_paths(&hits)
            )
            .into(),
        )
        .with_code(crate::error::Code::ManifestAmbiguous)
        .with_next(format!(
            "OPV_PROJECT={} opv <command>",
            project_of(hits[0]).unwrap_or("<project>")
        ))),
    }
}

/// The score of a manifest with `paths` for the directory `rel` (relative to the repo
/// root, `/`-separated, empty at the root): the length of the longest path that is a
/// whole-segment prefix of `rel` (plus one), `Some(0)` for a manifest without paths, and
/// `None` when it has paths and none covers `rel`.
pub fn path_score(paths: &[String], rel: &str) -> Option<usize> {
    if paths.is_empty() {
        return Some(0);
    }
    paths
        .iter()
        .filter(|p| rel == p.as_str() || rel.starts_with(&format!("{p}/")))
        .map(|p| p.len() + 1)
        .max()
}

/// `start` relative to `top`, `/`-separated (empty at the root); `None` outside it.
fn relative(start: &Path, top: &Path) -> Option<String> {
    let start = fs::canonicalize(start).ok()?;
    let top = fs::canonicalize(top).ok()?;
    let rel = start.strip_prefix(&top).ok()?;
    Some(
        rel.components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/"),
    )
}

/// The paths a manifest row's tags declare.
pub fn row_paths(row: &Row) -> Vec<String> {
    row.tags.iter().filter_map(|t| parse_path_tag(t)).collect()
}

/// The repos a manifest row's tags declare.
pub fn row_repos(row: &Row) -> Vec<String> {
    row.tags.iter().filter_map(|t| parse_repo_tag(t)).collect()
}

/// `"opv · a" in vault V (paths apps/api, apps/web)`, comma-separated.
fn listing_with_paths(rows: &[&Row]) -> String {
    rows.iter()
        .map(|r| {
            let paths = row_paths(r);
            let paths = if paths.is_empty() {
                "whole repository".to_string()
            } else {
                format!("paths {}", paths.join(", "))
            };
            format!("{:?} in vault {} ({paths})", r.title, vault_label(r))
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// `git rev-parse --show-toplevel`; `None` outside a repository or without git.
pub fn git_toplevel(r: &dyn CommandRunner) -> Option<PathBuf> {
    match r.probe(
        &Call::new("git", &["rev-parse", "--show-toplevel"]),
        PROBE_TIMEOUT,
    ) {
        Ok(o) if o.status == 0 => {
            let p = String::from_utf8_lossy(&o.stdout).trim().to_string();
            (!p.is_empty()).then(|| PathBuf::from(p))
        }
        _ => {
            let _ = crate::runner::take_failure_excerpt();
            None
        }
    }
}

/// The tag prefix carrying a monorepo path (`/` replaced by `|`, like [`repo_tag`]).
pub const PATH_TAG_PREFIX: &str = "opv-path:";

/// A repository-relative directory as `a/b` (no leading `./` or `/`, no trailing `/`);
/// `None` for the root or a segment outside `[A-Za-z0-9._-]`, `.` or `..`.
pub fn normalize_path(p: &str) -> Option<String> {
    let p = p.trim().replace('\\', "/");
    let segs: Vec<&str> = p
        .split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();
    let ok = !segs.is_empty()
        && segs.iter().all(|s| {
            *s != ".."
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        });
    ok.then(|| segs.join("/"))
}

/// The tag for a normalized path.
pub fn path_tag(path: &str) -> String {
    format!("{PATH_TAG_PREFIX}{}", path.replace('/', "|"))
}

/// The path a tag names, if it is a path tag.
pub fn parse_path_tag(tag: &str) -> Option<String> {
    let path = tag.strip_prefix(PATH_TAG_PREFIX)?.replace('|', "/");
    (normalize_path(&path).as_deref() == Some(path.as_str())).then_some(path)
}

/// `"opv · a" in vault V (item ID)`, comma-separated.
fn listing(rows: &[&Row]) -> String {
    rows.iter()
        .map(|r| format!("{:?} in vault {} ({})", r.title, vault_label(r), r.id))
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn vault_label(r: &Row) -> &str {
    if r.vault.name.is_empty() {
        &r.vault.id
    } else {
        &r.vault.name
    }
}

/// The project a manifest's title names.
pub fn project_of(r: &Row) -> Option<&str> {
    r.title.strip_prefix("opv · ")
}

/// No configuration anywhere: the first-run router. Starts with [`config::NOT_FOUND`] so
/// `doctor` keys its first-run step on it.
pub fn not_found(start: &Path, repo: Option<&str>) -> Error {
    let manifest = match repo {
        Some(repo) => format!("no 1Password manifest is tagged for {repo}"),
        None => "no git remote to match a 1Password manifest".to_string(),
    };
    Error::Config(
        format!(
            "{}{} or any parent directory, and {manifest}.\n  \
             New project?                    opv init <env> --vault <vault title> --item <item title>\n  \
             Have a secrets.toml elsewhere?  opv config import --file <path> --vault <vault>\n  \
             Manifest for another project?   OPV_PROJECT=<name> opv <command>\n  \
             Configured elsewhere?           opv --config <path> <command>\n  \
             Project ships opv.setup.toml?   opv setup",
            config::NOT_FOUND,
            start.display()
        )
        .into(),
    )
    .with_code(crate::error::Code::ConfigNotFound)
    .with_next("opv init <env> --vault <vault title> --item <item title>")
}

/// `git remote get-url origin`, normalized; `None` without git, a repository or a remote
/// opv can name. The raw URL (which may carry credentials) is never printed or kept.
pub fn git_repo(r: &dyn CommandRunner) -> Option<String> {
    let out = r
        .probe(
            &Call::new("git", &["remote", "get-url", "origin"]),
            PROBE_TIMEOUT,
        )
        .ok();
    match out {
        Some(o) if o.status == 0 => {
            let url = String::from_utf8_lossy(&o.stdout).into_owned();
            normalize_remote(&url)
        }
        _ => {
            // Not a repository, no remote, or no git: its stderr explains nothing later.
            let _ = crate::runner::take_failure_excerpt();
            None
        }
    }
}

/// A git remote URL as `host/owner/repo` (lower case, no user, password, port or `.git`).
///
/// Accepts `https://`, `http://`, `ssh://`, `git://` URLs and scp-like `user@host:path`.
/// Local paths and anything with characters outside `[A-Za-z0-9._-]` in a segment are
/// `None`.
pub fn normalize_remote(url: &str) -> Option<String> {
    let u = url.trim();
    let (authority, path) = match u.split_once("://") {
        Some((scheme, rest)) => {
            let scheme = scheme.to_ascii_lowercase();
            if !matches!(
                scheme.as_str(),
                "https" | "http" | "ssh" | "git" | "git+ssh" | "ssh+git"
            ) {
                return None;
            }
            let (authority, path) = rest.split_once('/')?;
            let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
            (host.split(':').next()?, path)
        }
        None => {
            let colon = u.find(':')?;
            let authority = &u[..colon];
            if authority.contains('/') || authority.contains('\\') {
                return None;
            }
            let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
            (host, &u[colon + 1..])
        }
    };
    let path = path.trim_matches('/');
    let path = path
        .strip_suffix(".git")
        .unwrap_or(path)
        .trim_end_matches('/');
    let segs: Vec<&str> = path.split('/').collect();
    let seg_ok = |s: &&str| {
        !s.is_empty()
            && *s != "."
            && *s != ".."
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    };
    if !seg_ok(&authority) || !authority.contains('.') && authority != "localhost" {
        return None;
    }
    if segs.len() < 2 || !segs.iter().all(seg_ok) {
        return None;
    }
    Some(format!("{authority}/{}", segs.join("/")).to_ascii_lowercase())
}

/// The tag for a normalized repo: `opv-repo:` then the segments joined by `|`. 1Password
/// reads `/` in a tag as nesting and `--tags` splits on `,`; neither appears.
pub fn repo_tag(repo: &str) -> String {
    format!("{REPO_TAG_PREFIX}{}", repo.replace('/', "|"))
}

/// The repo a tag names, if it is a repo tag.
pub fn parse_repo_tag(tag: &str) -> Option<String> {
    let rest = tag.strip_prefix(REPO_TAG_PREFIX)?;
    let repo = rest.replace('|', "/");
    (normalize_remote(&format!("https://{repo}")).as_deref() == Some(repo.as_str())).then_some(repo)
}

/// The project name a new manifest gets: `--project`, else the repo's last segment, else
/// the directory's name.
pub fn default_project(
    given: Option<&str>,
    repo: Option<&str>,
    dir: &Path,
) -> Result<String, Error> {
    let name = given
        .map(str::to_string)
        .or_else(|| repo.and_then(|r| r.rsplit('/').next()).map(str::to_string))
        .or_else(|| {
            dir.file_name()
                .map(|n| n.to_string_lossy().to_ascii_lowercase())
        })
        .unwrap_or_default();
    if is_project_name(&name) {
        Ok(name)
    } else {
        Err(Error::Config(
            format!("project name {name:?} must match ^[A-Za-z0-9][A-Za-z0-9._-]*$").into(),
        )
        .with_next("pass --project <name>"))
    }
}

/// The tags of a new manifest.
pub fn manifest_tags(repo: Option<&str>, paths: &[String]) -> Vec<String> {
    let mut tags = vec![MANIFEST_TAG.to_string()];
    tags.extend(repo.map(repo_tag));
    tags.extend(paths.iter().map(|p| path_tag(p)));
    tags
}

/// Create a manifest for `project` in `vault` holding `text` (validated by the caller),
/// refusing when a manifest for the project or repo already exists (one list call, then
/// one create). Returns the new store.
pub fn create_manifest(
    r: &dyn CommandRunner,
    vault: &str,
    project: &str,
    repo: Option<&str>,
    paths: &[String],
    text: &str,
    account: Option<&str>,
) -> Result<ManifestStore, Error> {
    crate::app::tidy::require_person(r, "this command")?;
    let rows = manifest::list(r, account, &Host::detect)?;
    let title = manifest_title(project);
    let tag = repo.map(repo_tag);
    // The same repo and the same paths (both none: the whole repository) is a duplicate.
    let mut wanted: Vec<String> = paths.to_vec();
    wanted.sort();
    let same_scope = |row: &Row| {
        let mut p = row_paths(row);
        p.sort();
        tag.as_ref().is_some_and(|t| row.tags.contains(t)) && p == wanted
    };
    if let Some(row) = rows.iter().find(|r| r.title == title || same_scope(r)) {
        return Err(Error::Config(
            format!(
                "a manifest for this project already exists: {:?} in vault {} ({})",
                row.title,
                vault_label(row),
                row.id
            )
            .into(),
        )
        .with_code(crate::error::Code::ManifestExists)
        .with_next("opv config edit"));
    }
    let item = manifest::template(&title, project, &manifest_tags(repo, paths), text);
    let row = manifest::create(r, vault, &item, account, &Host::detect)?;
    Ok(ManifestStore::from_row(
        &row,
        account.map(str::to_string),
        Matched::Given,
    ))
}

#[cfg(test)]
#[path = "config_store_tests.rs"]
mod tests;
