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
//! The manifest holds names, IDs and rules, never a value. D-G: its contract block holds no
//! id; the ids live in a second block tagged `toml opv-bindings`, which the store reads and
//! fills in like a file project's `secrets.bindings.toml`, and which `opv apply` writes
//! ([`ManifestStore::write_bindings`]).

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::adapters::onepassword_manifest::{self as manifest, MANIFEST_TAG, Row};
use crate::cause::{
    AccountId, AccountSource, Cause, ConfigSource, DottedPath, FieldRule, GivenBy, IoKind, LocalOp,
    Location, PatternId, StoreObject, UsageProblem, VarName, VaultId,
};
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
    /// Where it is, as the error catalog names it (X16: messages are source-aware).
    fn cause_source(&self) -> ConfigSource {
        match self.source() {
            config::Source::File(path) => ConfigSource::File {
                path: path.to_path_buf(),
                given_by: GivenBy::Discovered,
            },
            config::Source::Manifest(title) => ConfigSource::Manifest {
                title: title.to_string(),
                vault: VaultId::new(""),
                project: title.strip_prefix("opv · ").unwrap_or(title).to_string(),
            },
            config::Source::ManifestIn { title, vault } => ConfigSource::Manifest {
                title: title.to_string(),
                vault: VaultId::new(vault),
                project: title.strip_prefix("opv · ").unwrap_or(title).to_string(),
            },
        }
    }
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
        Replaced::Changed(_) => Err(Cause::ChangedBeforeWrite {
            object: store_object(&store.cause_source()),
        }
        .into()),
    }
}

/// The object a configuration edit can conflict on.
pub fn store_object(source: &ConfigSource) -> StoreObject {
    match source {
        ConfigSource::File { path, .. } => StoreObject::File { path: path.clone() },
        ConfigSource::Manifest { title, vault, .. } => StoreObject::Manifest {
            title: title.clone(),
            vault: vault.clone(),
        },
    }
}

/// A file that could not be read, as the catalog's `ConfigUnreadable`.
pub(crate) fn unreadable(path: &Path, e: &std::io::Error, given_by: GivenBy) -> Error {
    Cause::ConfigUnreadable {
        path: path.to_path_buf(),
        io: e.kind().into(),
        given_by,
    }
    .into()
}

/// The 1-based line and column of the start of `at` in `text`.
pub(crate) fn location(text: &str, at: Option<std::ops::Range<usize>>) -> Option<Location> {
    let at = at?.start.min(text.len());
    let before = text.get(..at)?;
    let line = before.matches('\n').count() + 1;
    let col = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
    Some(Location {
        line: u32::try_from(line).ok()?,
        col: u32::try_from(col).ok()?,
    })
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

    /// The contract with its sibling `secrets.bindings.toml` filled in (D-G): an edit sees the
    /// ids where it did before they moved out, and [`replace`](Self::replace) moves them back.
    /// An inline id is refused, as at load.
    fn read(&self, _: &dyn CommandRunner) -> Result<Snapshot, Error> {
        Ok(Snapshot {
            text: config::read_merged(&self.path)?,
            version: None,
        })
    }

    /// The contract as written, without its ids (D-G): an edit never sees, moves or writes
    /// an id; only `opv apply` writes `secrets.bindings.toml`.
    fn read_for_write(&self, _: &dyn CommandRunner) -> Result<Snapshot, Error> {
        Ok(Snapshot {
            text: fs::read_to_string(&self.path)
                .map_err(|e| unreadable(&self.path, &e, GivenBy::Discovered))?,
            version: None,
        })
    }

    /// Replace the contract with `text` if it is still at `base` (a
    /// [`read_for_write`](Self::read_for_write) snapshot). D-G: `text` carrying an inline id
    /// is refused `config_invalid` naming the field, and the bindings file is never written.
    /// Atomic (temporary file, then rename), symlinks followed, permissions kept, and
    /// compared once more right before the rename.
    fn replace(
        &self,
        r: &dyn CommandRunner,
        base: &Snapshot,
        text: &str,
    ) -> Result<Replaced, Error> {
        let now = self.read_for_write(r)?;
        if now.text != base.text {
            return Ok(Replaced::Changed(now));
        }
        config::bindings::refuse_inline(text)?;
        match crate::config_edit::replace(&self.path, &now.text, text) {
            Ok(()) => Ok(Replaced::Saved),
            Err(e) => match self.read_for_write(r) {
                Ok(now) if now.text != base.text => Ok(Replaced::Changed(now)),
                _ => Err(e),
            },
        }
    }

    fn source(&self) -> config::Source<'_> {
        config::Source::File(&self.path)
    }

    /// [`config::parse_at`]; for the text [`read`](Self::read) gives, an error names the line
    /// of the contract as written, not of the text with its ids filled in (D-G).
    fn parse(&self, text: &str) -> Result<Fleet, Error> {
        let raw = fs::read_to_string(&self.path).ok();
        if let Some(raw) = raw
            && config::with_bindings(&raw, &self.path).is_ok_and(|merged| merged == text)
        {
            let mut fleet = config::parse_file(&raw, &self.path, GivenBy::Discovered)?;
            fleet.read_from.0 = self.cause_source();
            return Ok(fleet);
        }
        config::parse_at(text, self.source())
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

    /// The text the commands edit and load: the contract block with the `opv-bindings`
    /// block's ids filled in (D-G), as a file project's contract and sibling. An inline id in
    /// the contract block is refused naming the field.
    fn snapshot(&self, m: &manifest::Manifest) -> Result<Snapshot, Error> {
        Ok(Snapshot {
            text: config::bindings::merge_manifest(
                &m.text,
                m.bindings.as_deref(),
                &self.cause_source(),
            )?,
            version: Some(m.version),
        })
    }

    /// The ids of the manifest's `opv-bindings` block (D-G); none before the first
    /// `opv apply`.
    pub fn read_bindings(
        &self,
        r: &dyn CommandRunner,
    ) -> Result<config::bindings::Bindings, Error> {
        let m = self.read_item(r, false)?;
        config::bindings::parse_block(m.bindings.as_deref(), &self.cause_source())
    }

    /// `opv apply`'s writer (D-G): replace the `opv-bindings` block with `ids` and, for the
    /// one-time move, the contract block with `contract` (which must hold no id). Text a
    /// person wrote around the blocks is kept. Refused unless a person runs opv (I3); built
    /// on a read past `op`'s cache (C1) and checked afterwards (I5).
    pub fn write_bindings(
        &self,
        r: &dyn CommandRunner,
        contract: Option<&str>,
        ids: &config::bindings::Bindings,
    ) -> Result<(), Error> {
        crate::app::tidy::require_person(r, "this command")?;
        let now = self.read_item(r, true)?;
        let contract = match contract {
            Some(text) => {
                config::bindings::merge_manifest(text, None, &self.cause_source())?;
                text.to_string()
            }
            None => now.text.clone(),
        };
        let written = manifest::edit(
            r,
            &self.vault_id,
            &self.item_id,
            &now.raw,
            &contract,
            Some(&ids.render()),
            self.account.as_deref(),
            &Host::detect,
        )?;
        self.confirm(r, now.version, written, &contract, ids)
    }

    /// The manifest read with its ids left inline in the contract block, returning the fleet
    /// and the ids to move into the `opv-bindings` block (D-G; `opv propose structure`): the
    /// manifest's [`config::load_for_move`], and the only manifest reader that accepts
    /// inline ids.
    pub fn read_for_move(
        &self,
        r: &dyn CommandRunner,
    ) -> Result<(Fleet, config::bindings::Bindings), Error> {
        let m = self.read_item(r, false)?;
        let mut fleet = config::parse_at(&m.text, self.source())?;
        fleet.origin = crate::domain::Origin::Manifest;
        let ids = config::bindings::inline_ids(&m.text).map_err(|_| {
            Error::from(Cause::Bug {
                site: "config_store: a parsed manifest contract whose ids do not read",
            })
        })?;
        Ok((fleet, ids))
    }

    /// The contract block as written (any inline id left in) and the ids of the
    /// `opv-bindings` block: the two texts `opv propose structure` splits for the one-time
    /// move (D-G). Read past `op`'s cache (C1): `opv apply` writes the move from it.
    /// Nothing is refused here; the move itself is confirmed by
    /// [`read_for_move`](Self::read_for_move).
    /// The contract block with the `opv-bindings` block's ids filled in, read past `op`'s
    /// cache and refused unless a person runs opv (I3): the text `opv apply` plans and
    /// checks its writes against. An edit starts from [`ConfigStore::read_for_write`]
    /// instead, which holds no id (D-G).
    pub fn read_merged_fresh(&self, r: &dyn CommandRunner) -> Result<String, Error> {
        crate::app::tidy::require_person(r, "this command")?;
        let m = self.read_item(r, true)?;
        Ok(self.snapshot(&m)?.text)
    }

    pub fn read_for_proposal(
        &self,
        r: &dyn CommandRunner,
    ) -> Result<(String, config::bindings::Bindings), Error> {
        let m = self.read_item(r, true)?;
        let ids = config::bindings::parse_block(m.bindings.as_deref(), &self.cause_source())?;
        Ok((m.text, ids))
    }

    /// I5: after the edit, the manifest must be exactly one version past the read it was
    /// built from and hold `text` and `ids`; otherwise another edit landed in between (one
    /// of the two was lost). Reported, never retried.
    fn confirm(
        &self,
        r: &dyn CommandRunner,
        built_on: u64,
        written: manifest::Written,
        text: &str,
        ids: &config::bindings::Bindings,
    ) -> Result<(), Error> {
        let (version, now, block) = match written {
            manifest::Written {
                version: Some(v),
                text: Some(t),
                bindings: Some(b),
            } => (v, t, b),
            _ => {
                let m = self.read_item(r, true)?;
                (m.version, m.text, m.bindings)
            }
        };
        let ids_now = config::bindings::parse_block(block.as_deref(), &self.cause_source()).ok();
        let expected = built_on + 1;
        if version == expected && now == text && ids_now.as_ref() == Some(ids) {
            return Ok(());
        }
        // Another edit landed with opv's (a version other than `expected`); opv did not
        // retry. The catalog asks a person to check the manifest's history.
        Err(Cause::ConcurrentEdit {
            object: store_object(&self.cause_source()),
        }
        .into())
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

    /// The contract block with the `opv-bindings` block's ids filled in (D-G): an edit sees
    /// the ids as a file project's does, and [`replace`](Self::replace) moves them back. An
    /// inline id in the contract block is refused, as at load.
    fn read(&self, r: &dyn CommandRunner) -> Result<Snapshot, Error> {
        let m = self.read_item(r, false)?;
        self.snapshot(&m)
    }

    /// The contract block alone (D-G): an edit never sees, moves or writes an id; only
    /// `opv apply` writes the `opv-bindings` block.
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
    /// re-read and the write is detected afterwards and reported, not prevented). D-G:
    /// `text` is the contract block; one carrying an inline id is refused `config_invalid`
    /// naming the field, and the `opv-bindings` block is kept as it is (only `opv apply`
    /// writes it).
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
        config::bindings::refuse_inline_into(text, config::bindings::MANIFEST_HOME)?;
        let ids = config::bindings::parse_block(now.bindings.as_deref(), &self.cause_source())?;
        let written = manifest::edit(
            r,
            &self.vault_id,
            &self.item_id,
            &now.raw,
            text,
            None,
            self.account.as_deref(),
            &Host::detect,
        )?;
        self.confirm(r, now.version, written, text, &ids)?;
        Ok(Replaced::Saved)
    }
    // C12: the manifest by title and vault, so its errors name the vault it lives in.
    fn source(&self) -> config::Source<'_> {
        config::Source::ManifestIn {
            title: &self.title,
            vault: &self.vault_id,
        }
    }

    fn cause_source(&self) -> ConfigSource {
        ConfigSource::Manifest {
            title: self.title.clone(),
            vault: VaultId::new(self.vault_id.clone()),
            project: self
                .title
                .strip_prefix("opv · ")
                .unwrap_or(&self.title)
                .to_string(),
        }
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

    /// The `using …` line for stderr, or `None` for a path given with `--config`, and for a
    /// manifest found the usual way (git remote, `.opv`) unless `verbose`: it is the same on
    /// every run, and a person saw it repeated on every command (found live). An
    /// environment variable's choice (`OPV_CONFIG`, `OPV_PROJECT`) is always named.
    pub fn announce(&self, verbose: bool) -> Option<String> {
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
            Found::Manifest(m)
                if !verbose && matches!(m.matched, Matched::Repo(_) | Matched::DotFile(_)) =>
            {
                None
            }
            Found::Manifest(m) => Some(format!("using {}", m.describe())),
        }
    }

    /// Read and validate the configuration. A manifest found in a given account (a `.opv`
    /// pointer, `OP_ACCOUNT` or the multi-account search) passes that account to every
    /// environment that names none of its own (I2), so the environments' item reads go to
    /// the account the manifest lives in.
    pub fn load(&self, r: &dyn CommandRunner) -> Result<Fleet, Error> {
        let snap = self.store().read(r).map_err(|e| self.given_by(e))?;
        let mut fleet = parse_from(self, &snap.text)?;
        // The account the configuration came from (a manifest's), or for a file the
        // account recorded in the nearest `.opv` (FR-40): environments naming none use it.
        let (account, account_from) = match self {
            Found::Manifest(ManifestStore {
                account: Some(a), ..
            }) => (Some(a.clone()), None),
            Found::File { store, .. } if Host::detect().op_credential.is_none() => {
                match store.path.parent() {
                    Some(parent) => (pointer_account(parent), find_dot_opv(parent)),
                    None => (None, None),
                }
            }
            _ => (None, None),
        };
        if let Some(a) = account {
            for env in fleet.environments.values_mut() {
                // An account the configuration itself declares keeps its environment origin;
                // one taken from the `.opv` records that file so the diagnosis can name it.
                if env.account.is_none() {
                    env.account = Some(a.clone());
                    env.account_from = account_from.clone();
                }
            }
        }
        Ok(fleet)
    }
}

impl Found {
    /// How the file was named (`--config`, `OPV_CONFIG` or discovery), as the catalog says it.
    fn given(&self) -> GivenBy {
        match self {
            Found::File {
                given: Some(Given::Flag),
                ..
            } => GivenBy::Flag {
                flag: "--config".into(),
            },
            Found::File {
                given: Some(Given::Env),
                ..
            } => GivenBy::EnvVar {
                var: VarName::new("OPV_CONFIG"),
            },
            _ => GivenBy::Discovered,
        }
    }

    /// `e` naming the flag or variable that gave an unreadable file (03.12).
    fn given_by(&self, e: Error) -> Error {
        match e.cause() {
            Some((Cause::ConfigUnreadable { path, io, .. }, None)) => Cause::ConfigUnreadable {
                path: path.clone(),
                io: *io,
                given_by: self.given(),
            }
            .into(),
            _ => e,
        }
    }

    /// Where the configuration is, as the catalog names it.
    pub fn cause_source(&self) -> ConfigSource {
        match self.store().cause_source() {
            ConfigSource::File { path, .. } => ConfigSource::File {
                path,
                given_by: self.given(),
            },
            m => m,
        }
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
    /// The project's manifest title; without it, the manifest is found by the git remote
    /// in `account` (a pointer that only picks the account, as `opv login --account` writes).
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub account: Option<String>,
}

/// Parse a `.opv` file's text.
pub fn parse_dot_opv(text: &str, path: &Path) -> Result<DotOpv, Error> {
    let invalid = |at: Option<Location>, field: &str, rule: FieldRule| -> Error {
        Cause::ConfigInvalid {
            source: ConfigSource::File {
                path: path.to_path_buf(),
                given_by: GivenBy::Discovered,
            },
            at,
            field: DottedPath(vec![field.to_string()]),
            rule,
        }
        .into()
    };
    let d: DotOpv = toml::from_str(text).map_err(|e| {
        // The pointer holds `project = "<name>"` and/or `account = "<account>"` only.
        let at = location(text, e.span());
        if e.message().starts_with("unknown field") {
            invalid(at, "the pointer", FieldRule::Unknown { suggestion: None })
        } else {
            invalid(at, "the pointer", FieldRule::Syntax)
        }
    })?;
    if let Some(project) = &d.project
        && !is_project_name(project)
    {
        return Err(invalid(
            None,
            "project",
            FieldRule::Pattern { id: PatternId::Id },
        ));
    }
    // M5: the account reaches `op` as `--account <account>`: a sign-in address, email or
    // account ID only, never something `op` could read as a flag.
    if let Some(a) = &d.account
        && !config::is_account(a)
    {
        return Err(invalid(
            None,
            "account",
            FieldRule::Pattern {
                id: PatternId::Account,
            },
        ));
    }
    Ok(d)
}

/// The account named by the nearest `.opv` pointer, if any (read without any `op` call,
/// for `opv login` before a manifest can be read).
pub fn pointer_account(start: &Path) -> Option<String> {
    let path = find_dot_opv(start)?;
    let text = fs::read_to_string(&path).ok()?;
    parse_dot_opv(&text, &path).ok()?.account
}

/// Record `account` (an account ID) as this checkout's 1Password account: in the nearest
/// `.opv` up to the repository root, keeping its `project`, or in a new `.opv` at the
/// repository root (or `start` outside a repository). Returns the file written. It holds an
/// ID, never a secret, and is meant to be committed so every checkout uses the same account.
///
/// A cloned repository is untrusted, so the file is never written through a symlink, an
/// existing `.opv` that does not parse is refused rather than replaced, and nothing above
/// the repository root is touched.
pub fn record_account(start: &Path, account: &str) -> Result<PathBuf, Error> {
    let root = repo_root(start).unwrap_or(start);
    let path = start
        .ancestors()
        .scan(false, |past_root, d| {
            (!*past_root).then(|| {
                *past_root = d == root;
                d.join(DOT_FILE)
            })
        })
        .find(|p| p.symlink_metadata().is_ok())
        .unwrap_or_else(|| root.join(DOT_FILE));
    // opv's own local write (A3): what failed, never the OS error's own text.
    let refuse = |op: LocalOp, io: IoKind| -> Error {
        Cause::LocalIo {
            op,
            path: path.clone(),
            io,
        }
        .into()
    };
    let project = match path.symlink_metadata() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(refuse(LocalOp::Read, e.kind().into())),
        // A symlink or another kind of file: opv only writes a plain .opv, never through it.
        Ok(m) if !m.file_type().is_file() => {
            return Err(refuse(LocalOp::Write, IoKind::NotAPlainFile));
        }
        Ok(_) => {
            let text =
                fs::read_to_string(&path).map_err(|e| refuse(LocalOp::Read, e.kind().into()))?;
            parse_dot_opv(&text, &path)?.project
        }
    };
    let mut text = String::from(
        "# opv: this project's 1Password account (an ID, not a secret). Commit this file.\n",
    );
    if let Some(p) = project {
        text.push_str(&format!("project = \"{p}\"\n"));
    }
    text.push_str(&format!("account = \"{account}\"\n"));
    write_no_follow(&path, &text).map_err(|e| refuse(LocalOp::Write, e.kind().into()))?;
    Ok(path)
}

/// Write `text` to `path`, refusing (rather than following) a symlink put there since the
/// check above.
fn write_no_follow(path: &Path, text: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(path)?.write_all(text.as_bytes())
}

/// The repository root holding `start`: the nearest ancestor (or `start` itself) with a
/// `.git` directory or file (a worktree or submodule), the directory `git rev-parse
/// --show-toplevel` names, found without running git. `None` outside a repository.
pub fn repo_root(start: &Path) -> Option<&Path> {
    start.ancestors().find(|d| d.join(".git").exists())
}

/// The `.opv` pointer for `start` (design §12.4, owner decision): the nearest one from
/// `start` up to and including the repository root, never above it; outside a repository,
/// only `start` itself. A `.opv` left in a parent such as `/tmp` or `$HOME` never selects
/// a checkout's account or project (09.08).
pub fn find_dot_opv(start: &Path) -> Option<PathBuf> {
    let root = repo_root(start).unwrap_or(start);
    let mut past_root = false;
    start
        .ancestors()
        .take_while(|d| {
            let keep = !past_root;
            past_root = past_root || *d == root;
            keep
        })
        .take_while(|d| hermetic(d))
        .map(|d| d.join(DOT_FILE))
        .find(|p| p.is_file())
}

/// The nearest file named `name` in `start` or a parent.
pub fn walk_up(start: &Path, name: &str) -> Option<PathBuf> {
    start
        .ancestors()
        .take_while(|d| hermetic(d))
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

/// Test builds never look at or above the system temp directory: a `.opv` or
/// `secrets.toml` a developer left in `/tmp` must not reach a test's scratch directory
/// (found: a stray `/tmp/.opv` failed login and discovery tests on one machine only). Nor
/// at this checkout, where unit tests run: a developer's own `.opv` there selected a real
/// account in tests that select none (found: access tests passed only without one).
#[cfg(test)]
pub(crate) fn hermetic(dir: &Path) -> bool {
    let tmp = std::env::temp_dir();
    let tmp = tmp.canonicalize().unwrap_or(tmp);
    let here = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
    let checkout = Path::new(env!("CARGO_MANIFEST_DIR"));
    let checkout = checkout
        .canonicalize()
        .unwrap_or_else(|_| checkout.to_path_buf());
    here != tmp && !tmp.starts_with(&here) && !checkout.starts_with(&here)
}

#[cfg(not(test))]
pub(crate) fn hermetic(_: &Path) -> bool {
    true
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
        let account = pick_account_at(r, req.account.clone(), &req.start)?;
        return by_project(r, project, account, Matched::ProjectEnv);
    }
    if !req.manifest_only
        && let Some(path) = config::discover(&req.start)
    {
        return Ok(Found::File {
            store: FileStore { path },
            given: None,
        });
    }
    if let Some(path) = find_dot_opv(&req.start) {
        let text =
            fs::read_to_string(&path).map_err(|e| unreadable(&path, &e, GivenBy::Discovered))?;
        let dot = parse_dot_opv(&text, &path)?;
        // One order everywhere (0.9.0): OP_ACCOUNT (which `opv login --account` sets for its
        // command) before the checkout's .opv.
        let account = pick_account_at(r, req.account.clone().or(dot.account), &req.start)?;
        if let Some(project) = &dot.project {
            return by_project(r, project, account, Matched::DotFile(path));
        }
        return match git_repo(r) {
            Some(repo) => by_repo(r, &repo, &req.start, account.as_deref()),
            None => Err(not_found(&req.start, None, None)),
        };
    }
    match git_repo(r) {
        Some(repo) => {
            let account = pick_account_at(r, req.account.clone(), &req.start)?;
            by_repo(r, &repo, &req.start, account.as_deref())
        }
        None => Err(not_found(&req.start, None, None)),
    }
}

/// The account value that selects this project's 1Password account, in the one order every
/// command uses (0.9.0): `OP_ACCOUNT` (which `opv login --account` sets for its command),
/// else the nearest `.opv`. `None` under a service-account or Connect credential, which
/// decides the account itself.
pub fn selected_account(start: &Path) -> Option<String> {
    if Host::detect().op_credential.is_some() {
        return None;
    }
    account_env().or_else(|| pointer_account(start))
}

/// [`selected_account`] as an account ID: a value that is not one (an email, a shorthand,
/// a sign-in address) is resolved once against the accounts op knows, so `op` never picks
/// one of several accounts on a shared address. An ambiguous or unknown value is refused
/// with the candidates; no selection stays `None` (op's own choice).
pub fn selected_account_id(r: &dyn CommandRunner, start: &Path) -> Result<Option<String>, Error> {
    let Some(given) = selected_account(start) else {
        return Ok(None);
    };
    let is_uuid = given.len() == 26
        && given
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
    if is_uuid {
        return Ok(Some(given));
    }
    let accounts = manifest::accounts(r);
    if accounts.is_empty() {
        return Ok(Some(given));
    }
    manifest::resolve_from(&accounts, &given, account_source(&given, start)).map(Some)
}

/// Where the account value `given` was chosen (C20): `OP_ACCOUNT` when it holds that value,
/// else the `.opv` pointer for `start` that names it; anything else came from `--account`.
fn account_source(given: &str, start: &Path) -> AccountSource {
    if account_env().is_some_and(|a| a == given) {
        return AccountSource::EnvVar {
            var: VarName::new("OP_ACCOUNT"),
        };
    }
    match find_dot_opv(start) {
        Some(path) if pointer_account(start).is_some_and(|a| a == given) => {
            AccountSource::DotOpv { path }
        }
        _ => AccountSource::Flag,
    }
}

/// The 1Password account every manifest call of this run uses (NR-7: never op's default
/// when it could be the wrong one). A given account (`.opv`, `OP_ACCOUNT`) that is not
/// already an account ID is resolved to one (`op` takes no email; a sign-in address can be
/// shared by several accounts). Without one: the only account op knows, or, when there are
/// several, `account_required` listing them; opv never searches them all (found live: each
/// search asked the 1Password app about an account this project was never pointed at).
/// A service-account or Connect credential decides the account itself: `None`.
pub fn pick_account(r: &dyn CommandRunner, given: Option<String>) -> Result<Option<String>, Error> {
    pick_account_at(r, given, &std::env::current_dir().unwrap_or_default())
}

/// [`pick_account`] for the checkout at `start`, whose `.opv` may be where `given` came from.
fn pick_account_at(
    r: &dyn CommandRunner,
    given: Option<String>,
    start: &Path,
) -> Result<Option<String>, Error> {
    // A credential decides the account: no `--account` beside it (0.9.0, as documented).
    if Host::detect().op_credential.is_some() {
        return Ok(None);
    }
    let is_uuid = |a: &str| {
        a.len() == 26
            && a.bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    };
    if let Some(a) = &given
        && is_uuid(a)
    {
        return Ok(given);
    }
    let accounts = manifest::accounts(r);
    match (given, accounts.as_slice()) {
        // op knows no account list here (or it failed): leave the choice to op.
        (given, []) => Ok(given),
        (Some(a), all) => manifest::resolve_from(all, &a, account_source(&a, start)).map(Some),
        (None, [one]) => Ok(Some(one.account_uuid.clone())),
        (None, all) => Err(manifest::choose_error(all)),
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
        return Err(match &matched {
            Matched::DotFile(path) => Cause::ConfigInvalid {
                source: ConfigSource::File {
                    path: path.clone(),
                    given_by: GivenBy::Discovered,
                },
                at: None,
                field: DottedPath(vec!["project".into()]),
                rule: FieldRule::Pattern { id: PatternId::Id },
            },
            Matched::ProjectEnv => project_usage("OPV_PROJECT"),
            Matched::Repo(_) | Matched::Given => project_usage("--project"),
        }
        .into());
    }
    let rows = manifest::list(r, account.as_deref(), &Host::detect)?;
    let title = manifest_title(project);
    let hits: Vec<&Row> = rows.iter().filter(|r| r.title == title).collect();
    match hits.as_slice() {
        [one] => Ok(Found::Manifest(ManifestStore::from_row(
            one, account, matched,
        ))),
        // 03.10: the likely causes are a misspelt name or another account; `opv projects`
        // lists what this account can see. Never `config import` (it needs a file).
        [] => Err(Cause::ManifestNotFound {
            project: project.to_string(),
            account: account.map(AccountId::new),
        }
        .into()),
        // Several manifests share the title: a person keeps one and archives the others.
        many => Err(Cause::ManifestAmbiguous {
            candidates: many.iter().map(|r| listing(&[*r])).collect(),
            person_picks: true,
        }
        .into()),
    }
}

/// A project name given by `flag` (or variable) that is not one.
fn project_usage(flag: &str) -> Cause {
    Cause::Usage {
        problem: UsageProblem::ValueFormat {
            flag: flag.to_string(),
            format: "a project name: letters, digits, ., _ and -, starting with a letter or \
                     digit, at most 64 characters",
        },
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
    // Only the chosen account is searched ([`pick_account`]); never every account.
    let rows = manifest::list(r, account, &Host::detect)?;
    let account = account.map(str::to_string);
    let hits: Vec<&Row> = rows.iter().filter(|r| r.tags.contains(&tag)).collect();
    let found = |row: &Row| {
        Ok(Found::Manifest(ManifestStore::from_row(
            row,
            account.clone(),
            Matched::Repo(repo.to_string()),
        )))
    };
    if hits.is_empty() {
        return Err(not_found(start, Some(repo), account.as_deref()));
    }
    let rel = git_toplevel(r).and_then(|top| relative(start, &top));
    let rel = rel.as_deref().unwrap_or("");
    // I1: even the only match is used only when it covers this directory: no path tags
    // (the whole repository) or a path tag that is a prefix of it.
    if let [one] = hits.as_slice() {
        if path_score(&row_paths(one), rel).is_some() {
            return found(one);
        }
        // 03.09: nothing to archive; the person points this directory at a project. Never
        // a guessed `OPV_PROJECT=<first match>` (X2).
        return Err(path_undecided(&hits));
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
        _ => Err(path_undecided(&hits)),
    }
}

/// The repository's manifests, whose path tags do not decide this directory (03.09): no
/// person-only pick between duplicates, and never a guessed first match (X2).
fn path_undecided(hits: &[&Row]) -> Error {
    Cause::ManifestAmbiguous {
        candidates: hits.iter().map(|r| listing_with_paths(&[*r])).collect(),
        person_picks: false,
    }
    .into()
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

/// No configuration anywhere, and no manifest for this checkout (the catalog's
/// `ConfigNotFound`).
pub fn not_found(start: &Path, repo: Option<&str>, account: Option<&str>) -> Error {
    // C16: no environment is guessed (`opv init dev` was one); a command naming one gets
    // `opv init <env>` from `main`. 03.20: only the selected account was searched; say so.
    crate::cause::Cause::ConfigNotFound {
        searched_from: start.to_path_buf(),
        env: None,
        manifest: Some(crate::cause::ManifestSearch {
            repo: repo.map(str::to_string),
            account: account.map(crate::cause::AccountId::new),
        }),
    }
    .into()
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
        Err(project_usage("--project").into())
    }
}

/// The tags of a new manifest.
pub fn manifest_tags(repo: Option<&str>, paths: &[String]) -> Vec<String> {
    let mut tags = vec![MANIFEST_TAG.to_string()];
    tags.extend(repo.map(repo_tag));
    tags.extend(paths.iter().map(|p| path_tag(p)));
    tags
}

/// Create a manifest for `project` in `vault` holding `text` (validated by the caller; its
/// ids go to the `opv-bindings` block, D-G), refusing when a manifest for the project or
/// repo already exists (one list call, then one create). Returns the new store.
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
        return Err(Cause::ManifestExists {
            title: listing(&[row]),
            local_file: None,
        }
        .into());
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
