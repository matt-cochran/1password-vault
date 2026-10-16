//! Configuration commands for a project whose configuration lives in 1Password or in a
//! file (FR-44): `config import`, `config export`, `config edit`, `config check`,
//! `projects` and `status --all`.
//!
//! The configuration holds names, IDs and rules, never a value; these commands print it,
//! diff it and send it to `op` on stdin only (SR-3). Reads go through the runner with its
//! retries; writes are never retried.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::json;

use super::{status, write_err};
use crate::adapters::onepassword_manifest::{self as manifest, Row};
use crate::cause::{AccountId, Cause, Cmd, GivenBy, UsageProblem};
use crate::config;
use crate::config_store::{
    self as store, ConfigStore, Found, ManifestStore, Matched, Replaced, Snapshot,
};
use crate::error::Error;
use crate::host::Host;
use crate::runner::CommandRunner;

fn line(out: &mut dyn Write, s: impl AsRef<str>) -> Result<(), Error> {
    writeln!(out, "{}", s.as_ref()).map_err(write_err)
}

/// opv's own failure at `site` (never the person's).
fn bug(site: &'static str) -> Error {
    Cause::Bug { site }.into()
}

/// A file named with `--file` that could not be read.
fn unreadable_file(path: &Path, e: &std::io::Error) -> Error {
    Cause::ConfigUnreadable {
        path: path.to_path_buf(),
        io: e.kind().into(),
        given_by: GivenBy::Flag {
            flag: "--file".into(),
        },
    }
    .into()
}

/// A typed `opv …` command line for a success-path `Next:` (design §10.1).
fn next_line(command: &[&str], args: &[&str]) -> String {
    let c = Cmd {
        command: command.iter().map(|w| w.to_string()).collect(),
        args: args.iter().map(|a| a.to_string()).collect(),
    };
    format!("Next: {}", crate::cause::render::cmd_text(&c))
}

/// `config export` output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Toml,
    Json,
}

/// `config export [--toml|--json]`: the configuration itself (no secrets), validated. TOML
/// is printed byte for byte as stored.
pub fn export(
    found: &Found,
    format: Format,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let snap = found.store().read(r)?;
    store::parse_from(found, &snap.text)?;
    match format {
        Format::Toml => out.write_all(snap.text.as_bytes()).map_err(write_err),
        Format::Json => {
            // The text was just validated as TOML: a failure here is opv's bug.
            let v: toml::Value =
                toml::from_str(&snap.text).map_err(|_| bug("config export: parse"))?;
            let s =
                serde_json::to_string_pretty(&v).map_err(|_| bug("config export: serialize"))?;
            line(out, s)
        }
    }
}

/// `config import` arguments.
#[derive(Debug, Clone)]
pub struct ImportArgs {
    pub file: PathBuf,
    pub vault: String,
    pub project: Option<String>,
    /// `--path` (repeatable): monorepo directories, relative to the repository root.
    pub paths: Vec<String>,
}

/// `config import`: validate the file, create the manifest tagged with the git remote (and
/// paths), and say how to retire the file. Never deletes it.
pub fn import(
    args: &ImportArgs,
    dir: &Path,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let text = fs::read_to_string(&args.file).map_err(|e| unreadable_file(&args.file, &e))?;
    config::parse_at(&text, config::Source::File(&args.file))?;
    let paths = normalize_paths(&args.paths)?;
    let repo = store::git_repo(r);
    if repo.is_none() && !paths.is_empty() {
        return Err(Cause::Usage {
            problem: UsageProblem::NeedsFlag {
                flag: "--path".into(),
                needs: "a git remote origin to be relative to, and none was found".into(),
            },
        }
        .into());
    }
    let project = store::default_project(args.project.as_deref(), repo.as_deref(), dir)?;
    let m = store::create_manifest(
        r,
        &args.vault,
        &project,
        repo.as_deref(),
        &paths,
        &text,
        None,
    )
    .map_err(|e| with_local_copy(e, &args.file))?;
    line(out, format!("created {}", m.describe()))?;
    match &repo {
        Some(repo) => {
            let scope = if paths.is_empty() {
                String::new()
            } else {
                format!(" under {}", paths.join(", "))
            };
            line(
                out,
                format!(
                    "tagged for {repo}{scope}: opv finds it in any checkout once the file is gone"
                ),
            )?;
        }
        None => line(
            out,
            format!(
                "no git remote origin: point a checkout at it with OPV_PROJECT={project} or a \
                 .opv file holding project = \"{project}\""
            ),
        )?,
    }
    line(
        out,
        format!(
            "{} still wins while it exists; compare, then delete it yourself",
            args.file.display()
        ),
    )?;
    // The typed Next compares the copy with the new manifest (§10.1); without a git remote
    // the checkout finds the manifest only through the pointer named above.
    let file = args.file.display().to_string();
    if repo.is_none() {
        line(
            out,
            format!("Do: write project = \"{project}\" in .opv (or set OPV_PROJECT={project})"),
        )?;
    }
    line(out, next_line(&["config", "check"], &["--file", &file]))
}

/// `e` naming the local copy beside an existing manifest (03.11): the step then compares
/// the two instead of editing the copy.
fn with_local_copy(e: Error, file: &Path) -> Error {
    match e.cause() {
        Some((Cause::ManifestExists { title, .. }, None)) => Cause::ManifestExists {
            title: title.clone(),
            local_file: Some(file.to_path_buf()),
        }
        .into(),
        _ => e,
    }
}

/// Normalize `--path` values; an invalid one is a configuration error.
fn normalize_paths(given: &[String]) -> Result<Vec<String>, Error> {
    let mut paths = Vec::new();
    for p in given {
        let n = store::normalize_path(p).ok_or_else(|| -> Error {
            Cause::Usage {
                problem: UsageProblem::ValueFormat {
                    flag: "--path".into(),
                    format: "a directory below the repository root, each part made of \
                             letters, digits, ., _ and -",
                },
            }
            .into()
        })?;
        if !paths.contains(&n) {
            paths.push(n);
        }
    }
    Ok(paths)
}

/// `config check --file <path>`: exit 8 with a diff when the file differs from the
/// manifest (line endings aside).
pub fn check(
    found: &Found,
    file: &Path,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let committed = fs::read_to_string(file).map_err(|e| unreadable_file(file, &e))?;
    // The file must be a configuration before any of it is printed as a diff: a `.env`
    // given by mistake would otherwise reach stdout line by line (C1, SR-1).
    config::parse_at(&committed, config::Source::File(file))?;
    let current = found.store().read(r)?;
    let (a, b) = (
        current.text.replace("\r\n", "\n"),
        committed.replace("\r\n", "\n"),
    );
    if a.trim_end() == b.trim_end() {
        return line(
            out,
            format!("{} matches {}", file.display(), found.store().describe()),
        );
    }
    line(
        out,
        format!("--- {}\n+++ {}", found.store().describe(), file.display()),
    )?;
    out.write_all(diff(&a, &b).as_bytes()).map_err(write_err)?;
    // 03.07: either copy may be the intended one (in a PR the committed copy often is); the
    // person picks the direction. Not "keys are missing".
    let manifest = match found.cause_source() {
        crate::cause::ConfigSource::Manifest { title, .. } => title,
        crate::cause::ConfigSource::File { path, .. } => path.display().to_string(),
    };
    Err(Cause::CopiesDiffer {
        file: file.to_path_buf(),
        manifest,
    }
    .into())
}

/// A line diff of `a` to `b`: `-` removed, `+` added, ` ` kept (longest common
/// subsequence; configurations are small).
pub fn diff(a: &str, b: &str) -> String {
    let x: Vec<&str> = a.lines().collect();
    let y: Vec<&str> = b.lines().collect();
    let (n, m) = (x.len(), y.len());
    let mut lcs = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if x[i] == y[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let mut s = String::new();
    let (mut i, mut j) = (0, 0);
    while i < n || j < m {
        if i < n && j < m && x[i] == y[j] {
            s.push_str(&format!(" {}\n", x[i]));
            i += 1;
            j += 1;
        } else if i < n && (j == m || lcs[i + 1][j] >= lcs[i][j + 1]) {
            s.push_str(&format!("-{}\n", x[i]));
            i += 1;
        } else {
            s.push_str(&format!("+{}\n", y[j]));
            j += 1;
        }
    }
    s
}

/// The interactive half of `config edit`: an editor and one yes/no question.
pub trait EditUi {
    /// Let the owner edit `text`; returns the edited text.
    fn edit(&mut self, text: &str) -> Result<String, Error>;
    /// Ask `question`; true for yes.
    fn confirm(&mut self, question: &str) -> Result<bool, Error>;
}

/// `config edit`: edit a copy, validate, show the diff, confirm once, and save only when
/// nobody changed the configuration meanwhile (otherwise re-open on the new version).
pub fn edit(
    found: &Found,
    r: &dyn CommandRunner,
    ui: &mut dyn EditUi,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let s = found.store();
    // Refused before the editor opens unless a person runs opv (I3); read past op's cache.
    let mut base: Snapshot = s.read_for_write(r)?;
    let mut draft = base.text.clone();
    loop {
        let edited = ui.edit(&draft)?;
        if edited == base.text {
            return line(out, "no changes; nothing saved");
        }
        if let Err(e) = store::parse_from(found, &edited) {
            line(out, e.to_string())?;
            // 03.05: the fix is shown here, where the person is editing, not only on exit.
            if let Some(fix) = fix_of(&e) {
                line(out, format!("Do: {fix}"))?;
            }
            if ui.confirm("Edit again?")? {
                draft = edited;
                continue;
            }
            return Err(e);
        }
        out.write_all(diff(&base.text, &edited).as_bytes())
            .map_err(write_err)?;
        if !ui.confirm(&format!("Save to {}?", s.describe()))? {
            return line(out, "not saved");
        }
        match s.replace(r, &base, &edited)? {
            Replaced::Saved => return line(out, format!("saved {}", s.describe())),
            Replaced::Changed(now) => {
                line(
                    out,
                    "refused: the configuration changed since it was opened; nothing saved. \
                     Re-opening on the new version (make your change again)",
                )?;
                base = now;
                draft = base.text.clone();
            }
        }
    }
}

/// The fix (`Do:`) of a validation error: its cause's; never a step derived from prose.
fn fix_of(e: &Error) -> Option<String> {
    super::own_step(e).0
}

/// `config edit` in a terminal: `$VISUAL`, else `$EDITOR`, else `vi`, on a temporary copy
/// (mode 0600, removed afterwards; it holds no secret), and a `[y/N]` prompt.
pub struct TerminalUi;

impl EditUi for TerminalUi {
    fn edit(&mut self, text: &str) -> Result<String, Error> {
        let editor = std::env::var("VISUAL")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .or_else(|| {
                std::env::var("EDITOR")
                    .ok()
                    .filter(|v| !v.trim().is_empty())
            })
            .unwrap_or_else(|| "vi".to_string());
        let mut words = editor.split_whitespace();
        let program = words.next().unwrap_or("vi").to_string();
        let tmp = TempCopy::create(text)?;
        let status = std::process::Command::new(&program)
            .args(words)
            .arg(&tmp.path)
            .status()
            .map_err(|e| -> Error {
                Cause::ChildStartFailed {
                    program: program.clone(),
                    workdir: None,
                    io: e.kind().into(),
                    remote: None,
                }
                .into()
            })?;
        if !status.success() {
            // The editor quit without success (`:cq`, a crash): the person's edit is
            // abandoned and nothing is saved.
            return Err(Cause::Guard {
                guard: crate::cause::Guard::Declined,
            }
            .into());
        }
        fs::read_to_string(&tmp.path).map_err(|e| tmp_failed(&e))
    }

    fn confirm(&mut self, question: &str) -> Result<bool, Error> {
        let mut err = std::io::stderr();
        let _ = write!(err, "{question} [y/N] ");
        let _ = err.flush();
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .map_err(|_| -> Error {
                Cause::NeedsTerminal {
                    why: crate::cause::NoTerminal::NoTty,
                }
                .into()
            })?;
        Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "Yes"))
    }
}

/// A temporary copy of the configuration for the editor, removed on drop.
struct TempCopy {
    path: PathBuf,
}

impl TempCopy {
    fn create(text: &str) -> Result<Self, Error> {
        let mut rnd = [0u8; 8];
        getrandom::fill(&mut rnd).map_err(|_| bug("config edit: no randomness"))?;
        let path = std::env::temp_dir().join(format!("opv-config-{}.toml", hex::encode(rnd)));
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&path).map_err(|e| tmp_failed(&e))?;
        let copy = TempCopy { path };
        f.write_all(text.as_bytes()).map_err(|e| tmp_failed(&e))?;
        Ok(copy)
    }
}

/// The private temporary copy in the system temp folder could not be made or read.
fn tmp_failed(e: &std::io::Error) -> Error {
    Cause::PrivateDirFailed {
        dir: std::env::temp_dir(),
        io: e.kind().into(),
    }
    .into()
}

impl Drop for TempCopy {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// One listed manifest, with the account it was listed under.
struct Listed {
    row: Row,
    account: Option<manifest::Account>,
}

/// One account's listing (#135): named by its account ID, since several accounts can share
/// one sign-in address. Never the person's email or user ID.
#[derive(Debug, Clone, serde::Serialize)]
struct AccountReport {
    account_id: String,
    sign_in: String,
    shorthand: Option<String>,
    /// `listed` or `failed`.
    status: &'static str,
    /// Manifests listed; `None` when the listing failed.
    manifests: Option<usize>,
    error_code: Option<&'static str>,
    reason: Option<String>,
}

impl AccountReport {
    fn new(a: &manifest::Account, listed: Result<usize, &Error>) -> Self {
        let (status, manifests, error_code, reason) = match listed {
            Ok(n) => ("listed", Some(n), None, None),
            Err(e) => (
                "failed",
                None,
                Some(e.code_str()),
                Some(e.text().lines().next().unwrap_or_default().to_string()),
            ),
        };
        Self {
            account_id: a.account_uuid.clone(),
            sign_in: a
                .url
                .trim_start_matches("https://")
                .trim_end_matches('/')
                .to_string(),
            shorthand: Some(a.shorthand.clone()).filter(|s| !s.is_empty()),
            status,
            manifests,
            error_code,
            reason,
        }
    }
}

/// What discovery listed (#135): the manifests, one report per account asked, and which
/// accounts were asked (`selected`: the one given or `OP_ACCOUNT`; `all`: every account op
/// knows; `default`: op's own account, when it knows at most one).
struct Inventory {
    listed: Vec<Listed>,
    accounts: Vec<AccountReport>,
    scope: &'static str,
}

impl Inventory {
    /// True when every account asked was listed: only then is a missing project absent.
    fn complete(&self) -> bool {
        self.accounts.iter().all(|a| a.status == "listed")
    }

    /// `inventory_incomplete` naming the accounts that could not be listed, or `None`.
    fn incomplete(&self) -> Option<Error> {
        let failed: Vec<&AccountReport> = self
            .accounts
            .iter()
            .filter(|a| a.status != "listed")
            .collect();
        failed.first()?;
        // 03.08: the catalog's sign-in step carries --no-record, so following it never
        // re-points the current checkout's .opv at another account.
        Some(
            Cause::InventoryIncomplete {
                unlisted: failed
                    .iter()
                    .map(|a| AccountId::new(a.account_id.clone()))
                    .collect(),
            }
            .into(),
        )
    }
}

/// Every visible manifest (#135). With `selected` (`--account`, else `OP_ACCOUNT`, which
/// `opv login --account` gives its command) only that account is listed and its failure is
/// the result. Without it, one listing per account op knows (one call when it knows at most
/// one, whose failure is the result); an account that cannot be listed is reported, never
/// dropped, so an incomplete inventory is never mistaken for an empty one.
fn inventory(r: &dyn CommandRunner, selected: Option<&str>) -> Result<Inventory, Error> {
    let accounts = manifest::accounts(r);
    if let Some(who) = selected {
        let id = if accounts.is_empty() {
            who.to_string()
        } else {
            manifest::resolve(&accounts, who)?
        };
        let rows = manifest::list(r, Some(&id), &Host::detect)?;
        let account = accounts.into_iter().find(|a| a.account_uuid == id);
        return Ok(Inventory {
            accounts: account
                .iter()
                .map(|a| AccountReport::new(a, Ok(rows.len())))
                .collect(),
            listed: rows
                .into_iter()
                .map(|row| Listed {
                    row,
                    account: account.clone(),
                })
                .collect(),
            scope: "selected",
        });
    }
    if accounts.len() <= 1 {
        let rows = manifest::list(r, None, &Host::detect)?;
        return Ok(Inventory {
            accounts: accounts
                .iter()
                .map(|a| AccountReport::new(a, Ok(rows.len())))
                .collect(),
            listed: rows
                .into_iter()
                .map(|row| Listed { row, account: None })
                .collect(),
            scope: "default",
        });
    }
    let mut inv = Inventory {
        listed: Vec::new(),
        accounts: Vec::new(),
        scope: "all",
    };
    for a in accounts {
        match manifest::list(r, Some(&a.account_uuid), &Host::detect) {
            Ok(rows) => {
                inv.accounts.push(AccountReport::new(&a, Ok(rows.len())));
                inv.listed.extend(rows.into_iter().map(|row| Listed {
                    row,
                    account: Some(a.clone()),
                }));
            }
            Err(e) => inv.accounts.push(AccountReport::new(&a, Err(&e))),
        }
    }
    Ok(inv)
}

/// One note per account that could not be listed, naming it unambiguously.
fn notes_of(inv: &Inventory) -> Vec<String> {
    inv.accounts
        .iter()
        .filter(|a| a.status != "listed")
        .map(|a| {
            format!(
                "account {} ({}): not listed ({})",
                a.sign_in,
                a.account_id,
                a.reason.as_deref().unwrap_or_default()
            )
        })
        .collect()
}

/// The line for an inventory that holds no manifest.
fn nothing_listed(inv: &Inventory) -> &'static str {
    if inv.complete() {
        "no project manifests visible"
    } else {
        "no project manifests listed: the inventory is incomplete"
    }
}

fn store_of(l: &Listed) -> Found {
    Found::Manifest(ManifestStore::from_row(
        &l.row,
        l.account.as_ref().map(|a| a.account_uuid.clone()),
        Matched::Given,
    ))
}

/// `projects [--long] [--json]`: every manifest visible to the signed-in account(s), with
/// vault, repos and paths from the listing alone; `--long` reads each manifest once more
/// for its environment names. Names only, never a value.
pub fn projects(
    r: &dyn CommandRunner,
    account: Option<&str>,
    long: bool,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let inv = inventory(r, account)?;
    let notes = notes_of(&inv);
    let mut docs = Vec::new();
    for l in &inv.listed {
        let envs = long.then(|| {
            store_of(l)
                .load(r)
                .map(|f| f.environments.keys().cloned().collect::<Vec<_>>())
                .map_err(|e| e.text().lines().next().unwrap_or_default().to_string())
        });
        docs.push((l, envs));
    }
    if json {
        let v: Vec<serde_json::Value> = docs
            .iter()
            .map(|(l, envs)| {
                let mut o = json!({
                    "project": store::project_of(&l.row).unwrap_or(&l.row.title),
                    "title": l.row.title,
                    "vault": store::vault_label(&l.row),
                    "vault_id": l.row.vault.id,
                    "item_id": l.row.id,
                    "account": l.account.as_ref().map(|a| a.url.clone()),
                    "account_id": l.account.as_ref().map(|a| a.account_uuid.clone()),
                    "repos": store::row_repos(&l.row),
                    "paths": store::row_paths(&l.row),
                });
                match envs {
                    Some(Ok(e)) => o["environments"] = json!(e),
                    Some(Err(why)) => o["error"] = json!(why),
                    None => {}
                }
                o
            })
            .collect();
        let s = serde_json::to_string(&json!({
            "schema_version": crate::json::SCHEMA_VERSION,
            "scope": inv.scope,
            "complete": inv.complete(),
            "accounts": inv.accounts,
            "projects": v,
            "notes": notes,
        }))
        .map_err(|_| bug("projects: serialize"))?;
        line(out, s)?;
        return inv.incomplete().map_or(Ok(()), Err);
    }
    if docs.is_empty() {
        line(out, nothing_listed(&inv))?;
    }
    for (l, envs) in &docs {
        let mut parts = vec![format!("vault {}", store::vault_label(&l.row))];
        if let Some(a) = &l.account {
            parts.push(format!("account {}", a.url));
        }
        let repos = store::row_repos(&l.row);
        if !repos.is_empty() {
            parts.push(format!("repo {}", repos.join(", ")));
        }
        let paths = store::row_paths(&l.row);
        if !paths.is_empty() {
            parts.push(format!("paths {}", paths.join(", ")));
        }
        match envs {
            Some(Ok(e)) => parts.push(format!("environments {}", e.join(", "))),
            Some(Err(why)) => parts.push(format!("not read ({why})")),
            None => {}
        }
        line(
            out,
            format!(
                "{}: {}",
                store::project_of(&l.row).unwrap_or(&l.row.title),
                parts.join("; ")
            ),
        )?;
    }
    for n in &notes {
        line(out, format!("note: {n}"))?;
    }
    inv.incomplete().map_or(Ok(()), Err)
}

/// `status --all [--json]`: the one-line-per-environment overview for every visible
/// project. Costs one manifest read per project plus the overview's reads per environment.
/// A project that cannot be read is one line with its reason; the rest still run. The
/// result is the first error, else findings. `product` (`--product` or `OPV_PRODUCT`)
/// limits it to the projects that declare that product, and counts only its keys (I7).
/// Each `Next:` names its project (`env OPV_PROJECT=<name> opv ...`), so it runs from any
/// directory.
pub fn status_all(
    r: &dyn CommandRunner,
    account: Option<&str>,
    product: Option<&str>,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let inv = inventory(r, account)?;
    let notes = notes_of(&inv);
    let mut first: Option<Error> = None;
    let mut docs = Vec::new();
    for l in &inv.listed {
        let name = store::project_of(&l.row)
            .unwrap_or(&l.row.title)
            .to_string();
        match store_of(l).load(r) {
            Ok(fleet) => {
                if product.is_some_and(|p| !fleet.products.contains_key(p)) {
                    continue;
                }
                let o = status::overview_of(&fleet, product, r);
                let lines = o.lines.clone();
                let mut envs = serde_json::to_value(&o.envs).unwrap_or_default();
                for env in envs.as_array_mut().into_iter().flatten() {
                    if let Some(next) = env["next"].as_str() {
                        env["next"] = json!(project_step(next, &name));
                    }
                }
                if let Err(e) = o.result(&fleet) {
                    first.get_or_insert(e);
                }
                docs.push((
                    name,
                    store::vault_label(&l.row).to_string(),
                    Ok((lines, envs)),
                ));
            }
            Err(e) => {
                let why = e.to_string();
                let code = e.code_str();
                first.get_or_insert(e);
                docs.push((
                    name,
                    store::vault_label(&l.row).to_string(),
                    Err((why, code)),
                ));
            }
        }
    }
    if json {
        let v: Vec<serde_json::Value> = docs
            .iter()
            .map(|(name, vault, res)| match res {
                Ok((_, envs)) => json!({
                    "project": name, "vault": vault, "environments": envs,
                    "error_code": null, "error": null,
                }),
                Err((why, code)) => json!({
                    "project": name, "vault": vault, "environments": [],
                    "error_code": code, "error": why,
                }),
            })
            .collect();
        let s = serde_json::to_string(&json!({
            "schema_version": crate::json::SCHEMA_VERSION,
            "scope": inv.scope,
            "complete": inv.complete(),
            "accounts": inv.accounts,
            "projects": v,
            "notes": notes,
        }))
        .map_err(|_| bug("status --all: serialize"))?;
        line(out, s)?;
    } else {
        if docs.is_empty() {
            line(out, nothing_listed(&inv))?;
        }
        for (name, vault, res) in &docs {
            match res {
                Ok((lines, _)) => {
                    line(out, format!("{name} (vault {vault}):"))?;
                    for l in lines {
                        line(out, format!("  {l}"))?;
                    }
                }
                Err((why, _)) => line(out, format!("{name} (vault {vault}): not read ({why})"))?,
            }
        }
        for n in &notes {
            line(out, format!("note: {n}"))?;
        }
    }
    first.or_else(|| inv.incomplete()).map_or(Ok(()), Err)
}

/// `next` run against project `name` from any directory, when it is an opv command.
fn project_step(next: &str, name: &str) -> String {
    if next.starts_with("opv ") {
        format!("env OPV_PROJECT={} {next}", crate::error::shell_word(name))
    } else {
        next.to_string()
    }
}

#[cfg(test)]
#[path = "config_cmd_tests.rs"]
mod tests;
