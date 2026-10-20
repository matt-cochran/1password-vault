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
use crate::cause::{AccountId, Cause, Cmd, EnvName, GivenBy, UsageProblem};
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

/// D-G: the committed `secrets.bindings.toml` must be the one the last `opv apply` wrote.
/// The apply record holds only digests, so a difference is reported with the environments
/// named in the bindings file (the record names none). No record means nothing was applied
/// yet, which passes; only names and digests are compared, never a value.
fn check_bindings(file: &Path) -> Result<(), Error> {
    let dir = file.parent().unwrap_or_else(|| Path::new("."));
    let Some(record) = config::bindings::read_record(&dir.join(config::bindings::APPLIED))? else {
        return Ok(());
    };
    let path = dir.join(config::bindings::FILE);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(unreadable_file(&path, &e)),
    };
    if config::bindings::digest(&bytes) == record.bindings_digest {
        return Ok(());
    }
    let ids = config::bindings::read_sibling(file)?;
    Err(Cause::BindingsUnapplied {
        environments: environments_of(&ids),
    }
    .into())
}

/// The environments a bindings file names, in the file's sorted order: the second dotted key
/// of every `environments.<env>…` path.
fn environments_of(ids: &config::bindings::Bindings) -> Vec<EnvName> {
    let mut envs: Vec<EnvName> = Vec::new();
    for line in ids.render().lines() {
        let Some(path) = line.split(" = ").next() else {
            continue;
        };
        let mut parts = path.split('.');
        if parts.next() != Some("environments") {
            continue;
        }
        let Some(env) = parts.next() else { continue };
        let env = EnvName::new(env);
        if !envs.contains(&env) {
            envs.push(env);
        }
    }
    envs
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
/// is the contract as stored with its ids filled in (D-G: from `secrets.bindings.toml` or
/// the manifest's `opv-bindings` block), the text `opv ui` and `config edit` work on.
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

/// `config export [--toml|--json]` without ids (D-G, the default): the contract itself,
/// validated, with every 1Password id left where it lives (a file project's
/// `secrets.bindings.toml`, a manifest's `opv-bindings` block). `--with-ids` (debugging
/// only) prints the merged form through [`export`].
pub fn export_contract(
    found: &Found,
    format: Format,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let snap = found.store().read(r)?;
    store::parse_from(found, &snap.text)?;
    let (contract, _) = config::bindings::split(&snap.text);
    write_text(&contract, format, out)
}

/// Write an already-validated configuration `text` in `format` (shared by the export forms).
fn write_text(text: &str, format: Format, out: &mut dyn Write) -> Result<(), Error> {
    match format {
        Format::Toml => out.write_all(text.as_bytes()).map_err(write_err),
        Format::Json => {
            let v: toml::Value = toml::from_str(text).map_err(|_| bug("config export: parse"))?;
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
    // D-G: the manifest gets the contract only. A file still carrying an inline id is
    // refused naming the field; the ids beside it are never copied: the manifest's
    // `opv-bindings` block is written only by `opv apply`.
    config::bindings::refuse_inline(&text)?;
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

/// `config check --file <path>`: exit 2 with a diff when the file differs from the
/// manifest (line endings aside).
pub fn check(
    found: &Found,
    file: &Path,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let committed = fs::read_to_string(file).map_err(|e| unreadable_file(file, &e))?;
    // The file must be a configuration before any of it is printed as a diff: a `.env`
    // given by mistake would otherwise reach stdout line by line (C1, SR-1). D-G: its ids
    // live beside it, so it is judged with them filled in.
    config::parse_at(
        &config::with_bindings(&committed, file)?,
        config::Source::File(file),
    )?;
    let current = found.store().read(r)?;
    // The manifest's read fills its `opv-bindings` ids in: it is compared the way the file
    // keeps it, the contract first, then (when that matches) the ids.
    let (contract, ids) = config::bindings::split(&current.text);
    let (contract, committed) = (
        contract.replace("\r\n", "\n"),
        committed.replace("\r\n", "\n"),
    );
    let (a, b) = if contract.trim_end() == committed.trim_end() {
        let committed_ids = config::bindings::read_sibling(file)?;
        (ids.render(), committed_ids.render())
    } else {
        (contract, committed)
    };
    if a.trim_end() == b.trim_end() {
        check_bindings(file)?;
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

/// `config check --file <path>` on a file project (#178): the regenerated file at `file`
/// must load, and the configuration it loads must equal the committed one: the project's
/// configuration file `project`, or, when `file` is that same file (regenerated in place),
/// its copy at git `HEAD`. Equal prints one line (exit 0); different prints a diff of the
/// two texts and is `copies_differ` (exit 2). Names, ids and rules only, never a value.
pub fn check_file_project(
    project: &Path,
    file: &Path,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let regenerated = fs::read_to_string(file).map_err(|e| unreadable_file(file, &e))?;
    // Loads first: a file that is not a configuration is never printed as a diff (C1). A
    // generator writes the contract only; its ids are the project's, beside the project file.
    let mut head = config::parse_at(
        &config::with_bindings(&regenerated, project)?,
        config::Source::File(file),
    )?;
    let in_place = same_path(project, file);
    let (committed, label) = if in_place {
        (
            committed_at_head(project, r)?,
            format!("{} (HEAD)", project.display()),
        )
    } else {
        (
            fs::read_to_string(project).map_err(|e| unreadable_file(project, &e))?,
            project.display().to_string(),
        )
    };
    let base = config::parse_at(
        &config::with_bindings(&committed, project)?,
        config::Source::File(project),
    )?;
    // Where each was read from is wording only (FR-44), never a difference.
    head.read_from = base.read_from.clone();
    head.origin = base.origin;
    if head == base {
        return line(out, format!("{} is equivalent to {label}", file.display()));
    }
    let (a, b) = (
        committed.replace("\r\n", "\n"),
        regenerated.replace("\r\n", "\n"),
    );
    line(out, format!("--- {label}\n+++ {}", file.display()))?;
    out.write_all(diff(&a, &b).as_bytes()).map_err(write_err)?;
    Err(Cause::RegeneratedFileDiffers {
        file: file.to_path_buf(),
        committed: project.to_path_buf(),
        in_place,
    }
    .into())
}

/// Whether `a` and `b` name the same file (canonical paths; the paths as given when either
/// cannot be resolved).
fn same_path(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// The text of `path` as committed at git `HEAD`: the committed side of a file regenerated
/// in place. Not committed (or not in git) is `config_unreadable` for that path.
fn committed_at_head(path: &Path, r: &dyn CommandRunner) -> Result<String, Error> {
    use crate::runner::{Call, PROBE_TIMEOUT};
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty());
    let dir = dir.unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    let spec = format!("HEAD:./{name}");
    let dir_text = dir.to_str().unwrap_or(".");
    let missing = || unreadable_file(path, &std::io::Error::from(std::io::ErrorKind::NotFound));
    match r.probe(
        &Call::new("git", &["-C", dir_text, "show", spec.as_str()]),
        PROBE_TIMEOUT,
    ) {
        Ok(o) if o.status == 0 => String::from_utf8(o.stdout.to_vec()).map_err(|_| missing()),
        _ => Err(missing()),
    }
}

/// The number of unchanged lines kept on each side of a change in [`diff`].
const DIFF_CONTEXT: usize = 3;

/// A line diff of `a` to `b` as unified-style hunks: only changed lines plus
/// [`DIFF_CONTEXT`] lines of context around each change, each hunk under an
/// `@@ -l,n +l,n @@` header (longest common subsequence; configurations are small).
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
    // 0 keeps a line, 1 removes one from `a`, 2 adds one from `b`.
    let mut ops: Vec<(u8, &str)> = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < n || j < m {
        if i < n && j < m && x[i] == y[j] {
            ops.push((0, x[i]));
            i += 1;
            j += 1;
        } else if i < n && (j == m || lcs[i + 1][j] >= lcs[i][j + 1]) {
            ops.push((1, x[i]));
            i += 1;
        } else {
            ops.push((2, y[j]));
            j += 1;
        }
    }
    // How many lines each side has before an op, so a hunk's `@@` numbers read off its ends.
    let mut a_before = vec![0usize; ops.len() + 1];
    let mut b_before = vec![0usize; ops.len() + 1];
    for (k, (kind, _)) in ops.iter().enumerate() {
        a_before[k + 1] = a_before[k] + if *kind == 2 { 0 } else { 1 };
        b_before[k + 1] = b_before[k] + if *kind == 1 { 0 } else { 1 };
    }
    let changes: Vec<usize> = ops
        .iter()
        .enumerate()
        .filter(|(_, (kind, _))| *kind != 0)
        .map(|(k, _)| k)
        .collect();
    let mut s = String::new();
    let mut g = 0;
    while g < changes.len() {
        let first = changes[g];
        let mut last = first;
        // Adjacent changes, and changes no more than two context bands apart, share a hunk.
        while g + 1 < changes.len() && changes[g + 1] - last <= 2 * DIFF_CONTEXT + 1 {
            g += 1;
            last = changes[g];
        }
        g += 1;
        let start = first.saturating_sub(DIFF_CONTEXT);
        let end = (last + DIFF_CONTEXT).min(ops.len() - 1);
        let a_count = a_before[end + 1] - a_before[start];
        let b_count = b_before[end + 1] - b_before[start];
        let a_start = if a_count == 0 {
            a_before[start]
        } else {
            a_before[start] + 1
        };
        let b_start = if b_count == 0 {
            b_before[start]
        } else {
            b_before[start] + 1
        };
        s.push_str(&format!(
            "@@ -{a_start},{a_count} +{b_start},{b_count} @@\n"
        ));
        for (kind, text) in &ops[start..=end] {
            let marker = match kind {
                0 => ' ',
                1 => '-',
                _ => '+',
            };
            s.push_str(&format!("{marker}{text}\n"));
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
