//! `opv needs` and the needs gate (design Part V, row `needs`).
//!
//! The scanner observes every name the code reads (or cannot resolve); this module compares
//! those names with the contract's declared keys and reports four states:
//! `undeclared`, `declared_unobserved`, `ambiguous` and `declared`. It never reads a value:
//! an observation carries a name, a `file:line` and a kind, and the only thing this module
//! does with a source line is hash it for an annotation span. A dotenv observation's span
//! hashes the file and the NAME, never the right-hand side, so no part of a value can reach
//! the span.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::cause::Cause;
use crate::domain::{Fleet, span_of};
use crate::error::Error;
use crate::runner::CommandRunner;
use crate::scan::{Coverage, DirTree, Kind, Observation, Pattern, Scan, Tree, WorkTree};

/// Every scanner pattern a `needs` scan runs: each language and manifest row.
fn patterns() -> [&'static dyn Pattern; 9] {
    [
        &crate::scan::lang::Rust,
        &crate::scan::lang::TypeScript,
        &crate::scan::lang::Python,
        &crate::scan::lang::Go,
        &crate::scan::manifests::DotEnv,
        &crate::scan::manifests::Compose,
        &crate::scan::manifests::K8sManifest,
        &crate::scan::manifests::FlyToml,
        &crate::scan::manifests::GithubActions,
    ]
}

/// Where `opv needs` takes the names the code reads from (#175).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum NeedsInput {
    /// The files git knows in the repository's working tree (the default).
    #[default]
    Git,
    /// Every file under this directory, walked without git (`--scan <DIR>`); `file:line`
    /// locations are relative to it.
    Scan(PathBuf),
    /// Names an assistant found itself (`--names <FILE>`): each is an observation with no
    /// `file:line`, checked by the same name grammar and runtime list as a scan.
    Names(Vec<String>),
}

/// What `opv needs` is asked for (#175): the environment and product that narrow the report,
/// and where the observed names come from. The CLI and `opv_state` build it; the library
/// validates `env` and `product` against the contract.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NeedsOptions {
    /// Only keys desired in this environment (`opv needs <ENV>`).
    pub env: Option<String>,
    /// Only this product's keys (`--product`); undeclared and ambiguous rows, which no
    /// product owns yet, are kept.
    pub product: Option<String>,
    /// Where the observed names come from.
    pub input: NeedsInput,
}

/// How one name stands against the contract (design Part V, row `needs`). The order is the
/// report's order: `undeclared`, then `declared_unobserved`, then `ambiguous`, then
/// `declared`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NeedState {
    /// The code reads it; the contract declares it nowhere and no live `ignore` hides it.
    Undeclared,
    /// The contract declares it; the scanner never observed it.
    DeclaredUnobserved,
    /// A computed-name observation the scanner could not resolve; by `file:line`.
    Ambiguous,
    /// The contract declares it and the scanner observed it.
    Declared,
}

impl NeedState {
    /// The state's word, as the report and the text rendering print it.
    pub fn word(self) -> &'static str {
        match self {
            NeedState::Undeclared => "undeclared",
            NeedState::DeclaredUnobserved => "declared_unobserved",
            NeedState::Ambiguous => "ambiguous",
            NeedState::Declared => "declared",
        }
    }
}

/// One row of a [`NeedsReport`]. Names and `file:line` only, never a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NeedRow {
    /// The undeclared name as observed, or the declared key (also when the code reads it
    /// under a name a target delivers it as); empty for an [`NeedState::Ambiguous`] row,
    /// whose location is in `files`.
    pub name: String,
    /// How the name stands against the contract.
    pub state: NeedState,
    /// The `file:line` locations the scanner observed, sorted by scan order; empty for
    /// [`NeedState::DeclaredUnobserved`].
    pub files: Vec<String>,
    /// The product that declares the key, or that holds the stale ignore annotation.
    pub product: Option<String>,
    /// True when an `ignore` annotation exists for this name but none of its observations
    /// carries the annotated span, so the annotation is stale and the name shows again.
    #[serde(default)]
    pub annotation_stale: bool,
}

/// The result of `opv needs`: one row per observed or declared name, and the scan's
/// coverage. Names and `file:line` only, never a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NeedsReport {
    pub rows: Vec<NeedRow>,
    pub coverage: Coverage,
}

/// Scan `repo`'s `tree` with every pattern, classify each observed name against `fleet`'s
/// declared keys, and report the states and the coverage. `base` is the default-branch
/// contract the [`gate`] reads; it does not change the classification.
pub fn needs(
    runner: &dyn CommandRunner,
    repo: &Path,
    tree: &dyn Tree,
    fleet: &Fleet,
    base: Option<&Fleet>,
) -> NeedsReport {
    let _ = base;
    let scan = Scan::collect(runner, repo, tree, &patterns());
    classify(runner, repo, tree, fleet, scan)
}

/// The report for `options` (#175): the scan its input names (the git tree at `repo`, a
/// directory, or an assistant's names), classified against all of `fleet` so a key another
/// product declares is never undeclared, then narrowed to `options.env` and
/// `options.product`. An unknown environment or product is refused with the candidates.
pub fn needs_with(
    runner: &dyn CommandRunner,
    repo: &Path,
    fleet: &Fleet,
    base: Option<&Fleet>,
    options: &NeedsOptions,
) -> Result<NeedsReport, Error> {
    if let Some(env) = &options.env {
        fleet.environment(env)?;
    }
    if let Some(product) = &options.product
        && !fleet.products.contains_key(product)
    {
        return Err(super::undefined_product(
            fleet,
            product,
            options.env.as_deref(),
        ));
    }
    let report = match &options.input {
        NeedsInput::Git => needs(runner, repo, &WorkTree, fleet, base),
        NeedsInput::Scan(dir) => needs(runner, dir, &DirTree, fleet, base),
        NeedsInput::Names(names) => classify(runner, repo, &WorkTree, fleet, scan_of_names(names)),
    };
    Ok(narrow(report, fleet, options))
}

/// The names in a `--names` file: one per line, surrounding space trimmed; blank lines and
/// `#` comment lines are skipped. A name outside the grammar is kept here and counted as
/// skipped by the classification, never echoed.
pub fn parse_names(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// Read a `--names <FILE>` input: the file at `path`, or standard input for `-`. An
/// unreadable file is `input_unreadable`, naming the file, never its contents.
pub fn read_names(path: &Path) -> Result<Vec<String>, Error> {
    use std::io::Read;
    let unreadable = |e: std::io::Error| -> Error {
        Cause::InputUnreadable {
            path: path.to_path_buf(),
            kind: crate::cause::InputKind::NamesFile,
            io: e.kind().into(),
        }
        .into()
    };
    let text = if path == Path::new("-") {
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .map_err(unreadable)?;
        text
    } else {
        std::fs::read_to_string(path).map_err(unreadable)?
    };
    Ok(parse_names(&text))
}

/// A scan made of names an assistant found itself: one observation per name with no
/// `file:line`, kept or dropped by the scanner's own grammar and runtime list.
fn scan_of_names(names: &[String]) -> Scan {
    let mut scan = Scan::default();
    for name in names {
        if crate::scan::valid_name(name) && !crate::scan::runtime_name(name) {
            scan.observations.push(Observation {
                name: Some(name.clone()),
                file: String::new(),
                line: 0,
                kind: Kind::Observed,
            });
        } else {
            scan.coverage.skipped_patterns += 1;
        }
    }
    scan
}

/// `report` narrowed to `options.product` (rows of other products go; rows no product owns
/// stay) and `options.env` (a declared row goes when its key is not desired there).
fn narrow(mut report: NeedsReport, fleet: &Fleet, options: &NeedsOptions) -> NeedsReport {
    report.rows.retain(|row| {
        let Some(owner) = &row.product else {
            return true;
        };
        if options.product.as_ref().is_some_and(|p| p != owner) {
            return false;
        }
        let declared = matches!(
            row.state,
            NeedState::Declared | NeedState::DeclaredUnobserved
        );
        match (&options.env, declared) {
            (Some(env), true) => fleet
                .products
                .get(owner)
                .and_then(|p| p.keys.get(&row.name))
                .is_none_or(|spec| spec.is_desired_in(env)),
            _ => true,
        }
    });
    report
}

/// Classify a finished scan against `fleet`. Reads a file's line only to hash an annotation
/// span, and never a dotenv line's right-hand side.
fn classify(
    runner: &dyn CommandRunner,
    repo: &Path,
    tree: &dyn Tree,
    fleet: &Fleet,
    scan: Scan,
) -> NeedsReport {
    // key -> the first product that declares it (products iterate sorted).
    let mut declared: BTreeMap<String, String> = BTreeMap::new();
    // name -> the first product that carries an ignore annotation for it, with its span.
    let mut ignores: BTreeMap<String, (String, String)> = BTreeMap::new();
    for (product, p) in &fleet.products {
        for key in p.keys.keys() {
            declared
                .entry(key.clone())
                .or_insert_with(|| product.clone());
        }
        for (name, annotation) in &p.ignore {
            ignores
                .entry(name.clone())
                .or_insert_with(|| (product.clone(), annotation.span.clone()));
        }
    }

    // name -> (key, product) for every name a declared key is delivered under on a target.
    let delivered = delivered_names(fleet);

    // (key, product) -> where the code reads the key, under its own name or a delivered one.
    let mut matched: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    let mut observed: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut ambiguous: Vec<String> = Vec::new();
    for observation in &scan.observations {
        // A name an assistant found itself carries no `file:line`.
        let location = (!observation.file.is_empty())
            .then(|| format!("{}:{}", observation.file, observation.line));
        match observation.kind {
            Kind::Ambiguous => ambiguous.extend(location),
            Kind::Observed => {
                let Some(name) = &observation.name else {
                    continue;
                };
                let owner = match declared.get(name) {
                    Some(product) => Some((name.clone(), product.clone())),
                    None => delivered.get(name).cloned(),
                };
                match owner {
                    Some(owner) => matched.entry(owner).or_default().extend(location),
                    None => observed.entry(name.clone()).or_default().extend(location),
                }
            }
        }
    }

    let mut rows: Vec<NeedRow> = Vec::new();
    let mut texts: BTreeMap<String, Option<String>> = BTreeMap::new();

    for ((key, product), files) in &matched {
        rows.push(NeedRow {
            name: key.clone(),
            state: NeedState::Declared,
            files: files.clone(),
            product: Some(product.clone()),
            annotation_stale: false,
        });
    }

    for (name, files) in &observed {
        if let Some((product, span)) = ignores.get(name) {
            if annotation_is_current(
                runner,
                repo,
                tree,
                &scan.observations,
                name,
                span,
                &mut texts,
            ) {
                continue;
            }
            rows.push(NeedRow {
                name: name.clone(),
                state: NeedState::Undeclared,
                files: files.clone(),
                product: Some(product.clone()),
                annotation_stale: true,
            });
            continue;
        }
        rows.push(NeedRow {
            name: name.clone(),
            state: NeedState::Undeclared,
            files: files.clone(),
            product: None,
            annotation_stale: false,
        });
    }

    for (name, product) in &declared {
        if !matched.keys().any(|(key, _)| key == name) {
            rows.push(NeedRow {
                name: name.clone(),
                state: NeedState::DeclaredUnobserved,
                files: Vec::new(),
                product: Some(product.clone()),
                annotation_stale: false,
            });
        }
    }

    for location in ambiguous {
        rows.push(NeedRow {
            name: String::new(),
            state: NeedState::Ambiguous,
            files: vec![location],
            product: None,
            annotation_stale: false,
        });
    }

    rows.sort_by(|a, b| (a.state, &a.name).cmp(&(b.state, &b.name)));
    NeedsReport {
        rows,
        coverage: scan.coverage,
    }
}

/// Every name a declared key of `fleet` is delivered under on a target: name -> (key,
/// product), rendered by each target's own name template exactly as a sync renders it, for
/// every environment the key is desired in and every target that delivers its product.
/// Products iterate sorted, so a name two products render belongs to the first, as a plain
/// key two products declare does.
fn delivered_names(fleet: &Fleet) -> BTreeMap<String, (String, String)> {
    let mut names: BTreeMap<String, (String, String)> = BTreeMap::new();
    for (product, p) in &fleet.products {
        for (env_name, env) in &fleet.environments {
            for target in env.targets.keys() {
                if !fleet.delivers(env_name, target, product) {
                    continue;
                }
                for (key, spec) in &p.keys {
                    if !spec.is_desired_in(env_name) {
                        continue;
                    }
                    names
                        .entry(fleet.target_name(env_name, target, product, key))
                        .or_insert_with(|| (key.clone(), product.clone()));
                }
            }
        }
    }
    names
}

/// Whether some observation of `name` still carries `recorded` as its evidence span, so the
/// `ignore` annotation is live.
fn annotation_is_current(
    runner: &dyn CommandRunner,
    repo: &Path,
    tree: &dyn Tree,
    observations: &[Observation],
    name: &str,
    recorded: &str,
    texts: &mut BTreeMap<String, Option<String>>,
) -> bool {
    // A name an assistant found itself has no source line to hash: its annotation stands.
    observations.iter().any(|observation| {
        observation.kind == Kind::Observed
            && observation.name.as_deref() == Some(name)
            && (observation.file.is_empty()
                || observation_span(runner, repo, tree, observation, texts) == recorded)
    })
}

/// The evidence span of one observation. A manifest observation hashes the file and the
/// NAME, never the line (it may hold a value); a source-code observation hashes the file
/// and its own source line.
fn observation_span(
    runner: &dyn CommandRunner,
    repo: &Path,
    tree: &dyn Tree,
    observation: &Observation,
    texts: &mut BTreeMap<String, Option<String>>,
) -> String {
    use crate::scan::manifests::{Compose, DotEnv, FlyToml, GithubActions, K8sManifest};
    // A manifest line can carry a literal value (`.env.example`, Compose `NAME=…`, a
    // Kubernetes `value:`, a fly.toml `[env]` entry): its span hashes the NAME, never the line.
    let manifest = [
        &DotEnv as &dyn crate::scan::Pattern,
        &Compose,
        &K8sManifest,
        &FlyToml,
        &GithubActions,
    ]
    .iter()
    .any(|p| p.applies(&observation.file));
    if manifest {
        return span_of(
            &observation.file,
            observation.name.as_deref().unwrap_or_default(),
        );
    }
    let text = texts
        .entry(observation.file.clone())
        .or_insert_with(|| tree.read(runner, repo, &observation.file));
    let line = text
        .as_deref()
        .and_then(|t| t.lines().nth(observation.line.saturating_sub(1)))
        .unwrap_or_default();
    span_of(&observation.file, line)
}

/// `opv needs [<ENV>] [--product] [--scan|--names] [--gate]` for the repository top `repo`
/// ([`NeedsOptions`]): the report against the contract, the
/// default branch's deciding which undeclared names are new, printed as `--json` or text, then
/// the gate when asked. The CLI and `opv_state` section `needs` both answer through here.
pub fn run(
    r: &dyn CommandRunner,
    repo: &Path,
    fleet: &Fleet,
    options: &NeedsOptions,
    gate_on: bool,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let source = crate::app::rule_source::rule_source(r, repo, fleet)?;
    let base = source.contract();
    let report = needs_with(r, repo, fleet, base, options)?;
    if json {
        let doc = serde_json::to_value(&report).map_err(|_| -> Error {
            Cause::Bug {
                site: "needs: the report did not serialize",
            }
            .into()
        })?;
        writeln!(out, "{doc}").map_err(super::write_err)?;
    } else {
        render_text(&report, out)?;
    }
    if gate_on {
        gate(&report, base, fleet)?;
    }
    Ok(())
}

/// Fail (`needs_undeclared`) when a row is `undeclared` and `base` does not declare it
/// either. Names only, never a value. The refusal names the product of `fleet` the names
/// would be declared in when exactly one product is delivered.
pub fn gate(report: &NeedsReport, base: Option<&Fleet>, fleet: &Fleet) -> Result<(), Error> {
    let mut names: Vec<String> = Vec::new();
    for row in &report.rows {
        if row.state == NeedState::Undeclared
            && !declared_in(base, &row.name)
            && !names.contains(&row.name)
        {
            names.push(row.name.clone());
        }
    }
    if names.is_empty() {
        Ok(())
    } else {
        Err(Cause::NeedsUndeclared {
            names,
            product: delivered_product(fleet),
        }
        .into())
    }
}

/// The one product of `fleet` that is delivered (not `source_only`), when there is exactly
/// one: the code that reads a name belongs to it.
fn delivered_product(fleet: &Fleet) -> Option<String> {
    let mut delivered = fleet.products.iter().filter(|(_, p)| !p.source_only);
    match (delivered.next(), delivered.next()) {
        (Some((name, _)), None) => Some(name.clone()),
        _ => None,
    }
}

/// Whether any product of `base` declares `name`, or delivers a key under it on a target.
fn declared_in(base: Option<&Fleet>, name: &str) -> bool {
    base.is_some_and(|fleet| {
        fleet.products.values().any(|p| p.keys.contains_key(name))
            || delivered_names(fleet).contains_key(name)
    })
}

/// Render `report` for a person: a counts line, one line per row (state, name, product and
/// `file:line`), and the scanner's coverage. Names and `file:line` only, never a value.
pub fn render_text(report: &NeedsReport, out: &mut dyn Write) -> Result<(), Error> {
    let count = |state: NeedState| report.rows.iter().filter(|r| r.state == state).count();
    writeln!(
        out,
        "needs: {} undeclared · {} declared_unobserved · {} ambiguous · {} declared",
        count(NeedState::Undeclared),
        count(NeedState::DeclaredUnobserved),
        count(NeedState::Ambiguous),
        count(NeedState::Declared),
    )
    .map_err(super::write_err)?;

    for row in &report.rows {
        let product = row.product.as_deref().unwrap_or("-");
        let files = if row.files.is_empty() {
            "-".to_string()
        } else {
            row.files.join(",")
        };
        let stale = if row.annotation_stale {
            " (annotation stale)"
        } else {
            ""
        };
        writeln!(
            out,
            "{} {} {} {}{}",
            row.state.word(),
            row.name,
            product,
            files,
            stale
        )
        .map_err(super::write_err)?;
    }

    writeln!(
        out,
        "coverage: {} files · {} · {} skipped patterns",
        report.coverage.files,
        report.coverage.languages.join(","),
        report.coverage.skipped_patterns,
    )
    .map_err(super::write_err)?;
    Ok(())
}

#[cfg(test)]
#[path = "needs_tests.rs"]
mod tests;
