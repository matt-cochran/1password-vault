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
use std::path::Path;

use serde::Serialize;

use crate::cause::Cause;
use crate::domain::{Fleet, span_of};
use crate::error::Error;
use crate::runner::CommandRunner;
use crate::scan::{Coverage, Kind, Observation, Pattern, Scan, Tree};

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
        let location = format!("{}:{}", observation.file, observation.line);
        match observation.kind {
            Kind::Ambiguous => ambiguous.push(location),
            Kind::Observed => {
                let Some(name) = &observation.name else {
                    continue;
                };
                let owner = match declared.get(name) {
                    Some(product) => Some((name.clone(), product.clone())),
                    None => delivered.get(name).cloned(),
                };
                match owner {
                    Some(owner) => matched.entry(owner).or_default().push(location),
                    None => observed.entry(name.clone()).or_default().push(location),
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
    observations.iter().any(|observation| {
        observation.kind == Kind::Observed
            && observation.name.as_deref() == Some(name)
            && observation_span(runner, repo, tree, observation, texts) == recorded
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

/// `opv needs [--gate]` for the repository top `repo`: the report against the contract, the
/// default branch's deciding which undeclared names are new, printed as `--json` or text, then
/// the gate when asked. The CLI and `opv_state` section `needs` both answer through here.
pub fn run(
    r: &dyn CommandRunner,
    repo: &Path,
    fleet: &Fleet,
    gate_on: bool,
    json: bool,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let source = crate::app::rule_source::rule_source(r, repo, fleet)?;
    let base = source.contract();
    let report = needs(r, repo, &crate::scan::WorkTree, fleet, base);
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
