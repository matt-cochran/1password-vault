//! `opv needs` and the needs gate (design Part V, row `needs`).
//!
//! The scanner observes every name the code reads (or cannot resolve); this module compares
//! those names with the contract's declared keys and reports four states:
//! `undeclared`, `declared_unobserved`, `ambiguous` and `declared`. It never reads a value:
//! an observation carries a name, a `file:line` and a kind, and the only thing this module
//! does with a source line is hash it for an annotation span. A dotenv observation's span
//! hashes the file and the NAME, never the right-hand side, so no part of a value can reach
//! the span.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::cause::Cause;
use crate::domain::value_state::ValueState;
use crate::domain::{Fleet, span_of};
use crate::error::Error;
use crate::runner::CommandRunner;
use crate::scan::{Coverage, DirTree, Kind, Observation, Pattern, Scan, Tree, WorkTree};

/// Every scanner pattern a `needs` scan runs (#175): each language and manifest row, plus
/// the reads of files under each product's declared secrets directory, built from `fleet`
/// (one group per product with `local.secrets_dir_env`, each key's `file` path mapped to
/// the key). The secrets-directory row is left out when no product declares one.
fn patterns(fleet: &Fleet) -> Vec<Box<dyn Pattern>> {
    let mut patterns: Vec<Box<dyn Pattern>> = vec![
        Box::new(crate::scan::lang::Rust),
        Box::new(crate::scan::lang::TypeScript),
        Box::new(crate::scan::lang::Python),
        Box::new(crate::scan::lang::Go),
        Box::new(crate::scan::lang::Ruby),
        Box::new(crate::scan::lang::C),
        Box::new(crate::scan::manifests::DotEnv),
        Box::new(crate::scan::manifests::Compose),
        Box::new(crate::scan::manifests::K8sManifest),
        Box::new(crate::scan::manifests::FlyToml),
        Box::new(crate::scan::manifests::GithubActions),
    ];
    let groups = fleet.products.values().filter_map(|product| {
        let dir_env = product.local.as_ref()?.secrets_dir_env.clone()?;
        let files: BTreeMap<String, String> = product
            .keys
            .iter()
            .filter_map(|(key, spec)| spec.file.clone().map(|file| (file, key.clone())))
            .collect();
        Some((dir_env, files))
    });
    let secrets_dir = crate::scan::lang::SecretsDir::from_groups(groups);
    if !secrets_dir.is_empty() {
        patterns.push(Box::new(secrets_dir));
    }
    patterns
}

/// Walk `tree` over `repo` with every pattern [`patterns`] builds from `fleet`.
fn collect(runner: &dyn CommandRunner, repo: &Path, tree: &dyn Tree, fleet: &Fleet) -> Scan {
    let patterns = patterns(fleet);
    let refs: Vec<&dyn Pattern> = patterns.iter().map(|p| p.as_ref()).collect();
    Scan::collect(runner, repo, tree, &refs)
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
    /// Several products could own the observed name; its candidates are in the row.
    Ambiguous,
    /// A computed-name observation the scanner could not resolve; by `file:line`.
    Computed,
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
            NeedState::Computed => "computed",
            NeedState::Declared => "declared",
        }
    }
}

/// One row of a [`NeedsReport`]. Names and `file:line` only, never a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NeedRow {
    /// The undeclared name as observed, or the declared key (also when the code reads it
    /// under a name a target delivers it as); empty for a [`NeedState::Computed`] row,
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
    /// The declared key's value state, classified exactly as `opv inventory` classifies it
    /// (never a value); absent for rows that declare no key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_state: Option<ValueState>,
    /// For an [`NeedState::Ambiguous`] row, each product that could own the name, sorted;
    /// empty for every other state.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<String>,
    /// For an [`NeedState::Undeclared`] row, the declaration that would make the name part
    /// of the contract, validated against the load rules; absent when no product is named.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested: Option<SuggestedDeclaration>,
}

/// A declaration an undeclared name would take: the product it belongs to, the key, and the
/// field `kind`. Names and a word only, never a value. Its TOML, merged into the contract,
/// loads ([`SuggestedDeclaration::toml`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SuggestedDeclaration {
    pub product: String,
    pub key: String,
    /// `secret` or `config`, from [`crate::domain::kind_guess::kind_for_name`].
    pub kind: String,
}

impl SuggestedDeclaration {
    /// The TOML fragment that declares this key in `fleet`'s languages, scoped to the
    /// environments whose boundary the product is bound in, so the merged document loads.
    pub fn toml(&self, fleet: &Fleet) -> String {
        let mut environments: Vec<&str> = fleet
            .environments
            .keys()
            .filter(|env| fleet.boundary(env, &self.product).is_ok())
            .map(String::as_str)
            .collect();
        environments.sort_unstable();
        let mut text = format!(
            "[products.{}.keys.{}]\nkind = \"{}\"\n",
            self.product, self.key, self.kind
        );
        if !environments.is_empty() {
            let list: Vec<String> = environments
                .iter()
                .map(|env| format!("\"{env}\""))
                .collect();
            text.push_str(&format!("environments = [{}]\n", list.join(", ")));
        }
        text
    }
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
    let scan = collect(runner, repo, tree, fleet);
    classify(runner, repo, tree, fleet, scan, &ValueStates::new(), None)
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
    let _ = base;
    let states = value_states(runner, fleet, options.env.as_deref());
    let report = match &options.input {
        NeedsInput::Git => classify(
            runner,
            repo,
            &WorkTree,
            fleet,
            collect(runner, repo, &WorkTree, fleet),
            &states,
            options.product.as_deref(),
        ),
        NeedsInput::Scan(dir) => classify(
            runner,
            dir,
            &DirTree,
            fleet,
            collect(runner, dir, &DirTree, fleet),
            &states,
            options.product.as_deref(),
        ),
        NeedsInput::Names(names) => classify(
            runner,
            repo,
            &WorkTree,
            fleet,
            scan_of_names(names),
            &states,
            options.product.as_deref(),
        ),
    };
    Ok(narrow(report, fleet, options))
}

/// The value state of each declared key, read exactly as `opv inventory` reads it. The
/// report is by `(product, key)`: from `env` when given, else the first environment that
/// desires the key. Never a value, and a failed inventory read yields no state rather than
/// failing the needs report — a row simply carries none.
type ValueStates = BTreeMap<(String, String), ValueState>;

fn value_states(runner: &dyn CommandRunner, fleet: &Fleet, env: Option<&str>) -> ValueStates {
    let Ok(document) = crate::app::inventory::gather(fleet, env, None, runner, None) else {
        return ValueStates::new();
    };
    let mut by_env: BTreeMap<(String, String, String), ValueState> = BTreeMap::new();
    for cell in document.cells {
        by_env
            .entry((cell.product, cell.key, cell.env))
            .or_insert(cell.state);
    }
    let mut states = ValueStates::new();
    for ((product, key, cell_env), state) in by_env {
        if env.is_some_and(|env| env != cell_env) {
            continue;
        }
        states.entry((product, key)).or_insert(state);
    }
    states
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
    states: &ValueStates,
    suggest_product: Option<&str>,
) -> NeedsReport {
    // key -> every product that declares it (products iterate sorted).
    let mut declared: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    // name -> the first product that carries an ignore annotation for it, with its span.
    let mut ignores: BTreeMap<String, (String, String)> = BTreeMap::new();
    for (product, p) in &fleet.products {
        for key in p.keys.keys() {
            declared
                .entry(key.clone())
                .or_default()
                .insert(product.clone());
        }
        for (name, annotation) in &p.ignore {
            ignores
                .entry(name.clone())
                .or_insert_with(|| (product.clone(), annotation.span.clone()));
        }
    }

    // name -> every (key, product) a declared key is delivered under on a target.
    let delivered = delivered_names(fleet);

    // (key, product) -> where the code reads the key, under its own name or a delivered one.
    let mut matched: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    let mut observed: BTreeMap<String, Vec<String>> = BTreeMap::new();
    // name -> every product that could own it, and the locations that read it.
    let mut ambiguous: Vec<(String, Vec<String>, Vec<String>)> = Vec::new();
    // A name read under several owners is not "no code reads it"; it gets no
    // DeclaredUnobserved row per candidate.
    let mut ambiguous_keys: BTreeSet<String> = BTreeSet::new();
    let mut computed: Vec<String> = Vec::new();
    for observation in &scan.observations {
        // A name an assistant found itself carries no `file:line`.
        let location = (!observation.file.is_empty())
            .then(|| format!("{}:{}", observation.file, observation.line));
        match observation.kind {
            Kind::Ambiguous => computed.extend(location),
            Kind::Observed => {
                let Some(name) = &observation.name else {
                    continue;
                };
                let mut candidates: BTreeSet<String> = BTreeSet::new();
                if let Some(products) = declared.get(name) {
                    candidates.extend(products.iter().cloned());
                }
                if let Some(owners) = delivered.get(name) {
                    candidates.extend(owners.iter().map(|(_, product)| product.clone()));
                }
                match candidates.len() {
                    0 => observed.entry(name.clone()).or_default().extend(location),
                    1 => {
                        let product = candidates.into_iter().next().expect("one candidate");
                        let key = match declared.get(name) {
                            Some(_) => name.clone(),
                            None => delivered
                                .get(name)
                                .and_then(|owners| owners.first())
                                .map(|(key, _)| key.clone())
                                .unwrap_or_else(|| name.clone()),
                        };
                        matched.entry((key, product)).or_default().extend(location);
                    }
                    _ => {
                        let mut files = Vec::new();
                        files.extend(location);
                        ambiguous_keys.insert(name.clone());
                        ambiguous.push((name.clone(), files, candidates.into_iter().collect()));
                    }
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
            value_state: states.get(&(product.clone(), key.clone())).cloned(),
            candidates: Vec::new(),
            suggested: None,
        });
    }

    let product = suggest_product
        .map(str::to_string)
        .or_else(|| delivered_product(fleet));
    for (name, files) in &observed {
        if let Some((annotation_product, span)) = ignores.get(name) {
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
                product: Some(annotation_product.clone()),
                annotation_stale: true,
                value_state: None,
                candidates: Vec::new(),
                suggested: product.as_ref().map(|product| SuggestedDeclaration {
                    product: product.clone(),
                    key: name.clone(),
                    kind: kind_word(crate::domain::kind_guess::kind_for_name(name)).to_string(),
                }),
            });
            continue;
        }
        rows.push(NeedRow {
            name: name.clone(),
            state: NeedState::Undeclared,
            files: files.clone(),
            product: None,
            annotation_stale: false,
            value_state: None,
            candidates: Vec::new(),
            suggested: product.as_ref().map(|product| SuggestedDeclaration {
                product: product.clone(),
                key: name.clone(),
                kind: kind_word(crate::domain::kind_guess::kind_for_name(name)).to_string(),
            }),
        });
    }

    for (name, products) in &declared {
        if ambiguous_keys.contains(name) {
            continue;
        }
        for product in products {
            if matched.contains_key(&(name.clone(), product.clone())) {
                continue;
            }
            rows.push(NeedRow {
                name: name.clone(),
                state: NeedState::DeclaredUnobserved,
                files: Vec::new(),
                product: Some(product.clone()),
                annotation_stale: false,
                value_state: None,
                candidates: Vec::new(),
                suggested: None,
            });
        }
    }

    for (name, files, candidates) in ambiguous {
        rows.push(NeedRow {
            name,
            state: NeedState::Ambiguous,
            files,
            product: None,
            annotation_stale: false,
            value_state: None,
            candidates,
            suggested: None,
        });
    }

    for location in computed {
        rows.push(NeedRow {
            name: String::new(),
            state: NeedState::Computed,
            files: vec![location],
            product: None,
            annotation_stale: false,
            value_state: None,
            candidates: Vec::new(),
            suggested: None,
        });
    }

    rows.sort_by(|a, b| (a.state, &a.name).cmp(&(b.state, &b.name)));
    NeedsReport {
        rows,
        coverage: scan.coverage,
    }
}

/// The word for a [`crate::domain::Kind`].
fn kind_word(kind: crate::domain::Kind) -> &'static str {
    match kind {
        crate::domain::Kind::Secret => "secret",
        crate::domain::Kind::Config => "config",
    }
}

/// Every name a declared key of `fleet` is delivered under on a target: name -> every
/// (key, product) that renders it, by each target's own name template exactly as a sync
/// renders it, for every environment the key is desired in and every target that delivers
/// its product. A name two products render lists both, so it is seen as ambiguous.
fn delivered_names(fleet: &Fleet) -> BTreeMap<String, Vec<(String, String)>> {
    let mut names: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
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
                    let owners = names
                        .entry(fleet.target_name(env_name, target, product, key))
                        .or_default();
                    let owner = (key.clone(), product.clone());
                    if !owners.contains(&owner) {
                        owners.push(owner);
                    }
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
        "needs: {} undeclared · {} declared_unobserved · {} ambiguous · {} computed · {} declared",
        count(NeedState::Undeclared),
        count(NeedState::DeclaredUnobserved),
        count(NeedState::Ambiguous),
        count(NeedState::Computed),
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
