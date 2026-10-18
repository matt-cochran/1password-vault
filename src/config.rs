//! `secrets.toml` loading and validation (FR-1, FR-2, §10.2).
//!
//! Validation runs before any secret operation; errors name the offending environment,
//! product, key or rule. The file holds IDs and rules only, never values.
//!
//! The generic environment fields (`boundaries`, `modes`, …) are parsed here. Each named
//! target (`[environments.<env>.targets.<name>]`, FR-56) holds exactly one provider
//! section, handed to the provider registered under that name (FR-37), and the target's own
//! `products`, `deploy_credentials` and `state_vault_id`. Name checks run generically from
//! each target's `NameRules`, per target.
//!
//! There is one form (FR-60): every removed form fails at load with its line and column and
//! the exact current form to write instead ([`removed_forms`]).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use toml::Spanned;
use toml::de::{DeTable, DeValue};

use crate::adapters::registry;
use crate::cause::{
    Cause, ConfigCheck, ConfigSource, Declared, DottedPath, FieldRule, GivenBy, Location,
    PatternId, StoreNameProblem,
};
use crate::domain::rules::{SIGNOZ_BODY, SIGNOZ_PREFIX};
use crate::domain::{
    Boundary, Environment, Fleet, ItemRef, KeySpec, Kind, Product, Target, Tier, ValueSource,
    boundary_missing, key_label,
};
use crate::error::Error;
use crate::provider::{
    Channel, FileCapability, NameRules, Section, StoreConfig, StoreNameRules, TargetConfig,
};

mod locate;

pub mod bindings;

/// Read and validate the configuration at `path`, found by discovery. An error names the
/// file, the line and the field the validator checked, and the fix built from the field and
/// its rule (H10, FR-2, audit 03.01).
pub fn load(path: impl AsRef<Path>) -> Result<Fleet, Error> {
    load_given(path, GivenBy::Discovered)
}

/// [`load`] for a path given by `given_by` (`--config`, `OPV_CONFIG`), so an unreadable file
/// names where the path came from (audit 03.12).
pub fn load_given(path: impl AsRef<Path>, given_by: GivenBy) -> Result<Fleet, Error> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path).map_err(|e| {
        Error::from(Cause::ConfigUnreadable {
            path: path.to_path_buf(),
            io: e.kind().into(),
            given_by: given_by.clone(),
        })
    })?;
    parse_file(&text, path, given_by)
}

/// [`parse`] for the text of the contract file at `path` (D-G): an inline id is refused,
/// the sibling `secrets.bindings.toml`'s ids are filled in, and an error names `path` at
/// the line of the contract as the person wrote it, not of the filled-in text.
pub fn parse_file(text: &str, path: &Path, given_by: GivenBy) -> Result<Fleet, Error> {
    let source = || ConfigSource::File {
        path: path.to_path_buf(),
        given_by: given_by.clone(),
    };
    let merged = merged(text, path, source())?;
    parse(&merged).map_err(|e| {
        in_contract(
            locate::relocate_at(e, &merged, source()),
            text,
            &merged,
            path,
        )
    })
}

/// The contract text at `path` with its sibling bindings filled in: the text the writers
/// that predate the bindings file edit (D-G). An inline id is refused, as at load.
pub fn read_merged(path: &Path) -> Result<String, Error> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| crate::config_store::unreadable(path, &e, GivenBy::Discovered))?;
    with_bindings(&text, path)
}

/// `text`, the contract read from `path`, with its sibling bindings filled in (D-G): what
/// [`read_merged`] gives for a text already read. An inline id is refused, as at load.
pub fn with_bindings(text: &str, path: &Path) -> Result<String, Error> {
    let source = ConfigSource::File {
        path: path.to_path_buf(),
        given_by: GivenBy::Discovered,
    };
    merged(text, path, source)
}

/// `text` (the contract at `path`, named `source`) refused when it writes an id inline,
/// else with the sibling bindings filled in. An error in the bindings file names that file.
fn merged(text: &str, path: &Path, source: ConfigSource) -> Result<String, Error> {
    // D-G: ids live in the sibling `secrets.bindings.toml`, one-way out of the contract.
    bindings::refuse_inline(text).map_err(|e| locate::relocate_at(e, text, source))?;
    let ids = bindings::read_sibling(path)?;
    Ok(bindings::merge(text, &ids))
}

/// `e`, from parsing `merged` (the contract at `path`, `original`, with its bindings filled
/// in) and naming the contract, placed at the line of `original` it came from. A line the
/// bindings filled in has no line in the contract: the error names the bindings file at the
/// id's line when the field is one of its ids, else the deepest part of its field the
/// contract declares.
fn in_contract(e: Error, original: &str, merged: &str, path: &Path) -> Error {
    let Some((cause, _)) = e.cause() else {
        return e;
    };
    let mut cause = cause.clone();
    let (source, at, field) = match &mut cause {
        Cause::ConfigInvalid {
            source, at, field, ..
        } => (source, at, field.0.clone()),
        Cause::StateVaultTooWide {
            source,
            at,
            env,
            target,
            ..
        } => (
            source,
            at,
            vec![
                "environments".to_string(),
                env.to_string(),
                "targets".to_string(),
                target.to_string(),
                "state_vault_id".to_string(),
            ],
        ),
        _ => return e,
    };
    let Some(loc) = at.as_mut() else {
        return e;
    };
    let lines = bindings::original_lines(original, merged);
    if let Some(Some(line)) = usize::try_from(loc.line)
        .ok()
        .and_then(|l| lines.get(l.checked_sub(1)?).copied())
    {
        loc.line = u32::try_from(line + 1).unwrap_or(u32::MAX);
        return cause.into();
    }
    let sibling = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(bindings::FILE);
    let key = format!("{} ", field.join("."));
    let in_bindings = std::fs::read_to_string(&sibling).ok().and_then(|text| {
        text.lines()
            .position(|l| l.starts_with(&key))
            .and_then(|i| u32::try_from(i + 1).ok())
    });
    match in_bindings {
        Some(line) => {
            *source = ConfigSource::File {
                path: sibling,
                given_by: GivenBy::Discovered,
            };
            *at = Some(Location { line, col: 1 });
        }
        None => {
            let refs: Vec<&str> = field.iter().map(String::as_str).collect();
            *at = Doc::parse(original).ok().and_then(|d| d.location(&refs));
        }
    }
    cause.into()
}

#[cfg(test)]
/// The contract file at `path` with its sibling bindings filled in, for a test that edits a
/// fixture's text before parsing it.
pub fn merged_text(path: impl AsRef<Path>) -> String {
    read_merged(path.as_ref()).unwrap()
}

/// Read the configuration at `path` with its ids left inline, returning the fleet and the
/// ids to move into `secrets.bindings.toml` (D-G; `opv propose structure`). This is the only
/// reader that accepts inline ids: [`load`] refuses them.
pub fn load_for_move(path: impl AsRef<Path>) -> Result<(Fleet, bindings::Bindings), Error> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path).map_err(|e| {
        Error::from(Cause::ConfigUnreadable {
            path: path.to_path_buf(),
            io: e.kind().into(),
            given_by: GivenBy::Discovered,
        })
    })?;
    let source = || ConfigSource::File {
        path: path.to_path_buf(),
        given_by: GivenBy::Discovered,
    };
    let ids = bindings::inline_ids(&text).map_err(|e| locate::relocate_at(e, &text, source()))?;
    let fleet = parse(&text).map_err(|e| locate::relocate_at(e, &text, source()))?;
    Ok((fleet, ids))
}

/// Where a configuration text came from, for its error messages (H10, FR-44).
#[derive(Debug, Clone, Copy)]
pub enum Source<'a> {
    /// A `secrets.toml` (or `--config`) file: errors read `<path>:<line>: <field>: …`.
    File(&'a Path),
    /// A project manifest in 1Password, by title: errors read
    /// `manifest "opv · app": <field>: …`.
    Manifest(&'a str),
    /// A project manifest in 1Password, by title and vault ID: the source a cause names.
    ManifestIn { title: &'a str, vault: &'a str },
}

impl Source<'_> {
    /// The catalog's [`ConfigSource`] for this source. A manifest's project is its title
    /// without the `opv · ` prefix.
    fn config_source(self) -> ConfigSource {
        let manifest = |title: &str, vault: &str| ConfigSource::Manifest {
            title: title.to_string(),
            vault: crate::cause::VaultId::new(vault),
            project: title.strip_prefix("opv · ").unwrap_or(title).to_string(),
        };
        match self {
            Source::File(path) => ConfigSource::File {
                path: path.to_path_buf(),
                given_by: GivenBy::Discovered,
            },
            Source::Manifest(title) => manifest(title, ""),
            Source::ManifestIn { title, vault } => manifest(title, vault),
        }
    }
}

/// [`parse`] with errors naming `source`, the line and the field.
pub fn parse_at(text: &str, source: Source<'_>) -> Result<Fleet, Error> {
    let source = source.config_source();
    match parse(text) {
        Ok(mut fleet) => {
            fleet.read_from.0 = source;
            Ok(fleet)
        }
        Err(e) => Err(locate::relocate_at(e, text, source)),
    }
}

/// `parse`'s errors name this source until [`locate::relocate_at`] names the real one.
fn parsing_source() -> ConfigSource {
    crate::domain::model::ReadFrom::default().0
}

/// A dotted configuration path from its parts.
fn dotted<S: AsRef<str>>(parts: &[S]) -> DottedPath {
    DottedPath(parts.iter().map(|p| p.as_ref().to_string()).collect())
}

/// The unique close candidate to `given`, when there is exactly one (X2).
fn closest<'a>(given: &str, candidates: impl IntoIterator<Item = &'a str>) -> Option<String> {
    match crate::app::suggest::close(given, candidates).as_slice() {
        [one] => Some(one.to_string()),
        _ => None,
    }
}

/// [`ConfigCheck::Undeclared`].
fn undeclared<'a>(
    kind: Declared,
    name: &str,
    declared: impl IntoIterator<Item = &'a str>,
) -> FieldRule {
    let declared: Vec<&str> = declared.into_iter().collect();
    FieldRule::Check {
        check: ConfigCheck::Undeclared {
            kind,
            name: name.to_string(),
            closest: closest(name, declared.iter().copied()),
            declared: declared.iter().map(|d| d.to_string()).collect(),
        },
    }
}

fn check(check: ConfigCheck) -> FieldRule {
    FieldRule::Check { check }
}

/// Walk up from `start`, returning the first directory that holds `secrets.toml`.
///
/// The start directory is an argument so the walk is testable with temp dirs, and only
/// file existence is checked, never file contents (FR-25).
pub fn discover(start: &Path) -> Option<PathBuf> {
    let mut dir = Some(start);
    while let Some(d) = dir {
        let candidate = d.join("secrets.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        dir = d.parent();
    }
    None
}

/// No `secrets.toml` in `start` or a parent (P3): the first-run router, offering both
/// starting paths and the explicit `--config`.
pub fn not_found(start: &Path) -> Error {
    // C16: the catalog's cause; no environment is guessed (`opv init dev` was one).
    crate::cause::Cause::ConfigNotFound {
        searched_from: start.to_path_buf(),
        env: None,
        manifest: None,
    }
    .into()
}

/// Parse and validate configuration text. A removed form (FR-60) fails before anything else
/// is read, showing the form to write instead.
pub fn parse(text: &str) -> Result<Fleet, Error> {
    let invalid = |e: toml::de::Error| toml_invalid(text, &e);
    let doc = Doc::parse(text).map_err(invalid)?;
    removed_forms(&doc)?;
    // The removed `pattern` rule must be reported as such, rather than as the
    // `deny_unknown_fields` error the typed parse would give (FR-60).
    reject_removed_pattern(&doc)?;
    let raw: RawConfig = toml::from_str(text).map_err(invalid)?;
    validate(raw, &doc)
}

/// A TOML parse or deserialize error as [`Cause::ConfigInvalid`]: the field is the document
/// path the error's span falls in, and the rule is the parser's own classification of the
/// error (missing, unknown, one of, type, duplicate, syntax). Never a value (C1, SR-1).
/// Provider sections ([`Section::deserialize`]) report through it too (D1, C15): their
/// spans are positions in the whole file, and the loader names the real source.
pub(crate) fn toml_invalid(text: &str, e: &toml::de::Error) -> Error {
    let span = e.span();
    let msg = sanitize_toml_message(e.message());
    let first = msg.lines().next().unwrap_or_default();
    // An empty span is the document itself (a missing top-level table).
    let mut path = span
        .clone()
        .filter(|s| !s.is_empty())
        .map(|s| path_at(text, s.start))
        .unwrap_or_default();
    let names = |marker: &str| -> Vec<String> {
        first
            .find(marker)
            .map(|at| {
                first[at..]
                    .split('`')
                    .skip(1)
                    .step_by(2)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    let rule = if let Some(missing) = ticked_after(first, "missing field ") {
        path.push(missing);
        if path == ["environments"] {
            FieldRule::NoEnvironment
        } else {
            FieldRule::Missing
        }
    } else if let Some(bad) = ticked_after(first, "unknown field ") {
        if path.last() != Some(&bad) {
            path.push(bad.clone());
        }
        let allowed = names("expected");
        FieldRule::Unknown {
            suggestion: closest(&bad, allowed.iter().map(String::as_str)),
        }
    } else if let Some(bad) = ticked_after(first, "unknown variant ") {
        let allowed = names("expected");
        check(ConfigCheck::NotOneOf {
            closest: closest(&bad, allowed.iter().map(String::as_str)),
            allowed,
        })
    } else if first.starts_with("duplicate key") {
        if path.is_empty()
            && let Some(k) = ticked_after(first, "duplicate key ")
        {
            path.push(k);
        }
        FieldRule::DuplicateKey
    } else if first.starts_with("invalid type") || first.starts_with("invalid value") {
        FieldRule::Type {
            expected: expected_words(first),
        }
    } else if let Some(expected) = provider_shape(first) {
        FieldRule::Type { expected }
    } else {
        FieldRule::Syntax
    };
    if path.is_empty() {
        path.push("the TOML".into());
    }
    Cause::ConfigInvalid {
        source: parsing_source(),
        at: span.and_then(|s| location(text, s.start)),
        field: DottedPath(path),
        rule,
    }
    .into()
}

/// The form a provider's own section check asks for (its serde message says `<field> <value>
/// must be <form>`), in opv's fixed words: never the message itself, which quotes the value
/// (C1). `None` for a message no provider check writes.
fn provider_shape(msg: &str) -> Option<&'static str> {
    registry::PROVIDERS
        .iter()
        .flat_map(|p| p.value_shapes().iter())
        .find(|(marker, _)| msg.contains(marker))
        .map(|(_, words)| *words)
}

/// The name in backticks after `marker`.
fn ticked_after(s: &str, marker: &str) -> Option<String> {
    let rest = &s[s.find(marker)? + marker.len()..];
    let inner = rest.strip_prefix('`')?;
    Some(inner[..inner.find('`')?].to_string())
}

/// The type a serde `invalid type` error expected, in words.
fn expected_words(msg: &str) -> &'static str {
    let expected = msg.split("expected ").nth(1).unwrap_or_default();
    match expected {
        e if e.starts_with("a sequence") => "a list, for example [\"prod\"]",
        e if e.starts_with("a boolean") => "true or false",
        e if e.starts_with("a string") => "a string in quotes",
        e if e.starts_with("i64") || e.starts_with("u16") || e.contains("integer") => {
            "a whole number"
        }
        e if e.starts_with("struct") || e.starts_with("a map") || e.contains("table") => "a table",
        _ => "of another type",
    }
}

/// The 1-based line and column of byte offset `at`.
fn location(text: &str, at: usize) -> Option<Location> {
    line_column(text, at).map(|(line, col)| Location {
        line: u32::try_from(line).unwrap_or(u32::MAX),
        col: u32::try_from(col).unwrap_or(u32::MAX),
    })
}

/// The document path whose key or value holds byte offset `at`: the deepest entry found
/// by walking the parsed tables (never the line's text, audit 03.01).
fn path_at(text: &str, at: usize) -> Vec<String> {
    /// The deepest entry under `t` whose key or value holds `at` (a header table's span
    /// covers only its header, so every table is searched, not only those holding `at`).
    fn find(t: &DeTable<'_>, at: usize) -> Option<Vec<String>> {
        for (k, v) in t.iter() {
            let name = k.get_ref().to_string();
            if let Some(inner) = v.get_ref().as_table()
                && let Some(mut rest) = find(inner, at)
            {
                rest.insert(0, name);
                return Some(rest);
            }
            if k.span().contains(&at) || v.span().contains(&at) {
                return Some(vec![name]);
            }
        }
        None
    }
    DeTable::parse(text)
        .ok()
        .and_then(|root| find(root.get_ref(), at))
        .unwrap_or_default()
}

/// FR-24, FR-60: the `pattern` rule is removed (0.7.0); a file that still sets it must
/// fail at load with the key and the equivalent `regex` rule. The typed parse cannot do
/// this (its `deny_unknown_fields` reports only "unknown field"), so the raw document is
/// walked first: every `rules` table gets one check, and the error points at the `pattern`
/// entry's line and column. The replacement is built from configuration (the prefix and
/// the pattern) and never from a value. A top-level `[keys]` table is [`removed_forms`]'s.
fn reject_removed_pattern(doc: &Doc<'_>) -> Result<(), Error> {
    // Path to the rules table of every declared key.
    let mut rules_tables: Vec<Vec<String>> = Vec::new();
    let root = doc.root.get_ref();
    if let Some(products) = table(root, "products") {
        for (product, pv) in products.iter() {
            let Some(keys) = pv
                .get_ref()
                .get("keys")
                .and_then(|v| v.get_ref().as_table())
            else {
                continue;
            };
            for (key, _) in keys.iter() {
                let (product, key) = (product.get_ref().as_ref(), key.get_ref().as_ref());
                rules_tables.push(vec![
                    "products".into(),
                    product.into(),
                    "keys".into(),
                    key.into(),
                    "rules".into(),
                ]);
            }
        }
    }
    for base in rules_tables {
        let mut path = base.clone();
        path.push("pattern".into());
        let path_refs: Vec<&str> = path.iter().map(String::as_str).collect();
        let Some(pattern) = doc.value(&path_refs).and_then(|v| v.get_ref().as_str()) else {
            continue;
        };
        let mut prefix = base.clone();
        prefix.push("ensure_prefix".into());
        let prefix_refs: Vec<&str> = prefix.iter().map(String::as_str).collect();
        let prefix = doc
            .value(&prefix_refs)
            .and_then(|v| v.get_ref().as_str())
            .unwrap_or_default();
        let regex = format!("{}(?:{pattern})", regex::escape(prefix));
        return Err(doc.invalid(
            &path_refs,
            FieldRule::RemovedForm {
                form: "pattern",
                replacement: format!("regex = {}", toml::Value::String(regex)),
            },
        ));
    }
    Ok(())
}

/// The inner table named `name`, if present (raw TOML lookup only; values are never read).
fn table<'a>(t: &'a DeTable<'a>, name: &str) -> Option<&'a DeTable<'a>> {
    t.iter()
        .find(|(n, _)| n.get_ref().as_ref() == name)
        .and_then(|(_, v)| v.get_ref().as_table())
}

/// The file as parsed TOML with source positions, so a provider section is read with its
/// place in the file and its errors point at the offending line (FR-2, FR-37).
struct Doc<'t> {
    text: &'t str,
    root: Spanned<DeTable<'t>>,
}

impl<'t> Doc<'t> {
    fn parse(text: &'t str) -> Result<Self, toml::de::Error> {
        Ok(Self {
            text,
            root: DeTable::parse(text)?,
        })
    }

    /// The place of the deepest declared part of `path` (its key's line and column).
    fn location(&self, path: &[&str]) -> Option<Location> {
        let mut table = Some(self.root.get_ref());
        let mut span = None;
        for part in path {
            let Some((n, v)) =
                table.and_then(|t| t.iter().find(|(n, _)| n.get_ref().as_ref() == *part))
            else {
                break;
            };
            span = Some(n.span());
            table = v.get_ref().as_table();
        }
        span.and_then(|s| location(self.text, s.start))
    }

    /// [`Cause::ConfigInvalid`] for the field `path`, placed at it (or at its deepest
    /// declared part), with `rule` from the check that refused it (audit 03.01).
    fn invalid(&self, path: &[&str], rule: FieldRule) -> Error {
        self.invalid_at(dotted(path), path, rule)
    }

    /// [`Doc::invalid`] for `field`, placed at `place` (when the field itself is not
    /// written, e.g. a template field a key's rendered name comes from).
    fn invalid_at(&self, field: DottedPath, place: &[&str], rule: FieldRule) -> Error {
        Cause::ConfigInvalid {
            source: parsing_source(),
            at: self.location(place),
            field,
            rule,
        }
        .into()
    }

    /// A provider section's refusal (C15): a [`Cause::ConfigInvalid`] that names its field
    /// within the section (`fly.app`, as [`section_invalid`] does) is named under the
    /// section's place `base` (`environments.prod.targets.web`) and placed at it. Every
    /// other error is returned unchanged.
    fn place(&self, e: Error, base: &[&str]) -> Error {
        let Some((
            Cause::ConfigInvalid {
                at: None,
                field,
                rule,
                ..
            },
            _,
        )) = e.cause()
        else {
            return e;
        };
        if field.0.first().map(String::as_str) == base.first().copied() {
            return e;
        }
        let under_base = |f: &DottedPath| {
            let mut full: Vec<String> = base.iter().map(|s| s.to_string()).collect();
            full.extend(f.0.iter().cloned());
            DottedPath(full)
        };
        // A field the rule names beside this one is in the same section.
        let rule = match rule {
            FieldRule::ConflictsWith { field: other } => FieldRule::ConflictsWith {
                field: under_base(other),
            },
            other => other.clone(),
        };
        let full = under_base(field);
        let full: Vec<&str> = full.0.iter().map(String::as_str).collect();
        self.invalid(&full, rule)
    }

    /// The value at `path`, with its place in the file.
    fn value(&self, path: &[&str]) -> Option<&Spanned<DeValue<'t>>> {
        let (first, rest) = path.split_first()?;
        let mut v = self
            .root
            .get_ref()
            .iter()
            .find(|(n, _)| n.get_ref().as_ref() == *first)
            .map(|(_, v)| v)?;
        for part in rest {
            v = v.get_ref().get(*part)?;
        }
        Some(v)
    }
}

/// A TOML parse or deserialize error as text that quotes nothing from `text` (C1, SR-1):
/// `TOML parse error at line L, column C` and the message with any quoted value removed.
/// Never `Display` a `toml` or `toml_edit` error: theirs prints the offending line.
pub fn toml_error(text: &str, span: Option<std::ops::Range<usize>>, message: &str) -> String {
    let msg = with_duplicate_key(text, span.clone(), sanitize_toml_message(message));
    match span.and_then(|s| line_column(text, s.start)) {
        Some((line, column)) => format!("TOML parse error at line {line}, column {column}\n{msg}"),
        None => msg,
    }
}

/// [`toml_error`] on one line: `line L, column C: message`.
pub fn toml_error_inline(
    text: &str,
    span: Option<std::ops::Range<usize>>,
    message: &str,
) -> String {
    let msg = with_duplicate_key(text, span.clone(), sanitize_toml_message(message));
    let msg = msg.split_whitespace().collect::<Vec<_>>().join(" ");
    match span.and_then(|s| line_column(text, s.start)) {
        Some((line, column)) => format!("line {line}, column {column}: {msg}"),
        None => msg,
    }
}

/// `duplicate key` names the key it points at: a key name is never a value, and only a
/// name of key characters (`[A-Za-z0-9_.-]`, at most 128) is shown.
fn with_duplicate_key(text: &str, span: Option<std::ops::Range<usize>>, msg: String) -> String {
    if msg != "duplicate key" {
        return msg;
    }
    let key = span
        .and_then(|s| text.get(s))
        .map(|k| k.trim_matches(|c| c == '"' || c == '\''));
    match key {
        Some(k)
            if !k.is_empty()
                && k.len() <= 128
                && k.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c)) =>
        {
            format!("duplicate key `{k}`")
        }
        _ => msg,
    }
}

/// 1-based line and column (in characters) of byte offset `at`.
fn line_column(text: &str, at: usize) -> Option<(usize, usize)> {
    let before = text.get(..at)?;
    let line = before.matches('\n').count() + 1;
    let start = before.rfind('\n').map_or(0, |i| i + 1);
    Some((line, before[start..].chars().count() + 1))
}

/// A parser or serde message with every quoted value dropped: serde's `invalid type:
/// string "…"` / `invalid value: …` quote the value they saw, which may be a secret. Field
/// and variant names (`unknown field `X``) stay: they name what to fix.
fn sanitize_toml_message(message: &str) -> String {
    static QUOTED: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(
            r#"(?s)\b(invalid (?:type|value|length): )([a-z ]+?)\s*(?:"(?:[^"\\]|\\.)*"|`[^`]*`|'[^']*')"#,
        )
        .expect("static regex")
    });
    QUOTED.replace_all(message.trim_end(), "$1$2").into_owned()
}

/// The names of the entries of the table at `path`, in file order (names only, never a
/// value).
fn table_keys<'d>(doc: &'d Doc<'_>, path: &[&str]) -> Vec<&'d str> {
    if path.is_empty() {
        return doc
            .root
            .get_ref()
            .iter()
            .map(|(n, _)| n.get_ref().as_ref())
            .collect();
    }
    match doc.value(path).map(|v| v.get_ref()) {
        Some(DeValue::Table(t)) => t.iter().map(|(n, _)| n.get_ref().as_ref()).collect(),
        _ => Vec::new(),
    }
}

/// Every removed configuration form fails here, before the typed parse, at its line and
/// column, naming the exact current form to write instead (FR-60). Nothing is converted.
fn removed_forms(doc: &Doc<'_>) -> Result<(), Error> {
    let removed = |path: &[&str], form: &'static str, replacement: String| {
        Err(doc.invalid(path, FieldRule::RemovedForm { form, replacement }))
    };
    let root = table_keys(doc, &[]);
    if root.contains(&"profile") {
        return removed(
            &["profile"],
            "[profile]",
            "one key per product, as [products.<name>.keys.<KEY>]".into(),
        );
    }
    if root.contains(&"keys") {
        let first = table_keys(doc, &["keys"])
            .first()
            .copied()
            .unwrap_or("<KEY>");
        return removed(
            &["keys"],
            "top-level [keys]",
            format!("[products.<name>.keys.{first}]"),
        );
    }
    for env in table_keys(doc, &["environments"]) {
        for field in table_keys(doc, &["environments", env]) {
            let path = ["environments", env, field];
            return match field {
                "vault_id" => removed(
                    &path,
                    "an environment's vault_id",
                    "one boundary per product, boundaries.<product> = { vault_id = \"...\", \
                     item_id = \"...\" } (opv apply records them)"
                        .into(),
                ),
                "item_id" => removed(
                    &path,
                    "an environment's item_id",
                    "one boundary per product, boundaries.<product> = { vault_id = \"...\", \
                     item_id = \"...\" } (opv apply records them)"
                        .into(),
                ),
                "deploy_credentials" => removed(
                    &path,
                    "an environment's deploy_credentials",
                    format!(
                        "deploy_credentials = \"...\" under [environments.{env}.targets.<name>]"
                    ),
                ),
                "state_vault_id" => removed(
                    &path,
                    "an environment's state_vault_id",
                    format!("state_vault_id = \"...\" under [environments.{env}.targets.<name>]"),
                ),
                section if registry::find(section).is_some() => {
                    let fields: Vec<String> = table_keys(doc, &["environments", env, section])
                        .iter()
                        .map(|f| format!("{section}.{f} = ..."))
                        .collect();
                    removed(
                        &path,
                        "an environment-level provider section",
                        format!(
                            "a named target, [environments.{env}.targets.<name>] with {}",
                            if fields.is_empty() {
                                format!("{section}.<field> = ...")
                            } else {
                                fields.join(", ")
                            }
                        ),
                    )
                }
                _ => continue,
            };
        }
        for target in table_keys(doc, &["environments", env, "targets"]) {
            let at = ["environments", env, "targets", target];
            for section in table_keys(doc, &at) {
                if registry::find(section).is_none() {
                    continue;
                }
                let path = [&at[..], &[section, "products"]].concat();
                if doc.value(&path).is_some() {
                    return removed(
                        &path,
                        "a provider section's products",
                        format!("targets.{target}.products = [...]"),
                    );
                }
            }
        }
    }
    Ok(())
}

/// product → mode name → mode value.
type FleetModes = BTreeMap<String, BTreeMap<String, String>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    environments: BTreeMap<String, RawEnvironment>,
    #[serde(default)]
    products: BTreeMap<String, Product>,
    /// Named stores (FR-39), parsed by the provider that declares their kind.
    #[serde(default)]
    stores: BTreeMap<String, toml::Value>,
}

/// One environment's generic fields.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEnvironment {
    /// boundary name → recorded vault and item (FR-57).
    #[serde(default)]
    boundaries: BTreeMap<String, RawBoundary>,
    /// target name → target (FR-56). Optional: environments used only for `run`,
    /// `config export` and `item skeleton` need no target.
    #[serde(default)]
    targets: BTreeMap<String, RawTarget>,
    #[serde(default)]
    modes: FleetModes,
    /// `sync` needs `--confirm <env>` (NR-20).
    #[serde(default)]
    confirm_env: bool,
    /// How far this environment's values may travel (FR-59); absent: derived from the
    /// name or title.
    #[serde(default)]
    tier: Option<Tier>,
    /// The 1Password account for this environment's `op` calls (FR-40).
    #[serde(default)]
    account: Option<String>,
    /// Display name, audience and order (FR-55).
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    audience: Option<String>,
    #[serde(default)]
    order: Option<i64>,
    /// Where each person's personal item lives (FR-55).
    #[serde(default)]
    personal_vault: Option<String>,
    #[serde(default)]
    personal_item: Option<String>,
}

/// `boundaries.<name> = { vault_id, item_id }` (FR-57).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBoundary {
    vault_id: String,
    item_id: String,
}

/// One named target (FR-56): its own options, and every other entry as a provider section.
#[derive(Deserialize)]
struct RawTarget {
    /// The products it delivers (FR-48).
    #[serde(default)]
    products: Option<Vec<String>>,
    /// The process roles this target serves (M3, §4.4). `None`: no scoping — every delivered
    /// key is delivered, as before — but a target that delivers a product whose keys declare
    /// roles must still declare `roles`. A key whose `roles` miss this target's is not
    /// desired here, so `--deploy --prune` removes an existing binding.
    #[serde(default)]
    roles: Option<Vec<String>>,
    /// `op://<vault>/<item>` holding the target's deploy identity (FR-40).
    #[serde(default)]
    deploy_credentials: Option<String>,
    /// The vault holding the target's delivery evidence (FR-58); required (D12).
    #[serde(default)]
    state_vault_id: Option<String>,
    /// product → its delivery item's ID in the state vault (FR-58), recorded by bootstrap.
    #[serde(default)]
    delivery_items: Option<BTreeMap<String, String>>,
    /// Exactly one provider section (FR-28).
    #[serde(flatten)]
    sections: BTreeMap<String, toml::Value>,
}

/// The named stores of a file (FR-39), by name.
type Stores = BTreeMap<String, Box<dyn StoreConfig>>;

/// Every `[stores.<name>]` table, parsed by the provider that declares its kind (FR-39). The
/// kind is the key that names it (`azure_key_vault = "..."`). A store name is a DNS label,
/// so it can name in-cluster objects as it is.
fn stores(raw: &BTreeMap<String, toml::Value>, doc: &Doc<'_>) -> Result<Stores, Error> {
    let mut out = Stores::new();
    for (name, value) in raw {
        let path = ["stores", name.as_str()];
        if !is_store_name(name) {
            return Err(doc.invalid(
                &path,
                FieldRule::Pattern {
                    id: PatternId::StoreName,
                },
            ));
        }
        let known: Vec<String> = registry::store_kinds()
            .iter()
            .map(|k| k.to_string())
            .collect();
        let Some(table) = value.as_table() else {
            return Err(doc.invalid(
                &path,
                FieldRule::Type {
                    expected: "a table",
                },
            ));
        };
        let kinds: Vec<&str> = table
            .keys()
            .map(String::as_str)
            .filter(|k| registry::store_kind(k).is_some())
            .collect();
        let kind = match kinds.as_slice() {
            [kind] => *kind,
            [] => {
                return Err(doc.invalid(&path, check(ConfigCheck::NoStoreKind { known })));
            }
            [a, b, ..] => {
                return Err(doc.invalid(
                    &["stores", name, a],
                    FieldRule::ConflictsWith {
                        field: dotted(&["stores", name, b]),
                    },
                ));
            }
        };
        let provider = registry::store_kind(kind).expect("kind found above");
        let value = doc
            .value(&path)
            .ok_or_else(|| doc.invalid(&path, FieldRule::Missing))?;
        let store = provider
            .parse_store(kind, &Section::new(name, value, doc.text))
            .map_err(|e| doc.place(e, &["stores", name]))?;
        out.insert(name.clone(), store);
    }
    Ok(out)
}

/// A store name: a DNS-1123 label.
fn is_store_name(s: &str) -> bool {
    let b = s.as_bytes();
    let alnum = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    (1..=63).contains(&b.len())
        && b.iter().all(|c| alnum(c) || *c == b'-')
        && b.first().is_some_and(alnum)
        && b.last().is_some_and(alnum)
}

/// The field of `t`'s provider section whose template renders the names the target manages,
/// for the fixes that name it (03.17): the provider's own `<x>_name` option (core names no
/// provider, FR-37), or the section itself when it declares none.
fn template_path<'a>(env: &'a str, target: &'a str, t: &'a dyn TargetConfig) -> Vec<&'a str> {
    let provider = t.provider();
    let mut path = vec!["environments", env, "targets", target, provider.section()];
    if let Some(f) = provider
        .init_fields()
        .iter()
        .find(|f| f.field.ends_with("_name"))
    {
        path.push(f.field);
    }
    path
}

/// A target's provider section, parsed by its provider (FR-28, FR-37): an unknown section
/// names the registered ones; none or two are refused. `secrets_in` binds it to a named
/// store when the registry declares the pair (FR-39).
fn target_of(
    env: &str,
    name: &str,
    sections: &BTreeMap<String, toml::Value>,
    stores: &Stores,
    doc: &Doc<'_>,
) -> Result<Box<dyn TargetConfig>, Error> {
    let base = ["environments", env, "targets", name];
    let known: Vec<&str> = registry::sections();
    if let Some((unknown, _)) = sections.iter().find(|(s, _)| registry::find(s).is_none()) {
        let mut allowed = vec!["products", "deploy_credentials", "state_vault_id"];
        allowed.extend(known.iter().copied());
        return Err(doc.invalid(
            &[&base[..], &[unknown.as_str()]].concat(),
            FieldRule::Unknown {
                suggestion: closest(unknown, allowed),
            },
        ));
    }
    let present: Vec<_> = registry::PROVIDERS
        .iter()
        .filter(|p| sections.contains_key(p.section()))
        .collect();
    let p = match present.as_slice() {
        [p] => p,
        [] => {
            return Err(doc.invalid(
                &base,
                check(ConfigCheck::NoProvider {
                    known: known.iter().map(|k| k.to_string()).collect(),
                }),
            ));
        }
        [a, b, ..] => {
            return Err(doc.invalid(
                &[&base[..], &[b.section()]].concat(),
                FieldRule::ConflictsWith {
                    field: dotted(&[&base[..], &[a.section()]].concat()),
                },
            ));
        }
    };
    let section = p.section();
    let section_path = [&base[..], &[section]].concat();
    let value = doc
        .value(&section_path)
        .ok_or_else(|| doc.invalid(&section_path, FieldRule::Missing))?;
    // `secrets_in` is generic (FR-39): taken out here, the rest goes to the provider.
    let mut rest = value.clone();
    let secrets_in = match rest.get_mut() {
        DeValue::Table(t) => t.remove("secrets_in"),
        _ => None,
    };
    let target = p
        .parse(&Section::new(env, &rest, doc.text))
        .map_err(|e| doc.place(e, &base))?;
    let Some(secrets_in) = secrets_in else {
        return Ok(target);
    };
    let path = [&base[..], &[section, "secrets_in"]].concat();
    let Some(store_name) = secrets_in.get_ref().as_str() else {
        return Err(doc.invalid(
            &path,
            FieldRule::Type {
                expected: "the name of a [stores.<name>] table",
            },
        ));
    };
    let Some(store) = stores.get(store_name) else {
        return Err(doc.invalid(
            &path,
            undeclared(
                Declared::Store,
                store_name,
                stores.keys().map(String::as_str),
            ),
        ));
    };
    if !registry::binds(section, store.kind()) {
        return Err(doc.invalid(
            &path,
            check(ConfigCheck::StoreBinding {
                section: section.to_string(),
                kind: store.kind().to_string(),
                supported: registry::supported_pairs(),
            }),
        ));
    }
    p.bind(target, store.as_ref())
        .map_err(|e| doc.place(e, &base))
}

/// One identifier at `path`: non-empty, unpadded, and accepted by `ok` (safe in argv).
fn ident(
    doc: &Doc<'_>,
    path: &[&str],
    value: &str,
    ok: fn(&str) -> bool,
    pattern: PatternId,
) -> Result<(), Error> {
    if value.trim().is_empty() {
        return Err(doc.invalid(path, FieldRule::Empty));
    }
    if value.trim() != value {
        return Err(doc.invalid(path, check(ConfigCheck::Whitespace)));
    }
    if !ok(value) {
        return Err(doc.invalid(path, FieldRule::Pattern { id: pattern }));
    }
    Ok(())
}

/// Validate one environment's generic fields, its boundaries and its targets.
fn environment(
    name: &str,
    e: RawEnvironment,
    stores: &Stores,
    doc: &Doc<'_>,
) -> Result<Environment, Error> {
    if let Some(account) = &e.account
        && !is_account(account)
    {
        return Err(doc.invalid(
            &["environments", name, "account"],
            FieldRule::Pattern {
                id: PatternId::Account,
            },
        ));
    }
    let tier = match e.tier {
        Some(tier) => tier,
        None => crate::domain::health::default_tier(name, e.title.as_deref()),
    };
    if tier == Tier::Local {
        if !e.targets.is_empty() {
            return Err(doc.invalid(
                &["environments", name, "tier"],
                FieldRule::ConflictsWith {
                    field: DottedPath(vec!["targets".into()]),
                },
            ));
        }
        if e.confirm_env {
            return Err(doc.invalid(
                &["environments", name, "tier"],
                FieldRule::ConflictsWith {
                    field: DottedPath(vec!["confirm_env".into()]),
                },
            ));
        }
    }
    let mut boundaries = BTreeMap::new();
    for (b, raw) in e.boundaries {
        let path = ["environments", name, "boundaries", b.as_str()];
        if !is_product_name(&b) {
            return Err(doc.invalid(
                &path,
                FieldRule::Pattern {
                    id: PatternId::ProductName,
                },
            ));
        }
        for (field, value) in [("vault_id", &raw.vault_id), ("item_id", &raw.item_id)] {
            ident(
                doc,
                &[&path[..], &[field]].concat(),
                value,
                is_id,
                PatternId::Id,
            )?;
        }
        boundaries.insert(
            b,
            Boundary {
                vault_id: raw.vault_id,
                item_id: raw.item_id,
            },
        );
    }
    let mut targets = BTreeMap::new();
    for (t, raw) in e.targets {
        let target = target(name, &t, raw, stores, doc)?;
        targets.insert(t, target);
    }
    Ok(Environment {
        name: name.to_string(),
        tier,
        boundaries,
        targets,
        modes: e.modes,
        confirm_env: e.confirm_env,
        account: e.account,
        account_from: None,
        title: e.title,
        audience: e.audience,
        order: e.order,
        personal_vault: e.personal_vault,
        personal_item: e.personal_item,
    })
}

/// A target name: `^[a-z][a-z0-9-]*$` (FR-56).
pub(crate) fn is_target_name(s: &str) -> bool {
    let mut c = s.chars();
    matches!(c.next(), Some('a'..='z'))
        && c.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
}

/// One named target (FR-56): its name, its one provider section, `products`,
/// `deploy_credentials` and the required `state_vault_id` (FR-58, D12).
fn target(
    env: &str,
    name: &str,
    raw: RawTarget,
    stores: &Stores,
    doc: &Doc<'_>,
) -> Result<Target, Error> {
    let base = ["environments", env, "targets", name];
    if !is_target_name(name) {
        return Err(doc.invalid(
            &base,
            FieldRule::Pattern {
                id: PatternId::TargetName,
            },
        ));
    }
    let config = target_of(env, name, &raw.sections, stores, doc)?;
    if raw.products.as_ref().is_some_and(Vec::is_empty) {
        return Err(doc.invalid(
            &[&base[..], &["products"]].concat(),
            check(ConfigCheck::EmptyProducts),
        ));
    }
    let deploy_credentials = match &raw.deploy_credentials {
        None => None,
        Some(r) => Some(deploy_credentials(env, name, r, config.as_ref(), doc)?),
    };
    let Some(state_vault_id) = raw.state_vault_id else {
        return Err(Cause::StateVaultMissing {
            env: crate::cause::EnvName::new(env),
            target: crate::cause::TargetName::new(name),
            source: parsing_source(),
        }
        .into());
    };
    ident(
        doc,
        &[&base[..], &["state_vault_id"]].concat(),
        &state_vault_id,
        is_id,
        PatternId::Id,
    )?;
    let delivery_items = raw.delivery_items.unwrap_or_default();
    for (product, id) in &delivery_items {
        ident(
            doc,
            &[&base[..], &["delivery_items", product.as_str()]].concat(),
            id,
            is_id,
            PatternId::Id,
        )?;
    }
    Ok(Target {
        name: name.to_string(),
        config,
        products: raw.products,
        roles: raw.roles,
        deploy_credentials,
        state_vault_id,
        delivery_items,
    })
}

/// A target's `deploy_credentials` (FR-40): an `op://<vault>/<item>` reference, on a target
/// whose provider signs in with one. Errors point at the line.
fn deploy_credentials(
    env: &str,
    name: &str,
    raw: &str,
    target: &dyn TargetConfig,
    doc: &Doc<'_>,
) -> Result<ItemRef, Error> {
    let path = ["environments", env, "targets", name, "deploy_credentials"];
    let reference = ItemRef::parse(raw)
        .map_err(|_| doc.invalid(&path, check(ConfigCheck::DeployCredentialsRef)))?;
    crate::provider::deploy_provider(target)
        .deploy_credential_fields()
        .map_err(|_| {
            doc.invalid(
                &path,
                check(ConfigCheck::DeployCredentialsUnsupported {
                    provider: target.provider().label().to_string(),
                }),
            )
        })?;
    Ok(reference)
}

/// A sign-in address (`my.1password.com`), email or account ID: non-empty, no whitespace,
/// not starting with `-`, and only characters those forms use (safe in env and argv).
pub(crate) fn is_account(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@' | '+'))
}

fn validate(raw: RawConfig, doc: &Doc<'_>) -> Result<Fleet, Error> {
    if raw.environments.is_empty() {
        return Err(doc.invalid(&["environments"], FieldRule::NoEnvironment));
    }

    let stores = stores(&raw.stores, doc)?;
    let mut environments = BTreeMap::new();
    for (name, e) in raw.environments {
        let env = environment(&name, e, &stores, doc)?;
        environments.insert(name, env);
    }
    check_shared_targets(&environments, doc)?;

    for (product, p) in &raw.products {
        if !is_product_name(product) {
            return Err(doc.invalid(
                &["products", product],
                FieldRule::Pattern {
                    id: PatternId::ProductName,
                },
            ));
        }
        if let Some(b) = &p.boundary
            && !is_product_name(b)
        {
            return Err(doc.invalid(
                &["products", product, "boundary"],
                FieldRule::Pattern {
                    id: PatternId::ProductName,
                },
            ));
        }
        if p.source_only && p.keys.is_empty() {
            return Err(doc.invalid(
                &["products", product, "source_only"],
                check(ConfigCheck::SourceOnlyWithoutKeys {
                    product: product.clone(),
                }),
            ));
        }
        for (key, spec) in &p.keys {
            validate_key(doc, product, key, spec, &environments)?;
        }
        validate_local(doc, product, p)?;
        validate_remotes(doc, product, p, &environments)?;
        validate_ignore(doc, product, p)?;
    }

    let mut products = raw.products;
    check_shared(&mut products, &environments, doc)?;
    let fleet = Fleet {
        environments,
        products,
        origin: Default::default(),
        read_from: Default::default(),
    };
    check_scopes(&fleet, doc)?;
    check_boundaries(&fleet, doc)?;
    check_target_roles(&fleet, doc)?;
    check_file_mounts(&fleet, doc)?;
    check_names(&fleet, doc)?;
    check_personal(&fleet, doc)?;
    check_evidence_width(&fleet, doc)?;
    check_delivery_items(&fleet, doc)?;
    Ok(fleet)
}

/// Ignore annotations (Part V, row `annotations`): a scanner-observed name a person judged
/// a false positive. Its name is key-shaped (`^[A-Z][A-Z0-9_]*$`, the scanner's grammar)
/// and its reason must say something (D-G: refused, not a finding). The span is left as the
/// scanner recorded it: it is a stable hash of the evidence line, never a value.
fn validate_ignore(doc: &Doc<'_>, product: &str, p: &crate::domain::Product) -> Result<(), Error> {
    for (name, annotation) in &p.ignore {
        if !is_env_name(name) {
            return Err(doc.invalid(
                &["products", product, "ignore", name],
                FieldRule::Pattern {
                    id: PatternId::KeyName,
                },
            ));
        }
        if annotation.reason.trim().is_empty() {
            return Err(doc.invalid(
                &["products", product, "ignore", name, "reason"],
                FieldRule::Empty,
            ));
        }
    }
    Ok(())
}

/// A process role name (M3, #136): `^[a-z0-9-]{1,32}$`, so a shell never has to quote it.
fn is_role_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Target-level process roles (M3, §4.4). A target that delivers a product whose keys
/// declare roles must also declare `roles`; every declared role must be a valid role and be
/// declared by a key of a product the target delivers (product-wide: a role says which
/// process a key is for, whichever environment it is desired in). A target with no such
/// product is unchanged.
fn check_target_roles(fleet: &Fleet, doc: &Doc<'_>) -> Result<(), Error> {
    for (env_name, env) in &fleet.environments {
        for (name, target) in &env.targets {
            let path = ["environments", env_name, "targets", name, "roles"];
            let mut declared: BTreeSet<&str> = BTreeSet::new();
            let mut role_scoped = false;
            for (product, p) in &fleet.products {
                if !fleet.delivers(env_name, name, product) {
                    continue;
                }
                for spec in p.keys.values() {
                    if let Some(roles) = &spec.roles {
                        role_scoped = true;
                        declared.extend(roles.iter().map(String::as_str));
                    }
                }
            }
            match &target.roles {
                None if role_scoped => {
                    return Err(doc.invalid(&path, FieldRule::Missing));
                }
                None => {}
                Some(roles) => {
                    if roles.is_empty() {
                        return Err(doc.invalid(&path, check(ConfigCheck::EmptyRoles)));
                    }
                    if roles.iter().any(|r| !is_role_name(r)) {
                        return Err(doc.invalid(
                            &path,
                            FieldRule::Pattern {
                                id: PatternId::RoleName,
                            },
                        ));
                    }
                    if let Some(x) = roles.iter().find(|r| !declared.contains(r.as_str())) {
                        return Err(doc.invalid(
                            &path,
                            undeclared(Declared::Role, x, declared.iter().copied()),
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

/// `secrets_dir` mount rules (design §6.2): the file keys of two products must land in
/// distinct directories, a config key with `file` needs a config object, and one product's
/// file paths must not nest. Targets without a native file capability are unchanged.
fn check_file_mounts(fleet: &Fleet, doc: &Doc<'_>) -> Result<(), Error> {
    for (env_name, env) in &fleet.environments {
        for (target_name, target) in &env.targets {
            let channels = target.config.channels();
            let FileCapability::Native { dir } = &channels.files else {
                continue;
            };
            let section = target.config.provider().section();
            let dir_path = [
                "environments",
                env_name,
                "targets",
                target_name,
                section,
                "secrets_dir",
            ];
            let config_path = [
                "environments",
                env_name,
                "targets",
                target_name,
                section,
                "config",
            ];
            // The directory each product with a file key renders, in product order.
            let mut rendered: Vec<(String, String, String)> = Vec::new();
            for (product, p) in &fleet.products {
                if !fleet.delivers(env_name, target_name, product) {
                    continue;
                }
                let mut files: Vec<(&str, &str)> = Vec::new();
                for (key, spec) in &p.keys {
                    if !spec.is_desired_in(env_name) {
                        continue;
                    }
                    let Some(file) = spec.file.as_deref() else {
                        continue;
                    };
                    if spec.kind == Kind::Config && matches!(channels.config, Channel::RuntimeEnv) {
                        return Err(doc.invalid(
                            &config_path,
                            check(ConfigCheck::ConfigFileNeedsObject {
                                key: format!("{product}/{key}"),
                            }),
                        ));
                    }
                    files.push((key.as_str(), file));
                }
                // (d) Within one product, no `file` is a parent of another's.
                let mut seen: Vec<(&str, &str)> = Vec::new();
                for (key, file) in &files {
                    if let Some((other_key, parent)) = seen.iter().find(|(_, o)| {
                        *o == *file
                            || file.starts_with(&format!("{o}/"))
                            || o.starts_with(&format!("{file}/"))
                    }) {
                        return Err(doc.invalid(
                            &["products", product, "keys", key, "file"],
                            FieldRule::Collision {
                                rendered: parent.to_string(),
                                other: dotted(&["products", product, "keys", other_key, "file"]),
                            },
                        ));
                    }
                    seen.push((key, file));
                }
                if files.is_empty() {
                    continue;
                }
                // (a) and (b): two products may not render the same directory.
                let rendered_dir = dir.replace("{product}", &product.replace('_', "-"));
                if let Some((_, other, other_key)) =
                    rendered.iter().find(|(d, ..)| d == &rendered_dir)
                {
                    return Err(doc.invalid(
                        &dir_path,
                        FieldRule::Collision {
                            rendered: rendered_dir.clone(),
                            other: dotted(&["products", other, "keys", other_key, "file"]),
                        },
                    ));
                }
                rendered.push((rendered_dir, product.clone(), files[0].0.to_string()));
            }
        }
    }
    Ok(())
}

/// FR-58: a recorded delivery item belongs to a product its target delivers; any other
/// entry names evidence nothing writes or reads, and is refused (FR-60).
fn check_delivery_items(fleet: &Fleet, doc: &Doc<'_>) -> Result<(), Error> {
    for (env_name, env) in &fleet.environments {
        for (name, target) in &env.targets {
            for product in target.delivery_items.keys() {
                if !fleet.delivers(env_name, name, product) {
                    return Err(doc.invalid(
                        &[
                            "environments",
                            env_name,
                            "targets",
                            name,
                            "delivery_items",
                            product,
                        ],
                        check(ConfigCheck::DeliveryItemUndelivered {
                            product: product.clone(),
                        }),
                    ));
                }
            }
        }
    }
    Ok(())
}

/// FR-58 (D12): a state vault shared by several targets is never readable more widely than
/// the values its evidence describes (`state_vault_wider_than_values`).
/// Each target reads the boundaries of the products it delivers and of their `from`
/// sources (FR-59), named `<boundary> (<vault id>)` so boundaries of different environments
/// never compare equal. Placed at the target's `state_vault_id` (audit 03.04).
fn check_evidence_width(fleet: &Fleet, doc: &Doc<'_>) -> Result<(), Error> {
    use crate::domain::placement::{TargetReads, wider_than_values};
    let mut reads: Vec<(&str, &str, &str, BTreeSet<String>)> = Vec::new();
    for (env_name, env) in &fleet.environments {
        for (name, target) in &env.targets {
            let mut boundaries = BTreeSet::new();
            for (product, p) in &fleet.products {
                if !fleet.delivers(env_name, name, product) {
                    continue;
                }
                let desired = p.keys.values().filter(|k| k.is_desired_in(env_name));
                for k in desired {
                    let source = k.source().map_or(product.as_str(), |(sp, _)| sp);
                    for needer in [product.as_str(), source] {
                        let b = fleet.boundary_of(needer);
                        if let Some(at) = env.boundaries.get(b) {
                            boundaries.insert(format!("{b} ({})", at.vault_id));
                        }
                    }
                }
            }
            reads.push((env_name, name, &target.state_vault_id, boundaries));
        }
    }
    let targets: Vec<TargetReads<'_>> = reads
        .iter()
        .map(|(environment, target, vault, boundaries)| TargetReads {
            environment,
            target,
            state_vault_id: vault,
            boundaries: boundaries.iter().map(String::as_str).collect(),
        })
        .collect();
    match wider_than_values(&targets).first() {
        Some(w) => Err(Cause::StateVaultTooWide {
            env: crate::cause::EnvName::new(w.environment.as_str()),
            target: crate::cause::TargetName::new(w.target.as_str()),
            vault: crate::cause::VaultId::new(w.state_vault_id.as_str()),
            shared_with: w
                .targets
                .iter()
                .filter(|t| **t != format!("{}/{}", w.environment, w.target))
                .map(|t| crate::cause::TargetName::new(t.as_str()))
                .collect(),
            source: parsing_source(),
            at: doc.location(&[
                "environments",
                &w.environment,
                "targets",
                &w.target,
                "state_vault_id",
            ]),
        }
        .into()),
        None => Ok(()),
    }
}

/// FR-57: every boundary [`Fleet::needed_boundaries`] names is recorded in its environment
/// (personal keys live in each person's own item, FR-55, so they need none)
/// ([`Cause::BoundaryMissing`]); a recorded boundary no such product uses is refused, so the
/// configuration never names a vault nothing reads.
fn check_boundaries(fleet: &Fleet, doc: &Doc<'_>) -> Result<(), Error> {
    for (env_name, env) in &fleet.environments {
        let needed = fleet.needed_boundaries(env_name);
        if let Some((_, needer)) = needed
            .iter()
            .find(|(b, _)| !env.boundaries.contains_key(**b))
        {
            return Err(boundary_missing(env_name, needer, parsing_source()).into());
        }
        if let Some(b) = env
            .boundaries
            .keys()
            .find(|b| !needed.contains_key(b.as_str()))
        {
            let products = fleet
                .products
                .keys()
                .filter(|p| fleet.boundary_of(p) == b.as_str())
                .cloned()
                .collect();
            return Err(doc.invalid(
                &["environments", env_name, "boundaries", b],
                check(ConfigCheck::BoundaryUnused {
                    env: env_name.clone(),
                    products,
                }),
            ));
        }
    }
    Ok(())
}

/// FR-55: a personal key lives only in environments without a target (it is never
/// deployed), and personal and team values never meet through `from`: a personal key's
/// source is personal, a team key's source is not.
fn check_personal(fleet: &Fleet, doc: &Doc<'_>) -> Result<(), Error> {
    for (product, p) in &fleet.products {
        for (key, spec) in &p.keys {
            if spec.personal
                && let Some(env) = spec.envs_in(fleet).into_iter().find(|e| {
                    fleet
                        .environments
                        .get(e)
                        .is_some_and(|x| !x.targets.is_empty())
                })
            {
                return Err(doc.invalid(
                    &["products", product, "keys", key, "personal"],
                    check(ConfigCheck::PersonalOnTarget { env: env.clone() }),
                ));
            }
            if let Some((sp, sk)) = spec.source() {
                let src_personal = fleet
                    .products
                    .get(sp)
                    .and_then(|x| x.keys.get(sk))
                    .is_some_and(|x| x.personal);
                if src_personal != spec.personal {
                    return Err(doc.invalid(
                        &["products", product, "keys", key, "from"],
                        check(ConfigCheck::PersonalMix {
                            source: key_label(sp, sk),
                            personal: spec.personal,
                        }),
                    ));
                }
            }
        }
    }
    Ok(())
}

/// FR-48: every product a target is limited to is declared and delivers its own keys (not
/// source-only), so a misspelt name can never silently deliver nothing.
fn check_scopes(fleet: &Fleet, doc: &Doc<'_>) -> Result<(), Error> {
    for (env_name, env) in &fleet.environments {
        for (name, t) in &env.targets {
            let Some(listed) = &t.products else {
                continue;
            };
            let path = ["environments", env_name, "targets", name, "products"];
            for p in listed {
                match fleet.products.get(p) {
                    None => {
                        return Err(doc.invalid(
                            &path,
                            undeclared(
                                Declared::Product,
                                p,
                                fleet.products.keys().map(String::as_str),
                            ),
                        ));
                    }
                    Some(prod) if prod.source_only => {
                        return Err(doc.invalid(
                            &path,
                            check(ConfigCheck::SourceOnlyListed { product: p.clone() }),
                        ));
                    }
                    Some(_) => {}
                }
            }
        }
    }
    Ok(())
}

/// One identifier: non-empty, unpadded, and accepted by `ok` (safe in argv). For the
/// providers' section parsers (C15): the refusal is a typed [`Cause::ConfigInvalid`] for
/// `field` within the section (`fly.app`); the loader places it under the section's path and
/// names the real source ([`Doc::place`]). `shape` is the allowed form in words; the shared
/// ID form is [`PatternId::Id`]. `_env` is the environment (the loader's path names it).
pub(crate) fn check_ident(
    _env: &str,
    field: &str,
    value: &str,
    ok: fn(&str) -> bool,
    shape: &'static str,
) -> Result<(), Error> {
    let rule = if value.trim().is_empty() {
        FieldRule::Empty
    } else if value.trim() != value {
        check(ConfigCheck::Whitespace)
    } else if !ok(value) {
        match shape {
            ID_SHAPE => FieldRule::Pattern { id: PatternId::Id },
            words => FieldRule::Type { expected: words },
        }
    } else {
        return Ok(());
    };
    Err(section_invalid(field, rule))
}

/// A provider's env-name template, in words (`fly.secret_name`, `kubernetes.env_name`).
pub(crate) const TEMPLATE_WORDS: &str =
    "a template containing {KEY}, such as \"FLEET__{PRODUCT}__{KEY}\" or \"{KEY}\"";

/// The ID form providers check with [`check_ident`] (Azure and Fly names).
pub(crate) const ID_SHAPE: &str = "^[A-Za-z0-9][A-Za-z0-9._-]*$";

/// [`Cause::ConfigInvalid`] for `field` within a provider section (`github.repo`): the
/// loader places it under the section's path ([`Doc::place`]) and names the source (C15).
pub(crate) fn section_invalid(field: &str, rule: FieldRule) -> Error {
    Cause::ConfigInvalid {
        source: parsing_source(),
        at: None,
        field: DottedPath(field.split('.').map(str::to_string).collect()),
        rule,
    }
    .into()
}

/// The SSH host key types a pinned `host_key` may name (#139), as `known_hosts` spells them.
const HOST_KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
];

/// A remote path pinned in a profile (#139): absolute, no `..` component, and only
/// characters that need no quoting in any shell (`[A-Za-z0-9._/+-]`).
pub(crate) fn is_remote_path(s: &str) -> bool {
    s.starts_with('/')
        && s.len() <= 255
        && s.split('/').all(|c| c != "..")
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '+' | '-'))
}

/// `[products.<p>.remotes.<name>]` (#139): every pinned field is checked at load, so a
/// profile that could reach the shell, an unknown environment or an undeclared role never
/// loads.
fn validate_remotes(
    doc: &Doc<'_>,
    product: &str,
    p: &crate::domain::Product,
    environments: &BTreeMap<String, crate::domain::Environment>,
) -> Result<(), Error> {
    let declared = crate::app::delivery_preview::declared_roles(p);
    for (name, r) in &p.remotes {
        let base = ["products", product, "remotes", name.as_str()];
        let invalid = |field: &'static str, rule: FieldRule| {
            Err(doc.invalid(&[&base[..], &[field]].concat(), rule))
        };
        let pattern = |id: PatternId| FieldRule::Pattern { id };
        let name_ok = name.len() <= 32
            && name.starts_with(|c: char| c.is_ascii_lowercase())
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if !name_ok {
            return Err(doc.invalid(&base, pattern(PatternId::RemoteName)));
        }
        let host_ok = !r.host.is_empty()
            && r.host.len() <= 253
            && !r.host.starts_with('-')
            && r.host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'));
        if !host_ok {
            return invalid("host", pattern(PatternId::RemoteHost));
        }
        if r.port == 0 {
            return invalid(
                "port",
                FieldRule::Type {
                    expected: "a port number from 1 to 65535",
                },
            );
        }
        let user_ok = r.user.len() <= 32
            && r.user
                .starts_with(|c: char| c.is_ascii_lowercase() || c == '_')
            && r.user.chars().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-' | '.')
            });
        if !user_ok {
            return invalid("user", pattern(PatternId::RemoteUser));
        }
        let key_ok = match r.host_key.split(' ').collect::<Vec<_>>().as_slice() {
            [ty, b64] => {
                HOST_KEY_TYPES.contains(ty)
                    && (16..=4096).contains(&b64.len())
                    && b64
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
            }
            _ => false,
        };
        if !key_ok {
            return invalid("host_key", pattern(PatternId::HostKey));
        }
        if r.environments.is_empty() {
            return invalid("environments", check(ConfigCheck::EmptyRemoteEnvironments));
        }
        if let Some(e) = r
            .environments
            .iter()
            .find(|e| !environments.contains_key(*e))
        {
            return invalid(
                "environments",
                undeclared(
                    Declared::Environment,
                    e,
                    environments.keys().map(String::as_str),
                ),
            );
        }
        // O9: a remote profile reaches a host over SSH by pinning a host, a user and a
        // command; a deployed environment's values must reach it only through the CI sync,
        // so a profile may name only environments with no deployment target.
        if let Some((env, target)) = r.environments.iter().find_map(|e| {
            let env = environments.get(e)?;
            let target = env.targets.keys().next()?;
            Some((e, target))
        }) {
            return invalid(
                "environments",
                check(ConfigCheck::RemoteEnvironmentHasTarget {
                    profile: name.clone(),
                    env: env.clone(),
                    target: target.clone(),
                }),
            );
        }
        if let Some(roles) = &r.roles {
            if roles.is_empty() {
                return invalid("roles", check(ConfigCheck::EmptyRemoteRoles));
            }
            if let Some(x) = roles.iter().find(|x| !declared.contains(&x.as_str())) {
                return invalid(
                    "roles",
                    undeclared(Declared::Role, x, declared.iter().copied()),
                );
            }
        }
        for (field, v) in [("opv", &r.opv), ("workdir", &r.workdir)] {
            if !is_remote_path(v) {
                return invalid(field, pattern(PatternId::RemotePath));
            }
        }
        if r.command.is_empty() {
            return invalid("command", FieldRule::Empty);
        }
        if r.command
            .iter()
            .any(|a| a.len() > 4096 || crate::app::remote_delivery::has_control(a))
        {
            return invalid("command", check(ConfigCheck::CommandArguments));
        }
        if let Some(f) = &r.identity_file
            && (f.is_empty() || f.chars().any(char::is_control))
        {
            return invalid(
                "identity_file",
                FieldRule::Type {
                    expected: "a file path",
                },
            );
        }
    }
    Ok(())
}

/// The names `local.secrets_dir_env` may not take: the 1Password CLI's own environment.
const RESERVED_DIR_ENV: [&str; 4] = ["PATH", "HOME", "XDG_CONFIG_HOME", "OP_*"];

/// `[products.<p>.local]` and the keys' `file` paths (#136, #137): the directory variable
/// is a plain, unreserved name; each path is relative, at most four `/`-separated
/// components matching `^[a-z0-9]+(-[a-z0-9]+)*$`, unique, and never inside another key's
/// file.
fn validate_local(doc: &Doc<'_>, product: &str, p: &crate::domain::Product) -> Result<(), Error> {
    let files: Vec<(&String, &str)> = p
        .keys
        .iter()
        .filter_map(|(k, spec)| spec.file.as_deref().map(|f| (k, f)))
        .collect();
    let dir_path = ["products", product, "local", "secrets_dir_env"];
    let dir_env = p.local.as_ref().and_then(|l| l.secrets_dir_env.as_deref());
    if let Some(v) = dir_env {
        // Split by cause (audit 03.01): the shape, a reserved name, or one of its keys.
        if !is_env_name(v) {
            return Err(doc.invalid(
                &dir_path,
                FieldRule::Pattern {
                    id: PatternId::KeyName,
                },
            ));
        }
        if matches!(v, "PATH" | "HOME" | "XDG_CONFIG_HOME") || v.starts_with("OP_") {
            return Err(doc.invalid(
                &dir_path,
                FieldRule::Reserved {
                    set: RESERVED_DIR_ENV.iter().map(|s| s.to_string()).collect(),
                },
            ));
        }
        if p.keys.contains_key(v) {
            return Err(doc.invalid(
                &dir_path,
                FieldRule::ConflictsWith {
                    field: dotted(&["products", product, "keys", v]),
                },
            ));
        }
        if files.is_empty() {
            return Err(doc.invalid(&dir_path, check(ConfigCheck::DirEnvWithoutFiles)));
        }
    }
    let segment = |s: &str| {
        s.split('-').all(|p| {
            !p.is_empty()
                && p.chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit())
        })
    };
    let mut seen: Vec<(&str, &str)> = Vec::new();
    for (key, path) in &files {
        let file_path = ["products", product, "keys", key.as_str(), "file"];
        // A product without a `[products.<p>.local]` section runs nowhere locally; its file
        // keys are delivered by a target's own filesystem (a target's `secrets_dir`,
        // design §6.2, checked by `check_file_mounts`), so only the path rules apply.
        if dir_env.is_none() && p.local.is_some() {
            return Err(doc.invalid_at(dotted(&dir_path), &file_path, FieldRule::Missing));
        }
        let parts: Vec<&str> = path.split('/').collect();
        if path.len() > 128 || parts.len() > 4 || !parts.iter().all(|c| segment(c)) {
            return Err(doc.invalid(
                &file_path,
                FieldRule::Pattern {
                    id: PatternId::LocalFile,
                },
            ));
        }
        if let Some((other_key, other)) = seen.iter().find(|(_, o)| {
            *o == *path || path.starts_with(&format!("{o}/")) || o.starts_with(&format!("{path}/"))
        }) {
            return Err(doc.invalid(
                &file_path,
                FieldRule::Collision {
                    rendered: other.to_string(),
                    other: dotted(&["products", product, "keys", other_key, "file"]),
                },
            ));
        }
        seen.push((key.as_str(), path));
    }
    Ok(())
}

/// The names a key may not take: `run` removes every declared name from the inherited
/// environment (#53), so a key named after `op`'s own context would strip it.
const RESERVED_KEYS: [&str; 4] = ["PATH", "HOME", "XDG_CONFIG_HOME", "OP_*"];

/// Per-key checks (FR-14 to FR-16, FR-24), each refusing the field it checks.
fn validate_key(
    doc: &Doc<'_>,
    product: &str,
    key: &str,
    spec: &KeySpec,
    environments: &BTreeMap<String, Environment>,
) -> Result<(), Error> {
    let base = ["products", product, "keys", key];
    let path = |field: &[&str]| -> Vec<String> {
        base.iter()
            .chain(field)
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
    };
    let invalid = |field: &[&str], rule: FieldRule| -> Error {
        let p = path(field);
        let refs: Vec<&str> = p.iter().map(String::as_str).collect();
        doc.invalid(&refs, rule)
    };
    if !is_env_name(key) {
        return Err(invalid(
            &[],
            FieldRule::Pattern {
                id: PatternId::KeyName,
            },
        ));
    }
    // Key attributes (Part V, `key-attrs`): `source` must agree with the declaration it
    // names (D-G: refused, never a finding). `derived` names another key via `from`;
    // `generated` names a key whose rules give a generate recipe, mirroring the refusals of
    // `crate::app::generate::recipe` (provider-issued prefix, personal, shared, byte count).
    match (spec.value_source, &spec.from) {
        (Some(ValueSource::Derived), None) => {
            return Err(invalid(&["from"], FieldRule::Missing));
        }
        (Some(source), Some(_)) if source != ValueSource::Derived => {
            return Err(invalid(
                &["source"],
                FieldRule::ConflictsWith {
                    field: dotted(&path(&["from"])),
                },
            ));
        }
        (Some(ValueSource::Generated), None) if !spec.has_generate_recipe() => {
            return Err(invalid(
                &["source"],
                FieldRule::Type {
                    expected: "generated only when the key has a base64_bytes or hex_bytes rule",
                },
            ));
        }
        _ => {}
    }
    // PATH finds `op`, HOME and XDG_CONFIG_HOME locate its configuration, OP_* holds its
    // sign-in.
    if matches!(key, "PATH" | "HOME" | "XDG_CONFIG_HOME") || key.starts_with("OP_") {
        return Err(invalid(
            &[],
            FieldRule::Reserved {
                set: RESERVED_KEYS.iter().map(|s| s.to_string()).collect(),
            },
        ));
    }
    let declared = || environments.keys().map(String::as_str);
    if let Some(envs) = &spec.environments {
        for env in envs {
            if !environments.contains_key(env) {
                return Err(invalid(
                    &["environments"],
                    undeclared(Declared::Environment, env, declared()),
                ));
            }
        }
    }
    // Presence (Part V, `presence`): `except` removes the key from a declared environment
    // with a reason. The reason must say something, the environment must exist, and an
    // `environments` list that already names it hides the removal (D-G: refused, not a
    // finding).
    for (env, reason) in &spec.except {
        if reason.trim().is_empty() {
            return Err(invalid(&["except", env], FieldRule::Empty));
        }
        if !environments.contains_key(env) {
            return Err(invalid(
                &["except", env],
                undeclared(Declared::Environment, env, declared()),
            ));
        }
        if spec.listed_in(env) && spec.environments.is_some() {
            return Err(invalid(
                &["except", env],
                FieldRule::ConflictsWith {
                    field: dotted(&path(&["environments"])),
                },
            ));
        }
    }
    // Process roles (#136): an empty list is refused (it would silently deliver nothing),
    // and every name is a lower-case word so a shell never has to quote it.
    if let Some(roles) = &spec.roles {
        if roles.is_empty() {
            return Err(invalid(&["roles"], check(ConfigCheck::EmptyRoles)));
        }
        if roles.iter().any(|role| !is_role_name(role)) {
            return Err(invalid(
                &["roles"],
                FieldRule::Pattern {
                    id: PatternId::RoleName,
                },
            ));
        }
    }
    for env in &spec.rules.refuse_in {
        if !environments.contains_key(env) {
            return Err(invalid(
                &["rules", "refuse_in"],
                undeclared(Declared::Environment, env, declared()),
            ));
        }
        if spec
            .environments
            .as_ref()
            .is_some_and(|envs| envs.contains(env))
        {
            return Err(invalid(
                &["rules", "refuse_in"],
                FieldRule::ConflictsWith {
                    field: dotted(&path(&["environments"])),
                },
            ));
        }
    }
    if spec.rules.prefix.as_deref() == Some("") {
        return Err(invalid(&["rules", "prefix"], FieldRule::Empty));
    }
    if let Some(np) = &spec.rules.not_prefix
        && !np.is_valid()
    {
        return Err(invalid(&["rules", "not_prefix"], FieldRule::Empty));
    }
    if let Some(p) = &spec.rules.prefix_by_mode {
        for (mode, v) in &p.values {
            if !v.is_valid() {
                return Err(invalid(
                    &["rules", "prefix_by_mode", "values", mode],
                    FieldRule::Empty,
                ));
            }
        }
        check_modes(doc, product, p, spec, environments)?;
    }
    if let Some(re) = &spec.rules.regex
        && regex::Regex::new(re).is_err()
    {
        return Err(invalid(&["rules", "regex"], FieldRule::Syntax));
    }
    if let Some(p) = &spec.rules.ensure_prefix
        && p.is_empty()
    {
        return Err(invalid(&["rules", "ensure_prefix"], FieldRule::Empty));
    }
    if spec.rules.transform.as_deref() == Some("signoz_ingestion_header") {
        let regex =
            toml::Value::String(format!("{}(?:{SIGNOZ_BODY})", regex::escape(SIGNOZ_PREFIX)));
        return Err(invalid(
            &["rules", "transform"],
            FieldRule::RemovedForm {
                form: "transform = \"signoz_ingestion_header\"",
                replacement: format!("ensure_prefix = \"{SIGNOZ_PREFIX}\" with regex = {regex}"),
            },
        ));
    }
    Ok(())
}

/// `prefix_by_mode` (audit 03.03, R08): every environment the key is declared for sets
/// `modes.<product>.<mode>` to a mapped or skipped value, checked at load, so the cause is
/// the configuration and never a value finding sent to 1Password.
fn check_modes(
    doc: &Doc<'_>,
    product: &str,
    p: &crate::domain::PrefixByMode,
    spec: &KeySpec,
    environments: &BTreeMap<String, Environment>,
) -> Result<(), Error> {
    for env_name in spec.envs_among(environments.keys().map(String::as_str)) {
        let Some(env) = environments.get(env_name) else {
            continue;
        };
        let field = ["environments", env_name, "modes", product, p.mode.as_str()];
        let rule = match env.modes.get(product).and_then(|m| m.get(&p.mode)) {
            None => FieldRule::Missing,
            Some(value) if p.values.contains_key(value) || p.skip.contains(value) => continue,
            Some(_) => FieldRule::ModeUnmapped {
                env: crate::cause::EnvName::new(env_name),
                mode: p.mode.clone(),
                allowed: p.values.keys().chain(&p.skip).cloned().collect(),
            },
        };
        return Err(doc.invalid(&field, rule));
    }
    Ok(())
}

/// Shared keys (FR-45): every `from` names a declared key with its own field, in the same
/// environment's item, of the same kind, declared for every environment the referencing
/// key uses. No chains, no cycles, no cross-environment reference, and always
/// `"<product>/<KEY>"`: a bare `"<KEY>"` is refused with the form to write (FR-60). The
/// referencing key may not set `immutable`: it follows the source, and is copied from it
/// here so every later check (rotate, prune, hold) treats both alike. Errors point at the
/// `from` line.
fn check_shared(
    products: &mut BTreeMap<String, Product>,
    environments: &BTreeMap<String, Environment>,
    doc: &Doc<'_>,
) -> Result<(), Error> {
    let mut follow: Vec<(String, String, bool)> = Vec::new();
    for (product, p) in products.iter() {
        for (key, spec) in &p.keys {
            let Some(from) = spec.from.as_deref() else {
                continue;
            };
            let err =
                |rule: FieldRule| doc.invalid(&["products", product, "keys", key, "from"], rule);
            let slashes = from.matches('/').count();
            if from.contains("://") || slashes > 1 {
                return Err(err(check(ConfigCheck::FromCrossEnvironment)));
            }
            let Some((sp, sk)) = spec.source() else {
                return Err(err(FieldRule::RemovedForm {
                    form: "a bare key in from",
                    replacement: format!("from = \"<product>/{from}\""),
                }));
            };
            let well_formed = is_env_name(sk) && is_product_name(sp);
            if !well_formed {
                return Err(err(check(ConfigCheck::FromShape)));
            }
            if (sp, sk) == (product.as_str(), key.as_str()) {
                return Err(err(check(ConfigCheck::FromSelf)));
            }
            let Some(src) = products.get(sp).and_then(|q| q.keys.get(sk)) else {
                let declared: Vec<String> = products
                    .iter()
                    .flat_map(|(dp, q)| q.keys.keys().map(move |dk| key_label(dp, dk)))
                    .collect();
                return Err(err(undeclared(
                    Declared::Key,
                    from,
                    declared.iter().map(String::as_str),
                )));
            };
            let source = key_label(sp, sk);
            if let Some((tp, tk)) = src.source() {
                return Err(err(check(
                    if (tp, tk) == (product.as_str(), key.as_str()) {
                        ConfigCheck::FromCycle { source }
                    } else {
                        ConfigCheck::FromChain {
                            source,
                            its_from: key_label(tp, tk),
                        }
                    },
                )));
            }
            if src.kind != spec.kind {
                return Err(err(check(ConfigCheck::FromKind {
                    source,
                    source_kind: kind_name(src.kind),
                    kind: kind_name(spec.kind),
                })));
            }
            for env in spec.envs_among(environments.keys().map(String::as_str)) {
                if !src.listed_in(env) {
                    return Err(err(check(ConfigCheck::FromEnvironment {
                        source,
                        env: env.to_string(),
                    })));
                }
            }
            if let Some(env) = spec.rules.refuse_in.iter().find(|e| src.listed_in(e)) {
                return Err(doc.invalid(
                    &["products", product, "keys", key, "rules", "refuse_in"],
                    check(ConfigCheck::FromRefused {
                        source,
                        env: env.clone(),
                    }),
                ));
            }
            if doc
                .value(&["products", product, "keys", key, "immutable"])
                .is_some()
            {
                return Err(doc.invalid(
                    &["products", product, "keys", key, "immutable"],
                    FieldRule::ConflictsWith {
                        field: dotted(&["products", product, "keys", key, "from"]),
                    },
                ));
            }
            follow.push((product.clone(), key.clone(), src.immutable));
        }
    }
    for (product, key, immutable) in follow {
        if let Some(spec) = products
            .get_mut(&product)
            .and_then(|p| p.keys.get_mut(&key))
        {
            spec.immutable = immutable;
        }
    }
    Ok(())
}

fn kind_name(k: crate::domain::Kind) -> &'static str {
    match k {
        crate::domain::Kind::Secret => "secret",
        crate::domain::Kind::Config => "config",
    }
}

/// Two targets on the same deployment target would manage the same names, and each would
/// prune what the other stages (FR-8). Within one environment a `(provider, locator)`
/// belongs to one target (FR-56); across environments the provider decides what "same"
/// means (a Fly app may serve two environments with different templates). Placed at the
/// second target's provider section (audit 03.04).
fn check_shared_targets(
    environments: &BTreeMap<String, Environment>,
    doc: &Doc<'_>,
) -> Result<(), Error> {
    let targets: Vec<(&str, &str, &dyn TargetConfig)> = environments
        .iter()
        .flat_map(|(e, env)| {
            env.targets
                .iter()
                .map(move |(n, t)| (e.as_str(), n.as_str(), t.config.as_ref()))
        })
        .collect();
    for (i, (env, name, t)) in targets.iter().enumerate() {
        let section = t.provider().section();
        for (prev_env, prev, p) in &targets[..i] {
            if prev_env == env {
                let same_provider = p.provider().section() == section;
                if same_provider && (p.target_locator() == t.target_locator() || t.same_target(*p))
                {
                    return Err(doc.invalid(
                        &["environments", env, "targets", name],
                        check(ConfigCheck::SameTarget {
                            label: t.provider().label().to_string(),
                            locator: t.target_locator(),
                            other: prev.to_string(),
                        }),
                    ));
                }
            } else if t.same_target(*p) {
                return Err(doc.invalid_at(
                    dotted(&template_path(env, name, *t)),
                    &["environments", env, "targets", name, section],
                    check(ConfigCheck::SharedAcrossEnvironments {
                        label: t.provider().label().to_string(),
                        locator: t.target_locator(),
                        other_env: prev_env.to_string(),
                        other_target: prev.to_string(),
                    }),
                ));
            }
        }
    }
    Ok(())
}

/// Every name a target renders, for EVERY declared key of each product it delivers (not
/// only those desired in the environment), must be a valid env-var name, fit the store's
/// limits and be unique within the target (case-folded when the store ignores case). The
/// managed set is every rendered name, so a key desired here and another key declared only
/// elsewhere that render the same name would otherwise be both staged and pruned in one run
/// (FR-2, FR-8, FR-30). Runs per target (FR-56).
fn check_names(fleet: &Fleet, doc: &Doc<'_>) -> Result<(), Error> {
    // Store names already taken in a named store, case-folded as it compares them, by
    // every target that keeps its secrets there (FR-39): (store, id) → (target, owner).
    let mut shared: Vec<(&dyn StoreConfig, String, String, String)> = Vec::new();
    for (env_name, env) in &fleet.environments {
        for (target_name, target) in &env.targets {
            check_target_names(fleet, env_name, target_name, target, &mut shared, doc)?;
        }
    }
    Ok(())
}

/// [`check_names`] for one target. Each refusal names the target's name template field,
/// the field a person changes (audit 03.01, 03.17), placed at the key.
fn check_target_names<'f>(
    fleet: &'f Fleet,
    env_name: &str,
    target_name: &str,
    target: &'f Target,
    shared: &mut Vec<(&'f dyn StoreConfig, String, String, String)>,
    doc: &Doc<'_>,
) -> Result<(), Error> {
    let t = target.config.as_ref();
    let template = template_path(env_name, target_name, t);
    let rules = t.name_rules();
    let store = t.secrets_in();
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    let mut seen_in_store: BTreeMap<String, String> = BTreeMap::new();
    for (product, p) in &fleet.products {
        // FR-47/FR-48: an undelivered product's keys render no name here, so they are
        // exempt from the name collision check too.
        if !fleet.delivers(env_name, target_name, product) {
            continue;
        }
        for key in p.keys.keys() {
            let refuse = |c: ConfigCheck| {
                doc.invalid_at(
                    dotted(&template),
                    &["products", product, "keys", key],
                    check(c),
                )
            };
            let name = t.env_name(product, key);
            let owner = key_label(product, key);
            if !is_env_name(&name) {
                return Err(refuse(ConfigCheck::RenderedName {
                    owner,
                    label: rules.env_label.to_string(),
                    rendered: name,
                    pattern: PatternId::KeyName,
                }));
            }
            let id = match &rules.store {
                None => name.clone(),
                Some(s) => store_id(&owner, &t.store_name(&name), s).map_err(|c| refuse(*c))?,
            };
            check_unique(&mut seen, &rules, id, &owner).map_err(|c| refuse(*c))?;
            if let Some(store) = store {
                let s = store.name_rules();
                let id = store_id(&owner, &store.store_name(&name), &s).map_err(|c| refuse(*c))?;
                let named = NameRules {
                    env_label: rules.env_label,
                    store: Some(s),
                };
                check_unique(&mut seen_in_store, &named, id.clone(), &owner)
                    .map_err(|c| refuse(*c))?;
                let here = env_name.to_string();
                if let Some((_, _, other, prev)) = shared
                    .iter()
                    .find(|(st, i, e, _)| st.same_store(store) && *i == id && *e != here)
                {
                    return Err(refuse(ConfigCheck::StoreShared {
                        owner: owner.clone(),
                        label: s.label.to_string(),
                        name: id.clone(),
                        store: store.describe(),
                        other_env: other.clone(),
                        other_owner: prev.clone(),
                    }));
                }
                shared.push((store, id, here, owner.clone()));
            }
        }
    }
    Ok(())
}

/// A rendered store name checked against `s` (FR-30): its identity for collisions,
/// case-folded when the store ignores case.
fn store_id(owner: &str, store: &str, s: &StoreNameRules) -> Result<String, Box<ConfigCheck>> {
    let problem = if store.is_empty() {
        Some(StoreNameProblem::Empty)
    } else if store.len() > s.max_len {
        Some(StoreNameProblem::TooLong {
            len: store.len(),
            max: s.max_len,
        })
    } else if !store.chars().all(s.allowed) {
        Some(StoreNameProblem::Character)
    } else {
        // The first and last characters, e.g. a key ending in `_` renders a Kubernetes
        // name ending in `-`: refused here, never at sync.
        let edges = [store.chars().next(), store.chars().last()];
        (!edges.into_iter().flatten().all(s.edge)).then_some(StoreNameProblem::Edge)
    };
    if let Some(problem) = problem {
        return Err(Box::new(ConfigCheck::RenderedStoreName {
            owner: owner.to_string(),
            label: s.label.to_string(),
            problem,
        }));
    }
    Ok(if s.case_insensitive {
        store.to_ascii_lowercase()
    } else {
        store.to_string()
    })
}

/// Two keys of one target must not render the same name (FR-8, FR-30): the refusal names
/// both keys, and its fix the two ways out (FR-20).
fn check_unique(
    seen: &mut BTreeMap<String, String>,
    rules: &NameRules,
    id: String,
    owner: &str,
) -> Result<(), Box<ConfigCheck>> {
    let Some(prev) = seen.insert(id.clone(), owner.to_string()) else {
        return Ok(());
    };
    Err(Box::new(ConfigCheck::NameTaken {
        owner: owner.to_string(),
        other: prev,
        label: match &rules.store {
            None => rules.env_label.to_string(),
            Some(s) => s.label.to_string(),
        },
        name: id,
    }))
}

/// IDs and app names go into argv, so they must not start with `-` (read as a flag) and
/// hold only `^[A-Za-z0-9][A-Za-z0-9._-]*$`.
pub(crate) fn is_id(s: &str) -> bool {
    let mut c = s.chars();
    c.next().is_some_and(|ch| ch.is_ascii_alphanumeric())
        && c.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

pub(crate) fn is_env_name(s: &str) -> bool {
    let mut c = s.chars();
    matches!(c.next(), Some('A'..='Z'))
        && c.all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
}

pub(crate) fn is_product_name(s: &str) -> bool {
    let mut c = s.chars();
    matches!(c.next(), Some('a'..='z'))
        && c.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '-')
}

/// Test documents (FR-57): every boundary a document's products need, recorded.
#[cfg(test)]
pub(crate) mod testing {
    use std::collections::{BTreeMap, BTreeSet};

    /// `text` with `boundaries.<product> = { vault_id = "v<product>", item_id =
    /// "i<product>" }` added under each `[environments.<env>]` header, for every product with
    /// a key declared for that environment. Names only.
    pub(crate) fn bounded(text: &str) -> String {
        let doc: toml::Table = toml::from_str(text).expect("test document parses");
        let mut needs: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let products = doc.get("products").and_then(toml::Value::as_table);
        for (product, p) in products.into_iter().flatten() {
            let keys = p.get("keys").and_then(toml::Value::as_table);
            for spec in keys.into_iter().flat_map(|k| k.values()) {
                let envs = spec.get("environments").and_then(toml::Value::as_array);
                for env in envs.into_iter().flatten().filter_map(toml::Value::as_str) {
                    needs
                        .entry(env.to_string())
                        .or_default()
                        .insert(product.clone());
                }
            }
        }
        let mut out = text.to_string();
        for (env, products) in needs {
            let header = format!("[environments.{env}]\n");
            let lines: String = products
                .iter()
                .map(|p| {
                    format!("boundaries.{p} = {{ vault_id = \"v{p}\", item_id = \"i{p}\" }}\n")
                })
                .collect();
            out = out.replacen(&header, &format!("{header}{lines}"), 1);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Kind;

    const RAW: &str = include_str!("../tests/fixtures/secrets.toml");
    const RAW_BINDINGS: &str = include_str!("../tests/fixtures/secrets.bindings.toml");

    /// The fixture with its bindings filled in and LF line endings, whatever the checkout
    /// did (Windows may give CRLF).
    fn ok() -> String {
        let ids = bindings::Bindings::parse(&RAW_BINDINGS.replace("\r\n", "\n")).unwrap();
        bindings::merge(&RAW.replace("\r\n", "\n"), &ids)
    }

    /// `text` with `from` replaced by `to`. Panics if `from` does not occur, so a mutation
    /// that silently fails to apply can never make a rejection test pass.
    fn replaced(text: &str, from: &str, to: &str) -> String {
        assert!(text.contains(from), "mutation did not match: {from:?}");
        text.replacen(from, to, 1)
    }

    /// The fixture with `from` replaced by `to`.
    fn mutate(from: &str, to: &str) -> String {
        replaced(&ok(), from, to)
    }

    // --- #136, #137: local delivery ---

    const LOCAL: &str = "\n[products.allumata.local]\nenvironment = \"declared_only\"\nsecrets_dir_env = \"APP_SECRETS_DIR\"\n";

    fn with_file(path: &str) -> String {
        replaced(
            &format!("{}{LOCAL}", ok()),
            "guidance = \"OpenAI platform / API keys\"",
            &format!("guidance = \"OpenAI platform / API keys\"\nfile = \"{path}\""),
        )
    }

    #[test]
    fn a_file_key_with_a_secrets_directory_loads() {
        assert!(parse(&with_file("openai/api-key")).is_ok());
    }

    #[test]
    fn a_file_key_records_its_path() {
        let f = parse(&with_file("openai/api-key")).unwrap();
        assert_eq!(
            f.products["allumata"].keys["OPENAI_API_KEY"]
                .file
                .as_deref(),
            Some("openai/api-key")
        );
    }

    #[test]
    fn declared_only_is_read() {
        let f = parse(&with_file("openai/api-key")).unwrap();
        assert_eq!(
            f.products["allumata"].local.as_ref().unwrap().environment,
            crate::domain::model::LocalEnvironment::DeclaredOnly
        );
    }

    #[test]
    fn a_file_key_without_a_secrets_directory_is_refused() {
        let t = with_file("openai/api-key").replace("secrets_dir_env = \"APP_SECRETS_DIR\"\n", "");
        assert!(parse(&t).is_err());
    }

    #[test]
    fn a_file_path_that_climbs_out_is_refused() {
        assert!(parse(&with_file("../escape")).is_err());
    }

    #[test]
    fn an_absolute_file_path_is_refused() {
        assert!(parse(&with_file("/etc/passwd")).is_err());
    }

    #[test]
    fn a_file_path_inside_another_keys_file_is_refused() {
        let t = replaced(
            &with_file("openai"),
            "[products.allumata.keys.INTEGRATION_ENC_KEY]\n",
            "[products.allumata.keys.INTEGRATION_ENC_KEY]\nfile = \"openai/nested\"\n",
        );
        assert!(parse(&t).is_err());
    }

    #[test]
    fn a_reserved_secrets_directory_variable_is_refused() {
        let t = with_file("k").replace("APP_SECRETS_DIR", "OP_SESSION_x");
        assert!(parse(&t).is_err());
    }

    #[test]
    fn a_secrets_directory_without_a_file_key_is_refused() {
        assert!(parse(&format!("{}{LOCAL}", ok())).is_err());
    }

    #[test]
    fn a_nested_lowercase_file_path_loads() {
        assert!(parse(&with_file("github-app/private-key")).is_ok());
    }

    #[test]
    fn a_two_segment_lowercase_file_path_loads() {
        assert!(parse(&with_file("database/url")).is_ok());
    }

    #[test]
    fn another_nested_lowercase_file_path_loads() {
        assert!(parse(&with_file("otel/endpoint")).is_ok());
    }

    #[test]
    fn an_uppercase_file_path_is_refused() {
        assert!(parse(&with_file("GitHub-app/private-key")).is_err());
    }

    #[test]
    fn a_file_path_with_a_dot_is_refused() {
        assert!(parse(&with_file("github.app/private-key")).is_err());
    }

    #[test]
    fn a_file_path_with_an_underscore_is_refused() {
        assert!(parse(&with_file("github_app/private-key")).is_err());
    }

    #[test]
    fn a_file_path_with_an_empty_segment_is_refused() {
        assert!(parse(&with_file("github-app//private-key")).is_err());
    }

    #[test]
    fn a_file_path_with_a_leading_dash_is_refused() {
        assert!(parse(&with_file("-github-app/private-key")).is_err());
    }

    #[test]
    fn a_file_path_with_a_trailing_dash_is_refused() {
        assert!(parse(&with_file("github-app-/private-key")).is_err());
    }

    #[test]
    fn a_file_path_with_more_than_four_segments_is_refused() {
        assert!(parse(&with_file("a/b/c/d/e")).is_err());
    }

    #[test]
    fn an_unknown_local_environment_mode_is_refused() {
        let t = with_file("k").replace("declared_only", "everything");
        assert!(parse(&t).is_err());
    }

    // --- #136, O9/R1: remote profiles refuse deployed environments ---

    /// `base` plus a reviewed remote profile for `allumata` with `fields`.
    fn remote_over(base: &str, fields: &str) -> String {
        format!(
            "{base}\n[products.allumata.remotes.builder]\nhost = \"builder.example.internal\"\n\
             user = \"dev\"\nhost_key = \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestMarkerHostKeyNotARealKey139\"\n\
             opv = \"/usr/local/bin/opv\"\nworkdir = \"/home/dev/src/app\"\ncommand = [\"cargo\", \"run\"]\n{fields}"
        )
    }

    #[test]
    fn a_remote_profile_refusal_names_the_profile_the_environment_and_the_target() {
        assert_eq!(
            check_of(&remote_over(&ok(), "environments = [\"prod\"]")),
            ConfigCheck::RemoteEnvironmentHasTarget {
                profile: "builder".into(),
                env: "prod".into(),
                target: "portfolio".into(),
            }
        );
    }

    #[test]
    fn a_remote_profile_over_a_target_less_environment_loads() {
        let base = format!("{}\n[environments.dev]\n", ok());
        assert!(parse(&remote_over(&base, "environments = [\"dev\"]")).is_ok());
    }

    /// `text` with boundary `b` recorded in `env` (IDs `v<b>` and `i<b>`).
    fn bound(text: &str, env: &str, b: &str) -> String {
        let header = format!("[environments.{env}]\n");
        replaced(
            text,
            &header,
            &format!("{header}boundaries.{b} = {{ vault_id = \"v{b}\", item_id = \"i{b}\" }}\n"),
        )
    }

    /// `text` plus a declared key `product/key` for `envs` (a TOML array) with `body`.
    fn key(text: &str, product: &str, key: &str, envs: &str, body: &str) -> String {
        format!(
            "{text}\n[products.{product}.keys.{key}]\nkind = \"secret\"\nenvironments = {envs}\n{body}"
        )
    }

    /// The fixture plus `product/key` in prod, with its boundary recorded there.
    fn with_prod_key(product: &str, k: &str, body: &str) -> String {
        bound(
            &key(&ok(), product, k, r#"["prod"]"#, body),
            "prod",
            product,
        )
    }

    /// The cause `text` is refused with.
    fn cause(text: &str) -> Cause {
        match parse(text) {
            Err(e) => match e.cause() {
                Some((c, _)) => c.clone(),
                None => panic!("expected a catalog cause, got {e:?}"),
            },
            Ok(_) => panic!("expected a refusal"),
        }
    }

    /// The message of the configuration error `text` is refused with.
    fn config_err(text: &str) -> String {
        cause(text).message()
    }

    /// The field and rule of the `ConfigInvalid` refusal of `text`.
    fn invalid(text: &str) -> (String, FieldRule) {
        match cause(text) {
            Cause::ConfigInvalid { field, rule, .. } => (field.to_string(), rule),
            other => panic!("expected ConfigInvalid, got {other:?}"),
        }
    }

    /// The field the refusal of `text` names.
    fn field_of(text: &str) -> String {
        invalid(text).0
    }

    /// The rule the refusal of `text` names.
    fn rule_of(text: &str) -> FieldRule {
        invalid(text).1
    }

    /// The check the refusal of `text` names.
    fn check_of(text: &str) -> ConfigCheck {
        match rule_of(text) {
            FieldRule::Check { check } => check,
            other => panic!("expected a check, got {other:?}"),
        }
    }

    /// The Do of the refusal of `text`.
    fn do_of(text: &str) -> Option<String> {
        cause(text).do_text(&crate::cause::Invocation::default())
    }

    /// The stable code of the configuration error `text` is refused with (A2).
    fn config_code(text: &str) -> &'static str {
        cause(text).code()
    }

    /// One environment `prod` with boundary `web`, target `site` (Fly, `{KEY}`) and one key.
    const WEB: &str = r#"[environments.prod]
boundaries.web = { vault_id = "vweb", item_id = "iweb" }

[environments.prod.targets.site]
fly.app = "web-prod"
fly.secret_name = "{KEY}"
state_vault_id = "sweb"

[products.web.keys.DATABASE_URL]
kind = "secret"
environments = ["prod"]
"#;

    /// [`WEB`] with `from` replaced by `to`.
    fn web(from: &str, to: &str) -> String {
        replaced(WEB, from, to)
    }

    /// [`WEB`] with `extra` appended.
    fn web_plus(extra: &str) -> String {
        format!("{WEB}{extra}")
    }

    /// The parsed fixture.
    fn fixture() -> Fleet {
        parse(&ok()).unwrap()
    }

    // ---- loading ---------------------------------------------------------------------

    #[test]
    fn load_reads_the_fixture_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("secrets.toml");
        std::fs::write(&p, RAW).unwrap();
        std::fs::write(dir.path().join(bindings::FILE), RAW_BINDINGS).unwrap();
        assert!(load(&p).is_ok());
    }

    #[test]
    fn load_names_a_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.toml");
        assert!(matches!(
            load(&missing).unwrap_err().cause(),
            Some((Cause::ConfigUnreadable { path, .. }, _)) if path == &missing
        ));
    }

    #[test]
    fn rejects_a_configuration_without_environments() {
        assert_eq!(
            invalid("[products.web.keys.K]\nkind = \"secret\"\nenvironments = []\n"),
            ("environments".to_string(), FieldRule::NoEnvironment)
        );
    }

    #[test]
    fn target_renders_names_from_its_template() {
        assert_eq!(
            fixture().target_name("prod", "portfolio", "allumata", "OPENAI_API_KEY"),
            "FLEET__ALLUMATA__OPENAI_API_KEY"
        );
    }

    #[test]
    fn records_each_boundary_by_ids() {
        assert_eq!(
            fixture().environments["prod"].boundaries["allumata"],
            Boundary {
                vault_id: "vprd".into(),
                item_id: "iprd".into()
            }
        );
    }

    #[test]
    fn records_the_targets_state_vault() {
        assert_eq!(
            fixture().environments["prod"].targets["portfolio"].state_vault_id,
            "sprd"
        );
    }

    #[test]
    fn a_target_keeps_its_name() {
        assert_eq!(
            fixture().environments["prod"].targets["portfolio"].name,
            "portfolio"
        );
    }

    #[test]
    fn a_target_keeps_its_fly_app() {
        let f = fixture();
        let app = f.environments["prod"].targets["portfolio"]
            .config
            .as_any()
            .downcast_ref::<crate::adapters::fly::FlyTarget>()
            .map(|t| t.app.clone());
        assert_eq!(app.as_deref(), Some("mcproductlabs-portfolio-production"));
    }

    #[test]
    fn parses_modes_per_product() {
        assert_eq!(
            fixture().environments["staging"].modes["allumata"]["payments"],
            "test"
        );
    }

    #[test]
    fn parses_the_key_kind() {
        assert_eq!(
            fixture().products["allumata"].keys["SIGNUP_POLICY"].kind,
            Kind::Config
        );
    }

    #[test]
    fn parses_immutable() {
        assert!(fixture().products["allumata"].keys["INTEGRATION_ENC_KEY"].immutable);
    }

    #[test]
    fn parses_the_key_environments() {
        assert_eq!(
            fixture().products["allumata"].keys["OPENAI_API_KEY"].environments,
            Some(vec!["prod".to_string()])
        );
    }

    #[test]
    fn parses_guidance() {
        assert_eq!(
            fixture().products["allumata"].keys["OPENAI_API_KEY"].guidance,
            "OpenAI platform / API keys"
        );
    }

    #[test]
    fn parses_the_prefix_rule() {
        assert_eq!(
            fixture().products["allumata"].keys["OPENAI_API_KEY"]
                .rules
                .prefix
                .as_deref(),
            Some("sk-")
        );
    }

    #[test]
    fn parses_the_not_prefix_rule() {
        assert_eq!(
            fixture().products["allumata"].keys["OPENAI_API_KEY"]
                .rules
                .not_prefix,
            Some(crate::domain::OneOrMany::One("sk-or-".into()))
        );
    }

    #[test]
    fn parses_the_base64_bytes_rule() {
        assert_eq!(
            fixture().products["allumata"].keys["INTEGRATION_ENC_KEY"]
                .rules
                .base64_bytes,
            Some(32)
        );
    }

    #[test]
    fn parses_the_prefix_by_mode_rule() {
        let f = fixture();
        let pbm = f.products["allumata"].keys["STRIPE_SECRET_KEY"]
            .rules
            .prefix_by_mode
            .clone()
            .unwrap();
        assert_eq!(
            (pbm.mode.as_str(), pbm.skip),
            ("payments", vec!["off".to_string(), "external".to_string()])
        );
    }

    #[test]
    fn parses_the_enum_rule() {
        assert_eq!(
            fixture().products["allumata"].keys["SIGNUP_POLICY"]
                .rules
                .r#enum,
            Some(vec!["open".to_string(), "invite_only".to_string()])
        );
    }

    #[test]
    fn an_environment_without_targets_is_run_only() {
        let text = bound(
            &format!("{}\n[environments.dev]\n", ok()),
            "dev",
            "allumata",
        );
        let text = replaced(
            &text,
            r#"environments = ["prod"]"#,
            r#"environments = ["prod", "dev"]"#,
        );
        assert!(parse(&text).unwrap().environments["dev"].targets.is_empty());
    }

    // ---- keys and rules ----------------------------------------------------------------

    #[test]
    fn rejects_a_key_for_an_undefined_environment() {
        let text = mutate(r#"environments = ["prod"]"#, r#"environments = ["qa"]"#);
        assert_eq!(
            field_of(&text),
            "products.allumata.keys.OPENAI_API_KEY.environments"
        );
    }

    #[test]
    fn rejects_a_key_name_that_is_not_an_env_name() {
        let text = mutate(
            "[products.allumata.keys.OPENAI_API_KEY]",
            "[products.allumata.keys.openai-key]",
        );
        assert_eq!(
            rule_of(&text),
            FieldRule::Pattern {
                id: PatternId::KeyName
            }
        );
    }

    #[test]
    fn rejects_an_unknown_key_field() {
        let text = mutate("immutable = true", "immutible = true");
        assert_eq!(
            rule_of(&text),
            FieldRule::Unknown {
                suggestion: Some("immutable".into())
            }
        );
    }

    #[test]
    fn rejects_an_unknown_rule() {
        let text = mutate("base64_bytes = 32", "base64_len = 32");
        assert!(
            field_of(&text).ends_with(".rules.base64_len"),
            "{}",
            field_of(&text)
        );
    }

    #[test]
    fn rejects_an_unknown_kind() {
        let text = mutate(r#"kind = "config""#, r#"kind = "text""#);
        assert_eq!(
            check_of(&text),
            ConfigCheck::NotOneOf {
                allowed: vec!["secret".into(), "config".into()],
                closest: None
            }
        );
    }

    #[test]
    fn rejects_a_bad_product_name() {
        let text = mutate("products.allumata.", "products.Allumata.");
        assert_eq!(field_of(&text), "products.Allumata");
    }

    #[test]
    fn rejects_a_regex_that_does_not_compile_naming_the_key() {
        let text = mutate(
            r#"rules = { base64_bytes = 32 }"#,
            r#"rules = { regex = "([a-z" }"#,
        );
        assert_eq!(
            invalid(&text),
            (
                "products.allumata.keys.INTEGRATION_ENC_KEY.rules.regex".to_string(),
                FieldRule::Syntax
            )
        );
    }

    #[test]
    fn parses_the_ensure_prefix_rule() {
        let f = parse(&with_prod_key(
            "p",
            "K1",
            "rules = { ensure_prefix = \"p-\" }\n",
        ))
        .unwrap();
        assert_eq!(
            f.products["p"].keys["K1"].rules.ensure_prefix.as_deref(),
            Some("p-")
        );
    }

    #[test]
    fn ensure_prefix_with_regex_loads() {
        let text = with_prod_key(
            "p",
            "K1",
            "rules = { ensure_prefix = \"p-\", regex = \"p-[a-z]+\" }\n",
        );
        assert!(parse(&text).is_ok());
    }

    /// FR-24, FR-60: the `pattern` rule is removed; a file that still sets it fails at
    /// load with the key and the equivalent `regex` rule.
    #[test]
    fn the_pattern_rule_fails_at_load_with_the_equivalent_regex() {
        let text = with_prod_key(
            "p",
            "K1",
            "rules = { ensure_prefix = \"p-\", pattern = \"[a-z]+\" }\n",
        );
        assert_eq!(
            rule_of(&text),
            FieldRule::RemovedForm {
                form: "pattern",
                replacement: "regex = 'p\\-(?:[a-z]+)'".into()
            }
        );
    }

    #[test]
    fn the_pattern_rule_error_points_at_the_pattern() {
        let text = with_prod_key(
            "p",
            "K1",
            "rules = { ensure_prefix = \"p-\", pattern = \"[a-z]+\" }\n",
        );
        assert!(
            config_err(&text).contains(" at line 50, column 33: "),
            "{}",
            config_err(&text)
        );
    }

    #[test]
    fn path_is_a_reserved_key_name() {
        assert!(matches!(
            rule_of(&with_prod_key("p", "PATH", "")),
            FieldRule::Reserved { .. }
        ));
    }

    #[test]
    fn op_variables_are_reserved_key_names() {
        assert!(matches!(
            rule_of(&with_prod_key("p", "OP_SERVICE_ACCOUNT_TOKEN", "")),
            FieldRule::Reserved { .. }
        ));
    }

    #[test]
    fn the_signoz_transform_is_refused_with_its_replacement() {
        let text = with_prod_key(
            "p",
            "K1",
            "rules = { transform = \"signoz_ingestion_header\" }\n",
        );
        assert_eq!(
            rule_of(&text),
            FieldRule::RemovedForm {
                form: "transform = \"signoz_ingestion_header\"",
                replacement: "ensure_prefix = \"signoz-ingestion-key=\" with regex = \
                              'signoz\\-ingestion\\-key=(?:[A-Za-z0-9._~+/-]+={0,2})'"
                    .into()
            }
        );
    }

    #[test]
    fn rejects_an_empty_not_prefix_list() {
        let text = mutate(
            r#"rules = { base64_bytes = 32 }"#,
            r#"rules = { not_prefix = [] }"#,
        );
        assert_eq!(
            field_of(&text),
            "products.allumata.keys.INTEGRATION_ENC_KEY.rules.not_prefix"
        );
    }

    #[test]
    fn rejects_an_empty_prefix_by_mode_value() {
        let text = mutate(
            r#"values = { test = "sk_test_", live = "sk_live_" }"#,
            r#"values = { test = "", live = "sk_live_" }"#,
        );
        assert_eq!(
            field_of(&text),
            "products.allumata.keys.STRIPE_SECRET_KEY.rules.prefix_by_mode.values.test"
        );
    }

    #[test]
    fn accepts_prefix_lists() {
        let t = mutate(
            r#"values = { test = "sk_test_", live = "sk_live_" }"#,
            r#"values = { test = ["sk_test_", "rk_test_"], live = ["sk_live_", "rk_live_"] }"#,
        );
        assert!(parse(&t).is_ok());
    }

    #[test]
    fn rejects_an_empty_prefix() {
        let text = mutate(r#"prefix = "sk-""#, r#"prefix = """#);
        assert_eq!(
            invalid(&text),
            (
                "products.allumata.keys.OPENAI_API_KEY.rules.prefix".to_string(),
                FieldRule::Empty
            )
        );
    }

    #[test]
    fn rejects_refuse_in_naming_an_undefined_environment() {
        let text = mutate(
            r#"not_prefix = "sk-or-" }"#,
            r#"not_prefix = "sk-or-", refuse_in = ["qa"] }"#,
        );
        assert!(matches!(
            check_of(&text),
            ConfigCheck::Undeclared { kind: Declared::Environment, name, .. } if name == "qa"
        ));
    }

    #[test]
    fn rejects_refuse_in_overlapping_environments() {
        let text = mutate(
            r#"not_prefix = "sk-or-" }"#,
            r#"not_prefix = "sk-or-", refuse_in = ["prod"] }"#,
        );
        assert!(matches!(rule_of(&text), FieldRule::ConflictsWith { .. }));
    }

    #[test]
    fn accepts_refuse_in_another_environment() {
        assert!(
            parse(&mutate(
                r#"not_prefix = "sk-or-" }"#,
                r#"not_prefix = "sk-or-", refuse_in = ["staging"] }"#,
            ))
            .is_ok()
        );
    }

    // ---- targets (FR-56) -------------------------------------------------------------

    #[test]
    fn a_key_template_renders_the_bare_key_name() {
        assert_eq!(
            parse(WEB)
                .unwrap()
                .target_name("prod", "site", "web", "DATABASE_URL"),
            "DATABASE_URL"
        );
    }

    #[test]
    fn rejects_a_fly_template_without_key() {
        let m = config_err(&mutate("FLEET__{PRODUCT}__{KEY}", "FLEET_STATIC"));
        assert!(
            m.contains("fly.secret_name must be a template containing {KEY}"),
            "{m}"
        );
    }

    #[test]
    fn fly_secret_name_is_required() {
        let m = config_err(&web("fly.secret_name = \"{KEY}\"\n", ""));
        assert!(m.contains("fly.secret_name is required but missing"), "{m}");
    }

    #[test]
    fn a_key_template_on_a_two_product_target_collides() {
        let text = bound(
            &key(WEB, "api", "DATABASE_URL", r#"["prod"]"#, ""),
            "prod",
            "api",
        );
        assert_eq!(
            check_of(&text),
            ConfigCheck::NameTaken {
                owner: "web/DATABASE_URL".into(),
                other: "api/DATABASE_URL".into(),
                label: "Fly name".into(),
                name: "DATABASE_URL".into()
            }
        );
    }

    #[test]
    fn a_name_collision_names_both_ways_out() {
        let text = bound(
            &key(WEB, "api", "DATABASE_URL", r#"["prod"]"#, ""),
            "prod",
            "api",
        );
        assert_eq!(
            do_of(&text).as_deref(),
            Some(
                "set environments.prod.targets.site.fly.secret_name with {PRODUCT} so the names \
                 differ, or deliver one product from a target of its own (products = [...]) in \
                 secrets.toml at line 10, column 20"
            )
        );
    }

    #[test]
    fn rejects_a_fly_app_that_reads_as_a_flag() {
        let m = config_err(&web("\"web-prod\"", "\"-a\""));
        assert!(m.contains("fly.app must be letters, digits"), "{m}");
    }

    #[test]
    fn rejects_a_padded_fly_app() {
        let m = config_err(&web("\"web-prod\"", "\"web-prod \""));
        assert!(
            m.contains("fly.app has leading or trailing whitespace"),
            "{m}"
        );
    }

    #[test]
    fn rejects_an_empty_fly_app() {
        let m = config_err(&web("\"web-prod\"", "\"\""));
        assert!(m.contains("fly.app is empty"), "{m}");
    }

    #[test]
    fn rejects_a_template_rendering_an_invalid_fly_name() {
        let text = mutate("FLEET__{PRODUCT}__{KEY}", "fleet__{PRODUCT}__{KEY}");
        assert!(matches!(
            check_of(&text),
            ConfigCheck::RenderedName { rendered, .. } if rendered.starts_with("fleet__ALLUMATA__")
        ));
    }

    /// FR-2, FR-37: an unknown field in a provider section reports line, column and the
    /// field; never the line itself (C1, SR-1).
    #[test]
    fn a_fly_section_unknown_field_points_at_the_field() {
        let bad = web(
            "fly.secret_name = \"{KEY}\"\n",
            "fly.secret_name = \"{KEY}\"\nfly.region = \"ams\"\n",
        );
        assert!(
            config_err(&bad).contains("fly.region is not a known setting"),
            "{}",
            config_err(&bad)
        );
    }

    #[test]
    fn an_unknown_target_section_lists_the_known_providers() {
        let text = web("fly.app", "flyy.app = \"x\"\nfly.app");
        assert_eq!(
            rule_of(&text),
            FieldRule::Unknown {
                suggestion: Some("fly".into())
            }
        );
    }

    #[test]
    fn an_unknown_target_field_names_the_expected_fields() {
        let text = web("fly.app", "vault = \"x\"\nfly.app");
        assert_eq!(field_of(&text), "environments.prod.targets.site.vault");
    }

    #[test]
    fn a_target_with_two_provider_sections_is_refused() {
        let text = web("fly.app", "azure.key_vault = \"kv\"\nfly.app");
        assert!(matches!(rule_of(&text), FieldRule::ConflictsWith { .. }));
    }

    #[test]
    fn a_target_without_a_provider_is_refused() {
        let text = web("fly.app = \"web-prod\"\nfly.secret_name = \"{KEY}\"\n", "");
        assert!(matches!(check_of(&text), ConfigCheck::NoProvider { .. }));
    }

    #[test]
    fn rejects_a_target_name_that_is_not_lowercase() {
        assert_eq!(
            invalid(&web("targets.site]", "targets.Site]")),
            (
                "environments.prod.targets.Site".to_string(),
                FieldRule::Pattern {
                    id: PatternId::TargetName
                }
            )
        );
    }

    #[test]
    fn rejects_a_target_name_with_an_underscore() {
        assert_eq!(
            field_of(&web("targets.site]", "targets.my_site]")),
            "environments.prod.targets.my_site"
        );
    }

    #[test]
    fn a_target_without_state_vault_id_is_state_vault_missing() {
        let text = web("state_vault_id = \"sweb\"\n", "");
        assert_eq!(config_code(&text), "state_vault_missing");
    }

    #[test]
    fn state_vault_missing_names_the_target() {
        assert!(matches!(
            cause(&web("state_vault_id = \"sweb\"\n", "")),
            Cause::StateVaultMissing { target, .. } if target.as_str() == "site"
        ));
    }

    #[test]
    fn a_recorded_delivery_item_is_loaded_by_product() {
        let f = parse(&web(
            "state_vault_id = \"sweb\"\n",
            "state_vault_id = \"sweb\"\ndelivery_items = { web = \"dweb\" }\n",
        ))
        .unwrap();
        assert_eq!(
            f.environments["prod"].targets["site"].delivery_items["web"],
            "dweb"
        );
    }

    #[test]
    fn a_delivery_item_for_a_product_the_target_does_not_deliver_is_refused() {
        let text = web(
            "state_vault_id = \"sweb\"\n",
            "state_vault_id = \"sweb\"\ndelivery_items = { api = \"dapi\" }\n",
        );
        assert_eq!(
            check_of(&text),
            ConfigCheck::DeliveryItemUndelivered {
                product: "api".into()
            }
        );
    }

    #[test]
    fn rejects_a_delivery_item_id_that_reads_as_a_flag() {
        let text = web(
            "state_vault_id = \"sweb\"\n",
            "state_vault_id = \"sweb\"\ndelivery_items = { web = \"-d\" }\n",
        );
        assert_eq!(
            field_of(&text),
            "environments.prod.targets.site.delivery_items.web"
        );
    }

    #[test]
    fn rejects_a_state_vault_id_that_reads_as_a_flag() {
        assert_eq!(
            invalid(&web("\"sweb\"", "\"-s\"")),
            (
                "environments.prod.targets.site.state_vault_id".to_string(),
                FieldRule::Pattern { id: PatternId::Id }
            )
        );
    }

    #[test]
    fn parses_the_target_products() {
        let text = web("state_vault_id", "products = [\"web\"]\nstate_vault_id");
        assert_eq!(
            parse(&text).unwrap().environments["prod"].targets["site"].products,
            Some(vec!["web".to_string()])
        );
    }

    #[test]
    fn rejects_empty_target_products() {
        assert_eq!(
            check_of(&web("state_vault_id", "products = []\nstate_vault_id")),
            ConfigCheck::EmptyProducts
        );
    }

    #[test]
    fn rejects_target_products_naming_an_undeclared_product() {
        let text = web("state_vault_id", "products = [\"wbe\"]\nstate_vault_id");
        assert_eq!(
            check_of(&text),
            ConfigCheck::Undeclared {
                kind: Declared::Product,
                name: "wbe".into(),
                declared: vec!["web".into()],
                // 09.13: a swapped pair of letters is one edit.
                closest: Some("web".into())
            }
        );
    }

    #[test]
    fn rejects_target_products_naming_a_source_only_product() {
        let text = bound(
            &web_plus(
                "[products.shared]\nsource_only = true\n[products.shared.keys.K]\nkind = \
                 \"secret\"\nenvironments = [\"prod\"]\n",
            ),
            "prod",
            "shared",
        );
        let text = replaced(
            &text,
            "state_vault_id",
            "products = [\"shared\"]\nstate_vault_id",
        );
        assert_eq!(
            check_of(&text),
            ConfigCheck::SourceOnlyListed {
                product: "shared".into()
            }
        );
    }

    #[test]
    fn two_targets_of_one_environment_on_one_app_are_refused() {
        let text = web_plus(
            "[environments.prod.targets.other]\nfly.app = \"web-prod\"\nfly.secret_name = \
             \"X__{KEY}\"\nstate_vault_id = \"s2\"\n",
        );
        assert_eq!(
            check_of(&text),
            ConfigCheck::SameTarget {
                label: "Fly".into(),
                locator: "app web-prod".into(),
                other: "other".into()
            }
        );
    }

    #[test]
    fn two_targets_of_one_environment_on_two_apps_load() {
        let text = web_plus(
            "[environments.prod.targets.other]\nfly.app = \"web-two\"\nfly.secret_name = \
             \"{KEY}\"\nstate_vault_id = \"s2\"\n",
        );
        assert_eq!(parse(&text).unwrap().environments["prod"].targets.len(), 2);
    }

    #[test]
    fn two_environments_on_one_app_and_template_are_refused() {
        let text = mutate(
            r#"fly.app = "mcproductlabs-portfolio-staging""#,
            r#"fly.app = "mcproductlabs-portfolio-production""#,
        );
        assert_eq!(
            field_of(&text),
            "environments.staging.targets.portfolio.fly.secret_name"
        );
    }

    #[test]
    fn two_environments_on_one_app_with_different_templates_load() {
        let t = mutate(
            "fly.app = \"mcproductlabs-portfolio-staging\"\nfly.secret_name = \"FLEET__{PRODUCT}__{KEY}\"",
            "fly.app = \"mcproductlabs-portfolio-production\"\nfly.secret_name = \"STG__{PRODUCT}__{KEY}\"",
        );
        assert!(parse(&t).is_ok());
    }

    #[test]
    fn parses_the_target_deploy_credentials() {
        let text = web(
            "state_vault_id",
            "deploy_credentials = \"op://Infra Prod/fly deploy\"\nstate_vault_id",
        );
        let f = parse(&text).unwrap();
        assert_eq!(
            f.environments["prod"].targets["site"]
                .deploy_credentials
                .as_ref()
                .map(ToString::to_string),
            Some("op://Infra Prod/fly deploy".to_string())
        );
    }

    #[test]
    fn deploy_credentials_with_a_field_is_refused_at_its_line() {
        let text = web(
            "state_vault_id",
            "deploy_credentials = \"op://v/i/FLY_API_TOKEN\"\nstate_vault_id",
        );
        assert_eq!(check_of(&text), ConfigCheck::DeployCredentialsRef);
    }

    #[test]
    fn deploy_credentials_must_be_an_op_reference() {
        let text = web(
            "state_vault_id",
            "deploy_credentials = \"vault/item\"\nstate_vault_id",
        );
        assert_eq!(
            field_of(&text),
            "environments.prod.targets.site.deploy_credentials"
        );
    }

    #[test]
    fn kubernetes_deploy_credentials_is_a_configuration_error() {
        let text = web(
            "fly.app = \"web-prod\"\nfly.secret_name = \"{KEY}\"\n",
            "deploy_credentials = \"op://v/deploy\"\nkubernetes.context = \"kind-dev\"\n\
             kubernetes.namespace = \"app\"\nkubernetes.deployment = \"web\"\n\
             kubernetes.env_name = \"{KEY}\"\n",
        );
        assert_eq!(
            check_of(&text),
            ConfigCheck::DeployCredentialsUnsupported {
                provider: "Kubernetes".into()
            }
        );
    }

    #[test]
    fn parses_the_environment_account() {
        let text = web(
            "[environments.prod]\n",
            "[environments.prod]\naccount = \"work.1password.com\"\n",
        );
        assert_eq!(
            parse(&text).unwrap().environments["prod"]
                .account
                .as_deref(),
            Some("work.1password.com")
        );
    }

    #[test]
    fn an_invalid_account_points_at_its_line() {
        let text = web(
            "[environments.prod]\n",
            "[environments.prod]\naccount = \"-work\"\n",
        );
        let m = config_err(&text);
        assert!(
            m.contains("line 2, column 1") && m.contains("account must be"),
            "{m}"
        );
    }

    #[test]
    fn an_unknown_environment_field_is_refused_at_its_line() {
        let text = web(
            "[environments.prod]\n",
            "[environments.prod]\nvault = \"x\"\n",
        );
        assert_eq!(field_of(&text), "environments.prod.vault");
    }

    /// Targets `site` (web) and `other` (api only) sharing state vault `sweb`.
    fn shared_state_vault() -> String {
        bound(
            &key(
                &web_plus(
                    "[environments.prod.targets.other]\nfly.app = \"api-prod\"\n\
                     fly.secret_name = \"{KEY}\"\nproducts = [\"api\"]\nstate_vault_id = \"sweb\"\n",
                ),
                "api",
                "API_KEY",
                r#"["prod"]"#,
                "",
            ),
            "prod",
            "api",
        )
    }

    #[test]
    fn a_state_vault_shared_by_targets_reading_other_boundaries_is_refused() {
        assert_eq!(config_code(&too_wide()), "state_vault_wider_than_values");
    }

    /// [`shared_state_vault`] with target `site` delivering only `web`.
    fn too_wide() -> String {
        replaced(
            &shared_state_vault(),
            "fly.app = \"web-prod\"",
            "fly.app = \"web-prod\"\nproducts = [\"web\"]",
        )
    }

    /// 03.04: the refusal is placed at the target's state_vault_id line.
    #[test]
    fn a_too_wide_state_vault_is_placed_at_its_line() {
        assert!(
            matches!(
                cause(&too_wide()),
                Cause::StateVaultTooWide { at: Some(_), .. }
            ),
            "{:?}",
            cause(&too_wide())
        );
    }

    #[test]
    fn a_state_vault_shared_by_targets_reading_the_same_boundaries_loads() {
        let text = replaced(
            &shared_state_vault(),
            "products = [\"api\"]",
            "products = [\"api\", \"web\"]",
        );
        assert!(parse(&text).is_ok());
    }

    // ---- delivery scope (FR-48, FR-56) -----------------------------------------------

    #[test]
    fn a_target_without_products_delivers_a_product_with_a_key_here() {
        assert!(parse(WEB).unwrap().delivers("prod", "site", "web"));
    }

    #[test]
    fn a_target_without_products_skips_a_product_with_keys_elsewhere_only() {
        let text = format!(
            "{}\n[environments.dev]\nboundaries.api = {{ vault_id = \"va\", item_id = \"ia\" }}\n",
            key(WEB, "api", "K", r#"["dev"]"#, "")
        );
        assert!(!parse(&text).unwrap().delivers("prod", "site", "api"));
    }

    #[test]
    fn a_target_with_products_delivers_only_those() {
        let text = bound(
            &key(
                &web("state_vault_id", "products = [\"web\"]\nstate_vault_id"),
                "api",
                "API_KEY",
                r#"["prod"]"#,
                "",
            ),
            "prod",
            "api",
        );
        assert!(!parse(&text).unwrap().delivers("prod", "site", "api"));
    }

    #[test]
    fn a_target_never_delivers_a_source_only_product() {
        let text = bound(
            &web_plus(
                "[products.shared]\nsource_only = true\n[products.shared.keys.K]\nkind = \
                 \"secret\"\nenvironments = [\"prod\"]\n",
            ),
            "prod",
            "shared",
        );
        assert!(!parse(&text).unwrap().delivers("prod", "site", "shared"));
    }

    #[test]
    fn an_unknown_target_delivers_nothing() {
        assert!(!parse(WEB).unwrap().delivers("prod", "nope", "web"));
    }

    // ---- boundaries (FR-57) ----------------------------------------------------------

    #[test]
    fn a_product_is_its_own_boundary_by_default() {
        assert_eq!(parse(WEB).unwrap().boundary_of("web"), "web");
    }

    #[test]
    fn a_product_in_a_group_uses_the_groups_boundary() {
        let text = web_plus("[products.web]\nboundary = \"core\"\n");
        let text = replaced(&text, "boundaries.web", "boundaries.core");
        assert_eq!(parse(&text).unwrap().boundary_of("web"), "core");
    }

    #[test]
    fn fleet_boundary_returns_the_recorded_ids() {
        assert_eq!(
            parse(WEB).unwrap().boundary("prod", "web").unwrap().item_id,
            "iweb"
        );
    }

    #[test]
    fn fleet_boundary_of_an_unrecorded_product_is_boundary_missing() {
        let f = parse(WEB).unwrap();
        assert!(matches!(
            f.boundary("prod", "api"),
            Err(e) if e.code_str() == "boundary_missing"
        ));
    }

    #[test]
    fn a_product_without_its_boundary_is_boundary_missing() {
        let text = key(WEB, "api", "K", r#"["prod"]"#, "");
        assert_eq!(config_code(&text), "boundary_missing");
    }

    #[test]
    fn a_from_source_without_its_boundary_is_boundary_missing() {
        let text = format!(
            "{WEB}[products.shared]\nsource_only = true\n[products.shared.keys.TOKEN]\nkind = \
             \"secret\"\nenvironments = [\"prod\"]\n[products.web.keys.TOKEN]\nkind = \
             \"secret\"\nenvironments = [\"prod\"]\nfrom = \"shared/TOKEN\"\n"
        );
        assert!(matches!(
            cause(&text),
            Cause::BoundaryMissing { product, .. } if product.as_str() == "shared"
        ));
    }

    #[test]
    fn boundary_missing_names_the_environment() {
        assert!(matches!(
            cause(&key(WEB, "api", "K", r#"["prod"]"#, "")),
            Cause::BoundaryMissing { env, .. } if env.as_str() == "prod"
        ));
    }

    #[test]
    fn a_recorded_boundary_nothing_uses_is_refused() {
        assert_eq!(
            invalid(&bound(WEB, "prod", "old")),
            (
                "environments.prod.boundaries.old".to_string(),
                FieldRule::Check {
                    check: ConfigCheck::BoundaryUnused {
                        env: "prod".into(),
                        products: vec![]
                    }
                }
            )
        );
    }

    #[test]
    fn rejects_a_boundary_vault_id_that_reads_as_a_flag() {
        assert_eq!(
            field_of(&web("\"vweb\"", "\"-v\"")),
            "environments.prod.boundaries.web.vault_id"
        );
    }

    #[test]
    fn rejects_a_padded_boundary_item_id() {
        assert_eq!(
            check_of(&web("\"iweb\"", "\" iweb\"")),
            ConfigCheck::Whitespace
        );
    }

    #[test]
    fn rejects_a_boundary_item_id_with_a_slash() {
        assert_eq!(
            invalid(&web("\"iweb\"", "\"i/web\"")),
            (
                "environments.prod.boundaries.web.item_id".to_string(),
                FieldRule::Pattern { id: PatternId::Id }
            )
        );
    }

    #[test]
    fn rejects_a_boundary_without_an_item_id() {
        assert_eq!(
            invalid(&web(", item_id = \"iweb\"", "")),
            (
                "environments.prod.boundaries.web.item_id".to_string(),
                FieldRule::Missing
            )
        );
    }

    #[test]
    fn rejects_a_bad_boundary_name() {
        assert_eq!(
            field_of(&web("boundaries.web", "boundaries.Web")),
            "environments.prod.boundaries.Web"
        );
    }

    #[test]
    fn rejects_a_bad_product_boundary_group() {
        assert_eq!(
            field_of(&web_plus("[products.web]\nboundary = \"Core\"\n")),
            "products.web.boundary"
        );
    }

    // ---- removed forms (FR-60) -------------------------------------------------------

    #[test]
    fn a_profile_table_is_refused_showing_the_products_form() {
        assert!(matches!(
            rule_of(&format!("[profile]\nkind = \"fleet\"\n{WEB}")),
            FieldRule::RemovedForm { form: "[profile]", replacement }
                if replacement.contains("[products.<name>.keys.<KEY>]")
        ));
    }

    #[test]
    fn a_removed_form_points_at_its_line_and_column() {
        let m = config_err(&format!("{WEB}[profile]\nkind = \"simple\"\n"));
        assert!(m.contains(" at line 12, column 2: "), "{m}");
    }

    #[test]
    fn top_level_keys_are_refused_showing_the_products_form() {
        assert_eq!(
            rule_of(&format!(
                "{WEB}[keys.JWT_KEY]\nkind = \"secret\"\nenvironments = [\"prod\"]\n"
            )),
            FieldRule::RemovedForm {
                form: "top-level [keys]",
                replacement: "[products.<name>.keys.JWT_KEY]".into()
            }
        );
    }

    #[test]
    fn an_environment_vault_id_is_refused_showing_the_boundaries_form() {
        let text = web(
            "[environments.prod]\n",
            "[environments.prod]\nvault_id = \"v\"\n",
        );
        assert!(matches!(
            rule_of(&text),
            FieldRule::RemovedForm { replacement, .. }
                if replacement.contains("boundaries.<product> = { vault_id = \"...\", item_id = \"...\" }")
        ));
    }

    #[test]
    fn an_environment_item_id_is_refused_showing_the_boundaries_form() {
        let text = web(
            "[environments.prod]\n",
            "[environments.prod]\nitem_id = \"i\"\n",
        );
        assert!(matches!(
            rule_of(&text),
            FieldRule::RemovedForm { replacement, .. } if replacement.contains("boundaries.<product> = {")
        ));
    }

    #[test]
    fn an_environment_fly_section_is_refused_showing_the_target_form() {
        let text = web(
            "[environments.prod]\n",
            "[environments.prod]\nfly.app = \"a\"\nfly.secret_name = \"{KEY}\"\n",
        );
        assert!(matches!(
            rule_of(&text),
            FieldRule::RemovedForm { replacement, .. } if replacement
                == "a named target, [environments.prod.targets.<name>] with fly.app = ..., fly.secret_name = ..."
        ));
    }

    #[test]
    fn an_environment_azure_table_is_refused_showing_the_target_form() {
        let text = format!("{WEB}[environments.prod.azure]\nkey_vault = \"kv\"\n");
        assert!(matches!(
            rule_of(&text),
            FieldRule::RemovedForm { replacement, .. }
                if replacement.ends_with("with azure.key_vault = ...")
        ));
    }

    #[test]
    fn an_environment_deploy_credentials_is_refused_showing_the_target_form() {
        let text = web(
            "[environments.prod]\n",
            "[environments.prod]\ndeploy_credentials = \"op://v/i\"\n",
        );
        assert!(matches!(
            rule_of(&text),
            FieldRule::RemovedForm { replacement, .. } if replacement
                == "deploy_credentials = \"...\" under [environments.prod.targets.<name>]"
        ));
    }

    #[test]
    fn an_environment_state_vault_id_is_refused_showing_the_target_form() {
        let text = web(
            "[environments.prod]\n",
            "[environments.prod]\nstate_vault_id = \"s\"\n",
        );
        assert!(matches!(
            rule_of(&text),
            FieldRule::RemovedForm { replacement, .. } if replacement
                == "state_vault_id = \"...\" under [environments.prod.targets.<name>]"
        ));
    }

    #[test]
    fn github_products_is_refused_showing_the_target_products() {
        let text = web(
            "fly.app = \"web-prod\"\nfly.secret_name = \"{KEY}\"\n",
            "github.repo = \"org/web\"\ngithub.products = [\"web\"]\n",
        );
        assert!(matches!(
            rule_of(&text),
            FieldRule::RemovedForm { replacement, .. } if replacement == "targets.site.products = [...]"
        ));
    }

    #[test]
    fn a_bare_from_is_refused_showing_the_product_form() {
        let text = web_plus(
            "[products.web.keys.PRISMA_URL]\nkind = \"secret\"\nenvironments = [\"prod\"]\nfrom = \"DATABASE_URL\"\n",
        );
        assert!(matches!(
            rule_of(&text),
            FieldRule::RemovedForm { replacement, .. } if replacement == "from = \"<product>/DATABASE_URL\""
        ));
    }

    // ---- name collisions (FR-8, FR-30) ------------------------------------------------

    #[test]
    fn rejects_a_collision_from_product_normalization() {
        let text = key(
            &with_prod_key("my-app", "K", ""),
            "my_app",
            "K",
            r#"["prod"]"#,
            "",
        );
        assert!(matches!(
            check_of(&bound(&text, "prod", "my_app")),
            ConfigCheck::NameTaken { other, owner, .. } if other == "my-app/K" && owner == "my_app/K"
        ));
    }

    #[test]
    fn rejects_a_collision_across_a_double_underscore() {
        let text = key(
            &with_prod_key("a__b", "C", ""),
            "a",
            "B__C",
            r#"["prod"]"#,
            "",
        );
        assert!(matches!(
            check_of(&bound(&text, "prod", "a")),
            ConfigCheck::NameTaken { other, owner, .. } if other == "a/B__C" && owner == "a__b/C"
        ));
    }

    #[test]
    fn a_collision_names_the_environment_and_target() {
        let text = key(
            &with_prod_key("my-app", "K", ""),
            "my_app",
            "K",
            r#"["prod"]"#,
            "",
        );
        let field = field_of(&bound(&text, "prod", "my_app"));
        assert!(
            field.starts_with("environments.prod.targets.portfolio."),
            "{field}"
        );
    }

    /// A source-only product whose one key renders the same Fly name as a delivered key of
    /// another product: `my-app` and `my_app` both normalize to `MY_APP` (FR-8).
    fn shared_name_fleet(source_only: bool) -> String {
        format!(
            "[environments.ci]\n\
             boundaries.my_app = {{ vault_id = \"v1\", item_id = \"i1\" }}\n\
             boundaries.my-app = {{ vault_id = \"v2\", item_id = \"i2\" }}\n\
             [environments.ci.targets.app]\n\
             fly.app = \"app\"\nfly.secret_name = \"FLEET__{{PRODUCT}}__{{KEY}}\"\n\
             state_vault_id = \"s\"\n\
             [products.my_app]\nsource_only = {source_only}\n\
             [products.my_app.keys.K]\nkind = \"secret\"\nenvironments = [\"ci\"]\n\
             [products.my-app.keys.K]\nkind = \"secret\"\nenvironments = [\"ci\"]\n"
        )
    }

    #[test]
    fn a_source_only_product_is_exempt_from_the_collision_check() {
        let r = parse(&shared_name_fleet(true));
        assert!(r.is_ok(), "{:?}", r.err());
    }

    #[test]
    fn delivered_products_rendering_one_name_collide() {
        assert!(matches!(
            check_of(&shared_name_fleet(false)),
            ConfigCheck::NameTaken { name, .. } if name == "FLEET__MY_APP__K"
        ));
    }

    #[test]
    fn a_source_only_product_without_keys_is_refused_at_its_line() {
        let text = format!("{}\n[products.shared]\nsource_only = true\n", ok());
        assert!(
            matches!(
                cause(&text),
                Cause::ConfigInvalid {
                    at: Some(_),
                    rule: FieldRule::Check {
                        check: ConfigCheck::SourceOnlyWithoutKeys { .. }
                    },
                    ..
                }
            ),
            "{:?}",
            cause(&text)
        );
    }

    #[test]
    fn source_only_with_a_non_boolean_value_is_refused_at_its_line() {
        let text = format!(
            "{}\n[products.shared]\nsource_only = \"true\"\n\
             [products.shared.keys.FLY_API_TOKEN]\nkind = \"secret\"\nenvironments = [\"prod\"]\n",
            ok()
        );
        assert_eq!(
            invalid(&text),
            (
                "products.shared.source_only".to_string(),
                FieldRule::Type {
                    expected: "true or false"
                }
            )
        );
    }

    // ---- shared keys (FR-45) ----------------------------------------------------------

    /// The fixture plus `api/DATABASE_URL` (secret, staging and prod) and a worker key whose
    /// table body is `worker`, with their boundaries recorded where they have keys.
    fn shared(worker: &str) -> String {
        let text = format!(
            "{}\n[products.api.keys.DATABASE_URL]\nkind = \"secret\"\nenvironments = [\"staging\", \"prod\"]\n\n[products.worker.keys.DATABASE_URL]\n{worker}\n",
            ok()
        );
        bound(
            &bound(&bound(&text, "staging", "api"), "prod", "api"),
            "prod",
            "worker",
        )
    }

    const WORKER_FROM_API: &str =
        "kind = \"secret\"\nfrom = \"api/DATABASE_URL\"\nenvironments = [\"prod\"]";

    #[test]
    fn a_shared_key_loads_with_its_source() {
        let f = parse(&shared(WORKER_FROM_API)).unwrap();
        assert_eq!(
            f.products["worker"].keys["DATABASE_URL"].source(),
            Some(("api", "DATABASE_URL"))
        );
    }

    #[test]
    fn a_shared_key_refuses_an_undeclared_source() {
        let text = shared("kind = \"secret\"\nfrom = \"api/DB_URL\"\nenvironments = [\"prod\"]");
        assert!(matches!(
            check_of(&text),
            ConfigCheck::Undeclared { kind: Declared::Key, name, .. } if name == "api/DB_URL"
        ));
    }

    #[test]
    fn a_shared_key_error_points_at_the_from_line() {
        let e = config_err(&shared(
            "kind = \"secret\"\nfrom = \"api/DB_URL\"\nenvironments = [\"prod\"]",
        ));
        assert!(e.contains("at line 55, column 1"), "{e}");
    }

    #[test]
    fn a_shared_key_refuses_a_source_of_another_kind() {
        let text =
            shared("kind = \"config\"\nfrom = \"api/DATABASE_URL\"\nenvironments = [\"prod\"]");
        assert_eq!(
            check_of(&text),
            ConfigCheck::FromKind {
                source: "api/DATABASE_URL".into(),
                source_kind: "secret",
                kind: "config"
            }
        );
    }

    #[test]
    fn a_shared_key_refuses_a_chain() {
        let text = bound(
            &format!(
                "{}\n[products.jobs.keys.DATABASE_URL]\nkind = \"secret\"\nfrom = \"worker/DATABASE_URL\"\nenvironments = [\"prod\"]\n",
                shared(WORKER_FROM_API)
            ),
            "prod",
            "jobs",
        );
        assert_eq!(
            check_of(&text),
            ConfigCheck::FromChain {
                source: "worker/DATABASE_URL".into(),
                its_from: "api/DATABASE_URL".into()
            }
        );
    }

    #[test]
    fn a_shared_key_refuses_a_cycle() {
        let text = format!(
            "{}\n[products.a.keys.K]\nkind = \"secret\"\nfrom = \"b/K\"\nenvironments = [\"prod\"]\n\n[products.b.keys.K]\nkind = \"secret\"\nfrom = \"a/K\"\nenvironments = [\"prod\"]\n",
            ok()
        );
        assert!(matches!(check_of(&text), ConfigCheck::FromCycle { .. }));
    }

    #[test]
    fn a_shared_key_refuses_its_own_name() {
        let text =
            shared("kind = \"secret\"\nfrom = \"worker/DATABASE_URL\"\nenvironments = [\"prod\"]");
        assert_eq!(check_of(&text), ConfigCheck::FromSelf);
    }

    #[test]
    fn a_shared_key_refuses_an_environment_its_source_lacks() {
        let text = format!(
            "{}\n[products.api.keys.DATABASE_URL]\nkind = \"secret\"\nenvironments = [\"prod\"]\n\n[products.worker.keys.DATABASE_URL]\nkind = \"secret\"\nfrom = \"api/DATABASE_URL\"\nenvironments = [\"staging\", \"prod\"]\n",
            ok()
        );
        assert_eq!(
            check_of(&text),
            ConfigCheck::FromEnvironment {
                source: "api/DATABASE_URL".into(),
                env: "staging".into()
            }
        );
    }

    #[test]
    fn a_shared_key_refuses_an_op_reference() {
        let text = shared(
            "kind = \"secret\"\nfrom = \"op://vprd/other/api/DATABASE_URL\"\nenvironments = [\"prod\"]",
        );
        assert_eq!(check_of(&text), ConfigCheck::FromCrossEnvironment);
    }

    #[test]
    fn a_shared_key_refuses_a_cross_environment_reference() {
        let text = shared(
            "kind = \"secret\"\nfrom = \"staging/api/DATABASE_URL\"\nenvironments = [\"prod\"]",
        );
        assert_eq!(check_of(&text), ConfigCheck::FromCrossEnvironment);
    }

    #[test]
    fn a_shared_key_refuses_its_own_immutable() {
        let text = shared(
            "kind = \"secret\"\nfrom = \"api/DATABASE_URL\"\nimmutable = true\nenvironments = [\"prod\"]",
        );
        assert_eq!(
            invalid(&text),
            (
                "products.worker.keys.DATABASE_URL.immutable".to_string(),
                FieldRule::ConflictsWith {
                    field: dotted(&["products", "worker", "keys", "DATABASE_URL", "from"])
                }
            )
        );
    }

    #[test]
    fn a_shared_keys_immutable_follows_its_source() {
        let text = with_prod_key(
            "worker",
            "INTEGRATION_ENC_KEY",
            "from = \"allumata/INTEGRATION_ENC_KEY\"\n",
        );
        assert!(parse(&text).unwrap().products["worker"].keys["INTEGRATION_ENC_KEY"].immutable);
    }

    /// FR-24, FR-60: the removal error's suggested `regex` rule pastes into the file as is
    /// and loads.
    #[test]
    fn the_suggested_regex_replacement_loads() {
        let FieldRule::RemovedForm { replacement, .. } = rule_of(&with_prod_key(
            "p",
            "K1",
            "rules = { ensure_prefix = \"p-\", pattern = \"[a-z]+\" }\n",
        )) else {
            panic!("expected the removed form");
        };
        let rule = replacement.strip_prefix("regex = ").unwrap();
        let text = with_prod_key(
            "p",
            "K1",
            &format!("rules = {{ ensure_prefix = \"p-\", regex = {rule} }}\n"),
        );
        assert!(parse(&text).is_ok(), "{text}");
    }

    // ---- personal keys and environment display fields (FR-55) ----------------------

    /// `dev` (run-only, titled) and `prod` (one target, audience `devops`), both recording
    /// the boundaries of `api` and, when `shared` holds, `shared`; then `extra`.
    fn team(shared: bool, extra: &str) -> String {
        let more = if shared {
            "boundaries.shared = { vault_id = \"vs\", item_id = \"is\" }\n"
        } else {
            ""
        };
        format!(
            "[environments.dev]\nboundaries.api = {{ vault_id = \"vdev\", item_id = \"idev\" }}\n\
             {more}title = \"Local development\"\n\
             [environments.prod]\nboundaries.api = {{ vault_id = \"vprd\", item_id = \"iprd\" }}\n\
             audience = \"devops\"\n\
             [environments.prod.targets.web]\nfly.app = \"a\"\n\
             fly.secret_name = \"FLEET__{{PRODUCT}}__{{KEY}}\"\nstate_vault_id = \"s\"\n\
             [products.api.keys.DATABASE_URL]\nkind = \"secret\"\nenvironments = [\"dev\", \"prod\"]\n\
             {extra}"
        )
    }

    #[test]
    fn a_personal_key_in_a_local_environment_loads() {
        let text = team(
            false,
            "[products.api.keys.OPENAI_API_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\npersonal = true\n",
        );
        assert!(parse(&text).is_ok());
    }

    #[test]
    fn a_personal_key_is_refused_in_an_environment_with_targets() {
        let text = team(
            false,
            "[products.api.keys.OPENAI_API_KEY]\nkind = \"secret\"\nenvironments = [\"dev\", \"prod\"]\npersonal = true\n",
        );
        assert_eq!(
            check_of(&text),
            ConfigCheck::PersonalOnTarget { env: "prod".into() }
        );
    }

    #[test]
    fn products_share_a_personal_value_through_a_personal_source() {
        // A source holding only personal keys needs no boundary (FR-55, FR-57).
        let text = team(
            false,
            "[products.shared]\nsource_only = true\n\
             [products.shared.keys.OPENAI_API_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\npersonal = true\n\
             [products.api.keys.OPENAI_API_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\npersonal = true\nfrom = \"shared/OPENAI_API_KEY\"\n",
        );
        assert!(parse(&text).is_ok());
    }

    #[test]
    fn a_team_key_cannot_read_a_personal_value() {
        let text = team(
            true,
            "[products.shared]\nsource_only = true\n\
             [products.shared.keys.OPENAI_API_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\npersonal = true\n\
             [products.api.keys.OPENAI_API_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\nfrom = \"shared/OPENAI_API_KEY\"\n",
        );
        assert!(matches!(
            check_of(&text),
            ConfigCheck::PersonalMix {
                personal: false,
                ..
            }
        ));
    }

    #[test]
    fn an_environment_keeps_its_display_name() {
        assert_eq!(
            parse(&team(false, "")).unwrap().environments["dev"].display(),
            "Local development"
        );
    }

    #[test]
    fn an_environment_keeps_its_audience() {
        assert_eq!(
            parse(&team(false, "")).unwrap().environments["prod"]
                .audience
                .as_deref(),
            Some("devops")
        );
    }

    #[test]
    fn an_undefined_environment_is_unknown_env() {
        assert_eq!(
            fixture().environment("qa").unwrap_err().code_str(),
            "unknown_env"
        );
    }

    // ---- discovery and name validators ------------------------------------------------

    #[test]
    fn discover_finds_secrets_toml_in_start_directory() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("secrets.toml");
        std::fs::write(&file, "").unwrap();
        assert_eq!(discover(dir.path()), Some(file));
    }

    #[test]
    fn discover_finds_secrets_toml_in_ancestor_directory() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("secrets.toml");
        std::fs::write(&file, "").unwrap();
        let nested = dir.path().join("a").join("b");
        std::fs::create_dir_all(&nested).unwrap();
        assert_eq!(discover(&nested), Some(file));
    }

    #[test]
    fn discover_prefers_the_nearest_secrets_toml() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("secrets.toml"), "").unwrap();
        let nested = dir.path().join("a");
        std::fs::create_dir_all(&nested).unwrap();
        let near = nested.join("secrets.toml");
        std::fs::write(&near, "").unwrap();
        assert_eq!(discover(&nested), Some(near));
    }

    #[test]
    fn discover_returns_none_when_no_secrets_toml_exists() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a");
        std::fs::create_dir_all(&nested).unwrap();
        assert_eq!(discover(&nested), None);
    }

    #[test]
    fn env_names_are_upper_snake_case() {
        let ok = ["A", "OPENAI_API_KEY", "K2"].iter().all(|s| is_env_name(s));
        let bad = ["", "_A", "1A", "A-B", "Abc"]
            .iter()
            .any(|s| is_env_name(s));
        assert_eq!((ok, bad), (true, false));
    }

    #[test]
    fn product_names_are_lower_case() {
        let ok = ["allumata", "my-app_2"].iter().all(|s| is_product_name(s));
        let bad = ["", "-a", "App"].iter().any(|s| is_product_name(s));
        assert_eq!((ok, bad), (true, false));
    }

    #[test]
    fn target_names_are_lower_case_with_dashes() {
        let ok = ["site", "p-overflow", "a1"]
            .iter()
            .all(|s| is_target_name(s));
        let bad = ["", "-a", "1a", "a_b", "Site"]
            .iter()
            .any(|s| is_target_name(s));
        assert_eq!((ok, bad), (true, false));
    }

    #[test]
    fn ids_are_argv_safe() {
        let ok = ["vprd", "a1.b_c-d", "9x"].iter().all(|s| is_id(s));
        let bad = ["", "-a", ".a", "a b", "a/b"].iter().any(|s| is_id(s));
        assert_eq!((ok, bad), (true, false));
    }

    // ---- audit 03: the field and rule come from the validator --------------------------

    /// 03.01: a role outside the pattern names the roles field, not the key's table.
    #[test]
    fn a_bad_role_names_the_roles_field() {
        let text = with_prod_key("p", "K1", "roles = [\"Serve\"]\n");
        assert_eq!(field_of(&text), "products.p.keys.K1.roles");
    }

    // --- target-level roles (#136, M3) ---

    /// The fixture plus a prod target `products = ["p"]` line, a target `roles` line
    /// and a prod key with `key_roles`.
    fn with_target_roles(target_roles: &str, key_roles: &str) -> String {
        let text = with_prod_key("p", "K1", &format!("roles = {key_roles}\n"));
        replaced(
            &text,
            "state_vault_id = \"sprd\"\n",
            &format!("state_vault_id = \"sprd\"\nproducts = [\"p\"]\n{target_roles}\n"),
        )
    }

    #[test]
    fn a_listed_role_scoped_product_on_a_target_without_roles_is_refused() {
        let text = with_prod_key("p", "K1", "roles = [\"serve\"]\n");
        let text = replaced(
            &text,
            "state_vault_id = \"sprd\"\n",
            "state_vault_id = \"sprd\"\nproducts = [\"p\"]\n",
        );
        assert_eq!(
            invalid(&text),
            (
                "environments.prod.targets.portfolio.roles".to_string(),
                FieldRule::Missing
            )
        );
    }

    #[test]
    fn a_target_role_no_delivered_key_declares_is_refused() {
        let text = with_target_roles("roles = [\"serve\"]", "[\"migrate\"]");
        assert!(matches!(
            check_of(&text),
            ConfigCheck::Undeclared { kind: Declared::Role, ref name, .. } if name == "serve"
        ));
    }

    #[test]
    fn an_empty_target_roles_list_is_refused() {
        let text = with_target_roles("roles = []", "[\"serve\"]");
        assert_eq!(check_of(&text), ConfigCheck::EmptyRoles);
    }

    #[test]
    fn a_target_role_a_delivered_key_declares_loads() {
        let text = with_target_roles("roles = [\"serve\"]", "[\"serve\"]");
        assert!(parse(&text).is_ok());
    }

    #[test]
    fn a_default_target_delivering_role_scoped_keys_is_refused() {
        let text = with_prod_key("p", "K1", "roles = [\"serve\"]\n");
        assert_eq!(
            invalid(&text),
            (
                "environments.prod.targets.portfolio.roles".to_string(),
                FieldRule::Missing
            )
        );
    }

    /// 03.01: a reserved directory variable is refused as reserved, not as a pattern it
    /// already matches.
    #[test]
    fn a_reserved_secrets_dir_env_is_reserved() {
        let text = replaced(
            &with_file("openai/api-key"),
            "secrets_dir_env = \"APP_SECRETS_DIR\"",
            "secrets_dir_env = \"PATH\"",
        );
        assert!(matches!(rule_of(&text), FieldRule::Reserved { .. }));
    }

    /// 03.01: a bad boundary ID names the ID field, not the boundary's table.
    #[test]
    fn a_bad_boundary_vault_id_names_the_vault_id() {
        assert_eq!(
            field_of(&web("\"vweb\"", "\"-x\"")),
            "environments.prod.boundaries.web.vault_id"
        );
    }

    /// 03.01: a rendered name the target cannot hold names the template field to change.
    #[test]
    fn a_bad_rendered_name_names_the_template_field() {
        let text = mutate("FLEET__{PRODUCT}__{KEY}", "fleet__{PRODUCT}__{KEY}");
        assert!(
            field_of(&text).ends_with(".fly.secret_name"),
            "{}",
            field_of(&text)
        );
    }

    /// 03.01: the Do of a rendered name never repeats a regular expression.
    #[test]
    fn a_bad_rendered_name_fix_has_no_regex() {
        let text = mutate("FLEET__{PRODUCT}__{KEY}", "fleet__{PRODUCT}__{KEY}");
        assert!(
            do_of(&text).is_some_and(|d| !d.contains('^')),
            "{:?}",
            do_of(&text)
        );
    }

    /// 03.03: a prefix_by_mode mode an environment does not set is refused at load.
    #[test]
    fn a_mode_missing_in_an_environment_is_refused_at_load() {
        let text = mutate("modes.allumata.payments = \"test\"\n", "");
        assert_eq!(
            invalid(&text),
            (
                "environments.staging.modes.allumata.payments".to_string(),
                FieldRule::Missing
            )
        );
    }

    /// 03.03: a mode value neither mapped nor skipped is refused at load.
    #[test]
    fn an_unmapped_mode_value_is_refused_at_load() {
        let text = mutate(
            "modes.allumata.payments = \"test\"",
            "modes.allumata.payments = \"sandbox\"",
        );
        assert!(matches!(rule_of(&text), FieldRule::ModeUnmapped { .. }));
    }

    /// 03.03: the unmapped mode lists the values the environment may set.
    #[test]
    fn an_unmapped_mode_lists_the_allowed_values() {
        let text = mutate(
            "modes.allumata.payments = \"test\"",
            "modes.allumata.payments = \"sandbox\"",
        );
        assert!(matches!(
            rule_of(&text),
            FieldRule::ModeUnmapped { allowed, .. } if allowed == ["live", "test", "off", "external"]
        ));
    }

    /// 03.12: a configuration file that cannot be read is unreadable, not "not found".
    #[test]
    fn an_unreadable_file_is_config_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            load(dir.path()).unwrap_err().code_str(),
            "config_unreadable"
        );
    }

    /// 03.12: a path given with --config is named as given.
    #[test]
    fn an_unreadable_flag_path_names_the_flag() {
        let dir = tempfile::tempdir().unwrap();
        let given = GivenBy::Flag {
            flag: "--config".into(),
        };
        assert!(matches!(
            load_given(dir.path().join("nope.toml"), given)
                .unwrap_err()
                .cause(),
            Some((
                Cause::ConfigUnreadable {
                    given_by: GivenBy::Flag { .. },
                    ..
                },
                _
            ))
        ));
    }

    /// 03.13: a removed form names no requirement ID.
    #[test]
    fn a_removed_form_names_no_requirement_id() {
        assert!(
            !config_err(&format!("[profile]\nkind = \"fleet\"\n{WEB}")).contains("FR-"),
            "{}",
            config_err(&format!("[profile]\nkind = \"fleet\"\n{WEB}"))
        );
    }

    /// 03.15: a duplicate key is refused as a duplicate.
    #[test]
    fn a_duplicate_key_is_a_duplicate() {
        let text = mutate("kind = \"secret\"", "kind = \"secret\"\nkind = \"secret\"");
        assert_eq!(rule_of(&text), FieldRule::DuplicateKey);
    }

    /// 03.15: a string where a list belongs says to write a list.
    #[test]
    fn a_string_where_a_list_belongs_says_list() {
        let text = mutate(r#"environments = ["prod"]"#, r#"environments = "prod""#);
        assert_eq!(
            rule_of(&text),
            FieldRule::Type {
                expected: "a list, for example [\"prod\"]"
            }
        );
    }

    /// 03.02: a boundary missing from a manifest names the manifest, so its step is the
    /// manifest's route and never `opv bootstrap`.
    #[test]
    fn a_manifests_missing_boundary_names_the_manifest() {
        let e = parse_at(
            &key(WEB, "api", "K", r#"["prod"]"#, ""),
            Source::ManifestIn {
                title: "opv · web",
                vault: "vlt",
            },
        )
        .unwrap_err();
        assert!(matches!(
            e.cause(),
            Some((
                Cause::BoundaryMissing {
                    source: ConfigSource::Manifest { .. },
                    ..
                },
                _
            ))
        ));
    }

    /// 03.02: a fleet read from a manifest reports a later missing boundary against it.
    #[test]
    fn a_manifest_fleets_boundary_lookup_names_the_manifest() {
        let f = parse_at(
            WEB,
            Source::ManifestIn {
                title: "opv · web",
                vault: "vlt",
            },
        )
        .unwrap();
        assert!(matches!(
            f.boundary("prod", "api").unwrap_err().cause(),
            Some((
                Cause::BoundaryMissing {
                    source: ConfigSource::Manifest { .. },
                    ..
                },
                _
            ))
        ));
    }

    /// 03.02: an undeclared environment substitutes only a unique close name (X2).
    #[test]
    fn an_undeclared_environment_offers_the_unique_close_name() {
        assert!(matches!(
            fixture().environment("prd").unwrap_err().cause(),
            Some((Cause::NotDeclared { closest: Some(c), .. }, _)) if c.as_str() == "prod"
        ));
    }

    /// 03.04: environments shared by two targets are placed at the second target's section.
    #[test]
    fn a_shared_target_across_environments_is_placed() {
        let text = mutate(
            r#"fly.app = "mcproductlabs-portfolio-staging""#,
            r#"fly.app = "mcproductlabs-portfolio-production""#,
        );
        assert!(matches!(
            cause(&text),
            Cause::ConfigInvalid { at: Some(_), .. }
        ));
    }
}
