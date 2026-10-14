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
use crate::domain::rules::{SIGNOZ_BODY, SIGNOZ_PREFIX};
use crate::domain::{
    Boundary, Environment, Fleet, ItemRef, KeySpec, Product, Target, boundary_missing, key_label,
};
use crate::error::Error;
use crate::provider::{NameRules, Section, StoreConfig, StoreNameRules, TargetConfig};

mod locate;

/// Read and validate the configuration at `path`. An error names the file, the line and
/// the field, and the fix when the message names what is allowed (H10, FR-2).
pub fn load(path: impl AsRef<Path>) -> Result<Fleet, Error> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path).map_err(|e| {
        Error::Config(format!("cannot read {}: {e}", path.display()).into())
            .with_code(crate::error::Code::ConfigNotFound)
            .with_do("check the path given with --config or OPV_CONFIG")
    })?;
    parse(&text).map_err(|e| locate::relocate(e, &text, path))
}

/// Where a configuration text came from, for its error messages (H10, FR-44).
#[derive(Debug, Clone, Copy)]
pub enum Source<'a> {
    /// A `secrets.toml` (or `--config`) file: errors read `<path>:<line>: <field>: …`.
    File(&'a Path),
    /// A project manifest in 1Password, by title: errors read
    /// `manifest "opv · app": <field>: …`.
    Manifest(&'a str),
}

/// [`parse`] with errors naming `source`, the line and the field, with `fix:` lines.
pub fn parse_at(text: &str, source: Source<'_>) -> Result<Fleet, Error> {
    parse(text).map_err(|e| locate::relocate_at(e, text, source))
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

/// How the error for a missing configuration starts; `doctor` keys its next step on it.
pub const NOT_FOUND: &str = "no secrets.toml found in ";

/// No `secrets.toml` in `start` or a parent (P3): the first-run router, offering both
/// starting paths and the explicit `--config`.
pub fn not_found(start: &Path) -> Error {
    Error::Config(
        format!(
            "{NOT_FOUND}{} or any parent directory.\n  \
             Project ships opv.setup.toml?   opv setup\n  \
             Configured elsewhere?           opv --config <path> <command>",
            start.display()
        )
        .into(),
    )
    .with_code(crate::error::Code::ConfigNotFound)
    .with_next("opv init dev")
}

/// Parse and validate configuration text. A removed form (FR-60) fails before anything else
/// is read, showing the form to write instead.
pub fn parse(text: &str) -> Result<Fleet, Error> {
    let invalid = |e: toml::de::Error| {
        Error::Config(
            format!(
                "invalid secrets.toml: {}",
                toml_error(text, e.span(), e.message())
            )
            .into(),
        )
    };
    let doc = Doc::parse(text).map_err(invalid)?;
    removed_forms(&doc)?;
    // The removed `pattern` rule must be reported as such, rather than as the
    // `deny_unknown_fields` error the typed parse would give (FR-60).
    reject_removed_pattern(&doc)?;
    let raw: RawConfig = toml::from_str(text).map_err(invalid)?;
    validate(raw, &doc)
}

/// FR-24, FR-60: the `pattern` rule is removed (0.7.0); a file that still sets it must
/// fail at load with the key and the equivalent `regex` rule. The typed parse cannot do
/// this (its `deny_unknown_fields` reports only "unknown field"), so the raw document is
/// walked first: every `rules` table gets one check, and the error points at the `pattern`
/// entry's line and column. The replacement is built from configuration (the prefix and
/// the pattern) and never from a value. A top-level `[keys]` table is [`removed_forms`]'s.
fn reject_removed_pattern(doc: &Doc<'_>) -> Result<(), Error> {
    // (owner label, path to the rules table) for every declared key.
    let mut rules_tables: Vec<(String, Vec<String>)> = Vec::new();
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
                rules_tables.push((
                    key_label(product, key),
                    vec![
                        "products".into(),
                        product.into(),
                        "keys".into(),
                        key.into(),
                        "rules".into(),
                    ],
                ));
            }
        }
    }
    for (owner, base) in rules_tables {
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
        let msg = format!(
            "{owner}: the pattern rule was removed; use regex = {} instead",
            toml::Value::String(regex)
        );
        return Err(doc.at_path(&path_refs, msg));
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

    /// `msg` located at the declaration of key `key` of `product` (`[products.<p>.keys.<K>]`),
    /// like [`Doc::at`].
    fn key_at(&self, product: &str, key: &str, msg: String) -> Error {
        fn find<'a, 't>(
            t: &'a DeTable<'t>,
            name: &str,
        ) -> Option<(std::ops::Range<usize>, Option<&'a DeTable<'t>>)> {
            t.iter()
                .find(|(n, _)| n.get_ref().as_ref() == name)
                .map(|(n, v)| (n.span(), v.get_ref().as_table()))
        }
        let root = self.root.get_ref();
        let keys = find(root, "products")
            .and_then(|(_, t)| t)
            .and_then(|t| find(t, product))
            .and_then(|(_, t)| t)
            .and_then(|t| find(t, "keys"))
            .and_then(|(_, t)| t);
        match keys.and_then(|t| find(t, key)) {
            Some((span, _)) => cfg(format!(
                "invalid secrets.toml: {}",
                located(self.text, span, &msg)
            )),
            None => cfg(msg),
        }
    }

    /// `msg` located at the key `environments.<env>.<key>` the way the TOML parser reports
    /// its own errors (line, column, the line itself), so every configuration error points
    /// at the file (FR-2). Just `msg` if the key cannot be found.
    fn at(&self, env: &str, key: &str, msg: String) -> Error {
        self.at_path(&["environments", env, key], msg)
    }

    /// `msg` located at the key `path` (e.g. `["stores", "prod-vault"]`), like [`Doc::at`].
    fn at_path(&self, path: &[&str], msg: String) -> Error {
        let mut table = Some(self.root.get_ref());
        let mut span = None;
        for part in path {
            let Some((n, v)) =
                table.and_then(|t| t.iter().find(|(n, _)| n.get_ref().as_ref() == *part))
            else {
                span = None;
                break;
            };
            span = Some(n.span());
            table = v.get_ref().as_table();
        }
        match span {
            Some(span) => cfg(format!(
                "invalid secrets.toml: {}",
                located(self.text, span, &msg)
            )),
            None => cfg(msg),
        }
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

/// `msg` placed at `span`: `TOML parse error at line L, column C` and the message, never
/// the source line (C1, SR-1). A file given by mistake may hold values (a `.env`), so no
/// configuration error quotes the text it came from.
fn located(text: &str, span: std::ops::Range<usize>, msg: &str) -> String {
    format!("{}\n", toml_error(text, Some(span), msg))
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
    let root = table_keys(doc, &[]);
    if root.contains(&"profile") {
        return Err(doc.at_path(
            &["profile"],
            "[profile] was removed in 0.7.0 (FR-60): there is one form; delete [profile] and \
             declare each key under its product as [products.<name>.keys.<KEY>]"
                .into(),
        ));
    }
    if root.contains(&"keys") {
        let first = table_keys(doc, &["keys"])
            .first()
            .copied()
            .unwrap_or("<KEY>");
        return Err(doc.at_path(
            &["keys"],
            format!(
                "top-level [keys] was removed in 0.7.0 (FR-60): declare each key under its \
                 product, as [products.<name>.keys.{first}]"
            ),
        ));
    }
    for env in table_keys(doc, &["environments"]) {
        for field in table_keys(doc, &["environments", env]) {
            let msg = match field {
                "vault_id" | "item_id" => format!(
                    "environment {env}: {field} was removed in 0.7.0 (FR-57, FR-60): record one \
                     boundary per product instead, boundaries.<product> = {{ vault_id = \"...\", \
                     item_id = \"...\" }} (opv bootstrap records them)"
                ),
                "deploy_credentials" | "state_vault_id" => format!(
                    "environment {env}: {field} was removed at the environment level in 0.7.0 \
                     (FR-56, FR-60): set it on the target, under \
                     [environments.{env}.targets.<name>] as {field} = \"...\""
                ),
                section if registry::find(section).is_some() => {
                    let fields: Vec<String> = table_keys(doc, &["environments", env, section])
                        .iter()
                        .map(|f| format!("{section}.{f} = ..."))
                        .collect();
                    format!(
                        "environment {env}: an environment-level {section} section was removed \
                         in 0.7.0 (FR-56, FR-60): declare a named target and put the section \
                         under it, [environments.{env}.targets.<name>] with {}",
                        if fields.is_empty() {
                            format!("{section}.<field> = ...")
                        } else {
                            fields.join(", ")
                        }
                    )
                }
                _ => continue,
            };
            return Err(doc.at(env, field, msg));
        }
        for target in table_keys(doc, &["environments", env, "targets"]) {
            let at = ["environments", env, "targets", target];
            for section in table_keys(doc, &at) {
                if registry::find(section).is_none() {
                    continue;
                }
                let path = [&at[..], &[section, "products"]].concat();
                if doc.value(&path).is_some() {
                    return Err(doc.at_path(
                        &path,
                        format!(
                            "environment {env}: {section}.products was removed in 0.7.0 (FR-48, \
                             FR-60): list the products on the target, \
                             targets.{target}.products = [...]"
                        ),
                    ));
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
    /// `op://<vault>/<item>` holding the target's deploy identity (FR-40).
    #[serde(default)]
    deploy_credentials: Option<String>,
    /// The vault holding the target's delivery evidence (FR-58); required (D12).
    #[serde(default)]
    state_vault_id: Option<String>,
    /// Exactly one provider section (FR-28).
    #[serde(flatten)]
    sections: BTreeMap<String, toml::Value>,
}

fn cfg(msg: String) -> Error {
    Error::Config(msg.into())
}

/// The named stores of a file (FR-39), by name.
type Stores = BTreeMap<String, Box<dyn StoreConfig>>;

/// Every `[stores.<name>]` table, parsed by the provider that declares its kind (FR-39). The
/// kind is the key that names it (`azure_key_vault = "..."`). A store name is a DNS label,
/// so it can name in-cluster objects as it is.
fn stores(raw: &BTreeMap<String, toml::Value>, doc: &Doc<'_>) -> Result<Stores, Error> {
    let mut out = Stores::new();
    for (name, value) in raw {
        let at = |msg: String| doc.at_path(&["stores", name], msg);
        if !is_store_name(name) {
            return Err(at(format!(
                "store {name:?}: name must match ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ (at most 63 \
                 characters)"
            )));
        }
        let known = registry::store_kinds().join(", ");
        let Some(table) = value.as_table() else {
            return Err(at(format!(
                "store {name}: must be a table, e.g. [stores.{name}] with one of: {known}"
            )));
        };
        let kinds: Vec<&str> = table
            .keys()
            .map(String::as_str)
            .filter(|k| registry::store_kind(k).is_some())
            .collect();
        let kind = match kinds.as_slice() {
            [kind] => *kind,
            [] => {
                return Err(at(format!(
                    "store {name}: names no store kind; add one of: {known}"
                )));
            }
            [a, b, ..] => {
                return Err(at(format!(
                    "store {name}: declares both {a} and {b}; a store has one kind"
                )));
            }
        };
        let provider = registry::store_kind(kind).expect("kind found above");
        let value = doc
            .value(&["stores", name])
            .ok_or_else(|| cfg(format!("store {name}: table not found")))?;
        let store = provider.parse_store(kind, &Section::new(name, value, doc.text))?;
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
    let known = registry::sections().join(", ");
    if let Some((unknown, v)) = sections.iter().find(|(s, _)| registry::find(s).is_none()) {
        return Err(doc.at_path(
            &[&base[..], &[unknown.as_str()]].concat(),
            if v.is_table() {
                format!(
                    "environment {env}: target {name}: unknown target section {unknown:?}; \
                     known: {known}"
                )
            } else {
                format!(
                    "environment {env}: target {name}: unknown field {unknown:?}; expected \
                     products, deploy_credentials, state_vault_id or one provider section \
                     ({known})"
                )
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
            return Err(doc.at_path(
                &base,
                format!(
                    "environment {env}: target {name} names no provider; add one provider \
                     section ({known}) under [environments.{env}.targets.{name}]"
                ),
            ));
        }
        [a, b, ..] => {
            return Err(doc.at_path(
                &[&base[..], &[b.section()]].concat(),
                format!(
                    "environment {env}: target {name} declares both {} and {}; a target has \
                     one provider (declare another target for the other)",
                    a.section(),
                    b.section()
                ),
            ));
        }
    };
    let section = p.section();
    let value = doc
        .value(&[&base[..], &[section]].concat())
        .ok_or_else(|| {
            cfg(format!(
                "environment {env}: target {name}: {section} not found"
            ))
        })?;
    // `secrets_in` is generic (FR-39): taken out here, the rest goes to the provider.
    let mut rest = value.clone();
    let secrets_in = match rest.get_mut() {
        DeValue::Table(t) => t.remove("secrets_in"),
        _ => None,
    };
    let target = p.parse(&Section::new(env, &rest, doc.text))?;
    let Some(secrets_in) = secrets_in else {
        return Ok(target);
    };
    let at = |msg: String| doc.at_path(&[&base[..], &[section, "secrets_in"]].concat(), msg);
    let Some(store_name) = secrets_in.get_ref().as_str() else {
        return Err(at(format!(
            "environment {env}: {section}.secrets_in must be the name of a [stores.<name>] table"
        )));
    };
    let Some(store) = stores.get(store_name) else {
        let defined: Vec<&str> = stores.keys().map(String::as_str).collect();
        return Err(at(format!(
            "environment {env}: {section}.secrets_in = {store_name:?} names no store; {}",
            if defined.is_empty() {
                format!("declare it as [stores.{store_name}]")
            } else {
                format!("defined: {}", defined.join(", "))
            }
        )));
    };
    if !registry::binds(section, store.kind()) {
        return Err(at(format!(
            "environment {env}: {section} cannot keep its secrets in store {store_name:?} \
             ({}); supported secrets_in pairs: {}",
            store.kind(),
            registry::supported_pairs().join("; ")
        )));
    }
    p.bind(target, store.as_ref())
}

/// `e` (a configuration error from a check that does not know the file) located at `path`.
fn located_at(doc: &Doc<'_>, path: &[&str], e: Error) -> Error {
    match e {
        Error::Config(m) => doc.at_path(path, m.text().to_string()),
        other => other,
    }
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
        return Err(doc.at(
            name,
            "account",
            format!(
                "environment {name}: account must be a 1Password sign-in address (for example \
                 my.1password.com), an email or an account ID"
            ),
        ));
    }
    let mut boundaries = BTreeMap::new();
    for (b, raw) in e.boundaries {
        let path = ["environments", name, "boundaries", b.as_str()];
        if !is_product_name(&b) {
            return Err(doc.at_path(
                &path,
                format!(
                    "environment {name}: boundary name {b:?} must match ^[a-z][a-z0-9_-]*$ (a \
                     product or a product's boundary group)"
                ),
            ));
        }
        check_ids(
            name,
            &format!("boundaries.{b}"),
            &raw.vault_id,
            &raw.item_id,
        )
        .map_err(|err| located_at(doc, &path, err))?;
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
        boundaries,
        targets,
        modes: e.modes,
        confirm_env: e.confirm_env,
        account: e.account,
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
        return Err(doc.at_path(
            &base,
            format!("environment {env}: target name {name:?} must match ^[a-z][a-z0-9-]*$"),
        ));
    }
    let config = target_of(env, name, &raw.sections, stores, doc)?;
    if raw.products.as_ref().is_some_and(Vec::is_empty) {
        return Err(doc.at_path(
            &[&base[..], &["products"]].concat(),
            format!(
                "environment {env}: target {name}: products must not be empty; remove it to \
                 deliver every product with a key in {env}"
            ),
        ));
    }
    let deploy_credentials = match &raw.deploy_credentials {
        None => None,
        Some(r) => Some(deploy_credentials(env, name, r, config.as_ref(), doc)?),
    };
    let Some(state_vault_id) = raw.state_vault_id else {
        return Err(doc.at_path(
            &base,
            format!(
                "state_vault_missing: target {name} in {env} needs state_vault_id; next: opv \
                 bootstrap --state {env} --target {name}"
            ),
        ));
    };
    check_ident(
        env,
        &format!("targets.{name}.state_vault_id"),
        &state_vault_id,
        is_id,
        "^[A-Za-z0-9][A-Za-z0-9._-]*$",
    )
    .map_err(|e| located_at(doc, &[&base[..], &["state_vault_id"]].concat(), e))?;
    Ok(Target {
        name: name.to_string(),
        config,
        products: raw.products,
        deploy_credentials,
        state_vault_id,
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
    let at = |msg: String| {
        doc.at_path(
            &["environments", env, "targets", name, "deploy_credentials"],
            msg,
        )
    };
    let reference = ItemRef::parse(raw)
        .map_err(|why| at(format!("environment {env}: deploy_credentials {why}")))?;
    crate::provider::deploy_provider(target)
        .deploy_credential_fields()
        .map_err(|why| at(format!("environment {env}: {why}")))?;
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
        return Err(cfg("no environments defined".into()));
    }

    let stores = stores(&raw.stores, doc)?;
    let mut environments = BTreeMap::new();
    for (name, e) in raw.environments {
        let env = environment(&name, e, &stores, doc)?;
        environments.insert(name, env);
    }
    check_shared_targets(&environments)?;

    for (product, p) in &raw.products {
        if !is_product_name(product) {
            return Err(cfg(format!(
                "product {product:?}: name must match ^[a-z][a-z0-9_-]*$"
            )));
        }
        if let Some(b) = &p.boundary
            && !is_product_name(b)
        {
            return Err(doc.at_path(
                &["products", product, "boundary"],
                format!("product {product:?}: boundary {b:?} must match ^[a-z][a-z0-9_-]*$"),
            ));
        }
        if p.source_only && p.keys.is_empty() {
            return Err(doc.at_path(
                &["products", product],
                format!(
                    "product {product:?}: source_only = true needs at least one key; declare a \
                     key under [products.{product}.keys], or remove source_only"
                ),
            ));
        }
        for (key, spec) in &p.keys {
            validate_key(&format!("{product}/{key}"), key, spec, &environments)?;
        }
    }

    let mut products = raw.products;
    check_shared(&mut products, doc)?;
    let fleet = Fleet {
        environments,
        products,
        origin: Default::default(),
    };
    check_scopes(&fleet, doc)?;
    check_boundaries(&fleet, doc)?;
    check_names(&fleet, doc)?;
    check_personal(&fleet)?;
    check_evidence_width(&fleet)?;
    Ok(fleet)
}

/// FR-58 (D12): a state vault shared by several targets is never readable more widely than
/// the values its evidence describes (`state_vault_wider_than_values`).
/// Each target reads the boundaries of the products it delivers and of their `from`
/// sources (FR-59), named `<boundary> (<vault id>)` so boundaries of different environments
/// never compare equal.
fn check_evidence_width(fleet: &Fleet) -> Result<(), Error> {
    use crate::domain::placement::{STATE_VAULT_WIDER_THAN_VALUES, TargetReads, wider_than_values};
    let mut reads: Vec<(&str, &str, &str, BTreeSet<String>)> = Vec::new();
    for (env_name, env) in &fleet.environments {
        for (name, target) in &env.targets {
            let mut boundaries = BTreeSet::new();
            for (product, p) in &fleet.products {
                if !fleet.delivers(env_name, name, product) {
                    continue;
                }
                let desired = p
                    .keys
                    .values()
                    .filter(|k| k.environments.iter().any(|e| e == env_name));
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
        Some(w) => Err(cfg(format!(
            "{STATE_VAULT_WIDER_THAN_VALUES}: {}",
            w.sentence()
        ))),
        None => Ok(()),
    }
}

/// FR-57: every product with a team key desired in an environment, and every source such a
/// key reads with `from`, has its boundary recorded there (personal keys live in each
/// person's own item, FR-55, so they need none) (`boundary_missing`, next step
/// `opv bootstrap`); a recorded boundary no such product uses is refused, so the
/// configuration never names a vault nothing reads.
fn check_boundaries(fleet: &Fleet, doc: &Doc<'_>) -> Result<(), Error> {
    for (env_name, env) in &fleet.environments {
        let mut used = BTreeSet::new();
        for (product, p) in &fleet.products {
            let desired: Vec<&KeySpec> = p
                .keys
                .values()
                .filter(|k| !k.personal && k.environments.iter().any(|e| e == env_name))
                .collect();
            if desired.is_empty() {
                continue;
            }
            let sources = desired.iter().filter_map(|k| k.source()).map(|(sp, _)| sp);
            for needer in std::iter::once(product.as_str()).chain(sources) {
                let b = fleet.boundary_of(needer);
                if !env.boundaries.contains_key(b) {
                    let msg = boundary_missing(env_name, needer, b);
                    return Err(
                        if doc
                            .value(&["environments", env_name, "boundaries"])
                            .is_some()
                        {
                            doc.at(env_name, "boundaries", msg)
                        } else {
                            doc.at_path(&["environments", env_name], msg)
                        },
                    );
                }
                used.insert(b);
            }
        }
        if let Some(b) = env.boundaries.keys().find(|b| !used.contains(b.as_str())) {
            return Err(doc.at_path(
                &["environments", env_name, "boundaries", b],
                format!(
                    "environment {env_name}: boundaries.{b} is recorded but no product with a \
                     key in {env_name} lives in it; remove it, or declare that product's keys \
                     for {env_name}"
                ),
            ));
        }
    }
    Ok(())
}

/// FR-55: a personal key lives only in environments without a target (it is never
/// deployed), and personal and team values never meet through `from`: a personal key's
/// source is personal, a team key's source is not.
fn check_personal(fleet: &Fleet) -> Result<(), Error> {
    for (product, p) in &fleet.products {
        for (key, spec) in &p.keys {
            let owner = key_label(product, key);
            if spec.personal
                && let Some(env) = spec.environments.iter().find(|e| {
                    fleet
                        .environments
                        .get(*e)
                        .is_some_and(|x| !x.targets.is_empty())
                })
            {
                return Err(cfg(format!(
                    "{owner}: personal = true is for local environments only, and {env} has a \
                     deployment target (a person's own value is never deployed); declare a \
                     team key for {env}"
                )));
            }
            if let Some((sp, sk)) = spec.source() {
                let src_personal = fleet
                    .products
                    .get(sp)
                    .and_then(|x| x.keys.get(sk))
                    .is_some_and(|x| x.personal);
                if src_personal != spec.personal {
                    let (what, why) = if spec.personal {
                        ("a personal key", "a team value")
                    } else {
                        ("a team key", "a personal value")
                    };
                    return Err(cfg(format!(
                        "{owner}: {what} cannot read {why} with from = \"{sp}/{sk}\"; personal and \
                         team values never mix"
                    )));
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
            let at = |msg: String| {
                doc.at_path(
                    &["environments", env_name, "targets", name, "products"],
                    msg,
                )
            };
            for p in listed {
                match fleet.products.get(p) {
                    None => {
                        let declared: Vec<&str> =
                            fleet.products.keys().map(String::as_str).collect();
                        return Err(at(format!(
                            "environment {env_name}: target {name}: products names {p:?}, which \
                             is not a declared product (declared: {})",
                            declared.join(", ")
                        )));
                    }
                    Some(prod) if prod.source_only => {
                        return Err(at(format!(
                            "environment {env_name}: target {name}: products names {p:?}, which \
                             is source-only and never delivered; list the products whose keys \
                             point at it with from instead"
                        )));
                    }
                    Some(_) => {}
                }
            }
        }
    }
    Ok(())
}

/// One identifier: non-empty, unpadded, and accepted by `ok` (safe in argv). Shared with
/// the providers' section parsers.
pub(crate) fn check_ident(
    name: &str,
    field: &str,
    value: &str,
    ok: fn(&str) -> bool,
    shape: &str,
) -> Result<(), Error> {
    if value.trim().is_empty() {
        return Err(cfg(format!("environment {name}: {field} is empty")));
    }
    if value.trim() != value {
        return Err(cfg(format!(
            "environment {name}: {field} has leading or trailing whitespace"
        )));
    }
    if !ok(value) {
        return Err(cfg(format!(
            "environment {name}: {field} {value:?} must match {shape}"
        )));
    }
    Ok(())
}

/// A boundary's IDs (`<owner>.vault_id`, `<owner>.item_id`) are non-empty, unpadded and
/// safe in argv.
fn check_ids(name: &str, owner: &str, vault_id: &str, item_id: &str) -> Result<(), Error> {
    for (field, value) in [("vault_id", vault_id), ("item_id", item_id)] {
        check_ident(
            name,
            &format!("{owner}.{field}"),
            value,
            is_id,
            "^[A-Za-z0-9][A-Za-z0-9._-]*$",
        )?;
    }
    Ok(())
}

/// Per-key checks (FR-14 to FR-16, FR-24). `owner` names the key in errors: `product/KEY`.
fn validate_key(
    owner: &str,
    key: &str,
    spec: &KeySpec,
    environments: &BTreeMap<String, Environment>,
) -> Result<(), Error> {
    if !is_env_name(key) {
        return Err(cfg(format!(
            "{owner}: key name must match ^[A-Z][A-Z0-9_]*$"
        )));
    }
    // `run` removes every declared name from the inherited environment (#53), so a key named
    // after `op`'s own context would strip it: PATH finds `op`, HOME and XDG_CONFIG_HOME
    // locate its configuration, OP_* holds its sign-in.
    if matches!(key, "PATH" | "HOME" | "XDG_CONFIG_HOME") || key.starts_with("OP_") {
        return Err(cfg(format!(
            "{owner}: key name is reserved (PATH, HOME, XDG_CONFIG_HOME and OP_* are the \
             1Password CLI's own environment)"
        )));
    }
    for env in &spec.environments {
        if !environments.contains_key(env) {
            return Err(cfg(format!("{owner}: undefined environment {env:?}")));
        }
    }
    for env in &spec.rules.refuse_in {
        if !environments.contains_key(env) {
            return Err(cfg(format!(
                "{owner}: rule refuse_in names undefined environment {env:?}"
            )));
        }
        if spec.environments.contains(env) {
            return Err(cfg(format!(
                "{owner}: environment {env:?} is in both environments and refuse_in"
            )));
        }
    }
    if spec.rules.prefix.as_deref() == Some("") {
        return Err(cfg(format!(
            "{owner}: rule prefix must be a non-empty string"
        )));
    }
    if let Some(np) = &spec.rules.not_prefix
        && !np.is_valid()
    {
        return Err(cfg(format!(
            "{owner}: rule not_prefix must be a non-empty string or non-empty list of non-empty strings"
        )));
    }
    if let Some(p) = &spec.rules.prefix_by_mode {
        for (mode, v) in &p.values {
            if !v.is_valid() {
                return Err(cfg(format!(
                    "{owner}: rule prefix_by_mode value for {mode:?} must be a non-empty string or non-empty list of non-empty strings"
                )));
            }
        }
    }
    if let Some(re) = &spec.rules.regex {
        regex::Regex::new(re)
            .map_err(|e| cfg(format!("{owner}: rule regex does not compile: {e}")))?;
    }
    if let Some(p) = &spec.rules.ensure_prefix
        && p.is_empty()
    {
        return Err(cfg(format!(
            "{owner}: rule ensure_prefix must be a non-empty string"
        )));
    }
    if spec.rules.transform.as_deref() == Some("signoz_ingestion_header") {
        let regex =
            toml::Value::String(format!("{}(?:{SIGNOZ_BODY})", regex::escape(SIGNOZ_PREFIX)));
        return Err(cfg(format!(
            "{owner}: transform = \"signoz_ingestion_header\" was removed in 0.4.0; \
             use ensure_prefix = \"{SIGNOZ_PREFIX}\" with regex = {regex}"
        )));
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
fn check_shared(products: &mut BTreeMap<String, Product>, doc: &Doc<'_>) -> Result<(), Error> {
    let at = |product: &str, key: &str, field: &str, msg: String| {
        doc.at_path(&["products", product, "keys", key, field], msg)
    };
    let shape = "\"<product>/<KEY>\"";
    let mut follow: Vec<(String, String, bool)> = Vec::new();
    for (product, p) in products.iter() {
        for (key, spec) in &p.keys {
            let Some(from) = spec.from.as_deref() else {
                continue;
            };
            let owner = key_label(product, key);
            let err = |msg: String| {
                at(
                    product,
                    key,
                    "from",
                    format!("{owner}: from = {from:?}: {msg}"),
                )
            };
            let slashes = from.matches('/').count();
            if from.contains("://") || slashes > 1 {
                return Err(err(format!(
                    "a shared key reads another key of the same environment; write from = \
                     {shape} (cross-environment references are not supported)"
                )));
            }
            let Some((sp, sk)) = spec.source() else {
                return Err(err(format!(
                    "a bare key was removed in 0.7.0 (FR-60): name the source's product too, \
                     from = \"<product>/{from}\""
                )));
            };
            let well_formed = is_env_name(sk) && is_product_name(sp);
            if !well_formed {
                return Err(err(format!("must be {shape}")));
            }
            if (sp, sk) == (product.as_str(), key.as_str()) {
                return Err(err("a key cannot share its own value (cycle)".into()));
            }
            let Some(src) = products.get(sp).and_then(|q| q.keys.get(sk)) else {
                return Err(err("names no declared key; declare the source first".into()));
            };
            let source = key_label(sp, sk);
            if let Some((tp, tk)) = src.source() {
                return Err(err(if (tp, tk) == (product.as_str(), key.as_str()) {
                    format!(
                        "{source} is shared from {owner} (cycle); keep the field on one of them"
                    )
                } else {
                    format!(
                        "{source} is itself shared from {} (no chains); write from = {:?}",
                        key_label(tp, tk),
                        src.from.as_deref().unwrap_or_default()
                    )
                }));
            }
            if src.kind != spec.kind {
                return Err(err(format!(
                    "{source} is a {} key, {owner} a {} key; a shared key has its source's kind",
                    kind_name(src.kind),
                    kind_name(spec.kind)
                )));
            }
            if let Some(env) = spec
                .environments
                .iter()
                .find(|e| !src.environments.contains(e))
            {
                return Err(err(format!(
                    "{source} is not declared for environment {env:?}, which {owner} uses; add \
                     {env:?} to its environments (the value is read from the same environment)"
                )));
            }
            if let Some(env) = spec
                .rules
                .refuse_in
                .iter()
                .find(|e| src.environments.contains(e))
            {
                return Err(err(format!(
                    "refuse_in {env:?} would refuse the value {source} provides there"
                )));
            }
            if doc
                .value(&["products", product, "keys", key, "immutable"])
                .is_some()
            {
                return Err(at(
                    product,
                    key,
                    "immutable",
                    format!(
                        "{owner}: immutable follows the source of a shared key ({source}); remove it here"
                    ),
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
/// means and words the error (a Fly app may serve two environments with different
/// templates).
fn check_shared_targets(environments: &BTreeMap<String, Environment>) -> Result<(), Error> {
    let targets: Vec<(&str, &str, &dyn TargetConfig)> = environments
        .iter()
        .flat_map(|(e, env)| {
            env.targets
                .iter()
                .map(move |(n, t)| (e.as_str(), n.as_str(), t.config.as_ref()))
        })
        .collect();
    for (i, (env, name, t)) in targets.iter().enumerate() {
        for (prev_env, prev, p) in &targets[..i] {
            if prev_env == env {
                let same_provider = p.provider().section() == t.provider().section();
                if same_provider && (p.target_locator() == t.target_locator() || t.same_target(*p))
                {
                    return Err(cfg(format!(
                        "environment {env}: targets {prev} and {name} both deliver to {} {}; \
                         within an environment a {} target belongs to one target\n  next: \
                         merge them into one target, with products listing what it delivers",
                        t.provider().label(),
                        t.target_locator(),
                        t.provider().label(),
                    )));
                }
            } else if t.same_target(*p) {
                return Err(cfg(t.shared_target_error(
                    &format!("{prev_env} (target {prev})"),
                    &format!("{env} (target {name})"),
                )));
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

/// [`check_names`] for one target.
fn check_target_names<'f>(
    fleet: &'f Fleet,
    env_name: &str,
    target_name: &str,
    target: &'f Target,
    shared: &mut Vec<(&'f dyn StoreConfig, String, String, String)>,
    doc: &Doc<'_>,
) -> Result<(), Error> {
    let t = target.config.as_ref();
    let here = format!("{env_name} (target {target_name})");
    // Messages read `environment <env>: target <name>: …`.
    let scope = format!("{env_name}: target {target_name}");
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
            let name = t.env_name(product, key);
            let owner = key_label(product, key);
            if !is_env_name(&name) {
                return Err(cfg(format!(
                    "environment {scope}: {owner} renders {} {name:?}, which must match \
                     ^[A-Z][A-Z0-9_]*$",
                    rules.env_label
                )));
            }
            let at = Place {
                env_name: &scope,
                product,
                key,
                owner: &owner,
            };
            let id = match &rules.store {
                None => name.clone(),
                Some(s) => store_id(&at, &t.store_name(&name), s, doc)?,
            };
            check_unique(&mut seen, &scope, &rules, id, &owner)?;
            if let Some(store) = store {
                let s = store.name_rules();
                let id = store_id(&at, &store.store_name(&name), &s, doc)?;
                let named = NameRules {
                    env_label: rules.env_label,
                    store: Some(s),
                };
                check_unique(&mut seen_in_store, &scope, &named, id.clone(), &owner)?;
                if let Some((_, _, other, prev)) = shared
                    .iter()
                    .find(|(st, i, e, _)| st.same_store(store) && *i == id && *e != here)
                {
                    return Err(cfg(format!(
                        "environments {other} and {here} both keep {} {id} in {} ({prev} and \
                         {owner}); each would overwrite and prune the other's value\n  next: \
                         give one of them its own store, or an env_name template that renders \
                         different names",
                        s.label,
                        store.describe()
                    )));
                }
                shared.push((store, id, here.clone(), owner.clone()));
            }
        }
    }
    Ok(())
}

/// Where a rendered name comes from, for messages.
struct Place<'a> {
    env_name: &'a str,
    product: &'a str,
    key: &'a str,
    owner: &'a str,
}

/// A rendered store name checked against `s` (FR-30): its identity for collisions,
/// case-folded when the store ignores case.
fn store_id(
    at: &Place<'_>,
    store: &str,
    s: &StoreNameRules,
    doc: &Doc<'_>,
) -> Result<String, Error> {
    let (env_name, owner) = (at.env_name, at.owner);
    if store.is_empty() || store.len() > s.max_len || !store.chars().all(s.allowed) {
        return Err(cfg(format!(
            "environment {env_name}: {owner} renders {} of {} characters, which must match {}",
            s.label,
            store.len(),
            s.pattern
        )));
    }
    // The first and last characters, e.g. a key ending in `_` renders a Kubernetes name
    // ending in `-`: refused here, never at sync.
    let edges = [store.chars().next(), store.chars().last()];
    if !edges.into_iter().flatten().all(s.edge) {
        return Err(doc.key_at(
            at.product,
            at.key,
            format!(
                "environment {env_name}: {owner} renders {} {store:?}, which must start and end \
                 with a letter or digit ({})",
                s.label, s.pattern
            ),
        ));
    }
    Ok(if s.case_insensitive {
        store.to_ascii_lowercase()
    } else {
        store.to_string()
    })
}

/// Two keys of one target must not render the same name (FR-8, FR-30): the error names both
/// keys and the two ways out (FR-20).
fn check_unique(
    seen: &mut BTreeMap<String, String>,
    env_name: &str,
    rules: &NameRules,
    id: String,
    owner: &str,
) -> Result<(), Error> {
    let Some(prev) = seen.insert(id.clone(), owner.to_string()) else {
        return Ok(());
    };
    let what = match &rules.store {
        None => format!("both render {} {id}", rules.env_label),
        Some(s) => format!("both map to {} {id}", s.label),
    };
    Err(cfg(format!(
        "environment {env_name}: {prev} and {owner} {what}\n  next: render different names \
         with {{PRODUCT}} in the template, or deliver one product from a target of its own \
         (products = [...])"
    )))
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

    /// The fixture with LF line endings, whatever the checkout did (Windows may give CRLF).
    fn ok() -> String {
        RAW.replace("\r\n", "\n")
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

    fn config_err(text: &str) -> String {
        match parse(text) {
            Err(Error::Config(m)) => m.to_string(),
            other => panic!("expected Config error, got {other:?}"),
        }
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
        assert!(load(&p).is_ok());
    }

    #[test]
    fn load_names_a_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.toml");
        assert!(matches!(load(&missing), Err(Error::Config(m)) if m.contains("nope.toml")));
    }

    #[test]
    fn rejects_a_configuration_without_environments() {
        assert_eq!(
            config_err("[products.web.keys.K]\nkind = \"secret\"\nenvironments = []\n"),
            "invalid secrets.toml: TOML parse error at line 1, column 1\nmissing field `environments`"
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
            vec!["prod"]
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
        let m = config_err(&mutate(
            r#"environments = ["prod"]"#,
            r#"environments = ["qa"]"#,
        ));
        assert!(m.contains("undefined environment \"qa\""), "{m}");
    }

    #[test]
    fn rejects_a_key_name_that_is_not_an_env_name() {
        let m = config_err(&mutate(
            "[products.allumata.keys.OPENAI_API_KEY]",
            "[products.allumata.keys.openai-key]",
        ));
        assert!(m.contains("key name must match"), "{m}");
    }

    #[test]
    fn rejects_an_unknown_key_field() {
        let m = config_err(&mutate("immutable = true", "immutible = true"));
        assert!(m.contains("unknown field `immutible`"), "{m}");
    }

    #[test]
    fn rejects_an_unknown_rule() {
        let m = config_err(&mutate("base64_bytes = 32", "base64_len = 32"));
        assert!(m.contains("unknown field `base64_len`"), "{m}");
    }

    #[test]
    fn rejects_an_unknown_kind() {
        let m = config_err(&mutate(r#"kind = "config""#, r#"kind = "text""#));
        assert!(m.contains("unknown variant `text`"), "{m}");
    }

    #[test]
    fn rejects_a_bad_product_name() {
        let m = config_err(&mutate("products.allumata.", "products.Allumata."));
        assert!(m.contains("product \"Allumata\": name must match"), "{m}");
    }

    #[test]
    fn rejects_a_regex_that_does_not_compile_naming_the_key() {
        let m = config_err(&mutate(
            r#"rules = { base64_bytes = 32 }"#,
            r#"rules = { regex = "([a-z" }"#,
        ));
        assert!(
            m.contains("allumata/INTEGRATION_ENC_KEY: rule regex does not compile"),
            "{m}"
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
        let m = config_err(&with_prod_key(
            "p",
            "K1",
            "rules = { ensure_prefix = \"p-\", pattern = \"[a-z]+\" }\n",
        ));
        assert!(
            m.ends_with(
                "\np/K1: the pattern rule was removed; use regex = 'p\\-(?:[a-z]+)' instead\n"
            ),
            "{m}"
        );
    }

    #[test]
    fn the_pattern_rule_error_points_at_the_pattern() {
        let m = config_err(&with_prod_key(
            "p",
            "K1",
            "rules = { ensure_prefix = \"p-\", pattern = \"[a-z]+\" }\n",
        ));
        assert!(m.contains("TOML parse error at line 48, column 33"), "{m}");
    }

    #[test]
    fn path_is_a_reserved_key_name() {
        let m = config_err(&with_prod_key("p", "PATH", ""));
        assert!(m.contains("p/PATH: key name is reserved"), "{m}");
    }

    #[test]
    fn op_variables_are_reserved_key_names() {
        let m = config_err(&with_prod_key("p", "OP_SERVICE_ACCOUNT_TOKEN", ""));
        assert!(m.contains("key name is reserved"), "{m}");
    }

    #[test]
    fn the_signoz_transform_is_refused_with_its_replacement() {
        let m = config_err(&with_prod_key(
            "p",
            "K1",
            "rules = { transform = \"signoz_ingestion_header\" }\n",
        ));
        assert_eq!(
            m,
            "p/K1: transform = \"signoz_ingestion_header\" was removed in 0.4.0; use \
             ensure_prefix = \"signoz-ingestion-key=\" with regex = \
             'signoz\\-ingestion\\-key=(?:[A-Za-z0-9._~+/-]+={0,2})'"
        );
    }

    #[test]
    fn rejects_an_empty_not_prefix_list() {
        let m = config_err(&mutate(
            r#"rules = { base64_bytes = 32 }"#,
            r#"rules = { not_prefix = [] }"#,
        ));
        assert!(
            m.contains("allumata/INTEGRATION_ENC_KEY: rule not_prefix"),
            "{m}"
        );
    }

    #[test]
    fn rejects_an_empty_prefix_by_mode_value() {
        let m = config_err(&mutate(
            r#"values = { test = "sk_test_", live = "sk_live_" }"#,
            r#"values = { test = "", live = "sk_live_" }"#,
        ));
        assert!(
            m.contains("allumata/STRIPE_SECRET_KEY: rule prefix_by_mode"),
            "{m}"
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
        let m = config_err(&mutate(r#"prefix = "sk-""#, r#"prefix = """#));
        assert!(
            m.contains("allumata/OPENAI_API_KEY: rule prefix must be"),
            "{m}"
        );
    }

    #[test]
    fn rejects_refuse_in_naming_an_undefined_environment() {
        let m = config_err(&mutate(
            r#"not_prefix = "sk-or-" }"#,
            r#"not_prefix = "sk-or-", refuse_in = ["qa"] }"#,
        ));
        assert!(
            m.contains("refuse_in names undefined environment \"qa\""),
            "{m}"
        );
    }

    #[test]
    fn rejects_refuse_in_overlapping_environments() {
        let m = config_err(&mutate(
            r#"not_prefix = "sk-or-" }"#,
            r#"not_prefix = "sk-or-", refuse_in = ["prod"] }"#,
        ));
        assert!(m.contains("is in both environments and refuse_in"), "{m}");
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
            m.contains("fly.secret_name \"FLEET_STATIC\" must contain {KEY}"),
            "{m}"
        );
    }

    #[test]
    fn fly_secret_name_is_required() {
        let m = config_err(&web("fly.secret_name = \"{KEY}\"\n", ""));
        assert!(m.contains("missing field `secret_name`"), "{m}");
    }

    #[test]
    fn a_key_template_on_a_two_product_target_collides() {
        let text = bound(
            &key(WEB, "api", "DATABASE_URL", r#"["prod"]"#, ""),
            "prod",
            "api",
        );
        let m = config_err(&text);
        assert!(
            m.contains("api/DATABASE_URL and web/DATABASE_URL both render Fly name DATABASE_URL"),
            "{m}"
        );
    }

    #[test]
    fn a_name_collision_names_both_ways_out() {
        let text = bound(
            &key(WEB, "api", "DATABASE_URL", r#"["prod"]"#, ""),
            "prod",
            "api",
        );
        assert!(
            parse(&text)
                .unwrap_err()
                .next_step()
                .is_some_and(|n| n.starts_with(
                    "render different names with {PRODUCT} in the template, or deliver one \
                     product from a target of its own"
                ))
        );
    }

    #[test]
    fn rejects_a_fly_app_that_reads_as_a_flag() {
        let m = config_err(&web("\"web-prod\"", "\"-a\""));
        assert!(m.contains("fly.app \"-a\" must match"), "{m}");
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
        let m = config_err(&mutate(
            "FLEET__{PRODUCT}__{KEY}",
            "fleet__{PRODUCT}__{KEY}",
        ));
        assert!(m.contains("renders Fly name \"fleet__ALLUMATA__"), "{m}");
    }

    /// FR-2, FR-37: an unknown field in a provider section reports line, column and the
    /// field; never the line itself (C1, SR-1).
    #[test]
    fn a_fly_section_unknown_field_points_at_the_field() {
        let bad = web(
            "fly.secret_name = \"{KEY}\"\n",
            "fly.secret_name = \"{KEY}\"\nfly.region = \"ams\"\n",
        );
        assert_eq!(
            config_err(&bad),
            "invalid secrets.toml: TOML parse error at line 7, column 5\nunknown field `region`, \
             expected `app` or `secret_name`"
        );
    }

    #[test]
    fn an_unknown_target_section_lists_the_known_providers() {
        let m = config_err(&web("fly.app", "flyy.app = \"x\"\nfly.app"));
        assert!(
            m.ends_with(
                "\nenvironment prod: target site: unknown target section \"flyy\"; known: \
                 azure, fly, github, kubernetes\n"
            ),
            "{m}"
        );
    }

    #[test]
    fn an_unknown_target_field_names_the_expected_fields() {
        let m = config_err(&web("fly.app", "vault = \"x\"\nfly.app"));
        assert!(
            m.ends_with(
                "\nenvironment prod: target site: unknown field \"vault\"; expected products, \
                 deploy_credentials, state_vault_id or one provider section (azure, fly, \
                 github, kubernetes)\n"
            ),
            "{m}"
        );
    }

    #[test]
    fn a_target_with_two_provider_sections_is_refused() {
        let m = config_err(&web("fly.app", "azure.key_vault = \"kv\"\nfly.app"));
        assert!(
            m.ends_with(
                "\nenvironment prod: target site declares both fly and azure; a target has one \
                 provider (declare another target for the other)\n"
            ),
            "{m}"
        );
    }

    #[test]
    fn a_target_without_a_provider_is_refused() {
        let m = config_err(&web(
            "fly.app = \"web-prod\"\nfly.secret_name = \"{KEY}\"\n",
            "",
        ));
        assert!(m.contains("target site names no provider"), "{m}");
    }

    #[test]
    fn rejects_a_target_name_that_is_not_lowercase() {
        let m = config_err(&web("targets.site]", "targets.Site]"));
        assert!(
            m.contains("target name \"Site\" must match ^[a-z][a-z0-9-]*$"),
            "{m}"
        );
    }

    #[test]
    fn rejects_a_target_name_with_an_underscore() {
        let m = config_err(&web("targets.site]", "targets.my_site]"));
        assert!(m.contains("target name \"my_site\" must match"), "{m}");
    }

    #[test]
    fn a_target_without_state_vault_id_is_state_vault_missing() {
        let m = config_err(&web("state_vault_id = \"sweb\"\n", ""));
        assert!(
            m.contains(
                "state_vault_missing: target site in prod needs state_vault_id; next: opv \
                 bootstrap --state prod --target site"
            ),
            "{m}"
        );
    }

    #[test]
    fn state_vault_missing_points_at_the_target() {
        let m = config_err(&web("state_vault_id = \"sweb\"\n", ""));
        assert!(m.contains("TOML parse error at line 4, column 28"), "{m}");
    }

    #[test]
    fn rejects_a_state_vault_id_that_reads_as_a_flag() {
        let m = config_err(&web("\"sweb\"", "\"-s\""));
        assert!(
            m.contains("targets.site.state_vault_id \"-s\" must match"),
            "{m}"
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
        let m = config_err(&web("state_vault_id", "products = []\nstate_vault_id"));
        assert!(m.contains("target site: products must not be empty"), "{m}");
    }

    #[test]
    fn rejects_target_products_naming_an_undeclared_product() {
        let m = config_err(&web(
            "state_vault_id",
            "products = [\"wbe\"]\nstate_vault_id",
        ));
        assert!(
            m.contains("products names \"wbe\", which is not a declared product (declared: web)"),
            "{m}"
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
        let m = config_err(&replaced(
            &text,
            "state_vault_id",
            "products = [\"shared\"]\nstate_vault_id",
        ));
        assert!(
            m.contains("products names \"shared\", which is source-only"),
            "{m}"
        );
    }

    #[test]
    fn two_targets_of_one_environment_on_one_app_are_refused() {
        let m = config_err(&web_plus(
            "[environments.prod.targets.other]\nfly.app = \"web-prod\"\nfly.secret_name = \
             \"X__{KEY}\"\nstate_vault_id = \"s2\"\n",
        ));
        assert!(
            m.contains("environment prod: targets other and site both deliver to Fly app web-prod"),
            "{m}"
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
        let m = config_err(&mutate(
            r#"fly.app = "mcproductlabs-portfolio-staging""#,
            r#"fly.app = "mcproductlabs-portfolio-production""#,
        ));
        assert!(
            m.contains(
                "environments prod (target portfolio) and staging (target portfolio) both use \
                 Fly app \"mcproductlabs-portfolio-production\""
            ),
            "{m}"
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
        let m = config_err(&text);
        assert!(
            m.contains("line 7, column 1") && m.contains("not a field"),
            "{m}"
        );
    }

    #[test]
    fn deploy_credentials_must_be_an_op_reference() {
        let text = web(
            "state_vault_id",
            "deploy_credentials = \"vault/item\"\nstate_vault_id",
        );
        let m = config_err(&text);
        assert!(
            m.contains("must be an op://<vault>/<item> reference"),
            "{m}"
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
        let m = config_err(&text);
        assert!(m.contains("kubeconfig"), "{m}");
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
        let m = config_err(&text);
        assert!(m.contains("unknown field `vault`"), "{m}");
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
        let m = config_err(&replaced(
            &shared_state_vault(),
            "fly.app = \"web-prod\"",
            "fly.app = \"web-prod\"\nproducts = [\"web\"]",
        ));
        assert!(
            m.starts_with(
                "state_vault_wider_than_values: state vault sweb is shared by targets prod/other, \
                 prod/site"
            ),
            "{m}"
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
            Err(Error::Config(m)) if m.contains("boundary_missing: product api in prod needs boundary api")
        ));
    }

    #[test]
    fn a_product_without_its_boundary_is_boundary_missing() {
        let m = config_err(&key(WEB, "api", "K", r#"["prod"]"#, ""));
        assert!(
            m.contains(
                "boundary_missing: product api in prod needs boundary api; next: opv bootstrap"
            ),
            "{m}"
        );
    }

    #[test]
    fn a_from_source_without_its_boundary_is_boundary_missing() {
        let text = format!(
            "{WEB}[products.shared]\nsource_only = true\n[products.shared.keys.TOKEN]\nkind = \
             \"secret\"\nenvironments = [\"prod\"]\n[products.web.keys.TOKEN]\nkind = \
             \"secret\"\nenvironments = [\"prod\"]\nfrom = \"shared/TOKEN\"\n"
        );
        let m = config_err(&text);
        assert!(
            m.contains("boundary_missing: product shared in prod needs boundary shared"),
            "{m}"
        );
    }

    #[test]
    fn boundary_missing_points_at_the_boundaries() {
        let m = config_err(&key(WEB, "api", "K", r#"["prod"]"#, ""));
        assert!(m.contains("TOML parse error at line 2, column 1"), "{m}");
    }

    #[test]
    fn a_recorded_boundary_nothing_uses_is_refused() {
        let m = config_err(&bound(WEB, "prod", "old"));
        assert!(
            m.contains("environment prod: boundaries.old is recorded but no product with a key in prod lives in it"),
            "{m}"
        );
    }

    #[test]
    fn rejects_a_boundary_vault_id_that_reads_as_a_flag() {
        let m = config_err(&web("\"vweb\"", "\"-v\""));
        assert!(
            m.contains("boundaries.web.vault_id \"-v\" must match"),
            "{m}"
        );
    }

    #[test]
    fn rejects_a_padded_boundary_item_id() {
        let m = config_err(&web("\"iweb\"", "\" iweb\""));
        assert!(
            m.contains("boundaries.web.item_id has leading or trailing whitespace"),
            "{m}"
        );
    }

    #[test]
    fn rejects_a_boundary_item_id_with_a_slash() {
        let m = config_err(&web("\"iweb\"", "\"i/web\""));
        assert!(
            m.contains("boundaries.web.item_id \"i/web\" must match"),
            "{m}"
        );
    }

    #[test]
    fn rejects_a_boundary_without_an_item_id() {
        let m = config_err(&web(", item_id = \"iweb\"", ""));
        assert!(m.contains("missing field `item_id`"), "{m}");
    }

    #[test]
    fn rejects_a_bad_boundary_name() {
        let m = config_err(&web("boundaries.web", "boundaries.Web"));
        assert!(m.contains("boundary name \"Web\" must match"), "{m}");
    }

    #[test]
    fn rejects_a_bad_product_boundary_group() {
        let m = config_err(&web_plus("[products.web]\nboundary = \"Core\"\n"));
        assert!(
            m.contains("product \"web\": boundary \"Core\" must match"),
            "{m}"
        );
    }

    // ---- removed forms (FR-60) -------------------------------------------------------

    #[test]
    fn a_profile_table_is_refused_showing_the_products_form() {
        let m = config_err(&format!("[profile]\nkind = \"fleet\"\n{WEB}"));
        assert!(
            m.contains("[profile] was removed in 0.7.0")
                && m.contains("[products.<name>.keys.<KEY>]"),
            "{m}"
        );
    }

    #[test]
    fn a_removed_form_points_at_its_line_and_column() {
        let m = config_err(&format!("{WEB}[profile]\nkind = \"simple\"\n"));
        assert!(m.contains("TOML parse error at line 12, column 2"), "{m}");
    }

    #[test]
    fn top_level_keys_are_refused_showing_the_products_form() {
        let m = config_err(&format!(
            "{WEB}[keys.JWT_KEY]\nkind = \"secret\"\nenvironments = [\"prod\"]\n"
        ));
        assert!(
            m.contains("top-level [keys] was removed in 0.7.0")
                && m.contains("[products.<name>.keys.JWT_KEY]"),
            "{m}"
        );
    }

    #[test]
    fn an_environment_vault_id_is_refused_showing_the_boundaries_form() {
        let m = config_err(&web(
            "[environments.prod]\n",
            "[environments.prod]\nvault_id = \"v\"\n",
        ));
        assert!(
            m.contains(
                "environment prod: vault_id was removed in 0.7.0 (FR-57, FR-60): record one \
                 boundary per product instead, boundaries.<product> = { vault_id = \"...\", \
                 item_id = \"...\" }"
            ),
            "{m}"
        );
    }

    #[test]
    fn an_environment_item_id_is_refused_showing_the_boundaries_form() {
        let m = config_err(&web(
            "[environments.prod]\n",
            "[environments.prod]\nitem_id = \"i\"\n",
        ));
        assert!(
            m.contains("item_id was removed in 0.7.0") && m.contains("boundaries.<product> = {"),
            "{m}"
        );
    }

    #[test]
    fn an_environment_fly_section_is_refused_showing_the_target_form() {
        let m = config_err(&web(
            "[environments.prod]\n",
            "[environments.prod]\nfly.app = \"a\"\nfly.secret_name = \"{KEY}\"\n",
        ));
        assert!(
            m.contains(
                "declare a named target and put the section under it, \
                 [environments.prod.targets.<name>] with fly.app = ..., fly.secret_name = ..."
            ),
            "{m}"
        );
    }

    #[test]
    fn an_environment_azure_table_is_refused_showing_the_target_form() {
        let m = config_err(&format!(
            "{WEB}[environments.prod.azure]\nkey_vault = \"kv\"\n"
        ));
        assert!(
            m.contains(
                "an environment-level azure section was removed in 0.7.0 (FR-56, FR-60): \
                 declare a named target and put the section under it, \
                 [environments.prod.targets.<name>] with azure.key_vault = ..."
            ),
            "{m}"
        );
    }

    #[test]
    fn an_environment_deploy_credentials_is_refused_showing_the_target_form() {
        let m = config_err(&web(
            "[environments.prod]\n",
            "[environments.prod]\ndeploy_credentials = \"op://v/i\"\n",
        ));
        assert!(
            m.contains(
                "deploy_credentials was removed at the environment level in 0.7.0 (FR-56, \
                 FR-60): set it on the target, under [environments.prod.targets.<name>] as \
                 deploy_credentials = \"...\""
            ),
            "{m}"
        );
    }

    #[test]
    fn an_environment_state_vault_id_is_refused_showing_the_target_form() {
        let m = config_err(&web(
            "[environments.prod]\n",
            "[environments.prod]\nstate_vault_id = \"s\"\n",
        ));
        assert!(
            m.contains("under [environments.prod.targets.<name>] as state_vault_id = \"...\""),
            "{m}"
        );
    }

    #[test]
    fn github_products_is_refused_showing_the_target_products() {
        let m = config_err(&web(
            "fly.app = \"web-prod\"\nfly.secret_name = \"{KEY}\"\n",
            "github.repo = \"org/web\"\ngithub.products = [\"web\"]\n",
        ));
        assert!(
            m.contains(
                "github.products was removed in 0.7.0 (FR-48, FR-60): list the products on the \
                 target, targets.site.products = [...]"
            ),
            "{m}"
        );
    }

    #[test]
    fn a_bare_from_is_refused_showing_the_product_form() {
        let m = config_err(&web_plus(
            "[products.web.keys.PRISMA_URL]\nkind = \"secret\"\nenvironments = [\"prod\"]\nfrom = \"DATABASE_URL\"\n",
        ));
        assert!(
            m.contains("name the source's product too, from = \"<product>/DATABASE_URL\""),
            "{m}"
        );
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
        let m = config_err(&bound(&text, "prod", "my_app"));
        assert!(
            m.contains("my-app/K and my_app/K both render Fly name FLEET__MY_APP__K"),
            "{m}"
        );
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
        let m = config_err(&bound(&text, "prod", "a"));
        assert!(m.contains("a/B__C and a__b/C both render"), "{m}");
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
        let m = config_err(&bound(&text, "prod", "my_app"));
        assert!(m.starts_with("environment prod: target portfolio: "), "{m}");
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
        let m = config_err(&shared_name_fleet(false));
        assert!(m.contains("both render Fly name FLEET__MY_APP__K"), "{m}");
    }

    #[test]
    fn a_source_only_product_without_keys_is_refused_at_its_line() {
        let m = config_err(&format!(
            "{}\n[products.shared]\nsource_only = true\n",
            ok()
        ));
        assert!(
            m.contains("source_only = true needs at least one key")
                && m.contains("TOML parse error at line"),
            "{m}"
        );
    }

    #[test]
    fn source_only_with_a_non_boolean_value_is_refused_at_its_line() {
        let text = format!(
            "{}\n[products.shared]\nsource_only = \"true\"\n\
             [products.shared.keys.FLY_API_TOKEN]\nkind = \"secret\"\nenvironments = [\"prod\"]\n",
            ok()
        );
        let m = config_err(&text);
        assert!(m.contains("invalid type: string"), "{m}");
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
        let e = config_err(&shared(
            "kind = \"secret\"\nfrom = \"api/DB_URL\"\nenvironments = [\"prod\"]",
        ));
        assert!(
            e.contains("worker/DATABASE_URL: from = \"api/DB_URL\": names no declared key"),
            "{e}"
        );
    }

    #[test]
    fn a_shared_key_error_points_at_the_from_line() {
        let e = config_err(&shared(
            "kind = \"secret\"\nfrom = \"api/DB_URL\"\nenvironments = [\"prod\"]",
        ));
        assert!(e.contains("at line 53, column 1"), "{e}");
    }

    #[test]
    fn a_shared_key_refuses_a_source_of_another_kind() {
        let e = config_err(&shared(
            "kind = \"config\"\nfrom = \"api/DATABASE_URL\"\nenvironments = [\"prod\"]",
        ));
        assert!(
            e.contains("api/DATABASE_URL is a secret key, worker/DATABASE_URL a config key"),
            "{e}"
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
        let e = config_err(&text);
        assert!(e.contains("worker/DATABASE_URL is itself shared from api/DATABASE_URL (no chains); write from = \"api/DATABASE_URL\""), "{e}");
    }

    #[test]
    fn a_shared_key_refuses_a_cycle() {
        let text = format!(
            "{}\n[products.a.keys.K]\nkind = \"secret\"\nfrom = \"b/K\"\nenvironments = [\"prod\"]\n\n[products.b.keys.K]\nkind = \"secret\"\nfrom = \"a/K\"\nenvironments = [\"prod\"]\n",
            ok()
        );
        let e = config_err(&text);
        assert!(e.contains("(cycle)"), "{e}");
    }

    #[test]
    fn a_shared_key_refuses_its_own_name() {
        let e = config_err(&shared(
            "kind = \"secret\"\nfrom = \"worker/DATABASE_URL\"\nenvironments = [\"prod\"]",
        ));
        assert!(e.contains("cannot share its own value (cycle)"), "{e}");
    }

    #[test]
    fn a_shared_key_refuses_an_environment_its_source_lacks() {
        let text = format!(
            "{}\n[products.api.keys.DATABASE_URL]\nkind = \"secret\"\nenvironments = [\"prod\"]\n\n[products.worker.keys.DATABASE_URL]\nkind = \"secret\"\nfrom = \"api/DATABASE_URL\"\nenvironments = [\"staging\", \"prod\"]\n",
            ok()
        );
        let e = config_err(&text);
        assert!(e.contains("api/DATABASE_URL is not declared for environment \"staging\", which worker/DATABASE_URL uses"), "{e}");
    }

    #[test]
    fn a_shared_key_refuses_an_op_reference() {
        let e = config_err(&shared(
            "kind = \"secret\"\nfrom = \"op://vprd/other/api/DATABASE_URL\"\nenvironments = [\"prod\"]",
        ));
        assert!(
            e.contains("cross-environment references are not supported"),
            "{e}"
        );
    }

    #[test]
    fn a_shared_key_refuses_a_cross_environment_reference() {
        let e = config_err(&shared(
            "kind = \"secret\"\nfrom = \"staging/api/DATABASE_URL\"\nenvironments = [\"prod\"]",
        ));
        assert!(
            e.contains("cross-environment references are not supported"),
            "{e}"
        );
    }

    #[test]
    fn a_shared_key_refuses_its_own_immutable() {
        let e = config_err(&shared(
            "kind = \"secret\"\nfrom = \"api/DATABASE_URL\"\nimmutable = true\nenvironments = [\"prod\"]",
        ));
        assert!(
            e.contains("immutable follows the source of a shared key (api/DATABASE_URL)"),
            "{e}"
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
        let m = config_err(&with_prod_key(
            "p",
            "K1",
            "rules = { ensure_prefix = \"p-\", pattern = \"[a-z]+\" }\n",
        ));
        let (_, rule) = m.split_once("use regex = ").unwrap();
        let rule = rule.trim_end().strip_suffix(" instead").unwrap();
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
        assert!(config_err(&text).contains(
            "personal = true is for local environments only, and prod has a deployment target"
        ));
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
        assert!(config_err(&text).contains("a team key cannot read a personal value"));
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
        assert!(matches!(fixture().environment("qa"), Err(Error::Config(m)) if m.contains("qa")));
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
}
