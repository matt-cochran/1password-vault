//! `secrets.toml` loading and validation (FR-1, FR-2, §10.2).
//!
//! Validation runs before any secret operation; errors name the offending environment,
//! product, key or rule. The file holds IDs and rules only, never values.
//!
//! The generic environment fields (`vault_id`, `item_id`, `modes`) are parsed here; every
//! other table under an environment is a target section, handed to the provider registered
//! under that name (FR-37). Name checks run generically from each target's `NameRules`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use toml::Spanned;
use toml::de::{DeTable, DeValue};

use crate::adapters::registry;
use crate::domain::rules::{SIGNOZ_BODY, SIGNOZ_PREFIX};
use crate::domain::{
    Environment, Fleet, ItemRef, KeySpec, Product, Profile, SIMPLE_PRODUCT, key_label,
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

/// Parse and validate configuration text.
///
/// `profile.kind = "simple"` selects the simple profile (FR-20). Anything else, including a
/// file that does not parse, takes the fleet path exactly as in v0.1, which reports any
/// other kind as a configuration error.
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
    // The raw document first: the removed `pattern` rule must be reported as such, rather
    // than as the `deny_unknown_fields` error the typed parse would give (FR-60).
    let doc = Doc::parse(text).map_err(invalid)?;
    reject_removed_pattern(&doc)?;
    if peek_kind(text).as_deref() == Some("simple") {
        let raw: RawSimpleConfig = toml::from_str(text).map_err(invalid)?;
        return validate_simple(raw, &doc);
    }
    let raw: RawConfig = toml::from_str(text).map_err(invalid)?;
    validate(raw, &doc)
}

/// FR-24, FR-60: the `pattern` rule is removed (0.7.0); a file that still sets it must
/// fail at load with the key and the equivalent `regex` rule. The typed parse cannot do
/// this (its `deny_unknown_fields` reports only "unknown field"), so the raw document is
/// walked first: every `rules` table gets one check, and the error points at the `pattern`
/// entry's line and column. The replacement is built from configuration (the prefix and
/// the pattern) and never from a value.
fn reject_removed_pattern(doc: &Doc<'_>) -> Result<(), Error> {
    // (owner label, path to the rules table) for every declared key in either profile.
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
    if let Some(keys) = table(root, "keys") {
        for (key, _) in keys.iter() {
            let key = key.get_ref().as_ref();
            rules_tables.push((
                key_label(SIMPLE_PRODUCT, key),
                vec!["keys".into(), key.into(), "rules".into()],
            ));
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

    /// `environments.<env>.<key>`: present for every entry the typed parse saw.
    fn entry(&self, env: &str, key: &str) -> Option<&Spanned<DeValue<'t>>> {
        self.value(&["environments", env, key])
    }

    /// `msg` located at the declaration of key `key` of `product` (`[products.<p>.keys.<K>]`,
    /// or `[keys.<K>]` under the simple profile), like [`Doc::at`].
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
        let keys = if product == SIMPLE_PRODUCT {
            find(root, "keys").and_then(|(_, t)| t)
        } else {
            find(root, "products")
                .and_then(|(_, t)| t)
                .and_then(|t| find(t, product))
                .and_then(|(_, t)| t)
                .and_then(|t| find(t, "keys"))
                .and_then(|(_, t)| t)
        };
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

/// `profile.kind` when the text parses as TOML and holds it as a string.
fn peek_kind(text: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct Peek {
        profile: Option<PeekProfile>,
    }
    #[derive(Deserialize)]
    struct PeekProfile {
        kind: Option<String>,
    }
    toml::from_str::<Peek>(text).ok()?.profile?.kind
}

/// A simple-profile file (FR-20). `products` is accepted by the parser only so that
/// validation can reject it with a message naming the profile.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSimpleConfig {
    #[allow(dead_code)]
    profile: RawProfile,
    /// Flat `mode name → mode value`: there is only one (implicit) product.
    environments: BTreeMap<String, RawEnvironment<BTreeMap<String, String>>>,
    #[serde(default)]
    keys: BTreeMap<String, KeySpec>,
    #[serde(default)]
    products: Option<toml::Value>,
    #[serde(default)]
    stores: BTreeMap<String, toml::Value>,
}

/// product → mode name → mode value.
type FleetModes = BTreeMap<String, BTreeMap<String, String>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    profile: RawProfile,
    environments: BTreeMap<String, RawEnvironment<FleetModes>>,
    #[serde(default)]
    products: BTreeMap<String, Product>,
    /// Named stores (FR-39), parsed by the provider that declares their kind.
    #[serde(default)]
    stores: BTreeMap<String, toml::Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProfile {
    kind: String,
}

/// One environment: the generic fields, and every other entry as a target section.
#[derive(Deserialize)]
struct RawEnvironment<M> {
    vault_id: String,
    item_id: String,
    #[serde(default)]
    modes: M,
    /// `sync` needs `--confirm <env>` (NR-20).
    #[serde(default)]
    confirm_env: bool,
    /// The 1Password account for this environment's `op` calls (FR-40).
    #[serde(default)]
    account: Option<String>,
    /// `op://<vault>/<item>` holding the environment's deploy identity (FR-40).
    #[serde(default)]
    deploy_credentials: Option<String>,
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
    /// The vault holding delivery evidence (#106): the deploy identity may write it.
    #[serde(default)]
    state_vault_id: Option<String>,
    /// Optional: environments used only for `run`, `config export` and `item skeleton`
    /// need no target. At most one entry (FR-28).
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

/// The environment's target section, parsed by its provider (FR-28, FR-37): an unknown
/// section names the registered ones; two sections are refused. `secrets_in` binds it to
/// a named store when the registry declares the pair (FR-39).
fn target_of(
    name: &str,
    sections: &BTreeMap<String, toml::Value>,
    profile: Profile,
    stores: &Stores,
    doc: &Doc<'_>,
) -> Result<Option<Box<dyn TargetConfig>>, Error> {
    if let Some((unknown, v)) = sections.iter().find(|(s, _)| registry::find(s).is_none()) {
        let known = registry::sections().join(", ");
        return Err(doc.at(
            name,
            unknown,
            if v.is_table() {
                format!("environment {name}: unknown target section {unknown:?}; known: {known}")
            } else {
                format!(
                    "environment {name}: unknown field {unknown:?}; expected vault_id, item_id, \
                 modes, confirm_env, account, deploy_credentials, title, audience, order, \
                 personal_vault, personal_item, state_vault_id or a target section ({known})"
                )
            },
        ));
    }
    let present: Vec<_> = registry::PROVIDERS
        .iter()
        .filter(|p| sections.contains_key(p.section()))
        .collect();
    match present.as_slice() {
        [] => Ok(None),
        [p] => {
            let section = p.section();
            let value = doc
                .entry(name, section)
                .ok_or_else(|| cfg(format!("environment {name}: {section} section not found")))?;
            // `secrets_in` is generic (FR-39): taken out here, the rest goes to the provider.
            let mut rest = value.clone();
            let secrets_in = match rest.get_mut() {
                DeValue::Table(t) => t.remove("secrets_in"),
                _ => None,
            };
            let target = p.parse(&Section::new(name, &rest, doc.text), profile)?;
            let Some(secrets_in) = secrets_in else {
                return Ok(Some(target));
            };
            let at = |msg: String| doc.at_path(&["environments", name, section, "secrets_in"], msg);
            let Some(store_name) = secrets_in.get_ref().as_str() else {
                return Err(at(format!(
                    "environment {name}: {section}.secrets_in must be the name of a [stores.<name>] table"
                )));
            };
            let Some(store) = stores.get(store_name) else {
                let defined: Vec<&str> = stores.keys().map(String::as_str).collect();
                return Err(at(format!(
                    "environment {name}: {section}.secrets_in = {store_name:?} names no store; {}",
                    if defined.is_empty() {
                        format!("declare it as [stores.{store_name}]")
                    } else {
                        format!("defined: {}", defined.join(", "))
                    }
                )));
            };
            if !registry::binds(section, store.kind()) {
                return Err(at(format!(
                    "environment {name}: {section} cannot keep its secrets in store {store_name:?} \
                     ({}); supported secrets_in pairs: {}",
                    store.kind(),
                    registry::supported_pairs().join("; ")
                )));
            }
            p.bind(target, store.as_ref()).map(Some)
        }
        [a, b, ..] => Err(doc.at(
            name,
            b.section(),
            format!(
                "environment {name}: declares both {} and {}; use one target",
                a.section(),
                b.section()
            ),
        )),
    }
}

/// Validate one environment's generic fields and parse its target section.
fn environment<M>(
    name: &str,
    e: RawEnvironment<M>,
    profile: Profile,
    stores: &Stores,
    doc: &Doc<'_>,
) -> Result<(Environment, M), Error> {
    check_ids(name, &e.vault_id, &e.item_id)?;
    let target = target_of(name, &e.sections, profile, stores, doc)?;
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
    let deploy_credentials = match &e.deploy_credentials {
        None => None,
        Some(raw) => Some(deploy_credentials(name, raw, target.as_deref(), doc)?),
    };
    Ok((
        Environment {
            name: name.to_string(),
            vault_id: e.vault_id,
            item_id: e.item_id,
            target,
            modes: BTreeMap::new(),
            confirm_env: e.confirm_env,
            account: e.account,
            deploy_credentials,
            title: e.title,
            audience: e.audience,
            order: e.order,
            personal_vault: e.personal_vault,
            personal_item: e.personal_item,
            state_vault_id: e.state_vault_id,
        },
        e.modes,
    ))
}

/// `deploy_credentials` (FR-40): an `op://<vault>/<item>` reference, on an environment whose
/// provider signs in with one. Errors point at the line.
fn deploy_credentials(
    name: &str,
    raw: &str,
    target: Option<&dyn TargetConfig>,
    doc: &Doc<'_>,
) -> Result<ItemRef, Error> {
    let at = |msg: String| doc.at(name, "deploy_credentials", msg);
    let reference = ItemRef::parse(raw)
        .map_err(|why| at(format!("environment {name}: deploy_credentials {why}")))?;
    let Some(target) = target else {
        return Err(at(format!(
            "environment {name}: deploy_credentials needs a deployment target; remove it, or \
             add the target section it signs in to"
        )));
    };
    crate::provider::deploy_provider(target)
        .deploy_credential_fields()
        .map_err(|why| at(format!("environment {name}: {why}")))?;
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
    if raw.profile.kind != "fleet" {
        return Err(cfg(format!(
            "profile.kind must be \"fleet\" or \"simple\", got {:?}",
            raw.profile.kind
        )));
    }
    if raw.environments.is_empty() {
        return Err(cfg("no environments defined".into()));
    }

    let stores = stores(&raw.stores, doc)?;
    let mut environments = BTreeMap::new();
    for (name, e) in raw.environments {
        let (mut env, modes) = environment(&name, e, Profile::Fleet, &stores, doc)?;
        env.modes = modes;
        environments.insert(name, env);
    }
    check_shared_targets(&environments)?;

    for (product, p) in &raw.products {
        if !is_product_name(product) {
            return Err(cfg(format!(
                "product {product:?}: name must match ^[a-z][a-z0-9_-]*$"
            )));
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
    check_shared(&mut products, Profile::Fleet, doc)?;
    let fleet = Fleet {
        environments,
        products,
        profile: Profile::Fleet,
        origin: Default::default(),
    };
    check_names(&fleet, doc)?;
    check_scopes(&fleet)?;
    check_personal(&fleet)?;
    Ok(fleet)
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
                        .is_some_and(|x| x.target().is_some())
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
fn check_scopes(fleet: &Fleet) -> Result<(), Error> {
    for (env_name, env) in &fleet.environments {
        let Some(t) = env.target() else {
            continue;
        };
        let Some(listed) = t.scoped_products() else {
            continue;
        };
        let section = t.provider().section();
        for p in listed {
            match fleet.products.get(p) {
                None => {
                    let declared: Vec<&str> = fleet.products.keys().map(String::as_str).collect();
                    return Err(cfg(format!(
                        "environment {env_name}: {section}.products names {p:?}, which is not a \
                         declared product (declared: {})",
                        declared.join(", ")
                    )));
                }
                Some(prod) if prod.source_only => {
                    return Err(cfg(format!(
                        "environment {env_name}: {section}.products names {p:?}, which is \
                         source-only and never delivered; list the products whose keys point \
                         at it with from instead"
                    )));
                }
                Some(_) => {}
            }
        }
    }
    Ok(())
}

/// Validate a simple-profile file (FR-20) and desugar it into the shared model: one product
/// named [`SIMPLE_PRODUCT`], each target's simple-profile name template, and modes under
/// the implicit product. The managed set is therefore exactly the declared keys (FR-8,
/// SR-6).
fn validate_simple(raw: RawSimpleConfig, doc: &Doc<'_>) -> Result<Fleet, Error> {
    if raw.products.is_some() {
        return Err(cfg(
            "simple profile: [products] is not allowed; declare keys under [keys] (or use \
             profile.kind = \"fleet\")"
                .into(),
        ));
    }
    if raw.environments.is_empty() {
        return Err(cfg("no environments defined".into()));
    }

    let stores = stores(&raw.stores, doc)?;
    let mut environments = BTreeMap::new();
    for (name, e) in raw.environments {
        let (mut env, modes) = environment(&name, e, Profile::Simple, &stores, doc)?;
        if !modes.is_empty() {
            env.modes = BTreeMap::from([(SIMPLE_PRODUCT.to_string(), modes)]);
        }
        environments.insert(name, env);
    }
    check_shared_targets(&environments)?;

    for (key, spec) in &raw.keys {
        validate_key(key, key, spec, &environments)?;
    }

    let mut products = BTreeMap::from([(
        SIMPLE_PRODUCT.to_string(),
        Product {
            source_only: false,
            keys: raw.keys,
        },
    )]);
    check_shared(&mut products, Profile::Simple, doc)?;
    let fleet = Fleet {
        environments,
        products,
        profile: Profile::Simple,
        origin: Default::default(),
    };
    check_names(&fleet, doc)?;
    check_personal(&fleet)?;
    Ok(fleet)
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

/// IDs are non-empty, unpadded and safe in argv.
fn check_ids(name: &str, vault_id: &str, item_id: &str) -> Result<(), Error> {
    for (field, value) in [("vault_id", vault_id), ("item_id", item_id)] {
        check_ident(name, field, value, is_id, "^[A-Za-z0-9][A-Za-z0-9._-]*$")?;
    }
    Ok(())
}

/// Per-key checks shared by both profiles (FR-14 to FR-16, FR-24). `owner` names the key in
/// errors: `product/KEY` under the fleet profile, `KEY` under the simple profile.
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
/// key uses. No chains, no cycles, no cross-item or cross-environment reference. The
/// referencing key may not set `immutable`: it follows the source, and is copied from it
/// here so every later check (rotate, prune, hold) treats both alike. Errors point at the
/// `from` line.
fn check_shared(
    products: &mut BTreeMap<String, Product>,
    profile: Profile,
    doc: &Doc<'_>,
) -> Result<(), Error> {
    let simple = profile == Profile::Simple;
    let path = |product: &str, key: &str, field: &str| -> Vec<String> {
        if simple {
            vec!["keys".into(), key.into(), field.into()]
        } else {
            vec![
                "products".into(),
                product.into(),
                "keys".into(),
                key.into(),
                field.into(),
            ]
        }
    };
    let at = |product: &str, key: &str, field: &str, msg: String| {
        let p = path(product, key, field);
        doc.at_path(&p.iter().map(String::as_str).collect::<Vec<_>>(), msg)
    };
    let shape = if simple {
        "\"<KEY>\""
    } else {
        "\"<product>/<KEY>\""
    };
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
            if from.contains("://") || slashes > usize::from(!simple) {
                return Err(err(format!(
                    "a shared key reads another key of the same environment's item; write \
                     from = {shape} (cross-item and cross-environment references are not supported)"
                )));
            }
            let (sp, sk) = spec.source().expect("from is set");
            let well_formed = is_env_name(sk) && (simple || (slashes == 1 && is_product_name(sp)));
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
                     {env:?} to its environments (the value is read from the same environment's item)"
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
            let set = if simple {
                doc.value(&["keys", key, "immutable"])
            } else {
                doc.value(&["products", product, "keys", key, "immutable"])
            };
            if set.is_some() {
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

/// Two environments on the same target would manage the same names, and each would prune
/// what the other stages (FR-8). The provider decides what "same" means and words the error.
fn check_shared_targets(environments: &BTreeMap<String, Environment>) -> Result<(), Error> {
    let targets: Vec<(&str, &dyn TargetConfig)> = environments
        .iter()
        .filter_map(|(n, e)| e.target().map(|t| (n.as_str(), t)))
        .collect();
    for (i, (name, t)) in targets.iter().enumerate() {
        if let Some((prev, _)) = targets[..i].iter().find(|(_, p)| t.same_target(*p)) {
            return Err(cfg(t.shared_target_error(prev, name)));
        }
    }
    Ok(())
}

/// Every name a target renders, for EVERY declared key (not only those desired in the
/// environment), must be a valid env-var name, fit the store's limits and be unique within
/// the environment (case-folded when the store ignores case). The managed set is every
/// rendered name, so a key desired here and another key declared only elsewhere that
/// render the same name would otherwise be both staged and pruned in one run (FR-2, FR-8,
/// FR-30).
fn check_names(fleet: &Fleet, doc: &Doc<'_>) -> Result<(), Error> {
    // Store names already taken in a named store, case-folded as it compares them, by
    // every environment that keeps its secrets there (FR-39): (store, id) → (env, owner).
    let mut shared: Vec<(&dyn StoreConfig, String, String, String)> = Vec::new();
    for (env_name, env) in &fleet.environments {
        let Some(t) = env.target() else {
            continue;
        };
        let rules = t.name_rules();
        let store = t.secrets_in();
        let mut seen: BTreeMap<String, String> = BTreeMap::new();
        let mut seen_in_store: BTreeMap<String, String> = BTreeMap::new();
        for (product, p) in &fleet.products {
            // FR-47/FR-48: an undelivered product's keys render no name here, so they are
            // exempt from the name collision check too.
            if !fleet.delivers(env_name, product) {
                continue;
            }
            for key in p.keys.keys() {
                let name = t.env_name(product, key);
                let owner = key_label(product, key);
                if !is_env_name(&name) {
                    return Err(cfg(format!(
                        "environment {env_name}: {owner} renders {} {name:?}, which must match ^[A-Z][A-Z0-9_]*$",
                        rules.env_label
                    )));
                }
                let id = match &rules.store {
                    None => name.clone(),
                    Some(s) => {
                        let at = Place {
                            env_name,
                            product,
                            key,
                            owner: &owner,
                        };
                        store_id(&at, &t.store_name(&name), s, doc)?
                    }
                };
                check_unique(&mut seen, env_name, &rules, id, &owner)?;
                if let Some(store) = store {
                    let s = store.name_rules();
                    let at = Place {
                        env_name,
                        product,
                        key,
                        owner: &owner,
                    };
                    let id = store_id(&at, &store.store_name(&name), &s, doc)?;
                    let named = NameRules {
                        env_label: rules.env_label,
                        store: Some(s),
                    };
                    check_unique(&mut seen_in_store, env_name, &named, id.clone(), &owner)?;
                    if let Some((_, _, other, prev)) = shared
                        .iter()
                        .find(|(st, i, e, _)| st.same_store(store) && *i == id && e != env_name)
                    {
                        return Err(cfg(format!(
                            "environments {other} and {env_name} both keep {} {id} in {} ({prev} \
                             and {owner}); each would overwrite and prune the other's value\n  \
                             next: give one of them its own store, or an env_name template that \
                             renders different names",
                            s.label,
                            store.describe()
                        )));
                    }
                    shared.push((store, id, env_name.clone(), owner.clone()));
                }
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

/// Two keys of one environment must not render the same name (FR-8).
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
    Err(cfg(match &rules.store {
        None => format!(
            "environment {env_name}: {prev} and {owner} both render {} {id}",
            rules.env_label
        ),
        Some(s) => format!(
            "environment {env_name}: {prev} and {owner} both map to {} {id}",
            s.label
        ),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Kind;
    const RAW: &str = include_str!("../tests/fixtures/secrets.toml");

    /// The fixture with LF line endings, whatever the checkout did (Windows may give CRLF).
    fn ok() -> String {
        RAW.replace("\r\n", "\n")
    }

    /// The fixture with `from` replaced by `to`. Panics if `from` does not occur, so a
    /// mutation that silently fails to apply can never make a rejection test pass.
    fn mutate(from: &str, to: &str) -> String {
        let base = ok();
        assert!(
            base.contains(from),
            "fixture mutation did not match: {from:?}"
        );
        base.replace(from, to)
    }
    #[test]
    fn loads_fleet_profile_and_builds_target_names() {
        let f = parse(&ok()).unwrap();
        assert_eq!(
            f.target_name("prod", "allumata", "OPENAI_API_KEY"),
            "FLEET__ALLUMATA__OPENAI_API_KEY"
        );
        assert_eq!(
            f.products["allumata"].keys["SIGNUP_POLICY"].kind,
            Kind::Config
        );
        assert!(f.products["allumata"].keys["INTEGRATION_ENC_KEY"].immutable);
    }
    #[test]
    fn rejects_key_for_undefined_environment() {
        let bad = mutate(r#"environments = ["prod"]"#, r#"environments = ["qa"]"#);
        assert!(matches!(parse(&bad), Err(Error::Config(m)) if m.contains("qa")));
    }
    #[test]
    fn rejects_template_without_placeholders() {
        let bad = mutate("FLEET__{PRODUCT}__{KEY}", "FLEET_STATIC");
        assert!(matches!(parse(&bad), Err(Error::Config(_))));
    }
    #[test]
    fn rejects_non_env_name_keys() {
        let bad = mutate(
            "[products.allumata.keys.OPENAI_API_KEY]",
            "[products.allumata.keys.openai-key]",
        );
        assert!(matches!(parse(&bad), Err(Error::Config(_))));
    }

    fn config_err(text: &str) -> String {
        match parse(text) {
            Err(Error::Config(m)) => m.to_string(),
            other => panic!("expected Config error, got {other:?}"),
        }
    }

    #[test]
    fn parses_full_model() {
        let f = parse(&ok()).unwrap();
        let prod = &f.environments["prod"];
        assert_eq!(prod.vault_id, "vprd");
        assert_eq!(prod.item_id, "iprd");
        assert_eq!(
            prod.target()
                .and_then(|t| t.as_any().downcast_ref::<crate::adapters::fly::FlyTarget>())
                .map(|t| t.app.as_str()),
            Some("mcproductlabs-portfolio-production")
        );
        assert_eq!(prod.modes["allumata"]["payments"], "off");
        assert_eq!(
            f.environments["staging"].modes["allumata"]["payments"],
            "test"
        );
        let keys = &f.products["allumata"].keys;
        assert_eq!(keys.len(), 4);
        let openai = &keys["OPENAI_API_KEY"];
        assert_eq!(openai.kind, Kind::Secret);
        assert_eq!(openai.environments, vec!["prod"]);
        assert_eq!(openai.rules.prefix.as_deref(), Some("sk-"));
        assert_eq!(
            openai.rules.not_prefix,
            Some(crate::domain::OneOrMany::One("sk-or-".into()))
        );
        assert!(!openai.immutable);
        assert_eq!(openai.guidance, "OpenAI platform / API keys");
        assert_eq!(keys["INTEGRATION_ENC_KEY"].rules.base64_bytes, Some(32));
        let pbm = keys["STRIPE_SECRET_KEY"]
            .rules
            .prefix_by_mode
            .as_ref()
            .unwrap();
        assert_eq!(pbm.mode, "payments");
        assert_eq!(
            pbm.values["test"],
            crate::domain::OneOrMany::One("sk_test_".into())
        );
        assert_eq!(
            pbm.values["live"],
            crate::domain::OneOrMany::One("sk_live_".into())
        );
        assert_eq!(pbm.skip, vec!["off", "external"]);
        assert_eq!(
            keys["SIGNUP_POLICY"].rules.r#enum,
            Some(vec!["open".to_string(), "invite_only".to_string()])
        );
    }

    #[test]
    fn rejects_non_fleet_profile() {
        // "simple" is a valid profile since FR-20; any other kind is still rejected.
        let m = config_err(&mutate(r#"kind = "fleet""#, r#"kind = "flat""#));
        assert!(m.contains("profile.kind"), "{m}");
    }

    #[test]
    fn rejects_unknown_fields_and_rules() {
        config_err(&mutate("immutable = true", "immutible = true"));
        config_err(&mutate("base64_bytes = 32", "base64_len = 32"));
        config_err(&mutate(
            "vault_id = \"vprd\"",
            "vault_id = \"vprd\"\nvault = \"x\"",
        ));
    }

    #[test]
    fn rejects_unknown_kind() {
        config_err(&mutate(r#"kind = "config""#, r#"kind = "text""#));
    }

    #[test]
    fn rejects_bad_product_name() {
        let m = config_err(&mutate("products.allumata.", "products.Allumata."));
        assert!(m.contains("Allumata"), "{m}");
    }

    #[test]
    fn rejects_missing_or_empty_fly_config() {
        let m = config_err(&mutate(r#"item_id = "iprd""#, r#"item_id = """#));
        assert!(m.contains("prod") && m.contains("item_id"), "{m}");
        config_err(&mutate(
            "fly.app = \"mcproductlabs-portfolio-production\"\n",
            "",
        ));
    }

    #[test]
    fn rejects_template_missing_one_placeholder() {
        config_err(&mutate("FLEET__{PRODUCT}__{KEY}", "FLEET__{KEY}"));
        config_err(&mutate("FLEET__{PRODUCT}__{KEY}", "FLEET__{PRODUCT}"));
    }

    #[test]
    fn rejects_regex_that_does_not_compile_naming_key() {
        let m = config_err(&mutate(
            r#"rules = { base64_bytes = 32 }"#,
            r#"rules = { regex = "([a-z" }"#,
        ));
        assert!(m.contains("allumata/INTEGRATION_ENC_KEY"), "{m}");
    }

    /// One extra `p/K1` key with the given rules table, appended to the fixture.
    fn signoz_like_key(key: &str, rules: &str) -> String {
        format!(
            "\n[products.p.keys.{key}]\nkind = \"secret\"\nenvironments = [\"prod\"]\nrules = {{ {rules} }}\n"
        )
    }

    #[test]
    fn parses_ensure_prefix_rule() {
        let fleet = parse(&format!(
            "{}{}",
            ok(),
            signoz_like_key("K1", "ensure_prefix = \"p-\"")
        ))
        .unwrap();
        assert_eq!(
            fleet.products["p"].keys["K1"]
                .rules
                .ensure_prefix
                .as_deref(),
            Some("p-")
        );
    }

    /// FR-24, FR-60: the `pattern` rule is removed; a file that still sets it fails at
    /// load, naming the key and the equivalent `regex` rule to write. The entry's line and
    /// column are reported like any other rule error, and the file's text is never quoted.
    #[test]
    fn pattern_rule_fails_at_load_with_the_equivalent_regex() {
        let text = "[profile]\nkind = \"simple\"\n[environments.prod]\nvault_id = \"v\"\n\
                    item_id = \"i\"\nfly.app = \"app\"\n[keys.K1]\nkind = \"secret\"\n\
                    environments = [\"prod\"]\nrules = { ensure_prefix = \"p-\", pattern = \"[a-z]+\" }\n";
        assert_eq!(
            config_err(text),
            "invalid secrets.toml: TOML parse error at line 10, column 33\n\
             K1: the pattern rule was removed; use regex = 'p\\-(?:[a-z]+)' instead\n"
        );
    }

    /// FR-24, FR-60: the same check applies under the fleet profile, naming the key as
    /// `product/KEY`.
    #[test]
    fn pattern_rule_fails_under_the_fleet_profile_naming_the_key() {
        let text = format!(
            "{}{}",
            ok(),
            signoz_like_key("K1", "ensure_prefix = \"p-\", pattern = \"[a-z]+\"")
        );
        let m = config_err(&text);
        let message = m.split_once('\n').map_or(m.as_str(), |(_, rest)| rest);
        assert_eq!(
            message,
            "p/K1: the pattern rule was removed; use regex = 'p\\-(?:[a-z]+)' instead\n"
        );
    }

    #[test]
    fn ensure_prefix_with_regex_is_a_valid_configuration() {
        assert!(
            parse(&format!(
                "{}{}",
                ok(),
                signoz_like_key("K1", "ensure_prefix = \"p-\", regex = \"p-[a-z]+\"")
            ))
            .is_ok()
        );
    }

    #[test]
    fn op_environment_names_are_reserved_key_names() {
        for key in [
            "PATH",
            "HOME",
            "XDG_CONFIG_HOME",
            "OP_SESSION_MY",
            "OP_SERVICE_ACCOUNT_TOKEN",
        ] {
            let m = config_err(&format!(
                "{}{}",
                ok(),
                signoz_like_key(key, "prefix = \"x\"")
            ));
            assert!(m.contains("key name is reserved"), "{key}: {m}");
        }
    }

    #[test]
    fn signoz_transform_is_a_configuration_error() {
        let m = config_err(&format!(
            "{}{}",
            ok(),
            signoz_like_key("K1", "transform = \"signoz_ingestion_header\"")
        ));
        assert_eq!(
            m,
            "p/K1: transform = \"signoz_ingestion_header\" was removed in 0.4.0; use \
             ensure_prefix = \"signoz-ingestion-key=\" with regex = \
             'signoz\\-ingestion\\-key=(?:[A-Za-z0-9._~+/-]+={0,2})'"
        );
    }

    #[test]
    fn rejects_empty_prefix_lists_and_strings() {
        for bad in [
            r#"rules = { not_prefix = [] }"#,
            r#"rules = { not_prefix = "" }"#,
            r#"rules = { not_prefix = ["a", ""] }"#,
        ] {
            let m = config_err(&mutate(r#"rules = { base64_bytes = 32 }"#, bad));
            assert!(m.contains("allumata/INTEGRATION_ENC_KEY"), "{m}");
        }
        for bad in [
            r#"values = { test = [], live = "sk_live_" }"#,
            r#"values = { test = "", live = "sk_live_" }"#,
            r#"values = { test = ["sk_test_", ""], live = "sk_live_" }"#,
        ] {
            let m = config_err(&mutate(
                r#"values = { test = "sk_test_", live = "sk_live_" }"#,
                bad,
            ));
            assert!(m.contains("allumata/STRIPE_SECRET_KEY"), "{m}");
        }
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
    fn load_reads_file_and_reports_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("secrets.toml");
        std::fs::write(&p, RAW).unwrap();
        assert!(load(&p).is_ok());
        let missing = dir.path().join("nope.toml");
        assert!(matches!(load(&missing), Err(Error::Config(m)) if m.contains("nope.toml")));
    }

    /// Appends an extra key declaration to the fixture.
    fn with_key(product: &str, key: &str, envs: &str) -> String {
        format!(
            "{}\n[products.{product}.keys.{key}]\nkind = \"secret\"\nenvironments = {envs}\n",
            ok()
        )
    }

    #[test]
    fn rejects_target_name_collision_from_product_normalization() {
        let text = with_key("my-app", "K", r#"["prod"]"#);
        let text = format!(
            "{text}\n[products.my_app.keys.K]\nkind = \"secret\"\nenvironments = [\"prod\"]\n"
        );
        let m = config_err(&text);
        assert!(
            m.contains("my-app/K") && m.contains("my_app/K") && m.contains("FLEET__MY_APP__K"),
            "{m}"
        );
    }

    #[test]
    fn rejects_target_name_collision_across_double_underscore() {
        let text = with_key("a__b", "C", r#"["staging"]"#);
        let text = format!(
            "{text}\n[products.a.keys.B__C]\nkind = \"secret\"\nenvironments = [\"staging\"]\n"
        );
        let m = config_err(&text);
        assert!(
            // Every declared key is checked in every environment with a Fly target (C1), so
            // the first environment checked (prod, in name order) reports it.
            m.contains("a__b/C") && m.contains("a/B__C") && m.contains("environment prod"),
            "{m}"
        );
    }

    /// C1: the managed set is every rendered name, so a collision is rejected even when the
    /// two keys are desired in different environments: in prod `my-app/K` is staged while
    /// `my_app/K` (staging only) is not desired there, and `--prune` would delete the very
    /// name the same run staged.
    #[test]
    fn rejects_target_name_collision_even_across_environments() {
        let text = with_key("my-app", "K", r#"["prod"]"#);
        let text = format!(
            "{text}\n[products.my_app.keys.K]\nkind = \"secret\"\nenvironments = [\"staging\"]\n"
        );
        let m = config_err(&text);
        assert!(
            m.contains("my-app/K") && m.contains("my_app/K") && m.contains("FLEET__MY_APP__K"),
            "{m}"
        );
    }

    /// The collision check covers keys declared for no environment of their own, too.
    #[test]
    fn rejects_target_name_collision_with_key_declared_for_no_environment() {
        let text = with_key("my-app", "K", r#"["prod"]"#);
        let text =
            format!("{text}\n[products.my_app.keys.K]\nkind = \"secret\"\nenvironments = []\n");
        config_err(&text);
    }

    #[test]
    fn rejects_ids_and_app_that_could_be_read_as_flags_or_hold_odd_characters() {
        for (from, to) in [
            (r#"vault_id = "vprd""#, r#"vault_id = "-vprd""#),
            (r#"item_id = "iprd""#, r#"item_id = "--format""#),
            (
                r#"fly.app = "mcproductlabs-portfolio-production""#,
                r#"fly.app = "-a""#,
            ),
            (r#"vault_id = "vprd""#, r#"vault_id = "v/prd""#),
            (r#"item_id = "iprd""#, r#"item_id = "i prd""#),
            (
                r#"fly.app = "mcproductlabs-portfolio-production""#,
                r#"fly.app = "app;rm""#,
            ),
        ] {
            let m = config_err(&mutate(from, to));
            assert!(m.contains("prod") && m.contains("must match"), "{to}: {m}");
        }
        // Dots, underscores and dashes after the first character are fine.
        assert!(parse(&mutate(r#"vault_id = "vprd""#, r#"vault_id = "v.p_r-d9""#)).is_ok());
    }

    #[test]
    fn rejects_two_environments_sharing_app_and_template() {
        let m = config_err(&mutate(
            r#"fly.app = "mcproductlabs-portfolio-staging""#,
            r#"fly.app = "mcproductlabs-portfolio-production""#,
        ));
        assert!(
            m.contains("prod") && m.contains("staging") && m.contains("production"),
            "{m}"
        );
        // Same app with a different template manages disjoint names: allowed.
        let t = mutate(
            r#"fly.app = "mcproductlabs-portfolio-staging"
fly.secret_name = "FLEET__{PRODUCT}__{KEY}""#,
            r#"fly.app = "mcproductlabs-portfolio-production"
fly.secret_name = "STG__{PRODUCT}__{KEY}""#,
        );
        assert!(parse(&t).is_ok());
    }

    /// I5: `fly` is optional per environment.
    #[test]
    fn fly_section_is_optional() {
        let t = format!(
            "{}\n[environments.dev]\nvault_id = \"vdev\"\nitem_id = \"idev\"\n",
            ok()
        );
        let f = parse(&t).unwrap();
        assert!(f.environments["dev"].target.is_none());
        assert!(matches!(
            crate::app::target(&f, "dev"),
            Err(Error::Config(m)) if m.contains("dev") && m.contains("no deployment target")
        ));
        assert!(crate::app::target(&f, "prod").is_ok());
        // `secret_name` stays required when `fly` is present.
        let t = format!(
            "{}\n[environments.dev]\nvault_id = \"vdev\"\nitem_id = \"idev\"\nfly.app = \"dev-app\"\n",
            ok()
        );
        let m = config_err(&t);
        assert!(m.contains("secret_name"), "{m}");
    }

    /// I1: refuse_in names must be defined, must not overlap `environments`.
    #[test]
    fn validates_refuse_in() {
        let m = config_err(&mutate(
            r#"rules = { prefix = "sk-", not_prefix = "sk-or-" }"#,
            r#"rules = { prefix = "sk-", not_prefix = "sk-or-", refuse_in = ["qa"] }"#,
        ));
        assert!(
            m.contains("allumata/OPENAI_API_KEY") && m.contains("qa"),
            "{m}"
        );
        let m = config_err(&mutate(
            r#"rules = { prefix = "sk-", not_prefix = "sk-or-" }"#,
            r#"rules = { prefix = "sk-", not_prefix = "sk-or-", refuse_in = ["prod"] }"#,
        ));
        assert!(
            m.contains("allumata/OPENAI_API_KEY") && m.contains("both"),
            "{m}"
        );
        assert!(
            parse(&mutate(
                r#"rules = { prefix = "sk-", not_prefix = "sk-or-" }"#,
                r#"rules = { prefix = "sk-", not_prefix = "sk-or-", refuse_in = ["staging"] }"#,
            ))
            .is_ok()
        );
    }

    #[test]
    fn rejects_empty_prefix() {
        let m = config_err(&mutate(r#"prefix = "sk-""#, r#"prefix = """#));
        assert!(
            m.contains("allumata/OPENAI_API_KEY") && m.contains("prefix"),
            "{m}"
        );
    }

    #[test]
    fn rejects_template_rendering_invalid_target_names() {
        let m = config_err(&mutate(
            "FLEET__{PRODUCT}__{KEY}",
            "fleet__{PRODUCT}__{KEY}",
        ));
        assert!(m.contains("fleet__ALLUMATA__"), "{m}");
        config_err(&mutate("FLEET__{PRODUCT}__{KEY}", "FLEET-{PRODUCT}-{KEY}"));
        config_err(&mutate("FLEET__{PRODUCT}__{KEY}", "{PRODUCT}{KEY} X"));
    }

    #[test]
    fn rejects_whitespace_around_ids_and_app() {
        let m = config_err(&mutate(r#"vault_id = "vprd""#, r#"vault_id = " vprd""#));
        assert!(
            m.contains("prod") && m.contains("vault_id") && m.contains("whitespace"),
            "{m}"
        );
        config_err(&mutate(r#"item_id = "iprd""#, r#"item_id = "iprd\n""#));
        config_err(&mutate(
            r#"fly.app = "mcproductlabs-portfolio-production""#,
            r#"fly.app = "mcproductlabs-portfolio-production ""#,
        ));
    }

    #[test]
    fn try_target_name_reports_undefined_environment() {
        let f = parse(&ok()).unwrap();
        let name =
            |env| crate::app::target(&f, env).map(|(_, t)| t.env_name("allumata", "SIGNUP_POLICY"));
        assert_eq!(name("staging").unwrap(), "FLEET__ALLUMATA__SIGNUP_POLICY");
        assert!(matches!(
            name("qa"),
            Err(Error::Config(m)) if m.contains("qa")
        ));
        assert_eq!(f.environment("prod").unwrap().vault_id, "vprd");
        assert!(matches!(f.environment("qa"), Err(Error::Config(_))));
    }

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
    fn name_validators() {
        assert!(is_env_name("A") && is_env_name("OPENAI_API_KEY") && is_env_name("K2"));
        assert!(
            !is_env_name("") && !is_env_name("_A") && !is_env_name("1A") && !is_env_name("A-B")
        );
        assert!(!is_env_name("Abc"));
        assert!(is_product_name("allumata") && is_product_name("my-app_2"));
        assert!(!is_product_name("") && !is_product_name("-a") && !is_product_name("App"));
        assert!(is_id("vprd") && is_id("a1.b_c-d") && is_id("9x"));
        assert!(!is_id("") && !is_id("-a") && !is_id(".a") && !is_id("a b") && !is_id("a/b"));
    }

    // ---------- simple profile (FR-20) ----------

    const SIMPLE: &str = include_str!("../tests/fixtures/simple.toml");

    fn simple() -> String {
        SIMPLE.replace("\r\n", "\n")
    }

    /// The simple fixture with `from` replaced by `to`; panics if `from` does not occur.
    fn simple_mutate(from: &str, to: &str) -> String {
        let base = simple();
        assert!(
            base.contains(from),
            "fixture mutation did not match: {from:?}"
        );
        base.replace(from, to)
    }

    #[test]
    fn simple_profile_parses_as_simple() {
        assert!(parse(&simple()).unwrap().is_simple());
    }

    #[test]
    fn fleet_profile_parses_as_fleet() {
        assert_eq!(parse(&ok()).unwrap().profile, Profile::Fleet);
    }

    #[test]
    fn simple_keys_desugar_into_the_implicit_product() {
        let f = parse(&simple()).unwrap();
        assert_eq!(f.products.len(), 1);
        assert_eq!(f.products[SIMPLE_PRODUCT].keys.len(), 5);
    }

    #[test]
    fn simple_target_name_is_the_key_name() {
        let f = parse(&simple()).unwrap();
        assert_eq!(f.target_name("prod", SIMPLE_PRODUCT, "JWT_KEY"), "JWT_KEY");
    }

    #[test]
    fn simple_key_carries_kind_rules_immutable_and_guidance() {
        let f = parse(&simple()).unwrap();
        let jwt = &f.products[SIMPLE_PRODUCT].keys["JWT_KEY"];
        assert!(jwt.immutable);
        assert_eq!(jwt.rules.base64_bytes, Some(32));
        assert_eq!(jwt.guidance, "32 random bytes, base64");
        assert_eq!(
            f.products[SIMPLE_PRODUCT].keys["LOG_LEVEL"].kind,
            Kind::Config
        );
    }

    #[test]
    fn simple_modes_land_under_the_implicit_product() {
        let f = parse(&simple()).unwrap();
        assert_eq!(
            f.environments["staging"].modes[SIMPLE_PRODUCT]["payments"],
            "test"
        );
    }

    #[test]
    fn simple_rejects_products_table() {
        let m = config_err(&format!(
            "{}\n[products.api.keys.K]\nkind = \"secret\"\nenvironments = [\"prod\"]\n",
            simple()
        ));
        assert!(m.contains("[products]") && m.contains("simple"), "{m}");
    }

    #[test]
    fn simple_rejects_fly_secret_name() {
        let m = config_err(&simple_mutate(
            "fly.app = \"myapp-production\"",
            "fly.app = \"myapp-production\"\nfly.secret_name = \"{KEY}\"",
        ));
        assert!(m.contains("prod") && m.contains("fly.secret_name"), "{m}");
    }

    #[test]
    fn simple_rejects_key_name_not_matching_env_name_format() {
        let m = config_err(&simple_mutate("[keys.JWT_KEY]", "[keys.jwt-key]"));
        assert!(
            m.contains("jwt-key") && m.contains("^[A-Z][A-Z0-9_]*$"),
            "{m}"
        );
    }

    #[test]
    fn simple_rejects_the_same_key_declared_twice() {
        let m = config_err(&format!(
            "{}\n[keys.JWT_KEY]\nkind = \"secret\"\nenvironments = [\"prod\"]\n",
            simple()
        ));
        assert!(m.contains("JWT_KEY"), "{m}");
    }

    #[test]
    fn simple_rejects_two_environments_on_one_app() {
        let m = config_err(&simple_mutate("myapp-staging", "myapp-production"));
        assert!(
            m.contains("prod") && m.contains("staging") && m.contains("myapp-production"),
            "{m}"
        );
    }

    #[test]
    fn simple_rejects_key_for_undefined_environment_naming_key() {
        let m = config_err(&simple_mutate(
            "environments = [\"staging\"]",
            "environments = [\"qa\"]",
        ));
        assert!(m.contains("STAGING_DEBUG_TOKEN") && m.contains("qa"), "{m}");
    }

    #[test]
    fn simple_rule_errors_name_the_key_without_a_product() {
        let m = config_err(&simple_mutate(
            "rules = { base64_bytes = 32 }",
            "rules = { regex = \"([a-z\" }",
        ));
        assert!(m.starts_with("JWT_KEY: rule regex"), "{m}");
    }

    #[test]
    fn simple_rejects_bad_ids() {
        let m = config_err(&simple_mutate(
            "vault_id = \"vprd\"",
            "vault_id = \"-vprd\"",
        ));
        assert!(m.contains("prod") && m.contains("must match"), "{m}");
    }

    #[test]
    fn simple_fly_section_is_optional() {
        let f = parse(&format!(
            "{}\n[environments.dev]\nvault_id = \"vdev\"\nitem_id = \"idev\"\n",
            simple()
        ))
        .unwrap();
        assert!(matches!(
            crate::app::target(&f, "dev"),
            Err(Error::Config(m)) if m.contains("add one target section (fly, azure, kubernetes, github)")
        ));
    }

    #[test]
    fn simple_rejects_unknown_fields() {
        config_err(&simple_mutate("immutable = true", "immutible = true"));
    }

    /// FR-37: a table under an environment that no registered provider owns.
    #[test]
    fn unknown_target_section_lists_known_providers() {
        let bad = mutate(
            "fly.app = \"mcproductlabs-portfolio-production\"",
            "flyy.app = \"x\"\nfly.app = \"mcproductlabs-portfolio-production\"",
        );
        assert!(config_err(&bad).ends_with(
            "\nenvironment prod: unknown target section \"flyy\"; known: azure, fly, github, kubernetes\n"
        ));
    }

    /// FR-2: an unknown entry under an environment names its line, as the parser's own
    /// errors do (never the line's text, C1).
    #[test]
    fn unknown_target_section_names_its_line() {
        let bad = mutate(
            "fly.app = \"mcproductlabs-portfolio-production\"",
            "flyy.app = \"x\"\nfly.app = \"mcproductlabs-portfolio-production\"",
        );
        assert!(
            config_err(&bad).contains("at line "),
            "{}",
            config_err(&bad)
        );
    }

    /// A plain value is a mistyped field, not a target section.
    #[test]
    fn unknown_environment_field_names_the_expected_fields() {
        let bad = mutate(
            "fly.app = \"mcproductlabs-portfolio-production\"",
            "vault = \"x\"\nfly.app = \"mcproductlabs-portfolio-production\"",
        );
        assert!(config_err(&bad).ends_with(
            "\nenvironment prod: unknown field \"vault\"; expected vault_id, item_id, modes, \
             confirm_env, account, deploy_credentials, title, audience, order, personal_vault, \
             personal_item, state_vault_id or a target section (azure, fly, github, kubernetes)\n"
        ));
    }

    /// `prod` with `line` added after its item_id.
    fn prod_with(line: &str) -> String {
        mutate("item_id = \"iprd\"", &format!("item_id = \"iprd\"\n{line}"))
    }

    #[test]
    fn account_and_deploy_credentials_are_parsed() {
        let f = parse(&prod_with(
            "account = \"work.1password.com\"\ndeploy_credentials = \"op://Infra Prod/fly deploy\"",
        ))
        .unwrap();
        let prod = f.environment("prod").unwrap();
        assert_eq!(
            (
                prod.account.as_deref(),
                prod.deploy_credentials.as_ref().map(ToString::to_string)
            ),
            (
                Some("work.1password.com"),
                Some("op://Infra Prod/fly deploy".to_string())
            )
        );
    }

    #[test]
    fn invalid_account_points_at_its_line() {
        let m = config_err(&prod_with("account = \"-work\""));
        assert!(m.contains("line ") && m.contains("account must be"), "{m}");
    }

    #[test]
    fn deploy_credentials_with_a_field_is_refused_at_its_line() {
        let m = config_err(&prod_with(
            "deploy_credentials = \"op://v/i/FLY_API_TOKEN\"",
        ));
        assert!(m.contains("line ") && m.contains("not a field"), "{m}");
    }

    #[test]
    fn deploy_credentials_must_be_an_op_reference() {
        let m = config_err(&prod_with("deploy_credentials = \"vault/item\""));
        assert!(
            m.contains("must be an op://<vault>/<item> reference"),
            "{m}"
        );
    }

    #[test]
    fn deploy_credentials_without_a_target_is_refused() {
        let text = "[profile]\nkind = \"simple\"\n[environments.dev]\nvault_id = \"v\"\n\
                    item_id = \"i\"\ndeploy_credentials = \"op://v/deploy\"\n";
        let m = config_err(text);
        assert!(
            m.contains("deploy_credentials needs a deployment target"),
            "{m}"
        );
    }

    #[test]
    fn kubernetes_deploy_credentials_is_a_configuration_error() {
        let text = "[profile]\nkind = \"simple\"\n[environments.dev]\nvault_id = \"v\"\n\
                    item_id = \"i\"\ndeploy_credentials = \"op://v/deploy\"\n\
                    [environments.dev.kubernetes]\ncontext = \"kind-dev\"\nnamespace = \"app\"\n\
                    deployment = \"web\"\n";
        let m = config_err(text);
        assert!(m.contains("kubeconfig") && m.contains("line "), "{m}");
    }

    /// FR-2, FR-37: an unknown field in the Fly section reports line, column and the field;
    /// never the line itself (C1, SR-1).
    #[test]
    fn fly_section_unknown_field_points_at_the_field() {
        let bad = "[profile]\nkind = \"fleet\"\n[environments.prod]\nvault_id = \"v\"\n\
                   item_id = \"i\"\nfly.app = \"a\"\nfly.secret_name = \"F__{PRODUCT}__{KEY}\"\n\
                   fly.region = \"ams\"\n";
        assert_eq!(
            config_err(bad),
            "invalid secrets.toml: TOML parse error at line 8, column 5\nunknown field `region`, \
             expected `app` or `secret_name`"
        );
    }

    /// FR-28 through the registry: one provider section per environment.
    #[test]
    fn two_provider_sections_are_refused() {
        let two = mutate(
            "fly.app = \"mcproductlabs-portfolio-production\"",
            "azure.key_vault = \"kv\"\nfly.app = \"mcproductlabs-portfolio-production\"",
        );
        assert!(
            config_err(&two)
                .ends_with("\nenvironment prod: declares both fly and azure; use one target\n")
        );
    }

    /// FR-37: moving Fly behind the provider contract keeps every Fly message byte for byte.
    #[test]
    fn fly_config_errors_are_unchanged() {
        let dev = |fly: &str| {
            format!(
                "{}\n[environments.dev]\nvault_id = \"vdev\"\nitem_id = \"idev\"\n{fly}",
                ok()
            )
        };
        let cases = [
            mutate(
                "FLEET__{PRODUCT}__{KEY}\"\nmodes.allumata.payments = \"off\"",
                "FLEET_STATIC\"\nmodes.allumata.payments = \"off\"",
            ),
            mutate("\"mcproductlabs-portfolio-production\"", "\"-prod\""),
            mutate("\"mcproductlabs-portfolio-production\"", "\" prod\""),
            mutate("\"mcproductlabs-portfolio-production\"", "\"\""),
            dev(
                "fly.app = \"mcproductlabs-portfolio-production\"\nfly.secret_name = \"FLEET__{PRODUCT}__{KEY}\"\n",
            ),
            mutate(
                "FLEET__{PRODUCT}__{KEY}\"\nmodes.allumata.payments = \"off\"",
                "fleet__{PRODUCT}__{KEY}\"\nmodes.allumata.payments = \"off\"",
            ),
            format!(
                "{}\n[products.my_app.keys.K]\nkind = \"secret\"\nenvironments = [\"prod\"]\n",
                with_key("my-app", "K", "[\"prod\"]")
            ),
        ];
        let got: Vec<String> = cases.iter().map(|c| config_err(c)).collect();
        assert_eq!(
            got,
            [
                "environment prod: fly.secret_name \"FLEET_STATIC\" must contain {PRODUCT} and {KEY}",
                "environment prod: fly.app \"-prod\" must match ^[A-Za-z0-9][A-Za-z0-9._-]*$",
                "environment prod: fly.app has leading or trailing whitespace",
                "environment prod: fly.app is empty",
                "environments dev and prod both use Fly app \"mcproductlabs-portfolio-production\" with fly.secret_name \"FLEET__{PRODUCT}__{KEY}\"",
                "environment prod: allumata/INTEGRATION_ENC_KEY renders Fly name \"fleet__ALLUMATA__INTEGRATION_ENC_KEY\", which must match ^[A-Z][A-Z0-9_]*$",
                "environment prod: my-app/K and my_app/K both render Fly name FLEET__MY_APP__K",
            ]
        );
    }

    // ---- shared keys (FR-45) ----------------------------------------------------------

    /// The fixture plus `api/DATABASE_URL` (secret, staging and prod) and a worker key
    /// whose table body is `worker`.
    fn shared(worker: &str) -> String {
        format!(
            "{}\n[products.api.keys.DATABASE_URL]\nkind = \"secret\"\nenvironments = [\"staging\", \"prod\"]\n\n[products.worker.keys.DATABASE_URL]\n{worker}\n",
            ok()
        )
    }

    #[test]
    fn shared_key_loads_with_its_source() {
        let f = parse(&shared(
            "kind = \"secret\"\nfrom = \"api/DATABASE_URL\"\nenvironments = [\"prod\"]",
        ))
        .unwrap();
        assert_eq!(
            f.products["worker"].keys["DATABASE_URL"].source(),
            Some(("api", "DATABASE_URL"))
        );
    }

    #[test]
    fn shared_key_refuses_an_undeclared_source() {
        let e = config_err(&shared(
            "kind = \"secret\"\nfrom = \"api/DB_URL\"\nenvironments = [\"prod\"]",
        ));
        assert!(
            e.contains("worker/DATABASE_URL: from = \"api/DB_URL\": names no declared key"),
            "{e}"
        );
    }

    #[test]
    fn shared_key_error_points_at_the_from_line() {
        let e = config_err(&shared(
            "kind = \"secret\"\nfrom = \"api/DB_URL\"\nenvironments = [\"prod\"]",
        ));
        assert!(e.contains("at line 49, column 1"), "{e}");
    }

    #[test]
    fn shared_key_refuses_a_source_of_another_kind() {
        let e = config_err(&shared(
            "kind = \"config\"\nfrom = \"api/DATABASE_URL\"\nenvironments = [\"prod\"]",
        ));
        assert!(
            e.contains("api/DATABASE_URL is a secret key, worker/DATABASE_URL a config key"),
            "{e}"
        );
    }

    #[test]
    fn shared_key_refuses_a_chain() {
        let text = format!(
            "{}\n[products.jobs.keys.DATABASE_URL]\nkind = \"secret\"\nfrom = \"worker/DATABASE_URL\"\nenvironments = [\"prod\"]\n",
            shared("kind = \"secret\"\nfrom = \"api/DATABASE_URL\"\nenvironments = [\"prod\"]")
        );
        let e = config_err(&text);
        assert!(e.contains("worker/DATABASE_URL is itself shared from api/DATABASE_URL (no chains); write from = \"api/DATABASE_URL\""), "{e}");
    }

    #[test]
    fn shared_key_refuses_a_cycle() {
        let text = format!(
            "{}\n[products.a.keys.K]\nkind = \"secret\"\nfrom = \"b/K\"\nenvironments = [\"prod\"]\n\n[products.b.keys.K]\nkind = \"secret\"\nfrom = \"a/K\"\nenvironments = [\"prod\"]\n",
            ok()
        );
        let e = config_err(&text);
        assert!(e.contains("(cycle)"), "{e}");
    }

    #[test]
    fn shared_key_refuses_its_own_name() {
        let e = config_err(&shared(
            "kind = \"secret\"\nfrom = \"worker/DATABASE_URL\"\nenvironments = [\"prod\"]",
        ));
        assert!(e.contains("cannot share its own value (cycle)"), "{e}");
    }

    #[test]
    fn shared_key_refuses_an_environment_its_source_lacks() {
        let text = format!(
            "{}\n[products.api.keys.DATABASE_URL]\nkind = \"secret\"\nenvironments = [\"prod\"]\n\n[products.worker.keys.DATABASE_URL]\nkind = \"secret\"\nfrom = \"api/DATABASE_URL\"\nenvironments = [\"staging\", \"prod\"]\n",
            ok()
        );
        let e = config_err(&text);
        assert!(e.contains("api/DATABASE_URL is not declared for environment \"staging\", which worker/DATABASE_URL uses"), "{e}");
    }

    #[test]
    fn shared_key_refuses_a_cross_item_reference() {
        let e = config_err(&shared(
            "kind = \"secret\"\nfrom = \"op://vprd/other/api/DATABASE_URL\"\nenvironments = [\"prod\"]",
        ));
        assert!(
            e.contains("cross-item and cross-environment references are not supported"),
            "{e}"
        );
    }

    #[test]
    fn shared_key_refuses_a_cross_environment_reference() {
        let e = config_err(&shared(
            "kind = \"secret\"\nfrom = \"staging/api/DATABASE_URL\"\nenvironments = [\"prod\"]",
        ));
        assert!(
            e.contains("cross-item and cross-environment references are not supported"),
            "{e}"
        );
    }

    #[test]
    fn shared_key_refuses_its_own_immutable() {
        let e = config_err(&shared(
            "kind = \"secret\"\nfrom = \"api/DATABASE_URL\"\nimmutable = true\nenvironments = [\"prod\"]",
        ));
        assert!(
            e.contains("immutable follows the source of a shared key (api/DATABASE_URL)"),
            "{e}"
        );
    }

    #[test]
    fn shared_key_immutable_follows_its_source() {
        let text = format!(
            "{}\n[products.worker.keys.INTEGRATION_ENC_KEY]\nkind = \"secret\"\nfrom = \"allumata/INTEGRATION_ENC_KEY\"\nenvironments = [\"prod\"]\n",
            ok()
        );
        assert!(parse(&text).unwrap().products["worker"].keys["INTEGRATION_ENC_KEY"].immutable);
    }

    #[test]
    fn simple_shared_key_names_a_bare_key() {
        let text = format!(
            "{}\n[keys.PRISMA_URL]\nkind = \"secret\"\nfrom = \"DATABASE_URL\"\nenvironments = [\"prod\"]\n",
            simple()
        );
        assert_eq!(
            parse(&text).unwrap().products[SIMPLE_PRODUCT].keys["PRISMA_URL"].source(),
            Some((SIMPLE_PRODUCT, "DATABASE_URL"))
        );
    }

    /// FR-24, FR-60: the removal error's suggested `regex` rule pastes into the file as is
    /// and loads.
    #[test]
    fn the_suggested_regex_replacement_loads() {
        let head = "[profile]\nkind = \"simple\"\n[environments.prod]\nvault_id = \"v\"\n\
                    item_id = \"i\"\nfly.app = \"app\"\n[keys.K1]\nkind = \"secret\"\n\
                    environments = [\"prod\"]\n";
        let m = config_err(&format!(
            "{head}rules = {{ ensure_prefix = \"p-\", pattern = \"[a-z]+\" }}\n"
        ));
        let (_, rule) = m.split_once("use regex = ").unwrap();
        let rule = rule.trim_end().strip_suffix(" instead").unwrap();
        let text = format!("{head}rules = {{ ensure_prefix = \"p-\", regex = {rule} }}\n");
        assert!(parse(&text).is_ok(), "{text}");
    }

    // ---- personal keys and environment display fields (FR-55) ----------------------

    fn team(extra: &str) -> String {
        format!(
            "[profile]\nkind = \"fleet\"\n[environments.dev]\nvault_id = \"vdev\"\nitem_id = \"idev\"\n\
             title = \"Local development\"\n\
             [environments.prod]\nvault_id = \"vprd\"\nitem_id = \"iprd\"\naudience = \"devops\"\n\
             fly.app = \"a\"\nfly.secret_name = \"FLEET__{{PRODUCT}}__{{KEY}}\"\n{extra}"
        )
    }

    #[test]
    fn a_personal_key_in_a_local_environment_loads() {
        let text = team(
            "[products.api.keys.OPENAI_API_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\npersonal = true\n",
        );
        assert!(parse(&text).is_ok());
    }

    #[test]
    fn a_personal_key_is_never_deployed() {
        let text = team(
            "[products.api.keys.OPENAI_API_KEY]\nkind = \"secret\"\nenvironments = [\"dev\", \"prod\"]\npersonal = true\n",
        );
        assert!(config_err(&text).contains(
            "personal = true is for local environments only, and prod has a deployment target"
        ));
    }

    #[test]
    fn products_share_a_personal_value_through_a_personal_source() {
        let text = team(
            "[products.shared]\nsource_only = true\n\
             [products.shared.keys.OPENAI_API_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\npersonal = true\n\
             [products.api.keys.OPENAI_API_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\npersonal = true\nfrom = \"shared/OPENAI_API_KEY\"\n",
        );
        assert!(parse(&text).is_ok());
    }

    #[test]
    fn a_team_key_cannot_read_a_personal_value() {
        let text = team(
            "[products.shared]\nsource_only = true\n\
             [products.shared.keys.OPENAI_API_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\npersonal = true\n\
             [products.api.keys.OPENAI_API_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\nfrom = \"shared/OPENAI_API_KEY\"\n",
        );
        assert!(config_err(&text).contains("a team key cannot read a personal value"));
    }

    #[test]
    fn an_environment_keeps_its_display_name() {
        let f = parse(&team("")).unwrap();
        assert_eq!(f.environments["dev"].display(), "Local development");
    }

    #[test]
    fn an_environment_keeps_its_audience() {
        let f = parse(&team("")).unwrap();
        assert_eq!(f.environments["prod"].audience.as_deref(), Some("devops"));
    }

    // ---- source-only products (FR-47) ------------------------------------------------

    /// A source-only product whose one key renders the same Fly name as a delivered key of
    /// another product: `my-app` and `my_app` both normalize to `MY_APP` (FR-8).
    fn shared_name_fleet(source_only: bool) -> String {
        format!(
            "[profile]\nkind = \"fleet\"\n\
             [environments.ci]\nvault_id = \"vci\"\nitem_id = \"ici\"\n\
             fly.app = \"app\"\nfly.secret_name = \"FLEET__{{PRODUCT}}__{{KEY}}\"\n\
             [products.my_app]\nsource_only = {source_only}\n\
             [products.my_app.keys.K]\nkind = \"secret\"\nenvironments = [\"ci\"]\n\
             [products.my-app.keys.K]\nkind = \"secret\"\nenvironments = [\"ci\"]\n"
        )
    }

    #[test]
    fn source_only_product_is_exempt_from_the_name_collision_check() {
        let r = parse(&shared_name_fleet(true));
        assert!(r.is_ok(), "{:?}", r.err());
    }

    #[test]
    fn delivered_products_rendering_one_name_still_collide() {
        let m = config_err(&shared_name_fleet(false));
        assert!(m.contains("both render Fly name FLEET__MY_APP__K"), "{m}");
    }

    #[test]
    fn source_only_product_without_keys_is_refused_at_its_line() {
        let text = format!("{}\n[products.shared]\nsource_only = true\n", ok());
        let m = config_err(&text);
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
             [products.shared.keys.FLY_API_TOKEN]\nkind = \"secret\"\nenvironments = [\"ci\"]\n",
            ok()
        );
        let m = config_err(&text);
        assert!(
            m.contains("invalid type: string") && m.contains("TOML parse error at line"),
            "{m}"
        );
    }
}
