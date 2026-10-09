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
use crate::domain::{Environment, Fleet, KeySpec, Product, Profile, SIMPLE_PRODUCT, key_label};
use crate::error::Error;
use crate::provider::{Section, TargetConfig};

/// Read and validate the configuration at `path`.
pub fn load(path: impl AsRef<Path>) -> Result<Fleet, Error> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path)
        .map_err(|e| Error::Config(format!("cannot read {}: {e}", path.display())))?;
    parse(&text)
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

/// Parse and validate configuration text.
///
/// `profile.kind = "simple"` selects the simple profile (FR-20). Anything else, including a
/// file that does not parse, takes the fleet path exactly as in v0.1, which reports any
/// other kind as a configuration error.
pub fn parse(text: &str) -> Result<Fleet, Error> {
    let invalid = |e| Error::Config(format!("invalid secrets.toml: {e}"));
    if peek_kind(text).as_deref() == Some("simple") {
        let raw: RawSimpleConfig = toml::from_str(text).map_err(invalid)?;
        let doc = Doc::parse(text).map_err(invalid)?;
        return validate_simple(raw, &doc);
    }
    let raw: RawConfig = toml::from_str(text).map_err(invalid)?;
    let doc = Doc::parse(text).map_err(invalid)?;
    validate(raw, &doc)
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
        let (_, envs) = self
            .root
            .get_ref()
            .iter()
            .find(|(n, _)| n.get_ref().as_ref() == "environments")?;
        envs.get_ref().get(env)?.get_ref().get(key)
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
        let span = self
            .root
            .get_ref()
            .iter()
            .find(|(n, _)| n.get_ref().as_ref() == "environments")
            .and_then(|(_, envs)| envs.get_ref().as_table())
            .and_then(|t| t.iter().find(|(n, _)| n.get_ref().as_ref() == env))
            .and_then(|(_, e)| e.get_ref().as_table())
            .and_then(|t| t.iter().find(|(n, _)| n.get_ref().as_ref() == key))
            .map(|(n, _)| n.span());
        match span {
            Some(span) => cfg(format!(
                "invalid secrets.toml: {}",
                located(self.text, span, &msg)
            )),
            None => cfg(msg),
        }
    }
}

/// `msg` under the source line holding `span`, in the TOML parser's error layout.
fn located(text: &str, span: std::ops::Range<usize>, msg: &str) -> String {
    let before = &text[..span.start];
    let line = before.matches('\n').count();
    let column = before.len() - before.rfind('\n').map_or(0, |i| i + 1);
    let content = text.split('\n').nth(line).unwrap_or("");
    let num = (line + 1).to_string();
    let pad = " ".repeat(num.len() + 1);
    let width = span.len().min(content.len().saturating_sub(column)).max(1);
    format!(
        "TOML parse error at line {num}, column {}\n{pad}|\n{num} | {content}\n{pad}|{}{}\n{msg}\n",
        column + 1,
        " ".repeat(column + 1),
        "^".repeat(width)
    )
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
    /// Optional: environments used only for `run`, `config export` and `item skeleton`
    /// need no target. At most one entry (FR-28).
    #[serde(flatten)]
    sections: BTreeMap<String, toml::Value>,
}

fn cfg(msg: String) -> Error {
    Error::Config(msg)
}

/// The environment's target section, parsed by its provider (FR-28, FR-37): an unknown
/// section names the registered ones; two sections are refused.
fn target_of(
    name: &str,
    sections: &BTreeMap<String, toml::Value>,
    profile: Profile,
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
                 modes or a target section ({known})"
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
            let value = doc.entry(name, p.section()).ok_or_else(|| {
                cfg(format!(
                    "environment {name}: {} section not found",
                    p.section()
                ))
            })?;
            p.parse(&Section::new(name, value, doc.text), profile)
                .map(Some)
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
    doc: &Doc<'_>,
) -> Result<(Environment, M), Error> {
    check_ids(name, &e.vault_id, &e.item_id)?;
    let target = target_of(name, &e.sections, profile, doc)?;
    Ok((
        Environment {
            vault_id: e.vault_id,
            item_id: e.item_id,
            target,
            modes: BTreeMap::new(),
        },
        e.modes,
    ))
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

    let mut environments = BTreeMap::new();
    for (name, e) in raw.environments {
        let (mut env, modes) = environment(&name, e, Profile::Fleet, doc)?;
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
        for (key, spec) in &p.keys {
            validate_key(&format!("{product}/{key}"), key, spec, &environments)?;
        }
    }

    let fleet = Fleet {
        environments,
        products: raw.products,
        profile: Profile::Fleet,
    };
    check_names(&fleet, doc)?;
    Ok(fleet)
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

    let mut environments = BTreeMap::new();
    for (name, e) in raw.environments {
        let (mut env, modes) = environment(&name, e, Profile::Simple, doc)?;
        if !modes.is_empty() {
            env.modes = BTreeMap::from([(SIMPLE_PRODUCT.to_string(), modes)]);
        }
        environments.insert(name, env);
    }
    check_shared_targets(&environments)?;

    for (key, spec) in &raw.keys {
        validate_key(key, key, spec, &environments)?;
    }

    let fleet = Fleet {
        environments,
        products: BTreeMap::from([(SIMPLE_PRODUCT.to_string(), Product { keys: raw.keys })]),
        profile: Profile::Simple,
    };
    check_names(&fleet, doc)?;
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
    if spec.rules.pattern.is_some() && spec.rules.ensure_prefix.is_none() {
        return Err(cfg(format!("{owner}: rule pattern requires ensure_prefix")));
    }
    if let Some(re) = &spec.rules.pattern {
        regex::Regex::new(re)
            .map_err(|e| cfg(format!("{owner}: rule pattern does not compile: {e}")))?;
    }
    if spec.rules.transform.as_deref() == Some("signoz_ingestion_header") {
        return Err(cfg(format!(
            "{owner}: transform = \"signoz_ingestion_header\" was removed in 0.4.0; \
             use ensure_prefix = \"{SIGNOZ_PREFIX}\" with pattern = \"{SIGNOZ_BODY}\""
        )));
    }
    Ok(())
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
    for (env_name, env) in &fleet.environments {
        let Some(t) = env.target() else {
            continue;
        };
        let rules = t.name_rules();
        let mut seen: BTreeMap<String, String> = BTreeMap::new();
        for (product, p) in &fleet.products {
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
                        let store = t.store_name(&name);
                        if store.is_empty()
                            || store.len() > s.max_len
                            || !store.chars().all(s.allowed)
                        {
                            return Err(cfg(format!(
                                "environment {env_name}: {owner} renders {} of {} characters, which must match {}",
                                s.label,
                                store.len(),
                                s.pattern
                            )));
                        }
                        // The first and last characters, e.g. a key ending in `_` renders a
                        // Kubernetes name ending in `-`: refused here, never at sync.
                        let edges = [store.chars().next(), store.chars().last()];
                        if !edges.into_iter().flatten().all(s.edge) {
                            return Err(doc.key_at(
                                product,
                                key,
                                format!(
                                    "environment {env_name}: {owner} renders {} {store:?}, which \
                                     must start and end with a letter or digit ({})",
                                    s.label, s.pattern
                                ),
                            ));
                        }
                        if s.case_insensitive {
                            store.to_ascii_lowercase()
                        } else {
                            store
                        }
                    }
                };
                if let Some(prev) = seen.insert(id.clone(), owner.clone()) {
                    return Err(cfg(match &rules.store {
                        None => format!(
                            "environment {env_name}: {prev} and {owner} both render {} {id}",
                            rules.env_label
                        ),
                        Some(s) => format!(
                            "environment {env_name}: {prev} and {owner} both map to {} {id}",
                            s.label
                        ),
                    }));
                }
            }
        }
    }
    Ok(())
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
    fn loads_fleet_profile_and_builds_fly_names() {
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
            Err(Error::Config(m)) => m,
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

    #[test]
    fn parses_pattern_rule() {
        let fleet = parse(&format!(
            "{}{}",
            ok(),
            signoz_like_key("K1", "ensure_prefix = \"p-\", pattern = \"[a-z]+\"")
        ))
        .unwrap();
        assert_eq!(
            fleet.products["p"].keys["K1"].rules.pattern.as_deref(),
            Some("[a-z]+")
        );
    }

    #[test]
    fn rejects_pattern_without_ensure_prefix_naming_key() {
        let m = config_err(&format!(
            "{}{}",
            ok(),
            signoz_like_key("K1", "pattern = \"[a-z]+\"")
        ));
        assert!(m.contains("p/K1"), "{m}");
    }

    #[test]
    fn rejects_pattern_that_does_not_compile_naming_key() {
        let m = config_err(&format!(
            "{}{}",
            ok(),
            signoz_like_key("K1", "ensure_prefix = \"p-\", pattern = \"([a-z\"")
        ));
        assert!(m.contains("p/K1"), "{m}");
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
             ensure_prefix = \"signoz-ingestion-key=\" with pattern = \"[A-Za-z0-9._~+/-]+={0,2}\""
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
    fn rejects_fly_name_collision_from_product_normalization() {
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
    fn rejects_fly_name_collision_across_double_underscore() {
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
    fn rejects_fly_name_collision_even_across_environments() {
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
    fn rejects_fly_name_collision_with_key_declared_for_no_environment() {
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
    fn rejects_template_rendering_invalid_fly_names() {
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
    fn simple_fly_name_is_the_key_name() {
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
            Err(Error::Config(m)) if m.contains("configure fly.app") && !m.contains("secret_name")
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
            "\nenvironment prod: unknown target section \"flyy\"; known: azure, fly, kubernetes\n"
        ));
    }

    /// FR-2: an unknown entry under an environment shows its line, as the parser's own
    /// errors do.
    #[test]
    fn unknown_target_section_shows_its_line() {
        let bad = mutate(
            "fly.app = \"mcproductlabs-portfolio-production\"",
            "flyy.app = \"x\"\nfly.app = \"mcproductlabs-portfolio-production\"",
        );
        assert!(config_err(&bad).contains(" | flyy.app = \"x\"\n"));
    }

    /// A plain value is a mistyped field, not a target section.
    #[test]
    fn unknown_environment_field_names_the_expected_fields() {
        let bad = mutate(
            "fly.app = \"mcproductlabs-portfolio-production\"",
            "vault = \"x\"\nfly.app = \"mcproductlabs-portfolio-production\"",
        );
        assert!(config_err(&bad).ends_with(
            "\nenvironment prod: unknown field \"vault\"; expected vault_id, item_id, modes or a \
             target section (azure, fly, kubernetes)\n"
        ));
    }

    /// FR-2, FR-37: an unknown field in the Fly section reports line, column, the line and
    /// the field exactly as 0.4 did, before the section moved behind the provider contract.
    #[test]
    fn fly_section_unknown_field_points_at_the_field() {
        let bad = "[profile]\nkind = \"fleet\"\n[environments.prod]\nvault_id = \"v\"\n\
                   item_id = \"i\"\nfly.app = \"a\"\nfly.secret_name = \"F__{PRODUCT}__{KEY}\"\n\
                   fly.region = \"ams\"\n";
        assert_eq!(
            config_err(bad),
            "invalid secrets.toml: TOML parse error at line 8, column 5\n  |\n8 | fly.region = \
             \"ams\"\n  |     ^^^^^^\nunknown field `region`, expected `app` or `secret_name`\n"
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
}
