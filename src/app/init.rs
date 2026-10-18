//! The starter contract `opv propose setup --from-item` and `--names-from` propose (0.11.0's
//! `opv init`, removed in 0.12.0): built, never written here.
//!
//! [`plan_item`] resolves the vault and item titles to IDs once, through [`onepassword_init`]
//! (the only title lookup in opv; FR-13's dev-time exception), reads the item once keeping
//! field names, sections and types only (values are never deserialized, SR-1, SR-2), and
//! declares each named section as a product and unsectioned fields as the keys of the given
//! product; concealed fields become `secret`, text fields `config` (FR-14). The item is one
//! boundary (FR-57). The text is validated with the same loader as a hand-written one and its
//! ids are split out (D-G): only `opv apply` writes `secrets.bindings.toml`. [`read_from`]
//! reads a `.env`'s names for `--names-from`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use crate::adapters::onepassword_init::{self, FieldShape};
use crate::cause::{
    Cause, Closest, FieldRule, InputKind, NameKind, PatternId, StoreObject, UsageProblem,
};
use crate::config;
use crate::config_edit;
use crate::domain::Kind;
use crate::error::Error;
use crate::host::Host;
use crate::runner::CommandRunner;

/// The file `init` writes, in the directory it is given (the current directory).
pub const FILE_NAME: &str = "secrets.toml";

/// The boundary group of several products that share one item (FR-57).
pub const SHARED_BOUNDARY: &str = "core";

/// `opv init` arguments.
#[derive(Debug, Clone, Default)]
pub struct InitArgs {
    pub env: String,
    pub vault: String,
    pub item: String,
    /// `--product`: the product the item's unsectioned fields (and `--from`'s keys) belong
    /// to.
    pub product: Option<String>,
    pub force: bool,
    /// `--from`: declare every key of a dotenv file, and with `apply` import its values
    /// (#90).
    pub from: Option<FromFile>,
}

/// `opv init <env> --from <file.env> [--config KEY]... [--secret KEY]... [--apply]` (#90).
#[derive(Debug, Clone, Default)]
pub struct FromFile {
    pub path: std::path::PathBuf,
    /// Keys declared as config whatever their name suggests.
    pub config: Vec<String>,
    /// Keys declared as secret whatever their name suggests.
    pub secret: Vec<String>,
    /// Create, declare and import; without it nothing is written anywhere.
    pub apply: bool,
}

/// The keys of a `--from` file: names and kinds, and which are empty. Never a value.
#[derive(Debug, Clone, Default)]
pub struct Imported {
    /// Name to kind, for every valid key name in the file.
    pub kinds: BTreeMap<String, Kind>,
    /// Keys whose value is empty: declared, not imported.
    pub empty: Vec<String>,
    /// Names in the file that are not valid key names (^[A-Z][A-Z0-9_]*$): skipped.
    pub invalid: Vec<String>,
}

/// The boundary of the products one item holds (FR-57): the product itself when it is the
/// only one, else [`SHARED_BOUNDARY`]; `None` without a product.
pub(crate) fn item_boundary<'a>(mut products: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    let first = products.next()?;
    Some(if products.next().is_some() {
        SHARED_BOUNDARY
    } else {
        first
    })
}

/// Read `from`'s file (private, regular, under 1 MiB; never executed) and decide each
/// key's kind: `--config` / `--secret` first, else by name only
/// ([`crate::domain::kind_guess`]), secret by default. Values are read only to tell which
/// are empty, and dropped (zeroized) here.
pub fn read_from(from: &FromFile) -> Result<Imported, Error> {
    let found = super::setup::read_legacy(&from.path)?;
    if let Some(name) = from.config.iter().find(|n| from.secret.contains(n)) {
        return Err(usage(UsageProblem::ConflictsWith {
            a: format!("--config-key {name}"),
            b: format!("--secret-key {name}"),
        }));
    }
    for names in [&from.config, &from.secret] {
        if let Some(name) = names.iter().find(|n| !found.contains_key(n.as_str())) {
            // A key the file does not have: the one close name in the file, never a guess.
            let close = super::suggest::close(name, found.keys().map(String::as_str));
            return Err(Cause::NotDeclared {
                kind: NameKind::Key,
                given: name.clone(),
                candidates: found.keys().cloned().collect(),
                closest: Closest::unique(&close),
            }
            .into());
        }
    }
    let mut imported = Imported::default();
    for (name, value) in &found {
        if !config::is_env_name(name) {
            imported.invalid.push(name.clone());
            continue;
        }
        let kind = if from.config.contains(name) {
            Kind::Config
        } else if from.secret.contains(name) {
            Kind::Secret
        } else {
            crate::domain::kind_guess::kind_for_name(name)
        };
        imported.kinds.insert(name.clone(), kind);
        if value.expose().is_empty() {
            imported.empty.push(name.clone());
        }
    }
    if imported.kinds.is_empty() {
        return Err(Cause::InputInvalid {
            path: from.path.clone(),
            kind: InputKind::Dotenv,
            at: None,
            field: "the file".into(),
            rule: FieldRule::Type {
                expected: "at least one KEY=value line whose KEY is upper-case letters, digits \
                           and _",
            },
        }
        .into());
    }
    Ok(imported)
}

/// A usage error of `opv init`: its step is init's help.
fn usage(problem: UsageProblem) -> Error {
    Cause::Usage { problem }.into()
}

/// A configuration error in text opv generated: say so, and that nothing was written.
/// `base` is the file the proposal changes (`None` when opv proposes the whole file): a field
/// not in it came from the proposal (R2-4).
fn would_write(base: Option<&str>) -> impl Fn(Error) -> Error + '_ {
    move |e| proposal_invalid(e, base)
}

/// Whether the TOML `text` holds the field at `path`.
fn holds_field(text: &str, path: &[String]) -> bool {
    let Ok(doc) = text.parse::<toml::Table>() else {
        return false;
    };
    let mut at = Some(&doc);
    let (last, parents) = match path.split_last() {
        Some(split) => split,
        None => return false,
    };
    for part in parents {
        at = at.and_then(|t| t.get(part)).and_then(toml::Value::as_table);
    }
    at.is_some_and(|t| t.contains_key(last))
}

fn proposal_invalid(e: Error, base: Option<&str>) -> Error {
    // F2: an invalid field in the proposed text is `ConfigProposalInvalid` (nothing written).
    if let Some((
        crate::cause::Cause::ConfigInvalid {
            source,
            field,
            rule,
            ..
        },
        _,
    )) = e.cause()
    {
        return crate::cause::Cause::ConfigProposalInvalid {
            source: source.clone(),
            field: field.clone(),
            rule: rule.clone(),
            from_proposal: base.is_none_or(|text| !holds_field(text, &field.0)),
        }
        .into();
    }
    e
}

/// When a parent directory already holds a `secrets.toml` (the FR-25 discovery walk from
/// `dir`'s parent), a one-line note naming it: the new file takes precedence below `dir`.
/// Never a refusal.
pub fn ancestor_note(dir: &Path) -> Option<String> {
    let found = config::discover(dir.parent()?)?;
    Some(format!(
        "note: {} also exists; the new {FILE_NAME} takes precedence for commands run from {} \
         and below",
        found.display(),
        dir.display()
    ))
}

/// Arguments that need no 1Password call: the environment name (a bare TOML key), vault,
/// item and product.
fn check_args(args: &InitArgs) -> Result<(), Error> {
    let env_ok = args
        .env
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric())
        && args
            .env
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !env_ok {
        return Err(usage(UsageProblem::ValueFormat {
            flag: format!("the environment name {:?}", args.env),
            format: "letters, digits, _ and -, starting with a letter or digit",
        }));
    }
    for (flag, v) in [("--vault", &args.vault), ("--item", &args.item)] {
        if v.is_empty() {
            return Err(usage(UsageProblem::ValueFormat {
                flag: flag.into(),
                format: "a title that is not empty",
            }));
        }
    }
    if let Some(p) = args
        .product
        .as_deref()
        .filter(|p| !config::is_product_name(p))
    {
        return Err(usage(UsageProblem::ValueFormat {
            flag: format!("--product {p:?}"),
            format: PatternId::ProductName.words(),
        }));
    }
    Ok(())
}

/// The vault title `bootstrap` uses for an environment: `<project>-<env>`.
pub fn default_vault(project: &str, env: &str) -> String {
    format!("{project}-{env}")
}

/// The item title `bootstrap` uses for an environment: `<project> · <env> values`, so it
/// reads apart from the project's manifest (`opv · <project>`) in the same vault.
pub fn default_item(project: &str, env: &str) -> String {
    format!("{project} · {env} values")
}

/// The target appeared (a file, directory or symlink) while init was working and `--force`
/// was not given: nothing is written over it, and the re-run says what to do with it.
fn refuse_existing(target: &Path, force: bool) -> Result<(), Error> {
    if !force && fs::symlink_metadata(target).is_ok() {
        return Err(Cause::ChangedBeforeWrite {
            object: StoreObject::File {
                path: target.to_path_buf(),
            },
        }
        .into());
    }
    Ok(())
}

/// What the item declares: product → key → kind, plus the notes and the number of fields
/// not written.
#[derive(Debug)]
struct Declared {
    keys: BTreeMap<String, BTreeMap<String, Kind>>,
    notes: Vec<String>,
    skipped: usize,
}

impl Declared {
    /// The item's boundary (FR-57); `None` while it declares no key.
    fn boundary(&self) -> Option<&str> {
        item_boundary(self.keys.keys().map(String::as_str))
    }
}

/// Turn fields into declared keys: a section is a product, unsectioned fields belong to
/// `product`. Names, sections and types only.
fn declare(
    fields: &[FieldShape],
    product: Option<&str>,
    vault_title: &str,
    item_title: &str,
) -> Result<Declared, Error> {
    let (sectioned, unsectioned): (Vec<&FieldShape>, Vec<&FieldShape>) =
        fields.iter().partition(|f| f.section.is_some());
    if !sectioned.is_empty() && !unsectioned.is_empty() {
        // init never guesses which product unsectioned fields belong to.
        return Err(usage(UsageProblem::NeedsFlag {
            flag: format!(
                "item {item_title:?}, with {} and {},",
                super::plural(unsectioned.len(), "unsectioned field", "unsectioned fields"),
                super::plural(sectioned.len(), "sectioned field", "sectioned fields")
            ),
            needs: "every field in a section named after its product: move the unsectioned \
                    ones in 1Password"
                .into(),
        }));
    }
    let unsectioned_product = match (unsectioned.is_empty(), product) {
        (true, _) => "",
        (false, Some(p)) => p,
        (false, None) => {
            // 05.07: --product alone changes init's default vault and item titles, so the
            // advice keeps this vault and item (X1).
            let names: Vec<String> = unsectioned.iter().map(|f| display_name(f)).collect();
            return Err(usage(UsageProblem::NeedsFlag {
                flag: format!(
                    "item {item_title:?}, with {} ({}),",
                    super::plural(names.len(), "unsectioned field", "unsectioned fields"),
                    names.join(", ")
                ),
                needs: format!(
                    "the product they belong to: pass --product <name> (the app's role, such \
                     as api or web) together with --vault {} --item {}, so init reads this \
                     same item",
                    crate::error::shell_word(vault_title),
                    crate::error::shell_word(item_title)
                ),
            }));
        }
    };
    let mut d = Declared {
        keys: BTreeMap::new(),
        notes: Vec::new(),
        skipped: 0,
    };
    let mut bad_products: BTreeMap<&str, usize> = BTreeMap::new();
    for f in fields {
        let product = f.section.as_deref().unwrap_or(unsectioned_product);
        if f.section.is_some() && !config::is_product_name(product) {
            *bad_products.entry(product).or_default() += 1;
            d.skipped += 1;
            if reader_rejects(f).is_some() {
                d.notes.push(skip_note(f, Some("its section is skipped")));
            }
            continue;
        }
        let kind = match f.ty.as_str() {
            "CONCEALED" => Some(Kind::Secret),
            "STRING" => Some(Kind::Config),
            _ => None,
        };
        if !config::is_env_name(&f.label) {
            d.notes.push(skip_note(
                f,
                Some(
                    "not a valid key name (^[A-Z][A-Z0-9_]*$); rename the field in 1Password \
                     to manage it",
                ),
            ));
            d.skipped += 1;
            continue;
        }
        let Some(kind) = kind else {
            d.notes.push(skip_note(f, None));
            d.skipped += 1;
            continue;
        };
        // A label given twice is read tolerantly (FR-43): declared once, never an error.
        d.keys
            .entry(product.to_string())
            .or_default()
            .insert(f.label.clone(), kind);
    }
    for (product, n) in bad_products {
        d.notes.push(format!(
            "skipped section {product:?} ({}): not a valid product name \
             (^[a-z][a-z0-9_-]*$); rename the section in 1Password to manage it",
            super::plural(n, "field", "fields")
        ));
    }
    Ok(d)
}

/// The tail of every note on a field the later reader rejects.
const REJECTED: &str = "status and sync will reject it until it is fixed in 1Password";

/// Why `status` / `sync` (the item reader) would reject this field, if they would, once it
/// is in its product's section (the tidy moves an unsectioned one there, FR-43); a
/// duplicate label is read tolerantly. Mirrors `onepassword::parse_fields`.
fn reader_rejects(f: &FieldShape) -> Option<String> {
    if f.section.is_some() && f.label.is_empty() {
        return Some("it has no label".into());
    }
    (!matches!(f.ty.as_str(), "CONCEALED" | "STRING")).then(|| {
        format!(
            "field type {:?} is neither concealed (secret) nor text (config)",
            f.ty
        )
    })
}

/// `skipped <name>: <why>[; <reader reason>; <REJECTED>]`. Names only.
fn skip_note(f: &FieldShape, why: Option<&str>) -> String {
    let mut parts: Vec<String> = why.map(str::to_string).into_iter().collect();
    if let Some(reason) = reader_rejects(f) {
        parts.push(reason);
        parts.push(REJECTED.to_string());
    }
    format!("skipped {}: {}", display_name(f), parts.join("; "))
}

/// `"section"/"label"` or `"label"`, quoted and escaped. A name, never a value.
fn display_name(f: &FieldShape) -> String {
    match &f.section {
        Some(s) => format!("{s:?}/{:?}", f.label),
        None => format!("{:?}", f.label),
    }
}

fn kind_word(k: Kind) -> &'static str {
    match k {
        Kind::Secret => "secret",
        Kind::Config => "config",
    }
}

/// A TOML basic string.
fn quoted(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

/// `[environments.<env>]` with the item's boundary, if it has one.
fn env_table(env: &str, boundary: Option<&str>, (vault_id, item_id): (&str, &str)) -> String {
    let mut s = format!("[environments.{env}]\n");
    if let Some(b) = boundary {
        let _ = writeln!(
            s,
            "boundaries.{b} = {{ vault_id = {}, item_id = {} }}",
            quoted(vault_id),
            quoted(item_id)
        );
    }
    s
}

/// The file text: one environment with the item's boundary, then each product (with
/// `boundary = "core"` when several share the item) and one table per key with its kind
/// and `environments = [<env>]`. Keys and products are validated names (bare TOML keys).
fn render(args: &InitArgs, ids: (&str, &str), d: &Declared) -> String {
    let env = &args.env;
    let mut s = String::new();
    s.push_str(
        "# Written by opv propose setup: key names and kinds only; values stay in 1Password.\n\
         # Propose keys with opv propose key, environments with opv propose env, targets with \
         opv propose target; rules and guidance by hand.\n\n",
    );
    s.push_str(&env_table(env, d.boundary(), ids));
    let shared = d.keys.len() > 1;
    for (product, keys) in &d.keys {
        if shared {
            let _ = writeln!(
                s,
                "\n[products.{product}]\nboundary = {}",
                quoted(SHARED_BOUNDARY)
            );
        }
        for (key, kind) in keys {
            let _ = writeln!(
                s,
                "\n[products.{product}.keys.{key}]\nkind = \"{}\"\nenvironments = [{}]",
                kind_word(*kind),
                quoted(env)
            );
        }
    }
    s
}

/// Write `text` to `target` atomically; without `force`, an existing target is refused
/// again just before the rename (it may have appeared during the 1Password calls).
pub(crate) fn write_atomic(target: &Path, text: &str, force: bool) -> Result<(), Error> {
    config_edit::write_atomic(target, text, || refuse_existing(target, force))
}

/// Write the configuration `text` to `target` as [`write_atomic`] does, with its ids moved
/// to the sibling `secrets.bindings.toml` (D-G), so what opv writes loads again. The
/// contract is written first: a refused write leaves the bindings as they were.
pub(crate) fn write_config(target: &Path, text: &str, force: bool) -> Result<(), Error> {
    let (contract, ids) = crate::config::bindings::split(text);
    write_atomic(target, &contract, force)?;
    crate::config::bindings::write_sibling(target, &ids)
}

/// A contract `opv init` would write, with the 1Password ids taken out of it (D-G) and the
/// structure an apply creates first, by name. Built read-only: nothing is created.
pub(crate) struct ItemSetup {
    /// The proposed `secrets.toml` text, carrying no id.
    pub contract: String,
    /// What an apply creates first: the boundary, the item and each field, by name.
    pub steps: Vec<String>,
    /// The existing item's ids, for `secrets.bindings.toml` (names of vaults and items,
    /// never a value).
    pub bindings: crate::config::bindings::Bindings,
}

/// Build (never write) the contract `opv init <env> --vault <title> --item <title>` would
/// write for an item that exists, with the ids split out of the contract (D-G). Reads at
/// most the three dev-time calls `init` reads; a missing vault or item is an error, never a
/// create (that is the person-only apply step).
pub(crate) fn plan_item(
    r: &dyn CommandRunner,
    env: &str,
    vault_title: &str,
    item_title: &str,
    product: Option<&str>,
) -> Result<ItemSetup, Error> {
    let args = InitArgs {
        env: env.to_string(),
        vault: vault_title.to_string(),
        item: item_title.to_string(),
        product: product.map(str::to_string),
        ..InitArgs::default()
    };
    check_args(&args)?;
    let vault = onepassword_init::find_vault(r, vault_title, &Host::detect)?.found()?;
    let item = onepassword_init::find_item(r, &vault.id, item_title, &Host::detect)?.found()?;
    let fields = onepassword_init::read_field_shapes(r, &vault.id, &item.id, &Host::detect)?;
    let decl = declare(&fields, product, vault_title, item_title)?;
    let text = render(&args, (vault.id.as_str(), item.id.as_str()), &decl);
    // Validated exactly like the file init writes; its ids are then moved out of the
    // contract, which loads again once `secrets.bindings.toml` supplies them (D-G).
    config::parse(&text).map_err(would_write(None))?;
    let (contract, bindings) = crate::config::bindings::split(&text);
    Ok(ItemSetup {
        contract,
        steps: setup_steps(&decl),
        bindings,
    })
}

/// The structure a setup proposal creates, by name: the boundary, the item and each field.
fn setup_steps(d: &Declared) -> Vec<String> {
    let mut steps = Vec::new();
    if let Some(boundary) = d.boundary() {
        steps.push(format!("boundary {boundary}"));
        steps.push(format!("item {boundary}"));
    }
    for (product, keys) in &d.keys {
        for (key, kind) in keys {
            steps.push(format!("field {product}/{key} {}", kind_word(*kind)));
        }
    }
    steps
}

#[cfg(test)]
#[path = "init_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "init_from_tests.rs"]
mod from_tests;
