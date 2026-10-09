//! `init <env> --vault <name> --item <name> [--target <provider> …]` use case (FR-23, H3)
//! and `init <env> … --add-env` (H2).
//!
//! A dev-time helper that writes a starter `secrets.toml` in the given directory:
//!
//! 1. Refuse before any call when the file exists and `--force` is not given (exit 2).
//! 2. Resolve the vault and item titles to IDs, once, through
//!    [`onepassword_init`] (the only title lookup in opv; FR-13's dev-time exception).
//! 3. Read the item once, keeping field names, sections and types only. Values are never
//!    deserialized (SR-1, SR-2).
//! 4. Detect the profile: unsectioned fields only is simple (FR-20), sectioned fields only
//!    is fleet (section = product); a mix fails naming both shapes unless `--profile` is
//!    given. Concealed fields become `secret`, text fields `config` (FR-14); other types and
//!    labels that are not valid key names are skipped with a note naming the field.
//! 5. Render the file, validate it with the same loader as a hand-written one (§10.2), and
//!    write it atomically (a temporary file in the same directory, then a rename). The file
//!    holds IDs, names and kinds only, never a value (SR-4).
//!
//! The target section comes from the provider through the plug-in contract
//! ([`Provider::init_fields`], [`Provider::init_section`]): `--target <section>` and the
//! options `--<section>-<field>`. Nothing is looked up; the section is validated by the
//! loader before any 1Password call. `--fly-app` is the Fly provider's `app` option.
//!
//! `--add-env` adds one `[environments.<env>]` to an existing file instead (edited in
//! place, comments kept, [`crate::config_edit`]), and adds the environment to every
//! declared key whose field the item has. It refuses an environment that already exists.
//!
//! Read-only against 1Password (FR-11, SR-5): the only write in opv stays `item skeleton`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::io::Write;
use std::path::Path;

use super::write_err;
use crate::adapters::onepassword_init::{self, FieldShape};
use crate::adapters::registry;
use crate::config;
use crate::config_edit::{self, ConfigDoc};
use crate::domain::{Kind, Profile};
use crate::error::Error;
use crate::host::Host;
use crate::provider::{InitField, Provider, init_flag};
use crate::runner::CommandRunner;

/// The file `init` writes, in the directory it is given (the current directory).
pub const FILE_NAME: &str = "secrets.toml";

/// `opv init` arguments.
#[derive(Debug, Clone)]
pub struct InitArgs {
    pub env: String,
    pub vault: String,
    pub item: String,
    /// `--target`: the provider section. Without it, the provider whose options were given
    /// (none: a run-only environment).
    pub target: Option<String>,
    /// Provider options given, by option name without dashes (`fly-app` → value).
    pub fields: BTreeMap<String, String>,
    /// `--profile`: overrides detection.
    pub profile: Option<Profile>,
    pub force: bool,
}

/// `--profile` text to a profile (`simple` or `fleet`).
pub fn parse_profile(s: &str) -> Result<Profile, Error> {
    match s {
        "simple" => Ok(Profile::Simple),
        "fleet" => Ok(Profile::Fleet),
        other => Err(Error::Config(
            format!("--profile must be simple or fleet, got {other:?}").into(),
        )),
    }
}

/// Run `init`, writing `dir/secrets.toml`.
pub fn run(
    args: &InitArgs,
    dir: &Path,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    run_on(args, dir, r, out, &Host::detect)
}

fn run_on(
    args: &InitArgs,
    dir: &Path,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
    host: &dyn Fn() -> Host,
) -> Result<(), Error> {
    check_args(args)?;
    let choice = choose_target(args).map_err(init_help)?;
    probe_target(args, choice.as_ref(), args.profile).map_err(init_help)?;
    let target = dir.join(FILE_NAME);
    refuse_existing(&target, args.force)?;
    let p = prepare(args, choice, r, host)?;
    write_atomic(&target, &p.text, args.force)?;
    let ancestor = ancestor_note(dir);
    report(args, &p, &target.display().to_string(), ancestor, out)
}

/// `init` for a new project with no `secrets.toml` (FR-44): the same declaration, saved as
/// a project manifest in the item's vault, tagged with the git remote. `--force` does not
/// overwrite a manifest; `opv config edit` changes one.
pub fn run_manifest(
    args: &InitArgs,
    project: Option<&str>,
    dir: &Path,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    check_args(args)?;
    let choice = choose_target(args).map_err(init_help)?;
    probe_target(args, choice.as_ref(), args.profile).map_err(init_help)?;
    let p = prepare(args, choice, r, &Host::detect)?;
    let repo = crate::config_store::git_repo(r);
    let project = crate::config_store::default_project(project, repo.as_deref(), dir)?;
    let m = crate::config_store::create_manifest(
        r,
        &p.vault.id,
        &project,
        repo.as_deref(),
        &[],
        &p.text,
        None,
    )?;
    use crate::config_store::ConfigStore as _;
    let note = match &repo {
        Some(repo) => format!("note: tagged for {repo}; any checkout of it finds this manifest"),
        None => format!(
            "note: no git remote origin; point a checkout at it with OPV_PROJECT={project} or \
             a .opv file holding project = \"{project}\""
        ),
    };
    report(args, &p, &m.describe(), Some(note), out)
}

/// What `init` declares, before it is written anywhere.
struct Prepared {
    vault: onepassword_init::Named,
    item: onepassword_init::Named,
    decl: Declared,
    text: String,
    /// The target section written, if any.
    choice: Option<TargetChoice>,
}

/// Resolve, read field shapes, declare, render and validate (steps 2 to 5).
fn prepare(
    args: &InitArgs,
    choice: Option<TargetChoice>,
    r: &dyn CommandRunner,
    host: &dyn Fn() -> Host,
) -> Result<Prepared, Error> {
    let vault = onepassword_init::resolve_vault(r, &args.vault, host)?;
    let item = onepassword_init::resolve_item(r, &vault.id, &args.item, host)?;
    let fields = onepassword_init::read_field_shapes(r, &vault.id, &item.id, host)?;

    let decl = declare(&fields, args.profile, &args.item)?;
    let text = render(args, &vault.id, &item.id, choice.as_ref(), &decl);
    // Validated exactly like a hand-written file (§10.2): IDs, target, key and product names.
    config::parse(&text).map_err(|e| would_write(e, "init"))?;
    Ok(Prepared {
        vault,
        item,
        decl,
        text,
        choice,
    })
}

/// The lines after a successful `init`: IDs, notes, counts, `where_` it was written, then
/// the next step.
fn report(
    args: &InitArgs,
    p: &Prepared,
    where_: &str,
    extra: Option<String>,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let (vault, item, decl, choice) = (&p.vault, &p.item, &p.decl, &p.choice);
    let w = |out: &mut dyn Write, s: String| writeln!(out, "{s}").map_err(write_err);
    w(
        out,
        format!(
            "vault {:?} is {}, item {:?} is {}",
            vault.name, vault.id, item.name, item.id
        ),
    )?;
    for note in &decl.notes {
        w(out, format!("note: {note}"))?;
    }
    let (secrets, configs) = decl.counts();
    w(
        out,
        format!(
            "wrote {where_} ({} profile{}): {secrets} secret, {configs} config, skipped {}",
            profile_word(decl.profile),
            target_word(choice.as_ref()),
            decl.skipped
        ),
    )?;
    if let Some(note) = extra {
        w(out, note)?;
    }
    // A URL: the rules reference moved to docs/configuration.md (review #16, #17).
    w(
        out,
        format!(
            "add keys with opv add, rules and guidance by hand; see \
             {}/configuration.md#rules-reference",
            crate::DOCS_URL
        ),
    )?;
    let products: Vec<&str> = decl.keys.keys().map(String::as_str).collect();
    w(
        out,
        format!(
            "Next: {}",
            next_command(&args.env, choice.is_some(), decl.profile, &products)
        ),
    )
}

/// `opv plan <env>` with a target, else `opv check <env>` naming the one product (or a
/// placeholder) under the fleet profile (review #16).
fn next_command(env: &str, has_target: bool, profile: Profile, products: &[&str]) -> String {
    if has_target {
        return format!("opv plan {env}");
    }
    let product = match (profile, products) {
        (Profile::Fleet, [one]) => format!(" --product {one}"),
        (Profile::Fleet, _) => " --product <product>".to_string(),
        (Profile::Simple, _) => String::new(),
    };
    format!("opv check {env}{product}")
}

/// A configuration error in text opv generated: say so, and that nothing was written.
fn would_write(e: Error, command: &str) -> Error {
    match e {
        e @ Error::Config(_) => {
            e.map_text(|m| format!("{m} (in the file {command} would write; nothing written)"))
        }
        other => other,
    }
}

/// A refusal of the target options names `opv init --help` unless it names its own step.
fn init_help(e: Error) -> Error {
    e.or_next(|| "opv init --help".into())
}

/// The provider and option values `init` writes, chosen from `--target` and the options.
struct TargetChoice {
    provider: &'static dyn Provider,
    values: BTreeMap<&'static str, String>,
}

fn target_word(choice: Option<&TargetChoice>) -> String {
    choice.map_or_else(String::new, |c| {
        format!(", {} target", c.provider.section())
    })
}

/// The provider option `flag` (without dashes) names, if any.
fn find_field(flag: &str) -> Option<(&'static dyn Provider, &'static InitField)> {
    registry::PROVIDERS.iter().copied().find_map(|p| {
        p.init_fields()
            .iter()
            .find(|f| init_flag(p, f) == flag)
            .map(|f| (p, f))
    })
}

/// `--target` and the provider options to one provider and its values (H3), before any
/// call: an unknown target, options of two providers, an option of another provider than
/// `--target` and a missing required option are each refused naming the options.
fn choose_target(args: &InitArgs) -> Result<Option<TargetChoice>, Error> {
    let mut given = Vec::new();
    for (flag, value) in &args.fields {
        let (p, f) = find_field(flag)
            .ok_or_else(|| Error::Config(format!("unknown init option --{flag}").into()))?;
        given.push((p, f, flag.as_str(), value));
    }
    let section = match &args.target {
        Some(t) => t.clone(),
        None => {
            let mut sections: Vec<&str> = given.iter().map(|(p, ..)| p.section()).collect();
            sections.dedup();
            match sections.as_slice() {
                [] => return Ok(None),
                [one] => (*one).to_string(),
                many => {
                    return Err(Error::Config(
                        format!(
                            "init options for {} given; one environment has one target: pass \
                             --target with one of them",
                            many.join(" and ")
                        )
                        .into(),
                    ));
                }
            }
        }
    };
    let provider = registry::find(&section).ok_or_else(|| {
        Error::Config(
            format!(
                "--target {section:?} is not a provider; known: {}",
                registry::sections().join(", ")
            )
            .into(),
        )
    })?;
    if provider.init_fields().is_empty() {
        return Err(Error::Config(
            format!(
                "init cannot write a {} target yet; add [environments.{}.{section}] by hand \
                 (see {}/configuration.md)",
                provider.label(),
                args.env,
                crate::DOCS_URL
            )
            .into(),
        ));
    }
    let mut values = BTreeMap::new();
    for (p, f, flag, value) in given {
        if p.section() != section {
            return Err(Error::Config(
                format!(
                    "--{flag} is an option of --target {}, not {section}",
                    p.section()
                )
                .into(),
            ));
        }
        values.insert(f.field, value.clone());
    }
    let missing: Vec<String> = provider
        .init_fields()
        .iter()
        .filter(|f| f.required && !values.contains_key(f.field))
        .map(|f| format!("--{}", init_flag(provider, f)))
        .collect();
    if !missing.is_empty() {
        return Err(Error::Config(
            format!(
                "--target {section} needs {} (opv init --help lists every option)",
                missing.join(", ")
            )
            .into(),
        ));
    }
    Ok(Some(TargetChoice { provider, values }))
}

/// The provider section for `profile`.
fn target_section(choice: &TargetChoice, profile: Profile) -> String {
    choice
        .provider
        .init_section(&choice.values, profile)
        .unwrap_or_default()
}

/// Validate the target section before any 1Password call, with the loader: a file holding
/// only this environment, under `profile` or, when the profile is not known yet, under
/// either (the first error is reported when both fail).
fn probe_target(
    args: &InitArgs,
    choice: Option<&TargetChoice>,
    profile: Option<Profile>,
) -> Result<(), Error> {
    let Some(choice) = choice else {
        return Ok(());
    };
    let profiles = match profile {
        Some(p) => vec![p],
        None => vec![Profile::Simple, Profile::Fleet],
    };
    let mut first = None;
    for p in profiles {
        let text = format!(
            "[profile]\nkind = \"{}\"\n\n{}",
            profile_word(p),
            env_table(&args.env, "vault", "item", Some(&target_section(choice, p)))
        );
        match config::parse(&text) {
            Ok(_) => return Ok(()),
            Err(e) => {
                first.get_or_insert(e);
            }
        }
    }
    Err(first.map_or_else(
        || Error::Config("invalid target".into()),
        |e| match e {
            e @ Error::Config(_) => {
                e.map_text(|m| format!("{m} (from the --target options; nothing written)"))
            }
            other => other,
        },
    ))
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

/// Arguments that need no 1Password call: the environment name (a bare TOML key), vault
/// and item. The target options are checked by [`probe_target`].
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
        return Err(Error::Config(
            format!(
                "environment name {:?} must match ^[A-Za-z0-9][A-Za-z0-9_-]*$",
                args.env
            )
            .into(),
        ));
    }
    for (flag, v) in [("--vault", &args.vault), ("--item", &args.item)] {
        if v.is_empty() {
            return Err(Error::Config(format!("{flag} is empty").into()));
        }
    }
    Ok(())
}

/// The target exists (a file, directory or symlink) and `--force` was not given: exit 2,
/// naming the path. `init` never merges.
fn refuse_existing(target: &Path, force: bool) -> Result<(), Error> {
    if !force && fs::symlink_metadata(target).is_ok() {
        return Err(Error::Config(
            format!(
                "{} already exists; init never merges: pass --force to overwrite it",
                target.display()
            )
            .into(),
        ));
    }
    Ok(())
}

/// What the file declares: product → key → kind (product `""` under the simple profile),
/// plus the notes and the number of fields not written.
#[derive(Debug)]
struct Declared {
    profile: Profile,
    keys: BTreeMap<String, BTreeMap<String, Kind>>,
    notes: Vec<String>,
    skipped: usize,
}

impl Declared {
    fn counts(&self) -> (usize, usize) {
        let kinds = || self.keys.values().flat_map(BTreeMap::values);
        let secrets = kinds().filter(|k| **k == Kind::Secret).count();
        (secrets, kinds().count() - secrets)
    }
}

fn profile_word(p: Profile) -> &'static str {
    match p {
        Profile::Simple => "simple",
        Profile::Fleet => "fleet",
    }
}

/// Detect the profile and turn fields into declared keys. Names, sections and types only.
fn declare(
    fields: &[FieldShape],
    explicit: Option<Profile>,
    item_title: &str,
) -> Result<Declared, Error> {
    let (sectioned, unsectioned): (Vec<&FieldShape>, Vec<&FieldShape>) =
        fields.iter().partition(|f| f.section.is_some());
    let profile =
        match (explicit, sectioned.is_empty(), unsectioned.is_empty()) {
            (Some(p), _, _) => p,
            (None, true, _) => Profile::Simple,
            (None, false, true) => Profile::Fleet,
            (None, false, false) => {
                return Err(Error::Config(format!(
                "item {item_title:?} mixes {} unsectioned field(s) (the simple profile shape) \
                 and {} sectioned field(s) (the fleet profile shape); init never guesses: pass \
                 --profile simple or --profile fleet",
                unsectioned.len(),
                sectioned.len()
            ).into()));
            }
        };
    check_duplicates(fields, profile, item_title)?;
    let mut d = Declared {
        profile,
        keys: BTreeMap::new(),
        notes: Vec::new(),
        skipped: 0,
    };
    let (used, ignored, flag) = match profile {
        Profile::Simple => (unsectioned, sectioned, "simple"),
        Profile::Fleet => (sectioned, unsectioned, "fleet"),
    };
    d.skipped += ignored.len();
    // An ignored field the reader still rejects gets its own note; the rest are listed.
    let (rejected, quiet): (Vec<&FieldShape>, Vec<&FieldShape>) = ignored
        .into_iter()
        .partition(|f| reader_rejects(f, profile).is_some());
    if !quiet.is_empty() {
        let names: Vec<String> = quiet.iter().map(|f| display_name(f)).collect();
        let shape = match profile {
            Profile::Simple => "sectioned",
            Profile::Fleet => "unsectioned",
        };
        d.notes.push(format!(
            "ignored {} {shape} field(s) under --profile {flag}: {}",
            names.len(),
            names.join(", ")
        ));
    }
    for f in rejected {
        d.notes.push(skip_note(f, None, profile));
    }
    let mut bad_products: BTreeMap<&str, usize> = BTreeMap::new();
    for f in used {
        let product = f.section.as_deref().unwrap_or("");
        if profile == Profile::Fleet && !config::is_product_name(product) {
            *bad_products.entry(product).or_default() += 1;
            d.skipped += 1;
            if reader_rejects(f, profile).is_some() {
                d.notes
                    .push(skip_note(f, Some("its section is skipped"), profile));
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
                profile,
            ));
            d.skipped += 1;
            continue;
        }
        let Some(kind) = kind else {
            d.notes.push(skip_note(f, None, profile));
            d.skipped += 1;
            continue;
        };
        // Duplicates were rejected above, before any key was declared.
        d.keys
            .entry(product.to_string())
            .or_default()
            .insert(f.label.clone(), kind);
    }
    for (product, n) in bad_products {
        d.notes.push(format!(
            "skipped section {product:?} ({n} field(s)): not a valid product name \
             (^[a-z][a-z0-9_-]*$); rename the section in 1Password to manage it"
        ));
    }
    Ok(d)
}

/// The tail of every note on a field the later reader rejects.
const REJECTED: &str = "status and sync will reject it until it is fixed in 1Password";

/// Why `status` / `sync` (the item reader for `profile`) would reject this field, if
/// they would; duplicates are checked separately ([`check_duplicates`]). Mirrors
/// `onepassword::parse_fields` (fleet) and `parse_unsectioned_fields` (simple).
fn reader_rejects(f: &FieldShape, profile: Profile) -> Option<String> {
    let bad_type = !matches!(f.ty.as_str(), "CONCEALED" | "STRING");
    let type_msg = || {
        format!(
            "field type {:?} is neither concealed (secret) nor text (config)",
            f.ty
        )
    };
    match profile {
        Profile::Fleet if f.unlabelled_section => Some("it is in a section without a label".into()),
        Profile::Fleet if f.section.is_none() => None,
        Profile::Fleet if f.label.is_empty() => Some("it has no label".into()),
        Profile::Fleet if bad_type => Some(type_msg()),
        Profile::Fleet => None,
        Profile::Simple if f.section.is_none() && config::is_env_name(&f.label) && bad_type => {
            Some(type_msg())
        }
        Profile::Simple => None,
    }
}

/// `skipped <name>: <why>[; <reader reason>; <REJECTED>]`. Names only.
fn skip_note(f: &FieldShape, why: Option<&str>, profile: Profile) -> String {
    let mut parts: Vec<String> = why.map(str::to_string).into_iter().collect();
    if let Some(reason) = reader_rejects(f, profile) {
        parts.push(reason);
        parts.push(REJECTED.to_string());
    }
    format!("skipped {}: {}", display_name(f), parts.join("; "))
}

/// A label given twice where the reader for `profile` looks (every sectioned field under
/// fleet, every unsectioned key-named field under simple), whatever its type: the reader
/// rejects the item, so init writes nothing (`Source`, names only).
fn check_duplicates(
    fields: &[FieldShape],
    profile: Profile,
    item_title: &str,
) -> Result<(), Error> {
    let mut seen = std::collections::BTreeSet::new();
    for f in fields {
        let read = match profile {
            Profile::Fleet => f.section.is_some() && !f.label.is_empty(),
            Profile::Simple => f.section.is_none() && config::is_env_name(&f.label),
        };
        if read && !seen.insert((f.section.as_deref(), f.label.as_str())) {
            return Err(Error::Source(
                format!(
                    "duplicate field {} in item {item_title:?}; rename one in 1Password \
                 (nothing written)",
                    display_name(f)
                )
                .into(),
            ));
        }
    }
    Ok(())
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

/// `[environments.<env>]` with its IDs and the target section, if any.
fn env_table(env: &str, vault_id: &str, item_id: &str, section: Option<&str>) -> String {
    let mut s = format!(
        "[environments.{env}]\nvault_id = {}\nitem_id = {}\n",
        quoted(vault_id),
        quoted(item_id)
    );
    if let Some(section) = section {
        s.push_str(section);
    }
    s
}

/// The file text: profile, one environment with IDs and the target, one table per key with
/// its kind and `environments = [<env>]`. Mirrors `tests/fixtures/secrets.toml` and
/// `tests/fixtures/simple.toml`. Keys and products are validated names (bare TOML keys).
fn render(
    args: &InitArgs,
    vault_id: &str,
    item_id: &str,
    choice: Option<&TargetChoice>,
    d: &Declared,
) -> String {
    let env = &args.env;
    let mut s = String::new();
    s.push_str(
        "# Written by opv init: IDs, key names and kinds only; values stay in 1Password.\n\
         # Add keys with opv add, environments with opv init <env> --add-env; rules and \
         guidance by hand.\n\n",
    );
    let _ = writeln!(s, "[profile]\nkind = \"{}\"\n", profile_word(d.profile));
    let section = choice.map(|c| target_section(c, d.profile));
    s.push_str(&env_table(env, vault_id, item_id, section.as_deref()));
    for (product, keys) in &d.keys {
        for (key, kind) in keys {
            let table = match d.profile {
                Profile::Simple => format!("keys.{key}"),
                Profile::Fleet => format!("products.{product}.keys.{key}"),
            };
            let _ = writeln!(
                s,
                "\n[{table}]\nkind = \"{}\"\nenvironments = [{}]",
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

/// Run `init <env> --add-env`: add the environment to the existing file at `path`.
pub fn add_env(
    args: &InitArgs,
    path: &Path,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    add_env_on(args, path, r, out, &Host::detect)
}

fn add_env_on(
    args: &InitArgs,
    path: &Path,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
    host: &dyn Fn() -> Host,
) -> Result<(), Error> {
    check_args(args)?;
    let original = std::fs::read_to_string(path)
        .map_err(|e| Error::Config(format!("cannot read {}: {e}", path.display()).into()))?;
    let fleet = config::parse(&original).map_err(|e| match e {
        e @ Error::Config(_) => {
            e.map_text(|m| format!("{m} (fix {} first; nothing written)", path.display()))
        }
        other => other,
    })?;
    if fleet.environments.contains_key(&args.env) {
        return Err(Error::Config(
            format!(
                "environment {} already exists in {}; --add-env never overwrites: edit it \
                 by hand",
                args.env,
                path.display()
            )
            .into(),
        ));
    }
    let profile = fleet.profile;
    let choice = choose_target(args).map_err(init_help)?;
    probe_target(args, choice.as_ref(), Some(profile)).map_err(init_help)?;

    let vault = onepassword_init::resolve_vault(r, &args.vault, host)?;
    let item = onepassword_init::resolve_item(r, &vault.id, &args.item, host)?;
    let fields = onepassword_init::read_field_shapes(r, &vault.id, &item.id, host)?;
    let decl = declare(&fields, Some(profile), &args.item)?;

    let mut doc = ConfigDoc::parse(&original)?;
    let section = choice.as_ref().map(|c| target_section(c, profile));
    doc.add_environment(
        &args.env,
        &env_table(&args.env, &vault.id, &item.id, section.as_deref()),
    )?;
    let fleet_profile = profile == Profile::Fleet;
    let label = |p: &Option<String>, k: &str| match p {
        Some(p) => format!("{p}/{k}"),
        None => k.to_string(),
    };
    let mut added: Vec<String> = Vec::new();
    let mut products: Vec<String> = Vec::new();
    let mut absent: Vec<String> = Vec::new();
    let mut notes = decl.notes.clone();
    let mut declared = std::collections::BTreeSet::new();
    for (product, key) in doc.keys(fleet_profile) {
        let in_item = decl
            .keys
            .get(product.as_deref().unwrap_or(""))
            .and_then(|keys| keys.get(&key));
        declared.insert((product.clone().unwrap_or_default(), key.clone()));
        let name = label(&product, &key);
        let Some(kind) = in_item else {
            absent.push(name);
            continue;
        };
        let spec_kind = fleet
            .products
            .get(product.as_deref().unwrap_or(crate::domain::SIMPLE_PRODUCT))
            .and_then(|p| p.keys.get(&key))
            .map(|k| k.kind);
        if spec_kind.is_some_and(|k| k != *kind) {
            notes.push(format!(
                "{name} is declared {} but its field in the item is {}; status will report \
                 the wrong kind until one of them changes",
                kind_word(spec_kind.unwrap_or(*kind)),
                kind_word(*kind)
            ));
        }
        doc.add_key_env(product.as_deref(), &key, &args.env)?;
        if let Some(p) = &product
            && !products.contains(p)
        {
            products.push(p.clone());
        }
        added.push(name);
    }
    let undeclared: Vec<(String, Kind)> = decl
        .keys
        .iter()
        .flat_map(|(p, keys)| keys.iter().map(move |(k, kind)| (p, k, *kind)))
        .filter(|(p, k, _)| !declared.contains(&((*p).clone(), (*k).clone())))
        .map(|(p, k, kind)| {
            let name = if fleet_profile {
                format!("{p}/{k}")
            } else {
                k.clone()
            };
            (name, kind)
        })
        .collect();

    let text = doc.to_string();
    config::parse(&text).map_err(|e| would_write(e, "init --add-env"))?;
    config_edit::replace(path, &original, &text)?;

    let w = |out: &mut dyn Write, s: String| writeln!(out, "{s}").map_err(write_err);
    w(
        out,
        format!(
            "vault {:?} is {}, item {:?} is {}",
            vault.name, vault.id, item.name, item.id
        ),
    )?;
    for note in &notes {
        w(out, format!("note: {note}"))?;
    }
    w(
        out,
        format!(
            "added environment {}{} to {}: {} now {} it{}",
            args.env,
            choice
                .as_ref()
                .map(|c| format!(" ({} target)", c.provider.section()))
                .unwrap_or_default(),
            path.display(),
            super::plural(added.len(), "key", "keys"),
            if added.len() == 1 {
                "includes"
            } else {
                "include"
            },
            if added.is_empty() {
                String::new()
            } else {
                format!(" ({})", added.join(", "))
            }
        ),
    )?;
    if !absent.is_empty() {
        w(
            out,
            format!(
                "not in the item, so left out of {}: {} (opv add {} --env {} includes one)",
                args.env,
                absent.join(", "),
                absent[0],
                args.env
            ),
        )?;
    }
    if !undeclared.is_empty() {
        let names: Vec<&str> = undeclared.iter().map(|(n, _)| n.as_str()).collect();
        let (first, kind) = &undeclared[0];
        w(
            out,
            format!(
                "in the item but not declared: {} (opv add {first} --kind {} --env {} declares \
                 one)",
                names.join(", "),
                kind_word(*kind),
                args.env
            ),
        )?;
    }
    let next = match (added.is_empty(), undeclared.first()) {
        (true, Some((name, kind))) => format!(
            "opv add {name} --kind {} --env {}",
            kind_word(*kind),
            args.env
        ),
        (true, None) => format!("opv add <key> --kind secret --env {}", args.env),
        (false, _) => {
            let ps: Vec<&str> = products.iter().map(String::as_str).collect();
            next_command(&args.env, choice.is_some(), profile, &ps)
        }
    };
    w(out, format!("Next: {next}"))
}

#[cfg(test)]
#[path = "init_tests.rs"]
mod tests;
