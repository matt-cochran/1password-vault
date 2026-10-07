//! `init <env> --vault <name> --item <name> --fly-app <app>` use case (FR-23).
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
//! Read-only against 1Password (FR-11, SR-5): the only write in opv stays `item skeleton`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use super::write_err;
use crate::adapters::onepassword_init::{self, FieldShape};
use crate::config;
use crate::domain::{Kind, Profile};
use crate::error::Error;
use crate::host::Host;
use crate::runner::CommandRunner;

/// The file `init` writes, in the directory it is given (the current directory).
pub const FILE_NAME: &str = "secrets.toml";

/// The fleet Fly name template written for a fleet file (§10.2, the fixture's template).
pub const FLEET_TEMPLATE: &str = "FLEET__{PRODUCT}__{KEY}";

/// `opv init` arguments.
#[derive(Debug, Clone)]
pub struct InitArgs {
    pub env: String,
    pub vault: String,
    pub item: String,
    pub fly_app: String,
    /// `--profile`: overrides detection.
    pub profile: Option<Profile>,
    pub force: bool,
}

/// `--profile` text to a profile (`simple` or `fleet`).
pub fn parse_profile(s: &str) -> Result<Profile, Error> {
    match s {
        "simple" => Ok(Profile::Simple),
        "fleet" => Ok(Profile::Fleet),
        other => Err(Error::Config(format!(
            "--profile must be simple or fleet, got {other:?}"
        ))),
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
    let target = dir.join(FILE_NAME);
    refuse_existing(&target, args.force)?;

    let vault = onepassword_init::resolve_vault(r, &args.vault, host)?;
    let item = onepassword_init::resolve_item(r, &vault.id, &args.item, host)?;
    let fields = onepassword_init::read_field_shapes(r, &vault.id, &item.id, host)?;

    let decl = declare(&fields, args.profile, &args.item)?;
    let text = render(args, &vault.id, &item.id, &decl);
    // Validated exactly like a hand-written file (§10.2): IDs, app, key and product names.
    config::parse(&text).map_err(|e| match e {
        Error::Config(m) => Error::Config(format!(
            "{m} (in the file init would write; nothing written)"
        )),
        other => other,
    })?;
    write_atomic(&target, &text, args.force)?;

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
            "wrote {} ({} profile): {secrets} secret, {configs} config, skipped {}",
            target.display(),
            profile_word(decl.profile),
            decl.skipped
        ),
    )?;
    w(
        out,
        "add rules and guidance by hand; see the README (Rules reference)".into(),
    )?;
    w(out, format!("Next step: opv fly plan {}", args.env))
}

/// Arguments that need no 1Password call: the environment name (a bare TOML key) and the
/// Fly app (the same rule as a hand-written `fly.app`, §10.2).
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
        return Err(Error::Config(format!(
            "environment name {:?} must match ^[A-Za-z0-9][A-Za-z0-9_-]*$",
            args.env
        )));
    }
    if !config::is_id(&args.fly_app) {
        return Err(Error::Config(format!(
            "--fly-app {:?} must match ^[A-Za-z0-9][A-Za-z0-9._-]*$",
            args.fly_app
        )));
    }
    for (flag, v) in [("--vault", &args.vault), ("--item", &args.item)] {
        if v.is_empty() {
            return Err(Error::Config(format!("{flag} is empty")));
        }
    }
    Ok(())
}

/// The target exists (a file, directory or symlink) and `--force` was not given: exit 2,
/// naming the path. `init` never merges.
fn refuse_existing(target: &Path, force: bool) -> Result<(), Error> {
    if !force && fs::symlink_metadata(target).is_ok() {
        return Err(Error::Config(format!(
            "{} already exists; init never merges: pass --force to overwrite it",
            target.display()
        )));
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
    let profile = match (explicit, sectioned.is_empty(), unsectioned.is_empty()) {
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
            )));
        }
    };
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
    if !ignored.is_empty() {
        let names: Vec<String> = ignored.iter().map(|f| display_name(f)).collect();
        let shape = match profile {
            Profile::Simple => "sectioned",
            Profile::Fleet => "unsectioned",
        };
        d.notes.push(format!(
            "ignored {} {shape} field(s) under --profile {flag}: {}",
            names.len(),
            names.join(", ")
        ));
        d.skipped += ignored.len();
    }
    let mut bad_products: BTreeMap<&str, usize> = BTreeMap::new();
    for f in used {
        let product = f.section.as_deref().unwrap_or("");
        if profile == Profile::Fleet && !config::is_product_name(product) {
            *bad_products.entry(product).or_default() += 1;
            d.skipped += 1;
            continue;
        }
        let name_ok = config::is_env_name(&f.label);
        let kind = match f.ty.as_str() {
            "CONCEALED" => Some(Kind::Secret),
            "STRING" => Some(Kind::Config),
            _ => None,
        };
        match (name_ok, kind) {
            (false, _) => {
                d.notes.push(format!(
                    "skipped {}: not a valid key name (^[A-Z][A-Z0-9_]*$); rename the field \
                     in 1Password to manage it",
                    display_name(f)
                ));
                d.skipped += 1;
            }
            (true, None) => {
                d.notes.push(format!(
                    "skipped {}: field type {:?} is neither concealed (secret) nor text \
                     (config); status and fly sync will reject this field until its type is \
                     changed",
                    display_name(f),
                    f.ty
                ));
                d.skipped += 1;
            }
            (true, Some(kind)) => {
                let keys = d.keys.entry(product.to_string()).or_default();
                if keys.insert(f.label.clone(), kind).is_some() {
                    return Err(Error::Source(format!(
                        "duplicate field {} in item {item_title:?}; rename one in 1Password \
                         (nothing written)",
                        display_name(f)
                    )));
                }
            }
        }
    }
    for (product, n) in bad_products {
        d.notes.push(format!(
            "skipped section {product:?} ({n} field(s)): not a valid product name \
             (^[a-z][a-z0-9_-]*$); rename the section in 1Password to manage it"
        ));
    }
    Ok(d)
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

/// The file text: profile, one environment with IDs and the Fly app, one table per key with
/// its kind and `environments = [<env>]`. Mirrors `tests/fixtures/secrets.toml` and
/// `tests/fixtures/simple.toml`. Keys and products are validated names (bare TOML keys).
fn render(args: &InitArgs, vault_id: &str, item_id: &str, d: &Declared) -> String {
    let env = &args.env;
    let mut s = String::new();
    s.push_str(
        "# Written by opv init: IDs, key names and kinds only; values stay in 1Password.\n\
         # Add rules, guidance and more environments by hand.\n\n",
    );
    let _ = writeln!(s, "[profile]\nkind = \"{}\"\n", profile_word(d.profile));
    let _ = writeln!(s, "[environments.{env}]");
    let _ = writeln!(s, "vault_id = {}", quoted(vault_id));
    let _ = writeln!(s, "item_id = {}", quoted(item_id));
    let _ = writeln!(s, "fly.app = {}", quoted(&args.fly_app));
    if d.profile == Profile::Fleet {
        let _ = writeln!(s, "fly.secret_name = {}", quoted(FLEET_TEMPLATE));
    }
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

/// Write `text` to `target` through a temporary file in the same directory and a rename,
/// so the target is never partly written. Without `force`, an existing target is refused
/// again just before the rename (it may have appeared during the 1Password calls).
fn write_atomic(target: &Path, text: &str, force: bool) -> Result<(), Error> {
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    let tmp: PathBuf = dir.join(format!(".{FILE_NAME}.opv-init.{}.tmp", std::process::id()));
    let fail = |what: &str, p: &Path, e: io::Error| {
        Error::Config(format!("cannot {what} {}: {e}", p.display()))
    };
    let res = (|| {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| fail("create", &tmp, e))?;
        f.write_all(text.as_bytes())
            .and_then(|()| f.sync_all())
            .map_err(|e| fail("write", &tmp, e))?;
        drop(f);
        refuse_existing(target, force)?;
        fs::rename(&tmp, target).map_err(|e| fail("write", target, e))
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res
}

#[cfg(test)]
#[path = "init_tests.rs"]
mod tests;
