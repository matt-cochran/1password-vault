//! `init <env> [--vault <name>] [--item <name>] [--product <name>]` use case (FR-23) and
//! `init <env> … --add-env` (H2).
//!
//! A dev-time helper that writes a starter configuration in the one form (FR-57, FR-60):
//! boundaries and products. It writes no target: `opv target add` is the one way to add
//! one (FR-56).
//!
//! 1. Refuse before any call when the file exists and `--force` is not given (exit 2).
//! 2. Resolve the vault and item titles to IDs, once, through
//!    [`onepassword_init`] (the only title lookup in opv; FR-13's dev-time exception).
//! 3. Read the item once, keeping field names, sections and types only. Values are never
//!    deserialized (SR-1, SR-2).
//! 4. Each named section is a product; unsectioned fields are the keys of the product
//!    `--product` names (required when there are any). An item with both shapes fails naming
//!    both. Concealed fields become `secret`, text fields `config` (FR-14); other types and
//!    labels that are not valid key names are skipped with a note naming the field.
//! 5. The item is one boundary (FR-57): `boundaries.<product>` for one product, else
//!    `boundary = "core"` on each product and `boundaries.core`.
//! 6. Render the file, validate it with the same loader as a hand-written one (§10.2), and
//!    write it atomically (a temporary file in the same directory, then a rename). The file
//!    holds IDs, names and kinds only, never a value (SR-4).
//!
//! `--add-env` adds one `[environments.<env>]` with its boundary to an existing
//! configuration instead (edited in place, comments kept, [`crate::config_edit`]), and adds
//! the environment to every declared key whose field the item has, and refuses an
//! environment that already exists.
//!
//! Read-only against 1Password (FR-11, SR-5) except for a signed-in person (FR-43): a
//! missing vault or item is created, and the declared item is tidied after the file is
//! written ([`super::tidy`]).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::io::Write;
use std::path::Path;

use super::write_err;
use crate::adapters::onepassword_init::{self, FieldShape};
use crate::cause::{
    Cause, Closest, Cmd, ConfigCheck, DottedPath, FieldRule, InputKind, NameKind, PatternId,
    StoreObject, UsageProblem,
};
use crate::config;
use crate::config_edit::{self, ConfigDoc};
use crate::config_store::ConfigStore;
use crate::domain::{Fleet, Kind};
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

/// `opv init <env> --from <file>` without `--apply`: the keys and kinds it would declare,
/// and which are empty. No 1Password call, nothing written. `again` is the same command
/// with `--apply`.
pub fn plan_from(
    args: &InitArgs,
    imported: &Imported,
    again: &str,
    out: &mut dyn Write,
    json: bool,
) -> Result<(), Error> {
    let from = args.from.as_ref().expect("plan_from is called with --from");
    if json {
        let keys: Vec<serde_json::Value> = imported
            .kinds
            .iter()
            .map(|(k, kind)| {
                serde_json::json!({
                    "key": k,
                    "kind": super::kind_label(*kind),
                    "empty": imported.empty.contains(k),
                })
            })
            .collect();
        let doc = serde_json::json!({
            "schema_version": crate::json::SCHEMA_VERSION,
            "applied": false,
            "environment": args.env,
            "product": args.product,
            "vault": args.vault,
            "item": args.item,
            "keys": keys,
            "invalid": imported.invalid,
            "next": again,
        });
        return writeln!(out, "{doc}").map_err(write_err);
    }
    let w = |out: &mut dyn Write, s: String| writeln!(out, "{s}").map_err(write_err);
    w(
        out,
        format!(
            "{}: {} for {} -> vault {:?}, item {:?}",
            from.path.display(),
            super::plural(imported.kinds.len(), "key", "keys"),
            args.env,
            args.vault,
            args.item
        ),
    )?;
    for (k, kind) in &imported.kinds {
        let empty = if imported.empty.contains(k) {
            "  (empty: declared, not imported)"
        } else {
            ""
        };
        w(out, format!("  {:<6} {k}{empty}", kind_word(*kind)))?;
    }
    for name in &imported.invalid {
        w(
            out,
            format!("note: skipped {name:?}: not a valid key name (^[A-Z][A-Z0-9_]*$)"),
        )?;
    }
    w(
        out,
        "Nothing written. Kinds are by name, secret when unsure; change one with --config-key \
         KEY or --secret-key KEY. A field the item already has keeps its kind and its value."
            .into(),
    )?;
    w(out, format!("Next: {again}"))
}

/// Run `init`, writing `dir/secrets.toml`.
pub fn run(
    args: &InitArgs,
    dir: &Path,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    run_on(args, dir, r, out, &Host::detect, false)
}

/// [`run`], printing what was written as one JSON document when `json` (A5): `{path,
/// manifest, environment, boundary, vault_id, item_id, created, keys:
/// [{product, key, kind}], skipped, next}`. Names, IDs and kinds only.
pub fn run_as(
    args: &InitArgs,
    dir: &Path,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
    json: bool,
) -> Result<(), Error> {
    run_on(args, dir, r, out, &Host::detect, json)
}

fn run_on(
    args: &InitArgs,
    dir: &Path,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
    host: &dyn Fn() -> Host,
    json: bool,
) -> Result<(), Error> {
    check_args(args)?;
    let target = dir.join(FILE_NAME);
    if !args.force && fs::symlink_metadata(&target).is_ok() {
        return Err(existing_refusal(args, &target));
    }
    let imported = from_apply(args)?;
    let p = prepare(args, imported.as_ref(), r, host)?;
    write_config(&target, &p.text, args.force)?;
    tidy_declared(args, &p, r);
    let place = Place::File(target.display().to_string());
    let adopted = import_values(args, &p, &place, r)?;
    if json {
        return write_json(out, args, &p, &place, adopted.as_ref());
    }
    print_adopted(out, adopted.as_ref())?;
    let ancestor = ancestor_note(dir);
    report(args, &p, &place, ancestor, out)
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
    json: bool,
) -> Result<(), Error> {
    check_args(args)?;
    let imported = from_apply(args)?;
    let p = prepare(args, imported.as_ref(), r, &Host::detect)?;
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
    tidy_declared(args, &p, r);
    use crate::config_store::ConfigStore as _;
    let place = Place::Manifest(m.describe());
    let adopted = import_values(args, &p, &place, r)?;
    if json {
        return write_json(out, args, &p, &place, adopted.as_ref());
    }
    print_adopted(out, adopted.as_ref())?;
    // Only the case a person must act on: a checkout with a remote finds the manifest by
    // itself (found live: a note on every new project that asked nothing of anyone).
    let note = repo.is_none().then(|| {
        format!(
            "note: no git remote origin; point a checkout at it with OPV_PROJECT={project} or \
             a .opv file holding project = \"{project}\""
        )
    });
    report(args, &p, &place, note, out)
}

/// FR-43: a person's init also tidies the item it just declared (a read; never fails init).
fn tidy_declared(args: &InitArgs, p: &Prepared, r: &dyn CommandRunner) {
    if super::tidy::active() {
        let _ = super::tidy::read(&p.fleet, &args.env, r);
    }
}

/// The keys of `--from … --apply`, read before any 1Password call so a bad file changes
/// nothing; `None` without `--from`. `--from` without `--apply` never gets here (main runs
/// [`plan_from`] instead).
fn from_apply(args: &InitArgs) -> Result<Option<Imported>, Error> {
    match &args.from {
        None => Ok(None),
        Some(from) if from.apply => read_from(from).map(Some),
        Some(_) => Err(Cause::Bug {
            site: "init: --from without --apply reached the write path",
        }
        .into()),
    }
}

/// Declare the imported keys in the `--product` product, next to the item's own fields; a
/// field the item already has keeps the kind it has there (#90). An item holding another
/// product's section is refused: `--from` declares one product's keys.
fn merge_imported(d: &mut Declared, imported: &Imported, args: &InitArgs) -> Result<(), Error> {
    let from = args.from.as_ref().expect("merged only with --from");
    let product = args.product.as_deref().ok_or_else(|| {
        usage(UsageProblem::NeedsFlag {
            flag: "--from".into(),
            needs: "--product <name>, the product its keys belong to".into(),
        })
    })?;
    if d.keys.keys().any(|p| p != product) {
        // The item holds another product's section: `--from` declares one product's keys,
        // so the file's values go in with adopt once the keys are declared (opv add).
        return Err(usage(UsageProblem::UseInstead {
            command: Cmd {
                command: vec!["adopt".into()],
                args: vec![
                    args.env.clone(),
                    "--from".into(),
                    from.path.display().to_string(),
                ],
            },
        }));
    }
    let keys = d.keys.entry(product.to_string()).or_default();
    let mut added = 0;
    for (name, kind) in &imported.kinds {
        if !keys.contains_key(name) {
            keys.insert(name.clone(), *kind);
            added += 1;
        }
    }
    d.notes.push(format!(
        "declared {} from {}",
        super::plural(added, "key", "keys"),
        from.path.display()
    ));
    for name in &imported.invalid {
        d.notes.push(format!(
            "skipped {name:?} from the file: not a valid key name (^[A-Z][A-Z0-9_]*$)"
        ));
        d.skipped += 1;
    }
    Ok(())
}

/// With `--from … --apply`, after the configuration is written: import the file's values
/// through `opv adopt` (one item edit, read back and verified; empty values are not
/// imported; a value 1Password already holds is kept and reported).
fn import_values(
    args: &InitArgs,
    p: &Prepared,
    place: &Place,
    r: &dyn CommandRunner,
) -> Result<Option<crate::domain::adopt::AdoptPlan>, Error> {
    let Some(from) = args.from.as_ref().filter(|f| f.apply) else {
        return Ok(None);
    };
    let source = super::adopt::Source::Dotenv(from.path.clone());
    super::adopt::plan_and_write(
        &p.fleet,
        &args.env,
        &source,
        &Default::default(),
        &Default::default(),
        true,
        r,
    )
    .map(Some)
    .map_err(|e| {
        // The configuration is already written (X20): the failure says so, with what was
        // created in 1Password for it.
        let Some((cause, upstream)) = e.cause() else {
            return e;
        };
        let mut done = p.created.clone();
        done.push(place.describe().to_string());
        let partial = Cause::Partial {
            done,
            approval_used: None,
            approval_scope: None,
            then: Box::new(cause.clone()),
        };
        match upstream {
            Some(up) => Error::with_evidence(partial, up.clone()),
            None => partial.into(),
        }
    })
}

/// The import lines after `init --from … --apply`: counts, and every key not imported with
/// why. Names only.
fn print_adopted(
    out: &mut dyn Write,
    plan: Option<&crate::domain::adopt::AdoptPlan>,
) -> Result<(), Error> {
    let Some(plan) = plan else { return Ok(()) };
    writeln!(
        out,
        "imported {} into 1Password (read back and verified)",
        super::plural(plan.writes.len(), "value", "values")
    )
    .map_err(write_err)?;
    for row in plan
        .rows
        .iter()
        .filter(|r| !matches!(r.action, crate::domain::adopt::Action::Import))
    {
        if let Some(key) = &row.key {
            writeln!(out, "  {key}: {}", row.action.word()).map_err(write_err)?;
        }
    }
    Ok(())
}

/// Where `init` saved the configuration.
enum Place {
    File(String),
    Manifest(String),
}

impl Place {
    fn describe(&self) -> &str {
        match self {
            Place::File(s) | Place::Manifest(s) => s,
        }
    }
}

/// What `init` declares, before it is written anywhere.
struct Prepared {
    vault: onepassword_init::Named,
    item: onepassword_init::Named,
    decl: Declared,
    text: String,
    /// The written text as the loader reads it: what the tidy and `--from`'s import work
    /// from.
    fleet: Fleet,
    /// What was created in 1Password for a signed-in person (FR-43), e.g. `vault "x"`.
    created: Vec<String>,
}

/// Resolve (creating a missing vault or item for a signed-in person, FR-43), read field
/// shapes, declare, render and validate (steps 2 to 6).
fn prepare(
    args: &InitArgs,
    imported: Option<&Imported>,
    r: &dyn CommandRunner,
    host: &dyn Fn() -> Host,
) -> Result<Prepared, Error> {
    // FR-43: a person gets a missing vault or item created; anyone else gets the error.
    let mut created = Vec::new();
    let mut person = None;
    let mut may_create = |r: &dyn CommandRunner| {
        *person.get_or_insert_with(|| {
            super::tidy::active() && super::tidy::identity(r) == super::tidy::Identity::Person
        })
    };
    let vault = match onepassword_init::find_vault(r, &args.vault, host)? {
        onepassword_init::Lookup::Found(v) => v,
        // A missing vault or item opv may not create (FR-43): the cause's Do has the person
        // create it (found live: the bare error's step was the same command).
        onepassword_init::Lookup::Missing(e) if !may_create(r) => return Err(e),
        onepassword_init::Lookup::Missing(_) => {
            created.push(format!("vault {:?}", args.vault));
            onepassword_init::create_vault(r, &args.vault)?
        }
    };
    let item = match onepassword_init::find_item(r, &vault.id, &args.item, host)? {
        onepassword_init::Lookup::Found(i) => i,
        onepassword_init::Lookup::Missing(e) if !may_create(r) => return Err(e),
        onepassword_init::Lookup::Missing(_) => {
            created.push(format!("item {:?}", args.item));
            onepassword_init::create_item(r, &vault.id, &args.item)?
        }
    };
    let fields = onepassword_init::read_field_shapes(r, &vault.id, &item.id, host)?;

    let mut decl = declare(&fields, args.product.as_deref(), &args.vault, &args.item)?;
    if let Some(imported) = imported {
        merge_imported(&mut decl, imported, args)?;
    }
    let ids = (vault.id.as_str(), item.id.as_str());
    let text = render(args, ids, &decl);
    // Validated exactly like a hand-written file (§10.2): IDs, key and product names.
    let fleet = config::parse(&text).map_err(would_write(None))?;
    Ok(Prepared {
        vault,
        item,
        decl,
        text,
        fleet,
        created,
    })
}

/// The lines after a successful `init`: IDs, notes, counts, where it was written, then
/// the next step.
fn report(
    args: &InitArgs,
    p: &Prepared,
    place: &Place,
    extra: Option<String>,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let (vault, item, decl) = (&p.vault, &p.item, &p.decl);
    let w = |out: &mut dyn Write, s: String| writeln!(out, "{s}").map_err(write_err);
    if !p.created.is_empty() {
        w(
            out,
            format!("created {} in 1Password", p.created.join(" and ")),
        )?;
    }
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
            "wrote {} ({}): {secrets} secret, {configs} config, skipped {}",
            place.describe(),
            decl.describe(),
            decl.skipped
        ),
    )?;
    if let Some(note) = extra {
        w(out, note)?;
    }
    // A new, empty configuration's one useful pointer is how to declare a key; rules and
    // guidance live in the docs and `opv add --help`.
    if secrets + configs == 0 {
        w(
            out,
            format!(
                "add a key: opv add {}/<KEY> --kind secret --env {}",
                args.product.as_deref().unwrap_or("<product>"),
                crate::error::shell_word(&args.env)
            ),
        )?;
    }
    // A deployed environment's target is added by `opv target add` (FR-56), whose options
    // only the person knows; a run-only environment needs none.
    w(
        out,
        format!(
            "add a deploy target: opv target add {} <name> --<provider options> (opv target \
             add --help); a run-only environment needs none",
            crate::error::shell_word(&args.env)
        ),
    )?;
    w(
        out,
        format!(
            "Next: {}",
            crate::cause::render::cmd_text(&next_after(args, p, place))
        ),
    )
}

/// The command after `init` (05.01, X8), typed (§10.1). A `secrets.toml` goes on to `opv
/// bootstrap`, which records every boundary it declares and adds each declared key's empty
/// field (FR-52). A manifest project never gets `opv bootstrap` (it reads a secrets.toml
/// only): init has recorded the item's boundary and declared its fields, so the step checks
/// what it declared, as `--add-env` does, or says how to declare a first key.
fn next_after(args: &InitArgs, p: &Prepared, place: &Place) -> Cmd {
    let cmd = |words: &[&str], a: &[&str]| Cmd {
        command: words.iter().map(|w| w.to_string()).collect(),
        args: a.iter().map(|w| w.to_string()).collect(),
    };
    match place {
        Place::File(_) => cmd(&["bootstrap"], &[]),
        Place::Manifest(_) => match p.decl.keys.keys().collect::<Vec<_>>().as_slice() {
            [] => cmd(&["add"], &["--help"]),
            [one] => cmd(&["check"], &[&args.env, "--product", one]),
            _ => cmd(&["doctor"], &["--env", &args.env]),
        },
    }
}

/// `init --json` (A5).
fn write_json(
    out: &mut dyn Write,
    args: &InitArgs,
    p: &Prepared,
    place: &Place,
    adopted: Option<&crate::domain::adopt::AdoptPlan>,
) -> Result<(), Error> {
    let decl = &p.decl;
    let keys: Vec<serde_json::Value> = decl
        .keys
        .iter()
        .flat_map(|(product, keys)| {
            keys.iter().map(move |(key, kind)| {
                serde_json::json!({
                    "product": product,
                    "key": key,
                    "kind": super::kind_label(*kind),
                })
            })
        })
        .collect();
    let (path, manifest) = match place {
        Place::File(f) => (Some(f.as_str()), None),
        Place::Manifest(m) => (None, Some(m.as_str())),
    };
    let mut doc = serde_json::json!({
        "schema_version": crate::json::SCHEMA_VERSION,
        "path": path,
        "manifest": manifest,
        "environment": args.env,
        "boundary": decl.boundary(),
        "vault_id": p.vault.id,
        "item_id": p.item.id,
        "created": p.created,
        "keys": keys,
        "skipped": decl.skipped,
        "next": crate::cause::render::cmd_text(&next_after(args, p, place)),
    });
    // `--from … --apply` (#90) adds what it imported; other runs keep the document as it was.
    if let Some(a) = adopted {
        let not_imported: Vec<serde_json::Value> = a
            .rows
            .iter()
            .filter(|r| !matches!(r.action, crate::domain::adopt::Action::Import))
            .filter_map(|r| {
                r.key
                    .as_ref()
                    .map(|k| serde_json::json!({"key": k, "action": r.action.word()}))
            })
            .collect();
        doc["imported"] = serde_json::json!(a.writes.len());
        doc["not_imported"] = serde_json::json!(not_imported);
    }
    writeln!(out, "{doc}").map_err(write_err)
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

/// `opv init` run where a `secrets.toml` already is (I5). A new environment is added with
/// `--add-env` (the exact command is the step); an environment the file already declares is
/// changed with `opv config edit`. Never a step that repeats the failing command.
fn existing_refusal(args: &InitArgs, target: &Path) -> Error {
    let declared = crate::config::read_merged(target)
        .ok()
        .and_then(|t| crate::config::parse(&t).ok())
        .is_some_and(|f| f.environments.contains_key(&args.env));
    if declared {
        // Its step is `opv config edit`, which changes a declared environment.
        return Cause::AlreadyDeclared {
            kind: NameKind::Environment,
            name: args.env.clone(),
        }
        .into();
    }
    // init never merges: a new environment is added to the file with --add-env.
    usage(UsageProblem::UseInstead {
        command: add_env_cmd(args),
    })
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

/// `opv init <env> --vault <v> --item <i> [--product <p>] --add-env`: this run's own
/// arguments, as `--add-env`.
fn add_env_cmd(args: &InitArgs) -> Cmd {
    let mut a = vec![
        args.env.clone(),
        "--vault".into(),
        args.vault.clone(),
        "--item".into(),
        args.item.clone(),
    ];
    if let Some(p) = &args.product {
        a.extend(["--product".into(), p.clone()]);
    }
    a.push("--add-env".into());
    Cmd {
        command: vec!["init".into()],
        args: a,
    }
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
    fn counts(&self) -> (usize, usize) {
        let kinds = || self.keys.values().flat_map(BTreeMap::values);
        let secrets = kinds().filter(|k| **k == Kind::Secret).count();
        (secrets, kinds().count() - secrets)
    }

    /// The item's boundary (FR-57); `None` while it declares no key.
    fn boundary(&self) -> Option<&str> {
        item_boundary(self.keys.keys().map(String::as_str))
    }

    /// `product api`, `products api, web (boundary core)` or `no key yet`.
    fn describe(&self) -> String {
        let products: Vec<&str> = self.keys.keys().map(String::as_str).collect();
        match products.as_slice() {
            [] => "no key yet".into(),
            [one] => format!("product {one}"),
            many => format!("products {} (boundary {SHARED_BOUNDARY})", many.join(", ")),
        }
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
        "# Written by opv init: IDs, key names and kinds only; values stay in 1Password.\n\
         # Add keys with opv add, environments with opv init <env> --add-env, targets with \
         opv target add; rules and guidance by hand.\n\n",
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

/// Run `init <env> --add-env`: add the environment to the existing configuration.
pub fn add_env(
    args: &InitArgs,
    store: &dyn ConfigStore,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    add_env_on(args, store, r, out, &Host::detect, false)
}

/// [`add_env`], printing `{environment, saved_in, boundary, vault_id, item_id, added,
/// absent, undeclared, next}` as one JSON document when `json` (A5). Names only.
pub fn add_env_as(
    args: &InitArgs,
    store: &dyn ConfigStore,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
    json: bool,
) -> Result<(), Error> {
    add_env_on(args, store, r, out, &Host::detect, json)
}

fn add_env_on(
    args: &InitArgs,
    store: &dyn ConfigStore,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
    host: &dyn Fn() -> Host,
    json: bool,
) -> Result<(), Error> {
    check_args(args)?;
    // The text the write is built from: for the manifest, a person's fresh read (I3, C1).
    let base = store.read_for_write(r)?;
    let original = &base.text;
    let place = store.describe();
    // A configuration that does not load is the loader's own cause (nothing is written).
    let fleet = store.parse(original)?;
    if fleet.environments.contains_key(&args.env) {
        // --add-env never overwrites; the step is `opv config edit`.
        return Err(Cause::AlreadyDeclared {
            kind: NameKind::Environment,
            name: args.env.clone(),
        }
        .into());
    }

    // The item must exist: its fields are what --add-env declares (nothing is created).
    let vault = onepassword_init::find_vault(r, &args.vault, host)?.found()?;
    let item = onepassword_init::find_item(r, &vault.id, &args.item, host)?.found()?;
    let fields = onepassword_init::read_field_shapes(r, &vault.id, &item.id, host)?;
    let decl = declare(&fields, args.product.as_deref(), &args.vault, &args.item)?;

    let mut doc = ConfigDoc::parse(original)?;
    let mut added: Vec<String> = Vec::new();
    let mut products: BTreeSet<String> = BTreeSet::new();
    let mut absent: Vec<String> = Vec::new();
    let mut notes = decl.notes.clone();
    let mut declared = BTreeSet::new();
    // Keys added to the new environment, as (product, key).
    let mut added_ids: Vec<(String, String)> = Vec::new();
    // Shared keys (FR-45), decided once their sources are: (product, key, source).
    let mut shared: Vec<(String, String, (String, String))> = Vec::new();
    for (product, key) in doc.keys() {
        declared.insert((product.clone(), key.clone()));
        let spec = fleet.products.get(&product).and_then(|p| p.keys.get(&key));
        // M6: a shared key has no field of its own; it joins the environment exactly when
        // its source does (below), whatever stray field sits under its own label.
        if let Some((sp, sk)) = spec.and_then(|s| s.source()) {
            shared.push((product, key, (sp.to_string(), sk.to_string())));
            continue;
        }
        let name = format!("{product}/{key}");
        let Some(kind) = decl.keys.get(&product).and_then(|keys| keys.get(&key)) else {
            absent.push(name);
            continue;
        };
        if let Some(declared_kind) = spec.map(|k| k.kind).filter(|k| k != kind) {
            notes.push(format!(
                "{name} is declared {} but its field in the item is {}; status will report \
                 the wrong kind until one of them changes",
                kind_word(declared_kind),
                kind_word(*kind)
            ));
        }
        added_ids.push((product.clone(), key));
        products.insert(product);
        added.push(name);
    }
    for (product, key, source) in shared {
        let name = format!("{product}/{key}");
        if !added_ids.contains(&source) {
            absent.push(name);
            continue;
        }
        added_ids.push((product.clone(), key));
        products.insert(product);
        added.push(name);
    }
    // The item is one boundary (FR-57): every product it gives the environment shares it.
    // FR-55: a personal key lives in each person's own item, so an item giving the
    // environment only personal keys is not its shared item and cannot be its boundary.
    if !added_ids.is_empty()
        && added_ids.iter().all(|(product, key)| {
            fleet
                .products
                .get(product)
                .and_then(|p| p.keys.get(key))
                .is_some_and(|spec| spec.personal)
        })
    {
        return Err(Cause::ConfigProposalInvalid {
            source: store.cause_source(),
            field: DottedPath(vec![
                "environments".into(),
                args.env.clone(),
                "boundaries".into(),
            ]),
            rule: FieldRule::Check {
                check: ConfigCheck::PersonalItemBoundary {
                    env: args.env.clone(),
                    item: item.name.clone(),
                },
            },
            from_proposal: true,
        }
        .into());
    }
    let boundaries: BTreeSet<&str> = products.iter().map(|p| fleet.boundary_of(p)).collect();
    if boundaries.len() > 1 {
        // The item is one boundary: every product it holds names the same one.
        let first = products
            .iter()
            .next()
            .expect("several boundaries, so a product");
        return Err(Cause::ConfigInvalid {
            source: store.cause_source(),
            at: None,
            field: DottedPath(vec!["products".into(), first.clone(), "boundary".into()]),
            rule: FieldRule::Type {
                expected: "\"core\" on every product of the item --add-env reads, which is one \
                           boundary",
            },
        }
        .into());
    }
    let boundary = boundaries.into_iter().next();
    doc.add_environment(
        &args.env,
        &env_table(&args.env, boundary, (&vault.id, &item.id)),
    )?;
    for (product, key) in &added_ids {
        doc.add_key_env(product, key, &args.env)?;
    }
    let undeclared: Vec<(String, Kind)> = decl
        .keys
        .iter()
        .flat_map(|(p, keys)| keys.iter().map(move |(k, kind)| (p, k, *kind)))
        .filter(|(p, k, _)| !declared.contains(&((*p).clone(), (*k).clone())))
        .map(|(p, k, kind)| (format!("{p}/{k}"), kind))
        .collect();

    let text = doc.to_string();
    store.parse(&text).map_err(would_write(Some(original)))?;
    crate::config_store::save(store, r, &base, &text)?;

    // Typed (§10.1): the declaring `opv add`, else the check of what was added.
    let cmd = |words: &str, a: Vec<String>| Cmd {
        command: vec![words.to_string()],
        args: a,
    };
    let next = crate::cause::render::cmd_text(&match (added.is_empty(), undeclared.first()) {
        (true, Some((name, kind))) => cmd(
            "add",
            vec![
                name.clone(),
                "--kind".into(),
                kind_word(*kind).into(),
                "--env".into(),
                args.env.clone(),
            ],
        ),
        (true, None) => cmd("add", vec!["--help".into()]),
        (false, _) => match products.iter().collect::<Vec<_>>().as_slice() {
            [one] => cmd(
                "check",
                vec![args.env.clone(), "--product".into(), (*one).clone()],
            ),
            _ => cmd("doctor", vec!["--env".into(), args.env.clone()]),
        },
    });
    if json {
        let names: Vec<&str> = undeclared.iter().map(|(n, _)| n.as_str()).collect();
        let doc = serde_json::json!({
            "schema_version": crate::json::SCHEMA_VERSION,
            "environment": args.env,
            "saved_in": place,
            "boundary": boundary,
            "vault_id": vault.id,
            "item_id": item.id,
            "added": added,
            "absent": absent,
            "undeclared": names,
            "next": next,
        });
        return writeln!(out, "{doc}").map_err(write_err);
    }
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
            boundary
                .map(|b| format!(" (boundary {b})"))
                .unwrap_or_default(),
            place,
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
    w(out, format!("Next: {next}"))
}

#[cfg(test)]
#[path = "init_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "init_from_tests.rs"]
mod from_tests;
