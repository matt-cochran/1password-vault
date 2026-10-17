//! `opv target add` and `opv target list` (FR-56, `docs/design/placements-and-access-boundaries.md`
//! §5.2).
//!
//! `target add` declares one named target under `[environments.<env>.targets.<name>]`: the
//! provider's section (its options and validation come through the
//! provider plug-in contract, FR-37), the products it delivers (FR-48), its deploy identity
//! (`deploy_credentials`, FR-40) and its state vault (FR-58). In the same confirmed step it
//! finds or creates the state vault titled [`naming::state_vault`] and records its ID. The
//! edit goes through [`crate::config_store`]: 1Password writes happen only in a person's own
//! session (FR-43, SR-3, SR-5), comments and order are kept ([`toml_edit`]), the edited text
//! is validated by the same loader as a hand-written file before anything is written, and a
//! concurrent change is refused. Names only, never a value (SR-1).
//!
//! `target list` is read-only: every target with its environment, provider, locator and
//! scope.

use std::collections::BTreeMap;
use std::io::Write;

use toml_edit::{DocumentMut, Item, Table};

use super::write_err;
use crate::adapters::onepassword_init::{self as init_op, Lookup};
use crate::adapters::registry;
use crate::app::{bootstrap, personal, tidy};
use crate::cause::{
    Cause, Cmd, ConfigSource, DottedPath, FieldRule, NameKind, NotEditable, UsageProblem,
};
use crate::config;
use crate::config_store::{self, ConfigStore};
use crate::domain::{Fleet, naming};
use crate::error::Error;
use crate::host::Host;
use crate::provider::{InitField, Provider, init_flag};
use crate::runner::CommandRunner;

/// `opv target add` arguments.
#[derive(Debug, Clone, Default)]
pub struct AddArgs {
    /// Environment name from the configuration.
    pub env: String,
    /// New target name (`^[a-z][a-z0-9-]*$`).
    pub name: String,
    /// `--provider`: `fly`, `azure`, `kubernetes`, `github`; `None` infers it from the
    /// provider options given, as `opv init` does.
    pub provider: Option<String>,
    /// The provider's options, by flag (`fly-app` → its value); validated against the
    /// provider's [`InitField`]s.
    pub fields: BTreeMap<String, String>,
    /// `--products <p>[,<p>…]`: the products it delivers; empty means every product.
    pub products: Vec<String>,
    /// `--role <name>` (repeatable): the process roles it delivers, written as the target's
    /// `roles` (delivery-transports §4.4); names only. Empty: no `roles` line.
    pub roles: Vec<String>,
    /// `--deploy-credentials op://<vault>/<item>` (FR-40).
    pub deploy_credentials: Option<String>,
    /// `--project <name>`: the project naming the state vault; default: the repository's.
    pub project: Option<String>,
    /// `--dry-run`: print what would be written and created, change nothing.
    pub dry_run: bool,
    /// `--json`: print one document (A5).
    pub json: bool,
}

/// `target list --env <ENV> [--json]`.
#[derive(Debug, Clone, Default)]
pub struct ListArgs {
    /// Only this environment; `None`: every environment.
    pub env: Option<String>,
    /// Print one JSON array (A5).
    pub json: bool,
}

/// An opv command as a typed step (design §10.1).
fn opv(command: &[&str], args: &[&str]) -> Cmd {
    Cmd {
        command: command.iter().map(|w| w.to_string()).collect(),
        args: args.iter().map(|w| w.to_string()).collect(),
    }
}

/// A command-line refusal: its Next is `opv target add --help` (flag errors only, 06.27).
fn usage(problem: UsageProblem) -> Error {
    Cause::Usage { problem }.into()
}

/// A target opv cannot write for this provider: the person adds it with `opv config edit`
/// (06.27: never `--help`, which cannot change the configuration).
fn by_hand() -> Error {
    usage(UsageProblem::UseInstead {
        command: opv(&["config", "edit"], &[]),
    })
}

/// A section of the configuration written in a shape opv does not edit (R15, 06.27): Do
/// edit it by hand, Next `opv config edit`.
fn not_editable(source: &ConfigSource, section: String) -> Error {
    Cause::ConfigNotEditable {
        source: source.clone(),
        reason: NotEditable::UnsupportedLayout { section },
    }
    .into()
}

/// `env`/`name` already declares a target: it is changed with `opv config edit`.
fn exists(env: &str, name: &str) -> Error {
    Cause::AlreadyDeclared {
        kind: NameKind::Target,
        name: format!("{name} in environment {env}"),
    }
    .into()
}

/// An internal invariant that does not hold (a fragment opv built itself).
fn bug(site: &'static str) -> Error {
    Cause::Bug { site }.into()
}

/// `opv target add` (FR-56). Every refusal is a catalog cause with its own step: flag
/// errors lead to `--help`, configuration-shape refusals to `opv config edit` (06.27).
pub fn add(
    args: &AddArgs,
    store: &dyn ConfigStore,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    add_inner(args, store, r, out)
}

fn add_inner(
    args: &AddArgs,
    store: &dyn ConfigStore,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    // The text the write is built from: for the manifest, a person's fresh read (I3, C1).
    let base = store.read_for_write(r)?;
    let original = &base.text;
    let place = store.describe();
    let source = store.cause_source();
    let fleet = store.parse(original)?;
    let environment = fleet.environment(&args.env)?;
    if !config::is_target_name(&args.name) {
        return Err(usage(UsageProblem::ValueFormat {
            flag: format!("the target name {:?}", args.name),
            format: "a name matching ^[a-z][a-z0-9-]*$",
        }));
    }
    if environment.targets.contains_key(&args.name) {
        return Err(exists(&args.env, &args.name));
    }
    let (provider, values) = provider_and_values(args)?;
    let section = provider.init_section(&values).ok_or_else(by_hand)?;
    let products = checked_products(&fleet, &args.products)?;

    let dir = std::env::current_dir().unwrap_or_default();
    let project = match &args.project {
        Some(p) => {
            if !config_store::is_project_name(p) {
                return Err(usage(UsageProblem::ValueFormat {
                    flag: "--project".into(),
                    format: "a name matching ^[A-Za-z0-9][A-Za-z0-9._-]*$ (at most 64 characters)",
                }));
            }
            p.clone()
        }
        None => personal::project_name(r, &dir),
    };
    let title = naming::state_vault(&project, &args.env, &args.name);
    let comment = format!(
        "# deploy target {} in {}; added by opv target add",
        args.name, args.env
    );
    let build = |state_vault_id: &str, items: &[(String, String)]| -> Result<String, Error> {
        let body = target_table(
            &args.env,
            &args.name,
            &section,
            &products,
            &args.roles,
            args.deploy_credentials.as_deref(),
            Some(state_vault_id),
            items,
        );
        let text = insert_target_in(original, &source, &args.env, &args.name, &body, &comment)?;
        // The same validation as a hand-written file: provider fields, products, deploy
        // credentials and the state vault, before anything is written or created.
        store.parse(&text)?;
        Ok(text)
    };
    let next =
        crate::cause::render::cmd_text(&opv(&["access"], &[&args.env, "--target", &args.name]));

    if args.dry_run {
        // Read-only: report whether the state vault would be created or reused.
        let (state_vault_id, created) = match init_op::find_vault(r, &title, &Host::detect)? {
            Lookup::Found(n) => (n.id, false),
            Lookup::Missing(_) => (title.clone(), true),
        };
        build(&state_vault_id, &[])?;
        // #150: the write needs a login session of the person's own.
        r.note(&super::login::dry_run_session_note(
            crate::config_store::selected_account(&dir).as_deref(),
            &super::login::this_command(),
        ));
        if args.json {
            return write_json(out, &args.env, &args.name, &state_vault_id, created, &next);
        }
        return print_add(
            out,
            &args.env,
            &args.name,
            &place,
            &title,
            &state_vault_id,
            created,
            true,
            &next,
        );
    }

    // Creating the vault and writing the configuration write to 1Password: a person's own
    // session (FR-43). The target is validated before the vault is created.
    tidy::require_person(r, "opv target add")?;
    build(&title, &[])?;
    let notes = naming::state_vault_notes(&project, &args.env, &args.name);
    let vault = bootstrap::ensure_vault(r, &title, &notes)?;
    // Each placement's delivery item too (FR-58), so the first sync can record evidence
    // without another opv bootstrap: one command per intent (E2).
    let planned = store.parse(&build(&vault.id, &[])?)?;
    let items = bootstrap::placement_items(&planned, &project, &args.env, &args.name, r)?;
    let text = build(&vault.id, &items)?;
    config_store::save(store, r, &base, &text)?;
    if args.json {
        return write_json(out, &args.env, &args.name, &vault.id, false, &next);
    }
    print_add(
        out, &args.env, &args.name, &place, &title, &vault.id, false, false, &next,
    )
}

/// The provider named by `--provider`, or else the one provider whose options were given,
/// with the options checked against its [`InitField`]s: unknown option, another provider's
/// option, or a missing required one is refused (H3).
pub(crate) fn provider_and_values(
    args: &AddArgs,
) -> Result<(&'static dyn Provider, BTreeMap<&'static str, String>), Error> {
    let provider = match &args.provider {
        Some(named) => registry::find(named).ok_or_else(|| {
            usage(UsageProblem::ValueFormat {
                flag: format!("--provider {named}"),
                format: "a provider opv knows (opv target add --help lists them)",
            })
        })?,
        None => inferred_provider(args)?,
    };
    if provider.init_fields().is_empty() {
        return Err(by_hand());
    }
    let mut values = BTreeMap::new();
    for (flag, value) in &args.fields {
        let (owner, field) = find_field(flag).ok_or_else(|| {
            usage(UsageProblem::UnknownFlag {
                flag: format!("--{flag}"),
                closest: None,
            })
        })?;
        if owner.section() != provider.section() {
            return Err(usage(UsageProblem::ConflictsWith {
                a: format!("--{flag}"),
                b: format!("--provider {}", provider.section()),
            }));
        }
        values.insert(field.field, value.clone());
    }
    let missing: Vec<String> = provider
        .init_fields()
        .iter()
        .filter(|f| f.required && !values.contains_key(f.field))
        .map(|f| format!("--{}", init_flag(provider, f)))
        .collect();
    if !missing.is_empty() {
        return Err(usage(UsageProblem::NeedsFlag {
            flag: format!("--provider {}", provider.section()),
            needs: missing.join(", "),
        }));
    }
    Ok((provider, values))
}

/// The one provider whose options `args` gives, when `--provider` is omitted: none or
/// several are refused, naming what to pass.
fn inferred_provider(args: &AddArgs) -> Result<&'static dyn Provider, Error> {
    // Each provider whose option was given, with the first such flag.
    let mut owners: Vec<(&'static dyn Provider, &str)> = Vec::new();
    for flag in args.fields.keys() {
        if let Some((p, _)) = find_field(flag)
            && !owners.iter().any(|(o, _)| o.section() == p.section())
        {
            owners.push((p, flag));
        }
    }
    match owners.as_slice() {
        [(one, _)] => Ok(*one),
        [] => Err(usage(UsageProblem::NeedsFlag {
            flag: "opv target add".into(),
            needs: format!(
                "the target's provider options or --provider <{}>",
                registry::sections().join("|")
            ),
        })),
        [(_, a), (_, b), ..] => Err(usage(UsageProblem::ConflictsWith {
            a: format!("--{a}"),
            b: format!("--{b}"),
        })),
    }
}

/// The provider field flag `flag` (for example `fly-app`), across every registered
/// provider, with the provider that declared it.
fn find_field(flag: &str) -> Option<(&'static dyn Provider, &'static InitField)> {
    registry::PROVIDERS.iter().copied().find_map(|p| {
        p.init_fields()
            .iter()
            .find(|f| init_flag(p, f) == flag)
            .map(|f| (p, f))
    })
}

/// `--products`: each named product is declared and not source-only; duplicates dropped, the
/// order kept. Empty means the target delivers every product with a key in its environment
/// (FR-48). The loader checks the same rule; this names the flag.
pub(crate) fn checked_products(fleet: &Fleet, given: &[String]) -> Result<Vec<String>, Error> {
    let mut products: Vec<String> = Vec::new();
    for p in given {
        if products.iter().any(|q| q == p) {
            continue;
        }
        match fleet.products.get(p) {
            None => {
                return Err(super::not_declared(
                    NameKind::Product,
                    p,
                    fleet.products.keys().map(String::as_str),
                ));
            }
            Some(prod) if prod.source_only => {
                return Err(usage(UsageProblem::ValueFormat {
                    flag: format!("--products {p}"),
                    format: "delivered products (a source-only product is never delivered; name \
                             the products whose keys point at it with from)",
                }));
            }
            Some(_) => products.push(p.clone()),
        }
    }
    Ok(products)
}

/// The fragment inserting one target under `[environments.<env>.targets.<name>]`: the
/// provider's section, `products`, `roles`, `deploy_credentials` and `state_vault_id`, in
/// that order. `roles` are written as given, duplicates dropped; the loader checks them.
#[allow(clippy::too_many_arguments)]
pub(crate) fn target_table(
    env: &str,
    name: &str,
    section: &str,
    products: &[String],
    roles: &[String],
    deploy: Option<&str>,
    state_vault_id: Option<&str>,
    items: &[(String, String)],
) -> String {
    let mut s = format!("[environments.{env}.targets.{name}]\n");
    s.push_str(section);
    if !products.is_empty() {
        let list: Vec<String> = products
            .iter()
            .map(|p| toml::Value::String(p.clone()).to_string())
            .collect();
        s.push_str(&format!("products = [{}]\n", list.join(", ")));
    }
    if !roles.is_empty() {
        let mut list: Vec<String> = Vec::new();
        for r in roles {
            let quoted = toml::Value::String(r.clone()).to_string();
            if !list.contains(&quoted) {
                list.push(quoted);
            }
        }
        s.push_str(&format!("roles = [{}]\n", list.join(", ")));
    }
    if let Some(d) = deploy {
        s.push_str(&format!(
            "deploy_credentials = {}\n",
            toml::Value::String(d.to_string())
        ));
    }
    // None: declared only; the approved structural plan creates the state vault (#133).
    if let Some(id) = state_vault_id {
        s.push_str(&format!(
            "state_vault_id = {}\n",
            toml::Value::String(id.to_string())
        ));
    }
    if !items.is_empty() {
        let entries: Vec<String> = items
            .iter()
            .map(|(p, id)| format!("{p} = {}", toml::Value::String(id.clone())))
            .collect();
        s.push_str(&format!("delivery_items = {{ {} }}\n", entries.join(", ")));
    }
    s
}

/// `original` with the target inserted, keeping every existing comment and line. `body` is
/// the TOML fragment [`target_table`] built; `comment` is the one-line note above the new
/// table. Its refusals name the configuration as `secrets.toml`; [`insert_target_in`] names
/// the source it came from.
pub(crate) fn insert_target(
    original: &str,
    env: &str,
    name: &str,
    body: &str,
    comment: &str,
) -> Result<String, Error> {
    let source = crate::domain::model::ReadFrom::default().0;
    insert_target_in(original, &source, env, name, body, comment)
}

/// [`insert_target`] for the configuration `source`. An unknown environment or a `targets`
/// written in a shape opv does not edit is refused with the reason (R15, 06.27); a parse
/// error never shows the offending line (06.53).
pub(crate) fn insert_target_in(
    original: &str,
    source: &ConfigSource,
    env: &str,
    name: &str,
    body: &str,
    comment: &str,
) -> Result<String, Error> {
    let mut doc: DocumentMut = original
        .parse()
        .map_err(|e: toml_edit::TomlError| -> Error {
            Cause::ConfigInvalid {
                source: source.clone(),
                at: config_store::location(original, e.span()),
                field: DottedPath(vec!["the TOML".into()]),
                rule: FieldRule::Syntax,
            }
            .into()
        })?;
    let frag: DocumentMut = body
        .parse()
        .map_err(|_| bug("target_cmd::insert_target fragment"))?;
    let Some(mut table) = frag
        .get("environments")
        .and_then(|e| e.get(env))
        .and_then(|t| t.get("targets"))
        .and_then(|t| t.get(name))
        .and_then(Item::as_table)
        .cloned()
    else {
        return Err(bug("target_cmd::insert_target fragment table"));
    };
    clear_positions(&mut table);
    table.set_implicit(false);
    table.decor_mut().set_prefix(format!("\n{comment}\n"));
    let envs = doc
        .get_mut("environments")
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| not_editable(source, "environments".into()))?;
    if envs.get(env).is_none() {
        let declared: Vec<String> = envs.iter().map(|(k, _)| k.to_string()).collect();
        return Err(super::not_declared(
            NameKind::Environment,
            env,
            declared.iter().map(String::as_str),
        ));
    }
    let env_tbl = envs
        .get_mut(env)
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| not_editable(source, format!("environments.{env}")))?;
    let targets_section = format!("environments.{env}.targets");
    match env_tbl.get("targets") {
        None => {
            let mut t = Table::new();
            t.set_implicit(true);
            env_tbl.insert("targets", Item::Table(t));
        }
        Some(Item::Table(t)) if t.contains_key(name) => return Err(exists(env, name)),
        Some(Item::Table(_)) => {}
        // An inline table or any other value: written by hand (06.27).
        Some(_) => return Err(not_editable(source, targets_section)),
    }
    let targets = env_tbl
        .get_mut("targets")
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| not_editable(source, targets_section.clone()))?;
    if targets.contains_key(name) {
        return Err(exists(env, name));
    }
    targets.insert(name, Item::Table(table));
    Ok(doc.to_string())
}

/// A table moved from another document takes its place from where it is inserted.
fn clear_positions(t: &mut Table) {
    t.set_position(None);
    for (_, v) in t.iter_mut() {
        if let Item::Table(sub) = v {
            clear_positions(sub);
        }
    }
}

/// `target add --json` (A5): what was written, names and the state vault's ID only.
fn write_json(
    out: &mut dyn Write,
    env: &str,
    target: &str,
    state_vault_id: &str,
    created_state_vault: bool,
    next: &str,
) -> Result<(), Error> {
    let doc = serde_json::json!({
        "schema_version": crate::json::SCHEMA_VERSION,
        "environment": env,
        "target": target,
        "state_vault_id": state_vault_id,
        "created_state_vault": created_state_vault,
        "next": next,
    });
    writeln!(out, "{doc}").map_err(write_err)
}

/// `target add` text: what was written, the state vault, and the next step.
#[allow(clippy::too_many_arguments)]
fn print_add(
    out: &mut dyn Write,
    env: &str,
    name: &str,
    place: &str,
    title: &str,
    state_vault_id: &str,
    created: bool,
    dry_run: bool,
    next: &str,
) -> Result<(), Error> {
    let w = |out: &mut dyn Write, s: String| writeln!(out, "{s}").map_err(write_err);
    if dry_run {
        w(
            out,
            format!("would add [environments.{env}.targets.{name}] to {place}"),
        )?;
        if created {
            w(out, format!("would create state vault {title}"))?;
        } else {
            w(
                out,
                format!("would reuse state vault {title} ({state_vault_id})"),
            )?;
        }
    } else {
        w(
            out,
            format!("added [environments.{env}.targets.{name}] to {place}"),
        )?;
        if created {
            w(
                out,
                format!("created state vault {title} ({state_vault_id})"),
            )?;
        } else {
            w(
                out,
                format!("reusing state vault {title} ({state_vault_id})"),
            )?;
        }
    }
    w(out, format!("Next: {next}"))
}

/// `opv target list` (FR-56): read-only. One line per target, in environment then name
/// order; `--json` instead prints an array of `{environment, name, provider, locator,
/// products, deploy_credentials}`. Never a value (SR-1).
pub fn list(fleet: &Fleet, args: &ListArgs, out: &mut dyn Write) -> Result<(), Error> {
    let envs: Vec<&crate::domain::Environment> = match &args.env {
        Some(e) => vec![fleet.environment(e)?],
        None => fleet.environments.values().collect(),
    };
    if args.json {
        let rows: Vec<serde_json::Value> = envs
            .iter()
            .flat_map(|env| {
                env.targets.iter().map(move |(name, t)| {
                    serde_json::json!({
                        "environment": env.name,
                        "name": name,
                        "provider": t.config.provider().section(),
                        "locator": t.config.target_locator(),
                        "products": match &t.products {
                            Some(list) => serde_json::json!(list),
                            None => serde_json::json!("all"),
                        },
                        "deploy_credentials": t.deploy_credentials.is_some(),
                    })
                })
            })
            .collect();
        return writeln!(out, "{}", serde_json::Value::Array(rows)).map_err(write_err);
    }
    let mut any = false;
    for env in &envs {
        for (name, t) in &env.targets {
            any = true;
            let products = match &t.products {
                Some(list) => list.join(","),
                None => "all".to_string(),
            };
            let deploy = if t.deploy_credentials.is_some() {
                "set"
            } else {
                "none"
            };
            writeln!(
                out,
                "{} {} {} {} products: {} deploy_credentials: {}",
                env.name,
                name,
                t.config.provider().section(),
                t.config.target_locator(),
                products,
                deploy,
            )
            .map_err(write_err)?;
        }
    }
    if !any {
        // Which scope is empty, and the command that adds a target to it (06.44).
        let scope = match &args.env {
            Some(e) => format!("environment {e} has no deploy targets"),
            None => "no environment declares a deploy target".to_string(),
        };
        writeln!(out, "{scope}").map_err(write_err)?;
        writeln!(
            out,
            "Next: {}",
            crate::cause::render::cmd_text(&opv(&["target", "add"], &["--help"]))
        )
        .map_err(write_err)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "target_cmd_tests.rs"]
mod tests;
