//! `opv target add` and `opv target list` (FR-56, `docs/design/placements-and-access-boundaries.md`
//! §5.2).
//!
//! `target add` declares one named target under `[environments.<env>.targets.<name>]`: the
//! provider's section (the same options and validation `opv init --target` uses, through the
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

use toml_edit::{DocumentMut, Item, Table, Value};

use super::write_err;
use crate::adapters::onepassword_init::{self as init_op, Lookup};
use crate::adapters::registry;
use crate::app::{bootstrap, personal, tidy};
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

fn cfg(msg: String) -> Error {
    Error::Config(msg.into())
}

/// `opv target add` (FR-56): a refusal names its own next step unless it has one.
pub fn add(
    args: &AddArgs,
    store: &dyn ConfigStore,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    add_inner(args, store, r, out).map_err(|e| match e {
        e @ Error::Config(_) => e.or_next(|| "opv target add --help".into()),
        other => other,
    })
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
    let fleet = store.parse(original).map_err(|e| match e {
        e @ Error::Config(_) => e
            .map_text(|m| super::on_first_line(&m, " (fix it first; nothing written)"))
            .or_next(|| "opv config edit".into()),
        other => other,
    })?;
    let environment = fleet.environment(&args.env)?;
    if !config::is_target_name(&args.name) {
        return Err(cfg(format!(
            "target name {:?} must match ^[a-z][a-z0-9-]*$",
            args.name
        )));
    }
    if environment.targets.contains_key(&args.name) {
        return Err(cfg(format!(
            "environment {}: target {} already exists; opv target add only adds new targets: \
             change it in {place} by hand (opv config edit)",
            args.env, args.name
        )));
    }
    let (provider, values) = provider_and_values(args)?;
    let section = provider.init_section(&values).ok_or_else(|| {
        cfg(format!(
            "opv target add cannot write a {} target yet; add [environments.{}.targets.{}] by \
             hand",
            provider.label(),
            args.env,
            args.name
        ))
    })?;
    let products = checked_products(&fleet, &args.products)?;

    let dir = std::env::current_dir()
        .map_err(|e| Error::Config(format!("cannot read the current directory: {e}").into()))?;
    let project = match &args.project {
        Some(p) => {
            if !config_store::is_project_name(p) {
                return Err(cfg(format!(
                    "--project {p:?} must match ^[A-Za-z0-9][A-Za-z0-9._-]*$ (at most 64 \
                     characters)"
                )));
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
            args.deploy_credentials.as_deref(),
            state_vault_id,
            items,
        );
        let text = insert_target(original, &args.env, &args.name, &body, &comment)?;
        // The same validation as a hand-written file: provider fields, products, deploy
        // credentials and the state vault, before anything is written or created.
        store.parse(&text).map_err(|e| match e {
            e @ Error::Config(_) => e.map_text(|m| {
                format!("{m} (in the configuration opv target add would write; nothing written)")
            }),
            other => other,
        })?;
        Ok(text)
    };
    let next = format!("opv access {} --target {}", args.env, args.name);

    if args.dry_run {
        // Read-only: report whether the state vault would be created or reused.
        let (state_vault_id, created) = match init_op::find_vault(r, &title, &Host::detect)? {
            Lookup::Found(n) => (n.id, false),
            Lookup::Missing(_) => (title.clone(), true),
        };
        build(&state_vault_id, &[])?;
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
/// option, or a missing required one is refused, exactly as `opv init --target` does (H3).
fn provider_and_values(
    args: &AddArgs,
) -> Result<(&'static dyn Provider, BTreeMap<&'static str, String>), Error> {
    let provider = match &args.provider {
        Some(named) => registry::find(named).ok_or_else(|| {
            cfg(format!(
                "--provider {named:?} is not a provider; known: {}",
                registry::sections().join(", ")
            ))
        })?,
        None => inferred_provider(args)?,
    };
    if provider.init_fields().is_empty() {
        return Err(cfg(format!(
            "opv target add cannot write a {} target yet; add [environments.{}.targets.{}] by \
             hand",
            provider.label(),
            args.env,
            args.name
        )));
    }
    let mut values = BTreeMap::new();
    for (flag, value) in &args.fields {
        let (owner, field) = find_field(flag).ok_or_else(|| {
            cfg(format!(
                "unknown target option --{flag} (opv target add --help lists every option)"
            ))
        })?;
        if owner.section() != provider.section() {
            return Err(cfg(format!(
                "--{flag} is an option of --provider {}, not {}",
                owner.section(),
                provider.section()
            )));
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
        return Err(cfg(format!(
            "--provider {} needs {}",
            provider.section(),
            missing.join(", ")
        )));
    }
    Ok((provider, values))
}

/// The one provider whose options `args` gives, when `--provider` is omitted: none or
/// several are refused, naming what to pass.
fn inferred_provider(args: &AddArgs) -> Result<&'static dyn Provider, Error> {
    let mut owners: Vec<&'static dyn Provider> = Vec::new();
    for flag in args.fields.keys() {
        if let Some((p, _)) = find_field(flag)
            && !owners.iter().any(|o| o.section() == p.section())
        {
            owners.push(p);
        }
    }
    match owners.as_slice() {
        [one] => Ok(*one),
        [] => Err(cfg(format!(
            "opv target add needs the target's provider options (opv target add --help lists \
             them) or --provider <{}>",
            registry::sections().join("|")
        ))),
        _ => Err(cfg(format!(
            "the options given belong to {} providers ({}); a target has one provider",
            owners.len(),
            owners
                .iter()
                .map(|p| p.section())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
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
fn checked_products(fleet: &Fleet, given: &[String]) -> Result<Vec<String>, Error> {
    let mut products: Vec<String> = Vec::new();
    for p in given {
        if products.iter().any(|q| q == p) {
            continue;
        }
        match fleet.products.get(p) {
            None => {
                let declared: Vec<&str> = fleet.products.keys().map(String::as_str).collect();
                return Err(cfg(format!(
                    "--products names {p:?}, which is not a declared product (declared: {})",
                    declared.join(", ")
                )));
            }
            Some(prod) if prod.source_only => {
                return Err(cfg(format!(
                    "--products names {p:?}, which is source-only and never delivered; list the \
                     products whose keys point at it with from instead"
                )));
            }
            Some(_) => products.push(p.clone()),
        }
    }
    Ok(products)
}

/// The fragment inserting one target under `[environments.<env>.targets.<name>]`: the
/// provider's section, `products`, `deploy_credentials` and `state_vault_id`, in that order.
fn target_table(
    env: &str,
    name: &str,
    section: &str,
    products: &[String],
    deploy: Option<&str>,
    state_vault_id: &str,
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
    if let Some(d) = deploy {
        s.push_str(&format!(
            "deploy_credentials = {}\n",
            toml::Value::String(d.to_string())
        ));
    }
    s.push_str(&format!(
        "state_vault_id = {}\n",
        toml::Value::String(state_vault_id.to_string())
    ));
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
/// table. An unknown environment or a `targets` written in a shape opv does not edit is
/// refused with the reason.
fn insert_target(
    original: &str,
    env: &str,
    name: &str,
    body: &str,
    comment: &str,
) -> Result<String, Error> {
    let mut doc: DocumentMut = original
        .parse()
        .map_err(|e: toml_edit::TomlError| cfg(format!("invalid secrets.toml: {e}")))?;
    let frag: DocumentMut = body
        .parse()
        .map_err(|e: toml_edit::TomlError| cfg(format!("invalid target section: {e}")))?;
    let Some(mut table) = frag
        .get("environments")
        .and_then(|e| e.get(env))
        .and_then(|t| t.get("targets"))
        .and_then(|t| t.get(name))
        .and_then(Item::as_table)
        .cloned()
    else {
        return Err(cfg(format!("invalid target section for {name}")));
    };
    clear_positions(&mut table);
    table.set_implicit(false);
    table.decor_mut().set_prefix(format!("\n{comment}\n"));
    let envs = doc
        .get_mut("environments")
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| {
            cfg(
                "cannot add under environments: the file writes it in a shape opv does not edit"
                    .into(),
            )
        })?;
    let Some(env_item) = envs.get_mut(env) else {
        return Err(cfg(format!(
            "no environment {env} in the configuration; add it with opv init {env} --add-env \
             first"
        )));
    };
    let env_tbl = env_item
        .as_table_like_mut()
        .ok_or_else(|| cfg(format!("environment {env} is not a table")))?;
    enum Where {
        Missing,
        Table,
        Inline,
        Other,
    }
    let where_ = match env_tbl.get("targets") {
        None => Where::Missing,
        Some(Item::Table(t)) => {
            if t.contains_key(name) {
                return Err(cfg(format!(
                    "environment {env}: target {name} already exists"
                )));
            }
            Where::Table
        }
        Some(Item::Value(Value::InlineTable(_))) => Where::Inline,
        Some(_) => Where::Other,
    };
    match where_ {
        Where::Missing => {
            let mut t = Table::new();
            t.set_implicit(true);
            env_tbl.insert("targets", Item::Table(t));
        }
        Where::Inline => {
            return Err(cfg(format!(
                "environment {env}: targets is written as an inline table; write each target as \
                 [environments.{env}.targets.<name>] by hand (opv config edit)"
            )));
        }
        Where::Other => {
            return Err(cfg(format!(
                "environment {env}: targets is not a table; opv does not edit this shape"
            )));
        }
        Where::Table => {}
    }
    let targets = env_tbl
        .get_mut("targets")
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| cfg(format!("environment {env}: targets is not a table")))?;
    if targets.contains_key(name) {
        return Err(cfg(format!(
            "environment {env}: target {name} already exists"
        )));
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
        writeln!(out, "no deploy targets declared").map_err(write_err)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "target_cmd_tests.rs"]
mod tests;
