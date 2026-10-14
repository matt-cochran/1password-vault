//! `opv bootstrap` (FR-52, #77): take a configuration from declared to ready in the selected
//! 1Password account. It records every missing ID, and nothing else: per environment, each
//! needed boundary (FR-57) without `boundaries.<b>` gets its vault and item found or created
//! by their conventional titles, and each target without `state_vault_id` gets its state
//! vault (FR-58). Then every declared field is added, empty (`item skeleton`). Nothing is
//! synced or deployed, and no value is read or written.
//!
//! It works on the raw document (comments and order kept), so it can complete a file the
//! strict loader still refuses for want of those IDs; the loader is the authority for the
//! result. Recorded IDs the selected account cannot see are never replaced silently
//! (`ids_not_in_account`): `--rebind <env>` asks for new boundary IDs.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;

use serde::Serialize;
use serde_json::json;
use toml_edit::{DocumentMut, InlineTable, Item, Table, value};

use super::write_err;
use crate::adapters::onepassword_init::{self as init_op, Lookup};
use crate::domain::{access_plan, naming};
use crate::error::Error;
use crate::host::Host;
use crate::runner::{Call, CommandRunner, Outcome, PROBE_TIMEOUT};

/// What bootstrap does for one boundary of an environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum BoundaryStep {
    /// The recorded vault is in the selected account.
    Ok { vault_id: String, item_id: String },
    /// Not recorded (or `--rebind`): find or create these, then record their IDs.
    Create { vault: String, item: String },
    /// A recorded vault the selected account cannot see; nothing is done.
    IdsNotInAccount { vault_id: String },
}

/// What bootstrap does for one target's state vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum StateStep {
    /// The recorded state vault is in the selected account.
    Ok { vault_id: String },
    /// No `state_vault_id`: find or create this vault, then record its ID.
    Create { vault: String },
    /// A recorded state vault the selected account cannot see; nothing is done.
    IdsNotInAccount { vault_id: String },
}

/// One needed boundary and its step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BoundaryPlan {
    pub boundary: String,
    /// The products whose values the boundary holds in this environment, sorted.
    pub products: Vec<String>,
    #[serde(flatten)]
    pub step: BoundaryStep,
}

/// One target's state vault and its step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatePlan {
    pub target: String,
    #[serde(flatten)]
    pub step: StateStep,
}

/// One environment's steps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnvPlan {
    pub environment: String,
    pub boundaries: Vec<BoundaryPlan>,
    pub state_vaults: Vec<StatePlan>,
}

/// Options of `opv bootstrap`.
#[derive(Debug, Default, Clone)]
pub struct Opts {
    /// Print the plan only.
    pub dry_run: bool,
    /// Environments whose recorded boundary IDs are replaced by ones in the selected account.
    pub rebind: BTreeSet<String>,
    /// Print the owner's command for a read-only CI service account for this environment.
    pub ci_reader: Option<String>,
    pub json: bool,
}

fn parse_doc(text: &str) -> Result<DocumentMut, Error> {
    text.parse().map_err(|e: toml_edit::TomlError| {
        Error::Config(format!("secrets.toml is not valid TOML ({e}).").into())
            .with_next("opv config edit")
    })
}

fn str_at<'a>(t: &'a dyn toml_edit::TableLike, key: &str) -> Option<&'a str> {
    t.get(key).and_then(Item::as_str)
}

/// The boundary of `product` in the raw document: its `boundary`, else its own name.
fn boundary_of(doc: &DocumentMut, product: &str) -> String {
    doc.get("products")
        .and_then(Item::as_table_like)
        .and_then(|p| p.get(product))
        .and_then(Item::as_table_like)
        .and_then(|p| str_at(p, "boundary"))
        .unwrap_or(product)
        .to_string()
}

/// The boundaries `env` needs, each with the products it holds there (FR-57): the boundary
/// of every product with a team (non-personal) key desired in `env`, and of every product
/// such a key reads with `from`.
fn needed_boundaries(doc: &DocumentMut, env: &str) -> BTreeMap<String, BTreeSet<String>> {
    let mut needed: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let Some(products) = doc.get("products").and_then(Item::as_table_like) else {
        return needed;
    };
    for (product, p) in products.iter() {
        let Some(keys) = p
            .as_table_like()
            .and_then(|p| p.get("keys"))
            .and_then(Item::as_table_like)
        else {
            continue;
        };
        for (_, k) in keys.iter() {
            let Some(k) = k.as_table_like() else { continue };
            let personal = k.get("personal").and_then(Item::as_bool).unwrap_or(false);
            let desired = k
                .get("environments")
                .and_then(Item::as_array)
                .is_some_and(|a| a.iter().any(|e| e.as_str() == Some(env)));
            if personal || !desired {
                continue;
            }
            let source = str_at(k, "from")
                .and_then(|f| f.split_once('/'))
                .map(|(sp, _)| sp);
            for needer in std::iter::once(product).chain(source) {
                needed
                    .entry(boundary_of(doc, needer))
                    .or_default()
                    .insert(needer.to_string());
            }
        }
    }
    needed
}

/// The environments of the raw document, in file order.
fn environment_names(doc: &DocumentMut) -> Result<Vec<String>, Error> {
    let envs = doc
        .get("environments")
        .and_then(Item::as_table_like)
        .ok_or_else(|| {
            Error::Config("secrets.toml declares no environment.".into())
                .with_next("opv init <env>")
        })?;
    Ok(envs.iter().map(|(name, _)| name.to_string()).collect())
}

fn env_table<'a>(doc: &'a DocumentMut, env: &str) -> Option<&'a dyn toml_edit::TableLike> {
    doc.get("environments")?
        .as_table_like()?
        .get(env)?
        .as_table_like()
}

/// The recorded `boundaries.<b>` of `env`, if both IDs are there.
fn recorded_boundary(doc: &DocumentMut, env: &str, b: &str) -> Option<(String, String)> {
    let at = env_table(doc, env)?
        .get("boundaries")?
        .as_table_like()?
        .get(b)?
        .as_table_like()?;
    Some((
        str_at(at, "vault_id")?.to_string(),
        str_at(at, "item_id")?.to_string(),
    ))
}

/// The targets of `env` in file order, with their recorded `state_vault_id`.
fn targets(doc: &DocumentMut, env: &str) -> Vec<(String, Option<String>)> {
    env_table(doc, env)
        .and_then(|e| e.get("targets"))
        .and_then(Item::as_table_like)
        .map(|ts| {
            ts.iter()
                .map(|(name, t)| {
                    let id = t
                        .as_table_like()
                        .and_then(|t| str_at(t, "state_vault_id"))
                        .map(str::to_string);
                    (name.to_string(), id)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Whether `vault_id` is a vault the signed-in account can see: `op vault get`, exit status
/// only (its output names the vault and is dropped unread). `None`: cannot tell.
fn vault_visible(r: &dyn CommandRunner, vault_id: &str) -> Option<bool> {
    r.probe(
        &Call::new("op", &["vault", "get", vault_id, "--format", "json"]),
        PROBE_TIMEOUT,
    )
    .ok()
    .map(|o| o.status == 0)
}

/// The plan for every environment of `text` (read-only: one `op vault get` per recorded
/// vault).
pub fn plan(
    r: &dyn CommandRunner,
    text: &str,
    project: &str,
    rebind: &BTreeSet<String>,
) -> Result<Vec<EnvPlan>, Error> {
    let doc = parse_doc(text)?;
    let envs = environment_names(&doc)?;
    if let Some(env) = rebind.iter().find(|e| !envs.contains(e)) {
        return Err(no_such_environment("--rebind", env));
    }
    let mut plans = Vec::new();
    for env in envs {
        let boundaries = needed_boundaries(&doc, &env)
            .into_iter()
            .map(|(b, products)| {
                let step = match recorded_boundary(&doc, &env, &b) {
                    Some((v, i)) if !rebind.contains(&env) => match vault_visible(r, &v) {
                        Some(false) => BoundaryStep::IdsNotInAccount { vault_id: v },
                        _ => BoundaryStep::Ok {
                            vault_id: v,
                            item_id: i,
                        },
                    },
                    _ => BoundaryStep::Create {
                        vault: naming::boundary_vault(project, &b, &env),
                        item: naming::boundary_item(project, &b, &env),
                    },
                };
                BoundaryPlan {
                    boundary: b,
                    products: products.into_iter().collect(),
                    step,
                }
            })
            .collect();
        let state_vaults = targets(&doc, &env)
            .into_iter()
            .map(|(t, id)| {
                let step = match id {
                    Some(v) => match vault_visible(r, &v) {
                        Some(false) => StateStep::IdsNotInAccount { vault_id: v },
                        _ => StateStep::Ok { vault_id: v },
                    },
                    None => StateStep::Create {
                        vault: naming::state_vault(project, &env, &t),
                    },
                };
                StatePlan { target: t, step }
            })
            .collect();
        plans.push(EnvPlan {
            environment: env,
            boundaries,
            state_vaults,
        });
    }
    Ok(plans)
}

/// A file whose first line says it is generated is never rewritten (FR-52).
fn is_generated(text: &str) -> bool {
    text.lines().next().is_some_and(|l| {
        l.trim_start()
            .to_ascii_lowercase()
            .starts_with("# generated")
    })
}

/// One `op ... create` write, never retried (NR-2): the new object's ID, checked like a
/// hand-written ID (SR-7).
fn create(
    r: &dyn CommandRunner,
    args: &[&str],
    stdin: Option<&[u8]>,
    what: &str,
    title: &str,
) -> Result<init_op::Named, Error> {
    let failed = || {
        Error::Source(format!("1Password did not create the {what} {title:?}.").into())
            .with_do(format!(
                "create the {what} {title:?} in the 1Password app (or ask an admin), then re-run \
                 opv bootstrap; it finds the {what} by its title"
            ))
            .with_next("opv bootstrap")
    };
    let call = Call::new("op", args).with_stdin(stdin);
    let Ok(Outcome::Done(out)) = r.write(&call) else {
        return Err(failed());
    };
    let id = serde_json::from_slice::<serde_json::Value>(&out.stdout)
        .ok()
        .and_then(|v| v["id"].as_str().map(str::to_string))
        .filter(|id| crate::config::is_id(id))
        .ok_or_else(failed)?;
    Ok(init_op::Named {
        id,
        name: title.to_string(),
    })
}

/// The vault titled `title` in the signed-in account, created with the description `notes`
/// when missing.
fn ensure_vault(r: &dyn CommandRunner, title: &str, notes: &str) -> Result<init_op::Named, Error> {
    match init_op::find_vault(r, title, &Host::detect)? {
        Lookup::Found(n) => Ok(n),
        Lookup::Missing(_) => create(
            r,
            &[
                "vault",
                "create",
                title,
                "--description",
                notes,
                "--format",
                "json",
            ],
            None,
            "vault",
            title,
        ),
    }
}

/// The item titled `title` in `vault_id`, created when missing as an empty Secure Note with
/// `notes` and tagged `tag` (FR-55), so `ready` can tell an item moved or wired to another
/// environment.
fn ensure_item(
    r: &dyn CommandRunner,
    vault_id: &str,
    title: &str,
    tag: &str,
    notes: &str,
) -> Result<init_op::Named, Error> {
    if let Lookup::Found(n) = init_op::find_item(r, vault_id, title, &Host::detect)? {
        return Ok(n);
    }
    let mut fields = Vec::new();
    if !notes.is_empty() {
        fields.push(json!({
            "id": "notesPlain", "type": "STRING", "purpose": "NOTES", "label": "notesPlain",
            "value": notes,
        }));
    }
    let template = serde_json::to_vec(&json!({
        "category": "SECURE_NOTE", "fields": fields, "sections": [], "tags": [tag],
    }))
    .expect("a fixed template serializes");
    let args = [
        "item", "create", "-", "--vault", vault_id, "--title", title, "--format", "json",
    ];
    create(r, &args, Some(&template), "item", title)
}

/// The detection tag of an environment's item (FR-55).
pub fn env_tag(project: &str, env: &str) -> String {
    format!("opv-env:{project}/{env}")
}

/// An ID bootstrap records, by where it goes in the document.
enum Recorded {
    Boundary {
        env: String,
        boundary: String,
        vault_id: String,
        item_id: String,
    },
    StateVault {
        env: String,
        target: String,
        vault_id: String,
    },
}

impl Recorded {
    fn line(&self) -> String {
        match self {
            Recorded::Boundary {
                env,
                boundary,
                vault_id,
                item_id,
            } => format!(
                "[environments.{env}] boundaries.{boundary} = {{ vault_id = {vault_id:?}, \
                 item_id = {item_id:?} }}"
            ),
            Recorded::StateVault {
                env,
                target,
                vault_id,
            } => format!("[environments.{env}.targets.{target}] state_vault_id = {vault_id:?}"),
        }
    }

    /// Write this ID into the raw document (comments and order kept).
    fn write(&self, doc: &mut DocumentMut) {
        match self {
            Recorded::Boundary {
                env,
                boundary,
                vault_id,
                item_id,
            } => {
                let e = &mut doc["environments"][env.as_str()];
                if let Some(t) = e.as_table_mut() {
                    t.set_implicit(false);
                }
                let Some(e) = e.as_table_like_mut() else {
                    return;
                };
                if e.get("boundaries").is_none() {
                    let mut t = Table::new();
                    t.set_dotted(true);
                    e.insert("boundaries", Item::Table(t));
                }
                let mut at = InlineTable::new();
                at.insert("vault_id", vault_id.as_str().into());
                at.insert("item_id", item_id.as_str().into());
                if let Some(bs) = e.get_mut("boundaries").and_then(Item::as_table_like_mut) {
                    bs.insert(boundary, Item::Value(at.into()));
                }
            }
            Recorded::StateVault {
                env,
                target,
                vault_id,
            } => {
                if let Some(t) = doc["environments"][env.as_str()]["targets"][target.as_str()]
                    .as_table_like_mut()
                {
                    t.insert("state_vault_id", value(vault_id.as_str()));
                }
            }
        }
    }
}

/// A placeholder ID for each ID bootstrap would record, so the loader can judge the result
/// before anything is created.
fn placeholders(plans: &[EnvPlan]) -> Vec<Recorded> {
    let mut out = Vec::new();
    for p in plans {
        for b in &p.boundaries {
            if matches!(b.step, BoundaryStep::Create { .. }) {
                out.push(Recorded::Boundary {
                    env: p.environment.clone(),
                    boundary: b.boundary.clone(),
                    vault_id: format!("vpending-{}-{}", p.environment, b.boundary),
                    item_id: format!("ipending-{}-{}", p.environment, b.boundary),
                });
            }
        }
        for s in &p.state_vaults {
            if matches!(s.step, StateStep::Create { .. }) {
                out.push(Recorded::StateVault {
                    env: p.environment.clone(),
                    target: s.target.clone(),
                    vault_id: format!("vpending-{}-{}-state", p.environment, s.target),
                });
            }
        }
    }
    out
}

/// `opv bootstrap` on the configuration file `path`.
pub fn run(
    path: &Path,
    project: &str,
    opts: &Opts,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        Error::Config(format!("Cannot read {} ({}).", path.display(), e.kind()).into())
            .with_next("opv init <env>")
    })?;
    let plans = plan(r, &text, project, &opts.rebind)?;
    if let Some(env) = &opts.ci_reader
        && !plans.iter().any(|p| &p.environment == env)
    {
        return Err(no_such_environment("--ci-reader", env));
    }
    if let Some(e) = first_stale(&plans) {
        print_plan(out, &plans, opts.json, false)?;
        return Err(e);
    }
    if opts.dry_run {
        return print_plan(out, &plans, opts.json, false);
    }
    let doc = parse_doc(&text)?;
    // Fail fast: the loader judges the completed file before anything is created.
    let mut trial = doc.clone();
    for id in placeholders(&plans) {
        id.write(&mut trial);
    }
    crate::config::parse(&trial.to_string())?;
    // Creating vaults and items and adding fields write to 1Password: a person's own
    // session, never a service account (FR-43).
    super::tidy::require_person(r, "opv bootstrap")?;
    let mut recorded = Vec::new();
    for p in &plans {
        let env = &p.environment;
        for b in &p.boundaries {
            let BoundaryStep::Create { vault, item } = &b.step else {
                continue;
            };
            let products: Vec<&str> = b.products.iter().map(String::as_str).collect();
            let notes = naming::boundary_notes(project, env, &products);
            let v = ensure_vault(r, vault, &notes)?;
            let i = ensure_item(r, &v.id, item, &env_tag(project, env), &notes)?;
            recorded.push(Recorded::Boundary {
                env: env.clone(),
                boundary: b.boundary.clone(),
                vault_id: v.id,
                item_id: i.id,
            });
        }
        for s in &p.state_vaults {
            let StateStep::Create { vault } = &s.step else {
                continue;
            };
            let notes = naming::state_vault_notes(project, env, &s.target);
            let v = ensure_vault(r, vault, &notes)?;
            recorded.push(Recorded::StateVault {
                env: env.clone(),
                target: s.target.clone(),
                vault_id: v.id,
            });
        }
    }
    let mut doc = doc;
    for id in &recorded {
        id.write(&mut doc);
    }
    let new_text = doc.to_string();
    // The result loads like any hand-written file before it replaces it.
    let fleet = crate::config::parse(&new_text)?;
    if !recorded.is_empty() {
        if is_generated(&text) {
            print_plan(out, &plans, opts.json, false)?;
            let ids: Vec<String> = recorded.iter().map(Recorded::line).collect();
            return Err(Error::Policy(
                format!(
                    "{} is generated, so opv does not rewrite it; record these IDs in its \
                     generator's input:\n  {}",
                    path.display(),
                    ids.join("\n  ")
                )
                .into(),
            )
            .with_code(crate::error::Code::PolicyRefused)
            .with_next("opv bootstrap --dry-run"));
        }
        super::init::write_atomic(path, &new_text, true)?;
    }
    // Every declared field, empty, in each boundary item.
    for p in &plans {
        super::skeleton::run_as(&fleet, &p.environment, r, &mut std::io::sink(), false)?;
    }
    let personal_items = personal_items(&fleet, project, &plans, r)?;
    print_plan(out, &plans, opts.json, true)?;
    if opts.json {
        return Ok(());
    }
    for line in &personal_items {
        writeln!(out, "{line}").map_err(write_err)?;
    }
    writeln!(
        out,
        "every environment has its boundary vaults, items, state vaults and empty fields; fill \
         the values in 1Password, then check what is left"
    )
    .map_err(write_err)?;
    if let Some(env) = &opts.ci_reader {
        ci_reader_steps(out, &fleet, project, env)?;
    }
    writeln!(out, "Next: opv ready").map_err(write_err)
}

/// FR-55: the signed-in person's own item, with empty fields for the personal keys, in
/// their own vault; nobody else's. One line per item for the receipt.
fn personal_items(
    fleet: &crate::domain::Fleet,
    project: &str,
    plans: &[EnvPlan],
    r: &dyn CommandRunner,
) -> Result<Vec<String>, Error> {
    let mut lines = Vec::new();
    for p in plans {
        let env_name = &p.environment;
        if !super::personal::declared(fleet, env_name) {
            continue;
        }
        let team = fleet.environment(env_name)?;
        let Some(vault) = super::personal::private_vault(r, team)? else {
            return Err(Error::Config(
                format!(
                    "Environment {env_name} has personal keys, but no personal vault was found \
                     (looked for {}).",
                    team.personal_vault
                        .clone()
                        .unwrap_or_else(|| "Private, Employee, Personal".into())
                )
                .into(),
            )
            .with_do("set personal_vault to the title of a vault only you can open")
            .with_next("opv bootstrap"));
        };
        let title = super::personal::item_title(team, project);
        let item = ensure_item(r, &vault.id, &title, &env_tag(project, env_name), "")?;
        let mut mine = super::personal::personal_fleet(fleet, env_name);
        // Every product's boundary is the personal item here (FR-55).
        let names: Vec<String> = mine
            .products
            .keys()
            .map(|p| mine.boundary_of(p).to_string())
            .collect();
        if let Some(e) = mine.environments.get_mut(env_name.as_str()) {
            e.boundaries = names
                .into_iter()
                .map(|b| {
                    let at = crate::domain::Boundary {
                        vault_id: vault.id.clone(),
                        item_id: item.id.clone(),
                    };
                    (b, at)
                })
                .collect();
        }
        super::skeleton::run_as(&mine, env_name, r, &mut std::io::sink(), false)?;
        lines.push(format!(
            "{env_name}: your personal item {title:?} in vault {:?}",
            vault.name
        ));
    }
    Ok(lines)
}

/// The owner's command for `env`'s least-privilege CI reader (FR-52, FR-59): one service
/// account reading every boundary vault of the environment. opv prints it and never runs
/// it, because 1Password shows the new token once, to the owner.
fn ci_reader_steps(
    out: &mut dyn Write,
    fleet: &crate::domain::Fleet,
    project: &str,
    env: &str,
) -> Result<(), Error> {
    let e = fleet.environment(env)?;
    let needs = access_plan::CiNeeds {
        environment: env,
        boundary_vaults: e.boundaries.values().map(|b| b.vault_id.as_str()).collect(),
    };
    let grants = access_plan::required(project, &[], &[needs]);
    let Some(command) = access_plan::create_command(&grants) else {
        return Err(Error::Config(
            format!(
                "Environment {env} has no boundary vault, so its CI reader would read nothing."
            )
            .into(),
        )
        .with_next("opv ready"));
    };
    let lines = [
        format!(
            "CI reader {} for {env} (run it yourself; the token is shown once, by 1Password):",
            access_plan::ci_account(project, env)
        ),
        format!("  {command}"),
        "  store the token it prints as the CI secret OP_SERVICE_ACCOUNT_TOKEN in your CI \
         provider (on GitHub: the repository's Settings > Secrets and variables > Actions), \
         pasting it there yourself; never give CI an owner or break-glass credential"
            .to_string(),
    ];
    for l in lines {
        writeln!(out, "{l}").map_err(write_err)?;
    }
    Ok(())
}

fn no_such_environment(flag: &str, env: &str) -> Error {
    Error::Config(format!("{flag} {env}: secrets.toml declares no environment {env}.").into())
        .with_next("opv bootstrap --dry-run")
}

/// The first recorded ID the selected account cannot see, as `ids_not_in_account`.
fn first_stale(plans: &[EnvPlan]) -> Option<Error> {
    for p in plans {
        let env = &p.environment;
        for b in &p.boundaries {
            if let BoundaryStep::IdsNotInAccount { vault_id } = &b.step {
                return Some(stale_error(
                    format!(
                        "Environment {env}: boundaries.{} names vault {vault_id}",
                        b.boundary
                    ),
                    format!(
                        "either select the account that holds it (opv account list, then opv \
                         account use <ID>), or record a new vault and item in this account with \
                         opv bootstrap --rebind {env} (values are not moved)"
                    ),
                ));
            }
        }
        for s in &p.state_vaults {
            if let StateStep::IdsNotInAccount { vault_id } = &s.step {
                return Some(stale_error(
                    format!(
                        "Environment {env}: target {} names state vault {vault_id}",
                        s.target
                    ),
                    format!(
                        "either select the account that holds it (opv account list, then opv \
                         account use <ID>), or remove state_vault_id from \
                         [environments.{env}.targets.{}] and run opv bootstrap to create one \
                         in this account",
                        s.target
                    ),
                ));
            }
        }
    }
    None
}

/// `ids_not_in_account`: a recorded ID belongs to an account other than the selected one.
fn stale_error(what: String, todo: String) -> Error {
    Error::Config(
        format!(
            "{what}, which is not in the selected 1Password account; opv never falls back to \
             another account."
        )
        .into(),
    )
    .with_code(crate::error::Code::IdsNotInAccount)
    .with_do(todo)
    .with_next("opv account list")
}

fn print_plan(out: &mut dyn Write, plans: &[EnvPlan], json: bool, done: bool) -> Result<(), Error> {
    if json {
        let v = json!({
            "schema_version": crate::json::SCHEMA_VERSION,
            "environments": plans,
        });
        return writeln!(out, "{v}").map_err(write_err);
    }
    for p in plans {
        writeln!(out, "{}:", p.environment).map_err(write_err)?;
        if p.boundaries.is_empty() && p.state_vaults.is_empty() {
            writeln!(out, "  nothing to record").map_err(write_err)?;
        }
        for b in &p.boundaries {
            let line = match &b.step {
                BoundaryStep::Ok { vault_id, item_id } => {
                    format!("ok (vault {vault_id}, item {item_id})")
                }
                BoundaryStep::Create { vault, item } if done => format!(
                    "vault {vault:?} and item {item:?} ready (created or found), IDs recorded"
                ),
                BoundaryStep::Create { vault, item } => format!(
                    "would create vault {vault:?} and item {item:?} (or use them if they exist)"
                ),
                BoundaryStep::IdsNotInAccount { vault_id } => {
                    format!("vault {vault_id} is not in the selected account (ids_not_in_account)")
                }
            };
            writeln!(out, "  boundary {}: {line}", b.boundary).map_err(write_err)?;
        }
        for s in &p.state_vaults {
            let line = match &s.step {
                StateStep::Ok { vault_id } => format!("ok (vault {vault_id})"),
                StateStep::Create { vault } if done => {
                    format!("vault {vault:?} ready (created or found), ID recorded")
                }
                StateStep::Create { vault } => {
                    format!("would create vault {vault:?} (or use it if it exists)")
                }
                StateStep::IdsNotInAccount { vault_id } => {
                    format!("vault {vault_id} is not in the selected account (ids_not_in_account)")
                }
            };
            writeln!(out, "  target {} state vault: {line}", s.target).map_err(write_err)?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "bootstrap_tests.rs"]
mod tests;
