//! `opv bootstrap` (FR-52, #77): take a configuration from declared to ready in the selected
//! 1Password account. It records every missing ID, and nothing else: per environment, each
//! needed boundary (FR-57) without `boundaries.<b>` gets its vault and item found or created
//! by their conventional titles, each target without `state_vault_id` gets its state
//! vault, and each placement (a product a target delivers) without `delivery_items.<p>`
//! gets its delivery item in that vault (FR-58), so nothing else ever looks a state item up
//! by title (FR-13). Then every declared field is added, empty (`item skeleton`). Nothing is
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
use crate::adapters::onepassword_diagnose::{self as op_diagnose, Facts};
use crate::adapters::onepassword_diagnose_items::diagnose_item_call;
use crate::adapters::onepassword_init::{self as init_op, Lookup};
use crate::cause::{
    AccountId, Cause, Cmd, ConfigSource, CreateKind, DiagnoseContext, DottedPath, EnvName,
    FieldRule, GivenBy, NameKind, NotEditable, Observed, Refind, ResourceKind, ResourceName,
    ResourceRef, Scope, System, Upstream,
};
use crate::domain::{access_plan, naming};
use crate::error::Error;
use crate::host::Host;
use crate::runner::{Call, CommandRunner, CreateOutcome, PROBE_TIMEOUT};

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

/// The raw document of `text`. TOML that does not parse is the loader's `ConfigInvalid`
/// (the field and line it stops at, never the parser's own text, which can quote input).
pub(crate) fn parse_doc(text: &str) -> Result<DocumentMut, Error> {
    text.parse().map_err(|_: toml_edit::TomlError| {
        crate::config::parse(text).err().unwrap_or_else(|| {
            Cause::Bug {
                site: "bootstrap: TOML the loader reads does not parse as a document",
            }
            .into()
        })
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
            Error::from(Cause::ConfigInvalid {
                source: crate::domain::model::ReadFrom::default().0,
                at: None,
                field: DottedPath(vec!["environments".into()]),
                rule: FieldRule::NoEnvironment,
            })
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

/// What `op vault get` said about a recorded vault.
enum Seen {
    /// The vault opened.
    Visible,
    /// op said the vault is not in the account (or nowhere): the cataloged cause, with op's
    /// reply as evidence, when the runner observed the call.
    NotVisible(Option<Error>),
    /// The probe never answered (a timeout, a spawn failure): what the runner observed.
    Unanswered(Option<Observed>),
}

/// Whether `vault_id` is a vault the signed-in account can see: `op vault get` (its output
/// names the vault and is dropped unread). A failed call is diagnosed from what op said
/// (#159): only "not in this account" is a vault outside the account; any other failure (a
/// sign-in, an unrecognised reply) is returned as its own cause, naming the call. `account`
/// is the environment's own 1Password account (FR-40), when it records one; `scope` the
/// account the caller already chose for the whole structure (G3), else the checkout's.
fn vault_visible(
    r: &dyn CommandRunner,
    account: Option<&str>,
    scope: Option<&str>,
    project_dir: Option<&Path>,
    env: &str,
    vault_id: &str,
) -> Result<Seen, Error> {
    // A service-account or Connect credential belongs to one account: it decides. Otherwise
    // the environment's own account, else the one the structure was scoped to (G3), is
    // where the probe looks; op's default only when neither is known.
    let account = account
        .or(scope)
        .filter(|_| Host::detect().op_credential.is_none())
        .map(str::to_string);
    // The project's own `.opv` (beside its configuration file), never the process's
    // working directory: `--file` may name a project elsewhere.
    let selected = account.clone().or_else(|| {
        project_dir
            .and_then(crate::config_store::selected_account)
            .filter(|a| crate::config::is_id(a))
    });
    let r = super::signin::EnvRunner::with_account(r, account);
    let out = match r.probe(
        &Call::new("op", &["vault", "get", vault_id, "--format", "json"]),
        PROBE_TIMEOUT,
    ) {
        Ok(out) => out,
        // Design §5: op that never started is the dependency's cause, before anything else.
        Err(e) if !crate::adapters::probe::started(&e) => {
            return Err(crate::adapters::probe::probe_failure(
                &crate::host::OP_CLI,
                &e,
                &Host::detect,
            ));
        }
        Err(_) => return Ok(Seen::Unanswered(crate::runner::take_observed())),
    };
    if out.status == 0 {
        return Ok(Seen::Visible);
    }
    let ctx = DiagnoseContext {
        env: Some(EnvName::new(env)),
        resource: Some(ResourceRef {
            kind: ResourceKind::Vault,
            name: ResourceName::new(vault_id),
            scope: selected.clone(),
        }),
        account: selected.map(AccountId::new),
        ..DiagnoseContext::default()
    };
    // A runner that observes nothing (a test fake) leaves the answer to the session check.
    let Some(error) = op_failure(|seen, said| {
        // #153a: a vault in another account names that account.
        op_diagnose::locate_owner(
            &r,
            op_diagnose::diagnose_with(seen, said, &ctx, &Facts::from_process_env()),
        )
    }) else {
        return Ok(Seen::NotVisible(None));
    };
    match error.cause() {
        Some((Cause::InOtherAccount { .. } | Cause::NotFound { .. }, _)) => {
            Ok(Seen::NotVisible(Some(error)))
        }
        _ => Err(error),
    }
}

/// The failed `op` call the runner just observed, as the cause `diagnose` gives it from
/// op's reply, with that reply (scrubbed) as its evidence; `None` when the runner observed
/// no call (a fake). The reply is taken once, so it attaches nowhere else (NR-31).
fn op_failure(diagnose: impl FnOnce(Observed, &str) -> Cause) -> Option<Error> {
    let seen = crate::runner::take_observed()?;
    let (said, truncated) = crate::scrub::Excerpt::parts(crate::runner::take_failure_excerpt());
    let exit = seen.exit();
    let cause = diagnose(seen, &said.join("\n"));
    if said.is_empty() {
        return Some(cause.into());
    }
    let upstream = Upstream {
        source: System::OnePassword,
        tool: "1Password CLI".into(),
        version: None,
        exit,
        said,
        removed_advice: false,
        truncated,
        untrusted: true,
    };
    Some(Error::with_evidence(cause, upstream))
}

/// The plan for every environment of `text` (read-only: one `op vault get` per recorded
/// vault).
pub fn plan(
    r: &dyn CommandRunner,
    text: &str,
    project: &str,
    rebind: &BTreeSet<String>,
) -> Result<Vec<EnvPlan>, Error> {
    plan_with(r, text, project, rebind, false)
}

/// [`plan`]; `strict` (the structural plan, #133) refuses when a recorded vault's
/// visibility cannot be told, instead of taking it as visible: an unknown answer never
/// becomes a plan that someone approves.
pub(crate) fn plan_with(
    r: &dyn CommandRunner,
    text: &str,
    project: &str,
    rebind: &BTreeSet<String>,
    strict: bool,
) -> Result<Vec<EnvPlan>, Error> {
    plan_checked(r, text, project, rebind, strict, None, None).map(|(plans, _)| plans)
}

/// [`plan_with`], plus the cataloged `ids_not_in_account` of the first recorded vault op
/// said is not in the account, with op's reply as its evidence (#159); `None` when there is
/// none, or when the runner observed no call (the caller then refuses: an observed call is
/// the only way to name it). `scope` is the account the caller chose for the structure
/// (G3): a recorded vault is looked for there, not in op's default. `project_dir` holds the
/// configuration file, whose `.opv` names the selected account when neither does.
pub(crate) fn plan_checked(
    r: &dyn CommandRunner,
    text: &str,
    project: &str,
    rebind: &BTreeSet<String>,
    strict: bool,
    scope: Option<&str>,
    project_dir: Option<&Path>,
) -> Result<(Vec<EnvPlan>, Option<Error>), Error> {
    // #157: a vault `op vault get` cannot open is outside the account only when someone is
    // signed in, so the session is checked (once) before the first such answer is believed.
    let session_checked = std::cell::Cell::new(false);
    let stale = std::cell::RefCell::new(None);
    let visible = |account: Option<&str>, env: &str, v: &str| -> Result<Option<bool>, Error> {
        match vault_visible(r, account, scope, project_dir, env, v)? {
            Seen::Visible => Ok(Some(true)),
            // A recorded ID is taken as it is when op is not asked at all (the offline trial
            // makes no call). A call op was asked and did not answer is reported (design §5,
            // X26): never "ok" on a guess.
            Seen::Unanswered(None) if !strict => Ok(None),
            Seen::Unanswered(seen) => Err(match seen {
                Some(seen) => op_diagnose::diagnose(seen, "", &DiagnoseContext::default()).into(),
                None => Cause::Bug {
                    site: "bootstrap: an unanswered op vault get left no observation",
                }
                .into(),
            }),
            Seen::NotVisible(cause) => {
                if !session_checked.replace(true) {
                    crate::adapters::onepassword::require_session(
                        r,
                        &Host::detect,
                        &format!("op vault get {v} failed"),
                    )?;
                }
                if stale.borrow().is_none() {
                    *stale.borrow_mut() = cause;
                }
                Ok(Some(false))
            }
        }
    };
    let doc = parse_doc(text)?;
    let envs = environment_names(&doc)?;
    if let Some(env) = rebind.iter().find(|e| !envs.contains(e)) {
        return Err(no_such_environment(env, &envs));
    }
    let mut plans = Vec::new();
    for env in envs {
        let account = env_table(&doc, &env)
            .and_then(|t| str_at(t, "account"))
            .map(str::to_string);
        let account = account.as_deref();
        let boundaries = needed_boundaries(&doc, &env)
            .into_iter()
            .map(|(b, products)| {
                let step = match recorded_boundary(&doc, &env, &b) {
                    Some((v, i)) if !rebind.contains(&env) => match visible(account, &env, &v)? {
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
                Ok(BoundaryPlan {
                    boundary: b,
                    products: products.into_iter().collect(),
                    step,
                })
            })
            .collect::<Result<_, Error>>()?;
        let state_vaults = targets(&doc, &env)
            .into_iter()
            .map(|(t, id)| {
                let step = match id {
                    Some(v) => match visible(account, &env, &v)? {
                        Some(false) => StateStep::IdsNotInAccount { vault_id: v },
                        _ => StateStep::Ok { vault_id: v },
                    },
                    None => StateStep::Create {
                        vault: naming::state_vault(project, &env, &t),
                    },
                };
                Ok(StatePlan { target: t, step })
            })
            .collect::<Result<_, Error>>()?;
        plans.push(EnvPlan {
            environment: env,
            boundaries,
            state_vaults,
        });
    }
    Ok((plans, stale.into_inner()))
}

/// A file whose first line says it is generated is never rewritten (FR-52).
pub fn is_generated(text: &str) -> bool {
    text.lines().next().is_some_and(|l| {
        l.trim_start()
            .to_ascii_lowercase()
            .starts_with("# generated")
    })
}

/// One `op ... create` through [`CommandRunner::create`], never retried (NR-2, X5): the new
/// object's ID, checked like a hand-written ID (SR-7). A create whose outcome is unknown is
/// `create_outcome_unknown`, never "did not create" (05.05); bootstrap finds a vault or an
/// item again by its title, so the step is the same command, every flag kept (05.06). A
/// definite refusal is diagnosed from op's reply.
fn create(
    r: &dyn CommandRunner,
    args: &[&str],
    stdin: Option<&[u8]>,
    kind: CreateKind,
    title: &str,
) -> Result<init_op::Named, Error> {
    let call = Call::new("op", args).with_stdin(stdin);
    let refused = || {
        let ctx = DiagnoseContext {
            create: Some((kind, title.to_string(), Refind::ByTitle)),
            write: true,
            ..DiagnoseContext::default()
        };
        op_failure(|seen, said| diagnose_item_call(seen, said, &ctx, &Facts::from_process_env()))
            .unwrap_or_else(|| {
                Cause::Bug {
                    site: "bootstrap: a failed op create left no observation",
                }
                .into()
            })
    };
    let out = match r.create(&call, kind) {
        Ok(CreateOutcome::Done(out)) => out,
        Ok(CreateOutcome::OutcomeUnknown(seen)) => {
            // Its reply, if any, belongs to this cause alone.
            let _ = crate::runner::take_failure_excerpt();
            return Err(Cause::CreateOutcomeUnknown {
                system: System::OnePassword,
                kind,
                name: title.to_string(),
                refind: Refind::ByTitle,
                seen,
            }
            .into());
        }
        Ok(CreateOutcome::Refused(_)) | Err(_) => return Err(refused()),
    };
    let id = serde_json::from_slice::<serde_json::Value>(&out.stdout)
        .ok()
        .and_then(|v| v["id"].as_str().map(str::to_string))
        .filter(|id| crate::config::is_id(id));
    // C19: op said it created the object but gave no usable ID. Whether it exists is not
    // known from that reply; the next run finds it by title, never a second create (X5).
    let Some(id) = id else {
        return Err(match crate::runner::take_unusable_reply(&call) {
            Some(seen) => Cause::CreateOutcomeUnknown {
                system: System::OnePassword,
                kind,
                name: title.to_string(),
                refind: Refind::ByTitle,
                seen,
            }
            .into(),
            None => Cause::Bug {
                site: "bootstrap: an op create reply the runner did not observe",
            }
            .into(),
        });
    };
    Ok(init_op::Named {
        id,
        name: title.to_string(),
    })
}

/// The vault titled `title` in the signed-in account, created with the description `notes`
/// when missing.
pub(crate) fn ensure_vault(
    r: &dyn CommandRunner,
    title: &str,
    notes: &str,
) -> Result<init_op::Named, Error> {
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
            CreateKind::Vault,
            title,
        ),
    }
}

/// The item titled `title` in `vault_id`, created when missing as an empty Secure Note with
/// `notes` and tagged `tag` (FR-55), so `ready` can tell an item moved or wired to another
/// environment.
pub(crate) fn ensure_item(
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
    // An empty Secure Note: no value is in it, so an orphan holds no secret.
    create(r, &args, Some(&template), CreateKind::Item, title)
}

/// The detection tag of an environment's item (FR-55).
pub fn env_tag(project: &str, env: &str) -> String {
    format!("opv-env:{project}/{env}")
}

/// An ID bootstrap records, by where it goes in the document.
pub(crate) enum Recorded {
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
    DeliveryItem {
        env: String,
        target: String,
        product: String,
        item_id: String,
    },
}

impl Recorded {
    pub(crate) fn line(&self) -> String {
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
            Recorded::DeliveryItem {
                env,
                target,
                product,
                item_id,
            } => format!(
                "[environments.{env}.targets.{target}] delivery_items.{product} = {item_id:?}"
            ),
        }
    }

    /// Write this ID into the raw document (comments and order kept).
    pub(crate) fn write(&self, doc: &mut DocumentMut) {
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
            Recorded::DeliveryItem {
                env,
                target,
                product,
                item_id,
            } => {
                let Some(t) = doc["environments"][env.as_str()]["targets"][target.as_str()]
                    .as_table_like_mut()
                else {
                    return;
                };
                if t.get("delivery_items").is_none() {
                    t.insert("delivery_items", Item::Value(InlineTable::new().into()));
                }
                if let Some(items) = t
                    .get_mut("delivery_items")
                    .and_then(Item::as_table_like_mut)
                {
                    items.insert(product, value(item_id.as_str()));
                }
            }
        }
    }
}

/// FR-58: the delivery item of every placement of `fleet` (a product with a binding on a
/// target) that has none recorded, found or created in the target's state vault with its
/// notes, by its conventional title (bootstrap, like init, may look titles up; FR-13).
fn delivery_items(
    fleet: &crate::domain::Fleet,
    project: &str,
    r: &dyn CommandRunner,
) -> Result<Vec<Recorded>, Error> {
    let mut out = Vec::new();
    for (env, e) in &fleet.environments {
        for target in e.targets.keys() {
            for (product, item_id) in placement_items(fleet, project, env, target, r)? {
                out.push(Recorded::DeliveryItem {
                    env: env.clone(),
                    target: target.clone(),
                    product,
                    item_id,
                });
            }
        }
    }
    Ok(out)
}

/// FR-58: `(product, item ID)` for every placement on `env`/`target` without a recorded
/// delivery item, found or created in the target's state vault with its notes. Shared by
/// bootstrap and `opv target add`, which records a new target's placements in one step.
pub(crate) fn placement_items(
    fleet: &crate::domain::Fleet,
    project: &str,
    env: &str,
    target: &str,
    r: &dyn CommandRunner,
) -> Result<Vec<(String, String)>, Error> {
    let Some(t) = fleet.environment(env)?.targets.get(target) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for product in fleet.products.keys() {
        if t.delivery_items.contains_key(product)
            || super::delivery::bindings(fleet, env, target, product)?.is_empty()
        {
            continue;
        }
        let item = ensure_item(
            r,
            fleet.state_vault(env, t)?,
            &naming::delivery_item(product, target),
            &format!("opv-delivery:{project}/{env}/{target}/{product}"),
            &naming::delivery_item_notes(product, target, env),
        )?;
        out.push((product.clone(), item.id));
    }
    Ok(out)
}

/// A placeholder ID for each ID bootstrap would record, so the loader can judge the result
/// before anything is created.
pub(crate) fn placeholders(plans: &[EnvPlan]) -> Vec<Recorded> {
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
    let text = crate::config::read_merged(path)?;
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let (plans, stale) = plan_checked(r, &text, project, &opts.rebind, false, None, Some(dir))?;
    if let Some(env) = &opts.ci_reader
        && !plans.iter().any(|p| &p.environment == env)
    {
        let envs: Vec<String> = plans.iter().map(|p| p.environment.clone()).collect();
        return Err(no_such_environment(env, &envs));
    }
    // A recorded ID outside the account: the cataloged `ids_not_in_account` op's reply was
    // diagnosed as, with that reply as its evidence (#159, C19).
    if let Some(e) = stale {
        print_plan(out, &plans, opts.json, false)?;
        return Err(e);
    }
    if has_stale(&plans) {
        return Err(Cause::Bug {
            site: "bootstrap: a recorded vault outside the account left no observation",
        }
        .into());
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
    // Every state vault exists now: each placement's delivery item goes in its target's.
    let items = delivery_items(&crate::config::parse(&doc.to_string())?, project, r)?;
    for id in &items {
        id.write(&mut doc);
    }
    recorded.extend(items);
    let new_text = doc.to_string();
    // The result loads like any hand-written file before it replaces it.
    let fleet = crate::config::parse(&new_text)?;
    if !recorded.is_empty() {
        if is_generated(&text) {
            print_plan(out, &plans, opts.json, false)?;
            // What was made in 1Password, with the IDs its generator's input must record;
            // the file itself is never rewritten (FR-52).
            return Err(Cause::Partial {
                done: recorded.iter().map(Recorded::line).collect(),
                scope: None,
                then: Box::new(Cause::ConfigNotEditable {
                    source: ConfigSource::File {
                        path: path.to_path_buf(),
                        given_by: GivenBy::Discovered,
                    },
                    reason: NotEditable::Generated { generator: None },
                }),
            }
            .into());
        }
        super::init::write_config(path, &new_text, true)?;
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
        "every environment has its boundary vaults, items, state vaults, delivery items and \
         empty fields; fill the values in 1Password, then check what is left"
    )
    .map_err(write_err)?;
    if let Some(env) = &opts.ci_reader {
        ci_reader_steps(out, &fleet, project, path, env)?;
    }
    let ready = Cmd {
        command: vec!["ready".into()],
        args: config_args(path),
    };
    writeln!(out, "Next: {}", crate::cause::render::cmd_text(&ready)).map_err(write_err)
}

/// `--config <path>`: the file bootstrap completed, for a later command to read the same one
/// (X1), wherever it was found or given.
fn config_args(path: &Path) -> Vec<String> {
    vec!["--config".into(), path.display().to_string()]
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
            // C19, R34: the vault titles looked for, and the field that names another one.
            return Err(super::personal::vault_missing(team));
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
                    (b, Some(at))
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
    path: &Path,
    env: &str,
) -> Result<(), Error> {
    // 05.27: `opv access` defaults its project (and so the service account's name) to the
    // repository's name, so it gets the project bootstrap used, and the same file (X1).
    let access = |extra: &[&str]| {
        let mut args = vec![
            env.to_string(),
            "--project".to_string(),
            project.to_string(),
        ];
        args.extend(config_args(path));
        args.extend(extra.iter().map(|w| w.to_string()));
        crate::cause::render::cmd_text(&Cmd {
            command: vec!["access".into()],
            args,
        })
    };
    let needs = access_plan::CiNeeds {
        environment: env,
        boundary_vaults: fleet
            .bound_boundaries(env)?
            .into_iter()
            .map(|(_, b)| b.vault_id.as_str())
            .collect(),
    };
    let grants = access_plan::required(project, &[], &[needs]);
    // No boundary vault: no product has a team key in this environment, so a CI reader
    // would read nothing.
    let Some(command) = access_plan::create_command(&grants) else {
        return Err(Cause::NothingInScope {
            env: EnvName::new(env),
            what: Scope::NoProductHasKeys,
        }
        .into());
    };
    let lines = [
        format!(
            "CI reader {} for {env}: create it and store its token as a GitHub Actions secret \
             in one step, the token never shown (run it yourself, in your own terminal):",
            access_plan::ci_account(project, env)
        ),
        format!(
            "  {} --github <owner/repo> [--github-env <environment>]",
            access(&["--create"])
        ),
        format!(
            "  another CI provider: run {command} yourself and paste the token it shows once \
             straight into that provider's secret OP_SERVICE_ACCOUNT_TOKEN; never give CI an \
             owner or break-glass credential"
        ),
        format!(
            "  this reader validates only (check, plan, ready): it cannot write delivery \
             evidence. A CI job that syncs or deploys uses each target's deploy identity \
             instead (boundary read, its own state vault read and write): {} --target <name> \
             --github <owner/repo>",
            access(&["--create"])
        ),
    ];
    for l in lines {
        writeln!(out, "{l}").map_err(write_err)?;
    }
    Ok(())
}

/// `--rebind` or `--ci-reader` names an environment the file does not declare.
fn no_such_environment(env: &str, declared: &[String]) -> Error {
    Cause::NotDeclared {
        kind: NameKind::Environment,
        given: env.to_string(),
        candidates: declared.to_vec(),
        closest: None,
    }
    .into()
}

/// True when a recorded ID of `plans` is not in the selected account.
fn has_stale(plans: &[EnvPlan]) -> bool {
    plans.iter().any(|p| {
        p.boundaries
            .iter()
            .any(|b| matches!(b.step, BoundaryStep::IdsNotInAccount { .. }))
            || p.state_vaults
                .iter()
                .any(|s| matches!(s.step, StateStep::IdsNotInAccount { .. }))
    })
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
