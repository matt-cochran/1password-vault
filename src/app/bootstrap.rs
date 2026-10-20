//! The structural planner (FR-52, #77; 0.11.0's `opv bootstrap`, removed in 0.12.0), used by
//! `opv propose structure` and `opv apply` ([`super::structure`]): what takes a
//! configuration from declared to ready in the selected 1Password account. It records every
//! missing ID, and nothing else: per environment, each
//! needed boundary (FR-57) without `boundaries.<b>` gets its vault and item found or created
//! by their conventional titles, each target without `state_vault_id` gets its state
//! vault, and each placement (a product a target delivers) without `delivery_items.<p>`
//! gets its delivery item in that vault (FR-58), so nothing else ever looks a state item up
//! by title (FR-13). Then every declared field is added, empty ([`super::skeleton`]). Nothing
//! is synced or deployed, and no value is read or written.
//!
//! It works on the raw document (comments and order kept), so it can complete a file the
//! strict loader still refuses for want of those IDs; the loader is the authority for the
//! result. Recorded IDs the selected account cannot see are never replaced silently
//! (`ids_not_in_account`): `opv propose structure --rebind <env>` asks for new boundary IDs.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Serialize;
use serde_json::json;
use toml_edit::{DocumentMut, InlineTable, Item, Table, value};

use crate::adapters::onepassword_diagnose::{self as op_diagnose, Facts};
use crate::adapters::onepassword_diagnose_items::diagnose_item_call;
use crate::adapters::onepassword_init::{self as init_op, Lookup};
use crate::cause::{
    AccountId, Cause, CreateKind, DiagnoseContext, DottedPath, EnvName, FieldRule, NameKind,
    Observed, Refind, ResourceKind, ResourceName, ResourceRef, System, Upstream,
};
use crate::domain::naming;
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

/// The raw document of `text`. TOML that does not parse is the loader's `ConfigInvalid`
/// (the field and line it stops at, never the parser's own text, which can quote input).
pub(crate) fn parse_doc(text: &str) -> Result<DocumentMut, Error> {
    text.parse().map_err(|_: toml_edit::TomlError| {
        crate::config::parse(text).err().unwrap_or_else(|| {
            Cause::Bug {
                site: "structure: TOML the loader reads does not parse as a document",
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
/// vault). The planner's tests read it through this.
#[cfg(test)]
pub(crate) fn plan(
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
                    site: "structure: an unanswered op vault get left no observation",
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
    generated_header(text).is_some()
}

/// The generator a generated file's first line names (#178): `# generated by <tool>` and
/// the `# GENERATED by <tool> from <input> — do not edit` form alike, any case, an optional
/// `:` after `by`. `None` for a hand-written file, and for a generated one whose header
/// names no tool (`# generated`, `# GENERATED — do not edit`). The name is the one word
/// after `by`, without trailing punctuation; it is a file or program name, never a value.
pub fn generated_by(text: &str) -> Option<String> {
    let rest = generated_header(text)?;
    let mut words = rest.trim_start_matches(':').split_whitespace();
    let by = words.next()?;
    if !by.trim_end_matches(':').eq_ignore_ascii_case("by") {
        return None;
    }
    let tool = words.next()?.trim_end_matches([';', ',', '.', ':', ')']);
    let printable = !tool.is_empty()
        && tool.len() <= 128
        && !tool
            .chars()
            .any(|c| c.is_control() || c == '"' || c == '\'' || c == '`');
    printable.then(|| tool.to_string())
}

/// The rest of a generated file's first line after `# generated` (any case), or `None`
/// when the first line does not start so.
fn generated_header(text: &str) -> Option<&str> {
    let line = text.lines().next()?.trim_start();
    let head = line.get(..11)?;
    head.eq_ignore_ascii_case("# generated")
        .then(|| &line[11..])
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
                    site: "structure: a failed op create left no observation",
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
                site: "structure: an op create reply the runner did not observe",
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

#[cfg(test)]
#[path = "bootstrap_tests.rs"]
mod tests;
