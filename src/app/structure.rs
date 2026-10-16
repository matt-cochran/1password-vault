//! The structural plan and its apply (#133): what `opv bootstrap` and `opv item skeleton`
//! would create for a project, as one reviewable plan with an id, and the apply of exactly
//! that plan once a person approved it in their own terminal (`opv approve`, [`crate::approval`]).
//!
//! Structure only: boundary vaults and items, state vaults, delivery items and empty fields.
//! The plan holds names, kinds, titles and public IDs, never a value; it is computed with
//! reads only (one `op vault get` per recorded vault, one fresh read per existing boundary
//! item, of which only field labels are kept). A vault whose visibility cannot be told
//! refuses the plan instead of being taken as visible, and a recorded ID the selected
//! account cannot see stops it (`ids_not_in_account`): structure is never rebound or
//! recreated around an access failure.
//!
//! The plan id is SHA-256 over the project, the 1Password account, the configuration text
//! and every planned step, so a plan approved for one project, account or configuration
//! never applies to another, and any change since the review is `stale_plan`. Permission
//! grants, personal items, credentials, sync, deploy and rotation are not part of it.

use std::collections::BTreeSet;
use std::path::Path;

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::bootstrap::{self, BoundaryStep, EnvPlan, Recorded, StateStep};
use crate::adapters::onepassword;
use crate::cause::{
    Cause, CommandId, GivenBy, PlanId, PlanScope, Principal, SessionState, StoreObject, System,
    VarName,
};
use crate::domain::{Fleet, naming};
use crate::error::Error;
use crate::runner::CommandRunner;

/// The plan id's prefix and length in hex digits after it: `sp-` and 16 (64 bits).
pub const PLAN_ID_PREFIX: &str = "sp-";
const PLAN_ID_HEX: usize = 16;

/// One delivery item the plan creates in a target's state vault (FR-58).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeliveryStep {
    pub environment: String,
    pub target: String,
    pub product: String,
    /// The item's title.
    pub item: String,
}

/// One empty field the plan adds to a boundary item (FR-19).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct FieldStep {
    pub environment: String,
    pub boundary: String,
    pub product: String,
    pub key: String,
    pub kind: &'static str,
}

/// The structural plan of one project in one 1Password account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Plan {
    pub plan_id: String,
    pub project: String,
    pub account_id: String,
    pub environments: Vec<EnvPlan>,
    pub delivery_items: Vec<DeliveryStep>,
    pub fields: Vec<FieldStep>,
    /// The configuration file is generated: apply records nothing in it and returns the
    /// IDs for its generator instead (FR-52).
    pub generated: bool,
}

impl Plan {
    /// True when applying it would change nothing.
    pub fn is_empty(&self) -> bool {
        self.delivery_items.is_empty()
            && self.fields.is_empty()
            && self.environments.iter().all(|e| {
                e.boundaries
                    .iter()
                    .all(|b| matches!(b.step, BoundaryStep::Ok { .. }))
                    && e.state_vaults
                        .iter()
                        .all(|s| matches!(s.step, StateStep::Ok { .. }))
            })
    }

    /// Counts for a one-line summary: vaults, items, fields.
    pub fn counts(&self) -> (usize, usize, usize) {
        let mut vaults = 0;
        let mut items = self.delivery_items.len();
        for e in &self.environments {
            for b in &e.boundaries {
                if matches!(b.step, BoundaryStep::Create { .. }) {
                    vaults += 1;
                    items += 1;
                }
            }
            vaults += e
                .state_vaults
                .iter()
                .filter(|s| matches!(s.step, StateStep::Create { .. }))
                .count();
        }
        (vaults, items, self.fields.len())
    }
}

/// True for a well-formed structural plan id (`sp-` and 16 lowercase hex digits).
pub fn is_plan_id(s: &str) -> bool {
    s.strip_prefix(PLAN_ID_PREFIX).is_some_and(|h| {
        h.len() == PLAN_ID_HEX
            && h.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// The structural plan for the configuration `text` of `project` in `account` (an account
/// ID). Reads only; refuses when a recorded vault is not in the account or its visibility
/// cannot be told.
pub fn plan(
    r: &dyn CommandRunner,
    text: &str,
    project: &str,
    account: &str,
) -> Result<Plan, Error> {
    if !crate::config::is_id(account) {
        return Err(no_account());
    }
    let (environments, stale) = bootstrap::plan_checked(r, text, project, &BTreeSet::new(), true)?;
    // A recorded ID outside the account: the cataloged `ids_not_in_account` op's reply was
    // diagnosed as, with that reply as its evidence.
    if let Some(e) = stale {
        return Err(e);
    }
    if has_stale(&environments) {
        return Err(Cause::Bug {
            site: "structure: a recorded vault outside the account left no observation",
        }
        .into());
    }
    let fleet = trial_fleet(text, &environments)?;
    let delivery_items = delivery_steps(&fleet)?;
    let fields = field_steps(&fleet, &environments, r)?;
    let generated = bootstrap::is_generated(text);
    let plan_id = plan_id(
        project,
        account,
        text,
        &environments,
        &delivery_items,
        &fields,
    );
    Ok(Plan {
        plan_id,
        project: project.to_string(),
        account_id: account.to_string(),
        environments,
        delivery_items,
        fields,
        generated,
    })
}

/// The configuration as it would load with every planned ID recorded (placeholders for
/// the ones still to create): the loader judges the result before anything is created.
/// True when a recorded ID of `environments` is not in the selected account.
fn has_stale(environments: &[EnvPlan]) -> bool {
    environments.iter().any(|e| {
        e.boundaries
            .iter()
            .any(|b| matches!(b.step, BoundaryStep::IdsNotInAccount { .. }))
            || e.state_vaults
                .iter()
                .any(|s| matches!(s.step, StateStep::IdsNotInAccount { .. }))
    })
}

/// No 1Password account ID for the project. Under a service-account or Connect credential
/// the structure is a person's own (`own_session_required`); otherwise op knows no account
/// on this machine, and signing in adds one (`op_not_signed_in`). opv never uses op's
/// default account for a write.
fn no_account() -> Error {
    match crate::host::Host::detect().op_credential {
        Some(c) => Cause::NeedsOwnSession {
            command: CommandId("structure".into()),
            identity: Principal::ShellToken {
                var: VarName::new(c.var()),
            },
        }
        .into(),
        None => Cause::NotSignedIn {
            system: System::OnePassword,
            account: None,
            state: SessionState::SignedOut,
        }
        .into(),
    }
}

/// The structural plan `old` is now `new` (the configuration, the account or what exists in
/// 1Password changed): nothing was approved, applied or used, and the step is the read of
/// the new plan, which a person then approves (05.15).
pub(crate) fn changed(old: &str, new: &str) -> Error {
    Cause::PlanChanged {
        old: PlanId::new(old),
        new: PlanId::new(new),
        scope: PlanScope::Structural,
    }
    .into()
}

fn trial_fleet(text: &str, environments: &[EnvPlan]) -> Result<Fleet, Error> {
    let mut doc = bootstrap::parse_doc(text)?;
    for id in bootstrap::placeholders(environments) {
        id.write(&mut doc);
    }
    crate::config::parse(&doc.to_string())
}

/// `text` as it will load once the structural plan records its IDs: placeholders for every
/// boundary and state vault still to create, judged without asking 1Password (a recorded
/// ID is taken as it is). For validating declarations before the structure exists.
pub(crate) fn trial_text(text: &str) -> Result<String, Error> {
    let environments = bootstrap::plan_with(&Offline, text, "project", &BTreeSet::new(), false)?;
    let mut doc = bootstrap::parse_doc(text)?;
    for id in bootstrap::placeholders(&environments) {
        id.write(&mut doc);
    }
    Ok(doc.to_string())
}

/// A runner that runs nothing: every probe "cannot tell", every call refused.
struct Offline;

impl CommandRunner for Offline {
    fn read(&self, _: &crate::runner::Call, _: &[i32]) -> std::io::Result<crate::runner::Outcome> {
        Err(std::io::ErrorKind::PermissionDenied.into())
    }
    fn write(&self, _: &crate::runner::Call) -> std::io::Result<crate::runner::Outcome> {
        Err(std::io::ErrorKind::PermissionDenied.into())
    }
    fn probe(
        &self,
        _: &crate::runner::Call,
        _: std::time::Duration,
    ) -> std::io::Result<crate::runner::Output> {
        Err(std::io::ErrorKind::PermissionDenied.into())
    }
    fn pause(&self, _: std::time::Duration, _: &str) {}
    fn note(&self, _: &str) {}
    fn run_inherited(&self, _: &str, _: &[&str], _: &[(&str, &str)]) -> std::io::Result<i32> {
        Err(std::io::ErrorKind::PermissionDenied.into())
    }
}

/// True for an ID [`bootstrap::placeholders`] made up.
fn pending(id: &str) -> bool {
    id.starts_with("vpending-") || id.starts_with("ipending-")
}

/// Every placement (a product with a binding on a target) without a recorded delivery
/// item, in environment, target, product order.
fn delivery_steps(fleet: &Fleet) -> Result<Vec<DeliveryStep>, Error> {
    let mut out = Vec::new();
    for (env, e) in &fleet.environments {
        for (target, t) in &e.targets {
            for product in fleet.products.keys() {
                if t.delivery_items.contains_key(product)
                    || super::delivery::bindings(fleet, env, target, product)?.is_empty()
                {
                    continue;
                }
                out.push(DeliveryStep {
                    environment: env.clone(),
                    target: target.clone(),
                    product: product.clone(),
                    item: naming::delivery_item(product, target),
                });
            }
        }
    }
    Ok(out)
}

/// Every empty field the plan adds: each declared field of a boundary still to create, and
/// the ones an existing boundary item lacks (one fresh read each; labels only).
fn field_steps(
    fleet: &Fleet,
    environments: &[EnvPlan],
    r: &dyn CommandRunner,
) -> Result<Vec<FieldStep>, Error> {
    let mut out = Vec::new();
    for p in environments {
        let env_name = &p.environment;
        let env = fleet.environment(env_name)?;
        for (name, b) in super::tidy::boundaries_needed(fleet, env_name)? {
            let part = super::tidy::in_boundary(fleet, &name);
            let fields = if pending(&b.vault_id) {
                super::skeleton::declared_fields(&part, env_name)
            } else {
                super::skeleton::missing_fields(&part, env, b, env_name, r)?.1
            };
            out.extend(fields.into_iter().map(|(product, key, kind)| FieldStep {
                environment: env_name.clone(),
                boundary: name.clone(),
                product,
                key,
                kind: super::kind_label(kind),
            }));
        }
    }
    out.sort();
    Ok(out)
}

/// SHA-256 over the plan's scope and every step, length-prefixed (like the sync plan id,
/// FR-41). Never over a value: the configuration holds none, and fields enter by name.
fn plan_id(
    project: &str,
    account: &str,
    text: &str,
    environments: &[EnvPlan],
    delivery: &[DeliveryStep],
    fields: &[FieldStep],
) -> String {
    let mut h = Sha256::new();
    let mut put = |s: &str| {
        h.update((s.len() as u64).to_be_bytes());
        h.update(s.as_bytes());
    };
    put("opv-structure-v1");
    put(project);
    put(account);
    put(&hex(&Sha256::digest(text.as_bytes())));
    for e in environments {
        put("env");
        put(&e.environment);
        for b in &e.boundaries {
            put("boundary");
            put(&b.boundary);
            put(&b.products.join(","));
            match &b.step {
                BoundaryStep::Ok { vault_id, item_id } => {
                    put("ok");
                    put(vault_id);
                    put(item_id);
                }
                BoundaryStep::Create { vault, item } => {
                    put("create");
                    put(vault);
                    put(item);
                }
                BoundaryStep::IdsNotInAccount { vault_id } => {
                    put("not_in_account");
                    put(vault_id);
                }
            }
        }
        for s in &e.state_vaults {
            put("state");
            put(&s.target);
            match &s.step {
                StateStep::Ok { vault_id } => {
                    put("ok");
                    put(vault_id);
                }
                StateStep::Create { vault } => {
                    put("create");
                    put(vault);
                }
                StateStep::IdsNotInAccount { vault_id } => {
                    put("not_in_account");
                    put(vault_id);
                }
            }
        }
    }
    for d in delivery {
        put("delivery");
        put(&d.environment);
        put(&d.target);
        put(&d.product);
    }
    for f in fields {
        put("field");
        put(&f.environment);
        put(&f.boundary);
        put(&f.product);
        put(&f.key);
        put(f.kind);
    }
    let digest = hex(&h.finalize());
    format!("{PLAN_ID_PREFIX}{}", &digest[..PLAN_ID_HEX])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Where a structural plan applies: the configuration file, the project and the 1Password
/// account (an account ID), resolved the same way for `opv approve` and the MCP tools so
/// an approval made in one always names the scope the other applies to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    pub path: std::path::PathBuf,
    pub project: String,
    pub account: String,
}

/// The [`Scope`] of the checkout at `start`: its `secrets.toml` (here or in a parent; a
/// configuration kept only in 1Password is not structured through this path yet), its
/// project name (git remote, else directory), and its account (`OP_ACCOUNT`, else the
/// `.opv` pointer, else the only account op knows). No account, or several and none
/// chosen, is `account_required`: opv never uses op's default for a write.
pub fn scope(start: &Path, r: &dyn CommandRunner) -> Result<Scope, Error> {
    use crate::config_store;
    let Some(path) = config_store::walk_up(start, "secrets.toml") else {
        return Err(no_file(start, r));
    };
    let project = config_store::default_project(
        None,
        config_store::git_repo(r).as_deref(),
        path.parent().unwrap_or(start),
    )?;
    let given = config_store::account_env().or_else(|| config_store::pointer_account(start));
    let account = config_store::pick_account(r, given)?.ok_or_else(no_account)?;
    Ok(Scope {
        path,
        project,
        account,
    })
}

/// The project and 1Password account an approval of a sync plan names (0.9.0): resolved
/// like [`scope`], from the checkout at `start`, but without needing a local
/// `secrets.toml` (a sync may use a configuration kept in 1Password). `opv approve --sync`
/// and the agent's approved sync resolve it the same way, so an approval made in one
/// always names what the other consumes.
pub fn binding(start: &Path, r: &dyn CommandRunner) -> Result<(String, String), Error> {
    use crate::config_store;
    let dir = config_store::walk_up(start, "secrets.toml")
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| start.to_path_buf());
    let project = config_store::default_project(None, config_store::git_repo(r).as_deref(), &dir)?;
    let given = config_store::account_env().or_else(|| config_store::pointer_account(start));
    let account = config_store::pick_account(r, given)?.ok_or_else(no_account)?;
    Ok((project, account))
}

/// No `secrets.toml` from `start` up (05.02): the structural plan works on a configuration
/// file only. A project whose configuration is a 1Password manifest is told so, with the
/// manifest's own route (`opv config edit`), never `opv bootstrap`, which needs a file too;
/// with no configuration at all, the lookup's own cause says so.
fn no_file(start: &Path, r: &dyn CommandRunner) -> Error {
    use crate::config_store::{self, Found, Request};
    let req = Request {
        start: start.to_path_buf(),
        config: None,
        project: config_store::project_env(),
        manifest_only: true,
        account: config_store::account_env(),
    };
    match config_store::locate(&req, r) {
        Ok(Found::Manifest(m)) => Cause::ConfigSourceMismatch {
            command: CommandId("structure".into()),
            manifest: m.title,
        }
        .into(),
        Ok(Found::File { .. }) => Cause::Bug {
            site: "structure: a manifest-only lookup found a file",
        }
        .into(),
        Err(e) => e,
    }
}

/// One line per step of `p`, names and titles only, for a person to review.
pub fn describe(p: &Plan) -> Vec<String> {
    let mut out = Vec::new();
    for e in &p.environments {
        for b in &e.boundaries {
            if let BoundaryStep::Create { vault, item } = &b.step {
                out.push(format!(
                    "{}: create vault {vault:?} and item {item:?} for {} ({})",
                    e.environment,
                    b.boundary,
                    b.products.join(", ")
                ));
            }
        }
        for s in &e.state_vaults {
            if let StateStep::Create { vault } = &s.step {
                out.push(format!(
                    "{}: create state vault {vault:?} for target {}",
                    e.environment, s.target
                ));
            }
        }
    }
    for d in &p.delivery_items {
        out.push(format!(
            "{}: create delivery item {:?} for {} on target {}",
            d.environment, d.item, d.product, d.target
        ));
    }
    for f in &p.fields {
        out.push(format!(
            "{}: add empty {} field {}/{} to the {} item",
            f.environment, f.kind, f.product, f.key, f.boundary
        ));
    }
    out
}

/// One object apply created, by public ID, with the link a person opens to enter values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Created {
    /// `boundary`, `state_vault` or `delivery_item`.
    pub kind: &'static str,
    pub environment: String,
    /// The boundary, target, or `target/product` it belongs to.
    pub name: String,
    pub vault_id: String,
    pub item_id: Option<String>,
    /// The 1Password link to the item (boundaries: where values are entered).
    pub link: Option<String>,
}

/// What apply did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Applied {
    pub plan_id: String,
    pub created: Vec<Created>,
    pub fields_added: Vec<FieldStep>,
    /// True when the configuration file was updated with the new IDs.
    pub config_written: bool,
    /// For a generated configuration: the IDs for its generator's input, one line each.
    pub generator_ids: Vec<String>,
    /// Boundary items another edit landed on while fields were added (check their history).
    pub concurrent_edits: Vec<String>,
}

/// Apply exactly the plan `plan_id` to the configuration file `path` of `project` in
/// `account`: re-plan, refuse a stale id (`stale_plan`), refuse anyone but a person signed in
/// (before the single-use approval is spent), then `authorize` (the approval
/// check; nothing is written unless it passes), then create what the plan lists. IDs are
/// recorded as each phase completes, so a run that stops part-way keeps what it made, and
/// a re-run (with a new plan and approval) finds it again by title.
pub fn apply(
    r: &dyn CommandRunner,
    path: &Path,
    project: &str,
    account: &str,
    plan_id: &str,
    authorize: &mut dyn FnMut(&Plan) -> Result<(), Error>,
) -> Result<Applied, Error> {
    // C2: an id that is not a structural plan id names no plan at all.
    if !is_plan_id(plan_id) {
        return Err(Cause::PlanUnknown {
            plan: plan_id.to_string(),
            scope: Some(PlanScope::Structural),
        }
        .into());
    }
    let text = read(path)?;
    let p = plan(r, &text, project, account)?;
    if p.plan_id != plan_id {
        return Err(changed(plan_id, &p.plan_id));
    }
    // A person's own session first (#157): the approval is single-use, so a signed-out or
    // non-interactive run is refused before it is consumed.
    super::tidy::require_person(r, "the structural apply")?;
    authorize(&p)?;
    // The approval is used up from here: any failure says what was created and that the
    // approval is spent, and its step reads what remains (X4, X20), never this apply again.
    let mut applied = Applied {
        plan_id: p.plan_id.clone(),
        created: Vec::new(),
        fields_added: Vec::new(),
        config_written: false,
        generator_ids: Vec::new(),
        concurrent_edits: Vec::new(),
    };
    match apply_approved(r, path, project, &text, &p, &mut applied) {
        Ok(()) => Ok(applied),
        Err(e) => Err(after_approval(e, &applied)),
    }
}

/// What `applied` holds so far, by name and public ID, for a failure's "already written".
fn done(applied: &Applied) -> Vec<String> {
    let mut out: Vec<String> = applied
        .created
        .iter()
        .map(|c| match &c.item_id {
            Some(i) => format!(
                "{} {} in {} (vault {}, item {i})",
                c.kind, c.name, c.environment, c.vault_id
            ),
            None => format!(
                "{} {} in {} (vault {})",
                c.kind, c.name, c.environment, c.vault_id
            ),
        })
        .collect();
    out.extend(
        applied
            .fields_added
            .iter()
            .map(|f| format!("empty field {}/{} in {}", f.product, f.key, f.environment)),
    );
    out
}

/// A failure after the approval of `applied.plan_id` was used (X4, X20): a cataloged cause
/// is kept inside `Partial`, with what was created and the used approval; one not yet
/// cataloged is reported as the used approval, so no step ever repeats it.
fn after_approval(e: Error, applied: &Applied) -> Error {
    let plan = PlanId::new(&applied.plan_id);
    let mut written = done(applied);
    match e {
        Error::Catalog(cause, upstream) => {
            let cause = match *cause {
                Cause::Partial { done, then, .. } => {
                    written.extend(done);
                    Cause::Partial {
                        done: written,
                        approval_used: Some(plan),
                        approval_scope: Some(PlanScope::Structural),
                        then,
                    }
                }
                then => Cause::Partial {
                    done: written,
                    approval_used: Some(plan),
                    approval_scope: Some(PlanScope::Structural),
                    then: Box::new(then),
                },
            };
            Error::Catalog(Box::new(cause), upstream)
        }
        _ => Cause::ApprovalUsed {
            plan,
            scope: PlanScope::Structural,
            partial: !written.is_empty(),
        }
        .into(),
    }
}

/// The writes of an approved plan `p`, recorded into `applied` as they complete.
fn apply_approved(
    r: &dyn CommandRunner,
    path: &Path,
    project: &str,
    text: &str,
    p: &Plan,
    applied: &mut Applied,
) -> Result<(), Error> {
    let link_account = onepassword::account(r);
    let link = |v: &str, i: &str| onepassword::item_link(link_account.as_ref(), v, i);
    let mut doc = bootstrap::parse_doc(text)?;
    let mut recorded: Vec<Recorded> = Vec::new();
    let mut written_text = text.to_string();
    let phase = create_vaults(r, project, p, &mut recorded, applied, &link);
    record(path, p, &mut doc, &recorded, &mut written_text, applied)?;
    phase?;
    let fleet = crate::config::parse(&doc.to_string())?;
    let mut items = Vec::new();
    let phase = create_delivery_items(r, project, &fleet, &mut items, applied);
    for id in &items {
        id.write(&mut doc);
    }
    recorded.extend(items);
    record(path, p, &mut doc, &[], &mut written_text, applied)?;
    phase?;
    if p.generated {
        applied.generator_ids = recorded.iter().map(Recorded::line).collect();
    }
    let fleet = crate::config::parse(&doc.to_string())?;
    add_fields(r, &fleet, p, applied)
}

/// The configuration file at `path` (05.37: the path is named; no guessed `opv init`).
fn read(path: &Path) -> Result<String, Error> {
    std::fs::read_to_string(path)
        .map_err(|e| crate::config_store::unreadable(path, &e, GivenBy::Discovered))
}

/// Phase 1: every boundary vault and item and every state vault the plan creates (found by
/// title when a previous run made it).
fn create_vaults(
    r: &dyn CommandRunner,
    project: &str,
    p: &Plan,
    recorded: &mut Vec<Recorded>,
    applied: &mut Applied,
    link: &dyn Fn(&str, &str) -> String,
) -> Result<(), Error> {
    for e in &p.environments {
        let env = &e.environment;
        for b in &e.boundaries {
            let BoundaryStep::Create { vault, item } = &b.step else {
                continue;
            };
            let products: Vec<&str> = b.products.iter().map(String::as_str).collect();
            let notes = naming::boundary_notes(project, env, &products);
            let v = bootstrap::ensure_vault(r, vault, &notes)?;
            let i =
                bootstrap::ensure_item(r, &v.id, item, &bootstrap::env_tag(project, env), &notes)?;
            applied.created.push(Created {
                kind: "boundary",
                environment: env.clone(),
                name: b.boundary.clone(),
                vault_id: v.id.clone(),
                item_id: Some(i.id.clone()),
                link: Some(link(&v.id, &i.id)),
            });
            recorded.push(Recorded::Boundary {
                env: env.clone(),
                boundary: b.boundary.clone(),
                vault_id: v.id,
                item_id: i.id,
            });
        }
        for s in &e.state_vaults {
            let StateStep::Create { vault } = &s.step else {
                continue;
            };
            let notes = naming::state_vault_notes(project, env, &s.target);
            let v = bootstrap::ensure_vault(r, vault, &notes)?;
            applied.created.push(Created {
                kind: "state_vault",
                environment: env.clone(),
                name: s.target.clone(),
                vault_id: v.id.clone(),
                item_id: None,
                link: None,
            });
            recorded.push(Recorded::StateVault {
                env: env.clone(),
                target: s.target.clone(),
                vault_id: v.id,
            });
        }
    }
    Ok(())
}

/// Phase 2: each placement's delivery item in its target's state vault (every state vault
/// exists now).
fn create_delivery_items(
    r: &dyn CommandRunner,
    project: &str,
    fleet: &Fleet,
    recorded: &mut Vec<Recorded>,
    applied: &mut Applied,
) -> Result<(), Error> {
    for (env, e) in &fleet.environments {
        for (target, t) in &e.targets {
            for (product, item_id) in bootstrap::placement_items(fleet, project, env, target, r)? {
                applied.created.push(Created {
                    kind: "delivery_item",
                    environment: env.clone(),
                    name: format!("{target}/{product}"),
                    vault_id: t.state_vault_id.clone(),
                    item_id: Some(item_id.clone()),
                    link: None,
                });
                recorded.push(Recorded::DeliveryItem {
                    env: env.clone(),
                    target: target.clone(),
                    product,
                    item_id,
                });
            }
        }
    }
    Ok(())
}

/// Record `ids` in `doc` and save it over `path` when the file is not generated and still
/// holds what this run read (else `config_changed`: nothing is overwritten).
fn record(
    path: &Path,
    p: &Plan,
    doc: &mut toml_edit::DocumentMut,
    ids: &[Recorded],
    written: &mut String,
    applied: &mut Applied,
) -> Result<(), Error> {
    for id in ids {
        id.write(doc);
    }
    let new_text = doc.to_string();
    if p.generated || new_text == *written {
        return Ok(());
    }
    // Only IDs are added (the plan judged the completed file with placeholders); a part
    // recorded before a failure may not load yet, and is kept so a re-run need not find it.
    // 05.14: the file is not overwritten; what was created stays in 1Password and the
    // caller reports it with the used approval, whose step is the new structural plan.
    if read(path)? != *written {
        return Err(Cause::ChangedBeforeWrite {
            object: StoreObject::File {
                path: path.to_path_buf(),
            },
        }
        .into());
    }
    super::init::write_atomic(path, &new_text, true)?;
    *written = new_text;
    applied.config_written = true;
    Ok(())
}

/// Phase 3: every declared field still missing, empty, in each boundary item (one fresh
/// read and at most one edit per item; existing fields and values are never touched).
fn add_fields(
    r: &dyn CommandRunner,
    fleet: &Fleet,
    p: &Plan,
    applied: &mut Applied,
) -> Result<(), Error> {
    for e in &p.environments {
        let env_name = &e.environment;
        let env = fleet.environment(env_name)?;
        for (name, b) in super::tidy::boundaries_needed(fleet, env_name)? {
            let part = super::tidy::in_boundary(fleet, &name);
            let (item, missing) = super::skeleton::missing_fields(&part, env, b, env_name, r)?;
            if missing.is_empty() {
                continue;
            }
            let written = onepassword::write_skeleton(r, env, b, &item, &missing)?;
            if let (Some(v), Some(w)) = (item.version, written)
                && w != v + 1
            {
                applied.concurrent_edits.push(format!("{env_name}/{name}"));
            }
            applied
                .fields_added
                .extend(missing.into_iter().map(|(product, key, kind)| FieldStep {
                    environment: env_name.clone(),
                    boundary: name.clone(),
                    product,
                    key,
                    kind: super::kind_label(kind),
                }));
        }
    }
    applied.fields_added.sort();
    Ok(())
}

#[cfg(test)]
#[path = "structure_tests.rs"]
mod tests;
