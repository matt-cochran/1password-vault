//! The structural plan and its apply (#133): what `opv bootstrap` and `opv item skeleton`
//! would create for a project, as one reviewable plan with an id, and the apply of exactly
//! that plan once a person confirmed it in their own terminal (`opv apply`).
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
//! and every planned step, so a plan confirmed for one project, account or configuration
//! never applies to another, and any change since the review is `stale_plan`. Permission
//! grants, personal items, credentials, sync, deploy and rotation are not part of it.

use std::collections::BTreeSet;
use std::path::Path;

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::bootstrap::{self, BoundaryStep, EnvPlan, Recorded, StateStep};
use crate::adapters::onepassword;
use crate::cause::{
    Cause, CommandId, PlanId, PlanScope, Principal, SessionState, StoreObject, System, VarName,
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
        return Err(no_account("structure"));
    }
    let (environments, stale) = bootstrap::plan_checked(
        r,
        text,
        project,
        &BTreeSet::new(),
        true,
        Some(account),
        None,
    )?;
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
/// default account for a write. `command` is the opv command that needed it (G3).
fn no_account(command: &str) -> Error {
    match crate::host::Host::detect().op_credential {
        Some(c) => Cause::NeedsOwnSession {
            command: CommandId(command.into()),
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
/// 1Password changed): nothing was applied, and the step is the read of the new plan,
/// which a person then applies (05.15).
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
    /// op is never asked: every probe is unanswered (never "op did not start", which is a
    /// missing dependency, design §5), so a recorded ID is taken as it is.
    fn probe(
        &self,
        _: &crate::runner::Call,
        _: std::time::Duration,
    ) -> std::io::Result<crate::runner::Output> {
        Err(std::io::ErrorKind::TimedOut.into())
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

/// Where a structural plan's configuration lives (D-G): a contract file with its sibling
/// `secrets.bindings.toml`, or a project manifest in 1Password with its contract block and
/// its `toml opv-bindings` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigAt {
    File(std::path::PathBuf),
    Manifest(crate::config_store::ManifestStore),
}

impl ConfigAt {
    /// The contract with its bindings filled in: the text the structural plan reads. An
    /// inline id is refused, as at load.
    pub fn read_merged(&self, r: &dyn CommandRunner) -> Result<String, Error> {
        use crate::config_store::ConfigStore;
        match self {
            ConfigAt::File(path) => crate::config::read_merged(path),
            ConfigAt::Manifest(m) => Ok(m.read(r)?.text),
        }
    }

    /// [`read_merged`](Self::read_merged) past `op`'s cache for a manifest (refused unless
    /// a person runs opv, I3): the read an apply plans and checks its writes against.
    pub fn read_for_write(&self, r: &dyn CommandRunner) -> Result<String, Error> {
        match self {
            ConfigAt::File(path) => crate::config::read_merged(path),
            ConfigAt::Manifest(m) => m.read_merged_fresh(r),
        }
    }

    /// Save `text` (the contract with its ids filled in), its ids split out (D-G): a file's
    /// contract and sibling bindings, or a manifest's contract block and `opv-bindings` block
    /// in one verified edit. The contract is written too: an id for a boundary the contract
    /// declared only through the product leaves its `boundaries.<name> = {}` table there,
    /// without which the id would fill nothing at the next load.
    fn write(&self, r: &dyn CommandRunner, text: &str) -> Result<(), Error> {
        match self {
            ConfigAt::File(path) => super::init::write_config(path, text, true),
            ConfigAt::Manifest(m) => {
                let (contract, ids) = crate::config::bindings::split(text);
                m.write_bindings(r, Some(&contract), &ids)
            }
        }
    }

    /// The store object a `changed_before_write` names.
    fn store_object(&self) -> StoreObject {
        use crate::config_store::ConfigStore;
        match self {
            ConfigAt::File(path) => StoreObject::File { path: path.clone() },
            ConfigAt::Manifest(m) => crate::config_store::store_object(&m.cause_source()),
        }
    }
}

/// Where a structural plan applies: the configuration (a file or a manifest), the project
/// and the 1Password account (an account ID), resolved the same way for the CLI and the MCP
/// tools.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    pub config: ConfigAt,
    pub project: String,
    pub account: String,
}

/// The [`Scope`] of the checkout at `start`: its `secrets.toml` (here or in a parent), else
/// the project's manifest in 1Password; its project name (git remote, else directory, or
/// the manifest's own project), and its account (`OP_ACCOUNT`, else the `.opv` pointer,
/// else the only account op knows; a manifest's, when it was found in one). No account, or
/// several and none chosen, is `account_required`: opv never uses op's default for a write.
/// A `project` given (`--project`) names the project instead: a file configuration's new
/// vault titles, or the manifest looked up.
pub fn scope(start: &Path, r: &dyn CommandRunner, project: Option<&str>) -> Result<Scope, Error> {
    scope_named(start, r, &invoked("propose structure"), project)
}

/// [`scope`] for the opv command `command` (an MCP tool names its command itself, L8:
/// its refusal is the CLI's word for word).
pub fn scope_as(start: &Path, r: &dyn CommandRunner, command: &str) -> Result<Scope, Error> {
    scope_named(start, r, command, None)
}

/// [`scope_as`] with the project name `project` when one is given (`--project`); without
/// it, the repository's name, else the directory's.
pub fn scope_named(
    start: &Path,
    r: &dyn CommandRunner,
    command: &str,
    project: Option<&str>,
) -> Result<Scope, Error> {
    use crate::config_store;
    let Some(path) = config_store::walk_up(start, "secrets.toml") else {
        return manifest_scope(start, r, command, project);
    };
    let project = config_store::default_project(
        project,
        config_store::git_repo(r).as_deref(),
        path.parent().unwrap_or(start),
    )?;
    let given = config_store::account_env().or_else(|| config_store::pointer_account(start));
    let account = config_store::pick_account(r, given)?.ok_or_else(|| no_account(command))?;
    Ok(Scope {
        config: ConfigAt::File(path),
        project,
        account,
    })
}

/// The opv command this run is (`sync`, `structure plan`), for a refusal that
/// names it (G3); `default` under the MCP server, whose tools name their own.
fn invoked(default: &str) -> String {
    let command = crate::error::invocation().command.join(" ");
    match command.as_str() {
        "" | "mcp" => default.to_string(),
        _ => command,
    }
}

/// The project and 1Password account of the checkout at `start`, resolved like [`scope`]
/// but without needing a local `secrets.toml` (a configuration may be kept in 1Password),
/// for the opv command `command` (an MCP tool names its command itself).
/// A `project` given (`--project`) is the project name instead.
pub fn binding_as(
    start: &Path,
    r: &dyn CommandRunner,
    command: &str,
    project: Option<&str>,
) -> Result<(String, String), Error> {
    use crate::config_store;
    let dir = config_store::walk_up(start, "secrets.toml")
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| start.to_path_buf());
    let project =
        config_store::default_project(project, config_store::git_repo(r).as_deref(), &dir)?;
    let given = config_store::account_env().or_else(|| config_store::pointer_account(start));
    let account = config_store::pick_account(r, given)?.ok_or_else(|| no_account(command))?;
    Ok((project, account))
}

/// No `secrets.toml` from `start` up: the project's manifest in 1Password (D-G), whose
/// project is its own and whose account is the one it was found in (else chosen as for a
/// file). With no configuration at all, the lookup's own cause says so (05.02: never
/// `opv bootstrap`).
fn manifest_scope(
    start: &Path,
    r: &dyn CommandRunner,
    command: &str,
    project: Option<&str>,
) -> Result<Scope, Error> {
    use crate::cause::ConfigSource;
    use crate::config_store::{self, ConfigStore, Found, Request};
    let req = Request {
        start: start.to_path_buf(),
        config: None,
        project: project
            .map(str::to_string)
            .or_else(config_store::project_env),
        manifest_only: true,
        account: config_store::account_env(),
    };
    let m = match config_store::locate(&req, r)? {
        Found::Manifest(m) => m,
        Found::File { .. } => {
            return Err(Cause::Bug {
                site: "structure: a manifest-only lookup found a file",
            }
            .into());
        }
    };
    let ConfigSource::Manifest { project, .. } = m.cause_source() else {
        return Err(Cause::Bug {
            site: "structure: a manifest named no manifest source",
        }
        .into());
    };
    let given = m
        .account
        .clone()
        .or_else(config_store::account_env)
        .or_else(|| config_store::pointer_account(start));
    let account = config_store::pick_account(r, given)?.ok_or_else(|| no_account(command))?;
    Ok(Scope {
        config: ConfigAt::Manifest(m),
        project,
        account,
    })
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
/// `account`: re-plan, refuse a stale id (`stale_plan`), refuse anyone but a person signed in,
/// then `authorize` (the caller's check that this is the plan the person confirmed; nothing
/// is written unless it passes), then create what the plan lists. IDs are recorded as each
/// phase completes, so a run that stops part-way keeps what it made, and a re-run (with a
/// new plan) finds it again by title.
pub fn apply(
    r: &dyn CommandRunner,
    path: &Path,
    project: &str,
    account: &str,
    plan_id: &str,
    authorize: &mut dyn FnMut(&Plan) -> Result<(), Error>,
) -> Result<Applied, Error> {
    let at = ConfigAt::File(path.to_path_buf());
    apply_at(r, &at, project, account, plan_id, authorize)
}

/// [`apply`] to the configuration `at`, a file or a manifest (D-G: a manifest's new ids go
/// to its `opv-bindings` block).
pub fn apply_at(
    r: &dyn CommandRunner,
    at: &ConfigAt,
    project: &str,
    account: &str,
    plan_id: &str,
    authorize: &mut dyn FnMut(&Plan) -> Result<(), Error>,
) -> Result<Applied, Error> {
    apply_on(
        r,
        at,
        project,
        account,
        plan_id,
        crate::host::Host::detect(),
        authorize,
    )
}

/// [`apply_at`] with the person's own-session check judged by `host` (the host the caller
/// was given, as `opv apply`'s is), never by this process's variables.
pub fn apply_on(
    r: &dyn CommandRunner,
    at: &ConfigAt,
    project: &str,
    account: &str,
    plan_id: &str,
    host: crate::host::Host,
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
    let text = at.read_for_write(r)?;
    let p = plan(r, &text, project, account)?;
    if p.plan_id != plan_id {
        return Err(changed(plan_id, &p.plan_id));
    }
    // A person's own session first (#157): a signed-out or non-interactive run is refused
    // before anything is authorized or written.
    super::tidy::require_person_on(r, "the structural apply", host)?;
    authorize(&p)?;
    // Writes may start from here: any failure says what was created, and its step reads
    // what remains (X4, X20), never this apply again.
    let mut applied = Applied {
        plan_id: p.plan_id.clone(),
        created: Vec::new(),
        fields_added: Vec::new(),
        config_written: false,
        generator_ids: Vec::new(),
        concurrent_edits: Vec::new(),
    };
    match apply_confirmed(r, at, project, &text, &p, &mut applied) {
        Ok(()) => Ok(applied),
        Err(e) => Err(after_authorized(e, &applied)),
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

/// A failure after `applied.plan_id` was authorized (X4, X20): a cataloged cause is kept
/// inside `Partial`, with what was created; its step reads what remains in the structural
/// scope, so no step ever repeats the apply.
fn after_authorized(e: Error, applied: &Applied) -> Error {
    let mut written = done(applied);
    let Error::Catalog(cause, upstream) = e;
    let cause = match *cause {
        Cause::Partial { done, then, .. } => {
            written.extend(done);
            Cause::Partial {
                done: written,
                scope: Some(PlanScope::Structural),
                then,
            }
        }
        then => Cause::Partial {
            done: written,
            scope: Some(PlanScope::Structural),
            then: Box::new(then),
        },
    };
    Error::Catalog(Box::new(cause), upstream)
}

/// The writes of a confirmed plan `p`, recorded into `applied` as they complete.
fn apply_confirmed(
    r: &dyn CommandRunner,
    at: &ConfigAt,
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
    record(r, at, p, &mut doc, &recorded, &mut written_text, applied)?;
    phase?;
    let fleet = crate::config::parse(&doc.to_string())?;
    let mut items = Vec::new();
    let phase = create_delivery_items(r, project, &fleet, &mut items, applied);
    for id in &items {
        id.write(&mut doc);
    }
    recorded.extend(items);
    record(r, at, p, &mut doc, &[], &mut written_text, applied)?;
    phase?;
    if p.generated {
        applied.generator_ids = recorded.iter().map(Recorded::line).collect();
    }
    let fleet = crate::config::parse(&doc.to_string())?;
    add_fields(r, &fleet, p, applied)
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
                    vault_id: fleet.state_vault(env, t)?.to_string(),
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

/// Record `ids` in `doc` and save it to `at` when the configuration is not generated and
/// still holds what this run read (else `config_changed`: nothing is overwritten).
fn record(
    r: &dyn CommandRunner,
    at: &ConfigAt,
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
    // 05.14: the configuration is not overwritten; what was created stays in 1Password and
    // the caller reports it as partial, whose step is the new structural plan.
    if at.read_for_write(r)? != *written {
        return Err(Cause::ChangedBeforeWrite {
            object: at.store_object(),
        }
        .into());
    }
    at.write(r, &new_text)?;
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
