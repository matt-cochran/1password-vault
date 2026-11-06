//! `opv import <env> --from <dotenv>|target:<name> [--replace <product/KEY>]...
//! [--dry-run] [--json]` (FR-53, #78): bring values that already exist elsewhere into the
//! environment's 1Password item, after a review. The plan is
//! [`crate::domain::import::plan`]; this module reads the source, prints the plan (names,
//! actions and presence words only) and, unless `--dry-run`, writes it into each key's
//! boundary item, one verified edit per item. The default writes; `--dry-run` writes
//! nothing. It never syncs, deploys, prunes, revokes or deletes the source. The bare
//! `--from target` form was removed (FR-60): `--from target:<name>` names the target one
//! way only.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::PathBuf;

use super::write_err;
use crate::adapters::{onepassword, onepassword_tidy};
use crate::cause::{
    Cause, Cmd, EnvName, FieldName, Guard, ItemId, NameKind, UsageProblem, VaultId,
};
use crate::domain::convention::{self, KEPT_SECTION, Op, TidyPlan};
use crate::domain::import::{Action, AdoptPlan};
use crate::domain::{Boundary, Fleet, Kind, SecretValue, key_label};
use crate::error::Error;
use crate::ports::Ports;
use crate::runner::CommandRunner;

/// Where the values come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// A dotenv file the owner points at (literal assignments, never executed).
    Dotenv(PathBuf),
    /// The named target of the environment, where it can read values back.
    Target(String),
}

/// The [`Source`] named by `--from <value>` (FR-53, FR-56, FR-60): a dotenv file path, or
/// `target:<name>` for the named target of `env_name`. The bare `target` form was removed
/// and is a usage error that names the environment's targets and the `target:<name>` form.
pub fn source_from(fleet: &Fleet, env_name: &str, from: &str) -> Result<Source, Error> {
    if let Some(name) = from.strip_prefix("target:") {
        if name.is_empty() {
            return Err(bare_target(fleet, env_name));
        }
        super::target(fleet, env_name, name)?;
        return Ok(Source::Target(name.to_string()));
    }
    if from == "target" {
        return Err(bare_target(fleet, env_name));
    }
    Ok(Source::Dotenv(PathBuf::from(from)))
}

/// The usage error for the removed bare `--from target` (FR-60): with one target, the same
/// command with `--from target:<name>` (every other flag kept); with several, the person
/// picks one of the `target:<name>` forms (never a guessed first target, X2).
fn bare_target(fleet: &Fleet, env_name: &str) -> Error {
    let names = match super::resolve_targets(fleet, env_name, &[], "import") {
        Ok(names) => names,
        Err(e) => return e,
    };
    let forms: Vec<String> = names.iter().map(|n| format!("target:{n}")).collect();
    match forms.as_slice() {
        [only] => Cause::Usage {
            problem: UsageProblem::UseInstead {
                command: with_named_target(env_name, only),
            },
        }
        .into(),
        _ => Cause::ChoiceRequired {
            flag: "--from".into(),
            candidates: forms,
        }
        .into(),
    }
}

/// The person's own `opv import` with its bare `--from target` replaced by `form`, every
/// other flag kept; the plain `opv import <env> --from <form>` when the command line does
/// not show that word (an MCP call, `--from=target`).
fn with_named_target(env_name: &str, form: &str) -> Cmd {
    let inv = crate::error::invocation();
    let changed = inv.with_arg("target", form);
    if inv.command == ["import"] && changed.args.iter().any(|a| a == form) {
        return Cmd {
            command: changed.command,
            args: changed.args,
        };
    }
    Cmd {
        command: vec!["import".into()],
        args: vec![env_name.to_string(), "--from".into(), form.to_string()],
    }
}

/// Options of `opv import`.
#[derive(Debug, Clone)]
pub struct Opts {
    pub source: Source,
    /// `product/KEY` to replace a value that is already set.
    pub replace: Vec<String>,
    /// Immutable keys `--replace` may change.
    pub rotate: Vec<String>,
    /// `product/KEY` (or `KEY`) left out of the import (#94).
    pub skip: Vec<String>,
    /// Show the plan and write nothing; the default writes (inverted `apply`).
    pub dry_run: bool,
    /// `--confirm <env>`: the environment's name again, required to write into one with
    /// `confirm_env = true` or `tier = "production"` (§21 P-11).
    pub confirm: Option<String>,
    pub json: bool,
}

/// `product/KEY` entries as `(product, key)` pairs, each declared: a malformed entry is a
/// usage error, an undeclared one `NotDeclared` naming the declared keys (05.39).
fn pairs(
    fleet: &Fleet,
    entries: &[String],
    flag: &str,
) -> Result<BTreeSet<(String, String)>, Error> {
    entries
        .iter()
        .map(|e| {
            let Some((p, k)) = e.split_once('/') else {
                return Err(Cause::Usage {
                    problem: UsageProblem::ValueFormat {
                        flag: flag.to_string(),
                        format: "<product>/<KEY>",
                    },
                }
                .into());
            };
            if fleet
                .products
                .get(p)
                .is_none_or(|prod| !prod.keys.contains_key(k))
            {
                let declared: Vec<String> = fleet
                    .products
                    .iter()
                    .flat_map(|(p, prod)| prod.keys.keys().map(move |k| key_label(p, k)))
                    .collect();
                return Err(super::not_declared(
                    NameKind::Key,
                    e,
                    declared.iter().map(String::as_str),
                ));
            }
            Ok((p.to_string(), k.to_string()))
        })
        .collect()
}

/// Refuse a value path (`set`, `import --replace`, `open`) for `product/key` in `env_name`
/// when it is an infrastructure key (#206 §4.4): the deploy job supplies its value to
/// `opv sync`, and opv keeps no 1Password field for it. Names only, from the configuration.
pub(crate) fn refuse_not_stored(
    fleet: &Fleet,
    product: &str,
    key: &str,
    env_name: &str,
) -> Result<(), Error> {
    let infrastructure = fleet
        .products
        .get(product)
        .and_then(|p| p.keys.get(key))
        .is_some_and(super::deliver_only::is_infrastructure);
    if !infrastructure {
        return Ok(());
    }
    Err(Cause::Guard {
        guard: Guard::NotStored {
            product: crate::cause::ProductName::new(product),
            key: crate::cause::KeyName::new(key),
            env: EnvName::new(env_name),
        },
    }
    .into())
}

/// Refuse a lone write of `product/key` in `env_name` when it is a member of a set (design
/// `owner-value-ingestion.md` §5.6, #262): a set's members are made and written together,
/// only by `opv provision`. Names only, from the configuration.
pub(crate) fn refuse_set_member(
    fleet: &Fleet,
    product: &str,
    key: &str,
    env_name: &str,
) -> Result<(), Error> {
    let Some(set) = fleet.set_of(product, key) else {
        return Ok(());
    };
    Err(Cause::Guard {
        guard: Guard::SetMember {
            product: crate::cause::ProductName::new(product),
            key: crate::cause::KeyName::new(key),
            env: EnvName::new(env_name),
            set: set.to_string(),
        },
    }
    .into())
}

/// [`refuse_set_member`] for every value a plan would write.
fn refuse_set_member_writes(fleet: &Fleet, env_name: &str, plan: &AdoptPlan) -> Result<(), Error> {
    plan.writes
        .iter()
        .try_for_each(|(p, k, _)| refuse_set_member(fleet, p, k, env_name))
}

/// The found values: the dotenv file, or what the target can read back. A target that
/// cannot show values (Fly secrets, GitHub secrets) is refused with the manual way.
fn read_source(
    fleet: &Fleet,
    env_name: &str,
    source: &Source,
    r: &dyn CommandRunner,
) -> Result<BTreeMap<String, SecretValue>, Error> {
    match source {
        Source::Dotenv(path) => super::setup::read_legacy(path),
        Source::Target(name) => {
            let (t, ports) = super::open_target(fleet, env_name, name, r)?;
            match &ports {
                Ports::Pinned { store, .. } => {
                    let mut found = BTreeMap::new();
                    for managed in super::managed_names(fleet, env_name, name)? {
                        if let Some((value, _)) = store.read(&managed)? {
                            found.insert(managed, value);
                        }
                    }
                    Ok(found)
                }
                Ports::Staged { store, .. } => match store.variables() {
                    Some(v) => Ok(v
                        .list()?
                        .into_iter()
                        .map(|(n, val)| (n, SecretValue::new(val)))
                        .collect()),
                    // 05.03: the guard's own step, never this same command again.
                    None => Err(Cause::Guard {
                        guard: Guard::ProviderHidesValues {
                            system: crate::provider::system_of(t.provider()),
                        },
                    }
                    .into()),
                },
            }
        }
    }
}

/// `opv import`: the plan, and unless `--dry-run` the verified write.
pub fn run(
    fleet: &Fleet,
    env_name: &str,
    opts: &Opts,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    require_confirm(fleet, env_name, opts)?;
    run_tagged(fleet, env_name, opts, None, r, out)
}

/// §21 P-11 (as `opv sync`'s NR-20 guard): a person's `opv import` into an environment with
/// `confirm_env = true` or `tier = "production"` writes only with `--confirm <env>`. A
/// `--confirm` naming another environment is refused whatever the environment (a
/// wrong-window typo); both refusals come before any call. `--dry-run` writes nothing and
/// needs no confirmation.
fn require_confirm(fleet: &Fleet, env_name: &str, opts: &Opts) -> Result<(), Error> {
    let env = fleet.environment(env_name)?;
    let guarded = env.confirm_env || env.tier == crate::domain::Tier::Production;
    match opts.confirm.as_deref() {
        Some(c) if c != env_name => Err(Cause::ConfirmMismatch {
            given: c.to_string(),
            env: EnvName::new(env_name),
        }
        .into()),
        None if guarded && !opts.dry_run => Err(Cause::NeedsConfirm {
            env: EnvName::new(env_name),
        }
        .into()),
        _ => Ok(()),
    }
}

/// [`run`] with `tag` added to every written item's 1Password tags (design row
/// `import-local`). The tag rides the same verified `op item edit` as the values and is
/// never a value; `None` is plain `opv import`.
pub fn run_tagged(
    fleet: &Fleet,
    env_name: &str,
    opts: &Opts,
    tag: Option<&str>,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let replace = pairs(fleet, &opts.replace, "--replace")?;
    let rotate = pairs(fleet, &opts.rotate, "--rotate")?;
    let skip = pairs(fleet, &opts.skip, "--skip")?;
    // Asking to replace or rotate an infrastructure key is refused by name (#206 §4.4); a
    // found value of one is only ever planned `not_stored`.
    // A set member is written only by `opv provision` (§5.6), so asking for one is refused.
    for (p, k) in replace.iter().chain(&rotate) {
        refuse_not_stored(fleet, p, k, env_name)?;
        refuse_set_member(fleet, p, k, env_name)?;
    }
    let plan = plan_skipping(
        fleet,
        env_name,
        &opts.source,
        (&replace, &rotate, &skip),
        !opts.dry_run,
        tag,
        &apply_command(env_name, opts),
        r,
    )?;
    print(out, env_name, opts, &plan)
}

/// The three key sets of `opv import`: `--replace`, `--rotate`, `--skip`.
type KeySets<'a> = (
    &'a BTreeSet<(String, String)>,
    &'a BTreeSet<(String, String)>,
    &'a BTreeSet<(String, String)>,
);

/// [`plan_and_write`] with `--skip`: an import of a key it names becomes `Skipped` and is
/// not written (#94). Only imports are skipped; a replace is already opt-in.
#[allow(clippy::too_many_arguments)]
fn plan_skipping(
    fleet: &Fleet,
    env_name: &str,
    source: &Source,
    (replace, rotate, skip): KeySets<'_>,
    apply: bool,
    tag: Option<&str>,
    by: &Cmd,
    r: &dyn CommandRunner,
) -> Result<AdoptPlan, Error> {
    let mut plan = plan_and_write(fleet, env_name, source, replace, rotate, false, r)?;
    let named = |p: &Option<String>, k: &Option<String>| match (p, k) {
        (Some(p), Some(k)) => skip.contains(&(p.clone(), k.clone())),
        _ => false,
    };
    for row in &mut plan.rows {
        if row.action == Action::Imported && named(&row.product, &row.key) {
            row.action = Action::Skipped;
        }
    }
    plan.writes
        .retain(|(p, k, _)| !skip.contains(&(p.clone(), k.clone())));
    // A found value of a set member is refused in the review too (§5.6); `--skip` leaves it
    // out and imports the rest.
    refuse_set_member_writes(fleet, env_name, &plan)?;
    if apply {
        super::tidy::require_person(r, "opv import")?;
        if !plan.writes.is_empty() {
            write(fleet, fleet.environment(env_name)?, by, &plan, tag, r)?;
        }
    }
    Ok(plan)
}

/// The adoption plan for `source`, written (one verified item edit) when `apply`. Also the
/// import step of `opv init --from … --apply` (#90).
pub fn plan_and_write(
    fleet: &Fleet,
    env_name: &str,
    source: &Source,
    replace: &BTreeSet<(String, String)>,
    rotate: &BTreeSet<(String, String)>,
    apply: bool,
    r: &dyn CommandRunner,
) -> Result<AdoptPlan, Error> {
    let env = fleet.environment(env_name)?;
    if apply {
        super::tidy::require_person(r, "opv import")?;
    }
    let found = read_source(fleet, env_name, source, r)?;
    // The item as the commands read it (tidied first when a person runs opv).
    let read = super::tidy::read(fleet, env_name, r)?;
    let plan = crate::domain::import::plan(fleet, env_name, &read.fields, &found, replace, rotate);
    if apply && !plan.writes.is_empty() {
        refuse_set_member_writes(fleet, env_name, &plan)?;
        write(fleet, env, &plan_command(&env.name, source), &plan, None, r)?;
    }
    Ok(plan)
}

/// Write `plan.writes` in one item edit per boundary item (FR-57), each value into its
/// key's boundary, keeping a replaced value in `opv · kept`, then read each item back and
/// verify every written field holds what was written. `by` is the command that wrote,
/// named by a read-back failure as the one to run again.
fn write(
    fleet: &Fleet,
    env: &crate::domain::Environment,
    by: &Cmd,
    plan: &AdoptPlan,
    tag: Option<&str>,
    r: &dyn CommandRunner,
) -> Result<(), Error> {
    write_values_tagged(fleet, env, &plan.writes, tag, by, r)
}

/// The adoption plan's own read, `import <env> --from <source>`: after a write it shows
/// what is in 1Password now and what remains (05.10).
fn plan_command(env_name: &str, source: &Source) -> Cmd {
    let from = match source {
        Source::Dotenv(p) => p.display().to_string(),
        Source::Target(name) => format!("target:{name}"),
    };
    Cmd {
        command: vec!["import".into()],
        args: vec![env_name.to_string(), "--from".into(), from],
    }
}

/// Write `writes` (product, key, value) into their boundary items, one verified edit per
/// item (shared with `opv generate`, 0.9.0). `by` is the command that wrote, named by a
/// read-back failure as the one to run again.
pub fn write_values(
    fleet: &Fleet,
    env: &crate::domain::Environment,
    writes: &[(String, String, SecretValue)],
    by: &Cmd,
    r: &dyn CommandRunner,
) -> Result<(), Error> {
    write_values_tagged(fleet, env, writes, None, by, r)
}

/// [`write_values`] with `tag` added to each written item's 1Password tags on the same
/// verified edit (design row `import-local`).
pub fn write_values_tagged(
    fleet: &Fleet,
    env: &crate::domain::Environment,
    writes: &[(String, String, SecretValue)],
    tag: Option<&str>,
    by: &Cmd,
    r: &dyn CommandRunner,
) -> Result<(), Error> {
    let mut by_boundary: BTreeMap<&str, Vec<&(String, String, SecretValue)>> = BTreeMap::new();
    for w in writes {
        by_boundary
            .entry(fleet.boundary_of(&w.0))
            .or_default()
            .push(w);
    }
    for (name, writes) in by_boundary {
        let b = fleet.boundary(&env.name, &writes[0].0)?;
        let part = super::tidy::in_boundary(fleet, name);
        write_item(&part, env, b, &writes, tag, by, None, r)?;
    }
    Ok(())
}

/// Add `tag` to the whole-item `template`'s `tags` array, keeping any it already carries.
/// Value-free metadata; the same JSON that holds the values on the one `op item edit`.
fn tag_template(
    mut template: zeroize::Zeroizing<Vec<u8>>,
    tag: &str,
) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
    let mut doc: serde_json::Value = serde_json::from_slice(&template).map_err(|_| Cause::Bug {
        site: "import tag template",
    })?;
    if let Some(obj) = doc.as_object_mut() {
        let tags = obj
            .entry("tags")
            .or_insert_with(|| serde_json::Value::Array(Vec::new()));
        if let Some(arr) = tags.as_array_mut()
            && !arr.iter().any(|t| t.as_str() == Some(tag))
        {
            arr.push(serde_json::Value::String(tag.to_string()));
        }
    }
    let bytes = serde_json::to_vec(&doc).map_err(|_| Cause::Bug {
        site: "import tag template",
    })?;
    template.clear();
    template.extend_from_slice(&bytes);
    Ok(template)
}

/// What a caller planned its write on (design `owner-value-ingestion.md` §4.6 step 1, D10):
/// the item's stamp `S0` and its layout at that read, and the fields that must not have
/// changed since. `set`, `import` and `generate` plan on the writer's own read and pass none.
pub struct Expected<'a> {
    /// The stamp (`version`, `updated_at`) of the read the caller planned on.
    pub stamp: &'a onepassword_tidy::Stamp,
    /// The item as the caller read it at `stamp`.
    pub seen: &'a convention::Layout,
    /// `(product, key)` whose field (presence and value) must be what `seen` holds.
    pub members: &'a [(String, String)],
}

/// What the one checked writer did: the edit landed and every written field was read back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Written {
    /// The item's version the final fresh read verified (`verified at version N`).
    pub version: Option<u64>,
    /// The edit's version was not exactly one past the writer's own read: another edit
    /// landed just before opv's and may have been replaced (kept only in the item's
    /// history). Detected, never prevented: `op` 2.40 has no version precondition.
    pub concurrent_edit: bool,
}

/// The one checked writer (D10): `writes` into the boundary item `b`, holding `fleet`'s
/// products, shared by `set`, `import`, `generate` and `provision`.
///
/// 1. A fresh read (`S1`) builds the whole-item template. With `expected`, a stamp other
///    than its `S0` is refused `ChangedBeforeWrite` (nothing written) when any of its
///    member fields changed; otherwise the write is re-planned on `S1`.
/// 2. One `op item edit`, the template (values included) on stdin only, never argv.
/// 3. The version the edit echoes must be `S1 + 1`; otherwise the write still stands but is
///    reported as a [`Written::concurrent_edit`]. 1Password offers no compare-and-swap
///    (`op` 2.40 has no version-precondition flag), so an edit racing opv's is detected
///    here, not prevented.
/// 4. A final fresh read: every field the template holds or kept is there
///    ([`onepassword_tidy::lost`]) and every written field holds its value, else
///    `ReadBackMissing` naming `by`.
/// 5. An edit whose outcome is unknown (timeout, kill, lost reply) is decided by that final
///    read: the written values there is success; the item still at `S1` with the written
///    fields unchanged is "not written; safe to re-run"; anything else stays
///    `WriteOutcomeUnknown`. Both failures keep the unknown outcome's exit.
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_item(
    fleet: &Fleet,
    env: &crate::domain::Environment,
    b: &Boundary,
    writes: &[&(String, String, SecretValue)],
    tag: Option<&str>,
    by: &Cmd,
    expected: Option<&Expected<'_>>,
    r: &dyn CommandRunner,
) -> Result<Written, Error> {
    let item = onepassword::read_whole_fresh(r, env, b)?;
    let (layout, stamp) = onepassword_tidy::parse(item.raw())?;
    let res = convention::resolve(&layout, fleet);
    if let Some(exp) = expected
        && stamp != *exp.stamp
    {
        let before = convention::resolve(exp.seen, fleet);
        let changed = exp
            .members
            .iter()
            .any(|id| !same_field(field_of(exp.seen, &before, id), field_of(&layout, &res, id)));
        if changed {
            r.note(&format!(
                "1Password ({}): a field opv was about to write changed since opv read the \
                 item; nothing written.",
                env.name
            ));
            return Err(Cause::ChangedBeforeWrite {
                object: crate::cause::StoreObject::Item {
                    vault: VaultId::new(&b.vault_id),
                    item: ItemId::new(&b.item_id),
                },
            }
            .into());
        }
    }
    let date = super::tidy::today();
    let mut ops = Vec::new();
    let mut kept = false;
    for (product, key, value) in writes.iter().copied() {
        let id = (product.clone(), key.clone());
        let kind = fleet.products[product].keys[key].kind;
        match res.chosen.get(&id) {
            Some(&i) => {
                let old = &layout.fields[i].value;
                if !old.expose().is_empty() {
                    ops.push(Op::Add {
                        section: Some(KEPT_SECTION.to_string()),
                        label: format!(
                            "{} (replaced by opv import, {date})",
                            key_label(product, key)
                        ),
                        concealed: true,
                        value: Some(SecretValue::new(old.expose().to_string())),
                    });
                    kept = true;
                }
                ops.push(Op::SetValue {
                    index: i,
                    value: SecretValue::new(value.expose().to_string()),
                });
            }
            None => ops.push(Op::Add {
                section: Some(product.clone()),
                label: key.clone(),
                concealed: kind == Kind::Secret,
                value: Some(SecretValue::new(value.expose().to_string())),
            }),
        }
    }
    let tidy = TidyPlan {
        ops,
        changes: Vec::new(),
        kept,
    };
    let template = onepassword_tidy::apply(item.raw(), &tidy)?;
    let template = match tag {
        Some(tag) => tag_template(template, tag)?,
        None => template,
    };
    let (echoed_version, unknown) = match onepassword_tidy::write(r, env, b, &template) {
        Ok(echoed) => (onepassword::item_version(&echoed), None),
        Err(e) if is_unknown_outcome(&e) => (None, Some(e)),
        Err(e) => return Err(e),
    };
    // The final fresh read decides, whatever the edit answered.
    let after = match onepassword::read_whole_fresh(r, env, b) {
        Ok(after) => after,
        Err(e) => return Err(unknown.unwrap_or(e)),
    };
    let (after_layout, _) = onepassword_tidy::parse(after.raw())?;
    let after_res = convention::resolve(&after_layout, fleet);
    let mut missing: Vec<FieldName> = writes
        .iter()
        .copied()
        .filter(|(p, k, v)| {
            let id = (p.clone(), k.clone());
            !field_of(&after_layout, &after_res, &id).is_some_and(|f| same(f, v))
        })
        .map(|(p, k, _)| FieldName::new(key_label(p, k)))
        .collect();
    for f in onepassword_tidy::lost(item.raw(), &template, after.raw())? {
        if !missing.contains(&f) {
            missing.push(f);
        }
    }
    drop(template);
    if let Some(unknown) = unknown {
        if !missing.is_empty() {
            let untouched = after.version.is_some()
                && after.version == item.version
                && writes.iter().copied().all(|(p, k, _)| {
                    let id = (p.clone(), k.clone());
                    same_field(
                        field_of(&layout, &res, &id),
                        field_of(&after_layout, &after_res, &id),
                    )
                });
            r.note(&if untouched {
                format!(
                    "1Password ({}): opv's edit of the item did not land: not written; safe to \
                     re-run.",
                    env.name
                )
            } else {
                format!(
                    "1Password ({}): opv cannot tell whether its edit of the item landed; \
                     check the item (and its history) in 1Password before re-running.",
                    env.name
                )
            });
            return Err(unknown);
        }
        r.note(&format!(
            "1Password ({}): the edit's reply was lost; the item read back holds what opv \
             wrote.",
            env.name
        ));
    }
    if !missing.is_empty() {
        // 05.10: the command that wrote is named, not always `opv import`.
        return Err(Cause::ReadBackMissing {
            vault: VaultId::new(&b.vault_id),
            item: ItemId::new(&b.item_id),
            fields: missing,
            by: by.clone(),
        }
        .into());
    }
    // Step 3: the echoed version (or, without one, the version read back) against `S1 + 1`.
    let landed = echoed_version.or(after.version);
    let concurrent_edit = item.version.is_some_and(|v| landed != Some(v + 1));
    if concurrent_edit {
        r.note(&format!(
            "1Password ({}): an edit made just before opv's may have been replaced; restore it \
             from the item's history.",
            env.name
        ));
    }
    Ok(Written {
        version: after.version,
        concurrent_edit,
    })
}

/// True for an edit whose outcome is unknown (it may or may not have landed).
fn is_unknown_outcome(e: &Error) -> bool {
    matches!(e.cause(), Some((Cause::WriteOutcomeUnknown { .. }, _)))
}

/// The value of `id`'s field in `layout` (resolved as `res`), `None` when it has none.
fn field_of<'a>(
    layout: &'a convention::Layout,
    res: &convention::Resolution,
    id: &(String, String),
) -> Option<&'a SecretValue> {
    res.chosen.get(id).map(|&i| &layout.fields[i].value)
}

/// Two values equal, compared in constant time (never printed).
fn same(a: &SecretValue, b: &SecretValue) -> bool {
    use subtle::ConstantTimeEq;
    a.expose().as_bytes().ct_eq(b.expose().as_bytes()).into()
}

/// Two fields the same: both without a value (absent or empty), or both holding the same.
fn same_field(a: Option<&SecretValue>, b: Option<&SecretValue>) -> bool {
    let a = a.filter(|v| !v.expose().is_empty());
    let b = b.filter(|v| !v.expose().is_empty());
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => same(a, b),
        _ => false,
    }
}

/// The plan's next step (design §10.1): `opv ready <env>` once written or when nothing is
/// to write, else the writing command, so the write does no more than was reviewed (05.04).
fn next_step(env_name: &str, opts: &Opts, writes: usize) -> Cmd {
    if !opts.dry_run || writes == 0 {
        return Cmd {
            command: vec!["ready".into()],
            args: vec![env_name.to_string()],
        };
    }
    apply_command(env_name, opts)
}

/// The writing command (05.04): this same review with the writing default, keeping every
/// `--replace`, `--rotate` and `--skip` it was made with.
fn apply_command(env_name: &str, opts: &Opts) -> Cmd {
    let from = match &opts.source {
        Source::Dotenv(p) => p.display().to_string(),
        Source::Target(name) => format!("target:{name}"),
    };
    let mut args = vec![env_name.to_string(), "--from".into(), from];
    for (flag, entries) in [
        ("--replace", &opts.replace),
        ("--rotate", &opts.rotate),
        ("--skip", &opts.skip),
    ] {
        for e in entries {
            args.extend([flag.to_string(), e.clone()]);
        }
    }
    if let Some(c) = &opts.confirm {
        args.extend(["--confirm".to_string(), c.clone()]);
    }
    Cmd {
        command: vec!["import".into()],
        args,
    }
}

/// Text: a count line, one line per row (names and the action word), the next step.
/// JSON: `{environment, applied, rows: [{found, product, key, action, rule}], counts, next}`.
fn print(out: &mut dyn Write, env_name: &str, opts: &Opts, plan: &AdoptPlan) -> Result<(), Error> {
    let label = |p: &Option<String>, k: &Option<String>| match (p, k) {
        (Some(p), Some(k)) => key_label(p, k),
        _ => "-".into(),
    };
    let count = |a: fn(&Action) -> bool| plan.rows.iter().filter(|r| a(&r.action)).count();
    let writes = plan.writes.len();
    let decide = count(|a| {
        matches!(
            a,
            Action::SkippedAlreadySet | Action::Conflict | Action::Ambiguous
        )
    });
    let next = crate::cause::render::cmd_text(&next_step(env_name, opts, writes));
    if opts.json {
        let rows: Vec<serde_json::Value> = plan
            .rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "found": r.found,
                    "product": r.product,
                    "key": r.key,
                    "action": r.action.word(),
                    "rule": match r.action { Action::FailsRule(rule) => Some(rule), _ => None },
                })
            })
            .collect();
        let v = serde_json::json!({
            "schema_version": crate::json::SCHEMA_VERSION,
            "environment": env_name,
            "applied": !opts.dry_run,
            "rows": rows,
            "writes": writes,
            "decisions_needed": decide,
            "next": next,
        });
        return writeln!(out, "{v}").map_err(write_err);
    }
    let verb = if opts.dry_run { "to write" } else { "written" };
    writeln!(
        out,
        "{env_name}: {} found · {writes} {verb} · {decide} need a decision",
        plan.rows.len()
    )
    .map_err(write_err)?;
    for r in &plan.rows {
        let what = match r.action {
            Action::Imported => format!("import ({verb})"),
            Action::Replaced => {
                format!("replace; the old value is kept in {KEPT_SECTION} ({verb})")
            }
            Action::SkippedAlreadySet => format!(
                "skipped: already set (--replace {} to take the found value)",
                label(&r.product, &r.key)
            ),
            Action::SkippedEmpty => "skipped: empty; nothing to write".to_string(),
            Action::HeldImmutable => "immutable: also needs --rotate to replace".to_string(),
            Action::FailsRule(rule) => format!("fails rule {rule}: not imported"),
            Action::Conflict => {
                "found copies differ: decide which is right in 1Password".to_string()
            }
            Action::Ambiguous => "matches several declared keys: not imported".to_string(),
            Action::NotDeclared => "not declared: ignored".to_string(),
            Action::NotApplicable => "not required in this environment: ignored".to_string(),
            Action::Skipped => "skipped (--skip): not imported".to_string(),
            Action::NotStored => {
                "infrastructure key: never stored in 1Password; the deploy job supplies it to opv sync"
                    .to_string()
            }
        };
        writeln!(
            out,
            "  {:<32} {what}  (from {})",
            label(&r.product, &r.key),
            r.found.join(", ")
        )
        .map_err(write_err)?;
    }
    writeln!(out, "Next: {next}").map_err(write_err)
}

#[cfg(test)]
#[path = "import_tests.rs"]
mod tests;
