//! Self-healing 1Password conventions in every command's item read (FR-43).
//!
//! [`read`] replaces the strict item read. It reads the item once (FR-13), finds every
//! declared key wherever its field is (tolerant reads, TRIZ #3), and, when the layout
//! differs from the convention, segments by identity (TRIZ #1):
//!
//! - **A signed-in person** (`op whoami` says `USER`, no service-account or Connect token,
//!   not CI): the item is tidied. The pure plan ([`convention::plan`]) is applied to the item
//!   JSON in memory and written whole by one `op item edit` (values on stdin only, SR-3),
//!   then verified. Before writing, the item is read again past `op`'s local cache
//!   (`--cache=false`, C1) and the template is built from that read: if its version changed
//!   (someone edited it), opv re-plans once on the new version; if it changed again,
//!   nothing is written. After the edit the item must be exactly one version later (I5,
//!   else `tidy_conflict`, never retried) and hold every field opv wrote or kept (I4, else
//!   `tidy_unverified`). An item holding an attachment, a website list or a field type a
//!   whole-item edit is not proven to keep is never tidied. Everything displaced or
//!   replaced goes to `opv · kept` (TRIZ #24); nothing is deleted. One
//!   `tidied 1Password (<env>): ...` line on stderr per run.
//! - **A service account, Connect, or CI**: 1Password stays read-only. The command reads
//!   the item as it is and prints one note that the next run by a person tidies it.
//!
//! A tidy that fails (no write access, a lost edit, an item edited twice meanwhile) never
//! fails the command: it prints one note and the command goes on with the tolerant read.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::adapters::onepassword::{self, IdentityType, Item, Session};
use crate::adapters::onepassword_tidy::{self, Stamp};
use crate::config;
use crate::domain::SecretValue;
use crate::domain::convention::{self, Change, KeyId, Layout, TidyPlan};
use crate::domain::plan::ItemField;
use crate::domain::{Environment, Fleet, key_label, rules};
use crate::error::{Code, Error};
use crate::host::Host;
use crate::runner::CommandRunner;

#[cfg(test)]
thread_local! {
    static ACTIVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether tidying (and `run`'s item read) is on. Always in the binary. In this crate's
/// unit tests it is off unless a test holds [`activate`]'s guard, so command tests written
/// for an exact call sequence keep it; tolerant reads are on everywhere.
pub(crate) fn active() -> bool {
    #[cfg(test)]
    {
        ACTIVE.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        true
    }
}

/// Turns [`active`] on for this thread until the guard drops (tests).
#[cfg(test)]
pub(crate) struct Active;

#[cfg(test)]
pub(crate) fn activate() -> Active {
    ACTIVE.with(|a| a.set(true));
    Active
}

#[cfg(test)]
impl Drop for Active {
    fn drop(&mut self) {
        ACTIVE.with(|a| a.set(false));
    }
}

/// Who runs opv, as far as 1Password writes go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Identity {
    /// A person signed in to `op` (`user_type` `USER`): may tidy.
    Person,
    /// A service account, Connect, or CI: 1Password is read-only (FR-11, SR-5).
    ReadOnly,
    /// This run signed in to the target with the environment's deploy credentials
    /// (FR-40): 1Password is read-only for the run, even for a person (FR-43).
    DeployCredentials,
    /// `op whoami` could not tell: treated as read-only, silently.
    Unknown,
}

/// The identity from the environment and `op whoami` (the existing probe; only its
/// `user_type` is parsed). A token or CI decides without a call.
pub(crate) fn identity(r: &dyn CommandRunner) -> Identity {
    let host = Host::detect();
    // A service account, Connect, CI or a run under deploy credentials never tidies.
    if host.op_credential.is_some() || host.ci {
        return Identity::ReadOnly;
    }
    if r.deploy_signed_in() {
        return Identity::DeployCredentials;
    }
    match onepassword::diagnose(r, &Host::detect) {
        Ok(Session::SignedIn(IdentityType::User)) => Identity::Person,
        Ok(Session::SignedIn(_)) => Identity::ReadOnly,
        _ => Identity::Unknown,
    }
}

/// Refuse a write to the project manifest (FR-44: `init` creating one, `add`, `init
/// --add-env`, `config import`, `config edit`) unless a person signed in with their own
/// session runs opv: under a service account, Connect, CI or deploy credentials, or when
/// `op whoami` cannot tell, 1Password stays read-only (FR-11, SR-5; requirements FR-23's
/// `init` acceptance). Nothing is written; the error names `opv login`.
pub(crate) fn require_person(r: &dyn CommandRunner, what: &str) -> Result<(), Error> {
    let why = match identity(r) {
        Identity::Person => return Ok(()),
        Identity::ReadOnly => {
            "this run is a service account, Connect or CI, for which 1Password is read-only"
        }
        Identity::DeployCredentials => {
            "this run signed in with deploy credentials, for which 1Password is read-only"
        }
        Identity::Unknown => "op whoami could not confirm a person signed in to 1Password",
    };
    Err(Error::Policy(
        format!(
            "{what} writes the project's manifest in 1Password, which only a person signed in \
             with their own session may do; {why}; nothing written"
        )
        .into(),
    )
    .with_next(crate::adapters::onepassword_manifest::LOGIN))
}

/// True when the item JSON carries the manifest tag (FR-44).
pub(crate) fn is_manifest(raw: &[u8]) -> bool {
    #[derive(serde::Deserialize)]
    struct Tagged {
        #[serde(default)]
        tags: Vec<String>,
    }
    serde_json::from_slice::<Tagged>(raw).is_ok_and(|t| {
        t.tags
            .iter()
            .any(|t| t == crate::adapters::onepassword_manifest::MANIFEST_TAG)
    })
}

/// Today's UTC date, `YYYY-MM-DD`, for the labels of kept copies.
pub(crate) fn today() -> String {
    let days = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() / 86_400);
    civil(i64::try_from(days).unwrap_or(0))
}

/// Days since 1970-01-01 to a proleptic Gregorian date (H. Hinnant's algorithm).
fn civil(days: i64) -> String {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// The item as a command reads it.
pub(crate) struct Read {
    /// The declared keys' fields (tolerant), then the unclaimed fields, for the planner.
    pub fields: Vec<ItemField>,
    /// What this run tidied; empty when nothing was written.
    pub changes: Vec<Change>,
    /// `op://<vault>/<item>/<field id>` for keys whose field is not where the convention
    /// puts it (a read-only run): `run` references those by id.
    pub refs: BTreeMap<KeyId, String>,
    /// The keys whose stored value differs from the value opv uses (a trailing newline or
    /// space removed, a missing `ensure_prefix` added; [`convention::normalized`]), with
    /// that value. Empty once a person's tidy wrote it; a read-only run (service account,
    /// CI) keeps the item as it is, so `sync`, `status` and `check` use these values and see
    /// the same value either way. `run` still passes references (so `op run` masks the
    /// values) and warns once per key listed here.
    pub normalized: BTreeMap<KeyId, SecretValue>,
    /// The error code of a tidy that was attempted and did not complete (`tidy_conflict`
    /// when the item changed twice meanwhile); the command still went on (FR-43).
    pub tidy_error: Option<Code>,
    /// The item's `version` integer as last read (after a tidy, the tidied item's): an
    /// input of the plan id (FR-41).
    pub version: Option<u64>,
    /// Who ran opv, when the item needed a tidy (`None` when it did not, or tidying is
    /// off): `run` words its warning by it (a person whose tidy failed is not told to sign
    /// in as themselves).
    pub identity: Option<Identity>,
}

/// The environment's item, read tolerantly and tidied when a person runs opv (see the
/// module docs). Errors only when the item cannot be read at all.
pub(crate) fn read(fleet: &Fleet, env_name: &str, r: &dyn CommandRunner) -> Result<Read, Error> {
    let env = fleet.environment(env_name)?;
    let item = onepassword::read_whole(r, env)?;
    let (layout, stamp) = onepassword_tidy::parse(item.raw())?;
    let date = today();
    let plan = convention::plan(&layout, fleet, env_name, &date);
    let done = |layout: Layout,
                changes: Vec<Change>,
                error: Option<Code>,
                version: Option<u64>,
                who: Option<Identity>| {
        let mut res = finish(layout, fleet, env_name, env, changes, error);
        res.version = version;
        res.identity = who;
        res
    };
    let first = item.version;
    if active() {
        foreign_note(r, &layout, fleet, env_name);
    }
    if plan.is_empty() || !active() {
        return Ok(done(layout, Vec::new(), None, first, None));
    }
    // The project manifest (FR-44) holds the configuration itself: its fields (`notesPlain`,
    // `project`, `convention`) are never renamed, moved or concealed, so an environment
    // that points at it is read as it is.
    if is_manifest(item.raw()) {
        r.note(&format!(
            "1Password ({env_name}) is the project's manifest item; opv never tidies it. Keep \
             the environment's values in an item of their own."
        ));
        return Ok(done(layout, Vec::new(), None, first, None));
    }
    // I4: an item holding something a whole-item edit is not proven to keep (an attachment,
    // a one-time password, an SSH key, any field type opv does not fully understand) is
    // never rewritten.
    if let Some(what) = onepassword_tidy::unprovable(item.raw()) {
        r.note(&unprovable_note(env_name, what));
        return Ok(done(layout, Vec::new(), None, first, None));
    }
    let who = identity(r);
    match who {
        Identity::Person => {}
        Identity::ReadOnly => {
            r.note(&format!(
                "1Password ({env_name}) is not laid out the way opv expects; read it as it is \
                 (read-only here). The next opv run by a signed-in person tidies it."
            ));
            return Ok(done(layout, Vec::new(), None, first, Some(who)));
        }
        Identity::DeployCredentials => {
            r.note(&format!(
                "1Password ({env_name}) is not laid out the way opv expects; read it as it is \
                 (this run signed in with the environment's deploy credentials, so 1Password \
                 stays read-only). opv check {env_name} tidies it."
            ));
            return Ok(done(layout, Vec::new(), None, first, Some(who)));
        }
        Identity::Unknown => return Ok(done(layout, Vec::new(), None, first, Some(who))),
    }
    match tidy(r, fleet, env_name, env, &date, stamp, plan) {
        Ok(Some(t)) => {
            if !t.changes.is_empty() {
                r.note(&format!(
                    "tidied 1Password ({env_name}): {}",
                    convention::summary(&t.changes)
                ));
                missing_values(r, &t.layout, fleet, env_name, env);
            }
            Ok(done(t.layout, t.changes, t.error, t.version, Some(who)))
        }
        Ok(None) => Ok(done(layout, Vec::new(), None, first, Some(who))),
        Err(e) => {
            let text = e.to_string();
            r.note(&format!(
                "could not tidy 1Password ({env_name}); read it as it is: {}",
                text.lines().next().unwrap_or("")
            ));
            let code = e.code();
            Ok(done(layout, Vec::new(), Some(code), first, Some(who)))
        }
    }
}

/// The one note for an item a tidy never rewrites (I4).
fn unprovable_note(env_name: &str, what: &str) -> String {
    format!(
        "1Password ({env_name}) holds {what}, which opv cannot prove a rewrite keeps; opv \
         never tidies such an item and reads it as it is. Keep opv's keys in an item of their \
         own to let opv tidy them."
    )
}

/// One note naming the keys whose only matching field sits where the other profile's
/// convention keeps it (M1): opv leaves it there for that configuration.
fn foreign_note(r: &dyn CommandRunner, layout: &Layout, fleet: &Fleet, env_name: &str) {
    let res = convention::resolve(layout, fleet);
    if res.foreign.is_empty() {
        return;
    }
    let names: Vec<String> = res.foreign.iter().map(|(p, k)| key_label(p, k)).collect();
    let (place, other, read) = if fleet.is_simple() {
        (
            "in a product section",
            "a fleet-profile",
            "does not read it",
        )
    } else {
        ("at the top level", "a simple-profile", "reads it there")
    };
    r.note(&format!(
        "1Password ({env_name}): a field for {} is {place}, where {other} configuration \
         keeps it; opv {read} and never moves it. If it belongs to this configuration, move \
         it in 1Password.",
        names.join(", ")
    ));
}

/// The item after a tidy attempt.
struct Tidied {
    /// Its layout as last read.
    layout: Layout,
    /// What was written (empty when nothing was).
    changes: Vec<Change>,
    /// `tidy_conflict` (changed twice before the write, or another edit landed with it) or
    /// `tidy_unverified` (the item read back lacks a field opv wrote or kept).
    error: Option<Code>,
    /// The item's version as last read.
    version: Option<u64>,
}

/// Check, write, verify (module docs). Every read here bypasses `op`'s cache (C1), and
/// the template is always built from the latest such read. `None`: keep the first read.
fn tidy(
    r: &dyn CommandRunner,
    fleet: &Fleet,
    env_name: &str,
    env: &Environment,
    date: &str,
    mut stamp: Stamp,
    mut plan: TidyPlan,
) -> Result<Option<Tidied>, Error> {
    let tidied = |layout, changes, error, version| {
        Ok(Some(Tidied {
            layout,
            changes,
            error,
            version,
        }))
    };
    for attempt in 0..2 {
        let fresh = onepassword::read_whole_fresh(r, env)?;
        let (seen, seen_stamp) = onepassword_tidy::parse(fresh.raw())?;
        if seen_stamp != stamp {
            if attempt == 1 {
                r.note(&format!(
                    "1Password ({env_name}) changed twice while opv was tidying it; nothing \
                     written. Re-run when nobody is editing the item."
                ));
                return tidied(seen, Vec::new(), Some(Code::TidyConflict), fresh.version);
            }
            stamp = seen_stamp;
            plan = convention::plan(&seen, fleet, env_name, date);
            if plan.is_empty() {
                return tidied(seen, Vec::new(), None, fresh.version);
            }
            continue;
        }
        if let Some(what) = onepassword_tidy::unprovable(fresh.raw()) {
            r.note(&unprovable_note(env_name, what));
            return tidied(seen, Vec::new(), None, fresh.version);
        }
        let template = onepassword_tidy::apply(fresh.raw(), &plan)?;
        let echoed = onepassword_tidy::write(r, env, &template)?;
        // I5: the edit echoes the item it wrote; without a version in it, read it back
        // (fresh). Exactly one version later than the read it was built from means no
        // other edit landed in between.
        let after = match onepassword::item_version(&echoed) {
            Some(_) => Item::from_raw(echoed),
            None => onepassword::read_whole_fresh(r, env)?,
        };
        let (layout, _) = onepassword_tidy::parse(after.raw())?;
        let expected = fresh.version.map(|v| v + 1);
        if expected.is_some() && after.version != expected {
            r.note(&format!(
                "1Password ({env_name}): another edit landed while opv was tidying it (version \
                 {} instead of {}); opv did not retry. Check the item's history in 1Password.",
                after
                    .version
                    .map_or_else(|| "unknown".into(), |v| v.to_string()),
                expected.unwrap_or_default()
            ));
            return tidied(
                layout,
                plan.changes,
                Some(Code::TidyConflict),
                after.version,
            );
        }
        // I4: every field opv wrote or kept (so every original label and value, in place or
        // in `opv · kept`) is in the item read back.
        let lost = onepassword_tidy::lost(fresh.raw(), &template, after.raw())?;
        drop(template);
        if lost > 0 {
            r.note(&format!(
                "1Password ({env_name}) was tidied, but {lost} field(s) opv wrote or kept are \
                 not in the item read back; restore them from the item's history in 1Password."
            ));
            return tidied(
                layout,
                plan.changes,
                Some(Code::TidyUnverified),
                after.version,
            );
        }
        if !convention::plan(&layout, fleet, env_name, date).is_empty() {
            r.note(&format!(
                "1Password ({env_name}) was written but is not fully tidy yet; the next run \
                 finishes it"
            ));
        }
        return tidied(layout, plan.changes, None, after.version);
    }
    Ok(None)
}

/// One line naming the keys that still need a value: a human action (FR-43).
fn missing_values(
    r: &dyn CommandRunner,
    layout: &Layout,
    fleet: &Fleet,
    env_name: &str,
    env: &Environment,
) {
    let res = convention::resolve(layout, fleet);
    let empty: Vec<String> = fleet
        .products
        .iter()
        .flat_map(|(p, prod)| prod.keys.iter().map(move |(k, s)| (p, k, s)))
        // A shared key (FR-45) has no field: its source is named instead.
        .filter(|(_, _, s)| s.from.is_none())
        .filter(|(p, _, s)| rules::applies(s, env_name, env, p))
        .filter(|(p, k, _)| {
            res.chosen
                .get(&((*p).clone(), (*k).clone()))
                .is_none_or(|&i| layout.fields[i].value.expose().is_empty())
        })
        .map(|(p, k, _)| key_label(p, k))
        .collect();
    if !empty.is_empty() {
        // H1: the item link (IDs only) to type the values in.
        let link = onepassword::item_link(
            onepassword::account(r).as_ref(),
            &env.vault_id,
            &env.item_id,
        );
        r.note(&format!(
            "still needs a value in 1Password ({env_name}): {} · open: {link}",
            empty.join(", ")
        ));
    }
}

fn finish(
    layout: Layout,
    fleet: &Fleet,
    env_name: &str,
    env: &Environment,
    changes: Vec<Change>,
    tidy_error: Option<Code>,
) -> Read {
    let res = convention::resolve(&layout, fleet);
    let mut refs = BTreeMap::new();
    let mut normalized = BTreeMap::new();
    for (id, &i) in &res.chosen {
        let f = &layout.fields[i];
        let spec = &fleet.products[&id.0].keys[&id.1];
        if let Some((v, _)) = convention::normalized(fleet, env_name, &id.0, &id.1, spec, &f.value)
        {
            normalized.insert(id.clone(), v);
        }
        let section = (!fleet.is_simple()).then_some(id.0.as_str());
        let same_place = |g: &convention::Found| g.section_label() == section && g.label == id.1;
        let conventional = same_place(f)
            && !res.duplicates.contains_key(id)
            && layout.fields.iter().filter(|g| same_place(g)).count() == 1;
        if !conventional && config::is_id(&f.id) {
            refs.insert(
                id.clone(),
                format!("op://{}/{}/{}", env.vault_id, env.item_id, f.id),
            );
        }
    }
    Read {
        fields: convention::read_fields(&layout, fleet, env_name),
        changes,
        refs,
        normalized,
        tidy_error,
        version: None,
        identity: None,
    }
}

#[cfg(test)]
#[path = "tidy_tests.rs"]
mod tests;
