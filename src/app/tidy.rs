//! Self-healing 1Password conventions in every command's item read (FR-43).
//!
//! [`read`] replaces the strict item read. It reads the item once (FR-13), finds every
//! declared key wherever its field is (tolerant reads, TRIZ #3), and, when the layout
//! differs from the convention, segments by identity (TRIZ #1):
//!
//! - **A signed-in person** (`op whoami` says `USER`, no service-account or Connect token,
//!   not CI): the item is tidied. The pure plan ([`convention::plan`]) is applied to the item
//!   JSON in memory and written whole by one `op item edit` (values on stdin only, SR-3),
//!   then re-read and verified. Before writing, the item is read again: if its version
//!   changed (someone edited it), opv re-plans once on the new version; if it changed again,
//!   nothing is written. Everything displaced or replaced goes to `opv · kept` (TRIZ #24);
//!   nothing is deleted. One `tidied 1Password (<env>): ...` line on stderr per run.
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

/// True the first time this run asks for `env_name`: the read-only note is printed at
/// most once per environment, however many times a command reads the item. Per thread in
/// this crate's unit tests, so tests stay independent.
fn first_note(env_name: &str) -> bool {
    use std::collections::BTreeSet;
    #[cfg(test)]
    {
        thread_local! {
            static SEEN: std::cell::RefCell<BTreeSet<String>> =
                const { std::cell::RefCell::new(BTreeSet::new()) };
        }
        SEEN.with(|s| s.borrow_mut().insert(env_name.to_string()))
    }
    #[cfg(not(test))]
    {
        static SEEN: std::sync::Mutex<BTreeSet<String>> = std::sync::Mutex::new(BTreeSet::new());
        SEEN.lock()
            .map_or(true, |mut s| s.insert(env_name.to_string()))
    }
}

/// Who runs opv, as far as 1Password writes go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Identity {
    /// A person signed in to `op` (`user_type` `USER`): may tidy.
    Person,
    /// A service account, Connect, or CI: 1Password is read-only (FR-11, SR-5).
    ReadOnly,
    /// `op whoami` could not tell: treated as read-only, silently.
    Unknown,
}

/// The identity from the environment and `op whoami` (the existing probe; only its
/// `user_type` is parsed). A token or CI decides without a call.
pub(crate) fn identity(r: &dyn CommandRunner) -> Identity {
    let host = Host::detect();
    // A service account, Connect, CI or a run under deploy credentials never tidies.
    if host.op_credential.is_some() || host.ci || r.deploy_signed_in() {
        return Identity::ReadOnly;
    }
    match onepassword::diagnose(r, &Host::detect) {
        Ok(Session::SignedIn(IdentityType::User)) => Identity::Person,
        Ok(Session::SignedIn(_)) => Identity::ReadOnly,
        _ => Identity::Unknown,
    }
}

/// True when the item JSON carries the manifest tag (FR-44).
fn is_manifest(raw: &[u8]) -> bool {
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
}

/// The environment's item, read tolerantly and tidied when a person runs opv (see the
/// module docs). Errors only when the item cannot be read at all.
pub(crate) fn read(fleet: &Fleet, env_name: &str, r: &dyn CommandRunner) -> Result<Read, Error> {
    let env = fleet.environment(env_name)?;
    let item = onepassword::read_whole(r, env)?;
    let (layout, stamp) = onepassword_tidy::parse(item.raw())?;
    let date = today();
    let plan = convention::plan(&layout, fleet, env_name, &date);
    let done = |layout: Layout, changes: Vec<Change>, error: Option<Code>, version: Option<u64>| {
        let mut res = finish(layout, fleet, env_name, env, changes, error);
        res.version = version;
        res
    };
    let first = item.version;
    if plan.is_empty() || !active() {
        return Ok(done(layout, Vec::new(), None, first));
    }
    // The project manifest (FR-44) holds the configuration itself: its fields (`notesPlain`,
    // `project`, `convention`) are never renamed, moved or concealed, so an environment
    // that points at it is read as it is.
    if is_manifest(item.raw()) {
        r.note(&format!(
            "1Password ({env_name}) is the project's manifest item; opv never tidies it. Keep \
             the environment's values in an item of their own."
        ));
        return Ok(done(layout, Vec::new(), None, first));
    }
    match identity(r) {
        Identity::Person => {}
        Identity::ReadOnly => {
            // Only a fix a person's run would make to existing fields is worth a note; once
            // per environment per run.
            if plan.fixes_layout() && first_note(env_name) {
                r.note(&format!(
                    "1Password ({env_name}) is not laid out the way opv expects; read it as \
                     it is (read-only here). The next opv run by a signed-in person tidies it."
                ));
            }
            return Ok(done(layout, Vec::new(), None, first));
        }
        Identity::Unknown => return Ok(done(layout, Vec::new(), None, first)),
    }
    match tidy(r, fleet, env_name, env, &date, &item, stamp, plan) {
        Ok(Some((after, changes, conflict, version))) => {
            if !changes.is_empty() {
                r.note(&format!(
                    "tidied 1Password ({env_name}): {}",
                    convention::summary(&changes)
                ));
                missing_values(r, &after, fleet, env_name, env);
            }
            Ok(done(after, changes, conflict, version))
        }
        Ok(None) => Ok(done(layout, Vec::new(), None, first)),
        Err(e) => {
            let text = e.to_string();
            r.note(&format!(
                "could not tidy 1Password ({env_name}); read it as it is: {}",
                text.lines().next().unwrap_or("")
            ));
            let code = e.code();
            Ok(done(layout, Vec::new(), Some(code), first))
        }
    }
}

/// The item after a tidy attempt: its layout, what was written, `tidy_conflict` when
/// nothing could be, and the version of the item as last read.
type Tidied = (Layout, Vec<Change>, Option<Code>, Option<u64>);

/// Check, write, verify (module docs). `Some((layout, changes, conflict))`: the item as it
/// now is, what was written (empty when nothing was) and `tidy_conflict` when the item
/// changed twice meanwhile. `None`: keep the first read.
#[allow(clippy::too_many_arguments)]
fn tidy(
    r: &dyn CommandRunner,
    fleet: &Fleet,
    env_name: &str,
    env: &Environment,
    date: &str,
    first: &Item,
    mut stamp: Stamp,
    mut plan: TidyPlan,
) -> Result<Option<Tidied>, Error> {
    let mut newer: Option<Item> = None;
    for attempt in 0..2 {
        let check = onepassword::read_whole(r, env)?;
        let (seen, seen_stamp) = onepassword_tidy::parse(check.raw())?;
        if seen_stamp != stamp {
            if attempt == 1 {
                r.note(&format!(
                    "1Password ({env_name}) changed twice while opv was tidying it; nothing \
                     written. Re-run when nobody is editing the item."
                ));
                return Ok(Some((
                    seen,
                    Vec::new(),
                    Some(Code::TidyConflict),
                    check.version,
                )));
            }
            stamp = seen_stamp;
            plan = convention::plan(&seen, fleet, env_name, date);
            if plan.is_empty() {
                return Ok(Some((seen, Vec::new(), None, check.version)));
            }
            newer = Some(check);
            continue;
        }
        let raw = newer.as_ref().map_or(first.raw(), Item::raw);
        let template = onepassword_tidy::apply(raw, &plan)?;
        onepassword_tidy::write(r, env, &template)?;
        drop(template);
        let after = onepassword::read_whole(r, env)?;
        let (layout, _) = onepassword_tidy::parse(after.raw())?;
        if !convention::plan(&layout, fleet, env_name, date).is_empty() {
            r.note(&format!(
                "1Password ({env_name}) was written but is not fully tidy yet; the next run \
                 finishes it"
            ));
        }
        return Ok(Some((layout, plan.changes, None, after.version)));
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
    }
}

#[cfg(test)]
#[path = "tidy_tests.rs"]
mod tests;
