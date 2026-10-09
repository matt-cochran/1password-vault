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
use crate::domain::convention::{self, Change, KeyId, Layout, TidyPlan};
use crate::domain::plan::ItemField;
use crate::domain::{Environment, Fleet, key_label, rules};
use crate::error::Error;
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
    /// `op whoami` could not tell: treated as read-only, silently.
    Unknown,
}

/// The identity from the environment and `op whoami` (the existing probe; only its
/// `user_type` is parsed). A token or CI decides without a call.
pub(crate) fn identity(r: &dyn CommandRunner) -> Identity {
    let host = Host::detect();
    if host.op_credential.is_some() || host.ci {
        return Identity::ReadOnly;
    }
    match onepassword::diagnose(r, &Host::detect) {
        Ok(Session::SignedIn(IdentityType::User)) => Identity::Person,
        Ok(Session::SignedIn(_)) => Identity::ReadOnly,
        _ => Identity::Unknown,
    }
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
}

/// The environment's item, read tolerantly and tidied when a person runs opv (see the
/// module docs). Errors only when the item cannot be read at all.
pub(crate) fn read(fleet: &Fleet, env_name: &str, r: &dyn CommandRunner) -> Result<Read, Error> {
    let env = fleet.environment(env_name)?;
    let item = onepassword::read_whole(r, env)?;
    let (layout, stamp) = onepassword_tidy::parse(item.raw())?;
    let date = today();
    let plan = convention::plan(&layout, fleet, env_name, &date);
    if plan.is_empty() || !active() {
        return Ok(finish(layout, fleet, env_name, env, Vec::new()));
    }
    match identity(r) {
        Identity::Person => {}
        Identity::ReadOnly => {
            r.note(&format!(
                "1Password ({env_name}) is not laid out the way opv expects; read it as it is \
                 (read-only here). The next opv run by a signed-in person tidies it."
            ));
            return Ok(finish(layout, fleet, env_name, env, Vec::new()));
        }
        Identity::Unknown => return Ok(finish(layout, fleet, env_name, env, Vec::new())),
    }
    match tidy(r, fleet, env_name, env, &date, &item, stamp, plan) {
        Ok(Some((after, changes))) => {
            if !changes.is_empty() {
                r.note(&format!(
                    "tidied 1Password ({env_name}): {}",
                    convention::summary(&changes)
                ));
                missing_values(r, &after, fleet, env_name, env);
            }
            Ok(finish(after, fleet, env_name, env, changes))
        }
        Ok(None) => Ok(finish(layout, fleet, env_name, env, Vec::new())),
        Err(e) => {
            let text = e.to_string();
            r.note(&format!(
                "could not tidy 1Password ({env_name}); read it as it is: {}",
                text.lines().next().unwrap_or("")
            ));
            Ok(finish(layout, fleet, env_name, env, Vec::new()))
        }
    }
}

/// Check, write, verify (module docs). `Some((layout, changes))`: the item as it now is and
/// what was written (empty when nothing was). `None`: keep the first read.
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
) -> Result<Option<(Layout, Vec<Change>)>, Error> {
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
                return Ok(Some((seen, Vec::new())));
            }
            stamp = seen_stamp;
            plan = convention::plan(&seen, fleet, env_name, date);
            if plan.is_empty() {
                return Ok(Some((seen, Vec::new())));
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
        return Ok(Some((layout, plan.changes)));
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
        .filter(|(p, _, s)| rules::applies(s, env_name, env, p))
        .filter(|(p, k, _)| {
            res.chosen
                .get(&((*p).clone(), (*k).clone()))
                .is_none_or(|&i| layout.fields[i].value.expose().is_empty())
        })
        .map(|(p, k, _)| key_label(p, k))
        .collect();
    if !empty.is_empty() {
        r.note(&format!(
            "still needs a value in 1Password ({env_name}): {}",
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
) -> Read {
    let res = convention::resolve(&layout, fleet);
    let mut refs = BTreeMap::new();
    for (id, &i) in &res.chosen {
        let f = &layout.fields[i];
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
    }
}

#[cfg(test)]
#[path = "tidy_tests.rs"]
mod tests;
