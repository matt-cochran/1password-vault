//! Receipt age, item versions and revision (design row `receipts`, opv 0.12.0). Pure and
//! value-free: a version is an integer and a revision is a hex commit, never a value or a
//! digest of one (SR-1).
//!
//! [`staleness`] compares the item versions a saved receipt saw with the current ones;
//! [`age`] reports when it was generated, at which revision, and how long ago.

use std::collections::BTreeMap;

use crate::app::ready::Receipt;

/// What comparing a saved receipt's item versions with the current ones found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Staleness {
    /// Every current version matches the receipt's.
    Fresh,
    /// These item ids moved to a newer version since the receipt.
    Stale { items: Vec<String> },
    /// The receipt cannot be judged: it recorded no item versions. (A missing revision does
    /// not stop the comparison: [`Age::missing_revision`] reports it.)
    Unknown,
}

/// Judge `receipt` against `current_versions` (item id → the `op item list` version now):
/// `Stale` naming every item whose current version is newer than the one the receipt saw,
/// `Fresh` when none moved, `Unknown` when the receipt recorded no versions to compare. Names only, never a value (SR-1).
pub fn staleness(receipt: &Receipt, current_versions: &BTreeMap<String, u64>) -> Staleness {
    if receipt.item_versions.is_empty() && !current_versions.is_empty() {
        return Staleness::Unknown;
    }
    let mut items: Vec<String> = receipt
        .item_versions
        .iter()
        .filter(|(id, seen)| current_versions.get(*id).is_some_and(|now| now > *seen))
        .map(|(id, _)| id.clone())
        .collect();
    items.sort();
    if items.is_empty() {
        Staleness::Fresh
    } else {
        Staleness::Stale { items }
    }
}

/// When a receipt was generated, at which revision, and how old it is as of `now`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Age {
    /// The receipt's `generated_at` (RFC 3339 UTC).
    pub generated_at: String,
    /// The receipt's git revision; `None` when it carries none.
    pub revision: Option<String>,
    /// Whole seconds between `generated_at` and `now`; `None` when either is not an opv UTC
    /// stamp.
    pub seconds: Option<u64>,
}

impl Age {
    /// True when the receipt carries no revision: nothing pins it to a commit.
    pub fn missing_revision(&self) -> bool {
        self.revision.is_none()
    }
}

/// The age of `receipt` as of `now` (both RFC 3339 UTC), with its revision. `seconds` is
/// `None` when either stamp does not parse; a `now` before `generated_at` gives 0.
pub fn age(receipt: &Receipt, now: &str) -> Age {
    let seconds = match (epoch_seconds(&receipt.generated_at), epoch_seconds(now)) {
        (Some(generated), Some(now)) => Some(now.saturating_sub(generated)),
        _ => None,
    };
    Age {
        generated_at: receipt.generated_at.clone(),
        revision: receipt.revision.clone(),
        seconds,
    }
}

/// `stamp` (`YYYY-MM-DDTHH:MM:SSZ`) as seconds since the Unix epoch; `None` for anything
/// else.
fn epoch_seconds(stamp: &str) -> Option<u64> {
    let b = stamp.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return None;
    }
    let num = |at: usize| stamp.get(at..at + 2).and_then(|s| s.parse::<i64>().ok());
    let year = stamp.get(0..4).and_then(|s| s.parse::<i64>().ok())?;
    let (month, day) = (num(5)?, num(8)?);
    let (hour, minute, second) = (num(11)?, num(14)?, num(17)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let days = days_from_civil(year, month, day);
    u64::try_from(days * 86_400 + hour * 3_600 + minute * 60 + second).ok()
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
#[path = "receipt_age_tests.rs"]
mod tests;
