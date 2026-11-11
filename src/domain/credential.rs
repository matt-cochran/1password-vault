//! The value-free credential lifecycle contract (#296, #297): what a CI credential or a
//! deploy identity is, when it expires, and where its expiry is recorded in
//! `secrets.bindings.toml`, beside the contract.
//!
//! Every field is a name or a date. No field can hold a token or secret value (SR-3), and
//! nothing here runs a command or knows a provider: the same types serve CI reader tokens,
//! minted deploy credentials and federated deploy identities.

use crate::config::bindings::Bindings;

/// The kind of credential a [`CredentialRecord`] describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    /// A 1Password service account a CI job signs in with: the environment's read-only CI
    /// reader (`target: None`) or a target's deploy identity (`target: Some`).
    ServiceAccount,
    /// A deploy credential minted at the provider for a target (a token or app secret).
    Deploy,
    /// A federated deploy identity: non-secret ids a CI sign-in presents. It holds no
    /// secret, so it has no expiry of its own.
    Federated,
}

/// One credential, as recorded beside the contract: who it is, what it is for, and when it
/// expires. `identity` is a service-account name or a client id, never a token; `expires_on`
/// is a `YYYY-MM-DD` date, never a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRecord {
    /// The environment the credential belongs to.
    pub env: String,
    /// The target it deploys to, or `None` for the environment's CI reader.
    pub target: Option<String>,
    /// What kind of credential this is.
    pub kind: CredentialKind,
    /// The service-account name or client id. Never a token.
    pub identity: String,
    /// The expiry date as `YYYY-MM-DD`, or `None` when none is recorded.
    pub expires_on: Option<String>,
}

/// A federated deploy identity's non-secret ids (#297): what a CI sign-in must present for
/// opv to accept the ambient identity. All fields are non-secret identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederatedIdentity {
    pub tenant_id: String,
    pub client_id: String,
    pub subscription_id: String,
}

/// The default number of days before expiry at which a credential is reported as expiring.
pub const DEFAULT_EXPIRY_WINDOW_DAYS: i64 = 14;

/// How close an expiry date is, relative to `today` and a window of `window_days`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryState {
    /// More than `window_days` ahead.
    Ok { days_left: i64 },
    /// Within `window_days` of expiry (but not yet expired).
    Expiring { days_left: i64 },
    /// Today or in the past.
    Expired,
    /// No date, or a date that cannot be read.
    Unknown,
}

/// The state of `expires_on` (`YYYY-MM-DD`, or a timestamp whose first ten bytes are that)
/// relative to `today`, whose first ten bytes must also be a date. `None` or a date that
/// cannot be read is [`ExpiryState::Unknown`]; a non-positive `days_left` is
/// [`ExpiryState::Expired`]; within `window_days` is [`ExpiryState::Expiring`]; otherwise
/// [`ExpiryState::Ok`]. Pure civil-date arithmetic.
pub fn expiry_state(expires_on: Option<&str>, today: &str, window_days: i64) -> ExpiryState {
    let (Some(expires), Some(today)) = (expires_on.and_then(date_days), date_days(today)) else {
        return ExpiryState::Unknown;
    };
    let days_left = expires - today;
    if days_left <= 0 {
        ExpiryState::Expired
    } else if days_left <= window_days {
        ExpiryState::Expiring { days_left }
    } else {
        ExpiryState::Ok { days_left }
    }
}

/// The dotted bindings key holding `env`'s CI reader expiry date.
pub fn ci_reader_expires_path(env: &str) -> String {
    format!("environments.{env}.ci_reader.expires_on")
}

/// The dotted bindings key of the CI reader's grant receipt in `env` (#304, FR-70).
pub fn ci_reader_receipt_path(env: &str) -> String {
    format!("environments.{env}.ci_reader.receipt")
}

/// The dotted bindings key of the grant receipt of `target`'s CI identity in `env` (#304,
/// FR-70).
pub fn ci_identity_receipt_path(env: &str, target: &str) -> String {
    format!("environments.{env}.targets.{target}.ci_identity.receipt")
}

/// The dotted bindings key holding the deploy credential expiry date of `target` in `env`.
pub fn deploy_expires_path(env: &str, target: &str) -> String {
    format!("environments.{env}.targets.{target}.deploy_credentials_expires_on")
}

/// The dotted bindings key holding the expiry date of the 1Password service account that
/// `target`'s CI deploy job in `env` signs in with.
pub fn ci_identity_expires_path(env: &str, target: &str) -> String {
    format!("environments.{env}.targets.{target}.ci_identity.expires_on")
}

/// Every credential record recorded in `bindings` for `env` and its `targets`: the CI
/// reader, then each target's deploy credential and CI service account, in target order.
/// Only expiry dates are recorded here; `identity` names the credential's holder in a
/// value-free way (the environment for the reader, the target otherwise).
pub fn records(bindings: &Bindings, env: &str, targets: &[String]) -> Vec<CredentialRecord> {
    let mut out = Vec::new();
    if let Some(expires) = bindings.get(&ci_reader_expires_path(env)) {
        out.push(CredentialRecord {
            env: env.to_string(),
            target: None,
            kind: CredentialKind::ServiceAccount,
            identity: env.to_string(),
            expires_on: Some(expires.to_string()),
        });
    }
    for target in targets {
        if let Some(expires) = bindings.get(&deploy_expires_path(env, target)) {
            out.push(CredentialRecord {
                env: env.to_string(),
                target: Some(target.clone()),
                kind: CredentialKind::Deploy,
                identity: target.clone(),
                expires_on: Some(expires.to_string()),
            });
        }
        if let Some(expires) = bindings.get(&ci_identity_expires_path(env, target)) {
            out.push(CredentialRecord {
                env: env.to_string(),
                target: Some(target.clone()),
                kind: CredentialKind::ServiceAccount,
                identity: target.clone(),
                expires_on: Some(expires.to_string()),
            });
        }
    }
    out
}

/// The `(year, month, day)` at the front of `text`, validated as a real calendar date.
fn date_parts(text: &str) -> Option<(i64, i64, i64)> {
    let b = text.as_bytes();
    if b.len() < 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let number = |digits: &[u8]| -> Option<i64> {
        digits.iter().all(u8::is_ascii_digit).then(|| {
            digits
                .iter()
                .fold(0i64, |n, d| n * 10 + i64::from(d - b'0'))
        })
    };
    let (year, month, day) = (
        number(b.get(0..4)?)?,
        number(b.get(5..7)?)?,
        number(b.get(8..10)?)?,
    );
    let last = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => return None,
    };
    (year != 0 && (1..=last).contains(&day)).then_some((year, month, day))
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`).
fn date_days(text: &str) -> Option<i64> {
    let (year, month, day) = date_parts(text)?;
    Some(days_from_civil(year, month, day))
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date `days` after `date` (`YYYY-MM-DD`, or a timestamp whose first ten bytes are
/// that); `None` when `date` is not a real calendar date. The expiry recorded for a minted
/// credential (#296).
pub fn add_days(date: &str, days: i64) -> Option<String> {
    Some(civil_from_days(date_days(date)?.checked_add(days)?))
}

/// The proleptic Gregorian `YYYY-MM-DD` for days since 1970-01-01 (Howard Hinnant's
/// `civil_from_days`).
fn civil_from_days(days: i64) -> String {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    format!("{:04}-{:02}-{:02}", if m <= 2 { y + 1 } else { y }, m, d)
}

/// A Gregorian leap year.
fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}
