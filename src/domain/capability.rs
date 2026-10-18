//! Capability per vault (design Part V, row `capability`): what the current 1Password
//! session can do with a vault the contract names — `write`, `read`, `none`, or `unknown`
//! with its source when 1Password does not expose effective permissions to this session.
//!
//! The capability is read from the session's own entry in `op vault user list <vault>
//! --format json`, matched by the session's `user_uuid`. A refusal is never guessed: it is
//! classified by the diagnosis's typed cause ([`from_refusal`]). No value, length, digest
//! or part of a value is ever held here.
//!
//! read-only member: no recording; owner-accepted assumption, 2026-10-18 (`allow_viewing`
//! without `allow_editing` is `read`, as 1Password documents).

use serde_json::Value;

use crate::cause::{Cause, ResourceKind};

/// Why a vault's capability is not known: 1Password did not report it, or the listing was
/// refused (which is not the same as "no access").
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownSource {
    /// The session user's entry in the reply has no `permissions` array.
    NoPermissionsInReply,
    /// Listing the vault's users was refused (it needs the Manage permission).
    UserListRefused,
    /// `op whoami` did not name the session's user, so no entry could be matched.
    NoSessionUser,
}

/// What this session can do with one vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// The session user may edit the vault.
    Write,
    /// The session user may view but not edit the vault.
    Read,
    /// The session user is not in the vault's user list (a non-member).
    None,
    /// 1Password did not expose the effective permissions to this session.
    Unknown {
        /// Why the capability is not known.
        source: UnknownSource,
    },
}

/// Classify one vault from the parsed `op vault user list <vault> --format json` reply
/// (`users`) and the session's `user_uuid` (`me`, from `op whoami --format json`).
///
/// The entry whose `id` equals `me` decides: `allow_editing` is [`Capability::Write`],
/// `allow_viewing` without it is [`Capability::Read`]. A list without that entry is
/// [`Capability::None`]; an entry without a `permissions` array is `unknown` (the reply
/// did not expose them). `users == None` (the listing was refused) is `unknown` too; a
/// caller with the refusal's diagnosis uses [`from_refusal`] to turn "not in this account"
/// or "not found" into [`Capability::None`].
pub fn classify(users: Option<&Value>, me: &str) -> Capability {
    let entries = match users {
        None => {
            return Capability::Unknown {
                source: UnknownSource::UserListRefused,
            };
        }
        Some(Value::Array(entries)) => entries,
        Some(_) => {
            return Capability::Unknown {
                source: UnknownSource::NoPermissionsInReply,
            };
        }
    };
    let Some(entry) = entries
        .iter()
        .find(|user| user.get("id").and_then(Value::as_str) == Some(me))
    else {
        return Capability::None;
    };
    let Some(permissions) = entry.get("permissions").and_then(Value::as_array) else {
        return Capability::Unknown {
            source: UnknownSource::NoPermissionsInReply,
        };
    };
    let allows = |wanted: &str| permissions.iter().any(|p| p.as_str() == Some(wanted));
    if allows("allow_editing") {
        Capability::Write
    } else if allows("allow_viewing") {
        Capability::Read
    } else {
        Capability::None
    }
}

/// The capability a refused listing implies, when the diagnosis names the vault as not in
/// this account ([`Cause::InOtherAccount`]) or not found ([`Cause::NotFound`] of a vault):
/// the session is a non-member, so [`Capability::None`]. `None` when the cause is not one
/// of those, so the caller keeps `unknown` rather than guessing.
pub fn from_refusal(cause: &Cause) -> Option<Capability> {
    match cause {
        Cause::InOtherAccount { .. } => Some(Capability::None),
        Cause::NotFound { resource, .. } if resource.kind == ResourceKind::Vault => {
            Some(Capability::None)
        }
        _ => None,
    }
}
