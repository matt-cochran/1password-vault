//! Diagnosis of `op item` and `op vault` failures that the session strategy alone cannot
//! classify (design §5, audit finding 04.01): a write refused on an item opv just read is a
//! missing Write grant, a refused `vault user list` on a readable vault is a missing Manage
//! grant, and the recorded item/vault-missing replies are delegated to the session strategy.
//!
//! Every phrase this strategy uses comes from `tests/fixtures/op/failures`; where opv has no
//! recording for a refusal (op 2.40.0 leaves no recorded wording), the refusal is classified
//! from the exit class and the [`Facts`] opv established, never from invented wording.

use crate::cause::{
    Cause, CreateKind, DiagnoseContext, ExitClass, GrantModel, Observed, Refind, ResourceKind,
    ResourceName, ResourceRef, Right, System,
};

use super::onepassword_diagnose::{Facts, diagnose_with};

/// Classify one failed `op item get/edit/create/list` or `op vault create/user list` call
/// (design §5). Session and account phrases are delegated to the session strategy.
pub fn diagnose_item_call(
    seen: Observed,
    stderr: &str,
    ctx: &DiagnoseContext,
    facts: &Facts,
) -> Cause {
    let words = seen.call().words.clone();

    // An unfinished create is diagnosed by what it was doing, never by its text. How it is
    // found again is the call site's own `Refind` (X5): a service account cannot be found by
    // title, so its create is never presented as safe to re-run.
    if let Some((kind, name, refind)) = unfinished_create(&seen, ctx) {
        return Cause::CreateOutcomeUnknown {
            system: System::OnePassword,
            kind,
            name: name.clone(),
            refind: refind.clone(),
            seen,
        };
    }

    // Session, account and credential failures — and the recorded item/vault-missing
    // phrases — belong to the session strategy. Call it rather than restating any phrase
    // here, so a phrase is recorded in exactly one place.
    let by_session = diagnose_with(seen.clone(), stderr, ctx, facts);
    if matches!(
        by_session,
        Cause::NotSignedIn { .. }
            | Cause::AccountNotOnMachine { .. }
            | Cause::CredentialRejected { .. }
            | Cause::CreateOutcomeUnknown { .. }
            | Cause::WriteOutcomeUnknown { .. }
            | Cause::Unavailable { .. }
    ) {
        return by_session;
    }

    // A write op refused on an item opv just read cannot be "not available": the read proved
    // the item exists and is readable, so the missing right is Write (audit finding 04.01).
    // op 2.40.0 leaves no recording of a write refusal, so this is classified from the exit
    // class plus the readable fact, never from invented op wording.
    if is_definite_failure(&seen)
        && (ctx.write || is_command(&words, &["item", "edit"]))
        && facts.item_readable
    {
        return missing_right(&seen, ctx, Right::Write, item_resource(&seen, ctx));
    }

    // A refused `vault user list` on a vault `op vault get` could read is a missing Manage
    // grant for the same reason; again there is no recording, so exit class plus the
    // readable fact.
    if is_definite_failure(&seen)
        && is_command(&words, &["vault", "user", "list"])
        && facts.vault_readable
    {
        return missing_right(&seen, ctx, Right::Manage, vault_resource(&seen, ctx));
    }

    // The remaining recorded item/vault replies (NotFound, InOtherAccount) come from the
    // session strategy; anything it did not recognize is `Unrecognized`.
    by_session
}

/// A failure op finished with a code (not a timeout, signal or spawn failure): the call
/// definitely did not happen.
fn is_definite_failure(seen: &Observed) -> bool {
    matches!(seen.exit(), ExitClass::Code { .. })
}

/// The kind, name and refind of a create whose outcome op did not deliver (timeout, signal
/// or lost reply).
fn unfinished_create<'a>(
    seen: &Observed,
    ctx: &'a DiagnoseContext,
) -> Option<(CreateKind, &'a String, &'a Refind)> {
    seen.exit().unanswered()?;
    ctx.create
        .as_ref()
        .map(|(kind, name, refind)| (*kind, name, refind))
}

/// The typed missing grant, addressed to the call's environment and target.
fn missing_right(
    seen: &Observed,
    ctx: &DiagnoseContext,
    right: Right,
    resource: ResourceRef,
) -> Cause {
    Cause::MissingRight {
        system: System::OnePassword,
        resource,
        right,
        grant: GrantModel::VaultPermission,
        env: ctx.env.clone(),
        target: ctx.target.clone(),
        seen: seen.clone(),
    }
}

/// The item of `op item edit`, from the call site's resource when it named one.
fn item_resource(seen: &Observed, ctx: &DiagnoseContext) -> ResourceRef {
    ctx.resource
        .clone()
        .filter(|r| r.kind == ResourceKind::Item)
        .unwrap_or_else(|| ResourceRef {
            kind: ResourceKind::Item,
            name: ResourceName::new(item_name(seen)),
            scope: flag_value(seen, "--vault"),
        })
}

/// The vault of `op vault user list`, from the call site's resource when it named one.
fn vault_resource(seen: &Observed, ctx: &DiagnoseContext) -> ResourceRef {
    ctx.resource
        .clone()
        .filter(|r| r.kind == ResourceKind::Vault)
        .unwrap_or_else(|| ResourceRef {
            kind: ResourceKind::Vault,
            name: ResourceName::new(vault_name(seen)),
            scope: ctx.account.as_ref().map(ToString::to_string),
        })
}

/// The first positional word after the `noun` command (skipping subcommand `verbs`).
fn positional_after(words: &[String], noun: &str, verbs: &[&str]) -> String {
    let start = words.iter().position(|w| w == noun).map_or(0, |i| i + 1);
    words[start..]
        .iter()
        .find(|w| !w.starts_with('-') && !verbs.contains(&w.as_str()))
        .cloned()
        .unwrap_or_default()
}

fn item_name(seen: &Observed) -> String {
    positional_after(
        &seen.call().words,
        "item",
        &["get", "edit", "create", "list"],
    )
}

fn vault_name(seen: &Observed) -> String {
    positional_after(
        &seen.call().words,
        "vault",
        &["get", "user", "list", "create"],
    )
}

/// The value of `flag` in the call's words, if it was given.
fn flag_value(seen: &Observed, flag: &str) -> Option<String> {
    seen.call().words.windows(2).find_map(|pair| match pair {
        [f, value] if f == flag => Some(value.clone()),
        _ => None,
    })
}

/// Whether the call's words begin with the command `path` (`["vault", "user", "list"]`).
fn is_command(words: &[String], path: &[&str]) -> bool {
    words.len() >= path.len() && words.iter().zip(path).all(|(w, p)| w == p)
}

#[cfg(test)]
#[path = "onepassword_diagnose_items_tests.rs"]
mod tests;
