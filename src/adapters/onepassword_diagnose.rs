//! 1Password (`op`) diagnosis of session and account failures: the one place that classifies
//! a failed `op` call as a sign-in, account, credential or vault-placement cause (design
//! `docs/design/error-catalog.md` §4.3, §5).
//!
//! A cause is built from the raw stderr (matched against the phrases recorded in
//! `tests/fixtures/op/failures`, before any scrubbing), the exit class and principal the
//! runner observed, the call site's [`DiagnoseContext`], and the [`Facts`] opv established
//! about the environment and the sessions on the machine. Nothing reads stdout of the failed
//! call, and no value ever reaches a cause.
//!
//! [`session_for`] is the probe that tells "signed out" from "signed in, but to another
//! account on the same sign-in address" (#160), for `opv login --account <id>`.

use serde::Deserialize;

use super::onepassword_manifest as manifest;
use crate::cause::{
    AccountId, AccountRef, AccountSource, Cause, CredentialProblem, CredentialRef, DiagnoseContext,
    ExitClass, ItemId, NamedBy, NotFoundState, Observed, Principal, ResourceKind, ResourceName,
    ResourceRef, SessionState, System, Unanswered, VarName, VaultId,
};
use crate::runner::{Call, CommandRunner, PROBE_TIMEOUT};

/// The variable that acts as `--account` on every `op` command (design §5).
pub const OP_ACCOUNT: &str = "OP_ACCOUNT";
/// The service-account token variable; its presence makes the runner's principal a shell
/// token.
pub const OP_SERVICE_ACCOUNT_TOKEN: &str = "OP_SERVICE_ACCOUNT_TOKEN";

/// What opv established about the call's surroundings, beyond the call site's context.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    /// Variables set in the call's environment that silently override what the person typed
    /// (`OP_ACCOUNT`), by name only.
    pub env_overrides: Vec<VarName>,
    /// A live session for this account, when [`session_for`] found one for another account
    /// than the one asked for (#160).
    pub live: Option<AccountId>,
    /// `op item get` on the call's item succeeded, so a later write refusal is the missing
    /// Write grant rather than "not available" (audit finding 04.01).
    pub item_readable: bool,
    /// `op vault get` on the call's vault succeeded, so a `vault user list` refusal is the
    /// missing Manage grant.
    pub vault_readable: bool,
    /// The account the checkout's `.opv` selects, with that file's path.
    pub pointer: Option<(String, std::path::PathBuf)>,
    /// The 1Password app holds the accounts op sees (macOS, Windows, op.exe from WSL): an
    /// account is added there, never with `opv login --add` (audit 04.07).
    pub in_app: bool,
}

/// The outcome of looking for a vault in the machine's other accounts ([`search_vault`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultSearch {
    /// No search could be made: op did not list the machine's accounts.
    NotSearched,
    /// The vault belongs to this account.
    FoundIn(AccountId),
    /// No account that could be asked holds it; `unasked` could not be asked.
    Nowhere { unasked: Vec<AccountId> },
}

/// Look for `vault` in the machine's accounts other than `selected` (#153a): `op account
/// list`, then per account the read-only probe `opv vault locate` makes
/// ([`manifest::holds_vault`]), which never prompts or signs in. The first account that
/// holds it is the owner.
pub fn search_vault(r: &dyn CommandRunner, vault: &VaultId, selected: &AccountId) -> VaultSearch {
    let manifest::Discovery::Listed(accounts) = manifest::discover(r) else {
        return VaultSearch::NotSearched;
    };
    let mut unasked = Vec::new();
    for a in accounts
        .iter()
        .filter(|a| !a.account_uuid.eq_ignore_ascii_case(selected.as_str()))
    {
        match manifest::holds_vault(r, &a.account_uuid, vault.as_str()) {
            manifest::Holds::Found => return VaultSearch::FoundIn(AccountId::new(&a.account_uuid)),
            manifest::Holds::NotFound => {}
            manifest::Holds::Unknown | manifest::Holds::Unanswered => {
                unasked.push(AccountId::new(&a.account_uuid))
            }
        }
    }
    VaultSearch::Nowhere { unasked }
}

/// A diagnosed [`Cause::InOtherAccount`] with its owner looked up in the machine's other
/// accounts (#153a, design §12.4): the account that holds the vault, else the accounts that
/// could not be asked. Any other cause is returned as it is. The search is part of the
/// failure's diagnosis: the failed call's reply must already be taken, and the probes leave
/// nothing of their own behind.
pub fn locate_owner(r: &dyn CommandRunner, cause: Cause) -> Cause {
    let search = match &cause {
        Cause::InOtherAccount {
            vault,
            selected,
            owning: None,
            unasked,
            searched: false,
            ..
        } if unasked.is_empty() => crate::runner::diagnosing(|| search_vault(r, vault, selected)),
        _ => return cause,
    };
    placed(cause, &search)
}

/// What `search` says about a vault op reported as not in the selected account (`cause`,
/// an unsearched [`Cause::InOtherAccount`]): in the account found, else in none that could
/// be asked, naming those that could not.
pub fn placed(cause: Cause, search: &VaultSearch) -> Cause {
    let Cause::InOtherAccount {
        vault,
        item,
        selected,
        env,
        seen,
        ..
    } = cause
    else {
        return cause;
    };
    let (owning, unasked, searched) = match search {
        VaultSearch::FoundIn(owner) => (Some(owner.clone()), Vec::new(), true),
        VaultSearch::Nowhere { unasked } => (None, unasked.clone(), true),
        VaultSearch::NotSearched => (None, Vec::new(), false),
    };
    Cause::InOtherAccount {
        vault,
        item,
        selected,
        owning,
        unasked,
        searched,
        env,
        seen,
    }
}

impl Facts {
    /// The overriding variables set in opv's own environment (presence only; the value is
    /// never read).
    pub fn from_process_env() -> Self {
        let env_overrides = [OP_ACCOUNT]
            .into_iter()
            .filter(|var| std::env::var_os(var).is_some_and(|v| !v.is_empty()))
            .map(VarName::new)
            .collect();
        let here = std::env::current_dir().unwrap_or_default();
        let pointer = crate::config_store::pointer_account(&here)
            .zip(crate::config_store::walk_up(&here, ".opv"));
        Self {
            env_overrides,
            pointer,
            in_app: crate::app::account::app_holds_accounts_here(),
            ..Self::default()
        }
    }

    fn overridden_by(&self, var: &str) -> bool {
        self.env_overrides.iter().any(|v| v.as_str() == var)
    }
}

/// Classify one failed `op` call (design §5), with the overriding variables of opv's own
/// environment. Call sites that know more use [`diagnose_with`].
pub fn diagnose(seen: Observed, stderr: &str, ctx: &DiagnoseContext) -> Cause {
    diagnose_with(seen, stderr, ctx, &Facts::from_process_env())
}

/// Classify one failed `op` call from what opv established (`facts`).
pub fn diagnose_with(seen: Observed, stderr: &str, ctx: &DiagnoseContext, facts: &Facts) -> Cause {
    // An unfinished call is diagnosed by what it was doing, never by its text.
    if seen.exit().unanswered().is_some() {
        return unknown_outcome(seen, ctx);
    }
    match reading(stderr) {
        Some(Reading::AccountNotOnMachine) => account_not_on_machine(&seen, stderr, ctx, facts),
        Some(Reading::ServiceAccountTokenRejected) => service_account_rejected(seen),
        Some(Reading::AllAndAccount) if facts.overridden_by(OP_ACCOUNT) => {
            Cause::CredentialRejected {
                system: System::OnePassword,
                credential: CredentialRef::ShellToken {
                    var: VarName::new(OP_ACCOUNT),
                },
                problem: CredentialProblem::OverriddenByEnvironment {
                    var: VarName::new(OP_ACCOUNT),
                },
                seen,
            }
        }
        Some(Reading::SignedOut) => not_signed_in(&seen, ctx, facts),
        Some(Reading::ItemNotFound) => item_not_found(seen, stderr, ctx),
        Some(Reading::NotAVaultHere) => match vault_of(&seen, ctx) {
            Some(vault) => vault_not_here(seen, ctx, vault),
            None => unrecognized(seen, ctx, facts),
        },
        Some(Reading::AllAndAccount) | None => unrecognized(seen, ctx, facts),
    }
}

/// What a recorded `op` phrase tells us, before the subject is filled in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reading {
    /// `no account found for filter <account>` (case 02).
    AccountNotOnMachine,
    /// `failed to DecodeSACredentials: …`, exit 9 (case 03).
    ServiceAccountTokenRejected,
    /// `You can't use both the '--all' and '--account' flags at the same time.` (case 04).
    AllAndAccount,
    /// `no active session found for account <id>` / `You are not currently signed in`
    /// (cases 05–07, 11–12).
    SignedOut,
    /// `"<item>" isn't an item in the "<vault>" vault.` (case 09).
    ItemNotFound,
    /// `"<vault>" isn't a vault in this account.` (cases 08, 14–15).
    NotAVaultHere,
}

/// The recorded `op` failure phrases (op 2.40.0), matched on the raw stderr. The first row
/// that matches wins.
const PHRASES: &[(Reading, &[&str])] = &[
    (
        Reading::AccountNotOnMachine,
        &["no account found for filter"],
    ),
    (
        Reading::ServiceAccountTokenRejected,
        &["failed to DecodeSACredentials"],
    ),
    (
        Reading::AllAndAccount,
        &["You can't use both the '--all' and '--account' flags"],
    ),
    (
        Reading::SignedOut,
        &[NO_ACTIVE_SESSION, NOT_CURRENTLY_SIGNED_IN],
    ),
    (Reading::ItemNotFound, &["isn't an item in the"]),
    (Reading::NotAVaultHere, &["isn't a vault in this account"]),
];

/// `op whoami --account <id>` with no session for that account (cases 05, 11).
const NO_ACTIVE_SESSION: &str = "no active session found for account";
/// Any other call without a session (cases 06, 07, 12).
const NOT_CURRENTLY_SIGNED_IN: &str = "You are not currently signed in";

fn reading(stderr: &str) -> Option<Reading> {
    PHRASES
        .iter()
        .find(|(_, phrases)| phrases.iter().any(|p| stderr.contains(p)))
        .map(|(reading, _)| *reading)
}

/// A call that ended on opv's timeout or a signal (§4.6): a create's or a write's outcome is
/// unknown, a read is unavailable.
fn unknown_outcome(seen: Observed, ctx: &DiagnoseContext) -> Cause {
    if let Some((kind, name, refind)) = &ctx.create {
        return Cause::CreateOutcomeUnknown {
            system: System::OnePassword,
            kind: *kind,
            name: name.clone(),
            refind: refind.clone(),
            seen,
        };
    }
    if ctx.write {
        let subject = ctx.resource.clone().unwrap_or_else(|| ResourceRef {
            kind: ResourceKind::Item,
            name: ResourceName::new(""),
            scope: ctx.account.as_ref().map(|a| a.to_string()),
        });
        return Cause::WriteOutcomeUnknown {
            system: System::OnePassword,
            subject,
            seen,
        };
    }
    Cause::Unavailable {
        system: System::OnePassword,
        why: seen.exit().unanswered().unwrap_or(Unanswered::Timeout),
        attempts: seen.attempts(),
        seen,
    }
}

/// The account op could not find (case 02): the `--account` the call named, else the call
/// site's account, else the filter op echoed.
fn account_not_on_machine(
    seen: &Observed,
    stderr: &str,
    ctx: &DiagnoseContext,
    facts: &Facts,
) -> Cause {
    let flag = flag_value(seen, "--account");
    let given = flag
        .clone()
        .or_else(|| ctx.account.as_ref().map(|a| a.to_string()))
        .or_else(|| after(stderr, "no account found for filter "))
        .unwrap_or_default();
    // Where the account came from: opv passes the selected account to op as `--account`,
    // so the flag alone does not say who chose it (L9 follow-up).
    let selected_by = match &facts.pointer {
        Some((id, path)) if id.eq_ignore_ascii_case(&given) => {
            AccountSource::DotOpv { path: path.clone() }
        }
        _ if facts.overridden_by(OP_ACCOUNT)
            && std::env::var(OP_ACCOUNT).is_ok_and(|v| v.eq_ignore_ascii_case(&given)) =>
        {
            AccountSource::EnvVar {
                var: VarName::new(OP_ACCOUNT),
            }
        }
        _ => match (&ctx.env, &ctx.account) {
            (Some(env), Some(a)) if a.as_str().eq_ignore_ascii_case(&given) => {
                AccountSource::Environment { env: env.clone() }
            }
            _ if flag.is_some() => AccountSource::Flag,
            _ if facts.overridden_by(OP_ACCOUNT) => AccountSource::EnvVar {
                var: VarName::new(OP_ACCOUNT),
            },
            _ => AccountSource::OpDefault,
        },
    };
    let account = if given.contains('@') {
        AccountRef::Email(given)
    } else {
        AccountRef::Id(AccountId::new(given))
    };
    Cause::AccountNotOnMachine {
        account,
        selected_by,
        in_app: facts.in_app,
    }
}

/// An unreadable service-account token (case 03): the token the runner saw in effect.
fn service_account_rejected(seen: Observed) -> Cause {
    let var = match seen.principal() {
        Principal::ShellToken { var } => var.clone(),
        _ => VarName::new(OP_SERVICE_ACCOUNT_TOKEN),
    };
    Cause::CredentialRejected {
        system: System::OnePassword,
        credential: CredentialRef::ServiceAccountToken { var },
        problem: CredentialProblem::Rejected { needs: Vec::new() },
        seen,
    }
}

/// No session for the account (cases 05–07, 11–12); a live session for another account
/// (#160) is named when the probe found one.
fn not_signed_in(seen: &Observed, ctx: &DiagnoseContext, facts: &Facts) -> Cause {
    let account = ctx
        .account
        .clone()
        .or_else(|| flag_value(seen, "--account").map(AccountId::new));
    let state = match (&account, &facts.live) {
        (Some(asked), Some(live)) if asked != live => {
            SessionState::OtherAccount { live: live.clone() }
        }
        _ => SessionState::SignedOut,
    };
    Cause::NotSignedIn {
        system: System::OnePassword,
        account,
        state,
    }
}

/// An item missing from a vault of the signed-in account (case 09).
fn item_not_found(seen: Observed, stderr: &str, ctx: &DiagnoseContext) -> Cause {
    let resource = ctx
        .resource
        .clone()
        .filter(|r| r.kind == ResourceKind::Item)
        .unwrap_or_else(|| ResourceRef {
            kind: ResourceKind::Item,
            name: ResourceName::new(
                word_after(&seen, "item", &["get"])
                    .or_else(|| quoted(stderr, 0))
                    .unwrap_or_default(),
            ),
            scope: flag_value(&seen, "--vault").or_else(|| quoted(stderr, 1)),
        });
    Cause::NotFound {
        system: System::OnePassword,
        resource,
        named_by: ctx.named_by.clone().unwrap_or(NamedBy::Flag {
            flag: "--item".to_string(),
        }),
        state: NotFoundState::Missing,
        seen,
    }
}

/// `"<vault>" isn't a vault in this account.` (cases 08, 14–15). op says the same whether
/// the vault belongs to another account on the machine or to none: with an account
/// selected, it is in another account, whose owner [`locate_owner`] looks up (#153a);
/// otherwise it is not found.
fn vault_not_here(seen: Observed, ctx: &DiagnoseContext, vault: VaultId) -> Cause {
    let selected = ctx
        .account
        .clone()
        .or_else(|| flag_value(&seen, "--account").map(AccountId::new));
    match selected {
        Some(selected) => Cause::InOtherAccount {
            vault,
            item: ctx
                .resource
                .as_ref()
                .filter(|r| r.kind == ResourceKind::Item)
                .map(|r| ItemId::new(r.name.as_str())),
            selected,
            owning: None,
            unasked: Vec::new(),
            searched: false,
            env: ctx.env.clone(),
            seen,
        },
        None => Cause::NotFound {
            system: System::OnePassword,
            resource: ResourceRef {
                kind: ResourceKind::Vault,
                name: ResourceName::new(vault.as_str()),
                scope: None,
            },
            named_by: ctx.named_by.clone().unwrap_or(NamedBy::Flag {
                flag: "--vault".to_string(),
            }),
            state: NotFoundState::Missing,
            seen,
        },
    }
}

/// The vault a call names: the call site's, else `--vault`, else the vault argument of
/// `vault get` / `vault user list`.
fn vault_of(seen: &Observed, ctx: &DiagnoseContext) -> Option<VaultId> {
    let from_ctx = ctx
        .resource
        .as_ref()
        .filter(|r| r.kind == ResourceKind::Vault)
        .map(|r| r.name.to_string());
    from_ctx
        .or_else(|| flag_value(seen, "--vault"))
        .or_else(|| word_after(seen, "vault", &["get", "user", "list", "group"]))
        .map(VaultId::new)
}

/// Nothing recorded matched (§5): the reply is shown in full, with what opv did establish.
fn unrecognized(seen: Observed, ctx: &DiagnoseContext, facts: &Facts) -> Cause {
    let mut established = Vec::new();
    if let Principal::ShellToken { var } = seen.principal() {
        established.push(format!("the token in {var} was in effect"));
    }
    for var in &facts.env_overrides {
        established.push(format!("{var} was set in the environment"));
    }
    if let Some(live) = &facts.live {
        established.push(format!("a session for account {live} is live"));
    }
    if let ExitClass::Code { code } = seen.exit() {
        established.push(format!("op exited {code}"));
    }
    Cause::Unrecognized {
        system: System::OnePassword,
        established,
        env: ctx.env.clone(),
        target: ctx.target.clone(),
        seen,
    }
}

/// The word after `flag` in the call's words.
fn flag_value(seen: &Observed, flag: &str) -> Option<String> {
    seen.call().words.windows(2).find_map(|pair| match pair {
        [f, value] if f == flag => Some(value.clone()),
        _ => None,
    })
}

/// The first positional word after the `noun` command and its subcommand `verbs`
/// (`vault user list <vault>`, `item get <item>`).
fn word_after(seen: &Observed, noun: &str, verbs: &[&str]) -> Option<String> {
    let words = &seen.call().words;
    let start = words.iter().position(|w| w == noun)? + 1;
    words[start..]
        .iter()
        .take_while(|w| !w.starts_with('-'))
        .find(|w| !verbs.contains(&w.as_str()))
        .cloned()
}

/// The `n`th double-quoted name in op's reply.
fn quoted(stderr: &str, n: usize) -> Option<String> {
    stderr
        .split('"')
        .skip(1)
        .step_by(2)
        .nth(n)
        .map(str::to_string)
}

/// The word following `prefix` in `stderr`.
fn after(stderr: &str, prefix: &str) -> Option<String> {
    let rest = &stderr[stderr.find(prefix)? + prefix.len()..];
    rest.split_whitespace().next().map(str::to_string)
}

// --- the #160 probe ------------------------------------------------------------------------

/// Whether `op` has a session for an account (#160).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionCheck {
    /// `op whoami --account <id>` succeeded.
    SignedIn,
    /// No session for the account, and none for another account either.
    NotSignedIn,
    /// No session for the account, but `op whoami` is signed in to `live`, another account
    /// on the same sign-in address.
    OtherAccountLive { live: AccountId },
    /// The probe did not finish, or op answered with something not recorded.
    Undetermined,
}

/// Probe the session for `account`: `op whoami --account <id> --format json` (stdin closed,
/// as a probe). When op says there is no active session for it, a plain `op whoami` (with
/// `OP_ACCOUNT` emptied, so no default account applies) tells whether another account's
/// session is live. Never an item read.
pub fn session_for(r: &dyn CommandRunner, account: &AccountId) -> SessionCheck {
    let id = account.as_str();
    let asked = match r.probe(
        &Call::new(
            crate::adapters::onepassword::OP,
            &["whoami", "--account", id, "--format", "json"],
        ),
        PROBE_TIMEOUT,
    ) {
        Ok(out) => out,
        Err(_) => return SessionCheck::Undetermined,
    };
    if asked.status == 0 {
        return SessionCheck::SignedIn;
    }
    // This probe's reply is read here and must not attach to the command's own result.
    let said = crate::runner::take_failure_excerpt()
        .map(|e| e.lines.join("\n"))
        .unwrap_or_default();
    if said.contains(NOT_CURRENTLY_SIGNED_IN) {
        return SessionCheck::NotSignedIn;
    }
    if !said.contains(NO_ACTIVE_SESSION) {
        return SessionCheck::Undetermined;
    }
    let plain = Call {
        env: &[(OP_ACCOUNT, "")],
        ..Call::new(
            crate::adapters::onepassword::OP,
            &["whoami", "--format", "json"],
        )
    };
    match r.probe(&plain, PROBE_TIMEOUT) {
        Ok(out) if out.status == 0 => match account_uuid(&out.stdout) {
            Some(live) if live != *account => SessionCheck::OtherAccountLive { live },
            Some(_) => SessionCheck::SignedIn,
            None => SessionCheck::Undetermined,
        },
        Ok(_) => {
            let _ = crate::runner::take_failure_excerpt();
            SessionCheck::NotSignedIn
        }
        Err(_) => SessionCheck::Undetermined,
    }
}

/// `account_uuid` from `op whoami --format json`, checked against a strict character set;
/// nothing else is parsed (SR-1).
fn account_uuid(stdout: &[u8]) -> Option<AccountId> {
    #[derive(Deserialize)]
    struct Who {
        #[serde(default)]
        account_uuid: Option<String>,
    }
    let who: Who = serde_json::from_slice(stdout).ok()?;
    who.account_uuid
        .filter(|u| !u.is_empty() && u.len() <= 64 && u.chars().all(|c| c.is_ascii_alphanumeric()))
        .map(AccountId::new)
}

#[cfg(test)]
#[path = "onepassword_diagnose_tests.rs"]
mod tests;
