//! 1Password adapter wrapping the official `op` CLI (S3; FR-11, FR-13, FR-14, FR-19).
//!
//! - [`read_whole`] makes exactly one `op item get <item_id> --vault <vault_id> --format json`
//!   call per environment, by ID only (FR-13), and keeps the raw item JSON for the tolerant
//!   reader ([`super::onepassword_tidy`], FR-43). A reply that is not an item opv can read is
//!   that call's `UnexpectedOutput`, found while the runner still holds the call.
//! - The item read is diagnosed after its first failed attempt, before any retry (P16):
//!   it is retried only when the identity is signed in and can open the vault.
//! - A failed `op` call becomes a catalog cause (design `docs/design/error-catalog.md` §5):
//!   its reply is matched against the recorded phrases
//!   ([`super::onepassword_diagnose_items`]); when they cannot tell, the free probes run:
//!   [`diagnose`] (`op whoami`, then `op account list` when it fails; never a second item
//!   read; own 15 s limit), then `op vault get`. The runner's observation of the call and
//!   its scrubbed reply are the error's evidence. The host is detected only on failure.
//!   For diagnosis only `user_type` is
//!   parsed from `whoami`, and only the entry count from `account list`; identity is never
//!   printed or kept. [`account`] parses `account_uuid` and the sign-in host, identifiers
//!   only, to build 1Password's private item link ([`item_link`], H1).
//! - An item write pipes the full current item to `op item edit <item_id> --vault <vault_id>
//!   --format json` on stdin. This is the invocation the D0 spike proved (attempt 1). A
//!   template replaces the item's fields, so it is always the whole item, never a partial one.
//!
//! Secrecy (SR-1, SR-3, SR-4, SR-8):
//! - Nothing but IDs and fixed words goes in argv; the template goes on stdin; no files.
//! - Child stderr is held in memory by the runner and shown only scrubbed, on failure or
//!   with `--verbose` (NR-31); every item read registers its field values with the
//!   scrubber. No error built here includes child output or serde_json's own messages
//!   (they can quote values).
//! - Values are deserialized straight into [`SecretValue`] (zeroized on drop). The raw JSON
//!   is kept in a `Zeroizing` buffer and never printed (`Item`'s `Debug` shows its length).
//!
//! Unavoidable transient copies, documented per ruling 7:
//! - serde_json decodes a string containing escape sequences into an internal scratch
//!   buffer that is not zeroized. Unescaped strings are borrowed from the input and copied
//!   once, at exact capacity, into the `SecretValue`.
//! - An item write parses the raw JSON into a `serde_json::Value`, whose `String`s hold
//!   values. Every string in that tree is zeroized before it is dropped (also on error paths),
//!   and the template is serialized into a `Zeroizing` buffer pre-sized to the exact length,
//!   so it never reallocates.

use std::collections::BTreeSet;
use std::fmt;
use std::io::{self, Write};
use std::time::Duration;

use serde::Deserialize;
use serde::de::{self, Deserializer, Visitor};
use serde_json::{Value, json};
use zeroize::{Zeroize, Zeroizing};

use super::onepassword_diagnose::{Facts, locate_owner};
use super::onepassword_diagnose_items::diagnose_item_call;
use crate::cause::{
    AccountId, AccountRef, AccountSource, Cause, CredentialProblem, CredentialRef, DiagnoseContext,
    DottedPath, EnvName, ExitClass, FieldName, FieldType, GrantModel, IoKind, ItemId, Location,
    NamedBy, NotFoundState, Observed, Principal, ResourceKind, ResourceName, ResourceRef, Right,
    SessionState, System, TargetName, Unanswered, Unusable, Upstream, VarName, VaultId,
};
use crate::domain::model::{Boundary, Environment, Kind};
use crate::domain::plan::ItemField;
use crate::domain::secret::SecretValue;
use crate::error::Error;
use crate::host::{Host, OpCredential, Platform};
use crate::runner::{Call, CommandRunner, Outcome, Output, PROBE_TIMEOUT};

pub(crate) const OP: &str = "op";

/// The result of one whole-item read.
///
/// `fields` may be moved out (`std::mem::take(&mut item.fields)`) to build a plan;
/// [`write_skeleton`] uses only the raw JSON kept inside.
pub struct Item {
    pub fields: Vec<ItemField>,
    /// The item's `version` integer (bumped by 1Password on every edit), when `op` reports
    /// it: an input of the plan id (FR-41). Never derived from a value.
    pub version: Option<u64>,
    raw: Zeroizing<Vec<u8>>,
}

impl Item {
    /// The item JSON exactly as `op` returned it (holds values; never print it).
    pub(crate) fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// An item from the JSON an `op item edit` printed (the item as written): no parsed
    /// fields, its version read from the JSON.
    pub(crate) fn from_raw(raw: Zeroizing<Vec<u8>>) -> Self {
        Self {
            fields: Vec::new(),
            version: item_version(&raw),
            raw,
        }
    }
}

impl fmt::Debug for Item {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Item")
            .field("fields", &self.fields)
            .field("version", &self.version)
            .field("raw_len", &self.raw.len())
            .finish()
    }
}

/// The identity `op` is signed in as: its type only, from `op whoami`'s `user_type`
/// field. Identity details (email, user UUID) are never parsed or kept (SR-1); the account
/// UUID and sign-in host are parsed only by [`account`], for a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityType {
    User,
    ServiceAccount,
    /// `user_type` missing or not a plain upper-case word.
    Unknown,
}

impl fmt::Display for IdentityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            IdentityType::User => "USER",
            IdentityType::ServiceAccount => "SERVICE_ACCOUNT",
            IdentityType::Unknown => "unknown type",
        })
    }
}

/// The 1Password session state, found without reading any item (FR-26, FR-13): `op whoami`
/// and, when it fails, `op account list` (both free under rate limits, D0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Session {
    /// `op whoami` succeeded.
    SignedIn(IdentityType),
    /// `op whoami` failed with no non-interactive credential set: no session, an expired
    /// `OP_SESSION_*`, a locked desktop app (or no network).
    NotSignedIn,
    /// `op whoami` failed while a service-account or Connect credential is set: rejected
    /// or unreachable. Ambiguous, so it keeps the source category (exit 4, FR-10).
    CredentialFailed(OpCredential),
    /// `op whoami` failed and `op account list` is empty: no account on this machine.
    NoAccount,
    /// `op whoami` could not run to completion (spawn error or timeout); nothing known.
    Unknown,
}

/// Classify the 1Password session (FR-26). Shared by `doctor` and every failed `op` call.
///
/// Calls: `op whoami --format json`; only if it fails, and only outside CI and without a
/// non-interactive credential, `op account list --format json`. Both are diagnosis probes
/// with their own [`PROBE_TIMEOUT`]. Never an item read (FR-13). From `whoami` only
/// `user_type` is parsed; from `account list` only the number of entries. `op` missing is
/// `Err(Dependency)` with the install hint. `host` is called only when needed.
pub fn diagnose(r: &dyn CommandRunner, host: &dyn Fn() -> Host) -> Result<Session, Error> {
    let who = match r.probe(
        &Call::new(OP, &["whoami", "--format", "json"]),
        PROBE_TIMEOUT,
    ) {
        Ok(o) => o,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(op_missing(&host())),
        Err(_) => return Ok(Session::Unknown),
    };
    if who.status == 0 {
        return Ok(Session::SignedIn(identity_type(&who.stdout)));
    }
    let h = host();
    if let Some(c) = h.op_credential {
        return Ok(Session::CredentialFailed(c));
    }
    if h.ci {
        return Ok(Session::NotSignedIn);
    }
    Ok(
        match r.probe(
            &Call::new(OP, &["account", "list", "--format", "json"]),
            PROBE_TIMEOUT,
        ) {
            Ok(o) if o.status == 0 && account_count(&o.stdout) == Some(0) => Session::NoAccount,
            _ => Session::NotSignedIn,
        },
    )
}

/// #157: the session a read-only command checks before it classifies any vault, so a
/// missing session is reported as `op_not_signed_in` (exit 7, `human_required`) rather than
/// as every vault being outside the account. Like `doctor`, it asks the 1Password app once
/// ([`wake`]) before reporting "not signed in" outside CI. A session that could not be
/// checked (`Unknown`) is let through: each vault is then classified on its own.
pub fn require_session(
    r: &dyn CommandRunner,
    host: &dyn Fn() -> Host,
    failed: &str,
) -> Result<(), Error> {
    let mut session = diagnose(r, host)?;
    if session == Session::NotSignedIn && !host().ci && wake(r) {
        session = diagnose(r, host)?;
    }
    match session {
        Session::SignedIn(_) | Session::Unknown => Ok(()),
        s => {
            Err(session_error(s, &host(), Some(failed), None)
                .expect("every other session is an error"))
        }
    }
}

/// Limit for [`wake`]: long enough for a person to approve the 1Password app's prompt.
pub const APPROVAL_TIMEOUT: Duration = Duration::from_secs(60);

/// Ask the 1Password app to authorize this terminal: `op whoami` never does, so with the
/// app integration it reports "not signed in" until some other command has been approved.
/// One `op vault list --format json` probe (exit status only; its output names vaults and
/// is dropped unread, SR-1); `true` when it succeeded. Never an item read (FR-13).
pub fn wake(r: &dyn CommandRunner) -> bool {
    let ok = r
        .probe(
            &Call::new(OP, &["vault", "list", "--format", "json"]),
            APPROVAL_TIMEOUT,
        )
        .is_ok_and(|o| o.status == 0);
    if !ok {
        // Its stderr must not attach to the error the caller reports (NR-31).
        let _ = crate::runner::take_failure_excerpt();
    }
    ok
}

/// `user_type` from `op whoami --format json`, nothing else. Unknown fields (identity) are
/// skipped by serde without being kept. With the 1Password app integration, `whoami` has
/// no `user_type`; a `user_uuid` (checked for presence only, never kept) then means a person,
/// since a service account always reports `SERVICE_ACCOUNT`.
fn identity_type(stdout: &[u8]) -> IdentityType {
    #[derive(Deserialize)]
    struct Who {
        #[serde(default)]
        user_type: Option<String>,
        #[serde(default)]
        user_uuid: Option<de::IgnoredAny>,
    }
    let Ok(w) = serde_json::from_slice::<Who>(stdout) else {
        return IdentityType::Unknown;
    };
    let t = w.user_type.filter(|t| {
        !t.is_empty() && t.len() <= 32 && t.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
    });
    match t.as_deref() {
        Some("SERVICE_ACCOUNT") => IdentityType::ServiceAccount,
        Some(_) => IdentityType::User,
        None if w.user_uuid.is_some() => IdentityType::User,
        None => IdentityType::Unknown,
    }
}

/// Number of accounts in `op account list --format json` (an array; empty output is none).
/// Entries are skipped unread (they name the account).
fn account_count(stdout: &[u8]) -> Option<usize> {
    if stdout.iter().all(u8::is_ascii_whitespace) {
        return Some(0);
    }
    serde_json::from_slice::<Vec<de::IgnoredAny>>(stdout)
        .ok()
        .map(|v| v.len())
}

/// The 1Password account a private item link opens in (H1): `account_uuid` and the
/// sign-in host from `op whoami`. Both are identifiers, not secrets, and are used only to
/// build an `open:` link for the person who is already signed in; no email or user id is
/// parsed (SR-1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    uuid: String,
    host: Option<String>,
}

/// The signed-in account from one `op whoami --format json` probe, or `None` when it fails
/// or names no well-formed account (the link is then built without it). Never an item
/// read (FR-13).
pub fn account(r: &dyn CommandRunner) -> Option<Account> {
    let who = r
        .probe(
            &Call::new(OP, &["whoami", "--format", "json"]),
            PROBE_TIMEOUT,
        )
        .ok()?;
    if who.status != 0 {
        // A link without the account is still useful; this probe's stderr must not
        // attach to the command's own result (NR-31).
        let _ = crate::runner::take_failure_excerpt();
        return None;
    }
    parse_account(&who.stdout)
}

/// `account_uuid` and the host of `url`, each checked against a strict character set so
/// nothing but an identifier can reach a link.
fn parse_account(stdout: &[u8]) -> Option<Account> {
    #[derive(Deserialize)]
    struct Who {
        #[serde(default)]
        account_uuid: Option<String>,
        #[serde(default)]
        url: Option<String>,
    }
    let w = serde_json::from_slice::<Who>(stdout).ok()?;
    let uuid = w.account_uuid.filter(|u| {
        !u.is_empty() && u.len() <= 64 && u.bytes().all(|b| b.is_ascii_alphanumeric())
    })?;
    let host = w.url.and_then(|u| {
        let h = u
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .to_ascii_lowercase();
        (!h.is_empty()
            && h.len() <= 253
            && h.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'))
        .then_some(h)
    });
    Some(Account { uuid, host })
}

/// 1Password's private item link, the form "Copy Private Link" produces:
/// `https://start.1password.com/open/i?a=<account>&v=<vault>&i=<item>&h=<host>`. It opens
/// the item in the 1Password app or web, the only place a value is typed. 1Password links
/// to items, not to single fields, so callers name the section and field next to it. IDs
/// only, never a value.
pub fn item_link(account: Option<&Account>, vault_id: &str, item_id: &str) -> String {
    let mut q = Vec::new();
    if let Some(a) = account {
        q.push(format!("a={}", a.uuid));
    }
    q.push(format!("v={}", url_part(vault_id)));
    q.push(format!("i={}", url_part(item_id)));
    if let Some(h) = account.and_then(|a| a.host.as_deref()) {
        q.push(format!("h={h}"));
    }
    format!("https://start.1password.com/open/i?{}", q.join("&"))
}

/// Percent-encode everything but unreserved characters (IDs are alphanumeric in practice).
fn url_part(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

// --- failed `op` calls, diagnosed (design `docs/design/error-catalog.md` §5) ----------------

/// What the runner kept of the failed `op` call the error at hand came from: its
/// observation and its scrubbed reply, taken once, right after the call and before any
/// diagnosis probe. The reply is the evidence box (§7.3) and the text the recorded phrase
/// tables ([`super::onepassword_diagnose`]) are matched against.
pub(crate) struct Failed {
    seen: Observed,
    stderr: String,
    upstream: Option<Upstream>,
}

impl Failed {
    /// The failed call's observation and reply, when the runner kept one.
    fn take() -> Option<Failed> {
        crate::runner::take_observed().map(Self::with_reply)
    }

    /// `seen` (a create's unknown outcome, from the runner) with the call's reply.
    pub(crate) fn with_reply(seen: Observed) -> Failed {
        let (said, truncated) = crate::scrub::Excerpt::parts(crate::runner::take_failure_excerpt());
        let upstream = (!said.is_empty()).then(|| Upstream {
            source: System::OnePassword,
            tool: "1Password CLI".to_string(),
            version: None,
            exit: seen.exit(),
            said: said.clone(),
            removed_advice: false,
            truncated,
            untrusted: true,
        });
        Failed {
            stderr: said.join("\n"),
            seen,
            upstream,
        }
    }

    /// The call this failure observed.
    pub(crate) fn seen(&self) -> &Observed {
        &self.seen
    }

    /// The failed `call`'s observation and reply. A call that answered with a reply opv
    /// cannot use (stdout over the output cap) is the runner's observation of that answer.
    pub(crate) fn of(call: &Call) -> Failed {
        Self::take().unwrap_or_else(|| Failed {
            seen: crate::runner::take_unusable_reply(call)
                .expect("op is an external system the runner observes"),
            stderr: String::new(),
            upstream: None,
        })
    }

    /// The cause the `op` strategy finds from the reply alone (design §5).
    pub(crate) fn diagnosed(&self, ctx: &DiagnoseContext, facts: &Facts) -> Cause {
        diagnose_item_call(self.seen.clone(), &self.stderr, ctx, facts)
    }

    /// `cause` as the error, with the call's reply as its evidence.
    pub(crate) fn report(self, cause: Cause) -> Error {
        match self.upstream {
            Some(up) => Error::with_evidence(cause, up),
            None => cause.into(),
        }
    }
}

/// What a call about item `b` of `env` is about, for the `op` strategy: the environment,
/// the item (scoped by its vault), the configuration field that names it and the account.
fn item_context(env: &Environment, b: &Boundary, write: bool) -> DiagnoseContext {
    let env_name = (!env.name.is_empty()).then(|| EnvName::new(env.name.as_str()));
    let named_by = env_name.as_ref().map(|e| {
        let mut path = vec!["environments".to_string(), e.to_string()];
        match env.boundaries.iter().find(|(_, x)| *x == b) {
            Some((name, _)) => path.extend(["boundaries".into(), name.clone(), "item_id".into()]),
            None => path.push("boundaries".into()),
        }
        NamedBy::ConfigField {
            path: DottedPath(path),
        }
    });
    DiagnoseContext {
        env: env_name,
        target: None,
        resource: Some(ResourceRef {
            kind: ResourceKind::Item,
            name: ResourceName::new(b.item_id.as_str()),
            scope: Some(b.vault_id.clone()),
        }),
        named_by,
        create: None,
        write,
        account: env.account.as_deref().map(AccountId::new),
    }
}

/// The account the call was made in: the call site's, else none (op's default).
fn account_source(ctx: &DiagnoseContext) -> AccountSource {
    match (&ctx.account, &ctx.env) {
        (Some(_), Some(env)) => AccountSource::Environment { env: env.clone() },
        (Some(_), None) => AccountSource::Flag,
        (None, _) => AccountSource::OpDefault,
    }
}

/// Stands in for the account when op knows none at all (`op account list` is empty).
const NO_ACCOUNT_YET: &str = "for this project";

/// The 1Password app holds op's accounts here (macOS, Windows, or op.exe from WSL), so an
/// account is added there, never with `op account add`.
fn accounts_in_app(host: &Host) -> bool {
    host.op_is_windows_exe() || matches!(host.platform, Platform::MacOs | Platform::Windows)
}

/// The cause for a session [`diagnose`] found unusable; `None` for `SignedIn` / `Unknown`.
/// `seen` is the failed call the session explains (a rejected credential's evidence).
fn session_cause(
    session: Session,
    host: &Host,
    ctx: &DiagnoseContext,
    seen: Option<&Observed>,
) -> Option<Cause> {
    match session {
        Session::SignedIn(_) | Session::Unknown => None,
        // Under CI no person can sign in (X8): the run needs its service-account token,
        // which is not set (a set one that fails is `CredentialFailed`).
        Session::NotSignedIn if host.ci && seen.is_some() => Some(Cause::CredentialRejected {
            system: System::OnePassword,
            credential: CredentialRef::ServiceAccountToken {
                var: VarName::new(OpCredential::ServiceAccount.var()),
            },
            problem: CredentialProblem::Unreadable,
            seen: seen.cloned()?,
        }),
        // With op.exe, op's sessions are the Windows app's: not signed in means it is
        // locked (or its CLI integration is off).
        Session::NotSignedIn => Some(Cause::NotSignedIn {
            system: System::OnePassword,
            account: ctx.account.clone(),
            state: if host.op_is_windows_exe() {
                SessionState::AppLocked
            } else {
                SessionState::SignedOut
            },
        }),
        Session::NoAccount => Some(Cause::AccountNotOnMachine {
            account: ctx.account.clone().map_or_else(
                || AccountRef::Shorthand(NO_ACCOUNT_YET.to_string()),
                AccountRef::Id,
            ),
            selected_by: account_source(ctx),
            in_app: accounts_in_app(host),
        }),
        Session::CredentialFailed(c) => Some(match seen {
            Some(seen) => credential_rejected(c, seen.clone()),
            None => Cause::Bug {
                site: "onepassword: a rejected credential without its failed call",
            },
        }),
    }
}

/// The service-account or Connect credential in effect was rejected, or 1Password could
/// not be reached with it (04.11): both Connect variables are named.
fn credential_rejected(c: OpCredential, seen: Observed) -> Cause {
    let credential = match c {
        OpCredential::ServiceAccount => CredentialRef::ServiceAccountToken {
            var: VarName::new(c.var()),
        },
        OpCredential::Connect => CredentialRef::Connect {
            host_var: VarName::new("OP_CONNECT_HOST"),
            token_var: VarName::new(c.var()),
        },
    };
    Cause::CredentialRejected {
        system: System::OnePassword,
        credential,
        problem: CredentialProblem::Rejected { needs: Vec::new() },
        seen,
    }
}

/// The remediation for a session that is not usable, or `None` for `SignedIn` / `Unknown`
/// (FR-26): a catalog cause (design §4.3) whose Do and Next come from the cause, so the
/// platform decides how an account is added (04.07) and a rejected credential names its
/// variables (04.11). Text only, never a prompt (FR-9). `failed` and `env` are kept for
/// the callers that still pass them; the failed call is the evidence's `checked:` line.
pub fn session_error(
    session: Session,
    host: &Host,
    _failed: Option<&str>,
    env: Option<&str>,
) -> Option<Error> {
    let ctx = DiagnoseContext {
        env: env.map(EnvName::new),
        ..DiagnoseContext::default()
    };
    // A credential (rejected, or missing under CI) is shown with the call it failed (the
    // whoami probe, or the call that probe explains); the other sessions are opv's own
    // findings.
    let failed = (matches!(session, Session::CredentialFailed(_))
        || (session == Session::NotSignedIn && host.ci))
        .then(Failed::take)
        .flatten();
    let cause = session_cause(session, host, &ctx, failed.as_ref().map(|f| &f.seen))?;
    Some(match failed {
        Some(f) => f.report(cause),
        None => cause.into(),
    })
}

/// What opv established when `op whoami` itself did not answer (X13: said, never guessed).
const WHOAMI_SILENT: &str = "op whoami did not answer, so the session is unconfirmed";

/// `cause` with `fact` added to what opv established, when it is `Unrecognized`.
pub(crate) fn established(mut cause: Cause, fact: impl Into<String>) -> Cause {
    if let Cause::Unrecognized { established, .. } = &mut cause {
        established.push(fact.into());
    }
    cause
}

/// A signed-in call about `vault` failed and `op vault get <vault>` was refused (04.06,
/// 04.25): with an account selected, the vault is not in it (deleted, not shared, or in
/// another account, which the caller looks up: [`locate_owner`]); in op's default account,
/// the missing grant is Read.
fn vault_unreachable(ctx: &DiagnoseContext, seen: &Observed, vault: &str) -> Cause {
    match ctx.account.clone() {
        Some(selected) => Cause::InOtherAccount {
            vault: VaultId::new(vault),
            item: ctx
                .resource
                .as_ref()
                .filter(|r| r.kind == ResourceKind::Item)
                .map(|r| ItemId::new(r.name.as_str())),
            selected,
            owning: None,
            unasked: Vec::new(),
            env: ctx.env.clone(),
            seen: seen.clone(),
        },
        None => Cause::MissingRight {
            system: System::OnePassword,
            resource: ResourceRef {
                kind: ResourceKind::Vault,
                name: ResourceName::new(vault),
                scope: None,
            },
            right: Right::Read,
            grant: GrantModel::VaultPermission,
            env: ctx.env.clone(),
            target: None,
            seen: seen.clone(),
        },
    }
}

/// A failed call the phrases could not settle (`cause` is `Unrecognized`), checked with the
/// free probes (FR-26): the session first (`op whoami`, `op account list`); signed in,
/// whether `vault` opens (`op vault get`). Returns the cause and whether the session is
/// signed in with the vault readable, so a read may be retried. Never an item read.
fn unsettled(
    r: &dyn CommandRunner,
    host: &dyn Fn() -> Host,
    ctx: &DiagnoseContext,
    vault: Option<&str>,
    seen: &Observed,
    cause: Cause,
) -> Result<(Cause, bool), Error> {
    let session = diagnose(r, host)?;
    if let Some(c) = session_cause(session, &host(), ctx, Some(seen)) {
        return Ok((c, false));
    }
    if session == Session::Unknown {
        return Ok((established(cause, WHOAMI_SILENT), false));
    }
    let Some(vault) = vault else {
        return Ok((established(cause, "you are signed in to 1Password"), false));
    };
    Ok(match vault_access(r, vault) {
        Some(true) => (
            established(
                cause,
                format!("you are signed in to 1Password and vault {vault} opens"),
            ),
            true,
        ),
        Some(false) => (vault_unreachable(ctx, seen, vault), false),
        None => (
            established(cause, format!("op vault get {vault} did not answer")),
            false,
        ),
    })
}

/// A failed `op` read reported at once (design §5): the recorded phrases first, then the
/// session, then (when it names one) whether its vault opens.
pub(crate) fn failed_read(
    r: &dyn CommandRunner,
    host: &dyn Fn() -> Host,
    ctx: &DiagnoseContext,
    call: &Call,
    vault: Option<&str>,
) -> Error {
    failed_read_from(r, host, ctx, Failed::of(call), vault)
}

/// [`failed_read`] for a failure the caller already took.
pub(crate) fn failed_read_from(
    r: &dyn CommandRunner,
    host: &dyn Fn() -> Host,
    ctx: &DiagnoseContext,
    failed: Failed,
    vault: Option<&str>,
) -> Error {
    let cause = failed.diagnosed(ctx, &Facts::from_process_env());
    if !matches!(cause, Cause::Unrecognized { .. }) {
        let cause = locate_owner(r, cause);
        return failed.report(cause);
    }
    match crate::runner::diagnosing(|| unsettled(r, host, ctx, vault, &failed.seen, cause)) {
        // The runner already retried the read: in a vault that opens, it is the item.
        Ok((cause, true)) => {
            let missing = missing_item(ctx, &failed.seen);
            failed.report(missing.unwrap_or(cause))
        }
        Ok((cause, false)) => failed.report(locate_owner(r, cause)),
        Err(e) => e,
    }
}

/// NR-26: 1Password grants access per vault, so a read of the item `ctx` names that keeps
/// failing in a vault this identity opens is an item that is not there (moved, archived or
/// deleted). `None` when the call was not a read of an item, or when it did not end with
/// op's own failure exit (1): a read that hung, was killed or could not start says nothing
/// about the item (E2, X13).
fn missing_item(ctx: &DiagnoseContext, seen: &Observed) -> Option<Cause> {
    if seen.exit() != (ExitClass::Code { code: 1 }) {
        return None;
    }
    let item = ctx
        .resource
        .as_ref()
        .filter(|r| r.kind == ResourceKind::Item && ctx.create.is_none() && !ctx.write)?;
    Some(Cause::NotFound {
        system: System::OnePassword,
        resource: item.clone(),
        named_by: ctx.named_by.clone().unwrap_or(NamedBy::Flag {
            flag: "--item".to_string(),
        }),
        state: NotFoundState::Missing,
        seen: seen.clone(),
    })
}

/// A refused `op item edit` of item `b`, built from a read of that item moments before
/// (04.01): the read proved the item exists and opens, so a refusal is the missing Write
/// grant, unless the session explains it (signed out, no account, a rejected credential).
pub(crate) fn failed_write(
    r: &dyn CommandRunner,
    env: &Environment,
    b: &Boundary,
    host: &dyn Fn() -> Host,
    call: &Call,
) -> Error {
    failed_edit(r, host, &item_context(env, b, true), call)
}

/// A refused `op item edit` of the item `ctx` names, built from a fresh read of it (04.01,
/// 04.23): the missing Write grant, unless the session explains the refusal.
pub(crate) fn failed_edit(
    r: &dyn CommandRunner,
    host: &dyn Fn() -> Host,
    ctx: &DiagnoseContext,
    call: &Call,
) -> Error {
    let failed = Failed::of(call);
    let facts = Facts {
        item_readable: true,
        ..Facts::from_process_env()
    };
    let cause = failed.diagnosed(ctx, &facts);
    if !matches!(
        cause,
        Cause::MissingRight { .. } | Cause::Unrecognized { .. }
    ) {
        return failed.report(cause);
    }
    let checked = crate::runner::diagnosing(|| -> Result<Cause, Error> {
        let session = diagnose(r, host)?;
        Ok(
            match session_cause(session, &host(), ctx, Some(&failed.seen)) {
                Some(c) => c,
                // The session could not be checked, so the refusal is not known to be
                // definite: the edit may or may not have been applied (NR-2).
                None if session == Session::Unknown => Cause::WriteOutcomeUnknown {
                    system: System::OnePassword,
                    subject: ctx.resource.clone().unwrap_or(ResourceRef {
                        kind: ResourceKind::Item,
                        name: ResourceName::new(""),
                        scope: None,
                    }),
                    seen: failed.seen.clone(),
                },
                None => cause,
            },
        )
    });
    match checked {
        Ok(cause) => failed.report(cause),
        Err(e) => e,
    }
}

/// An `op item edit` of item `b` that did not finish (a timeout, a signal or a lost reply):
/// it may or may not have been applied, and re-running is safe (one atomic edit, built from
/// a fresh read).
pub(crate) fn unfinished_write(env: &Environment, b: &Boundary, call: &Call) -> Error {
    let subject = item_context(env, b, true)
        .resource
        .expect("an item context names its item");
    unfinished_edit(subject, call)
}

/// An edit of `subject` that did not finish: its outcome is unknown, re-running is safe.
pub(crate) fn unfinished_edit(subject: ResourceRef, call: &Call) -> Error {
    let failed = Failed::of(call);
    let seen = failed.seen.clone();
    failed.report(Cause::WriteOutcomeUnknown {
        system: System::OnePassword,
        subject,
        seen,
    })
}

/// `op vault get <vault_id>`: `Some(true)` when the vault is readable, `Some(false)` when
/// this identity cannot access it, `None` when the probe could not run. Exit status only;
/// its output names the vault and is dropped unread (SR-1).
fn vault_access(r: &dyn CommandRunner, vault_id: &str) -> Option<bool> {
    r.probe(
        &Call::new(OP, &["vault", "get", vault_id, "--format", "json"]),
        PROBE_TIMEOUT,
    )
    .ok()
    .map(|o| o.status == 0)
}

/// One boundary item's read (FR-13) with no field parsing: the tolerant reader
/// ([`super::onepassword_tidy`], FR-43) parses the raw JSON itself. `fields` is empty.
pub fn read_whole(r: &dyn CommandRunner, env: &Environment, b: &Boundary) -> Result<Item, Error> {
    read_whole_as(r, env, b, false)
}

/// `op`'s global flag that bypasses its local cache (op 2.x; `OP_CACHE=false` is the same
/// setting as an environment variable). `op` caches item reads by default on UNIX-like
/// systems, so a read that feeds a write must not be served from that cache, or the write
/// would put stale values over a newer edit (FR-43, FR-44). Accepted (and a no-op) on
/// Windows, where op documents the flag but keeps no cache.
pub const NO_CACHE: &str = "--cache=false";

/// 1Password's unnamed default section: where its apps put a field added outside any named
/// section. A field with no section at all is readable by `op` but shown by no 1Password
/// app, even in edit mode (found live: the empty `API_KEY` opv created could not be filled
/// in), so every field opv writes outside a named section goes here.
pub const DEFAULT_SECTION_ID: &str = "add more";

/// The `sections` entry and field `section` reference of [`DEFAULT_SECTION_ID`].
pub fn default_section() -> Value {
    json!({"id": DEFAULT_SECTION_ID})
}

/// [`read_whole`] straight from 1Password, bypassing `op`'s local cache ([`NO_CACHE`]):
/// every read a 1Password write is built from or checked against (the tidy, `item
/// skeleton`).
pub fn read_whole_fresh(
    r: &dyn CommandRunner,
    env: &Environment,
    b: &Boundary,
) -> Result<Item, Error> {
    read_whole_as(r, env, b, true)
}

fn read_whole_as(
    r: &dyn CommandRunner,
    env: &Environment,
    b: &Boundary,
    fresh: bool,
) -> Result<Item, Error> {
    let mut args = vec![
        "item",
        "get",
        b.item_id.as_str(),
        "--vault",
        b.vault_id.as_str(),
        "--format",
        "json",
    ];
    if fresh {
        args.push(NO_CACHE);
    }
    let raw = read_diagnosed(r, env, b, &args, &Host::detect)?;
    // 09.74, C20: a reply that is not an item opv can read (not JSON, or JSON of another
    // shape) is this call's `UnexpectedOutput`, reported while the runner still holds the
    // call's observation; the tolerant reader parses it later.
    super::onepassword_tidy::check(&raw).map_err(|e| unreadable_reply(&args, &e))?;
    Ok(Item {
        fields: Vec::new(),
        version: item_version(&raw),
        raw,
    })
}

/// Read a `deploy_credentials` item once (FR-40), by the IDs or names in `reference`, and
/// return exactly the conventional `fields`, keyed by label, as [`SecretValue`]s. Each must
/// appear once (in any section), with its kind's field type (concealed = secret, text =
/// config, FR-14) and a value; every other field is skipped unread. `owner` is the deploy
/// identity the item belongs to (its environment and target): a refusal names the item by
/// its full reference and steps to that target's doctor (R37, 06.30), never a value (SR-1).
pub fn read_deploy_credentials(
    r: &dyn CommandRunner,
    reference: &crate::domain::ItemRef,
    fields: &[crate::provider::CredentialField],
    owner: Option<&Principal>,
) -> Result<std::collections::BTreeMap<String, SecretValue>, Error> {
    read_deploy_credentials_on(r, reference, fields, owner, &Host::detect)
}

fn read_deploy_credentials_on(
    r: &dyn CommandRunner,
    reference: &crate::domain::ItemRef,
    fields: &[crate::provider::CredentialField],
    owner: Option<&Principal>,
    host: &dyn Fn() -> Host,
) -> Result<std::collections::BTreeMap<String, SecretValue>, Error> {
    let args = [
        "item",
        "get",
        reference.item.as_str(),
        "--vault",
        reference.vault.as_str(),
        "--format",
        "json",
    ];
    let (env, target) = match owner {
        Some(Principal::DeployCredentials { env, target, .. }) => {
            (Some(env.clone()), Some(target.clone()))
        }
        _ => (None, None),
    };
    // A failure is diagnosed at once, as for the environment's item: a signed-out user is
    // told to sign in without blind retries; signed in with the vault open, the read is
    // retried (with backoff) before it is reported. The configuration may live in a
    // manifest, so the item is named by its configuration field, never by a file (04.24).
    let ctx = DiagnoseContext {
        env: env.clone(),
        target: target.clone(),
        resource: Some(ResourceRef {
            kind: ResourceKind::Item,
            name: ResourceName::new(reference.item.as_str()),
            scope: Some(reference.vault.clone()),
        }),
        named_by: Some(NamedBy::ConfigField {
            path: DottedPath(vec!["deploy_credentials".to_string()]),
        }),
        ..DiagnoseContext::default()
    };
    let stdout = read_or_diagnose(r, &ctx, &reference.vault, &args, host)?;
    let raw: RawItem = serde_json::from_slice(&stdout).map_err(|e| unreadable_reply(&args, &e))?;
    // The item answered but cannot be used as these credentials (R37): taken while the
    // runner still holds the read, so the cause names that call.
    let refused = |problem: CredentialProblem| -> Error {
        match crate::runner::take_unusable_reply(&Call::new(OP, &args)) {
            Some(seen) => Cause::CredentialRejected {
                system: System::OnePassword,
                credential: CredentialRef::DeployCredentials {
                    vault: VaultId::new(reference.vault.as_str()),
                    item: ItemId::new(reference.item.as_str()),
                    env: env.clone().unwrap_or_else(|| EnvName::new("")),
                    target: target.clone().unwrap_or_else(|| TargetName::new("")),
                },
                problem,
                seen,
            }
            .into(),
            None => Cause::Bug {
                site: "deploy credentials: the item read left no observation",
            }
            .into(),
        }
    };
    let mut found: std::collections::BTreeMap<String, SecretValue> = Default::default();
    // A field of another type, or one listed twice, is not a value opv can take as this
    // credential: the refusal names that field and what is wrong with it.
    let mut unusable: Option<CredentialProblem> = None;
    for f in raw.fields {
        let Some(want) = fields.iter().find(|w| w.label == f.label) else {
            continue;
        };
        let (expected, words) = match want.kind {
            Kind::Secret => ("CONCEALED", FieldType::Concealed),
            Kind::Config => ("STRING", FieldType::Text),
        };
        if f.ty != expected {
            unusable.get_or_insert(CredentialProblem::WrongType {
                field: FieldName::new(want.label),
                expected: words,
            });
            continue;
        }
        // An empty field is a missing one: no value to sign in with.
        let Some(value) = f.value.map(|c| c.0).filter(|v| !v.expose().is_empty()) else {
            continue;
        };
        if found.insert(want.label.to_string(), value).is_some() {
            unusable.get_or_insert(CredentialProblem::DuplicateField {
                field: FieldName::new(want.label),
            });
        }
    }
    if let Some(problem) = unusable {
        return Err(refused(problem));
    }
    let missing: Vec<FieldName> = fields
        .iter()
        .filter(|w| !found.contains_key(w.label))
        .map(|w| FieldName::new(w.label))
        .collect();
    if !missing.is_empty() {
        return Err(refused(CredentialProblem::Incomplete {
            missing_fields: missing,
        }));
    }
    Ok(found)
}

/// Every non-zero exit status: the first item read is refused on any failure so that it
/// is diagnosed before it is retried (P16).
const ANY_FAILURE: [i32; 255] = {
    let mut codes = [0; 255];
    let mut i = 0;
    while i < 255 {
        codes[i] = i as i32 + 1;
        i += 1;
    }
    codes
};

/// The environment's one item read (FR-13), diagnosed before it is retried (P16).
fn read_diagnosed(
    r: &dyn CommandRunner,
    env: &Environment,
    b: &Boundary,
    args: &[&str],
    host: &dyn Fn() -> Host,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    read_or_diagnose(r, &item_context(env, b, false), &b.vault_id, args, host)
}

/// One item read in `vault`, diagnosed before it is retried (P16).
///
/// `op` exits 1 for "not signed in", "no access" and "not found" alike, so a failed first
/// attempt is diagnosed (design §5): the recorded phrases, then the free probes (`op
/// whoami`, then `op vault get <vault>`) instead of the runner's blind retries. Only a
/// signed-in identity that can open the vault (the failure may be transient) gets the
/// retry, with the runner's usual attempts and backoff (NR-3); every other outcome is
/// reported at once. A read that never finished is 1Password unavailable (NR-28, exit 9).
fn read_or_diagnose(
    r: &dyn CommandRunner,
    ctx: &DiagnoseContext,
    vault: &str,
    args: &[&str],
    host: &dyn Fn() -> Host,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let call = Call::new(OP, args);
    match r
        .read(&call, &ANY_FAILURE)
        .map_err(|e| op_spawn_error(r, &e, host))?
    {
        Outcome::Done(o) => {
            // Every item read registers its field values with the stderr scrubber (NR-31).
            crate::scrub::register_item_values(&o.stdout);
            return Ok(o.stdout);
        }
        Outcome::Refused(_) => {}
        Outcome::Unknown { .. } => return Err(unanswered(&call)),
    }
    let failed = Failed::of(&call);
    let cause = failed.diagnosed(ctx, &Facts::from_process_env());
    if !matches!(cause, Cause::Unrecognized { .. }) {
        return Err(failed.report(locate_owner(r, cause)));
    }
    // The probes explain the failed read; its reply stays with the error (NR-31). The
    // retry below is a new call and owns its own reply.
    let (cause, retry) =
        crate::runner::diagnosing(|| unsettled(r, host, ctx, Some(vault), &failed.seen, cause))?;
    if !retry {
        return Err(failed.report(locate_owner(r, cause)));
    }
    r.note(&format!(
        "{} failed; signed in with access to vault {vault}, so retrying",
        call.step()
    ));
    match read_op(r, args, host)? {
        Output { status: 0, stdout } => Ok(stdout),
        Output { .. } => {
            // NR-26: still failing in a vault that opens, unless its reply says otherwise.
            let again = Failed::of(&call);
            let cause = match again.diagnosed(ctx, &Facts::from_process_env()) {
                cause @ Cause::Unrecognized { .. } => missing_item(ctx, again.seen())
                    .unwrap_or_else(|| {
                        established(
                            cause,
                            format!("you are signed in to 1Password and vault {vault} opens"),
                        )
                    }),
                other => other,
            };
            Err(again.report(cause))
        }
    }
}

/// Add the `missing` (section label, field label, kind) entries to the item as empty fields
/// (FR-19). Sections are matched by label and created (id = label) when absent; every
/// existing section and field is sent back unchanged. Exactly one `op item edit` call, or
/// none when `missing` is empty. An entry that already exists in the item, or is listed
/// twice, is a `Source` error and nothing is written: skeleton never modifies a field.
/// Returns the version of the item as written, when the edit printed one (I5).
pub fn write_skeleton(
    r: &dyn CommandRunner,
    env: &Environment,
    b: &Boundary,
    item: &Item,
    missing: &[(String, String, Kind)],
) -> Result<Option<u64>, Error> {
    write_skeleton_on(r, env, b, item, missing, &Host::detect)
}

/// [`write_skeleton`] on a given host (tests). A failed edit is diagnosed like a failed
/// read (FR-26).
pub fn write_skeleton_with(
    r: &dyn CommandRunner,
    env: &Environment,
    b: &Boundary,
    item: &Item,
    missing: &[(String, String, Kind)],
    host: &Host,
) -> Result<Option<u64>, Error> {
    write_skeleton_on(r, env, b, item, missing, &|| *host)
}

fn write_skeleton_on(
    r: &dyn CommandRunner,
    env: &Environment,
    b: &Boundary,
    item: &Item,
    missing: &[(String, String, Kind)],
    host: &dyn Fn() -> Host,
) -> Result<Option<u64>, Error> {
    if missing.is_empty() {
        return Ok(None);
    }
    let mut doc = WipeOnDrop(serde_json::from_slice(&item.raw).map_err(|e| json_error(&e))?);
    add_missing(&mut doc.0, missing)?;
    let template = serialize_exact(&doc.0)?;
    drop(doc);

    let args = [
        "item",
        "edit",
        b.item_id.as_str(),
        "--vault",
        b.vault_id.as_str(),
        "--format",
        "json",
    ];
    // The edited item comes back on stdout (with values); only its version is read (I5),
    // then it is dropped and zeroized.
    // A write (NR-2): never retried. A non-zero exit is diagnosed (the item was just read,
    // so a refusal is the missing Write grant unless the session says otherwise); anything
    // else is an unknown outcome, which is safe to re-run because the skeleton only adds
    // what is still missing.
    let call = Call::new(OP, &args).with_stdin(Some(&template));
    match r.write(&call).map_err(|e| op_spawn_error(r, &e, host))? {
        Outcome::Done(o) => Ok(item_version(&o.stdout)),
        Outcome::Refused(_)
        | Outcome::Unknown {
            status: Some(_), ..
        } => Err(failed_write(r, env, b, host, &call)),
        Outcome::Unknown { .. } => Err(unfinished_write(env, b, &call)),
    }
}

/// The ` --account <id>` suffix for an `op` command when the environment knows its
/// account (I6); empty otherwise, so `op`'s own default is used.
pub(crate) fn account_suffix(account: Option<&str>) -> String {
    account.map_or_else(String::new, |a| format!(" --account {a}"))
}

/// `op` is not on PATH: the install line for this platform and shell.
pub fn op_missing(host: &Host) -> Error {
    Cause::ToolMissing {
        tool: OP.to_string(),
        platform: host.platform,
        shell: host.shell,
        ci: host.ci,
    }
    .into()
}

/// An `op` that could not be started (04.14): missing (with the install line), not
/// executable, or the Windows `op.exe` with WSL interop off, in words, never a Rust
/// `ErrorKind`. A call the spent run budget never let start is opv's own limit
/// (`BudgetSpent`, R52), never op's failure.
pub(crate) fn op_spawn_error(
    r: &dyn CommandRunner,
    e: &io::Error,
    host: &dyn Fn() -> Host,
) -> Error {
    let why = match e.kind() {
        io::ErrorKind::NotFound => return op_missing(&host()),
        io::ErrorKind::TimedOut => return crate::host::OP_CLI.budget_spent(r, e),
        io::ErrorKind::PermissionDenied => Unusable::NotExecutable,
        _ if host().op_is_windows_exe() => Unusable::WslInteropOff,
        _ => Unusable::SpawnFailed { io: IoKind::Other },
    };
    Cause::ToolUnusable {
        tool: OP.to_string(),
        why,
    }
    .into()
}

/// A read of `call` still unanswered after its retries (NR-28): 1Password unavailable,
/// nothing changed, safe to re-run.
pub(crate) fn unanswered(call: &Call) -> Error {
    let failed = Failed::of(call);
    let seen = failed.seen.clone();
    // D6: what the runner saw (a timeout, a kill, a lost reply), never "timed out" by default.
    let why = seen.exit().unanswered().unwrap_or(Unanswered::Lost);
    failed.report(Cause::Unavailable {
        system: System::OnePassword,
        why,
        attempts: crate::runner::READ_ATTEMPTS,
        seen,
    })
}

/// One `op` read (NR-3: retried by the runner). The returned output may carry a non-zero
/// status (still failing after the last attempt): callers diagnose it (FR-26). A read that
/// never finished after its retries is 1Password unavailable (NR-28, exit 9); nothing was
/// changed.
pub(crate) fn read_op(
    r: &dyn CommandRunner,
    args: &[&str],
    host: &dyn Fn() -> Host,
) -> Result<Output, Error> {
    let call = Call::new(OP, args);
    match r
        .read(&call, &[])
        .map_err(|e| op_spawn_error(r, &e, host))?
    {
        Outcome::Done(o) => {
            // Every item read in this run registers all its field values with the stderr
            // scrubber (NR-31), the selected sections' or not.
            if args.starts_with(&["item", "get"]) {
                crate::scrub::register_item_values(&o.stdout);
            }
            Ok(o)
        }
        Outcome::Refused(o) => Ok(o),
        Outcome::Unknown { .. } => Err(unanswered(&call)),
    }
}

/// The reply of `op <args>` (exit 0) is JSON opv cannot read (04.26, design §4.7): an
/// unexpected output, whose Do is to update op and whose Next is `opv doctor`, never a
/// re-run against the same op. Only the position is kept: serde_json's own message can
/// quote input (values). Taken right after the call, while the runner still holds it.
pub(crate) fn unreadable_reply(args: &[&str], e: &serde_json::Error) -> Error {
    let call = Call::new(OP, args);
    match crate::runner::take_unusable_reply(&call) {
        Some(seen) => Cause::UnexpectedOutput {
            system: System::OnePassword,
            at: Some(Location {
                line: u32::try_from(e.line()).unwrap_or(u32::MAX),
                col: u32::try_from(e.column()).unwrap_or(u32::MAX),
            }),
            problem: crate::cause::OutputProblem::Unparseable,
            during: crate::cause::During::Read,
            seen,
        }
        .into(),
        None => Cause::Bug {
            site: "onepassword: an unreadable op reply left no observation",
        }
        .into(),
    }
}

/// Item JSON opv already holds that it cannot read. Every item reply is checked when it is
/// read ([`read_whole`], [`super::onepassword_tidy::check`]), while the runner still holds
/// the call, so a later failure is opv's own (C20).
pub(crate) fn json_error(_: &serde_json::Error) -> Error {
    Cause::Bug {
        site: "onepassword: item JSON checked when read no longer parses",
    }
    .into()
}

/// The item's top-level `version` integer, when present. Every other field is skipped
/// unread (`IgnoredAny`), so no value is copied (SR-8).
pub(crate) fn item_version(json: &[u8]) -> Option<u64> {
    #[derive(Deserialize)]
    struct Versioned {
        #[serde(default)]
        version: Option<u64>,
    }
    serde_json::from_slice::<Versioned>(json).ok()?.version
}

#[derive(Deserialize)]
struct RawItem {
    #[serde(default)]
    fields: Vec<RawField>,
}

#[derive(Deserialize)]
struct RawField {
    #[serde(rename = "type", default)]
    ty: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    value: Option<Concealed>,
}

/// A JSON string deserialized directly into a [`SecretValue`].
struct Concealed(SecretValue);

impl<'de> Deserialize<'de> for Concealed {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = Concealed;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Concealed, E> {
                Ok(Concealed(SecretValue::new(v.to_owned())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Concealed, E> {
                Ok(Concealed(SecretValue::new(v)))
            }
        }
        d.deserialize_string(V)
    }
}

/// A JSON tree whose strings are zeroized when it is dropped.
pub(crate) struct WipeOnDrop(pub(crate) Value);

impl Drop for WipeOnDrop {
    fn drop(&mut self) {
        fn wipe(v: &mut Value) {
            match v {
                Value::String(s) => s.zeroize(),
                Value::Array(a) => a.iter_mut().for_each(wipe),
                Value::Object(m) => m.values_mut().for_each(wipe),
                _ => {}
            }
        }
        wipe(&mut self.0);
    }
}

// Field creation. `missing` never holds a shared key (FR-45, `from = ...`): callers
// filter them out (see `app::skeleton`), and any self-healing that creates fields must too.
//
// `doc` is an item read with [`read_whole`] (its shape checked then, C20), and `missing` the
// fields the tolerant reader found absent from that same item, each once: a field already
// there, one listed twice or an item of another shape is opv's own error, and nothing is
// written (FR-19: skeleton never modifies a field).
fn add_missing(doc: &mut Value, missing: &[(String, String, Kind)]) -> Result<(), Error> {
    let bug = |site: &'static str| Error::from(Cause::Bug { site });
    let obj = doc
        .as_object_mut()
        .ok_or_else(|| bug("skeleton: an item checked when read is not an object"))?;

    let str_at = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
    let mut sections: Vec<(String, String)> = Vec::new(); // (id, label)
    if let Some(a) = obj.get("sections").and_then(Value::as_array) {
        for s in a {
            if let (Some(id), Some(label)) = (str_at(s, "id"), str_at(s, "label")) {
                sections.push((id, label));
            }
        }
    }
    let mut field_ids = BTreeSet::new();
    let mut existing = BTreeSet::new();
    if let Some(a) = obj.get("fields").and_then(Value::as_array) {
        for f in a {
            if let Some(id) = str_at(f, "id") {
                field_ids.insert(id);
            }
            if let (Some(s), Some(l)) = (
                f.get("section").and_then(|s| str_at(s, "label")),
                str_at(f, "label"),
            ) {
                existing.insert((s, l));
            }
        }
    }

    let mut listed = BTreeSet::new();
    for (s, l, _) in missing {
        if existing.contains(&(s.clone(), l.clone())) {
            return Err(bug("skeleton: a field to add is already in the item"));
        }
        if !listed.insert((s.clone(), l.clone())) {
            return Err(bug("skeleton: a field to add is listed twice"));
        }
    }

    let mut new_sections = Vec::new();
    let mut new_fields = Vec::new();
    for (section, label, kind) in missing {
        let ty = match kind {
            Kind::Secret => "CONCEALED",
            Kind::Config => "STRING",
        };
        let section_id = match sections.iter().find(|(_, l)| l == section) {
            Some((id, _)) => id.clone(),
            None => {
                let id = unique(section.clone(), |c| sections.iter().any(|(i, _)| i == c));
                sections.push((id.clone(), section.clone()));
                new_sections.push(json!({"id": id, "label": section}));
                id
            }
        };
        let id = unique(format!("{section}_{}", label.to_lowercase()), |c| {
            field_ids.contains(c)
        });
        field_ids.insert(id.clone());
        new_fields.push(json!({
            "id": id,
            "section": {"id": section_id, "label": section},
            "type": ty,
            "label": label,
            "value": "",
        }));
    }

    for (key, add) in [("sections", new_sections), ("fields", new_fields)] {
        let arr = obj
            .entry(key)
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .ok_or_else(|| bug("skeleton: an item checked when read has a list of another type"))?;
        arr.extend(add);
    }
    Ok(())
}

/// `base`, or `base_2`, `base_3`, ... until `taken` is false.
fn unique(base: String, taken: impl Fn(&str) -> bool) -> String {
    if !taken(&base) {
        return base;
    }
    (2..)
        .map(|n| format!("{base}_{n}"))
        .find(|c| !taken(c))
        .expect("unbounded")
}

/// Serialize into a `Zeroizing` buffer allocated at the exact final size, so the buffer is
/// never reallocated (a realloc would leave an unzeroized copy of the values behind).
pub(crate) fn serialize_exact(v: &Value) -> Result<Zeroizing<Vec<u8>>, Error> {
    struct Count(usize);
    impl Write for Count {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0 += b.len();
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    // A `Value` always serializes, and neither writer can fail: an error is opv's own.
    let fail = |_| {
        Error::from(Cause::Bug {
            site: "onepassword: an item template does not serialize",
        })
    };
    let mut n = Count(0);
    serde_json::to_writer(&mut n, v).map_err(fail)?;
    let mut buf = Zeroizing::new(Vec::with_capacity(n.0));
    serde_json::to_writer(&mut *buf, v).map_err(fail)?;
    debug_assert_eq!(buf.len(), n.0);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use std::io;

    use serde_json::{Value, json};

    use super::*;
    use crate::host::FakeEnv;
    use crate::runner::Output;
    use crate::runner::fake::{FakeRunner, failed_read};

    const GET_ARGS: [&str; 7] = ["item", "get", "istg", "--vault", "vstg", "--format", "json"];
    const EDIT_ARGS: [&str; 7] = [
        "item", "edit", "istg", "--vault", "vstg", "--format", "json",
    ];

    fn linux() -> Host {
        Host::from_env(&FakeEnv::new("linux").shell("/bin/bash"))
    }

    fn wsl_windows_op() -> Host {
        Host::from_env(
            &FakeEnv::new("linux")
                .var("WSL_DISTRO_NAME")
                .op_windows_exe(),
        )
    }

    fn accounts(n: usize) -> Output {
        let one = r#"{"url":"my.1password.com","email":"a@example.com"}"#;
        Output::success(format!("[{}]", vec![one; n].join(",")))
    }

    fn argvs(r: &FakeRunner) -> Vec<String> {
        r.calls
            .borrow()
            .iter()
            .map(|c| format!("{} {}", c.program, c.args.join(" ")))
            .collect()
    }

    fn test_env() -> Environment {
        Environment {
            name: "staging".into(),
            ..Default::default()
        }
    }

    /// The boundary item the tests read (`vstg`/`istg`).
    fn test_at() -> Boundary {
        Boundary {
            vault_id: "vstg".into(),
            item_id: "istg".into(),
        }
    }

    /// A field inside a section, in the shape of tests/fixtures/op_item.json.
    fn sf(id: &str, sec_id: &str, sec_label: &str, ty: &str, label: &str, value: &str) -> Value {
        json!({
            "id": id,
            "section": {"id": sec_id, "label": sec_label},
            "type": ty,
            "label": label,
            "value": value,
            "reference": format!("op://vstg/istg/{sec_label}/{label}"),
        })
    }

    fn notes() -> Value {
        json!({
            "id": "notesPlain", "type": "STRING", "purpose": "NOTES", "label": "notesPlain",
            "reference": "op://vstg/istg/notesPlain"
        })
    }

    fn item_json(sections: Value, fields: Vec<Value>) -> Vec<u8> {
        serde_json::to_vec_pretty(&json!({
            "id": "istg",
            "title": "fleet",
            "version": 7,
            "vault": {"id": "vstg", "name": "fleet-staging"},
            "category": "SECURE_NOTE",
            "last_edited_by": "U123",
            "created_at": "2026-10-07T03:53:02Z",
            "updated_at": "2026-10-07T07:02:46Z",
            "sections": sections,
            "fields": fields,
        }))
        .unwrap()
    }

    fn allumata_item() -> Vec<u8> {
        item_json(
            json!([{"id": "allumata", "label": "allumata"}]),
            vec![
                notes(),
                sf(
                    "a1",
                    "allumata",
                    "allumata",
                    "CONCEALED",
                    "OPENAI_API_KEY",
                    "sk-FIXTURE-openai",
                ),
                sf(
                    "a2",
                    "allumata",
                    "allumata",
                    "STRING",
                    "SIGNUP_POLICY",
                    "invite_only",
                ),
            ],
        )
    }

    fn read(bytes: Vec<u8>) -> Item {
        let r = FakeRunner::new([Output::success(bytes)]);
        read_item_with(&r, &test_env(), &test_at(), &linux()).unwrap()
    }

    fn read_err(bytes: Vec<u8>) -> Error {
        let r = FakeRunner::new([Output::success(bytes)]);
        read_item_with(&r, &test_env(), &test_at(), &linux()).unwrap_err()
    }

    fn find<'a>(fields: &'a [ItemField], section: &str, label: &str) -> &'a ItemField {
        fields
            .iter()
            .find(|f| f.section == section && f.label == label)
            .unwrap_or_else(|| panic!("no field {section}/{label}"))
    }

    // ---------- read_item ----------

    #[test]
    fn reads_whole_item_once_by_id() {
        let r = FakeRunner::new([Output::success(allumata_item())]);
        let item = read_item_with(&r, &test_env(), &test_at(), &linux()).unwrap();
        let calls = r.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].program, "op");
        assert_eq!(calls[0].args, GET_ARGS);
        assert!(calls[0].stdin.is_none());
        let cfg = find(&item.fields, "allumata", "SIGNUP_POLICY");
        assert_eq!(
            (cfg.kind, cfg.value.expose()),
            (Kind::Config, "invite_only")
        );
        let sec = find(&item.fields, "allumata", "OPENAI_API_KEY");
        assert_eq!(
            (sec.kind, sec.value.expose()),
            (Kind::Secret, "sk-FIXTURE-openai")
        );
        assert_eq!(item.fields.len(), 2);
    }

    #[test]
    fn parses_real_d0_fixture_shape() {
        let item = read(include_bytes!("../../tests/fixtures/op_item.json").to_vec());
        assert_eq!(
            item.fields.len(),
            4,
            "notesPlain dropped, 4 sectioned fields"
        );
        for s in ["probe_a", "probe_b"] {
            let k = find(&item.fields, s, "API_KEY");
            assert_eq!((k.kind, k.value.expose()), (Kind::Secret, "<v>"));
            assert_eq!(find(&item.fields, s, "BASE_URL").kind, Kind::Config);
        }
    }

    /// FR-41: the item's `version` integer is kept for the plan id.
    #[test]
    fn item_read_keeps_the_item_version() {
        assert_eq!(read(allumata_item()).version, Some(7));
    }

    #[test]
    fn fields_outside_sections_are_ignored() {
        let mut n = notes();
        n["value"] = json!("NOTE-MARKER-not-a-key");
        let item = read(item_json(
            json!([{"id": "allumata", "label": "allumata"}]),
            vec![
                n,
                // No section and a type we would otherwise reject: still ignored, not an error.
                json!({"id": "otp", "type": "OTP", "label": "one_time", "value": "otpauth://x"}),
                json!({"id": "pw", "type": "CONCEALED", "purpose": "PASSWORD", "label": "password", "value": "pw-FIXTURE"}),
                sf(
                    "a1",
                    "allumata",
                    "allumata",
                    "CONCEALED",
                    "OPENAI_API_KEY",
                    "sk-FIXTURE-openai",
                ),
            ],
        ));
        let labels: Vec<(&str, &str)> = item
            .fields
            .iter()
            .map(|f| (f.section.as_str(), f.label.as_str()))
            .collect();
        assert_eq!(labels, [("allumata", "OPENAI_API_KEY")]);
    }

    #[test]
    fn missing_value_is_empty_not_an_error() {
        let mut f = sf(
            "a1",
            "allumata",
            "allumata",
            "CONCEALED",
            "OPENAI_API_KEY",
            "",
        );
        f.as_object_mut().unwrap().remove("value");
        let item = read(item_json(
            json!([{"id": "allumata", "label": "allumata"}]),
            vec![f],
        ));
        assert_eq!(item.fields[0].value.expose(), "");
    }

    #[test]
    fn matches_section_by_label_not_id() {
        let item = read(item_json(
            json!([{"id": "x7f3kq", "label": "allumata"}]),
            vec![sf(
                "rnd1",
                "x7f3kq",
                "allumata",
                "STRING",
                "SIGNUP_POLICY",
                "open",
            )],
        ));
        find(&item.fields, "allumata", "SIGNUP_POLICY");
    }

    #[test]
    fn unsupported_type_in_section_is_source_error_naming_field() {
        let e = read_err(item_json(
            json!([{"id": "allumata", "label": "allumata"}]),
            vec![sf(
                "a1",
                "allumata",
                "allumata",
                "URL",
                "BASE_URL",
                "https://VALUE-MARKER",
            )],
        ));
        assert_eq!(
            e.to_string(),
            strict_refusal("a field has a type opv does not read").to_string()
        );
    }

    #[test]
    fn duplicate_section_and_label_is_source_error() {
        let e = read_err(item_json(
            json!([{"id": "s1", "label": "allumata"}, {"id": "s2", "label": "allumata"}]),
            vec![
                sf(
                    "a1",
                    "s1",
                    "allumata",
                    "CONCEALED",
                    "OPENAI_API_KEY",
                    "sk-FIXTURE-old",
                ),
                sf(
                    "a2",
                    "s2",
                    "allumata",
                    "CONCEALED",
                    "OPENAI_API_KEY",
                    "sk-FIXTURE-new",
                ),
            ],
        ));
        assert_eq!(
            e.to_string(),
            strict_refusal("two fields have the same section and label").to_string()
        );
    }

    const WHOAMI_SA: &str = r#"{"url":"https://my.1password.com","email":"ci-OPHINTMARKER@example.com","user_uuid":"UOPHINTMARKER","account_uuid":"AOPHINTMARKER","user_type":"SERVICE_ACCOUNT"}"#;

    /// NR-26: signed in, the vault opens, and every read of the item fails: the item is
    /// not there (item_not_found, exit 4), never "to see why".
    #[test]
    fn non_zero_exit_while_signed_in_is_item_not_found() {
        let r = signed_in_vault_ok_item_missing();
        let e = read_item_with(&r, &test_env(), &test_at(), &linux()).unwrap_err();
        assert_eq!(e.code_str(), "item_not_found");
    }

    /// SR-1: whoami's identity (email, IDs) never reaches the error.
    #[test]
    fn a_signed_in_failure_never_names_the_identity() {
        let r = signed_in_vault_ok_item_missing();
        let e = read_item_with(&r, &test_env(), &test_at(), &linux()).unwrap_err();
        let t = format!("{e} {e:?}");
        assert!(
            !t.contains("example.com") && !t.contains("OPHINTMARKER"),
            "{t}"
        );
    }

    fn vault_ok() -> Output {
        Output::success(br#"{"id":"vstg","name":"OPHINTMARKER"}"#.to_vec())
    }

    /// The first read fails, whoami and the vault probe pass, every retry fails too.
    fn signed_in_vault_ok_item_missing() -> FakeRunner {
        FakeRunner::new(
            std::iter::once(Output::failure(1))
                .chain([Output::success(WHOAMI_SA), vault_ok()])
                .chain(failed_read(1)),
        )
    }

    fn item_reads(r: &FakeRunner) -> usize {
        argvs(r).iter().filter(|a| a.starts_with("op item")).count()
    }

    /// P16: a failed first read is diagnosed before any retry.
    #[test]
    fn failed_read_is_diagnosed_before_it_is_retried() {
        let r = signed_in_vault_ok_item_missing();
        let _ = read_item_with(&r, &test_env(), &test_at(), &linux());
        assert_eq!(
            argvs(&r)[..4],
            [
                "op item get istg --vault vstg --format json",
                "op whoami --format json",
                "op vault get vstg --format json",
                "op item get istg --vault vstg --format json",
            ]
        );
    }

    /// NR-31: the diagnosis probes after a failed first read keep that read's reply, which
    /// is the error's evidence.
    #[test]
    fn diagnosed_first_read_keeps_its_stderr_excerpt() {
        let r = FakeRunner::default();
        r.push_with_stderr(
            Output::failure(1),
            "[ERROR] item istg isn't in vault vstg\n",
        );
        r.push_with_stderr(Output::failure(1), "[ERROR] not signed in\n");
        r.push_with_stderr(accounts(1), "");
        let e = read_item_with(&r, &test_env(), &test_at(), &linux()).unwrap_err();
        assert_eq!(
            e.cause().and_then(|(_, up)| up).map(|u| u.said.clone()),
            Some(vec!["[ERROR] item istg isn't in vault vstg".to_string()])
        );
    }

    /// NR-31: a first read that succeeds registers its values with the stderr scrubber.
    #[test]
    fn first_read_registers_its_values_with_the_scrubber() {
        let raw = br#"{"fields":[{"label":"K","value":"FirstReadMarker7Qz"}]}"#.to_vec();
        let r = FakeRunner::new([Output::success(raw)]);
        let _ = read_item_with(&r, &test_env(), &test_at(), &linux());
        assert!(!crate::scrub::scrub("x FirstReadMarker7Qz").contains("FirstReadMarker7Qz"));
    }

    /// P16: signed in with vault access, the failure may be transient: a retry succeeds.
    #[test]
    fn signed_in_with_vault_access_retries_and_reads_the_item() {
        let item_json = serde_json::to_vec(&json!({"fields": []})).unwrap();
        let r = FakeRunner::new([
            Output::failure(1),
            Output::success(WHOAMI_SA),
            vault_ok(),
            Output::success(item_json),
        ]);
        assert!(read_item_with(&r, &test_env(), &test_at(), &linux()).is_ok());
    }

    /// S2: signed in with vault access, op said the item does not exist: reported at once
    /// as missing, without a retry.
    #[test]
    fn item_op_says_does_not_exist_is_not_retried() {
        let r = FakeRunner::default();
        r.push_with_stderr(
            Output::failure(1),
            "[ERROR] \"istg\" isn't an item in the \"vstg\" vault.\n",
        );
        r.push_with_stderr(Output::success(WHOAMI_SA), "");
        r.push_with_stderr(vault_ok(), "");
        let _ = read_item_with(&r, &test_env(), &test_at(), &linux());
        assert_eq!(item_reads(&r), 1, "{:?}", argvs(&r));
    }

    /// S2: op's recorded "isn't an item" reply is the missing item, named by its IDs.
    #[test]
    fn item_op_says_does_not_exist_is_named() {
        let r = FakeRunner::default();
        r.push_with_stderr(
            Output::failure(1),
            "[ERROR] \"istg\" isn't an item in the \"vstg\" vault.\n",
        );
        let e = read_item_with(&r, &test_env(), &test_at(), &linux()).unwrap_err();
        assert_eq!(
            e.to_string(),
            "item istg in vstg was not found at 1Password"
        );
    }

    /// P16: not signed in is reported at once, without retrying the read.
    #[test]
    fn not_signed_in_is_reported_without_a_retry() {
        let r = FakeRunner::new([Output::failure(1), Output::failure(1), accounts(1)]);
        let _ = read_item_with(&r, &test_env(), &test_at(), &linux());
        assert_eq!(item_reads(&r), 1, "{:?}", argvs(&r));
    }

    /// P16: a vault this identity cannot open is reported at once, without retrying.
    #[test]
    fn vault_without_access_is_reported_without_a_retry() {
        let r = FakeRunner::new([
            Output::failure(1),
            Output::success(WHOAMI_SA),
            Output::failure(1),
        ]);
        let _ = read_item_with(&r, &test_env(), &test_at(), &linux());
        assert_eq!(item_reads(&r), 1, "{:?}", argvs(&r));
    }

    /// NR-26: signed in, the item read fails and the vault is readable: the step checks
    /// the configuration field that names the item (opv config edit), never a file.
    #[test]
    fn item_missing_from_readable_vault_is_named() {
        let r = signed_in_vault_ok_item_missing();
        let e = read_item_with(&r, &test_env(), &test_at(), &linux()).unwrap_err();
        let action = e.do_text();
        assert!(
            action
                .as_deref()
                .is_some_and(|a| a.contains("opv config edit")),
            "{action:?}"
        );
    }

    fn vault_refused() -> FakeRunner {
        FakeRunner::new([
            Output::failure(1),
            Output::success(WHOAMI_SA),
            Output::failure(1),
        ])
    }

    /// [`vault_refused`], then `op account list` fails, so the other accounts cannot be
    /// searched for the vault (#153a).
    fn vault_refused_accounts_unlisted() -> FakeRunner {
        FakeRunner::new([
            Output::failure(1),
            Output::success(WHOAMI_SA),
            Output::failure(1),
            Output::failure(1),
        ])
    }

    fn env_in_account() -> Environment {
        Environment {
            account: Some("AENV00000000000000000000AA".into()),
            ..test_env()
        }
    }

    /// 04.06: signed in to the environment's account, the item read fails and so does `op
    /// vault get`: the vault is not in that account (or not shared), never "grant access".
    #[test]
    fn op_vault_without_access_is_in_another_account() {
        let e = read_item_with(
            &vault_refused_accounts_unlisted(),
            &env_in_account(),
            &test_at(),
            &linux(),
        )
        .unwrap_err();
        assert_eq!(e.code_str(), "ids_not_in_account");
    }

    /// 04.06: its step is the command that finds the vault's account, never a raw probe.
    #[test]
    fn op_vault_without_access_steps_to_vault_locate() {
        let e = read_item_with(
            &vault_refused_accounts_unlisted(),
            &env_in_account(),
            &test_at(),
            &linux(),
        )
        .unwrap_err();
        assert_eq!(e.next_text().unwrap_or_default(), "opv vault locate vstg");
    }

    /// In op's default account, a vault that does not open is the missing Read grant.
    #[test]
    fn op_vault_without_access_in_the_default_account_is_vault_no_access() {
        let e = read_item_with(&vault_refused(), &test_env(), &test_at(), &linux()).unwrap_err();
        assert_eq!(e.code_str(), "vault_no_access");
    }

    /// NR-26: the vault probe's output names the vault; it is never echoed (SR-1).
    #[test]
    fn vault_probe_output_is_never_echoed() {
        let r = signed_in_vault_ok_item_missing();
        let e = read_item_with(&r, &test_env(), &test_at(), &linux()).unwrap_err();
        assert!(!format!("{e} {e:?}").contains("OPHINTMARKER"), "{e}");
    }

    /// FR-26: whoami fails → not signed in (exit 7), whatever credential variables are
    /// set (the motivating bug: an expired OP_SESSION_*).
    #[test]
    fn non_zero_exit_not_signed_in_is_op_not_signed_in() {
        let r = FakeRunner::new([Output::failure(1), Output::failure(1), accounts(1)]);
        let e = read_item_with(&r, &test_env(), &test_at(), &linux()).unwrap_err();
        assert_eq!(e.code_str(), "op_not_signed_in");
    }

    /// FR-13: diagnosis never reads the item itself; the retries after it (P16, NR-3)
    /// are attempts of the same read: at most one first attempt plus READ_ATTEMPTS.
    #[test]
    fn diagnosis_makes_no_extra_item_read() {
        let r = signed_in_vault_ok_item_missing();
        let _ = read_item_with(&r, &test_env(), &test_at(), &linux());
        assert_eq!(
            item_reads(&r),
            1 + crate::runner::READ_ATTEMPTS as usize,
            "{:?}",
            argvs(&r)
        );
    }

    /// X13: when whoami itself cannot run, the failure is unrecognised and says so.
    #[test]
    fn an_undiagnosed_session_is_unrecognized() {
        let r = FakeRunner::new([Output::failure(1)]);
        r.push_unknown("timeout");
        let e = read_item_with(&r, &test_env(), &test_at(), &linux()).unwrap_err();
        assert_eq!(e.code_str(), "unrecognized_failure");
    }

    /// I6: the failed call is evidence, never a hand-run `op` command without the
    /// environment's account.
    #[test]
    fn an_undiagnosed_failure_names_no_raw_op_command() {
        let r = FakeRunner::new([Output::failure(1)]);
        r.push_unknown("timeout");
        let env = Environment {
            account: Some("AENV00000000000000000000AA".into()),
            ..test_env()
        };
        let e = read_item_with(&r, &env, &test_at(), &linux()).unwrap_err();
        assert!(!e.next_text().unwrap_or_default().starts_with("op "), "{e}");
    }

    /// I6: the missing item's step lists the vault's items with op, by vault ID.
    #[test]
    fn a_missing_item_steps_to_the_vaults_listing() {
        let r = signed_in_vault_ok_item_missing();
        let env = Environment {
            account: Some("AENV00000000000000000000AA".into()),
            ..test_env()
        };
        let e = read_item_with(&r, &env, &test_at(), &linux()).unwrap_err();
        assert_eq!(
            e.next_text().unwrap_or_default(),
            "op item list --vault vstg"
        );
    }

    /// I7: with no account on the machine, the read error is the account to add.
    #[test]
    fn a_no_account_read_error_is_account_not_registered() {
        let r = FakeRunner::new([Output::failure(1), Output::failure(1), accounts(0)]);
        let e = read_item_with(&r, &test_env(), &test_at(), &linux()).unwrap_err();
        assert_eq!(e.code_str(), "account_not_registered");
    }

    /// E2 (X13): a read that keeps ending with an exit other than op's own failure (124
    /// from a hung op, 127 from a missing one) is never reported as a missing item.
    #[test]
    fn a_read_that_keeps_hanging_is_not_a_missing_item() {
        let r = FakeRunner::new(
            std::iter::once(Output::failure(124))
                .chain([Output::success(WHOAMI_SA), vault_ok()])
                .chain(failed_read(124)),
        );
        let e = read_item_with(&r, &test_env(), &test_at(), &linux()).unwrap_err();
        assert_ne!(e.code_str(), "item_not_found");
    }

    /// In WSL with the Windows `op.exe`, a signed-out session is the locked app.
    #[test]
    fn wsl_windows_op_signed_out_names_the_app() {
        let e = session_error(Session::NotSignedIn, &wsl_windows_op(), None, Some("dev")).unwrap();
        assert!(e.to_string().contains("1Password app is locked"), "{e}");
    }

    /// In WSL with the Windows `op.exe`, the fix is never op's own add/sign-in prompt.
    #[test]
    fn wsl_windows_op_signed_out_never_offers_opv_login_add() {
        let e = session_error(Session::NotSignedIn, &wsl_windows_op(), None, Some("dev")).unwrap();
        assert!(!e.mentions("opv login --add"), "{e}");
    }

    /// 04.07: with no account and the Windows `op.exe`, the account is added in the app.
    #[test]
    fn wsl_windows_op_no_account_names_the_app() {
        let e = session_error(Session::NoAccount, &wsl_windows_op(), None, Some("dev")).unwrap();
        assert!(
            e.to_string().contains("1Password app on this machine"),
            "{e}"
        );
    }

    /// With no account and the Windows `op.exe`, opv never steps to its own add command.
    #[test]
    fn wsl_windows_op_no_account_never_offers_opv_login_add() {
        let e = session_error(Session::NoAccount, &wsl_windows_op(), None, Some("dev")).unwrap();
        assert_ne!(e.next_text().as_deref(), Some("opv login --add"));
    }

    /// I6: child stdout (which can carry values, and whoami's identity) never reaches the
    /// message, for read and edit, signed in or not.
    #[test]
    fn failure_message_is_value_free() {
        const MARK: &str = "OPHINTMARKER";
        let leaky = || Output {
            status: 1,
            stdout: Zeroizing::new(format!("{{\"value\":\"{MARK}\"}}").into_bytes()),
        };
        let sessions = || {
            [
                vec![Output::success(WHOAMI_SA), leaky()],
                vec![leaky(), accounts(1)],
                vec![leaky(), accounts(0)],
            ]
        };
        for s in sessions() {
            let r = FakeRunner::new(std::iter::once(leaky()).chain(s));
            let e = read_item_with(&r, &test_env(), &test_at(), &linux()).unwrap_err();
            let t = format!("{e} {e:?}");
            assert!(!t.contains(MARK) && !t.contains("--reveal"), "{t}");
            assert!(
                !t.contains("example.com") && !t.contains("to see why"),
                "{t}"
            );
        }
        let item_json = serde_json::to_vec(&json!({"fields": []})).unwrap();
        for s in sessions() {
            let r = FakeRunner::new([Output::success(item_json.clone()), leaky()]);
            r.responses.borrow_mut().extend(s.into_iter().map(Ok));
            let item = read_item_with(&r, &test_env(), &test_at(), &linux()).unwrap();
            let e = write_skeleton_with(
                &r,
                &test_env(),
                &test_at(),
                &item,
                &[("p".into(), format!("{MARK}K"), Kind::Secret)],
                &linux(),
            )
            .unwrap_err();
            let t = format!("{e} {e:?}");
            assert!(!t.contains(MARK) && !t.contains("example.com"), "{t}");
        }
    }

    /// Found live: a person's read that waits on the 1Password app's approval prompt
    /// times out like an outage. op's diagnosis reports the outage it observed (X13: never
    /// the likeliest guess); naming the app prompt is op's diagnosis to add (R29).
    #[test]
    fn read_outage_for_a_person_is_the_observed_outage() {
        let r = FakeRunner::default();
        r.push_unknowns("timeout", crate::runner::READ_ATTEMPTS);
        let e = crate::host::with_test_host(linux(), || {
            read_item_with(&r, &test_env(), &test_at(), &linux()).unwrap_err()
        });
        assert_eq!(e.code_str(), "provider_unavailable");
    }

    #[test]
    fn read_outage_exits_9() {
        let r = FakeRunner::default();
        r.push_unknowns("timeout", crate::runner::READ_ATTEMPTS);
        let ci = Host::from_env(&FakeEnv::new("linux").var("CI"));
        let e = crate::host::with_test_host(ci, || {
            read_item_with(&r, &test_env(), &test_at(), &ci).unwrap_err()
        });
        // R51: op's diagnosis of the unanswered read; its Do names the status page.
        assert_eq!((e.exit_code(), e.code_str()), (9, "provider_unavailable"));
    }

    /// FR-26: a successful read never detects the host; a failed one does.
    #[test]
    fn host_is_detected_only_on_failure() {
        let item_json = serde_json::to_vec(&json!({"fields": []})).unwrap();
        let called = std::cell::Cell::new(0);
        let host = || {
            called.set(called.get() + 1);
            linux()
        };
        let r = FakeRunner::new([Output::success(item_json)]);
        read_item_on(&r, &test_env(), &test_at(), &host).unwrap();
        assert_eq!(called.get(), 0);
        let r = FakeRunner::new([Output::failure(1), Output::failure(1), accounts(1)]);
        let _ = read_item_on(&r, &test_env(), &test_at(), &host);
        assert!(called.get() > 0);
    }

    /// FR-26: whoami is a probe with its own 15 s limit; a timeout is Unknown and falls
    /// back to the re-run hint.
    #[test]
    fn whoami_timeout_is_unknown() {
        let r = FakeRunner::new([]);
        r.push_io_error(io::ErrorKind::TimedOut);
        assert_eq!(diagnose(&r, &linux).unwrap(), Session::Unknown);
    }

    /// Only `user_type` is used; identity fields are never kept.
    #[test]
    fn identity_type_parses_user_type_only() {
        assert_eq!(
            identity_type(WHOAMI_SA.as_bytes()),
            IdentityType::ServiceAccount
        );
        assert_eq!(
            identity_type(br#"{"email":"a@b.c","user_type":"HUMAN"}"#),
            IdentityType::User
        );
        assert_eq!(
            identity_type(br#"{"user_type":"x@y"}"#),
            IdentityType::Unknown
        );
        assert_eq!(identity_type(b"not json"), IdentityType::Unknown);
        assert_eq!(identity_type(b"{}"), IdentityType::Unknown);
    }

    /// With the 1Password app integration, `op whoami` names the user but has no
    /// `user_type` (recorded live, op 2.40.0): that is a person.
    #[test]
    fn app_integration_whoami_is_a_person() {
        assert_eq!(
            identity_type(
                br#"{"url":"https://x.1password.com/","email":"a@b.c","user_uuid":"UX","account_uuid":"AX"}"#
            ),
            IdentityType::User
        );
    }

    #[test]
    fn account_count_cases() {
        assert_eq!(account_count(b""), Some(0));
        assert_eq!(account_count(b"[]\n"), Some(0));
        assert_eq!(
            account_count(br#"[{"url":"my.1password.com","email":"a@b.c"}]"#),
            Some(1)
        );
        assert_eq!(account_count(b"oops"), None);
    }

    /// CI, a service account token or Connect: no `op account list` (it cannot help).
    #[test]
    fn diagnose_skips_account_list_under_ci_or_token() {
        for env in [
            FakeEnv::new("linux").var("CI"),
            FakeEnv::new("linux").var("OP_SERVICE_ACCOUNT_TOKEN"),
            FakeEnv::new("linux").var("OP_CONNECT_HOST"),
        ] {
            let r = FakeRunner::new(failed_read(1));
            let h = Host::from_env(&env);
            diagnose(&r, &|| h).unwrap();
            assert_eq!(argvs(&r), vec!["op whoami --format json"], "{env:?}");
        }
    }

    #[test]
    fn missing_op_binary_is_dependency_missing() {
        let r = FakeRunner::default();
        r.push_io_error(io::ErrorKind::NotFound);
        let e = read_item_with(&r, &test_env(), &test_at(), &linux()).unwrap_err();
        assert_eq!(e.code_str(), "dependency_missing");
    }

    /// 04.14: an op that cannot be executed is named in words, never as a Rust ErrorKind.
    #[test]
    fn op_permission_denied_is_tool_unusable() {
        let r = FakeRunner::default();
        r.push_io_error(io::ErrorKind::PermissionDenied);
        let e = read_item_with(&r, &test_env(), &test_at(), &linux()).unwrap_err();
        assert_eq!(e.to_string(), "op is not executable");
    }

    #[test]
    fn malformed_json_error_never_echoes_content() {
        // A non-string value makes serde_json's own message quote it; ours must not.
        let mut f = sf("a1", "allumata", "allumata", "CONCEALED", "K", "");
        f["value"] = json!(987654321123u64);
        for bytes in [
            item_json(json!([{"id": "allumata", "label": "allumata"}]), vec![f]),
            b"{\"fields\": [ sk-FIXTURE-garbage".to_vec(),
        ] {
            let e = read_err(bytes);
            let s = format!("{e} {e:?}");
            assert_eq!(e.code_str(), "unexpected_output", "{s}");
            assert!(
                !s.contains("987654321123") && !s.contains("sk-FIXTURE"),
                "{s}"
            );
        }
    }

    #[test]
    fn debug_never_prints_values_or_raw_json() {
        let item = read(allumata_item());
        let d = format!("{item:?} {item:#?}");
        assert!(
            !d.contains("sk-FIXTURE") && !d.contains("invite_only"),
            "{d}"
        );
        assert!(!d.contains("op://"), "raw JSON leaked: {d}");
        assert!(d.contains("OPENAI_API_KEY"), "names are fine: {d}");
    }

    // ---------- write_skeleton ----------

    fn edit_stdin(r: &FakeRunner) -> Value {
        let calls = r.calls.borrow();
        assert_eq!(calls.len(), 1, "skeleton write is exactly one call");
        assert_eq!(calls[0].program, "op");
        assert_eq!(calls[0].args, EDIT_ARGS);
        serde_json::from_slice(calls[0].stdin.as_ref().expect("template on stdin")).unwrap()
    }

    fn tpl_field<'a>(tpl: &'a Value, section: &str, label: &str) -> &'a Value {
        tpl["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["label"] == label && f["section"]["label"] == section)
            .unwrap_or_else(|| panic!("no template field {section}/{label}"))
    }

    #[test]
    fn skeleton_sends_full_item_on_stdin_with_empty_values() {
        let original: Value = serde_json::from_slice(&allumata_item()).unwrap();
        let item = read(allumata_item());
        let r = FakeRunner::new([Output::success(allumata_item())]);
        write_skeleton(
            &r,
            &test_env(),
            &test_at(),
            &item,
            &[
                ("allumata".into(), "STRIPE_SECRET_KEY".into(), Kind::Secret),
                ("signoz".into(), "OTEL_ENDPOINT".into(), Kind::Config),
            ],
        )
        .unwrap();
        assert!(!r.argv_contains("sk-FIXTURE") && !r.argv_contains("invite_only"));
        let tpl = edit_stdin(&r);

        // Every existing top-level key and every existing field survives unchanged.
        for (k, v) in original.as_object().unwrap() {
            if k != "fields" && k != "sections" {
                assert_eq!(&tpl[k], v, "top-level {k} changed");
            }
        }
        let fields = tpl["fields"].as_array().unwrap();
        for f in original["fields"].as_array().unwrap() {
            assert!(
                fields.contains(f),
                "existing field changed or dropped: {}",
                f["id"]
            );
        }
        assert_eq!(
            tpl_field(&tpl, "allumata", "OPENAI_API_KEY")["value"],
            "sk-FIXTURE-openai"
        );
        assert_eq!(fields.len(), 5);

        let s = tpl_field(&tpl, "allumata", "STRIPE_SECRET_KEY");
        assert_eq!((&s["type"], &s["value"]), (&json!("CONCEALED"), &json!("")));
        assert_eq!(s["section"]["id"], "allumata");
        let c = tpl_field(&tpl, "signoz", "OTEL_ENDPOINT");
        assert_eq!((&c["type"], &c["value"]), (&json!("STRING"), &json!("")));

        // The new section is created by label; the existing one is kept, not duplicated.
        let sections = tpl["sections"].as_array().unwrap();
        assert_eq!(
            sections
                .iter()
                .map(|s| s["label"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["allumata", "signoz"]
        );
        let sz = sections.iter().find(|s| s["label"] == "signoz").unwrap();
        assert_eq!(c["section"]["id"], sz["id"]);

        // Field ids are unique.
        let mut ids: Vec<&str> = fields.iter().map(|f| f["id"].as_str().unwrap()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), fields.len());
    }

    #[test]
    fn skeleton_reuses_existing_section_id_from_the_ui() {
        let bytes = item_json(
            json!([{"id": "x7f3kq", "label": "allumata"}]),
            vec![sf(
                "rnd1",
                "x7f3kq",
                "allumata",
                "STRING",
                "SIGNUP_POLICY",
                "open",
            )],
        );
        let item = read(bytes);
        let r = FakeRunner::new([Output::success("{}")]);
        let missing = [(
            "allumata".to_string(),
            "OPENAI_API_KEY".to_string(),
            Kind::Secret,
        )];
        write_skeleton(&r, &test_env(), &test_at(), &item, &missing).unwrap();
        let tpl = edit_stdin(&r);
        assert_eq!(tpl["sections"].as_array().unwrap().len(), 1);
        assert_eq!(
            tpl_field(&tpl, "allumata", "OPENAI_API_KEY")["section"]["id"],
            "x7f3kq"
        );
    }

    #[test]
    fn skeleton_field_ids_avoid_existing_ids() {
        let bytes = item_json(
            json!([{"id": "allumata", "label": "allumata"}]),
            vec![sf(
                "allumata_openai_api_key",
                "allumata",
                "allumata",
                "STRING",
                "OTHER",
                "x",
            )],
        );
        let item = read(bytes);
        let r = FakeRunner::new([Output::success("{}")]);
        let missing = [(
            "allumata".to_string(),
            "OPENAI_API_KEY".to_string(),
            Kind::Secret,
        )];
        write_skeleton(&r, &test_env(), &test_at(), &item, &missing).unwrap();
        let tpl = edit_stdin(&r);
        let id = tpl_field(&tpl, "allumata", "OPENAI_API_KEY")["id"]
            .as_str()
            .unwrap()
            .to_string();
        assert_ne!(id, "allumata_openai_api_key");
    }

    #[test]
    fn skeleton_with_nothing_missing_makes_no_call() {
        let item = read(allumata_item());
        let r = FakeRunner::default();
        write_skeleton(&r, &test_env(), &test_at(), &item, &[]).unwrap();
        assert!(r.calls.borrow().is_empty());
    }

    #[test]
    fn skeleton_refuses_to_touch_an_existing_field() {
        let item = read(allumata_item());
        let r = FakeRunner::default();
        let missing = [(
            "allumata".to_string(),
            "SIGNUP_POLICY".to_string(),
            Kind::Secret,
        )];
        // The tolerant reader never lists a field that is there: a caller that does is opv's
        // own bug, and nothing is written.
        let _ = write_skeleton(&r, &test_env(), &test_at(), &item, &missing);
        assert!(r.calls.borrow().is_empty());
    }

    #[test]
    fn skeleton_uses_raw_json_so_fields_can_be_moved_out_first() {
        let mut item = read(allumata_item());
        let fields = std::mem::take(&mut item.fields);
        assert_eq!(fields.len(), 2);
        let r = FakeRunner::new([Output::success("{}")]);
        let missing = [("allumata".to_string(), "NEW_KEY".to_string(), Kind::Config)];
        write_skeleton(&r, &test_env(), &test_at(), &item, &missing).unwrap();
        let tpl = edit_stdin(&r);
        assert_eq!(
            tpl_field(&tpl, "allumata", "OPENAI_API_KEY")["value"],
            "sk-FIXTURE-openai"
        );
    }

    /// 04.01: an edit refused right after the item was read is the missing Write grant.
    #[test]
    fn skeleton_edit_failure_while_signed_in_is_the_missing_write_grant() {
        let item = read(allumata_item());
        let r = FakeRunner::new([Output::failure(2), Output::success(WHOAMI_SA)]);
        let missing = [("allumata".to_string(), "NEW_KEY".to_string(), Kind::Config)];
        let e = write_skeleton_with(&r, &test_env(), &test_at(), &item, &missing, &linux())
            .unwrap_err();
        assert_eq!(e.code_str(), "vault_no_access");
    }

    #[test]
    fn skeleton_edit_failure_not_signed_in_is_op_not_signed_in() {
        let item = read(allumata_item());
        let r = FakeRunner::new([Output::failure(2), Output::failure(1), accounts(1)]);
        let missing = [("allumata".to_string(), "NEW_KEY".to_string(), Kind::Config)];
        let e = write_skeleton_with(&r, &test_env(), &test_at(), &item, &missing, &linux())
            .unwrap_err();
        assert_eq!(e.code_str(), "op_not_signed_in");
    }

    /// NR-2: an edit that timed out may or may not have happened: exit 9, safe to re-run.
    #[test]
    fn skeleton_edit_timeout_is_unknown_exit_9() {
        let item = read(allumata_item());
        let r = FakeRunner::default();
        r.push_unknown("timeout");
        let missing = [("allumata".to_string(), "NEW_KEY".to_string(), Kind::Config)];
        let e = write_skeleton_with(&r, &test_env(), &test_at(), &item, &missing, &linux())
            .unwrap_err();
        assert_eq!(e.exit_code(), 9, "{e}");
    }

    /// NR-2: a failed edit whose session cannot be diagnosed is an unknown outcome.
    #[test]
    fn skeleton_edit_failure_without_diagnosis_is_unknown_exit_9() {
        let item = read(allumata_item());
        let r = FakeRunner::new([Output::failure(1)]);
        r.push_io_error(io::ErrorKind::TimedOut);
        let missing = [("allumata".to_string(), "NEW_KEY".to_string(), Kind::Config)];
        let e = write_skeleton_with(&r, &test_env(), &test_at(), &item, &missing, &linux())
            .unwrap_err();
        assert_eq!(e.exit_code(), 9, "{e}");
    }

    /// NR-2: the edit is a write, so it is never retried.
    #[test]
    fn skeleton_edit_is_never_retried() {
        let item = read(allumata_item());
        let r = FakeRunner::new([Output::failure(2), Output::success(WHOAMI_SA)]);
        let missing = [("allumata".to_string(), "NEW_KEY".to_string(), Kind::Config)];
        let _ = write_skeleton_with(&r, &test_env(), &test_at(), &item, &missing, &linux());
        assert_eq!(
            argvs(&r)
                .iter()
                .filter(|a| a.starts_with("op item edit"))
                .count(),
            1
        );
    }

    // ---------- unsectioned fields (FR-20 removed) ----------

    /// An unsectioned field, as `op` returns a field added outside any section.
    fn tf(id: &str, ty: &str, label: &str, value: &str) -> Value {
        json!({"id": id, "type": ty, "label": label, "value": value,
               "reference": format!("op://vstg/istg/{label}")})
    }

    fn simple_item() -> Vec<u8> {
        item_json(
            json!([{"id": "allumata", "label": "allumata"}]),
            vec![
                notes(),
                json!({"id": "password", "type": "CONCEALED", "purpose": "PASSWORD",
                       "label": "PASSWORD", "value": "pw-FIXTURE"}),
                tf("f1", "CONCEALED", "JWT_KEY", "jwt-FIXTURE"),
                tf("f2", "STRING", "LOG_LEVEL", "info"),
                tf("f3", "OTP", "one-time password", "otpauth://FIXTURE"),
                sf(
                    "a1",
                    "allumata",
                    "allumata",
                    "CONCEALED",
                    "SECTIONED",
                    "s-FIXTURE",
                ),
            ],
        )
    }

    fn labels(item: &Item) -> Vec<(&str, &str)> {
        item.fields
            .iter()
            .map(|f| (f.section.as_str(), f.label.as_str()))
            .collect()
    }

    #[test]
    fn read_ignores_unsectioned_key_fields() {
        let item = read(simple_item());
        assert_eq!(labels(&item), [("allumata", "SECTIONED")]);
    }

    // ------------------------------------------------------------ private item links (H1)

    const WHOAMI_LINK: &[u8] = br#"{"url":"https://my.1password.com","email":"x-LINKMARKER@example.com","user_uuid":"ULINKMARKER","account_uuid":"ACCT123","user_type":"USER"}"#;

    #[test]
    fn item_link_carries_account_vault_item_and_host() {
        let a = parse_account(WHOAMI_LINK);
        assert_eq!(
            item_link(a.as_ref(), "vprd", "iprd"),
            "https://start.1password.com/open/i?a=ACCT123&v=vprd&i=iprd&h=my.1password.com"
        );
    }

    #[test]
    fn item_link_never_carries_email_or_user_id() {
        let link = item_link(parse_account(WHOAMI_LINK).as_ref(), "v", "i");
        assert!(!link.contains("LINKMARKER"), "{link}");
    }

    #[test]
    fn item_link_without_account_names_vault_and_item() {
        assert_eq!(
            item_link(None, "vprd", "iprd"),
            "https://start.1password.com/open/i?v=vprd&i=iprd"
        );
    }

    #[test]
    fn account_with_unexpected_characters_is_dropped() {
        assert_eq!(parse_account(br#"{"account_uuid":"A&x=1"}"#), None);
    }

    #[test]
    fn account_is_one_whoami_probe() {
        let r = FakeRunner::new([Output::success(WHOAMI_LINK.to_vec())]);
        account(&r);
        assert_eq!(r.calls.borrow()[0].args, ["whoami", "--format", "json"]);
    }
}

/// The strict item reader and the skeleton writer, kept for the tests only: production
/// reads every item tolerantly ([`read_whole`], [`super::onepassword_tidy`], FR-43) and
/// writes fields through `app::skeleton`, so nothing outside the tests calls these.
#[cfg(test)]
mod strict {
    use super::*;

    /// An item the strict reader refuses (tests only): opv's own refusal, naming why.
    pub fn strict_refusal(site: &'static str) -> Error {
        Cause::Bug { site }.into()
    }

    /// Read one boundary item `b` of `env` once, by vault ID and item ID (FR-13, FR-57). See
    /// the module docs. The host is detected only if the read fails.
    pub fn read_item(
        r: &dyn CommandRunner,
        env: &Environment,
        b: &Boundary,
    ) -> Result<Item, Error> {
        read_item_on(r, env, b, &Host::detect)
    }

    /// [`read_item`] limited to the fields in `sections`: fields of other sections are skipped
    /// before they are validated, so a malformed field in another product's section cannot fail
    /// a product-scoped check (#52). Still one read (FR-13).
    pub fn read_item_in_sections(
        r: &dyn CommandRunner,
        env: &Environment,
        b: &Boundary,
        sections: &BTreeSet<String>,
    ) -> Result<Item, Error> {
        read_sections_on(r, env, b, Some(sections), &Host::detect)
    }

    /// [`read_item`] on a given host (tests). A non-zero exit is diagnosed with
    /// [`diagnose`] (FR-26). No second item read is made (FR-13).
    pub fn read_item_with(
        r: &dyn CommandRunner,
        env: &Environment,
        b: &Boundary,
        host: &Host,
    ) -> Result<Item, Error> {
        read_item_on(r, env, b, &|| *host)
    }

    pub(super) fn read_item_on(
        r: &dyn CommandRunner,
        env: &Environment,
        b: &Boundary,
        host: &dyn Fn() -> Host,
    ) -> Result<Item, Error> {
        read_sections_on(r, env, b, None, host)
    }

    fn read_sections_on(
        r: &dyn CommandRunner,
        env: &Environment,
        b: &Boundary,
        sections: Option<&BTreeSet<String>>,
        host: &dyn Fn() -> Host,
    ) -> Result<Item, Error> {
        let args = [
            "item",
            "get",
            b.item_id.as_str(),
            "--vault",
            b.vault_id.as_str(),
            "--format",
            "json",
        ];
        let stdout = read_diagnosed(r, env, b, &args, host)?;
        // 09.74: JSON op answered with that opv cannot read is `UnexpectedOutput` of this call.
        let fields = parse_fields(&stdout, sections, &|e| unreadable_reply(&args, e))?;
        Ok(Item {
            fields,
            version: item_version(&stdout),
            raw: stdout,
        })
    }

    fn parse_fields(
        json: &[u8],
        only: Option<&BTreeSet<String>>,
        unreadable: &dyn Fn(&serde_json::Error) -> Error,
    ) -> Result<Vec<ItemField>, Error> {
        #[derive(Deserialize)]
        struct StrictItem {
            #[serde(default)]
            fields: Vec<StrictField>,
        }
        #[derive(Deserialize)]
        struct StrictField {
            #[serde(default)]
            section: Option<StrictSection>,
            #[serde(rename = "type", default)]
            ty: String,
            #[serde(default)]
            label: String,
            #[serde(default)]
            value: Option<Concealed>,
        }
        #[derive(Deserialize)]
        struct StrictSection {
            #[serde(default)]
            label: Option<String>,
        }
        let raw: StrictItem = serde_json::from_slice(json).map_err(|e| unreadable(&e))?;
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for f in raw.fields {
            // Fields outside sections (built-in notesPlain etc.) are not fleet keys (D0 Q1).
            let Some(section) = f.section else { continue };
            // Scoped reads skip other sections before validating them.
            if let Some(only) = only
                && !section.label.as_ref().is_some_and(|l| only.contains(l))
            {
                continue;
            }
            let section = match section.label {
                Some(l) if !l.is_empty() => l,
                _ => {
                    return Err(strict_refusal("a field is in a section without a label"));
                }
            };
            if f.label.is_empty() {
                return Err(strict_refusal("a field has no label"));
            }
            let kind = match f.ty.as_str() {
                "CONCEALED" => Kind::Secret,
                "STRING" => Kind::Config,
                _ => {
                    return Err(strict_refusal("a field has a type opv does not read"));
                }
            };
            if !seen.insert((section.clone(), f.label.clone())) {
                return Err(strict_refusal("two fields have the same section and label"));
            }
            out.push(ItemField {
                section,
                label: f.label,
                kind,
                concealed: kind == Kind::Secret,
                // D0: an empty field has no `value` key at all.
                value: f
                    .value
                    .map_or_else(|| SecretValue::new(String::new()), |c| c.0),
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
pub use strict::{read_item, read_item_in_sections, read_item_with};
#[cfg(test)]
use strict::{read_item_on, strict_refusal};
