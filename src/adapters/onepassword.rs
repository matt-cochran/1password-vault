//! 1Password adapter wrapping the official `op` CLI (S3; FR-11, FR-13, FR-14, FR-19).
//!
//! - [`read_item`] makes exactly one `op item get <item_id> --vault <vault_id> --format json`
//!   call per environment, by ID only (FR-13). It returns the fields that live inside a
//!   section, typed by field type (FR-14: CONCEALED = secret, STRING = config), plus the raw
//!   item JSON so that [`write_skeleton`] needs no second read.
//! - A failed `op` call is diagnosed with [`diagnose`] (FR-26): `op whoami`, then
//!   `op account list` when it fails (both free under rate limits; never a second item
//!   read; own 15 s limit). Not signed in, with no service-account or Connect credential
//!   set, is `Auth` (exit 7) with the sign-in step for the detected shell
//!   ([`crate::host`]); a set credential that fails whoami is `Source` (exit 4, ambiguous:
//!   rejected or unreachable); signed in is `Source` (exit 4) naming the IDs and the
//!   identity type. The host is detected only on failure. Only `user_type` is parsed from `whoami`, and only the entry count from
//!   `account list`; identity is never printed or kept.
//! - [`write_skeleton`] (FR-19, the only write) pipes the full current item, with the missing
//!   sections and empty fields appended, to `op item edit <item_id> --vault <vault_id>
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
//! - `write_skeleton` parses the raw JSON into a `serde_json::Value`, whose `String`s hold
//!   values. Every string in that tree is zeroized before it is dropped (also on error paths),
//!   and the template is serialized into a `Zeroizing` buffer pre-sized to the exact length,
//!   so it never reallocates.

use std::collections::BTreeSet;
use std::fmt;
use std::io::{self, Write};

use serde::Deserialize;
use serde::de::{self, Deserializer, Visitor};
use serde_json::{Value, json};
use zeroize::{Zeroize, Zeroizing};

use crate::domain::model::{Environment, Kind, Profile, SIMPLE_PRODUCT, key_label};
use crate::domain::plan::ItemField;
use crate::domain::secret::SecretValue;
use crate::error::Error;
use crate::host::{Host, OP_CLI, OpCredential, Platform};
use crate::runner::{
    Call, CommandRunner, Outcome, Output, PROBE_TIMEOUT, status_text, unknown_text,
};

const OP: &str = "op";

/// The result of one whole-item read.
///
/// `fields` may be moved out (`std::mem::take(&mut item.fields)`) to build a plan;
/// [`write_skeleton`] uses only the raw JSON kept inside.
pub struct Item {
    pub fields: Vec<ItemField>,
    raw: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for Item {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Item")
            .field("fields", &self.fields)
            .field("raw_len", &self.raw.len())
            .finish()
    }
}

/// The identity `op` is signed in as: its type only, from `op whoami`'s `user_type`
/// field. Identity details (email, account URL, UUIDs) are never parsed or kept (SR-1).
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

/// `user_type` from `op whoami --format json`, nothing else. Unknown fields (identity) are
/// skipped by serde without being kept.
fn identity_type(stdout: &[u8]) -> IdentityType {
    #[derive(Deserialize)]
    struct Who {
        #[serde(default)]
        user_type: Option<String>,
    }
    let t = serde_json::from_slice::<Who>(stdout)
        .ok()
        .and_then(|w| w.user_type)
        .filter(|t| {
            !t.is_empty() && t.len() <= 32 && t.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
        });
    match t.as_deref() {
        Some("SERVICE_ACCOUNT") => IdentityType::ServiceAccount,
        Some(_) => IdentityType::User,
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

/// The remediation for a session that is not usable, or `None` for `SignedIn` / `Unknown`.
/// `failed` names what failed first, if anything before `op whoami` (e.g. `op item get
/// failed (exit 1)`). Text only, never a prompt (FR-9); never asks for a secret anywhere
/// but `op`'s own prompt.
///
/// - `NotSignedIn` / `NoAccount` (no non-interactive credential set): [`Error::Auth`]
///   (exit 7) with the sign-in step for the shell, or "set OP_SERVICE_ACCOUNT_TOKEN" under
///   CI.
/// - `CredentialFailed`: [`Error::Source`] (exit 4, the pre-FR-26 category, FR-10): the
///   token was rejected or 1Password could not be reached; no interactive command.
pub fn session_error(session: Session, host: &Host, failed: Option<&str>) -> Option<Error> {
    let ctx = match failed {
        Some(f) => format!("{f}; op whoami failed"),
        None => "op whoami failed".to_string(),
    };
    let ci_token = "set OP_SERVICE_ACCOUNT_TOKEN to a service account token that can read \
                    the vault (as a CI secret, never in the repository)";
    let network = "if you are signed in, check network access to 1Password";
    let m = match session {
        Session::SignedIn(_) | Session::Unknown => return None,
        Session::CredentialFailed(c) => {
            return Some(Error::Source(format!(
                "{ctx}\n  1Password rejected the {} token or could not be reached: check the \
                 token in {} and network access",
                c.label(),
                c.var()
            )));
        }
        Session::NotSignedIn => match host.signin_line("sign in") {
            None => format!("not signed in to 1Password ({ctx})\n  next: {ci_token}"),
            Some(step) => format!(
                "not signed in to 1Password ({ctx})\n  {step}\n  (a session from op signin \
                 expires after 30 minutes idle; with the desktop app integration, unlock the \
                 1Password app instead)\n  {network}"
            ),
        },
        Session::NoAccount => match host.signin_line("then sign in") {
            None => format!("not signed in to 1Password ({ctx})\n  next: {ci_token}"),
            Some(step) => {
                let wsl = if host.platform == Platform::Wsl {
                    " (op in WSL does not share the Windows app's accounts)"
                } else {
                    ""
                };
                format!(
                    "no 1Password account is set up for op on this machine{wsl} ({ctx} \
                     and op account list is empty)\n  add one: op account \
                     add --address <sign-in address> --email <email>\n  {step}\n  \
                     type the Secret Key and password only at op's prompts, never into chat, \
                     tickets or files"
                )
            }
        },
    };
    Some(Error::Auth(format!("{m}\n  then run opv again")))
}

/// After a failed `op` call: diagnose the session and return the error to report. Not
/// signed in → `Auth` (exit 7) with the sign-in step; a non-interactive credential that
/// fails → `Source` (exit 4); signed in → `Source` (exit 4) naming the vault and item
/// IDs, the identity type and `grant`; the session could not be determined → `Source`
/// with a value-free re-run hint (the last resort).
pub(crate) fn failed_op_error(
    r: &dyn CommandRunner,
    env: &Environment,
    host: &dyn Fn() -> Host,
    failed: &str,
    grant: &str,
) -> Error {
    failed_op_error_as(r, env, host, failed, grant, false)
}

/// [`failed_op_error`] for a read or (`write`) a write. For a write whose session cannot be
/// diagnosed, the change may or may not have happened: `Error::Unknown` (exit 9, NR-2).
fn failed_op_error_as(
    r: &dyn CommandRunner,
    env: &Environment,
    host: &dyn Fn() -> Host,
    failed: &str,
    grant: &str,
    write: bool,
) -> Error {
    let session = match diagnose(r, host) {
        Ok(s) => s,
        Err(e) => return e,
    };
    match session {
        Session::SignedIn(t) => Error::Source(format!(
            "{failed}: signed in to 1Password as {t}, but item {} in vault {} is not \
             available to this identity\n  next: {grant} (vault {}), or check vault_id and \
             item_id in the configuration",
            env.item_id, env.vault_id, env.vault_id
        )),
        Session::Unknown if write => Error::Unknown(format!(
            "{failed}; the item may or may not have been changed{}, then re-run",
            rerun_hint(env)
        )),
        Session::Unknown => Error::Source(format!("{failed}{}", rerun_hint(env))),
        s => session_error(s, &host(), Some(failed)).expect("every other session is an error"),
    }
}

/// Read the environment's item once, by vault ID and item ID (FR-13). See the module docs.
/// The host is detected only if the read fails.
pub fn read_item(r: &dyn CommandRunner, env: &Environment) -> Result<Item, Error> {
    read_item_on(r, env, &Host::detect)
}

/// [`read_item`] for a configuration of the given profile. The call is the same single
/// whole-item read by IDs (FR-13); only the fields returned differ: sectioned fields for
/// the fleet profile, unsectioned fields (section [`SIMPLE_PRODUCT`]) for the simple
/// profile (FR-20).
pub fn read_item_as(
    r: &dyn CommandRunner,
    env: &Environment,
    profile: Profile,
) -> Result<Item, Error> {
    read_profile_on(r, env, profile, None, &Host::detect)
}

/// [`read_item_as`] limited to the fields in `sections` (fleet profile): fields of other
/// sections are skipped before they are validated, so a malformed field in another
/// product's section cannot fail a product-scoped check (#52). Still one read (FR-13).
pub fn read_item_in_sections(
    r: &dyn CommandRunner,
    env: &Environment,
    profile: Profile,
    sections: &BTreeSet<String>,
) -> Result<Item, Error> {
    read_profile_on(r, env, profile, Some(sections), &Host::detect)
}

/// [`read_item`] on a given host (tests). A non-zero exit is diagnosed with
/// [`diagnose`] (FR-26). No second item read is made (FR-13).
pub fn read_item_with(
    r: &dyn CommandRunner,
    env: &Environment,
    host: &Host,
) -> Result<Item, Error> {
    read_item_on(r, env, &|| *host)
}

fn read_item_on(
    r: &dyn CommandRunner,
    env: &Environment,
    host: &dyn Fn() -> Host,
) -> Result<Item, Error> {
    read_profile_on(r, env, Profile::Fleet, None, host)
}

fn read_profile_on(
    r: &dyn CommandRunner,
    env: &Environment,
    profile: Profile,
    sections: Option<&BTreeSet<String>>,
    host: &dyn Fn() -> Host,
) -> Result<Item, Error> {
    let args = [
        "item",
        "get",
        env.item_id.as_str(),
        "--vault",
        env.vault_id.as_str(),
        "--format",
        "json",
    ];
    let Output { status, stdout } = read_op(r, &args, host)?;
    if status != 0 {
        return Err(failed_op_error(
            r,
            env,
            host,
            &format!("op item get failed ({})", status_text(status)),
            "grant this identity access to the vault",
        ));
    }
    let fields = match profile {
        Profile::Fleet => parse_fields(&stdout, sections)?,
        Profile::Simple => parse_unsectioned_fields(&stdout)?,
    };
    Ok(Item {
        fields,
        raw: stdout,
    })
}

/// Add the `missing` (section label, field label, kind) entries to the item as empty fields
/// (FR-19). Sections are matched by label and created (id = label) when absent; every
/// existing section and field is sent back unchanged. Exactly one `op item edit` call, or
/// none when `missing` is empty. An entry that already exists in the item, or is listed
/// twice, is a `Source` error and nothing is written: skeleton never modifies a field.
pub fn write_skeleton(
    r: &dyn CommandRunner,
    env: &Environment,
    item: &Item,
    missing: &[(String, String, Kind)],
) -> Result<(), Error> {
    write_skeleton_on(r, env, item, missing, &Host::detect)
}

/// [`write_skeleton`] on a given host (tests). A failed edit is diagnosed like a failed
/// read (FR-26).
pub fn write_skeleton_with(
    r: &dyn CommandRunner,
    env: &Environment,
    item: &Item,
    missing: &[(String, String, Kind)],
    host: &Host,
) -> Result<(), Error> {
    write_skeleton_on(r, env, item, missing, &|| *host)
}

fn write_skeleton_on(
    r: &dyn CommandRunner,
    env: &Environment,
    item: &Item,
    missing: &[(String, String, Kind)],
    host: &dyn Fn() -> Host,
) -> Result<(), Error> {
    if missing.is_empty() {
        return Ok(());
    }
    let mut doc = WipeOnDrop(serde_json::from_slice(&item.raw).map_err(|e| json_error(&e))?);
    add_missing(&mut doc.0, missing)?;
    let template = serialize_exact(&doc.0)?;
    drop(doc);

    let args = [
        "item",
        "edit",
        env.item_id.as_str(),
        "--vault",
        env.vault_id.as_str(),
        "--format",
        "json",
    ];
    // The edited item comes back on stdout (with values); it is dropped, zeroized, unread.
    // A write (NR-2): never retried. A non-zero exit keeps the session diagnosis (a
    // definite read-back for access and sign-in); anything else is an unknown outcome,
    // which is safe to re-run because the skeleton only adds what is still missing.
    let call = Call::new(OP, &args).with_stdin(Some(&template));
    let status = match r.write(&call).map_err(|e| op_spawn_error(&e, host))? {
        Outcome::Done(_) => return Ok(()),
        Outcome::Refused(o) => o.status,
        Outcome::Unknown {
            status: Some(s), ..
        } => s,
        Outcome::Unknown { reason, .. } => {
            return Err(Error::Unknown(format!(
                "{}: {}; the item may or may not have been changed\n  next: re-run the \
                 same command (it adds only the fields still missing)",
                call.step(),
                unknown_text(OP, reason)
            )));
        }
    };
    if status != 0 {
        return Err(failed_op_error_as(
            r,
            env,
            host,
            &format!("op item edit failed ({})", status_text(status)),
            "grant this identity write access to the vault",
            true,
        ));
    }
    Ok(())
}

/// Last resort (FR-26), used only when the session could not be diagnosed: a value-free
/// command to re-run by hand (`op`'s stderr is shown only as a scrubbed excerpt). IDs only; without
/// `--format json` and `--reveal`, `op` conceals secret fields. (`op item edit` cannot be
/// re-run without its stdin, so the hint reads the item.)
fn rerun_hint(env: &Environment) -> String {
    format!(
        "; run `{OP} item get {} --vault {}` to see why",
        env.item_id, env.vault_id
    )
}

/// `op` is not on PATH: a dependency error with the install hint for this platform.
pub fn op_missing(host: &Host) -> Error {
    Error::Dependency(format!(
        "op CLI not found on PATH\n  {}",
        host.install_hint(OP_CLI)
    ))
}

/// An `op` spawn error: missing binary (with the install hint) or another start failure.
fn op_spawn_error(e: &io::Error, host: &dyn Fn() -> Host) -> Error {
    match e.kind() {
        io::ErrorKind::NotFound => op_missing(&host()),
        io::ErrorKind::TimedOut => Error::Source(format!("op: {e}")),
        kind => Error::Dependency(format!("failed to run op: {kind}")),
    }
}

/// One `op` read (NR-3: retried by the runner). The returned output may carry a non-zero
/// status (still failing after the last attempt): callers diagnose it (FR-26). A read that
/// never finished is a `Source` error naming the step; nothing was changed.
pub(crate) fn read_op(
    r: &dyn CommandRunner,
    args: &[&str],
    host: &dyn Fn() -> Host,
) -> Result<Output, Error> {
    let call = Call::new(OP, args);
    match r.read(&call, &[]).map_err(|e| op_spawn_error(&e, host))? {
        Outcome::Done(o) => {
            // Every item read in this run registers all its field values with the stderr
            // scrubber (NR-31), the selected sections' or not.
            if args.starts_with(&["item", "get"]) {
                crate::scrub::register_item_values(&o.stdout);
            }
            Ok(o)
        }
        Outcome::Refused(o) => Ok(o),
        Outcome::Unknown { reason, .. } => Err(Error::Source(format!(
            "{}: {}",
            call.step(),
            unknown_text(OP, reason)
        ))),
    }
}

/// serde_json's Display can quote input (values), so report only position and category.
pub(crate) fn json_error(e: &serde_json::Error) -> Error {
    Error::Source(format!(
        "op returned malformed item JSON ({:?} error at line {}, column {})",
        e.classify(),
        e.line(),
        e.column()
    ))
}

#[derive(Deserialize)]
struct RawItem {
    #[serde(default)]
    fields: Vec<RawField>,
}

#[derive(Deserialize)]
struct RawField {
    #[serde(default)]
    section: Option<RawSection>,
    #[serde(rename = "type", default)]
    ty: String,
    #[serde(default)]
    label: String,
    /// Set on built-in fields (`USERNAME`, `PASSWORD`, `NOTES`); never a declared key.
    #[serde(default)]
    purpose: Option<String>,
    #[serde(default)]
    value: Option<Concealed>,
}

#[derive(Deserialize)]
struct RawSection {
    #[serde(default)]
    label: Option<String>,
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

fn parse_fields(json: &[u8], only: Option<&BTreeSet<String>>) -> Result<Vec<ItemField>, Error> {
    let raw: RawItem = serde_json::from_slice(json).map_err(|e| json_error(&e))?;
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
                return Err(Error::Source(format!(
                    "field {} is in a section without a label",
                    f.label
                )));
            }
        };
        if f.label.is_empty() {
            return Err(Error::Source(format!(
                "field without a label in section {section}"
            )));
        }
        let kind = match f.ty.as_str() {
            "CONCEALED" => Kind::Secret,
            "STRING" => Kind::Config,
            _ => {
                return Err(Error::Source(format!(
                    "unsupported field type on {section}/{}",
                    f.label
                )));
            }
        };
        if !seen.insert((section.clone(), f.label.clone())) {
            return Err(Error::Source(format!(
                "duplicate field {section}/{} in item",
                f.label
            )));
        }
        out.push(ItemField {
            section,
            label: f.label,
            kind,
            // D0: an empty field has no `value` key at all.
            value: f
                .value
                .map_or_else(|| SecretValue::new(String::new()), |c| c.0),
        });
    }
    Ok(out)
}

/// Simple profile (FR-20): the fields outside any labelled section, keyed by section
/// [`SIMPLE_PRODUCT`]. Sectioned fields are ignored, as are built-in fields (with a
/// `purpose`) and fields whose label cannot be a key name (`^[A-Z][A-Z0-9_]*$`, e.g.
/// `notesPlain` or `one-time password`), because they can never match a declared key. A
/// field that could be a key but has an unsupported type, or a label given twice, is a
/// `Source` error naming the label (FR-14).
fn parse_unsectioned_fields(json: &[u8]) -> Result<Vec<ItemField>, Error> {
    let raw: RawItem = serde_json::from_slice(json).map_err(|e| json_error(&e))?;
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for f in raw.fields {
        let sectioned = f
            .section
            .as_ref()
            .and_then(|s| s.label.as_deref())
            .is_some_and(|l| !l.is_empty());
        if sectioned || f.purpose.is_some() || !is_key_name(&f.label) {
            continue;
        }
        let kind = match f.ty.as_str() {
            "CONCEALED" => Kind::Secret,
            "STRING" => Kind::Config,
            _ => {
                return Err(Error::Source(format!(
                    "unsupported field type on {}",
                    f.label
                )));
            }
        };
        if !seen.insert(f.label.clone()) {
            return Err(Error::Source(format!(
                "duplicate field {} in item",
                f.label
            )));
        }
        out.push(ItemField {
            section: SIMPLE_PRODUCT.to_string(),
            label: f.label,
            kind,
            value: f
                .value
                .map_or_else(|| SecretValue::new(String::new()), |c| c.0),
        });
    }
    Ok(out)
}

fn is_key_name(s: &str) -> bool {
    let mut c = s.chars();
    matches!(c.next(), Some('A'..='Z'))
        && c.all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
}

/// A field outside any labelled section (no `section`, or one without a label).
fn is_unsectioned(f: &Value) -> bool {
    f.get("section")
        .and_then(|s| s.get("label"))
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
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

fn add_missing(doc: &mut Value, missing: &[(String, String, Kind)]) -> Result<(), Error> {
    let obj = doc
        .as_object_mut()
        .ok_or_else(|| Error::Source("op item JSON is not an object".into()))?;

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
            } else if let Some(l) = str_at(f, "label")
                && is_unsectioned(f)
            {
                // Simple profile (FR-20): unsectioned fields are keyed by SIMPLE_PRODUCT.
                existing.insert((SIMPLE_PRODUCT.to_string(), l));
            }
        }
    }

    let mut listed = BTreeSet::new();
    for (s, l, _) in missing {
        if existing.contains(&(s.clone(), l.clone())) {
            return Err(Error::Source(format!(
                "skeleton: {} already exists in the item; not modified",
                key_label(s, l)
            )));
        }
        if !listed.insert((s.clone(), l.clone())) {
            return Err(Error::Source(format!(
                "skeleton: {} listed twice",
                key_label(s, l)
            )));
        }
    }

    let mut new_sections = Vec::new();
    let mut new_fields = Vec::new();
    for (section, label, kind) in missing {
        let ty = match kind {
            Kind::Secret => "CONCEALED",
            Kind::Config => "STRING",
        };
        if section == SIMPLE_PRODUCT {
            // Simple profile (FR-20): a top-level field, outside any section.
            let id = unique(label.to_lowercase(), |c| field_ids.contains(c));
            field_ids.insert(id.clone());
            new_fields.push(json!({"id": id, "type": ty, "label": label, "value": ""}));
            continue;
        }
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
            .ok_or_else(|| Error::Source(format!("op item JSON: `{key}` is not an array")))?;
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
    let fail = |_| Error::Source("could not serialize the item template".into());
    let mut n = Count(0);
    serde_json::to_writer(&mut n, v).map_err(fail)?;
    let mut buf = Zeroizing::new(Vec::with_capacity(n.0));
    serde_json::to_writer(&mut *buf, v).map_err(fail)?;
    debug_assert_eq!(buf.len(), n.0);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
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
            vault_id: "vstg".into(),
            item_id: "istg".into(),
            target: Some(Box::new(crate::adapters::fly::FlyTarget {
                app: "fleet-staging".into(),
                secret_name_template: "FLEET__{PRODUCT}__{KEY}".into(),
                profile: crate::domain::Profile::Fleet,
            })),
            modes: BTreeMap::new(),
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
        read_item_with(&r, &test_env(), &linux()).unwrap()
    }

    fn read_err(bytes: Vec<u8>) -> Error {
        let r = FakeRunner::new([Output::success(bytes)]);
        read_item_with(&r, &test_env(), &linux()).unwrap_err()
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
        let item = read_item_with(&r, &test_env(), &linux()).unwrap();
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
        match e {
            Error::Source(m) => {
                assert_eq!(m, "unsupported field type on allumata/BASE_URL");
            }
            other => panic!("{other:?}"),
        }
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
        match e {
            Error::Source(m) => {
                assert_eq!(m, "duplicate field allumata/OPENAI_API_KEY in item");
            }
            other => panic!("{other:?}"),
        }
    }

    const WHOAMI_SA: &str = r#"{"url":"https://my.1password.com","email":"ci-OPHINTMARKER@example.com","user_uuid":"UOPHINTMARKER","account_uuid":"AOPHINTMARKER","user_type":"SERVICE_ACCOUNT"}"#;

    /// FR-26: signed in (whoami succeeds) but the read fails → Source (exit 4) naming the
    /// IDs and the identity type, with the grant instruction; never "to see why".
    #[test]
    fn non_zero_exit_while_signed_in_is_source_naming_ids_and_identity_type() {
        let r = FakeRunner::new(failed_read(1).chain([Output::success(WHOAMI_SA)]));
        let e = read_item_with(&r, &test_env(), &linux()).unwrap_err();
        let m = match &e {
            Error::Source(m) => m.clone(),
            other => panic!("{other:?}"),
        };
        assert_eq!(e.exit_code(), 4);
        assert!(
            m.starts_with("op item get failed (exit 1): signed in"),
            "{m}"
        );
        assert!(m.contains("SERVICE_ACCOUNT"), "{m}");
        assert!(m.contains("item istg in vault vstg"), "{m}");
        assert!(m.contains("grant this identity access to the vault"), "{m}");
        assert!(!m.contains("to see why"), "{m}");
        assert!(
            !m.contains("example.com") && !m.contains("OPHINTMARKER"),
            "{m}"
        );
        assert_eq!(
            argvs(&r),
            vec![
                "op item get istg --vault vstg --format json",
                "op item get istg --vault vstg --format json",
                "op item get istg --vault vstg --format json",
                "op whoami --format json"
            ]
        );
    }

    /// FR-26: whoami fails → Auth (exit 7) with the sign-in command, whatever credential
    /// variables are set (the motivating bug: an expired OP_SESSION_*).
    #[test]
    fn non_zero_exit_not_signed_in_is_auth_with_signin_command() {
        let r = FakeRunner::new(failed_read(1).chain([Output::failure(1), accounts(1)]));
        let e = read_item_with(&r, &test_env(), &linux()).unwrap_err();
        assert_eq!(e.exit_code(), 7, "{e}");
        let t = e.to_string();
        assert!(t.contains("not signed in to 1Password"), "{t}");
        assert!(t.contains("op item get failed (exit 1)"), "{t}");
        assert!(t.contains("\n  sign in: eval $(op signin)\n"), "{t}");
        assert!(!t.contains("to see why"), "{t}");
    }

    /// FR-13: diagnosis never reads the item a second time (the one read's own retries,
    /// NR-3, are attempts of the same read).
    #[test]
    fn diagnosis_makes_no_extra_item_read() {
        for whoami in [Output::success(WHOAMI_SA), Output::failure(1)] {
            let r = FakeRunner::new(failed_read(1).chain([whoami, accounts(0)]));
            let _ = read_item_with(&r, &test_env(), &linux());
            let reads = argvs(&r)
                .iter()
                .filter(|a| a.starts_with("op item"))
                .count();
            assert_eq!(
                reads,
                crate::runner::READ_ATTEMPTS as usize,
                "{:?}",
                argvs(&r)
            );
        }
    }

    /// The re-run hint survives only as the last resort: when whoami itself cannot run.
    #[test]
    fn rerun_hint_only_when_session_cannot_be_diagnosed() {
        let r = FakeRunner::new(failed_read(1));
        r.push_unknown("timeout");
        let e = read_item_with(&r, &test_env(), &linux()).unwrap_err();
        assert!(
            matches!(&e, Error::Source(m) if m == "op item get failed (exit 1); run `op item get istg --vault vstg` to see why"),
            "{e:?}"
        );
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
                vec![Output::success(WHOAMI_SA)],
                vec![leaky(), accounts(1)],
                vec![leaky(), accounts(0)],
            ]
        };
        for s in sessions() {
            let r = FakeRunner::new((0..crate::runner::READ_ATTEMPTS).map(|_| leaky()).chain(s));
            let e = read_item_with(&r, &test_env(), &linux()).unwrap_err();
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
            let item = read_item_with(&r, &test_env(), &linux()).unwrap();
            let e = write_skeleton_with(
                &r,
                &test_env(),
                &item,
                &[("p".into(), format!("{MARK}K"), Kind::Secret)],
                &linux(),
            )
            .unwrap_err();
            let t = format!("{e} {e:?}");
            assert!(!t.contains(MARK) && !t.contains("example.com"), "{t}");
        }
    }

    #[test]
    fn timeout_is_source_error_naming_op() {
        let r = FakeRunner::default();
        r.push_unknowns("timeout", crate::runner::READ_ATTEMPTS);
        let e = read_item_with(&r, &test_env(), &linux()).unwrap_err();
        assert!(
            matches!(&e, Error::Source(m) if m.starts_with("op item get: op did not finish")),
            "{e:?}"
        );
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
        read_item_on(&r, &test_env(), &host).unwrap();
        assert_eq!(called.get(), 0);
        let r = FakeRunner::new(failed_read(1).chain([Output::failure(1), accounts(1)]));
        let _ = read_item_on(&r, &test_env(), &host);
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
    fn missing_op_binary_is_dependency_error_with_install_hint() {
        let r = FakeRunner::default();
        r.push_io_error(io::ErrorKind::NotFound);
        let e = read_item_with(&r, &test_env(), &linux()).unwrap_err();
        assert!(
            matches!(&e, Error::Dependency(m) if m.contains("op CLI not found on PATH\n  install")),
            "{e:?}"
        );
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
            assert!(matches!(e, Error::Source(_)), "{s}");
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
        write_skeleton(&r, &test_env(), &item, &missing).unwrap();
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
        write_skeleton(&r, &test_env(), &item, &missing).unwrap();
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
        write_skeleton(&r, &test_env(), &item, &[]).unwrap();
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
        let e = write_skeleton(&r, &test_env(), &item, &missing).unwrap_err();
        assert!(
            matches!(&e, Error::Source(m) if m.contains("allumata/SIGNUP_POLICY")),
            "{e:?}"
        );
        assert!(r.calls.borrow().is_empty());
    }

    #[test]
    fn skeleton_uses_raw_json_so_fields_can_be_moved_out_first() {
        let mut item = read(allumata_item());
        let fields = std::mem::take(&mut item.fields);
        assert_eq!(fields.len(), 2);
        let r = FakeRunner::new([Output::success("{}")]);
        let missing = [("allumata".to_string(), "NEW_KEY".to_string(), Kind::Config)];
        write_skeleton(&r, &test_env(), &item, &missing).unwrap();
        let tpl = edit_stdin(&r);
        assert_eq!(
            tpl_field(&tpl, "allumata", "OPENAI_API_KEY")["value"],
            "sk-FIXTURE-openai"
        );
    }

    #[test]
    fn skeleton_edit_failure_while_signed_in_is_source_asking_for_write_access() {
        let item = read(allumata_item());
        let r = FakeRunner::new([Output::failure(2), Output::success(WHOAMI_SA)]);
        let missing = [("allumata".to_string(), "NEW_KEY".to_string(), Kind::Config)];
        let e = write_skeleton_with(&r, &test_env(), &item, &missing, &linux()).unwrap_err();
        assert!(
            matches!(&e, Error::Source(m) if m.starts_with("op item edit failed (exit 2): signed in")
                && m.contains("grant this identity write access to the vault")
                && !m.contains("to see why")),
            "{e:?}"
        );
    }

    #[test]
    fn skeleton_edit_failure_not_signed_in_is_auth() {
        let item = read(allumata_item());
        let r = FakeRunner::new([Output::failure(2), Output::failure(1), accounts(1)]);
        let missing = [("allumata".to_string(), "NEW_KEY".to_string(), Kind::Config)];
        let e = write_skeleton_with(&r, &test_env(), &item, &missing, &linux()).unwrap_err();
        assert_eq!(e.exit_code(), 7, "{e}");
        assert!(e.to_string().contains("eval $(op signin)"), "{e}");
    }

    /// NR-2: an edit that timed out may or may not have happened: exit 9, safe to re-run.
    #[test]
    fn skeleton_edit_timeout_is_unknown_exit_9() {
        let item = read(allumata_item());
        let r = FakeRunner::default();
        r.push_unknown("timeout");
        let missing = [("allumata".to_string(), "NEW_KEY".to_string(), Kind::Config)];
        let e = write_skeleton_with(&r, &test_env(), &item, &missing, &linux()).unwrap_err();
        assert_eq!(e.exit_code(), 9, "{e}");
    }

    /// NR-2: a failed edit whose session cannot be diagnosed is an unknown outcome.
    #[test]
    fn skeleton_edit_failure_without_diagnosis_is_unknown_exit_9() {
        let item = read(allumata_item());
        let r = FakeRunner::new([Output::failure(1)]);
        r.push_io_error(io::ErrorKind::TimedOut);
        let missing = [("allumata".to_string(), "NEW_KEY".to_string(), Kind::Config)];
        let e = write_skeleton_with(&r, &test_env(), &item, &missing, &linux()).unwrap_err();
        assert_eq!(e.exit_code(), 9, "{e}");
    }

    /// NR-2: the edit is a write, so it is never retried.
    #[test]
    fn skeleton_edit_is_never_retried() {
        let item = read(allumata_item());
        let r = FakeRunner::new([Output::failure(2), Output::success(WHOAMI_SA)]);
        let missing = [("allumata".to_string(), "NEW_KEY".to_string(), Kind::Config)];
        let _ = write_skeleton_with(&r, &test_env(), &item, &missing, &linux());
        assert_eq!(
            argvs(&r)
                .iter()
                .filter(|a| a.starts_with("op item edit"))
                .count(),
            1
        );
    }

    // ---------- simple profile (FR-20) ----------

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

    fn read_simple(bytes: Vec<u8>) -> Result<Item, Error> {
        let r = FakeRunner::new([Output::success(bytes)]);
        read_profile_on(&r, &test_env(), Profile::Simple, None, &linux)
    }

    fn labels(item: &Item) -> Vec<(&str, &str)> {
        item.fields
            .iter()
            .map(|f| (f.section.as_str(), f.label.as_str()))
            .collect()
    }

    #[test]
    fn simple_read_is_one_whole_item_call_by_ids() {
        let r = FakeRunner::new([Output::success(simple_item())]);
        read_profile_on(&r, &test_env(), Profile::Simple, None, &linux).unwrap();
        let calls = r.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].args, GET_ARGS);
    }

    #[test]
    fn simple_read_returns_only_unsectioned_key_fields() {
        let item = read_simple(simple_item()).unwrap();
        assert_eq!(labels(&item), [("", "JWT_KEY"), ("", "LOG_LEVEL")]);
    }

    #[test]
    fn simple_read_types_fields_by_field_type() {
        let item = read_simple(simple_item()).unwrap();
        assert_eq!(find(&item.fields, "", "JWT_KEY").kind, Kind::Secret);
        assert_eq!(find(&item.fields, "", "LOG_LEVEL").kind, Kind::Config);
    }

    #[test]
    fn simple_read_treats_a_section_without_label_as_unsectioned() {
        let bytes = item_json(
            json!([]),
            vec![
                json!({"id": "k", "section": {"id": "add more"}, "type": "CONCEALED",
                        "label": "API_KEY", "value": "x-FIXTURE"}),
            ],
        );
        let item = read_simple(bytes).unwrap();
        assert_eq!(labels(&item), [("", "API_KEY")]);
    }

    #[test]
    fn simple_read_unsupported_type_is_source_error_naming_label_only() {
        let bytes = item_json(
            json!([]),
            vec![tf("k", "URL", "API_URL", "https://FIXTURE")],
        );
        let Err(Error::Source(m)) = read_simple(bytes) else {
            panic!("expected Source error")
        };
        assert!(m.contains("API_URL") && !m.contains("FIXTURE"), "{m}");
    }

    #[test]
    fn simple_read_duplicate_label_is_source_error() {
        let bytes = item_json(
            json!([]),
            vec![
                tf("a", "CONCEALED", "API_KEY", "a-FIXTURE"),
                tf("b", "CONCEALED", "API_KEY", "b-FIXTURE"),
            ],
        );
        let Err(Error::Source(m)) = read_simple(bytes) else {
            panic!("expected Source error")
        };
        assert!(m.contains("duplicate") && m.contains("API_KEY"), "{m}");
    }

    #[test]
    fn fleet_read_still_ignores_unsectioned_key_fields() {
        let item = read(simple_item());
        assert_eq!(labels(&item), [("allumata", "SECTIONED")]);
    }

    #[test]
    fn simple_skeleton_adds_a_top_level_field_without_a_section() {
        let item = read_simple(simple_item()).unwrap();
        let r = FakeRunner::new([Output::success("{}")]);
        let missing = [(String::new(), "DATABASE_URL".to_string(), Kind::Secret)];
        write_skeleton(&r, &test_env(), &item, &missing).unwrap();
        let tpl = edit_stdin(&r);
        let f = tpl["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["label"] == "DATABASE_URL")
            .expect("new field");
        assert_eq!(f.get("section"), None);
        assert_eq!((&f["type"], &f["value"]), (&json!("CONCEALED"), &json!("")));
    }

    #[test]
    fn simple_skeleton_creates_no_section() {
        let item = read_simple(simple_item()).unwrap();
        let r = FakeRunner::new([Output::success("{}")]);
        let missing = [(String::new(), "DATABASE_URL".to_string(), Kind::Config)];
        write_skeleton(&r, &test_env(), &item, &missing).unwrap();
        assert_eq!(edit_stdin(&r)["sections"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn simple_skeleton_refuses_an_existing_top_level_field() {
        let item = read_simple(simple_item()).unwrap();
        let r = FakeRunner::new([Output::success("{}")]);
        let missing = [(String::new(), "JWT_KEY".to_string(), Kind::Secret)];
        let e = write_skeleton(&r, &test_env(), &item, &missing).unwrap_err();
        assert!(matches!(e, Error::Source(m) if m.contains("JWT_KEY")));
        assert!(r.calls.borrow().is_empty(), "nothing written");
    }
}
