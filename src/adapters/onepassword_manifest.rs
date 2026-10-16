//! The project manifest in 1Password (FR-44): one Secure Note per project holding the
//! same TOML as `secrets.toml` in its notes, never a secret value.
//!
//! The notes are Markdown, which 1Password renders: an "opv managed configuration"
//! heading and a short explanation for whoever opens the item, then the TOML in one fenced
//! `toml` code block. opv reads only that block ([`config_text`]); notes without one (a
//! manifest written before the heading) are read whole. An edit replaces only the block's
//! contents, so text a person adds around it is kept ([`note_with`]).
//!
//! Calls, all through the runner (reads retried, writes never retried; NR-2, NR-3):
//! - [`list`]: `op item list --tags opv-manifest --format json` (item metadata only: IDs,
//!   titles, tags, versions; no field values).
//! - [`get`]: `op item get <item_id> --vault <vault_id> --format json`, by IDs (FR-13);
//!   with `--cache=false` when a write is built from or checked against it (C1).
//! - [`create`]: `op item create --vault <vault> --format json -`, the item JSON on stdin.
//! - [`edit`]: `op item edit <item_id> --vault <vault_id> --format json`, the whole item
//!   JSON on stdin (the same invocation as `item skeleton`, D0).
//!
//! Every call takes `--account <account>` when one is set (`.opv`, Task L's per-environment
//! account); otherwise op's own `OP_ACCOUNT` or default account applies. Only fixed words,
//! IDs, the vault and the account go in argv; the manifest text goes on stdin (SR-3, SR-7).
//! A failed call is diagnosed like every other `op` call (FR-26); a missing session names
//! `opv login` as the next step.

use serde::Deserialize;
use serde_json::{Value, json};

use super::onepassword::{NO_CACHE, Session, account_suffix, diagnose, json_error, session_error};
use crate::error::Error;
use crate::host::{Host, OP_CLI};
use crate::runner::{Call, CommandRunner, Outcome, status_text};

const OP: &str = "op";

/// The tag every manifest carries; discovery lists by it.
pub const MANIFEST_TAG: &str = "opv-manifest";
/// The manifest's convention version (its `convention` field).
pub const CONVENTION: &str = "1";
/// The next step when op has no session (Task L's sign-in command).
pub const LOGIN: &str = "opv login";

/// One manifest as `op item list` shows it: metadata only.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Row {
    pub id: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub version: u64,
    pub vault: VaultRef,
}

/// The vault an item lives in.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct VaultRef {
    pub id: String,
    #[serde(default)]
    pub name: String,
}

/// One manifest read in full: the TOML text, its version and the raw item (kept to write
/// it back whole; it holds no secret).
#[derive(Debug, Clone)]
pub struct Manifest {
    pub text: String,
    pub version: u64,
    pub project: Option<String>,
    pub raw: Value,
}

/// `args` with `--account <account>` appended when one is set.
fn argv<'a>(args: &[&'a str], account: Option<&'a str>) -> Vec<&'a str> {
    let mut v = args.to_vec();
    if let Some(a) = account {
        v.extend(["--account", a]);
    }
    v
}

/// The configuration is looked for in 1Password and the call failed: diagnose (FR-26).
/// Not signed in is `Auth` (exit 7) with `Next: opv login`, saying plainly that the
/// configuration lives in 1Password.
pub(crate) fn failure(
    r: &dyn CommandRunner,
    host: &dyn Fn() -> Host,
    failed: &str,
    what: &str,
) -> Error {
    let session = crate::runner::diagnosing(|| diagnose(r, host));
    match session {
        Err(e) => e,
        Ok(Session::SignedIn(t)) => Error::Source(
            format!(
                "{failed}: signed in to 1Password as {t}\n  next: check that this identity can \
                 see {what}"
            )
            .into(),
        ),
        Ok(Session::Unknown) => Error::Source(
            format!("{failed}; run `op item list --tags {MANIFEST_TAG}` to see why").into(),
        ),
        Ok(s) => {
            let e =
                session_error(s, &host(), Some(failed), None).expect("every other session fails");
            match e {
                Error::Auth(_) => login_next(
                    e.map_text(|m| {
                        format!(
                            "this project's configuration lives in 1Password, which needs a \
                             session: {m}"
                        )
                    }),
                    &host(),
                ),
                other => other,
            }
        }
    }
}

/// `e` with [`LOGIN`] as its step only when it names none (`opv login --add` for no
/// account stays) and a person can sign in here: under CI or a service-account or Connect
/// credential `opv login` refuses, so it is never offered there (#157).
fn login_next(e: Error, host: &Host) -> Error {
    if e.next_step().is_none() && host.signin_command(None).is_some() {
        e.with_next(LOGIN)
    } else {
        e
    }
}

/// The error for a read of `what` that failed, diagnosed for `account` when one is known
/// (#135): a `whoami` probe for exactly that account, so a failure for one account is
/// never reported as another account's signed-in identity. Without an account this is the
/// shared [`failure`] path, unchanged for its other callers.
fn diagnosis(
    r: &dyn CommandRunner,
    host: &dyn Fn() -> Host,
    account: Option<&str>,
    failed: &str,
    what: &str,
) -> Error {
    let Some(id) = account else {
        return failure(r, host, failed, what);
    };
    match signed_in(r, id) {
        Some(false) => Error::Auth(
            format!(
                "{failed}: the 1Password account {id} is not signed in; this project's \
                 configuration lives in 1Password"
            )
            .into(),
        )
        .with_code(crate::error::Code::OpNotSignedIn)
        .with_next(format!("opv login --account {id}")),
        Some(true) => Error::Source(
            format!(
                "{failed}: signed in to 1Password account {id}\n  next: check that this \
                 account can see {what}"
            )
            .into(),
        ),
        None => failure(r, host, failed, what),
    }
}

/// One read; a call still failing after its retries is diagnosed.
fn read(
    r: &dyn CommandRunner,
    args: &[&str],
    account: Option<&str>,
    host: &dyn Fn() -> Host,
    failed: &str,
    what: &str,
) -> Result<Vec<u8>, Error> {
    let call = Call::new(OP, args);
    let out = match r.read(&call, &[]) {
        Ok(Outcome::Done(o)) => o,
        Ok(Outcome::Refused(o)) => {
            let failed = format!("{failed} failed ({})", status_text(o.status));
            return Err(diagnosis(r, host, account, &failed, what));
        }
        Ok(Outcome::Unknown { .. }) => return Err(OP_CLI.outage(&call.step())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(super::onepassword::op_missing(&host()));
        }
        Err(e) => {
            return Err(Error::Dependency(
                format!("failed to run op: {}", e.kind()).into(),
            ));
        }
    };
    Ok(out.stdout.to_vec())
}

/// Every manifest this identity can see: one `op item list --tags opv-manifest` call.
pub fn list(
    r: &dyn CommandRunner,
    account: Option<&str>,
    host: &dyn Fn() -> Host,
) -> Result<Vec<Row>, Error> {
    let args = argv(
        &["item", "list", "--tags", MANIFEST_TAG, "--format", "json"],
        account,
    );
    let out = read(
        r,
        &args,
        account,
        host,
        &format!("op item list --tags {MANIFEST_TAG}"),
        "the vault that holds this project's manifest",
    )?;
    if out.iter().all(u8::is_ascii_whitespace) {
        return Ok(Vec::new());
    }
    let mut rows: Vec<Row> = serde_json::from_slice(&out).map_err(|e| json_error(&e))?;
    // `--tags` also returns nested tags (`opv-manifest/x`): keep exact ones only.
    rows.retain(|r| r.tags.iter().any(|t| t == MANIFEST_TAG));
    rows.sort_by(|a, b| (&a.title, &a.vault.name, &a.id).cmp(&(&b.title, &b.vault.name, &b.id)));
    Ok(rows)
}

/// An account op knows on this machine: its ID (for `--account`), sign-in address, and the
/// person's own email and user ID, used only to match what they type and to list their
/// accounts back to them when they must choose (never logged or sent anywhere).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Account {
    #[serde(default)]
    pub account_uuid: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub user_uuid: String,
    #[serde(default)]
    pub shorthand: String,
}

/// The account `who` names among `accounts`: an account ID, user ID, email, shorthand or
/// sign-in address (matched ignoring case). `op` itself takes no email, and a sign-in
/// address is shared by every account on `my.1password.com`, so opv resolves `who` to the
/// account ID once and uses that (found live). None, or several, is a configuration error
/// that lists the accounts.
pub fn resolve(accounts: &[Account], who: &str) -> Result<String, Error> {
    let w = who.trim().to_ascii_lowercase();
    let host = |u: &str| {
        u.trim_start_matches("https://")
            .trim_end_matches('/')
            .to_ascii_lowercase()
    };
    let hits: Vec<&Account> = accounts
        .iter()
        .filter(|a| {
            [&a.account_uuid, &a.user_uuid, &a.email, &a.shorthand]
                .iter()
                .any(|f| !f.is_empty() && f.to_ascii_lowercase() == w)
                || host(&a.url) == host(&w)
        })
        .collect();
    match hits.as_slice() {
        [one] => Ok(one.account_uuid.clone()),
        [] => Err(not_known(accounts, who)),
        many => Err(Error::Config(
            format!(
                "{} 1Password accounts match {who:?}; name one by its email or account ID:\n{}",
                many.len(),
                listing(&many.iter().map(|a| (*a).clone()).collect::<Vec<_>>())
            )
            .into(),
        )
        .with_code(crate::error::Code::AccountRequired)),
    }
}

/// `who` is not an account this `op` knows. On Linux and in WSL with a native `op`, `op`
/// keeps its own accounts (in WSL it does not share the Windows app's: found live), so the
/// step is `opv login --add --account` for that email in this terminal. In WSL with the
/// Windows `op.exe`, the account is added in the Windows 1Password app (the one `op.exe`
/// reads); elsewhere, in the 1Password app.
fn not_known(accounts: &[Account], who: &str) -> Error {
    use crate::host::Platform;
    let host = Host::detect();
    let e = Error::Config(
        format!(
            "no 1Password account on this machine matches {who:?}; the accounts op knows:\n{}",
            listing(accounts)
        )
        .into(),
    )
    .with_code(crate::error::Code::AccountRequired);
    let windows_op = host.op_is_windows_exe();
    let own_op = matches!(host.platform, Platform::Linux | Platform::Wsl) && !windows_op;
    if own_op && who.contains('@') && crate::config::is_account(who) {
        let wsl = if host.platform == Platform::Wsl {
            " (op in WSL does not see the Windows app's accounts)"
        } else {
            ""
        };
        return e
            .with_do(format!(
                "add the account to op here{wsl}: type its sign-in address, Secret Key and \
                 password only at op's prompts, then re-run opv login"
            ))
            .with_next(format!("opv login --add --account {who}"));
    }
    if windows_op {
        return e
            .with_do(
                "add the account in the Windows 1Password app and turn on Settings > Developer \
                 > Integrate with 1Password CLI, then re-run",
            )
            .with_next(format!("opv login --account {who}"));
    }
    e.with_do(
        "add the account in the 1Password app and turn on Settings > Developer > Integrate \
         with 1Password CLI, then re-run",
    )
}

/// One line per account: email, sign-in address and account ID (the person's own accounts,
/// shown so they can choose).
fn listing(accounts: &[Account]) -> String {
    if accounts.is_empty() {
        return "  (none: add one in the 1Password app)".into();
    }
    accounts
        .iter()
        .map(|a| {
            format!(
                "  {}  {}  {}",
                if a.email.is_empty() { "-" } else { &a.email },
                a.url.trim_start_matches("https://").trim_end_matches('/'),
                a.account_uuid
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Several accounts on this machine and none chosen for the project: opv never guesses and
/// never searches them all (each search asks the 1Password app about that account, and
/// none of them was granted to this project). The person picks one.
pub fn choose_error(accounts: &[Account]) -> Error {
    Error::Config(
        format!(
            "{} 1Password accounts are on this machine and this project names none; opv uses \
             only the account you choose, never op's default:\n{}",
            accounts.len(),
            listing(accounts)
        )
        .into(),
    )
    .with_code(crate::error::Code::AccountRequired)
    .with_do("pick the project's account: run opv login --account <email or account ID> in your own terminal")
    .with_next("opv account list")
}

/// The accounts op knows (`op account list`, a free probe); empty when it fails. Callers
/// that must tell "none" from "could not list" use [`discover`].
pub fn accounts(r: &dyn CommandRunner) -> Vec<Account> {
    match discover(r) {
        Discovery::Listed(found) => found,
        Discovery::OpMissing | Discovery::Unavailable => Vec::new(),
    }
}

/// What `op account list` found (FR-49): the accounts this `op` knows, or why none could be
/// listed. Accounts that live only in a desktop app this `op` is not integrated with are
/// never claimed: `op` cannot see them, so neither can opv.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Discovery {
    /// The list `op` printed (possibly empty), each with a valid account ID.
    Listed(Vec<Account>),
    /// `op` is not installed (or not on PATH).
    OpMissing,
    /// `op` failed or printed something that is not an account list; its scrubbed excerpt
    /// stays with the run (`--verbose`), never in JSON.
    Unavailable,
}

/// `op account list --format json`, one read-only probe that never prompts (FR-49).
pub fn discover(r: &dyn CommandRunner) -> Discovery {
    match r.probe(
        &Call::new(OP, &["account", "list", "--format", "json"]),
        crate::runner::PROBE_TIMEOUT,
    ) {
        Ok(o) if o.status == 0 => match serde_json::from_slice::<Vec<Account>>(&o.stdout) {
            Ok(found) => Discovery::Listed(
                found
                    .into_iter()
                    .filter(|a| crate::config::is_id(&a.account_uuid))
                    .collect(),
            ),
            Err(_) => Discovery::Unavailable,
        },
        Ok(_) => {
            let _ = crate::runner::take_failure_excerpt();
            Discovery::Unavailable
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Discovery::OpMissing,
        Err(_) => Discovery::Unavailable,
    }
}

/// Whether `op` holds a live session for `account_uuid` (FR-49): `op whoami --account <id>`,
/// exit status only (its output names the person and is dropped unread). It never prompts
/// and never asks the desktop app. `None` when the probe cannot run.
pub fn signed_in(r: &dyn CommandRunner, account_uuid: &str) -> Option<bool> {
    match r.probe(
        &Call::new(
            OP,
            &["whoami", "--account", account_uuid, "--format", "json"],
        ),
        crate::runner::PROBE_TIMEOUT,
    ) {
        Ok(o) => {
            if o.status != 0 {
                let _ = crate::runner::take_failure_excerpt();
            }
            Some(o.status == 0)
        }
        Err(_) => None,
    }
}

/// Read one manifest by vault ID and item ID. `fresh` bypasses `op`'s local cache
/// ([`NO_CACHE`]): every read a manifest write is built from or checked against (C1).
pub fn get(
    r: &dyn CommandRunner,
    vault_id: &str,
    item_id: &str,
    account: Option<&str>,
    fresh: bool,
    host: &dyn Fn() -> Host,
) -> Result<Manifest, Error> {
    let mut base = vec![
        "item", "get", item_id, "--vault", vault_id, "--format", "json",
    ];
    if fresh {
        base.push(NO_CACHE);
    }
    let args = argv(&base, account);
    let out = read(
        r,
        &args,
        account,
        host,
        &format!(
            "op item get {item_id} --vault {vault_id}{}",
            account_suffix(account)
        ),
        &format!("vault {vault_id}"),
    )?;
    let raw: Value = serde_json::from_slice(&out).map_err(|e| json_error(&e))?;
    parse(raw, item_id)
}

/// The manifest fields of an item JSON document.
fn parse(raw: Value, item_id: &str) -> Result<Manifest, Error> {
    let fields = raw["fields"].as_array().cloned().unwrap_or_default();
    let notes = fields
        .iter()
        .find(|f| f["purpose"] == "NOTES" || f["id"] == "notesPlain")
        .and_then(|f| f["value"].as_str())
        .map(config_text)
        .ok_or_else(|| {
            Error::Source(
                format!(
                    "item {item_id} is tagged {MANIFEST_TAG} but has no notes field holding the \
                     configuration\n  next: opv config import --vault <vault> (or fix the item \
                     in 1Password)"
                )
                .into(),
            )
        })?;
    let project = fields
        .iter()
        .find(|f| f["label"] == "project")
        .and_then(|f| f["value"].as_str())
        .map(str::to_string);
    Ok(Manifest {
        text: notes,
        version: raw["version"].as_u64().unwrap_or(0),
        project,
        raw,
    })
}

/// The item JSON for a new manifest.
pub fn template(title: &str, project: &str, tags: &[String], text: &str) -> Value {
    json!({
        "title": title,
        "category": "SECURE_NOTE",
        "tags": tags,
        "fields": [
            {"id": "notesPlain", "type": "STRING", "purpose": "NOTES", "label": "notesPlain",
             "value": note_with(text, None, project)},
            {"id": "project", "type": "STRING", "label": "project", "value": project},
            {"id": "convention", "type": "STRING", "label": "convention", "value": CONVENTION},
        ],
    })
}

/// The configuration in manifest notes: the first fenced `toml` code block's contents, or
/// the whole notes when there is none (a manifest written before the Markdown layout).
pub fn config_text(notes: &str) -> String {
    match fenced(notes) {
        Some((_, body, _)) => body.to_string(),
        None => notes.to_string(),
    }
}

/// Split `notes` around its first fenced `toml` block: (before, contents, after), the fence
/// lines excluded from all three. The closing fence is a line of exactly the opening's
/// backticks (Markdown's rule), so a shorter run inside the TOML never ends the block.
fn fenced(notes: &str) -> Option<(&str, &str, &str)> {
    let mut at = 0;
    let mut open: Option<(usize, usize, &str)> = None; // (start of fence, start of body, ticks)
    for line in notes.split_inclusive('\n') {
        let bare = line.trim_end_matches(['\n', '\r']);
        match open {
            None => {
                let ticks = bare.len() - bare.trim_start_matches('`').len();
                if ticks >= 3 && bare[ticks..].trim() == "toml" {
                    open = Some((at, at + line.len(), &bare[..ticks]));
                }
            }
            Some((start, body, ticks)) if bare.trim_end() == ticks => {
                return Some((&notes[..start], &notes[body..at], &notes[at + line.len()..]));
            }
            Some(_) => {}
        }
        at += line.len();
    }
    None
}

/// Manifest notes holding `config`: the `previous` notes with only their code block's
/// contents replaced, or, when they have no block (a new or older manifest), the heading
/// and explanation followed by the block.
pub fn note_with(config: &str, previous: Option<&str>, project: &str) -> String {
    let ticks = "`".repeat(longest_tick_run(config).max(2) + 1);
    let mut body = config.to_string();
    if !body.ends_with('\n') {
        body.push('\n');
    }
    let block = format!("{ticks}toml\n{body}{ticks}\n");
    if let Some((before, _, after)) = previous.and_then(fenced) {
        return format!("{before}{block}{after}");
    }
    format!(
        "# opv managed configuration\n\n\
         opv reads this note to know which keys the project **{project}** needs and where each \
         environment keeps them. **No secret values are stored here.**\n\n\
         - Values: in each environment's own item (its `vault_id` and `item_id` below). Open \
         one with `opv open KEY --env ENV`.\n\
         - Change keys with `opv add KEY` or `opv config edit`. Hand edits are fine inside the \
         code block while it stays valid TOML; opv reads only the code block.\n\
         - About opv: https://github.com/matt-cochran/1password-vault\n\n\
         {block}"
    )
}

fn longest_tick_run(text: &str) -> usize {
    text.split(|c| c != '`').map(str::len).max().unwrap_or(0)
}

/// A write that may or may not have happened, or failed for a known reason.
fn write_failed(
    r: &dyn CommandRunner,
    host: &dyn Fn() -> Host,
    step: &str,
    outcome: Outcome,
    check: &str,
) -> Error {
    match outcome {
        // M7: a refused call is a definite failure (nothing changed): diagnosed like a
        // non-zero exit, never reported as an unknown outcome.
        Outcome::Refused(o) => match crate::runner::diagnosing(|| diagnose(r, host)) {
            Ok(Session::SignedIn(t)) => Error::Source(
                format!(
                    "{step} failed ({}): signed in to 1Password as {t}; the manifest was not \
                     changed\n  next: check that this identity can write to the vault, then \
                     {check}",
                    status_text(o.status)
                )
                .into(),
            ),
            Ok(Session::Unknown) | Err(_) => Error::Source(
                format!(
                    "{step} failed ({}); the manifest was not changed: {check}",
                    status_text(o.status)
                )
                .into(),
            ),
            Ok(other) => login_next(
                session_error(other, &host(), Some(step), None).expect("every other session fails"),
                &host(),
            ),
        },
        Outcome::Unknown {
            status: Some(s), ..
        } => {
            // A non-zero exit: the session decides whether anything could have happened.
            match crate::runner::diagnosing(|| diagnose(r, host)) {
                Ok(Session::SignedIn(t)) => Error::Source(
                    format!(
                        "{step} failed ({}): signed in to 1Password as {t}\n  next: check that \
                         this identity can write to the vault, then {check}",
                        status_text(s)
                    )
                    .into(),
                ),
                Ok(Session::Unknown) | Err(_) => Error::Unknown(
                    format!(
                        "{step} failed ({}); the manifest may or may not have changed: {check}",
                        status_text(s)
                    )
                    .into(),
                ),
                Ok(other) => login_next(
                    session_error(other, &host(), Some(step), None)
                        .expect("every other session fails"),
                    &host(),
                ),
            }
        }
        _ => Error::Unknown(
            format!("{step} did not finish; the manifest may or may not have changed: {check}")
                .into(),
        ),
    }
}

/// Create a manifest in `vault` (a vault title or ID, as op accepts). Returns the new
/// item's row. One write, never retried.
pub fn create(
    r: &dyn CommandRunner,
    vault: &str,
    item: &Value,
    account: Option<&str>,
    host: &dyn Fn() -> Host,
) -> Result<Row, Error> {
    let body = serde_json::to_vec(item)
        .map_err(|_| Error::Config("cannot serialize the manifest".into()))?;
    let args = argv(
        &["item", "create", "--vault", vault, "--format", "json", "-"],
        account,
    );
    let call = Call::new(OP, &args).with_stdin(Some(&body));
    let check = format!("check with `op item list --tags {MANIFEST_TAG}` before re-running");
    match r.write(&call) {
        Ok(Outcome::Done(o)) => serde_json::from_slice(&o.stdout).map_err(|e| json_error(&e)),
        Ok(other) => Err(write_failed(r, host, "op item create", other, &check)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(super::onepassword::op_missing(&host()))
        }
        Err(e) => Err(Error::Dependency(
            format!("failed to run op: {}", e.kind()).into(),
        )),
    }
}

/// What a manifest edit wrote, as `op item edit` printed it back: its version and notes
/// (I5). `None` fields when op printed no item.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Written {
    pub version: Option<u64>,
    pub text: Option<String>,
}

/// Replace the manifest's notes with `text`, sending the whole item back (`base` is the
/// item as last read, fresh). One write, never retried. Returns what op says it wrote.
pub fn edit(
    r: &dyn CommandRunner,
    vault_id: &str,
    item_id: &str,
    base: &Value,
    text: &str,
    account: Option<&str>,
    host: &dyn Fn() -> Host,
) -> Result<Written, Error> {
    let mut item = base.clone();
    let fields = item["fields"]
        .as_array_mut()
        .ok_or_else(|| Error::Source(format!("item {item_id} has no fields").into()))?;
    let project = fields
        .iter()
        .find(|f| f["label"] == "project")
        .and_then(|f| f["value"].as_str())
        .unwrap_or("this project")
        .to_string();
    let notes = fields
        .iter_mut()
        .find(|f| f["purpose"] == "NOTES" || f["id"] == "notesPlain")
        .ok_or_else(|| Error::Source(format!("item {item_id} has no notes field").into()))?;
    let previous = notes["value"].as_str().map(str::to_string);
    notes["value"] = Value::String(note_with(text, previous.as_deref(), &project));
    let body = serde_json::to_vec(&item)
        .map_err(|_| Error::Config("cannot serialize the manifest".into()))?;
    let args = argv(
        &[
            "item", "edit", item_id, "--vault", vault_id, "--format", "json",
        ],
        account,
    );
    let call = Call::new(OP, &args).with_stdin(Some(&body));
    let check = "check with `opv config export --toml`, then re-run".to_string();
    match r.write(&call) {
        Ok(Outcome::Done(o)) => Ok(match serde_json::from_slice::<Value>(&o.stdout) {
            Ok(v) => Written {
                version: v["version"].as_u64(),
                text: parse(v, item_id).ok().map(|m| m.text),
            },
            Err(_) => Written::default(),
        }),
        Ok(other) => Err(write_failed(r, host, "op item edit", other, &check)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(super::onepassword::op_missing(&host()))
        }
        Err(e) => Err(Error::Dependency(
            format!("failed to run op: {}", e.kind()).into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::Output;
    use crate::runner::fake::FakeRunner;

    const ONE_ACCOUNT: &str = r#"[{"url":"my-team.1password.com","email":"owner@example.com","user_uuid":"USERUUID0000000000000000AA","account_uuid":"ACCOUNTUUID000000000000AAA","shorthand":"my-team"}]"#;

    #[test]
    fn discovery_lists_the_accounts_op_prints() {
        let r = FakeRunner::new([Output::success(ONE_ACCOUNT)]);
        assert!(matches!(discover(&r), Discovery::Listed(found) if found.len() == 1));
    }

    #[test]
    fn discovery_of_an_empty_list_is_listed_and_empty() {
        let r = FakeRunner::new([Output::success("[]")]);
        assert_eq!(discover(&r), Discovery::Listed(Vec::new()));
    }

    #[test]
    fn a_failing_op_is_unavailable_not_empty() {
        let r = FakeRunner::new([Output::failure(1)]);
        assert_eq!(discover(&r), Discovery::Unavailable);
    }

    #[test]
    fn unexpected_output_is_unavailable_not_empty() {
        let r = FakeRunner::new([Output::success("not json")]);
        assert_eq!(discover(&r), Discovery::Unavailable);
    }

    #[test]
    fn a_missing_op_is_reported_as_missing() {
        let r = FakeRunner::default();
        r.push_io_error(std::io::ErrorKind::NotFound);
        assert_eq!(discover(&r), Discovery::OpMissing);
    }

    #[test]
    fn signed_in_reads_the_exit_status_of_whoami_for_that_account() {
        let r = FakeRunner::new([Output::failure(1)]);
        assert_eq!(signed_in(&r, "ACCOUNTUUID000000000000AAA"), Some(false));
    }

    #[test]
    fn signed_in_names_the_account_on_whoami() {
        let r = FakeRunner::new([Output::success("{}")]);
        signed_in(&r, "ACCOUNTUUID000000000000AAA");
        assert!(r.argv_contains("ACCOUNTUUID000000000000AAA"));
    }

    /// #135: a listing that failed for account B is diagnosed for B, never as another
    /// account's signed-in identity.
    #[test]
    fn a_listing_for_a_signed_out_account_is_op_not_signed_in() {
        let r = signed_out_listing();
        let e = list(&r, Some("ACCOUNTBBB000000000000BBB"), &Host::detect).unwrap_err();
        assert_eq!(e.code().as_str(), "op_not_signed_in");
    }

    #[test]
    fn a_listing_for_a_signed_out_account_names_that_account() {
        let r = signed_out_listing();
        let e = list(&r, Some("ACCOUNTBBB000000000000BBB"), &Host::detect).unwrap_err();
        assert!(
            e.text().contains("ACCOUNTBBB000000000000BBB"),
            "{}",
            e.text()
        );
    }

    #[test]
    fn a_listing_for_a_signed_out_account_never_names_a_signed_in_identity() {
        let r = signed_out_listing();
        let e = list(&r, Some("ACCOUNTBBB000000000000BBB"), &Host::detect).unwrap_err();
        assert!(
            !e.text().contains("signed in to 1Password as"),
            "{}",
            e.text()
        );
    }

    /// A runner whose `op item list` fails every attempt and whose `op whoami --account`
    /// probe fails too (the account is signed out).
    fn signed_out_listing() -> FakeRunner {
        let mut responses: Vec<Output> = crate::runner::fake::failed_read(1).collect();
        responses.push(Output::failure(1));
        FakeRunner::new(responses)
    }

    #[test]
    fn template_holds_the_text_project_and_convention() {
        let t = template("opv · app", "app", &[MANIFEST_TAG.into()], "x = 1\n");
        let m = parse(t, "i").unwrap();
        assert_eq!(
            (m.text.as_str(), m.project.as_deref()),
            ("x = 1\n", Some("app"))
        );
    }

    #[test]
    fn a_new_manifest_note_opens_with_the_opv_heading() {
        assert!(note_with("x = 1\n", None, "app").starts_with("# opv managed configuration\n"));
    }

    #[test]
    fn the_configuration_is_read_from_the_code_block_only() {
        assert_eq!(config_text(&note_with("x = 1\n", None, "app")), "x = 1\n");
    }

    #[test]
    fn a_manifest_without_a_code_block_is_read_whole() {
        assert_eq!(config_text("x = 1\n"), "x = 1\n");
    }

    #[test]
    fn an_edit_keeps_what_a_person_wrote_around_the_code_block() {
        let before = "My notes\n```toml\nx = 1\n```\nMore notes\n";
        assert_eq!(
            note_with("x = 2\n", Some(before), "app"),
            "My notes\n```toml\nx = 2\n```\nMore notes\n"
        );
    }

    #[test]
    fn backticks_inside_the_configuration_never_end_its_code_block() {
        let config = "guidance = \"\"\"\n```\nnot the end\n```\n\"\"\"\n";
        assert_eq!(config_text(&note_with(config, None, "app")), config);
    }

    #[test]
    fn account_is_appended_to_argv() {
        assert_eq!(
            argv(&["item", "list"], Some("team")),
            ["item", "list", "--account", "team"]
        );
    }

    fn account(id: &str) -> Account {
        Account {
            account_uuid: id.into(),
            url: "my.1password.com".into(),
            email: "owner@example.com".into(),
            user_uuid: "USERUUID0000000000000000AA".into(),
            shorthand: "team".into(),
        }
    }

    /// I6: a failed manifest read hint names the account, so it cannot run against op's
    /// default account.
    #[test]
    fn a_failed_manifest_read_hint_names_the_account() {
        let mut responses: Vec<Output> = crate::runner::fake::failed_read(1).collect();
        responses.push(Output::failure(1));
        let r = FakeRunner::new(responses);
        let e = get(
            &r,
            "v",
            "i",
            Some("ACCOUNTUUID000000000000AAA"),
            false,
            &Host::detect,
        )
        .unwrap_err();
        assert!(
            e.text()
                .contains("op item get i --vault v --account ACCOUNTUUID000000000000AAA"),
            "{}",
            e.text()
        );
    }

    /// I7: several accounts and no choice: the step is opv's own list command, one
    /// command that runs as typed.
    #[test]
    fn choosing_among_several_accounts_steps_to_account_list() {
        let e = choose_error(&[
            account("ACCOUNTUUID000000000000AAA"),
            account("ACCOUNTUUID000000000000BBB"),
        ]);
        assert_eq!(e.next_step(), Some("opv account list"));
    }

    fn plain_linux() -> Host {
        Host::from_env(&crate::host::FakeEnv::new("linux").shell("/bin/bash"))
    }

    /// #157: no account on this machine keeps the step that adds one.
    #[test]
    fn a_failure_with_no_account_keeps_login_add() {
        let r = FakeRunner::new([Output::failure(1), Output::success("[]")]);
        let e = failure(&r, &plain_linux, "op item list failed", "the manifest");
        assert_eq!(e.next_step(), Some("opv login --add"));
    }

    /// #157: under CI `opv login` refuses, so it is never the step.
    #[test]
    fn a_failure_under_ci_never_steps_to_login() {
        let ci = || Host::from_env(&crate::host::FakeEnv::new("linux").var("CI"));
        let r = FakeRunner::new([Output::failure(1)]);
        let e = failure(&r, &ci, "op item list failed", "the manifest");
        assert_ne!(e.next_step(), Some(LOGIN));
    }

    /// Signed out at a person's terminal, the step is still `opv login`.
    #[test]
    fn a_signed_out_failure_steps_to_login() {
        let r = FakeRunner::new([Output::failure(1), Output::success(ONE_ACCOUNT)]);
        let e = failure(&r, &plain_linux, "op item list failed", "the manifest");
        assert_eq!(e.next_step(), Some(LOGIN));
    }

    /// #157: a write refused with no account on this machine keeps the step that adds one.
    #[test]
    fn a_refused_write_with_no_account_keeps_login_add() {
        let r = FakeRunner::new([Output::failure(1), Output::success("[]")]);
        let refused = Outcome::Refused(Output::failure(1));
        let e = write_failed(&r, &plain_linux, "op item edit", refused, "re-run");
        assert_eq!(e.next_step(), Some("opv login --add"));
    }

    fn wsl_windows_op() -> Host {
        Host::from_env(
            &crate::host::FakeEnv::new("linux")
                .var("WSL_DISTRO_NAME")
                .op_windows_exe(),
        )
    }

    /// In WSL with the Windows `op.exe`, an unknown account is added in the Windows app.
    #[test]
    fn wsl_windows_op_unknown_account_names_the_windows_app() {
        let e = crate::host::with_test_host(wsl_windows_op(), || {
            resolve(&[], "new@labs.example").unwrap_err()
        });
        assert!(
            e.action()
                .is_some_and(|a| a.contains("Windows 1Password app")),
            "{e:?}"
        );
    }

    /// In WSL with the Windows `op.exe`, opv never steps to adding the account at op's prompt.
    #[test]
    fn wsl_windows_op_unknown_account_never_adds_at_ops_prompt() {
        let e = crate::host::with_test_host(wsl_windows_op(), || {
            resolve(&[], "new@labs.example").unwrap_err()
        });
        assert_ne!(
            e.next_step(),
            Some("opv login --add --account new@labs.example")
        );
    }
}
