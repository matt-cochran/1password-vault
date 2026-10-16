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

use super::onepassword::{
    Failed, NO_CACHE, established, failed_edit, failed_read, failed_read_from, op_spawn_error,
    unanswered, unfinished_edit, unreadable_reply,
};
use super::onepassword_diagnose::Facts;
use crate::cause::{
    AccountId, AccountRef, AccountSource, Cause, CreateKind, DiagnoseContext, Refind, ResourceKind,
    ResourceName, ResourceRef, SessionState, System,
};
use crate::error::Error;
use crate::host::Host;
use crate::runner::{Call, CommandRunner, CreateOutcome, Outcome};

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

/// What a manifest call is about: the account it was made in and the manifest item.
fn context(account: Option<&str>, item: Option<(&str, &str)>, write: bool) -> DiagnoseContext {
    DiagnoseContext {
        account: account.map(AccountId::new),
        resource: item.map(|(item, vault)| ResourceRef {
            kind: ResourceKind::Item,
            name: ResourceName::new(item),
            scope: Some(vault.to_string()),
        }),
        write,
        ..DiagnoseContext::default()
    }
}

/// A manifest read that failed (FR-26, design §5). With an account known (#135), its session
/// is probed for exactly that account, so a failure in one account is never reported as
/// another account's; when that probe cannot run, and without an account, the shared
/// session diagnosis runs.
fn diagnosis(
    r: &dyn CommandRunner,
    host: &dyn Fn() -> Host,
    account: Option<&str>,
    call: &Call,
    item: Option<(&str, &str)>,
) -> Error {
    let ctx = context(account, item, false);
    // Taken before any probe: a probe that fails must not take the call's reply.
    let failed = Failed::of(call);
    let signed = match account {
        Some(id) => crate::runner::diagnosing(|| signed_in(r, id)),
        None => None,
    };
    let (Some(id), Some(signed)) = (account, signed) else {
        return failed_read_from(r, host, &ctx, failed, None);
    };
    let cause = failed.diagnosed(&ctx, &Facts::from_process_env());
    if !matches!(cause, Cause::Unrecognized { .. }) {
        return failed.report(cause);
    }
    let cause = if signed {
        established(cause, format!("account {id} is signed in"))
    } else {
        Cause::NotSignedIn {
            system: System::OnePassword,
            account: Some(AccountId::new(id)),
            state: SessionState::SignedOut,
        }
    };
    failed.report(cause)
}

/// One read; a call still failing after its retries is diagnosed.
fn read(
    r: &dyn CommandRunner,
    args: &[&str],
    account: Option<&str>,
    host: &dyn Fn() -> Host,
    item: Option<(&str, &str)>,
) -> Result<Vec<u8>, Error> {
    let call = Call::new(OP, args);
    match r.read(&call, &[]) {
        Ok(Outcome::Done(o)) => Ok(o.stdout.to_vec()),
        Ok(Outcome::Refused(_)) => Err(diagnosis(r, host, account, &call, item)),
        Ok(Outcome::Unknown { .. }) => Err(unanswered(&call)),
        Err(e) => Err(op_spawn_error(r, &e, host)),
    }
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
    let out = read(r, &args, account, host, None)?;
    if out.iter().all(u8::is_ascii_whitespace) {
        return Ok(Vec::new());
    }
    let mut rows: Vec<Row> =
        serde_json::from_slice(&out).map_err(|e| unreadable_reply(&args, &e))?;
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
/// that lists the accounts. `who` came from `--account`; [`resolve_from`] names another
/// source.
pub fn resolve(accounts: &[Account], who: &str) -> Result<String, Error> {
    resolve_from(accounts, who, AccountSource::Flag)
}

/// [`resolve`] for an account value that `selected_by` chose (`OP_ACCOUNT`, a `.opv`, an
/// argument): an account op does not know names that source, never `--account` (C20).
pub fn resolve_from(
    accounts: &[Account],
    who: &str,
    selected_by: AccountSource,
) -> Result<String, Error> {
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
        [] => Err(not_known(who, selected_by)),
        // An address or email several accounts share: a person picks one by its account
        // ID (04.09); opv never takes the first.
        many => Err(Cause::AccountAmbiguous {
            given: who.to_string(),
            candidates: many
                .iter()
                .map(|a| AccountId::new(a.account_uuid.as_str()))
                .collect(),
        }
        .into()),
    }
}

/// `who` is not an account this `op` knows (04.10): it is added where op keeps its
/// accounts. On Linux and in WSL with a native `op`, `op` keeps its own (in WSL it does not
/// share the Windows app's: found live), so it is added at op's prompt (`opv login --add`,
/// with `--account` only for an email); with the Windows `op.exe` or on macOS and Windows,
/// in the 1Password app. The cause renders the step for the platform.
fn not_known(who: &str, selected_by: AccountSource) -> Error {
    let account = if who.contains('@') {
        AccountRef::Email(who.to_string())
    } else if crate::config::is_id(who) {
        AccountRef::Id(AccountId::new(who))
    } else {
        AccountRef::Shorthand(who.to_string())
    };
    let host = Host::detect();
    Cause::AccountNotOnMachine {
        account,
        selected_by,
        in_app: host.op_is_windows_exe()
            || matches!(
                host.platform,
                crate::host::Platform::MacOs | crate::host::Platform::Windows
            ),
    }
    .into()
}

/// Several accounts on this machine and none chosen for the project: opv never guesses and
/// never searches them all (each search asks the 1Password app about that account, and
/// none of them was granted to this project). The person picks one: `AccountRequired`,
/// whose public code stays `account_required` (docs/usage.md, and `doctor`'s skip of the
/// sign-in check).
pub fn choose_error(accounts: &[Account]) -> Error {
    Cause::AccountRequired {
        accounts: accounts
            .iter()
            .map(|a| crate::cause::AccountChoice {
                email: a.email.clone(),
                address: a
                    .url
                    .trim_start_matches("https://")
                    .trim_end_matches('/')
                    .to_string(),
                id: AccountId::new(a.account_uuid.as_str()),
            })
            .collect(),
    }
    .into()
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
        // The failure stays with the runner for the caller's diagnosis (E1).
        Ok(_) => Discovery::Unavailable,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Discovery::OpMissing,
        Err(_) => Discovery::Unavailable,
    }
}

/// Whether `op` holds a live session for `account_uuid` (FR-49): `op whoami --account <id>`,
/// exit status only (its output names the person and is dropped unread). It never prompts
/// and never asks the desktop app. `None` when the probe cannot run.
pub fn signed_in(r: &dyn CommandRunner, account_uuid: &str) -> Option<bool> {
    // H3 (#160): an empty account names none; never `op whoami --account ""`.
    if account_uuid.trim().is_empty() {
        return None;
    }
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
    let out = read(r, &args, account, host, Some((item_id, vault_id)))?;
    let raw: Value = serde_json::from_slice(&out).map_err(|e| unreadable_reply(&args, &e))?;
    parse(raw, item_id, vault_id)
}

/// The manifest fields of an item JSON document. An item tagged as a manifest without a
/// notes field holding text is not a Secure Note opv can use: it is left unchanged.
fn parse(raw: Value, item_id: &str, vault_id: &str) -> Result<Manifest, Error> {
    let fields = raw["fields"].as_array().cloned().unwrap_or_default();
    let notes = fields
        .iter()
        .find(|f| f["purpose"] == "NOTES" || f["id"] == "notesPlain")
        .and_then(|f| f["value"].as_str())
        .map(config_text)
        .ok_or_else(|| {
            Error::from(Cause::ItemUnusable {
                vault: Some(crate::cause::VaultId::new(vault_id)),
                title: raw["title"].as_str().unwrap_or(item_id).to_string(),
                problem: crate::cause::ItemProblem::WrongCategory,
            })
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

/// Create a manifest in `vault` (a vault title or ID, as op accepts). Returns the new
/// item's row. One create, never retried (X5): an unknown outcome, or a reply opv cannot
/// read, may have made the manifest (04.12); re-running is safe because the creating
/// command refuses when a manifest with this title already exists.
pub fn create(
    r: &dyn CommandRunner,
    vault: &str,
    item: &Value,
    account: Option<&str>,
    host: &dyn Fn() -> Host,
) -> Result<Row, Error> {
    let body = serde_json::to_vec(item).map_err(|_| Cause::Bug {
        site: "onepassword_manifest: the manifest item does not serialize",
    })?;
    let title = item["title"].as_str().unwrap_or_default().to_string();
    let args = argv(
        &["item", "create", "--vault", vault, "--format", "json", "-"],
        account,
    );
    let call = Call::new(OP, &args).with_stdin(Some(&body));
    let unknown = |failed: Failed| {
        let seen = failed.seen().clone();
        failed.report(Cause::CreateOutcomeUnknown {
            system: System::OnePassword,
            kind: CreateKind::Manifest,
            name: title.clone(),
            refind: Refind::ByTitle,
            seen,
        })
    };
    match r.create(&call, CreateKind::Manifest) {
        Ok(CreateOutcome::Done(o)) => {
            serde_json::from_slice(&o.stdout).map_err(|_| unknown(Failed::of(&call)))
        }
        Ok(CreateOutcome::Refused(_)) => {
            let mut ctx = context(account, None, false);
            ctx.create = Some((CreateKind::Manifest, title.clone(), Refind::ByTitle));
            Err(failed_read(r, host, &ctx, &call, None))
        }
        Ok(CreateOutcome::OutcomeUnknown(seen)) => Err(unknown(Failed::with_reply(seen))),
        Err(e) => Err(op_spawn_error(r, &e, host)),
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
    // `base` is the manifest as `get` read it, whose parse found its notes field: an item
    // without one here is opv's own error.
    let not_read = || {
        Error::from(Cause::Bug {
            site: "onepassword_manifest: an edit base without the notes get found",
        })
    };
    let mut item = base.clone();
    let fields = item["fields"].as_array_mut().ok_or_else(not_read)?;
    let project = fields
        .iter()
        .find(|f| f["label"] == "project")
        .and_then(|f| f["value"].as_str())
        .unwrap_or("this project")
        .to_string();
    let notes = fields
        .iter_mut()
        .find(|f| f["purpose"] == "NOTES" || f["id"] == "notesPlain")
        .ok_or_else(not_read)?;
    let previous = notes["value"].as_str().map(str::to_string);
    notes["value"] = Value::String(note_with(text, previous.as_deref(), &project));
    let body = serde_json::to_vec(&item).map_err(|_| Cause::Bug {
        site: "onepassword_manifest: the manifest item does not serialize",
    })?;
    let args = argv(
        &[
            "item", "edit", item_id, "--vault", vault_id, "--format", "json",
        ],
        account,
    );
    let call = Call::new(OP, &args).with_stdin(Some(&body));
    let ctx = context(account, Some((item_id, vault_id)), true);
    match r.write(&call) {
        Ok(Outcome::Done(o)) => Ok(match serde_json::from_slice::<Value>(&o.stdout) {
            Ok(v) => Written {
                version: v["version"].as_u64(),
                text: parse(v, item_id, vault_id).ok().map(|m| m.text),
            },
            Err(_) => Written::default(),
        }),
        // A refusal of an edit built from a fresh read is the missing Write grant unless
        // the session explains it (04.23); nothing changed.
        Ok(Outcome::Refused(_))
        | Ok(Outcome::Unknown {
            status: Some(_), ..
        }) => Err(failed_edit(r, host, &ctx, &call)),
        Ok(Outcome::Unknown { .. }) => Err(unfinished_edit(
            ctx.resource.clone().expect("the edit names its item"),
            &call,
        )),
        Err(e) => Err(op_spawn_error(r, &e, host)),
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
        assert_eq!(e.code_str(), "op_not_signed_in");
    }

    #[test]
    fn a_listing_for_a_signed_out_account_names_that_account() {
        let r = signed_out_listing();
        let e = list(&r, Some("ACCOUNTBBB000000000000BBB"), &Host::detect).unwrap_err();
        assert!(e.to_string().contains("ACCOUNTBBB000000000000BBB"), "{e}");
    }

    #[test]
    fn a_listing_for_a_signed_out_account_never_names_a_signed_in_identity() {
        let r = signed_out_listing();
        let e = list(&r, Some("ACCOUNTBBB000000000000BBB"), &Host::detect).unwrap_err();
        assert!(!e.to_string().contains("signed in to 1Password as"), "{e}");
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
        let m = parse(t, "i", "v").unwrap();
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

    /// #135: a failed read in an account names that account.
    #[test]
    fn a_failed_manifest_read_names_the_account_in_its_call() {
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
        assert!(e.to_string().contains("ACCOUNTUUID000000000000AAA"), "{e}");
    }

    /// I7: several accounts and no choice: the step is opv's own list command, one
    /// command that runs as typed.
    #[test]
    fn choosing_among_several_accounts_steps_to_account_list() {
        let e = choose_error(&[
            account("ACCOUNTUUID000000000000AAA"),
            account("ACCOUNTUUID000000000000BBB"),
        ]);
        assert!(
            crate::error::report(&e).contains("Next: opv account list"),
            "{}",
            crate::error::report(&e)
        );
    }

    /// I6: the catalog cause keeps the public code `account_required` (docs/usage.md,
    /// doctor's skip of the sign-in check).
    #[test]
    fn choosing_among_several_accounts_keeps_account_required() {
        let e = choose_error(&[
            account("ACCOUNTUUID000000000000AAA"),
            account("ACCOUNTUUID000000000000BBB"),
        ]);
        assert_eq!(e.code_str(), "account_required");
    }

    fn plain_linux() -> Host {
        Host::from_env(&crate::host::FakeEnv::new("linux").shell("/bin/bash"))
    }

    fn list_call() -> Call<'static> {
        Call::new(
            OP,
            &["item", "list", "--tags", MANIFEST_TAG, "--format", "json"],
        )
    }

    /// #157: no account on this machine is the account to add, never a sign-in.
    #[test]
    fn a_failure_with_no_account_is_account_not_registered() {
        let r = FakeRunner::new([Output::failure(1), Output::success("[]")]);
        let e = diagnosis(&r, &plain_linux, None, &list_call(), None);
        assert_eq!(e.code_str(), "account_not_registered");
    }

    /// #157: under CI `opv login` refuses, so it is never the step.
    #[test]
    fn a_failure_under_ci_never_steps_to_login() {
        let ci = || Host::from_env(&crate::host::FakeEnv::new("linux").var("CI"));
        let r = FakeRunner::new([Output::failure(1)]);
        let e = diagnosis(&r, &ci, None, &list_call(), None);
        assert_ne!(e.next_text().as_deref(), Some(LOGIN));
    }

    /// Signed out at a person's terminal, the cause is the missing session.
    #[test]
    fn a_signed_out_failure_is_op_not_signed_in() {
        let r = FakeRunner::new([Output::failure(1), Output::success(ONE_ACCOUNT)]);
        let e = diagnosis(&r, &plain_linux, None, &list_call(), None);
        assert_eq!(e.code_str(), "op_not_signed_in");
    }

    /// #157: a write refused with no account on this machine is the account to add.
    #[test]
    fn a_refused_write_with_no_account_is_account_not_registered() {
        let r = FakeRunner::new([Output::failure(1), Output::success("[]")]);
        let ctx = context(None, Some(("i", "v")), true);
        let e = failed_edit(
            &r,
            &plain_linux,
            &ctx,
            &Call::new(OP, &["item", "edit", "i"]),
        );
        assert_eq!(e.code_str(), "account_not_registered");
    }

    /// 04.23: an edit refused while signed in is the missing Write grant, never "check …
    /// then check … before re-running".
    #[test]
    fn a_refused_write_signed_in_is_vault_no_access() {
        let r = FakeRunner::new([Output::success(r#"{"user_type":"HUMAN"}"#)]);
        let ctx = context(None, Some(("i", "v")), true);
        let e = failed_edit(
            &r,
            &plain_linux,
            &ctx,
            &Call::new(OP, &["item", "edit", "i"]),
        );
        assert_eq!(e.code_str(), "vault_no_access");
    }

    fn wsl_windows_op() -> Host {
        Host::from_env(
            &crate::host::FakeEnv::new("linux")
                .var("WSL_DISTRO_NAME")
                .op_windows_exe(),
        )
    }

    #[test]
    fn wsl_windows_op_unknown_account_names_the_windows_app() {
        let e = crate::host::with_test_host(wsl_windows_op(), || {
            resolve(&[], "new@labs.example").unwrap_err()
        });
        let action = e.do_text();
        assert!(
            action
                .as_deref()
                .is_some_and(|a| a.contains("in the 1Password app")),
            "{action:?}"
        );
    }

    /// In WSL with the Windows `op.exe`, opv never steps to adding the account at op's prompt.
    #[test]
    fn wsl_windows_op_unknown_account_never_adds_at_ops_prompt() {
        let e = crate::host::with_test_host(wsl_windows_op(), || {
            resolve(&[], "new@labs.example").unwrap_err()
        });
        assert_ne!(
            e.next_text().as_deref(),
            Some("opv login --add --account new@labs.example")
        );
    }

    /// 04.12: a manifest create whose reply cannot be read may have made the manifest.
    #[test]
    fn a_created_manifest_with_an_unreadable_reply_is_create_outcome_unknown() {
        let r = FakeRunner::new([Output::success("not json")]);
        let item = template("myapp · opv", "myapp", &[], "");
        let e = create(&r, "v", &item, None, &Host::detect).unwrap_err();
        assert_eq!(e.code_str(), "create_outcome_unknown");
    }

    /// 04.10: an account op does not know is the account to add, never "account required".
    #[test]
    fn an_unknown_account_is_account_not_registered() {
        let e = resolve(&[], "ACCOUNTUUID000000000000ZZZ").unwrap_err();
        assert_eq!(e.code_str(), "account_not_registered");
    }

    /// 04.09: an address several accounts share is ambiguous, never the first one.
    #[test]
    fn a_shared_address_is_account_ambiguous() {
        let mut a = account("ACCOUNTUUID000000000000AAA");
        let mut b = account("ACCOUNTUUID000000000000BBB");
        a.url = "https://my.1password.com".into();
        b.url = "https://my.1password.com".into();
        let e = resolve(&[a, b], "my.1password.com").unwrap_err();
        assert_eq!(e.code_str(), "account_ambiguous");
    }
}
