//! The project manifest in 1Password (FR-44): one Secure Note per project holding the
//! same TOML as `secrets.toml` in its notes, never a secret value.
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

use super::onepassword::{NO_CACHE, Session, diagnose, json_error, session_error};
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
                Error::Auth(_) => e
                    .map_text(|m| {
                        format!(
                            "this project's configuration lives in 1Password, which needs a \
                             session: {m}"
                        )
                    })
                    .with_next(LOGIN),
                other => other,
            }
        }
    }
}

/// One read; a call still failing after its retries is diagnosed.
fn read(
    r: &dyn CommandRunner,
    args: &[&str],
    host: &dyn Fn() -> Host,
    failed: &str,
    what: &str,
) -> Result<Vec<u8>, Error> {
    let call = Call::new(OP, args);
    let out = match r.read(&call, &[]) {
        Ok(Outcome::Done(o)) => o,
        Ok(Outcome::Refused(o)) => {
            let failed = format!("{failed} failed ({})", status_text(o.status));
            return Err(failure(r, host, &failed, what));
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

/// `who` is not an account this `op` knows. On Linux and in WSL, `op` keeps its own
/// accounts (in WSL it does not share the Windows app's: found live), so the step is
/// `op account add` for that email in this terminal; elsewhere, add it in the 1Password app.
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
    let own_op = matches!(host.platform, Platform::Linux | Platform::Wsl);
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
            .with_next(format!("op account add --email {who}"));
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
    .with_next("opv login --account <email>")
}

/// The accounts op knows (`op account list`, a free probe); empty when it fails.
pub fn accounts(r: &dyn CommandRunner) -> Vec<Account> {
    match r.probe(
        &Call::new(OP, &["account", "list", "--format", "json"]),
        crate::runner::PROBE_TIMEOUT,
    ) {
        Ok(o) if o.status == 0 => serde_json::from_slice::<Vec<Account>>(&o.stdout)
            .unwrap_or_default()
            .into_iter()
            .filter(|a| crate::config::is_id(&a.account_uuid))
            .collect(),
        _ => {
            let _ = crate::runner::take_failure_excerpt();
            Vec::new()
        }
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
        host,
        &format!("op item get {item_id} --vault {vault_id}"),
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
        text: notes.to_string(),
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
             "value": text},
            {"id": "project", "type": "STRING", "label": "project", "value": project},
            {"id": "convention", "type": "STRING", "label": "convention", "value": CONVENTION},
        ],
    })
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
            Ok(other) => session_error(other, &host(), Some(step), None)
                .expect("every other session fails")
                .with_next(LOGIN),
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
                Ok(other) => session_error(other, &host(), Some(step), None)
                    .expect("every other session fails")
                    .with_next(LOGIN),
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
    let notes = fields
        .iter_mut()
        .find(|f| f["purpose"] == "NOTES" || f["id"] == "notesPlain")
        .ok_or_else(|| Error::Source(format!("item {item_id} has no notes field").into()))?;
    notes["value"] = Value::String(text.to_string());
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
    fn account_is_appended_to_argv() {
        assert_eq!(
            argv(&["item", "list"], Some("team")),
            ["item", "list", "--account", "team"]
        );
    }
}
