//! Dev-time 1Password calls for `opv init` only (FR-23). Nothing else may use this module.
//!
//! - [`resolve_vault`] and [`resolve_item`] look a vault and an item up **by title**, once,
//!   so that `init` can write their IDs into `secrets.toml`. This is the single, documented
//!   exception to FR-13 (whole-item reads by ID). It is unreachable from `fly sync`,
//!   `fly plan`, `status`, `run` and `config export`, which keep reading by vault ID and item
//!   ID through [`super::onepassword`]. The module is `pub(crate)`, so the compiler keeps it
//!   inside the library, where only `app::init` calls it; a test in `app::init` runs every
//!   other command against a recording runner and asserts no title lookup is made.
//! - [`read_field_shapes`] reads the resolved item once (`op item get <item_id> --vault
//!   <vault_id> --format json`, the same call as the CI read) but deserializes only each
//!   field's section label, label, type and purpose. The `value` field is never
//!   deserialized: serde skips it without building a string, so no value is held in a
//!   Rust type at all (SR-1, SR-2). The raw `op` output stays in the runner's `Zeroizing`
//!   buffer and is wiped on drop (SR-8).
//!
//! Calls: `op vault list --format json`, `op item list --vault <vault_id> --format json`,
//! `op item get <item_id> --vault <vault_id> --format json` (three requests, at dev time).
//! Only fixed words and IDs go in argv; titles are matched in memory (SR-3, SR-7). Read-only
//! against 1Password (FR-11, SR-5). A failed call is diagnosed as in every other command
//! (FR-26, [`super::onepassword::diagnose`]).

use serde::Deserialize;

use super::onepassword::{Failed, OP, failed_read, op_spawn_error, read_op, unreadable_reply};
use crate::cause::{
    Cause, CreateKind, DiagnoseContext, During, OutputProblem, Refind, ResourceKind, ResourceName,
    ResourceRef, System, VaultId,
};
use crate::config;
use crate::domain::SecretValue;
use crate::error::Error;
use crate::host::Host;
use crate::runner::{Call, CommandRunner, CreateOutcome, Output};

/// At most this many candidates are listed in a no-match or several-matches error.
const MAX_CANDIDATES: usize = 20;

/// A vault or item: its ID and its title (vault `name`, item `title`). Titles are names,
/// never values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Named {
    pub id: String,
    pub name: String,
}

/// One item field without its value: what `init` needs to write a declared key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldShape {
    /// The section label; `None` for a field outside any labelled section (`init` gives
    /// it to the product `--product` names).
    pub section: Option<String>,
    pub label: String,
    /// The 1Password field type (`CONCEALED`, `STRING`, `URL`, ...).
    pub ty: String,
}

/// The vault whose name is exactly `title` (case-sensitive). One `op vault list` call.
/// No match, or several, is the catalog's `TitleLookup` listing the candidates by name and
/// ID.
#[cfg(test)]
pub fn resolve_vault(
    r: &dyn CommandRunner,
    title: &str,
    host: &dyn Fn() -> Host,
) -> Result<Named, Error> {
    find_vault(r, title, host)?.found()
}

/// [`resolve_vault`] telling "no such vault" apart from every other failure, so `init`
/// can create it for a person (FR-43).
pub fn find_vault(
    r: &dyn CommandRunner,
    title: &str,
    host: &dyn Fn() -> Host,
) -> Result<Lookup, Error> {
    #[derive(Deserialize)]
    struct Row {
        id: String,
        #[serde(default)]
        name: String,
    }
    let args = ["vault", "list", "--format", "json"];
    let out = list(r, &args, host, None)?;
    let rows: Vec<Row> = parse_list(&args, &out)?;
    let all = rows
        .into_iter()
        .map(|v| Named {
            id: v.id,
            name: v.name,
        })
        .collect();
    lookup(all, title, ResourceKind::Vault, None, &args)
}

/// Who can use `vault_id` (#96): the JSON array of `op vault user list <vault_id> --format
/// json` (type, state, permissions, name; read-only). `Ok(None)` when this person may not
/// see it (listing a vault's users needs managing it); a sign-in problem is an error.
pub fn vault_users(
    r: &dyn CommandRunner,
    vault_id: &str,
    host: &dyn Fn() -> Host,
) -> Result<Option<serde_json::Value>, Error> {
    let args = ["vault", "user", "list", vault_id, "--format", "json"];
    match list(r, &args, host, Some(vault_id)) {
        // A list op answered with but opv cannot read is op's unexpected output (A1), never
        // a list this person may not see.
        Ok(out) => serde_json::from_slice(&out.stdout)
            .map(Some)
            .map_err(|e| super::onepassword::unreadable_reply(&args, &e)),
        // Signed in, the listing is refused or not understood: this person may not manage
        // the vault. A session, account or credential problem is still reported.
        Err(e)
            if e.cause().is_some_and(|(c, _)| {
                matches!(
                    c,
                    Cause::MissingRight { .. }
                        | Cause::Unrecognized { .. }
                        | Cause::NotFound { .. }
                        | Cause::InOtherAccount { .. }
                )
            }) =>
        {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// The session's own `user_uuid` from `op whoami --format json` (#96): the identifier used
/// only to find this session's entry in a vault's user list ([`vault_users`]), never an
/// email, name or any other identity detail. `None` when whoami answers without one (for
/// example a service-account credential) or could not be read: the caller then reports the
/// capability as unknown rather than guessing, and never fails the read on this probe
/// alone (`require_session` already decided the session).
pub fn session_user(r: &dyn CommandRunner, host: &dyn Fn() -> Host) -> Option<String> {
    #[derive(Deserialize)]
    struct Who {
        #[serde(default)]
        user_uuid: Option<String>,
    }
    let args = ["whoami", "--format", "json"];
    let out = read_op(r, &args, host).ok()?;
    if out.status != 0 {
        return None;
    }
    let who: Who = serde_json::from_slice(&out.stdout).ok()?;
    who.user_uuid.filter(|id| !id.is_empty())
}

/// The item in `vault_id` whose title is exactly `title` (case-sensitive). One `op item
/// list --vault <vault_id>` call (item metadata only; it carries no field values).
#[cfg(test)]
pub fn resolve_item(
    r: &dyn CommandRunner,
    vault_id: &str,
    title: &str,
    host: &dyn Fn() -> Host,
) -> Result<Named, Error> {
    find_item(r, vault_id, title, host)?.found()
}

/// [`resolve_item`] telling "no such item" apart from every other failure (FR-43).
pub fn find_item(
    r: &dyn CommandRunner,
    vault_id: &str,
    title: &str,
    host: &dyn Fn() -> Host,
) -> Result<Lookup, Error> {
    #[derive(Deserialize)]
    struct Row {
        id: String,
        #[serde(default)]
        title: String,
    }
    let args = ["item", "list", "--vault", vault_id, "--format", "json"];
    let out = list(r, &args, host, Some(vault_id))?;
    let rows: Vec<Row> = parse_list(&args, &out)?;
    let all = rows
        .into_iter()
        .map(|i| Named {
            id: i.id,
            name: i.title,
        })
        .collect();
    lookup(all, title, ResourceKind::Item, Some(vault_id), &args)
}

/// Read the item once, by IDs, keeping only each field's section, label and type. Built-in
/// fields (with a `purpose`: notes, username, password) are left out: they are never keys.
pub fn read_field_shapes(
    r: &dyn CommandRunner,
    vault_id: &str,
    item_id: &str,
    host: &dyn Fn() -> Host,
) -> Result<Vec<FieldShape>, Error> {
    // No `value` member: serde skips it unread (see the module docs).
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
        #[serde(default)]
        purpose: Option<String>,
    }
    #[derive(Deserialize)]
    struct RawSection {
        #[serde(default)]
        label: Option<String>,
    }

    let args = [
        "item", "get", item_id, "--vault", vault_id, "--format", "json",
    ];
    let Output { status, stdout } = read_op(r, &args, host)?;
    if status != 0 {
        let ctx = DiagnoseContext {
            resource: Some(ResourceRef {
                kind: ResourceKind::Item,
                name: ResourceName::new(item_id),
                scope: Some(vault_id.to_string()),
            }),
            ..DiagnoseContext::default()
        };
        return Err(failed_read(
            r,
            host,
            &ctx,
            &Call::new(OP, &args),
            Some(vault_id),
        ));
    }
    let raw: RawItem = serde_json::from_slice(&stdout).map_err(|e| unreadable_reply(&args, &e))?;
    Ok(raw
        .fields
        .into_iter()
        .filter(|f| f.purpose.is_none())
        .map(|f| {
            let section = f.section.and_then(|s| s.label).filter(|l| !l.is_empty());
            FieldShape {
                section,
                label: f.label,
                ty: f.ty,
            }
        })
        .collect())
}

/// Run a list call; a non-zero exit is diagnosed (FR-26, design §5), about `vault` when
/// the listing is of one.
fn list(
    r: &dyn CommandRunner,
    args: &[&str],
    host: &dyn Fn() -> Host,
    vault: Option<&str>,
) -> Result<Output, Error> {
    let out = read_op(r, args, host)?;
    if out.status == 0 {
        return Ok(out);
    }
    let ctx = DiagnoseContext {
        resource: vault.map(|v| ResourceRef {
            kind: ResourceKind::Vault,
            name: ResourceName::new(v),
            scope: None,
        }),
        ..DiagnoseContext::default()
    };
    // The vault is not probed here: callers that need to tell access apart probe it
    // themselves (`opv ready`), and each probe is one more call against a rate limit.
    Err(failed_read(r, host, &ctx, &Call::new(OP, args), None))
}

/// A JSON array of rows (the reply of `op <args>`); empty output is an empty list.
fn parse_list<T: for<'de> Deserialize<'de>>(args: &[&str], out: &Output) -> Result<Vec<T>, Error> {
    if out.stdout.iter().all(u8::is_ascii_whitespace) {
        return Ok(Vec::new());
    }
    serde_json::from_slice(&out.stdout).map_err(|e| unreadable_reply(args, &e))
}

/// A title lookup: the one match, or no match with the error that names the candidates.
#[derive(Debug)]
pub enum Lookup {
    Found(Named),
    Missing(Error),
}

impl Lookup {
    /// The match, or the no-match error.
    pub fn found(self) -> Result<Named, Error> {
        match self {
            Lookup::Found(n) => Ok(n),
            Lookup::Missing(e) => Err(e),
        }
    }
}

/// Exactly one entry named `title`; none is [`Lookup::Missing`] (`TitleLookup` listing the
/// candidates); several (`TitleLookup` listing them), or an invalid ID in the reply of `op
/// <args>` (`UnexpectedOutput`), is an error.
fn lookup(
    mut all: Vec<Named>,
    title: &str,
    kind: ResourceKind,
    vault: Option<&str>,
    args: &[&str],
) -> Result<Lookup, Error> {
    all.sort_by(|a, b| (&a.name, &a.id).cmp(&(&b.name, &b.id)));
    let matches: Vec<&Named> = all.iter().filter(|n| n.name == title).collect();
    let vault = vault.map(VaultId::new);
    match matches.as_slice() {
        // The ID goes into argv next: check it like a hand-written ID (§10.2, SR-7) and never
        // echo an ID that fails the check.
        [one] if config::is_id(&one.id) => Ok(Lookup::Found((*one).clone())),
        [_] => Err(invalid_id(kind, args)),
        [] => Ok(Lookup::Missing(
            Cause::TitleLookup {
                kind,
                title: title.to_string(),
                vault,
                matches: 0,
                candidates: candidates(all.iter()),
            }
            .into(),
        )),
        many => Err(Cause::TitleLookup {
            kind,
            title: title.to_string(),
            vault,
            matches: many.len(),
            candidates: candidates(many.iter().copied()),
        }
        .into()),
    }
}

/// op's listing answered with an ID that is not a 1Password ID: the reply of `op <args>`
/// is unusable (the ID is never echoed).
fn invalid_id(kind: ResourceKind, args: &[&str]) -> Error {
    let what = match kind {
        ResourceKind::Vault => "vault ID",
        _ => "item ID",
    };
    match crate::runner::take_unusable_reply(&Call::new(OP, args)) {
        Some(seen) => Cause::UnexpectedOutput {
            system: System::OnePassword,
            at: None,
            problem: OutputProblem::InvalidValue { what },
            during: During::Read,
            seen,
        }
        .into(),
        None => Cause::Bug {
            site: "onepassword_init: an op listing with an invalid ID left no observation",
        }
        .into(),
    }
}

/// One typed field of the template [`create_item_with_secret_fields`] serializes: no value
/// is ever held outside the zeroizing template buffer.
#[derive(serde::Serialize)]
struct SecretFieldTemplate<'a> {
    id: &'a str,
    label: &'a str,
    #[serde(rename = "type")]
    ty: &'static str,
    value: &'a str,
}

/// The `op item create` template, serialized straight into a zeroizing buffer (SR-8).
#[derive(serde::Serialize)]
struct ItemTemplate<'a> {
    category: &'static str,
    fields: Vec<SecretFieldTemplate<'a>>,
    sections: &'a [()],
    tags: &'a [String],
}

/// Create a Secure Note `title` in `vault_id` whose `fields` are one CONCEALED field per
/// `(label, value)` (FR-40), tagged with `tags` (names, never values). The template is
/// serialized directly into a zeroizing buffer and sent on `op item create`'s stdin only
/// (SR-3/SR-8); the value never reaches argv or an error. A person running `opv target
/// credentials --create` gets the new item's ID. `refind` is how a person finds the item
/// again when the create's outcome is unknown: never a re-run, which would mint again (X5).
pub fn create_item_with_secret_fields(
    r: &dyn CommandRunner,
    vault_id: &str,
    title: &str,
    tags: &[String],
    fields: &[(&str, &SecretValue)],
    refind: Refind,
) -> Result<Named, Error> {
    let args = [
        "item", "create", "-", "--vault", vault_id, "--title", title, "--format", "json",
    ];
    let template = ItemTemplate {
        category: "SECURE_NOTE",
        fields: fields
            .iter()
            .map(|(label, value)| SecretFieldTemplate {
                id: label,
                label,
                ty: "CONCEALED",
                value: value.expose(),
            })
            .collect(),
        sections: &[],
        tags,
    };
    let mut buf = zeroize::Zeroizing::new(Vec::with_capacity(256));
    serde_json::to_writer(&mut *buf, &template).map_err(|_| Cause::Bug {
        site: "onepassword_init: the item template does not serialize",
    })?;
    created(
        r,
        &args,
        Some(buf.as_slice()),
        CreateKind::ItemWithSecrets,
        title,
        Some(vault_id),
        refind,
    )
}

/// One non-idempotent create (X5): through [`CommandRunner::create`], never retried. A
/// refusal is diagnosed like any failed call (nothing was made); an unknown outcome, or a
/// create whose reply carries no ID, may have made the object (04.04): a vault or a plain
/// item is found again by its title on the next run ([`Refind::ByTitle`]), so re-running is
/// safe; an item holding secrets is found by the caller's `refind` and checked first, never
/// re-created (C21).
fn created(
    r: &dyn CommandRunner,
    args: &[&str],
    stdin: Option<&[u8]>,
    kind: CreateKind,
    title: &str,
    vault: Option<&str>,
    refind: Refind,
) -> Result<Named, Error> {
    #[derive(Deserialize)]
    struct Row {
        #[serde(default)]
        id: String,
    }
    let call = Call::new(OP, args).with_stdin(stdin);
    let unknown = |seen| unknown_create(kind, title, refind.clone(), seen);
    match r.create(&call, kind) {
        Ok(CreateOutcome::Done(o)) => match serde_json::from_slice::<Row>(&o.stdout) {
            Ok(row) if config::is_id(&row.id) => Ok(Named {
                id: row.id,
                name: title.to_string(),
            }),
            _ => Err(unknown(Failed::of(&call))),
        },
        Ok(CreateOutcome::Refused(_)) => {
            let ctx = DiagnoseContext {
                resource: Some(ResourceRef {
                    kind: match kind {
                        CreateKind::Vault => ResourceKind::Vault,
                        _ => ResourceKind::Item,
                    },
                    name: ResourceName::new(title),
                    scope: vault.map(str::to_string),
                }),
                create: Some((kind, title.to_string(), refind.clone())),
                ..DiagnoseContext::default()
            };
            // A refusal is a cause of its own: a caller that minted the secret wraps it in
            // what was already made (C21).
            Err(failed_read(r, &Host::detect, &ctx, &call, vault))
        }
        Ok(CreateOutcome::OutcomeUnknown(seen)) => Err(unknown(Failed::with_reply(seen))),
        Err(e) => Err(op_spawn_error(r, &e, &Host::detect)),
    }
}

/// A create that may or may not have made `title` (X5, design §4.6).
fn unknown_create(kind: CreateKind, title: &str, refind: Refind, failed: Failed) -> Error {
    let seen = failed.seen().clone();
    failed.report(Cause::CreateOutcomeUnknown {
        system: System::OnePassword,
        kind,
        name: title.to_string(),
        refind,
        seen,
    })
}

fn candidates<'a>(it: impl ExactSizeIterator<Item = &'a Named>) -> Vec<String> {
    let n = it.len();
    let mut s: Vec<String> = it
        .take(MAX_CANDIDATES)
        .map(|c| {
            let id = if config::is_id(&c.id) {
                c.id.as_str()
            } else {
                "invalid ID"
            };
            format!("{:?} ({id})", c.name)
        })
        .collect();
    if n > MAX_CANDIDATES {
        s.push(format!("and {} more", n - MAX_CANDIDATES));
    }
    s
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::host::FakeEnv;
    use crate::runner::fake::{FakeRunner, failed_read};

    fn linux() -> Host {
        Host::from_env(&FakeEnv::new("linux").shell("/bin/bash"))
    }

    fn argvs(r: &FakeRunner) -> Vec<String> {
        r.calls
            .borrow()
            .iter()
            .map(|c| format!("{} {}", c.program, c.args.join(" ")))
            .collect()
    }

    fn vaults(rows: &[(&str, &str)]) -> Output {
        let v: Vec<_> = rows
            .iter()
            .map(|(id, n)| json!({"id": id, "name": n, "content_version": 3}))
            .collect();
        Output::success(serde_json::to_vec(&v).unwrap())
    }

    fn items(rows: &[(&str, &str)]) -> Output {
        let v: Vec<_> = rows
            .iter()
            .map(|(id, t)| json!({"id": id, "title": t, "category": "SECURE_NOTE"}))
            .collect();
        Output::success(serde_json::to_vec(&v).unwrap())
    }

    #[test]
    fn vault_exact_match_is_one_list_call() {
        let r = FakeRunner::new([vaults(&[("v1", "app-staging"), ("v2", "App-Staging")])]);
        let v = resolve_vault(&r, "App-Staging", &linux).unwrap();
        assert_eq!(v.id, "v2");
        assert_eq!(argvs(&r), vec!["op vault list --format json"]);
    }

    #[test]
    fn vault_no_match_lists_candidates_by_name_and_id() {
        let r = FakeRunner::new([vaults(&[("v1", "alpha"), ("v2", "beta")])]);
        let e = resolve_vault(&r, "gamma", &linux).unwrap_err();
        assert_eq!(e.exit_code(), 2);
        let m = e.to_string();
        assert!(m.contains("no vault is titled \"gamma\""), "{m}");
        assert!(m.contains("\"alpha\" (v1), \"beta\" (v2)"), "{m}");
    }

    #[test]
    fn item_several_matches_lists_them() {
        let r = FakeRunner::new([items(&[("i1", "app"), ("i2", "app"), ("i3", "other")])]);
        let e = resolve_item(&r, "vX", "app", &linux).unwrap_err();
        assert_eq!(e.exit_code(), 2);
        let m = e.to_string();
        assert!(m.contains("2 items are titled \"app\" in vault vX"), "{m}");
        assert!(m.contains("\"app\" (i1), \"app\" (i2)"), "{m}");
        assert!(!m.contains("i3"), "{m}");
        assert_eq!(argvs(&r), vec!["op item list --vault vX --format json"]);
    }

    #[test]
    fn titles_never_reach_argv() {
        let r = FakeRunner::new([vaults(&[("v1", "TITLEMARK")]), items(&[("i1", "ITEMMARK")])]);
        resolve_vault(&r, "TITLEMARK", &linux).unwrap();
        resolve_item(&r, "v1", "ITEMMARK", &linux).unwrap();
        assert!(!r.argv_contains("TITLEMARK") && !r.argv_contains("ITEMMARK"));
    }

    #[test]
    fn candidates_are_capped() {
        let rows: Vec<(String, String)> = (0..25)
            .map(|i| (format!("v{i:02}"), format!("n{i:02}")))
            .collect();
        let refs: Vec<(&str, &str)> = rows.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        let r = FakeRunner::new([vaults(&refs)]);
        let m = resolve_vault(&r, "zzz", &linux).unwrap_err().to_string();
        assert!(m.contains("and 5 more"), "{m}");
        assert!(!m.contains("n24"), "{m}");
    }

    /// IDs from `op` go into argv: an invalid one is refused, naming the title, never echoed.
    #[test]
    fn invalid_id_from_op_is_refused_without_echoing_it() {
        for bad in ["-rf", "a b", "", "x;y"] {
            let r = FakeRunner::new([vaults(&[(bad, "app")])]);
            let e = resolve_vault(&r, "app", &linux).unwrap_err();
            assert_eq!(e.code_str(), "unexpected_output", "{e}");
            let m = crate::error::report(&e);
            if !bad.is_empty() {
                assert!(!m.contains(bad), "{m}");
            }
            let r = FakeRunner::new([items(&[(bad, "app")])]);
            let e = resolve_item(&r, "v1", "app", &linux).unwrap_err();
            assert_eq!(e.code_str(), "unexpected_output", "{e}");
        }
        // In a candidate list, an invalid ID is replaced too.
        let r = FakeRunner::new([vaults(&[("--evil", "other")])]);
        let m = resolve_vault(&r, "app", &linux).unwrap_err().to_string();
        assert!(
            m.contains("\"other\" (invalid ID)") && !m.contains("--evil"),
            "{m}"
        );
    }

    #[test]
    fn empty_list_output_is_no_candidates() {
        let r = FakeRunner::new([Output::success(Vec::new())]);
        let m = resolve_item(&r, "v1", "x", &linux).unwrap_err().to_string();
        assert!(m.contains("there are none to choose from"), "{m}");
    }

    /// Signed in, a listing that keeps failing is unrecognised, with what opv checked.
    #[test]
    fn failed_list_while_signed_in_is_unrecognized() {
        let r = FakeRunner::new(
            failed_read(1).chain([Output::success(br#"{"user_type":"USER"}"#.to_vec())]),
        );
        let e = resolve_vault(&r, "x", &linux).unwrap_err();
        assert_eq!(e.code_str(), "unrecognized_failure");
    }

    /// Not signed in, a failed listing is the missing session (exit 7).
    #[test]
    fn failed_list_signed_out_is_op_not_signed_in() {
        let r =
            FakeRunner::new(failed_read(1).chain([Output::failure(1), Output::success("[{}]")]));
        let e = resolve_item(&r, "v1", "x", &linux).unwrap_err();
        assert_eq!(e.code_str(), "op_not_signed_in");
    }

    #[test]
    fn missing_op_is_dependency_error() {
        let r = FakeRunner::default();
        r.push_io_error(std::io::ErrorKind::NotFound);
        let e = resolve_vault(&r, "x", &linux).unwrap_err();
        assert_eq!(e.exit_code(), 3, "{e}");
    }

    #[test]
    fn shapes_never_hold_values_and_skip_builtins() {
        let item = json!({
            "id": "i1",
            "fields": [
                {"id": "notesPlain", "type": "STRING", "purpose": "NOTES", "label": "notesPlain",
                 "value": "NOTEMARKER"},
                {"id": "a", "type": "CONCEALED", "label": "TOKEN", "value": "VALUEMARKER"},
                {"id": "b", "type": "STRING", "label": "MODE", "section": {"id": "s", "label": "api"},
                 "value": "VALUEMARKER\\u0041"},
                {"id": "c", "type": "STRING", "label": "X", "section": {"id": "s2"}},
            ]
        });
        let r = FakeRunner::new([Output::success(serde_json::to_vec(&item).unwrap())]);
        let s = read_field_shapes(&r, "v1", "i1", &linux).unwrap();
        assert_eq!(argvs(&r), vec!["op item get i1 --vault v1 --format json"]);
        assert_eq!(s.len(), 3);
        assert_eq!(s[0].section, None);
        assert_eq!(s[1].section.as_deref(), Some("api"));
        assert_eq!(
            s[2].section, None,
            "a section without a label is unsectioned"
        );
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("MARKER"), "{dbg}");
    }

    #[test]
    fn failed_item_read_is_diagnosed_naming_ids() {
        let r = FakeRunner::new(failed_read(1).chain([
            Output::success(br#"{"user_type":"SERVICE_ACCOUNT"}"#.to_vec()),
            Output::success(b"{}".to_vec()),
        ]));
        let e = read_field_shapes(&r, "v1", "i1", &linux).unwrap_err();
        assert_eq!(e.to_string(), "item i1 in v1 was not found at 1Password");
    }

    /// 04.26: a listing op answered with JSON opv cannot read is an unexpected output.
    #[test]
    fn an_unreadable_vault_list_is_unexpected_output() {
        let r = FakeRunner::new([Output::success("not json")]);
        let e = resolve_vault(&r, "x", &linux).unwrap_err();
        assert_eq!(e.code_str(), "unexpected_output");
    }

    /// 09 (malformed op output): the step is opv doctor, never the same command again.
    #[test]
    fn an_unreadable_vault_list_steps_to_doctor() {
        let r = FakeRunner::new([Output::success("not json")]);
        let e = resolve_vault(&r, "x", &linux).unwrap_err();
        assert_eq!(e.next_text().unwrap_or_default(), "opv doctor");
    }
}
