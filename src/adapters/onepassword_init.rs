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

use std::collections::BTreeMap;

use serde::Deserialize;

use super::onepassword::{Session, diagnose, failed_op_error, json_error, read_op, session_error};
use crate::config;
use crate::domain::Environment;
use crate::error::Error;
use crate::host::Host;
use crate::runner::{CommandRunner, Output, status_text};

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
    /// The section label; `None` for a field outside any labelled section.
    pub section: Option<String>,
    /// True for a field inside a section object that has no label (or an empty one). The
    /// fleet reader rejects such a field; the simple reader treats it as unsectioned.
    pub unlabelled_section: bool,
    pub label: String,
    /// The 1Password field type (`CONCEALED`, `STRING`, `URL`, ...).
    pub ty: String,
}

/// The vault whose name is exactly `title` (case-sensitive). One `op vault list` call.
/// No match or several matches is `Error::Config` listing the candidates by name and ID.
pub fn resolve_vault(
    r: &dyn CommandRunner,
    title: &str,
    host: &dyn Fn() -> Host,
) -> Result<Named, Error> {
    #[derive(Deserialize)]
    struct Row {
        id: String,
        #[serde(default)]
        name: String,
    }
    let args = ["vault", "list", "--format", "json"];
    let out = list(r, &args, host, "op vault list", "the vault")?;
    let rows: Vec<Row> = parse_list(&out)?;
    let all = rows
        .into_iter()
        .map(|v| Named {
            id: v.id,
            name: v.name,
        })
        .collect();
    pick(all, title, "vault", "")
}

/// The item in `vault_id` whose title is exactly `title` (case-sensitive). One `op item
/// list --vault <vault_id>` call (item metadata only; it carries no field values).
pub fn resolve_item(
    r: &dyn CommandRunner,
    vault_id: &str,
    title: &str,
    host: &dyn Fn() -> Host,
) -> Result<Named, Error> {
    #[derive(Deserialize)]
    struct Row {
        id: String,
        #[serde(default)]
        title: String,
    }
    let args = ["item", "list", "--vault", vault_id, "--format", "json"];
    let failed = format!("op item list --vault {vault_id}");
    let out = list(r, &args, host, &failed, "the vault's items")?;
    let rows: Vec<Row> = parse_list(&out)?;
    let all = rows
        .into_iter()
        .map(|i| Named {
            id: i.id,
            name: i.title,
        })
        .collect();
    pick(all, title, "item", &format!(" in vault {vault_id}"))
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
        let env = Environment {
            vault_id: vault_id.to_string(),
            item_id: item_id.to_string(),
            target: None,
            modes: BTreeMap::new(),
        };
        return Err(failed_op_error(
            r,
            &env,
            host,
            &format!("op item get failed ({})", status_text(status)),
            "grant this identity access to the vault",
        ));
    }
    let raw: RawItem = serde_json::from_slice(&stdout).map_err(|e| json_error(&e))?;
    Ok(raw
        .fields
        .into_iter()
        .filter(|f| f.purpose.is_none())
        .map(|f| {
            let in_section = f.section.is_some();
            let section = f.section.and_then(|s| s.label).filter(|l| !l.is_empty());
            FieldShape {
                unlabelled_section: in_section && section.is_none(),
                section,
                label: f.label,
                ty: f.ty,
            }
        })
        .collect())
}

/// Run a list call; a non-zero exit is diagnosed (FR-26).
fn list(
    r: &dyn CommandRunner,
    args: &[&str],
    host: &dyn Fn() -> Host,
    failed: &str,
    what: &str,
) -> Result<Output, Error> {
    let out = read_op(r, args, host)?;
    if out.status == 0 {
        return Ok(out);
    }
    let failed = format!("{failed} failed ({})", status_text(out.status));
    Err(match diagnose(r, host) {
        Err(e) => e,
        Ok(Session::SignedIn(t)) => Error::Source(format!(
            "{failed}: signed in to 1Password as {t}\n  next: check that this identity can \
             see {what}"
        )),
        Ok(Session::Unknown) => {
            Error::Source(format!("{failed}; run `op {}` to see why", args.join(" ")))
        }
        Ok(s) => session_error(s, &host(), Some(&failed)).expect("every other session is an error"),
    })
}

/// A JSON array of rows; empty output is an empty list.
fn parse_list<T: for<'de> Deserialize<'de>>(out: &Output) -> Result<Vec<T>, Error> {
    if out.stdout.iter().all(u8::is_ascii_whitespace) {
        return Ok(Vec::new());
    }
    serde_json::from_slice(&out.stdout).map_err(|e| json_error(&e))
}

/// Exactly one entry named `title`, or `Error::Config` listing the candidates.
fn pick(mut all: Vec<Named>, title: &str, what: &str, scope: &str) -> Result<Named, Error> {
    all.sort_by(|a, b| (&a.name, &a.id).cmp(&(&b.name, &b.id)));
    let matches: Vec<&Named> = all.iter().filter(|n| n.name == title).collect();
    match matches.as_slice() {
        // The ID goes into argv next: check it like a hand-written ID (§10.2, SR-7) and never
        // echo an ID that fails the check.
        [one] if config::is_id(&one.id) => Ok((*one).clone()),
        [_] => Err(Error::Source(format!(
            "op returned an ID for the {what} titled {title:?}{scope} that is not a valid \
             1Password ID (^[A-Za-z0-9][A-Za-z0-9._-]*$); not used"
        ))),
        [] => Err(Error::Config(format!(
            "no {what} titled {title:?}{scope} (exact, case-sensitive match); candidates: {}",
            candidates(all.iter())
        ))),
        many => Err(Error::Config(format!(
            "{} {what}s are titled {title:?}{scope}; rename all but one in 1Password: {}",
            many.len(),
            candidates(many.iter().copied())
        ))),
    }
}

fn candidates<'a>(it: impl ExactSizeIterator<Item = &'a Named>) -> String {
    let n = it.len();
    if n == 0 {
        return "none".to_string();
    }
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
    s.join(", ")
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
        assert!(m.contains("no vault titled \"gamma\""), "{m}");
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
            assert_eq!(e.exit_code(), 4, "{e}");
            let m = e.to_string();
            assert!(m.contains("vault titled \"app\""), "{m}");
            if !bad.is_empty() {
                assert!(!m.contains(bad), "{m}");
            }
            let r = FakeRunner::new([items(&[(bad, "app")])]);
            let e = resolve_item(&r, "v1", "app", &linux).unwrap_err();
            assert_eq!(e.exit_code(), 4, "{e}");
            assert!(e.to_string().contains("item titled \"app\""), "{e}");
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
        assert!(m.contains("candidates: none"), "{m}");
    }

    #[test]
    fn failed_list_is_diagnosed() {
        // Signed in: Source (4) asking to check access.
        let r = FakeRunner::new(
            failed_read(1).chain([Output::success(br#"{"user_type":"USER"}"#.to_vec())]),
        );
        let e = resolve_vault(&r, "x", &linux).unwrap_err();
        assert_eq!(e.exit_code(), 4, "{e}");
        assert!(
            e.to_string().contains("op vault list failed (exit 1)"),
            "{e}"
        );
        // Not signed in: Auth (7) with the sign-in step.
        let r =
            FakeRunner::new(failed_read(1).chain([Output::failure(1), Output::success("[{}]")]));
        let e = resolve_item(&r, "v1", "x", &linux).unwrap_err();
        assert_eq!(e.exit_code(), 7, "{e}");
        assert!(e.to_string().contains("not signed in to 1Password"), "{e}");
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
        assert!(s[2].unlabelled_section && !s[0].unlabelled_section && !s[1].unlabelled_section);
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
        assert_eq!(e.exit_code(), 4);
        assert!(
            e.to_string().contains("item i1 not found in vault v1"),
            "{e}"
        );
    }
}
