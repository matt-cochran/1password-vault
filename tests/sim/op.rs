//! The simulated `op` (1Password CLI 2.x): "1Password in a file". It answers from
//! `world.op`, applies edits to it, and enforces sessions, accounts and vault membership.
//! Failure replies come from `tests/fixtures/op/failures/` (op 2.40.0); `item get` prints the
//! world's stored item, a document of the recorded shape of `tests/fixtures/op_item.json`.
//!
//! **Success replies from the owner's recordings** (`tests/fixtures/op/success/`, op 2.40.0):
//! `account list` (s01), `vault list` (s02), `vault get` (s03), `vault user list` (s04),
//! `item list` (s05) and `whoami` (s06 with `--account` or `OP_ACCOUNT`, s07 without). Each
//! reply is the recording with its marker values (`<ACCOUNT_2>`, `<ID_n>`, `<NAME_n>`,
//! `<TITLE_n>`, …) and op's fixed values (`MEMBER`, `SECURE_NOTE`, …) replaced by the world's,
//! field by field, so it keeps op's field set, order, nesting and layout ([`op_layout`]). A
//! list repeats the recording's first element once per world entry. A field the world does not
//! hold keeps its recorded value (the times, a vault's `description` and `content_version`,
//! an item's `additional_information`, the IDs of vault users); a vault's `items` counts the
//! world's items in it, and an item's `last_edited_by` is the acting user unless the world
//! names one. A world account's `url` is printed as stored, so it holds op's form with
//! `https://` (recording 10). Not recorded, so kept as before: an item with no tags prints
//! `"tags": null`, and an empty list prints `[]`.
//!
//! **Awaiting owner recording** (`RECORD.md` §3, optional writes in a throwaway vault): the
//! JSON success shapes of `vault create`, `item create` and `item edit`. Until then these print
//! the world's rows in the fields opv reads, one compact line, and are not taken from a
//! recording.
//!
//! `op signin --force --account <id>` with a live session for another account on the same
//! sign-in address is recording 13 (a success with no output): it marks that account signed in
//! for the calls after it (#160). With no such session, real op prompts, which the simulator
//! does not model.
//!
//! ```json
//! "op": {
//!   "default_account": "AAAA…",             // op's own default when no --account / OP_ACCOUNT
//!   "accounts": [{"id": "AAAA…", "shorthand": "my", "url": "https://my.1password.com",
//!                 "email": "a@example.com", "user": "UUUU…", "user_type": "HUMAN",
//!                 "signed_in": true}],
//!   "service_account_tokens": ["ops_…"],    // OP_SERVICE_ACCOUNT_TOKEN values op accepts
//!   "vaults": [{"id": "v…", "name": "myapp-dev", "account": "AAAA…", "users": []}],
//!   "items": [ /* `op item get --format json` documents, marker values only */ ]
//! }
//! ```
//!
//! A failure whose recording covers one call of a family stands for the family, as the
//! recordings show op answering before it looks at the subcommand: signed out is 05 for
//! `whoami`, 06 for every `vault …` call and 07 for every `item …` call; a live session for
//! another account is 11 for `whoami` and 12 for `vault …` (op 2.40 says the same as signed
//! out there).

use serde_json::{Value, json};

use crate::args::{flag, words};
use crate::faults::Kind;
use crate::recordings::{Reply, recorded};
use crate::world::World;

const BOOLEAN: &[&str] = &["--reveal", "--raw", "--version", "--force"];
const DIR: &str = "op/failures";
const SUCCESS: &str = "op/success";

pub fn call_words(args: &[String]) -> Vec<String> {
    words(args, BOOLEAN)
}

/// The account a call names: `--account`, else `OP_ACCOUNT`.
fn named_account(args: &[String]) -> Option<String> {
    flag(args, "--account")
        .map(str::to_string)
        .or_else(|| std::env::var("OP_ACCOUNT").ok().filter(|a| !a.is_empty()))
}

fn accounts(world: &World) -> Vec<Value> {
    world.doc["op"]["accounts"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

/// The account record `name` matches (ID, shorthand, sign-in address or email).
fn find_account(world: &World, name: &str) -> Option<Value> {
    accounts(world).into_iter().find(|a| {
        ["id", "shorthand", "url", "email"]
            .iter()
            .any(|k| a[*k].as_str() == Some(name))
    })
}

fn default_account(world: &World) -> Option<Value> {
    match world.doc["op"]["default_account"].as_str() {
        Some(d) => find_account(world, d),
        None => accounts(world).into_iter().next(),
    }
}

fn id_of(account: &Value) -> String {
    account["id"].as_str().unwrap_or_default().to_string()
}

fn family(w: &[String]) -> &str {
    w.first().map(String::as_str).unwrap_or("")
}

/// The recorded reply for `kind` on this call, with the call's names substituted.
pub fn fault(kind: Kind, world: &World, args: &[String]) -> Reply {
    let w = call_words(args);
    let account = named_account(args)
        .or_else(|| default_account(world).map(|a| id_of(&a)))
        .unwrap_or_default();
    let vault = flag(args, "--vault")
        .map(str::to_string)
        .or_else(|| (family(&w) == "vault").then(|| w.last().cloned()).flatten())
        .unwrap_or_default();
    let missing = || Reply::no_recording(&format!("{} on op {}", kind.name(), w.join(" ")), DIR);
    let case = |c: &str, subs: &[(&str, String)]| recorded(&format!("{DIR}/{c}"), subs);
    match (kind, family(&w)) {
        (Kind::SignedOut, "whoami") => case("05-signed-out-whoami", &[("<ACCOUNT_2>", account)]),
        (Kind::SignedOut, "vault") => case("06-signed-out-vault-list", &[]),
        (Kind::SignedOut, "item") => case("07-signed-out-item-get", &[]),
        (Kind::OtherAccountSession, "whoami") => {
            case("11-b-whoami-under-a-session", &[("<ACCOUNT_1>", account)])
        }
        (Kind::OtherAccountSession, "vault") => case("12-b-vault-list-under-a-session", &[]),
        (Kind::OtherAccountSession, "item") => case("07-signed-out-item-get", &[]),
        (Kind::AccountNotOnMachine, f) if f != "account" => case(
            "02-account-not-on-machine",
            &[("ZZZZZZZZZZZZZZZZZZZZZZZZZZ", account)],
        ),
        (Kind::CredentialRejected, _) => case("03-service-account-token-rejected", &[]),
        // `op vault list` names no vault, so no vault of it can be missing.
        (Kind::NotFound, "vault") if w.get(1).is_some_and(|s| s != "list") => case(
            "08-vault-not-found",
            &[("ZZZZZZZZZZZZZZZZZZZZZZZZZZ", vault)],
        ),
        (Kind::NotFound, "item") if w.get(1).is_some_and(|s| s == "get" || s == "edit") => case(
            "09-item-not-found",
            &[
                ("opv-recording-none", w.get(2).cloned().unwrap_or_default()),
                ("<VAULT_A>", vault),
            ],
        ),
        _ => missing(),
    }
}

/// Answer one `op` call from the world.
pub fn run(world: &mut World, args: &[String]) -> Reply {
    let w = call_words(args);
    if args.first().is_some_and(|a| a == "--version") {
        return recorded(&format!("{DIR}/01-version"), &[]);
    }
    if w.first().is_some_and(|s| s == "account") && w.get(1).is_some_and(|s| s == "list") {
        let rows: Vec<Value> = accounts(world).iter().map(account_row).collect();
        return from_recording("s01-account-list", |doc| per_entry(&doc, &rows));
    }
    // The acting identity: a service account token, else the named or default account.
    let account = if let Ok(token) = std::env::var("OP_SERVICE_ACCOUNT_TOKEN") {
        let known = world.doc["op"]["service_account_tokens"]
            .as_array()
            .is_some_and(|t| t.iter().any(|t| t.as_str() == Some(token.as_str())));
        if !known {
            return fault(Kind::CredentialRejected, world, args);
        }
        let Some(mut a) = default_account(world) else {
            return fault(Kind::CredentialRejected, world, args);
        };
        a["user_type"] = json!("SERVICE_ACCOUNT");
        a["signed_in"] = json!(true);
        a
    } else {
        let named = named_account(args);
        let found = match &named {
            Some(n) => find_account(world, n),
            None => default_account(world),
        };
        let Some(a) = found else {
            return match named {
                Some(_) => fault(Kind::AccountNotOnMachine, world, args),
                None => fault(Kind::SignedOut, world, args),
            };
        };
        // A sign-in establishes the session, so `op signin` is answered even for an account
        // with none yet (#160); every other call needs an existing one.
        if !a["signed_in"].as_bool().unwrap_or(false) && family(&w) != "signin" {
            let other = accounts(world)
                .iter()
                .any(|o| o["id"] != a["id"] && o["signed_in"].as_bool().unwrap_or(false));
            let kind = if other {
                Kind::OtherAccountSession
            } else {
                Kind::SignedOut
            };
            return fault(kind, world, args);
        }
        a
    };
    let acct = id_of(&account);
    let ws: Vec<&str> = w.iter().map(String::as_str).collect();
    match ws.as_slice() {
        ["whoami"] => whoami(&account, named_account(args).is_some()),
        ["vault", "list"] => {
            let rows: Vec<Value> = vaults_of(world, &acct)
                .iter()
                .map(|v| vault_row(world, v))
                .collect();
            from_recording("s02-vault-list", |doc| per_entry(&doc, &rows))
        }
        ["vault", "get", v] => match vault(world, &acct, v) {
            Ok(v) => {
                let row = vault_row(world, &v);
                from_recording("s03-vault-get", |doc| filled(&doc, &row))
            }
            Err(r) => r,
        },
        ["vault", "user", "list", v] => match vault(world, &acct, v) {
            Ok(v) => {
                let users = v["users"].as_array().cloned().unwrap_or_default();
                from_recording("s04-vault-user-list", |doc| per_entry(&doc, &users))
            }
            // A vault of another account: recording 15 has 14's text.
            Err(r) => r,
        },
        ["vault", "create", name] => {
            let id = world.new_id("vsim");
            world
                .array_at("/op/vaults")
                .push(json!({"id": id, "name": name, "account": acct, "users": []}));
            Reply::json(&json!({"id": id, "name": name}))
        }
        ["item", "list"] => item_list(world, &account, args),
        ["item", "get", item] => match find_item(world, &acct, item, flag(args, "--vault")) {
            Ok(i) => Reply::json(&i),
            Err(r) => r,
        },
        ["item", "create"] => item_create(world, &acct, args),
        ["item", "edit", item] => item_edit(world, &acct, item, args),
        ["signin", ..] => {
            // #160: `op signin --force --account B` succeeds while another account's session
            // on the same sign-in address is live (recording 13, exit 0, no output). With no
            // such session, real op prompts, which the simulator does not model.
            let live_elsewhere = accounts(world).iter().any(|a| {
                a["id"].as_str() != Some(&acct) && a["signed_in"].as_bool().unwrap_or(false)
            });
            if !live_elsewhere {
                return Reply::unsupported("op", args);
            }
            // The sign-in starts this account's session, so the calls after it see it signed
            // in.
            if let Some(account) = world.doc["op"]["accounts"]
                .as_array_mut()
                .and_then(|all| all.iter_mut().find(|a| a["id"].as_str() == Some(&acct)))
            {
                account["signed_in"] = json!(true);
            }
            recorded(&format!("{DIR}/13-b-signin-with-a-session-live"), &[])
        }
        _ => Reply::unsupported("op", args),
    }
}

/// A world account in op's field names (`op account list`, `op whoami`).
fn account_row(a: &Value) -> Value {
    let mut row = json!({"url": a["url"], "email": a["email"], "user_uuid": a["user"],
                         "account_uuid": a["id"], "shorthand": a["shorthand"]});
    if let Some(t) = a.get("user_type") {
        row["user_type"] = t.clone();
    }
    row
}

/// `op whoami --format json`: recording s06 when the call names its account, else s07, with
/// this account's identifiers and user type.
fn whoami(a: &Value, named: bool) -> Reply {
    let case = if named {
        "s06-whoami-a"
    } else {
        "s07-whoami-default"
    };
    from_recording(case, |doc| filled(&doc, &account_row(a)))
}

/// A world vault as op lists it: its own fields, and `items` counting the world's items in it.
fn vault_row(world: &World, v: &Value) -> Value {
    let mut row = v.clone();
    let count = items(world)
        .iter()
        .filter(|i| i["vault"]["id"] == v["id"])
        .count();
    row["items"] = json!(count);
    row
}

/// The success recording `case` (under `op/success/`) rebuilt by `build` from its parsed JSON
/// and printed in op's layout, with the recording's exit code and stderr.
fn from_recording(case: &str, build: impl FnOnce(Value) -> Value) -> Reply {
    let mut reply = recorded(&format!("{SUCCESS}/{case}"), &[]);
    if reply.code != 0 {
        return reply;
    }
    let Ok(doc) = serde_json::from_slice::<Value>(&reply.stdout) else {
        return Reply::no_recording(&format!("{case}: its stdout is not JSON"), SUCCESS);
    };
    reply.stdout = op_layout(&build(doc)).into_bytes();
    reply
}

/// The recorded list `doc` with its first element repeated once per world entry, each
/// [`filled`] from that entry.
fn per_entry(doc: &Value, entries: &[Value]) -> Value {
    let template = doc.get(0).cloned().unwrap_or(Value::Null);
    Value::Array(entries.iter().map(|e| filled(&template, e)).collect())
}

/// The recorded element `template` with each of its fields the world `entry` holds replaced
/// by the entry's value (nested objects field by field). Fields only the entry holds are left
/// out, so the field set and order stay the recording's.
fn filled(template: &Value, entry: &Value) -> Value {
    let mut out = template.clone();
    if let (Some(fields), Some(world)) = (out.as_object_mut(), entry.as_object()) {
        for (key, value) in fields.iter_mut() {
            match world.get(key) {
                Some(w) if value.is_object() && w.is_object() => *value = filled(value, w),
                Some(w) => *value = w.clone(),
                None => {}
            }
        }
    }
    out
}

/// op's JSON layout, as its success recordings print it: two-space indent, `": "` after a
/// key, an array of plain values on one line joined by `", "`, a trailing newline.
fn op_layout(v: &Value) -> String {
    fn write(out: &mut String, v: &Value, indent: usize) {
        let pad = |out: &mut String, n: usize| out.push_str(&" ".repeat(n));
        match v {
            Value::Object(m) if !m.is_empty() => {
                out.push_str("{\n");
                for (i, (k, x)) in m.iter().enumerate() {
                    if i > 0 {
                        out.push_str(",\n");
                    }
                    pad(out, indent + 2);
                    out.push_str(&Value::String(k.clone()).to_string());
                    out.push_str(": ");
                    write(out, x, indent + 2);
                }
                out.push('\n');
                pad(out, indent);
                out.push('}');
            }
            Value::Array(a) if a.iter().any(|x| x.is_object() || x.is_array()) => {
                out.push_str("[\n");
                for (i, x) in a.iter().enumerate() {
                    if i > 0 {
                        out.push_str(",\n");
                    }
                    pad(out, indent + 2);
                    write(out, x, indent + 2);
                }
                out.push('\n');
                pad(out, indent);
                out.push(']');
            }
            Value::Array(a) => {
                let parts: Vec<String> = a.iter().map(Value::to_string).collect();
                out.push('[');
                out.push_str(&parts.join(", "));
                out.push(']');
            }
            _ => out.push_str(&v.to_string()),
        }
    }
    let mut out = String::new();
    write(&mut out, v, 0);
    out.push('\n');
    out
}

/// The vaults of account `acct` (a vault with no `account` belongs to the default one).
fn vaults_of(world: &World, acct: &str) -> Vec<Value> {
    let default = default_account(world).map(|a| id_of(&a));
    world.doc["op"]["vaults"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|v| match v["account"].as_str() {
            Some(a) => a == acct,
            None => default.as_deref() == Some(acct),
        })
        .collect()
}

/// The vault `name` (ID or name) of account `acct`. A vault of another account gets
/// recording 14 (#157), an unknown one 08.
fn vault(world: &World, acct: &str, name: &str) -> Result<Value, Reply> {
    if let Some(v) = vaults_of(world, acct)
        .into_iter()
        .find(|v| v["id"] == name || v["name"] == name)
    {
        return Ok(v);
    }
    let elsewhere = world.doc["op"]["vaults"]
        .as_array()
        .is_some_and(|all| all.iter().any(|v| v["id"] == name || v["name"] == name));
    Err(if elsewhere {
        recorded(
            &format!("{DIR}/14-vault-in-other-account"),
            &[("<VAULT_B>", name.to_string())],
        )
    } else {
        recorded(
            &format!("{DIR}/08-vault-not-found"),
            &[("ZZZZZZZZZZZZZZZZZZZZZZZZZZ", name.to_string())],
        )
    })
}

fn items(world: &World) -> Vec<Value> {
    world.doc["op"]["items"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

/// The item `item` (ID or title), in `vault_arg` when given, else in any vault of `acct`.
fn find_item(
    world: &World,
    acct: &str,
    item: &str,
    vault_arg: Option<&str>,
) -> Result<Value, Reply> {
    let vault_ids: Vec<Value> = match vault_arg {
        Some(v) => vec![vault(world, acct, v)?["id"].clone()],
        None => vaults_of(world, acct)
            .into_iter()
            .map(|v| v["id"].clone())
            .collect(),
    };
    items(world)
        .into_iter()
        .find(|i| vault_ids.contains(&i["vault"]["id"]) && (i["id"] == item || i["title"] == item))
        .ok_or_else(|| {
            recorded(
                &format!("{DIR}/09-item-not-found"),
                &[
                    ("opv-recording-none", item.to_string()),
                    ("<VAULT_A>", vault_arg.unwrap_or_default().to_string()),
                ],
            )
        })
}

/// `op item list`: recording s05 per item, its tags as the world holds them (`null` when it
/// holds none, as before: an untagged item is not recorded) and `last_edited_by` the acting
/// user unless the world names one. Field values are never in it: the recording has no
/// `fields`, and [`filled`] adds none.
fn item_list(world: &World, account: &Value, args: &[String]) -> Reply {
    let acct = &id_of(account);
    let in_vault = match flag(args, "--vault") {
        Some(v) => match vault(world, acct, v) {
            Ok(v) => Some(v["id"].clone()),
            Err(r) => return r,
        },
        None => None,
    };
    let mine: Vec<Value> = vaults_of(world, acct)
        .into_iter()
        .map(|v| v["id"].clone())
        .collect();
    let tag = flag(args, "--tags");
    let rows: Vec<Value> = items(world)
        .into_iter()
        .filter(|i| mine.contains(&i["vault"]["id"]))
        .filter(|i| in_vault.as_ref().is_none_or(|v| &i["vault"]["id"] == v))
        .filter(|i| {
            tag.is_none_or(|t| {
                i["tags"].as_array().is_some_and(|tags| {
                    tags.iter().filter_map(Value::as_str).any(|x| {
                        t.split(',')
                            .any(|t| x == t || x.starts_with(&format!("{t}/")))
                    })
                })
            })
        })
        .map(|mut i| {
            if i.get("tags").is_none() {
                i["tags"] = Value::Null;
            }
            if i.get("last_edited_by").is_none() {
                i["last_edited_by"] = account["user"].clone();
            }
            i
        })
        .collect();
    from_recording("s05-item-list", |doc| per_entry(&doc, &rows))
}

fn read_stdin_json() -> Option<Value> {
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut std::io::stdin(), &mut buf).ok()?;
    serde_json::from_slice(&buf).ok()
}

/// `op item create [-] --vault <v> [--title <t>]`, the template on stdin.
fn item_create(world: &mut World, acct: &str, args: &[String]) -> Reply {
    let Some(v) = flag(args, "--vault") else {
        return Reply::unsupported("op", args);
    };
    let v = match vault(world, acct, v) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Some(mut item) = read_stdin_json() else {
        return Reply::no_recording("op item create with a template op cannot parse", DIR);
    };
    if let Some(t) = flag(args, "--title") {
        item["title"] = json!(t);
    }
    item["id"] = json!(world.new_id("isim"));
    item["vault"] = json!({"id": v["id"], "name": v["name"]});
    item["version"] = json!(1);
    world.array_at("/op/items").push(item.clone());
    Reply::json(&item)
}

/// `op item edit <item> --vault <v>`, the whole item on stdin: its fields, sections, tags
/// and title replace the stored ones and the version moves on.
fn item_edit(world: &mut World, acct: &str, item: &str, args: &[String]) -> Reply {
    let found = match find_item(world, acct, item, flag(args, "--vault")) {
        Ok(i) => i,
        Err(r) => return r,
    };
    let Some(new) = read_stdin_json() else {
        return Reply::no_recording("op item edit with a template op cannot parse", DIR);
    };
    let items = world.array_at("/op/items");
    let Some(stored) = items.iter_mut().find(|i| i["id"] == found["id"]) else {
        return Reply::unsupported("op", args);
    };
    for key in ["fields", "sections", "tags", "title"] {
        if let Some(v) = new.get(key) {
            stored[key] = v.clone();
        }
    }
    stored["version"] = json!(stored["version"].as_u64().unwrap_or(0) + 1);
    let written = stored.clone();
    Reply::json(&written)
}
