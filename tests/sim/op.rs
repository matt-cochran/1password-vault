//! The simulated `op` (1Password CLI 2.x): "1Password in a file". It answers from
//! `world.op`, applies edits to it, and enforces sessions, accounts and vault membership.
//! Failure replies come from `tests/fixtures/op/failures/` (op 2.40.0). `whoami --format json`
//! is recording 10; `item get` prints the world's stored item, a document of the recorded shape
//! of `tests/fixtures/op_item.json`.
//!
//! **Awaiting owner recording** (needs a 1Password session; the owner runs
//! `tests/fixtures/op/success/RECORD.md`): the JSON success shapes of `account list`,
//! `vault list`, `vault get`, `vault user list`, `vault create`, `item list`, `item create` and
//! `item edit`. Until then these print the world's rows in the fields opv reads, one compact
//! line, and are not taken from a recording.
//!
//! ```json
//! "op": {
//!   "default_account": "AAAA…",             // op's own default when no --account / OP_ACCOUNT
//!   "accounts": [{"id": "AAAA…", "shorthand": "my", "url": "my.1password.com",
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
        (Kind::NotFound, "vault") => case(
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
        let rows: Vec<Value> = accounts(world)
            .iter()
            .map(|a| {
                json!({"url": a["url"], "email": a["email"], "user_uuid": a["user"],
                       "account_uuid": a["id"], "shorthand": a["shorthand"]})
            })
            .collect();
        return Reply::json(&Value::Array(rows));
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
        if !a["signed_in"].as_bool().unwrap_or(false) {
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
        ["whoami"] => whoami(&account),
        ["vault", "list"] => Reply::json(&Value::Array(
            vaults_of(world, &acct)
                .iter()
                .map(|v| json!({"id": v["id"], "name": v["name"]}))
                .collect(),
        )),
        ["vault", "get", v] => match vault(world, &acct, v) {
            Ok(v) => Reply::json(&json!({"id": v["id"], "name": v["name"]})),
            Err(r) => r,
        },
        ["vault", "user", "list", v] => match vault(world, &acct, v) {
            Ok(v) => Reply::json(&v.get("users").cloned().unwrap_or_else(|| json!([]))),
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
        ["item", "list"] => item_list(world, &acct, args),
        ["item", "get", item] => match find_item(world, &acct, item, flag(args, "--vault")) {
            Ok(i) => Reply::json(&i),
            Err(r) => r,
        },
        ["item", "create"] => item_create(world, &acct, args),
        ["item", "edit", item] => item_edit(world, &acct, item, args),
        _ => Reply::unsupported("op", args),
    }
}

/// `op whoami --format json`: the shape of recording 10 with this account's identifiers.
fn whoami(a: &Value) -> Reply {
    let s = |k: &str| a[k].as_str().unwrap_or_default().to_string();
    let url = s("url");
    let address = url.strip_prefix("https://").unwrap_or(&url).to_string();
    let mut reply = recorded(
        &format!("{DIR}/10-whoami-a"),
        &[
            ("<ADDRESS>", address),
            ("<EMAIL_2>", s("email")),
            ("<USER_2>", s("user")),
            ("<ACCOUNT_2>", s("id")),
            ("<SHORTHAND_2>", s("shorthand")),
        ],
    );
    if let Some(t) = a["user_type"].as_str() {
        let text = String::from_utf8_lossy(&reply.stdout).replace("\"HUMAN\"", &format!("\"{t}\""));
        reply.stdout = text.into_bytes();
    }
    reply
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

fn item_list(world: &World, acct: &str, args: &[String]) -> Reply {
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
        .map(|i| {
            json!({"id": i["id"], "title": i["title"], "tags": i["tags"], "version": i["version"],
                   "vault": i["vault"], "category": i["category"]})
        })
        .collect();
    Reply::json(&Value::Array(rows))
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
