//! The simulated `flyctl` (flyctl v0.4.111). Failure replies come from
//! `tests/fixtures/fly/failures/`, success replies from `tests/fixtures/fly/success/`;
//! `status` and `releases` default to `tests/fixtures/fly/*-deployed.json`.
//!
//! Recorded success replies: `secrets list --json` (success 01-03: flyctl's indented array of
//! `{name, digest, status}`, `[]` for an app with no secrets; the world's rows are printed in
//! that layout) and `auth whoami` (success 04: the account's email, `<EMAIL>` unless the world
//! sets `fly.email`).
//!
//! Awaiting a recording: the stdout of `secrets import`, `secrets unset` and `secrets deploy`
//! (writes, never run against the owner's apps; the simulator prints nothing, and opv does not
//! read it), and `machine list --json` / `machine update --yes` (the owner skipped spikes S2
//! and S3, design `provider-operations` §8.1). A digest the simulator mints for an imported
//! value has the recorded shape (16 lowercase hex characters) but not Fly's value, which is
//! keyed server-side and cannot be computed (spike D0, Q4). `machine list` prints each world
//! Machine in flyctl's documented JSON shape (its `instance_id`/`created_at` synthesised from
//! the id, the rest as the world holds it), and `machine update` only moves the listed
//! Machine's `config.image`; both are documented, never recorded.
//!
//! ```json
//! "fly": {
//!   "signed_in": true,                       // false: no access token available
//!   "tokens": ["FlyV1 …"],                   // FLY_API_TOKEN / FLY_ACCESS_TOKEN values Fly accepts
//!   "apps": {"myapp": {"secrets": [{"name": "A", "digest": "…", "status": "Deployed",
//!                                   "value": "<marker>"}],
//!                      "machines": [{"id": "8edd22dc379d68", "name": "web",
//!                                    "state": "started", "region": "iad",
//!                                    "config": {"image": "registry.fly.io/myapp:v1",
//!                                               "env": {"K": "<marker>"}}}],
//!                      "status": { /* flyctl status --json */ },
//!                      "releases": [ /* flyctl releases --json */ ]}}
//! }
//! ```
//!
//! flyctl checks for a token before any network call (README, cases 01, 02, 08), so the
//! signed-out reply is the same text for every command.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::args::{flag, words};
use crate::faults::Kind;
use crate::recordings::{Reply, fixture, recorded};
use crate::world::World;

const BOOLEAN: &[&str] = &["--stage", "--json", "--detach", "--yes"];
const DIR: &str = "fly/failures";
const OK: &str = "fly/success";
/// The app name recorded in cases 10 (the recording's own made-up name).
const RECORDED_APP: &str = "opv-recording-nonexistent-app";

pub fn call_words(args: &[String]) -> Vec<String> {
    words(args, BOOLEAN)
}

fn app_of(args: &[String]) -> String {
    flag(args, "--app")
        .or_else(|| flag(args, "-a"))
        .unwrap_or_default()
        .to_string()
}

pub fn fault(kind: Kind, _world: &World, args: &[String]) -> Reply {
    let w = call_words(args);
    let ws: Vec<&str> = w.iter().map(String::as_str).collect();
    let case = |c: &str, subs: &[(&str, String)]| recorded(&format!("{DIR}/{c}"), subs);
    match (kind, ws.as_slice()) {
        (Kind::SignedOut, _) => case("01-signed-out-whoami", &[]),
        (Kind::CredentialRejected, ["auth", "whoami"]) => case("03-invalid-token-whoami", &[]),
        (Kind::CredentialRejected, ["secrets", ..]) => case("04-invalid-token-secrets-list", &[]),
        (Kind::NotFound, ["secrets", "list"]) => case("06-app-not-found-secrets-list", &[]),
        (Kind::Unreachable, ["auth", "whoami"]) => case("09-network-unreachable-whoami", &[]),
        (Kind::Unreachable, ["secrets", "list"]) => case(
            "10-network-unreachable-secrets-list",
            &[(RECORDED_APP, app_of(args))],
        ),
        _ => Reply::no_recording(&format!("{} on flyctl {}", kind.name(), w.join(" ")), DIR),
    }
}

pub fn run(world: &mut World, args: &[String]) -> Reply {
    let w = call_words(args);
    let ws: Vec<&str> = w.iter().map(String::as_str).collect();
    if ws == ["version"] {
        return recorded(&format!("{DIR}/12-version"), &[]);
    }
    let token = ["FLY_API_TOKEN", "FLY_ACCESS_TOKEN"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()));
    if let Some(t) = token {
        let known = world.doc["fly"]["tokens"]
            .as_array()
            .is_some_and(|ts| ts.iter().any(|x| x.as_str() == Some(t.as_str())));
        if !known {
            return fault(Kind::CredentialRejected, world, args);
        }
    } else if !world.doc["fly"]["signed_in"].as_bool().unwrap_or(true) {
        return fault(Kind::SignedOut, world, args);
    }
    let app = app_of(args);
    let exists = world.doc["fly"]["apps"].get(&app).is_some();
    match ws.as_slice() {
        ["auth", "whoami"] => {
            let email = world.doc["fly"]["email"].as_str().unwrap_or("<EMAIL>");
            recorded(
                &format!("{OK}/04-auth-whoami"),
                &[("<EMAIL>", email.to_string())],
            )
        }
        _ if !exists && ws.first() != Some(&"auth") => {
            if ws == ["secrets", "list"] {
                fault(Kind::NotFound, world, args)
            } else {
                Reply::no_recording(&format!("flyctl {} on a missing app", w.join(" ")), DIR)
            }
        }
        ["secrets", "list"] => {
            let rows: Vec<Value> = secrets(world, &app)
                .iter()
                .map(|s| json!({"name": s["name"], "digest": s["digest"], "status": s["status"]}))
                .collect();
            listed(&rows)
        }
        ["secrets", "import"] => {
            let mut input = Vec::new();
            let _ = std::io::Read::read_to_end(&mut std::io::stdin(), &mut input);
            let Some(pairs) = parse_import(&String::from_utf8_lossy(&input)) else {
                return Reply::no_recording("flyctl secrets import of input it cannot parse", DIR);
            };
            let list = world.array_at(&format!("/fly/apps/{app}/secrets"));
            for (name, value) in pairs {
                list.retain(|s| s["name"] != name.as_str());
                list.push(json!({"name": name, "digest": digest(&value),
                                 "status": "Staged", "value": value}));
            }
            Reply::silent()
        }
        ["secrets", "unset", names @ ..] => {
            let list = world.array_at(&format!("/fly/apps/{app}/secrets"));
            list.retain(|s| !names.iter().any(|n| s["name"] == *n));
            Reply::silent()
        }
        ["secrets", "deploy"] => {
            for s in world.array_at(&format!("/fly/apps/{app}/secrets")) {
                s["status"] = json!("Deployed");
            }
            Reply::silent()
        }
        ["machine", "list"] => {
            let rows: Vec<Value> = machines(world, &app)
                .iter()
                .map(|m| {
                    json!({
                        "id": m["id"],
                        "name": m["name"],
                        "state": m["state"],
                        "region": m["region"],
                        "instance_id": format!("{:0>26}", m["id"].as_str().unwrap_or_default()),
                        "created_at": "2026-01-01T00:00:00Z",
                        "config": {"image": m["config"]["image"],
                                   "env": m["config"]["env"].clone()},
                    })
                })
                .collect();
            Reply::json(&Value::Array(rows))
        }
        ["machine", "update", id] => {
            let image = flag(args, "--image").unwrap_or_default().to_string();
            let list = world.array_at(&format!("/fly/apps/{app}/machines"));
            let Some(machine) = list.iter_mut().find(|m| m["id"] == *id) else {
                return Reply::no_recording(
                    "flyctl machine update of an id not in the listing",
                    DIR,
                );
            };
            machine["config"]["image"] = json!(image);
            Reply::silent()
        }
        ["status"] => doc(world, &app, "status", "fly/status-deployed.json"),
        ["releases"] => doc(world, &app, "releases", "fly/releases-deployed.json"),
        _ => Reply::unsupported("flyctl", args),
    }
}

fn secrets(world: &World, app: &str) -> Vec<Value> {
    world.doc["fly"]["apps"][app]["secrets"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

/// The app's world Machines, in the documented shape (P6: `^[0-9a-f]{14}$`).
fn machines(world: &World, app: &str) -> Vec<Value> {
    world.doc["fly"]["apps"][app]["machines"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

/// The app's stored document `key`, else the recorded default.
fn doc(world: &World, app: &str, key: &str, default: &str) -> Reply {
    match world.doc["fly"]["apps"][app].get(key) {
        Some(v) => Reply::json(v),
        None => match fixture(default) {
            Some(text) => Reply::ok(text),
            None => Reply::no_recording(default, "fly"),
        },
    }
}

/// `secrets list --json` as flyctl prints it: the layout of success 01-03 (four-space
/// indent, `name`, `digest`, `status` in that order, a final newline; `[]` when empty).
fn listed(rows: &[Value]) -> Reply {
    use serde::Serialize;
    let mut out = Vec::new();
    let fmt = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    let mut ser = serde_json::Serializer::with_formatter(&mut out, fmt);
    if rows.serialize(&mut ser).is_err() {
        return Reply::no_recording("flyctl secrets list of rows it cannot print", OK);
    }
    out.push(b'\n');
    Reply::ok(out)
}

/// A digest that changes with the value (flyctl's own is opaque to opv).
fn digest(value: &str) -> String {
    hex::encode(&Sha256::digest(value.as_bytes())[..8])
}

/// `NAME="""VALUE"""` lines, as opv's `encode_import` writes them.
fn parse_import(mut text: &str) -> Option<Vec<(String, String)>> {
    const Q: &str = "\"\"\"";
    let mut out = Vec::new();
    while !text.is_empty() {
        let (name, rest) = text.split_once('=')?;
        let rest = rest.strip_prefix(Q)?;
        let end = rest.find(Q)?;
        out.push((name.to_string(), rest[..end].to_string()));
        text = rest[end + Q.len()..]
            .strip_prefix('\n')
            .unwrap_or(&rest[end + Q.len()..]);
    }
    Some(out)
}
