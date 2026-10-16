//! The simulated `gh` (GitHub CLI). Failure replies come from
//! `tests/fixtures/github/failures/` (gh 2.102.0) and the older `stderr-*.txt` /
//! `exit-*.txt` pairs beside them; list shapes from `secret-list*.json` and
//! `variable-list*.json`.
//!
//! ```json
//! "github": {
//!   "signed_in": true,
//!   "tokens": ["…"],                         // GH_TOKEN / GITHUB_TOKEN values GitHub accepts
//!   "repos": {"owner/name": {
//!     "secrets": {"NAME": {"updatedAt": "…", "value": "<marker>"}},
//!     "variables": {"NAME": {"updatedAt": "…", "value": "…"}},
//!     "environments": {"staging": {"secrets": {}, "variables": {}}}}}
//! }
//! ```
//!
//! gh checks the credential before anything else (README, note on case 04), so the
//! signed-out reply (01, 05) is the same text for every command.

use serde_json::{Map, Value, json};

use crate::args::{flag, words};
use crate::faults::Kind;
use crate::recordings::{Reply, recorded, recorded_pair};
use crate::world::World;

const BOOLEAN: &[&str] = &["--silent", "-i", "--version", "--app"];
const DIR: &str = "github/failures";
const RECORDED_REPO: &str = "example-org/example-repo";

pub fn call_words(args: &[String]) -> Vec<String> {
    words(args, BOOLEAN)
}

fn repo_of(args: &[String]) -> String {
    flag(args, "-R")
        .or_else(|| flag(args, "--repo"))
        .unwrap_or_default()
        .to_string()
}

fn env_of(args: &[String]) -> Option<String> {
    flag(args, "-e")
        .or_else(|| flag(args, "--env"))
        .map(str::to_string)
}

pub fn fault(kind: Kind, _world: &World, args: &[String]) -> Reply {
    let w = call_words(args);
    let ws: Vec<&str> = w.iter().map(String::as_str).collect();
    let (repo, env) = (repo_of(args), env_of(args));
    let pair = |c: &str, subs: &[(&str, String)]| recorded_pair("github", c, subs);
    match (kind, ws.as_slice(), env) {
        (Kind::SignedOut, [first, ..], _) if *first != "auth" => {
            recorded(&format!("{DIR}/01-not-signed-in"), &[])
        }
        (Kind::CredentialRejected, ["api", ..], _) => {
            recorded(&format!("{DIR}/02-invalid-token"), &[])
        }
        (Kind::CredentialRejected, ["secret", "list"], None) => {
            pair("bad_token", &[(RECORDED_REPO, repo)])
        }
        (Kind::NotFound, ["secret", "list"], None) => {
            pair("repo_missing", &[("example-org/missing-repo", repo)])
        }
        (Kind::NotFound, ["secret", "list"], Some(e)) => pair(
            "env_missing_list",
            &[
                (RECORDED_REPO, repo),
                ("environments/nope/", format!("environments/{e}/")),
            ],
        ),
        (Kind::NotFound, ["secret", "set", _], Some(e)) => pair(
            "env_missing_set",
            &[
                (RECORDED_REPO, repo),
                ("environments/staging/", format!("environments/{e}/")),
            ],
        ),
        (Kind::NotFound, ["secret", "delete", name], None) => pair(
            "del_missing",
            &[(RECORDED_REPO, repo), ("OPV_NOPE", name.to_string())],
        ),
        _ => Reply::no_recording(&format!("{} on gh {}", kind.name(), w.join(" ")), DIR),
    }
}

/// What a fault changes in the world before it is answered: a `not_found` on a listing or
/// write in a GitHub environment is that environment missing (the recorded 404 says so), so
/// the repository's environments read afterwards no longer lists it. `true` when it changed.
/// An environment marked `"listed_after_not_found": true` stays listed: its 404 has a cause
/// opv cannot see, so the scenario reaches the reply opv does not recognise.
pub fn fault_effect(kind: Kind, world: &mut World, args: &[String]) -> bool {
    let w = call_words(args);
    let (repo, env) = (repo_of(args), env_of(args));
    match (
        kind,
        w.first().map(String::as_str),
        w.get(1).map(String::as_str),
        env,
    ) {
        (Kind::NotFound, Some("secret"), Some("list" | "set"), Some(e)) => {
            let pointer = format!("/github/repos/{}/environments", repo.replace('/', "~1"));
            world
                .doc
                .pointer_mut(&pointer)
                .and_then(Value::as_object_mut)
                .filter(|envs| {
                    envs.get(&e)
                        .is_some_and(|v| v["listed_after_not_found"] != Value::Bool(true))
                })
                .is_some_and(|envs| envs.remove(&e).is_some())
        }
        _ => false,
    }
}

pub fn run(world: &mut World, args: &[String]) -> Reply {
    if args.first().is_some_and(|a| a == "--version") {
        return recorded(&format!("{DIR}/06-version"), &[]);
    }
    let w = call_words(args);
    let ws: Vec<&str> = w.iter().map(String::as_str).collect();
    let token = ["GH_TOKEN", "GITHUB_TOKEN"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()));
    let signed_in = match token {
        Some(t) => {
            let known = world.doc["github"]["tokens"]
                .as_array()
                .is_some_and(|ts| ts.iter().any(|x| x.as_str() == Some(t.as_str())));
            if !known {
                return fault(Kind::CredentialRejected, world, args);
            }
            true
        }
        None => world.doc["github"]["signed_in"].as_bool().unwrap_or(true),
    };
    if !signed_in {
        return fault(Kind::SignedOut, world, args);
    }
    let (repo, env) = (repo_of(args), env_of(args));
    match ws.as_slice() {
        // Exit status only (opv reads nothing else); its text was not recorded.
        ["auth", "status"] => Reply::silent(),
        ["api", path] => api(world, args, path),
        [kind @ ("secret" | "variable"), verb, rest @ ..] => {
            let plural = format!("{kind}s");
            let Some(scope) = scope(world, &repo, env.as_deref()) else {
                return missing_scope(world, args, kind, verb, &repo, env.as_deref());
            };
            match (*verb, rest) {
                ("list", []) => list(world, &scope, &plural, flag(args, "--json")),
                ("set", [name]) => {
                    let mut value = Vec::new();
                    let _ = std::io::Read::read_to_end(&mut std::io::stdin(), &mut value);
                    let stamp = world.stamp();
                    world.object_at(&format!("{scope}/{plural}")).insert(
                        name.to_string(),
                        json!({"updatedAt": stamp, "value": String::from_utf8_lossy(&value)}),
                    );
                    Reply::silent()
                }
                ("delete", [name]) => {
                    if world
                        .object_at(&format!("{scope}/{plural}"))
                        .remove(*name)
                        .is_some()
                    {
                        Reply::silent()
                    } else if *kind == "secret" && env.is_none() {
                        fault(Kind::NotFound, world, args)
                    } else {
                        Reply::no_recording(&format!("gh {} of a missing name", w.join(" ")), DIR)
                    }
                }
                _ => Reply::unsupported("gh", args),
            }
        }
        _ => Reply::unsupported("gh", args),
    }
}

/// The world pointer of a repository or one of its environments, when it exists.
fn scope(world: &World, repo: &str, env: Option<&str>) -> Option<String> {
    let r = world.doc["github"]["repos"].get(repo)?;
    let base = format!("/github/repos/{}", repo.replace('/', "~1"));
    match env {
        None => Some(base),
        Some(e) => r["environments"]
            .get(e)
            .map(|_| format!("{base}/environments/{e}")),
    }
}

fn missing_scope(
    world: &World,
    args: &[String],
    kind: &str,
    verb: &str,
    repo: &str,
    env: Option<&str>,
) -> Reply {
    let repo_exists = world.doc["github"]["repos"].get(repo).is_some();
    match (kind, verb, env, repo_exists) {
        ("secret", "list", None, false) | ("secret", "list" | "set", Some(_), true) => {
            fault(Kind::NotFound, world, args)
        }
        _ => Reply::no_recording(
            &format!("gh {kind} {verb} on a missing repository or environment"),
            DIR,
        ),
    }
}

fn list(world: &World, scope: &str, plural: &str, fields: Option<&str>) -> Reply {
    let at = scope_value(world, scope);
    let fields: Vec<&str> = fields.unwrap_or("name").split(',').collect();
    let rows: Vec<Value> = at[plural]
        .as_object()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|(name, v)| {
            let mut row = Map::new();
            for f in &fields {
                let value = if *f == "name" {
                    json!(name)
                } else {
                    v.get(*f).cloned().unwrap_or(Value::Null)
                };
                row.insert((*f).to_string(), value);
            }
            Value::Object(row)
        })
        .collect();
    Reply::json(&Value::Array(rows))
}

fn scope_value(world: &World, pointer: &str) -> Value {
    world
        .doc
        .pointer(pointer)
        .cloned()
        .unwrap_or_else(|| json!({}))
}

/// `gh api repos/<r>/environments` and `gh api -X PUT repos/<r>/environments/<e> --silent`.
fn api(world: &mut World, args: &[String], path: &str) -> Reply {
    let method = flag(args, "-X").unwrap_or("GET");
    let parts: Vec<&str> = path.split('/').collect();
    match (method, parts.as_slice()) {
        ("GET", ["repos", owner, name, "environments"]) => {
            let repo = format!("{owner}/{name}");
            let Some(r) = world.doc["github"]["repos"].get(&repo) else {
                return Reply::no_recording("gh api of a missing repository (404)", DIR);
            };
            let names: Vec<Value> = r["environments"]
                .as_object()
                .map(|m| m.keys().map(|k| json!({"name": k})).collect())
                .unwrap_or_default();
            Reply::json(&json!({"environments": names}))
        }
        ("PUT", ["repos", owner, name, "environments", env]) => {
            let repo = format!("{owner}/{name}");
            if world.doc["github"]["repos"].get(&repo).is_none() {
                return Reply::no_recording("gh api of a missing repository (404)", DIR);
            }
            let envs = world.object_at(&format!(
                "/github/repos/{}/environments",
                repo.replace('/', "~1")
            ));
            envs.entry(env.to_string())
                .or_insert_with(|| json!({"secrets": {}, "variables": {}}));
            Reply::silent()
        }
        _ => Reply::unsupported("gh", args),
    }
}
