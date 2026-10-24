//! The simulated `docker` CLI (docker 27.5.1), for `opv target op … registry-push` (#234,
//! `docs/design/provider-operations.md` §5.3, lane L5).
//!
//! **Every reply here is unrecorded**: the owner skipped spike S1 (design §8.1), so each one
//! is built from docker's documented output and marks an exception to the recordings-only
//! rule until the S1 recordings under `tests/fixtures/docker/` replace it:
//!
//! - `--version`: `Docker version 27.5.1, build 9f9e405`.
//! - `context inspect --format '{{.Endpoints.docker.Host}}'`: the world's endpoint
//!   (`unix:///var/run/docker.sock` unless `docker.endpoint` says otherwise).
//! - `image inspect --format '{{.Id}}' <image>`: `sha256:<hex>` for an image in
//!   `docker.images`; otherwise `[]` and `Error: No such image: <image>`, exit 1.
//! - `login registry.fly.io -u x --password-stdin`: the password is read from stdin and must
//!   be one of `fly.tokens` (else docker's `unauthorized` daemon reply, exit 1). On success
//!   docker records the login in `$DOCKER_CONFIG/config.json`, keeping what the file held:
//!   `auths["registry.fly.io"].auth = base64("x:<password>")` in the file store, or, with
//!   `docker.creds_store` set, an empty `auths` entry and `"credsStore": "secretservice"`
//!   (a credential helper took the password). Prints `Login Succeeded`.
//! - `push <image>`: needs the registry's `auth` in `$DOCKER_CONFIG/config.json` (else
//!   `no basic auth credentials`, exit 1); prints the repository line, one layer line and
//!   the final `<tag>: digest: sha256:<hex> size: <n>` line, and records the push in
//!   `docker.pushed`.
//!
//! ```json
//! "docker": {
//!   "endpoint": "unix:///var/run/docker.sock",   // what `context inspect` prints
//!   "images": ["registry.fly.io/myapp:v2"],      // images the local daemon holds
//!   "creds_store": false,                        // true: login lands in a helper
//!   "pushed": [{"image": "…", "digest": "sha256:…"}]
//! }
//! ```
//!
//! The simulator never writes the password anywhere but the file docker itself would write.

use base64::Engine as _;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::args::words;
use crate::recordings::Reply;
use crate::world::World;

const BOOLEAN: &[&str] = &["--password-stdin"];
const DEFAULT_ENDPOINT: &str = "unix:///var/run/docker.sock";

pub fn call_words(args: &[String]) -> Vec<String> {
    words(args, BOOLEAN)
}

pub fn run(world: &mut World, args: &[String]) -> Reply {
    if args == ["--version"] {
        // unrecorded: docker's documented `--version` line.
        return Reply::ok("Docker version 27.5.1, build 9f9e405\n");
    }
    let w = call_words(args);
    let ws: Vec<&str> = w.iter().map(String::as_str).collect();
    match ws.as_slice() {
        ["context", "inspect"] => {
            let endpoint = world.doc["docker"]["endpoint"]
                .as_str()
                .unwrap_or(DEFAULT_ENDPOINT);
            Reply::ok(format!("{endpoint}\n"))
        }
        ["image", "inspect", image] => {
            if local(world, image) {
                Reply::ok(format!("sha256:{}\n", sha(&format!("image {image}"))))
            } else {
                failure(&format!("Error: No such image: {image}\n"), "[]\n")
            }
        }
        ["login", registry] => login(world, registry),
        ["push", image] => push(world, image),
        _ => Reply::unsupported("docker", args),
    }
}

fn local(world: &World, image: &str) -> bool {
    world.doc["docker"]["images"]
        .as_array()
        .is_some_and(|a| a.iter().any(|i| i.as_str() == Some(image)))
}

fn login(world: &World, registry: &str) -> Reply {
    let mut input = String::new();
    let _ = std::io::Read::read_to_string(&mut std::io::stdin(), &mut input);
    let password = input.trim_end_matches(['\n', '\r']);
    let known = world.doc["fly"]["tokens"]
        .as_array()
        .is_some_and(|ts| ts.iter().any(|t| t.as_str() == Some(password)));
    if password.is_empty() || !known {
        return failure(
            &format!(
                "Error response from daemon: Get \"https://{registry}/v2/\": unauthorized: \
                 not authorized\n"
            ),
            "",
        );
    }
    let path = config_path();
    let mut config: Value = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_else(|| json!({}));
    if !config.is_object() {
        config = json!({});
    }
    if !config["auths"].is_object() {
        config["auths"] = json!({});
    }
    if world.doc["docker"]["creds_store"]
        .as_bool()
        .unwrap_or(false)
    {
        config["auths"][registry] = json!({});
        config["credsStore"] = json!("secretservice");
    } else {
        let auth = base64::engine::general_purpose::STANDARD.encode(format!("x:{password}"));
        config["auths"][registry] = json!({ "auth": auth });
    }
    let mut out = Vec::new();
    let fmt = serde_json::ser::PrettyFormatter::with_indent(b"\t");
    let mut ser = serde_json::Serializer::with_formatter(&mut out, fmt);
    if serde::Serialize::serialize(&config, &mut ser).is_err()
        || std::fs::write(&path, out).is_err()
    {
        return failure("Error saving credentials: cannot write config.json\n", "");
    }
    Reply::ok("Login Succeeded\n")
}

fn push(world: &mut World, image: &str) -> Reply {
    let Some((repository, tag)) = image.rsplit_once(':') else {
        return Reply::unsupported("docker", &["push".to_string(), image.to_string()]);
    };
    let registry = repository.split('/').next().unwrap_or_default();
    let authed = std::fs::read(config_path())
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .is_some_and(|c| c["auths"][registry]["auth"].is_string());
    if !authed {
        return failure("no basic auth credentials\n", "");
    }
    if !local(world, image) {
        return failure(
            &format!("An image does not exist locally with the tag: {repository}\n"),
            "",
        );
    }
    let digest = format!("sha256:{}", sha(&format!("pushed {image}")));
    world
        .array_at("/docker/pushed")
        .push(json!({"image": image, "digest": digest}));
    Reply::ok(format!(
        "The push refers to repository [{repository}]\n\
         5f70bf18a086: Pushed\n\
         {tag}: digest: {digest} size: 1570\n"
    ))
}

/// `$DOCKER_CONFIG/config.json`, or `~/.docker/config.json` as docker falls back to.
fn config_path() -> std::path::PathBuf {
    let dir = std::env::var_os("DOCKER_CONFIG")
        .filter(|d| !d.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".docker")
        });
    dir.join("config.json")
}

fn sha(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

fn failure(stderr: &str, stdout: &str) -> Reply {
    Reply {
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
        code: 1,
    }
}
