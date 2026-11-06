//! `opv-e2e-producer`: a scripted producer speaking `opv.produce/1` (design
//! `owner-value-ingestion.md` §5.2) for the provision scenarios (`tests/e2e/scenarios/
//! provision.rs`). opv spawns it with a cleared environment (its basics only), so it never
//! sees `OPV_SIM_WORLD`: its one argument is its script, a JSON file in the project (the file
//! the contract's `sha256` pins), read relative to its working directory (the project):
//!
//! ```json
//! {"notices": [{"open_url": "https://…"}, {"waiting": true}],
//!  "outputs": {"refresh_token": "…"},    // the result line; or
//!  "error": "consent_denied",            // an error line instead of a result
//!  "env": "…", "nonce": "…",             // override the request's (default: echoed)
//!  "stderr": "…",                        // written to stderr (never shown by opv)
//!  "exit": 0,
//!  "record": "producer/seen.json"}       // where to write what it was given
//! ```
//!
//! **Site get-or-create** (`provision_sets.rs`, #262): a script with `"sites"` in place of
//! `"outputs"` plays an idempotent issuer that keeps its sites in a state file in the project:
//!
//! ```json
//! {"sites": {"names": ["platform", "agency", "owner"], "issuer": "producer/issuer.json"}}
//! ```
//!
//! Each name it has not issued yet is created (an id and a key, both carrying the
//! `test-marker-e2e-site-` marker and the issue count, so a re-created site differs) and the
//! issuer file saved; a name it has issued is returned as it was. The result's outputs are
//! `<name>_site_id` and `<name>_site_key` for every name. The issuer file counts its
//! creations (`"created"`), so a test can tell a get from a create.
//!
//! The record holds its argv, its environment and the request's field names, never the
//! request's input values: a custody canary scans it with every other file of the scenario.

use std::io::{BufRead, Write};

use serde_json::{Map, Value, json};

const SCHEMA: &str = "opv.produce/1";

/// Run as the producer: `args` is `[<script>]`. The exit is the script's.
pub fn run(args: &[String]) -> i32 {
    let [script] = args else {
        eprintln!("opv-e2e-producer: usage: opv-e2e-producer <script.json>");
        return 2;
    };
    let script: Value = match std::fs::read(script)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
    {
        Some(v) => v,
        None => {
            eprintln!("opv-e2e-producer: cannot read the script {script}");
            return 2;
        }
    };
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return 2;
    }
    let request: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
    if let Some(path) = script["record"].as_str() {
        record(path, &request);
    }
    let mut out = std::io::stdout().lock();
    let mut say = |v: Value| {
        let _ = writeln!(out, "{v}");
        let _ = out.flush();
    };
    for notice in script["notices"].as_array().into_iter().flatten() {
        let mut doc = Map::new();
        doc.insert("schema".into(), json!(SCHEMA));
        doc.insert("kind".into(), json!("notice"));
        for (k, v) in notice.as_object().into_iter().flatten() {
            doc.insert(k.clone(), v.clone());
        }
        say(Value::Object(doc));
    }
    if let Some(code) = script["error"].as_str() {
        say(json!({"schema": SCHEMA, "kind": "error", "code": code}));
    } else if let Some(outputs) = script
        .get("sites")
        .map(get_or_create)
        .or_else(|| script.get("outputs").cloned())
    {
        let echo = |k: &str| script.get(k).unwrap_or(&request[k]).clone();
        say(
            json!({"schema": SCHEMA, "kind": "result", "env": echo("env"),
                   "nonce": echo("nonce"), "outputs": outputs}),
        );
    }
    if let Some(text) = script["stderr"].as_str() {
        let _ = std::io::stderr().write_all(text.as_bytes());
    }
    script["exit"]
        .as_i64()
        .and_then(|c| i32::try_from(c).ok())
        .unwrap_or(0)
}

/// The site issuer: every name in `sites.names` gets an id and a key, made once and kept in
/// the issuer file (`sites.issuer`), so a second run returns the same sites.
fn get_or_create(sites: &Value) -> Value {
    let path = sites["issuer"].as_str().unwrap_or("producer/issuer.json");
    let mut issuer: Value = std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_else(|| json!({"created": 0, "sites": {}}));
    let mut outputs = Map::new();
    for name in sites["names"].as_array().into_iter().flatten() {
        let name = name.as_str().unwrap_or_default();
        if issuer["sites"].get(name).is_none() {
            let n = issuer["created"].as_u64().unwrap_or(0) + 1;
            issuer["created"] = json!(n);
            issuer["sites"][name] = json!({
                "id": format!("test-marker-e2e-site-{name}-id-{n}"),
                "key": format!("test-marker-e2e-site-{name}-key-{n}"),
            });
        }
        let site = &issuer["sites"][name];
        outputs.insert(format!("{name}_site_id"), site["id"].clone());
        outputs.insert(format!("{name}_site_key"), site["key"].clone());
    }
    let _ = std::fs::write(path, issuer.to_string());
    Value::Object(outputs)
}

/// What the producer was given: argv, environment, and the request's field and input names.
fn record(path: &str, request: &Value) {
    let names = |v: &Value| -> Vec<String> {
        v.as_object()
            .map(|o| o.keys().cloned().collect())
            .unwrap_or_default()
    };
    let seen = json!({
        "argv": std::env::args().collect::<Vec<_>>(),
        "env": std::env::vars().collect::<std::collections::BTreeMap<_, _>>(),
        "request_fields": names(request),
        "input_names": names(&request["inputs"]),
        "outputs": request["outputs"],
        "env_requested": request["env"],
    });
    let _ = std::fs::write(path, seen.to_string());
}
