//! The HTTP target through the real `opv` binary and `opv-sim https` (design
//! `http-target` §9): the happy path — a first `opv sync prod --target platform` writes
//! every mapped name, a second writes nothing, and a value changed in 1Password is written
//! at the version the store listed — and the drift path: an entry changed outside opv is
//! `target_drift` under `--fail-on-drift`, a deploy credentials item whose `base_url` host
//! is not the target's `http.host` refuses before any HTTPS call, and a value shorter than
//! the store's 16-character minimum is refused in `opv plan` before any write.
//!
//! **The fake `https`.** `opv-sim https` is the descriptor-driven store (design §5): its
//! entries live in the scenario's `world/sim-state.json`, one per provider, and every call
//! is appended to `world/calls.log` (argv only, never a header value). A value changed in
//! the 1Password item between two syncs proves the second write carries the listed
//! `expected_version`; an entry whose version the simulator bumped behind opv's back (as a
//! person editing the platform console would) is drift.
//!
//! Every world value carries `test-marker-e2e-` (or the pinned simulator token), so the
//! coverage canary finds any value this module's snapshot
//! (`snapshots/scenarios/http_target_sync.snap`) or a `calls.log` holds. No run in this
//! module reads `/proc` or needs a Linux-only tool.
//!
//! **Documented deviations.** This module needs two one-line changes outside its own two
//! files, both permitted by the acceptance's "documented deviation" clause:
//!
//! 1. `tests/sim/https.rs`'s `run` passed `world.json` whole to `serve`, but `serve` reads
//!    the `http` section (`token`, `providers`, `descriptor`, `rejected`), so every
//!    `https` call in an app world answered `UNAUTHENTICATED`; `run` now passes that
//!    section (falling back to the whole document for a bare fixture).
//! 2. `tests/e2e/coverage.rs` chains this module's `SNAPSHOTS` const into
//!    `every_scenario_snapshot_belongs_to_a_scenario`, as it does for the other scenario
//!    modules.

use std::path::Path;

use serde_json::{Value, json};

use crate::coverage::{DEV_ACCOUNT, Run, Scenario, scenario_snapshots, updating};

/// The scenario snapshots this module writes (`tests/e2e/snapshots/scenarios/`).
pub(crate) const SNAPSHOTS: &[&str] = &["http_target_sync"];

const TARGET: &str = "platform";
const HOST: &str = "platform.e2e.test";
/// The pinned descriptor fixture, and the digest the target declares.
const DESCRIPTOR: &str = "tests/fixtures/https/zonetico/platform_console.binpb";
const DESCRIPTOR_SHA256: &str = "ec5b6933b89fc49c1ebeaaa31afc666e9090036c53301648cc657cd18f8a7445";
const OPERATOR: &str = "00000000-0000-4000-8000-000000000000";
/// The simulator's accepted bearer token (`tests/e2e/app/world.json` `http.token`).
const TOKEN: &str = "CANARY-TOKEN-0123456789";
/// The deploy credentials item (its `base_url` host must equal `http.host`).
const DEPLOY_VAULT: &str = "vE2EPLATFORMCRED0000000001";
const DEPLOY_ITEM: &str = "iE2EPLATFORMCRED0000000001";
/// The target's state vault and its `web` delivery item (FR-13, #106).
const STATE_VAULT: &str = "vE2ESTATEPLATFORM00000001";
const DELIVERY_ITEM: &str = "iE2EDELIVERYWEBPLATFORM01";
/// The web product's prod item (`tests/e2e/app/world.json`): `API_KEY`'s home.
const WEB_PROD_ITEM: &str = "iE2EWEBPROD000000000000001";
/// The simulator's providers: the original three plus the two extra remotes the five
/// delivered secrets map to. `tavily` is rejected (design §6), so no name maps to it.
const SIM_PROVIDERS: &[&str] = &[
    "openrouter",
    "tavily",
    "stripe",
    "database_url",
    "tls_certificate",
    "tls_private_key",
];
/// Every delivered secret, mapped to a distinct remote provider that the simulator serves.
const MAPPED: &[&str] = &[
    "database_url",
    "openrouter",
    "stripe",
    "tls_certificate",
    "tls_private_key",
];

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

/// The single JSON document a `--json` run printed.
fn document(run: &Run) -> Value {
    serde_json::Deserializer::from_str(&run.stdout)
        .into_iter::<Value>()
        .next()
        .and_then(Result::ok)
        .unwrap_or_else(|| panic!("no document: {}{}", run.stdout, run.stderr))
}

/// The platform target's section, appended to `secrets.toml` (design §3.1). The ids go to
/// `secrets.bindings.toml` when [`Scenario::config`] writes the merged text back.
fn platform_target() -> String {
    format!(
        r#"
[environments.prod.targets.platform]
products = ["web"]
roles = ["serve"]
deploy_credentials = "op://{DEPLOY_VAULT}/{DEPLOY_ITEM}"
state_vault_id = "{STATE_VAULT}"
delivery_items.web = "{DELIVERY_ITEM}"

[environments.prod.targets.platform.http]
host = "{HOST}"
descriptor = "platform_console.binpb"
descriptor_sha256 = "{DESCRIPTOR_SHA256}"
names = {{ DATABASE_URL = "database_url", API_KEY = "openrouter", SESSION_SECRET = "stripe", TLS_CERTIFICATE = "tls_certificate", TLS_PRIVATE_KEY = "tls_private_key" }}
list.call = "portal.v1.PlatformConsoleService/ListPlatformConnections"
list.request = {{ operator_id = "{OPERATOR}" }}
list.items = "connections"
list.name = "provider"
list.version = "version"
list.status = "status"
list.absent = ["CONNECTION_STATUS_NOT_CONFIGURED", "CONNECTION_STATUS_REVOKED"]
list.rejected = ["CONNECTION_STATUS_REJECTED"]
put.call = "portal.v1.PlatformConsoleService/SavePlatformConnection"
put.request = {{ operator_id = "{OPERATOR}", provider = "{{name}}", expected_version = "{{version}}" }}
put.value = {{ field = "secret_value", number = 3, type = "bytes" }}
put.reply = "connection"
put.conflict = ["ALREADY_EXISTS"]
"#
    )
}

/// The deploy credentials item, the state vault and its `web` delivery item, and the
/// providers the simulator serves.
fn platform_world(w: &mut Value) {
    let vaults = w["op"]["vaults"].as_array_mut().expect("vaults");
    vaults.push(json!({
        "id": DEPLOY_VAULT,
        "name": "e2e-app · platform · credentials",
        "account": DEV_ACCOUNT,
    }));
    vaults.push(json!({
        "id": STATE_VAULT,
        "name": "e2e-app · platform · state",
        "account": DEV_ACCOUNT,
    }));
    let items = w["op"]["items"].as_array_mut().expect("items");
    items.push(json!({
        "id": DEPLOY_ITEM,
        "title": "e2e-app · platform · deploy",
        "version": 1,
        "vault": {"id": DEPLOY_VAULT, "name": "e2e-app · platform · credentials"},
        "category": "SECURE_NOTE",
        "fields": [
            {"id": "notesPlain", "type": "STRING", "purpose": "NOTES", "label": "notesPlain", "value": ""},
            {"id": "base_url", "type": "STRING", "label": "base_url", "value": format!("https://{HOST}")},
            {"id": "token", "type": "CONCEALED", "label": "token", "value": TOKEN},
            {"id": "cf_access_client_id", "type": "CONCEALED", "label": "cf_access_client_id", "value": "test-marker-e2e-cf-access-client-id"},
            {"id": "cf_access_client_secret", "type": "CONCEALED", "label": "cf_access_client_secret", "value": "test-marker-e2e-cf-access-client-secret"},
        ],
    }));
    items.push(json!({
        "id": DELIVERY_ITEM,
        "title": "opv · delivery · web · platform",
        "version": 1,
        "vault": {"id": STATE_VAULT, "name": "e2e-app · platform · state"},
        "category": "SECURE_NOTE",
        "fields": [{"id": "notesPlain", "type": "STRING", "purpose": "NOTES", "label": "notesPlain", "value": ""}],
    }));
    w["http"]["providers"] = json!(SIM_PROVIDERS);
}

/// The app with the platform target installed: the descriptor beside `secrets.toml`, the
/// target section appended, and the world holding the deploy and delivery items.
fn app() -> Scenario {
    let s = Scenario::new()
        .marked()
        .config(|c| format!("{c}{}", platform_target()))
        .world(platform_world);
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join(DESCRIPTOR);
    std::fs::write(
        s.path("project/platform_console.binpb"),
        std::fs::read(&fixture).expect("descriptor"),
    )
    .expect("descriptor");
    s
}

/// The scenario's `sim-state.json` (the simulator's store).
fn sim_state(s: &Scenario) -> Value {
    serde_json::from_str(
        &std::fs::read_to_string(s.path("world/sim-state.json")).expect("sim-state"),
    )
    .expect("sim-state")
}

/// The version the store holds for `provider`.
fn version_of(s: &Scenario, provider: &str) -> i64 {
    sim_state(s)["http"]["entries"][provider]["version"]
        .as_i64()
        .unwrap_or(-1)
}

/// The scenario's `calls.log`.
fn calls(s: &Scenario) -> String {
    std::fs::read_to_string(s.path("world/calls.log")).unwrap_or_default()
}

/// The number of write calls in the log.
fn writes(s: &Scenario) -> usize {
    calls(s)
        .lines()
        .filter(|l| l.contains("SavePlatformConnection"))
        .count()
}

/// Edit the world's item `id`, changing the field labelled `label` to `value`.
fn change_field(s: Scenario, id: &str, label: &str, value: &str) -> Scenario {
    s.world(move |w| {
        for item in w["op"]["items"].as_array_mut().expect("items") {
            if item["id"] == id {
                for field in item["fields"].as_array_mut().expect("fields") {
                    if field["label"] == label {
                        field["value"] = json!(value);
                    }
                }
            }
        }
    })
}

/// The app after one sync, with the `API_KEY` value changed in 1Password (as a person
/// would), so the next sync must write it at the version the store listed.
fn rotated() -> Scenario {
    let s = app();
    assert_eq!(s.opv(&sync_args()).code, Some(0), "first sync");
    change_field(
        s,
        WEB_PROD_ITEM,
        "API_KEY",
        "S7MARKERVALUE-rotated-api-key-0123456789",
    )
}

/// The app after one sync, with the `openrouter` entry's version bumped in the simulator's
/// store (an edit outside opv, as the platform console would make).
fn drifted() -> Scenario {
    let s = app();
    assert_eq!(s.opv(&sync_args()).code, Some(0), "first sync");
    let mut state = sim_state(&s);
    state["http"]["entries"]["openrouter"]["version"] = json!(2);
    std::fs::write(s.path("world/sim-state.json"), state.to_string()).expect("sim-state");
    s
}

/// The app with a deploy credentials item whose `base_url` host is not `http.host`.
fn host_mismatch() -> Scenario {
    change_field(app(), DEPLOY_ITEM, "base_url", "https://elsewhere.e2e.test")
}

/// The app with a value shorter than the store's 16-character minimum.
fn too_short() -> Scenario {
    change_field(app(), WEB_PROD_ITEM, "API_KEY", "S7MARKER")
}

fn sync_args() -> Vec<String> {
    args(&["sync", "prod", "--confirm", "prod", "--target", TARGET])
}

fn plan_args() -> Vec<String> {
    args(&["plan", "prod", "--target", TARGET])
}

fn status_args() -> Vec<String> {
    args(&["status", "prod", "--target", TARGET])
}

fn drift_args() -> Vec<String> {
    args(&["status", "prod", "--target", TARGET, "--fail-on-drift"])
}

// --- the happy path --------------------------------------------------------------------------

#[test]
fn first_sync_writes_every_mapped_name() {
    let s = app();
    let run = s.opv(&sync_args());
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
    for provider in MAPPED {
        assert_eq!(version_of(&s, provider), 1, "{provider} was not written");
    }
}

#[test]
fn second_sync_writes_nothing() {
    let s = app();
    assert_eq!(s.opv(&sync_args()).code, Some(0), "first sync");
    let before = writes(&s);
    let run = s.opv(&sync_args());
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
    assert_eq!(writes(&s), before, "the second sync wrote again");
    for provider in MAPPED {
        assert_eq!(version_of(&s, provider), 1, "{provider} moved");
    }
}

#[test]
fn a_changed_value_is_written_at_the_listed_version() {
    let s = rotated();
    let run = s.opv(&sync_args());
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
    assert_eq!(
        version_of(&s, "openrouter"),
        2,
        "the change was not written"
    );
}

// --- the drift path --------------------------------------------------------------------------

#[test]
fn an_entry_changed_outside_opv_is_target_drift() {
    let run = drifted().opv(&args(&[
        "status",
        "prod",
        "--target",
        TARGET,
        "--fail-on-drift",
        "--json",
    ]));
    assert_eq!(run.code, Some(8), "{}{}", run.stdout, run.stderr);
    assert_eq!(
        document(&run)["error"]["code"],
        "target_drift",
        "{}{}",
        run.stdout,
        run.stderr
    );
}

#[test]
fn a_host_mismatch_refuses_before_any_call() {
    let s = host_mismatch();
    let run = s.opv(&sync_args());
    assert_ne!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
    assert!(
        !calls(&s).lines().any(|l| l.starts_with("https ")),
        "a call was made: {}",
        calls(&s)
    );
}

#[test]
fn a_too_short_value_is_refused_in_plan_before_any_write() {
    let s = too_short();
    let run = s.opv(&plan_args());
    assert_ne!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
    assert!(
        run.stdout.contains("http-value-too-short") || run.stderr.contains("http-value-too-short"),
        "{}{}",
        run.stdout,
        run.stderr
    );
    assert_eq!(writes(&s), 0, "a write happened: {}", calls(&s));
}

// --- the canary ------------------------------------------------------------------------------

#[test]
fn no_snapshot_or_call_log_holds_a_value() {
    let snapshot = scenario_snapshots().join(format!("{}.snap", SNAPSHOTS[0]));
    let snapshot = std::fs::read_to_string(&snapshot).unwrap_or_default();
    let s = app();
    assert_eq!(s.opv(&sync_args()).code, Some(0), "sync");
    let logs = calls(&s);
    for text in [&snapshot, &logs] {
        for canary in [
            crate::coverage::MARK,
            "test-marker-e2e-",
            TOKEN,
            "masked_key",
        ] {
            assert!(!text.contains(canary), "a value leaked ({canary}): {text}");
        }
    }
}

// --- the snapshot ---------------------------------------------------------------------------

/// What a snapshot must not depend on beyond [`Scenario::normalize`]: when and by which opv
/// version a target was last written, and the plan id of that write (text and `--json`).
fn steady(text: &str) -> String {
    let stamp = regex::Regex::new(
        r"last changed by opv \S+ at \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ \(plan [0-9a-f]+\)",
    )
    .expect("regex");
    let text = stamp.replace_all(text, "last changed by opv <version> at <time> (plan <id>)");
    // A delivery revision is random (`delivery::new_revision`), so the same delivery must
    // snapshot the same text.
    let revision = regex::Regex::new(r"\bdrv-[a-z0-9]+\b").expect("regex");
    let text = revision.replace_all(&text, "drv-<id>");
    let provenance =
        regex::Regex::new(r#""written":"[^"]*","plan_id":"[0-9a-f]+""#).expect("regex");
    provenance
        .replace_all(&text, r#""written":"<time>","plan_id":"<id>""#)
        .into_owned()
}

/// One run as snapshot sections.
fn section(snap: &mut String, label: &str, run: &Run) {
    snap.push_str(&format!(
        "\n## {label} exit: {}\n## {label} stdout\n{}\n## {label} stderr\n{}",
        run.code.map_or("killed".into(), |c| c.to_string()),
        steady(&run.stdout),
        steady(&run.stderr),
    ));
}

/// The runs that tell the HTTP target's story, each on a fresh world.
fn transcript() -> String {
    let mut snap = String::from("# http_target_sync: the HTTP target's happy and drift paths\n");
    // The happy path on one world: the first sync writes, the second writes nothing.
    let s = app();
    section(&mut snap, "first opv sync", &s.opv(&sync_args()));
    section(&mut snap, "second opv sync", &s.opv(&sync_args()));
    section(&mut snap, "opv status", &s.opv(&status_args()));
    // A value changed in 1Password is written at the version the store listed.
    section(
        &mut snap,
        "changed value opv sync",
        &rotated().opv(&sync_args()),
    );
    // An entry changed outside opv is drift under `--fail-on-drift`.
    section(
        &mut snap,
        "drift opv status --fail-on-drift",
        &drifted().opv(&drift_args()),
    );
    // A deploy credentials host that is not `http.host` refuses before any call.
    section(
        &mut snap,
        "host mismatch opv sync",
        &host_mismatch().opv(&sync_args()),
    );
    // A value shorter than 16 characters is refused in plan, before any write.
    section(
        &mut snap,
        "too-short value opv plan",
        &too_short().opv(&plan_args()),
    );
    snap
}

#[test]
fn the_http_target_matches_its_snapshot() {
    let got = transcript();
    let path = scenario_snapshots().join(format!("{}.snap", SNAPSHOTS[0]));
    if updating() {
        std::fs::write(&path, &got).expect("write snapshot");
        return;
    }
    let want = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(
        got,
        want,
        "{} differs from its snapshot; review and rerun with UPDATE_SNAPSHOTS=1",
        path.display()
    );
}
