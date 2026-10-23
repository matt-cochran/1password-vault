//! The two http fixes of opv 0.16.1, each proven by unit tests, reached through the real
//! `opv` binary against `opv-sim` on the test application in `tests/e2e/app`:
//!
//! 1. #237: with the `http_target_sync` platform target (its descriptor `platform_console.binpb`
//!    beside `project/secrets.toml`), `opv plan prod --config <root>/project/secrets.toml` run
//!    with the working directory in the scenario's home (not `project/`) reads the descriptor
//!    beside the configuration file, so the run does not fail with "must be a readable
//!    descriptor file".
//! 2. #236: `opv propose target prod vault --provider http --http-descriptor platform_console.binpb
//!    --http-service portal.v1.PlatformConsoleService`, run in `project/` with the descriptor
//!    beside `secrets.toml`, is not refused as `high_entropy` and the proposal carries an `http`
//!    section.
//! 3. #236: the same with `--http-service portal.v1.NoSuchService` fails naming that the service
//!    is not in the descriptor, not "names no provider".
//!
//! **The world.** This module copies `http_target_sync.rs`'s platform target: the descriptor
//! sits beside `secrets.toml`, the world holds the deploy and delivery items, and the simulator
//! serves the providers the delivered secrets map to. Every world value carries
//! `test-marker-e2e-`, so the coverage canary finds any value a snapshot holds. The fixes are
//! proven by assertions, so this module writes no snapshot.

use std::path::Path;

use serde_json::json;

use crate::coverage::Scenario;

/// The scenario snapshots this module writes (`tests/e2e/snapshots/scenarios/`).
pub(crate) const SNAPSHOTS: &[&str] = &[];

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
fn platform_world(w: &mut serde_json::Value) {
    let vaults = w["op"]["vaults"].as_array_mut().expect("vaults");
    vaults.push(json!({
        "id": DEPLOY_VAULT,
        "name": "e2e-app · platform · credentials",
        "account": crate::coverage::DEV_ACCOUNT,
    }));
    vaults.push(json!({
        "id": STATE_VAULT,
        "name": "e2e-app · platform · state",
        "account": crate::coverage::DEV_ACCOUNT,
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

/// `opv <args>` with the working directory set to the scenario's home (not `project/`),
/// where config discovery finds nothing: the file is named outright.
fn opv_from_home(s: &Scenario, args: &[String]) -> std::process::Output {
    s.command()
        .current_dir(s.path("home"))
        .args(args)
        .output()
        .expect("run opv")
}

// --- #237: a --config file's descriptor resolves beside it -----------------------------------

/// The run from the home directory reaches the descriptor beside the named configuration
/// file: it does not fail with "must be a readable descriptor file".
#[test]
fn a_plan_from_home_reads_the_descriptor_beside_the_named_config() {
    let s = app();
    let config = s.path("project/secrets.toml").display().to_string();
    let out = opv_from_home(&s, &["plan", "prod", "--config", &config].map(String::from));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("must be a readable descriptor file"),
        "the descriptor beside the config was not read: {stderr}"
    );
}

// --- #236: propose target screens option names, and carries the http section ------------------

/// The proposal is not refused as `high_entropy` and carries the generated `http` section.
#[test]
fn an_http_target_proposal_carries_the_http_section() {
    let s = app();
    let out = s
        .command()
        .args([
            "propose",
            "target",
            "prod",
            "vault",
            "--provider",
            "http",
            "--http-descriptor",
            "platform_console.binpb",
            "--http-service",
            "portal.v1.PlatformConsoleService",
        ])
        .output()
        .expect("run opv");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("http.descriptor = \"platform_console.binpb\""),
        "the proposal carries no http section: {stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A service absent from the descriptor fails naming that it is not in the descriptor.
#[test]
fn an_http_service_absent_from_the_descriptor_names_the_reason() {
    let s = app();
    let out = s
        .command()
        .args([
            "propose",
            "target",
            "prod",
            "vault",
            "--provider",
            "http",
            "--http-descriptor",
            "platform_console.binpb",
            "--http-service",
            "portal.v1.NoSuchService",
        ])
        .output()
        .expect("run opv");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("portal.v1.NoSuchService` is not in the descriptor"),
        "the reason was not named: {stderr}"
    );
}

/// A service absent from the descriptor does not fail with "names no provider".
#[test]
fn an_http_service_absent_from_the_descriptor_does_not_report_no_provider() {
    let s = app();
    let out = s
        .command()
        .args([
            "propose",
            "target",
            "prod",
            "vault",
            "--provider",
            "http",
            "--http-descriptor",
            "platform_console.binpb",
            "--http-service",
            "portal.v1.NoSuchService",
        ])
        .output()
        .expect("run opv");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !combined.contains("names no provider"),
        "the reason was hidden behind 'names no provider': {combined}"
    );
}
