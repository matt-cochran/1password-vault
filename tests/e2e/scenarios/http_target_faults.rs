//! The HTTPS target's fault scenarios (design `http-target` §8, §9), reached through the
//! real `opv` binary against `opv-sim https` on the test application in `tests/e2e/app`:
//!
//! 1. `version_bumped`: the target's stored version moves between the List and the Save, so
//!    the Save conflicts (`target_changed`, exit 5).
//! 2. A provider the world marks `rejected` (`tavily`): the write is accepted, the receipt
//!    and evidence are recorded, and only then the written name's status is checked
//!    (`target_unhealthy`, exit 5). A later `opv delivery verify` reads the recorded version
//!    and reports the placement `verified`.
//! 3. A wrong token in the deploy credentials item: the target answers `UNAUTHENTICATED`,
//!    and the refusal names the deploy credentials item (`deploy_credentials_failed`,
//!    exit 7).
//! 4. `applied_but_reply_lost`: the Save is applied to the world, then the `https` program
//!    dies without a reply, so the write's effect is unknown (`outcome_unknown`, exit 9).
//!
//! Each scenario adds its own `[environments.prod.targets.platform]` target (design §3.1) to
//! the app's configuration and its own deploy credentials item, state vault and delivery
//! item to the world. Every world value carries `test-marker-e2e-` (or is the recorded
//! `CANARY-TOKEN-…`), so the coverage canary finds any value the snapshot holds.

use std::path::Path;

use serde_json::{Value, json};

use crate::coverage::{Run, Scenario, DEV_ACCOUNT, scenario_snapshots, updating};

/// The scenario snapshots this module writes (`tests/e2e/snapshots/scenarios/`).
pub(crate) const SNAPSHOTS: &[&str] = &["http_target_faults"];

/// The target's host (design §4.2: the item's `base_url` host must equal `http.host`).
const HOST: &str = "platform.e2e.test";
/// The token the world's store accepts; the deploy credentials item holds it.
const TOKEN: &str = "CANARY-TOKEN-0123456789";
/// A token the store does not accept: the wrong-credentials case.
const WRONG_TOKEN: &str = "test-marker-e2e-wrong-platform-token";
const CF_CLIENT_ID: &str = "test-marker-e2e-cf-access-client-id";
const CF_CLIENT_SECRET: &str = "test-marker-e2e-cf-access-client-secret";
const OPERATOR_ID: &str = "00000000-0000-4000-8000-000000000000";
const DESCRIPTOR_SHA256: &str = "ec5b6933b89fc49c1ebeaaa31afc666e9090036c53301648cc657cd18f8a7445";
const DESCRIPTOR: &str = "tests/fixtures/https/zonetico/platform_console.binpb";

const DEPLOY_VAULT: &str = "vE2EPLATFORMVAULT0000000001";
const DEPLOY_VAULT_NAME: &str = "e2e-platform-deploy";
const DEPLOY_ITEM: &str = "iE2EPLATFORMDEPLOY0000001";
const DEPLOY_ITEM_TITLE: &str = "opv-platform-prod";
const STATE_VAULT: &str = "vE2ESTATEPLATFORM0000000001";
const STATE_VAULT_NAME: &str = "e2e-app · platform · state";
const DELIVERY_ITEM: &str = "iE2EDELIVERYWEBPLATFORM0001";

/// The delivered env name → remote name mapping (design §3.1). Rule 5 forbids two env names
/// mapping to one remote name, so each name has its own provider in the world.
const NAMES: &str = "API_KEY = \"openrouter\"\n\
                     DATABASE_URL = \"database\"\n\
                     SESSION_SECRET = \"stripe\"\n\
                     TLS_CERTIFICATE = \"tls-cert\"\n\
                     TLS_PRIVATE_KEY = \"tls-key\"\n";

/// The same mapping with `API_KEY` pointed at the provider the world rejects (`tavily`).
const REJECTED_NAMES: &str = "API_KEY = \"tavily\"\n\
                              DATABASE_URL = \"database\"\n\
                              SESSION_SECRET = \"stripe\"\n\
                              TLS_CERTIFICATE = \"tls-cert\"\n\
                              TLS_PRIVATE_KEY = \"tls-key\"\n";

/// `opv sync prod --confirm prod --target platform`, the write path of every case.
const SYNC: &[&str] = &["sync", "prod", "--confirm", "prod", "--target", "platform"];
/// `opv delivery verify prod --target platform`, the receipt read of the rejected case.
const VERIFY: &[&str] = &["delivery", "verify", "prod", "--target", "platform"];

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

/// The `--json` document of a run.
fn document(run: &Run) -> Value {
    serde_json::Deserializer::from_str(&run.stdout)
        .into_iter::<Value>()
        .next()
        .and_then(Result::ok)
        .unwrap_or_else(|| panic!("no document: {}{}", run.stdout, run.stderr))
}

/// The app with the `platform` HTTPS target (`names`: its `http.names` table body), its
/// deploy credentials item, its state vault and its delivery item. The `http` section's
/// fields are also flattened to the world's top level, which is where `opv-sim https` reads
/// them.
fn platform(names: &'static str) -> Scenario {
    let descriptor = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(DESCRIPTOR)
        .display()
        .to_string();
    Scenario::new()
        .config(move |text| {
            let mut out = text;
            out.push_str("\n[environments.prod.targets.platform]\n");
            out.push_str("products = [\"web\"]\n");
            out.push_str("roles = [\"serve\"]\n");
            out.push_str(&format!(
                "deploy_credentials = \"op://{DEPLOY_VAULT_NAME}/{DEPLOY_ITEM_TITLE}\"\n"
            ));
            out.push_str(&format!("state_vault_id = \"{STATE_VAULT}\"\n"));
            out.push_str(&format!("delivery_items.web = \"{DELIVERY_ITEM}\"\n\n"));
            out.push_str(&format!("http.host = \"{HOST}\"\n"));
            out.push_str(&format!("http.descriptor = \"{descriptor}\"\n"));
            out.push_str(&format!("http.descriptor_sha256 = \"{DESCRIPTOR_SHA256}\"\n\n"));
            out.push_str("[environments.prod.targets.platform.http.names]\n");
            out.push_str(names);
            out.push_str("\n[environments.prod.targets.platform.http.list]\n");
            out.push_str("call = \"portal.v1.PlatformConsoleService/ListPlatformConnections\"\n");
            out.push_str(&format!("request = {{ operator_id = \"{OPERATOR_ID}\" }}\n"));
            out.push_str("items = \"connections\"\n");
            out.push_str("name = \"provider\"\n");
            out.push_str("version = \"version\"\n");
            out.push_str("status = \"status\"\n");
            out.push_str(
                "absent = [\"CONNECTION_STATUS_NOT_CONFIGURED\", \"CONNECTION_STATUS_REVOKED\"]\n",
            );
            out.push_str("rejected = [\"CONNECTION_STATUS_REJECTED\"]\n\n");
            out.push_str("[environments.prod.targets.platform.http.put]\n");
            out.push_str("call = \"portal.v1.PlatformConsoleService/SavePlatformConnection\"\n");
            out.push_str(&format!(
                "request = {{ operator_id = \"{OPERATOR_ID}\", provider = \"{{name}}\", \
                 expected_version = \"{{version}}\" }}\n"
            ));
            out.push_str("value = { field = \"secret_value\", number = 3, type = \"bytes\" }\n");
            out.push_str("reply = \"connection\"\n");
            out.push_str("conflict = [\"ALREADY_EXISTS\"]\n");
            out
        })
        .world(|w| {
            // `opv-sim https` reads these at the world's top level.
            let http = w["http"].clone();
            for key in ["descriptor", "operator_id", "token", "rejected"] {
                w[key] = http[key].clone();
            }
            // Every remote name the mapping may use; `tavily` is the world's rejected one.
            w["providers"] =
                json!(["openrouter", "tavily", "stripe", "database", "tls-cert", "tls-key"]);
            w["op"]["vaults"].as_array_mut().expect("vaults").push(json!({
                "id": DEPLOY_VAULT,
                "name": DEPLOY_VAULT_NAME,
                "account": DEV_ACCOUNT,
            }));
            w["op"]["items"].as_array_mut().expect("items").push(json!({
                "id": DEPLOY_ITEM,
                "title": DEPLOY_ITEM_TITLE,
                "version": 1,
                "vault": {"id": DEPLOY_VAULT, "name": DEPLOY_VAULT_NAME},
                "category": "SECURE_NOTE",
                "fields": [
                    {"id": "base_url", "type": "STRING", "label": "base_url",
                     "value": format!("https://{HOST}")},
                    {"id": "token", "type": "CONCEALED", "label": "token", "value": TOKEN},
                    {"id": "cf_access_client_id", "type": "CONCEALED",
                     "label": "cf_access_client_id", "value": CF_CLIENT_ID},
                    {"id": "cf_access_client_secret", "type": "CONCEALED",
                     "label": "cf_access_client_secret", "value": CF_CLIENT_SECRET},
                ]
            }));
            w["op"]["vaults"].as_array_mut().expect("vaults").push(json!({
                "id": STATE_VAULT,
                "name": STATE_VAULT_NAME,
                "account": DEV_ACCOUNT,
            }));
            w["op"]["items"].as_array_mut().expect("items").push(json!({
                "id": DELIVERY_ITEM,
                "title": "opv · delivery · web · platform",
                "version": 1,
                "vault": {"id": STATE_VAULT, "name": STATE_VAULT_NAME},
                "category": "SECURE_NOTE",
                "fields": [{"id": "notesPlain", "type": "STRING", "purpose": "NOTES",
                            "label": "notesPlain", "value": ""}]
            }));
        })
}

/// `version_bumped` on the next Save: the listed version is stale and the write conflicts.
fn version_bumped() -> Scenario {
    platform(NAMES).faults(
        "[[fault]]\nprogram = \"https\"\n\
         call = \"POST portal.v1.PlatformConsoleService/SavePlatformConnection\"\n\
         kind = \"version_bumped\"\noccurrence = \"first\"\n",
    )
}

/// A provider the world marks `rejected`: the write is accepted, then checked.
fn rejected_provider() -> Scenario {
    platform(REJECTED_NAMES)
}

/// The deploy credentials item's token replaced by one the store does not accept.
fn wrong_token() -> Scenario {
    platform(NAMES).world(|w| {
        for item in w["op"]["items"].as_array_mut().expect("items") {
            if item["id"] == DEPLOY_ITEM {
                for field in item["fields"].as_array_mut().expect("fields") {
                    if field["label"] == "token" {
                        field["value"] = json!(WRONG_TOKEN);
                    }
                }
            }
        }
    })
}

/// The Save is applied, then the `https` program dies without a reply.
fn reply_lost() -> Scenario {
    platform(NAMES).faults(
        "[[fault]]\nprogram = \"https\"\n\
         call = \"POST portal.v1.PlatformConsoleService/SavePlatformConnection\"\n\
         kind = \"applied_but_reply_lost\"\noccurrence = \"first\"\n",
    )
}

/// The rejected provider's scenario after its (failed) sync, so a later run reads the
/// receipt the sync recorded before it checked the written names.
fn synced_rejected_provider() -> Scenario {
    let s = rejected_provider();
    let run = s.opv(&args(SYNC));
    assert_eq!(run.code, Some(5), "{}{}", run.stdout, run.stderr);
    s
}

// --- the four faults -------------------------------------------------------------------------

#[test]
fn version_bumped_is_target_changed() {
    let run = version_bumped().opv(&args(&[SYNC, &["--json"]].concat()));
    assert_eq!(
        document(&run)["error"]["code"],
        "target_changed",
        "{}{}",
        run.stdout,
        run.stderr
    );
}

#[test]
fn version_bumped_exits_5() {
    let run = version_bumped().opv(&args(SYNC));
    assert_eq!(run.code, Some(5), "{}{}", run.stdout, run.stderr);
}

#[test]
fn a_rejected_provider_is_target_unhealthy() {
    let run = rejected_provider().opv(&args(&[SYNC, &["--json"]].concat()));
    assert_eq!(
        document(&run)["error"]["code"],
        "target_unhealthy",
        "{}{}",
        run.stdout,
        run.stderr
    );
}

#[test]
fn a_rejected_provider_exits_5() {
    let run = rejected_provider().opv(&args(SYNC));
    assert_eq!(run.code, Some(5), "{}{}", run.stdout, run.stderr);
}

#[test]
fn a_rejected_provider_records_the_receipt_before_failing() {
    let s = synced_rejected_provider();
    let run = s.opv(&args(&[VERIFY, &["--json"]].concat()));
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
    let doc = document(&run);
    let placement = doc["placements"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|p| p["target"] == "platform" && p["product"] == "web")
        .cloned()
        .unwrap_or_else(|| panic!("no web/platform placement: {doc}"));
    assert_eq!(placement["state"], "verified", "{doc}");
}

#[test]
fn a_wrong_token_is_deploy_credentials_failed() {
    let run = wrong_token().opv(&args(&[SYNC, &["--json"]].concat()));
    assert_eq!(
        document(&run)["error"]["code"],
        "deploy_credentials_failed",
        "{}{}",
        run.stdout,
        run.stderr
    );
}

#[test]
fn a_wrong_token_exits_7() {
    let run = wrong_token().opv(&args(SYNC));
    assert_eq!(run.code, Some(7), "{}{}", run.stdout, run.stderr);
}

#[test]
fn a_wrong_token_names_the_deploy_credentials_item() {
    // The catalogue's subject loses the deploy identity (the store builds the cause after
    // the principal's scope ended); the run's own diagnosis still names the item it read.
    let run = wrong_token().opv(&args(SYNC));
    assert!(
        run.stderr.contains(DEPLOY_ITEM_TITLE),
        "the refusal must name the deploy credentials item:\n{}",
        run.stderr
    );
}

#[test]
fn a_lost_reply_is_outcome_unknown() {
    let run = reply_lost().opv(&args(&[SYNC, &["--json"]].concat()));
    assert_eq!(
        document(&run)["error"]["code"],
        "outcome_unknown",
        "{}{}",
        run.stdout,
        run.stderr
    );
}

#[test]
fn a_lost_reply_exits_9() {
    let run = reply_lost().opv(&args(SYNC));
    assert_eq!(run.code, Some(9), "{}{}", run.stdout, run.stderr);
}

// --- the snapshot ----------------------------------------------------------------------------

/// What a snapshot must not depend on beyond [`Scenario::normalize`]: when and by which opv
/// version a target was last written, and the plan id of that write (text and `--json`).
fn steady(text: &str) -> String {
    let stamp = regex::Regex::new(
        r"last changed by opv \S+ at \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ \(plan [0-9a-f]+\)",
    )
    .expect("regex");
    let text = stamp.replace_all(text, "last changed by opv <version> at <time> (plan <id>)");
    let provenance =
        regex::Regex::new(r#""written":"[^"]*","plan_id":"[0-9a-f]+""#).expect("regex");
    let text = provenance.replace_all(&text, r#""written":"<time>","plan_id":"<id>""#);
    // A delivery revision is random (src/domain/delivery.rs), so the snapshot cannot hold
    // the id a particular run minted.
    let revision = regex::Regex::new(r"drv-[a-z0-9]+").expect("regex");
    revision.replace_all(&text, "drv-<id>").into_owned()
}

/// One run as snapshot sections. The headings name the case, never `json stdout` or
/// `mcp …`, so the coverage gates read no document of this snapshot as a scenario's.
fn section(snap: &mut String, label: &str, run: &Run) {
    snap.push_str(&format!(
        "\n## {label} exit: {}\n## {label} stdout\n{}\n## {label} stderr\n{}",
        run.code.map_or("killed".into(), |c| c.to_string()),
        steady(&run.stdout),
        steady(&run.stderr),
    ));
}

/// Each fault's telling runs, text and `--json`, each case on a fresh world.
fn transcript() -> String {
    let mut snap =
        String::from("# http_target_faults: the HTTPS target's failure paths through the real binary\n");
    let both = |snap: &mut String, label: &str, build: &dyn Fn() -> Scenario, a: &[&str]| {
        section(snap, &format!("{label} text"), &build().opv(&args(a)));
        let json = [a, &["--json"]].concat();
        section(snap, &format!("{label} --json"), &build().opv(&args(&json)));
    };
    both(
        &mut snap,
        "version bumped opv sync prod --target platform",
        &version_bumped,
        SYNC,
    );
    both(
        &mut snap,
        "rejected provider opv sync prod --target platform",
        &rejected_provider,
        SYNC,
    );
    both(
        &mut snap,
        "rejected provider opv delivery verify prod --target platform",
        &synced_rejected_provider,
        VERIFY,
    );
    both(
        &mut snap,
        "wrong token opv sync prod --target platform",
        &wrong_token,
        SYNC,
    );
    both(
        &mut snap,
        "lost reply opv sync prod --target platform",
        &reply_lost,
        SYNC,
    );
    snap
}

#[test]
fn the_faults_match_their_snapshot() {
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
