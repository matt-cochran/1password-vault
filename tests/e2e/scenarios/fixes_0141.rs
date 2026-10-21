//! The four fixes of opv 0.14.1, each proven by unit tests, reached through the real `opv`
//! binary against `opv-sim` on the test application in `tests/e2e/app`:
//!
//! 1. #218: `opv changed prod` before any sync, where the placement's delivery item is
//!    recorded but op answers its `source versions` field with "item … does not have a field"
//!    (recording 16), is `no_record`: `ok: true`, exit 10.
//! 2. #221: `opv changed prod` run under a service-account token whose service account was deleted
//!    (op's "(403) Forbidden (Service Account Deleted)", recording 17) is the rejected
//!    service-account token (`credential_rejected`, exit 7), not `unrecognized_failure`.
//! 3. #219, Fly (a staged target): after a sync, a secret whose digest changed outside opv
//!    makes `status prod --fail-on-drift` exit 8 (`target_drift`); without the flag, 0.
//! 4. #219, Kubernetes: after `sync --deploy`, a deployed env reference replaced by a literal
//!    value makes `status prod --fail-on-drift` exit 8 and names the key "changed outside opv
//!    since its last deploy"; a literal opv never deployed stays pending deploy, exit 0.
//! 5. #217: `opv import dev --from <file>` writes a single-quoted multi-line value of a key
//!    declared with `file = "…"`, and `opv inventory --env dev` shows it set; the same value for a
//!    key without `file` is refused `single_line`.
//!
//! **The fake `op`.** opv-sim models no `op read` (no reply is recorded) and no deleted
//! service account, so cases 1 and 2 put a small `/bin/sh` `op` in front of the simulator, as
//! `session_reuse.rs` does: it prints the recorded reply (`tests/fixtures/op/failures/16-…`,
//! `17-…`, its markers filled with the world's ids) for the call the recording is of and hands
//! every other call to the simulator. The Fly and Kubernetes cases change the world between
//! runs, as a person editing the app or the Deployment by hand would.
//!
//! Every world value carries `test-marker-e2e-`, and the values these cases add do too, so
//! the coverage canary finds any value the snapshot (`snapshots/scenarios/fixes_0141.snap`)
//! holds. Nothing here reads `/proc` or needs a Linux-only tool: each case runs on the Ubuntu
//! and macOS runners.

use std::path::Path;

use serde_json::{Value, json};

use crate::coverage::{Run, Scenario, scenario_snapshots, updating};

/// The scenario snapshots this module writes (`tests/e2e/snapshots/scenarios/`).
pub(crate) const SNAPSHOTS: &[&str] = &["fixes_0141"];

const SIM: &str = env!("CARGO_BIN_EXE_opv-sim");
const FLY_STATE_VAULT: &str = "vE2ESTATEFLY00000000000001";
const DELIVERY_ITEM: &str = "iE2EDELIVERYWEBFLY00000001";
const WEB_DEV_ITEM: &str = "iE2EWEBDEV0000000000000001";
const WEB_DEV_VAULT: &str = "vE2EWEBDEV0000000000000001";
/// The dev account's user (`tests/e2e/app/world.json`).
const DEV_USER: &str = "UE2EDEVUSER000000000000001";
const NS: &str = "/kubernetes/contexts/e2e-cluster/namespaces/e2e-prod";
/// A service-account token op knows nothing of: obviously fake.
const DELETED_TOKEN: &str = "ops_e2e_fake_token_of_a_deleted_service_account";

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

fn document(run: &Run) -> Value {
    serde_json::Deserializer::from_str(&run.stdout)
        .into_iter::<Value>()
        .next()
        .and_then(Result::ok)
        .unwrap_or_else(|| panic!("no document: {}{}", run.stdout, run.stderr))
}

/// The scenario's world, edited in place (between two runs).
fn edit_world(s: &Scenario, edit: impl FnOnce(&mut Value)) {
    let p = s.path("world/world.json");
    let mut w: Value =
        serde_json::from_str(&std::fs::read_to_string(&p).expect("world")).expect("world");
    edit(&mut w);
    std::fs::write(&p, w.to_string()).expect("world");
}

/// `op` in front of the simulator: `script` runs first, then the simulator answers. The
/// simulator stays reachable as `op` (its `argv[0]`) under `<root>/sim`.
fn fake_op(s: &Scenario, script: &str) {
    s.install();
    let sim = s.path("sim");
    std::fs::create_dir_all(&sim).expect("sim dir");
    std::os::unix::fs::symlink(SIM, sim.join("op")).expect("sim op");
    let op = s.path("bin/op");
    std::fs::remove_file(&op).expect("simulated op");
    std::fs::write(
        &op,
        format!(
            "#!/bin/sh\n{script}\nexec '{}' \"$@\"\n",
            sim.join("op").display()
        ),
    )
    .expect("fake op");
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

/// A recorded op failure under `tests/fixtures/op/failures/`, its markers filled: its stderr
/// and exit code.
fn recording(case: &str, subs: &[(&str, &str)]) -> (String, i32) {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/op/failures");
    let read =
        |ext: &str| std::fs::read_to_string(base.join(format!("{case}.{ext}"))).expect("recording");
    let stderr = subs
        .iter()
        .fold(read("stderr"), |t, (from, to)| t.replace(from, to));
    (stderr, read("exit").trim().parse().expect("exit code"))
}

/// The fake `op` replies with `reply` (its stderr kept in `<root>/sim/<name>`) when `test`
/// holds.
fn reply_when(s: &Scenario, name: &str, test: &str, reply: (String, i32)) -> String {
    let (stderr, exit) = reply;
    let file = s.path("sim").join(name);
    std::fs::create_dir_all(s.path("sim")).expect("sim dir");
    std::fs::write(&file, stderr).expect("reply");
    format!(
        "if {test}; then cat '{}' >&2; exit {exit}; fi",
        file.display()
    )
}

// --- #218: changed before any sync -----------------------------------------------------------

/// The app with the Fly placement's delivery item recorded, op as simulated.
fn with_fly_delivery_item() -> Scenario {
    Scenario::new()
        .world(|w| {
            w["op"]["items"].as_array_mut().expect("items").push(json!({
                "id": DELIVERY_ITEM,
                "title": "opv · delivery · web · fly",
                "version": 1,
                "vault": {"id": FLY_STATE_VAULT, "name": "e2e-app · fly · state"},
                "category": "SECURE_NOTE",
                "fields": [{"id": "notesPlain", "type": "STRING", "purpose": "NOTES",
                            "label": "notesPlain", "value": ""}]
            }));
        })
        .file(
            "project/secrets.bindings.toml",
            &format!(
                "{}environments.prod.targets.fly.delivery_items.web = \"{DELIVERY_ITEM}\"\n",
                std::fs::read_to_string(
                    Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("tests/e2e/app/secrets.bindings.toml")
                )
                .expect("bindings")
            ),
        )
}

/// The Fly placement's delivery item recorded (as setup leaves it) and never synced: op says
/// the item has no `source versions` field (recording 16).
fn never_synced() -> Scenario {
    let s = with_fly_delivery_item();
    let reply = recording(
        "16-item-field-missing",
        &[("<VAULT>", FLY_STATE_VAULT), ("<ITEM>", DELIVERY_ITEM)],
    );
    let test = r#"[ "$1" = read ] && case "$*" in *"/source versions"*) true ;; *) false ;; esac"#;
    let script = reply_when(&s, "field-missing", test, reply);
    fake_op(&s, &script);
    s
}

fn changed_before_any_sync() -> Run {
    never_synced().opv(&args(&["changed", "prod", "--json"]))
}

#[test]
fn changed_before_any_sync_exits_10() {
    let run = changed_before_any_sync();
    assert_eq!(run.code, Some(10), "{}{}", run.stdout, run.stderr);
}

#[test]
fn changed_before_any_sync_is_ok() {
    let run = changed_before_any_sync();
    assert_eq!(document(&run)["ok"], true, "{}{}", run.stdout, run.stderr);
}

#[test]
fn changed_before_any_sync_reports_the_fly_placement_no_record() {
    let run = changed_before_any_sync();
    let doc = document(&run);
    let fly = doc["placements"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|p| p["target"] == "fly")
        .cloned()
        .unwrap_or_default();
    assert_eq!(fly["state"], "no_record", "{doc}");
}

// --- #221: a deleted service account --------------------------------------------------------

/// The CI job of #221: `opv changed` under the token of a service account since deleted, the
/// Fly placement's delivery item recorded.
fn deleted_service_account() -> Scenario {
    let s = with_fly_delivery_item()
        .var("CI", "true")
        .var("OP_SERVICE_ACCOUNT_TOKEN", DELETED_TOKEN);
    let reply = recording("17-service-account-deleted", &[]);
    let test = r#"[ -n "$OP_SERVICE_ACCOUNT_TOKEN" ] && [ "$1" != --version ]"#;
    let script = reply_when(&s, "service-account-deleted", test, reply);
    fake_op(&s, &script);
    s
}

fn changed_under_a_deleted_service_account() -> Run {
    deleted_service_account().opv(&args(&["changed", "prod", "--json"]))
}

#[test]
fn a_deleted_service_account_exits_7() {
    let run = changed_under_a_deleted_service_account();
    assert_eq!(run.code, Some(7), "{}{}", run.stdout, run.stderr);
}

#[test]
fn a_deleted_service_account_is_a_rejected_service_account_token() {
    let run = changed_under_a_deleted_service_account();
    let error = &document(&run)["error"];
    assert_eq!(
        (&error["code"], &error["subject"]["credential"]),
        (
            &json!("credential_rejected"),
            &json!({"kind": "service_account_token", "var": "OP_SERVICE_ACCOUNT_TOKEN"})
        ),
        "{error}"
    );
}

// --- #219: Fly, a staged target -------------------------------------------------------------

const FLY_NAME: &str = "E2E__WEB__API_KEY";

/// Synced to Fly, then `API_KEY` set on Fly by hand: a new digest.
fn fly_changed_outside_opv() -> Scenario {
    let s = with_fly_delivery_item();
    let run = s.opv(&args(&[
        "sync",
        "prod",
        "--confirm",
        "prod",
        "--target",
        "fly",
    ]));
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
    edit_world(&s, |w| {
        let secrets = w["fly"]["apps"]["e2e-app-prod"]["secrets"]
            .as_array_mut()
            .expect("secrets");
        secrets.retain(|x| x["name"] != FLY_NAME);
        secrets.push(json!({"name": FLY_NAME, "digest": "00000000fa4e0219", "status": "Deployed"}));
    });
    s
}

#[test]
fn fly_value_changed_outside_opv_fails_status_on_drift_with_8() {
    let s = fly_changed_outside_opv();
    let run = s.opv(&args(&[
        "status",
        "prod",
        "--target",
        "fly",
        "--fail-on-drift",
    ]));
    assert_eq!(run.code, Some(8), "{}{}", run.stdout, run.stderr);
}

#[test]
fn fly_value_changed_outside_opv_is_target_drift() {
    let s = fly_changed_outside_opv();
    let run = s.opv(&args(&[
        "status",
        "prod",
        "--target",
        "fly",
        "--fail-on-drift",
        "--json",
    ]));
    assert_eq!(
        document(&run)["error"]["code"],
        "target_drift",
        "{}{}",
        run.stdout,
        run.stderr
    );
}

#[test]
fn fly_value_changed_outside_opv_without_the_flag_exits_0() {
    let s = fly_changed_outside_opv();
    let run = s.opv(&args(&["status", "prod", "--target", "fly"]));
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
}

// --- #219: Kubernetes, a pinned target ------------------------------------------------------

const K8S_NAME: &str = "E2E__WEB__API_KEY";
/// What a person types into the Deployment by hand: obviously fake, and a world marker.
const LITERAL: &str = "test-marker-e2e-fake-literal-typed-by-hand";

/// The `e2e-app` container's env, edited.
fn edit_container_env(s: &Scenario, edit: impl FnOnce(&mut Vec<Value>)) {
    edit_world(s, |w| {
        let container = w
            .pointer_mut(&format!(
                "{NS}/deployments/0/spec/template/spec/containers/0"
            ))
            .expect("the e2e-app container");
        if container.get("env").is_none() {
            container["env"] = json!([]);
        }
        edit(container["env"].as_array_mut().expect("env"));
    });
}

const K8S_SYNC: &[&str] = &["sync", "prod", "--confirm", "prod", "--target", "k8s"];
const K8S_DRIFT: &[&str] = &["status", "prod", "--target", "k8s", "--fail-on-drift"];

/// Deployed by `sync --deploy`, then `API_KEY`'s reference replaced by a literal value.
fn k8s_reference_replaced_by_hand() -> Scenario {
    let s = Scenario::new();
    let run = s.opv(&args(&[K8S_SYNC, &["--deploy"]].concat()));
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
    edit_container_env(&s, |env| {
        let entry = env
            .iter_mut()
            .find(|e| e["name"] == K8S_NAME)
            .expect("the deployed reference");
        *entry = json!({"name": K8S_NAME, "value": LITERAL});
    });
    s
}

/// Synced without a deploy, `API_KEY` set as a literal in the Deployment by hand: opv never
/// bound it by reference.
fn k8s_literal_never_deployed() -> Scenario {
    let s = Scenario::new();
    edit_container_env(&s, |env| {
        env.push(json!({"name": K8S_NAME, "value": LITERAL}))
    });
    let run = s.opv(&args(K8S_SYNC));
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
    s
}

#[test]
fn k8s_reference_replaced_by_hand_fails_status_on_drift_with_8() {
    let run = k8s_reference_replaced_by_hand().opv(&args(K8S_DRIFT));
    assert_eq!(run.code, Some(8), "{}{}", run.stdout, run.stderr);
}

#[test]
fn k8s_reference_replaced_by_hand_is_named_changed_outside_opv() {
    let run = k8s_reference_replaced_by_hand().opv(&args(K8S_DRIFT));
    assert!(
        run.stdout.lines().any(|l| l.contains(
            "changed outside opv since its last deploy: web/API_KEY (E2E__WEB__API_KEY)"
        )),
        "{}{}",
        run.stdout,
        run.stderr
    );
}

#[test]
fn k8s_literal_never_deployed_does_not_fail_status_on_drift() {
    let run = k8s_literal_never_deployed().opv(&args(K8S_DRIFT));
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
}

#[test]
fn k8s_literal_never_deployed_stays_pending_deploy() {
    let run = k8s_literal_never_deployed().opv(&args(&[K8S_DRIFT, &["--json"]].concat()));
    let row = document(&run)["rows"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|r| r["target_name"] == K8S_NAME)
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        (&row["pending_deploy"], &row["drift"]),
        (&json!(true), &json!(false)),
        "{row}"
    );
}

// --- #217: a multi-line value in an import file ---------------------------------------------

/// A single-quoted multi-line value, obviously fake, every line a world marker.
const MULTI_LINE: &str = "'-----BEGIN FAKE TEST CERTIFICATE-----\n\
                          test-marker-e2e-fake-certificate-line\n\
                          -----END FAKE TEST CERTIFICATE-----'";

/// dev's `web/<key>` empty in 1Password, and `local.env` holding the multi-line value for
/// `<key>`.
fn importing(key: &'static str) -> Scenario {
    Scenario::new()
        .world(move |w| {
            // The developer reads the dev web vault, so inventory reads its cells.
            for v in w["op"]["vaults"].as_array_mut().expect("vaults") {
                if v["id"] == WEB_DEV_VAULT {
                    v["users"] = json!([{"id": DEV_USER, "name": "E2E Dev",
                                         "email": "dev@example.com"}]);
                }
            }
            for item in w["op"]["items"].as_array_mut().expect("items") {
                if item["id"] != WEB_DEV_ITEM {
                    continue;
                }
                for f in item["fields"].as_array_mut().expect("fields") {
                    if f["label"] == key {
                        f["value"] = json!("");
                    }
                }
            }
        })
        .file("project/local.env", &format!("{key}={MULTI_LINE}\n"))
        .mode("project/local.env", 0o600)
}

const IMPORT: &[&str] = &["import", "dev", "--from", "local.env"];

/// The import row of `web/<key>`.
fn import_row(run: &Run, key: &str) -> Value {
    document(run)["rows"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|r| r["key"] == key)
        .cloned()
        .unwrap_or_else(|| panic!("no row for {key}: {}{}", run.stdout, run.stderr))
}

#[test]
fn import_writes_a_multi_line_value_of_a_file_key() {
    let run = importing("TLS_CERTIFICATE").opv(&args(&[IMPORT, &["--json"]].concat()));
    assert_eq!(import_row(&run, "TLS_CERTIFICATE")["action"], "imported");
}

#[test]
fn inventory_shows_an_imported_multi_line_file_key_set() {
    let s = importing("TLS_CERTIFICATE");
    let run = s.opv(&args(IMPORT));
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
    let run = s.opv(&args(&["inventory", "--env", "dev", "--json"]));
    assert_eq!(inventory_state(&run, "TLS_CERTIFICATE"), "set");
}

#[test]
fn import_refuses_a_multi_line_value_of_a_non_file_key_single_line() {
    let run = importing("SESSION_SECRET").opv(&args(&[IMPORT, &["--json"]].concat()));
    let row = import_row(&run, "SESSION_SECRET");
    assert_eq!(
        (&row["action"], &row["rule"]),
        (&json!("fails_rule"), &json!("single_line")),
        "{row}"
    );
}

/// The dev state `opv inventory --env dev --json` gives `web/<key>`.
fn inventory_state(run: &Run, key: &str) -> String {
    let doc = document(run);
    doc["cells"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|c| c["product"] == "web" && c["key"] == key && c["env"] == "dev")
        .and_then(|c| c["state"]["state"].as_str())
        .unwrap_or_else(|| panic!("no dev cell for web/{key}: {doc}"))
        .to_string()
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
    let provenance =
        regex::Regex::new(r#""written":"[^"]*","plan_id":"[0-9a-f]+""#).expect("regex");
    provenance
        .replace_all(&text, r#""written":"<time>","plan_id":"<id>""#)
        .into_owned()
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

/// Each fix's telling runs, text and `--json`, each case on a fresh world.
fn transcript() -> String {
    let mut snap = String::from("# fixes_0141: the opv 0.14.1 fixes through the real binary\n");
    let both = |snap: &mut String, label: &str, build: &dyn Fn() -> Scenario, a: &[&str]| {
        section(snap, &format!("{label} text"), &build().opv(&args(a)));
        let json = [a, &["--json"]].concat();
        section(snap, &format!("{label} --json"), &build().opv(&args(&json)));
    };
    both(
        &mut snap,
        "#218 opv changed prod",
        &never_synced,
        &["changed", "prod"],
    );
    both(
        &mut snap,
        "#221 opv changed prod (deleted service account)",
        &deleted_service_account,
        &["changed", "prod"],
    );
    both(
        &mut snap,
        "#219 fly opv status prod --target fly --fail-on-drift",
        &fly_changed_outside_opv,
        &["status", "prod", "--target", "fly", "--fail-on-drift"],
    );
    both(
        &mut snap,
        "#219 k8s replaced by hand opv status prod --target k8s --fail-on-drift",
        &k8s_reference_replaced_by_hand,
        K8S_DRIFT,
    );
    both(
        &mut snap,
        "#219 k8s never deployed opv status prod --target k8s --fail-on-drift",
        &k8s_literal_never_deployed,
        K8S_DRIFT,
    );
    both(
        &mut snap,
        "#217 file key opv import dev --from local.env",
        &|| importing("TLS_CERTIFICATE"),
        IMPORT,
    );
    both(
        &mut snap,
        "#217 non-file key opv import dev --from local.env",
        &|| importing("SESSION_SECRET"),
        IMPORT,
    );
    snap
}

#[test]
fn the_fixes_match_their_snapshot() {
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
