//! Unit tests for the pure volume functions (design §6.3, §6.6). Every test is one atomic
//! scenario with one assertion; the recorded K1 fixtures are the only source of deployment
//! shapes (`tests/fixtures/kubernetes/success/`, K-R1/K-R3).

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::*;

const SENT: &str =
    include_str!("../../../tests/fixtures/kubernetes/success/08-replace-files-volume.stdin.json");
const BEFORE: &str = include_str!(
    "../../../tests/fixtures/kubernetes/success/07-get-deployment-before-files.stdout"
);
const AFTER: &str =
    include_str!("../../../tests/fixtures/kubernetes/success/09-get-deployment-after-files.stdout");
const MINIMAL: &str = include_str!(
    "../../../tests/fixtures/kubernetes/success/11-get-deployment-after-minimal.stdout"
);

const DIR: &str = "/run/secrets/{product}";
const PRODUCT: &str = "api";
const PRIVATE_KEY: &str = "opv-api--private-key-abcdefghij";
const OTEL_RESOURCE: &str = "opv-api--otel-resource-abcdefghij";

fn doc(text: &str) -> Value {
    serde_json::from_str(text).unwrap()
}

fn sent() -> Value {
    doc(SENT)
}

fn before() -> Value {
    doc(BEFORE)
}

fn after() -> Value {
    doc(AFTER)
}

fn minimal() -> Value {
    doc(MINIMAL)
}

fn items() -> Vec<(&'static str, ObjectKind, &'static str)> {
    vec![
        (PRIVATE_KEY, ObjectKind::Secret, "github-app/private-key"),
        (OTEL_RESOURCE, ObjectKind::ConfigMap, "otel/resource"),
    ]
}

fn after_with(edit: impl FnOnce(&mut Value)) -> Value {
    let mut d = after();
    edit(&mut d);
    d
}

fn container<'a>(d: &'a Value, name: &str) -> &'a Value {
    d.pointer("/spec/template/spec/containers")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap()
}

fn drop_env(d: &mut Value) {
    for c in d
        .pointer_mut("/spec/template/spec/containers")
        .and_then(Value::as_array_mut)
        .into_iter()
        .flatten()
    {
        c.as_object_mut().unwrap().remove("env");
    }
}

// ---- volume / mount golden JSON ----

#[test]
fn the_projected_volume_equals_the_sent_design_section_volume() {
    let expected = sent()
        .pointer("/spec/template/spec/volumes/0")
        .unwrap()
        .clone();
    assert_eq!(volume(PRODUCT, DIR, &items()), expected);
}

#[test]
fn the_volume_mount_equals_the_sent_design_section_mount() {
    let expected = sent()
        .pointer("/spec/template/spec/containers/0/volumeMounts/0")
        .unwrap()
        .clone();
    assert_eq!(mount(PRODUCT, DIR), expected);
}

// ---- apply_files ----

#[test]
fn applying_files_adds_the_projected_volume() {
    let mut d = before();
    apply_files(&mut d, PRODUCT, PRODUCT, DIR, &items(), &[]);
    let found = d
        .pointer("/spec/template/spec/volumes")
        .and_then(Value::as_array)
        .and_then(|vols| vols.iter().find(|v| v["name"] == "opv-files-api"));
    assert_eq!(found, Some(&volume(PRODUCT, DIR, &items())));
}

#[test]
fn applying_files_mounts_the_volume_into_the_target_container() {
    let mut d = before();
    apply_files(&mut d, PRODUCT, PRODUCT, DIR, &items(), &[]);
    let found = container(&d, PRODUCT)
        .get("volumeMounts")
        .and_then(Value::as_array)
        .and_then(|ms| ms.iter().find(|m| m["name"] == "opv-files-api"));
    assert_eq!(found, Some(&mount(PRODUCT, DIR)));
}

#[test]
fn applying_files_leaves_a_second_container_without_the_mount() {
    let mut d = before();
    apply_files(&mut d, PRODUCT, PRODUCT, DIR, &items(), &[]);
    assert_eq!(container(&d, "sidecar").get("volumeMounts"), None);
}

#[test]
fn applying_files_removes_the_file_keys_environment_entry() {
    let mut d = before();
    apply_files(
        &mut d,
        PRODUCT,
        PRODUCT,
        DIR,
        &items(),
        &["FLEET__API__PRIVATE_KEY".to_string()],
    );
    assert!(
        !container(&d, PRODUCT)
            .get("env")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|e| e["name"] == "FLEET__API__PRIVATE_KEY")
    );
}

#[test]
fn removing_the_last_file_key_removes_the_volume() {
    let mut d = after();
    apply_files(&mut d, PRODUCT, PRODUCT, DIR, &[], &[]);
    assert_eq!(d.pointer("/spec/template/spec/volumes"), None);
}

#[test]
fn removing_the_last_file_key_removes_the_mount() {
    let mut d = after();
    apply_files(&mut d, PRODUCT, PRODUCT, DIR, &[], &[]);
    assert_eq!(container(&d, PRODUCT).get("volumeMounts"), None);
}

#[test]
fn applying_files_keeps_a_foreign_volume() {
    let mut d = after();
    d["spec"]["template"]["spec"]["volumes"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name": "foreign", "emptyDir": {}}));
    apply_files(&mut d, PRODUCT, PRODUCT, DIR, &[], &[]);
    let kept = d
        .pointer("/spec/template/spec/volumes")
        .and_then(Value::as_array)
        .is_some_and(|vols| vols.iter().any(|v| v["name"] == "foreign"));
    assert!(kept);
}

// ---- read_bindings ----

#[test]
fn reading_the_stored_bindings_returns_both_file_objects() {
    let found = read_bindings(&after(), PRODUCT, PRODUCT, DIR);
    let expected = BTreeMap::from([
        (
            "github-app/private-key".to_string(),
            Binding::Bound {
                object: PRIVATE_KEY.to_string(),
                kind: ObjectKind::Secret,
            },
        ),
        (
            "otel/resource".to_string(),
            Binding::Bound {
                object: OTEL_RESOURCE.to_string(),
                kind: ObjectKind::ConfigMap,
            },
        ),
    ]);
    assert_eq!(found, expected);
}

#[test]
fn an_item_without_the_value_key_is_a_missing_item() {
    let d = after_with(|d| {
        d["spec"]["template"]["spec"]["volumes"][0]["projected"]["sources"][0]["secret"]["items"]
            [0]["key"] = json!("other");
    });
    assert_eq!(
        read_bindings(&d, PRODUCT, PRODUCT, DIR).get("github-app/private-key"),
        Some(&Binding::Other(Why::MissingItem))
    );
}

#[test]
fn a_missing_volume_mount_is_reported() {
    let d = after_with(|d| {
        d["spec"]["template"]["spec"]["containers"][0]
            .as_object_mut()
            .unwrap()
            .remove("volumeMounts");
    });
    assert_eq!(
        read_bindings(&d, PRODUCT, PRODUCT, DIR).get("github-app/private-key"),
        Some(&Binding::Other(Why::MountMissing))
    );
}

#[test]
fn a_mount_without_read_only_is_reported() {
    let d = after_with(|d| {
        d["spec"]["template"]["spec"]["containers"][0]["volumeMounts"][0]
            .as_object_mut()
            .unwrap()
            .remove("readOnly");
    });
    assert_eq!(
        read_bindings(&d, PRODUCT, PRODUCT, DIR).get("github-app/private-key"),
        Some(&Binding::Other(Why::NotReadOnly))
    );
}

#[test]
fn a_mount_at_another_path_is_reported() {
    let d = after_with(|d| {
        d["spec"]["template"]["spec"]["containers"][0]["volumeMounts"][0]["mountPath"] =
            json!("/run/secrets/elsewhere");
    });
    assert_eq!(
        read_bindings(&d, PRODUCT, PRODUCT, DIR).get("github-app/private-key"),
        Some(&Binding::Other(Why::WrongPath))
    );
}

#[test]
fn an_object_still_referenced_by_an_environment_entry_is_reported() {
    let d = after_with(|d| {
        d["spec"]["template"]["spec"]["containers"][0]["env"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "name": "OTEL_RESOURCE",
                "valueFrom": {"configMapKeyRef": {"name": OTEL_RESOURCE, "key": "value"}}
            }));
    });
    assert_eq!(
        read_bindings(&d, PRODUCT, PRODUCT, DIR).get("otel/resource"),
        Some(&Binding::Other(Why::StillEnv))
    );
}

// ---- strip_managed ----

#[test]
fn stripping_the_file_volume_leaves_the_before_deployment_template() {
    let mut stripped = strip_managed(&after());
    let mut unchanged = before();
    drop_env(&mut stripped);
    drop_env(&mut unchanged);
    assert_eq!(
        stripped.pointer("/spec/template/spec"),
        unchanged.pointer("/spec/template/spec")
    );
}

#[test]
fn stripping_the_minimal_recording_matches_the_explicit_recording_template() {
    assert_eq!(
        strip_managed(&minimal()).pointer("/spec/template/spec"),
        strip_managed(&after()).pointer("/spec/template/spec")
    );
}

#[test]
fn stripping_normalises_the_server_added_projected_default_mode() {
    let defaulted = json!({"spec": {"template": {"spec": {"volumes": [
        {"name": "foreign", "projected": {"defaultMode": SERVER_DEFAULT_MODE, "sources": []}}
    ]}}}});
    let omitted = json!({"spec": {"template": {"spec": {"volumes": [
        {"name": "foreign", "projected": {"sources": []}}
    ]}}}});
    assert_eq!(strip_managed(&defaulted), strip_managed(&omitted));
}

// ---- readability (design §6.6) ----

#[test]
fn a_pod_fs_group_is_readable() {
    assert_eq!(
        readability(Some(&json!({"fsGroup": 10001})), None),
        Verdict::Readable
    );
}

#[test]
fn a_root_user_without_fs_group_is_readable_as_root() {
    assert_eq!(
        readability(Some(&json!({"runAsUser": 0})), None),
        Verdict::ReadableAsRoot
    );
}

#[test]
fn a_group_zero_user_without_fs_group_is_readable_as_group_zero() {
    assert_eq!(
        readability(
            Some(&json!({})),
            Some(&json!({"runAsUser": 10001, "runAsGroup": 0}))
        ),
        Verdict::ReadableAsGroupZero
    );
}

#[test]
fn a_non_root_non_group_zero_user_is_unreadable() {
    assert_eq!(
        readability(
            Some(&json!({})),
            Some(&json!({"runAsUser": 10001, "runAsGroup": 10001}))
        ),
        Verdict::Unreadable
    );
}

#[test]
fn an_unknown_group_without_fs_group_is_unknown() {
    assert_eq!(
        readability(Some(&json!({})), Some(&json!({"runAsUser": 10001}))),
        Verdict::Unknown
    );
}

#[test]
fn an_unknown_user_without_fs_group_is_unknown() {
    assert_eq!(
        readability(Some(&json!({"runAsGroup": 10001})), None),
        Verdict::Unknown
    );
}

#[test]
fn a_container_user_overrides_the_pod_user() {
    assert_eq!(
        readability(
            Some(&json!({"runAsUser": 0})),
            Some(&json!({"runAsUser": 10001, "runAsGroup": 10001}))
        ),
        Verdict::Unreadable
    );
}

// ---- mount_conflict ----

#[test]
fn a_foreign_mount_at_the_same_path_is_a_conflict() {
    let d = after_with(|d| {
        d["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name": "foreign", "mountPath": "/run/secrets/api"}));
    });
    assert_eq!(
        mount_conflict(&d, PRODUCT, "/run/secrets/api"),
        Some(("foreign".to_string(), "/run/secrets/api".to_string()))
    );
}

#[test]
fn a_foreign_mount_above_the_path_is_a_conflict() {
    let d = after_with(|d| {
        d["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name": "foreign", "mountPath": "/run/secrets"}));
    });
    assert_eq!(
        mount_conflict(&d, PRODUCT, "/run/secrets/api"),
        Some(("foreign".to_string(), "/run/secrets".to_string()))
    );
}

#[test]
fn a_foreign_mount_below_the_path_is_a_conflict() {
    let d = after_with(|d| {
        d["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name": "foreign", "mountPath": "/run/secrets/api/sub"}));
    });
    assert_eq!(
        mount_conflict(&d, PRODUCT, "/run/secrets/api"),
        Some(("foreign".to_string(), "/run/secrets/api/sub".to_string()))
    );
}

#[test]
fn opvs_own_mount_is_not_a_conflict() {
    assert_eq!(mount_conflict(&after(), PRODUCT, "/run/secrets/api"), None);
}

#[test]
fn a_sibling_mount_is_not_a_conflict() {
    let d = after_with(|d| {
        d["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name": "foreign", "mountPath": "/run/secrets/other"}));
    });
    assert_eq!(mount_conflict(&d, PRODUCT, "/run/secrets/api"), None);
}

// ---- no-value property ----

const MARKER: &str = "S7MARKER";

fn next(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}

fn random_name(state: &mut u64, len: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789-";
    (0..len)
        .map(|_| ALPHABET[(next(state) % ALPHABET.len() as u64) as usize] as char)
        .collect()
}

#[test]
fn the_volume_functions_never_emit_a_value_marker() {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut emitted = String::new();
    for _ in 0..200 {
        let product = random_name(&mut state, 6);
        let dir = format!("/run/secrets/{{product}}/{}", random_name(&mut state, 4));
        let count = (next(&mut state) % 4) as usize;
        let names: Vec<String> = (0..count).map(|_| random_name(&mut state, 12)).collect();
        let paths: Vec<String> = (0..count).map(|_| random_name(&mut state, 8)).collect();
        let items: Vec<(&str, ObjectKind, &str)> = names
            .iter()
            .zip(paths.iter())
            .enumerate()
            .map(|(i, (name, path))| {
                let kind = if i % 2 == 0 {
                    ObjectKind::Secret
                } else {
                    ObjectKind::ConfigMap
                };
                (name.as_str(), kind, path.as_str())
            })
            .collect();
        emitted.push_str(&volume(&product, &dir, &items).to_string());
        let mut deployment = before();
        apply_files(&mut deployment, PRODUCT, &product, &dir, &items, &[]);
        emitted.push_str(&deployment.to_string());
    }
    assert!(!emitted.contains(MARKER));
}
