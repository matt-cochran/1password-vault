//! File keys and ConfigMaps on the Deployment (K5, design §6.3): `apply`, `bindings`,
//! `fingerprint`, the reconcile comparison and `chain`, fed from the recorded Deployments
//! (`tests/fixtures/kubernetes/`, K1). Names only: no value enters the Deployment.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde_json::{Value, json};

use super::super::testutil::*;
use super::*;
use crate::domain::runtime::FileMount;
use crate::runner::fake::FakeRunner;

/// `get deployment api -o json` before any file (K-R1): containers `api` and `sidecar`.
const BEFORE_FILES: &str = include_str!(
    "../../../tests/fixtures/kubernetes/success/07-get-deployment-before-files.stdout"
);
/// The replace that added the §6.3 volume, as sent (K-R1).
const REPLACE_FILES: &str =
    include_str!("../../../tests/fixtures/kubernetes/success/08-replace-files-volume.stdin.json");
/// `get deployment api -o json` after that replace: stored exactly as sent.
const AFTER_FILES: &str =
    include_str!("../../../tests/fixtures/kubernetes/success/09-get-deployment-after-files.stdout");
/// After the minimal volume: the server added `projected.defaultMode: 420` (A5).
const AFTER_MINIMAL: &str = include_str!(
    "../../../tests/fixtures/kubernetes/success/11-get-deployment-after-minimal.stdout"
);

const DIR: &str = "/run/secrets/{product}";

fn names(list: &[&str]) -> BTreeSet<String> {
    list.iter().map(|n| n.to_string()).collect()
}

fn mount(product: &str, path: &str) -> FileMount {
    FileMount {
        product: product.into(),
        path: path.into(),
    }
}

fn parsed(text: &str) -> Value {
    serde_json::from_str(text).unwrap()
}

fn stdin_of(r: &FakeRunner, i: usize) -> Value {
    serde_json::from_slice(r.calls.borrow()[i].stdin.as_ref().unwrap()).unwrap()
}

fn no_wait<'a>(rt: KubeDeployment<'a>) -> KubeDeployment<'a> {
    rt.with_wait(POLL_EVERY, Duration::from_secs(20), |_| {})
        .with_progress(|_| {})
}

fn change(pins: &[(&str, &str, &str)]) -> RuntimeChange {
    RuntimeChange {
        pin: pins
            .iter()
            .map(|(n, s, v)| (n.to_string(), (s.to_string(), v.to_string())))
            .collect(),
        set: BTreeMap::new(),
        unbind: vec![],
        stamp: None,
    }
}

// ---- the spike's Deployment (deployment-get.json): one container, `K7` unmanaged ------

/// The recorded spike Deployment on a `configmap` target with `secrets_dir`:
/// `FLEET__API__DB_URL` is a file key of product `api`, `LOG_LEVEL` a config key. `K7`
/// is bound on the recording but not managed here, so opv leaves it alone.
fn on_spike<T>(r: &FakeRunner, f: impl FnOnce(&KubeDeployment) -> T) -> T {
    let t = target();
    let rt = no_wait(
        KubeDeployment::new(
            r,
            &t,
            names(&["FLEET__API__DB_URL", "LOG_LEVEL", "NEW_KEY"]),
        )
        .with_config_in_store(true)
        .with_configmaps(true)
        .with_config_names(names(&["LOG_LEVEL"]))
        .with_files(
            Some(DIR.into()),
            BTreeMap::from([("FLEET__API__DB_URL".to_string(), mount("api", "db/url"))]),
        ),
    );
    f(&rt)
}

fn spike_change() -> RuntimeChange {
    let mut c = change(&[
        ("FLEET__API__DB_URL", "fleet--api--db-url", "s7aw2ylfpc"),
        ("LOG_LEVEL", "log-level", "h6tn4wbr5e"),
    ]);
    c.set.insert("NEW_KEY".into(), MARK.into());
    c
}

/// Reads the recorded spike Deployment, applies [`spike_change`], returns the runner.
fn spike_applied() -> FakeRunner {
    let r = FakeRunner::new([ok(DEPLOYMENT), ok("7")]);
    on_spike(&r, |rt| {
        let snap = rt.bindings().unwrap();
        rt.apply(&spike_change(), &snap).unwrap()
    });
    r
}

fn spike_sent() -> Value {
    stdin_of(&spike_applied(), 1)
}

fn spike_env(name: &str) -> Value {
    spike_sent()["spec"]["template"]["spec"]["containers"][0]["env"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == name)
        .cloned()
        .unwrap_or(Value::Null)
}

#[test]
fn apply_adds_the_products_projected_volume() {
    assert_eq!(
        spike_sent()["spec"]["template"]["spec"]["volumes"],
        json!([{"name": "opv-files-api", "projected": {"defaultMode": 288, "sources": [
            {"secret": {"name": "opv-fleet--api--db-url-s7aw2ylfpc", "optional": false,
                        "items": [{"key": "value", "path": "db/url", "mode": 288}]}}
        ]}}])
    );
}

#[test]
fn apply_mounts_the_volume_read_only_at_the_rendered_directory() {
    assert_eq!(
        spike_sent()["spec"]["template"]["spec"]["containers"][0]["volumeMounts"],
        json!([{"name": "opv-files-api", "mountPath": "/run/secrets/api", "readOnly": true}])
    );
}

#[test]
fn apply_removes_the_file_keys_env_entry() {
    assert_eq!(spike_env("FLEET__API__DB_URL"), Value::Null);
}

#[test]
fn apply_binds_config_by_config_map_key_ref_on_a_configmap_target() {
    assert_eq!(
        spike_env("LOG_LEVEL"),
        json!({"name": "LOG_LEVEL", "valueFrom": {"configMapKeyRef":
            {"name": "opv-log-level-h6tn4wbr5e", "key": "value"}}})
    );
}

#[test]
fn apply_keeps_an_unmanaged_entry() {
    assert_eq!(
        spike_env("K7"),
        json!({"name": "K7", "valueFrom": {"secretKeyRef":
            {"name": "opv-k7-h6tn4wbr5e", "key": "value"}}})
    );
}

#[test]
fn apply_with_file_keys_keeps_values_out_of_argv() {
    assert!(!all_argv(&spike_applied()).contains(MARK));
}

#[test]
fn bindings_read_back_what_apply_wrote() {
    let r = FakeRunner::new([json(&spike_sent())]);
    let read = on_spike(&r, |rt| rt.bindings()).unwrap().bindings;
    assert_eq!(
        (read.get("FLEET__API__DB_URL"), read.get("LOG_LEVEL")),
        (
            Some(&Binding::Pinned {
                store_name: "fleet--api--db-url".into(),
                version: "s7aw2ylfpc".into(),
            }),
            Some(&Binding::Pinned {
                store_name: "log-level".into(),
                version: "h6tn4wbr5e".into(),
            })
        )
    );
}

#[test]
fn a_file_key_still_bound_as_env_reads_back_other() {
    let r = FakeRunner::new([ok(DEPLOYMENT)]);
    let read = on_spike(&r, |rt| rt.bindings()).unwrap().bindings;
    assert_eq!(read.get("FLEET__API__DB_URL"), Some(&Binding::Other));
}

#[test]
fn config_bound_by_secret_key_ref_on_a_configmap_target_reads_back_other() {
    let doc = deployment_with(|d| {
        d["spec"]["template"]["spec"]["containers"][0]["env"][1] = json!({"name": "LOG_LEVEL",
            "valueFrom": {"secretKeyRef": {"name": "opv-log-level-h6tn4wbr5e", "key": "value"}}});
    });
    let r = FakeRunner::new([json(&doc)]);
    let read = on_spike(&r, |rt| rt.bindings()).unwrap().bindings;
    assert_eq!(read.get("LOG_LEVEL"), Some(&Binding::Other));
}

#[test]
fn config_on_the_store_route_keeps_secret_key_ref() {
    let t = target();
    let r = FakeRunner::new([ok(DEPLOYMENT), ok("7")]);
    let rt = no_wait(
        KubeDeployment::new(&r, &t, names(&["LOG_LEVEL"]))
            .with_config_in_store(true)
            .with_config_names(names(&["LOG_LEVEL"])),
    );
    let snap = rt.bindings().unwrap();
    rt.apply(&change(&[("LOG_LEVEL", "log-level", "h6tn4wbr5e")]), &snap)
        .unwrap();
    assert_eq!(
        stdin_of(&r, 1)["spec"]["template"]["spec"]["containers"][0]["env"][1],
        json!({"name": "LOG_LEVEL", "valueFrom": {"secretKeyRef":
            {"name": "opv-log-level-h6tn4wbr5e", "key": "value"}}})
    );
}

#[test]
fn chain_of_a_file_key_ends_at_its_file() {
    let r = FakeRunner::default();
    assert_eq!(
        on_spike(&r, |rt| rt.chain("FLEET__API__DB_URL", "s7aw2ylfpc")),
        Some(
            "FLEET__API__DB_URL → secret opv-fleet--api--db-url-s7aw2ylfpc → file \
             /run/secrets/api/db/url"
                .to_string()
        )
    );
}

#[test]
fn chain_of_a_configmap_key_names_its_configmap() {
    let r = FakeRunner::default();
    assert_eq!(
        on_spike(&r, |rt| rt.chain("LOG_LEVEL", "h6tn4wbr5e")),
        Some("LOG_LEVEL → configmap opv-log-level-h6tn4wbr5e → env LOG_LEVEL".to_string())
    );
}

#[test]
fn a_secret_bound_as_env_has_no_chain() {
    let r = FakeRunner::default();
    let t = target();
    let rt = KubeDeployment::new(&r, &t, managed());
    assert_eq!(rt.chain("FLEET__API__DB_URL", "s7aw2ylfpc"), None);
}

// ---- the K1 recordings: containers `api` and `sidecar` ---------------------------------

fn recorded_target() -> KubeTarget {
    KubeTarget {
        container: Some("api".into()),
        ..target()
    }
}

/// The K-R1 change on the recorded Deployment: the private key and the OTel resource are
/// file keys of product `api`, the OTel resource and `LOG_LEVEL` config keys.
fn on_recorded<T>(r: &FakeRunner, f: impl FnOnce(&KubeDeployment) -> T) -> T {
    let t = recorded_target();
    let rt = no_wait(
        KubeDeployment::new(
            r,
            &t,
            names(&[
                "FLEET__API__DB_URL",
                "FLEET__API__PRIVATE_KEY",
                "FLEET__API__OTEL_RESOURCE",
                "LOG_LEVEL",
            ]),
        )
        .with_config_in_store(true)
        .with_configmaps(true)
        .with_config_names(names(&["FLEET__API__OTEL_RESOURCE", "LOG_LEVEL"]))
        .with_files(
            Some(DIR.into()),
            BTreeMap::from([
                (
                    "FLEET__API__PRIVATE_KEY".to_string(),
                    mount("api", "github-app/private-key"),
                ),
                (
                    "FLEET__API__OTEL_RESOURCE".to_string(),
                    mount("api", "otel/resource"),
                ),
            ]),
        ),
    );
    f(&rt)
}

/// The pins the recorded replace bound (`08-replace-files-volume`).
fn recorded_change() -> RuntimeChange {
    change(&[
        ("FLEET__API__PRIVATE_KEY", "api--private-key", "abcdefghij"),
        (
            "FLEET__API__OTEL_RESOURCE",
            "api--otel-resource",
            "abcdefghij",
        ),
        ("LOG_LEVEL", "api--log-level", "abcdefghij"),
    ])
}

/// `apply` of [`recorded_change`] on the 07 recording: the document it sends.
fn recorded_sent() -> Value {
    let r = FakeRunner::new([ok(BEFORE_FILES), ok("2")]);
    on_recorded(&r, |rt| {
        let snap = rt.bindings().unwrap();
        rt.apply(&recorded_change(), &snap).unwrap()
    });
    stdin_of(&r, 1)
}

#[test]
fn apply_sends_the_volume_the_api_server_accepted() {
    assert_eq!(
        recorded_sent()["spec"]["template"]["spec"]["volumes"],
        parsed(REPLACE_FILES)["spec"]["template"]["spec"]["volumes"]
    );
}

#[test]
fn apply_sends_the_env_the_api_server_accepted() {
    assert_eq!(
        recorded_sent()["spec"]["template"]["spec"]["containers"][0]["env"],
        parsed(REPLACE_FILES)["spec"]["template"]["spec"]["containers"][0]["env"]
    );
}

/// FM-08: the mount goes into the target's container only.
#[test]
fn a_second_container_gets_no_mount() {
    assert_eq!(
        recorded_sent()["spec"]["template"]["spec"]["containers"][1].get("volumeMounts"),
        None
    );
}

/// FM-08 on the spike's one-container recording with a sidecar added to it.
#[test]
fn an_added_sidecar_gets_no_mount() {
    let doc = deployment_with(|d| {
        let first = d["spec"]["template"]["spec"]["containers"][0].clone();
        let mut sidecar = first;
        sidecar["name"] = json!("sidecar");
        sidecar.as_object_mut().unwrap().remove("env");
        d["spec"]["template"]["spec"]["containers"]
            .as_array_mut()
            .unwrap()
            .push(sidecar);
    });
    let r = FakeRunner::new([json(&doc), ok("7")]);
    let t = KubeTarget {
        container: Some("agnhost".into()),
        ..target()
    };
    let rt = no_wait(
        KubeDeployment::new(&r, &t, names(&["FLEET__API__DB_URL"])).with_files(
            Some(DIR.into()),
            BTreeMap::from([("FLEET__API__DB_URL".to_string(), mount("api", "db/url"))]),
        ),
    );
    let snap = rt.bindings().unwrap();
    rt.apply(
        &change(&[("FLEET__API__DB_URL", "fleet--api--db-url", "s7aw2ylfpc")]),
        &snap,
    )
    .unwrap();
    assert_eq!(
        stdin_of(&r, 1)["spec"]["template"]["spec"]["containers"][1].get("volumeMounts"),
        None
    );
}

#[test]
fn unbinding_a_products_last_file_key_removes_its_volume() {
    let r = FakeRunner::new([ok(AFTER_FILES), ok("3")]);
    on_recorded(&r, |rt| {
        let snap = rt.bindings().unwrap();
        let mut c = change(&[]);
        c.unbind = vec![
            "FLEET__API__PRIVATE_KEY".into(),
            "FLEET__API__OTEL_RESOURCE".into(),
        ];
        rt.apply(&c, &snap).unwrap()
    });
    assert_eq!(
        stdin_of(&r, 1)["spec"]["template"]["spec"].get("volumes"),
        None
    );
}

#[test]
fn unbinding_one_file_key_keeps_the_other_files_item() {
    let r = FakeRunner::new([ok(AFTER_FILES), ok("3")]);
    on_recorded(&r, |rt| {
        let snap = rt.bindings().unwrap();
        let mut c = change(&[]);
        c.unbind = vec!["FLEET__API__OTEL_RESOURCE".into()];
        rt.apply(&c, &snap).unwrap()
    });
    assert_eq!(
        stdin_of(&r, 1)["spec"]["template"]["spec"]["volumes"][0]["projected"]["sources"],
        json!([{"secret": {"name": "opv-api--private-key-abcdefghij", "optional": false,
            "items": [{"key": "value", "path": "github-app/private-key", "mode": 288}]}}])
    );
}

/// The recording's objects were named with the env template `{PRODUCT}__{KEY}`, so the env
/// names whose store names they are read back pinned.
fn on_read_back<T>(r: &FakeRunner, f: impl FnOnce(&KubeDeployment) -> T) -> T {
    let t = recorded_target();
    let rt = KubeDeployment::new(r, &t, names(&["API__PRIVATE_KEY", "API__OTEL_RESOURCE"]))
        .with_config_in_store(true)
        .with_configmaps(true)
        .with_config_names(names(&["API__OTEL_RESOURCE"]))
        .with_files(
            Some(DIR.into()),
            BTreeMap::from([
                (
                    "API__PRIVATE_KEY".to_string(),
                    mount("api", "github-app/private-key"),
                ),
                (
                    "API__OTEL_RESOURCE".to_string(),
                    mount("api", "otel/resource"),
                ),
            ]),
        );
    f(&rt)
}

#[test]
fn bindings_read_a_file_key_back_pinned() {
    let r = FakeRunner::new([ok(AFTER_FILES)]);
    assert_eq!(
        on_read_back(&r, |rt| rt.bindings()).unwrap().bindings["API__PRIVATE_KEY"],
        Binding::Pinned {
            store_name: "api--private-key".into(),
            version: "abcdefghij".into(),
        }
    );
}

#[test]
fn bindings_read_a_config_file_key_back_pinned_to_its_configmap() {
    let r = FakeRunner::new([ok(AFTER_FILES)]);
    assert_eq!(
        on_read_back(&r, |rt| rt.bindings()).unwrap().bindings["API__OTEL_RESOURCE"],
        Binding::Pinned {
            store_name: "api--otel-resource".into(),
            version: "abcdefghij".into(),
        }
    );
}

#[test]
fn a_file_key_whose_mount_is_missing_reads_back_other() {
    let mut doc = parsed(AFTER_FILES);
    doc["spec"]["template"]["spec"]["containers"][0]
        .as_object_mut()
        .unwrap()
        .remove("volumeMounts");
    let r = FakeRunner::new([json(&doc)]);
    assert_eq!(
        on_read_back(&r, |rt| rt.bindings()).unwrap().bindings["API__PRIVATE_KEY"],
        Binding::Other
    );
}

#[test]
fn a_file_key_missing_from_its_products_volume_reads_back_other() {
    let mut doc = parsed(AFTER_FILES);
    doc["spec"]["template"]["spec"]["volumes"][0]["projected"]["sources"]
        .as_array_mut()
        .unwrap()
        .remove(0);
    let r = FakeRunner::new([json(&doc)]);
    assert_eq!(
        on_read_back(&r, |rt| rt.bindings()).unwrap().bindings["API__PRIVATE_KEY"],
        Binding::Other
    );
}

#[test]
fn a_file_key_with_no_volume_yet_is_unbound() {
    let r = FakeRunner::new([ok(BEFORE_FILES)]);
    assert!(
        !on_read_back(&r, |rt| rt.bindings())
            .unwrap()
            .bindings
            .contains_key("API__PRIVATE_KEY")
    );
}

#[test]
fn fingerprint_is_unchanged_by_opvs_own_volume() {
    let print = |text: &str| {
        let r = FakeRunner::new([ok(text)]);
        on_recorded(&r, |rt| rt.bindings())
            .unwrap()
            .unmanaged_fingerprint
    };
    assert_eq!(print(BEFORE_FILES), print(AFTER_FILES));
}

#[test]
fn fingerprint_ignores_the_server_default_mode_of_opvs_volume() {
    let print = |text: &str| {
        let r = FakeRunner::new([ok(text)]);
        on_recorded(&r, |rt| rt.bindings())
            .unwrap()
            .unmanaged_fingerprint
    };
    assert_eq!(print(AFTER_MINIMAL), print(AFTER_FILES));
}

#[test]
fn fingerprint_changes_with_a_foreign_volume() {
    let print = |doc: &Value| {
        let r = FakeRunner::new([json(doc)]);
        on_recorded(&r, |rt| rt.bindings())
            .unwrap()
            .unmanaged_fingerprint
    };
    let mut foreign = parsed(AFTER_FILES);
    foreign["spec"]["template"]["spec"]["volumes"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name": "certs", "emptyDir": {}}));
    assert_ne!(print(&foreign), print(&parsed(AFTER_FILES)));
}

#[test]
fn lost_apply_whose_volume_landed_returns_the_new_generation() {
    let r = FakeRunner::new([ok(BEFORE_FILES)]);
    r.push_unknown("lost");
    let mut landed = recorded_sent();
    landed["metadata"]["resourceVersion"] = json!("1001");
    landed["metadata"]["generation"] = json!(2);
    r.responses.borrow_mut().push_back(Ok(json(&landed)));
    let revision = on_recorded(&r, |rt| {
        let snap = rt.bindings().unwrap();
        rt.apply(&recorded_change(), &snap)
    });
    assert_eq!(revision.unwrap(), Revision("2".into()));
}

#[test]
fn lost_apply_whose_volume_did_not_land_is_a_change_before_the_write() {
    let r = FakeRunner::new([ok(BEFORE_FILES)]);
    r.push_unknown("lost");
    let mut moved = recorded_sent();
    moved["metadata"]["resourceVersion"] = json!("1001");
    moved["spec"]["template"]["spec"]
        .as_object_mut()
        .unwrap()
        .remove("volumes");
    r.responses.borrow_mut().push_back(Ok(json(&moved)));
    let e = on_recorded(&r, |rt| {
        let snap = rt.bindings().unwrap();
        rt.apply(&recorded_change(), &snap)
    })
    .unwrap_err();
    assert!(
        matches!(e.cause(), Some((Cause::ChangedBeforeWrite { .. }, _))),
        "{e}"
    );
}
