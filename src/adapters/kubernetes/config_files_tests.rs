//! The readability and mount-path preflight of a target with `secrets_dir` (K5, design
//! §6.6), fed from the recorded Deployment (`07-get-deployment-before-files`: containers
//! `api` and `sidecar`, `runAsUser: 10001, runAsGroup: 10001`, no `fsGroup`), with the
//! security contexts of the K-R5 recordings put into it.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::*;
use crate::domain::runtime::FileMount;
use crate::runner::Output;
use crate::runner::fake::FakeRunner;

const BEFORE_FILES: &str = include_str!(
    "../../../tests/fixtures/kubernetes/success/07-get-deployment-before-files.stdout"
);

const ROOT_LINE: &str = "warn  deployment api runs as root: every mounted file is readable \
                         by any process in the container; run as a non-root user with fsGroup";

fn target(secrets_dir: Option<&str>) -> KubernetesTarget {
    KubernetesTarget {
        target: KubeTarget {
            context: "kind-opv".into(),
            namespace: "opv-spike".into(),
            deployment: "api".into(),
            container: Some("api".into()),
            env: "dev".into(),
        },
        env_name_template: "FLEET__{PRODUCT}__{KEY}".into(),
        config: ConfigRoute::ConfigMap,
        secrets_dir: secrets_dir.map(String::from),
        store: None,
    }
}

fn files() -> BTreeMap<String, FileMount> {
    BTreeMap::from([(
        "FLEET__API__PRIVATE_KEY".to_string(),
        FileMount {
            product: "api".into(),
            path: "github-app/private-key".into(),
        },
    )])
}

/// The recording, edited by `f`.
fn recorded(f: impl FnOnce(&mut Value)) -> Output {
    let mut d: Value = serde_json::from_str(BEFORE_FILES).unwrap();
    f(&mut d);
    Output::success(serde_json::to_vec(&d).unwrap())
}

fn security(context: Value) -> Output {
    recorded(|d| d["spec"]["template"]["spec"]["securityContext"] = context)
}

fn checks(deployment: Output, mode: PreflightMode) -> Result<Vec<String>, Error> {
    let r = FakeRunner::new([deployment]);
    let found = target(Some("/run/secrets/{product}")).preflight_files(&r, mode, &files())?;
    Ok(found
        .into_iter()
        .map(|c| c.outcome.map(|v| v.line(&c.name)).unwrap_or_default())
        .collect())
}

#[test]
fn an_unreadable_workload_refuses_sync_as_mount_unreadable() {
    let e = checks(recorded(|_| {}), PreflightMode::Mutate).unwrap_err();
    assert_eq!(e.code_str(), "mount_unreadable");
}

#[test]
fn an_unreadable_workload_refusal_names_the_uid() {
    let e = checks(recorded(|_| {}), PreflightMode::Mutate).unwrap_err();
    assert!(
        matches!(
            e.cause(),
            Some((
                Cause::MountUnreadable {
                    run_as: Some(10001),
                    why: MountWhy::NoFsGroup,
                    ..
                },
                _
            ))
        ),
        "{e}"
    );
}

#[test]
fn an_unreadable_workload_makes_no_write_call() {
    let r = FakeRunner::new([recorded(|_| {})]);
    let _ =
        target(Some("/run/secrets/{product}")).preflight_files(&r, PreflightMode::Mutate, &files());
    let args: Vec<Vec<String>> = r.calls.borrow().iter().map(|c| c.args.clone()).collect();
    assert!(
        args.iter()
            .all(|a| !a.iter().any(|w| w == "replace" || w == "apply")),
        "{args:?}"
    );
}

#[test]
fn an_unreadable_workload_is_a_warning_under_plan() {
    assert_eq!(
        checks(recorded(|_| {}), PreflightMode::Read).unwrap(),
        [
            "warn  deployment api sets no fsGroup and runs as 10001: the mounted files \
          (0440, root-owned) would be unreadable"
        ]
    );
}

/// K-R5 `imagegid`: `runAsUser: 10001` only, so the group is the image's.
#[test]
fn an_unknown_group_refuses_sync_as_mount_unreadable() {
    let e = checks(security(json!({"runAsUser": 10001})), PreflightMode::Mutate).unwrap_err();
    assert!(
        matches!(
            e.cause(),
            Some((
                Cause::MountUnreadable {
                    why: MountWhy::RunAsUnknown,
                    ..
                },
                _
            ))
        ),
        "{e}"
    );
}

/// K-R5 `fsgroup`: readable, nothing to say.
#[test]
fn a_workload_with_fs_group_passes_silently() {
    let ctx = json!({"runAsUser": 10001, "runAsGroup": 10001, "fsGroup": 10001});
    assert!(
        checks(security(ctx), PreflightMode::Mutate)
            .unwrap()
            .is_empty()
    );
}

/// FM-13, K-R5 `root`: readable, so sync goes on, with the root warn line.
#[test]
fn a_root_workload_syncs_with_the_root_warn_line() {
    assert_eq!(
        checks(security(json!({"runAsUser": 0})), PreflightMode::Mutate).unwrap(),
        [ROOT_LINE]
    );
}

#[test]
fn a_root_workload_warns_under_plan_too() {
    assert_eq!(
        checks(security(json!({"runAsUser": 0})), PreflightMode::Read).unwrap(),
        [ROOT_LINE]
    );
}

#[test]
fn a_group_zero_workload_warns_that_group_0_reads_every_file() {
    let ctx = json!({"runAsUser": 10001, "runAsGroup": 0});
    assert_eq!(
        checks(security(ctx), PreflightMode::Mutate).unwrap(),
        [
            "warn  deployment api runs in group 0: every mounted file is readable by any \
          process in group 0 in the container; set fsGroup to a group only this container uses"
        ]
    );
}

/// The container's own security context overrides the pod's.
#[test]
fn a_container_running_as_root_overrides_the_pods_user() {
    let doc = recorded(|d| {
        d["spec"]["template"]["spec"]["containers"][0]["securityContext"] = json!({"runAsUser": 0});
    });
    assert_eq!(checks(doc, PreflightMode::Mutate).unwrap(), [ROOT_LINE]);
}

fn foreign_mount_at(path: &str) -> Output {
    let path = path.to_string();
    recorded(move |d| {
        let spec = &mut d["spec"]["template"]["spec"];
        spec["securityContext"]["fsGroup"] = json!(10001);
        spec["volumes"] = json!([{"name": "certs", "emptyDir": {}}]);
        spec["containers"][0]["volumeMounts"] = json!([{"name": "certs", "mountPath": path}]);
    })
}

#[test]
fn a_foreign_volume_at_the_directory_refuses_as_policy_refused() {
    let e = checks(foreign_mount_at("/run/secrets/api"), PreflightMode::Mutate).unwrap_err();
    assert_eq!(e.code_str(), "policy_refused");
}

#[test]
fn a_foreign_volume_above_the_directory_refuses_under_plan_too() {
    let e = checks(foreign_mount_at("/run/secrets"), PreflightMode::Read).unwrap_err();
    assert!(
        matches!(e.cause(), Some((Cause::Guard { guard: Guard::MountPathInUse { volume, .. } }, _)) if volume == "certs"),
        "{e}"
    );
}

#[test]
fn a_foreign_volume_in_another_container_is_no_conflict() {
    let doc = recorded(|d| {
        let spec = &mut d["spec"]["template"]["spec"];
        spec["securityContext"]["fsGroup"] = json!(10001);
        spec["volumes"] = json!([{"name": "certs", "emptyDir": {}}]);
        spec["containers"][1]["volumeMounts"] =
            json!([{"name": "certs", "mountPath": "/run/secrets/api"}]);
    });
    assert!(checks(doc, PreflightMode::Mutate).unwrap().is_empty());
}

#[test]
fn a_target_without_secrets_dir_reads_nothing() {
    let r = FakeRunner::default();
    let _ = target(None).preflight_files(&r, PreflightMode::Mutate, &files());
    assert!(r.calls.borrow().is_empty());
}

/// `secrets_dir` set, no file key delivered: the readability check still runs.
#[test]
fn a_target_with_secrets_dir_and_no_file_key_still_checks_readability() {
    let r = FakeRunner::new([recorded(|_| {})]);
    let e = target(Some("/run/secrets/{product}"))
        .preflight_files(&r, PreflightMode::Mutate, &BTreeMap::new())
        .unwrap_err();
    assert_eq!(e.code_str(), "mount_unreadable");
}

#[test]
fn the_refusal_names_the_target_once_the_caller_fills_it() {
    let e = checks(recorded(|_| {}), PreflightMode::Mutate)
        .unwrap_err()
        .in_target("k8s");
    assert_eq!(
        e.next_text().unwrap_or_default(),
        "opv plan dev --target k8s"
    );
}
