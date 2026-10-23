//! The job's read side against recorded `az containerapp job show` replies
//! (`tests/fixtures/azure/jobs/`, Spike S-238).

use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::*;
use crate::adapters::azure::config::ResolvedUri;
use crate::adapters::azure::{AzureTarget, ConfigRoute};
use crate::domain::{Binding, RuntimeChange};
use crate::runner::Output;
use crate::runner::fake::FakeRunner;

const JOB: &str = "<JOB>";
const MANAGED: &str = "SPIKE_VAL";
const STORE: &str = "OPV-SPIKE-JOB-238B";
/// The Key Vault version the W3 job pins (`containerapp-job-show-keyvault-ref.json`).
const V1: &str = "d56ca729962f4a02b392a538da367950";
/// The user-assigned identity as configured: `resourceGroups`, where the job lists
/// `resourcegroups` (J12).
const UAMI: &str = "/subscriptions/<SUB>/resourceGroups/<RG>/providers/Microsoft.ManagedIdentity/userAssignedIdentities/<UAMI>";

fn fixture(name: &str) -> Value {
    let path = format!(
        "{}/tests/fixtures/azure/jobs/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn out(v: &Value) -> Output {
    Output::success(serde_json::to_vec(v).unwrap())
}

fn target(identity: &str) -> AzureTarget {
    let vault_uri = ResolvedUri::default();
    vault_uri.set("https://<KV>.vault.azure.net".into());
    AzureTarget {
        subscription: "<SUB>".into(),
        key_vault: "<KV>".into(),
        resource_group: "<RG>".into(),
        container_app: "app".into(),
        companion_jobs: Vec::new(),
        container: None,
        identity: identity.into(),
        env_name_template: "{KEY}".into(),
        config: ConfigRoute::Env,
        vault_uri,
    }
}

/// `bindings` of the job whose `job show` replies `show`, with the runner it ran on.
fn read(show: &Value, identity: &str) -> (FakeRunner, Result<RuntimeSnapshot, Error>) {
    let t = target(identity);
    let r = FakeRunner::new([out(show)]);
    let managed: BTreeSet<String> = [MANAGED.to_string()].into();
    let snap = ContainerAppJob::new(&r, &t, JOB, managed).bindings();
    (r, snap)
}

/// The principal `principal` finds in the job `show`.
fn principal_of(show: &Value, identity: &str) -> Result<String, String> {
    let t = target(identity);
    let (r, snap) = read(show, identity);
    let job = ContainerAppJob::new(&r, &t, JOB, BTreeSet::new());
    job.principal(&snap.unwrap()).unwrap()
}

#[test]
fn job_is_read_with_job_show_in_its_resource_group_and_subscription() {
    let (r, _) = read(&fixture("containerapp-job-show.json"), "system");
    assert_eq!(
        r.calls.borrow()[0].args,
        [
            "containerapp",
            "job",
            "show",
            "-g",
            "<RG>",
            "-n",
            JOB,
            "-o",
            "json",
            "--only-show-errors",
            "--subscription",
            "<SUB>",
        ]
    );
}

#[test]
fn job_bindings_parse_the_pinned_key_vault_reference() {
    let (_, snap) = read(
        &fixture("containerapp-job-show-keyvault-ref.json"),
        "system",
    );
    assert_eq!(
        snap.unwrap().bindings[MANAGED],
        Binding::Pinned {
            store_name: STORE.into(),
            version: V1.into(),
        }
    );
}

#[test]
fn job_whose_secrets_are_null_reads_as_no_bindings() {
    let (_, snap) = read(&fixture("containerapp-job-show.json"), "system");
    assert!(snap.unwrap().bindings.is_empty());
}

#[test]
fn job_fingerprint_ignores_its_status_fields() {
    let before = fixture("containerapp-job-show-keyvault-ref.json");
    let mut after = before.clone();
    after["properties"]["provisioningState"] = json!("InProgress");
    after["properties"]["outboundIpAddresses"] = json!([]);
    after["properties"]["eventStreamEndpoint"] = json!("https://elsewhere");
    after["systemData"] = json!({});
    let fp = |v: &Value| read(v, "system").1.unwrap().unmanaged_fingerprint;
    assert_eq!(fp(&before), fp(&after));
}

#[test]
fn system_assigned_job_principal_is_the_jobs_own_identity() {
    let mut show = fixture("containerapp-job-show.json");
    show["identity"]["principalId"] = json!("job-system-principal");
    assert_eq!(
        principal_of(&show, "system"),
        Ok("job-system-principal".into())
    );
}

#[test]
fn user_assigned_job_principal_matches_the_lower_case_resourcegroups_key() {
    let mut show = fixture("containerapp-job-show-user-assigned.json");
    let ids = show["identity"]["userAssignedIdentities"]
        .as_object_mut()
        .unwrap();
    let entry = ids.values_mut().next().unwrap();
    entry["principalId"] = json!("job-user-principal");
    assert_eq!(principal_of(&show, UAMI), Ok("job-user-principal".into()));
}

/// The Key Vault version the W7 update repins to (`containerapp-job-update-repinned.json`).
const V3: &str = "35a2929273b84eb28b2ff4910843cc52";
/// A config value written through the job's document (a marker, R10).
const MARK: &str = "opv-marker-job-config";

fn pin(version: &str) -> RuntimeChange {
    RuntimeChange {
        pin: [(
            MANAGED.to_string(),
            (STORE.to_string(), version.to_string()),
        )]
        .into(),
        set: Default::default(),
        unbind: vec![],
        stamp: None,
    }
}

/// `apply(change)` to the W5 job (a pinned `opv-w3` and the plain `plain1`), answered by
/// `responses` after its `job show`.
fn apply_with(change: &RuntimeChange, responses: Vec<Output>) -> (FakeRunner, Result<(), Error>) {
    let show = fixture("containerapp-job-show-plain-secret.json");
    let (_, snap) = read(&show, "system");
    let t = target("system");
    let r = FakeRunner::new([out(&show)].into_iter().chain(responses));
    let managed: BTreeSet<String> = [MANAGED.to_string()].into();
    let done = ContainerAppJob::new(&r, &t, JOB, managed).apply(change, &snap.unwrap());
    (r, done)
}

fn apply(change: &RuntimeChange) -> (FakeRunner, Result<(), Error>) {
    apply_with(
        change,
        vec![out(&fixture("containerapp-job-update-repinned.json"))],
    )
}

/// The document the update sent on stdin.
fn sent(r: &FakeRunner) -> Value {
    let calls = r.calls.borrow();
    let update = calls.iter().find(|c| c.stdin.is_some()).unwrap();
    serde_json::from_slice(update.stdin.as_ref().unwrap()).unwrap()
}

fn sent_secrets(r: &FakeRunner) -> Vec<Value> {
    sent(r)["properties"]["configuration"]["secrets"]
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn job_update_reads_its_document_from_stdin() {
    let (r, _) = apply(&pin(V3));
    assert_eq!(
        r.calls.borrow()[1].args,
        [
            "containerapp",
            "job",
            "update",
            "-g",
            "<RG>",
            "-n",
            JOB,
            "--yaml",
            "/dev/stdin",
            "-o",
            "json",
            "--only-show-errors",
            "--subscription",
            "<SUB>",
        ]
    );
}

#[test]
fn job_config_value_goes_on_stdin_never_in_argv() {
    let mut change = pin(V3);
    change.pin.clear();
    change.set.insert(MANAGED.into(), MARK.into());
    let (r, _) = apply(&change);
    let on_stdin = sent(&r).to_string().contains(MARK);
    assert!(on_stdin && !r.argv_contains(MARK));
}

#[test]
fn job_secret_references_the_pinned_version() {
    let (r, _) = apply(&pin(V3));
    assert!(sent_secrets(&r).contains(&json!({
        "name": crate::adapters::azure::resource::secret_name(STORE, V3),
        "keyVaultUrl": format!("https://<KV>.vault.azure.net/secrets/{STORE}/{V3}"),
        "identity": "system",
    })));
}

/// J9: a job has no serving revision, so the superseded secret goes in the same update.
#[test]
fn job_update_removes_the_superseded_opv_secret() {
    let (r, _) = apply(&pin(V3));
    assert!(!sent_secrets(&r).iter().any(|s| s["name"] == "opv-w3"));
}

/// J5, J6: the job's own plain secret goes back as `show` listed it, without a value.
#[test]
fn job_update_keeps_its_plain_secret_without_a_value() {
    let (r, _) = apply(&pin(V3));
    assert!(sent_secrets(&r).contains(&json!({"name": "plain1"})));
}

/// J11: the reply's `provisioningState` settles the update; nothing is polled.
#[test]
fn job_update_settles_from_its_reply() {
    let (r, done) = apply(&pin(V3));
    assert!(done.is_ok() && r.calls.borrow().len() == 2);
}

#[test]
fn job_update_whose_reply_reads_failed_is_a_refusal() {
    let mut reply = fixture("containerapp-job-update-repinned.json");
    reply["properties"]["provisioningState"] = json!("Failed");
    let (_, done) = apply_with(&pin(V3), vec![out(&reply)]);
    assert_eq!(done.map_err(|e| e.code_str()), Err("update_refused"));
}

/// An update that exits 1, then `back` as the read-back, then `az account show` signed in.
fn failed_update(back: &Value) -> Result<(), Error> {
    let r = FakeRunner::default();
    let show = fixture("containerapp-job-show-plain-secret.json");
    let (_, snap) = read(&show, "system");
    let t = target("system");
    r.responses.borrow_mut().push_back(Ok(out(&show)));
    r.push_with_stderr(Output::failure(1), "ERROR: the update failed");
    r.responses.borrow_mut().push_back(Ok(out(back)));
    r.responses.borrow_mut().push_back(Ok(Output::success("")));
    let managed: BTreeSet<String> = [MANAGED.to_string()].into();
    ContainerAppJob::new(&r, &t, JOB, managed).apply(&pin(V3), &snap.unwrap())
}

/// The read-back shows the job as it was: Azure applied nothing.
#[test]
fn failed_job_update_whose_read_back_is_unchanged_is_a_refusal() {
    let back = fixture("containerapp-job-show-plain-secret.json");
    assert_eq!(
        failed_update(&back).map_err(|e| e.code_str()),
        Err("update_refused")
    );
}

/// The read-back shows the new pin: the update may have landed (NR-2).
#[test]
fn failed_job_update_whose_read_back_changed_is_unknown_outcome() {
    let back = fixture("containerapp-job-show-repointed.json");
    assert_eq!(
        failed_update(&back).map_err(|e| e.code_str()),
        Err("outcome_unknown")
    );
}
