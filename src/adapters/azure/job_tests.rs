//! The job's read side against recorded `az containerapp job show` replies
//! (`tests/fixtures/azure/jobs/`, Spike S-238).

use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::*;
use crate::adapters::azure::config::ResolvedUri;
use crate::adapters::azure::{AzureTarget, ConfigRoute};
use crate::domain::Binding;
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
