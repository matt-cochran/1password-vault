# Container Apps Jobs fixtures (Spike S-238, #238)

These are recorded `az` 2.91.0 outputs from the owner's sandbox (`opv-spike-rg`, 2026-10-23). They
were redacted by the spike's `redact.sh`, then re-scanned here: no GUIDs, subscription, tenant,
vault, app, environment, job or identity names, e-mails, IPv4 addresses or marker values remain.

Placeholders: `<SUB>`, `<TENANT>`, `<RG>`, `<ENV>`, `<KV>`, `<JOB>`, `<UAMI>`, `<IP>`, `<USER>`.
Every GUID became `<PRINCIPAL>`, so the system principal, a user-assigned principal and its client
id all read the same. A test that needs them to differ substitutes its own ids. The Key Vault secret
name (`OPV-SPIKE-JOB-238B`) and its 32-hex version ids are kept: they are not identifying, and the
version ids tell the three versions apart. The execution-scoped secret Azure names
`cappjob-<job name>` is written `cappjob-<JOB>`.

Findings: `docs/design/spike-238-azure-jobs-findings.md`. Steps: `docs/design/azure-jobs.md` §8.

| File | Command (all `--subscription <SUB> --only-show-errors`) | Step | What it shows |
|---|---|---|---|
| `containerapp-job-list-empty.json` | `containerapp job list -g <RG> -o json` | R4 | no job yet: `[]` |
| `containerapp-job-show.json` | `containerapp job show -g <RG> -n <JOB> -o json` | W2 | a new manual job with a system identity; `configuration.secrets: null`; no `etag`; status fields `provisioningState`, `outboundIpAddresses`, `eventStreamEndpoint` |
| `containerapp-job-update-keyvault-ref.json` | `containerapp job update -g <RG> -n <JOB> --yaml /dev/stdin -o json` | W3 | the reply to adding a Key Vault reference **before** the identity had any grant: accepted (exit 0, 21 s), `provisioningState: Succeeded` |
| `containerapp-job-show-keyvault-ref.json` | `containerapp job show …` | W3 | the job after that update: one `opv-w3` secret with `keyVaultUrl` (v1) and `identity: system` |
| `containerapp-job-execution-list.json` | `containerapp job execution list -g <RG> -n <JOB> -o json` | W3 | one execution, `Failed` (identity without access) |
| `containerapp-job-execution-show-failed.json` | `containerapp job execution show … --job-execution-name <e> -o json` | W3 | `status: Failed`, no `endTime`, no reason field; the execution's env `secretRef`s all name `cappjob-<JOB>` |
| `role-assignment-list-job-principal.json` | `role assignment list --assignee <principal> --scope <vault id> --include-inherited --include-groups -o json` | W4 | the job principal's `Key Vault Secrets User` grant, listed at once, with `createdOn` |
| `containerapp-job-show-plain-secret.json` | `containerapp job show …` | W5 | an unmanaged plain secret listed as `{"name": "plain1"}` (no value) next to the Key Vault reference |
| `containerapp-job-execution-show-succeeded.json` | `containerapp job execution show …` | W5 | `Succeeded` after the plain secret was sent back without its value: Azure kept it |
| `containerapp-job-show-repointed.json` | `containerapp job show …` | W6 | the same secret name `opv-w3` repointed to version v2 by `keyVaultUrl` only |
| `containerapp-job-execution-show-running.json` | `containerapp job execution show …` | W7 | `status: Running` while the job was repinned to v3 |
| `containerapp-job-update-repinned.json` | `containerapp job update … --yaml /dev/stdin` | W7 | the reply to the repin: `opv-w6v2` removed and `opv-w7v3` (v3) added in one update, while that execution ran; `provisioningState: Succeeded` |
| `containerapp-job-show-user-assigned.json` | `containerapp job show …` after `containerapp job identity assign --user-assigned <id>` | W10 | `identity.type: "SystemAssigned, UserAssigned"`; `userAssignedIdentities` keyed by resource id with lower-case `resourcegroups`, each with `principalId` and `clientId` |
| `containerapp-job-provisioning-timeline.json` | `containerapp job show --query properties.provisioningState` every 5 s | W8 | `InProgress` seen only while an update call was running; `Succeeded` by the time it returned |
