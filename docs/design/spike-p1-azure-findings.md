# P1 spike: Azure Key Vault + Container Apps (live recon)

Status: done; the findings are built into 0.5.0 and the recorded outputs are test fixtures.

Date: 2026-10-08. Owner-approved throwaway resources in the owner's sandbox subscription, resource
group `opv-spike-rg` (Key Vault in eastus; Container Apps environment in eastus2 after eastus
returned `AKSCapacityHeavyUsage`). Marker values only (`opv-spike-marker-*`); no real secret was
used. Tools: `az` 2.90.0 (containerapp commands are core; no extension installed, Q13).

Recorded outputs, with subscription, tenant, principal ids, IPs and host names replaced, are in
`tests/fixtures/azure/` and are the adapters' test inputs (R10).

| # | Question | Finding | Consequence |
|---|---|---|---|
| Q1 | `keyvault secret set --file /dev/stdin --encoding utf-8 --tags opv-managed=dev` | Stores the exact bytes (18 in, 18 stored, no newline added). `.id` is the versioned URI `https://<vault>.vault.azure.net/secrets/<name>/<32 hex>`. Adds tag `file-encoding=utf-8`. **The output echoes `.value`.** | Writes pass `--query id -o tsv` so the value never comes back (R11). Ignore the extra tag. |
| Q2 | `keyvault secret list -o json` | Fields `attributes, contentType, id (unversioned), managed, name, tags`; no value, no version. | Version comes from `show`/the binding, not `list`. |
| Q3 | `keyvault secret show` | Versioned `.id`, `.value`. Missing name: exit **3** (`SecretNotFound` on stderr, not captured). | Read refused-exit = 3 ⇒ absent; never retried. |
| Q4 | Delete, then `set` the same name | `set` exits **1** (`Conflict` / `ObjectIsDeletedButRecoverable`). `show-deleted` exits 0 for a deleted name, 1 for a never-existing one; `show` of a deleted name exits 3. | After a failed `set`, probe `show-deleted` to name the recover command. |
| Q5 | `containerapp update --yaml /dev/stdin` with a JSON document from `show`, plus a Key Vault reference secret and env entries; an existing plain secret left **without** its value | Accepted. The plain secret kept its value (22 bytes before and after). New revision created because env changed. | `apply` never needs or fetches unmanaged secret values. |
| Q6 | Versioned `keyVaultUrl` honoured? | Wrote v2 after binding v1, restarted the revision: the replica still sees v1 (18 bytes, v2 would be 35). | FR-29 holds on Container Apps. |
| Q7 | Revision health fields | `revision show`: `provisioningState Provisioned`, `runningState Running`, `healthState Healthy`, `replicas`, `trafficWeight`, `active`. An ingress app with no configured probes reports `Healthy` (default probes). | R8. |
| Q8 | etag for optimistic concurrency | `show` has no `etag` field. | Fingerprint before/after apply (R9). |
| Q12 | Do values reach `~/.azure`? | After writes, reads and updates of five markers (one deliberately passed in argv), `grep -rlF` over `~/.azure` finds none. `~/.azure/commands/*.log` records commands at INFO level. | SR-4 holds for stdin values and responses; argv stays value-free anyway (SR-3). |
| Q13 | Extension prompts | All commands used are core with `AZURE_EXTENSION_USE_DYNAMIC_INSTALL=no`. | Pinned env (R7) is safe. |
| Q14 | Deploy when the app identity has no Key Vault access | `update` fails **synchronously** (exit 1 after ~15 s); **no revision is created**; the old revision stays active, healthy, 100 % traffic; the app's `provisioningState` becomes `Failed` until the next good update, which succeeds once access is restored. | R6 (access check advisory) is safe: Azure refuses before any rollout. Preflight treats app `Failed` as "last update failed" (R11). |
| Q16 | Repin by changing only a secret's `keyVaultUrl` | Update succeeds but **no new revision**: running replicas would pick the new version up on their next restart. Naming the secret per version (so the env `secretRef` changes) creates a new revision (`--0000002`) that sees the new version (19 bytes) and takes 100 % traffic. While starting, `healthState` is `None` and `latestReadyRevisionName` still names the old revision. | R2 amended: secret name includes the version. R8 amended: healthy only when the new revision is `latestReadyRevisionName` and reports `Healthy`. |
| Q15 | Scale to zero | See the appendix (recorded in the background run). | R8 wording for min-replicas 0. |
| — | Provisioning latency and dropped polling | Creating a Container Apps environment took ~19 min; `az` lost its polling connection (`Max retries exceeded`) and exited 1 while ARM finished the create. | NR-2 (unknown outcome), NR-4 (long waits with progress), NR-25. |

## Appendix: Q15 scale to zero

`az containerapp update --min-replicas 0` created revision `--0000003`. Observed once a minute
for 16 minutes: minutes 1–4 `Provisioned / Running / Healthy`, replicas 1; from minute 5 on
`Provisioned / ScaledToZero / Healthy`, replicas 0; the revision stayed `latestReadyRevisionName`.

Consequence (R8): `ScaledToZero` counts as running for a revision that is already the latest
ready one; `healthState` stays `Healthy` at zero replicas.
