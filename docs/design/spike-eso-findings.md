# Spike: Key Vault → Kubernetes via the External Secrets Operator (FR-39)

Date: 2026-10-08. kind cluster `kind-opv`; External Secrets Operator chart/app **2.11.0** (API
`external-secrets.io/v1`; `v1beta1` not served); Helm 3.19.0 (checksum-verified). Store: the P1
sandbox Key Vault, reached by a temporary service principal (`Key Vault Secrets User` on that vault
only, 1-day secret, deleted after the spike) held in a Kubernetes Secret. Marker values only.
Recorded outputs (tenant and vault scrubbed): `tests/fixtures/external-secrets/`.

| # | Question | Finding | Consequence |
|---|---|---|---|
| E1 | `ExternalSecret` with `refreshInterval: "0"`, `remoteRef.key` + `remoteRef.version`, `target.creationPolicy: Owner` | `Ready=True`, reason `SecretSynced`, `status.binding.name` = the target Secret. The Secret holds exactly the pinned version (18 bytes = v1, while v2 and v3 exist). The Secret is owned by the ExternalSecret and carries `reconcile.external-secrets.io/*` labels plus ours. | Pinning holds (FR-29). Name the ExternalSecret/Secret from the **Key Vault version id** (random, not value-derived). |
| E2 | `ClusterSecretStore` (azurekv, ServicePrincipal auth) | `Ready=True`, reason `Valid`, message `store validated`, `status.capabilities: ReadWrite`. | doctor/preflight check `Ready` before any write; a not-Ready store refuses with its message. |
| E3 | Failure states: missing version, missing key, missing store | All three: `Ready=False`, reason `SecretSyncedError`, message **`could not get secret data from provider`** — indistinguishable. No Secret is created. | opv must diagnose itself: confirm the version exists in Key Vault (it just wrote it) and the store is Ready, then name the likely cause; poll `Ready` with a deadline and fail fast on `SecretSyncedError`. |
| E4 | Delete an ExternalSecret with `creationPolicy: Owner` | Its Secret is garbage-collected within seconds. | Prune/GC deletes ExternalSecrets, never Secrets directly. |
| E5 | Deployment `secretKeyRef` → the ExternalSecret's target Secret | Rollout succeeds; the pod sees exactly the pinned version. | The existing Kubernetes runtime pinning works unchanged once the Secret exists. |
