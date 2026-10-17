# kubectl success recordings

Real kubectl output, recorded 2026-10-16 for the simulator (`tests/sim/kube.rs`, docs/design/error-catalog.md §13). Nothing here is invented. Same setup as `../failures/README.md`: kubectl v1.36.1, API server v1.37.0, kind v0.33.0, a throwaway cluster `opv-rec` (context `kind-opv-rec`) with its own `KUBECONFIG` in a temp directory, deleted after recording (`kind delete cluster --name opv-rec`). Each case has `.stdout`, `.stderr` and `.exit`; every call ran with stdin closed or with the manifest on stdin.

Context `opv-rbac` is a ServiceAccount `opv-rec:opv-rbac` bound to a Role granting get, list, create, patch, update and delete on secrets and deployments in `opv-rec`, using a `kubectl create token` bearer token.

| Case | Command | Exit | stdout |
|---|---|---|---|
| 01-can-i-create-secrets-yes | `kubectl --context opv-rbac -n opv-rec --request-timeout=60s auth can-i create secrets` | 0 | `yes` |
| 01-can-i-update-deployments-yes | `kubectl --context opv-rbac -n opv-rec --request-timeout=60s auth can-i update deployments` | 0 | `yes` |
| 01-can-i-create-secrets-yes-admin | same as the first, `--context kind-opv-rec` (cluster admin) | 0 | `yes` |
| 02-apply-secret-created | `kubectl --context kind-opv-rec -n opv-rec --request-timeout=120s apply -f - --server-side --field-manager=opv -o name`, a Secret `opv-api--db-url-abcdefghij` on stdin (value `<MARKER>`) | 0 | `secret/opv-api--db-url-abcdefghij` |
| 02-apply-secret-unchanged | the same apply again | 0 | the same line |
| 02-apply-secret-second | the same, Secret `opv-api--db-url-klmnopqrst` | 0 | `secret/opv-api--db-url-klmnopqrst` |
| 03-delete-secrets | `kubectl --context kind-opv-rec -n opv-rec --request-timeout=120s delete secret opv-api--db-url-abcdefghij opv-api--db-url-klmnopqrst --ignore-not-found` | 0 | `secret "<name>" deleted from opv-rec namespace`, one line per Secret |
| 03-delete-secrets-missing-ignored | the first delete again, the Secret already gone | 0 | *(empty)* |

The `no` answer of `auth can-i` is `../failures/02-can-i-create-secrets-no` (exit 1, stdout `no`). stderr was empty in every case here.

The K1 recordings for ConfigMaps and mounted files (cases 04–17 here, with `cases.tsv`) are described in `../README.md`.
