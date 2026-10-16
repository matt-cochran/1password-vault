# kubectl failure recordings (error catalog §5, kubectl diagnosis)

Real kubectl output, recorded 2026-10-15 against a throwaway local cluster; nothing here is invented
(CONTRIBUTING, "Adding a provider"). Each case has `NN-<case>.stderr` (possibly empty), `.exit`, and
`.stdout` when kubectl printed anything.

## Environment

- kubectl **v1.36.1** (Kustomize v5.8.1), API server **v1.37.0** (kind node image default).
- kind **v0.33.0** (released 2026-08-26), official `kind-linux-amd64`, sha256
  `aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d`, verified with
  `sha256sum -c kind-linux-amd64.sha256sum` against the release's published checksum file.
- Cluster `opv-rec` (context `kind-opv-rec`) in Docker, with its own `KUBECONFIG` under `<TMP>`;
  deleted after recording (`kind delete cluster --name opv-rec`).
- Namespace `opv-rec`, Deployment `api` (pause image), Secret `opv-present`, ServiceAccount
  `opv-norbac` with **no** RoleBinding.
- Extra kubeconfig contexts: `opv-bogus` (user with bearer token `<TOKEN>`, a made-up string),
  `opv-norbac` (user with `kubectl create token opv-norbac` output, `<TOKEN>`), `opv-unreachable`
  (server `https://127.0.0.1:9`, nothing listens there). `opv-nonexistent` is in no kubeconfig.
- Every command ran with stdin closed (`< /dev/null`), `NO_COLOR=1`, except the `apply`/`create`/
  `replace` cases, whose stdin was a manifest: a Secret `opv-api--db-url-abcdefghij` with labels
  `opv-managed=dev, opv-key=api--db-url` and `data.value` = base64 of the marker `<MARKER>`, or the
  Deployment as read by the cluster admin.
- Call shapes are opv's own (`src/adapters/kubernetes/`): `--context <ctx> --namespace <ns>
  --request-timeout=60s` for reads, `120s` for writes, and the diagnosis probes
  `config get-contexts <ctx> -o name` and `--context <ctx> version --request-timeout=5s`.

Markers: `<TMP>` temp paths, `<TOKEN>` bearer tokens, `<CA>` cluster CA data and `<SERVER>` the kind
API server address (neither appears in any output). Lines from kubectl's klog are prefixed
`E<MMDD> <TIME> <PID>` in place of the date, time and process id. `127.0.0.1:9` is kept verbatim: it
is the fixed unreachable address the case chose, not a generated port.

`$LIST` = `jsonpath={range .items[*]}{.metadata.name}{"\t"}{.metadata.labels.opv-key}{"\n"}{end}`,
`$VALUE` = `jsonpath={.metadata.labels.opv-managed}{"\t"}{.data.value}`,
`$GEN` = `jsonpath={.metadata.generation}`; `-n` below stands for `--namespace`.

## Cases

| File | Command | Exit | Cause (design §4) |
|---|---|---|---|
| 01-unauthorized-get-secret-list | `kubectl --context opv-bogus -n opv-rec --request-timeout=60s get secret -l opv-managed=dev -o $LIST` | 1 | `NotSignedIn{system: Kubernetes, state: Expired}` (401) |
| 01-unauthorized-version-probe | `kubectl --context opv-bogus version --request-timeout=5s` | 1 | `NotSignedIn{Kubernetes}`; stdout still prints the client version |
| 01-unauthorized-auth-can-i | `kubectl --context opv-bogus -n opv-rec --request-timeout=60s auth can-i create secrets` | 1 | `NotSignedIn{Kubernetes}`; no `no` on stdout |
| 02-forbidden-get-secret | `kubectl --context opv-norbac -n opv-rec --request-timeout=60s get secret opv-present --ignore-not-found -o $VALUE` | 1 | `MissingRight{K8sRbac{verb: get, resource: secrets}}` |
| 02-forbidden-list-secrets | `kubectl --context opv-norbac -n opv-rec --request-timeout=60s get secret -l opv-managed=dev -o $LIST` | 1 | `MissingRight{K8sRbac{list, secrets}}` |
| 02-forbidden-create-secret | `kubectl --context opv-norbac -n opv-rec --request-timeout=120s apply -f - --server-side --field-manager=opv -o name` (Secret manifest on stdin) | 1 | `MissingRight{K8sRbac{patch, secrets}}`: server-side apply is a PATCH, so the refusal names `patch`, not `create` |
| 02-forbidden-create-secret-clientside | `kubectl --context opv-norbac -n opv-rec --request-timeout=120s create -f - -o name` (same stdin) | 1 | `MissingRight{K8sRbac{create, secrets}}` |
| 02-forbidden-patch-deployment | `kubectl --context opv-norbac -n opv-rec --request-timeout=120s patch deployment api --type=merge -p '{"metadata":{"annotations":{"opv-rec":"1"}}}'` | 1 | `MissingRight{K8sRbac{get, deployments}}`: `kubectl patch` reads first, so the refusal names `get` |
| 02-forbidden-replace-deployment | `kubectl --context opv-norbac -n opv-rec --request-timeout=120s replace -f - -o $GEN` (Deployment on stdin; opv's repin call) | 1 | `MissingRight{K8sRbac{update, deployments}}` |
| 02-forbidden-get-deployment | `kubectl --context opv-norbac -n opv-rec --request-timeout=60s get deployment api -o json` | 1 | `MissingRight{K8sRbac{get, deployments}}` |
| 02-can-i-create-secrets-no | `kubectl --context opv-norbac -n opv-rec --request-timeout=60s auth can-i create secrets` | 1 | stdout `no`, stderr empty: a missing right (`MissingRight{K8sRbac{create, secrets}}`), not a failure |
| 02-forbidden-version-probe | `kubectl --context opv-norbac version --request-timeout=5s` | 0 | none: an identity with no RBAC still reads the server version, so the reachability probe passes |
| 03-notfound-secret | `kubectl --context kind-opv-rec -n opv-rec --request-timeout=60s get secret opv-missing -o name` | 1 | `NotFound{resource: Secret, state: Missing}` |
| 03-notfound-secret-ignore | `kubectl --context kind-opv-rec -n opv-rec --request-timeout=60s get secret opv-missing --ignore-not-found -o $VALUE` | 0 | none: opv's read of a bound Secret gets empty stdout, exit 0 |
| 03-notfound-deployment | `kubectl --context kind-opv-rec -n opv-rec --request-timeout=60s get deployment opv-missing -o json` | 1 | `NotFound{resource: Deployment, named_by: ConfigField, state: Missing}` |
| 03-notfound-namespace-get-deployment | `kubectl --context kind-opv-rec -n opv-missing-ns --request-timeout=60s get deployment api -o json` | 1 | `NotFound{resource: Namespace, state: Missing}`: the server names the namespace, not the Deployment |
| 03-notfound-namespace-create-secret | `kubectl --context kind-opv-rec -n opv-missing-ns --request-timeout=120s apply -f - --server-side --field-manager=opv -o name` (Secret on stdin) | 1 | `NotFound{resource: Namespace, state: Missing}` |
| 03-notfound-namespace-get | `kubectl --context kind-opv-rec get namespace opv-missing-ns -o name` | 1 | `NotFound{resource: Namespace, state: Missing}` |
| 04-context-missing-get-deployment | `kubectl --context opv-nonexistent -n opv-rec --request-timeout=60s get deployment api -o json` | 1 | `NotFound{resource: context, state: LocalContextMissing}` |
| 04-context-missing-probe | `kubectl config get-contexts opv-nonexistent -o name` | 1 | `NotFound{LocalContextMissing}` (diagnosis probe; note the different phrase: `not found`, unquoted) |
| 04-context-present-probe | `kubectl config get-contexts kind-opv-rec -o name` | 0 | none: the probe's success shape (stdout is the bare context name) |
| 05-unreachable-get-deployment | `kubectl --context opv-unreachable -n opv-rec --request-timeout=60s get deployment api -o json` | 1 | `Unavailable{why: Network}` (connection refused; five klog lines before the final line) |
| 05-unreachable-version-probe | `kubectl --context opv-unreachable version --request-timeout=5s` | 1 | `Unavailable{Network}`; stdout still prints the client version |
| 05-unreachable-auth-can-i | `kubectl --context opv-unreachable -n opv-rec --request-timeout=60s auth can-i create secrets` | 1 | `Unavailable{Network}`; includes a misleading `Warning: the server doesn't have a resource type 'secrets'` and no `no` on stdout |
| 06-eso-get-clustersecretstores | `kubectl --context kind-opv-rec -n opv-rec --request-timeout=60s get clustersecretstores` | 1 | `OwnerSetupRequired{object: ClusterOperator{name: External Secrets Operator}}` |
| 06-eso-get-clustersecretstore-named | `kubectl --context kind-opv-rec -n opv-rec --request-timeout=60s get clustersecretstores.external-secrets.io opv-store --ignore-not-found -o json` | 1 | `OwnerSetupRequired{ClusterOperator}`: `--ignore-not-found` does not cover a missing resource type |
| 06-eso-api-resources | `kubectl --context kind-opv-rec -n opv-rec --request-timeout=60s api-resources --api-group=external-secrets.io` | 0 | `OwnerSetupRequired{ClusterOperator}`: exit 0, stdout is the header row only |
| 06-eso-raw-v1 | `kubectl --context kind-opv-rec -n opv-rec --request-timeout=60s get --raw /apis/external-secrets.io/v1` | 1 | `OwnerSetupRequired{ClusterOperator}` (opv's preflight call) |
| 06-eso-raw-group | `kubectl --context kind-opv-rec -n opv-rec --request-timeout=60s get --raw /apis/external-secrets.io` | 1 | `OwnerSetupRequired{ClusterOperator}` |
| 07-version-client | `kubectl version --client` | 0 | none (doctor's version line) |
| 07-version-server | `kubectl --context kind-opv-rec version --request-timeout=5s` | 0 | none (reachability probe, success shape) |

## Findings for the kubectl phrase table

- 401 has two phrasings: `You must be logged in to the server (Unauthorized)` on resource calls, and
  `You must be logged in to the server (the server has asked for the client to provide credentials)`
  on `version`. Match the prefix `You must be logged in to the server`.
- 403 always reads `Error from server (Forbidden): ... cannot <verb> resource "<resource>" in API
  group "<group>" in the namespace "<ns>"`, naming the principal (`User "system:serviceaccount:..."`).
  The verb is the HTTP verb the server saw, so derive `K8sRbac{verb}` from this text, not from opv's
  intent: server-side `apply` says `patch`, `kubectl patch` says `get`.
- The version probe succeeds for an identity with no RBAC (02-forbidden-version-probe), and fails
  with exit 1 for both 401 and unreachable; tell those apart by the stderr phrase.
- A missing namespace is reported as `namespaces "<ns>" not found` even for a namespaced get.
- Missing context: resource calls say `context "<ctx>" does not exist`; the `config get-contexts`
  probe says `context <ctx> not found`.
- External Secrets not installed: `the server doesn't have a resource type "clustersecretstores"`
  (exit 1, even with `--ignore-not-found`); `get --raw` says `the server could not find the requested
  resource`; `api-resources` exits 0 with only the header.

## Not recorded

- ClusterSecretStore present but not Ready: needs the External Secrets Operator installed (Helm is
  not installed on the recording machine). The Ready shape is in
  `tests/fixtures/external-secrets/clustersecretstore-ready.json`.
- A silently dropped network (timeout) and rate limiting (429): kind cannot produce them without
  extra tooling.
