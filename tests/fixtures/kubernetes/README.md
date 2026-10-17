# kubectl recordings for ConfigMaps and mounted files (K1, design `delivery-transports.md` §6.9)

Real kubectl output, recorded 2026-10-17 for opv 0.11.0 (deliverable K1). Nothing here is invented.
The earlier Secret-only recordings and their phrase findings are in `success/README.md` and
`failures/README.md`; this file covers cases `success/04`–`17` and `failures/08`–`14`.
Each directory's `cases.tsv` lists these K1 cases with their exit code and exact command.

## Environment

- kubectl **v1.36.1**, API server **v1.37.0**, kind **v0.33.0** (`~/.local/bin/kind`, sha256
  `aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d`, the official release binary
  as verified in `failures/README.md`).
- A throwaway cluster `opv-rec-k1` (context `kind-opv-rec-k1`) with its own `KUBECONFIG` in a temp
  directory; `~/.kube/config` was never written. Deleted after recording
  (`kind delete cluster --name opv-rec-k1`), and the temp kubeconfig, which held the
  ServiceAccount tokens, was removed.
- Namespace `opv-rec`. Deployment `api`: two containers `api` and `sidecar`, image `ubuntu:24.04`
  (GNU coreutils `stat`, `id`; the image has no passwd entry for uid 10001), `sleep infinity`. It
  was created with client-side `kubectl apply`, so it carries a
  `kubectl.kubernetes.io/last-applied-configuration` annotation, which `replace` keeps updating.
  The pods run as the namespace's `default` ServiceAccount, which has no RoleBinding.
- Contexts, each a ServiceAccount in `opv-rec` with a `kubectl create token` bearer token:

| Context | Role in `opv-rec` |
|---|---|
| `opv-rbac` | get, list, create, patch, update, delete on secrets, configmaps and deployments; get, list on replicasets and pods |
| `opv-noconfigmaps` | the same without configmaps (today's opv rights) |
| `opv-designrights` | exactly the §6.5 rights: get, list, create, delete on secrets and configmaps; get, update deployments; list replicasets, pods |
| `opv-patchonly` | as `opv-designrights` with `patch` in place of `create` |
| `kind-opv-rec-k1` | cluster admin; used only for `exec` and `get events` (verification calls, not opv's) |

- Objects (labels `opv-managed=dev`, `opv-key=<store>`; annotations `opv-version=0.11.0`,
  `opv-written=2026-10-17T00:00:00Z`, `opv-env=dev`, `opv-plan=opv-plan-marker`; `immutable: true`;
  every value a marker): Secrets `opv-api--db-url-abcdefghij` (`S7MARKER-db-url`),
  `opv-api--private-key-abcdefghij` (`S7MARKER-private-key`), `opv-api--private-key-klmnopqrst`;
  ConfigMaps `opv-api--otel-resource-abcdefghij` (`S7MARKER-otel-resource`),
  `opv-api--log-level-abcdefghij` (`S7MARKER-log-level`), `opv-api--log-level-klmnopqrst`. The
  ConfigMap manifests on stdin had the shape of opv's Secret manifest (`src/adapters/kubernetes/store.rs`
  `manifest`) with `kind: ConfigMap`, no `type`, and `data.value` as plain text.
- Every `replace` read the Deployment first and sent it back whole with its `resourceVersion`, as
  opv does; its stdin is kept as `<case>.stdin.json`. Call shapes are opv's: `--context <ctx>
  --namespace <ns> --request-timeout=60s` for reads and `120s` for writes, `NO_COLOR=1`, stdin closed
  unless a manifest was piped.

Markers: `<UID_n>` UIDs (numbered, so an `ownerReferences` uid still matches its owner, and the
kubelet's pod directory in event messages), `<RV>` resourceVersions (also inside the escaped
last-applied annotation), `<TIME>` server timestamps (the `opv-written` stamp is the manifest's own
fixed value and kept), `<POD>` the random pod-name suffix (the ReplicaSet hash before it is kept: it
is derived from the template), `<DATE>` dates in `ls -l`, `..<TIMESTAMP_DIR>` the kubelet's atomic-
writer directory. No output contained an IP address or a token.

`$PODS` = opv's `PODS_PATH` (`src/adapters/kubernetes/runtime.rs:56`), `$VALUE` and `$LIST` = opv's
`VALUE_PATH` and `LIST_PATH` (`src/adapters/kubernetes/store.rs:46-51`), `$GEN` =
`jsonpath={.metadata.generation}`; `cases.tsv` spells them out.

## Cases

### K-R1, K-R3: the §6.3 volume, written and read back

| Case | Command | Exit | Result |
|---|---|---|---|
| success/07-get-deployment-before-files | `--context opv-rbac … get deployment api -o json` | 0 | the Deployment before (env-only bindings) |
| success/08-replace-files-volume | `--context opv-rbac … replace -f - -o $GEN`, stdin: the §6.3 volume (`defaultMode: 288`, a `secret` and a `configMap` source, nested `items[].path`, `mode: 288`, `optional: false`), the mount `readOnly` at `/run/secrets/api` in container `api` only, `LOG_LEVEL` as `configMapKeyRef`, the file key's env entry removed | 0 | `2` |
| success/09-get-deployment-after-files | `get deployment api -o json` after it | 0 | volume, env and mounts stored exactly as sent |
| success/10-replace-files-volume-minimal | the same volume without `defaultMode`, `optional`, item `mode` and `readOnly` | 0 | `3` |
| success/11-get-deployment-after-minimal | `get deployment api -o json` after it | 0 | the server added only `projected.defaultMode: 420` |

### K-R2: refused volumes (all `replace -f - -o $GEN` as `opv-rbac`)

| Case | Change to the §6.3 volume | Exit | stderr |
|---|---|---|---|
| failures/12-invalid-replace-path-dotdot | item path `../x` | 1 | `The Deployment "api" is invalid:` then `* spec.template.spec.volumes[0].projected.sources[0].secret.items[0].path: Invalid value: "../x": must not contain '..'` |
| failures/12-invalid-replace-path-dotdot-inner | `github-app/../x` | 1 | the same phrase |
| failures/12-invalid-replace-path-absolute | `/x` | 1 | `…path: Invalid value: "/x": must be a relative path` |
| failures/12-invalid-replace-path-duplicate | both sources at `github-app/private-key` | 1 | `* spec.template.spec.volumes[0].projected: Invalid value: "opv-api--otel-resource-abcdefghij": conflicting duplicate paths` |
| failures/12-invalid-replace-mode-out-of-range | item `mode: 1000` | 1 | `…mode: Invalid value: 1000: must be a number between 0 and 0777 (octal), both inclusive` |
| failures/12-invalid-replace-mountpath-duplicate | a second mount at `/run/secrets/api` | 1 | `…volumeMounts[1].mountPath: Invalid value: "/run/secrets/api": must be unique` (single line) |
| failures/12-invalid-replace-volume-name-duplicate | a second volume `opv-files-api` | 1 | `spec.template.spec.volumes[1].name: Duplicate value: "opv-files-api"` (single line) |
| failures/12-warning-replace-overlapping-paths | ConfigMap item at `github-app`, Secret item at `github-app/private-key` | **0** | stdout `11`; stderr only `Warning: volume "opv-files-api" (Projected): overlapping paths: …` |
| failures/13-get-pods-overlapping-paths | `get pods -l app=api -o $PODS` 45 s later | 0 | the new pod `ContainerCreating ContainerCreating`; the kubelet's FailedMount events (seen, not kept) said `file exists` / `is a directory` |
| failures/11-conflict-replace-deployment | a `replace` whose read was older than the Deployment's last status write | 1 | `Error from server (Conflict): error when replacing "STDIN": Operation cannot be fulfilled on deployments.apps "api": the object has been modified; please apply your changes to the latest version and try again` |

A path error in a volume also produces a second, consequential line,
`* spec.template.spec.containers[0].volumeMounts[0].name: Not found: "opv-files-api"`: the invalid
volume is dropped before the mounts are checked. Match the first line.

### K-R4: a missing source

| Case | Command | Exit | stdout |
|---|---|---|---|
| success/13-replace-missing-configmap-source | `replace` with the ConfigMap source named `opv-missing` | 0 | `13`: the API server accepts it |
| failures/14-get-pods-missing-configmap-source-20s | `--context opv-rbac … get pods -l app=api -o $PODS`, 20 s later | 0 | new pod `ContainerCreating ContainerCreating `, old pod still running |
| failures/14-get-pods-missing-configmap-source-120s | the same, 120 s later | 0 | unchanged |
| failures/14-get-events-missing-configmap-source | `--context kind-opv-rec-k1 … get events --field-selector involvedObject.name=<pod>,reason=FailedMount -o jsonpath=…` | 0 | `FailedMount	MountVolume.SetUp failed for volume "opv-files-api" : configmap "opv-missing" not found` |
| success/13-replace-missing-secret-source | `replace` with the Secret source named `opv-missing` | 0 | `15` |
| failures/14-get-pods-missing-secret-source-60s | `get pods … -o $PODS`, 60 s later | 0 | `ContainerCreating ContainerCreating ` |
| failures/14-get-events-missing-secret-source | as above | 0 | `… : secret "opv-missing" not found` |

The two `ContainerCreating` words are the pod's two containers. The progress deadline (600 s) was
not waited for.

### K-R5: inside the container (`--context kind-opv-rec-k1 … exec <pod> -c api -- …`)

Five pod security contexts, each a fresh rollout of the §6.3 volume (`defaultMode`/`mode` 0440):

| Variant (`12-exec-<variant>-*`) | securityContext | `stat -f -c %T /run/secrets/api` | `stat -L -c "%a %u %g"` key / config | `id` | `cat` the key |
|---|---|---|---|---|---|
| `nofsgroup` | `runAsUser: 10001, runAsGroup: 10001` | `tmpfs` | `440 0 0` / `440 0 0` | `uid=10001 gid=10001 groups=10001` | exit 1, `Permission denied` |
| `fsgroup` | as above + `fsGroup: 10001` | `tmpfs` | `440 0 10001` / same | `uid=10001 gid=10001 groups=10001` | the marker |
| `fsgroup-other` | `runAsUser: 10001, runAsGroup: 10001, fsGroup: 20002` | `tmpfs` | `440 0 20002` / same | `uid=10001 gid=10001 groups=10001,20002` | the marker |
| `root` | `runAsUser: 0` | `tmpfs` | `440 0 0` / same | `uid=0(root) gid=0(root) groups=0(root)` | the marker |
| `imagegid` | `runAsUser: 10001` only | `tmpfs` | `440 0 0` / same | `uid=10001 gid=0(root) groups=0(root)` | **the marker** |

`-ls` shows the layout: `github-app -> ..data/github-app`, `otel -> ..data/otel`,
`..data -> ..<TIMESTAMP_DIR>`; with `fsGroup` the directories are setgid and group-owned by it.
`-sidecar-ls` (`exec … -c sidecar -- ls /run/secrets/api`) exits 2 with
`ls: cannot access '/run/secrets/api': No such file or directory` in every variant.

### K-R6: references after two deploys

| Case | Command | Exit | stdout |
|---|---|---|---|
| success/15-replace-deploy-1 | `replace` back to key `…-private-key-abcdefghij`, log level `…-log-level-abcdefghij` | 0 | `16` |
| success/15-replace-deploy-2 | `replace` to `…-private-key-klmnopqrst`, `…-log-level-klmnopqrst` | 0 | `17` |
| success/16-get-replicasets-after-two-deploys | `--context opv-rbac … get replicasets -o json` | 0 | 11 ReplicaSets; the live one (revision 17) names the new Secret and ConfigMap; every older one still names the versions it ran with |

Deploy 1 restored a template the Deployment had run before, so the controller reused that
ReplicaSet (`api-7d87cb47bc`) and renumbered its revision to 16 instead of creating one.

### K-R7: the ConfigMap store

| Case | Command | Exit | stdout |
|---|---|---|---|
| success/04-can-i-{create,get,list,delete}-configmaps-yes | `--context opv-rbac … auth can-i <verb> configmaps` | 0 | `yes` |
| success/05-apply-configmap-created | `--context opv-rbac … apply -f - --server-side --field-manager=opv -o name`, ConfigMap `opv-api--otel-resource-abcdefghij` | 0 | `configmap/opv-api--otel-resource-abcdefghij` |
| success/05-apply-configmap-unchanged | the same again | 0 | the same line |
| success/05-apply-configmap-second | ConfigMap `opv-api--log-level-abcdefghij` | 0 | `configmap/opv-api--log-level-abcdefghij` |
| success/05-get-configmap-value | `… get configmap opv-api--log-level-abcdefghij --ignore-not-found -o $VALUE` | 0 | `dev	S7MARKER-log-level` (plain text, not base64; no newline) |
| success/05-get-configmap-value-missing | the same for `opv-missing` | 0 | *(empty)* |
| success/05-list-configmaps | `… get configmap -l opv-managed=dev -o $LIST` | 0 | one tab-separated line per ConfigMap |
| success/17-delete-configmaps | `--context opv-rbac … delete configmap <two names> --ignore-not-found` | 0 | `configmap "<name>" deleted from opv-rec namespace`, one line each |
| success/17-delete-configmaps-missing-ignored | the same again | 0 | *(empty)* |
| success/17-delete-configmap-one | `delete configmap opv-api--log-level-abcdefghij --ignore-not-found` (immutable, still named by old ReplicaSets) | 0 | one `deleted` line: neither immutability nor a reference blocks a delete |
| failures/08-can-i-{create,get,list,delete}-configmaps-no | `--context opv-noconfigmaps … auth can-i <verb> configmaps` | 1 | `no`, stderr empty |
| failures/08-forbidden-apply-configmap | `--context opv-noconfigmaps … apply … --server-side …` | 1 | `Error from server (Forbidden): configmaps "opv-api--log-level-klmnopqrst" is forbidden: User "system:serviceaccount:opv-rec:opv-noconfigmaps" cannot patch resource "configmaps" in API group "" in the namespace "opv-rec"` |
| failures/08-forbidden-get-configmap | `… get configmap … --ignore-not-found -o $VALUE` | 1 | `… cannot get resource "configmaps" …` |
| failures/08-forbidden-list-configmaps | `… get configmap -l opv-managed=dev -o $LIST` | 1 | `Error from server (Forbidden): configmaps is forbidden: … cannot list resource "configmaps" …` |
| failures/08-forbidden-delete-configmap | `… delete configmap … --ignore-not-found` | 1 | `… cannot delete resource "configmaps" …` |
| failures/09-immutable-configmap-apply-changed | `--context opv-rbac … apply …`, the existing immutable ConfigMap with a different value | 1 | ``The ConfigMap "opv-api--log-level-abcdefghij" is invalid: data: Forbidden: field is immutable when `immutable` is set`` |
| failures/09-notfound-configmap | `… get configmap opv-missing -o name` | 1 | `Error from server (NotFound): configmaps "opv-missing" not found` |
| failures/10-forbidden-apply-configmap-create-rights-only | `--context opv-designrights … apply …` (new ConfigMap) | 1 | `… cannot patch resource "configmaps" …` |
| failures/10-forbidden-apply-configmap-create-rights-only-unchanged | the same again | 1 | the same |
| failures/10-forbidden-apply-secret-create-rights-only | the same with Secret `opv-api--private-key-klmnopqrst` | 1 | `… cannot patch resource "secrets" …` |
| failures/10-can-i-create-configmaps-yes-without-patch | `--context opv-designrights … auth can-i create configmaps` | 0 | `yes` |
| failures/10-can-i-patch-configmaps-no-without-patch | `--context opv-designrights … auth can-i patch configmaps` | 1 | `no` |
| failures/10-forbidden-apply-configmap-patch-rights-only | `--context opv-patchonly … apply …` (new ConfigMap) | 1 | `… cannot create resource "configmaps" …` |

## Assumptions (§13)

- **[A2] Confirmed, with one gap.** One projected volume merged a Secret and a ConfigMap into
  `/run/secrets/api` (`12-exec-*-ls`); nested `items[].path` works (`github-app/private-key`,
  `otel/resource`); `..` anywhere in a path is refused (`must not contain '..'`), and so are
  absolute paths and duplicate paths. The merged volume, holding both kinds of source, is `tmpfs` (`stat -f`).
  **Gap:** a file path that is a directory of another (`github-app` and `github-app/private-key`)
  is *accepted* with only a `Warning:` on stderr and exit 0, and the new pod then sticks in
  `ContainerCreating` (failures/12-warning-…, 13-…). The API server does not catch it, so opv must.
- **[A3] Confirmed.** Without `fsGroup` the files are `0 0` (root:root) at 0440; with `fsGroup` the
  group is `fsGroup`, and `fsGroup` is a supplementary group of the process (`groups=10001,20002`
  with `runAsGroup: 10001, fsGroup: 20002`). **But §6.6's verdict table is wrong in one row:**
  "`fsGroup` unset, `runAsUser` set and not 0 → unreadable" does not hold when the process's
  primary group is 0. With `runAsUser: 10001` and no `runAsGroup`, the gid comes from the image's
  `/etc/passwd`, and an image with no entry for that uid gives gid 0, so the root-group-readable
  0440 files *are* readable (`12-exec-imagegid-*`: `gid=0(root)`, `cat` succeeds). The verdict
  needs the effective `runAsGroup` too (§6.6 amended).
- **[A5] Confirmed, narrowly.** The only default the API server added to the volume was
  `projected.defaultMode: 420`, and only when it was omitted (success/10, 11). It added no
  `optional`, no item `mode` and no `readOnly`. With the §6.3 volume as designed (every field
  explicit) the stored volume, env and mounts equal what was sent (success/08, 09), so the
  normalisation in `fingerprint()` is just `defaultMode` absent ↔ 420.
- **[A7] Confirmed.** A missing ConfigMap or Secret source leaves the new pod `ContainerCreating`
  (both containers) for at least 120 s, with no other waiting reason in `$PODS`; the API server
  accepts the `replace`. The FailedMount event names the missing object.
- **[A4]** (partly, from K-R6): every template change made a new revision, and old ReplicaSets keep
  naming the versions they ran with. A template equal to an earlier one reuses that ReplicaSet.
  The kubelet-refresh half is for V10.
- **[A6]** (corroborated, settled by V8): the pods ran as the namespace's `default` ServiceAccount,
  which has no RoleBinding, and mounted both kinds of source.

## Other findings for the design

- **Server-side apply needs `patch` and, for a new object, `create`.** opv's write is `apply
  --server-side`. With exactly the §6.5 rights (get, list, create, delete) it is refused `cannot
  patch` (10-…-create-rights-only), for ConfigMaps and equally for Secrets, while `auth can-i
  create` answers `yes` (10-can-i-…). With `patch` but not `create` it is refused `cannot create`
  (10-…-patch-rights-only). So §6.5 must list `patch` on configmaps, and today's `ACCESS`
  (`src/adapters/kubernetes/runtime.rs:62-118`) has the same hole for Secrets: a Role granting just
  what `doctor` checks passes `doctor` and fails `sync` with 403.
- **A conflict on `replace` is easy to hit** (failures/11): the Deployment controller writes status
  right after a rollout, so a read taken just before that write is stale. This session hit it twice; one is kept.
- **ConfigMap values read back as plain text** (`05-get-configmap-value`), not base64 as with
  Secrets; the compare-before-write read must not base64-decode them.
- **Deleting an immutable, still-referenced ConfigMap succeeds** (`17-delete-configmap-one`);
  only opv's `referenced_names` check stands between clean-up and a rollback that needs it.

## Not recorded

- The rollout failing at `progressDeadlineSeconds` with a missing source (needs a 600 s wait, or a
  shorter deadline that is not opv's to set).
- Pod Security `restricted` ([A11]): V2, with a labelled namespace.
