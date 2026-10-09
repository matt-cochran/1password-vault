# Multi-cloud targets: Azure, AWS and GCP

Status: approved by the owner on 2026-10-08. Requirements FR-28 to FR-33 and §8 items 27 to 36 in
`docs/design/requirements.md` are normative; this document is their argument and the delivery plan.

## 1. Intent

opv today syncs 1Password into Fly.io only. Adopters outside the fleet run on Azure, AWS and GCP.
This change lets them use opv without weakening any FR or SR:

- **Secrets** (concealed fields) go to the cloud's secret store and reach the app as a
  *reference*, never as a plain env value.
- **Config** (text fields) goes to the runtime's env vars by default, or to the store when the
  adopter sets `config = "store"`.
- A secret can never be routed to plain env. There is no flag for it.

What the owner said: secrets belong in the secret store; things that can be env vars should not be
forced into the store; users choose split (default) or everything-in-store. The driver is other
adopters, not a fleet migration. Assumption: one target per environment, as with Fly today.

## 2. Scope

| Cloud | Store | Runtimes | Phase |
|---|---|---|---|
| (all) | ports + Fly on the ports | Fly | P0 |
| Azure | Key Vault | Container Apps | P1 |
| Azure | Key Vault | App Service | P2 |
| AWS | Secrets Manager | ECS (Fargate and EC2 launch types) | P3 |
| GCP | Secret Manager | Cloud Run (covers Cloud Run functions) | P4 |

Deferred, tracked as backlog issues:

- **AWS Lambda runtime.** Lambda env vars cannot reference Secrets Manager; the app would need
  the Parameters and Secrets extension or SDK code, and env is capped at 4 KB. Needs its own design.
- **A separate Cloud Run functions adapter.** Not needed: current Cloud Run functions are Cloud
  Run services, so the Cloud Run adapter covers them. Confirmed or reopened in P4.

Rejected: a value-entropy heuristic to catch a secret stored as a text field (unproven, false
positives). The concealed/text kind is explicit in 1Password (FR-14) and every plan lists
env-routed names.

## 3. Architecture (FR-12, FR-28)

Two ports replace the Fly calls in `app/` and `domain/`:

```rust
/// A secret store: Key Vault, Secrets Manager, Secret Manager. Fly implements it too.
pub trait SecretStore {
    /// Managed entries by store name: version id and ownership tag. Never values.
    fn list(&self) -> Result<Vec<StoreEntry>, Error>;
    /// Current value and version of one entry, for compare-before-write (FR-31).
    fn read(&self, name: &StoreName) -> Result<Option<(SecretValue, VersionId)>, Error>;
    /// Writes a new version (value on stdin) tagged `opv-managed=<env>`; returns its version id.
    fn write(&self, name: &StoreName, value: &SecretValue) -> Result<VersionId, Error>;
    /// Deletes an entry. Refuses an entry without the ownership tag (FR-32).
    fn delete(&self, name: &StoreName) -> Result<(), Error>;
    fn limits(&self) -> StoreLimits;                        // FR-30
    fn store_name(&self, env_name: &str) -> Result<StoreName, Error>; // FR-30
}

/// A runtime: Container Apps, App Service, ECS, Cloud Run. Fly implements it too.
pub trait Runtime {
    /// Managed env bindings by env name: plain config (name only) or a pinned store reference.
    fn bindings(&self) -> Result<RuntimeSnapshot, Error>;
    /// Applies config values and pinned references to managed names only, as one spec document
    /// on stdin (FR-31); creates the new revision. Called only under `--deploy`.
    fn apply(&self, change: &RuntimeChange, snapshot: &RuntimeSnapshot) -> Result<Revision, Error>;
    /// Waits for the new revision to report healthy or failed (FR-33).
    fn await_healthy(&self, revision: &Revision) -> Result<Health, Error>;
    /// Checks the runtime identity can read each referenced store entry (FR-33).
    fn check_access(&self, names: &[StoreName]) -> Result<Vec<AccessFinding>, Error>;
    fn limits(&self) -> RuntimeLimits;
}
```

- A target is one `SecretStore` plus one `Runtime`. The ports are synchronous and take the
  existing `CommandRunner`, like the current adapters.
- **Fly** is one adapter implementing both: its store write is `secrets import --stage`, its
  runtime apply is `secrets deploy`, and its "version" is the Fly digest. Fly behaviour stays
  byte-identical (P0 characterization tests). Fly has no `read`: its compare stays
  stage-and-compare on digests (§6.4), expressed through the port as `read → None` plus
  digest-based versions.
- `app/sync.rs`, `app/status.rs`, `domain/plan.rs`, `app/doctor.rs` and `app/explain.rs` stop naming
  Fly. Fly-only names (`FlySecret`, `fly_name`) become target-neutral (`StoreEntry`, `target_name`).
  No parallel path remains after P0.
- **Fly config is unchanged:** config fields have never been synced to Fly (consumers read them with
  `config export`), and P0 keeps that. Config routing applies to cloud runtimes only.
- **Ports grow with their consumers:** P0 adds only the operations the current engine calls
  (`list`, value refusal, batch validate, write, remove, deploy). P1 adds `read`, `bindings`,
  `apply`, `check_access` and `await_healthy` when Key Vault and Container Apps first need them;
  the signatures above are that destination.

## 4. Configuration (FR-28)

Each environment declares at most one target section: `fly`, `azure`, `aws` or `gcp`. A second
one is a configuration error. Existing `fly` sections are unchanged.

```toml
[environments.prod.azure]
subscription   = "00000000-0000-0000-0000-000000000000"  # required; --subscription on every call (NR-7)
key_vault      = "kv-myapp-prod"
resource_group = "rg-myapp"
container_app  = "ca-myapp"            # exactly one of container_app | app_service
identity       = "system"              # or a user-assigned identity resource id
env_name       = "FLEET__{PRODUCT}__{KEY}"   # fleet profile; the managed set (FR-8)
config         = "env"                 # default; "store" routes config like secrets

[environments.prod.aws]
region        = "eu-west-1"
secret_prefix = "opv/prod/"            # store names are prefix + mapped env name
ecs           = { cluster = "c", service = "s", container = "app" }

[environments.prod.gcp]
project   = "my-project"
cloud_run = { service = "api", region = "europe-west1", container = "app" }  # container optional
```

- Simple profile (FR-20): `env_name` is not allowed; the field name is the env name, as with Fly.
- Every identifier is validated like `fly.app` (no leading `-`, no shell metacharacters).
- `config = "store"` is the only routing switch. Secrets → env is not expressible.

## 5. Naming and limits (FR-30)

- The env name comes from the template (fleet) or the field name (simple), unchanged.
- Each store maps the env name to a store name and validates it **when the config loads**:
  - Key Vault: `_` → `-`; result must match `^[0-9A-Za-z-]{1,127}$`.
  - Secrets Manager: `secret_prefix` + env name; `^[A-Za-z0-9/_+=.@-]{1,512}$`.
  - Secret Manager: env name as is; `^[A-Za-z0-9_-]{1,255}$`.
- Two env names that map to one store name is a configuration error naming both keys.
- Each adapter declares value-size limits (Key Vault 25 KB, Secrets Manager 64 KB, Secret Manager
  64 KiB; runtime env limits as documented per platform, verified in the adapter phase). The rule
  engine checks them before any write and reports the key and rule, never the value (FR-15).

## 6. Sync flow on clouds (FR-29, FR-31, FR-32)

`opv sync <env>` (and `opv plan <env>`) work for every target; `opv fly sync` and `opv fly plan`
stay as aliases with a deprecation warning for one minor release, then are removed. Removed in 0.4.0.

```text
resolve desired values from 1Password (one item read, FR-13)
validate names, limits and rules for every key            # fail before any call
store.list()                                              # names, versions, tags
for each secret-routed key:
    store.read(name) → compare with desired in constant time
    differs or missing → store.write(name)  → new version V   # the staging step
runtime.bindings()                                        # current pinned refs and config names
compute RuntimeChange: refs to repin, config to set, names to unbind
if --deploy and change non-empty:
    runtime.check_access(referenced names)                # blocking (FR-33)
    runtime.apply(change)  → revision R                   # the deploy step
    runtime.await_healthy(R)
if --prune and --deploy:
    delete from store only names unbound by a healthy R   # FR-32 order
report: written, pending deploy, deployed, pruned, unchanged, unmanaged count
```

- **FR-29 pinned references.** Every reference binds an explicit version id (Key Vault versioned
  URI, ECS `valueFrom` ARN with version id, Cloud Run `secret:N`, App Service versioned
  `SecretUri`). A store write is invisible to the running app until `--deploy` repins it, so a
  restart or scale-out never picks up a staged value.
- **Config values** are written only by `runtime.apply`, so they too change only under `--deploy`.
  Without `--deploy` they are reported as pending.
- **No change** means: every secret's store value equals 1Password, every binding points to the
  store's current version, and every config value matches. Then nothing is written or deployed.
- **Drift:** a binding that points to a version opv did not write (re-pinned by hand) is reported
  by `status` and only overwritten under `--deploy`.
- **FR-31 read-modify-write.** `apply` reads the current spec, changes only managed names, and
  sends the whole spec on stdin. It fingerprints the unmanaged part before and after, and uses the
  platform's optimistic concurrency where one exists (ECS task-definition revision, Cloud Run
  `metadata.generation`, Azure resource etag). A changed unmanaged part fails with the changed
  paths (never values) and a "safe to re-run" exit category. Config values never appear in argv.
- **FR-32 prune.** `--prune` without `--deploy` only reports. With `--deploy`: unbind, wait for a
  healthy revision, then delete from the store. Delete requires the `opv-managed=<env>` tag. A
  soft-deleted name (Key Vault, AWS recovery window) that blocks a re-create fails with the exact
  recover command; opv never recovers or purges by itself.
- **SR-3 on Azure and AWS.** Values go through `/dev/stdin` (`az ... --file /dev/stdin`,
  `aws ... file:///dev/stdin`). On native Windows these writes fail closed with a typed error
  naming WSL; `plan`, `status` and reads work everywhere. GCP uses `--data-file=-`.

## 7. Errors and observability (FR-10, FR-26)

- New errors reuse the existing categories: config (names, limits, two target sections), auth
  (cloud CLI not logged in, diagnosed like `flyctl auth whoami`), target (CLI failure, race,
  unhealthy revision), policy (ownership tag missing, value refused).
- Each cloud adapter diagnoses a failure with a read-only identity probe (`az account show`,
  `aws sts get-caller-identity`, `gcloud auth print-access-token` exit status only), as FR-26 does
  for Fly, and prints the next command.
- `status` and `plan`, text and `--json`, gain per-key columns: store version current,
  binding current, pending deploy, drift, and an "env-routed (visible to readers of <service>)"
  section. `schema_version` bumps.
- `doctor` checks the cloud CLI, login, store read/write on a managed name, and runtime-identity
  access. It reports an identity that can read untagged secrets as "scope broader than needed".

## 8. Testing

- **P0:** characterization tests record every Fly argv and stdin byte for `plan`, `sync`,
  `--deploy`, `--prune`, `--rotate`, `--prune-immutable`; the refactor must keep them identical.
- **Every adapter:** a fake CLI (existing `CommandRunner` fakes) and four contract tests shared
  across adapters through the ports: no 1Password value in argv (marker-value test, config
  included), stdin carries exactly the expected document, a non-zero exit is diagnosed to its
  category, and unknown JSON fields are ignored.
- **Sync engine:** table tests over the port fakes for pinned-version repin, no-change, drift,
  prune ordering, ownership refusal, soft-delete conflict and the unmanaged-fingerprint race.
- Tests follow the project rule: atomic scenarios, declarative names, one behavioral assertion.
- Real-cloud smoke tests are manual per phase and recorded in the phase PR; CI uses fakes only.

## 9. Delivery

Each phase is one feature branch → `dev` PR → release through staging → main.

| Phase | Owner | Junior tasks |
|---|---|---|
| P0 ports + Fly | manager (judgment: interfaces, refactor) | characterization tests; renames once the ports exist |
| P1 Key Vault + Container Apps | manager wires the engine | `recon` on `az` stdin, versioned refs and YAML update; Key Vault adapter; Container Apps adapter |
| P2 App Service | Junior | adapter + contract tests |
| P3 Secrets Manager + ECS | manager reviews | `recon`; two adapters |
| P4 Secret Manager + Cloud Run | manager reviews | `recon`; two adapters; confirm Cloud Run functions coverage |

The P1 `recon` result can change §6 details (exact commands, health signals). Any change goes back
into this document and `docs/design/requirements.md` before the adapter is built.

## 10. Risk summary

From the 2026-10-08 FMECA review: all High risks mitigated to Low. The residual Medium-severity,
Low-probability risk is a secret stored as a text field becoming plain env (R12), accepted
because a heuristic would be speculative. The mitigations that must not be dropped are pinned
references (FR-29), read-modify-write with the unmanaged fingerprint (FR-31), prune order and the
ownership tag (FR-32), and P0 characterization tests.

## 11. Provider plug-in contract (FR-37)

Decided 2026-10-08 (owner): every provider is pluggable behind one contract, so adding a provider
changes no core code. Fly, Azure and Kubernetes all implement it.

```rust
/// One deployment provider. Registered once in `adapters::registry::PROVIDERS`.
pub trait Provider: Sync {
    /// Config section name under `[environments.<env>]`: "fly", "azure", "kubernetes".
    fn section(&self) -> &'static str;
    fn label(&self) -> &'static str;                          // "Fly", "Azure", "Kubernetes"
    /// Parses and validates that section (identifiers, templates, required fields, NR-7 scope).
    /// `Section::deserialize` reports a shape error with the file's line and column (FR-2).
    fn parse(&self, section: &Section<'_>, profile: Profile) -> Result<Box<dyn TargetConfig>, Error>;
    fn credential_vars(&self) -> &'static [&'static str] { &[] } // e.g. FLY_API_TOKEN, by name
    fn doctor_checks(&self) -> &'static [&'static str];      // names, for doctor's "skip" lines
    fn setup_hint(&self, profile: Profile) -> String;          // "configure fly.app ..." (no target)
    fn init_section(&self, name: &str, profile: Profile) -> Option<String>; // `opv init` (FR-23)
}

/// A validated, provider-specific target. Core code sees only this trait.
pub trait TargetConfig: fmt::Debug + Send + Sync {
    fn provider(&self) -> &'static dyn Provider;               // its label names it: "on Fly"
    fn env_name(&self, product: &str, key: &str) -> String;   // runtime env var name
    fn store_name(&self, env_name: &str) -> String;           // name in the store
    fn name_rules(&self) -> NameRules;                        // patterns, case sensitivity, limits (FR-30)
    fn same_target(&self, other: &dyn TargetConfig) -> bool;  // two environments sharing one target
    fn shared_target_error(&self, first: &str, second: &str) -> String; // its FR-8 message
    fn open<'a>(&'a self, env: &'a str, managed: BTreeSet<String>, r: &'a dyn CommandRunner)
        -> Result<Ports<'a>, Error>;                           // managed: template env names (FR-8)
    fn preflight(&self, r: &dyn CommandRunner) -> Result<(), Error>;  // NR-23..NR-26, read-only
    fn doctor(&self, r: &dyn CommandRunner, host: &dyn Fn() -> Host) -> Vec<Check>;
    fn explain(&self, product: &str, key: &str) -> Vec<(&'static str, String)>;
    fn eq_dyn(&self, other: &dyn TargetConfig) -> bool;       // whole-config equality
    fn as_any(&self) -> &dyn Any;
    fn clone_box(&self) -> Box<dyn TargetConfig>;
}
```

As implemented (Task P): `open` returns `Result` (a provider whose adapters are not wired in
yet refuses with `Error::Config`); `doctor` takes the host so install hints and token checks
stay testable; `label`, `doctor_checks`, `setup_hint`, `shared_target_error` keep every Fly
message byte-identical without core naming Fly; `eq_dyn`, `as_any`, `clone_box` let the
configuration model keep `Clone`/`Eq`. `adapters::registry::DEFAULT` names the provider opv
suggests when an environment has no target (and the one `init` writes): Fly in 0.5.0.

Review fixes (Task P): a provider section is read through `Section::deserialize`, which keeps
the TOML source positions, so a missing, unknown or mistyped field shows the line, column and
field exactly as 0.4 did; unknown entries under an environment and the two-provider error point
at their line too. `preflight` returns `Result<(), Error>`: the warning concept waits for the
preflight task (R2), which decides where warnings print. `tools()` had no caller and is gone; a
provider's CLI is a `host::Tool` value (program and install line per platform) declared in its
own module, and its credential variables come from `Provider::credential_vars`, so `host.rs`
names no provider.

Integration (Key Vault + Container Apps): `open` also takes the managed env names (FR-8), which
the pinned adapters need to recognise what they own. Every store port speaks runtime env names;
Key Vault maps them to its spelling (`_` → `-`) inside the adapter. The Azure adapters live in
`src/adapters/azure/` (`keyvault.rs`, `containerapp.rs`, and `az.rs`, their shared spawn,
diagnosis, `/dev/stdin` and pacing plumbing), and `AzureTarget::open` returns `Ports::Pinned`.

- `config.rs` keeps the generic environment fields and dispatches each remaining table to the
  provider registered under that section name; an unknown section is a config error listing the
  registered names; two provider sections in one environment is the FR-28 error.
- `Target` (the enum) is replaced by `Box<dyn TargetConfig>`. `app/`, `domain/` and `config.rs`
  never name a provider; the existing guard test is extended to every provider module name.
- `init` stays provider-aware by design (it writes a provider section) through
  `Provider::init_section`, added when a provider supports `init`.
- Adding a provider = one module under `src/adapters/<provider>/` (declared with `pub mod` in
  `src/adapters/mod.rs`) + one line in the registry + docs. Nothing else.

## 12. Kubernetes target (FR-38)

Store: Kubernetes Secrets. Runtime: a Deployment (StatefulSet later if asked). CLI: `kubectl`.

```toml
[environments.dev.kubernetes]
context    = "kind-opv"                    # required; passed as --context on every call (NR-7)
namespace  = "myapp"                       # required; --namespace on every call
deployment = "api"
container  = "api"                         # optional when the pod has one container
env_name   = "FLEET__{PRODUCT}__{KEY}"     # fleet profile only
config     = "env"                         # or "store" (a ConfigMap-free design: config in Secrets)
```

- **Pinned flow.** Kubernetes Secrets have no versions, so opv creates an immutable Secret per
  value version: name `opv-<store name>-<first 10 hex of SHA-256(value)>`, `immutable: true`,
  labels `opv-managed=<env>`, `opv-key=<store name>`. The hash suffix is the version (FR-29); a pod
  sees a new value only when the Deployment is repinned. Store names follow DNS-1123
  (`_` → `-`, lower case, ≤ 253 with the suffix) and are collision-checked at load.
- **Writes** go through `kubectl apply -f - --server-side --field-manager=opv` with the manifest on
  stdin (SR-3); values are base64 in `data`, never in argv.
- **Compare before write** lists `kubectl get secret -l opv-key=<name>,opv-managed=<env>` with a
  jsonpath of names and labels only (`-o json` returns `data`, recon K2); the current version is
  the one the Deployment binds; the desired version's name is computable locally from the value
  hash, so an unchanged value is a name lookup, with no value read back.
- **Runtime apply** reads the Deployment (`kubectl get deployment -o json`), edits only managed
  env entries (`valueFrom.secretKeyRef` for secrets, `value` for config), and writes it back with
  `kubectl replace -f -` carrying `metadata.resourceVersion`: Kubernetes rejects the write if anyone
  changed the Deployment in between (true optimistic concurrency, stronger than R9).
- **Health:** opv polls the Deployment and judges it as `kubectl rollout status` does
  (observedGeneration ≥ generation, then updated = replicas, no old replicas, available =
  updated; a Deployment scaled to 0 is healthy once observed) within the remaining run budget.
  It fails fast, without waiting for the progress deadline, on `ProgressDeadlineExceeded`, a
  paused Deployment, or a pod of the *new* ReplicaSet waiting with `CreateContainerConfigError`,
  `ImagePullBackOff`, `ErrImagePull` or `CrashLoopBackOff` (recon K4). Pods are judged only once
  the new generation is observed, so an old ReplicaSet's pods are never misread as the new one's.
- **Prune** deletes old `opv-managed=<env>` Secrets only after a successful rollout, and never one
  named anywhere in the Deployment or in any ReplicaSet of the namespace. Decision (rollback):
  Kubernetes keeps `revisionHistoryLimit` old ReplicaSets for `kubectl rollout undo`; a Secret
  one of them references is kept, so a rollback never starts pods that bind a missing Secret.
  Old versions are reclaimed as Kubernetes trims the history.
- **Access** (FR-33 as amended by R6): the Deployment's ServiceAccount needs no secret access
  (kubelet mounts the env); `doctor` checks the operator's own rights with
  `kubectl auth can-i` for get/create/delete/list secrets, get/update deployments and list
  replicasets and pods; a missing right is a warning naming the `create role` /
  `create rolebinding` commands that grant exactly it.

As implemented (provider plug-in): `src/adapters/kubernetes/config.rs` holds the section, its
`TargetConfig` and the doctor checks (`kubectl`, `kubernetes context`, `kubernetes cluster`,
`kubernetes access`). Each identifier is validated while the section is deserialized, so a bad
`context`, `namespace`, `deployment`, `container`, `env_name` or `config` shows its line and
column. `namespace`/`deployment`/`container` are DNS-1123 labels; `context` allows
`[A-Za-z0-9_.:/@+-]` and no leading `-` (cloud context names hold `:`, `/` and `@`). The store
name is also the `opv-key` label value, so it is held to a label (≤ 63), which keeps the Secret
name ≤ 253. `env_name` is required under the fleet profile and refused under the simple one.
Two environments on the same context, namespace and Deployment with the same template are a
configuration error. `TargetConfig::open` takes the managed env names (as on the Azure branch)
and the rollout wait is the run budget left (`CommandRunner::remaining`), not a fixed 600 s.
`KUBECONFIG` is inherited; no credential variable is required.

