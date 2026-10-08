# P1: Azure Key Vault + Container Apps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `opv plan|status|sync <env>` work for an environment whose target is Azure Key Vault (secrets) plus an Azure Container App (runtime), with pinned Key Vault references, config as env vars, and no change to Fly behaviour. Released as opv 0.5.0 (issue #39).

**Architecture:** A new `[environments.<env>.azure]` target maps to two adapters, `adapters::keyvault::KeyVault` and `adapters::containerapp::ContainerApp`, both wrapping `az` through `CommandRunner`. The ports split by flow (R4): a shared `Store` (list, refusal) with `StagedStore` (Fly: validate, write, remove) and `PinnedStore` (Key Vault: read, write_one, delete); `StagedRuntime` (Fly: deploy) and `PinnedRuntime` (Container Apps: bindings, apply, await_healthy). `adapters::open` returns `Ports::Staged | Ports::Pinned`, so a Fly path can never call a Key Vault operation and vice versa (compile-time, no "not supported" errors). `app/sync.rs` keeps the Fly flow byte-identical and adds the pinned flow; the planner gets exact `Present`/`WouldChange` from compare-before-write reads.

**Review:** FMECA/poka-yoke/TRIZ review of this plan, 2026-10-08 (in the PR description). Its changes are folded in below: typed port split (R4), hashed Container Apps secret names (R2), access check demoted to `doctor` (R6), hardened `az` environment (R7), health definition for probe-less and scale-to-zero apps (R8), post-apply verification (R9), recon fixtures as test inputs (R10).

**Tech Stack:** Rust 2024, clap, serde_json, zeroize, `az` CLI 2.90.0. New runtime dependencies (Task 3 adds them; `cargo deny check` must pass): `subtle = "2"` for the constant-time compare, and `sha2 = "0.10"` moved from `[dev-dependencies]` to `[dependencies]` for config digests and the unmanaged fingerprint. Tests use `runner::fake::FakeRunner` and `app::testutil`.

**Spec:** `docs/design/multi-cloud-targets.md` (§3–§8); `docs/design/requirements.md` FR-28 to FR-33, §8 items 29–35. Issue #39.

## Global Constraints

- Fly behaviour is byte-identical: the 14 golden transcripts in `tests/fixtures/characterization/` must not change (`cargo test characterization` without `UPDATE_GOLDEN`).
- No secret value in argv, env, logs, errors, panics or `Debug` (SR-1, SR-2, SR-3). Key Vault values go on stdin through `--file /dev/stdin`; config values go only inside the stdin spec document of `apply`, never in argv (spec §6).
- No plaintext temp files (SR-4): no `--yaml <tempfile>`; every document goes through `/dev/stdin`.
- On native Windows, every `az` call that carries a value on stdin fails closed before spawning with `Error::Dependency` naming WSL (spec §6 "SR-3 on Azure"). Reads work everywhere.
- A secret is never routed to a plain env var. The only routing switch is `config = "env" | "store"` (default `"env"`).
- Every reference is pinned to an explicit Key Vault version id (FR-29): `https://<vault>.vault.azure.net/secrets/<name>/<version>`.
- `apply` runs only under `--deploy`; it changes only managed env names, sends the whole spec on stdin, and fails with `Error::Target` naming changed unmanaged paths when the unmanaged fingerprint moved (FR-31).
- Delete from Key Vault only names tagged `opv-managed=<env>`, and only after a healthy revision no longer binds them (FR-32). opv never recovers or purges soft-deleted secrets; it prints the recover command.
- One target section per environment; a second one is `Error::Config` (FR-28).
- Ports are synchronous and take `&dyn CommandRunner`.
- Guard test `use_cases_name_no_target_adapter` keeps passing: `app/` and `domain/` never name `keyvault`, `containerapp` or `az`.
- Tests: atomic scenarios, declarative names, exactly one behavioral assertion each.
- After every task: `cargo fmt --all --check`, `cargo clippy --all-targets --features fake -- -D warnings`, `cargo test --locked --features fake`.
- Commits cite requirement IDs and end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Rulings (decisions this plan makes where the spec is silent)

- **R1 `container`.** A Container App can run several containers. `azure.container` is optional; when absent the app must have exactly one container, otherwise `apply`/`bindings` fail with `Error::Config` listing the container names. Mirrors the GCP section's optional `container`.
- **R2 Container Apps secret names.** The Container App secret that holds a reference is named `opv-` + the first 16 hex chars of SHA-256(lower-case Key Vault name) — 20 chars, the limit `az containerapp secret set --help` states, deterministic and collision-checked at config load. `opv explain` shows the mapping. Managed set = env names from the template; `opv-` CA secrets no managed env var references are reported, never removed in P1.
- **R3 Case.** Key Vault names are case-insensitive, so the collision check (spec §5) compares lower-cased store names.
- **R4 Two flows, typed ports.** Fly has no versions, so it cannot pin; clouds have no staging area. Two flows are domain reality, so the ports say so in types: `Store {list, refusal}`; `StagedStore: Store {validate, write, remove}`; `PinnedStore: Store {read, write_one, delete}`; `StagedRuntime {deploy}`; `PinnedRuntime {bindings, apply, await_healthy}`; `adapters::open → Ports::{Staged{store, runtime}, Pinned{store, runtime}}`. `status`/`plan` use `Store` only. No trait method with a "not supported" default exists. Migration: the current `SecretStore`/`Runtime` are renamed in place (Task 3), leaving no old trait behind.
- **R5 JSON schema.** `status --json`/`plan --json` gain optional per-key fields (`binding`, `pending_deploy`, `drift`) that are absent for Fly. Additive, so `schema_version` stays 1 (the spec's bump is deferred until a field changes meaning).
- **R6 Identity; access check demoted.** `identity = "system"` or a user-assigned identity resource id, written verbatim into each CA secret's `identity`. A role-assignment check gives false "no access" answers (group membership needs `--include-groups`, custom roles and PIM are invisible), and a false answer would block every deploy. The authoritative check is Azure's own: a revision whose identity cannot fetch a referenced secret fails provisioning (recon Q14), which `await_healthy` already reports and which leaves the previous revision serving. So `check_access` is a `doctor` **warning** with the grant command, not a deploy gate. Amends FR-33 ("blocking access check" → "advisory in doctor; deploy gated by revision health") — owner approval required.
- **R7 Hardened `az` environment.** Every `az` call gets `AZURE_EXTENSION_USE_DYNAMIC_INSTALL=no` (an extension install prompt would hang a non-interactive run, FR-9), `AZURE_CORE_NO_COLOR=true`, `AZURE_CORE_ONLY_SHOW_ERRORS=true`, `AZURE_CORE_COLLECT_TELEMETRY=no`, and `--only-show-errors`. `az` writes each command's argv to `~/.azure/commands/*.log` (observed 2026-10-08), which is why no value and no config value may ever be in argv. Recon Q12 proves stdin values and response bodies do not reach that directory.
- **R8 Health.** Healthy = `provisioningState` `Provisioned` and `runningState` in {`Running`, `RunningAtMaxScale`} and `healthState` in {`Healthy`, `None`} (`None` = no probes configured). A revision scaled to zero (recon Q7) counts as healthy once `Provisioned`. Failed = `provisioningState` `Failed` or `healthState` `Unhealthy`. Timeout default 300 s, `--deploy-timeout <s>` to override; a timeout is `Error::Target` naming the revision and the last states.
- **R9 Post-apply verification.** Container Apps exposes no usable etag (recon Q8 to confirm), so a change made between opv's read and its update cannot be prevented. It is detected: after `update`, `bindings` is read again; a different unmanaged fingerprint than before the update ⇒ `Error::Target("container app <app> changed while opv applied (<paths>); check those settings")`. Window ≈ one `az` call.
- **R10 Fixtures from reality.** Every adapter test fixture is a recon output with values replaced by markers, stored under `tests/fixtures/azure/`. No hand-invented JSON shapes.

The live recon (Task 1) may overturn R1–R6 or any `az` argv below; its findings update this plan, the spec and `requirements.md` before Task 4 starts.

## Review Focus

1. A Container App with a plain (non–Key Vault) secret the user set by hand: `apply` must keep it, and must not need or send its value. Test in Task 6 (`apply_keeps_unmanaged_plain_secret_without_its_value`).
2. Two keys whose Key Vault names (or hashed Container Apps secret names, R2) differ only by case or `_`/`-` (`DB_URL` and `DB-URL`, or `Db_Url` and `DB_URL`): config load fails naming both. Test in Task 2.
3. A value exactly at and one byte over Key Vault's 25 KB limit: at passes, over is `RuleFailed("store_limit", …)` in `status`, and `sync` refuses before any call. Test in Task 4.
4. A binding re-pinned by hand to an older version: `status` reports drift; `sync` without `--deploy` leaves it; `sync --deploy` repins. Test in Task 7.
5. `--prune --deploy` when the new revision comes up unhealthy: nothing is deleted from Key Vault. Test in Task 7.

---

### Task 1: Live recon against a throwaway Azure resource group (manager + owner)

Needs the owner's explicit OK to create and delete resources in subscription "OutboundLabs". Nothing here goes to CI.

**Files:**
- Create: `docs/design/spike-p1-azure-findings.md`
- Modify: `docs/design/multi-cloud-targets.md` (§6 exact commands), this plan (argv and rulings), `docs/design/requirements.md` if a requirement changes.

- [ ] **Step 1: Create the sandbox** (owner approves first; all names prefixed `opv-spike-`)

```sh
az group create -n opv-spike-rg -l westeurope
az keyvault create -n opv-spike-kv-<rand> -g opv-spike-rg --enable-rbac-authorization true
az containerapp env create -n opv-spike-env -g opv-spike-rg -l westeurope
az containerapp create -n opv-spike-app -g opv-spike-rg --environment opv-spike-env \
  --image mcr.microsoft.com/k8se/quickstart:latest --system-assigned --ingress external --target-port 80
```

Grant the app identity `Key Vault Secrets User` on the vault, and the operator `Key Vault Secrets Officer`. Save every JSON output (values replaced by markers) under `tests/fixtures/azure/` for R10.

- [ ] **Step 2: Answer each question with the exact command and output shape** (use the marker value `opv-spike-marker-1`; never a real secret)

| # | Question | Expected (to confirm) |
|---|---|---|
| Q1 | Does `printf %s marker \| az keyvault secret set --vault-name V --name N --file /dev/stdin --encoding utf-8 --tags opv-managed=dev -o json` store the bytes exactly (no trailing newline added)? Which field holds the versioned id? | `.id` = `https://V.vault.azure.net/secrets/N/<32 hex>` |
| Q2 | Does `az keyvault secret list --vault-name V -o json` return `name`, `id` (unversioned), `tags`, and no `value`? | yes |
| Q3 | `az keyvault secret show --vault-name V --name N -o json`: `.value` and versioned `.id`? Exit code and stderr marker for a missing name (`SecretNotFound`)? | exit 3, stderr contains `SecretNotFound` |
| Q4 | After `az keyvault secret delete`, does `set` on the same name fail with `ObjectIsDeletedButRecoverable`, and with which exit code? | exit 1 |
| Q5 | Does `az containerapp update -g G -n A --yaml /dev/stdin` accept a JSON document (YAML superset) built from `az containerapp show -o json` with `properties.configuration.secrets[*]` carrying `keyVaultUrl`+`identity` and no `value`? Does it keep an existing plain secret whose `value` is omitted, or require it? | determines Task 6's handling of plain secrets |
| Q6 | Is a versioned `keyVaultUrl` honoured (the running replica sees the pinned version, not the latest)? Write v1, bind, write v2, restart revision, check the replica still sees v1 via `az containerapp exec` printing the length only. | yes |
| Q7 | After `update`, which field names the new revision (`properties.latestRevisionName`) and which fields report health (`az containerapp revision show ... --query properties.{health:healthState,running:runningState,provisioning:provisioningState}`)? Which values mean healthy / failed / still going? | `Healthy` / `Unhealthy` / `None` |
| Q8 | Does `show` expose an etag usable for optimistic concurrency with `update`? | probably not; fingerprint fallback |
| Q9 | Probe for login: `az account show` exit status when signed out. | non-zero |
| Q10 | Secret name limits for Container Apps secrets (`opv-` + lower-cased KV name): max length, allowed characters. | `^[a-z0-9][a-z0-9-]*[a-z0-9]$`, ≤ 253 |
| Q11 | `az role assignment list --assignee <principalId> --scope <vault id> --include-inherited --include-groups -o json`: shape of `roleDefinitionName`. | string |
| Q12 | After writing and reading the marker, `grep -rl opv-spike-marker-1 ~/.azure` finds nothing (no value in command logs, caches or telemetry). Repeat with a config marker sent through `update --yaml /dev/stdin`. | no matches |
| Q13 | With `AZURE_EXTENSION_USE_DYNAMIC_INSTALL=no`, does any command opv uses need an extension (`containerapp` is core in 2.90?)? Missing extension ⇒ immediate non-zero exit, no prompt. | no prompt |
| Q14 | Remove the app identity's role, deploy a new revision pinned to a version: does the revision fail provisioning (`provisioningState Failed`), and does the previous revision keep serving traffic in single-revision mode? | yes / yes — R6 depends on it |
| Q15 | A probe-less app and a min-replicas-0 app: their `healthState`/`runningState` after a good deploy. | `None` / scaled-to-zero state — R8 |

- [ ] **Step 3: Write `docs/design/spike-p1-azure-findings.md`** with versions (`az version`, extension `containerapp` version), each question, the command, the observed output shape (names only, marker values only), and the decision. Update this plan's argv tables and rulings where they differ.

- [ ] **Step 4: Tear down**

```sh
az group delete -n opv-spike-rg --yes --no-wait
az keyvault purge -n opv-spike-kv-<rand>   # after the group delete finishes
```

- [ ] **Step 5: Commit**

```sh
git add docs/design/spike-p1-azure-findings.md docs/design/multi-cloud-targets.md docs/design/plans/2026-10-08-p1-azure-container-apps.md
git commit -m "docs(p1): Azure recon findings (FR-29, FR-31, FR-33)"
```

---

### Task 2: Azure target in the model and config (FR-28, FR-30)

**Files:**
- Modify: `src/domain/model.rs` (new `AzureTarget`, `ConfigRoute`, `Target::Azure`)
- Modify: `src/config.rs` (`RawAzure`, one-target rule, identifier checks, name mapping and collision check)
- Test: `src/config.rs` tests module

**Interfaces:**
- Produces:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConfigRoute { #[default] Env, Store }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AzureTarget {
    pub key_vault: String,
    pub resource_group: String,
    pub container_app: String,
    /// R1: required only when the app has more than one container.
    pub container: Option<String>,
    /// "system" or a user-assigned identity resource id (R6).
    pub identity: String,
    /// Env-name template; `{KEY}` under the simple profile.
    pub env_name_template: String,
    pub config: ConfigRoute,
}

impl AzureTarget {
    /// Env var name for product/key (same rendering as FlyTarget::target_name).
    pub fn env_name(&self, product: &str, key: &str) -> String;
    /// Key Vault secret name for an env name: `_` → `-` (spec §5).
    pub fn store_name(env_name: &str) -> String;
}

pub enum Target { Fly(FlyTarget), Azure(AzureTarget) }
// Target::label() → "Azure" ; Target::target_name() → env name for Azure.
```

- [ ] **Step 1: Write the failing tests** in `src/config.rs` tests (each one assertion):

```rust
const AZURE_ENV: &str = r#"
[environments.prod]
vault_id = "v"
item_id = "i"
[environments.prod.azure]
key_vault = "kv-myapp-prod"
resource_group = "rg-myapp"
container_app = "ca-myapp"
identity = "system"
env_name = "FLEET__{PRODUCT}__{KEY}"
"#;

#[test]
fn loads_azure_target() {
    let f = parse(&format!("[profile]\nkind = \"fleet\"\n{AZURE_ENV}{KEYS}")).unwrap();
    assert_eq!(f.environments["prod"].target.as_ref().unwrap().label(), "Azure");
}

#[test]
fn azure_config_route_defaults_to_env() { /* parse AZURE_ENV; assert ConfigRoute::Env */ }

#[test]
fn rejects_two_target_sections() {
    // AZURE_ENV plus [environments.prod.fly] app=..., secret_name=...
    let e = parse(&two_targets).unwrap_err().to_string();
    assert!(e.contains("environment prod: declares both fly and azure; use one target"), "{e}");
}

#[test]
fn rejects_key_vault_name_collision_by_case_or_dash() {
    // products.api.keys.DB_URL and products.api.keys.DB-URL? (keys must match ^[A-Z][A-Z0-9_]*$,
    // so use template collision: product "a-b" key "C" vs product "a" key "B__C" under FLEET__{PRODUCT}__{KEY})
    let e = parse(&colliding).unwrap_err().to_string();
    assert!(e.contains("both map to Key Vault name"), "{e}");
}

#[test]
fn rejects_key_vault_name_over_127_chars() { /* key of 120 chars + template → > 127; error names key */ }

#[test]
fn rejects_azure_identifier_with_leading_dash() { /* resource_group = "-rg" → "azure.resource_group" in error */ }

#[test]
fn rejects_env_name_under_simple_profile_azure() { /* simple profile + azure.env_name → error */ }

#[test]
fn rejects_unknown_config_route() { /* config = "plain" → error naming `config` and the allowed values */ }
```

- [ ] **Step 2: Run** `cargo test --features fake config::` — expect FAIL (unknown field `azure`).

- [ ] **Step 3: Implement.** `RawEnvironment` gains `#[serde(default)] azure: Option<RawAzure>`; `RawAzure { key_vault, resource_group, container_app, #[serde(default)] container: Option<String>, identity: String, env_name: Option<String>, #[serde(default)] config: Option<String> }` with `deny_unknown_fields`. Rules:
  - both `fly` and `azure` → `environment {name}: declares both fly and azure; use one target`.
  - `check_ids` extended to `azure.key_vault`, `azure.resource_group`, `azure.container_app`, `azure.container`, `azure.identity` (same non-empty / unpadded / no leading `-` / no shell metacharacters rule as `fly.app`; identity may contain `/` for a resource id).
  - fleet: `env_name` required and must contain `{PRODUCT}` and `{KEY}`; simple: `env_name` not allowed, template is `SIMPLE_TEMPLATE`.
  - `config`: `None`/`"env"` → `Env`, `"store"` → `Store`, else `environment {name}: azure.config must be "env" or "store", got {v:?}`.
  - New `check_azure_names(&fleet)`: for every declared key in every Azure environment, env name must match `^[A-Z][A-Z0-9_]*$` (like Fly), store name `^[0-9A-Za-z-]{1,127}$`, and lower-cased store names unique: `environment {env}: {a} and {b} both map to Key Vault name {name}`.
  - `check_shared_targets`: two environments with the same `key_vault` and the same template → error (mirrors Fly).

- [ ] **Step 4: Run** the config tests, then the full suite (golden files unchanged). Expected: PASS.

- [ ] **Step 5: Commit** `feat(config): Azure Key Vault + Container Apps target section (FR-28, FR-30)`.

---

### Task 3: Ports grow the P1 operations (FR-29, FR-31, FR-33)

**Files:**
- Modify: `src/ports.rs`, `src/adapters/fly.rs` (impl the new methods with Fly-preserving behaviour), `src/domain/plan.rs` (`StoreEntry` unchanged), new `src/domain/runtime.rs` (types below), `src/domain/mod.rs`.

**Interfaces:**
- Produces (exact):

```rust
// src/domain/runtime.rs — names only, never values (config values live in RuntimeChange only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Binding {
    /// Plain env value (config). The value is not kept: only a SHA-256 hex digest of it,
    /// so `status` can tell "matches" from "differs" without holding the value.
    Plain { digest: String },
    /// Reference to a store entry pinned to `version`.
    Pinned { store_name: String, version: String },
    /// A reference opv cannot interpret (unversioned URL, other vault, other secret source).
    Other,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeSnapshot {
    /// env name → binding, managed names only.
    pub bindings: std::collections::BTreeMap<String, Binding>,
    /// SHA-256 of the canonical JSON of everything outside managed names (FR-31).
    pub unmanaged_fingerprint: String,
    /// The runtime's raw spec, kept for read-modify-write. Holds no secret values
    /// (Key Vault references and config only); `Debug` prints its length only.
    pub spec: RawSpec,
}

pub struct RawSpec(pub serde_json::Value); // Debug: "RawSpec(<n> bytes)"

pub struct RuntimeChange {
    /// env name → (store name, version) to bind.
    pub pin: std::collections::BTreeMap<String, (String, String)>,
    /// env name → config value to set. Config only, never secrets.
    pub set: std::collections::BTreeMap<String, String>,
    /// env names to remove.
    pub unbind: Vec<String>,
}
// Debug for RuntimeChange: names only.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revision(pub String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health { Healthy, Unhealthy(String), TimedOut }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessFinding { pub store_name: String, pub reason: &'static str }

```

```rust
// src/ports.rs (replaces SecretStore/Runtime; renamed in place, no old trait left)
pub trait Store {
    fn list(&self) -> Result<Vec<StoreEntry>, Error>;
    fn refusal(&self, name: &str, value: &SecretValue) -> Option<(&'static str, &'static str)>;
}
pub trait StagedStore: Store {           // Fly
    fn validate(&self, batch: &[(String, &SecretValue)]) -> Result<(), Error>;
    fn write(&self, batch: &[(String, &SecretValue)]) -> Result<(), Error>;
    fn remove(&self, names: &[String]) -> Result<(), Error>;
}
pub trait PinnedStore: Store {           // Key Vault
    /// Current value and version, for compare-before-write (FR-31). None when absent.
    fn read(&self, name: &str) -> Result<Option<(SecretValue, String)>, Error>;
    /// One new version, value on stdin, tagged opv-managed=<env>; returns the version id.
    fn write_one(&self, name: &str, value: &SecretValue) -> Result<String, Error>;
    /// Refuses an entry without the ownership tag (FR-32).
    fn delete(&self, name: &str) -> Result<(), Error>;
}
pub trait StagedRuntime { fn deploy(&self) -> Result<(), Error>; }
pub trait PinnedRuntime {
    fn bindings(&self) -> Result<RuntimeSnapshot, Error>;
    fn apply(&self, change: &RuntimeChange, snapshot: &RuntimeSnapshot) -> Result<Revision, Error>;
    fn await_healthy(&self, revision: &Revision) -> Result<Health, Error>;
    /// Advisory only (R6): used by doctor, never gates a deploy.
    fn check_access(&self, names: &[String]) -> Result<Vec<AccessFinding>, Error>;
}

// src/adapters/mod.rs
pub enum Ports<'a> {
    Staged { store: Box<dyn StagedStore + 'a>, runtime: Box<dyn StagedRuntime + 'a> },
    Pinned { store: Box<dyn PinnedStore + 'a>, runtime: Box<dyn PinnedRuntime + 'a> },
}
impl<'a> Ports<'a> { pub fn store(&self) -> &dyn Store; }   // for status/plan
pub fn open<'a>(target: &'a Target, r: &'a dyn CommandRunner) -> Ports<'a>;
```

There is no `Flow` enum: the `Ports` variant is the flow.

Fly implements `Store + StagedStore + StagedRuntime` by moving its existing impl blocks; no Fly logic changes.

- [ ] **Step 1: Failing tests** in `src/domain/runtime.rs`:

```rust
#[test]
fn runtime_change_debug_names_only() {
    let mut c = RuntimeChange { pin: Default::default(), set: Default::default(), unbind: vec![] };
    c.set.insert("LOG_LEVEL".into(), "opv-marker-config".into());
    assert!(!format!("{c:?}").contains("opv-marker-config"));
}

#[test]
fn raw_spec_debug_prints_length_only() {
    let s = RawSpec(serde_json::json!({"value": "opv-marker-config"}));
    assert!(!format!("{s:?}").contains("opv-marker-config"));
}
```

And in `src/adapters/mod.rs` tests: `fly_target_opens_staged_ports` (`assert!(matches!(open(&fly_target, &r), Ports::Staged { .. }))`).

- [ ] **Step 2: Run** — FAIL (types missing).
- [ ] **Step 3: Implement** the types and traits above; update every caller (`app/sync.rs`, `app/status.rs`, `app/mod.rs`, `app/doctor.rs`) to match on `Ports`.
- [ ] **Step 4: Run** full suite; golden files unchanged.
- [ ] **Step 5: Commit** `refactor(ports): split ports by flow, staged (Fly) and pinned (clouds) (FR-12, FR-28)`.

---

### Task 4: Key Vault adapter (Junior candidate; FR-29, FR-30, FR-32, SR-3)

**Files:**
- Create: `src/adapters/keyvault.rs`, `src/adapters/az.rs` (shared: `PROGRAM = "az"`, error diagnosis, Windows stdin guard)
- Modify: `src/adapters/mod.rs` (`pub mod az; pub mod keyvault;`), `src/host.rs` (`Tool::Az` with install hint)

**Interfaces:**
- Consumes: `Store`, `PinnedStore` (Task 3), `AzureTarget::store_name` (Task 2).
- Produces: `pub struct KeyVault<'a> { pub runner: &'a dyn CommandRunner, pub vault: &'a str, pub env: &'a str, pub template_names: &'a BTreeSet<String> }` implementing `Store + PinnedStore`; `pub const VALUE_LIMIT: usize = 25 * 1024;`; `pub fn az::diagnose(r, op: &str, target: &str) -> Error`; `pub fn az::stdin_supported() -> Result<(), Error>`.

argv (confirm against Task 1 findings):

| fn | argv | stdin |
|---|---|---|
| `list` | `keyvault secret list --vault-name <vault> -o json` | — |
| `read` | `keyvault secret show --vault-name <vault> --name <name> -o json` | — |
| `write_one` | `keyvault secret set --vault-name <vault> --name <name> --file /dev/stdin --encoding utf-8 --tags opv-managed=<env> -o json` | value bytes |
| `delete` | `keyvault secret delete --vault-name <vault> --name <name> -o none` | — |

Behaviour:
- `list` returns `StoreEntry { name, version: None, pending: false }` for entries tagged `opv-managed=<env>` **and** whose name is in `template_names` (managed set, FR-8). Unknown JSON fields ignored.
- `read`: exit with `SecretNotFound` → `Ok(None)`; otherwise parse `.value` into `SecretValue` (zeroize the JSON buffer: it is `Output::stdout`, already `Zeroizing`) and the version = last path segment of `.id`.
- `refusal(name, value)`: value longer than `VALUE_LIMIT` → `Some(("store_limit", "longer than the Key Vault limit of 25 KB"))`; empty → `Some(("store_limit", "Key Vault cannot store an empty value"))`.
- `write_one`: `az::stdin_supported()?` first; parse `.id` → version.
- `delete`: `list` first; name not tagged → `Error::Policy("<name>: not tagged opv-managed=<env>; refusing to delete")`.
- `ObjectIsDeletedButRecoverable` on `set` → `Error::Target("<name> is soft-deleted in Key Vault <vault>; recover it with: az keyvault secret recover --vault-name <vault> --name <name>")`. Detection: the runner discards stderr, so detect by a follow-up read-only probe `keyvault secret show-deleted --vault-name <vault> --name <name> -o none` exit 0.
- `az::diagnose` on any non-zero exit: `az account show -o none` exit status only → non-zero ⇒ `Error::Auth("not logged in to Azure; run: az login")`; zero ⇒ `Error::Target("az <op> failed for <target>")`. `az` missing ⇒ `Error::Dependency` with `host.install_hint(Tool::Az)`.
- `az::stdin_supported`: `cfg!(windows)` ⇒ `Error::Dependency("writing to Key Vault needs /dev/stdin; run opv sync from WSL or Linux")`.

- [ ] **Step 1: Failing tests** in `src/adapters/keyvault.rs` (FakeRunner; marker value `opv-marker-kv`). One assertion each:
  - `write_sends_value_on_stdin_only` (argv has no marker; stdin == marker bytes)
  - `write_tags_entry_with_environment` (argv contains `opv-managed=prod`)
  - `write_returns_version_from_id`
  - `read_missing_secret_is_none` (fake exit 3 for `show`, `show-deleted` not called)
  - `read_returns_value_and_version`
  - `list_keeps_only_tagged_template_names`
  - `list_ignores_unknown_json_fields`
  - `value_at_limit_is_accepted` / `value_over_limit_is_refused_by_store_limit`
  - `delete_refuses_untagged_entry`
  - `soft_deleted_name_error_names_recover_command`
  - `failed_call_when_signed_out_is_auth_error`
  - `failed_call_when_signed_in_is_target_error`
  - `#[cfg(windows)] write_on_windows_fails_closed_naming_wsl`
- [ ] **Step 2: Run** `cargo test --features fake keyvault` — FAIL.
- [ ] **Step 3: Implement** per the table.
- [ ] **Step 4: Run** — PASS; full suite green.
- [ ] **Step 5: Commit** `feat(azure): Key Vault store adapter (FR-29, FR-30, FR-32, SR-3)`.

---

### Task 5: `adapters::open` and target-aware planning for Azure (FR-28, FR-31)

**Files:**
- Modify: `src/adapters/mod.rs` (`Target::Azure` → `(KeyVault, ContainerApp)`; `ContainerApp` may be a stub returning `Error::Target("not implemented")` until Task 6 — tests here use only the store), `src/app/mod.rs` (`plan_item` exact compare), `src/domain/plan.rs` (`PlanOptions::current` hook).

**Interfaces:**
- Produces: in `PlanOptions`, a new field
  `pub current: &'a dyn Fn(&str) -> Option<CurrentState>` where
  `pub enum CurrentState { Same, Differs, Absent }` (from domain::plan). `None` from the closure keeps today's behaviour (Fly → `Unknown`/`Absent`).
- `plan_item`: when `store.read(name)` is supported (returns `Some` or a typed `Absent`), compare with the desired value in constant time (`subtle::ConstantTimeEq` on bytes) → `Present` when equal, `WouldChange` when not, `Absent` when missing. Reads happen only for ready secret rows routed to the store (and config rows when `config = "store"`).

- [ ] **Step 1: Failing tests** (app-level, FakeRunner scripted with `op` item + `az` calls):
  - `azure_status_reports_present_when_store_value_matches`
  - `azure_status_reports_would_change_when_store_value_differs`
  - `azure_status_reports_absent_for_missing_store_entry`
  - `azure_plan_reads_each_secret_once` (count of `keyvault secret show` == number of ready secrets)
  - `fly_plan_makes_no_read_calls` (golden files also cover this)
- [ ] **Step 2–4:** Run (FAIL), implement, run (PASS, goldens unchanged).
- [ ] **Step 5: Commit** `feat(plan): exact store compare for targets that can read (FR-31)`.

---

### Task 6: Container Apps runtime adapter (FR-29, FR-31, FR-33)

**Files:**
- Create: `src/adapters/containerapp.rs`
- Modify: `src/adapters/mod.rs`

**Interfaces:**
- Consumes: `PinnedRuntime`, `RuntimeSnapshot`, `RuntimeChange`, `Binding`, `Revision`, `Health`, `AccessFinding` (Task 3); `az::diagnose`, `az::stdin_supported` (Task 4).
- Produces: `pub struct ContainerApp<'a> { pub runner, pub target: &'a AzureTarget, pub managed: &'a BTreeSet<String> /* env names */, pub vault_uri: String /* https://<vault>.vault.azure.net */ }` implementing `PinnedRuntime`.

argv (confirm against Task 1):

| fn | argv | stdin |
|---|---|---|
| `bindings` | `containerapp show -g <rg> -n <app> -o json` | — |
| `apply` | `containerapp update -g <rg> -n <app> --yaml /dev/stdin -o json` | the full spec as JSON |
| `await_healthy` | `containerapp revision show -g <rg> -n <app> --revision <rev> -o json` (poll every 5 s, max 300 s) | — |
| `check_access` | `containerapp show` (principal id from `.identity.principalId` or the user identity's `principalId` via `identity show --ids <id>`), `keyvault show -n <vault> -o json` (`.id`, `.properties.enableRbacAuthorization`), then `role assignment list --assignee <principal> --scope <vault id> --include-inherited -o json` | — |

Behaviour:
- `bindings`: select the container (R1). For each env var whose name is in `managed`: `value` → `Plain{digest: sha256(value)}`; `secretRef` → look up the CA secret; a `keyVaultUrl` of the form `<vault_uri>/secrets/<name>/<version>` → `Pinned`; anything else → `Other`. `unmanaged_fingerprint` = SHA-256 of canonical JSON of the spec with managed env entries and `opv-` CA secrets removed, and with read-only fields (`provisioningState`, `latestRevisionName`, `latestReadyRevisionName`, `outboundIpAddresses`, `systemData`, `eventStreamEndpoint`, `latestRevisionFqdn`) removed. `spec` keeps the document.
- `apply`: `az::stdin_supported()?`; re-run `bindings`; if the new `unmanaged_fingerprint` differs from `snapshot.unmanaged_fingerprint` ⇒ `Error::Target("container app <app> changed outside opv since it was read (<paths>); nothing applied, safe to re-run")` where paths are JSON pointers of differing unmanaged nodes (names only). Then edit the fresh spec: for each `pin` set CA secret `opv-<lower store name>` = `{name, keyVaultUrl: <vault_uri>/secrets/<store>/<version>, identity}` and env `{name, secretRef}`; for each `set` env `{name, value}`; remove `unbind` env names and their `opv-` secrets. Plain unmanaged secrets keep their entry as returned by `show` (Task 1 Q5 decides whether that needs a value; if it does, `apply` fails with `Error::Config("container app <app> has plain secrets <names>; move them to Key Vault references before using opv")` before sending anything — never fetch secret values). Return `Revision(properties.latestRevisionName)` from the update output.
- `await_healthy`: per R8. After `Healthy`, re-read `bindings` and compare the unmanaged fingerprint with the pre-update one (R9).
- `check_access`: for an RBAC vault, a role named `Key Vault Secrets User`, `Key Vault Secrets Officer` or `Key Vault Administrator` at the vault scope or above ⇒ no findings; else one `AccessFinding{store_name, reason: "the app identity has no Key Vault secrets read role on <vault>"}` per name. Access-policy vault: `keyvault show` `.properties.accessPolicies[]` with the principal's `objectId` and `permissions.secrets` containing `get`.

- [ ] **Step 1: Failing tests** (fixtures under `tests/fixtures/azure/containerapp-show-*.json`, hand-written from Task 1 shapes, marker values only):
  - `bindings_reads_pinned_reference`
  - `bindings_reads_plain_config_as_digest_only` (Debug of snapshot has no marker)
  - `bindings_marks_unversioned_reference_as_other`
  - `bindings_with_two_containers_and_no_container_setting_is_config_error`
  - `apply_sends_spec_on_stdin_and_no_values_in_argv`
  - `apply_pins_reference_with_version`
  - `apply_keeps_unmanaged_env_vars_unchanged`
  - `apply_keeps_unmanaged_plain_secret_without_its_value` (or the Config error, per Q5)
  - `apply_refuses_when_unmanaged_part_changed_and_names_the_path`
  - `apply_returns_latest_revision_name`
  - `await_healthy_reports_healthy` / `await_healthy_accepts_probe_less_revision` / `await_healthy_accepts_scaled_to_zero_revision` / `await_healthy_reports_failed_provisioning` / `await_healthy_times_out` (fake clock: inject `sleep: &dyn Fn(Duration)`)
  - `concurrent_unmanaged_change_after_apply_is_reported` (R9)
  - `every_az_call_carries_the_hardened_environment` (R7)
  - `check_access_passes_with_secrets_user_role`
  - `check_access_reports_each_name_without_role`
- [ ] **Step 2–4:** Run (FAIL), implement, run (PASS).
- [ ] **Step 5: Commit** `feat(azure): Container Apps runtime adapter (FR-29, FR-31, FR-33)`.

---

### Task 7: Pinned-reference sync flow (FR-29, FR-31, FR-32, FR-33)

**Files:**
- Modify: `src/app/sync.rs` (match on `Ports`; new `run_pinned`), `src/app/status.rs` (drift/pending lines), `src/app/mod.rs` (JSON optional fields, R5)
- Test: `src/app/azure_tests.rs` (new, `#[cfg(test)] mod azure_tests;` in `app/mod.rs`)

**Interfaces:**
- Consumes: everything above.
- Produces: `fn run_pinned(fleet, env_name, plan, store, runtime, out, opts) -> Result<(), Error>`.

Flow (spec §6, exact output lines):

```text
1. plan (Task 5) → refuse on blocking rows: "sync refused, nothing staged: <names>"   (unchanged text)
2. every value checked with store.refusal before any write (refuse the whole run on the first one)
3. for each ready secret (and config when config = "store") with state Absent/WouldChange:
       v = store.write_one(name, value)          → "written: <names> (new versions, not live until --deploy)"
   unchanged                                     → "unchanged: <names>"
4. snap = runtime.bindings()
5. change.pin  = every store-routed env name whose binding is not Pinned{store_name, current version}
   change.set  = every env-routed config whose Plain digest differs or is missing
   change.unbind = plan.prune (env names), only with --prune
   drift = Pinned bindings whose version is not the store's current one and was not written by this run
       → "drift (binding re-pinned outside opv): <names>"
6. if change empty → "nothing pending"
   elif !--deploy  → "pending deploy (pass --deploy): <names>"
   else:
       rev = runtime.apply(change, snap) ; health = runtime.await_healthy(rev)
       Healthy → "deployed revision <rev>"
       Unhealthy/TimedOut → Error::Target("revision <rev> is <state>; previous revision keeps serving; nothing pruned; run opv doctor --env <env> to check Key Vault access")
7. if --prune and --deploy and Healthy: store.delete(each unbound store name) → "pruned: <names>"
   if --prune without --deploy → "not pruned without --deploy: <names>"
8. "env-routed (visible to readers of <container_app>): <names>"   (config routed to env)
```

- [ ] **Step 1: Failing table tests** in `src/app/azure_tests.rs` (FakeRunner scripted calls; one assertion each):
  - `no_change_writes_nothing_and_does_not_deploy`
  - `changed_secret_writes_new_version_and_reports_pending_without_deploy`
  - `deploy_pins_new_version` (stdin spec contains the new version id)
  - `deploy_sets_changed_config_as_env_value` (value in stdin spec, not argv)
  - `config_routed_to_store_is_written_to_key_vault`
  - `drift_is_reported_by_status`
  - `drift_is_left_without_deploy`
  - `failed_revision_names_doctor_access_check`
  - `unhealthy_revision_prunes_nothing`
  - `prune_with_deploy_deletes_after_healthy_revision`
  - `prune_without_deploy_only_reports`
  - `refused_sync_makes_no_az_calls`
  - `values_never_reach_argv` (uses `assert_no_values_in_argv` over every scenario's runner)
  - `secret_is_never_routed_to_plain_env` (spec stdin has no `value` for a secret key's env entry)
- [ ] **Step 2–4:** Run (FAIL), implement, run (PASS; goldens unchanged).
- [ ] **Step 5: Commit** `feat(sync): pinned-reference flow for cloud targets (FR-29, FR-31, FR-32, FR-33)`.

---

### Task 8: `doctor`, `explain`, CLI text for Azure (FR-26, FR-33)

**Files:**
- Modify: `src/app/doctor.rs` (az checks when any environment has an Azure target, scoped like Fly), `src/app/explain.rs` (show `key vault name`, `env name`, `routing`), `src/main.rs` help text, `src/host.rs` (`Tool::Az` install hints: Linux `curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash`, macOS `brew install azure-cli`, Windows `winget install -e --id Microsoft.AzureCLI`).

Doctor lines (in order, after the op lines):
`az` version (warn below 2.60.0), `az login` (`az account show -o none`), `key vault <vault>` (`keyvault secret list ... -o none` exit status), `container app <app>` (`containerapp show ... -o none`), `app identity access` (`check_access` on every managed store name; a finding is a **warn** line with the grant command `az role assignment create --assignee <principal> --role "Key Vault Secrets User" --scope <vault id>`, never a failure, R6).

- [ ] **Step 1: Failing tests:** `doctor_checks_az_only_with_azure_target`, `doctor_signed_out_of_azure_names_az_login`, `doctor_missing_access_warns_with_grant_command`, `explain_azure_key_shows_key_vault_name`, `fly_doctor_output_unchanged` (existing tests keep passing).
- [ ] **Step 2–4:** Run (FAIL), implement, run (PASS).
- [ ] **Step 5: Commit** `feat(doctor): Azure CLI, login, vault, app and identity checks (FR-26, FR-33)`.

---

### Task 9: Docs, requirements, changelog, version 0.5.0

**Files:**
- Modify: `README.md` (Targets table: Azure Key Vault + Container Apps "supported (preview until the live receipt in #39)"; "Works today" line), `docs/configuration.md` (`[environments.<env>.azure]` reference, routing, naming rules, R1–R3), `docs/usage.md` (Azure sync flow, `--deploy`, `--prune` order, drift, soft delete), `docs/install.md` (prerequisite `az` ≥ 2.60, WSL for writes on Windows), `docs/agent-setup.md` + `llms.txt` (Azure steps and the identity grant), `docs/design/requirements.md` (§8 items 29–35 marked for Azure Container Apps; record R1–R6), `docs/design/multi-cloud-targets.md` (rulings, recon outcome), `CHANGELOG.md` (`## [0.5.0] - <date>` Added: Azure target; Changed: doctor flyctl patch range from [Unreleased]), `Cargo.toml` + `Cargo.lock` + `npm/*/package.json` version `0.5.0` (follow how 0.4.0 bumped them: `git show 98a56df --stat`).
- [ ] **Step 1:** Write the docs. Every config example uses placeholder names (`kv-myapp-prod`), never real IDs.
- [ ] **Step 2:** `cargo test`, `cargo deny check`, link check by eye.
- [ ] **Step 3: Commit** `release: prepare opv v0.5.0 — Azure Key Vault + Container Apps (#39)`.

---

### Task 10: Live smoke test and release (owner + manager)

- [ ] **Step 1:** With the owner's OK, recreate the Task 1 sandbox; a disposable 1Password item `opv-spike-azure` with two secrets and one config field; `secrets.toml` in a scratch directory.
- [ ] **Step 2:** Run and record (names and versions only): `opv doctor`, `opv plan dev`, `opv sync dev`, `opv sync dev --deploy`, change one secret in 1Password, `opv status dev` (WouldChange), `opv sync dev --deploy` (repin), re-pin by hand to v1 then `opv status dev` (drift), `opv sync dev --deploy --prune` after removing a key from the config.
- [ ] **Step 3:** Paste the receipt into the PR and issue #39; tear the sandbox down (Task 1 Step 4).
- [ ] **Step 4:** Merge to `dev`, promote `dev` → `staging` → `main`, tag `v0.5.0`; owner runs `scripts/npm/publish-manual.sh v0.5.0`.
