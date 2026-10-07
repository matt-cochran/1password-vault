# Secret Sync CLI — CONOPS, Functional Requirements, and Implementation Notes

## 1. Purpose

This document defines the initial concept of operations and requirements for an open-source Rust CLI that synchronizes secrets from **1Password** into runtime targets, with **Fly.io** as the first supported target.

The tool is intentionally **not** a secrets manager. It does not store secrets, provide a server, manage users, implement encryption, or replace 1Password. Its role is orchestration:

> Resolve secrets from a trusted source, safely inject them into a local process or synchronize them to a runtime target.

Initial scope:

- 1Password is the canonical source of truth.
- Local development uses `op://` secret references and process injection.
- Fly.io is the first deployment target.
- CI/CD must support unattended, least-privilege operation.
- Secret values must never be persisted by the CLI.

---

# 2. CONOPS

## 2.1 Operating Model

The CLI sits between 1Password and consumers of secrets.

```text
                 1Password
              canonical source
                    │
             op:// references
                    │
              ┌─────▼─────┐
              │    opv    │
              │   Rust    │
              └─────┬─────┘
                    │
          ┌─────────┴─────────┐
          │                   │
          ▼                   ▼
   local process          Fly.io Secrets
     environment               │
                               ▼
                          Fly Machines
```

The repository contains only secret references and deployment configuration.

```text
secrets.toml          safe to commit
op:// references      safe to commit
secret values         never committed
plaintext .env        not required
```

## 2.2 Primary Users

### Developer

A developer wants to run an application locally using secrets stored in 1Password without maintaining plaintext `.env` files.

Example:

```bash
opv run dev -- dotnet run
```

The CLI validates configuration and delegates secret resolution to the 1Password CLI. The child process receives secrets through its environment.

### Operator

An operator wants to inspect whether Fly.io secrets would change before applying them.

```bash
opv fly plan prod
```

No secret values are printed.

### CI/CD Pipeline

A deployment workflow uses a restricted 1Password service account and Fly API token.

```bash
opv fly sync prod --deploy
```

The command must:

- require no interactive input;
- use read-only 1Password access;
- transmit secret values only through memory/stdin;
- avoid deployment when the resulting Fly secret state is unchanged.

## 2.3 Source of Truth

1Password is authoritative for secret values.

The CLI must not create an independent secret database or state store.

A committed configuration file maps environment variable names to 1Password references.

Example:

```toml
[environments.dev.secrets]
DATABASE_URL = "op://myapp-dev/database/url"
STRIPE_KEY   = "op://myapp-dev/stripe/secret"

[environments.prod.fly]
app = "myapp-production"

[environments.prod.secrets]
DATABASE_URL = "op://myapp-prod/database/url"
STRIPE_KEY   = "op://myapp-prod/stripe/secret"
JWT_KEY      = "op://myapp-prod/application/jwt"
```

## 2.4 Secret Ownership

The CLI must distinguish between secrets it owns and secrets managed by other systems.

By default, synchronization must **not delete** unconfigured Fly secrets.

Deletion must require explicit authorization.

Example:

```bash
opv fly sync prod --prune
```

Preferably, ownership is declared explicitly:

```toml
[environments.prod.fly]
app = "myapp-production"
managed = [
  "STRIPE_KEY",
  "JWT_KEY",
  "OPENAI_API_KEY"
]
```

Only explicitly managed secrets may be deleted.

---

# 3. Functional Requirements

## FR-1 — Configuration

The CLI shall load a repository-local configuration file named `secrets.toml` by default.

The configuration shall support:

- named environments;
- secret-name to `op://` reference mappings;
- Fly application name;
- optional managed-secret ownership;
- products, per-key kind, rules, guidance and immutability (fleet profile, §10);
- future extension to additional secret sources and targets.

Configuration shall never contain secret values.

## FR-2 — Configuration Validation

The CLI shall validate configuration before performing secret operations.

Validation shall include:

- duplicate secret names;
- malformed `op://` references;
- missing required Fly configuration;
- invalid managed-secret declarations;
- references to undefined environments.

Validation failures shall occur before any target mutation.

## FR-3 — Diagnostics

The CLI shall provide:

```bash
opv doctor
```

The command shall verify:

- configuration validity;
- presence of the `op` CLI;
- 1Password authentication;
- presence of `flyctl` when Fly functionality is requested;
- Fly authentication;
- minimum supported dependency versions where relevant.

The command shall not resolve or print secret values unless necessary to verify access.

## FR-4 — Local Process Execution

The CLI shall provide:

```bash
opv run <environment> -- <command> [args...]
```

The command shall:

1. load the selected environment;
2. construct the required secret-reference environment;
3. delegate resolution to the 1Password CLI where practical;
4. start the requested child process;
5. propagate the child's exit code.

The CLI shall not write resolved secrets to disk.

## FR-5 — Fly Plan

The CLI shall provide:

```bash
opv fly plan <environment>
```

The command shall produce a human-readable synchronization plan without exposing secret values.

The plan should classify keys as:

- managed;
- new;
- potentially changed;
- removed from configuration;
- unmanaged on Fly.

Where Fly exposes sufficient metadata or digests, the CLI should use that metadata to improve change detection.

Decided in v0.1.0: Fly digests cannot be computed locally, so a desired key that is already on Fly is shown as "potentially changed"; real change detection happens in `fly sync` (§6.4). A key removed from the configuration is no longer declared, so it is neither reported nor pruned; unset it manually. Unmanaged names on Fly are only counted.

## FR-6 — Fly Synchronization

The CLI shall provide:

```bash
opv fly sync <environment>
```

The command shall:

1. validate configuration and authentication;
2. resolve the configured 1Password secret references (in CI, by reading each configured item once, by ID; see FR-13);
3. transmit values to Fly without command-line arguments or plaintext files;
4. stage the resulting Fly secrets;
5. determine whether the effective Fly secret state changed;
6. report the result without exposing values.

The command shall be deterministic and suitable for CI.

## FR-7 — Fly Deployment

The CLI shall support:

```bash
opv fly sync <environment> --deploy
```

When `--deploy` is provided, the CLI shall deploy staged secret changes only when necessary.

If no effective secret change occurred, it shall avoid an unnecessary Fly deployment/restart.

## FR-8 — Pruning

The CLI shall never delete Fly secrets by default.

Pruning shall require:

```bash
--prune
```

Pruning shall apply only to secrets explicitly owned by the CLI.

If ownership is not declared, pruning should fail safely rather than infer ownership.

In the fleet profile (§10) the managed set is derived from the declaration: every name produced by the target naming template for a declared key. Names outside that set (for example values staged by other automation) are never pruned.

Decided in v0.1.0: every declared key's rendered name must be unique within an environment's template, whichever environments the keys are declared for (otherwise one run could stage and prune the same name); a name staged by a run is never pruned by it; and an immutable key (FR-16) is never pruned. It is reported as "held (immutable), not pruned", and releasing it takes `--prune --prune-immutable <product>/<key>` (repeatable, validated before any call). Two environments may not share the same Fly app and naming template.

Prune scope: only template names of declared keys that are not desired in this environment. A key removed from the configuration is outside the managed set and is never pruned.

## FR-9 — Non-Interactive Operation

Commands used by CI shall not prompt for input.

If an operation requires confirmation, the CLI shall require an explicit command-line option instead of falling back to interactive confirmation.

CI behavior must be predictable from arguments and configuration alone.

## FR-10 — Exit Codes

The CLI shall use stable exit codes for at least:

- success;
- configuration error;
- authentication error;
- source resolution error;
- target communication error;
- denied destructive operation;
- child-process failure.

Final assignments (a public contract from v0.1.0):

| code | meaning |
|---|---|
| 0 | success |
| 2 | configuration error, and command-line usage error |
| 3 | dependency (`op` or `flyctl` missing or unusable) |
| 4 | source (1Password) |
| 5 | target (Fly) |
| 6 | policy: refused (blocking keys, a refused value, a denied destructive operation) |
| 7 | authentication (1Password or Fly) |
| 8 | findings (`status`, `fly plan` found blocking keys) |

`run` exits with the child's own exit code. A closed stdout (`status | head`) does not change the result.

## FR-11 — Dry-Run Safety

Planning commands shall not mutate 1Password or Fly.

No read-only operation shall write metadata such as "last synchronized at" back to 1Password.

## FR-12 — Extensible Source/Target Model

The internal design shall permit future sources and targets without coupling core synchronization logic to 1Password or Fly.

Possible future targets include:

- AWS Secrets Manager;
- Kubernetes Secrets;
- Cloudflare;
- Docker/Compose;
- other deployment platforms.

Possible future sources may be supported only if they preserve the project's security model.

## FR-13 — Whole-Item Reads

In CI, the CLI shall read each configured 1Password item once per run, by vault ID and item ID, and serve every key from that in-memory copy. It shall not look items up by title or resolve one reference per key.

Reason: service-account rate limits. On 1Password Families/Teams a token gets 1,000 reads per hour and the whole account 1,000 (Families) or 5,000 (Teams) requests per 24 hours. A fleet release must cost a handful of requests, not one per key.

Measured (D0 spike): a cold whole-item read by vault ID and item ID costs 2 requests; `op` caches by default on UNIX, so a repeat read costs 0. CI should set `OP_CACHE=false` to see the worst case.

Local commands (`run`) may resolve per-reference through `op run`; they use the person's desktop-app session, not a service account.

## FR-14 — Field Kinds

Each declared key has a kind, `secret` or `config`. In 1Password the field type records it: concealed = secret, text = config. A key stored with the wrong type is an error reported by `status` and refused by `fly sync` and `config export`.

## FR-15 — Declarative Validation Rules

Each declared key may carry rules, evaluated after resolution and before any target mutation. Rules are generic and data-driven; the CLI has no product-specific code. Initial rule set:

- `nonempty`, single line, maximum length (always on);
- `prefix`, `not_prefix`, `regex`, `enum`;
- `base64_bytes = N`, `hex_bytes = N`;
- `email_list`, `https_url`;
- `prefix_by_mode` (for example Stripe `sk_test_` vs `sk_live_` chosen by a declared mode);
- `refuse_in = [<environment>]` (a key that must not exist in an environment): evaluated before anything else, so a non-empty field in a refused environment is a blocking `refuse_in` failure even though the key is not otherwise expected there; the environments must be defined and must not also be listed in `environments`;
- named transforms with a fixed output format (for example a SigNoz ingestion header).

Rule failures name the key and the rule, never the value.

Target limits count as rules too: `status` and `fly plan` check each ready secret against the Fly import rules (`fly-name-invalid`, `import-newline`, `import-hash-after-odd-quotes`, `import-line-too-long`, `import-invalid-utf8`, `import-duplicate-name`) and show a refusal as a failing rule, so they never show green for a value `fly sync` would refuse. The maximum length is 59 000 bytes, below the 60 000-byte import line limit.

## FR-16 — Immutable Keys

A key may be declared `immutable` (encryption keys, session-signing keys: changing them makes data unreadable or signs everyone out). For an immutable key, `fly sync` stages a value only when the name is absent on the target. Changing it requires `--rotate <product>/<key>`; otherwise a difference is reported and not staged.

Under stage-and-compare (§6.4) the value cannot be compared locally, so an immutable key present on Fly is reported as "held" and left alone; `--rotate` stages it.

## FR-17 — Status

The CLI shall provide:

```bash
opv status <environment>
```

One row per product × key: declared, saved, missing, extra (in the item but not declared), wrong kind, failing rule, and target state (present, absent; "would change" is not produced, because digests cannot be compared locally, see §6.4). Names only. Non-zero exit when anything is missing or failing, so it can run as a scheduled drift check. For missing keys it prints the declared guidance text.

## FR-18 — Config Export

The CLI shall provide:

```bash
opv config export <environment> --json
```

It prints the config-kind values only, as non-secret JSON for deployment tooling to render. It refuses to run if any declared config key is stored as a secret, or any secret as config. There is still no command that prints secret values.

## FR-19 — Item Skeleton

The CLI shall provide:

```bash
opv item skeleton <environment>
```

It creates or completes the environment's item: every declared section and field, with the right type and empty value, without changing existing values. This is the only command that writes to 1Password, and it needs a write-capable identity; `fly sync`, `plan`, `status` and `config export` stay read-only.

---

# 4. Security Requirements

## SR-1 — No Secret Logging

Secret values shall never appear in:

- normal logs;
- debug logs;
- error messages;
- tracing output;
- panic output generated by project code.

Debug logging shall redact conservatively.

## SR-2 — Secret-Safe Types

Resolved secret values shall use a dedicated wrapper type whose `Debug` and `Display` implementations are redacted.

Example concept:

```rust
pub struct SecretValue(SecretString);

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<REDACTED>")
    }
}
```

Use a crate such as `secrecy` or an equivalent implementation where appropriate.

## SR-3 — No Secret CLI Arguments

Resolved secret values shall never be passed as subprocess command-line arguments.

Secret transmission to external tools shall use:

- stdin;
- environment variables;
- controlled in-memory APIs.

## SR-4 — No Plaintext Temporary Files

The CLI shall not create plaintext files containing resolved secrets, including temporary files.

## SR-5 — Least Privilege

A CI identity shall require only:

- read access to the required 1Password vault/items;
- the minimum Fly permissions required to manage secrets for the target application.

The CLI shall not require write access to 1Password for synchronization.

## SR-6 — Explicit Destructive Operations

Secret deletion shall require explicit user intent.

The CLI shall never infer that every secret present on Fly but absent from configuration should be deleted.

## SR-7 — Shell Avoidance

The implementation shall not execute user-generated shell command strings.

Subprocesses shall use structured argument invocation via `std::process::Command` or `tokio::process::Command`.

## SR-8 — Memory Hygiene

Secret buffers should be zeroized when practical.

Copies of secret values should be minimized.

Security-sensitive dependencies should be kept small and audited.

---

# 5. CLI Surface

The surface shipped in v0.1.0:

```text
opv [--config <path>] doctor
opv [--config <path>] status <environment>
opv [--config <path>] run <environment> --product <product> -- <command>
opv [--config <path>] fly plan <environment>
opv [--config <path>] fly sync <environment> [--deploy] [--prune] [--rotate <product>/<key>] [--prune-immutable <product>/<key>]
opv [--config <path>] config export <environment> --json
opv [--config <path>] item skeleton <environment>
```

`--config` defaults to `secrets.toml`. `--json` exists only on `config export`; `--verbose` and `--quiet` are not implemented.

There should be no generic `secret get` command in the initial release because printing raw values conflicts with the tool's primary safety goals.

---

# 6. Implementation Notes

## 6.1 Language

Rust is recommended because the project benefits from:

- static binaries;
- cross-platform distribution;
- strong type modeling;
- explicit resource ownership;
- safe subprocess handling;
- secret-safe wrapper types;
- low runtime dependency footprint.

## 6.2 Architecture

Prefer ports-and-adapters / hexagonal organization.

```text
src/
├── domain/
│   ├── environment.rs
│   ├── secret.rs
│   ├── secret_ref.rs
│   └── sync_plan.rs
│
├── application/
│   ├── doctor.rs
│   ├── plan.rs
│   ├── run.rs
│   └── sync.rs
│
├── ports/
│   ├── secret_source.rs
│   └── secret_target.rs
│
├── adapters/
│   ├── onepassword/
│   │   └── op_cli.rs
│   └── fly/
│       └── flyctl.rs
│
├── config/
│   └── toml.rs
│
└── cli/
    └── ...
```

Core orchestration must not know about subprocess syntax.

Example interfaces:

```rust
#[async_trait]
pub trait SecretSource {
    async fn resolve(
        &self,
        reference: &SecretRef,
    ) -> Result<SecretValue>;
}

#[async_trait]
pub trait SecretTarget {
    async fn metadata(&self) -> Result<SecretMetadataSet>;

    async fn stage(
        &self,
        secrets: &[ResolvedSecret],
    ) -> Result<StageResult>;

    async fn remove(
        &self,
        names: &[SecretName],
    ) -> Result<()>;
}
```

## 6.3 1Password Integration

Initial implementation should prefer the official `op` CLI rather than implementing 1Password authentication or API behavior.

Advantages:

- reuses supported 1Password authentication;
- supports interactive developer accounts and service accounts;
- reduces security-sensitive code in this project;
- preserves compatibility with `op://` references.

For `opv run`, prefer delegating directly to `op run` where possible rather than resolving secrets into the parent process.

## 6.4 Fly Integration

Prefer `flyctl` for normal Fly application secret operations.

Secret values must be transmitted through stdin.

Do not rely on undocumented Fly Machines API secret behavior unless Fly documents it as the supported application-secret interface.

The implementation should use Fly secret metadata/digests, when available, to avoid unnecessary deployment.

A safe synchronization sequence is approximately:

```text
read Fly metadata A
resolve desired secrets
stage desired secrets
read Fly metadata B

if A == B:
    report no change
else if --deploy:
    deploy/sync staged secrets
else:
    report staged changes
```

Exact behavior should be verified against the current Fly CLI semantics during implementation.

Decided in v0.1.0 (stage-and-compare): Fly digests cannot be computed locally, so `fly sync` stages, then compares the digests it read before and after. Names whose digest differs, or that had none before, count as changed. Deploy is gated: it runs only with `--deploy`, and only when something changed, a prune happened, or a managed name is still pending on Fly (status Staged or Partial) from an earlier run. Otherwise sync reports "nothing pending". A deploy on an app with no machines fails with exit 5.

## 6.5 Plan Model

Synchronization logic should produce a domain-level `SyncPlan` before mutation.

Example:

```rust
pub struct SyncPlan {
    pub additions: Vec<SecretName>,
    pub updates: Vec<SecretName>,
    pub removals: Vec<SecretName>,
    pub unmanaged: Vec<SecretName>,
}
```

The plan itself shall never contain resolved secret values.

This makes dry-run behavior and destructive-operation checks testable independently from Fly or 1Password.

## 6.6 Error Handling

Use typed errors.

Possible categories:

```text
ConfigError
DependencyError
AuthenticationError
SourceError
TargetError
PolicyError
ProcessError
```

User-facing errors should describe the operation and key name/reference where useful, but must never include secret values.

## 6.7 Testing

The project should require meaningful behavioral tests from the first release.

### Unit tests

Test:

- configuration parsing;
- secret reference validation;
- ownership/prune rules;
- synchronization planning;
- redaction;
- error mapping;
- no-op detection.

### Adapter tests

Mock subprocess execution for:

- `op`;
- `flyctl`.

Verify that secret values:

- do not enter command arguments;
- do not enter logs;
- are written only to intended stdin/environment channels.

### Integration tests

Where feasible, use disposable test accounts/apps or fixtures for:

- 1Password CLI behavior;
- Fly secret staging;
- digest/change detection.

Integration tests containing real credentials must run only in controlled CI contexts.

## 6.8 Observability

Logs should describe operations using names and counts only.

Good:

```text
Resolved 7 secret references.
3 Fly secrets will be updated.
No secrets require pruning.
```

Bad:

```text
DATABASE_URL=postgres://...
```

Structured JSON output may be provided for CI but must follow the same redaction rules.

## 6.9 Distribution

Initial distribution targets (v0.1.0 ships GitHub Releases and `cargo install --git`; Homebrew and crates.io arrive in v0.1.1):

- GitHub Releases;
- Homebrew;
- cargo install;
- prebuilt Linux/macOS binaries;
- Windows binary if practical.

Supply-chain practices should include:

- reproducible release workflow where feasible;
- checksums;
- signed release artifacts where practical;
- pinned GitHub Actions;
- Dependabot/Renovate;
- dependency auditing (`cargo audit`);
- release provenance/SLSA support when reasonable.

---

# 7. Non-Goals

The initial project shall not provide:

- a hosted service;
- a daemon;
- a database;
- a web UI;
- user management;
- its own encryption system;
- secret editing/storage;
- automatic credential rotation;
- PKI;
- dynamic database credentials;
- audit-log replacement for 1Password or Fly.

Those concerns remain the responsibility of the secret source or runtime platform.

---

# 8. MVP Acceptance Criteria

Version 0.1 is acceptable when:

1. `opv doctor` validates a developer/CI environment.
2. `opv run dev -- <command>` runs without plaintext secret files.
3. `opv fly plan prod` reports intended changes without exposing values.
4. `opv fly sync prod` stages configured secrets safely.
5. `--deploy` deploys only when secret state changed.
6. `--prune` can remove only explicitly managed secrets.
7. CI operation is fully non-interactive.
8. A read-only 1Password service account is sufficient.
9. Secret values do not appear in logs, debug output, CLI arguments, or temporary files.
10. Core planning and security behavior has automated test coverage.
11. A full fleet `fly sync` (§10) costs at most 4 1Password requests per environment.
12. `status` reports missing, extra, wrong-kind and rule-failing keys for every product without printing values.
13. An immutable key that differs from the target is reported and not staged unless `--rotate` names it.
14. `config export` never emits a secret-kind field.

---

# 9. Guiding Principle

The project should stay narrowly focused:

> **1Password owns secrets. The runtime platform consumes secrets. The CLI safely connects the two.**

If a feature requires the CLI to become a new source of truth, secrets database, identity provider, or secrets platform, it is probably outside the intended scope.

---

# 10. Fleet Profile (first consumer: `matt-cochran-products/infra`)

The first deployment runs many products inside **one Fly app per environment**, each product a container whose launcher maps only its own names. The general model in §2–§3 is one environment ↔ one Fly app ↔ a flat list of keys. The fleet profile adds a product dimension without adding product-specific code.

## 10.1 Store layout

```text
vault <name>-<environment>   item <name>   section <product>   field <KEY>
                                                               concealed = secret, text = config
```

One vault per environment is the isolation boundary: service accounts are granted whole vaults, not items. One item per environment keeps a release to one read (FR-13).

## 10.2 Configuration

```toml
[profile]
kind = "fleet"

[environments.prod]
vault_id = "…"            # IDs, not names (FR-13)
item_id  = "…"
fly.app  = "mcproductlabs-portfolio-production"
fly.secret_name = "FLEET__{PRODUCT}__{KEY}"   # naming template; defines the managed set (FR-8)

[environments.prod.modes]
allumata.payments = "off"                      # inputs to prefix_by_mode rules

[products.allumata.keys.OPENAI_API_KEY]
kind = "secret"
environments = ["prod"]
rules = { prefix = "sk-", not_prefix = "sk-or-" }
guidance = "OpenAI platform / API keys …"

[products.allumata.keys.INTEGRATION_ENC_KEY]
kind = "secret"
environments = ["staging", "prod"]
immutable = true
rules = { base64_bytes = 32 }

[products.allumata.keys.SIGNUP_POLICY]
kind = "config"
environments = ["staging", "prod"]
rules = { enum = ["open", "invite_only"] }
```

The consumer may generate this file from its own catalog; opv reads only this file. Product names are upper-cased into the template (`allumata` → `ALLUMATA`).

The `fly` section is optional per environment: an environment used only for `run`, `config export` and `item skeleton` (for example `dev`) omits it, and `status` and the `fly` commands refuse it with a configuration error. `vault_id`, `item_id` and `fly.app` must match `^[A-Za-z0-9][A-Za-z0-9._-]*$`.

## 10.3 Coexistence with other automation

Other tools stage names outside the managed set on the same Fly app (database URLs from Terraform state, generated keys). opv must:

- stage with `--stage` semantics and never deploy unless `--deploy` is passed, so one later deploy applies everything staged by every tool;
- never read, compare or prune names outside its managed set.

## 10.4 Local development

`run` maps a product's keys to plain names for the child process (`OPENAI_API_KEY`, not the fleet name) and resolves `op://<vault>/<item>/<product>/<KEY>` references through `op run`.

---

# 11. Prior Art: `significa/1password-secrets`

[significa/1password-secrets](https://github.com/significa/1password-secrets) (Python, MIT per `setup.py`) solves a similar problem: 1Password secure notes holding `.env` text, pulled locally or imported to Fly. opv borrows its workflow, not its code. If any code is ported, keep its MIT notice.

**Keep:**

- the flow: read item → compute change → stage on Fly → `fly secrets deploy`;
- lookup by naming convention instead of a per-key mapping;
- a diff before any write, showing names only;
- share links for handing one item to someone.

**Reject**, because each one breaks a requirement above:

| Their behavior | Breaks |
|---|---|
| Debug log prints the parsed secrets (`logger.debug(f"Secrets loaded…{json.dumps(secrets)}")`) | SR-1 |
| `op item create/edit … notesPlain=<all secrets>` passes values as command-line arguments | SR-3 |
| `edit` writes secrets to a `NamedTemporaryFile` for the editor | SR-4 |
| `local pull` writes `./.env` | FR-4 |
| Deletes every Fly secret not in the note, after a y/n prompt | FR-8, FR-9, SR-6 |
| Writes "last imported at" back to 1Password on every import | FR-11, SR-5 |
| Finds items by `op item list` + title substring | FR-13 |
| One `.env` text blob per Fly app | FR-14, §10.1 (one typo breaks every product; coarse history) |
