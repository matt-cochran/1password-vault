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
              │ secretctl │
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
secretctl run dev -- dotnet run
```

The CLI validates configuration and delegates secret resolution to the 1Password CLI. The child process receives secrets through its environment.

### Operator

An operator wants to inspect whether Fly.io secrets would change before applying them.

```bash
secretctl fly plan prod
```

No secret values are printed.

### CI/CD Pipeline

A deployment workflow uses a restricted 1Password service account and Fly API token.

```bash
secretctl fly sync prod --deploy
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
secretctl fly sync prod --prune
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
secretctl doctor
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
secretctl run <environment> -- <command> [args...]
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
secretctl fly plan <environment>
```

The command shall produce a human-readable synchronization plan without exposing secret values.

The plan should classify keys as:

- managed;
- new;
- potentially changed;
- removed from configuration;
- unmanaged on Fly.

Where Fly exposes sufficient metadata or digests, the CLI should use that metadata to improve change detection.

## FR-6 — Fly Synchronization

The CLI shall provide:

```bash
secretctl fly sync <environment>
```

The command shall:

1. validate configuration and authentication;
2. resolve the configured 1Password secret references;
3. transmit values to Fly without command-line arguments or plaintext files;
4. stage the resulting Fly secrets;
5. determine whether the effective Fly secret state changed;
6. report the result without exposing values.

The command shall be deterministic and suitable for CI.

## FR-7 — Fly Deployment

The CLI shall support:

```bash
secretctl fly sync <environment> --deploy
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

Exact numeric assignments may be finalized during implementation.

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

# 5. Initial CLI Surface

The MVP should intentionally remain small.

```text
secretctl doctor

secretctl run <environment> -- <command>

secretctl fly plan <environment>

secretctl fly sync <environment> [--deploy] [--prune]
```

Potential global options:

```text
--config <path>
--verbose
--quiet
--json
```

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

For `secretctl run`, prefer delegating directly to `op run` where possible rather than resolving secrets into the parent process.

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

Initial distribution targets:

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

1. `secretctl doctor` validates a developer/CI environment.
2. `secretctl run dev -- <command>` runs without plaintext secret files.
3. `secretctl fly plan prod` reports intended changes without exposing values.
4. `secretctl fly sync prod` stages configured secrets safely.
5. `--deploy` deploys only when secret state changed.
6. `--prune` can remove only explicitly managed secrets.
7. CI operation is fully non-interactive.
8. A read-only 1Password service account is sufficient.
9. Secret values do not appear in logs, debug output, CLI arguments, or temporary files.
10. Core planning and security behavior has automated test coverage.

---

# 9. Guiding Principle

The project should stay narrowly focused:

> **1Password owns secrets. The runtime platform consumes secrets. The CLI safely connects the two.**

If a feature requires the CLI to become a new source of truth, secrets database, identity provider, or secrets platform, it is probably outside the intended scope.
