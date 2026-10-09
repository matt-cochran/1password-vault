# Secret Sync CLI — CONOPS, Functional Requirements, and Implementation Notes

## 1. Purpose

This document defines the initial concept of operations and requirements for an open-source Rust CLI that synchronizes secrets from **1Password** into runtime targets, with **Fly.io** as the first supported target.

The tool is intentionally **not** a secrets manager. It does not store secrets, provide a server, manage users, implement encryption, or replace 1Password. Its role is orchestration:

> Resolve secrets from a trusted source, safely inject them into a local process or synchronize them to a runtime target.

Initial scope:

- 1Password is the canonical source of truth.
- Local development uses `op://` secret references and process injection.
- Fly.io is the first deployment target. Since v0.3, Azure, AWS and GCP are targets too (FR-28 to FR-33).
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
- a flat key map with no products (simple profile, v0.2, FR-20);
- future extension to additional secret sources and targets.

Since v0.2: when `--config` is not given, the file is found by walking up parent directories (FR-25).

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

Decided in v0.4: `doctor --env <environment> [--product <product>]` checks only what that scope needs; an environment without a target needs no deployment CLI. Every `doctor` run on Linux and macOS also reports whether `op` can start a local child (FR-36).

Decided in v0.5 (UX review P6, P18): `doctor --env` makes the environment's one item read by IDs (FR-13) and evaluates the selected keys as `check` does, reporting names, counts and states only, so it is never all clear when `check` would fail. Unscoped `doctor` reads no item. `doctor --json` prints `{schema_version: 1, checks: [{name, status, detail, next}], next}`.

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

Decided in v0.4: before delegating, `run` removes every declared key name from the inherited environment and adds only the selected references (FR-35).

## FR-5 — Fly Plan

The CLI shall provide:

```bash
opv fly plan <environment>
```

Since v0.4 the command is `opv plan <environment>` (FR-28); the `fly` form is removed.

The command shall produce a human-readable synchronization plan without exposing secret values.

The plan should classify keys as:

- managed;
- new;
- potentially changed;
- removed from configuration;
- unmanaged on Fly.

Where Fly exposes sufficient metadata or digests, the CLI should use that metadata to improve change detection.

Decided in v0.1.0: Fly digests cannot be computed locally, so a desired key that is already on Fly is shown as "potentially changed"; real change detection happens in `fly sync` (§6.4). A key removed from the configuration is no longer declared, so it is neither reported nor pruned; unset it manually. Unmanaged names on Fly are only counted.

Decided in v0.5 (FR-31): a pinned store that can read its values back (Azure Key Vault) is read once per ready secret it lists, and the value compared exactly in constant time, so `plan` shows "unchanged" or "changed" and `status` "present" or "would change" for it. Fly is unchanged.

Decided in v0.5 (CLI UX pass 2, H4/H5): `status` and `plan` share one TARGET vocabulary on every provider: `new`, `same`, `changed`, `unknown` (Fly: the value cannot be compared; this replaces "potentially changed"), `pending`, `held`, `extra` (on the target, not desired here), `drift` and `n/a` (config, or skipped and absent). Problem rows (missing, wrong kind, failed) are listed first, each with its full reason and a link to its 1Password item (H1). `opv help states` defines each word. The FR-21 JSON `state` and `target` values are unchanged; the document gains `changes` (`none`/`some`/`unknown`) and `open_url` on blocking rows.

## FR-6 — Fly Synchronization

The CLI shall provide:

```bash
opv fly sync <environment>
```

Since v0.4 the command is `opv sync <environment>` (FR-28); the `fly` form is removed (also for `--deploy`, FR-7).

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

Automation commands require explicit flags for confirmation and never fall back to prompts. The owner-only `setup` and `session` commands are explicit interactive entry points: they require a terminal, refuse CI and service-account/Connect authentication, and do not deploy or prune.

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
| 3 | dependency (`op` or `flyctl` missing or unusable, including a Windows `op.exe` used for `run` under WSL) |
| 4 | source (1Password) |
| 5 | target (Fly) |
| 6 | policy: refused (blocking keys, a refused value, a denied destructive operation) |
| 7 | authentication (1Password or Fly) |
| 8 | findings (`status`, `plan` or `check` found blocking keys) |

`run` exits with the child's own exit code. A closed stdout (`status | head`) does not change the result.

## FR-11 — Dry-Run Safety

Planning commands shall not mutate 1Password or Fly.

No read-only operation shall write metadata such as "last synchronized at" back to 1Password.

## FR-12 — Extensible Source/Target Model

The internal design shall permit future sources and targets without coupling core synchronization logic to 1Password or Fly.

Decided in v0.3 (2026-10-08): the target side is two ports, `SecretStore` and `Runtime` (FR-28). A target is one of each; Fly implements both. The design and its argument are in `docs/design/multi-cloud-targets.md`.

Possible future targets include:

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

Since v0.2: `init` (FR-23) looks a vault and an item up by title once, at dev time, to write their IDs into `secrets.toml`. The exception is limited to the `init` command: title lookup must be unreachable from `fly sync`, `status`, `fly plan`, `run` and `config export` (and `explain`, which reads only the configuration).

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
- named transforms with a fixed output format (for example a SigNoz ingestion header). v0.1.0 ships `transform = "signoz_ingestion_header"`; since v0.2, it is replaced by the generic `ensure_prefix` and `pattern` rules, with the old name kept as a deprecated alias for one release (FR-24). Removed in 0.4.0. v0.1.1 adds `transform = "pem_private_key"`, which stays: it validates and normalises a standard format (any PEM private key), not one vendor's convention.

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

Decided in v0.5 (H1, H11): target words follow the shared vocabulary under FR-5's plan decisions; each missing or failing row also prints `open:` with 1Password's private item link (account UUID and sign-in host from `op whoami`, vault and item IDs; never a value) and the section and field to fix, and `opv open <[product/]KEY>` opens it. `opv status` without an environment reads every environment, run-only ones included (one item read each, FR-13), and takes `--product`, `OPV_PRODUCT` and `--json`. With `$GITHUB_STEP_SUMMARY` set, `status`, `plan` and `sync` append a names-and-states Markdown summary (H8; no value, reason or link).

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

It creates or completes the environment's item: every declared section and field, with the right type and empty value, without changing existing values. This noninteractive command writes empty fields and needs a write-capable identity; owner-guided `setup` is the separate explicitly interactive write path described in FR-9 and SR-5; `fly sync`, `plan`, `status` and `config export` stay read-only.

## v0.2 ergonomics (FR-20 to FR-25)

The requirements below shipped in v0.2.0. They make opv usable by a single-app adopter and easier to start with, without weakening any FR or SR above. The owner adopted them on 2026-10-07. Rejected and deferred proposals are listed in §8 under "v0.2 scope".

## FR-20 — Simple Profile

The CLI shall accept `profile.kind = "simple"`, a flat key map for one app per environment with no products:

```toml
[profile]
kind = "simple"

[environments.prod]
vault_id = "…"
item_id  = "…"
fly.app  = "myapp-production"

[keys.DATABASE_URL]
kind = "secret"
environments = ["prod"]

[keys.JWT_KEY]
kind = "secret"
environments = ["prod"]
immutable = true
rules = { base64_bytes = 32 }
```

The 1Password field name is the Fly name: `[keys.JWT_KEY]` reads field `JWT_KEY` of the environment's item and stages it as `JWT_KEY`. There is no naming template and no `[products]` table; a file that mixes `[keys]` and `[products]`, or sets `fly.secret_name` under the simple profile, is a configuration error. Per-key kind, rules, guidance and `immutable` work as in the fleet profile (FR-14 to FR-16). `run <environment> -- <command>` takes no `--product`. Fleet stays as it is (§10.2).

Acceptance:

- The managed set is exactly the declared keys. Prune scope is the declared keys that are not desired in this environment (FR-8); prune never touches an undeclared name on the Fly app.
- `fly sync`, `fly plan` and `status` read one whole item per environment, by vault ID and item ID (FR-13); the request budget of §8.11 applies.
- The same key name declared twice, or a key name that does not match `^[A-Z][A-Z0-9_]*$`, is a configuration error.
- Every command behaves the same for a fleet file as in v0.1.0.

Constraints kept: FR-8, FR-13, SR-1, SR-3, SR-6. No new 1Password or Fly call path.

Decisions (implementation):

- Simple keys are unsectioned item fields: a field with no section, or a section without a label. Under the simple profile, sectioned fields, built-in fields (with a `purpose`) and fields whose label cannot be a key name are ignored; an unsectioned key-named field of another type is an error (FR-14). `item skeleton` adds missing keys as top-level fields. `run` references them as `op://<vault_id>/<item_id>/<KEY>`.
- Two environments may not share a Fly app under the simple profile: both would manage the same names (FR-8).
- Environment `modes` are flat (`modes.payments = "test"`).
- Output never shows a product: no PRODUCT column in `status` and `fly plan` tables, `"product": null` in their `--json` rows, extras and held entries (FR-21), the bare `KEY` in messages, `--rotate KEY` and `--prune-immutable KEY`, and a flat `{"KEY": "value"}` from `config export`.

## FR-21 — Machine-Readable Status and Plan

The CLI shall accept `--json` on `status` and `fly plan`:

```bash
opv status <environment> --json
opv fly plan <environment> --json
```

stdout carries one JSON document with a top-level integer `schema_version` (1 in v0.2). Adding a field keeps the version; renaming or removing a field, or changing its meaning, increments it. The document is meant for the scheduled drift check (FR-17).

Acceptance:

- The document contains names, states and counts only (value lengths are metadata about values, and guidance belongs in `explain`, FR-22): environment, product and key names, kind, row state (saved, missing, extra, wrong kind, failing rule, held, present, absent, would stage, would prune), the name of a failing rule, Fly names, and totals. It contains no value, no value fragment, no value length and no guidance text.
- Exit codes are unchanged (FR-10): with blocking findings the command still exits 8, and an error still exits with its category. An error before the document is produced is reported on stderr as text; stdout then carries no partial document.
- Without `--json` the human output is unchanged.

Constraints kept: SR-1, SR-2, FR-10, FR-11 (both commands stay read-only), §6.8.

## FR-22 — Next Step and Explain

`doctor` shall end with one "Next step" line that names the first failing check and the exact safe command that addresses it (for example `opv item skeleton staging`, or the existing re-run hint), or says that nothing is pending. It is text, never a prompt (FR-9).

The CLI shall provide:

```bash
opv explain <product>/<key> [--env <environment>]
```

(`opv explain <key>` under the simple profile.) `--env` may be omitted when the configuration declares exactly one environment. For each environment the key is declared for, or only the one named by `--env`, it prints the `op://` reference, the field kind, the Fly name, the declared rules, `immutable`, and `guidance`, plus the `op` command a person can run to inspect the field in their own terminal: `op item get <item_id> --vault <vault_id>`, without `--reveal`.

Acceptance:

- `explain` never emits a value or a value fragment, including length, prefix or position. It reads only the configuration; it makes no 1Password or Fly call.
- The printed `op` command never contains `--reveal`.
- An undeclared key, product or environment is a configuration error (exit 2).
- `explain` is not a `secret get` (§5).

Constraints kept: SR-1, SR-2, §5 (no command prints secret values), FR-9, FR-11.

### Failure reasons

A rule failure (FR-15) shall also carry a **reason**: one string from a fixed, closed set defined
per rule in code, describing the value's shape and never its content. `status`, `fly plan`,
`fly sync` and `--json` (FR-21) print it after the rule name, for example
`journeeze/GITHUB_APP_PRIVATE_KEY: failed transform (BEGIN/END labels differ)`. For
`pem_private_key` the set is: `no BEGIN/END markers`, `BEGIN/END labels differ`,
`not a private key`, `encrypted key`, `more than one PEM block`, `body is not base64`,
`not a key structure`. Other rules get reasons where useful (for example `prefix`:
`wrong prefix for mode <mode>`, naming the expected prefix from the configuration and never the
actual one).

Acceptance:

- Every reason is a compile-time constant or is built only from configuration, never from the value.
  A test feeds marker values through every failure path and asserts no marker byte appears in
  any output.
- No reason includes a length, a position, a character, an actual prefix or a label read from
  the value.
- The rule name stays the stable identifier: a reason may be added or reworded in a minor release;
  `--json` carries it as a separate `reason` field next to `rule`.

## FR-23 — Init

The CLI shall provide:

```bash
opv init <environment> --vault <name> --item <name> --fly-app <app> [--profile simple|fleet] [--force]
```

It is a dev-time helper that writes a starter `secrets.toml`. It resolves the vault and item titles to IDs (exact title match; zero or several matches is an error), reads the item once, and writes the configuration: the environment with `vault_id`, `item_id` and `fly.app`, and one declared key per field, with its kind taken from the field type (concealed = secret, text = config, FR-14). A sectioned item produces a fleet file (section = product, with the default template `FLEET__{PRODUCT}__{KEY}`); an unsectioned item produces a simple file (FR-20), whose fields are unsectioned. `--profile simple|fleet` overrides this detection. Without `--profile`, an item that mixes sectioned and unsectioned fields is an error that names both shapes; `init` never guesses. Rules and guidance are left for the person to add.

`init` is the second 1Password-adjacent command after `item skeleton` (FR-19), and unlike it, it is read-only against 1Password.

Acceptance:

- Titles are resolved to IDs at dev time only. The FR-13 exception is limited to the `init` command: title lookup is unreachable from `fly sync`, `status`, `fly plan`, `run` and `config export`, and from the CI read path, which stay by vault ID and item ID (FR-13).
- `init` reads the item but writes only names and kinds. Values are never deserialized into opv types (the field struct has no `value` member; the raw `op` output stays in a zeroizing buffer, SR-2, SR-8), and no value reaches disk or output (SR-1, SR-4).
- If the target file exists, `init` refuses (exit 2) unless `--force` is given. It never merges into an existing file.
- `init` writes nothing to 1Password (FR-11, SR-5).
- `--fly-app`, the IDs and the field names are validated as for a hand-written file (§10.2), and the generated text is checked with the same loader before it is written. A field whose label is not a valid key name, a section whose label is not a valid product name, and a field of another type are skipped with a note that names them; nothing is ever renamed (ruling, v0.2: skipped with a note rather than failing the whole file, so one stray field does not block init).

Constraints kept: FR-11, FR-13, SR-1, SR-2, SR-3, SR-4, SR-5, SR-7.

## FR-24 — Generic Prefix Normalisation

The rule set (FR-15) shall gain:

- `ensure_prefix = "<p>"`: accepts a value with or without the prefix `<p>` and stages it with exactly one `<p>`;
- `pattern = "<regex>"` (optional, only with `ensure_prefix`): the part after the prefix must fully match the regex; a value that is only the prefix fails.

They replace `transform = "signoz_ingestion_header"`, which becomes a deprecated alias for one release (v0.2) with identical behaviour: it is equivalent to `ensure_prefix = "signoz-ingestion-key="` with `pattern = "[A-Za-z0-9._~+/-]+={0,2}"`. Identical behaviour includes the failure rule name: a value refused through the alias fails as `transform`, as in v0.1.0. Using the alias prints a deprecation warning naming the key, not the value. Removed in 0.4.0. The infra catalog's OTEL entries migrate to the new rules.

Acceptance:

- For every input, the alias and its `ensure_prefix` + `pattern` equivalent accept and refuse the same values and stage the same output.
- A failure names the key and the rule, never the value: the new rules fail as `ensure_prefix` or `pattern`, the alias as `transform`.
- The staged value is built at its final size (SR-8). After the alias is removed, the only named transform left is `pem_private_key` (a standard format, not a vendor convention).

Constraints kept: FR-15 (generic, data-driven; no product-specific code), SR-1, SR-8.

## FR-25 — Config Discovery

When `--config` is not given, the CLI shall look for `secrets.toml` in the current directory and then in each parent directory, and use the first one found.

Acceptance:

- The resolved path is always printed on stderr, whether found by discovery or given with `--config`.
- `--config <path>` overrides discovery; no search is done.
- Files are never merged; a `secrets.toml` further up is ignored once one is found.
- No file found is a configuration error (exit 2) naming the directory the search started from.

Constraints kept: FR-1, FR-2, FR-9. stdout is unchanged, so `config export --json` and FR-21 output stay parseable.

---

## v0.3 multi-cloud targets (FR-28 to FR-33)

The requirements below add Azure, AWS and GCP as targets without weakening any FR or SR above. The owner adopted them on 2026-10-08 after an FMECA review. They are delivered in phases (P0 to P4, issues #38 to #42); deferred items are listed in §8 under "v0.3 scope". Design: `docs/design/multi-cloud-targets.md`.

## FR-28 — Targets, Ports and Routing

A target is one secret store plus one runtime:

| Cloud | Store | Runtimes |
|---|---|---|
| Fly | Fly secrets | Fly app (one adapter for both) |
| Azure | Key Vault | Container Apps, App Service |
| AWS | Secrets Manager | ECS |
| GCP | Secret Manager | Cloud Run (which covers Cloud Run functions) |

- Core logic reaches targets only through the `SecretStore` and `Runtime` ports (FR-12). `app/` and `domain/` name no target.
- Each environment declares at most one target section: `fly`, `azure`, `aws` or `gcp`. Existing `fly` sections are unchanged.
- **Routing by kind (FR-14).** A secret (concealed field) is written to the store and bound on the runtime as a reference. Config (text field) is set as a plain runtime env var, unless the environment sets `config = "store"`, which routes config like secrets. Routing a secret to plain env is not expressible. On Fly, config is not synced, as since v0.1; consumers read it with `config export`.
- `opv plan <env>` and `opv sync <env>` work for every target. `opv fly plan` and `opv fly sync` remain as aliases that print a deprecation warning for one minor release and are then removed. Removed in 0.4.0.

## FR-29 — Pinned References

Every secret reference on a cloud runtime binds an explicit store version (Key Vault versioned URI, ECS `valueFrom` ARN with a version id, Cloud Run `secret:N`, App Service versioned `SecretUri`), never "latest".

- A store write is the staging step: the running app does not see it, even on restart or scale-out.
- Rebinding to the new version, and setting config env values, is the deploy step and happens only with `--deploy` (FR-7, FR-9).
- `status` reports, per key: store value current, binding current, pending deploy, and drift (a binding to a version opv did not write). Drift is overwritten only with `--deploy`.

## FR-30 — Store Naming and Limits

- The env name comes from the naming template (fleet) or the field name (simple). Each store maps it to a store name with a fixed rule (Key Vault: `_` becomes `-`; Secrets Manager: `secret_prefix` plus the name; Secret Manager: unchanged; Kubernetes: lower case, `_` becomes `-`) and validates it when the configuration loads, first and last characters included (a Kubernetes name cannot end in `-`, so a key ending in `_` is refused at load with the key and its line, never at sync).
- Two keys that map to one store name are a configuration error naming both keys.
- Each store and runtime declares its value-size limits. They are checked with the rules, before any call, and a failure names the key and the limit, never the value (FR-15).

## FR-31 — Compare Before Write; Read-Modify-Write on Runtimes

- Before writing a secret, opv reads the store's current value into a redacting type and compares it in constant time. It writes only when the value differs or is missing, so an unchanged run creates no store version and reports no change.
- A runtime change reads the current service spec, changes only managed names, and sends the whole spec on stdin. Config values are never in argv (SR-3).
- The unmanaged part of the spec is fingerprinted before and after the write, and the platform's optimistic concurrency is used where it exists. A concurrent change fails with the changed paths (never values) and a "safe to re-run" exit.
- On Azure and AWS, values travel through `/dev/stdin`. On native Windows those writes fail closed with a typed error naming WSL; reads, `plan` and `status` work everywhere.

## FR-32 — Cloud Prune Order and Ownership

- `--prune` without `--deploy` only reports on cloud targets.
- With `--deploy`, opv unbinds the names on the runtime, waits for a healthy revision, then deletes them from the store. A store entry is never deleted while a running revision references it.
- After a healthy revision, superseded versions of every pinned name are collected where versions are separate objects (Kubernetes: version Secrets labelled `opv-managed=<env>` that neither the Deployment nor any ReplicaSet references); Key Vault keeps them as history. Every name is collected on every `--deploy` run, so an interrupted run's leftovers go on the next one (NR-1).
- opv tags every store entry it creates with `opv-managed=<environment>` and refuses to delete one without that tag. The declared-set rule of FR-8 still applies.
- A soft-deleted name (Key Vault soft delete, AWS recovery window) that blocks a re-create fails with the exact recover command. opv never recovers or purges by itself.

## FR-33 — Runtime Access and Health

- Before a cloud deploy, opv checks that the runtime identity (Container Apps or App Service managed identity, ECS execution role, Cloud Run service account) can read every referenced store entry. A missing grant blocks the deploy and names the identity and the entry.
- After a deploy, opv waits for the new revision to report healthy or failed and reports the outcome with its exit category.
- `doctor` checks the cloud CLI and login, store access on managed names, and runtime-identity access, and reports an identity that can read untagged secrets as broader than needed (SR-5).

## FR-37 — Pluggable Providers

Every deployment provider implements one plug-in contract (`docs/design/multi-cloud-targets.md`
§11): config section parsing, name mapping and limits, ports, preflight, doctor and explain. Core
modules (`app/`, `domain/`, `config.rs`) never name a provider; a guard test enforces it. Adding a
provider changes no core code. Owner decision 2026-10-08.

## FR-38 — Kubernetes Target

`[environments.<env>.kubernetes]` targets a Deployment through `kubectl` with explicit
`--context` and `--namespace`. Values are stored as immutable Secrets named
`opv-<store name>-<random id>` (the id is the version, FR-29), bound through `secretKeyRef`. The id
comes from the OS RNG and is never derived from the value: a content-hash name would let anyone
who can list Secrets confirm a guessed value, so no name, label or annotation carries anything
value-derived (SR-1, SR-2). Compare-before-write reads the bound value and compares it in
constant time; an unchanged value writes nothing, and a version orphaned by a lost write is
collected after the next healthy rollout (NR-1); the Deployment is updated with its
`resourceVersion` (optimistic concurrency, FR-31); health is the rollout status (FR-33); old
Secrets are pruned only after a successful rollout (FR-32). Design: §12 of the multi-cloud design.

## FR-39 — Named Stores and Cross-Provider Bindings

Stores can be declared once as `[stores.<name>]` and referenced by a runtime with
`secrets_in = "<name>"`; without it, a runtime uses its own store. A binding registry lists the
supported (store kind, runtime) pairs; an unsupported pair is a config error at load. 0.5.0 adds
Key Vault → Kubernetes Deployment through the External Secrets Operator, with versions pinned
(`refreshInterval: 0`, `remoteRef.version`), readiness checked before the Deployment is repinned,
and prune only after a healthy rollout. Commands are unchanged. Design: §13 of the multi-cloud
design. Owner decision 2026-10-08.

## v0.4 local development (FR-34 to FR-36)

The requirements below make opv usable for local development without a deployment target, from issues #52, #53 and #54 found while adopting opv across products. The owner adopted them on 2026-10-08. Live account validation stays an owner-run receipt on those issues; automated tests use synthetic values and fake CLIs.

## FR-34 — Local Check

```bash
opv check <environment> [--product <product>] [--json]
```

- Reads the environment's item once, by IDs (FR-13), and reports each selected key as saved, missing, wrong kind, failing a rule or skipped, by name only (SR-1). Exit 8 when any key blocks (FR-10).
- Never lists, stages or deploys on a target, even when the environment has one; `--json` carries `target_checked: false`.
- With `--product`, fields in other products' sections are skipped before they are validated, so they can neither block nor fail the check.
- `--product` is required under the fleet profile and refused under the simple profile.

## FR-35 — Managed-Key Isolation in `run`

- Before starting `op run`, `run` removes from the inherited environment every key name declared in the loaded configuration (all products, all environments, mode-skipped keys included), then adds only the selected product's applicable references. Switching products in one shell never carries another product's managed key into the child.
- PATH, shell and tool context, 1Password authentication and undeclared variables stay inherited: this is managed-key isolation, not a sandbox.
- Key names that are the 1Password CLI's own environment (`PATH`, `HOME`, `XDG_CONFIG_HOME` and `OP_*`) are refused at configuration load, because removing them would break `op`.
- A runner that cannot remove variables fails closed (exit 3) instead of starting the child with stale values.

## FR-36 — Local-Only Onboarding and Diagnostics

- `opv init` without `--fly-app` writes a run-only environment (vault and item IDs only); deployment `init` is unchanged.
- On Linux and macOS, `doctor` reports `op local run`: the first `op` on PATH must be a native binary, because a Windows `op.exe` reached from WSL cannot start a Linux child. It fails a scope of environments without a target and warns otherwise, always with the remaining checks and a `Next step` line. `run` refuses such an `op` before starting anything (exit 3).
- Supported: `op` 2.40.0 or newer; WSL 2 with the Linux `op` and its own sign-in; native Linux, macOS and Windows. Automatic Windows desktop-to-Linux execution is not provided.

# 4. Security Requirements

## FR-26 — Diagnose and Guide

When opv cannot finish, it shall say **what is wrong and the exact next command for this platform**,
instead of pointing at a tool to re-run. Each case below was hit during the first fleet
rollout (2026-10-07); each has a test.

| Situation | Detection (no value is read) | Message and exit |
|---|---|---|
| 1Password session expired or never started | after any failed `op` call, run `op whoami` (free under rate limits, D0) | "not signed in to 1Password", then the sign-in command for the detected shell (bash/zsh: `eval $(op signin)`; PowerShell: `Invoke-Expression $(op signin)`), or "set OP_SERVICE_ACCOUNT_TOKEN" under CI; exit 7 (auth), not 4 |
| No 1Password account on this machine (fresh WSL or Linux) | `op account list --format json` is empty | `op account add --address <sign-in address> --email <email>`, then sign in; "type the Secret Key and password only at op's prompts, never into chat, tickets or files"; exit 7 |
| Signed in, but the item or vault is not visible to this identity | `op whoami` succeeds and the item read fails | names the vault and item IDs and the identity type (user or service account, never the identity itself) and says to grant that identity access to the vault; exit 4 |
| `op` or `flyctl` missing or untested version | existing `doctor` checks | the install command for the detected OS |
| A value fails its rule | FR-22 reasons | the reason plus the key's `guidance` |
| Clean run | n/a | a summary line: `N saved, M not yet on <target> (staged by the next sync), 0 findings` |

Acceptance:

- No failure message tells the user to run another tool "to see why" when opv can find out
  itself without reading a value.
- Every remediation string is covered by a test per detected platform (Linux, WSL, macOS,
  Windows PowerShell, CI), and each suggested command is checked to be the correct syntax
  for that shell.
- Remediation text never asks for a secret to be pasted anywhere but the owning tool's own prompt.
- Detection makes no extra 1Password item reads (FR-13). `op whoami` and `op account list`
  have no rate-limit cost.

Constraints kept: SR-1, SR-2, FR-9 (text, never a prompt), FR-10 (stable exit categories), FR-13.

Limitation (v0.1.2): an `op` timeout and `opv run` (which passes the child's exit code through, FR-4) are not diagnosed.

## FR-27 — Install and Update Script

The repository shall ship `install.sh`, a POSIX `sh` script that installs or updates opv from
GitHub releases without npm, Homebrew or Rust:

```bash
curl -fsSL https://raw.githubusercontent.com/matt-cochran/1password-vault/main/install.sh | sh
sh install.sh [--version vX.Y.Z] [--dir <path>] [--check]
```

- **Platform detection:** `uname -s` and `uname -m` select the release asset: Linux `x86_64` /
  `aarch64` (`arm64`) → the static `*-unknown-linux-musl` binaries (this covers WSL); macOS
  `x86_64` / `arm64` → `*-apple-darwin`. On macOS, a shell running under Rosetta
  (`sysctl -n sysctl.proc_translated` = 1) gets the `arm64` binary. Anything else fails with
  the platform it detected and a link to the releases page; it never guesses. Windows is out
  of scope for `install.sh`: use the release `.exe` (or npm from v0.2.0).
- **Version:** the latest release by default, or exactly `--version`. A requested version
  that has no asset for this platform fails naming both.
- **Update:** when opv is already installed in the target directory, the script compares
  `opv --version` with the target version. It replaces the binary only when they differ,
  and prints `opv <old> → <new>`, or `opv <version> is already installed`. `--check` reports
  what would happen and changes nothing.
- **Integrity:** the binary is verified against the release's `SHA256SUMS` before anything is
  installed. When `gh` is available, it additionally runs
  `gh attestation verify <file> --repo matt-cochran/1password-vault` and fails on a mismatch.
  A checksum mismatch, or a missing `sha256sum`/`shasum`, fails closed.
- **Placement:** the default directory is `~/.local/bin`, with no `sudo`. The binary is
  downloaded to a temporary file in the target directory and moved into place only after
  verification, so an interrupted run never leaves a broken `opv`. If the directory is not
  on `PATH`, the script prints the line to add.
- It handles no secrets and never reads 1Password. Its output names versions and paths only.

Acceptance:

- A test matrix (CI, with fake `uname` and a local fixture release) covers each supported
  platform/architecture pair, Rosetta, unsupported platforms, latest versus a pinned version,
  update versus already current, `--check`, and checksum mismatch (fails, leaves any existing
  binary untouched).
- `shellcheck` passes, and the script runs under `dash` and `bash`.

## SR-1 — No Secret Logging

Secret values shall never appear in:

- normal logs;
- debug logs;
- error messages;
- tracing output;
- panic output generated by project code.

Debug logging shall redact conservatively.

Child output: the stderr of every captured `op`, `flyctl`, `az` and `kubectl` call is held in memory only (never on disk) and shown only after the scrubber of NR-31 has masked secret values: at most 5 lines under the error of the call that failed, or every call's lines with `--verbose`. A child's stdout and anything opv sends on stdin (values, Kubernetes Secret manifests) are never shown; `--verbose` gives only stdout's size and JSON shape (NR-31).

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
- the minimum Fly permissions required to manage secrets for the target application;
- on cloud targets, read and write on the opv-tagged store entries and update on the one runtime service. Read is needed for compare-before-write (FR-31); it adds no exposure, because the same values are readable through the CI 1Password token.

The CLI shall not require write access to 1Password for synchronization. Owner-guided `setup` may create a Secure Note or fill only missing declared fields after a concrete save confirmation. It preserves existing filled values and uses JSON stdin, never secret arguments or files. This write exception does not apply to synchronization or CI.

## SR-6 — Explicit Destructive Operations

Secret deletion shall require explicit user intent.

The CLI shall never infer that every secret present on a target but absent from configuration should be deleted.

## SR-7 — Shell Avoidance

The implementation shall not execute user-generated shell command strings.

Subprocesses shall use structured argument invocation via `std::process::Command` or `tokio::process::Command`.

## SR-8 — Memory Hygiene

Secret buffers should be zeroized when practical.

Copies of secret values should be minimized.

Security-sensitive dependencies should be kept small and audited.

# 4a. Resilience Requirements (NR-1 to NR-31)

Every realistic failure is a requirement (owner direction, 2026-10-08): designed for
resiliency, transparency, and to keep the user effective. The argument, mechanisms and tests
are in `docs/design/resilience.md`; each NR below is normative.

- **NR-1 Convergence.** Every command is safe to interrupt after any external call; re-running it reaches the same end state, and no intermediate state leaves a live reference to a missing or half-written value. Proven by an interruption-matrix test per flow.
- **NR-2 Unknown outcomes.** A write that fails, times out or is killed has an unknown outcome; opv reconciles by reading the state back before reporting. When it stays unknown, opv exits **9** ("outcome unknown; safe to re-run"), naming the step and the reconciled state. Extends FR-10.
- **NR-3 Bounded read retry.** Reads (never writes) are retried up to 3 attempts with jittered backoff (1 s, 2 s, 4 s) inside the run budget; a definite refusal (not found, auth) is never retried. The runner's API makes write-retry unrepresentable. Since v0.5 (UX review P16) the 1Password item read is diagnosed after its first failed attempt (`op whoami`, then `op vault get <vault_id>`) and retried only when the identity is signed in and can open the vault; otherwise the diagnosis is reported at once.
- **NR-4 Deadlines and progress.** Per-effect deadlines (probe 15 s, read 60 s, write 120 s; waits poll with their own deadline) and a run budget `--timeout` (default 900 s). Any wait prints progress on stderr at least every 15 s.
- **NR-5 Output cap.** Captured CLI output over 8 MiB is refused and the child killed.
- **NR-6 Validated outputs.** Every id, version and name read from a CLI is validated before reuse in argv or a document; unknown fields are ignored, missing required fields refused.
- **NR-7 Explicit scope, pinned environment.** Every call names its scope explicitly (Fly `--app`, Azure `--subscription` from the now-required `azure.subscription`, 1Password IDs) and runs with an environment that neutralises behaviour-changing user config and prompts.
- **NR-8 Detect, don't lock.** Concurrent edits and overlapping runs are detected (ownership tags, fingerprints, A/B compare, drift) and reported; opv takes no remote locks.
- **NR-9 Fewest calls.** One list per store, reads only for ready keys, writes only on difference, deploy only on change; `--json` reports calls per program and duration.
- **NR-10 Auth expiry.** Sign-in is probed before the first write; an auth failure after writes began is reported as such with the sign-in command and "re-run".
- **NR-11 No prompts.** No captured call can wait on a prompt (no TTY stdin, prompt-disabling env, no dynamic extension install); a would-be prompt surfaces as a timeout naming the sign-in fix.
- **NR-12 Signals.** SIGINT/SIGTERM are forwarded to the running child, which gets 5 s before it is killed; opv exits 130/143 naming the last completed step.
- **NR-13 Version drift.** `doctor` checks minimum versions of op, flyctl and az; adapter tests use recorded real outputs.
- **NR-14 OS differences.** Platform capabilities (stdin device, native op) are checked up front; value bytes are never re-encoded.
- **NR-15 Value edge cases.** Byte-exact round trip per adapter; values a target would mangle are refused before any call (FR-15, FR-22).
- **NR-16 Scale.** At most O(keys) calls; output starts with a one-line count summary (rows kept as they are, PR #63); `--product` scoping on status, plan and sync.
- **NR-17 All blockers at once.** A refusal names every blocking key and its next command in one run.
- **NR-18 Run summary.** Every mutating run ends with one summary (written, deployed, pruned, pending, unchanged, skipped, next step), mirrored in `--json`, consistent with the exit code.
- **NR-19 Next step on every error.** Every non-zero exit ends with exactly one `Next:` line holding a runnable command (extends FR-22), the last line on stderr; `run` passes its child's exit code through and is exempt. Every error carries an optional next step; one without falls back to its category's (the install or sign-in line for dependency and authentication, the same command for outcome unknown, `opv doctor` otherwise). Tested by error category and by CLI exit path.
- **NR-20 Guarded destruction.** Destructive flags stay explicit (SR-6); `--prune` lists names before acting (`will prune: <names>`); an environment with `confirm_env = true` requires `--confirm <env>` for `sync`, the only command that changes the target (`item skeleton` writes to 1Password and is exempt); a refusal is exit 6 before any call, with the exact command to re-run.
- **NR-21 No clock assumptions.** No decision compares wall-clock times across machines; deadlines use monotonic local time.
- **NR-22 Safe diagnostics.** `--verbose` adds program, argv, duration and outcome per call, followed by that call's scrubbed stderr and its stdout shape (NR-31). Child stderr is shown only scrubbed, stdout and stdin content never (SR-1).
- **NR-23 Preflight before the first write.** Mutating commands check every needed CLI, sign-in, provider reachability and target state read-only first; any failure stops the run with nothing written. The plan's own reads (the item read by IDs, the target's first list) are the CLI, sign-in and reachability checks, so preflight adds no second item read; tool versions stay with `doctor` (NR-13).
- **NR-24 Fly state.** Deleted (`dead`) apps are refused with the reason and next step. A deploy in progress is waited for (releases re-read every 5 s, a progress line at least every 15 s, within the run budget and at most 10 minutes) and refused with nothing written only if it is still running then. Suspended or pending apps (on the Machines platform: no machines), missing machines and stopped machines are a `warn` line; secrets are app-level so they still stage, and `--deploy` is skipped with `deploy skipped: <app> has no machines; staged secrets apply when machines start` (exit 0). `Partial` deploys are detected and reported with the exact command. Fixtures are recorded flyctl output (`tests/fixtures/fly/`).
- **NR-25 Azure state.** Soft-deleted or firewalled vaults, RBAC propagation delay (bounded wait with progress), resource locks, app provisioning in progress or failed, and revision mode are detected and handled or reported. Preflight has a mode: read commands (`status`, `plan`, `doctor`) run the same checks but never wait on an update in progress (provisioning `InProgress`, or any provider's equivalent); they print one note line on stderr and continue. Only `sync` waits, with progress, bounded by the run budget.
- **NR-26 1Password state.** Moved, archived or deleted items, removed vault access, rate limits and a locked desktop app are diagnosed by ID with the next command; never a title fallback (FR-13).
- **NR-27 Missing dependencies.** Each needed CLI is resolved once in preflight with the OS-specific install command; only the CLIs the chosen environment needs are required (FR-36).
- **NR-28 Provider outage.** Reads exhausted before any write ⇒ exit 9 "provider unavailable", naming the provider, the step and its status page; nothing written. Applies to every read before a write, `status` and `plan` included.
- **NR-29 Network glitches and proxies.** Covered by NR-3/NR-2; proxy and CA environment variables pass through to CLIs untouched.
- **NR-30 Eventual consistency.** After a write, the confirming read polls until it observes the written version or the deadline; a stale read is never reported as "unchanged".
- **NR-31 CLI output transparency.** Every failure shows what the CLI said, without leaking a secret. (1) Capture: the stderr of every captured call of every provider (`op`, `flyctl`, `az`, `kubectl`; reads, writes and probes) is read into a bounded, zeroized in-memory buffer (the last 64 KiB) and never written to disk; interactive calls (`run`, `setup`, `session`) keep the terminal. (2) Scrubbing: before any of it is shown, every registered value is replaced with `__SECRET__`. Registered: all field values of every 1Password item read in the run and every `SecretValue` created (transformed by `ensure_prefix`, staged, read from a target). Each is matched raw, JSON-escaped (plain, ASCII-only `\uXXXX` as az writes it, and Go's form with `<`, `>`, `&` escaped, as kubectl writes it), Go-quoted (`%q`), Python-`repr`-quoted, standard base64 (the form a Kubernetes Secret manifest carries), base64url (padded and unpadded) and percent-encoded. Values under 4 bytes and their encodings are matched as whole tokens only. Then patterns mask secrets opv never handled: JWTs, `Bearer <token>`, `OP_SESSION_*=…`, `ops_…` service-account tokens, Azure `sig=`, `AccountKey=`, `SharedAccessSignature=` and `client_secret=`, PEM private-key blocks (also a block whose BEGIN line was cut off), well-known API key prefixes (`sk-`, `sk_live_`, `ghp_`, `xoxb-`, `AKIA…`), and `password=`, `token=`, `secret=`, `apikey=` assignments in `key=value` or `"key": "value"` form. Names and ids (a Key Vault secret id, a Secret name) stay readable. Escape sequences and control characters are removed and lines cut at 240 characters. The registry holds values in `Zeroizing` memory; its `Debug` shows a count. (3) On failure: when a call fails (a refused read, a write or probe exiting non-zero) and opv exits with a dependency, authentication, source, target or unknown-outcome error, the last ≤5 non-empty scrubbed lines follow the error's first line, labelled `  <program> said: <line>` (`op said:`, `flyctl said:`, `az said:`, `kubectl said:`), before the rest of the error's text and the single `Next:` line, which stays last (NR-19). An excerpt attaches only to the error made from its own call: every call takes a new call id and clears the excerpt when it starts, a failure is stored with its call id, and it is shown only if no later call started before opv exits. The one exception is the read-only diagnosis of that failure (`op whoami`, `op vault get`, `az account show`, `flyctl auth whoami`, kubectl's context and version checks, and the read-back after a failed write): those calls neither clear nor replace the excerpt. Configuration, policy and findings errors never show one. (4) With `--verbose`: each call line is followed by its scrubbed stderr (`    stderr: <line>`, at most 20) and its stdout shape (`    stdout: <n> bytes`, plus the top-level JSON keys or array length). (5) Never shown: stdout content, and what opv sends on stdin (values, Kubernetes Secret manifests, Container App and Deployment bodies). The error's `Display` is unchanged (tests and `--json` too). Limit: a value opv has not read yet (a failure before or during the item read) is masked only by the patterns.

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

Since v0.2 (FR-20 to FR-27), in addition to the above:

```text
opv [--config <path>] status <environment> [--json]
opv [--config <path>] fly plan <environment> [--json]
opv [--config <path>] explain <product>/<key> [--env <environment>]
opv [--config <path>] init <environment> --vault <name> --item <name> --fly-app <app> [--profile simple|fleet] [--force]
opv [--config <path>] run <environment> -- <command>        # simple profile: no --product
```

In v0.2, `--json` is on `status`, `fly plan` and `config export`, and `status` and `fly plan` print text without it. Without `--config`, `secrets.toml` is found by walking up parent directories, and the resolved path is printed on stderr (FR-25). `doctor` ends with a "Next step" line (FR-22). `--verbose` and `--quiet` stay unimplemented.

Since v0.3 (FR-28 to FR-33), in addition to the above:

```text
opv [--config <path>] plan <environment> [--json]
opv [--config <path>] sync <environment> [--deploy] [--prune] [--rotate <product>/<key>] [--prune-immutable <product>/<key>]
```

`plan` and `sync` work for every target. `fly plan` and `fly sync` are deprecated aliases for one minor release. Removed in 0.4.0.

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

Decided in v0.3: the shipped layout keeps the flat `src/app`, `src/domain` and `src/adapters` modules. The target ports are synchronous, take the existing `CommandRunner`, and are `SecretStore` and `Runtime` as specified in FR-28 and the v0.3 design; the `SecretTarget` sketch below is superseded.

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

Version 0.2 is acceptable when, in addition to 1–14:

15. A simple-profile file (FR-20) passes `status`, `fly plan` and `fly sync` against one item per environment, within the request budget of item 11, and `--prune` touches only declared keys.
16. Every fleet file accepted by v0.1.0 behaves the same in v0.2.
17. `status --json` and `fly plan --json` carry `schema_version`, contain no value (checked by a test that plants known values and searches the output), and exit with the same codes as the text output.
18. `opv explain` prints the reference, kind, Fly name, rules and guidance, and an `op item get` command without `--reveal`; it makes no 1Password or Fly call and emits no value or value fragment.
19. `doctor` ends with a "Next step" line naming a safe command, and never prompts.
20. `opv init` writes a `secrets.toml` with IDs, names and kinds only, refuses to overwrite without `--force`, writes nothing to 1Password, and no title lookup is reachable from `fly sync`, `fly plan`, `status` or `config export`.
21. `ensure_prefix` + `pattern` reproduce `transform = "signoz_ingestion_header"` exactly, and the alias still works with a deprecation warning.
22. Without `--config`, `secrets.toml` is found in a parent directory and its path is printed on stderr; `--config` overrides; files are never merged.
23. Items 9 and 10 hold for every new command and flag.
24. Every rule failure carries a reason from its rule's fixed set (FR-22); a marker-value test proves no reason contains any byte of the value, and `pem_private_key` reports each of its seven reasons.
25. Each FR-26 situation, simulated with a fake `op`, prints its platform-specific next command and exits with its category; an expired session reports exit 7 and the sign-in command, never "run op item get to see why".
26. `install.sh` installs, updates and pins versions on Linux (x86_64, aarch64, WSL) and macOS (x86_64, arm64, Rosetta), verifies the checksum before replacing anything, and fails closed on an unknown platform or a mismatch (FR-27).

## v0.2 scope

Rejected or deferred from the 2026-10-07 ergonomics review:

- **Pre-declared sync policy** (deploy or prune by configuration): rejected, because it replaces explicit per-run intent (FR-8, FR-9, SR-6).
- **Rotation epoch** (rotate immutable keys by bumping a counter): rejected, because rotation must stay a per-key explicit act (FR-16, SR-6).
- **Generic target trait** (formal `SecretTarget` for many targets): deferred until a second target is funded. Funded in v0.3 as the `SecretStore` and `Runtime` ports (FR-28).
- **Exact change detection in `fly plan`**: deferred, because Fly digests cannot be computed locally and `plan` must not stage (FR-5, FR-11, §6.4). Backlog: #36.
- **Merging `pattern` into `regex`**: deferred. In v0.2 `pattern` is allowed only alongside `ensure_prefix` and applies to the text after the prefix, which `regex` does not do (FR-24). Backlog: #37.

Version 0.3 is acceptable, per phase, when in addition to 1–26:

27. Every Fly command produces byte-identical `flyctl` argv, stdin and output before and after the move onto the ports (characterization tests), and `app/` and `domain/` reach Fly only through the ports (`init`, which writes a Fly configuration, and `doctor`, which checks the installed vendor CLIs, excepted; `doctor` gains per-adapter checks in P1).
28. `opv plan` and `opv sync` behave as `fly plan` and `fly sync` on Fly targets; the `fly` forms still work and print a deprecation warning.
29. A secret is written to the store and bound by a pinned version reference; a config field is a plain runtime env var, or a store reference with `config = "store"`. No configuration routes a secret to plain env.
30. `sync` without `--deploy` changes nothing the running app can see, including after a restart; `status` reports the pending deploy.
31. A run where 1Password, the store and the bindings already agree writes nothing, deploys nothing and reports no change.
32. Store-name collisions and size-limit violations fail at configuration load or rule check, naming the key, before any cloud call.
33. A runtime change touches only managed names; a concurrent change to the unmanaged part fails with the changed paths and a re-run exit.
34. `--prune --deploy` deletes a store entry only after a healthy revision no longer references it, and refuses an entry without the ownership tag.
35. A missing runtime-identity grant blocks `--deploy` and names the identity and the entry.
36. Items 9 and 10 hold for every adapter, checked by a shared marker-value test that config values never reach argv either.

Version 0.4 is acceptable when, in addition to 1–36 (item 42 supersedes items 21 and 28, which described the deprecated forms):

37. `opv check` reports every selected key by name with no value, makes no target call, ignores other products' sections when `--product` is given, and exits 8 on blocking keys, 3 without `op` and 7 when signed out.
38. `opv run` removes other products' and mode-skipped declared names, keeps PATH and undeclared variables, passes the child's exit status through, and does not leak an outer product's key into a nested run (real child-process tests).
39. A key named `PATH`, `HOME`, `XDG_CONFIG_HOME` or `OP_*` is a configuration error.
40. `opv init` without `--fly-app` writes a run-only environment; with it, output is unchanged.
41. `doctor` reports `op local run` on every run off Windows: a Windows `op.exe` fails a local-only scope and warns otherwise, with every other check and a `Next step` line still printed.
42. `opv fly plan` / `opv fly sync` are removed (usage error, exit 2), and `transform = "signoz_ingestion_header"` is a configuration error naming the key and its replacement.
43. Items 9 and 10 hold for every new command and flag.

## v0.4 scope

- **Removed, as promised:** the `fly plan` / `fly sync` aliases (deprecated in v0.3) and the `signoz_ingestion_header` transform alias (deprecated in v0.2).
- **Owner-run, not automated:** live dogfooding receipts for #52, #53 and #54, with a disposable development item; those issues stay open until recorded.
- **Not provided:** remote credential forwarding (infra #524, zonetico-saas #565) and automatic Windows desktop-to-Linux execution.

## v0.3 scope

Rejected or deferred from the 2026-10-08 multi-cloud review:

- **AWS Lambda runtime**: deferred, because Lambda env vars cannot reference Secrets Manager, so FR-29 cannot hold without app-side code. Backlog: #34.
- **Separate Cloud Run functions adapter**: not needed, because current Cloud Run functions are Cloud Run services; confirmed in P4. Backlog: #35.
- **Value-entropy heuristic** to catch a secret stored as a text field: rejected as unproven and prone to false positives. The 1Password kind is explicit (FR-14) and every plan lists env-routed names.

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

Since v0.2: fleet stays the default profile and is unchanged; every v0.1.0 fleet file keeps working. A second profile, `kind = "simple"` (FR-20), serves one app per environment with a flat `[keys]` map: no products, no template, and the field name is the Fly name. `profile.kind` stays required, so a file always says which profile it uses. Both profiles share the environment table, the rules, the one-item read (FR-13) and the managed-set rule (FR-8).

## 10.3 Coexistence with other automation

Other tools stage names outside the managed set on the same Fly app (database URLs from Terraform state, generated keys). opv must:

- stage with `--stage` semantics and never deploy unless `--deploy` is passed, so one later deploy applies everything staged by every tool;
- never read, compare or prune names outside its managed set.

## 10.4 Local development

Since v0.4: local-only environments, `opv check`, scoped `doctor`, managed-key isolation in `run` and WSL support are specified in FR-34 to FR-36.

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
