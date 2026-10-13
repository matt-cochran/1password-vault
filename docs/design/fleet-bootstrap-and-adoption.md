# Fleet bootstrap and adopting existing settings

Status: designed 2026-10-13 for issues #77 (fresh-account fleet onboarding) and #78 (safe
adoption, import and verification). FR-52 and FR-53 in `docs/design/requirements.md` are
normative. Both build on account discovery (FR-49), the sign-in experience (FR-50), the
readiness receipt (FR-51), shared values (FR-47) and the GitHub target (FR-46).

## 1. `opv bootstrap` (FR-52, #77)

One owner command takes a fleet configuration from "declared" to "every environment has its
vault, item, sections and empty fields in the selected account", resumably, then hands over
to the readiness receipt.

```text
$ opv bootstrap
account   owner@example.com (my-team) · selected by .opv
plan
  staging   create vault portfolio-staging, item "portfolio · staging values"
  prod      ok (vault vprd…, item iprd…)
  ci-api    ids belong to another account → stop (see below)
products  allumata 12 keys, journeeze 9, shared 4 (source-only)
Apply? [y/N]
```

- Order, each step idempotent and re-run safe: (1) the account is selected and signed in
  (FR-49/FR-50, never op's default); (2) per environment, the recorded `vault_id`/`item_id`
  are checked **in the selected account** (`op vault get`, `op item get`, names only); (3) a
  missing vault or item is created (`<project>-<env>`, `<project> · <env> values`, as `init`
  does) and its IDs are recorded where the configuration lives (manifest or file, never a
  generated file: see below); (4) `item skeleton` adds every product's section and empty
  fields; (5) the readiness receipt (FR-51) is printed, `--json` included.
- **Stale IDs** (recorded IDs that the selected account cannot see) stop that environment
  with `ids_not_in_account`: it names the account and the environment and offers exactly two
  explicit choices: `opv bootstrap --rebind <env>` (create or find the vault in the selected
  account and record the new IDs; values are not moved) or selecting the account that owns
  them (`opv account use <id>`). opv never falls back to another account.
- **Generated declarations**: a configuration file with a `# generated` header line, or a
  manifest whose notes say so, is never rewritten; bootstrap prints the IDs to record and the
  generator's input to change instead (`ids_for_generator`).
- `--dry-run` prints the plan and changes nothing; `--json` prints the plan or result as one
  document. It never deploys, never syncs and never writes a value.
- CI readers: `opv bootstrap --ci-reader <env>` prints the exact owner command to create a
  read-only service account for that environment's vault
  (`op service-account create <project>-<env>-ci --vault <vault-id>:read_items --expires-in 90d`)
  and how to store its token where CI reads it (a `github` target environment's
  `OP_SERVICE_ACCOUNT_TOKEN`, through `opv sync`, or the CI provider's secret store). opv
  never runs it on the owner's behalf in this version: the token is printed once by
  1Password, to the owner.
- PATH: before recommending an install, bootstrap checks `op` and each target CLI on PATH
  and the known install locations (the same checks as `doctor`), and on WSL says how the
  Windows app integration relates to the Linux CLI (FR-50).

## 2. `opv adopt` (FR-53, #78)

Imports values that already exist elsewhere into the environment's 1Password item, after a
review, so a migration never depends on per-project scripts.

```text
$ opv adopt staging --from .env.staging
staging: 9 keys found · 5 match · 2 to import · 1 format only · 1 differs (needs a decision)
  api/DATABASE_URL     differs        keep 1Password (default) · --replace api/DATABASE_URL
  api/PRIVATE_KEY_PEM  import         (PEM, stored as one line)
  web/LOG_LEVEL        format only    trailing newline; nothing to do
  shared/FLY_API_TOKEN import         one field for 2 products' copies (same value)
  GH_DEPLOY_KEY        not declared   ignored
Next: opv adopt staging --from .env.staging --apply
```

- Sources: `--from <dotenv file>` (owner-run; literal assignments only, the same parser and
  limits as setup's `legacy_env`: never executed, private file, no symlink, ≤ 1 MiB);
  `--from target` reads the environment's target **through its ports** where the target can
  read values back: Key Vault and Kubernetes Secrets (`PinnedStore::read`), GitHub and other
  variable channels (config only). Write-only sources are refused with a plain explanation
  and the manual alternative: Fly secrets (digests only), GitHub secrets (never readable).
- Matching: a found name maps to a declared key by the target's rendered name (env names),
  else by the bare key name; a name that maps to several keys is ambiguous and skipped with
  a finding. A shared key's value lands in its source's field (FR-45/FR-47): one canonical
  field, and copies that equal it produce no extra field; copies that differ are a conflict.
- Comparison applies each key's rules and transforms (FR-15, FR-24, `pem_private_key`) to
  both sides: equal after normalisation → `match` or `format only`; otherwise `differs`.
  Nothing about a value is shown beyond these words.
- Defaults that protect: a non-empty 1Password field is never replaced, and an immutable key
  never, unless the owner names it with `--replace <product/KEY>` (immutable keys also need
  `--rotate`); a replaced value is kept in `opv · kept` like the tidy does (FR-43).
- `--apply` writes in one verified item edit (values on stdin, never argv or a file), then
  re-reads and verifies every imported field by comparing digests in memory; an interrupted
  apply is resumable (re-running recomputes the plan from what was written). It never syncs,
  deploys, prunes, revokes or deletes the source.
- Bound to the environment's account and item (FR-13, FR-40); a source for another
  environment is never inferred. Output (text, JSON, errors, provider failure excerpts)
  holds names, actions and findings only (SR-1, NR-31).
- Owner-run: `--apply` needs a person's own session (it writes 1Password), like the tidy.

## 3. Order

FR-53 (`adopt`) first: it is self-contained and reuses the tidy writer. Then FR-52
(`bootstrap`), which reuses `init`, `item skeleton`, account selection and the receipt.
