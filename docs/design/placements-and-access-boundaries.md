# Placements and access boundaries

Status: draft 4, 2026-10-14. Normative text: FR-56 to FR-60 in `requirements.md`.

- **Greenfield (owner ruling, 2026-10-14):** opv is not live, so nothing here migrates or
  stays backward compatible. One model replaces the old one, and the old code is removed in
  the same change (FR-60).
- **Review:** the FMECA review is in
  [placements-and-access-boundaries-review.md](placements-and-access-boundaries-review.md).
  Its migration findings no longer apply, because nothing migrates (§11).
- **Scope:** answers issue #114 (one product on several apps in one environment) and a new
  issue for per-boundary vaults.

Builds on:
- targets (FR-28, FR-37, FR-48)
- deploy credentials (FR-40)
- the tidy (FR-43)
- shared keys (FR-45) and source-only products (FR-47)
- bootstrap and `opv access` (FR-52)
- the version ledger (FR-54)
- personal keys (FR-55)
- delivery receipts (`delivery-receipts.md`)

## 1. The problem

Two gaps, one on each side of opv:

- **Where values go.** An environment has one deployment target
  (`Environment.target: Option<Box<dyn TargetConfig>>`), so one product cannot run on a
  shared Fly app and also on a dedicated overflow app in the same environment. Forcing it
  makes the second delivery overwrite the first one's evidence:
  - the state item is `opv · delivery · <product>`, looked up by product alone;
  - a receipt file is matched on the first entry for the product;
  - the FR-54 ledger is keyed by the rendered name only.
- **Where values come from.** An environment's values are one item in one vault, with a
  section per product. 1Password grants access per vault, never per item or field. So
  anyone who can open `fleet-prod`, whether a person, a CI reader or a deploy identity, can
  read every product's production values.

## 2. Objectives

Security is a requirement: every S-objective holds in every release.

| # | Security objective (required) |
|---|---|
| S1 | **Environment isolation.** No identity opv creates or recommends can read the values of more than one environment. Development is readable only by developers, and a person's personal values only by that person (FR-55). |
| S2 | **Least privilege per boundary.** Whoever needs product P's values in environment E can be given exactly P's values in E, plus the shared sources P reads, and not product Q's. |
| S3 | **Least privilege per deployment.** A target's deploy identity reads only the values of the products it delivers, and writes only its own delivery evidence. It never writes values. |
| S4 | **One source per value.** Every delivered or run value has exactly one source, stated in the configuration. No fallback, shadowing or precedence decides it at run time. |
| S5 | **Independent evidence per placement.** Delivering P to target A never changes, hides or verifies P's evidence on target B. Account and environment isolation of evidence stays strict. |
| S6 | **Evidence is no wider than values.** Delivery evidence (evidence key, keyed fingerprints, Fly digests) lets its reader test guesses against values. So anyone who can read evidence must be able to read the values it covers. |
| S7 | **Measured where 1Password allows it.** opv reports access wider than the configuration needs wherever 1Password lets it see that access. It never reports "clean" for access it could not inspect. |
| S8 | **No value leaves its path.** As today: no value, digest or fingerprint appears in output, logs, argv, receipts or errors. |

| # | Efficacy objective (aspiration: a very ergonomic API) |
|---|---|
| E1 | **No vault picking.** People name products, environments and targets. opv derives vault and item titles from the convention, creates them and records their IDs. |
| E2 | **One command per intent.** Adding a product and adding a target are one command each. Each is idempotent and resumable, and ends with `Next:`. |
| E3 | **No secret typed twice.** A value lives in one place. Two targets, or two products through `from`, read the same field. |
| E5 | **Visible state.** `opv ui` and `opv ready` show, per product × environment × target, readiness, the source of each value and the missing grants. |
| E6 | **Agent-ready.** Every new command has `--json`, a schema entry, `error.code`, `next` and `human_required`, and is covered by the agent skill and guide. |
| E7 | **Cost grows with the work done**, not with fleet size, and is measured rather than estimated (§8). |
| E8 | **Self-documenting.** Anyone reading output, configuration or a 1Password item can tell what it is and what to do next without opening the docs (§2.1). |

(E4, "existing configurations keep working", was withdrawn by the greenfield ruling.)

Non-goals: opv does not create 1Password groups or service accounts (it prints the owner's
commands), implement release policy, or manage group membership.

### 2.1 Self-documenting rules (E8)

- **People choose names.** opv never invents a name a person later sees. Every target is
  named when it is declared.
- **Configuration explains itself.** Every entry a command writes gets a one-line comment
  saying what it is and which command wrote it.
- **1Password explains itself.** Every vault and item opv creates says in its notes what it
  holds, which configuration owns it, and what not to do by hand.
- **Every finding is a sentence plus a next step.** The sentence names the thing, says who
  acts, and gives the exact `Next:` command. In `--json` the finding carries the FR-51 fields.
- **`opv explain` answers "why".**
  - For a key: its vault and item, its targets, and who can read it.
  - For a target: its products, deploy identity and state vault.
- **Docs ship with the code.** User docs, `opv guide agent`, `opv schema`, the agent skill
  and a runnable example under `examples/` change in the same change as the behavior.

### 2.2 One way only (FR-60)

- One runtime model per concept, and one configuration form per setting.
- No shorthand, alias, deprecated name, legacy reader, fallback or compatibility shim.
- A replaced form is removed in the same change.
- A configuration in a removed form fails at load with a configuration error. The error
  names the line and column and shows the exact current form to write instead.

## 3. Model

Three orthogonal concepts:

| Concept | Answers | Unit |
|---|---|---|
| **Boundary** | who can read a set of values | one vault holding one values item, per environment |
| **Source** | where one key's value lives | exactly one field in one boundary (S4) |
| **Target** | where a set of products is delivered | a named placement in one environment, with its own deploy identity, state vault and evidence |

```text
 boundaries (1Password)                  targets (runtime)
 ─────────────────────                   ─────────────────
 portfolio-shared-prod            ─┐
 portfolio-api-prod               ─┼──►  prod/shared      fly app portfolio-prod
 portfolio-worker-prod            ─┤         api, worker, p
 portfolio-p-prod                 ─┴──►  prod/p-overflow  fly app p-overflow-prod
                                             p only
```

## 4. Boundaries: one vault per access boundary (FR-57)

### 4.1 Layout

| Boundary | Vault | Item | Declared by |
|---|---|---|---|
| product (default) | `<project>-<product>-<env>` | `<project> · <product> · <env> values` | every product |
| project shared | `<project>-shared-<env>` | `<project> · shared · <env> values` | a source-only product (FR-47), conventionally `shared` |
| group (opt-in) | `<project>-<group>-<env>` | `<project> · <group> · <env> values` | `boundary = "<group>"` on each product in the group |

- Inside a boundary item, each product's keys stay in its `<product>` section. The FR-43
  convention, the tidy, `item skeleton`, field labels and evidence `source.field` keep
  their meaning.
- Each values vault holds exactly one opv item. Delivery state, the manifest and deploy
  credentials live elsewhere (§6).
- Environment-level `vault_id`/`item_id` no longer exists.

### 4.2 Configuration

People write products and keys. `opv bootstrap` creates the vaults and items and records
their IDs:

```toml
[environments.prod]
# values vaults, one per boundary; recorded by opv bootstrap
boundaries.api    = { vault_id = "vapi…", item_id = "iapi…" }
boundaries.worker = { vault_id = "vwrk…", item_id = "iwrk…" }
boundaries.p      = { vault_id = "vp…",   item_id = "ip…" }
boundaries.shared = { vault_id = "vshr…", item_id = "ishr…" }

[products.shared]
source_only = true                    # values several products read with `from`

[products.p.keys.OPENAI_API_KEY]
from = "shared/OPENAI_API_KEY"        # the one source (S4)
```

Every product with a key desired in an environment needs a recorded boundary there. One
that has none fails at load with `boundary_missing`, whose next step is `opv bootstrap`.

### 4.3 One source per key, never precedence (FR-45 amended)

- `from = "<product>/<KEY>"` resolves through the existing `KeySpec::source` path to the
  source product's boundary item.
- Each distinct item is read once per command.
- A source the reader cannot open is `source_not_accessible`, naming the boundary and its
  `audience` (FR-55's wording).
- References to another environment stay refused.

Precedence ("the most local value wins") is rejected:
- a missing local value would silently fall back to a broader one;
- anyone with write access to a broader vault could change what a product runs;
- a value's source would depend on what exists, not on the configuration.

A field under a referencing key is reported by FR-45's extra-field finding.

### 4.4 Account-wide sources (later phase)

An account-wide `shared-<env>`, read by every project, waits for a tidy change: today's
implicit tidy on a signed-in read would let one project rewrite another project's fields
(review F14). The prerequisite is that the implicit tidy never writes an item holding
sections no configuration here declares.

## 5. Targets: named placements (FR-56, closes #114)

### 5.1 Configuration

```toml
[environments.prod.targets.shared]
# deploy target; added by opv target add
fly.app = "portfolio-prod"
fly.secret_name = "FLEET__{PRODUCT}__{KEY}"
deploy_credentials = "op://infra-prod/fly-deploy-shared"
state_vault_id = "vst1…"              # recorded by opv bootstrap --state prod --target shared

[environments.prod.targets.p-overflow]
# deploy target for p only; added by opv target add
fly.app = "p-overflow-prod"
fly.secret_name = "{KEY}"
products = ["p"]
deploy_credentials = "op://infra-prod/fly-deploy-p-overflow"
state_vault_id = "vst2…"
```

**One form.**
- Targets exist only as `[environments.<env>.targets.<name>]`, even when there is just one.
  `Environment.target` becomes an ordered map of named targets.
- A provider table directly under the environment (`fly.app = …`, `[environments.prod.azure]`)
  fails at load, with the exact `targets.<name>` form to write instead.
- Target names match `^[a-z][a-z0-9-]*$` and are always chosen by a person.

**`products` is a target option for every provider** (FR-48 generalized).
- GitHub's own `products` option and its `serves()` are removed. The shared target layer
  decides which products a target serves.
- Without `products`, a target delivers every non-source-only product with a key desired in
  the environment.

**On the target, with no fallback:**
- `deploy_credentials` (S3);
- `state_vault_id` (§6.3).

**Collisions.**
- A `(provider, locator)` belongs to one target within an environment. The existing
  `same_target` check runs between targets.
- Across environments, one Fly app stays allowed when the templates differ, because the
  environment is part of the evidence scope.
- A template without `{PRODUCT}` on a multi-product target is caught by the FR-30
  name-collision check.

All of an environment's targets read the same boundary items, so P's values exist once (E3).

### 5.2 Commands

```sh
opv target add prod p-overflow --fly-app p-overflow-prod --products p [--secret-name '{KEY}'] \
    --deploy-credentials op://infra-prod/fly-deploy-p-overflow
opv target list [--env prod] [--json]
opv plan prod [--target p-overflow]
opv sync prod --expect-plan <id> [--target p-overflow] [--deploy]
opv delivery verify prod --product p [--target p-overflow] --json
```

- **`opv target add`**
  - writes through `config_edit`: comments kept, validated, concurrency refused;
  - is also how the first target is declared;
  - ends with `Next: opv bootstrap --state prod --target p-overflow`, then `opv access prod --target p-overflow`.
- **`plan` / `sync`**
  - Without `--target`: every target, under one plan id that covers exactly the targets
    planned.
  - `--target` (repeatable) narrows the run.
  - Rows always carry a `TARGET` column (JSON `target`).
- **`delivery verify`**
  - Without `--target`: every placement of the product, each with its own `target` and
    `state`.
  - `--target` narrows the result. It is never required.
- **`ready`** shows a target as `grants_missing` until its deploy credentials, its state
  vault and every boundary it reads can be opened.

### 5.3 Delivery evidence per placement (FR-58)

**Scope.** Receipt scope is `(account_id, environment, product, target, provider, locator)`.
The target name is part of it, so a receipt says where it applies in a person's words.

**Matching a scope.**
- A receipt file entry is selected by the full scope, independent of order.
- A duplicate full scope is refused with `duplicate_scope`.
- The first-match-by-product code is removed.
- A changed locator gives `not_delivered`, reusing the existing path.

**Items.**
- One item per placement, `opv · delivery · <product> · <target>`, in the target's state
  vault. Writing one never touches another (S5).
- Its item ID is recorded on first creation, so `sync` never looks state items up by title
  (FR-13).

**Ledger.** The FR-54 ledger moves out of the values item and into the same state item.
- One evidence key per item serves both the ledger and the revision evidence.
- Entries are per placement, so two placements that render the same name never share one.
- It is written by whoever delivers: the deploy identity in CI, or a person.
- The values item no longer has an `opv · state` section, and the code that writes it is
  removed.

**Per placement.** Staged versus deployed, drift and revisions are computed per placement,
so a stale revision on `p-overflow` changes nothing about `shared`.

## 6. Identities, evidence and access (FR-59)

### 6.1 Who needs what

| Principal | Read | Write | Never |
|---|---|---|---|
| target deploy identity (`prod/p-overflow`) | its products' boundaries and their `from` sources; its state vault | its state vault | another environment; values; other targets' evidence |
| CI reader (`prod`) | the boundaries of the products its jobs run | none | another environment |
| verifier (`delivery verify`) | the boundaries and the state vault of the placements it verifies | none | |
| developer on P | `<project>-p-dev`, shared dev boundaries, own personal item | values they own | staging and production unless granted by name |
| operator of P in prod | `<project>-p-prod` and P's shared sources | values | other products' prod boundaries |

`opv access` (FR-52, #96) is extended, not duplicated:
- it computes this table per boundary and per target;
- it prints only the missing grants, as the exact owner commands;
- it never runs them.

### 6.2 Measuring access (S7)

- **Now (proven):** `op vault user list` per boundary and state vault in the owner's
  session, compared with the table.
- **After the spike (speculative until then):**
  - the vault list under a service account, reporting `cross_environment_access` (a
    problem) and `overbroad_access` (a note);
  - group listing.
- Every result reports `checked: n, unclassified: m`, never "clean".
- The docs recommend `opv access --json` on a schedule in CI.

### 6.3 Where evidence lives (S6)

The state item holds the evidence key, the fingerprints and, for Fly, digests that reveal
values. So each target has its own state vault, `<project>-<env>-<target>-state`.

- **Why a target's own vault is safe:** its readers are that target's deploy identity and
  its verifiers, who already read every product the target delivers.
- **Sharing a state vault:** several targets may share one only if they deliver products
  from the same set of boundaries. Otherwise the configuration fails at load with
  `state_vault_wider_than_values`. The error names:
  - the state vault;
  - the targets sharing it;
  - the boundary one of them cannot read.
- **Creating it:** `opv bootstrap --state <env> --target <t>`.

## 7. What the change removes (FR-60)

| Removed | Replaced by |
|---|---|
| environment-level `vault_id`/`item_id` | `boundaries.<name>` |
| environment-level provider tables (`fly.app`, `[environments.<env>.azure]`, …) and `Environment.target` | `targets.<name>` |
| environment-level `deploy_credentials` and `state_vault_id` | the same keys on the target |
| GitHub-only `products` and `serves()` | the target-level `products` |
| `opv · delivery · <product>` items and first-match receipt selection | per-placement items, full-scope selection |
| the values item's `opv · state` ledger section and its writer | the ledger in the per-placement state item |
| the simple profile, `[profile]`, top-level `[keys]`, unsectioned keys and `"product": null` rows (FR-20) | one product in the one model |
| the `pattern` rule (deprecated alias of `regex`, FR-24) | `regex` |
| the `fly_name` JSON field (deprecated alias of `target_name`, P4) and the schema's `deprecated` list | `target_name`; no list, because nothing is deprecated |

**Not removed.** These are not compatibility code:
- tolerance of the shapes external CLIs emit (for example, flyctl's field casing);
- reading dotenv files in `opv adopt` (importing values is a feature).

## 8. Cost (E7)

Costs are counted in `op` requests, not items. A cold whole-item read costs 2 requests (D0
spike). FR-13's limits are 1,000 reads per hour per service-account token and, per account,
1,000 (Families) or 5,000 (Teams) requests per 24 hours.

| Command | Reads |
|---|---|
| `sync prod --target t` | each distinct boundary the target's products read, plus one state item per product, plus one write per product delivered |
| `sync prod` | the same, summed over targets; a boundary read by several targets is read once |
| `run dev --product p` | P's boundary plus its sources (usually 1–2 items) |

No total is claimed. The spike measures a full `sync` and a `run` with `OP_CACHE=false`,
using `op service-account ratelimit` before and after (FR-13 method), and records the
counts here.

## 9. Spike (gates access measurement, §6.2)

These run read-only, or against a throwaway test account. Outputs are recorded as fixtures.

1. The request cost of one full `sync` and one `run` (§8).
2. Under a service account, whether `op vault list` shows exactly the granted vaults.
3. Whether a service account's vault access is fixed at creation. Until confirmed, guidance
   assumes it is, and plans a new identity.
4. `op vault group list`: the permission it needs, and group availability by plan. Also
   confirm the `SERVICE_ACCOUNT` type string `domain/access.rs` marks unconfirmed.
5. Limits on vaults and service accounts by plan. No figure is assumed.

## 10. Decisions (owner, 2026-10-14)

| # | Question | Decided |
|---|---|---|
| D1 | `plan`/`sync <env>` without `--target` | every target, one plan id; `--target` narrows |
| D3 | target names | always chosen by a person, from the first target on |
| D4 | where evidence lives | one state vault per target, refused at load when wider than values (§6.3) |
| D5 | boundary default | one per product; `boundary = "<group>"` is an opt-in, and `opv access` states who can read what |
| D6 | account-wide sources | a later phase, after the tidy prerequisite (§4.4) |
| D8 | backward compatibility | none: greenfield, one way only, old forms fail at load (FR-60) |

D2 (migrating evidence) and D7 (deleting the old item after a split) are withdrawn: nothing
migrates.

| D9 | the simple profile | folded into the one model: a single-app project is a configuration with one product (FR-20 removed, FR-60) |
| D10 | `--product` with one product | may be omitted when exactly one product has keys desired in the environment; with several it is a usage error listing them |

The review's one remaining Medium risk is owner workload: more vaults and identities. D5 is
the explicit, visible way to trade it against S2.

## 11. Delivery

**0.7.0 ships the whole model in one change:**
- §4.1–4.3 and §5–§6.1;
- §6.3 and the `opv access` extension;
- the removals in §7;
- `bootstrap` per boundary and per target state vault;
- docs, the agent skill and an example (shared baseline plus dedicated overflow).

It closes #114 and the boundaries issue.

**Later:**
- the spike (§9), then access measurement (§6.2);
- account-wide sources (§4.4).

These are additions, not second forms.

Review items that no longer apply, because nothing migrates:
- R2: the split rebind;
- R3, R9 and R10: split grants, retiring the old vault, and edits to the old item;
- R11: the split comparison;
- R18: migrating evidence to the wrong target;
- C2, C5, C7 and C15.

## 12. Acceptance (synthetic fixtures, no live mutation, no value in any output)

#114:
1. Record P on A, then P on B: both revisions stay independently `verified`.
2. A stale revision on B leaves A `verified`. Staged versus deployed, drift and ledger
   entries are per placement.
3. Receipt selection is order-independent across distinct locators. A duplicate full scope
   is refused.
4. The agent skill and setup docs show a shared baseline plus a dedicated overflow app, with
   no value entered twice.

Structure:

5. Every removed form in §7 fails at load (or as a usage error) and shows the current form.
   No code path reads it.
6. A key with a field in two boundaries is reported by the extra-field finding. Nothing
   decides between them at run time.
7. A state vault shared by targets with different boundaries is refused at load with
   `state_vault_wider_than_values`.
8. Self-documenting (E8):
   - every new finding has a sentence and a `Next:` (guidance test);
   - every entry and 1Password item a command writes carries its explanation;
   - `opv explain` answers for a key and a target;
   - the example runs as a scenario test.
9. Redaction: marker values never appear in output, receipts, errors or argv.
