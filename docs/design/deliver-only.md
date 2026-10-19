# Deliver-only infrastructure values (#206)

Status: design for 0.13.0, 2026-10-19. Built on opv 0.12.3. The owner chose deliver-only on #206.
The design is vetted under the owner's DESIGN-FMECA procedure, run by a separate agent, before any build.

## 0. The decision in one paragraph

Some values are produced by infrastructure, not by people. Examples are the Neon database URL that
Terraform creates and the Stripe webhook signing secret that `stripe_webhooks.py` creates. A key that
holds such a value declares `source = "infrastructure"`. The approved deploy workflow pipes the value
to `opv sync … --supply-stdin` as a JSON document on stdin, and that is the only way in. opv checks
three things before it reads 1Password or writes anything: the name, the scope and the key's opt-in.
The planner then applies the key's rules, and the value goes out through the normal staged-store sync.
Delivery evidence and the receipt mark the name as `supplied`. **The value is never written to
1Password.** After the sync, opv keeps only the keyed fingerprint and the target version in the state
vault, which the deploy identity can already write. CI gets no new 1Password capability, and opv
defines no roles.

## 1. Terms

- **Infrastructure key**: a declared key with `source = "infrastructure"`.
- **Supply**: the values that one `sync` run reads from stdin. Each value lives only in opv's memory,
  for the length of that run.
- **Supplied evidence**: the evidence line of a name opv delivered from a supply.
  The line is `s1|<store version>|<fingerprint>|<product/KEY>|<serial>|<recorded at>`.
- **Serial**: a non-secret integer from the producer that must increase over time (§5.1).

## 2. Contract

### 2.1 Declaration and name

```toml
[products.api.keys.DATABASE_URL]
kind = "secret"
source = "infrastructure"
environments = ["staging", "prod"]
rules = { regex = "^postgres(ql)?://" }

[products.api.keys.STRIPE_WEBHOOK_SECRET]
kind = "secret"
source = "infrastructure"
environments = ["staging", "prod"]
rules = { prefix = "whsec_" }
```

The new variant is `ValueSource::Infrastructure` (`src/domain/model.rs`). The `source` attribute
already answers one question: who or what produces the value (`person`, `generated`, `derived`).
Infrastructure is a fourth producer, so the name follows the attribute's meaning. Other names were
considered and rejected:

- **`ci`** names a courier, not a producer, and it reads like a role. opv defines no roles.
- **`supplied`** describes the channel. It is kept as the provenance word that plan, receipts and
  value states show.
- **`terraform`** names one tool. Stripe is not Terraform.

Opting in is per key, and `source` is the only opt-in. No flag or environment setting widens it.
`source` is a single-valued enum, so a key cannot also be `person`, `generated` or `derived`.

### 2.2 Combinations refused at load (`config_invalid`, field rule in §4.12 of the error catalog)

| Combination | Rule | Why |
|---|---|---|
| `from = …` | `ConflictsWith{from}` (existing check) | a shared key reads another key's 1Password field |
| another key's `from` names this key | `ConflictsWith{source}` on the consumer | the consumer would read a 1Password field that never exists |
| `personal = true` | `ConflictsWith{personal}` | personal keys exist only where there is no target |
| any environment the key is present in has no target | `Type{"infrastructure only in environments with targets"}` | nothing could deliver it, and `opv run` has no value |
| `environments` absent | `Missing` | the scope must be written down, not "every environment" |
| no shape rule | `Type{"infrastructure needs a shape rule"}` | a mis-mapped value must fail (§4). Shape rules are `prefix`, `ensure_prefix`, `prefix_by_mode`, `regex`, `enum`, `base64_bytes`, `hex_bytes`, `https_url` and `email_list`. `not_prefix`, `refuse_in` and `transform` alone do not count |
| `allow_same_value = true` | `ConflictsWith{source}` | there is no stored value to compare, so the attribute has no effect |
| product is `source_only` | `ConflictsWith{source_only}` | a source-only product is never delivered |
| a pinned target (Kubernetes, Azure) delivers the product in a present environment | `Type{"infrastructure keys need a staged target (Fly, GitHub) in 0.13"}` | §10 non-goal |

`immutable = true` is **allowed**, and immutability holds in full (§4.3). `kind = "config"` is
allowed. A supplied config value is handled as a concealed config value (M4): it is delivered,
never printed, and registered with the scrubber as a secret. `expires`, `lifecycle`, `roles`,
`except`, `guidance` and `file` keep their meanings.

An opv older than 0.13 refuses `source = "infrastructure"` at load, because serde rejects the
unknown variant. An old CI binary therefore fails loudly and never skips the key quietly.

### 2.3 Scope

A supply is admitted against three things:

- the run's environment;
- its `--product`, if given;
- the binding sets of its selected targets (`--target`, or every target of the environment).

A name is in scope only when all of these hold:

- it is declared;
- it is an infrastructure key;
- it is present in the environment (it is listed, not `except`ed, and not skipped by a mode or
  `refuse_in`);
- its product is in `--product`, when that flag is given;
- it is in the binding set of at least one selected target.

opv delivers the name to every selected target whose binding set holds it.

## 3. Intake channel

**`opv sync <env> --supply-stdin`.** The flag is boolean and takes no argument, so no path to a
file can be given. stdin carries one or more JSON documents back to back, separated by whitespace:

```json
{"schema": "opv.supply/1", "env": "prod", "serial": 4182,
 "values": {"api/DATABASE_URL": "postgresql://…"}}
```

**Rules.** opv reads stdin to EOF before it reads 1Password or calls a target:

- **Channel.**
  - stdin must not be a terminal. If it is, opv refuses before reading a byte. A typed value would
    echo on screen.
  - Without the flag, opv never reads stdin. That is the behaviour today.
  - Agent mode refuses the flag. The value path is never driven by an assistant (R1).
- **Limits.**
  - 1 MiB in total: opv reads at most 1 MiB + 1 bytes, then refuses.
  - 64 KiB per value.
  - 256 names per run.
  - Store limits still apply on top through `Guard::ValueTooLarge`.
- **Encoding.**
  - UTF-8 JSON, as JSON itself requires.
  - Each value must be a JSON string. `null`, a number, an object, an empty string or a string
    containing NUL is refused.
  - A secret-kind value shorter than `SECRET_MIN` (8 bytes) is refused, because the output guard
    could not mask it.
  - A value from the placeholder list is refused.
  - Values are taken byte-exact, with no trimming.
- **Documents.**
  - `deny_unknown_fields`.
  - `schema` must be `opv.supply/1`.
  - `env` must equal the sync's environment. This catches staging outputs piped into prod.
  - `serial` is a u64 and required.
  - `values` must be non-empty.
- **Names.**
  - A name must be a canonical key reference, `<product>/<KEY>`, the same grammar as `--rotate`.
  - Rendered target names (`FLEET__API__DATABASE_URL`) and bare `KEY` are refused, because a
    contract has one way only (FR-60).
  - A name that appears twice is refused as `duplicate`. This holds inside one object (a custom
    map visitor, because serde_json's default keeps the last entry silently) and across documents.
- **All before any write.** Every admission refusal (§4) happens before the first 1Password read.
  Rule refusals happen after that read but before the first target write. A sync that refuses
  writes nothing.

**Why stdin.**

- argv is visible in `ps` and in logs.
- The environment is inherited by children (`flyctl`, `gh`) and readable from `/proc`.
- Files persist on the runner.
- A dedicated file descriptor (`--supply-fd 3`) is equivalent but easier to get wrong in YAML. It
  is left as an open question (§13).

Several producers concatenate into one pipe (§8.4). That is why multiple documents are accepted and
duplicates are refused: a merge with `jq add` would hide a collision.

**In memory.**

- The raw buffer is `Zeroizing<Vec<u8>>` and is wiped right after parsing.
- Each value becomes a `SecretValue`.
- Each value is registered with the scrubber (`scrub::register_kind(v, Kind::Secret)`) **while it
  is parsed, before any later step can fail**. Any echo from `flyctl` or `gh`, or any later error,
  is then masked.
- `Debug` prints names only.
- No supplied value reaches stdout, stderr, `--json`, a receipt, a log, MCP, argv, an environment
  variable or a file. The courier invariant (stdin to the platform tool) is unchanged.

**What an error can show.**

- serde errors are mapped to `{document, line, column, rule}`. Their text is never shown, because
  serde's messages quote the input.
- A name that fails the key-reference grammar is reported only by its position
  ("document 2, entry 3"). A mapping bug can put a value where a name belongs.

## 4. Validation and refusals

### 4.1 Admission (pure, before 1Password)

`deliver_only::admit` returns `Guard::SupplyRefused` (code `policy_refused`, guard
`supply_refused`, exit 6, retry `never`). It carries `{env, entry: Named{product, key} |
Position{document, index}, reason}` and refuses on the first problem, ordered by document, then
entry. Reasons:

| Reason | Do | Next |
|---|---|---|
| `NotAKeyRef` (position only) | "supply names as product/KEY; check the producer's output mapping" | none |
| `Undeclared` (closest infrastructure key offered) | "declare p/K with source = \"infrastructure\", or fix the name" | `opv propose key p/K --source infrastructure` |
| `NotOptedIn` (declared, other source) | "only a key with source = \"infrastructure\" takes a supplied value; p/K comes from 1Password" | `opv explain p/K --env E` |
| `NotInEnvironment` | "p/K is not present in E" | `opv explain p/K --env E` |
| `OutOfScope{targets, product}` | "p/K is not delivered by the selected targets/product" | `opv plan E [--target …]` |
| `Duplicate` | "supply p/K once per run" | none |
| `WrongEnvironment{document_env}` | "this document was produced for <document_env>" | none |
| `Empty`, `TooShort`, `Placeholder`, `NotAString` | "the producer gave no usable value for p/K" | none |
| `RotateWithoutValue` (`--rotate p/K` on an infrastructure key that is not supplied) | "supply p/K in the same run to rotate it" | none |

Stream-level problems use the existing `InputInvalid` (code `input_invalid`, exit 8) with a new
`kind: Supply` and `path: <stdin>`. Its rules are `StdinIsTerminal`, `NotJson{line, col}`,
`UnknownField`, `WrongSchema`, `TooLarge{limit}`, `MissingSerial` and `NoValues`.

### 4.2 Rules (after the 1Password read, before any write)

Supplied values enter the planner as synthetic `ItemField`s (§6.1). The key's rules therefore run
through the same `rules::check` as stored values, and `transform` and `ensure_prefix` apply the same
way. The rule gate (H1) is unchanged: CI evaluates the contract it checked out.

A `RuleFailed` row for a supplied name is reported as
`Guard::SupplyRefused{reason: RuleFailed{rule}}`, with the Do "the supplied value of p/K fails rule
<name>; check the producer". It is never `ValuesNeeded`, whose Do says "fill in 1Password".

`deliver_only::refusal(&plan, &supply)` runs in `sync` immediately before `refuse_blocking`.

### 4.3 Immutability

An immutable infrastructure key is written only when it is absent from the target, or when the same
run supplies it **and** names it with `--rotate p/K`. A supplied immutable value is handled by its
target state:

| Target state | Ledger | Without `--rotate` | With `--rotate` |
|---|---|---|---|
| absent | — | written | written |
| present | `Same` | no write (idempotent) | no write |
| present | `Differs` | **refused** `ImmutableDiffers`, before any write | written |
| present | no evidence, or another version | **refused** `ImmutableUnproven` | written |

Infrastructure supplying a value is not the same as being allowed to rotate it. A run that supplies
a value it cannot apply fails, so the workflow goes red instead of quietly holding a stale value.
Attestation (#201) refuses infrastructure keys with a new `AttestRefusal::NotStored`, because there
is no 1Password value to attest. The one-time way out is a rotation run. `--prune` never unsets an
immutable infrastructure key without `--prune-immutable`, the same as today.

### 4.4 A 1Password field for an infrastructure key

**Refused, whether or not the value is supplied.** The boundary item still holding a field for an
infrastructure key is a blocking finding, `Guard::SupplyRefused{reason: Stored}`. Its Do is "archive
field p/K in <item>: infrastructure keys are never stored", and its Next is
`opv propose key p/K --source infrastructure`. That proposal's apply step archives the field.

Two sources of truth would let a person edit 1Password, believe production changed, and be wrong.
Ignoring the field quietly would hide that.

`propose structure` and tidy never create a field for an infrastructure key. `opv set`, `opv import`,
`opv open`, `propose generate` and `opv_import_local` refuse one with the same reason.

## 5. Staleness, idempotency, concurrency, failures

### 5.1 Stale source

Each name's `s1` line records the serial it was delivered at.

| Supplied serial vs recorded | Value vs recorded | Outcome |
|---|---|---|
| lower | — | refused `Stale{recorded}` |
| equal | same fingerprint | idempotent |
| equal | different fingerprint | refused `SerialReused` |
| higher | — | normal plan |

This catches a re-run of an old workflow run, or an old Terraform state, overwriting a newer value.
Recommended serials:

- **Terraform**: the state `serial`.
- **Stripe helper**: `github.run_number`. A re-run keeps its old number, so it reads as stale.

### 5.2 Idempotency

When the ledger shows the target already holds this value (`Same`), the name is not staged, not
deployed and its line is unchanged. The revision is unchanged too, and the delivery item is not
rewritten (`record`'s existing `changed` test). Supplying the same value twice writes nothing.

### 5.3 Concurrency

- **Generated jobs.** Every job opv generates that syncs an environment uses one concurrency group,
  `opv-sync-<env>`, with `cancel-in-progress: false`. Infra's `apply.yml` must join that group.
- **State item writes.** Before writing a delivery item, `record` reads it again. If its version
  changed since this run read it, opv merges once: it keeps the other run's lines for names this
  run did not confirm. It then writes. If the item changed again, the result is `ChangedBeforeWrite`
  (`item_changed`, exit 4, retry safe), with the target writes listed in `Partial`.
- **Names a run did not supply.** Their lines are carried unchanged and never re-timestamped. Two
  jobs that supply disjoint names therefore never erase each other's evidence.

### 5.4 Failures never report success

- **Write failure.** A failed or unconfirmed target write uses the existing `Partial`: the written
  names, then the inner cause. No revision is minted, and the exit code is non-zero.
- **Evidence failure.** Recording evidence after a confirmed write is a **failure, not a note**,
  when the run supplied values. Today `record_delivery` downgrades it to a note. For a supplied name
  the evidence line is opv's only memory of the value, so the run exits with
  `DeliveryUnverified{state: NotRecorded}` (exit 8). The Do is "re-run the deploy workflow; the
  target holds the value but opv cannot vouch for it".
- **Retry.** A retry with the same supply is idempotent. Names with no evidence for the new version
  are staged again with the same value, confirmed, then recorded.
- **Producer failure.** A producer that fails mid-stream leaves invalid JSON, so the whole supply is
  refused. One that fails after a complete document leaves a valid subset, which is delivered and
  reported honestly. `set -o pipefail` (§8.4) then fails the step.
- **Missing delivery item.** A run with `--supply-stdin` refuses before any write when a selected
  placement has no recorded delivery item or state vault (`RecordMissing{StateVault}`, Next `opv propose structure`).

## 6. Delivery and evidence

### 6.1 Plan integration

In `prepare_staged`, opv works in this order:

1. `tidy::read` reads the boundary items, as today.
2. `deliver_only::refuse_stored` refuses any field of an infrastructure key (§4.4).
3. `deliver_only::item_fields(&supply)` is appended to the read fields.
4. `plan::build_with_gate` runs unchanged for supplied names.

The planner handles an infrastructure key that has **no** field (not supplied this run) as follows:

- it gives the key `KeyState::SuppliedAtSync`, which is not blocking and never `Missing`;
- it never stages or prunes the key;
- it judges the target state from the ledger's version alone:

| Target state | Meaning | ON TARGET word |
|---|---|---|
| `AsSupplied` | the store lists the version the `s1` line recorded | `as supplied` |
| `Drifted` | the store lists another version | `drifted` (joins `plan.drift`) |
| `Absent` | the store does not list the name | `absent` |
| `Unrecorded` | the name is listed but has no `s1` line | `not recorded` |

`opv plan` shows `supplied at sync` in the 1Password column. `--json` rows add
`"value_state": "supplied"` and `"supplied": true`.

**Plan id.** Each supplied name enters with route `supplied` and **without** its write/no-write bit.
`provenance::plan_id` skips infrastructure keys when it builds the `apply` set. Two things follow:

- A value-free `opv plan` and the supplying `sync --expect-plan` derive the same id.
- The plan id never carries an equality bit about a CI-supplied value.

### 6.2 Evidence

The fingerprint is HMAC-SHA256 of the supplied value under the placement's evidence key, the same as
today. The line uses the tag `s1`:

```
s1|<store version>|<fingerprint>|<product/KEY>|<serial>|<recorded at>
```

`decode_evidence` and `encode_evidence` gain the tag. `Evidence` gains
`supplied: Option<SuppliedMark{serial, at}>`, and `Ledger::from_evidence` reads `s1` lines into its
entries. So a later supplying sync's `Ledger::check` gives `Same` or `Differs`, and `Ledger::drift`
covers supplied names.

`record` changes in three ways:

1. A supplied name's value comes from the `Supply`, not from `values_by_field`.
2. A name that was not supplied and is `AsSupplied` is passed in a new `carried` set. Its line is
   kept verbatim and counts as confirmed. The store version is a value digest (Fly) or a write
   stamp (GitHub `updatedAt`), so equality proves the target still holds what opv delivered.
3. `source versions` (C2) leaves infrastructure keys out, because they have no item.

`opv changed` ignores infrastructure keys.

### 6.3 Receipts

The schema id stays `opv.delivery/1`. A supplied binding's source is
`{"item_id": "supplied", "field": "api/DATABASE_URL"}`. `supplied` can never be a 1Password id,
which is 26 characters long. An optional `supplied: [names]` list (omitted when empty) mirrors
`attested`. A consumer that cares about provenance reads `supplied`.

A revision is minted when every name in the binding set is written, identical, carried or attested.
It is reused while every line is unchanged.

### 6.4 Reporting when the workflow did not supply

The scheduled `--on-change` or drift jobs run without `--supply-stdin`:

| Command | Behaviour |
|---|---|
| `sync` | holds every infrastructure name. `AsSupplied` names count as carried, so the product's revision stays valid. `Absent`, `Drifted` or `Unrecorded` names mint nothing, and the sync reports `delivery: api not recorded: supplied at sync, not supplied by this run: …` (exit 0: this run wrote what it could and claims nothing more) |
| `status --fail-on-drift` | fails on a drifted supplied name, the same as any drift |
| `ready --gate` | fails unless every present infrastructure key is `AsSupplied` on every target of the tier. Findings: `supplied_not_delivered` or `supplied_drifted`, with the Next "run the deploy workflow" |
| `delivery verify` | per name: `verified` (version equal, `"supplied": true`), `drifted_on_target` or `missing_on_target`. Never `source_changed`, because there is no 1Password source |
| `inventory`, `opv_state` | value state `supplied`, the 8th word of §3.3: "opv stores no value; the deploy workflow supplies it at sync". The delivery state comes from evidence |
| `explain p/K` | "supplied at sync by the deploy workflow; never stored", plus last delivery time and serial per placement |
| `opv run` in a target environment | does not inject the key, and prints one note naming it |

## 7. Identity

The run uses the **existing deploy identity**:

- a 1Password service account that can read the environment's boundary vaults and write its state
  vault, as built by `opv access --create`;
- the platform token (`FLY_API_TOKEN`, or a GitHub token).

A supplying sync reads the boundary items, to plan the other keys and to refuse stored fields. It
writes only delivery items in the state vault. **No new 1Password capability is needed or created.**

`deliver_only.rs` imports no 1Password write adapter. A test (§9) asserts that a supplying sync in
the simulator issues no `op item edit` or `op item create` outside the state vault. `import`, `set`
and `apply` keep `require_person`. The #206 ingestion identity and writable boundary do not exist
under this design.

## 8. Surface

### 8.1 CLI

- `opv sync … --supply-stdin` (§3).
- `opv propose key … --source infrastructure`, whose apply archives an existing field (§4.4).
- `opv ci workflow <env> --target <t> --supply` emits a deploy job with these parts:
  - the concurrency group;
  - `set -euo pipefail`;
  - a commented placeholder producer block;
  - `opv sync <env> --target <t> --supply-stdin [--deploy] --receipt <t>.receipt.json [--confirm]`.

  It also emits a comment naming the infrastructure keys in scope and the rule each must pass.

### 8.2 MCP

No tool accepts a value.

- `opv_propose` accepts `source: "infrastructure"` as one more enumerated attribute. It is
  value-free.
- `opv_state` shows `supplied` and the target states above.
- `tests/mcp_protocol.py` still asserts exactly five tools. The intake is CLI-only.

### 8.3 Schema and docs

- `opv schema` gains:
  - the capability `supplied_values/1`;
  - `value_state` + `supplied`;
  - `row_state` + `supplied_at_sync`;
  - the `opv.supply/1` input schema.
- `tests/e2e/expected/surface.json`: `sync` + `supply-stdin`, `ci workflow` + `supply`.
- Docs to update:
  - `docs/configuration.md`: the attribute and its load refusals.
  - `docs/usage.md`: the intake, the states and the exit codes.
  - `docs/security.md`: the courier invariant now has an inbound leg.
  - `docs/design/error-catalog.md`: the rows of §4.
  - `docs/design/delivery-receipts.md`: `s1` and `supplied`.
  - `opv guide agent` and the skill: an assistant proposes the key and never handles values.
  - CHANGELOG: first supported in 0.13.0, plus the example below.

### 8.4 Supported infra migration (`apply.yml`, `stripe_webhooks.py`)

Steps, in order:

1. Propose and apply both keys (§2.1). The apply archives any existing 1Password field.
2. If the placement has no delivery item yet, run `opv propose structure`, then `opv apply`, which records it.
3. Change `stripe_webhooks.py` so it prints exactly one `opv.supply/1` document on stdout and
   nothing else. It must not call `flyctl secrets set` itself.
4. Replace the direct Fly delivery in `apply.yml`:

```yaml
  deliver-infrastructure-values:
    needs: terraform-apply
    environment: prod
    concurrency: {group: opv-sync-prod, cancel-in-progress: false}
    steps:
      - uses: actions/checkout@v4
      - # install opv 0.13.0 (opv ci workflow emits the pinned step)
      - name: Deliver Terraform and Stripe values through opv
        env:
          OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OPV_PROD_DEPLOY }}
          FLY_API_TOKEN: ${{ secrets.FLY_API_TOKEN }}
        run: |
          set -euo pipefail
          serial=$(terraform -chdir=infra state pull | jq .serial)
          {
            terraform -chdir=infra output -json |
              jq -c --argjson s "$serial" \
                '{schema:"opv.supply/1", env:"prod", serial:$s,
                  values:{"api/DATABASE_URL": .neon_database_url.value}}'
            python fly/shared-host/stripe_webhooks.py --env prod \
              --emit-opv-supply --serial "${{ github.run_number }}"
          } | opv sync prod --target web --supply-stdin --deploy \
                --confirm prod --receipt web.receipt.json
          opv delivery verify prod --target web --receipt web.receipt.json
```

Notes on the example:

- If an output is missing, `jq` gives `null`, which is refused as `NotAString`.
- Both producers write only into the pipe.
- A pipe's contents never appear in the step's log, even under `set -x`.
- infra keeps its direct delivery until this job has run green on staging and prod, and
  `delivery verify` reports `verified` (owner condition on #206).
- Build-once promotion and the Build gate are untouched: the job compiles nothing.

## 9. Test plan

All tests use synthetic fixtures and the simulator (`tests/sim`). Values are `S7MARKER-…`
canaries.

| # | Test | Layer |
|---|---|---|
| T1 | positive: two documents supply two infrastructure keys for prod/web; staged on stdin only; confirmed; `s1` lines; revision with `supplied` | sync unit + e2e |
| T2 | wrong environment: document `env` ≠ sync env; key not present in env; `--product` excludes it; `--target` whose binding set lacks it → `supply_refused`, zero target calls, zero 1Password reads | core unit |
| T3 | unknown name (offers the closest infrastructure key); non-opted-in (`person`) key; bare `KEY`; rendered name; non-grammar name reported by position only | core unit |
| T4 | duplicates within one object and across documents | core unit |
| T5 | stream: terminal stdin, invalid JSON (error text contains no input byte), oversize (reads ≤ 1 MiB + 1), `null` value, empty `values`, missing serial, unknown field | core unit |
| T6 | validation: rule failure → `RuleFailed{rule}`, no target write; `transform` and `ensure_prefix` applied | core unit |
| T7 | immutable: absent → written; present `Same` → no write; `Differs` without rotate → refused before any write; unproven → refused; with `--rotate` → written, new revision; `--rotate` without the value → refused | sync unit |
| T8 | stored field present → refused with and without a supply; `propose key --source infrastructure` apply archives it | core + flows |
| T9 | idempotency: same supply twice → second run writes neither target nor delivery item, same revision | sync unit |
| T10 | staleness: lower serial refused; equal serial with another value refused | sync unit |
| T11 | concurrency: two runs supplying disjoint names interleave at `record`; the re-read merge keeps both lines; a third concurrent change → `item_changed`, `Partial` names the writes | sync unit |
| T12 | partial: target write fails after one name → `Partial`, no revision, exit ≠ 0; evidence write fails → `delivery_unverified`, exit 8; retry mints one revision | sync unit |
| T13 | no supply: carried `AsSupplied` keeps the revision; drift fails `status --fail-on-drift` and `ready --gate`; absent → `supplied_not_delivered`; `delivery verify` states | sync unit |
| T14 | no 1Password write: fake op log of a supplying sync has writes only to the state vault's delivery item | sync unit, `tests/security.rs` |
| T15 | redaction canaries: the marker never appears in stdout, stderr, `--json`, receipt file, delivery item (only the HMAC), argv, child env, files under the temp dir, MCP answers, panic text or error text, for T1–T13 | `tests/courier.rs`, `tests/security.rs` |
| T16 | plan id: `opv plan` without a supply equals `sync --supply-stdin --expect-plan` for changed and unchanged values | sync unit |
| T17 | load refusals of §2.2, each at its line | `src/config.rs` tests |
| T18 | e2e scenario `infrastructure_values`: propose and apply (structure and key), supplying sync, scheduled sync without a supply, simulated drift, re-supply, verify; snapshots | `tests/e2e/scenarios` |
| T19 | surface: `surface.json`, `opv schema`, MCP five tools, `opv ci workflow --supply` golden output | e2e + `ci_workflow_tests.rs` |

## 10. Non-goals

- **Writing supplied values to 1Password, by anyone.** The value lives in infrastructure. The
  target is its delivered copy, and opv holds a fingerprint. Recovery is re-running the producer.
- **Pinned targets (Kubernetes, Azure) in 0.13.** Their sync reads the store's value and rebinds
  runtime versions. Holding a value that is not supplied there needs its own design. Load refuses
  the combination.
- **Derived consumers of a supplied key** (`from`): refused. A consumer that needs the value
  declares its own infrastructure key, and the producer supplies both names.
- **Local `opv run` of infrastructure values.**
- **The app-value copies from GitHub secrets** that #206 mentions. Those use normal stored keys.

**#206 acceptance criteria that do not apply.** AC2's "dedicated ingestion identity and isolated
writable boundary", and AC6's "unauthorized identity" test, presume CI writes 1Password. Under
deliver-only nothing is ingested into 1Password, so there is no writer to isolate. Tests T14 and T2
cover the replacements:

- the deploy identity is not widened;
- out-of-scope supplies are refused.

The other criteria map as follows:

- **AC1**: §2.3, §4.1.
- **AC2**: human-only paths preserved, §7.
- **AC3**: §3, §4.
- **AC4**: §5.
- **AC5**: §6.
- **AC6**: §9.
- **AC7**: §8.3, §8.4.

## 11. Implementation split and interface

**Step 0 (interface commit, before both lanes).** This commit adds:

- `ValueSource::Infrastructure`;
- `src/app/deliver_only.rs` with the items below, bodies `todo!()`;
- the `Cause` shapes.

Both lanes branch from it, and their files do not overlap.

```rust
// src/app/deliver_only.rs (owned by deliver-only-core)
pub struct Supplied { pub product: String, pub key: String, pub value: SecretValue, pub serial: u64 } // Debug: names only
pub struct Supply { /* env; BTreeMap<(product, key), Supplied> */ }
impl Supply {
    pub fn env(&self) -> &str;
    pub fn get(&self, product: &str, key: &str) -> Option<&Supplied>;
    pub fn names(&self) -> impl Iterator<Item = (&str, &str)>;  // sorted
    pub fn is_empty(&self) -> bool;
}
pub struct Limits { pub total: usize, pub value: usize, pub names: usize }  // Limits::DEFAULT = 1 MiB, 64 KiB, 256
pub struct RawSupply { /* parsed documents, values registered with the scrubber */ }
pub fn read(input: &mut dyn std::io::Read, stdin_is_terminal: bool, limits: Limits) -> Result<RawSupply, Error>;
pub struct Scope<'a> { pub env: &'a str, pub targets: &'a [String], pub product: Option<&'a str>,
                       pub rotate: &'a BTreeSet<(String, String)> }
pub fn admit(fleet: &Fleet, scope: &Scope<'_>, raw: RawSupply) -> Result<Supply, Error>;  // §4.1, pure
pub fn refuse_stored(fleet: &Fleet, env: &str, read: &[ItemField]) -> Result<(), Error>;  // §4.4
pub fn item_fields(fleet: &Fleet, supply: &Supply) -> Vec<ItemField>;                     // §6.1
pub fn refusal(plan: &SyncPlan, supply: Option<&Supply>, ledgers: &[Ledger]) -> Option<Error>; // §4.2, §4.3, §5.1
pub fn is_infrastructure(spec: &KeySpec) -> bool;
```

Shared domain shapes, also part of Step 0:

- `KeyState::SuppliedAtSync`;
- `TargetState::{AsSupplied, Unrecorded}`;
- `Evidence.supplied: Option<SuppliedMark { serial: u64, at: String }>`;
- `Receipt.supplied: Vec<String>`;
- `Ledger::supplied(&self, name) -> Option<(&str /*version*/, u64 /*serial*/)>`;
- `Guard::SupplyRefused { env, entry: SupplyEntry, reason: SupplyRefusal }`;
- `InputKind::Supply`;
- `AttestRefusal::NotStored`;
- the value-state word `supplied`.

**Lane `deliver-only-core`.** Owns:

- `src/app/deliver_only.rs` and `deliver_only_tests.rs`;
- `src/config.rs` (§2.2);
- `src/domain/model.rs`;
- `src/domain/plan.rs` (planner handling of infrastructure keys and the `refusal` inputs);
- `src/cause/*` rendering, and the error-catalog rows;
- the refusals in `structure.rs`, `set.rs`, `import.rs`, `import_local.rs`, `open.rs`,
  `generate.rs` and `attest.rs`;
- the `propose key --source infrastructure` apply step that archives the field;
- `docs/configuration.md`.

Tests: T2–T6, T8, T17, and the core part of T15.

**Lane `deliver-only-sync`.** Owns:

- `src/app/sync.rs`: the intake wiring, `SyncOpts.supply: Option<Supply>`, evidence failure as an
  error, and the carried set;
- `src/app/delivery.rs` (`record`, re-read merge, `verify`) and `src/domain/delivery.rs` (`s1`);
- `src/domain/ledger.rs` and `src/domain/provenance.rs` (plan id);
- `ready.rs`, `status.rs`, `inventory.rs`, `explain.rs`, `changed.rs`, `run.rs` and
  `ci_workflow.rs`;
- `src/main.rs` (`--supply-stdin`, `--supply`, agent-mode refusal) and `src/mcp.rs`
  (`opv_propose` enum);
- `tests/e2e/expected/surface.json` and the e2e scenario;
- `docs/usage.md`, `docs/security.md`, `delivery-receipts.md`, CHANGELOG and the infra example.

Tests: T1, T7, T9–T16, T18, T19.

Lane sync builds against the Step 0 signatures and fakes `admit` in its unit tests. The lanes join
in T18.

## 12. Self-vet

### 12.1 Poka-yoke

| Mistake | Made impossible or detected by |
|---|---|
| value given in argv or file | flag takes no argument; stdin only |
| typed value at a terminal | `StdinIsTerminal` |
| staging output piped into prod | document `env` must match |
| jq path wrong → null | `NotAString` |
| two producers emit the same name | `Duplicate`, including within one object |
| value mapped to the wrong key | mandatory shape rule per key |
| old run overwrites newer value | serial (`Stale`, `SerialReused`) |
| key also kept in 1Password | `Stored` refusal at plan, archive on apply |
| infrastructure key on a target-less env, pinned target, or as `from` source | refused at load |
| immutable key overwritten by routine supply | `ImmutableDiffers` / `ImmutableUnproven` unless `--rotate` |
| old opv in CI skips the key | old opv refuses the contract at load |
| assistant drives the value path | agent mode refuses `--supply-stdin`; MCP has no value input |

### 12.2 Security pass

**Where a value could leak, and the closure for each:**

| Where | Closure |
|---|---|
| serde error text | position-only mapping, T5 |
| unknown-name echo | grammar gate |
| `Debug` and panics | names-only `Debug`, `SecretValue`, `no_core_dumps` first |
| platform tool echo | values registered as secret scrub needles at parse |
| short values | `TooShort` |
| plan id equality bit | excluded |
| evidence | keyed HMAC in the state vault only |
| supplied config values | concealed |
| producers' own stderr | out of opv's scope, documented, as for third-party tools under R8 |

**Residual.** The run report says whether a supplied name changed. That is a fact about
infrastructure, the same as for stored values today, and it is not value content.

**Where CI could end up writing 1Password.**

- No code path exists: the module has no write adapter.
- The deploy identity cannot write boundary vaults.
- T14 detects a regression.
- Archiving a stored field happens only in a person's `opv apply`.

**Where a failed sync could claim success.**

- An evidence failure after a supplied write is now an error.
- Partial writes use `Partial`.
- Names that were not supplied count only when their version is proven unchanged.
- A missing delivery item refuses up front.
- Concurrent item edits are re-read and merged or refused.
- The receipt marks `supplied`.
- `ready --gate` fails on absent or drifted supplied names.

## 13. Open questions for the owner

1. **Serial required** (§5.1). The alternative is optional, with staleness checks only when it is
   given. Required is recommended, because a re-run of an old workflow is the likeliest real fault.
2. **A stored field** (§4.4): refuse (recommended) or ignore with a warning.
3. **Immutable but unproven on first adoption** (§4.3): refusal requires one `--rotate` run. The
   alternative is an attestation-like person step that records an `s1` line without a write.
4. **8th value state `supplied`** (§6.4) in the closed set of §3.3. The alternative reports these
   keys outside value states, only as delivery states.
5. **`--supply-fd <n>`** as a second channel, or stdin only (recommended: stdin only, one way).
6. **Pinned targets** (Kubernetes, Azure): a follow-up issue for 0.14, or never.
7. **`opv run` against a target environment**: a note (proposed), or refuse the run.
