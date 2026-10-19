# Deliver-only infrastructure values (#206)

Status: design for 0.13.0, revised 2026-10-19 after the DESIGN-FMECA review
([deliver-only-fmeca.md](deliver-only-fmeca.md): approve after fixes, S1–S13 incorporated below).
Built on opv 0.12.3. The owner chose deliver-only on #206.

## 1. The decision

Some values are produced by infrastructure, not by people: the Neon database URL Terraform creates,
the Stripe webhook signing secret `stripe_webhooks.py` creates. A key holding one declares
`source = "infrastructure"`. The deploy job that produced the value pipes it to
`opv sync … --supply-stdin`, the only way in. opv admits the supply (name, scope, opt-in,
completeness) before it reads 1Password, applies the key's rules, and delivers through the normal
staged-store sync. Evidence and receipts mark the name `supplied`. **The value is never written to
1Password**: the state vault keeps only the target version, a keyed fingerprint and the producer's
serial. CI gets no new 1Password capability; opv defines no roles.

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

`ValueSource::Infrastructure` is a fourth value of the existing attribute, which answers "who or
what produces the value" (`person`, `generated`, `derived`). Rejected names: `ci` names the courier
and reads as a role; `supplied` names the channel (kept as the provenance word in plan, receipts and
value states); `terraform` names one tool. `source` is single-valued and is the only opt-in; no flag
or environment setting widens it.

### 2.2 Refused at load (`config_invalid`)

| Combination | Rule | Why |
|---|---|---|
| `from = …` | `ConflictsWith{from}` (existing) | a shared key reads another key's 1Password field |
| another key's `from` names this key | `ConflictsWith{source}` on the consumer | the consumer would read a field that never exists |
| `kind = "config"` | `ConflictsWith{kind}` | GitHub refuses concealed config (`variables.rs`); short config escapes the output guard (S3) |
| `personal = true` | `ConflictsWith{personal}` | personal keys exist only without targets |
| `environments` absent, or a present environment has no target | `Missing` / `Type{"infrastructure only in environments with targets"}` | scope is written down; nothing could deliver it otherwise |
| no shape rule (`prefix`, `ensure_prefix`, `prefix_by_mode`, `regex`, `enum`, `base64_bytes`, `hex_bytes`, `https_url`, `email_list`) | `Type{"infrastructure needs a shape rule"}` | a mis-mapped value must fail (§4.2) |
| `allow_same_value` | `ConflictsWith{source}` | no stored value to compare |
| product is `source_only` | `ConflictsWith{source_only}` | never delivered |
| a pinned target (Kubernetes, Azure) delivers the product in a present environment | `Type{"infrastructure keys need a staged target (Fly, GitHub)"}` | §10 |

`immutable` is allowed and fully honoured (§4.3). `expires`, `lifecycle`, `roles`, `except`,
`guidance` and `file` keep their meanings.

**Version pins (S13).** An opv before 0.13 refuses the contract at load (unknown variant), so an old
binary fails loudly, never skips the key. Every workflow and teammate pin must move to ≥ 0.13.0
**before** the attribute is committed; migration step 0 (§8.4) and the CHANGELOG say so.

### 2.3 Scope

A run's scope is its environment, its `--product` (if any) and the binding sets of its selected
targets (`--target`, or every target). An entry is in scope only if it is a declared infrastructure
key, present in the environment (listed, not `except`ed, not skipped by mode or `refuse_in`), of the
selected product, and in at least one selected target's binding set. It is delivered to every
selected target whose binding set holds it.

**Completeness (S2).** A run with `--supply-stdin` must supply **every** infrastructure key in its
scope; a missing one is `NotSupplied`, naming the keys. Producers that run separately narrow their
runs with `--product`/`--target`, or share one pipe (§8.4). This removes the green job that silently
held a value Terraform had just rotated.

## 3. Intake channel

`opv sync <env> --supply-stdin` is boolean and takes no argument, so no file path can be given.
stdin carries one or more JSON documents back to back:

```json
{"schema": "opv.supply/1", "env": "prod", "serial": 4182,
 "values": {"api/DATABASE_URL": "postgresql://…"}}
```

| Aspect | Rule |
|---|---|
| Channel | stdin must not be a terminal (refused before reading a byte). Without the flag opv never reads stdin. Agent mode refuses the flag (R1) |
| Bounds | at most 1 MiB in total (opv reads 1 MiB + 1 bytes, then refuses) and 256 names. Per-value size is the store's own `Guard::ValueTooLarge`. The read must reach EOF within the run budget, else `Timeout` (S12) |
| Stream | at least one document (`NoDocuments` otherwise). Each: `deny_unknown_fields`; `schema` = `opv.supply/1`; `env` = the sync's environment (catches staging output piped into prod); `serial` a required u64; `values` non-empty |
| Values | JSON strings only (`null`, numbers, objects refused), non-empty, no NUL, not a known placeholder, at least `SECRET_MIN` (8) bytes so the output guard can mask them; taken byte-exact |
| Names | canonical `<product>/<KEY>` only. Rendered target names and bare `KEY` are refused (FR-60). A name twice is `Duplicate`, inside one object (a custom map visitor: serde_json keeps the last entry silently) and across documents |
| Order | all of §3 and §4.1 before the first 1Password read; rules (§4.2) and target-state refusals (§4.3, §5.1) before the first target write |

**Why stdin**: argv shows in `ps` and logs, the environment reaches `flyctl`/`gh` and `/proc`, files
persist on the runner. No `--supply-fd`. **In memory**: the raw buffer is `Zeroizing`, wiped after
parsing; each value is a `SecretValue`, registered with the scrubber as a secret **as it is parsed**;
`Debug` prints names only. No supplied value reaches any output, log, MCP, argv, environment or
file; the courier invariant to the platform tool is unchanged.

**What an error may show.** serde errors become `{document, line, column, rule}`; serde's text,
which quotes input, is never shown. An entry is echoed by name **only if it is a declared key**
(S11); anything else is reported by position ("document 2, entry 3"), still offering the closest
infrastructure key, because a mapping bug can put a value where a name belongs.

## 4. Validation and refusals

### 4.1 Admission (pure, before 1Password)

`Guard::SupplyRefused { env, entry: Named{product, key} | Position{document, index}, reason }`,
code `policy_refused`, guard `supply_refused`, exit 6, retry `never`; first problem wins, in
document then entry order.

| Reason | Do | Next |
|---|---|---|
| `Undeclared` (by position unless declared elsewhere) | "declare the key with source = \"infrastructure\", or fix the producer's name" | `opv propose key p/K --source infrastructure` |
| `NotOptedIn` | "p/K comes from 1Password; only an infrastructure key takes a supplied value" | `opv explain p/K --env E` |
| `NotInEnvironment` | "p/K is not present in E" | `opv explain p/K --env E` |
| `OutOfScope{targets, product}` | "p/K is not delivered by the selected targets/product" | `opv plan E [--target …]` |
| `NotSupplied{keys}` | "supply every infrastructure key in scope, or narrow with --product/--target" | `opv plan E [--target …]` |
| `Duplicate`, `WrongEnvironment{document_env}` | "supply p/K once" / "this document was produced for <env>" | none |
| `Empty`, `TooShort`, `Placeholder`, `NotAString` | "the producer gave no usable value for p/K" | none |
| `RotateWithoutValue` | "supply p/K in the same run to rotate it" | none |

Stream problems use `InputInvalid` (code `input_invalid`, exit 8) with `kind: Supply`,
`path: <stdin>` and rules `StdinIsTerminal`, `NotJson{line, col}`, `UnknownField`, `WrongSchema`,
`TooLarge{limit}`, `MissingSerial`, `NoValues`, `NoDocuments`, `Timeout`.

### 4.2 Rules

Supplied values enter the planner as synthetic `ItemField`s (§6.1), so the key's rules run through
the same `rules::check` (including `transform`, `ensure_prefix`) and the same rule gate (H1; CI
evaluates the contract it checked out). A failing rule is reported as
`SupplyRefused{reason: RuleFailed{rule}}` ("the supplied value of p/K fails rule <name>; check the
producer"), never `ValuesNeeded`, whose Do says "fill in 1Password".

### 4.3 Target state: one rule for every infrastructure key (S7)

| Target holds the name | Ledger | Not immutable | Immutable |
|---|---|---|---|
| absent | — | write | write |
| listed, **no `s1` line** | — | `Unproven` unless `--rotate` | `Unproven` unless `--rotate` |
| `s1` at the current version | `Same` | no write | no write |
| `s1` at the current version | `Differs` | write | `ImmutableDiffers` unless `--rotate` |
| `s1` at another version (drifted) | — | write (repairs drift) | `Unproven` unless `--rotate` |

"No evidence" is fail-closed for all keys, not only immutable ones. That covers first adoption
(infra set the value directly) and the case where an older opv or a key leaving the binding set
dropped the `s1` line, losing the serial high-water mark: the next supply cannot be judged stale, so
it needs an explicit rotation. Attestation (#201) refuses infrastructure keys
(`AttestRefusal::NotStored`): there is no 1Password value to attest. `--prune` never unsets an
immutable infrastructure key without `--prune-immutable`.

### 4.4 A 1Password field for an infrastructure key

Refused, supplied or not: `SupplyRefused{reason: Stored}`, Do "archive field p/K in <item>:
infrastructure keys are never stored", Next `opv propose key p/K --source infrastructure`, whose
apply archives the field. Two sources of truth would let a person edit 1Password and wrongly
believe production changed. `propose structure` and tidy never create such a field; `opv set`,
`opv import`, `opv open`, `propose generate` and `opv_import_local` refuse the key.

## 5. Staleness, idempotency, concurrency, failures

### 5.1 Stale source (S6)

| Supplied vs recorded serial | Fingerprint | Outcome |
|---|---|---|
| lower | — | `Stale{recorded, supplied}` |
| equal | same, target `AsSupplied` | idempotent, no write (S10) |
| equal | same, target not `AsSupplied` | §4.3 (drift is repaired, not skipped) |
| equal | different | `SerialReused{serial}` |
| higher | — | §4.3 |

**The serial is a non-secret integer from the producer's own object, never a CI counter.** Terraform: the state `serial`. The
Stripe helper: the webhook endpoint secret's creation time (Unix seconds) from Stripe's own object.
A re-run attempt that re-emits the same object supplies an equal serial and the same value
(idempotent); one that makes a new secret has a later creation time (accepted). `--rotate p/K`
overrides `Stale` and `SerialReused` for producer resets (a Terraform state migration), and the run
prints `rotated p/K at serial N` (S5); `status` shows each name's last rotation.

### 5.2 Idempotency

A name the ledger proves `Same` at the current version is not staged or deployed; its line,
the revision and the delivery item stay unchanged (`record`'s existing `changed` test).

### 5.3 Concurrency (S8, S9)

- **Supply in the job that produced the value**, under that job's own concurrency group (the
  Terraform apply job's), never in `opv-sync`: GitHub cancels a *pending* job in a group when another
  queues, so a scheduled sync could cancel a supply right after Terraform rotated.
- Scheduled, non-supplying jobs keep the existing `opv-sync` group, unrenamed; a future rename ships
  with a migration note, since old and new generated jobs would stop sharing a group.
- **State item: re-read, recompute, write, or `item_changed`.** Just before writing, `record` reads
  the delivery item again, recomputes the evidence from that read (other runs' lines kept as read),
  checks the version once more and writes; a change in between fails with `ChangedBeforeWrite`
  (`item_changed`, exit 4) inside `Partial`. 1Password has no compare-and-swap; the window is accepted.
- **A newer serial on re-read** (S9): if the fresh item holds a **higher** serial for a name this run
  supplied, the newer line is kept and the run fails `Partial` + `Stale` (exit ≠ 0, both serials
  named). The target now holds the older value, so the name reads `drifted` until the next supply.

### 5.4 Failures never report success (S1)

- `record` returns an outcome per supplied name. **Any supplied name left without an `s1` line fails
  the run** with `DeliveryUnverified{NotRecorded}` (exit 8): no listed version, an unencodable
  version, no delivery item, or a failed `record`. Do: "re-run the deploy job; the target may hold
  the value but opv cannot vouch for it". Runs without a supply keep today's note.
- A failed or unconfirmed target write is `Partial` (written names, then the cause), no revision,
  exit ≠ 0. A retry with the same supply re-stages names without evidence and records them.
- A producer failing mid-stream leaves invalid JSON (refused); one failing before its document leaves
  a key unsupplied (`NotSupplied`); `set -o pipefail` also fails the step.
- A supplying run refuses before any write when a selected placement has no recorded delivery item or
  state vault (`RecordMissing{StateVault}`, Next `opv propose structure`).

## 6. Delivery and evidence

### 6.1 Plan

In `prepare_staged`: `tidy::read` → `deliver_only::refuse_stored` → append
`deliver_only::item_fields(&supply)` → `plan::build_with_gate` (unchanged for supplied names) →
`deliver_only::refusal` (§4.2, §4.3, §5.1) → `refuse_blocking`.

An infrastructure key with no field this run (no supply) gets `KeyState::SuppliedAtSync`, which is
not blocking and never `Missing`. It is never staged or pruned. Its target state comes from the
version alone:

| Target state | Condition | ON TARGET |
|---|---|---|
| `AsSupplied` | store lists the `s1` line's version | `as supplied` |
| `Drifted` | store lists another version (joins `plan.drift`) | `drifted` |
| `Absent` | not listed | `absent` |
| `Unrecorded` | listed, no `s1` line | `not recorded` |

The 1Password column shows `supplied at sync`; `--json` rows add `"value_state": "supplied"`,
`"supplied": true`.

**Plan id.** A supplied name enters with route `supplied` and **without** its write/no-write bit
(`provenance::plan_id` skips infrastructure keys in the `apply` set). A value-free `opv plan` and
`sync --supply-stdin --expect-plan` derive the same id, and the id carries no equality bit about a
supplied value.

### 6.2 Evidence

The line is `s1|<store version>|<fingerprint>|<product/KEY>|<serial>|<recorded at>`; the fingerprint
is HMAC-SHA256 of the supplied value under the placement's evidence key, as today.
`decode_evidence`/`encode_evidence` gain the `s1` tag; `Evidence` gains
`supplied: Option<SuppliedMark{serial, at}>`; `Ledger::from_evidence` reads `s1` lines, so
`Ledger::check` and `Ledger::drift` cover supplied names. `record`:

1. takes a supplied name's value from the `Supply`, not `values_by_field`;
2. keeps the line of a name not supplied this run and `AsSupplied` verbatim, in a `carried` set that
   counts as confirmed (a Fly version is a value digest, a GitHub `updatedAt` a write stamp);
3. leaves infrastructure keys out of `source versions` (C2). `opv changed` ignores them.

An older opv drops `s1` lines and the receipt's `supplied` list on rewrite; §4.3 makes the result
fail closed (`Unrecorded`, then `Unproven`).

### 6.3 Receipts

Schema id unchanged (`opv.delivery/1`). A supplied binding's source is
`{"item_id": "supplied", "field": "api/DATABASE_URL"}` (a 1Password id is 26 characters, so it cannot
collide), and an optional `supplied: [names]` list (omitted when empty) mirrors `attested`. A
revision is minted when every name is written, identical, carried or attested.

### 6.4 Without a supply

| Command | Behaviour |
|---|---|
| `sync` (scheduled) | holds every infrastructure name. `AsSupplied` names are carried, so the revision stays valid. `Absent`, `Drifted` or `Unrecorded` mint nothing: `delivery: api not recorded: supplied at sync, not supplied by this run: …` (exit 0: it claims nothing) |
| `status --fail-on-drift` | fails on a drifted supplied name |
| `ready --gate` | fails unless every present infrastructure key is `AsSupplied` on every target of the tier: `supplied_not_delivered`, `supplied_drifted`, Next "run the deploy job" |
| `delivery verify` | `verified` (`"supplied": true`; means "unchanged since supplied", not "current"), `drifted_on_target`, `missing_on_target`; never `source_changed` |
| `inventory`, `opv_state` | value state `supplied`, the 8th word of the guided-setup §3.3 |
| `explain p/K` | "supplied at sync; never stored", with last delivery time, serial and last rotation per placement |
| `opv run` in a target environment | does not inject the key; prints one note naming it |

## 7. Identity

The **existing deploy identity**: a 1Password service account that reads the environment's boundary
vaults and writes its state vault (`opv access --create`; `access_create.rs` grants read-only on
boundaries), plus the platform token. A supplying sync reads boundary items (other keys, and the
`Stored` check) and writes only delivery items in the state vault. **No new 1Password capability.**
`deliver_only.rs` imports no 1Password write adapter, and T12 asserts that a supplying sync issues no
`op item edit|create` outside the state vault. `import`, `set` and `apply` keep `require_person`.

## 8. Surface

### 8.1 CLI and generator

- `opv sync … --supply-stdin`.
- `opv propose key … --source infrastructure`; its apply archives an existing field.
- `opv ci workflow <env> --target <t> --supply` emits a **step** to paste into the producing job (not
  a job of its own, and no concurrency group), with `set -euo pipefail`, one jq mapping per key, and
  `opv sync <env> --target <t> --supply-stdin [--deploy] --receipt <t>.receipt.json [--confirm <env>]`.
  - Each mapping is `jq -e '.<output>.value | strings // error("<output> missing")'`: a fixed message,
    so jq never quotes its input (S4).
  - A comment forbids `${{ … }}` in the step's script.
  - The generator **never emits `--rotate`** (S5). Docs show a rotation as a manually dispatched
    workflow whose boolean input, passed through `env:`, adds `--rotate p/K` for that run only.
- `opv ci workflow --supply-check <file>` (also emitted as a `pull_request` job) refuses, in any step
  whose `run:` pipes into `--supply-stdin`, a `${{ … }}` expression other than `github.*`: such
  expressions are expanded into the logged script. Refusal: `InputInvalid{kind: Workflow, rule:
  ExpressionInSupplyStep{line}}`.

### 8.2 MCP

No tool accepts a value. `opv_propose` takes `source: "infrastructure"` as one more enumerated
attribute; `opv_state` shows `supplied` and the target states. `tests/mcp_protocol.py` still asserts
exactly five tools.

### 8.3 Schema and docs

- `opv schema`: capability `supplied_values/1`; `value_state` + `supplied`; `row_state` +
  `supplied_at_sync`; the `opv.supply/1` input schema.
- `tests/e2e/expected/surface.json`: `sync` + `supply-stdin`; `ci workflow` + `supply`, `supply-check`.
- Docs: `configuration.md`, `usage.md`, `security.md` (the courier's inbound leg), `error-catalog.md`,
  `delivery-receipts.md`, `opv guide agent` and the skill (an assistant proposes, never handles
  values), CHANGELOG (first supported in 0.13.0, with §8.4).

### 8.4 Supported infra migration (`apply.yml`, `stripe_webhooks.py`)

0. Move every opv pin (workflows, teammates, infra) to ≥ 0.13.0 (S13).
1. Propose and apply both keys (§2.1); apply archives any existing 1Password field.
2. If the placement has no delivery item, run `opv propose structure`, then `opv apply`.
3. Change `stripe_webhooks.py` to print exactly one `opv.supply/1` document on stdout, with
   `serial` = the endpoint secret's creation time, and to stop calling `flyctl secrets set`.
4. Append the supply step to the **Terraform apply job** in `apply.yml`:

```yaml
      - name: Deliver Terraform and Stripe values through opv
        env:
          OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OPV_PROD_DEPLOY }}
          FLY_API_TOKEN: ${{ secrets.FLY_API_TOKEN }}
        run: |
          set -euo pipefail
          serial=$(terraform -chdir=infra state pull | jq -e '.serial')
          {
            terraform -chdir=infra output -json | jq -ce --argjson s "$serial" \
              '{schema:"opv.supply/1", env:"prod", serial:$s,
                values:{"api/DATABASE_URL":
                  (.neon_database_url.value | strings // error("neon_database_url missing"))}}'
            python fly/shared-host/stripe_webhooks.py --env prod --emit-opv-supply
          } | opv sync prod --target web --supply-stdin --deploy \
                --confirm prod --receipt web.receipt.json
          opv delivery verify prod --target web --receipt web.receipt.json
```

5. Because the values were set directly before, the first run needs one dispatched rotation
   (§4.3: `Unproven`), then routine runs need none.

The step compiles nothing, so build-once promotion and the Build gate are untouched. infra keeps its
direct delivery until this step has run green on staging and prod and `delivery verify` reports
`verified` (owner condition on #206).

## 9. Test plan

Simulator and synthetic fixtures; values are `S7MARKER-…` canaries. Core: C; sync: S.

| # | Test | Lane |
|---|---|---|
| T1 | positive: two documents supply both keys for prod/web; stdin-only staging; `s1` lines; revision lists `supplied` | S, e2e |
| T2 | scope: wrong document `env`, key absent in env, excluded by `--product`/`--target` → refused with zero 1Password reads and target calls | C |
| T3 | names: undeclared (by position, closest offered), `NotOptedIn`, bare `KEY`, rendered name, `Duplicate` (one object, two documents), `NotSupplied` | C |
| T4 | stream: terminal, invalid JSON (no input byte in the error), > 1 MiB, `null`, empty, no documents, no serial, unknown field, unclosed stdin → `Timeout` | C |
| T5 | rules: `RuleFailed{rule}` with no write; `transform`/`ensure_prefix` applied; every §2.2 load refusal at its line | C |
| T6 | `Stored` with and without a supply; `propose key --source infrastructure` apply archives it | C |
| T7 | every cell of §4.3; `RotateWithoutValue` | S |
| T8 | idempotency and §5.1: same supply twice writes nothing; equal serial while drifted repairs; `Stale`/`SerialReused`, each overridden by `--rotate` with its printed line | S |
| T9 | concurrency: re-read keeps the other run's lines; second change → `item_changed`; higher serial on re-read → `Partial` + `Stale` | S |
| T10 | failures: target write fails → `Partial`; record `Err`, unlisted or unencodable version, no item → each exit 8; retry mints one revision | S |
| T11 | without supply: carried revision; drift fails `status --fail-on-drift` and `ready --gate`; `delivery verify` states | S |
| T12 | the fake op log of a supplying sync writes only the state vault's delivery item | S |
| T13 | canary absent from stdout, stderr, `--json`, receipt, delivery item (HMAC only), argv, child env, temp files, MCP, panic and error text, across T1–T11 | C, S |
| T14 | plan id of `opv plan` = `sync --supply-stdin --expect-plan`, value changed or not | S |
| T15 | e2e `infrastructure_values`: propose and apply, adoption rotation, supply, scheduled sync, drift, re-supply, verify | e2e |
| T16 | surface: `surface.json`, `opv schema`, five MCP tools, `--supply` golden (jq `error`, no `--rotate`), `--supply-check` refuses `${{ steps.x.outputs.v }}` and accepts `${{ github.sha }}` | S |

## 10. Non-goals and #206 criteria

Not built: writing supplied values to 1Password by anyone (recovery is re-running the producer);
pinned targets; `from` consumers of a supplied key (declare a second infrastructure key); supplied
config; local `opv run` of these values; the GitHub-secret app values #206 mentions (ordinary stored
keys).

AC2's ingestion identity and isolated writable boundary, and AC6's unauthorized-identity test,
presume CI writes 1Password. Nothing is ingested here, so there is no writer to isolate; T12 and T2
replace them. The rest map to AC1 §2.3/§4.1, AC2 §7, AC3 §3–§4, AC4 §5, AC5 §6, AC6 §9, AC7 §8.

## 11. Implementation split and interface

**Step 0, an interface commit both lanes branch from**: `ValueSource::Infrastructure`, the shapes
below, and `src/app/deliver_only.rs` with `todo!()` bodies. File ownership does not overlap.

```rust
// src/app/deliver_only.rs (deliver-only-core)
pub struct Supplied { pub product: String, pub key: String, pub value: SecretValue, pub serial: u64 } // Debug: names only
pub struct Supply { /* env; BTreeMap<(product, key), Supplied> */ }
impl Supply {
    pub fn env(&self) -> &str;
    pub fn get(&self, product: &str, key: &str) -> Option<&Supplied>;
    pub fn names(&self) -> impl Iterator<Item = (&str, &str)>; // sorted
}
pub struct Limits { pub total: usize, pub names: usize, pub deadline: std::time::Instant } // 1 MiB, 256, run budget
pub struct RawSupply { /* parsed documents; values already registered with the scrubber */ }
pub fn read(input: &mut dyn std::io::Read, stdin_is_terminal: bool, limits: &Limits) -> Result<RawSupply, Error>;
pub struct Scope<'a> { pub env: &'a str, pub targets: &'a [String], pub product: Option<&'a str>,
                       pub rotate: &'a BTreeSet<(String, String)> }
pub fn admit(fleet: &Fleet, scope: &Scope<'_>, raw: RawSupply) -> Result<Supply, Error>; // §4.1 incl. NotSupplied; pure
pub fn refuse_stored(fleet: &Fleet, env: &str, read: &[ItemField]) -> Result<(), Error>; // §4.4
pub fn item_fields(fleet: &Fleet, supply: &Supply) -> Vec<ItemField>;                    // §6.1
pub fn refusal(plan: &SyncPlan, supply: &Supply, ledgers: &[Ledger],
               rotate: &BTreeSet<(String, String)>) -> Option<Error>;                    // §4.2, §4.3, §5.1
pub fn is_infrastructure(spec: &KeySpec) -> bool;
```

Shared shapes in Step 0:

- `KeyState::SuppliedAtSync`; `TargetState::{AsSupplied, Unrecorded}`; value-state word `supplied`.
- `Evidence.supplied: Option<SuppliedMark { serial: u64, at: String }>`; `Receipt.supplied: Vec<String>`;
  `Ledger::supplied(&self, name) -> Option<(&str /*version*/, u64 /*serial*/)>`.
- `delivery::record` returns `Recorded { minted, not_minted, supplied: BTreeMap<String,
  SuppliedOutcome> }` with `enum SuppliedOutcome { Recorded, NotRecorded(NotRecordedWhy) }` and
  `NotRecordedWhy::{Unlisted, Unencodable, NoItem, Failed, NewerSerial{recorded}}` (S1, S9).
- `Guard::SupplyRefused { env, entry: SupplyEntry, reason: SupplyRefusal }`, where `SupplyRefusal`
  is `Undeclared, NotOptedIn, NotInEnvironment, OutOfScope, NotSupplied{keys}, Duplicate,
  WrongEnvironment, Empty, TooShort, Placeholder, NotAString, RotateWithoutValue, RuleFailed{rule},
  Stored, Unproven, ImmutableDiffers, Stale{recorded, supplied}, SerialReused{serial}`.
- `InputKind::{Supply, Workflow}` with the rules of §4.1 and §8.1; `AttestRefusal::NotStored`.

**`deliver-only-core`** owns `src/app/deliver_only.rs` and tests; `src/config.rs` (§2.2);
`src/domain/model.rs`; `src/domain/plan.rs` (infrastructure rows, target states); `src/cause/*` and
the `error-catalog.md` rows; the refusals in `structure.rs`, `set.rs`, `import.rs`,
`import_local.rs`, `open.rs`, `generate.rs`, `attest.rs`; the archive step of `propose key`;
`docs/configuration.md`. Tests T2–T6 and the core half of T13.

**`deliver-only-sync`** owns `src/app/sync.rs` (intake wiring, `SyncOpts.supply: Option<Supply>`,
per-name outcomes as exit 8, carried set, rotation line); `src/app/delivery.rs` (`record` with
re-read and recompute, `verify`); `src/domain/{delivery,ledger,provenance}.rs`; `ready.rs`,
`status.rs`, `inventory.rs`, `explain.rs`, `changed.rs`, `run.rs`, `ci_workflow.rs`; `src/main.rs`
(flags, agent-mode refusal); `src/mcp.rs` (`opv_propose` enum); `tests/e2e/expected/surface.json`
and the scenario; `usage.md`, `security.md`, `delivery-receipts.md`, CHANGELOG, the infra example.
Tests T1, T7–T16. It fakes `admit` and `refusal` in unit tests; the lanes join at T15.

## 12. Self-vet

**Poka-yoke** is listed where each mistake is stopped (§2.2, §3, §4, §5.1, §8.1).

**Leaks.** serde text never shown (position only); only declared names echoed; `Debug`/panics carry
names only (`SecretValue`, `no_core_dumps`); values scrub-registered at parse, all secrets ≥ 8 bytes;
plan id without an equality bit; evidence is an HMAC in the state vault; producer step guarded by the
jq idiom and `--supply-check`; producers' own stderr is out of scope (R8). Residual: the report says
whether a supplied name changed, a fact about infrastructure as for stored values today.

**CI writing 1Password.** No code path, a deploy identity without boundary write, T12 to catch a
regression; archiving a stored field is a person's `opv apply`.

**False success.** Any supplied name without an `s1` line exits 8; partial writes are `Partial`;
incomplete supplies are `NotSupplied`; unsupplied names count only at a proven-unchanged version; a
missing delivery item refuses up front; concurrent changes give `item_changed` or `Stale`; receipts
mark `supplied`; `ready --gate` fails on absent or drifted supplied names.

## 13. Proposed answers (pending owner approval)

The FMECA reviewer's recommendations, adopted:

1. **Serial**: required, taken from the producer's own object; `--rotate p/K` overrides `Stale` and
   `SerialReused`.
2. **A stored 1Password field**: refused (§4.4).
3. **Adoption**: one `--rotate` run, for every infrastructure key the target already lists without
   evidence (§4.3). No attest-like step: it would need a person to hold the value.
4. **Value state**: add `supplied` as the 8th value state.
5. **Channel**: stdin only.
6. **Kubernetes and Azure**: refused at load; a 0.14 issue only when a user needs it.
7. **`opv run`** in a target environment: prints a note naming the key; it does not refuse.
