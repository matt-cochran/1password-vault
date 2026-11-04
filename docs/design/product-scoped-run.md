# Product-scoped `opv run` (#264, #263)

> **Owner decisions (2026-11-04):** the owner accepted every recommended option in this document's decisions section.

Status: design, for 0.18.0. **Revised after DESIGN-FMECA vet**
(`docs/design/product-scoped-run-fmeca.md`, verdict "ready with changes"; every required
change is applied here). Branch `v0180/design`, cut from `dev` at opv 0.17.2 (7cc0b6dd).
Requirements: FR-4, FR-43, FR-45, FR-55, FR-57 (its acceptance line names this case), SR-1,
SR-3, SR-4, SR-5.
Related designs: `placements-and-access-boundaries.md` §4, `deliver-only.md` §4.4 and §6.4,
`local-delivery.md`, `self-healing-conventions.md`.

Every claim below is **verified** against one of these, unless it is marked **inferred**:

- the code at 7cc0b6dd (file:line given);
- the names-only CI log of run 40927616817;
- the Zonetico producer at `zonetico-saas@b8f820a4`
  (`scripts/release/provision-private-production-acceptance.ts`);
- the infra configuration at `infra@50b370a1`
  (`fly/shared-host/acceptance-authority/zonetico/secrets.toml`), as cited by the vet.

## 1. Problem and root cause

### 1.1 What the issues report

- **#264**: `opv run prod --product input -- <producer>` seems to exit before the producer
  starts. It names empty keys from sibling output products that share the input product's
  boundary item. Those outputs are made later by the same producer, so this looks like a
  producer/consumer deadlock.
- **#263**: the pre-run diagnostic for `run --product` names empty fields from unrelated
  products in the shared boundary, so the real blocker is hard to see.

### 1.2 What the code does

`run` (local and `--remote`) goes through `launch`, `src/app/run.rs:207-389`. It does five
things that matter here.

1. **It selects keys per product. Correct.** `delivery_preview::select`
   (`run.rs:237` → `src/app/delivery_preview.rs:59-102`) keeps only the `prod.keys` that
   apply in the environment and to the role. Infrastructure keys are split off and not
   injected, with one note each (`run.rs:240-250`). Only the selected keys become `op://`
   references (`run.rs:298-345`).
2. **It reads every boundary item in the environment. Wrong.** `run.rs:287-289` calls
   `tidy::read(fleet, env_name, runner)` with the **whole** fleet. That call goes through
   `read` (`src/app/tidy.rs:321`), `read_as` (`tidy.rs:383-390`) and
   `read_in(fleet, fleet, …)` (`tidy.rs:393-421`). `read_in` reads `boundaries_needed(fleet)`
   (`tidy.rs:355-364`), and `Fleet::needed_boundaries` (`src/domain/model.rs:746-763`) builds
   that from **every product** with a key in the environment. This breaks FR-57's acceptance
   line: "`run --product p` reads only p's boundary and its sources". Read errors are dropped
   (`.ok()`, `run.rs:288`).
3. **Its "still needs a value" note covers the whole boundary item. This is #263.** `finish`
   fills `Read.needing_values` from `needing_values(&layout, fleet, …)` (`tidy.rs:790`). That
   fleet is `in_boundary(fleet, b)`, which is every product whose values live in the item
   (`tidy.rs:368-378`, `403`). `needing_values` (`tidy.rs:721-744`) loops over all of those
   products, and `run.rs:293-297` prints the whole list. A person's tidy prints the same
   list from inside `read_item_as` (`tidy.rs:520-530`).
4. **It names infrastructure keys as needing a value in 1Password. Any command does this.**
   The filter at `tidy.rs:733-734` drops `from` and personal keys, but not
   `source = "infrastructure"` keys. The convention never creates a field for such a key
   (`src/domain/convention.rs:645-649`), so the key is always "missing" and always named.
   That contradicts `deliver-only.md` §6.4.
5. **It clears every declared key name from the child's environment, infrastructure names
   included.** `run.rs:376-385` builds the list from every key of every product and passes
   it to `run_inherited_clean`. This is FR-4's v0.4 decision.

   An infrastructure value is never stored in 1Password (deliver-only §4.4). So `run`
   cannot inject it, and it also removes the only carrier the caller has: the parent
   environment.

There is **no check that stops the run on an empty value**. The note at `run.rs:293-297` is
only a note, and an empty field reaches the child as `""` (`run.rs:291-292`;
`tidy_tests.rs:1264-1277`).

### 1.3 What happened in run 40927616817 (names only)

- **opv printed one note naming 16 keys**: 3 of the selected product
  `zonetico-platform-acceptance`, 7 of `zonetico-platform-agency-acceptance` and 6 of
  `zonetico-private-acceptance`. **All 13 sibling names are infrastructure keys**, so
  item 4 above alone accounts for that noise.
- **opv started the child.** The next line, `private-production acceptance provisioning
  failed at stage=input; no credential values were printed`, is the producer's own
  `ProvisioningStageError` (producer `:109-124`, `:174-178`, `:1290`).
- **The line has no `missing=` suffix.** An empty selected platform key would have thrown
  `ProvisioningStageError('input', [names])`, and that error carries the suffix (producer
  `:111`, `:286-297`). With no suffix, the error is a plain `Error` from
  `inputFromEnvironment`, wrapped by `atStage` (`:121-122`).
- **`inputFromEnvironment` first requires four names**: `PRIVATE_PRODUCTION_ACCEPTANCE_`
  `TENANT_ID`, `_EMAIL`, `_PASSWORD` and `_TOTP_SECRET` (producer `:233-261`). It checks
  them before it looks at the three selected keys.
- **The workflow sets all four** in the step's environment (log lines 178-181).
- **All four are declared infrastructure keys** of the sibling product
  `zonetico-private-acceptance` (infra config lines 18-42). So `run` removed them
  (`run.rs:376-385`), and the producer failed on them.
- **The failing step's `sync --supply-stdin` then reported "the supply holds no document"**,
  because the producer printed nothing.

The three selected keys may also read as empty: opv's note names them. The producer never got
that far, so this run does not show it. One verified mechanism would make them read empty
even when filled: infrastructure keys take part in `resolve` (`convention.rs:185-188`
filters only `from` and personal keys). `zonetico-private-acceptance` declares
`PRIVATE_PRODUCTION_PLATFORM_ACCEPTANCE_*` as infrastructure keys (infra config lines 46-63).
A field it claims is therefore not the platform product's. Whether that happened here is
**inferred**. It is follow-up 2 (§7), and the names-only check is:
`opv explain zonetico-platform-acceptance/PRIVATE_PRODUCTION_PLATFORM_ACCEPTANCE_EMAIL --env zonetico-prod-acceptance`.

### 1.4 Root cause in two sentences

`opv run --product` delivers only the selected product's keys, but it removes every declared
key name from the child's environment, including a sibling product's infrastructure names.
opv never holds those values and the workflow passes them in, so the producer that needs them
fails at `stage=input`. That is the real producer/consumer cycle in #264.

Separately, `run` reads and reports on the whole environment instead of the selected
product. It reads every boundary item, and names every empty or never-stored key in each one.
That buries the real blocker under unrelated names (#263) and breaks FR-57.

### 1.5 Other commands that take `--product`

| Command | What can block, or what the note names | Read scope | Same bug? |
|---|---|---|---|
| `run` / `run --remote` | note covers the whole item (`run.rs:293-297`); every declared name cleared (`run.rs:376-385`) | all boundaries (`run.rs:287`) | **yes, in scope** |
| `run --preview` / `opv_state delivery_preview` | reads nothing (`delivery_preview.rs:104-115`) | none | no. But it lists infrastructure keys as delivered while `run` does not inject them (`delivery_preview.rs:200-218` against `run.rs:240-250`), in both JSON and text (`write_text`, `delivery_preview.rs:317-336`). **In scope** as D2 |
| `sync --product`, `plan --product` | blocking rows are scoped (`sync.rs:1035`, `mod.rs:1743-1760`, `status.rs:304-306`), **except `refuse_stored`**: it runs before scoping and checks every product's fields (`sync.rs:1015`, `:1602`; `deliver_only.rs:907-927`), so another product's stored infrastructure field refuses a `--product` sync | all boundaries (`sync.rs:1014`, `mod.rs:159/205`) | partly. Out of scope: follow-ups 1 and 2 |
| `status --product` | rows `retain(product == p)` (`status.rs:514-515`) | all boundaries | blocking is scoped. Out of scope |
| `doctor --env --product` | fleet narrowed by `local::select` (`doctor.rs:146-151`, `local.rs:6-39`) | narrowed, read-only `inspect` | no |
| `changed --product`, `delivery verify --product`, `config export <env> --product` | scoped per placement or per product (`changed.rs:175-182`; `product_flag_tests.rs:302`) | per placement | no |
| `set`, `needs --product`, `ready` | `set` is per key; `needs` reads no 1Password; `ready` has no `--product` | n/a | no |

Rule 4 (§2.3), the infrastructure filter, also cleans the note for every command that tidies.
That is the only effect outside `run`.

## 2. Proposed behaviour

### 2.1 The run's key set (one source of truth)

`launch` computes **`wanted`** once, as a set of `(product, KEY)` ids, from the selection it
already makes:

- start from every key in `selection.delivered` (product, environment, mode rules and role,
  as now);
- remove infrastructure keys (not injected; the existing note stays, `run.rs:244-250`);
- remove personal keys (FR-55: they live in the person's item, which is checked separately
  as now);
- replace each `from` key with its **source** id (FR-45: the value lives in the source's
  field).

`wanted` is the run's dependency closure. Three things are derived from it and nothing else:
the read scope (`ReadScope::Keys(wanted)`), the references, and the note filter.

### 2.2 What is read

The run reads exactly the boundary items whose products own a `wanted` id. Because `from`
keys were replaced by their source ids, the sources' boundaries are included by
construction. Each item is read once. This meets FR-57's acceptance line: a run never reads
another product's separate boundary item.

When a person's run tidies an item it read, the tidy still sees **every product in that
item**. That is `in_boundary(whole fleet, b)`, which `read_in` already uses at `tidy.rs:403`.
A shared item is tidied exactly as today, and a narrowed fleet never reaches
`convention::plan` (§5).

### 2.3 What is validated, delivered and reported

| Key | Referenced on `op run` | Named in "still needs a value" |
|---|---|---|
| selected, stored, filled | yes | no |
| selected, stored, field **empty** | yes; the child gets `""`, as today (verified, `run.rs:291-292`) | **yes** |
| selected, stored, field **missing** | yes, by the conventional reference (`run.rs:337-340`). **Inferred**: `op run` refuses a reference it cannot resolve, so the child does not start and the user sees op's error | **yes**, printed before `op run` |
| `from` key whose source is empty | yes (the source's field) | **yes, as the source's `product/KEY`** (as today, `tidy_tests.rs:882`) |
| selected, `source = "infrastructure"` | no (none stored). The existing "is not injected … supplied at sync" note stays | **no** |
| selected, personal | yes (person's item) | no (a missing personal item is already its own error) |
| withheld by `--role` | no | no |
| any key of another product in the same item, filled, empty, generated later or infrastructure | no | **no** |

The rules:

1. **opv adds no new refusal** (D1-A). An empty wanted key is still a note, not a refusal,
   and `run` still starts `op run`. A missing field may still stop `op run` itself, which
   is **inferred** (row 3).
2. **The note names only `wanted ∩ needing_values`.** If no wanted key is empty or missing,
   the run prints no "still needs a value" line, whatever else the item holds.
3. **The note is printed in one place, once.** A scoped read (`ReadScope::Keys`) never
   prints the needs-value note inside `read_item_as`. It returns `needing_values` as
   `KeyId`s, and `run` prints `needing ∩ wanted` once after the read, whether or not it
   tidied. The "tidied 1Password" summary stays inside the reader and covers the whole
   item, because the write did. `ReadScope::Whole` (every other caller) keeps today's
   in-tidy print byte-for-byte.
4. **Infrastructure keys are never named** as needing a value in 1Password, by any command.
   The filter in `needing_values` gains `!is_infrastructure(spec)`.
5. **Clearing the inherited environment (D4-B, recommended, assumed in the lanes).** `run`
   keeps removing every declared **stored** key name of every product from the inherited
   environment, so a stale parent value never shadows a value from 1Password. It **does not
   remove a declared `source = "infrastructure"` name**: opv never holds that value, and the
   parent environment is its only carrier.

   When one or more such names are present in the parent environment, `run` prints one
   names-only note:

   ```
   taken from the environment as given (supplied at sync, never stored in 1Password): zonetico-private-acceptance/PRIVATE_PRODUCTION_ACCEPTANCE_EMAIL, …
   ```

   Stored and `from` names stay cleared (`clears_another_products_managed_keys` stays
   green).

The note keeps its wording; only the list of names is filtered:

```
still needs a value in 1Password (prod): input/API_TOKEN. Open it with opv open input/API_TOKEN --env prod, then click Edit: 1Password hides empty fields until then.
```

### 2.4 JSON, CLI and MCP parity

- `run` without `--preview` prints no JSON. Its notes go to stderr, as today. D1-A and D4-B
  add no flag, so `tests/e2e/expected/surface.json`, completions and `opv schema` are
  unchanged.
- `run --preview --json` and `opv_state` section `delivery_preview` share one builder
  (`delivery_preview::build_for`), so parity holds by construction.
- **Under D2-A**, infrastructure keys move out of `keys` into a new array:

  ```json
  { "keys": [ { "product": "input", "key": "API_TOKEN", "source": "input/API_TOKEN", "destination": "env:API_TOKEN", "roles": null } ],
    "supplied_at_sync": ["OWNER_EMAIL"] }
  ```

  - `supplied_at_sync` is **present only when non-empty**, like `containers`
    (`delivery_preview.rs:242-246`). The eight `tests/e2e/snapshots/run_preview__*.snap`
    files hold no infrastructure key, so they stay byte-identical. `schema_version` is
    unchanged.
  - The text form (`write_text`, `delivery_preview.rs:317-336`) gains one line, printed only
    when the array is present: `supplied at sync (not injected): OWNER_EMAIL`.
- The preview still reads no value. It does not report which keys are empty, because that
  would need an item read.

## 3. Alternatives considered

| Alternative | Why not |
|---|---|
| Filter only the printed note, and keep the fleet-wide read | Fixes #263's text but leaves the FR-57 breach. A CI identity that can read only the input boundary makes `tidy::read` fail. The `.ok()` then drops the whole read silently, and the run loses its field-id references and normalization warnings. That effect is **inferred**; the code path is verified. |
| `tidy::read(&local::select(fleet, env, Some(p)))`: a narrowed fleet, as doctor does | Doctor gets away with it because `inspect` never writes. `run` tidies for a person, and `convention::plan` would then see a shared item without its sibling sections, which is the hazard FR-57 defers account-wide boundaries for. The scope must narrow **which items** are read, never **which products the tidy sees**. |
| A scope keyed by product names, with the note filtered inside `read_item_as` | It cannot express role-withheld keys or a single `from` key of a source product, so the tidy path and the non-tidy path would disagree (vet R2). Replaced by `wanted` `KeyId`s and one print site. |
| Print sibling empties as a count | #263 asks that unrelated names not be shown at all. `opv status <env>` lists them. |
| Make `run` refuse when a wanted key is empty | D1 option B. |
| Keep rule 5 unchanged (clear every declared name) | That is the verified Zonetico failure. It is D4 option A. |
| Make the fake `op` in the binary test resolve `op://` references | New, brittle `sh` work that B1-B5 do not need (vet R7). The fake `op` only execs, as in `tests/local_delivery.rs:408`. |

## 4. Owner decisions

### D1. Should `run` refuse to start when a key it delivers is empty?

**Situation.** Today `run` starts your command even when a key it passes is empty in
1Password. The child gets `""`, and opv prints one "still needs a value" line. After this fix
that line names only keys the run uses, so the blocker is clear. The question is whether opv
should also stop before the child starts.

- **A. Note only (today's behaviour, scoped).** Nothing breaks. Apps that tolerate an empty
  optional value keep working; the existing `LOG_LEVEL` test does exactly that. Producers
  keep their own input checks.
- **B. Always refuse** with the existing `values_needed` error before `op run`. Every app
  that tolerates an empty optional key stops until someone fills it. A future scoping
  mistake would then turn into a real deadlock.
- **C. Opt-in `--require-values`.** B on request. It is a surface change: `surface.json`,
  completions, `opv schema` and docs.

**Recommendation: A.** The noise is in the diagnostic, not in a missing gate. Note one
limit: a *missing* field (as opposed to an empty one) is expected to stop `op run` itself.
That is **inferred**, and the note names the key first either way.

### D2. Should `run --preview` stop listing infrastructure keys as delivered?

**Situation.** The preview (text, JSON and the assistant's `opv_state delivery_preview`)
lists a `source = "infrastructure"` key as delivered. A real run does not inject it. Preview
and run disagree.

- **A. Move those keys to `supplied_at_sync`.** The array is present only when non-empty,
  and the text form gets one `supplied at sync (not injected): …` line. Preview matches run,
  and existing snapshots stay unchanged.
- **B. Leave it.** The preview keeps over-reporting.

**Recommendation: A.** A preview must never claim to deliver more than the run does.

### D3. Is an opv-sim end-to-end scenario part of this release?

**Situation.** opv-sim does not implement `op run` (`tests/sim/op.rs:218-290`). Adding it
makes the fault matrix discover a new call. The coverage gate (`tests/e2e/coverage.rs`) then
requires that call to be faulted with every fault kind, or listed in `SKIPPED.md`.

- **A. A binary-level regression test only** (the real `opv` binary with an exec-only fake
  `op`). Sim support for `op run` becomes a follow-up.
- **B. Add `op run` to opv-sim and an e2e scenario now.** About 5 more hours, on the
  critical path.

**Recommendation: A.**

### D4. Should `run` clear a declared infrastructure name from the inherited environment?

**Situation.** Some values are made by infrastructure (`source = "infrastructure"`) and are
never stored in 1Password; opv only delivers them at sync. When a workflow already holds such
a value and passes it to `opv run` in its environment, `run` removes it today, because it
removes every declared key name before starting the child. That is what broke the Zonetico
producer: four names it needs were removed (§1.3). opv cannot supply those values itself, so
after removal the child has nothing.

- **A. Keep clearing every declared name.** No change. #264 stays open, and the workaround
  stays: run the producer outside `opv run`.
- **B. Never clear a declared infrastructure name.** Stored and `from` names are still
  cleared. One names-only note lists the infrastructure names taken from the environment,
  printed only when any is present. No flag. The Zonetico pipeline works as written. The
  child receives whatever the caller passed, the same as running it without opv.
- **C. Opt-in `--inherit <NAME>`**, limited to declared infrastructure names. Explicit
  per run, but a surface change (`surface.json`, completions, `opv schema`, docs), about
  +1.5 h on L2 and L5.

**Recommendation: B.** opv has no better value to offer for these names. Clearing them only
removes the one carrier the caller has, while stored names, the case FR-4's rule protects,
stay cleared. The lanes below assume B.

**Acceptance for closing #264:** a names-only re-run of the Zonetico workflow (L8) gets past
`stage=input`, with the producer's own output and opv's notes as evidence. Unit and binary
tests alone do not close it.

## 5. Self-vet

### 5.1 Poka-yoke

- **One set drives everything.** `wanted` is computed once (§2.1). The read scope
  (`ReadScope::Keys(wanted)`), the references and the note filter all come from it, so the
  note cannot name a key that is not referenced (T13).
- **One print site.** A scoped read never prints the needs-value note. `run` prints it once,
  so the tidy path and the non-tidy path cannot disagree. T5, T15 and T16 run on both paths.
- **The tidy and the scope cannot be swapped.** `read_in(scope: &Fleet, fleet: &Fleet, …)`
  takes two values of the same type, so a caller can pass them in the wrong order. It is
  replaced by `tidy::read_for(fleet, scope: &ReadScope, env, r)`.
  - `ReadScope` is an enum: `Whole`, or `Keys(BTreeSet<KeyId>)`.
  - `in_boundary(fleet, b)` keeps receiving the whole fleet, inside `tidy.rs`, so no caller
    can hand the tidy a narrowed fleet.
  - `ReadScope::Whole` keeps every other caller unchanged (T6).
- **Filtering can only remove.**
  - Note: `needing ∩ wanted`.
  - Read: `boundaries(wanted) ⊆ boundaries(fleet)`.
  - Selection: `select` is unchanged.
  - The clear list loses only names opv never holds (D4-B), and nothing in this design adds
    a key to the references or to the local-delivery `--key` list.
- **Infrastructure has one predicate.** Rule 4 and D4-B both call
  `deliver_only::is_infrastructure`, the predicate `run.rs:243` partitions by.
- **Architecture guards.**
  - All changes are in `src/app` (`tidy.rs`, `run.rs`, `delivery_preview.rs`), and no
    adapter or provider is named.
  - FR-37 `core_modules_name_no_provider` skips `*_tests.rs` (`src/app/mod.rs:2326`), but
    FR-12 `use_cases_name_no_target_adapter` scans test files with `cfg(test)` items removed
    (`mod.rs:2125-2145`). The #264 fixture therefore has **no target**: `launch` never reads
    targets.
  - `run_scope_tests.rs` is mounted with `#[path]` from `run.rs`, the existing pattern
    (`delivery_preview.rs:423`).
  - No `Observed` constructor is touched, so J7 `tests/observed_seal.rs` is unaffected.
  - There is no new `Cause`, so the error-catalog coverage gate is unaffected.
  - Under D1-A and D4-B there is no new flag, so `tests/e2e/expected/surface.json` is
    unchanged. D2-A keeps the preview snapshots byte-identical.

### 5.2 Security

- **A product filter never widens delivery.** The delivered set is still `select`'s output.
  The scope only shrinks the read and the note.
- **D4-B is a narrow exception** to FR-4's clear rule, split by value source:
  - It applies only to declared infrastructure names, which opv never holds.
  - Stored names stay cleared, so a stale parent value can never shadow a 1Password value
    (`clears_another_products_managed_keys`, `run.rs:805-816`).
  - An inherited infrastructure value is named in a note, never shown (vet R9).
- **Fewer reads.** A `--product` run no longer reads other boundary items (FR-57, SR-5).
- **Values.** There is no new path for a value.
  - The notes carry only `product/KEY` labels (SR-1).
  - The references still go to `op run` in the child environment, never in argv (SR-3), and
    nothing is written to disk (SR-4).
  - The emptiness check is the existing in-memory `value.expose().is_empty()`
    (`tidy.rs:741`), and D4-B only *keeps* a variable; it never reads it.
  - T14 asserts that a marker value appears in no note.
- **The tidy's write scope is unchanged.** A person's run still tidies the whole shared
  item with every product in it (FR-43). T4 guards this.

## 6. Test plan

Rules for every test (vet R3):

- One behavioural assertion each. Fixtures hold test markers only, and the fixture for the
  #264 regression has no target.
- **Every `run` unit test holds `let _on = tidy::activate();`.** Without it,
  `tidy::active()` is false in unit tests (`tidy.rs:44-56`), the read is skipped, and every
  "names no X" assertion passes vacuously.
- **Every negative test has a positive partner** on the same fixture, listed side by side.
  The pair proves the read ran and the note can name keys.
- **T5, T15 and T16 run twice**: on the tidy path (`FakeOp::person` with a messy item) and
  on the non-tidy path (a tidy item).
- **T9, T12, B2 and B5 are written first and shown failing on 7cc0b6dd.** The PR records
  the red run, then the green one.

**Unit: `src/app/tidy_tests.rs` (L1), scoped read and `needing_values`**

| id | test | asserts |
|---|---|---|
| T1 | `needing_values_never_names_an_infrastructure_key` | a person's tidy note does not contain an empty infrastructure key's label |
| T1+ | `needing_values_names_an_empty_stored_key_beside_it` | the same note contains the empty stored key's label |
| T2 | `a_scoped_read_reads_only_the_scopes_boundary_item` | `read_for(Keys{a/K})` with two boundary items makes zero `item get` calls for b's item |
| T2+ | `a_scoped_read_reads_the_scopes_item` | the same read makes one `item get` for a's item |
| T3 | `a_scoped_read_reads_a_from_sources_boundary` | a scope holding the source id `shared/K` reads shared's item |
| T4 | `a_scoped_tidy_still_sees_every_product_in_a_shared_item` | a person's scoped read of a shared item leaves the sibling's field in the sibling's section, not in `opv · kept` |
| T5 | `a_scoped_read_prints_no_needs_value_note` | a `Keys` read prints no "still needs a value" line (tidy and non-tidy paths) |
| T5+ | `a_whole_read_still_prints_the_tidy_needs_value_note` | a `Whole` read on the tidy path still prints it |
| T6 | `an_unscoped_read_is_unchanged` | `ReadScope::Whole` reads the same items as `read` today |

**Unit: `src/app/run_scope_tests.rs` (new, mounted from `run.rs`; L2)**

Fixture: one boundary `acceptance` holding two products in environment `prod`, with no
target:

- `input`: keys A and B, both filled;
- `output`: keys X and Y, empty, and key Z with `source = "infrastructure"`.

| id | test | asserts |
|---|---|---|
| T7 | `run_input_starts_the_child_when_only_output_keys_are_empty` (**#264 regression**) | `run(prod, input)` returns `Ok`, and the runner recorded one `op run` call |
| T8 | `run_input_references_only_input_keys` | the opv-added names in the child environment are exactly {A, B} (+ `OPV_RUN_OUTER`) |
| T9 | `run_input_names_no_output_key_as_needing_a_value` (**#263 regression**) | the notes contain neither `output/X` nor `output/Y` |
| T9+ | `run_input_names_its_own_empty_key` | with A emptied, the note contains `input/A` |
| T10 | `run_input_prints_no_needs_value_line_when_its_keys_are_filled` | no note contains `still needs a value` |
| T12 | `run_never_names_an_infrastructure_key_as_needing_a_value` | running `output` (Z selected), no "still needs a value" note names `output/Z` |
| T12+ | `run_output_names_its_empty_stored_key` | the same run's note names `output/X` |
| T13 | `the_needs_value_note_names_only_referenced_keys` | every label in the note is a referenced key or its `from` source |
| T14 | `the_needs_value_note_holds_no_value` | the input marker value appears in no note |
| T15 | `run_names_an_empty_from_source_of_a_selected_key` | a selected `from = shared/K` whose K is empty gets a note naming `shared/K` (tidy and non-tidy paths) |
| T16 | `run_skips_a_role_withheld_empty_key` | an empty key withheld by `--role` is not named (both paths) |
| T16+ | `run_names_an_empty_key_of_the_selected_role` | an empty key of the selected role is named (both paths) |
| T17 | `run_input_does_not_read_a_separate_sibling_boundary` | with `output` in its own boundary, zero `item get` calls for that item (FR-57) |
| T17+ | `run_input_reads_its_own_boundary` | one `item get` for `acceptance` |
| T22 | `a_remote_run_names_no_output_key` | `run --remote` on the T7 fixture names no `output/` key |
| T23 | `run_keeps_an_inherited_infrastructure_name` (D4-B) | with Z set in the parent environment, Z is not in the clear list |
| T23+ | `run_still_clears_an_inherited_stored_name` | with X set in the parent environment, X is in the clear list |
| T24 | `run_names_an_inherited_infrastructure_name_once` | one "taken from the environment as given" note naming `output/Z` |
| T24+ | `run_prints_no_inherit_note_without_one` | with Z absent from the parent environment, no such note |

**Unit: `src/app/delivery_preview_tests.rs` (L3, D2-A)**

| id | test | asserts |
|---|---|---|
| T18 | `preview_lists_an_infrastructure_key_under_supplied_at_sync` | `supplied_at_sync` == ["Z"] |
| T19 | `preview_keys_omit_an_infrastructure_key` | no entry of `keys` is Z |
| T19+ | `preview_keys_keep_a_stored_key` | `keys` holds X |
| T20 | `preview_without_infrastructure_keys_has_no_supplied_at_sync` | the document has no `supplied_at_sync` field |
| T21 | `preview_text_names_supplied_at_sync_keys` | the text form holds `supplied at sync (not injected): Z` |

**Binary: `tests/product_scoped_run.rs` (new; L4)**

The fake `op` on PATH serves the item JSON for `item get` and, for `run --`, only execs the
child. It does not resolve references (pattern of `tests/local_delivery.rs:408`, `:420-460`).

| id | test | asserts |
|---|---|---|
| B1 | `run_input_exits_with_the_childs_code` | `opv run prod --product input --confirm prod -- sh -c 'exit 0'` exits 0 |
| B2 | `run_input_stderr_names_no_output_product` | stderr does not contain `output/` |
| B2+ | `run_input_stderr_names_its_own_empty_key` | with A emptied, stderr contains `input/A` |
| B3 | `run_input_child_sees_no_stored_output_name` | with X set in the parent environment, the child's `env` has no X |
| B4 | `run_input_preview_json_lists_only_input_keys` | `run prod --product input --preview --json` exits 0, and every `keys[*].product` is `input` |
| B5 | `run_input_child_keeps_an_inherited_infrastructure_name` (**the Zonetico cycle**, D4-B) | with Z set in the parent environment, the child's `env` holds Z (name compared only) |

**e2e (opv-sim)**: deferred under D3-A (follow-up 3).

**Release gate** (L6):

- `cargo test`, `cargo clippy -D warnings`, and the e2e suite with `CI=true`.
- That run includes the FR-37 and FR-12 guards, `tests/observed_seal.rs`,
  `tests/surface_contract.rs` and the `run_preview__*` snapshots.
- Check the red-first evidence for T9, T12, B2 and B5.

**Live gate** (L8, owner): a names-only re-run of the Zonetico workflow gets past
`stage=input`. #264 closes only on that.

## 7. Delivery steps

| id | lane | files owned | prereqs | est. h | owner type |
|---|---|---|---|---|---|
| L1 | `ReadScope` (`Whole` / `Keys`) and `read_for`; a scoped read never prints the needs-value note; `needing_values` as `KeyId`s without infrastructure keys; T1-T6 | `src/app/tidy.rs`, `src/app/tidy_tests.rs` | none | 3.0 | **Claude agent**: broad reading (tidy safety; every other `tidy::read` caller stays `Whole`) |
| L2 | `run`: `wanted`, `read_for(Keys(wanted))`, one note print; D4-B clear rule and its note; new `run_scope_tests.rs` T7-T17, T22-T24 | `src/app/run.rs`, `src/app/run_scope_tests.rs` (new) | L1, D4 | 3.0 | commodity worker (file-scoped; L1 fixes the interface) |
| L3 | Preview `supplied_at_sync` in JSON and `write_text` (D2-A); T18-T21 | `src/app/delivery_preview.rs`, `src/app/delivery_preview_tests.rs` | D2 | 1.25 | commodity worker |
| L4 | Binary regression B1-B5 with an exec-only fake `op` | `tests/product_scoped_run.rs` (new) | L2 | 2.0 | commodity worker |
| L5 | Docs: see the list below | listed docs | L2, L3 | 1.25 | commodity worker |
| L6 | Release gate: full `cargo test`, clippy, e2e with `CI=true`; guards and snapshots unchanged; red-first evidence present | none (read-only) | L1-L5 | 1.0 | Claude agent |
| L8 | **Owner step**: names-only re-run of the Zonetico workflow; gates closing #264 | none | L6 released | 0.25 | owner |
| L7 | *(D3-B only)* `op run` in opv-sim, fault-matrix cells or `SKIPPED.md`, e2e scenario and snapshots | `tests/sim/op.rs`, `tests/e2e/scenarios/product_scoped_run.rs`, `tests/e2e/main.rs`, `tests/e2e/snapshots/*` | L2 | 5.0 | Claude agent |

L5 updates these files:

- `docs/usage.md`: the run note's scope, D4 and the preview field;
- `docs/design/local-delivery.md`: the preview document;
- `docs/design/deliver-only.md` §6.4: the `opv run` and `run --preview` rows;
- `docs/design/requirements.md`: the FR-4 decision line for D4, and the FR-43 transparency
  bullet ("names the keys the command uses");
- `CHANGELOG.md`.

Every lane stays under about 400 changed lines (L2 is about 80 production lines plus 300
test lines). The critical path is L1 → L2 → L4 → L6, **9.0 h**, then the 0.25 h owner step
L8. L3 runs in parallel with L1 and L2. With D4-C instead of D4-B, add about 1.5 h to L2 and
L5, plus the `surface.json` diff.

### Follow-up issues (not in this release)

1. `sync --product`, `plan --product` and `status --product` read every boundary in the
   environment (`sync.rs:1014`, `mod.rs:159/205`), and their tidy note covers the whole
   item. That is FR-57 over-reading. Whether it blocks a scoped deploy identity is
   **inferred**. `ReadScope` from L1 is the tool to fix it.
2. **Infrastructure keys claim fields, and `refuse_stored` is fleet-wide.**
   - Infrastructure keys take part in `convention::resolve` (`convention.rs:185-188`), so
     one can claim a filled field that another product's stored key needs. That contradicts
     "never stored" (`convention.rs:645-649`, deliver-only §4.4), and it is the likely,
     **inferred**, reason Zonetico's selected keys read empty.
   - `refuse_stored` checks every product's fields before `--product` scoping
     (`sync.rs:1015`, `:1602`; `deliver_only.rs:907-927`), so another product's stored
     infrastructure field refuses a scoped sync.
   - Fix both: infrastructure keys never claim a field, and `refuse_stored` is scoped the
     way `scope_plan` is.
   - Related: a filled field in a human-named section whose label exactly matches keys of
     two products is claimed by neither, with no note (`convention.rs:236-246`).
3. opv-sim `op run` support (D3-A).
4. *(Optional, low.)* A `--verbose` line when `run`'s tolerant read fails. Today the `.ok()`
   at `run.rs:288` makes "no empty keys" look the same as "read failed" (vet R13; existing
   behaviour).
