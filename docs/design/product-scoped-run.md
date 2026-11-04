# Product-scoped `opv run` (#264, #263)

Status: design, for 0.18.0. Branch `v0180/design`, cut from `dev` at opv 0.17.2 (7cc0b6dd).
Requirements: FR-4, FR-43, FR-45, FR-55, FR-57 (its acceptance line names this case), SR-1, SR-3, SR-4.
Related designs: `placements-and-access-boundaries.md` §4, `deliver-only.md` §6.4,
`local-delivery.md`, `self-healing-conventions.md`.

Every claim below is **verified** by reading the code at 7cc0b6dd (file:line given) or by
the names-only CI log of run 40927616817, unless it is marked **inferred**.

## 1. Problem and root cause

### 1.1 What the issues report

- **#264**: `opv run prod --product input -- <producer>` seems to exit before the producer
  starts. It names empty keys from sibling output products that share the input product's
  boundary item. Those outputs are made later by that same producer, so this looks like a
  producer/consumer deadlock.
- **#263**: the pre-run diagnostic for `run --product` names empty fields from unrelated
  products in the shared boundary, so the real blocker is hard to see.

### 1.2 What the code does

`run` (local and `--remote`; both go through `launch`, `src/app/run.rs:207-389`):

1. **Selection is product-scoped. Correct.** `delivery_preview::select`
   (`src/app/run.rs:237` → `src/app/delivery_preview.rs:59-102`) keeps only
   `prod.keys` that apply in the environment and to the role. Infrastructure keys are then
   split off and are not injected; each one gets one note (`run.rs:240-250`). Only the
   selected keys become `op://` references (`run.rs:298-345`). The delivered set is already
   exactly the selected product's keys, so #264's "deliver only the selected product's
   keys" is already true for delivery.
2. **The read is fleet-wide. Wrong.** `run.rs:287-289` calls
   `tidy::read(fleet, env_name, runner)` with the **whole** fleet. `read`
   (`src/app/tidy.rs:321`) → `read_as` (`tidy.rs:383-390`) → `read_in(fleet, fleet, …)`
   (`tidy.rs:393-421`). That reads `boundaries_needed(fleet)` (`tidy.rs:355-364`), which
   `Fleet::needed_boundaries` (`src/domain/model.rs:746-763`) builds from **every product**
   with a key in the environment. So `run --product p` reads every boundary item in the
   environment. This breaks FR-57's acceptance line: "`run --product p` reads only p's
   boundary and its sources". `read_in` already takes a separate `scope` argument for this
   purpose (`tidy.rs:393-403`), but every caller passes the whole fleet (`tidy.rs:389`).
3. **The diagnostic is boundary-wide. This is the #263 root cause.** For each item,
   `finish` fills `Read.needing_values` from `needing_values(&layout, fleet, …)`
   (`tidy.rs:790`). That fleet is `in_boundary(fleet, b)`, meaning every product whose
   values live in that item (`tidy.rs:368-378`, `403`). `needing_values`
   (`tidy.rs:721-744`) loops over all of those products. `run.rs:293-297` then prints the
   whole list through `note_needing_values` (`tidy.rs:748-756`). When a person's run tidies
   the item, the same boundary-wide list is printed from inside `read_item_as`
   (`tidy.rs:520-530`).
4. **Infrastructure keys are named as "needs a value in 1Password". A separate bug, any
   command.** The filter in `needing_values` (`tidy.rs:734`) drops `from` keys and personal
   keys, but not `source = "infrastructure"` keys. The convention never creates a field for
   such a key (`src/domain/convention.rs:647`), so it is always "missing" and is always
   named. That contradicts `deliver-only.md` §6.4 ("supplied at sync, never stored"). The
   `OWNER_EMAIL` key in #263's minimal shape is this case.
5. **There is no gate on empty values. This contradicts #264's "exits before starting".**
   Nothing in `launch` returns an error for an empty key. The note at `run.rs:293-297` is
   only a note, and the read's errors are dropped (`.ok()`, `run.rs:288`). An empty field
   reaches the child as `""`. The comment at `run.rs:291-292` and the test
   `run_names_a_key_that_still_needs_a_value` (`src/app/tidy_tests.rs:1264`, which unwraps
   `Ok`) both confirm this.

### 1.3 What run 40927616817 shows (names only)

The failed step's log was read locally and only opv's names-only lines were looked at.

- opv printed **one** note, `still needs a value in 1Password (zonetico-prod-acceptance): …`.
  It names **16 keys**:
  - 3 of the selected product `zonetico-platform-acceptance`;
  - 7 of `zonetico-platform-agency-acceptance`;
  - 6 of `zonetico-private-acceptance`.
- The next line is the **producer's own** message: `private-production acceptance
  provisioning failed at stage=input; no credential values were printed`. That text is not
  in the workflow's shell script, so it came from the child. **opv started the child.** The
  `sync --supply-stdin` after it then failed with "the supply holds no document" because
  the producer printed nothing.
- So the real blocker was **the selected product's own three keys**, which opv's read saw
  as empty or unresolved. It was hidden among 13 unrelated names. The "deadlock" in #264 is
  the boundary-wide diagnostic (1.2 item 3) making the sibling outputs look like
  prerequisites. opv is not blocking.
- **Inferred, not verified**: why the three selected keys read as empty while the reporter
  believes they are filled. One plausible cause: `PRIVATE_PRODUCTION_PLATFORM_ACCEPTANCE_*`
  is declared by **two** products in the same item (`zonetico-platform-acceptance` and
  `zonetico-private-acceptance`). A filled field under that label in a human-named section
  matches both products exactly. `resolve` then claims it for neither and prints no note
  (`src/domain/convention.rs:236-246`). Each product's own section field stays empty, and
  `run` references that empty field. The owner can check this from names alone with
  `opv explain zonetico-platform-acceptance/PRIVATE_PRODUCTION_PLATFORM_ACCEPTANCE_EMAIL --env zonetico-prod-acceptance`.
  A silent two-way exact-label match is a convention gap and goes to a follow-up issue,
  not this design.
- **Inferred**: the workflow also sets `PRIVATE_PRODUCTION_ACCEPTANCE_*` variables. If any
  of those names is a declared key of any product, `run` removes it from the child's
  environment by design (FR-4 v0.4 decision, `run.rs:376-382`). This is intended and stays.

### 1.4 Root cause in two sentences

`opv run --product` builds its references from the selected product only, but its 1Password
read and its "still needs a value" diagnostic use the whole fleet. So it reads every
boundary item in the environment, and it names every empty key in each item, sibling
products and never-stored infrastructure keys included. The child is still started (there
is no gate), so the visible "deadlock" is a misleading diagnostic that hides the selected
product's own empty keys.

### 1.5 Other commands that take `--product`

| Command | Blocking or diagnostic scope | Read scope | Same bug? |
|---|---|---|---|
| `run` / `run --remote` | note is boundary-wide (`run.rs:293-297`) | all boundaries (`run.rs:287`) | **yes, in scope** |
| `run --preview` / `opv_state delivery_preview` | no read (`delivery_preview.rs:104-115`) | none | no. But it lists infrastructure keys as delivered while `run` does not inject them (`delivery_preview.rs:200-218` against `run.rs:240-243`): a parity bug, **in scope** (D2) |
| `sync --product`, `plan --product` | rows scoped by `scope_plan` (`src/app/mod.rs:1743-1760`; `sync.rs:660-665`; `status.rs:304-306`) | all boundaries (`sync.rs:1014`, `mod.rs:159/205`) | blocking is scoped. Over-read is **inferred** to be FR-57's concern, and the tidy note is boundary-wide. Out of scope: follow-up issue |
| `status --product` | rows `retain(product == p)` (`status.rs:514-515`) | all boundaries | blocking is scoped (narrower: drops `from` sources). Out of scope |
| `doctor --env --product` | fleet narrowed by `local::select` (`doctor.rs:146-151`, `local.rs:6-39`) | narrowed, read-only `inspect` | no |
| `changed --product`, `delivery verify --product`, `config export <env> --product` | placement-scoped or product-scoped (`changed.rs:175-182`; `product_flag_tests.rs:302`) | per placement | no |
| `set`, `needs --product`, `ready` | `set` is per key; `needs` reads no 1Password; `ready` has no `--product` | n/a | no |

The fix to the tidy note and the infrastructure filter (§2.3, rules 4 and 5) also cleans
the note for every command that tidies. That is the only effect outside `run`.

## 2. Proposed behaviour

### 2.1 The run's key set (one source of truth)

`launch` computes **`wanted`**, one set of `(product, KEY)` ids, from the selection it
already makes:

- every key in `selection.delivered` (product, environment, mode rules and role, as now);
- minus infrastructure keys (they are not injected; the existing note stays, `run.rs:244-250`);
- minus personal keys (FR-55: they live in the person's item, which is checked separately
  as now);
- with each `from` key replaced by its **source** id (FR-45: the value lives in the
  source's field).

`wanted` is the dependency closure of the run. The read scope, the references and the
diagnostic are all derived from it, and from nothing else.

### 2.2 What is read

The boundary items that `wanted` needs: the selected product's boundary plus its `from`
sources' boundaries, each read once. This is FR-57's acceptance line. A run never reads
another product's separate boundary item.

A person's tidy of an item that is read still sees **every product in that item**
(`in_boundary(whole fleet, b)`, as `read_in` already does at `tidy.rs:403`). A shared item
is therefore tidied exactly as today, and a narrowed fleet never reaches `convention::plan`
(see §5).

### 2.3 What is validated, delivered and reported

| Key | Referenced on `op run` | Named in "still needs a value" |
|---|---|---|
| selected, stored, filled | yes | no |
| selected, stored, empty or missing | yes (child gets `""`, as today) | **yes** |
| `from` key whose source is empty | yes (the source's field) | **yes, as the source's `product/KEY`** (as today, `tidy_tests.rs:882`) |
| selected, `source = "infrastructure"` | no | **no**. The existing "is not injected … supplied at sync" note is kept |
| selected, personal | yes (person's item) | no (a missing personal item is already its own error) |
| withheld by `--role` | no | no |
| any key of another product in the same item, filled or empty, generated-later or infrastructure | no | **no** |

Five rules:

1. **Nothing new blocks.** An empty selected key is still a note, not a refusal (D1).
   `run` still starts the child, which owns its own input checks.
2. **The diagnostic names only `wanted ∩ needing_values`.** If no wanted key is empty, the
   run prints no "still needs a value" line, whatever else the item holds.
3. **The tidy note follows the same filter** when the caller is `run`: the "tidied
   1Password" summary line stays item-wide, because the write was item-wide. The "still
   needs a value" list after it is filtered to `wanted`.
4. **Infrastructure keys are never named** as needing a value in 1Password, by any
   command. The filter in `needing_values` gains `!is_infrastructure(spec)`.
5. **The clear list is unchanged.** `run` keeps removing every declared key name of every
   product from the inherited environment (`run.rs:376-382`). The scope narrows what is read
   and reported. It never narrows what is cleared.

Note text: unchanged wording, with the names filtered:

```
still needs a value in 1Password (prod): input/API_TOKEN. Open it with opv open input/API_TOKEN --env prod, then click Edit: 1Password hides empty fields until then.
```

### 2.4 JSON, CLI and MCP parity

- `run` without `--preview` prints no JSON (only its child's output). The note goes to
  stderr as today. No new flag, so `tests/e2e/expected/surface.json`, completions and
  `opv schema` stay unchanged under the recommendations.
- `run --preview --json` and `opv_state` section `delivery_preview` share one builder
  (`delivery_preview::build_for`), so parity holds by construction. If D2 is chosen,
  infrastructure keys move out of `keys` into a new array:

  ```json
  { "keys": [ { "product": "input", "key": "API_TOKEN", "source": "input/API_TOKEN", "destination": "env:API_TOKEN", "roles": null } ],
    "supplied_at_sync": ["OWNER_EMAIL"] }
  ```

  `supplied_at_sync` is **present only when non-empty**, like `containers`
  (`delivery_preview.rs:242-246`). That leaves the eight
  `tests/e2e/snapshots/run_preview__*.snap` documents byte-identical. `schema_version` is
  unchanged, because the field is additive and absent in every current document.
- The preview still reads no value. Value state (empty or filled) is not added to the
  preview, because that would need an item read and break its "reads no value" contract.

## 3. Alternatives considered

| Alternative | Why not |
|---|---|
| Filter only the printed note (keep the fleet-wide read) | Fixes #263's text but leaves the FR-57 breach. A CI identity that can read only the input boundary makes `tidy::read` fail, the `.ok()` drops the whole read silently, and the run loses its field-id references and normalization warnings (**inferred** effect; the code path is verified). |
| Call `tidy::read(&local::select(fleet, env, Some(p)))` (narrowed fleet, as doctor does) | Doctor gets away with it because `inspect` never writes. `run` tidies for a person. A narrowed fleet would make `convention::plan` see a shared item without its sibling sections, which is the hazard FR-57 defers account-wide boundaries for ("until the implicit tidy never writes an item holding sections this configuration does not declare"). The scope must narrow **which items** are read, never **which products the tidy sees**. |
| Print sibling empties as a count ("3 other keys in this item are empty, not used by this run") | #263 asks that unrelated names not be shown at all. `opv status <env>` already lists them. A count adds noise to every run in a shared boundary. |
| Make `run` refuse when a wanted key is empty | See D1, option B. |
| Exclude only generated-later (empty) sibling keys | Any sibling key is irrelevant to the run, filled or empty. Scope by membership, not by state. |
| Fix #264 by teaching `run` to order producer and consumer | Not needed. `run` never waited on siblings; the confusion came from the diagnostic. |

## 4. Owner decisions

### D1. Should `run` refuse to start when a key it delivers is empty?

**Situation.** Today `run` starts your command even when a key it passes is empty in
1Password. The child gets `""`, and opv prints one "still needs a value" line. After this
fix, that line names only keys the run actually uses, so the real blocker is clear. The
question is whether opv should go further and stop before the child starts.

- **A. Keep the note only (today's behaviour, scoped).** Nothing breaks. An app that can
  run with an empty optional value (the existing test does exactly that with `LOG_LEVEL`)
  keeps working. Producers keep their own input checks, as the Zonetico producer already
  has (`failed at stage=input`).
- **B. Always refuse** with the existing `values_needed` error, naming only the wanted
  empty keys, before `op run`. The child never sees `""`. But every app that tolerates an
  empty optional key stops working until someone fills it. The run also becomes sensitive
  to any future scoping mistake: a wrongly widened scope would turn into exactly the
  deadlock #264 feared.
- **C. Opt-in flag** (`--require-values`) that does B on request. One more flag, which
  means updating `surface.json`, completions, `opv schema` and docs.

**Recommendation: A.** The bug is the diagnostic, not the lack of a gate. A keeps the
fix small and non-breaking. C can be added later if a pipeline asks for it.

### D2. Should `run --preview` stop listing infrastructure keys as delivered?

**Situation.** `opv run --preview` (and the assistant's `opv_state delivery_preview`)
lists a key with `source = "infrastructure"` under `keys`, as if it were delivered.
A real run does not inject it: it prints "not injected: supplied at sync". So the preview
and the run disagree.

- **A. Move those keys to a `supplied_at_sync` list**, present only when non-empty.
  Preview matches run. Existing snapshots stay unchanged. Assistants see the truth.
- **B. Leave the preview as it is.** No change. The preview keeps over-reporting what a
  run gives the child.

**Recommendation: A.** It is a few lines, and a preview must never claim to deliver more
than the run does.

### D3. Is an opv-sim end-to-end scenario part of this release?

**Situation.** The opv-sim harness does not implement `op run` (`tests/sim/op.rs:218-290`
has no `run` arm). Adding it is more than a scenario: the fault matrix would discover a new
`op run` call, and the coverage gate (`tests/e2e/coverage.rs`) then requires it to be
faulted with every fault kind or listed in `snapshots/SKIPPED.md`.

- **A. Binary-level regression only this release** (the real `opv` binary with a fake
  `op`, the pattern of `tests/local_delivery.rs:420-460`), plus unit tests. Sim support for
  `op run` becomes a follow-up issue.
- **B. Add `op run` to opv-sim and an e2e scenario now.** About 5 more hours and the
  fault-matrix work, on the release's critical path.

**Recommendation: A.** The binary test exercises the exact #264 path (real argv, real
`op run` hand-off, child exit). Sim support for `run` is worth having, but it is its own
piece of work.

## 5. Self-vet

### 5.1 Poka-yoke

- **One set drives everything.** `wanted` is computed once from `selected` (§2.1), and the
  read scope, the references and the note filter are all derived from it. The note cannot
  name a key that is not referenced, by construction. Test T13 asserts it.
- **Two fleets cannot be swapped.** `read_in(scope: &Fleet, fleet: &Fleet, …)` takes two
  values of the same type, so a caller can pass them in the wrong order. Replace it with
  `tidy::read_for(fleet: &Fleet, scope: &ReadScope, env, r)`. `ReadScope` is a newtype over
  the set of product names whose boundaries are read (built from `wanted`).
  `in_boundary(fleet, b)` keeps receiving the whole fleet inside `tidy.rs`, so no caller can
  hand the tidy a narrowed fleet. `ReadScope::Whole` keeps every existing caller unchanged.
- **Filtering can only remove.** The note list is `needing ∩ wanted`. The read set is
  `boundaries(wanted) ⊆ boundaries(fleet)`. `select` is unchanged. Nothing in this design
  adds a key to the references, the local-delivery `--key` list or the child environment.
- **Infrastructure keys use one predicate.** The new filter calls
  `deliver_only::is_infrastructure`, the same predicate `run.rs:243` partitions by. There
  is no second definition.
- **Architecture guards.** All changes are in `src/app` (`tidy.rs`, `run.rs`,
  `delivery_preview.rs`). No adapter or provider is named. **Test fixtures in `src/app`
  must not name a provider either** (FR-37 `core_modules_name_no_provider`, FR-12
  `use_cases_name_no_target_adapter`, `src/app/mod.rs:2128-2145`, `2313-2334`). The #264
  fixture needs **no target at all**: `launch` never reads targets, so target ownership of
  the output products does not change the run path. No `Observed` constructor is touched
  (J7 `tests/observed_seal.rs`). There are no new Cause variants and no new flags, so the
  error-catalog coverage gate and `tests/e2e/expected/surface.json` are unaffected under
  D1-A. D2-A keeps the preview snapshots byte-identical.

### 5.2 Security

- **A product filter never widens delivery.** The delivered set stays `select`'s output.
  The scope only shrinks the read and the note. The fleet-wide clear list stays, so a
  sibling product's declared name in the parent environment still never reaches the child
  (existing test `clears_another_products_managed_keys`, `run.rs:805-816`).
- **Fewer reads.** A `--product` run no longer reads other boundary items (FR-57, SR-5
  least privilege).
- **Values.** No new value path. The note carries `product/KEY` labels only (SR-1). The
  references still go to `op run` in the child environment, never in argv (SR-3), and
  nothing is written to disk (SR-4). The emptiness check is the existing in-memory
  `value.expose().is_empty()` (`tidy.rs:741`). Test T14 asserts that a marker value never
  appears in notes for the shared-boundary fixture.
- **The tidy's write scope is unchanged**: a person's run still tidies the whole shared
  item with every product in it, as FR-43 specifies. Test T11 guards this.

## 6. Test plan

Each test makes one behavioural assertion. Unit tests use the crate's fakes. Fixtures name
no provider and hold test markers only.

**Unit: `src/app/tidy_tests.rs` (L1), scoped read and `needing_values`**

| id | test | asserts |
|---|---|---|
| T1 | `needing_values_never_names_an_infrastructure_key` | a person's tidy note on an item with an empty infrastructure key does not contain that key's label |
| T2 | `a_scoped_read_reads_only_the_scopes_boundary_item` | with two boundary items, `read_for(scope = {a})` makes zero `item get` calls for b's item |
| T3 | `a_scoped_read_reads_a_from_sources_boundary` | scope `{a}`, where a has `from = shared/K`, reads shared's item |
| T4 | `a_scoped_tidy_still_sees_every_product_in_a_shared_item` | a person's scoped run on a shared item leaves the sibling's field in the sibling's section (not in `opv · kept`) |
| T5 | `the_tidy_note_lists_only_the_scopes_keys` | after a person's tidy, the "still needs a value" line holds no sibling label |
| T6 | `an_unscoped_read_is_unchanged` | `ReadScope::Whole` reads the same items as `read` today (regression for every other command) |

**Unit: `src/app/run_scope_tests.rs` (new, mounted from `run.rs`; L2)**

Fixture: one boundary `acceptance` holding products `input` (keys A, B; A filled, B filled)
and `output` (keys X, Y empty; Z `source = "infrastructure"`), environment `prod`, no target.

| id | test | asserts |
|---|---|---|
| T7 | `run_input_starts_the_child_when_only_output_keys_are_empty` (**#264 regression**) | `run(prod, input)` returns `Ok` and the runner recorded one `op run` call |
| T8 | `run_input_references_only_input_keys` | the child environment's opv-added names are exactly {A, B} (+ `OPV_RUN_OUTER`) |
| T9 | `run_input_names_no_output_key_as_needing_a_value` (**#263 regression**) | the notes contain neither `output/X` nor `output/Y` |
| T10 | `run_input_prints_no_needs_value_line_when_its_keys_are_filled` | no note contains `still needs a value` |
| T11 | `run_input_names_its_own_empty_key` | with A empty, the note contains `input/A` |
| T12 | `run_never_names_an_infrastructure_key_as_needing_a_value` | with Z selected (product `output` run), no note contains `still needs a value` naming `output/Z` |
| T13 | `the_needs_value_note_names_only_referenced_keys` | every label in the note is a key referenced on `op run` (or its `from` source) |
| T14 | `the_needs_value_note_holds_no_value` | the input marker value appears in no note |
| T15 | `run_names_an_empty_from_source_of_a_selected_key` | a selected `from = shared/K` with K empty, so the note names `shared/K` |
| T16 | `run_skips_a_role_withheld_empty_key` | an empty key withheld by `--role` is not named |
| T17 | `run_input_does_not_read_a_separate_sibling_boundary` | with `output` in its own boundary, zero `item get` calls for that item (FR-57) |

**Unit: `src/app/delivery_preview_tests.rs` (L3, if D2-A)**

| id | test | asserts |
|---|---|---|
| T18 | `preview_lists_an_infrastructure_key_under_supplied_at_sync` | `supplied_at_sync` == ["Z"] |
| T19 | `preview_keys_omit_an_infrastructure_key` | no entry of `keys` has key Z |
| T20 | `preview_without_infrastructure_keys_has_no_supplied_at_sync` | the document has no `supplied_at_sync` field |

**Binary: `tests/product_scoped_run.rs` (new; L4; fake `op` on PATH, pattern of `tests/local_delivery.rs:420-460`)**

The fake `op` answers `item get` with the shared item, and for `run --` it resolves the
references and execs the child.

| id | test | asserts |
|---|---|---|
| B1 | `run_input_exits_with_the_childs_code` | `opv run prod --product input --confirm prod -- sh -c 'exit 0'` exits 0 |
| B2 | `run_input_stderr_names_no_output_product` | stderr does not contain `output/` |
| B3 | `run_input_child_sees_no_output_name` | the child's `env` holds no X, Y or Z |
| B4 | `run_input_preview_json_lists_only_input_keys` | `run prod --product input --preview --json` exits 0 and `keys[*].product` are all `input` |

**e2e (opv-sim)**: deferred under D3-A. Under D3-B: scenario
`tests/e2e/scenarios/product_scoped_run.rs` repeating B1-B3 against `opv-sim` with an
`S7MARKER` world, with text and JSON snapshots, plus `op run` fault-matrix cells or
`SKIPPED.md` entries.

**Release gate** (memory: release gate under CI): `cargo test`, `cargo clippy -D warnings`,
and e2e with `CI=true`, including the FR-37 and FR-12 guards, `tests/observed_seal.rs`,
`tests/surface_contract.rs`, and the `run_preview__*` snapshots.

## 7. Delivery steps

| id | lane | files owned | prereqs | est. h | owner type |
|---|---|---|---|---|---|
| L1 | Scoped tidy read (`ReadScope`, `read_for`), `needing_values` as `KeyId`s excluding infrastructure, tidy note filtered by scope; T1-T6 | `src/app/tidy.rs`, `src/app/tidy_tests.rs` | none | 3.0 | **Claude agent**: broad reading (tidy safety, every `tidy::read` caller must stay `Whole`) |
| L2 | `run` wiring: `wanted` from `selected`, `read_for(ReadScope::of(wanted))`, note filter; new `run_scope_tests.rs` T7-T17 | `src/app/run.rs`, `src/app/run_scope_tests.rs` (new) | L1 | 2.5 | commodity worker (file-scoped; interfaces fixed by L1) |
| L3 | Preview `supplied_at_sync` (D2-A); T18-T20 | `src/app/delivery_preview.rs`, `src/app/delivery_preview_tests.rs` | D2 | 1.0 | commodity worker |
| L4 | Binary regression B1-B4 with fake `op` | `tests/product_scoped_run.rs` (new) | L2 (L3 for B4 only if Z is in `input`) | 2.0 | commodity worker |
| L5 | Docs: `docs/usage.md` (run note scope, preview field), `docs/design/local-delivery.md` (preview doc), `docs/design/deliver-only.md` §6.4 (`run --preview` row), `docs/design/requirements.md` FR-43 transparency bullet ("names the keys the command uses"), `CHANGELOG.md` | listed docs | L2, L3 | 1.0 | commodity worker |
| L6 | Release gate: full `cargo test`, clippy, e2e with `CI=true`; check guards and snapshots unchanged | none (read-only) | L1-L5 | 1.0 | Claude agent |
| L7 | *(D3-B only)* `op run` in opv-sim, fault-matrix cells or `SKIPPED.md`, e2e scenario and snapshots | `tests/sim/op.rs`, `tests/e2e/scenarios/product_scoped_run.rs`, `tests/e2e/main.rs`, `tests/e2e/snapshots/*` | L2 | 5.0 | Claude agent |

Every lane stays under about 400 changed lines. L1 is about 120 production lines plus 200
test lines. L2 is about 60 plus 250. The critical path is L1 → L2 → L4 → L6, about 8.5 h.
L3 runs in parallel with L1.

### Follow-up issues (not in this release)

1. `sync --product`, `plan --product` and `status --product` read every boundary in the
   environment (`sync.rs:1014`, `mod.rs:159/205`), and their tidy note is boundary-wide.
   That is FR-57 over-reading; whether it blocks a scoped deploy identity is **inferred**,
   not verified. `ReadScope` from L1 is the tool to fix it.
2. Convention gap: a filled field in a human-named section whose label exactly matches keys
   of two products in the same item is claimed by neither, with no note
   (`convention.rs:236-246`). This is the likely, **inferred**, reason Zonetico's input keys
   read as empty.
3. opv-sim `op run` support (D3-A).
